"""Engagement files: what a written engagement permits, in a form the gate can hold a run to.

``--target`` and ``--engagement-confirmed`` say *that* an engagement exists, not what it
covers. An engagement file says what it covers — which hosts, ports and paths, in which
window, with which scenarios, whether the script may call tools — and the gate refuses a run
outside it (docs/engagements.md, 2).

**A file only narrows.** It never lets a run through that :func:`authorization.check` refuses:
``--engagement-confirmed`` is still needed for a scenario or a script that calls tools against
a non-local target, and the file does not imply it. The file adds refusals, nothing else.

**A claim is recorded as a claim.** Everything in the file was typed by the operator or the
customer, and nothing in it was checked against the world: the tool checks a run *against* the
file, never the file against the world. What the customer said about their own servers stays
under ``declared``, verbatim, and feeds no decision.

**Read whole or refused whole**, like a manifest or a scenario: the same strict JSON and YAML
front ends (:func:`mcp_kymograph.scenario.parse_json`, :func:`~mcp_kymograph.scenario.parse_yaml`),
keys closed at every level, refused on the first thing that is wrong, with the file and the
place. The digest is the SHA-256 of the file's bytes, as a scenario's is.

**A draft is a file, not a refusal.** A string that is wholly a bracketed placeholder
(``"[CUSTOMER NAME]"``) is what ``engagement intake`` leaves where it could not fill in a value.
Such a file loads, says where its placeholders are, and is refused by the gate: a draft can be
shown and agreed on, never run under.

**Times are UTC.** ``window.from`` and ``window.until`` carry ``Z`` or ``+00:00``; a time without
an offset, or with another, is refused rather than read in some zone. ``window.tz`` is for
showing the window in the customer's zone and decides nothing.

This module makes no network connection and resolves no name. Reading a file reads it and the
scenario files it lists; :func:`record_refusal` appends one line to ``refusals.jsonl`` and
:func:`read_refusals` reads it back; the stop file is written and removed by
:func:`write_stop_file` and :func:`clear_stop_file` and looked for (never read) by
:func:`stop_file_present`; nothing else here touches the filesystem.

**The stop file is the kill switch.** ``engagement stop FILE`` makes ``FILE.stop`` beside the
engagement file. While it is there the gate refuses every run under the file, and a run that is
already going is stopped (docs/engagements.md, 4). A run looks for three names
(:func:`stopped`): the one beside the file as resolved at load, the one beside the path as
given, and the one beside the path as given resolved now.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import unicodedata
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

from mcp_kymograph.authorization import is_local, split_target
from mcp_kymograph.corpus import _NAME
from mcp_kymograph.credentials import ENV_NAME, HEADER_NAME, RESERVED_HEADERS
from mcp_kymograph.masking import Masker, VerbatimPath, withheld_path, withhold_url_path
from mcp_kymograph.output import (
    Severity,
    inspect_destination,
    make_private_directories,
    unusable,
)
from mcp_kymograph.pacing import MAX_RUNS_PER_ORIGIN, Pacing
from mcp_kymograph.pacing import settings as pacing_settings
from mcp_kymograph.receiver import limits
from mcp_kymograph.receiver.store import check_prefix
from mcp_kymograph.recorder import FILE_MODE
from mcp_kymograph.sandbox.policy import ISOLATIONS
from mcp_kymograph.scenario import MAX_FILE_BYTES, ScenarioError, parse_json, parse_yaml

#: The first format version, and the one ``engagement intake`` still writes.
FORMAT_VERSION = 1
#: The second: the fields an engagement through an agency needs (docs/engagements.md, 2). It has
#: no ``customer``, and its new keys are unknown keys in a file of the first version.
FORMAT_VERSION_2 = 2
#: The versions this reader reads. A file of the first version is read as it always was.
READABLE_VERSIONS = (FORMAT_VERSION, FORMAT_VERSION_2)

#: What ``id`` may be: a name, as a manifest entry's — 1-64 letters, digits, ``.``, ``_``, ``-``.
ENGAGEMENT_ID = _NAME

_TOP_KEYS = frozenset(
    {
        "version",
        "id",
        "customer",
        "reference",
        "contacts",
        "window",
        "targets",
        "scenarios",
        "actions",
        "pacing",
        "retention",
        "redaction",
        "supersedes",
        "declared",
        "identities",
        "secret_headers",
    }
)
#: The keys only a file of the second version has. ``customer`` is the one it gives up: there it
#: is ``agency`` and ``end_customer``.
_V2_ONLY_KEYS = frozenset(
    {
        "agency",
        "end_customer",
        "tools",
        "deny_tools",
        "abort_criteria",
        "emergency",
        "known_values",
        "salt_env",
        "canaries",
        "receiver",
        "token_passthrough",
    }
)
_TOP_KEYS_V2 = (_TOP_KEYS - {"customer"}) | _V2_ONLY_KEYS
#: Without these a file says nothing a run can be held to: which file it is, when, where, and
#: what the script may do. Everything else may be left out.
_REQUIRED_TOP = ("version", "id", "window", "targets", "actions")
#: What a file of the second version must also say: whose engagement it is, when to stop, whom to
#: call when something goes wrong, and where the salt comes from.
_REQUIRED_TOP_V2 = (*_REQUIRED_TOP, "end_customer", "abort_criteria", "emergency", "salt_env")
_AGENCY_KEYS = frozenset({"name", "contacts"})
_END_CUSTOMER_KEYS = frozenset({"name"})
_TOOL_KEYS = frozenset({"name", "writes"})
_EMERGENCY_KEYS = frozenset({"name", "reach"})
#: Where a canary can be planted; ``file`` is the one that names a path.
CANARY_KINDS = ("tool_text", "resource", "prompt", "file")
_CANARY_KEYS = frozenset({"id", "kind", "where", "path", "removed"})
RECEIVER_VARIANTS = ("local", "reachable")
_RECEIVER_KEYS = frozenset(
    {"variant", "address", "path_prefix", "key_env", "ssh", "retention_seconds"}
)
#: What a ``reachable`` receiver cannot do without.
_RECEIVER_REACHABLE = ("address", "path_prefix", "key_env", "retention_seconds")
#: How a token that passes through to the upstream server is to be shown: the upstream bent to
#: the receiver, or a sample from the upstream's own log.
PASSTHROUGH_METHODS = ("redirect", "upstream_log")
_PASSTHROUGH_KEYS = frozenset({"method"})
#: A value to be replaced when written is at least this long: a shorter one would match
#: inside everything.
MIN_KNOWN_VALUE = 4
#: The limits of a receiver's ``path_prefix``, as the receiver holds them (``receiver.limits``).
RECEIVER_PREFIX_MIN_LENGTH = limits.MIN_PREFIX_CHARS
RECEIVER_PREFIX_MAX_LENGTH = limits.MAX_PREFIX_CHARS
RECEIVER_PREFIX_MIN_DISTINCT = limits.MIN_PREFIX_DISTINCT_CHARS
#: A DNS name for ``receiver.address``: dot-separated labels of letters, digits and ``-``, none
#: starting or ending with ``-``, and a last label that is not all digits (that is an IPv4 shape).
_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)
_ADDRESS_PORT = re.compile(r"[0-9]{1,5}")
_CONTACT_KEYS = frozenset({"name", "role", "reach"})
_WINDOW_KEYS = frozenset({"from", "until", "tz"})
_TARGET_KEYS = frozenset({"host", "ports", "paths", "isolation", "era", "version"})
#: The generations a target may say its server speaks, as the customer states them, and what a
#: version looks like: the date a protocol revision carries.
_ERAS = ("legacy", "modern")
_VERSION = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_SCENARIO_KEYS = frozenset({"path", "sha256"})
_ACTION_KEYS = frozenset({"list", "call"})
#: A file of the second version may also say ``write``: whether the tools it marks as writing may
#: be called at all.
_ACTION_KEYS_V2 = frozenset({"list", "call", "write", "probes"})
#: What the name of a probe module looks like.
PROBE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_PACING_KEYS = frozenset({"runs_per_origin", "min_interval_seconds"})
_RETENTION_KEYS = frozenset({"delete_after"})
_REDACTION_KEYS = frozenset({"mask_keys", "mask_patterns"})
#: What an identity names: who it is, in what role, and where its token comes from — exactly one
#: of ``token_env``, ``token_file`` and ``token: none`` — and the secret headers it sends, each
#: from an environment variable. A token's value is no key: the file holds none.
_IDENTITY_KEYS = frozenset({"name", "role", "token_env", "token_file", "token", "headers"})
_IDENTITY_KEYS_V2 = _IDENTITY_KEYS | {"observation"}
_TOKEN_SOURCES = ("token_env", "token_file", "token")
#: A file of the second version may also mark an identity as an observation: a run as it only
#: shows how the server answers a token that is foreign, expired or absent. ``no_token`` goes with
#: ``token: none``, the other two with a token source. The values are the words the recording's
#: ``run_started.auth.observation`` and ``token_observation.kind`` use.
OBSERVATIONS = ("foreign_audience", "expired", "no_token")
#: The one value ``token`` takes: this identity sends no ``Authorization`` header.
NO_SOURCE = "none"
#: The keys of ``declared``, of each of its servers and of its constraints: the shape of the
#: customer's answers, which ``engagement intake`` asks for and reads (:mod:`.intake`).
DECLARED_KEYS = frozenset({"servers", "constraints", "notes"})
DECLARED_SERVER_KEYS = frozenset(
    {
        "name",
        "reached_how",
        "transport",
        "version_or_commit",
        "clients_in_use",
        "owner_contact",
        "may_be_run_locally",
        "change_freeze",
        "entry",
    }
)
CONSTRAINT_KEYS = frozenset({"hours", "rate", "do_not"})
_DECLARED_KEYS = DECLARED_KEYS
_DECLARED_SERVER_KEYS = DECLARED_SERVER_KEYS
_CONSTRAINT_KEYS = CONSTRAINT_KEYS

#: The ports an endpoint target (a host that is not local) is read as when the file names none:
#: the port of ``https``, the one scheme a host that is not local is spoken to with
#: (docs/design/http-transport.md 8.5). Plain HTTP goes to loopback literals only, so the port
#: of ``http`` would reach nothing there. Not
#: "any": scope against somebody else's server is what the file says, and where it says nothing
#: about the port, the one port this version would use.
ENDPOINT_DEFAULT_PORTS = (443,)
ENDPOINT_DEFAULT_SCHEME = "https"

#: The longest time a receiver may keep what it receives, as the receiver holds it.
MAX_RETENTION_SECONDS = limits.MAX_RETENTION_SECONDS

#: What :meth:`Engagement.sanitized` leaves out, as key paths (``[]``: in every item of a
#: list): the operator's contacts and reference, with no place in an artifact that may be handed
#: on; the literal strings that must be blanked before a handover, which a copy of the file
#: would otherwise carry to wherever the handover goes; and the customer's own contact for each
#: server, which is a contact like the operator's; and the path of each identity's token file, a
#: local path with no place in such an artifact either. The file holds no token.
#: Of the second version: the values to be replaced, which are secrets of the customer's; whom to
#: call in an emergency; the names of the variables that hold the salt and the receiver's key, and
#: the reference to the receiver's host; and the agency's contacts. The receiver's path prefix is
#: the one part of its callback URL that cannot be guessed, and all that separates one engagement
#: from another there, so no store or bundle may carry it.
REMOVED = (
    "contacts",
    "reference",
    "redaction.mask_patterns",
    "declared.servers[].owner_contact",
    "identities[].token_file",
    "known_values",
    "emergency",
    "salt_env",
    "receiver.key_env",
    "receiver.ssh",
    "receiver.path_prefix",
    "agency.contacts",
)

#: A placeholder: the whole string in brackets, with at least one letter inside and no bracket.
#: The letter keeps ``[::1]`` an address; where a value may be either, the address is tried
#: first (``targets[].host``).
_PLACEHOLDER = re.compile(r"\[[^\[\]]*[A-Za-z][^\[\]]*\]")
#: The same, for the code that writes a draft (:mod:`.intake`).
PLACEHOLDER_SHAPE = _PLACEHOLDER
#: ISO 8601 in UTC, to the second, with three or six fractional digits at most — what Python
#: 3.10's ``fromisoformat`` takes once ``Z`` is spelled ``+00:00``.
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})?(?:Z|\+00:00)")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
#: The shape of an IANA zone name (``UTC``, ``Europe/Berlin``, ``Etc/GMT+1``). Only the shape:
#: whether this machine's zone database knows it must not decide whether a file loads.
_ZONE = re.compile(r"[A-Za-z][A-Za-z0-9_+-]{0,31}(?:/[A-Za-z0-9_+-]{1,32}){0,3}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
#: What a target's ``paths`` may list: printable ASCII from a ``/``. A listed path is compared
#: with a URL's path exactly; a query or a fragment never matches.
TARGET_PATH = re.compile(r"/[!-~]*")
_PATH = TARGET_PATH

#: Unicode categories kept off the terminal, as ``cli.display`` keeps them off.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


class EngagementError(ValueError):
    """An engagement file that cannot be used, with the file and the place in it.

    Shaped like :class:`mcp_kymograph.corpus.ManifestError`: the file is kept apart from the
    reason, as ``source``, so whoever has to shorten the message shortens the path and never
    the reason.
    """

    def __init__(self, reason: str, *, source: str | None = None) -> None:
        super().__init__(reason if source is None else f"{source}: {reason}")
        self.source = source
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Target:
    """One entry of ``targets``. ``host`` is as written; ``name`` is what
    :func:`authorization.split_target` made of it for comparing, or None for a placeholder."""

    host: str
    name: str | None
    #: None: any port, and a target without one (a local target only). A tuple: only these.
    ports: tuple[int, ...] | None = None
    #: None: any path (a local target only). A tuple: only these, compared exactly with a URL's
    #: path.
    paths: tuple[str, ...] | None = None
    #: The floor for this target, or None for none.
    isolation: str | None = None
    #: True when the file names no ports for an endpoint target and ``ports`` is the gate's
    #: reading of that — the scheme's port, :data:`ENDPOINT_DEFAULT_PORTS` — not the file's
    #: words. ``data`` keeps the file as written; ``render`` says the default was applied.
    ports_defaulted: bool = False
    #: The protocol generation the customer says this server speaks (``legacy`` or ``modern``),
    #: and the version if they name one, or None. A statement to compare the detected generation
    #: with, recorded and reported when they differ; the run is not stopped by it.
    era: str | None = None
    era_version: str | None = None


@dataclass(frozen=True, slots=True)
class ListedScenario:
    """One entry of ``scenarios``: the path as written and the SHA-256 it was checked against."""

    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class Identity:
    """One entry of ``identities``: a name, a role, and where its token comes from. No value."""

    name: str
    #: None when the file still holds a placeholder for it (listed in ``placeholders``).
    role: str | None
    #: The environment variable the token is read from, or None.
    token_env: str | None = None
    #: The token file as written (relative to the engagement file's directory), or None.
    token_file: str | None = None
    #: The secret headers this identity sends, ``(header name, environment variable)`` in the
    #: order the file lists them. Their values are read when the run starts.
    headers: tuple[tuple[str, str], ...] = ()
    #: One of :data:`OBSERVATIONS`, or None: a run as this identity is then a token observation.
    observation: str | None = None

    @property
    def source(self) -> str:
        """``env``, ``file`` or ``none``, as ``run_started.auth.source`` says it."""
        if self.token_env is not None:
            return "env"
        return "file" if self.token_file is not None else "none"


@dataclass(frozen=True, slots=True)
class Tool:
    """One entry of ``tools``: a tool the engagement allows, and whether it writes."""

    name: str
    writes: bool


@dataclass(frozen=True, slots=True)
class Canary:
    """One entry of ``canaries``: where one was planted, and whether the agency has taken it out.

    ``path`` is the file of a ``file`` canary, outside what the server may read: the tool cannot
    check that. ``removed`` is the date the agency confirmed it gone, or None for still there.
    """

    id: str
    kind: str
    #: None when the file still holds a placeholder for it (listed in ``placeholders``).
    where: str | None
    path: str | None = None
    removed: date | None = None


@dataclass(frozen=True, slots=True)
class Receiver:
    """``receiver``: where the callback of a canary is received. Holds no key."""

    variant: str
    address: str | None = None
    path_prefix: str | None = None
    #: The environment variable that holds the receiver's key, or None.
    key_env: str | None = None
    #: A reference to the receiver's host (``<RECEIVER_SSH>``), never a key.
    ssh: str | None = None
    retention_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class Engagement:
    """A loaded engagement file.

    ``data`` is the file as parsed, every key as written; the other fields are what the gate
    and the recording read from it. A time or a host that is a placeholder is None here and
    listed in ``placeholders``.
    """

    source: str
    #: SHA-256 of the file's bytes, as read. Which file a run was gated against — a fact.
    digest: str
    data: dict[str, Any]
    id: str
    window_from: datetime | None
    window_until: datetime | None
    tz: str | None
    targets: tuple[Target, ...]
    scenarios: tuple[ListedScenario, ...]
    actions_list: bool
    actions_call: bool
    customer: str | None = None
    supersedes: str | None = None
    delete_after: date | None = None
    mask_keys: tuple[str, ...] = ()
    mask_patterns: tuple[str, ...] = ()
    #: Where the file still holds a placeholder, as key paths (``window.from``,
    #: ``targets[0].host``). Not empty: the file is a draft, and the gate refuses it.
    placeholders: tuple[str, ...] = ()
    #: Who a run may speak as (``--identity``), in the file's order; empty when the file names
    #: none.
    identities: tuple[Identity, ...] = ()
    #: Header names the file declares secret for every run under it: their values are replaced
    #: whole in what is recorded, whether the run sends them or not.
    secret_headers: tuple[str, ...] = ()
    #: The format version of the file: 1 or 2. The fields below are those of the second.
    version: int = FORMAT_VERSION
    #: ``agency.name``, or None without an agency (the client is then the end customer).
    agency: str | None = None
    #: The tools the file allows, or None when it lists none and only ``actions`` applies.
    tools: tuple[Tool, ...] | None = None
    #: ``actions.write``: whether a tool marked ``writes: true`` may be called. False when the
    #: file does not say, and always in a file of the first version.
    actions_write: bool = False
    #: ``deny_tools``: tool names that are never called, listed or not; empty for none.
    deny_tools: tuple[str, ...] = ()
    #: ``actions.probes``: the names of the probe modules a run under the file may use
    #: (``drive --probe``); empty for none, and always in a file of the first version.
    actions_probes: tuple[str, ...] = ()
    #: Where the stop file of this engagement is (:func:`stop_path`): beside the file as it was
    #: loaded, by an absolute path made when it was read. None for a file not read from a path.
    #: Not part of what the file says, so not compared: two loads of the same bytes are equal.
    stop_file: str | None = field(default=None, compare=False)
    #: The second stop file (:func:`stop_path_as_given`): beside the path the file was loaded by,
    #: not resolved, so that it is looked for afresh and follows a link put somewhere else.
    stop_file_as_given: str | None = field(default=None, compare=False)
    abort_criteria: tuple[str, ...] = ()
    #: How many strings ``known_values`` holds; the values themselves are in ``data`` only.
    known_value_count: int = 0
    #: The environment variable the salt is read from.
    salt_env: str | None = None
    canaries: tuple[Canary, ...] = ()
    receiver: Receiver | None = None
    #: ``token_passthrough.method``, or None for none declared.
    token_passthrough: str | None = None

    #: What :meth:`sanitized` takes out, as key paths: what a store's chain entry says it left
    #: out (``Store.set_engagement(removed=…)``).
    removed: ClassVar[tuple[str, ...]] = REMOVED

    @property
    def is_draft(self) -> bool:
        return bool(self.placeholders)

    def sanitized(self) -> dict[str, Any]:
        """The file as parsed without what :attr:`removed` names: what may be stored and handed
        on. A copy; changing it changes nothing here."""
        kept = copy.deepcopy(self.data)
        kept.pop("contacts", None)
        kept.pop("reference", None)
        redaction = kept.get("redaction")
        if isinstance(redaction, dict):
            redaction.pop("mask_patterns", None)
        declared = kept.get("declared")
        servers = declared.get("servers") if isinstance(declared, dict) else None
        for server in servers if isinstance(servers, list) else ():
            if isinstance(server, dict):
                server.pop("owner_contact", None)
        identities = kept.get("identities")
        for identity in identities if isinstance(identities, list) else ():
            if isinstance(identity, dict):
                identity.pop("token_file", None)
        for key in ("known_values", "emergency", "salt_env"):
            kept.pop(key, None)
        receiver = kept.get("receiver")
        if isinstance(receiver, dict):
            receiver.pop("key_env", None)
            receiver.pop("ssh", None)
            receiver.pop("path_prefix", None)
        agency = kept.get("agency")
        if isinstance(agency, dict):
            agency.pop("contacts", None)
        return kept

    def declared_era(self, url: str) -> dict[str, str | None] | None:
        """The generation (``era`` and ``version``, the version possibly None) the file declares
        for the target a URL reaches, or None when that target declares none or no target
        matches. The match is the gate's: host, port and path."""
        try:
            reach = _url_reach(url)
        except EngagementRefused:
            return None
        for target in self.targets:
            if target.name is None or target.name != reach.name or target.era is None:
                continue
            if target.ports is not None and reach.port not in target.ports:
                continue
            if target.paths is not None and reach.path not in target.paths:
                continue
            return {"era": target.era, "version": target.era_version}
        return None

    def identity(self, name: str) -> Identity | None:
        """The identity of that name, or None."""
        return next((identity for identity in self.identities if identity.name == name), None)

    def window_declared(self) -> dict[str, str] | None:
        """The window as the recording carries it — ``{"from", "until"}``, UTC, ending in ``Z``
        — or None for a draft whose window is not filled in."""
        if self.window_from is None or self.window_until is None:
            return None
        return {"from": utc_text(self.window_from), "until": utc_text(self.window_until)}


def declaration_fields(engagement: Engagement | None) -> dict[str, Any]:
    """What :class:`authorization.Declaration` takes from an engagement file — its id, its
    digest, its window — as keyword arguments; all None without a file. Nothing else of the
    file enters a recording."""
    if engagement is None:
        return {"engagement_id_declared": None, "engagement_digest": None, "window_declared": None}
    return {
        "engagement_id_declared": engagement.id,
        "engagement_digest": engagement.digest,
        "window_declared": engagement.window_declared(),
    }


def utc_text(moment: datetime) -> str:
    """An aware time as ISO 8601 in UTC, ending in ``Z``."""
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# -- reading ------------------------------------------------------------------------------


def load(path: str | Path) -> Engagement:
    """Read, parse and validate one engagement file, or raise :class:`EngagementError`.

    Scenario files are resolved against the engagement file's directory and checked against
    their listed SHA-256 now, so a file that names a scenario it does not hold is refused here
    and not at the run that would use it.
    """
    path = Path(path)
    source = str(path)
    suffix = path.suffix.lower()
    if suffix not in (".json", ".yaml", ".yml"):
        raise EngagementError(f"unknown suffix {suffix!r}; use .yaml, .yml or .json", source=source)
    raw = _read_capped(path, source)
    held = loads(raw, source=source, directory=path.resolve().parent, suffix=suffix)
    return replace(
        held, stop_file=str(stop_path(path)), stop_file_as_given=str(stop_path_as_given(path))
    )


# -- the stop file --------------------------------------------------------------------------

#: What is added to an engagement file's name to name its stop file: ``acme.yaml`` is stopped by
#: ``acme.yaml.stop``, in the same directory.
STOP_SUFFIX = ".stop"

#: How much of the reason an operator gives for a stop is kept.
MAX_STOP_REASON = 200


def stop_path(engagement_file: str | Path) -> Path:
    """The stop file of an engagement file: beside it, named as it is with ``.stop`` added. An
    absolute path, made from the real file: symlinks of the file and of every directory are
    resolved, so the stop file is the same whichever path the file is reached by. Two hard links
    to one file have a stop file each: stop by the path the runs were started with."""
    resolved = Path(os.path.realpath(engagement_file))
    return resolved.with_name(resolved.name + STOP_SUFFIX)


def stop_path_as_given(engagement_file: str | Path) -> Path:
    """The stop file beside the path as it was given: absolute, but not resolved. A run looks
    for this one too, and every time through the filesystem, so a link that is pointed elsewhere
    during the run takes the name along. The working directory is put before a relative path;
    ``..`` is not cut out, for the system reads it after a link, as ``engagement stop`` does over
    the same text. An absolute path is taken as written, without asking for the working
    directory. ``engagement stop`` writes only :func:`stop_path`."""
    text = os.fspath(engagement_file)
    given = Path(text if os.path.isabs(text) else os.path.join(os.getcwd(), text))
    return given.with_name(given.name + STOP_SUFFIX)


def stop_file_present(path: str | Path | None) -> bool:
    """Whether the stop file is there. Only that: it is never opened or read, and what it is does
    not matter — a symlink (a dangling one too), a directory, a device all stop. A path that
    cannot be looked at for any reason but its absence stops too: when in doubt, the run stops.
    None (no file to name one) stops nothing."""
    if path is None:
        return False
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def stop_file_resolved_now(stop_file_as_given: str | None) -> bool:
    """Whether the stop file beside the target of the path as given, resolved now, is there. The
    path is taken from the second stop file's name (:func:`stop_path_as_given`) and resolved at
    every check, so a link pointed elsewhere after the load, a link to the file itself too, names
    the file ``engagement stop`` writes today. As in :func:`stop_file_present`: a file that is
    gone stops nothing by this name, any other failure of the resolving (no rights, a loop, a
    name too long) stops."""
    if stop_file_as_given is None:
        return False
    given = stop_file_as_given.removesuffix(STOP_SUFFIX)
    try:
        resolved = os.path.realpath(given, strict=True)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, RuntimeError, ValueError):
        return True
    return stop_file_present(resolved + STOP_SUFFIX)


def stopped(engagement: Engagement | None) -> bool:
    """Whether one of the engagement's three stop files is there (:func:`stop_file_present`):
    beside the file as resolved at load, beside the path as given, and beside the path as given
    resolved now (:func:`stop_file_resolved_now`)."""
    return engagement is not None and (
        stop_file_present(engagement.stop_file)
        or stop_file_present(engagement.stop_file_as_given)
        or stop_file_resolved_now(engagement.stop_file_as_given)
    )


def write_stop_file(path: Path, *, reason: str | None, masker: Masker, now: datetime) -> None:
    """Write the stop file: mode 0600, JSON with the time (UTC) and the reason, cut and masked
    as other text the operator typed. An existing stop file is replaced in one step: the new file
    is made beside it under another name and put in its place with ``os.replace``, so there is
    no moment without a stop file. A link in its place is replaced, not written through. If
    anything fails the old file stays, the temporary one is removed and the error goes on."""
    kept = None
    if reason is not None:
        # Masked first and cut after: cut first, a token could be left too short to be known.
        kept = masker.mask_text(_safe(reason))[0][:MAX_STOP_REASON]
    body = json.dumps({"time": utc_text(now), "reason": kept}, separators=(",", ":")) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".stop-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            # By the descriptor, not the path: mkstemp's 0600 does not depend on the umask here.
            os.fchmod(handle.fileno(), FILE_MODE)
            handle.write(body)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def clear_stop_file(path: Path) -> bool:
    """Remove the stop file; False when there was none."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    return True


def loads(raw: bytes, *, source: str, directory: Path, suffix: str | None = None) -> Engagement:
    """:func:`load` over bytes already read, or raise :class:`EngagementError`.

    ``source`` names the file in every refusal; ``directory`` is where listed scenario files
    are resolved, as the engagement file's own directory is for :func:`load`. ``suffix`` says
    the format (``.json``, ``.yaml`` or ``.yml``), the suffix of ``source`` when not given. The
    digest is the SHA-256 of ``raw``, so bytes written to a file as they are load from it with
    the same digest.
    """
    suffix = (Path(source).suffix if suffix is None else suffix).lower()
    if suffix not in (".json", ".yaml", ".yml"):
        raise EngagementError(f"unknown suffix {suffix!r}; use .yaml, .yml or .json", source=source)
    if len(raw) > MAX_FILE_BYTES:
        raise EngagementError(f"larger than {MAX_FILE_BYTES} bytes", source=source)
    try:
        text = raw.decode("utf-8")
        data = (
            parse_json(text, source=source)
            if suffix == ".json"
            else parse_yaml(text, source=source)
        )
    except UnicodeDecodeError as exc:
        raise EngagementError(f"not UTF-8 at byte {exc.start}", source=source) from None
    except ScenarioError as exc:
        # The parsers name the file first, as ``source: reason``, and speak of a scenario
        # where the extra is missing; the reason is theirs, the file is ours.
        reason = str(exc).removeprefix(f"{source}: ").replace("write the scenario", "write it")
        raise EngagementError(reason, source=source) from None
    digest = hashlib.sha256(raw).hexdigest()
    try:
        return _Reader(directory, digest).engagement(data, source)
    except _Invalid as invalid:
        where = f"{invalid.where}: " if invalid.where else ""
        raise EngagementError(f"{where}{invalid.message}", source=source) from None


def _read_capped(path: Path, source: str) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise EngagementError(f"cannot read: {exc.strerror or exc}", source=source) from None
    if len(raw) > MAX_FILE_BYTES:
        raise EngagementError(f"larger than {MAX_FILE_BYTES} bytes", source=source)
    return raw


class _Invalid(Exception):
    def __init__(self, where: str, message: str) -> None:
        super().__init__(message)
        self.where = where
        self.message = message


def token_file_inside(directory: Path, token_file: str) -> bool:
    """Whether ``token_file``, relative to ``directory``, lies inside it once symbolic links are
    followed (``Path.resolve``): a link that stays inside is fine, one that leaves is not."""
    try:
        return (directory / token_file).resolve().is_relative_to(directory.resolve())
    except (OSError, RuntimeError, ValueError):  # a link loop, a name the system refuses
        return False


class _Reader:
    """One file's validation. Collects placeholders on the way; raises :class:`_Invalid`."""

    def __init__(self, directory: Path, digest: str) -> None:
        self.directory = directory
        self.digest = digest
        self.placeholders: list[str] = []

    def engagement(self, data: Any, source: str) -> Engagement:
        _mapping(data, "", "the engagement file must be a mapping")
        version = _required(data, "version", "")
        if type(version) is not int or version not in READABLE_VERSIONS:
            raise _Invalid("version", f"unsupported {version!r}; this reader reads 1 and 2")
        second = version == FORMAT_VERSION_2
        if second and "customer" in data:
            raise _Invalid(
                "customer",
                "not a key of version 2; name end_customer and, if there is one, agency",
            )
        _only(data, _TOP_KEYS_V2 if second else _TOP_KEYS, "")
        for key in _REQUIRED_TOP_V2 if second else _REQUIRED_TOP:
            _required(data, key, "")
        identifier = data["id"]
        if not isinstance(identifier, str) or not _NAME.fullmatch(identifier):
            raise _Invalid("id", "is not a name: 1-64 letters, digits, . _ -")
        customer = self.text(data, "customer", "") if "customer" in data else None
        if "reference" in data:
            self.text(data, "reference", "")
        if "contacts" in data:
            self.contacts(data["contacts"], "contacts")
        window_from, window_until, tz = self.window(data["window"])
        targets = self.targets(data["targets"])
        scenarios = self.scenarios(data["scenarios"]) if "scenarios" in data else ()
        actions_list, actions_call, actions_write, actions_probes = self.actions(
            data["actions"], second
        )
        if "pacing" in data:
            self.pacing(data["pacing"])
        delete_after = (
            self.retention(data["retention"], window_until) if "retention" in data else None
        )
        mask_keys, mask_patterns = (
            self.redaction(data["redaction"]) if "redaction" in data else ((), ())
        )
        supersedes = self.supersedes(data["supersedes"]) if "supersedes" in data else None
        if "declared" in data:
            _declared(data["declared"])
        identities = (
            self.identities(data["identities"], second=second) if "identities" in data else ()
        )
        secret_headers = _secret_headers(data["secret_headers"]) if "secret_headers" in data else ()
        later = self.second(data, actions_write) if second else {}
        return Engagement(
            source=source,
            digest=self.digest,
            data=copy.deepcopy(data),
            id=identifier,
            window_from=window_from,
            window_until=window_until,
            tz=tz,
            targets=targets,
            scenarios=scenarios,
            actions_list=actions_list,
            actions_call=actions_call,
            supersedes=supersedes,
            delete_after=delete_after,
            mask_keys=mask_keys,
            mask_patterns=mask_patterns,
            placeholders=tuple(self.placeholders),
            identities=identities,
            secret_headers=secret_headers,
            version=version,
            actions_probes=actions_probes,
            **({"customer": customer} | later),
        )

    def second(self, data: dict, actions_write: bool = False) -> dict[str, Any]:
        """The fields only a file of the second version has, as :class:`Engagement` takes them.
        ``customer`` is the end customer's name, as the rest of the tool reads it."""
        agency = self.agency(data["agency"]) if "agency" in data else None
        customer = self.end_customer(data["end_customer"])
        self.emergency(data["emergency"])
        tools = self.tools(data["tools"]) if "tools" in data else None
        if actions_write and not any(tool.writes for tool in tools or ()):
            raise _Invalid(
                "actions.write",
                "true, and no entry of tools has writes: true; the release would name nothing",
            )
        return {
            "customer": customer,
            "agency": agency,
            "tools": tools,
            "actions_write": actions_write,
            "deny_tools": (
                self.deny_tools(data["deny_tools"], tools) if "deny_tools" in data else ()
            ),
            "abort_criteria": self.abort_criteria(data["abort_criteria"]),
            "known_value_count": (
                self.known_values(data["known_values"], data["id"]) if "known_values" in data else 0
            ),
            "salt_env": self.env(data, "salt_env", ""),
            "canaries": self.canaries(data["canaries"]) if "canaries" in data else (),
            "receiver": self.receiver(data["receiver"]) if "receiver" in data else None,
            "token_passthrough": (
                self.passthrough(data["token_passthrough"]) if "token_passthrough" in data else None
            ),
        }

    # -- one value

    def text(self, mapping: dict, key: str, where: str, *, placeholder: bool = True) -> str | None:
        """A non-empty string, or None for a placeholder (recorded where it is)."""
        here = f"{where}.{key}" if where else key
        value = _required(mapping, key, where)
        if not isinstance(value, str) or not value:
            raise _Invalid(here, "expected a non-empty string")
        if placeholder and _PLACEHOLDER.fullmatch(value):
            self.placeholders.append(here)
            return None
        return value

    def time(self, mapping: dict, key: str, where: str) -> datetime | None:
        here = f"{where}.{key}"
        value = self.text(mapping, key, where)
        if value is None:
            return None
        if not _UTC_TIME.fullmatch(value):
            raise _Invalid(
                here,
                f"{value!r} is not a time in UTC: write ISO 8601 with Z or +00:00, as "
                "2026-10-27T06:00:00Z; a time without an offset or with another is refused",
            )
        try:
            # Python 3.10's fromisoformat takes no "Z"; it is the same offset spelled otherwise.
            spelled = value[:-1] + "+00:00" if value.endswith("Z") else value
            return datetime.fromisoformat(spelled)
        except ValueError:
            raise _Invalid(here, f"{value!r} is not a time that exists") from None

    # -- sections

    def contacts(self, listed: Any, field: str) -> None:
        _list(listed, field)
        for index, item in enumerate(listed):
            where = f"{field}[{index}]"
            _mapping(item, where, "expected a mapping with name, role, reach")
            _only(item, _CONTACT_KEYS, where)
            self.text(item, "name", where)
            for key in ("role", "reach"):
                if key in item:
                    self.text(item, key, where)

    def window(self, window: Any) -> tuple[datetime | None, datetime | None, str | None]:
        _mapping(window, "window", "expected a mapping with from, until and optionally tz")
        _only(window, _WINDOW_KEYS, "window")
        start = self.time(window, "from", "window")
        end = self.time(window, "until", "window")
        if start is not None and end is not None and end <= start:
            raise _Invalid("window.until", "is not after window.from")
        tz = None
        if "tz" in window:
            tz = self.text(window, "tz", "window")
            if tz is not None and not _ZONE.fullmatch(tz):
                raise _Invalid("window.tz", f"{tz!r} is not a time zone name, as Europe/Berlin")
        return start, end, tz

    def targets(self, listed: Any) -> tuple[Target, ...]:
        if not isinstance(listed, list) or not listed:
            raise _Invalid("targets", "expected a non-empty list: a run under a file names one")
        return tuple(self.target(item, f"targets[{i}]") for i, item in enumerate(listed))

    def target(self, item: Any, where: str) -> Target:
        _mapping(item, where, "expected a mapping with host and optionally ports, paths, isolation")
        _only(item, _TARGET_KEYS, where)
        host = _required(item, "host", where)
        if not isinstance(host, str) or not host:
            raise _Invalid(f"{where}.host", "expected a non-empty string")
        # An address first: "[::1]" is bracketed, and is a host, not a placeholder.
        split = split_target(host)
        if split is None and _PLACEHOLDER.fullmatch(host):
            self.placeholders.append(f"{where}.host")
            name = None
        elif split is None:
            raise _Invalid(
                f"{where}.host",
                f"{host!r} cannot be taken apart as a host: a name, an IPv4 address or a "
                "bracketed IPv6 address, with no scheme, path or port",
            )
        elif split[1] is not None:
            raise _Invalid(f"{where}.host", f"{host!r} carries a port; list it under ports")
        else:
            name = split[0]
        ports = _ports(item["ports"], f"{where}.ports") if "ports" in item else None
        paths = self.paths(item["paths"], f"{where}.paths") if "paths" in item else None
        defaulted = False
        if name is not None and not is_local(name):
            # Somebody else's server: what may be reached there is listed, never "any".
            if "paths" not in item:
                raise _Invalid(
                    f"{where}.paths",
                    f"missing: {host!r} is not a local host, and scope against somebody else's "
                    "server is not any path; list the paths the engagement covers",
                )
            if ports is None:
                ports, defaulted = ENDPOINT_DEFAULT_PORTS, True
        isolation = None
        if "isolation" in item:
            isolation = item["isolation"]
            if isolation not in ISOLATIONS:
                raise _Invalid(
                    f"{where}.isolation",
                    f"unknown isolation {isolation!r}; expected one of {', '.join(ISOLATIONS)}",
                )
        era, era_version = self.era(item, where)
        return Target(
            host=host,
            name=name,
            ports=ports,
            paths=paths,
            isolation=isolation,
            ports_defaulted=defaulted,
            era=era,
            era_version=era_version,
        )

    def era(self, item: dict, where: str) -> tuple[str | None, str | None]:
        """The generation a target declares, and its version if it names one."""
        era = item.get("era")
        version = item.get("version")
        if era is None:
            if version is not None:
                raise _Invalid(f"{where}.version", "a version is named with an era; add era")
            return None, None
        if era not in _ERAS:
            raise _Invalid(f"{where}.era", f"expected one of {', '.join(_ERAS)}")
        if version is not None and not (isinstance(version, str) and _VERSION.fullmatch(version)):
            raise _Invalid(f"{where}.version", "expected a protocol version such as 2025-11-25")
        return era, version

    def paths(self, listed: Any, where: str) -> tuple[str, ...]:
        if not isinstance(listed, list) or not listed:
            raise _Invalid(where, "expected a non-empty list of paths; leave it out for any path")
        paths: list[str] = []
        for index, value in enumerate(listed):
            here = f"{where}[{index}]"
            if isinstance(value, str) and _PLACEHOLDER.fullmatch(value):
                self.placeholders.append(here)
                continue
            if not isinstance(value, str) or not _PATH.fullmatch(value) or "?" in value:
                raise _Invalid(here, f"{value!r} is not a path: it starts with / and has no query")
            if "#" in value:
                raise _Invalid(here, f"{value!r} is not a path: it has a fragment")
            if value in paths:
                raise _Invalid(here, f"{value!r} is listed twice")
            paths.append(value)
        return tuple(paths)

    def scenarios(self, listed: Any) -> tuple[ListedScenario, ...]:
        _list(listed, "scenarios")
        result: list[ListedScenario] = []
        for index, item in enumerate(listed):
            where = f"scenarios[{index}]"
            _mapping(item, where, "expected a mapping with path and sha256")
            _only(item, _SCENARIO_KEYS, where)
            written = _required(item, "path", where)
            if not isinstance(written, str) or not written or Path(written).is_absolute():
                raise _Invalid(f"{where}.path", "expected a path relative to the engagement file")
            expected = _required(item, "sha256", where)
            if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
                raise _Invalid(f"{where}.sha256", "expected 64 lowercase hexadecimal digits")
            try:
                with (self.directory / written).open("rb") as handle:
                    raw = handle.read(MAX_FILE_BYTES + 1)
            except OSError as exc:
                raise _Invalid(f"{where}.path", f"cannot read: {exc.strerror or exc}") from None
            if len(raw) > MAX_FILE_BYTES:
                raise _Invalid(f"{where}.path", f"larger than {MAX_FILE_BYTES} bytes")
            actual = hashlib.sha256(raw).hexdigest()
            if actual != expected:
                raise _Invalid(
                    f"{where}.sha256",
                    f"the file's SHA-256 is {actual}, not the one listed: it changed, or the "
                    "listing is wrong",
                )
            result.append(ListedScenario(written, expected))
        return tuple(result)

    def actions(
        self, actions: Any, second: bool = False
    ) -> tuple[bool, bool, bool, tuple[str, ...]]:
        _mapping(actions, "actions", "expected a mapping with list and call")
        _only(actions, _ACTION_KEYS_V2 if second else _ACTION_KEYS, "actions")
        values = []
        for key in ("list", "call"):
            value = _required(actions, key, "actions")
            if type(value) is not bool:
                raise _Invalid(f"actions.{key}", "expected true or false")
            values.append(value)
        write = actions.get("write", False)
        if type(write) is not bool:
            raise _Invalid("actions.write", "expected true or false")
        return (
            values[0],
            values[1],
            write,
            self.probes(actions["probes"]) if "probes" in actions else (),
        )

    def probes(self, listed: Any) -> tuple[str, ...]:
        """``actions.probes``: a list of module names, each once. Whether a module of that name
        exists is not asked here: the file is read without the modules, and a name nothing
        provides is a module no run can use."""
        _list(listed, "actions.probes")
        names: list[str] = []
        for index, name in enumerate(listed):
            here = f"actions.probes[{index}]"
            if not isinstance(name, str) or not PROBE_NAME.fullmatch(name):
                raise _Invalid(here, "expected a module name: lowercase letters, digits, _ and -")
            if name in names:
                raise _Invalid(here, "listed twice")
            names.append(name)
        return tuple(names)

    def pacing(self, pacing: Any) -> None:
        _mapping(pacing, "pacing", "expected a mapping")
        _only(pacing, _PACING_KEYS, "pacing")
        if "runs_per_origin" in pacing:
            runs = pacing["runs_per_origin"]
            if type(runs) is not int or not 1 <= runs <= MAX_RUNS_PER_ORIGIN:
                raise _Invalid(
                    "pacing.runs_per_origin",
                    f"expected a whole number from 1 to {MAX_RUNS_PER_ORIGIN}",
                )
        if "min_interval_seconds" in pacing:
            seconds = pacing["min_interval_seconds"]
            if type(seconds) not in (int, float) or not 0 <= seconds < float("inf"):
                raise _Invalid("pacing.min_interval_seconds", "expected a number of seconds >= 0")

    def retention(self, retention: Any, until: datetime | None) -> date | None:
        """``delete_after`` is a calendar date: what the runs of the engagement are kept
        through, the whole day in UTC. Refused if that day ends before ``window.until`` —
        the data would be due for deletion while runs may still be made."""
        _mapping(retention, "retention", "expected a mapping with delete_after")
        _only(retention, _RETENTION_KEYS, "retention")
        written = self.text(retention, "delete_after", "retention")
        if written is None:
            return None
        if not _DATE.fullmatch(written):
            raise _Invalid("retention.delete_after", f"{written!r} is not a date, as 2027-01-31")
        try:
            day = date.fromisoformat(written)
        except ValueError:
            raise _Invalid(
                "retention.delete_after", f"{written!r} is not a date that exists"
            ) from None
        ends = datetime(day.year, day.month, day.day, tzinfo=timezone.utc) + timedelta(days=1)
        if until is not None and ends < until:
            raise _Invalid(
                "retention.delete_after",
                f"{written} ends before window.until: the runs would be due for deletion "
                "before the last of them may be made",
            )
        return day

    def redaction(self, redaction: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
        _mapping(redaction, "redaction", "expected a mapping")
        _only(redaction, _REDACTION_KEYS, "redaction")
        found = []
        for key in ("mask_keys", "mask_patterns"):
            values = redaction.get(key, [])
            where = f"redaction.{key}"
            _list(values, where)
            for index, value in enumerate(values):
                if not isinstance(value, str) or not value:
                    raise _Invalid(f"{where}[{index}]", "expected a non-empty string")
            found.append(tuple(values))
        return found[0], found[1]

    def identities(self, listed: Any, *, second: bool = False) -> tuple[Identity, ...]:
        """Who a run may speak as. What an error says never repeats a value the file holds under
        a key that takes a source: a mistake there may be a credential."""
        if not isinstance(listed, list) or not listed:
            raise _Invalid("identities", "expected a non-empty list; leave it out for none")
        found: list[Identity] = []
        names: set[str] = set()
        for index, item in enumerate(listed):
            where = f"identities[{index}]"
            _mapping(item, where, "expected a mapping with name, role and a token source")
            _only(item, _IDENTITY_KEYS_V2 if second else _IDENTITY_KEYS, where)
            name = _required(item, "name", where)
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                raise _Invalid(f"{where}.name", "is not a name: 1-64 letters, digits, . _ -")
            if name in names:
                raise _Invalid(f"{where}.name", f"{name!r} is listed twice")
            names.add(name)
            role = self.text(item, "role", where)
            given = [key for key in _TOKEN_SOURCES if key in item]
            if len(given) != 1:
                raise _Invalid(
                    where,
                    "expected exactly one of token_env: NAME, token_file: PATH or token: none; "
                    "the file holds no token",
                )
            token_env = token_file = None
            if given[0] == "token_env":
                token_env = item["token_env"]
                if not isinstance(token_env, str) or not ENV_NAME.fullmatch(token_env):
                    raise _Invalid(
                        f"{where}.token_env",
                        "expected the name of an environment variable (letters, digits, _)",
                    )
            elif given[0] == "token_file":
                token_file = item["token_file"]
                if (
                    not isinstance(token_file, str)
                    or not token_file
                    or Path(token_file).is_absolute()
                ):
                    raise _Invalid(
                        f"{where}.token_file", "expected a path relative to the engagement file"
                    )
                if not token_file_inside(self.directory, token_file):
                    raise _Invalid(
                        f"{where}.token_file",
                        "expected a path inside the engagement file's directory",
                    )
            elif item["token"] != NO_SOURCE:
                raise _Invalid(
                    f"{where}.token",
                    f"the file holds no token: write token: {NO_SOURCE}, or name a source with "
                    "token_env or token_file",
                )
            observation = _observation(item, f"{where}.observation", given[0])
            headers = self.headers(item["headers"], f"{where}.headers") if "headers" in item else ()
            found.append(Identity(name, role, token_env, token_file, headers, observation))
        return tuple(found)

    def headers(self, listed: Any, where: str) -> tuple[tuple[str, str], ...]:
        _mapping(listed, where, "expected a mapping of header names to env: NAME")
        found: list[tuple[str, str]] = []
        for index, (name, source) in enumerate(listed.items()):
            here = f"{where}[{index}]"
            if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
                raise _Invalid(here, "is not a header name")
            if name.lower() in RESERVED_HEADERS:
                raise _Invalid(here, f"{name} is a header this tool sends itself or owns")
            if any(name.lower() == other.lower() for other, _ in found):
                raise _Invalid(here, f"{name} is listed twice")
            if (
                not isinstance(source, dict)
                or set(source) != {"env"}
                or not isinstance(source["env"], str)
                or not ENV_NAME.fullmatch(source["env"])
            ):
                raise _Invalid(
                    here,
                    f"expected a mapping with env: NAME, the name of an environment variable "
                    f"for {name}; the file holds no value",
                )
            found.append((name, source["env"]))
        return tuple(found)

    # -- the second version

    def env(self, mapping: dict, key: str, where: str) -> str | None:
        """The name of an environment variable, or None for a placeholder. Never a value: what
        is wrong is not repeated, as a mistake here may be the secret itself."""
        here = f"{where}.{key}" if where else key
        value = _required(mapping, key, where)
        if isinstance(value, str) and _PLACEHOLDER.fullmatch(value):
            self.placeholders.append(here)
            return None
        if not isinstance(value, str) or not ENV_NAME.fullmatch(value):
            raise _Invalid(
                here,
                "expected the name of an environment variable (letters, digits, _), not a value",
            )
        return value

    def agency(self, agency: Any) -> str | None:
        _mapping(agency, "agency", "expected a mapping with name and optionally contacts")
        _only(agency, _AGENCY_KEYS, "agency")
        name = self.text(agency, "name", "agency")
        if "contacts" in agency:
            self.contacts(agency["contacts"], "agency.contacts")
        return name

    def end_customer(self, end_customer: Any) -> str | None:
        _mapping(end_customer, "end_customer", "expected a mapping with name")
        _only(end_customer, _END_CUSTOMER_KEYS, "end_customer")
        return self.text(end_customer, "name", "end_customer")

    def tools(self, listed: Any) -> tuple[Tool, ...]:
        if not isinstance(listed, list) or not listed:
            raise _Invalid("tools", "expected a non-empty list; leave it out to list none")
        found: list[Tool] = []
        names: set[str] = set()
        for index, item in enumerate(listed):
            where = f"tools[{index}]"
            _mapping(item, where, "expected a mapping with name and writes")
            _only(item, _TOOL_KEYS, where)
            name = self.text(item, "name", where, placeholder=False)
            writes = _required(item, "writes", where)
            if type(writes) is not bool:
                raise _Invalid(f"{where}.writes", "expected true or false")
            if name in names:
                raise _Invalid(f"{where}.name", f"{name!r} is listed twice")
            names.add(name)
            found.append(Tool(name, writes))
        return tuple(found)

    def deny_tools(self, listed: Any, tools: tuple[Tool, ...] | None) -> tuple[str, ...]:
        if not isinstance(listed, list) or not listed:
            raise _Invalid("deny_tools", "expected a non-empty list; leave it out to deny none")
        found: list[str] = []
        for index, name in enumerate(listed):
            where = f"deny_tools[{index}]"
            if not isinstance(name, str) or not name:
                raise _Invalid(where, "expected a non-empty tool name")
            if name in found:
                raise _Invalid(where, f"{name!r} is listed twice")
            if any(name == tool.name for tool in tools or ()):
                raise _Invalid(where, f"{name!r} is in tools as well; a tool is allowed or denied")
            found.append(name)
        return tuple(found)

    def abort_criteria(self, listed: Any) -> tuple[str, ...]:
        if not isinstance(listed, list) or not listed:
            raise _Invalid("abort_criteria", "expected a non-empty list of sentences")
        found = []
        for index, item in enumerate(listed):
            here = f"abort_criteria[{index}]"
            if not isinstance(item, str) or not item.strip():
                raise _Invalid(here, "expected a non-empty sentence")
            if _PLACEHOLDER.fullmatch(item):
                self.placeholders.append(here)
            found.append(item)
        return tuple(found)

    def emergency(self, emergency: Any) -> None:
        _mapping(emergency, "emergency", "expected a mapping with name and reach")
        _only(emergency, _EMERGENCY_KEYS, "emergency")
        self.text(emergency, "name", "emergency")
        self.text(emergency, "reach", "emergency")

    def known_values(self, listed: Any, identifier: str) -> int:
        """Strings to be replaced when written. What an error says never repeats one: each is a
        secret of the customer's, and a mistake here may be one. The ``id`` is written as it
        is (refusals, store, bundle), so it may hold none: a name is refused, not replaced."""
        _list(listed, "known_values")
        first: dict[str, int] = {}
        for index, value in enumerate(listed):
            here = f"known_values[{index}]"
            if not isinstance(value, str):
                raise _Invalid(here, "expected a string")
            if len(value) < MIN_KNOWN_VALUE:
                raise _Invalid(here, f"shorter than {MIN_KNOWN_VALUE} characters")
            if value in first:
                raise _Invalid(here, f"the same value as known_values[{first[value]}]")
            first[value] = index
        for index, value in enumerate(listed):
            if value in identifier:
                raise _Invalid(
                    "id",
                    f"holds known_values[{index}]; choose an id that names no customer value",
                )
        return len(listed)

    def canaries(self, listed: Any) -> tuple[Canary, ...]:
        if not isinstance(listed, list) or not listed:
            raise _Invalid("canaries", "expected a non-empty list; leave it out to list none")
        found: list[Canary] = []
        identifiers: set[str] = set()
        for index, item in enumerate(listed):
            where = f"canaries[{index}]"
            _mapping(item, where, "expected a mapping with id, kind, where and removed")
            _only(item, _CANARY_KEYS, where)
            identifier = _required(item, "id", where)
            if not isinstance(identifier, str) or not _NAME.fullmatch(identifier):
                raise _Invalid(f"{where}.id", "is not a name: 1-64 letters, digits, . _ -")
            if identifier in identifiers:
                raise _Invalid(f"{where}.id", f"{identifier!r} is listed twice")
            identifiers.add(identifier)
            kind = _required(item, "kind", where)
            if kind not in CANARY_KINDS:
                raise _Invalid(f"{where}.kind", f"expected one of {', '.join(CANARY_KINDS)}")
            place = self.text(item, "where", where)
            path = None
            if kind == "file":
                path = self.checked(item, "path", where, _absolute, "an absolute path")
            elif "path" in item:
                raise _Invalid(f"{where}.path", f"not allowed for kind {kind}: only for file")
            if "removed" not in item:
                raise _Invalid(f"{where}.removed", "missing; write null while it is still there")
            removed = self.confirmed(item["removed"], f"{where}.removed")
            found.append(Canary(identifier, kind, place, path, removed))
        return tuple(found)

    def confirmed(self, value: Any, where: str) -> date | None:
        """``removed``: null, or the date the agency confirmed the canary gone."""
        if value is None:
            return None
        if isinstance(value, str) and _PLACEHOLDER.fullmatch(value):
            self.placeholders.append(where)
            return None
        if not isinstance(value, str) or not _DATE.fullmatch(value):
            raise _Invalid(where, "expected null or a date, as 2026-11-04")
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise _Invalid(where, f"{value!r} is not a date that exists") from None

    def checked(self, mapping: dict, key: str, where: str, good: Any, expected: str) -> str | None:
        """A string that ``good`` accepts, or None for a placeholder."""
        here = f"{where}.{key}"
        value = _required(mapping, key, where)
        # What ``good`` accepts first: ``[2001:db8::7]`` has the shape of a placeholder.
        if isinstance(value, str) and good(value):
            return value
        if isinstance(value, str) and _PLACEHOLDER.fullmatch(value):
            self.placeholders.append(here)
            return None
        raise _Invalid(here, f"expected {expected}")

    def receiver(self, receiver: Any) -> Receiver:
        _mapping(receiver, "receiver", "expected a mapping with variant")
        _only(receiver, _RECEIVER_KEYS, "receiver")
        variant = _required(receiver, "variant", "receiver")
        if variant not in RECEIVER_VARIANTS:
            raise _Invalid("receiver.variant", f"expected one of {', '.join(RECEIVER_VARIANTS)}")
        if variant == "reachable":
            for key in _RECEIVER_REACHABLE:
                if key not in receiver or receiver[key] is None:
                    raise _Invalid(f"receiver.{key}", "missing: a reachable receiver needs it")
        address = path_prefix = key_env = ssh = seconds = None
        if "address" in receiver:
            if isinstance(receiver["address"], str) and has_scope_id(receiver["address"]):
                # Not a placeholder, though bracketed text with a letter has that shape.
                raise _Invalid(
                    "receiver.address",
                    "expected host or host:port; an IPv6 address in square brackets, with no "
                    "scope ID",
                )
            address = self.checked(
                receiver,
                "address",
                "receiver",
                good_receiver_address,
                "host or host:port, with no scheme, path, query, fragment or user; an IPv6 "
                "address in square brackets; a port from 1 to 65535",
            )
        if "path_prefix" in receiver:
            path_prefix = self.checked(
                receiver,
                "path_prefix",
                "receiver",
                good_receiver_prefix,
                f"Base64url without padding, {RECEIVER_PREFIX_MIN_LENGTH} to "
                f"{RECEIVER_PREFIX_MAX_LENGTH} characters, at least "
                f"{RECEIVER_PREFIX_MIN_DISTINCT} of them different",
            )
        if "key_env" in receiver:
            key_env = self.env(receiver, "key_env", "receiver")
        if "ssh" in receiver:
            if isinstance(receiver["ssh"], str) and has_scope_id(receiver["ssh"]):
                # As for the address: bracketed text with a letter has the shape of a placeholder.
                raise _Invalid(
                    "receiver.ssh",
                    "a reference to the receiver's host, as [user@]host[:port] or <NAME>; an "
                    "IPv6 address in square brackets, with no scope ID; never a key",
                )
            ssh = self.checked(
                receiver,
                "ssh",
                "receiver",
                good_receiver_ssh,
                "a reference to the receiver's host, as [user@]host[:port] or <NAME>; never a key",
            )
        if "retention_seconds" in receiver:
            seconds = receiver["retention_seconds"]
            if isinstance(seconds, str) and _PLACEHOLDER.fullmatch(seconds):
                self.placeholders.append("receiver.retention_seconds")
                seconds = None
            elif type(seconds) is not int or not 1 <= seconds <= MAX_RETENTION_SECONDS:
                raise _Invalid(
                    "receiver.retention_seconds",
                    f"expected a whole number of seconds, from 1 to {MAX_RETENTION_SECONDS} "
                    "(90 days)",
                )
        return Receiver(variant, address, path_prefix, key_env, ssh, seconds)

    def passthrough(self, passthrough: Any) -> str:
        _mapping(passthrough, "token_passthrough", "expected a mapping with method")
        _only(passthrough, _PASSTHROUGH_KEYS, "token_passthrough")
        method = _required(passthrough, "method", "token_passthrough")
        if method not in PASSTHROUGH_METHODS:
            raise _Invalid(
                "token_passthrough.method", f"expected one of {', '.join(PASSTHROUGH_METHODS)}"
            )
        return method

    def supersedes(self, value: Any) -> str:
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise _Invalid("supersedes", "expected the 64 lowercase hex digits of a file's SHA-256")
        if value == self.digest:
            raise _Invalid("supersedes", "is this file's own digest: a file cannot replace itself")
        return value


def good_receiver_prefix(value: str) -> bool:
    """A receiver ``path_prefix`` as the receiver takes it at ``register``: ``check_prefix`` and
    the count of different characters that ``parse_registration`` adds for a new one."""
    return check_prefix(value) and len(set(value)) >= limits.MIN_PREFIX_DISTINCT_CHARS


def has_scope_id(value: str) -> bool:
    """A bracketed address with a ``%`` inside the brackets. Such a value has the shape of a
    placeholder (brackets around text with a letter), but is no placeholder for an address: it is
    an IPv6 address with a scope ID, which :func:`good_receiver_address` refuses."""
    return value.startswith("[") and "%" in value.partition("]")[0]


def good_receiver_address(value: str) -> bool:
    """``host`` or ``host:port``: a DNS name or an IP address (IPv6 in square brackets), a port
    from 1 to 65535. Nothing that is a scheme, a path, a query, a fragment or a user."""
    if value.startswith("["):
        host, bracket, rest = value[1:].partition("]")
        # No scope ID: ``ipaddress`` takes ``fe80::1%eth0``, but a URL parser reads what follows
        # the ``%`` as it likes, and the probes build ``https://<address>/…`` from this text.
        if not bracket or ":" not in host or "%" in host:
            return False
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        port = rest[1:] if rest.startswith(":") else None
        if rest and port is None:
            return False
    else:
        host, colon, port = value.partition(":")
        port = port if colon else None
        if not host or ":" in (port or ""):
            return False
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            if not _DNS_NAME.fullmatch(host) or host.rsplit(".", 1)[-1].isdigit():
                return False
    return port is None or (_ADDRESS_PORT.fullmatch(port) is not None and 1 <= int(port) <= 65535)


#: The name of an ssh reference kept elsewhere, as ``<RECEIVER_SSH>``.
_SSH_NAME = re.compile(r"<[A-Za-z][A-Za-z0-9_]{0,63}>")
_SSH_USER = re.compile(r"[A-Za-z_][A-Za-z0-9._-]{0,31}")


def good_receiver_ssh(value: str) -> bool:
    """``receiver.ssh`` is a reference, not a key: ``<NAME>``, or ``[user@]host[:port]`` with the
    host and port as :func:`good_receiver_address` takes them. The form is checked, not whether
    a value is secret: a short password looks like a host."""
    if _SSH_NAME.fullmatch(value):
        return True
    user, at, rest = value.partition("@")
    if not at:
        return good_receiver_address(value)
    return _SSH_USER.fullmatch(user) is not None and good_receiver_address(rest)


def declared_customer(declared: dict) -> str | None:
    """The customer's name in a declared engagement file (the file as parsed, or as stored and
    sanitized): ``customer`` in version 1, ``end_customer.name`` in version 2 — never the agency.
    None where the file names none."""
    if declared.get("version") == FORMAT_VERSION_2:
        end_customer = declared.get("end_customer")
        name = end_customer.get("name") if isinstance(end_customer, dict) else None
    else:
        name = declared.get("customer")
    return name if isinstance(name, str) else None


def _absolute(value: str) -> bool:
    return "\0" not in value and Path(value).is_absolute()


def _secret_headers(listed: Any) -> tuple[str, ...]:
    """The header names the file declares secret."""
    _list(listed, "secret_headers")
    found: list[str] = []
    lowered: set[str] = set()
    for index, name in enumerate(listed):
        where = f"secret_headers[{index}]"
        if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
            raise _Invalid(where, "expected a header name")
        if name.lower() in lowered:
            raise _Invalid(where, f"{name} is listed twice")
        lowered.add(name.lower())
        found.append(name)
    return tuple(found)


def _ports(listed: Any, where: str) -> tuple[int, ...]:
    if not isinstance(listed, list) or not listed:
        raise _Invalid(where, "expected a non-empty list of ports; leave it out for any port")
    ports: list[int] = []
    for index, value in enumerate(listed):
        here = f"{where}[{index}]"
        if type(value) is not int or not 1 <= value <= 65535:
            raise _Invalid(here, f"{value!r} is not a port: a whole number from 1 to 65535")
        if value in ports:
            raise _Invalid(here, f"{value} is listed twice")
        ports.append(value)
    return tuple(ports)


def _declared(declared: Any) -> None:
    """The customer's answers, kept as claims: shape only. No placeholder in here makes a
    draft — an answer in brackets is the customer's answer — and nothing here feeds the gate."""
    _mapping(declared, "declared", "expected a mapping")
    _only(declared, _DECLARED_KEYS, "declared")
    if "servers" in declared:
        _list(declared["servers"], "declared.servers")
        for index, server in enumerate(declared["servers"]):
            where = f"declared.servers[{index}]"
            _mapping(server, where, "expected a mapping")
            _only(server, _DECLARED_SERVER_KEYS, where)
            for key, value in server.items():
                if key == "entry":
                    if not isinstance(value, str) or not _NAME.fullmatch(value):
                        raise _Invalid(f"{where}.entry", f"{value!r} is not a manifest entry name")
                else:
                    _answer(value, f"{where}.{key}")
    if "constraints" in declared:
        constraints = declared["constraints"]
        _mapping(constraints, "declared.constraints", "expected a mapping")
        _only(constraints, _CONSTRAINT_KEYS, "declared.constraints")
        for key, value in constraints.items():
            _answer(value, f"declared.constraints.{key}")
    if "notes" in declared:
        notes = declared["notes"]
        _list(notes, "declared.notes")
        for index, note in enumerate(notes):
            if not isinstance(note, str):
                raise _Invalid(f"declared.notes[{index}]", "expected a string")


def _answer(value: Any, where: str) -> None:
    if isinstance(value, str):
        return
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return
    raise _Invalid(where, "expected a string or a list of strings")


def _mapping(value: Any, where: str, message: str) -> None:
    if not isinstance(value, dict):
        raise _Invalid(where, message)


def _list(value: Any, where: str) -> None:
    if not isinstance(value, list):
        raise _Invalid(where, "expected a list")


def _only(mapping: dict, allowed: frozenset[str], where: str) -> None:
    for key in mapping:
        if key not in allowed:
            raise _Invalid(
                where, f"unknown key {key!r}; expected one of {', '.join(sorted(allowed))}"
            )


def _observation(item: dict, where: str, source: str) -> str | None:
    """The identity's ``observation`` and whether it fits its token source. What an error says
    never repeats the value: it sits beside a credential's source."""
    if "observation" not in item:
        return None
    value = item["observation"]
    if not isinstance(value, str) or value not in OBSERVATIONS:
        raise _Invalid(where, f"expected one of {', '.join(OBSERVATIONS)}")
    if (value == "no_token") != (source == "token"):
        raise _Invalid(
            where,
            "no_token goes with token: none; foreign_audience and expired go with token_env "
            "or token_file",
        )
    return value


def _required(mapping: dict, key: str, where: str) -> Any:
    if key not in mapping or mapping[key] is None:
        raise _Invalid(f"{where}.{key}" if where else key, "missing")
    return mapping[key]


# -- the gate -----------------------------------------------------------------------------

#: Why the gate refused a run under a file: a closed set, each a key a report can count by.
CONDITIONS = (
    "stop_file",
    "draft",
    "before_window",
    "after_window",
    "target_not_listed",
    "port_not_listed",
    "path_not_listed",
    "below_isolation",
    "scenario_not_listed",
    "builtin_scenario",
    "calls_not_permitted",
    "lists_not_permitted",
    "identity_not_declared",
    "identity_required",
    "token_not_declared",
    "token_source_differs",
    "salt_missing",
    "salt_too_short",
    "tool_not_listed",
    "tool_writes_not_released",
    "tool_denied",
    "probe_not_listed",
)

#: The salt of the pseudonyms is at least this many characters (the variable's value, as bytes).
MIN_SALT_LENGTH = 32

#: The versions of the file whose runs are refused without a salt. By design, version 1 is not
#: among them: a run under such a file keeps a salt of its own, per run
#: (``run_started.pseudonyms``), and is not refused without ``salt_env`` (version 1 has none, so
#: with 1 here every run under such a file would be refused ``salt_missing``).
SALT_REQUIRED_VERSIONS = (FORMAT_VERSION_2,)

#: Why a tool call is not allowed under a file, in the words of :data:`CONDITIONS`: the gate
#: refuses a script for them, the driver and the proxy block a call for them. Fixed words; no
#: value from a script or from traffic is ever part of one.
TOOL_DENIED = "tool_denied"
TOOL_NOT_LISTED = "tool_not_listed"
TOOL_WRITES_NOT_RELEASED = "tool_writes_not_released"

#: How much of a refusal's words the file keeps, cut after the masking.
MAX_REFUSAL_MESSAGE = 2000

#: The commands that take a file.
COMMANDS = ("run", "drive", "fleet")

#: How strong each isolation that runs a server here is, for a target's floor. Written out
#: rather than read from the order of ``policy.ISOLATIONS``: an isolation this table does not
#: name meets none of these floors, so it is refused, not ranked by where it happens to stand
#: in a tuple. ``remote`` is not on this scale — nothing of the server runs here, so it is no
#: weaker and no stronger than these — and is a floor of its own (:data:`REMOTE`).
_STRENGTH = {"host": 0, "runc": 1, "runsc": 2}

#: The isolation of an endpoint entry's run: the server is somebody else's, reached over HTTP.
#: A ``remote`` floor is met by a ``remote`` run and nothing else; a ``remote`` run meets no
#: ``host``, ``runc`` or ``runsc`` floor.
REMOTE = "remote"

#: The port of a URL that names none, by scheme. Explicit, because a target entry with
#: ``ports`` must be matched by a port, and "none given" is not one. Any other scheme is
#: refused: its port is not known here.
DEFAULT_PORTS = {"http": 80, "https": 443}


class EngagementRefused(Exception):
    """The file does not cover this run. ``condition`` is one of :data:`CONDITIONS`; ``words``
    say what to do. ``str()`` is ``condition: words``, for ``kymograph: <file>: …``.

    Where the words name a URL's path they are built twice: ``words``
    for the terminal, with the path whole, and ``recorded_words`` for ``refusals.jsonl``, with
    the path's place holding :func:`mcp_kymograph.masking.withheld_path`. Everywhere else the
    two are the same."""

    def __init__(self, condition: str, words: str, recorded_words: str | None = None) -> None:
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition {condition!r}")
        super().__init__(condition, words)
        self.condition = condition
        self.words = words
        self.recorded_words = words if recorded_words is None else recorded_words

    def __str__(self) -> str:
        return f"{self.condition}: {self.words}"

    @property
    def recorded(self) -> str:
        """:meth:`__str__` with the words the record gets."""
        return f"{self.condition}: {self.recorded_words}"


@dataclass(frozen=True, slots=True)
class GateFacts:
    """What the command line knows before anything starts, and all the gate looks at."""

    #: ``run``, ``drive`` or ``fleet``.
    command: str
    #: ``--target`` as typed, or None.
    declared_target: str | None = None
    #: ``--http`` as typed, or None.
    http_url: str | None = None
    #: SHA-256 of the scenario file's bytes, or None for no scenario or a built-in one.
    scenario_digest: str | None = None
    #: Whether the scenario is a built-in one (it has no file, so it cannot be listed).
    scenario_builtin: bool = False
    #: The isolation the run is to have.
    isolation: str = "host"
    #: Whether the script calls tools or reads resources.
    script_acts: bool = False
    #: Whether the script lists (every script of ``drive`` does).
    script_lists: bool = False
    #: The tool of each ``call`` step of the script, in order; empty for a run without calls.
    script_tools: tuple[str, ...] = ()
    #: ``--identity`` as typed, or None.
    identity: str | None = None
    #: Which flag named a token's source: ``--token-env`` or ``--token-file``, or None for
    #: neither. The name of the variable or the path is not the gate's to read.
    source_flag: str | None = None
    #: Whether the caller looked at the salt's variable at all, and, if it did, how many
    #: characters the variable holds (None: not set or empty). Never the value. A caller that
    #: does not look (the fleet's gate; each of its runs is gated again) leaves the salt
    #: unchecked.
    salt_read: bool = False
    salt_length: int | None = None
    #: Whether the engagement's stop file is there (:func:`stopped`), looked at by the caller:
    #: the gate itself touches nothing.
    stopped: bool = False
    #: The probe module the run is to use (``drive --probe``), or None.
    probe: str | None = None


@dataclass(frozen=True, slots=True)
class _Reach:
    """One thing the run reaches, as compared with ``targets``. ``name`` None: the child."""

    what: str
    name: str | None
    port: int | None = None
    path: str | None = None
    #: True for ``--target``: a declared target is held to the ports the file lists, never to
    #: a default the file does not write (:func:`_refused_default`).
    declared: bool = False


def check(engagement: Engagement, facts: GateFacts, now: datetime) -> None:
    """Refuse a run the file does not cover, with :class:`EngagementRefused`; return if it does.

    Called after :func:`authorization.check` with the flag as typed, so the file can only add
    refusals: nothing here reads ``--engagement-confirmed``, and nothing here allows anything.
    Reads only the file as loaded and ``facts``; touches nothing, resolves nothing. ``now`` is
    an aware time, given by the caller so a test can hold the clock.

    In this order: a draft; the window; every target the run reaches; the scenario; what the
    script does; the identity; the salt.

    A declared target matches no entry whose ports were defaulted, on any port or none: the
    default (:data:`ENDPOINT_DEFAULT_PORTS`) is the port of the scheme a URL is spoken to with,
    and a declared target has no scheme. Under the earlier default, 80, ``--target host:80``
    passed; reading 443 for it would let ``--target host:443`` through where it was refused, and
    the gate only narrows. So a declared target is held to ports the file lists. Fail closed.
    """
    if facts.command not in COMMANDS:
        raise ValueError(f"unknown command {facts.command!r}")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be an aware time")
    if facts.stopped:
        raise EngagementRefused(
            "stop_file",
            "the engagement's stop file is there: runs under it are stopped until it is removed "
            "(engagement stop FILE --clear)",
        )
    if engagement.is_draft:
        raise EngagementRefused(
            "draft",
            "the file is a draft: it still holds placeholders at "
            + ", ".join(engagement.placeholders)
            + "; no run is permitted under it until every one is filled in and the file agreed",
        )
    start, end = engagement.window_from, engagement.window_until
    if start is None or end is None:  # a draft, refused above; said again for the reader
        raise EngagementRefused("draft", "the file's window is not filled in")
    if now < start:
        raise EngagementRefused(
            "before_window",
            f"the engagement's window opens at {utc_text(start)}; it is {utc_text(now)}",
        )
    if now >= end:
        raise EngagementRefused(
            "after_window",
            f"the engagement's window closed at {utc_text(end)}; it is {utc_text(now)}",
        )
    for reach in _reaches(facts):
        _match(engagement, reach, facts)
    if facts.scenario_builtin:
        raise EngagementRefused(
            "builtin_scenario",
            "a built-in scenario has no file and no digest, so the engagement cannot list it; "
            "give the scenario as a file the engagement lists",
        )
    listed = {scenario.sha256 for scenario in engagement.scenarios}
    if facts.scenario_digest is not None and facts.scenario_digest not in listed:
        raise EngagementRefused(
            "scenario_not_listed",
            f"the scenario's SHA-256 {facts.scenario_digest} is not among the scenarios the "
            "engagement lists",
        )
    if facts.script_acts and not engagement.actions_call:
        raise EngagementRefused(
            "calls_not_permitted",
            "the script calls tools or reads resources, and the engagement says actions.call: "
            "false",
        )
    if facts.probe is not None and facts.probe not in engagement.actions_probes:
        raise EngagementRefused(
            "probe_not_listed",
            f"the probe module {_safe(facts.probe)!r} is not among the "
            "modules the engagement lists under actions.probes",
        )
    for name in facts.script_tools:
        cause = tool_cause(engagement, name)
        if cause is not None:
            raise EngagementRefused(cause, f"the script calls {_tool_words(name, cause)}")
    if (facts.command in ("drive", "fleet") or facts.script_lists) and not engagement.actions_list:
        raise EngagementRefused(
            "lists_not_permitted",
            f"{facts.command} speaks a script that lists what the server offers, and the "
            "engagement says actions.list: false",
        )
    _identity(engagement, facts)
    _salt(engagement, facts)


def _salt(engagement: Engagement, facts: GateFacts) -> None:
    """The salt the pseudonyms of personal data are made with comes from the variable the file
    names (``salt_env``) and is at least :data:`MIN_SALT_LENGTH` characters. The words name the
    variable and never what it holds."""
    if not facts.salt_read or engagement.version not in SALT_REQUIRED_VERSIONS:
        return
    if engagement.salt_env is None:
        raise EngagementRefused(
            "salt_missing",
            "the file names no environment variable for the salt of the pseudonyms (salt_env)",
        )
    if not facts.salt_length:
        raise EngagementRefused(
            "salt_missing",
            f"the environment variable {engagement.salt_env}, which holds the salt of the "
            "pseudonyms, is not set or is empty",
        )
    if facts.salt_length < MIN_SALT_LENGTH:
        raise EngagementRefused(
            "salt_too_short",
            f"the environment variable {engagement.salt_env}, which holds the salt of the "
            f"pseudonyms, holds fewer than {MIN_SALT_LENGTH} characters",
        )


def tool_cause(engagement: Engagement, name: str | None) -> str | None:
    """Why the file does not allow a call of the tool ``name``, as one of :data:`TOOL_DENIED`,
    :data:`TOOL_NOT_LISTED` and :data:`TOOL_WRITES_NOT_RELEASED`; None when it does.

    In this order: a name in ``deny_tools`` is never called, whatever else the file says; with
    ``tools`` set, only a name listed there is called; a tool marked ``writes: true`` is called
    only when ``actions.write`` is true. Without ``tools`` and ``deny_tools``, as in every file
    of the first version, nothing here refuses: only ``actions`` applies. ``name`` None is a
    call that names no tool the file can recognise: not listed when ``tools`` is set, else nothing
    to compare. Exact names; no
    case folding, no trimming. Reads only the file; the name is compared, never kept.
    """
    if name is None or not isinstance(name, str):
        return TOOL_NOT_LISTED if engagement.tools is not None else None
    if name in engagement.deny_tools:
        return TOOL_DENIED
    if engagement.tools is None:
        return None
    for tool in engagement.tools:
        if tool.name == name:
            return (
                TOOL_WRITES_NOT_RELEASED if tool.writes and not engagement.actions_write else None
            )
    return TOOL_NOT_LISTED


def _tool_words(name: str, cause: str) -> str:
    """What the gate says about a script's tool, for the refusal: the name as the script wrote
    it, without the characters a terminal must not be handed. Not cut here: the words are masked
    first, by whoever writes or shows them, and cut after."""
    shown = repr(_safe(name))
    if cause == TOOL_DENIED:
        return f"the tool {shown}, and the engagement lists it under deny_tools"
    if cause == TOOL_WRITES_NOT_RELEASED:
        return (
            f"the tool {shown}, which the engagement marks as writing, and it says actions.write: "
            "false"
        )
    return f"the tool {shown}, and it is not among the tools the engagement lists"


def _identity(engagement: Engagement, facts: GateFacts) -> None:
    """Who the run speaks as, and the token it sends. The file is the agreement: an identity it
    does not name, and a credential outside it, are outside scope; a run that sends less than
    the file declares is allowed, because it can only see less."""
    names = ", ".join(identity.name for identity in engagement.identities) or "none"
    if facts.identity is not None and engagement.identity(facts.identity) is None:
        raise EngagementRefused(
            "identity_not_declared",
            f"the identity {_safe(facts.identity)!r} is not among the identities the file "
            f"declares ({names})",
        )
    if facts.source_flag is None:
        return
    if not engagement.identities:
        raise EngagementRefused(
            "token_not_declared",
            f"{facts.source_flag} names a token, and the file declares no identity: a "
            "credential the file does not name is outside scope; declare the identity and its "
            "token source in the file and select it with --identity",
        )
    if facts.identity is None:
        raise EngagementRefused(
            "identity_required",
            f"{facts.source_flag} names a token, and the file declares identities ({names}): "
            "select one with --identity; the source of its token is the file's",
        )
    raise EngagementRefused(
        "token_source_differs",
        f"{facts.source_flag} names a token's source, and the source of identity "
        f"{_safe(facts.identity)!r} comes from the file; drop {facts.source_flag}",
    )


def _reaches(facts: GateFacts) -> list[_Reach]:
    """What the run reaches: the declared target and the URL, each; with neither, the child."""
    reaches: list[_Reach] = []
    if facts.declared_target is not None:
        split = split_target(facts.declared_target)
        if split is None:
            # The record has the URL bare, without quotes, and its path withheld: the closing
            # quote would run into the path and the digest would differ from ``command``'s.
            # Built by joining, never by formatting: the text is the command line's.
            after = " cannot be taken apart as a host or host:port, so it cannot be one of the "
            after += "engagement's targets"
            raise EngagementRefused(
                "target_not_listed",
                "the target " + repr(_safe(facts.declared_target)) + after,
                "the target " + withhold_url_path(_safe(facts.declared_target)) + after,
            )
        reaches.append(_Reach(f"the target {split[0]}", split[0], split[1], declared=True))
    if facts.http_url is not None:
        reaches.append(_url_reach(facts.http_url))
    if not reaches:
        reaches.append(_Reach("the server this run starts as its own child", None))
    return reaches


def _url_reach(url: str) -> _Reach:
    before = "the URL "
    after = (
        " cannot be taken apart into host, port and path, so it cannot be one of the "
        "engagement's targets"
    )
    # A URL that cannot be taken apart has no path to withhold, so the record does not have it
    # at all: it is only said to have been given. Built by joining, never by formatting: the
    # URL is the command line's text and may hold braces.
    refusal = EngagementRefused(
        "target_not_listed", before + repr(_safe(url)) + after, before + "given" + after
    )
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        raise refusal from None
    if scheme not in DEFAULT_PORTS or userinfo or not parts.netloc:
        raise refusal
    split = split_target(parts.netloc)
    if split is None:
        raise refusal
    port = DEFAULT_PORTS[scheme] if split[1] is None else split[1]
    return _Reach(f"the URL's host {split[0]}", split[0], port, parts.path)


def matched_target(engagement: Engagement, facts: GateFacts) -> Target | None:
    """The entry of ``targets`` that the gate meets for the URL of ``facts`` — the one
    :func:`check` lets the run through on, by the same logic — or None for a run without a URL.
    Called after :func:`check` passed; refuses as it does if it had not."""
    if facts.http_url is None:
        return None
    return _match(engagement, _url_reach(facts.http_url), facts)


def _match(engagement: Engagement, reach: _Reach, facts: GateFacts) -> Target:
    """Return the first entry of ``targets`` that covers ``reach``; otherwise refuse with the
    condition of the entry that came closest — the host matched but the port did not, and so on."""
    closest: EngagementRefused | None = None
    stage = 0
    for target in engagement.targets:
        if reach.name is None:
            matched = target.name is not None and is_local(target.name)
        else:
            matched = target.name == reach.name
        if not matched:
            continue
        if target.ports_defaulted and reach.declared:
            if stage < 1:
                stage, closest = 1, _refused_default(reach, target)
            continue
        if target.ports is not None and reach.port not in target.ports:
            if stage < 1:
                stage, closest = 1, _refused_port(reach, target)
            continue
        if target.paths is not None and reach.path is not None and reach.path not in target.paths:
            if stage < 2:
                stage, closest = 2, _refused_path(reach, target)
            continue
        floor = _floor(target, facts)
        if floor is not None:
            if stage < 3:
                stage, closest = 3, floor
            continue
        return target
    if closest is not None:
        raise closest
    hosts = ", ".join(_safe(target.host) for target in engagement.targets)
    if reach.name is None:
        words = (
            f"{reach.what} is local, and the engagement lists no local host ({hosts}); a run "
            "under a file names one of its targets, the local child included"
        )
    else:
        words = f"{reach.what} is not among the engagement's targets ({hosts})"
    raise EngagementRefused("target_not_listed", words)


def _refused_port(reach: _Reach, target: Target) -> EngagementRefused:
    ports = ", ".join(str(port) for port in target.ports or ())
    if target.ports_defaulted:
        ports += f" (the default for {ENDPOINT_DEFAULT_SCHEME}: the file names no port)"
    given = "names no port" if reach.port is None else f"is on port {reach.port}"
    return EngagementRefused(
        "port_not_listed",
        f"{reach.what} {given}, and the engagement lists {_safe(target.host)} on {ports} only",
    )


def _refused_default(reach: _Reach, target: Target) -> EngagementRefused:
    ports = ", ".join(str(port) for port in target.ports or ())
    given = "names no port" if reach.port is None else f"is on port {reach.port}"
    return EngagementRefused(
        "port_not_listed",
        f"{reach.what} {given}, and the file names no port for {_safe(target.host)}: its default "
        f"({ports}, the port of {ENDPOINT_DEFAULT_SCHEME}) is read only for a URL. A declared "
        "target is held to the ports the file lists; list the port the run is against",
    )


def _refused_path(reach: _Reach, target: Target) -> EngagementRefused:
    paths = ", ".join(_safe(path) for path in target.paths or ())
    # The terminal gets the path whole; the record gets its SHA-256 and length. The listed
    # paths are the file's own words and stay in both.
    # Built by joining, never by formatting: the path and the listed paths are text from the
    # command line and the file, and may hold braces.
    before = "the URL's path "
    after = (
        f" is not among the paths the engagement lists for {_safe(target.host)} ({paths}); "
        "paths are compared exactly"
    )
    return EngagementRefused(
        "path_not_listed",
        before + repr(_safe(reach.path)) + after,
        before + withheld_path(reach.path or "") + after,
    )


def _floor(target: Target, facts: GateFacts) -> EngagementRefused | None:
    if target.isolation is None:
        return None
    if target.isolation == REMOTE:
        if facts.isolation == REMOTE:
            return None
        return EngagementRefused(
            "below_isolation",
            f"the engagement requires isolation remote for {_safe(target.host)}: an endpoint "
            f"entry's run, reached over HTTP; this run is to have {_safe(facts.isolation)}",
        )
    if facts.isolation == REMOTE:
        return EngagementRefused(
            "below_isolation",
            f"the engagement requires isolation {target.isolation} for {_safe(target.host)}, and "
            "a remote run meets none: the server runs elsewhere, nothing of it runs here",
        )
    if facts.http_url is not None:
        return EngagementRefused(
            "below_isolation",
            f"the engagement requires isolation {target.isolation} for {_safe(target.host)}, and "
            "an --http run meets none: the server runs elsewhere, nothing of it runs here",
        )
    run = _STRENGTH.get(facts.isolation, -1)
    if run < _STRENGTH.get(target.isolation, len(_STRENGTH)):
        return EngagementRefused(
            "below_isolation",
            f"the engagement requires isolation {target.isolation} or stronger for "
            f"{_safe(target.host)}, and this run is to have {_safe(facts.isolation)}",
        )
    return None


# -- the refusal record -------------------------------------------------------------------

#: Why a run under a file was refused, as ``refusals.jsonl`` records it: the gate's conditions,
#: then the command line's own refusals after the file was read, each named after what refused
#: (``cli._main``): the ``--http`` options, the manifest (provenance and isolation included),
#: plain HTTP to a host that is not a loopback literal (``plain_http``), the
#: arguments, the script, today's gate (``not_confirmed``), the scenario, a scenario with rules
#: over HTTP, the server's identity, a token or a secret header that cannot be read (``token``;
#: the words name the source, never what it held), the sandbox's delivery, the destination; and
#: for ``fleet run``, a store that cannot be opened (``store``) and the fleet's own refusals
#: before it starts (``fleet``: its manifest, its destination, a store that holds another
#: engagement), and a name the operator gave (``server_name``, ``scenario_name``) that holds a
#: known value or a literal of the run (``name_holds_known_value``; the words name the field,
#: never the value).
REFUSAL_REASONS = (
    *CONDITIONS,
    "http_options",
    "manifest",
    "plain_http",
    "arguments",
    "script",
    "not_confirmed",
    "scenario",
    "scenario_over_http",
    "identity",
    "token",
    "probe_without_engagement",
    "delivery",
    "destination",
    "pacing",
    "store",
    "fleet",
    "name_holds_known_value",
)

#: The file under ``--out-dir`` refusals are appended to: beside the run directories, never in
#: one.
REFUSALS_FILE = "refusals.jsonl"

#: What a refused run exits with; the record says so, as the terminal did.
REFUSED_EXIT_CODE = 2

#: A refusals file is appended to for the length of an engagement; this is far beyond that.
MAX_REFUSALS_BYTES = 16 * 1024 * 1024

#: A run directory's name (``output.run_directory_name``).
_RUN_DIRECTORY = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")

_REFUSAL_KEYS = frozenset(
    {"refused_utc", "command", "reason", "message", "engagement", "exit_code"}
)
_REFUSAL_ENGAGEMENT_KEYS = frozenset({"engagement_id_declared", "engagement_digest"})


@dataclass(frozen=True, slots=True)
class RefusalRecord:
    """One line of ``refusals.jsonl``: a run that was refused under a file, and why.

    ``command`` is the command line as typed after :meth:`Masker.mask_argv`, the server command
    after ``--`` included; ``message`` the refusal's words after :meth:`Masker.mask_text`. Of the
    file, its declared id and its digest — as a recording carries them, and nothing more.
    """

    refused_utc: str
    command: tuple[str, ...]
    reason: str
    message: str
    engagement_id_declared: str
    engagement_digest: str
    exit_code: int = REFUSED_EXIT_CODE

    def to_dict(self) -> dict[str, Any]:
        return {
            "refused_utc": self.refused_utc,
            "command": list(self.command),
            "reason": self.reason,
            "message": self.message,
            "engagement": {
                "engagement_id_declared": self.engagement_id_declared,
                "engagement_digest": self.engagement_digest,
            },
            "exit_code": self.exit_code,
        }


def record_refusal(
    out_dir: str | Path,
    *,
    argv: Sequence[str],
    masker: Masker,
    reason: str,
    message: str,
    engagement: Engagement,
    now: datetime,
    verbatim_paths: Collection[VerbatimPath] = (),
) -> str | None:
    """Append one refusal to ``<out_dir>/refusals.jsonl``; None when it was written, otherwise
    the words why nothing was recorded. The refusal itself stands either way: the caller still
    exits 2.

    A refusal is part of what happened during an engagement,
    and the terminal line is gone when the terminal is. So it is written down — where the
    recordings go, under the same rules: the out-dir passes ``output.inspect_destination``
    (a git working tree is refused) and is created ``0700`` as ``prepare_run`` creates it, but
    no run directory is made and none is written into. The file is ``0600``, opened
    ``O_APPEND`` and ``O_NOFOLLOW``, and written only when it is a regular file of this user's
    with mode ``0600``: a link or a file someone else placed there is not appended to.

    ``reason`` is one of :data:`REFUSAL_REASONS`; any other is a mistake in the caller and
    raises :class:`ValueError`.
    """
    if reason not in REFUSAL_REASONS:
        raise ValueError(f"unknown refusal reason {reason!r}")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be an aware time")
    record = RefusalRecord(
        refused_utc=utc_text(now),
        command=tuple(masker.mask_argv(list(argv), verbatim_paths)[0]),
        reason=reason,
        # The path of a URL in the words is withheld as in ``command`` (6.4), whichever message
        # it is in. A path already withheld by the caller has no slash after the host and is
        # not matched again.
        message=withhold_url_path(masker.mask_text(message)[0], verbatim_paths)[
            :MAX_REFUSAL_MESSAGE
        ],
        engagement_id_declared=engagement.id,
        engagement_digest=engagement.digest,
    )
    line = json.dumps(record.to_dict(), ensure_ascii=True) + "\n"
    not_recorded = "the refusal was not recorded"

    out = Path(out_dir).expanduser()
    target = out / REFUSALS_FILE
    try:
        advisories = inspect_destination(out, target)
        inside_run = _inside_run_directory(out)
    except (OSError, RuntimeError) as exc:
        return f"{unusable(exc).message} {not_recorded}"
    for advisory in advisories:
        if advisory.severity is Severity.REFUSAL:
            return f"{advisory.message} {not_recorded}"
    if inside_run:
        return f"the output directory is a run directory or lies inside one; {not_recorded}"
    try:
        make_private_directories(out)
    except OSError as exc:
        return f"{unusable(exc).message} {not_recorded}"

    # O_NONBLOCK: a FIFO someone placed at the path must not hold the refusal until a reader
    # comes; without one the open fails (ENXIO), and with one it is refused below as no file.
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            descriptor = os.open(target, flags | os.O_CREAT | os.O_EXCL, FILE_MODE)
            # Ours from the first byte: the mode exactly, whatever the umask took away.
            os.fchmod(descriptor, FILE_MODE)
        except FileExistsError:
            descriptor = os.open(target, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            why = "it is a symbolic link"
        elif exc.errno == errno.ENXIO:
            why = "it is a FIFO, not a file"
        else:
            why = exc.strerror or str(exc)
        return f"{REFUSALS_FILE} cannot be opened for appending ({why}); {not_recorded}"
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            return f"{REFUSALS_FILE} is not a regular file; {not_recorded}"
        if status.st_uid != os.getuid():
            return f"{REFUSALS_FILE} belongs to another user; {not_recorded}"
        if stat.S_IMODE(status.st_mode) != FILE_MODE:
            return (
                f"{REFUSALS_FILE} has mode {stat.S_IMODE(status.st_mode):04o}, not "
                f"{FILE_MODE:04o}; {not_recorded}"
            )
        data = line.encode("ascii")
        if status.st_size + len(data) > MAX_REFUSALS_BYTES:
            # Beyond what read_refusals reads: a line written now would make the whole file
            # unreadable, the refusals before it included.
            return (
                f"{REFUSALS_FILE} is full: one more line would take it past the "
                f"{MAX_REFUSALS_BYTES} bytes it is read up to; {not_recorded}"
            )
        while data:
            written = os.write(descriptor, data)
            data = data[written:]
    except OSError as exc:
        return f"{REFUSALS_FILE} could not be written ({exc.strerror or exc}); {not_recorded}"
    finally:
        os.close(descriptor)
    return None


def _inside_run_directory(path: Path) -> bool:
    """Whether ``path`` is a run directory or lies in one.

    A run directory is what ``output.prepare_run`` makes and the recorder writes ``events.jsonl``
    into, and nothing else: it holds that one file and no directory. So a directory holding
    ``events.jsonl`` is one, wherever it stands above ``path``. A directory merely named like
    one (``%Y%m%dT%H%M%SZ-`` and eight hex digits) is one only where nothing else can be told:
    when it is ``path`` itself and holds no recording yet — a run directory between its making
    and its first event — it is taken to be one. Above ``path`` it is not, because a run
    directory has no directories in it: that is a fleet's directory (the same shape of name,
    a run's out-dir per job below it), and a child refused inside a fleet records there.
    """
    resolved = path.resolve()
    if any((candidate / "events.jsonl").exists() for candidate in (resolved, *resolved.parents)):
        return True
    return bool(_RUN_DIRECTORY.fullmatch(resolved.name))


class _NotOpened(EngagementError):
    """A ``refusals.jsonl`` the system would not open: ``said`` is what it said, kept apart
    from the reader's own words, so a report can tell a file it could not read from one whose
    content the reader refuses."""

    def __init__(self, said: str, *, source: str) -> None:
        super().__init__(f"cannot read: {said}", source=source)
        self.said = said


def read_refusals(path: str | Path) -> list[RefusalRecord]:
    """Every refusal in a ``refusals.jsonl``, in the order written — read whole or refused
    whole with :class:`EngagementError`. A line that is not one of these records, a last line
    without its newline (a write cut short), a link at the path: the file is refused."""
    path = Path(path)
    source = str(path)
    # O_NONBLOCK: a FIFO at the path opens at once instead of waiting for a writer, and is then
    # refused as what it is.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise EngagementError("cannot read: it is a symbolic link", source=source) from None
        raise _NotOpened(exc.strerror or str(exc), source=source) from None
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise EngagementError("not a regular file", source=source)
        raw = handle.read(MAX_REFUSALS_BYTES + 1)
    if len(raw) > MAX_REFUSALS_BYTES:
        raise EngagementError(f"larger than {MAX_REFUSALS_BYTES} bytes", source=source)
    if raw and not raw.endswith(b"\n"):
        raise EngagementError("the last line has no end: a write was cut short", source=source)
    records: list[RefusalRecord] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        try:
            records.append(_refusal(line))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise EngagementError(f"line {number}: {exc}", source=source) from None
    return records


#: How deep below an out-dir :func:`find_refusals` looks for ``refusals.jsonl``: the out-dir's
#: own (depth 1), and a fleet's runs' (``<out>/<fleet>/<NNN-entry>/refusals.jsonl``, depth 3).
REFUSALS_DEPTH = 3


@dataclass(frozen=True, slots=True)
class RefusalsFile:
    """One ``refusals.jsonl`` found under an out-dir: its records, or why it was refused whole.

    ``refused`` None: ``records`` is every line. Otherwise ``records`` is empty and ``refused``
    says why — a file that cannot be read is reported, never left out, or a reader would count
    fewer refusals than there were and not know it. ``not_listed`` is set for a directory that
    could not be listed, ``not_read`` for a file the system would not open: what the system
    said, apart from the tool's own words, which a report shows as a value and never as one of
    its sentences.
    """

    path: Path
    records: tuple[RefusalRecord, ...] = ()
    refused: str | None = None
    not_listed: str | None = None
    not_read: str | None = None


def find_refusals(out_dir: str | Path) -> list[RefusalsFile]:
    """Every ``refusals.jsonl`` under ``out_dir`` down to :data:`REFUSALS_DEPTH`, in path order,
    each read whole or reported as refused.

    No symbolic link is followed: a linked directory is not entered, and a linked
    ``refusals.jsonl`` is reported as refused (:func:`read_refusals` does not open it). A
    directory that cannot be listed is reported the same way, under its own path, so that what
    could not be looked at is said. ``out_dir`` itself must be a directory that can be listed;
    otherwise :class:`EngagementError`.
    """
    root = Path(out_dir)
    try:
        if not stat.S_ISDIR(os.lstat(root).st_mode):
            raise EngagementError("not a directory", source=str(root))
    except OSError as exc:
        raise EngagementError(f"cannot read: {exc.strerror or exc}", source=str(root)) from None
    found: list[RefusalsFile] = []
    _find(root, 1, found)
    return sorted(found, key=lambda item: str(item.path))


def _find(directory: Path, depth: int, found: list[RefusalsFile]) -> None:
    try:
        with os.scandir(directory) as entries:
            listed = list(entries)
    except OSError as exc:
        said = exc.strerror or str(exc)
        found.append(RefusalsFile(directory, refused=f"cannot be listed: {said}", not_listed=said))
        return
    for entry in listed:
        path = Path(entry.path)
        if entry.name == REFUSALS_FILE:
            try:
                found.append(RefusalsFile(path, tuple(read_refusals(path))))
            except _NotOpened as refusal:
                found.append(RefusalsFile(path, refused=refusal.reason, not_read=refusal.said))
            except EngagementError as refusal:
                found.append(RefusalsFile(path, refused=refusal.reason))
        elif depth < REFUSALS_DEPTH and entry.is_dir(follow_symlinks=False):
            _find(path, depth + 1, found)


def _refusal(line: bytes) -> RefusalRecord:
    data = json.loads(line.decode("ascii"), object_pairs_hook=_unique)
    if not isinstance(data, dict) or set(data) != _REFUSAL_KEYS:
        raise ValueError(
            f"not a refusal record: expected the keys {', '.join(sorted(_REFUSAL_KEYS))}"
        )
    engaged = data["engagement"]
    if not isinstance(engaged, dict) or set(engaged) != _REFUSAL_ENGAGEMENT_KEYS:
        raise ValueError("engagement: expected engagement_id_declared and engagement_digest")
    command = data["command"]
    checks = (
        (
            "refused_utc",
            isinstance(data["refused_utc"], str) and _UTC_TIME.fullmatch(data["refused_utc"]),
        ),
        ("command", isinstance(command, list) and all(isinstance(part, str) for part in command)),
        ("reason", data["reason"] in REFUSAL_REASONS),
        ("message", isinstance(data["message"], str)),
        ("engagement.engagement_id_declared", isinstance(engaged["engagement_id_declared"], str)),
        (
            "engagement.engagement_digest",
            isinstance(engaged["engagement_digest"], str)
            and _DIGEST.fullmatch(engaged["engagement_digest"]),
        ),
        ("exit_code", type(data["exit_code"]) is int and data["exit_code"] == REFUSED_EXIT_CODE),
    )
    for key, good in checks:
        if not good:
            raise ValueError(f"{key}: not what a refusal record holds")
    return RefusalRecord(
        refused_utc=data["refused_utc"],
        command=tuple(command),
        reason=data["reason"],
        message=data["message"],
        engagement_id_declared=engaged["engagement_id_declared"],
        engagement_digest=engaged["engagement_digest"],
        exit_code=data["exit_code"],
    )


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


# -- showing ------------------------------------------------------------------------------


def to_json(engagement: Engagement) -> str:
    """``engagement show --json``: the file as parsed — contacts and reference included, this
    is the operator's view — beside its digest and its placeholders.

    The known values are not in it, only their number (``known_value_count``): they are the
    customer's secrets and never go to stdout. The file sits under ``engagement`` rather than
    among the other keys, so it can be written back to a ``.json`` file and read by
    :func:`load`; that file loads, but without the known values.
    """
    shown = {key: value for key, value in engagement.data.items() if key != "known_values"}
    return json.dumps(
        {
            "source": engagement.source,
            "digest": engagement.digest,
            "placeholders": list(engagement.placeholders),
            "known_value_count": engagement.known_value_count,
            "engagement": shown,
        },
        ensure_ascii=True,
        indent=2,
    )


def render(engagement: Engagement) -> str:
    """``engagement show``: the file as a short document a customer can sign off.

    Every value from the file goes through :func:`_safe`, so nothing in it can move the cursor
    or reorder what the reader sees. The digest is the last line: the one every recording made
    under the file will carry, and the one the customer compares with the file they received.
    """
    data = engagement.data
    lines: list[str] = []
    title = f"Engagement {_safe(engagement.id)}"
    lines += [title, "=" * len(title), ""]
    if engagement.is_draft:
        lines += [
            "DRAFT — this file still holds placeholders, and no run is permitted under it until "
            "every one is filled in:",
            *(f"  [placeholder] {where}" for where in engagement.placeholders),
            "",
        ]
    if engagement.version == FORMAT_VERSION_2:
        agency = data.get("agency")
        lines.append(f"Agency:     {_shown(agency['name'], 'not given') if agency else 'none'}")
        lines.append(f"Customer:   {_shown(data['end_customer']['name'])}  (the end customer)")
    else:
        lines.append(f"Customer:   {_shown(data.get('customer'), 'not given')}")
    lines.append(f"Reference:  {_shown(data.get('reference'), 'not given')}")
    if "supersedes" in data:
        lines.append(f"Supersedes: {data['supersedes']}")
    lines.append("")

    lines += ["Window", "------"]
    window = data["window"]
    lines.append(f"  from   {_shown(window['from'])}")
    lines.append(f"  until  {_shown(window['until'])}")
    lines += _in_zone(engagement)
    lines.append("")

    lines += ["Targets", "-------", *_target_table(engagement.targets), ""]
    lines += [
        "Every run under this file names one of these targets, the local child process "
        "included; anything else is refused.",
        "",
    ]

    lines += ["What the script will and will not do", "------------------------------------"]
    lines.append(
        "  list tools, resources and prompts: "
        + ("permitted" if engagement.actions_list else "NOT permitted")
    )
    lines.append(
        "  call tools, read resources:        "
        + ("permitted" if engagement.actions_call else "NOT permitted")
    )
    if engagement.version == FORMAT_VERSION_2:
        lines.append(
            "  call tools marked as writing:      "
            + ("permitted" if engagement.actions_write else "NOT permitted")
        )
    if engagement.version == FORMAT_VERSION_2:
        lines.append(
            "  probe modules:                     "
            + (", ".join(engagement.actions_probes) or "none")
        )
    if engagement.scenarios:
        lines.append("  scenarios, by SHA-256:")
        lines += [f"    {_safe(s.path)}  {s.sha256}" for s in engagement.scenarios]
    else:
        lines.append("  scenarios: none — observation only; a built-in scenario is never permitted")
    lines.append(
        "  --engagement-confirmed is still needed for a scenario or a script that calls tools "
        "against a non-local target: this file does not imply it."
    )
    lines.append("")

    if engagement.version == FORMAT_VERSION_2:
        lines += _second_shown(engagement)

    if engagement.identities or engagement.secret_headers:
        lines += ["Identities", "----------"]
        for identity in engagement.identities:
            lines.append(f"  {_safe(identity.name)} — {_shown(identity.role, 'not given')}")
            lines.append("    " + _token_source_shown(identity))
            lines += [
                f"    header {_safe(name)}: a value from env {_safe(env)} (declared; the file "
                "holds no value)"
                for name, env in identity.headers
            ]
        if engagement.secret_headers:
            lines.append(
                "  secret headers, replaced whole in every recording: "
                + ", ".join(_safe(name) for name in engagement.secret_headers)
            )
        lines += [
            "A run names its identity with --identity; a token from any other source is "
            "refused. No token and no secret is written into a recording, a store or a bundle.",
            "",
        ]

    lines += ["Contacts", "--------"]
    lines += _contacts_shown(data.get("contacts") or [])
    agency = data.get("agency")
    if agency and agency.get("contacts"):
        lines.append("  of the agency:")
        lines += _contacts_shown(agency["contacts"], "  ")
    lines.append("")

    lines += ["Pacing", "------"]
    pacing = pacing_settings(data.get("pacing"))
    lines.append(
        "  enforced: runs_per_origin "
        f"{pacing.runs_per_origin} ({_pacing_source(pacing, 'runs_per_origin')}), "
        f"min_interval_seconds {pacing.min_interval_seconds:g} "
        f"({_pacing_source(pacing, 'min_interval_seconds')})"
    )
    lines.append(
        "  for every HTTP run to a host that is not a loopback literal, an endpoint entry or "
        "--http, as the origin's runs take turns under --out-dir"
    )
    lines.append("")

    retention = data.get("retention") or {}
    lines.append(
        "Retention:  delete after "
        + _shown(retention.get("delete_after"), "not declared")
        + (" (kept through that day, UTC)" if engagement.delete_after is not None else "")
    )
    lines.append(
        "Redaction:  mask keys "
        + (", ".join(_safe(k) for k in engagement.mask_keys) or "none")
        + "; literal patterns "
        + (str(len(engagement.mask_patterns)) if engagement.mask_patterns else "none")
    )
    if "declared" in data:
        servers = data["declared"].get("servers") or []
        lines.append(
            f"Declared:   {len(servers)} server(s) as the customer described them — claims, "
            "checked against nothing"
        )
    lines += ["", f"SHA-256: {engagement.digest}"]
    return "\n".join(lines) + "\n"


def _contacts_shown(contacts: list, indent: str = "") -> list[str]:
    if not contacts:
        return ["  none given"]
    lines = []
    for contact in contacts:
        parts = [_shown(contact.get(key)) for key in ("name", "role", "reach") if key in contact]
        lines.append(indent + "  " + " — ".join(parts))
    return lines


def _second_shown(engagement: Engagement) -> list[str]:
    """What a file of the second version adds to the document. The values of ``known_values``
    are not shown, only how many there are; an environment variable is shown by its name, and
    nothing here holds a value."""
    data = engagement.data
    lines = ["Tools", "-----"]
    if engagement.tools is None:
        lines.append("  not listed: only actions applies")
    for tool in engagement.tools or ():
        lines.append(f"  {_safe(tool.name)} — {'writes' if tool.writes else 'does not write'}")
    lines.append(
        "  denied, never called: "
        + (", ".join(_safe(name) for name in engagement.deny_tools) or "none")
    )
    lines.append("")

    lines += ["Stop at once if", "---------------"]
    lines += [f"  - {_shown(criterion)}" for criterion in engagement.abort_criteria]
    emergency = data["emergency"]
    lines.append(f"  emergency: {_shown(emergency['name'])} — {_shown(emergency['reach'])}")
    lines.append("")

    lines += ["Canaries", "--------"]
    if not engagement.canaries:
        lines.append("  none listed")
    for canary in engagement.canaries:
        state = f"removed {canary.removed.isoformat()}" if canary.removed else "OPEN: not removed"
        lines.append(f"  {_safe(canary.id)} ({canary.kind}) — {state}")
        lines.append(f"    where: {_shown(canary.where)}")
        if canary.path is not None:
            lines.append(f"    path: {_shown(canary.path)}")
    lines += [
        "  A file canary's path must lie outside what the server may read; the tool cannot "
        "check that.",
        "",
    ]

    lines += ["Receiver and secrets", "--------------------"]
    receiver = engagement.receiver
    if receiver is None:
        lines.append("  receiver: none declared")
    else:
        lines.append(f"  receiver: {receiver.variant}")
        for label, value in (
            ("address", receiver.address),
            ("path prefix", receiver.path_prefix),
            ("key from env", receiver.key_env),
            ("ssh", receiver.ssh),
            ("retention seconds", receiver.retention_seconds),
        ):
            if value is not None:
                lines.append(f"    {label}: {_shown(value)}")
    lines.append(f"  salt from env: {_shown(engagement.salt_env, 'not given')}")
    lines.append(
        f"  known values, replaced when written: {engagement.known_value_count} "
        "(the values are not shown)"
    )
    passthrough = engagement.token_passthrough or "not declared"
    lines += [f"  token passthrough: {_safe(passthrough)}", ""]
    return lines


def _token_source_shown(identity: Identity) -> str:
    seen = f"; observation: {identity.observation}" if identity.observation else ""
    if identity.token_env is not None:
        return (
            f"auth: a token from env {_safe(identity.token_env)} "
            f"(declared; the file holds no value){seen}"
        )
    if identity.token_file is not None:
        return f"auth: a token from a file (declared; the file holds no value){seen}"
    return f"auth: no token (declared; no Authorization header is sent){seen}"


def _era_shown(target: Target) -> str:
    if target.era is None:
        return "not declared"
    return target.era + (f" {_safe(target.era_version)}" if target.era_version else "")


def _ports_shown(target: Target) -> str:
    if target.ports is None:
        return "any"
    listed = ", ".join(str(port) for port in target.ports)
    if target.ports_defaulted:
        return f"{listed} (default for {ENDPOINT_DEFAULT_SCHEME}; not in the file)"
    return listed


def _target_table(targets: tuple[Target, ...]) -> list[str]:
    declared = any(target.era is not None for target in targets)
    head = ("host", "ports", "paths", "isolation floor") + (("declared era",) if declared else ())
    rows = [head]
    for target in targets:
        rows.append(
            (
                _shown(target.host),
                _ports_shown(target),
                "any" if target.paths is None else ", ".join(_safe(p) for p in target.paths),
                target.isolation or "none",
            )
            + ((_era_shown(target),) if declared else ())
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(head))]
    lines = ["  " + "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True))
             for row in rows]  # fmt: skip
    lines.insert(1, "  " + "  ".join("-" * width for width in widths))
    return [line.rstrip() for line in lines]


def _in_zone(engagement: Engagement) -> list[str]:
    """The window in ``window.tz`` when this machine's zone database knows it. Display only:
    a zone the database lacks is said to be unknown here, and the file still loads."""
    if engagement.tz is None:
        return []
    zone_name = _safe(engagement.tz)
    if engagement.window_from is None or engagement.window_until is None:
        return [f"  ({zone_name}: shown once the window is filled in)"]
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

        zone = ZoneInfo(engagement.tz)
    except (ImportError, ZoneInfoNotFoundError, ValueError, OSError):
        return [f"  the zone {zone_name} is unknown on this machine; the window is shown in UTC"]
    start = engagement.window_from.astimezone(zone).isoformat()
    end = engagement.window_until.astimezone(zone).isoformat()
    return [f"  in {zone_name}: {start} to {end}"]


def _pacing_source(pacing: Pacing, name: str) -> str:
    return "from the file" if name in pacing.from_file else "default"


def _shown(value: Any, missing: str = "") -> str:
    if value is None:
        return missing
    # An address is no placeholder, though ``[2001:db8::7]`` has the shape of one.
    if (
        isinstance(value, str)
        and _PLACEHOLDER.fullmatch(value)
        and not good_receiver_address(value)
    ):
        return f"{_safe(value)}  <- placeholder"
    return _safe(value)


def safe_text(value: Any) -> str:
    """A value from the file, without the characters that have no business on a terminal: what
    every value of the file goes through before it is shown."""
    return "".join(
        character
        for character in str(value)
        if unicodedata.category(character) not in _UNSAFE_CATEGORIES
    )


_safe = safe_text
