"""Evidence bundles: what an engagement produced, in one directory a reader can check without
this tool's store.

**Nothing is rewritten.** A bundle holds every recording, scenario, manifest and refusals file
as the bytes that were written, and a copy of the store made by SQLite's own backup from a
read-only connection. :func:`pack` reads; it writes into nothing but the new directory ``out``,
and never into a recording, a run directory or the store. Beside them, the reference page of
every signal the store's findings name (:func:`mcp_kymograph.signals.reference`), as this tool
ships it, under ``reference/``: knowledge about a pattern, never about a server.

**Everything is checked before anything is written.** A run the store filed whose recording is
not found under ``--runs``, or whose bytes are no longer the ones filed (``runs.run`` is the
SHA-256 of the recording), a scenario or a manifest a run names that is not found with the
digest the run recorded, a session made under another engagement, a refusals file that cannot
be read: each refuses the whole pack, with words naming what and where, and ``out`` is not
created. A missing recording is a refusal, never a skipped run — a bundle that left it out
would say less than happened and not know it.

**The index says what is there.** ``index.json`` lists every file with its SHA-256, its size and
its role, and is written last, as canonical JSON (sorted keys), so the same bundle gives the same
index digest. A recording's entry carries the run's state, entry, scenario, mode and isolation
as copies made at pack time; the index says so, and the recording stays authoritative.
``index.json.sig`` is never written here: a signature is made, and checked, by a tool of the
operator's choice, and no cryptography beyond ``hashlib`` enters this project.

**A script is placed masked, a run can be repeated.** The script file of a driven run is given to
:func:`pack` and kept only with the engagement's values replaced (role ``script``, the original's
digest as ``source_digest``); each recording's entry names the image digests of its run.
:func:`replay_plan` reads an intact bundle for the ``drive`` arguments that repeat one run, and
refuses what the run recorded only withheld or masked.

**Verifying reads the index and the files, nothing else.** :func:`verify` recomputes each listed
file's digest and size and says, per file, ``intact``, ``changed`` or ``missing``; a file the
index does not list is ``unlisted``. The bundle is intact only when every listed file is and
nothing is unlisted. No file's claim about itself is trusted, and no symbolic link is followed:
a link where the index lists a file is ``changed`` (it is not the file that was listed), a link
anywhere else is ``unlisted``. Without a digest of the index known from elsewhere (the store's
``bundles``, an attestation), a replaced index cannot be told from the original; with one
(``index_digest``), it can.

**A handover bundle is another bundle.** :func:`review` lists the text surfaces of an intact
bundle's recordings; :func:`redact` writes a new bundle in which the engagement's redaction rules
have blanked values in those surfaces, with ``redactions.json`` saying where and by which rule,
``CUSTOMER-README.md`` beside the index, no store, and an index whose ``derived_from`` is the
source's digest. The source is only read.

**An engagement ends with a purge.** :func:`purge` deletes the store, the operator's notes
beside it (by their name, never opened), the run directories and refusals under the out-dir and
every bundle the store filed, each held to the store's chain first, and writes ``purged.json``.
A run the store filed that is not found under the out-dir is listed as such and the purge is not
complete. It does not reach the operator's files the store
does not name — ``--session`` recordings elsewhere, reports outside a filed bundle, the
attestation, intake answers and drafts — and ``purged.json`` says so.

Every directory written is ``0700`` and every file ``0600``, opened ``O_EXCL`` and
``O_NOFOLLOW``: nothing is overwritten and no link is written through.
"""

from __future__ import annotations

import errno
import hashlib
import itertools
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from mcp_kymograph import corpus, events, handover, inspection, script, store, verdict
from mcp_kymograph.engagement import (
    FORMAT_VERSION_2,
    Engagement,
    EngagementError,
    declared_customer,
    find_refusals,
    read_refusals,
    utc_text,
)
from mcp_kymograph.engagement import load as load_engagement
from mcp_kymograph.handover import (
    CUSTOMER_README,
    ReadmeFields,
    parse_customer_readme,
    render_customer_readme,
)
from mcp_kymograph.identity import IdentityError, from_revision
from mcp_kymograph.masking import PLACEHOLDER, Masker, normalise_key
from mcp_kymograph.operator_notes import beside as notes_beside
from mcp_kymograph.output import (
    DIR_MODE,
    Advisory,
    Severity,
    inspect_destination,
    make_private_directories,
    unusable,
)
from mcp_kymograph.recorder import FILE_MODE, MAX_HTTP_PATH_LENGTH, TOO_DEEP_TO_RECORD
from mcp_kymograph.scenario import MAX_FILE_BYTES, ScenarioError, parse_json, parse_yaml
from mcp_kymograph.signals import Signal, reference
from mcp_kymograph.web._found import (
    RECORDING,
    ROOT_REF,
    Found,
    first_line,
    read_bytes,
    resolve_filed,
    search,
)

#: The one index format this module writes and reads.
INDEX_VERSION = 1

INDEX_FILE = "index.json"
#: A detached signature over ``index.json``, made by the operator's own tool. Never written
#: here; :func:`verify` says when one is present and that it did not check it.
SIGNATURE_FILE = "index.json.sig"
SIGNATURE_NOT_CHECKED = "present; not checked by this tool"
#: What :func:`verify` says of a ``CUSTOMER-README.md`` that names the index it lies beside.
README_NAMES_INDEX = (
    "present; the page this bundle's index, engagement.json and redactions.json give"
)
#: Files at the top of a bundle that the index does not list, and :func:`verify` does not call
#: unlisted: the index, a signature over it, and the README that names its digest.
_BESIDE_THE_INDEX = ("index.json", "index.json.sig", "CUSTOMER-README.md")

ENGAGEMENT_FILE = "engagement.json"
STORE_FILE = "store.sqlite"
TOOL_FILE = "tool.json"
REPORT_FILE = "report.md"
#: Where a bundle holds the signal reference pages, one ``<id>.md`` per signal its findings name.
REFERENCE_DIR = "reference"

#: What a file in a bundle is. A closed set: an index naming any other role is refused whole.
#: ``redactions`` is the ``redactions.json`` of a bundle made by :func:`redact`; ``reference`` a
#: signal's reference page (``reference/<id>.md``). A role is only ever added: an index made
#: before one existed names none of it, and reads as it did.
ROLES = (
    "engagement",
    "manifest",
    "scenario",
    "script",
    "recording",
    "store",
    "refusals",
    "report",
    "tool",
    "redactions",
    "reference",
)

#: A listed file's state in :func:`verify`, and a file the index does not list.
INTACT = "intact"
CHANGED = "changed"
MISSING = "missing"
UNLISTED = "unlisted"
#: The bundle as a whole.
NOT_INTACT = "not_intact"

#: The fixed sentence every index carries about the fields of a recording's entry.
CONVENIENCE_NOTE = (
    "The fields of a recording's entry beside path, sha256, size and role (run, state, entry, "
    "scenario, mode, filed, isolation, egress_observed) are convenience copies made at pack "
    "time, from the store for a filed run and from the recording's verdict for a session; the "
    "recording itself is authoritative."
)

#: Why ``engagement.json``'s two digests differ, as its index entry says it.
ENGAGEMENT_NOTE = (
    "sha256 is the digest of this file: the engagement file as JSON, without what removed "
    "names. source_digest is the digest of the engagement file's own bytes, the one every "
    "recording and the store's chain name. They differ because this is not that file."
)

#: An index larger than this is not read: far beyond what any bundle lists.
MAX_INDEX_BYTES = 64 * 1024 * 1024

#: The fields every entry of ``files`` has, and those each role adds. Closed: an entry with any
#: other key is refused, and so is one without these.
_FILE_KEYS = frozenset({"path", "sha256", "size", "role"})
_ROLE_KEYS: dict[str, frozenset[str]] = {
    "engagement": frozenset({"source_digest", "removed", "digest_note"}),
    "recording": frozenset(
        {"run", "state", "entry", "scenario", "mode", "filed", "isolation", "egress_observed"}
    ),
    "script": frozenset({"source_digest", "runs"}),
}
#: What an entry may add and need not have, so that a bundle packed before the field existed is
#: still read: a recording's ``images``, the digests of the target and sandbox images the run
#: recorded (``target`` and ``sandbox``, each a string, or null where the run had none).
_OPTIONAL_KEYS: dict[str, frozenset[str]] = {
    "recording": frozenset({"images"}),
    "script": frozenset({"pseudonyms", "replayable", "not_replayable"}),
}
#: Whose pseudonyms a placed script carries: the recordings' (the engagement's salt made both),
#: or its own (a run's salt was the run's, or the engagement's is not set where it is packed).
_SCRIPT_PSEUDONYMS = ("as_recordings", "own")
#: What a script's entry says of replaying: ``replayable`` (true when the placed script loads as
#: a script, false when it does not once the engagement's values are replaced in it) and, for
#: false, ``not_replayable``: the place in the script that does not load, never a value.
_IMAGE_KEYS = frozenset({"target", "sandbox"})
#: An image as the index (``images`` of a recording entry) and a recording's
#: ``run_started.reproduction.environment`` may name it: by its id, the digest of its content as
#: Docker gives it (``sha256:`` and 64 hex digits, or the 64 digits alone as other engines give
#: it), never by a name or a tag. A registry refuses 64 hex digits as a name, so the form cannot
#: be a tag. The recording itself is placed as it is: a container run's ``sandbox_step``
#: ``images`` holds, beside each id, the reference as the operator gave it (a tag or a registry
#: path), and keeps it in a handover. That is a reference; no bundle carries an image's content,
#: packed or redacted.
_IMAGE_ID = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
_INDEX_KEYS = frozenset(
    {
        "index_version",
        "engagement",
        "created_utc",
        "derived_from",
        "triage",
        "files",
        "note",
        "page_version",
    }
)
#: ``page_version`` names the wording of the generated page beside the index
#: (:data:`mcp_kymograph.handover.WORDINGS`): required in a bundle made by :func:`redact`, which
#: has that page, and refused in one packed from a store, which has none.
_INDEX_REQUIRED = _INDEX_KEYS - {"page_version"}
_ENGAGEMENT_KEYS = frozenset({"engagement_id_declared", "engagement_digest"})
#: What a recording's entry adds in a derived bundle (``derived_from`` set): the SHA-256 of the
#: recording it was made from, and whether anything in it was blanked. Required there, and
#: refused in a bundle packed from a store, where the recording is the one filed.
_DERIVED_RECORDING_KEYS = frozenset({"source_sha256", "redacted"})
#: What an index says of the triage, counted from the bundle's own store copy: identities of
#: the store's findings no row concerns, and current rows with status ``open`` and ``question``.
TRIAGE_KEYS = ("untriaged", "open", "question")

_DIGEST = re.compile(r"[0-9a-f]{64}")
_PREFIXED_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_RUN_ID = re.compile(r"[0-9a-f]{8}")
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
#: The suffixes a scenario or a manifest is read with; the copy keeps its file's.
_SUFFIXES = (".yaml", ".yml", ".json")

_HASH_CHUNK = 1024 * 1024


class EvidenceError(ValueError):
    """A bundle that is not packed, or an index that is not read, and why — naming what and
    where. A refused pack has written nothing."""


# -- the index ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IndexFile:
    """One entry of an index's ``files``: where the file is in the bundle, its SHA-256 and
    size, its role, and what that role adds (``details``: for ``engagement`` its
    ``source_digest``, ``removed`` and ``digest_note``; for ``recording`` the convenience
    copies :data:`CONVENIENCE_NOTE` names; nothing for the others)."""

    path: str
    sha256: str
    size: int
    role: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
            **{key: _copy(value) for key, value in self.details.items()},
        }


@dataclass(frozen=True, slots=True)
class Index:
    """A bundle's ``index.json`` as read: what the bundle is expected to hold.

    ``digest`` is the SHA-256 of the index file's bytes — what a bundle is known by in the
    store's ``bundles`` and wherever else it is named.
    """

    index_version: int
    engagement_id_declared: str
    engagement_digest: str
    created_utc: str
    derived_from: str | None
    triage: Mapping[str, int] | None
    files: tuple[IndexFile, ...]
    note: str
    digest: str = ""
    #: The version of the wording ``CUSTOMER-README.md`` was made with
    #: (:data:`mcp_kymograph.handover.WORDINGS`); None in a bundle packed from a store, which
    #: has no generated page. :func:`verify` rebuilds the page with this wording, so a later
    #: wording never fails a bundle made before it.
    page_version: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """The index as written: everything but its own digest, which is over these bytes."""
        paged = {} if self.page_version is None else {"page_version": self.page_version}
        return {
            "index_version": self.index_version,
            "engagement": {
                "engagement_id_declared": self.engagement_id_declared,
                "engagement_digest": self.engagement_digest,
            },
            "created_utc": self.created_utc,
            "derived_from": self.derived_from,
            "triage": None if self.triage is None else dict(self.triage),
            "files": [entry.to_dict() for entry in self.files],
            "note": self.note,
            **paged,
        }


def canonical_json(value: Any) -> bytes:
    """The bytes a bundle's JSON files are written as: keys sorted, ASCII, two-space indents,
    one final newline. The same value gives the same bytes, so the same bundle gives the same
    index digest."""
    text = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
    return (text + "\n").encode("ascii")


def index_bytes(index: Index) -> bytes:
    """The index as it is written into a bundle (:func:`canonical_json` of
    :meth:`Index.to_dict`)."""
    return canonical_json(index.to_dict())


def read_index(path: str | Path) -> Index:
    """A bundle's ``index.json``, read whole or refused whole with :class:`EvidenceError`.

    Keys are closed at every level, every type is checked, every digest is 64 lowercase
    hexadecimal digits, every role is one of :data:`ROLES`, and every path is a relative POSIX
    path inside the bundle, listed once, and neither the index nor its signature. A link at
    ``path`` is not followed: the index is refused.
    """
    path = Path(path)
    source = str(path)
    try:
        raw = _read_no_link(path, MAX_INDEX_BYTES)
    except OSError as exc:
        raise EvidenceError(f"{source}: cannot read: {_why(exc)}") from None
    if len(raw) > MAX_INDEX_BYTES:
        raise EvidenceError(f"{source}: larger than {MAX_INDEX_BYTES} bytes; not read")
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_no_constant
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"{source}: not an index: {exc}") from None
    try:
        return _index(data, hashlib.sha256(raw).hexdigest())
    except _Invalid as invalid:
        raise EvidenceError(f"{source}: {invalid.where}: {invalid.message}") from None


class _Invalid(Exception):
    def __init__(self, where: str, message: str) -> None:
        super().__init__(f"{where}: {message}")
        self.where = where
        self.message = message


def _index(data: Any, digest: str) -> Index:
    if not isinstance(data, dict):
        raise _Invalid("index", "expected a JSON object")
    _closed(data, _INDEX_KEYS, _INDEX_REQUIRED, "index")
    version = data["index_version"]
    if type(version) is not int or version != INDEX_VERSION:
        raise _Invalid("index_version", f"{version!r} is not {INDEX_VERSION}, the one read here")
    engaged = data["engagement"]
    if not isinstance(engaged, dict):
        raise _Invalid("engagement", "expected an object")
    _closed(engaged, _ENGAGEMENT_KEYS, _ENGAGEMENT_KEYS, "engagement")
    name = engaged["engagement_id_declared"]
    if not isinstance(name, str) or not name:
        raise _Invalid("engagement.engagement_id_declared", "expected a non-empty string")
    _digest(engaged["engagement_digest"], "engagement.engagement_digest")
    created = data["created_utc"]
    if not isinstance(created, str) or not _UTC_TIME.fullmatch(created):
        raise _Invalid("created_utc", "expected a UTC time ending in Z")
    if data["derived_from"] is not None:
        _digest(data["derived_from"], "derived_from")
    page_version = _page_version(data)
    triage = data["triage"]
    if triage is not None:
        if not isinstance(triage, dict):
            raise _Invalid("triage", "expected an object of counts, or null")
        _closed(triage, frozenset(TRIAGE_KEYS), frozenset(TRIAGE_KEYS), "triage")
        for key, count in triage.items():
            if type(count) is not int or count < 0:
                raise _Invalid(f"triage.{key}", "expected a count, a whole number from 0")
    if not isinstance(data["note"], str):
        raise _Invalid("note", "expected a string")
    listed = data["files"]
    if not isinstance(listed, list):
        raise _Invalid("files", "expected a list")
    files: list[IndexFile] = []
    seen: set[str] = set()
    derived = data["derived_from"] is not None
    for number, item in enumerate(listed):
        entry = _entry(item, f"files[{number}]", derived)
        if entry.path in seen:
            raise _Invalid(f"files[{number}].path", f"{entry.path!r} is listed twice")
        seen.add(entry.path)
        files.append(entry)
    return Index(
        index_version=version,
        engagement_id_declared=name,
        engagement_digest=engaged["engagement_digest"],
        created_utc=created,
        derived_from=data["derived_from"],
        triage=None if triage is None else dict(triage),
        files=tuple(files),
        note=data["note"],
        digest=digest,
        page_version=page_version,
    )


def _page_version(data: dict[str, Any]) -> int | None:
    """The page version of an index, read whole or refused whole: a handover bundle names one
    this tool knows; a bundle packed from a store names none."""
    if data["derived_from"] is None:
        if "page_version" in data:
            raise _Invalid(
                "page_version",
                "a bundle packed from a store has no generated page, so no page version",
            )
        return None
    if "page_version" not in data:
        raise _Invalid(
            "page_version",
            "missing: the bundle was made before its CUSTOMER-README.md carried a page version, "
            "and which wording it was made with cannot be told; make the handover again from "
            "its source bundle with evidence redact",
        )
    try:
        handover.wording(data["page_version"])
    except ValueError as exc:
        raise _Invalid(
            "page_version",
            f"{exc}; check the bundle with the version of the tool that made it",
        ) from None
    return data["page_version"]


def _entry(item: Any, where: str, derived: bool = False) -> IndexFile:
    if not isinstance(item, dict):
        raise _Invalid(where, "expected an object")
    role = item.get("role")
    if role not in ROLES:
        raise _Invalid(f"{where}.role", f"{role!r} is not one of {', '.join(ROLES)}")
    role_keys = _ROLE_KEYS.get(role, frozenset())
    if role == "recording" and derived:
        role_keys = role_keys | _DERIVED_RECORDING_KEYS
    expected = _FILE_KEYS | role_keys
    optional = _OPTIONAL_KEYS.get(role, frozenset())
    _closed(item, expected | optional, expected, where)
    path = item["path"]
    if not _bundle_path(path):
        raise _Invalid(f"{where}.path", f"{path!r} is not a relative path inside the bundle")
    _digest(item["sha256"], f"{where}.sha256")
    size = item["size"]
    if type(size) is not int or size < 0:
        raise _Invalid(f"{where}.size", "expected a size in bytes, a whole number from 0")
    details = {key: item[key] for key in sorted(role_keys | (optional & set(item)))}
    if role == "engagement":
        _digest(details["source_digest"], f"{where}.source_digest")
        removed = details["removed"]
        if not isinstance(removed, list) or not all(
            isinstance(path, str) and path for path in removed
        ):
            raise _Invalid(f"{where}.removed", "expected a list of key paths")
        if not isinstance(details["digest_note"], str):
            raise _Invalid(f"{where}.digest_note", "expected a string")
    elif role == "recording":
        _digest(details["run"], f"{where}.run")
        if details["state"] not in verdict.STATES:
            raise _Invalid(f"{where}.state", f"{details['state']!r} is not a run's state")
        for key in ("entry", "scenario"):
            if details[key] is not None and not isinstance(details[key], str):
                raise _Invalid(f"{where}.{key}", "expected a string or null")
        for key in ("mode", "isolation"):
            if not isinstance(details[key], str):
                raise _Invalid(f"{where}.{key}", "expected a string")
        for key in ("filed", "egress_observed"):
            if not isinstance(details[key], bool):
                raise _Invalid(f"{where}.{key}", "expected true or false")
        if derived:
            _digest(details["source_sha256"], f"{where}.source_sha256")
            if not isinstance(details["redacted"], bool):
                raise _Invalid(f"{where}.redacted", "expected true or false")
        if "images" in details:
            _images(details["images"], f"{where}.images")
    elif role == "script":
        _digest(details["source_digest"], f"{where}.source_digest")
        runs = details["runs"]
        if not isinstance(runs, list) or not runs:
            raise _Invalid(f"{where}.runs", "expected a list of the runs that use the script")
        for number, run in enumerate(runs):
            _digest(run, f"{where}.runs[{number}]")
        if "pseudonyms" in details and details["pseudonyms"] not in _SCRIPT_PSEUDONYMS:
            raise _Invalid(
                f"{where}.pseudonyms", f"expected one of {', '.join(_SCRIPT_PSEUDONYMS)}"
            )
        replayable = details.get("replayable")
        if "replayable" in details and not isinstance(replayable, bool):
            raise _Invalid(f"{where}.replayable", "expected true or false")
        if "not_replayable" in details:
            if replayable is not False:
                raise _Invalid(f"{where}.not_replayable", "only a script with replayable: false")
            if not isinstance(details["not_replayable"], str) or not details["not_replayable"]:
                raise _Invalid(f"{where}.not_replayable", "expected the place, a string")
        elif replayable is False:
            raise _Invalid(f"{where}.not_replayable", "missing: replayable is false")
    return IndexFile(path, item["sha256"], size, role, details)


def _images(value: Any, where: str) -> None:
    if not isinstance(value, dict):
        raise _Invalid(where, "expected an object with target and sandbox")
    _closed(value, _IMAGE_KEYS, _IMAGE_KEYS, where)
    for key, image in value.items():
        if image is not None and not (isinstance(image, str) and _IMAGE_ID.fullmatch(image)):
            raise _Invalid(
                f"{where}.{key}",
                "expected an image id (sha256:<64 hex> or the 64 hex digits alone) or null",
            )


def _closed(mapping: dict, allowed: frozenset[str], required: frozenset[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise _Invalid(where, f"unknown key(s) {', '.join(map(repr, unknown))}")
    absent = sorted(required - set(mapping))
    if absent:
        raise _Invalid(where, f"missing key(s) {', '.join(map(repr, absent))}")


def _digest(value: Any, where: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise _Invalid(where, "expected 64 lowercase hexadecimal digits")


def _bundle_path(value: Any) -> bool:
    """Whether ``value`` names a file inside a bundle: relative, POSIX, no empty, ``.`` or
    ``..`` component, and neither the index nor its signature."""
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        return False
    if "\x00" in value:
        return False
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return value not in _BESIDE_THE_INDEX


# -- packing ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Packed:
    """A bundle that was packed: what the command line files with ``Store.file_bundle`` and
    prints."""

    #: The SHA-256 of ``index.json``'s bytes: what the bundle is known by.
    index_digest: str
    path: Path
    packed_utc: str
    engagement_id_declared: str
    engagement_digest: str
    #: Always None here: a bundle packed from a store derives from nothing. Redaction sets it.
    derived_from: str | None
    #: How many files of each role, every role named.
    counts: Mapping[str, int]
    #: The triage counts the index carries, counted from the bundle's store copy.
    triage: Mapping[str, int] | None = None
    #: Warnings about the destination (``output.inspect_destination``); a refusal never
    #: reaches here.
    advisories: tuple[Advisory, ...] = ()
    #: One line per run whose script file has no entry in the bundle, and why (the file was not
    #: given). Never a value.
    scripts_unplaced: tuple[str, ...] = ()
    #: One line per placed script whose pseudonyms are not those of the recordings. Never a value.
    scripts_own_pseudonyms: tuple[str, ...] = ()
    #: One line per placed script that no longer loads as a script, and the place. Never a value.
    scripts_not_replayable: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_digest": self.index_digest,
            "path": str(self.path),
            "packed_utc": self.packed_utc,
            "engagement_id_declared": self.engagement_id_declared,
            "engagement_digest": self.engagement_digest,
            "derived_from": self.derived_from,
            "counts": dict(self.counts),
            "triage": None if self.triage is None else dict(self.triage),
            "advisories": [advisory.to_dict() for advisory in self.advisories],
            "scripts_unplaced": list(self.scripts_unplaced),
            "scripts_own_pseudonyms": list(self.scripts_own_pseudonyms),
            "scripts_not_replayable": list(self.scripts_not_replayable),
        }


@dataclass(slots=True)
class _Planned:
    """One file the bundle will hold: its path in the bundle, its bytes, its index entry."""

    path: str
    data: bytes
    role: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _ScriptLines:
    """What pack says on stderr about scripts, a line each, never a value: a run whose script
    file was not given, a script with pseudonyms of its own, a script that does not load."""

    unplaced: tuple[str, ...] = ()
    own: tuple[str, ...] = ()
    not_replayable: tuple[str, ...] = ()


@dataclass(slots=True)
class _Recording:
    """A recording to be packed, read once: the bytes that are digested are the bytes written."""

    run: str
    source: str
    data: bytes
    started: dict[str, Any]
    filed: bool
    state: str
    entry: str | None
    scenario: str | None
    isolation: str


def pack(
    *,
    engagement: Engagement,
    store_path: str | Path,
    runs_dir: str | Path,
    sessions: Sequence[str | Path] = (),
    report: str | Path | None = None,
    out: str | Path,
    manifests: Sequence[str | Path] = (),
    scripts: Sequence[str | Path] = (),
    masker_for: Callable[[Sequence[str]], Masker] | None = None,
    now: datetime | None = None,
) -> Packed:
    """Pack the store's engagement into a new directory ``out``, or refuse with
    :class:`EvidenceError` and write nothing.

    ``engagement`` is the operator's file as loaded (:func:`mcp_kymograph.engagement.load`);
    its digest must be in the store's chain. The store is opened read-only and every run it
    holds is packed — one store holds one engagement, so its runs are the
    engagement's. Their recordings are found under ``runs_dir`` by the rule the web interface
    applies (:func:`mcp_kymograph.web._found.resolve_filed`). ``sessions`` are recordings the
    store does not hold — a proxy run, a run without a corpus entry — each made under a digest
    of the chain; the index marks them ``filed: false``. A scenario a run loaded is found through
    the engagement file's ``scenarios``, the manifest's entries and the path the run recorded; a
    manifest a run names through the path it recorded (as given, and against the engagement
    file's directory) and ``manifests``. The index's triage counts are taken from the bundle's
    own store copy, so they say what the bundled store says, whatever was decided meanwhile; a
    bundle with open rows is still packed, and says how many. From the
    same copy come the signals its findings name, and for each of them, and no other, the
    reference page this tool ships is copied to ``reference/<id>.md`` (role ``reference``); every
    page is read before ``out`` is created, so a page that cannot be read refuses the pack.

    ``scripts`` are the script files of the runs that drove one. The recording names a script by
    its digest and not its path, so each file given is matched to the runs by ``script_digest``;
    one that matches no run refuses the pack. A file is placed with the engagement's values
    replaced — read as a document and masked as the recorder masks arguments, then
    ``mask_patterns`` — and placed as JSON, never as it was read. ``masker_for`` gives the masker
    for the ``--mask-key`` names the script's runs recorded (``inputs.mask_keys``, all of them
    together): the engagement's (``cli.pack_masker``), with every credential of the engagement
    file as it can be read now and the salt as literals. Beneath it, drive's masking as the runs'
    recordings hold it is the floor: wherever a run's ``step_called`` holds a masked form, the
    script keeps only exactly that and is blanked otherwise (:func:`_floored_by_runs`), so a
    credential that changed since the run stays out. A run that sent a token given by a flag,
    which no engagement file names and pack cannot know, refuses the pack once its script is
    given. A run whose script was not given has no entry, and
    :attr:`Packed.scripts_unplaced` says so; a script whose pseudonyms are not the recordings'
    (``pseudonyms: own`` in its entry) is said in :attr:`Packed.scripts_own_pseudonyms`. One
    that no longer loads once masked is placed with ``replayable: false`` and the place that does
    not load, and :attr:`Packed.scripts_not_replayable` says so.

    Everything is read and checked first; only then is ``out`` created. Should writing fail
    part-way, what was written is removed again and the refusal says so — or says what could
    not be removed.
    """
    moment = datetime.now(timezone.utc) if now is None else now
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("now must be an aware time")
    packed_utc = utc_text(moment)
    out = Path(out).expanduser()
    runs_root = Path(runs_dir).expanduser()
    if not runs_root.is_dir():
        raise EvidenceError(f"refused: --runs {runs_root} is not a directory")
    advisories = _destination(
        out,
        [
            (
                runs_root,
                f"--runs ({runs_root}); the bundle's copies would be found there as recordings "
                "by the next pack",
            )
        ],
    )

    try:
        source = store.Store.open_read_only(store_path)
    except (store.StoreError, sqlite3.Error, OSError) as exc:
        raise EvidenceError(f"refused: the store cannot be opened for reading: {exc}") from None
    with source:
        try:
            held = source.engagement()
            runs = source.runs()
            filed_paths = source.recordings()
        except (store.StoreError, sqlite3.Error) as exc:
            raise EvidenceError(f"refused: {store_path}: {exc}") from None
        chain = _chain(held, engagement, store_path)
        recordings = _filed(runs, filed_paths, runs_root, store_path)
        recordings += _sessions(sessions, recordings, held, chain)
        planned, lines = _plan(
            engagement, recordings, runs_root, chain, report, manifests, scripts, masker_for
        )
        planned.append(_Planned(TOOL_FILE, canonical_json(_tool()), "tool"))
        pages = _reference_pages()
        return _write(out, planned, pages, source, runs, engagement, packed_utc, advisories, lines)


def _destination(out: Path, apart: Sequence[tuple[Path, str]]) -> tuple[Advisory, ...]:
    """The destination's warnings, or a refusal: ``out`` exists, lies in a git working tree,
    inside a run directory, or under one of ``apart`` (a directory, and why not under it)."""
    if os.path.lexists(out):
        raise EvidenceError(
            f"refused: {out} exists; a bundle is written into a new directory, never over or "
            "beside anything"
        )
    try:
        advisories = inspect_destination(out, out)
        resolved = out.resolve()
        kept_apart = [(directory.resolve(), why) for directory, why in apart]
    except (OSError, RuntimeError) as exc:
        raise EvidenceError(f"refused: {out}: {unusable(exc).message}") from None
    for advisory in advisories:
        if advisory.severity is Severity.REFUSAL:
            raise EvidenceError(f"refused: {out}: {advisory.message}")
    for directory, why in kept_apart:
        if resolved == directory or directory in resolved.parents:
            raise EvidenceError(f"refused: {out} lies under {why}")
    for above in resolved.parents:
        if (above / RECORDING).exists():
            raise EvidenceError(
                f"refused: {out} lies inside a run directory ({above}); nothing is written into one"
            )
    return tuple(advisories)


def _chain(held: dict[str, Any] | None, engagement: Engagement, store_path: Any) -> set[str]:
    if held is None:
        raise EvidenceError(
            f"refused: {store_path} holds no engagement; a bundle is packed from an "
            "engagement's store"
        )
    chain = {entry["digest"] for entry in held["chain"]}
    if engagement.digest not in chain:
        raise EvidenceError(
            f"refused: {engagement.source} (SHA-256 {engagement.digest}) is not a version of "
            f"the engagement {held['engagement_id_declared']!r} that {store_path} holds "
            f"({len(chain)} version(s) in its chain)"
        )
    return chain


def _filed(
    runs: list[store.RunInfo],
    filed_paths: Mapping[str, str],
    runs_root: Path,
    store_path: Any,
) -> list[_Recording]:
    """Every run the store holds, its recording found under ``runs_root`` and read once.
    Not found and changed are two refusals."""
    if not runs:
        return []
    found = search(runs_root)
    unreadable = (
        f"; {len(found.unreadable)} directory(ies) under it could not be listed "
        f"({', '.join(found.unreadable)})"
        if found.unreadable
        else ""
    )
    recordings: list[_Recording] = []
    for run in runs:
        filed = filed_paths[run.run]
        hit = resolve_filed(found, filed)
        if hit is None:
            raise EvidenceError(
                f"refused: run {run.run} ({run.server}, {run.scenario}): its recording, filed "
                f"as {filed}, was not found under {runs_root}{unreadable}; a bundle without it "
                "would say less than happened"
            )
        _, path = hit
        try:
            data = read_bytes(path)
        except OSError as exc:
            raise EvidenceError(
                f"refused: run {run.run}: its recording {path} cannot be read: {_why(exc)}"
            ) from None
        actual = hashlib.sha256(data).hexdigest()
        if actual != run.run:
            raise EvidenceError(
                f"refused: run {run.run} ({run.server}, {run.scenario}): the recording found "
                f"at {path} has SHA-256 {actual}, not the one {store_path} filed; it changed "
                "after ingest, or it is another run's"
            )
        started = _started(data, path)
        recordings.append(
            _Recording(
                run=run.run,
                source=str(path),
                data=data,
                started=started,
                filed=True,
                state=run.state,
                entry=run.server,
                scenario=run.scenario,
                isolation=run.isolation,
            )
        )
    return recordings


def _sessions(
    sessions: Sequence[str | Path],
    filed: list[_Recording],
    held: dict[str, Any],
    chain: set[str],
) -> list[_Recording]:
    """Each ``--session`` recording, read once and judged from its own bytes; refused when the
    store files it already, when it is given twice, or when it was not made under this
    engagement."""
    known = {recording.run: recording for recording in filed}
    recordings: list[_Recording] = []
    for given in sessions:
        path = Path(given)
        if path.is_dir() and not path.is_symlink():
            path = path / RECORDING
        try:
            data = _read_no_link(path)
        except OSError as exc:
            raise EvidenceError(f"refused: session {given}: cannot read: {_why(exc)}") from None
        run = hashlib.sha256(data).hexdigest()
        if run in known:
            other = known[run]
            what = "the store files it as" if other.filed else "it was given already as session"
            raise EvidenceError(
                f"refused: session {given}: {what} run {run} ({other.source}); a recording is "
                "packed once"
            )
        lines, problems = verdict.read_events(data)
        if not lines or lines[0].get("type") != "run_started":
            raise EvidenceError(
                f"refused: session {given}: does not begin with run_started; not a recording"
            )
        started = lines[0]
        engaged = (started.get("authorization") or {}).get("engagement")
        digest = engaged.get("engagement_digest") if isinstance(engaged, dict) else None
        name = engaged.get("engagement_id_declared") if isinstance(engaged, dict) else None
        if digest is None:
            raise EvidenceError(
                f"refused: session {given}: made under no engagement; this bundle is "
                f"{held['engagement_id_declared']!r}'s"
            )
        if digest not in chain or name != held["engagement_id_declared"]:
            raise EvidenceError(
                f"refused: session {given}: made under engagement {name!r} with digest "
                f"{digest}, which is not a version of {held['engagement_id_declared']!r} in the "
                "store's chain; one bundle, one engagement"
            )
        isolation = started.get("isolation")
        recording = _Recording(
            run=run,
            source=str(path),
            data=data,
            started=started,
            filed=False,
            state=verdict.judge(lines, problems).state,
            entry=_text(started.get("server_name")),
            scenario=_text(started.get("scenario_name")),
            isolation=isolation if isinstance(isolation, str) else "host",
        )
        known[run] = recording
        recordings.append(recording)
    return recordings


def _started(data: bytes, path: Path) -> dict[str, Any]:
    lines, _ = verdict.read_events(data)
    if not lines or lines[0].get("type") != "run_started":
        raise EvidenceError(f"refused: {path}: does not begin with run_started; not a recording")
    return lines[0]


def _plan(
    engagement: Engagement,
    recordings: list[_Recording],
    runs_root: Path,
    chain: set[str],
    report: str | Path | None,
    manifests: Sequence[str | Path],
    scripts: Sequence[str | Path],
    masker_for: Callable[[Sequence[str]], Masker] | None,
) -> tuple[list[_Planned], _ScriptLines]:
    """Every file of the bundle but the store's copy, the tool and the index, in memory, and
    the lines about its scripts."""
    planned = [_engagement_file(engagement)]
    found_manifests = _manifests(engagement, recordings, manifests)
    planned += [file for file, _ in found_manifests.values()]
    planned += _scenarios(engagement, recordings, found_manifests)
    placed, lines = _scripts(engagement, recordings, scripts, masker_for)
    planned += placed
    planned += _recordings(recordings)
    planned += _refusals(runs_root, chain)
    if report is not None:
        try:
            data = _read_no_link(Path(report))
        except OSError as exc:
            raise EvidenceError(f"refused: report {report}: cannot read: {_why(exc)}") from None
        planned.append(_Planned(REPORT_FILE, data, "report"))
    return planned, lines


def _engagement_file(engagement: Engagement) -> _Planned:
    try:
        data = canonical_json(engagement.sanitized())
    except (TypeError, ValueError) as exc:
        raise EvidenceError(
            f"refused: {engagement.source}: cannot be written as JSON ({exc})"
        ) from None
    details = {
        "source_digest": engagement.digest,
        "removed": list(engagement.removed),
        "digest_note": ENGAGEMENT_NOTE,
    }
    return _Planned(ENGAGEMENT_FILE, data, "engagement", details)


def _manifests(
    engagement: Engagement,
    recordings: list[_Recording],
    given: Sequence[str | Path],
) -> dict[str, tuple[_Planned, tuple[corpus.ScenarioRef, ...]]]:
    """Each manifest the runs name, by recorded digest: its bytes, and the scenarios its
    entries name — none when it no longer loads (a scenario it lists is gone, say): its bytes
    are still the ones the runs named, and what the runs loaded is looked for elsewhere too."""
    wanted: dict[str, list[tuple[str, str]]] = {}
    for recording in recordings:
        named = (recording.started.get("reproduction") or {}).get("manifest")
        if named is None:
            continue
        digest = named.get("digest") if isinstance(named, dict) else None
        source = named.get("source") if isinstance(named, dict) else None
        if not isinstance(digest, str) or not _PREFIXED_DIGEST.fullmatch(digest):
            raise EvidenceError(
                f"refused: run {recording.run}: the manifest it names has no digest of the "
                f"form sha256:<64 hex digits> ({digest!r})"
            )
        wanted.setdefault(digest, []).append((recording.run, _text(source) or ""))
    directory = Path(engagement.source).resolve().parent
    result: dict[str, tuple[_Planned, tuple[corpus.ScenarioRef, ...]]] = {}
    for digest, named in sorted(wanted.items()):
        candidates: list[Path] = []
        for _, source in named:
            if source:
                candidates.append(Path(source))
                if not Path(source).is_absolute():
                    candidates.append(directory / source)
        candidates += [Path(path) for path in given]
        hit, seen = _first_with(candidates, digest.removeprefix("sha256:"))
        run, source = named[0]
        if hit is None:
            raise EvidenceError(
                f"refused: run {run}: the manifest it names ({source or 'no path recorded'}, "
                f"{digest}) " + _not_found(seen)
            )
        path, data = hit
        try:
            loaded = corpus.load(path)
        except corpus.ManifestError:
            refs: tuple[corpus.ScenarioRef, ...] = ()
        else:
            same = loaded.digest == digest
            refs = tuple(ref for entry in loaded.entries for ref in entry.scenarios) if same else ()
        name = f"manifest/{digest.removeprefix('sha256:')}{_suffix(path)}"
        result[digest] = (_Planned(name, data, "manifest"), refs)
    return result


def _scenarios(
    engagement: Engagement,
    recordings: list[_Recording],
    manifests: Mapping[str, tuple[_Planned, tuple[corpus.ScenarioRef, ...]]],
) -> list[_Planned]:
    """Each scenario a run loaded, by digest, found through the engagement file's
    ``scenarios``, the manifests' entries and the path the run recorded."""
    directory = Path(engagement.source).resolve().parent
    pool = [directory / listed.path for listed in engagement.scenarios]
    by_name: dict[str, list[Path]] = {}
    for _, refs in manifests.values():
        for ref in refs:
            pool.append(ref.path)
            by_name.setdefault(ref.name, []).append(ref.path)
    planned: dict[str, _Planned] = {}
    for recording in recordings:
        digest, recorded = _scenario_of(recording)
        if digest is None or digest in planned:
            continue
        named = [Path(recorded)] if recorded else []
        named += by_name.get(recording.scenario or "", [])
        named += [
            directory / listed.path for listed in engagement.scenarios if listed.sha256 == digest
        ]
        hit, seen = _first_with([*named, *pool], digest)
        if hit is None:
            # Only a file named for this scenario can have changed; any other is merely not it.
            mine = {str(path) for path in named}
            named_seen = {path: actual for path, actual in seen.items() if path in mine}
            raise EvidenceError(
                f"refused: run {recording.run}: the scenario it loaded "
                f"({recording.scenario or recorded}, SHA-256 {digest}) " + _not_found(named_seen)
            )
        path, data = hit
        planned[digest] = _Planned(f"scenarios/{digest}{_suffix(path)}", data, "scenario")
    return list(planned.values())


def _scenario_of(recording: _Recording) -> tuple[str | None, str | None]:
    """The digest of the scenario a run loaded, from its reproduction triple or its
    authorization, and the path it recorded; (None, None) for a run that loaded no file."""
    started = recording.started
    authorization = started.get("authorization") or {}
    triple = (started.get("reproduction") or {}).get("scenario") or {}
    digest = triple.get("digest") if isinstance(triple, dict) else None
    if digest is None:
        digest = authorization.get("scenario_digest")
    if digest is None:
        return None, None
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise EvidenceError(
            f"refused: run {recording.run}: the scenario digest it recorded ({digest!r}) is not "
            "64 lowercase hexadecimal digits"
        )
    recorded = authorization.get("scenario")
    return digest, recorded if isinstance(recorded, str) and recorded else None


def _first_with(
    candidates: Sequence[Path], digest: str
) -> tuple[tuple[Path, bytes] | None, dict[str, str]]:
    """The first candidate whose bytes have SHA-256 ``digest``, and what every candidate read
    had instead (path → digest, or the reason it could not be read)."""
    seen: dict[str, str] = {}
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        try:
            data = _read_no_link(path, MAX_FILE_BYTES)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                seen[key] = f"cannot be read: {_why(exc)}"
            continue
        if len(data) > MAX_FILE_BYTES:
            seen[key] = f"larger than {MAX_FILE_BYTES} bytes"
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual == digest:
            return (path, data), seen
        seen[key] = f"SHA-256 {actual}"
    return None, seen


def _not_found(seen: Mapping[str, str]) -> str:
    if not seen:
        return "was not found"
    there = "; ".join(f"{path}: {what}" for path, what in seen.items())
    return f"was not found with that digest — it changed, or another file is there ({there})"


def _script_of(recording: _Recording) -> str | None:
    """The digest of the script file a run drove, or None for a run that drove none."""
    digest = recording.started.get("script_digest")
    if digest is None:
        return None
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise EvidenceError(
            f"refused: run {recording.run}: the script digest it recorded (script_digest) is not "
            "64 lowercase hexadecimal digits"
        )
    return digest


def _scripts(
    engagement: Engagement,
    recordings: list[_Recording],
    given: Sequence[str | Path],
    masker_for: Callable[[Sequence[str]], Masker] | None,
) -> tuple[list[_Planned], _ScriptLines]:
    """Each script file a run drove, by recorded digest, as the document of the file given for
    it with the engagement's values replaced, written as JSON; a line for each run whose file
    was not given; a line for each script whose pseudonyms are not the recordings'; a line for
    each script that no longer loads once the values are replaced (it is placed all the same,
    ``replayable: false``).

    The recording holds the script's name and digest and no path, so what ``--script`` names is
    matched by its bytes: a file whose digest no run recorded refuses the pack, and so does one
    that cannot be read as a script (``script.build``), and the refusal names the place and never
    what stands there. Only the masked document is kept; the original's digest is the entry's
    ``source_digest``."""
    by_digest: dict[str, list[_Recording]] = {}
    for recording in recordings:
        digest = _script_of(recording)
        if digest is not None:
            by_digest.setdefault(digest, []).append(recording)
    files: dict[str, tuple[Path, bytes]] = {}
    for path in map(Path, given):
        try:
            data = _read_no_link(path, MAX_FILE_BYTES)
        except OSError as exc:
            raise EvidenceError(f"refused: --script {path}: cannot read: {_why(exc)}") from None
        if len(data) > MAX_FILE_BYTES:
            raise EvidenceError(f"refused: --script {path}: larger than {MAX_FILE_BYTES} bytes")
        digest = hashlib.sha256(data).hexdigest()
        if digest not in by_digest:
            raise EvidenceError(
                f"refused: --script {path} (SHA-256 {digest}) is the script of no run in this "
                "bundle; it changed since the runs, or it is another file"
            )
        files.setdefault(digest, (path, data))
    planned: list[_Planned] = []
    unplaced: list[str] = []
    own: list[str] = []
    broken: list[str] = []
    for digest, users in sorted(by_digest.items()):
        if digest not in files:
            unplaced.extend(
                f"run {_label(user)}: its script file (SHA-256 {digest}) was not given with "
                "--script; the bundle has no script for it"
                for user in users
            )
            continue
        if masker_for is None:
            raise EvidenceError("refused: a script is placed with the engagement's values replaced")
        for user in users:
            if _token_by_flag(user.started):
                raise EvidenceError(
                    f"refused: run {_label(user)}: auth: it sent a token given by a flag "
                    "(--token-env or --token-file), which no engagement file names, so its value "
                    "cannot be replaced in the script; nothing was packed. Pack without its "
                    "script, or run the script under an identity of the engagement file"
                )
        masker = masker_for(_mask_keys_of(users))
        path, data = files[digest]
        text, not_replayable = _masked_script(engagement, users, path, data, masker)
        # The pseudonyms in the copy are the recordings' only where both are made with the
        # engagement's salt: the salt of a per-run recording was never recorded.
        same = masker.pseudonyms == "per_engagement" and all(
            user.started.get("pseudonyms") == "per_engagement" for user in users
        )
        if not same:
            own.append(
                f"script {digest}: its pseudonyms are its own and are not those of the "
                "recordings (a run's salt was its own, or the engagement's salt is not set here)"
            )
        details = {
            "source_digest": digest,
            "runs": sorted(user.run for user in users),
            "pseudonyms": "as_recordings" if same else "own",
            "replayable": not_replayable is None,
        }
        if not_replayable is not None:
            details["not_replayable"] = not_replayable
            broken.append(
                f"script {digest}: placed, and not replayable: it does not load once the "
                f"engagement's values are replaced in it ({not_replayable})"
            )
        planned.append(_Planned(f"scripts/{digest}.json", text.encode("utf-8"), "script", details))
    return planned, _ScriptLines(tuple(unplaced), tuple(own), tuple(broken))


def _label(recording: _Recording) -> str:
    return _run_label(recording.started, recording.run)


def _run_label(started: Mapping[str, Any], run: str) -> str:
    """How a run is named in words: its own id where that is one, else its digest. A recorded
    id of another form is not shown."""
    run_id = _text(started.get("run_id"))
    return run_id if run_id and _RUN_ID.fullmatch(run_id) else run


def _token_by_flag(started: Mapping[str, Any]) -> bool:
    """Whether a run sent a token that came from a flag (``--token-env``, ``--token-file``) and
    not from an identity of the engagement file: ``auth`` names no identity, and a token was
    used. An identity recorded masked is still one of the file's."""
    auth = started.get("auth")
    return isinstance(auth, dict) and auth.get("identity") is None and bool(auth.get("token_used"))


def _mask_keys_of(users: list[_Recording]) -> list[str]:
    """The ``--mask-key`` names the runs of one script recorded (``inputs.mask_keys``), all of
    them, in the order first seen. A run that recorded them in another shape refuses the pack:
    the script would be masked with fewer keys than the run was."""
    keys: dict[str, None] = {}
    for user in users:
        inputs = user.started.get("inputs")
        named = inputs.get("mask_keys", []) if isinstance(inputs, dict) else []
        if named is None:
            named = []
        if not isinstance(named, list) or not all(
            isinstance(key, str) and normalise_key(key) for key in named
        ):
            raise EvidenceError(
                f"refused: run {_label(user)}: inputs.mask_keys is not a list of names; the "
                "script cannot be masked with the keys the run was masked with"
            )
        keys.update(dict.fromkeys(named))
    return list(keys)


def _masked_script(
    engagement: Engagement,
    users: list[_Recording],
    path: Path,
    data: bytes,
    masker: Masker,
) -> tuple[str, str | None]:
    """The script's document with the engagement's values replaced, as JSON text, and the place
    that no longer loads as a script once they are replaced (None if it all loads).

    The file is read as the tool reads a script (its suffix says YAML or JSON, and the document
    must build as a script) and the document runs through the masking the recorder applies to
    arguments (``Masker.mask_json``: secret keys, ``mask_keys``, literals, known values, the
    three shapes), then the engagement's ``mask_patterns``, then numbers that hold a known value
    or a literal (:func:`_numbers_masked`), then drive's masking as the runs recorded it
    (:func:`_floored_by_runs`); what is left is held to redact's check, and refused if anything
    is found. Comments are not kept. A run whose
    pseudonyms last across the engagement is held to a masker that has the salt. A file that is
    no script is refused, naming the place and nothing the loader says of what stands there."""
    if masker.pseudonyms != "per_engagement" and any(
        user.started.get("pseudonyms") == "per_engagement" for user in users
    ):
        salt = engagement.salt_env or "salt_env"
        raise EvidenceError(
            f"refused: --script {path}: the runs' pseudonyms are the engagement's, and the "
            f"environment variable {salt} that holds the salt is not set here; without it the "
            "script would carry other pseudonyms than the recordings"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"refused: --script {path}: not UTF-8 at byte {exc.start}") from None
    # Whether a file is a script does not depend on the values of its placeholders.
    stand_in = dict.fromkeys(script.PLACEHOLDERS, "x")
    try:
        if path.suffix.lower() not in script.SUFFIXES:
            raise script.ScriptError(f"unknown suffix {path.suffix!r}; use .yaml, .yml or .json")
        if path.suffix.lower() == ".json":
            document = parse_json(text, source=str(path))
        else:
            document = parse_yaml(text, source=str(path))
        script.build(document, source=str(path), variables=stand_in)
    except (ScenarioError, script.ScriptError) as exc:
        raise EvidenceError(
            f"refused: --script {path}: not readable as a script: {_where(exc)}"
        ) from None
    try:
        masked, _ = masker.mask_json(document)
        masked = _blanked(masked, engagement.mask_patterns)
        masked = _numbers_masked(masked, masker)
        masked, unsent = _floored_by_runs(masked, users, path)
        text = json.dumps(masked, ensure_ascii=False, indent=2) + "\n"
        left = any(masker.holds_known_value(found) for found in _texts_of(masked))
    except RecursionError:
        raise EvidenceError(
            f"refused: --script {path}: nested too deeply once the engagement's values are "
            "replaced in it; nothing of it is placed"
        ) from None
    if left:
        # The check redact makes, made here on what would be placed: nothing of it is placed.
        raise EvidenceError(
            f"refused: --script {path}: a credential, the salt or a known value is still in it "
            "once masked; nothing was packed"
        )
    if unsent is not None:
        return text, unsent
    try:
        script.build(masked, source=str(path), variables=stand_in)
    except script.ScriptError as exc:
        return text, _where(exc)
    return text, None


def _numbers_masked(value: Any, masker: Masker) -> Any:
    """``value`` with each number whose JSON text holds a known value or a literal replaced by
    that text as the masker masks a string, as if it had been quoted (``47110815`` with the known
    value ``4711`` becomes ``***KNOWN-…***0815``). A bool is no number."""
    if isinstance(value, dict):
        return {key: _numbers_masked(item, masker) for key, item in value.items()}
    if isinstance(value, list):
        return [_numbers_masked(item, masker) for item in value]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        written = json.dumps(value)
        if masker.holds_known_value(written):
            return masker.mask_json(written)[0]
    return value


class _Misaligned(Exception):
    """A call step of the script and a call a run recorded do not have the same shape."""


def _is_masked(value: Any) -> bool:
    """Whether a value stands as a stand-in of the masker: the placeholder, a pseudonym, any
    other ``***…***``, a withheld path."""
    return isinstance(value, str) and ("***" in value or _WITHHELD in value)


def _as_filled(text: str) -> re.Pattern[str]:
    """The strings ``text`` can become once drive fills its placeholders (any text for each
    ``{name}`` of :data:`mcp_kymograph.script.PLACEHOLDERS`, a brace for ``{{`` or ``}}``)."""
    parts = []
    position = 0
    for found in _FILLED.finditer(text):
        parts.append(re.escape(text[position : found.start()]))
        token = found.group(0)
        parts.append(re.escape(token[0]) if token in ("{{", "}}") else "(?s:.*)")
        position = found.end()
    parts.append(re.escape(text[position:]))
    return re.compile("".join(parts))


_FILLED = re.compile(r"\{\{|\}\}|\{(?:" + "|".join(script.PLACEHOLDERS) + r")\}")


def _held(placed: Any, recorded: Any) -> Any:
    """One position of the floor where the recording holds a masked form: the placed text is
    kept only if it is exactly what the recording holds, else the placeholder stands for the
    whole position. Whatever pack masked in it is no reason to keep it: a part pack did not mask
    (a token rotated since the run) would stay beside a part it did."""
    return placed if placed == recorded else PLACEHOLDER


def _floor(placed: Any, recorded: Any) -> Any:
    """``placed`` (a part of the placed script) floored by what one run recorded at the same
    place: wherever the recording holds a masked form, ``placed`` is kept only where it is
    exactly that, and is blanked whole otherwise (:func:`_held`); :class:`_Misaligned` where the
    two differ in shape, or in a value the recording holds unmasked and pack left unmasked too. A
    position the recording holds unmasked and pack masked stays as pack masked it. A string of
    the script with a placeholder matches what drive filled in; where drive's text holds
    anything masked, the whole string is blanked."""
    if _is_masked(recorded):
        return _held(placed, recorded)
    if _is_masked(placed):
        return placed
    if isinstance(placed, dict):
        if not isinstance(recorded, dict) or len(recorded) != len(placed):
            raise _Misaligned
        floored: dict[str, Any] = {}
        for (key, item), (seen, held) in zip(placed.items(), recorded.items(), strict=True):
            if _is_masked(seen):
                key = _held(key, seen)
            elif key != seen and not _is_masked(key):
                raise _Misaligned
            if key in floored:
                # Two keys blanked: each keeps a key of its own, so no value is lost.
                number = 1
                while f"{PLACEHOLDER}-{number}" in floored:
                    number += 1
                key = f"{PLACEHOLDER}-{number}"
            floored[key] = _floor(item, held)
        return floored
    if isinstance(placed, list):
        if not isinstance(recorded, list) or len(recorded) != len(placed):
            raise _Misaligned
        return [_floor(item, held) for item, held in zip(placed, recorded, strict=True)]
    if isinstance(placed, str):
        if not isinstance(recorded, str) or not _as_filled(placed).fullmatch(recorded):
            raise _Misaligned
        return placed
    if type(placed) is not type(recorded) or placed != recorded:
        raise _Misaligned
    return placed


def _floor_call(call: Any, record: dict[str, Any]) -> dict[str, Any]:
    """A call step of the placed script floored by one ``step_called`` of a run: its tool, its
    check and its arguments. Where the recorded tool or check holds a masked form, the placed
    one keeps only exactly what the recording holds there; otherwise the two are compared."""
    if not isinstance(call, dict):
        raise _Misaligned
    floored = dict(call)
    tool, seen = call.get("tool"), record.get("tool")
    if not isinstance(seen, str):
        raise _Misaligned
    if _is_masked(seen):
        floored["tool"] = _held(tool, seen)
    elif tool != seen and not _is_masked(tool):
        raise _Misaligned
    check, seen_check = call.get("check"), record.get("check")
    if _is_masked(seen_check):
        floored["check"] = _held(check, seen_check)
    elif check != seen_check and not _is_masked(check):
        raise _Misaligned
    arguments = call.get("arguments")
    held = record.get("arguments")
    if held == TOO_DEEP_TO_RECORD:
        pass  # blanked whole by the caller, as a call that was not sent
    elif arguments is None:
        if held not in ({}, None):
            raise _Misaligned
    else:
        floored["arguments"] = _floor(arguments, held)
    return floored


def _floored_by_runs(masked: Any, users: list[_Recording], path: Path) -> tuple[Any, str | None]:
    """The placed script with drive's masking as the floor: each call step is aligned with the
    calls the runs recorded as sent (``step_called``, in order), and every key or value (tool name,
    check) a run holds with a masked form in it is kept only where the script holds exactly that,
    and blanked whole otherwise (:func:`_floor`); a call step no run recorded as sent has its
    arguments and its tool's name blanked, and the first such step is returned as the place that
    makes the script not replayable. A run's recorded name of the script is held to the same
    rule.

    The calls a run sent are those of its script in order, some left out (a step skipped, the
    run halted): every order-keeping choice of call steps for the recorded calls is tried, and
    each one in which every pair matches counts. Where several do, each one's blanks are made,
    and a step counts as sent only if it is sent in all of them. Where none does, or a run
    recorded more calls than the script has, or its calls cannot be read, the pack is refused."""
    steps = masked.get("steps") if isinstance(masked, dict) else None
    if not isinstance(steps, list):
        raise EvidenceError(
            f"refused: --script {path}: its steps are no list once masked; nothing was packed"
        )
    calls = [index for index, step in enumerate(steps) if isinstance(step, dict) and "call" in step]
    sent: set[int] = set()
    too_deep: set[int] = set()
    for user in users:
        label = _label(user)
        recorded_name = user.started.get("script")
        name = masked.get("name")
        if _is_masked(recorded_name):
            masked = {**masked, "name": _held(name, recorded_name)}
        elif name != recorded_name and not _is_masked(name):
            raise EvidenceError(
                f"refused: run {label}: the script name it recorded (script) is not the "
                f"name of --script {path}; nothing was packed"
            )
        records = _calls_recorded(user)
        if len(records) > len(calls):
            raise EvidenceError(
                f"refused: run {label} recorded more calls (step_called) than --script {path} "
                "has call steps; nothing was packed"
            )
        matching = []
        for chosen in itertools.combinations(calls, len(records)):
            try:
                for index, record in zip(chosen, records, strict=True):
                    _floor_call(steps[index]["call"], record)
            except _Misaligned:
                continue
            matching.append(list(zip(chosen, records, strict=True)))
        if not matching:
            where = "its call steps"
            if len(records) == len(calls):
                for index, record in zip(calls, records, strict=True):
                    try:
                        _floor_call(steps[index]["call"], record)
                    except _Misaligned:
                        where = f"steps[{index}]"
                        break
            raise EvidenceError(
                f"refused: run {label}: the calls it recorded (step_called) do not match "
                f"{where} of --script {path} in order; nothing was packed"
            )
        for pairs in matching:
            for index, record in pairs:
                # Floored against the step as it now stands: the blanks of each choice add up.
                steps[index] = {**steps[index], "call": _floor_call(steps[index]["call"], record)}
                if record.get("arguments") == TOO_DEEP_TO_RECORD:
                    too_deep.add(index)
        sent |= set.intersection(*({index for index, _ in pairs} for pairs in matching))
    # A call whose arguments the run could not record is blanked as one that was not sent.
    unsent = [index for index in calls if index not in sent or index in too_deep]
    for index in unsent:
        # Nothing of it was recorded to hold it to: its tool's name, which drive masks with the
        # run's literals, is blanked as well as its arguments.
        call = {**steps[index]["call"], "tool": PLACEHOLDER, "arguments": {}}
        steps[index] = {**steps[index], "call": call}
    masked = {**masked, "steps": steps}
    first = f"steps[{unsent[0]}].call: sent in no run" if unsent else None
    return masked, first


def _calls_recorded(user: _Recording) -> list[dict[str, Any]]:
    """The ``step_called`` events of a run, in order; a recording that cannot be read there
    refuses the pack."""
    records = []
    for number, (line, event) in enumerate(_lines(user.data)):
        if event is None:
            if line.strip():
                raise EvidenceError(
                    f"refused: run {_label(user)}: line {number + 1} of its recording is no "
                    "event; its calls cannot be read; nothing was packed"
                )
            continue
        if event.get("type") == events.EventType.STEP_CALLED.value:
            if not isinstance(event.get("tool"), str) or "arguments" not in event:
                raise EvidenceError(
                    f"refused: run {_label(user)}: a step_called at line {number + 1} lacks its "
                    "tool or arguments; nothing was packed"
                )
            records.append(event)
    return records


def _where(exc: Exception) -> str:
    """Where in a script file a loader's error is, and nothing of what stands there: the
    exception's ``where`` (a script's error has one, a parse error has none), or "the file".
    A place below ``arguments`` is cut there: the rest of it is a key of the customer's."""
    where = getattr(exc, "where", "") or "the file"
    head, found, _ = where.partition(".arguments")
    return head + found


def _blanked(value: Any, literals: Sequence[str]) -> Any:
    """``value`` with each literal replaced by the placeholder in every string and every key,
    and a number whose JSON text holds one replaced by the placeholder, as a string. A bool is
    no number."""

    def blank(text: str) -> str:
        for literal in literals:
            text = text.replace(literal, PLACEHOLDER)
        return text

    if isinstance(value, dict):
        return {
            (blank(key) if isinstance(key, str) else key): _blanked(item, literals)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_blanked(item, literals) for item in value]
    if isinstance(value, str):
        return blank(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        written = json.dumps(value)
        return PLACEHOLDER if any(literal in written for literal in literals if literal) else value
    return value


def _images_of(recording: _Recording) -> dict[str, str | None]:
    """The digests of the target and sandbox images a run recorded in its reproduction
    triple's environment; null for one it had none of (an endpoint, no container).

    This tool records an image there by its id only (``cli.pin_images``, ``fleet.pin``; the
    reference the operator gave stands beside the id in the ``sandbox_step`` ``images`` of the
    recording, which is placed as it is); a recording that names one otherwise there — a
    session made elsewhere or edited — refuses the pack, so that the index never names an image
    by a name or tag."""
    environment = (recording.started.get("reproduction") or {}).get("environment")
    environment = environment if isinstance(environment, dict) else {}
    images = {}
    for key, name in (("target", "target_image"), ("sandbox", "sandbox_image")):
        image = environment.get(name)
        if image is not None and not (isinstance(image, str) and _IMAGE_ID.fullmatch(image)):
            raise EvidenceError(
                f"refused: run {recording.run}: reproduction.environment.{name} does not name "
                "the image by its id; the index names an image only by its id (sha256:<64 hex> or "
                "the 64 hex digits alone), never by a name or tag; nothing was packed"
            )
        images[key] = image
    return images


def _recordings(recordings: list[_Recording]) -> list[_Planned]:
    """Each recording at ``runs/<run id>/events.jsonl`` — by the run's own id where it has one
    no other packed run shares, else by its digest."""
    ids = [_text(recording.started.get("run_id")) for recording in recordings]
    planned = []
    for recording, run_id in zip(recordings, ids, strict=True):
        unique = run_id is not None and _RUN_ID.fullmatch(run_id) and ids.count(run_id) == 1
        name = run_id if unique else recording.run
        mode = recording.started.get("mode")
        details = {
            "run": recording.run,
            "state": recording.state,
            "entry": recording.entry,
            "scenario": recording.scenario,
            "mode": mode if isinstance(mode, str) else "",
            "filed": recording.filed,
            "isolation": recording.isolation,
            "egress_observed": recording.isolation in verdict.OBSERVED_ISOLATIONS,
            "images": _images_of(recording),
        }
        planned.append(_Planned(f"runs/{name}/{RECORDING}", recording.data, "recording", details))
    return planned


def _refusals(runs_root: Path, chain: set[str]) -> list[_Planned]:
    """Every refusals file under ``runs_root``, as its bytes. One that cannot be read refuses
    the pack, and so does one that records a refusal under another engagement."""
    try:
        found = find_refusals(runs_root)
    except EngagementError as exc:
        raise EvidenceError(f"refused: --runs: {exc}") from None
    planned = []
    for item in found:
        if item.refused is not None:
            raise EvidenceError(
                f"refused: {item.path}: {item.refused}; a refusals file that cannot be read "
                "cannot be packed, and leaving it out would count fewer refusals than there were"
            )
        for number, record in enumerate(item.records, start=1):
            if record.engagement_digest not in chain:
                raise EvidenceError(
                    f"refused: {item.path}: line {number} records a refusal under engagement "
                    f"{record.engagement_id_declared!r} with digest {record.engagement_digest}, "
                    "not of this store's chain; one out-dir per engagement"
                )
        try:
            data = _read_no_link(item.path)
        except OSError as exc:
            raise EvidenceError(f"refused: {item.path}: cannot read: {_why(exc)}") from None
        relative = item.path.parent.relative_to(runs_root).as_posix()
        prefix = "refusals" if relative == "." else f"refusals/{relative}"
        planned.append(
            _Planned(
                f"{prefix}/{item.path.name}",
                data,
                "refusals",
                {"_records": item.records},
            )
        )
    return planned


def _tool() -> dict[str, Any]:
    return {
        "tool": corpus.tool_identity(),
        "rules_version": verdict.RULES_VERSION,
        "recording_schema": events.SCHEMA_VERSION,
        "store_schema": store.SCHEMA_VERSION,
    }


# -- writing ------------------------------------------------------------------------------


class _Written:
    """What one pack created, so that a pack that fails part-way can take it back."""

    def __init__(self) -> None:
        self.files: list[Path] = []
        self.directories: list[Path] = []
        #: The store copy: the one file SQLite may have put a journal beside.
        self.database: Path | None = None

    def directory(self, path: Path) -> None:
        os.mkdir(path, DIR_MODE)
        self.directories.append(path)

    def parents(self, path: Path) -> None:
        """Create every missing level above ``path``, each ``0700``, outermost first, as
        ``output.make_private_directories`` does — and keep each one created here, so that it
        is taken back too. A level another process made meanwhile is its, and is left alone."""
        missing: list[Path] = []
        current = path.parent
        while not os.path.lexists(current) and current.parent != current:
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            try:
                self.directory(directory)
            except FileExistsError:
                continue

    def file(self, path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags, FILE_MODE)
        self.files.append(path)
        try:
            # Ours from the first byte: the mode exactly, whatever the umask took away.
            os.fchmod(descriptor, FILE_MODE)
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def take_back(self) -> list[str]:
        """Remove what was created, newest first; what could not be removed, by path."""
        left: list[str] = []
        names = list(reversed(self.files))
        if self.database is not None:
            names[:0] = [Path(f"{self.database}{extra}") for extra in ("-journal", "-wal", "-shm")]
        for path in names:
            try:
                os.unlink(path)
            except FileNotFoundError:
                continue
            except OSError:
                left.append(str(path))
        # Only directories created here, and only empty ones: rmdir removes nothing else.
        for path in reversed(self.directories):
            try:
                os.rmdir(path)
            except OSError:
                left.append(str(path))
        return left


def _write(
    out: Path,
    planned: list[_Planned],
    pages: Mapping[Signal, bytes],
    source: store.Store,
    runs: list[store.RunInfo],
    engagement: Engagement,
    packed_utc: str,
    advisories: tuple[Advisory, ...],
    lines: _ScriptLines,
) -> Packed:
    written = _Written()
    try:
        written.parents(out)
        written.directory(out)
        for item in planned:
            _place(out, item, written)
        # Written here, by SQLite, not placed: the copy's bytes are known once it is made.
        copy, triage, reported = _copy_store(out, source, runs, written)
        # The pages were read before ``out`` was made; the copy only says which of them go in.
        listed = [
            _Planned(f"{REFERENCE_DIR}/{signal.value}.md", pages[signal], "reference")
            for signal in reported
        ]
        for item in listed:
            _place(out, item, written)
        planned = [copy, *planned, *listed]
        entries = [
            IndexFile(
                item.path,
                hashlib.sha256(item.data).hexdigest(),
                len(item.data),
                item.role,
                {k: v for k, v in item.details.items() if not k.startswith("_")},
            )
            for item in planned
        ]
        index = Index(
            index_version=INDEX_VERSION,
            engagement_id_declared=engagement.id,
            engagement_digest=engagement.digest,
            created_utc=packed_utc,
            derived_from=None,
            triage=triage,
            files=tuple(sorted(entries, key=lambda entry: entry.path)),
            note=CONVENIENCE_NOTE,
        )
        data = index_bytes(index)
        written.file(out / INDEX_FILE, data)
        digest = _read_back(out, index, data, planned)
    except (OSError, sqlite3.Error, store.StoreError, EngagementError, EvidenceError) as exc:
        left = written.take_back()
        why = str(exc) if isinstance(exc, EvidenceError) else _why(exc)
        if left:
            raise EvidenceError(
                f"refused: writing {out} failed ({why}); what it wrote was removed except "
                f"{', '.join(left)}"
            ) from None
        raise EvidenceError(
            f"refused: writing {out} failed ({why}); what it wrote was removed"
        ) from None
    counts = dict.fromkeys(ROLES, 0)
    for item in planned:
        counts[item.role] += 1
    return Packed(
        index_digest=digest,
        path=out,
        packed_utc=packed_utc,
        engagement_id_declared=engagement.id,
        engagement_digest=engagement.digest,
        derived_from=None,
        counts=counts,
        triage=triage,
        advisories=advisories,
        scripts_unplaced=lines.unplaced,
        scripts_own_pseudonyms=lines.own,
        scripts_not_replayable=lines.not_replayable,
    )


def _place(out: Path, item: _Planned, written: _Written) -> None:
    parts = PurePosixPath(item.path).parts
    directory = out
    for part in parts[:-1]:
        directory = directory / part
        if not directory.is_dir() or directory.is_symlink():
            written.directory(directory)
    written.file(directory / parts[-1], item.data)


def _copy_store(
    out: Path, source: store.Store, runs: list[store.RunInfo], written: _Written
) -> tuple[_Planned, dict[str, int], tuple[Signal, ...]]:
    """The whole store, through SQLite's backup from the read-only connection, into a new
    ``0600`` file; read back and opened as a store before it is listed. With it, the triage
    counts of the copy and the signals its findings name — the store the bundle holds, not the
    one that may have moved on."""
    path = out / STORE_FILE
    written.file(path, b"")
    written.database = path
    target = sqlite3.connect(str(path))
    try:
        # Kept in memory: no journal file appears beside the copy in the bundle.
        target.execute("PRAGMA journal_mode = MEMORY")
        source.backup_into(target)
    finally:
        target.close()
    with store.Store.open_read_only(path) as copy:
        copied = {run.run for run in copy.runs()}
        triage = triage_counts(copy)
        reported = reported_signals(copy)
    if copied != {run.run for run in runs}:
        raise EvidenceError(f"the store's copy {path} does not hold the store's runs")
    data = _read_no_link(path)
    return _Planned(STORE_FILE, data, "store"), triage, reported


def reported_signals(held: store.Store) -> tuple[Signal, ...]:
    """The signals a store's findings name, of every provenance, in the order of
    :class:`~mcp_kymograph.signals.Signal`. A name that is no signal of this tool has no page
    and is not among them."""
    named = {
        finding["signal"]
        for provenance in corpus.PROVENANCES
        for finding in held.findings_by_provenance(provenance)
    }
    return tuple(signal for signal in Signal if signal.value in named)


def reference_page_refusal(signal: Signal, exc: BaseException) -> str:
    """The refusal for a reference page the installed package cannot read (``exc``), up to
    what was not done, which the caller adds: it names the page by its signal id and says the
    installation is incomplete. ``evidence pack`` and ``signals list --reference`` share it."""
    return (
        f"refused: the reference page of {signal.value} cannot be read from the installed "
        f"package ({_why(exc)}); the installation is incomplete"
    )


def _reference_pages() -> dict[Signal, bytes]:
    """Every signal's reference page, as the installed package holds it, read before anything
    is written: which of them a bundle holds is known only once the store's copy is made, and
    a page that cannot be read then would leave half a bundle. A page that cannot be read or is
    not UTF-8 refuses the pack, and ``out`` is not created — whichever signals the store's
    findings name, the page of a signal none of them names too. The reason: a page the
    package cannot read means the installation is damaged, and a damaged tool packs no evidence.
    The refusal names the page by its signal id, says the installation is incomplete and that
    nothing was packed."""
    pages: dict[Signal, bytes] = {}
    for signal in Signal:
        try:
            pages[signal] = reference(signal).encode("utf-8")
        except (OSError, ValueError) as exc:
            raise EvidenceError(
                f"{reference_page_refusal(signal, exc)}, and nothing was packed: a damaged "
                "installation packs no evidence, whichever signals the findings name"
            ) from None
    return pages


def triage_counts(held: store.Store) -> dict[str, int]:
    """What an index says of a store's triage (:data:`TRIAGE_KEYS`): how many identities of
    its findings no row concerns, in either role, and how many current rows — the latest of
    each identity and role — are ``open`` and ``question``. A snapshot, not an approval."""
    current = held.triage_current()
    concerned = {tuple(row["identity"][name] for name in store.IDENTITY_FIELDS) for row in current}
    identities = {
        tuple(finding[name] for name in store.IDENTITY_FIELDS)
        for provenance in corpus.PROVENANCES
        for finding in held.findings_by_provenance(provenance)
    }
    return {
        "untriaged": len(identities - concerned),
        "open": sum(1 for row in current if row["status"] == "open"),
        "question": sum(1 for row in current if row["status"] == "question"),
    }


def _read_back(out: Path, index: Index, data: bytes, planned: list[_Planned]) -> str:
    """Read what was written: the index through :func:`read_index`, every file through
    :func:`verify`, every refusals copy through :func:`read_refusals`. The index digest, or a
    refusal."""
    again = read_index(out / INDEX_FILE)
    digest = hashlib.sha256(data).hexdigest()
    if again.digest != digest or again.to_dict() != index.to_dict():
        raise EvidenceError(f"{out / INDEX_FILE} does not read back as written")
    checked = verify(out, index_digest=digest)
    if not checked.intact:
        raise EvidenceError(f"{out} does not verify as written: {checked.summary()}")
    for item in planned:
        records = item.details.get("_records")
        if records is not None and tuple(read_refusals(out / item.path)) != tuple(records):
            raise EvidenceError(
                f"{item.path}: the refusals file changed while it was packed; pack again"
            )
    return digest


# -- verifying ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileState:
    """One file of a bundle as :func:`verify` found it."""

    path: str
    #: ``intact``, ``changed`` or ``missing`` for a listed file; ``unlisted`` for one the
    #: index does not name.
    state: str
    role: str | None = None
    expected_sha256: str | None = None
    expected_size: int | None = None
    #: What is there now; None where nothing was read.
    sha256: str | None = None
    size: int | None = None
    #: Why, where the state alone does not say it (a link, a directory, a file not readable).
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "state": self.state,
            "role": self.role,
            "expected_sha256": self.expected_sha256,
            "expected_size": self.expected_size,
            "sha256": self.sha256,
            "size": self.size,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class Verified:
    """A bundle as :func:`verify` found it: each listed file, each unlisted one, and whole."""

    directory: Path
    index: Index
    files: tuple[FileState, ...]
    unlisted: tuple[FileState, ...]
    #: The index digest that was expected, or None when none was given.
    index_digest_expected: str | None = None
    #: :data:`SIGNATURE_NOT_CHECKED` when ``index.json.sig`` is present, else None.
    signature: str | None = None
    #: What kept the walk from seeing all of the tree, and an index digest that does not match.
    problems: tuple[str, ...] = ()
    #: :data:`README_NAMES_INDEX` when ``CUSTOMER-README.md`` is present and names this index's
    #: digest, else None; one that names another or cannot be read is a problem.
    readme: str | None = None

    @property
    def index_digest(self) -> str:
        return self.index.digest

    @property
    def index_digest_matches(self) -> bool | None:
        if self.index_digest_expected is None:
            return None
        return self.index_digest_expected == self.index.digest

    @property
    def intact(self) -> bool:
        return (
            all(item.state == INTACT for item in self.files)
            and not self.unlisted
            and not self.problems
            and self.index_digest_matches is not False
        )

    @property
    def state(self) -> str:
        return INTACT if self.intact else NOT_INTACT

    def summary(self) -> str:
        """One line: how many files in each state, and every problem."""
        counts: dict[str, int] = {}
        for item in (*self.files, *self.unlisted):
            counts[item.state] = counts.get(item.state, 0) + 1
        parts = [f"{count} {state}" for state, count in sorted(counts.items())]
        return "; ".join([", ".join(parts) or "no files", *self.problems])

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": self.state,
            "intact": self.intact,
            "directory": str(self.directory),
            "index_digest": self.index.digest,
            "index_digest_expected": self.index_digest_expected,
            "index_digest_matches": self.index_digest_matches,
            "engagement": {
                "engagement_id_declared": self.index.engagement_id_declared,
                "engagement_digest": self.index.engagement_digest,
            },
            "created_utc": self.index.created_utc,
            "derived_from": self.index.derived_from,
            "files": [item.to_dict() for item in self.files],
            "unlisted": [item.to_dict() for item in self.unlisted],
            "signature": self.signature,
            "readme": self.readme,
            "problems": list(self.problems),
        }


def verify(directory: str | Path, *, index_digest: str | None = None) -> Verified:
    """Check a bundle against its own index; :class:`EvidenceError` when the index cannot be
    read whole.

    Only ``index.json`` says what is expected. Every listed file is opened without following a
    link, its SHA-256 and size recomputed: ``intact``, ``changed`` or ``missing``. Every other
    file in the tree is ``unlisted`` — but for ``index.json``, ``index.json.sig`` and
    ``CUSTOMER-README.md`` at the top: the signature is reported as present and not checked, the
    README is read and must name this index's digest. A link where a listed file should be is
    ``changed``; a link anywhere else is ``unlisted``; neither is followed. ``index_digest``,
    when given, must be the index's own SHA-256, or the bundle is not intact and says why.
    """
    root = Path(directory)
    if index_digest is not None and not (
        isinstance(index_digest, str) and _DIGEST.fullmatch(index_digest)
    ):
        raise EvidenceError(
            f"refused: the index digest {index_digest!r} is not 64 lowercase hexadecimal digits"
        )
    try:
        if not stat.S_ISDIR(os.stat(root).st_mode):
            raise EvidenceError(f"refused: {root} is not a directory")
    except OSError as exc:
        raise EvidenceError(f"refused: {root}: cannot read: {_why(exc)}") from None
    index = read_index(root / INDEX_FILE)
    problems: list[str] = []
    if index_digest is not None and index_digest != index.digest:
        problems.append(
            f"the index's SHA-256 is {index.digest}, not the {index_digest} it was expected to "
            "be: the index is not the one known from elsewhere"
        )
    files = tuple(_check(root, entry) for entry in index.files)
    listed = {entry.path for entry in index.files}
    above = {
        "/".join(entry.path.split("/")[:depth])
        for entry in index.files
        for depth in range(1, entry.path.count("/") + 1)
    }
    unlisted, unreadable = _unlisted(root, listed, above)
    problems += [
        f"{where} could not be listed: what is in it was not checked" for where in unreadable
    ]
    signature = SIGNATURE_NOT_CHECKED if os.path.lexists(root / SIGNATURE_FILE) else None
    readme = None
    if os.path.lexists(root / CUSTOMER_README):
        why = _readme_problem(root, index)
        if why is None:
            readme = README_NAMES_INDEX
        else:
            problems.append(why)
    return Verified(
        directory=root,
        index=index,
        files=files,
        unlisted=unlisted,
        index_digest_expected=index_digest,
        signature=signature,
        problems=tuple(problems),
        readme=readme,
    )


def _readme_problem(root: Path, index: Index) -> str | None:
    """Why the ``CUSTOMER-README.md`` beside an index is not the page the bundle gives, or None.

    Every name and number on the page derives from the index, ``engagement.json`` and
    ``redactions.json``, and the rest is fixed text in the wording the index's
    ``page_version`` names; so the page is rebuilt from them in that wording and compared byte
    for byte. A page that says anything else — another digest, another count, a sentence added —
    is not this bundle's."""
    by_role = {entry.role: entry for entry in index.files}
    if index.page_version is None:
        return (
            f"{CUSTOMER_README} lies beside an index that names no page version: a bundle packed "
            "from a store has no such page"
        )
    try:
        page = _read_no_link(root / CUSTOMER_README, MAX_INDEX_BYTES)
        if "engagement" not in by_role:
            return f"{CUSTOMER_README} lies beside an index that lists no engagement.json"
        engaged = _read_no_link(root / by_role["engagement"].path, MAX_INDEX_BYTES)
        listed = by_role.get("redactions")
        redactions = None if listed is None else read_redactions(root / listed.path)
    except OSError as exc:
        return f"{CUSTOMER_README} cannot be checked: {_why(exc)}"
    except EvidenceError as exc:
        return f"{CUSTOMER_README} cannot be checked: {exc}"
    expected = render_customer_readme(
        _readme_fields(index, index.digest, engaged, redactions), version=index.page_version
    )
    if page != expected.encode("utf-8"):
        return (
            f"{CUSTOMER_README} is not the page this bundle's index, engagement.json and "
            "redactions.json give: it was changed or written for another bundle"
        )
    return None


def _check(root: Path, entry: IndexFile) -> FileState:
    expected = {
        "path": entry.path,
        "role": entry.role,
        "expected_sha256": entry.sha256,
        "expected_size": entry.size,
    }
    parts = entry.path.split("/")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags & ~os.O_NOFOLLOW)
        descriptors.append(current)
        for part in parts[:-1]:
            try:
                current = os.open(part, directory_flags, dir_fd=current)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    return FileState(state=MISSING, **expected)
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    what = _kind_at(descriptors[-1], part)
                    return FileState(
                        state=CHANGED, note=f"{part} is {what} where a directory was", **expected
                    )
                raise
            descriptors.append(current)
        name = parts[-1]
        try:
            status = os.stat(name, dir_fd=current, follow_symlinks=False)
        except FileNotFoundError:
            return FileState(state=MISSING, **expected)
        if not stat.S_ISREG(status.st_mode):
            what = _kind(status.st_mode)
            return FileState(state=CHANGED, note=f"{what}, not the file listed", **expected)
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, file_flags, dir_fd=current)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return FileState(state=CHANGED, note="not a regular file", **expected)
            digest = hashlib.sha256()
            size = 0
            while chunk := handle.read(_HASH_CHUNK):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        # Not shown to be what was listed: a file nobody can read back is not intact.
        return FileState(state=CHANGED, note=f"cannot be read: {_why(exc)}", **expected)
    finally:
        for opened in descriptors:
            os.close(opened)
    actual = digest.hexdigest()
    state = INTACT if actual == entry.sha256 and size == entry.size else CHANGED
    return FileState(state=state, sha256=actual, size=size, **expected)


def _kind_at(directory: int, name: str) -> str:
    try:
        return _kind(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode)
    except OSError:
        return "something else"


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "a symbolic link, not followed"
    if stat.S_ISDIR(mode):
        return "a directory"
    if stat.S_ISREG(mode):
        return "a file"
    return "not a regular file"


def _unlisted(
    root: Path, listed: set[str], above: set[str]
) -> tuple[tuple[FileState, ...], list[str]]:
    """Every file in the tree the index does not list, every directory that holds no listed
    file (``above``: the directories the listed paths pass through), and every directory that
    could not be listed. An unlisted directory is reported, empty or not, and what is in it
    too. No link is followed; a link that is not listed is itself unlisted."""
    unlisted: list[FileState] = []
    unreadable: list[str] = []
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda item: item.name)
        except OSError:
            unreadable.append(prefix.rstrip("/") or ".")
            continue
        for entry in entries:
            relative = f"{prefix}{entry.name}"
            try:
                is_link = entry.is_symlink()
                is_directory = not is_link and entry.is_dir(follow_symlinks=False)
            except OSError:
                is_link = is_directory = False
            if is_directory:
                # A directory where a file is listed is that file, changed (_check).
                if relative not in above and relative not in listed:
                    unlisted.append(
                        FileState(
                            path=f"{relative}/",
                            state=UNLISTED,
                            note="a directory the index does not list",
                        )
                    )
                pending.append((Path(entry.path), f"{relative}/"))
                continue
            if relative in listed or (prefix == "" and entry.name in _BESIDE_THE_INDEX):
                continue
            note = "a symbolic link, not followed" if is_link else None
            unlisted.append(FileState(path=relative, state=UNLISTED, note=note))
    return tuple(sorted(unlisted, key=lambda item: item.path)), sorted(unreadable)


# -- review and redaction before a handover --------------------------------------------------

#: The surfaces a review lists beside :func:`mcp_kymograph.inspection.surfaces`: what an
#: ``initialize`` answer says the client should tell the model, and a progress message.
INSTRUCTIONS_SURFACE = "instructions"
PROGRESS_SURFACE = "progress_message"

#: Events whose text came from the server and lies outside any message: counted by a review,
#: never listed and never redacted.
_UNREVIEWED_EVENTS = ("server_stderr", "http_response")

REDACTIONS_FILE = "redactions.json"
REDACTIONS_VERSION = 1
_REDACTIONS_KEYS = frozenset({"redactions_version", "derived_from", "rules", "recordings"})
_REDACTED_RECORDING_KEYS = frozenset({"path", "source_sha256", "sha256", "blanked"})
_BLANKED_KEYS = frozenset({"seq", "path", "rule", "count"})
_RULE = re.compile(r"mask_patterns\[(0|[1-9][0-9]*)\]|mask_key:.+")

#: What a derived bundle's index adds to :data:`CONVENIENCE_NOTE`.
REDACTED_NOTE = (
    "This bundle was derived from the one whose index digest is derived_from, for a handover: "
    "a recording whose entry says redacted true differs from the recording first filed, whose "
    "SHA-256 is its source_sha256, and redactions.json names each place a value was blanked and "
    "the rule that did it, never the value. It holds no store."
)


@dataclass(frozen=True, slots=True)
class ReviewedText:
    """One text surface of one server message, with its value as recorded."""

    recording: str
    seq: int | None
    surface: str
    path: str
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "recording": self.recording,
            "seq": self.seq,
            "surface": self.surface,
            "path": self.path,
            "text": self.text,
        }


@dataclass(frozen=True, slots=True)
class ReviewedMessage:
    """One server message: how many of its strings a review lists, and how many it does not."""

    recording: str
    seq: int | None
    listed: int
    not_listed: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "recording": self.recording,
            "seq": self.seq,
            "listed": self.listed,
            "not_listed": self.not_listed,
        }


@dataclass(frozen=True, slots=True)
class ReviewGroup:
    """Everything a review lists of one entry and one method."""

    entry: str | None
    method: str | None
    texts: tuple[ReviewedText, ...]
    messages: tuple[ReviewedMessage, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "method": self.method,
            "texts": [text.to_dict() for text in self.texts],
            "messages": [message.to_dict() for message in self.messages],
        }


@dataclass(frozen=True, slots=True)
class Review:
    """The text surfaces of every recording in a bundle, grouped by entry and method, and what
    the review did not list: strings elsewhere in the messages, and events of the server's text
    outside any message (``unreviewed``: recording → event type → count)."""

    bundle: Path
    index_digest: str
    groups: tuple[ReviewGroup, ...]
    unreviewed: Mapping[str, Mapping[str, int]]

    @property
    def not_listed(self) -> int:
        return sum(m.not_listed for group in self.groups for m in group.messages)

    @property
    def complete(self) -> bool:
        """Whether every string the server sent is listed. Rarely: a message's ``jsonrpc`` and
        its protocol names are strings too, and a review says so rather than pass them by."""
        return self.not_listed == 0 and not any(
            count for counts in self.unreviewed.values() for count in counts.values()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": str(self.bundle),
            "index_digest": self.index_digest,
            "complete": self.complete,
            "not_listed": self.not_listed,
            "unreviewed": {name: dict(counts) for name, counts in self.unreviewed.items()},
            "groups": [group.to_dict() for group in self.groups],
        }


def review(bundle: str | Path) -> Review:
    """Every text surface of every recording in an intact bundle, as recorded — the surfaces
    :func:`redact` may blank, and nothing else is claimed.

    For each message the server sent: :func:`mcp_kymograph.inspection.surfaces` with the method
    it answers, an ``initialize`` answer's ``result.instructions`` and a progress notification's
    ``params.message``; then how many of its string values were not listed. The values are as
    the recording holds them, masked when they were written. A bundle that is not intact is
    refused with :class:`EvidenceError`: what it holds is not what was packed.
    """
    root = Path(bundle)
    index = _intact(root)
    groups: dict[tuple[str | None, str | None], tuple[list, list]] = {}
    unreviewed: dict[str, dict[str, int]] = {}
    for entry in index.files:
        if entry.role != "recording":
            continue
        data = _listed_bytes(root, entry)
        counts = dict.fromkeys(_UNREVIEWED_EVENTS, 0)
        for _, event in _lines(data):
            if event is None:
                continue
            kind = event.get("type")
            if kind in counts:
                counts[kind] += 1
            message = _server_message(event)
            if message is None:
                continue
            method, found, not_listed = message
            seq = event.get("seq") if type(event.get("seq")) is int else None
            texts, messages = groups.setdefault((entry.details.get("entry"), method), ([], []))
            texts += [ReviewedText(entry.path, seq, s, path, text) for s, path, text in found]
            messages.append(ReviewedMessage(entry.path, seq, len(found), not_listed))
        unreviewed[entry.path] = counts
    return Review(
        bundle=root,
        index_digest=index.digest,
        groups=tuple(
            ReviewGroup(entry, method, tuple(texts), tuple(messages))
            for (entry, method), (texts, messages) in sorted(
                groups.items(), key=lambda item: (item[0][0] or "", item[0][1] or "")
            )
        ),
        unreviewed=unreviewed,
    )


def _intact(root: Path, index_digest: str | None = None) -> Index:
    checked = verify(root, index_digest=index_digest)
    if checked.index_digest_matches is False:
        raise EvidenceError(
            f"refused: {root}: the index's SHA-256 is not the one given with --index-digest; "
            "the index is not the one known from elsewhere"
        )
    if not checked.intact:
        raise EvidenceError(
            f"refused: {root} is not intact ({checked.summary()}); what it holds is not what "
            "was packed"
        )
    return checked.index


def _listed_bytes(root: Path, entry: IndexFile) -> bytes:
    """A listed file's bytes, read once and held to its index entry."""
    path = root / entry.path
    try:
        data = _read_no_link(path)
    except OSError as exc:
        raise EvidenceError(f"refused: {path}: cannot read: {_why(exc)}") from None
    if hashlib.sha256(data).hexdigest() != entry.sha256:
        raise EvidenceError(f"refused: {path} changed after it was verified")
    return data


def _lines(data: bytes) -> list[tuple[bytes, dict[str, Any] | None]]:
    """A recording's lines, each with its event, or None for a line that is no event. The last
    element is the empty remainder after the final newline, kept so that joining gives the
    bytes back."""
    result: list[tuple[bytes, dict[str, Any] | None]] = []
    for line in data.split(b"\n"):
        event = None
        if line.strip():
            loaded, too_deep = events.load_bytes(line, events.MAX_READ_DEPTH)
            event = loaded if isinstance(loaded, dict) and not too_deep else None
        result.append((line, event))
    return result


def _server_message(
    event: dict[str, Any],
) -> tuple[str | None, list[tuple[str, str, str]], int] | None:
    """For a message the server sent: the method it answers or is, its text surfaces, and how
    many of its strings those are not. None for any other event."""
    if event.get("type") != "message" or event.get("direction") != "server_to_client":
        return None
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None, [], 0
    data = payload.get("data")
    if payload.get("encoding") != "json":
        return None, [], int(isinstance(data, str) and bool(data))
    answered = _text(event.get("responded_method"))
    own = _text(data.get("method")) if isinstance(data, dict) else None
    found = [
        (surface.value, path, text) for surface, path, text in inspection.surfaces(data, answered)
    ]
    if isinstance(data, dict):
        result = data.get("result")
        result = result if isinstance(result, dict) else {}
        if answered == "initialize" and isinstance(result.get("instructions"), str):
            found.append((INSTRUCTIONS_SURFACE, "result.instructions", result["instructions"]))
        params = data.get("params")
        params = params if isinstance(params, dict) else {}
        if own == "notifications/progress" and isinstance(params.get("message"), str):
            found.append((PROGRESS_SURFACE, "params.message", params["message"]))
    return answered or own, found, max(_strings(data) - len(found), 0)


def _strings(node: Any) -> int:
    """How many string values lie under ``node``, keys not counted."""
    count = 0
    pending = [node]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            count += 1
        elif isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return count


def _resolve(node: Any, path: str) -> list[tuple[Any, Any]] | None:
    """The steps ``(container, key)`` from a message to the string a surface path names, or
    None. Keys are matched as written, so a key holding a dot or a bracket is still found."""
    steps: list[tuple[Any, Any]] = []

    def walk(current: Any, rest: str) -> bool:
        if not rest:
            return isinstance(current, str)
        if rest.startswith("[") and isinstance(current, list):
            end = rest.find("]")
            number = rest[1:end] if end > 0 else ""
            if number.isdigit() and int(number) < len(current):
                steps.append((current, int(number)))
                if walk(current[int(number)], rest[end + 1 :]):
                    return True
                steps.pop()
            return False
        if rest.startswith(".") and isinstance(current, dict):
            tail = rest[1:]
            for key in current:
                if isinstance(key, str) and tail.startswith(key):
                    after = tail[len(key) :]
                    if after == "" or after[0] in ".[":
                        steps.append((current, key))
                        if walk(current[key], after):
                            return True
                        steps.pop()
        return False

    return steps if walk(node, f".{path}") else None


@dataclass(frozen=True, slots=True)
class Blanked:
    """One place a value was blanked: the message, the JSON path in it, the rule — never the
    value — and for a pattern how many times it occurred there."""

    seq: int | None
    path: str
    rule: str
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "path": self.path, "rule": self.rule, "count": self.count}


@dataclass(frozen=True, slots=True)
class RedactedRecording:
    path: str
    source_sha256: str
    sha256: str
    blanked: tuple[Blanked, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "source_sha256": self.source_sha256,
            "sha256": self.sha256,
            "blanked": [item.to_dict() for item in self.blanked],
        }


@dataclass(frozen=True, slots=True)
class Redactions:
    """``redactions.json``: every rule by name, and per recording every place blanked."""

    redactions_version: int
    derived_from: str
    rules: tuple[str, ...]
    recordings: tuple[RedactedRecording, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "redactions_version": self.redactions_version,
            "derived_from": self.derived_from,
            "rules": list(self.rules),
            "recordings": [recording.to_dict() for recording in self.recordings],
        }


def read_redactions(path: str | Path) -> Redactions:
    """A ``redactions.json``, read whole or refused whole with :class:`EvidenceError`: closed
    keys, digests of 64 hex digits, every rule named as ``mask_patterns[i]`` or
    ``mask_key:NAME`` and listed under ``rules``."""
    path = Path(path)
    try:
        raw = _read_no_link(path, MAX_INDEX_BYTES)
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_no_constant
        )
    except OSError as exc:
        raise EvidenceError(f"{path}: cannot read: {_why(exc)}") from None
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"{path}: not a redactions file: {exc}") from None
    try:
        return _redactions(data)
    except _Invalid as invalid:
        raise EvidenceError(f"{path}: {invalid.where}: {invalid.message}") from None


def _redactions(data: Any) -> Redactions:
    if not isinstance(data, dict):
        raise _Invalid("redactions", "expected a JSON object")
    _closed(data, _REDACTIONS_KEYS, _REDACTIONS_KEYS, "redactions")
    if type(data["redactions_version"]) is not int or data["redactions_version"] != 1:
        raise _Invalid("redactions_version", f"{data['redactions_version']!r} is not 1")
    _digest(data["derived_from"], "derived_from")
    rules = data["rules"]
    if not isinstance(rules, list) or not all(
        isinstance(rule, str) and _RULE.fullmatch(rule) for rule in rules
    ):
        raise _Invalid("rules", "expected a list of mask_patterns[i] and mask_key:NAME")
    if not isinstance(data["recordings"], list):
        raise _Invalid("recordings", "expected a list")
    recordings = []
    for number, item in enumerate(data["recordings"]):
        where = f"recordings[{number}]"
        if not isinstance(item, dict):
            raise _Invalid(where, "expected an object")
        _closed(item, _REDACTED_RECORDING_KEYS, _REDACTED_RECORDING_KEYS, where)
        if not _bundle_path(item["path"]):
            raise _Invalid(f"{where}.path", "not a relative path inside the bundle")
        _digest(item["source_sha256"], f"{where}.source_sha256")
        _digest(item["sha256"], f"{where}.sha256")
        if not isinstance(item["blanked"], list):
            raise _Invalid(f"{where}.blanked", "expected a list")
        blanked = []
        for index, place in enumerate(item["blanked"]):
            at = f"{where}.blanked[{index}]"
            if not isinstance(place, dict):
                raise _Invalid(at, "expected an object")
            _closed(place, _BLANKED_KEYS, _BLANKED_KEYS, at)
            if place["seq"] is not None and type(place["seq"]) is not int:
                raise _Invalid(f"{at}.seq", "expected a whole number or null")
            if not isinstance(place["path"], str) or not place["path"]:
                raise _Invalid(f"{at}.path", "expected a JSON path")
            if place["rule"] not in rules:
                raise _Invalid(f"{at}.rule", "not one of the rules listed")
            if type(place["count"]) is not int or place["count"] < 1:
                raise _Invalid(f"{at}.count", "expected a count from 1")
            blanked.append(Blanked(place["seq"], place["path"], place["rule"], place["count"]))
        recordings.append(
            RedactedRecording(item["path"], item["source_sha256"], item["sha256"], tuple(blanked))
        )
    return Redactions(1, data["derived_from"], tuple(rules), tuple(recordings))


@dataclass(frozen=True, slots=True)
class Redacted:
    """A handover bundle that was made: what the command line files with ``Store.file_bundle``
    and prints."""

    index_digest: str
    path: Path
    packed_utc: str
    #: The source bundle's index digest.
    derived_from: str
    engagement_id_declared: str
    engagement_digest: str
    counts: Mapping[str, int]
    #: How many rules were applied, and how many values they blanked.
    rules: int
    values_redacted: int
    advisories: tuple[Advisory, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_digest": self.index_digest,
            "path": str(self.path),
            "packed_utc": self.packed_utc,
            "derived_from": self.derived_from,
            "engagement_id_declared": self.engagement_id_declared,
            "engagement_digest": self.engagement_digest,
            "counts": dict(self.counts),
            "rules": self.rules,
            "values_redacted": self.values_redacted,
            "advisories": [advisory.to_dict() for advisory in self.advisories],
        }


@dataclass(frozen=True, slots=True)
class _Rules:
    #: ``(name, literal)``, in the file's order: ``mask_patterns[i]``.
    patterns: tuple[tuple[str, str], ...]
    #: ``(name, needle)``: ``mask_key:NAME`` and the key as ``normalise_key`` makes it.
    keys: tuple[tuple[str, str], ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in (*self.patterns, *self.keys))


def redact(
    bundle: str | Path,
    *,
    engagement_path: str | Path,
    out: str | Path,
    mask_keys: Sequence[str] = (),
    masker: Masker | None = None,
    now: datetime | None = None,
) -> Redacted:
    """A new bundle at ``out`` for a handover: the recordings of an intact ``bundle`` with the
    engagement's redaction rules applied to the surfaces :func:`review` lists, or a refusal
    with :class:`EvidenceError` and nothing written.

    The rules come from the operator's own file (``engagement_path``), whose SHA-256 must be a
    version in the chain of the bundle's store copy — the bundle's ``engagement.json`` holds no
    patterns. A ``redaction.mask_patterns`` entry blanks each occurrence of its
    literal string, never read as a pattern (``.*`` is those two characters); a key from
    ``redaction.mask_keys`` or ``mask_keys`` blanks the whole value of a surface any of whose
    keys holds it, as ``--mask-key`` matches (:func:`mcp_kymograph.masking.normalise_key`, a
    substring). Each blank is :data:`mcp_kymograph.masking.PLACEHOLDER`. Nothing else in a
    recording is touched: a finding's locator is a name and stays. Every recording, once
    redacted, is held to the check a placed script is held to (:func:`_known_in_event`): one
    that still holds a credential or the salt (``masker``'s literals) or a known value of the
    engagement (``masker``'s, or the operator's file's where no ``masker`` is given) refuses the
    redaction, naming the run and the place, never the value. Such a value is not blanked by
    this check: a ``mask_patterns`` entry blanks it where a review lists the surface, and a
    number, which is no surface, cannot be blanked (a recording made before numbers that hold a
    known value in part were masked is refused, and is to be made again).

    The new bundle holds the redacted recordings, the source's scenarios, manifests, refusals,
    tool, reference pages and ``engagement.json`` as they are, its report only if no pattern and
    no blanked value occurs in it, ``redactions.json``, ``CUSTOMER-README.md`` beside the index,
    and no store (the store's digests are those of the originals). Its index names
    the source index as ``derived_from``. A pattern still found anywhere in it — outside the
    surfaces reviewed, in a file copied — refuses the whole redaction, naming the rule and the
    place, never the value. The source is only read, and is byte for byte what it was.

    A ``script`` file is copied as it is, after a check: ``masker`` is the engagement's, with
    every credential of the engagement file and the salt as literals (``cli.pack_masker``), and a
    script that still holds one of them or a known value, in a string, a key or a number, refuses
    the redaction, and so does a script whose runs sent a token given by a flag, which pack
    cannot have replaced. A bundle with a script and no ``masker`` is refused.
    """
    moment = datetime.now(timezone.utc) if now is None else now
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("now must be an aware time")
    packed_utc = utc_text(moment)
    root = Path(bundle)
    out = Path(out).expanduser()
    index = _intact(root)
    held = _operator_file(root, index, engagement_path)
    rules = _rules(held, mask_keys)
    advisories = _destination(
        out, [(root, f"the source bundle ({root}); it is never written into")]
    )

    planned: list[_Planned] = []
    recorded: list[RedactedRecording] = []
    blanked_values: dict[str, str] = {}
    report: tuple[IndexFile, bytes] | None = None
    for entry in index.files:
        if entry.role == "store":
            continue
        data = _listed_bytes(root, entry)
        if entry.role == "report":
            report = (entry, data)
            continue
        if entry.role == "recording":
            redacted, places = _redact_recording(entry.path, data, rules, blanked_values)
            recorded.append(
                RedactedRecording(
                    entry.path, entry.sha256, hashlib.sha256(redacted).hexdigest(), places
                )
            )
            details = {**entry.details, "source_sha256": entry.sha256, "redacted": bool(places)}
            planned.append(_Planned(entry.path, redacted, "recording", details))
            continue
        if entry.role == "script":
            _script_clean(root, index, entry, data, masker)
        planned.append(_Planned(entry.path, data, entry.role, dict(entry.details)))
    for value, rule in blanked_values.items():
        if value in PLACEHOLDER:
            raise EvidenceError(
                f"refused: a value {rule} blanks occurs in the placeholder {PLACEHOLDER} itself; "
                "where it was blanked could not be told from where it was left — nothing is "
                "written"
            )
    if report is not None:
        entry, data = report
        _report_clean(data, rules, blanked_values)
        planned.append(_Planned(entry.path, data, "report"))

    redactions = Redactions(REDACTIONS_VERSION, index.digest, rules.names, tuple(recorded))
    planned.append(_Planned(REDACTIONS_FILE, canonical_json(redactions.to_dict()), "redactions"))
    derived = Index(
        index_version=INDEX_VERSION,
        engagement_id_declared=index.engagement_id_declared,
        engagement_digest=index.engagement_digest,
        created_utc=packed_utc,
        derived_from=index.digest,
        triage=index.triage,
        files=tuple(
            sorted(
                (
                    IndexFile(
                        item.path,
                        hashlib.sha256(item.data).hexdigest(),
                        len(item.data),
                        item.role,
                        item.details,
                    )
                    for item in planned
                ),
                key=lambda entry: entry.path,
            )
        ),
        note=f"{CONVENIENCE_NOTE} {REDACTED_NOTE}",
        page_version=handover.PAGE_VERSION,
    )
    data = index_bytes(derived)
    digest = hashlib.sha256(data).hexdigest()
    values = sum(place.count for item in recorded for place in item.blanked)
    engaged = next(item.data for item in planned if item.role == "engagement")
    fields = _readme_fields(derived, digest, engaged, redactions)
    readme = render_customer_readme(fields, version=derived.page_version).encode("utf-8")
    # Every recording is held to the check a placed script is held to: the masker given (the
    # engagement's credentials and salt as literals, and its known values), or, without one, the
    # known values of the operator's file.
    held_to = masker if masker is not None else Masker(known_values=_known_values(held))
    for item in planned:
        if item.role == "recording":
            lines = _lines(item.data)
            if held_to.looks_for_values:
                run = _recorded_run(lines, item.details.get("run"))
                for number, (line, event) in enumerate(lines, start=1):
                    _known_in_event(item.path, run, event, held_to, line=line, number=number)
            for line, event in lines:
                _still_in_event(item.path, line, event, rules, blanked_values)
        elif item.role != "report":
            _still_there(item.path, item.data, rules, blanked_values)
    _still_there(CUSTOMER_README, readme, rules, blanked_values)

    written = _Written()
    try:
        written.parents(out)
        written.directory(out)
        for item in planned:
            _place(out, item, written)
        written.file(out / INDEX_FILE, data)
        written.file(out / CUSTOMER_README, readme)
        _read_back_derived(out, derived, digest, redactions, fields)
    except (OSError, EvidenceError) as exc:
        raise _taken_back(out, written, exc) from None
    counts = dict.fromkeys(ROLES, 0)
    for item in planned:
        counts[item.role] += 1
    return Redacted(
        index_digest=digest,
        path=out,
        packed_utc=packed_utc,
        derived_from=index.digest,
        engagement_id_declared=index.engagement_id_declared,
        engagement_digest=index.engagement_digest,
        counts=counts,
        rules=len(rules.names),
        values_redacted=values,
        advisories=advisories,
    )


def _script_clean(
    root: Path, index: Index, entry: IndexFile, data: bytes, masker: Masker | None
) -> None:
    """Refuse a placed script that could still hold a credential: no masker to check it with, a
    run of it that sent a token given by a flag, or a credential, the salt or a known value of
    the engagement found in one of its strings, keys or numbers. Never names a value."""
    if masker is None:
        raise EvidenceError(
            f"refused: {entry.path} is a script, and no masker with the engagement's credentials "
            "was given to check it; nothing is written"
        )
    for item in index.files:
        if item.role == "recording" and item.details["run"] in entry.details["runs"]:
            started = _started(_listed_bytes(root, item), root / item.path)
            if _token_by_flag(started):
                raise EvidenceError(
                    f"refused: {entry.path}: run {_run_label(started, item.details['run'])} sent "
                    "a token given by a flag, whose value cannot have been replaced in the "
                    "script; nothing is written"
                )
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise EvidenceError(
            f"refused: {entry.path} is not a JSON document; nothing is written"
        ) from None
    if any(masker.holds_known_value(text) for text in _texts_of(document)):
        raise EvidenceError(
            f"refused: {entry.path} holds a credential, the salt or a known value of the "
            "engagement; it would reach the customer unmasked, and nothing is written"
        )


def _known_values(held: Engagement) -> list[str]:
    """The known values of an engagement file, or none (a file of the first version has none)."""
    listed = held.data.get("known_values")
    return [value for value in listed if isinstance(value, str)] if isinstance(listed, list) else []


def _recorded_run(lines: list[tuple[bytes, dict[str, Any] | None]], run: Any) -> str:
    """How a recording's run is named in a refusal: its recorded id, as :func:`_run_label` takes
    it from ``run_started``, else the digest the index names."""
    first = lines[0][1] if lines else None
    started = first if isinstance(first, dict) and first.get("type") == "run_started" else {}
    return _run_label(started, run if isinstance(run, str) else "?")


#: What the masker writes in place of a value: a pseudonym or a handle (``***KIND-<12 hex>***``)
#: and a withheld URL path. Taken out of a recorded string before it is held to the known values:
#: their hex digits are the masker's own, and a short known value made of digits can stand in
#: them by chance. Each is replaced by a character no value is matched across.
_STAND_IN = re.compile(
    r"\*\*\*[A-Z]+-[0-9a-f]{12}\*\*\*|<path withheld: sha256 [0-9a-f]{64}, [0-9]+ characters>"
)
#: A digest the tool writes (SHA-256 in hex, plain or with ``sha256:``). A string of this form is
#: not searched for the known values, whose digits can stand in sixty-four hex digits by chance;
#: it is refused where its digits are, whole, a credential, the salt or a known value
#: (:meth:`Masker.is_known_value`): a key or a token is often of this very form, and nothing
#: says that a string of it in a recording is the tool's.
_TOOL_DIGEST = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
#: How a key is shown in the place a refusal names: as written where it reads like a name of the
#: path syntax and the masker would leave it as it is, ``<key>`` otherwise (a key can be a
#: credential by its shape alone, in a recording made before keys were masked).
_SHOWN_KEY = re.compile(r"[A-Za-z_$][A-Za-z0-9_$-]{0,63}")

#: The strings of ``run_started`` that are not held to the known values, each as a path from the
#: root of the event: what the tool writes from its own clock, version and platform, and the
#: engagement's window, which the handover names anyway. A short known value stands in a time
#: or a version by chance, and a new run would write it again. Every other string of an event
#: is looked at, the operator's names and paths too.
TOOL_STRING_PATHS = frozenset(
    {
        ("wall_clock_utc",),
        ("tool_version",),
        ("inputs", "platform"),
        ("inputs", "python", "implementation"),
        ("inputs", "python", "version"),
        ("reproduction", "tool", "version"),
        ("authorization", "engagement", "window_declared", "from"),
        ("authorization", "engagement", "window_declared", "until"),
    }
)


#: The tallies of an event that are not held to the known values, per event type, each as the
#: start of a path from the root of the event: how many connections or packets the kernel
#: counted, what the sink and the kernel counted in all, how often a signal fired or a method
#: was looked at, how many findings a cap cut. Only the numbers below such a path: a key or a
#: string there is looked at. A target can steer such a count, and it is no value it wrote. A
#: target that knows a short value of digits can make a count of it (that many packets), and
#: the handover then holds the digits: a count cannot be masked and still be a count, and a
#: recording refused for it could never be handed over. The numbers a target chooses (a port,
#: a query type, a code, an id) are masked when they are recorded, and are looked at here. The
#: patterns of a review are held to these counts as before (:data:`TOOL_NUMBER_PATHS`).
TALLY_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "egress_attempt": (("count",),),
    "egress_summary": (("counters",), ("capped",), ("udp_loss",), ("account_differences",)),
    "statement_evaluated": (("fired",),),
    "findings_capped": (("cut",),),
    "run_finished": (("findings_by_statement",), ("observations_by_method",)),
}

#: The same for a ``sandbox_step``, per step: the readers write the kernel's counters as they
#: stand (the one after the target with all it sent), and ``collect`` repeats the summary of
#: the egress in its detail. No other step has a tally.
STEP_TALLY_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "reader_baseline": (("detail", "counters"),),
    "reader_final": (("detail", "counters"),),
    "collect": tuple(
        ("detail", name)
        for name in (
            "counters",
            "capped",
            "udp_loss",
            "account_differences",
            "attempts",
            "dns_queries",
            "direct_sink_access",
            "sink_suppressed",
        )
    ),
}


def _known_in_event(
    name: str,
    run: str,
    event: dict[str, Any] | None,
    masker: Masker,
    *,
    line: bytes = b"",
    number: int = 0,
) -> None:
    """Refuse when an event of a recording still holds a credential, the salt or a known value
    of the engagement, as ``masker`` finds them (:meth:`Masker.holds_known_value`, as written,
    percent-encoded or in the normalised copy): in any string or key, and in any number (not a
    ``bool``) by its JSON text, except where the tool writes one itself
    (:data:`TOOL_NUMBER_PATHS`, as for the patterns; :data:`TOOL_STRING_PATHS` in
    ``run_started``) or counts (:data:`TALLY_PATHS`, :data:`STEP_TALLY_PATHS`). The masker's
    stand-ins are taken out of a string first (:data:`_STAND_IN`). A string of the form of a
    digest the tool writes (:data:`_TOOL_DIGEST`) is held to the values only as a whole, and
    the envelope's ``run_id`` is not looked at. A line that is no event is looked at as text.

    The refusal names the recording, the run, the event's ``seq`` and the place, never the value:
    a key is shown in the place only where it reads like a name and the masker would leave it
    as it is (:data:`_SHOWN_KEY`). The place is put into words only for a refusal, its end
    where it is long: on the way each item carries its parent's place and its own key or
    position, whatever the depth and the length of a list."""
    found = "holds a credential, the salt or a known value of the engagement"
    if event is None:
        if line.strip() and masker.holds_known_value(line.decode("utf-8", "replace")):
            raise EvidenceError(
                f"refused: {name} (run {run}), line {number}, which is no event, {found}; it "
                "would reach the customer unmasked, and nothing is written"
            )
        return
    seq = event.get("seq")
    where = f"seq {seq}" if type(seq) is int else f"line {number}"
    kind = event.get("type")
    tool_strings = TOOL_STRING_PATHS if kind == "run_started" else frozenset()
    tallies = TALLY_PATHS.get(kind, ()) if isinstance(kind, str) else ()
    if kind == "sandbox_step":
        step = event.get("step")
        tallies = STEP_TALLY_PATHS.get(step, ()) if isinstance(step, str) else ()

    def holds(text: str) -> bool:
        if "***" in text or "<path withheld" in text:
            text = _STAND_IN.sub("\0", text)
        return masker.holds_known_value(text)

    def label(key: str) -> str:
        if _SHOWN_KEY.fullmatch(key) is None:
            return "<key>"
        with masker.uncounted():
            return key if masker.mask_text(key)[0] == key else "<key>"

    def refuse(place: tuple[Any, str | int] | None, *, key: bool = False) -> EvidenceError:
        steps: list[str | int] = []
        while place is not None:
            place, step = place
            steps.append(step)
        shown = ""
        for step in reversed(steps):
            if isinstance(step, int):
                shown += f"[{step}]"
            else:
                shown = f"{shown}.{label(step)}" if shown else label(step)
        if len(shown) > _SHOWN_PLACE:
            # From the next step on, so that the cut is not inside a name.
            shown = shown[-_SHOWN_PLACE:]
            starts = [at for at in (shown.find("."), shown.find("[")) if at >= 0]
            shown = "…" + shown[min(starts, default=0) :]
        if key:
            shown = f"a key in {shown or 'the event'}"
        return EvidenceError(
            f"refused: {name} (run {run}), {where}: {shown} {found}; it would reach the customer "
            "unmasked, and nothing is written"
        )

    # A path is None below a list (an element has no fixed path, so none of it is the tool's)
    # and below the depth of the longest of the tool's paths. A place is None for the event,
    # else the parent's place and the key or the position.
    pending: list[tuple[Any, tuple[str, ...] | None, tuple[Any, str | int] | None]]
    pending = [(event, (), None)]
    while pending:
        item, path, place = pending.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                key = str(key)
                if holds(key):
                    raise refuse(place, key=True)
                if path is None or path in tallies:
                    below = path  # below a tally the path stays the tally's, whatever the depth
                elif len(path) >= _TOOL_PATH_DEPTH:
                    below = None
                else:
                    below = (*path, key)
                pending.append((value, below, (place, key)))
        elif isinstance(item, list):
            pending.extend((value, None, (place, i)) for i, value in enumerate(item))
        elif isinstance(item, str):
            if path == ("run_id",) or path in tool_strings:
                continue
            digest = _TOOL_DIGEST.fullmatch(item)
            if masker.is_known_value(digest.group(1)) if digest else holds(item):
                raise refuse(place)
        elif (
            isinstance(item, (int, float))
            and not isinstance(item, bool)
            and path not in TOOL_NUMBER_PATHS
            and path not in tallies
            and holds(json.dumps(item))
        ):
            raise refuse(place)


def _texts_of(value: Any) -> list[str]:
    """Every string, key and number of a JSON document, a number as JSON writes it."""
    found: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            found.extend(key for key in item if isinstance(key, str))
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            found.append(item)
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            found.append(json.dumps(item))
    return found


def _operator_file(root: Path, index: Index, engagement_path: str | Path) -> Engagement:
    """The operator's own engagement file, refused unless it is a version of the chain the
    bundle's store copy holds."""
    stored = next((entry for entry in index.files if entry.role == "store"), None)
    if stored is None:
        raise EvidenceError(
            f"refused: {root} holds no store, so no chain to hold the engagement file to; "
            "redact the bundle packed from the store"
        )
    try:
        held = load_engagement(engagement_path)
    except EngagementError as exc:
        raise EvidenceError(f"refused: {exc}") from None
    try:
        with store.Store.open_read_only(root / stored.path) as copy:
            engaged = copy.engagement()
    except (store.StoreError, sqlite3.Error, OSError) as exc:
        raise EvidenceError(f"refused: {root / stored.path}: {exc}") from None
    chain = [] if engaged is None else [entry["digest"] for entry in engaged["chain"]]
    if held.digest not in chain:
        raise EvidenceError(
            f"refused: {held.source} (SHA-256 {held.digest}) is not a version of the engagement "
            f"in the chain of {root / stored.path} ({len(chain)} version(s)); the redaction "
            "rules are read only from a file the runs were made under"
        )
    return held


def _rules(held: Engagement, extra_keys: Sequence[str]) -> _Rules:
    for number, pattern in enumerate(held.mask_patterns):
        if pattern in PLACEHOLDER:
            raise EvidenceError(
                f"refused: mask_patterns[{number}] occurs in the placeholder {PLACEHOLDER} "
                "itself; a value blanked by it could not be told from one left"
            )
    keys: dict[str, str] = {}
    for key in (*held.mask_keys, *extra_keys):
        needle = normalise_key(key)
        if not needle:
            raise EvidenceError(f"refused: the mask key {key!r} has no letter or digit")
        keys.setdefault(f"mask_key:{key}", needle)
    return _Rules(
        patterns=tuple(
            (f"mask_patterns[{number}]", pattern)
            for number, pattern in enumerate(held.mask_patterns)
        ),
        keys=tuple(keys.items()),
    )


def _redact_recording(
    name: str, data: bytes, rules: _Rules, blanked_values: dict[str, str]
) -> tuple[bytes, tuple[Blanked, ...]]:
    """A recording with the rules applied to its reviewed surfaces, and where. Only lines that
    changed are written anew, as the recorder writes a line; every other byte stays."""
    places: list[Blanked] = []
    lines = []
    for line, event in _lines(data):
        message = None if event is None else _server_message(event)
        changed = False
        if message is not None:
            seq = event.get("seq") if type(event.get("seq")) is int else None
            document = event["payload"].get("data")
            for _, path, text in message[1]:
                steps = _resolve(document, path)
                keys = [key for _, key in steps or () if isinstance(key, str)]
                rule = next(
                    (
                        name
                        for name, needle in rules.keys
                        if any(needle in normalise_key(key) for key in keys)
                    ),
                    None,
                )
                hits = any(literal in text for _, literal in rules.patterns)
                if rule is None and not hits:
                    continue
                if steps is None:
                    raise EvidenceError(
                        f"refused: {name}, seq {seq}: the surface {path} cannot be located in "
                        "the message, so it cannot be blanked in place"
                    )
                if rule is not None:
                    new = PLACEHOLDER
                    blanked_values.setdefault(text, rule)
                    places.append(Blanked(seq, path, rule))
                else:
                    # In the file's order, each on what the ones before it left.
                    new = text
                    for rule_name, literal in rules.patterns:
                        count = new.count(literal)
                        if count:
                            new = new.replace(literal, PLACEHOLDER)
                            places.append(Blanked(seq, path, rule_name, count))
                container, key = steps[-1]
                if container[key] != text:
                    raise EvidenceError(
                        f"refused: {name}, seq {seq}: {path} does not hold the value the review "
                        "listed there, so it is not overwritten — nothing is written"
                    )
                container[key] = new
                changed = True
        if changed:
            line = json.dumps(event, ensure_ascii=True, allow_nan=False).encode("ascii")
        lines.append((line, event))
    return b"\n".join(line for line, _ in lines), tuple(places)


#: The numbers of a recorded event that only the tool writes, each as a path from the root of
#: the event; every other number is looked at. Read off ``events.py`` and ``recorder.py`` (a
#: record is the envelope ``v``, ``run_id``, ``seq``, ``t_ns``, ``type`` and the event's own
#: fields). A path is exact: ``("seq",)`` is the envelope's, and a ``seq`` inside
#: ``refusal.data`` or a payload is the server's or the script's and is looked at. What the
#: server or the script can deliver is not here: a code, a status, an exit code, ``data``,
#: arguments, content, the kernel's account of what the target did (``port``, ``count``,
#: ``family``, ``qtype``). A dictionary with keys from the traffic (``fired``, ``cut``,
#: ``counters``, ``observations_by_method``) has no fixed path and is not here either. The
#: target's port is the operator's own, from the engagement file, and stands here.
TOOL_NUMBER_PATHS = frozenset(
    {
        # The envelope: the schema, the recorder's order, the clock of the run.
        ("v",),
        ("seq",),
        ("t_ns",),
        # Sizes, ordinals and times the tool measured or numbered itself.
        ("size_bytes",),
        ("duration_ns",),
        ("seconds",),
        ("exchange",),
        ("connection",),
        ("stream",),
        ("session",),
        ("request_body_bytes",),
        ("response_body_bytes",),
        ("head_bytes",),
        ("events",),
        ("comments",),
        # Places in the recording and counts of the inspection and the driver.
        ("message_seq",),
        ("from_seq",),
        ("pages",),
        ("page",),
        ("checked",),
        ("not_strings",),
        ("cap",),
        ("made",),
        ("recorded",),
        ("invalidated_hits",),
        # Counters of ``run_started``, ``run_finished`` and the egress summary, kept by the tool.
        ("schema_version",),
        ("argv_redaction_count",),
        ("message_count",),
        ("dropped_events",),
        ("unwritten_events",),
        ("server_redactions",),
        ("inspection_bounded",),
        ("server_output_bytes",),
        ("client_input_bytes",),
        ("client_undecodable",),
        ("redaction_count",),
        ("attempts",),
        ("dns_queries",),
        ("direct_sink_access",),
        ("sink_suppressed",),
        # What the run was configured with (``limit_exceeded.value`` is one of the limits).
        ("value",),
        ("limits", "rule_budget_seconds"),
        ("limits", "max_message_bytes"),
        ("limits", "max_duration_seconds"),
        ("limits", "queue_size"),
        ("limits", "terminate_grace_seconds"),
        ("limits", "shutdown_budget_seconds"),
        ("limits", "client_settle_seconds"),
        # The tally of an HTTP run, counted by the proxy.
        ("http", "exchanges"),
        ("http", "streams"),
        ("http", "events"),
        ("http", "framing_errors"),
        # What the masker replaced, per kind of personal data.
        ("replacements", "email"),
        ("replacements", "iban"),
        ("replacements", "tel"),
        ("replacements", "known"),
        # What the masker struck in a payload; the payload's ``data`` is not here.
        ("payload", "redaction_count"),
        ("original", "redaction_count"),
        ("replacement", "redaction_count"),
        # The operator's port, and the length of a path the recorder withheld and measured.
        ("endpoint", "port"),
        ("endpoint", "path_length"),
        ("target", "port"),
        ("target", "path_length"),
    }
)


#: How deep the tool's own paths go: below that no path is kept on the walk of an event.
_TOOL_PATH_DEPTH = max(
    len(path)
    for paths in (
        TOOL_NUMBER_PATHS,
        TOOL_STRING_PATHS,
        *TALLY_PATHS.values(),
        *STEP_TALLY_PATHS.values(),
    )
    for path in paths
)

#: How many characters of a place a refusal names, counted from its end.
_SHOWN_PLACE = 300


def _still_in_event(
    name: str,
    line: bytes,
    event: dict[str, Any] | None,
    rules: _Rules,
    blanked_values: Mapping[str, str],
) -> None:
    """Refuse when a pattern, or a value a mask key blanked, still occurs in a recording's
    line: in any string, key or value, anywhere in the event, and in any number (not a
    ``bool``) by its JSON text, except where the tool wrote it itself
    (:data:`TOOL_NUMBER_PATHS`, exactly at those paths). A number is no surface: it is not
    redacted, it refuses.

    The scan is per event. A string the server wrote across two events — a pattern split
    between two ``server_stderr`` chunks — is in neither whole and is not found here; the
    review counts those events as not reviewed, so that this is never read as complete."""
    if event is None:
        _still_there(name, line, rules, blanked_values)
        return
    looked_for = [*rules.patterns, *((rule, value) for value, rule in blanked_values.items())]
    # A path is None below a list: an element has no fixed path, so none of it is the tool's.
    pending: list[tuple[Any, tuple[str, ...] | None]] = [(event, ())]
    while pending:
        item, path = pending.pop()
        number = isinstance(item, (int, float)) and not isinstance(item, bool)
        if (number and path not in TOOL_NUMBER_PATHS) or isinstance(item, str):
            text = json.dumps(item) if number else item
            for rule, literal in looked_for:
                if literal in text:
                    what = rule if rule.startswith("mask_patterns") else f"a value {rule} blanks"
                    raise EvidenceError(
                        f"refused: {what} still occurs in {name} at seq {event.get('seq')}, "
                        "outside the surfaces a review lists; it is not redacted there, and "
                        "nothing is written"
                    )
        elif isinstance(item, dict):
            pending.extend((key, None) for key in item)
            pending.extend(
                (value, None if path is None else (*path, key)) for key, value in item.items()
            )
        elif isinstance(item, list):
            pending.extend((value, None) for value in item)


def _forms(literal: str) -> tuple[bytes, ...]:
    """A string as it can stand in a file: as UTF-8, and as JSON writes it with escapes."""
    escaped = json.dumps(literal, ensure_ascii=True)[1:-1].encode("ascii")
    return tuple(dict.fromkeys((literal.encode("utf-8", "surrogatepass"), escaped)))


def _still_there(
    name: str, data: bytes, rules: _Rules, blanked_values: Mapping[str, str] | None = None
) -> None:
    """Refuse when a pattern, or a value a mask key blanked, occurs in a file of the new bundle
    that is not a recording, in any form it can stand there."""
    looked_for = [
        *rules.patterns,
        *((rule, value) for value, rule in (blanked_values or {}).items()),
    ]
    for rule, literal in looked_for:
        if any(form in data for form in _forms(literal)):
            what = rule if rule.startswith("mask_patterns") else f"a value {rule} blanks"
            raise EvidenceError(
                f"refused: {what} occurs in {name}; it would reach the customer unredacted, and "
                "nothing is written"
            )


def _report_clean(data: bytes, rules: _Rules, blanked_values: Mapping[str, str]) -> None:
    found = [rule for rule, literal in rules.patterns if any(f in data for f in _forms(literal))]
    found += [
        rule for value, rule in blanked_values.items() if any(f in data for f in _forms(value))
    ]
    if found:
        raise EvidenceError(
            f"refused: {REPORT_FILE} holds what {', '.join(dict.fromkeys(found))} blanks; "
            "regenerate the report from the redacted bundle, then redact again — nothing is "
            "written"
        )


def _readme_fields(
    index: Index, digest: str, engaged: bytes, redactions: Redactions | None
) -> ReadmeFields:
    """Every name and number of a customer README, from the bundle alone: its index (and the
    digest of it), its ``engagement.json`` and its ``redactions.json``. :func:`redact` writes
    the page from these, and :func:`verify` rebuilds it from them to compare."""
    try:
        declared = json.loads(engaged)
    except ValueError:
        declared = {}
    declared = declared if isinstance(declared, dict) else {}
    window = declared.get("window")
    window = window if isinstance(window, dict) else {}
    recordings = [entry for entry in index.files if entry.role == "recording"]
    return ReadmeFields(
        engagement_id_declared=index.engagement_id_declared,
        customer_declared=declared_customer(declared),
        window_from=_text(window.get("from")),
        window_until=_text(window.get("until")),
        index_digest=digest,
        derived_from=index.derived_from,
        created_utc=index.created_utc,
        recordings=len(recordings),
        egress_not_observed=sum(
            1 for entry in recordings if not entry.details.get("egress_observed")
        ),
        redaction_rules=0 if redactions is None else len(redactions.rules),
        values_redacted=0
        if redactions is None
        else sum(place.count for item in redactions.recordings for place in item.blanked),
        report=any(entry.role == "report" for entry in index.files),
    )


def _read_back_derived(
    out: Path, index: Index, digest: str, redactions: Redactions, fields: ReadmeFields
) -> None:
    again = read_index(out / INDEX_FILE)
    if again.digest != digest or again.to_dict() != index.to_dict():
        raise EvidenceError(f"{out / INDEX_FILE} does not read back as written")
    if read_redactions(out / REDACTIONS_FILE) != redactions:
        raise EvidenceError(f"{out / REDACTIONS_FILE} does not read back as written")
    try:
        readme = parse_customer_readme(
            (out / CUSTOMER_README).read_text(encoding="utf-8"), version=index.page_version
        )
    except ValueError as exc:
        raise EvidenceError(f"{out / CUSTOMER_README} does not read back: {exc}") from None
    if readme != fields:
        raise EvidenceError(f"{out / CUSTOMER_README} does not read back as written")
    checked = verify(out, index_digest=digest)
    if not checked.intact or checked.readme != README_NAMES_INDEX:
        raise EvidenceError(f"{out} does not verify as written: {checked.summary()}")


def _taken_back(out: Path, written: _Written, exc: BaseException) -> EvidenceError:
    left = written.take_back()
    why = str(exc) if isinstance(exc, EvidenceError) else _why(exc)
    if left:
        return EvidenceError(
            f"refused: writing {out} failed ({why}); what it wrote was removed except "
            f"{', '.join(left)}"
        )
    return EvidenceError(f"refused: writing {out} failed ({why}); what it wrote was removed")


# -- replaying a run ---------------------------------------------------------------------------

#: What a replay says when a field of the run is not the original's. The field is named, never
#: its value.
_USE_THE_ORIGINAL = "run it with the original files and values instead"

#: ``run_started.limits`` keys that have a ``drive`` option, and the option.
_LIMIT_OPTIONS = (
    ("max_message_bytes", "--max-message-bytes"),
    ("max_duration_seconds", "--max-duration"),
    ("queue_size", "--queue-size"),
    ("on_rule_error", "--on-rule-error"),
    ("client_settle_seconds", "--client-settle-timeout"),
)
_WITHHELD = "<path withheld"


@dataclass(frozen=True, slots=True)
class Replay:
    """What :func:`replay_plan` found: the run it is for, and the ``drive`` arguments that
    repeat it, but for the operator's own ``--engagement``, ``--engagement-confirmed`` and
    ``--out-dir``."""

    run: str
    arguments: tuple[str, ...]


def replay_plan(
    bundle: str | Path,
    *,
    run: str,
    engagement_path: str | Path,
    manifest: str | Path | None = None,
    index_digest: str | None = None,
) -> Replay:
    """The ``drive`` arguments that repeat one driven run of an intact ``bundle``, or a refusal
    with :class:`EvidenceError` naming the field that cannot be restored.

    ``run`` is the recording's digest or the run's own id. The script is the bundle's copy (the
    engagement's values replaced in it), the options come from the recording's ``run_started``:
    the target (a manifest and its entry with the image ids, or an endpoint with its pinned
    revision), the identity, the scenario, the script's variables and the limits. What the run
    recorded only withheld or masked — a URL's path, a command's arguments, a token given by a
    flag — is not restored, and the replay is refused, and so is a script that does not load once
    masked (``replayable: false``), a container run whose image was not resolved to an id, and an
    endpoint run whose server identity is a digest over files (``--server-content``).
    ``engagement_path`` is the operator's own file; its id must be the bundle's. A value the
    bundle holds only as a pseudonym goes out as that pseudonym. The manifest is the operator's:
    ``manifest`` if given, else the path the run recorded; either must have the digest the run
    recorded (the bundle's copy is evidence and is not loaded: the server files it lists are not
    in a bundle).

    The bundle is verified first against its own index: what it holds is what that index lists.
    ``index_digest``, the index's SHA-256 as known from elsewhere, is checked while the bundle is
    verified (which reads and hashes its files), before the run, the engagement file, the
    manifest or the script is read; without it, a bundle whose index was replaced and re-hashed
    with it is consistent and is replayed."""
    root = Path(bundle)
    index = _intact(root, index_digest)
    entry = _replayed(index, run)
    path = root / entry.path
    started = _started(_listed_bytes(root, entry), path)
    label = _run_label(started, entry.details["run"])
    _replay_shapes(started, label)
    if started.get("mode") != "driver":
        raise EvidenceError(
            f"refused: run {label} is a passive run (its mode is not driver); only a driven run "
            "has a script to repeat"
        )
    digest = started.get("script_digest")
    if digest is None:
        raise EvidenceError(
            f"refused: run {label} drove a built-in script, not a script file; there is no "
            "script to repeat from the bundle"
        )
    script = next(
        (
            item
            for item in index.files
            if item.role == "script" and entry.details["run"] in item.details["runs"]
        ),
        None,
    )
    if script is None or script.details["source_digest"] != digest:
        raise EvidenceError(
            f"refused: run {label}: the bundle holds no script for it "
            f"({_digest_named(digest, 'script_digest')}); it was packed without --script, or "
            "the script did not read once masked"
        )
    if script.details.get("replayable") is False:
        raise EvidenceError(
            f"refused: run {label}: its script in the bundle does not load once the engagement's "
            f"values are replaced in it ({script.details['not_replayable']}); {_USE_THE_ORIGINAL}"
        )
    try:
        held = load_engagement(engagement_path)
    except EngagementError as exc:
        raise EvidenceError(f"refused: {exc}") from None
    if held.id != index.engagement_id_declared:
        raise EvidenceError(
            f"refused: {held.source} is the engagement {held.id!r}, and this bundle is "
            f"{index.engagement_id_declared!r}'s; the engagement file is the operator's own, "
            "of the same engagement"
        )
    arguments = ["--script", str(root / script.path)]
    for name, value in (started.get("script_vars") or {}).items():
        if _masked_var(name, value):
            raise EvidenceError(
                f"refused: run {label}: script_vars.{name} was recorded masked or cut short; "
                f"{_USE_THE_ORIGINAL}"
            )
        arguments += ["--script-var", f"{name}={value}"]
    arguments += _replayed_limits(started, label)
    arguments += _replayed_target(root, index, started, label, manifest)
    arguments += _replayed_who(started, label)
    return Replay(entry.details["run"], tuple(arguments))


#: A pseudonym of the masker: ``***<KIND>-<12 hex>***``, of a personal kind or of a handle.
_PSEUDONYM = re.compile(r"\*\*\*(?:EMAIL|IBAN|TEL|KNOWN|HANDLE)-[0-9a-f]{12}\*\*\*")


def _digest_named(digest: Any, where: str) -> str:
    """A recorded digest as words: ``SHA-256 <digest>`` where it is 64 hexadecimal digits, else
    only the field that holds it, never what stands there."""
    if isinstance(digest, str) and _DIGEST.fullmatch(digest):
        return f"SHA-256 {digest}"
    return where


#: What :func:`replay_plan` reads of ``run_started``, and the shapes it takes: a field of another
#: shape is refused, naming the field (``None`` stands for a field that may be null or absent).
_REPLAY_SHAPES: tuple[tuple[str, tuple[type, ...]], ...] = (
    ("script_vars", (dict, type(None))),
    ("authorization", (dict, type(None))),
    ("endpoint", (dict, type(None))),
    ("reproduction", (dict, type(None))),
    ("auth", (dict, type(None))),
    ("server_identity", (dict, type(None))),
    ("limits", (dict, type(None))),
    ("inputs", (dict, type(None))),
)


def _replay_shapes(started: dict[str, Any], label: str) -> None:
    """Refuse a ``run_started`` whose fields that replay reads are not of the shape the recorder
    writes, naming the field and never what stands there."""

    def refuse(where: str) -> EvidenceError:
        return EvidenceError(
            f"refused: run {label}: {where} is not of the shape a recording has; "
            f"{_USE_THE_ORIGINAL}"
        )

    for name, shapes in _REPLAY_SHAPES:
        if not isinstance(started.get(name), shapes):
            raise refuse(name)
    for name, value in (started.get("script_vars") or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise refuse("script_vars")
    for key, _ in _LIMIT_OPTIONS:
        value = (started.get("limits") or {}).get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float, str, type(None))):
            raise refuse(f"limits.{key}")
    inputs = started.get("inputs") or {}
    timeout = inputs.get("step_timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float, type(None))):
        raise refuse("inputs.step_timeout")
    keys = inputs.get("mask_keys")
    if keys is not None and (
        not isinstance(keys, list) or not all(isinstance(key, str) for key in keys)
    ):
        raise refuse("inputs.mask_keys")
    authorization = started.get("authorization") or {}
    for key in ("declared_target", "scenario_digest"):
        if not isinstance(authorization.get(key), (str, type(None))):
            raise refuse(f"authorization.{key}")
    endpoint = started.get("endpoint") or {}
    for key in ("scheme", "host", "path"):
        if not isinstance(endpoint.get(key), (str, type(None))):
            raise refuse(f"endpoint.{key}")
    port = endpoint.get("port")
    if isinstance(port, bool) or not isinstance(port, (int, type(None))):
        raise refuse("endpoint.port")
    reproduction = started.get("reproduction") or {}
    for key in ("manifest", "corpus", "scenario", "environment"):
        if not isinstance(reproduction.get(key), (dict, type(None))):
            raise refuse(f"reproduction.{key}")
    entry = (reproduction.get("corpus") or {}).get("entry")
    if not isinstance(entry, (str, type(None))):
        raise refuse("reproduction.corpus.entry")


def _masked_var(name: Any, value: Any) -> bool:
    """Whether a recorded script variable is not the operator's value: its name is as long as
    the recorder cuts names (it may be cut), or its value holds a stand-in of the masker that
    is no pseudonym (the placeholder, a withheld path, any other ``***…***``). A pseudonym is
    kept: it goes out as it is."""
    if len(str(name)) >= events.MAX_METHOD_LENGTH:
        return True
    rest = _PSEUDONYM.sub("", str(value))
    return "***" in rest or PLACEHOLDER in rest or _WITHHELD in rest


def _replayed(index: Index, run: str) -> IndexFile:
    found = [
        item
        for item in index.files
        if item.role == "recording"
        and run in (item.details["run"], PurePosixPath(item.path).parent.name)
    ]
    if len(found) != 1:
        raise EvidenceError(
            f"refused: --run {run!r} "
            + ("names no recording in the bundle" if not found else "names several recordings")
        )
    return found[0]


def _replayed_limits(started: dict[str, Any], label: str) -> list[str]:
    limits = started.get("limits")
    inputs = started.get("inputs")
    if not isinstance(limits, dict) or not isinstance(inputs, dict):
        raise EvidenceError(
            f"refused: run {label} recorded no limits or inputs; {_USE_THE_ORIGINAL}"
        )
    arguments: list[str] = []
    for key, option in _LIMIT_OPTIONS:
        if limits.get(key) is not None:
            arguments += [option, str(limits[key])]
    if inputs.get("step_timeout") is not None:
        arguments += ["--step-timeout", str(inputs["step_timeout"])]
    for number, name in enumerate(inputs.get("mask_keys") or ()):
        # The recorder writes the names through the masker: one that holds a value of the run
        # stands masked, and would be another key here.
        if _is_masked(name):
            raise EvidenceError(
                f"refused: run {label}: inputs.mask_keys[{number}] was recorded masked; "
                f"{_USE_THE_ORIGINAL}"
            )
        arguments += ["--mask-key", str(name)]
    return arguments


def _replayed_target(
    root: Path, index: Index, started: dict[str, Any], label: str, manifest: str | Path | None
) -> list[str]:
    """The target of the run as ``drive`` options: a manifest entry, or an endpoint."""
    reproduction = started.get("reproduction")
    reproduction = reproduction if isinstance(reproduction, dict) else {}
    arguments: list[str] = []
    named = reproduction.get("manifest")
    if isinstance(named, dict):
        arguments += _replayed_entry(started, reproduction, named, label, manifest)
        scenario = reproduction.get("scenario")
        name = scenario.get("name") if isinstance(scenario, dict) else None
        if isinstance(name, str):
            _refuse_masked(name, "reproduction.scenario.name", label)
            arguments += ["--scenario", name]
    else:
        arguments += _replayed_endpoint(started, label)
        arguments += _replayed_scenario(root, index, started, reproduction, label)
    target = (started.get("authorization") or {}).get("declared_target")
    if target is not None:
        if not isinstance(target, str) or _is_masked(target):
            raise EvidenceError(
                f"refused: run {label}: authorization.declared_target was recorded withheld or "
                f"masked; {_USE_THE_ORIGINAL}"
            )
        arguments += ["--target", target]
    return arguments


def _replayed_entry(
    started: dict[str, Any],
    reproduction: dict[str, Any],
    named: dict[str, Any],
    label: str,
    manifest: str | Path | None,
) -> list[str]:
    digest = named.get("digest")
    corpus_entry = reproduction.get("corpus")
    entry = corpus_entry.get("entry") if isinstance(corpus_entry, dict) else None
    if not isinstance(digest, str) or not _PREFIXED_DIGEST.fullmatch(digest) or not entry:
        raise EvidenceError(
            f"refused: run {label}: reproduction.manifest or reproduction.corpus is incomplete; "
            f"{_USE_THE_ORIGINAL}"
        )
    # The bundle holds the manifest and not the server files it lists, so it is not loaded from
    # there: the operator's own file (--manifest) or the path the run recorded, either with the
    # digest the run recorded.
    recorded = named.get("source")
    given = manifest is not None
    source = manifest if given else (recorded if isinstance(recorded, str) and recorded else None)
    help_with = "give your own copy of the manifest, with this digest, with --manifest PATH"
    if source is None:
        raise EvidenceError(
            f"refused: run {label}: reproduction.manifest.source was not recorded; {help_with}"
        )
    # No path and no text of the exception in a sentence: either can be long, and the output is
    # cut, which would drop the hint. The hint comes first after the field.
    where = "the file given with --manifest" if given else "the recorded path"
    try:
        loaded = corpus.load(Path(source))
    except (corpus.ManifestError, OSError):
        raise EvidenceError(
            f"refused: run {label}: reproduction.manifest cannot be loaded from {where}; "
            f"{help_with}"
        ) from None
    if loaded.digest != digest:
        raise EvidenceError(
            f"refused: run {label}: reproduction.manifest: {where} is not the manifest the run "
            f"named (its digest differs); {help_with}"
        )
    _refuse_masked(str(entry), "reproduction.corpus.entry", label)
    arguments = ["--manifest", str(source), "--entry", str(entry)]
    isolation = started.get("isolation")
    if isolation in ("host", "runc"):
        arguments += ["--isolation", isolation]
    environment = reproduction.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    for key, option in (("target_image", "--target-image"), ("sandbox_image", "--sandbox-image")):
        image = environment.get(key)
        if image is None and isolation == "runc":
            # A run in a container whose image Docker could not resolve: given again without it,
            # drive would take today's default image, another run than the one recorded.
            raise EvidenceError(
                f"refused: run {label}: reproduction.environment.{key} is null: the image was not "
                f"resolved to an id when the run was made; {_USE_THE_ORIGINAL}"
            )
        if image is None:
            continue
        # By its id only: a name or tag would run whatever it names here and now.
        if not (isinstance(image, str) and _IMAGE_ID.fullmatch(image)):
            raise EvidenceError(
                f"refused: run {label}: reproduction.environment.{key} does not name the image "
                f"by its id; {_USE_THE_ORIGINAL}"
            )
        arguments += [option, image]
    return arguments


def _replayed_endpoint(started: dict[str, Any], label: str) -> list[str]:
    endpoint = started.get("endpoint")
    if not isinstance(endpoint, dict):
        raise EvidenceError(
            f"refused: run {label} recorded its server only as a command (argv, masked), with "
            f"no manifest entry; {_USE_THE_ORIGINAL}"
        )
    path = endpoint.get("path")
    if path is None:
        raise EvidenceError(
            f"refused: run {label}: endpoint.path was withheld when it was recorded; "
            f"{_USE_THE_ORIGINAL}"
        )
    if len(path) >= MAX_HTTP_PATH_LENGTH:
        # The recorder cuts a path at this length and does not mark the cut: a path this long
        # may be cut, and is not the path the run used.
        raise EvidenceError(
            f"refused: run {label}: endpoint.path is as long as the recorder cuts a path "
            f"({MAX_HTTP_PATH_LENGTH} characters) and may be cut; {_USE_THE_ORIGINAL}"
        )
    if endpoint.get("query") or endpoint.get("userinfo_dropped"):
        raise EvidenceError(
            f"refused: run {label}: endpoint.query or endpoint.userinfo_dropped says the URL had "
            f"parts that were masked or dropped; {_USE_THE_ORIGINAL}"
        )
    scheme, host, port = endpoint.get("scheme"), endpoint.get("host"), endpoint.get("port")
    if not isinstance(scheme, str) or not isinstance(host, str) or _is_masked(host + path):
        raise EvidenceError(
            f"refused: run {label}: endpoint.host or endpoint.path was masked when it was "
            f"recorded; {_USE_THE_ORIGINAL}"
        )
    shown = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{shown}{'' if port is None else f':{port}'}{path}"
    return ["--http", url, *_replayed_server(started, label)]


def _replayed_server(started: dict[str, Any], label: str) -> list[str]:
    """The server's identity of a run without a manifest entry, as ``drive`` takes it again:
    ``--server-revision`` for a pinned repository. An identity made from files
    (``--server-content``) is recorded only as a digest over them, and the files are not in a
    bundle; it is refused."""
    server = started.get("server_identity")
    if server is None:
        return []
    kind = server.get("kind") if isinstance(server, dict) else None
    if kind == "content":
        raise EvidenceError(
            f"refused: run {label}: server_identity is a digest over the server's files "
            f"(--server-content), which a bundle does not hold; {_USE_THE_ORIGINAL}"
        )
    version = server.get("version") if isinstance(server, dict) else None
    if kind == "revision" and isinstance(version, str):
        try:
            pinned = from_revision(version)
        except IdentityError:
            pinned = None
        if pinned is not None and pinned.version == version:
            return ["--server-revision", version]
    raise EvidenceError(
        f"refused: run {label}: server_identity is not a pinned revision drive can be given "
        f"again (recorded masked, or of another kind); {_USE_THE_ORIGINAL}"
    )


def _replayed_scenario(
    root: Path, index: Index, started: dict[str, Any], reproduction: dict[str, Any], label: str
) -> list[str]:
    triple = reproduction.get("scenario")
    triple = triple if isinstance(triple, dict) else {}
    name = _text(started.get("scenario_name"))
    digest, where = triple.get("digest"), "reproduction.scenario.digest"
    if digest is None:
        digest = (started.get("authorization") or {}).get("scenario_digest")
        where = "authorization.scenario_digest"
    if digest is None:
        if name is None:
            return []
        _refuse_masked(name, "scenario_name", label)
        return ["--scenario", name]
    held = next(
        (item for item in index.files if item.role == "scenario" and item.sha256 == digest), None
    )
    if held is None:
        raise EvidenceError(
            f"refused: run {label}: the scenario it loaded ({_digest_named(digest, where)}) "
            "is not in the bundle"
        )
    return ["--scenario", str(root / held.path)]


def _replayed_who(started: dict[str, Any], label: str) -> list[str]:
    """``--identity``: the one thing of ``auth`` that can be given again."""
    auth = started.get("auth")
    if auth is None:
        return []
    identity = auth.get("identity") if isinstance(auth, dict) else None
    if not isinstance(identity, str):
        raise EvidenceError(
            f"refused: run {label}: auth names no identity of an engagement file (a token given "
            f"by a flag); {_USE_THE_ORIGINAL}"
        )
    _refuse_masked(identity, "auth.identity", label)
    return ["--identity", identity]


def _refuse_masked(value: str, where: str, label: str) -> None:
    """Refuse a value replay would hand to drive that the run recorded only masked: any stand-in
    of the masker in it (:func:`_is_masked`), a pseudonym too. Names the field, never the value.
    A script variable is the one exception (:func:`_masked_var`): a pseudonym in it goes out as
    it is."""
    if _is_masked(value):
        raise EvidenceError(
            f"refused: run {label}: {where} was recorded masked; {_USE_THE_ORIGINAL}"
        )


# -- the end of an engagement ----------------------------------------------------------------

PURGED_VERSION = 1
#: What :func:`purge` deletes, and the outcome of each path. ``operator_notes`` are the operator's
#: notes beside the store (:func:`mcp_kymograph.operator_notes.beside`, the suffix in any case),
#: found among the directory's entries, deleted by their name and never opened: deleting them is
#: not reading them.
NOTES_KIND = "operator_notes"
PURGE_KINDS = ("run_directory", "refusals", "bundle", "store", NOTES_KIND)
DELETED = "deleted"
ABSENT = "missing"
#: A run the store filed whose recording was not found under the out-dir: it may be elsewhere,
#: and the purge cannot say it is gone.
NOT_FOUND = "not found under the out-dir"
#: What a purge does not reach, said in every ``purged.json``: files the operator keeps
#: elsewhere, which the store does not name.
NOT_COVERED = (
    "--session recordings outside the out-dir",
    "report.md and any report written outside a bundle the store filed",
    "the attestation",
    "intake answers and drafts",
)
_PURGED_KEYS = frozenset(
    {
        "purged_version",
        "not_covered",
        "engagement",
        "chain",
        "bundles",
        "purged_utc",
        "author",
        "before_retention_reason",
        "delete_after_declared",
        "paths",
        "salt_deleted",
    }
)
#: Keys a ``purged.json`` may lack: it was written before the salt of the pseudonyms.
_PURGED_OPTIONAL_KEYS = frozenset({"salt_deleted"})
_SALT_DELETED_KEYS = frozenset({"confirmed", "utc"})
_PURGED_PATH_KEYS = frozenset({"path", "kind", "outcome"})
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


@dataclass(frozen=True, slots=True)
class PurgedPath:
    """One path :func:`purge` set out to delete, and what became of it: ``deleted``,
    ``missing`` (gone before the purge came to it), ``failed: <words>``, or — for a run the
    store filed — ``not found under the out-dir``, which is not gone."""

    path: str
    kind: str
    outcome: str

    @property
    def gone(self) -> bool:
        return self.outcome in (DELETED, ABSENT)

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "outcome": self.outcome}


@dataclass(frozen=True, slots=True)
class Purged:
    """``purged.json``: which engagement was purged, by whom, when, and what became of each
    path. The one thing that survives an engagement; it holds no customer data — no recording,
    no finding, nothing of the engagement file but its id and digests."""

    purged_version: int
    engagement_id_declared: str
    engagement_digest: str
    chain: tuple[str, ...]
    #: The index digests of every bundle the store had filed.
    bundles: tuple[str, ...]
    purged_utc: str
    author: str
    before_retention_reason: str | None
    delete_after_declared: str | None
    paths: tuple[PurgedPath, ...]
    #: What the purge does not reach (:data:`NOT_COVERED`).
    not_covered: tuple[str, ...] = NOT_COVERED
    #: When the operator confirmed (``--salt-deleted``) that the salt of the pseudonyms was
    #: deleted with the raw data, or None where no confirmation was given.
    salt_deleted_utc: str | None = None

    @property
    def complete(self) -> bool:
        """Whether every path is gone: deleted now, or missing already."""
        return all(item.gone for item in self.paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "purged_version": self.purged_version,
            "engagement": {
                "engagement_id_declared": self.engagement_id_declared,
                "engagement_digest": self.engagement_digest,
            },
            "chain": list(self.chain),
            "bundles": list(self.bundles),
            "purged_utc": self.purged_utc,
            "author": self.author,
            "before_retention_reason": self.before_retention_reason,
            "delete_after_declared": self.delete_after_declared,
            "paths": [item.to_dict() for item in self.paths],
            "not_covered": list(self.not_covered),
            "salt_deleted": None
            if self.salt_deleted_utc is None
            else {"confirmed": True, "utc": self.salt_deleted_utc},
        }


def purge(
    *,
    store_path: str | Path,
    out_dir: str | Path,
    author: str,
    out: str | Path,
    before_retention_reason: str | None = None,
    salt_deleted: bool = False,
    now: datetime | None = None,
) -> Purged:
    """End an engagement: delete its store, the operator's notes beside it, its run directories
    and refusals under ``out_dir`` and every bundle the store filed, and write ``purged.json`` at
    ``out``.

    The operator's notes are deleted by name and never opened: every entry beside the store
    whose name is one of :func:`mcp_kymograph.operator_notes.beside` but for the case of its
    suffix, which :func:`mcp_kymograph.operator_notes.load` takes in any case — the directory is
    listed, not guessed at — and every one of those names the file system finds though the
    listing spells it otherwise (NFD on disk, another case), the same file once. Each one found
    is listed as kind ``operator_notes`` under its own name with its outcome; where none is found,
    the first name is listed as ``missing``, so ``purged.json`` names the notes either way.

    Refused with :class:`EvidenceError`, deleting nothing: a missing author; a store that holds
    no engagement; an engagement of version 2 without ``salt_deleted``, the operator's
    confirmation that the salt of its pseudonyms is deleted with the raw data (``purged.json``
    keeps it with the time; version 1 needs none); a time before ``delete_after`` as declared —
    the whole UTC day of it counts as before — unless ``before_retention_reason`` says why, which
    ``purged.json`` then keeps;
    a recording under ``out_dir``, a refusals file there or a filed bundle that names no digest
    of the store's chain, or cannot be read to say which: what is not this engagement's is not
    deleted with it, and nothing is; a directory under ``out_dir`` that cannot be listed; and an
    ``out`` that exists, lies in a git working tree, or lies in anything to be deleted.

    Refused as well: a store, its notes, a filed bundle or anything to be deleted that is a
    symbolic link — deleting it would delete the link and leave the data; notes that are not a
    file; a directory of the store that cannot be listed to look for the notes; a bundle filed
    under a relative path, which cannot be told where it lies; and a bundle holding anything its
    index does not list (but its README and signature), which is not the bundle's to delete.

    Every run the store filed is held against what was found under ``out_dir``, as the web
    interface resolves a filed recording there: one not found is listed ``not found under the
    out-dir``, and the purge is not complete — it may lie elsewhere, and is never counted gone.

    Then each path is deleted, no link followed, and its outcome recorded; a bundle by the files
    its index lists, the index, README and signature, and the directories that emptied.
    ``purged.json`` is opened ``O_EXCL`` and ``0600`` before the first deletion, so that a purge
    that cannot write its record deletes nothing, and is read back after.
    :attr:`Purged.complete` says whether everything went. What a purge does not reach — the
    operator's files the store does not name (:data:`NOT_COVERED`) — ``purged.json`` says.
    """
    moment = datetime.now(timezone.utc) if now is None else now
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("now must be an aware time")
    if not isinstance(author, str) or not author.strip():
        raise EvidenceError("refused: no author; a purge says who did it")
    reason = before_retention_reason
    if reason is not None and (not isinstance(reason, str) or not reason.strip()):
        raise EvidenceError("refused: a reason to purge before retention is given but empty")
    store_file = Path(store_path)
    root = Path(out_dir)
    out = Path(out).expanduser()

    for extra in ("", "-journal", "-wal", "-shm"):
        if Path(f"{store_file}{extra}").is_symlink():
            raise EvidenceError(
                f"refused: {store_file}{extra} is a symbolic link; deleting it would leave what "
                "it points to — give the store's own path; nothing is deleted"
            )
    named = notes_beside(store_file)
    notes = _notes_found(named)
    for path in notes:
        if path.is_symlink():
            raise EvidenceError(
                f"refused: {path} is a symbolic link; deleting it would leave the operator's "
                "notes it points to — nothing is deleted"
            )
        if os.path.lexists(path) and not stat.S_ISREG(os.lstat(path).st_mode):
            raise EvidenceError(
                f"refused: {path} is not a file; the operator's notes are one file, and what "
                "else lies under their name is not looked into — nothing is deleted"
            )
    try:
        with store.Store.open_read_only(store_file) as held:
            engaged = held.engagement()
            filed = held.bundles()
            filed_runs = sorted(held.recordings().values())
    except (store.StoreError, sqlite3.Error, OSError) as exc:
        raise EvidenceError(f"refused: the store cannot be read: {exc}") from None
    if engaged is None:
        raise EvidenceError(f"refused: {store_file} holds no engagement; there is none to end")
    chain = tuple(entry["digest"] for entry in engaged["chain"])
    if not salt_deleted and any(
        entry["file_declared"].get("version") == FORMAT_VERSION_2 for entry in engaged["chain"]
    ):
        raise EvidenceError(
            "refused: the engagement is of version 2, whose pseudonyms are made with a salt kept "
            "outside the store; delete the salt with the raw data and confirm it with "
            "--salt-deleted — nothing is deleted"
        )
    delete_after = engaged["delete_after_declared"]
    _retention(delete_after, moment, reason)

    bundles = _purged_bundles(filed, set(chain))
    recordings, refusals, unfound = _purged_runs(
        root, set(chain), [path for _, path in bundles], filed_runs
    )
    targets = [
        *((path, "run_directory") for path in recordings),
        *((path, "refusals") for path in refusals),
        *((path, "bundle") for _, path in bundles),
        *(
            (Path(f"{store_file}{extra}"), "store")
            for extra in ("", "-journal", "-wal", "-shm")
            if extra == "" or os.path.lexists(f"{store_file}{extra}")
        ),
        *((path, NOTES_KIND) for path in notes or named[:1]),
    ]
    _destination(out, [(path, f"{path}, which the purge deletes") for path, _ in targets])
    try:
        make_private_directories(out.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(out, flags, FILE_MODE)
    except OSError as exc:
        raise EvidenceError(
            f"refused: {out} cannot be created: {_why(exc)}; nothing is deleted"
        ) from None

    try:
        os.fchmod(descriptor, FILE_MODE)
        paths = (
            *(PurgedPath(str(path), kind, _delete(path, kind)) for path, kind in targets),
            *(PurgedPath(filed, "run_directory", NOT_FOUND) for filed in unfound),
        )
        record = Purged(
            purged_version=PURGED_VERSION,
            engagement_id_declared=engaged["engagement_id_declared"],
            engagement_digest=engaged["engagement_digest"],
            chain=chain,
            bundles=tuple(digest for digest, _ in bundles),
            purged_utc=utc_text(moment),
            author=author,
            before_retention_reason=reason,
            delete_after_declared=delete_after,
            paths=paths,
            salt_deleted_utc=utc_text(moment) if salt_deleted else None,
        )
        view = memoryview(canonical_json(record.to_dict()))
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if read_purged(out) != record:
        raise EvidenceError(f"{out} does not read back as written")
    return record


def _notes_found(named: tuple[Path, ...]) -> list[Path]:
    """The operator's notes that lie beside the store, by two ways, so that neither misses them.

    Every entry of the directory whose name is one of ``named``
    (:func:`mcp_kymograph.operator_notes.beside`, all of one directory) but for the case of its
    suffix — ``….operator-notes.YAML`` too, as :func:`mcp_kymograph.operator_notes.load` takes
    it; the store's name and ``.operator-notes`` are matched as they are, as what differs there
    is another store's notes, or no notes at all. And every name of ``named`` the file system
    finds (``lexists``) though the listing spells it otherwise — NFD on disk where the store was
    named in NFC, another case on a case-insensitive file system. A name found both ways is one
    file (the same ``lstat`` identity), kept once under its name on disk; two entries of the
    listing are two names, each kept, even of one file.

    In the order of ``named``, then by name. The directory is listed and nothing in it opened.
    A directory that does not exist holds no notes (and no store, which then refuses the purge);
    one that cannot be listed refuses it: notes that cannot be looked for cannot be said gone."""
    directory = named[0].parent
    rank = {path.name: place for place, path in enumerate(named)}
    try:
        entries = os.listdir(directory)
    except FileNotFoundError:
        entries = []
    except OSError as exc:
        raise EvidenceError(
            f"refused: {directory} cannot be listed to look for the operator's notes beside the "
            f"store ({_why(exc)}); nothing is deleted"
        ) from None
    found: list[tuple[int, str]] = []
    for entry in entries:
        suffix = Path(entry).suffix
        place = rank.get(entry[: len(entry) - len(suffix)] + suffix.lower()) if suffix else None
        if place is not None:
            found.append((place, entry))
    identities = [_identity(directory / entry) for _, entry in found]
    for place, path in enumerate(named):
        if path.name in {entry for _, entry in found} or not os.path.lexists(path):
            continue
        identity = _identity(path)
        if identity is None or identity not in identities:
            found.append((place, path.name))
            identities.append(identity)
    return [directory / entry for _, entry in sorted(found)]


def _identity(path: Path) -> tuple[int, int] | None:
    """The device and inode of ``path`` itself, no link followed; None where it cannot be had."""
    try:
        found = os.lstat(path)
    except OSError:
        return None
    return (found.st_dev, found.st_ino)


def _retention(delete_after: str | None, moment: datetime, reason: str | None) -> None:
    if delete_after is None:
        return
    if not _DATE.fullmatch(delete_after):
        raise EvidenceError(
            f"refused: the store's delete_after {delete_after!r} is not a date; nothing is deleted"
        )
    try:
        day = datetime.strptime(delete_after, "%Y-%m-%d").date()
    except ValueError:
        raise EvidenceError(
            f"refused: the store's delete_after {delete_after!r} is not a date"
        ) from None
    if moment.astimezone(timezone.utc).date() <= day and reason is None:
        raise EvidenceError(
            f"refused: the engagement is kept until the end of {delete_after} (UTC); give a "
            "reason to purge before retention, and it is recorded — nothing is deleted"
        )


def _purged_bundles(filed: list[dict[str, Any]], chain: set[str]) -> list[tuple[str, Path]]:
    """Each filed bundle by index digest and path, refused whole when one is not this
    engagement's or cannot be read to say whose it is."""
    bundles = []
    for row in filed:
        path = Path(row["path"])
        if not path.is_absolute():
            raise EvidenceError(
                f"refused: the store filed the bundle {row['index_digest']} under the relative "
                f"path {path}, which cannot be told where it lies; nothing is deleted"
            )
        if path.is_symlink():
            raise EvidenceError(
                f"refused: the bundle at {path} is a symbolic link; deleting it would leave what "
                "it points to, and nothing is deleted"
            )
        if row["engagement_digest"] not in chain:
            raise EvidenceError(
                f"refused: the store filed the bundle {row['index_digest']} ({path}) under "
                f"{row['engagement_digest']}, no digest of its chain; nothing is deleted"
            )
        if os.path.lexists(path):
            try:
                named = read_index(path / INDEX_FILE).engagement_digest
            except EvidenceError as exc:
                raise EvidenceError(
                    f"refused: the bundle at {path} cannot be read to say whose it is ({exc}); "
                    "nothing is deleted"
                ) from None
            if named not in chain:
                raise EvidenceError(
                    f"refused: the bundle at {path} names the engagement digest {named}, no "
                    "digest of the store's chain; nothing is deleted"
                )
            checked = verify(path)
            beside = [item.path for item in checked.unlisted]
            unreadable = [p for p in checked.problems if "could not be listed" in p]
            if beside or unreadable:
                raise EvidenceError(
                    f"refused: the bundle at {path} holds what its index does not list "
                    f"({', '.join([*beside, *unreadable])}); it is not the bundle's to delete, "
                    "and nothing is deleted"
                )
        bundles.append((row["index_digest"], path))
    return bundles


def _purged_runs(
    root: Path, chain: set[str], bundles: Sequence[Path], filed_runs: Sequence[str]
) -> tuple[list[Path], list[Path], list[str]]:
    """Every run directory and every refusals file under ``root`` that lies in no bundle about
    to be deleted, each held to the chain, refused whole otherwise; and every recording the
    store filed that is not found among them, by its path as filed."""
    if not root.is_dir() or root.is_symlink():
        raise EvidenceError(f"refused: --out-dir {root} is not a directory")
    # By the paths as written, never resolved: a link is not followed to decide what lies where.
    inside = [Path(os.path.abspath(path)) for path in bundles]

    def in_bundle(path: Path) -> bool:
        absolute = Path(os.path.abspath(path))
        return any(absolute == b or b in absolute.parents for b in inside)

    found = search(root)
    if found.unreadable:
        raise EvidenceError(
            f"refused: under {root}, {', '.join(found.unreadable)} cannot be listed; what is "
            "in it cannot be held to the engagement, and nothing is deleted"
        )
    runs = []
    for ref, path in found.recordings.items():
        if in_bundle(path):
            continue
        try:
            lines, _ = verdict.read_events(first_line(path, MAX_INDEX_BYTES))
        except OSError as exc:
            raise EvidenceError(
                f"refused: {path} cannot be read to say whose it is ({_why(exc)}); nothing is "
                "deleted"
            ) from None
        started = lines[0] if lines and lines[0].get("type") == "run_started" else {}
        engaged = (started.get("authorization") or {}).get("engagement")
        digest = engaged.get("engagement_digest") if isinstance(engaged, dict) else None
        if digest not in chain:
            raise EvidenceError(
                f"refused: {path} was made under {digest or 'no engagement'}, no digest of the "
                "store's chain; it is not this engagement's, and nothing is deleted"
            )
        if ref == ROOT_REF:
            raise EvidenceError(
                f"refused: {root} is itself a run directory; --out-dir is the directory the run "
                "directories are in, and nothing is deleted"
            )
        runs.append(path.parent)
    outside = Found(
        root=found.root,
        recordings={ref: p for ref, p in found.recordings.items() if not in_bundle(p)},
        fleets=found.fleets,
    )
    unfound = [filed for filed in filed_runs if resolve_filed(outside, filed) is None]
    try:
        refusals = find_refusals(root)
    except EngagementError as exc:
        raise EvidenceError(f"refused: {exc}") from None
    files = []
    for item in refusals:
        if in_bundle(item.path):
            continue
        if item.refused is not None:
            raise EvidenceError(
                f"refused: {item.path}: {item.refused}; it cannot be read to say whose it is, "
                "and nothing is deleted"
            )
        foreign = [r.engagement_digest for r in item.records if r.engagement_digest not in chain]
        if foreign:
            raise EvidenceError(
                f"refused: {item.path} records a refusal under {foreign[0]}, no digest of the "
                "store's chain; nothing is deleted"
            )
        files.append(item.path)
    return sorted(runs), files, unfound


def _delete(path: Path, kind: str) -> str:
    """Delete a file, or a directory and everything in it, following no link; the outcome. A
    bundle goes by what its index lists (:func:`_delete_bundle`)."""
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return ABSENT
    except OSError as exc:
        return f"failed: {_why(exc)}"
    try:
        if stat.S_ISLNK(status.st_mode):
            return "failed: it is a symbolic link now; not followed, not deleted"
        if kind == "bundle":
            _delete_bundle(path)
        elif stat.S_ISDIR(status.st_mode):
            _remove_tree(path)
        else:
            os.unlink(path)
    except (OSError, EvidenceError) as exc:
        return f"failed: {_why(exc)}"
    return DELETED


def _delete_bundle(root: Path) -> None:
    """A bundle's files as its index lists them, then the index, its README and signature,
    then each directory that emptied: nothing it does not list is deleted, and a directory
    still holding something stays, and says so."""
    index = read_index(root / INDEX_FILE)
    directories: set[Path] = set()
    for entry in index.files:
        parts = entry.path.split("/")
        for depth in range(1, len(parts)):
            directories.add(root.joinpath(*parts[:depth]))
        try:
            os.unlink(root / entry.path)
        except FileNotFoundError:
            continue
    for name in _BESIDE_THE_INDEX:
        try:
            os.unlink(root / name)
        except FileNotFoundError:
            continue
    for directory in sorted(directories, key=lambda d: len(d.parts), reverse=True):
        try:
            os.rmdir(directory)
        except FileNotFoundError:
            continue
    os.rmdir(root)


def _remove_tree(directory: Path) -> None:
    with os.scandir(directory) as listing:
        entries = list(listing)
    for entry in entries:
        if entry.is_dir(follow_symlinks=False):
            _remove_tree(Path(entry.path))
        else:
            os.unlink(entry.path)
    os.rmdir(directory)


def read_purged(path: str | Path) -> Purged:
    """A ``purged.json``, read whole or refused whole with :class:`EvidenceError`."""
    path = Path(path)
    try:
        raw = _read_no_link(path, MAX_INDEX_BYTES)
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_no_constant
        )
    except OSError as exc:
        raise EvidenceError(f"{path}: cannot read: {_why(exc)}") from None
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"{path}: not a purged.json: {exc}") from None
    try:
        return _purged(data)
    except _Invalid as invalid:
        raise EvidenceError(f"{path}: {invalid.where}: {invalid.message}") from None


def _purged(data: Any) -> Purged:
    if not isinstance(data, dict):
        raise _Invalid("purged", "expected a JSON object")
    _closed(data, _PURGED_KEYS, _PURGED_KEYS - _PURGED_OPTIONAL_KEYS, "purged")
    if type(data["purged_version"]) is not int or data["purged_version"] != PURGED_VERSION:
        raise _Invalid("purged_version", f"{data['purged_version']!r} is not {PURGED_VERSION}")
    engaged = data["engagement"]
    if not isinstance(engaged, dict):
        raise _Invalid("engagement", "expected an object")
    _closed(engaged, _ENGAGEMENT_KEYS, _ENGAGEMENT_KEYS, "engagement")
    if not isinstance(engaged["engagement_id_declared"], str):
        raise _Invalid("engagement.engagement_id_declared", "expected a string")
    _digest(engaged["engagement_digest"], "engagement.engagement_digest")
    for key in ("chain", "bundles"):
        if not isinstance(data[key], list):
            raise _Invalid(key, "expected a list of digests")
        for number, digest in enumerate(data[key]):
            _digest(digest, f"{key}[{number}]")
    if not isinstance(data["purged_utc"], str) or not _UTC_TIME.fullmatch(data["purged_utc"]):
        raise _Invalid("purged_utc", "expected a UTC time ending in Z")
    if not isinstance(data["author"], str) or not data["author"]:
        raise _Invalid("author", "expected a non-empty string")
    for key in ("before_retention_reason", "delete_after_declared"):
        if data[key] is not None and not isinstance(data[key], str):
            raise _Invalid(key, "expected a string or null")
    salt_deleted_utc = None
    confirmed = data.get("salt_deleted")
    if confirmed is not None:
        if not isinstance(confirmed, dict):
            raise _Invalid("salt_deleted", "expected an object or null")
        _closed(confirmed, _SALT_DELETED_KEYS, _SALT_DELETED_KEYS, "salt_deleted")
        if confirmed["confirmed"] is not True:
            raise _Invalid("salt_deleted.confirmed", "expected true")
        if not isinstance(confirmed["utc"], str) or not _UTC_TIME.fullmatch(confirmed["utc"]):
            raise _Invalid("salt_deleted.utc", "expected a UTC time ending in Z")
        salt_deleted_utc = confirmed["utc"]
    if not isinstance(data["not_covered"], list) or not all(
        isinstance(item, str) for item in data["not_covered"]
    ):
        raise _Invalid("not_covered", "expected a list of strings")
    if not isinstance(data["paths"], list):
        raise _Invalid("paths", "expected a list")
    paths = []
    for number, item in enumerate(data["paths"]):
        where = f"paths[{number}]"
        if not isinstance(item, dict):
            raise _Invalid(where, "expected an object")
        _closed(item, _PURGED_PATH_KEYS, _PURGED_PATH_KEYS, where)
        if not isinstance(item["path"], str) or not item["path"]:
            raise _Invalid(f"{where}.path", "expected a path")
        if item["kind"] not in PURGE_KINDS:
            raise _Invalid(f"{where}.kind", f"{item['kind']!r} is not one of the kinds")
        outcome = item["outcome"]
        if not isinstance(outcome, str) or not (
            outcome in (DELETED, ABSENT, NOT_FOUND) or outcome.startswith("failed: ")
        ):
            raise _Invalid(
                f"{where}.outcome",
                f"expected deleted, missing, {NOT_FOUND} or failed: <words>",
            )
        paths.append(PurgedPath(item["path"], item["kind"], outcome))
    return Purged(
        purged_version=data["purged_version"],
        engagement_id_declared=engaged["engagement_id_declared"],
        engagement_digest=engaged["engagement_digest"],
        chain=tuple(data["chain"]),
        bundles=tuple(data["bundles"]),
        purged_utc=data["purged_utc"],
        author=data["author"],
        before_retention_reason=data["before_retention_reason"],
        delete_after_declared=data["delete_after_declared"],
        paths=tuple(paths),
        not_covered=tuple(data["not_covered"]),
        salt_deleted_utc=salt_deleted_utc,
    )


# -- small helpers ------------------------------------------------------------------------


def _read_no_link(path: Path, limit: int | None = None) -> bytes:
    """A file's bytes, opened without following a link at its last component and only if it
    is a regular file; with ``limit``, at most ``limit + 1`` bytes."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return handle.read() if limit is None else handle.read(limit + 1)


def _why(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        if exc.errno == errno.ELOOP:
            return "it is a symbolic link, not followed"
        return exc.strerror or str(exc)
    return str(exc)


def _suffix(path: Path) -> str:
    suffix = path.suffix.lower()
    return suffix if suffix in _SUFFIXES else ""


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON value")
