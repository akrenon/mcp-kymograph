"""The engagement gate. The tool can alter traffic, which changes its legal footing: altering
traffic to a system you were not engaged to test is a different act from observing your own.

The rule: while a scenario is active, a target outside localhost may only be run with an
explicit confirmation that an engagement exists. Without it the run is refused before any
process starts. Pure observation with no scenario needs no confirmation.

Fail closed. Anything not recognisably local counts as non-local and therefore needs the
confirmation — an unrecognised target must not slip through as if it were safe. That includes
anything this module cannot take apart with certainty: a target it cannot parse is treated as
non-local, never waved through.

This module makes no network connection and **resolves no name**. ``box.local`` and
``127.0.0.2`` may well point at loopback; they still count as non-local, because deciding
otherwise would mean asking a resolver, and a resolver's answer is not something a gate with
legal weight should depend on. The cost is that the tool sometimes asks when it need not.
That is the safe direction.

In this phase the stdio transport always spawns a local child, so ``target`` is only ever the
operator's declaration for this gate; it gains a transport meaning when a networked transport
arrives, not here.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

#: Loopback, in the one definition the project has: these literals, compared as strings, and
#: nothing resolved. No name is among them, ``localhost`` included: a name means what a resolver
#: says it means. Plain HTTP is spoken to these only (:func:`plain_http_refusal`).
LOOPBACK_LITERALS = frozenset({"127.0.0.1", "::1", "[::1]"})

#: Only these count as local for the gate: the loopback literals and the name ``localhost``,
#: which the gate has always taken. Everything else, including anything unrecognised, is treated
#: as non-local so the gate errs towards asking for confirmation rather than towards skipping it.
LOCAL_TARGETS = LOOPBACK_LITERALS | {"localhost"}

#: A port must be a real one. 0 is reserved and never a target you can be engaged against.
MIN_PORT = 1
MAX_PORT = 65535


class Unauthorized(Exception):
    """Raised when a scenario would run against a non-local target without confirmation."""


@dataclass(frozen=True, slots=True)
class Declaration:
    """What the operator said about this run's authorization, recorded as what it is.

    **This is a claim, not a finding.** Nothing here was verified by the tool and nothing here
    could be: ``declared_target`` is a string the operator typed, never compared against what
    the child process actually talks to, and ``engagement_confirmed_flag`` is the state of a
    command-line flag — an attestation, not a credential. The field names say so, because a
    reader of the recording months later has only the names to go on.

    ``rules_loaded`` is the one fact in here. The proxy reports it from the engine it was
    actually given, so a report can see when a named scenario loaded nothing — which is the
    condition under which the gate quietly does not apply.
    """

    #: The scenario the operator selected, or None for pure observation: a built-in name, or
    #: a file path exactly as typed.
    scenario: str | None = None
    #: SHA-256 of the scenario file's bytes as they were read, or None for a built-in or no
    #: scenario. A fact, not a claim: a file can change after the run, and this is what says
    #: which version of it the run was under.
    scenario_digest: str | None = None
    #: The ``--target`` string as typed. None means no target was given, which over stdio is
    #: the local child process. Never resolved, never checked against the real destination.
    declared_target: str | None = None
    #: Whether ``--engagement-confirmed`` was passed. Records that a claim was made.
    engagement_confirmed_flag: bool = False
    #: Observed, not declared: whether the engine actually had rules.
    rules_loaded: bool = False
    #: The engagement file's ``id`` as written in it: the operator's name for the engagement,
    #: a claim. None for a run without a file (mcp_kymograph.engagement).
    engagement_id_declared: str | None = None
    #: SHA-256 of the engagement file's bytes as they were read. A fact, not a claim: which
    #: file the run was gated against, whatever that file says.
    engagement_digest: str | None = None
    #: The window as the file declares it, ``{"from": …, "until": …}`` in UTC ending in ``Z``.
    #: What was agreed, not when anything was permitted to happen.
    window_declared: dict[str, str] | None = None

    def window_until(self) -> datetime | None:
        """The end of the declared window as an aware time, or None without one."""
        if self.window_declared is None:
            return None
        until = self.window_declared["until"]
        # Written by mcp_kymograph.engagement in UTC with a "Z", which Python 3.10's
        # fromisoformat does not take.
        return datetime.fromisoformat(until[:-1] + "+00:00" if until.endswith("Z") else until)

    def as_dict(self) -> dict[str, Any]:
        """What ``run_started.authorization`` records. Of an engagement file only its id, its
        digest and its window go in, under ``engagement`` (null without a file): contacts and
        references are the operator's and have no place in an artifact that may be handed on."""
        engaged = (
            self.engagement_id_declared is not None
            or self.engagement_digest is not None
            or self.window_declared is not None
        )
        return {
            "scenario": self.scenario,
            "scenario_digest": self.scenario_digest,
            "declared_target": self.declared_target,
            "engagement_confirmed_flag": self.engagement_confirmed_flag,
            "rules_loaded": self.rules_loaded,
            "engagement": {
                "engagement_id_declared": self.engagement_id_declared,
                "engagement_digest": self.engagement_digest,
                "window_declared": None
                if self.window_declared is None
                else dict(self.window_declared),
            }
            if engaged
            else None,
        }


def is_local(target: str | None) -> bool:
    """Whether a target is local. ``None`` is the stdio child, which is always local.

    A port does not change where a target is: ``localhost:8080`` is as local as ``localhost``.
    The host is therefore split off before the comparison — but only when the split is
    unambiguous. Anything else falls through as non-local.
    """
    if target is None:
        return True
    cleaned = target.strip().lower()
    if cleaned in LOCAL_TARGETS:
        return True
    host = host_of(cleaned)
    return host is not None and host in LOCAL_TARGETS


def host_of(target: str) -> str | None:
    """The host part of a ``host:port`` target, or None when it does not split cleanly.

    None is the fail-closed answer and covers every case this cannot be sure about: an
    unbracketed address with several colons (``::ffff:127.0.0.1`` — is the tail a port or part
    of the address?), an unclosed bracket, a missing host, a port that is not a plain number
    in range. A URL like ``http://localhost:8080`` lands here too, and is refused rather than
    guessed at: this gate takes a host, not an address to be interpreted.
    """
    if target.startswith("["):
        # An unclosed bracket needs no guard of its own: `find` returns -1, the slicing then
        # yields an empty host and leaves the whole string as `rest`, and `rest` cannot start
        # with ":" because this branch began with "[". So it falls out below. That is not
        # obvious to read, which is why it is not left to a comment — the invariant it rests
        # on is pinned by `test_host_of_never_returns_a_malformed_host`, and a refactor that
        # breaks it turns that test red instead of leaving a guard here that no longer guards.
        closing = target.find("]")
        host = target[: closing + 1]  # brackets kept: "[::1]" is the form we compare against
        rest = target[closing + 1 :]
        # A bracketed host is "[", something, "]" — nothing shorter is one. This is the
        # invariant the whole branch rests on, checked once, here.
        if len(host) < 3 or not host.endswith("]"):
            return None
        if not rest:
            return host
        if not rest.startswith(":") or not _is_port(rest[1:]):
            return None
        return host

    # Unbracketed. Splitting on the *first* colon is enough to refuse everything ambiguous,
    # without a separate "at most one colon" guard: for the result to be judged local, the
    # part before that colon has to be one of the colon-free local literals, and the part
    # after it has to be nothing but ASCII digits. Both conditions exclude a second colon by
    # construction, so "::ffff:127.0.0.1" (empty host) and "localhost:80:90" (no port) fall
    # out here on their own. A guard would have looked protective and done nothing — the
    # mutation that deleted it changed no outcome.
    host, _, port = target.partition(":")
    if not host or not _is_port(port):
        return None
    return host


def split_target(text: str) -> tuple[str, int | None] | None:
    """Host and port of a target, or None when it does not split cleanly.

    The rules of :func:`host_of`, fail closed in the same places — no name resolved, a URL
    refused, an unbracketed address with several colons refused, a port that is not plain ASCII
    digits in range refused — with two forms more: a bare host (``example.com``) and a
    bracketed IPv6 literal without a port (``[2001:db8::1]``) are taken, with port None. An
    engagement file names hosts and ports apart, and a ``--target`` may be either.

    What comes back is for comparing as strings, and nothing else: lower case, the brackets of
    an IPv6 literal removed. Nothing is normalised beyond that — ``[0:0::1]`` and ``[::1]`` are
    two strings, as ``box.local`` and ``127.0.0.2`` are two names, because telling them equal
    means interpreting them, and that is the same step as asking a resolver.

    Narrower than :func:`host_of` on purpose: a name is ASCII letters, digits, ``.``, ``_`` and
    ``-``, so a path, an ``@``, a space or a character that only lower-cases into ASCII
    (``"\\u212a".lower() == "k"``) is refused; a bracketed host must be an IPv6 address without
    a zone. ``::1`` is the one unbracketed address taken, because :data:`LOCAL_TARGETS` already
    names it.
    """
    cleaned = text.strip()
    if not cleaned.isascii():
        return None
    cleaned = cleaned.lower()
    if cleaned == "::1":
        return cleaned, None
    if cleaned.startswith("["):
        closing = cleaned.find("]")
        if closing < 0:
            return None
        inner, rest = cleaned[1:closing], cleaned[closing + 1 :]
        if not _is_ipv6(inner):
            return None
    else:
        inner, colon, port = cleaned.partition(":")
        if not _HOST_NAME.fullmatch(inner):
            return None
        rest = colon + port
    if not rest:
        return inner, None
    if not rest.startswith(":") or not _is_port(rest[1:]):
        return None
    return inner, int(rest[1:])


#: A host name as :func:`split_target` takes it, after lower-casing: ASCII only, no separators.
_HOST_NAME = re.compile(r"[a-z0-9_][a-z0-9._-]{0,252}")


def _is_ipv6(text: str) -> bool:
    # A zone ("%eth0") names an interface of this machine, which a target in a file cannot.
    if "%" in text or ":" not in text:
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _is_port(text: str) -> bool:
    # isascii() before isdigit(): str.isdigit() is true for Unicode digits that int() then
    # rejects outright ("\u00b2") or silently reads as a western number ("\u0663" -> 3). A
    # gate must not take either for a port.
    if not (text.isascii() and text.isdigit()):
        return False
    return MIN_PORT <= int(text) <= MAX_PORT


def is_loopback(host: str | None) -> bool:
    """Whether a URL's host is a loopback literal: one of :data:`LOOPBACK_LITERALS`, the host
    taken as ``urlsplit(url).hostname`` gives it — lower case, an IPv6 literal's brackets
    removed. None, a URL without a host, is not.

    A string comparison and nothing more, fail closed. ``localhost`` is not loopback here, nor
    are ``127.0.0.2``, ``::ffff:127.0.0.1``, ``0:0::1``, ``127.1`` or ``127.0.0.1.``, though each
    may well reach this machine: a name is resolved by a resolver; telling two spellings equal
    means interpreting them. Neither is a step this rule takes. The cost is that a URL that does
    reach loopback is sometimes refused. That is the safe direction.
    """
    return host is not None and host in LOOPBACK_LITERALS


def plain_http_refusal(url: str) -> str | None:
    """The words refusing ``url`` because it is plain HTTP to a host that is not a loopback
    literal (:func:`is_loopback`), or None. Kept here, in one place, so that the terminal and
    ``refusals.jsonl`` say the same.

    The words name the host, an IPv6 literal in brackets, and the port when the URL gives one —
    nothing else of the URL: user information, a path and a query can carry a credential, and
    the words reach a terminal and a file.

    None as well for a URL this cannot take apart: a character outside printable ASCII, a URL
    ``urlsplit`` refuses, no host, a port that is not a port. That is not this function's
    business: the URL reader (``http_client._parse_url``) refuses each of them in its own words,
    before anything connects.
    """
    # The reader's own first check: such a URL is refused there, and its characters must not
    # reach a terminal through these words.
    if any(ord(char) <= 0x20 or ord(char) >= 0x7F for char in url):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname
    if parts.scheme != "http" or not host or is_loopback(host):
        return None
    where = (f"[{host}]" if ":" in host else host) + ("" if port is None else f":{port}")
    return (
        f"plain HTTP to {where}, which is not a loopback address (127.0.0.1 or [::1]; no name, "
        "not even localhost): a recording made over it is evidence of what arrived, not of what "
        "the server sent, and the answers would cross the network readable. Use https:// or a "
        "loopback address."
    )


def requires_confirmation(
    *, scenario_active: bool, target: str | None, script_calls: bool = False
) -> bool:
    """Whether this run needs the confirmation. A script that calls a tool acts on the target
    as a scenario does, and is held to the same rule; a script that only lists is not."""
    return (scenario_active or script_calls) and not is_local(target)


def check(
    *, scenario_active: bool, target: str | None, confirmed: bool, script_calls: bool = False
) -> None:
    """Refuse a scenario, or a script that calls tools, against a non-local target unless an
    engagement is confirmed."""
    if (
        requires_confirmation(
            scenario_active=scenario_active, target=target, script_calls=script_calls
        )
        and not confirmed
    ):
        what = "A scenario alters traffic" if scenario_active else "A script that calls tools acts"
        raise Unauthorized(
            f"{what}. Running one against a target outside localhost "
            "requires a written engagement that covers it. Re-run with --engagement-confirmed "
            "only if such an engagement exists."
        )
