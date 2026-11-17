"""What an engagement has done, whether it is ready to begin, and its report — read, never
decided.

Three readings of an engagement for the people working it (docs/engagements.md, 3, 4 and 7):

* :func:`status` — the status line the operator can send the customer without writing anything
  by hand: the window and how much of it is left, the runs so far by state, the findings so far
  by entry, the refusals, and what is still planned. The same text is the first paragraph of the
  report's section 2, so the customer reads the same account twice.
* :func:`preflight` — the day before: is each thing the engagement needs in place? One item
  per thing, each ``ready``, ``not_ready`` or ``not_checked``, with the words why.
* :func:`build`, :func:`render`, :func:`parse` — the report: seven sections of sentences, each
  of exactly one kind, tagged at the start of its line — ``[recorded]``, what the tool wrote
  down; ``[derived]``, what follows from that by the rule the sentence names; ``[assessed]``,
  what a person entered in the triage table, under their name. Every value from the traffic, the
  store or a file is a code span, so none is read as Markdown; :func:`parse` reads the report
  back and refuses a line it cannot place.

**Which kind a fixed sentence is.** A count of what the store or a refusals file holds, and a
sentence about what the report was given (no out-dir, no previous bundle), is recorded: it is
what the tool wrote down or was handed. A statement about this version — what it enforces,
observes or computes, what a signal's kind is — is derived, from the code it names
(``verdict.OBSERVED_ISOLATIONS``, ``signals.KINDS``, ``sandbox.policy.PROVIDED``,
``engagement.record_refusal``). A sentence about a real-world entry's finding, in whichever
section, begins with :data:`CANDIDATE`.

**What the engagement did not do and did not observe** opens section 7 and stands in the
attestation alike (:func:`coverage`): one derived clause per recorded fact, each present only
where its fact holds. No generated sentence uses a word of :data:`BANNED_WORDS`.

**Every count has a source, and it is named.** The store (its runs, its findings, its fleets'
results, its engagement chain) or a refusals file under the out-dir; nothing is inferred, and
nothing is counted that neither holds. A run that is not complete is counted under its own
state and never as done: what is still planned is what has no *complete* run.

**The status goes by mail; the findings go in the bundle.** So the status carries counts and
nothing else of a finding — no locator, no signal, no text the server sent. A real-world entry's
findings are counted apart and called what they are: candidates for responsible disclosure.

**What could not be read is said.** A refusals file that cannot be read is named as unreadable,
never left out, or the status would count fewer refusals than there were and not know it. A file
with little room left below its cap (:data:`mcp_kymograph.engagement.MAX_REFUSALS_BYTES`) says
how little: a refusal longer than that room is not written, and nothing records that it was
not, so the room is what can be said — never that a refusal was or was not dropped.

**Preflight touches nothing.** No network, no target contacted, nothing created or written. It
reads the engagement file and what it lists, the manifest, the store (through SQLite's read-only
mode), the out-dir's listing and modes; it asks the local ``git`` whether those two lie where
recordings could be committed, as every run asks it, and the local ``docker`` for image ids
through a function the caller hands in. Whether an endpoint answers is found out by the first
run inside the window, and recorded there.

None of them assesses anything — the report shows what a person assessed, as theirs — and none
judges a server. Every string that came from a file or the store is passed through the command
line's terminal filter (:func:`mcp_kymograph.cli.display`) before it is shown.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import sqlite3
import stat
import unicodedata
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_kymograph import eras, evidence, verdict
from mcp_kymograph import store as store_module
from mcp_kymograph.authorization import is_local, plain_http_refusal, split_target
from mcp_kymograph.corpus import Manifest, ManifestError
from mcp_kymograph.corpus import load as load_manifest
from mcp_kymograph.engagement import (
    ENDPOINT_DEFAULT_PORTS,
    ENDPOINT_DEFAULT_SCHEME,
    FORMAT_VERSION_2,
    MAX_REFUSALS_BYTES,
    MIN_SALT_LENGTH,
    REFUSAL_REASONS,
    REFUSALS_FILE,
    REMOTE,
    Engagement,
    RefusalsFile,
    declared_customer,
    find_refusals,
    utc_text,
)
from mcp_kymograph.engagement import load as load_engagement
from mcp_kymograph.finding_classes import UnknownIdentError, class_of
from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES
from mcp_kymograph.masking import PERSONAL_KINDS, PLACEHOLDER
from mcp_kymograph.output import DIR_MODE, Severity, inspect_destination, unusable
from mcp_kymograph.pacing import DEFAULT_MIN_INTERVAL_SECONDS, DEFAULT_RUNS_PER_ORIGIN
from mcp_kymograph.recorder import FILE_MODE
from mcp_kymograph.sandbox import docker
from mcp_kymograph.sandbox.policy import PROVIDED
from mcp_kymograph.signals import KINDS, Signal
from mcp_kymograph.store import IDENTITY_FIELDS, Store, StoreError
from mcp_kymograph.web._found import read_bytes, resolve_filed, search

#: The states a filed run can have, in the order the status names them: the one that is a
#: result first, then those that are not.
RUN_STATES = (verdict.COMPLETE, *(s for s in verdict.STATES if s != verdict.COMPLETE))

#: The states of a fleet's result that have no run behind them in the store: refused by its
#: child before anything started, or run but not filed.
FLEET_ONLY_STATES = ("refused", "unfiled")

#: How many pairs, entries or files a rendered status names before it gives only the count: the
#: status is a dozen lines, and every count stays whole in :meth:`Status.to_dict`.
LISTED = 8

#: A preflight item's states. ``not_checked``: the option that would let it be checked was not
#: given, or nothing machine-readable exists to check it against.
READY = "ready"
NOT_READY = "not_ready"
NOT_CHECKED = "not_checked"
ITEM_STATES = (READY, NOT_READY, NOT_CHECKED)

#: What ``engagement preflight`` exits with: everything ready (or not checked), or not.
EXIT_READY = 0
EXIT_NOT_READY = 3

#: Below how much room under :data:`~mcp_kymograph.engagement.MAX_REFUSALS_BYTES` a refusals
#: file's room is said. A refusal's line is its masked command and its words: well under a
#: kilobyte for a command typed by hand, tens of kilobytes for a long generated one. 64 KiB is
#: above any line seen in practice and a negligible part of the 16 MiB a file may grow to, so a
#: file is said to be near its cap only when an ordinary refusal could indeed not be written.
REFUSALS_ROOM_SAID = 64 * 1024

#: What ``engagement status`` exits with when something it was to count could not be read.
EXIT_UNREAD = 3

_DAY = 86400


class ReportError(ValueError):
    """A store and an engagement file that do not belong together; says which and why."""


# -- the terminal filter -------------------------------------------------------------------


def _safe(value: object) -> str:
    """A value from a file or the store, without what has no business on a terminal — the
    command line's own filter, whole (not shortened)."""
    # Imported here: the command line imports this module, and this is the one thing of it
    # used here.
    from mcp_kymograph.cli import display

    text = str(value)
    return display(text, limit=len(text) + 1)


# -- time ---------------------------------------------------------------------------------


def _aware(now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be an aware time")
    return now.astimezone(timezone.utc)


def _parse_utc(value: Any) -> datetime | None:
    """A window time as the file and the store hold it (ISO 8601 with ``Z`` or ``+00:00``), or
    None when it is not one."""
    if not isinstance(value, str):
        return None
    spelled = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = datetime.fromisoformat(spelled)
    except ValueError:
        return None
    if moment.utcoffset() is None or moment.utcoffset().total_seconds() != 0:
        return None
    return moment


def _span(seconds: int) -> str:
    """A length of time in the coarsest unit that is not zero: days, hours, or under an hour."""
    if seconds >= _DAY:
        days = seconds // _DAY
        return f"{days} day{'s' if days != 1 else ''}"
    if seconds >= 3600:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return "less than an hour"


@dataclass(frozen=True, slots=True)
class Window:
    """Where ``now`` stands against a window: ``not_open`` (``seconds`` until it opens),
    ``open`` (``seconds`` until it closes), ``closed`` (``seconds`` since it closed), or
    ``unknown`` when there is no window that can be read (``seconds`` None)."""

    position: str
    seconds: int | None

    def words(self) -> str:
        if self.position == "not_open":
            return f"opens in {_span(self.seconds)}"
        if self.position == "open":
            return f"open, {_span(self.seconds)} left"
        if self.position == "closed":
            return f"closed {_span(self.seconds)} ago"
        return "not known: no window that can be read as UTC times"


def _window(start: datetime | None, end: datetime | None, now: datetime) -> Window:
    if start is None or end is None:
        return Window("unknown", None)
    if now < start:
        return Window("not_open", int((start - now).total_seconds()))
    if now < end:
        return Window("open", int((end - now).total_seconds()))
    return Window("closed", int((now - end).total_seconds()))


# -- status -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntryCount:
    """One entry's runs and findings, as the store has filed them — counts only.

    ``findings`` is the number of findings filed under the entry's runs (each finding once,
    however often it was sighted); ``findings_in_complete`` how many of them were sighted in at
    least one complete run. The rest were sighted only in runs that are not results.
    """

    entry: str
    provenance: str
    runs: int
    complete_runs: int
    findings: int
    findings_in_complete: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "provenance": self.provenance,
            "runs": self.runs,
            "complete_runs": self.complete_runs,
            "findings": self.findings,
            "findings_in_complete": self.findings_in_complete,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntryCount:
        return cls(**data)


@dataclass(frozen=True, slots=True)
class RefusalsCount:
    """One ``refusals.jsonl`` under the out-dir: its refusals counted by reason, or why it could
    not be read.

    ``by_reason`` counts the refusals made under a version of this engagement's file;
    ``other_engagement`` those that name a digest the store's chain does not hold;
    ``outside_window`` how many of the first lie outside the window of the version they name.
    ``room_bytes``: how many bytes are left below
    :data:`~mcp_kymograph.engagement.MAX_REFUSALS_BYTES`. A refusal whose line is longer is not
    written, and the file keeps no trace of one that was not, so the room is said
    (:attr:`near_cap`) and no drop is ever claimed or denied.
    """

    path: str
    #: Why the file was not counted, in the tool's words, a part of a sentence; None when it was.
    unreadable: str | None = None
    #: Beside ``unreadable``: what the system said (an operating system's reason), or None. A
    #: value, not a sentence of the tool's: a report shows it in a code span.
    detail: str | None = None
    #: For a file the engagement reader refused, its reason as it gave it, which sets what it read
    #: in its own sentence: for the status's JSON only, never a document's words or spans.
    reason: str | None = None
    by_reason: dict[str, int] = field(default_factory=dict)
    other_engagement: int = 0
    outside_window: int = 0
    size_bytes: int | None = None
    room_bytes: int | None = None

    @property
    def counted(self) -> int:
        return sum(self.by_reason.values())

    @property
    def near_cap(self) -> bool:
        """Whether the room left is under :data:`REFUSALS_ROOM_SAID`, and so is said."""
        return self.room_bytes is not None and self.room_bytes < REFUSALS_ROOM_SAID

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "unreadable": self.unreadable,
            "detail": self.detail,
            "reason": self.reason,
            "by_reason": dict(self.by_reason),
            "other_engagement": self.other_engagement,
            "outside_window": self.outside_window,
            "size_bytes": self.size_bytes,
            "room_bytes": self.room_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RefusalsCount:
        return cls(**{**data, "by_reason": dict(data["by_reason"])})


@dataclass(frozen=True, slots=True)
class Planned:
    """One thing still planned: a scenario the file lists — with a manifest, under one entry —
    that has no complete run in the store. ``states`` counts the runs it has, none complete."""

    entry: str | None
    scenario_path: str
    scenario_sha256: str
    states: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "scenario_path": self.scenario_path,
            "scenario_sha256": self.scenario_sha256,
            "states": dict(self.states),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Planned:
        return cls(**{**data, "states": dict(data["states"])})


@dataclass(frozen=True, slots=True)
class Status:
    """``engagement status``: what the engagement has done so far, from the store and the
    refusals files, counted and never judged."""

    now_utc: str
    #: The store's engagement: the file's id as typed, the current version's digest, and how
    #: many versions the chain holds. None (and 0) for a store that holds none.
    engagement_id_declared: str | None
    engagement_digest: str | None
    versions: int
    #: Where the id and window were read: ``store`` (the chain's current version), ``file`` (a
    #: file handed in for a store that holds no engagement yet), or None.
    engagement_source: str | None
    #: The current version's window as declared, and where ``now`` stands against it.
    window_from: str | None
    window_until: str | None
    window: Window
    #: Every run state, each with its count (zeros included).
    runs_by_state: dict[str, int]
    entries: tuple[EntryCount, ...]
    #: Fleet results with no run behind them, from the store's ``fleet_results``.
    fleet_results: dict[str, int]
    #: None: no out-dir was given, and refusals were not looked at.
    refusals_out_dir: str | None
    refusal_files: tuple[RefusalsCount, ...]
    #: The scenarios the file lists, as ``{"path", "sha256"}``.
    listed_scenarios: tuple[dict[str, str], ...]
    #: The manifest the planned pairs were read against, or None (then ``planned`` is by
    #: scenario only).
    manifest_source: str | None
    #: How many pairs (or, without a manifest, scenarios) were looked at; ``planned`` is those
    #: of them without a complete run.
    plannable: int
    planned: tuple[Planned, ...]
    #: The canaries the file lists that the agency has not confirmed gone, as ``{"id", "kind"}``:
    #: never where they lie.
    open_canaries: tuple[dict[str, str], ...] = ()

    @property
    def refusals_unreadable(self) -> tuple[RefusalsCount, ...]:
        return tuple(item for item in self.refusal_files if item.unreadable is not None)

    @property
    def exit_code(self) -> int:
        """0, or :data:`EXIT_UNREAD` when something to be counted could not be read: a refusals
        file, or an engagement the store does not hold."""
        if self.refusals_unreadable or self.engagement_digest is None:
            return EXIT_UNREAD
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "now_utc": self.now_utc,
            "engagement_id_declared": self.engagement_id_declared,
            "engagement_digest": self.engagement_digest,
            "versions": self.versions,
            "engagement_source": self.engagement_source,
            "window_from": self.window_from,
            "window_until": self.window_until,
            "window": {"position": self.window.position, "seconds": self.window.seconds},
            "runs_by_state": dict(self.runs_by_state),
            "entries": [entry.to_dict() for entry in self.entries],
            "fleet_results": dict(self.fleet_results),
            "refusals_out_dir": self.refusals_out_dir,
            "refusal_files": [item.to_dict() for item in self.refusal_files],
            "listed_scenarios": [dict(item) for item in self.listed_scenarios],
            "manifest_source": self.manifest_source,
            "plannable": self.plannable,
            "planned": [item.to_dict() for item in self.planned],
            "open_canaries": [dict(item) for item in self.open_canaries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Status:
        """The status :meth:`to_dict` wrote, read back."""
        return cls(
            **{
                **data,
                "open_canaries": tuple(dict(item) for item in data.get("open_canaries", ())),
                "window": Window(**data["window"]),
                "runs_by_state": dict(data["runs_by_state"]),
                "entries": tuple(EntryCount.from_dict(item) for item in data["entries"]),
                "fleet_results": dict(data["fleet_results"]),
                "refusal_files": tuple(
                    RefusalsCount.from_dict(item) for item in data["refusal_files"]
                ),
                "listed_scenarios": tuple(dict(item) for item in data["listed_scenarios"]),
                "planned": tuple(Planned.from_dict(item) for item in data["planned"]),
            }
        )


def status(
    store: Store,
    *,
    engagement: Engagement | None = None,
    manifest: Manifest | str | Path | None = None,
    out_dir: str | Path | None = None,
    now: datetime,
) -> Status:
    """Count what the engagement has done so far.

    The engagement is the store's (:meth:`Store.engagement`, the chain's current version). A
    file handed in as ``engagement`` must be a version of it; for a store that holds no
    engagement yet and no runs, the file's id, window and scenarios are used and the status
    says so. Raises :class:`ReportError` for a file that is not the store's,
    :class:`~mcp_kymograph.store.StoreError` for a store whose engagement rows do not fit,
    :class:`~mcp_kymograph.corpus.ManifestError` for a manifest that cannot be read, and
    :class:`~mcp_kymograph.engagement.EngagementError` for an out-dir that is not a directory
    that can be listed. A refusals file under it that cannot be read is not raised: it is
    counted as unreadable.
    """
    moment = _aware(now)
    held = store.engagement()
    runs = store.runs()
    fleets = store.fleets()
    source: str | None
    if held is not None:
        if engagement is not None and not any(
            entry["digest"] == engagement.digest for entry in held["chain"]
        ):
            raise ReportError(
                f"{engagement.source}: its digest {engagement.digest} is not among the store's "
                f"versions of {held['engagement_id_declared']}; the status is of the store's "
                "engagement, and this file is not one of its versions"
            )
        current = held["chain"][-1]["file_declared"]
        name, digest, versions = (
            held["engagement_id_declared"],
            held["engagement_digest"],
            len(held["chain"]),
        )
        declared_window = current.get("window") if isinstance(current, dict) else None
        listed_raw = current.get("scenarios") if isinstance(current, dict) else None
        canaries_raw = current.get("canaries") if isinstance(current, dict) else None
        source = "store"
    elif engagement is not None:
        if runs or fleets:
            raise ReportError(
                f"the store holds {len(runs)} run(s) and {len(fleets)} fleet run(s) filed "
                f"without an engagement; {engagement.source} is not its engagement"
            )
        name, digest, versions = engagement.id, engagement.digest, 1
        declared_window = engagement.data.get("window")
        listed_raw = [{"path": s.path, "sha256": s.sha256} for s in engagement.scenarios]
        canaries_raw = engagement.data.get("canaries")
        source = "file"
    else:
        name = digest = declared_window = listed_raw = canaries_raw = source = None
        versions = 0

    window_from = window_until = None
    if isinstance(declared_window, dict):
        window_from = declared_window.get("from")
        window_until = declared_window.get("until")
    window = _window(_parse_utc(window_from), _parse_utc(window_until), moment)
    listed = _listed(listed_raw)

    counted = Counter(run.state for run in runs)
    runs_by_state = {state: counted.get(state, 0) for state in RUN_STATES}
    for state, count in counted.items():  # a state this version does not name, kept anyway
        runs_by_state.setdefault(state, count)

    fleet_counts: Counter[str] = Counter()
    for fleet in fleets:
        for result in fleet["results"].values():
            if result["state"] in FLEET_ONLY_STATES:
                fleet_counts[result["state"]] += 1
    fleet_results = (
        {state: fleet_counts.get(state, 0) for state in FLEET_ONLY_STATES} if fleets else {}
    )

    if held is not None:
        windows = _windows(held["chain"])
    elif digest is not None:
        windows = {digest: _window_of({"window": declared_window})}
    else:
        windows = {}
    refusal_files: tuple[RefusalsCount, ...] = ()
    shown_out_dir = None
    if out_dir is not None:
        shown_out_dir = str(out_dir)
        refusal_files = tuple(
            _count_refusals(found, Path(out_dir), windows) for found in find_refusals(out_dir)
        )

    loaded = manifest
    if manifest is not None and not isinstance(manifest, Manifest):
        loaded = load_manifest(manifest)
    plannable, planned = _planned(runs, listed, loaded)

    return Status(
        now_utc=utc_text(moment),
        engagement_id_declared=name,
        engagement_digest=digest,
        versions=versions,
        engagement_source=source,
        window_from=window_from if isinstance(window_from, str) else None,
        window_until=window_until if isinstance(window_until, str) else None,
        window=window,
        runs_by_state=runs_by_state,
        entries=_entries(store, runs),
        fleet_results=fleet_results,
        refusals_out_dir=shown_out_dir,
        refusal_files=refusal_files,
        listed_scenarios=listed,
        manifest_source=None if loaded is None else loaded.source,
        plannable=plannable,
        planned=planned,
        open_canaries=_open_canaries(canaries_raw),
    )


def _open_canaries(raw: Any) -> tuple[dict[str, str], ...]:
    """The file's canaries the agency has not confirmed gone, by ID and kind. ``removed`` is a date
    once confirmed; null, or a placeholder in a draft, is not."""
    if not isinstance(raw, list):
        return ()
    found = []
    for item in raw:
        if not (
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and isinstance(item.get("kind"), str)
        ):
            continue
        removed = item.get("removed")
        if isinstance(removed, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", removed):
            continue
        found.append({"id": item["id"], "kind": item["kind"]})
    return tuple(found)


def _listed(raw: Any) -> tuple[dict[str, str], ...]:
    """The file's ``scenarios`` as the store keeps them; anything else in the list is not one
    and is left out (the reader refused such a file before the store took it)."""
    if not isinstance(raw, list):
        return ()
    return tuple(
        {"path": item["path"], "sha256": item["sha256"]}
        for item in raw
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha256"), str)
    )


def _entries(store: Store, runs: list) -> tuple[EntryCount, ...]:
    """Each entry's runs and findings, from the runs' sightings: a finding counted once per
    entry however many runs sighted it."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for run in runs:
        group = grouped.setdefault(
            (run.server, run.provenance),
            {"runs": 0, "complete": 0, "findings": set(), "in_complete": set()},
        )
        group["runs"] += 1
        found = set(store.findings_of(run.run))
        group["findings"] |= found
        if run.complete:
            group["complete"] += 1
            group["in_complete"] |= found
    return tuple(
        EntryCount(
            entry=entry,
            provenance=provenance,
            runs=group["runs"],
            complete_runs=group["complete"],
            findings=len(group["findings"]),
            findings_in_complete=len(group["in_complete"]),
        )
        for (entry, provenance), group in sorted(grouped.items())
    )


def _window_of(declared: Any) -> tuple[datetime | None, datetime | None]:
    """The window a version of the file declares, as times, or None where it cannot be read."""
    window = declared.get("window") if isinstance(declared, dict) else None
    if not isinstance(window, dict):
        return None, None
    return _parse_utc(window.get("from")), _parse_utc(window.get("until"))


def _windows(chain: list[dict[str, Any]]) -> dict[str, tuple[datetime | None, datetime | None]]:
    """Each version's window, by the digest a refusal under it names."""
    return {entry["digest"]: _window_of(entry["file_declared"]) for entry in chain}


#: Why a refusals file the engagement reader refused is not counted, in a document's words.
REFUSED_BY_THE_READER = "the engagement reader refuses it"


def _unread_words(counted: RefusalsCount, show: Callable[[object], str]) -> str:
    """Why a refusals file was not counted: the tool's words, then what the system said as a
    value, through ``show``."""
    return counted.unreadable + (f": {show(counted.detail)}" if counted.detail else "")


def _count_refusals(
    found: RefusalsFile,
    out_dir: Path,
    windows: dict[str, tuple[datetime | None, datetime | None]],
) -> RefusalsCount:
    """One refusals file counted: each refusal against the window of the version it names (a
    refusal under an earlier version is judged by that version's window, not the current one's),
    and the room left below the cap."""
    try:
        shown = str(found.path.relative_to(out_dir))
    except ValueError:
        shown = str(found.path)
    if found.not_listed is not None:
        return RefusalsCount(path=shown, unreadable="it cannot be listed", detail=found.not_listed)
    if found.not_read is not None:
        return RefusalsCount(path=shown, unreadable="it cannot be read", detail=found.not_read)
    if found.refused is not None:
        # The engagement reader refuses what the file holds (or a link at its place). Its reason
        # is its own sentence, with what it read set in it; it is not taken over, so no value of
        # the file stands among a document's words.
        return RefusalsCount(path=shown, unreadable=REFUSED_BY_THE_READER, reason=found.refused)
    by_reason: Counter[str] = Counter()
    other = outside = 0
    for record in found.records:
        if record.engagement_digest not in windows:
            other += 1
            continue
        by_reason[record.reason] += 1
        start, end = windows[record.engagement_digest]
        refused = _parse_utc(record.refused_utc)
        known = start is not None and end is not None and refused is not None
        if known and not start <= refused < end:
            outside += 1
    try:
        size = os.lstat(found.path).st_size
    except OSError as exc:
        return RefusalsCount(
            path=shown,
            unreadable="read, then could not be measured",
            detail=exc.strerror or str(exc),
        )
    return RefusalsCount(
        path=shown,
        by_reason={reason: by_reason[reason] for reason in REFUSAL_REASONS if by_reason[reason]},
        other_engagement=other,
        outside_window=outside,
        size_bytes=size,
        room_bytes=max(MAX_REFUSALS_BYTES - size, 0),
    )


def _planned(
    runs: list, listed: tuple[dict[str, str], ...], manifest: Manifest | None
) -> tuple[int, tuple[Planned, ...]]:
    """What is still planned: each listed scenario — with a manifest, each (entry, scenario)
    whose scenario the file lists — that has no complete run in the store."""
    digests = {item["sha256"]: item["path"] for item in listed}
    pairs: list[tuple[str | None, str]] = []
    if manifest is None:
        pairs = [(None, item["sha256"]) for item in listed]
    else:
        pairs = [
            (entry.name, ref.digest)
            for entry in manifest.entries
            for ref in entry.scenarios
            if ref.digest in digests
        ]
    planned = []
    for entry, digest in pairs:
        matching = [
            run
            for run in runs
            if run.scenario_digest == digest and (entry is None or run.server == entry)
        ]
        if any(run.complete for run in matching):
            continue
        states = Counter(run.state for run in matching)
        planned.append(
            Planned(
                entry=entry,
                scenario_path=digests[digest],
                scenario_sha256=digest,
                states={state: states[state] for state in RUN_STATES if states[state]},
            )
        )
    return len(pairs), tuple(planned)


def render_status(status: Status) -> str:
    """The status in a dozen lines, as it goes by mail and as it opens the report's section 2.

    Counts only. Names that appear are the operator's: the engagement's id, the entries', the
    scenario files' as the engagement lists them; never a locator, a signal or anything the
    server sent.
    """
    lines = status_lines(status)
    if status.open_canaries:
        # Not in ``status_lines``: those open the report, which does not show canaries (yet).
        # Every one is named: a canary left out of the list would be left in the source.
        lines.append(
            "Canaries not confirmed removed: "
            + "; ".join(f"{_safe(c['id'])} ({_safe(c['kind'])})" for c in status.open_canaries)
            + "."
        )
    return "\n".join(lines) + "\n"


def status_lines(status: Status, show: Callable[[object], str] = _safe) -> list[str]:
    """The status's lines, each value from a file or the store shown through ``show``: the
    terminal filter for the mail, a code span for the report (:func:`build`)."""
    lines: list[str] = []
    if status.engagement_digest is None:
        lines.append(
            "This store holds no engagement: its runs were filed without an engagement file, "
            "and there is no window to report against."
        )
    else:
        versions = (
            f"version {status.versions} of {status.versions}"
            if status.engagement_source == "store"
            else "from the file; the store holds no engagement yet"
        )
        lines.append(
            f"Engagement {show(status.engagement_id_declared)} ({versions}, SHA-256 "
            f"{show(status.engagement_digest)})."
        )
        if status.window.position == "unknown":
            lines.append(f"Window: {status.window.words()}.")
        else:
            lines.append(
                f"Window {show(status.window_from)} to {show(status.window_until)}: "
                f"{status.window.words()} (at {status.now_utc})."
            )

    complete = status.runs_by_state.get(verdict.COMPLETE, 0)
    others = [(s, n) for s, n in status.runs_by_state.items() if s != verdict.COMPLETE]
    total = sum(status.runs_by_state.values())
    lines.append(
        f"Runs filed: {total} — {complete} complete; not results: "
        + ", ".join(f"{n} {show(s)}" for s, n in others)
        + "."
    )
    if status.fleet_results:
        lines.append(
            "Fleet jobs with no run filed: "
            + ", ".join(f"{n} {show(s)}" for s, n in status.fleet_results.items())
            + " (the store's fleet results)."
        )

    ordinary = [e for e in status.entries if e.provenance != "real-world"]
    wild = [e for e in status.entries if e.provenance == "real-world"]
    if not ordinary:
        lines.append("Findings: no reference or poison entry has a run filed.")
    else:
        lines.append(
            "Findings by entry (counts only; what they are is in the bundle): "
            + _listing([_entry_words(e, "finding", show) for e in ordinary])
            + "."
        )
    if wild:
        lines.append(
            "Real-world entries, counted apart — candidates for responsible disclosure, not "
            "confirmed: " + _listing([_entry_words(e, "candidate", show) for e in wild]) + "."
        )
    else:
        lines.append("Real-world entries: none has a run filed.")

    lines += _refusal_lines(status, show)
    lines += _planned_lines(status, show)
    return lines


def _entry_words(entry: EntryCount, noun: str, show: Callable[[object], str]) -> str:
    words = (
        f"{show(entry.entry)} ({entry.provenance}) {entry.findings} {noun}"
        f"{'s' if entry.findings != 1 else ''} in {entry.runs} run{'s' if entry.runs != 1 else ''}"
    )
    if entry.complete_runs != entry.runs:
        words += f", {entry.complete_runs} of them complete"
    only = entry.findings - entry.findings_in_complete
    if only:
        words += f"; {only} sighted only in runs that are not results"
    return words


def _listing(items: list[str]) -> str:
    shown = items[:LISTED]
    if len(items) > LISTED:
        shown.append(f"and {len(items) - LISTED} more")
    return "; ".join(shown)


def _refusal_lines(status: Status, show: Callable[[object], str]) -> list[str]:
    if status.refusals_out_dir is None:
        return ["Refusals: not looked at — no out-dir was given."]
    files = status.refusal_files
    if not files:
        return [f"Refusals: none recorded; no {show(REFUSALS_FILE)} under the out-dir."]
    readable = [item for item in files if item.unreadable is None]
    reasons: Counter[str] = Counter()
    for item in readable:
        reasons.update(item.by_reason)
    total = sum(reasons.values())
    words = (
        f"Refusals under this engagement: {total} in {len(readable)} file"
        f"{'s' if len(readable) != 1 else ''}"
    )
    if total:
        words += " — " + ", ".join(
            f"{reasons[reason]} {show(reason)}" for reason in REFUSAL_REASONS if reasons[reason]
        )
    outside = sum(item.outside_window for item in readable)
    if outside:
        words += f"; {outside} of them outside the window of the version they name"
    other = sum(item.other_engagement for item in readable)
    if other:
        words += (
            f"; {other} more naming a file digest that is not in this store's chain, not "
            "counted here"
        )
    lines = [words + "."]
    lines += [
        f"{show(item.path)}: {_room_words(item.room_bytes)}" for item in readable if item.near_cap
    ][:LISTED]
    unreadable = status.refusals_unreadable
    if unreadable:
        lines.append(
            "Unreadable, not counted: "
            + _listing([f"{show(i.path)} ({_unread_words(i, show)})" for i in unreadable])
            + "."
        )
    return lines


def _room_words(room: int | None) -> str:
    return (
        f"{room} bytes left below the cap of {MAX_REFUSALS_BYTES}; a refusal longer than that "
        "cannot be written now."
    )


def _planned_lines(status: Status, show: Callable[[object], str]) -> list[str]:
    if status.engagement_digest is None:
        return ["Still planned: not known — there is no engagement file to read it from."]
    if not status.listed_scenarios:
        return ["Still planned: nothing — the engagement lists no scenario."]
    if status.manifest_source is None:
        words = (
            f"Still planned: {len(status.planned)} of {status.plannable} listed scenarios have "
            "no complete run"
        )
    else:
        words = (
            f"Still planned: {len(status.planned)} of {status.plannable} (entry, scenario) "
            f"pairs of {show(Path(status.manifest_source).name)} whose scenario the engagement "
            "lists have "
            "no complete run"
        )
    if status.planned:
        words += ": " + _listing([_planned_words(p, show) for p in status.planned])
    lines = [words + "."]
    if status.manifest_source is None:
        lines.append(
            f"Entries are not named: the engagement file names none; give {show('--manifest')} "
            "for them."
        )
    return lines


def _planned_words(planned: Planned, show: Callable[[object], str]) -> str:
    words = show(planned.scenario_path)
    if planned.entry is not None:
        words = f"{show(planned.entry)} × {words}"
    if planned.states:
        runs = sum(planned.states.values())
        words += (
            f" ({runs} run{'s' if runs != 1 else ''}, none complete: "
            + ", ".join(f"{n} {show(s)}" for s, n in planned.states.items())
            + ")"
        )
    return words


# -- preflight ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Item:
    """One thing preflight looked at: ``ready``, ``not_ready`` or ``not_checked``, and why."""

    name: str
    state: str
    words: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "state": self.state, "words": self.words}


@dataclass(frozen=True, slots=True)
class Preflight:
    """``engagement preflight``: each item it checks, in order."""

    source: str
    digest: str
    now_utc: str
    items: tuple[Item, ...]

    @property
    def ready(self) -> bool:
        """Every item ready or not checked: nothing that was looked at is missing."""
        return all(item.state != NOT_READY for item in self.items)

    @property
    def exit_code(self) -> int:
        return EXIT_READY if self.ready else EXIT_NOT_READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "digest": self.digest,
            "now_utc": self.now_utc,
            "ready": self.ready,
            "items": [item.to_dict() for item in self.items],
        }


def preflight(
    engagement_path: str | Path,
    *,
    manifest: str | Path | None = None,
    store: str | Path | None = None,
    out_dir: str | Path | None = None,
    sandbox_image: str | None = None,
    target_image: str | None = None,
    image_id: Callable[[str], str] = docker.image_id,
    environ: Mapping[str, str] | None = None,
    now: datetime,
) -> Preflight:
    """Check, item by item, whether an engagement is ready to begin. Nothing is contacted,
    created or written.

    The file is read by :func:`mcp_kymograph.engagement.load`; a file it refuses is not an item
    but the answer — :class:`~mcp_kymograph.engagement.EngagementError` propagates, and the
    command line exits 2. Two things leave this process, both on this machine: ``git``, asked
    whether the store and the out-dir lie where recordings could be committed (as every run asks
    it, :func:`mcp_kymograph.output.inspect_destination`), and ``image_id`` — by default the local
    ``docker image inspect``, which asks the local daemon and nothing beyond it. ``environ`` is
    where the salt's and the receiver key's variables are looked up (default: this process's);
    only whether a name is set and not empty is read, never the value.
    """
    moment = _aware(now)
    loaded = load_engagement(engagement_path)
    items = [
        _file_item(loaded, moment),
        _scenarios_item(loaded),
        _manifest_item(loaded, manifest),
        _isolation_item(loaded),
        _image_item("sandbox image", sandbox_image, "--sandbox-image", image_id),
        _image_item("target image", target_image, "--target-image", image_id),
        _endpoints_item(loaded),
        _store_item(loaded, store),
        _out_dir_item(out_dir),
        Item(
            "client templates",
            NOT_CHECKED,
            "docs/clients.md is documentation: nothing machine-readable says which client's "
            "configuration snippet exists, so whether one exists for each client the customer "
            "named is not checked here",
        ),
        _contacts_item(loaded),
        _canaries_item(loaded),
        _salt_item(loaded, os.environ if environ is None else environ),
        _receiver_key_item(loaded, os.environ if environ is None else environ),
    ]
    return Preflight(
        source=loaded.source, digest=loaded.digest, now_utc=utc_text(moment), items=tuple(items)
    )


def _file_item(loaded: Engagement, now: datetime) -> Item:
    if loaded.is_draft:
        return Item(
            "file",
            NOT_READY,
            "read whole, and a draft: it still holds placeholders at "
            + ", ".join(loaded.placeholders)
            + "; no run is permitted under it until every one is filled in",
        )
    window = _window(loaded.window_from, loaded.window_until, now)
    start, end = utc_text(loaded.window_from), utc_text(loaded.window_until)
    if window.position == "closed":
        return Item(
            "file",
            NOT_READY,
            f"read whole, no placeholders; the window closed at {end}, {_span(window.seconds)} "
            "ago: every run under it is refused",
        )
    if window.position == "open":
        return Item(
            "file",
            READY,
            f"read whole, no placeholders; the window is open now, until {end} "
            f"({_span(window.seconds)} left)",
        )
    return Item(
        "file",
        READY,
        f"read whole, no placeholders; the window opens at {start}, in {_span(window.seconds)}, "
        f"and closes at {end}",
    )


def _scenarios_item(loaded: Engagement) -> Item:
    if not loaded.scenarios:
        return Item(
            "scenarios",
            READY,
            "none listed: only runs without a scenario are permitted under this file, and a "
            "corpus run always has one",
        )
    count = len(loaded.scenarios)
    return Item(
        "scenarios",
        READY,
        f"{count} listed, each read and its SHA-256 matching the listing (the reader refuses the "
        "file otherwise): " + ", ".join(s.path for s in loaded.scenarios),
    )


def _manifest_item(loaded: Engagement, path: str | Path | None) -> Item:
    if path is None:
        return Item("manifest", NOT_CHECKED, "no --manifest given")
    try:
        manifest = load_manifest(path)
    except ManifestError as refused:
        return Item("manifest", NOT_READY, f"cannot be used: {refused}")
    listed = {s.sha256: s.path for s in loaded.scenarios}
    runnable: list[str] = []
    refused: list[str] = []
    unlisted: list[str] = []
    endpoints: list[str] = []
    for entry in manifest.entries:
        pairs = [
            f"{entry.name} × {listed[ref.digest]}"
            for ref in entry.scenarios
            if ref.digest in listed
        ]
        if not pairs:
            unlisted.append(entry.name)
            continue
        if entry.endpoint is not None:
            # Plain HTTP to a host that is not a loopback literal is read here and refused when
            # it is run: said now, as a real-world entry's refusal is.
            words = plain_http_refusal(entry.endpoint)
            if words is not None:
                refused.append(f"{entry.name} will be refused: {words}")
                continue
            # A server someone else runs: remote is what it runs under, real-world or not.
            endpoints.append(
                f"{entry.name} is an endpoint entry: driven through drive only, under remote, "
                "never in a fleet; not contacted"
            )
        elif entry.provenance == "real-world":
            refused.append(
                f"{entry.name} (real-world) will be refused: this version does not provide runsc"
            )
            continue
        why = entry.refusal_to_run(None)
        if why is not None:
            refused.append(f"{entry.name} will be refused: {why}")
            continue
        runnable += pairs
    parts = [f"{manifest.source} loads, {len(manifest.entries)} entries"]
    if runnable:
        parts.append(
            f"{len(runnable)} (entry, scenario) pair(s) whose scenario the file lists: "
            + ", ".join(runnable)
        )
    else:
        parts.append("no entry can run a scenario the file lists")
    parts += endpoints
    parts += refused
    if unlisted:
        parts.append(
            "no scenario the file lists, so not run under it: " + ", ".join(sorted(unlisted))
        )
    state = READY if runnable and not refused else NOT_READY
    return Item("manifest", state, "; ".join(parts))


def _isolation_item(loaded: Engagement) -> Item:
    lacking = [
        f"targets[{index}] ({target.host}) will be refused: it requires {target.isolation}, "
        "and this version does not provide runsc"
        if target.isolation == "runsc"
        else f"targets[{index}] ({target.host}) will be refused: it requires "
        f"{target.isolation}, which this version does not provide"
        for index, target in enumerate(loaded.targets)
        if target.isolation is not None and target.isolation not in PROVIDED
    ]
    if lacking:
        return Item("isolation", NOT_READY, "; ".join(lacking))
    floors = sorted({t.isolation for t in loaded.targets if t.isolation is not None})
    return Item(
        "isolation",
        READY,
        "no target requires an isolation this version lacks"
        + (f" (floors: {', '.join(floors)})" if floors else " (no target sets a floor)"),
    )


def _image_item(
    name: str, reference: str | None, option: str, image_id: Callable[[str], str]
) -> Item:
    if reference is None:
        return Item(name, NOT_CHECKED, f"no {option} given")
    try:
        found = image_id(reference)
    except docker.DockerError as exc:
        return Item(name, NOT_READY, f"{reference}: {exc}")
    return Item(name, READY, f"{reference} is present here as {found}")


def _endpoints_item(loaded: Engagement) -> Item:
    remote = [t.host for t in loaded.targets if t.name is not None and not is_local(t.name)]
    if not remote:
        return Item("endpoints", READY, "every target is on this machine; there is none to reach")
    return Item(
        "endpoints",
        NOT_CHECKED,
        ", ".join(remote) + ": not contacted; whether it answers is found out by the first run "
        "inside the window, and recorded there",
    )


def _destination(directory: Path, inside: Path) -> tuple[list[str], list[str]]:
    """``inspect_destination`` on a place: its refusals and its warnings, as words."""
    try:
        advisories = inspect_destination(directory, inside)
    except (OSError, RuntimeError) as exc:
        return [unusable(exc).message], []
    refusals = [a.message for a in advisories if a.severity is Severity.REFUSAL]
    warnings = [a.message for a in advisories if a.severity is not Severity.REFUSAL]
    return refusals, warnings


def _store_item(loaded: Engagement, path: str | Path | None) -> Item:
    if path is None:
        return Item("store", NOT_CHECKED, "no --store given")
    place = Path(path).expanduser()
    problems: list[str] = []
    try:
        directory = os.stat(place.parent)
    except OSError as exc:
        return Item("store", NOT_READY, f"its directory cannot be read: {exc.strerror or exc}")
    if not stat.S_ISDIR(directory.st_mode):
        return Item("store", NOT_READY, "its directory is not a directory")
    refusals, warnings = _destination(place.parent, place)
    problems += refusals
    try:
        found = os.lstat(place)
    except FileNotFoundError:
        found = None
    except OSError as exc:
        return Item("store", NOT_READY, f"cannot be read: {exc.strerror or exc}")
    if found is None:
        words = "not created yet; the first store ingest creates it, readable by its owner only"
    elif not stat.S_ISREG(found.st_mode):
        link = " (a symbolic link)" if stat.S_ISLNK(found.st_mode) else ""
        problems.append(f"it is not a regular file{link}")
        words = ""
    else:
        if found.st_uid != os.getuid():
            problems.append("it belongs to another user")
        if stat.S_IMODE(found.st_mode) != FILE_MODE:
            problems.append(f"it has mode {stat.S_IMODE(found.st_mode):04o}, not {FILE_MODE:04o}")
        words, problem = _store_holds(loaded, place)
        if problem:
            problems.append(problem)
    if problems:
        return Item("store", NOT_READY, "; ".join(problems))
    return Item("store", READY, "; ".join([words, *warnings]))


def _store_holds(loaded: Engagement, place: Path) -> tuple[str, str | None]:
    """What an existing store holds, read through SQLite's read-only mode: words, and a
    problem or None."""
    try:
        with Store.open_read_only(place) as store:
            held = store.engagement()
            runs = len(store.runs())
            fleets = len(store.fleets())
    except (StoreError, sqlite3.Error) as exc:
        return "", f"cannot be read as a store: {exc}"
    if held is None:
        if runs or fleets:
            return "", (
                f"holds {runs} run(s) and {fleets} fleet run(s) filed without an engagement; "
                "one store per engagement — give this one a new store"
            )
        return "an empty store", None
    if held["engagement_id_declared"] != loaded.id:
        return "", (
            f"holds another engagement, {held['engagement_id_declared']}; one store per engagement"
        )
    digests = [entry["digest"] for entry in held["chain"]]
    if loaded.digest in digests:
        return (
            f"holds this engagement (this file is version {digests.index(loaded.digest) + 1} "
            f"of {len(digests)}), {runs} run(s) filed",
            None,
        )
    if loaded.supersedes == held["engagement_digest"]:
        return (
            f"holds the version this file supersedes, {runs} run(s) filed; the first ingest "
            "under this file adds it to the chain",
            None,
        )
    return "", (
        f"holds {loaded.id} at a version this file neither is nor supersedes; a run under it "
        "would be refused at ingest"
    )


def _out_dir_item(path: str | Path | None) -> Item:
    if path is None:
        return Item("out-dir", NOT_CHECKED, "no --out-dir given")
    place = Path(path).expanduser()
    try:
        found = os.lstat(place)
    except FileNotFoundError:
        return Item(
            "out-dir",
            NOT_READY,
            f"does not exist; preflight creates nothing — create it empty, mode "
            f"{DIR_MODE:04o}, before the window opens",
        )
    except OSError as exc:
        return Item("out-dir", NOT_READY, f"cannot be read: {exc.strerror or exc}")
    if not stat.S_ISDIR(found.st_mode):
        return Item(
            "out-dir",
            NOT_READY,
            "it is a symbolic link, not a directory"
            if stat.S_ISLNK(found.st_mode)
            else "it is not a directory",
        )
    problems: list[str] = []
    if found.st_uid != os.getuid():
        problems.append("it belongs to another user")
    if stat.S_IMODE(found.st_mode) != DIR_MODE:
        problems.append(f"it has mode {stat.S_IMODE(found.st_mode):04o}, not {DIR_MODE:04o}")
    try:
        held = len(os.listdir(place))
    except OSError as exc:
        problems.append(f"it cannot be listed: {exc.strerror or exc}")
    else:
        if held:
            problems.append(
                f"it holds {held} entr{'ies' if held != 1 else 'y'}; an engagement's out-dir is "
                "its own and empty before the window opens"
            )
    # A run directory's name stands for the one a run would make: the git question is about it.
    refusals, warnings = _destination(place, place / "20000101T000000Z-00000000")
    problems += refusals
    if problems:
        return Item("out-dir", NOT_READY, "; ".join(problems))
    words = f"exists, empty, mode {DIR_MODE:04o}, not where recordings may be committed"
    return Item("out-dir", READY, "; ".join([words, *warnings]))


def _contacts_item(loaded: Engagement) -> Item:
    contacts = loaded.data.get("contacts") or []
    reachable = [
        index
        for index, contact in enumerate(contacts)
        if "reach" in contact and f"contacts[{index}].reach" not in loaded.placeholders
    ]
    if not reachable:
        return Item(
            "contacts",
            NOT_READY,
            f"{len(contacts)} listed, none with a reach: nobody can be reached during the window",
        )
    return Item("contacts", READY, f"{len(contacts)} listed, {len(reachable)} with a reach")


def _canaries_item(loaded: Engagement) -> Item:
    if loaded.version < FORMAT_VERSION_2:
        return Item("canaries", NOT_CHECKED, "version 1 declares no canaries")
    if not loaded.canaries:
        return Item("canaries", NOT_CHECKED, "none listed")
    # Open before the test is as it should be: said, not held against the file. Never the path.
    open_ones = [f"{c.id} ({c.kind})" for c in loaded.canaries if c.removed is None]
    words = f"{len(loaded.canaries)} listed, " + (
        f"{len(open_ones)} open, not yet confirmed removed: " + ", ".join(open_ones)
        if open_ones
        else "none open"
    )
    return Item("canaries", READY, words)


def _env_item(name: str, what: str, variable: str | None, environ: Mapping[str, str]) -> Item:
    """Whether the variable a file names is set and not empty: its name is said, its value never."""
    if variable is None:
        return Item(name, NOT_CHECKED, f"{what} still holds a placeholder")
    if not environ.get(variable):
        return Item(name, NOT_READY, f"{variable} is not set or is empty in this environment")
    return Item(name, READY, f"{variable} is set")


def _salt_item(loaded: Engagement, environ: Mapping[str, str]) -> Item:
    if loaded.version < FORMAT_VERSION_2:
        return Item("salt", NOT_CHECKED, "version 1 declares no salt_env")
    item = _env_item("salt", "salt_env", loaded.salt_env, environ)
    # The length is said as a bound, the value never.
    if (
        item.state == READY
        and loaded.salt_env is not None
        and len(environ[loaded.salt_env]) < MIN_SALT_LENGTH
    ):
        return Item(
            "salt", NOT_READY, f"{loaded.salt_env} holds fewer than {MIN_SALT_LENGTH} characters"
        )
    return item


def _receiver_key_item(loaded: Engagement, environ: Mapping[str, str]) -> Item:
    if loaded.version < FORMAT_VERSION_2:
        return Item("receiver key", NOT_CHECKED, "version 1 declares no receiver")
    if loaded.receiver is None:
        return Item("receiver key", NOT_CHECKED, "no receiver declared")
    if loaded.receiver.variant != "reachable":
        return Item("receiver key", NOT_CHECKED, "the receiver is local: it needs no key")
    return _env_item("receiver key", "receiver.key_env", loaded.receiver.key_env, environ)


def render_preflight(result: Preflight) -> str:
    """The preflight, one line per item, then whether everything looked at is ready."""
    width = max(len(item.name) for item in result.items)
    lines = [f"Preflight of {_safe(result.source)} (SHA-256 {result.digest}) at {result.now_utc}"]
    lines += [
        f"  {item.name.ljust(width)}  {item.state.ljust(11)}  {_safe(item.words)}"
        for item in result.items
    ]
    not_ready = [item.name for item in result.items if item.state == NOT_READY]
    lines.append(
        "Ready: every item is ready or was not checked."
        if result.ready
        else "Not ready: " + ", ".join(not_ready) + "."
    )
    return "\n".join(lines) + "\n"


# -- the report ---------------------------------------------------------------------------

#: The three kinds of sentence, each written as a fixed tag at the start of its line: what the
#: tool wrote down, what follows from that by a rule the sentence names, and what a person
#: entered in the triage table, with their name.
RECORDED = "recorded"
DERIVED = "derived"
ASSESSED = "assessed"
SENTENCE_KINDS = (RECORDED, DERIVED, ASSESSED)

#: The report's seven sections, in order. ``parse`` refuses a report whose sections are not
#: exactly these.
SECTION_TITLES = (
    "Engagement",
    "What was done",
    "Findings of reference and poison entries",
    "Real-world entries: candidates for responsible disclosure",
    "Comparison with the previous engagement",
    "Reproduction",
    "What this report does not say",
)

#: The report's first line, before the engagement's id as a code span.
TITLE = "# Report on engagement "

#: Words no generated document uses as a word of its own, in any sentence, not even to deny
#: one: whole words, compared without case, never stems — ``certificate`` is not ``certified``.
#: A value in a code span is data, not a word of the tool's (a tool may be called
#: ``secure_login``); what may stand in a code span the tool writes itself is
#: :data:`CODE_SPAN_IDENTIFIERS`. ``tests/test_banned_words.py`` holds every generated document
#: and the generators' own strings against this list.
BANNED_WORDS = (
    "safe",
    "secure",
    "security",
    "vulnerable",
    "vulnerability",
    "exploit",
    "risk",
    "clean",
    "compliant",
    "certified",
    "guaranteed",
)

#: The hints a finding :func:`store.compare_runs` sets as new or gone may carry
#: (``Compared.statement_hint``, ``Compared.cap_hint``), each shown as itself.
COMPARED_HINTS = ("statement_added", "statement_removed", "capped_before", "capped_after")

#: Why an opening stopped, as ``era_decided`` records it: each ``reason`` :mod:`eras` ends a
#: detection with (``tests/test_banned_words.py`` holds the two alike).
ERA_STOP_REASONS = (
    eras.CLOSED_ON_PROBE,
    eras.MODERN_REFUSED,
    eras.NO_COMMON_VERSION,
    eras.HANDSHAKE_CLOSED,
    eras.HANDSHAKE_UNANSWERED,
    eras.NO_RESULT,
    eras.HANDSHAKE_REFUSED,
    eras.MALFORMED_VERSION,
    eras.UNKNOWN_VERSION,
)


#: What a code span in a generated sentence may hold when the generator's source spells it out,
#: rather than filling it from data: a command or an option, a field, event or header name, a
#: state, kind or cause key, a file name, or a name in this tool's code. Never prose: a word in
#: a code span is not read as one of the tool's sentence words, so prose there would pass every
#: document check by being quoted. ``tests/test_banned_words.py`` reads the generators' source
#: and refuses a code span that is neither a placeholder nor one of these.
CODE_SPAN_IDENTIFIERS = frozenset(
    {
        # commands and options
        "engagement report",
        "kymograph evidence verify",
        "store",
        "--manifest",
        "--session",
        # fields, with a value where the sentence names one, events, headers, methods
        "actions.call: false",
        "filed: false",
        "window_exceeded: true",
        "min_interval_seconds",
        "pacing_enforced",
        "cap_hint",
        # the caveats of store.compare_runs
        "scenario_drift",
        "environment_moved",
        "findings_capped",
        "listing_capped",
        "server_unpinned",
        "certificate_changed",
        "runs_per_origin",
        "window.tz",
        "run_started",
        "run_finished",
        "script_finished",
        "step_called",
        "paced",
        "Authorization",
        "server/discover",
        # state, kind and provenance keys
        "evidence",
        "heuristic",
        "endpoint",
        "real-world",
        "remote",
        "host",
        "runc",
        "runsc",
        "http",
        "https",
        # files of a bundle
        "index.json",
        "redactions.json",
        "refusals.jsonl",
        # names in this tool's code
        "corpus.PROVENANCES",
        "engagement.record_refusal",
        "evidence.verify",
        "sandbox.policy.PROVIDED",
        "signals.KINDS",
        "store.compare_runs",
        "verdict.OBSERVED_ISOLATIONS",
    }
    # fixed vocabularies a sentence names one of: refusal reasons, kinds of personal data, run
    # states, the states evidence.verify gives a file, the hints of a compared finding
    | frozenset(REFUSAL_REASONS)
    | frozenset(PERSONAL_KINDS)
    | frozenset(verdict.STATES)
    | frozenset((evidence.INTACT, evidence.CHANGED, evidence.MISSING, evidence.UNLISTED))
    | frozenset(COMPARED_HINTS)
    | frozenset(ERA_STOP_REASONS)
)


#: Each caveat :func:`store.compare_runs` may set, in the report's words: the store's own
#: sentences set an identifier among their words, which a sentence of the report puts in a span.
CAVEAT_WORDS = {
    store_module.SCENARIO_DRIFT: "`scenario_drift`, the scenario's content differs between the "
    "two runs; this set may hold changes to the set of statements, not only to what was "
    "detected",
    store_module.ENVIRONMENT_MOVED: "`environment_moved`, only where the runs observed differs "
    "(isolation or image), and findings are not expected to depend on it; a difference here is "
    "not the server's",
    store_module.FINDINGS_CAPPED: "`findings_capped`, a run cut findings at the per-message "
    "cap; an entry with a `cap_hint` may be among those cut rather than gone or new",
    store_module.LISTING_CAPPED: "`listing_capped`, a run cut a listing at the driver's page "
    "limit; what lay past it was not looked at in that run",
    store_module.SERVER_UNPINNED: "`server_unpinned`, a side's version is the operator's "
    "declared word, not established from content; the deployment may have changed under the "
    "same URL and version, so what this set holds may be its doing, whichever axes moved",
    store_module.CERTIFICATE_CHANGED: "`certificate_changed`, the endpoint presented "
    "certificates in this run that share none with the other's; a rotated certificate is not a "
    "changed server, and neither a same nor a changed certificate says whether the deployment "
    "changed",
}


def _caveat_words(caveat: str) -> str:
    return CAVEAT_WORDS.get(caveat, "one this version of the report has no words for")


def _attribution_words(diff: Any) -> str:
    """To what a comparison's new or gone findings can be put down, in the report's words, from
    the store's ``attributable`` and ``axis`` and the axes that moved; the store's note, which
    names the entries, is not taken over."""
    attribution = diff.attribution
    if attribution.attributable and attribution.axis == "environment" and (diff.new or diff.gone):
        return (
            f"none, only the {_code(attribution.axis)} axis moved, and findings are not expected "
            "to depend on where they were observed: flagged, not put down to the server"
        )
    if attribution.attributable and attribution.axis is not None:
        return f"the {_code(attribution.axis)} axis, the only one that moved"
    if attribution.attributable:
        return "none needed"
    if not diff.moved:
        return "none, nothing recorded moved, yet the findings differ"
    return "none, more than one axis moved, so a new or gone finding cannot be put down to one"


def _file_states(verified: Any) -> str:
    """How many files of a bundle :func:`evidence.verify` found in each state, and how many
    problems it found, counted; what it says of them is not taken over."""
    counts = Counter(item.state for item in (*verified.files, *verified.unlisted))
    parts = [
        f"{counts[state]} {_code(state)}"
        for state in (evidence.INTACT, evidence.CHANGED, evidence.MISSING, evidence.UNLISTED)
        if counts[state]
    ]
    if verified.problems:
        count = len(verified.problems)
        parts.append(f"{count} problem{'s' if count != 1 else ''}")
    return ", ".join(parts) or "no files"


def reference_page(signal: str) -> str:
    """The path in a bundle of the reference page of ``signal``: ``reference/<id>.md`` under
    :data:`mcp_kymograph.evidence.REFERENCE_DIR`, where the bundle files it, the page about the
    pattern the signal stands for."""
    return f"{evidence.REFERENCE_DIR}/{signal}.md"


#: How much of a run id the report shows: enough for ``store`` commands, which take 8 or more.
SHORT_RUN = 12

#: What exit a report advises: every run it used complete and its recording read, or not.
EXIT_REPORT_COMPLETE = 0
EXIT_REPORT_INCOMPLETE = 3

#: Characters the report's own words never use outside a code span: each means something to
#: Markdown (emphasis, links, HTML, tables, escapes, headings, code). A line whose words hold
#: one was not written by :func:`render`, and :func:`parse` refuses it.
_MARKUP = frozenset("<>[]*_\\|`#")

_TAG = re.compile(r"\[(recorded|derived|assessed)\] (.+)")
_SECTION_LINE = re.compile(r"## ([1-9])\. (.+)")
_SUBHEADING = "### "


#: Unicode categories a rendered value shows by code point: the line and paragraph separators.
_SEPARATORS = frozenset({"Zl", "Zp"})


class ReportParseError(ValueError):
    """A report :func:`parse` cannot place, line by line: not one :func:`render` writes."""


def _code(value: object) -> str:
    """A value from the traffic, the store or a file as a Markdown code span, after the terminal
    filter: never read as Markdown, and unable to end its own span.

    The fence is one backtick longer than the longest run of backticks in the value (CommonMark
    6.1); a value that begins or ends with a backtick, or with a space at both ends, is padded
    with one space each side, which a reader strips again. The filter has removed every line
    break, so no value can start a line. An empty value has no code span and is said so. A
    value that is not a string is shown as JSON (``true``, ``null``, ``10``), as the file and
    the store hold it.
    """
    text = _safe(
        value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    )
    # A line or paragraph separator is no line break to CommonMark, but ``str.splitlines`` and
    # many renderers break on it: shown by its code point, never as itself.
    text = "".join(f"U+{ord(c):04X}" if unicodedata.category(c) in _SEPARATORS else c for c in text)
    if not text:
        return "(empty)"
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    padded = (
        text[0] == "`"
        or text[-1] == "`"
        or (text[0] == " " and text[-1] == " " and text.strip(" ") != "")
    )
    return f"{fence} {text} {fence}" if padded else f"{fence}{text}{fence}"


def _spans(text: str) -> tuple[list[str], str]:
    """The code spans of a line, their contents read back as :func:`_code` wrote them, and the
    line's own words with every span taken out. :class:`ValueError` for a span not closed."""
    values: list[str] = []
    words: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "`":
            words.append(text[index])
            index += 1
            continue
        end = index
        while end < len(text) and text[end] == "`":
            end += 1
        fence = end - index
        search = end
        while True:
            found = text.find("`" * fence, search)
            if found < 0:
                raise ValueError(f"a code span opened at column {index + 1} is not closed")
            stop = found
            while stop < len(text) and text[stop] == "`":
                stop += 1
            if stop - found == fence:
                break
            search = stop
        content = text[end:found]
        if len(content) >= 2 and content[0] == " " and content[-1] == " " and content.strip(" "):
            content = content[1:-1]
        values.append(content)
        words.append(" ")
        index = found + fence
    return values, "".join(words)


@dataclass(frozen=True, slots=True)
class Sentence:
    """One sentence: its kind and its text, values in code spans."""

    kind: str
    text: str

    @property
    def values(self) -> tuple[str, ...]:
        """Every value the sentence quotes, as it was shown."""
        return tuple(_spans(self.text)[0])

    @property
    def words(self) -> str:
        """The sentence's own words: its text with every quoted value taken out."""
        return _spans(self.text)[1]

    def line(self) -> str:
        return f"[{self.kind}] {self.text}"


@dataclass(frozen=True, slots=True)
class Heading:
    """A heading inside a section: an entry, a run, a paragraph of its own. Not a sentence."""

    text: str

    def line(self) -> str:
        return f"{_SUBHEADING}{self.text}"


@dataclass(frozen=True, slots=True)
class Section:
    number: int
    title: str
    items: tuple[Sentence | Heading, ...]

    @property
    def sentences(self) -> tuple[Sentence, ...]:
        return tuple(item for item in self.items if isinstance(item, Sentence))


@dataclass(frozen=True, slots=True)
class ParsedReport:
    """A report as :func:`parse` read it: the engagement's id and the seven sections."""

    engagement_id: str
    sections: tuple[Section, ...]

    @property
    def sentences(self) -> tuple[Sentence, ...]:
        return tuple(sentence for section in self.sections for sentence in section.sentences)


@dataclass(frozen=True, slots=True)
class Report:
    """The engagement's report, built from the store, the recordings and the refusals files.

    ``complete``: every run the report uses is complete and its recording was read with the
    bytes the store filed. The report is written either way; the exit says which
    (:attr:`exit_code`), as ``store diff`` does. The report's own SHA-256 is the caller's to
    compute, over the bytes it writes.
    """

    engagement_id: str
    engagement_digest: str
    generated_utc: str
    sections: tuple[Section, ...]
    complete: bool

    @property
    def exit_code(self) -> int:
        return EXIT_REPORT_COMPLETE if self.complete else EXIT_REPORT_INCOMPLETE

    def parsed(self) -> ParsedReport:
        """What :func:`parse` reads back from :func:`render` of this report."""
        return ParsedReport(_safe(self.engagement_id), self.sections)


def render(report: Report) -> str:
    """The report as Markdown: a title, the seven sections, one item per paragraph."""
    lines = [TITLE + _code(report.engagement_id), ""]
    for section in report.sections:
        lines += [f"## {section.number}. {section.title}", ""]
        for item in section.items:
            lines += [item.line(), ""]
    return "\n".join(lines)


def parse(text: str) -> ParsedReport:
    """Read a report back into its sections and sentences, or refuse it with
    :class:`ReportParseError` naming the line.

    Every line is placed or the report is refused: the title, a section heading in its order
    and with its title, a heading inside a section, a sentence with exactly one tag. Items are
    separated by one empty line, as :func:`render` writes them, so no line can run on into the
    one before it. Every code span must close, and the words outside the spans must hold none
    of :data:`_MARKUP`: a value cannot fake a tag, a heading, a link or HTML, because it is
    never outside a span and never at the start of a line.
    """
    if not text.endswith("\n"):
        raise ReportParseError("the report does not end with a line break")
    lines = text[:-1].split("\n")
    engagement_id = _parse_title(lines[0], TITLE)
    sections: list[Section] = []
    current: tuple[int, str, list[Sentence | Heading]] | None = None
    for number, line in enumerate(lines[1:], start=2):
        if (number % 2 == 0) != (line == ""):
            raise ReportParseError(f"line {number}: items are separated by exactly one empty line")
        if not line:
            continue
        heading = _SECTION_LINE.fullmatch(line)
        if heading is not None:
            expected = len(sections) + (1 if current is None else 2)
            if expected > len(SECTION_TITLES):
                raise ReportParseError(
                    f"line {number}: a report has {len(SECTION_TITLES)} sections"
                )
            title = SECTION_TITLES[expected - 1]
            if int(heading.group(1)) != expected or heading.group(2) != title:
                raise ReportParseError(f"line {number}: expected section {expected}, {title!r}")
            if current is not None:
                sections.append(Section(current[0], current[1], tuple(current[2])))
            current = (expected, heading.group(2), [])
            continue
        if current is None:
            raise ReportParseError(f"line {number}: outside any section")
        current[2].append(_parse_item(line, number, SENTENCE_KINDS))
    if current is not None:
        sections.append(Section(current[0], current[1], tuple(current[2])))
    if len(sections) != len(SECTION_TITLES):
        raise ReportParseError(
            f"the report has {len(sections)} sections, not {len(SECTION_TITLES)}"
        )
    return ParsedReport(engagement_id, tuple(sections))


def _parse_title(line: str, title: str) -> str:
    """The engagement's id from a title line, or :class:`ReportParseError`."""
    if not line.startswith(title):
        raise ReportParseError(f"line 1 is not the title {title.strip()!r}")
    try:
        values, words = _spans(line[len(title) :])
    except ValueError as exc:
        raise ReportParseError(f"line 1: {exc}") from None
    if len(values) != 1 or words.strip():
        raise ReportParseError("line 1: the title names the engagement's id, and nothing else")
    return values[0]


def _parse_item(line: str, number: int, kinds: tuple[str, ...]) -> Sentence | Heading:
    """One heading or one sentence of one of ``kinds``, its spans closed and no Markdown in its
    own words; :class:`ReportParseError` naming the line otherwise."""
    if line.startswith(_SUBHEADING):
        item: Sentence | Heading = Heading(line[len(_SUBHEADING) :])
    else:
        tagged = _TAG.fullmatch(line)
        if tagged is None or tagged.group(1) not in kinds:
            raise ReportParseError(
                f"line {number}: neither a heading nor a sentence with one of the tags "
                + ", ".join(f"[{kind}]" for kind in kinds)
            )
        item = Sentence(tagged.group(1), tagged.group(2))
    try:
        _, words = _spans(item.text)
    except ValueError as exc:
        raise ReportParseError(f"line {number}: {exc}") from None
    markup = sorted(set(words) & _MARKUP)
    if markup:
        raise ReportParseError(
            f"line {number}: {''.join(markup)!r} outside a code span: not a line this tool writes"
        )
    return item


# -- gathering ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Recording:
    """A run's recording as found under ``--runs``: ``read`` with what the report takes from
    it, or why not (``not_found``, ``changed``, ``unreadable``)."""

    state: str
    why: str = ""
    started: dict[str, Any] | None = None
    window_exceeded: bool | None = None
    #: How many ``step_called`` events the recording holds: tool calls the script made.
    calls: int = 0
    #: The endpoint's scheme as ``run_started.endpoint.scheme`` records it (``http``,
    #: ``https``), None for a run without an endpoint; and the TLS versions the run spoke, as
    #: ``run_finished.http.tls.versions`` records them, None where it records none.
    scheme: str | None = None
    tls_versions: tuple[str, ...] | None = None
    #: How the run's opening settled the server's generation, from its ``era_decided`` event (the
    #: last one), or None where the recording holds none: ``era``, ``version``, ``outcome``,
    #: ``reason`` (of a stop), the error ``code`` that came with a stop, the generation the
    #: engagement file ``declared`` for the endpoint and whether it ``differs``.
    decided: dict[str, Any] | None = None
    #: ``run_started.auth``: whom the run spoke as and where its token came from, or None.
    auth: dict[str, Any] | None = None
    #: ``run_finished.replacements``: how many values of each kind were replaced by a pseudonym,
    #: or None where the recording holds none (a run before the field, or one never finished).
    replacements: dict[str, int] | None = None
    #: ``run_started.pacing_enforced`` and ``run_started.pacing`` as recorded (None where the
    #: recording has no such field), and the run's ``paced`` events, in order.
    pacing_enforced: bool | None = None
    pacing: dict[str, Any] | None = None
    paced: tuple[dict[str, Any], ...] = ()
    #: How many tool names the recording's ``script_finished`` events list under ``called``
    #: (schema 5); one for each such event whose ``called`` is there but not a list, since
    #: what it holds cannot be counted. Nothing for an event without the field.
    script_called: int = 0
    #: Beside ``why``, the tool's own words: what the system said when the recording could not
    #: be read (an operating system's reason, a JSON reader's message), or None. A value, not a
    #: sentence of the tool's: a report shows it in a code span.
    detail: str | None = None


def _script_called(typed: list[dict[str, Any]]) -> int:
    """What :attr:`_Recording.script_called` counts, over a recording's events."""
    count = 0
    for event in typed:
        if event.get("type") != "script_finished" or "called" not in event:
            continue
        called = event["called"]
        count += len(called) if isinstance(called, list) else 1
    return count


@dataclass
class _Finding:
    """One finding identity across the engagement's runs: its latest key, and where seen."""

    identity: tuple
    key: dict[str, Any]
    provenance: str
    sightings: list[tuple[Any, int]] = field(default_factory=list)

    @property
    def real_world(self) -> bool:
        return self.provenance == "real-world"


def _pacing_fields(started: dict[str, Any], typed: list[dict[str, Any]]) -> dict[str, Any]:
    """What the report takes of a recording's pacing: ``pacing_enforced`` (True or False, else
    None), ``pacing`` (an object, else None) and the ``paced`` events."""
    enforced = started.get("pacing_enforced")
    held_to = started.get("pacing")
    return {
        "pacing_enforced": enforced if enforced in (True, False) else None,
        "pacing": held_to if isinstance(held_to, dict) else None,
        "paced": tuple(event for event in typed if event.get("type") == "paced"),
    }


def _read_recordings(store: Store, runs: list, runs_dir: Path) -> dict[str, _Recording]:
    """Each filed run's recording, found under ``runs_dir`` only, as the web interface and the
    evidence bundle find it, and held against the digest the store filed it under."""
    found = search(runs_dir)
    filed = store.recordings()
    result: dict[str, _Recording] = {}
    for run in runs:
        hit = resolve_filed(found, filed.get(run.run, ""))
        if hit is None:
            result[run.run] = _Recording("not_found", "not found under the runs directory")
            continue
        try:
            raw = read_bytes(hit[1])
        except OSError as exc:
            result[run.run] = _Recording(
                "unreadable", "it cannot be read", detail=exc.strerror or str(exc)
            )
            continue
        if hashlib.sha256(raw).hexdigest() != run.run:
            result[run.run] = _Recording(
                "changed", "its bytes are not the ones the store filed under this run"
            )
            continue
        try:
            events = [json.loads(line) for line in raw.split(b"\n") if line.strip()]
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            result[run.run] = _Recording("unreadable", "a line is not JSON", detail=str(exc))
            continue
        started = events[0] if events else None
        if not isinstance(started, dict) or started.get("type") != "run_started":
            result[run.run] = _Recording("unreadable", "it does not begin with `run_started`")
            continue
        typed = [event for event in events if isinstance(event, dict)]
        finished = next((e for e in reversed(typed) if e.get("type") == "run_finished"), None)
        exceeded = None if finished is None else finished.get("window_exceeded")
        endpoint = started.get("endpoint")
        scheme = endpoint.get("scheme") if isinstance(endpoint, dict) else None
        http = None if finished is None else finished.get("http")
        tls = http.get("tls") if isinstance(http, dict) else None
        versions = tls.get("versions") if isinstance(tls, dict) else None
        decided = next((e for e in reversed(typed) if e.get("type") == "era_decided"), None)
        auth = started.get("auth")
        counted = None if finished is None else finished.get("replacements")
        result[run.run] = _Recording(
            "read",
            started=started,
            decided=decided,
            auth=auth if isinstance(auth, dict) else None,
            **_pacing_fields(started, typed),
            replacements=(
                {kind: counted[kind] for kind in PERSONAL_KINDS}
                if isinstance(counted, dict)
                and all(type(counted.get(kind)) is int for kind in PERSONAL_KINDS)
                else None
            ),
            window_exceeded=exceeded if exceeded in (True, False) else None,
            calls=sum(1 for event in typed if event.get("type") == "step_called"),
            script_called=_script_called(typed),
            scheme=scheme if isinstance(scheme, str) else None,
            tls_versions=(
                tuple(versions)
                if isinstance(versions, list) and all(isinstance(v, str) for v in versions)
                else None
            ),
        )
    return result


def _gather_findings(store: Store, runs: list) -> list[_Finding]:
    by_identity: dict[tuple, _Finding] = {}
    for run in runs:
        for identity, (key, seen) in store.findings_of(run.run).items():
            finding = by_identity.get(identity)
            if finding is None:
                finding = by_identity[identity] = _Finding(identity, key, run.provenance)
            finding.key = key
            finding.sightings.append((run, len(seen)))
    return sorted(by_identity.values(), key=lambda f: json.dumps(f.identity))


def _identity_of(row: dict[str, Any]) -> tuple | None:
    identity = row.get("identity")
    if not isinstance(identity, dict):
        return None
    return tuple(identity.get(name) for name in IDENTITY_FIELDS)


def _triage(store: Any) -> list[dict[str, Any]]:
    """The store's current triage rows: the latest of each identity and role."""
    return list(store.triage_current())


#: Every line about a real-world entry's finding begins with this, in whichever section it
#: stands: such a finding is a candidate for responsible disclosure, never a confirmed weakness,
#: and is never read beside the reference and poison findings as one of them (README).
CANDIDATE = "Candidate for responsible disclosure"


def _mark(text: str, real_world: bool) -> str:
    """A sentence about a real-world entry's finding, marked as a candidate; others unchanged."""
    if not real_world:
        return text
    return f"{CANDIDATE} (section 4): {text[:1].lower()}{text[1:]}"


#: The status's lines, by how each begins, and their kinds in the report: counts of what the
#: store and the refusals files hold are recorded; where ``now`` stands against the window and
#: what is still planned follow by a rule (the window's times; a pair without a complete run).
_STATUS_DERIVED = ("Window", "Still planned", "Entries are not named")


# -- the coverage statement ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Coverage:
    """The recorded facts the coverage statement is made from, each from where the report and the
    attestation read it alike.

    ``calls_declared_false``: every version of the store's chain declares ``actions.call``
    false. ``recordings_read`` and ``recordings_unread``: the store's runs whose recording was
    read under the runs directory with the bytes filed, and those whose was not.
    ``step_called``: the ``step_called`` events in the recordings read; ``script_called``: the
    tool names their ``script_finished`` events list as called (:attr:`_Recording.script_called`).
    ``isolations``: the store's runs by isolation, as filed. ``sessions``: the recordings in the
    bundle's index that are not the store's runs (``filed: false``) — a client session, or any
    other recording given beside the runs — or None where the document has no bundle to read it
    from: the report, which takes no ``--session``.
    """

    calls_declared_false: bool
    recordings_read: int
    recordings_unread: int
    step_called: int
    script_called: int
    isolations: Mapping[str, int]
    sessions: int | None


def coverage_facts(
    chain: list[dict[str, Any]],
    runs: list,
    recordings: Mapping[str, _Recording],
    sessions: int | None,
) -> Coverage:
    """The :class:`Coverage` of a store's ``chain`` and ``runs``, with each run's recording as
    :func:`_read_recordings` found it, and ``sessions`` as the caller counted them (or None)."""
    read = [recordings[run.run] for run in runs if recordings[run.run].state == "read"]
    declared = [(entry["file_declared"].get("actions") or {}).get("call") for entry in chain]
    return Coverage(
        calls_declared_false=bool(declared) and all(call is False for call in declared),
        recordings_read=len(read),
        recordings_unread=len(runs) - len(read),
        step_called=sum(recording.calls for recording in read),
        script_called=sum(recording.script_called for recording in read),
        isolations=dict(sorted(Counter(run.isolation for run in runs).items())),
        sessions=sessions,
    )


def coverage(facts: Coverage) -> list[Sentence]:
    """The coverage statement: what this engagement did not do and did not observe, one
    ``derived`` sentence per clause, each present only when the recorded fact it names holds,
    and last the README's rule on what an observation is. The same clauses open the report's
    section 7 and stand in the attestation; where the two read a fact from different places
    (a client session), each names its own. Where the bundle lists recordings beside the store's
    runs, the attestation does not read them, and says so in place of the client clause rather
    than leaving the question out."""
    sentences: list[Sentence] = []
    if (
        facts.calls_declared_false
        and facts.recordings_read
        and not facts.recordings_unread
        and not facts.step_called
        and not facts.script_called
    ):
        read = facts.recordings_read
        sentences.append(
            Sentence(
                DERIVED,
                "This engagement's runs called no tool: every version of its file declares "
                f"{_code('actions.call: false')}, none of the {read} recording"
                f"{'s' if read != 1 else ''} read holds a {_code('step_called')} event, and no "
                f"{_code('script_finished')} among them names a tool as called.",
            )
        )
    if facts.sessions is None:
        sentences.append(
            Sentence(
                DERIVED,
                "This engagement's report does not show how a client reacts to the text the "
                "server hands it: it is built from the store's runs alone, each driven by this "
                "tool in the client's place, and holds no recording of a client session "
                f"({_code('engagement report')} takes no {_code('--session')}).",
            )
        )
    elif facts.sessions == 0:
        sentences.append(
            Sentence(
                DERIVED,
                "This engagement did not observe how a client reacts to the text the server "
                "hands it: the bundle's index lists no recording of a client session (none with "
                f"{_code('filed: false')}), only the store's runs, each driven by this tool in "
                "the client's place.",
            )
        )
    else:
        count = facts.sessions
        sentences.append(
            Sentence(
                DERIVED,
                f"This engagement's bundle lists {count} recording{'s' if count != 1 else ''} "
                f"beside the store's runs ({_code('filed: false')}): this attestation does not "
                "read such recordings, so whether a client's response to the server's text was "
                "observed is not said here.",
            )
        )
    unobserved = {
        isolation: count
        for isolation, count in facts.isolations.items()
        if isolation not in verdict.OBSERVED_ISOLATIONS
    }
    if unobserved:
        sentences.append(
            Sentence(
                DERIVED,
                "This engagement did not observe egress in "
                + " and ".join(
                    f"{count} run{'s' if count != 1 else ''} with isolation {_code(isolation)}"
                    for isolation, count in unobserved.items()
                )
                + f": only an isolation in {_code('verdict.OBSERVED_ISOLATIONS')}, "
                f"{_code(', '.join(verdict.OBSERVED_ISOLATIONS))}, records where a server "
                "connects to, and for these runs nothing about it was observed, in either "
                "direction.",
            )
        )
    remote = facts.isolations.get(REMOTE, 0)
    if remote:
        total = sum(facts.isolations.values())
        sentences.append(
            Sentence(
                DERIVED,
                f"This engagement did not run the server in {remote} of its {total} run"
                f"{'s' if total != 1 else ''}: isolation {_code('remote')} is an endpoint this "
                "tool reaches over the network and does not start, so what the server does on "
                "its own machine is in no recording.",
            )
        )
    sentences.append(
        Sentence(
            DERIVED,
            "This engagement's observations say where something sat and what shape it had, not "
            "whether it has an effect: that depends on what the consuming side does with the "
            "text, which is not visible on the wire (the README's rule).",
        )
    )
    return sentences


# -- building -----------------------------------------------------------------------------


def build(
    *,
    engagement_path: str | Path,
    store: Store | str | Path,
    runs_dir: str | Path,
    out_dir: str | Path | None = None,
    previous: str | Path | None = None,
    manifest: Manifest | str | Path | None = None,
    now: datetime,
) -> Report:
    """Build the engagement's report from what was recorded, nothing else.

    ``engagement_path`` is the operator's original file: its digest must be a version in the
    store's chain (:class:`ReportError` otherwise), and only the number of its literal
    redaction patterns is taken from it, never a pattern. ``store`` is a store (opened by the
    caller, read-only) or its path, opened here read-only. ``runs_dir`` is where the recordings
    are found, by the rule the evidence bundle uses — a directory, or :class:`ReportError`;
    ``out_dir`` where the refusals files are; ``previous`` an earlier engagement's bundle,
    verified before anything of it is read; ``manifest`` what section 2's status reads its
    still-planned pairs against, as ``engagement status --manifest`` does.

    Raises :class:`~mcp_kymograph.engagement.EngagementError` for a file the reader refuses or
    an out-dir that is not a directory, :class:`ReportError` for a store without an engagement,
    a file not of its chain or a runs directory that is not one,
    :class:`~mcp_kymograph.corpus.ManifestError` for a manifest that cannot be read, and
    :class:`~mcp_kymograph.store.StoreError` for a store that cannot be read. A recording that
    cannot be found or read, or a previous bundle that is not intact, is said in the report,
    never raised.
    """
    moment = _aware(now)
    loaded = load_engagement(engagement_path)
    runs_path = Path(runs_dir)
    try:
        is_directory = stat.S_ISDIR(os.stat(runs_path).st_mode)
    except OSError as exc:
        raise ReportError(f"{runs_path}: cannot read: {exc.strerror or exc}") from None
    if not is_directory:
        raise ReportError(
            f"{runs_path}: not a directory; the recordings are looked for under a directory"
        )
    if manifest is not None and not isinstance(manifest, Manifest):
        manifest = load_manifest(manifest)
    options = (runs_path, out_dir, previous, manifest, moment)
    if isinstance(store, (str, Path)):
        with Store.open_read_only(store) as opened:
            return _Builder(loaded, opened, *options).build()
    return _Builder(loaded, store, *options).build()


class _Builder:
    def __init__(
        self,
        loaded: Engagement,
        store: Store,
        runs_dir: Path,
        out_dir: str | Path | None,
        previous: str | Path | None,
        manifest: Manifest | None,
        now: datetime,
    ) -> None:
        self.loaded = loaded
        self.store = store
        self.runs_dir = runs_dir
        self.out_dir = None if out_dir is None else Path(out_dir)
        self.previous = None if previous is None else Path(previous)
        self.manifest = manifest
        self.now = now
        held = store.engagement()
        if held is None:
            raise ReportError(
                "the store holds no engagement: a report is of one engagement's store"
            )
        self.held = held
        self.digests = [entry["digest"] for entry in held["chain"]]
        if loaded.digest not in self.digests:
            raise ReportError(
                f"{loaded.source}: its SHA-256 {loaded.digest} is not a version of the store's "
                f"engagement {held['engagement_id_declared']}; the report reads the redaction "
                "patterns' number from the operator's own file, which must be one of its versions"
            )
        self.current = held["chain"][-1]["file_declared"]
        self.runs = store.runs()
        self.recordings = _read_recordings(store, self.runs, runs_dir)
        self.findings = _gather_findings(store, self.runs)
        self.wild = {f.identity for f in self.findings if f.real_world}
        self.triage = _triage(store)
        self.rows: dict[tuple, list[dict[str, Any]]] = {}
        for row in self.triage:
            identity = _identity_of(row)
            if identity is not None:
                self.rows.setdefault(identity, []).append(row)

    # -- how runs are named

    def ref(self, run: Any) -> str:
        """A run by its short id, and — wherever it is named — whether it is not complete."""
        text = f"run {_code(run.run[:SHORT_RUN])}"
        if not run.complete:
            text += f" (not complete: {_code(run.state)})"
        return text

    def build(self) -> Report:
        sections = [
            self.engagement_section(),
            self.done_section(),
            self.findings_section(3, real_world=False),
            self.findings_section(4, real_world=True),
            self.comparison_section(),
            self.reproduction_section(),
            self.limits_section(),
        ]
        assessed = sum(1 for section in sections for s in section.sentences if s.kind == ASSESSED)
        if not assessed:
            three = sections[2]
            sections[2] = Section(
                three.number,
                three.title,
                (
                    Sentence(
                        DERIVED,
                        "This report has no assessed sentences, counted over all its sections: "
                        "the triage table holds no row for any finding in it, and no previous "
                        "bundle's row was shown.",
                    ),
                    *three.items,
                ),
            )
        complete = all(run.complete for run in self.runs) and all(
            recording.state == "read" for recording in self.recordings.values()
        )
        return Report(
            engagement_id=self.held["engagement_id_declared"],
            engagement_digest=self.held["engagement_digest"],
            generated_utc=utc_text(self.now),
            sections=tuple(sections),
            complete=complete,
        )

    # -- 1

    def engagement_section(self) -> Section:
        items: list[Sentence | Heading] = []
        chain = self.held["chain"]
        version = self.digests.index(self.loaded.digest) + 1
        items.append(
            Sentence(
                RECORDED,
                f"Engagement {_code(self.held['engagement_id_declared'])}: the store holds "
                f"{len(chain)} version{'s' if len(chain) != 1 else ''} of its file; the current "
                f"one has SHA-256 {_code(self.held['engagement_digest'])}, and the operator's "
                f"file {_code(Path(self.loaded.source).name)} given to this report is version "
                f"{version}.",
            )
        )
        given = ["the store", "the recordings found under the runs directory"]
        if self.out_dir is not None:
            given.append("the refusals files under the out-dir")
        if self.previous is not None:
            given.append(f"the previous bundle {_code(self.previous.name)}")
        if self.manifest is not None:
            given.append(f"the manifest {_code(Path(self.manifest.source).name)}")
        items.append(
            Sentence(
                RECORDED,
                f"This report was generated at {_code(utc_text(self.now))} from "
                + ", ".join(given)
                + ".",
            )
        )
        items.append(Heading("Versions of the file"))
        for number, entry in enumerate(chain, start=1):
            declared = entry["file_declared"]
            window = declared.get("window") or {}
            actions = declared.get("actions") or {}
            items.append(
                Sentence(
                    RECORDED,
                    f"Version {number}: SHA-256 {_code(entry['digest'])}, set in the store at "
                    f"{_code(entry['set_utc'])}, "
                    + (
                        f"superseding {_code(entry['supersedes'])}"
                        if entry["supersedes"]
                        else "superseding no earlier version"
                    )
                    + f"; window {_code(window.get('from'))} to {_code(window.get('until'))}"
                    + f"; actions list {_code(actions.get('list'))}, call "
                    f"{_code(actions.get('call'))}.",
                )
            )
            if number > 1:
                changes = _changes(chain[number - 2]["file_declared"], declared)
                items.append(
                    Sentence(
                        DERIVED,
                        f"Between version {number - 1} and version {number}, compared key by "
                        "key: "
                        + (
                            "; ".join(changes)
                            if changes
                            else "no change in targets, window, scenarios or actions"
                        )
                        + ".",
                    )
                )
        items.append(Heading(f"As declared in the current version, version {len(chain)}"))
        for target in self.current.get("targets") or []:
            items.append(Sentence(RECORDED, _target_words(target)))
        for listed in self.current.get("scenarios") or []:
            items.append(
                Sentence(
                    RECORDED,
                    f"Scenario listed: {_code(listed.get('path'))} at SHA-256 "
                    f"{_code(listed.get('sha256'))}.",
                )
            )
        count = len(self.loaded.mask_patterns)
        items.append(
            Sentence(
                RECORDED,
                f"The engagement defines {count} literal redaction pattern"
                f"{'s' if count != 1 else ''}, counted in the operator's file, version "
                f"{version}; what they are is not shown here.",
            )
        )
        pacing = self.current.get("pacing") or {}
        if pacing:
            items.append(
                Sentence(
                    RECORDED,
                    "Pacing declared: "
                    + ", ".join(f"{_code(key)} {_code(value)}" for key, value in pacing.items())
                    + ".",
                )
            )
            items.append(
                Sentence(
                    DERIVED,
                    "Pacing is declared. Whether a run kept it is in its own "
                    f"{_code('run_started')} ({_code('pacing_enforced')}): an HTTP run to a host "
                    "that is not a loopback literal keeps it, any other run does not.",
                )
            )
        else:
            items.append(Sentence(RECORDED, "No pacing is declared."))
            items.append(
                Sentence(
                    DERIVED,
                    "With no pacing declared, an HTTP run to a host that is not a loopback "
                    f"literal keeps the defaults: {_code('runs_per_origin')} "
                    f"{_code(DEFAULT_RUNS_PER_ORIGIN)} and {_code('min_interval_seconds')} "
                    f"{_code(DEFAULT_MIN_INTERVAL_SECONDS)}.",
                )
            )
        items.append(Heading("The gate's record"))
        items += self.refusal_sentences()
        items.append(
            Sentence(
                DERIVED,
                "Refusals made before the engagement file was read are not recorded: "
                f"{_code('engagement.record_refusal')} writes a refusal under the file it was "
                "refused against, and before the file is read there is none.",
            )
        )
        return Section(1, SECTION_TITLES[0], tuple(items))

    def refusal_sentences(self) -> list[Sentence]:
        if self.out_dir is None:
            return [Sentence(RECORDED, "The refusals were not read: no out-dir was given.")]
        found = find_refusals(self.out_dir)
        if not found:
            return [Sentence(RECORDED, f"No {_code(REFUSALS_FILE)} was found under the out-dir.")]
        windows = _windows(self.held["chain"])
        sentences: list[Sentence] = []
        for item in found:
            counted = _count_refusals(item, self.out_dir, windows)
            where = _code(counted.path)
            if counted.unreadable is not None:
                sentences.append(
                    Sentence(
                        RECORDED,
                        f"The refusals file {where} could not be read "
                        f"({_unread_words(counted, _code)}): its refusals are not counted here.",
                    )
                )
                continue
            for record in item.records:
                if record.engagement_digest in windows:
                    version = self.digests.index(record.engagement_digest) + 1
                    # The reader takes only a reason of REFUSAL_REASONS; the span shows the word
                    # of that list, so what stands in it is the list's, not the file's.
                    reason = next(
                        (known for known in REFUSAL_REASONS if known == record.reason), None
                    )
                    sentences.append(
                        Sentence(
                            RECORDED,
                            f"Refused at {_code(record.refused_utc)} under version {version} of "
                            "the file: "
                            + (
                                f"reason {_code(reason)}"
                                if reason
                                else "a reason this version does not know"
                            )
                            + f", exit {record.exit_code} ({where}).",
                        )
                    )
            if counted.outside_window:
                sentences.append(
                    Sentence(
                        DERIVED,
                        f"{counted.outside_window} of the refusals in {where} lie outside the "
                        "window of the version of the file they name, compared with its times.",
                    )
                )
            if counted.other_engagement:
                sentences.append(
                    Sentence(
                        DERIVED,
                        f"{counted.other_engagement} refusal"
                        f"{'s' if counted.other_engagement != 1 else ''} in {where} name a "
                        "file digest that is not in this store's chain, and are not listed here.",
                    )
                )
            if counted.near_cap:
                sentences.append(
                    Sentence(
                        DERIVED,
                        f"The refusals log {where} has {_room_words(counted.room_bytes)}",
                    )
                )
        return sentences

    # -- 2

    def done_section(self) -> Section:
        counted = status(self.store, manifest=self.manifest, out_dir=self.out_dir, now=self.now)
        items: list[Sentence | Heading] = [
            Sentence(DERIVED if line.startswith(_STATUS_DERIVED) else RECORDED, line)
            for line in status_lines(counted, _code)
        ]
        items.append(Heading("Entries and scenarios"))
        latest: dict[str, Any] = {}
        for run in self.runs:
            latest[run.server] = run
        for name, run in sorted(latest.items()):
            items.append(
                Sentence(
                    RECORDED,
                    f"Entry {_code(name)}: provenance {_code(run.provenance)}, version "
                    f"{_code(run.server_version)} ({_code(run.server_version_kind)}, identity "
                    f"kind {_code(run.server_identity_kind)}).",
                )
            )
        scenarios: dict[tuple[str, str], list[Any]] = {}
        for run in self.runs:
            scenarios.setdefault((run.scenario, run.scenario_digest), []).append(run)
        for (name, digest), runs in sorted(scenarios.items()):
            done = sum(1 for run in runs if run.complete)
            items.append(
                Sentence(
                    RECORDED,
                    f"Scenario {_code(name)} at SHA-256 {_code(digest)}: {len(runs)} run"
                    f"{'s' if len(runs) != 1 else ''}, {done} of them complete.",
                )
            )
        items.append(Heading("Runs, by state, with the environment each observed in"))
        if not self.runs:
            items.append(Sentence(RECORDED, "The store holds no run."))
        for run in self.runs:
            causes = (
                ", causes " + ", ".join(_code(cause) for cause in run.causes) if run.causes else ""
            )
            items.append(
                Sentence(
                    RECORDED,
                    f"{_upper(self.ref(run))} of entry {_code(run.server)}, scenario "
                    f"{_code(run.scenario)}: state {_code(run.state)}{causes}; isolation "
                    f"{_code(run.isolation)}, sandbox image "
                    f"{_code(run.sandbox_image) if run.sandbox_image else 'none'}, target "
                    f"image {_code(run.target_image) if run.target_image else 'none'}.",
                )
            )
            if not run.egress_observed:
                items.append(Sentence(DERIVED, _egress_words(f"for {self.ref(run)}", run)))
            if run.server_version_kind == "declared":
                items.append(
                    Sentence(
                        DERIVED,
                        f"Server unpinned for {self.ref(run)}: its version "
                        f"{_code(run.server_version)} is the operator's declared word, not "
                        "established from content (identity kind "
                        f"{_code(run.server_identity_kind)}).",
                    )
                )
            recording = self.recordings[run.run]
            tls = _tls_words(self.ref(run), run, recording)
            if tls is not None:
                items.append(Sentence(RECORDED, tls))
            for kind, words in _generation_words(self.ref(run), recording):
                items.append(Sentence(kind, words))
            token = _token_words(self.ref(run), recording)
            if token is not None:
                items.append(Sentence(RECORDED, token))
            for words in _pacing_words(self.ref(run), recording):
                items.append(Sentence(RECORDED, words))
            if recording.replacements is not None:
                counts = ", ".join(
                    f"{recording.replacements[kind]} {_code(kind)}" for kind in PERSONAL_KINDS
                )
                items.append(
                    Sentence(
                        RECORDED,
                        f"{_upper(self.ref(run))} replaced personal data by pseudonyms: {counts}.",
                    )
                )
            if recording.state != "read":
                items.append(
                    Sentence(
                        DERIVED,
                        f"The recording of {self.ref(run)} was not read "
                        f"({recording.why}"
                        + (f": {_code(recording.detail)}" if recording.detail else "")
                        + ", looked for under the runs directory as the evidence bundle looks): "
                        "what only the recording holds — whether the window was exceeded, the "
                        "tool calls made, the reproduction triple as recorded — is not in this "
                        "report for it.",
                    )
                )
        items.append(Heading("What was not done"))
        items += self.not_done()
        return Section(2, SECTION_TITLES[1], tuple(items))

    def not_done(self) -> list[Sentence]:
        sentences: list[Sentence] = []
        read = [run for run in self.runs if self.recordings[run.run].state == "read"]
        calling = [run for run in read if self.recordings[run.run].calls]
        if read and not calling:
            sentences.append(
                Sentence(
                    RECORDED,
                    f"No tool call is recorded: none of the {len(read)} recording"
                    f"{'s' if len(read) != 1 else ''} read holds a {_code('step_called')} "
                    "event.",
                )
            )
        for run in calling:
            calls = self.recordings[run.run].calls
            sentences.append(
                Sentence(
                    RECORDED,
                    f"{_upper(self.ref(run))} records {calls} tool call{'s' if calls != 1 else ''}"
                    f" ({_code('step_called')} events).",
                )
            )
        unread = len(self.runs) - len(read)
        if unread:
            sentences.append(
                Sentence(
                    DERIVED,
                    f"{unread} recording{'s were' if unread != 1 else ' was'} not read, so "
                    "whether a tool was called in "
                    + ("them" if unread != 1 else "it")
                    + " is not said here.",
                )
            )
        for fleet in self.store.fleets():
            for result in fleet["results"].values():
                if result["state"] in FLEET_ONLY_STATES:
                    sentences.append(
                        Sentence(
                            RECORDED,
                            f"Fleet {_code(fleet['fleet'])}: job {_code(result['entry'])} × "
                            f"{_code(result['scenario'])} was {_code(result['state'])}, and no "
                            "run of it is filed.",
                        )
                    )
        others = [run for run in self.runs if not run.complete]
        if others:
            sentences.append(
                Sentence(
                    RECORDED,
                    f"{len(others)} of {len(self.runs)} runs are not results, each named with "
                    "its state and causes above: "
                    + "; ".join(self.ref(run) for run in others)
                    + ".",
                )
            )
        for run in self.runs:
            if self.recordings[run.run].window_exceeded is True:
                sentences.append(
                    Sentence(
                        RECORDED,
                        f"{_upper(self.ref(run))} finished at or after the end of the "
                        f"window ({_code('window_exceeded: true')}); it was not cut short.",
                    )
                )
        for target in self.current.get("targets") or []:
            if target.get("isolation") == "runsc":
                sentences.append(
                    Sentence(
                        DERIVED,
                        f"Target {_code(target.get('host'))} requires {_code('runsc')}, which "
                        f"this version does not provide ({_code('sandbox.policy.PROVIDED')} is "
                        f"{_code(', '.join(PROVIDED))}): no run against it was possible.",
                    )
                )
        sentences.append(
            Sentence(
                DERIVED,
                "No class and no bound over repeated runs is given: this version computes none.",
            )
        )
        return sentences

    # -- 3 and 4

    def findings_section(self, number: int, *, real_world: bool) -> Section:
        items: list[Sentence | Heading] = []

        def add(kind: str, text: str) -> None:
            items.append(Sentence(kind, _mark(text, real_world)))

        entries = sorted(
            {
                (run.server, run.provenance)
                for run in self.runs
                if (run.provenance == "real-world") is real_world
            }
        )
        if not entries:
            items.append(
                Sentence(
                    RECORDED,
                    "No real-world entry has a run filed."
                    if real_world
                    else "No reference or poison entry has a run filed.",
                )
            )
        questions: list[Sentence] = []
        for entry, provenance in entries:
            runs = [run for run in self.runs if run.server == entry]
            items.append(Heading(f"Entry {_code(entry)} ({_code(provenance)})"))
            unobserved = [run for run in runs if not run.egress_observed]
            if unobserved:
                add(DERIVED, _egress_words("for this entry's runs", *unobserved))
            declared = sorted(
                {run.server_version for run in runs if run.server_version_kind == "declared"}
            )
            if declared:
                add(
                    DERIVED,
                    "Server unpinned: this entry's version "
                    + ", ".join(_code(version) for version in declared)
                    + " is the operator's declared word, not established from content (identity "
                    f"kind {_code('endpoint')}).",
                )
            mine = [f for f in self.findings if f.key["server"] == entry]
            if not mine:
                done = sum(1 for run in runs if run.complete)
                add(
                    RECORDED,
                    f"No finding is filed for this entry, in {len(runs)} run"
                    f"{'s' if len(runs) != 1 else ''}, {done} of them complete.",
                )
                if done < len(runs):
                    add(
                        DERIVED,
                        "No finding in a run that is not complete proves nothing: what it lacks "
                        "may only be missing.",
                    )
            for finding in mine:
                for kind, text in self.finding_sentences(finding):
                    add(kind, text)
                for row in self.rows.get(finding.identity, ()):
                    if row.get("status") == "question":
                        questions.append(
                            Sentence(
                                ASSESSED,
                                _mark(
                                    f"On signal {_code(finding.key['signal'])} at "
                                    f"{_code(finding.key['locator'])} of {_code(entry)}: "
                                    + _row_words(row),
                                    real_world,
                                ),
                            )
                        )
        if questions:
            items.append(Heading("Open questions"))
            items += questions
        return Section(number, SECTION_TITLES[number - 1], tuple(items))

    def finding_sentences(self, finding: _Finding) -> list[tuple[str, str]]:
        key = finding.key
        try:
            kind = KINDS[Signal(key["signal"])].value
            of_kind = f"({_code(kind)})"
        except (ValueError, KeyError):
            of_kind = "(of a kind unknown to this version)"
        sentences = [
            (
                RECORDED,
                f"Signal {_code(key['signal'])} {of_kind} at {_code(key['locator'])}, "
                f"statement {_code(key['statement'])}, scenario {_code(key['scenario'])}.",
            )
        ]
        try:
            found_class = class_of("signal", key["signal"])
            class_words = f"Class {_code(found_class.id)}, {found_class.title}."
        except UnknownIdentError:
            class_words = "Class: none, the signal is unknown to this version."
        sentences.append((DERIVED, class_words))
        try:
            page = reference_page(Signal(key["signal"]).value)
            reference_words = (
                f"Reference page, by signal id: {_code(page)} in the bundle; it describes the "
                "pattern, not this server."
            )
        except (ValueError, KeyError):
            reference_words = "Reference page: none, the signal is unknown to this version."
        sentences.append((DERIVED, reference_words))
        complete = [(run, count) for run, count in finding.sightings if run.complete]
        if complete:
            times = sum(count for _, count in complete)
            sentences.append(
                (
                    RECORDED,
                    f"Sighted {times} time{'s' if times != 1 else ''} in "
                    f"{len(complete)} complete run{'s' if len(complete) != 1 else ''}: "
                    + ", ".join(self.ref(run) for run, _ in complete)
                    + ".",
                )
            )
        else:
            sentences.append(
                (
                    DERIVED,
                    "Sighted in no complete run: this finding rests only on runs that are not "
                    "results, and a run that is not complete is no result.",
                )
            )
        for run, count in finding.sightings:
            if not run.complete:
                sentences.append(
                    (
                        RECORDED,
                        f"Also sighted {count} time{'s' if count != 1 else ''} in "
                        f"{self.ref(run)}, which is not a result, so not a sighting of one.",
                    )
                )
        rows = sorted(self.rows.get(finding.identity, ()), key=lambda row: str(row.get("role")))
        for row in rows:
            sentences.append((ASSESSED, _row_words(row)))
        statuses = {row.get("role"): row.get("status") for row in rows}
        if len(statuses) > 1 and len(set(statuses.values())) > 1:
            sentences.append(
                (
                    DERIVED,
                    "The current rows of the two roles differ, compared status by status; both "
                    "stand, side by side.",
                )
            )
        return sentences

    # -- 5

    def comparison_section(self) -> Section:
        if self.previous is None:
            items: list[Sentence | Heading] = [
                Sentence(
                    RECORDED, "No previous engagement's bundle was given: nothing is compared."
                )
            ]
            return Section(5, SECTION_TITLES[4], tuple(items))
        named = _code(self.previous.name)
        # What evidence.verify and the store say is not taken over: their sentences set what
        # they read (a path, a name) among their words. The report says what happened in its
        # own words, and names the command that shows why; the operator's path to the bundle
        # is not the customer's business, so the bundle is named as everywhere else.
        verify = f"{_code('kymograph evidence verify')} on the bundle {named}"
        try:
            verified = evidence.verify(self.previous)
        except evidence.EvidenceError:
            return Section(
                5,
                SECTION_TITLES[4],
                (
                    Sentence(
                        DERIVED,
                        f"The previous bundle {named} was not compared: its index cannot be "
                        f"read by {_code('evidence.verify')}; {verify} says why.",
                    ),
                ),
            )
        if not verified.intact:
            return Section(
                5,
                SECTION_TITLES[4],
                (
                    Sentence(
                        DERIVED,
                        f"The previous bundle {named} is not intact by "
                        f"{_code('evidence.verify')} ({_file_states(verified)}): nothing of it "
                        "is compared, since what it holds is not what was packed; "
                        f"{verify} names each file and problem.",
                    ),
                ),
            )
        try:
            with Store.open_read_only(self.previous / evidence.STORE_FILE) as before:
                items = self.compare_with(before, verified)
        except StoreError:
            items = [self.store_unread(named, "it is not a store this version reads")]
        except sqlite3.Error as exc:
            detail = str(exc)
            items = [self.store_unread(named, f"SQLite: {_code(detail)}")]
        return Section(5, SECTION_TITLES[4], tuple(items))

    @staticmethod
    def store_unread(named: str, why: str) -> Sentence:
        """The sentence for a previous bundle whose store cannot be read: ``why`` in the report's
        words, or SQLite's message in a code span."""
        return Sentence(
            DERIVED,
            f"The previous bundle {named} is intact, but its store cannot be read ({why}): "
            "nothing is compared.",
        )

    def compare_with(self, before: Store, verified: Any) -> list[Sentence | Heading]:
        items: list[Sentence | Heading] = [
            Sentence(
                RECORDED,
                f"The previous bundle {_code(self.previous.name)} is intact, index SHA-256 "
                f"{_code(verified.index_digest)}, of engagement "
                f"{_code(verified.index.engagement_id_declared)}.",
            )
        ]
        earlier = _chosen(before.runs())
        later = _chosen(self.runs)
        for pair in sorted(earlier.keys() | later.keys()):
            server, scenario = pair
            wild = any(
                run.provenance == "real-world"
                for run in (earlier.get(pair), later.get(pair))
                if run is not None
            )

            def add(kind: str, text: str, wild: bool = wild) -> None:
                items.append(Sentence(kind, _mark(text, wild)))

            if pair not in earlier or pair not in later:
                side = "this engagement" if pair in later else "the previous bundle"
                add(
                    DERIVED,
                    f"{_code(server)} × {_code(scenario)} has runs only in {side}: not compared.",
                )
                continue
            old, new = earlier[pair], later[pair]
            items.append(Heading(f"{_code(server)} × {_code(scenario)}"))
            for side, run in (("the previous bundle", old), ("this engagement", new)):
                if not run.complete:
                    add(
                        DERIVED,
                        f"{_upper(side)} has no complete run of {_code(server)} × "
                        f"{_code(scenario)}: its latest run, {self.ref(run)}, is compared, and a "
                        "comparison with a run that is not a result proves nothing.",
                    )
            diff = store_module.compare_runs(before, old.run, self.store, new.run)
            moved = [
                c
                for c in diff.unchanged
                if {s.path for s in c.seen_before} != {s.path for s in c.seen_after}
            ]
            add(
                DERIVED,
                f"The previous bundle's {self.ref(old)} against this engagement's "
                f"{self.ref(new)}, by {_code('store.compare_runs')} on the key without its "
                f"version fields: {len(diff.new)} new, {len(diff.gone)} gone, "
                f"{len(diff.unchanged)} unchanged, {len(moved)} of them moved (sighted at other "
                "places).",
            )
            if not diff.complete:
                add(
                    DERIVED,
                    "Not a complete comparison: a run on either side is not complete, so a "
                    "finding it lacks may only be missing, and gone says nothing.",
                )
            add(
                DERIVED,
                f"Moved axes: {', '.join(_code(a) for a in diff.moved) or 'none'}; "
                f"attribution: {_attribution_words(diff)}.",
            )
            kinds = {diff.before.server_version_kind, diff.after.server_version_kind}
            if "declared" in kinds:
                add(
                    DERIVED,
                    "Server unpinned: a side's version is the operator's declared word, so "
                    "the server axis cannot say whether the server moved.",
                )
            if store_module.CERTIFICATE_CHANGED in diff.caveats.get("new", ()):
                add(
                    DERIVED,
                    "Certificate changed: the endpoint presented certificates in this "
                    "engagement's run that share none with the previous bundle's, by "
                    f"{_code('store.compare_runs')}; it moves no axis and no attribution, since "
                    "a rotated certificate is not a changed server, and neither a same nor a "
                    "changed certificate says whether the deployment changed.",
                )
            if diff.rules["moved"]:
                add(
                    DERIVED,
                    f"The two runs were judged by rules {_code(diff.rules['before'])} and "
                    f"{_code(diff.rules['after'])}: a difference in state may be the rules'.",
                )
            for name in ("new", "gone"):
                for caveat in diff.caveats.get(name, ()):
                    add(DERIVED, f"Caveat on {name}: {_caveat_words(caveat)}.")
            for label, compared in (("New", diff.new), ("Gone", diff.gone), ("Moved", moved)):
                for c in compared:
                    hints = [h for h in COMPARED_HINTS if h in (c.statement_hint, c.cap_hint)]
                    add(
                        DERIVED,
                        f"{label}: signal {_code(c.identity['signal'])} at "
                        f"{_code(c.identity['locator'])} of {_code(c.identity['server'])}"
                        + (" (" + ", ".join(_code(h) for h in hints) + ")" if hints else "")
                        + ".",
                    )
        current = {f.identity for f in self.findings}
        came_back = [row for row in _triage(before) if _identity_of(row) in current]
        if came_back:
            items.append(Heading("Previous decisions on findings that came back"))
            for row in came_back:
                identity = _identity_of(row)
                items.append(
                    Sentence(
                        ASSESSED,
                        _mark(
                            f"Previous, on signal {_code(identity[4])} at {_code(identity[3])} "
                            f"of {_code(identity[0])}: " + _row_words(row),
                            identity in self.wild,
                        ),
                    )
                )
        return items

    # -- 6

    def reproduction_section(self) -> Section:
        items: list[Sentence | Heading] = [Heading("Runs")]
        commands: dict[str, str] = {}
        for run in self.runs:
            recording = self.recordings[run.run]
            started = recording.started or {}
            triple = started.get("reproduction") if isinstance(started, dict) else None
            manifest = (triple or {}).get("manifest") or {}
            # A run outside a corpus records the triple with manifest and corpus null: the
            # recording was read, there is no manifest to name and no command to build from it.
            outside = bool(triple) and not manifest
            triple = triple if manifest else None
            items.append(
                Sentence(
                    RECORDED,
                    f"{_upper(self.ref(run))}: entry {_code(run.server)} at "
                    f"{_code(run.server_version)} ({_code(run.server_version_kind)}), launch "
                    f"{_code(run.launch_digest)}; tool {_code(run.tool_version)} at "
                    f"{_code(run.tool_content)}; scenario {_code(run.scenario)} at "
                    f"{_code(run.scenario_digest)}; isolation {_code(run.isolation)}"
                    + (
                        f"; manifest {_code(manifest.get('source'))} at "
                        f"{_code(manifest.get('digest'))}"
                        if triple
                        else "; the manifest is not known: the run ran outside a corpus"
                        if outside
                        else "; the manifest is not known: the recording was not read"
                    )
                    + ".",
                )
            )
            if not triple:
                continue
            command, notes = self.command(run, manifest.get("source"), started)
            commands[run.run] = command
            items.append(
                Sentence(
                    DERIVED,
                    f"Reproduced by {_code(command)}, built from the triple and the "
                    f"{_code('run_started')} it was recorded with.",
                )
            )
            items += [Sentence(RECORDED, note) for note in notes]
        items.append(Heading("Findings of reference and poison entries"))
        ordinary = [f for f in self.findings if not f.real_world]
        wild = [f for f in self.findings if f.real_world]
        if not ordinary:
            items.append(Sentence(RECORDED, "No finding of a reference or poison entry is filed."))
        items += [self.reproduced(f, commands) for f in ordinary]
        items.append(Heading("Findings of real-world entries, candidates, as in section 4"))
        if not wild:
            items.append(Sentence(RECORDED, "No finding of a real-world entry is filed."))
        items += [self.reproduced(f, commands) for f in wild]
        return Section(6, SECTION_TITLES[5], tuple(items))

    def reproduced(self, finding: _Finding, commands: dict[str, str]) -> Sentence:
        runs = [run for run, _ in finding.sightings]
        chosen = next((r for r in reversed(runs) if r.complete), runs[-1])
        key = finding.key
        return Sentence(
            DERIVED,
            _mark(
                f"Signal {_code(key['signal'])} at {_code(key['locator'])} of entry "
                f"{_code(key['server'])}, scenario {_code(key['scenario'])}: reproduced by the "
                f"command of {self.ref(chosen)}"
                + ("" if chosen.run in commands else ", which is not known here")
                + ".",
                finding.real_world,
            ),
        )

    def command(self, run: Any, manifest: Any, started: dict[str, Any]) -> tuple[str, list[str]]:
        """The ``drive`` command that reproduces a run, naming the operator's file by its name
        only: the report goes to the customer, the operator's directories do not."""
        return _drive_command(Path(self.loaded.source).name, run, manifest, started)

    # -- 7

    def limits_section(self) -> Section:
        by_kind: dict[str, list[str]] = {}
        for signal, kind in KINDS.items():
            by_kind.setdefault(kind.value, []).append(signal.value)
        items: list[Sentence | Heading] = [
            *coverage(
                coverage_facts(self.held["chain"], self.runs, self.recordings, sessions=None)
            ),
            Heading("What a finding says"),
            Sentence(
                DERIVED,
                "A finding says that a signal fired at a place, reproducibly and by name, and "
                "nothing more: it is not a judgement of the server, and it carries "
                f"no verdict (the README's rule, which {_code('store')} keeps: a finding is "
                "filed under its key and nothing else).",
            ),
            Sentence(
                DERIVED,
                "Against a real-world server a finding is a candidate for a person to look at, "
                f"not a confirmed weakness (the provenance {_code('real-world')}, "
                f"{_code('corpus.PROVENANCES')}).",
            ),
            Sentence(
                DERIVED,
                "Nothing in this report is generated prose about impact: recorded sentences are "
                "what the tool wrote down or was given, derived ones follow from those by the "
                "rule or the code they name, and assessed ones are what a person entered, under "
                "their name.",
            ),
            Sentence(
                DERIVED,
                "Egress not observed means that nothing about egress was observed, not that "
                f"there was none: only an isolation in {_code('verdict.OBSERVED_ISOLATIONS')}, "
                f"{_code(', '.join(verdict.OBSERVED_ISOLATIONS))}, observes it.",
            ),
            Heading("Signals by kind"),
            Sentence(
                DERIVED,
                f"Signals of kind {_code('evidence')}, read from {_code('signals.KINDS')}: one "
                "hit is the recorded fact the signal stands for: "
                + ", ".join(_code(s) for s in by_kind.get("evidence", []))
                + ".",
            ),
            Sentence(
                DERIVED,
                f"Signals of kind {_code('heuristic')}, read from {_code('signals.KINDS')}: a "
                "hit is a shape honest content has too, so a row of one can fire on honest "
                "content: " + ", ".join(_code(s) for s in by_kind.get("heuristic", [])) + ".",
            ),
        ]
        return Section(7, SECTION_TITLES[6], tuple(items))


def _drive_command(
    engagement: str,
    run: Any,
    manifest: Any,
    started: dict[str, Any],
    out_dir: str | None = None,
) -> tuple[str, list[str]]:
    """The ``drive`` command that reproduces a run, from its triple and its ``run_started``,
    each part quoted for a POSIX shell; and what the command cannot carry, as sentences.

    It carries what the run recorded: the script (a built-in by name, a file by the name it
    recorded, its digest said beside it), each script variable as recorded — a value masked
    in the recording is masked here too, and said so — the declared target, and
    ``--engagement-confirmed`` exactly where the run recorded the flag as typed.
    """
    parts = [
        "kymograph", "drive", "--engagement", engagement,
        "--manifest", str(manifest), "--entry", run.server, "--scenario", run.scenario,
        "--isolation", run.isolation,
    ]  # fmt: skip
    notes: list[str] = []
    script = started.get("script")
    if isinstance(script, str) and script:
        parts += ["--script", script]
        digest = started.get("script_digest")
        if digest:
            notes.append(
                f"Its script {_code(script)} is a file, named here as the run recorded it, "
                f"with SHA-256 {_code(digest)}: give the file with that digest."
            )
    variables = started.get("script_vars")
    masked: list[str] = []
    if isinstance(variables, dict):
        for name, value in variables.items():
            parts += ["--script-var", f"{name}={value}"]
            if isinstance(value, str) and PLACEHOLDER in value:
                masked.append(name)
    if masked:
        notes.append(
            "The value of "
            + ", ".join(_code(name) for name in masked)
            + " is masked in the recording, and so in the command: give it again."
        )
    authorization = started.get("authorization")
    authorization = authorization if isinstance(authorization, dict) else {}
    target = authorization.get("declared_target")
    if isinstance(target, str) and target:
        parts += ["--target", target]
    for option, image in (("--sandbox-image", run.sandbox_image),
                          ("--target-image", run.target_image)):  # fmt: skip
        if image:
            parts += [option, image]
    limits = started.get("limits")
    limits = limits if isinstance(limits, dict) else {}
    for option, key, default in (
        ("--max-message-bytes", "max_message_bytes", DEFAULT_MAX_MESSAGE_BYTES),
        ("--max-duration", "max_duration_seconds", DEFAULT_MAX_DURATION),
    ):
        value = limits.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value != default:
            parts += [option, f"{value:g}" if isinstance(value, float) else str(value)]
    if out_dir is not None:
        parts += ["--out-dir", out_dir]
    if authorization.get("engagement_confirmed_flag") is True:
        parts.append("--engagement-confirmed")
    return " ".join(shlex.quote(str(part)) for part in parts), notes


def _tls_words(ref: str, run: Any, recording: _Recording) -> str | None:
    """What TLS a run spoke with its endpoint, as recorded: the certificates the store filed
    (``runs.endpoint_certificates``) and the versions the recording names; "no TLS" for a run
    whose endpoint's scheme is ``http``; None — nothing said — for a run without an endpoint, or
    one whose recording was not read and whose store row holds no set."""
    certificates = run.endpoint_certificates
    if certificates is None:
        if recording.scheme == "http":
            return f"No TLS for {ref}: its endpoint's scheme is {_code('http')}."
        if recording.scheme == "https":
            return (
                f"TLS for {ref}: its endpoint's scheme is {_code('https')}, and its "
                f"{_code('run_finished')} records no set of certificates."
            )
        return None
    versions = recording.tls_versions
    if recording.state != "read":
        spoken = "its versions are not read, since its recording was not"
    elif versions:
        spoken = f"version{'s' if len(versions) != 1 else ''} " + ", ".join(
            _code(version) for version in versions
        )
    else:
        spoken = "no version recorded"
    if not certificates:
        return f"TLS for {ref}: {spoken}; the endpoint presented no certificate the run recorded."
    counted = "certificate" if len(certificates) == 1 else f"{len(certificates)} certificates"
    return (
        f"TLS for {ref}: {spoken}; the SHA-256 of the {counted} the endpoint presented, as "
        "presented and not checked here: " + ", ".join(_code(c) for c in certificates) + "."
    )


def _probe_words(probe: str, outcome: str | None) -> str:
    """What became of the probe, as ``era_decided`` records it: no answer and a closed connection
    are not an answer."""
    if outcome is None:
        return f"no answer to {probe} is recorded"
    if outcome == eras.NO_ANSWER:
        return f"{probe} got no answer ({_code(outcome)})"
    if outcome == eras.CLOSED:
        return f"the connection was closed before {probe} was answered ({_code(outcome)})"
    return f"{probe} was answered as {_code(outcome)}"


def _generation_words(ref: str, recording: _Recording) -> list[tuple[str, str]]:
    """Which generation of the protocol a run spoke, as its ``era_decided`` records it: the era and
    the version, what the probe was answered with, a stop and why, and a generation the engagement
    file declares that the server did not speak (an observation, which stopped nothing). Nothing
    for a recording that holds no decision (a stdio run without an engagement is legacy by
    construction and says so only where its ``script_finished`` does)."""
    decided = recording.decided
    if decided is None:
        return []
    era = decided.get("era") if isinstance(decided.get("era"), str) else None
    version = decided.get("version") if isinstance(decided.get("version"), str) else None
    probe = decided.get("probe") if isinstance(decided.get("probe"), dict) else {}
    outcome = probe.get("outcome") if isinstance(probe.get("outcome"), str) else None
    spoke = f"{_code(era)}" if era else "no generation"
    if version:
        spoke += f", protocol version {_code(version)}"
    out: list[tuple[str, str]] = []
    if decided.get("outcome") == "stop":
        refusal = decided.get("refusal") if isinstance(decided.get("refusal"), dict) else {}
        code = refusal.get("code") if isinstance(refusal.get("code"), int) else None
        # The span shows the word of ERA_STOP_REASONS the recorded reason equals, not what
        # the recording holds under ``reason``.
        stop_reason = decided.get("reason")
        reason = next((known for known in ERA_STOP_REASONS if known == stop_reason), None)
        out.append(
            (
                RECORDED,
                f"Opening stopped for {ref}: {spoke}; "
                + (
                    f"reason {_code(reason)}"
                    if reason
                    else "no reason recorded"
                    if stop_reason is None
                    else "a reason this version does not know"
                )
                + (f", error code {_code(str(code))}" if code is not None else "")
                + f"; {_probe_words('the probe', outcome)}. No listing was sent.",
            )
        )
    else:
        out.append(
            (
                RECORDED,
                f"Generation for {ref}: {spoke}; "
                + _probe_words(f"the probe {_code('server/discover')}", outcome)
                + ".",
            )
        )
    declared = decided.get("declared") if isinstance(decided.get("declared"), dict) else None
    if declared is not None and decided.get("differs") is True:
        said = str(declared.get("era")) + (
            f" {declared['version']}" if isinstance(declared.get("version"), str) else ""
        )
        out.append(
            (
                RECORDED,
                f"The engagement file declares {_code(said)} for the endpoint of {ref}, and the "
                f"server spoke {spoke}: an observation, which stopped nothing.",
            )
        )
    return out


def _token_words(ref: str, recording: _Recording) -> str | None:
    """Whether a run sent a token and where it came from, as ``run_started.auth`` records it:
    "a token was used (env NAME / a file)", the identity and its role if the run spoke as one, or
    that none was sent. Never a value. None for a run whose recording says nothing of it."""
    auth = recording.auth
    if auth is None:
        return None
    who = ""
    if isinstance(auth.get("identity"), str):
        role = auth.get("role")
        who = f" as identity {_code(auth['identity'])}" + (
            f" (role {_code(role)})" if isinstance(role, str) else ""
        )
    if auth.get("token_used") is not True:
        return (
            f"No token was sent for {ref}{who}: the identity sends no "
            f"{_code('Authorization')} header."
        )
    named = f"env {_code(str(auth.get('env_name')))}"
    place = named if auth.get("source") == "env" else "a file"
    return f"A token was used for {ref}{who} ({place})."


def _seconds(value: object) -> float | None:
    """A recorded ``seconds`` as a float if it counts as seconds: an int or a float, no bool,
    finite and not negative. An int too large for a float does not count. Anything else is None."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _pacing_words(ref: str, recording: _Recording) -> list[str]:
    """What a run was held to and how long it waited, as ``run_started.pacing_enforced``,
    ``run_started.pacing`` and the ``paced`` events record it: the values and their source
    (``file`` or ``default``), then per reason the number of waits and their seconds, with the
    status that asked for a ``retry_after``. "Declared, not enforced" for a recording that says
    ``false``; nothing for ``null`` or no field. A sum is of the numbers the events hold: of
    ints only, exact and whole (``3``); with a float, a float to three places (``8.0``). No
    judgement of the wait."""
    if recording.pacing_enforced is False:
        return [
            f"Pacing for {ref} is declared, not enforced by the version that made the recording "
            f"({_code('pacing_enforced')} {_code(False)})."
        ]
    if recording.pacing_enforced is not True:
        return []
    values = recording.pacing
    if values is None:
        held = "the values it was held to are not recorded"
    else:
        held = (
            f"{_code('runs_per_origin')} {_code(values.get('runs_per_origin'))} and "
            f"{_code('min_interval_seconds')} {_code(values.get('min_interval_seconds'))}, "
            f"source {_code(values.get('source'))}"
        )
    words = [f"{_upper(ref)} was paced: {held}."]
    if not recording.paced:
        words.append(f"No wait is recorded for {ref}: it has no {_code('paced')} event.")
        return words
    reasons: dict[str, list[dict[str, Any]]] = {}
    for event in recording.paced:
        reasons.setdefault(json.dumps(event.get("why"), default=str), []).append(event)
    for waits in reasons.values():
        counted = [e["seconds"] for e in waits if _seconds(e.get("seconds")) is not None]
        count = f"{len(waits)} wait{'s' if len(waits) != 1 else ''}"
        if not counted:
            said = f"{count}, no sum of seconds"
        elif all(type(n) is int for n in counted):
            # ints add exactly; a float would round a large one to other digits
            said = f"{count}, {_code(sum(counted))} seconds"
        elif not math.isfinite(total := sum(float(n) for n in counted)):
            said = f"{count}, the seconds are too large to add"
        else:
            said = f"{count}, {_code(round(total, 3))} seconds"
        if len(counted) != len(waits):
            said += f" ({len(counted)} of them with a number of seconds)"
        statuses = {
            json.dumps(e["status"], default=str): e["status"] for e in waits if "status" in e
        }
        if statuses:
            said += ", status " + ", ".join(_code(statuses[key]) for key in sorted(statuses))
        words.append(f"{_upper(ref)} waited for {_code(waits[0].get('why'))}: {said}.")
    return words


def _egress_words(where: str, *runs: Any) -> str:
    isolations = sorted({run.isolation for run in runs})
    return (
        f"Egress not observed {where}: isolation "
        + ", ".join(_code(isolation) for isolation in isolations)
        + f" is not one that observes egress ({_code('verdict.OBSERVED_ISOLATIONS')} is "
        f"{_code(', '.join(verdict.OBSERVED_ISOLATIONS))}); no egress event, and no absence of "
        "one, says anything of it."
    )


def _upper(text: str) -> str:
    """The first letter made a capital, nothing else touched (``str.capitalize`` lowers the
    rest, values included)."""
    return text[:1].upper() + text[1:]


def _row_words(row: dict[str, Any]) -> str:
    return (
        f"{_code(row.get('author'))} ({_code(row.get('role'))}), at {_code(row.get('at_utc'))}: "
        f"status {_code(row.get('status'))}" + _imported_words(row.get("imported")) + "."
    )


def _imported_words(imported: Any) -> str:
    """Where a row carried into the store came from (``Store.triage_imports``), or nothing for a
    row written in it: whoever reads the decision can ask the store it was made in."""
    if not isinstance(imported, dict):
        return ""
    return (
        f" (imported from store {_code(imported.get('store_sha256'))} of schema "
        f"{_code(imported.get('store_schema'))}, by the export {_code(imported.get('file_sha256'))}"
        f", at {_code(imported.get('at_utc'))})"
    )


def _target_words(target: Any) -> str:
    """A target as the version declares it, read by the reader's rule (engagement.py, decision
    14): a target that is not local and lists no ports is held to the scheme's port, and the
    sentence says that default was applied and is not in the file; a local one keeps any."""
    if not isinstance(target, dict):
        return f"Target declared: {_code(target)}."
    ports = target.get("ports")
    paths = target.get("paths")
    isolation = target.get("isolation")
    host = target.get("host")
    split = split_target(host) if isinstance(host, str) else None
    if ports is None and split is not None and not is_local(split[0]):
        port_words = (
            ", ".join(f"port {_code(port)}" for port in ENDPOINT_DEFAULT_PORTS)
            + f", the default for {_code(ENDPOINT_DEFAULT_SCHEME)}, not in the file"
        )
    elif ports is None:
        port_words = "any port"
    else:
        port_words = "ports " + ", ".join(_code(p) for p in ports)
    return (
        f"Target declared: {_code(host)}, "
        + port_words
        + ", "
        + ("any path" if paths is None else "paths " + ", ".join(_code(p) for p in paths))
        + ", "
        + (f"isolation floor {_code(isolation)}" if isolation else "no isolation floor")
        + "."
    )


def _changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """What changed between two versions of the file, in the keys a reader of the scope asks
    about: targets added or removed, the window moved (or only its display zone changed),
    scenarios added or removed, actions."""

    def keyed(items: Any) -> set[str]:
        """Each item as JSON with sorted keys: what is compared, and what is shown."""
        return {json.dumps(item, sort_keys=True) for item in (items or []) if item is not None}

    changes: list[str] = []
    for name, field_name in (("target", "targets"), ("scenario", "scenarios")):
        old, new = keyed(before.get(field_name)), keyed(after.get(field_name))
        changes += [f"{name} {_code(item)} added" for item in sorted(new - old)]
        changes += [f"{name} {_code(item)} removed" for item in sorted(old - new)]
    old, new = before.get("window") or {}, after.get("window") or {}
    if (old.get("from"), old.get("until")) != (new.get("from"), new.get("until")):
        changes.append(
            f"window moved from {_code(old.get('from'))}–{_code(old.get('until'))} to "
            f"{_code(new.get('from'))}–{_code(new.get('until'))}"
        )
    if old.get("tz") != new.get("tz"):
        changes.append(
            f"the window's display zone {_code('window.tz')} changed from "
            f"{_code(old.get('tz'))} to {_code(new.get('tz'))}"
        )
    if before.get("actions") != after.get("actions"):
        changes.append(
            f"actions changed from {_code(json.dumps(before.get('actions'), sort_keys=True))} "
            f"to {_code(json.dumps(after.get('actions'), sort_keys=True))}"
        )
    return changes


def _chosen(runs: list) -> dict[tuple[str, str], Any]:
    """The run of each (entry, scenario) a comparison takes: the latest complete one, or the
    latest at all where none is complete — which the comparison then says. Runs come oldest
    first (``Store.runs``)."""
    latest: dict[tuple[str, str], Any] = {}
    complete: dict[tuple[str, str], Any] = {}
    for run in runs:
        latest[(run.server, run.scenario)] = run
        if run.complete:
            complete[(run.server, run.scenario)] = run
    return {pair: complete.get(pair, run) for pair, run in latest.items()}


# -- the re-check -------------------------------------------------------------------------

#: The outcomes of a re-check against a later run (docs/engagements.md, 6).
GONE = "gone"
UNCHANGED = "unchanged"
NOT_PROVEN = "not_proven"
OUTCOMES = (GONE, UNCHANGED, NOT_PROVEN)

#: What a re-check exits with: every identity settled, or something not proven or not known.
EXIT_RECHECK_COMPLETE = 0
EXIT_RECHECK_INCOMPLETE = 3

#: What ``drive`` takes when ``--max-duration`` is not given (``cli``): a recorded limit of
#: another value is carried into the command that reproduces the run.
DEFAULT_MAX_DURATION = 86400.0

#: What a reproduction command cannot carry, because the recording does not hold it.
NOT_RECORDED_FLAGS = (
    "The recording does not hold the --step-timeout or any --mask-key given on the command "
    "line beyond the engagement file's own: give them as the run was made with them."
)

#: Placeholders a re-check's commands carry where only the operator can fill in the value.
NEW_RECORDING = "[NEW RECORDING]"
NEW_RUN = "[NEW RUN]"
AUTHOR = "[NAME]"

#: Beside a re-check's ``gone`` and beside what its run sighted new, when a run's version is the
#: operator's declared word (an endpoint entry): the report's "server unpinned".
UNPINNED = (
    "server unpinned: the version is the operator's declared word, not established from "
    "content, so the deployment may have changed under the same URL and version"
)


@dataclass(frozen=True, slots=True)
class RecheckItem:
    """One identity re-checked: the run it was sighted in, and either the commands that make
    the re-check run, or the outcome against it with the triage line that records it."""

    identity: dict[str, str]
    finding: int
    provenance: str
    #: The run the identity was last sighted in (a complete one when there is one), its state.
    before: str
    before_state: str
    #: Without ``after``: the commands to run, in order. With it: empty.
    commands: tuple[str, ...] = ()
    #: What the commands cannot carry (a script file's digest, a masked value).
    notes: tuple[str, ...] = ()
    outcome: str | None = None
    reason: str = ""
    #: The complete ``store triage set`` line that records the outcome, or None (not proven).
    triage_line: str | None = None
    #: The customer's declared version for the entry (``declared.servers[].version_or_commit``)
    #: beside the versions the two runs recorded; None where nothing was declared.
    declared_version: str | None = None
    version_before: str | None = None
    version_after: str | None = None
    #: What kind of version each is (:func:`mcp_kymograph.store.version_kind`): ``declared``
    #: for an endpoint entry, whose version nothing here established.
    version_kind_before: str | None = None
    version_kind_after: str | None = None
    #: Whether the two runs' endpoint certificates share none
    #: (:data:`mcp_kymograph.store.CERTIFICATE_CHANGED`, as the comparison gives it): said
    #: beside ``gone``, never a reason for an outcome.
    certificate_changed: bool = False

    @property
    def server_unpinned(self) -> bool:
        """Whether either run's version is only declared, so the server may have moved unseen."""
        return "declared" in (self.version_kind_before, self.version_kind_after)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": dict(self.identity),
            "finding": self.finding,
            "provenance": self.provenance,
            "before": self.before,
            "before_state": self.before_state,
            "commands": list(self.commands),
            "notes": list(self.notes),
            "outcome": self.outcome,
            "reason": self.reason,
            "triage_line": self.triage_line,
            "declared_version": self.declared_version,
            "version_before": self.version_before,
            "version_after": self.version_after,
            "version_kind_before": self.version_kind_before,
            "version_kind_after": self.version_kind_after,
            "server_unpinned": self.server_unpinned,
            "certificate_changed": self.certificate_changed,
        }


@dataclass(frozen=True, slots=True)
class Recheck:
    """``engagement recheck``: what to run, or what the re-check run showed. Runs nothing,
    writes nothing."""

    engagement_id: str
    store: str
    after: str | None
    after_state: str | None
    items: tuple[RecheckItem, ...]
    #: Identities the re-check run sighted that no earlier run of the store sighted: new, to be
    #: triaged from ``open``.
    new: tuple[dict[str, str], ...] = ()
    #: What kind of version the re-check run's is; None without one.
    after_version_kind: str | None = None

    @property
    def complete(self) -> bool:
        """Every identity settled: no outcome ``not_proven``, and every command known."""
        if self.after is None:
            return all(item.commands for item in self.items)
        return all(item.outcome != NOT_PROVEN for item in self.items)

    @property
    def exit_code(self) -> int:
        return EXIT_RECHECK_COMPLETE if self.complete else EXIT_RECHECK_INCOMPLETE

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id_declared": self.engagement_id,
            "store": self.store,
            "after": self.after,
            "after_state": self.after_state,
            "after_version_kind": self.after_version_kind,
            "complete": self.complete,
            "items": [item.to_dict() for item in self.items],
            "new": [dict(identity) for identity in self.new],
        }


def recheck(
    *,
    store: str | Path,
    engagement_path: str | Path,
    runs_dir: str | Path,
    identities: list[dict[str, str]] | None = None,
    finding_ids: list[int] | None = None,
    all_fixed_pending: bool = False,
    after: str | None = None,
) -> Recheck:
    """Re-check findings the customer says are fixed (docs/engagements.md, 6). Runs nothing and
    writes nothing; it prints what to run and, given the re-check run, what it showed.

    The findings are named exactly one way: by ``identities`` (as ``store diff`` prints them),
    by ``finding_ids``, or as every identity whose current row, of either role, is
    ``fixed_pending_recheck``. For each, the run it was last sighted in — the latest complete
    one, else the latest — is the one to repeat.

    Without ``after``: the ``drive`` command that reproduces that run (the report's own builder,
    ``--engagement`` the operator's file as given), the ``store ingest`` that files the new
    recording, and the ``engagement recheck … --after`` that reads it. With ``after`` (a run of
    the store, by id, prefix or recording): :func:`mcp_kymograph.store.compare_runs` between the
    run the finding was sighted in and it. ``gone`` only where the later run is complete, of the
    same entry and scenario, and does not sight the identity, and nothing the comparison says
    (a statement no longer asked, a cap) leaves room for it to be there; ``unchanged`` where it
    is sighted; ``not_proven`` otherwise, with the reason — a run that is not complete proves
    nothing. Each outcome but ``not_proven`` comes with the complete ``store triage set`` line
    that records it, the author left as ``[NAME]``.

    ``store`` is the store's path: opened here read-only, and named in the commands.

    :class:`ReportError` for a store without an engagement, an operator's file not of its
    chain, a finding named that the store does not hold, or not exactly one way of naming.
    """
    named = sum(1 for given in (identities, finding_ids) if given is not None) + bool(
        all_fixed_pending
    )
    if named != 1:
        raise ReportError(
            "name the findings exactly one way: by identity, by finding id, or as every one "
            "fixed pending a re-check"
        )
    loaded = load_engagement(engagement_path)
    with Store.open_read_only(store) as opened:
        return _recheck(
            opened, str(store), loaded, str(engagement_path), Path(runs_dir),
            identities, finding_ids, all_fixed_pending, after,
        )  # fmt: skip


def _recheck(
    store: Store,
    store_path: str,
    loaded: Engagement,
    engagement_arg: str,
    runs_dir: Path,
    identities: list[dict[str, str]] | None,
    finding_ids: list[int] | None,
    all_fixed_pending: bool,
    after: str | None,
) -> Recheck:
    held = store.engagement()
    if held is None:
        raise ReportError("the store holds no engagement: a re-check is of one engagement's store")
    if loaded.digest not in [entry["digest"] for entry in held["chain"]]:
        raise ReportError(
            f"{loaded.source}: its SHA-256 {loaded.digest} is not a version of the store's "
            f"engagement {held['engagement_id_declared']}"
        )
    filed: dict[tuple, tuple[int, str]] = {}
    by_id: dict[int, tuple] = {}
    for provenance in ("reference", "poison", "real-world"):
        for row in store.findings_with_triage(provenance):
            identity = tuple(row[name] for name in IDENTITY_FIELDS)
            by_id[row["finding"]] = identity
            if identity not in filed or row["finding"] > filed[identity][0]:
                filed[identity] = (row["finding"], provenance)
    wanted: list[tuple] = []
    if identities is not None:
        for given in identities:
            identity = tuple(given.get(name) for name in IDENTITY_FIELDS) if isinstance(
                given, dict
            ) else None  # fmt: skip
            if identity is None or identity not in filed:
                raise ReportError(
                    f"no finding of the identity {json.dumps(given, sort_keys=True)} is in the "
                    "store; nothing is re-checked"
                )
            wanted.append(identity)
    elif finding_ids is not None:
        for finding in finding_ids:
            if finding not in by_id:
                raise ReportError(f"no finding {finding} in the store; nothing is re-checked")
            wanted.append(by_id[finding])
    else:
        wanted = [
            identity
            for row in _triage(store)
            if row.get("status") == "fixed_pending_recheck"
            and (identity := _identity_of(row)) in filed
        ]
    wanted = list(dict.fromkeys(wanted))
    runs = store.runs()
    later = None if after is None else store.run_info(store.resolve(after))
    sighted: dict[tuple, list[Any]] = {}
    found_in: dict[str, set[tuple]] = {}
    for run in runs:
        found_in[run.run] = set(store.findings_of(run.run))
        for identity in found_in[run.run]:
            sighted.setdefault(identity, []).append(run)
    recordings = _read_recordings(store, runs, runs_dir) if later is None else {}
    declared = _declared_versions(held["chain"][-1]["file_declared"])
    items = []
    for identity in wanted:
        candidates = [r for r in sighted.get(identity, []) if later is None or r.run != later.run]
        if not candidates:
            raise ReportError(
                f"the identity {json.dumps(dict(zip(IDENTITY_FIELDS, identity, strict=True)))} "
                "is sighted in no run but the re-check run: there is nothing to re-check it "
                "against"
            )
        before = next((r for r in reversed(candidates) if r.complete), candidates[-1])
        finding, provenance = filed[identity]
        common = {
            "identity": dict(zip(IDENTITY_FIELDS, identity, strict=True)),
            "finding": finding,
            "provenance": provenance,
            "before": before.run,
            "before_state": before.state,
            "declared_version": declared.get(identity[0]),
            "version_before": before.server_version,
            "version_kind_before": before.server_version_kind,
        }
        if later is None:
            items.append(
                _recheck_commands(
                    common,
                    before,
                    recordings[before.run],
                    engagement_arg,
                    store_path,
                    str(runs_dir),
                    finding,
                )  # fmt: skip
            )
        else:
            order = {run.run: index for index, run in enumerate(runs)}
            items.append(
                _recheck_outcome(
                    common,
                    store,
                    before,
                    later,
                    store_path,
                    finding,
                    order[later.run] < order[before.run],
                )  # fmt: skip
            )
    new: tuple[dict[str, str], ...] = ()
    if later is not None:
        earlier = set().union(*(found_in[r.run] for r in runs if r.run != later.run))
        new = tuple(
            dict(zip(IDENTITY_FIELDS, identity, strict=True))
            for identity in sorted(found_in[later.run] - earlier, key=json.dumps)
        )
    return Recheck(
        engagement_id=held["engagement_id_declared"],
        store=store_path,
        after=None if later is None else later.run,
        after_state=None if later is None else later.state,
        items=tuple(items),
        new=new,
        after_version_kind=None if later is None else later.server_version_kind,
    )


def _declared_versions(declared_file: dict[str, Any]) -> dict[str, str]:
    """The customer's declared version per entry: ``declared.servers[]`` paired with an entry
    by its ``entry`` key, as the customer's answers were paired by the operator."""
    declared = declared_file.get("declared") if isinstance(declared_file, dict) else None
    servers = declared.get("servers") if isinstance(declared, dict) else None
    versions: dict[str, str] = {}
    for server in servers if isinstance(servers, list) else ():
        if not isinstance(server, dict):
            continue
        entry, version = server.get("entry"), server.get("version_or_commit")
        if isinstance(entry, str) and isinstance(version, str) and version:
            versions[entry] = version
    return versions


def _recheck_commands(
    common: dict[str, Any],
    before: Any,
    recording: _Recording,
    engagement_arg: str,
    store_path: str,
    runs_dir: str,
    finding: int,
) -> RecheckItem:
    started = recording.started or {}
    triple = started.get("reproduction") if isinstance(started, dict) else None
    if recording.state != "read" or not isinstance(triple, dict):
        return RecheckItem(
            **common,
            reason=(
                f"the recording of run {before.run[:SHORT_RUN]} was not read ({recording.why}"
                + (f": {recording.detail}" if recording.detail else "")
                + "): "
                "the command that reproduces it is not known here"
            ),
        )
    manifest = (triple.get("manifest") or {}).get("source")
    if manifest is None:
        return RecheckItem(
            **common,
            reason=(
                f"run {before.run[:SHORT_RUN]} names no manifest (it ran outside a corpus): "
                "the command that reproduces it is not known here"
            ),
        )
    drive, notes = _drive_command(engagement_arg, before, manifest, started, runs_dir)
    notes.append(NOT_RECORDED_FLAGS)
    quoted = [shlex.quote(part) for part in (store_path, engagement_arg, runs_dir)]
    ingest = (
        f"kymograph store ingest --store {quoted[0]} --engagement {quoted[1]} "
        f"{shlex.quote(NEW_RECORDING)}"
    )
    again = (
        f"kymograph engagement recheck --store {quoted[0]} --engagement {quoted[1]} "
        f"--runs {quoted[2]} --finding {finding} --after {shlex.quote(NEW_RUN)}"
    )
    return RecheckItem(**common, commands=(drive, ingest, again), notes=tuple(notes))


def _recheck_outcome(
    common: dict[str, Any],
    store: Store,
    before: Any,
    later: Any,
    store_path: str,
    finding: int,
    started_earlier: bool,
) -> RecheckItem:
    identity = tuple(common["identity"][name] for name in IDENTITY_FIELDS)
    diff = store_module.compare_runs(store, before.run, store, later.run)
    short = later.run[:SHORT_RUN]
    sighted = any(tuple(c.identity[n] for n in IDENTITY_FIELDS) == identity for c in diff.unchanged)
    gone = next(
        (c for c in diff.gone if tuple(c.identity[n] for n in IDENTITY_FIELDS) == identity), None
    )
    common = {
        **common,
        "version_after": later.server_version,
        "version_kind_after": later.server_version_kind,
        "certificate_changed": store_module.CERTIFICATE_CHANGED in diff.caveats.get("gone", ()),
    }

    def line(status: str) -> str:
        return " ".join(
            shlex.quote(part)
            for part in (
                "kymograph", "store", "triage", "set", "--store", store_path, "--finding",
                str(finding), "--role", "operator", "--status", status, "--author", AUTHOR,
            )
        )  # fmt: skip

    if started_earlier:
        return RecheckItem(
            **common,
            outcome=NOT_PROVEN,
            reason=(
                f"run {short} started before run {before.run[:SHORT_RUN]}, in which the finding "
                "was sighted: it is no re-check of that run"
            ),
        )
    if sighted:
        reason = f"still sighted in run {short}"
        if not later.complete:
            reason += f", which is not complete ({later.state}): sighted all the same"
        return RecheckItem(
            **common,
            outcome=UNCHANGED,
            reason=reason,
            triage_line=line("confirmed"),
        )
    if not later.complete:
        return RecheckItem(
            **common,
            outcome=NOT_PROVEN,
            reason=(
                f"run {short} is not complete ({later.state}): a run that is not complete proves "
                "nothing, and what it lacks may only be missing"
            ),
        )
    if (later.server, later.scenario) != (identity[0], identity[1]):
        return RecheckItem(
            **common,
            outcome=NOT_PROVEN,
            reason=(
                f"run {short} is of entry {later.server} and scenario {later.scenario}, not of "
                f"{identity[0]} and {identity[1]}: it could not have sighted the finding"
            ),
        )
    if diff.rules["moved"]:
        return RecheckItem(
            **common,
            outcome=NOT_PROVEN,
            reason=(
                f"the two runs were judged by rules {diff.rules['before']} and "
                f"{diff.rules['after']}: an absence under other rules proves nothing"
            ),
        )
    capped = [run.run[:SHORT_RUN] for run in (before, later) if run.listing_capped]
    if capped:
        return RecheckItem(
            **common,
            outcome=NOT_PROVEN,
            reason=(
                f"the listing of run {', '.join(capped)} was cut at the driver's page limit: "
                "what was not listed may hold the finding"
            ),
        )
    hints = [] if gone is None else [h for h in (gone.statement_hint, gone.cap_hint) if h]
    if hints:
        return RecheckItem(
            **common,
            outcome=NOT_PROVEN,
            reason=(
                f"not sighted in run {short}, but the comparison says {', '.join(hints)}: the "
                "finding may be there and not asked for, or cut at the cap"
            ),
        )
    return RecheckItem(
        **common,
        outcome=GONE,
        reason=f"not sighted in run {short}, which is complete",
        triage_line=line("fixed"),
    )


def _version(version: str | None, kind: str | None) -> str:
    """A version for the terminal, labelled when it is only declared."""
    return _safe(version) + (" (declared)" if kind == "declared" else "")


def render_recheck(result: Recheck) -> str:
    """The re-check for the terminal: per identity, the commands to run, or the outcome and the
    line that records it. Every value passes the terminal filter; ``--json`` has every command
    exactly as built."""
    lines = [f"Re-check of engagement {_safe(result.engagement_id)}"]
    if result.after is not None:
        lines.append(
            f"against run {result.after[:SHORT_RUN]} ({_safe(result.after_state)})"
            + (
                ""
                if result.after_state == verdict.COMPLETE
                else ": not complete — what it lacks proves nothing"
            )
        )
    for item in result.items:
        identity = item.identity
        lines += [
            "",
            f"{_safe(identity['server'])} × {_safe(identity['scenario'])}: signal "
            f"{_safe(identity['signal'])} at {_safe(identity['locator'])} (finding "
            f"{item.finding}, {item.provenance})",
            f"  last sighted in run {item.before[:SHORT_RUN]} ({_safe(item.before_state)}), "
            f"version {_version(item.version_before, item.version_kind_before)}",
        ]
        if item.declared_version is not None:
            lines.append(
                f"  the customer declared version {_safe(item.declared_version)} for the entry"
                + (
                    "; the re-check run recorded "
                    + _version(item.version_after, item.version_kind_after)
                    if item.version_after is not None
                    else ""
                )
            )
        if result.after is None:
            if not item.commands:
                lines.append(f"  not known: {_safe(item.reason)}")
            for number, command in enumerate(item.commands, start=1):
                shown = _safe(command)
                lines.append(f"  {number}. {shown}")
                if shown != command:
                    lines.append("     (a character a terminal does not show was dropped here)")
            lines += [f"  note: {_safe(note)}" for note in item.notes]
            continue
        lines.append(f"  {item.outcome}: {_safe(item.reason)}")
        if item.outcome == GONE and item.server_unpinned:
            lines.append(f"  {UNPINNED}")
        if item.outcome == GONE and item.certificate_changed:
            lines.append(f"  {store_module.CERTIFICATE_CHANGED}")
        if item.triage_line is not None:
            lines.append(f"  record it: {_safe(item.triage_line)}")
    if result.new:
        lines += ["", "New in the re-check run, to be triaged from open:"]
        if result.after_version_kind == "declared":
            lines.append(f"  ({UNPINNED})")
        lines += [
            f"  {_safe(i['server'])} × {_safe(i['scenario'])}: signal {_safe(i['signal'])} at "
            f"{_safe(i['locator'])}"
            for i in result.new
        ]
    lines += [
        "",
        "Nothing was run and nothing written."
        + ("" if result.complete else " Not everything is settled: see not_proven above."),
    ]
    return "\n".join(lines) + "\n"


# -- the attestation ----------------------------------------------------------------------

#: The attestation's first line, before the engagement's id as a code span.
ATTESTATION_TITLE = "# Attestation for engagement "

#: The kinds an attestation's sentences may have: it states recorded facts and what follows
#: from them by a named rule, and holds no one's assessment.
ATTESTATION_KINDS = (RECORDED, DERIVED)


@dataclass(frozen=True, slots=True)
class ParsedAttestation:
    """An attestation as :func:`parse_attestation` read it."""

    engagement_id: str
    items: tuple[Sentence | Heading, ...]

    @property
    def sentences(self) -> tuple[Sentence, ...]:
        return tuple(item for item in self.items if isinstance(item, Sentence))


@dataclass(frozen=True, slots=True)
class Attestation:
    """``engagement attest``: what was done and not done, from recorded facts only
    (docs/engagements.md, 7) — no finding, no locator, no signal, no triage row. What a
    customer can show a third party without disclosing what was found."""

    engagement_id: str
    index_digest: str
    items: tuple[Sentence | Heading, ...]

    @property
    def sentences(self) -> tuple[Sentence, ...]:
        return tuple(item for item in self.items if isinstance(item, Sentence))

    def parsed(self) -> ParsedAttestation:
        return ParsedAttestation(_safe(self.engagement_id), self.items)


def attest(
    *,
    store: Store | str | Path,
    engagement_path: str | Path,
    bundle_dir: str | Path,
    runs_dir: str | Path,
    now: datetime,
) -> Attestation:
    """The engagement's attestation, from the store, the recordings under ``runs_dir`` (and the
    refusals files under it), and the bundle it was packed into.

    Refused with :class:`ReportError` — nothing is written either way — for a bundle that is not
    intact (:func:`mcp_kymograph.evidence.verify`), whose index digest the store's ``bundles``
    does not hold, or that names an engagement digest the store's chain does not; for a store
    without an engagement, and a runs directory that is not one. The report's digest is the one
    the bundle's index names, when it holds a report: the customer decides whether to hand
    the report over, and the attestation names which report it would be.

    ``engagement_path`` is the operator's own file, a version of the store's chain: the literal
    strings it lists under ``redaction.mask_patterns`` are what must not leave the operator's
    hands. An attestation in which any of them occurs — a target host, a script's name — is
    refused whole, naming the rule (``mask_patterns[i]``) and never the string.
    """
    moment = _aware(now)
    loaded = load_engagement(engagement_path)
    runs_path = Path(runs_dir)
    if not runs_path.is_dir():
        raise ReportError(f"{runs_path}: not a directory that can be read")
    if isinstance(store, (str, Path)):
        with Store.open_read_only(store) as opened:
            made = _attest(opened, loaded, Path(bundle_dir), runs_path, moment)
    else:
        made = _attest(store, loaded, Path(bundle_dir), runs_path, moment)
    text = render_attestation(made)
    found = [
        f"mask_patterns[{index}]"
        for index, pattern in enumerate(loaded.mask_patterns)
        if pattern and pattern in text
    ]
    if found:
        raise ReportError(
            f"the attestation would show what {', '.join(found)} of the engagement file names, "
            "a string to be kept from handover; nothing is written"
        )
    return made


def _attest(
    store: Store, loaded: Engagement, bundle: Path, runs_dir: Path, now: datetime
) -> Attestation:
    held = store.engagement()
    if held is None:
        raise ReportError("the store holds no engagement: an attestation is of one engagement")
    if loaded.digest not in {entry["digest"] for entry in held["chain"]}:
        raise ReportError(
            f"{loaded.source}: its SHA-256 {loaded.digest} is not a version of the store's "
            f"engagement {held['engagement_id_declared']}"
        )
    try:
        verified = evidence.verify(bundle)
    except evidence.EvidenceError as exc:
        raise ReportError(f"{bundle}: the bundle cannot be verified: {exc}") from None
    if not verified.intact:
        raise ReportError(
            f"{bundle}: the bundle is not intact ({verified.summary()}); an attestation names "
            "only an intact bundle"
        )
    digest = verified.index_digest
    if digest not in {row["index_digest"] for row in store.bundles()}:
        raise ReportError(
            f"{bundle}: its index SHA-256 {digest} is not among the bundles this store filed; "
            "an attestation names a bundle packed from this store"
        )
    chain = held["chain"]
    if verified.index.engagement_digest not in {entry["digest"] for entry in chain}:
        raise ReportError(
            f"{bundle}: it was packed under {verified.index.engagement_digest}, not a version of "
            "the store's engagement"
        )
    runs = store.runs()
    recordings = _read_recordings(store, runs, runs_dir)
    items: list[Sentence | Heading] = []

    def say(kind: str, text: str) -> None:
        items.append(Sentence(kind, text))

    say(
        RECORDED,
        f"Engagement {_code(held['engagement_id_declared'])}, attested at {_code(utc_text(now))}"
        f" from its store, its recordings and its bundle; the store holds {len(chain)} "
        f"version{'s' if len(chain) != 1 else ''} of its file.",
    )
    for number, entry in enumerate(chain, start=1):
        window = entry["file_declared"].get("window") or {}
        say(
            RECORDED,
            f"Version {number}: SHA-256 {_code(entry['digest'])}, window "
            f"{_code(window.get('from'))} to {_code(window.get('until'))}.",
        )
    items.append(Heading(f"Targets as declared, version {len(chain)}"))
    for target in chain[-1]["file_declared"].get("targets") or []:
        say(RECORDED, _target_words(target))

    items.append(Heading("Runs"))
    counted = Counter(run.state for run in runs)
    say(
        RECORDED,
        f"Runs filed: {len(runs)} — "
        + ", ".join(f"{counted.get(state, 0)} {_code(state)}" for state in RUN_STATES)
        + ".",
    )
    for run in runs:
        say(
            RECORDED,
            f"Run {_code(run.run[:SHORT_RUN])} ({_code(run.state)}): isolation "
            f"{_code(run.isolation)}.",
        )
    unobserved = [run for run in runs if not run.egress_observed]
    if unobserved:
        say(DERIVED, _egress_words(f"for {len(unobserved)} of these runs", *unobserved))
    scenarios = Counter((run.scenario, run.scenario_digest) for run in runs)
    for (name, scenario_digest), count in sorted(scenarios.items()):
        say(
            RECORDED,
            f"Scenario {_code(name)} at SHA-256 {_code(scenario_digest)}: {count} run"
            f"{'s' if count != 1 else ''}.",
        )

    items.append(Heading("Scripts and tool calls"))
    read = [run for run in runs if recordings[run.run].state == "read"]
    scripts: Counter[tuple[str, str | None]] = Counter()
    for run in read:
        started = recordings[run.run].started or {}
        scripts[(str(started.get("script")), started.get("script_digest"))] += 1
    for (name, script_digest), count in sorted(scripts.items(), key=str):
        say(
            RECORDED,
            f"Script {_code(name)}, "
            + (f"a file at SHA-256 {_code(script_digest)}" if script_digest else "built in")
            + f": {count} run{'s' if count != 1 else ''}.",
        )
    calling = [run for run in read if recordings[run.run].calls]
    if read and not calling:
        say(
            RECORDED,
            f"No tool call is recorded: none of the {len(read)} recording"
            f"{'s' if len(read) != 1 else ''} read holds a {_code('step_called')} event.",
        )
    elif calling:
        calls = sum(recordings[run.run].calls for run in calling)
        say(
            RECORDED,
            f"{len(calling)} of the {len(read)} recordings read hold tool calls, {calls} "
            f"{_code('step_called')} event{'s' if calls != 1 else ''} in all.",
        )
    unread = len(runs) - len(read)
    if unread:
        say(
            DERIVED,
            f"{unread} recording{'s were' if unread != 1 else ' was'} not read under the runs "
            "directory, so what script ran and whether a tool was called there is not said.",
        )

    items.append(Heading("The gate's record"))
    windows = _windows(chain)
    found = find_refusals(runs_dir)
    reasons: Counter[str] = Counter()
    for refusals in found:
        counted_file = _count_refusals(refusals, runs_dir, windows)
        if counted_file.unreadable is not None:
            say(
                RECORDED,
                f"The refusals file {_code(counted_file.path)} could not be read "
                f"({_unread_words(counted_file, _code)}): its refusals are not counted.",
            )
            continue
        reasons.update(counted_file.by_reason)
        if counted_file.near_cap:
            say(
                DERIVED,
                f"The refusals log {_code(counted_file.path)} has "
                + _room_words(counted_file.room_bytes),
            )
    total = sum(reasons.values())
    say(
        RECORDED,
        f"Refusals under this engagement: {total}"
        + (
            " — " + ", ".join(f"{reasons[r]} {_code(r)}" for r in REFUSAL_REASONS if reasons[r])
            if total
            else ""
        )
        + ".",
    )
    say(
        DERIVED,
        "Refusals made before the engagement file was read are not recorded: "
        f"{_code('engagement.record_refusal')} writes a refusal under the file it was refused "
        "against.",
    )

    items.append(Heading("What this engagement did not do or observe"))
    sessions = sum(
        1
        for listed in verified.index.files
        if listed.role == "recording" and listed.details.get("filed") is not True
    )
    items += coverage(coverage_facts(chain, runs, recordings, sessions=sessions))

    items.append(Heading("The evidence"))
    say(
        RECORDED,
        f"The evidence bundle {_code(bundle.name)} has index SHA-256 {_code(digest)}; it is "
        f"intact by {_code('evidence.verify')} and filed among this store's bundles.",
    )
    reports = [f for f in verified.index.files if f.role == "report"]
    for listed in reports:
        say(
            RECORDED,
            f"The bundle holds the report {_code(listed.path)} with SHA-256 "
            f"{_code(listed.sha256)}; whether to hand it over is the customer's decision.",
        )
    if not reports:
        say(RECORDED, "The bundle holds no report.")
    say(
        DERIVED,
        "This attestation holds no finding, no locator, no signal and no triage row: it is "
        "built from the store's runs, the recordings and the bundle's index alone, and what was "
        "found is in the report.",
    )
    return Attestation(
        engagement_id=held["engagement_id_declared"], index_digest=digest, items=tuple(items)
    )


def render_attestation(attestation: Attestation) -> str:
    """The attestation as one page of Markdown: a title, then one item per paragraph."""
    lines = [ATTESTATION_TITLE + _code(attestation.engagement_id), ""]
    for item in attestation.items:
        lines += [item.line(), ""]
    return "\n".join(lines)


def parse_attestation(text: str) -> ParsedAttestation:
    """Read an attestation back, or refuse it with :class:`ReportParseError` naming the line: a
    line it cannot place, an ``[assessed]`` sentence (an attestation holds none), Markdown
    outside a code span, a span not closed."""
    if not text.endswith("\n"):
        raise ReportParseError("the attestation does not end with a line break")
    lines = text[:-1].split("\n")
    engagement_id = _parse_title(lines[0], ATTESTATION_TITLE)
    items: list[Sentence | Heading] = []
    for number, line in enumerate(lines[1:], start=2):
        if (number % 2 == 0) != (line == ""):
            raise ReportParseError(f"line {number}: items are separated by exactly one empty line")
        if line:
            items.append(_parse_item(line, number, ATTESTATION_KINDS))
    return ParsedAttestation(engagement_id, tuple(items))


# -- the dossier --------------------------------------------------------------------------

#: What ``engagement history`` exits with: every store read, or one that was not.
EXIT_DOSSIER_COMPLETE = 0
EXIT_DOSSIER_INCOMPLETE = 3

#: Where a finding has no current row of a role, the dossier counts it under this.
NO_ROW = "none"


@dataclass(frozen=True, slots=True)
class DossierEngagement:
    """One engagement of the customer, as its store holds it."""

    store: str
    engagement_id: str
    #: Every version of the file, oldest first: ``{"version", "digest", "from", "until"}``.
    versions: tuple[dict[str, Any], ...]
    runs_by_state: dict[str, int]
    findings_by_provenance: dict[str, int]
    #: Per role, how many findings have each current status (:data:`NO_ROW` for none).
    triage: dict[str, dict[str, int]]
    bundles: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "store": self.store,
            "engagement_id_declared": self.engagement_id,
            "versions": [dict(version) for version in self.versions],
            "runs_by_state": dict(self.runs_by_state),
            "findings_by_provenance": dict(self.findings_by_provenance),
            "triage": {role: dict(counts) for role, counts in self.triage.items()},
            "bundles": list(self.bundles),
        }


@dataclass(frozen=True, slots=True)
class Dossier:
    """``engagement history``: one customer's engagements across stores (docs/engagements.md,
    8). Read every time from the stores, read-only; nothing is cached."""

    customer: str
    engagements: tuple[DossierEngagement, ...]
    #: Stores that could not be read by this version, each with its words — never skipped.
    unreadable: tuple[tuple[str, str], ...] = ()
    #: Stores read that hold no engagement, by path.
    without_engagement: tuple[str, ...] = ()
    #: How many stores hold another customer's engagement: counted, neither named nor placed.
    other_customer: int = 0

    @property
    def complete(self) -> bool:
        return not self.unreadable

    @property
    def exit_code(self) -> int:
        return EXIT_DOSSIER_COMPLETE if self.complete else EXIT_DOSSIER_INCOMPLETE

    def to_dict(self) -> dict[str, Any]:
        return {
            "customer": self.customer,
            "complete": self.complete,
            "engagements": [engagement.to_dict() for engagement in self.engagements],
            "unreadable": [{"store": store, "words": words} for store, words in self.unreadable],
            "without_engagement": list(self.without_engagement),
            "other_customer": self.other_customer,
            "by_class": None,
            "by_class_note": BY_CLASS_NOTE,
        }


#: What the dossier says of "findings by class" (docs/engagements.md, 8).
BY_CLASS_NOTE = "findings by class over repeated runs are not computed by this version"


def dossier(*, customer: str, stores: list[str | Path]) -> Dossier:
    """Every engagement of ``customer`` in ``stores`` (docs/engagements.md, 8).

    Each store is opened through :meth:`Store.open_read_only` and read whole, every time: a
    store that cannot be read — another schema, not a store, not there — is listed with its
    words, never skipped, and the dossier is then not complete (exit 3). A store whose
    engagement's ``customer`` (the chain's current version) is another is counted, without its
    name or its path. Per engagement of the customer: its id, every version's window, runs by
    state, findings by provenance and by each role's current triage status, and the index
    digests of the bundles filed. Findings by class are not computed, and the dossier says so.
    """
    engagements: list[DossierEngagement] = []
    unreadable: list[tuple[str, str]] = []
    without: list[str] = []
    others = 0
    for given in stores:
        place = str(given)
        try:
            with Store.open_read_only(given) as store:
                held = store.engagement()
                if held is None:
                    without.append(place)
                    continue
                current = held["chain"][-1]["file_declared"]
                if declared_customer(current) != customer:
                    others += 1
                    continue
                engagements.append(_dossier_engagement(store, place, held))
        except (StoreError, sqlite3.Error, OSError) as exc:
            unreadable.append((place, str(exc)))
    engagements.sort(key=lambda e: (str(e.versions[0].get("from")), e.engagement_id, e.store))
    return Dossier(
        customer=customer,
        engagements=tuple(engagements),
        unreadable=tuple(unreadable),
        without_engagement=tuple(without),
        other_customer=others,
    )


def _dossier_engagement(store: Store, place: str, held: dict[str, Any]) -> DossierEngagement:
    versions = []
    for number, entry in enumerate(held["chain"], start=1):
        window = entry["file_declared"].get("window") or {}
        versions.append(
            {
                "version": number,
                "digest": entry["digest"],
                "from": window.get("from"),
                "until": window.get("until"),
            }
        )
    counted = Counter(run.state for run in store.runs())
    findings: dict[str, int] = {}
    triage: dict[str, Counter[str]] = {}
    for provenance in ("reference", "poison", "real-world"):
        rows = store.findings_with_triage(provenance)
        findings[provenance] = len(rows)
        for row in rows:
            for role, current in (row.get("triage") or {}).items():
                status = current.get("status") if isinstance(current, dict) else None
                triage.setdefault(role, Counter())[status or NO_ROW] += 1
    return DossierEngagement(
        store=place,
        engagement_id=held["engagement_id_declared"],
        versions=tuple(versions),
        runs_by_state={state: counted.get(state, 0) for state in RUN_STATES},
        findings_by_provenance=findings,
        triage={role: dict(sorted(counts.items())) for role, counts in sorted(triage.items())},
        bundles=tuple(row["index_digest"] for row in store.bundles()),
    )


def render_dossier(result: Dossier) -> str:
    """The dossier for the terminal: one block per engagement, then what could not be read."""
    lines = [f"Engagements of {_safe(result.customer)}: {len(result.engagements)}"]
    for engagement in result.engagements:
        lines += ["", f"{_safe(engagement.engagement_id)}  ({_safe(engagement.store)})"]
        for version in engagement.versions:
            lines.append(
                f"  version {version['version']}: {_safe(version['from'])} to "
                f"{_safe(version['until'])}, SHA-256 {_safe(version['digest'])}"
            )
        lines.append(
            "  runs: "
            + ", ".join(f"{count} {state}" for state, count in engagement.runs_by_state.items())
        )
        lines.append(
            "  findings: "
            + ", ".join(
                f"{count} {provenance}"
                for provenance, count in engagement.findings_by_provenance.items()
            )
        )
        for role, counts in engagement.triage.items():
            lines.append(
                f"  current triage, {_safe(role)}: "
                + ", ".join(f"{count} {_safe(status)}" for status, count in counts.items())
            )
        lines.append(
            "  bundles: " + (", ".join(engagement.bundles) if engagement.bundles else "none filed")
        )
    lines += ["", f"By class: {BY_CLASS_NOTE}."]
    if result.other_customer:
        lines.append(
            f"{result.other_customer} store{'s hold' if result.other_customer != 1 else ' holds'}"
            " another customer's engagement: counted, not named."
        )
    for place in result.without_engagement:
        lines.append(f"{_safe(place)}: holds no engagement.")
    for place, words in result.unreadable:
        lines.append(f"{_safe(place)}: not readable by this version — {_safe(words)}")
    if not result.complete:
        lines.append("Not complete: a store above could not be read.")
    return "\n".join(lines) + "\n"
