"""The finding store: findings from corpus runs, kept by their key, compared run against run.

**The store keeps; it never decides.** What a finding is was settled by the inspector when the
run was recorded. The store reads the ``finding`` events of a recording and files them. It
checks that an entry is well-formed and that a run is complete; it never adds, drops or
reinterprets a finding.

**One key, and nothing else.** A finding is filed under its key, the seven-tuple
``{server, server_version, tool_version, scenario, statement, locator, signal}``, held as one
canonical JSON string with a uniqueness constraint on it — "literally this finding, in this
version context". The positional ``path`` and ``message_seq`` are stored as a *sighting* of
that finding in a run — where it sat — and are never part of what identifies it.

**Only corpus runs are filed.** A run is accepted when it was driven from a manifest entry and
records the reproduction triple (:mod:`mcp_kymograph.corpus`): the entry at its content, this
tool at its content, the scenario at its digest. The entry's name is the key's ``server``;
its provenance — ``reference``, ``poison`` or ``real-world`` — comes from the manifest through
the recording, and every finding carries it. A finding against a real-world server is a
candidate for responsible disclosure, never a confirmed weakness, and stays queryable apart.

**One engagement, one store** (docs/engagements.md, 4). A store holds no engagement and
takes only runs made without one, or holds one — the file's id, its current digest and the
chain of every version (:meth:`Store.set_engagement`) — and takes only runs whose recording
names a digest of that chain. What a run's engagement says is filed beside the run as a claim
(``engagement_id_declared``, ``engagement_declared``); it never enters a key, a state or a
comparison.

**Comparing two runs** answers a different question from the key: "the same finding across
version contexts". :meth:`Store.diff` gives three sets — new, gone, unchanged — matched on the
key *without its two version fields*, and then says what moved between the two runs, axis by
axis:

* **server** — the entry's content (``server_version``) or how it is launched;
* **tool** — this tool's version or its content;
* **scenario** — the scenario's name or its digest;
* **environment** — the isolation the run observed in, and the images it ran, by id.
  Never part of a key: a finding is the same finding under runc and on the host, which
  the reference/poison pair shows. When only this axis moved and findings differ anyway, the
  comparison says so and flags it softly — it is not put down to the server, and not
  swallowed.

When exactly one axis moved, a new or gone finding is attributed to it. When none moved, there
should be nothing new or gone, and if there is, the diff says that nothing recorded explains
it. When two or more moved, a gone finding cannot be attributed to either, and the diff says
so instead of picking one.

**Two ways a comparison can fall short, kept apart.** A run that is not *complete* — a
recording that ends early, a line that cannot be read, fewer findings recorded than the run
counted, a server that never answered, a sandbox that did not hold (:mod:`mcp_kymograph.verdict`
judges which, and the run is filed with that state) — lacks data: a finding it lacks may only
be missing, so the comparison is marked incomplete, hard (the command line exits 3). A
*scenario drift* — the same scenario name with other content — is complete data answering a
different question: findings of an added statement read as new, of a removed one as gone. The
new and gone sets are then flagged, softly, and each entry whose statement exists on only one
side says so; the rest of the comparison keeps its value.

**A recorded cap is complete data, and a comparison says where it reaches**. A run
that cut findings at the per-message cap is filed complete, with what it cut kept beside it
(``truncations``). A finding gone in a later run that cut findings of that statement and
signal may be among those cut, not gone; such an entry says so (``cap_hint``) and the set is
flagged, softly — as is every set when either run cut a listing at the driver's page limit.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_kymograph import definitions, verdict
from mcp_kymograph.corpus import PROVENANCES, undisplayable

#: The fields of a finding key, in the order a key is written. A finding event whose key has
#: any other set of fields is malformed.
KEY_FIELDS = (
    "server",
    "server_version",
    "tool_version",
    "scenario",
    "statement",
    "locator",
    "signal",
)

#: The key without the two version fields: what a comparison between runs matches on.
IDENTITY_FIELDS = tuple(f for f in KEY_FIELDS if f not in ("server_version", "tool_version"))

#: The axes a comparison attributes a change to, and the run fields that make up each.
AXES: dict[str, tuple[str, ...]] = {
    "server": ("server_version", "launch_digest"),
    "tool": ("tool_version", "tool_content"),
    "scenario": ("scenario", "scenario_digest"),
    "environment": ("isolation", "sandbox_image", "target_image"),
}

#: How many problems are listed per run; the count is kept in full.
MAX_LISTED_PROBLEMS = 20

#: The store's layout. Raised for a change to its tables — never again for a change to the rules
#: a run is judged by, which have a version of their own
#: (:data:`mcp_kymograph.verdict.RULES_VERSION`, kept with every run and every fleet, and named by
#: every comparison across two of them). Until 8 this number was raised for rule changes too: 7
#: for UDP by destination and UDP loss, 8 for the kinds of shortfall (``causes``). 9 adds the
#: ``rules`` column to runs and fleets; 10 lets a run and a fleet result be ``call_failed``, which
#: a store of 9 refuses to hold. 11 adds what an engagement needs, all of it in one step:
#: the engagement each run was gated against, the ``triage`` table of decisions kept beside the
#: findings, and the ``bundles`` packed from the store. 12 adds the certificates an endpoint
#: presented over TLS (``runs.endpoint_certificates``, docs/design/http-transport.md 8.4). 13
#: drops the ``triage.rationale`` and ``triage.severity`` columns: a decision keeps its status,
#: role, author and time, and the reason and the score stay in the operator's private notes
#: (``mcp_kymograph.operator_notes``), which this tool never reads. 13 also holds the
#: ``definition_runs`` and ``definitions`` tables (:mod:`mcp_kymograph.definitions`), created when
#: a store is opened for writing; a run filed before them has no rows there. A store of any other
#: schema is refused whole, never migrated and never read in part; the runs are driven again into
#: a new store. One exception, for what no run can produce again: :func:`export_triage` reads of a
#: store of schema 11 to 13 the ``triage`` table and the engagement's ``meta`` rows and
#: nothing else, so that ``store triage import`` can carry the rows a person wrote into the new
#: store (:data:`TRIAGE_EXPORT_SCHEMAS`).
SCHEMA_VERSION = "13"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run TEXT PRIMARY KEY,
    run_id TEXT,
    recording TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('reference', 'poison', 'real-world')),
    server TEXT NOT NULL,
    announced_server TEXT,
    server_version TEXT NOT NULL,
    server_identity_kind TEXT NOT NULL,
    launch_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_content TEXT NOT NULL,
    scenario TEXT NOT NULL,
    scenario_digest TEXT NOT NULL,
    isolation TEXT NOT NULL,
    sandbox_image TEXT,
    target_image TEXT,
    statements TEXT NOT NULL,
    wall_clock_utc TEXT,
    state TEXT NOT NULL
        CHECK (state IN ('complete', 'incomplete', 'server_failed', 'sandbox_failed',
                         'call_failed')),
    problem_count INTEGER NOT NULL,
    problems TEXT NOT NULL,
    causes TEXT NOT NULL,
    truncations TEXT NOT NULL,
    rules INTEGER NOT NULL,
    engagement_id_declared TEXT,
    engagement_digest TEXT,
    engagement_declared TEXT,
    endpoint_certificates TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    server TEXT NOT NULL,
    server_version TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    scenario TEXT NOT NULL,
    statement TEXT NOT NULL,
    locator TEXT NOT NULL,
    signal TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('reference', 'poison', 'real-world'))
);
CREATE TABLE IF NOT EXISTS sightings (
    finding INTEGER NOT NULL REFERENCES findings (id),
    run TEXT NOT NULL REFERENCES runs (run),
    path TEXT NOT NULL,
    message_seq INTEGER NOT NULL,
    normalized INTEGER NOT NULL,
    UNIQUE (finding, run, path, message_seq)
);
CREATE TABLE IF NOT EXISTS fleets (
    fleet TEXT PRIMARY KEY,
    started_utc TEXT NOT NULL,
    finished_utc TEXT NOT NULL,
    manifest_source TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_content TEXT NOT NULL,
    isolation TEXT NOT NULL,
    sandbox_image TEXT,
    target_image TEXT,
    parallel INTEGER NOT NULL,
    processed TEXT NOT NULL,
    digest TEXT NOT NULL,
    complete INTEGER NOT NULL,
    problems TEXT NOT NULL,
    rules INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_results (
    fleet TEXT NOT NULL REFERENCES fleets (fleet),
    entry TEXT NOT NULL,
    scenario TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('reference', 'poison', 'real-world')),
    state TEXT NOT NULL CHECK (state IN ('complete', 'incomplete', 'server_failed',
                                         'sandbox_failed', 'call_failed', 'refused',
                                         'unfiled')),
    exit_code INTEGER,
    run TEXT REFERENCES runs (run),
    problems TEXT NOT NULL,
    causes TEXT NOT NULL,
    UNIQUE (fleet, entry, scenario)
);
CREATE TABLE IF NOT EXISTS triage (
    id INTEGER PRIMARY KEY,
    identity TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'customer')),
    status TEXT NOT NULL
        CHECK (status IN ('open', 'confirmed', 'false_positive', 'accepted',
                          'fixed_pending_recheck', 'fixed', 'intentional', 'question')),
    author TEXT NOT NULL CHECK (author <> ''),
    at_utc TEXT NOT NULL,
    engagement_digest TEXT,
    supersedes INTEGER REFERENCES triage (id),
    CHECK (status <> 'intentional' OR role = 'customer'),
    CHECK (status <> 'fixed' OR role = 'operator')
);
CREATE INDEX IF NOT EXISTS triage_by_identity ON triage (identity, role, id);
-- A decision is never changed and never taken back: a second one is a second row.
CREATE TRIGGER IF NOT EXISTS triage_rows_are_not_changed BEFORE UPDATE ON triage
BEGIN
    SELECT RAISE(ABORT, 'refused: a triage row is never changed; a new decision is a new row');
END;
CREATE TRIGGER IF NOT EXISTS triage_rows_are_not_deleted BEFORE DELETE ON triage
BEGIN
    SELECT RAISE(ABORT, 'refused: a triage row is never deleted');
END;
CREATE TABLE IF NOT EXISTS bundles (
    index_digest TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    packed_utc TEXT NOT NULL,
    derived_from TEXT,
    engagement_digest TEXT
);
-- What a run's */list answers held (mcp_kymograph.definitions): one digest per definition,
-- listing and segment, and per run the listings and list_changed notifications it saw. A run
-- filed before these tables existed has no row in ``definition_runs``: "not captured", never
-- "unchanged".
CREATE TABLE IF NOT EXISTS definition_runs (
    run TEXT PRIMARY KEY REFERENCES runs (run),
    listings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS definitions (
    run TEXT NOT NULL REFERENCES runs (run),
    segment INTEGER NOT NULL,
    listing INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tool', 'prompt', 'resource', 'resource_template')),
    name TEXT NOT NULL,
    digest TEXT NOT NULL,
    fields TEXT NOT NULL,
    duplicate INTEGER NOT NULL CHECK (duplicate IN (0, 1))
);
CREATE INDEX IF NOT EXISTS definitions_by_run ON definitions (run, kind, segment);
"""

_RUN_COLUMNS = (
    "run",
    "run_id",
    "recording",
    "provenance",
    "server",
    "announced_server",
    "server_version",
    "server_identity_kind",
    "launch_digest",
    "manifest_digest",
    "tool_version",
    "tool_content",
    "scenario",
    "scenario_digest",
    "isolation",
    "sandbox_image",
    "target_image",
    "statements",
    "wall_clock_utc",
    "state",
    "problem_count",
    "problems",
    "causes",
    "truncations",
    "rules",
    "engagement_id_declared",
    "engagement_digest",
    "engagement_declared",
    "endpoint_certificates",
)

#: What ``run_finished.http.tls`` holds when a run spoke TLS to its endpoint
#: (docs/design/http-transport.md 8.2): exactly these, each a list of distinct strings in order.
_RECORDED_TLS = ("versions", "certificates")

#: What ``run_started.authorization.engagement`` holds when a run was gated against an
#: engagement file: exactly these, and nothing else of the file.
_RECORDED_ENGAGEMENT = ("engagement_id_declared", "engagement_digest", "window_declared")

#: The ``meta`` rows that hold the store's engagement. ``delete_after_declared`` is absent for a
#: file that declares no retention: a ``meta`` value is never NULL.
_ENGAGEMENT_META = (
    "engagement_id_declared",
    "engagement_digest",
    "engagement_chain",
    "delete_after_declared",
)

#: What the store never keeps of an engagement file, whatever the caller says it removed: the
#: operator's contacts and references, and the literal strings to be blanked before a handover,
#: have no place in a store that may be packed and handed on.
#: Key paths, as ``Store.set_engagement``'s ``removed`` names them.
REMOVED_FROM_FILE = ("contacts", "reference", "redaction.mask_patterns")

#: The fields of one entry of ``meta.engagement_chain``: one entry per version of the file.
_CHAIN_FIELDS = ("digest", "file_declared", "removed", "supersedes", "set_utc")


#: The columns of the two definition tables, in order. A table of another shape comes from an
#: unreleased build of this step and is refused: there is no migration. A schema-13 store made
#: before the tables existed gets them when opened for writing.
_DEFINITION_COLUMNS = {
    "definition_runs": ("run", "listings"),
    "definitions": (
        "run",
        "segment",
        "listing",
        "kind",
        "name",
        "digest",
        "fields",
        "duplicate",
    ),
}


def _stale_definition_tables(connection: sqlite3.Connection) -> str | None:
    """Why a definition table that exists is not the one this version writes, or None. A table
    that does not exist is no fault: opening for writing creates it."""
    for table, expected in _DEFINITION_COLUMNS.items():
        found = tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
        if found and found != expected:
            return (
                f"the table {table} comes from an earlier state of schema {SCHEMA_VERSION} "
                f"(columns {', '.join(found)}; expected {', '.join(expected)}); this version "
                "does not migrate it, the store must be created anew"
            )
    return None


class StoreError(ValueError):
    """A recording the store will not take, or a run it does not have. Says which and why."""


#: What kind of version a server identity's version is, wherever the store gives one out
#: (``server_version_kind``): established from content, pinned to a revision, or declared —
#: the operator's word for a server someone else runs (an ``endpoint`` identity), which nothing
#: here checked. Read from the identity's kind, never from the version string.
VERSION_KINDS = {"content": "content", "revision": "revision", "endpoint": "declared"}

#: The kind of a finding's version when the runs that sighted it name more than one: said so,
#: never one of them picked.
MIXED = "mixed"

#: The kind of a version whose identity kind this version does not know.
UNKNOWN = "unknown"


#: The roles a triage decision is made in (docs/engagements.md, 5): the operator's, and
#: the customer's, kept side by side — neither overrides the other.
TRIAGE_ROLES = ("operator", "customer")

#: The statuses both roles may set, and ``question``: the
#: question is asked outside the tool, the party asked is named in ``author``.
_EITHER_ROLE = frozenset(
    {"open", "confirmed", "false_positive", "accepted", "fixed_pending_recheck", "question"}
)

#: The statuses :meth:`Store.triage_set` takes from each role — all eight the schema holds, each
#: in the role that may claim it (docs/engagements.md, 5 and 6). ``intentional`` is the
#: customer's alone: "this is deliberate" is the customer's to say about their own server, never
#: the operator's to say for them. ``fixed`` is the operator's alone, after a re-check, the run it
#: was checked by kept in the operator's own record: the customer says ``fixed_pending_recheck``,
#: and the operator says what a run showed. The schema's CHECKs hold the same two constraints.
TRIAGE_STATUSES: dict[str, frozenset[str]] = {
    "operator": _EITHER_ROLE | {"fixed"},
    "customer": _EITHER_ROLE | {"intentional"},
}

#: The longest text a decision keeps, per field: a reason and a name, not a report.
TRIAGE_CAPS = {"author": 200}

#: A triage row's columns, as the store holds them and as ``store triage list`` and an export
#: give them (the identity as its five fields).
_TRIAGE_COLUMNS = (
    "id", "identity", "role", "status", "author", "at_utc", "engagement_digest", "supersedes",
)  # fmt: skip

#: The layout of a triage export (:func:`export_triage`, :meth:`Store.import_triage`).
TRIAGE_EXPORT_VERSION = 1
_TRIAGE_EXPORT_FIELDS = (
    "triage_export_version",
    "store_schema",
    "store_sha256",
    "engagement_chain_digests",
    "rows",
)

#: One import as the ``meta`` row ``triage_imports`` records it, and what of it each row carried
#: in gives as its ``imported`` (:meth:`Store.import_triage`, :meth:`Store.triage_imports`).
_IMPORT_FIELDS = ("file_sha256", "store_sha256", "store_schema", "rows", "first_id", "at_utc")
_IMPORTED_FIELDS = ("file_sha256", "store_sha256", "store_schema", "at_utc")

#: The store schemas a triage export reads: this version's, and the two before it, whose
#: ``triage`` tables are the same (12 added ``runs.endpoint_certificates`` only) — the one place a
#: store of an older schema is read, and only to carry rows a person wrote and no run can produce
#: again (docs/design/http-transport.md 8.4).
TRIAGE_EXPORT_SCHEMAS = (SCHEMA_VERSION, "12", "11")

#: The schemas whose triage rows held a ``rationale`` and a ``severity``: their export leaves both
#: out, and so does an import of an export written before 13.
LEGACY_TRIAGE_SCHEMAS = ("12", "11")

#: The columns of a legacy triage row that the tool no longer keeps.
_DROPPED_COLUMNS = ("rationale", "severity")


def version_kind(identity_kind: str | None) -> str:
    """``content``, ``revision`` or ``declared`` for a run's identity kind, or ``unknown``."""
    return VERSION_KINDS.get(identity_kind, UNKNOWN) if identity_kind is not None else UNKNOWN


def canonical_key(key: dict[str, Any]) -> str:
    """The one string a finding is filed under: the seven fields, in order, as JSON."""
    return json.dumps([key[name] for name in KEY_FIELDS], ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class Ingested:
    run: str
    provenance: str
    findings: int
    #: ``complete``, ``incomplete``, ``server_failed``, ``sandbox_failed`` or ``call_failed``,
    #: judged from the recording (:mod:`mcp_kymograph.verdict`).
    state: str
    problems: tuple[str, ...]
    already: bool = False
    #: The kinds of shortfall (mcp_kymograph.verdict.CAUSES), each once, sorted.
    causes: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.state == verdict.COMPLETE


@dataclass(frozen=True, slots=True)
class RunInfo:
    run: str
    provenance: str
    server: str
    announced_server: str | None
    server_version: str
    launch_digest: str
    tool_version: str
    tool_content: str
    scenario: str
    scenario_digest: str
    #: Where the run observed (the environment axis): the isolation, and the images by id.
    isolation: str
    sandbox_image: str | None
    target_image: str | None
    #: Every (statement, signal) the run's scenario asked for, zero findings included.
    statements: frozenset[tuple[str, str]]
    state: str
    problem_count: int
    problems: tuple[str, ...]
    #: Recorded caps (mcp_kymograph.verdict): complete data, cut where and why it says.
    truncations: tuple[dict[str, Any], ...] = ()
    #: The kinds of shortfall (mcp_kymograph.verdict.CAUSES), each once, sorted — kept whole,
    #: where ``problems`` lists only the first :data:`MAX_LISTED_PROBLEMS` reasons.
    causes: tuple[str, ...] = ()
    #: The version of the rules the run was judged by when it was filed
    #: (:data:`mcp_kymograph.verdict.RULES_VERSION`).
    rules: int = verdict.RULES_VERSION
    #: The engagement the run was gated against, as its recording names it: the file's ``id``
    #: as the operator typed it, and the SHA-256 of the file's bytes. None for a run made
    #: without an engagement file. Neither is part of a key, a state or a comparison.
    engagement_id_declared: str | None = None
    engagement_digest: str | None = None
    #: What the customer declared under ``declared:`` in that version of the file, as the
    #: store's chain keeps it — never read from the recording. None when it declared nothing.
    engagement_declared: Any = None
    #: How the server's version was established, as the recording's triple names it:
    #: ``content``, ``revision`` or ``endpoint`` (mcp_kymograph.identity). What
    #: :attr:`server_version_kind` is read from — never the version string itself.
    server_identity_kind: str | None = None
    #: The SHA-256 of every leaf certificate the endpoint presented over TLS, sorted, as
    #: ``run_finished.http.tls`` records them; None for a run that spoke no TLS (stdio, plain
    #: HTTP, or a recording made before TLS was spoken). Not part of an axis: a comparison says
    #: when two runs' sets share none (:data:`CERTIFICATE_CHANGED`), and moves nothing for it.
    endpoint_certificates: tuple[str, ...] | None = None

    @property
    def complete(self) -> bool:
        return self.state == verdict.COMPLETE

    @property
    def server_version_kind(self) -> str:
        """What kind of version ``server_version`` is: see :func:`version_kind`."""
        return version_kind(self.server_identity_kind)

    @property
    def egress_observed(self) -> bool:
        """Whether the run's isolation observes the server's egress at all
        (:data:`mcp_kymograph.verdict.OBSERVED_ISOLATIONS`). Where it does not — on the host,
        or for a server someone else runs — nothing about egress can be said of the run, and
        no absence of an egress event means anything."""
        return self.isolation in verdict.OBSERVED_ISOLATIONS

    @property
    def cut_statements(self) -> frozenset[tuple[str, str]]:
        """Every (statement, signal) of which the run cut findings at the per-message cap."""
        return frozenset(
            (statement, signal)
            for truncation in self.truncations
            if truncation.get("kind") == "findings_per_message"
            for statement, signals in (truncation.get("cut") or {}).items()
            for signal in signals
        )

    @property
    def listing_capped(self) -> bool:
        return any(t.get("kind") == "page_limit" for t in self.truncations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run,
            "provenance": self.provenance,
            "server": self.server,
            "announced_server": self.announced_server,
            "server_version": self.server_version,
            "server_version_kind": self.server_version_kind,
            "launch_digest": self.launch_digest,
            "tool_version": self.tool_version,
            "tool_content": self.tool_content,
            "scenario": self.scenario,
            "scenario_digest": self.scenario_digest,
            "isolation": self.isolation,
            "sandbox_image": self.sandbox_image,
            "target_image": self.target_image,
            "egress_observed": self.egress_observed,
            "state": self.state,
            "complete": self.complete,
            "problem_count": self.problem_count,
            "problems": list(self.problems),
            "causes": list(self.causes),
            "truncations": [dict(t) for t in self.truncations],
            "rules": self.rules,
            "engagement_id_declared": self.engagement_id_declared,
            "engagement_digest": self.engagement_digest,
            "engagement_declared": self.engagement_declared,
            "endpoint_certificates": (
                None if self.endpoint_certificates is None else list(self.endpoint_certificates)
            ),
        }


@dataclass(frozen=True, slots=True)
class Sighting:
    path: str
    message_seq: int
    normalized: bool

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "message_seq": self.message_seq, "normalized": self.normalized}


@dataclass(frozen=True, slots=True)
class Compared:
    """One finding in a comparison: its identity, its full key on each side, where it sat."""

    identity: dict[str, Any]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    seen_before: tuple[Sighting, ...] = ()
    seen_after: tuple[Sighting, ...] = ()
    #: ``statement_added`` for a new finding whose statement and signal the earlier run's
    #: scenario did not ask for; ``statement_removed`` for a gone one the later run's did not.
    #: Such a finding reflects a change in the question, not in what was detected.
    statement_hint: str | None = None
    #: ``capped_after`` for a gone finding whose statement and signal the later run cut
    #: findings of at the per-message cap; ``capped_before`` for a new one the earlier run
    #: cut. It may be among those cut rather than gone or new.
    cap_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": dict(self.identity),
            "key_before": self.before,
            "key_after": self.after,
            "sightings_before": [s.to_dict() for s in self.seen_before],
            "sightings_after": [s.to_dict() for s in self.seen_after],
            "statement_hint": self.statement_hint,
            "cap_hint": self.cap_hint,
        }


@dataclass(frozen=True, slots=True)
class Attribution:
    """To what a new or gone finding can be put down, and whether it can be at all."""

    attributable: bool
    axis: str | None
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"attributable": self.attributable, "axis": self.axis, "note": self.note}


@dataclass(frozen=True, slots=True)
class Diff:
    before: RunInfo
    after: RunInfo
    new: tuple[Compared, ...]
    gone: tuple[Compared, ...]
    unchanged: tuple[Compared, ...]
    axes: dict[str, dict[str, Any]] = field(default_factory=dict)
    attribution: Attribution = Attribution(True, None, "")
    #: Soft flags per set: complete data, but a comparison that is not clean. Never an exit.
    caveats: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return self.before.complete and self.after.complete

    @property
    def rules(self) -> dict[str, Any]:
        """The rules each run was judged by. Where they differ, so may the two states, by the
        rules alone: the comparison says so rather than putting it down to the server."""
        before, after = self.before.rules, self.after.rules
        return {"before": before, "after": after, "moved": before != after}

    @property
    def moved(self) -> tuple[str, ...]:
        return tuple(name for name, axis in self.axes.items() if axis["moved"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "complete": self.complete,
            "rules": self.rules,
            "same_entry": self.before.server == self.after.server,
            # Beside the server axis, not in it: what kind of version each side's is, so a
            # declared one is never read as established. Neither moves an axis.
            "server_version_kind": {
                "before": self.before.server_version_kind,
                "after": self.after.server_version_kind,
            },
            "axes": {name: dict(axis) for name, axis in self.axes.items()},
            "moved_axes": list(self.moved),
            "attribution": self.attribution.to_dict(),
            "caveats": {name: list(flags) for name, flags in self.caveats.items()},
            "new": [c.to_dict() for c in self.new],
            "gone": [c.to_dict() for c in self.gone],
            "unchanged": [c.to_dict() for c in self.unchanged],
        }


SCENARIO_DRIFT = (
    "scenario_drift: the scenario's content differs between the two runs; this set may hold "
    "changes to the set of statements, not only to what was detected"
)
FINDINGS_CAPPED = (
    "findings_capped: a run cut findings at the per-message cap; an entry with a cap_hint may "
    "be among those cut rather than gone or new"
)
ENVIRONMENT_MOVED = (
    "environment_moved: only where the runs observed differs (isolation or image), and findings "
    "are not expected to depend on it; a difference here is not the server's"
)
LISTING_CAPPED = (
    "listing_capped: a run cut a listing at the driver's page limit; what lay past it was not "
    "looked at in that run"
)
SERVER_UNPINNED = (
    "server_unpinned: a side's version is the operator's declared word, not established from "
    "content; the deployment may have changed under the same URL and version, so what this set "
    "holds may be its doing, whichever axes moved"
)
CERTIFICATE_CHANGED = (
    "certificate_changed: the endpoint presented certificates in this run that share none with "
    "the other's; a rotated certificate is not a changed server, and neither a same nor a "
    "changed certificate says whether the deployment changed"
)


class Store:
    """An SQLite file holding runs, findings and where each finding was sighted."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection

    @classmethod
    def open(cls, path: str | Path) -> Store:
        """Open or create a store. A new file is created readable by its owner only."""
        path = Path(path)
        if not path.exists():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        connection = sqlite3.connect(path)
        try:
            refusal = _schema_refusal(connection, path)
        except sqlite3.Error:
            connection.close()
            raise
        if refusal is not None:
            connection.close()
            raise StoreError(refusal)
        found = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
        ).fetchone()
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            stale = _stale_definition_tables(connection)
        except sqlite3.Error:
            connection.close()
            raise
        if stale is not None:
            connection.close()
            raise StoreError(f"{path}: {stale}")
        connection.executescript(_SCHEMA)
        if found is None:
            connection.execute("INSERT INTO meta VALUES ('schema', ?)", (SCHEMA_VERSION,))
            connection.commit()
        return cls(connection)

    @classmethod
    def open_read_only(cls, path: str | Path) -> Store:
        """Open an existing store for reading, through SQLite's ``mode=ro``: the file can be
        neither created nor changed, and a write through this store fails in SQLite itself.

        Refused as :meth:`open` refuses: a store of another schema whole, never read in part.
        Refused besides, because nothing is created here: a missing file, a file without tables,
        which :meth:`open` would make a new store, and a file in write-ahead-log mode, which
        SQLite reads only by creating its ``-wal`` and ``-shm`` files beside it.
        """
        path = Path(path)
        connection = _connect_read_only(path)
        try:
            empty = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
            if empty:
                refusal = (
                    f"{path}: holds no tables — not a store yet; opened for reading, nothing is "
                    "created"
                )
            else:
                refusal = _schema_refusal(connection, path)
            if refusal is None:
                connection.execute("PRAGMA query_only = ON")
        except sqlite3.Error:
            connection.close()
            raise
        if refusal is not None:
            connection.close()
            raise StoreError(refusal)
        return cls(connection)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- filing a run ----------------------------------------------------------------

    def ingest(self, recording: str | Path, provenance: str | None = None) -> Ingested:
        """File one corpus recording. All of it, or none of it.

        The provenance is the one the recording carries from the manifest. ``provenance``,
        when given, is a cross-check: a recording that says otherwise is refused.

        The run's engagement must be the store's (:meth:`set_engagement`): a store without one
        takes only runs made without one, and a store with one only runs whose recorded digest
        is in its chain, under the same id. Anything else is refused before anything is written.
        """
        if provenance is not None and provenance not in PROVENANCES:
            raise StoreError(f"unknown provenance {provenance!r}; one of {', '.join(PROVENANCES)}")
        path = _events_path(Path(recording))
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise StoreError(f"{path}: cannot read: {exc.strerror or exc}") from None
        run = hashlib.sha256(raw).hexdigest()
        if self._db.execute("SELECT 1 FROM runs WHERE run = ?", (run,)).fetchone():
            count = self._db.execute(
                "SELECT COUNT(*) FROM sightings WHERE run = ?", (run,)
            ).fetchone()[0]
            info = self.run_info(run)
            return Ingested(
                run, info.provenance, count, info.state, info.problems, True, info.causes
            )

        parsed = _read_run(path, raw)
        if provenance is not None and provenance != parsed.provenance:
            raise StoreError(
                f"{path}: the run is {parsed.provenance!r} by its manifest entry, "
                f"not {provenance!r}; refusing rather than relabelling it"
            )
        try:
            with self._db:
                # Taken before the store's engagement is read, so that nothing can change it
                # between the check and the filing.
                self._db.execute("BEGIN IMMEDIATE")
                parsed.engagement_declared = self._admit(path, parsed)
                self._file(run, path, parsed)
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"{path}: {exc}") from None
        except (UnicodeEncodeError, OverflowError, sqlite3.Error) as exc:
            # A value of the run the database cannot hold; the ``with`` has rolled it back.
            raise StoreError(
                f"{path}: a value of the run cannot be stored ({type(exc).__name__}: {exc}); "
                "the whole run is refused and nothing of it is filed"
            ) from None
        return Ingested(
            run,
            parsed.provenance,
            len(parsed.findings),
            parsed.state,
            tuple(parsed.problems),
            causes=tuple(parsed.causes),
        )

    def _file(self, run: str, path: Path, parsed: _ParsedRun) -> None:
        listed = parsed.problems[:MAX_LISTED_PROBLEMS]
        values = {
            "run": run,
            "run_id": parsed.run_id,
            "recording": str(path),
            "provenance": parsed.provenance,
            "server": parsed.server,
            "announced_server": parsed.announced_server,
            "server_version": parsed.server_version,
            "server_identity_kind": parsed.server_identity_kind,
            "launch_digest": parsed.launch_digest,
            "manifest_digest": parsed.manifest_digest,
            "tool_version": parsed.tool_version,
            "tool_content": parsed.tool_content,
            "scenario": parsed.scenario,
            "scenario_digest": parsed.scenario_digest,
            "isolation": parsed.isolation,
            "sandbox_image": parsed.sandbox_image,
            "target_image": parsed.target_image,
            "statements": json.dumps(sorted(parsed.statements)),
            "wall_clock_utc": parsed.wall_clock_utc,
            "state": parsed.state,
            "problem_count": len(parsed.problems),
            "problems": json.dumps(listed),
            "causes": json.dumps(parsed.causes),
            "truncations": json.dumps(parsed.truncations),
            "rules": verdict.RULES_VERSION,
            "engagement_id_declared": parsed.engagement_id_declared,
            "engagement_digest": parsed.engagement_digest,
            "engagement_declared": parsed.engagement_declared,
            "endpoint_certificates": (
                None
                if parsed.endpoint_certificates is None
                else json.dumps(parsed.endpoint_certificates)
            ),
        }
        self._db.execute(
            f"INSERT INTO runs ({', '.join(_RUN_COLUMNS)})"  # noqa: S608 - fixed column names
            f" VALUES ({', '.join('?' for _ in _RUN_COLUMNS)})",
            tuple(values[name] for name in _RUN_COLUMNS),
        )
        for key, sighting in parsed.findings:
            canonical = canonical_key(key)
            existing = self._db.execute(
                "SELECT id, provenance FROM findings WHERE key = ?", (canonical,)
            ).fetchone()
            if existing is None:
                cursor = self._db.execute(
                    "INSERT INTO findings (key, server, server_version, tool_version, scenario,"
                    " statement, locator, signal, provenance)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (canonical, *(key[name] for name in KEY_FIELDS), parsed.provenance),
                )
                finding = cursor.lastrowid
            elif existing[1] != parsed.provenance:
                # The same entry at the same content, under the same scenario, cannot be a
                # reference entry in one run and a real-world one in the next. One of the two
                # labels is wrong, and filing both would put a disclosure candidate among the
                # expected findings or the other way round.
                raise StoreError(
                    f"{path}: finding {canonical} is already filed as {existing[1]!r}, "
                    f"not {parsed.provenance!r}; refusing the whole run"
                )
            else:
                finding = existing[0]
            self._db.execute(
                "INSERT OR IGNORE INTO sightings VALUES (?, ?, ?, ?, ?)",
                (finding, run, sighting.path, sighting.message_seq, int(sighting.normalized)),
            )
        self._db.execute(
            "INSERT INTO definition_runs VALUES (?, ?)",
            (run, json.dumps(parsed.definitions.listings, sort_keys=True)),
        )
        self._db.executemany(
            "INSERT INTO definitions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                (
                    run,
                    item.segment,
                    item.listing,
                    item.kind,
                    item.name,
                    item.digest,
                    json.dumps(dict(item.fields), sort_keys=True),
                    int(item.duplicate),
                )
                for item in parsed.definitions.definitions
            ),
        )

    def _admit(self, path: Path, parsed: _ParsedRun) -> str | None:
        """The customer's declaration to file the run with, once its engagement is the store's;
        refused whole where the run and the store do not belong together.

        The declaration is that of the chain entry of the run's digest, as canonical JSON, or
        None when that version of the file declared nothing. It comes from the store, never
        from the recording, which carries only the file's id, digest and window.
        """
        held = self.engagement()
        name, digest = parsed.engagement_id_declared, parsed.engagement_digest
        if held is None:
            if digest is None:
                return None
            raise StoreError(
                f"{path}: the run was made under {_named(name, digest)}; this store holds no "
                "engagement, and a store without an engagement takes only runs without one; "
                "refusing the whole run"
            )
        holds = _named(held["engagement_id_declared"], held["engagement_digest"])
        if digest is None:
            raise StoreError(
                f"{path}: the run was made under no engagement; this store holds {holds} and "
                "takes only runs made under it; refusing the whole run"
            )
        entry = next((e for e in held["chain"] if e["digest"] == digest), None)
        if entry is None:
            raise StoreError(
                f"{path}: the run was made under {_named(name, digest)}, a version this store's "
                f"chain does not hold ({len(held['chain'])} version(s) of {holds}); refusing the "
                "whole run"
            )
        filed_as = entry["file_declared"].get("id", held["engagement_id_declared"])
        if name != filed_as:
            raise StoreError(
                f"{path}: the run names engagement {name!r} with digest {digest}, but the file "
                f"of that digest is engagement {filed_as!r} in this store's chain: the recording "
                "contradicts the file it names; refusing the whole run"
            )
        declared = entry["file_declared"].get("declared")
        if declared is None:
            return None
        return json.dumps(declared, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    # -- the engagement --------------------------------------------------------------

    def set_engagement(
        self,
        *,
        engagement_id_declared: str,
        digest: str,
        file_declared: Mapping[str, Any],
        supersedes: str | None,
        delete_after_declared: str | None,
        removed: Sequence[str],
        now: datetime | None = None,
    ) -> None:
        """Make this the store of one engagement, or advance it to a new version of its file.

        One store per engagement. The store keeps the file's id,
        the digest of its current version, its ``retention.delete_after`` as declared, and a
        chain of every version it has held, oldest first:
        each with the digest of the original file's bytes — the one recordings carry — the file
        as the caller hands it over, and ``removed``: what the caller took out of it, as key
        paths (``declared.servers[].owner_contact``; mcp_kymograph.engagement.REMOVED). A file
        that still holds anything ``removed`` names is refused, so that what the entry says it
        removed is true; and so is one that holds anything of :data:`REMOVED_FROM_FILE`, whatever
        ``removed`` says.

        * A store with no engagement and nothing filed takes it.
        * A digest the chain holds already changes nothing: a run under an earlier version that
          is still in the chain may be filed.
        * A file of the same id whose ``supersedes`` is the current digest is a new version: it
          is appended to the chain and becomes current, with its ``delete_after``.
        * Anything else is refused, naming what the store holds and what it was offered: another
          engagement, a version that does not supersede the current one, and a store holding
          runs or fleets filed without an engagement — one's own runs, which do not become an
          engagement's.

        All of it in one transaction; a refusal changes nothing.
        """
        if not isinstance(engagement_id_declared, str) or not engagement_id_declared:
            raise StoreError("the engagement's id is not a non-empty string; nothing is set")
        if not _is_digest(digest):
            raise StoreError(
                f"the engagement's digest {digest!r} is not 64 lowercase hex characters; "
                "nothing is set"
            )
        offered = _named(engagement_id_declared, digest)
        if supersedes is not None and (not _is_digest(supersedes) or supersedes == digest):
            raise StoreError(
                f"{offered}: supersedes {supersedes!r}, which is not the digest of another "
                "file as 64 lowercase hex characters; nothing is set"
            )
        if delete_after_declared is not None and not isinstance(delete_after_declared, str):
            raise StoreError(f"{offered}: delete_after is not a string; nothing is set")
        if not isinstance(file_declared, Mapping):
            raise StoreError(f"{offered}: the file as declared is not a mapping; nothing is set")
        if (
            isinstance(removed, str)
            or not isinstance(removed, Sequence)
            or not all(isinstance(path, str) and path for path in removed)
            or len(set(removed)) != len(removed)
        ):
            raise StoreError(
                f"{offered}: what was removed is not a list of distinct key paths; nothing is set"
            )
        kept = [
            path
            for path in dict.fromkeys([*REMOVED_FROM_FILE, *removed])
            if _holds(file_declared, path)
        ]
        if kept:
            raise StoreError(
                f"{offered}: the file as given still holds {', '.join(kept)}, which it is said "
                "to be without or the store never keeps; nothing is set"
            )
        for name, given in (("id", engagement_id_declared), ("supersedes", supersedes)):
            if name in file_declared and file_declared[name] != given:
                raise StoreError(
                    f"{offered}: the file's {name} is {file_declared[name]!r}, not {given!r}; "
                    "nothing is set"
                )
        moment = datetime.now(timezone.utc) if now is None else now
        if moment.utcoffset() is None:
            raise StoreError(f"{offered}: the time it is set at has no time zone; nothing is set")
        entry = {
            "digest": digest,
            "file_declared": dict(file_declared),
            "removed": list(removed),
            "supersedes": supersedes,
            "set_utc": _utc(moment),
        }
        try:
            json.dumps(entry, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise StoreError(
                f"{offered}: the file as declared cannot be kept as JSON ({exc}); nothing is set"
            ) from None
        try:
            with self._db:
                # Taken before the store's engagement is read, so that the check and the write
                # see the same store.
                self._db.execute("BEGIN IMMEDIATE")
                self._set_engagement(entry, engagement_id_declared, delete_after_declared)
        except sqlite3.Error as exc:
            raise StoreError(
                f"{offered}: cannot be set ({type(exc).__name__}: {exc}); nothing is set"
            ) from None

    def _set_engagement(self, entry: dict[str, Any], name: str, delete_after: str | None) -> None:
        offered = _named(name, entry["digest"])
        held = self.engagement()
        if held is None:
            runs, fleets = self._db.execute(
                "SELECT (SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM fleets)"
            ).fetchone()
            if runs or fleets:
                raise StoreError(
                    f"this store holds {runs} run(s) and {fleets} fleet run(s) filed without an "
                    f"engagement; offered {offered}: one store per engagement, and a store of "
                    "one's own runs does not become an engagement's — give it a new store"
                )
            self._write_engagement(name, entry["digest"], delete_after, [entry])
            return
        holds = _named(held["engagement_id_declared"], held["engagement_digest"])
        if name != held["engagement_id_declared"]:
            raise StoreError(
                f"this store holds {holds}; offered {offered}: one store per engagement — "
                "another engagement goes into a store of its own"
            )
        if any(known["digest"] == entry["digest"] for known in held["chain"]):
            return
        if entry["supersedes"] != held["engagement_digest"]:
            raise StoreError(
                f"this store holds {holds}; offered {offered}, which supersedes "
                f"{entry['supersedes'] or 'no earlier version'}: a new version of the file must "
                "supersede the store's current one"
            )
        self._write_engagement(name, entry["digest"], delete_after, [*held["chain"], entry])

    def _write_engagement(
        self, name: str, digest: str, delete_after: str | None, chain: list[dict[str, Any]]
    ) -> None:
        rows = {
            "engagement_id_declared": name,
            "engagement_digest": digest,
            "engagement_chain": json.dumps(chain, allow_nan=False),
            "delete_after_declared": delete_after,
        }
        for row, value in rows.items():
            if value is None:
                self._db.execute("DELETE FROM meta WHERE name = ?", (row,))
            else:
                self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (row, value))

    def engagement(self) -> dict[str, Any] | None:
        """The store's engagement as ``meta`` holds it, or None for a store without one: the
        file's id, the current version's digest, ``delete_after`` as declared (None when the
        file declares none), and the chain of every version, oldest first."""
        return _engagement(self._db)

    # -- reading ---------------------------------------------------------------------

    def resolve(self, reference: str) -> str:
        """A run by its id, an unambiguous prefix of it (8+ characters), or its recording."""
        candidate = Path(reference)
        if candidate.exists():
            run = hashlib.sha256(_events_path(candidate).read_bytes()).hexdigest()
            if not self._db.execute("SELECT 1 FROM runs WHERE run = ?", (run,)).fetchone():
                raise StoreError(f"{reference}: this recording is not in the store")
            return run
        if len(reference) < 8:
            raise StoreError(f"{reference!r}: give at least 8 characters of a run id")
        rows = self._db.execute(
            "SELECT run FROM runs WHERE run LIKE ? ESCAPE '\\'",
            (reference.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",),
        ).fetchall()
        if not rows:
            raise StoreError(f"{reference!r}: no such run in the store")
        if len(rows) > 1:
            raise StoreError(f"{reference!r}: matches {len(rows)} runs; give more of the id")
        return rows[0][0]

    def run_info(self, run: str) -> RunInfo:
        row = self._db.execute(
            f"SELECT {', '.join(_RUN_COLUMNS)} FROM runs WHERE run = ?",  # noqa: S608 - fixed
            (run,),
        ).fetchone()
        if row is None:
            raise StoreError(f"{run}: no such run in the store")
        values = dict(zip(_RUN_COLUMNS, row, strict=True))
        return RunInfo(
            run=values["run"],
            provenance=values["provenance"],
            server=values["server"],
            announced_server=values["announced_server"],
            server_version=values["server_version"],
            launch_digest=values["launch_digest"],
            tool_version=values["tool_version"],
            tool_content=values["tool_content"],
            scenario=values["scenario"],
            scenario_digest=values["scenario_digest"],
            isolation=values["isolation"],
            sandbox_image=values["sandbox_image"],
            target_image=values["target_image"],
            statements=frozenset(tuple(pair) for pair in json.loads(values["statements"])),
            state=values["state"],
            problem_count=values["problem_count"],
            problems=tuple(json.loads(values["problems"])),
            truncations=tuple(json.loads(values["truncations"])),
            causes=tuple(json.loads(values["causes"])),
            rules=values["rules"],
            engagement_id_declared=values["engagement_id_declared"],
            engagement_digest=values["engagement_digest"],
            engagement_declared=(
                None
                if values["engagement_declared"] is None
                else json.loads(values["engagement_declared"])
            ),
            server_identity_kind=values["server_identity_kind"],
            endpoint_certificates=(
                None
                if values["endpoint_certificates"] is None
                else tuple(json.loads(values["endpoint_certificates"]))
            ),
        )

    def runs(self) -> list[RunInfo]:
        rows = self._db.execute("SELECT run FROM runs ORDER BY wall_clock_utc, run").fetchall()
        return [self.run_info(row[0]) for row in rows]

    def recordings(self) -> dict[str, str]:
        """Each run's recording, by run: the path as it was given at ingest, which may be
        relative to wherever ingest ran. Not in :class:`RunInfo`, which says what a run is,
        not where it was read from."""
        return dict(self._db.execute("SELECT run, recording FROM runs").fetchall())

    def findings_of(self, run: str) -> dict[tuple, tuple[dict[str, Any], tuple[Sighting, ...]]]:
        """Every finding sighted in a run, by identity: its full key and its sightings."""
        rows = self._db.execute(
            "SELECT f.key, s.path, s.message_seq, s.normalized FROM sightings s"
            " JOIN findings f ON f.id = s.finding WHERE s.run = ?"
            " ORDER BY f.key, s.message_seq, s.path",
            (run,),
        ).fetchall()
        result: dict[tuple, tuple[dict[str, Any], list[Sighting]]] = {}
        for canonical, path, message_seq, normalized in rows:
            key = dict(zip(KEY_FIELDS, json.loads(canonical), strict=True))
            identity = tuple(key[name] for name in IDENTITY_FIELDS)
            entry = result.setdefault(identity, (key, []))
            entry[1].append(Sighting(path, message_seq, bool(normalized)))
        return {identity: (key, tuple(seen)) for identity, (key, seen) in result.items()}

    # -- fleets ---------------------------------------------------------------------

    def file_fleet(self, fleet: dict[str, Any], results: Sequence[dict[str, Any]]) -> None:
        """File one fleet run and its result per entry and scenario. All of it, or none.

        The store keeps what the fleet says; it decides nothing about it. Each result points
        at the run it filed, if any — the findings stay where every run's findings are.
        """
        columns = (
            "fleet", "started_utc", "finished_utc", "manifest_source", "manifest_digest",
            "tool_version", "tool_content", "isolation", "sandbox_image", "target_image",
            "parallel", "processed", "digest", "complete", "problems", "rules",
        )  # fmt: skip
        try:
            with self._db:
                self._db.execute(
                    f"INSERT INTO fleets ({', '.join(columns)})"  # noqa: S608 - fixed names
                    f" VALUES ({', '.join('?' for _ in columns)})",
                    tuple(fleet[name] for name in columns),
                )
                for result in results:
                    self._db.execute(
                        "INSERT INTO fleet_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            fleet["fleet"],
                            result["entry"],
                            result["scenario"],
                            result["provenance"],
                            result["state"],
                            result["exit_code"],
                            result["run"],
                            json.dumps(list(result["problems"])),
                            json.dumps(list(result.get("causes", ()))),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"fleet {fleet['fleet']}: {exc}") from None

    def fleets(self) -> list[dict[str, Any]]:
        """Every fleet run, oldest first, without its results."""
        rows = self._db.execute("SELECT fleet FROM fleets ORDER BY started_utc, fleet").fetchall()
        return [self.fleet(row[0]) for row in rows]

    def fleet(self, fleet: str) -> dict[str, Any]:
        """One fleet run, with its results keyed by ``(entry, scenario)``."""
        cursor = self._db.execute("SELECT * FROM fleets WHERE fleet = ?", (fleet,))
        row = cursor.fetchone()
        if row is None:
            raise StoreError(f"{fleet}: no such fleet run in the store")
        info = dict(zip([d[0] for d in cursor.description], row, strict=True))
        info["processed"] = [tuple(pair) for pair in json.loads(info["processed"])]
        info["problems"] = json.loads(info["problems"])
        info["complete"] = bool(info["complete"])
        results = {}
        for (
            entry,
            scenario,
            provenance,
            state,
            exit_code,
            run,
            problems,
            causes,
        ) in self._db.execute(
            "SELECT entry, scenario, provenance, state, exit_code, run, problems, causes"
            " FROM fleet_results WHERE fleet = ? ORDER BY entry, scenario",
            (fleet,),
        ):
            results[(entry, scenario)] = {
                "entry": entry,
                "scenario": scenario,
                "provenance": provenance,
                "state": state,
                "exit_code": exit_code,
                "run": run,
                "problems": json.loads(problems),
                "causes": json.loads(causes),
            }
        info["results"] = results
        return info

    def resolve_fleet(self, reference: str) -> str:
        """A fleet run by its id or an unambiguous prefix of it."""
        rows = self._db.execute(
            "SELECT fleet FROM fleets WHERE fleet LIKE ? ESCAPE '\\'",
            (reference.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",),
        ).fetchall()
        if not rows:
            raise StoreError(f"{reference!r}: no such fleet run in the store")
        if len(rows) > 1:
            raise StoreError(f"{reference!r}: matches {len(rows)} fleet runs; give more of it")
        return rows[0][0]

    def findings_by_provenance(self, provenance: str) -> list[dict[str, Any]]:
        """Every filed finding of one provenance — the disclosure candidates, for real-world —
        as its key, with ``server_version_kind`` beside it (:meth:`_version_kinds`)."""
        rows = self._db.execute(
            "SELECT id, key FROM findings WHERE provenance = ? ORDER BY key", (provenance,)
        ).fetchall()
        kinds = self._version_kinds([row[0] for row in rows])
        return [
            {
                **dict(zip(KEY_FIELDS, json.loads(key), strict=True)),
                "server_version_kind": kinds[finding],
            }
            for finding, key in rows
        ]

    def _version_kinds(self, findings: Sequence[int]) -> dict[int, str]:
        """The kind of each finding's ``server_version``. A finding's key does not carry it; the
        runs that sighted the finding do. They share its server and version, so they should
        agree — where they do not, the kind is ``mixed``, never one of them picked."""
        seen: dict[int, set[str]] = {finding: set() for finding in findings}
        for finding, kind in self._db.execute(
            "SELECT DISTINCT s.finding, r.server_identity_kind FROM sightings s"
            " JOIN runs r ON r.run = s.run"
        ):
            if finding in seen:
                seen[finding].add(version_kind(kind))
        return {
            finding: (next(iter(kinds)) if len(kinds) == 1 else MIXED if kinds else UNKNOWN)
            for finding, kinds in seen.items()
        }

    # -- triage ----------------------------------------------------------------------

    def triage_set(
        self,
        *,
        identity: Mapping[str, Any] | None = None,
        finding: int | None = None,
        role: str,
        status: str,
        author: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record one decision on a finding's identity, in one role, and return it as read back.

        Triage is kept beside the findings, never in them: a
        decision is a row of its own, keyed by the identity — the five fields a comparison
        matches on, as ``store diff`` prints them — with its author and its role. No reason is
        kept: it belongs in the operator's private notes (``mcp_kymograph.operator_notes``).
        ``finding`` names the identity by the id of any finding that has it, for a locator a
        terminal cannot carry whole. The store fills what it knows: the row this one supersedes
        (the current one of that identity and role, or None), the store's engagement digest
        (or None), and the time. A row is never changed and never deleted; a new decision is a
        new row, and the database itself refuses anything else.

        Refused whole, writing nothing: not exactly one of ``identity`` and ``finding``; an
        identity no finding in the store has, or an unknown finding id; an unknown role, or a
        status that role may not set (:data:`TRIAGE_STATUSES`); an empty author;
        text with a character ``cli.display`` drops; text past its cap (:data:`TRIAGE_CAPS`).
        """
        if (identity is None) == (finding is None):
            raise _triage_refused("name the finding by its identity or by its id, exactly one")
        if not isinstance(role, str) or role not in TRIAGE_ROLES:
            raise _triage_refused(f"role {role!r} is not one of {', '.join(TRIAGE_ROLES)}")
        if not isinstance(status, str) or status not in TRIAGE_STATUSES[role]:
            raise _triage_refused(
                f"status {status!r} is not one the {role} may set; the {role} may set "
                f"{', '.join(sorted(TRIAGE_STATUSES[role]))}"
            )
        _triage_text("author", author)
        moment = datetime.now(timezone.utc) if now is None else now
        if moment.utcoffset() is None:
            raise _triage_refused("the time has no time zone")
        values = None if identity is None else _identity_values(identity)
        if finding is not None and (isinstance(finding, bool) or not isinstance(finding, int)):
            raise _triage_refused("a finding is named by its id, a whole number")
        try:
            with self._db:
                # Taken before the current row is read, so that the row this one supersedes is
                # still the current one when it is written.
                self._db.execute("BEGIN IMMEDIATE")
                values = self._identity_of(finding) if values is None else values
                if not self._db.execute(
                    "SELECT 1 FROM findings WHERE server = ? AND scenario = ? AND statement = ?"
                    " AND locator = ? AND signal = ? LIMIT 1",
                    values,
                ).fetchone():
                    named = json.dumps(dict(zip(IDENTITY_FIELDS, values, strict=True)))
                    raise _triage_refused(f"no finding in this store has the identity {named}")
                canonical = _identity_key(values)
                current = self._db.execute(
                    "SELECT MAX(id) FROM triage WHERE identity = ? AND role = ?",
                    (canonical, role),
                ).fetchone()[0]
                held = self.engagement()
                written = self._insert_triage(
                    canonical,
                    role,
                    status,
                    author,
                    _utc(moment),
                    None if held is None else held["engagement_digest"],
                    current,
                )
        except sqlite3.Error as exc:
            raise _triage_refused(f"cannot be written ({type(exc).__name__}: {exc})") from None
        (row,) = self._triage_rows("WHERE id = ?", (written,))
        return row

    def _insert_triage(self, *values: Any) -> int:
        """Write one triage row, the columns of :data:`_TRIAGE_COLUMNS` after ``id``, as given;
        its id is the store's own. Every check is the caller's, in the caller's transaction."""
        cursor = self._db.execute(
            f"INSERT INTO triage ({', '.join(_TRIAGE_COLUMNS[1:])})"  # noqa: S608 - fixed names
            f" VALUES ({', '.join('?' for _ in _TRIAGE_COLUMNS[1:])})",
            values,
        )
        return cursor.lastrowid

    def import_triage(
        self, document: Any, *, source_sha256: str, now: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Carry the triage of an export (:func:`export_triage`) into this store, and return
        every row as read back, with this store's ids.

        For a store of this schema made from the same recordings as the one exported — a store
        of the previous schema is not read, and its triage is what a person wrote and no run can
        produce again (docs/design/http-transport.md 8.4). The rows go in in the file's order,
        each with its recorded ``at_utc``, author, role and engagement digest; ``supersedes`` is
        mapped to this store's id of the row it names. A ``meta`` row ``triage_imports`` (a JSON
        list of ``{file_sha256, store_sha256, store_schema, rows, first_id, at_utc}``: the file's
        SHA-256 as ``source_sha256`` gives it, the exported store's SHA-256 and schema as the file
        names them, how many rows it carried, the id of the first of them here, when) says that
        the rows were carried here, not written here; every row read from the store says so in
        its ``imported`` (:meth:`triage_imports`).

        Refused whole, writing nothing: a store that holds a triage row already; a document that
        is not an export of :data:`TRIAGE_EXPORT_VERSION` from a store of
        :data:`TRIAGE_EXPORT_SCHEMAS`; a row that is not one — every check
        :meth:`triage_set` makes, an ``at_utc`` not as the store writes one, a ``supersedes``
        that names no earlier row of the file or not the decision of the same identity and role
        before it; an identity no finding in this store has; an engagement digest this store's
        chain does not hold, or one where the store holds none and the other way round. The
        chain comes from ``store ingest --engagement FILE``, each version of the file in order,
        before the import: it is never made here.
        """
        if not _is_digest(source_sha256):
            raise _import_refused("the file's SHA-256 is not 64 lowercase hex characters")
        rows = _export_rows(document, _import_refused)
        moment = datetime.now(timezone.utc) if now is None else now
        if moment.utcoffset() is None:
            raise _import_refused("the time has no time zone")
        try:
            with self._db:
                # Taken before anything is read, so that the store checked is the store written.
                self._db.execute("BEGIN IMMEDIATE")
                self._import_rows(document, rows, source_sha256, _utc(moment))
        except sqlite3.Error as exc:
            raise _import_refused(f"cannot be written ({type(exc).__name__}: {exc})") from None
        return self.triage_history()

    def _import_rows(
        self, document: dict[str, Any], rows: list[dict[str, Any]], source: str, at_utc: str
    ) -> None:
        held = self._db.execute("SELECT COUNT(*) FROM triage").fetchone()[0]
        if held:
            raise _import_refused(
                f"this store holds {held} triage row(s) already; triage is carried only into a "
                "store that holds none"
            )
        engagement = self.engagement()
        chain = [] if engagement is None else [entry["digest"] for entry in engagement["chain"]]
        for row in rows:
            values = tuple(row["identity"][name] for name in IDENTITY_FIELDS)
            if not self._db.execute(
                "SELECT 1 FROM findings WHERE server = ? AND scenario = ? AND statement = ?"
                " AND locator = ? AND signal = ? LIMIT 1",
                values,
            ).fetchone():
                raise _import_refused(
                    f"row {row['id']}: no finding in this store has the identity "
                    f"{json.dumps(row['identity'])}; ingest the same recordings first"
                )
            problem = _digest_problem(
                row["engagement_digest"], chain, "this store's engagement chain"
            )
            if problem is not None:
                raise _import_refused(
                    f"row {row['id']}: {problem}; give the store its engagement first — store "
                    "ingest --engagement FILE, each version of the file in order"
                )
        ids: dict[int, int] = {}
        for row in rows:
            ids[row["id"]] = self._insert_triage(
                _identity_key(tuple(row["identity"][name] for name in IDENTITY_FIELDS)),
                row["role"],
                row["status"],
                row["author"],
                row["at_utc"],
                row["engagement_digest"],
                None if row["supersedes"] is None else ids[row["supersedes"]],
            )
        try:
            imports = self.triage_imports()
        except StoreError as refusal:
            raise _import_refused(str(refusal)) from None
        imports.append(
            {
                "file_sha256": source,
                "store_sha256": document["store_sha256"],
                "store_schema": document["store_schema"],
                "rows": len(rows),
                "first_id": min(ids.values()) if ids else None,
                "at_utc": at_utc,
            }
        )
        self._db.execute(
            "INSERT OR REPLACE INTO meta VALUES ('triage_imports', ?)", (json.dumps(imports),)
        )

    def triage_current(self) -> list[dict[str, Any]]:
        """The current decision of each identity and role — the latest row of each — ordered by
        identity, then role. Both roles' rows stand side by side."""
        return self._triage_rows(
            "WHERE id IN (SELECT MAX(id) FROM triage GROUP BY identity, role)"
            " ORDER BY identity, role"
        )

    def triage_history(self, identity: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """Every decision, in the order it was made — of one identity, when one is given."""
        if identity is None:
            return self._triage_rows("ORDER BY id")
        return self._triage_rows(
            "WHERE identity = ? ORDER BY id", (_identity_key(_identity_values(identity)),)
        )

    def findings_with_triage(self, provenance: str) -> list[dict[str, Any]]:
        """Every filed finding of one provenance, as :meth:`findings_by_provenance` gives it,
        with its id (``finding``), its ``finding_key`` and the current decision of each role
        beside it (``triage``, None where that role has made none)."""
        rows = self._db.execute(
            "SELECT id, key FROM findings WHERE provenance = ? ORDER BY key", (provenance,)
        ).fetchall()
        kinds = self._version_kinds([row[0] for row in rows])
        current = self._current_by_identity()
        listed = []
        for finding, key in rows:
            named = dict(zip(KEY_FIELDS, json.loads(key), strict=True))
            identity = _identity_key(tuple(named[name] for name in IDENTITY_FIELDS))
            listed.append(
                {
                    **named,
                    "server_version_kind": kinds[finding],
                    "finding": finding,
                    "finding_key": finding_key(tuple(named[name] for name in IDENTITY_FIELDS)),
                    "triage": {role: current.get((identity, role)) for role in TRIAGE_ROLES},
                }
            )
        return listed

    def _current_by_identity(self) -> dict[tuple[str, str], dict[str, Any]]:
        """The current rows by (identity as stored, role)."""
        return {
            (_identity_key(tuple(row["identity"][n] for n in IDENTITY_FIELDS)), row["role"]): row
            for row in self.triage_current()
        }

    def _identity_of(self, finding: int) -> tuple[str, ...]:
        row = self._db.execute(
            "SELECT server, scenario, statement, locator, signal FROM findings WHERE id = ?",
            (finding,),
        ).fetchone()
        if row is None:
            raise _triage_refused(f"no finding {finding} in this store")
        return tuple(row)

    def triage_imports(self) -> list[dict[str, Any]]:
        """Every import of triage into this store (:meth:`import_triage`), in the order made, as
        its ``meta`` row ``triage_imports`` holds them; none when nothing was carried here.
        Refused, as a store whose rows' origin cannot be told: a row that is not such a list."""
        found = self._db.execute("SELECT value FROM meta WHERE name = 'triage_imports'").fetchone()
        if found is None:
            return []
        try:
            imports = json.loads(found[0])
        except (TypeError, ValueError):
            imports = None
        if not (isinstance(imports, list) and all(map(_is_import_entry, imports))):
            raise StoreError(
                "the store's triage_imports row is not a list of imports as this version "
                "writes them: which triage rows were carried here cannot be told"
            )
        return imports

    def _triage_rows(self, where: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
        """Triage rows, each with ``imported``: None for a row written here, or where a row
        carried here came from — ``{file_sha256, store_sha256, store_schema, at_utc}`` of its
        import."""
        rows = self._db.execute(
            f"SELECT {', '.join(_TRIAGE_COLUMNS)} FROM triage {where}",  # noqa: S608 - fixed text
            tuple(parameters),
        ).fetchall()
        imports = self.triage_imports() if rows else []
        result = []
        for row in rows:
            values = dict(zip(_TRIAGE_COLUMNS, row, strict=True))
            values["identity"] = dict(
                zip(IDENTITY_FIELDS, json.loads(values["identity"]), strict=True)
            )
            values["finding_key"] = finding_key(tuple(values["identity"].values()))
            values["imported"] = _imported(values["id"], imports)
            result.append(values)
        return result

    # -- a server over time ------------------------------------------------------------

    def history(self, server: str) -> dict[str, Any]:
        """Every identity of one server's findings, column by column: each fleet that ran the
        server, in the order the fleets ran, then each run of it filed outside a fleet, in the
        order it was made.

        A cell says what the store holds and nothing more, and never that a run saw nothing
        where it could not have reported the finding:

        * ``sighted`` — the column's run sighted a finding of the identity (in any state);
        * ``not_a_result`` — the run is no result to go by: incomplete, failed, refused or
          unfiled, its state beside it;
        * ``not_asked`` — a complete run whose scenario did not ask the identity's statement
          for its signal (a comparison's ``statement_removed``);
        * ``capped`` — a complete run that cut findings of that statement and signal at the
          per-message cap: the finding may be among those cut (a comparison's
          ``capped_after``);
        * ``listing_capped`` — a complete run that cut a listing at the driver's page limit:
          what lay past it was not looked at (a comparison's ``listing_capped``);
        * ``not_sighted`` — a complete run that asked, cut nothing of it and listed in full,
          and did not sight it;
        * ``not_run`` — the column ran nothing of the identity's scenario.

        Beside the cells: the first and last time a run sighted the identity, every server
        version it was sighted under with the kind of each, and the current triage rows.
        """
        runs = {info.run: info for info in self.runs() if info.server == server}
        if not runs:
            raise StoreError(f"{server!r}: no run of this server in the store")
        columns: list[dict[str, Any]] = []
        # Per column, what it ran of each scenario: (run or None, state).
        ran: list[dict[str, tuple[str | None, str]]] = []
        in_fleets: set[str] = set()
        for fleet in self.fleets():
            results = {
                scenario: (result["run"], result["state"])
                for (entry, scenario), result in self.fleet(fleet["fleet"])["results"].items()
                if entry == server
            }
            if not results:
                continue
            in_fleets.update(run for run, _ in results.values() if run is not None)
            columns.append(
                {"kind": "fleet", "fleet": fleet["fleet"], "started_utc": fleet["started_utc"]}
            )
            ran.append(results)
        for info in runs.values():  # runs() is ordered by wall clock
            if info.run in in_fleets:
                continue
            columns.append(
                {"kind": "run", "run": info.run, "wall_clock_utc": self._wall_clock(info.run)}
            )
            ran.append({info.scenario: (info.run, info.state)})

        rows = self._db.execute(
            "SELECT f.id, f.key, s.run FROM findings f JOIN sightings s ON s.finding = f.id"
            " WHERE f.server = ? ORDER BY f.key",
            (server,),
        ).fetchall()
        sighted: dict[tuple, set[str]] = {}
        # Per identity and server version: the findings with it, and when it was sighted.
        versions: dict[tuple, dict[str, tuple[set[int], list[str]]]] = {}
        for finding, key, run in rows:
            named = dict(zip(KEY_FIELDS, json.loads(key), strict=True))
            identity = tuple(named[name] for name in IDENTITY_FIELDS)
            sighted.setdefault(identity, set()).add(run)
            ids, times = versions.setdefault(identity, {}).setdefault(
                named["server_version"], (set(), [])
            )
            ids.add(finding)
            moment = self._wall_clock(run)
            if moment is not None:
                times.append(moment)
        kinds = self._version_kinds(
            [f for by in versions.values() for ids, _ in by.values() for f in ids]
        )
        current = self._current_by_identity()
        identities = []
        for identity in sorted(sighted, key=_order):
            named = dict(zip(IDENTITY_FIELDS, identity, strict=True))
            times = sorted(t for _, seen in versions[identity].values() for t in seen)
            canonical = _identity_key(identity)
            identities.append(
                {
                    "identity": named,
                    "cells": [
                        _cell(column.get(named["scenario"]), named, sighted[identity], runs)
                        for column in ran
                    ],
                    "first_utc": times[0] if times else None,
                    "last_utc": times[-1] if times else None,
                    # In the order each was first sighted; one never sighted at a known time last.
                    "server_versions": [
                        {
                            "server_version": version,
                            "server_version_kind": _one_kind([kinds[f] for f in ids]),
                        }
                        for version, (ids, seen) in sorted(
                            versions[identity].items(),
                            key=lambda item: (not item[1][1], min(item[1][1], default=""), item[0]),
                        )
                    ],
                    "triage": {role: current.get((canonical, role)) for role in TRIAGE_ROLES},
                }
            )
        return {"server": server, "columns": columns, "identities": identities}

    def _wall_clock(self, run: str) -> str | None:
        row = self._db.execute("SELECT wall_clock_utc FROM runs WHERE run = ?", (run,)).fetchone()
        return None if row is None else row[0]

    # -- bundles ---------------------------------------------------------------------

    def file_bundle(
        self,
        *,
        index_digest: str,
        path: str,
        packed_utc: str,
        derived_from: str | None,
        engagement_digest: str | None,
    ) -> None:
        """Name one bundle packed from this store, by the SHA-256 of its index:
        where it was written, when, the bundle it was derived from, and the engagement it was
        packed under. A bundle is filed once; the row touches no run, finding or sighting.
        Refused whole, writing nothing, when a value is not one."""
        where = "bundle"
        if not _is_digest(index_digest):
            raise _bundle_refused(where, "index_digest is not 64 lowercase hex characters")
        where = f"bundle {index_digest}"
        for name, value in (
            ("derived_from", derived_from),
            ("engagement_digest", engagement_digest),
        ):
            if value is not None and not _is_digest(value):
                raise _bundle_refused(where, f"{name} is not 64 lowercase hex characters")
        if derived_from == index_digest:
            raise _bundle_refused(where, "a bundle is not derived from itself")
        for name, value in (("path", path), ("packed_utc", packed_utc)):
            if not isinstance(value, str) or not value:
                raise _bundle_refused(where, f"{name} is not a non-empty string")
        try:
            with self._db:
                self._db.execute(
                    "INSERT INTO bundles (index_digest, path, packed_utc, derived_from,"
                    " engagement_digest) VALUES (?, ?, ?, ?, ?)",
                    (index_digest, path, packed_utc, derived_from, engagement_digest),
                )
        except sqlite3.IntegrityError:
            raise _bundle_refused(
                where, "already filed; a bundle is filed once, by the digest of its index"
            ) from None
        except sqlite3.Error as exc:
            raise _bundle_refused(
                where, f"cannot be written ({type(exc).__name__}: {exc})"
            ) from None

    def bundles(self) -> list[dict[str, Any]]:
        """Every bundle filed, in the order it was packed."""
        columns = ("index_digest", "path", "packed_utc", "derived_from", "engagement_digest")
        rows = self._db.execute(
            f"SELECT {', '.join(columns)} FROM bundles"  # noqa: S608 - fixed names
            " ORDER BY packed_utc, index_digest"
        ).fetchall()
        return [dict(zip(columns, row, strict=True)) for row in rows]

    def backup_into(self, target: sqlite3.Connection) -> None:
        """Copy the whole store, as it is at this moment, into ``target`` — a connection the
        caller opened, to a file it chose — through SQLite's backup API.

        Every page is copied in one step, under one read transaction on this store, so the copy
        is one state of it and never a mix of two; a store opened read-only is read and nothing
        of it is written. What ``target`` held before is replaced. Where the copy goes and with
        which mode is the caller's to decide; a copy that cannot be made is refused.
        """
        try:
            self._db.backup(target, pages=-1)
        except sqlite3.Error as exc:
            raise StoreError(
                f"the store cannot be copied ({type(exc).__name__}: {exc}); the copy is not "
                "to be used"
            ) from None

    # -- comparing -------------------------------------------------------------------

    def diff(self, before: str, after: str) -> Diff:
        """New, gone and unchanged between two runs, with what moved between them."""
        return compare_runs(self, before, self, after)

    def definitions_of(self, run: str) -> definitions.Recorded | None:
        """The definitions the run's ``*/list`` answers held, or None for a run filed before they
        were kept — ``not captured``, which is not the same as having none."""
        self.run_info(run)
        # First, as Store.open does: a definition table of another shape is refused even where
        # the other table is missing, never read as "not captured".
        stale = _stale_definition_tables(self._db)
        if stale is not None:
            raise StoreError(stale)
        tables = {
            row[0]
            for row in self._db.execute(
                "SELECT name FROM sqlite_master WHERE name IN ('definition_runs', 'definitions')"
            )
        }
        if tables != {"definition_runs", "definitions"}:
            return None  # a store of this schema opened read-only, made before the tables
        found = self._db.execute(
            "SELECT listings FROM definition_runs WHERE run = ?", (run,)
        ).fetchone()
        if found is None:
            return None
        rows = self._db.execute(
            "SELECT kind, name, digest, fields, segment, listing, duplicate FROM definitions"
            " WHERE run = ? ORDER BY kind, segment, listing, name, digest",
            (run,),
        )
        return definitions.Recorded(
            json.loads(found[0]),
            [
                definitions.Definition(
                    kind, name, digest, json.loads(fields), segment, listing, bool(dup)
                )
                for kind, name, digest, fields, segment, listing, dup in rows
            ],
        )

    def definition_diff(self, before: str, after: str) -> dict[str, Any]:
        """What changed in the definitions between two runs of one corpus entry, and within each
        run (:func:`mcp_kymograph.definitions.compare`). An observation, not a finding."""
        first, second = self.run_info(before), self.run_info(after)
        return definitions.compare(
            self.definitions_of(before),
            self.definitions_of(after),
            same_entry=first.server == second.server,
        )

    def definition_summary(self, run: str) -> dict[str, Any] | None:
        """Per kind, how many definitions the run listed and what it saw of ``list_changed``;
        None for a run whose definitions were not captured."""
        held = self.definitions_of(run)
        if held is None:
            return None
        return {
            kind: {
                "definitions": sum(1 for item in held.definitions if item.kind == kind),
                "segments": held.segments(kind),
                "partial": [meta["reasons"] for meta in entry["listings"] if not meta["complete"]],
                "list_changed": entry.get("list_changed"),
            }
            for kind, entry in held.listings.items()
        }


def compare_runs(first_store: Store, before: str, second_store: Store, after: str) -> Diff:
    """New, gone and unchanged between a run of one store and a run of another, with what moved
    between them — :meth:`Store.diff` across two stores, which it is with the same store twice.

    Each side is read whole from its own store: the run as filed there (its axes, its rules,
    the kind of its version, its environment, its caps and statements) and the findings it
    sighted. Nothing of one side is looked up in the other's store, so a run of this
    engagement's store compares with one in an earlier bundle's copy, either opened read-only.
    A run a store does not hold is refused there, as :meth:`Store.run_info` refuses it.
    """
    first, second = first_store.run_info(before), second_store.run_info(after)
    old, new = first_store.findings_of(before), second_store.findings_of(after)
    added = sorted(new.keys() - old.keys(), key=_order)
    lost = sorted(old.keys() - new.keys(), key=_order)
    kept = sorted(old.keys() & new.keys(), key=_order)
    axes = _axes(first, second)
    drift = axes["scenario"]["moved"]
    elsewhere = axes["environment"]["moved"]
    appeared = tuple(
        _compared(
            i,
            None,
            new[i],
            _hint(i, first.statements, "statement_added"),
            _cap_hint(i, first.cut_statements, "capped_before"),
        )
        for i in added
    )
    vanished = tuple(
        _compared(
            i,
            old[i],
            None,
            _hint(i, second.statements, "statement_removed"),
            _cap_hint(i, second.cut_statements, "capped_after"),
        )
        for i in lost
    )
    listing = (LISTING_CAPPED,) if first.listing_capped or second.listing_capped else ()
    # An endpoint's version is declared, never pinned (http-transport.md 4.2): said beside each
    # set, as the report says it; the attribution is left as the axes give it.
    unpinned = "declared" in (first.server_version_kind, second.server_version_kind)
    # Compared as sets, never as an axis (http-transport.md 8.4): two sets that share no
    # certificate are said beside both sets, as a drift is, and the attribution stays as the axes
    # give it. A side without TLS, or whose set is empty, presented nothing to compare.
    held, offered = first.endpoint_certificates, second.endpoint_certificates
    rotated = bool(held) and bool(offered) and set(held or ()).isdisjoint(offered or ())
    return Diff(
        before=first,
        after=second,
        new=appeared,
        gone=vanished,
        unchanged=tuple(_compared(i, old[i], new[i], None) for i in kept),
        axes=axes,
        attribution=_attribute(first, second, axes, bool(added or lost)),
        caveats={
            name: (
                ((SCENARIO_DRIFT,) if drift else ())
                + ((ENVIRONMENT_MOVED,) if elsewhere and entries else ())
                + ((FINDINGS_CAPPED,) if any(c.cap_hint for c in entries) else ())
                + (listing if entries else ())
                + ((SERVER_UNPINNED,) if unpinned and entries else ())
                + ((CERTIFICATE_CHANGED,) if rotated else ())
            )
            for name, entries in (("new", appeared), ("gone", vanished))
        },
    )


def _order(identity: tuple) -> str:
    return json.dumps(identity)


def _compared(
    identity: tuple,
    old: tuple | None,
    new: tuple | None,
    hint: str | None,
    cap_hint: str | None = None,
) -> Compared:
    return Compared(
        identity=dict(zip(IDENTITY_FIELDS, identity, strict=True)),
        before=None if old is None else old[0],
        after=None if new is None else new[0],
        seen_before=() if old is None else old[1],
        seen_after=() if new is None else new[1],
        statement_hint=hint,
        cap_hint=cap_hint,
    )


def _cap_hint(identity: tuple, cut: frozenset[tuple[str, str]], hint: str) -> str | None:
    """The hint, when the other run cut findings of this statement and signal at the cap."""
    named = dict(zip(IDENTITY_FIELDS, identity, strict=True))
    return hint if (named["statement"], named["signal"]) in cut else None


def _hint(identity: tuple, other_side: frozenset[tuple[str, str]], hint: str) -> str | None:
    """The hint, when the other run's scenario never asked this statement for this signal."""
    named = dict(zip(IDENTITY_FIELDS, identity, strict=True))
    return None if (named["statement"], named["signal"]) in other_side else hint


def _axes(first: RunInfo, second: RunInfo) -> dict[str, dict[str, Any]]:
    """Each axis: whether it moved, and every field of it with both values."""
    result: dict[str, dict[str, Any]] = {}
    for axis, names in AXES.items():
        fields = {
            name: {"before": getattr(first, name), "after": getattr(second, name)} for name in names
        }
        moved = any(value["before"] != value["after"] for value in fields.values())
        result[axis] = {"moved": moved, **fields}
    return result


def _attribute(
    first: RunInfo, second: RunInfo, axes: dict[str, dict[str, Any]], differs: bool
) -> Attribution:
    """Name the axis a difference belongs to, or say plainly why none can be named."""
    if first.server != second.server:
        return Attribution(
            False,
            None,
            f"different corpus entries ({first.server!r}, {second.server!r}): not one target "
            "over time, so nothing here is a change of it",
        )
    moved = [name for name, axis in axes.items() if axis["moved"]]
    if moved == ["environment"] and differs:
        return Attribution(
            True,
            "environment",
            "only the environment axis moved: findings are not expected to depend on where "
            "they were observed, so this difference is not the server's — flagged, not "
            "attributed to it",
        )
    if len(moved) == 1:
        return Attribution(True, moved[0], f"only the {moved[0]} axis moved")
    if not moved:
        if differs:
            return Attribution(
                False,
                None,
                "nothing recorded moved, yet findings differ: no recorded change explains them",
            )
        return Attribution(True, None, "nothing moved, and nothing differs")
    return Attribution(
        False,
        None,
        f"several axes moved ({', '.join(moved)}): a new or gone finding cannot be put down "
        "to any one of them",
    )


# -- carrying triage across a schema step --------------------------------------------------


def export_triage(path: str | Path) -> dict[str, Any]:
    """The triage of the store at ``path`` as a document :meth:`Store.import_triage` takes:
    ``{"triage_export_version": 1, "store_schema", "store_sha256", "engagement_chain_digests",
    "rows"}``, the rows as the ``triage`` table holds them (``store triage list --history``
    without ``imported``), in ``id`` order. ``store_sha256`` is the SHA-256 of the store file's
    bytes, read inside the same read transaction, so the store a row is later said to come from
    is the one it was read from.

    The one reader of a store of an earlier schema (:data:`TRIAGE_EXPORT_SCHEMAS`), and only to
    carry what a person wrote and no run can produce again (docs/design/http-transport.md 8.4).
    It reads the ``meta`` rows of the schema and the engagement and the whole ``triage`` table,
    and nothing else, through its own ``mode=ro`` connection, in one read transaction. Refused
    whole: a store of any other schema, a missing table, engagement rows that do not fit
    together, a row that is not one (every check the import makes of a row by itself).
    """
    return export_triage_counting(path)[0]


def export_triage_counting(path: str | Path) -> tuple[dict[str, Any], dict[str, int]]:
    """:func:`export_triage`, and with it how many rows of the store hold a ``rationale`` and a
    ``severity`` that the export leaves out (both 0 for a store of this schema; a column the
    store lacks counts 0). Counted in the same connection and the same read transaction as the
    rows, so the caller has both before it writes anything. Any failure to read, to connect
    included, is a refusal of the whole export."""
    path = Path(path)
    try:
        connection = _connect_read_only(path)
    except sqlite3.Error as exc:
        raise _export_refused(path, f"cannot be read ({type(exc).__name__}: {exc})") from None
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        return _read_export(connection, path)
    except sqlite3.Error as exc:
        raise _export_refused(path, f"cannot be read ({type(exc).__name__}: {exc})") from None
    finally:
        connection.close()


def _read_export(
    connection: sqlite3.Connection, path: Path
) -> tuple[dict[str, Any], dict[str, int]]:
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    missing = sorted({"meta", "triage"} - tables)
    if missing:
        raise _export_refused(path, f"holds no {' and no '.join(missing)} table")
    found = connection.execute("SELECT value FROM meta WHERE name = 'schema'").fetchone()
    if found is None:
        raise _export_refused(path, "names no store schema — not a store this tool wrote")
    schema = found[0]
    if schema not in TRIAGE_EXPORT_SCHEMAS:
        raise _export_refused(
            path,
            f"store schema {schema!r}; the triage export reads a store of schema "
            f"{' or '.join(TRIAGE_EXPORT_SCHEMAS)} only — this version's and the two before it — "
            "and no other, not even in part",
        )
    try:
        engagement = _engagement(connection)
    except StoreError as refusal:
        raise _export_refused(path, str(refusal)) from None
    chain = [] if engagement is None else [entry["digest"] for entry in engagement["chain"]]
    dropped = dict.fromkeys(_DROPPED_COLUMNS, 0)
    if schema in LEGACY_TRIAGE_SCHEMAS:
        held = {row[1] for row in connection.execute("PRAGMA table_info(triage)")}
        for name in _DROPPED_COLUMNS:
            if name in held:
                dropped[name] = connection.execute(
                    f"SELECT COUNT({name}) FROM triage"  # noqa: S608 - fixed names
                ).fetchone()[0]
    rows = []
    for row in connection.execute(
        f"SELECT {', '.join(_TRIAGE_COLUMNS)} FROM triage ORDER BY id"  # noqa: S608 - fixed
    ):
        values = dict(zip(_TRIAGE_COLUMNS, row, strict=True))
        try:
            identity = json.loads(values["identity"])
        except (TypeError, ValueError):
            identity = None
        if not (
            isinstance(identity, list)
            and len(identity) == len(IDENTITY_FIELDS)
            and all(isinstance(value, str) for value in identity)
        ):
            raise _export_refused(
                path, f"row {values['id']}: its identity is not five strings as JSON"
            )
        values["identity"] = dict(zip(IDENTITY_FIELDS, identity, strict=True))
        rows.append(values)
    # The read transaction holds SQLite's shared lock from the first read on: no writer commits
    # until it ends, and a store in write-ahead-log mode was refused before it was opened.
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1 << 20), b""):
            digest.update(chunk)
    document = {
        "triage_export_version": TRIAGE_EXPORT_VERSION,
        "store_schema": schema,
        "store_sha256": digest.hexdigest(),
        "engagement_chain_digests": chain,
        "rows": rows,
    }
    _export_rows(document, lambda reason: _export_refused(path, reason))
    return document, dropped


def _export_rows(document: Any, refused: Callable[[str], StoreError]) -> list[dict[str, Any]]:
    """The rows of a triage export, each checked by itself and against the rows before it; the
    first that is not one is refused, by ``refused``'s words."""
    if not isinstance(document, dict) or set(document) != set(_TRIAGE_EXPORT_FIELDS):
        raise refused(f"a triage export is exactly {', '.join(_TRIAGE_EXPORT_FIELDS)}")
    version = document["triage_export_version"]
    if type(version) is not int or version != TRIAGE_EXPORT_VERSION:
        raise refused(
            f"triage_export_version {version!r} is not {TRIAGE_EXPORT_VERSION}, the one this "
            "version reads"
        )
    if document["store_schema"] not in TRIAGE_EXPORT_SCHEMAS:
        raise refused(
            f"store_schema {document['store_schema']!r} is not {' or '.join(TRIAGE_EXPORT_SCHEMAS)}"
        )
    if not _is_digest(document["store_sha256"]):
        raise refused("store_sha256 is not 64 lowercase hex characters")
    chain = document["engagement_chain_digests"]
    if not (
        isinstance(chain, list)
        and all(_is_digest(digest) for digest in chain)
        and len(set(chain)) == len(chain)
    ):
        raise refused(
            "engagement_chain_digests is not a list of distinct digests as 64 lowercase hex "
            "characters"
        )
    rows = document["rows"]
    if not isinstance(rows, list):
        raise refused("rows is not a list")
    if document["store_schema"] in LEGACY_TRIAGE_SCHEMAS:
        # An export written before the rationale and the severity left the tool: its status, role
        # and author are carried, both are dropped here, before the row is checked or kept.
        rows = [_without_dropped(row) for row in rows]
    earlier = _EarlierRows()
    for number, row in enumerate(rows):
        problem = _row_problem(row, earlier, chain)
        if problem is not None:
            named = row.get("id") if isinstance(row, dict) else None
            label = named if type(named) is int else f"at position {number + 1}"
            raise refused(f"row {label}: {problem}")
        earlier.add(row)
    return rows


def _without_dropped(row: Any) -> Any:
    """``row`` of a legacy export without its ``rationale`` and ``severity``; anything else as
    it is."""
    if isinstance(row, dict):
        return {name: value for name, value in row.items() if name not in _DROPPED_COLUMNS}
    return row


def legacy_dropped(document: Any) -> dict[str, int]:
    """How many rows of a triage export carry a ``rationale`` and a ``severity`` (text, not
    null) — written by a version before schema 13, which :meth:`Store.import_triage` drops.
    Both 0 for any document that is not one."""
    counts = dict.fromkeys(_DROPPED_COLUMNS, 0)
    rows = document.get("rows") if isinstance(document, dict) else None
    if not isinstance(rows, list) or document.get("store_schema") not in LEGACY_TRIAGE_SCHEMAS:
        return counts
    for row in rows:
        if isinstance(row, dict):
            for name in _DROPPED_COLUMNS:
                counts[name] += isinstance(row.get(name), str)
    return counts


class _EarlierRows:
    """What the rows of an export before one say about it, kept as they are added, so that each
    row is checked in constant time and a file of many rows in linear time: the last id, every
    id, and the last id of each identity and role."""

    def __init__(self) -> None:
        self.last_id = 0
        self.ids: set[int] = set()
        self.last_by_decision: dict[tuple[tuple[str, ...], str], int] = {}

    def add(self, row: dict[str, Any]) -> None:
        self.last_id = row["id"]
        self.ids.add(row["id"])
        self.last_by_decision[_decision(row["identity"], row["role"])] = row["id"]


def _decision(identity: dict[str, str], role: str) -> tuple[tuple[str, ...], str]:
    return tuple(identity[name] for name in IDENTITY_FIELDS), role


def _row_problem(row: Any, earlier: _EarlierRows, chain: list[str]) -> str | None:
    """Why ``row`` is not a triage row as the store writes one, after ``earlier``, under an
    engagement chain of ``chain`` — every check :meth:`Store.triage_set` makes, and what it
    fills: an ``at_utc`` as it writes one, the ``supersedes`` it would have written — or None.
    Whether a finding has the identity is the importing store's to say."""
    if not isinstance(row, dict) or set(row) != set(_TRIAGE_COLUMNS):
        return f"a row is exactly {', '.join(_TRIAGE_COLUMNS)}"
    number = row["id"]
    if type(number) is not int or number < 1 or number <= earlier.last_id:
        return "its id is not a whole number above the id of the row before it"
    identity = row["identity"]
    if (
        not isinstance(identity, dict)
        or set(identity) != set(IDENTITY_FIELDS)
        or not all(isinstance(value, str) for value in identity.values())
    ):
        return f"its identity is not exactly {', '.join(IDENTITY_FIELDS)}, as strings"
    role, status = row["role"], row["status"]
    if not isinstance(role, str) or role not in TRIAGE_ROLES:
        return f"role {role!r} is not one of {', '.join(TRIAGE_ROLES)}"
    if not isinstance(status, str) or status not in TRIAGE_STATUSES[role]:
        return f"status {status!r} is not one the {role} may set"
    problem = _text_problem("author", row["author"])
    if problem is not None:
        return problem
    try:
        moment = datetime.fromisoformat(row["at_utc"])
    except (TypeError, ValueError):
        moment = None
    if moment is None or moment.utcoffset() is None or _utc(moment) != row["at_utc"]:
        return "its at_utc is not a moment as the store writes one (UTC, to the millisecond)"
    digest = row["engagement_digest"]
    if digest is not None and not _is_digest(digest):
        return "its engagement_digest is neither null nor 64 lowercase hex characters"
    problem = _digest_problem(digest, chain, "the export's engagement chain")
    if problem is not None:
        return problem
    expected = earlier.last_by_decision.get(_decision(identity, role))
    supersedes = row["supersedes"]
    if supersedes is not None and (type(supersedes) is not int or supersedes not in earlier.ids):
        return f"it supersedes {supersedes!r}, which is no earlier row of the file"
    if supersedes != expected:
        return (
            f"it supersedes {supersedes!r}, where the decision of its identity and role before "
            f"it is {expected!r}"
        )
    return None


def _digest_problem(digest: str | None, chain: list[str], holder: str) -> str | None:
    """Why a row made under ``digest`` (None: under no engagement) does not belong under the
    engagement chain ``chain`` of ``holder``, or None."""
    if digest is None:
        return f"made under no engagement, where {holder} holds one" if chain else None
    if digest not in chain:
        return f"made under engagement digest {digest}, which {holder} does not hold"
    return None


def _export_refused(path: Path, reason: str) -> StoreError:
    return StoreError(f"{path}: triage export: {reason}; nothing is exported")


def _import_refused(reason: str) -> StoreError:
    return StoreError(f"triage import: {reason}; nothing is written")


# -- reading a recording ----------------------------------------------------------------


@dataclass
class _ParsedRun:
    run_id: str | None = None
    provenance: str = ""
    server: str = ""
    announced_server: str | None = None
    server_version: str = ""
    server_identity_kind: str = ""
    launch_digest: str = ""
    manifest_digest: str = ""
    tool_version: str = ""
    tool_content: str = ""
    scenario: str = ""
    scenario_digest: str = ""
    statements: set[tuple[str, str]] = field(default_factory=set)
    wall_clock_utc: str | None = None
    isolation: str = "host"
    sandbox_image: str | None = None
    target_image: str | None = None
    findings: list[tuple[dict[str, Any], Sighting]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    causes: list[str] = field(default_factory=list)
    state: str = verdict.COMPLETE
    truncations: list[dict[str, Any]] = field(default_factory=list)
    engagement_id_declared: str | None = None
    engagement_digest: str | None = None
    #: Canonical JSON of the declaration, from the store's chain at filing; never recorded.
    engagement_declared: str | None = None
    #: The leaf certificates' SHA-256, sorted, from ``run_finished.http.tls``; None without TLS.
    endpoint_certificates: list[str] | None = None
    #: The definitions the run's ``*/list`` answers held, and its ``list_changed`` notifications.
    definitions: definitions.Captured = field(default_factory=definitions.Captured)

    @property
    def complete(self) -> bool:
        return self.state == verdict.COMPLETE


def _events_path(path: Path) -> Path:
    return path / "events.jsonl" if path.is_dir() else path


def _connect_read_only(path: Path) -> sqlite3.Connection:
    """A connection to an existing file through SQLite's ``mode=ro``, or refused: a missing file,
    and a file in write-ahead-log mode, which SQLite reads only by creating files beside it."""
    if not path.is_file():
        raise StoreError(f"{path}: no store there; opened for reading, nothing is created")
    with path.open("rb") as file:
        header = file.read(20)
    if header.startswith(b"SQLite format 3\x00") and 2 in header[18:20]:
        raise StoreError(
            f"{path}: in write-ahead-log mode, which SQLite reads only by writing its -wal and "
            "-shm files beside it; opened for reading, nothing is written, so it is not read"
        )
    return sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)


def _schema_refusal(connection: sqlite3.Connection, path: Path) -> str | None:
    """Why this file is not a store this version may open, or None. Asked before anything is
    read from it or written to it: a store of another schema is refused whole."""
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    if not tables:
        return None  # an empty file: a new store
    found = None
    if "meta" in tables:
        found = connection.execute("SELECT value FROM meta WHERE name = 'schema'").fetchone()
    if found is None:
        return (
            f"{path}: holds tables but names no store schema — not a store this tool wrote; "
            "not read, not even in part"
        )
    schema = found[0]
    if schema == SCHEMA_VERSION:
        return None
    if isinstance(schema, str) and schema.isdigit() and int(schema) < int(SCHEMA_VERSION):
        # The one exception (export_triage) is named where it applies: what a person wrote into
        # a store of the previous schema is carried, never read here.
        carried = (
            f". Its triage can be carried with store triage export --store {path} --out FILE "
            "and store triage import into the new store"
            if schema in TRIAGE_EXPORT_SCHEMAS
            else ""
        )
        return (
            f"{path}: store schema {schema}, written by an earlier version of Kymograph; this "
            f"version reads schema {SCHEMA_VERSION} only, does not migrate, and reads no older "
            f"store, not even in part. Drive the corpus again into a new store{carried}"
        )
    return (
        f"{path}: store schema {schema!r} is not one this version knows (it reads "
        f"{SCHEMA_VERSION}): written by a newer version, or not a store of this tool; not read, "
        "not even in part. Open it with the version that wrote it, or drive the corpus again "
        "into a new store"
    )


def _read_run(path: Path, raw: bytes) -> _ParsedRun:
    """Everything the store needs from one recording, or a refusal saying what is missing.

    Refused outright: no ``run_started``, a proxy run, a run without the reproduction triple.
    Everything else that is wrong is a shortfall recorded against the run, which is then filed
    in the state :mod:`mcp_kymograph.verdict` gives it — never skipped without a trace.
    """
    events, line_problems = verdict.read_events(raw)
    started = events[0] if events and events[0].get("type") == "run_started" else None
    if started is None:
        raise StoreError(f"{path}: the recording does not begin with run_started")
    foreign = verdict.schema_problem(events)
    if foreign is not None:
        raise StoreError(f"{path}: {foreign}")
    if started.get("mode") != "driver":
        raise StoreError(
            f"{path}: a {started.get('mode')!r} run; the store takes driver runs only, "
            "whose client half is the same script every time"
        )
    parsed = _triple(path, started)
    filing: list[str] = []
    for event in events:
        if event.get("type") == "finding":
            entry = _finding(path, event, parsed, filing)
            if entry is not None:
                parsed.findings.append(entry)
    judged = verdict.assess(events, line_problems)
    # A finding the store cannot file under this run's context is data the run lacks.
    parsed.problems = judged.problems + filing
    parsed.causes = sorted(set(judged.causes) | ({"unfiled_finding"} if filing else set()))
    parsed.state = verdict.gravest(
        [s.state for s in judged.shortfalls] + [verdict.INCOMPLETE] * bool(filing)
    )
    parsed.statements = judged.statements
    parsed.announced_server = judged.announced_server
    parsed.truncations = judged.truncations
    parsed.endpoint_certificates = _recorded_certificates(path, events)
    parsed.definitions = definitions.read(events)
    return parsed


def _triple(path: Path, started: dict[str, Any]) -> _ParsedRun:
    """The run's context from ``run_started``: refused unless it is a complete corpus run."""
    triple = started.get("reproduction")
    if isinstance(triple, dict) and triple.get("corpus") is None and "corpus" in triple:
        raise StoreError(
            f"{path}: the run ran outside a corpus; the store takes corpus runs only — "
            "drive the server with --manifest and --entry"
        )
    try:
        corpus, tool, scenario = triple["corpus"], triple["tool"], triple["scenario"]
        values = {
            "provenance": corpus["provenance"],
            "server": corpus["entry"],
            "server_version": corpus["identity"]["version"],
            "server_identity_kind": corpus["identity"]["kind"],
            "launch_digest": corpus["launch_digest"],
            "manifest_digest": triple["manifest"]["digest"],
            "tool_version": tool["version"],
            "tool_content": tool["content"],
            "scenario": scenario["name"],
            "scenario_digest": scenario["digest"],
        }
    except (KeyError, TypeError):
        raise StoreError(
            f"{path}: no reproduction triple; the store takes corpus runs only — "
            "drive the server with --manifest and --entry"
        ) from None
    for name, value in values.items():
        if not isinstance(value, str):
            raise StoreError(f"{path}: reproduction field {name} is not a string")
    env = triple.get("environment")
    if not isinstance(env, dict) or not isinstance(env.get("isolation"), str):
        raise StoreError(
            f"{path}: the triple names no environment; a run whose environment is not "
            "recorded cannot be compared on it"
        )
    images = {name: env.get(name) for name in ("sandbox_image", "target_image")}
    if any(value is not None and not isinstance(value, str) for value in images.values()):
        raise StoreError(f"{path}: an image in the environment is not a string")
    if values["provenance"] not in PROVENANCES:
        raise StoreError(f"{path}: unknown provenance {values['provenance']!r}")
    # The triple is one statement of the run's context and the rest of run_started another;
    # where they could disagree, they must not.
    identity = started.get("server_identity")
    authorization = started.get("authorization")
    for name, value in (("server_identity", identity), ("authorization", authorization)):
        if value is not None and not isinstance(value, dict):
            raise StoreError(f"{path}: run_started's {name} is not an object")
    identity = identity or {}
    for name, ours, theirs in (
        ("server", values["server"], started.get("server_name")),
        ("server_version", values["server_version"], identity.get("version")),
        ("tool_version", values["tool_version"], started.get("tool_version")),
        ("scenario", values["scenario"], started.get("scenario_name")),
        ("isolation", env["isolation"], started.get("isolation", "host")),
        (
            "scenario_digest",
            values["scenario_digest"],
            (authorization or {}).get("scenario_digest"),
        ),
    ):
        if ours != theirs:
            raise StoreError(f"{path}: the triple's {name} differs from run_started's")
    engagement_id, engagement_digest = _recorded_engagement(
        path, (authorization or {}).get("engagement")
    )
    return _ParsedRun(
        engagement_id_declared=engagement_id,
        engagement_digest=engagement_digest,
        run_id=_string(started.get("run_id")),
        wall_clock_utc=_string(started.get("wall_clock_utc")),
        isolation=env["isolation"],
        **images,
        **values,
    )


def _finding(
    path: Path, event: dict[str, Any], parsed: _ParsedRun, problems: list[str]
) -> tuple[dict, Sighting] | None:
    """One finding event as a key and a sighting, or None with the reason in ``problems``."""
    seq = event.get("seq")
    key = event.get("key")
    where = f"finding seq={seq}"
    if not isinstance(key, dict) or set(key) != set(KEY_FIELDS):
        problems.append(f"{where}: key does not have exactly {', '.join(KEY_FIELDS)}")
        return None
    for name in KEY_FIELDS:
        if not isinstance(key[name], str):
            problems.append(f"{where}: key field {name} is not a string")
            return None
    # Inside one run, the context is the run's. A finding that says otherwise was not made by
    # this run's inspector as recorded, and must not be filed under a context it claims.
    for name in ("server", "server_version", "tool_version", "scenario"):
        if key[name] != getattr(parsed, name):
            problems.append(f"{where}: {name} differs from the run's")
            return None
    where_in, message_seq = event.get("path"), event.get("message_seq")
    if (
        not isinstance(where_in, str)
        or isinstance(message_seq, bool)
        or not isinstance(message_seq, int)
    ):
        problems.append(f"{where}: no position to record it at")
        return None
    if not -(2**63) <= message_seq < 2**63:
        raise StoreError(
            f"{path}: {where}: message_seq is outside the 64-bit range the store holds; "
            "refusing the whole run"
        )
    return dict(key), Sighting(where_in, message_seq, event.get("normalized") is True)


def _recorded_engagement(path: Path, value: Any) -> tuple[str | None, str | None]:
    """The engagement a run was gated against, as ``run_started.authorization`` records it: its
    id and digest, or None for both — a run made without an engagement file, or recorded before
    the field existed, which is the same thing.

    Anything else is refused whole: the store holds a run against its engagement by these two
    values, and a run whose engagement cannot be read can be neither admitted nor told apart.
    """
    if value is None:
        return None, None
    where = f"{path}: run_started's authorization.engagement"
    if not isinstance(value, dict):
        raise StoreError(f"{where} is neither null nor an object")
    if set(value) != set(_RECORDED_ENGAGEMENT):
        raise StoreError(f"{where} does not have exactly {', '.join(_RECORDED_ENGAGEMENT)}")
    name, digest, window = (value[field_name] for field_name in _RECORDED_ENGAGEMENT)
    if not isinstance(name, str) or not name:
        raise StoreError(f"{where}: engagement_id_declared is not a non-empty string")
    if not _is_digest(digest):
        raise StoreError(f"{where}: engagement_digest is not 64 lowercase hex characters")
    if (
        not isinstance(window, dict)
        or set(window) != {"from", "until"}
        or not all(isinstance(moment, str) for moment in window.values())
    ):
        raise StoreError(f"{where}: window_declared is not exactly from and until, as strings")
    return name, digest


def _recorded_certificates(path: Path, events: Sequence[dict[str, Any]]) -> list[str] | None:
    """The certificates an endpoint presented, as the run's last ``run_finished`` records them
    in ``http.tls`` (docs/design/http-transport.md 8.2), or None: a run without ``run_finished``
    or without ``http`` — which the verdict judges — and an ``http`` whose ``tls`` is null or
    absent, a run that spoke no TLS or was recorded before it was spoken.

    Anything else is refused whole: the store files the set as a column and compares runs by it,
    and a set that cannot be read can be neither filed nor compared. Exactly ``versions`` and
    ``certificates``, each a list of distinct strings in order, a certificate as 64 lowercase hex
    characters — the set as the proxy writes it, never repaired here.
    """
    finished = [event for event in events if event.get("type") == "run_finished"]
    http = finished[-1].get("http") if finished else None
    tls = http.get("tls") if isinstance(http, dict) else None
    if tls is None:
        return None
    where = f"{path}: run_finished's http.tls"
    if not isinstance(tls, dict) or set(tls) != set(_RECORDED_TLS):
        raise StoreError(f"{where} is neither null nor exactly {', '.join(_RECORDED_TLS)}")
    for name in _RECORDED_TLS:
        listed = tls[name]
        if not (
            isinstance(listed, list)
            and all(isinstance(value, str) and value for value in listed)
            and listed == sorted(set(listed))
        ):
            raise StoreError(f"{where}: {name} is not a list of distinct strings in order")
    if not all(_is_digest(certificate) for certificate in tls["certificates"]):
        raise StoreError(f"{where}: a certificate is not 64 lowercase hex characters")
    return list(tls["certificates"])


def _engagement(connection: sqlite3.Connection) -> dict[str, Any] | None:
    """The engagement the ``meta`` rows of ``connection`` hold (:meth:`Store.engagement`), read
    from those rows and nothing else; refused whole when they do not fit together."""
    marks = ", ".join("?" for _ in _ENGAGEMENT_META)
    rows = dict(
        connection.execute(
            f"SELECT name, value FROM meta WHERE name IN ({marks})",  # noqa: S608 - fixed
            _ENGAGEMENT_META,
        ).fetchall()
    )
    if not rows:
        return None
    try:
        chain = json.loads(rows["engagement_chain"])
        name, digest = rows["engagement_id_declared"], rows["engagement_digest"]
    except (KeyError, TypeError, ValueError):
        chain = name = digest = None
    if not (
        isinstance(chain, list)
        and chain
        and all(
            isinstance(entry, dict)
            and set(entry) == set(_CHAIN_FIELDS)
            and isinstance(entry["file_declared"], dict)
            for entry in chain
        )
        and chain[-1]["digest"] == digest
        and isinstance(name, str)
    ):
        raise StoreError(
            "the store's engagement rows do not fit together (an id, a current digest and a "
            "chain of versions ending in it); not read, not even in part"
        )
    return {
        "engagement_id_declared": name,
        "engagement_digest": digest,
        "delete_after_declared": rows.get("delete_after_declared"),
        "chain": chain,
    }


def _is_import_entry(entry: Any) -> bool:
    """Whether ``entry`` is one import as :meth:`Store.import_triage` records it."""
    return (
        isinstance(entry, dict)
        and set(entry) == set(_IMPORT_FIELDS)
        and _is_digest(entry["file_sha256"])
        and _is_digest(entry["store_sha256"])
        and entry["store_schema"] in TRIAGE_EXPORT_SCHEMAS
        and type(entry["rows"]) is int
        and entry["rows"] >= 0
        and (entry["first_id"] is None if entry["rows"] == 0 else type(entry["first_id"]) is int)
        and isinstance(entry["at_utc"], str)
    )


def _imported(row_id: int, imports: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Where the triage row ``row_id`` came from, or None for a row written in this store. An
    import's rows hold consecutive ids from its ``first_id``: it goes only into a store that holds
    no triage row, all of them in one transaction."""
    for entry in imports:
        if entry["rows"] and entry["first_id"] <= row_id < entry["first_id"] + entry["rows"]:
            return {name: entry[name] for name in _IMPORTED_FIELDS}
    return None


def _is_digest(value: Any) -> bool:
    """A SHA-256 as an engagement's digests are written: 64 lowercase hex characters."""
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _utc(moment: datetime) -> str:
    """A moment as the store writes it: UTC, to the millisecond, as a fleet's times are."""
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _triage_refused(reason: str) -> StoreError:
    return StoreError(f"triage: {reason}; nothing is written")


def _triage_text(name: str, value: Any, *, allowed: str = "") -> None:
    """Refuses text a decision cannot keep as given: not a string, empty, past its cap, or
    holding a character a terminal would not show (``allowed`` excepted)."""
    problem = _text_problem(name, value, allowed=allowed)
    if problem is not None:
        raise _triage_refused(problem)


def _text_problem(name: str, value: Any, *, allowed: str = "") -> str | None:
    """Why a decision cannot keep this text as given (:func:`_triage_text`), or None."""
    if not isinstance(value, str):
        return f"the {name} is not a string"
    if not value.strip():
        return f"the {name} is empty"
    if len(value) > TRIAGE_CAPS[name]:
        return f"the {name} is longer than {TRIAGE_CAPS[name]} characters"
    if undisplayable(value, allowed=allowed):
        return f"the {name} holds a control, format or other character a terminal does not show"
    return None


def _identity_values(identity: Any) -> tuple[str, ...]:
    """The five values of an identity as ``store diff`` prints it, in order, or refused."""
    if not isinstance(identity, Mapping) or set(identity) != set(IDENTITY_FIELDS):
        raise _triage_refused(f"an identity is exactly {', '.join(IDENTITY_FIELDS)}")
    values = tuple(identity[name] for name in IDENTITY_FIELDS)
    if not all(isinstance(value, str) for value in values):
        raise _triage_refused("every value of an identity is a string")
    return values


def finding_key(identity_values: Sequence[str]) -> str:
    """The key of a finding in the operator's private notes: ``fk-`` and the first 16 hex
    characters of the SHA-256 of the identity as the triage keeps it (:func:`_identity_key`, in
    UTF-8). The identity is the five fields without the two version fields, so the key is the
    same under every version of the server: the notes name the same finding at a new version."""
    digest = hashlib.sha256(_identity_key(identity_values).encode("utf-8")).hexdigest()
    return f"fk-{digest[:16]}"


def _identity_key(values: Sequence[str]) -> str:
    """The one string a triage row is kept under: the five values, in order, as JSON — as
    :func:`canonical_key` writes the seven of a finding's key."""
    return json.dumps(list(values), ensure_ascii=True)


def _cell(
    ran: tuple[str | None, str] | None,
    identity: dict[str, str],
    sighted: set[str],
    runs: dict[str, RunInfo],
) -> dict[str, Any]:
    """One cell of :meth:`Store.history`: what the column ran of the identity's scenario, and
    whether that run could have reported the identity at all before it says it did not."""
    if ran is None:
        return {"cell": "not_run", "run": None, "state": None}
    run, state = ran
    asked = (identity["statement"], identity["signal"])
    if run is not None and run in sighted:
        cell = "sighted"
    elif run not in runs or state != verdict.COMPLETE or not runs[run].complete:
        cell = "not_a_result"
    elif asked not in runs[run].statements:
        cell = "not_asked"
    elif asked in runs[run].cut_statements:
        cell = "capped"
    elif runs[run].listing_capped:
        cell = "listing_capped"
    else:
        cell = "not_sighted"
    return {"cell": cell, "run": run, "state": state}


def _one_kind(kinds: Sequence[str]) -> str:
    """The kind several findings share, or :data:`MIXED` — never one of them picked."""
    distinct = set(kinds)
    return next(iter(distinct)) if len(distinct) == 1 else MIXED if distinct else UNKNOWN


def _bundle_refused(where: str, reason: str) -> StoreError:
    return StoreError(f"{where}: {reason}; nothing is written")


def _named(name: str, digest: str) -> str:
    """An engagement in a refusal's words: what the store holds, or what it was offered."""
    return f"engagement {name!r} (digest {digest})"


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def ingest_all(
    store: Store, recordings: Sequence[str | Path], provenance: str | None = None
) -> Iterable[tuple[str | Path, Ingested | StoreError]]:
    """Each recording in turn; one that is refused does not stop the others."""
    for recording in recordings:
        try:
            yield recording, store.ingest(recording, provenance)
        except StoreError as refusal:
            yield recording, refusal


def _holds(document: Mapping[str, Any], path: str) -> bool:
    """Whether ``document`` holds the key path ``path`` (``a``, ``a.b``, ``a[].b`` for ``b`` in
    any item of the list ``a``). A value of the wrong shape on the way holds nothing there."""
    head, _, rest = path.partition(".")
    each = head.endswith("[]")
    key = head.removesuffix("[]")
    if not isinstance(document, Mapping) or key not in document:
        return False
    value = document[key]
    if not rest:
        return True
    if each:
        return isinstance(value, list) and any(_holds(item, rest) for item in value)
    return _holds(value, rest)
