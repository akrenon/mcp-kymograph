"""The web interface's views: pure functions from :class:`Sources` to an envelope.

``CONTRACT.md`` beside this module is their shape and the closed set of notices. Nothing here
writes: the store is opened with :meth:`~mcp_kymograph.store.Store.open_read_only`, every other
file for reading.

**Shown from the artifact, never derived around it.** A run's state and causes are what
:mod:`mcp_kymograph.verdict` says of the bytes of its recording, read once; a comparison is what
:meth:`~mcp_kymograph.store.Store.diff` or :func:`mcp_kymograph.fleet.compare` return; a fleet's
state is what its ``fleet.json`` says, never worked out from its results. Where the code has no
answer, a notice says so in place of one.

**A view that shows nothing or not everything says why.** Every envelope carries its notices,
gravest first (:data:`NOTICE_KINDS`). A run that is not a result is never shown as one that
found nothing: its ``not_a_result`` comes first, with every cause.

**Strings off the wire are passed on as recorded.** The recording is already masked; nothing is
re-read from anywhere else, nothing is cleaned or cut here. The page makes them safe to show.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import math
import os
import shlex
import sqlite3
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_kymograph import __version__, finding_classes, inspection, masking, paths, verdict
from mcp_kymograph import corpus as corpus_module
from mcp_kymograph import events as events_module
from mcp_kymograph import evidence as evidence_module
from mcp_kymograph import fleet as fleet_module
from mcp_kymograph import handover as handover_module
from mcp_kymograph import report as report_module
from mcp_kymograph import scenario as scenario_module
from mcp_kymograph import signals as signals_module
from mcp_kymograph import store as store_module
from mcp_kymograph.driver import MAX_PAGES
from mcp_kymograph.sandbox import policy
from mcp_kymograph.web import _found

#: The notices a view can carry, gravest first (CONTRACT.md, section 4).
NOTICE_KINDS = (
    "not_given",
    "store_refused",
    "recording_changed",
    "recording_not_found",
    "bundle_not_intact",
    "refused",
    "not_a_result",
    "comparison_not_complete",
    "fleet_state_not_in_store",
    "capped",
    "not_in_this_recording",
    "not_recorded_by_this_version",
    "candidates",
)

Envelope = dict[str, Any]

#: How many runs the run listing shows at most; the rest are counted, and the cut is said.
MAX_LISTED_RUNS = 1000

#: How many messages one page of the message listing holds at most.
MAX_MESSAGE_PAGE = 500

#: Provenances whose findings may be listed with :func:`store_findings`. A real-world finding is
#: a candidate for disclosure, shown by :func:`store_candidates` alone.
PUBLISHABLE = tuple(p for p in corpus_module.PROVENANCES if p != "real-world")

#: The listings an inventory is made of: the member of the answer's ``result`` that holds the
#: items, and the method that asks for them. The members are the protocol's names (and the
#: element types of :data:`mcp_kymograph.paths.IDENTITY_FIELDS`).
LISTINGS = (
    ("tools", "tools/list"),
    ("resources", "resources/list"),
    ("resourceTemplates", "resources/templates/list"),
    ("prompts", "prompts/list"),
)

LOCAL = "read-only · 127.0.0.1 · token at start · no TLS"

_INTERVENTION_EVENTS = ("intervention", "rule_quarantined")
_HTTP_EVENTS = ("http_request", "http_response", "http_end")
_SANDBOX_EVENTS = (
    "sandbox_step",
    "sandbox_failed",
    "egress_attempt",
    "egress_dns",
    "egress_summary",
)
_STEP_EVENTS = (
    "step_skipped",
    "step_unanswered",
    "step_reissued",
    "step_called",
    "call_failed",
)
_FINISHED_FOR_OVERVIEW = (
    "reason",
    "message_count",
    "duration_ns",
    "dropped_events",
    "unwritten_events",
    "server_redactions",
    "http",
    "window_exceeded",
)


@dataclass(frozen=True)
class Sources:
    """What the operator gave on the command line; nothing else on disk is read."""

    store: Path | None = None
    runs: Path | None = None
    manifests: tuple[Path, ...] = ()
    scenarios: tuple[Path, ...] = ()
    #: ``--bundle DIR``, repeatable: evidence bundles, each checked against its own index.
    bundles: tuple[Path, ...] = ()
    #: ``--attestation FILE``, repeatable: attestations, each read back before it is shown.
    attestations: tuple[Path, ...] = ()


class ViewError(Exception):
    """A parameter that names nothing (404) or is malformed (400); or a file asked for as a
    download that is not served as it stands (409: a bundle not intact, a file changed, an
    attestation that does not read back)."""

    def __init__(self, status: int, words: str) -> None:
        super().__init__(words)
        self.status = status
        self.words = words


# -- the envelope and its notices ---------------------------------------------------------------


def _notice(kind: str, text: str, where: str = "view", **fields: Any) -> dict[str, Any]:
    if kind not in NOTICE_KINDS:
        raise ValueError(f"{kind!r} is not a notice this interface knows")
    return {"kind": kind, "text": text, "where": where, **fields}


def _envelope(view: str, notices: Iterable[dict[str, Any]], data: Any) -> Envelope:
    """The view, its notices gravest first (in the order they were made within one kind), and
    its data as JSON values."""
    order = {kind: index for index, kind in enumerate(NOTICE_KINDS)}
    return {
        "view": view,
        "notices": _json(sorted(notices, key=lambda notice: order[notice["kind"]])),
        "data": _json(data),
    }


def _json(value: Any) -> Any:
    """The value as JSON values only: tuples become lists; anything else that is not one is a
    bug here, raised, never passed on to be serialised as something it is not.

    A number JSON cannot carry — a recording read back with Python's parser takes ``1e400``,
    ``Infinity`` and ``NaN`` as floats that are not finite — is passed on as the word Python's
    JSON writer spells it with, a string: strict JSON has no such number, and a value from the
    traffic must neither break the envelope nor make the run vanish from the page.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else json.dumps(value)
    if isinstance(value, (list, tuple)):
        return [_json(item) for item in value]
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"a key that is not a string: {key!r}")
        return {key: _json(item) for key, item in value.items()}
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def _not_given(view: str, option: str) -> Envelope:
    return _envelope(
        view,
        [
            _notice(
                "not_given",
                f"{option} was not given on the command line, and this view reads nothing else.",
                option=option,
            )
        ],
        None,
    )


def _store_refused(path: Path, words: str) -> dict[str, Any]:
    return _notice(
        "store_refused",
        "The store was refused and nothing of it is shown: a store is read whole or refused "
        "whole, never in part.",
        store=str(path),
        words=words,
    )


_NOT_A_RESULT = {
    verdict.SANDBOX_FAILED: "Not a result: the sandbox failed, and nothing the run shows can be "
    'trusted as an observation. Its causes come first; what follows is not "no findings".',
    verdict.SERVER_FAILED: "Not a result: the server failed, and nothing was observed. Its causes "
    'come first; an empty list below is "not looked at", never "no findings".',
    verdict.INCOMPLETE: "Not a result: the run is incomplete, data is missing, and a finding it "
    'lacks may only be missing. Its causes come first; what follows is not "no findings".',
    verdict.CALL_FAILED: "Not a result about the content: the server answered a tool call of the "
    "script with an error, and what the call was to deliver never came. The rest of the data "
    "is all there.",
}


def _not_a_result(
    state: str,
    exit_code: int | None,
    rules: Any,
    causes: list[dict[str, Any]],
    where: str = "view",
    **fields: Any,
) -> dict[str, Any]:
    text = _NOT_A_RESULT.get(
        state,
        f"Not a result: this is {state}, and no run of it was judged. Its causes come first.",
    )
    return _notice(
        "not_a_result",
        text,
        where,
        state=state,
        exit_code=exit_code,
        rules=rules,
        causes=causes,
        **fields,
    )


def _capped(
    where: str,
    text: str,
    *,
    what: str,
    source: str,
    cap: Any,
    shown: Any,
    total: Any,
    **fields: Any,
) -> dict[str, Any]:
    return _notice(
        "capped", text, where, what=what, source=source, cap=cap, shown=shown, total=total, **fields
    )


def _unreadable_directories(found: _found.Found, shown: int | None) -> list[dict[str, Any]]:
    """``capped`` for a walk of ``--runs`` that could not list some of its directories: what
    is in them was not found, so what was found is not all there is."""
    if not found.unreadable:
        return []
    return [
        _capped(
            "view",
            f"{len(found.unreadable)} director(y/ies) under --runs could not be read: what they "
            "hold was not found, so this is not every run there is.",
            what="runs",
            source="unreadable directories",
            cap=None,
            shown=shown,
            total=None,
            unreadable=list(found.unreadable),
        )
    ]


def _candidates(count: int | None, where: str = "view") -> dict[str, Any]:
    return _notice(
        "candidates",
        "Real-world findings are candidates for responsible disclosure, not results to "
        "publish; they are kept apart from every publishable finding.",
        where,
        count=count,
    )


def _shortfalls(judged: verdict.Verdict) -> list[dict[str, Any]]:
    """Every shortfall of a verdict as its cause key, its words and its state, in order."""
    return [{"cause": s.cause, "words": s.reason, "state": s.state} for s in judged.shortfalls]


def _filed_causes(causes: Iterable[Any]) -> list[dict[str, Any]]:
    """Causes as a store or a fleet keeps them: keys alone, without the reason each was given
    for (the store keeps the reasons apart, in ``problems``). The words are the cause's
    meaning (:data:`mcp_kymograph.verdict.CAUSES`); its state is not kept per cause."""
    return [
        {"cause": cause, "words": verdict.CAUSES.get(cause) if isinstance(cause, str) else None,
         "state": None}
        for cause in causes
    ]  # fmt: skip


# -- the sources ----------------------------------------------------------------------------------


class _Refused(Exception):
    def __init__(self, notice: dict[str, Any]) -> None:
        super().__init__(notice["text"])
        self.notice = notice


def _open_store(path: Path) -> store_module.Store:
    """The store, read-only, or :class:`_Refused` with the refusal as raised — also a store
    whose record of triage imports cannot be read: none of its triage rows could say whether
    it was written there or carried in (:meth:`Store.triage_imports`)."""
    try:
        store = store_module.Store.open_read_only(path)
    except store_module.StoreError as refusal:
        raise _Refused(_store_refused(path, str(refusal))) from None
    except (sqlite3.Error, OSError) as refusal:
        raise _Refused(_store_refused(path, f"{path}: {refusal}")) from None
    try:
        store.triage_imports()
    except store_module.StoreError as refusal:
        store.close()
        raise _Refused(_store_refused(path, f"{path}: {refusal}")) from None
    except sqlite3.Error as refusal:
        store.close()
        raise _Refused(_store_refused(path, f"{path}: {refusal}")) from None
    return store


@dataclass
class _Run:
    """One recording, read once: its bytes' digest, its events, and the verdict on them."""

    ref: str
    digest: str | None
    events: list[dict[str, Any]]
    judged: verdict.Verdict
    #: Whether nothing of it may be shown but its verdict: unreadable, or of another schema.
    whole_refused: bool

    @property
    def result(self) -> bool:
        return self.judged.state == verdict.COMPLETE

    def of(self, *types: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event.get("type") in types]

    @property
    def started(self) -> dict[str, Any] | None:
        if self.events and self.events[0].get("type") == "run_started":
            return self.events[0]
        return None

    @property
    def finished(self) -> dict[str, Any] | None:
        # The last one, as the verdict takes it.
        found = self.of("run_finished")
        return found[-1] if found else None


def _judge(ref: str, path: Path) -> _Run:
    """The verdict on one recording, from its bytes read once — as :func:`verdict.read` judges
    a recording on disk: unreadable, of another schema (judged by nothing else, not even in
    part), or assessed."""
    try:
        raw = _found.read_bytes(path)
    except OSError as exc:
        return _Run(ref, None, [], verdict.unreadable(exc), whole_refused=True)
    digest = hashlib.sha256(raw).hexdigest()
    events, problems = verdict.read_events(raw)
    if verdict.schema_problem(events) is not None:
        return _Run(ref, digest, [], verdict.judge(events, problems), whole_refused=True)
    return _Run(ref, digest, events, verdict.judge(events, problems), whole_refused=False)


def _run_of(sources: Sources, ref: str) -> _Run:
    if sources.runs is None:
        raise ValueError("no --runs")  # the callers ask first
    found = _found.search(sources.runs)
    try:
        path = _found.lookup(found, ref)
    except _found.NotFound as missing:
        raise ViewError(404, str(missing)) from None
    return _judge(ref, path)


def _verdict_data(run: _Run) -> dict[str, Any]:
    judged = run.judged
    return {
        "state": judged.state,
        "exit_code": judged.exit_code,
        "rules": verdict.RULES_VERSION,
        "causes": _shortfalls(judged),
        "server_exit": judged.server_exit,
        "truncations": judged.truncations,
        "announced_server": judged.announced_server,
        "statements": [list(pair) for pair in sorted(judged.statements)],
    }


def _run_notice(run: _Run) -> dict[str, Any] | None:
    """``not_a_result`` for a run whose state is not complete, or None."""
    if run.result:
        return None
    judged = run.judged
    return _not_a_result(judged.state, judged.exit_code, verdict.RULES_VERSION, _shortfalls(judged))


# -- about --------------------------------------------------------------------------------------


def _package() -> str:
    """The distribution's own name, from its metadata."""
    top = __name__.split(".")[0]
    try:
        return importlib.metadata.metadata(top.replace("_", "-"))["Name"]
    except importlib.metadata.PackageNotFoundError:
        return top.replace("_", "-")


def about(sources: Sources) -> Envelope:
    """This version, what it reads, and what was given to read."""
    notices = []
    if sources.store is not None:
        try:
            _open_store(sources.store).close()
        except _Refused as refused:
            notices.append(refused.notice)
    data = {
        "package": _package(),
        "version": __version__,
        "recording_schema": events_module.SCHEMA_VERSION,
        "store_schema": store_module.SCHEMA_VERSION,
        "rules": verdict.RULES_VERSION,
        # The isolations this version records, and those of them under which it observes what
        # a server sends anywhere else: under any other isolation, or one it does not know,
        # egress is not observed, and no absence of an egress event means anything.
        "isolations": list(verdict.ISOLATIONS),
        "observed_isolations": list(verdict.OBSERVED_ISOLATIONS),
        "sources": {
            "store": None if sources.store is None else str(sources.store),
            "runs": None if sources.runs is None else str(sources.runs),
            "manifests": [str(path) for path in sources.manifests],
            "scenarios": [str(path) for path in sources.scenarios],
            "bundles": [str(path) for path in sources.bundles],
            "attestations": [str(path) for path in sources.attestations],
        },
        "local": LOCAL,
    }
    return _envelope("about", notices, data)


# -- runs ---------------------------------------------------------------------------------------


def _wall_clock(path: Path) -> str:
    """The first line's ``wall_clock_utc``, for the order of the listing only; "" if none."""
    try:
        first = _found.first_line(path, 1024 * 1024)
    except OSError:
        return ""
    event, _ = events_module.load_bytes(first, events_module.MAX_READ_DEPTH)
    if isinstance(event, dict) and event.get("type") == "run_started":
        stamp = event.get("wall_clock_utc")
        return stamp if isinstance(stamp, str) else ""
    return ""


def _fleet_of(ref: str, fleets: dict[str, str]) -> str | None:
    """The fleet a run lies in: the nearest directory above it holding that fleet's file."""
    parts = [] if ref == _found.ROOT_REF else ref.split("/")
    for length in range(len(parts), 0, -1):
        fleet = fleets.get("/".join(parts[:length]))
        if fleet is not None:
            return fleet
    return None


def runs(sources: Sources) -> Envelope:
    """Every recording under ``--runs``, newest first, each with its state from its verdict."""
    if sources.runs is None:
        return _not_given("runs", "--runs")
    found = _found.search(sources.runs)
    fleets = {}
    for name in found.fleets:
        taken = _found.fleet_file(found, name)
        if taken.content is not None and taken.ref is not None:
            fleets[taken.ref] = name
    order = sorted(
        found.recordings.items(),
        key=lambda item: (_wall_clock(item[1]), item[0]),
        reverse=True,
    )
    notices = []
    if len(order) > MAX_LISTED_RUNS:
        notices.append(
            _capped(
                "view",
                f"{MAX_LISTED_RUNS} of {len(order)} runs shown, capped: the newest; the rest "
                "are under --runs and not listed here.",
                what="runs",
                source="--runs",
                cap=MAX_LISTED_RUNS,
                shown=MAX_LISTED_RUNS,
                total=len(order),
            )
        )
    notices.extend(_unreadable_directories(found, min(len(order), MAX_LISTED_RUNS)))
    listed = []
    for ref, path in order[:MAX_LISTED_RUNS]:
        run = _judge(ref, path)
        started = run.started or {}
        listed.append(
            {
                "ref": ref,
                "run_id": started.get("run_id"),
                "wall_clock_utc": started.get("wall_clock_utc"),
                "mode": started.get("mode"),
                "transport": started.get("transport"),
                "isolation": started.get("isolation"),
                "egress_observed": _egress_observed(started),
                "server_name": started.get("server_name"),
                "scenario_name": started.get("scenario_name"),
                "fleet": _fleet_of(ref, fleets),
                "state": run.judged.state,
                "exit_code": run.judged.exit_code,
                "causes": run.judged.causes,
            }
        )
    return _envelope("runs", notices, listed)


# -- one run ------------------------------------------------------------------------------------


def run(sources: Sources, ref: str) -> Envelope:
    """One run: its verdict, and every part of its recording in the tabs it has."""
    if sources.runs is None:
        return _not_given("run", "--runs")
    found_run = _run_of(sources, ref)
    notices: list[dict[str, Any]] = []
    first = _run_notice(found_run)
    if first is not None:
        notices.append(first)
    data: dict[str, Any] = {
        "ref": ref,
        "recording": _found.recording_path(ref),
        "sha256": found_run.digest,
        "verdict": _verdict_data(found_run),
    }
    if found_run.whole_refused:
        data["tabs"] = ["verdict"]
        return _envelope("run", notices, data)
    tabs = ["overview", "verdict", "messages", "findings"]
    started = found_run.started or {}
    data["egress_observed"] = _egress_observed(started)
    data.update(_server_version(started))
    data["engagement"] = _run_engagement(found_run, notices)
    if started.get("mode") == "driver":
        tabs.append("inventory")
    if found_run.of(*_INTERVENTION_EVENTS):
        tabs.append("interventions")
    if found_run.of(*_HTTP_EVENTS):
        tabs.append("http")
    elif started.get("transport") == events_module.TRANSPORT_HTTP:
        notices.append(
            _absent(
                "http_request",
                "view",
                "No HTTP event is in this recording of a Streamable HTTP run: its exchanges "
                "are not known.",
            )
        )
    isolation = started.get("isolation")
    if found_run.of(*_SANDBOX_EVENTS):
        tabs.append("sandbox")
    elif isinstance(isolation, str) and isolation in verdict.OBSERVED_ISOLATIONS:
        notices.append(
            _absent(
                "egress_summary",
                "view",
                f"No sandbox event is in this recording of a {isolation} run, egress_summary "
                'among them: what its target sent is unknown, not "nothing".',
            )
        )
    if found_run.of("server_stderr"):
        tabs.append("stderr")
    if _provenance(started) == "real-world":
        notices.append(_candidates(len(found_run.of("finding"))))
    data["tabs"] = tabs
    data["overview"] = _overview(found_run, notices)
    data["messages"] = _messages_tab(found_run, notices)
    data["findings"] = _findings_tab(found_run, notices)
    builders: dict[str, Callable[[_Run, list[dict[str, Any]]], dict[str, Any]]] = {
        "inventory": _inventory_tab,
        "interventions": _interventions_tab,
        "http": _http_tab,
        "sandbox": _sandbox_tab,
        "stderr": _stderr_tab,
    }
    for name, build in builders.items():
        if name in tabs:
            data[name] = build(found_run, notices)
    return _envelope("run", notices, data)


def _run_engagement(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The engagement header of a run, as its recording has it: the file's id, digest and window
    as ``run_started.authorization.engagement`` records them (declared, never checked here),
    ``run_started.pacing_enforced``, ``run_started.pacing`` and ``run_finished.window_exceeded``.
    None for a run under no file: ``authorization.engagement`` absent or null. A block that is
    not an object of exactly those three is refused whole, as a fleet's is, and no header is
    shown."""
    started = run.started or {}
    authorization = started.get("authorization")
    block = authorization.get("engagement") if isinstance(authorization, dict) else None
    if block is None:
        return None
    if not isinstance(block, dict) or set(block) != set(store_module._RECORDED_ENGAGEMENT):
        notices.append(
            _notice(
                "refused",
                "The engagement this run recorded is not one this version reads: it is refused "
                "whole, and no engagement is shown for the run.",
                "engagement",
                path=_found.recording_path(run.ref),
                words="run_started.authorization.engagement is not null or an object of exactly "
                + ", ".join(store_module._RECORDED_ENGAGEMENT),
                source=None,
            )
        )
        return None
    fields = block
    return {
        "engagement_id_declared": fields.get("engagement_id_declared"),
        "engagement_digest": fields.get("engagement_digest"),
        "window_declared": fields.get("window_declared"),
        "pacing_enforced": started.get("pacing_enforced"),
        "pacing": started.get("pacing"),
        "window_exceeded": (run.finished or {}).get("window_exceeded"),
    }


def _egress_observed(started: dict[str, Any]) -> bool:
    """Whether the run's isolation, as ``run_started`` records it, is one under which this
    version observes the server's egress (:data:`mcp_kymograph.verdict.OBSERVED_ISOLATIONS`).
    An isolation it does not know, or none recorded, is never observed."""
    isolation = started.get("isolation")
    return isinstance(isolation, str) and isolation in verdict.OBSERVED_ISOLATIONS


def _server_version(started: dict[str, Any]) -> dict[str, Any]:
    """The server's version as the run's manifest entry pinned it
    (``reproduction.corpus.identity``), with what kind of version it is, read from the
    identity's kind as the store reads it (:func:`mcp_kymograph.store.version_kind`) — an
    endpoint's is ``declared`` — never from the version string. Both None for a run without
    a manifest entry: it pins no version."""
    reproduction = started.get("reproduction")
    entry = reproduction.get("corpus") if isinstance(reproduction, dict) else None
    identity = entry.get("identity") if isinstance(entry, dict) else None
    if not isinstance(identity, dict):
        return {"server_version": None, "server_version_kind": None}
    kind = identity.get("kind")
    return {
        "server_version": identity.get("version"),
        "server_version_kind": store_module.version_kind(kind)
        if isinstance(kind, str)
        else store_module.UNKNOWN,
    }


def _provenance(started: dict[str, Any]) -> Any:
    """The provenance a run's ``run_started`` records from its manifest entry, or None."""
    reproduction = started.get("reproduction")
    entry = reproduction.get("corpus") if isinstance(reproduction, dict) else None
    return entry.get("provenance") if isinstance(entry, dict) else None


def _absent(event: str, where: str, text: str) -> dict[str, Any]:
    return _notice("not_in_this_recording", text, where, event=event)


def _overview(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    finished = run.finished
    if run.started is None:
        notices.append(
            _absent(
                "run_started",
                "tab:overview",
                "run_started is not in this recording: how the run was started is not known.",
            )
        )
    if finished is None:
        notices.append(
            _absent(
                "run_finished",
                "tab:overview",
                "run_finished is not in this recording: the recording ends early, and how the "
                "run ended is not known.",
            )
        )
    return {
        "run_started": run.started,
        # Why a handshake did not complete, as recorded: a ``tls`` one with the library's text
        # in ``detail``, which only the event holds whole (the verdict's words quote it).
        "server_failed": run.of("server_failed"),
        "server_exited": run.of("server_exited"),
        "server_name_mismatch": run.of("server_name_mismatch"),
        # How the opening settled the server's generation, and the generation and version the
        # script ended in: as recorded, for the run's header (``era_decided``, ``script_finished``).
        "era_decided": run.of("era_decided"),
        "script_finished": run.of("script_finished"),
        "run_stopped": run.of("run_stopped"),
        # The waits of a paced run, each as recorded (``paced``): no sum, no judgement.
        "paced": run.of("paced"),
        "recording_stopped": run.of("recording_stopped"),
        "limit_exceeded": run.of("limit_exceeded"),
        "run_finished": None
        if finished is None
        else {name: finished.get(name) for name in _FINISHED_FOR_OVERVIEW},
    }


def _messages_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    messages = run.of("message")
    truncated = [m.get("seq") for m in messages if m.get("truncated") is True]
    incomplete = [m.get("seq") for m in messages if m.get("incomplete") is True]
    notices.extend(_message_caps(run, truncated, incomplete, "tab:messages"))
    return {"total": len(messages), "truncated": truncated, "incomplete": incomplete}


def _message_caps(
    run: _Run, truncated: list[Any], incomplete: list[Any], where: str
) -> list[dict[str, Any]]:
    limits = (run.started or {}).get("limits")
    cap = limits.get("max_message_bytes") if isinstance(limits, dict) else None
    found = []
    if truncated:
        found.append(
            _capped(
                where,
                f"{len(truncated)} message(s) were cut at the message limit: what is shown of "
                "them is not all they held.",
                what="message payload",
                source="message.truncated",
                cap=cap,
                shown=None,
                total=None,
                seqs=truncated,
            )
        )
    if incomplete:
        found.append(
            _capped(
                where,
                f"{len(incomplete)} message(s) are recorded incomplete: their end was never "
                "read, and what is shown of them is not all they held.",
                what="message payload",
                source="message.incomplete",
                cap=cap,
                shown=None,
                total=None,
                seqs=incomplete,
            )
        )
    return found


def _with_class(event: dict[str, Any]) -> dict[str, Any]:
    """A finding event with its class beside it, derived from the signal of its key here and
    never filed (finding_classes); ``finding_class`` is ``None`` for a signal this version does
    not know. The recording is not changed."""
    key = event.get("key")
    return {**event, "finding_class": _class_of_key(key if isinstance(key, dict) else {})}


def _findings_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    finished = run.finished
    findings = run.of("finding")
    observations = run.of("observation")
    capped = run.of("findings_capped")
    for event in capped:
        notices.append(
            _capped(
                "tab:findings",
                f"{event.get('recorded')} of {event.get('made')} findings of message seq "
                f"{event.get('message_seq')} recorded, capped at {event.get('cap')} per "
                "message; what was cut is counted by statement and signal.",
                what="findings",
                source="findings_capped",
                cap=event.get("cap"),
                shown=event.get("recorded"),
                total=event.get("made"),
                message_seq=event.get("message_seq"),
            )
        )
    bounded = finished.get("inspection_bounded") if finished else None
    if bounded:
        notices.append(
            _capped(
                "tab:findings",
                f"{bounded} message(s) were only partly inspected: a work bound stopped the "
                "inspection, and what lay past it was not looked at.",
                what="messages inspected",
                source="run_finished.inspection_bounded",
                cap=None,
                shown=None,
                total=None,
                count=bounded,
            )
        )
    if finished is None:
        notices.append(
            _absent(
                "run_finished",
                "tab:findings",
                "run_finished is not in this recording: the counts the findings are checked "
                "against are missing, and findings may be missing too.",
            )
        )
    if findings or observations:
        notices.append(
            _notice(
                "not_recorded_by_this_version",
                "The characters a signal fired on are not recorded by this version: the field "
                "is named, not the span within it.",
                "tab:findings",
                what="the characters a signal fired on",
            )
        )
    return {
        "findings": [_with_class(e) for e in findings],
        "observations": observations,
        "statements_evaluated": run.of("statement_evaluated"),
        "findings_capped": capped,
        "findings_by_statement": None
        if finished is None
        else finished.get("findings_by_statement"),
        "observations_by_method": None
        if finished is None
        else finished.get("observations_by_method"),
    }


def _points_into(path: Any, prefix: str) -> bool:
    return isinstance(path, str) and (
        path == prefix or path.startswith(prefix + ".") or path.startswith(prefix + "[")
    )


def _inventory_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    steps = []
    for event in run.events:
        kind = event.get("type")
        if kind == "message" and event.get("direction") == "client_to_server":
            parse = event.get("parse") if isinstance(event.get("parse"), dict) else {}
            steps.append(
                {
                    "seq": event.get("seq"),
                    "type": "message",
                    "method": parse.get("method"),
                    "id": parse.get("id"),
                    "kind": parse.get("kind"),
                }
            )
        elif kind in _STEP_EVENTS:
            steps.append(event)
    finished_script = run.of("script_finished")
    if not finished_script:
        notices.append(
            _absent(
                "script_finished",
                "tab:inventory",
                "script_finished is not in this recording: the script never recorded its end, "
                "and the inventory may be partial.",
            )
        )
    marked = run.of("finding", "observation")
    listings = {}
    for name, method in LISTINGS:
        items, seqs = [], []
        for event in run.of("message"):
            if event.get("direction") != "server_to_client":
                continue
            if event.get("responded_method") != method:
                continue
            payload = event.get("payload")
            document = payload.get("data") if isinstance(payload, dict) else None
            result = document.get("result") if isinstance(document, dict) else None
            listed = result.get(name) if isinstance(result, dict) else None
            if not isinstance(listed, list):
                continue
            seq = event.get("seq")
            seqs.append(seq)
            for index, item in enumerate(listed):
                prefix = f"result.{name}[{index}]"
                here = [
                    e
                    for e in marked
                    if e.get("message_seq") == seq and _points_into(e.get("path"), prefix)
                ]
                items.append(
                    {
                        "item": item,
                        "message_seq": seq,
                        "path": prefix,
                        "findings": [_with_class(e) for e in here if e.get("type") == "finding"],
                        "observations": [e for e in here if e.get("type") == "observation"],
                    }
                )
        listings[name] = {"items": items, "pages": len(seqs), "seqs": seqs}
        if seqs:
            notices.append(
                _notice(
                    "not_recorded_by_this_version",
                    "Pages per listing are not recorded by this version as a number: they are "
                    "counted here from the messages that answered the listing.",
                    f"listing:{name}",
                    what="pages per listing",
                )
            )
    by_method = {method: name for name, method in LISTINGS}
    for event in run.of("step_skipped"):
        if event.get("reason") == events_module.PAGE_LIMIT:
            step = event.get("step")
            name = by_method.get(step) if isinstance(step, str) else None
            shown = len(listings[name]["items"]) if name else None
            notices.append(
                _capped(
                    f"listing:{name}" if name else "tab:inventory",
                    f"The listing {event.get('step')} was cut at the driver's page limit "
                    f"({event.get('detail') or MAX_PAGES} pages): what lay past it was not "
                    "asked for.",
                    what=name or str(event.get("step")),
                    source="step_skipped.page_limit_reached",
                    cap=event.get("detail") or MAX_PAGES,
                    shown=shown,
                    total=None,
                )
            )
    for event in finished_script:
        if event.get("inventory") != events_module.INVENTORY_CAPPED:
            continue
        skipped = event.get("skipped") if isinstance(event.get("skipped"), list) else []
        named = [
            by_method.get(pair[0])
            for pair in skipped
            if isinstance(pair, list)
            and len(pair) == 2
            and isinstance(pair[0], str)
            and pair[1] == events_module.PAGE_LIMIT
        ]
        for name in [n for n in named if n] or [None]:
            notices.append(
                _capped(
                    f"listing:{name}" if name else "tab:inventory",
                    "The script ended with its inventory capped: a listing reached the page "
                    "limit, and what lay past it was not asked for.",
                    what=name or "inventory",
                    source="script_finished.inventory",
                    cap=MAX_PAGES,
                    shown=len(listings[name]["items"]) if name else None,
                    total=None,
                )
            )
    return {
        "steps": steps,
        "script_finished": finished_script[-1] if finished_script else None,
        "listings": listings,
    }


def _linked_interventions(run: _Run) -> dict[Any, list[dict[str, Any]]]:
    """Each intervention by the seq of the message it acted on.

    An intervention names its message by direction and id, not by seq; it is recorded after
    the original message it acted on. It is taken to be that message's only when the message
    recorded last in its direction carries its id — otherwise (a message event dropped from a
    full queue) it is linked to none, and shown only among the interventions.
    """
    last: dict[Any, dict[str, Any]] = {}
    linked: dict[Any, list[dict[str, Any]]] = {}
    for event in run.events:
        kind, direction = event.get("type"), event.get("direction")
        if not isinstance(direction, str):
            continue  # names no direction: no message of it can be told apart
        if kind == "message":
            last[direction] = event
        elif kind == "intervention":
            message = last.get(direction)
            parse = message.get("parse") if message else None
            seq = message.get("seq") if message else None
            if (
                isinstance(parse, dict)
                and parse.get("id") == event.get("message_id")
                and isinstance(seq, int)
                and not isinstance(seq, bool)
            ):
                linked.setdefault(seq, []).append(event)
    return linked


def _quarantined(run: _Run) -> set[str]:
    rules = {e.get("rule") for e in run.of("rule_quarantined") if isinstance(e.get("rule"), str)}
    named = (run.finished or {}).get("quarantined_rules")
    if isinstance(named, list):
        rules |= {rule for rule in named if isinstance(rule, str)}
    return rules


def _step_rules(intervention: dict[str, Any]) -> set[str]:
    steps = intervention.get("steps")
    if not isinstance(steps, list):
        return set()
    return {s.get("rule") for s in steps if isinstance(s, dict) and isinstance(s.get("rule"), str)}


def _interventions_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    interventions = run.of("intervention")
    quarantined = _quarantined(run)
    linked = _linked_interventions(run)
    message_of = {id(e): seq for seq, found in linked.items() for e in found}
    return {
        "interventions": [
            {
                "event": event,
                "message_seq": message_of.get(id(event)),
                "invalidated_by": sorted(_step_rules(event) & quarantined),
            }
            for event in interventions
        ],
        "rule_quarantined": [
            {
                "event": event,
                "invalidates": [
                    e.get("seq")
                    for e in interventions
                    if isinstance(event.get("rule"), str) and event.get("rule") in _step_rules(e)
                ],
            }
            for event in run.of("rule_quarantined")
        ],
        "quarantined_rules": sorted(quarantined),
    }


def _http_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    exchanges: dict[Any, dict[str, Any]] = {}
    for event in run.events:
        kind = event.get("type")
        number = event.get("exchange")
        if kind not in (*_HTTP_EVENTS, "message") or not isinstance(number, (int, str)):
            continue
        entry = exchanges.setdefault(
            number,
            {"exchange": number, "request": [], "response": [], "end": [], "messages": []},
        )
        slot = {
            "http_request": "request",
            "http_response": "response",
            "http_end": "end",
            "message": "messages",
        }[kind]
        entry[slot].append(event.get("seq") if kind == "message" else event)
    return {
        "exchanges": list(exchanges.values()),
        "http": (run.finished or {}).get("http"),
    }


def _sandbox_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    summary = run.of("egress_summary")
    isolation = (run.started or {}).get("isolation")
    if isolation in verdict.OBSERVED_ISOLATIONS and not summary:
        notices.append(
            _absent(
                "egress_summary",
                "tab:sandbox",
                f"egress_summary is not in this recording: a {isolation} run without the "
                'account of what its target sent; its egress is unknown, not "nothing".',
            )
        )
    for what, text in (
        (
            "the sink's count per destination where it equals the kernel's",
            "The sink's count per destination is recorded only where it differs from the "
            "kernel's (account_differences); where they agree it is not recorded by this "
            "version.",
        ),
        (
            "a gate or target-started sandbox step",
            "No sandbox step for the gate as a whole or for the target's start is recorded by "
            "this version: the gate's conditions are the steps themselves.",
        ),
        (
            "the files-delivered check",
            "The check that the files delivered are the entry's is made before the run and "
            "refuses it on a mismatch; that it held is not recorded by this version.",
        ),
    ):
        notices.append(_notice("not_recorded_by_this_version", text, "tab:sandbox", what=what))
    return {
        "steps": run.of("sandbox_step"),
        "sandbox_failed": run.of("sandbox_failed"),
        "egress_attempt": run.of("egress_attempt"),
        "egress_dns": run.of("egress_dns"),
        "egress_summary": summary[-1] if summary else None,
    }


def _stderr_tab(run: _Run, notices: list[dict[str, Any]]) -> dict[str, Any]:
    return {"server_stderr": run.of("server_stderr")}


# -- messages -----------------------------------------------------------------------------------


def _int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ViewError(400, f"{name} must be a whole number, not {value!r}")
    return value


def messages(sources: Sources, ref: str, offset: int, limit: int) -> Envelope:
    """One page of a run's messages, in recording order, each as its analysis and marks."""
    offset, limit = _int(offset, "offset"), _int(limit, "limit")
    if offset < 0:
        raise ViewError(400, f"offset must not be below 0, not {offset}")
    if not 1 <= limit <= MAX_MESSAGE_PAGE:
        raise ViewError(400, f"limit must be between 1 and {MAX_MESSAGE_PAGE}, not {limit}")
    if sources.runs is None:
        return _not_given("messages", "--runs")
    found_run = _run_of(sources, ref)
    notices = [n for n in (_run_notice(found_run),) if n is not None]
    if found_run.whole_refused:
        return _envelope("messages", notices, None)
    linked = _linked_interventions(found_run)
    quarantined = _quarantined(found_run)
    listed = found_run.of("message")
    items = []
    for event in listed[offset : offset + limit]:
        parse = event.get("parse") if isinstance(event.get("parse"), dict) else {}
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        seq = event.get("seq")
        acted = linked.get(seq, []) if isinstance(seq, int) else []
        items.append(
            {
                "seq": event.get("seq"),
                "direction": event.get("direction"),
                "size_bytes": event.get("size_bytes"),
                "truncated": event.get("truncated"),
                "incomplete": event.get("incomplete"),
                "method": parse.get("method"),
                "responded_method": event.get("responded_method"),
                "id": parse.get("id"),
                "kind": parse.get("kind"),
                "is_error": parse.get("is_error"),
                "redaction_count": payload.get("redaction_count"),
                "exchange": event.get("exchange"),
                "intervened": bool(acted),
                "quarantined": any(_step_rules(e) & quarantined for e in acted),
            }
        )
    return _envelope("messages", notices, {"total": len(listed), "offset": offset, "items": items})


def message(sources: Sources, ref: str, seq: int) -> Envelope:
    """One message as recorded, with what acted on it and what was seen in it."""
    seq = _int(seq, "seq")
    if sources.runs is None:
        return _not_given("message", "--runs")
    found_run = _run_of(sources, ref)
    notices = [n for n in (_run_notice(found_run),) if n is not None]
    if found_run.whole_refused:
        return _envelope("message", notices, None)
    event = next((e for e in found_run.of("message") if e.get("seq") == seq), None)
    if event is None:
        raise ViewError(404, f"{ref}: no message with seq {seq} in this recording")
    notices.extend(
        _message_caps(
            found_run,
            [seq] if event.get("truncated") is True else [],
            [seq] if event.get("incomplete") is True else [],
            "view",
        )
    )
    seen = [e for e in found_run.of("observation", "finding") if e.get("message_seq") == seq]
    data = {
        "message": event,
        "interventions": _linked_interventions(found_run).get(seq, []),
        "observations": [e for e in seen if e.get("type") == "observation"],
        "findings": [_with_class(e) for e in seen if e.get("type") == "finding"],
    }
    return _envelope("message", notices, data)


# -- the store ----------------------------------------------------------------------------------


def store_runs(sources: Sources) -> Envelope:
    """Every run in the store, with where its recording is under ``--runs`` and whether it is
    still the one the store filed."""
    if sources.store is None:
        return _not_given("store_runs", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("store_runs", [refused.notice], None)
    with opened as store:
        infos = store.runs()
        filed = store.recordings()
    found = None if sources.runs is None else _found.search(sources.runs)
    notices: list[dict[str, Any]] = [] if found is None else _unreadable_directories(found, None)
    rows = []
    for info in infos:
        where = f"run:{info.run}"
        row = info.to_dict()
        recording = filed.get(info.run)
        row.update(recording=recording, recording_status="not_found", ref=None)
        resolved = (
            None
            if found is None or not isinstance(recording, str)
            else _found.resolve_filed(found, recording)
        )
        if resolved is None:
            looked_in = None if sources.runs is None else str(sources.runs)
            notices.append(_recording_not_found(where, recording, looked_in))
        else:
            ref, path = resolved
            try:
                digest, unreadable = hashlib.sha256(_found.read_bytes(path)).hexdigest(), None
            except OSError as exc:
                digest, unreadable = None, str(exc.strerror or exc)
            if digest == info.run:
                row.update(recording_status="found", ref=ref)
            else:
                row.update(recording_status="changed")
                notices.append(
                    _recording_changed(where, recording, ref, info.run, digest, unreadable)
                )
        if not info.complete:
            notices.append(
                _not_a_result(
                    info.state,
                    verdict.EXIT_CODES.get(info.state),
                    info.rules,
                    _filed_causes(info.causes),
                    where,
                    problems=list(info.problems),
                )
            )
        if info.problem_count > len(info.problems):
            notices.append(
                _capped(
                    where,
                    f"{len(info.problems)} of {info.problem_count} problems shown, capped: the "
                    "store keeps the first "
                    f"{store_module.MAX_LISTED_PROBLEMS} and counts the rest.",
                    what="problems",
                    source="runs.problems",
                    cap=store_module.MAX_LISTED_PROBLEMS,
                    shown=len(info.problems),
                    total=info.problem_count,
                )
            )
        rows.append(row)
    return _envelope("store_runs", notices, rows)


def _recording_not_found(where: str, recording: Any, looked_in: str | None) -> dict[str, Any]:
    return _notice(
        "recording_not_found",
        "This run's recording was not looked for: no --runs was given."
        if looked_in is None
        else "This run's recording is not under --runs: it was looked for there and nowhere else.",
        where,
        recording=recording,
        looked_in=looked_in,
    )


def _recording_changed(
    where: str, recording: Any, ref: str, filed: str, digest: str | None, unreadable: str | None
) -> dict[str, Any]:
    return _notice(
        "recording_changed",
        "A file was found where this run's recording should be, and it is not the recording "
        "the store filed: its bytes differ. It is not shown as this run's."
        if unreadable is None
        else "A file was found where this run's recording should be, and it could not be read: "
        "it cannot be held against what the store filed, so it is not shown as this run's.",
        where,
        recording=recording,
        found=_found.recording_path(ref),
        filed=filed,
        found_digest=digest,
        unreadable=unreadable,
    )


def store_findings(sources: Sources, provenance: str) -> Envelope:
    """Every filed finding of one publishable provenance. Real-world findings are not here."""
    if provenance == "real-world":
        raise ViewError(
            400,
            "real-world findings are candidates for disclosure and are listed apart, at "
            "/api/store/candidates; never among the publishable findings",
        )
    if provenance not in PUBLISHABLE:
        raise ViewError(400, f"unknown provenance {provenance!r}; one of {', '.join(PUBLISHABLE)}")
    if sources.store is None:
        return _not_given("store_findings", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("store_findings", [refused.notice], None)
    with opened as store:
        found = store.findings_by_provenance(provenance)
        short = _not_results_of(store, provenance)
    return _envelope("store_findings", short, found)


def store_candidates(sources: Sources) -> Envelope:
    """The real-world findings, apart: candidates for disclosure, not results to publish."""
    if sources.store is None:
        envelope = _not_given("store_candidates", "--store")
        envelope["notices"].append(_candidates(None))
        return envelope
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("store_candidates", [refused.notice, _candidates(None)], None)
    with opened as store:
        found = store.findings_by_provenance("real-world")
        short = _not_results_of(store, "real-world")
    return _envelope("store_candidates", [*short, _candidates(len(found))], found)


def _not_results_of(
    store: store_module.Store, provenance: str, where: str = "view"
) -> list[dict[str, Any]]:
    """``not_a_result`` for a listing of findings of one provenance when runs of it in the store
    are not results: a finding absent from the listing may only be missing from them."""
    of_it = [info for info in store.runs() if info.provenance == provenance]
    short = [info for info in of_it if not info.complete]
    if not short:
        return []
    return [
        _notice(
            "not_a_result",
            f"{len(short)} of {len(of_it)} {provenance} runs in the store are not a result: a "
            "finding absent here may only be missing from them.",
            where,
            state=None,
            exit_code=None,
            rules=None,
            causes=_filed_causes(sorted({c for info in short for c in info.causes})),
            runs=[
                {"run": info.run, "state": info.state, "causes": list(info.causes)}
                for info in short
            ],
            count=len(short),
            total=len(of_it),
        )
    ]


def _resolve_run(store: store_module.Store, reference: Any, name: str) -> str:
    """A run by its id or an unambiguous prefix of it (8+ characters), as ``store diff`` takes
    one — but never as a path: nothing on disk is looked at for it."""
    if not isinstance(reference, str) or not reference:
        raise ViewError(400, f"give {name}: a run id, or at least 8 characters of one")
    if len(reference) < 8 or any(c not in "0123456789abcdef" for c in reference):
        raise ViewError(400, f"{name} {reference!r}: give at least 8 hex characters of a run id")
    matches = [info.run for info in store.runs() if info.run.startswith(reference)]
    if not matches:
        raise ViewError(404, f"{name} {reference!r}: no such run in the store")
    if len(matches) > 1:
        raise ViewError(400, f"{name} {reference!r}: matches {len(matches)} runs; give more of it")
    return matches[0]


_CAPPED_CAVEATS = {
    store_module.FINDINGS_CAPPED: ("findings", "caveats: findings_capped"),
    store_module.LISTING_CAPPED: ("listing", "caveats: listing_capped"),
}


def _diff_caps(
    caveats: dict[str, list[str]],
    sets: dict[str, list[dict[str, Any]]],
    where_of: Callable[[str], str],
) -> list[dict[str, Any]]:
    """``capped`` for every set a comparison flags as reaching where a run cut findings or a
    listing — from its caveats and its entries' ``cap_hint``, never worked out anew."""
    found = []
    for name, entries in sets.items():
        flags = caveats.get(name) or []
        hinted = [e for e in entries if e.get("cap_hint")]
        for caveat, (what, source) in _CAPPED_CAVEATS.items():
            if caveat not in flags:
                continue
            found.append(
                _capped(
                    where_of(name),
                    f"{len(entries)} {name} shown, and a run cut {what} at a cap: "
                    + (
                        f"{len(hinted)} of them may be among what was cut rather than {name}."
                        if what == "findings"
                        else "what lay past the driver's page limit was not looked at."
                    ),
                    what=what,
                    source=source,
                    cap=None,
                    shown=len(entries),
                    total=None,
                    cap_hints=len(hinted),
                )
            )
    return found


def store_diff(sources: Sources, before: str, after: str) -> Envelope:
    """New, gone and unchanged between two runs of the store, as :meth:`Store.diff` says."""
    if sources.store is None:
        return _not_given("store_diff", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("store_diff", [refused.notice], None)
    with opened as store:
        first = _resolve_run(store, before, "before")
        second = _resolve_run(store, after, "after")
        diff = store.diff(first, second)
    compared = diff.to_dict()
    notices = []
    if not diff.complete:
        notices.append(
            _notice(
                "comparison_not_complete",
                "The comparison is not complete: a run in it is not a result, so a finding "
                "that is gone may only be missing.",
                before_state=diff.before.state,
                after_state=diff.after.state,
            )
        )
    notices.extend(
        _diff_caps(
            compared["caveats"],
            {"new": compared["new"], "gone": compared["gone"]},
            lambda name: name,
        )
    )
    for side, info in (("before", diff.before), ("after", diff.after)):
        if info.truncations:
            notices.append(
                _capped(
                    "unchanged",
                    f"The {side} run recorded caps (truncations): an unchanged finding may have "
                    "been seen in fewer places than it sat.",
                    what="sightings",
                    source=f"{side}.truncations",
                    cap=None,
                    shown=len(compared["unchanged"]),
                    total=None,
                )
            )
    if "real-world" in (diff.before.provenance, diff.after.provenance):
        notices.append(_candidates(len(diff.new) + len(diff.gone) + len(diff.unchanged)))
    return _envelope("store_diff", notices, compared)


# -- fleets -------------------------------------------------------------------------------------


def _fleet_state(info: dict[str, Any], found: _found.Found | None) -> _found.FleetFile:
    """A fleet's ``fleet.json`` under ``--runs``, held against the digest the store filed the
    fleet under (``fleets.digest``, the digest the fleet wrote into the file)."""
    fleet = info["fleet"]
    if found is None:
        return _found.FleetFile(None, f"{fleet}/{_found.FLEET_FILE} (no --runs was given)")
    return _found.fleet_file(found, fleet, info["digest"])


def _no_fleet_state(fleet: str, taken: _found.FleetFile, where: str) -> dict[str, Any]:
    return _notice(
        "fleet_state_not_in_store",
        (
            "This fleet's state is not recorded in the store, and its fleet.json was not found "
            "under --runs: no state is shown, and none is worked out from its results."
            if taken.problem is None
            else "This fleet's state is not recorded in the store, and the fleet.json found "
            f"under --runs is not taken: {taken.problem}. No state is shown, and none is "
            "worked out from its results."
        ),
        where,
        fleet=fleet,
        looked_for=taken.looked_for,
        found=taken.found,
    )


def _fleet_engagement(
    taken: _found.FleetFile, where: str, notices: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The engagement a fleet ran under, as its ``fleet.json`` records it
    (:func:`mcp_kymograph.fleet.recorded_engagement`): the file's id, digest and window as
    declared, or None for a fleet under no file. A block that is not one is refused whole, and
    a ``refused`` notice says so where the header would be."""
    if taken.content is None:
        return None
    try:
        return fleet_module.recorded_engagement(taken.content)
    except fleet_module.FleetError as refusal:
        notices.append(
            _notice(
                "refused",
                "The engagement block of this fleet's fleet.json is not one this version reads: "
                "it is refused whole, and no engagement is shown for the fleet.",
                where,
                path=f"{taken.ref}/{_found.FLEET_FILE}",
                words=str(refusal),
                source=None,
            )
        )
        return None


def _candidate_count(content: dict[str, Any]) -> int | None:
    """The real-world findings a ``fleet.json`` counts, or None where it holds no count."""
    candidates = content.get("disclosure_candidates")
    count = candidates.get("real-world") if isinstance(candidates, dict) else None
    return count if isinstance(count, int) and not isinstance(count, bool) else None


def _plain_fleet(info: dict[str, Any]) -> dict[str, Any]:
    """A fleet row of the store with its tuples as lists and its results as a list."""
    plain = {key: value for key, value in info.items() if key != "results"}
    plain["processed"] = [list(pair) for pair in info.get("processed", ())]
    return plain


def fleets(sources: Sources) -> Envelope:
    """Every fleet run in the store, oldest first, with its state from its ``fleet.json``."""
    if sources.store is None:
        return _not_given("fleets", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("fleets", [refused.notice], None)
    with opened as store:
        listed = store.fleets()
    found = None if sources.runs is None else _found.search(sources.runs)
    notices: list[dict[str, Any]] = []
    rows = []
    for info in listed:
        row = _plain_fleet(info)
        taken = _fleet_state(info, found)
        where = f"fleet:{info['fleet']}"
        if taken.content is None:
            row["fleet_json"] = None
            row["engagement"] = None
            notices.append(_no_fleet_state(info["fleet"], taken, where))
        else:
            row["fleet_json"] = {
                "state": taken.content.get("state"),
                "interrupted": taken.content.get("interrupted"),
            }
            row["engagement"] = _fleet_engagement(taken, where, notices)
            count = _candidate_count(taken.content)
            if count:
                notices.append(_candidates(count, where))
        rows.append(row)
    return _envelope("fleets", notices, rows)


def _resolve_fleet(store: store_module.Store, reference: Any, name: str) -> str:
    if not isinstance(reference, str) or not reference:
        raise ViewError(400, f"give {name}: a fleet id, or an unambiguous prefix of one")
    ids = [info["fleet"] for info in store.fleets()]
    if reference in ids:
        return reference
    matches = [fleet for fleet in ids if fleet.startswith(reference)]
    if not matches:
        raise ViewError(404, f"{name} {reference!r}: no such fleet run in the store")
    if len(matches) > 1:
        raise ViewError(
            400, f"{name} {reference!r}: matches {len(matches)} fleet runs; give more of it"
        )
    return matches[0]


def fleet(sources: Sources, fleet_id: str) -> Envelope:
    """One fleet run: what the store filed, and its state and findings from its ``fleet.json``."""
    if sources.store is None:
        return _not_given("fleet", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("fleet", [refused.notice], None)
    with opened as store:
        name = _resolve_fleet(store, fleet_id, "id")
        info = store.fleet(name)
    found = None if sources.runs is None else _found.search(sources.runs)
    taken = _fleet_state(info, found)
    data = _plain_fleet(info)
    data["results"] = [info["results"][key] for key in sorted(info["results"])]
    notices: list[dict[str, Any]] = []
    if taken.content is None:
        notices.append(_no_fleet_state(name, taken, "view"))
        data.update(
            state=None,
            interrupted=None,
            findings=None,
            disclosure_candidates=None,
            engagement=None,
        )
    else:
        data.update(
            state=taken.content.get("state"),
            interrupted=taken.content.get("interrupted"),
            findings=taken.content.get("findings"),
            disclosure_candidates=taken.content.get("disclosure_candidates"),
            engagement=_fleet_engagement(taken, "engagement", notices),
        )
        notices.append(_candidates(_candidate_count(taken.content)))
    for result in data["results"]:
        if result["state"] != verdict.COMPLETE:
            notices.append(
                _not_a_result(
                    result["state"],
                    result["exit_code"],
                    info["rules"],
                    _filed_causes(result["causes"]),
                    f"result:{result['entry']}/{result['scenario']}",
                    problems=result["problems"],
                )
            )
    return _envelope("fleet", notices, data)


def fleet_compare(sources: Sources, before: str | None, after: str | None) -> Envelope:
    """Two fleet runs, entry by entry, as :func:`mcp_kymograph.fleet.compare` says; both left
    out, the last two in the store."""
    if (before is None) != (after is None):
        raise ViewError(400, "give both fleet runs, or neither for the last two")
    if sources.store is None:
        return _not_given("fleet_compare", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("fleet_compare", [refused.notice], None)
    with opened as store:
        if before is None:
            ids = [info["fleet"] for info in store.fleets()]
            if len(ids) < 2:
                raise ViewError(404, "fewer than two fleet runs in the store")
            first, second = ids[-2], ids[-1]
        else:
            first = _resolve_fleet(store, before, "before")
            second = _resolve_fleet(store, after, "after")
        compared = fleet_module.compare(store, first, second)
        filed = {"before": store.fleet(first), "after": store.fleet(second)}
    found = None if sources.runs is None else _found.search(sources.runs)
    notices: list[dict[str, Any]] = []
    states = {}
    for side, name in (("before", first), ("after", second)):
        taken = _fleet_state(filed[side], found)
        states[side] = None if taken.content is None else taken.content.get("state")
        if taken.content is None:
            notices.append(_no_fleet_state(name, taken, "view"))
    if not compared["complete"]:
        notices.append(
            _notice(
                "comparison_not_complete",
                "The comparison is not complete: an entry in it is not a result on one side, "
                "or has no filed run to compare, so a finding that is gone may only be missing.",
                before_state=states["before"],
                after_state=states["after"],
            )
        )
    for entry in compared["entries"]:
        where = f"entry:{entry['entry']}/{entry['scenario']}"
        key = (entry["entry"], entry["scenario"])
        # Each side's result as the store filed it: its state, its causes, its provenance.
        results = {
            side: filed[side]["results"][key]
            for side in ("before", "after")
            if key in filed[side]["results"]
        }
        for side, result in results.items():
            if result["state"] != verdict.COMPLETE:
                notices.append(
                    _not_a_result(
                        result["state"],
                        result["exit_code"],
                        compared["rules"][side],
                        _filed_causes(result["causes"]),
                        where,
                        side=side,
                    )
                )
        if any(r["provenance"] == "real-world" for r in results.values()):
            briefed = entry.get("new", []) + entry.get("gone", [])
            unchanged = entry.get("unchanged")
            notices.append(
                _candidates(
                    len(briefed) + unchanged
                    if entry["change"] == "compared" and isinstance(unchanged, int)
                    else None,
                    where,
                )
            )
        if entry["change"] == "compared":
            notices.extend(
                _diff_caps(
                    entry["caveats"],
                    {"new": entry["new"], "gone": entry["gone"]},
                    lambda _name, where=where: where,
                )
            )
    return _envelope("fleet_compare", notices, compared)


# -- manifests and scenarios ---------------------------------------------------------------------


def _source_text(path: Path) -> str | None:
    """A file's text as the loaders read it: UTF-8, at most their size; None if not that.

    A file the operator named on the command line, read as the loaders read it — a symbolic
    link to it followed. Only the search of ``--runs`` refuses links."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(scenario_module.MAX_FILE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > scenario_module.MAX_FILE_BYTES:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _refused(path: Path, words: str) -> dict[str, Any]:
    return _notice(
        "refused",
        "The file was refused by the loader, whole: nothing of it was read but its text, shown "
        "beside the loader's words.",
        source=_source_text(path),
        path=str(path),
        words=words,
    )


def _listing(paths_given: tuple[Path, ...], load: Callable[[Path], Any]) -> list[dict[str, Any]]:
    listed = []
    for index, path in enumerate(paths_given):
        try:
            load(path)
            ok = True
        except ValueError:
            ok = False
        listed.append({"index": index, "path": str(path), "ok": ok})
    return listed


def _given(paths_given: tuple[Path, ...], index: Any) -> Path:
    index = _int(index, "index")
    if not 0 <= index < len(paths_given):
        raise ViewError(404, f"no file at index {index}; {len(paths_given)} given")
    return paths_given[index]


def corpora(sources: Sources) -> Envelope:
    """The manifests given, each with whether the project's loader takes it."""
    if not sources.manifests:
        return _not_given("corpora", "--manifest")
    return _envelope("corpora", [], _listing(sources.manifests, corpus_module.load))


def _relative(path: Path, directory: Path) -> str:
    return Path(os.path.relpath(path, directory)).as_posix()


def corpus(sources: Sources, index: int) -> Envelope:
    """One manifest as :func:`mcp_kymograph.corpus.load` reads it, beside its text."""
    if not sources.manifests:
        return _not_given("corpus", "--manifest")
    path = _given(sources.manifests, index)
    try:
        manifest = corpus_module.load(path)
    except corpus_module.ManifestError as refusal:
        return _envelope("corpus", [_refused(path, str(refusal))], None)
    data = {
        "path": str(path),
        "format_version": corpus_module.FORMAT_VERSION,
        "manifest": {"source": manifest.source, "digest": manifest.digest},
        "tool": corpus_module.tool_identity(),
        "entries": [
            {
                "name": entry.name,
                "provenance": entry.provenance,
                "identity": entry.identity.to_dict(),
                "paths": [_relative(p, manifest.directory) for p in entry.paths],
                "launch_digest": entry.launch_digest,
                "transport": entry.transport,
                "command": list(entry.command_written),
                "scenarios": [
                    {
                        "name": ref.name,
                        "digest": ref.digest,
                        "path": _relative(ref.path, manifest.directory),
                    }
                    for ref in entry.scenarios
                ],
                "server_version_kind": store_module.version_kind(entry.identity.kind),
                "endpoint": entry.endpoint,
                # An endpoint entry runs under one isolation whatever its provenance permits a
                # command entry (policy.decide).
                "isolation_permitted": [policy.ENDPOINT_ISOLATION]
                if entry.endpoint is not None
                else list(policy.PERMITTED.get(entry.provenance, ())),
                "isolation_provided": list(policy.PROVIDED),
                "refused_here": entry.refusal_to_run(),
            }
            for entry in manifest.entries
        ],
        "source": _source_text(path),
    }
    return _envelope("corpus", [], data)


def scenarios(sources: Sources) -> Envelope:
    """The scenario files given, each with whether the project's loader takes it."""
    if not sources.scenarios:
        return _not_given("scenarios", "--scenario")
    return _envelope("scenarios", [], _listing(sources.scenarios, scenario_module.load))


def scenario(sources: Sources, index: int) -> Envelope:
    """One scenario file as :func:`mcp_kymograph.scenario.load` reads it, beside its text."""
    if not sources.scenarios:
        return _not_given("scenario", "--scenario")
    path = _given(sources.scenarios, index)
    try:
        loaded = scenario_module.load(path)
    except scenario_module.ScenarioError as refusal:
        return _envelope("scenario", [_refused(path, str(refusal))], None)
    data = {
        "path": str(path),
        "source_name": loaded.source,
        "format_version": scenario_module.FORMAT_VERSION,
        "name": loaded.name,
        "digest": loaded.digest,
        "rules": [
            {
                "name": rule.name,
                "direction": rule.direction.value,
                "method": rule.method,
                "action": rule.action,
                "path": None if rule.path is None else rule.path.text,
                "value": rule.value,
                "text": rule.text,
                "position": rule.position,
            }
            for rule in loaded.rules
        ],
        "statements": [
            {
                "name": statement.name,
                "method": statement.method,
                "path": statement.path.text,
                "signals": [signal.value for signal in statement.signals],
            }
            for statement in loaded.statements
        ],
        "source": _source_text(path),
    }
    return _envelope("scenario", [], data)


# -- signals ------------------------------------------------------------------------------------


def _code_points(characters: Iterable[Any]) -> list[str]:
    return [f"U+{ord(c) if isinstance(c, str) else c:04X}" for c in sorted(characters)]


def signals(sources: Sources) -> Envelope:
    """The signal library, the surfaces, the locator identities, the normalisation and the caps,
    generated from the modules at the time of the call."""
    library = signals_module.LIBRARY
    data = {
        "signals": [
            {
                "signal": d.signal.value,
                "kind": d.signal.kind.value,
                "view": d.view.value,
                "reach": d.reach.value,
            }
            for d in library
        ],
        "inspector_only": [
            s.value for s in signals_module.Signal if s not in signals_module.BY_SIGNAL
        ],
        # What one hit of each signal is (signals.KINDS), the inspector-only ones included, and
        # the code's own words for the two: a heuristic's hit is a shape honest content has
        # too. No severity and no verdict.
        "signal_kinds": {s.value: s.kind.value for s in signals_module.Signal},
        "kinds": [kind.value for kind in signals_module.Kind],
        "kind_meaning": inspect.getdoc(signals_module.Kind),
        "views": [view.value for view in signals_module.View],
        "reaches": [reach.value for reach in signals_module.Reach],
        "walk": {
            "metadata_surfaces": [s.value for s in signals_module.WALK_METADATA],
            "other_surfaces": [s.value for s in signals_module.WALK_CONTENT],
        },
        "surfaces": [
            {"surface": s.value, "metadata": s in inspection.METADATA_SURFACES}
            for s in inspection.Surface
        ],
        "statement_reasons": [reason.value for reason in inspection.Reason],
        "identity_fields": [
            {"list": listed, "field": member} for listed, member in paths.IDENTITY_FIELDS.items()
        ],
        "normalization": {
            # The order is the code's (signals._flatten); its docstring is the only place
            # the code says it in words.
            "order": inspect.getdoc(signals_module._flatten),
            "normalize": inspect.getdoc(signals_module.normalize),
            "stripped": {
                "zero_width": _code_points(signals_module.ZERO_WIDTH),
                "joiners": _code_points(signals_module.JOINERS),
                "bidi": _code_points(signals_module.BIDI),
                "tag_block": [
                    f"U+{signals_module.TAG_BLOCK.start:04X}",
                    f"U+{signals_module.TAG_BLOCK.stop - 1:04X}",
                ],
            },
        },
        "caps": {
            "observations_per_message": inspection.MAX_OBSERVATIONS_PER_MESSAGE,
            "findings_per_message": inspection.MAX_FINDINGS_PER_MESSAGE,
            "scanned_strings": inspection.MAX_SCANNED_STRINGS,
            "scanned_chars": inspection.MAX_SCANNED_CHARS,
            "schema_depth": inspection.MAX_SCHEMA_DEPTH,
            "inspected_depth": inspection.MAX_INSPECTED_DEPTH,
            "path_length": inspection.MAX_PATH_LENGTH,
            "locator_length": inspection.MAX_LOCATOR_LENGTH,
            "normalized_growth": signals_module.NORMALIZED_GROWTH,
            "normalized_slack": signals_module.NORMALIZED_SLACK,
            "min_base64_chars": signals_module.MIN_BASE64_CHARS,
            "max_base64_blocks": signals_module.MAX_BASE64_BLOCKS,
            "max_base64_chars": signals_module.MAX_BASE64_CHARS,
            "pages_per_listing": MAX_PAGES,
        },
        "masking": {
            "placeholder": masking.PLACEHOLDER,
            "handle_prefix": masking.HANDLE_PREFIX,
            "handle_suffix": masking.HANDLE_SUFFIX,
            "handle_digest_length": masking.HANDLE_DIGEST_LENGTH,
            "protocol_handle_paths": sorted(masking.PROTOCOL_HANDLE_PATHS),
            "key_needles": sorted(masking.DEFAULT_KEY_NEEDLES),
            "blanked_headers": sorted(masking.BLANKED_HEADERS),
            "header_handles": sorted(masking.HEADER_HANDLES),
            "parsed_header": masking.PARSED_HEADER,
            "secret_query_names": sorted(masking.COMMON_SECRET_NAMES),
        },
    }
    return _envelope("signals", [], data)


# -- the store's engagement ---------------------------------------------------------------------


def store_engagement(sources: Sources) -> Envelope:
    """The engagement the store holds (:meth:`Store.engagement`): its id, the current version's
    digest, ``delete_after`` as declared and every version of the file, oldest first — or
    None for a store without one; and the bundles packed from it (:meth:`Store.bundles`)."""
    if sources.store is None:
        return _not_given("store_engagement", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("store_engagement", [refused.notice], None)
    notices: list[dict[str, Any]] = []
    with opened as store:
        try:
            held = store.engagement()
        except store_module.StoreError as refusal:
            held = None
            notices.append(
                _notice(
                    "refused",
                    "The store's engagement rows are not read, not even in part: they do not "
                    "fit together. No engagement is shown for this store.",
                    "engagement",
                    path=str(sources.store),
                    words=str(refusal),
                    source=None,
                )
            )
        bundles_filed = store.bundles()
    engagement = None
    if held is not None:
        engagement = {
            "engagement_id_declared": held["engagement_id_declared"],
            "engagement_digest": held["engagement_digest"],
            "delete_after_declared": held["delete_after_declared"],
            "versions": [
                {
                    "version": number,
                    "digest": entry["digest"],
                    "supersedes": entry["supersedes"],
                    "set_utc": entry["set_utc"],
                    "window_declared": entry["file_declared"].get("window"),
                    "removed": entry["removed"],
                    "file_declared": entry["file_declared"],
                }
                for number, entry in enumerate(held["chain"], start=1)
            ],
        }
    return _envelope(
        "store_engagement", notices, {"engagement": engagement, "bundles": bundles_filed}
    )


# -- triage -------------------------------------------------------------------------------------

#: The program a line to copy names.
COMMAND = "kymograph"

#: The placeholders of the line to copy: what the meeting decides, and who says it. In single
#: quotes, where nothing is live for a shell — no ``$``, no backtick, no backslash — so the
#: customer's words typed in their place cannot run anything; an apostrophe is written ``'\''``.
#: A line pasted unchanged is refused by the tool, never read as redirections.
STATUS_PLACEHOLDER = "'<STATUS>'"
AUTHOR_PLACEHOLDER = "'[NAME]'"

#: The role review mode writes the line for.
REVIEW_ROLE = "customer"

#: How many places of a finding's sightings review mode shows at most; the rest are counted.
MAX_REVIEW_PLACES = 200

QUESTION = "question"


def _statuses() -> dict[str, list[str]]:
    return {role: sorted(store_module.TRIAGE_STATUSES[role]) for role in store_module.TRIAGE_ROLES}


def _key_of(row: dict[str, Any]) -> dict[str, Any]:
    return {name: row[name] for name in (*store_module.KEY_FIELDS, "server_version_kind")}


def _identity(row: dict[str, Any]) -> dict[str, Any]:
    return {name: row[name] for name in store_module.IDENTITY_FIELDS}


def triage(sources: Sources) -> Envelope:
    """The store's findings, each with every role's current decision beside it
    (:meth:`Store.findings_with_triage`): publishable ones by provenance, real-world ones apart
    as candidates, and the open questions (status ``question``) apart again."""
    if sources.store is None:
        envelope = _not_given("triage", "--store")
        envelope["notices"].append(_candidates(None, "candidates"))
        return envelope
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("triage", [refused.notice, _candidates(None, "candidates")], None)
    notices: list[dict[str, Any]] = []
    listed: dict[str, list[dict[str, Any]]] = {}
    with opened as store:
        for provenance in corpus_module.PROVENANCES:
            listed[provenance] = store.findings_with_triage(provenance)
            where = "candidates" if provenance == "real-world" else f"findings:{provenance}"
            notices.extend(_not_results_of(store, provenance, where))
    notices.append(_candidates(len(listed["real-world"]), "candidates"))
    questions = {
        provenance: [
            {"finding": row["finding"], "role": role, "row": current, "key": _key_of(row)}
            for row in rows
            for role, current in row["triage"].items()
            if current is not None and current["status"] == QUESTION
        ]
        for provenance, rows in listed.items()
    }
    data = {
        "store": str(sources.store),
        "roles": list(store_module.TRIAGE_ROLES),
        "statuses": _statuses(),
        "findings": {provenance: listed[provenance] for provenance in PUBLISHABLE},
        "candidates": listed["real-world"],
        "questions": questions,
    }
    return _envelope("triage", notices, data)


def _finding_of(store: store_module.Store, finding: int) -> tuple[str, dict[str, Any]]:
    """A finding by the store's id, with its provenance, or a 404."""
    for provenance in corpus_module.PROVENANCES:
        for row in store.findings_with_triage(provenance):
            if row["finding"] == finding:
                return provenance, row
    raise ViewError(404, f"no finding {finding} in this store")


def triage_history(sources: Sources, finding: int) -> Envelope:
    """One finding's decisions, every row in the order it was made
    (:meth:`Store.triage_history` of its identity), with each role's current one."""
    finding = _int(finding, "finding")
    if sources.store is None:
        return _not_given("triage_history", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("triage_history", [refused.notice], None)
    with opened as store:
        provenance, row = _finding_of(store, finding)
        history = store.triage_history(_identity(row))
    notices = [_candidates(1)] if provenance == "real-world" else []
    data = {
        "finding": finding,
        "provenance": provenance,
        "key": _key_of(row),
        "identity": _identity(row),
        "triage": row["triage"],
        "history": history,
    }
    return _envelope("triage_history", notices, data)


#: How many values one sighting's path may resolve to before review mode stops looking: a key
#: holding a dot or a bracket can make a path name more than one place, and each is shown as a
#: candidate, never one of them picked.
MAX_PATH_CANDIDATES = 20


def _values_at(document: Any, path: Any) -> tuple[list[Any], bool]:
    """Every value a sighting's path can name in a message, as recorded, and whether the search
    stopped at :data:`MAX_PATH_CANDIDATES`.

    The inspector spells a path by joining keys with ``.`` and indices with ``[n]``, without
    escaping (``inspection``): a key that itself holds a dot or a bracket makes the spelling
    ambiguous — under ``result``, ``{"tools[0].description": …, "tools": [{"description": …}]}``
    holds two places ``result.tools[0].description`` names. So every way the path can be read
    is followed, whatever the order of the keys, and every value is returned."""
    found: list[Any] = []

    def walk(current: Any, rest: str) -> None:
        if len(found) >= MAX_PATH_CANDIDATES:
            return
        if not rest:
            found.append(current)
            return
        if rest.startswith("[") and isinstance(current, list):
            end = rest.find("]")
            number = rest[1:end] if end > 0 else ""
            if number.isdigit() and int(number) < len(current):
                walk(current[int(number)], rest[end + 1 :])
            return
        if rest.startswith(".") and isinstance(current, dict):
            tail = rest[1:]
            for key in current:
                if isinstance(key, str) and tail.startswith(key):
                    after = tail[len(key) :]
                    if after == "" or after[0] in ".[":
                        walk(current[key], after)

    if isinstance(path, str) and path:
        walk(document, f".{path}")
    return found, len(found) >= MAX_PATH_CANDIDATES


def _places(
    events: list[dict[str, Any]], seen: tuple[store_module.Sighting, ...]
) -> list[dict[str, Any]]:
    """Each place a run sighted the finding, with the text recorded there: the value the path
    names in the message of that seq, as the recording holds it (already masked)."""
    messages = {
        event.get("seq"): event
        for event in events
        if event.get("type") == "message" and isinstance(event.get("seq"), int)
    }
    places = []
    for sighting in seen:
        message_event = messages.get(sighting.message_seq) or {}
        payload = message_event.get("payload")
        document = payload.get("data") if isinstance(payload, dict) else None
        values, stopped = _values_at(document, sighting.path)
        status = {0: "not_located", 1: "recorded"}.get(len(values), "ambiguous")
        places.append(
            {
                **sighting.to_dict(),
                "text_status": status,
                "text": values[0] if status == "recorded" else None,
                # Every place the path can name, when it names more than one: none is picked.
                "candidates": values if status == "ambiguous" else None,
                "candidates_capped": stopped,
                "truncated": message_event.get("truncated") is True,
                "incomplete": message_event.get("incomplete") is True,
            }
        )
    return places


def _review_store(store: Path) -> str:
    """The store as the line names it: absolute — made so against the working directory, not
    resolved through links — so that the line pasted in any other directory names this store."""
    return str(store.absolute())


def _review_line(store: Path, finding: int) -> str:
    """The complete ``store triage set`` line review mode gives to copy: the store by its
    absolute path, shell-quoted and joined to its option with ``=`` so that a path beginning with
    ``-`` is still its value; the finding, the customer's role, and placeholders for the status
    and the name — nothing to be assembled by hand in the meeting."""
    return (
        f"{COMMAND} store triage set --store={shlex.quote(_review_store(store))}"
        f" --finding {finding}"
        f" --role {REVIEW_ROLE} --status {STATUS_PLACEHOLDER} --author {AUTHOR_PLACEHOLDER}"
    )


def _sighted(
    store: store_module.Store, identity: dict[str, Any]
) -> list[tuple[store_module.RunInfo, dict[str, Any], tuple[store_module.Sighting, ...]]]:
    """Every run of the store that sighted the identity, in the store's order, with the key it
    was filed under in that run and the places."""
    wanted = tuple(identity[name] for name in store_module.IDENTITY_FIELDS)
    sighted = []
    for info in store.runs():
        hit = store.findings_of(info.run).get(wanted)
        if hit is not None:
            sighted.append((info, hit[0], hit[1]))
    return sighted


def _class_of_key(row: dict[str, Any]) -> dict[str, str] | None:
    """The finding's class, derived from its signal here and never filed (finding_classes), or
    ``None`` for a signal this version does not know."""
    try:
        return finding_classes.class_of("signal", row["signal"]).to_dict()
    except (finding_classes.UnknownIdentError, KeyError):
        return None


def triage_review(sources: Sources, finding: int) -> Envelope:
    """Review mode: one finding and nothing else of the store — its key, the text recorded at
    each place a complete run sighted it (from the recording under ``--runs``), the runs that
    sighted it and are not results (named, never counted as sightings of a result), both roles'
    current decisions and every row, and the complete line to copy for the customer's."""
    finding = _int(finding, "finding")
    if sources.store is None:
        return _not_given("triage_review", "--store")
    try:
        opened = _open_store(sources.store)
    except _Refused as refused:
        return _envelope("triage_review", [refused.notice], None)
    with opened as store:
        provenance, row = _finding_of(store, finding)
        identity = _identity(row)
        history = store.triage_history(identity)
        filed = store.recordings()
        sighted = _sighted(store, identity)
    found = None if sources.runs is None else _found.search(sources.runs)
    looked_in = None if sources.runs is None else str(sources.runs)
    notices: list[dict[str, Any]] = []
    if found is not None and found.unreadable:
        # Counted, not named: the screen is shared, and a directory under --runs can name
        # another engagement.
        notices.append(
            _capped(
                "view",
                f"{len(found.unreadable)} director(y/ies) under --runs could not be read: a "
                "recording in them was not found.",
                what="runs",
                source="unreadable directories",
                cap=None,
                shown=None,
                total=None,
                unreadable=None,
                unreadable_count=len(found.unreadable),
            )
        )
    sightings: list[dict[str, Any]] = []
    short: list[dict[str, Any]] = []
    shown = total = 0
    for info, key, seen in sighted:
        if not info.complete:
            short.append(
                {
                    "run": info.run,
                    "state": info.state,
                    "exit_code": verdict.EXIT_CODES.get(info.state),
                    "causes": list(info.causes),
                    "places": len(seen),
                }
            )
            continue
        where = f"sighting:{info.run}"
        recording = filed.get(info.run)
        entry: dict[str, Any] = {
            "run": info.run,
            "state": info.state,
            "server_version": key["server_version"],
            "server_version_kind": info.server_version_kind,
            "tool_version": key["tool_version"],
            "isolation": info.isolation,
            "egress_observed": info.egress_observed,
            "recording": recording,
            "recording_status": "not_found",
            "ref": None,
            "places": [{**s.to_dict(), "text_status": "not_read", "text": None} for s in seen],
        }
        total += len(seen)
        resolved = (
            None
            if found is None or not isinstance(recording, str)
            else _found.resolve_filed(found, recording)
        )
        if resolved is None:
            notices.append(_recording_not_found(where, recording, looked_in))
        else:
            ref, path = resolved
            try:
                raw, unreadable = _found.read_bytes(path), None
            except OSError as exc:
                raw, unreadable = None, str(exc.strerror or exc)
            digest = None if raw is None else hashlib.sha256(raw).hexdigest()
            if raw is None or digest != info.run:
                entry["recording_status"] = "changed"
                notices.append(
                    _recording_changed(where, recording, ref, info.run, digest, unreadable)
                )
            else:
                events, _ = verdict.read_events(raw)
                entry.update(recording_status="found", ref=ref, places=_places(events, seen))
        entry["places"] = entry["places"][: max(MAX_REVIEW_PLACES - shown, 0)]
        shown += len(entry["places"])
        sightings.append(entry)
    if total > shown:
        notices.append(
            _capped(
                "sightings",
                f"{shown} of {total} places this finding was sighted at in complete runs are "
                "shown, capped; the rest are in the store's sightings and the recordings.",
                what="sightings",
                source="review mode",
                cap=MAX_REVIEW_PLACES,
                shown=shown,
                total=total,
            )
        )
    if short:
        notices.append(
            _notice(
                "not_a_result",
                f"{len(short)} of {len(sighted)} runs that sighted this finding are not a "
                "result: they are named here and not counted as sightings of a result.",
                "not_results",
                state=None,
                exit_code=None,
                rules=None,
                causes=_filed_causes(sorted({c for run in short for c in run["causes"]})),
                runs=[{"run": r["run"], "state": r["state"], "causes": r["causes"]} for r in short],
                count=len(short),
                total=len(sighted),
            )
        )
    if provenance == "real-world":
        notices.append(_candidates(1))
    data = {
        "finding": finding,
        "provenance": provenance,
        "key": _key_of(row),
        "identity": identity,
        "finding_class": _class_of_key(row),
        "triage": row["triage"],
        "history": history,
        "sightings": sightings,
        "not_results": short,
        "line": {
            "text": _review_line(sources.store, finding),
            "store": _review_store(sources.store),
            "role": REVIEW_ROLE,
            "statuses": sorted(store_module.TRIAGE_STATUSES[REVIEW_ROLE]),
            "placeholders": [STATUS_PLACEHOLDER, AUTHOR_PLACEHOLDER],
        },
    }
    return _envelope("triage_review", notices, data)


# -- bundles and attestations -------------------------------------------------------------------


@dataclass(frozen=True)
class Download:
    """A file served as an attachment: its name (the last part of its path) and its bytes, read
    once, checked, and served as they were checked."""

    name: str
    body: bytes


#: An attestation is one page; a file larger than this is not one.
MAX_ATTESTATION_BYTES = 1024 * 1024

#: The largest file of a bundle served for download. A download is read whole into memory,
#: hashed and served as read, after the whole bundle is verified again for that request; a file
#: larger than this is not served (409) — copy it from the bundle and verify it there.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024


def _read_inside(root: Path, relative: str, limit: int) -> bytes:
    """A file of a bundle by its path relative to the bundle, opened one directory at a time
    without following a link, and only if it is a regular file; at most ``limit + 1`` bytes,
    so that a file larger than listed is told apart. :class:`OSError` otherwise."""
    parts = relative.split("/")
    if not relative or relative.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise OSError(f"{relative!r} is not a path inside the bundle")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptors = [os.open(root, directory_flags)]
    try:
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags | nofollow, dir_fd=descriptors[-1]))
        flags = os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(parts[-1], flags, dir_fd=descriptors[-1])
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError(f"{relative}: not a regular file")
            return handle.read(limit + 1)
    finally:
        for opened in descriptors:
            os.close(opened)


def bundles(sources: Sources) -> Envelope:
    """The bundles given, each checked against its own index (:func:`evidence.verify`)."""
    if not sources.bundles:
        return _not_given("bundles", "--bundle")
    listed = []
    for index, path in enumerate(sources.bundles):
        row: dict[str, Any] = {"index": index, "path": str(path)}
        try:
            verified = evidence_module.verify(path)
        except evidence_module.EvidenceError as refusal:
            row.update(bundle="refused", words=str(refusal), index_digest=None, engagement=None,
                       created_utc=None)  # fmt: skip
        else:
            row.update(
                bundle=verified.state,
                words=None if verified.intact else verified.summary(),
                index_digest=verified.index_digest,
                engagement={
                    "engagement_id_declared": verified.index.engagement_id_declared,
                    "engagement_digest": verified.index.engagement_digest,
                },
                created_utc=verified.index.created_utc,
            )
        listed.append(row)
    return _envelope("bundles", [], listed)


def _customer_readme(root: Path, verified: evidence_module.Verified) -> dict[str, Any]:
    """The ``CUSTOMER-README.md`` beside a bundle's index, if there is one: what
    :func:`evidence.verify` says of it, and its names and numbers as
    :func:`handover.parse_customer_readme` reads them back."""
    readme = root / handover_module.CUSTOMER_README
    if not os.path.lexists(readme):
        return {"present": False, "check": None, "problem": None, "fields": None}
    problem = next(
        (p for p in verified.problems if p.startswith(handover_module.CUSTOMER_README)), None
    )
    try:
        raw = _found.read_bytes(readme, evidence_module.MAX_INDEX_BYTES)
        fields = handover_module.parse_customer_readme(raw.decode("utf-8")).to_dict()
    except (OSError, UnicodeDecodeError, ValueError):
        fields = None
    return {"present": True, "check": verified.readme, "problem": problem, "fields": fields}


def bundle(sources: Sources, index: int) -> Envelope:
    """One bundle as :func:`evidence.verify` finds it: intact or not, each file with its state,
    the index's files by role, and the customer README beside it with its check. Its files can
    be downloaded only while the whole bundle is intact."""
    if not sources.bundles:
        return _not_given("bundle", "--bundle")
    root = _given(sources.bundles, index)
    try:
        verified = evidence_module.verify(root)
    except evidence_module.EvidenceError as refusal:
        notice = _notice(
            "refused",
            "The bundle was refused whole: its index cannot be read, and nothing of the bundle "
            "is shown or served.",
            path=str(root),
            words=str(refusal),
            source=None,
        )
        return _envelope("bundle", [notice], None)
    states = {item.path: item for item in verified.files}
    by_role: dict[str, list[dict[str, Any]]] = {}
    for entry in verified.index.files:
        state = states[entry.path]
        by_role.setdefault(entry.role, []).append(
            {
                **entry.to_dict(),
                "state": state.state,
                "note": state.note,
                "download": verified.intact
                and state.state == evidence_module.INTACT
                and entry.size <= MAX_DOWNLOAD_BYTES,
            }
        )
    notices = []
    if not verified.intact:
        notices.append(
            _notice(
                "bundle_not_intact",
                "The bundle is not intact: not every file is the one its index lists, or the "
                "tree holds what the index does not. No file of it is served for download.",
                directory=str(root),
                summary=verified.summary(),
                files=[
                    item.to_dict()
                    for item in (*verified.files, *verified.unlisted)
                    if item.state != evidence_module.INTACT
                ],
                problems=list(verified.problems),
            )
        )
    data = {
        **verified.to_dict(),
        "index": index,
        "path": str(root),
        "triage": None if verified.index.triage is None else dict(verified.index.triage),
        "roles": list(evidence_module.ROLES),
        "files_by_role": by_role,
        "downloadable": verified.intact,
        "customer_readme": _customer_readme(root, verified),
    }
    return _envelope("bundle", notices, data)


def bundle_file(sources: Sources, index: int, path: str) -> Download:
    """One file of a bundle, for download: only a file its index lists, only while the whole
    bundle is intact, and only with the bytes read now matching the index's SHA-256 and size —
    the bytes served are the ones checked. Nothing outside the bundle, no link followed."""
    if not sources.bundles:
        raise ViewError(404, "no --bundle was given; nothing is served")
    root = _given(sources.bundles, index)
    unread = "the bundle's index cannot be read; nothing of it is served"
    try:
        listed = evidence_module.read_index(root / evidence_module.INDEX_FILE)
    except evidence_module.EvidenceError:
        raise ViewError(409, unread) from None
    entry = next((item for item in listed.files if item.path == path), None)
    if entry is None:
        raise ViewError(
            404,
            "no file of that path is listed in the bundle's index; only listed files are served",
        )
    try:
        verified = evidence_module.verify(root, index_digest=listed.digest)
    except evidence_module.EvidenceError:
        raise ViewError(409, unread) from None
    if not verified.intact:
        raise ViewError(409, "the bundle is not intact; no file of it is served")
    if entry.size > MAX_DOWNLOAD_BYTES:
        raise ViewError(
            409,
            f"the file is larger than {MAX_DOWNLOAD_BYTES} bytes, the most this interface serves; "
            "copy it from the bundle and verify it there",
        )
    try:
        raw = _read_inside(root, entry.path, entry.size)
    except OSError:
        raise ViewError(409, "the file cannot be read as the one listed; not served") from None
    if len(raw) != entry.size or hashlib.sha256(raw).hexdigest() != entry.sha256:
        raise ViewError(
            409, "the file changed: its bytes are not the ones the index lists; not served"
        )
    return Download(name=entry.path.rsplit("/", 1)[-1], body=raw)


def _attestation_of(path: Path) -> tuple[bytes | None, Any, str | None]:
    """An attestation's bytes and what :func:`report.parse_attestation` reads of them, or the
    words it was refused with. Opened without following a link, a regular file only."""
    try:
        raw = _found.read_bytes(path, MAX_ATTESTATION_BYTES)
    except OSError as exc:
        return None, None, f"{path}: cannot be read: {exc.strerror or exc}"
    if len(raw) > MAX_ATTESTATION_BYTES:
        return raw, None, f"{path}: larger than {MAX_ATTESTATION_BYTES} bytes; not an attestation"
    try:
        return raw, report_module.parse_attestation(raw.decode("utf-8")), None
    except UnicodeDecodeError:
        return raw, None, f"{path}: not UTF-8 text"
    except report_module.ReportParseError as refusal:
        return raw, None, f"{path}: {refusal}"


def attestations(sources: Sources) -> Envelope:
    """The attestations given, each with whether it reads back."""
    if not sources.attestations:
        return _not_given("attestations", "--attestation")
    listed = []
    for index, path in enumerate(sources.attestations):
        _, parsed, words = _attestation_of(path)
        listed.append(
            {
                "index": index,
                "path": str(path),
                "ok": parsed is not None,
                "engagement_id": None if parsed is None else parsed.engagement_id,
                "words": words,
            }
        )
    return _envelope("attestations", [], listed)


def attestation(sources: Sources, index: int) -> Envelope:
    """One attestation as :func:`report.parse_attestation` reads it back: its engagement and
    every item with its kind. One that does not read back is refused — shown only as its text
    beside the words — and not served."""
    if not sources.attestations:
        return _not_given("attestation", "--attestation")
    path = _given(sources.attestations, index)
    raw, parsed, words = _attestation_of(path)
    if raw is None or parsed is None:
        try:
            source = None if raw is None or len(raw) > MAX_ATTESTATION_BYTES else raw.decode()
        except UnicodeDecodeError:
            source = None
        notice = _notice(
            "refused",
            "The attestation does not read back as one: it is refused whole, shown only as its "
            "text beside the words, and not served for download.",
            path=str(path),
            words=words,
            source=source,
        )
        return _envelope("attestation", [notice], None)
    data = {
        "index": index,
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "engagement_id": parsed.engagement_id,
        "items": [
            {"kind": item.kind, "text": item.text}
            if isinstance(item, report_module.Sentence)
            else {"kind": "heading", "text": item.text}
            for item in parsed.items
        ],
        "downloadable": True,
    }
    return _envelope("attestation", [], data)


def attestation_file(sources: Sources, index: int) -> Download:
    """An attestation for download: read now, served only if it reads back, as the bytes read."""
    if not sources.attestations:
        raise ViewError(404, "no --attestation was given; nothing is served")
    path = _given(sources.attestations, index)
    raw, parsed, _ = _attestation_of(path)
    if raw is None or parsed is None:
        raise ViewError(409, "the attestation does not read back as one; not served")
    return Download(name=path.name, body=raw)
