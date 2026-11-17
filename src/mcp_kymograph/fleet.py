"""The batch over the corpus: every entry and scenario run once, filed, and the whole compared.

**The fleet orchestrates and files; it decides nothing.** What a finding is, the inspector
settled during each run. Whether a run is a result, :mod:`mcp_kymograph.verdict` settles from its
recording, as the store files it. The fleet starts the runs, files them, and keeps one result
per entry and scenario — the state the store gave the recording, never the run's own word.

**Each run is a process of its own, bound to its provenance.** It is ``kymograph drive`` for
one entry and one scenario, under ``runc`` — the floor for the project's own entries. A
``real-world`` entry is refused before anything starts (it runs only under ``runsc``, which
this version does not provide), and that refusal is its recorded result: not run, not run under
something weaker, and not left out.

**An endpoint entry is never part of a fleet** (docs/design/http-transport.md 4.5): a server
someone else runs is driven through ``drive`` alone, one run at a time, under the operator's
eye. A manifest that holds one refuses the whole fleet before anything starts — not one refused
result among the others, which would run everything else against a manifest that was never
meant for a batch.

**A failed entry is a result, not the end of the batch.** A sandbox that did not hold, a server
that never answered, a run that lacks data: each is filed with its state and the batch goes
on. Nothing is a silent no-op; nothing about one entry stops the others.

**The exit code is a claim, the recording is the evidence.** Every run's exit code is held
against the state its recording is filed in; when they disagree, the fleet records it as a
problem of its own and goes by the recording.

**One environment for every entry.** The sandbox's image and the target image are resolved to
their ids once, before the first run, and every run is handed those ids. Afterwards, the
fleet checks from the store — from what each recording names — that every run observed under
exactly them.

**The order is not part of the result.** Runs finish in whatever order they finish; results
are kept by entry and scenario, and the fleet's digest is taken over them sorted, so two
fleets over the same corpus that ran in different orders have the same digest. The order they
finished in is recorded, as a fact about this fleet, never as a key.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_kymograph import verdict
from mcp_kymograph.corpus import Manifest, tool_identity
from mcp_kymograph.corpus import load as load_manifest
from mcp_kymograph.driver import MIN_STEP_TIMEOUT
from mcp_kymograph.engagement import (
    Engagement,
    EngagementRefused,
    GateFacts,
    declaration_fields,
    stopped,
)
from mcp_kymograph.engagement import check as check_engagement
from mcp_kymograph.events import STOPPED_BY_STOP_FILE
from mcp_kymograph.output import (
    Severity,
    inspect_destination,
    make_private_directories,
    unusable,
)
from mcp_kymograph.proxy import CLIENT_SETTLE_SECONDS
from mcp_kymograph.sandbox import docker
from mcp_kymograph.sandbox.runner import SANDBOX_IMAGE, TARGET_IMAGE, clean_up_after
from mcp_kymograph.store import Store, StoreError, canonical_key

#: The isolation every entry of a fleet runs under. The floor for reference and poison; a
#: real-world entry needs more than that and is refused.
ISOLATION = "runc"

#: Not run, by policy: the entry's provenance does not permit the fleet's isolation, or it
#: cannot be delivered. Its reason is the result.
REFUSED = "refused"
#: No run filed: no recording, the store refused it, or the fleet was interrupted before the
#: run ended (stopped, or never started; cause ``interrupted``).
UNFILED = "unfiled"

#: Every state a fleet result can have: a run's, or one of the two above.
STATES = (*verdict.STATES, REFUSED, UNFILED)

#: A fixed limit on runs at a time, whatever is asked for.
MAX_PARALLEL = 16
DEFAULT_PARALLEL = 2
#: How long one run may take, start to filed, before it is stopped.
DEFAULT_JOB_TIMEOUT = 600.0
#: Between asking a run to stop and making it.
STOP_GRACE = 15.0
#: The same, when the whole fleet is interrupted: long enough for a run to stop its server,
#: remove its containers and write its ending; a second interruption cuts it short. What a run
#: that had to be killed left behind is removed by its nonce (:func:`clean_up_after`).
INTERRUPT_GRACE = 10.0
#: The signals that interrupt a fleet: Ctrl-C at the terminal, and a polite stop from outside.
INTERRUPTS = (signal.SIGINT, signal.SIGTERM)
#: How often the fleet looks for an interruption while it waits for its runs.
POLL_SECONDS = 0.2

#: How an interruption reached a run: it was running and was stopped, or it never started.
STOPPED = "stopped"
NOT_STARTED = "not_started"

#: The command one run is: this interpreter, this package, drive.
DRIVE = (sys.executable, "-m", "mcp_kymograph.cli", "drive")


class FleetError(ValueError):
    """A fleet that cannot start: nothing was run, nothing filed.

    ``condition`` is the engagement gate's condition (mcp_kymograph.engagement.CONDITIONS) when
    the engagement file refused a job, so the refusal can be recorded under it; None otherwise.
    """

    def __init__(self, message: str, *, condition: str | None = None) -> None:
        super().__init__(message)
        self.condition = condition


@dataclass(frozen=True, slots=True)
class Job:
    """One entry and one of its scenarios: what one run is."""

    index: int
    entry: str
    scenario: str
    provenance: str
    #: Why it may not run, or None.
    refusal: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.entry, self.scenario)


@dataclass(frozen=True, slots=True)
class Pins:
    """The environment of every run in the fleet: the isolation, the images by id."""

    isolation: str
    sandbox_image: str
    target_image: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "isolation": self.isolation,
            "sandbox_image": self.sandbox_image,
            "target_image": self.target_image,
        }


@dataclass(frozen=True, slots=True)
class Launched:
    """What a run's process left: its exit code (None if it had to be stopped), its
    recording if one was made, and the last of what it said."""

    exit_code: int | None
    recording: Path | None
    stderr: str = ""
    problems: tuple[str, ...] = ()
    #: :data:`STOPPED` or :data:`NOT_STARTED` when the fleet's interruption reached the run.
    interrupted: str | None = None


@dataclass
class Result:
    entry: str
    scenario: str
    provenance: str
    state: str
    exit_code: int | None = None
    run: str | None = None
    problems: list[str] = field(default_factory=list)
    #: The kinds of shortfall of the filed run (mcp_kymograph.verdict.CAUSES), each once, sorted:
    #: what tells one incomplete run from another without reading its reasons — or, for a run
    #: the fleet's interruption cut short or never started, ``interrupted``.
    causes: tuple[str, ...] = ()
    #: Every finding the run filed, by its canonical key, sorted.
    findings: tuple[str, ...] = ()
    #: The run's context as filed: what the digest carries besides the findings.
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return (self.entry, self.scenario)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "scenario": self.scenario,
            "provenance": self.provenance,
            "state": self.state,
            "exit_code": self.exit_code,
            "run": self.run,
            "findings": len(self.findings),
            "causes": list(self.causes),
            "problems": list(self.problems),
        }


@dataclass
class FleetRun:
    fleet: str
    started_utc: str
    finished_utc: str
    manifest: dict[str, str]
    tool: dict[str, str]
    pins: Pins
    parallel: int
    #: The order runs finished in. A fact about this fleet, never part of its result.
    processed: list[tuple[str, str]]
    results: dict[tuple[str, str], Result]
    problems: list[str] = field(default_factory=list)
    #: The signal that interrupted the fleet before every run had ended, or None.
    interrupted: str | None = None
    #: The version of the rules its runs were judged by (mcp_kymograph.verdict.RULES_VERSION).
    rules: int = verdict.RULES_VERSION
    #: The engagement file the fleet was gated against, exactly as a recording carries it
    #: (``engagement_id_declared``, ``engagement_digest``, ``window_declared``), or None. Which
    #: file it was, for a reader of ``fleet.json``; never part of the digest, a comparison or the
    #: store's ``fleets`` row.
    engagement: dict[str, Any] | None = None

    @property
    def complete(self) -> bool:
        """Every entry a result, and nothing wrong with the fleet itself."""
        return not self.problems and all(r.state == verdict.COMPLETE for r in self.results.values())

    @property
    def state(self) -> str:
        """The gravest state of any result; a refusal or an unfiled run is data missing."""
        states = [
            verdict.INCOMPLETE if r.state in (REFUSED, UNFILED) else r.state
            for r in self.results.values()
        ]
        return verdict.gravest(states + [verdict.INCOMPLETE] * bool(self.problems))

    def canonical(self) -> dict[str, Any]:
        """What the fleet found, and nothing about when, how fast or in which order.

        With each result's causes: two fleets whose run is incomplete for different reasons —
        the sink missed datagrams in one, a listing went unanswered in the other — did not come
        out the same. This is the full digest of docs/design/repeated-runs.md; the
        comparison digest proposed there leaves the causes out. And with the version of the rules
        the states were judged by: the same states under other rules are not the same result."""
        return {
            "rules": self.rules,
            "manifest": self.manifest["digest"],
            "tool": dict(self.tool),
            "environment": self.pins.to_dict(),
            "results": [
                {
                    "entry": r.entry,
                    "scenario": r.scenario,
                    "provenance": r.provenance,
                    "state": r.state,
                    "causes": list(r.causes),
                    "context": dict(r.context),
                    "findings": list(r.findings),
                }
                for r in (self.results[key] for key in sorted(self.results))
            ],
        }

    @property
    def digest(self) -> str:
        text = json.dumps(self.canonical(), sort_keys=True, ensure_ascii=True)
        return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """The fleet's output. Findings appear only for provenances whose findings may be
        published; a real-world entry's are counted here and queried apart."""
        publishable: dict[str, list[dict[str, Any]]] = {"reference": [], "poison": []}
        candidates = 0
        for result in (self.results[key] for key in sorted(self.results)):
            if result.provenance in publishable:
                publishable[result.provenance].extend(
                    {"entry": result.entry, "scenario": result.scenario, "key": json.loads(k)}
                    for k in result.findings
                )
            else:
                candidates += len(result.findings)
        return {
            "fleet": self.fleet,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc,
            "digest": self.digest,
            "rules": self.rules,
            "state": self.state,
            "complete": self.complete,
            "manifest": dict(self.manifest),
            "tool": dict(self.tool),
            "environment": self.pins.to_dict(),
            "parallel": self.parallel,
            "processed": [list(key) for key in self.processed],
            "interrupted": self.interrupted,
            "engagement": None if self.engagement is None else dict(self.engagement),
            "problems": list(self.problems),
            "results": [self.results[key].to_dict() for key in sorted(self.results)],
            "findings": publishable,
            "disclosure_candidates": {
                "real-world": candidates,
                "note": "candidates for responsible disclosure, never part of a publishable "
                "report; query them with: store findings --provenance real-world",
            },
        }


# -- planning ---------------------------------------------------------------------------------


def plan(manifest: Manifest) -> list[Job]:
    """Every entry and scenario of the manifest, in manifest order, each with its refusal."""
    jobs: list[Job] = []
    for entry in manifest.entries:
        refusal = entry.refusal_to_run(ISOLATION)
        for ref in entry.scenarios:
            jobs.append(Job(len(jobs), entry.name, ref.name, entry.provenance, refusal))
    return jobs


def pin(sandbox_image: str = SANDBOX_IMAGE, target_image: str = TARGET_IMAGE) -> Pins:
    """Both images by id, once, for every run of the fleet."""
    try:
        return Pins(ISOLATION, docker.image_id(sandbox_image), docker.image_id(target_image))
    except docker.DockerError as exc:
        raise FleetError(f"the fleet's images cannot be pinned: {exc}") from None


# -- one run ----------------------------------------------------------------------------------


class Processes:
    """The runs' processes the fleet has started and not yet seen end — and, once the fleet is
    interrupted, the one place that stops them all and starts no more.

    Each run is a process group and a session of its own, so neither a Ctrl-C at the terminal
    nor the end of the fleet reaches it by itself: left alone it would run to its end with
    nobody to file it. :meth:`stop` asks every group to stop, and makes it after a grace.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running: dict[int, subprocess.Popen[bytes]] = {}
        self._stopped: set[int] = set()
        self._closed = False
        #: Set by a second interruption, from a signal handler: a plain flag, no lock.
        self.kill_now = False

    def start(self, argv: Sequence[str], **options: Any) -> subprocess.Popen[bytes] | None:
        """The run's process, in a session of its own — or None once the fleet is stopping."""
        with self._lock:
            if self._closed:
                return None
            process = subprocess.Popen(argv, start_new_session=True, **options)  # noqa: S603
            self._running[process.pid] = process
            return process

    def ended(self, process: subprocess.Popen[bytes]) -> bool:
        """Forget a process that has ended; whether the fleet stopped it."""
        with self._lock:
            self._running.pop(process.pid, None)
            return process.pid in self._stopped

    def stop(self, grace: float) -> int:
        """Start no more runs, and stop every one still running: SIGTERM to its process group —
        the run then stops its server, removes its containers and writes its ending — and
        SIGKILL to every group still there after ``grace``, or at a second interruption.
        Returns how many runs it stopped."""
        with self._lock:
            self._closed = True
            targets = dict(self._running)
            self._stopped.update(targets)
        for process in targets.values():
            _signal_group(process, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while self._alive(targets) and time.monotonic() < deadline and not self.kill_now:
            time.sleep(POLL_SECONDS / 2)
        for pid in self._alive(targets):
            _signal_group(targets[pid], signal.SIGKILL)
        return len(targets)

    def _alive(self, targets: dict[int, subprocess.Popen[bytes]]) -> list[int]:
        with self._lock:
            return [pid for pid in targets if pid in self._running]


def _signal_group(process: subprocess.Popen[bytes], number: int) -> None:
    # Only while the process has not been reaped: until then its pid, and the group it leads,
    # are still its own.
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, number)


def launch(
    job: Job,
    pins: Pins,
    manifest_path: Path,
    out_dir: Path,
    *,
    step_timeout: float,
    job_timeout: float,
    client_settle_timeout: float = CLIENT_SETTLE_SECONDS,
    processes: Processes | None = None,
    engagement_path: Path | None = None,
) -> Launched:
    """One run: ``kymograph drive`` for this entry and scenario, in a process of its own.

    The run is handed a nonce of the fleet's making, which names its containers and its staging
    directory. A run that had to be stopped — by its timeout, or by the fleet's interruption —
    is looked after by it: whatever it left is removed (:func:`clean_up_after`), and said.

    Under an engagement the run is handed the file by its absolute path, so that it gates itself
    at its own start — a run that would start after the window has closed is refused by itself,
    and filed as refused — and masks what the file says to mask.
    """
    processes = processes or Processes()
    nonce = secrets.token_hex(6)
    argv = [
        *DRIVE, "-q",
        "--out-dir", str(out_dir),
        "--manifest", str(manifest_path),
        "--entry", job.entry,
        "--scenario", job.scenario,
        "--isolation", pins.isolation,
        "--sandbox-image", pins.sandbox_image,
        "--target-image", pins.target_image,
        "--sandbox-nonce", nonce,
        "--step-timeout", str(step_timeout),
        "--client-settle-timeout", str(client_settle_timeout),
    ]  # fmt: skip
    if engagement_path is not None:
        argv += ["--engagement", str(Path(engagement_path).absolute())]
    process = processes.start(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    if process is None:
        return Launched(None, None, interrupted=NOT_STARTED)
    problems = []
    timed_out = False
    try:
        _, stderr = process.communicate(timeout=job_timeout)
    except subprocess.TimeoutExpired:
        # Asked first: the run stops its server, removes its containers and writes its
        # ending. Made to stop only when it will not.
        timed_out = True
        _signal_group(process, signal.SIGTERM)
        try:
            _, stderr = process.communicate(timeout=STOP_GRACE)
        except subprocess.TimeoutExpired:
            _signal_group(process, signal.SIGKILL)
            _, stderr = process.communicate()
        problems.append(f"the run did not finish within {job_timeout:g} s and was stopped")
    stopped = processes.ended(process)
    if stopped or timed_out:
        problems.extend(clean_up_after(nonce))
    recordings = sorted(out_dir.glob("*/events.jsonl"))
    if len(recordings) > 1:
        problems.append(f"{len(recordings)} recordings where one run makes one")
    return Launched(
        exit_code=process.returncode,
        recording=recordings[0] if len(recordings) == 1 else None,
        stderr=stderr.decode("utf-8", "replace")[-1000:],
        problems=tuple(problems),
        interrupted=STOPPED if stopped else None,
    )


Launcher = Callable[..., Launched]


# -- the fleet --------------------------------------------------------------------------------


def run(
    manifest_path: Path,
    store: Store,
    out_dir: Path,
    *,
    pins: Pins | None = None,
    parallel: int = DEFAULT_PARALLEL,
    order: Sequence[tuple[str, str]] | None = None,
    step_timeout: float = 30.0,
    job_timeout: float = DEFAULT_JOB_TIMEOUT,
    client_settle_timeout: float = CLIENT_SETTLE_SECONDS,
    launcher: Launcher = launch,
    engagement: Engagement | None = None,
    now: datetime | None = None,
) -> FleetRun:
    """Run the corpus, file every run, file the fleet. Raises :class:`FleetError` only when
    nothing could be started at all.

    Under an ``engagement``, before anything is launched or written: every job the fleet would
    run is held to the file (:func:`mcp_kymograph.engagement.check`, at ``now``), and one it does
    not cover refuses the fleet whole, with the gate's condition on the :class:`FleetError`; the
    store is then made the engagement's (:meth:`Store.set_engagement`), and a store holding
    another refuses the fleet the same way. A job the fleet refuses anyway — a real-world entry
    — stays a refused result and is not held to the file. Each run is handed the file and gates
    itself again at its own start; each filed run must name the file's digest.
    """
    if not 1 <= parallel <= MAX_PARALLEL:
        raise FleetError(f"parallel must be between 1 and {MAX_PARALLEL}, not {parallel}")
    if not step_timeout >= MIN_STEP_TIMEOUT:
        # Once, for the fleet: every run would otherwise refuse it on its own.
        raise FleetError(
            f"a step must be given at least {MIN_STEP_TIMEOUT:g} s, not {step_timeout}"
        )
    if engagement is None:
        _no_engagement_held(store)
    try:
        manifest = load_manifest(manifest_path)
    except ValueError as exc:
        raise FleetError(str(exc)) from None
    _no_endpoint_entries(manifest)
    jobs = plan(manifest)
    if not jobs:
        # A fleet over nothing would be complete with nothing in it: refused, not reported.
        raise FleetError(f"{manifest.source}: no entries, so nothing to run and no result")
    if order is not None:
        jobs = _ordered(jobs, order)
    pins = pins or pin()
    if pins.isolation != ISOLATION:
        # The floor is not a parameter: whatever is handed in, the fleet runs under runc.
        raise FleetError(f"a fleet runs under {ISOLATION}, not {pins.isolation}")
    if engagement is not None:
        _gate(engagement, manifest, jobs, pins.isolation, _now() if now is None else now)
    started = _now()
    fleet = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    directory = Path(out_dir) / fleet
    # The destination is checked once, for the fleet, before any run exists — the check every
    # run makes for itself would otherwise refuse each of them, one by one, as its result.
    try:
        advisories = inspect_destination(Path(out_dir), directory)
    except (OSError, RuntimeError) as exc:
        raise FleetError(f"{out_dir}: {unusable(exc).message}") from None
    for advisory in advisories:
        if advisory.severity is Severity.REFUSAL:
            raise FleetError(f"{advisory.message} Nothing was started.")
    if engagement is not None:
        _set_engagement(store, engagement, now)
    try:
        make_private_directories(directory)
    except OSError as exc:
        # A file where the directory should be, a place that cannot be created: the input was
        # wrong, and no run has been started yet.
        raise FleetError(f"{out_dir}: {unusable(exc).message}") from None

    results: dict[tuple[str, str], Result] = {}
    processed: list[tuple[str, str]] = []
    problems: list[str] = []
    for job in jobs:
        if job.refusal is not None:
            results[job.key] = Result(
                job.entry, job.scenario, job.provenance, REFUSED, problems=[job.refusal]
            )
            processed.append(job.key)
    runnable = [job for job in jobs if job.refusal is None]
    # Only under a file: a launcher written before engagements existed takes no such option.
    handed = {} if engagement is None else {"engagement_path": Path(engagement.source)}
    processes = Processes()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=parallel)
    # From the first run to the fleet's own record, an interruption is a fact to act on, not an
    # exception raised wherever the main thread happens to be — in the middle of filing a run.
    with _interruptible(processes) as interruption:
        futures = {
            pool.submit(
                launcher,
                job,
                pins,
                Path(manifest_path),
                directory / f"{job.index:03d}-{job.entry}",
                step_timeout=step_timeout,
                job_timeout=job_timeout,
                client_settle_timeout=client_settle_timeout,
                processes=processes,
                **handed,
            ): job
            for job in runnable
        }
        pending = set(futures)
        while pending and interruption.reason is None:
            if stopped(engagement):
                # The kill switch (engagement stop): no run is started from here on, and those
                # going are stopped, as at an interruption; the reason is the stop file's.
                interruption.reason = STOPPED_BY_STOP_FILE
                break
            done, pending = concurrent.futures.wait(
                pending, timeout=POLL_SECONDS, return_when=concurrent.futures.FIRST_COMPLETED
            )
            # Filed here, one at a time, in whatever order they finish.
            for future in sorted(done, key=lambda f: futures[f].index):
                job = futures[future]
                results[job.key] = _file(store, job, _launched(future), problems)
                processed.append(job.key)
        if pending:
            processes.stop(INTERRUPT_GRACE)
            pool.shutdown(wait=True, cancel_futures=True)
            cut = {STOPPED: 0, NOT_STARTED: 0}
            for future in sorted(pending, key=lambda f: futures[f].index):
                job = futures[future]
                launched = (
                    Launched(None, None, interrupted=NOT_STARTED)
                    if future.cancelled()
                    else _launched(future)
                )
                if launched.interrupted is None:
                    # It ended on its own before the stop reached it: a run like any other.
                    results[job.key] = _file(store, job, launched, problems)
                else:
                    results[job.key] = _cut_short(job, launched, interruption.reason)
                    cut[launched.interrupted] += 1
                processed.append(job.key)
            problems.append(
                f"interrupted by {interruption.reason}: {cut[STOPPED]} run(s) stopped and "
                f"{cut[NOT_STARTED]} never started; none of them is filed, and the fleet is "
                "incomplete"
            )
        pool.shutdown(wait=True)

        _check_environment(store, results, pins, problems)
        if engagement is not None:
            _check_engagement(store, results, engagement, problems)
        record = FleetRun(
            fleet=fleet,
            started_utc=_utc(started),
            finished_utc=_utc(_now()),
            manifest={"source": manifest.source, "digest": manifest.digest},
            tool=tool_identity(),
            pins=pins,
            parallel=parallel,
            processed=processed,
            results=results,
            problems=problems,
            interrupted=interruption.reason if pending else None,
            rules=verdict.RULES_VERSION,
            engagement=None if engagement is None else declaration_fields(engagement),
        )
        store.file_fleet(_fleet_row(record), [r.to_dict() for r in results.values()])
        with contextlib.suppress(OSError):
            (directory / "fleet.json").write_text(json.dumps(record.to_dict(), indent=2) + "\n")
    return record


@dataclass
class _Interruption:
    #: The name of the signal that interrupted the fleet, or None.
    reason: str | None = None


@contextlib.contextmanager
def _interruptible(processes: Processes) -> Iterator[_Interruption]:
    """While the fleet runs: the first SIGINT or SIGTERM marks it interrupted, a second makes
    the stop immediate. The handler only sets flags — no lock, nothing raised — and the fleet
    acts on them where it looks. Only the main thread can take signals; elsewhere nothing is
    installed, and the previous handlers are back when the fleet is done."""
    interruption = _Interruption()
    if threading.current_thread() is not threading.main_thread():
        yield interruption
        return

    def handler(number: int, _frame: Any) -> None:
        if interruption.reason is None:
            interruption.reason = signal.Signals(number).name
        else:
            processes.kill_now = True

    previous = {number: signal.signal(number, handler) for number in INTERRUPTS}
    try:
        yield interruption
    finally:
        for number, before in previous.items():
            signal.signal(number, signal.SIG_DFL if before is None else before)


def _launched(future: concurrent.futures.Future[Launched]) -> Launched:
    try:
        return future.result()
    except Exception as exc:  # noqa: BLE001 - one run's failure is that run's result
        return Launched(None, None, problems=(f"{type(exc).__name__}: {exc}",))


def _cut_short(job: Job, launched: Launched, reason: str | None) -> Result:
    """A run the interruption stopped or never started. Not filed: what it recorded ends where
    the stop reached it, not where the run would have — its recording is named, not judged."""
    what = "stopped" if launched.interrupted == STOPPED else "not started"
    problems = [f"{what}: the fleet was interrupted ({reason})", *launched.problems]
    if launched.recording is not None:
        problems.append(f"its recording is not filed: {launched.recording}")
    return Result(
        job.entry,
        job.scenario,
        job.provenance,
        UNFILED,
        exit_code=launched.exit_code,
        problems=problems,
        causes=("interrupted",),
    )


def _ordered(jobs: list[Job], order: Sequence[tuple[str, str]]) -> list[Job]:
    """The jobs in the order given; every job exactly once."""
    by_key: dict[tuple[str, ...], Job] = {job.key: job for job in jobs}
    # Taken as given, whatever its length: an entry of the wrong shape names no job and
    # fails the comparison below rather than being cut to fit.
    keys = [tuple(key) for key in order]
    if sorted(keys) != sorted(by_key):
        raise FleetError("an order must name every entry and scenario of the manifest once")
    return [by_key[key] for key in keys]


def _file(store: Store, job: Job, launched: Launched, problems: list[str]) -> Result:
    """One run's result, from what the store makes of its recording."""
    result = Result(
        job.entry,
        job.scenario,
        job.provenance,
        UNFILED,
        exit_code=launched.exit_code,
        problems=list(launched.problems),
    )
    if launched.recording is None:
        reason = _last_line(launched.stderr) or "no recording"
        if launched.exit_code == 2:
            # Refused by the run itself, before anything was recorded: its reason is the result.
            result.state = REFUSED
        result.problems.append(reason)
        return result
    try:
        filed = store.ingest(launched.recording)
    except StoreError as refusal:
        result.problems.append(f"the store refused the recording: {refusal}")
        return result
    info = store.run_info(filed.run)
    result.state = filed.state
    result.run = filed.run
    result.causes = info.causes
    result.problems.extend(filed.problems)
    result.findings = tuple(
        sorted(canonical_key(key) for key, _ in store.findings_of(filed.run).values())
    )
    result.context = {
        "server_version": info.server_version,
        "launch_digest": info.launch_digest,
        "scenario_digest": info.scenario_digest,
    }
    expected = verdict.EXIT_CODES[filed.state]
    if launched.exit_code != expected:
        problems.append(
            f"{job.entry}/{job.scenario}: exit code {launched.exit_code}, but its recording is "
            f"filed {filed.state} ({expected}); the recording is what counts"
        )
    return result


def _check_environment(
    store: Store, results: dict[tuple[str, str], Result], pins: Pins, problems: list[str]
) -> None:
    """Every filed run observed under the fleet's pins — as its own recording names them."""
    for key in sorted(results):
        result = results[key]
        if result.run is None:
            continue
        info = store.run_info(result.run)
        ran = {
            "isolation": info.isolation,
            "sandbox_image": info.sandbox_image,
            "target_image": info.target_image,
        }
        if ran != pins.to_dict():
            problems.append(
                f"{result.entry}/{result.scenario} observed under {ran}, not under the fleet's "
                f"{pins.to_dict()}"
            )


def gate(
    manifest_path: str | Path, engagement: Engagement | None, *, now: datetime | None = None
) -> None:
    """The manifest's refusals of a fleet — an endpoint entry in it — and, under an engagement
    file, every job held to the file, as :func:`run` holds them: for a caller that has to know
    before it starts anything of its own — :func:`pin`, which asks ``docker`` for the images'
    ids, included. Raises :class:`FleetError` as :func:`run` does; :func:`run` asks again, so
    nothing depends on this having been called."""
    try:
        manifest = load_manifest(manifest_path)
    except ValueError as exc:
        raise FleetError(str(exc)) from None
    _no_endpoint_entries(manifest)
    if engagement is not None:
        _gate(engagement, manifest, plan(manifest), ISOLATION, _now() if now is None else now)


def manifest_names(manifest_path: str | Path) -> list[tuple[str, str]]:
    """The names the manifest gives, each as ``(place, name)``: the place says the field and the
    number of the entry (and of the scenario) in the manifest, counted from 1, never the name.
    Empty where the manifest cannot be read; :func:`gate` says why. Reads only."""
    try:
        manifest = load_manifest(manifest_path)
    except ValueError:
        return []
    named: list[tuple[str, str]] = []
    for number, entry in enumerate(manifest.entries, 1):
        named.append((f"the name of entry {number}", entry.name))
        for position, scenario in enumerate(entry.scenarios, 1):
            named.append((f"the name of scenario {position} of entry {number}", scenario.name))
    return named


def _no_endpoint_entries(manifest: Manifest) -> None:
    """A manifest with an endpoint entry refuses the whole fleet, before anything starts."""
    endpoints = [entry.name for entry in manifest.entries if entry.endpoint is not None]
    if endpoints:
        raise FleetError(
            f"{manifest.source}: endpoint entr{'y' if len(endpoints) == 1 else 'ies'} "
            f"{', '.join(repr(name) for name in endpoints)}: an endpoint entry runs through drive "
            "only in this version, never as part of a fleet; nothing was started"
        )


def _gate(
    engagement: Engagement, manifest: Manifest, jobs: list[Job], isolation: str, now: datetime
) -> None:
    """Every job the fleet would launch, held to the engagement file before anything starts.

    A fleet runs corpus entries as children of its own runs: no declared target, no URL, under
    the fleet's isolation, with the default script, which lists and calls nothing.
    """
    for job in jobs:
        if job.refusal is not None:
            continue  # refused anyway, and recorded so; the file is not asked
        facts = GateFacts(
            command="fleet",
            scenario_digest=manifest.entry(job.entry).scenario(job.scenario).digest,
            isolation=isolation,
            script_acts=False,
            script_lists=True,
            stopped=stopped(engagement),
        )
        try:
            check_engagement(engagement, facts, now)
        except EngagementRefused as refusal:
            raise FleetError(
                f"{engagement.source}: {job.entry}/{job.scenario}: {refusal}; nothing was started",
                condition=refusal.condition,
            ) from None


def _no_engagement_held(store: Store) -> None:
    """A fleet without a file, into a store that holds an engagement, is refused before
    anything starts: every run it made would be refused by the store when filed, after the
    runs had been made against servers under no file at all."""
    try:
        held = store.engagement()
    except StoreError as refusal:
        raise FleetError(f"the store's engagement cannot be read: {refusal}") from None
    if held is not None:
        raise FleetError(
            f"the store holds engagement {held['engagement_id_declared']!r} "
            f"(digest {held['engagement_digest']}); a fleet into it is run under that file, with "
            "--engagement naming it; nothing was started"
        )


def _set_engagement(store: Store, engagement: Engagement, now: datetime | None) -> None:
    """The store becomes the engagement's, or refuses the fleet before anything is launched."""
    try:
        store.set_engagement(
            engagement_id_declared=engagement.id,
            digest=engagement.digest,
            file_declared=engagement.sanitized(),
            supersedes=engagement.supersedes,
            delete_after_declared=(
                None if engagement.delete_after is None else engagement.delete_after.isoformat()
            ),
            removed=engagement.removed,
            now=now,
        )
    except StoreError as refusal:
        raise FleetError(
            f"{engagement.source}: the store refused the engagement: {refusal}; nothing was started"
        ) from None


def _check_engagement(
    store: Store,
    results: dict[tuple[str, str], Result],
    engagement: Engagement,
    problems: list[str],
) -> None:
    """Every filed run was gated against the fleet's file — as its own recording names it. A
    run under another version of the file can be in the store's chain and be filed; it is still
    not a run under this fleet's file."""
    for key in sorted(results):
        result = results[key]
        if result.run is None:
            continue
        named = store.run_info(result.run).engagement_digest
        if named != engagement.digest:
            problem = (
                f"{result.entry}/{result.scenario} was gated against the engagement file "
                f"{named}, not the fleet's {engagement.digest}"
            )
            result.problems.append(problem)
            problems.append(problem)


#: The keys of ``fleet.json``'s ``engagement`` block: what a recording carries, nothing more.
_RECORDED_ENGAGEMENT = ("engagement_id_declared", "engagement_digest", "window_declared")
#: A window's end as the gate writes it: UTC, ending in ``Z`` (engagement.utc_text).
_UTC_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def recorded_engagement(document: Mapping[str, Any]) -> dict[str, Any] | None:
    """The ``engagement`` block of a parsed ``fleet.json``: None for a fleet under no file — and
    for a ``fleet.json`` written before the field existed — or exactly the file's id, digest and
    window as a recording carries them. Anything else is refused whole with :class:`FleetError`:
    a block that says more, or less, than which file gated the fleet is not that block."""
    if not isinstance(document, Mapping):
        raise FleetError("fleet.json is not an object")
    block = document.get("engagement")
    if block is None:
        return None
    if not isinstance(block, Mapping) or set(block) != set(_RECORDED_ENGAGEMENT):
        raise FleetError(
            "fleet.json's engagement is not null or exactly " + ", ".join(_RECORDED_ENGAGEMENT)
        )
    name, digest, window = (block[key] for key in _RECORDED_ENGAGEMENT)
    if not isinstance(name, str) or not name:
        raise FleetError("fleet.json's engagement_id_declared is not a non-empty string")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise FleetError("fleet.json's engagement_digest is not 64 lowercase hex characters")
    if (
        not isinstance(window, Mapping)
        or set(window) != {"from", "until"}
        or not all(isinstance(window[k], str) and _UTC_Z.fullmatch(window[k]) for k in window)
    ):
        raise FleetError("fleet.json's window_declared is not {from, until} as UTC times")
    return {
        "engagement_id_declared": name,
        "engagement_digest": digest,
        "window_declared": {"from": window["from"], "until": window["until"]},
    }


def _fleet_row(record: FleetRun) -> dict[str, Any]:
    return {
        "fleet": record.fleet,
        "started_utc": record.started_utc,
        "finished_utc": record.finished_utc,
        "manifest_source": record.manifest["source"],
        "manifest_digest": record.manifest["digest"],
        "tool_version": record.tool["version"],
        "tool_content": record.tool["content"],
        **record.pins.to_dict(),
        "parallel": record.parallel,
        "processed": json.dumps([list(key) for key in record.processed]),
        "digest": record.digest,
        "complete": int(record.complete),
        "problems": json.dumps(record.problems),
        "rules": record.rules,
    }


def _last_line(text: str) -> str:
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return lines[-1][:300] if lines else ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00"


# -- comparing two fleets ----------------------------------------------------------------------


def previous(store: Store, fleet: str) -> str | None:
    """The fleet run filed before this one in the store, or None for the first."""
    ids = [info["fleet"] for info in store.fleets()]
    position = ids.index(fleet)
    return ids[position - 1] if position > 0 else None


def compare(store: Store, before: str, after: str) -> dict[str, Any]:
    """Two fleet runs, entry by entry, through the store's run comparison — with its axes,
    the environment among them."""
    first, second = store.fleet(before), store.fleet(after)
    entries = []
    complete = True
    for key in sorted(first["results"].keys() | second["results"].keys()):
        old, new = first["results"].get(key), second["results"].get(key)
        item: dict[str, Any] = {"entry": key[0], "scenario": key[1]}
        if old is None or new is None:
            item["change"] = "added" if old is None else "removed"
            item["state"] = (new or old)["state"]
        elif old["run"] is None or new["run"] is None:
            complete = False
            item.update(
                change="not_comparable",
                states={"before": old["state"], "after": new["state"]},
                reason="a side has no filed run to compare",
            )
        else:
            diff = store.diff(old["run"], new["run"])
            complete = complete and diff.complete
            item.update(
                change="compared",
                states={"before": old["state"], "after": new["state"]},
                causes={"before": old["causes"], "after": new["causes"]},
                complete=diff.complete,
                moved_axes=list(diff.moved),
                axes={name: dict(axis) for name, axis in diff.axes.items()},
                attribution=diff.attribution.to_dict(),
                caveats={name: list(flags) for name, flags in diff.caveats.items()},
                new=[_brief(c) for c in diff.new],
                gone=[_brief(c) for c in diff.gone],
                unchanged=len(diff.unchanged),
            )
        entries.append(item)
    fields = {
        "manifest": ("manifest_digest",),
        "tool": ("tool_version", "tool_content"),
        "environment": ("isolation", "sandbox_image", "target_image"),
    }
    axes = {}
    for axis, names in fields.items():
        values = {name: {"before": first[name], "after": second[name]} for name in names}
        axes[axis] = {"moved": any(v["before"] != v["after"] for v in values.values()), **values}
    rules = {"before": first["rules"], "after": second["rules"]}
    rules["moved"] = rules["before"] != rules["after"]
    return {
        "before": before,
        "after": after,
        "complete": complete,
        "same_result": first["digest"] == second["digest"],
        # Said apart from the axes: the rules do not find anything, they judge what was found.
        # Under two versions the states, and so the digests, may differ by the rules alone.
        "rules": rules,
        "axes": axes,
        "entries": entries,
    }


def _brief(compared) -> dict[str, Any]:
    return {
        "identity": dict(compared.identity),
        "statement_hint": compared.statement_hint,
        "cap_hint": compared.cap_hint,
    }
