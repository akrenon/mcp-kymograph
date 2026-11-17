"""The runc sandbox for one corpus entry: build the namespace, prove it, and only then the target.

**The rules are not the barrier.** The barrier is that the target's network namespace has no
interface leading anywhere: loopback, and a dummy device that discards whatever is sent to
it. The ruleset only redirects to the sink and records; it is observation. A rule that is
missing costs observation and opens nothing. Barrier and observation fail independently, and
the expensive failure — a silent leak — is excluded by construction, not by a check.

**The order leaves no window.** Each container below is started only after the one before
it has finished or reported:

1. the sink, with ``--network none``: the namespace exists, loopback only, no route;
2. the helper (``CAP_NET_ADMIN`` only): ruleset first, in one transaction for both address
   families, then the dummy and the default routes, then the ruleset read back; it exits;
3. the sink binds its sockets and reports ``armed``;
4. the positive probe, confined exactly like the target, makes every kind of attempt;
   the reader takes the kernel's record (the baseline);
5. the gate: only when every condition holds is a :class:`Cleared` made — and the target's
   command line can only be built from one. The target does not exist before this point,
   so there is no moment in which it runs and the rule is not yet there.

**Fail closed, provably.** A condition that does not hold, or was never established, stops
the run as ``sandbox_failed`` before the target exists. Which one, and the evidence, is
recorded; a failed sandbox is never a run with nothing found.

After the target: it is removed, the reader takes the record again, the sink is stopped and
its account is held against the record (:func:`mcp_kymograph.sandbox.egress.reconcile`).
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_kymograph.environment import helper_env
from mcp_kymograph.identity import ServerIdentity, content_files, from_content
from mcp_kymograph.sandbox import docker
from mcp_kymograph.sandbox.egress import (
    Reconciliation,
    Record,
    RecordError,
    Verdict,
    delta,
    judge_arrivals,
    judge_report,
    parse_record,
    reconcile,
)
from mcp_kymograph.sandbox.inside import common

SANDBOX_IMAGE = "mcp-kymograph-sandbox:1"
#: The image the project's own entries (Python, standard library only) run in.
TARGET_IMAGE = "python:3.12-slim"

INSIDE = Path(__file__).resolve().parent / "inside"
#: Where the sandbox's scripts appear in its own containers. Never mounted into the target.
SCRIPTS = "/opt/mcp-kymograph"
#: Where the target's delivered files appear.
SERVER_ROOT = "/srv"
#: ``-E -s``: no environment and no user site steer the interpreter. The bytecode prefix
#: points nowhere, so the mounted sources are compiled every time: a ``__pycache__`` next to
#: them, written by the host, is never read — a mutated script cannot run as its stale self.
PYTHON = ("python3", "-E", "-s", "-X", "pycache_prefix=/nonexistent/pycache")

RUNTIME = "runc"
UNPRIVILEGED = f"{common.UNPRIVILEGED_UID}:{common.UNPRIVILEGED_UID}"
LABEL_RUN = "mcp-kymograph.run"
LABEL_ROLE = "mcp-kymograph.role"
#: The staging directory's name begins with this, and with the run's nonce when it has one, so
#: that what a killed run left in the temporary directory can be found by the nonce.
STAGE_PREFIX = "mcp-kymograph-stage-"

#: Every condition the gate needs, in the order the steps establish them. One that never got
#: established counts exactly like one that failed.
REQUIRED = (
    "sink_started",
    "helper_exit",
    "ruleset_digest",
    "armed",
    "confinement",
    "barrier",
    "sink_bindings",
    "resolver",
    "authoritative_unreadable",
    "direct_blocked",
    "probe",
    "udp_marks",
)


@dataclass(frozen=True)
class Timeouts:
    container: float = 120.0
    sink_started: float = 60.0
    sink_reply: float = 15.0
    probe_arrival: float = 5.0


class SandboxFailed(Exception):
    """A condition did not hold, or could not be established. The target was not started
    (``phase`` ``before_target``) or its observation is not trustworthy (``after_target``)."""

    def __init__(self, condition: str, detail: Any, *, phase: str = "before_target") -> None:
        super().__init__(f"{condition}: {_short(detail)}")
        self.condition = condition
        self.detail = detail
        self.phase = phase


_GATE = object()


class Cleared:
    """Evidence that every condition held. Only the gate makes one."""

    __slots__ = ("conditions",)

    def __init__(self, conditions: dict[str, Verdict], *, key: object) -> None:
        if key is not _GATE:
            raise TypeError("only the gate clears a sandbox")
        self.conditions = conditions


def clear(conditions: dict[str, Verdict]) -> Cleared:
    """The gate. Every required condition must be present and must have held."""
    for name in REQUIRED:
        verdict = conditions.get(name)
        if verdict is None:
            raise SandboxFailed(name, "never established")
        if not verdict.ok:
            raise SandboxFailed(name, verdict.detail)
    return Cleared(dict(conditions), key=_GATE)


# -- delivering the target's files -----------------------------------------------------------


@dataclass
class Delivery:
    """The entry's files, copied out of the checkout and checked to be the ones identified."""

    directory: Path
    workdir: str
    command: tuple[str, ...]

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def stage(
    paths: Sequence[Path],
    identity: ServerIdentity,
    manifest_directory: Path,
    command_written: Sequence[str],
    *,
    nonce: str | None = None,
) -> Delivery:
    """Copy exactly the files that make up the entry, and prove the copy is what was hashed.

    The target sees this copy and nothing else of the checkout. Its content identity is
    computed again over the copy; a file that changed since the manifest was read makes the
    copy another server, and it is refused rather than run under the old identity. In the
    command, ``{python}`` becomes the image's interpreter and ``{dir}`` the manifest's
    directory inside the copy — a command that needs ``{dir}`` outside it cannot run here.
    """
    root, files = content_files(paths)
    directory = Path(tempfile.mkdtemp(prefix=f"{STAGE_PREFIX}{nonce}-" if nonce else STAGE_PREFIX))
    try:
        for file in files:
            target = directory / file.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, target)
        _readable_by_all(directory)
        # Below itself: where the system keeps temporary files is not part of the copy, and a
        # link on the way there (/tmp on some systems) is none inside it.
        copied = from_content([directory], base=directory)
        if copied.version != identity.version:
            raise SandboxFailed(
                "delivery",
                {"identified": identity.version, "delivered": copied.version},
            )
        try:
            inside = Path(manifest_directory).resolve().relative_to(root)
        except ValueError:
            inside = None
        if inside is None and any("{dir}" in part for part in command_written):
            raise SandboxFailed(
                "delivery", "the command names {dir}, which is not part of the delivered files"
            )
        if inside is None or inside == Path("."):
            workdir = SERVER_ROOT
        else:
            workdir = f"{SERVER_ROOT}/{inside.as_posix()}"
        command = tuple(
            part.replace("{python}", "python3").replace("{dir}", workdir)
            for part in command_written
        )
        return Delivery(directory, workdir, command)
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def _readable_by_all(directory: Path) -> None:
    """The target runs as an unprivileged user that owns none of these files."""
    for current, _, names in os.walk(directory):
        os.chmod(current, 0o755)  # noqa: S103 - read and traverse, nothing more
        for name in names:
            os.chmod(os.path.join(current, name), 0o644)


def clean_up_after(nonce: str) -> list[str]:
    """Whatever a run that had to be killed left behind, found by its nonce and removed: its
    containers (label ``mcp-kymograph.run=<nonce>``) and its staging directory.

    A run that is asked to stop removes both itself; one that is killed cannot, and the target's
    container outlives it (its docker CLI is in a session of its own). Says what it found and
    removed, and when it could not look — never silent about a container it could not remove.
    """
    said = []
    label = f"{LABEL_RUN}={nonce}"
    try:
        found = docker.leftovers(label)
        if found:
            docker.remove(found)
            said.append(f"the stopped run left {len(found)} container(s) behind; removed")
            still = docker.leftovers(label)
            if still:
                said.append(
                    f"{len(still)} container(s) of the stopped run could not be removed: "
                    + " ".join(still)
                )
    except docker.DockerError as exc:
        said.append(f"whether the stopped run left containers behind could not be checked: {exc}")
    for staged in Path(tempfile.gettempdir()).glob(f"{STAGE_PREFIX}{nonce}-*"):
        shutil.rmtree(staged, ignore_errors=True)
        said.append("the stopped run left its staging directory behind; removed")
    return said


# -- the sandbox -----------------------------------------------------------------------------


@dataclass
class EgressReport:
    """What the target attempted, from the kernel's record, and whether the sink agreed."""

    attempts: list[dict[str, Any]]
    dns: list[dict[str, Any]]
    counters: dict[str, int]
    capped: dict[str, int]
    direct: int
    suppressed: int
    problems: list[str] = field(default_factory=list)
    #: Per class where the sink's count differs from the kernel's: both. Recorded, not judged.
    differences: dict[str, dict[str, int]] = field(default_factory=dict)
    #: Per UDP set: counted by the kernel, received by the sink, lost, destinations unseen.
    loss: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def consistent(self) -> bool:
        return not self.problems

    def udp_loss(self) -> dict[str, Any]:
        """What the sink missed of the target's UDP, both families together: recorded on every
        run, and judged by mcp_kymograph.verdict — never here."""
        total = {
            name: sum(family.get(name, 0) for family in self.loss.values())
            for name in ("kernel", "sink", "lost", "unseen_destinations")
        }
        total["rate"] = round(total["lost"] / total["kernel"], 6) if total["kernel"] else 0.0
        return total

    def summary(self) -> dict[str, Any]:
        return {
            "consistent": self.consistent,
            "problems": list(self.problems),
            "attempts": len(self.attempts),
            "dns_queries": len(self.dns),
            "counters": dict(self.counters),
            "capped": dict(self.capped),
            "direct_sink_access": self.direct,
            "sink_suppressed": self.suppressed,
            "account_differences": {k: dict(v) for k, v in self.differences.items()},
            "udp_loss": self.udp_loss(),
        }


class Sandbox:
    """One run's namespace, sink, helper, probe and reader, and the target's place in it.

    Use as a context manager: whatever happens, :meth:`close` removes every container of the
    run and checks that none is left.
    """

    def __init__(
        self,
        delivery: Delivery,
        *,
        target_image: str = TARGET_IMAGE,
        sandbox_image: str = SANDBOX_IMAGE,
        nonce: str | None = None,
        timeouts: Timeouts | None = None,
        inside: Path = INSIDE,
    ) -> None:
        self.delivery = delivery
        #: The scripts, the ruleset and the resolver file this run uses — and the ruleset the
        #: read-back is compared with. One directory, so the file the helper loads and the file
        #: its read-back is held against cannot be two files.
        self.inside = Path(inside)
        self.nonce = nonce or secrets.token_hex(6)
        self.timeouts = timeouts or Timeouts()
        self._images = {"sandbox": sandbox_image, "target": target_image}
        self._ids: dict[str, str] = {}
        self.conditions: dict[str, Verdict] = {}
        #: The evidence of each step, in order, for the recording.
        self.steps: list[dict[str, Any]] = []
        self._cleared: Cleared | None = None
        self._baseline: Record | None = None
        self._readback: str | None = None
        self._sink: subprocess.Popen[bytes] | None = None
        self._sink_lines: list[dict[str, Any]] = []
        self._sink_eof = False
        self._sink_stderr = bytearray()
        self._sink_changed = threading.Condition()
        self._names: list[str] = []
        self._last_reader_state: dict[str, Any] = {}
        self.environment: dict[str, Any] = {}

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def name(self, role: str) -> str:
        return f"mcpb-{self.nonce}-{role}"

    # -- before the target ---------------------------------------------------------------

    def prepare(self) -> Cleared:
        """Steps 1–5. Returns the clearance, or raises :class:`SandboxFailed`."""
        self._resolve_images()
        self._start_sink()
        self._helper()
        self._arm()
        self._probe()
        self._mark("target")
        self._cleared = clear(self.conditions)
        return self._cleared

    def _resolve_images(self) -> None:
        started = time.monotonic()
        try:
            for role, reference in self._images.items():
                self._ids[role] = docker.image_id(reference)
            self.environment = {
                "isolation": RUNTIME,
                "docker": docker.server_version(),
                "images": {
                    role: {"reference": self._images[role], "id": self._ids[role]}
                    for role in self._images
                },
            }
        except docker.DockerError as exc:
            self._step("images", started, False, {"error": str(exc)})
            raise SandboxFailed("images", str(exc)) from None
        self._step("images", started, True, self.environment)

    def _start_sink(self) -> None:
        started = time.monotonic()
        argv = [
            docker.DOCKER,
            *self._base("sink"),
            "-i",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--user",
            UNPRIVILEGED,
            # Explicit rather than inherited from whatever the daemon defaults to: ICMP echo
            # stays possible without a capability (so the target's attempts are observable
            # rather than refused), and IPv6 stays on (so they are observable over it too).
            "--sysctl",
            "net.ipv4.ping_group_range=0 2147483647",
            "--sysctl",
            "net.ipv6.conf.all.disable_ipv6=0",
            "--sysctl",
            "net.ipv6.conf.default.disable_ipv6=0",
            *self._scripts(),
            self._ids["sandbox"],
            *PYTHON,
            f"{SCRIPTS}/sink.py",
        ]
        self._sink = subprocess.Popen(  # noqa: S603 - fixed program, arguments built here
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=helper_env(),
        )
        threading.Thread(target=self._read_sink, daemon=True, name="sink-out").start()
        threading.Thread(target=self._drain_sink_stderr, daemon=True, name="sink-err").start()
        event = self._sink_wait(lambda e: e.get("event") == "started", self.timeouts.sink_started)
        ok = event is not None
        self._verdict("sink_started", started, ok, {} if ok else self._sink_failure())

    def _helper(self) -> None:
        started = time.monotonic()
        argv = [
            *self._base("helper"),
            *self._join_privileged(),
            *self._scripts(),
            self._ids["sandbox"],
            *PYTHON,
            f"{SCRIPTS}/helper.py",
        ]
        done, output = self._run_json(argv)
        self._verdict(
            "helper_exit",
            started,
            done.returncode == 0 and output.get("ok") is True,
            {"returncode": done.returncode, **output, **_stderr(done)},
        )
        expected = common.ruleset_digest((self.inside / "rules.nft").read_bytes())
        self._readback = output.get("readback")
        self._verdict(
            "ruleset_digest",
            started,
            self._readback == expected,
            {"expected": expected, "read_back": self._readback, "nft": output.get("nft_version")},
        )

    def _arm(self) -> None:
        started = time.monotonic()
        self._sink_send("arm")
        event = self._sink_wait(lambda e: e.get("event") == "armed", self.timeouts.sink_reply)
        ok = event is not None
        detail = (
            {"bound": event.get("bound"), "receive_buffer": event.get("receive_buffer")}
            if ok
            else self._sink_failure()
        )
        self._verdict("armed", started, ok, detail)

    def _probe(self) -> None:
        started = time.monotonic()
        self._mark("probe")
        argv = [
            *self._base("probe"),
            *self._confined(),
            *self._scripts(),
            self._ids["sandbox"],
            *PYTHON,
            f"{SCRIPTS}/probe.py",
            self.nonce,
        ]
        done, report = self._run_json(argv)
        if done.returncode != 0 or not report:
            self._verdict("probe", started, False, {"returncode": done.returncode, **_stderr(done)})
        resolv_conf = (self.inside / "resolv.conf").read_text()
        self._verdicts(started, judge_report(report, resolv_conf))
        record = self._read_record("baseline")
        self._baseline = record

        def judged() -> dict[str, Verdict]:
            events = [e for e in self._sink_snapshot() if e.get("phase") == "probe"]
            return judge_arrivals(self.nonce, report, events, record)

        # The sink writes an attempt down once it has read it; give it the time to.
        deadline = time.monotonic() + self.timeouts.probe_arrival
        verdicts = judged()
        while not verdicts["probe"].ok and time.monotonic() < deadline:
            time.sleep(0.05)
            verdicts = judged()
        self._verdicts(started, verdicts)

    def _mark(self, label: str) -> None:
        self._sink_send(f"mark {label}")
        event = self._sink_wait(
            lambda e: e.get("event") == "mark" and e.get("label") == label,
            self.timeouts.sink_reply,
        )
        if event is None:
            raise SandboxFailed("armed", {"mark": label, **self._sink_failure()})

    # -- the target ----------------------------------------------------------------------

    def target_argv(self, cleared: Cleared) -> list[str]:
        """The target's ``docker run`` line. Only from this sandbox's own clearance."""
        if self._cleared is None or cleared is not self._cleared:
            raise SandboxFailed("gate", "the target's command was asked for without clearance")
        return [
            docker.DOCKER,
            *self._base("target"),
            "-i",
            *self._confined(),
            "-v",
            f"{self.delivery.directory}:{SERVER_ROOT}:ro",
            "-w",
            self.delivery.workdir,
            self._ids["target"],
            *self.delivery.command,
        ]

    # -- after the target ----------------------------------------------------------------

    def collect(self) -> EgressReport:
        """Remove the target, take the record again, stop the sink, hold one against the other."""
        started = time.monotonic()
        docker.remove([self.name("target")])
        if self._baseline is None:
            raise SandboxFailed("baseline", "no baseline record", phase="after_target")
        final = self._read_record("final", phase="after_target")
        self._sink_send("stop", phase="after_target")
        stopped = self._sink_wait(lambda e: e.get("event") == "stopped", self.timeouts.sink_reply)
        if stopped is None:
            raise SandboxFailed("sink_account", self._sink_failure(), phase="after_target")
        try:
            moved = delta(final, self._baseline)
        except RecordError as exc:
            raise SandboxFailed("record", str(exc), phase="after_target") from None
        events = [e for e in self._sink_snapshot() if e.get("phase") == "target"]
        totals = stopped.get("totals") or {}
        suppressed = int(stopped.get("suppressed") or 0)
        checked: Reconciliation = reconcile(moved, events, totals, suppressed)
        problems = list(checked.problems)
        if stopped.get("closed") != "target":
            problems.append(
                f"the sink's last phase was {stopped.get('closed')!r}, not the target's"
            )
        problems.extend(self._unchanged())
        report = EgressReport(
            attempts=moved.attempts(),
            dns=[
                {k: e.get(k) for k in ("transport", "family", "qname", "qtype", "answered")}
                for e in events
                if e.get("event") == "dns"
            ],
            counters=dict(moved.counters),
            capped=checked.capped,
            direct=moved.counters.get("n_direct", 0),
            suppressed=suppressed,
            problems=problems,
            differences=checked.differences,
            loss=checked.loss,
        )
        self._step("collect", started, report.consistent, report.summary())
        return report

    def _unchanged(self) -> list[str]:
        """What the target could not change, shown not to have changed."""
        problems = []
        state = self._last_reader_state
        if state.get("readback") != self._readback:
            problems.append("the ruleset read back after the target differs from before")
        if state.get("interfaces") != common.expected_interfaces():
            problems.append(f"the interfaces after the target are {state.get('interfaces')}")
        if state.get("sockets") != common.expected_inventory():
            problems.append(f"the namespace's sockets after the target are {state.get('sockets')}")
        return problems

    # -- teardown ------------------------------------------------------------------------

    def close(self) -> None:
        """Remove every container this run made, and check that none is left."""
        if self._sink is not None and self._sink.poll() is None:
            with contextlib.suppress(Exception):
                if self._sink.stdin is not None:
                    self._sink.stdin.close()
        with contextlib.suppress(docker.DockerError):
            docker.remove([self.name(r) for r in ("target", "probe", "helper", "sink")])
            docker.remove(self._names)
        if self._sink is not None:
            try:
                self._sink.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._sink.kill()
                self._sink.wait(timeout=5)
        self.delivery.cleanup()

    def leftovers(self) -> list[str]:
        return docker.leftovers(f"{LABEL_RUN}={self.nonce}")

    # -- building blocks -----------------------------------------------------------------

    def _base(self, role: str, name: str | None = None) -> list[str]:
        name = name or self.name(role)
        self._names.append(name)
        return [
            "run",
            "--rm",
            "--name",
            name,
            "--label",
            f"{LABEL_RUN}={self.nonce}",
            "--label",
            f"{LABEL_ROLE}={role}",
            "--runtime",
            RUNTIME,
            "--log-driver",
            "none",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
        ]

    def _scripts(self) -> list[str]:
        return ["-v", f"{self.inside}:{SCRIPTS}:ro"]

    def _join_privileged(self) -> list[str]:
        """The helper and the reader: in the sink's namespace, with ``CAP_NET_ADMIN`` alone."""
        return [
            "--network",
            f"container:{self.name('sink')}",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_ADMIN",
        ]

    def _confined(self) -> list[str]:
        """What the probe and the target share — one list, so the probe proves the target's
        conditions and not some other container's."""
        return [
            "--network",
            f"container:{self.name('sink')}",
            "--cap-drop",
            "ALL",
            "--user",
            UNPRIVILEGED,
            "--init",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",  # noqa: S108 - the container's own /tmp
            "--pids-limit",
            "256",
            "--memory",
            "512m",
            "-v",
            f"{self.inside / 'resolv.conf'}:/etc/resolv.conf:ro",
        ]

    def _run_json(self, args: list[str]) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        try:
            done = docker.run(args, timeout=self.timeouts.container)
        except docker.DockerError as exc:
            done = subprocess.CompletedProcess(args, 125, b"", str(exc).encode())
        lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
        try:
            output = json.loads(lines[-1]) if lines else {}
        except ValueError:
            output = {}
        return done, output if isinstance(output, dict) else {}

    def _read_record(self, which: str, *, phase: str = "before_target") -> Record:
        started = time.monotonic()
        argv = [
            *self._base("reader", self.name(f"reader-{which}")),
            *self._join_privileged(),
            *self._scripts(),
            self._ids["sandbox"],
            *PYTHON,
            f"{SCRIPTS}/reader.py",
        ]
        done, output = self._run_json(argv)
        if done.returncode != 0 or output.get("ok") is not True:
            detail = {"returncode": done.returncode, **output, **_stderr(done)}
            self._step(f"reader_{which}", started, False, detail)
            raise SandboxFailed("record", detail, phase=phase)
        try:
            record = parse_record(output["record"])
        except RecordError as exc:
            self._step(f"reader_{which}", started, False, {"error": str(exc)})
            raise SandboxFailed("record", str(exc), phase=phase) from None
        self._last_reader_state = {k: output.get(k) for k in ("readback", "interfaces", "sockets")}
        self._step(
            f"reader_{which}",
            started,
            True,
            {"counters": record.counters, **self._last_reader_state},
        )
        return record

    def _step(self, step: str, started: float, ok: bool, detail: Any) -> None:
        self.steps.append(
            {
                "step": step,
                "ok": ok,
                "seconds": round(time.monotonic() - started, 3),
                "detail": detail,
            }
        )

    def _verdicts(self, started: float, verdicts: dict[str, Verdict]) -> None:
        """Record every condition one piece of evidence settles, then stop at the first that
        failed — each is written down as itself, none hidden behind another."""
        for name, verdict in verdicts.items():
            self.conditions[name] = verdict
            self._step(name, started, verdict.ok, verdict.detail)
        for name, verdict in verdicts.items():
            if not verdict.ok:
                raise SandboxFailed(name, verdict.detail)

    def _verdict(self, name: str, started: float, ok: bool, detail: Any) -> None:
        """Record a condition; a condition that failed ends the preparation here."""
        self.conditions[name] = Verdict(
            ok, detail if isinstance(detail, dict) else {"detail": detail}
        )
        self._step(name, started, ok, detail)
        if not ok:
            raise SandboxFailed(name, detail)

    # -- talking to the sink -------------------------------------------------------------

    def _read_sink(self) -> None:
        if self._sink is None or self._sink.stdout is None:
            return
        for raw in self._sink.stdout:
            try:
                event = json.loads(raw)
            except ValueError:
                event = {"event": "unreadable", "bytes": len(raw)}
            with self._sink_changed:
                self._sink_lines.append(event if isinstance(event, dict) else {})
                self._sink_changed.notify_all()
        with self._sink_changed:
            self._sink_eof = True
            self._sink_changed.notify_all()

    def _drain_sink_stderr(self) -> None:
        if self._sink is None or self._sink.stderr is None:
            return
        for raw in self._sink.stderr:
            self._sink_stderr += raw
            del self._sink_stderr[:-4096]

    def _sink_snapshot(self) -> list[dict[str, Any]]:
        with self._sink_changed:
            return list(self._sink_lines)

    def _sink_wait(
        self, predicate: Callable[[dict[str, Any]], bool], timeout: float
    ) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        with self._sink_changed:
            seen = 0
            while True:
                for event in self._sink_lines[seen:]:
                    if predicate(event):
                        return event
                seen = len(self._sink_lines)
                remaining = deadline - time.monotonic()
                if self._sink_eof or remaining <= 0:
                    return None
                self._sink_changed.wait(remaining)

    def _sink_send(self, command: str, *, phase: str = "before_target") -> None:
        if self._sink is None or self._sink.stdin is None:
            raise SandboxFailed("armed", "the sink was never started", phase=phase)
        try:
            self._sink.stdin.write(command.encode("ascii") + b"\n")
            self._sink.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            raise SandboxFailed(
                "armed", {"command": command, **self._sink_failure()}, phase=phase
            ) from None

    def _sink_failure(self) -> dict[str, Any]:
        return {
            "sink_ended": self._sink_eof,
            "sink_stderr": self._sink_stderr.decode("utf-8", "replace")[-500:],
        }


def _stderr(done: subprocess.CompletedProcess[bytes]) -> dict[str, str]:
    text = done.stderr.decode("utf-8", "replace").strip()
    return {"stderr": text[-500:]} if text else {}


def _short(detail: Any) -> str:
    text = detail if isinstance(detail, str) else json.dumps(detail, default=str)
    return text if len(text) <= 300 else text[:299] + "…"
