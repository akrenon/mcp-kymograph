"""The runc sandbox against a real Docker daemon: the order, the gate, the record.

Whether the target was ever created is read from the **daemon's event log**, filtered by the
run's label — an artifact of Docker, not a statement of the code under test. The healthy run
is the control: there the target must appear, and only after the probe, the helper and the
baseline reader have exited. Every injected fault must leave no target behind at all.

Faults are injected through the one seam the sandbox has — the directory its scripts, ruleset
and resolver file come from — or by leaving a step out, never by reaching into the gate.

Marked ``docker``: skipped and counted without Docker or the images, an error in CI
(``tests/conftest.py``).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mcp_kymograph import cli, verdict
from mcp_kymograph.corpus import load as load_manifest
from mcp_kymograph.environment import helper_env
from mcp_kymograph.identity import from_content
from mcp_kymograph.sandbox.egress import Verdict
from mcp_kymograph.sandbox.inside import common
from mcp_kymograph.sandbox.runner import (
    INSIDE,
    EgressReport,
    Sandbox,
    SandboxFailed,
    Timeouts,
    stage,
)
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
INITIALIZE = (
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
    b'"capabilities":{},"clientInfo":{"name":"test","version":"0"}}}\n'
)


pytestmark = pytest.mark.docker


def container_events(since: float, nonce: str) -> list[dict[str, Any]]:
    """Every container event the daemon logged for this run's label since ``since``."""
    done = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "events",
            "--since",
            f"{since:.3f}",
            "--until",
            f"{time.time():.3f}",
            "--format",
            "{{json .}}",
            "--filter",
            "type=container",
            "--filter",
            f"label=mcp-kymograph.run={nonce}",
        ],
        capture_output=True,
        env=helper_env(),
        timeout=60,
        check=True,
    )
    return [json.loads(line) for line in done.stdout.splitlines() if line.strip()]


@dataclass
class Run:
    nonce: str
    conditions: dict[str, Verdict] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)
    failure: SandboxFailed | None = None
    target: subprocess.CompletedProcess[bytes] | None = None
    report: EgressReport | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    leftovers: list[str] = field(default_factory=list)

    def times(self, role: str, action: str) -> list[int]:
        return [
            int(e["timeNano"])
            for e in self.events
            if e.get("Action") == action
            and e["Actor"]["Attributes"].get("mcp-kymograph.role") == role
        ]

    def target_created(self) -> bool:
        return bool(self.times("target", "create"))

    def named(self, suffix: str, action: str) -> list[int]:
        """When the container named ``mcpb-<nonce>-<suffix>`` did ``action``."""
        name = f"mcpb-{self.nonce}-{suffix}"
        return [
            int(e["timeNano"])
            for e in self.events
            if e.get("Action") == action and e["Actor"]["Attributes"].get("name") == name
        ]

    def step(self, name: str) -> dict[str, Any]:
        (found,) = [s for s in self.steps if s["step"] == name]
        return found


def sandboxed(box: Sandbox, target_input: bytes = b"") -> Run:
    """Prepare, run the target if cleared, collect; never raises — the evidence is the result."""
    since = time.time() - 1
    run = Run(box.nonce)
    try:
        cleared = box.prepare()
        run.target = subprocess.run(  # noqa: S603
            box.target_argv(cleared), input=target_input, capture_output=True, timeout=120
        )
        run.report = box.collect()
    except SandboxFailed as failed:
        run.failure = failed
    finally:
        box.close()
        run.conditions = dict(box.conditions)
        run.steps = list(box.steps)
        run.leftovers = box.leftovers()
        run.events = container_events(since, box.nonce)
    return run


def _poison_delivery():
    manifest = load_manifest(FIXTURES / "corpus" / "manifest.yaml")
    entry = manifest.entry("poison-server")
    return stage(entry.paths, entry.identity, manifest.directory, entry.command_written)


def _egress_delivery(*args: str):
    target = FIXTURES / "sandbox" / "egress_target.py"
    return stage(
        [target],
        from_content([target]),
        target.parent,
        ["{python}", "{dir}/egress_target.py", *args],
    )


def _inside_copy(tmp_path: Path, edit=None) -> Path:
    """A copy of the scripts directory, optionally with one file changed: the injected fault."""
    copy = tmp_path / "inside"
    shutil.copytree(INSIDE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    if edit is not None:
        name, old, new = edit
        text = (copy / name).read_text()
        assert text.count(old) == 1, (name, old)
        (copy / name).write_text(text.replace(old, new))
    for path in [copy, *copy.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
    return copy


# -- the healthy run: every condition, the order, the target -----------------------------------


@pytest.fixture(scope="module")
def healthy() -> Run:
    return sandboxed(Sandbox(_poison_delivery()), INITIALIZE)


def test_helper_exits_zero(healthy):
    assert healthy.conditions["helper_exit"].ok, healthy.conditions.get("helper_exit")


def test_ruleset_read_back_is_the_file(healthy):
    verdict = healthy.conditions["ruleset_digest"]
    assert verdict.ok, verdict
    assert verdict.detail["read_back"] == common.ruleset_digest((INSIDE / "rules.nft").read_bytes())


def test_sink_is_armed(healthy):
    assert healthy.conditions["armed"].ok, healthy.conditions.get("armed")


def test_positive_probe_arrives_everywhere(healthy):
    verdict = healthy.conditions["probe"]
    assert verdict.ok, {n: a for n, a in verdict.detail.items() if not a["arrived"]}
    assert set(verdict.detail) == set(common.probe_plan(healthy.nonce))
    for name, arrival in verdict.detail.items():
        assert arrival["record"] is True, name
        if not name.startswith("icmp"):
            assert arrival["sink"] is True, name


def test_authoritative_record_unreadable_under_target_credentials(healthy):
    verdict = healthy.conditions["authoritative_unreadable"]
    assert verdict.ok, verdict
    assert verdict.detail["read"] == list(common.AUTHORITATIVE_READ)


def test_sink_binds_only_its_redirect_ports(healthy):
    verdict = healthy.conditions["sink_bindings"]
    assert verdict.ok, verdict
    assert verdict.detail["seen"] == common.expected_inventory()


def test_resolver_is_the_sink_not_the_host(healthy):
    verdict = healthy.conditions["resolver"]
    assert verdict.ok, verdict
    assert "search" not in verdict.detail["seen"]


def test_target_is_unprivileged_without_capabilities_and_read_only(healthy):
    verdict = healthy.conditions["confinement"]
    assert verdict.ok, verdict
    assert verdict.detail["uid"] == common.UNPRIVILEGED_UID
    assert set(verdict.detail["caps"].values()) == {common.NO_CAPABILITIES}
    assert verdict.detail["root_read_only"] is True


def test_barrier_is_loopback_and_one_dummy(healthy):
    verdict = healthy.conditions["barrier"]
    assert verdict.ok, verdict


def test_sink_reachable_only_through_the_redirect(healthy):
    verdict = healthy.conditions["direct_blocked"]
    assert verdict.ok, verdict
    assert "Refused" in verdict.detail["local"]["error"]  # answered like a closed port


def test_target_created_only_after_probe_helper_and_baseline(healthy):
    assert healthy.failure is None, healthy.failure
    created = healthy.times("target", "create")
    assert len(created) == 1  # the control: the instrument sees the target
    for role in ("sink",):
        assert max(healthy.times(role, "start")) < created[0]
    for role in ("helper", "probe", "reader"):
        died = healthy.times(role, "die")
        assert died, role
        assert min(died) < created[0], role
    # The baseline reader is the last container before the target; the final one comes after.
    readers = sorted(healthy.times("reader", "die"))
    assert readers[0] < created[0] < readers[-1]


def test_the_baseline_is_read_after_the_probe_and_before_the_target(healthy):
    """The order, from the daemon's own log: the probe has exited before the baseline reader
    is even created, and the baseline reader has exited before the target is created. So the
    probe's traffic is inside the baseline, and what moves after it is the target's alone."""
    probe_died = healthy.times("probe", "die")
    baseline_created = healthy.named("reader-baseline", "create")
    baseline_died = healthy.named("reader-baseline", "die")
    final_created = healthy.named("reader-final", "create")
    target_created = healthy.times("target", "create")
    assert len(probe_died) == len(baseline_created) == len(target_created) == 1  # the control
    assert probe_died[0] < baseline_created[0] < baseline_died[0] < target_created[0]
    assert target_created[0] < final_created[0]


def test_the_probe_is_in_the_baseline_and_not_in_the_target_s_delta(healthy):
    """Both halves of the claim, read from the record itself: the baseline holds every kind
    of attempt the probe made (two TCP and two UDP per family — direct and DNS — one ICMP
    each, one refused direct access), and the target's delta — a quiet target — holds none."""
    baseline = healthy.step("reader_baseline")["detail"]["counters"]
    for counter, at_least in (
        ("n_tcp4", 2), ("n_tcp6", 2), ("n_udp4", 2), ("n_udp6", 2),
        ("n_icmp4", 1), ("n_icmp6", 1), ("n_direct", 1),
    ):  # fmt: skip
        assert baseline[counter] >= at_least, (counter, baseline)
    assert healthy.report is not None
    assert all(value == 0 for value in healthy.report.counters.values()), healthy.report.counters
    assert healthy.report.attempts == []


def test_the_marks_tell_the_probe_s_udp_destinations_apart(healthy):
    """Two UDP destinations per family in the probe, two marks per family in the kernel's
    record — the evidence, on every run, that UDP is held destination by destination."""
    verdict = healthy.conditions["udp_marks"]
    assert verdict.ok, verdict.detail
    for family in ("udp4", "udp6"):
        marks = verdict.detail[family]
        assert len(marks) == 2 and len(set(marks)) == 2 and 0 not in marks, verdict.detail


def test_target_answers_from_inside(healthy):
    assert healthy.target is not None and healthy.target.returncode == 0
    assert b'"name":"poison-server"' in healthy.target.stdout


def test_a_quiet_target_leaves_a_consistent_empty_record(healthy):
    assert healthy.report is not None
    assert healthy.report.consistent, healthy.report.problems
    assert healthy.report.attempts == []
    assert healthy.report.direct == 0


def test_nothing_is_left_behind(healthy):
    assert healthy.leftovers == []


# -- what a target attempts is recorded with its destination ---------------------------------


@pytest.fixture(scope="module")
def egress() -> Run:
    return sandboxed(Sandbox(_egress_delivery()))


def test_every_attempt_is_recorded_with_its_original_destination(egress):
    assert egress.failure is None, egress.failure
    seen = {
        (a["proto"], a["family"], a["destination"], a.get("port", a.get("type", a.get("l4proto"))))
        for a in egress.report.attempts
    }
    assert seen >= {
        ("tcp", 4, "198.51.100.1", 443),  # the address DNS handed out
        ("tcp", 6, "2001:db8::77", 8443),
        ("udp", 4, "203.0.113.9", 9999),
        ("udp", 4, "198.51.100.4", 4444),
        ("udp", 6, "2001:db8::99", 5353),
        ("udp", 4, common.RESOLVER_V4, 53),
        ("icmp", 4, "203.0.113.7", "echo-request"),
        ("icmp", 6, "2001:db8::7", "echo-request"),
        ("other", 4, "203.0.113.8", "udplite"),
    }


def test_dns_names_are_recorded_and_answered_unreachably(egress):
    names = {(q["qname"], q["qtype"], q["answered"]) for q in egress.report.dns}
    assert ("exfil.attacker.example", common.QTYPE_A, True) in names
    resolved = json.loads(egress.target.stdout)["resolved"]
    assert common.DNS_ANSWER_V4 in resolved


def test_the_sink_s_account_agrees_with_the_kernel(egress):
    assert egress.report.consistent, egress.report.problems
    assert egress.report.capped == {}


def test_a_sink_that_keeps_quiet_about_one_udp_destination_is_caught(tmp_path):
    """Two UDP destinations over IPv4; the sink counts the datagram to the second and never
    writes it down. Held by class, the account agreed — the family was seen. Held by the mark
    each datagram carries, the kernel names a destination the sink never did, and it lost
    nothing that would explain it."""
    inside = _inside_copy(
        tmp_path,
        (
            "sink.py",
            "            else:\n                self.emit(\n                    {\n"
            '                        "event": "udp",',
            '            elif not data.startswith(b"udp-second"):\n                self.emit(\n'
            '                    {\n                        "event": "udp",',
        ),
    )
    run = sandboxed(Sandbox(_egress_delivery(), inside=inside))
    assert run.failure is None and run.report is not None, run.failure
    assert run.report.problems == [
        "udp over IPv4: the kernel recorded 1 destination(s) the sink never named, more than "
        "the 0 datagram(s) it lost can explain"
    ]


@pytest.fixture(scope="module")
def flood() -> Run:
    return sandboxed(Sandbox(_egress_delivery("--flood", "4200")))


def test_a_full_set_is_a_recorded_cap_not_a_gap(flood):
    assert flood.failure is None, flood.failure
    assert flood.report.counters["n_icmp4"] == 4200
    listed = sum(a["count"] for a in flood.report.attempts if a["proto"] == "icmp")
    assert flood.report.capped == {"icmp4": 4200 - listed}
    assert flood.report.capped["icmp4"] > 0
    assert flood.report.consistent


@pytest.fixture(scope="module")
def burst() -> Run:
    return sandboxed(Sandbox(_egress_delivery("--udp-burst", "5000")))


def test_a_burst_faster_than_the_sink_reads_is_counted_whole_and_its_loss_written_down(burst):
    """5000 datagrams to one destination, as fast as a process can send them. How many the sink
    keeps up with is a matter of timing (measured, ten runs: a median of 4494, between 4185 and
    5000) and is not what this holds. What is held is what does not depend on timing: the kernel
    counts every one, the account agrees on the destination, and the loss is written down to the
    datagram — kernel minus sink, never judged as a disagreement. That reading comes before
    writing is held without Docker (test_sandbox.py)."""
    assert burst.failure is None, burst.failure
    assert burst.report.counters["n_udp4"] == 5000
    assert burst.report.consistent, burst.report.problems
    received = burst.report.differences.get("udp4", {"sink": 5000})["sink"]
    loss = burst.report.udp_loss()
    assert (loss["kernel"], loss["sink"], loss["lost"]) == (5000, received, 5000 - received)
    assert loss["unseen_destinations"] == (1 if received == 0 else 0)
    (attempt,) = [a for a in burst.report.attempts if a["proto"] == "udp"]
    assert (attempt["destination"], attempt["port"], attempt["count"]) == (
        "203.0.113.9",
        9999,
        5000,
    )


def test_the_sink_asks_for_the_largest_receive_buffer_the_host_grants(burst):
    """An unprivileged socket gets at most twice net.core.rmem_max, which is the host's and
    not the namespace's; the sink asks for more, and reports what it was granted."""
    granted = int(Path("/proc/sys/net/core/rmem_max").read_text()) * 2
    (armed,) = [step for step in burst.steps if step["step"] == "armed"]
    assert armed["detail"]["receive_buffer"] == granted


@pytest.fixture(scope="module")
def starved(tmp_path_factory) -> Run:
    """A sink that can hold almost nothing: a receive queue of the kernel's minimum and one
    datagram pending at a time. Loss is then certain, not a matter of timing."""
    inside = _starved_inside(tmp_path_factory.mktemp("starved"))
    return sandboxed(Sandbox(_egress_delivery("--udp-burst", "5000"), inside=inside))


def test_a_count_the_sink_falls_short_of_is_recorded_not_a_failed_run(starved):
    """The kernel counts every datagram; the starved sink drops most. Both name the same
    destination, so the run stands — held by membership — and the shortfall is written down,
    not judged. Under a comparison by count this run was invalid."""
    assert starved.failure is None, starved.failure
    assert starved.report.counters["n_udp4"] == 5000
    assert starved.report.consistent, starved.report.problems
    difference = starved.report.differences["udp4"]
    assert difference["kernel"] == 5000 and 0 < difference["sink"] < 5000, difference


# -- every fault stops the run before the target exists --------------------------------------


def _assert_stopped_before_target(run: Run, condition: str) -> None:
    assert run.failure is not None, "the run was cleared"
    assert run.failure.condition == condition, (run.failure.condition, run.failure.detail)
    assert run.failure.phase == "before_target"
    assert run.times("sink", "start"), "control: the daemon log shows this run at all"
    assert not run.target_created(), "the target was created"
    assert run.leftovers == []


def test_helper_failing_stops_the_run(tmp_path):
    inside = _inside_copy(
        tmp_path, ("helper.py", "    return 0\n\n\nif __name__", "    return 1\n\n\nif __name__")
    )
    run = sandboxed(Sandbox(_poison_delivery(), inside=inside))
    _assert_stopped_before_target(run, "helper_exit")


def test_ruleset_not_held_as_written_stops_the_run(tmp_path):
    inside = _inside_copy(
        tmp_path,
        (
            "rules.nft",
            "type filter hook output priority filter;",
            "type filter hook output priority 0;",
        ),
    )
    run = sandboxed(Sandbox(_poison_delivery(), inside=inside))
    _assert_stopped_before_target(run, "ruleset_digest")


def test_a_ruleset_that_marks_nothing_stops_the_run_at_the_marks(tmp_path):
    """Loaded and read back as written, every datagram arriving — under mark 0, on both sides.
    Only the marks of the probe's two destinations per family show that they say nothing."""
    rules = (INSIDE / "rules.nft").read_text()
    edits = [
        f"meta mark set jhash {ip} daddr . udp dport mod 4294967295 seed 0x6d6362 offset 1 "
        for ip in ("ip", "ip6")
    ]
    assert all(rules.count(edit) == 1 for edit in edits)
    inside = _inside_copy(tmp_path)
    for edit in edits:
        rules = rules.replace(edit, "")
    (inside / "rules.nft").write_text(rules)
    run = sandboxed(Sandbox(_poison_delivery(), inside=inside))
    _assert_stopped_before_target(run, "udp_marks")
    assert run.conditions["probe"].ok
    assert run.conditions["udp_marks"].detail == {"udp4": [0, 0], "udp6": [0, 0]}


def test_a_blind_ruleset_that_matches_its_file_is_caught_by_the_probe(tmp_path):
    """The case that happened: rules loaded and read back as written, observation blind."""
    inside = _inside_copy(tmp_path, ("rules.nft", "\t\tct status dnat accept\n", ""))
    run = sandboxed(Sandbox(_poison_delivery(), inside=inside))
    _assert_stopped_before_target(run, "probe")
    assert run.conditions["ruleset_digest"].ok  # the file and the kernel agree...
    blind = {n for n, a in run.conditions["probe"].detail.items() if not a["arrived"]}
    assert blind == {"dns_udp4", "dns_tcp4"}  # ...and the local resolver's traffic never arrives
    assert all(run.conditions["probe"].detail[n]["record"] for n in blind)


def test_sink_not_armed_stops_the_run(tmp_path):
    inside = _inside_copy(tmp_path, ("sink.py", 'if word == "arm" and', 'if word == "never" and'))
    run = sandboxed(Sandbox(_poison_delivery(), inside=inside, timeouts=Timeouts(sink_reply=3)))
    _assert_stopped_before_target(run, "armed")


def test_an_extra_sink_binding_stops_the_run(tmp_path):
    inside = _inside_copy(
        tmp_path,
        (
            "sink.py",
            '        self.emit({"event": "armed", "bound": bound, "receive_buffer": min(buffers)}, '
            "always=True)\n",
            "        extra = socket.socket()\n"
            '        extra.bind(("127.0.0.1", 15099))\n'
            "        extra.listen()\n"
            "        self.listeners.append(extra)\n"
            '        self.emit({"event": "armed", "bound": bound, "receive_buffer": min(buffers)}, '
            "always=True)\n",
        ),
    )
    run = sandboxed(Sandbox(_poison_delivery(), inside=inside))
    _assert_stopped_before_target(run, "sink_bindings")
    assert ["127.0.0.1", 15099] in run.conditions["sink_bindings"].detail["seen"]["tcp"]


class _WithoutHelper(Sandbox):
    def _helper(self) -> None:
        pass


class _WithoutProbe(Sandbox):
    def _probe(self) -> None:
        pass


class _TargetWithNetAdmin(Sandbox):
    """Root with ``CAP_NET_ADMIN``. Adding the capability alone does not arrive: under the
    unprivileged user it lands in the bounding set and nowhere else, so the read stays
    refused — two layers, and the fault has to remove both to be a fault at all."""

    def _confined(self) -> list[str]:
        flags = super()._confined()
        flags[flags.index("--user") + 1] = "0:0"
        return [*flags, "--cap-add", "NET_ADMIN"]


def test_no_helper_means_no_barrier_and_the_run_stops():
    run = sandboxed(_WithoutHelper(_poison_delivery()))
    _assert_stopped_before_target(run, "barrier")
    assert "helper_exit" not in run.conditions


def test_skipping_the_probe_leaves_conditions_unestablished_and_the_gate_shut():
    run = sandboxed(_WithoutProbe(_poison_delivery()))
    _assert_stopped_before_target(run, "confinement")  # the first one the probe would settle
    assert run.failure.detail == "never established"


def test_a_target_able_to_read_the_record_stops_the_run():
    """Both layers report it, each as itself: the confinement, and the record readable."""
    run = sandboxed(_TargetWithNetAdmin(_poison_delivery()))
    _assert_stopped_before_target(run, "confinement")
    assert not run.conditions["authoritative_unreadable"].ok
    assert run.conditions["authoritative_unreadable"].detail["stdout_bytes"] > 0


class _UnprivilegedWithNetAdmin(Sandbox):
    def _confined(self) -> list[str]:
        return [*super()._confined(), "--cap-add", "NET_ADMIN"]


def test_an_added_capability_does_not_reach_the_unprivileged_target():
    """The second layer on its own: the capability lands in the bounding set, the user's
    effective set stays empty — the record stays unreadable. The confinement check still
    refuses the run, because a capability in the bounding set is not 'without capabilities'."""
    run = sandboxed(_UnprivilegedWithNetAdmin(_poison_delivery()), INITIALIZE)
    assert run.conditions["authoritative_unreadable"].ok
    assert run.conditions["confinement"].detail["caps"]["CapEff"] == common.NO_CAPABILITIES
    _assert_stopped_before_target(run, "confinement")


# -- through the command line: the pair, the store, a failure, an egress ---------------------

PROJECT = FIXTURES / "corpus" / "manifest.yaml"
EXPECTED = json.loads((FIXTURES / "corpus" / "expected.json").read_text())


def drive_entry(
    out: Path, manifest: Path, name: str, *extra: str
) -> tuple[int, list[dict[str, Any]], Path]:
    """One corpus run through ``main`` in this process, returning code, events, recording."""
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), "--manifest", str(manifest), "--entry", name, *extra]
    )
    (path,) = out.glob("*/events.jsonl")
    return code, [json.loads(line) for line in path.read_text().splitlines()], path


def findings(events: list[dict[str, Any]]) -> list[str]:
    return sorted(
        json.dumps([e["key"], e["path"]], sort_keys=True) for e in events if e["type"] == "finding"
    )


@pytest.mark.parametrize("name", ["reference", "poison"])
def test_the_pair_finds_through_the_sandbox_exactly_what_it_finds_on_the_host(tmp_path, name):
    """The isolation must not change the detection: the same keys at the same places."""
    server = EXPECTED["entries"][name]["server"]
    code, host, _ = drive_entry(tmp_path / "host", PROJECT, server)
    assert code == 0
    code, boxed, recording = drive_entry(tmp_path / "runc", PROJECT, server, "--isolation", "runc")
    assert code == 0
    assert boxed[0]["isolation"] == "runc" and host[0]["isolation"] == "host"
    assert findings(boxed) == findings(host)
    assert len(findings(boxed)) == len(EXPECTED["entries"][name]["findings"])
    (summary,) = [e for e in boxed if e["type"] == "egress_summary"]
    assert summary["consistent"] and summary["attempts"] == 0
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(recording)
    assert filed.complete, filed.problems


def test_a_sandbox_that_does_not_hold_is_recorded_and_is_not_a_result(
    tmp_path, monkeypatch, capsys
):
    inside = _inside_copy(
        tmp_path, ("helper.py", "    return 0\n\n\nif __name__", "    return 1\n\n\nif __name__")
    )
    made: list[Sandbox] = []

    def broken(delivery, **images):
        made.append(Sandbox(delivery, inside=inside, **images))
        return made[-1]

    monkeypatch.setattr(cli, "Sandbox", broken)
    since = time.time() - 1
    code, events, recording = drive_entry(
        tmp_path / "runs", PROJECT, "poison-server", "--isolation", "runc"
    )
    assert code == cli.EXIT_SANDBOX_FAILED
    (failed,) = [e for e in events if e["type"] == "sandbox_failed"]
    assert (failed["condition"], failed["phase"]) == ("helper_exit", "before_target")
    assert ("helper_exit", False) in [
        (e["step"], e["ok"]) for e in events if e["type"] == "sandbox_step"
    ]
    assert not [e for e in events if e["type"] in ("message", "server_exited")]
    assert events[-1]["type"] == "run_finished" and events[-1]["reason"] == "sandbox_failed"
    assert not [e for e in events if e["type"] == "server_failed"]  # no server to fail
    assert "sandbox_failed (helper_exit)" in capsys.readouterr().err
    run = Run(made[0].nonce, events=container_events(since, made[0].nonce))
    assert run.times("sink", "start") and not run.target_created()
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(recording)
    assert filed.state == "sandbox_failed"
    assert "sandbox_failed: helper_exit (before_target)" in filed.problems


def test_a_server_phoning_home_is_recorded_with_destination_and_name(tmp_path):
    manifest = FIXTURES / "sandbox" / "manifest.yaml"
    code, events, recording = drive_entry(
        tmp_path / "runs", manifest, "phone-home-server", "--isolation", "runc"
    )
    assert code == 0
    attempts = [e for e in events if e["type"] == "egress_attempt"]
    assert {(a["proto"], a["destination"], a["port"]) for a in attempts} >= {
        ("tcp", common.DNS_ANSWER_V4, 443),
        ("udp", common.RESOLVER_V4, 53),
    }
    names = {(e["qname"], e["qtype"]) for e in events if e["type"] == "egress_dns"}
    assert ("collector.attacker.invalid", common.QTYPE_A) in names
    (summary,) = [e for e in events if e["type"] == "egress_summary"]
    assert summary["consistent"], summary["problems"]
    # The server answered as usual: the attempt went nowhere and the run is a result.
    assert not [e for e in events if e["type"] == "server_failed"]
    answered = [e.get("responded_method") for e in events if e["type"] == "message"]
    assert "tools/list" in answered
    with Store.open(tmp_path / "store.sqlite") as store:
        assert store.ingest(recording).complete


def test_the_caller_s_environment_cannot_send_the_target_to_another_daemon(tmp_path, monkeypatch):
    """Every docker call of the sandbox, the target's included, runs with the helper
    environment: a DOCKER_HOST around us must not split the target from its namespace."""
    monkeypatch.setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
    code, events, _ = drive_entry(
        tmp_path / "runs", PROJECT, "poison-server", "--isolation", "runc"
    )
    assert code == 0
    assert not [e for e in events if e["type"] in ("server_failed", "sandbox_failed")]
    assert len(findings(events)) == len(EXPECTED["entries"]["poison"]["findings"])


def _starved_inside(tmp_path: Path) -> Path:
    inside = _inside_copy(tmp_path)
    text = (inside / "sink.py").read_text()
    for old, new in (("RECEIVE_BUFFER = 1 << 24", "RECEIVE_BUFFER = 1"),
                     ("MAX_PENDING = 20000", "MAX_PENDING = 1")):  # fmt: skip
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    (inside / "sink.py").write_text(text)
    return inside


def test_a_server_whose_every_datagram_reached_the_sink_is_complete(tmp_path):
    """Both sides of the loss limit, end to end through drive: 200 datagrams before the
    handshake, all received — the run is a result, and its account says so."""
    manifest = FIXTURES / "sandbox" / "manifest.yaml"
    code, events, _ = drive_entry(
        tmp_path / "runs", manifest, "chatty-server", "--isolation", "runc"
    )
    (summary,) = [e for e in events if e["type"] == "egress_summary"]
    assert summary["udp_loss"] == {
        "kernel": 200, "sink": 200, "lost": 0, "unseen_destinations": 0, "rate": 0.0
    }  # fmt: skip
    assert code == verdict.EXIT_COMPLETE


def test_a_server_whose_datagrams_the_sink_partly_missed_is_incomplete(tmp_path, monkeypatch):
    """The same server, a sink that can hold almost nothing: the account still agrees — the
    kernel and the sink name the same destination — but datagrams are missing, so the run is
    incomplete (3), not sandbox_failed and not complete."""
    inside = _starved_inside(tmp_path)
    monkeypatch.setattr(
        cli, "Sandbox", lambda delivery, **images: Sandbox(delivery, inside=inside, **images)
    )
    manifest = FIXTURES / "sandbox" / "manifest.yaml"
    code, events, recording = drive_entry(
        tmp_path / "runs", manifest, "chatty-server", "--isolation", "runc"
    )
    (summary,) = [e for e in events if e["type"] == "egress_summary"]
    assert summary["consistent"] is True, summary["problems"]
    loss = summary["udp_loss"]
    assert loss["kernel"] == 200 and loss["lost"] > 0, loss
    assert code == cli.EXIT_INCOMPLETE
    judged = verdict.read(recording)
    assert judged.state == verdict.INCOMPLETE
    unseen = loss["unseen_destinations"]
    assert [p for p in judged.problems if "UDP" in p] == [
        f"the sink missed {loss['lost']} of 200 UDP datagram(s) ({loss['lost'] / 200:.2%})"
        + (f", {unseen} destination(s) not once" if unseen else "")
        + ": what they carried was not observed"
    ]
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(recording)
    assert (filed.state, filed.causes) == (verdict.INCOMPLETE, ("udp_loss",))


def test_a_sink_whose_account_differs_from_the_kernel_invalidates_the_run(tmp_path, monkeypatch):
    """The target ran and its findings stand, but what it sent is not known in full: the run
    is not a result. Here the sink stops writing down the questions it is asked — it still
    counts them — once the target's phase begins (the probe's account stays whole, or the
    gate would stop the run first). The kernel recorded the target's question: a destination
    the sink never named, though it lost nothing."""
    old = "        self.emit(event)\n"
    new = old.replace("self.emit(", '(self.emit if self.phase != "target" else lambda _: None)(')
    inside = _inside_copy(tmp_path, ("sink.py", old, new))
    monkeypatch.setattr(
        cli, "Sandbox", lambda delivery, **images: Sandbox(delivery, inside=inside, **images)
    )
    manifest = FIXTURES / "sandbox" / "manifest.yaml"
    code, events, recording = drive_entry(
        tmp_path / "runs", manifest, "phone-home-server", "--isolation", "runc"
    )
    assert code == cli.EXIT_SANDBOX_FAILED
    (failed,) = [e for e in events if e["type"] == "sandbox_failed"]
    assert (failed["condition"], failed["phase"]) == ("reconciliation", "after_target")
    assert failed["detail"]["problems"] == [
        "udp over IPv4: the kernel recorded 1 destination(s) the sink never named, more than "
        "the 0 datagram(s) it lost can explain"
    ]
    (summary,) = [e for e in events if e["type"] == "egress_summary"]
    assert summary["consistent"] is False
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(recording)
    assert not filed.complete
