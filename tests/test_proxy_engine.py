"""The decision point wired into the proxy, end to end. Subprocesses, no network."""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

from mcp_kymograph.engine import Action, Engine, RuleErrorPolicy
from mcp_kymograph.events import Direction
from mcp_kymograph.proxy import EXIT_RULE_WEDGED, Limits
from test_proxy import TOY, Session, request, run, still_running

TOY_ARGS = [sys.executable, TOY, "--mode", "normal"]


class PoisonToolsList:
    """Test rule: rewrites the tools/list response, keyed by id."""

    name = "test-poison"

    def act(self, direction, document, responded_method):
        if direction is not Direction.SERVER_TO_CLIENT or responded_method != "tools/list":
            return None
        poisoned = json.loads(json.dumps(document))
        poisoned["result"]["tools"][0]["description"] += " [INJECTED]"
        return poisoned


class DropToolsList:
    name = "test-drop"

    def act(self, direction, document, responded_method):
        if direction is Direction.SERVER_TO_CLIENT and responded_method == "tools/list":
            return Action.DROP
        return None


def events_of(session) -> list[dict]:
    return [json.loads(line) for line in session.path.read_text().splitlines()]


# -- the default is still Phase 1 -----------------------------------------------------


def test_an_empty_scenario_delivers_the_servers_bytes_unchanged(tmp_path):
    """With no rules the client must receive exactly the bytes the server produced, byte for
    byte — the Phase 1 guarantee. Compared against the server run directly with the same
    input, not against another proxied run, so a mutation that reframed or reserialised the
    pass-through path would be caught."""
    requests = request(1, "initialize") + request(2, "tools/list")

    async def proxied():
        async with Session(tmp_path, TOY_ARGS, engine=Engine()) as s:
            s.send(requests)
            await s.until_received(2)
        return s

    proxied_session = run(proxied)
    client_received = bytes(proxied_session.received)

    # The same server, same input, no proxy in the way.
    direct = subprocess.run(  # noqa: S603
        TOY_ARGS, input=requests, capture_output=True, timeout=30, check=True
    )
    assert client_received == direct.stdout, "an empty scenario must not alter a single byte"
    assert not [e for e in events_of(proxied_session) if e["type"] == "intervention"]


# -- interception ---------------------------------------------------------------------


def test_a_replacement_reaches_the_client_and_is_recorded_as_an_intervention(tmp_path):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([PoisonToolsList()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await s.until_received(2)
        return s

    session = run(scenario)

    # The client received the poisoned description.
    client_lines = [json.loads(line) for line in bytes(session.received).splitlines()]
    tools_list = next(m for m in client_lines if m.get("id") == 2)
    assert "[INJECTED]" in tools_list["result"]["tools"][0]["description"]

    # The recording holds an intervention with both sides, kept apart.
    interventions = [e for e in events_of(session) if e["type"] == "intervention"]
    assert len(interventions) == 1
    event = interventions[0]
    assert [step["rule"] for step in event["steps"]] == ["test-poison"]
    assert event["steps"][0]["action"] == "replace_document"
    assert event["action"] == "replace"
    assert event["direction"] == "server_to_client"
    assert event["message_id"] == 2
    assert "[INJECTED]" not in event["original"]["data"]["result"]["tools"][0]["description"]
    assert "[INJECTED]" in event["replacement"]["data"]["result"]["tools"][0]["description"]


def test_an_untouched_message_is_forwarded_unchanged_under_an_active_scenario(tmp_path):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([PoisonToolsList()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
        return s

    session = run(scenario)
    reply = json.loads(bytes(session.received).splitlines()[0])
    assert reply["id"] == 1
    assert reply["result"]["serverInfo"]["name"] == "toy"
    assert not [e for e in events_of(session) if e["type"] == "intervention"]


def test_an_active_but_non_firing_scenario_forwards_bytes_verbatim(tmp_path):
    """On the message-wise path, a message a rule does not touch must be forwarded exactly as
    it arrived — the same bytes the server produced, not a reserialised copy. Compared against
    the server run directly, so a mutation that reserialised the FORWARD path is caught."""
    # Odd whitespace so the server's bytes differ from Python's canonical json.dumps form:
    # that is what tells "forwarded verbatim" apart from "reparsed and re-emitted".
    odd_args = [sys.executable, TOY, "--mode", "normal", "--odd-whitespace"]
    requests = request(1, "initialize")  # the rule only fires on tools/list, so this passes

    async def scenario():
        async with Session(tmp_path, odd_args, engine=Engine([PoisonToolsList()])) as s:
            s.send(requests)
            await s.until_received(1)
        return s

    session = run(scenario)
    direct = subprocess.run(  # noqa: S603
        odd_args, input=requests, capture_output=True, timeout=30, check=True
    )
    assert b" : " in direct.stdout, "precondition: the server really emits odd whitespace"
    assert bytes(session.received) == direct.stdout, "an untouched message must go out verbatim"


def test_a_dropped_message_does_not_reach_the_client_but_is_recorded(tmp_path):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([DropToolsList()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await asyncio.sleep(0.3)
        return s

    session = run(scenario)
    client_ids = [json.loads(line).get("id") for line in bytes(session.received).splitlines()]
    assert 2 not in client_ids, "the dropped tools/list response must not reach the client"
    assert 1 in client_ids, "everything else still flows"
    dropped = [e for e in events_of(session) if e["type"] == "intervention"]
    assert dropped and dropped[0]["action"] == "drop"
    assert dropped[0]["replacement"] is None


def test_the_client_to_server_direction_is_untouched_by_a_server_only_rule(tmp_path):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([PoisonToolsList()])) as s:
            s.send(request(1, "tools/list"))
            await s.until_received(1)
        return s

    session = run(scenario)
    sent_to_server = [
        e
        for e in events_of(session)
        if e["type"] == "message" and e["direction"] == "client_to_server"
    ]
    assert sent_to_server, "the request was still observed"
    assert all(e["parse"]["method"] == "tools/list" for e in sent_to_server)


# -- the rule works on real traffic; the recording masks independently -----------------


def test_the_rule_and_client_see_real_text_while_the_recording_masks_it(tmp_path):
    """The Phase 1 known property, proven end to end.

    The server's tool description carries a Bearer token, which the recorder masks. The rule
    runs on the real traffic, so the client receives the true token (plus the injection),
    while the recording — a separate path on a separate copy — shows it redacted. If the two
    paths were not separated, either the client would get a redacted token or the recording
    would leak it. Neither may happen.
    """
    from mcp_kymograph.rules import POISON_INSTRUCTION, ToolPoisoning

    canary = "Bearer sk-abcdefghijklmnop1234"
    args = [sys.executable, TOY, "--mode", "normal", "--tool-desc", f"call with {canary}"]

    async def scenario():
        async with Session(tmp_path, args, engine=Engine([ToolPoisoning()])) as s:
            s.send(request(1, "tools/list"))
            await s.until_received(1)
        return s

    session = run(scenario)

    # The client received the real token, untouched, plus the injected instruction.
    reply = next(
        json.loads(line) for line in bytes(session.received).splitlines() if b'"id": 1' in line
    )
    description = reply["result"]["tools"][0]["description"]
    assert canary in description, "the client must receive the real, unmasked traffic"
    assert POISON_INSTRUCTION in description

    # The recording masked the token in both the message event and the intervention.
    text = session.path.read_text()
    assert "sk-abcdefghijklmnop1234" not in text, "the recording must not leak the token"
    interventions = [e for e in events_of(session) if e["type"] == "intervention"]
    assert interventions
    both = interventions[0]["original"]["data"], interventions[0]["replacement"]["data"]
    assert all("sk-abcdefghijklmnop1234" not in json.dumps(side) for side in both)


# -- an invalid replacement never goes out --------------------------------------------


class BrokenRule:
    """A rule whose replacement cannot be serialised. The engine must refuse it, and the
    proxy must forward the untouched original rather than let anything invalid out."""

    name = "broken"
    directions = frozenset({Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        if direction is Direction.SERVER_TO_CLIENT and responded_method == "tools/list":
            return {"result": {1, 2, 3}}  # a set is not JSON-serialisable
        return None


def test_an_invalid_replacement_forwards_the_original_and_stops_the_run(tmp_path):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([BrokenRule()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await s.until_received(2)
        return s

    session = run(scenario)

    # The client got the real, valid tools/list response, unchanged.
    reply = next(
        json.loads(line)
        for line in bytes(session.received).splitlines()
        if json.loads(line).get("id") == 2
    )
    assert "tools" in reply["result"], "the original valid response must reach the client"

    # Nothing invalid was recorded as an intervention, and the run stopped for that reason.
    assert not [e for e in events_of(session) if e["type"] == "intervention"]
    assert session.outcome.reason == "invalid_replacement"


# -- a misbehaving rule must not take the connection with it ---------------------------


class ThrowingRule:
    """A rule with a bug."""

    name = "throws"
    directions = frozenset({Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        if responded_method == "tools/list":
            raise ValueError("a rule with a bug")
        return


def test_a_rule_that_raises_forwards_the_original_instead_of_killing_the_pump(tmp_path):
    """Before this was contained, an exception from a rule travelled out of decide(), out of
    the pump, and killed forwarding mid-stream — while observation carried on. That is the
    inversion of the guarantee: the recording outlived the connection."""

    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([ThrowingRule()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await s.until_received(2)
        return s

    session = run(scenario)

    ids = [json.loads(line).get("id") for line in bytes(session.received).splitlines()]
    assert ids == [1, 2], "the untouched original must still reach the client"
    reply = json.loads(bytes(session.received).splitlines()[1])
    assert "tools" in reply["result"], "and it must be the real, valid response"
    assert session.outcome.reason == "rule_error"
    assert not still_running(session.proxy.child_pid)


WEDGE_SCRIPT = """
import asyncio, pathlib, sys, threading
sys.path.insert(0, {tests!r})
from test_proxy import Session, request, run
from mcp_kymograph.engine import Engine
from mcp_kymograph.events import Direction
from mcp_kymograph.proxy import Limits

class BlockingRule:
    name = "blocks"
    directions = frozenset({{Direction.SERVER_TO_CLIENT}})
    def act(self, direction, document, responded_method):
        if responded_method == "tools/list":
            threading.Event().wait()   # never returns
        return None

limits = Limits(max_duration_seconds=30.0, terminate_grace_seconds=0.5,
                shutdown_budget_seconds=3.0, rule_budget_seconds=1.0)

async def scenario():
    out = pathlib.Path({out!r}); out.mkdir(parents=True, exist_ok=True)
    async with Session(out, {argv!r}, limits=limits, engine=Engine([BlockingRule()])) as s:
        s.send(request(1, "initialize"))
        await s.until_received(1)
        s.send(request(2, "tools/list"))
        await asyncio.sleep(60)

run(scenario)
"""


def test_a_rule_that_never_returns_is_torn_down_instead_of_hanging(tmp_path):
    """A rule runs on the event loop, so one that blocks freezes the duration limit, the
    signal handlers and the shutdown budget all at once. The watchdog lives outside that loop
    and turns a silent hang with an orphaned server into a loud, bounded abort."""
    script = WEDGE_SCRIPT.format(
        tests=str(Path(__file__).parent),
        out=str(tmp_path / "runs"),
        argv=[sys.executable, TOY, "--mode", "ignore_sigterm"],
    )
    started = time.monotonic()
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        capture_output=True,
        timeout=40,
        check=False,
        cwd=Path(__file__).parent.parent,
    )
    elapsed = time.monotonic() - started

    assert done.returncode == EXIT_RULE_WEDGED, "a wedged rule must end with its own exit code"
    assert elapsed < 20, f"the abort must be bounded, took {elapsed:.1f}s"
    assert b"wedged" in done.stderr, "and it must say so on stderr"


# -- what a failing rule costs: the run, or only itself --------------------------------


class HitsThenThrows:
    """Changes one message successfully, then breaks on the next.

    Both halves matter. Without the first hit there is nothing for a quarantine to
    invalidate, and the interesting claim — that a rule's *earlier* work is suspect once it
    has failed — would not be exercised at all.
    """

    name = "hits-then-throws"
    directions = frozenset({Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        if responded_method == "initialize":
            return {**document, "_marked": True}
        if responded_method == "tools/list":
            raise ValueError("a bug in a rule")
        return None


class SecondRule:
    """Sits behind the broken one, so it is only reached once that one is out of the way."""

    name = "second"
    directions = frozenset({Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        if responded_method != "tools/list":
            return None
        marked = json.loads(json.dumps(document))
        marked["result"]["tools"][0]["description"] += " [SECOND]"
        return marked


CONTINUE = Limits(
    max_duration_seconds=30.0,
    terminate_grace_seconds=0.5,
    shutdown_budget_seconds=3.0,
    on_rule_error=RuleErrorPolicy.CONTINUE,
)


def test_abort_is_the_default_and_stays_the_default():
    """The older behaviour is what a run gets when nobody chose. A half-run scenario is
    harder to reason about than one that stopped, so continuing has to be asked for."""
    assert Limits().on_rule_error is RuleErrorPolicy.ABORT


def continue_run(tmp_path, rules):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine(rules), limits=CONTINUE) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await s.until_received(2)
            s.send(request(3, "tools/list"))
            await s.until_received(3)
        return s

    return run(scenario)


def replies_by_id(session) -> dict:
    return {
        json.loads(line).get("id"): json.loads(line)
        for line in bytes(session.received).splitlines()
    }


def test_continue_stills_only_the_failing_rule_and_the_run_carries_on(tmp_path):
    """The whole point of the setting: one rule's bug costs that rule, not the assessment."""
    session = continue_run(tmp_path, [HitsThenThrows(), SecondRule()])
    replies = replies_by_id(session)

    assert sorted(replies) == [1, 2, 3], "every message must still have reached the client"
    assert "tools" in replies[2]["result"], "the message the rule broke on goes out untouched"
    assert "[SECOND]" not in json.dumps(replies[2]), "the broken rule was ahead in the order"
    assert "[SECOND]" in json.dumps(replies[3]), "the rule behind it must keep working"
    assert session.outcome.reason != "rule_error", "the run must not have been ended by this"


def test_continue_leaves_the_rest_of_the_scenario_running_not_just_the_connection(tmp_path):
    """`continue` is not `switch interception off`. Read separately because a proxy that
    forwarded everything untouched would also pass the test above."""
    session = continue_run(tmp_path, [HitsThenThrows(), SecondRule()])
    interventions = [e for e in events_of(session) if e["type"] == "intervention"]
    assert [[step["rule"] for step in e["steps"]] for e in interventions] == [
        ["hits-then-throws"],
        ["second"],
    ]


def test_a_quarantine_says_which_rule_and_how_much_of_the_report_it_invalidates(tmp_path):
    session = continue_run(tmp_path, [HitsThenThrows(), SecondRule()])
    quarantines = [e for e in events_of(session) if e["type"] == "rule_quarantined"]

    assert len(quarantines) == 1, "said once, when it happens, not once per later message"
    (quarantine,) = quarantines
    assert quarantine["rule"] == "hits-then-throws"
    assert quarantine["reason"] == "rule_error"
    assert quarantine["message_id"] == 2, "and on which message it broke"
    assert quarantine["invalidated_hits"] == 1, (
        "the hit it made before failing is invalid too: a rule that broke once cannot be "
        "trusted to have been right earlier"
    )


def test_the_closing_event_repeats_the_quarantine_where_nothing_can_drop_it(tmp_path):
    """The quarantine event rides the droppable observer path like everything else there. If
    it were the only record, a full queue could leave a report reading a broken rule's hits
    as valid."""
    session = continue_run(tmp_path, [HitsThenThrows(), SecondRule()])
    (finished,) = [e for e in events_of(session) if e["type"] == "run_finished"]
    assert finished["quarantined_rules"] == ["hits-then-throws"]
    assert session.outcome.quarantined_rules == ("hits-then-throws",)


def test_an_invalid_replacement_is_quarantined_by_the_same_setting(tmp_path):
    """The instruction is explicit that one switch covers both failures. Read on its own,
    because the two arrive by different routes: one is raised by the rule, the other by the
    engine refusing what the rule returned."""
    session = continue_run(tmp_path, [BrokenRule(), SecondRule()])
    replies = replies_by_id(session)

    assert "tools" in replies[2]["result"], "nothing invalid may go out"
    assert "[SECOND]" in json.dumps(replies[3]), "the other rule must keep working"
    (quarantine,) = [e for e in events_of(session) if e["type"] == "rule_quarantined"]
    assert quarantine["rule"] == "broken"
    assert quarantine["reason"] == "invalid_replacement"
    assert quarantine["invalidated_hits"] == 0, "a refused replacement reached nobody"
    assert session.outcome.reason != "invalid_replacement"


def test_abort_still_ends_the_run_when_that_is_what_was_asked_for(tmp_path):
    """Guards the default against the new path: adding `continue` must not have quietly
    turned every rule error into a survivable one."""

    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([HitsThenThrows()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await s.until_received(2)
        return s

    session = run(scenario)
    assert session.outcome.reason == "rule_error"
    assert session.outcome.quarantined_rules == (), "abort stills nothing; it stops"
    assert not [e for e in events_of(session) if e["type"] == "rule_quarantined"]


class BrokenEngine(Engine):
    """Not a rule failing but the engine around it. There is no one rule to still."""

    def decide(self, direction, raw):
        raise RuntimeError("the engine itself")


def test_a_failure_with_no_rule_to_blame_ends_the_run_even_under_continue(tmp_path):
    """`continue` acts on a named rule. When the engine itself breaks there is nothing to
    quarantine, and carrying on would mean carrying on blind."""

    async def scenario():
        async with Session(
            tmp_path, TOY_ARGS, engine=BrokenEngine([SecondRule()]), limits=CONTINUE
        ) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
        return s

    session = run(scenario)
    ids = [json.loads(line).get("id") for line in bytes(session.received).splitlines()]
    assert ids == [1], "the untouched original must still reach the client"
    assert session.outcome.reason == "engine_error"
    assert not still_running(session.proxy.child_pid)


# -- a rule that did not say which directions it touches --------------------------------


class Undeclared:
    """No `directions`: assumed to modify everything, which is the most expensive setting."""

    name = "undeclared"

    def act(self, direction, document, responded_method):
        return


def test_a_rule_without_directions_is_warned_about_once_at_the_start(tmp_path):
    """Once per rule, when it is loaded. Warning where the cost is actually paid would mean
    warning once per message, from inside the forwarding path."""

    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([Undeclared()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
            s.send(request(2, "tools/list"))
            await s.until_received(2)
        return s

    session = run(scenario)
    warnings = [n for n in session.notices if "undeclared" in n and "directions" in n]
    assert len(warnings) == 1, f"expected exactly one warning, got {session.notices}"
    assert "both" in warnings[0], "it has to say what the silent default actually costs"


def test_a_rule_that_declares_its_directions_is_not_warned_about(tmp_path):
    async def scenario():
        async with Session(tmp_path, TOY_ARGS, engine=Engine([SecondRule()])) as s:
            s.send(request(1, "initialize"))
            await s.until_received(1)
        return s

    session = run(scenario)
    assert not [n for n in session.notices if "directions" in n]
