"""The decision point, in isolation. Pure logic: no proxy, no processes, no network."""

import json

import pytest

from mcp_kymograph.engine import (
    Action,
    Change,
    Edited,
    Engine,
    InvalidReplacement,
    NoEffect,
    Outcome,
    RuleError,
    RuleFailure,
)
from mcp_kymograph.events import Direction

C2S = Direction.CLIENT_TO_SERVER
S2C = Direction.SERVER_TO_CLIENT


def msg(document) -> bytes:
    return json.dumps(document).encode()


class OnResponse:
    """A test rule: rewrites the response to a chosen method, keyed by id, not order."""

    def __init__(self, method: str, *, action=None, rewrite=None) -> None:
        self.name = f"on-{method}"
        self._method = method
        self._action = action
        self._rewrite = rewrite

    def act(self, direction, document, responded_method):
        if direction is not S2C or responded_method != self._method:
            return None
        if self._action is not None:
            return self._action
        return self._rewrite(document)


# -- the default -----------------------------------------------------------------------


def test_an_engine_with_no_rules_is_inactive_and_always_forwards():
    engine = Engine()
    assert engine.active is False
    outcome = engine.decide(S2C, msg({"jsonrpc": "2.0", "id": 1, "result": {}}))
    assert outcome.action is Action.FORWARD


def test_a_rule_that_does_not_match_forwards():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: d)])
    engine.decide(C2S, msg({"id": 1, "method": "tools/call"}))
    outcome = engine.decide(S2C, msg({"id": 1, "result": {"content": []}}))
    assert outcome.action is Action.FORWARD


# -- matching by id, not order ---------------------------------------------------------


def test_a_response_is_matched_to_its_request_by_id():
    poisoned = {"tools": [{"name": "x", "description": "POISONED"}]}
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {**d, "result": poisoned})])

    # Two requests in flight; the tools/list one is id 2, and its response arrives second.
    engine.decide(C2S, msg({"id": 1, "method": "tools/call"}))
    engine.decide(C2S, msg({"id": 2, "method": "tools/list"}))

    other = engine.decide(S2C, msg({"id": 1, "result": {"content": []}}))
    assert other.action is Action.FORWARD, "the tools/call response must pass untouched"

    hit = engine.decide(S2C, msg({"id": 2, "result": {"tools": []}}))
    assert hit.action is Action.REPLACE
    assert hit.message_id == 2
    assert json.loads(hit.replacement)["result"] == poisoned


def test_order_alone_does_not_trigger_a_rule():
    """A response whose id was never a tools/list request is left alone, even if it looks
    like one by position."""
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {**d, "poisoned": True})])
    engine.decide(C2S, msg({"id": 9, "method": "tools/call"}))
    outcome = engine.decide(S2C, msg({"id": 9, "result": {"tools": []}}))
    assert outcome.action is Action.FORWARD


# -- the three outcomes ----------------------------------------------------------------


def test_drop_is_carried_through_as_its_own_action():
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    outcome = engine.decide(S2C, msg({"id": 1, "result": {}}))
    assert outcome.action is Action.DROP
    assert outcome.original_document == {"id": 1, "result": {}}
    assert outcome.replacement is None


def test_replace_carries_both_documents_for_the_event():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {**d, "added": 1})])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    outcome = engine.decide(S2C, msg({"id": 1, "result": {}}))
    assert outcome.original_document == {"id": 1, "result": {}}
    assert outcome.replacement_document == {"id": 1, "result": {}, "added": 1}


# -- the engine works on real traffic, not the masked recording ------------------------


def test_the_engine_sees_the_unmasked_description():
    """A tool description containing 'token' would be redacted in the recording. The engine
    must see the real text, or a rule keying on that text could never fire."""
    seen = {}

    def capture(document):
        seen["description"] = document["result"]["tools"][0]["description"]
        return document

    engine = Engine([OnResponse("tools/list", rewrite=capture)])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    real = "refresh the auth token for the session"
    engine.decide(S2C, msg({"id": 1, "result": {"tools": [{"name": "x", "description": real}]}}))
    assert seen["description"] == real, "the rule must see the unredacted text"
    assert "REDACTED" not in seen["description"]


# -- validity of what goes out ---------------------------------------------------------


def test_a_replacement_that_cannot_be_serialised_is_refused_not_sent():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {"bad": {1, 2, 3}})])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    with pytest.raises(InvalidReplacement):
        engine.decide(S2C, msg({"id": 1, "result": {}}))


def test_a_replacement_is_always_valid_json():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {"ok": True, "n": 1})])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    outcome = engine.decide(S2C, msg({"id": 1, "result": {}}))
    assert json.loads(outcome.replacement) == {"ok": True, "n": 1}  # parseable by definition


# -- unreadable input ------------------------------------------------------------------


def test_non_json_passes_through_rather_than_being_dropped():
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    assert engine.decide(S2C, b"this is not json").action is Action.FORWARD


def test_invalid_utf8_passes_through():
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    assert engine.decide(S2C, b'{"x": "\xff\xfe"}').action is Action.FORWARD


def test_a_forward_outcome_is_the_shared_singleton_shape():
    assert Outcome.passthrough().action is Action.FORWARD


# -- only the modified direction is message-wise --------------------------------------


class ServerOnlyRule:
    name = "server-only"
    directions = frozenset({Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        return None


class UndeclaredRule:
    name = "undeclared"

    def act(self, direction, document, responded_method):
        return None


def test_a_direction_scoped_rule_only_marks_its_own_direction_for_interception():
    engine = Engine([ServerOnlyRule()])
    assert engine.modifies(S2C) is True
    assert engine.modifies(C2S) is False, "the untouched direction must stay on the fast path"


def test_a_rule_without_declared_directions_is_treated_as_touching_all():
    engine = Engine([UndeclaredRule()])
    assert engine.modifies(S2C) is True
    assert engine.modifies(C2S) is True


def test_id_tracking_still_works_when_the_request_direction_is_only_observed():
    """The request direction stays blockwise, so the engine learns its ids through observe(),
    not decide(). A response must still be matched by that id."""
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {**d, "hit": True})])
    engine.observe(C2S, msg({"id": 5, "method": "tools/list"}))  # as the observer would
    outcome = engine.decide(S2C, msg({"id": 5, "result": {"tools": []}}))
    assert outcome.action is Action.REPLACE
    assert outcome.message_id == 5


# -- a failing rule names itself, so it can be stilled alone ----------------------------


class ThrowsOnResponse:
    """A rule with a bug in it. The engine must say *which* rule broke, not just that one did."""

    name = "throws"
    directions = frozenset({Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        if responded_method == "tools/list":
            raise ValueError("a bug in a rule")
        return


def test_an_exception_from_a_rule_arrives_named_and_placed():
    """Without the rule's name there is no way to still one rule and keep the rest: the only
    available answer would be to end the run, whatever the policy says."""
    engine = Engine([ThrowsOnResponse()])
    engine.decide(C2S, msg({"id": 7, "method": "tools/list"}))
    with pytest.raises(RuleError) as raised:
        engine.decide(S2C, msg({"id": 7, "result": {}}))
    assert raised.value.rule == "throws"
    assert raised.value.reason == "rule_error"
    assert raised.value.message_id == 7, "the report has to say which message it broke on"


def test_an_invalid_replacement_arrives_named_and_placed():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {"bad": {1, 2, 3}})])
    engine.decide(C2S, msg({"id": 8, "method": "tools/list"}))
    with pytest.raises(InvalidReplacement) as raised:
        engine.decide(S2C, msg({"id": 8, "result": {}}))
    assert raised.value.rule == "on-tools/list"
    assert raised.value.reason == "invalid_replacement"
    assert raised.value.message_id == 8


def test_both_failures_share_one_type_so_one_policy_covers_both():
    assert issubclass(RuleError, RuleFailure)
    assert issubclass(InvalidReplacement, RuleFailure)


# -- quarantine: one rule stilled, the others left alone --------------------------------


def test_a_quarantined_rule_stops_acting_and_the_others_keep_working():
    thrower = ThrowsOnResponse()
    working = OnResponse("tools/list", rewrite=lambda d: {**d, "hit": True})
    engine = Engine([thrower, working])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))

    with pytest.raises(RuleError):
        engine.decide(S2C, msg({"id": 1, "result": {}}))

    assert engine.quarantine("throws") is True
    outcome = engine.decide(S2C, msg({"id": 1, "result": {}}))
    assert outcome.action is Action.REPLACE
    assert [step.rule for step in outcome.steps] == ["on-tools/list"], (
        "the rule behind the broken one must now be reached"
    )


def test_quarantining_the_same_rule_twice_is_reported_as_no_change():
    engine = Engine([ThrowsOnResponse()])
    assert engine.quarantine("throws") is True
    assert engine.quarantine("throws") is False
    assert engine.quarantined == ("throws",)


def test_a_quarantine_does_not_switch_interception_off():
    """The instruction is explicit: still the one rule, never the engine. A quarantined rule
    also keeps its declared directions on the message-wise path, because a pump chooses its
    framing once and cannot be re-framed underneath a half-read message."""
    engine = Engine([ThrowsOnResponse()])
    engine.quarantine("throws")
    assert engine.active is True
    assert engine.modifies(S2C) is True


def test_hits_count_what_the_engine_did_not_what_got_recorded():
    """Interventions are droppable; the count a quarantine invalidates must not be."""
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {**d, "hit": True})])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    engine.decide(S2C, msg({"id": 1, "result": {}}))
    engine.decide(S2C, msg({"id": 1, "result": {}}))
    assert engine.hits("on-tools/list") == 2
    assert engine.hits("never-ran") == 0


def test_a_refused_replacement_is_a_failure_not_a_hit():
    """An invalid replacement never reached anyone. Counting it would overstate how much of
    the report a quarantine invalidates."""
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: {"bad": {1, 2, 3}})])
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    with pytest.raises(InvalidReplacement):
        engine.decide(S2C, msg({"id": 1, "result": {}}))
    assert engine.hits("on-tools/list") == 0


# -- the undeclared-directions warning --------------------------------------------------


def test_a_rule_without_directions_is_named_so_it_can_be_warned_about_once():
    engine = Engine([UndeclaredRule(), ServerOnlyRule()])
    assert engine.undeclared_directions() == ("undeclared",)


def test_a_scenario_that_declares_everything_has_nothing_to_warn_about():
    assert Engine([ServerOnlyRule()]).undeclared_directions() == ()


# -- the chain: every matching rule acts, in scenario order -----------------------------


class Appends:
    """Changes the working document in place, as a rule from a scenario file does."""

    directions = frozenset({S2C})

    def __init__(self, name: str, text: str, *, path_present: bool = True) -> None:
        self.name = name
        self._text = text
        self._present = path_present

    def act(self, direction, document, responded_method):
        if responded_method != "tools/list":
            return None
        tools = document["result"]["tools"]
        if not self._present or not tools:
            return NoEffect("inject", "path_not_found")
        before = tools[0]["description"]
        tools[0]["description"] = before + self._text
        return Edited("inject", (Change("result.tools[0].description", before, before + "x"),))


def tools_list_engine(*rules) -> Engine:
    engine = Engine(rules)
    engine.decide(C2S, msg({"id": 1, "method": "tools/list"}))
    return engine


TOOLS = {"id": 1, "result": {"tools": [{"name": "t", "description": "D"}]}}


def test_every_matching_rule_acts_in_scenario_order_on_what_the_one_before_left():
    engine = tools_list_engine(Appends("a", "[A]"), Appends("b", "[B]"))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert outcome.action is Action.REPLACE
    assert json.loads(outcome.replacement)["result"]["tools"][0]["description"] == "D[A][B]"
    assert [step.rule for step in outcome.steps] == ["a", "b"]


def test_the_order_is_the_scenario_order_and_nothing_else():
    engine = tools_list_engine(Appends("b", "[B]"), Appends("a", "[A]"))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert json.loads(outcome.replacement)["result"]["tools"][0]["description"] == "D[B][A]"


def test_the_original_survives_an_in_place_chain():
    """The rules change the parsed document in place; the record needs it as it arrived."""
    engine = tools_list_engine(Appends("a", "[A]"))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert outcome.original_document == TOOLS


def test_a_rule_that_matched_and_changed_nothing_leaves_a_step_saying_why():
    engine = tools_list_engine(Appends("a", "[A]", path_present=False), Appends("b", "[B]"))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert [(step.rule, step.effective, step.reason) for step in outcome.steps] == [
        ("a", False, "path_not_found"),
        ("b", True, None),
    ]
    assert engine.hits("a") == 0, "a step without effect is not a hit"
    assert engine.hits("b") == 1


def test_a_chain_with_no_effect_at_all_forwards_but_still_carries_its_steps():
    engine = tools_list_engine(Appends("a", "[A]", path_present=False))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert outcome.action is Action.FORWARD
    assert [step.reason for step in outcome.steps] == ["path_not_found"]


def test_drop_ends_the_chain():
    engine = tools_list_engine(
        OnResponse("tools/list", action=Action.DROP), Appends("after", "[X]")
    )
    outcome = engine.decide(S2C, msg(TOOLS))
    assert outcome.action is Action.DROP
    assert [step.rule for step in outcome.steps] == ["on-tools/list"]
    assert engine.hits("after") == 0


def test_a_change_before_a_drop_counts_but_is_not_sent():
    engine = tools_list_engine(Appends("a", "[A]"), OnResponse("tools/list", action=Action.DROP))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert outcome.action is Action.DROP
    assert outcome.replacement is None
    assert [step.rule for step in outcome.steps] == ["a", "on-tools/list"]


def test_a_failure_mid_chain_costs_the_whole_chain_its_hits():
    """Half a chain is a message no scenario describes. Nothing of it went out."""
    engine = tools_list_engine(Appends("a", "[A]"), ThrowsOnResponse())
    with pytest.raises(RuleError) as raised:
        engine.decide(S2C, msg(TOOLS))
    assert raised.value.rule == "throws"
    assert engine.hits("a") == 0


def test_a_whole_document_step_is_recorded_as_it_was_not_as_the_chain_ended():
    engine = tools_list_engine(
        OnResponse("tools/list", rewrite=lambda d: json.loads(json.dumps(d))),
        Appends("a", "[A]"),
    )
    outcome = engine.decide(S2C, msg(TOOLS))
    first = outcome.steps[0]
    assert first.action == "replace_document"
    (change,) = first.changes
    assert change.path == ""
    assert change.after["result"]["tools"][0]["description"] == "D", (
        "the later in-place step must not reach back into this one's record"
    )


def test_a_whole_document_rule_cannot_have_its_result_changed_by_a_later_rule():
    shared = {"id": 1, "result": {"tools": [{"name": "t", "description": "D"}]}}
    engine = tools_list_engine(
        OnResponse("tools/list", rewrite=lambda d: shared), Appends("a", "[A]")
    )
    engine.decide(S2C, msg(TOOLS))
    assert shared["result"]["tools"][0]["description"] == "D"


def test_the_document_is_serialised_once_as_one_line():
    """A newline inside an injected text must not split the message on the stdio framing."""
    engine = tools_list_engine(Appends("a", "\nsecond line\r\n"))
    outcome = engine.decide(S2C, msg(TOOLS))
    assert b"\n" not in outcome.replacement and b"\r" not in outcome.replacement


def test_a_whole_document_step_is_recorded_as_returned_even_if_the_rule_keeps_its_result():
    """The recorder masks when the event is written, which is later. A rule that hands back
    an object it goes on changing must not be able to rewrite the record of an earlier step.
    """
    kept = {"id": 1, "result": {"calls": 0}}

    def rewrite(document):
        kept["result"]["calls"] += 1
        return kept

    engine = tools_list_engine(OnResponse("tools/list", rewrite=rewrite))
    first = engine.decide(S2C, msg(TOOLS))
    engine.decide(S2C, msg(TOOLS))
    assert first.steps[0].changes[0].after["result"]["calls"] == 1


# -- ids compared as the clients compare them, one table per direction ---------------------


@pytest.mark.parametrize("identifier", [1.0, "1", " 1 ", "0x1", "1e0"], ids=repr)
def test_a_differently_written_id_still_reaches_the_rule(identifier):
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    outcome = engine.decide(S2C, msg({"jsonrpc": "2.0", "id": identifier, "result": {}}))
    assert outcome.action is Action.DROP


def test_an_id_the_clients_disagree_on_is_matched_to_nothing():
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    raw = b'{"jsonrpc":"2.0","id":9007199254740993,"result":{}}'
    assert engine.decide(S2C, raw).action is Action.FORWARD


def test_a_server_request_does_not_take_the_place_of_a_client_request():
    """Client tools/list id 2, server prompts/list id 2, then the answer with id 2."""
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    engine.observe(C2S, msg({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    engine.observe(S2C, msg({"jsonrpc": "2.0", "id": 2, "method": "prompts/list"}))
    outcome = engine.decide(S2C, msg({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}))
    assert outcome.action is Action.DROP


def test_the_same_flow_through_decide_alone():
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    engine.decide(S2C, msg({"jsonrpc": "2.0", "id": 2, "method": "prompts/list"}))
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 2, "result": {}}))
    outcome = engine.decide(S2C, msg({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}))
    assert outcome.action is Action.DROP


def test_the_clients_answer_to_a_server_request_is_matched_in_the_server_table():
    catcher = CatchesClientAnswer()
    engine = Engine([OnResponse("tools/list", action=Action.DROP), catcher])
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    engine.decide(S2C, msg({"jsonrpc": "2.0", "id": 2, "method": "prompts/list"}))
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 2, "result": {}}))
    assert catcher.seen == [None, "prompts/list"]  # the request itself, then the answer


class CatchesClientAnswer:
    """Records the method the engine tied a client's answer to."""

    name = "catch"
    directions = frozenset({C2S})

    def __init__(self) -> None:
        self.seen: list = []

    def act(self, direction, document, responded_method):
        if direction is C2S:
            self.seen.append(responded_method)


# -- invalid UTF-8 -----------------------------------------------------------------------


def test_an_id_is_learned_from_a_message_that_is_not_valid_utf8():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: d)])
    engine.decide(C2S, b'{"jsonrpc":"2.0","id":3,"method":"tools/list","x":"\xff"}')
    outcome = engine.decide(S2C, msg({"id": 3, "result": {"tools": []}}))
    assert [step.rule for step in outcome.steps] == ["on-tools/list"]


def test_a_message_that_is_not_valid_utf8_goes_on_unchanged_and_says_so():
    engine = Engine([OnResponse("tools/list", action=Action.DROP)])
    engine.decide(C2S, msg({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
    outcome = engine.decide(S2C, b'{"jsonrpc":"2.0","id":3,"result":{"tools":[],"x":"\xff"}}')
    assert outcome.action is Action.FORWARD
    assert outcome.replacement is None
    assert outcome.steps == ()
    assert outcome.unreadable is True


def test_a_message_that_is_not_valid_utf8_is_not_unreadable_where_no_rule_acts():
    class OnClient(OnResponse):
        directions = frozenset({C2S})

    engine = Engine([OnClient("tools/list", action=Action.DROP)])
    outcome = engine.decide(S2C, b'{"id":3,"result":"\xff"}')
    assert outcome.action is Action.FORWARD
    assert outcome.unreadable is False


def test_valid_utf8_is_not_unreadable():
    engine = Engine([OnResponse("tools/list", rewrite=lambda d: d)])
    assert engine.decide(S2C, msg({"id": 3, "result": "ü"})).unreadable is False


def test_a_quarantined_rule_reads_nothing_so_an_undecodable_message_is_not_unreadable():
    """Only a rule still acting on the direction would have read it."""

    class OnServer:
        name = "on-server"
        directions = frozenset({Direction.SERVER_TO_CLIENT})

        def act(self, direction, document, responded_method):
            return None

    engine = Engine([OnServer()])
    raw = b'{"jsonrpc":"2.0","id":1,"result":{"x":"\xff"}}'
    assert engine.decide(Direction.SERVER_TO_CLIENT, raw).unreadable is True
    engine.quarantine("on-server")
    assert engine.decide(Direction.SERVER_TO_CLIENT, raw).unreadable is False
