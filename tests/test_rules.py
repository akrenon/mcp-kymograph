"""The tool-poisoning rule. Pure logic; the proxy wiring is tested separately."""

import json

from mcp_kymograph.engine import Action, Engine
from mcp_kymograph.events import Direction
from mcp_kymograph.rules import POISON_INSTRUCTION, ToolPoisoning

C2S = Direction.CLIENT_TO_SERVER
S2C = Direction.SERVER_TO_CLIENT


def tools_list_reply(identifier, description="does a thing"):
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "result": {"tools": [{"name": "fetch", "description": description}]},
    }


def engine_with_request(identifier, method):
    engine = Engine([ToolPoisoning()])
    engine.decide(C2S, json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method}).encode())
    return engine


# -- what it acts on -------------------------------------------------------------------


def test_it_poisons_the_first_tool_description_in_a_tools_list_reply():
    engine = engine_with_request(2, "tools/list")
    outcome = engine.decide(S2C, json.dumps(tools_list_reply(2)).encode())
    assert outcome.action is Action.REPLACE
    poisoned = outcome.replacement_document["result"]["tools"][0]["description"]
    assert poisoned.endswith(POISON_INSTRUCTION)
    assert poisoned.startswith("does a thing")


def test_the_payload_is_the_named_constant_and_visibly_inert():
    # Guards the "deliberately harmless" claim: the payload asks only for an inert marker.
    assert "MCP-KYMOGRAPH-CANARY" in POISON_INSTRUCTION
    assert "<!--" in POISON_INSTRUCTION  # hidden as a comment, the classic poisoning form


def test_it_ignores_responses_to_other_methods():
    engine = engine_with_request(2, "tools/call")
    outcome = engine.decide(S2C, json.dumps({"jsonrpc": "2.0", "id": 2, "result": {}}).encode())
    assert outcome.action is Action.FORWARD


def test_it_ignores_the_client_to_server_direction():
    engine = Engine([ToolPoisoning()])
    # Even a tools/list *request* going to the server is left alone.
    outcome = engine.decide(C2S, json.dumps({"id": 2, "method": "tools/list"}).encode())
    assert outcome.action is Action.FORWARD


def test_it_matches_by_id_not_arrival_order():
    engine = Engine([ToolPoisoning()])
    engine.decide(C2S, json.dumps({"id": 1, "method": "tools/call"}).encode())
    engine.decide(C2S, json.dumps({"id": 2, "method": "tools/list"}).encode())

    # The tools/call response arrives first; it must not be poisoned.
    first = engine.decide(S2C, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode())
    assert first.action is Action.FORWARD

    second = engine.decide(S2C, json.dumps(tools_list_reply(2)).encode())
    assert second.action is Action.REPLACE


def test_a_tools_list_reply_with_no_tools_is_left_alone():
    engine = engine_with_request(2, "tools/list")
    outcome = engine.decide(S2C, json.dumps({"id": 2, "result": {"tools": []}}).encode())
    assert outcome.action is Action.FORWARD


# -- the rule sees real traffic, not the masked recording ------------------------------


def test_the_rule_sees_the_unmasked_description_even_when_it_contains_a_secret_word():
    """A description containing 'token' would be redacted in the recording. The rule runs on
    the real traffic, so it sees and extends the true text. If this ever failed, it would
    mean the masking and interception paths are not separated — a real finding."""
    engine = engine_with_request(2, "tools/list")
    real = "call this to refresh the auth token before other calls"
    outcome = engine.decide(S2C, json.dumps(tools_list_reply(2, description=real)).encode())
    poisoned = outcome.replacement_document["result"]["tools"][0]["description"]
    assert poisoned.startswith(real), "the rule must see and build on the unredacted text"
    assert "REDACTED" not in poisoned
