"""Scenario files: what they may say, and how loudly they are refused when they say it wrong."""

import json
from pathlib import Path

import pytest

from mcp_kymograph.engine import Action, Edited, Engine, NoEffect
from mcp_kymograph.events import Direction
from mcp_kymograph.scenario import (
    MAX_FILE_BYTES,
    ScenarioError,
    _strict_loader,
    build,
    load,
    parse_json,
    parse_yaml,
)
from mcp_kymograph.signals import Signal

S2C = Direction.SERVER_TO_CLIENT
C2S = Direction.CLIENT_TO_SERVER

INJECT = {
    "name": "poison",
    "match": {"direction": "server_to_client", "method": "tools/list"},
    "action": "inject",
    "path": "result.tools[*].description",
    "text": " [INJECTED]",
}

STATEMENT = {
    "name": "hidden-comment",
    "match": {"method": "tools/list"},
    "path": "result.tools[*].description",
    "signals": ["hidden_comment"],
}


@pytest.fixture
def fixtures():
    return Path(__file__).parent / "fixtures"


def scenario(**sections):
    return {"version": 1, **sections}


def refused(data) -> str:
    with pytest.raises(ScenarioError) as raised:
        build(data, source="s.yaml")
    return str(raised.value)


def tools(*descriptions):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{"name": f"t{i}", "description": d} for i, d in enumerate(descriptions)]
        },
    }


# -- the empty scenario -------------------------------------------------------------------


def test_a_scenario_with_nothing_in_it_is_valid():
    """The case the gate exists for: selected, and loading no rules at all."""
    loaded = build(scenario(), source="s.yaml")
    assert loaded.rules == () and loaded.statements == ()


def test_sections_left_empty_by_commenting_everything_out_are_valid_and_empty():
    loaded = build(scenario(rules=None, observations=None), source="s.yaml")
    assert loaded.rules == () and loaded.statements == ()


def test_the_empty_fixture_loads_as_empty(fixtures):
    loaded = load(fixtures / "scenarios" / "empty.yaml")
    assert loaded.rules == () and loaded.statements == ()
    assert len(loaded.digest) == 64


# -- the frame ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ([], "a mapping"),
        ({}, "version: missing"),
        ({"version": 2}, "version: unsupported"),
        ({"version": "1"}, "version: unsupported"),
        ({"version": True}, "version: unsupported"),
        (scenario(rule=[]), "unknown key 'rule'"),
        (scenario(rules={}), "rules: expected a list"),
        (scenario(rules=["x"]), "rules[0]: expected a mapping"),
    ],
)
def test_a_malformed_frame_is_refused(data, fragment):
    assert fragment in refused(data)


def test_the_source_is_named_in_every_refusal():
    assert refused({}).startswith("s.yaml: ")


# -- rules --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({"action": "repalce"}, "rules[0].action: unknown action 'repalce'; expected one of"),
        ({"action": None}, "rules[0].action: unknown action"),
        ({"path": "result..tools"}, "rules[0].path: expected a key at position 7"),
        ({"path": None}, "rules[0].path: missing"),
        ({"text": None}, "rules[0].text: missing"),
        ({"text": 3}, "rules[0].text: expected a string"),
        ({"position": "middle"}, "rules[0].position: unknown position 'middle'"),
        ({"value": "x"}, "rules[0].value: not allowed for action 'inject'"),
        ({"match": {"method": "tools/list"}}, "rules[0].match.direction: missing"),
        ({"match": {"direction": "inbound"}}, "rules[0].match.direction: unknown direction"),
        ({"match": {"direction": "server_to_client", "methd": "x"}}, "unknown key 'methd'"),
        ({"match": {"direction": "server_to_client", "method": ""}}, "match.method: empty"),
        ({"name": "has space"}, "rules[0].name: "),
        ({"name": None}, "rules[0].name: missing"),
        ({"surprise": 1}, "rules[0]: unknown key 'surprise'"),
    ],
)
def test_a_wrong_rule_is_refused_with_where(change, fragment):
    rule = {**INJECT, **change}
    rule = {key: value for key, value in rule.items() if value is not None}
    assert fragment in refused(scenario(rules=[rule]))


def test_drop_takes_no_path_because_it_drops_the_whole_message():
    drop = {"name": "d", "match": {"direction": "server_to_client"}, "action": "drop"}
    assert build(scenario(rules=[drop]), source="s").rules[0].name == "d"
    assert "rules[0].path: not allowed for action 'drop'" in refused(
        scenario(rules=[{**drop, "path": "result"}])
    )


def test_replace_needs_a_value_and_any_json_value_will_do():
    replace = {
        "name": "r",
        "match": {"direction": "server_to_client"},
        "action": "replace",
        "path": "result.x",
    }
    assert "rules[0].value: missing" in refused(scenario(rules=[replace]))
    for value in (None, False, 0, "s", [1], {"a": [None]}):
        build(scenario(rules=[{**replace, "value": value}]), source="s")


@pytest.mark.parametrize("value", [float("nan"), {1: "x"}, {"a": {1, 2}}, b"bytes"])
def test_a_value_that_is_not_json_is_refused(value):
    replace = {
        "name": "r",
        "match": {"direction": "server_to_client"},
        "action": "replace",
        "path": "result.x",
        "value": value,
    }
    assert "rules[0].value" in refused(scenario(rules=[replace]))


def test_names_are_unique_across_rules_and_statements():
    """A name is what a report and a quarantine point at; two things under one is one too many."""
    assert "observations[0].name: 'poison' is already used" in refused(
        scenario(rules=[INJECT], observations=[{**STATEMENT, "name": "poison"}])
    )


def test_a_rule_declares_the_one_direction_it_modifies():
    """So the other direction stays on the chunk path and no load-time warning is due."""
    (rule,) = build(scenario(rules=[INJECT]), source="s").rules
    assert rule.directions == frozenset({S2C})
    assert Engine([rule]).undeclared_directions() == ()


# -- what a rule does ---------------------------------------------------------------------


def rule_from(**overrides):
    """INJECT with changes; an override of None takes the key out."""
    rule = {**INJECT, **overrides}
    rule = {key: value for key, value in rule.items() if overrides.get(key, ...) is not None}
    return build(scenario(rules=[rule]), source="s").rules[0]


def test_inject_appends_and_keeps_the_original_text():
    document = tools("A", "B")
    result = rule_from().act(S2C, document, "tools/list")
    assert isinstance(result, Edited)
    assert result.action == "inject"
    assert [t["description"] for t in document["result"]["tools"]] == [
        "A [INJECTED]",
        "B [INJECTED]",
    ]
    assert [(c.path, c.before, c.after) for c in result.changes] == [
        ("result.tools[0].description", "A", "A [INJECTED]"),
        ("result.tools[1].description", "B", "B [INJECTED]"),
    ]


def test_inject_can_prepend():
    document = tools("A")
    rule_from(position="prepend", text="[P] ").act(S2C, document, "tools/list")
    assert document["result"]["tools"][0]["description"] == "[P] A"


def test_replace_overwrites_and_records_both_sides():
    document = tools("A")
    rule = rule_from(action="replace", value="Z", text=None)
    result = rule.act(S2C, document, "tools/list")
    assert document["result"]["tools"][0]["description"] == "Z"
    assert result.action == "replace"
    assert [(c.before, c.after) for c in result.changes] == [("A", "Z")]


def test_a_replacement_value_is_never_shared_between_messages():
    """An object value from the file goes in as a copy each time, or a later step changing
    it in place would change the scenario itself."""
    rule = rule_from(action="replace", path="result.tools[0]", value={"k": "v"}, text=None)
    first, second = tools("A"), tools("B")
    result = rule.act(S2C, first, "tools/list")
    first["result"]["tools"][0]["k"] = "changed"
    rule.act(S2C, second, "tools/list")
    assert second["result"]["tools"][0] == {"k": "v"}
    assert result.changes[0].after == {"k": "v"}, "nor the record of the first"


def test_drop_drops():
    drop = {"name": "d", "match": {"direction": "server_to_client"}, "action": "drop"}
    rule = build(scenario(rules=[drop]), source="s").rules[0]
    assert rule.act(S2C, tools("A"), "tools/list") is Action.DROP


def test_another_method_is_not_this_rule_s_message():
    assert rule_from().act(S2C, tools("A"), "tools/call") is None


def test_another_direction_is_not_this_rule_s_message():
    assert rule_from().act(C2S, tools("A"), "tools/list") is None


def test_a_request_is_matched_by_its_own_method():
    rule = rule_from(
        match={"direction": "client_to_server", "method": "tools/call"},
        path="params.arguments.city",
        action="replace",
        value="Atlantis",
        text=None,
    )
    document = {"id": 4, "method": "tools/call", "params": {"arguments": {"city": "Bonn"}}}
    assert isinstance(rule.act(C2S, document, None), Edited)
    assert document["params"]["arguments"]["city"] == "Atlantis"


def test_a_path_that_is_not_there_is_a_step_without_effect_not_silence():
    result = rule_from().act(S2C, {"id": 1, "result": {"tools": []}}, "tools/list")
    assert result == NoEffect("inject", "path_not_found")


def test_inject_into_something_that_is_not_text_is_skipped_by_name():
    document = tools("A")
    document["result"]["tools"].append({"name": "x", "description": 5})
    result = rule_from().act(S2C, document, "tools/list")
    assert isinstance(result, Edited)
    assert result.skipped == (("result.tools[1].description", "not_a_string"),)

    only_numbers = {"id": 1, "result": {"tools": [{"description": 5}]}}
    assert rule_from().act(S2C, only_numbers, "tools/list") == NoEffect(
        "inject", "not_a_string", skipped=(("result.tools[0].description", "not_a_string"),)
    )


def test_two_rules_from_one_file_chain_in_file_order():
    second = {**INJECT, "name": "second", "text": " [SECOND]"}
    engine = Engine(build(scenario(rules=[INJECT, second]), source="s").rules)
    engine.decide(C2S, json.dumps({"id": 1, "method": "tools/list"}).encode())
    outcome = engine.decide(S2C, json.dumps(tools("A")).encode())
    replaced = json.loads(outcome.replacement)
    assert replaced["result"]["tools"][0]["description"] == "A [INJECTED] [SECOND]"


# -- statements ---------------------------------------------------------------------------


def test_a_statement_is_built_with_its_signals():
    (statement,) = build(scenario(observations=[STATEMENT]), source="s").statements
    assert statement.name == "hidden-comment"
    assert statement.method == "tools/list"
    assert statement.signals == (Signal.HIDDEN_COMMENT,)


def test_a_statement_may_name_a_signal_the_walk_never_applies():
    data = {**STATEMENT, "signals": ["imperative", "tool_name_duplicate", "base64_block"]}
    (statement,) = build(scenario(observations=[data]), source="s").statements
    assert statement.signals == (
        Signal.IMPERATIVE,
        Signal.TOOL_NAME_DUPLICATE,
        Signal.BASE64_BLOCK,
    )


def test_the_old_name_of_the_split_signal_is_an_unknown_signal():
    data = {**STATEMENT, "signals": ["tool_name_collision"]}
    assert "unknown signal 'tool_name_collision'" in refused(scenario(observations=[data]))


def test_a_statement_brings_no_matcher_of_its_own():
    """Named signals only: a regex or a literal in the list is an unknown signal,
    and the old key for the list is an unknown key, so nothing half-loads."""
    assert "unknown signal" in refused(
        scenario(observations=[{**STATEMENT, "signals": [{"regex": "ignore.*"}]}])
    )
    old = {key: value for key, value in STATEMENT.items() if key != "signals"}
    assert "unknown key 'patterns'" in refused(
        scenario(observations=[{**old, "patterns": ["hidden_comment"]}])
    )


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({"signals": []}, "observations[0].signals: empty"),
        ({"signals": "hidden_comment"}, "observations[0].signals: expected a list"),
        ({"signals": ["hiden_comment"]}, "unknown signal 'hiden_comment'"),
        ({"signals": ["hidden_comment", "hidden_comment"]}, "listed twice"),
        ({"path": "result["}, "observations[0].path: "),
        ({"match": {"direction": "client_to_server"}}, "what the server delivers"),
        ({"action": "inject"}, "observations[0]: unknown key 'action'"),
    ],
)
def test_a_wrong_statement_is_refused_with_where(change, fragment):
    assert fragment in refused(scenario(observations=[{**STATEMENT, **change}]))


def test_a_statement_may_leave_the_method_open():
    data = {key: value for key, value in STATEMENT.items() if key != "match"}
    (statement,) = build(scenario(observations=[data]), source="s").statements
    assert statement.method is None


# -- the two front ends -------------------------------------------------------------------


def test_a_scenario_is_named_by_its_name_or_else_by_its_file(tmp_path):
    """The name goes into every finding key, so it must not depend on where the file lies."""
    named = tmp_path / "anywhere.json"
    named.write_text(json.dumps({"version": 1, "name": "assessment-7"}))
    assert load(named).name == "assessment-7"
    unnamed = tmp_path / "quarterly-check.yaml"
    unnamed.write_text("version: 1\n")
    assert load(unnamed).name == "quarterly-check"


def test_json_and_yaml_read_into_the_same_scenario(tmp_path):
    data = scenario(rules=[INJECT], observations=[STATEMENT])
    as_json = tmp_path / "s.json"
    as_json.write_text(json.dumps(data))
    as_yaml = tmp_path / "s.yaml"
    as_yaml.write_text(json.dumps(data))  # JSON is YAML
    assert load(as_json).rules[0].name == load(as_yaml).rules[0].name == "poison"


def test_an_unknown_suffix_is_refused(tmp_path):
    other = tmp_path / "s.toml"
    other.write_text("")
    with pytest.raises(ScenarioError, match="suffix"):
        load(other)


def test_a_missing_file_is_refused_not_raised(tmp_path):
    with pytest.raises(ScenarioError, match="cannot read"):
        load(tmp_path / "absent.yaml")


def test_an_oversized_file_is_refused_before_it_is_parsed(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (MAX_FILE_BYTES + 1))
    with pytest.raises(ScenarioError, match="larger than"):
        load(big)


def test_duplicate_keys_are_refused_in_json(tmp_path):
    duplicated = tmp_path / "s.json"
    duplicated.write_text('{"version": 1, "version": 1}')
    with pytest.raises(ScenarioError, match="duplicate key 'version'"):
        load(duplicated)


def test_nan_is_refused_in_json(tmp_path):
    nan = tmp_path / "s.json"
    nan.write_text('{"version": NaN}')
    with pytest.raises(ScenarioError, match="NaN"):
        load(nan)


def test_duplicate_keys_are_refused_in_yaml():
    with pytest.raises(ScenarioError, match="duplicate key 'version'"):
        parse_yaml("version: 1\nversion: 1\n", source="s")


def test_yaml_aliases_are_refused():
    """An alias is how a few hundred bytes of YAML become gigabytes of memory."""
    with pytest.raises(ScenarioError, match="alias"):
        parse_yaml("a: &x [1, 2]\nb: *x\n", source="s")


@pytest.mark.parametrize("reader", [parse_json, parse_yaml])
def test_an_integer_of_5000_digits_is_refused_like_any_invalid_document(reader):
    digits = "9" * 5000
    text = '{"version": ' + digits + "}" if reader is parse_json else "version: " + digits
    with pytest.raises(ScenarioError, match="^s.json: ") as raised:
        reader(text, source="s.json")
    assert "9" * 50 not in str(raised.value) and len(str(raised.value).splitlines()) == 1


def test_a_scenario_file_with_an_integer_of_5000_digits_is_refused(tmp_path):
    path = tmp_path / "s.json"
    path.write_text('{"version": ' + "9" * 5000 + "}")
    with pytest.raises(ScenarioError, match="too many digits"):
        load(path)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("v: no", "no"),
        ("v: on", "on"),
        ("v: 1:30", "1:30"),
        ("v: 0o17", "0o17"),
        ("v: 2026-10-02", "2026-10-02"),
        ("v: true", True),
        ("v: null", None),
        ("v: 7", 7),
        ("v: -1.5", -1.5),
    ],
)
def test_yaml_reads_scalars_the_way_json_would_not_the_way_yaml_1_1_did(text, expected):
    """`no` is not false, `1:30` is not 90 and a date is not a datetime: a scenario value is
    a JSON value, and a YAML 1.1 surprise would be a payload nobody wrote."""
    assert parse_yaml(text, source="s") == {"v": expected}


def test_yaml_tags_that_make_non_json_values_are_refused():
    with pytest.raises(ScenarioError):
        build(parse_yaml("version: 1\nname: !!binary aGk=\n", source="s"), source="s")


def test_a_yaml_syntax_error_says_where():
    with pytest.raises(ScenarioError, match="line 3 column 1"):
        parse_yaml("version: 1\nrules: [\n", source="s")


def test_yaml_multiline_text_survives(fixtures):
    loaded = load(fixtures / "scenarios" / "tool-poisoning.yaml")
    (rule,) = loaded.rules
    assert rule.text.startswith("\n\n<!--")
    assert rule.text.endswith("-->")


def test_a_statement_cannot_ask_for_the_signal_only_the_inspector_sets():
    """A lone surrogate is no property of a text at a path, so the scenario is refused."""
    data = {**STATEMENT, "signals": ["lone_surrogate"]}
    message = refused(scenario(observations=[data]))
    assert "observations[0].signals[0]" in message
    assert "'lone_surrogate' cannot be asked for: only the inspector sets it" in message


@pytest.mark.parametrize(
    "spelling",
    ["0" + "7" * 5000, "!!int 0x" + "f" * 5000, "!!int 0b" + "1" * 5000, "!!int 1:2:3"],
    ids=["octal digits", "hexadecimal", "binary", "sexagesimal"],
)
def test_a_scenario_file_with_a_whole_number_in_another_base_names_the_line(tmp_path, spelling):
    path = tmp_path / "s.yaml"
    path.write_text("name: x\nversion: " + spelling + "\n")
    with pytest.raises(ScenarioError) as raised:
        load(path)
    message = str(raised.value)
    assert message.startswith(f"{path}: line 2: ") and "\n" not in message
    assert "7" * 50 not in message and "f" * 50 not in message


@pytest.mark.parametrize(
    "spelling", ["!!int 0o17", "!!int 1_000", "!!int 1:30", "!!int 0x1f", "!!int abc", "!!int 1.5"]
)
def test_yaml_whole_numbers_in_any_spelling_but_decimal_are_refused(spelling):
    with pytest.raises(ScenarioError, match="^s: line 1: not a whole number in decimal digits$"):
        parse_yaml("v: " + spelling, source="s")


@pytest.mark.parametrize(
    ("text", "expected"),
    [("00003600", 3600), ("09", 9), ("-007", -7), ("+08", 8), ("0", 0)],
)
def test_yaml_whole_numbers_are_decimal_and_leading_zeros_do_not_count(text, expected):
    assert parse_yaml("v: " + text, source="s") == {"v": expected}


def test_yaml_takes_a_whole_number_of_4300_digits_and_not_of_4301():
    assert parse_yaml("v: " + "9" * 4300, source="s") == {"v": int("9" * 4300)}
    with pytest.raises(ScenarioError, match="^s: line 1: a whole number of too many digits$"):
        parse_yaml("v: " + "9" * 4301, source="s")
    with pytest.raises(ScenarioError, match="too many digits"):
        parse_yaml("v: -" + "0" * 4301, source="s")


_TAGGED = [
    "!!bool x",
    "!!timestamp x",
    '!!float ""',
    "!!binary ***",
    "!!set {a}",
    "!!str 1",
    "!foo bar",
    "!<tag:yaml.org,2002:int> 1",
]


@pytest.mark.parametrize("tagged", _TAGGED)
def test_yaml_explicit_tags_are_refused_with_the_line(tagged):
    with pytest.raises(ScenarioError, match="^s: line 2: YAML tags are not allowed$"):
        parse_yaml("a: 1\nv: " + tagged + "\n", source="s")


@pytest.mark.parametrize("tagged", _TAGGED)
def test_a_scenario_file_with_an_explicit_tag_names_the_line(tmp_path, tagged):
    path = tmp_path / "s.yaml"
    path.write_text("name: x\nversion: " + tagged + "\n")
    with pytest.raises(ScenarioError, match=f"^{path}: line 2: YAML tags are not allowed$"):
        load(path)


def test_yaml_tags_are_refused_on_keys_in_collections_and_behind_a_tag_directive():
    for text in ["!!str a: 1", "v: [1, !!str 2]", "%TAG !e! tag:yaml.org,2002:\n---\nv: !e!int 1"]:
        with pytest.raises(ScenarioError, match="YAML tags are not allowed"):
            parse_yaml(text, source="s")


def test_a_tag_directive_that_rebinds_the_handle_is_refused_without_its_text():
    text = "%TAG !! tag:example.com,2000:\n---\na: 1\nv: !!int 1\n"
    with pytest.raises(ScenarioError, match="^s: line 1: YAML tags are not allowed$"):
        parse_yaml(text, source="s")


@pytest.mark.parametrize(
    "text",
    [
        "%TAG ! tag:yaml.org,2002:\n---\nv: !int 0x10\n",
        "%TAG !e! tag:example.com,2000:\n---\nv: !e!int 1\n",
        "%TAG !e! tag:example.com,2000:\n---\nv: 1\n",
    ],
)
def test_every_tag_directive_is_refused_with_the_same_message(text):
    with pytest.raises(ScenarioError, match="^s: line 1: YAML tags are not allowed$"):
        parse_yaml(text, source="s")


def test_a_yaml_directive_without_tags_is_read_as_before():
    assert parse_yaml("%YAML 1.2\n---\nv: 1\n", source="s") == {"v": 1}


def test_an_int_tag_without_a_directive_is_still_read():
    assert parse_yaml("v: !!int 12\n", source="s") == {"v": 12}


def test_a_yaml_file_without_tags_is_read_as_before():
    assert parse_yaml("v: [1, 'a', {b: null}]\n# !!x in a comment\nw: 'a !b'", source="s") == {
        "v": [1, "a", {"b": None}],
        "w": "a !b",
    }


@pytest.mark.parametrize("error", [KeyError, AttributeError, IndexError, TypeError])
def test_yaml_a_constructor_that_fails_on_its_text_is_refused_without_the_text(monkeypatch, error):
    yaml = pytest.importorskip("yaml")

    def fails(loader, node):
        raise error("secret" + "q" * 60)

    monkeypatch.setitem(_strict_loader(yaml).yaml_constructors, "tag:yaml.org,2002:int", fails)
    with pytest.raises(ScenarioError, match="^s: a value that cannot be read$"):
        parse_yaml("v: 12", source="s")
