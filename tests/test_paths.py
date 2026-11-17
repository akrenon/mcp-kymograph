"""Field paths: the one syntax a recording, a rule and a statement all speak."""

import pytest

from mcp_kymograph.paths import PathSyntaxError, parse, resolve

TOOLS = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "tools": [
            {"name": "get_weather", "description": "Weather."},
            {"name": "send_mail"},
            {"name": "get.weather", "description": "Dotted."},
            "not a tool",
        ]
    },
}


def paths_of(path: str, document=TOOLS) -> list[str]:
    return [location.path for location in resolve(document, parse(path))]


def test_a_concrete_path_resolves_to_itself():
    assert paths_of("result.tools[0].description") == ["result.tools[0].description"]


def test_the_wildcard_reports_only_the_elements_that_have_the_field():
    """A tool without a description is not a location: inventing one is the rule's choice."""
    assert paths_of("result.tools[*].description") == [
        "result.tools[0].description",
        "result.tools[2].description",
    ]


def test_a_selector_resolves_to_the_concrete_index_a_recording_would_show():
    """Written as a name, reported as a position — the form an observation path has."""
    assert paths_of('result.tools[name="get.weather"].description') == [
        "result.tools[2].description"
    ]


def test_a_selector_compares_strings_exactly():
    assert paths_of('result.tools[name="GET_WEATHER"].description') == []


def test_a_missing_path_resolves_to_nothing_rather_than_raising():
    assert paths_of("result.prompts[0].description") == []
    assert paths_of("result.tools[9].description") == []
    assert paths_of("id.deeper") == []


def test_an_index_into_an_object_is_not_a_key_lookup():
    assert paths_of("result[0]") == []


def test_a_location_can_be_read_and_written():
    document = {"result": {"tools": [{"description": "a"}]}}
    (location,) = resolve(document, parse("result.tools[0].description"))
    assert location.value == "a"
    location.set("b")
    assert document == {"result": {"tools": [{"description": "b"}]}}


def test_a_bool_is_not_an_index():
    """JSON true is not 1 for addressing, whatever Python thinks."""
    assert paths_of('result.tools[name="x"]', {"result": {"tools": [{"name": True}]}}) == []


@pytest.mark.parametrize(
    ("path", "fragment"),
    [
        ("", "empty"),
        (".result", "position 0"),
        ("result.", "position 7"),
        ("result..tools", "position 7"),
        ("result.tools[", "unclosed"),
        ("result.tools[]", "position 13"),
        ("result.tools[-1]", "position 13"),
        ("result.tools[01]", "leading zero"),
        ("[0].x", "must start with a key"),
        ("result.tools[name=get]", "quoted"),
        ('result.tools[name="a"', "unclosed"),
        ("result.tools[0]x", "position 15"),
        ("result.tools[0x]", "position 14"),
        ("result.tools[*x]", "position 14"),
        ('result.tools[name="a"x]', "position 21"),
        ("result.to ols", "position 9"),
        ("result/tools", "position 6"),
        ('result.tools[name="\\q"]', "string"),
    ],
)
def test_a_malformed_path_is_refused_with_where(path, fragment):
    with pytest.raises(PathSyntaxError) as raised:
        parse(path)
    assert fragment in str(raised.value)


def test_keys_that_mcp_actually_uses_are_addressable():
    for path in (
        "params._meta.progressToken",
        "result.tools[0].inputSchema.$defs.x-y.description",
        "result.serverInfo.instructions",
    ):
        parse(path)


def test_an_overlong_path_is_refused():
    with pytest.raises(PathSyntaxError, match="longer"):
        parse("a" + ".a" * 400)


# -- locators: the same place, by name ------------------------------------------------------


def locators_of(path: str, document=TOOLS) -> list[str]:
    return [location.locator for location in resolve(document, parse(path))]


def test_a_list_step_becomes_the_element_s_name_whatever_the_author_wrote():
    """``[*]``, an index and a selector all name the same element the same way."""
    expected = ['result.tools[name="get_weather"].description']
    assert locators_of("result.tools[0].description") == expected
    assert locators_of('result.tools[name="get_weather"].description') == expected
    assert locators_of("result.tools[*].description") == [
        *expected,
        'result.tools[name="get.weather"].description',
    ]


def test_an_element_without_a_name_loses_its_position_and_keeps_nothing_else():
    document = {"result": {"content": [{"type": "text", "text": "a"}, {"text": "b"}]}}
    assert locators_of("result.content[*].text", document) == [
        "result.content[].text",
        "result.content[].text",
    ]


def test_a_path_without_lists_is_its_own_locator():
    document = {"result": {"instructions": "Be brief."}}
    assert locators_of("result.instructions", document) == ["result.instructions"]


def test_the_same_rule_names_prompts_resource_contents_and_templates():
    """Not a rule for tools: the walk asks every element the same question."""
    prompts = {"result": {"prompts": [{"name": "review", "arguments": [{"name": "code"}]}]}}
    assert locators_of("result.prompts[*].arguments[*]", prompts) == [
        'result.prompts[name="review"].arguments[name="code"]'
    ]
    contents = {"result": {"contents": [{"uri": "file:///a.md", "text": "x"}]}}
    assert locators_of("result.contents[*].text", contents) == [
        'result.contents[uri="file:///a.md"].text'
    ]
    templates = {"result": {"resourceTemplates": [{"uriTemplate": "t://{id}", "title": "T"}]}}
    assert locators_of("result.resourceTemplates[*].title", templates) == [
        'result.resourceTemplates[uriTemplate="t://{id}"].title'
    ]


def test_two_resources_with_one_display_name_are_two_resources():
    """A resource's ``name`` may repeat, its ``uri`` may not. Asked for ``name``
    first, as the walk once did, these two would be one place."""
    document = {
        "result": {
            "resources": [
                {"uri": "file:///a/README.md", "name": "README", "description": "x"},
                {"uri": "file:///b/README.md", "name": "README", "description": "y"},
            ]
        }
    }
    assert locators_of("result.resources[*].description", document) == [
        'result.resources[uri="file:///a/README.md"].description',
        'result.resources[uri="file:///b/README.md"].description',
    ]


def test_a_resource_without_its_uri_has_no_identity_rather_than_a_borrowed_one():
    """No fallback to the display name: a missing protocol identity is ``[]``, as before."""
    document = {"result": {"resources": [{"name": "README", "description": "x"}]}}
    assert locators_of("result.resources[*].description", document) == [
        "result.resources[].description"
    ]


def test_tool_and_prompt_locators_are_what_they_were():
    """Regression: the table changed how the field is chosen, not what tools, prompts and
    prompt arguments are called — those findings keep their keys."""
    document = {
        "result": {
            "tools": [{"name": "search", "uri": "x://ignored", "description": "d"}],
            "prompts": [{"name": "review", "arguments": [{"name": "code", "description": "c"}]}],
        }
    }
    assert locators_of("result.tools[*].description", document) == [
        'result.tools[name="search"].description'
    ]
    assert locators_of("result.prompts[*].arguments[*].description", document) == [
        'result.prompts[name="review"].arguments[name="code"].description'
    ]


def test_only_a_string_is_an_identity():
    document = {"result": {"tools": [{"name": 7, "title": "a"}, {"name": None, "title": "b"}]}}
    assert locators_of("result.tools[*].title", document) == [
        "result.tools[].title",
        "result.tools[].title",
    ]


def test_a_list_the_protocol_gives_no_identity_is_never_guessed_at():
    """A ``name`` on an element is not its identity unless its type says so."""
    document = {"result": {"items": [{"name": "n", "uri": "u://1", "text": "a"}]}}
    assert locators_of("result.items[*].text", document) == ["result.items[].text"]


def test_a_list_with_a_protocol_name_elsewhere_in_the_message_is_not_that_type():
    """The type is where the list sits, not its last key: a ``tools`` list inside a tool's
    structured output is data, not the tools of a ``tools/list`` answer."""
    document = {"result": {"structuredContent": {"tools": [{"name": "x", "note": "n"}]}}}
    assert locators_of("result.structuredContent.tools[*].note", document) == [
        "result.structuredContent.tools[].note"
    ]


def test_nested_lists_are_located_level_by_level():
    document = {
        "result": {
            "tools": [
                {
                    "name": "t",
                    "inputSchema": {"properties": {"mode": {"enum": ["fast", "slow"]}}},
                }
            ]
        }
    }
    assert locators_of("result.tools[*].inputSchema.properties.mode.enum[*]", document) == [
        'result.tools[name="t"].inputSchema.properties.mode.enum[]',
        'result.tools[name="t"].inputSchema.properties.mode.enum[]',
    ]


def test_a_name_is_escaped_so_a_lookalike_shows_and_the_selector_reads_back():
    """A Cyrillic letter or a quote in a name: visible in the locator, and the selector parses
    back to the element it came from."""
    document = {"result": {"tools": [{"name": 're\u0430d_"file"', "title": "x"}]}}
    (locator,) = locators_of("result.tools[*].title", document)
    assert locator == 'result.tools[name="re\\u0430d_\\"file\\""].title'
    assert [loc.path for loc in resolve(document, parse(locator))] == ["result.tools[0].title"]


def test_a_position_never_reaches_the_locator():
    """A tool put in front moves every position and no locator."""
    first = {"result": {"tools": [{"name": "a", "description": "x"}]}}
    second = {"result": {"tools": [{"name": "new", "description": "y"}, *first["result"]["tools"]]}}
    assert paths_of("result.tools[*].description", first) == ["result.tools[0].description"]
    assert locators_of("result.tools[*].description", first) == [
        'result.tools[name="a"].description'
    ]
    assert locators_of("result.tools[*].description", second)[1] == (
        'result.tools[name="a"].description'
    )
