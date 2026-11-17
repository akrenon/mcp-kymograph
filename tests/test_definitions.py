"""The definitions a run saw: a digest each, compared run against run, an observation and no more.

What a server can be made to do is driven: ``tests/fixtures/discovery_server.py`` through
``cli.main(["drive", ...])``, filed with ``store ingest`` and compared with ``store diff`` — a
changed description, a new and a removed tool, a list over several pages, a listing cut off by the
page limit or by a server that stops answering. Only what no server delivers is written down by
hand around ``test_store.recording``, each with its reason in the docstring: a ``list_changed``
with a second listing, a notification between two pages, a listing twice, a name twice in one
listing, a run filed before the tables, and the shapes the fixture has no switch for.
"""

import hashlib
import json
import os
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path

import pytest

from mcp_kymograph import cli
from mcp_kymograph.definitions import (
    NO_FIRST_PAGE,
    NOT_CAPTURED,
    NOT_RE_LISTED,
    RE_LISTED,
    UNREADABLE_REQUEST,
    Definition,
    Recorded,
    canonical,
    compare,
    digest,
)
from mcp_kymograph.driver import CURSOR_INVALID, MAX_PAGES, PAGE_LIMIT
from mcp_kymograph.masking import PLACEHOLDER
from mcp_kymograph.store import Store, StoreError
from test_store import finding, recording

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = FIXTURES / "discovery_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"

FIRST_TEXT = "ZEBRA-QUARTZ-0042"
OTHER_TEXT = "WALRUS-MARBLE-0077"
THIRD_TEXT = "OKAPI-TIMBER-0013"


def tool(name, description="returns what it was given", **more):
    return {"name": name, "description": description, "inputSchema": {"type": "object"}, **more}


def answer(seq, method, member, items, cursor=None):
    result = {member: items}
    if cursor is not None:
        result["nextCursor"] = cursor
    return {
        "seq": seq,
        "type": "message",
        "direction": "server_to_client",
        "responded_method": method,
        "truncated": False,
        "incomplete": False,
        "payload": {
            "encoding": "json",
            "data": {"jsonrpc": "2.0", "id": seq, "result": result},
            "redactions": [],
            "redaction_count": 0,
        },
        "parse": {"ok": True, "kind": "response", "method": None, "id": seq},
    }


def tools_answer(seq, tools, cursor=None):
    return answer(seq, "tools/list", "tools", tools, cursor)


def error_answer(seq, method="tools/list"):
    """The server answers a list request with a JSON-RPC error."""
    event = answer(seq, method, "tools", [])
    event["payload"]["data"] = {
        "jsonrpc": "2.0",
        "id": seq,
        "error": {"code": -32601, "message": "no such method"},
    }
    return event


def list_request(seq, method="tools/list", cursor=None):
    params = {} if cursor is None else {"cursor": cursor}
    return {
        "seq": seq,
        "type": "message",
        "direction": "client_to_server",
        "responded_method": None,
        "truncated": False,
        "incomplete": False,
        "payload": {
            "encoding": "json",
            "data": {"jsonrpc": "2.0", "id": seq, "method": method, "params": params},
            "redactions": [],
            "redaction_count": 0,
        },
        "parse": {"ok": True, "kind": "request", "method": method, "id": seq},
    }


def changed_notice(seq, kind="tools"):
    return {
        "seq": seq,
        "type": "message",
        "direction": "server_to_client",
        "responded_method": None,
        "truncated": False,
        "incomplete": False,
        "payload": {
            "encoding": "json",
            "data": {"jsonrpc": "2.0", "method": f"notifications/{kind}/list_changed"},
            "redactions": [],
            "redaction_count": 0,
        },
        "parse": {
            "ok": True,
            "kind": "notification",
            "method": f"notifications/{kind}/list_changed",
        },
    }


def run_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def filed(tmp_path, *recordings):
    """A store holding these recordings, and each one's run id."""
    store = Store.open(tmp_path / "findings.sqlite")
    for path in recordings:
        store.ingest(path)
    return store, [run_of(path) for path in recordings]


def observe(tmp_path, before, after):
    with filed(tmp_path, before, after)[0] as store:
        return store.definition_diff(run_of(before), run_of(after))


def tools_run(tmp_path, name, *messages, **options):
    return recording(tmp_path, [], name=name, extra=list(messages), **options)


def driven(tmp_path, tag, *server_args):
    """The recording of the discovery server driven with these flags, through a one-entry
    manifest: the store takes corpus runs only. The entry has one name whatever the flags."""
    work = tmp_path / tag
    work.mkdir()
    manifest = work / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "discovery",
                        "provenance": "reference",
                        "source": {"paths": [os.path.relpath(DISCOVERY, work)]},
                        "launch": {
                            "transport": "stdio",
                            "command": ["{python}", str(DISCOVERY), *server_args],
                        },
                        "scenarios": [os.path.relpath(ALL_SIGNALS, work)],
                    }
                ],
            }
        )
    )
    cli.main(
        ["drive", "-q", "--out-dir", str(work / "runs"), "--step-timeout", "2.0",
         "--manifest", str(manifest), "--entry", "discovery"]
    )  # fmt: skip
    (path,) = (work / "runs").glob("*/events.jsonl")
    return path


def store_diff(tmp_path, capsys, before, after, *flags):
    """Files both recordings with ``store ingest`` and compares them with ``store diff``: the
    JSON on stdout and the text on stderr."""
    database = str(tmp_path / "findings.sqlite")
    for path in (before, after):
        cli.main(["store", "ingest", "--store", database, str(path)])
    capsys.readouterr()
    cli.main(["store", "diff", *flags, "--store", database, run_of(before), run_of(after)])
    shown = capsys.readouterr()
    return json.loads(shown.out)["definitions"], shown.err


# -- driven: what a server shows ------------------------------------------------------------


def test_a_harmless_change_of_a_description_is_changed_and_names_the_field(tmp_path, capsys):
    before = driven(tmp_path, "before", "--tool-count", "2")
    after = driven(
        tmp_path, "after", "--tool-count", "2", "--tool-description", "Says it once more."
    )

    observed, _ = store_diff(tmp_path, capsys, before, after)

    kinds = observed["kinds"]["tool"]
    assert [(c["name"], c["fields"]) for c in kinds["changed"]] == [
        ("tool_0", ["description"]),
        ("tool_0_1", ["description"]),
    ]
    assert kinds["added"] == kinds["removed"] == []
    assert kinds["partial"] == {}


def test_a_new_and_a_removed_tool_are_found(tmp_path, capsys):
    before = driven(tmp_path, "before", "--tool-name", "old", "--leading-tool", "keep")
    after = driven(tmp_path, "after", "--tool-name", "fresh", "--leading-tool", "keep")

    observed, said = store_diff(tmp_path, capsys, before, after)

    kinds = observed["kinds"]["tool"]
    assert [e["name"] for e in kinds["added"]] == ["fresh"]
    assert [e["name"] for e in kinds["removed"]] == ["old"]
    assert kinds["changed"] == []
    assert kinds["unchanged"] == 1
    assert "definitions (tool): 1 added, 1 removed, 0 changed, 1 unchanged" in said
    assert "added fresh" in said and "removed old" in said


def test_the_same_list_over_several_pages_is_no_change(tmp_path, capsys):
    before = driven(tmp_path, "before", "--pages", "3")
    after = driven(tmp_path, "after", "--pages", "3")

    observed, _ = store_diff(tmp_path, capsys, before, after)

    kinds = observed["kinds"]["tool"]
    assert (kinds["added"], kinds["removed"], kinds["changed"]) == ([], [], [])
    assert kinds["unchanged"] == 3
    assert kinds["partial"] == {}


def test_all_pages_and_all_four_kinds_of_a_driven_run_are_read_and_keyed(tmp_path):
    path = driven(tmp_path, "run", "--pages", "2", "--offers", "tools,prompts,resources")
    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)

    assert held is not None
    assert sorted((d.kind, d.name) for d in held.definitions) == [
        ("prompt", "prompt_0"),
        ("prompt", "prompt_1"),
        ("resource", "test://r0"),
        ("resource", "test://r1"),
        ("resource_template", "test://t0/{id}"),
        ("resource_template", "test://t1/{id}"),
        ("tool", "tool_0"),
        ("tool", "tool_1"),
    ]
    assert [meta["pages"] for meta in held.listings["tool"]["listings"]] == [2]
    assert all(meta["complete"] for entry in held.listings.values() for meta in entry["listings"])


def test_a_listing_cut_off_by_the_page_limit_removes_nothing_and_says_partial(tmp_path, capsys):
    """A name the capped listing never reached is not gone, and one the capped listing lacks is
    not new: the far side was read whole, and says so."""
    whole = driven(tmp_path, "whole", "--leading-tool", "extra")
    capped = driven(tmp_path, "capped", "--pages", str(MAX_PAGES + 5))
    beyond = sorted(f"tool_{n}" for n in range(1, MAX_PAGES))

    observed, said = store_diff(tmp_path, capsys, whole, capped)

    kinds = observed["kinds"]["tool"]
    assert kinds["removed"] == []  # extra: the capped listing never said
    assert [e["name"] for e in kinds["added"]] == beyond
    assert kinds["unchanged"] == 1
    assert kinds["partial"] == {"after": {"reasons": [PAGE_LIMIT], "unreadable": 0}}
    assert f"definitions (tool): partial (after: {PAGE_LIMIT})" in said
    assert "removed extra" not in said

    observed, said = store_diff(tmp_path, capsys, capped, whole)

    kinds = observed["kinds"]["tool"]
    assert kinds["added"] == []  # extra: the capped listing never said
    assert [e["name"] for e in kinds["removed"]] == beyond
    assert kinds["partial"] == {"before": {"reasons": [PAGE_LIMIT], "unreadable": 0}}
    assert f"definitions (tool): partial (before: {PAGE_LIMIT})" in said
    assert "added extra" not in said


def test_a_listing_a_server_stopped_answering_is_partial_with_the_reason(tmp_path, capsys):
    whole = driven(tmp_path, "whole", "--pages", "3")
    cut = driven(tmp_path, "cut", "--pages", "3", "--answer-limit", "2")

    observed, said = store_diff(tmp_path, capsys, whole, cut)

    kinds = observed["kinds"]["tool"]
    assert kinds["removed"] == []
    assert kinds["unchanged"] == 2
    assert kinds["partial"]["after"]["reasons"] == ["no_answer"]
    assert "definitions (tool): partial (after: no_answer)" in said


def test_a_listing_never_answered_at_all_is_a_partial_one_not_an_empty_one(tmp_path, capsys):
    whole = driven(tmp_path, "whole", "--pages", "2")
    silent = driven(tmp_path, "silent", "--silent-after-handshake")

    observed, _ = store_diff(tmp_path, capsys, whole, silent)

    kinds = observed["kinds"]["tool"]
    assert kinds["removed"] == []
    assert kinds["partial"]["after"]["reasons"] == ["no_answer"]


def test_no_value_of_a_definition_is_in_the_output_of_store_diff_of_driven_runs(tmp_path, capsys):
    before = driven(tmp_path, "before", "--tool-description", FIRST_TEXT)
    after = driven(tmp_path, "after", "--tool-description", OTHER_TEXT)
    store_diff(tmp_path, capsys, before, after)

    for quiet in ([], ["-q"]):
        cli.main(
            ["store", "diff", *quiet, "--store", str(tmp_path / "findings.sqlite")]
            + [run_of(before), run_of(after)]
        )
        shown = capsys.readouterr()
        assert FIRST_TEXT not in shown.out + shown.err
        assert OTHER_TEXT not in shown.out + shown.err
    assert json.loads(shown.out)["definitions"]["kinds"]["tool"]["changed"][0]["fields"] == [
        "description"
    ]


# -- by hand: what no server delivers -------------------------------------------------------


def test_another_order_of_the_list_alone_is_no_change(tmp_path):
    """The fixture lists in one fixed order; the reverse order is only a recording written down."""
    items = [tool("a"), tool("b"), tool("c")]
    before = tools_run(tmp_path, "before", tools_answer(10, items))
    after = tools_run(tmp_path, "after", tools_answer(10, list(reversed(items))))

    kinds = observe(tmp_path, before, after)["kinds"]["tool"]

    assert (kinds["added"], kinds["removed"], kinds["changed"]) == ([], [], [])
    assert kinds["unchanged"] == 3


def test_the_same_list_on_one_page_and_over_two_is_no_change(tmp_path):
    """The fixture names its tools after the page, so no flags give the same list once on one
    page and once on two: the split is written down."""
    items = [tool("a"), tool("b")]
    one = tools_run(tmp_path, "one", tools_answer(10, items))
    two = tools_run(
        tmp_path, "two", tools_answer(10, items[:1], "page-1"), tools_answer(11, items[1:])
    )

    kinds = observe(tmp_path, one, two)["kinds"]["tool"]

    assert (kinds["added"], kinds["removed"], kinds["changed"]) == ([], [], [])
    assert kinds["unchanged"] == 2
    assert kinds["partial"] == {}


def test_a_change_to_several_fields_names_each_top_level_field_once(tmp_path):
    """The fixture changes the description only; a change of the schema and the title is a
    recording written down."""
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("echo")]))
    after = tools_run(
        tmp_path,
        "after",
        tools_answer(10, [tool("echo", "other", inputSchema={"type": "array"}, title="Echo")]),
    )

    changed = observe(tmp_path, before, after)["kinds"]["tool"]["changed"]

    assert changed[0]["fields"] == ["description", "inputSchema", "title"]


def test_the_order_of_a_definition_s_keys_does_not_move_its_digest():
    one = {"name": "x", "description": "d", "inputSchema": {"a": 1, "b": 2}}
    other = {"inputSchema": {"b": 2, "a": 1}, "description": "d", "name": "x"}

    assert digest(one) == digest(other)
    assert (
        digest(one)
        == hashlib.sha256(b'{"description":"d","inputSchema":{"a":1,"b":2},"name":"x"}').hexdigest()
    )
    assert canonical({"é": "ü"}) == '{"é":"ü"}'.encode()


def test_a_list_asked_twice_with_no_notification_between_is_not_doubled(tmp_path):
    """A client that asks twice is not a server that lists a tool twice, and no server makes the
    driver ask twice: two answers in one segment are written down. The last complete listing
    stands for the segment, and against a run that listed once nothing changed."""
    twice = tools_run(
        tmp_path,
        "twice",
        tools_answer(10, [tool("echo"), tool("sum")]),
        tools_answer(11, [tool("echo"), tool("sum")]),
    )
    once = tools_run(tmp_path, "once", tools_answer(10, [tool("echo"), tool("sum")]))
    store, [run, other] = filed(tmp_path, twice, once)
    with store:
        held = store.definitions_of(run)
        observed = store.definition_diff(run, other)

    assert held is not None
    assert not any(d.duplicate for d in held.definitions)
    kinds = observed["kinds"]["tool"]
    assert (kinds["added"], kinds["removed"], kinds["changed"]) == ([], [], [])
    assert kinds["unchanged"] == 2
    assert observed["within_run"]["before"] == {}


def test_of_two_listings_in_a_segment_the_last_complete_one_stands(tmp_path):
    """The last complete listing of a segment stands for it, a later cut one does not. The driver
    asks once per kind, so a second and a third request in one segment are written down."""
    cut = tools_answer(12, [tool("echo", "cut")], "page-1")
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("echo", "first")]),
        tools_answer(11, [tool("echo", "second")]),
        cut,
    )
    other = tools_run(tmp_path, "other", tools_answer(10, [tool("echo", "second")]))

    kinds = observe(tmp_path, path, other)["kinds"]["tool"]

    assert kinds["changed"] == [] and kinds["unchanged"] == 1
    assert kinds["partial"] == {}


def test_the_same_content_twice_against_once_is_a_duplicate_and_no_change(tmp_path):
    """A server that lists one tool twice with the same content: the fixture's names are unique."""
    twice = tools_run(tmp_path, "twice", tools_answer(10, [tool("echo"), tool("echo")]))
    once = tools_run(tmp_path, "once", tools_answer(10, [tool("echo")]))

    kinds = observe(tmp_path, twice, once)["kinds"]["tool"]

    assert kinds["changed"] == []
    assert kinds["unchanged"] == 1
    assert kinds["duplicates"] == [{"name": "echo", "side": "before", "before": 2, "after": 1}]


def test_a_whole_side_with_two_digests_against_a_partial_side_with_one_is_no_change(tmp_path):
    """The partial side did not read d2, which may sit on a page it never got. The driver's page
    limit cuts a listing, but not one that holds the same name twice: written down."""
    whole = tools_run(tmp_path, "whole", tools_answer(10, [tool("echo", "d1"), tool("echo", "d2")]))
    partial = tools_run(tmp_path, "partial", tools_answer(10, [tool("echo", "d1")], "page-1"))

    kinds = observe(tmp_path, whole, partial)["kinds"]["tool"]

    assert kinds["changed"] == []
    assert kinds["unchanged"] == 1
    assert list(kinds["partial"]) == ["after"]


def test_a_digest_only_the_partial_side_read_is_changed(tmp_path):
    """The partial side read d3, the whole side holds d1 only: both sides can explain the
    difference. Written down, as the fixture changes a whole listing and not a cut one."""
    whole = tools_run(tmp_path, "whole", tools_answer(10, [tool("echo", "d1")]))
    partial = tools_run(tmp_path, "partial", tools_answer(10, [tool("echo", "d3")], "page-1"))

    for before, after in ((whole, partial), (partial, whole)):
        kinds = observe(tmp_path, before, after)["kinds"]["tool"]
        assert [(c["name"], c["fields"]) for c in kinds["changed"]] == [("echo", ["description"])]


def test_two_partial_sides_that_each_read_a_name_once_with_another_digest_are_changed(tmp_path):
    """Both listings stop at a cursor never followed: no fixture server stops both runs so."""
    one = tools_run(tmp_path, "one", tools_answer(10, [tool("echo", "d1")], "page-1"))
    other = tools_run(tmp_path, "other", tools_answer(10, [tool("echo", "d3")], "page-1"))
    twice = tools_run(
        tmp_path, "twice", tools_answer(10, [tool("echo", "d1"), tool("echo", "d3")], "page-1")
    )

    kinds = observe(tmp_path, one, other)["kinds"]["tool"]
    assert [(c["name"], c["fields"]) for c in kinds["changed"]] == [("echo", ["description"])]

    kinds = observe(tmp_path, one, twice)["kinds"]["tool"]
    assert kinds["changed"] == [] and kinds["unchanged"] == 1


def test_a_field_one_side_drops_is_named_whole_against_partial(tmp_path):
    """The whole side has ``title`` on echo, the partial side read echo without it."""
    whole = tools_run(tmp_path, "whole", tools_answer(10, [tool("echo", title="Echo")]))
    partial = tools_run(tmp_path, "partial", tools_answer(10, [tool("echo")], "page-1"))

    for before, after in ((whole, partial), (partial, whole)):
        kinds = observe(tmp_path, before, after)["kinds"]["tool"]
        assert [(c["name"], c["fields"]) for c in kinds["changed"]] == [("echo", ["title"])]


def test_a_field_the_added_digest_lacks_is_named_for_one_against_two(tmp_path):
    """Both sides whole, ``{d1}`` against ``{d1, d2}`` where d2 has no ``title``."""
    one = tools_run(tmp_path, "one", tools_answer(10, [tool("echo", title="Echo")]))
    two = tools_run(tmp_path, "two", tools_answer(10, [tool("echo", title="Echo"), tool("echo")]))

    kinds = observe(tmp_path, one, two)["kinds"]["tool"]

    assert [(c["name"], c["fields"]) for c in kinds["changed"]] == [("echo", ["title"])]


def test_digests_that_cover_each_other_are_changed_with_no_field(tmp_path):
    """Every value occurs on the other side, only combined differently."""
    ab = [tool("echo", "a", title="x"), tool("echo", "b", title="y")]
    ba = [tool("echo", "a", title="y"), tool("echo", "b", title="x")]
    old = tools_run(tmp_path, "old", tools_answer(10, ab))
    new = tools_run(tmp_path, "new", tools_answer(10, ba))

    kinds = observe(tmp_path, old, new)["kinds"]["tool"]

    assert [(c["name"], c["fields"]) for c in kinds["changed"]] == [("echo", [])]


def test_a_name_twice_on_one_side_only_is_a_duplicate_against_a_partial_side(tmp_path, capsys):
    """before is partial without ``x``, after is whole with ``x`` twice."""
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("a")], "page-1"))
    after = tools_run(tmp_path, "after", tools_answer(10, [tool("a"), tool("x"), tool("x", "2")]))

    observed, said = store_diff(tmp_path, capsys, before, after)

    kinds = observed["kinds"]["tool"]
    assert kinds["duplicates"] == [{"name": "x", "side": "after", "before": 0, "after": 2}]
    assert "duplicate x [before: 0 (partial), after: 2]" in said


def test_the_terminal_names_three_occurrences_and_counts_duplicates_beyond_the_limit(
    tmp_path, capsys
):
    triple = [tool("x", str(n)) for n in range(3)]
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("a")]))
    after = tools_run(tmp_path, "after", tools_answer(10, triple))

    _, said = store_diff(tmp_path, capsys, before, after)
    assert "duplicate x [before: 0, after: 3]" in said
    assert "twice" not in said
    assert "added x [name listed more than once]" in said

    many = [tool(f"n{n:02}", str(i)) for n in range(21) for i in range(2)]
    other = tools_run(tmp_path, "other", tools_answer(10, many))

    _, said = store_diff(tmp_path, capsys, before, other)
    assert said.count("duplicate n") == 20
    assert "... and 1 more duplicates" in said


def test_a_duplicate_within_a_run_is_counted_from_and_to(tmp_path, capsys):
    """Needs a ``list_changed`` with a second listing, so it is written down by hand."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("echo")]),
        changed_notice(11),
        tools_answer(12, [tool("echo"), tool("x", "1"), tool("x", "2")]),
    )

    _, said = store_diff(tmp_path, capsys, path, path)

    assert "duplicate x [from: 0, to: 2]" in said
    assert "twice" not in said


def test_a_name_listed_twice_keeps_both_digests_and_is_marked(tmp_path):
    """A server that lists one name twice in one listing: the fixture's names are unique."""
    twins = [tool("twin", "first"), tool("twin", "second"), tool("alone")]
    store, [run] = filed(tmp_path, tools_run(tmp_path, "run", tools_answer(10, twins)))
    with store:
        held = store.definitions_of(run)
        after = tools_run(
            tmp_path, "after", tools_answer(10, [tool("twin", "first"), tool("alone")])
        )
        store.ingest(after)
        observed = store.definition_diff(run, run_of(after))

    assert held is not None
    twin = [d for d in held.definitions if d.name == "twin"]
    assert len(twin) == 2 and twin[0].digest != twin[1].digest
    assert all(d.duplicate for d in twin)
    assert not [d for d in held.definitions if d.name == "alone"][0].duplicate
    assert observed["kinds"]["tool"]["changed"] == [
        {"name": "twin", "duplicate": True, "fields": ["description"]}
    ]


def test_a_name_on_two_pages_of_one_listing_is_a_duplicate(tmp_path):
    """The same name on page one and page two is twice in one listing. The fixture names its
    tools after the page, so no flags give one name on two pages: the pages are written down."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("twin", "first")], "page-1"),
        tools_answer(11, [tool("twin", "second")]),
    )
    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)

    assert held is not None
    assert [d.duplicate for d in held.definitions] == [True, True]


def test_list_changed_in_the_middle_with_a_new_list_is_a_change_within_the_run(tmp_path):
    """No server of the fixtures sends ``list_changed`` and then lists again."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("echo"), tool("gone")]),
        changed_notice(11),
        changed_notice(12),
        tools_answer(13, [tool("echo", "reworded"), tool("new")]),
    )
    store, [run] = filed(tmp_path, path)
    with store:
        observed = store.definition_diff(run, run)

    pair = observed["within_run"]["before"]["tool"][0]
    assert (pair["from_segment"], pair["to_segment"]) == (0, 2)
    assert [e["name"] for e in pair["added"]] == ["new"]
    assert [e["name"] for e in pair["removed"]] == ["gone"]
    assert pair["changed"] == [{"name": "echo", "duplicate": False, "fields": ["description"]}]
    notified = observed["list_changed"]["before"]["tool"]
    assert (notified["count"], notified["first_seq"], notified["relisted"]) == (2, 11, True)


def test_a_notification_between_two_pages_does_not_split_the_listing(tmp_path):
    """The notification arrives while a listing is read page by page; the server decides when.
    The listing belongs to the segment where it began, and nothing began after the notice."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("a")], "page-1"),
        changed_notice(11),
        tools_answer(12, [tool("b")]),
    )
    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)
        observed = store.definition_diff(run, run)

    assert held is not None
    assert {d.segment for d in held.definitions} == {0}
    assert observed["within_run"]["before"] == {}
    notified = observed["list_changed"]["before"]["tool"]
    assert notified["relisted"] is False and notified["status"] == NOT_RE_LISTED


def test_a_listing_that_begins_after_that_notification_starts_the_next_segment(tmp_path):
    """A listing with a notice between its pages, then a second listing after it: the second
    starts the next segment. No fixture server sends a notification or is asked a second time, so
    the whole sequence is written down."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("a")], "page-1"),
        changed_notice(11),
        tools_answer(12, [tool("b")]),
        tools_answer(13, [tool("a"), tool("b"), tool("c")]),
    )
    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)
        observed = store.definition_diff(run, run)

    assert held is not None
    assert sorted((d.segment, d.name) for d in held.definitions) == [
        (0, "a"),
        (0, "b"),
        (1, "a"),
        (1, "b"),
        (1, "c"),
    ]
    pair = observed["within_run"]["before"]["tool"][0]
    assert [e["name"] for e in pair["added"]] == ["c"]
    assert observed["list_changed"]["before"]["tool"]["status"] == RE_LISTED


def test_list_changed_without_a_new_list_is_said_not_re_listed(tmp_path):
    """A notification that no request follows. No fixture server sends ``list_changed``, so the
    recording of a run that ends on it is written down."""
    path = tools_run(tmp_path, "run", tools_answer(10, [tool("echo")]), changed_notice(11))
    store, [run] = filed(tmp_path, path)
    with store:
        observed = store.definition_diff(run, run)

    assert observed["within_run"]["before"] == {}
    notified = observed["list_changed"]["before"]["tool"]
    assert notified["status"] == NOT_RE_LISTED == "list_changed, not re-listed"
    assert notified["first_seq"] == 11


def test_an_error_answer_to_the_list_after_the_notification_is_re_listed_and_partial(
    tmp_path, capsys
):
    """The server answers the request after ``list_changed`` with a JSON-RPC error. The fixture
    sends no notification, so the sequence is written down. The request began a listing: the run
    asked for the new list, and what came back is a partial listing, not a list from before."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("a"), tool("b")]),
        changed_notice(11),
        list_request(12),
        error_answer(13),
    )

    observed, said = store_diff(tmp_path, capsys, path, path)

    notified = observed["list_changed"]["before"]["tool"]
    assert notified["relisted"] is True and notified["status"] == RE_LISTED
    assert notified["partial"] == {"reasons": ["error_answer"], "unreadable": 1}
    pair = observed["within_run"]["before"]["tool"][0]
    assert pair["removed"] == [] and pair["partial"]["to"]["reasons"] == ["error_answer"]
    assert "not re-listed" not in said


def test_a_partial_listing_after_the_notification_is_re_listed_and_partial(tmp_path, capsys):
    """The one listing after the notification stops at a page whose cursor was never followed.
    The server said its list changed and the run asked again: re-listed, and partial, with
    nothing removed for what the pages it did read lack. A server of the fixtures sends no
    notification."""
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("a"), tool("b")]),
        changed_notice(11),
        tools_answer(12, [tool("a")], "page-1"),
    )

    observed, said = store_diff(tmp_path, capsys, path, path)

    notified = observed["list_changed"]["before"]["tool"]
    assert notified["status"] == RE_LISTED and notified["partial"]["reasons"] == ["unfinished"]
    pair = observed["within_run"]["before"]["tool"][0]
    assert pair["removed"] == []
    assert pair["partial"] == {"to": {"reasons": ["unfinished"], "unreadable": 0}}
    assert "not re-listed" not in said
    assert "within the before run: partial (to: unfinished)" in said


def test_a_truncated_page_is_partial_and_its_count_is_on_the_terminal(tmp_path, capsys):
    """The recorder cuts a page at its size limit; no switch of the fixture makes it so small."""
    cut = tools_answer(11, [tool("a")])
    cut["truncated"] = True
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("a"), tool("b")]))
    after = tools_run(tmp_path, "after", tools_answer(10, [tool("a")], "page-1"), cut)

    observed, said = store_diff(tmp_path, capsys, before, after)

    kinds = observed["kinds"]["tool"]
    assert kinds["removed"] == []
    assert kinds["partial"]["after"] == {"reasons": ["truncated"], "unreadable": 1}
    assert "after: truncated, 1 unreadable page(s)" in said


def test_a_cursor_that_cannot_be_sent_back_is_partial(tmp_path):
    """A ``nextCursor`` that is no string: the driver says so in a ``step_unanswered`` after the
    page. The fixture only ever offers strings."""
    unsent = tools_answer(10, [tool("a")], 7)
    reason = {
        "seq": 11,
        "type": "step_unanswered",
        "step": "tools/list",
        "pages": 1,
        "reason": CURSOR_INVALID,
    }
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("a"), tool("b")]))
    after = tools_run(tmp_path, "after", unsent, reason)

    kinds = observe(tmp_path, before, after)["kinds"]["tool"]

    assert kinds["removed"] == []
    assert kinds["partial"]["after"]["reasons"] == [CURSOR_INVALID]


def test_list_changed_of_prompts_and_resources_is_counted_per_kind(tmp_path):
    """The notifications of prompts and resources, one each, and none of tools. The fixture
    sends no notification of any kind, so they are written down."""
    path = tools_run(
        tmp_path,
        "run",
        answer(10, "prompts/list", "prompts", [{"name": "p"}]),
        changed_notice(11, "prompts"),
        changed_notice(12, "resources"),
    )
    store, [run] = filed(tmp_path, path)
    with store:
        notified = store.definition_diff(run, run)["list_changed"]["before"]

    assert sorted(notified) == ["prompt", "resource"]
    assert notified["prompt"]["first_seq"] == 11


def test_an_older_run_without_rows_is_not_captured_and_never_unchanged(tmp_path):
    """A run filed before the tables existed: its rows are deleted from a store."""
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("echo")]))
    after = tools_run(tmp_path, "after", tools_answer(10, [tool("echo", "other")]))
    store, [earlier, later] = filed(tmp_path, before, after)
    store.close()
    with closing(sqlite3.connect(tmp_path / "findings.sqlite")) as connection, connection:
        for table in ("definitions", "definition_runs"):
            connection.execute(f"DELETE FROM {table} WHERE run = ?", (earlier,))  # noqa: S608
    with Store.open(tmp_path / "findings.sqlite") as store:
        observed = store.definition_diff(earlier, later)
        assert store.definitions_of(earlier) is None
        assert store.definition_summary(earlier) is None

    assert observed["status"] == NOT_CAPTURED
    assert observed["captured"] == {"before": False, "after": True}
    assert observed["kinds"] == {}
    assert "unchanged" not in json.dumps(observed)


def test_a_store_made_before_the_tables_reads_not_captured_through_the_read_only_open(tmp_path):
    """A store of schema 13 made before the tables: they are dropped from one."""
    path = tools_run(tmp_path, "run", tools_answer(10, [tool("echo")]))
    store, [run] = filed(tmp_path, path)
    store.close()
    with closing(sqlite3.connect(tmp_path / "findings.sqlite")) as connection, connection:
        connection.execute("DROP TABLE definitions")
        connection.execute("DROP TABLE definition_runs")

    with Store.open_read_only(tmp_path / "findings.sqlite") as reading:
        assert reading.definitions_of(run) is None


def test_runs_of_two_entries_are_not_compared(tmp_path):
    """Two entries of the corpus. ``driven`` gives every run the entry name ``discovery`` whatever
    the flags, so the second entry name is only reached by a recording written down."""
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("echo")]), entry="srv")
    after = tools_run(tmp_path, "after", tools_answer(10, [tool("other")]), entry="srv2")

    observed = observe(tmp_path, before, after)

    assert observed["status"] == "different corpus entries"
    assert observed["kinds"] == {}


def test_a_kind_one_run_never_listed_is_not_read_as_removed(tmp_path):
    before = driven(tmp_path, "before", "--offers", "tools,prompts")
    after = driven(tmp_path, "after", "--offers", "tools")

    kinds = observe(tmp_path, before, after)["kinds"]

    assert kinds["prompt"] == {"state": "not listed in after"}
    assert kinds["tool"]["unchanged"] == 1


def test_an_item_without_a_name_and_a_page_that_cannot_be_read_are_counted(tmp_path):
    """A nameless item and a cut page: neither is something the fixture sends."""
    broken = tools_answer(11, [tool("fine")])
    broken["truncated"] = True
    path = tools_run(
        tmp_path,
        "run",
        tools_answer(10, [tool("fine"), {"description": "no name"}], "page-1"),
        broken,
    )
    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)

    assert held is not None
    assert held.listings["tool"]["listings"][0]["unkeyed"] == 1
    assert held.listings["tool"]["listings"][0]["unreadable"] == 1


def test_no_value_of_a_definition_is_in_the_output_of_store_diff(tmp_path, capsys):
    """The within-run part needs a ``list_changed`` with a second listing, so it is by hand."""
    before = tools_run(
        tmp_path,
        "before",
        tools_answer(10, [tool("echo", FIRST_TEXT, annotations={"hint": FIRST_TEXT})]),
        changed_notice(11),
        tools_answer(12, [tool("echo", OTHER_TEXT)]),
    )
    after = tools_run(tmp_path, "after", tools_answer(10, [tool("echo", THIRD_TEXT)]))
    store, [earlier, later] = filed(tmp_path, before, after)
    store.close()
    capsys.readouterr()

    for quiet in ([], ["-q"]):
        code = cli.main(
            ["store", "diff", *quiet, "--store", str(tmp_path / "findings.sqlite"), earlier, later]
        )
        shown = capsys.readouterr()
        assert code == 0
        assert FIRST_TEXT not in shown.out + shown.err
        assert OTHER_TEXT not in shown.out + shown.err
        assert THIRD_TEXT not in shown.out + shown.err
    emitted = json.loads(shown.out)
    assert emitted["definitions"]["kinds"]["tool"]["changed"][0]["fields"] == ["description"]
    assert emitted["definitions"]["within_run"]["before"]["tool"][0]["changed"][0]["fields"] == [
        "annotations",
        "description",
    ]


def test_store_ingest_says_what_it_saw_of_list_changed(tmp_path, capsys):
    """The driven run has no notification; the second run, written down, ends on one, which no
    fixture server sends."""
    path = driven(tmp_path, "run")
    cli.main(["store", "ingest", "--store", str(tmp_path / "findings.sqlite"), str(path)])
    said = capsys.readouterr().err
    assert "definitions: 1 tool" in said
    assert "list_changed" not in said

    notified = tools_run(tmp_path, "notified", tools_answer(10, [tool("echo")]), changed_notice(11))
    cli.main(["store", "ingest", "--store", str(tmp_path / "findings.sqlite"), str(notified)])
    said = capsys.readouterr().err

    assert "definitions: 1 tool" in said
    assert "tool list_changed x1, first at seq 11: list_changed, not re-listed" in said


def test_store_ingest_says_a_listing_was_partial(tmp_path, capsys):
    path = driven(tmp_path, "run", "--pages", str(MAX_PAGES + 2))

    cli.main(["store", "ingest", "--store", str(tmp_path / "findings.sqlite"), str(path)])

    assert f"tool: a partial listing ({PAGE_LIMIT})" in capsys.readouterr().err


def test_store_diff_of_a_run_not_captured_says_so(tmp_path, capsys):
    """A run filed before the tables existed: its rows are deleted from a store."""
    before = driven(tmp_path, "before")
    after = driven(tmp_path, "after")
    store, [earlier, later] = filed(tmp_path, before, after)
    store.close()
    with closing(sqlite3.connect(tmp_path / "findings.sqlite")) as connection, connection:
        connection.execute("DELETE FROM definitions WHERE run = ?", (earlier,))
        connection.execute("DELETE FROM definition_runs WHERE run = ?", (earlier,))
    capsys.readouterr()

    cli.main(["store", "diff", "--store", str(tmp_path / "findings.sqlite"), earlier, later])
    said = capsys.readouterr().err

    assert "not captured" in said
    assert "unchanged" not in said.split("definitions:")[1]


def test_a_store_with_the_definitions_table_of_an_earlier_state_is_refused(tmp_path, capsys):
    """A store made when ``definitions`` had no ``listing`` column: the table is put back to that
    shape by hand, as no version of the tool writes it any more."""
    before = tools_run(tmp_path, "before", tools_answer(10, [tool("echo")]))
    after = tools_run(tmp_path, "after", tools_answer(10, [tool("echo", "other")]))
    store, [earlier, later] = filed(tmp_path, before, after)
    store.close()
    database = tmp_path / "findings.sqlite"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TABLE definitions")
        connection.execute(
            "CREATE TABLE definitions (run TEXT NOT NULL, segment INTEGER NOT NULL,"
            " kind TEXT NOT NULL, name TEXT NOT NULL, digest TEXT NOT NULL,"
            " fields TEXT NOT NULL, duplicate INTEGER NOT NULL)"
        )
    third = tools_run(tmp_path, "third", tools_answer(10, [tool("sum")]))
    capsys.readouterr()

    for command in (
        ["store", "diff", "--store", str(database), earlier, later],
        ["store", "ingest", "--store", str(database), str(third)],
    ):
        code = cli.main(command)
        said = capsys.readouterr().err
        assert code == cli.EXIT_REFUSED == 2
        assert "table definitions comes from an earlier state of schema 13" in said
        assert "created anew" in said
        assert "Traceback" not in said and "OperationalError" not in said

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 2
    with Store.open_read_only(database) as reading, pytest.raises(StoreError, match="definitions"):
        reading.definitions_of(earlier)


def test_a_name_with_a_lone_surrogate_is_filed_with_u_fffd_in_its_place(tmp_path):
    """Chosen as for the announced server name: filed, the surrogate replaced by U+FFFD. Before
    definitions were kept such a run was filed, and a refusal would lose it whole, findings and
    all, for one character of a name. The digest is over the item as recorded, so two items whose
    names differ only in their surrogates keep two digests, and their one stored name is a
    duplicate in the listing. A field name and a reason with a surrogate are stored as JSON
    escapes and read back as they were. No fixture server sends a lone surrogate in a name."""
    odd = tool("x\ud800")
    other = tool("x\udc00")
    unanswered = {"seq": 11, "type": "step_unanswered", "step": "tools/list", "reason": "r\ud800"}
    path = recording(
        tmp_path,
        [finding(5)],
        extra=[tools_answer(10, [odd, other, {"name": "y", "f\ud800": 1}], "page-1"), unanswered],
    )
    assert "\\ud800" in path.read_text()

    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)
        found = store.findings_of(run)

    assert len(found) == 1
    assert held is not None
    named = {(d.name, d.digest, d.duplicate) for d in held.definitions}
    assert named == {
        ("x\N{REPLACEMENT CHARACTER}", digest(odd), True),
        ("x\N{REPLACEMENT CHARACTER}", digest(other), True),
        ("y", digest({"name": "y", "f\ud800": 1}), False),
    }
    assert digest(odd) != digest(other)
    assert set(next(d for d in held.definitions if d.name == "y").fields) == {"name", "f\ud800"}
    assert held.listings["tool"]["listings"][0]["reasons"] == ["r\ud800"]


class CountedFields(Mapping):
    """A definition's field digests that count every read of a field: each value looked up and
    each name handed out by iteration."""

    reads = 0

    def __init__(self, fields):
        self._fields = fields

    def __getitem__(self, name):
        CountedFields.reads += 1
        return self._fields[name]

    def __iter__(self):
        for name in self._fields:
            CountedFields.reads += 1
            yield name

    def __len__(self):
        return len(self._fields)


def reads_to_compare(count):
    """How many field reads comparing one name held ``count`` times on each side takes, every
    digest different, so that each field is looked at."""
    listings = {
        "tool": {
            "listings": [
                {"segment": 0, "pages": 1, "unkeyed": 0, "unreadable": 0, "complete": True,
                 "reasons": []}
            ],
            "list_changed": None,
        }
    }  # fmt: skip

    def side(tag):
        return Recorded(
            listings,
            [
                Definition(
                    "tool",
                    "x",
                    f"{tag}-{n}",
                    CountedFields({"name": "n", "description": f"{tag}-{n}", "inputSchema": "s"}),
                    duplicate=True,
                )
                for n in range(count)
            ],
        )

    before, after = side("old"), side("new")
    CountedFields.reads = 0
    changed = compare(before, after)["kinds"]["tool"]["changed"]
    assert changed == [{"name": "x", "duplicate": True, "fields": ["description"]}]
    return CountedFields.reads


def test_the_fields_of_a_name_held_many_times_are_compared_in_linear_time():
    """A server may list one name tens of thousands of times (a page of 1 MiB, up to the page
    limit of pages). Naming its changed fields once took time in the square of that number: per
    definition, a set of the other side's values built anew. A clock would make this test slow
    when it fails and flaky on a loaded machine, so it counts instead: every read of a field
    digest, by lookup or by iteration, whatever the comparison does with it. Twice the
    definitions must cost about twice the reads; the square would cost four times."""
    small, large = reads_to_compare(200), reads_to_compare(400)

    assert large <= 2.2 * small


def _as_list(event, *path):
    """The event with the string at ``path`` wrapped in a list: a value no recorder writes."""
    *outer, last = path
    for step in outer:
        event = event[step]
    event[last] = [event[last]]


def _paged_then_no_step():
    unanswered = {"seq": 11, "type": "step_unanswered", "step": "tools/list", "reason": "x"}
    events = [list_request(9), tools_answer(10, [tool("echo")], "page-1"), unanswered]
    _as_list(events[2], "step")
    return events, (["unfinished"], 1)


def _answer_with_no_method():
    events = [list_request(9), tools_answer(10, [tool("echo")])]
    _as_list(events[1], "responded_method")
    return events, (["unfinished"], 0)


def _request_with_no_method():
    events = [list_request(9), tools_answer(10, [tool("echo")])]
    _as_list(events[0], "parse", "method")
    return events, ([UNREADABLE_REQUEST], 1)


@pytest.mark.parametrize(
    "shape", [_paged_then_no_step, _answer_with_no_method, _request_with_no_method]
)
def test_a_method_or_step_that_is_a_list_matches_nothing_and_is_no_traceback(tmp_path, shape):
    """A damaged or foreign recording: the ``step`` of a ``step_unanswered``, the
    ``responded_method`` of an answer or the ``parse.method`` of a request is a list, which no
    recorder writes. Looked up as it was, a list raised TypeError before ``ingest`` could refuse
    anything. It names no kind now. The step says nothing, so the listing it would have ended
    is ``unfinished``; the answer answers no listing, so the request's listing is
    ``unfinished`` with nothing read; the request begins nothing, so its answer begins the
    listing, and as nothing says which list from which cursor that request asked for, the
    listing is partial (``unreadable_request``) though its one page offers no cursor."""
    events, (reasons, count) = shape()
    store, [run] = filed(tmp_path, tools_run(tmp_path, "run", *events))
    with store:
        held = store.definitions_of(run)

    assert held is not None
    (listing,) = held.listings["tool"]["listings"]
    assert listing["reasons"] == reasons
    assert len(held.definitions) == count


def test_a_notification_whose_method_is_a_list_is_not_counted(tmp_path):
    """The ``parse.method`` of a notification is a list: not a ``list_changed``, no traceback."""
    notice = changed_notice(11)
    _as_list(notice, "parse", "method")
    store, [run] = filed(
        tmp_path, tools_run(tmp_path, "run", tools_answer(10, [tool("a")]), notice)
    )
    with store:
        held = store.definitions_of(run)

    assert held is not None
    assert held.listings["tool"]["list_changed"] is None


#: Earlier shapes of the two tables, as an unreleased build wrote them: no version
#: of the tool writes them any more, so they are put back by hand.
EARLIER_SHAPES = {
    "definitions": "CREATE TABLE definitions (run TEXT NOT NULL, segment INTEGER NOT NULL,"
    " kind TEXT NOT NULL, name TEXT NOT NULL, digest TEXT NOT NULL, fields TEXT NOT NULL,"
    " duplicate INTEGER NOT NULL)",
    "definition_runs": "CREATE TABLE definition_runs (run TEXT PRIMARY KEY, notified TEXT)",
}


def test_a_store_made_before_the_tables_gets_both_when_opened_for_writing(tmp_path):
    """A store of schema 13 made before these tables: both tables are dropped from one. Opened for
    writing it gets them, files a new run with its definitions, and still says ``not captured``
    of the run filed before."""
    old = tools_run(tmp_path, "old", tools_answer(10, [tool("echo")]))
    store, [earlier] = filed(tmp_path, old)
    store.close()
    database = tmp_path / "findings.sqlite"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TABLE definitions")
        connection.execute("DROP TABLE definition_runs")
    new = tools_run(tmp_path, "new", tools_answer(10, [tool("echo"), tool("sum")]))

    with Store.open(database) as store:
        store.ingest(new)
        held = store.definitions_of(run_of(new))
        assert store.definitions_of(earlier) is None

    assert held is not None
    assert sorted(d.name for d in held.definitions) == ["echo", "sum"]
    with closing(sqlite3.connect(database)) as connection:
        for table, shape in (
            ("definition_runs", ("run", "listings")),
            ("definitions", ("run", "segment", "listing", "kind", "name", "digest", "fields",
                             "duplicate")),
        ):  # fmt: skip
            found = tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
            assert found == shape


@pytest.mark.parametrize("table", ["definition_runs", "definitions"])
@pytest.mark.parametrize("other_dropped", [False, True], ids=["both", "alone"])
def test_a_definition_table_of_another_shape_is_refused_for_writing_and_reading(
    tmp_path, table, other_dropped
):
    """Either table in an earlier shape, beside the other table or alone: ``Store.open`` refuses
    the store, and so does reading the definitions through the read-only open. A table of another
    shape alone is not a store made before the tables, and never reads as ``not captured``."""
    path = tools_run(tmp_path, "run", tools_answer(10, [tool("echo")]))
    store, [run] = filed(tmp_path, path)
    store.close()
    database = tmp_path / "findings.sqlite"
    (other,) = set(EARLIER_SHAPES) - {table}
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(f"DROP TABLE {table}")
        connection.execute(EARLIER_SHAPES[table])
        if other_dropped:
            connection.execute(f"DROP TABLE {other}")

    said = f"table {table} comes from an earlier state of schema 13"
    with pytest.raises(StoreError, match=said):
        Store.open(database)
    with Store.open_read_only(database) as reading, pytest.raises(StoreError, match=said):
        reading.definitions_of(run)


def _incomplete_page(event):
    event["incomplete"] = True


def _text_page(event):
    event["payload"]["encoding"] = "text"
    event["payload"]["data"] = '{"jsonrpc": "2.0", "result": {"tools": ['
    event["parse"]["ok"] = False


def _member_no_list(event):
    event["payload"]["data"]["result"]["tools"] = {"name": "echo"}


@pytest.mark.parametrize(
    ("spoil", "reason"),
    [(_incomplete_page, "incomplete"), (_text_page, "unreadable"), (_member_no_list, "unreadable")],
)
def test_a_page_that_cannot_be_read_gives_its_reason(tmp_path, spoil, reason):
    """The second page of a listing is marked incomplete by the recorder, is no JSON, or holds
    its tools in something other than a list. None of these is a page the fixture sends. The
    listing is partial for that reason, the page counted as unreadable, the first page kept."""
    second = tools_answer(11, [tool("b")])
    spoil(second)
    path = tools_run(tmp_path, "run", tools_answer(10, [tool("a")], "page-1"), second)
    store, [run] = filed(tmp_path, path)
    with store:
        held = store.definitions_of(run)

    assert held is not None
    (listing,) = held.listings["tool"]["listings"]
    assert listing["reasons"] == [reason]
    assert (listing["complete"], listing["pages"], listing["unreadable"]) == (False, 1, 1)
    assert [d.name for d in held.definitions] == ["a"]


#: A made-up key of the shape the masker knows, put together at run time so that no secret scan
#: reads it whole in the source.
SECRET = "sk-" + "live-" + "0123456789" + "0abcdef"


def test_ingest_keeps_the_recording_and_no_value_and_hashes_what_the_recorder_masked(tmp_path):
    """Driven, so that the recorder masks: the description carries a key the masker knows and a
    plain marker it does not. ``store ingest`` leaves the recording as it was, byte for byte;
    the database file holds the name, the field names and the digests, and neither the
    description nor the schema's text. The digests are over the item as the recording holds it,
    masked: never over the key the server sent."""
    described = f"{FIRST_TEXT} Use Bearer {SECRET} to authenticate"
    path = driven(tmp_path, "run", "--tool-description", described)
    recorded = path.read_bytes()
    assert SECRET.encode() not in recorded and FIRST_TEXT.encode() in recorded
    (item,) = next(
        event["payload"]["data"]["result"]["tools"]
        for event in map(json.loads, recorded.decode().splitlines())
        if event.get("responded_method") == "tools/list"
    )
    assert PLACEHOLDER in item["description"]

    database = tmp_path / "findings.sqlite"
    assert cli.main(["store", "ingest", "--store", str(database), str(path)]) == 0
    assert path.read_bytes() == recorded
    with Store.open_read_only(database) as store:
        held = store.definitions_of(run_of(path))

    assert held is not None
    (stored,) = held.definitions
    assert stored.digest == digest(item)
    assert stored.fields["description"] == digest(item["description"])
    sent = {**item, "description": described}
    assert stored.digest != digest(sent)
    assert stored.fields["description"] != digest(described)
    raw = database.read_bytes()
    for value in (FIRST_TEXT, SECRET, PLACEHOLDER, "Some text.", "to authenticate"):
        assert value.encode() not in raw
    for kept in ("tool_0", "description", "inputSchema", stored.digest):
        assert kept.encode() in raw


@pytest.mark.parametrize("notified", [False, True], ids=["plain", "list_changed"])
def test_a_request_whose_method_cannot_be_read_completes_no_listing_open_before_it(
    tmp_path, notified
):
    """A damaged recording: a listing's first page offers a cursor that is never followed and
    nothing says why; then (or after a ``list_changed``) a request whose method is a list, and an
    answer without a cursor. Counted as the open listing's next page, that answer made a half-read
    chain and a later list one complete listing: names were called removed and added, and the
    notification read as not re-listed. The unreadable request fails closed now: the open listing
    is partial for it, and so is the one its answer begins: against a whole run nothing is
    removed, ``b``, which the partial side did read, is added, and the run did list again after
    the notification. No recorder writes
    such a request, so it is written down."""
    unread = list_request(12)
    _as_list(unread, "parse", "method")
    path = tools_run(
        tmp_path,
        "run",
        list_request(9),
        tools_answer(10, [tool("a")], "page-1"),
        *([changed_notice(11)] if notified else []),
        unread,
        tools_answer(13, [tool("b")]),
    )
    whole = tools_run(tmp_path, "whole", tools_answer(10, [tool("a"), tool("x")]))
    store, [run, other] = filed(tmp_path, path, whole)
    with store:
        held = store.definitions_of(run)
        observed = store.definition_diff(other, run)

    assert held is not None
    listings = held.listings["tool"]["listings"]
    assert [meta["complete"] for meta in listings] == [False, False]
    assert all(UNREADABLE_REQUEST in meta["reasons"] for meta in listings)
    kinds = observed["kinds"]["tool"]
    assert kinds["removed"] == []
    assert [entry["name"] for entry in kinds["added"]] == ["b"]
    assert UNREADABLE_REQUEST in kinds["partial"]["after"]["reasons"]
    if notified:
        notice = observed["list_changed"]["after"]["tool"]
        assert notice["status"] == RE_LISTED
        assert notice["partial"]["reasons"] == [UNREADABLE_REQUEST]


@pytest.mark.parametrize("again", [False, True], ids=["alone", "then_listed_again"])
def test_a_request_for_a_later_page_after_an_unreadable_one_lifts_nothing(tmp_path, again):
    """A damaged recording: a listing's first page offers a cursor; a request whose method is a
    list; then a readable request that sends that cursor back, and its last page. The request for
    the later page finds no listing open, as the unreadable one closed it. Read as beginning a
    listing that lifted the unreadable request, it made the second page a whole listing, and
    ``a``, on the first page, read as removed against a whole run. Only a readable request for a
    first page lifts it: the later page begins a partial listing, and a first-page request after
    it (``then_listed_again``) begins one that is whole again. Written down: no recorder writes
    such a request."""
    unread = list_request(11)
    _as_list(unread, "parse", "method")
    listed_again = [list_request(14), tools_answer(15, [tool("a"), tool("b")])] if again else []
    path = tools_run(
        tmp_path,
        "run",
        list_request(9),
        tools_answer(10, [tool("a")], "page-1"),
        unread,
        list_request(12, cursor="page-1"),
        tools_answer(13, [tool("b")]),
        *listed_again,
    )
    whole = tools_run(tmp_path, "whole", tools_answer(10, [tool("a"), tool("b")]))
    store, [run, other] = filed(tmp_path, path, whole)
    with store:
        held = store.definitions_of(run)
        observed = store.definition_diff(other, run)

    assert held is not None
    listings = held.listings["tool"]["listings"]
    assert [meta["reasons"] for meta in listings[:2]] == [
        [UNREADABLE_REQUEST],
        [UNREADABLE_REQUEST, NO_FIRST_PAGE],
    ]
    kinds = observed["kinds"]["tool"]
    assert (kinds["added"], kinds["removed"]) == ([], [])
    if again:
        assert listings[2]["complete"] and listings[2]["reasons"] == []
        assert kinds["partial"] == {} and kinds["unchanged"] == 2
    else:
        assert len(listings) == 2 and not listings[1]["complete"]
        assert kinds["partial"]["after"]["reasons"] == [UNREADABLE_REQUEST, NO_FIRST_PAGE]


def _cursor_params(event, value):
    event["payload"]["data"]["params"] = value


@pytest.mark.parametrize(
    "params",
    [{"cursor": "page-1"}, {"cursor": 7}, "page-1", None],
    ids=["cursor", "cursor_no_string", "params_no_object", "params_null"],
)
def test_a_recording_that_starts_in_the_middle_of_a_chain_is_partial(tmp_path, params):
    """The first list request the recording holds sends a cursor back (or params that cannot be
    read): its first page was never seen. It began a listing that ended whole, so ``a``, which a
    first page would have held, read as removed. That listing is partial now, for
    ``no_first_page``. No recorder writes a chain without its first request: written down."""
    later = list_request(9)
    _cursor_params(later, params)
    path = tools_run(tmp_path, "run", later, tools_answer(10, [tool("b")]))
    whole = tools_run(tmp_path, "whole", tools_answer(10, [tool("a"), tool("b")]))
    store, [run, other] = filed(tmp_path, path, whole)
    with store:
        held = store.definitions_of(run)
        observed = store.definition_diff(other, run)

    assert held is not None
    (listing,) = held.listings["tool"]["listings"]
    assert (listing["complete"], listing["reasons"]) == (False, [NO_FIRST_PAGE])
    kinds = observed["kinds"]["tool"]
    assert kinds["removed"] == [] and kinds["unchanged"] == 1
