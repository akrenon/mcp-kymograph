"""The report over both stages: rows from definitions and ``result.json``, as Markdown and HTML.

What it must hold: a server has one row per stage, in the order of the definitions; a skipped
stage shows its reason and no run; a stage that is active and has no run is ``error`` with
``no_run``; of the runs of a stage (this server, this stage) the last two by directory name are
taken, and the double run is ``same``, ``different``, ``single`` or ``none``; a result that cannot
be read or is not of ``result_version`` 1 is a ``RunnerError`` with its path; each column has its
value; the excerpt of a signal is escaped in both formats and shown only with ``excerpts``; the
HTML has no script, no link out and no event attribute; ``bench.py report`` writes both files and
refuses a place inside the repository. No docker is needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from test_bench_stage_b import _active, _write_defs, bench

report = bench._sibling("report")

HOSTILE = '<script>alert("x") & more</script> a|b'


def _server(name: str = "toy", **over: Any) -> Any:
    fields: dict[str, Any] = {
        "name": name,
        "provenance": "p",
        "archived": False,
        "role": None,
        "package": {"version": "1"},
        "source": {},
        "image_context": Path("."),
        "image_base": "b",
        "args": (),
        "env": (),
        "stage_a_status": "active",
        "stage_a_reason": None,
        "stage_b": bench.StageB(status="active", reason=None),
    }
    fields.update(over)
    return bench.Server(**fields)


def _result(
    stage: str = "A",
    server: str = "toy",
    value: str = "signal",
    causes: tuple[str, ...] = (),
    signals: list[tuple[str, str, str | None]] | None = None,
    canary: str = "missing",
    network: str = "none",
    **over: Any,
) -> dict[str, Any]:
    wanted = signals if signals is not None else [("whitespace_padding", "result.tools[0]", "ex")]
    result: dict[str, Any] = {
        "result_version": 1,
        "server": server,
        "stage": stage,
        "transport": "stdio",
        "state": "complete",
        "causes": [],
        "outcome": {"value": value, "causes": list(causes)},
        "signals": [
            {"signal": s, "path": p, "surface": "description", "excerpt": e} for s, p, e in wanted
        ],
        "isolation": {"name": "runc", "network": network},
    }
    if stage == "B":
        result["canary"] = {"placeholder": "x", "result": canary, "found": []}
    result.update(over)
    return result


def _put(root: Path, run: str, result: dict[str, Any], server: str = "toy") -> Path:
    directory = root / server / run
    directory.mkdir(parents=True)
    (directory / "result.json").write_text(json.dumps(result), encoding="utf-8")
    return directory


def _rows(tmp_path: Path, *servers: Any) -> list[Any]:
    definitions = {server.name: server for server in servers or (_server(),)}
    return report.collect(definitions, [tmp_path])


# -- collecting ------------------------------------------------------------------------------


def test_a_server_has_a_row_for_each_stage_in_the_order_of_the_definitions(tmp_path):
    _put(tmp_path, "r1", _result("A"))
    _put(tmp_path, "r1b", _result("B"))
    rows = _rows(tmp_path, _server("zeta"), _server("toy"))
    assert [(row.server, row.stage) for row in rows] == [
        ("zeta", "A"), ("zeta", "B"), ("toy", "A"), ("toy", "B")
    ]  # fmt: skip


def test_a_skipped_stage_has_its_reason_and_no_run(tmp_path):
    _put(tmp_path, "r1", _result("A"))
    server = _server(stage_a_status="skipped", stage_a_reason="needs a key", stage_b=None)
    a, b = _rows(tmp_path, server)
    assert (a.outcome["value"], a.reason) == ("skipped", "needs a key")
    assert (a.runs, a.double_run) == (0, "none")
    assert (b.outcome["value"], b.runs) == ("skipped", 0)
    assert b.reason


def test_a_skipped_stage_b_has_the_reason_of_the_definition(tmp_path):
    server = _server(stage_b=bench.StageB(status="skipped", reason="no fixture fits"))
    assert _rows(tmp_path, server)[1].reason == "no fixture fits"


def test_an_active_stage_without_a_run_is_an_error_with_no_run(tmp_path):
    a, b = _rows(tmp_path)
    for row in (a, b):
        assert row.outcome == {"value": "error", "causes": ["no_run"]}
        assert (row.runs, row.double_run) == (0, "none")


def test_only_the_results_of_this_server_and_this_stage_count(tmp_path):
    _put(tmp_path, "r1", _result("A", value="no_signal", signals=[]))
    _put(tmp_path, "r2", _result("B"))
    _put(tmp_path, "r3", _result("A", server="other"))
    a, b = _rows(tmp_path)
    assert (a.runs, a.outcome["value"]) == (1, "no_signal")
    assert (b.runs, b.outcome["value"]) == (1, "signal")


def test_the_last_two_runs_by_directory_name_are_chosen(tmp_path):
    for name, value in (("r3", "no_signal"), ("r1", "error"), ("r2", "error"), ("r4", "signal")):
        _put(tmp_path, name, _result("A", value=value, signals=[]))
    row = _rows(tmp_path)[0]
    assert (row.runs, row.outcome["value"]) == (2, "signal")
    # only r3 and r4 differ; had r1 or r2 been taken the row would be `same` or show `error`
    assert row.double_run == "different"


def test_two_runs_of_one_second_are_ordered_by_their_start_not_by_their_name(tmp_path):
    # The name is the second plus a random ending: "r-ffff" sorts after "r-0000" whatever ran first.
    early, late = "2026-10-17T05:16:21.100000Z", "2026-10-17T05:16:21.900000Z"
    first = _result("A", value="no_signal", signals=[], started_utc=early)
    last = _result("A", value="signal", signals=[], started_utc=late)
    _put(tmp_path, "r-ffff", first)
    _put(tmp_path, "r-0000", last)
    row = _rows(tmp_path)[0]
    assert (row.runs, row.outcome["value"]) == (2, "signal")  # r-0000 began last


def test_a_result_without_a_start_comes_before_all_that_have_one(tmp_path):
    _put(tmp_path, "r9", _result("A", value="error", signals=[]))
    early, late = "2026-10-17T05:16:21.100000Z", "2026-10-17T05:16:21.200000Z"
    _put(tmp_path, "r1", _result("A", value="no_signal", signals=[], started_utc=early))
    _put(tmp_path, "r2", _result("A", value="signal", signals=[], started_utc=late))
    row = _rows(tmp_path)[0]
    assert (row.runs, row.outcome["value"], row.double_run) == (2, "signal", "different")
    assert report.run_order("r9", {}) < report.run_order("r1", {"started_utc": early})
    assert report.run_order("r9", {"started_utc": 5}) == ("", "r9")


def test_a_result_that_was_retried_is_not_a_run(tmp_path):
    _put(tmp_path, "r1", _result("B", value="error", causes=("server_failed",), retried=True))
    _put(tmp_path, "r2", _result("B"))
    _put(tmp_path, "r3", _result("B", retried=True))
    row = _rows(tmp_path)[1]
    assert (row.runs, row.double_run, row.outcome["value"]) == (1, "single", "signal")
    only = tmp_path / "only"
    _put(only, "r1", _result("B", retried=True))
    assert _rows(only)[1].outcome == {"value": "error", "causes": ["no_run"]}


def test_two_results_that_are_not_retried_are_still_compared(tmp_path):
    _put(tmp_path, "r1", _result("B", retried=False))
    _put(tmp_path, "r2", _result("B"))
    assert _rows(tmp_path)[1].double_run == "same"


def test_runs_under_several_roots_are_taken_together(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    _put(first, "r1", _result("A"))
    _put(second, "r2", _result("A"))
    row = report.collect({"toy": _server()}, [first, second])[0]
    assert (row.runs, row.double_run) == (2, "same")


def test_the_double_run_is_same_for_equal_runs(tmp_path):
    _put(tmp_path, "r1", _result("B", canary="delivered"))
    _put(tmp_path, "r2", _result("B", canary="delivered", state="other"))
    assert _rows(tmp_path)[1].double_run == "same"


@pytest.mark.parametrize(
    "second",
    [
        {"value": "no_signal"},
        {"causes": ("c",), "value": "error"},
        {"signals": [("whitespace_padding", "result.tools[1]", "ex")]},
        {"signals": [("zero_width", "result.tools[0]", "ex")]},
        {"canary": "delivered"},
    ],
    ids=["value", "causes", "path", "signal", "canary"],
)
def test_the_double_run_is_different_where_one_of_the_compared_parts_differs(tmp_path, second):
    _put(tmp_path, "r1", _result("B"))
    _put(tmp_path, "r2", _result("B", **second))
    assert _rows(tmp_path)[1].double_run == "different"


def test_the_double_run_ignores_what_it_does_not_compare(tmp_path):
    _put(tmp_path, "r1", _result("A", signals=[("s", "p", "one")]))
    _put(tmp_path, "r2", _result("A", signals=[("s", "p", "two")]))
    assert _rows(tmp_path)[0].double_run == "same"


def test_one_run_is_single(tmp_path):
    _put(tmp_path, "r1", _result("A"))
    row = _rows(tmp_path)[0]
    assert (row.runs, row.double_run) == (1, "single")


def test_the_row_shows_the_last_run(tmp_path):
    _put(tmp_path, "r1", _result("A", value="no_signal", signals=[]))
    _put(tmp_path, "r2", _result("A", value="signal", transport="streamable-http"))
    row = _rows(tmp_path)[0]
    assert row.outcome["value"] == "signal"
    assert row.transport == "stdio"
    assert [item["path"] for item in row.signals] == ["result.tools[0]"]


@pytest.mark.parametrize(
    "text", ["{", "[]", "", '{"result_version": 2}', '{"result_version": true}']
)
def test_a_result_that_cannot_be_read_or_is_not_version_1_is_refused_with_its_path(tmp_path, text):
    directory = _put(tmp_path, "r1", _result("A"))
    (directory / "result.json").write_text(text, encoding="utf-8")
    with pytest.raises(bench.RunnerError, match=re.escape(str(directory / "result.json"))):
        _rows(tmp_path)


def test_a_result_nested_too_deeply_is_refused_with_its_path_not_a_crash(tmp_path):
    directory = _put(tmp_path, "r1", _result("A"))
    (directory / "result.json").write_text("[" * 100_000, encoding="utf-8")
    with pytest.raises(
        bench.RunnerError, match=re.escape(f"{directory / 'result.json'}: cannot be read")
    ):
        report._read(directory / "result.json")
    with pytest.raises(bench.RunnerError, match=re.escape(str(directory / "result.json"))):
        _rows(tmp_path)


def test_a_result_version_that_is_true_is_not_1_even_with_every_field(tmp_path):
    """``True == 1`` in Python: a whole result with ``result_version: true`` is refused too."""
    directory = _put(tmp_path, "r1", {**_result("A"), "result_version": True})
    with pytest.raises(bench.RunnerError, match=re.escape(str(directory / "result.json"))):
        _rows(tmp_path)


def test_a_value_of_ours_with_a_backslash_before_a_pipe_stays_in_its_cell():
    """A pipe is escaped where an odd number of backslashes stands before it; a backslash of
    the value must not make that number even."""
    for value in ("a\\|b", "a\\\\|b", "a|b"):
        cell = report._cell(value)
        assert re.search(r"(?<!\\)(?:\\\\)*\|", cell) is None, cell


def test_a_result_without_the_fields_the_report_reads_is_refused(tmp_path):
    directory = _put(tmp_path, "r1", _result("A"))
    (directory / "result.json").write_text(json.dumps({"result_version": 1}), encoding="utf-8")
    with pytest.raises(bench.RunnerError, match="result.json"):
        _rows(tmp_path)


def test_a_result_without_a_known_isolation_is_refused(tmp_path):
    _put(tmp_path, "r1", _result("A", isolation={"name": "runc", "network": "host"}))
    with pytest.raises(bench.RunnerError, match="isolation"):
        _rows(tmp_path)


# -- the columns -----------------------------------------------------------------------------


def _cells(table: str, line: int) -> list[str]:
    """The cells of a row of the Markdown table (0: head, 2: the first row)."""
    text = table.splitlines()[line]
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", text)[1:-1]]


def _table(tmp_path: Path, excerpts: bool = False) -> str:
    return report.markdown(_rows(tmp_path), excerpts)


def test_the_columns_are_named_in_the_order_of_the_design(tmp_path):
    head = _cells(_table(tmp_path), 0)
    assert head == [
        "Server", "Stage", "Transport", "Isolation", "State", "Outcome",
        "Signals (place)", "Canary", "Double run", "skipped (reason)",
    ]  # fmt: skip


def test_the_server_stage_and_transport_columns(tmp_path):
    _put(tmp_path, "r1", _result("A"))
    cells = _cells(_table(tmp_path), 2)
    assert cells[:3] == ["toy", "A", "stdio"]
    assert _cells(_table(tmp_path), 3)[:2] == ["toy", "B"]


def test_the_isolation_column_is_the_wording_of_the_design_and_the_name(tmp_path):
    _put(tmp_path, "r1", _result("A", network="none"))
    _put(tmp_path, "r1b", _result("B", network="internal"))
    table = _table(tmp_path)
    assert _cells(table, 2)[3] == "docker, `--network none` (runc)"
    assert _cells(table, 3)[3] == "docker, internal network (runc)"


def test_the_state_column(tmp_path):
    _put(tmp_path, "r1", _result("A", state="incomplete"))
    assert _cells(_table(tmp_path), 2)[4] == "incomplete"


def test_the_outcome_column_has_the_value_and_the_causes(tmp_path):
    _put(tmp_path, "r1", _result("A", value="error", causes=("c1", "c2"), signals=[]))
    _put(tmp_path, "r1b", _result("B", value="signal"))
    table = _table(tmp_path)
    assert _cells(table, 2)[5] == "error (c1, c2)"
    assert _cells(table, 3)[5] == "signal"


def test_the_signals_column_has_the_signal_its_surface_and_its_place(tmp_path):
    _put(tmp_path, "r1", _result("A", signals=[("s1", "p1", None), ("s2", "p2", None)]))
    assert _cells(_table(tmp_path), 2)[6] == (
        "s1 \\[description\\] \\(p1\\)<br>s2 \\[description\\] \\(p2\\)"
    )


def test_the_canary_column_is_the_result_of_the_observation_in_stage_b(tmp_path):
    _put(tmp_path, "r1", _result("A"))
    _put(tmp_path, "r1b", _result("B", canary="altered"))
    table = _table(tmp_path)
    assert _cells(table, 2)[7] == ""
    assert _cells(table, 3)[7] == "altered"


def test_the_double_run_column(tmp_path):
    _put(tmp_path, "r1", _result("A"))
    _put(tmp_path, "r2", _result("A"))
    table = _table(tmp_path)
    assert _cells(table, 2)[8] == "same"
    assert _cells(table, 3)[8] == "none"


def test_the_skipped_column_has_the_reason(tmp_path):
    server = _server(stage_a_status="skipped", stage_a_reason="needs a key")
    table = report.markdown(_rows(tmp_path, server), False)
    cells = _cells(table, 2)
    assert (cells[5], cells[9]) == ("skipped", "needs a key")


def test_two_stages_of_a_server_stand_in_consecutive_rows(tmp_path):
    table = report.markdown(_rows(tmp_path, _server("a"), _server("b")), False)
    assert [tuple(_cells(table, n)[:2]) for n in range(2, 6)] == [
        ("a", "A"), ("a", "B"), ("b", "A"), ("b", "B")
    ]  # fmt: skip


# -- the excerpts ----------------------------------------------------------------------------


def _hostile(tmp_path: Path) -> list[Any]:
    _put(tmp_path, "r1", _result("A", signals=[("s", "p", HOSTILE)]))
    return _rows(tmp_path)


def test_the_html_escapes_an_excerpt_and_no_tag_comes_from_it(tmp_path):
    page = report.html(_hostile(tmp_path), True)
    assert "&lt;script&gt;alert(&quot;x&quot;) &amp; more&lt;/script&gt;" in page
    assert "<script" not in page
    assert "</script" not in page


def test_the_html_has_no_script_no_link_out_and_no_event_attribute(tmp_path):
    page = report.html(_hostile(tmp_path), True)
    assert not re.search(r"<(script|link|iframe|img|a|object|embed)\b", page, re.I)
    assert not re.search(r"\son[a-z]+\s*=", page, re.I)
    assert "http://" not in page and "https://" not in page
    assert page.count("<style>") == 1


def test_the_html_escapes_every_value(tmp_path):
    server = _server(stage_a_status="skipped", stage_a_reason='<b onclick="x">&')
    page = report.html(_rows(tmp_path, server), False)
    assert "<b " not in page
    assert "&lt;b onclick=&quot;x&quot;&gt;&amp;" in page


def test_the_html_without_excerpts_shows_the_place_and_not_the_text(tmp_path):
    page = report.html(_hostile(tmp_path), False)
    assert "whitespace" not in page and "alert" not in page
    assert "s [description] (p)" in page


def test_the_markdown_masks_a_pipe_and_a_line_break_in_an_excerpt(tmp_path):
    _put(tmp_path, "r1", _result("A", signals=[("s", "p", "a|b\nc\r\nd")]))
    table = report.markdown(_rows(tmp_path), True)
    row = table.splitlines()[2]
    assert "a\\|b c d" in row
    assert len(_cells(table, 2)) == 10
    assert len(table.splitlines()) == 4


def test_the_markdown_reads_an_excerpt_as_text_and_nothing_else(tmp_path):
    """An excerpt is the server's: no image (a request to a third party for every reader of the
    published report), link, HTML or emphasis of it may come through in the Markdown."""
    hostile = "![x](https://tracker.example/p.png) <img src=x> [a](javascript:x) **b** `c`"
    _put(tmp_path, "r1", _result("A", signals=[("s", "p](x)", hostile)]))
    line, text = _cells(report.markdown(_rows(tmp_path), True), 2)[6].split("<br>")
    # Every ASCII punctuation character of the server's is escaped, in the excerpt and in the
    # path; read back without the escapes, the text is the server's word for word.
    for cell in (line, text):
        assert re.search(r"[^\w\s]", re.sub(r"\\.", "", cell)) is None, cell
    assert re.sub(r"\\(.)", r"\1", text) == hostile


def test_the_markdown_masks_a_backslash_before_a_pipe(tmp_path):
    _put(tmp_path, "r1", _result("A", signals=[("s", "p", "a\\|b")]))
    table = report.markdown(_rows(tmp_path), True)
    assert len(_cells(table, 2)) == 10


def test_the_markdown_without_excerpts_shows_no_excerpt(tmp_path):
    rows = _hostile(tmp_path)
    table = report.markdown(rows, False)
    assert "alert" not in table and "more" not in table
    assert "s \\[description\\] \\(p\\)" in table
    assert "alert" in report.markdown(rows, True)


def test_a_value_in_another_column_is_masked_as_well(tmp_path):
    server = _server(stage_a_status="skipped", stage_a_reason="a|b\nc")
    table = report.markdown(_rows(tmp_path, server), False)
    assert _cells(table, 2)[9] == "a\\|b c"


# -- the command -----------------------------------------------------------------------------


def _defs(tmp_path: Path) -> Path:
    return _write_defs(tmp_path, _active())


def test_the_command_writes_both_files(tmp_path, capsys):
    runs, out = tmp_path / "runs", tmp_path / "out"
    _put(runs, "r1", _result("A", signals=[("s", "p", HOSTILE)]))
    code = bench.main(
        ["report", "--definitions", str(_defs(tmp_path)), "--runs", str(runs),
         "--out", str(out)]
    )  # fmt: skip
    assert code == 0
    assert "toy" in (out / "report.md").read_text(encoding="utf-8")
    page = (out / "report.html").read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "alert" not in page and "alert" not in (out / "report.md").read_text(encoding="utf-8")


def test_the_command_shows_excerpts_only_when_asked(tmp_path, capsys):
    runs, out = tmp_path / "runs", tmp_path / "out"
    _put(runs, "r1", _result("A", signals=[("s", "p", HOSTILE)]))
    base = ["report", "--definitions", str(_defs(tmp_path)), "--runs", str(runs), "--out", str(out)]
    assert bench.main([*base, "--excerpts"]) == 0
    assert "&lt;script&gt;" in (out / "report.html").read_text(encoding="utf-8")
    assert "a\\|b" in (out / "report.md").read_text(encoding="utf-8")


def test_the_command_takes_several_runs_directories(tmp_path, capsys):
    one, two, out = tmp_path / "one", tmp_path / "two", tmp_path / "out"
    _put(one, "r1", _result("A"))
    _put(two, "r2", _result("A"))
    code = bench.main(
        ["report", "--definitions", str(_defs(tmp_path)), "--runs", str(one),
         "--runs", str(two), "--out", str(out)]
    )  # fmt: skip
    assert code == 0
    assert "same" in (out / "report.md").read_text(encoding="utf-8")


def test_the_command_refuses_to_write_inside_the_repository(tmp_path, capsys):
    out = bench.REPO_ROOT / "benchmarks" / "report-test-never-written"
    code = bench.main(
        ["report", "--definitions", str(_defs(tmp_path)), "--runs", str(tmp_path),
         "--out", str(out)]
    )  # fmt: skip
    assert code == bench.EXIT_REFUSED
    assert "public tree" in capsys.readouterr().err
    assert not out.exists()


def test_the_command_fails_on_a_broken_result_and_writes_nothing(tmp_path, capsys):
    runs, out = tmp_path / "runs", tmp_path / "out"
    directory = _put(runs, "r1", _result("A"))
    (directory / "result.json").write_text("{", encoding="utf-8")
    code = bench.main(
        ["report", "--definitions", str(_defs(tmp_path)), "--runs", str(runs),
         "--out", str(out)]
    )  # fmt: skip
    assert code == bench.EXIT_FAILED
    assert "result.json" in capsys.readouterr().err
    assert not (out / "report.html").exists()
