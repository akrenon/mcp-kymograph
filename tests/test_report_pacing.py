"""What a run was held to and how long it waited, in the report (docs/engagements.md, pacing):
as recorded, per run, and never judged.

The recordings are real ones, made by ``drive`` as ``tests/test_pacing.py`` makes them, and read
the way the report reads a recording (``_pacing_fields``); the sentences about a file without
pacing are tested through the report of the fixture engagement.
"""

# The fixtures are imported and named again as arguments.
# ruff: noqa: F811
from __future__ import annotations

import copy
import json

import pytest

from mcp_kymograph import cli, pacing, report
from mcp_kymograph.report import DERIVED, RECORDED, _pacing_fields, _pacing_words, _Recording
from mcp_kymograph.store import Store
from test_cli_engagement import events_of
from test_http_tls import TRUSTED, http_server, serve, trust_ca  # noqa: F401 - fixtures
from test_pacing import (  # noqa: F401 - fixtures
    clock,
    drive_localhost,
    engaged,
    limited,
    retry,
    run_directories,
    salt,
    waits,
)
from test_report import build, filed, section  # noqa: F401 - filed is a fixture


def read_run(path) -> _Recording:
    """The report's reading of a run's recording."""
    events = events_of(path / "events.jsonl")
    return _Recording("read", started=events[0], **_pacing_fields(events[0], events))


def latest(tmp_path) -> _Recording:
    return read_run(max(run_directories(tmp_path / "runs"), key=lambda p: p.stat().st_mtime_ns))


def test_a_run_paced_by_the_defaults_says_so_with_the_source_and_that_it_did_not_wait(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    assert drive_localhost(tmp_path, port) == 0

    words = _pacing_words("run 1", latest(tmp_path))

    assert words == [
        "Run 1 was paced: `runs_per_origin` `1` and `min_interval_seconds` `10`, source `default`.",
        "No wait is recorded for run 1: it has no `paced` event.",
    ]


def test_a_run_paced_by_the_file_says_the_file_s_values_and_source(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    held = engaged(tmp_path, port, pacing={"runs_per_origin": 2, "min_interval_seconds": 0})
    assert drive_localhost(tmp_path, port, engagement=held) == 0

    first, _ = _pacing_words("run 1", latest(tmp_path))

    assert first == (
        "Run 1 was paced: `runs_per_origin` `2` and `min_interval_seconds` `0`, source `file`."
    )


def test_the_waits_of_a_run_are_counted_by_reason_with_their_seconds(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    assert drive_localhost(tmp_path, port) == 0
    clock.now += 2
    assert drive_localhost(tmp_path, port) == 0

    recording = latest(tmp_path)
    (event,) = recording.paced
    _, waited = _pacing_words("run 2", recording)

    assert event["why"] == "interval"
    assert waited == f"Run 2 waited for `interval`: 1 wait, `{event['seconds']}` seconds."


def test_a_wait_for_a_retry_after_names_the_status_that_asked_for_it(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429)])
    assert drive_localhost(tmp_path, port) == 0

    recording = latest(tmp_path)
    (event,) = recording.paced
    _, waited = _pacing_words("run 1", recording)

    assert (event["why"], event["status"]) == ("retry_after", 429)
    assert waited == (
        f"Run 1 waited for `retry_after`: 1 wait, `{event['seconds']}` seconds, status `429`."
    )


def test_waits_of_one_reason_are_summed_and_each_status_is_named_once():
    paced = (
        {"type": "paced", "seconds": 1.25, "why": "retry_after", "status": 429},
        {"type": "paced", "seconds": 2.5, "why": "retry_after", "status": 503},
        {"type": "paced", "seconds": 1.0, "why": "retry_after", "status": 429},
        {"type": "paced", "seconds": 3, "why": "interval"},
    )
    held = {"runs_per_origin": 1, "min_interval_seconds": 10, "source": "default"}
    recording = _Recording("read", pacing_enforced=True, pacing=held, paced=paced)

    _, retried, interval = _pacing_words("run 1", recording)

    assert retried == (
        "Run 1 waited for `retry_after`: 3 waits, `4.75` seconds, status `429`, `503`."
    )
    assert interval == "Run 1 waited for `interval`: 1 wait, `3` seconds."


def test_a_value_that_is_no_number_or_a_reason_nobody_knows_is_shown_as_it_stands():
    odd = (
        {"type": "paced", "seconds": "soon", "why": "<b>x</b>`"},
        {"type": "paced", "seconds": 2, "why": "<b>x</b>`"},
    )
    held = {"runs_per_origin": "many", "min_interval_seconds": None, "source": "x`y"}
    recording = _Recording("read", pacing_enforced=True, pacing=held, paced=odd)

    first, waited = _pacing_words("run 1", recording)

    assert first == (
        "Run 1 was paced: `runs_per_origin` `many` and `min_interval_seconds` `null`, source "
        "``x`y``."
    )
    assert waited == (
        "Run 1 waited for `` <b>x</b>` ``: 2 waits, `2` seconds (1 of them with a number of "
        "seconds)."
    )


def test_a_recording_that_says_false_is_declared_and_not_enforced(tmp_path, trust_ca, serve, clock):
    port = serve(tls=TRUSTED)
    assert drive_localhost(tmp_path, port) == 0
    (path,) = run_directories(tmp_path / "runs")
    events = events_of(path / "events.jsonl")
    events[0]["pacing_enforced"], events[0]["pacing"] = False, None
    recording = _Recording("read", **_pacing_fields(events[0], events))

    assert _pacing_words("run 1", recording) == [
        "Pacing for run 1 is declared, not enforced by the version that made the recording "
        "(`pacing_enforced` `false`)."
    ]


def test_a_loopback_run_and_a_recording_without_the_field_get_no_sentence(tmp_path, serve):
    port = serve()
    args = ["drive", "-q", "--http", f"http://127.0.0.1:{port}/mcp"]
    assert cli.main([*args, "--out-dir", str(tmp_path / "runs")]) == 0
    (path,) = run_directories(tmp_path / "runs")
    events = events_of(path / "events.jsonl")
    assert events[0]["pacing_enforced"] is None

    assert _pacing_words("run 1", read_run(path)) == []
    del events[0]["pacing_enforced"], events[0]["pacing"]
    assert _pacing_words("run 1", _Recording("read", **_pacing_fields(events[0], events))) == []


# -- the sentences about a file ---------------------------------------------------------------


def declared(parsed) -> list[report.Sentence]:
    return [s for s in section(parsed, 1).sentences if "acing" in s.text]


def test_a_file_that_declares_pacing_keeps_its_sentences(filed):
    sentences = declared(report.parse(report.render(build(filed))))

    assert [s.kind for s in sentences] == [RECORDED, DERIVED]
    assert sentences[0].text.startswith("Pacing declared: ")


@pytest.fixture
def no_pacing(monkeypatch):
    """The store's engagement as it would be if its latest version declared no pacing."""
    held = Store.engagement

    def engagement(self):
        found = copy.deepcopy(held(self))
        del found["chain"][-1]["file_declared"]["pacing"]
        return found

    monkeypatch.setattr(Store, "engagement", engagement)


def test_no_pacing_declared_is_recorded_and_the_defaults_are_derived_from_the_constants(
    filed, no_pacing
):
    parsed = report.parse(report.render(build(filed)))

    recorded, derived = declared(parsed)

    assert (recorded.kind, recorded.text) == (RECORDED, "No pacing is declared.")
    assert derived.kind == DERIVED
    assert derived.text == (
        "With no pacing declared, an HTTP run to a host that is not a loopback literal keeps the "
        f"defaults: `runs_per_origin` `{pacing.DEFAULT_RUNS_PER_ORIGIN}` and "
        f"`min_interval_seconds` `{pacing.DEFAULT_MIN_INTERVAL_SECONDS}`."
    )


def test_the_defaults_in_the_sentence_follow_the_constants(filed, no_pacing, monkeypatch):
    monkeypatch.setattr(report, "DEFAULT_RUNS_PER_ORIGIN", 3)
    monkeypatch.setattr(report, "DEFAULT_MIN_INTERVAL_SECONDS", 45)

    parsed = report.parse(report.render(build(filed)))

    assert "`runs_per_origin` `3` and `min_interval_seconds` `45`" in declared(parsed)[1].text


# -- seconds from a recording nobody here made -------------------------------------------------

NO_NUMBER = "no sum of seconds (0 of them with a number of seconds)"


def paced_report(filed, tmp_path, *seconds: str) -> list[str]:
    """The sentences about the waits in a whole report over a recording whose ``paced`` events
    hold ``seconds`` as JSON text, written as given and read back by ``json.loads`` as the report
    reads a file."""
    source = next(
        path / "events.jsonl"
        for path in sorted(run_directories(filed["runs"]))
        if "reference-server" in (path / "events.jsonl").read_text()
    )
    lines = source.read_text().splitlines()
    started = json.loads(lines[0])
    started["pacing_enforced"] = True
    started["pacing"] = {"runs_per_origin": 1, "min_interval_seconds": 10, "source": "default"}
    # the second line of a recording, made a paced event, with the seconds put in as text
    wait = json.dumps({**json.loads(lines[1]), "type": "paced", "seconds": "@", "why": "interval"})
    waits = [wait.replace('"@"', text) for text in seconds]
    runs = tmp_path / "runs"
    (runs / "edited").mkdir(parents=True)
    edited = runs / "edited" / "events.jsonl"
    edited.write_text("\n".join([json.dumps(started), *waits, *lines[1:]]) + "\n")
    database = tmp_path / "edited.sqlite"
    code = cli.main(
        ["store", "ingest", "-q", "--store", str(database), "--engagement", str(filed["held"]),
         str(edited)]
    )  # fmt: skip
    assert code == 0, code
    text = report.render(build(filed, database=database, runs_dir=runs, out_dir=runs))
    assert "Infinity" not in text and "NaN" not in text
    return [line for line in text.splitlines() if "waited for" in line]


@pytest.mark.parametrize(
    ("seconds", "said"),
    [
        pytest.param(
            ["1" + "0" * 400, "1.5"],
            "2 waits, `1.5` seconds (1 of them with a number of seconds)",
            id="a-huge-int-beside-a-float",
        ),
        pytest.param(["1" + "0" * 4299] * 2, f"2 waits, {NO_NUMBER}", id="two-ints-of-4300-digits"),
        pytest.param(
            ["2", "NaN"], "2 waits, `2` seconds (1 of them with a number of seconds)", id="nan"
        ),
        pytest.param(["Infinity", "-Infinity"], f"2 waits, {NO_NUMBER}", id="infinities"),
        pytest.param(["1e400"], f"1 wait, {NO_NUMBER}", id="1e400"),
        pytest.param(["1e308"] * 2, "2 waits, the seconds are too large to add", id="overflow"),
        pytest.param(["true"], f"1 wait, {NO_NUMBER}", id="true"),
        pytest.param(["-1"], f"1 wait, {NO_NUMBER}", id="negative"),
        pytest.param(["0"], "1 wait, `0` seconds", id="zero"),
        pytest.param(["9007199254740993"], "1 wait, `9007199254740993` seconds", id="2**53+1"),
        pytest.param(
            ["1" + "0" * 30, "1"],
            "2 waits, `1" + "0" * 29 + "1` seconds",
            id="ints-past-a-float-add-exactly",
        ),
        pytest.param(
            ["1" + "0" * 308] * 2, "2 waits, `2" + "0" * 308 + "` seconds", id="ints-past-1e308"
        ),
        pytest.param(["2", "1.5"], "2 waits, `3.5` seconds", id="an-int-beside-a-float"),
    ],
)
def test_seconds_that_are_no_finite_number_from_nothing_up_are_not_summed(
    filed, tmp_path, seconds, said
):
    (waited,) = paced_report(filed, tmp_path, *seconds)

    assert waited.endswith(f"waited for `interval`: {said}.")
