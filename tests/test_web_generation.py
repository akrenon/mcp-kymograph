"""The run page and its data: which generation the run spoke, whom it spoke as, and a listing that
was asked for again (web/CONTRACT.md 7.4). Only as recorded.

The views are checked on recordings made by this version against the fixture server; the page's
script is read as text for the words it must be able to show, since no browser runs here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli
from mcp_kymograph.web import views
from mcp_kymograph.web.views import Sources
from test_cli_engagement import write_engagement

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

APP = Path(views.__file__).parent / "static" / "app.js"
CONTRACT = Path(views.__file__).parent / "CONTRACT.md"


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """Three runs against the fixture server, each in its own directory under ``--runs``."""
    root = tmp_path_factory.mktemp("web-generation")
    held = write_engagement(root / "engagement")
    modes = {
        "modern": {"era": "modern", "break_stream": 1},
        "legacy": {"era": "legacy"},
        "refused": {"era": "modern", "refuse": -32021},
    }
    servers = {name: http_server.serve(**behaviour) for name, behaviour in modes.items()}
    try:
        for name, server in servers.items():
            url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
            cli.main(["drive", "-q", "--http", url, "--engagement", str(held),
                      "--out-dir", str(root / "runs" / name)])  # fmt: skip
    finally:
        for server in servers.values():
            server.shutdown()
            server.server_close()
    return Sources(runs=root / "runs")


def refs(sources: Sources) -> dict[str, str]:
    found = {}
    for row in views.runs(sources)["data"]:
        found[row["ref"].split("/")[0]] = row["ref"]
    return found


def overview(runs: Sources, name: str) -> dict:
    return views.run(runs, refs(runs)[name])["data"]["overview"]


def test_the_overview_passes_the_decision_and_the_end_of_the_script_whole(runs):
    seen = overview(runs, "modern")

    (decided,) = seen["era_decided"]
    assert (decided["era"], decided["version"], decided["outcome"]) == (
        "modern",
        "2026-07-28",
        "proceed",
    )
    (finished,) = seen["script_finished"]
    assert (finished["era"], finished["protocol_version"]) == ("modern", "2026-07-28")


def test_the_overview_says_whom_the_run_spoke_as_it_records_it(runs):
    started = overview(runs, "legacy")["run_started"]

    assert started["auth"] is None  # no token, no identity chosen
    assert overview(runs, "legacy")["era_decided"][0]["era"] == "legacy"


def test_a_stop_is_passed_whole_with_its_reason_and_the_refusal(runs):
    (decided,) = overview(runs, "refused")["era_decided"]

    assert (decided["outcome"], decided["reason"]) == ("stop", "modern_refused")
    assert decided["refusal"]["code"] == -32021


def test_a_listing_asked_for_again_is_a_step_of_the_inventory(runs):
    data = views.run(runs, refs(runs)["modern"])["data"]

    steps = [s for s in data["inventory"]["steps"] if s.get("type") == "step_reissued"]
    assert [(s["step"], s["page"], s["reason"]) for s in steps] == [
        ("tools/list", 0, "stream_broken")
    ]
    assert "inventory" in data["tabs"]


def test_a_run_made_before_this_version_has_no_decision_and_the_lists_are_empty(runs, tmp_path):
    ref = refs(runs)["legacy"]
    source = runs.runs / ref / "events.jsonl"
    kept = []
    for line in source.read_text().splitlines():
        event = json.loads(line)
        if event["type"] == "era_decided":
            continue
        if event["type"] == "script_finished":
            del event["era"], event["protocol_version"]
        kept.append(json.dumps(event))
    old = tmp_path / "runs" / ref / "events.jsonl"
    old.parent.mkdir(parents=True)
    old.write_text("\n".join(kept) + "\n")

    data = views.run(Sources(runs=tmp_path / "runs"), ref)["data"]

    assert data["overview"]["era_decided"] == []
    assert "era" not in data["overview"]["script_finished"][0]


@pytest.mark.parametrize(
    "words",
    [
        "function generation(",
        "function authCell(",
        "no token was sent, and no identity was chosen",
        "a token was used",
        "stopped at the opening",
        "an observation, not a stop",
        "case 'step_reissued':",
        "'era', 'protocol_version'",
    ],
)
def test_the_page_can_say_what_the_contract_says_it_shows(words):
    assert words in APP.read_text()


def test_the_page_builds_no_markup_from_what_a_recording_holds():
    text = APP.read_text()
    start = text.index("function generation(")
    end = text.index("// run_finished.http: the counts")
    shown = text[start:end]

    assert "innerHTML" not in shown and "insertAdjacentHTML" not in shown
    assert "setAttribute" not in shown  # attributes only through h(), by the contract


def test_the_contract_describes_the_fields_the_views_pass():
    text = CONTRACT.read_text()
    assert "7.4" in text and "`era_decided`" in text and "`step_reissued`" in text
