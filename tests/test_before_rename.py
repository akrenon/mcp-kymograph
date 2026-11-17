"""What was written before the tool was renamed is still read.

The data in ``fixtures/before_rename`` was made by the tool under its earlier name (the README
there says at which commit and by which commands), and each test reads it with the tool as it is
now. Three readers compare against a text that held the earlier name: the customer page of a
handover bundle, the value of a canary, and the companion of a benchmark run. The files under
``expected`` are what the earlier tool printed for the same data.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mcp_kymograph import cli, handover, marking
from test_benchmark_runner import bench

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "before_rename"
RUN = "20261117T114140Z-80f72f28"
BENCH_RUNS = ("20261117T114150Z-c7e81a68", "20261117T114151Z-494a4c56")
INDEX_DIGEST = "b2ad40f365ead1e8d1f98526ce945fbe54546d6455422e7f538fd7d2189e283a"
#: The engagement file of then names this variable; the value was made up for the fixtures.
SALT_ENV = "POLYGRAPH_SALT"
SALT = "before-rename-fixture-salt-not-a-secret-0001"
#: The key the two benchmark runs were made with. Made for the fixtures and public: test only.
BENCH_KEY = bytes.fromhex("600b879417d607b90e125310c458da6540a79bf2306775d01201bce5dfdf2994")
EARLIER_PREFIX = "polygraph-canary-"


@pytest.fixture
def old(tmp_path: Path) -> Path:
    """A copy of the fixtures outside the repository, where a run or a bundle would be."""
    return Path(shutil.copytree(FIXTURES, tmp_path / "before-rename"))


def expected(name: str) -> str:
    return (FIXTURES / "expected" / name).read_text(encoding="utf-8")


# -- the customer page of a handover bundle -------------------------------------------------


def test_a_handover_bundle_of_before_the_rename_still_verifies(old, capsys):
    bundle = old / "handover"
    index = json.loads((bundle / "index.json").read_text(encoding="utf-8"))
    page = (bundle / "CUSTOMER-README.md").read_text(encoding="utf-8")
    assert index["page_version"] == 1 < handover.PAGE_VERSION
    assert "    mcp-polygraph evidence verify DIR --index-digest " + INDEX_DIGEST in page

    code = cli.main(["evidence", "verify", str(bundle), "--index-digest", INDEX_DIGEST])
    out, err = capsys.readouterr()
    assert code == 0, err
    then = json.loads(expected("verify-handover.json"))
    assert json.loads(out) == {**then, "directory": str(bundle)}
    assert then["readme"].startswith("present; the page this bundle's index")
    assert err == "kymograph: 5 intact\n"


def test_a_changed_page_of_before_the_rename_is_still_noticed(old, capsys):
    # Version 1 is checked against its own words, not waved through: the page as the tool
    # writes it today is not the page of this bundle.
    bundle = old / "handover"
    page = bundle / "CUSTOMER-README.md"
    text = page.read_text(encoding="utf-8")
    today = handover.render_customer_readme(handover.parse_customer_readme(text, 1), 2)
    assert today != text
    page.write_text(today, encoding="utf-8")
    code = cli.main(["evidence", "verify", str(bundle), "--index-digest", INDEX_DIGEST])
    out, _ = capsys.readouterr()
    assert code != 0
    assert any("is not the page this bundle" in problem for problem in json.loads(out)["problems"])


# -- the value of a canary ------------------------------------------------------------------


def test_a_canary_of_before_the_rename_is_still_found_in_its_recording(old, monkeypatch, capsys):
    monkeypatch.setenv(SALT_ENV, SALT)
    run = old / "runs" / RUN
    held = old / "engagement" / "acme-2026-11.json"
    recording = (run / "events.jsonl").read_text(encoding="utf-8")
    planted = json.loads(expected("canary.json"))["canaries"][0]["value"]
    assert planted.startswith(EARLIER_PREFIX) and planted in recording
    assert marking.VALUE_PREFIX not in recording

    assert cli.main(["engagement", "marking", str(run), "--engagement", str(held), "--json"]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out) == json.loads(expected("marking.json"))
    assert err == "kymograph: 1 delivery(ies); an observation, not a severity\n"

    assert cli.main(["engagement", "marking", str(run), "--engagement", str(held)]) == 0
    assert capsys.readouterr().out == expected("marking.txt")


def test_a_canary_of_the_same_file_differs_today_in_its_prefix_only(old, monkeypatch, capsys):
    monkeypatch.setenv(SALT_ENV, SALT)
    held = old / "engagement" / "acme-2026-11.json"
    assert cli.main(["engagement", "canary", str(held), "--json"]) == 0
    today = json.loads(capsys.readouterr().out)
    then = json.loads(expected("canary.json"))
    for item in then["canaries"]:
        assert item["value"].startswith(EARLIER_PREFIX)
        item["value"] = marking.VALUE_PREFIX + item["value"].removeprefix(EARLIER_PREFIX)
    assert today == then


def test_the_verdict_on_a_recording_of_before_the_rename_is_the_same(old, capsys):
    run = old / "runs" / RUN
    code = cli.main(["verdict", str(run)])
    out, _ = capsys.readouterr()
    then = json.loads(expected("verdict.json"))
    assert code == then["exit_code"] == 0
    assert json.loads(out) == {**then, "recording": str(run / "events.jsonl")}


# -- the companion of a benchmark run -------------------------------------------------------


@pytest.fixture
def bench_key(tmp_path: Path) -> Path:
    path = tmp_path / "bench.key"
    path.write_bytes(BENCH_KEY)
    path.chmod(0o600)
    return path


def companion(directory: Path) -> dict:
    return json.loads((directory / "container.json").read_text(encoding="utf-8"))


def compare(a: Path, b: Path, key: Path, capsys) -> tuple[int, dict]:
    capsys.readouterr()
    code = bench.main(["compare", str(a), str(b), "--key", str(key)])
    return code, json.loads(capsys.readouterr().out)


def test_two_benchmark_runs_of_before_the_rename_still_compare_under_their_key(
    old, bench_key, capsys
):
    a, b = (old / "bench" / name for name in BENCH_RUNS)
    one, two = companion(a), companion(b)
    # What the comparison has to read past: the key id (an HMAC of a text with the earlier
    # name), and the label with each run's own nonce in the docker command.
    assert one["inputs"]["environment_key_id"] == bench.key_id(BENCH_KEY)
    assert one["network"]["label"] != two["network"]["label"]
    for held in (one, two):
        assert held["network"]["label"].startswith("mcp-polygraph.bench=")
        assert held["network"]["label"] in held["docker_command"]

    code, result = compare(a, b, bench_key, capsys)
    assert code == bench.EXIT_OK
    then = json.loads(expected("compare-http.json"))
    for entry, directory in zip(then["runs"], (a, b), strict=True):
        entry["dir"] = str(directory)
    assert result == then
    assert result["inputs_differ"] == [] and result["differences"] == []


def test_the_version_in_a_companion_of_before_the_rename_is_read_under_its_earlier_key(
    old, bench_key, capsys
):
    # The second run, as a run of today names the tool's version: nothing else is changed.
    a, b = (old / "bench" / name for name in BENCH_RUNS)
    held = companion(b)
    assert "mcp_kymograph_version" not in held["tool"]
    held["tool"] = {
        "mcp_kymograph_version" if name == "mcp_polygraph_version" else name: value
        for name, value in held["tool"].items()
    }
    assert held["tool"]["mcp_kymograph_version"] == companion(a)["tool"]["mcp_polygraph_version"]
    (b / "container.json").write_text(json.dumps(held, indent=2) + "\n", encoding="utf-8")

    code, result = compare(a, b, bench_key, capsys)
    assert code == bench.EXIT_OK
    assert result["inputs_differ"] == []
