"""A finding gone on an endpoint says "server unpinned" beside it, wherever it is said gone.

An endpoint's version is the operator's declared word (http-transport.md 4.2): the deployment
behind one URL can change while the URL and the declared version stay as they are. Here it does:
the loopback HTTP test server (tests/fixtures/http_server.py) answers the first run as the
poison variant and the second, at the same URL under the same declared version, as the
reference variant. ``store diff`` and ``engagement recheck`` then see findings gone with no axis
moved, and both say "server unpinned" beside them, as the report does — so no reader takes a
declared version for a content identity. Nothing connects beyond 127.0.0.1.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, report
from mcp_kymograph.store import IDENTITY_FIELDS, SERVER_UNPINNED, Store
from test_report_d import write_engagement

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"


def endpoint_manifest(directory: Path, url: str) -> Path:
    directory.mkdir(parents=True)
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": {"endpoint": url, "version_declared": "3.1"},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, directory)],
                    }
                ],
            }
        )
    )
    return path


def drive(held: Path, manifest: Path, out_dir: Path) -> Path:
    before = set(out_dir.iterdir()) if out_dir.exists() else set()
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--manifest", str(manifest), "--entry",
         "customer-mcp", "--out-dir", str(out_dir)]
    )  # fmt: skip
    assert code == 0
    (run,) = set(out_dir.iterdir()) - before
    return run / "events.jsonl"


@pytest.fixture(scope="module")
def redeployed(tmp_path_factory):
    """Two endpoint runs under one engagement, filed: the same URL and declared version, the
    deployment changed between them."""
    root = tmp_path_factory.mktemp("unpinned")
    held = write_engagement(root / "engagement")
    server = http_server.serve(0, variant="poison")
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
        manifest = endpoint_manifest(root / "manifest", url)
        runs = root / "runs"
        first = drive(held, manifest, runs)
        server.behaviour = http_server.Behaviour(variant="reference")
        second = drive(held, manifest, runs)
    finally:
        server.shutdown()
        server.server_close()
    database = root / "findings.sqlite"
    assert (
        cli.main(["store", "ingest", "-q", "--store", str(database), "--engagement", str(held),
                  str(first), str(second)])
        == 0
    )  # fmt: skip
    with Store.open_read_only(database) as store:
        before, after = store.resolve(str(first)), store.resolve(str(second))
    return {"held": held, "runs": runs, "database": database, "before": before, "after": after}


def test_the_store_s_diff_says_server_unpinned_beside_what_is_gone(redeployed):
    with Store.open_read_only(redeployed["database"]) as store:
        diff = store.diff(redeployed["before"], redeployed["after"])

    assert diff.gone, "the reference variant does not say what the poison variant said"
    assert diff.moved == (), "the same URL and the same declared version: no axis moved"
    assert diff.before.server_version == diff.after.server_version == "3.1"
    assert SERVER_UNPINNED in diff.caveats["gone"]
    assert diff.to_dict()["caveats"]["gone"] == list(diff.caveats["gone"])
    assert (SERVER_UNPINNED in diff.caveats["new"]) == bool(diff.new)


def test_store_diff_prints_each_caveat_by_name_and_says_server_unpinned(redeployed, capsys):
    code = cli.main(
        ["store", "diff", "--store", str(redeployed["database"]), redeployed["before"],
         redeployed["after"]]
    )  # fmt: skip

    assert code == 0
    said = capsys.readouterr()
    assert SERVER_UNPINNED in json.loads(said.out)["caveats"]["gone"]
    assert "caveat on gone: server_unpinned: " in said.err
    assert "scenario's content differs" not in said.err, "the scenario did not change"


def test_a_content_identity_s_diff_never_says_server_unpinned(tmp_path):
    """The caveat is read from the version's kind: a corpus entry whose version is established
    from its files does not carry it, though findings are gone between its two runs."""
    from test_report_d import FIXED, POISONED, fixable_manifest

    recordings = []
    for name, description in (("poisoned", POISONED), ("fixed", FIXED)):
        out = tmp_path / f"runs-{name}"
        manifest = fixable_manifest(tmp_path / name, description)
        assert cli.main(["drive", "-q", "--manifest", str(manifest), "--entry", "fixable-server",
                         "--isolation", "host", "--out-dir", str(out)]) == 0  # fmt: skip
        (path,) = out.glob("*/events.jsonl")
        recordings.append(path)
    with Store.open(tmp_path / "findings.sqlite") as store:
        first, second = (store.ingest(path).run for path in recordings)
        diff = store.diff(first, second)
    assert diff.gone
    assert diff.before.server_version_kind == "content"
    assert all(SERVER_UNPINNED not in flags for flags in diff.caveats.values())


def test_a_re_check_gone_on_an_endpoint_says_server_unpinned_beside_a_bare_line(redeployed):
    with Store.open_read_only(redeployed["database"]) as store:
        sighted = set(store.findings_of(redeployed["before"])) - set(
            store.findings_of(redeployed["after"])
        )
        findings = [
            f["finding"]
            for f in store.findings_with_triage("real-world")
            if tuple(f[n] for n in IDENTITY_FIELDS) in sighted
        ]
    assert findings

    result = report.recheck(
        store=redeployed["database"],
        engagement_path=redeployed["held"],
        runs_dir=redeployed["runs"],
        finding_ids=findings,
        after=redeployed["after"],
    )

    assert {item.outcome for item in result.items} == {report.GONE}
    rendered = report.render_recheck(result)
    for item in result.items:
        assert (item.version_kind_before, item.version_kind_after) == ("declared", "declared")
        assert item.server_unpinned
        assert "--rationale" not in shlex.split(item.triage_line)
    lines = rendered.splitlines()
    for number, text in enumerate(lines):
        if text.startswith("  gone: "):
            assert lines[number + 1] == f"  {report.UNPINNED}"
    assert "version 3.1 (declared)" in rendered
    written = result.to_dict()
    assert written["after_version_kind"] == "declared"
    assert {item["server_unpinned"] for item in written["items"]} == {True}
    assert json.loads(json.dumps(written)) == written


def test_a_re_check_of_a_content_identity_says_nothing_of_pinning(tmp_path):
    """The re-check of a corpus entry run here: gone, and no "server unpinned" beside it."""
    from test_report_d import FIXED, POISONED, fixable_manifest, ingest
    from test_report_d import drive as drive_here

    held = write_engagement(tmp_path / "engagement")
    runs = tmp_path / "runs"
    database = tmp_path / "findings.sqlite"
    poisoned = drive_here(held, runs, fixable_manifest(tmp_path / "p", POISONED), "fixable-server")
    fixed = drive_here(held, runs, fixable_manifest(tmp_path / "f", FIXED), "fixable-server")
    ingest(database, held, poisoned, fixed)
    with Store.open_read_only(database) as store:
        findings = [f["finding"] for f in store.findings_with_triage("poison")]
        gone = set(store.findings_of(store.resolve(str(poisoned)))) - set(
            store.findings_of(store.resolve(str(fixed)))
        )
        named = [
            f["finding"]
            for f in store.findings_with_triage("poison")
            if tuple(f[n] for n in IDENTITY_FIELDS) in gone
        ]
    assert findings and named

    result = report.recheck(store=database, engagement_path=held, runs_dir=runs,
                            finding_ids=named, after=str(fixed))  # fmt: skip

    assert {item.outcome for item in result.items} == {report.GONE}
    assert not any(item.server_unpinned for item in result.items)
    assert report.UNPINNED not in report.render_recheck(result)
    assert "(declared)" not in report.render_recheck(result)
