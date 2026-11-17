"""``kymograph report`` on the command line: written once, ``0600``, read back through its
own parser; a report that uses a run it cannot vouch for exits 3 and says so; refusals exit 2
and write nothing."""

import pytest

from mcp_kymograph import cli, report
from test_cli_engagement import MANIFEST, run_directories, write_engagement


@pytest.fixture
def engaged(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"
    for entry in ("poison-server", "reference-server"):
        assert cli.main(
            ["drive", "-q", "--engagement", str(held), "--manifest", str(MANIFEST), "--entry",
             entry, "--isolation", "host", "--out-dir", str(out_dir)]
        ) == 0  # fmt: skip
    database = tmp_path / "findings.sqlite"
    recordings = [str(run / "events.jsonl") for run in sorted(run_directories(out_dir))]
    assert cli.main(
        ["store", "ingest", "-q", "--store", str(database), "--engagement", str(held),
         *recordings]
    ) == 0  # fmt: skip
    capsys.readouterr()
    return held, out_dir, database


def make_report(held, out_dir, database, out, *extra):
    return cli.main(
        ["report", "--engagement", str(held), "--store", str(database), "--runs", str(out_dir),
         "--out-dir", str(out_dir), "--out", str(out), *extra]
    )  # fmt: skip


def test_a_report_is_written_once_private_and_reads_back(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    out = tmp_path / "reports" / "report.md"

    assert make_report(held, out_dir, database, out) == 0

    assert out.stat().st_mode & 0o777 == 0o600
    assert out.parent.stat().st_mode & 0o777 == 0o700
    parsed = report.parse(out.read_text())
    assert parsed.engagement_id == "acme-2026-10"
    assert all(sentence.kind in ("recorded", "derived", "assessed") for sentence in
               parsed.sentences)  # fmt: skip
    assert "sha256" in capsys.readouterr().err


def test_an_existing_report_is_never_written_over(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    out = tmp_path / "report.md"
    out.write_text("mine")

    assert make_report(held, out_dir, database, out) == 2
    assert "exists" in capsys.readouterr().err
    assert out.read_text() == "mine"


def test_a_file_not_of_the_store_s_chain_is_refused(engaged, tmp_path, capsys):
    _, out_dir, database = engaged
    other = write_engagement(tmp_path / "other", id="other-2026-11")
    out = tmp_path / "report.md"

    assert make_report(other, out_dir, database, out) == 2
    assert "refused" in capsys.readouterr().err
    assert not out.exists()


def test_a_recording_changed_since_filing_makes_the_report_say_so_and_exit_3(
    engaged, tmp_path, capsys
):
    held, out_dir, database = engaged
    recording = sorted(run_directories(out_dir))[0] / "events.jsonl"
    recording.write_bytes(recording.read_bytes() + b"\n")
    out = tmp_path / "report.md"

    assert make_report(held, out_dir, database, out) == 3

    assert out.exists()
    assert "not complete" in capsys.readouterr().err


def test_the_manifest_names_what_is_still_planned_and_a_runs_dir_that_is_none_is_refused(
    engaged, tmp_path, capsys
):
    held, out_dir, database = engaged
    out = tmp_path / "report.md"

    assert make_report(held, out_dir, database, out, "--manifest", str(MANIFEST)) == 0
    assert "give `--manifest`" not in out.read_text()

    capsys.readouterr()
    missing = tmp_path / "no-such-runs"
    code = cli.main(
        ["report", "--engagement", str(held), "--store", str(database), "--runs", str(missing),
         "--out", str(tmp_path / "other.md")]
    )  # fmt: skip
    assert code == 2
    assert not (tmp_path / "other.md").exists()
