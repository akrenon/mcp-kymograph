"""``engagement recheck``, ``attest``, ``history`` and ``intake`` on the command line.

``recheck`` prints commands and outcomes and runs nothing; ``attest`` writes once, ``0600``, and
holds no finding; ``history`` lists a store it cannot read rather than skip it; ``intake`` writes
a questionnaire, and from its answers a draft the gate refuses.
"""

import hashlib
import json

import pytest

from mcp_kymograph import cli, engagement, report
from mcp_kymograph.store import Store
from test_cli_engagement import MANIFEST, run_directories
from test_cli_phase_b import emitted, engagement_with_runs, findings_of


@pytest.fixture
def engaged(tmp_path, capsys):
    return engagement_with_runs(tmp_path, capsys)


def digest_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# -- recheck --------------------------------------------------------------------------------


def test_recheck_prints_the_commands_and_writes_nothing(engaged, capsys):
    held, out_dir, database = engaged
    before = digest_of(database)
    (finding, *_) = findings_of(database)
    with Store.open_read_only(database) as store:
        found = next(
            row["finding"] for row in store.findings_with_triage("poison")
            if row["locator"] == finding["locator"]
        )  # fmt: skip

    code = cli.main(
        ["engagement", "recheck", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--finding", str(found)]
    )  # fmt: skip

    assert code == 0
    said = capsys.readouterr().out
    assert "kymograph drive" in said and "--engagement" in said
    assert digest_of(database) == before
    assert len(run_directories(out_dir)) == 3, "nothing was run"


def test_recheck_after_a_run_that_still_sights_it_says_unchanged(engaged, capsys):
    held, out_dir, database = engaged
    with Store.open_read_only(database) as store:
        runs = [run for run in store.runs() if run.server == "poison-server"]
        found = store.findings_with_triage("poison")[0]["finding"]
    later = runs[-1].run

    code = cli.main(
        ["engagement", "recheck", "--json", "--store", str(database), "--engagement",
         str(held), "--runs", str(out_dir), "--finding", str(found), "--after", later]
    )  # fmt: skip

    assert code == 0
    said = json.dumps(emitted(capsys))
    assert '"unchanged"' in said
    assert '"gone"' not in said and '"not_proven"' not in said
    assert "--status confirmed" in said


def test_recheck_refuses_an_identity_that_is_not_json(engaged, capsys):
    held, out_dir, database = engaged
    code = cli.main(
        ["engagement", "recheck", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--identity", "{nope"]
    )  # fmt: skip
    assert code == 2
    assert "--identity is not JSON" in capsys.readouterr().err


# -- attest ---------------------------------------------------------------------------------


def packed(held, out_dir, database, bundle, capsys):
    assert cli.main(
        ["evidence", "pack", "-q", "--engagement", str(held), "--store", str(database),
         "--runs", str(out_dir), "--out", str(bundle)]
    ) == 0  # fmt: skip
    return emitted(capsys)


def test_an_attestation_is_written_once_reads_back_and_holds_no_finding(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    bundle = tmp_path / "bundle"
    index = packed(held, out_dir, database, bundle, capsys)
    out = tmp_path / "attestation.md"

    code = cli.main(
        ["engagement", "attest", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--bundle",
         str(bundle), "--out", str(out)]
    )  # fmt: skip

    assert code == 0
    assert out.stat().st_mode & 0o777 == 0o600
    text = out.read_text()
    report.parse_attestation(text)
    assert index["index_digest"] in text
    for finding in findings_of(database):
        assert finding["locator"] not in text
    assert "no finding" in capsys.readouterr().err

    assert cli.main(
        ["engagement", "attest", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--bundle",
         str(bundle), "--out", str(out)]
    ) == 2  # fmt: skip


def test_an_attestation_of_a_bundle_that_is_not_intact_is_refused(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    bundle = tmp_path / "bundle"
    packed(held, out_dir, database, bundle, capsys)
    (recording,) = sorted(bundle.glob("runs/*/events.jsonl"))[:1]
    data = bytearray(recording.read_bytes())
    data[10] ^= 0x01
    recording.write_bytes(bytes(data))
    out = tmp_path / "attestation.md"

    code = cli.main(
        ["engagement", "attest", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--bundle",
         str(bundle), "--out", str(out)]
    )  # fmt: skip

    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert not out.exists()


# -- history --------------------------------------------------------------------------------


def test_history_lists_a_store_it_cannot_read_and_exits_3(engaged, tmp_path, capsys):
    held, _, database = engaged
    customer = engagement.load(held).customer
    not_a_store = tmp_path / "notes.sqlite"
    not_a_store.write_text("not a database\n" * 50)

    code = cli.main(
        ["engagement", "history", "--json", "--customer", customer, "--store", str(database),
         "--store", str(not_a_store)]
    )  # fmt: skip

    assert code == 3
    dossier = emitted(capsys)
    assert str(not_a_store) in json.dumps(dossier)
    assert "acme-2026-10" in json.dumps(dossier)


# -- intake ---------------------------------------------------------------------------------


def test_intake_questionnaire_answers_and_a_draft_the_gate_refuses(tmp_path, capsys):
    questionnaire = tmp_path / "questionnaire.yaml"
    assert cli.main(["engagement", "intake", "--out", str(questionnaire)]) == 0
    assert "Nothing here is checked against your systems" in questionnaire.read_text()
    text_form = tmp_path / "questionnaire.txt"
    assert cli.main(["engagement", "intake", "--text", "--out", str(text_form)]) == 0

    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "servers": [
                    {
                        "name": "customer mcp",
                        "reached_how": "http://mcp.example-customer.test/mcp",
                        "transport": "streamable-http",
                        "version_or_commit": "3.1",
                    }
                ]
            }
        )
    )
    draft = tmp_path / "draft.json"
    capsys.readouterr()

    assert cli.main(
        ["engagement", "intake", "--from", str(answers), "--id", "acme-2026-11", "--out",
         str(draft)]
    ) == 0  # fmt: skip

    assert "still to fill in" in capsys.readouterr().err
    loaded = engagement.load(draft)
    assert loaded.is_draft
    assert loaded.data["declared"]["servers"][0]["version_or_commit"] == "3.1"
    code = cli.main(
        ["drive", "--engagement", str(draft), "--manifest", str(MANIFEST), "--entry",
         "reference-server", "--isolation", "host", "--out-dir", str(tmp_path / "runs")]
    )  # fmt: skip
    assert code == 2
    assert ": draft: " in capsys.readouterr().err


def test_intake_refuses_answers_without_an_id_and_an_existing_out(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text("{}")
    assert cli.main(["engagement", "intake", "--from", str(answers), "--out",
                     str(tmp_path / "d.json")]) == 2  # fmt: skip
    assert "--from needs --id" in capsys.readouterr().err
    existing = tmp_path / "q.yaml"
    existing.write_text("mine")
    assert cli.main(["engagement", "intake", "--out", str(existing)]) == 2
    assert existing.read_text() == "mine"


# -- review, redact, purge ------------------------------------------------------------------

PATTERN = "do not tell the user"


def engaged_with_pattern(tmp_path, capsys, **changes):
    from test_cli_engagement import write_engagement

    held = write_engagement(
        tmp_path / "engagement",
        redaction={"mask_keys": [], "mask_patterns": [PATTERN]},
        **changes,
    )
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
    bundle = tmp_path / "evidence" / "bundle"
    packed(held, out_dir, database, bundle, capsys)
    return held, out_dir, database, bundle


def every_byte(directory):
    return b"".join(p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file())


def test_review_lists_the_surfaces_with_the_values_as_recorded(tmp_path, capsys):
    _, _, _, bundle = engaged_with_pattern(tmp_path, capsys)

    assert cli.main(["evidence", "review", "-q", str(bundle)]) == 0

    assert PATTERN in json.dumps(emitted(capsys))


def test_redact_writes_a_second_bundle_without_the_pattern_and_files_it(tmp_path, capsys):
    held, _, database, bundle = engaged_with_pattern(tmp_path, capsys)
    before = every_byte(bundle)
    handover = tmp_path / "evidence" / "handover"

    code = cli.main(
        ["evidence", "redact", str(bundle), "--engagement", str(held), "--store", str(database),
         "--out", str(handover)]
    )  # fmt: skip

    assert code == 0
    made = emitted(capsys)
    assert every_byte(bundle) == before, "the first bundle is not touched"
    assert PATTERN.encode() not in every_byte(handover)
    assert "mask_patterns[0]" in (handover / "redactions.json").read_text()
    readme = (handover / "CUSTOMER-README.md").read_text()
    assert made["index_digest"] in readme
    assert not (handover / "store.sqlite").exists()
    assert cli.main(["evidence", "verify", "-q", str(handover)]) == 0
    capsys.readouterr()
    with Store.open_read_only(database) as store:
        rows = {row["index_digest"]: row for row in store.bundles()}
    assert rows[made["index_digest"]]["derived_from"] == made["derived_from"]


def test_redact_refuses_a_file_not_of_the_bundle_s_chain(tmp_path, capsys):
    from test_cli_engagement import write_engagement

    _, _, database, bundle = engaged_with_pattern(tmp_path, capsys)
    other = write_engagement(tmp_path / "other", id="other-2026-11")
    handover = tmp_path / "handover"

    code = cli.main(
        ["evidence", "redact", str(bundle), "--engagement", str(other), "--store",
         str(database), "--out", str(handover)]
    )  # fmt: skip

    assert code == 2
    assert not handover.exists()


def test_purge_before_retention_needs_a_reason_and_then_leaves_only_purged_json(tmp_path, capsys):
    held, out_dir, database, bundle = engaged_with_pattern(
        tmp_path, capsys, retention={"delete_after": "2099-12-31"}
    )
    purged = tmp_path / "purged.json"
    argv = ["engagement", "purge", "--store", str(database), "--out-dir", str(out_dir),
            "--author", "A. Operator", "--out", str(purged)]  # fmt: skip

    assert cli.main(argv) == 2
    assert database.exists() and run_directories(out_dir), "nothing was deleted"
    assert not purged.exists()
    capsys.readouterr()

    assert cli.main([*argv, "--before-retention", "the customer asked for it"]) == 0

    record = json.loads(purged.read_text())
    assert record["before_retention_reason"] == "the customer asked for it"
    assert not database.exists()
    assert run_directories(out_dir) == []
    assert not bundle.exists()
    assert purged.stat().st_mode & 0o777 == 0o600
    assert PATTERN not in purged.read_text()


# -- edge cases of attest, redact and filing ------------------------------------------------


def test_an_attestation_inside_a_run_directory_is_refused(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    bundle = tmp_path / "bundle"
    packed(held, out_dir, database, bundle, capsys)
    run_directory = sorted(run_directories(out_dir))[0]
    out = run_directory / "attestation.md"

    code = cli.main(
        ["engagement", "attest", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--bundle",
         str(bundle), "--out", str(out)]
    )  # fmt: skip

    assert code == 2
    assert "lies in the run directory" in capsys.readouterr().err
    assert not out.exists()


def test_redact_refuses_a_store_of_another_engagement(tmp_path, capsys):
    from test_cli_engagement import write_engagement

    held, _, _, bundle = engaged_with_pattern(tmp_path, capsys)
    other = write_engagement(tmp_path / "other", id="other-2026-11")
    elsewhere = tmp_path / "other.sqlite"
    with Store.open(elsewhere) as store:
        from mcp_kymograph import cli as cli_module

        cli_module.set_engagement(store, engagement.load(other))
    handover = tmp_path / "handover"

    code = cli.main(
        ["evidence", "redact", str(bundle), "--engagement", str(held), "--store",
         str(elsewhere), "--out", str(handover)]
    )  # fmt: skip

    assert code == 2
    assert "does not hold the engagement the bundle was packed under" in capsys.readouterr().err
    assert not handover.exists()


def test_a_bundle_is_filed_by_its_absolute_path(engaged, tmp_path, capsys, monkeypatch):
    held, out_dir, database = engaged
    monkeypatch.chdir(tmp_path)

    packed(held, out_dir, database, "relative-bundle", capsys)

    with Store.open_read_only(database) as store:
        (row,) = store.bundles()
    assert row["path"] == str((tmp_path / "relative-bundle").absolute())
