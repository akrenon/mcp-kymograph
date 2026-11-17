"""Triage and evidence on the command line: ``store triage set|list``, ``store history``,
``evidence pack|verify`` and ``engagement status|preflight`` over runs of the fixture corpus made
under an engagement file.

Every refusal exits 2 and writes nothing; a bundle with one changed byte is not intact (exit 3);
the triage is append-only and keeps both roles' rows side by side.
"""

import json
import re

import pytest

from mcp_kymograph import cli
from mcp_kymograph.store import Store
from test_cli_engagement import MANIFEST, run_directories, write_engagement


@pytest.fixture
def engaged(tmp_path, capsys):
    """An engagement file, two poison runs and one reference run under it, filed in a store."""
    return engagement_with_runs(tmp_path, capsys)


def engagement_with_runs(tmp_path, capsys):
    """What ``engaged`` gives, as a plain function other modules' fixtures can call."""
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"
    for entry in ("poison-server", "poison-server", "reference-server"):
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


def findings_of(database):
    with Store.open_read_only(database) as store:
        return store.findings_by_provenance("poison")


def finding_id(database):
    with Store.open_read_only(database) as store:
        (first, *_) = store.findings_with_triage("poison")
    return first["finding"]


def emitted(capsys):
    return json.loads(capsys.readouterr().out)


# -- store triage ---------------------------------------------------------------------------


def test_two_roles_rows_stand_side_by_side_and_history_keeps_every_row(engaged, capsys):
    _, _, database = engaged
    found = finding_id(database)
    base = ["store", "triage", "set", "-q", "--store", str(database), "--finding", str(found)]

    operator = ["--role", "operator", "--author", "A. Operator"]
    customer = ["--role", "customer", "--author", "C. Customer"]

    confirmed = ["--status", "confirmed"]
    assert cli.main([*base, *operator, *confirmed]) == 0
    first = emitted(capsys)
    accepted = ["--status", "accepted"]
    assert cli.main([*base, *customer, *accepted]) == 0
    capsys.readouterr()
    reread = ["--status", "false_positive"]
    assert cli.main([*base, *operator, *reread]) == 0
    third = emitted(capsys)

    assert third["supersedes"] == first["id"]
    assert cli.main(["store", "triage", "list", "--store", str(database)]) == 0
    current = emitted(capsys)
    assert sorted((row["role"], row["status"]) for row in current) == [
        ("customer", "accepted"),
        ("operator", "false_positive"),
    ]
    assert cli.main(["store", "triage", "list", "--history", "--store", str(database)]) == 0
    assert [row["status"] for row in emitted(capsys)] == [
        "confirmed",
        "accepted",
        "false_positive",
    ]


def test_a_row_can_name_the_identity_as_store_diff_prints_it(engaged, capsys):
    _, _, database = engaged
    (finding, *_) = findings_of(database)
    identity = {
        field: finding[field] for field in ("server", "scenario", "statement", "locator", "signal")
    }

    code = cli.main(
        ["store", "triage", "set", "-q", "--store", str(database), "--identity",
         json.dumps(identity), "--role", "operator", "--status", "open", "--author",
         "A. Operator"]
    )  # fmt: skip

    assert code == 0
    assert emitted(capsys)["identity"] == identity


@pytest.mark.parametrize(
    ("change", "words"),
    [
        (["--finding", "999999"], "no finding"),
        (["--author", ""], "author"),
        (["--status", "intentional"], "not one the operator may set"),
        (["--status", "vulnerable"], "status"),
    ],
)
def test_a_triage_refusal_exits_2_and_writes_nothing(engaged, capsys, change, words):
    _, _, database = engaged
    argv = {
        "--finding": str(finding_id(database)),
        "--role": "operator",
        "--status": "confirmed",
        "--author": "A. Operator",
    }
    for flag, value in zip(change[::2], change[1::2], strict=True):
        argv[flag] = value
    flat = [item for pair in argv.items() for item in pair]

    code = cli.main(["store", "triage", "set", "--store", str(database), *flat])

    assert code == 2
    assert words in capsys.readouterr().err
    with Store.open_read_only(database) as store:
        assert store.triage_history() == []


@pytest.mark.parametrize("given", ["because", "", "--"])
def test_triage_set_refuses_a_rationale_in_one_line_and_writes_nothing(engaged, capsys, given):
    _, _, database = engaged
    before = database.read_bytes()

    code = cli.main(
        ["store", "triage", "set", "--store", str(database), "--finding",
         str(finding_id(database)), "--role", "operator", "--status", "confirmed",
         f"--rationale={given}", "--author", "A. Operator"]
    )  # fmt: skip

    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert err.count("\n") == 1
    assert "does not store a rationale" in err and "operator's private notes" in err
    assert database.read_bytes() == before
    with Store.open_read_only(database) as store:
        assert store.triage_history() == []


@pytest.mark.parametrize("given", ["high", "", "--"])
def test_triage_set_refuses_a_severity_in_one_line_and_writes_nothing(engaged, capsys, given):
    _, _, database = engaged
    before = database.read_bytes()

    code = cli.main(
        ["store", "triage", "set", "--store", str(database), "--finding",
         str(finding_id(database)), "--role", "operator", "--status", "confirmed",
         f"--severity={given}", "--author", "A. Operator"]
    )  # fmt: skip

    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert err.count("\n") == 1
    assert "does not store a severity" in err and "operator's private notes" in err
    assert database.read_bytes() == before
    with Store.open_read_only(database) as store:
        assert store.triage_history() == []


#: Every way to give the option, with a value and without; the part of the line it takes.
GIVEN_FORMS = {
    "equals": lambda flag: [flag + "=X", "--author", "A. Operator"],
    "separate": lambda flag: [flag, "X", "--author", "A. Operator"],
    "at_the_end": lambda flag: ["--author", "A. Operator", flag],
    "before_an_option": lambda flag: [flag, "--author", "A. Operator"],
}


@pytest.mark.parametrize("form", GIVEN_FORMS)
@pytest.mark.parametrize(
    ("flag", "words"),
    [("--rationale", "a rationale"), ("--severity", "a severity")],
)
def test_the_option_is_refused_in_one_line_with_or_without_a_value(
    engaged, capsys, flag, words, form
):
    _, _, database = engaged
    before = database.read_bytes()

    code = cli.main(
        ["store", "triage", "set", "--store", str(database), "--finding",
         str(finding_id(database)), "--role", "operator", "--status", "confirmed",
         *GIVEN_FORMS[form](flag)]
    )  # fmt: skip

    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert err.count("\n") == 1, err
    assert f"does not store {words}" in err and "operator's private notes" in err
    assert "usage" not in err.lower()
    assert database.read_bytes() == before
    with Store.open_read_only(database) as store:
        assert store.triage_history() == []


def test_triage_set_refuses_a_store_that_does_not_exist_and_creates_none(tmp_path, capsys):
    database = tmp_path / "none.sqlite"

    code = cli.main(
        ["store", "triage", "set", "--store", str(database), "--finding", "1", "--role",
         "operator", "--status", "open", "--author", "a"]
    )  # fmt: skip

    assert code == 2
    assert "no such store" in capsys.readouterr().err
    assert not database.exists()


def test_triage_set_refuses_an_identity_that_is_not_json(engaged, capsys):
    _, _, database = engaged
    code = cli.main(
        ["store", "triage", "set", "--store", str(database), "--identity", "{nope", "--role",
         "operator", "--status", "open", "--author", "a"]
    )  # fmt: skip
    assert code == 2
    assert "--identity is not JSON" in capsys.readouterr().err


# -- store history --------------------------------------------------------------------------


def test_history_gives_each_identity_its_cells(engaged, capsys):
    _, _, database = engaged

    assert cli.main(["store", "history", "--store", str(database), "--server",
                     "poison-server"]) == 0  # fmt: skip

    history = emitted(capsys)
    assert history["server"] == "poison-server"
    assert history["identities"]
    for identity in history["identities"]:
        assert {cell["cell"] for cell in identity["cells"]} <= {
            "sighted", "not_sighted", "not_a_result", "not_run", "not_asked", "capped",
            "listing_capped",
        }  # fmt: skip


def test_history_of_a_server_the_store_never_ran_is_refused(engaged, capsys):
    _, _, database = engaged
    assert cli.main(["store", "history", "--store", str(database), "--server", "nobody"]) == 2
    assert "no run of this server" in capsys.readouterr().err


# -- evidence pack and verify ---------------------------------------------------------------


def test_a_bundle_is_packed_filed_and_verified_and_one_changed_byte_is_not_intact(
    engaged, tmp_path, capsys
):
    held, out_dir, database = engaged
    bundle = tmp_path / "evidence" / "acme-2026-10"

    code = cli.main(
        ["evidence", "pack", "-q", "--engagement", str(held), "--store", str(database),
         "--runs", str(out_dir), "--out", str(bundle)]
    )  # fmt: skip

    assert code == 0
    packed = emitted(capsys)
    with Store.open_read_only(database) as store:
        assert [row["index_digest"] for row in store.bundles()] == [packed["index_digest"]]
    assert cli.main(["evidence", "verify", "-q", str(bundle), "--index-digest",
                     packed["index_digest"]]) == 0  # fmt: skip
    assert emitted(capsys)["bundle"] == "intact"

    (recording,) = sorted(bundle.glob("runs/*/events.jsonl"))[:1]
    data = bytearray(recording.read_bytes())
    data[len(data) // 2] ^= 0x01
    recording.write_bytes(bytes(data))

    assert cli.main(["evidence", "verify", "-q", str(bundle)]) == 3
    verified = emitted(capsys)
    assert verified["bundle"] == "not_intact"
    changed = [f for f in verified["files"] if f["state"] == "changed"]
    assert [f["path"] for f in changed] == [str(recording.relative_to(bundle))]


def test_pack_refuses_an_existing_destination_and_writes_nothing(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    code = cli.main(
        ["evidence", "pack", "--engagement", str(held), "--store", str(database), "--runs",
         str(out_dir), "--out", str(bundle)]
    )  # fmt: skip

    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert list(bundle.iterdir()) == []
    with Store.open_read_only(database) as store:
        assert store.bundles() == []


def test_verify_refuses_a_directory_without_an_index(tmp_path, capsys):
    assert cli.main(["evidence", "verify", str(tmp_path)]) == 2
    assert "refused" in capsys.readouterr().err


# -- engagement status and preflight --------------------------------------------------------


def test_status_counts_and_names_no_locator(engaged, capsys):
    _, out_dir, database = engaged

    code = cli.main(["engagement", "status", "--store", str(database), "--out-dir",
                     str(out_dir), "--manifest", str(MANIFEST)])  # fmt: skip

    assert code == 0
    said = capsys.readouterr().out
    assert "acme-2026-10" in said
    for finding in findings_of(database):
        assert finding["locator"] not in said
    assert cli.main(["engagement", "status", "--json", "--store", str(database)]) == 0
    assert emitted(capsys)["engagement_id_declared"] == "acme-2026-10"


def test_status_of_a_store_without_an_engagement_exits_3(tmp_path, capsys):
    database = tmp_path / "empty.sqlite"
    Store.open(database).close()
    assert cli.main(["engagement", "status", "--store", str(database)]) == 3


def test_preflight_touches_nothing_and_exits_by_its_items(engaged, tmp_path, monkeypatch, capsys):
    held, _, _ = engaged
    monkeypatch.setattr("mcp_kymograph.sandbox.docker.image_id", lambda ref: "sha256:" + "0" * 64)

    code = cli.main(["engagement", "preflight", "--json", str(held)])

    assert code in (0, 3)
    result = emitted(capsys)
    assert result["items"]
    assert cli.main(["engagement", "preflight", str(tmp_path / "missing.json")]) == 2


def test_the_new_commands_have_quiet(capsys):
    for argv in (
        ["store", "triage", "list", "--help"],
        ["store", "history", "--help"],
        ["evidence", "pack", "--help"],
        ["evidence", "verify", "--help"],
        ["engagement", "status", "--help"],
        ["engagement", "preflight", "--help"],
    ):
        with pytest.raises(SystemExit):
            cli.main(argv)
        assert "-q, --quiet" in capsys.readouterr().out, argv


# -- edge cases of the store and the pack ---------------------------------------------------


@pytest.mark.parametrize("command", ["status", "pack"])
def test_a_store_that_is_not_a_database_is_refused_not_a_traceback(
    engaged, tmp_path, capsys, command
):
    held, out_dir, _ = engaged
    not_a_store = tmp_path / "notes.txt"
    not_a_store.write_text("not a database\n" * 100)
    argv = {
        "status": ["engagement", "status", "--store", str(not_a_store)],
        "pack": ["evidence", "pack", "--engagement", str(held), "--store", str(not_a_store),
                 "--runs", str(out_dir), "--out", str(tmp_path / "bundle")],
    }[command]  # fmt: skip

    assert cli.main(argv) == 2
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "bundle").exists()


def test_store_findings_gives_the_id_triage_set_takes_and_the_rows_beside(engaged, capsys):
    _, _, database = engaged
    assert cli.main(["store", "findings", "--store", str(database), "--provenance", "poison"]) == 0
    (first, *_) = emitted(capsys)
    assert first["triage"] == {"operator": None, "customer": None}
    assert re.fullmatch(r"fk-[0-9a-f]{16}", first["finding_key"])

    assert cli.main(
        ["store", "triage", "set", "-q", "--store", str(database), "--finding",
         str(first["finding"]), "--role", "customer", "--status", "accepted", "--author",
         "C. Customer"]
    ) == 0  # fmt: skip
    capsys.readouterr()

    assert cli.main(["store", "findings", "--store", str(database), "--provenance", "poison"]) == 0
    again = {row["finding"]: row for row in emitted(capsys)}
    assert again[first["finding"]]["triage"]["customer"]["status"] == "accepted"
    assert again[first["finding"]]["triage"]["operator"] is None
    assert again[first["finding"]]["finding_key"] == first["finding_key"]

    assert cli.main(["store", "triage", "list", "--store", str(database)]) == 0
    (row,) = emitted(capsys)
    assert row["finding_key"] == first["finding_key"], (
        "the key the operator's notes are written with"
    )


def test_a_store_gone_before_filing_is_not_made_anew_and_the_pack_says_so(
    engaged, tmp_path, monkeypatch, capsys
):
    held, out_dir, database = engaged
    real_pack = cli.evidence.pack
    moved = tmp_path / "moved.sqlite"

    def pack_then_move(**given):
        packed = real_pack(**given)
        database.rename(moved)
        return packed

    monkeypatch.setattr(cli.evidence, "pack", pack_then_move)
    bundle = tmp_path / "bundle"

    code = cli.main(
        ["evidence", "pack", "--engagement", str(held), "--store", str(database), "--runs",
         str(out_dir), "--out", str(bundle)]
    )  # fmt: skip

    assert code == 3
    assert "the store did not file it" in capsys.readouterr().err
    assert not database.exists(), "no new, empty store was made to file the bundle in"
    assert (bundle / "index.json").exists(), "the bundle stands as written"


def test_pack_refuses_a_file_not_of_the_store_s_chain(engaged, tmp_path, capsys):
    _, out_dir, database = engaged
    other = write_engagement(tmp_path / "other", id="other-2026-11")

    code = cli.main(
        ["evidence", "pack", "--engagement", str(other), "--store", str(database), "--runs",
         str(out_dir), "--out", str(tmp_path / "bundle")]
    )  # fmt: skip

    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "bundle").exists()


def test_pack_refuses_a_recording_not_found_under_runs(engaged, tmp_path, capsys):
    held, out_dir, database = engaged
    elsewhere = tmp_path / "elsewhere"
    out_dir.rename(elsewhere)
    elsewhere.mkdir(exist_ok=True)
    empty = tmp_path / "empty-runs"
    empty.mkdir()

    code = cli.main(
        ["evidence", "pack", "--engagement", str(held), "--store", str(database), "--runs",
         str(empty), "--out", str(tmp_path / "bundle")]
    )  # fmt: skip

    assert code == 2
    assert "not found" in capsys.readouterr().err
    assert not (tmp_path / "bundle").exists()


def test_pack_refuses_a_destination_in_a_git_working_tree(engaged, tmp_path, capsys):
    import shutil
    import subprocess

    held, out_dir, database = engaged
    git = shutil.which("git")
    assert git, "this test needs a git binary"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=repo, check=True)  # noqa: S603

    code = cli.main(
        ["evidence", "pack", "--engagement", str(held), "--store", str(database), "--runs",
         str(out_dir), "--out", str(repo / "bundle")]
    )  # fmt: skip

    assert code == 2
    assert "git" in capsys.readouterr().err
    assert not (repo / "bundle").exists()
