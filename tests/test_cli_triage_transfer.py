"""``store triage export`` and ``store triage import`` on the command line: a store of the
previous schema's triage carried into a new store (http-transport.md 8.4).
The export is written once, ``0600``, and read back; every refusal exits 2 and writes nothing."""

from __future__ import annotations

import json
import sqlite3
import stat
from contextlib import closing

import pytest

from mcp_kymograph import cli
from mcp_kymograph import store as store_module
from mcp_kymograph.store import Store
from test_triage_transfer import by_position, decided, engaged_store, old_store


def export(tmp_path, store, out, capsys):
    code = cli.main(["store", "triage", "export", "--store", str(store), "--out", str(out)])
    return code, capsys.readouterr()


def test_a_store_of_12_s_triage_is_carried_into_a_new_store_with_the_same_history(tmp_path, capsys):
    source, history = decided(tmp_path)
    old = old_store(tmp_path, source)
    out = tmp_path / "carried" / "triage.json"

    code, said = export(tmp_path, old, out, capsys)

    assert code == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "4 triage row(s) of a store of schema 12 written to " in said.err
    assert json.loads(out.read_text())["store_schema"] == "12"

    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    code = cli.main(["store", "triage", "import", "--store", str(fresh), str(out)])
    said = capsys.readouterr()

    assert code == 0
    assert "4 triage row(s) carried into " in said.err
    assert by_position(json.loads(said.out)) == by_position(history)
    assert cli.main(["store", "triage", "list", "--store", str(fresh), "--history"]) == 0
    assert by_position(json.loads(capsys.readouterr().out)) == by_position(history)


def test_an_export_is_never_written_over_a_file(tmp_path, capsys):
    source, _ = decided(tmp_path)
    out = tmp_path / "triage.json"
    out.write_text("kept")

    code, said = export(tmp_path, source, out, capsys)

    assert code == cli.EXIT_REFUSED
    assert "is written once, never over another" in said.err
    assert out.read_text() == "kept"


def test_a_store_of_10_is_not_exported_and_nothing_is_written(tmp_path, capsys):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source, schema="10")
    out = tmp_path / "triage.json"

    code, said = export(tmp_path, old, out, capsys)

    assert code == cli.EXIT_REFUSED
    assert "the triage export reads a store of schema 13 or 12 or 11 only" in said.err
    assert not out.exists()


def test_a_store_of_11_s_triage_is_carried_like_one_of_12(tmp_path, capsys):
    source, history = decided(tmp_path)
    old = old_store(tmp_path, source, schema="11")
    out = tmp_path / "triage.json"

    code, said = export(tmp_path, old, out, capsys)

    assert code == 0
    assert "4 triage row(s) of a store of schema 11 written to " in said.err
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    assert cli.main(["store", "triage", "import", "-q", "--store", str(fresh), str(out)]) == 0
    assert by_position(json.loads(capsys.readouterr().out)) == by_position(history)


def test_an_import_into_no_store_is_refused_and_makes_none(tmp_path, capsys):
    source, _ = decided(tmp_path)
    out = tmp_path / "triage.json"
    assert export(tmp_path, source, out, capsys)[0] == 0

    code = cli.main(["store", "triage", "import", "--store", str(tmp_path / "no.sqlite"), str(out)])

    assert code == cli.EXIT_REFUSED
    assert "no such store" in capsys.readouterr().err
    assert not (tmp_path / "no.sqlite").exists()


def test_a_file_that_is_not_json_is_refused(tmp_path, capsys):
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    given = tmp_path / "triage.json"
    given.write_text("not json")

    code = cli.main(["store", "triage", "import", "--store", str(fresh), str(given)])

    assert code == cli.EXIT_REFUSED
    assert "is not JSON" in capsys.readouterr().err


def test_a_second_import_is_refused_whole(tmp_path, capsys):
    source, history = decided(tmp_path)
    out = tmp_path / "triage.json"
    assert export(tmp_path, source, out, capsys)[0] == 0
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    assert cli.main(["store", "triage", "import", "--store", str(fresh), str(out)]) == 0
    capsys.readouterr()

    code = cli.main(["store", "triage", "import", "--store", str(fresh), str(out)])

    assert code == cli.EXIT_REFUSED
    assert "nothing is written" in capsys.readouterr().err
    with closing(sqlite3.connect(fresh)) as connection:
        (count,) = connection.execute("SELECT count(*) FROM triage").fetchone()
    assert count == len(history)


def test_rows_that_do_not_read_back_as_the_file_has_them_fail_the_import(
    tmp_path, capsys, monkeypatch
):
    """Read what you write back: every field of every row, and each supersession by place."""
    source, _ = decided(tmp_path)
    out = tmp_path / "triage.json"
    assert export(tmp_path, source, out, capsys)[0] == 0
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    honest = Store.import_triage

    def altered(self, document, **kwargs):
        rows = honest(self, document, **kwargs)
        rows[1] = {**rows[1], "author": "someone else"}
        return rows

    monkeypatch.setattr(Store, "import_triage", altered)

    code = cli.main(["store", "triage", "import", "--store", str(fresh), str(out)])

    assert code == cli.EXIT_OUTPUT_FAILED
    assert "do not read back as the file has them: row 2: author" in capsys.readouterr().err


def test_the_refusal_of_a_store_of_11_shows_on_the_terminal_how_its_triage_is_carried(
    tmp_path, capsys
):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source)

    assert cli.main(["store", "runs", "--store", str(old)]) == cli.EXIT_REFUSED

    said = capsys.readouterr().err
    assert "Drive the corpus again into a new store" in said
    assert "store triage export --store" in said and "store triage import" in said


@pytest.mark.parametrize(
    ("damage", "counted"),
    [
        ("ALTER TABLE triage DROP COLUMN severity", "4 rationale(s) of the store are dropped"),
        ("ALTER TABLE triage DROP COLUMN rationale", "2 severity(ies) of the store are dropped"),
    ],
)
def test_a_store_of_12_that_lacks_a_dropped_column_is_exported_and_counts_it_as_0(
    tmp_path, capsys, damage, counted
):
    source, history = decided(tmp_path)
    old = old_store(tmp_path, source)
    with closing(sqlite3.connect(old)) as connection:
        connection.execute(damage)
        connection.commit()
    out = tmp_path / "triage.json"

    code, said = export(tmp_path, old, out, capsys)

    assert code == 0, said.err
    assert counted in said.err and "nothing is exported" not in said.err
    document = json.loads(out.read_text())
    assert len(document["rows"]) == 4 and document["store_schema"] == "12"
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    assert cli.main(["store", "triage", "import", "-q", "--store", str(fresh), str(out)]) == 0
    assert by_position(json.loads(capsys.readouterr().out)) == by_position(history)


@pytest.mark.parametrize("failing", ["_read_export", "_connect_read_only"])
def test_a_read_that_fails_refuses_the_export_whole_and_writes_nothing(
    tmp_path, capsys, monkeypatch, failing
):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source)
    out = tmp_path / "triage.json"

    def broken(*_args, **_kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store_module, failing, broken)

    code, said = export(tmp_path, old, out, capsys)

    assert code == cli.EXIT_REFUSED
    assert "cannot be read (OperationalError: disk I/O error); nothing is exported" in said.err
    assert not out.exists()


def test_the_refusal_of_a_foreign_schema_has_a_space_before_and_no_other(tmp_path, capsys):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source, schema="10")

    code, said = export(tmp_path, old, tmp_path / "triage.json", capsys)

    assert code == cli.EXIT_REFUSED
    assert (
        "the triage export reads a store of schema 13 or 12 or 11 only — this version's and the "
        "two before it — and no other, not even in part; nothing is exported"
    ) in said.err
