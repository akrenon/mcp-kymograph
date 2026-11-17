"""Store schema 11: what an engagement needs, in one step, and nothing a store of 10 can be read as.

The step is additive and not migrated, as every step before it: a store of 10 is refused whole by
both ways of opening one. A new store has every table at once — the ``triage`` and ``bundles``
tables too, though only later commands write them — so that one schema number means one layout,
whether the store was opened for writing or only for reading. A triage row is never changed and
never deleted: the database itself refuses it, not only the code that writes the rows.
"""

import sqlite3

import pytest

from mcp_kymograph.store import SCHEMA_VERSION, Store, StoreError
from test_store import recording

TRIAGE_COLUMNS = (
    "INSERT INTO triage (identity, role, status, author, at_utc,"
    " engagement_digest, supersedes) VALUES (?, ?, ?, ?, ?, ?, ?)"
)


def a_row(role="operator", status="confirmed", author="A. Operator"):
    return ('["srv","s","st","loc","sig"]', role, status, author,
            "2026-10-28T00:00:00Z", None, None)  # fmt: skip


def new_store(tmp_path):
    path = tmp_path / "findings.sqlite"
    Store.open(path).close()
    return path


def test_the_schema_is_thirteen():
    assert SCHEMA_VERSION == "13"


def test_the_triage_table_has_no_rationale_and_no_severity_column(tmp_path):
    with sqlite3.connect(new_store(tmp_path)) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(triage)")]
    connection.close()
    assert columns == [
        "id", "identity", "role", "status", "author", "at_utc", "engagement_digest", "supersedes",
    ]  # fmt: skip


def test_a_store_of_ten_is_refused_whole_by_both_ways_of_opening_it(tmp_path):
    path = tmp_path / "findings.sqlite"
    with Store.open(path) as store:
        store.ingest(recording(tmp_path, [], name="run-0", entry="srv0"))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE meta SET value = '10' WHERE name = 'schema'")
    connection.close()
    before = path.read_bytes()

    for opening in (Store.open, Store.open_read_only):
        with pytest.raises(StoreError, match="store schema 10, written by an earlier version"):
            opening(path)

    assert path.read_bytes() == before


def test_a_new_store_has_every_table_index_and_trigger_at_once(tmp_path):
    path = new_store(tmp_path)

    with sqlite3.connect(path) as connection:
        found = {
            (kind, name)
            for kind, name in connection.execute("SELECT type, name FROM sqlite_master")
            if not name.startswith("sqlite_")
        }
        run_columns = [row[1] for row in connection.execute("PRAGMA table_info(runs)")]
    connection.close()

    tables = {name for kind, name in found if kind == "table"}
    assert tables == {
        "meta", "runs", "findings", "sightings", "fleets", "fleet_results", "triage", "bundles",
        "definition_runs", "definitions",
    }  # fmt: skip
    assert ("index", "triage_by_identity") in found
    assert ("trigger", "triage_rows_are_not_changed") in found
    assert ("trigger", "triage_rows_are_not_deleted") in found
    assert run_columns[-4:] == [
        "engagement_id_declared",
        "engagement_digest",
        "engagement_declared",
        "endpoint_certificates",
    ]


def test_the_read_only_open_sees_the_same_layout_as_the_writable_one(tmp_path):
    path = new_store(tmp_path)

    with Store.open_read_only(path) as store:
        assert store._db.execute("SELECT count(*) FROM triage").fetchone() == (0,)
        assert store._db.execute("SELECT count(*) FROM bundles").fetchone() == (0,)


def test_a_run_filed_without_an_engagement_has_none(tmp_path):
    path = tmp_path / "findings.sqlite"
    with Store.open(path) as store:
        store.ingest(recording(tmp_path, [], name="run-0", entry="srv0"))
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT engagement_id_declared, engagement_digest, engagement_declared FROM runs"
        ).fetchone()
    connection.close()

    assert row == (None, None, None)


def test_a_triage_row_is_never_changed_and_never_deleted(tmp_path):
    path = new_store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(TRIAGE_COLUMNS, a_row())
    connection.close()

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="a triage row is never changed"):
            connection.execute("UPDATE triage SET status = 'accepted'")
        with pytest.raises(sqlite3.IntegrityError, match="a triage row is never deleted"):
            connection.execute("DELETE FROM triage")
        assert connection.execute("SELECT status FROM triage").fetchall() == [("confirmed",)]
    finally:
        connection.close()


@pytest.mark.parametrize(
    "row",
    [
        a_row(role="reviewer"),
        a_row(status="vulnerable"),
        a_row(role="operator", status="intentional"),
        a_row(role="customer", status="fixed"),
        a_row(author=""),
    ],
    ids=["role", "status", "intentional-by-operator", "fixed-by-customer", "author"],
)
def test_the_schema_refuses_a_row_outside_its_closed_sets(tmp_path, row):
    path = new_store(tmp_path)
    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            connection.execute(TRIAGE_COLUMNS, row)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("role", "status"),
    [
        ("operator", "open"),
        ("operator", "fixed"),
        ("operator", "question"),
        ("customer", "intentional"),
        ("customer", "question"),
    ],
)
def test_the_schema_holds_every_status_its_role_may_write(tmp_path, role, status):
    path = new_store(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute(TRIAGE_COLUMNS, a_row(role=role, status=status))
        assert connection.execute("SELECT role, status FROM triage").fetchall() == [(role, status)]
    connection.close()
