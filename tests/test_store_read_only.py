"""A store opened for reading only: nothing created, nothing changed, another schema refused whole.

``Store.open_read_only`` is how a viewer reads a store. ``Store.open`` creates a missing file and
runs the schema's ``CREATE TABLE IF NOT EXISTS``; this one goes through SQLite's ``mode=ro`` and
leaves every byte of the file as it found it, whatever it is asked.
"""

import hashlib
import sqlite3

import pytest

from mcp_kymograph.store import SCHEMA_VERSION, Store, StoreError
from test_store import recording


def filed(directory, runs=1):
    """A store in ``directory`` holding ``runs`` runs, closed again."""
    path = directory / "findings.sqlite"
    with Store.open(path) as store:
        for number in range(runs):
            store.ingest(recording(directory, [], name=f"run-{number}", entry=f"srv{number}"))
    return path


def state_of(directory):
    """Every file in the directory with the digest of its bytes and its modification time."""
    return {
        path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def test_reads_what_open_reads_and_leaves_every_file_as_it_was(tmp_path):
    path = filed(tmp_path, runs=2)
    with Store.open(path) as written:
        expected_runs = [run.to_dict() for run in written.runs()]
        expected_fleets = written.fleets()
    before = state_of(tmp_path)

    with Store.open_read_only(path) as store:
        assert [run.to_dict() for run in store.runs()] == expected_runs
        assert store.fleets() == expected_fleets
        first, second = (run["run"] for run in expected_runs)
        assert store.diff(first, second).to_dict()["before"]["run"] == first

    assert len(expected_runs) == 2
    assert state_of(tmp_path) == before, "no byte changed, no journal or WAL file left behind"


def test_a_write_through_it_fails_in_sqlite_and_changes_nothing(tmp_path):
    path = filed(tmp_path)
    another = recording(tmp_path, [], name="another", entry="other")
    before = state_of(tmp_path)

    # ingest words every database error as a refusal of the whole run; the cause is SQLite's.
    with (
        Store.open_read_only(path) as store,
        pytest.raises(StoreError, match="attempt to write a readonly database"),
    ):
        store.ingest(another)

    assert state_of(tmp_path) == before


def test_a_missing_file_is_refused_and_not_created(tmp_path):
    path = tmp_path / "absent.sqlite"

    with pytest.raises(StoreError, match="nothing is created"):
        Store.open_read_only(path)

    assert list(tmp_path.iterdir()) == []


def test_a_directory_is_refused(tmp_path):
    with pytest.raises(StoreError, match="no store there"):
        Store.open_read_only(tmp_path)


def test_an_empty_file_is_refused_and_stays_empty(tmp_path):
    """Store.open would make an empty file a new store; read-only, it is not a store at all."""
    path = tmp_path / "empty.sqlite"
    path.touch()

    with pytest.raises(StoreError, match="holds no tables"):
        Store.open_read_only(path)

    assert path.read_bytes() == b""
    assert [p.name for p in tmp_path.iterdir()] == ["empty.sqlite"]


@pytest.mark.parametrize(
    ("schema", "words"),
    [
        (str(int(SCHEMA_VERSION) - 1), "earlier version"),
        (str(int(SCHEMA_VERSION) + 1), "not one this version knows"),
    ],
)
def test_another_schema_is_refused_whole_and_left_as_it_is(tmp_path, schema, words):
    path = filed(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE meta SET value = ? WHERE name = 'schema'", (schema,))
    connection.close()
    before = state_of(tmp_path)

    with pytest.raises(StoreError, match=words) as refused:
        Store.open_read_only(path)

    assert "not even in part" in str(refused.value)
    assert state_of(tmp_path) == before


def test_tables_without_a_schema_are_refused(tmp_path):
    path = tmp_path / "other.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE notes (text TEXT)")
    connection.close()
    before = state_of(tmp_path)

    with pytest.raises(StoreError, match="names no store schema"):
        Store.open_read_only(path)

    assert state_of(tmp_path) == before


def test_a_file_that_is_not_sqlite_is_refused_as_open_refuses_it(tmp_path):
    path = tmp_path / "findings.sqlite"
    path.write_bytes(b"not a database, " * 64)
    before = state_of(tmp_path)

    with pytest.raises(sqlite3.DatabaseError):
        Store.open_read_only(path)

    assert state_of(tmp_path) == before


def test_a_path_with_uri_syntax_in_it_is_the_file_it_names(tmp_path):
    """The path goes into a file: URI; '?', '#', '%' and spaces in it are the file's name."""
    directory = tmp_path / "a?mode=rwc#b %41 c"
    directory.mkdir()
    path = filed(directory)
    before = state_of(directory)

    with Store.open_read_only(path) as store:
        assert len(store.runs()) == 1

    assert state_of(directory) == before


def test_a_store_in_write_ahead_log_mode_is_refused_and_nothing_appears_beside_it(tmp_path):
    """SQLite reads a WAL file only by creating its -wal and -shm files; that would be a write."""
    path = filed(tmp_path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
    connection.close()
    before = state_of(tmp_path)

    with pytest.raises(StoreError, match="write-ahead-log"):
        Store.open_read_only(path)

    assert state_of(tmp_path) == before
    assert sorted(p.name for p in tmp_path.iterdir() if p.suffix != ".jsonl") == ["findings.sqlite"]
