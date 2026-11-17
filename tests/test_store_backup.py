"""A copy of the whole store, through SQLite's backup API, into a connection the caller opened."""

import sqlite3
from contextlib import closing

import pytest

from mcp_kymograph.store import Store, StoreError
from test_store import finding
from test_store_engagement import engaged, set_engagement, tables
from test_store_triage import IDENTITY


@pytest.fixture
def filled(tmp_path):
    """A store under an engagement with one run, one decision and one bundle, closed again."""
    path = tmp_path / "findings.sqlite"
    with Store.open(path) as store:
        set_engagement(store)
        store.ingest(engaged(tmp_path, [finding(5)]))
        store.triage_set(identity=IDENTITY, role="operator", status="confirmed",
                         author="A. Operator")  # fmt: skip
        store.file_bundle(index_digest="1d" * 32, path="b", packed_utc="2026-10-29T10:00:00Z",
                          derived_from=None, engagement_digest=None)  # fmt: skip
    return path


def contents(store):
    return (
        [info.to_dict() for info in store.runs()],
        store.engagement(),
        store.triage_history(),
        store.findings_with_triage("poison"),
        store.bundles(),
    )


def test_a_backup_of_a_read_only_store_opens_read_only_and_holds_the_same(filled, tmp_path):
    copy = tmp_path / "copy.sqlite"
    before = tables(filled)
    with Store.open_read_only(filled) as store:
        expected = contents(store)
        with closing(sqlite3.connect(copy)) as target:
            store.backup_into(target)

    assert tables(filled) == before, "the original is read, never written"
    with Store.open_read_only(copy) as backed_up:
        assert contents(backed_up) == expected
    assert expected[1]["engagement_digest"] and expected[2] and expected[0]


def test_a_backup_from_a_writable_store_is_the_same(filled, tmp_path):
    copy = tmp_path / "copy.sqlite"
    with Store.open(filled) as store, closing(sqlite3.connect(copy)) as target:
        expected = contents(store)
        store.backup_into(target)
    with Store.open_read_only(copy) as backed_up:
        assert contents(backed_up) == expected


def test_a_backup_into_a_connection_that_cannot_take_it_is_refused(filled, tmp_path):
    target = tmp_path / "target.sqlite"
    sqlite3.connect(target).close()
    with Store.open_read_only(filled) as store:
        read_only = sqlite3.connect(f"{target.absolute().as_uri()}?mode=ro", uri=True)
        with closing(read_only), pytest.raises(StoreError, match="the store cannot be copied"):
            store.backup_into(read_only)
