"""What was packed from the store: one row per bundle, by the digest of its index, never twice."""

import pytest

from mcp_kymograph.store import Store, StoreError
from test_store_engagement import FIRST, tables

INDEX = "1d" * 32
EARLIER = "0e" * 32


@pytest.fixture
def database(tmp_path):
    return tmp_path / "findings.sqlite"


def bundle(store, index_digest=INDEX, **changes):
    values = {
        "index_digest": index_digest,
        "path": "bundles/acme-2026-10-01",
        "packed_utc": "2026-10-29T10:00:00.000+00:00",
        "derived_from": None,
        "engagement_digest": FIRST,
    }
    values.update(changes)
    store.file_bundle(**values)
    return values


def test_a_bundle_reads_back_as_filed(database):
    with Store.open(database) as store:
        first = bundle(store, EARLIER, packed_utc="2026-10-28T10:00:00.000+00:00")
        second = bundle(store, derived_from=EARLIER, engagement_digest=None)
        assert store.bundles() == [first, second]
    with Store.open_read_only(database) as reading:
        assert reading.bundles() == [first, second]


def test_a_repeated_index_digest_is_refused_and_nothing_changes(database):
    with Store.open(database) as store:
        bundle(store)
        before = tables(database)
        with pytest.raises(StoreError) as refused:
            bundle(store, path="elsewhere")
        assert str(refused.value) == (
            f"bundle {INDEX}: already filed; a bundle is filed once, by the digest of its "
            "index; nothing is written"
        )
        assert tables(database) == before


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"index_digest": INDEX.upper()}, "index_digest is not 64 lowercase hex characters"),
        ({"index_digest": "sha256:" + INDEX}, "index_digest is not 64 lowercase hex characters"),
        ({"derived_from": "abc"}, "derived_from is not 64 lowercase hex characters"),
        ({"derived_from": INDEX}, "a bundle is not derived from itself"),
        ({"engagement_digest": "x"}, "engagement_digest is not 64 lowercase hex characters"),
        ({"path": ""}, "path is not a non-empty string"),
        ({"path": None}, "path is not a non-empty string"),
        ({"packed_utc": ""}, "packed_utc is not a non-empty string"),
    ],
)
def test_what_is_not_a_bundle_row_is_refused(database, changes, words):
    with Store.open(database) as store:
        before = tables(database)
        with pytest.raises(StoreError) as refused:
            bundle(store, **changes)
        assert words in str(refused.value)
        assert str(refused.value).endswith("; nothing is written")
        assert tables(database) == before
        assert store.bundles() == []
