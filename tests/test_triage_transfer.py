"""Triage carried across a store's schema step: exported from a store of 12 or 13, imported into 13.

A store of the previous schema is refused whole, as every step's was; what a person wrote into it —
its triage — is what no run can produce again, so it is carried: ``export_triage`` is the one
reader of that schema, and reads the ``meta`` rows of the schema and the engagement and the
``triage`` table and nothing else. ``Store.import_triage`` puts the rows into a store of 13 made
from the same recordings, in order, with their own times, authors and roles, under the store's own
ids, and says in ``meta`` that they were carried. Every refusal is whole: nothing is exported,
nothing is written (docs/design/http-transport.md 8.4).

Schema 13 dropped the rationale: a store of 12 exports its rows without it, and an export written
before 13 is imported without it, said in one line with the number.
"""

import hashlib
import json
import sqlite3
import stat
import sys
from contextlib import closing
from datetime import datetime, timezone

import pytest

from mcp_kymograph import cli
from mcp_kymograph import store as store_module
from mcp_kymograph.store import Store, StoreError, export_triage
from schema12_ddl import SCHEMA_12
from test_store import finding, recording
from test_store_engagement import FIRST, SECOND, engaged, set_engagement, tables
from test_store_triage import IDENTITY, OTHER, decide

LATER = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)
IMPORTED = datetime(2026, 11, 2, 8, 0, tzinfo=timezone.utc)
#: Old ids are moved by this much, so that carried rows are told apart from the store's own ids.
OFFSET = 10


def schema_12():
    """Schema 12's DDL (11's triage table is the same), as it was before 13."""
    return SCHEMA_12


def recordings(tmp_path):
    """The same two runs, under the first version of the engagement, for every store here."""
    directory = tmp_path / "runs"
    directory.mkdir(exist_ok=True)
    findings = [finding(5), finding(6, statement="other")]
    return [
        engaged(directory, findings, name="one"),
        engaged(directory, findings[:1], name="two", tool_content="sha256:" + "12" * 32),
    ]


def engaged_store(path, tmp_path, *, versions=(FIRST, SECOND)):
    """A store of 12 holding the engagement in ``versions`` and the recordings."""
    with Store.open(path) as store:
        set_engagement(store, versions[0])
        for path_ in recordings(tmp_path):
            store.ingest(path_)
        for previous, digest in zip(versions, versions[1:], strict=False):
            set_engagement(store, digest, supersedes=previous)
    return path


def decided(tmp_path):
    """A store of 13 with triage from both roles, a supersession, rows under two versions."""
    path = tmp_path / "source.sqlite"
    with Store.open(path) as store:
        set_engagement(store, FIRST)
        for path_ in recordings(tmp_path):
            store.ingest(path_)
        decide(store)
        decide(store, role="customer", status="question", author="C. Customer")
        set_engagement(store, SECOND, supersedes=FIRST)
        decide(store, status="accepted", now=LATER)
        decide(store, OTHER, role="customer", status="intentional", author="C. Customer",
               now=LATER)  # fmt: skip
        history = store.triage_history()
    assert [row["supersedes"] for row in history] == [None, None, 1, None]
    assert {row["engagement_digest"] for row in history} == {FIRST, SECOND}
    return path, history


#: The reason schema 12 kept with every row, and the severity with every other; neither may reach
#: an export, a store or any output.
REASON = "REASON-CANARY-4717"
SEVERITY = "SEVERITY-CANARY-4719"


def severity_of(number):
    """What schema 12 kept as the severity of row ``number``: text for the odd ones, else null."""
    return f"{SEVERITY} {number}" if number % 2 else None


def old_store(tmp_path, source, *, schema="12", name="old.sqlite"):
    """A store of ``schema`` built by its DDL, holding ``source``'s engagement and triage rows
    with their ids moved and a reason each, and a run of its own."""
    path = tmp_path / name
    with closing(sqlite3.connect(path)) as old, closing(sqlite3.connect(source)) as new:
        old.executescript(schema_12())
        old.execute("INSERT INTO meta VALUES ('schema', ?)", (schema,))
        old.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            new.execute("SELECT name, value FROM meta WHERE name <> 'schema'"),
        )
        for row in new.execute("SELECT * FROM triage ORDER BY id"):
            moved = (row[0] + OFFSET, *row[1:4], severity_of(row[0]), f"{REASON} {row[0]}",
                     *row[4:7], None if row[7] is None else row[7] + OFFSET)  # fmt: skip
            old.execute("INSERT INTO triage VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", moved)
        old.commit()
    return path


#: What the reader adds to a row, and an export does not hold.
READ_ONLY = ("imported", "finding_key")


def by_position(rows):
    """The rows with each id replaced by the row's place, ``supersedes`` by the place of the
    row it names, without ``imported``: what must be equal across a transfer, where ids are each
    store's own and only the importing store says where its rows came from."""
    place = {row["id"]: number for number, row in enumerate(rows)}
    return [
        {**{k: v for k, v in row.items() if k not in READ_ONLY}, "id": place[row["id"]],
         "supersedes": None if row["supersedes"] is None else place[row["supersedes"]]}
        for row in rows
    ]  # fmt: skip


def as_held(rows):
    """Rows as the ``triage`` table holds them: without ``imported``, which the reader adds."""
    return [{k: v for k, v in row.items() if k not in READ_ONLY} for row in rows]


def carried(document):
    """The document as a file carries it, and that file's SHA-256."""
    data = json.dumps(document, indent=2).encode()
    return json.loads(data), hashlib.sha256(data).hexdigest()


# -- export, import, the same history --------------------------------------------------------


def test_triage_exported_from_a_store_of_12_is_imported_into_a_new_store_of_13(tmp_path):
    source, history = decided(tmp_path)
    old = old_store(tmp_path, source)
    before = old.read_bytes()

    document = export_triage(old)

    assert old.read_bytes() == before, "read-only: nothing of the old store is written"
    assert document["triage_export_version"] == 1
    assert document["store_schema"] == "12"
    assert REASON not in json.dumps(document), "the reason is not exported"
    assert SEVERITY not in json.dumps(document), "the severity is not exported"
    assert document["store_sha256"] == hashlib.sha256(before).hexdigest()
    assert document["engagement_chain_digests"] == [FIRST, SECOND]
    assert [row["id"] for row in document["rows"]] == [11, 12, 13, 14]
    assert by_position(document["rows"]) == by_position(history)

    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    loaded, digest = carried(document)
    with Store.open(fresh) as store:
        written = store.import_triage(loaded, source_sha256=digest, now=IMPORTED)
        assert written == store.triage_history()
        imports = store._db.execute("SELECT value FROM meta WHERE name = 'triage_imports'")
        (record,) = imports.fetchone()
    assert by_position(written) == by_position(history)
    assert [row["id"] for row in written] == [1, 2, 3, 4], "the store's own ids"
    assert written[2]["supersedes"] == 1, "mapped to the store's own id"
    assert [row["at_utc"] for row in written] == [row["at_utc"] for row in history]
    source_of = {
        "file_sha256": digest,
        "store_sha256": document["store_sha256"],
        "store_schema": "12",
        "at_utc": "2026-11-02T08:00:00.000+00:00",
    }
    assert json.loads(record) == [{**source_of, "rows": 4, "first_id": 1}]
    assert [row["imported"] for row in written] == [source_of] * 4
    assert all(row["imported"] is None for row in history), "written there, not carried"


def test_a_store_of_13_is_exported_too(tmp_path):
    source, history = decided(tmp_path)
    document = export_triage(source)
    assert document["store_schema"] == "13"
    assert document["rows"] == as_held(history)


def test_a_store_without_an_engagement_exports_rows_made_under_none(tmp_path):
    source = tmp_path / "s.sqlite"
    with Store.open(source) as store:
        store.ingest(recording(tmp_path, [finding(5)]))
        decide(store)
    document = export_triage(old_store(tmp_path, source))
    assert document["engagement_chain_digests"] == []
    assert document["rows"][0]["engagement_digest"] is None

    fresh = tmp_path / "fresh.sqlite"
    with Store.open(fresh) as store:
        store.ingest(recording(tmp_path, [finding(5)]))
        (row,) = store.import_triage(document, source_sha256="ab" * 32)
    assert row["engagement_digest"] is None and row["id"] == 1


def test_the_export_reads_nothing_but_meta_and_triage(tmp_path):
    """A store whose runs, findings and sightings are broken or gone exports the same."""
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source)
    whole = export_triage(old)
    with closing(sqlite3.connect(old)) as connection:
        connection.executescript(
            "DROP TABLE runs; CREATE TABLE runs (anything BLOB); INSERT INTO runs VALUES (x'00');"
            "DROP TABLE sightings; DROP TABLE findings; DROP TABLE fleets; DROP TABLE bundles;"
            "INSERT INTO meta VALUES ('something_else', '{not json');"
        )
    again = export_triage(old)
    assert again["store_sha256"] != whole["store_sha256"], "the bytes are not the same"
    assert {**again, "store_sha256": None} == {**whole, "store_sha256": None}


def test_an_empty_triage_is_exported_as_no_rows(tmp_path):
    source = engaged_store(tmp_path / "s.sqlite", tmp_path)
    document = export_triage(old_store(tmp_path, source))
    assert document["rows"] == []


# -- the export refused ----------------------------------------------------------------------


@pytest.mark.parametrize("schema", ["10", "14", "9", "012", "13 "])
def test_a_store_of_any_other_schema_is_not_exported(tmp_path, schema):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source, schema=schema)
    with pytest.raises(StoreError) as refused:
        export_triage(old)
    words = str(refused.value)
    assert f"store schema {schema!r}" in words
    assert "reads a store of schema 13 or 12 or 11 only" in words
    assert words.endswith("nothing is exported")


@pytest.mark.parametrize(
    ("damage", "words"),
    [
        ("DROP TABLE triage", "holds no triage table"),
        ("DROP TABLE meta", "holds no meta table"),
        ("DELETE FROM meta WHERE name = 'schema'", "names no store schema"),
        ("UPDATE meta SET value = '[]' WHERE name = 'engagement_chain'",
         "engagement rows do not fit together"),
        ("DELETE FROM meta WHERE name = 'engagement_digest'",
         "engagement rows do not fit together"),
        ("INSERT INTO triage VALUES (20, 'not json', 'operator', 'open', NULL, 'r', 'a',"
         " '2026-10-29T09:00:00.000+00:00', NULL, NULL)", "row 20: its identity is not five"),
        ("INSERT INTO triage VALUES (20, '[\"a\",\"b\",\"c\",\"d\",\"e\"]', 'operator', 'open',"
         " NULL, 'r', 'a', 'yesterday', NULL, NULL)", "row 20: its at_utc is not a moment"),
        ("INSERT INTO triage VALUES (20, '[\"a\",\"b\",\"c\",\"d\",\"e\"]', 'operator', 'open',"  # noqa: S608
         f" NULL, 'r', 'a', '2026-10-29T09:00:00.000+00:00', '{'e9' * 32}', NULL)",
         "row 20: made under engagement digest e9e9"),
        ("INSERT INTO triage VALUES (20, '[\"a\",\"b\",\"c\",\"d\",\"e\"]', 'operator', 'open',"  # noqa: S608
         f" NULL, 'r', 'a', '2026-10-29T09:00:00.000+00:00', '{FIRST}', 99)",
         "row 20: it supersedes 99, which is no earlier row of the file"),
        ("ALTER TABLE triage DROP COLUMN at_utc", "cannot be read"),
    ],
)  # fmt: skip
def test_a_store_that_does_not_hold_together_is_not_exported(tmp_path, damage, words):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source)
    with closing(sqlite3.connect(old)) as connection:
        connection.execute("DROP INDEX IF EXISTS triage_by_identity")
        connection.execute(damage)
        connection.commit()
    with pytest.raises(StoreError, match="nothing is exported") as refused:
        export_triage(old)
    assert words in str(refused.value)


def test_no_store_at_all_is_not_exported_and_not_created(tmp_path):
    with pytest.raises(StoreError, match="no store there"):
        export_triage(tmp_path / "missing.sqlite")
    assert not (tmp_path / "missing.sqlite").exists()


# -- the import refused, whole ---------------------------------------------------------------


def exported(tmp_path):
    source, _ = decided(tmp_path)
    return export_triage(old_store(tmp_path, source))


def refused_import(tmp_path, document, words, *, fresh=None, digest="ab" * 32):
    fresh = fresh or engaged_store(tmp_path / "new.sqlite", tmp_path)
    before = tables(fresh)
    with Store.open(fresh) as store, pytest.raises(StoreError) as refused:
        store.import_triage(document, source_sha256=digest)
    assert words in str(refused.value)
    assert str(refused.value).startswith("triage import: ")
    assert str(refused.value).endswith("; nothing is written")
    assert tables(fresh) == before, "nothing of the file is written"


def changed_row(document, number, **changes):
    rows = [dict(row) for row in document["rows"]]
    rows[number] = {**rows[number], **changes}
    return {**document, "rows": rows}


def test_a_store_that_holds_triage_already_takes_none(tmp_path):
    document = exported(tmp_path)
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    with Store.open(fresh) as store:
        decide(store)
    refused_import(tmp_path, document, "this store holds 1 triage row(s) already", fresh=fresh)


def test_an_identity_no_finding_of_the_store_has_is_refused(tmp_path):
    document = exported(tmp_path)
    stranger = {**IDENTITY, "locator": "elsewhere"}
    refused_import(tmp_path, changed_row(document, 1, identity=stranger),
                   "row 12: no finding in this store has the identity")  # fmt: skip


def test_a_digest_the_store_s_chain_does_not_hold_is_refused(tmp_path):
    """The store holds only the first version: the rows made under the second do not belong."""
    document = exported(tmp_path)
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path, versions=(FIRST,))
    refused_import(tmp_path, document, f"row 13: made under engagement digest {SECOND}, which "
                   "this store's engagement chain does not hold", fresh=fresh)  # fmt: skip


def test_rows_made_under_an_engagement_go_into_no_store_without_one(tmp_path):
    document = exported(tmp_path)
    fresh = tmp_path / "plain.sqlite"
    with Store.open(fresh) as store:
        store.ingest(recording(tmp_path, [finding(5), finding(6, statement="other")]))
    refused_import(tmp_path, document, "this store's engagement chain does not hold",
                   fresh=fresh)  # fmt: skip


def test_rows_made_under_no_engagement_go_into_no_store_with_one(tmp_path):
    document = exported(tmp_path)
    document = {
        **document,
        "engagement_chain_digests": [],
        "rows": [{**row, "engagement_digest": None} for row in document["rows"]],
    }
    refused_import(tmp_path, document, "row 11: made under no engagement, where this store's "
                   "engagement chain holds one")  # fmt: skip


@pytest.mark.parametrize(
    ("number", "changes", "words"),
    [
        (2, {"supersedes": 14}, "row 13: it supersedes 14, which is no earlier row of the file"),
        (2, {"supersedes": 99}, "row 13: it supersedes 99, which is no earlier row of the file"),
        (2, {"supersedes": "11"}, "row 13: it supersedes '11', which is no earlier row"),
        (2, {"supersedes": None}, "row 13: it supersedes None, where the decision of its "
                                  "identity and role before it is 11"),
        (2, {"supersedes": 12}, "row 13: it supersedes 12, where the decision"),
        (0, {"role": "auditor"}, "row 11: role 'auditor' is not one of operator, customer"),
        (0, {"status": "intentional"}, "row 11: status 'intentional' is not one the operator"),
        (3, {"status": "fixed"}, "row 14: status 'fixed' is not one the customer may set"),
        (0, {"author": "A.\nOperator"}, "row 11: the author holds a control"),
        (0, {"author": None}, "row 11: the author is not a string"),
        (0, {"at_utc": "2026-10-29T09:00:00Z"}, "row 11: its at_utc is not a moment as the "
                                               "store writes one"),
        (0, {"at_utc": "2026-10-29T09:00:00.000"}, "row 11: its at_utc is not a moment"),
        (0, {"engagement_digest": "E1" * 32}, "row 11: its engagement_digest is neither null"),
        (0, {"identity": {**IDENTITY, "locator": 3}}, "row 11: its identity is not exactly"),
        (0, {"id": True}, "row at position 1: its id is not a whole number"),
        (1, {"id": 11}, "row 11: its id is not a whole number above the id of the row before"),
    ],
)  # fmt: skip
def test_a_row_that_is_not_one_is_refused(tmp_path, number, changes, words):
    refused_import(tmp_path, changed_row(exported(tmp_path), number, **changes), words)


def test_a_supersession_across_roles_is_not_the_one_the_store_would_write(tmp_path):
    """The customer's question superseding the operator's decision: not a chain triage_set
    writes, so not one the import writes."""
    refused_import(tmp_path, changed_row(exported(tmp_path), 1, supersedes=11),
                   "row 12: it supersedes 11, where the decision of its identity and role "
                   "before it is None")  # fmt: skip


def test_a_row_with_a_field_more_or_less_is_refused(tmp_path):
    document = exported(tmp_path)
    refused_import(tmp_path, changed_row(document, 0, extra=1), "row 11: a row is exactly id")
    rows = [dict(row) for row in document["rows"]]
    del rows[0]["author"]
    refused_import(tmp_path, {**document, "rows": rows}, "row 11: a row is exactly id")


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"triage_export_version": 2}, "triage_export_version 2 is not 1"),
        ({"triage_export_version": True}, "triage_export_version True is not 1"),
        ({"store_schema": "10"}, "store_schema '10' is not 13 or 12 or 11"),
        ({"store_schema": 13}, "store_schema 13 is not 13 or 12 or 11"),
        ({"engagement_chain_digests": [FIRST, FIRST]}, "engagement_chain_digests is not a list"),
        ({"engagement_chain_digests": FIRST}, "engagement_chain_digests is not a list"),
        ({"rows": {}}, "rows is not a list"),
        ({"rows": ["row"]}, "row at position 1: a row is exactly id"),
        ({"store_sha256": "AB" * 32}, "store_sha256 is not 64 lowercase hex characters"),
        ({"store_sha256": None}, "store_sha256 is not 64 lowercase hex characters"),
        ({"extra": 1}, "a triage export is exactly triage_export_version, store_schema, "
                       "store_sha256, engagement_chain_digests, rows"),
    ],
)  # fmt: skip
def test_a_document_that_is_no_export_is_refused(tmp_path, changes, words):
    refused_import(tmp_path, {**exported(tmp_path), **changes}, words)


def test_a_row_under_a_digest_its_own_export_does_not_name_is_refused(tmp_path):
    document = {**exported(tmp_path), "engagement_chain_digests": [FIRST]}
    refused_import(tmp_path, document, f"row 13: made under engagement digest {SECOND}, which "
                   "the export's engagement chain does not hold")  # fmt: skip


@pytest.mark.parametrize("document", [None, [], "rows"])
def test_no_document_is_refused(tmp_path, document):
    refused_import(tmp_path, document, "a triage export is exactly")


def test_a_row_written_after_the_import_is_not_said_to_be_imported(tmp_path):
    document, digest = carried(exported(tmp_path))
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    with Store.open(fresh) as store:
        store.import_triage(document, source_sha256=digest, now=IMPORTED)
        decide(store, status="accepted", now=LATER)
        history = store.triage_history()
    assert [row["imported"] is None for row in history] == [False] * 4 + [True]


def test_the_command_line_lists_each_row_with_where_it_came_from(tmp_path, capsys):
    """store triage list, with and without --history, as the store reads the rows back; and a
    store whose record of imports cannot be read refused, exit 2, nothing listed."""
    data = json.dumps(exported(tmp_path), indent=2).encode()
    carried_file = tmp_path / "triage.json"
    carried_file.write_bytes(data)
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    assert cli.main(["store", "triage", "import", "-q", "--store", str(fresh),
                     str(carried_file)]) == 0  # fmt: skip
    capsys.readouterr()
    for extra in ([], ["--history"]):
        assert cli.main(["store", "triage", "list", "--store", str(fresh), *extra]) == 0
        listed = json.loads(capsys.readouterr().out)
        assert listed and all(
            row["imported"]["file_sha256"] == hashlib.sha256(data).hexdigest() for row in listed
        )
    with closing(sqlite3.connect(fresh)) as connection, connection:
        connection.execute("UPDATE meta SET value = '7' WHERE name = 'triage_imports'")
    assert cli.main(["store", "triage", "list", "--store", str(fresh), "--history"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and "which triage rows were carried here cannot be told" in err


@pytest.mark.parametrize(
    "record",
    ["{not json", "{}", '[{"sha256": "ab"}]', '[{"file_sha256": "x", "store_sha256": "x", '
     '"store_schema": "11", "rows": 1, "first_id": 1, "at_utc": "t"}]'],
)  # fmt: skip
def test_a_store_whose_imports_cannot_be_read_shows_no_triage_row(tmp_path, record):
    """A row whose origin cannot be told is not shown as one written here."""
    document, digest = carried(exported(tmp_path))
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    with Store.open(fresh) as store:
        store.import_triage(document, source_sha256=digest, now=IMPORTED)
        with store._db:
            store._db.execute("UPDATE meta SET value = ? WHERE name = 'triage_imports'", (record,))
        for read in (store.triage_history, store.triage_current):
            with pytest.raises(StoreError) as refused:
                read()
            assert "which triage rows were carried here cannot be told" in str(refused.value)


def test_the_file_s_digest_is_one(tmp_path):
    refused_import(tmp_path, exported(tmp_path), "the file's SHA-256 is not", digest="x")


def test_a_failed_row_late_in_the_file_leaves_the_earlier_ones_unwritten(tmp_path):
    """Refused whole: the first rows are fine, the last one's identity is no finding's."""
    document = changed_row(exported(tmp_path), 3, identity={**OTHER, "signal": "nothing"})
    refused_import(tmp_path, document, "row 14: no finding in this store has the identity")


# -- the refusal of a store of 12 names the way across ---------------------------------------


def test_a_store_of_12_is_refused_whole_and_told_how_its_triage_is_carried(tmp_path):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source)
    before = old.read_bytes()
    for opening in (Store.open, Store.open_read_only):
        with pytest.raises(StoreError) as refused:
            opening(old)
        words = str(refused.value)
        assert "store schema 12, written by an earlier version of Kymograph" in words
        assert "reads no older store, not even in part" in words
        assert "Drive the corpus again into a new store" in words
        assert (
            f"Its triage can be carried with store triage export --store {old} --out FILE and "
            "store triage import into the new store"
        ) in words
    assert old.read_bytes() == before


def test_a_store_of_11_is_told_the_same_way(tmp_path):
    """Its triage table is the one of 12: the same export, the same words."""
    source, history = decided(tmp_path)
    old = old_store(tmp_path, source, schema="11")
    with pytest.raises(StoreError) as refused:
        Store.open(old)
    assert "store schema 11" in str(refused.value)
    assert f"store triage export --store {old} --out FILE" in str(refused.value)
    document = export_triage(old)
    assert document["store_schema"] == "11"
    assert by_position(document["rows"]) == by_position(history)
    assert REASON not in json.dumps(document) and SEVERITY not in json.dumps(document)
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    loaded, digest = carried(document)
    with Store.open(fresh) as store:
        written = store.import_triage(loaded, source_sha256=digest, now=IMPORTED)
    assert by_position(written) == by_position(history)


# -- the file, as the command line writes it -------------------------------------------------


def test_the_export_is_written_once_owner_only_and_never_over_another(tmp_path):
    """The command line's own writer, given the export: 0600, O_EXCL, refused where a file is."""
    data = json.dumps(exported(tmp_path), indent=2).encode()
    out = tmp_path / "carried" / "triage.json"
    view = cli.TerminalView(sys.stderr)

    assert not cli.refused_destination(view, out, "a triage export")
    assert cli.write_once(view, out, data)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_bytes())["store_schema"] == "12"

    assert cli.refused_destination(view, out, "a triage export")
    assert not cli.write_once(view, out, b"{}")
    assert out.read_bytes() == data


# -- schema 12 to 13: the rationale does not cross ---------------------------------------------


def written_before_13(tmp_path, source):
    """An export as a version of schema 12 wrote it: every row with its ``rationale`` and its
    ``severity`` (null on the even ones)."""
    document = export_triage(old_store(tmp_path, source))
    rows = [
        {**row, "severity": severity_of(row["id"] - OFFSET), "rationale": f"{REASON} {row['id']}"}
        for row in document["rows"]
    ]
    return {**document, "rows": rows}


def test_an_export_written_before_13_is_imported_with_its_status_and_without_its_reason(tmp_path):
    source, history = decided(tmp_path)
    old = written_before_13(tmp_path, source)
    document, digest = carried(old)
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)

    with Store.open(fresh) as store:
        written = store.import_triage(document, source_sha256=digest, now=IMPORTED)

    assert [(r["role"], r["status"]) for r in written] == [
        (r["role"], r["status"]) for r in history
    ]
    assert by_position(written) == by_position(history)
    assert all("rationale" not in row and "severity" not in row for row in written)
    assert REASON.encode() not in fresh.read_bytes()
    assert SEVERITY.encode() not in fresh.read_bytes()
    assert store_module.legacy_dropped(document) == {"rationale": 4, "severity": 2}


@pytest.mark.parametrize("dropped", ["rationale", "severity"])
def test_an_export_of_13_with_a_rationale_or_a_severity_is_refused(tmp_path, dropped):
    source, _ = decided(tmp_path)
    document = export_triage(source)
    rows = [{**row, dropped: "kept"} for row in document["rows"]]
    refused_import(tmp_path, {**document, "rows": rows}, "row 1: a row is exactly id")


def test_the_import_says_in_one_line_how_many_reasons_and_severities_it_dropped(tmp_path, capsys):
    source, _ = decided(tmp_path)
    path = tmp_path / "before-13.json"
    path.write_text(json.dumps(written_before_13(tmp_path, source)))
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)

    assert cli.main(["store", "triage", "import", "-q", "--store", str(fresh), str(path)]) == 0

    out, err = capsys.readouterr()
    assert REASON not in out + err and SEVERITY not in out + err
    lines = [line for line in err.splitlines() if "rationale" in line]
    assert len(lines) == 1
    assert lines[0].endswith(
        "4 rationale(s) and 2 severity(ies) in the file are dropped, not carried: the tool keeps "
        "none; keep them in the operator's private notes"
    )
    assert "rationale" not in out and "severity" not in out


def test_the_export_of_a_store_of_12_says_how_many_reasons_and_severities_it_leaves_behind(
    tmp_path, capsys
):
    source, _ = decided(tmp_path)
    old = old_store(tmp_path, source)
    out_file = tmp_path / "carried.json"

    assert cli.main(["store", "triage", "export", "-q", "--store", str(old),
                     "--out", str(out_file)]) == 0  # fmt: skip

    out, err = capsys.readouterr()
    assert REASON not in out + err + out_file.read_text()
    assert SEVERITY not in out + err + out_file.read_text()
    assert "4 rationale(s) and 2 severity(ies) of the store are dropped, not written" in err
    assert err.count("rationale") == 1


def test_the_export_of_a_store_of_13_has_nothing_to_say_of_reasons_or_severities(tmp_path, capsys):
    source, _ = decided(tmp_path)

    assert cli.main(["store", "triage", "export", "--store", str(source),
                     "--out", str(tmp_path / "carried.json")]) == 0  # fmt: skip

    err = capsys.readouterr().err
    assert "rationale" not in err and "severity" not in err
