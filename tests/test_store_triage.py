"""Triage: decisions kept beside the findings, by identity and role, never changed, never deleted.

A decision is a row of its own, with its author and its role; the next decision on the
same identity and role is a second row that names the first. The store fills what it knows — the
row it supersedes, the engagement it was made under, the time — and refuses whole, writing
nothing, what it cannot keep as given: an identity no finding has, empty or invisible text, text
past its cap, a status that role may not set. Nothing here touches a finding,
its key, a run's state or a comparison.
"""

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_kymograph import store as store_module
from mcp_kymograph.store import IDENTITY_FIELDS, Store, StoreError, finding_key
from test_store import LOCATOR, finding, recording
from test_store_engagement import FIRST, set_engagement, tables
from test_store_engagement import engaged as engaged_recording

NOW = datetime(2026, 10, 29, 9, 0, tzinfo=timezone.utc)
IDENTITY = {
    "server": "srv",
    "scenario": "scn",
    "statement": "st",
    "locator": LOCATOR,
    "signal": "hidden_comment",
}
OTHER = {**IDENTITY, "statement": "other"}


@pytest.fixture
def database(tmp_path):
    return tmp_path / "findings.sqlite"


@pytest.fixture
def store(database, tmp_path):
    with Store.open(database) as opened:
        opened.ingest(recording(tmp_path, [finding(5), finding(6, statement="other")]))
        yield opened


def decide(store, identity=IDENTITY, *, finding=None, role="operator", status="confirmed",
           author="A. Operator", now=NOW):  # fmt: skip
    return store.triage_set(
        identity=None if finding is not None else identity,
        finding=finding,
        role=role,
        status=status,
        author=author,
        now=now,
    )


def finding_id(database, identity=IDENTITY):
    with closing(sqlite3.connect(database)) as connection:
        return connection.execute(
            "SELECT id FROM findings WHERE server = ? AND scenario = ? AND statement = ?"
            " AND locator = ? AND signal = ?",
            tuple(identity[name] for name in IDENTITY_FIELDS),
        ).fetchone()[0]


# -- setting and reading back ---------------------------------------------------------------


def test_a_decision_reads_back_as_it_was_set(store, database):
    written = decide(store)

    expected = {
        "id": 1,
        "identity": IDENTITY,
        "role": "operator",
        "status": "confirmed",
        "author": "A. Operator",
        "at_utc": "2026-10-29T09:00:00.000+00:00",
        "engagement_digest": None,
        "supersedes": None,
        "finding_key": finding_key(tuple(IDENTITY[name] for name in IDENTITY_FIELDS)),
        "imported": None,
    }
    assert written == expected
    assert store.triage_current() == [expected]
    assert store.triage_history() == [expected]
    with closing(sqlite3.connect(database)) as connection:
        (identity,) = connection.execute("SELECT identity FROM triage").fetchone()
    assert identity == json.dumps([IDENTITY[name] for name in IDENTITY_FIELDS])


def test_a_finding_id_names_the_same_identity(store, database):
    written = decide(store, finding=finding_id(database))
    assert written["identity"] == IDENTITY


def test_a_finding_id_of_any_key_with_the_identity_names_it(store, database, tmp_path):
    """Two server versions, two keys, one identity: either id decides on the identity."""
    later = "sha256:" + "bb" * 32
    store.ingest(recording(tmp_path, [finding(5, server_version=later)], name="later",
                           version=later))  # fmt: skip
    with closing(sqlite3.connect(database)) as connection:
        ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM findings WHERE statement = 'st' ORDER BY id"
            )
        ]
    assert len(ids) == 2
    first, second = (decide(store, finding=i, now=NOW + timedelta(minutes=i)) for i in ids)
    assert first["identity"] == second["identity"] == IDENTITY
    assert second["supersedes"] == first["id"]


def test_the_next_decision_supersedes_the_current_one_of_its_role_only(store):
    first = decide(store, status="open")
    customer = decide(store, role="customer", status="accepted", author="C. Customer",
                      now=NOW + timedelta(hours=1))  # fmt: skip
    second = decide(store, status="confirmed", now=NOW + timedelta(hours=2))
    elsewhere = decide(store, OTHER, status="false_positive")

    assert first["supersedes"] is None
    assert customer["supersedes"] is None, "the other role's row is not superseded"
    assert second["supersedes"] == first["id"]
    assert elsewhere["supersedes"] is None
    assert [row["id"] for row in store.triage_history()] == [1, 2, 3, 4]
    assert [row["id"] for row in store.triage_history(IDENTITY)] == [1, 2, 3]
    assert [row["id"] for row in store.triage_history(OTHER)] == [4]
    current = store.triage_current()
    assert [(row["identity"]["statement"], row["role"], row["id"]) for row in current] == [
        ("other", "operator", 4),
        ("st", "customer", 2),
        ("st", "operator", 3),
    ]


def test_a_decision_under_an_engagement_names_its_digest(store, database, tmp_path):
    with Store.open(tmp_path / "engaged.sqlite") as engaged:
        set_engagement(engaged)
        engaged.ingest(engaged_recording(tmp_path, [finding(5)], name="engaged"))
        assert decide(engaged)["engagement_digest"] == FIRST
    assert decide(store)["engagement_digest"] is None


def test_the_findings_carry_their_current_decisions_beside_them(store, database):
    decide(store, status="open")
    decide(store, status="confirmed", now=NOW + timedelta(hours=1))
    decide(store, role="customer", status="accepted", author="C. Customer")

    listed = store.findings_with_triage("poison")
    by_statement = {item["statement"]: item for item in listed}
    assert set(by_statement) == {"st", "other"}
    st = by_statement["st"]
    assert st["finding"] == finding_id(database)
    assert st["server_version_kind"] == "content"
    assert st["triage"]["operator"]["status"] == "confirmed"
    assert st["triage"]["customer"]["status"] == "accepted"
    assert by_statement["other"]["triage"] == {"operator": None, "customer": None}
    # The keys are those findings_by_provenance gives, unchanged.
    plain = store.findings_by_provenance("poison")
    assert [
        {k: v for k, v in item.items() if k not in ("finding", "finding_key", "triage")}
        for item in listed
    ] == (plain)
    assert all("triage" not in item for item in plain)


def test_triage_reads_through_a_store_opened_for_reading(store, database):
    decide(store)
    expected = (
        store.triage_current(),
        store.triage_history(),
        store.findings_with_triage("poison"),
    )
    store.close()
    with Store.open_read_only(database) as reading:
        assert (
            reading.triage_current(),
            reading.triage_history(),
            reading.findings_with_triage("poison"),
        ) == expected
        before = tables(database)
        with pytest.raises(StoreError, match="attempt to write a readonly database"):
            decide(reading)
        assert tables(database) == before


# -- refusals: each writes nothing ----------------------------------------------------------


def refused(store, database, words, **options):
    before = tables(database)
    with pytest.raises(StoreError) as raised:
        decide(store, **options)
    message = str(raised.value)
    assert message.startswith("triage: "), message
    assert words in message, message
    assert message.endswith("; nothing is written"), message
    assert tables(database) == before
    return message


@pytest.mark.parametrize(
    ("options", "words"),
    [
        ({"identity": {**IDENTITY, "statement": "absent"}}, "no finding in this store has"),
        ({"identity": {**IDENTITY, "server": "elsewhere"}}, "no finding in this store has"),
        ({"identity": {k: v for k, v in IDENTITY.items() if k != "signal"}},
         "an identity is exactly server, scenario, statement, locator, signal"),
        ({"identity": {**IDENTITY, "server_version": "x"}},
         "an identity is exactly server, scenario, statement, locator, signal"),
        ({"identity": {**IDENTITY, "locator": 7}}, "every value of an identity is a string"),
        ({"identity": ["srv"]}, "an identity is exactly"),
        ({"finding": 999}, "no finding 999 in this store"),
        ({"finding": True}, "a finding is named by its id, a whole number"),
        ({"finding": "1"}, "a finding is named by its id, a whole number"),
        ({"role": "reviewer"}, "role 'reviewer' is not one of operator, customer"),
        ({"status": "vulnerable"}, "status 'vulnerable' is not one the operator may set"),
        ({"status": 3}, "status 3 is not one the operator may set"),
        ({"author": ""}, "the author is empty"),
        ({"author": "A.\nOperator"}, "the author holds a control, format or other character"),
        ({"author": "A. Operator​"}, "the author holds a control, format or other"),
        ({"author": "a" * 201}, "the author is longer than 200 characters"),
        ({"now": datetime(2026, 10, 29, 9, 0)}, "the time has no time zone"),
    ],
)  # fmt: skip
def test_what_cannot_be_kept_as_given_is_refused_whole(store, database, options, words):
    refused(store, database, words, **options)
    assert store.triage_history() == []


def test_exactly_one_of_identity_and_finding(store, database):
    before = tables(database)
    for identity, chosen in ((IDENTITY, 1), (None, None)):
        with pytest.raises(StoreError, match="name the finding by its identity or by its id"):
            store.triage_set(identity=identity, finding=chosen, role="operator",
                             status="open", author="a")  # fmt: skip
    assert tables(database) == before


@pytest.mark.parametrize("dropped", ["rationale", "severity"])
def test_the_store_keeps_no_rationale_and_no_severity_and_takes_none(store, database, dropped):
    with pytest.raises(TypeError):
        store.triage_set(identity=IDENTITY, role="operator", status="open", author="a",
                         **{dropped: "r"})  # type: ignore[call-arg]  # fmt: skip
    written = decide(store)
    assert dropped not in written
    with closing(sqlite3.connect(database)) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(triage)")]
    assert dropped not in columns


STATUSES = ("open", "confirmed", "false_positive", "accepted", "fixed_pending_recheck",
            "intentional", "question", "fixed")  # fmt: skip
#: Who may set what: every status in both roles, but intentional (the customer's alone) and fixed
#: (the operator's alone).
MAY = {
    (role, status)
    for role in ("operator", "customer")
    for status in STATUSES
    if (role, status) not in (("operator", "intentional"), ("customer", "fixed"))
}
MAY_NOT = {(role, status) for role in ("operator", "customer") for status in STATUSES} - MAY
INSERT = (
    "INSERT INTO triage (identity, role, status, author, at_utc,"
    " engagement_digest, supersedes) VALUES (?, ?, ?, ?, ?, ?, ?)"
)


def schema_row(role, status):
    return (json.dumps([IDENTITY[name] for name in IDENTITY_FIELDS]), role, status, "a",
            "2026-10-29T09:00:00.000+00:00", None, None)  # fmt: skip


def test_the_statuses_are_one_constant_per_role_holding_all_eight():
    statuses = store_module.TRIAGE_STATUSES
    assert {(role, status) for role, held in statuses.items() for status in held} == MAY
    refused_pairs = MAY_NOT
    assert refused_pairs == {("operator", "intentional"), ("customer", "fixed")}


@pytest.mark.parametrize(("role", "status"), sorted(MAY))
def test_each_role_sets_each_status_it_may_and_it_reads_back(store, role, status):
    written = decide(store, role=role, status=status)
    assert (written["role"], written["status"]) == (role, status)
    assert store.triage_history() == [written]
    assert store.triage_current() == [written]


@pytest.mark.parametrize(("role", "status"), sorted(MAY_NOT))
def test_a_status_the_role_may_not_set_is_refused_by_the_store(store, database, role, status):
    allowed = ", ".join(sorted(s for r, s in MAY if r == role))
    message = refused(store, database, f"status {status!r} is not one the {role} may set",
                      role=role, status=status)  # fmt: skip
    assert message == (
        f"triage: status {status!r} is not one the {role} may set; the {role} may set "
        f"{allowed}; nothing is written"
    )
    assert store.triage_history() == []


@pytest.mark.parametrize(("role", "status"), sorted(MAY_NOT))
def test_a_status_the_role_may_not_set_is_refused_by_the_schema_too(store, database, role, status):
    """Past the store's own check, by direct SQL: the database refuses the same pairs."""
    before = tables(database)
    with (
        closing(sqlite3.connect(database)) as connection,
        pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"),
    ):
        connection.execute(INSERT, schema_row(role, status))
    assert tables(database) == before


@pytest.mark.parametrize(("role", "status"), sorted(MAY))
def test_the_schema_takes_every_pair_the_store_takes(store, database, role, status):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(INSERT, schema_row(role, status))
        rows = connection.execute("SELECT role, status FROM triage").fetchall()
    assert rows == [(role, status)]


def test_a_question_an_answer_and_a_fix_after_a_recheck_are_rows_of_their_roles(store):
    """The customer workflow in rows: the operator asks, the customer answers and later says it
    is fixed, the operator confirms the fix from a run."""
    asked = decide(store, status="question")
    customer = {"role": "customer", "author": "C. Customer"}
    answered = decide(store, status="intentional", now=NOW + timedelta(hours=1), **customer)
    pending = decide(
        store, status="fixed_pending_recheck", now=NOW + timedelta(hours=2), **customer
    )
    fixed = decide(store, status="fixed", now=NOW + timedelta(hours=3))
    assert pending["supersedes"] == answered["id"]
    assert fixed["supersedes"] == asked["id"]
    assert {(row["role"], row["status"]) for row in store.triage_current()} == {
        ("operator", "fixed"),
        ("customer", "fixed_pending_recheck"),
    }


# -- never changed, never deleted ------------------------------------------------------------


def test_the_api_offers_no_way_to_change_or_delete_a_row(store, database):
    decide(store)
    public = {name for name in dir(Store) if not name.startswith("_")}
    names = {name for name in public if "triage" in name}
    # import_triage only adds rows, into a store that holds none (test_triage_transfer.py).
    assert names == {
        "triage_set",
        "triage_current",
        "triage_history",
        "findings_with_triage",
        "import_triage",
        "triage_imports",
    }
    for word in ("update", "delete", "remove", "change", "edit", "clear", "undo", "purge"):
        assert not [name for name in dir(Store) if word in name.lower() and "triage" in name]
    # The one statement that writes the table is the INSERT triage_set and import_triage share.
    source = Path(store_module.__file__).read_text()
    assert "UPDATE triage" not in source and "DELETE FROM triage" not in source
    assert source.count("INSERT INTO triage") == 1
    with closing(sqlite3.connect(database)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="a triage row is never changed"):
            connection.execute("UPDATE triage SET status = 'accepted'")
        with pytest.raises(sqlite3.IntegrityError, match="a triage row is never deleted"):
            connection.execute("DELETE FROM triage")
    assert [row["status"] for row in store.triage_history()] == ["confirmed"]


def test_a_decision_changes_no_finding_key_state_or_comparison(store, database, tmp_path):
    run = store.runs()[0].run
    before = (
        store.findings_by_provenance("poison"),
        [info.to_dict() for info in store.runs()],
        store.diff(run, run).to_dict(),
    )
    decide(store, status="false_positive")
    after = (
        store.findings_by_provenance("poison"),
        [info.to_dict() for info in store.runs()],
        store.diff(run, run).to_dict(),
    )
    assert after == before


# -- the finding key of the operator's notes ---------------------------------------------------


def identity_values(identity=IDENTITY):
    return tuple(identity[name] for name in IDENTITY_FIELDS)


def test_the_finding_key_is_fk_and_sixteen_hex_of_the_sha256_of_the_identity():
    key = finding_key(identity_values())
    assert re.fullmatch(r"fk-[0-9a-f]{16}", key)
    shown = json.dumps(list(identity_values()), ensure_ascii=True).encode("utf-8")
    assert key == "fk-" + hashlib.sha256(shown).hexdigest()[:16]


def test_two_identities_have_two_keys():
    keys = {
        finding_key(identity_values(i)) for i in (IDENTITY, OTHER, {**IDENTITY, "locator": "x"})
    }
    assert len(keys) == 3
    assert finding_key(identity_values(IDENTITY)) == finding_key(identity_values(IDENTITY))


def test_the_key_is_the_same_under_every_version_of_the_server(store, database, tmp_path):
    """A re-test rates the same finding at a new version: two keys of a finding, one finding key."""
    later = "sha256:" + "bb" * 32
    store.ingest(recording(tmp_path, [finding(5, server_version=later)], name="later",
                           version=later))  # fmt: skip
    listed = [item for item in store.findings_with_triage("poison") if item["statement"] == "st"]
    assert len(listed) == 2
    assert listed[0]["server_version"] != listed[1]["server_version"]
    assert listed[0]["finding_key"] == listed[1]["finding_key"] == finding_key(identity_values())


def test_the_key_is_shown_beside_the_findings_and_the_decisions(store, database):
    written = decide(store)
    expected = finding_key(identity_values())
    assert written["finding_key"] == expected
    assert store.triage_current()[0]["finding_key"] == expected
    assert store.triage_history(IDENTITY)[0]["finding_key"] == expected
    shown = {
        item["statement"]: item["finding_key"] for item in store.findings_with_triage("poison")
    }
    assert shown == {"st": expected, "other": finding_key(identity_values(OTHER))}
