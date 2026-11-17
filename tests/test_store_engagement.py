"""One engagement, one store: a run is filed only under the engagement the store holds.

A store either holds no engagement and takes only runs made without one, or holds one — its id,
the digest of its current file, and the chain of every version — and takes only runs whose
recorded digest is in that chain. The customer's declaration is filed with each run from the
chain, never from the recording. Every refusal is whole: nothing of the run, or of the
engagement offered, reaches the store. Nothing here touches a key, a state or a comparison.
"""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from mcp_kymograph import cli, fleet
from mcp_kymograph.engagement import REMOVED
from mcp_kymograph.store import REMOVED_FROM_FILE, Store, StoreError
from test_store import finding, recording

FIRST = "e1" * 32
SECOND = "e2" * 32
THIRD = "e3" * 32
NAME = "acme-2026-10"
WINDOW = {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"}
NOW = datetime(2026, 10, 28, 9, 30, tzinfo=timezone.utc)
DECLARED = {"servers": [{"name": "acme-mcp", "version": "1.4.2"}], "notes": "ä"}


def recorded(name=NAME, digest=FIRST, window=WINDOW):
    """``run_started.authorization.engagement`` as the gate writes it."""
    return {"engagement_id_declared": name, "engagement_digest": digest, "window_declared": window}


_RECORDED = object()


def engaged(tmp_path, findings=(), *, engagement=_RECORDED, **options):
    """A corpus recording whose run_started names this engagement (``recorded()`` by default)."""
    path = recording(tmp_path, list(findings), **options)
    lines = path.read_text().splitlines()
    started = json.loads(lines[0])
    started["authorization"]["engagement"] = recorded() if engagement is _RECORDED else engagement
    lines[0] = json.dumps(started)
    path.write_text("\n".join(lines) + "\n")
    return path


def file_declared(name=NAME, supersedes=None, declared=DECLARED, delete_after="2027-01-31"):
    """An engagement file without contacts and reference, as the caller hands it over."""
    sanitized = {
        "version": 1,
        "id": name,
        "customer": "[CUSTOMER NAME]",
        "window": dict(WINDOW),
        "targets": [{"host": "mcp.example-customer.test", "ports": [443], "paths": ["/mcp"]}],
        "retention": {"delete_after": delete_after},
        "supersedes": supersedes,
    }
    if declared is not None:
        sanitized["declared"] = declared
    return sanitized


def set_engagement(store, digest=FIRST, *, name=NAME, supersedes=None, declared=DECLARED,
                   delete_after="2027-01-31", now=NOW, sanitized=None,
                   removed=REMOVED):  # fmt: skip
    store.set_engagement(
        engagement_id_declared=name,
        digest=digest,
        file_declared=(
            file_declared(name, supersedes, declared, delete_after)
            if sanitized is None
            else sanitized
        ),
        supersedes=supersedes,
        delete_after_declared=delete_after,
        removed=removed,
        now=now,
    )


def tables(path):
    """Every row of every table of the store file, read through a connection of its own."""
    with closing(sqlite3.connect(path)) as connection:
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ]
        return {
            name: sorted(repr(row) for row in connection.execute(f"SELECT * FROM {name}"))  # noqa: S608
            for name in names
        }


@pytest.fixture
def database(tmp_path):
    return tmp_path / "findings.sqlite"


@pytest.fixture
def store(database):
    with Store.open(database) as opened:
        yield opened


# -- runs without an engagement -------------------------------------------------------------


def test_a_run_without_an_engagement_files_null_for_all_three(store, database, tmp_path):
    absent = recording(tmp_path, [finding(5)], name="absent")
    null = engaged(tmp_path, [finding(5)], name="null", engagement=None)
    assert json.loads(null.read_text().splitlines()[0])["authorization"]["engagement"] is None

    for path in (absent, null):
        store.ingest(path)

    assert store.engagement() is None
    for info in store.runs():
        row = info.to_dict()
        assert (
            row["engagement_id_declared"],
            row["engagement_digest"],
            row["engagement_declared"],
        ) == (None, None, None)
    with closing(sqlite3.connect(database)) as connection:
        assert (
            connection.execute(
                "SELECT engagement_id_declared, engagement_digest, engagement_declared FROM runs"
            ).fetchall()
            == [(None, None, None)] * 2
        )


@pytest.mark.parametrize(
    ("engagement", "words"),
    [
        ([NAME, FIRST], "is neither null nor an object"),
        ("acme", "is neither null nor an object"),
        (
            {"engagement_id_declared": NAME, "engagement_digest": FIRST},
            "does not have exactly engagement_id_declared, engagement_digest, window_declared",
        ),
        (
            {**recorded(), "customer": "ACME"},
            "does not have exactly engagement_id_declared, engagement_digest, window_declared",
        ),
        (recorded(name=7), "engagement_id_declared is not a non-empty string"),
        (recorded(name=""), "engagement_id_declared is not a non-empty string"),
        (recorded(digest=FIRST.upper()), "engagement_digest is not 64 lowercase hex characters"),
        (recorded(digest=FIRST[:-1]), "engagement_digest is not 64 lowercase hex characters"),
        (recorded(digest="sha256:" + FIRST), "engagement_digest is not 64 lowercase hex"),
        (recorded(digest=None), "engagement_digest is not 64 lowercase hex characters"),
        (recorded(window=None), "window_declared is not exactly from and until, as strings"),
        (recorded(window={"from": "x"}), "window_declared is not exactly from and until"),
        (recorded(window={**WINDOW, "tz": "UTC"}), "window_declared is not exactly from and"),
        (recorded(window={**WINDOW, "until": 5}), "window_declared is not exactly from and"),
    ],
)
def test_a_malformed_recorded_engagement_refuses_the_run_whole(
    store, database, tmp_path, engagement, words
):
    set_engagement(store)
    path = engaged(tmp_path, [finding(5)], engagement=engagement)
    before = tables(database)

    with pytest.raises(StoreError) as refused:
        store.ingest(path)

    assert str(refused.value).startswith(f"{path}: run_started's authorization.engagement")
    assert words in str(refused.value)
    assert tables(database) == before


# -- setting the store's engagement ---------------------------------------------------------


def test_set_on_a_new_store_reads_back_as_written(store, database):
    set_engagement(store)

    expected_entry = {
        "digest": FIRST,
        "file_declared": file_declared(),
        "removed": list(REMOVED),
        "supersedes": None,
        "set_utc": "2026-10-28T09:30:00.000+00:00",
    }
    assert store.engagement() == {
        "engagement_id_declared": NAME,
        "engagement_digest": FIRST,
        "delete_after_declared": "2027-01-31",
        "chain": [expected_entry],
    }
    with closing(sqlite3.connect(database)) as connection:
        meta = dict(connection.execute("SELECT name, value FROM meta").fetchall())
    assert meta.keys() == {
        "schema",
        "engagement_id_declared",
        "engagement_digest",
        "engagement_chain",
        "delete_after_declared",
    }
    assert json.loads(meta["engagement_chain"]) == [expected_entry]
    assert tuple(REMOVED_FROM_FILE) == ("contacts", "reference", "redaction.mask_patterns")


def test_set_reads_back_through_a_store_opened_for_reading(store, database):
    set_engagement(store, now=datetime(2026, 10, 28, 11, 30, tzinfo=timezone(timedelta(hours=2))))
    written = store.engagement()
    store.close()

    with Store.open_read_only(database) as reading:
        assert reading.engagement() == written
        before = tables(database)
        with pytest.raises(StoreError, match="attempt to write a readonly database"):
            set_engagement(reading, SECOND, supersedes=FIRST)
        assert tables(database) == before
    assert written["chain"][0]["set_utc"] == "2026-10-28T09:30:00.000+00:00"


def test_a_file_without_retention_or_declaration_leaves_those_out(store, database, tmp_path):
    set_engagement(store, declared=None, delete_after=None)

    assert store.engagement()["delete_after_declared"] is None
    with closing(sqlite3.connect(database)) as connection:
        names = {row[0] for row in connection.execute("SELECT name FROM meta")}
    assert "delete_after_declared" not in names

    store.ingest(engaged(tmp_path, [finding(5)]))
    (info,) = store.runs()
    assert info.engagement_declared is None
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT engagement_declared FROM runs").fetchall() == [(None,)]


def test_the_same_digest_again_changes_nothing(store, database):
    set_engagement(store)
    before = tables(database)

    set_engagement(store, now=NOW + timedelta(days=1))

    assert tables(database) == before


def test_a_superseding_version_advances_the_chain_and_an_earlier_one_changes_nothing(
    store, database
):
    set_engagement(store)
    set_engagement(store, SECOND, supersedes=FIRST, delete_after="2027-03-31",
                   now=NOW + timedelta(days=2), declared={"servers": []})  # fmt: skip

    held = store.engagement()
    assert held["engagement_id_declared"] == NAME
    assert held["engagement_digest"] == SECOND
    assert held["delete_after_declared"] == "2027-03-31"
    assert [entry["digest"] for entry in held["chain"]] == [FIRST, SECOND]
    assert [entry["supersedes"] for entry in held["chain"]] == [None, FIRST]
    assert held["chain"][1]["file_declared"]["declared"] == {"servers": []}
    assert held["chain"][1]["set_utc"] == "2026-10-30T09:30:00.000+00:00"

    before = tables(database)
    set_engagement(store, FIRST)  # the first version again, still in the chain
    assert tables(database) == before


def refused_setting(store, database, words, **options):
    before = tables(database)
    with pytest.raises(StoreError) as refused:
        set_engagement(store, **options)
    for part in words:
        assert part in str(refused.value)
    assert tables(database) == before
    return str(refused.value)


def test_a_store_holding_runs_of_its_own_does_not_become_an_engagements(store, database, tmp_path):
    store.ingest(recording(tmp_path, [finding(5)]))

    refused_setting(
        store,
        database,
        [
            "this store holds 1 run(s) and 0 fleet run(s) filed without an engagement",
            f"offered engagement {NAME!r} (digest {FIRST})",
            "one store per engagement",
        ],
    )
    assert store.engagement() is None


def test_a_store_holding_a_fleet_of_its_own_does_not_become_an_engagements(store, database):
    store.file_fleet(fleet_row("f0"), [])

    refused_setting(store, database, ["0 run(s) and 1 fleet run(s)"])


def test_another_engagement_is_refused(store, database):
    set_engagement(store)

    refused_setting(
        store,
        database,
        [
            f"this store holds engagement {NAME!r} (digest {FIRST})",
            f"offered engagement 'other-2026-11' (digest {SECOND})",
            "another engagement goes into a store of its own",
        ],
        digest=SECOND,
        name="other-2026-11",
    )
    # Also when the other id claims to supersede this store's file, or names a digest it holds.
    other = {"name": "other-2026-11"}
    refused_setting(store, database, ["one store per engagement"], digest=SECOND, **other,
                    supersedes=FIRST)  # fmt: skip
    refused_setting(store, database, ["one store per engagement"], **other)


def test_engagement_rows_that_do_not_fit_together_are_not_read(store, database):
    set_engagement(store)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DELETE FROM meta WHERE name = 'engagement_digest'")

    with pytest.raises(StoreError, match="the store's engagement rows do not fit together"):
        store.engagement()


def test_a_version_that_does_not_supersede_the_current_one_is_refused(store, database):
    set_engagement(store)
    set_engagement(store, SECOND, supersedes=FIRST)

    for supersedes, named in ((None, "no earlier version"), (FIRST, FIRST)):
        refused_setting(
            store,
            database,
            [
                f"this store holds engagement {NAME!r} (digest {SECOND})",
                f"offered engagement {NAME!r} (digest {THIRD}), which supersedes {named}",
                "must supersede the store's current one",
            ],
            digest=THIRD,
            supersedes=supersedes,
        )


@pytest.mark.parametrize(
    ("options", "words"),
    [
        ({"digest": FIRST.upper()}, "is not 64 lowercase hex characters"),
        ({"name": ""}, "the engagement's id is not a non-empty string"),
        ({"supersedes": "abc"}, "supersedes 'abc', which is not the digest of another file"),
        ({"supersedes": FIRST}, "which is not the digest of another file"),
        ({"delete_after": 20270131}, "delete_after is not a string"),
        ({"sanitized": [("id", NAME)]}, "the file as declared is not a mapping"),
        (
            {"sanitized": {**file_declared(), "contacts": [], "reference": "SOW-1"}},
            "still holds contacts, reference, which it is said to be without or the store "
            "never keeps",
        ),
        (
            {
                "sanitized": {**file_declared(), "redaction": {"mask_patterns": ["ACME-X"]}},
                "removed": (),
            },
            "still holds redaction.mask_patterns, which",
        ),
        (
            {
                "sanitized": {
                    **file_declared(),
                    "declared": {"servers": [{"name": "a", "owner_contact": "x"}]},
                }
            },
            "still holds declared.servers[].owner_contact, which",
        ),
        ({"removed": "contacts"}, "what was removed is not a list of distinct key paths"),
        ({"removed": ["contacts", "contacts"]}, "what was removed is not a list"),
        ({"removed": ["contacts", ""]}, "what was removed is not a list"),
        ({"sanitized": file_declared(name="other")}, "the file's id is 'other', not"),
        ({"sanitized": file_declared(supersedes=SECOND)}, "the file's supersedes is"),
        ({"sanitized": {**file_declared(), "x": float("nan")}}, "cannot be kept as JSON"),
        ({"sanitized": {**file_declared(), "x": {1, 2}}}, "cannot be kept as JSON"),
        ({"now": datetime(2026, 10, 28, 9, 30)}, "has no time zone"),
    ],
)
def test_what_cannot_be_an_engagement_is_refused_before_anything_is_read(
    store, database, options, words
):
    refused_setting(store, database, [words, "nothing is set"], **options)
    assert store.engagement() is None


# -- filing a run under the store's engagement ----------------------------------------------


def test_a_run_under_the_engagement_is_filed_with_the_declaration_from_the_chain(
    store, database, tmp_path
):
    set_engagement(store)
    path = engaged(tmp_path, [finding(5)])

    filed = store.ingest(path)

    (info,) = store.runs()
    assert info.run == filed.run
    assert info.engagement_id_declared == NAME
    assert info.engagement_digest == FIRST
    assert info.engagement_declared == DECLARED
    row = info.to_dict()
    assert row["engagement_id_declared"] == NAME
    assert row["engagement_digest"] == FIRST
    assert row["engagement_declared"] == DECLARED
    with closing(sqlite3.connect(database)) as connection:
        (column,) = connection.execute("SELECT engagement_declared FROM runs").fetchone()
    assert column == '{"notes":"\\u00e4","servers":[{"name":"acme-mcp","version":"1.4.2"}]}'
    # The recording never carried the declaration; the store did.
    assert "acme-mcp" not in path.read_text()


def test_runs_under_each_version_in_the_chain_are_filed_with_that_versions_declaration(
    store, tmp_path
):
    set_engagement(store)
    set_engagement(store, SECOND, supersedes=FIRST, declared=None)
    first = engaged(tmp_path, [finding(5)], name="first")
    second = engaged(tmp_path, [finding(5)], name="second", engagement=recorded(digest=SECOND))

    store.ingest(first)
    store.ingest(second)

    by_digest = {info.engagement_digest: info for info in store.runs()}
    assert by_digest[FIRST].engagement_declared == DECLARED
    assert by_digest[SECOND].engagement_declared is None


def refused_ingest(store, database, path, words):
    before = tables(database)
    with pytest.raises(StoreError) as refused:
        store.ingest(path)
    message = str(refused.value)
    assert message.startswith(f"{path}: ")
    for part in words:
        assert part in message
    assert message.endswith("refusing the whole run")
    assert tables(database) == before
    return message


def test_a_run_with_an_engagement_into_a_store_without_one_is_refused(store, database, tmp_path):
    store.ingest(recording(tmp_path, [finding(5)], name="own"))

    refused_ingest(
        store,
        database,
        engaged(tmp_path, [finding(5)], name="engaged"),
        [
            f"the run was made under engagement {NAME!r} (digest {FIRST})",
            "this store holds no engagement",
            "a store without an engagement takes only runs without one",
        ],
    )


def test_a_run_without_an_engagement_into_a_store_with_one_is_refused(store, database, tmp_path):
    set_engagement(store)

    refused_ingest(
        store,
        database,
        recording(tmp_path, [finding(5)]),
        [
            "the run was made under no engagement",
            f"this store holds engagement {NAME!r} (digest {FIRST})",
            "takes only runs made under it",
        ],
    )


def test_a_run_under_a_digest_not_in_the_chain_is_refused(store, database, tmp_path):
    set_engagement(store)
    set_engagement(store, SECOND, supersedes=FIRST)

    refused_ingest(
        store,
        database,
        engaged(tmp_path, [finding(5)], engagement=recorded(digest=THIRD)),
        [
            f"the run was made under engagement {NAME!r} (digest {THIRD})",
            "a version this store's chain does not hold",
            f"2 version(s) of engagement {NAME!r} (digest {SECOND})",
        ],
    )


def test_a_run_naming_another_id_for_a_digest_in_the_chain_is_refused(store, database, tmp_path):
    set_engagement(store)

    refused_ingest(
        store,
        database,
        engaged(tmp_path, [finding(5)], engagement=recorded(name="other-2026-11")),
        [
            f"the run names engagement 'other-2026-11' with digest {FIRST}",
            f"the file of that digest is engagement {NAME!r} in this store's chain",
            "the recording contradicts the file it names",
        ],
    )


def test_store_ingest_reports_the_refusal_and_exits_two(database, tmp_path, capsys):
    with Store.open(database) as store:
        set_engagement(store)
    path = recording(tmp_path, [finding(5)])
    before = tables(database)

    assert cli.main(["store", "ingest", "--store", str(database), str(path)]) == 2

    err = capsys.readouterr().err
    assert "refused:" in err
    assert "the run was made under no engagement" in err
    assert tables(database) == before


def test_a_fleet_reports_the_refusal_as_a_problem_and_files_nothing(store, database, tmp_path):
    set_engagement(store)
    path = recording(tmp_path, [finding(5)])
    before = tables(database)
    problems = []

    result = fleet._file(
        store, fleet.Job(0, "srv", "scn", "poison"), fleet.Launched(0, path), problems
    )

    assert result.state == fleet.UNFILED
    assert result.run is None
    assert any(
        p.startswith("the store refused the recording: ") and "under no engagement" in p
        for p in result.problems
    )
    assert tables(database) == before


# -- comparisons do not see the engagement --------------------------------------------------


def fleet_row(name, digest="f" * 64):
    return {
        "fleet": name,
        "started_utc": f"2026-10-28T09:0{name[-1]}:00.000+00:00",
        "finished_utc": f"2026-10-28T09:0{name[-1]}:30.000+00:00",
        "manifest_source": "m.yaml",
        "manifest_digest": "sha256:" + "33" * 32,
        "tool_version": "t",
        "tool_content": "sha256:" + "11" * 32,
        "isolation": "host",
        "sandbox_image": None,
        "target_image": None,
        "parallel": 1,
        "processed": json.dumps([["srv", "scn"]]),
        "digest": digest,
        "complete": 1,
        "problems": "[]",
        "rules": 9,
    }


def compared_in(directory, with_engagement):
    """A store with two runs of one entry — the server moved, one finding gone, one new — and
    two fleets filing them: its run diff and its fleet comparison, without the run ids."""
    directory.mkdir()
    later = "sha256:" + "ab" * 32
    asked = [(statement, "hidden_comment") for statement in ("kept", "gone", "new")]
    make = engaged if with_engagement else recording
    pair = [
        make(
            directory,
            [finding(5, statement="kept"), finding(6, statement="gone")],
            name="before",
            asked=asked,
        ),
        make(
            directory,
            [
                finding(5, statement="kept", server_version=later),
                finding(7, statement="new", server_version=later),
            ],
            name="after",
            version=later,
            asked=asked,
        ),
    ]
    with Store.open(directory / "findings.sqlite") as store:
        if with_engagement:
            set_engagement(store)
        runs = [store.ingest(path).run for path in pair]
        for number, run in enumerate(runs, start=1):
            result = {
                "entry": "srv",
                "scenario": "scn",
                "provenance": "poison",
                "state": "complete",
                "exit_code": 0,
                "run": run,
                "problems": [],
            }
            store.file_fleet(fleet_row(f"f{number}", str(number) * 64), [result])
        diff = store.diff(*runs).to_dict()
        fleets = fleet.compare(store, "f1", "f2")
        # runs() orders by time, then by run id, which differs between the two stores.
        infos = sorted((info.to_dict() for info in store.runs()), key=lambda i: i["server_version"])
    for side in ("before", "after"):
        diff.pop(side)
    return diff, fleets, infos


def test_a_diff_and_a_fleet_comparison_are_the_same_with_and_without_an_engagement(tmp_path):
    plain_diff, plain_fleets, plain_runs = compared_in(tmp_path / "plain", False)
    engaged_diff, engaged_fleets, engaged_runs = compared_in(tmp_path / "engaged", True)

    assert plain_diff["moved_axes"] == ["server"]
    assert [c["identity"]["statement"] for c in plain_diff["new"]] == ["new"]
    assert [c["identity"]["statement"] for c in plain_diff["gone"]] == ["gone"]
    assert engaged_diff == plain_diff
    assert engaged_fleets == plain_fleets
    assert plain_fleets["entries"][0]["moved_axes"] == ["server"]

    engagement_fields = ("engagement_id_declared", "engagement_digest", "engagement_declared")
    assert [{k: v for k, v in run.items() if k not in ("run", *engagement_fields)}
            for run in engaged_runs] == [
        {k: v for k, v in run.items() if k not in ("run", *engagement_fields)}
        for run in plain_runs
    ]  # fmt: skip
    assert [run["engagement_digest"] for run in engaged_runs] == [FIRST, FIRST]
    assert [run["engagement_digest"] for run in plain_runs] == [None, None]
