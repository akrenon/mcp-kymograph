"""The end of an engagement: ``evidence.purge`` and ``purged.json``.

Everything lives under ``tmp_path``: an engagement with a retention date, corpus runs driven
under it, a refusal it wrote down, a store, and a bundle packed and filed in the store. A purge
that is refused deletes nothing — every byte under the work directory is checked — and one that
runs leaves only ``purged.json``, which names ids, digests, paths and outcomes and no customer
data.
"""

import builtins
import io
import json
import os
import shutil
import stat
import sys
import unicodedata
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, evidence
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
CUSTOMER = "CUSTOMER-CANARY-8841"
CONTACT = "CONTACT-CANARY-8842"
REFERENCE = "REFERENCE-CANARY-8843"
KEPT_UNTIL = date.today() + timedelta(days=30)
BEFORE = datetime.now(timezone.utc)
AFTER = datetime(KEPT_UNTIL.year, KEPT_UNTIL.month, KEPT_UNTIL.day, tzinfo=timezone.utc) + (
    timedelta(days=1)
)


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_engagement(directory: Path, **changes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    listed = directory / "all-signals.yaml"
    shutil.copyfile(FIXTURES / "scenarios" / "all-signals.yaml", listed)
    now = datetime.now(timezone.utc)
    data = {
        "version": 1,
        "id": "acme-2026-10",
        "customer": CUSTOMER,
        "reference": REFERENCE,
        "contacts": [{"name": CONTACT, "role": "lead", "reach": "phone"}],
        "window": {"from": utc(now - timedelta(days=1)), "until": utc(now + timedelta(days=1))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": [
            {"path": "all-signals.yaml", "sha256": sha256(listed.read_bytes()).hexdigest()}
        ],
        "actions": {"list": True, "call": False},
        "retention": {"delete_after": KEPT_UNTIL.isoformat()},
    }
    data.update(changes)
    path = directory / "engagement.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def drive(out_dir: Path, *argv: str) -> Path:
    before = set(out_dir.glob("*/events.jsonl")) if out_dir.exists() else set()
    assert cli.main(["drive", "-q", "--out-dir", str(out_dir), *argv]) == 0
    (recording,) = set(out_dir.glob("*/events.jsonl")) - before
    return recording


class Work:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.held_path = write_engagement(root / "engagement")
        self.held = engagement.load(self.held_path)
        self.runs = root / "runs"
        corpus = ["--manifest", str(FIXTURES / "corpus" / "manifest.yaml"), "--entry",
                  "reference-server", "--isolation", "host"]  # fmt: skip
        self.recordings = [
            drive(self.runs, "--engagement", str(self.held_path), *corpus) for _ in range(2)
        ]
        refused = ["drive", "-q", "--engagement", str(self.held_path), "--manifest",
                   str(FIXTURES / "corpus" / "manifest.yaml"), "--entry", "no-such-entry",
                   "--out-dir", str(self.runs)]  # fmt: skip
        assert cli.main(refused) == 2
        self.store = root / "store.sqlite"
        assert cli.main(
            ["store", "ingest", "-q", "--store", str(self.store), "--engagement",
             str(self.held_path), *map(str, self.recordings)]
        ) == 0  # fmt: skip
        self.bundle = root / "bundles" / "final"
        packed = evidence.pack(
            engagement=self.held, store_path=self.store, runs_dir=self.runs, out=self.bundle
        )
        with Store.open(self.store) as held:
            held.file_bundle(
                index_digest=packed.index_digest,
                path=str(self.bundle),
                packed_utc=packed.packed_utc,
                derived_from=None,
                engagement_digest=packed.engagement_digest,
            )
        self.index_digest = packed.index_digest
        self.out = root / "record" / "purged.json"

    def purge(self, **changes) -> evidence.Purged:
        arguments = {
            "store_path": self.store,
            "out_dir": self.runs,
            "author": "A. Operator",
            "out": self.out,
            "now": AFTER,
        }
        arguments.update(changes)
        return evidence.purge(**arguments)


@pytest.fixture
def work(tmp_path) -> Work:
    return Work(tmp_path / "work")


def snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        str(path): (path.read_bytes() if path.is_file() else None)
        for path in sorted(root.rglob("*"))
    }


def refused(work: Work, words: str, **changes) -> str:
    before = snapshot(work.root)
    with pytest.raises(evidence.EvidenceError) as caught:
        work.purge(**changes)
    said = str(caught.value)
    assert said.startswith("refused: ")
    assert words in said, said
    assert snapshot(work.root) == before, "a refused purge deletes nothing and writes nothing"
    return said


# -- a purge that runs -----------------------------------------------------------------------


def test_after_retention_everything_goes_and_purged_json_says_so(work):
    run_directories = sorted(path.parent for path in work.recordings)

    purged = work.purge()

    assert purged.complete
    for path in (*run_directories, work.bundle, work.store, work.runs / "refusals.jsonl"):
        assert not path.exists(), path
    assert work.runs.is_dir(), "the out-dir itself stays; what was in it of the engagement went"
    kinds = [(item.kind, item.outcome) for item in purged.paths]
    assert kinds.count(("run_directory", "deleted")) == 2
    assert ("refusals", "deleted") in kinds
    assert ("bundle", "deleted") in kinds
    assert ("store", "deleted") in kinds
    assert purged.engagement_id_declared == "acme-2026-10"
    assert purged.engagement_digest == work.held.digest
    assert purged.chain == (work.held.digest,)
    assert purged.bundles == (work.index_digest,)
    assert purged.author == "A. Operator"
    assert purged.before_retention_reason is None
    assert purged.delete_after_declared == KEPT_UNTIL.isoformat()
    assert stat.S_IMODE(work.out.stat().st_mode) == 0o600
    assert stat.S_IMODE(work.out.parent.stat().st_mode) == 0o700


def test_purged_json_round_trips(work):
    purged = work.purge()
    raw = work.out.read_bytes()
    again = evidence.read_purged(work.out)
    assert again == purged
    assert evidence.canonical_json(again.to_dict()) == raw


def test_purged_json_holds_no_customer_data(work):
    work.purge()
    raw = work.out.read_bytes()
    for canary in (CUSTOMER, CONTACT, REFERENCE):
        assert canary.encode() not in raw


def test_before_retention_with_a_reason_purges_and_records_the_reason(work):
    purged = work.purge(now=BEFORE, before_retention_reason="the customer asked, ticket 12")
    assert purged.complete
    assert purged.before_retention_reason == "the customer asked, ticket 12"
    assert evidence.read_purged(work.out).before_retention_reason == (
        "the customer asked, ticket 12"
    )
    assert not work.store.exists()


def test_the_last_day_of_retention_is_still_before_it(work):
    last = AFTER - timedelta(seconds=1)
    refused(work, "kept until the end of", now=last)


def test_a_bundle_already_gone_is_missing_and_the_purge_complete(work):
    shutil.rmtree(work.bundle)
    purged = work.purge()
    assert purged.complete
    assert ("bundle", "missing") in [(item.kind, item.outcome) for item in purged.paths]


@pytest.mark.skipif(getattr(os, "geteuid", lambda: 0)() == 0, reason="root deletes everything")
def test_a_path_that_cannot_be_deleted_is_listed_and_the_purge_not_complete(work):
    stuck = work.recordings[0].parent
    stuck.chmod(0o500)
    try:
        purged = work.purge()
    finally:
        stuck.chmod(0o700)

    assert not purged.complete
    (failed,) = [item for item in purged.paths if not item.gone]
    assert failed.path == str(stuck)
    assert failed.outcome.startswith("failed: ")
    assert evidence.read_purged(work.out) == purged
    assert not work.store.exists(), "the rest went"


# -- the refusals of purge --------------------------------------------------------------------


def test_before_retention_without_a_reason_is_refused(work):
    said = refused(work, "kept until the end of", now=BEFORE)
    assert KEPT_UNTIL.isoformat() in said


def test_a_missing_author_is_refused(work):
    refused(work, "no author", author="  ")


def test_a_foreign_recording_under_the_out_dir_refuses_whole(work):
    foreign = drive(
        work.runs, "--", sys.executable, str(FIXTURES / "discovery_server.py")
    )  # made under no engagement
    said = refused(work, "not this engagement's")
    assert str(foreign) in said


def test_a_recording_of_another_engagement_refuses_whole(work, tmp_path):
    other = write_engagement(tmp_path / "other", id="other-2026-11")
    drive(work.runs, "--engagement", str(other), "--", sys.executable,
          str(FIXTURES / "discovery_server.py"))  # fmt: skip
    said = refused(work, "no digest of the store's chain")
    assert engagement.load(other).digest in said


def test_a_bundle_filed_under_another_engagement_refuses_whole(work):
    with Store.open(work.store) as held:
        held.file_bundle(
            index_digest="e" * 64,
            path=str(work.root / "elsewhere"),
            packed_utc="2026-10-29T00:00:00Z",
            derived_from=None,
            engagement_digest="f" * 64,
        )
    refused(work, "no digest of its chain")


def test_a_foreign_refusals_file_refuses_whole(work):
    line = json.loads((work.runs / "refusals.jsonl").read_text().splitlines()[0])
    line["engagement"]["engagement_digest"] = "f" * 64
    nested = work.runs / "fleet" / "001-x"
    nested.mkdir(parents=True)
    (nested / "refusals.jsonl").write_text(json.dumps(line) + "\n")
    refused(work, "no digest of the store's chain")


def test_an_out_inside_what_is_deleted_is_refused(work):
    refused(work, "which the purge deletes", out=work.bundle / "purged.json")


def test_an_existing_out_is_refused(work):
    work.out.parent.mkdir()
    work.out.write_text("mine")
    refused(work, "exists")


def test_a_store_without_an_engagement_is_refused(work, tmp_path):
    empty = tmp_path / "empty.sqlite"
    Store.open(empty).close()
    refused(work, "holds no engagement", store_path=empty)


@pytest.mark.parametrize(
    ("change", "words"),
    [
        (lambda d: d.update(extra=1), "unknown key"),
        (lambda d: d.update(author=""), "author"),
        (lambda d: d["paths"][0].update(outcome="gone"), "outcome"),
        (lambda d: d["paths"][0].update(kind="file"), "kind"),
        (lambda d: d.update(chain=["x"]), "chain"),
    ],
)
def test_read_purged_refuses_whole(work, tmp_path, change, words):
    work.purge()
    data = json.loads(work.out.read_text())
    change(data)
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(data))
    with pytest.raises(evidence.EvidenceError, match=words):
        evidence.read_purged(broken)


# -- what a purge must not count as gone -----------------------------------------------------


def test_a_filed_run_not_found_under_the_out_dir_leaves_the_purge_not_complete(work, tmp_path):
    empty = tmp_path / "empty-out-dir"
    empty.mkdir()

    purged = work.purge(out_dir=empty)

    assert not purged.complete
    unfound = [item for item in purged.paths if item.outcome == evidence.NOT_FOUND]
    assert len(unfound) == 2
    assert {item.kind for item in unfound} == {"run_directory"}
    for recording in work.recordings:
        assert recording.exists(), "it was not under the out-dir, and it is still there"
    assert evidence.read_purged(work.out) == purged


def test_purged_json_says_what_a_purge_does_not_reach(work):
    purged = work.purge()
    assert purged.not_covered == evidence.NOT_COVERED
    said = json.loads(work.out.read_text())["not_covered"]
    assert "--session recordings outside the out-dir" in said
    assert any("report.md" in item for item in said)
    assert "the attestation" in said
    assert "intake answers and drafts" in said


def test_a_store_that_is_a_link_is_refused(work, tmp_path):
    link = tmp_path / "store-link.sqlite"
    link.symlink_to(work.store)
    refused(work, "is a symbolic link", store_path=link)
    assert work.store.exists()


def _file_bundle(work: Work, path: Path, digest: str = "d" * 64) -> None:
    with Store.open(work.store) as held:
        held.file_bundle(
            index_digest=digest,
            path=str(path),
            packed_utc="2026-10-29T00:00:00Z",
            derived_from=None,
            engagement_digest=work.held.digest,
        )


def test_a_bundle_that_is_a_link_is_refused(work):
    link = work.root / "bundle-link"
    link.symlink_to(work.bundle)
    _file_bundle(work, link)
    refused(work, "is a symbolic link")


def test_a_bundle_link_to_the_out_dir_cannot_hide_a_foreign_run(work):
    drive(work.runs, "--", sys.executable, str(FIXTURES / "discovery_server.py"))
    link = work.root / "runs-link"
    link.symlink_to(work.runs)
    _file_bundle(work, link)
    refused(work, "is a symbolic link")


def test_a_bundle_filed_under_a_relative_path_is_refused(work):
    _file_bundle(work, Path("bundles/elsewhere"))
    refused(work, "relative path")


def test_a_bundle_holding_something_its_index_does_not_list_is_refused(work):
    foreign = work.bundle / "runs" / "20261029T000000Z-0badc0de"
    foreign.mkdir(parents=True)
    (foreign / "events.jsonl").write_text("{}\n")
    said = refused(work, "holds what its index does not list")
    assert "events.jsonl" in said


def test_a_bundle_goes_with_its_readme_and_signature(work):
    (work.bundle / "index.json.sig").write_bytes(b"signed elsewhere")
    purged = work.purge()
    assert purged.complete
    assert ("bundle", "deleted") in [(item.kind, item.outcome) for item in purged.paths]
    assert not work.bundle.exists()


# -- the operator's notes beside the store ------------------------------------------------------

NOTES_CANARY = "NOTES-CANARY-8851"


def _notes(work: Work, suffix: str = ".yaml") -> Path:
    path = work.store.with_name(f"{work.store.name}.operator-notes{suffix}")
    path.write_text(f"engagement: acme-2026-10\nfindings: {{}}\n# {NOTES_CANARY}\n")
    return path


def test_the_operator_s_notes_go_with_the_store_and_purged_json_names_them_deleted(
    work, monkeypatch
):
    notes = _notes(work)
    opened: list[str] = []
    for module, name in ((os, "open"), (io, "open"), (builtins, "open")):
        original = getattr(module, name)

        def watching(path, *args, _original=original, **kwargs):
            opened.append(os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else "")
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(module, name, watching)

    purged = work.purge()

    assert purged.complete and not notes.exists()
    assert [
        (item.path, item.outcome) for item in purged.paths if item.kind == "operator_notes"
    ] == [(str(notes), "deleted")]
    assert str(work.out) in opened, "the watch sees what the purge opens"
    assert str(notes) not in opened and not [p for p in opened if "operator-notes" in p], (
        "deleting the notes is not reading them"
    )
    monkeypatch.undo()
    raw = work.out.read_text()
    assert NOTES_CANARY not in raw
    assert not [item for item in purged.not_covered if "notes" in item]
    again = evidence.read_purged(work.out)
    assert again == purged
    assert {"path": str(notes), "kind": "operator_notes", "outcome": "deleted"} in json.loads(raw)[
        "paths"
    ]


def test_every_suffix_of_the_notes_goes(work):
    noted = [_notes(work, suffix) for suffix in (".yaml", ".yml", ".json")]
    purged = work.purge()
    assert [item.path for item in purged.paths if item.kind == "operator_notes"] == [
        str(path) for path in noted
    ]
    assert not [path for path in noted if path.exists()]


def test_without_notes_purged_json_still_names_them_as_missing(work):
    purged = work.purge()
    (listed,) = [item for item in purged.paths if item.kind == "operator_notes"]
    assert listed.path == f"{work.store}.operator-notes.yaml"
    assert listed.outcome == "missing" and listed.gone and purged.complete


def test_notes_of_another_store_in_the_same_directory_stay(work):
    other = work.store.with_name("other.sqlite.operator-notes.yaml")
    other.write_text("engagement: other\nfindings: {}\n")
    work.purge()
    assert other.read_text() == "engagement: other\nfindings: {}\n"


def test_notes_that_are_a_link_are_refused(work, tmp_path):
    kept = tmp_path / "elsewhere.yaml"
    kept.write_text("engagement: acme\nfindings: {}\n")
    work.store.with_name(f"{work.store.name}.operator-notes.yml").symlink_to(kept)
    refused(work, "is a symbolic link")
    assert kept.exists()


def test_notes_that_are_a_directory_are_refused(work):
    work.store.with_name(f"{work.store.name}.operator-notes.json").mkdir()
    refused(work, "is not a file")


def _case_sensitive(directory: Path) -> bool:
    probe = directory / "case-probe"
    probe.write_text("")
    try:
        return not (directory / "CASE-PROBE").exists()
    finally:
        probe.unlink()


def test_notes_with_an_upper_case_suffix_go_and_are_listed_by_their_name(work):
    """``operator_notes.load`` takes a suffix in any case: so does the purge, which finds the
    notes among the directory's entries instead of guessing their names, and lists them under
    the name they have."""
    notes = _notes(work, ".YAML")
    purged = work.purge()
    assert [
        (item.path, item.outcome) for item in purged.paths if item.kind == "operator_notes"
    ] == [(str(notes), "deleted")]
    assert not notes.exists() and purged.complete


@pytest.mark.parametrize(
    "suffixes", [(".yaml", ".YAML"), (".Yml", ".JSON")], ids=["one-suffix", "two-suffixes"]
)
def test_every_notes_file_beside_the_store_goes_whatever_its_case(work, suffixes):
    """Each notes file found is deleted and listed. Only the suffix may differ in case: a name
    that differs in the store's name or in ``.operator-notes`` is another store's, or no notes
    at all, and stays."""
    if not _case_sensitive(work.store.parent):
        pytest.skip("the file system does not tell names apart by case")
    noted = [_notes(work, suffix) for suffix in suffixes]
    kept = [
        work.store.with_name(f"{work.store.name.upper()}.operator-notes.yaml"),
        work.store.with_name(f"{work.store.name}.OPERATOR-NOTES.yaml"),
        work.store.with_name(f"{work.store.name}.operator-notes.yaml.bak"),
        work.store.with_name(f"{work.store.name}.operator-notes.txt"),
    ]
    for path in kept:
        path.write_text("engagement: other\nfindings: {}\n")
    purged = work.purge()
    listed = [item for item in purged.paths if item.kind == "operator_notes"]
    assert sorted(item.path for item in listed) == sorted(str(path) for path in noted)
    assert {item.outcome for item in listed} == {"deleted"}
    assert not [path for path in noted if path.exists()] and purged.complete
    assert all(path.read_text() == "engagement: other\nfindings: {}\n" for path in kept)


def test_notes_with_an_upper_case_suffix_that_are_a_link_are_refused(work, tmp_path):
    kept = tmp_path / "elsewhere.yaml"
    kept.write_text("engagement: acme\nfindings: {}\n")
    work.store.with_name(f"{work.store.name}.operator-notes.YML").symlink_to(kept)
    refused(work, "is a symbolic link")
    assert kept.exists()


def test_notes_with_an_upper_case_suffix_that_are_a_directory_are_refused(work):
    work.store.with_name(f"{work.store.name}.operator-notes.Json").mkdir()
    refused(work, "is not a file")


def _listed_as(monkeypatch, directory: Path, spelled) -> None:
    """``os.listdir`` of ``directory`` gives each name as ``spelled`` makes it: the name on disk
    of a file system that resolves the name the purge was given to the same file — NFD where
    the shell wrote NFC (macOS), another case (a case-insensitive file system)."""
    listdir = os.listdir

    def listing(path="."):
        names = listdir(path)
        return [spelled(name) for name in names] if Path(path) == directory else names

    monkeypatch.setattr(os, "listdir", listing)


def _store_named(work: Work, name: str) -> None:
    moved = work.store.with_name(name)
    work.store.rename(moved)
    work.store = moved


#: How a file system may spell on disk the name of a store it resolves from another spelling.
SPELLED = pytest.mark.parametrize(
    ("store_name", "spelled"),
    [
        ("kunde-\u00e4.sqlite", lambda name: unicodedata.normalize("NFD", name)),
        ("acme.sqlite", lambda name: name.replace("acme.sqlite", "ACME.sqlite")),
    ],
    ids=["nfd-on-disk", "other-case-on-disk"],
)


@SPELLED
def test_notes_the_file_system_finds_under_the_given_name_go(
    work, monkeypatch, store_name, spelled
):
    """The directory's listing spells the notes otherwise than the name the purge was given,
    but the file system resolves that name to them: they are found all the same, deleted and
    listed — never left behind under a ``missing`` and a complete purge."""
    _store_named(work, store_name)
    notes = _notes(work, ".json")
    _listed_as(monkeypatch, work.store.parent, spelled)
    assert notes.name not in os.listdir(work.store.parent), "the listing spells it otherwise"
    purged = work.purge()
    assert [
        (item.path, item.outcome) for item in purged.paths if item.kind == "operator_notes"
    ] == [(str(notes), "deleted")]
    assert not notes.exists() and purged.complete


@SPELLED
def test_notes_the_file_system_finds_under_the_given_name_are_refused_as_a_link(
    work, monkeypatch, tmp_path, store_name, spelled
):
    _store_named(work, store_name)
    kept = tmp_path / "elsewhere.yaml"
    kept.write_text("engagement: acme\nfindings: {}\n")
    work.store.with_name(f"{work.store.name}.operator-notes.yaml").symlink_to(kept)
    _listed_as(monkeypatch, work.store.parent, spelled)
    refused(work, "is a symbolic link")
    assert kept.exists()


def test_notes_found_both_listed_and_by_name_are_one_file_listed_once(work, monkeypatch):
    """On a case-insensitive file system ``….operator-notes.yaml`` resolves to the
    ``….operator-notes.YAML`` the listing gives: one file, listed once, under its name on disk.
    Simulated with a hard link the listing does not show."""
    on_disk = _notes(work, ".YAML")
    given = work.store.with_name(f"{work.store.name}.operator-notes.yaml")
    os.link(on_disk, given)
    listdir = os.listdir
    monkeypatch.setattr(
        os,
        "listdir",
        lambda path=".": [name for name in listdir(path) if Path(path, name) != given],
    )
    purged = work.purge()
    assert [
        (item.path, item.outcome) for item in purged.paths if item.kind == "operator_notes"
    ] == [(str(on_disk), "deleted")]
    assert not on_disk.exists()


def test_a_directory_of_the_store_that_cannot_be_listed_refuses_the_purge(work, monkeypatch):
    """Notes that cannot be looked for cannot be said gone: nothing is deleted, the store and
    the notes stay, and no ``purged.json`` is written."""
    notes = _notes(work)
    listdir = os.listdir

    def listing(path="."):
        if Path(path) == work.store.parent:
            raise PermissionError(13, "Permission denied")
        return listdir(path)

    monkeypatch.setattr(os, "listdir", listing)
    said = refused(work, "cannot be listed to look for the operator's notes")
    assert "Permission denied" in said and "nothing is deleted" in said
    assert work.store.exists() and notes.exists() and not work.out.exists()
