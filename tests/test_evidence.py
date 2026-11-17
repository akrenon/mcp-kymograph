"""Evidence bundles: ``evidence.pack``, ``evidence.verify`` and the index's reader.

The material is real: an engagement file, corpus runs driven under it through ``cli.main``
against a copy of the project's own corpus, filed with ``store ingest --engagement``, a refusal
the gate wrote down, and a session the store does not hold. Every refusal of ``pack`` is shown
to name what and where and to leave ``out`` uncreated; every role's file, changed by one byte,
is shown to be ``changed`` and the bundle not intact.
"""

import contextlib
import json
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, corpus, engagement, events, evidence, store, verdict
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = FIXTURES / "discovery_server.py"

#: Values of the engagement file that must never reach a bundle.
CONTACT = "CONTACT-CANARY-5811"
REFERENCE = "REFERENCE-CANARY-5812"
PATTERN = "PATTERN-CANARY-5813"
OWNER = "OWNER-CANARY-5814"
NEVER_PACKED = (CONTACT, REFERENCE, PATTERN, OWNER)
#: A value of the file that is kept: the customer's name is part of what was agreed.
CUSTOMER = "CUSTOMER-KEPT-5815"

NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_engagement(directory: Path, **changes) -> Path:
    """An engagement file whose window holds now, covering the local child and the
    ``all-signals`` scenario (copied beside it), with a canary in every value that is removed
    before the file is stored or packed."""
    directory.mkdir(parents=True, exist_ok=True)
    listed = directory / "all-signals.yaml"
    shutil.copyfile(FIXTURES / "scenarios" / "all-signals.yaml", listed)
    now = datetime.now(timezone.utc)
    data = {
        "version": 1,
        "id": "acme-2026-10",
        "customer": CUSTOMER,
        "reference": REFERENCE,
        "contacts": [{"name": CONTACT, "role": "security lead", "reach": "phone"}],
        "window": {"from": utc(now - timedelta(days=1)), "until": utc(now + timedelta(days=1))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": [
            {"path": "all-signals.yaml", "sha256": sha256(listed.read_bytes()).hexdigest()}
        ],
        "actions": {"list": True, "call": False},
        "redaction": {"mask_keys": ["customer_id"], "mask_patterns": [PATTERN]},
        "declared": {"servers": [{"name": "echo", "owner_contact": OWNER}]},
    }
    data.update(changes)
    path = directory / "engagement.json"
    path.write_text(json.dumps(data, indent=2))
    return path


@dataclass
class Material:
    root: Path
    engagement_path: Path
    held: engagement.Engagement
    runs: Path
    store: Path
    manifest: Path
    #: The scenario the manifest names (and the runs recorded), and the engagement file's copy.
    scenario: Path
    listed_scenario: Path
    filed: list[Path]
    sessions: list[Path]
    report: Path


def copy_corpus(root: Path) -> Path:
    """The project's corpus with the files it names, under ``root``; its manifest's path."""
    fixtures = root / "fixtures"
    shutil.copytree(
        FIXTURES / "corpus", fixtures / "corpus", ignore=shutil.ignore_patterns("__pycache__")
    )
    (fixtures / "scenarios").mkdir()
    shutil.copyfile(
        FIXTURES / "scenarios" / "all-signals.yaml", fixtures / "scenarios" / "all-signals.yaml"
    )
    shutil.copyfile(DISCOVERY, fixtures / "discovery_server.py")
    return fixtures / "corpus" / "manifest.yaml"


def drive_corpus(held: Path, manifest: Path, out_dir: Path) -> Path:
    before = set(out_dir.glob("*/events.jsonl")) if out_dir.exists() else set()
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--manifest", str(manifest), "--entry",
         "reference-server", "--isolation", "host", "--out-dir", str(out_dir)]
    )  # fmt: skip
    assert code == 0
    (recording,) = set(out_dir.glob("*/events.jsonl")) - before
    return recording


def drive_session(held: Path, scenario: Path, out_dir: Path) -> Path:
    """A run the store does not hold: no corpus entry, so no reproduction triple."""
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--scenario", str(scenario), "--out-dir",
         str(out_dir), "--", sys.executable, str(DISCOVERY)]
    )  # fmt: skip
    assert code == 0
    (recording,) = out_dir.glob("*/events.jsonl")
    return recording


def build(tmp_path: Path, *, runs: int = 2, refusal: bool = True, session: bool = True):
    root = tmp_path / "work"
    manifest = copy_corpus(root)
    held_path = write_engagement(root / "engagement")
    runs_dir = root / "runs"
    filed = [drive_corpus(held_path, manifest, runs_dir) for _ in range(runs)]
    if refusal:
        code = cli.main(
            ["drive", "-q", "--engagement", str(held_path), "--manifest", str(manifest),
             "--entry", "no-such-entry", "--out-dir", str(runs_dir)]
        )  # fmt: skip
        assert code == 2
        assert (runs_dir / engagement.REFUSALS_FILE).is_file()
    database = root / "store.sqlite"
    code = cli.main(
        ["store", "ingest", "-q", "--store", str(database), "--engagement", str(held_path),
         *map(str, filed)]
    )  # fmt: skip
    assert code == 0
    sessions = []
    if session:
        sessions.append(drive_session(held_path, held_path.parent / "all-signals.yaml",
                                      root / "sessions"))  # fmt: skip
    report = root / "report.md"
    report.write_text("# Report\n\nNothing here is a finding.\n")
    return Material(
        root=root,
        engagement_path=held_path,
        held=engagement.load(held_path),
        runs=runs_dir,
        store=database,
        manifest=manifest,
        scenario=root / "fixtures" / "scenarios" / "all-signals.yaml",
        listed_scenario=held_path.parent / "all-signals.yaml",
        filed=filed,
        sessions=sessions,
        report=report,
    )


def pack(material: Material, out: Path, **changes) -> evidence.Packed:
    arguments = {
        "engagement": material.held,
        "store_path": material.store,
        "runs_dir": material.runs,
        "sessions": material.sessions,
        "report": material.report,
        "out": out,
        "now": NOW,
    }
    arguments.update(changes)
    return evidence.pack(**arguments)


@pytest.fixture
def material(tmp_path) -> Material:
    return build(tmp_path)


@pytest.fixture
def bundle(material, tmp_path) -> tuple[Material, Path, evidence.Packed]:
    out = tmp_path / "bundle"
    return material, out, pack(material, out)


def entries(out: Path) -> list[dict]:
    return json.loads((out / evidence.INDEX_FILE).read_text())["files"]


def flip(path: Path) -> None:
    """Change one byte of a file in place."""
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))


def tree(out: Path) -> list[Path]:
    return sorted(out.rglob("*"))


# -- pack, then verify -----------------------------------------------------------------------


def test_a_packed_bundle_verifies_intact_and_holds_every_role(bundle):
    material, out, packed = bundle

    checked = evidence.verify(out)

    assert checked.intact, checked.summary()
    assert checked.state == evidence.INTACT
    assert checked.to_dict()["bundle"] == "intact"
    assert checked.signature is None
    assert all(item.state == evidence.INTACT for item in checked.files)
    assert checked.unlisted == ()
    assert packed.path == out
    assert packed.packed_utc == "2026-10-28T12:00:00Z"
    assert packed.derived_from is None
    assert packed.engagement_digest == material.held.digest
    assert packed.engagement_id_declared == "acme-2026-10"
    assert dict(packed.counts) == {
        "engagement": 1,
        "manifest": 1,
        "scenario": 1,
        "script": 0,
        "recording": 3,
        "store": 1,
        "refusals": 1,
        "report": 1,
        "tool": 1,
        "redactions": 0,
        "reference": 0,
    }
    assert packed.index_digest == sha256((out / evidence.INDEX_FILE).read_bytes()).hexdigest()
    assert not (out / evidence.SIGNATURE_FILE).exists(), "the tool never signs"


def test_the_index_says_what_each_file_is(bundle):
    material, out, packed = bundle
    index = json.loads((out / evidence.INDEX_FILE).read_text())

    assert index["index_version"] == 1
    assert index["engagement"] == {
        "engagement_id_declared": "acme-2026-10",
        "engagement_digest": material.held.digest,
    }
    assert index["created_utc"] == "2026-10-28T12:00:00Z"
    assert index["derived_from"] is None
    assert index["triage"] == {"untriaged": 0, "open": 0, "question": 0}, "no finding, no row"
    assert index["note"] == evidence.CONVENIENCE_NOTE
    assert "the recording itself is authoritative" in index["note"]
    paths = [entry["path"] for entry in index["files"]]
    assert paths == sorted(paths)
    for entry in index["files"]:
        data = (out / entry["path"]).read_bytes()
        assert entry["sha256"] == sha256(data).hexdigest()
        assert entry["size"] == len(data)
        assert entry["role"] in evidence.ROLES
    manifest_digest = sha256(material.manifest.read_bytes()).hexdigest()
    scenario_digest = sha256(material.scenario.read_bytes()).hexdigest()
    assert f"manifest/{manifest_digest}.yaml" in paths
    assert f"scenarios/{scenario_digest}.yaml" in paths
    assert {"engagement.json", "store.sqlite", "tool.json", "report.md"} <= set(paths)
    assert "refusals/refusals.jsonl" in paths


def test_recordings_are_packed_as_written_with_their_convenience_copies(bundle):
    material, out, _ = bundle
    recordings = [entry for entry in entries(out) if entry["role"] == "recording"]

    filed = [entry for entry in recordings if entry["filed"]]
    sessions = [entry for entry in recordings if not entry["filed"]]
    assert len(filed) == 2 and len(sessions) == 1
    for entry, source in zip(
        sorted(filed, key=lambda e: e["run"]),
        sorted(material.filed, key=lambda p: sha256(p.read_bytes()).hexdigest()),
        strict=True,
    ):
        assert (out / entry["path"]).read_bytes() == source.read_bytes(), "nothing is rewritten"
        run_id = json.loads(source.read_text().splitlines()[0])["run_id"]
        assert entry["path"] == f"runs/{run_id}/events.jsonl"
        assert entry["run"] == sha256(source.read_bytes()).hexdigest()
        assert entry["state"] == verdict.COMPLETE
        assert entry["entry"] == "reference-server"
        assert entry["scenario"] == "all-signals"
        assert entry["mode"] == "driver"
        assert entry["isolation"] == "host"
        assert entry["egress_observed"] is False
    (session,) = sessions
    assert (out / session["path"]).read_bytes() == material.sessions[0].read_bytes()
    assert session["state"] == verdict.read(material.sessions[0]).state
    assert session["entry"] is None, "a run outside the corpus names no entry"
    assert session["scenario"] == "all-signals"
    assert session["filed"] is False


def test_engagement_json_is_the_sanitized_file_and_says_whose_digest_it_carries(bundle):
    material, out, _ = bundle
    (entry,) = [e for e in entries(out) if e["role"] == "engagement"]
    held = json.loads((out / "engagement.json").read_text())

    assert held == material.held.sanitized()
    assert held["customer"] == CUSTOMER
    assert entry["source_digest"] == sha256(material.engagement_path.read_bytes()).hexdigest()
    assert entry["source_digest"] == material.held.digest
    assert entry["sha256"] != entry["source_digest"]
    assert entry["removed"] == list(engagement.Engagement.removed)
    assert entry["digest_note"] == evidence.ENGAGEMENT_NOTE


def test_no_contact_reference_or_mask_pattern_reaches_the_bundle(bundle):
    _, out, _ = bundle
    for path in tree(out):
        if path.is_file():
            data = path.read_bytes()
            for canary in NEVER_PACKED:
                assert canary.encode() not in data, f"{canary} in {path}"


def test_files_are_0600_and_directories_0700(bundle):
    _, out, _ = bundle
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for path in tree(out):
        mode = stat.S_IMODE(path.lstat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), path


def test_the_store_copy_opens_read_only_and_holds_the_same_runs(bundle):
    material, out, _ = bundle
    with Store.open_read_only(material.store) as original:
        runs = [run.to_dict() for run in original.runs()]
        held = original.engagement()
    with Store.open_read_only(out / "store.sqlite") as copy:
        assert [run.to_dict() for run in copy.runs()] == runs
        assert copy.engagement() == held


def test_tool_json_names_the_tool_and_every_version(bundle):
    _, out, _ = bundle
    assert json.loads((out / "tool.json").read_text()) == {
        "tool": corpus.tool_identity(),
        "rules_version": verdict.RULES_VERSION,
        "recording_schema": events.SCHEMA_VERSION,
        "store_schema": store.SCHEMA_VERSION,
    }


def test_refusals_report_and_manifest_are_copied_as_their_bytes(bundle):
    material, out, _ = bundle
    assert (out / "refusals/refusals.jsonl").read_bytes() == (
        material.runs / engagement.REFUSALS_FILE
    ).read_bytes()
    assert (out / "report.md").read_bytes() == material.report.read_bytes()
    digest = sha256(material.manifest.read_bytes()).hexdigest()
    assert (out / f"manifest/{digest}.yaml").read_bytes() == material.manifest.read_bytes()


def test_pack_changes_nothing_it_reads(material, tmp_path):
    def snapshot() -> dict[str, bytes]:
        return {
            str(path): path.read_bytes() for path in sorted(material.root.rglob("*"))
            if path.is_file()
        }  # fmt: skip

    before = snapshot()
    pack(material, tmp_path / "bundle")
    assert snapshot() == before


def test_a_fleet_s_refusals_are_packed_under_their_relative_path(material, tmp_path):
    nested = material.runs / "fleet-1" / "001-reference-server"
    nested.mkdir(parents=True)
    shutil.copyfile(material.runs / engagement.REFUSALS_FILE, nested / engagement.REFUSALS_FILE)
    out = tmp_path / "bundle"

    packed = pack(material, out)

    assert packed.counts["refusals"] == 2
    assert (out / "refusals/fleet-1/001-reference-server/refusals.jsonl").is_file()
    assert evidence.verify(out).intact


def test_without_a_report_or_sessions_none_is_packed(material, tmp_path):
    out = tmp_path / "bundle"
    pack(material, out, report=None, sessions=())
    index = evidence.read_index(out / evidence.INDEX_FILE)
    assert not (out / "report.md").exists()
    assert all(entry.role != "recording" or entry.details["filed"] for entry in index.files)
    assert all(entry.role != "report" for entry in index.files)


def test_the_same_material_packs_to_the_same_index_digest(material, tmp_path):
    first = pack(material, tmp_path / "one")
    second = pack(material, tmp_path / "two")
    assert first.index_digest == second.index_digest


# -- verify: what changed, what is missing, what was added ----------------------------------


# ``reference``: this material's store has no finding, so no page (test_signal_reference.py).
# ``script`` has no file in this material; tests/test_replay_bundle.py flips one of its own.
@pytest.mark.parametrize(
    "role", [r for r in evidence.ROLES if r not in ("redactions", "reference", "script")]
)
def test_one_flipped_byte_in_a_file_of_each_role_is_changed(bundle, tmp_path, role):
    _, out, _ = bundle
    copy = tmp_path / f"copy-{role}"
    shutil.copytree(out, copy)
    target = next(entry["path"] for entry in entries(copy) if entry["role"] == role)

    flip(copy / target)
    checked = evidence.verify(copy)

    assert not checked.intact
    assert checked.state == evidence.NOT_INTACT
    states = {item.path: item.state for item in checked.files}
    assert states.pop(target) == evidence.CHANGED
    assert set(states.values()) == {evidence.INTACT}, "only the flipped file changed"
    assert checked.to_dict()["bundle"] == "not_intact"


def test_a_deleted_file_is_missing(bundle):
    _, out, _ = bundle
    target = next(entry["path"] for entry in entries(out) if entry["role"] == "recording")
    (out / target).unlink()

    checked = evidence.verify(out)

    assert not checked.intact
    (missing,) = [item for item in checked.files if item.state == evidence.MISSING]
    assert missing.path == target
    assert missing.sha256 is None


def test_a_deleted_directory_leaves_its_files_missing(bundle):
    _, out, _ = bundle
    shutil.rmtree(out / "scenarios")
    checked = evidence.verify(out)
    assert not checked.intact
    assert [i.state for i in checked.files if i.role == "scenario"] == [evidence.MISSING]


def test_an_added_empty_directory_is_unlisted(bundle):
    _, out, _ = bundle
    (out / "runs" / "spare").mkdir()
    (out / "spare").mkdir()

    checked = evidence.verify(out)

    assert not checked.intact
    assert [item.path for item in checked.unlisted] == ["runs/spare/", "spare/"]
    assert all(item.note == "a directory the index does not list" for item in checked.unlisted)
    assert all(item.state == evidence.INTACT for item in checked.files)


def test_a_directory_where_a_file_is_listed_is_changed_not_unlisted(bundle):
    _, out, _ = bundle
    (out / "report.md").unlink()
    (out / "report.md").mkdir()

    checked = evidence.verify(out)

    (report,) = [item for item in checked.files if item.path == "report.md"]
    assert report.state == evidence.CHANGED
    assert checked.unlisted == ()


def test_an_added_file_is_unlisted(bundle):
    _, out, _ = bundle
    (out / "runs" / "extra.txt").write_text("not packed")

    checked = evidence.verify(out)

    assert not checked.intact
    assert [item.path for item in checked.unlisted] == ["runs/extra.txt"]
    assert all(item.state == evidence.INTACT for item in checked.files)


def test_a_link_is_never_followed_listed_it_is_changed_elsewhere_unlisted(bundle, tmp_path):
    _, out, _ = bundle
    outside = tmp_path / "outside.md"
    shutil.copyfile(out / "report.md", outside)
    (out / "report.md").unlink()
    (out / "report.md").symlink_to(outside)
    (out / "elsewhere").symlink_to(outside)

    checked = evidence.verify(out)

    assert not checked.intact
    (report,) = [item for item in checked.files if item.path == "report.md"]
    assert report.state == evidence.CHANGED
    assert "symbolic link" in report.note
    assert report.sha256 is None, "the link was not followed"
    (elsewhere,) = checked.unlisted
    assert elsewhere.path == "elsewhere"
    assert "symbolic link" in elsewhere.note


def test_a_linked_directory_in_a_listed_path_is_changed(bundle, tmp_path):
    _, out, _ = bundle
    moved = tmp_path / "scenarios-elsewhere"
    (out / "scenarios").rename(moved)
    (out / "scenarios").symlink_to(moved)

    checked = evidence.verify(out)

    (scenario,) = [item for item in checked.files if item.role == "scenario"]
    assert scenario.state == evidence.CHANGED
    assert "symbolic link" in scenario.note


def test_an_index_digest_known_from_elsewhere_must_match(bundle):
    _, out, packed = bundle
    assert evidence.verify(out, index_digest=packed.index_digest).intact

    checked = evidence.verify(out, index_digest="0" * 64)

    assert not checked.intact
    assert checked.index_digest_matches is False
    assert all(item.state == evidence.INTACT for item in checked.files)
    (problem,) = checked.problems
    assert "not the one known from elsewhere" in problem
    assert checked.to_dict()["index_digest_matches"] is False


def test_a_replaced_index_is_caught_only_by_the_digest(bundle):
    _, out, packed = bundle
    index = json.loads((out / evidence.INDEX_FILE).read_text())
    index["files"] = [e for e in index["files"] if e["role"] != "report"]
    (out / "report.md").unlink()
    (out / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    assert evidence.verify(out).intact, "without a digest from elsewhere it cannot be told"
    assert not evidence.verify(out, index_digest=packed.index_digest).intact


def test_a_signature_is_reported_and_not_checked(bundle):
    _, out, _ = bundle
    (out / evidence.SIGNATURE_FILE).write_bytes(b"whatever the operator's tool wrote")

    checked = evidence.verify(out)

    assert checked.intact
    assert checked.signature == "present; not checked by this tool"
    assert checked.to_dict()["signature"] == evidence.SIGNATURE_NOT_CHECKED


def test_verify_to_dict_is_json(bundle):
    _, out, _ = bundle
    shown = json.loads(json.dumps(evidence.verify(out).to_dict()))
    assert shown["bundle"] == "intact"
    assert {item["state"] for item in shown["files"]} == {"intact"}


def test_an_unreadable_or_malformed_index_refuses_verify(bundle):
    _, out, _ = bundle
    (out / evidence.INDEX_FILE).write_text("{not json")
    with pytest.raises(evidence.EvidenceError, match="not an index"):
        evidence.verify(out)
    (out / evidence.INDEX_FILE).unlink()
    with pytest.raises(evidence.EvidenceError, match="cannot read"):
        evidence.verify(out)


# -- the index reader -------------------------------------------------------------------------


def test_the_index_round_trips_through_read_index(bundle):
    _, out, packed = bundle
    raw = (out / evidence.INDEX_FILE).read_bytes()

    index = evidence.read_index(out / evidence.INDEX_FILE)

    assert index.digest == packed.index_digest
    assert index.to_dict() == json.loads(raw)
    assert evidence.index_bytes(index) == raw
    assert evidence.read_index(out / evidence.INDEX_FILE) == index


def _broken(out: Path, change) -> Path:
    index = json.loads((out / evidence.INDEX_FILE).read_text())
    change(index)
    path = out / "broken.json"
    path.write_text(json.dumps(index))
    return path


@pytest.mark.parametrize(
    ("change", "words"),
    [
        (lambda i: i.update(extra=1), "unknown key"),
        (lambda i: i.pop("note"), "missing key"),
        (lambda i: i.update(index_version=2), "index_version"),
        (lambda i: i.update(index_version=True), "index_version"),
        (lambda i: i["engagement"].update(engagement_digest="ABC"), "64 lowercase"),
        (lambda i: i.update(created_utc="2026-10-28 12:00"), "created_utc"),
        (lambda i: i.update(derived_from="x"), "derived_from"),
        (lambda i: i.update(triage={"untriaged": 0, "open": -1, "question": 0}), "triage.open"),
        (lambda i: i.update(triage={"open": 0, "question": 0}), "missing key"),
        (
            lambda i: i.update(triage={"untriaged": 0, "open": 0, "question": 0, "later": 1}),
            "unknown key",
        ),
        (lambda i: i.update(triage=[0, 0, 0]), "triage"),
        (lambda i: i["files"][0].update(role="secret"), "is not one of"),
        (lambda i: i["files"][0].update(sha256="0" * 63), "sha256"),
        (lambda i: i["files"][0].update(size=-1), "size"),
        (lambda i: i["files"][0].update(path="../outside"), "not a relative path"),
        (lambda i: i["files"][0].update(path="/etc/passwd"), "not a relative path"),
        (lambda i: i["files"][0].update(path="index.json"), "not a relative path"),
        (lambda i: i["files"][0].update(colour="red"), "unknown key"),
        (lambda i: i["files"].append(dict(i["files"][0])), "listed twice"),
    ],
)
def test_read_index_refuses_whole(bundle, change, words):
    _, out, _ = bundle
    with pytest.raises(evidence.EvidenceError, match=words):
        evidence.read_index(_broken(out, change))


def test_read_index_refuses_a_recording_entry_without_its_fields(bundle):
    _, out, _ = bundle

    def strip(index):
        recording = next(e for e in index["files"] if e["role"] == "recording")
        del recording["state"]

    with pytest.raises(evidence.EvidenceError, match="missing key"):
        evidence.read_index(_broken(out, strip))

    def wrong(index):
        recording = next(e for e in index["files"] if e["role"] == "recording")
        recording["state"] = "fine"

    with pytest.raises(evidence.EvidenceError, match="is not a run's state"):
        evidence.read_index(_broken(out, wrong))


def test_read_index_refuses_duplicate_keys_and_constants(tmp_path):
    path = tmp_path / "index.json"
    path.write_text('{"index_version": 1, "index_version": 1}')
    with pytest.raises(evidence.EvidenceError, match="duplicate key"):
        evidence.read_index(path)
    path.write_text('{"index_version": NaN}')
    with pytest.raises(evidence.EvidenceError, match="not a JSON value"):
        evidence.read_index(path)


def test_read_index_does_not_follow_a_link(bundle, tmp_path):
    _, out, _ = bundle
    link = tmp_path / "linked.json"
    link.symlink_to(out / evidence.INDEX_FILE)
    with pytest.raises(evidence.EvidenceError, match="symbolic link"):
        evidence.read_index(link)


# -- every refusal of pack --------------------------------------------------------------------


def refused(material: Material, out: Path, words: str, **changes) -> str:
    with pytest.raises(evidence.EvidenceError) as caught:
        pack(material, out, **changes)
    said = str(caught.value)
    assert said.startswith("refused: ")
    assert words in said, said
    assert not out.exists(), "a refused pack writes nothing"
    return said


def test_a_store_without_an_engagement_is_refused(material, tmp_path):
    empty = tmp_path / "empty.sqlite"
    Store.open(empty).close()
    said = refused(material, tmp_path / "bundle", "holds no engagement", store_path=empty)
    assert str(empty) in said


def test_a_missing_store_is_refused(material, tmp_path):
    refused(material, tmp_path / "bundle", "no store there", store_path=tmp_path / "none")


def test_an_engagement_file_not_in_the_store_s_chain_is_refused(material, tmp_path):
    other = engagement.load(write_engagement(tmp_path / "other", id="other-2026-11"))
    said = refused(material, tmp_path / "bundle", "is not a version", engagement=other)
    assert other.digest in said
    assert "acme-2026-10" in said


def test_a_recording_not_found_under_runs_is_refused(material, tmp_path):
    gone = material.filed[0]
    run = sha256(gone.read_bytes()).hexdigest()
    gone.unlink()
    said = refused(material, tmp_path / "bundle", "was not found under")
    assert run in said
    assert str(material.runs) in said


def test_a_changed_recording_is_refused(material, tmp_path):
    changed = material.filed[1]
    run = sha256(changed.read_bytes()).hexdigest()
    with changed.open("ab") as handle:
        handle.write(b"\n")
    said = refused(material, tmp_path / "bundle", "not the one")
    assert run in said
    assert str(changed) in said
    assert "changed after ingest" in said


def test_a_scenario_not_found_is_refused(material, tmp_path):
    digest = sha256(material.scenario.read_bytes()).hexdigest()
    material.scenario.unlink()
    material.listed_scenario.unlink()
    said = refused(material, tmp_path / "bundle", "was not found")
    assert digest in said
    assert "all-signals" in said


def test_a_changed_scenario_is_refused(material, tmp_path):
    digest = sha256(material.scenario.read_bytes()).hexdigest()
    for path in (material.scenario, material.listed_scenario):
        with path.open("a") as handle:
            handle.write("# changed after the run\n")
    said = refused(material, tmp_path / "bundle", "it changed")
    assert digest in said
    assert "corpus/../scenarios/all-signals.yaml: SHA-256 " in said, "the path the run recorded"
    assert f"{material.listed_scenario}: SHA-256 " in said, "the engagement file's copy"


def test_a_scenario_found_through_the_engagement_file_alone_is_packed(material, tmp_path):
    """The recorded path and the manifest's copy are gone; the engagement file lists the same
    bytes, and that is enough: a scenario is the bytes of its digest, wherever they are."""
    material.scenario.unlink()
    out = tmp_path / "bundle"
    pack(material, out)
    assert evidence.verify(out).intact


def test_a_manifest_not_found_is_refused(material, tmp_path):
    digest = sha256(material.manifest.read_bytes()).hexdigest()
    material.manifest.unlink()
    said = refused(material, tmp_path / "bundle", "was not found")
    assert digest in said
    assert "manifest" in said


def test_a_changed_manifest_is_refused(material, tmp_path):
    with material.manifest.open("a") as handle:
        handle.write("# changed after the run\n")
    said = refused(material, tmp_path / "bundle", "it changed")
    assert str(material.manifest) in said


def test_a_manifest_given_beside_the_recorded_path_is_found(material, tmp_path):
    moved = tmp_path / "elsewhere.yaml"
    material.manifest.rename(moved)
    out = tmp_path / "bundle"
    pack(material, out, manifests=[moved])
    assert evidence.verify(out).intact


def test_a_session_of_another_engagement_is_refused(material, tmp_path):
    other = write_engagement(tmp_path / "other", id="other-2026-11")
    session = drive_session(other, other.parent / "all-signals.yaml", tmp_path / "other-runs")
    said = refused(material, tmp_path / "bundle", "not a version", sessions=[session])
    assert "other-2026-11" in said
    assert str(session) in said


def test_a_session_under_no_engagement_is_refused(material, tmp_path):
    out_dir = tmp_path / "plain"
    assert cli.main(
        ["drive", "-q", "--out-dir", str(out_dir), "--", sys.executable, str(DISCOVERY)]
    ) == 0  # fmt: skip
    (session,) = out_dir.glob("*/events.jsonl")
    refused(material, tmp_path / "bundle", "made under no engagement", sessions=[session])


def test_a_session_the_store_files_is_refused(material, tmp_path):
    said = refused(material, tmp_path / "bundle", "packed once", sessions=[material.filed[0]])
    assert "the store files it" in said


def test_a_missing_session_is_refused(material, tmp_path):
    refused(material, tmp_path / "bundle", "cannot read", sessions=[tmp_path / "none.jsonl"])


def test_an_existing_out_is_refused(material, tmp_path):
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "keep.txt").write_text("mine")
    with pytest.raises(evidence.EvidenceError, match="exists"):
        pack(material, out)
    assert [path.name for path in out.iterdir()] == ["keep.txt"]


def test_an_out_inside_a_git_working_tree_is_refused(material, tmp_path):
    git = shutil.which("git")
    assert git, "this test needs a git binary"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=repo, check=True)  # noqa: S603
    refused(material, repo / "bundle", "git working tree")


def test_an_out_under_runs_is_refused(material):
    refused(material, material.runs / "bundle", "lies under --runs")


def test_runs_that_is_not_a_directory_is_refused(material, tmp_path):
    refused(material, tmp_path / "bundle", "not a directory", runs_dir=tmp_path / "none")


def test_an_unreadable_refusals_file_refuses_the_pack(material, tmp_path):
    with (material.runs / engagement.REFUSALS_FILE).open("a") as handle:
        handle.write("not a refusal\n")
    said = refused(material, tmp_path / "bundle", "cannot be packed")
    assert engagement.REFUSALS_FILE in said


def test_a_refusal_under_another_engagement_refuses_the_pack(material, tmp_path):
    line = json.loads((material.runs / engagement.REFUSALS_FILE).read_text().splitlines()[0])
    line["engagement"]["engagement_digest"] = "f" * 64
    nested = material.runs / "other"
    nested.mkdir()
    (nested / engagement.REFUSALS_FILE).write_text(json.dumps(line) + "\n")
    said = refused(material, tmp_path / "bundle", "one out-dir per engagement")
    assert "f" * 64 in said


def test_a_report_that_cannot_be_read_is_refused(material, tmp_path):
    refused(material, tmp_path / "bundle", "report", report=tmp_path / "none.md")


def test_a_report_that_is_a_link_is_refused(material, tmp_path):
    link = tmp_path / "linked.md"
    link.symlink_to(material.report)
    refused(material, tmp_path / "bundle", "symbolic link", report=link)


def bundled_triage(database: Path) -> dict[str, int]:
    """The triage of a store as the bundle's index should say it, counted here by SQL of its
    own: identities of findings no row concerns, current rows open and question."""
    with contextlib.closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as db:
        identities = {
            json.dumps(list(row))
            for row in db.execute(
                "SELECT server, scenario, statement, locator, signal FROM findings"
            )
        }
        current = db.execute(
            "SELECT identity, status FROM triage WHERE id IN"
            " (SELECT MAX(id) FROM triage GROUP BY identity, role)"
        ).fetchall()
    concerned = {json.dumps(json.loads(identity)) for identity, _ in current}
    return {
        "untriaged": len(identities - concerned),
        "open": sum(status == "open" for _, status in current),
        "question": sum(status == "question" for _, status in current),
    }


def test_the_index_s_triage_is_the_bundled_store_s_and_open_rows_do_not_refuse(material, tmp_path):
    out_dir = material.runs
    code = cli.main(
        ["drive", "-q", "--engagement", str(material.engagement_path), "--manifest",
         str(material.manifest), "--entry", "poison-server", "--isolation", "host",
         "--out-dir", str(out_dir)]
    )  # fmt: skip
    assert code in (0, 3)
    poisoned = max(out_dir.glob("*/events.jsonl"), key=lambda p: p.stat().st_mtime_ns)
    with Store.open(material.store) as held:
        held.ingest(poisoned)
        findings = held.findings_with_triage("poison")
        assert len({tuple(f[n] for n in store.IDENTITY_FIELDS) for f in findings}) >= 4
        decide = {"author": "operator"}
        held.triage_set(finding=findings[0]["finding"], role="operator", status="open", **decide)
        held.triage_set(finding=findings[1]["finding"], role="customer", status="open", **decide)
        held.triage_set(finding=findings[2]["finding"], role="operator", status="open", **decide)
        held.triage_set(
            finding=findings[2]["finding"], role="operator", status="confirmed", **decide
        )
    out = tmp_path / "bundle"

    packed = pack(material, out)

    expected = bundled_triage(out / "store.sqlite")
    assert expected["open"] == 2, "the latest row of each identity and role counts"
    assert expected["question"] == 0, "no role may set question in this version"
    assert (
        expected["untriaged"]
        == len({tuple(f[n] for n in store.IDENTITY_FIELDS) for f in findings}) - 3
    )
    assert packed.triage == expected
    assert evidence.read_index(out / evidence.INDEX_FILE).triage == expected
    assert evidence.verify(out).intact

    # A decision made after the pack is the store's, not the bundle's.
    with Store.open(material.store) as held:
        held.triage_set(finding=findings[3]["finding"], role="operator", status="open", **decide)
    assert bundled_triage(material.store) != expected
    assert bundled_triage(out / "store.sqlite") == expected
    assert evidence.verify(out, index_digest=packed.index_digest).intact


def test_packed_to_dict_is_json(bundle):
    _, out, packed = bundle
    shown = json.loads(json.dumps(packed.to_dict()))
    assert shown["index_digest"] == packed.index_digest
    assert shown["path"] == str(out)
    assert shown["counts"]["recording"] == 3


def test_a_store_holding_no_runs_packs_sessions_alone(tmp_path):
    root = tmp_path / "work"
    held_path = write_engagement(root / "engagement")
    held = engagement.load(held_path)
    database = root / "store.sqlite"
    with Store.open(database) as fresh:
        cli.set_engagement(fresh, held)
    session = drive_session(held_path, held_path.parent / "all-signals.yaml", root / "sessions")
    runs = root / "runs"
    runs.mkdir()
    out = tmp_path / "bundle"

    packed = evidence.pack(
        engagement=held, store_path=database, runs_dir=runs, sessions=[session], out=out, now=NOW
    )

    assert packed.counts["recording"] == 1
    assert packed.counts["scenario"] == 1
    assert packed.counts["manifest"] == 0
    assert evidence.verify(out, index_digest=packed.index_digest).intact


def test_a_pack_that_fails_while_writing_takes_back_what_it_wrote(material, tmp_path, monkeypatch):
    def fails(*_args, **_kwargs):
        raise evidence.EvidenceError("read back differs")

    monkeypatch.setattr(evidence, "_read_back", fails)
    out = tmp_path / "bundle"

    with pytest.raises(evidence.EvidenceError, match="what it wrote was removed") as caught:
        pack(material, out)

    assert "read back differs" in str(caught.value)
    assert not out.exists()


def test_a_failed_pack_takes_back_the_parents_it_created_and_only_those(
    material, tmp_path, monkeypatch
):
    def fails(*_args, **_kwargs):
        raise evidence.EvidenceError("read back differs")

    monkeypatch.setattr(evidence, "_read_back", fails)
    kept = tmp_path / "kept"
    kept.mkdir()
    out = kept / "made" / "also-made" / "bundle"

    with pytest.raises(evidence.EvidenceError, match="what it wrote was removed"):
        pack(material, out)

    assert not (kept / "made").exists(), "the parents it created are gone"
    assert kept.is_dir(), "a directory it did not create stays"


def test_parents_created_above_out_are_0700(material, tmp_path):
    out = tmp_path / "made" / "bundle"
    pack(material, out)
    assert stat.S_IMODE((tmp_path / "made").stat().st_mode) == 0o700


def test_take_back_removes_only_names_it_wrote(tmp_path):
    written = evidence._Written()
    written.file(tmp_path / "report.md", b"mine")
    (tmp_path / "report.md-journal").write_text("not mine")
    database = tmp_path / "store.sqlite"
    written.file(database, b"")
    written.database = database
    (tmp_path / "store.sqlite-journal").write_text("SQLite's, beside the copy")

    assert written.take_back() == []

    assert sorted(path.name for path in tmp_path.iterdir()) == ["report.md-journal"]


@pytest.mark.skipif(getattr(os, "geteuid", lambda: 0)() == 0, reason="root reads everything")
def test_a_directory_that_cannot_be_listed_leaves_the_bundle_not_intact(bundle):
    _, out, _ = bundle
    (out / "scenarios").chmod(0)
    try:
        checked = evidence.verify(out)
    finally:
        (out / "scenarios").chmod(0o700)

    assert not checked.intact
    (scenario,) = [item for item in checked.files if item.role == "scenario"]
    assert scenario.state == evidence.CHANGED
    assert "cannot be read" in scenario.note
    assert any("scenarios could not be listed" in problem for problem in checked.problems)


def test_a_receiver_path_prefix_is_in_no_file_of_a_store_or_a_bundle(tmp_path):
    # The file of the bundle tests, made one of the second version with a prefix put together at
    # run time; the store files it as it files a file with `store ingest --engagement`.
    prefix = secrets.token_urlsafe(24)
    assert engagement.good_receiver_prefix(prefix)
    material = build(tmp_path, refusal=False, session=False)
    data = json.loads(material.engagement_path.read_text())
    del data["customer"]
    data.update(
        version=2,
        end_customer={"name": CUSTOMER},
        abort_criteria=["any write to production data"],
        emergency={"name": "Lee Ops", "reach": "+49 30 5550100"},
        salt_env="KYMOGRAPH_SALT",
        receiver={
            "variant": "reachable",
            "address": "recv.example.test",
            "path_prefix": prefix,
            "key_env": "KYMOGRAPH_RECEIVER_KEY",
            "retention_seconds": 3600,
        },
    )
    data["supersedes"] = material.held.digest
    later = material.engagement_path.with_name("engagement-2.json")
    later.write_text(json.dumps(data))
    held = engagement.load(later)
    assert held.receiver.path_prefix == prefix
    # Filed as a later version of the file the runs were made under.
    with Store.open(material.store) as filed:
        cli.set_engagement(filed, held)
    assert prefix.encode() not in material.store.read_bytes()

    out = tmp_path / "second-bundle"
    pack(material, out, engagement=held)
    files = [path for path in tree(out) if path.is_file()]
    assert {"engagement.json", "store.sqlite"} <= {path.name for path in files}
    for path in files:
        assert prefix.encode() not in path.read_bytes(), path
