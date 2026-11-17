"""Review and redaction before a handover: ``evidence.review``, ``evidence.redact``,
``redactions.json`` and ``CUSTOMER-README.md``.

The material is real: an engagement file whose redaction patterns name a canary, a server of our
own whose tool description carries it (and ``.*`` as two plain characters), driven under the
file as a session beside filed corpus runs, packed with ``evidence.pack``. The canary must occur
in no byte of the redacted bundle, the source bundle must be byte for byte what it was, and the
new bundle must verify intact.
"""

import json
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, evidence, handover
from mcp_kymograph.masking import PLACEHOLDER

FIXTURES = Path(__file__).parent / "fixtures"
CANARY = "HOSTILE-CANARY-7731"
DESCRIPTION = f"Returns the text it is given. <!-- account {CANARY} --> Matches .* literally."
CONTACT = "CONTACT-CANARY-7732"
NOW = datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc)


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
        "customer": 'ACME "Labs"\nGmbH',
        "contacts": [{"name": CONTACT, "role": "lead", "reach": "phone"}],
        "window": {"from": utc(now - timedelta(days=1)), "until": utc(now + timedelta(days=1))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": [
            {"path": "all-signals.yaml", "sha256": sha256(listed.read_bytes()).hexdigest()}
        ],
        "actions": {"list": True, "call": False},
        "redaction": {"mask_keys": ["customer_id"], "mask_patterns": [CANARY, ".*"]},
    }
    data.update(changes)
    path = directory / "engagement.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def write_canary_server(directory: Path) -> Path:
    """A server of our own: the discovery fixture with a tool description that holds the canary.
    The description is in the file, not on the command line, so the recording's argv does not
    carry it."""
    path = directory / "canary_server.py"
    path.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(FIXTURES)!r})\n"
        "import discovery_server\n"
        "sys.argv = [sys.argv[0], '--server-name', 'canary-server', '--tool-description', "
        f"{DESCRIPTION!r}, *sys.argv[1:]]\n"
        "sys.exit(discovery_server.main())\n"
    )
    return path


def copy_corpus(root: Path) -> Path:
    fixtures = root / "fixtures"
    shutil.copytree(
        FIXTURES / "corpus", fixtures / "corpus", ignore=shutil.ignore_patterns("__pycache__")
    )
    (fixtures / "scenarios").mkdir()
    shutil.copyfile(
        FIXTURES / "scenarios" / "all-signals.yaml", fixtures / "scenarios" / "all-signals.yaml"
    )
    shutil.copyfile(FIXTURES / "discovery_server.py", fixtures / "discovery_server.py")
    return fixtures / "corpus" / "manifest.yaml"


def drive(held: Path, out_dir: Path, *argv: str) -> Path:
    before = set(out_dir.glob("*/events.jsonl")) if out_dir.exists() else set()
    code = cli.main(["drive", "-q", "--engagement", str(held), "--out-dir", str(out_dir), *argv])
    assert code == 0
    (recording,) = set(out_dir.glob("*/events.jsonl")) - before
    return recording


class Material:
    def __init__(self, root: Path) -> None:
        self.root = root
        manifest = copy_corpus(root)
        self.held_path = write_engagement(root / "engagement")
        self.held = engagement.load(self.held_path)
        self.runs = root / "runs"
        filed = drive(
            self.held_path, self.runs, "--manifest", str(manifest), "--entry",
            "reference-server", "--isolation", "host",
        )  # fmt: skip
        self.store = root / "store.sqlite"
        assert cli.main(
            ["store", "ingest", "-q", "--store", str(self.store), "--engagement",
             str(self.held_path), str(filed)]
        ) == 0  # fmt: skip
        server = write_canary_server(root)
        self.session = drive(
            self.held_path, root / "sessions", "--scenario",
            str(self.held_path.parent / "all-signals.yaml"), "--", sys.executable, str(server),
        )  # fmt: skip
        self.report = root / "report.md"
        self.report.write_text("# Report\n\nOne tool, one description.\n")

    def pack(self, out: Path, **changes) -> evidence.Packed:
        arguments = {
            "engagement": self.held,
            "store_path": self.store,
            "runs_dir": self.runs,
            "sessions": [self.session],
            "report": self.report,
            "out": out,
            "now": NOW,
        }
        arguments.update(changes)
        return evidence.pack(**arguments)


@pytest.fixture
def source(tmp_path) -> tuple[Material, Path, evidence.Packed]:
    material = Material(tmp_path / "work")
    out = tmp_path / "bundle"
    return material, out, material.pack(out)


def redact(material: Material, bundle: Path, out: Path, **changes) -> evidence.Redacted:
    arguments = {"engagement_path": material.held_path, "out": out, "now": NOW}
    arguments.update(changes)
    return evidence.redact(bundle, **arguments)


def snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }


def session_entry(bundle: Path) -> dict:
    index = json.loads((bundle / evidence.INDEX_FILE).read_text())
    return next(e for e in index["files"] if e["role"] == "recording" and not e["filed"])


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def described(path: Path) -> str:
    listing = next(
        e for e in events_of(path)
        if e["type"] == "message" and e.get("responded_method") == "tools/list"
    )  # fmt: skip
    return listing["payload"]["data"]["result"]["tools"][0]["description"]


# -- review -----------------------------------------------------------------------------------


def test_a_review_lists_every_text_surface_by_entry_and_method(source):
    _, bundle, packed = source

    reviewed = evidence.review(bundle)

    assert reviewed.index_digest == packed.index_digest
    groups = {(group.entry, group.method): group for group in reviewed.groups}
    session = groups[(None, "tools/list")]
    (description,) = [t for t in session.texts if t.path == "result.tools[0].description"]
    assert description.text == DESCRIPTION, "the value as recorded"
    assert description.surface == "tool_description"
    assert description.recording == session_entry(bundle)["path"]
    filed = groups[("reference-server", "tools/list")]
    assert any(t.text == "Returns the text it is given." for t in filed.texts)
    assert ("reference-server", "initialize") in groups
    assert reviewed.not_listed > 0, "jsonrpc and protocol names are strings it does not list"
    assert not reviewed.complete, "a review never reads as complete when it is not"
    shown = json.loads(json.dumps(reviewed.to_dict()))
    assert shown["complete"] is False
    assert all(
        m["not_listed"] >= 0 and m["listed"] >= 0 for g in shown["groups"] for m in g["messages"]
    )


def test_a_review_of_a_bundle_that_is_not_intact_is_refused(source):
    _, bundle, _ = source
    (bundle / "report.md").write_text("changed")
    with pytest.raises(evidence.EvidenceError, match="is not intact"):
        evidence.review(bundle)


# -- redact -----------------------------------------------------------------------------------


def test_redaction_blanks_the_canary_and_the_new_bundle_verifies_intact(source, tmp_path):
    material, bundle, packed = source
    before = snapshot(bundle)
    out = tmp_path / "handover"

    made = redact(material, bundle, out)

    assert snapshot(bundle) == before, "the source bundle is byte for byte what it was"
    assert evidence.verify(bundle, index_digest=packed.index_digest).intact
    checked = evidence.verify(out, index_digest=made.index_digest)
    assert checked.intact, checked.summary()
    assert checked.readme == evidence.README_NAMES_INDEX
    for name, data in snapshot(out).items():
        assert CANARY.encode() not in data, f"the canary in {name}"
        assert CONTACT.encode() not in data, f"a contact in {name}"
    assert made.derived_from == packed.index_digest
    assert made.engagement_digest == material.held.digest
    assert made.rules == 3, "two patterns and one mask key from the file"
    assert made.counts["store"] == 0, "no store in a handover bundle"
    assert not (out / "store.sqlite").exists()
    assert made.counts["redactions"] == 1
    assert json.loads(json.dumps(made.to_dict()))["derived_from"] == packed.index_digest


def test_a_pattern_is_a_literal_and_only_its_occurrences_are_blanked(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)

    entry = session_entry(out)
    assert described(out / entry["path"]) == (
        f"Returns the text it is given. <!-- account {PLACEHOLDER} --> Matches {PLACEHOLDER} "
        "literally."
    ), "'.*' is the two characters, not everything"


def test_the_index_names_the_source_and_each_original_recording(source, tmp_path):
    material, bundle, packed = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    source_index = json.loads((bundle / evidence.INDEX_FILE).read_text())
    index = evidence.read_index(out / evidence.INDEX_FILE)

    assert index.derived_from == packed.index_digest
    assert evidence.REDACTED_NOTE in index.note
    assert index.triage == source_index["triage"]
    by_path = {e["path"]: e for e in source_index["files"]}
    recordings = [entry for entry in index.files if entry.role == "recording"]
    assert len(recordings) == 2
    for entry in recordings:
        assert entry.details["source_sha256"] == by_path[entry.path]["sha256"]
        assert entry.details["redacted"] is (entry.details["source_sha256"] != entry.sha256)
    assert [e.details["redacted"] for e in recordings if not e.details["filed"]] == [True]
    for entry in index.files:
        if entry.role in ("engagement", "manifest", "scenario", "refusals", "tool", "report"):
            assert entry.sha256 == by_path[entry.path]["sha256"], "copied as it is"


def test_only_the_blanked_values_change_and_locators_stay(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    path = session_entry(out)["path"]

    before = (bundle / path).read_bytes().split(b"\n")
    after = (out / path).read_bytes().split(b"\n")

    assert len(before) == len(after)
    changed = [number for number, (a, b) in enumerate(zip(before, after, strict=True)) if a != b]
    assert len(changed) == 1, "one message held the canary"
    findings_before = [e for e in events_of(bundle / path) if e["type"] == "finding"]
    findings_after = [e for e in events_of(out / path) if e["type"] == "finding"]
    assert findings_before, "the hidden comment around the canary is a finding"
    assert findings_after == findings_before, "a finding's locator is a name, and stays"


def test_redactions_json_names_rules_and_places_never_values(source, tmp_path):
    material, bundle, packed = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    raw = (out / evidence.REDACTIONS_FILE).read_bytes()

    redactions = evidence.read_redactions(out / evidence.REDACTIONS_FILE)

    assert evidence.canonical_json(redactions.to_dict()) == raw, "round trip"
    assert redactions.derived_from == packed.index_digest
    assert redactions.rules == ("mask_patterns[0]", "mask_patterns[1]", "mask_key:customer_id")
    session = next(r for r in redactions.recordings if r.blanked)
    assert {(b.path, b.rule, b.count) for b in session.blanked} == {
        ("result.tools[0].description", "mask_patterns[0]", 1),
        ("result.tools[0].description", "mask_patterns[1]", 1),
    }
    assert session.sha256 == sha256((out / session.path).read_bytes()).hexdigest()
    assert CANARY.encode() not in raw and b".*" not in raw


@pytest.mark.parametrize(
    ("change", "words"),
    [
        (lambda r: r.update(extra=1), "unknown key"),
        (lambda r: r.update(rules=["mask_patterns[x]"]), "rules"),
        (lambda r: r.update(derived_from="x"), "derived_from"),
        (lambda r: r["recordings"][0].update(sha256="0"), "sha256"),
    ],
)
def test_read_redactions_refuses_whole(source, tmp_path, change, words):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    data = json.loads((out / evidence.REDACTIONS_FILE).read_text())
    change(data)
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(data))
    with pytest.raises(evidence.EvidenceError, match=words):
        evidence.read_redactions(broken)


def test_a_mask_key_blanks_whole_values_under_a_matching_key(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"

    made = redact(material, bundle, out, mask_keys=["input-schema"])

    redactions = evidence.read_redactions(out / evidence.REDACTIONS_FILE)
    assert "mask_key:input-schema" in redactions.rules
    keyed = [
        b for r in redactions.recordings for b in r.blanked if b.rule == "mask_key:input-schema"
    ]
    assert {b.path for b in keyed} == {"result.tools[0].inputSchema.properties.text.description"}
    assert len(keyed) == 2, "the filed run's listing and the session's"
    assert made.values_redacted == 4
    for entry in evidence.read_index(out / evidence.INDEX_FILE).files:
        if entry.role == "recording":
            assert b"Some text." not in (out / entry.path).read_bytes()


def test_a_one_byte_flip_in_the_new_bundle_is_not_intact(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    made = redact(material, bundle, out)
    target = out / evidence.REDACTIONS_FILE
    data = bytearray(target.read_bytes())
    data[10] ^= 1
    target.write_bytes(bytes(data))
    assert not evidence.verify(out, index_digest=made.index_digest).intact


def test_a_readme_that_names_another_digest_is_not_intact(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    made = redact(material, bundle, out)
    readme = out / handover.CUSTOMER_README
    readme.write_text(readme.read_text().replace(made.index_digest, "0" * 64))

    checked = evidence.verify(out)

    assert not checked.intact
    assert any("is not the page this bundle" in problem for problem in checked.problems)


# -- the refusals of redact -------------------------------------------------------------------


def refused(material, bundle, out, words, **changes) -> str:
    with pytest.raises(evidence.EvidenceError) as caught:
        redact(material, bundle, out, **changes)
    said = str(caught.value)
    assert said.startswith("refused: ")
    assert words in said, said
    assert not out.exists(), "a refused redaction writes nothing"
    assert CANARY not in said, "a refusal never names the value"
    return said


def test_a_source_that_is_not_intact_is_refused(source, tmp_path):
    material, bundle, _ = source
    (bundle / "tool.json").write_text("{}")
    refused(material, bundle, tmp_path / "handover", "is not intact")


def test_a_file_not_of_the_chain_is_refused(source, tmp_path):
    material, bundle, _ = source
    other = write_engagement(tmp_path / "other", id="other-2026-11")
    said = refused(material, bundle, tmp_path / "handover", "not a version", engagement_path=other)
    assert engagement.load(other).digest in said


def test_a_bundle_without_a_store_is_refused(source, tmp_path):
    material, bundle, _ = source
    first = tmp_path / "handover"
    redact(material, bundle, first)
    refused(material, first, tmp_path / "again", "holds no store")


def test_a_report_holding_a_pattern_is_refused_and_says_to_regenerate(tmp_path):
    material = Material(tmp_path / "work")
    material.report.write_text(f"# Report\n\nThe description names {CANARY}.\n")
    bundle = tmp_path / "bundle"
    material.pack(bundle)
    said = refused(material, bundle, tmp_path / "handover", "regenerate the report")
    assert "mask_patterns[0]" in said


def test_a_report_holding_a_blanked_value_is_refused(tmp_path):
    material = Material(tmp_path / "work")
    material.report.write_text("# Report\n\nThe field says: Some text.\n")
    bundle = tmp_path / "bundle"
    material.pack(bundle)
    said = refused(material, bundle, tmp_path / "handover", "regenerate", mask_keys=["inputschema"])
    assert "mask_key:inputschema" in said


def test_a_pattern_outside_the_reviewed_surfaces_refuses(tmp_path):
    """On the command line the description is in run_started's argv, where nothing is
    redacted: the canary would reach the customer, so nothing is written."""
    material = Material(tmp_path / "work")
    material.session = drive(
        material.held_path, tmp_path / "argv", "--scenario",
        str(material.held_path.parent / "all-signals.yaml"), "--", sys.executable,
        str(FIXTURES / "discovery_server.py"), "--tool-description", DESCRIPTION,
    )  # fmt: skip
    bundle = tmp_path / "bundle"
    material.pack(bundle)
    said = refused(material, bundle, tmp_path / "handover", "outside the surfaces")
    assert "mask_patterns[0]" in said


def test_an_out_inside_the_source_or_existing_is_refused(source, tmp_path):
    material, bundle, _ = source
    with pytest.raises(evidence.EvidenceError, match="source bundle"):
        redact(material, bundle, bundle / "handover")
    assert not (bundle / "handover").exists()
    existing = tmp_path / "taken"
    existing.mkdir()
    with pytest.raises(evidence.EvidenceError, match="exists"):
        redact(material, bundle, existing)


# -- the customer README ----------------------------------------------------------------------


def test_the_readme_names_the_index_digest_and_reads_back(source, tmp_path):
    material, bundle, packed = source
    out = tmp_path / "handover"
    made = redact(material, bundle, out)
    text = (out / handover.CUSTOMER_README).read_text()

    fields = handover.parse_customer_readme(text)

    assert f"evidence verify DIR --index-digest {made.index_digest}" in text
    assert fields.index_digest == made.index_digest
    assert fields.derived_from == packed.index_digest
    assert fields.engagement_id_declared == "acme-2026-10"
    assert fields.customer_declared == 'ACME "Labs"\nGmbH', "a name read back exactly"
    assert fields.recordings == 2
    assert fields.egress_not_observed == 2, "host runs: egress not observed"
    assert fields.redaction_rules == 3
    assert fields.values_redacted == made.values_redacted == 2
    assert fields.report is True
    assert handover.render_customer_readme(fields) == text
    assert "egress not observed" in text
    assert "Nothing in this bundle is a verdict" in text
    assert "responsible disclosure" in text
    assert "mask_patterns" not in text, "how many rules, never what"


def test_the_readme_is_the_same_text_but_names_and_numbers(source, tmp_path):
    fields = handover.ReadmeFields(
        engagement_id_declared="x", customer_declared=None, window_from=None, window_until=None,
        index_digest="a" * 64, derived_from=None, created_utc="2026-10-29T09:00:00Z",
        recordings=0, egress_not_observed=0, redaction_rules=0, values_redacted=0, report=False,
    )  # fmt: skip
    other = handover.ReadmeFields(
        engagement_id_declared="- Recordings: 99", customer_declared="Ünïcode",
        window_from="2026-10-01T00:00:00Z", window_until="2026-10-31T00:00:00Z",
        index_digest="b" * 64, derived_from="c" * 64, created_utc="2026-10-30T09:00:00Z",
        recordings=3, egress_not_observed=1, redaction_rules=2, values_redacted=7, report=True,
    )  # fmt: skip
    first = handover.render_customer_readme(fields)
    second = handover.render_customer_readme(other)
    assert handover.parse_customer_readme(second) == other, "a name cannot pass for a line"
    fixed = [line for line in first.splitlines() if not line.startswith("- ")]
    assert fixed == [
        line.replace("b" * 64, "a" * 64)
        for line in second.splitlines()
        if not line.startswith("- ")
    ]


def test_parse_customer_readme_refuses_a_page_missing_a_field():
    with pytest.raises(ValueError, match="not named"):
        handover.parse_customer_readme("# Evidence bundle\n\n- Recordings: 3\n")


def test_a_readme_with_a_sentence_added_is_not_intact(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    made = redact(material, bundle, out)
    readme = out / handover.CUSTOMER_README
    readme.write_text(readme.read_text() + "\nThe operator found no weakness.\n")

    checked = evidence.verify(out, index_digest=made.index_digest)

    assert not checked.intact
    assert checked.readme is None
    assert any("is not the page this bundle" in problem for problem in checked.problems)


def test_a_readme_with_a_count_changed_is_not_intact(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    readme = out / handover.CUSTOMER_README
    text = readme.read_text()
    changed = text.replace(
        "- Values redacted for this handover: 2", "- Values redacted for this handover: 0"
    )
    assert changed != text
    readme.write_text(changed)
    assert not evidence.verify(out).intact


# -- what a mask key blanks must be gone everywhere ------------------------------------------


def test_a_value_a_mask_key_blanks_that_also_stands_elsewhere_refuses(tmp_path):
    """The description is blanked in the listing by its key, but the command line carries it
    too, in run_started's argv: it would reach the customer, so nothing is written."""
    material = Material(tmp_path / "work")
    unique = "Unique description 5150, no pattern in it."
    material.session = drive(
        material.held_path, tmp_path / "argv", "--scenario",
        str(material.held_path.parent / "all-signals.yaml"), "--", sys.executable,
        str(FIXTURES / "discovery_server.py"), "--tool-description", unique,
    )  # fmt: skip
    bundle = tmp_path / "bundle"
    material.pack(bundle)

    said = refused(
        material, bundle, tmp_path / "handover", "outside the surfaces", mask_keys=["tools"]
    )

    assert "a value mask_key:tools blanks" in said
    assert unique not in said, "never the value"


# -- the page version -------------------------------------------------------------------------

#: The words no generated document uses: whole words, so "certificate" passes.
BANNED = re.compile(
    r"\b(safe|secure|security|vulnerable|vulnerability|exploit|risk|clean|compliant|certified|"
    r"guaranteed)\b",
    re.IGNORECASE,
)


def a_page(**changes) -> handover.ReadmeFields:
    fields = {
        "engagement_id_declared": "x", "customer_declared": None, "window_from": None,
        "window_until": None, "index_digest": "a" * 64, "derived_from": "b" * 64,
        "created_utc": "2026-11-09T09:00:00Z", "recordings": 1, "egress_not_observed": 1,
        "redaction_rules": 1, "values_redacted": 1, "report": True,
    }  # fmt: skip
    fields.update(changes)
    return handover.ReadmeFields(**fields)


def rewritten_index(bundle: Path, change) -> None:
    path = bundle / evidence.INDEX_FILE
    data = json.loads(path.read_text())
    change(data)
    path.write_bytes(evidence.canonical_json(data))


@pytest.mark.parametrize("version", sorted(handover.WORDINGS))
def test_no_wording_of_the_page_uses_a_banned_word(version):
    text = handover.render_customer_readme(a_page(), version=version)
    assert not BANNED.findall(text)
    assert "not a judgement of the server" in text


def test_a_handover_made_now_names_the_page_version_and_verifies(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    made = redact(material, bundle, out)

    index = json.loads((out / evidence.INDEX_FILE).read_text())
    assert index["page_version"] == handover.PAGE_VERSION == 2
    assert "page_version" not in json.loads((bundle / evidence.INDEX_FILE).read_text()), (
        "a bundle packed from a store has no generated page"
    )
    checked = evidence.verify(out, index_digest=made.index_digest)
    assert checked.intact and checked.readme == evidence.README_NAMES_INDEX
    assert checked.index.page_version == 2
    text = (out / handover.CUSTOMER_README).read_text()
    assert text == handover.render_customer_readme(handover.parse_customer_readme(text), 2)


def test_a_bundle_of_version_2_keeps_verifying_after_a_third_wording(source, tmp_path, monkeypatch):
    material, bundle, _ = source
    first = tmp_path / "handover-2"
    made_first = redact(material, bundle, first)
    page_2 = (first / handover.CUSTOMER_README).read_bytes()

    third_text = handover.WORDINGS[2].text.replace(
        "Nothing in this bundle is a verdict.", "No part of this bundle is a verdict."
    )
    assert third_text != handover.WORDINGS[2].text
    monkeypatch.setattr(
        handover,
        "WORDINGS",
        {**handover.WORDINGS, 3: handover.Wording(handover.WORDINGS[2].labels, third_text)},
    )
    monkeypatch.setattr(handover, "PAGE_VERSION", 3)

    old = evidence.verify(first, index_digest=made_first.index_digest)
    assert old.intact and old.readme == evidence.README_NAMES_INDEX, old.summary()
    assert (first / handover.CUSTOMER_README).read_bytes() == page_2
    fields = handover.parse_customer_readme(page_2.decode(), version=2)
    assert handover.render_customer_readme(fields, version=3).encode() != page_2, (
        "the third wording would have failed the second bundle"
    )

    second = tmp_path / "handover-3"
    made_second = redact(material, bundle, second)
    assert json.loads((second / evidence.INDEX_FILE).read_text())["page_version"] == 3
    page_3 = (second / handover.CUSTOMER_README).read_text()
    assert "No part of this bundle is a verdict." in page_3
    new = evidence.verify(second, index_digest=made_second.index_digest)
    assert new.intact and new.readme == evidence.README_NAMES_INDEX


@pytest.mark.parametrize("version", [99, 0, True, "1", 1.0, None])
def test_an_unknown_page_version_is_refused_whole(source, tmp_path, version):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    rewritten_index(out, lambda data: data.update(page_version=version))

    for read in (
        lambda: evidence.read_index(out / evidence.INDEX_FILE),
        lambda: evidence.verify(out),
    ):
        with pytest.raises(evidence.EvidenceError) as refused:
            read()
        assert "page_version" in str(refused.value)
        assert "is not one this tool knows (1, 2)" in str(refused.value)
        assert "the version of the tool that made it" in str(refused.value)


def test_a_handover_index_without_a_page_version_is_refused_whole(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    rewritten_index(out, lambda data: data.pop("page_version"))

    with pytest.raises(evidence.EvidenceError) as refused:
        evidence.verify(out)
    assert "page_version: missing" in str(refused.value)
    assert "make the handover again from its source bundle with evidence redact" in str(
        refused.value
    )


def test_a_packed_index_naming_a_page_version_is_refused_whole(source):
    _, bundle, _ = source
    rewritten_index(bundle, lambda data: data.update(page_version=1))
    with pytest.raises(evidence.EvidenceError, match="a bundle packed from a store has no"):
        evidence.read_index(bundle / evidence.INDEX_FILE)


def test_a_readme_beside_a_packed_index_is_not_the_bundle_s(source, tmp_path):
    material, bundle, _ = source
    out = tmp_path / "handover"
    redact(material, bundle, out)
    shutil.copyfile(out / handover.CUSTOMER_README, bundle / handover.CUSTOMER_README)
    checked = evidence.verify(bundle)
    assert not checked.intact
    assert any("names no page version" in problem for problem in checked.problems)


def test_parse_and_render_refuse_an_unknown_page_version():
    for call in (
        lambda: handover.render_customer_readme(a_page(), version=3),
        lambda: handover.parse_customer_readme("", version=3),
    ):
        with pytest.raises(ValueError, match="page version 3 is not one this tool knows"):
            call()
