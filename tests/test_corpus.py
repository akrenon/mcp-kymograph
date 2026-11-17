"""The reference/poison pair: a corpus entry with an expected output, held as an invariant.

The pair guards the whole pipeline at once — signals, normalisation, inspector, recording,
store. Against the scenario that asks for every signal, the clean server must yield nothing;
should it ever yield something, a signal has become too loose or the normalisation reaches too
far, and this test says so before a real server is involved. The poison server must yield
exactly the pinned set: no more, which would be the same looseness, and no fewer, which would be
a signal that stopped seeing what it was built for.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import __version__
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = json.loads((FIXTURES / "corpus" / "expected.json").read_text())
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"


def content_version(files: list[str]) -> str:
    """Relative to the fixtures directory, which is the deepest one holding both files."""
    pairs = sorted([f, hashlib.sha256((FIXTURES / f).read_bytes()).hexdigest()] for f in files)
    return "sha256:" + hashlib.sha256(json.dumps(pairs).encode()).hexdigest()


def drive(entry: dict, out: Path) -> list[dict]:
    """The entry driven through the project's manifest, the way a corpus run is made."""
    done = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "drive",
            "-q",
            "--out-dir",
            str(out),
            "--manifest",
            str(FIXTURES / "corpus" / "manifest.yaml"),
            "--entry",
            entry["server"],
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    (path,) = out.glob("*/events.jsonl")
    return [json.loads(line) for line in path.read_text().splitlines()]


def projected(events: list[dict]) -> list[dict]:
    return sorted(
        (
            {name: e["key"][name] for name in ("statement", "locator", "signal")}
            for e in events
            if e["type"] == "finding"
        ),
        key=json.dumps,
    )


@pytest.mark.parametrize("name", ["reference", "poison"])
def test_each_entry_yields_exactly_its_expected_findings(tmp_path, name):
    entry = EXPECTED["entries"][name]
    events = drive(entry, tmp_path)
    assert projected(events) == sorted(entry["findings"], key=json.dumps)

    # Every statement was evaluated, so "nothing" on the reference is a checked nothing.
    evaluated = {e["statement"] for e in events if e["type"] == "statement_evaluated"}
    finished = events[-1]
    assert finished["type"] == "run_finished"
    assert evaluated == set(finished["findings_by_statement"])
    assert all(e["reason"] is None for e in events if e["type"] == "statement_evaluated")


@pytest.mark.parametrize("name", ["reference", "poison"])
def test_each_entry_s_key_carries_its_own_content_version(tmp_path, name):
    """server_version is the digest over the entry's own files — not the repository commit,
    not this tool's version — and the two entries differ in it."""
    entry = EXPECTED["entries"][name]
    events = drive(entry, tmp_path)
    expected = content_version(entry["files"])
    assert events[0]["server_identity"]["version"] == expected
    assert events[0]["scenario_name"] == EXPECTED["scenario"]
    for event in (e for e in events if e["type"] == "finding"):
        assert event["key"]["server"] == entry["server"]
        assert event["key"]["server_version"] == expected
        assert event["key"]["tool_version"] == __version__
        assert event["key"]["scenario"] == EXPECTED["scenario"]
    other = "poison" if name == "reference" else "reference"
    assert content_version(EXPECTED["entries"][other]["files"]) != expected


def test_the_pair_goes_through_the_store_with_its_provenance(tmp_path):
    """Filed under reference and poison respectively: the clean run complete and empty, the
    poison run complete with exactly the pinned keys."""
    store = Store.open(tmp_path / "findings.sqlite")
    with store:
        for name in ("reference", "poison"):
            drive(EXPECTED["entries"][name], tmp_path / name)
            (path,) = (tmp_path / name).glob("*/events.jsonl")
            filed = store.ingest(path)
            assert filed.provenance == name, "from the manifest entry, not from the caller"
            assert filed.complete, filed.problems
            assert filed.findings == len(EXPECTED["entries"][name]["findings"])
        assert store.findings_by_provenance("reference") == []
        poison = store.findings_by_provenance("poison")
        assert sorted(
            ({n: k[n] for n in ("statement", "locator", "signal")} for k in poison),
            key=json.dumps,
        ) == sorted(EXPECTED["entries"]["poison"]["findings"], key=json.dumps)
        assert store.findings_by_provenance("real-world") == []


def write_manifest(directory: Path, paths: list[str]) -> Path:
    """A one-entry manifest in ``directory`` whose server content is ``paths``."""
    (directory / "s.yaml").write_text(ALL_SIGNALS.read_text())
    entry = {
        "name": "e",
        "provenance": "reference",
        "source": {"paths": paths},
        "launch": {"transport": "stdio", "command": ["python"]},
        "scenarios": ["s.yaml"],
    }
    manifest = directory / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "entries": [entry]}))
    return manifest


@pytest.mark.parametrize("inside", [False, True])
def test_a_link_as_an_intermediate_component_of_a_source_path_is_refused(tmp_path, inside):
    """A manifest entry naming ``link/x.py`` through a linked directory is invalid."""
    from mcp_kymograph.corpus import ManifestError, load

    real = tmp_path / "real"
    target = real / "inner" if inside else tmp_path / "outside"
    target.mkdir(parents=True)
    real.mkdir(exist_ok=True)
    (target / "x.py").write_text("x = 1\n")
    (real / "link").symlink_to(target, target_is_directory=True)
    manifest = write_manifest(real, ["link/x.py"])
    with pytest.raises(ManifestError, match="link is a symbolic link"):
        load(manifest)


@pytest.mark.parametrize(
    ("paths", "said"),
    [
        (["link/x.py"], "link is a symbolic link on the way to x.py"),
        (["absent.py"], "absent.py: neither a file nor a directory"),
        (["tree"], "tree/inner: a symbolic link inside the server's files"),
    ],
    ids=["link in a component", "nothing there", "link inside a directory"],
)
def test_a_refused_source_path_is_named_relative_to_the_manifest(tmp_path, paths, said):
    """The refusal says the path as the manifest wrote it. Where the manifest lies on this
    machine is not in the reason: a refusal may be kept beside a recording."""
    from mcp_kymograph.corpus import ManifestError, load

    real = tmp_path / "real"
    (real / "target").mkdir(parents=True)
    (real / "target" / "x.py").write_text("x = 1\n")
    (real / "link").symlink_to(real / "target", target_is_directory=True)
    (real / "tree").mkdir()
    (real / "tree" / "inner").symlink_to(real / "target", target_is_directory=True)
    manifest = write_manifest(real, paths)
    with pytest.raises(ManifestError) as refused:
        load(manifest)
    assert said in refused.value.reason
    assert str(tmp_path) not in refused.value.reason


def test_a_link_above_the_manifest_directory_does_not_change_the_identity(tmp_path):
    """Loading through ``alias -> real`` gives the identity of loading ``real`` itself."""
    from mcp_kymograph.corpus import load

    real = tmp_path / "real"
    real.mkdir()
    (real / "x.py").write_text("x = 1\n")
    write_manifest(real, ["x.py"])
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    direct = load(real / "manifest.json")
    through = load(tmp_path / "alias" / "manifest.json")
    assert through.entries[0].identity == direct.entries[0].identity
