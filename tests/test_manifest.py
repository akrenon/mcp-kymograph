"""The corpus manifest: read whole or refused whole, pinned by content, and what a run records."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import __version__, cli
from mcp_kymograph.corpus import ManifestError, load, tool_identity
from mcp_kymograph.identity import from_content
from mcp_kymograph.scenario import MAX_FILE_BYTES
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = FIXTURES / "discovery_server.py"
POISON = FIXTURES / "corpus" / "poison_server.py"
REFERENCE = FIXTURES / "corpus" / "reference_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"
EMPTY = FIXTURES / "scenarios" / "empty.yaml"
PROJECT = FIXTURES / "corpus" / "manifest.yaml"
SHA = "0123456789abcdef0123456789abcdef01234567"


def entry(here: Path, **changes) -> dict:
    """A valid in-repo entry for the poison server, relative to ``here``."""

    def rel(path: Path) -> str:
        return os.path.relpath(path, here)

    base = {
        "name": "poison-server",
        "provenance": "poison",
        "source": {"paths": [rel(POISON), rel(DISCOVERY)]},
        "launch": {"transport": "stdio", "command": ["{python}", str(POISON)]},
        "scenarios": [rel(ALL_SIGNALS)],
    }
    return {**base, **changes}


def write(tmp_path: Path, *entries: dict, **top) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "entries": list(entries), **top}))
    return path


# -- reading -------------------------------------------------------------------------------


def test_the_project_manifest_pins_the_pair_by_its_own_content():
    manifest = load(PROJECT)
    by_name = {e.name: e for e in manifest.entries}
    assert set(by_name) == {"reference-server", "poison-server"}
    assert by_name["poison-server"].identity == from_content([POISON, DISCOVERY])
    assert by_name["reference-server"].identity == from_content([REFERENCE, DISCOVERY])
    assert by_name["reference-server"].provenance == "reference"
    assert [s.name for s in by_name["poison-server"].scenarios] == ["all-signals"]


def test_placeholders_are_substituted_and_the_launch_digest_is_over_the_written_form(tmp_path):
    """The digest must not change from one machine to the next, so it covers the command as
    written; the command run here has the interpreter and the manifest's directory in it."""
    command = ["{python}", "{dir}/server.py", "--flag"]
    path = write(tmp_path, entry(tmp_path, launch={"transport": "stdio", "command": command}))
    (loaded,) = load(path).entries
    assert loaded.command == (sys.executable, f"{tmp_path.resolve()}/server.py", "--flag")
    assert loaded.command_written == tuple(command)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    moved = write(elsewhere, entry(elsewhere, launch={"transport": "stdio", "command": command}))
    assert load(moved).entries[0].launch_digest == loaded.launch_digest


def test_other_launch_arguments_are_another_launch(tmp_path):
    one = load(write(tmp_path, entry(tmp_path))).entries[0]
    other = entry(tmp_path, launch={"transport": "stdio", "command": ["{python}", "x", "-v"]})
    two = load(write(tmp_path, other)).entries[0]
    assert one.identity == two.identity
    assert one.launch_digest != two.launch_digest


def test_an_external_entry_is_pinned_to_a_full_commit(tmp_path):
    external = entry(
        tmp_path, provenance="real-world", source={"revision": f"github.com/x/y@{SHA}"}
    )
    (loaded,) = load(write(tmp_path, external)).entries
    assert (loaded.identity.kind, loaded.identity.version) == ("revision", f"github.com/x/y@{SHA}")


def test_a_manifest_without_entries_is_valid_and_empty(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("version: 1\n")
    assert load(path).entries == ()


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({"provenance": "trusted"}, "unknown provenance 'trusted'"),
        ({"source": {}}, "exactly one"),
        ({"source": {"paths": ["a"], "revision": f"x/y@{SHA}"}}, "exactly one"),
        ({"source": {"revision": "github.com/x/y@HEAD"}}, "not a pinned revision"),
        ({"source": {"revision": "github.com/x/y@main"}}, "not a pinned revision"),
        ({"source": {"revision": "github.com/x/y@v1.0.0"}}, "not a pinned revision"),
        ({"source": {"revision": "github.com/x/y@0123456"}}, "not a pinned revision"),
        ({"source": {"paths": ["/etc/passwd"]}}, "relative to the manifest"),
        ({"source": {"paths": ["absent.py"]}}, "neither a file nor a directory"),
        ({"launch": {"transport": "http", "command": ["x"]}}, "unsupported transport 'http'"),
        ({"launch": {"transport": "stdio", "command": []}}, "non-empty list"),
        ({"scenarios": []}, "non-empty list of scenario files"),
        ({"scenarios": ["absent.yaml"]}, "cannot read"),
        ({"name": "has space"}, "is not a name"),
        ({"colour": "red"}, "unknown key 'colour'"),
    ],
)
def test_a_wrong_entry_is_refused_whole_with_the_place(tmp_path, change, fragment):
    path = write(tmp_path, {**entry(tmp_path), **change})
    with pytest.raises(ManifestError, match="entries\\[0\\]") as refused:
        load(path)
    assert fragment in str(refused.value)


@pytest.mark.parametrize("missing", ["name", "provenance", "source", "launch", "scenarios"])
def test_no_part_of_an_entry_has_a_default(tmp_path, missing):
    """In particular no identity: an entry without a pinned content does not load."""
    data = entry(tmp_path)
    del data[missing]
    with pytest.raises(ManifestError, match=f"{missing}: missing"):
        load(write(tmp_path, data))


def test_two_entries_with_one_name_are_refused(tmp_path):
    with pytest.raises(ManifestError, match="already an entry"):
        load(write(tmp_path, entry(tmp_path), entry(tmp_path)))


def test_a_version_this_loader_does_not_read_is_refused(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"version": 2, "entries": []}))
    with pytest.raises(ManifestError, match="unsupported 2"):
        load(path)


def test_an_entry_with_several_scenarios_needs_one_named(tmp_path):
    data = entry(
        tmp_path,
        scenarios=[os.path.relpath(ALL_SIGNALS, tmp_path), os.path.relpath(EMPTY, tmp_path)],
    )
    (loaded,) = load(write(tmp_path, data)).entries
    with pytest.raises(ManifestError, match="pick one of all-signals, empty"):
        loaded.scenario(None)
    assert loaded.scenario("empty").name == "empty"
    with pytest.raises(ManifestError, match="has no scenario 'other'"):
        loaded.scenario("other")


def test_the_tool_is_identified_by_its_version_and_its_own_content():
    identity = tool_identity()
    assert identity["version"] == __version__
    assert identity["content"].startswith("sha256:")
    assert identity == tool_identity(), "the same every time"


# -- driving an entry ------------------------------------------------------------------------


def drive(tmp_path: Path, *ours: str, server: tuple = ()) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "drive",
            "-q",
            "--out-dir",
            str(tmp_path / "runs"),
            *ours,
            *(("--", *server) if server else ()),
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )


def events_of(tmp_path: Path) -> list[dict]:
    (path,) = (tmp_path / "runs").glob("*/events.jsonl")
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_a_corpus_run_records_the_reproduction_triple(tmp_path):
    done = drive(tmp_path, "--manifest", str(PROJECT), "--entry", "poison-server")
    assert done.returncode == 0, done.stderr
    started = events_of(tmp_path)[0]
    loaded = load(PROJECT).entry("poison-server")
    assert started["server_name"] == "poison-server"
    assert started["reproduction"] == {
        "manifest": {"source": str(PROJECT), "digest": load(PROJECT).digest},
        "corpus": {
            "entry": "poison-server",
            "provenance": "poison",
            "identity": loaded.identity.to_dict(),
            "launch_digest": loaded.launch_digest,
        },
        "tool": tool_identity(),
        "scenario": {"name": "all-signals", "digest": loaded.scenarios[0].digest},
        "environment": {"isolation": "host", "sandbox_image": None, "target_image": None},
    }
    assert started["reproduction"]["tool"]["version"] == started["tool_version"]
    assert started["authorization"]["scenario_digest"] == loaded.scenarios[0].digest


def test_a_server_that_names_itself_otherwise_is_recorded_and_keyed_on_the_entry(tmp_path):
    """End to end: the entry is called "impostor", the server says "poison-server".
    Every key says impostor; the difference is an event; the announced name is kept."""
    data = entry(tmp_path, name="impostor")
    done = drive(tmp_path, "--manifest", str(write(tmp_path, data)), "--entry", "impostor")
    assert done.returncode == 0, done.stderr
    events = events_of(tmp_path)
    (mismatch,) = [e for e in events if e["type"] == "server_name_mismatch"]
    assert (mismatch["declared"], mismatch["announced"]) == ("impostor", "poison-server")
    by_seq = {e["seq"]: e for e in events}
    assert by_seq[mismatch["message_seq"]]["responded_method"] == "initialize"
    findings = [e for e in events if e["type"] == "finding"]
    assert findings and all(f["key"]["server"] == "impostor" for f in findings)
    assert events[-1]["announced_server"] == "poison-server"


def test_a_server_that_names_itself_as_its_entry_leaves_no_mismatch(tmp_path):
    done = drive(tmp_path, "--manifest", str(PROJECT), "--entry", "poison-server")
    assert done.returncode == 0, done.stderr
    assert not [e for e in events_of(tmp_path) if e["type"] == "server_name_mismatch"]


@pytest.mark.parametrize(
    ("data", "flags", "fragment"),
    [
        ({"provenance": "real-world"}, (), "only under runsc, which this version does not"),
        ({"provenance": "real-world"}, ("--isolation", "runc"), "only under runsc, not runc"),
        ({"provenance": "real-world"}, ("--isolation", "host"), "only under runsc, not host"),
        ({"provenance": "real-world"}, ("--isolation", "runsc"), "does not provide"),
        (
            {"provenance": "poison", "source": {"revision": f"github.com/x/y@{SHA}"}},
            (),
            "delivers",
        ),
    ],
)
def test_entries_this_version_cannot_run_safely_are_refused_not_downgraded(
    tmp_path, data, flags, fragment
):
    path = write(tmp_path, entry(tmp_path, **data))
    done = drive(tmp_path, "--manifest", str(path), "--entry", "poison-server", *flags)
    assert done.returncode == cli.EXIT_REFUSED
    assert fragment.encode() in done.stderr
    assert not (tmp_path / "runs").exists(), "refused before anything was created"


def test_a_server_that_never_completes_the_handshake_is_not_a_result(tmp_path):
    """server_failed: recorded as the run's result, its own exit code, filed in that state —
    never as a server with nothing to find."""
    command = ["{python}", str(POISON), "--fail-initialize"]
    path = write(tmp_path, entry(tmp_path, launch={"transport": "stdio", "command": command}))
    done = drive(tmp_path, "--manifest", str(path), "--entry", "poison-server")
    assert done.returncode == cli.EXIT_SERVER_FAILED, done.stderr
    assert b"server_failed (handshake_incomplete)" in done.stderr
    events = events_of(tmp_path)
    assert [(e["reason"]) for e in events if e["type"] == "server_failed"] == [
        "handshake_incomplete"
    ]
    with Store.open(tmp_path / "store.sqlite") as store:
        (recording,) = (tmp_path / "runs").glob("*/events.jsonl")
        filed = store.ingest(recording)
    assert not filed.complete
    assert filed.state == "server_failed"
    assert "server_failed: handshake_incomplete (initialize was answered without a result)" in (
        filed.problems
    )


@pytest.mark.parametrize(
    ("summary", "problem"),
    [
        (None, "runc run without egress_summary"),
        ({"consistent": False}, "the sink's account differs from the kernel's"),
        ({"consistent": True}, "egress_summary has no udp_loss"),
        ({"consistent": True, "udp_loss": {"kernel": 10, "sink": 7, "lost": 3}},
         "the sink missed 3 of 10 UDP datagram(s) (30.00%)"),
    ],
)  # fmt: skip
def test_a_sandboxed_run_without_a_sound_egress_account_is_incomplete(tmp_path, summary, problem):
    """What the target sent is then unknown — not "nothing"."""
    done = drive(tmp_path, "--manifest", str(PROJECT), "--entry", "poison-server")
    assert done.returncode == 0, done.stderr
    (recording,) = (tmp_path / "runs").glob("*/events.jsonl")
    events = [json.loads(line) for line in recording.read_text().splitlines()]
    events[0]["isolation"] = "runc"
    events[0]["reproduction"]["environment"]["isolation"] = "runc"
    if summary is not None:
        events.insert(-1, {"v": events[0]["v"], "type": "egress_summary", "seq": 0, **summary})
    recording.write_text("".join(json.dumps(e) + "\n" for e in events))
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(recording)
    assert not filed.complete
    assert any(problem in p for p in filed.problems), filed.problems


def test_isolation_is_decided_per_corpus_entry_only(tmp_path):
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "drive", "--isolation", "runc", "--", "true"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == cli.EXIT_REFUSED
    assert b"belongs to a corpus run" in done.stderr


@pytest.mark.parametrize(
    "extra",
    [
        ("--server-content", str(POISON)),
        ("--server-revision", f"github.com/x/y@{SHA}"),
    ],
)
def test_a_corpus_run_takes_nothing_of_its_identity_from_the_command_line(tmp_path, extra):
    done = drive(tmp_path, "--manifest", str(PROJECT), "--entry", "poison-server", *extra)
    assert done.returncode == cli.EXIT_REFUSED
    assert b"from the manifest" in done.stderr


def test_a_corpus_run_takes_no_server_command(tmp_path):
    done = drive(
        tmp_path,
        "--manifest",
        str(PROJECT),
        "--entry",
        "poison-server",
        server=(sys.executable, str(POISON)),
    )
    assert done.returncode == cli.EXIT_REFUSED
    assert b"drop the -- command" in done.stderr


def test_an_unknown_entry_is_refused_naming_the_entries(tmp_path):
    done = drive(tmp_path, "--manifest", str(PROJECT), "--entry", "nobody")
    assert done.returncode == cli.EXIT_REFUSED
    assert b"no entry 'nobody'" in done.stderr and b"poison-server" in done.stderr


def test_a_long_manifest_path_gives_way_and_the_entries_stay_whole(tmp_path):
    # A checkout can lie arbitrarily deep. The refusal is cut to fit the terminal line; what
    # is cut is the front of the path, never the list of entries the operator picks from.
    deep = tmp_path.joinpath(*(f"{index}-" + "d" * 90 for index in range(5)))
    deep.mkdir(parents=True)
    names = [f"server-number-{index:02d}" for index in range(8)]
    path = write(deep, *(entry(deep, name=name) for name in names))
    assert len(str(path)) > 400
    done = drive(tmp_path, "--manifest", str(path), "--entry", "nobody")
    assert done.returncode == cli.EXIT_REFUSED
    line = done.stderr.decode().strip()
    assert line.endswith("no entry 'nobody'; entries: " + ", ".join(names)), line
    assert "/manifest.json: no entry" in line
    assert str(tmp_path) not in line
    assert len(line) <= len("kymograph: ") + 200


def test_a_refusal_shortens_its_path_only_when_it_has_to():
    short = ManifestError("no entry 'x'; entries: a, b", source="corpus/manifest.yaml")
    assert cli.manifest_refusal(short) == "corpus/manifest.yaml: no entry 'x'; entries: a, b"
    long = ManifestError("no entry 'x'; entries: a, b", source="/" + "p" * 300 + "/m.yaml")
    shortened = cli.manifest_refusal(long, limit=80)
    assert len(shortened) == 80
    assert shortened.startswith("…") and shortened.endswith("p/m.yaml: no entry 'x'; entries: a, b")


def test_a_reason_longer_than_the_line_is_kept_whole_and_the_file_name_stays():
    known = ", ".join(f"entry-{index}" for index in range(60))
    refusal = ManifestError(f"no entry 'x'; entries: {known}", source="/" + "p" * 300 + "/m.yaml")
    assert cli.manifest_refusal(refusal) == f"…/m.yaml: no entry 'x'; entries: {known}"
    without = ManifestError(f"a corpus run needs both; {known}")
    assert cli.manifest_refusal(without) == f"a corpus run needs both; {known}"


def test_a_path_as_long_as_its_room_is_kept_whole():
    # A reason past the line leaves the path its file name and the mark. When that is the whole
    # path already, a "…" would stand in for one character and claim a cut that saves nothing.
    at_the_edge = ManifestError("y" * 250, source="c/manifest.yaml")
    assert cli.manifest_refusal(at_the_edge) == "c/manifest.yaml: " + "y" * 250


def test_a_path_shorter_than_its_room_is_kept_whole():
    short = ManifestError("x" * 300, source="m.yaml")
    assert cli.manifest_refusal(short) == "m.yaml: " + "x" * 300


def test_a_path_one_longer_than_its_room_is_shortened():
    one_over = ManifestError("y" * 250, source="cd/manifest.yaml")
    assert cli.manifest_refusal(one_over) == "…/manifest.yaml: " + "y" * 250


def test_a_refusal_keeps_its_path_apart_from_its_reason(tmp_path):
    with pytest.raises(ManifestError) as caught:
        load(PROJECT).entry("nobody")
    assert caught.value.source == str(PROJECT)
    assert caught.value.reason == "no entry 'nobody'; entries: reference-server, poison-server"
    assert str(caught.value) == f"{PROJECT}: {caught.value.reason}"
    with pytest.raises(ManifestError) as caught:
        load(tmp_path / "missing.yaml")
    assert caught.value.source == str(tmp_path / "missing.yaml")
    assert caught.value.reason.startswith("cannot read: ")


#: One file per way the loader refuses a file it could open: name, bytes (None: one byte past
#: the size limit, built when the test runs), and how the reason for exactly that refusal begins.
REFUSED_FILES = {
    "suffix": ("manifest.txt", b"{}", "unknown suffix '.txt'"),
    "size": ("manifest.json", None, f"larger than {MAX_FILE_BYTES} bytes"),
    "encoding": ("manifest.json", b"\xff", "not UTF-8 at byte 0"),
    "parse": ("manifest.json", b"{not json", "line 1 column 2: "),
    "content": ("manifest.json", b'{"version": 1, "entries": [], "unknown": 1}', "unknown key"),
}


@pytest.mark.parametrize("kind", sorted(REFUSED_FILES))
def test_every_refused_file_keeps_its_path_apart_from_its_reason(tmp_path, kind):
    # The path is what the terminal line may shorten; a reason that carried it again would bring
    # the whole path back in the part that is never shortened.
    name, raw, begins = REFUSED_FILES[kind]
    path = tmp_path / name
    path.write_bytes(b" " * (MAX_FILE_BYTES + 1) if raw is None else raw)
    with pytest.raises(ManifestError) as caught:
        load(path)
    assert caught.value.reason.startswith(begins), caught.value.reason
    assert caught.value.source == str(path)
    assert str(path) not in caught.value.reason, caught.value.reason
    assert str(caught.value) == f"{path}: {caught.value.reason}"


def test_corpus_check_shortens_a_long_manifest_path_as_drive_does(tmp_path):
    deep = tmp_path.joinpath(*(f"{index}-" + "d" * 90 for index in range(5)))
    deep.mkdir(parents=True)
    path = deep / "manifest.json"
    path.write_bytes(REFUSED_FILES["content"][1])
    with pytest.raises(ManifestError) as caught:
        load(path)
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "corpus", "check", str(path)],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == cli.EXIT_REFUSED
    line = done.stderr.decode().strip().splitlines()[-1]
    assert line == "kymograph: " + cli.manifest_refusal(caught.value), line
    assert line.endswith(f"/manifest.json: {caught.value.reason}"), line
    assert str(tmp_path) not in line


def test_an_entry_without_a_manifest_is_refused(tmp_path):
    done = drive(tmp_path, "--entry", "poison-server")
    assert done.returncode == cli.EXIT_REFUSED
    assert b"both --manifest and --entry" in done.stderr


def test_corpus_check_shows_what_the_manifest_pins(tmp_path):
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "corpus", "check", str(PROJECT)],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    listing = json.loads(done.stdout)
    assert listing["tool"] == tool_identity()
    names = {e["name"]: e for e in listing["entries"]}
    assert (
        names["poison-server"]["identity"]
        == load(PROJECT).entry("poison-server").identity.to_dict()
    )
    assert names["poison-server"]["refused_here"] is None
    assert names["poison-server"]["isolation_permitted"] == ["host", "runc"]


def test_corpus_check_refuses_a_broken_manifest(tmp_path):
    path = write(tmp_path, entry(tmp_path, provenance="trusted"))
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "corpus", "check", str(path)],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == cli.EXIT_REFUSED
    assert b"unknown provenance" in done.stderr


# -- the working directory of a host run -----------------------------------------------------


def marking_server(directory: Path, marker: str) -> Path:
    """A server script that leaves ``marker`` in its own directory, then is the discovery one."""
    script = directory / "server.py"
    script.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(FIXTURES)!r})\n"
        "import discovery_server\n"
        f"Path(__file__).resolve().parent.joinpath({marker!r}).write_text('ran')\n"
        "sys.exit(discovery_server.main())\n"
    )
    return script


def drive_from(cwd: Path, out: Path, *rest: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "drive", "-q", "--out-dir", str(out), *rest],
        capture_output=True,
        timeout=60,
        check=False,
        cwd=cwd,
    )


def test_a_host_run_starts_the_hashed_file_not_one_of_the_same_name_in_the_callers_directory(
    tmp_path,
):
    """A relative ``server.py`` in the command is the manifest directory's, whatever the working
    directory of the caller: the file that was hashed is the file that runs."""
    mods, evil = tmp_path / "mods", tmp_path / "evil"
    mods.mkdir()
    evil.mkdir()
    marking_server(mods, "hashed-ran")
    marking_server(evil, "evil-ran")
    data = entry(
        mods,
        source={"paths": ["server.py"]},
        launch={"transport": "stdio", "command": ["{python}", "server.py"]},
        scenarios=[os.path.relpath(ALL_SIGNALS, mods)],
    )
    path = write(mods, data)
    done = drive_from(evil, tmp_path / "runs", "--manifest", str(path), "--entry", "poison-server")
    assert done.returncode == 0, done.stderr
    assert (mods / "hashed-ran").exists()
    assert not (evil / "evil-ran").exists()
    started = events_of(tmp_path)[0]
    # No field for the working directory: the fields are those of any drive. Where the manifest
    # lies is said as before, by the paths the manifest and its scenario were given by.
    assert list(started) == PLAIN_DRIVE_RUN_STARTED
    assert str(mods) not in json.dumps(started["reproduction"]["environment"])
    assert started["reproduction"]["manifest"]["source"] == str(path)


def test_a_relative_program_of_a_host_run_is_the_manifest_directorys(tmp_path):
    """``./server`` as the program itself, not as an argument of the interpreter."""
    mods, evil = tmp_path / "mods", tmp_path / "evil"
    for directory, marker in ((mods, "hashed-ran"), (evil, "evil-ran")):
        directory.mkdir()
        script = marking_server(directory, marker)
        program = directory / "server"
        program.write_text(f"#!{sys.executable}\n" + script.read_text())
        program.chmod(0o755)
    data = entry(
        mods,
        source={"paths": ["server"]},
        launch={"transport": "stdio", "command": ["./server"]},
        scenarios=[os.path.relpath(ALL_SIGNALS, mods)],
    )
    path = write(mods, data)
    done = drive_from(evil, tmp_path / "runs", "--manifest", str(path), "--entry", "poison-server")
    assert done.returncode == 0, done.stderr
    assert (mods / "hashed-ran").exists()
    assert not (evil / "evil-ran").exists()


def test_a_drive_without_a_manifest_keeps_the_callers_working_directory(tmp_path):
    """No manifest, no directory to name: ``drive -- python server.py`` runs in the cwd."""
    marking_server(tmp_path, "ran-here")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    marking_server(elsewhere, "ran-elsewhere")
    done = drive_from(
        elsewhere,
        tmp_path / "runs",
        "--scenario",
        str(ALL_SIGNALS),
        "--",
        sys.executable,
        "server.py",
    )
    assert done.returncode == 0, done.stderr
    assert (elsewhere / "ran-elsewhere").exists()
    assert not (tmp_path / "ran-here").exists()


#: The fields of ``run_started`` in a ``drive`` without a manifest, in the order they are written.
PLAIN_DRIVE_RUN_STARTED = [
    "v",
    "run_id",
    "seq",
    "t_ns",
    "type",
    "argv",
    "argv_redaction_count",
    "mode",
    "script",
    "script_digest",
    "script_vars",
    "server_identity",
    "scenario_name",
    "server_name",
    "reproduction",
    "authorization",
    "virtual_environment",
    "isolation",
    "transport",
    "endpoint",
    "trust_store_env",
    "auth",
    "pacing_enforced",
    "pacing",
    "pseudonyms",
    "probe",
    "limits",
    "inputs",
    "wall_clock_utc",
    "tool_version",
    "schema_version",
]


def test_a_drive_without_a_manifest_records_what_it_recorded_before(tmp_path):
    """The other side of the rule above: without a manifest nothing about the start changes, and
    nothing about the recording. The command is written as it was given, no identity and no
    manifest are claimed, and the directory the server started in is in no field."""
    here = tmp_path / "here"
    here.mkdir()
    marking_server(here, "ran-here")
    done = drive_from(
        here, tmp_path / "runs", "--scenario", str(ALL_SIGNALS), "--", sys.executable, "server.py"
    )
    assert done.returncode == 0, done.stderr
    assert (here / "ran-here").exists()
    started = events_of(tmp_path)[0]
    assert list(started) == PLAIN_DRIVE_RUN_STARTED
    assert started["argv"] == [os.path.basename(sys.executable), "server.py"]
    assert started["server_identity"] is None
    assert started["server_name"] is None
    assert started["isolation"] == "host"
    assert started["reproduction"]["manifest"] is None
    assert started["reproduction"]["corpus"] is None
    assert started["reproduction"]["environment"] == {
        "isolation": "host",
        "sandbox_image": None,
        "target_image": None,
    }
    assert str(here) not in json.dumps(started)
