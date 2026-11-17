"""Replaying a run from a bundle: the ``script`` role, the image digests of the index, and
``evidence replay``.

The material is real: a corpus run driven under a second-version engagement file (known values
and a salt) with a script file, filed, packed with ``--script``, the bundle copied to another
place and the run repeated from there. The customer's values are made up when the test runs, so
that none stands in the file. A recording that cannot be repeated is the real one with its
``run_started`` edited and packed as a session.
"""

from __future__ import annotations

import json
import re
import secrets
import shutil
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, events, evidence, masking
from mcp_kymograph import script as script_file
from mcp_kymograph.masking import PLACEHOLDER
from mcp_kymograph.scenario import parse_yaml
from test_personal_data import PSEUDONYM, SALT_ENV, address, iban, second_file

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = FIXTURES / "discovery_server.py"

#: What differs between a run and its repetition and is not the run: the clock and spans of time
#: (every event's ``t_ns``, ``duration_ns`` of ``run_finished``, ``wall_clock_utc``), the run's
#: name, and the fields of ``run_started`` that say where and on what it ran — the path of the
#: scenario (the repetition loads the bundle's copy), and what 1.2 records as the environment
#: (``inputs.python``, ``inputs.platform``). No process id is recorded for a host run. The
#: server's command (``argv``) and the manifest's path (``reproduction.manifest.source``) are
#: compared: the manifest is loaded from where the run recorded it while the file there is still
#: the one. ``script_digest`` is the one field of the script's that differs: the repetition runs
#: the bundle's copy, a JSON document, so its digest is the copy's (the test says which).
VOLATILE = {"t_ns", "duration_ns", "run_id", "wall_clock_utc"}
ENVIRONMENT = (
    ("authorization", "scenario"),
    ("inputs", "python"),
    ("inputs", "platform"),
    ("script_digest",),
)

SCRIPT = """\
# A probe of the server's listing.
version: 1
name: probe
steps:
  - initialize
  - list: tools/list
"""


@pytest.fixture
def salt(monkeypatch) -> str:
    value = "salt-" + secrets.token_hex(16)
    monkeypatch.setenv(SALT_ENV, value)
    return value


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def stable(events: list[dict]) -> list[dict]:
    """The events without their time and name, and without ``run_started``'s environment."""
    kept = [{key: value for key, value in event.items() if key not in VOLATILE} for event in events]
    started = json.loads(json.dumps(kept[0]))
    for path in ENVIRONMENT:
        node = started
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    kept[0] = started
    return kept


class Setup:
    """A corpus run under the engagement with ``script``, filed and packed."""

    def __init__(
        self, root: Path, *, script: str = SCRIPT, values: tuple[str, ...] = (), **file
    ) -> None:
        self.root = root
        self.value_list = list(values)
        manifest_dir = root / "fixtures"
        shutil.copytree(
            FIXTURES / "corpus",
            manifest_dir / "corpus",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        (manifest_dir / "scenarios").mkdir()
        shutil.copyfile(
            FIXTURES / "scenarios" / "all-signals.yaml",
            manifest_dir / "scenarios" / "all-signals.yaml",
        )
        shutil.copyfile(DISCOVERY, manifest_dir / "discovery_server.py")
        self.manifest = manifest_dir / "corpus" / "manifest.yaml"
        self.held = second_file(root / "engagement", known_values=list(values), **file)
        self.script = root / "script.yaml"
        self.script.write_text(script)
        self.runs = root / "runs"
        self.store = root / "store.sqlite"

    def drive(
        self, *extra: str, script: Path | None = None, entry: str = "reference-server", ok=(0,)
    ) -> Path:
        before = set(self.runs.glob("*/events.jsonl"))
        code = cli.main(
            ["drive", "-q", "--engagement", str(self.held), "--manifest", str(self.manifest),
             "--entry", entry, "--isolation", "host", "--out-dir", str(self.runs),
             *([] if script is None else ["--script", str(script)]), *extra]
        )  # fmt: skip
        assert code in ok
        (recording,) = set(self.runs.glob("*/events.jsonl")) - before
        return recording

    def ingest(self, *recordings: Path, ok=(0,)) -> None:
        code = cli.main(
            ["store", "ingest", "-q", "--store", str(self.store), "--engagement", str(self.held),
             *map(str, recordings)]
        )  # fmt: skip
        assert code in ok

    def pack(self, out: Path, *scripts: Path, sessions: tuple[Path, ...] = ()) -> int:
        return cli.main(
            ["evidence", "pack", "-q", "--engagement", str(self.held), "--store", str(self.store),
             "--runs", str(self.runs), "--out", str(out),
             *[arg for script in scripts for arg in ("--script", str(script))],
             *[arg for session in sessions for arg in ("--session", str(session))]]
        )  # fmt: skip

    def replay(self, bundle: Path, run: str, out_dir: Path, *extra: str, held: Path | None = None):
        return cli.main(
            ["evidence", "replay", "-q", str(bundle), "--run", run,
             "--engagement", str(held or self.held), "--out-dir", str(out_dir), *extra]
        )  # fmt: skip


@pytest.fixture
def setup(tmp_path, salt) -> Setup:
    return Setup(tmp_path / "work")


@pytest.fixture
def packed(setup, tmp_path) -> tuple[Setup, Path, Path, Path]:
    """The setup, the recording, the bundle and the bundle's copy at another place."""
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    moved = tmp_path / "elsewhere" / "copy"
    shutil.copytree(bundle, moved)
    return setup, recording, bundle, moved


def entries(bundle: Path, role: str) -> list[dict]:
    index = json.loads((bundle / evidence.INDEX_FILE).read_text())
    return [entry for entry in index["files"] if entry["role"] == role]


def edited_session(recording: Path, destination: Path, **changes) -> Path:
    """The recording with its ``run_started`` changed (``None`` removes a key), as a recording
    of its own at ``destination``."""
    lines = recording.read_text().splitlines()
    started = json.loads(lines[0])
    for key, value in changes.items():
        if value is None:
            started.pop(key, None)
        else:
            started[key] = value
    started["run_id"] = secrets.token_hex(4)
    destination.mkdir(parents=True)
    path = destination / "events.jsonl"
    path.write_text("\n".join([json.dumps(started), *lines[1:]]) + "\n")
    return path


# -- the script role ---------------------------------------------------------------------------


def test_a_script_file_is_placed_with_the_digest_of_the_original_and_of_the_copy(packed):
    setup, recording, bundle, _ = packed
    (script,) = entries(bundle, "script")
    original = setup.script.read_bytes()
    run = sha256(recording.read_bytes()).hexdigest()

    assert script["path"] == f"scripts/{sha256(original).hexdigest()}.json"
    assert script["source_digest"] == sha256(original).hexdigest()
    assert script["sha256"] == sha256((bundle / script["path"]).read_bytes()).hexdigest()
    assert script["runs"] == [run]
    started = events_of(recording)[0]
    assert started["script_digest"] == script["source_digest"]
    assert evidence.verify(bundle).intact


def test_a_script_without_a_customer_value_is_placed_as_its_document_in_json(packed):
    """Comments are dropped and the keys keep the order of the document."""
    setup, _, bundle, _ = packed
    (script,) = entries(bundle, "script")
    placed = (bundle / script["path"]).read_text()
    assert json.loads(placed) == parse_yaml(setup.script.read_text(), source="script.yaml")
    assert list(json.loads(placed)) == ["version", "name", "steps"]
    assert "A probe" not in placed
    assert script["pseudonyms"] == "as_recordings"


def call_script(arguments: str) -> str:
    """A script that calls the discovery server's tool, with ``arguments`` (YAML lines,
    already indented by eight)."""
    return (
        "version: 1\nname: probe\nsteps:\n  - initialize\n  - list: tools/list\n"
        f"  - call:\n      tool: tool_0\n      arguments:\n{arguments}"
    )


CALLS = {"actions": {"list": True, "call": True}}


def test_the_values_of_the_customer_are_replaced_in_the_script_and_nowhere_else(tmp_path, salt):
    mail, account, name = address(), iban(), "Kunde-" + secrets.token_hex(5)
    text = call_script(f"        mail: {mail}\n        account: {account}\n        who: {name}\n")
    setup = Setup(tmp_path / "work", script=text, values=(name,), **CALLS)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    placed = (bundle / script["path"]).read_text()
    assert script["sha256"] != script["source_digest"]
    assert script["source_digest"] == sha256(text.encode()).hexdigest()
    for value in (mail, account, name):
        assert value not in placed
    # The pseudonyms a recording carries: the engagement's masker, under the engagement's salt.
    masker = cli.run_masker([], (), held=engagement.load(setup.held))
    assert json.loads(placed) == masker.mask_json(parse_yaml(text, source="script.yaml"))[0]
    for path in bundle.rglob("*"):
        if path.is_file() and path.name != "store.sqlite":
            data = path.read_bytes()
            for value in (mail, account, name):
                assert value.encode() not in data, path


def test_the_engagements_literal_patterns_are_blanked_in_the_script(tmp_path, salt):
    pattern = "PATTERN-" + secrets.token_hex(5)
    text = call_script(f"        note: before {pattern} after\n")
    setup = Setup(
        tmp_path / "work",
        script=text,
        redaction={"mask_keys": [], "mask_patterns": [pattern]},
        **CALLS,
    )
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    placed = (bundle / script["path"]).read_text()
    assert pattern not in placed and PLACEHOLDER in placed


def unquoted(tmp_path: Path) -> tuple[Setup, dict[str, str]]:
    """A script with a secret key, a key of ``mask_keys``, a known value and an address as
    plain YAML values, none of them quoted. The values are made up here."""
    values = {
        "password": "hunter2-" + secrets.token_hex(4),
        "customer_id": "4711",
        "who": "Kunde-" + secrets.token_hex(5),
        "mail": address(),
    }
    text = call_script("".join(f"        {key}: {value}\n" for key, value in values.items()))
    setup = Setup(
        tmp_path / "work",
        script=text,
        values=(values["who"],),
        redaction={"mask_keys": ["customer_id"], "mask_patterns": []},
        **CALLS,
    )
    return setup, values


def test_unquoted_values_of_a_script_are_not_in_the_bundle_nor_after_redact(tmp_path, salt):
    setup, values = unquoted(tmp_path)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"
    assert setup.pack(bundle, setup.script) == 0
    code = cli.main(
        ["evidence", "redact", "-q", str(bundle), "--engagement", str(setup.held),
         "--store", str(setup.store), "--out", str(handover)]
    )  # fmt: skip
    assert code == 0

    for root in (bundle, handover):
        (script,) = entries(root, "script")
        document = json.loads((root / script["path"]).read_text())
        shown = document["steps"][-1]["call"]["arguments"]
        assert shown["password"] == PLACEHOLDER and shown["customer_id"] == PLACEHOLDER
        assert PSEUDONYM.fullmatch(shown["who"]) and PSEUDONYM.fullmatch(shown["mail"])
        # 4711 is four digits and would occur by chance in a digest: only the script is read
        # for it.
        assert "4711" not in json.dumps(document)
        for path in root.rglob("*"):
            if path.is_file() and path.name != "store.sqlite":
                for key in ("password", "who", "mail"):
                    assert values[key].encode() not in path.read_bytes(), (key, path)


def test_the_placed_script_loads_with_the_loader_of_the_tool(packed):
    _, _, bundle, _ = packed
    (script,) = entries(bundle, "script")
    loaded = script_file.load(bundle / script["path"])
    assert loaded.name == "probe" and len(loaded.steps) == 1


def test_the_masked_script_with_a_placeholder_loads_too(tmp_path, salt):
    setup, _ = unquoted(tmp_path)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    (script,) = entries(bundle, "script")
    loaded = script_file.load(bundle / script["path"])
    assert loaded.steps[-1].arguments["password"] == PLACEHOLDER


def test_a_script_that_is_only_json_goes_the_same_way(tmp_path, salt):
    mail, name = address(), "Kunde-" + secrets.token_hex(5)
    document = {
        "version": 1,
        "name": "probe",
        "steps": [
            "initialize",
            {"list": "tools/list"},
            {"call": {"tool": "tool_0", "arguments": {"password": "x" + name, "who": name,
                                                            "mail": mail}}},
        ],
    }  # fmt: skip
    setup = Setup(tmp_path / "work", values=(name,), **CALLS)
    setup.script = setup.root / "script.json"
    setup.script.write_text(json.dumps(document))
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    assert script["path"].endswith(".json")
    placed = (bundle / script["path"]).read_text()
    for value in (mail, name):
        assert value not in placed
    shown = json.loads(placed)["steps"][-1]["call"]["arguments"]
    assert shown["password"] == PLACEHOLDER
    assert script_file.load(bundle / script["path"]).name == "probe"


def test_a_script_file_that_is_not_a_script_refuses_the_pack_and_names_the_field(
    setup, tmp_path, capsys
):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    broken = setup.root / "broken.yaml"
    broken.write_text("version: 1\nname: probe\nsteps:\n  - list: tools/list\n")
    session = edited_session(
        recording, tmp_path / "session", script_digest=sha256(broken.read_bytes()).hexdigest()
    )
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, broken, sessions=(session,)) == 2

    assert "steps[0]" in capsys.readouterr().err
    assert not bundle.exists(), "nothing is written"


def test_a_number_that_a_pattern_meets_is_blanked_in_the_placed_script(tmp_path, salt):
    """``ref: 123456789`` is a number for the loader, not a string; the pattern meets its JSON
    text. A number no pattern meets, and a bool, stay as they are. The run's recording holds the
    number as it was sent (``mask_patterns`` act in ``evidence redact`` only), so the placed
    script is what is looked at."""
    number = "123456789"
    text = call_script(f"        ref: {number}\n        other: 42\n        flag: true\n")
    setup = Setup(
        tmp_path / "work",
        script=text,
        redaction={"mask_keys": [], "mask_patterns": [number]},
        **CALLS,
    )
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    placed = (bundle / script["path"]).read_text()
    shown = json.loads(placed)["steps"][-1]["call"]["arguments"]
    assert shown == {"ref": PLACEHOLDER, "other": 42, "flag": True}
    assert script["replayable"] is True
    assert number not in placed


# What the loader's error says of a script that is not one, and the place it names. The value in
# each text is the customer's: it must not reach stderr, the place must. A duplicate key is found
# while the file is parsed, where the loader has no place: it is "the file".
NOT_A_SCRIPT = [
    ("version: 1\nname: {v} AG\nsteps:\n  - initialize\n", "name"),
    ("version: 1\nname: probe\nsteps:\n  - initialize\n  - list: {v}/list\n", "steps[1].list"),
    ("version: 1\nname: probe\nsteps:\n  - initialize\n  - list: tools/list\n    {v}: 1\n",
     "steps[1]"),
    (call_script("        {v}: 1\n        {v}: 2\n"), "the file"),
]  # fmt: skip


@pytest.mark.parametrize(("text", "place"), NOT_A_SCRIPT)
def test_a_refused_script_names_the_place_and_never_the_value(setup, tmp_path, capsys, text, place):
    value = "Zorn" + secrets.token_hex(4)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    broken = setup.root / "broken.yaml"
    broken.write_text(text.replace("{v}", value))
    session = edited_session(
        recording, tmp_path / "session", script_digest=sha256(broken.read_bytes()).hexdigest()
    )
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle, broken, sessions=(session,)) == 2

    error = capsys.readouterr().err
    assert value not in error
    assert f"not readable as a script: {place}" in error
    assert not bundle.exists(), "nothing is written"


def test_a_place_below_arguments_is_cut_there(setup, tmp_path, capsys):
    """A key of ``arguments`` may be the customer's: the place stops at ``arguments``."""
    value = "Zorn" + secrets.token_hex(4)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    broken = setup.root / "broken.yaml"
    broken.write_text(call_script(f"        {value}: stray {{ brace\n"))
    session = edited_session(
        recording, tmp_path / "session", script_digest=sha256(broken.read_bytes()).hexdigest()
    )
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", broken, sessions=(session,)) == 2

    error = capsys.readouterr().err
    assert value not in error and "steps[2].call.arguments" in error


def session_of_script(setup: Setup, tmp_path: Path, text: str) -> tuple[Path, Path]:
    """The script ``text`` as a file, and a session made of a plain run that names it as its
    script. The real run drove another script: the recording of a run that drove ``text`` would
    hold its values itself (the recorder keeps a script's name and its call arguments' numbers
    as they are), and the bundle's script is what is looked at here."""
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    custom = setup.root / "custom.yaml"
    custom.write_text(text)
    digest = sha256(custom.read_bytes()).hexdigest()
    return custom, edited_session(recording, tmp_path / "session", script_digest=digest)


def test_a_placed_script_that_does_not_load_once_masked_is_not_replayable(tmp_path, salt, capsys):
    """A known value in the placed script's name: the masked name is no name. The bundle is made,
    the entry says where, stderr says it with the script's digest, and ``replay`` refuses. The
    value is in no file of the bundle, as the session ran a plain script (see
    ``session_of_script``): the name a recording holds is not masked by the recorder."""
    setup = Setup(tmp_path / "work", values=("Zorn",))
    custom, session = session_of_script(setup, tmp_path, SCRIPT.replace("probe", "Zorn-probe"))
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle, custom, sessions=(session,)) == 0

    (script,) = entries(bundle, "script")
    assert script["replayable"] is False and script["not_replayable"] == "name"
    assert "Zorn" not in (bundle / script["path"]).read_text()
    for path in bundle.rglob("*"):
        if path.is_file():
            assert b"Zorn" not in path.read_bytes(), path
    error = capsys.readouterr().err
    (line,) = [line for line in error.splitlines() if "not replayable" in line]
    assert script["source_digest"] in line and "(name)" in line and "Zorn" not in line
    assert evidence.verify(bundle).intact

    digest = sha256(session.read_bytes()).hexdigest()
    assert setup.replay(bundle, digest, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "(name)" in error and "original" in error and "Zorn" not in error
    assert not (tmp_path / "again").exists()


def test_a_pattern_in_a_list_value_makes_the_placed_script_not_replayable_too(
    tmp_path, salt, capsys
):
    """The session ran a plain script (see ``session_of_script``); the placed one is looked at."""
    setup = Setup(tmp_path / "work", redaction={"mask_keys": [], "mask_patterns": ["prompts/"]})
    text = SCRIPT + "  - list: prompts/list\n"
    custom, session = session_of_script(setup, tmp_path, text)
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle, custom, sessions=(session,)) == 0

    (script,) = entries(bundle, "script")
    assert script["replayable"] is False and script["not_replayable"] == "steps[2].list"
    assert "prompts/" not in (bundle / script["path"]).read_text()
    error = capsys.readouterr().err
    assert any("not replayable" in line and "steps[2].list" in line for line in error.splitlines())

    assert setup.replay(bundle, sha256(session.read_bytes()).hexdigest(), tmp_path / "again") == 2

    assert "steps[2].list" in capsys.readouterr().err
    assert not (tmp_path / "again").exists()


def test_a_script_run_with_its_own_pseudonyms_is_placed_as_own_and_said_so(setup, tmp_path, capsys):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    session = edited_session(recording, tmp_path / "session", pseudonyms="per_run")
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    (script,) = entries(bundle, "script")
    assert script["pseudonyms"] == "own"
    (line,) = [x for x in capsys.readouterr().err.splitlines() if "pseudonyms are its own" in x]
    assert script["source_digest"] in line
    assert evidence.verify(bundle).intact


def test_a_known_value_has_the_pseudonym_of_the_recording_in_the_script(tmp_path, salt):
    name = "Kunde-" + secrets.token_hex(5)
    setup = Setup(tmp_path / "work", script=call_script(f"        who: {name}\n"), values=(name,),
                  **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    assert script["pseudonyms"] == "as_recordings"
    in_script = {
        found.group() for found in PSEUDONYM.finditer((bundle / script["path"]).read_text())
    }
    in_recording = {found.group() for found in PSEUDONYM.finditer(recording.read_text())}
    assert len(in_script) == 1 and in_script <= in_recording


def test_a_script_that_matches_no_run_refuses_the_pack(setup, tmp_path, capsys):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    other = setup.root / "other.yaml"
    other.write_text(SCRIPT.replace("probe", "another"))
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script, other) == 2

    assert "is the script of no run" in capsys.readouterr().err
    assert not bundle.exists(), "nothing is written"


def test_a_run_whose_script_is_not_given_has_no_entry_and_is_said_so(setup, tmp_path, capsys):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle) == 0

    assert entries(bundle, "script") == []
    error = capsys.readouterr().err
    (line,) = [line for line in error.splitlines() if "was not given with --script" in line]
    assert events_of(recording)[0]["run_id"] in line
    assert evidence.verify(bundle).intact


def test_a_run_without_a_script_file_has_no_entry_and_no_line(setup, tmp_path, capsys):
    recording = setup.drive()
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle) == 0

    assert entries(bundle, "script") == []
    assert "script" not in capsys.readouterr().err


def test_the_original_engagement_file_is_never_in_the_bundle(tmp_path, salt):
    """Every string of the operator's file, from four characters on, is looked for in the raw
    bytes of every file of the bundle, ``store.sqlite`` too. What the tool passes on on purpose
    is listed with the reason; nothing else may stand in any file."""
    value = "Kunde-" + secrets.token_hex(5)
    setup = Setup(
        tmp_path / "work",
        values=(value,),
        end_customer={"name": "Zorn AG"},
        emergency={"name": "Hans", "reach": "Zi 42"},
        abort_criteria=["Stopp bei Wunsch"],
    )
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    original = json.loads(setup.held.read_text())
    passed_on = {
        original["id"]: "the engagement's id names the bundle and every recording's authorization",
        "127.0.0.1": "the target's host, which every recording of a run against it names",
        original["scenarios"][0]["path"]: "the scenario, which the bundle holds as a file",
        original["scenarios"][0]["sha256"]: "the scenario's digest, the name of its file",
        original["window"]["from"]: "the window is in the sanitized copy, for the gate to read",
        original["window"]["until"]: "the window is in the sanitized copy, for the gate to read",
        original["retention"]["delete_after"]: "the retention date is in the sanitized copy",
        original["end_customer"]["name"]: "the end customer is named in the sanitized copy",
        original["abort_criteria"][0]: "the criteria are in the sanitized copy, for the reviewer",
    }
    strings: list[str] = []
    pending = [original]
    while pending:
        node = pending.pop()
        if isinstance(node, str):
            strings.append(node)
        elif isinstance(node, dict):
            # Values only: a key such as ``known_values`` is the format's.
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    looked_for = [text for text in strings if len(text) >= 4 and text not in passed_on]
    assert value in looked_for and "Zi 42" in looked_for and "Hans" in looked_for
    files = [path for path in bundle.rglob("*") if path.is_file()]
    assert any(path.name == "store.sqlite" for path in files)
    for path in files:
        data = path.read_bytes()
        for text in looked_for:
            assert text.encode() not in data, (text, path)
        assert setup.held.read_bytes() not in data


# -- the images of the index -------------------------------------------------------------------


def test_the_images_of_a_run_without_a_container_are_null(packed):
    _, _, bundle, _ = packed
    (recording,) = entries(bundle, "recording")
    assert recording["images"] == {"target": None, "sandbox": None}


def test_the_images_are_the_digests_the_run_recorded(setup, tmp_path):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    target, sandbox = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    environment = {"isolation": "runc", "target_image": target, "sandbox_image": sandbox}
    started = events_of(recording)[0]
    session = edited_session(
        recording,
        tmp_path / "session",
        reproduction={**started["reproduction"], "environment": environment},
    )
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    images = {entry["images"]["target"]: entry["images"]["sandbox"] for entry in
              entries(bundle, "recording")}  # fmt: skip
    assert images == {None: None, target: sandbox}


#: An image id as the index may hold it; anything else in ``images`` would be a name or a tag.
IMAGE_ID = re.compile(r"(?:sha256:)?[0-9a-f]{64}")


def session_with_images(setup: Setup, tmp_path: Path, target: str, sandbox: str) -> Path:
    """A filed run, and a session of it whose environment names ``target`` and ``sandbox``."""
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    started = events_of(recording)[0]
    environment = {"isolation": "runc", "target_image": target, "sandbox_image": sandbox}
    return edited_session(
        recording,
        tmp_path / "session",
        isolation="runc",
        reproduction={**started["reproduction"], "environment": environment},
    )


# This tool records an image in run_started by its id only; a session made elsewhere or edited
# can name it there by whatever it likes, and such a name, a customer's registry and repository
# among them, must not become the index's name of the image.
@pytest.mark.parametrize(
    "tag",
    [
        "registry.customer.example/billing/app:2.3",
        "billing-app:latest",
        "billing-app@sha256:" + "c" * 64,
        "sha256:" + "C" * 64,
    ],
)
@pytest.mark.parametrize("role", ["target_image", "sandbox_image"])
def test_a_recording_naming_an_image_other_than_by_its_id_refuses_the_pack(
    setup, tmp_path, capsys, tag, role
):
    images = {"target_image": "sha256:" + "a" * 64, "sandbox_image": "sha256:" + "b" * 64}
    images[role] = tag
    session = session_with_images(setup, tmp_path, images["target_image"], images["sandbox_image"])
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle, setup.script, sessions=(session,)) == 2

    err = capsys.readouterr().err
    assert f"reproduction.environment.{role} does not name the image by its id" in err
    assert "(sha256:<64 hex> or the 64 hex digits alone)" in err
    assert tag not in err
    assert not bundle.exists()


def test_an_index_naming_an_image_by_a_tag_is_refused(packed, tmp_path):
    _, _, bundle, _ = packed
    copy = tmp_path / "tagged"
    shutil.copytree(bundle, copy)
    index = json.loads((copy / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        if entry["role"] == "recording":
            entry["images"] = {"target": "billing-app:latest", "sandbox": None}
    (copy / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    with pytest.raises(evidence.EvidenceError, match="images.target") as refused:
        evidence.verify(copy)
    assert "sha256:<64 hex> or the 64 hex digits alone" in str(refused.value)


def test_a_redacted_bundle_names_the_images_by_their_ids_and_carries_none(setup, tmp_path):
    target, sandbox = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    session = session_with_images(setup, tmp_path, target, sandbox)
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0
    code = cli.main(
        ["evidence", "redact", "-q", str(bundle), "--engagement", str(setup.held),
         "--store", str(setup.store), "--out", str(handover)]
    )  # fmt: skip
    assert code == 0

    for root in (bundle, handover):
        index = evidence.read_index(root / evidence.INDEX_FILE)
        recordings = [entry for entry in index.files if entry.role == "recording"]
        assert {(entry.details["images"]["target"], entry.details["images"]["sandbox"])
                for entry in recordings} == {(None, None), (target, sandbox)}  # fmt: skip
        for entry in recordings:
            for image in entry.details["images"].values():
                assert image is None or IMAGE_ID.fullmatch(image)
        # No role holds an image: every file is one the index lists under a role of its own, and
        # nothing else is in the bundle but the index (and, for a packed bundle, the store).
        assert {entry.role for entry in index.files} <= set(evidence.ROLES)
        listed = {entry.path for entry in index.files} | {evidence.INDEX_FILE}
        found = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
        assert found <= listed | {"CUSTOMER-README.md"}, found - listed


def test_a_runc_recording_keeps_the_image_reference_and_the_index_names_only_the_id(
    setup, tmp_path
):
    """A run in a container records, in its ``sandbox_step`` ``images``, the reference as the
    operator gave it beside the id (``Sandbox._resolve_images``). The index names the image by
    its id only; the recording keeps the reference, in the bundle and in the handover. That is a
    reference: no file of either bundle is an image."""
    target, sandbox = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    tag, sandbox_tag = "registry.customer.example/billing/app:2.3", "mcp-kymograph-sandbox:1"
    session = session_with_images(setup, tmp_path, target, sandbox)
    started, *rest = [json.loads(line) for line in session.read_text().splitlines()]
    detail = {
        "isolation": "runc",
        "docker": "27.3.1",
        "images": {
            "target": {"reference": tag, "id": target},
            "sandbox": {"reference": sandbox_tag, "id": sandbox},
        },
    }
    step = {"v": started["v"], "run_id": rest[0]["run_id"], "seq": started["seq"] + 1,
            "t_ns": started["t_ns"] + 1, "type": "sandbox_step", "step": "images", "ok": True,
            "seconds": 0.02, "detail": detail}  # fmt: skip
    for event in rest:
        event["seq"] += 1
    session.write_text("".join(json.dumps(event) + "\n" for event in [started, step, *rest]))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0
    assert redacted(setup, bundle, handover) == 0

    run = sha256(session.read_bytes()).hexdigest()
    for root in (bundle, handover):
        index = json.loads((root / evidence.INDEX_FILE).read_text())
        (entry,) = [item for item in index["files"] if item.get("run") == run]
        assert entry["images"] == {"target": target, "sandbox": sandbox}
        assert tag not in json.dumps(index) and sandbox_tag not in json.dumps(index)
        kept = [json.loads(line) for line in (root / entry["path"]).read_text().splitlines()]
        (images,) = [event for event in kept if event["type"] == "sandbox_step"]
        assert images["detail"]["images"]["target"] == {"reference": tag, "id": target}
        assert images["detail"]["images"]["sandbox"] == {"reference": sandbox_tag, "id": sandbox}
        assert evidence.verify(root).intact


# -- verify ------------------------------------------------------------------------------------


def test_one_flipped_byte_in_the_script_is_changed(packed, tmp_path):
    _, _, bundle, _ = packed
    copy = tmp_path / "flipped"
    shutil.copytree(bundle, copy)
    (script,) = entries(copy, "script")
    data = bytearray((copy / script["path"]).read_bytes())
    data[len(data) // 2] ^= 0x01
    (copy / script["path"]).write_bytes(bytes(data))

    checked = evidence.verify(copy)

    assert not checked.intact
    assert {item.path: item.state for item in checked.files}[script["path"]] == evidence.CHANGED


# The index as the tool wrote it before scripts and images were packed, held here as literals:
# the keys of the index, the roles, and the keys of an entry (``path``, ``sha256``, ``size`` and
# ``role``, and those a role adds).
OLD_INDEX_KEYS = {
    "index_version", "engagement", "created_utc", "derived_from", "triage", "files", "note",
}  # fmt: skip
OLD_ROLES = {
    "engagement", "manifest", "scenario", "recording", "store", "refusals", "report", "tool",
    "redactions", "reference",
}  # fmt: skip
OLD_ENTRY_KEYS = {"path", "sha256", "size", "role"}
OLD_ROLE_KEYS = {
    "engagement": {"source_digest", "removed", "digest_note"},
    "recording": {
        "run", "state", "entry", "scenario", "mode", "filed", "isolation", "egress_observed",
    },
}  # fmt: skip
#: What this commit adds to an entry.
NEW_ROLE_KEYS = {
    "recording": {"images"},
    "script": {"source_digest", "runs", "pseudonyms", "replayable"},
}


def test_a_bundle_packed_before_the_script_role_and_the_images_is_intact(packed, tmp_path):
    """Today's bundle differs from one packed before scripts and images by the images, the role
    ``script`` and its fields and by nothing else; with those removed it is intact."""
    _, _, bundle, _ = packed
    old = tmp_path / "old"
    shutil.copytree(bundle, old)
    index = json.loads((old / evidence.INDEX_FILE).read_text())
    assert set(index) == OLD_INDEX_KEYS
    assert set(evidence.ROLES) == OLD_ROLES | {"script"}
    for entry in index["files"]:
        role = entry["role"]
        assert role in OLD_ROLES | {"script"}
        expected = OLD_ENTRY_KEYS | OLD_ROLE_KEYS.get(role, set()) | NEW_ROLE_KEYS.get(role, set())
        assert set(entry) == expected, role
    assert {entry["role"] for entry in index["files"]} >= {"script", "recording"}

    for entry in index["files"]:
        entry.pop("images", None)
    for entry in [entry for entry in index["files"] if entry["role"] == "script"]:
        (old / entry["path"]).unlink()
        index["files"].remove(entry)
    (old / "scripts").rmdir()
    (old / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    checked = evidence.verify(old)

    assert checked.intact
    assert {entry["role"] for entry in index["files"]} <= OLD_ROLES
    assert evidence.read_index(old / evidence.INDEX_FILE).files


def test_a_script_entry_without_pseudonyms_is_still_read_and_intact(packed, tmp_path):
    """A bundle of the time when there was the role ``script`` and not yet its ``pseudonyms``."""
    _, _, bundle, _ = packed
    old = tmp_path / "old"
    shutil.copytree(bundle, old)
    index = json.loads((old / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        entry.pop("pseudonyms", None)
    (old / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    assert evidence.verify(old).intact


def test_a_script_entry_without_replayable_is_still_read_and_intact(packed, tmp_path, capsys):
    """A bundle of the time when there were the role and the pseudonyms, not yet ``replayable``;
    a script of it is repeated as before."""
    setup, recording, bundle, _ = packed
    old = tmp_path / "old"
    shutil.copytree(bundle, old)
    index = json.loads((old / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        entry.pop("replayable", None)
    (old / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    assert evidence.verify(old).intact
    assert setup.replay(old, events_of(recording)[0]["run_id"], tmp_path / "again") == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"replayable": "yes"},
        {"replayable": True, "not_replayable": "name"},
        {"replayable": False},
        {"replayable": False, "not_replayable": ""},
    ],
)
def test_an_entry_with_a_wrong_replayable_field_is_refused(packed, tmp_path, changes):
    _, _, bundle, _ = packed
    copy = tmp_path / "wrong"
    shutil.copytree(bundle, copy)
    index = json.loads((copy / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        if entry["role"] == "script":
            entry.update(changes)
    (copy / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    with pytest.raises(evidence.EvidenceError, match="replayable"):
        evidence.verify(copy)


def test_an_entry_with_a_wrong_pseudonyms_field_is_refused(packed, tmp_path):
    _, _, bundle, _ = packed
    copy = tmp_path / "wrong"
    shutil.copytree(bundle, copy)
    index = json.loads((copy / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        if entry["role"] == "script":
            entry["pseudonyms"] = "mine"
    (copy / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    with pytest.raises(evidence.EvidenceError, match="pseudonyms"):
        evidence.verify(copy)


def test_an_entry_with_a_wrong_images_field_is_refused(packed, tmp_path):
    _, _, bundle, _ = packed
    copy = tmp_path / "wrong"
    shutil.copytree(bundle, copy)
    index = json.loads((copy / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        if entry["role"] == "recording":
            entry["images"] = {"target": 1, "sandbox": None}
    (copy / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    with pytest.raises(evidence.EvidenceError, match="images.target"):
        evidence.verify(copy)


# -- replay ------------------------------------------------------------------------------------


def test_a_run_repeated_from_a_copied_bundle_is_the_same_but_for_its_environment(packed, tmp_path):
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    again = tmp_path / "again"

    assert setup.replay(moved, run, again) == 0

    (second,) = again.glob("*/events.jsonl")
    first_events, second_events = events_of(recording), events_of(second)
    assert second_events[0]["run_id"] != first_events[0]["run_id"]
    assert stable(second_events) == stable(first_events)
    # What was left out is only what ENVIRONMENT names: the rest of run_started is equal.
    (script,) = entries(moved, "script")
    assert second_events[0]["script_digest"] == script["sha256"]
    assert second_events[0]["mode"] == "driver"


def test_the_run_can_be_named_by_its_digest(packed, tmp_path):
    setup, recording, _, moved = packed
    again = tmp_path / "again"
    assert setup.replay(moved, sha256(recording.read_bytes()).hexdigest(), again) == 0
    assert len(list(again.glob("*/events.jsonl"))) == 1


def test_the_limits_and_the_script_variables_of_the_run_are_given_again(setup, tmp_path):
    script = setup.root / "vars.yaml"
    script.write_text(SCRIPT.replace("probe", "vars"))
    recording = setup.drive(
        "--script-var", "canary=value-" + secrets.token_hex(3), "--max-message-bytes", "500000",
        "--queue-size", "77", "--step-timeout", "12.5", "--mask-key", "customer_id",
        script=script,
    )  # fmt: skip
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, script) == 0
    again = tmp_path / "again"

    assert setup.replay(bundle, events_of(recording)[0]["run_id"], again) == 0

    (second,) = again.glob("*/events.jsonl")
    first_started, second_started = events_of(recording)[0], events_of(second)[0]
    assert first_started["limits"]["max_message_bytes"] == 500000
    for key in ("limits", "script_vars", "inputs"):
        if key == "inputs":
            assert second_started[key]["step_timeout"] == 12.5
            assert second_started[key]["mask_keys"] == ["customer_id"]
        else:
            assert second_started[key] == first_started[key]


def refused_variable(setup: Setup, tmp_path: Path, capsys, value: str, secret: str) -> str:
    """Drive with ``--script-var canary=value``, pack, repeat: the refusal's words, which must
    name the variable and hold neither the value nor ``secret``."""
    recording = setup.drive("--script-var", f"canary={value}", script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    capsys.readouterr()

    assert setup.replay(bundle, events_of(recording)[0]["run_id"], tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "script_vars.canary" in error and "original" in error
    assert value not in error and secret not in error
    assert not (tmp_path / "again").exists()
    return error


def test_a_script_variable_recorded_in_the_credential_form_is_refused(setup, tmp_path, capsys):
    secret = "cred-" + secrets.token_hex(6)
    refused_variable(setup, tmp_path, capsys, f"token={secret}", secret)


def test_a_script_variable_that_held_the_salt_is_refused(setup, tmp_path, capsys, salt):
    refused_variable(setup, tmp_path, capsys, f"x{salt}y", salt)


def test_a_script_variable_cut_to_the_length_of_a_name_may_be_cut_and_is_refused(setup, tmp_path):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    name = "n" * events.MAX_METHOD_LENGTH
    session = edited_session(recording, tmp_path / "session", script_vars={name: "value"})
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    with pytest.raises(evidence.EvidenceError, match=f"script_vars.{name}"):
        evidence.replay_plan(
            bundle, run=sha256(session.read_bytes()).hexdigest(), engagement_path=setup.held
        )


def test_a_script_variable_that_holds_a_withheld_path_is_refused(setup, tmp_path):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    withheld = {"canary": "<path withheld: sha256 " + "ab" * 32 + ", 9 characters>"}
    session = edited_session(recording, tmp_path / "session", script_vars=withheld)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    with pytest.raises(evidence.EvidenceError, match="script_vars.canary"):
        evidence.replay_plan(
            bundle, run=sha256(session.read_bytes()).hexdigest(), engagement_path=setup.held
        )


def test_a_script_variable_that_holds_a_pseudonym_goes_out_as_the_pseudonym(tmp_path, salt):
    name = "Kunde-" + secrets.token_hex(5)
    setup = Setup(tmp_path / "work", values=(name,))
    recording = setup.drive("--script-var", f"canary=ref-{name}", script=setup.script)
    setup.ingest(recording)
    (found,) = PSEUDONYM.finditer(events_of(recording)[0]["script_vars"]["canary"])
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    again = tmp_path / "again"

    assert setup.replay(bundle, events_of(recording)[0]["run_id"], again) == 0

    (second,) = again.glob("*/events.jsonl")
    assert events_of(second)[0]["script_vars"] == {"canary": f"ref-{found.group()}"}
    assert name not in second.read_text()


def test_the_engagement_file_is_the_reviewers_not_the_bundles(packed, tmp_path, capsys):
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    other = second_file(tmp_path / "other", name="another-2026-10")

    assert setup.replay(moved, run, tmp_path / "again", held=other) == 2

    error = capsys.readouterr().err
    assert "another-2026-10" in error and "acme-2026-10" in error
    assert not (tmp_path / "again").exists()


def test_a_replay_goes_through_the_gate(packed, tmp_path):
    """A file whose window has ended refuses the run as any drive is refused."""
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    data = json.loads(setup.held.read_text())
    data["window"] = {"from": "2020-01-01T00:00:00Z", "until": "2020-01-02T00:00:00Z"}
    late = setup.held.with_name("late.json")
    late.write_text(json.dumps(data))
    again = tmp_path / "again"

    assert setup.replay(moved, run, again, held=late) == 2
    assert not list(again.glob("*/events.jsonl"))


def test_a_bundle_that_is_not_intact_is_refused(packed, tmp_path, capsys):
    setup, recording, _, moved = packed
    (script,) = entries(moved, "script")
    (moved / script["path"]).write_bytes(b"version: 1\n")

    assert setup.replay(moved, events_of(recording)[0]["run_id"], tmp_path / "again") == 2

    assert "not intact" in capsys.readouterr().err
    assert not (tmp_path / "again").exists()


def test_a_run_the_bundle_does_not_hold_is_refused(packed, tmp_path, capsys):
    setup, _, _, moved = packed
    assert setup.replay(moved, "00000000", tmp_path / "again") == 2
    assert "names no recording" in capsys.readouterr().err


def test_a_run_without_a_script_file_is_refused(setup, tmp_path, capsys):
    recording = setup.drive()
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle) == 0

    assert setup.replay(bundle, events_of(recording)[0]["run_id"], tmp_path / "again") == 2

    assert "built-in script" in capsys.readouterr().err


def test_a_run_whose_script_was_not_packed_is_refused(setup, tmp_path, capsys):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle) == 0

    assert setup.replay(bundle, events_of(recording)[0]["run_id"], tmp_path / "again") == 2

    assert "holds no script for it" in capsys.readouterr().err


def test_a_passive_run_is_refused(setup, tmp_path, capsys):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    session = edited_session(recording, tmp_path / "session", mode="proxy")
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0
    digest = sha256(session.read_bytes()).hexdigest()

    assert setup.replay(bundle, digest, tmp_path / "again") == 2

    assert "passive run" in capsys.readouterr().err


def run_of(setup: Setup, tmp_path: Path, **changes) -> tuple[Path, str]:
    """A bundle holding the real run and a session made of it with ``run_started`` changed; the
    bundle and the session's digest."""
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    session = edited_session(recording, tmp_path / "session", **changes)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0
    return bundle, sha256(session.read_bytes()).hexdigest()


ENDPOINT = {
    "scheme": "http",
    "host": "127.0.0.1",
    "port": 8080,
    "path": None,
    "path_sha256": "c" * 64,
    "path_length": 4,
    "query": {},
    "userinfo_dropped": False,
}


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"reproduction": None, "server_name": None}, "recorded its server only as a command"),
        (
            {"reproduction": None, "server_name": None, "endpoint": ENDPOINT},
            "endpoint.path was withheld",
        ),
        (
            {
                "reproduction": None,
                "server_name": None,
                "endpoint": {**ENDPOINT, "path": "/mcp", "query": {"a": "***REDACTED***"}},
            },
            "endpoint.query",
        ),
        (
            {"auth": {"identity": PLACEHOLDER, "role": None, "token_used": True, "source": "env",
                      "env_name": "SOME_TOKEN"}},
            "auth.identity was recorded masked",
        ),
        (
            {"authorization": {"declared_target": "http://h/<path withheld: sha256 ab, 3 chars>"}},
            "authorization.declared_target",
        ),
    ],
)  # fmt: skip
def test_what_the_run_recorded_only_withheld_or_masked_is_refused(
    setup, tmp_path, capsys, changes, field
):
    started = events_of(setup.drive(script=setup.script))[0]
    if "authorization" in changes:
        changes = {"authorization": {**started["authorization"], **changes["authorization"]}}
    recording = next(setup.runs.glob("*/events.jsonl"))
    setup.ingest(recording)
    session = edited_session(recording, tmp_path / "session", **changes)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0
    digest = sha256(session.read_bytes()).hexdigest()

    assert setup.replay(bundle, digest, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert field in error
    assert "original" in error, "it says to run the original"
    assert "path_sha256" not in error and "SOME_TOKEN" not in error, "never a value"


def test_the_endpoint_of_a_run_is_given_again_as_http(setup, tmp_path):
    bundle, digest = run_of(
        setup,
        tmp_path,
        reproduction=None,
        server_name=None,
        # The session is made of a corpus run: its server identity is the entry's, which an
        # endpoint run given no --server-revision or --server-content does not have.
        server_identity=None,
        endpoint={**ENDPOINT, "path": "/mcp", "path_sha256": None, "path_length": None},
    )
    plan = evidence.replay_plan(bundle, run=digest, engagement_path=setup.held)
    arguments = list(plan.arguments)
    assert arguments[arguments.index("--http") + 1] == "http://127.0.0.1:8080/mcp"
    assert "--manifest" not in arguments


def option(arguments: list[str], name: str) -> str | None:
    return arguments[arguments.index(name) + 1] if name in arguments else None


def moved_manifest(setup: Setup, tmp_path: Path) -> Path:
    """The recorded manifest's directory, with the server files, moved: the manifest's new
    place."""
    target = tmp_path / "reviewer" / "fixtures"
    target.parent.mkdir()
    shutil.move(str(setup.manifest.parent.parent), target)
    return target / "corpus" / "manifest.yaml"


def test_a_manifest_that_moved_is_given_with_manifest_and_the_run_goes_through(packed, tmp_path):
    """The bundle's copy of the manifest is evidence and is never loaded: the server files it
    lists are not in a bundle. The reviewer's own copy, of the recorded digest, is."""
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    new = moved_manifest(setup, tmp_path)
    again = tmp_path / "again"

    assert setup.replay(moved, run, again, "--manifest", str(new)) == 0

    (second,) = again.glob("*/events.jsonl")
    started = events_of(second)[0]
    assert (
        started["reproduction"]["manifest"]["digest"]
        == (events_of(recording)[0]["reproduction"]["manifest"]["digest"])
    )
    assert started["reproduction"]["manifest"]["source"] == str(new)


def test_a_manifest_path_over_the_limit_of_the_notice_is_not_in_the_refusal(tmp_path, salt, capsys):
    """The notice is cut at ``STORE_NOTICE_LIMIT``: the sentence names the field, the kind of
    failure and ``--manifest``, and no part of the recorded path."""
    setup = Setup(tmp_path / "work")
    deep = tmp_path / "deep"
    for index in range(8):
        deep /= f"nested-{index}-" + "d" * 80
    deep.parent.mkdir(parents=True)
    shutil.move(str(setup.manifest.parent.parent), deep)
    setup.manifest = deep / "corpus" / "manifest.yaml"
    assert len(str(setup.manifest)) > cli.STORE_NOTICE_LIMIT
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    run = events_of(recording)[0]["run_id"]
    shutil.move(str(deep), tmp_path / "gone")
    capsys.readouterr()

    assert setup.replay(bundle, run, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "reproduction.manifest" in error and "--manifest" in error
    assert "cannot be loaded from the recorded path" in error
    assert "nested-" not in error and "d" * 20 not in error
    assert not (tmp_path / "again").exists()


def test_a_manifest_that_moved_is_refused_without_manifest_and_says_which_option_helps(
    packed, tmp_path, capsys
):
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    moved_manifest(setup, tmp_path)
    capsys.readouterr()

    assert setup.replay(moved, run, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "reproduction.manifest" in error and "--manifest" in error
    assert not (tmp_path / "again").exists()


def test_a_manifest_of_another_digest_is_refused_with_and_without_manifest(
    packed, tmp_path, capsys
):
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    new = moved_manifest(setup, tmp_path)
    new.write_text(new.read_text() + "\n# another file\n")
    capsys.readouterr()

    assert setup.replay(moved, run, tmp_path / "again", "--manifest", str(new)) == 2
    given = capsys.readouterr().err
    # The recorded path holds nothing now: it is gone with the move.
    assert setup.replay(moved, run, tmp_path / "again") == 2
    recorded = capsys.readouterr().err

    assert "reproduction.manifest" in given and "digest differs" in given
    assert "reproduction.manifest" in recorded
    assert not (tmp_path / "again").exists()


def test_the_recorded_path_holding_another_manifest_is_refused(packed, tmp_path, capsys):
    setup, recording, _, moved = packed
    run = events_of(recording)[0]["run_id"]
    setup.manifest.write_text(setup.manifest.read_text() + "\n# changed since the run\n")
    capsys.readouterr()

    assert setup.replay(moved, run, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "reproduction.manifest" in error and "digest differs" in error
    assert "--manifest" in error
    assert not (tmp_path / "again").exists()


def test_a_run_in_a_container_gives_its_image_ids_again(setup, tmp_path):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    target, sandbox = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    started = events_of(recording)[0]
    environment = {"isolation": "runc", "target_image": target, "sandbox_image": sandbox}
    session = edited_session(
        recording,
        tmp_path / "session",
        isolation="runc",
        reproduction={**started["reproduction"], "environment": environment},
    )
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    plan = evidence.replay_plan(
        bundle, run=sha256(session.read_bytes()).hexdigest(), engagement_path=setup.held
    )

    arguments = list(plan.arguments)
    assert option(arguments, "--isolation") == "runc"
    assert option(arguments, "--target-image") == target
    assert option(arguments, "--sandbox-image") == sandbox


def test_a_run_without_images_gives_no_image_ids(packed):
    setup, recording, _, moved = packed
    plan = evidence.replay_plan(
        moved, run=events_of(recording)[0]["run_id"], engagement_path=setup.held
    )
    arguments = list(plan.arguments)
    assert "--target-image" not in arguments and "--sandbox-image" not in arguments


# -- what a bundle's recording says, changed after packing -----------------------------------


def rehashed(bundle: Path, path: str, data: bytes) -> None:
    """``path`` of the bundle replaced by ``data``, and its digest and size in the index with it:
    a replaced index, which verify cannot tell from the original without the index's digest."""
    (bundle / path).chmod(0o600)
    (bundle / path).write_bytes(data)
    index_path = bundle / evidence.INDEX_FILE
    index_path.chmod(0o600)
    index = json.loads(index_path.read_text())
    for entry in index["files"]:
        if entry["path"] == path:
            entry["sha256"] = sha256(data).hexdigest()
            entry["size"] = len(data)
    index_path.write_bytes(evidence.canonical_json(index))


def with_started(bundle: Path, **changes) -> str:
    """The bundle's one recording with ``run_started`` changed, re-hashed in the index; the run's
    digest as the index names it."""
    (recording,) = entries(bundle, "recording")
    lines = (bundle / recording["path"]).read_text().splitlines()
    started = {**json.loads(lines[0]), **changes}
    data = ("\n".join([json.dumps(started), *lines[1:]]) + "\n").encode()
    rehashed(bundle, recording["path"], data)
    return recording["run"]


def test_a_replay_of_a_run_whose_token_came_from_a_flag_is_refused(packed, capsys):
    """Pack refuses the script of such a run (below); a bundle whose recording says so only
    after packing is refused by replay as well."""
    setup, _, bundle, _ = packed
    auth = {"identity": None, "role": None, "token_used": True, "source": "env",
            "env_name": "SOME_TOKEN"}  # fmt: skip
    run = with_started(bundle, auth=auth)
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again") == 2

    error = capsys.readouterr().err
    assert "auth names no identity" in error and "SOME_TOKEN" not in error


def test_a_replay_gives_the_identity_of_the_run_again(packed):
    setup, _, bundle, _ = packed
    auth = {"identity": "reader", "role": "reader", "token_used": True, "source": "env",
            "env_name": "TOKEN_READER"}  # fmt: skip
    run = with_started(bundle, auth=auth)

    plan = evidence.replay_plan(bundle, run=run, engagement_path=setup.held)

    assert option(list(plan.arguments), "--identity") == "reader"


@pytest.mark.parametrize("image", ["billing-app:latest", "registry.customer.example/app:2"])
def test_a_replay_of_a_run_whose_image_is_no_id_is_refused(setup, tmp_path, capsys, image):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    started = events_of(recording)[0]
    environment = {"isolation": "runc", "target_image": image, "sandbox_image": "b" * 64}
    run = with_started(
        bundle,
        isolation="runc",
        reproduction={**started["reproduction"], "environment": environment},
    )
    capsys.readouterr()

    assert setup.replay(bundle, run, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "reproduction.environment.target_image does not name the image by its id" in error
    assert image not in error


@pytest.mark.parametrize("role", ["target_image", "sandbox_image"])
def test_a_replay_of_a_runc_run_whose_image_was_not_resolved_is_refused(
    setup, tmp_path, capsys, role
):
    """``null`` in a container run is an image Docker could not resolve; given again without it,
    drive would run today's default image."""
    images = {"target_image": "sha256:" + "a" * 64, "sandbox_image": "sha256:" + "b" * 64}
    images[role] = None
    session = session_with_images(setup, tmp_path, images["target_image"], images["sandbox_image"])
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0
    capsys.readouterr()

    assert setup.replay(bundle, sha256(session.read_bytes()).hexdigest(), tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert f"reproduction.environment.{role} is null" in error
    assert not (tmp_path / "again").exists()


def test_an_image_id_of_64_hex_digits_alone_is_packed_and_given_again(setup, tmp_path):
    target, sandbox = "a" * 64, "b" * 64
    session = session_with_images(setup, tmp_path, target, sandbox)
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    pairs = {(entry["images"]["target"], entry["images"]["sandbox"])
             for entry in entries(bundle, "recording")}  # fmt: skip
    assert pairs == {(None, None), (target, sandbox)}
    assert evidence.verify(bundle).intact
    plan = evidence.replay_plan(
        bundle, run=sha256(session.read_bytes()).hexdigest(), engagement_path=setup.held
    )
    assert option(list(plan.arguments), "--target-image") == target


def test_an_index_naming_an_image_by_a_tag_is_refused_by_redact_and_replay(packed, tmp_path):
    setup, recording, bundle, _ = packed
    index = json.loads((bundle / evidence.INDEX_FILE).read_text())
    for entry in index["files"]:
        if entry["role"] == "recording":
            entry["images"] = {"target": "billing-app:latest", "sandbox": None}
    (bundle / evidence.INDEX_FILE).chmod(0o600)
    (bundle / evidence.INDEX_FILE).write_bytes(evidence.canonical_json(index))

    code = cli.main(
        ["evidence", "redact", "-q", str(bundle), "--engagement", str(setup.held),
         "--store", str(setup.store), "--out", str(tmp_path / "handover")]
    )  # fmt: skip
    assert code == 2
    assert not (tmp_path / "handover").exists()
    with pytest.raises(evidence.EvidenceError, match="images.target"):
        evidence.replay_plan(
            bundle, run=events_of(recording)[0]["run_id"], engagement_path=setup.held
        )


# -- the server identity of an endpoint run -------------------------------------------------


ENDPOINT_RUN = {
    "reproduction": None,
    "server_name": None,
    "endpoint": {**ENDPOINT, "path": "/mcp", "path_sha256": None, "path_length": None},
}


def test_the_server_revision_of_an_endpoint_run_is_given_again(setup, tmp_path):
    revision = "github.com/acme/server@" + "1" * 40
    bundle, digest = run_of(
        setup,
        tmp_path,
        **ENDPOINT_RUN,
        server_identity={"kind": "revision", "version": revision, "files": 0},
    )

    plan = evidence.replay_plan(bundle, run=digest, engagement_path=setup.held)

    assert option(list(plan.arguments), "--server-revision") == revision


@pytest.mark.parametrize(
    ("server", "words"),
    [
        ({"kind": "content", "version": "sha256:" + "c" * 64, "files": 3},
         "server_identity is a digest over the server's files (--server-content)"),
        ({"kind": "revision", "version": PLACEHOLDER, "files": 0},
         "server_identity is not a pinned revision"),
    ],
)  # fmt: skip
def test_a_server_identity_that_cannot_be_given_again_is_refused(
    setup, tmp_path, capsys, server, words
):
    bundle, digest = run_of(setup, tmp_path, **ENDPOINT_RUN, server_identity=server)
    capsys.readouterr()

    assert setup.replay(bundle, digest, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert words in error and "original" in error
    assert "c" * 64 not in error


# -- recorded values that are not shown --------------------------------------------------------


def test_a_passive_run_is_refused_without_its_recorded_id_or_mode(setup, tmp_path, capsys):
    secret = "Zorn" + secrets.token_hex(4)
    bundle, digest = run_of(setup, tmp_path, mode=f"proxy-{secret}")
    capsys.readouterr()
    index = json.loads((bundle / evidence.INDEX_FILE).read_text())
    path = next(
        e["path"] for e in index["files"] if e["role"] == "recording" and e["run"] == digest
    )
    lines = (bundle / path).read_text().splitlines()
    started = {**json.loads(lines[0]), "run_id": f"id-{secret}"}
    rehashed(bundle, path, ("\n".join([json.dumps(started), *lines[1:]]) + "\n").encode())

    assert setup.replay(bundle, digest, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "passive run" in error and digest in error
    assert secret not in error


def test_a_malformed_script_digest_is_refused_without_its_value(setup, tmp_path, capsys):
    secret = "Zorn" + secrets.token_hex(4)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    session = edited_session(recording, tmp_path / "session", script_digest=secret)
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script, sessions=(session,)) == 2

    error = capsys.readouterr().err
    assert "script_digest" in error and secret not in error
    assert not (tmp_path / "bundle").exists()


# -- the credentials, the salt and the mask keys of the runs in a placed script ---------------

TOKEN_ENV, HEADER_ENV = "KYMOGRAPH_TEST_REPLAY_TOKEN", "KYMOGRAPH_TEST_REPLAY_HEADER"
IDENTITIES = [
    {"name": "reader", "role": "reader", "token_env": TOKEN_ENV,
     "headers": {"X-Api-Key": {"env": HEADER_ENV}}},
]  # fmt: skip


@pytest.fixture
def credentials(monkeypatch) -> dict[str, str]:
    """A token and a header value of the identity ``reader``, made up here, with no shape a
    masker knows (no ``Bearer``, ``sk-``, JWT): only a literal finds them."""
    values = {"token": "tq" + secrets.token_hex(12), "header": "hv" + secrets.token_hex(12)}
    monkeypatch.setenv(TOKEN_ENV, values["token"])
    monkeypatch.setenv(HEADER_ENV, values["header"])
    return values


def redacted(setup: Setup, bundle: Path, out: Path) -> int:
    return cli.main(
        ["evidence", "redact", "-q", str(bundle), "--engagement", str(setup.held),
         "--store", str(setup.store), "--out", str(out)]
    )  # fmt: skip


def nowhere(roots: tuple[Path, ...], *values: str) -> None:
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                for value in values:
                    assert value.encode() not in data, path


def test_the_credentials_and_the_salt_under_neutral_keys_are_replaced_in_the_script(
    tmp_path, salt, credentials
):
    """A token, a header value and the salt as the values of keys no masker knows: drive
    replaced them as literals, and so does pack; the handover keeps the script so."""
    text = call_script(
        f"        q: {credentials['token']}\n        k: {credentials['header']}\n"
        f"        s: {salt}\n"
    )
    setup = Setup(tmp_path / "work", script=text, identities=IDENTITIES, **CALLS)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script) == 0
    nowhere((bundle,), *credentials.values(), salt)
    assert redacted(setup, bundle, handover) == 0

    for root in (bundle, handover):
        (script,) = entries(root, "script")
        shown = json.loads((root / script["path"]).read_text())["steps"][-1]["call"]["arguments"]
        assert shown == {"q": PLACEHOLDER, "k": PLACEHOLDER, "s": PLACEHOLDER}
    nowhere((bundle, handover), *credentials.values(), salt)


def test_a_credential_of_the_engagement_that_cannot_be_read_refuses_a_pack_with_a_script(
    tmp_path, salt, credentials, monkeypatch, capsys
):
    setup = Setup(tmp_path / "work", identities=IDENTITIES)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    monkeypatch.delenv(HEADER_ENV)
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script) == 2

    error = capsys.readouterr().err
    assert "identities[0].headers[0]" in error and credentials["token"] not in error
    assert not (tmp_path / "bundle").exists()
    assert setup.pack(tmp_path / "without") == 0, "a bundle without a script needs none"


def test_a_run_with_a_token_given_by_a_flag_refuses_the_pack_of_its_script(setup, tmp_path, capsys):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    auth = {"identity": None, "role": None, "token_used": True, "source": "env",
            "env_name": "SOME_TOKEN"}  # fmt: skip
    session = edited_session(recording, tmp_path / "session", auth=auth)
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script, sessions=(session,)) == 2

    error = capsys.readouterr().err
    assert "auth: it sent a token given by a flag" in error and "SOME_TOKEN" not in error
    assert f"run {events_of(session)[0]['run_id']}:" in error
    assert not (tmp_path / "bundle").exists()
    assert setup.pack(tmp_path / "without", sessions=(session,)) == 0


def edited_script(bundle: Path, change) -> None:
    """The bundle's placed script with ``change`` made to its call's arguments, re-hashed in the
    index: a script edited after pack, which is what redact's check is for."""
    (script,) = entries(bundle, "script")
    document = json.loads((bundle / script["path"]).read_text())
    change(document["steps"][-1]["call"]["arguments"])
    rehashed(bundle, script["path"], (json.dumps(document, indent=2) + "\n").encode())


@pytest.mark.parametrize("what", ["token", "header", "salt", "known value"])
def test_redact_refuses_a_script_edited_after_pack_to_hold_a_value_it_knows(
    tmp_path, salt, credentials, capsys, what
):
    name = "Kunde-" + secrets.token_hex(5)
    value = {"token": credentials["token"], "header": credentials["header"], "salt": salt,
             "known value": name}[what]  # fmt: skip
    setup = Setup(tmp_path / "work", script=call_script("        q: 1\n"), values=(name,),
                  identities=IDENTITIES, **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    edited_script(bundle, lambda arguments: arguments.update(q=f"x-{value}-y"))
    capsys.readouterr()

    assert redacted(setup, bundle, tmp_path / "handover") == 2

    error = capsys.readouterr().err
    assert "holds a credential, the salt or a known value" in error and value not in error
    assert not (tmp_path / "handover").exists()


def test_redact_refuses_a_bundle_with_a_script_when_a_credential_cannot_be_read(
    tmp_path, salt, credentials, monkeypatch, capsys
):
    setup = Setup(tmp_path / "work", identities=IDENTITIES)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    monkeypatch.delenv(TOKEN_ENV)
    capsys.readouterr()

    assert redacted(setup, bundle, tmp_path / "handover") == 2

    assert "identities[0].token" in capsys.readouterr().err
    assert not (tmp_path / "handover").exists()


@pytest.mark.parametrize("command", ["pack", "redact"])
def test_a_salt_variable_that_is_not_set_refuses_a_script(
    tmp_path, salt, monkeypatch, capsys, command
):
    """The file names ``salt_env``; without its value the salt would be neither masked in a
    script nor looked for, whatever the runs' pseudonyms."""
    setup = Setup(tmp_path / "work")
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    if command == "redact":
        assert setup.pack(bundle, setup.script) == 0
    monkeypatch.delenv(SALT_ENV)
    capsys.readouterr()

    if command == "pack":
        assert setup.pack(bundle, setup.script) == 2
        assert not bundle.exists()
    else:
        assert redacted(setup, bundle, tmp_path / "handover") == 2
        assert not (tmp_path / "handover").exists()

    assert f"{SALT_ENV} that salt_env names is not set here" in capsys.readouterr().err


def test_redact_refuses_the_script_of_a_run_whose_token_came_from_a_flag(packed, tmp_path, capsys):
    setup, _, bundle, _ = packed
    auth = {"identity": None, "role": None, "token_used": True, "source": "file"}
    with_started(bundle, auth=auth)
    capsys.readouterr()

    assert redacted(setup, bundle, tmp_path / "handover") == 2

    assert "sent a token given by a flag" in capsys.readouterr().err
    assert not (tmp_path / "handover").exists()


def test_the_mask_keys_of_the_run_mask_the_script_in_the_bundle_and_after_redact(tmp_path, salt):
    """``--mask-key customer_id`` on drive, a key the engagement file does not name."""
    setup = Setup(tmp_path / "work", script=call_script("        customer_id: 4711\n"), **CALLS)
    recording = setup.drive("--mask-key", "customer_id", script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script) == 0
    (script,) = entries(bundle, "script")
    assert "4711" not in (bundle / script["path"]).read_text()
    assert redacted(setup, bundle, handover) == 0

    for root in (bundle, handover):
        (script,) = entries(root, "script")
        shown = json.loads((root / script["path"]).read_text())["steps"][-1]["call"]["arguments"]
        assert shown == {"customer_id": PLACEHOLDER}


def test_a_tel_uri_a_known_value_in_a_key_and_as_a_number_are_replaced(tmp_path, salt):
    name, number = "Kunde-" + secrets.token_hex(5), "47110815"
    pattern = "PATTERN-" + secrets.token_hex(5)
    text = call_script(
        "        phone: tel:+493012345678\n"
        f"        {name}: 1\n"
        f"        before-{pattern}: 2\n"
        f"        count: {number}\n"
    )
    setup = Setup(tmp_path / "work", script=text, values=(name, number),
                  redaction={"mask_keys": [], "mask_patterns": [pattern]}, **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    placed = (bundle / script["path"]).read_text()
    shown = json.loads(placed)["steps"][-1]["call"]["arguments"]
    phone, known_key, pattern_key, count = shown.items()
    assert re.fullmatch(r"\*\*\*TEL-[0-9a-f]{12}\*\*\*", phone[1])
    assert PSEUDONYM.fullmatch(known_key[0]) and pattern_key[0] == f"before-{PLACEHOLDER}"
    assert count[0] == "count" and PSEUDONYM.fullmatch(count[1])
    for value in ("+493012345678", name, number, pattern):
        assert value not in placed


def test_a_pack_with_a_script_is_refused_without_the_salt_of_per_engagement_runs(
    setup, tmp_path, monkeypatch, capsys
):
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    assert events_of(recording)[0]["pseudonyms"] == "per_engagement"
    monkeypatch.delenv(SALT_ENV)
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script) == 2

    error = capsys.readouterr().err
    assert SALT_ENV in error and "not set here" in error
    assert not (tmp_path / "bundle").exists()


def test_a_secret_header_name_as_a_key_of_the_script_loses_its_value(tmp_path, salt, credentials):
    setup = Setup(tmp_path / "work", script=call_script("        X-Tenant-Ref: plain-4321\n"),
                  identities=[{**IDENTITIES[0], "headers": {"X-Tenant-Ref": {"env": HEADER_ENV}}}],
                  **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    shown = json.loads((bundle / script["path"]).read_text())["steps"][-1]["call"]["arguments"]
    assert shown == {"X-Tenant-Ref": PLACEHOLDER}


def test_an_unreadable_token_of_the_engagement_refuses_a_pack_with_a_script(
    tmp_path, salt, credentials, monkeypatch, capsys
):
    setup = Setup(tmp_path / "work", identities=IDENTITIES)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    monkeypatch.delenv(TOKEN_ENV)
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script) == 2

    error = capsys.readouterr().err
    assert "identities[0].token" in error and credentials["header"] not in error
    assert not (tmp_path / "bundle").exists()


def test_a_number_that_holds_a_known_value_becomes_its_masked_text(tmp_path, salt):
    """``order: 47110815`` with the known value ``4711``: the number is masked as the quoted
    text would be, in the bundle, and redact finds nothing left in the script."""
    setup = Setup(tmp_path / "work", script=call_script("        order: 47110815\n"),
                  values=("4711",), **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script) == 0
    assert redacted(setup, bundle, handover) == 0

    for root in (bundle, handover):
        (script,) = entries(root, "script")
        placed = (root / script["path"]).read_text()
        order = json.loads(placed)["steps"][-1]["call"]["arguments"]["order"]
        assert PSEUDONYM.fullmatch(order[: -len("0815")]) and order.endswith("0815")
        assert "4711" not in placed


# -- drive's masking, as the recording holds it, is the floor of the placed script -------------


def test_a_token_rotated_since_the_run_stays_out_of_bundle_and_handover(
    tmp_path, salt, credentials, monkeypatch
):
    """The run sent the token of the day under a key no masker knows; drive blanked it as a
    literal. By the time of pack the variable holds the next token: the recording's blank is
    the floor of the script."""
    old = credentials["token"]
    setup = Setup(tmp_path / "work", script=call_script(f"        q: {old}\n"),
                  identities=IDENTITIES, **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    monkeypatch.setenv(TOKEN_ENV, "tq" + secrets.token_hex(12))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script) == 0
    nowhere((bundle,), old)
    assert redacted(setup, bundle, handover) == 0

    nowhere((bundle, handover), old)
    (script,) = entries(bundle, "script")
    shown = json.loads((bundle / script["path"]).read_text())["steps"][-1]["call"]["arguments"]
    assert shown == {"q": PLACEHOLDER}


def test_an_identity_removed_from_a_newer_engagement_file_stays_out_of_the_bundle(
    tmp_path, salt, credentials
):
    old = credentials["token"]
    setup = Setup(tmp_path / "work", script=call_script(f"        q: {old}\n"),
                  identities=IDENTITIES, **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    # A newer version of the file, without the identity, in the store's chain through a run.
    first = engagement.load(setup.held).digest
    second_file(setup.held.parent, actions={"list": True, "call": True}, supersedes=first)
    setup.ingest(setup.drive())
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script) == 0
    nowhere((bundle,), old)
    assert redacted(setup, bundle, handover) == 0
    nowhere((bundle, handover), old)


def test_a_call_step_no_run_sent_has_its_arguments_blanked_and_is_not_replayable(
    tmp_path, salt, capsys
):
    """The second call names a tool the server does not list: drive skips it, and nothing of
    its arguments was masked by a run."""
    secret = "Zorn" + secrets.token_hex(4)
    text = (
        call_script("        a: 1\n")
        + f"  - call:\n      tool: tool_unlisted\n      arguments:\n        b: {secret}\n"
    )
    setup = Setup(tmp_path / "work", script=text, **CALLS)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    assert [e["tool"] for e in events_of(recording) if e["type"] == "step_called"] == ["tool_0"]
    bundle = tmp_path / "bundle"
    capsys.readouterr()

    assert setup.pack(bundle, setup.script) == 0

    (script,) = entries(bundle, "script")
    placed = json.loads((bundle / script["path"]).read_text())
    assert placed["steps"][3]["call"]["arguments"] == {}
    assert placed["steps"][3]["call"]["tool"] == PLACEHOLDER
    assert placed["steps"][2]["call"]["tool"] == "tool_0"
    assert placed["steps"][2]["call"]["arguments"] == {"a": 1}
    assert script["replayable"] is False
    assert script["not_replayable"] == "steps[3].call: sent in no run"
    assert secret not in json.dumps(placed)
    assert "steps[3].call: sent in no run" in capsys.readouterr().err


def edited_calls(recording: Path, destination: Path, change) -> Path:
    """The recording as a session of its own, ``change`` made to each ``step_called``."""
    lines = recording.read_text().splitlines()
    changed = []
    for number, line in enumerate(lines):
        event = json.loads(line)
        if number == 0:
            event["run_id"] = secrets.token_hex(4)
        elif event["type"] == "step_called":
            change(event)
        changed.append(json.dumps(event))
    destination.mkdir(parents=True)
    path = destination / "events.jsonl"
    path.write_text("\n".join(changed) + "\n")
    return path


@pytest.mark.parametrize(
    ("change", "where"),
    [
        (lambda event: event["arguments"].update(a=2), "steps[2]"),
        (lambda event: event.update(tool="tool_other"), "steps[2]"),
        (lambda event: event["arguments"].update(extra=1), "steps[2]"),
    ],
)
def test_a_run_whose_recorded_calls_do_not_match_the_script_refuses_the_pack(
    tmp_path, salt, capsys, change, where
):
    setup = Setup(tmp_path / "work", script=call_script("        a: 1\n"), **CALLS)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    session = edited_calls(recording, tmp_path / "session", change)
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script, sessions=(session,)) == 2

    error = capsys.readouterr().err
    assert f"do not match {where} of --script" in error
    assert f"run {events_of(session)[0]['run_id']}:" in error
    assert not (tmp_path / "bundle").exists()


def test_a_run_that_recorded_more_calls_than_the_script_has_refuses_the_pack(
    tmp_path, salt, capsys
):
    setup = Setup(tmp_path / "work", script=call_script("        a: 1\n"), **CALLS)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    lines = recording.read_text().splitlines()
    called = next(line for line in lines if json.loads(line)["type"] == "step_called")
    started = {**json.loads(lines[0]), "run_id": secrets.token_hex(4)}
    session = tmp_path / "session" / "events.jsonl"
    session.parent.mkdir()
    session.write_text("\n".join([json.dumps(started), called, *lines[1:]]) + "\n")
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script, sessions=(session,)) == 2

    assert "recorded more calls (step_called)" in capsys.readouterr().err


# -- replay reads only the shapes a recording has ---------------------------------------------


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"script_vars": []}, "script_vars"),
        ({"authorization": "x"}, "authorization"),
        ({"reproduction": None, "endpoint": {**ENDPOINT, "path": 1}}, "endpoint.path"),
    ],
)
def test_a_run_started_of_another_shape_is_refused_by_replay(packed, capsys, changes, field):
    setup, _, bundle, _ = packed
    run = with_started(bundle, **changes)
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again") == 2

    assert f"{field} is not of the shape a recording has" in capsys.readouterr().err


def test_digests_that_are_not_digests_are_named_by_their_field(packed, capsys):
    setup, _, bundle, _ = packed
    secret = "Zorn" + secrets.token_hex(4)
    run = with_started(bundle, script_digest=secret)
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again") == 2

    error = capsys.readouterr().err
    assert "(script_digest)" in error and secret not in error


def test_a_scenario_digest_that_is_no_digest_is_named_by_its_field(setup, tmp_path, capsys):
    secret = "Zorn" + secrets.token_hex(4)
    started = events_of(setup.drive(script=setup.script))[0]
    recording = next(setup.runs.glob("*/events.jsonl"))
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, setup.script) == 0
    run = with_started(
        bundle,
        **ENDPOINT_RUN,
        server_identity=None,
        authorization={**started["authorization"], "scenario_digest": secret},
    )
    capsys.readouterr()

    assert setup.replay(bundle, run, tmp_path / "again") == 2

    error = capsys.readouterr().err
    assert "(authorization.scenario_digest)" in error and secret not in error


def test_an_endpoint_path_as_long_as_the_recorder_cuts_is_refused(packed, capsys):
    setup, _, bundle, _ = packed
    path = "/" + "a" * 2047
    run = with_started(
        bundle,
        **{**ENDPOINT_RUN, "endpoint": {**ENDPOINT_RUN["endpoint"], "path": path}},
        server_identity=None,
    )
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again") == 2

    error = capsys.readouterr().err
    assert "endpoint.path is as long as the recorder cuts a path" in error and path not in error


# -- the floor holds a position only where it is what the recording holds ---------------------


@pytest.mark.parametrize("beside", ["e-mail", "known value", "pattern"])
@pytest.mark.parametrize("place", ["value", "key"])
def test_a_rotated_token_beside_a_value_pack_masks_itself_is_blanked_whole(
    tmp_path, salt, credentials, monkeypatch, beside, place
):
    """Drive masked the token of the day and the value beside it; pack, knowing only the next
    token, masks the value beside it alone. What it placed is masked in part, and is not what the
    recording holds: the whole string is blanked."""
    old = credentials["token"]
    name, pattern = "Kunde-" + secrets.token_hex(5), "PATTERN-" + secrets.token_hex(5)
    other = {"e-mail": address(), "known value": name, "pattern": pattern}[beside]
    text = f'"{old} {other}"'
    arguments = f"        q: {text}\n" if place == "value" else f"        {text}: 1\n"
    setup = Setup(tmp_path / "work", script=call_script(arguments), values=(name,),
                  redaction={"mask_keys": [], "mask_patterns": [pattern]},
                  identities=IDENTITIES, **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    monkeypatch.setenv(TOKEN_ENV, "tq" + secrets.token_hex(12))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    assert setup.pack(bundle, setup.script) == 0
    nowhere((bundle,), old)
    # A pattern stands in the run's step_called as sent (drive does not apply mask_patterns),
    # outside the surfaces redact reviews, so redact refuses that bundle whole: no handover.
    if beside != "pattern":
        assert redacted(setup, bundle, handover) == 0
        nowhere((bundle, handover), old)

    (script,) = entries(bundle, "script")
    shown = json.loads((bundle / script["path"]).read_text())["steps"][-1]["call"]["arguments"]
    assert shown == ({"q": PLACEHOLDER} if place == "value" else {PLACEHOLDER: 1})


def test_a_tool_name_and_a_script_name_masked_in_part_by_pack_are_blanked_whole():
    """The tool's name and the script's name follow the same rule as a value."""
    pseudonym = "***EMAIL-0123456789ab***"
    record = {"tool": f"{PLACEHOLDER} {pseudonym}", "arguments": {}, "check": None}
    floored = evidence._floor_call({"tool": f"OLD {pseudonym}", "arguments": {}}, record)
    assert floored["tool"] == PLACEHOLDER
    same = evidence._floor_call({"tool": record["tool"], "arguments": {}}, record)
    assert same["tool"] == record["tool"], "what the recording holds is kept"
    assert evidence._floor({"a": f"OLD {pseudonym}"}, {"a": f"{PLACEHOLDER} {pseudonym}"}) == {
        "a": PLACEHOLDER
    }


def test_a_script_name_masked_in_part_by_pack_is_blanked_whole(tmp_path, salt):
    """Pack masks the known value in ``Zorn-OLD-probe``; the run recorded the name masked
    otherwise (``OLD`` was a literal then): the name is blanked whole."""
    setup = Setup(tmp_path / "work", values=("Zorn",))
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    custom = setup.root / "custom.yaml"
    custom.write_text(SCRIPT.replace("probe", "Zorn-OLD-probe"))
    pseudonym = "***KNOWN-0123456789ab***"
    session = edited_session(
        recording,
        tmp_path / "session",
        script=f"{pseudonym}-{PLACEHOLDER}-probe",
        script_digest=sha256(custom.read_bytes()).hexdigest(),
    )
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, custom, sessions=(session,)) == 0

    (script,) = entries(bundle, "script")
    placed = (bundle / script["path"]).read_text()
    assert json.loads(placed)["name"] == PLACEHOLDER and "OLD" not in placed
    assert script["replayable"] is False and script["not_replayable"] == "name"


def test_pack_refuses_a_script_in_which_its_own_check_still_finds_a_known_value(
    tmp_path, salt, monkeypatch, capsys
):
    """The last check of pack, with the number rule taken out of the masker and of pack, and the
    floor of the run's recording too (it holds the number masked, and would blank it), so that a
    known value is left in a number: the script is not placed and nothing is written."""
    setup = Setup(tmp_path / "work", script=call_script("        order: 47110815\n"),
                  values=("4711",), **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    monkeypatch.setattr(evidence, "_numbers_masked", lambda value, masker: value)
    monkeypatch.setattr(masking.Masker, "_mask_number", lambda self, value: (value, False))
    monkeypatch.setattr(evidence, "_floored_by_runs", lambda masked, users, path: (masked, None))
    capsys.readouterr()

    assert setup.pack(tmp_path / "bundle", setup.script) == 2

    error = capsys.readouterr().err
    assert "a credential, the salt or a known value is still in it once masked" in error
    assert "47110815" not in error
    assert not (tmp_path / "bundle").exists()


# -- replay hands drive nothing the run recorded masked -----------------------------------------


@pytest.mark.parametrize(
    "masked", [PLACEHOLDER, "***KNOWN-0123456789ab***", "x-***IBAN-0123456789ab***"]
)
def test_a_mask_key_recorded_masked_is_refused_by_replay(packed, capsys, masked):
    setup, recording, bundle, _ = packed
    inputs = {**events_of(recording)[0]["inputs"], "mask_keys": ["customer_id", masked]}
    run = with_started(bundle, inputs=inputs)
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again") == 2

    error = capsys.readouterr().err
    assert "inputs.mask_keys[1] was recorded masked" in error and masked not in error


@pytest.mark.parametrize(
    "identity", ["***KNOWN-0123456789ab***", "reader-***EMAIL-0123456789ab***"]
)
def test_a_pseudonymised_identity_is_refused_by_replay(packed, capsys, identity):
    setup, _, bundle, _ = packed
    auth = {"identity": identity, "role": "reader", "token_used": True, "source": "env",
            "env_name": "TOKEN_READER"}  # fmt: skip
    run = with_started(bundle, auth=auth)
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again") == 2

    error = capsys.readouterr().err
    assert "auth.identity was recorded masked" in error and identity not in error


@pytest.mark.parametrize(
    ("host", "path"),
    [("***KNOWN-0123456789ab***", "/mcp"), ("127.0.0.1", "/mcp/***EMAIL-0123456789ab***")],
)
def test_a_masked_endpoint_host_or_a_pseudonym_in_its_path_is_refused_by_replay(packed, host, path):
    setup, _, bundle, _ = packed
    endpoint = {**ENDPOINT_RUN["endpoint"], "host": host, "path": path}
    run = with_started(bundle, **{**ENDPOINT_RUN, "endpoint": endpoint}, server_identity=None)

    with pytest.raises(evidence.EvidenceError) as refused:
        evidence.replay_plan(bundle, run=run, engagement_path=setup.held)

    assert "endpoint.host or endpoint.path was masked" in str(refused.value)
    assert "0123456789ab" not in str(refused.value)


@pytest.mark.parametrize("masked", [PLACEHOLDER, "probe-***KNOWN-0123456789ab***"])
@pytest.mark.parametrize(
    "field", ["reproduction.scenario.name", "reproduction.corpus.entry", "scenario_name"]
)
def test_a_masked_scenario_or_entry_name_is_refused_by_replay(packed, field, masked):
    setup, recording, bundle, _ = packed
    started = events_of(recording)[0]
    reproduction = started["reproduction"]
    if field == "reproduction.scenario.name":
        changes = {"reproduction": {**reproduction, "scenario": {"name": masked}}}
    elif field == "reproduction.corpus.entry":
        corpus_entry = {**reproduction["corpus"], "entry": masked}
        changes = {"reproduction": {**reproduction, "corpus": corpus_entry}}
    else:
        authorization = {**started["authorization"], "scenario_digest": None}
        changes = {**ENDPOINT_RUN, "server_identity": None, "authorization": authorization,
                   "scenario_name": masked}  # fmt: skip
    run = with_started(bundle, **changes)

    with pytest.raises(evidence.EvidenceError) as refused:
        evidence.replay_plan(bundle, run=run, engagement_path=setup.held)

    assert f"{field} was recorded masked" in str(refused.value)
    assert masked not in str(refused.value)


def test_the_floor_keeps_a_check_recorded_masked_only_where_it_is_exactly_that():
    """``check`` follows the rule of a value: recorded with a masked form, it is kept only where
    the placed check is exactly what the recording holds, and blanked whole otherwise."""
    recorded = "result.***KNOWN-0123456789ab***.id"
    record = {"tool": "tool_0", "arguments": {}, "check": recorded}

    same = evidence._floor_call({"tool": "tool_0", "arguments": {}, "check": recorded}, record)
    rotated = evidence._floor_call(
        {"tool": "tool_0", "arguments": {}, "check": f"result.{PLACEHOLDER}.id"}, record
    )
    other = evidence._floor_call(
        {"tool": "tool_0", "arguments": {}, "check": "result.Zorn.id"}, record
    )

    assert same["check"] == recorded
    assert rotated["check"] == PLACEHOLDER
    assert other["check"] == PLACEHOLDER


def test_pseudonyms_of_a_run_made_with_another_salt_are_blanked_in_the_script(
    tmp_path, monkeypatch
):
    """Drive made the run's pseudonym of a known value with one salt; the script is packed under
    another (the run's own salt of a ``per_run`` run is never the one pack has). Pack's
    pseudonym of the same value is not exactly what the recording holds, so it is blanked."""
    name = "Kunde-" + secrets.token_hex(5)
    monkeypatch.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
    setup = Setup(tmp_path / "work", script=call_script(f"        who: {name}\n"),
                  values=(name,), **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    (called,) = [event for event in events_of(recording) if event["type"] == "step_called"]
    recorded = called["arguments"]["who"]
    assert PSEUDONYM.fullmatch(recorded)
    monkeypatch.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
    session = edited_session(recording, tmp_path / "session", pseudonyms="per_run")
    bundle = tmp_path / "bundle"

    assert setup.pack(bundle, setup.script, sessions=(session,)) == 0

    (script,) = entries(bundle, "script")
    text = (bundle / script["path"]).read_text()
    assert json.loads(text)["steps"][-1]["call"]["arguments"] == {"who": PLACEHOLDER}
    assert name not in text and recorded not in text
    assert not PSEUDONYM.search(text), "pack's own pseudonym of the value is blanked too"


# -- replay and the index's digest ---------------------------------------------------------------


def test_replay_refuses_an_index_that_is_not_the_one_index_digest_names(packed, capsys):
    """Without --index-digest a re-hashed index is consistent and replayed; with the digest of
    the index handed over, it is refused while the bundle is verified: before the run, the
    engagement file or the script is read, so a run that is not there and an engagement file
    that does not exist change nothing in the refusal."""
    setup, _, bundle, _ = packed
    handed_over = sha256((bundle / evidence.INDEX_FILE).read_bytes()).hexdigest()
    auth = {"identity": "reader", "role": "reader", "token_used": True, "source": "env",
            "env_name": "TOKEN_READER"}  # fmt: skip
    run = with_started(bundle, auth=auth)
    assert evidence.replay_plan(bundle, run=run, engagement_path=setup.held).arguments
    capsys.readouterr()

    assert setup.replay(bundle, run, setup.root / "again", "--index-digest", handed_over) == 2

    error = capsys.readouterr().err
    assert "not the one given with --index-digest" in error
    assert not (setup.root / "again").exists()

    with pytest.raises(evidence.EvidenceError, match="not the one given with --index-digest"):
        evidence.replay_plan(
            bundle,
            run="no-such-run",
            engagement_path=setup.root / "no-such-engagement.yaml",
            index_digest=handed_over,
        )


def test_replay_goes_through_with_the_index_digest_of_the_bundle(packed):
    setup, recording, bundle, _ = packed
    digest = sha256((bundle / evidence.INDEX_FILE).read_bytes()).hexdigest()
    run = events_of(recording)[0]["run_id"]
    again = setup.root / "again"

    assert setup.replay(bundle, run, again, "--index-digest", digest) == 0
    assert len(list(again.glob("*/events.jsonl"))) == 1
