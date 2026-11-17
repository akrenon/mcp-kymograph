"""What a recording holds once masked, and what a handover lets through: the ``check`` of a call
step is masked like its arguments, a JSON number that holds a known value is masked as its quoted
text, and ``evidence redact`` holds every recording to the check it holds a placed script to.

The customer's values are made up when the test runs, so that none stands in a file.
"""

from __future__ import annotations

import io
import json
import re
import secrets
import time
from pathlib import Path

import pytest

from mcp_kymograph import cli, evidence
from mcp_kymograph.events import Direction
from mcp_kymograph.masking import PLACEHOLDER, Masker
from mcp_kymograph.recorder import Recorder
from test_personal_data import HANDLE_SALT, PSEUDONYM, SALT_ENV
from test_replay_bundle import (
    CALLS,
    HEADER_ENV,
    IDENTITIES,
    TOKEN_ENV,
    Setup,
    call_script,
    entries,
    events_of,
    nowhere,
    redacted,
)

#: A made-up key of a known shape, put together when the test runs.
TOKEN = "".join(["sk", "-abcdefgh", "ijklmnopqrst"])


@pytest.fixture
def salt(monkeypatch) -> str:
    value = "salt-" + secrets.token_hex(16)
    monkeypatch.setenv(SALT_ENV, value)
    return value


def written(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def customer() -> str:
    return "Kunde-" + secrets.token_hex(5)


# -- the check of a call step --------------------------------------------------------------------


def test_the_check_of_a_call_is_masked_like_its_arguments():
    """A check is a path from a script file; a quoted string in it is the script's text, and a
    known value or a token in it never reaches the recording."""
    name = customer()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[name])
    stream = io.StringIO()
    recorder = Recorder(stream, run_id="r", masker=masker)
    check = f'result.items[name="{name}"].{TOKEN}'

    recorder.step_called(1, 0, step="tools/call", tool="t", arguments={}, check=check)

    (event,) = written(stream)
    stand_in = masker.personal_pseudonym("known", name)
    assert event["check"] == f'result.items[name="{stand_in}"].{PLACEHOLDER}'
    assert name not in json.dumps(event) and TOKEN not in json.dumps(event)
    assert masker.replacements["known"] == 0, "the script's text is not counted, as its arguments"


def test_a_check_without_a_value_and_no_check_are_written_as_they_are():
    stream = io.StringIO()
    recorder = Recorder(stream, run_id="r", masker=Masker(handle_salt=HANDLE_SALT))

    recorder.step_called(1, 0, step="tools/call", tool="t", arguments={}, check="result.items[0]")
    recorder.step_called(2, 0, step="tools/call", tool="t", arguments={})

    first, second = written(stream)
    assert first["check"] == "result.items[0]" and second["check"] is None


def test_a_check_holding_a_known_value_is_masked_in_the_recording_and_kept_in_the_script(
    tmp_path, salt
):
    """The run records the check masked; pack masks the script's check the same way, so the
    placed check is exactly what the recording holds and is kept; the value is in no file of the
    bundle or the handover."""
    name = customer()
    text = call_script("        q: 1\n") + f"      check: 'result.content[text=\"{name}\"]'\n"
    setup = Setup(tmp_path / "work", script=text, values=(name,), **CALLS)
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    (called,) = [e for e in events_of(recording) if e["type"] == "step_called"]
    assert name not in json.dumps(called)
    assert PSEUDONYM.search(called["check"]) and called["check"].startswith("result.content[")
    assert setup.pack(bundle, setup.script) == 0
    (script,) = entries(bundle, "script")
    placed = json.loads((bundle / script["path"]).read_text())
    assert placed["steps"][-1]["call"]["check"] == called["check"], "aligned, and kept"
    assert script["replayable"] is True
    assert redacted(setup, bundle, handover) == 0
    nowhere((bundle, handover), name)


# -- a number that holds a known value -----------------------------------------------------------


def test_a_number_that_holds_a_known_value_is_masked_as_its_quoted_text():
    value = "4111222233334444"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[value])

    document, paths = masker.mask_json(
        {"number": int("9" + value), "text": "9" + value, "float": float("0." + value[:8])}
    )

    stand_in = masker.personal_pseudonym("known", value)
    assert document["number"] == document["text"] == f"9{stand_in}"
    assert document["float"] == float("0." + value[:8]), "the float's text does not hold it"
    assert paths == [], "a stand-in for a known value is no redaction, as for a string"
    assert masker.replacements["known"] == 2


def test_a_number_masked_in_part_is_the_text_pack_makes_of_it():
    """The recorder and ``evidence pack`` make the same text of a number, so a placed script
    lines up with what its runs recorded."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["4711"])

    recorded = masker.mask_json({"order": 47110815, "year": 2026})[0]
    placed = evidence._numbers_masked({"order": 47110815, "year": 2026}, masker)

    assert recorded == {"order": masker.personal_pseudonym("known", "4711") + "0815", "year": 2026}
    assert placed == recorded


def test_a_number_from_the_server_that_holds_a_known_value_is_recorded_masked():
    value = "4111222233334444"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[value])
    stream = io.StringIO()
    recorder = Recorder(stream, run_id="r", masker=masker)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"n": int("9" + value)}}).encode()

    recorder.message(1, 0, direction=Direction.SERVER_TO_CLIENT, raw=body)

    (event,) = written(stream)
    assert value not in json.dumps(event)
    stand_in = masker.personal_pseudonym("known", value)
    assert event["payload"]["data"]["result"]["n"] == "9" + stand_in
    assert recorder.server_redactions == 0


def test_the_arguments_of_a_call_hold_the_number_as_the_placed_script_does(tmp_path, salt):
    """``order: 47110815`` with the known value ``4711``: the run records the number masked as
    its quoted text, the placed script holds exactly that, and the handover has it nowhere."""
    setup = Setup(tmp_path / "work", script=call_script("        order: 47110815\n"),
                  values=("4711",), **CALLS)  # fmt: skip
    recording = setup.drive(script=setup.script, ok=(0, 3, 6))
    setup.ingest(recording, ok=(0, 3, 6))
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"

    (called,) = [e for e in events_of(recording) if e["type"] == "step_called"]
    order = called["arguments"]["order"]
    assert isinstance(order, str) and PSEUDONYM.fullmatch(order[:-4]) and order.endswith("0815")
    assert setup.pack(bundle, setup.script) == 0
    (script,) = entries(bundle, "script")
    placed = json.loads((bundle / script["path"]).read_text())
    assert placed["steps"][-1]["call"]["arguments"] == {"order": order}
    assert redacted(setup, bundle, handover) == 0
    nowhere((bundle, handover), "47110815")


# -- redact holds every recording to the check of a placed script --------------------------------


def with_value(recording: Path, destination: Path, value) -> Path:
    """The recording as a session of its own at ``destination``, with ``value`` at
    ``result.customer`` of its ``tools/list`` answer: what a recording made before a rule existed
    may hold."""
    lines = []
    for line in recording.read_text().splitlines():
        event = json.loads(line)
        if event["type"] == "run_started":
            event["run_id"] = secrets.token_hex(4)
        if event["type"] == "message" and event.get("responded_method") == "tools/list":
            event["payload"]["data"]["result"]["customer"] = value
        lines.append(json.dumps(event))
    destination.mkdir(parents=True)
    path = destination / "events.jsonl"
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.mark.parametrize("with_script", [False, True])
@pytest.mark.parametrize("form", ["number", "string"])
def test_redact_refuses_a_recording_that_still_holds_a_known_value(
    tmp_path, salt, capsys, with_script, form
):
    """The number is what a recording made before numbers were masked in part may hold; the
    string what a recording forged or made by another version may. The refusal names the run, the
    event and the place, never the value; nothing is written."""
    setup = Setup(tmp_path / "work", values=("4711",))
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    value = 47110815 if form == "number" else "order 47110815"
    session = with_value(recording, tmp_path / "session", value)
    bundle = tmp_path / "bundle"
    scripts = (setup.script,) if with_script else ()
    assert setup.pack(bundle, *scripts, sessions=(session,)) == 0
    capsys.readouterr()

    assert redacted(setup, bundle, tmp_path / "handover") == 2

    error = capsys.readouterr().err
    run = events_of(session)[0]["run_id"]
    assert "holds a credential, the salt or a known value" in error
    assert f"run {run}" in error and "payload.data.result.customer" in error
    assert re.search(r"seq \d+", error)
    assert "4711" not in error
    assert not (tmp_path / "handover").exists()


def test_redact_lets_a_bundle_through_whose_recordings_hold_no_known_value(tmp_path, salt):
    """The same material without the value: no refusal, and the known value is nowhere."""
    setup = Setup(tmp_path / "work", values=("4711",))
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"
    assert setup.pack(bundle, setup.script) == 0

    assert redacted(setup, bundle, handover) == 0


@pytest.fixture
def credentials(monkeypatch) -> dict[str, str]:
    """A token and a header value of the identity ``reader``, made up here, with no shape a
    masker knows: only a literal finds them."""
    values = {"token": "tq" + secrets.token_hex(12), "header": "hv" + secrets.token_hex(12)}
    monkeypatch.setenv(TOKEN_ENV, values["token"])
    monkeypatch.setenv(HEADER_ENV, values["header"])
    return values


@pytest.mark.parametrize("what", ["token", "header", "salt"])
def test_redact_refuses_a_bundle_of_recordings_only_that_holds_a_credential_or_the_salt(
    tmp_path, salt, credentials, capsys, what
):
    """A bundle without a script is held to the credentials of the engagement file and the salt
    as well, not to the known values alone."""
    value = {**credentials, "salt": salt}[what]
    setup = Setup(tmp_path / "work", identities=IDENTITIES)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    session = with_value(recording, tmp_path / "session", f"x-{value}-y")
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle, sessions=(session,)) == 0
    assert not entries(bundle, "script")
    capsys.readouterr()

    assert redacted(setup, bundle, tmp_path / "handover") == 2

    error = capsys.readouterr().err
    assert "holds a credential, the salt or a known value" in error and value not in error
    assert "payload.data.result.customer" in error
    assert not (tmp_path / "handover").exists()


@pytest.mark.parametrize("missing", ["token", "salt"])
def test_redact_of_recordings_only_says_what_it_cannot_read_and_checks_for_the_rest(
    tmp_path, salt, credentials, monkeypatch, capsys, missing
):
    """A credential or the salt that cannot be read here refuses a bundle with a script. A
    bundle of recordings only is redacted, with a warning that names the place or the variable;
    what can still be read is looked for all the same."""
    setup = Setup(tmp_path / "work", identities=IDENTITIES)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle, handover = tmp_path / "bundle", tmp_path / "handover"
    assert setup.pack(bundle) == 0
    held = with_value(recording, tmp_path / "session", f"x-{credentials['header']}-y")
    holding = tmp_path / "holding"
    assert setup.pack(holding, sessions=(held,)) == 0
    monkeypatch.delenv(TOKEN_ENV if missing == "token" else SALT_ENV)
    capsys.readouterr()

    assert redacted(setup, bundle, handover) == 0

    error = capsys.readouterr().err
    named = "identities[0].token" if missing == "token" else f"the environment variable {SALT_ENV}"
    assert f"warning: {named}" in error or f"warning: the salt ({named})" in error
    assert "cannot be read here" in error and "not for these" in error
    assert credentials["token"] not in error and salt not in error
    assert (handover / evidence.INDEX_FILE).is_file()
    capsys.readouterr()
    assert redacted(setup, holding, tmp_path / "second") == 2
    assert "warning" not in capsys.readouterr().err
    assert not (tmp_path / "second").exists()


def test_redact_of_recordings_only_warns_of_nothing_when_everything_can_be_read(
    tmp_path, salt, credentials, capsys
):
    setup = Setup(tmp_path / "work", identities=IDENTITIES)
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle) == 0
    capsys.readouterr()

    assert redacted(setup, bundle, tmp_path / "handover") == 0

    assert "warning" not in capsys.readouterr().err


def refuses(event: dict, masker: Masker) -> str | None:
    try:
        evidence._known_in_event("events.jsonl", "r1", event, masker)
    except evidence.EvidenceError as refusal:
        return str(refusal)
    return None


def test_the_tools_own_numbers_digests_and_stand_ins_are_not_held_to_the_known_values():
    """The known value's digits by chance in the tool's own numbers, in a digest, in a run id or
    in a pseudonym the masker made: no refusal. In a number or a string of the traffic: one."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["4711"])
    digest = "4711" + "0" * 60
    event = {
        "v": 5, "run_id": "a4711bcd", "seq": 3, "t_ns": 94711, "type": "message",
        "size_bytes": 4711, "payload": {"redaction_count": 4711, "data": {
            "pseudonym": "***KNOWN-0047110000ab***", "handle": "***HANDLE-4711aaaaaaaa***",
            "withheld": f"<path withheld: sha256 {digest}, 4711 characters>",
            "digest": digest, "prefixed": f"sha256:{digest}",
        }},
    }  # fmt: skip

    assert refuses(event, masker) is None
    for place, value in (("n", 47110815), ("s", "x4711"), ("k", {"a4711": 1})):
        changed = json.loads(json.dumps(event))
        changed["payload"]["data"][place] = value
        said = refuses(changed, masker)
        assert said is not None and "4711" not in said, place
        assert f"payload.data.{place}" in said and "r1" in said and "seq 3" in said


@pytest.mark.parametrize("held_as", ["known value", "literal"])
@pytest.mark.parametrize("prefix", ["", "sha256:"])
def test_a_string_of_the_form_of_a_digest_that_is_a_value_whole_refuses(held_as, prefix):
    """A key or a token is often sixty-four hex digits. Such a string is not searched for parts,
    which are there by chance, but it is no digest of the tool where it is a value whole."""
    value = secrets.token_hex(32)
    values = {"known_values": [value, "4711"]} if held_as == "known value" else {
        "literals": [value], "known_values": ["4711"]}  # fmt: skip
    masker = Masker(handle_salt=HANDLE_SALT, **values)
    other = "4711" + secrets.token_hex(30)

    def event(text: str) -> dict:
        return {"seq": 4, "type": "message", "payload": {"data": {"d": text}}}

    said = refuses(event(prefix + value), masker)

    assert said is not None and value not in said and "payload.data.d" in said
    assert refuses(event(prefix + other), masker) is None


def test_a_key_that_holds_the_value_is_named_by_its_place_and_not_by_itself():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["Zornbach"])
    event = {"seq": 3, "type": "message", "payload": {"data": {"Zornbach-GmbH": {"a": 1}}}}

    said = refuses(event, masker)

    assert said is not None and "Zornbach" not in said
    assert "a key in payload.data holds" in said


def test_a_key_that_is_a_credential_by_its_shape_is_not_named_in_the_refusal():
    """A recording made before keys were masked can hold a key that is a token. It reads like a
    name, and the place of what was found below it is named without it."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["4711"])
    data = {TOKEN: {"n": 47110815}, "a b": {"n": 47110815}, "plain_name": {"n": 47110815}}

    for key, shown in ((TOKEN, "<key>"), ("a b", "<key>"), ("plain_name", "plain_name")):
        event = {"seq": 7, "type": "message", "payload": {"data": {"result": {key: data[key]}}}}
        said = refuses(event, masker)
        assert said is not None and TOKEN not in said and "4711" not in said
        assert f"payload.data.result.{shown}.n holds" in said


def test_a_line_that_is_no_event_is_looked_at_as_text():
    name = customer()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[name])

    def said(line: bytes) -> str | None:
        try:
            evidence._known_in_event("events.jsonl", "r1", None, masker, line=line, number=7)
        except evidence.EvidenceError as refusal:
            return str(refusal)
        return None

    found = said(f"cut off: {name}".encode())
    assert found is not None and name not in found
    assert "line 7, which is no event" in found and "r1" in found
    assert said(b"cut off: nothing") is None and said(b"  ") is None


def test_a_known_value_in_another_spelling_of_its_space_is_found_in_a_recording():
    """What a recording made before the normalised copy was read may hold."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["Max Mustermann"])
    event = {"seq": 2, "type": "message", "payload": {"data": {"q": "Max\u00a0Mustermann"}}}

    said = refuses(event, masker)

    assert said is not None and "Mustermann" not in said and "payload.data.q" in said


def test_what_the_tool_writes_into_run_started_is_not_held_to_the_known_values():
    """The year stands in the tool's clock and in the engagement's window by chance, and a new
    run would write it again. A name the operator gave the run is looked at, and so is the
    same field in any other event."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["2026"])
    started = {
        "v": 5, "run_id": "ab2026cd", "seq": 0, "t_ns": 1, "type": "run_started",
        "wall_clock_utc": "2026-11-13T09:28:24.158+00:00", "tool_version": "0.1.2026",
        "inputs": {"platform": "Linux-6.8.2026", "step_timeout": 30.0,
                   "python": {"implementation": "CPython", "version": "3.12.2026"}},
        "reproduction": {"tool": {"version": "0.1.2026"}},
        "authorization": {"engagement": {
            "engagement_id_declared": "acme-pilot",
            "window_declared": {"from": "2026-11-12T09:28:24Z", "until": "2026-11-14T09:28:24Z"},
        }},
        "script": "probe",
    }  # fmt: skip

    assert refuses(started, masker) is None
    named = refuses({**started, "script": "run-2026.yaml"}, masker)
    assert named is not None and "script holds" in named
    elsewhere = refuses({**started, "type": "message"}, masker)
    assert elsewhere is not None and "2026" not in elsewhere


def test_a_real_recording_under_a_known_value_that_is_the_year_is_redacted(tmp_path, salt):
    """End to end: what the tool itself writes into a run does not refuse the handover. The
    value is the day as the tool's clock writes it, which no path of a temporary directory
    holds."""
    day = time.strftime("%Y-%m-%dT", time.gmtime())
    setup = Setup(tmp_path / "work", values=(day,))
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    started = events_of(recording)[0]
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle) == 0

    assert redacted(setup, bundle, tmp_path / "handover") == 0
    if time.strftime("%Y-%m-%dT", time.gmtime()) == day:
        assert started["wall_clock_utc"].startswith(day)


def test_the_check_of_a_recording_needs_no_memory_for_the_places_it_does_not_name():
    """A long list far down below long keys: every element carries its parent's place and its
    position, not the words of its place."""
    import tracemalloc

    masker = Masker(handle_salt=HANDLE_SALT, known_values=["Kunde-0001"])
    data: object = list(range(20_000))
    for level in range(200):
        data = {f"{level:03d}" + "k" * 61: data}
    event = {"seq": 1, "type": "message", "payload": {"data": data}}

    tracemalloc.start()
    try:
        evidence._known_in_event("events.jsonl", "r1", event, masker)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 20_000_000


def test_a_place_far_down_is_named_by_its_end():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["Kunde-0001"])
    data: object = {"last": "Kunde-0001"}
    for level in range(200):
        data = {f"level_{level:03d}": data}
    event = {"seq": 1, "type": "message", "payload": {"data": data}}

    said = refuses(event, masker)

    assert said is not None and len(said) < 700
    assert "level_000.last holds a credential, the salt or a known value" in said
    assert re.search(r": …\.level_\d{3}\.", said)


def test_the_address_and_the_port_a_server_tried_are_masked_when_recorded():
    """The kernel records them, the server chooses them: a known value that is an address or
    stands in a port is not written, and the recording passes the check of a handover."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["10.20.30.40", "4711"])
    stream = io.StringIO()
    recorder = Recorder(stream, run_id="r", masker=masker)
    attempt = {"proto": "tcp", "family": 2, "destination": "10.20.30.40", "port": 14711,
               "count": 1, "unit": "connections"}  # fmt: skip

    recorder.egress_attempt(1, 0, attempt=attempt)
    recorder.egress_attempt(2, 0, attempt={**attempt, "destination": "192.0.2.1", "port": 443})

    recorder.egress_dns(3, 0, query={"transport": "udp", "family": 2, "qname": "a.example",
                                     "qtype": 14711, "answered": False})  # fmt: skip
    recorder.egress_dns(4, 0, query={"transport": "udp", "family": 2, "qname": "a.example",
                                     "qtype": 28, "answered": True})  # fmt: skip

    first, second, asked, plain = written(stream)
    assert first["destination"] == masker.personal_pseudonym("known", "10.20.30.40")
    assert isinstance(first["port"], str) and "4711" not in first["port"]
    assert (second["destination"], second["port"]) == ("192.0.2.1", 443)
    assert isinstance(asked["qtype"], str) and "4711" not in asked["qtype"]
    assert plain["qtype"] == 28
    for event in (first, second, asked, plain):
        assert refuses(event, masker) is None

    recorder.egress_dns(5, 0, query={"transport": "udp", "family": 2, "qname": "a.example",
                                     "qtype": True, "answered": True})  # fmt: skip
    assert written(stream)[-1]["qtype"] is None


def test_the_account_of_a_sandboxed_run_passes_the_check_of_a_handover():
    """The step that collects the egress repeats its summary, and a run whose account does not
    add up says so in sentences that name the counts: with a count whose digits hold a known
    value, every event of it is written so that the handover takes it."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["4711"])
    stream = io.StringIO()
    recorder = Recorder(stream, run_id="r", masker=masker)
    said = "udp over IPv4: the sink could not tell where 14711 datagram(s) were sent"
    summary = {
        "consistent": False, "problems": [said], "attempts": 4711, "dns_queries": 4711,
        "counters": {"n_udp4": 14711}, "capped": {"udp4": 14711}, "direct_sink_access": 4711,
        "sink_suppressed": 4711,
        "account_differences": {"udp4": {"kernel": 14711, "sink": {"seen": 14711}}},
        "udp_loss": {"kernel": 14711, "sink": 4711, "lost": 10000, "rate": 0.4711},
    }  # fmt: skip

    recorder.sandbox_step(1, 0, step="collect", ok=False, seconds=0.5, detail=summary)
    recorder.egress_summary(2, 0, summary=summary)
    recorder.sandbox_failed(3, 0, condition="reconciliation", phase="after_target",
                            detail={"problems": [said]})  # fmt: skip
    recorder.sandbox_step(4, 0, step="images", ok=True, seconds=0.5, detail={"error": "none"})
    for at, which in enumerate(("baseline", "final"), 5):
        # The kernel's counters as they stand: after the target, with all it sent.
        recorder.sandbox_step(at, 0, step=f"reader_{which}", ok=True, seconds=0.5,
                              detail={"counters": {"n_udp4": 14711}, "sockets": []})  # fmt: skip

    step, account, failure, other, before, after = written(stream)
    for event in (step, account, failure, other, before, after):
        assert refuses(event, masker) is None, (event["type"], event.get("step"))
    assert after["detail"]["counters"] == {"n_udp4": 14711}
    assert refuses({**after, "detail": {"counters": {}, "sockets": [14711]}}, masker) is not None
    assert refuses({**after, "detail": {"returncode": 14711}}, masker) is not None
    assert step["detail"]["counters"] == {"n_udp4": 14711}
    assert account["udp_loss"]["kernel"] == 14711 and other["detail"] == {"error": "none"}
    for event in (step["detail"], account, failure["detail"]):
        (problem,) = event["problems"]
        assert "4711" not in problem and problem.endswith(" datagram(s) were sent")
    assert summary["problems"] == [said]

    # The same detail under another step is no account, and is looked at.
    assert refuses({**step, "step": "images"}, masker) is not None


def test_a_count_of_the_kernel_the_sink_or_the_signals_is_not_held_to_the_known_values():
    """A target can steer how many packets it sends, and it does not write the count. The same
    number where a target writes it is looked at."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["4711"])
    counted = [
        {"type": "egress_attempt", "proto": "udp", "family": 2, "destination": "192.0.2.1",
         "port": 53, "kind": None, "count": 14711, "unit": "packets"},
        {"type": "egress_summary", "consistent": True, "problems": [], "attempts": 1,
         "counters": {"n_udp4": 14711}, "capped": {"udp4": 14711},
         "udp_loss": {"kernel": 14711, "lost": 0},
         "account_differences": {"udp4": {"kernel": 14711, "sink": 14710}}},
        {"type": "statement_evaluated", "statement": "s", "fired": {"imperative": 4711}},
        {"type": "run_finished", "findings_by_statement": {"s": {"imperative": 4711}},
         "observations_by_method": {"tools/list": 4711}},
        {"type": "findings_capped", "cut": {"s": {"imperative": 14711}}},
    ]  # fmt: skip
    for event in counted:
        assert refuses({"seq": 1, **event}, masker) is None, event["type"]

    for event in (
        {"type": "egress_attempt", "port": 14711},
        {"type": "egress_dns", "qtype": 14711},
        {"type": "message", "count": 14711},
        {"type": "egress_summary", "problems": ["x 14711"]},
        {"type": "egress_summary", "counters": {"n_udp4": "14711"}},
        {"type": "egress_summary", "counters": {"n_14711": 1}},
        {"type": "egress_summary", "counters": {"n_udp4": [14711]}},
        {"type": "run_finished", "findings_by_statement": {"s-4711": {"imperative": 1}}},
        {"type": "findings_capped", "made": 5, "method": "m-14711"},
        {"type": "sandbox_step", "step": "collect", "detail": {"problems": ["x 14711"]}},
        {"type": "sandbox_step", "step": "collect", "detail": {"other": 14711}},
    ):
        assert refuses({"seq": 1, **event}, masker) is not None, event


def test_a_wide_object_far_down_keeps_no_path_per_key():
    import tracemalloc

    masker = Masker(handle_salt=HANDLE_SALT, known_values=["Kunde-0001"])
    data: object = {f"k{n}": n for n in range(20_000)}
    for level in range(200):
        data = {f"l{level}": data}
    event = {"seq": 1, "type": "message", "payload": {"data": data}}

    tracemalloc.start()
    try:
        evidence._known_in_event("events.jsonl", "r1", event, masker)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 12_000_000


def test_redact_names_a_missing_engagement_file_as_a_refusal(tmp_path, salt, capsys):
    setup = Setup(tmp_path / "work")
    recording = setup.drive(script=setup.script)
    setup.ingest(recording)
    bundle = tmp_path / "bundle"
    assert setup.pack(bundle) == 0
    capsys.readouterr()

    code = cli.main(
        ["evidence", "redact", "-q", str(bundle), "--engagement", str(tmp_path / "missing.json"),
         "--store", str(setup.store), "--out", str(tmp_path / "handover")]
    )  # fmt: skip

    assert code == 2 and "refused: " in capsys.readouterr().err
    assert not (tmp_path / "handover").exists()


def test_a_literal_of_the_masker_in_a_recording_is_found_like_a_known_value():
    """With the masker redact gets for a bundle with a script, the engagement's credentials and
    its salt are literals: one left in a recording refuses as well."""
    secret = "tq" + secrets.token_hex(12)
    masker = Masker(handle_salt=HANDLE_SALT, literals=[secret])
    event = {"seq": 2, "type": "message", "payload": {"data": {"q": f"x {secret} y"}}}

    said = refuses(event, masker)

    assert said is not None and secret not in said


def test_the_check_of_a_recording_is_linear_in_its_size():
    """Ten megabytes of strings and numbers, twenty known values: well under the time the other
    checks of a redaction take."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[f"Kunde-{n:04d}" for n in range(20)])
    text = ("Grüße aus Köln 1234 ***KNOWN-0123456789ab*** %41 \\u0041 " * 20)[:1000]
    events_list = [
        {"seq": n, "type": "message", "payload": {"data": {"text": text, "n": 12345678 + n}}}
        for n in range(10_000)
    ]

    started = time.perf_counter()
    for event in events_list:
        evidence._known_in_event("events.jsonl", "r1", event, masker)
    assert time.perf_counter() - started < 5.0
