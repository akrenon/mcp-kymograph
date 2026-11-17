"""The recorder, including the invariant the whole design rests on:

nothing that goes in comes back out in the clear.

No network, no subprocesses. The envelope — sequence number and timestamp — is supplied by
the caller here, the way the sink supplies it in a real run.
"""

import json
import os
import stat

import pytest

from mcp_kymograph.events import SCHEMA_VERSION, Direction
from mcp_kymograph.masking import PLACEHOLDER, Masker
from mcp_kymograph.recorder import Recorder

# A distinctive marker, not a real credential: a plaintext search for it over the
# recording must find nothing.
CANARY = "CANARY-do-not-leak-0123456789"


class Numbered:
    """Hands out envelopes the way the sink does, so tests read like the real call sites."""

    def __init__(self, recorder: Recorder) -> None:
        self.recorder = recorder
        self.seq = 0
        self.t_ns = 0

    def __call__(self, method: str, **kwargs) -> None:
        self.seq += 1
        self.t_ns += 1000
        getattr(self.recorder, method)(self.seq, self.t_ns, **kwargs)


@pytest.fixture
def path(tmp_path):
    return tmp_path / "events.jsonl"


@pytest.fixture
def emit(path):
    with Recorder.open(path, run_id="testrun", masker=Masker()) as recorder:
        yield Numbered(recorder)


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


# -- file handling -------------------------------------------------------------------


def test_a_recording_is_not_readable_by_group_or_others(path):
    with Recorder.open(path, run_id="r", masker=Masker()):
        pass
    assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0


def test_an_existing_recording_is_never_overwritten(path):
    path.write_text("earlier evidence\n")
    with pytest.raises(FileExistsError):
        Recorder.open(path, run_id="r", masker=Masker())
    assert path.read_text() == "earlier evidence\n"


def test_events_are_flushed_as_they_happen_not_at_the_end(path, emit):
    emit("run_started", argv=["srv"], limits={})
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b'{"method":"ping"}')
    # Still open: an abort here must not lose what has already happened.
    assert len(read_events(path)) == 2


def test_one_line_of_valid_json_per_event(path, emit):
    emit("run_started", argv=["srv"], limits={"max_message_bytes": 1024})
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b'{"id":1,"method":"ping"}')
    emit("server_stderr", raw=b"starting up\n")
    emit("server_exited", exit_code=0)
    emit("limit_exceeded", limit="max_duration", value=86400, unit="seconds")
    emit("recording_stopped", reason="write_failed", from_seq=12)
    emit("run_finished", reason="client_eof", duration_ns=5, dropped_events=3, unwritten_events=1,
         server_output_bytes=10, client_input_bytes=20, server_exited_first=False)  # fmt: skip

    assert [event["type"] for event in read_events(path)] == [
        "run_started",
        "message",
        "server_stderr",
        "server_exited",
        "limit_exceeded",
        "recording_stopped",
        "run_finished",
    ]


def test_run_finished_carries_the_clients_undecodable_count_and_reads_zero_without_it(path, emit):
    """The count is written as given, and a caller that does not know it writes 0."""
    emit("run_finished", reason="client_eof", duration_ns=5, client_undecodable=3,
         server_output_bytes=0, client_input_bytes=0, server_exited_first=False)  # fmt: skip
    emit("run_finished", reason="client_eof", duration_ns=5,
         server_output_bytes=0, client_input_bytes=0, server_exited_first=False)  # fmt: skip
    first, second = read_events(path)
    assert first["client_undecodable"] == 3
    assert second["client_undecodable"] == 0


def test_the_envelope_comes_from_the_caller(path, emit):
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b"{}")
    emit("server_stderr", raw=b"x")
    events = read_events(path)
    assert [event["seq"] for event in events] == [1, 2]
    assert [event["t_ns"] for event in events] == [1000, 2000]
    assert all(event["run_id"] == "testrun" and event["v"] == SCHEMA_VERSION for event in events)


def test_a_gap_in_the_numbers_survives_into_the_file(path, emit):
    """What the sink produces when it drops: the file must carry the jump, not smooth it."""
    emit.seq = 4
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b"{}")
    emit.seq = 9
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b"{}")
    assert [event["seq"] for event in read_events(path)] == [5, 10]


# -- masking on the way in -----------------------------------------------------------


def test_a_credential_in_a_field_never_reaches_the_file(path, emit):
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"api_key": CANARY}}
    ).encode()
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=raw)

    assert CANARY not in path.read_text()
    (event,) = read_events(path)
    assert event["payload"]["data"]["params"]["api_key"] == PLACEHOLDER
    assert event["payload"]["redactions"] == ["params.api_key"]
    assert event["payload"]["redaction_count"] == 1


def test_a_credential_in_prose_never_reaches_the_file(path, emit):
    raw = json.dumps({"result": {"text": f"use Bearer {CANARY} to authenticate"}}).encode()
    emit("message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert CANARY not in path.read_text()


def test_a_credential_in_an_unparseable_message_never_reaches_the_file(path, emit):
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=f"garbage Bearer {CANARY}".encode())
    assert CANARY not in path.read_text()
    (event,) = read_events(path)
    assert event["payload"]["encoding"] == "text"
    assert event["parse"]["ok"] is False


def test_a_credential_on_server_stderr_never_reaches_the_file(path, emit):
    emit("server_stderr", raw=f"config loaded, key=Bearer {CANARY}\n".encode())
    assert CANARY not in path.read_text()


def test_a_credential_on_the_server_command_line_never_reaches_the_file(path, emit):
    emit("run_started", argv=["/opt/bin/srv", "--api-key", CANARY], limits={})
    assert CANARY not in path.read_text()
    (event,) = read_events(path)
    assert event["argv"] == ["srv", "--api-key", PLACEHOLDER]
    assert event["argv_redaction_count"] == 1


def test_run_started_says_whether_something_reshaped_the_environment_first(path, emit):
    emit("run_started", argv=["srv"], limits={})
    (event,) = read_events(path)
    assert isinstance(event["virtual_environment"], bool)


# -- content and analysis stay apart -------------------------------------------------


def test_payload_and_parse_are_separate_fields(path, emit):
    emit(
        "message",
        direction=Direction.CLIENT_TO_SERVER,
        raw=b'{"jsonrpc":"2.0","id":7,"method":"tools/call"}',
    )
    (event,) = read_events(path)
    assert event["payload"]["encoding"] == "json"
    assert event["payload"]["data"]["method"] == "tools/call"
    assert event["parse"] == {
        "ok": True,
        "kind": "request",
        "method": "tools/call",
        "id": 7,
        "is_error": False,
        "error_reason": None,
    }


def test_size_is_the_size_of_the_original_message(path, emit):
    emit(
        "message",
        direction=Direction.SERVER_TO_CLIENT,
        raw=b"",
        size_bytes=5_000_000,
        truncated=True,
    )
    (event,) = read_events(path)
    assert event["size_bytes"] == 5_000_000
    assert event["truncated"] is True
    assert event["parse"]["error_reason"] == "truncated"


def test_an_unfinished_message_is_marked_rather_than_dropped(path, emit):
    emit("message", direction=Direction.SERVER_TO_CLIENT, raw=b'{"half":', incomplete=True)
    (event,) = read_events(path)
    assert event["incomplete"] is True
    assert event["parse"]["error_reason"] == "incomplete"
    assert event["payload"]["data"] == '{"half":'


def test_a_document_json_cannot_round_trip_is_kept_as_text(path, emit):
    emit("message", direction=Direction.SERVER_TO_CLIENT, raw=b'{"n": 1e400}')
    (event,) = read_events(path)
    assert event["payload"]["encoding"] == "text"
    assert event["parse"]["error_reason"] == "unrepresentable"
    assert "1e400" in event["payload"]["data"]


def test_the_file_stays_pure_ascii(path, emit):
    emit("message", direction=Direction.SERVER_TO_CLIENT, raw='{"t":"grüße ‮"}'.encode())
    assert path.read_text().isascii()
    (event,) = read_events(path)
    assert event["payload"]["data"]["t"] == "grüße ‮"


def test_writing_after_close_is_refused(path, emit):
    emit.recorder.close()
    with pytest.raises(RuntimeError):
        emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b"{}")


# -- intervention steps: a changed value is masked where it sat --------------------------


def step(path, before, after):
    from mcp_kymograph.engine import Change, Step

    return Step(rule="r", action="replace", changes=(Change(path, before, after),))


def intervene(emit, *steps):
    emit(
        "intervention",
        action="replace",
        direction=Direction.SERVER_TO_CLIENT,
        message_id=1,
        original=None,
        replacement=None,
        steps=steps,
    )


def test_a_value_under_a_secret_key_is_masked_in_a_step_too(emit, path):
    """Masking the bare string would let it through: the key is what the rule reads."""
    intervene(emit, step("params.arguments.api_key", CANARY, CANARY + "x"))
    text = path.read_text()
    assert CANARY not in text
    (change,) = read_events(path)[0]["steps"][0]["changes"]
    assert change["before"]["data"] == PLACEHOLDER
    assert change["before"]["redactions"] == ["params.arguments.api_key"]


def test_a_secret_key_above_the_value_masks_it_and_is_named_at_its_real_position(emit, path):
    intervene(emit, step("result.items[7].token.value", CANARY, "x"))
    assert CANARY not in path.read_text()
    (change,) = read_events(path)[0]["steps"][0]["changes"]
    assert change["before"]["data"] == PLACEHOLDER
    assert change["before"]["redactions"] == ["result.items[7].token"]


def test_a_redaction_inside_a_changed_value_keeps_its_real_list_position(emit, path):
    intervene(emit, step("result.tools[4000].description", f"use Bearer {CANARY}", "x"))
    assert CANARY not in path.read_text()
    (change,) = read_events(path)[0]["steps"][0]["changes"]
    assert change["before"]["redactions"] == ["result.tools[4000].description"]
    assert change["path"] == "result.tools[4000].description"


def test_a_protocol_handle_in_a_step_is_pseudonymised_as_in_a_message(emit, path):
    intervene(emit, step("params.progressToken", "tok-1", "tok-2"))
    (change,) = read_events(path)[0]["steps"][0]["changes"]
    assert change["before"]["data"].startswith("***HANDLE-")
    assert "tok-1" not in path.read_text()


def test_a_whole_document_step_is_masked_as_a_document(emit, path):
    intervene(emit, step("", {"auth": CANARY}, {"auth": "y"}))
    assert CANARY not in path.read_text()


def test_a_step_without_effect_is_recorded_with_its_reason(emit, path):
    from mcp_kymograph.engine import Step

    intervene(emit, Step(rule="r", action="inject", reason="path_not_found"))
    (recorded,) = read_events(path)[0]["steps"]
    assert recorded == {
        "rule": "r",
        "action": "inject",
        "reason": "path_not_found",
        "changes": [],
        "skipped": [],
    }
