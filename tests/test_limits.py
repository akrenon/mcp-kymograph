"""What a server cannot do with the size and shape of what it sends: a line longer than any
limit, nesting deeper than any walk, a schema without a bottom. Each ends in a named cause or
state — never in a crash that costs the rest of the run or the recording.
"""

from __future__ import annotations

import asyncio
import gc
import json
import sys
import threading
from pathlib import Path

import pytest

from mcp_kymograph import cli, events, verdict
from mcp_kymograph.driver import (
    DISCOVERY,
    MAX_LINE_BYTES,
    MIN_LINE_BYTES,
    NO_ANSWER,
    OVERSIZED,
    ClientChannel,
    Driver,
    OversizedTimeout,
)
from mcp_kymograph.engine import Action, Engine
from mcp_kymograph.events import UNREADABLE, Direction
from mcp_kymograph.inspection import MAX_INSPECTED_DEPTH, MAX_SCHEMA_DEPTH, Inspector
from mcp_kymograph.masking import Masker
from mcp_kymograph.proxy import Observer
from mcp_kymograph.recorder import MAX_RECORDED_DEPTH, TOO_DEEP_TO_RECORD, Recorder

SERVER = str(Path(__file__).parent / "fixtures" / "discovery_server.py")


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def _deep(depth: int) -> list:
    """``depth`` nested lists, built without json.loads: on 3.10 and 3.11 its recursion would
    give out before the depths these tests need."""
    value: list = []
    for _ in range(depth - 1):
        value = [value]
    return value


#: Depths past the read depth: one every version parses, one only 3.12 and later parse, one no
#: version does. Each must come out the same.
PAST_READ_DEPTH = [events.MAX_READ_DEPTH + 1, 2_000, 100_000]


# -- the driver's line ---------------------------------------------------------------------


def _read_lines(written: bytes, count: int, limit: int = MAX_LINE_BYTES) -> list[bytes | None]:
    """What the driver's channel reads, ``count`` times, from a server that wrote this."""

    async def read() -> list[bytes | None]:
        channel = ClientChannel(max_line_bytes=limit)
        await channel.open()
        writer = threading.Thread(target=_write_and_close, args=(channel.proxy_out, written))
        writer.start()
        try:
            return [await channel.read_line(10.0) for _ in range(count)]
        finally:
            channel.close()  # first, so that a writer still writing is not waited for forever
            writer.join()

    return asyncio.run(read())


def _write_and_close(out, data: bytes) -> None:
    out.write(data)
    out.close()


def test_a_line_at_the_limit_is_read_whole():
    """The limit counts what comes before the newline: exactly that much is still a line."""
    line = b"x" * MAX_LINE_BYTES + b"\n"
    assert _read_lines(line, 2) == [line, None]


def test_the_channel_takes_the_limit_it_is_given():
    written = b"x" * 17 + b"\n" + b"y" * 16 + b"\n"
    assert _read_lines(written, 3, limit=16) == [OVERSIZED, b"y" * 16 + b"\n", None]


@pytest.mark.filterwarnings("error::ResourceWarning")
@pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning")
def test_time_running_out_inside_a_line_over_the_limit_says_so():
    """Silence after the start of an overlong line: a timeout, and one that says what came.
    The channel is closed whole afterwards, though the stream never ended."""

    async def read() -> None:
        channel = ClientChannel(max_line_bytes=16)
        await channel.open()
        try:
            channel.proxy_out.write(b"x" * 40)  # no newline, and the pipe stays open
            with pytest.raises(OversizedTimeout):
                await channel.read_line(1.0)
        finally:
            channel.close()

    asyncio.run(read())
    gc.collect()  # what was left open says so now, inside this test, not in a later one


@pytest.mark.parametrize("size", [MAX_LINE_BYTES + 1, 3 * MAX_LINE_BYTES + 17])
def test_a_line_over_the_limit_is_read_past_and_the_next_one_is_read(size):
    lines = _read_lines(b"x" * size + b"\n" + b'{"id": 1}\n', 3)
    assert lines == [OVERSIZED, b'{"id": 1}\n', None]


def test_a_line_over_the_limit_that_never_ends_is_read_past_to_the_end():
    assert _read_lines(b"x" * (2 * MAX_LINE_BYTES), 2) == [OVERSIZED, None]


def test_reading_past_an_overlong_line_gets_only_the_time_that_is_left(monkeypatch):
    """One time for a line, however it is read: never a second full timeout to read past it."""
    budgets: list[float] = []
    wait_for = asyncio.wait_for

    async def recorded(awaitable, timeout):
        budgets.append(timeout)
        return await wait_for(awaitable, timeout)

    async def read() -> None:
        channel = ClientChannel(max_line_bytes=16)
        await channel.open()
        try:
            channel.proxy_out.write(b"x" * 40)  # no newline, and the pipe stays open
            monkeypatch.setattr(asyncio, "wait_for", recorded)
            with pytest.raises(OversizedTimeout):
                await channel.read_line(0.5)
        finally:
            monkeypatch.undo()
            channel.close()

    asyncio.run(read())
    assert len(budgets) == 2
    assert budgets[0] == 0.5
    assert budgets[1] < budgets[0]


def test_the_last_line_without_its_newline_is_still_a_line():
    assert _read_lines(b'{"id": 1}', 2) == [b'{"id": 1}', None]


class _Wire:
    """A channel that hands over prepared lines and then nothing, as a server that wrote
    them and then fell silent."""

    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)
        self.sent: list[dict] = []

    async def open(self) -> None:
        return None

    async def send(self, line: bytes) -> None:
        self.sent.append(json.loads(line))

    async def read_line(self, timeout: float) -> bytes | None:
        if self._lines:
            return self._lines.pop(0)
        await asyncio.sleep(timeout)
        raise asyncio.TimeoutError

    def close_write(self) -> None:
        return None


def _drive(
    lines: list[bytes], wire: _Wire | None = None, step_timeout: float = 0.05
) -> tuple[list, list]:
    failed: list = []
    unanswered: list = []

    async def record_failed(**fields) -> None:
        failed.append(fields)

    async def record_unanswered(**fields) -> None:
        unanswered.append(fields)

    async def record_skipped(**fields) -> None:
        return None

    driver = Driver(
        DISCOVERY,
        _Wire(lines) if wire is None else wire,  # type: ignore[arg-type]
        record_skipped=record_skipped,
        record_failed=record_failed,
        record_unanswered=record_unanswered,
        step_timeout=step_timeout,
    )
    asyncio.run(driver.run())
    return failed, unanswered


@pytest.mark.parametrize(
    "line",
    [OVERSIZED, (_nested(100_000) + "\n").encode()],
    ids=["too long", "too deep"],
)
def test_an_unreadable_line_and_no_answer_is_named_as_such(line):
    failed, _ = _drive([line])
    assert [entry["reason"] for entry in failed] == [UNREADABLE]
    assert "could read" in failed[0]["detail"]


def test_time_running_out_inside_an_unreadable_line_is_unreadable_too():
    class Overlong(_Wire):
        async def read_line(self, timeout: float) -> bytes | None:
            raise OversizedTimeout

    failed, _ = _drive([], Overlong([]))
    assert [entry["reason"] for entry in failed] == [UNREADABLE]


def test_an_unreadable_line_in_one_step_is_not_the_cause_of_the_next():
    """Each request starts from no answer: an unreadable line before the handshake's answer
    says nothing about why the listing after it went unanswered."""
    hello = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
             "serverInfo": {"name": "s", "version": "1"}}  # fmt: skip
    answer = {"jsonrpc": "2.0", "id": 1, "result": hello}
    failed, unanswered = _drive([OVERSIZED, json.dumps(answer).encode() + b"\n"])
    assert failed == []
    assert [(entry["step"], entry["reason"]) for entry in unanswered] == [("tools/list", NO_ANSWER)]


def test_an_unreadable_line_then_the_end_is_still_unreadable():
    """The server closing after it is no reason to forget what came before."""

    class Ending(_Wire):
        async def read_line(self, timeout: float) -> bytes | None:
            return self._lines.pop(0) if self._lines else None

    failed: list = []

    async def record_failed(**fields) -> None:
        failed.append(fields)

    async def nothing(**fields) -> None:
        return None

    driver = Driver(DISCOVERY, Ending([OVERSIZED]), record_skipped=nothing,  # type: ignore[arg-type]
                    record_failed=record_failed, step_timeout=0.05)  # fmt: skip
    asyncio.run(driver.run())
    assert [entry["reason"] for entry in failed] == [UNREADABLE]


def test_an_unreadable_step_leaves_the_inventory_partial():
    for kind in ("step_skipped", "step_unanswered"):
        event = {"type": kind, "step": "tools/list", "reason": UNREADABLE, "pages": 0}
        judged = verdict.assess([event])
        assert judged.state == verdict.INCOMPLETE
        assert any(UNREADABLE in problem for problem in judged.problems)


@pytest.mark.parametrize("depth", PAST_READ_DEPTH)
def test_an_answer_too_deep_to_read_is_the_answer_and_no_later_one_is_waited_for(depth):
    """Its id is ours: there is no other answer to it, so a second with the same id that
    follows is not taken in its place — also where json.loads gives out before its end."""
    hello = ('{"protocolVersion":"2025-06-18","capabilities":{},'
             '"serverInfo":{"name":"s","version":"1"}}')  # fmt: skip
    deep = '{"jsonrpc":"2.0","id":1,"result":' + _nested(depth - 1) + "}\n"
    flat = '{"jsonrpc":"2.0","id":1,"result":' + hello + "}\n"
    failed, _ = _drive([deep.encode(), flat.encode()])
    assert [entry["reason"] for entry in failed] == [UNREADABLE]


def _broken(depth: int, how: str) -> str:
    """``depth`` levels that are no JSON: closed with the wrong bracket, or with something
    in them that is not a value."""
    if how == "wrong bracket":
        return "[" * (depth - 1) + "{}" + "}" * (depth - 1)
    return "[" * depth + "?" + "]" * depth


@pytest.mark.parametrize("depth", [2_000, 100_000])
@pytest.mark.parametrize(
    ("how", "unreadable"), [("wrong bracket", False), ("not a value inside", True)]
)
def test_a_deep_line_that_is_no_json_is_judged_the_same_on_every_version(depth, how, unreadable):
    """Brackets that do not pair make no JSON at any depth: the answer after it is read.
    Brackets that pair but go too deep make a line too deep, whatever lies inside: as with a
    valid one, it is the answer when its id is ours. Neither depends on where json.loads
    would have given out."""
    hello = ('{"protocolVersion":"2025-06-18","capabilities":{},'
             '"serverInfo":{"name":"s","version":"1"}}')  # fmt: skip
    deep = '{"jsonrpc":"2.0","id":1,"result":' + _broken(depth - 1, how) + "}\n"
    flat = '{"jsonrpc":"2.0","id":1,"result":' + hello + "}\n"
    failed, _ = _drive([deep.encode(), flat.encode()])
    assert [entry["reason"] for entry in failed] == ([UNREADABLE] if unreadable else [])


@pytest.mark.parametrize("depth", [3, *PAST_READ_DEPTH])
def test_an_answer_with_a_byte_order_mark_is_read_as_without(depth):
    """json.loads skips the mark in bytes; what is read past the depth skips it too."""
    hello = ('{"protocolVersion":"2025-06-18","capabilities":{},'
             '"serverInfo":{"name":"s","version":"1"}}')  # fmt: skip
    if depth == 3:
        first = '{"jsonrpc":"2.0","id":1,"result":' + hello + "}\n"
    else:
        first = '{"jsonrpc":"2.0","id":1,"result":' + _nested(depth - 1) + "}\n"
    flat = '{"jsonrpc":"2.0","id":1,"result":' + hello + "}\n"
    failed, _ = _drive([b"\xef\xbb\xbf" + first.encode(), flat.encode()])
    assert [entry["reason"] for entry in failed] == ([] if depth == 3 else [UNREADABLE])


def test_without_an_unreadable_line_no_answer_stays_no_answer():
    failed, _ = _drive([b"not json\n"])
    assert [entry["reason"] for entry in failed] == ["no_answer"]


def test_an_unreadable_line_before_the_answer_costs_nothing():
    answer = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18",
              "capabilities": {}, "serverInfo": {"name": "s", "version": "1"}}}  # fmt: skip
    # Reading the deep line takes time of its own, which is part of the step's one time.
    failed, unanswered = _drive([OVERSIZED, (_nested(100_000) + "\n").encode(),
                                 json.dumps(answer).encode() + b"\n"], step_timeout=5)  # fmt: skip
    assert failed == unanswered == []


@pytest.mark.parametrize("depth", [events.MAX_READ_DEPTH, *PAST_READ_DEPTH])
def test_how_deep_an_answer_is_read_is_a_fixed_depth(depth):
    """The same on every Python version: not wherever its own json.loads gives out."""
    hello = ('{"protocolVersion":"2025-06-18","capabilities":{},'
             '"serverInfo":{"name":"s","version":"1"},"x":' + _nested(depth - 2) + "}")  # fmt: skip
    answer = '{"jsonrpc":"2.0","id":1,"result":' + hello + "}\n"
    failed, unanswered = _drive([answer.encode()])
    assert [entry["reason"] for entry in failed + unanswered] == (
        [] if depth <= events.MAX_READ_DEPTH else [UNREADABLE]
    )


# -- reading a recording -------------------------------------------------------------------


def test_a_recording_line_nested_too_deeply_is_a_problem_not_a_crash():
    raw = (_nested(100_000) + "\n" + json.dumps({"type": "x"}) + "\n").encode()
    events, problems = verdict.read_events(raw)
    assert events == [{"type": "x"}]
    assert problems == ["line 1: nested too deeply"]


@pytest.mark.parametrize("depth", [2_000, 100_000])
@pytest.mark.parametrize(
    ("how", "problem"), [("wrong bracket", "not JSON"), ("not a value inside", "nested too deeply")]
)
def test_a_deep_recording_line_that_is_no_json_is_named_the_same_on_every_version(
    depth, how, problem
):
    read, problems = verdict.read_events((_broken(depth, how) + "\n").encode())
    assert (read, problems) == ([], [f"line 1: {problem}"])


@pytest.mark.parametrize("depth", [events.MAX_READ_DEPTH, events.MAX_READ_DEPTH + 1])
def test_how_deep_a_recording_line_is_read_is_a_fixed_depth(depth):
    line = '{"type":"x","deep":' + _nested(depth - 1) + "}"
    read, problems = verdict.read_events((line + "\n").encode())
    assert len(read) == (depth <= events.MAX_READ_DEPTH)
    assert problems == ([] if depth <= events.MAX_READ_DEPTH else ["line 1: nested too deeply"])


# -- recording a message -------------------------------------------------------------------


def _recorded(tmp_path, call: str, masker: Masker | None = None, **fields) -> dict:
    """The one event a recorder writes for this call."""
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="limits", masker=masker or Masker()) as recorder:
        getattr(recorder, call)(1, 0, **fields)
    return [json.loads(line) for line in path.read_text().splitlines()][-1]


def _token() -> str:
    """A token of a shape the masking blanks wherever it stands, put together here."""
    return "".join(("g", "h", "p_")) + "A1b2" * 5


@pytest.mark.parametrize("depth", [MAX_RECORDED_DEPTH + 1, 5_000, 100_000])
def test_a_message_too_deep_to_mask_is_recorded_as_a_note(tmp_path, depth):
    """Deeper than the masking walk follows, or deeper than json.loads goes at all: only the
    note, said to be too deep — and the recording goes on."""
    raw = _nested(depth).encode()
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert (message["parse"]["ok"], message["parse"]["error_reason"]) == (False, "too_deep")
    assert message["payload"]["encoding"] == "text"
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    assert message["payload"]["redaction_count"] == 0


@pytest.mark.parametrize(
    ("depth", "data"),
    [(MAX_RECORDED_DEPTH, _deep(MAX_RECORDED_DEPTH)), (MAX_RECORDED_DEPTH + 1, TOO_DEEP_TO_RECORD)],
    ids=["at the depth", "one deeper"],
)
def test_how_deep_a_message_is_written_as_json_is_a_fixed_depth(tmp_path, depth, data):
    """The same on every Python version and from every stack: not where recursion gives out."""
    raw = _nested(depth).encode()
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["ok"] is (depth == MAX_RECORDED_DEPTH)
    assert message["payload"]["encoding"] == ("json" if depth == MAX_RECORDED_DEPTH else "text")
    assert message["payload"]["data"] == data


@pytest.mark.parametrize("depth", [MAX_RECORDED_DEPTH + 44, 100_000], ids=["parsed", "unparsed"])
@pytest.mark.parametrize("escaped", [False, True], ids=["as written", "behind an escape"])
def test_a_token_in_a_message_too_deep_to_mask_is_never_written(tmp_path, depth, escaped):
    """Not by key, but by its shape — which the rules by shape miss in the text once one of
    its characters is written as a JSON escape. Too deep to mask, the message is not written
    at all, however deep and in whatever spelling."""
    token = _token()
    spelled = (f"\\u{ord(token[0]):04x}" + token[1:]) if escaped else token
    raw = ('{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"' + spelled
           + '","deep":' + _nested(depth - 2) + "}}").encode()  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == "too_deep"
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    written = (tmp_path / "events.jsonl").read_text()
    assert token[3:] not in written


@pytest.mark.parametrize("depth", [2_000, 100_000])
@pytest.mark.parametrize(
    ("how", "reason"), [("wrong bracket", "invalid_json"), ("not a value inside", "too_deep")]
)
def test_a_deep_message_that_is_no_json_is_recorded_the_same_on_every_version(
    tmp_path, depth, how, reason
):
    raw = _broken(depth, how).encode()
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == reason
    if reason == "too_deep":
        assert message["payload"]["data"] == TOO_DEEP_TO_RECORD


@pytest.mark.parametrize("depth", [600, 2_000, 100_000])
@pytest.mark.parametrize("how", ["valid", "not a value inside"])
def test_a_deep_message_with_a_byte_that_is_not_utf8_is_only_a_note(tmp_path, depth, how):
    """Such a message is read as its document, to be masked — but never past the read depth,
    where only the note is written, on every version."""
    token = _token()
    escaped = f"\\u{ord(token[0]):04x}" + token[1:]
    deep = _nested(depth - 2) if how == "valid" else _broken(depth - 2, how)
    raw = (b'{"jsonrpc":"2.0","method":"m","params":{"note":"' + escaped.encode()
           + b'","filler":"a\xff","deep":' + deep.encode() + b"}}")  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    assert token[3:] not in (tmp_path / "events.jsonl").read_text()


def test_an_answer_with_a_lone_surrogate_is_still_read():
    """As json.loads reads it from bytes: such a string is no reason to miss the answer."""
    answer = (b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",'
              b'"capabilities":{},"serverInfo":{"name":"\xed\xa0\x80",'
              b'"version":"1"}}}\n')  # fmt: skip
    failed, unanswered = _drive([answer])
    assert failed == unanswered == []


def test_a_note_counts_a_secret_key_once_whatever_its_value_holds(tmp_path):
    """The masking blanks such a value whole, keys inside it and all: one redaction."""
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"password":{"token":"a","secret":"b"},'
           + '"deep":' + _nested(MAX_RECORDED_DEPTH) + "}}").encode()  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    assert message["payload"]["redaction_count"] == 1


def test_a_note_counts_the_secret_keys_it_withholds(tmp_path):
    """What the masking would have blanked by key is not written, and is counted as such."""
    field = '{"password":"a","token":"b","name":"c"}'
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"one":' + field + ',"two":[' + field
           + '],"deep":' + _nested(MAX_RECORDED_DEPTH) + "}}").encode()  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    assert message["payload"]["redaction_count"] == 4


def test_a_number_json_cannot_carry_beside_a_secret_is_recorded_masked(tmp_path):
    """1e400 parses, and becomes infinite: the message is text, the masked document's."""
    secret = "value" + "-of-a-pass" + "word"
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"password":"' + secret + '","n":1e400,'
           + '"note":"' + _token() + '","' + _token() + '":1}}').encode()  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == "unrepresentable"
    assert message["payload"]["encoding"] == "text"
    # Two by path, and one more in the text: the token written as a key, which no path names.
    assert message["payload"]["redaction_count"] == 3
    written = (tmp_path / "events.jsonl").read_text()
    assert secret not in written
    assert _token()[3:] not in written


def test_a_number_json_cannot_carry_beside_a_token_written_as_a_key_is_recorded_masked(tmp_path):
    """No path names a key, so only the masked text's own rules by shape find it — decoded."""
    token = _token()
    escaped = f"\\u{ord(token[0]):04x}" + token[1:]
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"' + escaped + '":1,"n":1e400}}').encode()
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == "unrepresentable"
    assert message["payload"]["redaction_count"] == 1
    assert token[3:] not in (tmp_path / "events.jsonl").read_text()


def test_a_number_json_cannot_carry_and_nothing_to_mask_keeps_its_digits(tmp_path):
    raw = b'{"jsonrpc":"2.0","method":"m","params":{"n":1e400,"x":"plain"}}'
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == "unrepresentable"
    assert message["payload"]["data"] == raw.decode()
    assert message["payload"]["redaction_count"] == 0


def test_an_intervention_value_json_cannot_carry_is_recorded_masked(tmp_path):
    """The same for a document an intervention records: not its unmasked repr."""
    secret = "value" + "-of-a-pass" + "word"
    event = _recorded(
        tmp_path,
        "intervention",
        action="replace",
        direction=Direction.SERVER_TO_CLIENT,
        message_id=1,
        original={"password": secret, "n": float("inf")},
        replacement=None,
    )
    assert event["original"]["encoding"] == "text"
    assert event["original"]["redaction_count"] == 1
    assert secret not in (tmp_path / "events.jsonl").read_text()


@pytest.mark.parametrize(
    "spoiler",
    ["constant", "repeated key", "not utf-8"],
)
@pytest.mark.parametrize("deep", [False, True], ids=["flat", "too deep to mask"])
def test_a_message_rejected_as_written_is_masked_as_its_document(tmp_path, spoiler, deep):
    """A constant JSON has not, a key given twice, a byte that is not UTF-8: each makes the
    message one that is rejected, but read all the same — and masked as such, never by its
    shape alone, which a JSON escape gets past."""
    token, secret = _token(), "value" + "-of-a-pass" + "word"
    escaped = f"\\u{ord(token[0]):04x}" + token[1:]
    extra = {"constant": ',"n":NaN', "repeated key": ',"note":"plain"', "not utf-8": ""}[spoiler]
    filler = '"a\xff"' if spoiler == "not utf-8" else '"a"'
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"password":"' + secret + '","note":"'
           + escaped + '","filler":' + filler + extra + ',"deep":'
           + _nested(MAX_RECORDED_DEPTH if deep else 1) + "}}").encode("latin-1")  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    reason = {"constant": "non_json_constant", "repeated key": "duplicate_keys",
              "not utf-8": "not_utf8"}[spoiler]  # fmt: skip
    assert message["parse"]["error_reason"] == reason
    written = (tmp_path / "events.jsonl").read_text()
    assert secret not in written
    assert token[3:] not in written
    if deep:
        assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
        assert message["payload"]["redaction_count"] == 1
    else:
        assert message["payload"]["redaction_count"] == 2


def test_a_repeated_key_gives_every_one_of_its_values_to_the_masking(tmp_path):
    token = _token()
    escaped = f"\\u{ord(token[0]):04x}" + token[1:]
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"note":"' + escaped
           + '","note":"plain","note":"third"}}').encode()  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == "duplicate_keys"
    assert token[3:] not in (tmp_path / "events.jsonl").read_text()
    assert "plain" in message["payload"]["data"]
    assert "third" in message["payload"]["data"]


@pytest.mark.parametrize(
    "raw",
    [b'{"jsonrpc":"2.0","method":"m","params":{"n":NaN}}',
     b'{"jsonrpc":"2.0","method":"m","params":{"a":1,"a":2}}',
     b'{"jsonrpc":"2.0","method":"m","params":{"a":"\xff"}}'],
    ids=["constant", "repeated key", "not utf-8"],
)  # fmt: skip
def test_a_message_rejected_as_written_with_nothing_to_mask_keeps_its_spelling(tmp_path, raw):
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["payload"]["data"] == raw.decode("utf-8", errors="replace")
    assert message["payload"]["redaction_count"] == 0


def test_a_message_that_is_not_json_is_still_masked_by_shape(tmp_path):
    """The one case left to the rules by shape: there is no document to mask."""
    raw = ('{"jsonrpc":"2.0","method":"m","params":{"note":"' + _token() + '"').encode()
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["parse"]["error_reason"] == "invalid_json"
    assert _token()[3:] not in (tmp_path / "events.jsonl").read_text()


def test_the_depths_are_fixed_numbers():
    """The recorded depth counts from a document's root, the schema depth from a schema's;
    the inspected depth lies above the one and below where any version's parser gives out."""
    assert MAX_RECORDED_DEPTH == events.MAX_DOCUMENT_DEPTH == 256
    assert MAX_SCHEMA_DEPTH == 256
    assert MAX_INSPECTED_DEPTH == 512


@pytest.mark.parametrize(
    ("document", "depth"),
    [(1, 0), ([], 1), ({"a": [1, {"b": None}]}, 3), (_deep(300), 300),
     ([[1], [[2]], [[[3]]]], 4), ({"x": {"y": {}}, "z": []}, 3),
     ({}, 1), ([[]], 2), ({"a": {}}, 2), ([[], [[]]], 3), ([1, "a", None, []], 2)],
)  # fmt: skip
def test_the_depth_is_counted_in_objects_and_lists_from_the_root(document, depth):
    assert events.deeper_than(document, depth - 1) is (depth > 0)
    assert not events.deeper_than(document, depth)
    assert not events.deeper_than(document, depth + 1)


@pytest.mark.parametrize(
    ("text", "members"),
    [('{"id":7,"method":"m","params":{"a":[1,{"b":2}]}}', {"id": 7, "method": "m", "params": None}),
     ('{"a":"x]}{[\\"","b":[],"c":{}}', {"a": 'x]}{["', "b": None, "c": None}),
     ('{"a":"[x]","b":{"c":"{"}}', {"a": "[x]", "b": None}),
     ('{"id":1,"result":' + _nested(100_000) + "}", {"id": 1, "result": None}),
     ('{"a":"\\\\","b":[]}', {"a": "\\", "b": None}),
     ("[1,2]", None), ('"x"', None), ('{"a":[[', None), ("{not json}", None)],
    ids=["nested", "brackets in a string", "an opening in a string", "deeper than any parser",
         "escaped backslash", "a list", "a string", "never closed", "not json"],
)  # fmt: skip
def test_the_top_level_of_an_object_is_read_however_deep_it_nests(text, members):
    assert events.top_level(text) == members


@pytest.mark.parametrize(
    ("text", "depth"),
    [("1", 0), ("[]", 1), ('{"a":[1,{"b":"]]]"}]}', 3), ('["\\"[["]', 1),
     (_nested(100_000), 100_000), ("[}", None), ("[[]", None), ("[]]", None), ('["]', None),
     ('{"a":"x\\"}', None), ("[1,\\]", None), ('[]"', None)],
    ids=["scalar", "empty", "brackets in a string", "escaped quote", "deep",
         "wrong bracket", "never closed", "closed too often", "string never ends",
         "escaped end of string", "an escape outside a string", "a string after the end"],
)  # fmt: skip
def test_how_deep_a_text_nests_is_read_without_parsing_it(text, depth):
    assert events.nesting(text) == depth


@pytest.mark.parametrize(
    ("text", "limit", "loaded"),
    [("[[1]]", 2, ([[1]], False)), ("[[1]]", 1, (None, True)),
     ('{"id":1,"x":[[1]]}', 2, ({"id": 1, "x": None}, True)), ("[[1}]", 1, (None, False)),
     ("[[1]] x", 2, (None, False)), ("[[1]] x", 1, (None, True))],
    ids=["within", "too deep, no object", "too deep, its top level", "brackets that do not pair",
         "not json within", "too deep, whatever follows"],
)  # fmt: skip
def test_a_text_is_loaded_only_within_the_depth(text, limit, loaded):
    assert events.load(text, limit) == loaded


@pytest.mark.parametrize(
    ("raw", "loaded"),
    [(b'{"a":[1]}', ({"a": [1]}, False)), (b"\xef\xbb\xbf" + b'{"a":[1]}', ({"a": [1]}, False)),
     ('{"a":[1]}'.encode("utf-16"), ({"a": [1]}, False)), (b'{"a":"\xff"}', (None, False)),
     (b'{"a":' + _nested(9).encode() + b"}", ({"a": None}, True)),
     (b'{"a":"\xed\xa0\x80"}', ({"a": "\ud800"}, False))],
    ids=["utf-8", "byte order mark", "utf-16", "not utf-8", "too deep", "a lone surrogate"],
)  # fmt: skip
def test_bytes_are_loaded_as_json_loads_decodes_them(raw, loaded):
    assert events.load_bytes(raw, 8) == loaded


@pytest.mark.parametrize("depth", [events.MAX_READ_DEPTH, events.MAX_READ_DEPTH + 1, 2_000])
@pytest.mark.parametrize("utf8", [True, False], ids=["utf-8", "a byte that is not"])
def test_a_message_is_parsed_for_its_note_up_to_the_read_depth(tmp_path, depth, utf8):
    """Up to there the note counts what it withholds; past it nothing is parsed to count —
    whether its bytes are UTF-8 or not."""
    filler = b'"a"' if utf8 else b'"a\xff"'
    raw = (b'{"jsonrpc":"2.0","method":"m","params":{"password":"a","filler":' + filler
           + b',"deep":' + _nested(depth - 2).encode() + b"}}")  # fmt: skip
    message = _recorded(tmp_path, "message", direction=Direction.SERVER_TO_CLIENT, raw=raw)
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    assert message["payload"]["redaction_count"] == (depth <= events.MAX_READ_DEPTH)


@pytest.mark.parametrize(
    ("extra", "in_a_list"),
    [((), False), (("customer_ref",), False), ((), True)],
    ids=["default needle", "mask key", "inside a list"],
)
def test_a_message_too_deep_to_mask_with_a_secret_key_is_only_a_note(tmp_path, extra, in_a_list):
    """Its text would carry what the masking blanks by key, which the rules by shape miss."""
    secret, kept = "value" + "-of-a-pass" + "word", "value-of-a-reference"
    key = "customer_ref" if extra else "password"
    field = '{"' + key + '":"' + (kept if extra else secret) + '"}'
    arguments = '{"items":[1,' + field + "]}" if in_a_list else field
    raw = (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":' + arguments
        + ',"deep":' + _nested(MAX_RECORDED_DEPTH) + "}}"
    ).encode()  # fmt: skip
    message = _recorded(
        tmp_path, "message", Masker(extra), direction=Direction.CLIENT_TO_SERVER, raw=raw
    )
    assert message["parse"]["error_reason"] == "too_deep"
    assert message["payload"]["data"] == TOO_DEEP_TO_RECORD
    written = (tmp_path / "events.jsonl").read_text()
    assert secret not in written
    assert kept not in written


def test_a_message_at_the_recorded_depth_reads_back_on_every_version(tmp_path):
    raw = _nested(MAX_RECORDED_DEPTH).encode()
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="limits", masker=Masker()) as recorder:
        recorder.message(1, 0, direction=Direction.SERVER_TO_CLIENT, raw=raw)
    events, problems = verdict.read_events(path.read_bytes())
    assert problems == []
    assert events[-1]["payload"]["data"] == _deep(MAX_RECORDED_DEPTH)


@pytest.mark.parametrize("depth", [MAX_RECORDED_DEPTH + 1, 3_000])
def test_a_changed_value_too_deep_to_mask_is_recorded_as_a_note(tmp_path, depth):
    deep = {"password": "a", "inner": {"token": "b"}, "deep": _deep(depth - 1)}
    change = type("Change", (), {"path": "result.x", "before": deep, "after": 2})()
    step = type(
        "Step", (), {"rule": "r", "action": "set", "reason": "", "changes": [change], "skipped": []}
    )()
    event = _recorded(
        tmp_path,
        "intervention",
        action="replace",
        direction=Direction.SERVER_TO_CLIENT,
        message_id=1,
        original={"result": {"x": 1}},
        replacement={"result": {"x": 2}},
        steps=[step],
    )
    (recorded,) = event["steps"][0]["changes"]
    assert recorded["before"]["data"] == TOO_DEEP_TO_RECORD
    assert recorded["before"]["redaction_count"] == 2


@pytest.mark.parametrize("depth", [MAX_RECORDED_DEPTH, MAX_RECORDED_DEPTH + 1, 5_000])
def test_an_intervention_too_deep_to_mask_is_recorded_as_a_note(tmp_path, depth):
    event = _recorded(
        tmp_path,
        "intervention",
        action="replace",
        direction=Direction.SERVER_TO_CLIENT,
        message_id=1,
        original=_deep(depth),
        replacement=None,
    )
    if depth > MAX_RECORDED_DEPTH:
        assert event["original"]["data"] == TOO_DEEP_TO_RECORD
    else:
        assert event["original"]["data"] == _deep(depth)


@pytest.mark.parametrize("truncated", [True, False])
def test_server_stderr_says_whether_it_was_cut(tmp_path, truncated):
    event = _recorded(tmp_path, "server_stderr", raw=b"", size_bytes=99, truncated=truncated)
    assert event["truncated"] is truncated


def test_the_proxy_passes_on_that_a_stderr_line_was_over_the_limit():
    offered: list = []
    sink = type("Sink", (), {"offer": lambda self, emit, kind: offered.append(emit)})()
    recorder = type("Recorder", (), {"server_stderr": lambda self, *a, **k: None})()
    observer = Observer(sink=sink, recorder=recorder, direction=None, max_message_bytes=16)
    observer.observe(b"x" * 40 + b"\nshort\n")
    assert [emit.keywords["truncated"] for emit in offered] == [True, False]
    assert [emit.keywords["size_bytes"] for emit in offered] == [40, 5]


# -- inspecting a message ------------------------------------------------------------------


#: The innermost node of a schema: invisible text, an observation if it is reached.
INNERMOST = '{"description":"x\\u200by"}'


def _listing(depth: int, through_lists: bool = False, innermost: str = INNERMOST) -> bytes:
    """A listing whose schema puts ``innermost`` ``depth`` objects or lists down.

    Written as text, as a server would send it: json.dumps would need recursion that 3.10 and
    3.11 do not have at these depths.
    """
    if through_lists:  # anyOf: [[[ … ]]], one level per list
        schema = '{"type":"object","anyOf":' + "[" * (depth - 1) + innermost
        schema += "]" * (depth - 1) + "}"
    else:  # items: {items: { … }}, one level per object
        schema = '{"type":"object","items":' + '{"items":' * (depth - 1) + innermost
        schema += "}" * depth
    tool = '{"name":"t","description":"d","inputSchema":' + schema + "}"
    return ('{"jsonrpc":"2.0","id":1,"result":{"tools":[' + tool + "]}}").encode()


def _look(depth: int, through_lists: bool = False, innermost: str = INNERMOST):
    inspector = Inspector()
    inspector.learn({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    return inspector.look(Direction.SERVER_TO_CLIENT, _listing(depth, through_lists, innermost))


def test_the_listing_is_built_as_the_schema_it_stands_for():
    schema = json.loads(_listing(3))["result"]["tools"][0]["inputSchema"]
    assert schema == {"type": "object", "items": {"items": {"items": {"description": "x\u200by"}}}}
    schema = json.loads(_listing(3, through_lists=True))["result"]["tools"][0]["inputSchema"]
    assert schema == {"type": "object", "anyOf": [[{"description": "x\u200by"}]]}


def test_a_schema_within_the_depth_is_walked_to_the_bottom():
    look = _look(MAX_SCHEMA_DEPTH)
    assert look.observations
    assert not look.bounded


@pytest.mark.parametrize("depth", [MAX_SCHEMA_DEPTH + 1, 5_000])
def test_a_schema_past_the_depth_is_counted_as_bounded_and_the_observer_goes_on(depth):
    look = _look(depth)
    assert look.bounded
    assert not look.observations


@pytest.mark.parametrize(
    "innermost",
    ['{"type":"string","description":"x\\u200by"}', '{"description":"x\\u200by","type":"string"}'],
    ids=["type first", "description first"],
)  # fmt: skip
def test_a_scalar_beside_the_description_is_no_level_of_its_own(innermost):
    look = _look(MAX_SCHEMA_DEPTH, innermost=innermost)
    assert look.observations
    assert not look.bounded


def test_a_listing_too_deep_to_parse_is_counted_as_bounded():
    """Deeper than json.loads goes on any version: nothing inspected, and that is counted."""
    inspector = Inspector()
    inspector.learn({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    look = inspector.look(Direction.SERVER_TO_CLIENT, _listing(100_000))
    assert look.bounded
    assert inspector.bounded_messages == 1
    # From the client it is not inspected in the first place, so nothing is missing.
    assert not inspector.look(Direction.CLIENT_TO_SERVER, _listing(100_000)).bounded
    assert inspector.bounded_messages == 1
    # Nor does it matter that it is no object, whose top level could be read.
    assert inspector.look(Direction.SERVER_TO_CLIENT, _nested(100_000).encode()).bounded
    assert inspector.bounded_messages == 2


@pytest.mark.parametrize("depth", [MAX_INSPECTED_DEPTH, MAX_INSPECTED_DEPTH + 1])
def test_how_deep_a_message_is_inspected_at_all_is_a_fixed_depth(depth):
    """The same on every Python version, whatever the message: here one the walk would not
    even look into."""
    inspector = Inspector()
    raw = ('{"jsonrpc":"2.0","method":"notifications/message","params":'
           + _nested(depth - 1) + "}").encode()  # fmt: skip
    assert inspector.look(Direction.SERVER_TO_CLIENT, raw).bounded is (depth > MAX_INSPECTED_DEPTH)


def test_a_deep_schema_still_leaves_the_rest_of_the_listing_inspected():
    """Deeper than the schema walk, not deeper than inspection: the tool's own description is
    still looked at, and the schema is counted as bounded."""
    tool = ('{"name":"t","description":"x\\u200by","inputSchema":{"type":"object","items":'
            + '{"items":' * 399 + "{}" + "}" * 400 + "}")  # fmt: skip
    raw = ('{"jsonrpc":"2.0","id":1,"result":{"tools":[' + tool + "]}}").encode()
    inspector = Inspector()
    inspector.learn({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    look = inspector.look(Direction.SERVER_TO_CLIENT, raw)
    assert look.bounded
    assert [observation.path for observation in look.observations] == [
        "result.tools[0].description"
    ]


@pytest.mark.parametrize("depth", [MAX_SCHEMA_DEPTH, MAX_SCHEMA_DEPTH + 1, 5_000])
def test_lists_count_as_levels_of_a_schema_too(depth):
    look = _look(depth, through_lists=True)
    assert look.bounded is (depth > MAX_SCHEMA_DEPTH)
    assert bool(look.observations) is (depth <= MAX_SCHEMA_DEPTH)


# -- the scenario engine -------------------------------------------------------------------


class _Seen:
    """A rule that only counts the messages it was shown."""

    name = "seen"

    def __init__(self) -> None:
        self.shown = 0

    def act(self, direction, document, responded_method) -> None:
        self.shown += 1  # and asks for nothing: None leaves the message as it is


@pytest.mark.parametrize(
    ("depth", "shown"),
    [(events.MAX_DOCUMENT_DEPTH, 1), (events.MAX_DOCUMENT_DEPTH + 1, 0), (100_000, 0)],
)
def test_a_message_too_deep_for_the_rules_passes_the_engine_untouched(depth, shown):
    """Not a stopped engine, and not a rule blamed for the server's nesting."""
    rule = _Seen()
    engine = Engine([rule])
    raw = _nested(depth).encode()
    engine.observe(Direction.CLIENT_TO_SERVER, raw)
    assert engine.decide(Direction.SERVER_TO_CLIENT, raw).action is Action.FORWARD
    assert rule.shown == shown


class _Answered:
    """A rule that notes which request each message it was shown answers."""

    name = "answered"

    def __init__(self) -> None:
        self.responded: list[str | None] = []

    def act(self, direction, document, responded_method) -> None:
        self.responded.append(responded_method)


def _deep_request(depth: int) -> bytes:
    return ('{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"deep":'
            + _nested(depth - 2) + "}}").encode()  # fmt: skip


@pytest.mark.parametrize("depth", [events.MAX_DOCUMENT_DEPTH + 1, 600, 2_000, 100_000])
@pytest.mark.parametrize("seen_by", ["observe", "decide"])
def test_a_request_too_deep_for_the_rules_still_names_the_method_of_its_answer(depth, seen_by):
    """Its id is learned from the top level: a flat answer to it is not left without its
    method, whether the engine only observes requests or decides on them too."""
    rule = _Answered()
    engine = Engine([rule])
    getattr(engine, seen_by)(Direction.CLIENT_TO_SERVER, _deep_request(depth))
    answer = b'{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}'
    assert engine.decide(Direction.SERVER_TO_CLIENT, answer).action is Action.FORWARD
    assert rule.responded[-1] == "tools/list"


@pytest.mark.parametrize("depth", [2_000, 100_000])
@pytest.mark.parametrize(
    ("how", "learned"), [("wrong bracket", None), ("not a value inside", "tools/list")]
)
def test_what_is_learned_from_a_deep_request_that_is_no_json_is_the_same_on_every_version(
    depth, how, learned
):
    request = ('{"jsonrpc":"2.0","id":7,"method":"tools/list","params":'
               + _broken(depth - 1, how) + "}").encode()  # fmt: skip
    rule = _Answered()
    engine = Engine([rule])
    engine.observe(Direction.CLIENT_TO_SERVER, request)
    engine.decide(Direction.SERVER_TO_CLIENT, b'{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}')
    assert rule.responded[-1] == learned
    inspector = Inspector()
    inspector.look(Direction.CLIENT_TO_SERVER, request)
    assert inspector.look(Direction.SERVER_TO_CLIENT, request).bounded is (learned is not None)


@pytest.mark.parametrize("depth", [MAX_INSPECTED_DEPTH, 600, 2_000, 100_000])
def test_a_request_too_deep_to_inspect_still_has_its_answer_inspected(depth):
    inspector = Inspector()
    assert not inspector.look(Direction.CLIENT_TO_SERVER, _deep_request(depth)).bounded
    answer = (b'{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"t",'
              b'"description":"x\\u200by","inputSchema":{"type":"object"}}]}}')  # fmt: skip
    look = inspector.look(Direction.SERVER_TO_CLIENT, answer)
    assert not look.bounded
    assert [observation.path for observation in look.observations] == [
        "result.tools[0].description"
    ]


# -- the command line ----------------------------------------------------------------------


def test_a_small_message_limit_does_not_shrink_what_the_driver_reads(tmp_path):
    """--max-message-bytes below what the driver always read narrows the recording only:
    an answer between the two is still read, and the inventory is complete."""
    assert MIN_LINE_BYTES == 64 * 1024
    out = tmp_path / "runs"
    command = [sys.executable, SERVER, "--tool-description", "d" * 10_000]
    code = cli.main(["drive", "--out-dir", str(out), "--max-message-bytes", "4096", "--", *command])
    assert code == 0
    (path,) = list(out.glob("*/events.jsonl"))
    recorded = [json.loads(line) for line in path.read_text().splitlines()]
    assert not [event for event in recorded if event["type"] == "step_unanswered"]
    cut = [event for event in recorded if event["type"] == "message" and event["truncated"]]
    assert [event["size_bytes"] > 10_000 for event in cut] == [True]  # recorded cut, read whole
