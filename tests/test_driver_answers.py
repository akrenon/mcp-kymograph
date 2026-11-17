"""Only a message without ``method`` is the answer to the driver's request.

Ids are per sender: a request or notification of the server's own may carry the very id the
driver is waiting on. Taken as the answer, it ended the step with nothing listed and left the
inventory complete. Held here on a rebuilt wire, so the order of the server's lines is exact.
"""

import asyncio
import json

import pytest

from mcp_kymograph import events
from mcp_kymograph.driver import (
    DISCOVERY,
    INVENTORY_COMPLETE,
    INVENTORY_PARTIAL,
    NO_ANSWER,
    UNREADABLE,
    Driver,
)

HELLO = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "s", "version": "1"},
    },
}
SERVER_REQUEST = {"jsonrpc": "2.0", "id": 2, "method": "sampling/createMessage", "params": {}}
REAL = {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "echo", "inputSchema": {}}]}}


class Wire:
    def __init__(self, lines):
        self.lines = list(lines)
        self.sent = []

    async def open(self):
        pass

    async def send(self, line):
        self.sent.append(json.loads(line))

    async def read_line(self, timeout):
        if self.lines:
            line = self.lines.pop(0)
            return line if isinstance(line, bytes) else json.dumps(line).encode()
        await asyncio.sleep(timeout)
        raise asyncio.TimeoutError

    def close_write(self):
        pass


def too_deep(**members):
    """A message nested past the read limit, with the given members at its top level."""
    depth = events.MAX_READ_DEPTH + 1
    head = json.dumps({"jsonrpc": "2.0", **members})[:-1]
    return (head + ', "params": ' + "[" * depth + "]" * depth + "}").encode()


def drive(*lines):
    """The outcome, and what was recorded as finished, of a run against these lines."""
    outcome, finished, _ = drive_on(*lines)
    return outcome, finished


def drive_on(*lines):
    """:func:`drive`, and the lines the driver left unread."""
    finished = []

    async def rec(**fields):
        finished.append(fields)

    async def ignore(**fields):
        pass

    wire = Wire([HELLO, *lines])
    driver = Driver(
        DISCOVERY,
        wire,
        record_skipped=ignore,
        record_unanswered=ignore,
        record_finished=rec,
        step_timeout=0.05,
    )
    outcome = asyncio.run(driver.run())
    return outcome, finished[-1], wire.lines


def test_a_server_request_with_the_id_of_the_open_request_is_no_answer():
    outcome, finished = drive(SERVER_REQUEST)
    assert outcome.unanswered == (("tools/list", 0, NO_ANSWER, ""),)
    assert outcome.inventory == INVENTORY_PARTIAL
    assert finished["unanswered"] == (("tools/list", 0, NO_ANSWER),)


def test_the_same_as_when_the_server_sends_nothing_after_the_handshake():
    assert drive()[0].unanswered == drive(SERVER_REQUEST)[0].unanswered
    assert drive()[0].inventory == drive(SERVER_REQUEST)[0].inventory


def test_the_real_answer_after_the_server_request_answers_the_step():
    # The real answer was read, not left on the wire: taking the request as the answer ends
    # the step just as "complete", but before the tools were ever listed.
    outcome, finished, unread = drive_on(SERVER_REQUEST, REAL)
    assert unread == []
    assert outcome.unanswered == ()
    assert outcome.inventory == INVENTORY_COMPLETE
    assert finished["unanswered"] == ()
    assert "tools/list" in outcome.sent


@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "2.0", "id": 2, "method": "notifications/x"},
        {"jsonrpc": "2.0", "id": 2, "method": "notifications/x", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "result": {"tools": []}},
    ],
    ids=["notification with id", "notification with id and params", "method and result"],
)
def test_a_message_with_method_is_no_answer_whatever_else_it_carries(message):
    outcome, _ = drive(message)
    assert outcome.unanswered == (("tools/list", 0, NO_ANSWER, ""),)
    assert outcome.inventory == INVENTORY_PARTIAL
    outcome, _, unread = drive_on(message, REAL)
    assert unread == []
    assert outcome.unanswered == ()
    assert outcome.inventory == INVENTORY_COMPLETE


def test_a_too_deep_message_with_method_is_read_past_like_any_other():
    # Not the answer: the step goes on to the real one, which answers it in full.
    outcome, _, unread = drive_on(too_deep(id=2, method="sampling/createMessage"), REAL)
    assert unread == []
    assert outcome.unanswered == ()
    assert outcome.inventory == INVENTORY_COMPLETE


def test_a_too_deep_message_with_method_and_no_real_answer_leaves_the_step_unanswered():
    # It is read past, and its top level says it is a request of the server's own: the answer
    # was not among it, so the step is unanswered (``no_answer``), not unreadable.
    outcome, _ = drive(too_deep(id=2, method="sampling/createMessage"))
    assert outcome.unanswered == (("tools/list", 0, NO_ANSWER, ""),)
    assert outcome.inventory == INVENTORY_PARTIAL


def test_a_too_deep_message_without_method_is_the_unreadable_answer_as_before():
    # Its id is read from the top level: it is the answer, and the step ends there. The
    # real answer after it is never waited for.
    outcome, _, unread = drive_on(too_deep(id=2, result=None), REAL)
    assert unread == [REAL]
    assert outcome.unanswered == (("tools/list", 0, UNREADABLE, ""),)
    assert outcome.inventory == INVENTORY_PARTIAL


@pytest.mark.parametrize(
    "members",
    [{"id": 7, "method": "notifications/x"}, {"method": "notifications/x"}],
    ids=["another id", "no id"],
)
def test_any_too_deep_message_with_method_is_read_past_without_making_the_answer_unreadable(
    members,
):
    # Whatever its id: a top level that names a method is a request or notification of the
    # server's own, so the answer was not among it. The line itself is still in the recording.
    outcome, _, unread = drive_on(too_deep(**members))
    assert outcome.unanswered == (("tools/list", 0, NO_ANSWER, ""),)
    outcome, _, unread = drive_on(too_deep(**members), REAL)
    assert unread == []
    assert outcome.unanswered == ()


def test_an_answer_with_the_id_true_is_no_answer_to_request_one():
    # In Python True == 1; no client takes true for 1 (both SDKs refuse a boolean id). The
    # handshake waits for the real answer and, without one, does not complete.
    hello_true = {**HELLO, "id": True}
    finished = []

    async def rec(**fields):
        finished.append(fields)

    outcome = asyncio.run(
        Driver(
            DISCOVERY,
            Wire([hello_true]),
            record_skipped=rec,
            record_unanswered=rec,
            record_finished=rec,
            step_timeout=0.05,
        ).run()
    )
    assert outcome.server_failed == NO_ANSWER
    assert "tools/list" not in outcome.sent
