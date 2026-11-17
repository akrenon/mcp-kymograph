"""A partial inventory is an incomplete run — never a complete one with nothing found.

The discovery script is the inventory: what the server offers. A server that stops answering,
or dies, halfway through it leaves a recording of part of that inventory, and a store that
filed it as complete would compare a fraction of a server against all of it — the most
dangerous form of a false green. Each way an inventory can fall short is held here: a step
left unanswered, a page left unanswered, a server that dies, a script cut off before it could
say how it ended. And the one way it is short and still complete: the page limit, which is a
recorded cap.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, verdict
from mcp_kymograph.driver import (
    CLOSED,
    CURSOR_INVALID,
    INVENTORY_CAPPED,
    INVENTORY_COMPLETE,
    INVENTORY_PARTIAL,
    MAX_PAGES,
    NO_ANSWER,
    PAGE_LIMIT,
)
from mcp_kymograph.proxy import Proxy
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
SERVER = FIXTURES / "discovery_server.py"
POISON = FIXTURES / "corpus" / "poison_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"


def drive(tmp_path, *server_args, timeout="2.0", extra=()):
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), "--step-timeout", timeout, *extra, "--",
         sys.executable, str(SERVER), *server_args]
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def test_a_full_inventory_is_complete_and_says_how_it_ended(tmp_path):
    code, path, events = drive(tmp_path, "--offers", "tools,prompts")
    assert code == 0
    (end,) = of(events, "script_finished")
    assert end["inventory"] == INVENTORY_COMPLETE
    assert end["unanswered"] == []
    assert verdict.read(path).state == verdict.COMPLETE


def test_a_server_that_dies_mid_inventory_leaves_an_incomplete_run(tmp_path):
    """It answers the handshake and dies on the first listing. The listing is unanswered
    because its side closed, every later step says it was not sent for that reason, and the
    run is incomplete — exit 3, never a complete run of a server that offers nothing."""
    code, path, events = drive(tmp_path, "--offers", "tools,resources", "--exit-after", "0")
    assert code == cli.EXIT_INCOMPLETE
    assert [(e["step"], e["pages"], e["reason"]) for e in of(events, "step_unanswered")] == [
        ("tools/list", 0, CLOSED)
    ]
    assert [(e["step"], e["reason"]) for e in of(events, "step_skipped")] == [
        ("resources/list", CLOSED),
        ("resources/templates/list", CLOSED),
        ("prompts/list", CLOSED),  # the script stopped; it says why for every step left
    ]
    (end,) = of(events, "script_finished")
    assert end["inventory"] == INVENTORY_PARTIAL
    assert not of(events, "server_failed"), "the handshake held: partial, not failed"
    judged = verdict.read(path)
    assert judged.state == verdict.INCOMPLETE
    assert any("tools/list unanswered after 0 page(s)" in p for p in judged.problems)


def test_a_page_left_unanswered_is_a_partial_listing(tmp_path):
    """Page one came, page two did not: the step says how many pages it got."""
    code, _, events = drive(tmp_path, "--pages", "3", "--answer-limit", "1")
    assert code == cli.EXIT_INCOMPLETE
    assert [(e["step"], e["pages"], e["reason"]) for e in of(events, "step_unanswered")] == [
        ("tools/list", 1, NO_ANSWER)
    ]


def test_the_page_limit_is_a_recorded_cap_and_the_run_stays_complete(tmp_path):
    """Analogous to path_not_found: what was cut and why is known. Exit 0, the cut recorded
    as a truncation beside the state, the script's end says capped."""
    code, path, events = drive(tmp_path, "--pages", str(MAX_PAGES + 5))
    assert code == 0
    assert [(e["step"], e["reason"]) for e in of(events, "step_skipped")] == [
        ("tools/list", PAGE_LIMIT),
        ("resources/list", "capability_not_offered"),
        ("resources/templates/list", "capability_not_offered"),
        ("prompts/list", "capability_not_offered"),
    ]
    (end,) = of(events, "script_finished")
    assert end["inventory"] == INVENTORY_CAPPED
    judged = verdict.read(path)
    assert judged.state == verdict.COMPLETE
    assert judged.truncations == [
        {"kind": "page_limit", "step": "tools/list", "pages": str(MAX_PAGES)}
    ]


def test_a_driven_run_without_the_script_s_end_is_incomplete():
    """The positive marker: a script cut off writes nothing, so its absence is the gap."""
    events = [
        {"type": "run_started", "mode": "driver", "isolation": "host"},
        {
            "type": "run_finished",
            "findings_by_statement": {},
            "server_output_bytes": 100,
            "client_input_bytes": 100,
            "server_exited_first": False,
        },
    ]
    judged = verdict.assess(events)
    assert judged.state == verdict.INCOMPLETE
    assert any("no script_finished" in p for p in judged.problems)
    # A proxied run has no script, and is not asked for one.
    events[0]["mode"] = "proxy"
    assert verdict.assess(events).state == verdict.COMPLETE


def test_the_script_s_end_is_written_before_the_closing_event_even_when_it_is_slow(
    tmp_path, monkeypatch
):
    """The server dies, so the run ends under the script. The driver learns it from its
    channel and writes how the script ended — here, on purpose, slower than the tail the
    proxy waits for its server's last words. The closing event waits for it: the end is in
    the recording, before run_finished, and the run is incomplete for the step it lost, not
    for a missing end."""
    original = Proxy.record_script_finished

    async def slow(self, **summary):
        await asyncio.sleep(1.5)
        await original(self, **summary)

    monkeypatch.setattr(Proxy, "record_script_finished", slow)
    code, path, events = drive(tmp_path, "--exit-after", "0")
    assert code == cli.EXIT_INCOMPLETE
    kinds = [e["type"] for e in events]
    assert kinds.index("script_finished") < kinds.index("run_finished") == len(kinds) - 1
    problems = verdict.read(path).problems
    assert not any("no script_finished" in p for p in problems), problems
    assert any("tools/list unanswered" in p for p in problems), problems


@pytest.mark.parametrize(("settle", "writing", "expired"), [("3", 1.0, False), ("0.5", 2.0, True)])
def test_the_wait_for_the_script_s_end_is_configurable_and_recorded_when_it_runs_out(
    tmp_path, monkeypatch, capsys, settle, writing, expired
):
    """Both sides of the wait. A driver that writes its end within it: the end is in the
    recording, and nothing else is. One that does not: the closing event goes on without it,
    the recording says the wait ran out, and the run is incomplete for that reason — named."""
    original = Proxy.record_script_finished

    async def slow(self, **summary):
        await asyncio.sleep(writing)
        await original(self, **summary)

    monkeypatch.setattr(Proxy, "record_script_finished", slow)
    code, path, events = drive(
        tmp_path, "--exit-after", "0", extra=("--client-settle-timeout", settle)
    )
    assert code == cli.EXIT_INCOMPLETE
    assert events[0]["limits"]["client_settle_seconds"] == float(settle)
    ran_out = [e for e in of(events, "limit_exceeded") if e["limit"] == "client_settle_seconds"]
    problems = verdict.read(path).problems
    if expired:
        assert [(e["value"], e["unit"]) for e in ran_out] == [(0.5, "seconds")]
        assert not of(events, "script_finished")
        assert any(
            "no script_finished" in p and "stopped waiting for it after 0.5 s" in p
            for p in problems
        ), problems
        assert "the driver had not settled after 0.5 s" in capsys.readouterr().err
    else:
        assert ran_out == []
        assert of(events, "script_finished")
        assert not any("no script_finished" in p for p in problems), problems


def test_the_wait_defaults_to_five_seconds_and_is_in_the_run_s_limits(tmp_path):
    _, _, events = drive(tmp_path)
    assert events[0]["limits"]["client_settle_seconds"] == 5.0


@pytest.mark.parametrize(
    ("server_args", "fragment"),
    [
        (("--silent-after-handshake",), "step tools/list unanswered after 0 page(s) (no_answer)"),
        (("--exit-after", "0"), "step tools/list unanswered after 0 page(s) (connection_closed)"),
    ],
)
def test_the_store_files_a_partial_inventory_as_incomplete_with_the_reason(
    tmp_path, server_args, fragment
):
    """End to end through the manifest: the poison entry, made to fall silent or die after
    its handshake. Filed as incomplete, with the step that was lost — never as complete with
    zero of four findings."""
    manifest = tmp_path / "manifest.json"

    def rel(path: Path) -> str:
        return os.path.relpath(path, tmp_path)

    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "poison-server",
                        "provenance": "poison",
                        "source": {"paths": [rel(POISON), rel(SERVER)]},
                        "launch": {
                            "transport": "stdio",
                            "command": ["{python}", str(POISON), *server_args],
                        },
                        "scenarios": [rel(ALL_SIGNALS)],
                    }
                ],
            }
        )
    )
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), "--step-timeout", "2.0", "--manifest",
         str(manifest), "--entry", "poison-server"]
    )  # fmt: skip
    assert code == cli.EXIT_INCOMPLETE
    (recording,) = out.glob("*/events.jsonl")
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(recording)
        assert filed.state == verdict.INCOMPLETE
        assert filed.findings == 0
        assert any(fragment in problem for problem in filed.problems), filed.problems
        (run,) = store.runs()
        assert run.state == verdict.INCOMPLETE and not run.complete


@pytest.mark.parametrize("reason", ["no_answer", "connection_closed", "driver_error"])
def test_a_step_not_sent_for_a_reason_that_leaves_the_inventory_short_is_a_gap(reason):
    """Each reason on its own, with nothing else wrong: the run is incomplete for that step."""
    events = [
        {"type": "run_started", "mode": "driver", "isolation": "host"},
        {"type": "step_skipped", "step": "prompts/list", "reason": reason},
        {"type": "script_finished", "inventory": "partial"},
        {
            "type": "run_finished",
            "findings_by_statement": {},
            "server_output_bytes": 100,
            "client_input_bytes": 100,
            "server_exited_first": False,
        },
    ]
    judged = verdict.assess(events)
    assert judged.state == verdict.INCOMPLETE
    assert judged.problems == [f"step prompts/list not sent ({reason}): the inventory is partial"]
    events[1]["reason"] = "capability_not_offered"
    assert verdict.assess(events).state == verdict.COMPLETE


class _BrokenSend:
    """A client channel whose server side is gone the moment the first listing is sent:
    the handshake is answered, then sending fails — the other way a connection can close,
    on the write rather than on the read."""

    def __init__(self) -> None:
        self.lines: list[bytes] = []

    async def open(self) -> None:
        return None

    async def send(self, line: bytes) -> None:
        if b'"tools/list"' in line:
            raise BrokenPipeError("the server's side is gone")
        self.lines.append(line)

    async def read_line(self, timeout: float) -> bytes | None:
        sent = json.loads(self.lines[-1])
        answer = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "prompts": {}}}
        return json.dumps({"jsonrpc": "2.0", "id": sent["id"], "result": answer}).encode()

    def close_write(self) -> None:
        return None


def test_a_step_whose_sending_fails_is_unanswered_because_the_connection_closed():
    from mcp_kymograph.driver import DISCOVERY, Driver

    written: list[tuple] = []

    async def record(kind, **fields):
        written.append((kind, fields))

    driver = Driver(
        DISCOVERY,
        _BrokenSend(),
        record_skipped=lambda **f: record("skipped", **f),
        record_unanswered=lambda **f: record("unanswered", **f),
        record_finished=lambda **f: record("finished", **f),
    )
    outcome = asyncio.run(driver.run())
    assert outcome.unanswered == (("tools/list", 0, CLOSED, ""),)
    assert ("skipped", {"step": "prompts/list", "reason": CLOSED, "detail": ""}) in written
    assert written[-1][1]["inventory"] == INVENTORY_PARTIAL


class _Cursor:
    """A channel that answers the handshake with tools only, then the first tools/list with
    the given ``nextCursor`` (left out when it is the marker ``MISSING``). Any later page has
    none, so a cursor the driver does follow ends the listing on the second page."""

    MISSING = object()

    def __init__(self, cursor) -> None:
        self.cursor = cursor
        self.lines: list[bytes] = []
        self.listings = 0

    async def open(self) -> None:
        return None

    async def send(self, line: bytes) -> None:
        self.lines.append(line)

    async def read_line(self, timeout: float) -> bytes | None:
        sent = json.loads(self.lines[-1])
        if sent["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "prompts": {}}}
        else:
            result = {"tools": [{"name": "a"}]}
            if sent["method"] == "tools/list":
                if self.listings == 0 and self.cursor is not self.MISSING:
                    result["nextCursor"] = self.cursor
                self.listings += 1
        return json.dumps({"jsonrpc": "2.0", "id": sent["id"], "result": result}).encode()

    def close_write(self) -> None:
        return None


def _drive_cursor(cursor):
    from mcp_kymograph.driver import DISCOVERY, Driver

    written: list[tuple] = []

    async def record(kind, **fields):
        written.append((kind, fields))

    channel = _Cursor(cursor)
    driver = Driver(
        DISCOVERY,
        channel,
        record_skipped=lambda **f: record("skipped", **f),
        record_unanswered=lambda **f: record("unanswered", **f),
        record_finished=lambda **f: record("finished", **f),
    )
    return asyncio.run(driver.run()), written, channel


@pytest.mark.parametrize("cursor", [123, True, False, {}, [], 1.5, 0])
def test_a_next_cursor_that_is_not_a_string_is_a_named_stop(cursor):
    """``"nextCursor": 123`` used to end the list as if it were whole."""
    outcome, written, channel = _drive_cursor(cursor)
    assert outcome.unanswered == (("tools/list", 1, CURSOR_INVALID, ""),)
    assert outcome.inventory == INVENTORY_PARTIAL
    assert channel.listings == 1, "nothing was sent back as a cursor"
    assert (
        "unanswered",
        {"step": "tools/list", "pages": 1, "reason": CURSOR_INVALID, "detail": ""},
    ) in written
    # An answer came: the script goes on with its next step rather than skipping the rest.
    assert "prompts/list" in outcome.sent
    assert not any(f["reason"] == CURSOR_INVALID for k, f in written if k == "skipped")


@pytest.mark.parametrize(("cursor", "listings"), [(None, 1), (_Cursor.MISSING, 1), ("", 2)])
def test_a_null_or_absent_cursor_ends_the_list_and_an_empty_string_is_still_a_cursor(
    cursor, listings
):
    """Unchanged: null and absent end the list. An empty string is a string, so it is sent
    back as the cursor and the listing goes on to the next page."""
    outcome, _, channel = _drive_cursor(cursor)
    assert outcome.unanswered == ()
    assert outcome.inventory == INVENTORY_COMPLETE
    assert channel.listings == listings


def test_an_invalid_cursor_is_recorded_and_the_run_is_incomplete(tmp_path):
    """The recording has the step_unanswered event with the reason, and the verdict reads
    it as a gap."""
    events = [
        {"type": "run_started", "mode": "driver", "isolation": "host"},
        {"type": "step_unanswered", "step": "tools/list", "pages": 1, "reason": CURSOR_INVALID},
        {"type": "script_finished", "inventory": INVENTORY_PARTIAL},
        {
            "type": "run_finished",
            "findings_by_statement": {},
            "server_output_bytes": 100,
            "client_input_bytes": 100,
            "server_exited_first": False,
        },
    ]
    judged = verdict.assess(events)
    assert judged.state == verdict.INCOMPLETE
    assert any(
        "tools/list unanswered after 1 page(s) (cursor_invalid)" in p for p in judged.problems
    )
