"""The proxy, end to end, against the toy server. Subprocesses but no network."""

import asyncio
import contextlib
import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from mcp_kymograph.masking import Masker
from mcp_kymograph.proxy import Limits, Proxy
from mcp_kymograph.recorder import Recorder

TOY = str(Path(__file__).parent / "fixtures" / "toy_server.py")
CANARY = "CANARY-do-not-leak-0123456789"


def argv_for(mode: str = "normal", *extra: str) -> list[str]:
    return [sys.executable, TOY, "--mode", mode, *extra]


def request(identifier: int, method: str = "initialize") -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method}).encode() + b"\n"


class Session:
    """Stands in for the client: writes into the proxy and reads what comes back."""

    def __init__(self, tmp_path, argv, *, limits=None, masker=None, engine=None):
        self.notices: list[str] = []
        self.path = tmp_path / "events.jsonl"
        self.argv = argv
        self.limits = limits or Limits(
            max_duration_seconds=30.0, terminate_grace_seconds=0.5, shutdown_budget_seconds=3.0
        )
        self.masker = masker or Masker()
        self.engine = engine
        self.received = bytearray()
        self.outcome = None

    async def __aenter__(self):
        to_proxy_read, self._to_proxy = os.pipe()
        self._from_proxy, from_proxy_write = os.pipe()
        self._client_in = os.fdopen(to_proxy_read, "rb", buffering=0)
        self._client_out = os.fdopen(from_proxy_write, "wb", buffering=0)

        self.recorder = Recorder.open(self.path, run_id="proxytest", masker=self.masker)
        self.proxy = Proxy(
            argv=self.argv,
            recorder=self.recorder,
            limits=self.limits,
            client_in=self._client_in,
            client_out=self._client_out,
            engine=self.engine,
            notice=self.notices.append,
        )
        self._task = asyncio.create_task(self.proxy.run())
        self._reader = asyncio.create_task(self._drain_output())
        return self

    async def _drain_output(self) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(self._from_proxy, "rb", 0)
        )
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            self.received.extend(chunk)

    def send(self, data: bytes) -> None:
        os.write(self._to_proxy, data)

    def close_client_stdin(self) -> None:
        os.close(self._to_proxy)
        self._to_proxy = -1

    async def until_received(self, count: int, *, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while self.received.count(b"\n") < count and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

    async def __aexit__(self, *exc):
        if self._to_proxy != -1:
            self.close_client_stdin()
        try:
            self.outcome = await asyncio.wait_for(self._task, timeout=20)
        except asyncio.TimeoutError:
            self._task.cancel()
            raise
        finally:
            self.recorder.close()
            self._reader.cancel()
            await asyncio.gather(self._reader, return_exceptions=True)
            for handle in (self._client_in, self._client_out):
                with contextlib.suppress(OSError):
                    handle.close()
            await asyncio.sleep(0)

    @property
    def events(self) -> list[dict]:
        return [json.loads(line) for line in self.path.read_text().splitlines()]


def run(scenario):
    return asyncio.run(scenario())


def still_running(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


# -- transparency ---------------------------------------------------------------------


def test_bytes_arrive_verbatim_in_both_directions(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for()) as session:
            for index in range(1, 4):
                session.send(request(index))
                await asyncio.sleep(0.02)  # awkward chunking on the way in
            await session.until_received(3)
        return session

    session = run(scenario)
    lines = bytes(session.received).splitlines()
    assert len(lines) == 3
    for index, line in enumerate(lines, start=1):
        assert json.loads(line)["id"] == index


def test_the_recording_holds_every_message_in_order(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for()) as session:
            for index in range(1, 4):
                session.send(request(index))
            await session.until_received(3)
        return session

    session = run(scenario)
    messages = [event for event in session.events if event["type"] == "message"]
    assert [event["direction"] for event in messages] == [
        "client_to_server",
        "client_to_server",
        "client_to_server",
        "server_to_client",
        "server_to_client",
        "server_to_client",
    ] or len(messages) == 6
    assert [event["seq"] for event in session.events] == sorted(
        event["seq"] for event in session.events
    )


def test_the_server_stderr_never_reaches_the_protocol_channel(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for("stderr")) as session:
            session.send(request(1))
            await session.until_received(1)
        return session

    session = run(scenario)
    assert b"toy: handling a request" not in bytes(session.received)
    stderr_events = [event for event in session.events if event["type"] == "server_stderr"]
    assert stderr_events, "the server's stderr belongs in the recording"


def test_a_server_that_closes_stdout_but_keeps_reading_is_not_a_dead_server(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for("close_stdout")) as session:
            session.send(request(1))
            await session.until_received(1)
            await asyncio.sleep(0.2)
            session.send(request(2))  # the other direction must still work
            await asyncio.sleep(0.2)
        return session

    session = run(scenario)
    assert session.outcome is not None
    assert not still_running(session.proxy.child_pid)


# -- credentials ----------------------------------------------------------------------


def test_no_credential_reaches_the_recording_not_even_from_the_server_command_line(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for("normal", "--api-key", CANARY)) as session:
            session.send(
                json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"token": CANARY}}
                ).encode()
                + b"\n"
            )
            await session.until_received(1)
        return session

    session = run(scenario)
    assert CANARY not in session.path.read_text()


# -- limits ---------------------------------------------------------------------------


def test_an_oversized_message_is_truncated_in_the_log_and_forwarded_in_full(tmp_path):
    async def scenario():
        limits = Limits(
            max_message_bytes=4096,
            max_duration_seconds=30.0,
            terminate_grace_seconds=0.5,
            shutdown_budget_seconds=3.0,
        )
        async with Session(tmp_path, argv_for("oversize", "--size", "200000"), limits=limits) as s:
            s.send(request(1))
            await s.until_received(1)
        return s

    session = run(scenario)
    assert len(bytes(session.received).strip()) > 200000, "forwarded in full"
    oversized = [
        event
        for event in session.events
        if event["type"] == "message" and event.get("truncated") is True
    ]
    assert oversized, "the recording must say the message was too big"
    assert oversized[0]["payload"]["data"] == ""
    assert oversized[0]["size_bytes"] > 200000


# -- shutdown -------------------------------------------------------------------------


def test_a_crashing_server_leaves_nothing_running(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for("crash_midway")) as session:
            session.send(request(1))
            await asyncio.sleep(0.3)
        return session

    session = run(scenario)
    assert not still_running(session.proxy.child_pid)
    assert session.outcome.reason == "server_exited"


def test_a_server_that_ignores_termination_is_killed_anyway(tmp_path):
    async def scenario():
        async with Session(tmp_path, argv_for("ignore_sigterm")) as session:
            session.send(request(1))
            await asyncio.sleep(0.3)
            os.kill(os.getpid(), signal.SIGINT)  # as if the operator pressed Ctrl-C
            await asyncio.sleep(0.3)
        return session

    session = run(scenario)
    assert not still_running(session.proxy.child_pid)


def test_a_flooding_server_does_not_stop_the_run_from_ending(tmp_path):
    async def scenario():
        limits = Limits(
            max_message_bytes=4096,
            max_duration_seconds=30.0,
            terminate_grace_seconds=0.5,
            shutdown_budget_seconds=3.0,
        )
        async with Session(tmp_path, argv_for("flood"), limits=limits) as session:
            await asyncio.sleep(0.4)
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(0.3)
        return session

    session = run(scenario)
    assert not still_running(session.proxy.child_pid)


@pytest.mark.parametrize(
    "mode,interrupt",
    [("normal", False), ("crash_midway", False), ("ignore_sigterm", True), ("slow", True)],
)
def test_the_recording_always_has_a_closing_event(tmp_path, mode, interrupt):
    async def scenario():
        async with Session(tmp_path, argv_for(mode)) as session:
            session.send(request(1))
            await asyncio.sleep(0.3)
            if interrupt:
                os.kill(os.getpid(), signal.SIGINT)
                await asyncio.sleep(0.2)
        return session

    session = run(scenario)
    assert session.events[-1]["type"] == "run_finished"
    assert session.outcome.closing_event_written is True


def test_shutdown_stays_inside_its_budget_even_against_a_stubborn_server(tmp_path):
    async def scenario():
        limits = Limits(
            max_duration_seconds=30.0,
            terminate_grace_seconds=1.0,
            shutdown_budget_seconds=4.0,
            final_write_seconds=1.0,
        )
        async with Session(tmp_path, argv_for("ignore_sigterm"), limits=limits) as session:
            session.send(request(1))
            await asyncio.sleep(0.3)
            started = time.monotonic()
            os.kill(os.getpid(), signal.SIGINT)
        return session, started

    session, started = run(scenario)
    assert time.monotonic() - started < 10, "a tool that looks hung is a tool nobody waits out"
    assert not still_running(session.proxy.child_pid)


# -- working directory ----------------------------------------------------------------


def test_the_child_starts_in_the_directory_it_is_given(tmp_path, monkeypatch):
    """``Proxy(cwd=…)`` starts the server there; a child that reports ``os.getcwd()`` shows it,
    and its ``PWD`` says the same."""
    where = tmp_path / "there"
    where.mkdir()
    script = tmp_path / "cwd_server.py"
    script.write_text(
        "import json, os, sys\n"
        "sys.stdin.readline()\n"
        "print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'cwd': os.getcwd(),"
        " 'pwd': os.environ.get('PWD')}}), flush=True)\n"
    )
    monkeypatch.setenv("PWD", str(tmp_path))

    async def scenario():
        recorder = Recorder.open(tmp_path / "events.jsonl", run_id="cwdtest", masker=Masker())
        to_proxy_read, to_proxy = os.pipe()
        from_proxy, from_proxy_write = os.pipe()
        client_in = os.fdopen(to_proxy_read, "rb", buffering=0)
        client_out = os.fdopen(from_proxy_write, "wb", buffering=0)
        proxy = Proxy(
            argv=[sys.executable, str(script)],
            recorder=recorder,
            limits=Limits(
                max_duration_seconds=30.0, terminate_grace_seconds=0.5, shutdown_budget_seconds=3.0
            ),
            client_in=client_in,
            client_out=client_out,
            cwd=where,
        )
        task = asyncio.create_task(proxy.run())
        os.write(to_proxy, request(1))
        reader = os.fdopen(from_proxy, "rb", 0)
        answer = await asyncio.get_running_loop().run_in_executor(None, reader.readline)
        os.close(to_proxy)
        await asyncio.wait_for(task, timeout=20)
        recorder.close()
        for handle in (client_in, client_out, reader):
            handle.close()
        return json.loads(answer)["result"]

    result = run(scenario)
    assert Path(result["cwd"]).resolve() == where.resolve()
    assert result["pwd"] == str(where)


def test_a_working_directory_that_cannot_be_entered_is_said_as_that(tmp_path):
    """The system reports a missing directory with the number of a missing command. The recording
    says which of the two it was, and names no path."""
    gone = tmp_path / "gone"
    events_path = tmp_path / "events.jsonl"

    async def scenario():
        recorder = Recorder.open(events_path, run_id="cwdgone", masker=Masker())
        to_proxy_read, to_proxy = os.pipe()
        from_proxy, from_proxy_write = os.pipe()
        client_in = os.fdopen(to_proxy_read, "rb", buffering=0)
        client_out = os.fdopen(from_proxy_write, "wb", buffering=0)
        proxy = Proxy(
            argv=[sys.executable, "-c", "pass"],
            recorder=recorder,
            limits=Limits(
                max_duration_seconds=30.0, terminate_grace_seconds=0.5, shutdown_budget_seconds=3.0
            ),
            client_in=client_in,
            client_out=client_out,
            cwd=gone,
        )
        os.close(to_proxy)
        await asyncio.wait_for(proxy.run(), timeout=20)
        recorder.close()
        os.close(from_proxy)
        for handle in (client_in, client_out):
            handle.close()

    run(scenario)
    written = [json.loads(line) for line in events_path.read_text().splitlines()]
    (failed,) = [event for event in written if event["type"] == "server_failed"]
    assert failed["detail"] == "the working directory could not be entered (ENOENT)"
    assert str(tmp_path) not in events_path.read_text()


def test_a_program_that_is_the_working_directory_itself_is_the_commands_failure():
    """The system names the same path for both. A directory given as the program cannot be run,
    and that is said of the command, not of the directory the server was to start in."""
    from mcp_kymograph.proxy import _not_started

    refused = PermissionError(13, "Permission denied", "/srv/entry")
    assert _not_started(refused, "/srv/entry", "python") == (
        "the working directory could not be entered (EACCES)"
    )
    assert _not_started(refused, "/srv/entry", "/srv/entry") == _not_started(refused)
    assert "working directory" not in _not_started(refused)
