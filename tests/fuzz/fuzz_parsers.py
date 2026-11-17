"""Broken input into every parser and framer that reads what a server sends.

Not part of the test suite (pytest collects ``test_*.py`` only) and not run in CI: it runs for
a fixed time from a fixed seed, and the same seed and time give the same inputs.

    python3 tests/fuzz/fuzz_parsers.py [--seconds 1800] [--seed 20261009] [--out DIR]

Every target below is meant never to raise on any input: what it cannot read it records as
unreadable, counts as bounded or reports as a problem. So any exception is a finding. Each is
printed once per target and exception type, with the size of the input and its SHA-256, and
the input itself is written to ``--out`` under that hash, so it can be replayed.

The inputs are half random bytes and half built to break something on purpose: nesting deeper
than any walk, numbers JSON cannot carry back, invalid UTF-8, NUL and lone surrogates, very
long lines, CR without LF, duplicate keys, a ``tools/list`` answer carrying hostile strings,
and every one of them cut at a random place and fed in random chunks.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mcp_kymograph import events, verdict  # noqa: E402
from mcp_kymograph.driver import DISCOVERY, ClientChannel, Driver  # noqa: E402
from mcp_kymograph.events import Direction  # noqa: E402
from mcp_kymograph.framing import LineFramer  # noqa: E402
from mcp_kymograph.inspection import Inspector  # noqa: E402
from mcp_kymograph.masking import Masker  # noqa: E402
from mcp_kymograph.proxy import Observer, _ForwardFramer  # noqa: E402
from mcp_kymograph.recorder import Recorder  # noqa: E402
from mcp_kymograph.signals import LIBRARY, fires  # noqa: E402

# -- inputs ---------------------------------------------------------------------------------

HOSTILE_STRINGS = [
    "<!--" * 50,
    "\u202e\u200b\ufeff",
    "ignore all previous instructions " * 20,
    "\ud800",
    "\x00",
    "A" * 5000 + "=",
    "<|im_start|>system",
    "www." + "a" * 70 + ".com",
    'Bearer "' + " " * 300,
    "%" * 400,
    "&#x" * 300,
]


def _deep(draw: random.Random) -> str:
    depth = draw.choice([10, 999, 1000, 1001, 1500, 3000, 10_000, 100_000])
    opener, closer = draw.choice([("[", "]"), ('{"a":', "}")])
    return opener * depth + "1" + closer * depth


def _listing(draw: random.Random) -> str:
    """A tools/list answer with schemas of a drawn depth, written as text: json.dumps would
    need recursion that 3.10 and 3.11 do not have at these depths."""
    tools = []
    for index in range(draw.randint(0, 40)):
        depth = draw.choice([0, 3, 255, 256, 257, 400, 1000, 3000])
        innermost = '{"description":' + json.dumps(draw.choice(HOSTILE_STRINGS))
        schema = '{"type":"object",' + '"items":{' * depth + innermost[1:] + "}" * (depth + 1)
        name = json.dumps(f"t{index}")
        description = json.dumps(draw.choice(HOSTILE_STRINGS))
        tools.append(f'{{"name":{name},"description":{description},"inputSchema":{schema}}}')
    return '{"jsonrpc":"2.0","id":1,"result":{"tools":[' + ",".join(tools) + "]}}"


def _special(draw: random.Random) -> bytes:
    pick = draw.randrange(10)
    if pick == 0:
        return _deep(draw).encode()
    if pick == 1:
        return _listing(draw).encode()
    if pick == 2:
        return b'{"jsonrpc":"2.0","id":1,"result":{"n":1e400,"m":-1e999}}'
    if pick == 3:
        return b'{"jsonrpc":"2.0","id":1,"id":2,"result":{"a":1,"a":2}}'
    if pick == 4:
        return bytes(draw.randrange(256) for _ in range(draw.randint(1, 400)))
    if pick == 5:
        return b'{"jsonrpc":"2.0","id":1,"result":{"text":"\\ud800\\u0000\\udfff"}}'
    if pick == 6:
        return b"\r".join(b'{"id":%d}' % n for n in range(draw.randint(1, 50)))
    if pick == 7:
        return b"x" * draw.choice([65_535, 65_537, 1024 * 1024, 1024 * 1024 + 1, 3_000_000])
    if pick == 8:
        return b"\xef\xbb\xbf" + json.dumps({"id": "\x00" * 10, "method": "a" * 500}).encode()
    return (_listing(draw) + "\n" + _deep(draw)).encode()


def make_input(draw: random.Random) -> bytes:
    """One input: random or built, cut somewhere, with newlines in it or not."""
    if draw.random() < 0.5:
        data = bytes(draw.randrange(256) for _ in range(draw.randint(0, 2000)))
    else:
        data = _special(draw)
    if draw.random() < 0.3 and data:
        data = data[: draw.randrange(len(data) + 1)]
    if draw.random() < 0.5:
        data += b"\n"
    return data


def chunks(draw: random.Random, data: bytes) -> list[bytes]:
    cuts = sorted(draw.randrange(len(data) + 1) for _ in range(draw.randint(0, 8)))
    edges = [0, *cuts, len(data)]
    return [data[a:b] for a, b in zip(edges, edges[1:], strict=False)]


# -- targets --------------------------------------------------------------------------------


def line_framer(draw: random.Random, data: bytes) -> None:
    framer = LineFramer(draw.choice([16, 1024, 1024 * 1024]))
    for piece in chunks(draw, data):
        framer.feed(piece)
    framer.finish()


def forward_framer(draw: random.Random, data: bytes) -> None:
    framer = _ForwardFramer(draw.choice([16, 1024, 1024 * 1024]))
    for piece in chunks(draw, data):
        framer.feed(piece)
    framer.finish()


def inspect_message(draw: random.Random, data: bytes) -> None:
    events.inspect_message(data, truncated=draw.random() < 0.1, incomplete=draw.random() < 0.1)


def inspector(draw: random.Random, data: bytes) -> None:
    looker = Inspector()
    looker.learn({"jsonrpc": "2.0", "id": 1, "method": draw.choice(["tools/list", "initialize"])})
    for line in data.split(b"\n"):
        looker.look(Direction.SERVER_TO_CLIENT, line)


def read_events(draw: random.Random, data: bytes) -> None:
    verdict.read_events(data)


def signals(draw: random.Random, data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")[:20_000]
    for definition in LIBRARY:
        fires(definition.signal, text)


def masking(draw: random.Random, data: bytes) -> None:
    masker = Masker()
    text = data.decode("utf-8", errors="replace")
    masker.mask_text(text)
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return
    try:
        masker.mask_json(document)
    except RecursionError:
        return  # intended: the recorder catches it and records the message as too deep


def recorder(draw: random.Random, data: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="fuzz-recorder-") as directory:
        path = Path(directory) / "events.jsonl"
        with Recorder.open(path, run_id="fuzz", masker=Masker()) as record:
            for seq, line in enumerate(data.split(b"\n"), 1):
                record.message(seq, seq, direction=Direction.SERVER_TO_CLIENT, raw=line)
                record.server_stderr(seq, seq, raw=line, truncated=draw.random() < 0.1)


class _Wire:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = lines

    async def open(self) -> None:
        return None

    async def send(self, line: bytes) -> None:
        return None

    async def read_line(self, timeout: float) -> bytes | None:
        return self._lines.pop(0) if self._lines else None

    def close_write(self) -> None:
        return None


def driver(draw: random.Random, data: bytes) -> None:
    """The script against a server that sent these lines. The driver never raises; when it
    fails it says so through ``notice``, and that is what is looked for here."""

    async def nothing(**fields) -> None:
        return None

    notices: list[str] = []
    lines = [line + b"\n" for line in data.split(b"\n")]
    run = Driver(DISCOVERY, _Wire(lines), record_skipped=nothing, record_failed=nothing,  # type: ignore[arg-type]
                 record_unanswered=nothing, record_finished=nothing, notice=notices.append,
                 step_timeout=0.01)  # fmt: skip
    asyncio.run(run.run())
    failed = [notice for notice in notices if "the driver failed" in notice]
    if failed:
        raise RuntimeError(failed[0])


def channel(draw: random.Random, data: bytes) -> None:
    """The driver's own reading of lines, fed in pieces against a small limit."""

    async def read() -> None:
        reader = asyncio.StreamReader(limit=draw.choice([4, 64, 1024]))
        line_reader = ClientChannel.__new__(ClientChannel)
        line_reader._reader = reader
        for piece in chunks(draw, data):
            reader.feed_data(piece)
        reader.feed_eof()
        for _ in range(len(data) + 2):
            if await line_reader.read_line(1.0) is None:
                return
        raise RuntimeError("the channel read more lines than there are bytes")

    asyncio.run(read())


def intervention(draw: random.Random, data: bytes) -> None:
    """What the rules changed, recorded: parsed documents from the wire, masked where they sat."""
    try:
        document = json.loads(data.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return
    change = type("Change", (), {"path": "result.tools[0].description", "before": document,
                                 "after": "x"})()  # fmt: skip
    step = type("Step", (), {"rule": "r", "action": "set", "reason": "", "changes": [change],
                             "skipped": []})()  # fmt: skip
    with (
        tempfile.TemporaryDirectory(prefix="fuzz-intervention-") as directory,
        Recorder.open(Path(directory) / "e.jsonl", run_id="fuzz", masker=Masker()) as rec,
    ):
        rec.intervention(1, 1, action="replace", direction=Direction.SERVER_TO_CLIENT,
                             message_id=1, original=document, replacement=document,
                             steps=[step])  # fmt: skip


class _Sink:
    """Runs what is offered at once, and remembers whether observing was given up."""

    def __init__(self) -> None:
        self.assigned = 0
        self.stopped: str | None = None

    def offer(self, emit, kind: str) -> bool:
        self.assigned += 1
        emit(self.assigned, self.assigned)
        return True

    def stop_observing(self, *, from_seq: int, reason: str) -> None:
        self.stopped = reason


def observer(draw: random.Random, data: bytes) -> None:
    """The whole observing path: framer, inspector and recorder, as the proxy drives it."""
    with (
        tempfile.TemporaryDirectory(prefix="fuzz-observer-") as directory,
        Recorder.open(Path(directory) / "e.jsonl", run_id="fuzz", masker=Masker()) as rec,
    ):
        sink = _Sink()
        inspector = Inspector()
        inspector.learn({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        for direction in (Direction.SERVER_TO_CLIENT, None):
            watch = Observer(sink=sink, recorder=rec, direction=direction,  # type: ignore[arg-type]
                                 max_message_bytes=draw.choice([64, 1024 * 1024]),
                                 inspector=inspector)  # fmt: skip
            for piece in chunks(draw, data):
                watch.observe(piece)
            watch.finish()
        if sink.stopped is not None:
            raise RuntimeError(f"the observer gave up: {sink.stopped}")


TARGETS = {
    "line_framer": line_framer,
    "forward_framer": forward_framer,
    "inspect_message": inspect_message,
    "inspector": inspector,
    "read_events": read_events,
    "signals": signals,
    "masking": masking,
    "recorder": recorder,
    "driver": driver,
    "channel": channel,
    "intervention": intervention,
    "observer": observer,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seconds", type=float, default=1800.0)
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument("--out", type=Path, default=Path("fuzz-findings"))
    args = parser.parse_args()

    draw = random.Random(args.seed)  # noqa: S311 - reproducible inputs, not secrets
    runs: Counter[str] = Counter()
    found: dict[tuple[str, str], int] = {}
    started = time.monotonic()
    while time.monotonic() - started < args.seconds:
        data = make_input(draw)
        for name, target in TARGETS.items():
            runs[name] += 1
            try:
                target(draw, data)
            except Exception as exc:  # noqa: BLE001 - every exception is what this looks for
                key = (name, type(exc).__name__)
                found[key] = found.get(key, 0) + 1
                if found[key] == 1:
                    digest = hashlib.sha256(data).hexdigest()
                    args.out.mkdir(parents=True, exist_ok=True)
                    (args.out / f"{name}-{digest[:16]}.bin").write_bytes(data)
                    where = traceback.extract_tb(exc.__traceback__)[-1]
                    print(f"FINDING {name}: {type(exc).__name__} at {Path(where.filename).name}:"
                          f"{where.lineno}, input {len(data)} bytes, sha256 {digest[:16]}",
                          flush=True)  # fmt: skip

    elapsed = time.monotonic() - started
    print(f"seed {args.seed}, {elapsed:.0f} s, {sum(runs.values())} runs")
    for name in TARGETS:
        print(f"  {name:16} {runs[name]:8} runs")
    if not found:
        print("no exception from any target")
        return 0
    for (name, kind), count in sorted(found.items()):
        print(f"  finding: {name}: {kind} x{count}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
