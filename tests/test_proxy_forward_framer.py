"""The proxy's forwarding framer (``_ForwardFramer`` in src/mcp_kymograph/proxy.py), on its own.

It sits on the forwarding path while a scenario intercepts: what it returns is what is written
on. Two things hold for every input, however it is cut into reads: the bytes it returns, joined,
are exactly the bytes fed in; and it never holds more than its limit. A line within the limit
comes back as a message to decide on; anything else goes through raw.
"""

from __future__ import annotations

import pytest

from mcp_kymograph.proxy import _ForwardFramer

LIMIT = 8


def splits(data: bytes):
    """The whole input, every split in two, and one byte at a time."""
    yield [data]
    for index in range(1, len(data)):
        yield [data[:index], data[index:]]
    yield [data[index : index + 1] for index in range(len(data))]


def framed(data: bytes, limit: int = LIMIT) -> list[tuple[str, bytes]]:
    """Feed ``data`` every way; check that nothing is lost or held past the limit; return
    the outputs of the whole-input feed, with consecutive raw pieces joined."""
    results = []
    for parts in splits(data):
        framer = _ForwardFramer(limit)
        out: list[tuple[str, bytes]] = []
        for part in parts:
            out += framer.feed(part)
            assert len(framer._buf) <= limit
        out += framer.finish()
        assert (
            b"".join(payload + (b"\n" if kind == "message" else b"") for kind, payload in out)
            == data
        )
        assert framer._buf == b"" and not framer._overflow
        results.append(joined(out))
    # A message is a message however the reads were cut; only raw pieces may split.
    assert all(result == results[0] for result in results[1:])
    return results[0]


def joined(out: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    merged: list[tuple[str, bytes]] = []
    for kind, payload in out:
        if kind == "raw" and merged and merged[-1][0] == "raw":
            merged[-1] = ("raw", merged[-1][1] + payload)
        else:
            merged.append((kind, payload))
    return merged


def test_lines_within_the_limit_are_messages():
    assert framed(b"{}\n[1]\n") == [("message", b"{}"), ("message", b"[1]")]


def test_a_line_of_exactly_the_limit_is_a_message_and_one_byte_more_is_raw():
    assert framed(b"x" * LIMIT + b"\n") == [("message", b"x" * LIMIT)]
    assert framed(b"x" * (LIMIT + 1) + b"\n") == [("raw", b"x" * (LIMIT + 1) + b"\n")]


def test_an_oversized_line_streams_raw_to_its_end_and_the_next_line_is_a_message_again():
    data = b"a" * 30 + b"\n" + b"ok\n"
    assert framed(data) == [("raw", b"a" * 30 + b"\n"), ("message", b"ok")]


def test_an_unfinished_tail_goes_through_raw_at_the_end():
    assert framed(b"{}\nhalf") == [("message", b"{}"), ("raw", b"half")]
    assert framed(b"{}\n" + b"b" * 20) == [("message", b"{}"), ("raw", b"b" * 20)]


def test_an_empty_line_is_an_empty_message():
    assert framed(b"\n\n") == [("message", b""), ("message", b"")]


def test_an_oversized_line_cut_across_reads_never_grows_the_buffer():
    framer = _ForwardFramer(LIMIT)
    out = []
    for _ in range(10):
        out += framer.feed(b"zzzz")
        assert len(framer._buf) <= LIMIT
    out += framer.feed(b"z\nnext\n")
    assert out[-1] == ("message", b"next")
    assert b"".join(payload for kind, payload in out if kind == "raw") == b"z" * 41 + b"\n"
    assert framer.finish() == []


@pytest.mark.parametrize("limit", [1, 2, 3])
def test_tiny_limits_lose_nothing(limit):
    framed(b"a\nbb\nccc\n\ndddd", limit=limit)
