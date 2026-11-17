"""The JSON body framer (src/mcp_kymograph/http/body.py), against bytes alone: every body fed
whole, split at every byte boundary, and one byte at a time, with the same frames each way."""

from __future__ import annotations

import json

from mcp_kymograph.http.body import BodyFrame, JsonBodyFramer

BODY_JSON = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'


def splits(data: bytes):
    """The whole input, every split in two, and one byte at a time."""
    yield [data]
    for index in range(1, len(data)):
        yield [data[:index], data[index:]]
    yield [data[index : index + 1] for index in range(len(data))]


# -- JSON bodies ---------------------------------------------------------------------------


def bodies(payload: bytes, *, complete: bool = True, limit: int = 1024) -> list[BodyFrame]:
    results = []
    for parts in splits(payload):
        framer = JsonBodyFramer(limit)
        frames = [frame for part in parts for frame in framer.feed(part)]
        results.append(frames + framer.finish(complete=complete))
        assert framer.buffered_bytes == 0
    assert all(result == results[0] for result in results[1:])
    return results[0]


def test_a_json_body_is_one_message():
    assert bodies(BODY_JSON) == [BodyFrame(BODY_JSON, len(BODY_JSON))]


def test_a_json_array_is_one_batch():
    batch = b' \r\n[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"x"}]'
    assert bodies(batch) == [BodyFrame(batch, len(batch), batch=True)]


def test_an_empty_body_is_no_message():
    assert bodies(b"") == []
    assert bodies(b" \r\n\t") == []


def test_an_oversized_body_is_counted_and_dropped_not_clipped():
    big = json.dumps({"result": "x" * 100}).encode()
    assert bodies(big, limit=50) == [BodyFrame(b"", len(big), truncated=True)]
    exact = b"[" + b"1" * 48 + b"]"
    assert bodies(exact, limit=50) == [BodyFrame(exact, 50, batch=True)]


def test_a_body_cut_short_is_marked_incomplete():
    assert bodies(BODY_JSON[:10], complete=False) == [
        BodyFrame(BODY_JSON[:10], 10, incomplete=True)
    ]


def test_a_large_body_is_never_held_past_the_bound_while_it_arrives():
    framer = JsonBodyFramer(1024)
    framer.feed(b'{"result":"')
    for _ in range(512):
        framer.feed(b"z" * 8192)
        assert framer.buffered_bytes <= 1024
    framer.feed(b'"}')
    (frame,) = framer.finish()
    assert frame == BodyFrame(b"", 11 + 512 * 8192 + 2, truncated=True)


def test_an_oversized_body_cut_short_is_both_truncated_and_incomplete():
    big = b"[" + b"1," * 100
    assert bodies(big, complete=False, limit=50) == [
        BodyFrame(b"", len(big), batch=True, truncated=True, incomplete=True)
    ]


def test_a_body_of_exactly_the_bound_is_kept_and_one_byte_more_is_not():
    body = b'{"a":"' + b"x" * 24 + b'"}'
    assert len(body) == 32
    (kept,) = bodies(body, limit=32)
    assert (kept.data, kept.size_bytes, kept.truncated) == (body, 32, False)
    (dropped,) = bodies(body + b" ", limit=32)
    assert (dropped.data, dropped.size_bytes, dropped.truncated) == (b"", 33, True)
