"""The SSE framer (src/mcp_kymograph/http/sse.py), against bytes alone: every stream fed whole,
split at every byte boundary, and one byte at a time, with the same events and counts each way."""

from __future__ import annotations

import pytest

from mcp_kymograph.http.sse import SseEvent, SseFramer


def splits(data: bytes):
    """The whole input, every split in two, and one byte at a time."""
    yield [data]
    for index in range(1, len(data)):
        yield [data[:index], data[index:]]
    yield [data[index : index + 1] for index in range(len(data))]


# -- server-sent events --------------------------------------------------------------------


def events(stream: bytes, *, limit: int = 1024) -> tuple[list[SseEvent], tuple]:
    results = []
    for parts in splits(stream):
        framer = SseFramer(limit)
        found = [event for part in parts for event in framer.feed(part)] + framer.finish()
        counts = (framer.comments, framer.retries, framer.retry, framer.events)
        results.append((found, counts, framer.last_event_id))
    assert all(result == results[0] for result in results[1:])
    return results[0][0], results[0][1]


def test_one_event_per_blank_line_with_data_lines_joined():
    found, _ = events(b'data: {"a":\ndata: 1}\n\ndata:second\n\n')
    assert [e.data for e in found] == [b'{"a":\n1}', b"second"]
    assert all(e.is_message and e.event_type == "message" for e in found)


@pytest.mark.parametrize("end", [b"\r\n", b"\n", b"\r"])
def test_crlf_lf_and_cr_end_lines_alike(end):
    stream = end.join([b"id: 1", b"event: note", b"data: a", b"data: b", b"", b"data: c", b"", b""])
    found, _ = events(stream)
    assert [(e.data, e.event_type, e.event_id) for e in found] == [
        (b"a\nb", "note", "1"),
        (b"c", "message", "1"),
    ]


def test_a_bom_is_dropped_at_the_start_and_only_there():
    found, _ = events(b"\xef\xbb\xbfdata: x\n\n\xef\xbb\xbfdata: y\n\n")
    # Later, a BOM is part of the line: its field is no field this framer reads, and a block of
    # nothing else is no event.
    assert [(e.data, e.is_message) for e in found] == [(b"x", True)]
    # Two bytes of a BOM and then the end: not a BOM but content — an unfinished line of no
    # field this framer reads, dropped. Whatever it was is not held back either.
    framer = SseFramer()
    assert framer.feed(b"\xef\xbb") == [] and framer.buffered_bytes == 2
    assert framer.finish() == [] and framer.buffered_bytes == 0


def test_comments_and_retry_are_counted_not_messages():
    stream = b": keep-alive\n\nretry: 3000\nretry: soon\n:\ndata: x\n\n: bye\n"
    found, (comments, retries, retry, count) = events(stream)
    assert (comments, retries, retry) == (3, 1, 3000)
    assert [(e.data, e.is_message) for e in found] == [(b"x", True)]
    assert count == 1


def test_events_with_empty_data_are_counted_and_keep_their_ids():
    stream = b"id: 41\ndata:\n\nid: 42\n\ndata: real\n\nid: x\x00y\ndata: z\n\n"
    found, (_, _, _, count) = events(stream)
    assert [(e.data, e.event_id, e.is_message) for e in found] == [
        (b"", "41", False),
        (b"", "42", False),
        (b"real", "42", True),
        (b"z", "42", True),  # an id holding NUL is ignored; the last one stays
    ]
    assert count == 4


def test_fields_keep_one_space_off_and_unknown_fields_are_ignored():
    found, _ = events(b"data:no space\ndata:  two\ndata\nfoo: bar\n\n")
    assert found[0].data == b"no space\n two\n"


def test_an_oversized_event_is_counted_and_dropped_not_clipped():
    found, _ = events(b"data: " + b"x" * 40 + b"\ndata: y\n\ndata: ok\n\n", limit=32)
    assert [(e.data, e.size_bytes, e.truncated) for e in found] == [
        (b"", 42, True),
        (b"ok", 2, False),
    ]
    found, _ = events(b"data: " + b"x" * 100 + b"\n\n", limit=32)
    assert found[0].truncated and found[0].data == b""


def test_a_line_is_held_no_further_than_the_bound_whatever_its_field():
    framer = SseFramer(32)
    for _ in range(50):
        framer.feed(b": " + b"c" * 20)  # one comment line that never ends
        assert framer.buffered_bytes <= 32 + 16
    found, _ = events(b"id: " + b"7" * 60 + b"\ndata: ok\n\ndata: next\n\n", limit=32)
    # An id too long to keep: the last event id is unknown from there, not unset.
    assert [(e.data, e.truncated, e.event_id, e.id_lost) for e in found] == [
        (b"ok", False, None, True),
        (b"next", False, None, True),
    ]


def test_an_event_the_stream_ends_in_is_returned_incomplete():
    found, _ = events(b"data: done\n\nid: 9\ndata: half")
    assert [(e.data, e.incomplete, e.event_id) for e in found] == [
        (b"done", False, None),
        (b"half", True, "9"),
    ]


def test_a_large_event_over_many_reads_is_counted_whole_and_held_no_further_than_the_bound():
    framer = SseFramer(1024)
    framer.feed(b"id: 1\ndata: ")
    for _ in range(256):
        assert framer.feed(b"d" * 4096) == []
        assert framer.buffered_bytes <= 1024 + 16
    (big,) = framer.feed(b"\n\n")
    assert (big.data, big.size_bytes, big.truncated, big.event_id) == (b"", 256 * 4096, True, "1")
    (after,) = framer.feed(b"data: small\n\n")
    assert (after.data, after.truncated) == (b"small", False)


def test_multiline_data_comments_and_empty_events_together():
    stream = (
        b": open\r\nid: a\r\ndata:\r\n\r\n"  # an empty event that only sets the id
        b'data: {"jsonrpc":"2.0",\r\ndata:  "method":"notifications/message"}\r\n'
        b": keep-alive\r\n\r\n"
        b"event: ping\r\n\r\n"  # a typed event without data: counted, not a message
    )
    found, (comments, _, _, count) = events(stream)
    assert [(e.data, e.event_id, e.event_type, e.is_message) for e in found] == [
        (b"", "a", "message", False),
        (b'{"jsonrpc":"2.0",\n "method":"notifications/message"}', "a", "message", True),
        (b"", "a", "ping", False),
    ]
    assert (comments, count) == (2, 3)


def test_an_overlong_line_is_read_for_what_it_is():
    long = b"q" * 40
    stream = (
        b": " + long + b"\n"  # a comment: counted, the event unharmed
        b"x-very-long-field-name-indeed: " + long + b"\n"  # no field this framer reads
        b"data: ok\n\n"
        b"data:" + long + b"\ndata: " + long + b"\n\n"  # data lines past the bound
    )
    found, (comments, _, _, _) = events(stream, limit=8)
    assert comments == 1
    assert [(e.data, e.size_bytes, e.truncated) for e in found] == [
        (b"ok", 2, False),
        (b"", 40 + 1 + 40, True),  # true sizes, joined by one newline
    ]


# -- edge cases -----------------------------------------------------------------------------


def test_a_retry_too_long_to_be_a_wait_is_passed_over_without_failing():
    found, (_, retries, retry, _) = events(b"retry: " + b"1" * 5000 + b"\ndata: x\n\n")
    assert (retries, retry) == (0, None) and [e.data for e in found] == [b"x"]
    _, (_, retries, retry, _) = events(b"retry: 9999999999\nretry: 12345678901\n")
    assert (retries, retry) == (1, 9999999999)


@pytest.mark.parametrize("end", [b"\n", b"\r", b"\r\n"])
def test_a_large_read_of_many_lines_is_framed_in_linear_time(end):
    import time

    framer = SseFramer()
    chunk = (b":" + end) * (1024 * 1024)
    started = time.monotonic()
    framer.feed(chunk)
    elapsed = time.monotonic() - started
    assert framer.comments == 1024 * 1024
    assert elapsed < 8.0, elapsed  # quadratic, this took minutes


def test_an_id_kept_again_ends_the_lost_id():
    found, _ = events(b"id: 1\n\nid: " + b"9" * 60 + b"\ndata: x\n\nid: 2\ndata: y\n\n", limit=32)
    assert [(e.event_id, e.id_lost) for e in found] == [("1", False), (None, True), ("2", False)]


def test_an_unfinished_last_line_changes_nothing_but_the_data():
    framer = SseFramer()
    framer.feed(b"data: a\n\nid: 9")
    assert framer.finish() == [] and framer.last_event_id is None
    framer = SseFramer()
    framer.feed(b"retry: 10")
    assert framer.finish() == [] and framer.retry is None
    framer = SseFramer()
    framer.feed(b"id: 3\ndata: par")
    (half,) = framer.finish()
    assert (half.data, half.event_id, half.incomplete) == (b"par", "3", True)  # id line ended


def test_a_block_of_only_retry_or_unknown_fields_is_no_event():
    found, (_, retries, _, count) = events(b"retry: 1000\n\nfoo: bar\n\nevent: e\n\n")
    assert (retries, count) == (1, 1)
    assert [(e.event_type, e.is_message) for e in found] == [("e", False)]


def test_an_overlong_event_type_truncates_its_event():
    found, _ = events(b"event: " + b"t" * 60 + b"\ndata: x\n\n", limit=32)
    assert [(e.data, e.truncated) for e in found] == [(b"", True)]


# -- more edge cases -------------------------------------------------------------------------


def test_a_cr_held_at_the_end_of_a_read_meets_its_lf_in_the_next():
    framer = SseFramer(1024)
    assert framer.feed(b"data: a\rdata: b") == []
    (event,) = framer.feed(b"\n\n")
    assert event.data == b"a\nb"
    found, _ = events(b"data: a\rdata: b\r\n\r\ndata: c\n\r\n")
    assert [e.data for e in found] == [b"a\nb", b"c"]


def test_the_line_and_data_bounds_are_exact():
    limit = 32
    fits, _ = events(b"data: " + b"x" * limit + b"\n\n", limit=limit)
    assert [(e.data, e.truncated) for e in fits] == [(b"x" * limit, False)]
    over, _ = events(b"data: " + b"x" * (limit + 1) + b"\n\n", limit=limit)
    assert [(e.data, e.size_bytes, e.truncated) for e in over] == [(b"", limit + 1, True)]
    # A line of exactly the bound plus the slack is still read as a line.
    line = b"data:" + b"y" * (limit + 16 - 5)
    assert len(line) == limit + 16
    exact, _ = events(line + b"\n\n", limit=limit)
    assert [(e.size_bytes, e.truncated) for e in exact] == [(limit + 11, True)]
    framer = SseFramer(limit)
    framer.feed(b": " + b"c" * (limit + 14))
    assert framer.buffered_bytes == limit + 16


def test_an_event_cut_short_by_its_size_is_still_a_message():
    found, _ = events(b"data: " + b"x" * 40 + b"\n\n", limit=32)
    assert found[0].truncated and found[0].data == b"" and found[0].is_message


def test_an_id_holding_a_nul_is_ignored_and_makes_no_event():
    found, counts = events(b"id: a\0b\n\ndata: x\n\n")
    assert [(e.data, e.event_id) for e in found] == [(b"x", None)]
    assert counts[3] == 1
    found, _ = events(b"id: 1\n\nid: a\0" + b"b" * 60 + b"\ndata: x\n\n", limit=32)
    assert [(e.data, e.event_id, e.id_lost) for e in found] == [
        (b"", "1", False),
        (b"x", "1", False),
    ]


def test_an_id_line_one_byte_past_the_bound_is_lost_and_at_the_bound_is_kept():
    limit = 32
    at = b"id:" + b"7" * (limit + 16 - 3)
    found, _ = events(at + b"\ndata: x\n\n", limit=limit)
    assert [(e.event_id, e.id_lost) for e in found] == [("7" * (limit + 13), False)]
    found, _ = events(at + b"7\ndata: x\n\n", limit=limit)
    assert [(e.event_id, e.id_lost) for e in found] == [(None, True)]
    framer = SseFramer(limit)
    framer.feed(at)
    assert framer.buffered_bytes == limit + 16
    framer.feed(b"7")
    assert framer.buffered_bytes <= limit + 16
