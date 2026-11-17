"""The framer: message boundaries found on a copy of the stream.

No network, no subprocesses. Every test here is bytes in, frames out.
"""

import pytest

from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES, Frame, LineFramer


def frames_of(chunks, **kwargs):
    """Feed the chunks in order and close the stream."""
    framer = LineFramer(**kwargs)
    out = []
    for chunk in chunks:
        out.extend(framer.feed(chunk))
    out.extend(framer.finish())
    return out


# -- ordinary framing ----------------------------------------------------------------


def test_a_message_split_across_chunks_is_reassembled():
    frames = frames_of([b'{"jsonrpc":', b'"2.0","id":1', b',"method":"ping"}\n'])
    assert frames == [Frame(data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}', size_bytes=40)]


def test_several_messages_in_one_chunk():
    frames = frames_of([b'{"a":1}\n{"b":2}\n{"c":3}\n'])
    assert [frame.data for frame in frames] == [b'{"a":1}', b'{"b":2}', b'{"c":3}']


def test_a_newline_exactly_on_the_chunk_boundary():
    frames = frames_of([b'{"a":1}\n', b'{"b":2}\n'])
    assert [frame.data for frame in frames] == [b'{"a":1}', b'{"b":2}']


def test_a_newline_as_the_first_byte_of_the_next_chunk():
    frames = frames_of([b'{"a":1}', b'\n{"b":2}\n'])
    assert [frame.data for frame in frames] == [b'{"a":1}', b'{"b":2}']


def test_feeding_one_byte_at_a_time_gives_the_same_result():
    stream = b'{"a":1}\n\n  \n{"b":2}\nleftover'
    whole = frames_of([stream])
    piecewise = frames_of([stream[i : i + 1] for i in range(len(stream))])
    assert whole == piecewise
    assert [frame.data for frame in whole] == [b'{"a":1}', b'{"b":2}', b"leftover"]


def test_size_excludes_the_terminator_but_keeps_a_carriage_return():
    (frame,) = frames_of([b'{"a":1}\r\n'])
    assert frame.data == b'{"a":1}\r'
    assert frame.size_bytes == 8


# -- framing is not content ----------------------------------------------------------


def test_blank_lines_and_stray_whitespace_produce_no_frames():
    assert frames_of([b'\n\n   \n\t\n{"a":1}\n\n']) == [Frame(data=b'{"a":1}', size_bytes=7)]


def test_a_lone_carriage_return_line_is_whitespace_too():
    assert frames_of([b"\r\n\r\n"]) == []


def test_finish_after_a_clean_ending_yields_nothing():
    framer = LineFramer()
    framer.feed(b'{"a":1}\n')
    assert framer.finish() == []


def test_finish_is_idempotent():
    framer = LineFramer()
    framer.feed(b"tail")
    assert len(framer.finish()) == 1
    assert framer.finish() == []


# -- the edges -----------------------------------------------------------------------


def test_a_remnant_at_stream_end_is_reported_not_dropped():
    complete, remnant = frames_of([b'{"complete":1}\n{"half":'])
    assert complete == Frame(data=b'{"complete":1}', size_bytes=14)
    assert remnant == Frame(data=b'{"half":', size_bytes=8, incomplete=True)


def test_an_oversized_message_is_dropped_and_the_framer_resynchronises():
    huge = b"x" * 200
    frames = frames_of([huge + b'\n{"after":1}\n'], max_message_bytes=32)
    assert frames == [
        Frame(data=b"", size_bytes=200, truncated=True),
        Frame(data=b'{"after":1}', size_bytes=11),
    ]


def test_the_true_size_is_counted_across_the_discard_boundary():
    # The limit is hit inside the second chunk; the count must still cover all three.
    (frame,) = frames_of([b"a" * 20, b"b" * 20, b"c" * 20, b"\n"], max_message_bytes=32)
    assert frame.truncated is True
    assert frame.size_bytes == 60
    assert frame.data == b""


def test_a_message_exactly_at_the_limit_is_kept():
    (frame,) = frames_of([b"x" * 32 + b"\n"], max_message_bytes=32)
    assert frame.truncated is False
    assert frame.size_bytes == 32


def test_one_byte_over_the_limit_is_dropped():
    (frame,) = frames_of([b"x" * 33 + b"\n"], max_message_bytes=32)
    assert frame.truncated is True


def test_an_oversized_remnant_is_both_truncated_and_incomplete():
    (frame,) = frames_of([b"x" * 200], max_message_bytes=32)
    assert frame == Frame(data=b"", size_bytes=200, truncated=True, incomplete=True)


def test_the_buffer_never_grows_past_the_limit_even_without_a_newline():
    # A server that never sends a newline must cost us the counter and nothing else.
    limit = 1024
    framer = LineFramer(max_message_bytes=limit)
    for _ in range(100):
        framer.feed(b"y" * 1000)
        assert framer.buffered_bytes <= limit
    (frame,) = framer.finish()
    assert frame.size_bytes == 100_000
    assert frame.data == b""


def test_a_single_chunk_far_larger_than_the_limit_is_never_buffered():
    framer = LineFramer(max_message_bytes=64)
    framer.feed(b"z" * 5_000_000)
    assert framer.buffered_bytes == 0


def test_the_default_limit_is_one_mebibyte():
    assert DEFAULT_MAX_MESSAGE_BYTES == 1024 * 1024


def test_a_nonsensical_limit_is_refused_at_construction():
    with pytest.raises(ValueError):
        LineFramer(max_message_bytes=0)
