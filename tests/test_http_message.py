"""The head parser and the message framer (src/mcp_kymograph/http/head.py, message.py), against
bytes alone.

Every input is fed three ways and must come out the same: whole, split at every single byte
boundary in turn, and one byte at a time. One more thing holds in every case, framing error
or not, because the forwarder relies on it: the raw bytes of the pieces, joined, are exactly
the bytes fed in.
"""

from __future__ import annotations

import pytest

from mcp_kymograph.http.head import (
    BAD_FIELD_LINE,
    BAD_LINE_END,
    BAD_START_LINE,
    HEAD_TOO_LARGE,
    MAX_HEAD_BYTES,
    OBSOLETE_LINE_FOLDING,
    TOO_MANY_FIELDS,
    UNSUPPORTED_VERSION,
    HeadError,
    parse_head,
)
from mcp_kymograph.http.message import (
    BAD_CHUNK_END,
    BAD_CHUNK_SIZE,
    BAD_CONTENT_LENGTH,
    BODY,
    CHUNK_LINE_TOO_LARGE,
    CONFLICTING_LENGTH,
    END,
    FRAMER_STALLED,
    FRAMING_ERROR,
    GAP,
    HEAD,
    PASSTHROUGH,
    PROTOCOL_SWITCHED,
    TRAILER_TOO_LARGE,
    UNSUPPORTED_TRANSFER_CODING,
    HttpFramer,
    Piece,
)
from mcp_kymograph.http.sse import SseFramer

# -- feeding every way ---------------------------------------------------------------------


def splits(data: bytes):
    """The whole input, every split in two, and one byte at a time."""
    yield [data]
    for index in range(1, len(data)):
        yield [data[:index], data[index:]]
    yield [data[index : index + 1] for index in range(len(data))]


def merged(pieces: list[Piece]) -> list[tuple]:
    """Pieces with consecutive body, gap and pass-through stretches joined: how a read was cut
    may cut a body into more pieces, never change what the pieces say."""
    out: list[tuple] = []
    for piece in pieces:
        if piece.kind in (BODY, GAP, PASSTHROUGH) and out and out[-1][0] == piece.kind:
            kind, raw, payload = out[-1][:3]
            out[-1] = (kind, raw + piece.raw, payload + piece.payload)
            continue
        if piece.kind in (BODY, GAP, PASSTHROUGH):
            out.append((piece.kind, piece.raw, piece.payload))
        else:
            out.append(
                (piece.kind, piece.raw, piece.head, piece.complete, piece.trailers, piece.reason)
            )
    return out


def framed(data: bytes, *, request: bool, expect=(), **bounds) -> list[tuple]:
    """Feed ``data`` every way; check the partition and the agreement; return the pieces."""
    results = []
    for parts in splits(data):
        framer = HttpFramer(request=request, **bounds)
        for method in expect:
            framer.expect(method)
        pieces = [piece for part in parts for piece in framer.feed(part)] + framer.finish()
        assert b"".join(piece.raw for piece in pieces) == data
        assert framer.buffered_bytes == 0
        results.append(merged(pieces))
    assert all(result == results[0] for result in results[1:])
    return results[0]


def kinds(pieces: list[tuple]) -> list[str]:
    return [piece[0] for piece in pieces]


def body_of(pieces: list[tuple]) -> bytes:
    return b"".join(piece[2] for piece in pieces if piece[0] == BODY)


def errors(pieces: list[tuple]) -> list[str]:
    return [piece[5] for piece in pieces if piece[0] == FRAMING_ERROR]


def heads(pieces: list[tuple]):
    return [piece[2] for piece in pieces if piece[0] == HEAD]


def ends(pieces: list[tuple]) -> list[tuple]:
    return [piece for piece in pieces if piece[0] == END]


BODY_JSON = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'


def post(body: bytes = BODY_JSON, *extra: bytes) -> bytes:
    return (
        b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\n"
        + b"".join(extra)
        + b"Content-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )


# -- heads ---------------------------------------------------------------------------------


def test_a_request_head_is_parsed():
    head = parse_head(post().split(b"\r\n\r\n")[0] + b"\r\n\r\n", request=True)
    assert (head.method, head.target, head.version) == ("POST", "/mcp", "HTTP/1.1")
    assert head.values("CONTENT-type") == ["application/json"]
    assert head.is_request


def test_a_response_head_is_parsed_with_or_without_a_reason():
    head = parse_head(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n", request=False)
    assert (head.status, head.reason, head.version) == (202, "Accepted", "HTTP/1.1")
    assert parse_head(b"HTTP/1.0 404\n\n", request=False).status == 404


@pytest.mark.parametrize(
    ("block", "is_request", "reason"),
    [
        (b"POST /mcp\r\n\r\n", True, BAD_START_LINE),
        (b"POST  /mcp HTTP/1.1\r\n\r\n", True, BAD_START_LINE),
        (b"PO(ST /mcp HTTP/1.1\r\n\r\n", True, BAD_START_LINE),
        (b"POST /mcp HTTP/2.0\r\n\r\n", True, UNSUPPORTED_VERSION),
        (b"PRI * HTTP/2.0\r\n\r\n", True, UNSUPPORTED_VERSION),
        (b"HTTP/1.1 20 OK\r\n\r\n", False, BAD_START_LINE),
        (b"POST /mcp HTTP/1.1\r\nHost : x\r\n\r\n", True, BAD_FIELD_LINE),
        (b"POST /mcp HTTP/1.1\r\nno colon\r\n\r\n", True, BAD_FIELD_LINE),
        (b"POST /mcp HTTP/1.1\r\nX: a\x00b\r\n\r\n", True, BAD_FIELD_LINE),
        (b"POST /mcp HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", True, OBSOLETE_LINE_FOLDING),
        (b"POST /mcp HTTP/1.1\r\nX: a\rY: b\r\n\r\n", True, BAD_LINE_END),
    ],
)
def test_a_head_that_is_not_read_says_why(block, is_request, reason):
    with pytest.raises(HeadError) as caught:
        parse_head(block, request=is_request)
    assert caught.value.reason == reason
    assert str(caught.value).startswith(reason + ": ")


def test_a_head_has_at_most_100_fields():
    fields = b"".join(b"X-%d: v\r\n" % index for index in range(100))
    assert len(parse_head(b"GET / HTTP/1.1\r\n" + fields + b"\r\n", request=True).fields) == 100
    with pytest.raises(HeadError) as caught:
        parse_head(b"GET / HTTP/1.1\r\n" + fields + b"X: 1\r\n\r\n", request=True)
    assert caught.value.reason == TOO_MANY_FIELDS


# -- where a message ends ------------------------------------------------------------------


def test_a_request_with_content_length_then_another_on_the_same_connection():
    second = b"GET /mcp HTTP/1.1\r\nHost: h\r\nAccept: text/event-stream\r\n\r\n"
    pieces = framed(b"\r\n" + post() + b"\r\n" + second, request=True)
    assert kinds(pieces) == [GAP, HEAD, BODY, END, GAP, HEAD, END]
    assert body_of(pieces) == BODY_JSON
    assert [h.method for h in heads(pieces)] == ["POST", "GET"]
    assert all(end[3] for end in ends(pieces))


def test_an_empty_body_is_a_message_with_no_body():
    pieces = framed(post(b""), request=True)
    assert kinds(pieces) == [HEAD, END]


CHUNKED = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
    b'16;name=value;flag\r\nid: 7\ndata: {"id":1}\n\n\r\n'
    b"5\r\n:ping\r\n"
    b"0;last=yes\r\nX-Checksum: abc\r\nX-Other: 1\r\n\r\n"
)


def test_chunked_with_extensions_and_trailers():
    pieces = framed(CHUNKED, request=False, expect=["POST"])
    assert kinds(pieces) == [HEAD, BODY, END]
    assert body_of(pieces) == b'id: 7\ndata: {"id":1}\n\n:ping'
    (end,) = ends(pieces)
    assert end[3] is True
    assert end[4] == (("X-Checksum", "abc"), ("X-Other", "1"))


def test_a_chunked_body_of_length_zero():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    pieces = framed(data + b"HTTP/1.1 204 No Content\r\n\r\n", request=False)
    assert kinds(pieces) == [HEAD, BODY, END, HEAD, END]
    assert body_of(pieces) == b""
    assert ends(pieces)[0][4] == ()


def test_responses_without_a_body():
    data = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n"  # answers HEAD: no body
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n"
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
    )
    pieces = framed(data, request=False, expect=["HEAD", "GET", "POST"])
    assert kinds(pieces) == [HEAD, END] * 4
    assert [h.status for h in heads(pieces)] == [100, 200, 304, 202]


def test_a_response_without_length_ends_with_the_connection():
    data = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"result":{}}'
    pieces = framed(data, request=False)
    assert kinds(pieces) == [HEAD, BODY, END]
    assert body_of(pieces) == b'{"result":{}}'
    assert ends(pieces)[0][3] is True


def test_a_response_with_a_coding_not_ending_in_chunked_is_delimited_by_the_close():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nabc"
    assert kinds(framed(data, request=False)) == [HEAD, BODY, END]


def test_chunked_counts_only_as_the_last_coding_and_only_once():
    # RFC 9112, 6.3: a response whose last coding is not chunked ends with the connection.
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"
    pieces = framed(data, request=False)
    assert kinds(pieces) == [HEAD, BODY, END]
    assert body_of(pieces) == b"0\r\n\r\n"
    twice = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert errors(framed(twice, request=True)) == [UNSUPPORTED_TRANSFER_CODING]


def test_bare_line_feeds_end_lines_too():
    data = b"POST /mcp HTTP/1.1\nContent-Length: 2\n\n{}"
    pieces = framed(data, request=True)
    assert kinds(pieces) == [HEAD, BODY, END]


# -- the connection ends early -------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"POST /mcp HTTP/1.1\r\nContent-Le", [END]),
        (post()[:-5], [HEAD, BODY, END]),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc", [HEAD, BODY, END]),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r", [HEAD, BODY, END]),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: 1\r\n", [HEAD, BODY, END]),
    ],
)
def test_a_connection_that_ends_mid_message_says_so(data, expected):
    pieces = framed(data, request=data.startswith(b"POST") or data == b"\r")
    assert kinds(pieces) == expected
    assert ends(pieces)[-1][3] is False


def test_a_connection_that_ends_between_messages_ends_nothing():
    assert kinds(framed(post() + b"\r\n", request=True)) == [HEAD, BODY, END, GAP]


# -- framing errors: pass through, never lose a byte ---------------------------------------


@pytest.mark.parametrize(
    ("data", "reason", "is_request"),
    [
        (post(b"{}", b"Transfer-Encoding: chunked\r\n"), CONFLICTING_LENGTH, True),
        (post(b"{}", b"Content-Length: 3\r\n"), CONFLICTING_LENGTH, True),
        (b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", BAD_CONTENT_LENGTH, True),
        (b"POST / HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n", BAD_CONTENT_LENGTH, True),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\nabc",
            UNSUPPORTED_TRANSFER_CODING,
            True,
        ),
        (
            b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            UNSUPPORTED_TRANSFER_CODING,
            True,
        ),
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", BAD_CHUNK_SIZE, True),
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc", BAD_CHUNK_SIZE, True),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n",
            BAD_CHUNK_END,
            True,
        ),
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\rX", BAD_CHUNK_END, True),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nbad\r\n\r\n",
            BAD_FIELD_LINE,
            True,
        ),
        (b"GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n", OBSOLETE_LINE_FOLDING, True),
        (b"HTTP/1.1 999x\r\n\r\n", BAD_START_LINE, False),
        (b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n", BAD_START_LINE, True),
    ],
)
def test_a_framing_error_switches_to_passthrough_and_keeps_every_byte(data, reason, is_request):
    tail = b"GET / HTTP/1.1\r\n\r\n"  # a valid message after the error is not read as one
    pieces = framed(data + tail, request=is_request)
    assert errors(pieces) == [reason]
    after = kinds(pieces)[kinds(pieces).index(FRAMING_ERROR) + 1 :]
    assert set(after) <= {PASSTHROUGH}
    assert pieces[-1][0] == PASSTHROUGH and pieces[-1][1].endswith(tail)


def test_an_overlong_head_is_a_framing_error_at_the_bound():
    small = {"max_head_bytes": 64}
    fits = b"GET / HTTP/1.1\r\nX: " + b"a" * 41 + b"\r\n\r\n"
    assert len(fits) == 64
    assert kinds(framed(fits, request=True, **small)) == [HEAD, END]
    over = b"GET / HTTP/1.1\r\nX: " + b"a" * 42 + b"\r\n\r\n"
    pieces = framed(over + b"rest", request=True, **small)
    assert errors(pieces) == [HEAD_TOO_LARGE]
    assert kinds(pieces) == [FRAMING_ERROR, PASSTHROUGH]


def test_an_overlong_head_at_the_real_bound_is_held_no_further():
    framer = HttpFramer(request=True)
    data = b"GET / HTTP/1.1\r\nX: " + b"a" * (2 * MAX_HEAD_BYTES)
    pieces = framer.feed(data)
    assert [piece.kind for piece in pieces] == [FRAMING_ERROR, PASSTHROUGH]
    assert pieces[0].reason == HEAD_TOO_LARGE
    assert pieces[1].raw == data  # what was held, and the rest of the read, in one piece
    assert framer.buffered_bytes == 0


def test_more_than_the_bound_of_fields_is_a_framing_error():
    fields = b"".join(b"X-%d: v\r\n" % index for index in range(4))
    pieces = framed(b"GET / HTTP/1.1\r\n" + fields + b"\r\n", request=True, max_fields=3)
    assert errors(pieces) == [TOO_MANY_FIELDS]


def test_an_overlong_chunk_line_and_trailer_are_framing_errors():
    line = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;" + b"e" * 40 + b"\r\n"
    assert errors(framed(line, request=True, max_chunk_line_bytes=32)) == [CHUNK_LINE_TOO_LARGE]
    trailer = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: " + b"t" * 80 + b"\r\n\r\n"
    )
    assert errors(framed(trailer, request=False, max_head_bytes=64)) == [TRAILER_TOO_LARGE]


def test_a_protocol_switch_hands_the_rest_through():
    data = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n\x00\x01binary"
    pieces = framed(data, request=False)
    assert kinds(pieces) == [HEAD, END, FRAMING_ERROR, PASSTHROUGH]
    assert errors(pieces) == [PROTOCOL_SWITCHED]
    connect = framed(b"CONNECT h:443 HTTP/1.1\r\n\r\n\x16\x03", request=True)
    assert errors(connect) == [PROTOCOL_SWITCHED]


# -- together ------------------------------------------------------------------------------


def test_body_bytes_are_handed_on_as_they_arrive_and_never_held():
    framer = HttpFramer(request=False)
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    first = framer.feed(head + b"400\r\n" + b"d" * 300)
    assert [piece.kind for piece in first] == [HEAD, BODY]
    assert (first[-1].raw, first[-1].payload) == (b"400\r\n" + b"d" * 300, b"d" * 300)
    assert framer.buffered_bytes == 0
    for _ in range(100):  # 300 + 700 bytes of a chunk of 1024: each read goes on at once
        assert framer.feed(b"e" * 7) == [Piece(BODY, b"e" * 7, b"e" * 7)]
        assert framer.buffered_bytes == 0


def test_an_event_stream_through_both_framers_gives_the_same_events_however_it_is_cut():
    results = []
    for parts in splits(CHUNKED):
        http, sse = HttpFramer(request=False), SseFramer()
        found = []
        for part in parts:
            for piece in http.feed(part):
                found += sse.feed(piece.payload) if piece.kind == BODY else []
        found += sse.finish()
        results.append((found, sse.comments))
    assert all(result == results[0] for result in results[1:])
    found, comments = results[0]
    assert [(e.data, e.event_id) for e in found] == [(b'{"id":1}', "7")]
    assert comments == 0  # ":ping" ends the stream unfinished: dropped, as the standard has it


# -- the edge cases named for the transport ------------------------------------------------


def test_framing_header_names_compare_without_case():
    data = (
        b"POST /mcp HTTP/1.1\r\ncontent-LENGTH: 2\r\n\r\n{}"
        b"HTTP/1.1 200 OK\r\nTRANSFER-ENCODING: Chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
    )
    request = framed(data[: data.index(b"HTTP/1.1 200")], request=True)
    assert kinds(request) == [HEAD, BODY, END] and body_of(request) == b"{}"
    response = framed(data[data.index(b"HTTP/1.1 200") :], request=False)
    assert kinds(response) == [HEAD, BODY, END] and body_of(response) == b"{}"


def test_a_content_length_repeated_with_one_value_is_that_length():
    # RFC 9112, 6.3: a list of identical values is one length; differing ones are an error
    # (test_a_framing_error_switches_to_passthrough_and_keeps_every_byte).
    data = b"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2, 2\r\n\r\n{}"
    pieces = framed(data + b"GET / HTTP/1.1\r\n\r\n", request=True)
    assert kinds(pieces) == [HEAD, BODY, END, HEAD, END]
    assert body_of(pieces) == b"{}"


def test_transfer_codings_over_several_header_lines_are_read_in_order():
    last = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert kinds(framed(last + b"0\r\n\r\n", request=False)) == [HEAD, BODY, END]
    first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
    # chunked not last: the body runs to the close, and the chunk framing is not read.
    pieces = framed(first + b"0\r\n\r\n", request=False)
    assert kinds(pieces) == [HEAD, BODY, END] and body_of(pieces) == b"0\r\n\r\n"


def test_many_chunks_split_across_reads_give_their_data_whole():
    chunks = [bytes([65 + n % 26]) * (n % 7 + 1) for n in range(40)]
    body = b"".join(b"%x;n=%d\r\n%s\r\n" % (len(c), n, c) for n, c in enumerate(chunks))
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body + b"0\r\n\r\n"
    pieces = framed(data, request=False)
    assert kinds(pieces) == [HEAD, BODY, END]
    assert body_of(pieces) == b"".join(chunks)


def test_a_large_body_streams_through_without_being_held():
    size = 8 * 1024 * 1024
    head = b"POST /mcp HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % size
    framer = HttpFramer(request=True)
    pieces = framer.feed(head)
    held = 0
    for _ in range(size // 65536):
        pieces += framer.feed(b"x" * 65536)
        held = max(held, framer.buffered_bytes)
    pieces += framer.finish()
    assert held == 0
    assert sum(len(p.payload) for p in pieces if p.kind == BODY) == size
    assert [p.kind for p in pieces][-1] == END and pieces[-1].complete


def test_a_large_chunk_announced_in_one_line_streams_through():
    size = 3 * 1024 * 1024
    framer = HttpFramer(request=False)
    pieces = framer.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n" % size)
    for _ in range(size // 4096):
        pieces += framer.feed(b"y" * 4096)
        assert framer.buffered_bytes == 0
    pieces += framer.feed(b"\r\n0\r\n\r\n")
    assert sum(len(p.payload) for p in pieces if p.kind == BODY) == size
    assert pieces[-1].kind == END and pieces[-1].complete


# -- edge cases of framing ------------------------------------------------------------------


@pytest.mark.parametrize("encoding", [b"", b",", b" , "])
def test_an_empty_transfer_encoding_beside_a_content_length_is_still_a_conflict(encoding):
    data = b"POST / HTTP/1.1\r\nTransfer-Encoding: " + encoding + b"\r\nContent-Length: 3\r\n\r\n"
    pieces = framed(data + b"abcGET / HTTP/1.1\r\n\r\n", request=True)
    assert errors(pieces) == [CONFLICTING_LENGTH]


def test_an_empty_transfer_encoding_alone_is_no_coding_list():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ,\r\n\r\nabc"
    assert errors(framed(data, request=False)) == [UNSUPPORTED_TRANSFER_CODING]


def test_chunked_twice_is_an_error_in_a_response_too():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n"
    assert errors(framed(data, request=False)) == [UNSUPPORTED_TRANSFER_CODING]


def test_a_flood_of_empty_lines_or_tiny_chunks_comes_back_as_few_pieces():
    framer = HttpFramer(request=True)
    gaps = framer.feed(b"\r\n" * 100_000)
    assert [(p.kind, len(p.raw)) for p in gaps] == [(GAP, 200_000)]
    framer = HttpFramer(request=False)
    chunks = b"1\r\na\r\n" * 50_000
    pieces = framer.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks)
    assert [p.kind for p in pieces] == [HEAD, BODY]
    assert (len(pieces[1].raw), pieces[1].payload) == (len(chunks), b"a" * 50_000)


def test_a_trailer_section_is_held_to_the_same_bound_as_a_head():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
    fits = head + b"X: " + b"t" * 57 + b"\r\n\r\n"  # a trailer section of exactly 64 bytes
    assert kinds(framed(fits, request=False, max_head_bytes=64)) == [HEAD, BODY, END]
    over = head + b"X: " + b"t" * 58 + b"\r\n\r\n"
    assert errors(framed(over, request=False, max_head_bytes=64)) == [TRAILER_TOO_LARGE]


@pytest.mark.parametrize(
    "line", [b"3 \r\n", b"3;\x00\r\n", b"3;e=\x7f\r\n", b"3\r\r\n", b"1" * 17 + b"\r\n"]
)
def test_a_chunk_size_line_with_stray_bytes_or_too_many_digits_is_refused(line):
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + line + b"abc\r\n0\r\n\r\n"
    assert errors(framed(data, request=False)) == [BAD_CHUNK_SIZE]


def test_whitespace_before_a_chunk_extension_is_allowed():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3 ;ext\r\nabc\r\n0\r\n\r\n"
    pieces = framed(data, request=False)
    assert kinds(pieces) == [HEAD, BODY, END] and body_of(pieces) == b"abc"


def test_a_204_and_an_early_hint_have_no_body_and_what_follows_is_read():
    data = (
        b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n"
        b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
    )
    pieces = framed(data, request=False, expect=["POST", "POST"])
    assert [h.status for h in heads(pieces)] == [204, 103, 200]
    assert kinds(pieces) == [HEAD, END, HEAD, END, HEAD, BODY, END]


def test_a_successful_answer_to_connect_hands_the_rest_through():
    data = b"HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x01"
    pieces = framed(data, request=False, expect=["connect"])
    assert errors(pieces) == [PROTOCOL_SWITCHED]


def test_the_expected_method_is_read_without_case():
    data = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
    assert kinds(framed(data, request=False, expect=["head", "post"])) == [HEAD, END, HEAD, END]


@pytest.mark.parametrize("length", ["²", "1" * 20, "+5"])
def test_a_content_length_that_is_no_plain_number_is_refused_without_failing(length):
    data = (
        b"POST / HTTP/1.1\r\nContent-Length: " + length.encode("latin-1", "replace") + b"\r\n\r\n"
    )
    assert errors(framed(data, request=True)) == [BAD_CONTENT_LENGTH]


def test_a_trailer_with_more_fields_than_the_bound_is_a_framing_error():
    fields = b"".join(b"X-%d: 1\r\n" % n for n in range(4))
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n" + fields + b"\r\n"
    assert errors(framed(data, request=False, max_fields=3)) == [TOO_MANY_FIELDS]


def test_an_http_1_0_response_without_length_runs_to_the_close():
    pieces = framed(b"HTTP/1.0 200 OK\r\n\r\nall of it", request=False)
    assert kinds(pieces) == [HEAD, BODY, END] and body_of(pieces) == b"all of it"


@pytest.mark.parametrize(
    ("block", "is_request"),
    [(b"GET / HTTP/1.1\r\nX: a\x7fb\r\n\r\n", True), (b"GET /\x01 HTTP/1.1\r\n\r\n", True),
     (b"HTTP/1.1 200 O\x01K\r\n\r\n", False)],
)  # fmt: skip
def test_control_characters_in_a_head_are_refused(block, is_request):
    with pytest.raises(HeadError):
        parse_head(block, request=is_request)


# -- more edge cases -------------------------------------------------------------------------

SECRET = b"zqXv" + b"Jk7Wp" + b"Yb3Hn"


@pytest.mark.parametrize(
    ("data", "request_"),
    [
        (b"POST /mcp HTTP/1.1\r\nAuthorization : Bearer " + SECRET + b"\r\n\r\n", True),
        (b"POST /mcp HTTP/1.1\r\nAuthorization Bearer " + SECRET + b"\r\n\r\n", True),
        (b"POST /mcp HTTP/1.1\r\nX-" + SECRET + b"\x01: 1\r\n\r\n", True),
        (b"POST /mcp HTTP/1.1\r\nX-Token: a\x01" + SECRET + b"\r\n\r\n", True),
        (b"GET /mcp?access_token=" + SECRET + b" HTTP/1.1 x\r\n\r\n", True),
        (b"GET /mcp?access_token=" + SECRET + b"\x7f HTTP/1.1\r\n\r\n", True),
        (b"G" + SECRET + b"@ / HTTP/1.1\r\n\r\n", True),
        (b"GET / " + SECRET + b"\r\n\r\n", True),
        (b"HTTP/1.1 2" + SECRET + b" OK\r\n\r\n", False),
        (b"POST / HTTP/1.1\r\nContent-Length: 5, " + SECRET + b"\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: " + SECRET + b"\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: , \r\n\r\n", True),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + SECRET + b"\r\n", False),
    ],
)
def test_a_framing_errors_detail_carries_no_byte_of_the_traffic(data, request_):
    framer = HttpFramer(request=request_)
    pieces = framer.feed(data) + framer.finish()
    (error,) = [piece for piece in pieces if piece.kind == FRAMING_ERROR]
    assert error.detail and SECRET[:5].decode() not in error.detail
    for start in range(len(SECRET) - 4):
        assert SECRET[start : start + 5].decode() not in error.detail


def test_a_framing_errors_detail_is_short_whatever_the_head():
    data = b"POST / HTTP/1.1\r\nTransfer-Encoding: " + b"a," * 30_000 + b"\r\n\r\n"
    framer = HttpFramer(request=True)
    (error,) = [piece for piece in framer.feed(data) if piece.kind == FRAMING_ERROR]
    assert len(error.detail) <= 80


def test_the_detail_names_the_field_line_and_what_was_wrong():
    cases = {
        b"GET / HTTP/1.1\r\nA: 1\r\nB\r\n\r\n": "field line 2: no colon",
        b"GET / HTTP/1.1\r\n: 1\r\n\r\n": "field line 1: no name",
        b"GET / HTTP/1.1\r\nA B: 1\r\n\r\n": "field line 1: a byte outside tchar in the name",
        b"GET / HTTP/1.1\r\nA: 1\x00\r\n\r\n": "field line 1: a control character in the value",
        b"GET / HTTP/1.1\r\nA: 1\r\n\tb\r\n\r\n": "field line 2 continues the one before it",
        b"GET / HTTP/2.0\r\n\r\n": "not HTTP/1.0 or HTTP/1.1: HTTP/2.0",
        b"GET / HTTPS/1.1\r\n\r\n": "not HTTP/1.0 or HTTP/1.1: something else",
    }
    for data, detail in cases.items():
        with pytest.raises(HeadError) as raised:
            parse_head(data, request=True)
        assert raised.value.detail == detail


@pytest.mark.parametrize(
    "start",
    [b"GET  HTTP/1.1", b" / HTTP/1.1", b"GET /\x7f HTTP/1.1", b"GET / HTTP/1.1 x"],
)
def test_an_empty_or_broken_part_of_a_request_line_is_refused(start):
    with pytest.raises(HeadError) as raised:
        parse_head(start + b"\r\n\r\n", request=True)
    assert raised.value.reason == BAD_START_LINE


@pytest.mark.parametrize("status", [b"000", b"099", b"600", b"999"])
def test_a_status_outside_100_to_599_is_refused(status):
    with pytest.raises(HeadError) as raised:
        parse_head(b"HTTP/1.1 " + status + b" X\r\n\r\n", request=False)
    assert raised.value.reason == BAD_START_LINE
    for edge in (b"100", b"599"):
        assert parse_head(b"HTTP/1.1 " + edge + b" X\r\n\r\n", request=False).status


def test_a_tab_folds_a_line_and_surrounds_a_value_like_a_space():
    with pytest.raises(HeadError) as raised:
        parse_head(b"GET / HTTP/1.1\r\nA: 1\r\n\tb\r\n\r\n", request=True)
    assert raised.value.reason == OBSOLETE_LINE_FOLDING
    head = parse_head(b"GET / HTTP/1.1\r\nA:\t 1 \t\r\n\r\n", request=True)
    assert head.fields == (("A", "1"),)


def test_responses_are_matched_to_requests_in_order():
    data = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
    )
    pieces = framed(data, request=False, expect=("HEAD", "POST"))
    assert kinds(pieces) == [HEAD, END, HEAD, BODY, END]
    assert body_of(pieces) == b"{}"


def test_a_refused_connect_keeps_the_connection_http():
    data = (
        b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
    )
    pieces = framed(data, request=False, expect=("CONNECT", "GET"))
    assert kinds(pieces) == [HEAD, END, HEAD, BODY, END]
    pieces = framed(
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", request=False, expect=("CONNECT",)
    )
    assert kinds(pieces) == [HEAD, END]


def test_whitespace_before_a_chunk_size_is_refused_even_with_an_extension():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n  3;x\r\nabc\r\n0\r\n\r\n"
    assert errors(framed(data, request=False)) == [BAD_CHUNK_SIZE]


def test_the_chunk_line_bound_is_exact():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    line = b"1;" + b"x" * 6 + b"\r\n"  # ten bytes
    fits = framed(head + line + b"a\r\n0\r\n\r\n", request=False, max_chunk_line_bytes=10)
    assert errors(fits) == []
    over = framed(head + b"1;" + b"x" * 7 + b"\r\n", request=False, max_chunk_line_bytes=10)
    assert errors(over) == [CHUNK_LINE_TOO_LARGE]


def test_a_head_without_end_is_held_no_further_than_the_bound():
    framer = HttpFramer(request=True, max_head_bytes=64)
    framer.feed(b"GET / HTTP/1.1\r\n")
    for _ in range(100):
        framer.feed(b"X")
        assert framer.buffered_bytes <= 64 + 1


def test_a_lone_carriage_return_between_messages_is_part_of_the_gap():
    framer = HttpFramer(request=True)
    pieces = framer.feed(b"GET / HTTP/1.1\r\n\r\n\r") + framer.finish()
    assert [piece.kind for piece in pieces] == [HEAD, END, GAP]
    assert pieces[-1].raw == b"\r"
    assert framed(b"\r", request=True) == [(GAP, b"\r", b"")]


def test_a_framer_that_stops_advancing_passes_the_rest_through(monkeypatch):
    framer = HttpFramer(request=True)
    first = framer.feed(b"GET / HT")
    monkeypatch.setattr(HttpFramer, "_step", lambda self, data, position, pieces: position)
    pieces = framer.feed(b"TP/1.1\r\n\r\n")
    assert [piece.kind for piece in pieces] == [FRAMING_ERROR, PASSTHROUGH]
    assert pieces[0].reason == FRAMER_STALLED
    assert b"".join(piece.raw for piece in first + pieces) == b"GET / HTTP/1.1\r\n\r\n"
    later = framer.feed(b"more")
    assert [(piece.kind, piece.raw) for piece in later] == [(PASSTHROUGH, b"more")]
