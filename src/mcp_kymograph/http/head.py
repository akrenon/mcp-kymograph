"""HTTP/1.1 heads: the start line and the header fields, parsed from bytes, bounded.

A head is read whole before it is parsed — its end is an empty line, and the framer that
finds it holds at most :data:`MAX_HEAD_BYTES` of it (:mod:`mcp_kymograph.http.message`). Parsing
is strict where leniency is how one message is read as two (RFC 9112, 11.2: a space before a
field's colon, a folded line, a lone CR): what this module does not accept, the connection
passes through verbatim and the observer stops interpreting it. It never guesses.

Every refusal is a :class:`HeadError` with a fixed reason word and a detail for a person. The
detail says where and what kind of thing was wrong — a field line's number, a count, a class of
byte — and never carries a byte of the traffic: a head that does not parse can still hold a
credential (``Authorization : Bearer …`` is one byte away from a field line), and a detail is
meant to be recorded. It is short, whatever the head.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The most a head may occupy, start line and empty line included (docs/design/http-transport.md,
#: 2.2). Also the bound on a chunked message's trailer section.
MAX_HEAD_BYTES = 64 * 1024

#: The most header fields one head (or one trailer section) may carry.
MAX_FIELDS = 100

#: Versions this framer reads. Anything else — HTTP/2's preface included — is not HTTP/1.x.
VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1"})

#: RFC 9110 ``tchar``: what a method and a field name are made of.
TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

# -- the reason words a refusal carries -----------------------------------------------------

HEAD_TOO_LARGE = "head_too_large"
TOO_MANY_FIELDS = "too_many_fields"
BAD_START_LINE = "bad_start_line"
UNSUPPORTED_VERSION = "unsupported_version"
BAD_FIELD_LINE = "bad_field_line"
OBSOLETE_LINE_FOLDING = "obsolete_line_folding"
BAD_LINE_END = "bad_line_end"


class HeadError(ValueError):
    """A head this module does not read, with the reason word and what was wrong."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Head:
    """One parsed head. Field names as sent, values with surrounding whitespace removed.

    A request has ``method`` and ``target``; a response has ``status`` and ``reason``. Bytes
    are decoded as Latin-1, which maps every byte to one character and back.
    """

    version: str
    fields: tuple[tuple[str, str], ...]
    size_bytes: int
    method: str | None = None
    target: str | None = None
    status: int | None = None
    reason: str | None = None

    @property
    def is_request(self) -> bool:
        return self.method is not None

    def values(self, name: str) -> list[str]:
        """Every value of the named field, in order; names compare without case."""
        wanted = name.lower()
        return [value for field, value in self.fields if field.lower() == wanted]


def split_lines(block: bytes) -> list[bytes]:
    """Lines of a head, each without its end: CRLF or a bare LF (RFC 9112, 2.2), never a bare CR.

    The block ends with the empty line that closes the head, or ends without it; an empty
    last element from a final line end is not a line.
    """
    lines = block.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    out = []
    for line in lines:
        if line.endswith(b"\r"):
            line = line[:-1]
        if b"\r" in line:
            raise HeadError(BAD_LINE_END, "a carriage return that does not end a line")
        out.append(line)
    return out


def parse_fields(
    lines: list[bytes], *, max_fields: int = MAX_FIELDS
) -> tuple[tuple[str, str], ...]:
    """Field lines (RFC 9112, 5): ``name ":" OWS value OWS``, strictly."""
    if len(lines) > max_fields:
        raise HeadError(TOO_MANY_FIELDS, f"{len(lines)} fields, at most {max_fields}")
    fields = []
    for number, line in enumerate(lines, start=1):
        if line[:1] in (b" ", b"\t"):
            raise HeadError(
                OBSOLETE_LINE_FOLDING, f"field line {number} continues the one before it"
            )
        name, colon, value = line.partition(b":")
        if not colon:
            raise HeadError(BAD_FIELD_LINE, f"field line {number}: no colon")
        if not name:
            raise HeadError(BAD_FIELD_LINE, f"field line {number}: no name")
        if any(byte not in TCHAR for byte in name):
            raise HeadError(
                BAD_FIELD_LINE, f"field line {number}: a byte outside tchar in the name"
            )
        value = value.strip(b" \t")
        if any((byte < 0x20 and byte != 0x09) or byte == 0x7F for byte in value):
            raise HeadError(
                BAD_FIELD_LINE, f"field line {number}: a control character in the value"
            )
        fields.append((name.decode("latin-1"), value.decode("latin-1")))
    return tuple(fields)


def parse_head(
    block: bytes,
    *,
    request: bool,
    max_fields: int = MAX_FIELDS,
    max_head_bytes: int = MAX_HEAD_BYTES,
) -> Head:
    """Parse one head: a request's (``request=True``) or a response's.

    ``block`` runs from the start line to the empty line that ends the head, both included;
    empty lines before the start line belong to the gap between messages, not to it.
    """
    if len(block) > max_head_bytes:
        raise HeadError(HEAD_TOO_LARGE, f"{len(block)} bytes, at most {max_head_bytes}")
    lines = split_lines(block)
    while lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        raise HeadError(BAD_START_LINE, "no start line")
    start, rest = lines[0], lines[1:]
    fields = parse_fields(rest, max_fields=max_fields)
    if request:
        parts = start.split(b" ")
        if len(parts) != 3:
            raise HeadError(BAD_START_LINE, f"a request line of {min(len(parts), 99)} parts, not 3")
        method, target, version = parts
        if not method or not target:
            raise HeadError(BAD_START_LINE, "an empty method or request target")
        if any(byte not in TCHAR for byte in method):
            raise HeadError(BAD_START_LINE, "a byte outside tchar in the method")
        if any(byte <= 0x20 or byte == 0x7F for byte in target):
            raise HeadError(BAD_START_LINE, "a control character in the request target")
        _check_version(version)
        return Head(
            version=version.decode("latin-1"),
            fields=fields,
            size_bytes=len(block),
            method=method.decode("latin-1"),
            target=target.decode("latin-1"),
        )
    version, _, remainder = start.partition(b" ")
    _check_version(version)
    status, _, reason = remainder.partition(b" ")
    # RFC 9110, 15: three digits, and values outside 100..599 are invalid.
    if len(status) != 3 or not status.isdigit() or not 100 <= int(status) <= 599:
        raise HeadError(BAD_START_LINE, "a status that is not three digits from 100 to 599")
    if any((byte < 0x20 and byte != 0x09) or byte == 0x7F for byte in reason):
        raise HeadError(BAD_START_LINE, "a control character in the reason phrase")
    return Head(
        version=version.decode("latin-1"),
        fields=fields,
        size_bytes=len(block),
        status=int(status),
        reason=reason.decode("latin-1"),
    )


def _check_version(version: bytes) -> None:
    if version.decode("latin-1") not in VERSIONS:
        # A version of HTTP's own shape is named; anything else may be anything.
        named = version.decode() if _VERSION_SHAPE.fullmatch(version) else "something else"
        raise HeadError(UNSUPPORTED_VERSION, f"not HTTP/1.0 or HTTP/1.1: {named}")


_VERSION_SHAPE = re.compile(rb"HTTP/[0-9]\.[0-9]")
