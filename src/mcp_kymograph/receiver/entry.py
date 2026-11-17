"""Turning one request into one entry — the only place that decides what is kept.

An entry holds names, sizes and keyed digests. A value of a header, a query parameter or the
body never reaches the returned dictionary, so it cannot reach a file: the digests are the
only trace, and they are HMAC-SHA-256 under the registration's key, which the audited server
never saw.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

from . import limits
from .store import Registration

#: Headers whose presence is recorded with a digest, whatever the registration says.
ALWAYS_SECRET = ("authorization", "proxy-authorization", "cookie")
_SCHEME_RE = re.compile(r"^([A-Za-z]+)[ \t]+\S")
_NAME_RE = re.compile(
    rf"[A-Za-z][A-Za-z_.-]{{0,{limits.MAX_NAME_CHARS - 1 - limits.MAX_NAME_DIGITS}}}"
    rf"[0-9]{{0,{limits.MAX_NAME_DIGITS}}}"
)
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]+")
#: Query name under which the HMAC of the elements without a usable name is kept.
UNNAMED = "(unnamed)"
MAX_PORT = 65535


@dataclass
class Request:
    method: str
    target: str
    #: Header (name, value) pairs in the order received; values decoded as latin-1.
    headers: list[tuple[str, str]]
    body: bytes
    #: Whether the body was cut at ``MAX_BODY_BYTES``.
    truncated: bool
    sender: str
    scheme: str


def digest(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def is_name(text: str) -> bool:
    """Whether text looks like a name: a letter, then letters and ``_ . -``, then up to 3 digits.

    At most ``MAX_NAME_CHARS`` characters. Digits come only at the end, so a hex string, a UUID,
    a number or a base64url token is not a name.
    """
    return _NAME_RE.fullmatch(text) is not None


def is_header_name(text: str) -> bool:
    """Whether a header name is stored: letters, digits and ``-``, at most 64 characters."""
    return len(text) <= limits.MAX_HEADER_NAME_CHARS and _HEADER_NAME_RE.fullmatch(text) is not None


def count_invalid_header_names(headers: list[tuple[str, str]]) -> int:
    return sum(1 for name, _ in headers if not is_header_name(name))


def _decoded(text: str) -> bytes:
    return unquote(text, errors="surrogateescape").encode("utf-8", "surrogateescape")


def mask_names(key: bytes, pieces: list[str], separator: str, decode: bool) -> str:
    """``pieces`` joined by ``separator``; each run of pieces that are not names is one HMAC.

    An empty piece and a name are kept as they came. A run of other pieces becomes
    ``hmac:<hex>`` over the run, joined by ``separator``. At most ``MAX_STORED_PARTS`` parts are
    kept: the ones past the limit are one HMAC together, so the result never grows with the
    number of pieces. ``decode`` percent-decodes the pieces before they are hashed.
    """
    parts: list[str | list[str]] = []
    for piece in pieces:
        if piece == "" or is_name(piece):
            parts.append(piece)
        elif parts and isinstance(parts[-1], list):
            parts[-1].append(piece)
        else:
            parts.append([piece])
    if len(parts) > limits.MAX_STORED_PARTS:
        rest = parts[limits.MAX_STORED_PARTS - 1 :]
        parts = [
            *parts[: limits.MAX_STORED_PARTS - 1],
            [piece for part in rest for piece in ([part] if isinstance(part, str) else part)],
        ]
    texts = []
    for part in parts:
        if isinstance(part, str):
            texts.append(part)
            continue
        joined = separator.join(part)
        material = _decoded(joined) if decode else joined.encode("utf-8", "surrogateescape")
        texts.append("hmac:" + digest(key, material))
    return separator.join(texts)


def query_parameters(key: bytes, query: str) -> dict[str, list[str]]:
    """Name -> HMACs of the values. Only a name followed by ``=`` is kept as a name.

    The server chooses these names, so one that does not look like a name (or an element without
    ``=``) is a value in the wrong place. Those elements, decoded and joined by ``&``, are one
    HMAC under ``UNNAMED``. At most ``MAX_STORED_PARTS`` parts are stored; a named element past
    the limit goes into the ``UNNAMED`` HMAC as well.
    """
    params: dict[str, list[str]] = {}
    unnamed: list[str] = []
    stored = 0
    for element in query.split("&"):
        if not element:
            continue
        name, equals, value = element.partition("=")
        name = unquote_plus(name, errors="surrogateescape")
        if equals and is_name(name) and stored < limits.MAX_STORED_PARTS - 1:
            text = unquote_plus(value, errors="surrogateescape")
            params.setdefault(name, []).append(digest(key, text.encode("utf-8", "surrogateescape")))
            stored += 1
        else:
            unnamed.append(unquote_plus(element, errors="surrogateescape"))
    if unnamed:
        params[UNNAMED] = [digest(key, "&".join(unnamed).encode("utf-8", "surrogateescape"))]
    return params


def path_segments(key: bytes, rest: str) -> str:
    """``rest`` with each run of segments that are not names replaced by one ``hmac:<hex>``."""
    return mask_names(key, rest.split("/"), "/", decode=True)


def host_labels(key: bytes, host: str) -> str:
    """The ``Host`` value with the labels that are not names hashed, and a port kept as a number."""
    name, colon, port = host.rpartition(":")
    # The length comes before any conversion: ``int`` of thousands of digits raises.
    if (
        colon
        and 1 <= len(port) <= 5
        and port.isascii()
        and port.isdigit()
        and int(port) <= MAX_PORT
    ):
        return mask_names(key, name.split("."), ".", decode=False) + ":" + port
    return mask_names(key, host.split("."), ".", decode=False)


def split_target(target: str) -> tuple[str, str]:
    path, _, query = target.partition("?")
    return path, query.partition("#")[0]


def route(target: str) -> tuple[str, str] | None:
    """``/<prefix>/<rest>`` as (prefix, rest); anything else is None."""
    path, _ = split_target(target)
    if not path.startswith("/"):
        return None
    prefix, slash, rest = path[1:].partition("/")
    return (prefix, rest) if slash else None


def scheme_of(value: str) -> str | None:
    """The first word of an ``Authorization`` value, when it is letters followed by credentials.

    A value that is one bare word is the credential itself, not a scheme, and is not kept.
    """
    found = _SCHEME_RE.match(value)
    if found and len(found.group(1)) <= limits.MAX_SCHEME_CHARS:
        return found.group(1)
    return None


def build_entry(reg: Registration, request: Request, rest: str) -> dict[str, object]:
    names: list[str] = []
    values: dict[str, list[str]] = {}
    for name, value in request.headers:
        if name not in names and is_header_name(name):
            names.append(name)
        values.setdefault(name.lower(), []).append(value)

    secret = {}
    for name in dict.fromkeys((*ALWAYS_SECRET, *reg.secret_headers)):
        if name not in values:
            continue
        whole = ", ".join(values[name])
        secret[name] = {
            "present": True,
            "scheme": scheme_of(values[name][0]) if name == "authorization" else None,
            "hmac": digest(reg.key, whole.encode("latin-1", "replace")),
        }

    value = next((v for n, v in request.headers if n.lower() == "host"), None)
    host = None if value is None else host_labels(reg.key, value)
    _, query = split_target(request.target)
    params = query_parameters(reg.key, query)

    return {
        "sender": request.sender,
        "scheme": request.scheme,
        "method": request.method,
        "host": host,
        "path": path_segments(reg.key, rest),
        "query": params,
        "headers": names,
        "secret_headers": secret,
        "body": {
            "size": len(request.body),
            "sha256": hashlib.sha256(request.body).hexdigest(),
            "truncated": request.truncated,
        },
    }
