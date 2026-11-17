"""The web interface's HTTP server: routes, refusals, headers and the static files.

It decides nothing about content. A route names a function of :mod:`mcp_kymograph.web.views`
and its parameters; the server checks that the parameters are there and well-formed, calls the
function and serialises what it returns. Everything else is about who may ask.

**What it shows is sensitive, and a browser is not on its side.** Recordings hold hostile
traffic and whatever the operator's servers said; any web page the operator has open could try
to read them. So the server listens on a loopback address only, answers ``GET`` and ``HEAD``
only, refuses a ``Host`` that is not its own (a page that rebinds a name of its own to
127.0.0.1 sends its own name) and an ``Origin`` that is not its own, and puts the same security
headers on every answer, refusals included: a page of another origin can neither read an answer
nor frame the interface, and the interface itself can load nothing from anywhere else.

**A start token, then a session cookie; no TLS.** Listening on loopback keeps out the network,
not another local user's process nor a page in the operator's browser. So the server draws a
*token* at start and prints it in the start address only; a ``GET`` of that address is
exchanged for a cookie holding a second random value, the *session*, and every other request
needs the cookie. Neither value is in any answer (but the one ``Set-Cookie``), on stderr (but
the start line) or in a file. It is still a local viewer for the operator at one machine with
one user (docs/web.md), and says so when it starts: no TLS.

**Nothing in the answer about what went wrong inside.** A view that fails is a 500 with words
that name no detail; the traceback goes to stderr, made safe for a terminal first, since a
view's failure can carry a string that came off the wire.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
import socketserver
import sys
import traceback
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote

from mcp_kymograph.web import views as _views
from mcp_kymograph.web.views import Sources, ViewError

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

#: How long a connection may sit idle on a read or a write before it is dropped, in seconds: a
#: slow client cannot hold a thread for longer than this per step.
HANDLER_TIMEOUT = 10.0

#: The one address the server may listen on, written so. The interface has sets of its own,
#: narrower than :data:`~mcp_kymograph.authorization.LOOPBACK_LITERALS` and ``LOCAL_TARGETS``,
#: which other parts of the tool use to tell what is local when they decide about a target:
#: there a wider set is harmless. Here every further address would be one more place a browser
#: sends the cookie to, and one more a local process can reach, so it is ``127.0.0.1`` alone.
BIND_LITERALS = frozenset({"127.0.0.1"})

#: The names a ``Host`` header may give, each with the bound port.
HOST_NAMES = frozenset({"127.0.0.1", "localhost"})

#: What a request without the session is told, whatever was missing or wrong.
SESSION_WORDS = "refused: open the address printed when the interface started"

#: The most items one page of messages may ask for (CONTRACT.md, section 6).
MAX_LIMIT = 500
#: The page of messages when none is asked for.
DEFAULT_OFFSET = 0
DEFAULT_LIMIT = 100

#: At most this many parameters in a query string; no route takes more than three.
MAX_FIELDS = 8
#: An integer parameter longer than this is not one any view could look up.
MAX_DIGITS = 18

#: On every answer, refusals included (CONTRACT.md, section 8). No CORS header, ever.
SECURITY_HEADERS = (
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)

JSON_TYPE = "application/json; charset=utf-8"

#: What a download is served as, whatever it holds: bytes to be saved, never shown or run.
DOWNLOAD_TYPE = "application/octet-stream"

#: The statuses a view may refuse with: a parameter malformed or naming nothing, and a file
#: asked for as a download that is not served as it stands (CONTRACT.md, section 3).
VIEW_STATUSES = (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.CONFLICT)

#: The characters a download's name keeps in the plain ``filename``; any other is ``_``. The
#: name as it is goes in ``filename*``, percent-encoded.
_PLAIN_NAME = re.compile(r"[^A-Za-z0-9._-]")

#: What a static file may be, by its suffix: an explicit map, anything else is not served.
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".png": "image/png",
}

#: A static file's name, which is also the last part of its address: nothing a browser would
#: percent-encode, no leading dot, no separator. A file named otherwise is not served.
_STATIC_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_DIGITS = re.compile(r"[0-9]+")

#: Where the static files are, besides ``/<name>``: by exact name under this prefix or at the
#: root, never by a path.
STATIC_PREFIX = "/static/"
INDEX = "index.html"

ALLOWED_METHODS = ("GET", "HEAD")

#: The categories ``cli.display`` drops for the terminal: controls, format characters (zero-width
#: and bidi overrides), surrogates, private use, unassigned.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

#: The words of the refusals the server makes itself; none of them repeats the request.
_WORDS = {
    HTTPStatus.BAD_REQUEST: "refused: the request is malformed",
    HTTPStatus.FORBIDDEN: "refused: a request from another origin than this interface's own",
    HTTPStatus.NOT_FOUND: "nothing here: no view and no file of the interface at this address",
    HTTPStatus.CONFLICT: "not served: the file is not the one that was checked",
    HTTPStatus.METHOD_NOT_ALLOWED: "refused: this interface answers GET and HEAD only",
    HTTPStatus.MISDIRECTED_REQUEST: (
        "refused: the Host header names another server than this one (DNS rebinding is refused)"
    ),
    HTTPStatus.REQUEST_URI_TOO_LONG: "refused: the request line is too long",
    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE: "refused: the request's headers are too large",
    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED: "refused: this interface speaks HTTP/1.0 and 1.1",
    HTTPStatus.INTERNAL_SERVER_ERROR: (
        "the view failed; what went wrong is on the server's stderr, not here"
    ),
}

#: The ``kind`` of the error envelope per status. 400 and 404 are the contract's (section 3);
#: the others are the server's own refusals.
_KINDS = {
    HTTPStatus.BAD_REQUEST: "bad_request",
    HTTPStatus.FORBIDDEN: "forbidden",
    HTTPStatus.NOT_FOUND: "not_found",
    HTTPStatus.CONFLICT: "conflict",
    HTTPStatus.METHOD_NOT_ALLOWED: "method_not_allowed",
    HTTPStatus.MISDIRECTED_REQUEST: "misdirected_request",
    HTTPStatus.INTERNAL_SERVER_ERROR: "internal_error",
}


def loopback(text: str) -> ipaddress.IPv4Address:
    """The address to listen on: ``127.0.0.1`` (:data:`BIND_LITERALS`), exactly as written.

    Refused (``ValueError``, with the words) is everything else: a name, ``localhost`` included
    — what it resolves to is the resolver's choice, not the operator's —, an unspecified address
    (``0.0.0.0``, ``::``), any other address, the rest of 127.0.0.0/8 (``127.0.0.2``) among them,
    and every IPv6 address, ``::1`` included. The text is compared as a string and nothing is
    normalised: telling two spellings equal means interpreting them, and a rule that only
    narrows can afford to refuse a spelling that would have reached the same address.
    """
    if text not in BIND_LITERALS:
        raise ValueError(f"must be 127.0.0.1, not {text!r}")
    return ipaddress.IPv4Address(text)


def _printable(text: str) -> str:
    return "".join(c for c in text if unicodedata.category(c) not in _UNSAFE_CATEGORIES)


def _cookie_values(headers: list[str], name: str) -> list[bytes]:
    """The values of the cookies called ``name`` in the ``Cookie`` headers, as bytes. Any other
    cookie is skipped and a piece that is no ``name=value`` is ignored, so no header can fail
    this; every piece is looked at, so two cookies of the one name are two values."""
    found = []
    for header in headers:
        for piece in header.split(";"):
            key, separator, value = piece.partition("=")
            if separator and key.strip() == name:
                found.append(value.strip().encode("latin-1", "replace"))
    return found


def _report(lines: str) -> None:
    """Write to stderr what an answer must not carry, each line made safe for a terminal."""
    stream = sys.stderr
    if stream is None:
        return
    try:
        for line in lines.splitlines():
            stream.write(f"kymograph: {_printable(line)}\n")
        stream.flush()
    except (OSError, ValueError):
        pass


# -- routes ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Parameter:
    """One query parameter: its name in the query, whether it is an integer, and what it is
    when it is not given (``required`` when it must be)."""

    name: str
    integer: bool = False
    required: bool = True
    default: Any = None
    maximum: int | None = None


@dataclass(frozen=True)
class Route:
    """A path and the view function it calls, with its parameters in the function's order."""

    function: str
    parameters: tuple[Parameter, ...] = ()
    #: Restricts a string parameter to these values (``provenance``).
    choices: Mapping[str, tuple[str, ...]] | None = None
    #: The function returns a :class:`~mcp_kymograph.web.views.Download`, served as an
    #: attachment, not an envelope.
    download: bool = False


_REF = Parameter("ref")
_INDEX = Parameter("i", integer=True)
_FINDING = Parameter("finding", integer=True)

#: CONTRACT.md, section 6. ``/api/corpus`` is two routes, told apart by whether ``i`` is given.
ROUTES: dict[str, Route] = {
    "/api/about": Route("about"),
    "/api/runs": Route("runs"),
    "/api/run": Route("run", (_REF,)),
    "/api/run/messages": Route(
        "messages",
        (
            _REF,
            Parameter("offset", integer=True, required=False, default=DEFAULT_OFFSET),
            Parameter(
                "limit", integer=True, required=False, default=DEFAULT_LIMIT, maximum=MAX_LIMIT
            ),
        ),
    ),
    "/api/run/message": Route("message", (_REF, Parameter("seq", integer=True))),
    "/api/store/runs": Route("store_runs"),
    "/api/store/findings": Route(
        "store_findings",
        (Parameter("provenance"),),
        choices={"provenance": ("reference", "poison")},
    ),
    "/api/store/candidates": Route("store_candidates"),
    "/api/store/diff": Route("store_diff", (Parameter("before"), Parameter("after"))),
    "/api/fleets": Route("fleets"),
    "/api/fleet": Route("fleet", (Parameter("id"),)),
    "/api/fleets/compare": Route(
        "fleet_compare",
        (Parameter("before", required=False), Parameter("after", required=False)),
    ),
    "/api/corpus": Route("corpora"),
    "/api/scenarios": Route("scenarios"),
    "/api/scenario": Route("scenario", (_INDEX,)),
    "/api/signals": Route("signals"),
    "/api/store/engagement": Route("store_engagement"),
    "/api/store/triage": Route("triage"),
    "/api/store/triage/history": Route("triage_history", (_FINDING,)),
    "/api/store/triage/review": Route("triage_review", (_FINDING,)),
    "/api/bundles": Route("bundles"),
    "/api/bundle": Route("bundle", (_INDEX,)),
    "/api/bundle/file": Route("bundle_file", (_INDEX, Parameter("path")), download=True),
    "/api/attestations": Route("attestations"),
    "/api/attestation": Route("attestation", (_INDEX,)),
    "/api/attestation/file": Route("attestation_file", (_INDEX,), download=True),
}
_CORPUS = Route("corpus", (_INDEX,))


class _BadRequest(Exception):
    """A query the route cannot take; its words go into the 400."""


def _arguments(route: Route, query: str) -> list[Any]:
    """The route's parameters from the query string, in the function's order, or refused."""
    try:
        given = parse_qs(
            query,
            keep_blank_values=True,
            strict_parsing=True,
            errors="strict",
            max_num_fields=MAX_FIELDS,
        )
    except (ValueError, UnicodeDecodeError):
        raise _BadRequest("the query string is malformed") from None
    names = {parameter.name for parameter in route.parameters}
    unknown = sorted(set(given) - names)
    if unknown:
        allowed = ", ".join(sorted(names)) or "none"
        raise _BadRequest(f"unknown parameter {unknown[0]!r} (this view takes: {allowed})")
    arguments = []
    for parameter in route.parameters:
        values = given.get(parameter.name)
        if values is None:
            if parameter.required:
                raise _BadRequest(f"parameter {parameter.name!r} is required")
            arguments.append(parameter.default)
            continue
        if len(values) != 1:
            raise _BadRequest(f"parameter {parameter.name!r} is given more than once")
        value = values[0]
        if parameter.integer:
            if not _DIGITS.fullmatch(value) or len(value) > MAX_DIGITS:
                raise _BadRequest(f"parameter {parameter.name!r} must be a whole number, 0 or more")
            number = int(value)
            if parameter.maximum is not None and number > parameter.maximum:
                raise _BadRequest(
                    f"parameter {parameter.name!r} must be at most {parameter.maximum}"
                )
            arguments.append(number)
            continue
        choices = (route.choices or {}).get(parameter.name)
        if choices is not None and value not in choices:
            raise _BadRequest(
                f"parameter {parameter.name!r} must be one of {', '.join(choices)}"
                + (
                    "; real-world findings are disclosure candidates, at /api/store/candidates"
                    if parameter.name == "provenance"
                    else ""
                )
            )
        arguments.append(value)
    return arguments


def _query_names(query: str) -> set[str]:
    try:
        return set(parse_qs(query, keep_blank_values=True))
    except ValueError:
        return set()


def _route(path: str, query: str) -> Route | None:
    if path == "/api/corpus" and query:
        try:
            given = parse_qs(query, keep_blank_values=True)
        except ValueError:
            given = {}
        if "i" in given:
            return _CORPUS
    return ROUTES.get(path)


# -- downloads -------------------------------------------------------------------------


def _download(answer: Any) -> tuple[str, bytes]:
    """The name and the bytes of a download, as the view gave them; anything else is a fault
    of the view (500)."""
    name, body = getattr(answer, "name", None), getattr(answer, "body", None)
    if not isinstance(name, str) or not isinstance(body, bytes):
        raise TypeError(f"a download route's view gave {type(answer).__name__}, not a Download")
    return name, body


def _attachment(name: str) -> str:
    """``Content-Disposition`` for a download: always an attachment, never shown inline. The
    plain ``filename`` holds only ``[A-Za-z0-9._-]``; ``filename*`` the name as it is,
    percent-encoded — so no name can end the header or add another."""
    plain = _PLAIN_NAME.sub("_", name).lstrip(".") or "download"
    return f"attachment; filename=\"{plain}\"; filename*=UTF-8''{quote(name, safe='')}"


# -- static files ----------------------------------------------------------------------


def _static_directory() -> Traversable:
    return resources.files("mcp_kymograph.web") / "static"


def static_files(directory: Traversable | Path | None = None) -> dict[str, Traversable]:
    """The files the interface serves, by name: the regular files directly in ``directory``
    (``web/static/`` by default) whose name is plain and whose suffix is in
    :data:`STATIC_TYPES`. Listed once, when the server starts; nothing else is ever opened."""
    directory = _static_directory() if directory is None else directory
    if not directory.is_dir():
        return {}
    found: dict[str, Traversable] = {}
    for entry in directory.iterdir():
        name = entry.name
        if not _STATIC_NAME.fullmatch(name) or Path(name).suffix not in STATIC_TYPES:
            continue
        if isinstance(entry, Path):
            if entry.is_symlink() or not entry.is_file():
                continue
        elif not entry.is_file():
            continue
        found[name] = entry
    return found


# -- the server ------------------------------------------------------------------------


class Server(ThreadingHTTPServer):
    """A threading HTTP server on one loopback address, holding what its views read."""

    daemon_threads = True
    allow_reuse_port = False

    def __init__(
        self,
        address: ipaddress.IPv4Address,
        port: int,
        *,
        sources: Sources,
        views: Any,
        static: Mapping[str, Traversable],
    ) -> None:
        #: Drawn at start. The token is printed in the start address, the session never; both
        #: are read by the CLI and the tests, and are in no answer but the one ``Set-Cookie``.
        self.token = secrets.token_urlsafe(32)
        self.session = secrets.token_urlsafe(32)
        self.sources = sources
        self.views = views
        self.static = dict(static)
        self.address = address
        super().__init__((str(address), port), _Handler)
        self.port = self.server_address[1]
        #: The cookie's name: the port in it, so two interfaces at once keep their own.
        self.cookie_name = f"kymograph-{self.port}"
        hosts = {f"{name}:{self.port}" for name in HOST_NAMES}
        if self.port == 80:
            hosts |= HOST_NAMES  # a browser leaves the default port out
        #: Host header values that name this server; an Origin must be ``http://`` + one of
        #: them, and the one the request came by.
        self.hosts = frozenset(hosts)
        self.url = f"http://{address}:{self.port}/"
        #: The address to open: the one place the token is printed.
        self.start_url = f"{self.url}?token={self.token}"

    def server_bind(self) -> None:
        # HTTPServer.server_bind asks the resolver for the address's name (socket.getfqdn): a
        # lookup the server has no use for. It fetches nothing.
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = self.server_address[1]

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A client that went away is not worth a line; anything else is a fault of ours.
        error = sys.exc_info()[1]
        if isinstance(error, OSError):
            return
        _report("internal error while answering a request:\n" + traceback.format_exc())


def make_server(
    sources: Sources,
    bind: str,
    port: int,
    *,
    views: Any = _views,
    static: Traversable | Path | None = None,
) -> Server:
    """The server for ``sources`` on ``bind``:``port`` (0 for any free port), not yet serving.

    ``views`` is the module (or a stand-in with the same functions) the routes call; ``static``
    the directory of the page's files, ``web/static/`` by default. A ``bind`` that is not a
    ``127.0.0.1`` is refused (``ValueError``); a port that cannot be had raises ``OSError``.
    """
    address = loopback(bind)
    if not 0 <= port <= 65535:
        raise ValueError(f"must be a port number from 0 to 65535, not {port}")
    return Server(address, port, sources=sources, views=views, static=static_files(static))


class _Handler(BaseHTTPRequestHandler):
    server: Server
    timeout = HANDLER_TIMEOUT
    server_version = "mcp-kymograph"

    def version_string(self) -> str:
        """The ``Server`` header: the name, not the interpreter's version."""
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        """No request log: what was asked for is the operator's business, not the terminal's,
        and a request line may hold the token. ``log_error`` ends here too, and
        :meth:`send_error` is overridden and says nothing of the request."""

    def handle_one_request(self) -> None:
        """One request, as the base class reads it — but every method reaches :meth:`_answer`,
        so a method other than GET and HEAD is a 405 with the headers, not a bare 501."""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            words = self.raw_requestline.split()
            if len(words) == 2 and words[0] == b"GET":
                # An HTTP/0.9 GET: no headers to read, and an answer would have none to carry
                # the security headers in, so it gets none, at once. Up to Python 3.13,
                # parse_request would first wait for headers that never come.
                self.close_connection = True
                return
            if not self.parse_request():
                return
            if self.request_version == "HTTP/0.9":
                # An HTTP/0.9 answer has no headers to carry the security headers in: none.
                self.close_connection = True
                return
            self._answer()
            self.wfile.flush()
        except TimeoutError:
            self.close_connection = True

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """The base class's refusals (a malformed request line, too many headers), in the
        error envelope and with the headers; the request is not repeated in them."""
        self.close_connection = True
        self._error(HTTPStatus(code))

    # -- answering -----------------------------------------------------------------

    def _answer(self) -> None:
        # The order: Host (421), method (405), Origin (403), session (403), then the route.
        host = self._host()
        if host is None:
            self._error(HTTPStatus.MISDIRECTED_REQUEST)
            return
        if self.command not in ALLOWED_METHODS:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, ("Allow", ", ".join(ALLOWED_METHODS)))
            return
        if not self._origin_is_own(host):
            self._error(HTTPStatus.FORBIDDEN)
            return
        path, _, query = self.path.partition("?")
        if path == "/" and self._is_token(query):
            self._exchange()
            return
        if not self._has_session():
            self._error(HTTPStatus.FORBIDDEN, words=SESSION_WORDS)
            return
        if not self.path.startswith("/"):
            self._error(HTTPStatus.BAD_REQUEST)
            return
        route = _route(path, query)
        if route is not None:
            self._view(route, query)
            return
        if "token" in _query_names(query):
            # The token is good in the start address only; anywhere else it is a parameter
            # no address takes.
            self._error(
                HTTPStatus.BAD_REQUEST,
                words="unknown parameter 'token' (this view takes: none)",
            )
            return
        if path == "/":
            self._static(INDEX)
            return
        if path.startswith(STATIC_PREFIX):
            self._static(path[len(STATIC_PREFIX) :])
            return
        # The page refers to its files relative to itself (``app.css`` from ``/``): each listed
        # file is at ``/<name>`` too, looked up by the same exact name.
        self._static(path[1:])

    def _host(self) -> str | None:
        """The request's ``Host``, lower-cased, if it is exactly one and names this server."""
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0].strip().lower() not in self.server.hosts:
            return None
        return hosts[0].strip().lower()

    def _origin_is_own(self, host: str) -> bool:
        """No ``Origin``, or exactly one that is ``http://`` and the request's own Host."""
        origins = self.headers.get_all("Origin") or []
        if not origins:
            return True
        return len(origins) == 1 and origins[0].strip().lower() == "http://" + host

    def _is_token(self, query: str) -> bool:
        """Whether the query is exactly ``token=<the token>``, compared as bytes in constant
        time."""
        expected = b"token=" + self.server.token.encode("ascii")
        return hmac.compare_digest(query.encode("latin-1", "replace"), expected)

    def _has_session(self) -> bool:
        """Whether there is exactly one cookie of this server's name and it holds the session.
        Other cookies are not looked at; a header that cannot be read as cookies has none."""
        values = _cookie_values(self.headers.get_all("Cookie") or [], self.server.cookie_name)
        session = self.server.session.encode("ascii")
        return len(values) == 1 and hmac.compare_digest(values[0], session)

    def _exchange(self) -> None:
        """The token, in the start address: 303 to ``/`` and the session as a cookie. May be
        repeated and sets the same session."""
        name, session = self.server.cookie_name, self.server.session
        cookie = f"{name}={session}; Path=/; HttpOnly; SameSite=Strict"
        self._send(HTTPStatus.SEE_OTHER, b"", JSON_TYPE, ("Location", "/"), ("Set-Cookie", cookie))

    def _view(self, route: Route, query: str) -> None:
        try:
            arguments = _arguments(route, query)
        except _BadRequest as refusal:
            self._error(HTTPStatus.BAD_REQUEST, words=str(refusal))
            return
        function: Callable[..., Any] = getattr(self.server.views, route.function)
        try:
            answer = function(self.server.sources, *arguments)
            if route.download:
                name, body = _download(answer)
            else:
                body = json.dumps(answer, ensure_ascii=True, allow_nan=False).encode("ascii")
        except ViewError as refusal:
            if refusal.status in VIEW_STATUSES:
                self._error(HTTPStatus(refusal.status), words=str(refusal.words))
                return
            _report(
                f"view {route.function} refused with status {refusal.status!r}, which is "
                f"not 400, 404 or 409: {refusal.words}"
            )
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        except Exception:
            _report(f"view {route.function} failed:\n" + traceback.format_exc())
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if route.download:
            self._send(
                HTTPStatus.OK, body, DOWNLOAD_TYPE, ("Content-Disposition", _attachment(name))
            )
            return
        self._send(HTTPStatus.OK, body, JSON_TYPE)

    def _static(self, name: str) -> None:
        entry = self.server.static.get(name)
        # Listed at the start and read now, so a page being worked on is served as it is; a
        # listed file that has since become a symbolic link is not followed.
        if entry is None or (isinstance(entry, Path) and entry.is_symlink()):
            self._error(HTTPStatus.NOT_FOUND)
            return
        try:
            body = entry.read_bytes()
        except OSError:
            self._error(HTTPStatus.NOT_FOUND)
            return
        self._send(HTTPStatus.OK, body, STATIC_TYPES[Path(name).suffix])

    def _error(self, status: HTTPStatus, *extra: tuple[str, str], words: str | None = None) -> None:
        envelope = {
            "view": "error",
            "notices": [
                {
                    "kind": _KINDS.get(status, "bad_request"),
                    "text": _WORDS.get(status, _WORDS[HTTPStatus.BAD_REQUEST])
                    if words is None
                    else words,
                }
            ],
            "data": None,
        }
        body = json.dumps(envelope, ensure_ascii=True).encode("ascii")
        self._send(status, body, JSON_TYPE, *extra)

    def _send(self, status: HTTPStatus, body: bytes, content_type: str, *extra: tuple[str, str]):
        # Every answer goes out with a status line and the headers. The base class writes
        # neither for HTTP/0.9, and up to Python 3.13 parse_request refuses a malformed request
        # line (one word, a two-word line with another method than GET) while request_version
        # is still its default, 'HTTP/0.9'. A genuine HTTP/0.9 request never gets here: it is
        # closed unanswered (handle_one_request).
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.0"
        self.send_response(status)
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
