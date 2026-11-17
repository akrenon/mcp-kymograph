"""The fixture server of the benchmark: pages and names for a tool that fetches, in a network
with no way out.

It runs in a container on the internal network, next to the server under test. It does two
things and nothing else: it serves the files of one directory over HTTP, and it answers DNS
for the names it was given. A name it does not know is NXDOMAIN; nothing is ever forwarded, so
what a fetching tool asks for outside the fixture is answered with nothing and recorded.

Every HTTP request and every DNS question is one JSON line on stdout, up to
``MAX_LOGGED_EVENTS`` of them; past that they are only counted, and every ``DROPPED_EVERY``
of them there is a line ``{"event": "dropped", "http": n, "dns": m}`` with the counts so far, so
a flood cannot grow the log without bound. ``ready`` is written once after the start and is not
counted. The files are read at start: a file that appears later is not served.

    python fixture_server.py --root /srv/fixture --name fixture.test=10.0.0.2

Standard library only (Python 3.12); the runner starts it in the pinned ``python:3.12-slim``.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import signal
import socketserver
import struct
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import IO

#: The most connections served at once; the next one is told to come back later.
MAX_CONNECTIONS = 32

#: A connection that says nothing for this long is dropped.
CONNECTION_TIMEOUT = 10

#: The most ``http`` and ``dns`` events written one by one; every one after that is only counted.
MAX_LOGGED_EVENTS = 2000

#: Past the limit, one ``dropped`` line with the counts so far per this many events not written.
DROPPED_EVERY = 1000

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}
_DEFAULT_CONTENT_TYPE = "application/octet-stream"

_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    255: "ANY",
}
_TYPE_A = 1
_CLASS_IN = 1
_NOERROR = 0
_NXDOMAIN = 3
_MAX_NAME = 255
_MAX_LABEL = 63


def load_files(root: str) -> dict[str, tuple[bytes, str]]:
    """The direct children of ``root`` that are regular files: name -> (content, type)."""
    files: dict[str, tuple[bytes, str]] = {}
    with os.scandir(root) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                continue
            with open(entry.path, "rb") as handle:
                content = handle.read()
            extension = os.path.splitext(entry.name)[1].lower()
            files["/" + entry.name] = (
                content,
                _CONTENT_TYPES.get(extension, _DEFAULT_CONTENT_TYPE),
            )
    return files


# -- DNS ----------------------------------------------------------------------------------


def parse_question(packet: bytes) -> tuple[int, int, str, int, int, int] | None:
    """(id, flags, name, type, class, end of the question) of a packet that asks one question;
    None for anything else — a response, another opcode, no or several questions, a name that
    is compressed or runs past the packet."""
    if len(packet) < 12:
        return None
    ident, flags, questions = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000 or (flags >> 11) & 0xF != 0 or questions != 1:
        return None
    labels: list[str] = []
    position = 12
    total = 1
    while True:
        if position >= len(packet):
            return None
        length = packet[position]
        position += 1
        if length == 0:
            break
        if length > _MAX_LABEL:  # also a compression pointer (top bits set)
            return None
        total += length + 1
        if total > _MAX_NAME or position + length > len(packet):
            return None
        labels.append(packet[position : position + length].decode("latin-1"))
        position += length
    if position + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[position : position + 4])
    return ident, flags, ".".join(labels), qtype, qclass, position + 4


def build_response(packet: bytes, question: tuple, address: str | None, rcode: int) -> bytes:
    ident, flags, _name, _qtype, _qclass, end = question
    answers = 1 if address is not None else 0
    reply_flags = 0x8000 | 0x0400 | (flags & 0x0100) | rcode  # QR, AA, RD copied
    header = struct.pack("!HHHHHH", ident, reply_flags, 1, answers, 0, 0)
    body = packet[12:end]  # the question, as asked
    if address is not None:
        # Name as a pointer to the question's, type A, class IN, TTL 0, four bytes.
        body += struct.pack("!HHHIH", 0xC00C, _TYPE_A, _CLASS_IN, 0, 4)
        body += ipaddress.IPv4Address(address).packed
    return header + body


def _status(code: object) -> int | None:
    """The status ``log_request`` was given as a number, or None (``"-"``). ``send_response``
    passes an ``HTTPStatus``, whose ``str`` is its name, not its number, before Python 3.11."""
    if isinstance(code, int):
        return int(code)
    return int(code) if isinstance(code, str) and code.isascii() and code.isdigit() else None


class _DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        app: FixtureServer = self.server.app  # type: ignore[attr-defined]
        question = parse_question(packet)
        if question is None:
            return
        _ident, _flags, name, qtype, qclass, _end = question
        key = name.lower().rstrip(".")
        address = app.names.get(key)
        if address is None:
            rcode, answer = _NXDOMAIN, None
        elif qtype == _TYPE_A and qclass == _CLASS_IN:
            rcode, answer = _NOERROR, address
        else:
            rcode, answer = _NOERROR, None
        app.log(
            {
                "event": "dns",
                "client": self.client_address[0],
                "name": name,
                "type": _TYPE_NAMES.get(qtype, f"TYPE{qtype}"),
                "answer": answer,
                "rcode": "NXDOMAIN" if rcode == _NXDOMAIN else "NOERROR",
            }
        )
        sock.sendto(build_response(packet, question, answer, rcode), self.client_address)


# -- HTTP ---------------------------------------------------------------------------------


class _HttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], app: FixtureServer) -> None:
        self.app = app
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, _HttpHandler)

    def process_request(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        if not self._slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            self.app.log(
                {
                    "event": "http",
                    "method": None,
                    "path": None,
                    "client": client_address[0],
                    "user_agent": None,
                    "status": 503,
                }
            )
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _HttpHandler(BaseHTTPRequestHandler):
    server_version = "fixture"
    sys_version = ""
    timeout = CONNECTION_TIMEOUT

    def _target(self) -> str | None:
        # The request line as it came. ``self.path`` is not it: http.server folds a leading
        # "//" into "/", which would serve //canary.html as /canary.html.
        parts = getattr(self, "requestline", "").split()
        return parts[1] if len(parts) >= 2 else None

    def _serve(self, body: bool) -> None:
        target = self._target()
        name = target.split("?", 1)[0] if target is not None else None
        entry = self.server.app.files.get(name) if name is not None else None  # type: ignore[attr-defined]
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content, content_type = entry
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body:
            self.wfile.write(content)

    def do_GET(self) -> None:
        self._serve(body=True)

    def do_HEAD(self) -> None:
        self._serve(body=False)

    def _not_allowed(self) -> None:
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _not_allowed

    def log_request(self, code="-", size="-") -> None:  # type: ignore[no-untyped-def]
        # Called by send_response for every answer, an error page included.
        status = _status(code)
        self.server.app.log(  # type: ignore[attr-defined]
            {
                "event": "http",
                "method": getattr(self, "command", None),
                "path": self._target(),
                "client": self.client_address[0],
                "user_agent": self.headers.get("User-Agent") if hasattr(self, "headers") else None,
                "status": status,
            }
        )

    def log_message(self, format, *args) -> None:  # type: ignore[no-untyped-def]  # noqa: A002
        pass


# -- the server ---------------------------------------------------------------------------


class FixtureServer:
    """The two listeners, the files and the names; ``start`` binds, ``stop`` releases."""

    def __init__(
        self,
        root: str,
        names: dict[str, str],
        *,
        host: str = "127.0.0.1",
        http_port: int = 8080,
        dns_port: int = 53,
        out: IO[str] | None = None,
    ) -> None:
        self.files = load_files(root)
        self.names = {
            name.lower().rstrip("."): str(ipaddress.IPv4Address(address))
            for name, address in names.items()
        }
        self._out = out if out is not None else sys.stdout
        self._lock = threading.Lock()
        self._logged = 0
        self._dropped = {"http": 0, "dns": 0}
        self._http = _HttpServer((host, http_port), self)
        try:
            self._dns = socketserver.UDPServer((host, dns_port), _DnsHandler)
        except OSError:
            self._http.server_close()
            raise
        self._dns.app = self  # type: ignore[attr-defined]
        self._threads: list[threading.Thread] = []

    @property
    def http_port(self) -> int:
        return self._http.server_address[1]

    @property
    def dns_port(self) -> int:
        return self._dns.server_address[1]

    def log(self, event: dict) -> None:
        kind = event["event"]
        with self._lock:
            if kind in self._dropped:
                if self._logged < MAX_LOGGED_EVENTS:
                    self._logged += 1
                else:
                    self._dropped[kind] += 1
                    if sum(self._dropped.values()) % DROPPED_EVERY:
                        return
                    event = {"event": "dropped", **self._dropped}
            line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
            self._out.write(line + "\n")
            self._out.flush()

    def start(self) -> None:
        for server in (self._http, self._dns):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
        self.log(
            {
                "event": "ready",
                "http_port": self.http_port,
                "dns_port": self.dns_port,
                "names": self.names,
                "files": sorted(self.files),
            }
        )

    def stop(self) -> None:
        for server in (self._http, self._dns):
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads.clear()


def _name_pair(text: str) -> tuple[str, str]:
    name, separator, address = text.partition("=")
    if not separator or not name:
        raise argparse.ArgumentTypeError(f"expected NAME=IPV4, got {text!r}")
    try:
        ipaddress.IPv4Address(address)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not an IPv4 address: {address!r}") from error
    return name, address


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default="/srv/fixture")
    # Loopback unless told otherwise: the runner passes --host 0.0.0.0 inside the container,
    # where the internal network is the only one there is.
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--name", action="append", default=[], type=_name_pair, metavar="NAME=IPV4")
    args = parser.parse_args(argv)
    server = FixtureServer(
        args.root,
        dict(args.name),
        host=args.host,
        http_port=args.http_port,
        dns_port=args.dns_port,
    )
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())
    server.start()
    done.wait()
    server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
