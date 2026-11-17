"""The HTTP side: read one request, record it or count it, answer the same way every time.

A small HTTP/1.1 reader written for this one job rather than ``http.server``: the limits on
header size, body size and time per connection have to hold *while* reading, and the answer
must not depend on the request. One request per connection (``Connection: close``).

Nothing here opens a connection. ``socketserver.TCPServer`` only binds, listens and accepts;
the ``http.server`` variant is avoided because its bind resolves the host's own name.
"""

import contextlib
import ipaddress
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from typing import Any

from . import limits
from .entry import Request, build_entry, count_invalid_header_names, route
from .store import HEADER_NAME_RE, Store

#: The same bytes for every request, whatever it was and whatever became of it.
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)


class Unrecordable(Exception):
    """A request that is not recorded: too large, too slow, or not HTTP. It is only counted."""


class _Connection:
    """A socket with a wall-clock deadline and a buffer for what was read ahead."""

    def __init__(self, sock: socket.socket, timeout: float) -> None:
        self.sock = sock
        self.deadline = time.monotonic() + timeout
        self.buffer = b""

    def _receive(self, size: int) -> bytes:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Unrecordable("timeout")
        self.sock.settimeout(remaining)
        try:
            return self.sock.recv(size)
        except OSError:
            raise Unrecordable("timeout or reset") from None

    def read_head(self) -> bytes:
        while True:
            end = self.buffer.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > limits.MAX_HEADER_BYTES:
                    raise Unrecordable("headers too large")
                head, self.buffer = self.buffer[:end], self.buffer[end + 4 :]
                return head
            if len(self.buffer) >= limits.MAX_HEADER_BYTES:
                raise Unrecordable("headers too large")
            chunk = self._receive(4096)
            if not chunk:
                raise Unrecordable("closed before the end of the headers")
            self.buffer += chunk

    def read(self, count: int) -> bytes:
        """Up to ``count`` bytes; fewer only if the peer closed first."""
        while len(self.buffer) < count:
            chunk = self._receive(min(65536, count - len(self.buffer)))
            if not chunk:
                break
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def read_line(self) -> bytes:
        while b"\r\n" not in self.buffer:
            if len(self.buffer) > 1024:
                raise Unrecordable("chunk header too long")
            chunk = self._receive(1024)
            if not chunk:
                raise Unrecordable("closed inside a chunked body")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        return line

    def read_body(self, headers: list[tuple[str, str]]) -> tuple[bytes, bool]:
        """The body up to ``MAX_BODY_BYTES``, and whether more was sent than that."""
        fields = {name.lower(): value for name, value in headers}
        if "chunked" in fields.get("transfer-encoding", "").lower():
            return self._read_chunked()
        lengths = [v for n, v in headers if n.lower() == "content-length"]
        if not lengths:
            return b"", False
        if (
            len(set(lengths)) != 1
            or not lengths[0].isascii()
            or not lengths[0].isdigit()
            or len(lengths[0]) > 15
        ):
            raise Unrecordable("bad Content-Length")
        declared = int(lengths[0])
        return self.read(min(declared, limits.MAX_BODY_BYTES)), declared > limits.MAX_BODY_BYTES

    def _read_chunked(self) -> tuple[bytes, bool]:
        body = b""
        while True:
            try:
                size = int(self.read_line().split(b";")[0].strip(), 16)
            except ValueError:
                raise Unrecordable("bad chunk size") from None
            if size < 0:
                raise Unrecordable("bad chunk size")
            if size == 0:
                return body, False
            room = limits.MAX_BODY_BYTES - len(body)
            body += self.read(min(size, room))
            if size > room:
                return body, True
            self.read(2)


def parse_head(head: bytes) -> tuple[str, str, list[tuple[str, str]]]:
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise Unrecordable("bad request line")
    method, target = parts[0], parts[1]
    if not (method.isascii() and method.isalpha() and method.isupper()) or len(method) > 16:
        raise Unrecordable("bad method")
    if not target.startswith("/"):
        raise Unrecordable("bad target")
    headers = []
    for line in lines[1:]:
        name, colon, value = line.decode("latin-1").partition(":")
        if not colon or not HEADER_NAME_RE.fullmatch(name):
            raise Unrecordable("bad header line")
        headers.append((name, value.strip(" \t")))
    return method, target, headers


def forwarded(headers: list[tuple[str, str]], peer: str) -> tuple[str, str]:
    """(sender, scheme) from the proxy's headers — believed only when the peer is the proxy."""
    if peer != limits.TRUSTED_PROXY:
        return peer, "http"
    sender, scheme = peer, "http"
    for name, value in headers:
        lowered = name.lower()
        if lowered == "x-forwarded-proto" and value.strip().lower() in ("http", "https"):
            scheme = value.strip().lower()
        elif lowered == "x-forwarded-for":
            last = value.split(",")[-1].strip()
            with contextlib.suppress(ValueError):
                sender = str(ipaddress.ip_address(last))
    return sender, scheme


class Receiver(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        store: Store,
        port: int,
        peer_ip: Callable[[Any], str] | None = None,
    ) -> None:
        """``peer_ip`` maps a client address to the peer address the proxy rule judges.

        The default is the socket's own; a test replaces it to play a peer it cannot be.
        """
        super().__init__((limits.BIND_ADDRESS, port), socketserver.BaseRequestHandler)
        self.store = store
        self.peer_ip = peer_ip or (lambda address: address[0])
        self._slots = threading.BoundedSemaphore(limits.MAX_CONNECTIONS)
        self._stop = threading.Event()
        self._sweeper = threading.Thread(target=self._sweep_loop, name="receiver-sweeper")

    @property
    def port(self) -> int:
        return self.server_address[1]

    def serve_forever(self, poll_interval: float = 0.2) -> None:
        self._sweeper.start()
        try:
            super().serve_forever(poll_interval)
        finally:
            self._stop.set()
            # Carry what is only in memory to disk before the process ends.
            with contextlib.suppress(Exception):
                self.store.sweep()

    def _sweep_loop(self) -> None:
        while not self._stop.is_set():
            # A failed sweep is retried at the next interval.
            with contextlib.suppress(Exception):
                self.store.sweep()
            self._stop.wait(limits.SWEEP_INTERVAL_SECONDS)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            # Closed unread: before reading there is no request to answer. Memory only.
            self.store.count_over_limit()
            self.shutdown_request(request)
            return
        threading.Thread(
            target=self._serve, args=(request, client_address), name="receiver-connection"
        ).start()

    def _serve(self, sock: socket.socket, client_address: Any) -> None:
        try:
            self.handle_connection(sock, client_address)
        finally:
            self._slots.release()
            self.shutdown_request(sock)

    def handle_connection(self, sock: socket.socket, client_address: Any) -> None:
        connection = _Connection(sock, limits.CONNECTION_TIMEOUT_SECONDS)
        try:
            try:
                method, target, headers = parse_head(connection.read_head())
                body, truncated = connection.read_body(headers)
                sender, scheme = forwarded(headers, self.peer_ip(client_address))
                request = Request(method, target, headers, body, truncated, sender, scheme)
                self.record(request)
            except Unrecordable:
                self.store.count_other()
        except Exception:
            # A fault in storing must not change the answer, and must not go unnoticed.
            self.store.count_handler_error()
        try:
            sock.settimeout(limits.CONNECTION_TIMEOUT_SECONDS)
            sock.sendall(RESPONSE)
        except OSError:
            pass

    def record(self, request: Request) -> None:
        found = route(request.target)
        reg = self.store.lookup(found[0]) if found else None
        if found is None or reg is None:
            self.store.count_other()
            return
        self.store.append_entry(
            reg.prefix,
            build_entry(reg, request, found[1]),
            count_invalid_header_names(request.headers),
        )
