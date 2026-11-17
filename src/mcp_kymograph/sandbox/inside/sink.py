"""The sink: where every redirected connection and datagram arrives, and is written down.

It owns the namespace (its container is started with ``--network none``; the helper, the
probe, the reader and the target all join it), holds no capability, and runs as an
unprivileged user. It is the part of the sandbox that reads what the target sends, so it
treats every byte as hostile: questions are parsed strictly and bounded, previews are a
fixed number of bytes written as hex, and a connection that fails to be handled is counted
as an error and closed — it never ends the sink.

**It binds exactly** :data:`common.SINK_BINDINGS` **and nothing else**, at no time: no health
port, no debug port, not even briefly. The target shares the namespace and could reach any
such socket over ``lo`` without going through the redirect. The host checks this from the
namespace's own socket tables, not from what the sink says it bound.

Talks to the host over stdin and stdout, one JSON object per line:

* stdout ``started`` at once, so the host knows the namespace exists.
* stdin ``arm`` → binds, then stdout ``armed``.
* stdin ``mark <label>`` → closes the current phase: stdout ``mark`` with that phase's totals.
* stdin ``stop`` (or end of input) → drains what is already queued, stdout ``stopped`` with
  the last phase's totals, exit 0.

Its account is a claim like any other: after the run the host checks the totals against the
kernel's counters, which the target cannot touch and the sink cannot read.

**It reads before it writes.** A datagram the receive queue cannot hold is dropped by the
kernel, and that queue is bounded by the host: an unprivileged process gets at most twice
``net.core.rmem_max``, which is host-wide (not per network namespace on the kernels this runs
on, so no container can raise it) and ``SO_RCVBUFFORCE`` needs a capability. So every datagram
the kernel holds is taken off its socket first, and written down afterwards, a few at a time
between reads: the backlog waits in this process, not in the queue. Measured over ten runs of
2000 datagrams sent as fast as a process can: writing each one down before reading the next
received a median of 550, reading first a median of 1996.5. What is still lost is counted by
the kernel all the same, and the host records the difference.

**Every datagram says where it was going.** The redirect rewrites a datagram's destination,
and the original one lives in conntrack, which needs ``CAP_NET_ADMIN`` to read; ``TPROXY``
would keep it, but only for a socket with ``IP_TRANSPARENT``, which needs a capability too
(both refused here, measured). What needs none is the packet's mark: the ruleset sets it,
before the redirect, to a digest of the original destination and port and keeps it beside
that destination in the kernel's set; ``SO_RCVMARK`` hands it up with each datagram. The sink
writes it down, and the host matches it to the kernel's record — destination by destination,
as for TCP.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import selectors
import socket
import struct
import sys
import time
from collections import deque

try:
    from . import common
except ImportError:  # run as a script inside the container
    import common  # type: ignore[no-redef]

#: ``SO_ORIGINAL_DST`` (IPv4, level ``SOL_IP``) and ``IP6T_SO_ORIGINAL_DST`` (level
#: ``SOL_IPV6``) share the number: where a redirected connection was going.
SO_ORIGINAL_DST = 80
#: ``SO_RCVMARK`` (Linux 5.19) hands each datagram's mark up as a control message of level
#: ``SOL_SOCKET`` and type ``SO_MARK``. Neither is named by the standard library.
SO_RCVMARK = 75
SO_MARK = 36
MARK_SPACE = socket.CMSG_SPACE(4)

#: Events written per run. Past this, attempts are still counted in the totals and the number
#: left out is reported: a capped account that says so, not a silent one.
MAX_EVENTS = 20000
#: Connections held open at once while their first bytes are read.
MAX_OPEN = 256
#: How long one connection may take to send what is read from it.
READ_SECONDS = 1.0

#: The receive buffer each UDP socket asks for. The kernel grants at most twice
#: ``net.core.rmem_max`` and silently caps the rest; what it granted is reported at arming.
RECEIVE_BUFFER = 1 << 24
#: Datagrams taken off their socket and not yet written down. Past this many the sink stops
#: reading until it has caught up, and the kernel's queue holds the rest again.
MAX_PENDING = 20000
#: How many pending datagrams are written down before the sockets are read again.
CHUNK = 64
#: What is kept of a datagram until it is written down: the preview, or a question in full.
#: A question is at most 12 + 255 + 4 bytes; the rest of a longer datagram is never read.
KEEP_UDP = common.PREVIEW_BYTES
KEEP_DNS = 512


class Sink:
    def __init__(self) -> None:
        self.selector = selectors.DefaultSelector()
        self.phase = "setup"
        self.totals = self._zero()
        self.events = 0
        self.suppressed = 0
        self.open: dict[socket.socket, dict] = {}
        self.listeners: list[socket.socket] = []
        #: ``(socket, role, family, peer, size, kept bytes, mark)`` per datagram read, not
        #: yet written.
        self.pending: deque[tuple] = deque()
        self.stdin_buffer = b""
        self.running = True

    @staticmethod
    def _zero() -> dict[str, int]:
        return {
            "tcp4": 0,
            "tcp6": 0,
            "udp4": 0,
            "udp6": 0,
            "dns_udp4": 0,
            "dns_udp6": 0,
            "errors": 0,
        }

    # -- output ----------------------------------------------------------------------

    def emit(self, event: dict, *, always: bool = False) -> None:
        """Write one line. What the host waits for (``always``) goes out at once; an account
        of traffic goes out when the loop next waits, so a burst is not one flush per item."""
        if not always:
            if self.events >= MAX_EVENTS:
                self.suppressed += 1
                return
            self.events += 1
        sys.stdout.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n")
        if always:
            sys.stdout.flush()

    # -- binding ---------------------------------------------------------------------

    def arm(self) -> None:
        bound = []
        buffers = set()
        for proto, address, port in sorted(common.SINK_BINDINGS):
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
            sock = socket.socket(family, kind)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if proto == "udp":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
                buffers.add(sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
                # Without it every datagram arrives unattributed, and the probe says so before
                # the target exists.
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, SO_RCVMARK, 1)
            sock.bind((address, port))
            if proto == "tcp":
                sock.listen(128)
            sock.setblocking(False)
            role = "accept" if proto == "tcp" else ("dns" if port == common.DNS_PORT else "udp")
            self.selector.register(sock, selectors.EVENT_READ, role)
            self.listeners.append(sock)
            bound.append([proto, address, port])
        self.emit({"event": "armed", "bound": bound, "receive_buffer": min(buffers)}, always=True)

    # -- commands from the host ------------------------------------------------------

    def command(self, line: str) -> None:
        word, _, rest = line.strip().partition(" ")
        if word == "arm" and not self.listeners:
            self.arm()
        elif word == "mark":
            # Everything read before the mark is written down as part of the phase it closes.
            self.work(len(self.pending))
            self.emit(
                {"event": "mark", "closed": self.phase, "label": rest, "totals": self.totals},
                always=True,
            )
            self.phase = rest
            self.totals = self._zero()
        elif word == "stop":
            self.running = False

    def read_stdin(self) -> None:
        chunk = os.read(sys.stdin.fileno(), 4096)
        if not chunk:
            self.running = False
            return
        self.stdin_buffer += chunk
        while b"\n" in self.stdin_buffer:
            line, self.stdin_buffer = self.stdin_buffer.split(b"\n", 1)
            self.command(line.decode("ascii", "replace"))

    # -- TCP -------------------------------------------------------------------------

    def accept(self, listener: socket.socket) -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except BlockingIOError:
                return
            family = 6 if conn.family == socket.AF_INET6 else 4
            self.totals[f"tcp{family}"] += 1
            try:
                destination, port = original_destination(conn)
            except OSError:
                destination, port = None, None
                self.totals["errors"] += 1
            state = {
                "family": family,
                "destination": destination,
                "port": port,
                "data": b"",
                "deadline": time.monotonic() + READ_SECONDS,
            }
            conn.setblocking(False)
            if len(self.open) >= MAX_OPEN:
                self.finish(conn, state)
                continue
            self.open[conn] = state
            self.selector.register(conn, selectors.EVENT_READ, "conn")

    def read_conn(self, conn: socket.socket) -> None:
        state = self.open[conn]
        try:
            chunk = conn.recv(2048)
        except BlockingIOError:
            return
        except OSError:
            chunk = b""
        state["data"] += chunk
        wanted = 2 + 512 if state["port"] == 53 else common.PREVIEW_BYTES
        if not chunk or len(state["data"]) >= wanted or self._dns_complete(state):
            self.close_conn(conn)

    @staticmethod
    def _dns_complete(state: dict) -> bool:
        data = state["data"]
        if state["port"] != 53 or len(data) < 2:
            return False
        return len(data) >= 2 + struct.unpack("!H", data[:2])[0]

    def close_conn(self, conn: socket.socket) -> None:
        state = self.open.pop(conn)
        self.selector.unregister(conn)
        self.finish(conn, state)

    def finish(self, conn: socket.socket, state: dict) -> None:
        try:
            data = state["data"]
            self.emit(
                {
                    "event": "tcp",
                    "phase": self.phase,
                    "family": state["family"],
                    "destination": state["destination"],
                    "port": state["port"],
                    "bytes": len(data),
                    "preview": data[: common.PREVIEW_BYTES].hex(),
                }
            )
            if state["port"] == 53 and len(data) >= 2:
                query = data[2 : 2 + struct.unpack("!H", data[:2])[0]]
                answer = common.dns_answer(query)
                if answer is not None:
                    conn.setblocking(True)
                    conn.settimeout(0.5)
                    conn.sendall(struct.pack("!H", len(answer)) + answer)
                self.dns_event("tcp", state["family"], query, answer is not None)
        except OSError:
            self.totals["errors"] += 1
        finally:
            conn.close()

    # -- UDP -------------------------------------------------------------------------

    def datagram(self, sock: socket.socket, role: str) -> None:
        """Take every datagram the kernel holds for this socket off it, and count it. It is
        written down later (:meth:`work`), so the receive queue empties as fast as reading
        alone allows."""
        family = 6 if sock.family == socket.AF_INET6 else 4
        keep = KEEP_DNS if role == "dns" else KEEP_UDP
        while len(self.pending) < MAX_PENDING:
            try:
                data, control, _, peer = sock.recvmsg(4096, MARK_SPACE)
            except BlockingIOError:
                return
            except OSError:
                self.totals["errors"] += 1
                return
            self.totals[f"udp{family}"] += 1
            if role == "dns":
                self.totals[f"dns_udp{family}"] += 1
            self.pending.append((sock, role, family, peer, len(data), data[:keep], mark(control)))

    def work(self, limit: int) -> None:
        """Write down up to ``limit`` pending datagrams, answering each question as it goes."""
        for _ in range(min(limit, len(self.pending))):
            sock, role, family, peer, size, data, marked = self.pending.popleft()
            if role == "dns":
                answer = common.dns_answer(data)
                if answer is not None:
                    try:
                        sock.sendto(answer, peer)
                    except OSError:
                        self.totals["errors"] += 1
                self.dns_event("udp", family, data, answer is not None, marked)
            else:
                self.emit(
                    {
                        "event": "udp",
                        "phase": self.phase,
                        "family": family,
                        "bytes": size,
                        "preview": data.hex(),
                        "mark": marked,
                    }
                )

    def dns_event(
        self, transport: str, family: int, query: bytes, answered: bool, marked: int | None = None
    ) -> None:
        parsed = common.parse_question(query)
        event = {
            "event": "dns",
            "phase": self.phase,
            "transport": transport,
            "family": family,
            "qname": None if parsed is None else parsed[1],
            "qtype": None if parsed is None else parsed[2],
            "answered": answered,
        }
        if transport == "udp":
            event["mark"] = marked
        self.emit(event)

    # -- the loop --------------------------------------------------------------------

    def run(self) -> int:
        os.set_blocking(sys.stdin.fileno(), False)
        self.selector.register(sys.stdin.fileno(), selectors.EVENT_READ, "stdin")
        self.emit({"event": "started"}, always=True)
        while self.running:
            now = time.monotonic()
            for conn in [c for c, s in self.open.items() if s["deadline"] <= now]:
                self.close_conn(conn)
            # What was written since the last wait goes out before the next one.
            if not self.guarded(sys.stdout.flush):
                return 1
            for key, _ in self.selector.select(timeout=0 if self.pending else 0.1):
                if not self.guarded(self.dispatch, key):
                    return 1
            if not self.guarded(self.work, CHUNK):
                return 1
        self.drain()
        self.emit(
            {
                "event": "stopped",
                "closed": self.phase,
                "totals": self.totals,
                "suppressed": self.suppressed,
            },
            always=True,
        )
        return 0

    def guarded(self, action, *args) -> bool:
        """One piece of work. An error is counted, never the end of the sink — unless it is our
        own output that broke: then the host is gone, and False says so."""
        try:
            action(*args)
        except OSError as exc:
            if exc.errno == errno.EPIPE:
                return False
            self.totals["errors"] += 1
        return True

    def dispatch(self, key: selectors.SelectorKey) -> None:
        if key.data == "stdin":
            self.read_stdin()
        elif key.data == "accept":
            self.accept(key.fileobj)
        elif key.data == "conn":
            self.read_conn(key.fileobj)
        else:
            self.datagram(key.fileobj, key.data)

    def drain(self) -> None:
        """What arrived before the stop is part of the account: datagrams still pending here
        or queued in the kernel, and connections still in the accept queue, are read and
        written down; open connections are closed."""
        for sock in self.listeners:
            try:
                if sock.type == socket.SOCK_STREAM:
                    self.accept(sock)
                    continue
                role = "dns" if sock.getsockname()[1] == common.DNS_PORT else "udp"
                while True:
                    self.work(len(self.pending))
                    self.datagram(sock, role)
                    if not self.pending:
                        break
            except OSError:
                self.totals["errors"] += 1
        self.work(len(self.pending))
        for conn in list(self.open):
            self.close_conn(conn)


def mark(control: list[tuple[int, int, bytes]]) -> int | None:
    """The mark the ruleset gave a datagram, from its control messages; None without one."""
    for level, kind, data in control:
        if level == socket.SOL_SOCKET and kind == SO_MARK and len(data) >= 4:
            return struct.unpack("=I", data[:4])[0]
    return None


def original_destination(conn: socket.socket) -> tuple[str, int]:
    """Where a redirected connection was going, as conntrack remembers it."""
    if conn.family == socket.AF_INET:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, address = struct.unpack("!2xH4s8x", raw)
        return socket.inet_ntop(socket.AF_INET, address), port
    raw = conn.getsockopt(socket.IPPROTO_IPV6, SO_ORIGINAL_DST, 28)
    port = struct.unpack("!H", raw[2:4])[0]
    return socket.inet_ntop(socket.AF_INET6, raw[8:24]), port


if __name__ == "__main__":
    sys.exit(Sink().run())
