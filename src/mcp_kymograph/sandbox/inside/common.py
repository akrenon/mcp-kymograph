"""What the host and the sandbox's own containers agree on, in one place.

Every constant here is read on both sides: the containers act on it, the host checks against
it. A port, a binding or a read that existed twice could drift apart, and the check would then
confirm something other than what runs.

Standard library only; nothing here touches the network or the file system on import.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct

#: The nft table (family ``inet``, so one ruleset and one transaction cover IPv4 and IPv6).
TABLE = "mcp_kymograph"

#: Where the redirect sends every TCP connection and every UDP datagram that is not DNS.
TCP_PORT = 15001
#: Where the redirect sends UDP to port 53.
DNS_PORT = 15053

#: The resolver the target is given. The address a container on a user-defined Docker network
#: sees, so the resolver itself is not a sign of being sandboxed; nothing listens on it, the
#: ruleset redirects port 53 there to the sink.
RESOLVER_V4 = "127.0.0.11"

#: Every socket the sink holds, and nothing else: ``(protocol, address, port)``. The target
#: shares the namespace and reaches everything bound here over ``lo`` without going through
#: the redirect, so anything beyond these is surface it can fire at directly. Checked from
#: the outside (the socket tables of the namespace), never taken from the sink's own word.
SINK_BINDINGS = frozenset(
    {
        ("tcp", "127.0.0.1", TCP_PORT),
        ("tcp", "::1", TCP_PORT),
        ("udp", "127.0.0.1", TCP_PORT),
        ("udp", "::1", TCP_PORT),
        ("udp", "127.0.0.1", DNS_PORT),
        ("udp", "::1", DNS_PORT),
    }
)

#: The one read of the authoritative record (the kernel's counters and sets). The reader runs
#: it with ``CAP_NET_ADMIN`` after the target is gone; the probe runs exactly the same argv
#: under the target's credentials, and it must be refused. One tuple, so the read that is
#: trusted and the read that is shown to be out of the target's reach cannot be two reads.
AUTHORITATIVE_READ = ("nft", "-j", "list", "table", "inet", TABLE)

#: The ruleset as the kernel holds it: stateless (no counter values) and terse (no set
#: contents), so it reads the same before and after traffic. ``rules.nft`` is written in
#: exactly this rendering; equal digests mean the kernel holds that file and nothing else.
READBACK = ("nft", "-s", "-t", "list", "ruleset")

#: The user the target and the probe run as, and their capability sets: all empty.
UNPRIVILEGED_UID = 65534
NO_CAPABILITIES = "0000000000000000"
#: ``Seccomp: 2`` in ``/proc/self/status``: a filter is installed (Docker's default profile).
SECCOMP_FILTER = "2"

#: What the namespace may contain: loopback, and one dummy device that discards every packet
#: sent to it. This is the barrier. Named like the interface of an ordinary container.
INTERFACES = (("lo", "loopback"), ("eth0", "dummy"))

#: How the helper builds the dummy side, after the ruleset is in. No link-local address
#: (``addrgenmode none``) and no duplicate address detection, so the kernel itself sends
#: nothing out of it: everything the record shows was sent by a process.
INTERFACE_SETUP = (
    ("ip", "link", "add", "eth0", "type", "dummy"),
    ("ip", "link", "set", "eth0", "addrgenmode", "none"),
    ("ip", "addr", "add", "172.17.0.2/16", "dev", "eth0"),
    ("ip", "-6", "addr", "add", "fd17::2/64", "dev", "eth0", "nodad"),
    ("ip", "link", "set", "eth0", "up"),
    ("ip", "route", "add", "default", "via", "172.17.0.1", "dev", "eth0"),
    ("ip", "-6", "route", "add", "default", "via", "fd17::1", "dev", "eth0"),
)

#: What every name resolves to: addresses reserved for documentation, reachable nowhere. A
#: connection the target then opens to one of them is redirected like any other.
DNS_ANSWER_V4 = "198.51.100.1"
DNS_ANSWER_V6 = "2001:db8:5ee::1"

#: ICMP echo request, the only ICMP a process without ``CAP_NET_RAW`` can send (ping sockets).
ICMP_ECHO = 8
ICMPV6_ECHO = 128

#: Bounds on what the sink writes down from a single connection or datagram.
PREVIEW_BYTES = 64
MAX_QNAME = 253


def ruleset_digest(text: bytes) -> str:
    return "sha256:" + hashlib.sha256(text).hexdigest()


# -- the positive probe ----------------------------------------------------------------------


def probe_plan(nonce: str) -> dict[str, dict]:
    """Every attempt the probe makes, with the destination it must be recorded at.

    Ports and names come from the run's nonce, so an attempt cannot be confused with one made
    before this run or by anything other than this probe. Addresses are documentation ranges.
    """
    if len(nonce) < 8 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("the nonce is at least eight lowercase hex digits")
    tcp_port = 20000 + int(nonce[0:4], 16) % 20000
    udp_port = 40000 + int(nonce[4:8], 16) % 20000
    return {
        "tcp4": {"proto": "tcp", "family": 4, "destination": "192.0.2.10", "port": tcp_port},
        "tcp6": {"proto": "tcp", "family": 6, "destination": "2001:db8::10", "port": tcp_port},
        "udp4": {"proto": "udp", "family": 4, "destination": "192.0.2.11", "port": udp_port},
        "udp6": {"proto": "udp", "family": 6, "destination": "2001:db8::11", "port": udp_port},
        "dns_udp4": {
            "proto": "udp",
            "family": 4,
            "destination": RESOLVER_V4,
            "port": 53,
            "qname": f"u4-{nonce}.probe.invalid",
        },
        "dns_udp6": {
            "proto": "udp",
            "family": 6,
            "destination": "2001:db8::53",
            "port": 53,
            "qname": f"u6-{nonce}.probe.invalid",
        },
        "dns_tcp4": {
            "proto": "tcp",
            "family": 4,
            "destination": RESOLVER_V4,
            "port": 53,
            "qname": f"t4-{nonce}.probe.invalid",
        },
        "dns_tcp6": {
            "proto": "tcp",
            "family": 6,
            "destination": "2001:db8::53",
            "port": 53,
            "qname": f"t6-{nonce}.probe.invalid",
        },
        "icmp4": {"proto": "icmp", "family": 4, "destination": "192.0.2.12", "type": ICMP_ECHO},
        "icmp6": {
            "proto": "icmp",
            "family": 6,
            "destination": "2001:db8::12",
            "type": ICMPV6_ECHO,
        },
    }


# -- reading the namespace from the inside ---------------------------------------------------


def socket_inventory(proc_net: str = "/proc/net") -> dict:
    """Every socket the namespace holds that something could be reached through.

    TCP in ``LISTEN``, every UDP socket, and the number of raw and Unix sockets (abstract Unix
    sockets are per network namespace, so the target would share them). Read from the
    namespace's own tables, which need no capability and are the same for every process in it.
    """
    tcp = []
    udp = []
    for name, family in (("tcp", 4), ("tcp6", 6)):
        for local, state in _table(f"{proc_net}/{name}", family):
            if state == "0A":  # LISTEN
                tcp.append(local)
    for name, family in (("udp", 4), ("udp6", 6)):
        for local, _ in _table(f"{proc_net}/{name}", family):
            udp.append(local)
    raw = sum(len(list(_table(f"{proc_net}/{n}", f))) for n, f in (("raw", 4), ("raw6", 6)))
    return {
        "tcp": sorted(tcp),
        "udp": sorted(udp),
        "raw": raw,
        "unix": _count_lines(f"{proc_net}/unix"),
    }


def expected_inventory() -> dict:
    return {
        "tcp": sorted([a, p] for proto, a, p in SINK_BINDINGS if proto == "tcp"),
        "udp": sorted([a, p] for proto, a, p in SINK_BINDINGS if proto == "udp"),
        "raw": 0,
        "unix": 0,
    }


def _table(path: str, family: int):
    try:
        with open(path) as handle:
            lines = handle.read().splitlines()[1:]
    except FileNotFoundError:
        return
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        address, port = fields[1].split(":")
        yield [_address(address, family), int(port, 16)], fields[3]


def _address(hexed: str, family: int) -> str:
    raw = bytes.fromhex(hexed)
    # The kernel prints each 32-bit word in host byte order.
    words = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
    return str(ipaddress.ip_address(words if family == 6 else words[:4]))


def _count_lines(path: str) -> int:
    try:
        with open(path) as handle:
            return max(0, len(handle.read().splitlines()) - 1)
    except FileNotFoundError:
        return 0


def interface_inventory(links: list) -> list[list[str]]:
    """``[name, kind]`` per interface from ``ip -j -d link``; kind is the driver, not the name."""
    found = []
    for link in links:
        kind = (link.get("linkinfo") or {}).get("info_kind")
        if kind is None:
            kind = "loopback" if link.get("link_type") == "loopback" else "unknown"
        found.append([str(link.get("ifname")), str(kind)])
    return sorted(found)


def expected_interfaces() -> list[list[str]]:
    return sorted([name, kind] for name, kind in INTERFACES)


# -- DNS, as far as the sink and the probe need it -------------------------------------------


QTYPE_A = 1
QTYPE_AAAA = 28


def dns_query(identifier: int, qname: str, qtype: int) -> bytes:
    """A standard query with recursion desired, one question, class IN."""
    header = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(qname) + struct.pack("!HH", qtype, 1)


def parse_question(packet: bytes) -> tuple[int, str, int, int] | None:
    """``(id, qname, qtype, end of question)`` of a query, or None for anything else.

    Strict on purpose: the sink reads what the target sends, so only the plain form of a
    question is read — one question, labels written out, no compression pointer, bounded.
    """
    if len(packet) < 12:
        return None
    identifier, flags, questions = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000 or questions != 1:
        return None
    labels = []
    position = 12
    while True:
        if position >= len(packet):
            return None
        length = packet[position]
        position += 1
        if length == 0:
            break
        if length > 63 or position + length > len(packet):
            return None
        label = packet[position : position + length]
        position += length
        labels.append(label.decode("ascii", "backslashreplace"))
        if sum(len(x) + 1 for x in labels) > MAX_QNAME:
            return None
    if position + 4 > len(packet):
        return None
    qtype, _ = struct.unpack("!HH", packet[position : position + 4])
    return identifier, ".".join(labels), qtype, position + 4


def dns_answer(query: bytes) -> bytes | None:
    """The answer the sink gives: every A and AAAA name exists, at an address reachable nowhere.

    Any other type is answered with no records. Anything that is not a plain query gets no
    answer at all.
    """
    parsed = parse_question(query)
    if parsed is None:
        return None
    identifier, _, qtype, end = parsed
    question = query[12:end]
    record = b""
    if qtype == QTYPE_A:
        record = _answer(QTYPE_A, ipaddress.ip_address(DNS_ANSWER_V4).packed)
    elif qtype == QTYPE_AAAA:
        record = _answer(QTYPE_AAAA, ipaddress.ip_address(DNS_ANSWER_V6).packed)
    header = struct.pack("!HHHHHH", identifier, 0x8180, 1, 1 if record else 0, 0, 0)
    return header + question + record


def answered_address(response: bytes) -> str | None:
    """The address in an answer built by :func:`dns_answer`, for the probe's check."""
    parsed = _response_question_end(response)
    if parsed is None:
        return None
    end, answers = parsed
    if answers != 1 or len(response) < end + 12:
        return None
    rtype, _, _, length = struct.unpack("!HHIH", response[end + 2 : end + 12])
    data = response[end + 12 : end + 12 + length]
    if (rtype, length) in ((QTYPE_A, 4), (QTYPE_AAAA, 16)):
        return str(ipaddress.ip_address(data))
    return None


def _response_question_end(response: bytes) -> tuple[int, int] | None:
    if len(response) < 12:
        return None
    answers = struct.unpack("!H", response[6:8])[0]
    position = 12
    while position < len(response) and response[position] != 0:
        position += response[position] + 1
    position += 5
    if position > len(response):
        return None
    return position, answers


def _answer(qtype: int, data: bytes) -> bytes:
    # Name: a pointer to the question at offset 12.
    return struct.pack("!HHHIH", 0xC00C, qtype, 1, 60, len(data)) + data


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        encoded = label.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"
