"""The positive probe: makes every kind of attempt the target could, where it must arrive.

Runs before the target, in the same runtime and with the same confinement (the host builds
both from one function), joined to the sink's namespace. It reports what it saw locally; the
host decides whether each attempt *arrived* — at the sink, and in the authoritative record.

**Arrival, not failure, is what is checked.** "The connection failed" holds just as well when
the redirect is broken and everything is silently dropped: a probe that expected failure would
report a blind sandbox as a tight one. Only an attempt that must show up separates the two.

Before any attempt it reads what the target will see: the interfaces (the barrier), the
namespace's socket tables (the sink's bindings), the resolver file, and whether the
authoritative record is readable from here — it must not be.

Prints one JSON object. Exits 0 even when attempts fail: judging is the host's.
"""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys

try:
    from . import common
except ImportError:  # run as a script inside the container
    import common  # type: ignore[no-redef]

TIMEOUT = 2.0


def attempt(name: str, spec: dict, nonce: str) -> dict:
    family = socket.AF_INET6 if spec["family"] == 6 else socket.AF_INET
    try:
        if spec["proto"] == "tcp" and "qname" in spec:
            return {"answer": dns_over_tcp(family, spec)}
        if spec["proto"] == "tcp":
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((spec["destination"], spec["port"]))
                sock.sendall(f"probe {name} {nonce}\n".encode())
            return {"connected": True}
        if spec["proto"] == "udp" and "qname" in spec:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.sendto(common.dns_query(0x5EE, spec["qname"], 1), (spec["destination"], 53))
                return {"answer": common.answered_address(sock.recv(4096))}
        if spec["proto"] == "udp":
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.sendto(f"probe {name} {nonce}\n".encode(), (spec["destination"], spec["port"]))
            return {"sent": True}
        protocol = socket.IPPROTO_ICMPV6 if spec["family"] == 6 else socket.IPPROTO_ICMP
        with socket.socket(family, socket.SOCK_DGRAM, protocol) as sock:
            header = struct.pack("!BBHHH", spec["type"], 0, 0, 0, 1)
            sock.sendto(header + nonce.encode(), (spec["destination"], 0))
        return {"sent": True}
    except OSError as exc:
        return {"error": f"{type(exc).__name__}: {exc.strerror or exc}"}


def dns_over_tcp(family: int, spec: dict) -> str | None:
    query = common.dns_query(0x5EE, spec["qname"], 1)
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect((spec["destination"], 53))
        sock.sendall(struct.pack("!H", len(query)) + query)
        data = b""
        while len(data) < 2 or len(data) < 2 + struct.unpack("!H", data[:2])[0]:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return common.answered_address(data[2:]) if len(data) > 2 else None


def direct() -> dict:
    """The sink's port, addressed directly instead of through the redirect: refused."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(("127.0.0.1", common.TCP_PORT))
        return {"connected": True}
    except OSError as exc:
        return {"error": f"{type(exc).__name__}: {exc.strerror or exc}"}


def confinement() -> dict:
    """What this process is allowed: its user, its capability sets, whether it can gain more,
    its seccomp mode, and whether the root file system is mounted read-only. The target's
    flags are the probe's flags, so this is the target's confinement, read from the inside.

    Read-only is read from the mount options, not tried with a write: as an unprivileged user
    a write to ``/`` fails on permissions alone, mounted read-only or not — a write probe
    would pass for the wrong reason (it did, until a mutation showed it).
    """
    status = {}
    with open("/proc/self/status") as handle:
        for line in handle:
            key, _, value = line.partition(":")
            status[key] = value.split()
    read_only = None
    with open("/proc/self/mounts") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "/":
                read_only = "ro" in fields[3].split(",")  # the last mount on / is what is seen
    return {
        "uid": int(status["Uid"][0]),
        "caps": {k: status[k][0] for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        "no_new_privs": status.get("NoNewPrivs", ["0"])[0] == "1",
        "seccomp": status.get("Seccomp", ["0"])[0],
        "root_read_only": read_only,
    }


def authoritative_read() -> dict:
    done = subprocess.run(  # noqa: S603
        common.AUTHORITATIVE_READ, capture_output=True, check=False, timeout=10
    )
    return {
        "returncode": done.returncode,
        "stdout_bytes": len(done.stdout),
        "stderr": done.stderr.decode("utf-8", "replace").strip()[:200],
    }


def main() -> int:
    nonce = sys.argv[1]
    # The image's own ip, from its fixed PATH: this runs inside the sandbox image only.
    links = subprocess.run(  # noqa: S603
        ("ip", "-j", "-d", "link"),  # noqa: S607
        capture_output=True,
        check=False,
    )
    try:
        with open("/etc/resolv.conf", "rb") as handle:
            resolver = handle.read(4096).decode("utf-8", "replace")
    except OSError as exc:
        resolver = f"unreadable: {exc.strerror}"
    report = {
        "interfaces": common.interface_inventory(json.loads(links.stdout or b"[]")),
        "sockets": common.socket_inventory(),
        "resolv_conf": resolver,
        "authoritative_read": authoritative_read(),
        "confinement": confinement(),
        "direct": direct(),
        "attempts": {
            name: attempt(name, spec, nonce) for name, spec in common.probe_plan(nonce).items()
        },
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
