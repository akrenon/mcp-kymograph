"""The network of a stage B run, and the count of what the server tries in it.

A server that fetches pages or talks to a database needs a network, and a foreign server must
not have more of it than the benchmark gave. For one run this module builds an internal network
with the fixture server (pages and names) and, where the kind needs it, PostgreSQL; a *holder*
container whose network namespace the server then joins; and nftables rules in that namespace
that let through what the kind needs and **count** everything else: every new connection with
its target, protocol and port, and — in the fixture server's log — every name asked. Only
counts, no contents. Before the server starts a probe shows that the counting works.
Afterwards everything is removed, and the removal is checked by the run's label.

Kinds without a network (``file``, ``sqlite``, ``git``, ``positive``) get a volume with the
fixture and ``--network none`` as before.

This is plain Docker, not gVisor: the isolation is "container (docker), not gVisor".

    with StageBNetwork("page", fixture, definition, "docker", out_dir) as net:
        subprocess.run(net.server_command(image, args, env))
    report = net.report

Docker needs the pinned ``python:3.12-slim`` and the ``nft`` helper image (``bench.py
build-helpers``) to be here already; nothing is pulled.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, NamedTuple


def _load_bench():  # type: ignore[no-untyped-def]
    """The runner module, as already loaded by whoever imports this one: a second copy would
    have a second ``RunnerError``, which the caller's ``except`` would not catch."""
    for name in ("bench_local_servers", "bench"):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "RunnerError"):
            return module
    main = sys.modules.get("__main__")
    if (
        main is not None
        and Path(getattr(main, "__file__", None) or "").name == "bench.py"
        and hasattr(main, "RunnerError")
    ):
        return main
    spec = importlib.util.spec_from_file_location(
        "bench_local_servers", Path(__file__).resolve().parent / "bench.py"
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 - a file next to this one
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bench = _load_bench()
RunnerError = bench.RunnerError

HERE = Path(__file__).resolve().parent
FIXTURE_SERVER = HERE / "fixture_server.py"

#: The kinds that get a network, what each of them is allowed to reach, and which have files
#: the server reads from a volume.
NET_KINDS = ("postgres", "page", "page-js")
HTTP_KINDS = ("page", "page-js")
VOLUME_KINDS = ("file", "positive", "sqlite", "git")
WRITABLE_KINDS = ("sqlite", "git")
KINDS = (*VOLUME_KINDS, *NET_KINDS)

FIXTURE_HOST = 10
POSTGRES_HOST = 11
HOLDER_HOST = 20
HTTP_PORT = 8080
DNS_PORT = 53
POSTGRES_PORT = 5432
#: The resolver docker builds into every container's namespace.
DOCKER_RESOLVER = "127.0.0.11"

SUBNET_ATTEMPTS = 6
FILL_PATH = "/srv/fixtures"
NFT_TABLE = "mcpb"
#: ``local4``: the new connections over loopback, per target; they are let through (they do not
#: leave the namespace) but not left unseen.
NFT_SETS = ("allowed", "refused4", "refused6", "local4")
NFT_COUNTERS = ("resolver", "other", "input_dropped", "overflow")
#: The helper containers (fixture server, PostgreSQL) have rules of their own, in their own
#: namespaces: the sets of refused targets and of loopback, and the counters, without the
#: holder's allowed set (they let nothing new out).
HELPER_ROLES = ("fixture", "postgres")
HELPER_SETS = ("refused4", "refused6", "local4")
HELPER_COUNTERS = ("resolver", "other", "input_dropped", "overflow")
#: The most single events the report lists of the fixture server's log, for each of the two kinds.
REPORT_EVENT_LIMIT = 2000
#: How the fixture server's container keeps its log: one file of at most this size, so that a
#: flood does not fill the disk of the host.
FIXTURE_LOG_OPTIONS = (
    "--log-driver",
    "json-file",
    "--log-opt",
    "max-size=8m",
    "--log-opt",
    "max-file=1",
)
#: The user PostgreSQL runs as (the image's ``postgres``) and the role the server is given.
POSTGRES_USER_ID = "999:999"
READER_ROLE = "reader"
#: How many distinct targets each of the sets of refused attempts holds.
SET_SIZE = 4096
#: What the counting cannot see, said in every report and in the README.
IPV6_LIMIT = (
    "The namespace has no IPv6 address: an IPv6 attempt fails without a packet, leaves nothing "
    "and is not counted."
)
NFT_IMAGE = next(iter(bench.HELPER_IMAGES))

READY_SECONDS = 30
POSTGRES_READY_SECONDS = 60
COMMAND_SECONDS = 120

#: The address the probe tries to reach: TEST-NET-1, which no network routes.
PROBE_TARGET = ("192.0.2.1", 9)
PROBE_CHECKS: tuple[str, ...] = (
    "default_route_without_gateway",
    "no_ipv6_address",
    "fixture_accepts",
    "dns_answers_fixture",
    "dns_nxdomain",
    "external_connect_fails",
    "counting_works",
)

#: The probe, run in the holder's namespace. Standard library only; a check that raises is
#: false. It makes DNS questions itself, by hand, to the fixture server's address. Prints one
#: JSON line. ``counting_works`` is not its business: the runner reads the counters afterwards.
STAGE_B_PROBE_SCRIPT = """\
import json
import socket
import struct
import sys

FIXTURE = sys.argv[1]
NEEDS_HTTP = sys.argv[2] == "1"


def default_routes():
    with open("/proc/net/route", encoding="ascii") as handle:
        rows = [line.split() for line in handle.read().splitlines()[1:]]
    zero = "00000000"
    return [(row[0], row[2]) for row in rows if len(row) >= 8 and row[1] == zero and row[7] == zero]


def ipv6_addresses():
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as handle:
            rows = [line.split() for line in handle.read().splitlines()]
    except FileNotFoundError:
        return []
    # scope 0x10 is the host (loopback), 0x20 the link: neither reaches beyond the namespace.
    return [row[0] for row in rows if len(row) >= 6 and int(row[3], 16) not in (0x10, 0x20)]


def connects(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError:
        return False
    return True


def ask(name):
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    packet = struct.pack("!HHHHHH", 0x4D42, 0x0100, 1, 0, 0, 0) + labels + b"\\0"
    packet += struct.pack("!HH", 1, 1)
    last = None
    for _ in range(3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(packet, (FIXTURE, 53))
            data, _ = sock.recvfrom(512)
        except OSError as error:
            last = error
            continue
        finally:
            sock.close()
        rcode = data[3] & 0x0F
        answers = struct.unpack("!H", data[6:8])[0]
        address = ".".join(str(byte) for byte in data[-4:]) if answers else None
        return rcode, address
    raise last


def main():
    result = {"fixture": FIXTURE}
    errors = {}

    def check(name, test):
        try:
            result[name] = test() is True
        except Exception as error:  # a check that cannot be made did not hold
            result[name] = False
            errors[name] = type(error).__name__

    check("default_route_without_gateway", lambda: default_routes() == [("eth0", "00000000")])
    check("no_ipv6_address", lambda: not ipv6_addresses())
    check("fixture_accepts", lambda: not NEEDS_HTTP or connects(FIXTURE, 8080))
    check("dns_answers_fixture", lambda: ask("fixture") == (0, FIXTURE))
    check("dns_nxdomain", lambda: ask("mcpb-probe.invalid")[0] == 3)
    check("external_connect_fails", lambda: not connects("192.0.2.1", 9))
    result["errors"] = errors
    print(json.dumps(result, sort_keys=True))


main()
"""


# -- addresses ----------------------------------------------------------------------------


def choose_subnet(
    rng: random.Random | None = None, avoid: Sequence[ipaddress.IPv4Network] = ()
) -> ipaddress.IPv4Network:
    """A random ``10.<200-254>.<0-255>.0/24`` that overlaps none of ``avoid``."""
    rng = rng if rng is not None else random.SystemRandom()
    candidates = [(second, third) for second in range(200, 255) for third in range(256)]
    rng.shuffle(candidates)
    for second, third in candidates:
        subnet = ipaddress.IPv4Network(f"10.{second}.{third}.0/24")
        if not any(subnet.overlaps(other) for other in avoid):
            return subnet
    raise RunnerError("no free subnet from 10.200.0.0/24 to 10.254.255.0/24")


@dataclass(frozen=True)
class Addresses:
    """The fixed addresses in the run's subnet."""

    subnet: ipaddress.IPv4Network

    def _host(self, number: int) -> str:
        return str(self.subnet.network_address + number)

    @property
    def fixture(self) -> str:
        return self._host(FIXTURE_HOST)

    @property
    def postgres(self) -> str:
        return self._host(POSTGRES_HOST)

    @property
    def holder(self) -> str:
        return self._host(HOLDER_HOST)

    def as_dict(self) -> dict[str, str]:
        return {
            "subnet": str(self.subnet),
            "fixture": self.fixture,
            "postgres": self.postgres,
            "holder": self.holder,
        }


# -- the counting rules -------------------------------------------------------------------


#: A new connection over loopback is let through and counted per target (a dynamic set with a
#: counter per element): it does not leave the namespace, but it is not unseen. Where the set is
#: full, ``add`` does not take and the rule is left, to the plain ``oif "lo" accept`` after it.
LOCAL_RULES = """\
        oif "lo" ct state new meta nfproto ipv4 meta l4proto tcp add @local4 {{ {key4} }} accept
        oif "lo" ct state new meta nfproto ipv4 meta l4proto udp add @local4 {{ {key4} }} accept
"""


def nft_ruleset(kind: str, addresses: Addresses, set_size: int = SET_SIZE) -> str:
    """The rules the holder's namespace gets, for a kind with a network.

    Output: what goes to docker's resolver is counted and rejected *before* loopback is let
    through; then loopback, a new connection counted per target in ``local4`` (:data:`LOCAL_RULES`),
    and answers to what was let in; then exactly the targets of the kind,
    counted per target (a dynamic set with a counter per element); every other new TCP/UDP
    connection over IPv4 or IPv6 is counted per target and rejected (TCP with a reset, UDP with
    ICMP): one attempt is one packet, and the server learns at once that it may not, instead of
    waiting out its own deadline. Where a set of refused targets is full, ``add`` does not take
    and the rule is left: the two last rules then reject the attempt all the same, counted in
    ``overflow`` without its target. The rest (ICMP …) is counted in one counter and dropped.
    Input: answers and loopback; the rest is counted and dropped. The default route without a
    gateway (:func:`route_args`) is what makes an attempt beyond the subnet a packet at all.
    """
    if kind not in NET_KINDS:
        raise ValueError(f"{kind!r} has no network; known with one: {', '.join(NET_KINDS)}")
    key4 = "ip daddr . meta l4proto . th dport"
    key6 = "ip6 daddr . meta l4proto . th dport"
    targets: list[tuple[str, str, int]] = [(addresses.fixture, "udp", DNS_PORT)]
    if kind in HTTP_KINDS:
        targets.insert(0, (addresses.fixture, "tcp", HTTP_PORT))
    if kind == "postgres":
        targets.append((addresses.postgres, "tcp", POSTGRES_PORT))
    allowed = "".join(
        f"        ip daddr {address} {protocol} dport {port} add @allowed {{ {key4} }} accept\n"
        for address, protocol, port in targets
    )
    return f"""\
table inet {NFT_TABLE} {{
    counter resolver {{ }}
    counter other {{ }}
    counter input_dropped {{ }}
    counter overflow {{ }}
    set allowed {{
        type ipv4_addr . inet_proto . inet_service
        flags dynamic
        counter
        size 16
    }}
    set refused4 {{
        type ipv4_addr . inet_proto . inet_service
        flags dynamic
        counter
        size {set_size}
    }}
    set refused6 {{
        type ipv6_addr . inet_proto . inet_service
        flags dynamic
        counter
        size {set_size}
    }}
    set local4 {{
        type ipv4_addr . inet_proto . inet_service
        flags dynamic
        counter
        size {set_size}
    }}
    chain output {{
        type filter hook output priority filter; policy drop;
        ip daddr {DOCKER_RESOLVER} counter name "resolver" reject
{LOCAL_RULES.format(key4=key4)}\
        oif "lo" accept
        ct state established,related accept
{allowed}\
        meta nfproto ipv4 meta l4proto tcp add @refused4 {{ {key4} }} reject with tcp reset
        meta nfproto ipv4 meta l4proto udp add @refused4 {{ {key4} }} reject
        meta nfproto ipv6 meta l4proto tcp add @refused6 {{ {key6} }} reject with tcp reset
        meta nfproto ipv6 meta l4proto udp add @refused6 {{ {key6} }} reject
        meta l4proto tcp counter name "overflow" reject with tcp reset
        meta l4proto udp counter name "overflow" reject
        counter name "other" drop
    }}
    chain input {{
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iif "lo" accept
        counter name "input_dropped" drop
    }}
}}
"""


#: What each helper container serves, and so what may come in to it.
HELPER_SERVES: dict[str, tuple[tuple[str, int], ...]] = {
    "fixture": (("tcp", HTTP_PORT), ("udp", DNS_PORT)),
    "postgres": (("tcp", POSTGRES_PORT),),
}


def helper_ruleset(role: str, addresses: Addresses, set_size: int = SET_SIZE) -> str:
    """The rules a helper container's own namespace gets (``fixture`` or ``postgres``).

    The helpers are part of the trust boundary: what they do is counted, as the server's is.
    Input: answers and loopback, and from the run's subnet exactly what the role serves
    (:data:`HELPER_SERVES`); everything else is counted (``input_dropped``) and dropped. Output:
    docker's resolver is counted (``resolver``) and rejected before loopback is let through,
    as in the holder; loopback (a new connection counted per target in ``local4``) and answers
    (``ct state established,related``) and nothing else — every new attempt is counted per
    target in the sets of refused targets and rejected, as in the holder (:func:`nft_ruleset`),
    with the same fall-back counter ``overflow`` where a set is full.
    """
    if role not in HELPER_ROLES:
        raise ValueError(f"{role!r} is no helper; known: {', '.join(HELPER_ROLES)}")
    key4 = "ip daddr . meta l4proto . th dport"
    key6 = "ip6 daddr . meta l4proto . th dport"
    served = "".join(
        f"        ip saddr {addresses.subnet} {protocol} dport {port} accept\n"
        for protocol, port in HELPER_SERVES[role]
    )
    return f"""\
table inet {NFT_TABLE} {{
    counter resolver {{ }}
    counter other {{ }}
    counter input_dropped {{ }}
    counter overflow {{ }}
    set refused4 {{
        type ipv4_addr . inet_proto . inet_service
        flags dynamic
        counter
        size {set_size}
    }}
    set refused6 {{
        type ipv6_addr . inet_proto . inet_service
        flags dynamic
        counter
        size {set_size}
    }}
    set local4 {{
        type ipv4_addr . inet_proto . inet_service
        flags dynamic
        counter
        size {set_size}
    }}
    chain output {{
        type filter hook output priority filter; policy drop;
        ip daddr {DOCKER_RESOLVER} counter name "resolver" reject
{LOCAL_RULES.format(key4=key4)}\
        oif "lo" accept
        ct state established,related accept
        meta nfproto ipv4 meta l4proto tcp add @refused4 {{ {key4} }} reject with tcp reset
        meta nfproto ipv4 meta l4proto udp add @refused4 {{ {key4} }} reject
        meta nfproto ipv6 meta l4proto tcp add @refused6 {{ {key6} }} reject with tcp reset
        meta nfproto ipv6 meta l4proto udp add @refused6 {{ {key6} }} reject
        meta l4proto tcp counter name "overflow" reject with tcp reset
        meta l4proto udp counter name "overflow" reject
        counter name "other" drop
    }}
    chain input {{
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iif "lo" accept
{served}\
        counter name "input_dropped" drop
    }}
}}
"""


class Count(NamedTuple):
    packets: int
    bytes: int


Target = tuple[str, str, int]


class SetupFailure(RunnerError):
    """A step of the set-up the runner answers with a second attempt, ``cause`` saying which:
    the fixture could not be filled (``fixture_fill_failed``), its server or PostgreSQL was not
    ready (``fixture_not_ready``), or the probe did not find the network as required
    (``network_probe_failed``). Any other failure of the set-up is not one of these and ends the
    run: a wrong set-up is not a server that could not be reached."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause


class NftError(RunnerError):
    """What ``nft`` printed is not what the rules produce; nothing is guessed from it."""


@dataclass(frozen=True)
class NftCounts:
    """The counters of the table: per set the targets with their counts, and the named counters."""

    sets: dict[str, dict[Target, Count]]
    counters: dict[str, Count]

    def minus(self, base: NftCounts) -> NftCounts:
        """What was counted since ``base``. A count that went down is an error: the rules were
        replaced, and the difference would mean nothing."""
        sets: dict[str, dict[Target, Count]] = {}
        for name, entries in self.sets.items():
            sets[name] = {}
            for target, count in entries.items():
                before = base.sets.get(name, {}).get(target, Count(0, 0))
                delta = Count(count.packets - before.packets, count.bytes - before.bytes)
                if delta.packets < 0 or delta.bytes < 0:
                    raise NftError(f"{name} {target}: the count went down since the baseline")
                if delta.packets:
                    sets[name][target] = delta
            for target in base.sets.get(name, {}):
                if target not in entries:
                    raise NftError(f"{name} {target}: gone since the baseline")
        counters: dict[str, Count] = {}
        for name, count in self.counters.items():
            before = base.counters.get(name, Count(0, 0))
            counters[name] = Count(count.packets - before.packets, count.bytes - before.bytes)
            if counters[name].packets < 0 or counters[name].bytes < 0:
                raise NftError(f"{name}: the count went down since the baseline")
        return NftCounts(sets, counters)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            name: [
                {"target": target[0], "protocol": target[1], "port": target[2], "count": c.packets}
                for target, c in sorted(entries.items())
            ]
            for name, entries in self.sets.items()
        }
        result["counters"] = {name: c.packets for name, c in self.counters.items()}
        return result


_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def _count(value: Any, where: str) -> Count:
    if (
        not isinstance(value, dict)
        or type(value.get("packets")) is not int
        or type(value.get("bytes")) is not int
    ):
        raise NftError(f"{where}: no counter with packets and bytes")
    return Count(value["packets"], value["bytes"])


def _target(value: Any, where: str) -> Target:
    parts = value.get("concat") if isinstance(value, dict) else None
    if not isinstance(parts, list) or len(parts) != 3:
        raise NftError(f"{where}: an element that is not (address, protocol, port)")
    address, protocol, port = parts
    if isinstance(protocol, int) and not isinstance(protocol, bool):
        protocol = _PROTOCOLS.get(protocol, str(protocol))
    if not isinstance(address, str) or not isinstance(protocol, str) or type(port) is not int:
        raise NftError(f"{where}: an element that is not (address, protocol, port)")
    return address, protocol, port


def parse_nft(
    text: str, wanted_sets: Sequence[str] = NFT_SETS, wanted_counters: Sequence[str] = NFT_COUNTERS
) -> NftCounts:
    """The counts from ``nft -j list table inet mcpb`` (nft 1.0.6). Anything that is not exactly
    that table with all its sets and counters is an ``NftError``, never an empty result.
    ``wanted_sets`` and ``wanted_counters`` are those of the table that was loaded: the
    holder's (the default) or a helper's (:data:`HELPER_SETS`, :data:`HELPER_COUNTERS`)."""
    try:
        data = json.loads(text)
    except ValueError:
        raise NftError("nft did not print JSON") from None
    items = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise NftError("nft's JSON has no 'nftables' list")
    tables = [
        item["table"]
        for item in items
        if isinstance(item, dict) and isinstance(item.get("table"), dict)
    ]
    if not any(t.get("family") == "inet" and t.get("name") == NFT_TABLE for t in tables):
        raise NftError(f"the table inet {NFT_TABLE} is not in nft's answer")
    sets: dict[str, dict[Target, Count]] = {}
    counters: dict[str, Count] = {}
    for item in items:
        if not isinstance(item, dict):
            raise NftError("nft's JSON holds an item that is no object")
        if isinstance(item.get("counter"), dict):
            body = item["counter"]
            if body.get("table") == NFT_TABLE and body.get("name") in wanted_counters:
                counters[body["name"]] = _count(body, f"counter {body['name']}")
        elif isinstance(item.get("set"), dict):
            body = item["set"]
            if body.get("table") != NFT_TABLE or body.get("name") not in wanted_sets:
                continue
            entries: dict[Target, Count] = {}
            elements = body.get("elem", [])
            if not isinstance(elements, list):
                raise NftError(f"set {body['name']}: elem is no list")
            for element in elements:
                inner = element.get("elem") if isinstance(element, dict) else None
                if not isinstance(inner, dict):
                    raise NftError(f"set {body['name']}: an element without counter")
                where = f"set {body['name']}"
                entries[_target(inner.get("val"), where)] = _count(inner.get("counter"), where)
            sets[body["name"]] = entries
    for name in wanted_sets:
        if name not in sets:
            raise NftError(f"the set {name} is not in nft's answer")
    for name in wanted_counters:
        if name not in counters:
            raise NftError(f"the counter {name} is not in nft's answer")
    return NftCounts(sets, counters)


# -- the fixture server's log -------------------------------------------------------------


@dataclass(frozen=True)
class FixtureLog:
    """What the fixture server wrote: its events in order, and what in the log was not one."""

    events: tuple[dict[str, Any], ...]
    problems: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return any(event.get("event") == "ready" for event in self.events)

    def since(self, base: FixtureLog) -> FixtureLog:
        """The events after the first ``len(base.events)``; a log that is shorter is a problem."""
        if len(self.events) < len(base.events):
            return FixtureLog((), (*self.problems, "the log is shorter than at the baseline"))
        return FixtureLog(self.events[len(base.events) :], self.problems)

    def of(self, event: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e.get("event") == event]

    def dropped(self) -> dict[str, int | None] | None:
        """The totals of the last ``dropped`` line: how many requests (``http``) and questions
        (``dns``) the server did not write down singly, past its limit. None if it dropped none;
        a total that is no count is None in it (and the caller says so)."""
        lines = self.of("dropped")
        if not lines:
            return None
        return {
            kind: lines[-1][kind]
            if type(lines[-1].get(kind)) is int and lines[-1][kind] >= 0
            else None
            for kind in ("http", "dns")
        }


def _total(count: int | None) -> str:
    """A total of a ``dropped`` line as the report says it: the number, or that there is none."""
    return str(count) if count is not None else "an uncounted number of"


def parse_fixture_log(text: str) -> FixtureLog:
    """The JSON lines of ``docker logs``. A line that is not a JSON object with an ``event`` is a
    problem, listed with its number, not skipped. Past its limit of single events the server
    writes a line ``dropped`` with the totals so far (:meth:`FixtureLog.dropped`)."""
    events: list[dict[str, Any]] = []
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict) or not isinstance(event.get("event"), str):
            problems.append(f"line {number}: not an event: {line[:120]!r}")
            continue
        events.append(event)
    return FixtureLog(tuple(events), tuple(problems))


# -- PostgreSQL's log ---------------------------------------------------------------------

#: PostgreSQL's default line prefix (``%m [%p] ``): time, zone, process id; then the level.
_PG_LINE = re.compile(
    r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)? \S+ \[(?P<pid>\d+)\] (?P<level>[A-Z0-9]+):  "
    r"(?P<text>.*)$"
)
_PG_AUTHORIZED = re.compile(
    r"^connection authorized: user=(?P<user>\S*) database=(?P<database>\S*)"
    r"(?: application_name=(?P<application>.*?))?(?: SSL enabled.*)?$"
)
_PG_RECEIVED = re.compile(r"^connection received: host=(?P<host>\S+)")
_PG_STATEMENT = re.compile(r"^(?:statement|execute [^:]*): (?P<statement>.*)$", re.DOTALL)
#: What a ``FATAL`` line of a failed login names: the user (``for user "x"``, ``user "x"`` of a
#: ``pg_hba`` line, ``role "x" does not exist``) and the database.
_PG_FATAL_USER = re.compile(r'\b(?:user|role) "(?P<user>[^"]*)"')
_PG_FATAL_DATABASE = re.compile(r'\bdatabase "(?P<database>[^"]*)"')
#: A ``FATAL`` that ends a session that was fine, and is no failed login.
_PG_FATAL_ENDS = ("terminating connection", "connection to client lost")
PG_NEVER_AUTHORIZED = "connection received, never authorized"
#: A statement longer than this is cut: the log is evidence of what was asked, not a copy of it.
PG_STATEMENT_LIMIT = 2000


@dataclass(frozen=True)
class PostgresLog:
    """What PostgreSQL logged of the sessions the server made: ``sessions`` (the user, the
    database and the application of each connection that was authorized, in order) and
    ``statements`` (each with the user and database of its session, or None where the
    session's line is not in the log). The runner's own readiness check is left out. ``problems``
    are the lines that fit no pattern, with their number. ``failed_logins`` (the user, the
    database and the reason of each; None where the log does not say) are the connections that
    did not get in: a ``FATAL`` of authentication, an unknown role or database, ``pg_hba``, and a
    connection that was received and never authorized. ``failed_lines`` is the line of each."""

    sessions: tuple[dict[str, Any], ...]
    statements: tuple[dict[str, Any], ...]
    problems: tuple[str, ...]
    #: How many lines the log had: where a later reading goes on.
    lines: int = 0
    failed_logins: tuple[dict[str, Any], ...] = ()
    failed_lines: tuple[int, ...] = ()

    def since(self, base: PostgresLog) -> PostgresLog:
        """What came after the first ``len(base.sessions)`` sessions and ``len(base.statements)``
        statements, the problems and failed logins on later lines; a log that is shorter is a
        problem."""
        if (
            len(self.sessions) < len(base.sessions)
            or len(self.statements) < len(base.statements)
            or self.lines < base.lines
        ):
            return PostgresLog((), (), (*self.problems, "the log is shorter than at the baseline"))
        later = tuple(
            p for p in self.problems if int(p.split(":", 1)[0].removeprefix("line ")) > base.lines
        )
        failed = [
            (entry, line)
            for entry, line in zip(self.failed_logins, self.failed_lines, strict=True)
            if line > base.lines
        ]
        return PostgresLog(
            self.sessions[len(base.sessions) :],
            self.statements[len(base.statements) :],
            later,
            self.lines,
            tuple(entry for entry, _ in failed),
            tuple(line for _, line in failed),
        )


def parse_postgres_log(text: str, own_address: str, scrub: Any = None) -> PostgresLog:
    """The sessions and statements in ``docker logs`` of the PostgreSQL container, which logs
    connections, disconnections and every statement (:func:`postgres_command`).

    A session is a ``connection authorized`` line; its process id ties the statements that follow
    to it, until ``disconnection``. A connection from ``own_address`` is the runner's
    ``pg_isready`` and is left out, its sessions and statements too. A line that is not of this
    form is a problem, except those before the first log line (the image's own start-up text)
    and the continuation of a statement over several lines (it starts with a blank).
    A ``FATAL`` line of a connection (not the runner's own) is a failed login, and so is a
    connection that was received and never authorized (:attr:`PostgresLog.failed_logins`).
    ``scrub``, if given, is applied to every string that goes into the result.
    """
    clean = scrub if scrub is not None else (lambda s: s)
    hosts: dict[str, str] = {}
    owners: dict[str, dict[str, Any] | None] = {}
    sessions: list[dict[str, Any]] = []
    statements: list[dict[str, Any]] = []
    problems: list[str] = []
    last: dict[str, Any] | None = None
    started = False
    number = 0
    pending: dict[str, int] = {}  # connections received and not yet authorized: pid -> line
    failed: list[tuple[int, dict[str, Any]]] = []

    def fail(line: int, user: str | None, database: str | None, reason: str) -> None:
        failed.append(
            (
                line,
                {
                    "user": None if user is None else clean(user),
                    "database": None if database is None else clean(database),
                    "reason": clean(reason),
                },
            )
        )

    for number, line in enumerate(text.splitlines(), 1):
        found = _PG_LINE.match(line)
        if found is None:
            if last is not None and line[:1] in (" ", "\t"):
                last["statement"] = clean((last["_raw"] + "\n" + line.strip())[:PG_STATEMENT_LIMIT])
                last["_raw"] += "\n" + line.strip()
            elif started and line.strip():
                problems.append(f"line {number}: not a log line: {clean(line[:120])!r}")
            continue
        started = True
        last = None
        pid, level, message = found["pid"], found["level"], found["text"]
        if level == "FATAL":
            pending.pop(pid, None)
            if hosts.get(pid) == own_address or (pid in owners and owners[pid] is None):
                continue  # the readiness check's
            if (pid not in hosts and pid not in owners) or message.startswith(_PG_FATAL_ENDS):
                continue  # no connection's, or the end of one that was fine
            owner = owners.get(pid)
            user = _PG_FATAL_USER.search(message)
            database = _PG_FATAL_DATABASE.search(message)
            fail(
                number,
                user["user"] if user else None if owner is None else owner["user"],
                database["database"] if database else None if owner is None else owner["database"],
                message[:200],
            )
            continue
        if level != "LOG":
            continue
        received = _PG_RECEIVED.match(message)
        if received:
            if pid in pending:  # the pid is used again: the earlier one never got in
                fail(pending.pop(pid), None, None, PG_NEVER_AUTHORIZED)
            hosts[pid] = received["host"]
            if received["host"] != own_address:
                pending[pid] = number
            continue
        authorized = _PG_AUTHORIZED.match(message)
        if authorized:
            pending.pop(pid, None)
            if hosts.get(pid) == own_address:
                owners[pid] = None
                continue
            session = {
                "user": clean(authorized["user"]),
                "database": clean(authorized["database"]),
                "application": clean(authorized["application"] or ""),
            }
            sessions.append(session)
            owners[pid] = session
            continue
        if message.startswith("disconnection:"):
            owners.pop(pid, None)
            hosts.pop(pid, None)
            pending.pop(pid, None)
            continue
        statement = _PG_STATEMENT.match(message)
        if statement:
            if pid in owners and owners[pid] is None:
                continue  # the readiness check's
            owner = owners.get(pid)
            raw = statement["statement"]
            entry = {
                "user": None if owner is None else owner["user"],
                "database": None if owner is None else owner["database"],
                "statement": clean(raw[:PG_STATEMENT_LIMIT]),
                "_raw": raw,
            }
            statements.append(entry)
            last = entry
    for line_number in pending.values():
        fail(line_number, None, None, PG_NEVER_AUTHORIZED)
    failed.sort(key=lambda item: item[0])
    return PostgresLog(
        tuple(sessions),
        tuple({k: v for k, v in e.items() if k != "_raw"} for e in statements),
        tuple(problems),
        number,
        tuple(entry for _, entry in failed),
        tuple(line_number for line_number, _ in failed),
    )


def resolv_conf(addresses: Addresses) -> str:
    """The server's resolver file: the fixture server and nothing else, one try, short wait."""
    return f"nameserver {addresses.fixture}\noptions attempts:1 timeout:2\n"


# -- commands -----------------------------------------------------------------------------


def _label(nonce: str) -> list[str]:
    return ["--label", f"{bench.RUN_LABEL}={nonce}"]


def network_create_command(docker: str, nonce: str, subnet: ipaddress.IPv4Network) -> list[str]:
    options = [
        part for key, value in bench.NETWORK_OPTIONS.items() for part in ("-o", f"{key}={value}")
    ]
    return [
        docker, "network", "create", "--internal", "--subnet", str(subnet), *options,
        *_label(nonce), f"mcpb-netb-{nonce}",
    ]  # fmt: skip


def volume_create_command(docker: str, nonce: str, volume: str) -> list[str]:
    return [docker, "volume", "create", *_label(nonce), volume]


#: What the filling container runs: the tar from stdin, unpacked with the ``data`` filter, all
#: of it given to the server's user.
FILL_SCRIPT = (
    "import os, sys, tarfile\n"
    f"with tarfile.open(fileobj=sys.stdin.buffer, mode='r|') as archive:\n"
    f"    archive.extractall('{FILL_PATH}', filter='data')\n"
    f"os.chown('{FILL_PATH}', 65534, 65534)\n"
    f"for root, directories, files in os.walk('{FILL_PATH}'):\n"
    "    for name in directories + files:\n"
    "        os.chown(os.path.join(root, name), 65534, 65534, follow_symlinks=False)\n"
)


def fill_command(docker: str, nonce: str, name: str, volume: str) -> list[str]:
    """A short container that pours the tar on its stdin into the volume. Nothing of the host
    is in the command; the one capability is the one ``chown`` needs."""
    return [
        docker, "run", "-i", "--rm", "--name", name, *_label(nonce),
        "--network", "none", "--ipc", "none", "--read-only",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--security-opt", "no-new-privileges",
        "--pids-limit", "16", "--memory", "128m",
        "-v", f"{volume}:{FILL_PATH}",
        bench.PYTHON_IMAGE, "python", "-B", "-c", FILL_SCRIPT,
    ]  # fmt: skip


def postgres_command(
    docker: str, nonce: str, name: str, network: str, address: str, image: str, volume: str,
    password: str,
) -> list[str]:  # fmt: skip
    """PostgreSQL by digest, with the init script from the fixture volume read-only. It runs as
    its own user with a read-only root and no capability at all: the data, the socket directory
    and ``/tmp`` are memory owned by that user (the data directory ``0700``, as PostgreSQL
    demands), so the image's entrypoint has no ownership to change. ``password`` is the
    superuser's, new for each run and nowhere but here: the server under test is given the
    role ``reader`` only. It logs connections, disconnections and every statement
    (:func:`parse_postgres_log`)."""
    uid, gid = POSTGRES_USER_ID.split(":")
    tmpfs = f"rw,nosuid,nodev,uid={uid},gid={gid}"
    return [
        docker, "run", "-d", "--name", name, *_label(nonce),
        "--network", network, "--ip", address, "--ipc", "none",
        "--dns", "127.0.0.1", "--dns-search", ".",
        "--user", POSTGRES_USER_ID, "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "512m",
        "--tmpfs", f"/var/lib/postgresql/data:{tmpfs},size=256m,mode=0700",
        "--tmpfs", f"/var/run/postgresql:{tmpfs},size=1m",
        "--tmpfs", f"/tmp:{tmpfs},size=64m",  # noqa: S108 - inside the container
        "-e", f"POSTGRES_PASSWORD={password}", *bench._proxies_empty(),
        "-v", f"{volume}:/docker-entrypoint-initdb.d:ro",
        image,
        "-c", "log_connections=on", "-c", "log_disconnections=on", "-c", "log_statement=all",
    ]  # fmt: skip


def pg_isready_command(docker: str, name: str, address: str) -> list[str]:
    # Over TCP: while the image runs its init scripts, the temporary server listens on the
    # socket only, and a ready answer from the socket would come too early.
    return [docker, "exec", name, "pg_isready", "-h", address, "-U", "postgres"]


def fixture_server_command(
    docker: str, nonce: str, name: str, network: str, addresses: Addresses, kind: str,
    volume: str, source: str,
) -> list[str]:  # fmt: skip
    """The fixture server: pages (from the volume, read-only) and the names, ``fixture`` for
    itself and ``postgres`` where the kind has a database. The script is passed as text, so no
    host path is in the command. A kind without pages serves an empty read-only directory. Its
    log (what the report is made of) is kept by docker in one file of at most 8 MB
    (:data:`FIXTURE_LOG_OPTIONS`), the server itself writing down a limited number of events."""
    names = ["--name", f"fixture={addresses.fixture}"]
    if kind == "postgres":
        names += ["--name", f"postgres={addresses.postgres}"]
    pages = ["-v", f"{volume}:/srv/fixture:ro"] if kind in HTTP_KINDS else [
        "--tmpfs", "/srv/fixture:ro,nosuid,nodev,noexec,size=4k"
    ]  # fmt: skip
    return [
        docker, "run", "-d", "--name", name, *_label(nonce), *FIXTURE_LOG_OPTIONS,
        "--network", network, "--ip", addresses.fixture,
        *bench._hardening(), *bench._proxies_empty(), *pages,
        bench.PYTHON_IMAGE, "python", "-B", "-c", source, "--root", "/srv/fixture",
        "--host", "0.0.0.0", *names,  # noqa: S104 - the internal network is the only one
    ]  # fmt: skip


def holder_command(
    docker: str, nonce: str, name: str, network: str, addresses: Addresses
) -> list[str]:
    return [
        docker, "run", "-d", "--name", name, *_label(nonce),
        "--network", network, "--ip", addresses.holder,
        *bench._hardening(), *bench._proxies_empty(),
        bench.PYTHON_IMAGE, "sleep", "infinity",
    ]  # fmt: skip


#: What the helper runs after the rules are in place: a default route without a gateway, so
#: that ``connect()`` to an address beyond the subnet makes a packet the rules count instead of
#: failing at the route lookup (``ENETUNREACH``) unseen. No router exists to send it to.
ROUTE_ARGS: tuple[str, ...] = ("route", "replace", "default", "dev", "eth0")


def nft_command(
    docker: str, nonce: str, name: str, holder: str, image: str, args: Sequence[str],
    stdin: bool = False, program: str = "nft",
) -> list[str]:  # fmt: skip
    """A short helper in the holder's namespace; its one capability is ``NET_ADMIN``.

    ``program`` is ``nft`` or ``ip`` (:data:`ROUTE_ARGS`), both in the helper's image.
    """
    return [
        docker, "run", *(["-i"] if stdin else []), "--rm", "--name", name, *_label(nonce),
        "--network", f"container:{holder}", "--ipc", "none", "--read-only",
        "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges",
        "--pids-limit", "16", "--memory", "64m",
        image, program, *args,
    ]  # fmt: skip


def probe_command(
    docker: str, nonce: str, name: str, holder: str, script: Path, addresses: Addresses,
    kind: str,
) -> list[str]:  # fmt: skip
    return [
        docker, "run", "--rm", "--name", name, *_label(nonce),
        "--network", f"container:{holder}", *bench._hardening(dns=False),
        *bench._proxies_empty(),
        "-v", f"{script}:/probe.py:ro",
        bench.PYTHON_IMAGE, "python", "-B", "/probe.py", addresses.fixture,
        "1" if kind in HTTP_KINDS else "0",
    ]  # fmt: skip


def server_command(
    docker: str, nonce: str, name: str, kind: str, volume: str, image: str, args: Sequence[str],
    env: Sequence[tuple[str, str]], holder: str | None = None, resolv: Path | None = None,
) -> list[str]:  # fmt: skip
    """The server under test. With a network it joins the holder's namespace and reads its
    resolver file from ``resolv`` (the one file of the host); without one it is stage A's
    ``--network none``. The fixture volume goes to ``/srv/fixtures``, read-only for a kind that
    only reads."""
    variables: list[str] = []
    for variable in bench.PROXY_VARIABLES:
        variables += ["-e", f"{variable}="]
    for key, value in env:
        variables += ["-e", f"{key}={value}"]
    mounts: list[str] = []
    if kind in VOLUME_KINDS:
        mode = "" if kind in WRITABLE_KINDS else ":ro"
        mounts += ["-v", f"{volume}:{FILL_PATH}{mode}"]
    if holder is None:
        isolation = list(bench.HARDENING)
    else:
        if resolv is None:
            raise RunnerError("a server in the holder's network needs a resolver file")
        isolation = ["--network", f"container:{holder}", *bench._hardening(dns=False)]
        mounts += ["-v", f"{resolv}:/etc/resolv.conf:ro"]
    return [
        docker, "run", "-i", "--rm", "--name", name, *_label(nonce),
        *isolation, *mounts, *variables, image, *args,
    ]  # fmt: skip


def left_commands(docker: str, nonce: str) -> dict[str, list[str]]:
    """What is asked after the removal, each by the run's label."""
    label = f"label={bench.RUN_LABEL}={nonce}"
    return {
        "containers": [docker, "ps", "-a", "-q", "--filter", label],
        "volumes": [docker, "volume", "ls", "-q", "--filter", label],
        "networks": [docker, "network", "ls", "-q", "--filter", label],
    }


# -- the report ---------------------------------------------------------------------------


@dataclass
class NetworkReport:
    """What a run's network was and what happened in it, counted from the baseline after the
    probe. ``network`` is None for a kind without one."""

    kind: str
    nonce: str
    network: dict[str, Any] | None
    addresses: dict[str, str] | None
    images: dict[str, dict[str, str]]
    probe: dict[str, Any] | None
    sets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    #: The new connections over loopback in the holder's namespace, per target (let through).
    local: list[dict[str, Any]] = field(default_factory=list)
    dns_questions: list[dict[str, Any]] = field(default_factory=list)
    http_requests: list[dict[str, Any]] = field(default_factory=list)
    #: What the fixture server did not write down singly, past its limit: the totals of its
    #: last ``dropped`` line (``http`` requests, ``dns`` questions), zero where it dropped none.
    dropped: dict[str, int | None] = field(default_factory=lambda: {"http": 0, "dns": 0})
    #: Per helper container (``fixture``, ``postgres``): what it tried to reach and what was
    #: refused coming in, counted in its own namespace, and its loopback (``local``); for
    #: ``postgres`` also the sessions, statements and failed logins of its log.
    helpers: dict[str, dict[str, Any]] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=lambda: [IPV6_LIMIT])
    left_after_run: dict[str, list[str]] = field(default_factory=dict)
    isolation: str = "container (docker), not gVisor"

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "nonce": self.nonce,
            "isolation": self.isolation,
            "network": self.network,
            "addresses": self.addresses,
            "images": self.images,
            "probe": self.probe,
            "sets": self.sets,
            "counters": self.counters,
            "local": self.local,
            "dns_questions": self.dns_questions,
            "http_requests": self.http_requests,
            "dropped": self.dropped,
            "helpers": self.helpers,
            "problems": self.problems,
            "limits": self.limits,
            "left_after_run": self.left_after_run,
        }


# -- the run ------------------------------------------------------------------------------


def _sh(command: list[str], *, stdin: bytes | None = None, seconds: int = COMMAND_SECONDS):
    """One docker call. It cannot be run, or does not end in time: a ``RunnerError``."""
    try:
        return subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
            command, input=stdin, capture_output=True, check=False, timeout=seconds
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"{' '.join(command[:3])}: {exc}") from None


def _text(done: subprocess.CompletedProcess) -> str:
    return done.stdout.decode("utf-8", errors="replace")


def _checked(
    command: list[str], what: str, *, stdin: bytes | None = None, seconds: int = COMMAND_SECONDS
):
    done = _sh(command, stdin=stdin, seconds=seconds)
    if done.returncode != 0:
        tail = done.stderr.decode("utf-8", errors="replace").strip()[-400:]
        raise RunnerError(f"{what} failed (exit {done.returncode}): {tail}")
    return done


class StageBNetwork:
    """The network of one stage B run; see the module text.

    ``kind`` is a fixture kind, ``fixture`` the built ``fixtures.Fixture`` of that kind,
    ``definition`` anything with ``postgres_image`` (a ``name@sha256:…`` reference, needed for
    ``postgres`` only), ``out_dir`` the run's output directory, where the resolver file goes.
    After the ``with`` block ``report`` holds the :class:`NetworkReport`.
    """

    def __init__(
        self,
        kind: str,
        fixture: Any,
        definition: Any,
        docker: str,
        out_dir: Path,
        *,
        nonce: str | None = None,
        rng: random.Random | None = None,
        set_size: int = SET_SIZE,
        canary_id: str | None = None,
        reader_password: str | None = None,
        hidden: Sequence[str] = (),
    ) -> None:
        if kind not in KINDS:
            raise RunnerError(f"unknown fixture kind {kind!r}; known: {', '.join(KINDS)}")
        if kind == "postgres" and not reader_password:
            raise RunnerError("the kind postgres needs the run's password of the role reader")
        if getattr(fixture, "kind", kind) != kind:
            raise RunnerError(f"the fixture is of kind {fixture.kind!r}, not {kind!r}")
        self.kind = kind
        self.fixture = fixture
        self.definition = definition
        self.docker = docker
        self.out_dir = Path(out_dir).resolve()
        self.rng = rng
        self.set_size = set_size
        self.nonce = nonce if nonce is not None else secrets.token_hex(4)
        self.has_network = kind in NET_KINDS
        self.network = f"mcpb-netb-{self.nonce}"
        self.volume = f"mcpb-fix-{self.nonce}"
        self.holder = f"mcpb-hold-{self.nonce}"
        self.server_name = f"mcpb-srv-{self.nonce}"
        self.addresses: Addresses | None = None
        self.resolv_path = self.out_dir / f"resolv-{self.nonce}.conf"
        self.report: NetworkReport | None = None
        self._containers: list[str] = []
        self._fixture_name = ""
        self._helpers = 0
        self._images: dict[str, dict[str, str]] = {}
        self._probe: dict[str, Any] | None = None
        self._base_counts: NftCounts | None = None
        self._base_log: FixtureLog | None = None
        self._counts: NftCounts | None = None
        self._log: FixtureLog | None = None
        #: What the end of the run could not read, and why: the report says it.
        self._unread: list[str] = []
        self._postgres_password = secrets.token_urlsafe(24)
        self.canary_id = canary_id
        self._reader_password = reader_password
        self._hidden = tuple(hidden)
        self._postgres_name = f"mcpb-pg-{self.nonce}"
        #: Counters of the helper containers' namespaces and PostgreSQL's log, at the baseline
        #: and at the end.
        self._base_helpers: dict[str, NftCounts] = {}
        self._helper_counts: dict[str, NftCounts] = {}
        self._base_pg: PostgresLog | None = None
        self._pg: PostgresLog | None = None

    @property
    def secrets(self) -> tuple[str, ...]:
        """The run's secrets: what no file, output or report of the runner may hold. The
        passwords, and what the caller gave as ``hidden`` (the values of the server's
        environment)."""
        if self.kind != "postgres":
            return self._hidden
        return (str(self._reader_password), self._postgres_password, *self._hidden)

    def _scrub(self, text: str) -> str:
        return bench.scrub(text, self.canary_id, self.secrets)

    @property
    def helper_names(self) -> dict[str, str]:
        """The helper containers whose namespaces have rules of their own, by role."""
        if not self.has_network:
            return {}
        names = {"fixture": self._fixture_name or f"mcpb-fixsrv-{self.nonce}"}
        if self.kind == "postgres":
            names["postgres"] = self._postgres_name
        return names

    # -- names ------------------------------------------------------------------------

    def _helper(self, role: str) -> str:
        self._helpers += 1
        name = f"mcpb-{role}-{self.nonce}-{self._helpers}"
        self._containers.append(name)
        return name

    def _container(self, name: str) -> str:
        self._containers.append(name)
        return name

    # -- the server -------------------------------------------------------------------

    def server_command(
        self, image: str, args: Sequence[str], env: Sequence[tuple[str, str]] = ()
    ) -> list[str]:
        """The command that starts the server under test in this run's network (or none)."""
        if self.has_network and self.addresses is None:
            raise RunnerError("the network is not up; use the run inside its with block")
        self._containers.append(self.server_name)
        return server_command(
            self.docker,
            self.nonce,
            self.server_name,
            self.kind,
            self.volume,
            image,
            [self._with_url(a) for a in args],
            env,
            holder=self.holder if self.has_network else None,
            resolv=self.resolv_path if self.has_network else None,
        )

    def _with_url(self, argument: str) -> str:
        """``{postgres_url}`` in an argument: the URL of the database with the role ``reader``
        and this run's password. The only place that password is put together."""
        if bench.POSTGRES_URL_PLACEHOLDER not in argument:
            return argument
        if self.kind != "postgres":
            raise RunnerError(f"{bench.POSTGRES_URL_PLACEHOLDER} in the arguments, and no database")
        url = (
            f"postgresql://{READER_ROLE}:{self._reader_password}@postgres:{POSTGRES_PORT}/postgres"
        )
        return argument.replace(bench.POSTGRES_URL_PLACEHOLDER, url)

    # -- entering ---------------------------------------------------------------------

    def __enter__(self) -> StageBNetwork:
        try:
            self._set_up()
        except BaseException:
            try:
                self._tear_down()
            except RunnerError as leftover:
                print(f"bench: {leftover}", file=sys.stderr)
            raise
        return self

    def _image(self, role: str, reference: str) -> str:
        image = bench.image_id(self.docker, reference)
        self._images[role] = {"reference": reference, "id": image}
        return image

    def _check_images(self) -> None:
        self._image("python", bench.PYTHON_IMAGE)
        if not self.has_network:
            return
        nft_id = self._image("nft", NFT_IMAGE)
        context, _ = bench.HELPER_IMAGES[NFT_IMAGE]
        digest, _ = bench.context_digest(context)
        config = bench.image_inspect(self.docker, nft_id).get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        found = labels.get(bench.CONTEXT_LABEL) if isinstance(labels, dict) else None
        if found != digest:
            raise RunnerError(
                f"{NFT_IMAGE} was not built from the context as it is now: the image says "
                f"{found}, the context is {digest}; run bench.py build-helpers"
            )
        if self.kind == "postgres":
            reference = getattr(self.definition, "postgres_image", None)
            if not isinstance(reference, str) or not re.fullmatch(
                r"[^\s@]+@sha256:[0-9a-f]{64}", reference
            ):
                raise RunnerError("the definition names no PostgreSQL image by digest")
            self._image("postgres", reference)

    def _set_up(self) -> None:
        self._check_images()
        self._create_volume()
        if not self.has_network:
            return
        self._create_network()
        assert self.addresses is not None  # noqa: S101 - set by _create_network
        addresses = self.addresses
        if self.kind == "postgres":
            self._start_postgres(addresses)
        self._start_fixture_server(addresses)
        # The helpers are counted from before the holder exists: nothing they do is unseen.
        self._load_helper_rules(addresses)
        _checked(
            holder_command(
                self.docker, self.nonce, self._container(self.holder), self.network, addresses
            ),
            "the holder's container",
        )
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.resolv_path.write_text(resolv_conf(addresses), encoding="ascii")
        self.resolv_path.chmod(0o644)
        self._load_rules(addresses)
        _checked(
            nft_command(
                self.docker, self.nonce, self._helper("route"), self.holder, NFT_IMAGE,
                ROUTE_ARGS, program="ip",
            ),
            "the default route without a gateway",
        )  # fmt: skip
        self._run_probe(addresses)
        self._base_counts = self._read_counts()
        self._base_log = self._read_log()
        self._base_helpers = self._read_helper_counts()
        if self.kind == "postgres":
            self._base_pg = self._read_pg_log()

    def _create_volume(self) -> None:
        _checked(
            volume_create_command(self.docker, self.nonce, self.volume), "docker volume create"
        )
        try:
            _checked(
                fill_command(self.docker, self.nonce, self._helper("fill"), self.volume),
                "filling the fixture volume",
                stdin=self.fixture.archive,
            )
        except SetupFailure:
            raise
        except RunnerError as failure:
            raise SetupFailure("fixture_fill_failed", str(failure)) from None

    def _create_network(self) -> None:
        tried: list[ipaddress.IPv4Network] = []
        for _ in range(SUBNET_ATTEMPTS):
            subnet = choose_subnet(self.rng, tried)
            tried.append(subnet)
            created = _sh(network_create_command(self.docker, self.nonce, subnet))
            if created.returncode == 0:
                self.addresses = Addresses(subnet)
                return
            message = created.stderr.decode("utf-8", errors="replace")
            if "overlap" not in message.lower():
                raise RunnerError(f"docker network create failed: {message.strip()}")
        raise RunnerError(f"the subnet overlapped another one {SUBNET_ATTEMPTS} times")

    def _start_postgres(self, addresses: Addresses) -> None:
        name = self._container(self._postgres_name)
        image = self._images["postgres"]["reference"]
        _checked(
            postgres_command(
                self.docker,
                self.nonce,
                name,
                self.network,
                addresses.postgres,
                image,
                self.volume,
                self._postgres_password,
            ),
            "the PostgreSQL container",
        )
        deadline = time.monotonic() + POSTGRES_READY_SECONDS
        while True:
            done = _sh(pg_isready_command(self.docker, name, addresses.postgres), seconds=30)
            if done.returncode == 0:
                return
            if time.monotonic() >= deadline:
                raise SetupFailure(
                    "fixture_not_ready", f"PostgreSQL was not ready in {POSTGRES_READY_SECONDS} s"
                )
            time.sleep(0.5)

    def _start_fixture_server(self, addresses: Addresses) -> None:
        name = self._container(f"mcpb-fixsrv-{self.nonce}")
        self._fixture_name = name
        source = FIXTURE_SERVER.read_text(encoding="utf-8")
        self._images["fixture_server"] = {
            "script_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()
        }
        _checked(
            fixture_server_command(
                self.docker,
                self.nonce,
                name,
                self.network,
                addresses,
                self.kind,
                self.volume,
                source,
            ),
            "the fixture server's container",
        )
        deadline = time.monotonic() + READY_SECONDS
        while not self._read_log().ready:
            if time.monotonic() >= deadline:
                raise SetupFailure(
                    "fixture_not_ready", f"the fixture server was not ready in {READY_SECONDS} s"
                )
            time.sleep(0.25)

    def _read_log(self) -> FixtureLog:
        done = _checked(
            [self.docker, "logs", self._fixture_name], "docker logs of the fixture server"
        )
        log = parse_fixture_log(_text(done))
        error = done.stderr.decode("utf-8", errors="replace").strip()
        if error:
            log = FixtureLog(log.events, (*log.problems, f"stderr: {error[-200:]}"))
        return log

    def _load_rules(self, addresses: Addresses) -> None:
        _checked(
            nft_command(
                self.docker,
                self.nonce,
                self._helper("nft"),
                self.holder,
                NFT_IMAGE,
                ["-f", "-"],
                stdin=True,
            ),
            "loading the counting rules",
            stdin=nft_ruleset(self.kind, addresses, self.set_size).encode("ascii"),
        )

    def _read_pg_log(self) -> PostgresLog:
        """PostgreSQL's log as it is now (it writes to stderr), cleaned with ``scrub``."""
        done = _checked([self.docker, "logs", self._postgres_name], "docker logs of PostgreSQL")
        text = _text(done) + done.stderr.decode("utf-8", errors="replace")
        assert self.addresses is not None  # noqa: S101 - the network is up
        return parse_postgres_log(text, self.addresses.postgres, self._scrub)

    def _load_helper_rules(self, addresses: Addresses) -> None:
        """The helpers' rules, each in the namespace of its container, and their default route
        (without which an attempt beyond the subnet fails unseen). Not loaded is an error of
        the set-up itself, not tried again: the rules are wrong or the helper is."""
        for role, container in self.helper_names.items():
            _checked(
                nft_command(
                    self.docker, self.nonce, self._helper("nft"), container, NFT_IMAGE,
                    ["-f", "-"], stdin=True,
                ),
                f"loading the counting rules of the {role}",
                stdin=helper_ruleset(role, addresses, self.set_size).encode("ascii"),
            )  # fmt: skip
            _checked(
                nft_command(
                    self.docker, self.nonce, self._helper("route"), container, NFT_IMAGE,
                    ROUTE_ARGS, program="ip",
                ),
                f"the default route without a gateway of the {role}",
            )  # fmt: skip

    def _read_helper_counts(self, only: str | None = None) -> dict[str, NftCounts]:
        counts: dict[str, NftCounts] = {}
        for role, container in self.helper_names.items():
            if only is not None and role != only:
                continue
            done = _checked(
                nft_command(
                    self.docker, self.nonce, self._helper("nft"), container, NFT_IMAGE,
                    ["-j", "list", "table", "inet", NFT_TABLE],
                ),
                f"reading the counters of the {role}",
            )  # fmt: skip
            counts[role] = parse_nft(_text(done), HELPER_SETS, HELPER_COUNTERS)
        return counts

    def _read_counts(self) -> NftCounts:
        done = _checked(
            nft_command(
                self.docker,
                self.nonce,
                self._helper("nft"),
                self.holder,
                NFT_IMAGE,
                ["-j", "list", "table", "inet", NFT_TABLE],
            ),
            "reading the counters",
        )
        return parse_nft(_text(done))

    def _run_probe(self, addresses: Addresses) -> None:
        with tempfile.TemporaryDirectory(prefix="mcpb-probe-") as scratch:
            script = Path(scratch) / "probe.py"
            script.write_text(STAGE_B_PROBE_SCRIPT, encoding="utf-8")
            script.chmod(0o644)
            done = _sh(
                probe_command(
                    self.docker,
                    self.nonce,
                    self._helper("probe"),
                    self.holder,
                    script,
                    addresses,
                    self.kind,
                ),
                seconds=60,
            )
        lines = [line for line in _text(done).splitlines() if line.strip()]
        try:
            result = json.loads(lines[-1]) if lines else None
        except ValueError:
            result = None
        if not isinstance(result, dict):
            tail = (done.stderr.decode("utf-8", errors="replace") or _text(done)).strip()[-400:]
            raise SetupFailure(
                "network_probe_failed", f"the probe gave no result (exit {done.returncode}): {tail}"
            )
        # Counting works if the probe's own attempt is in the refused set, as exactly one
        # packet (rejected, not retried), and only then.
        counted = self._read_counts().sets["refused4"]
        result["counting_works"] = any(
            target[0] == PROBE_TARGET[0]
            and target[1] == "tcp"
            and target[2] == PROBE_TARGET[1]
            and count.packets == 1
            for target, count in counted.items()
        )
        self._probe = result
        failed = [name for name in PROBE_CHECKS if result.get(name) is not True]
        if failed:
            raise SetupFailure(
                "network_probe_failed",
                f"the network is not as required; failed: {', '.join(failed)}; "
                f"probe: {json.dumps(result, sort_keys=True)}",
            )

    # -- leaving ----------------------------------------------------------------------

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        failure: RunnerError | None = None
        if self.has_network:
            # Also after an exception in the body (a timeout, Ctrl-C): what the server tried
            # before that is in the counters and the log, and must not be lost with it.
            failure = self._read_end()
        try:
            self._tear_down()
        except RunnerError as leftover:
            failure = failure or leftover
        if failure is None:
            return
        if exc_type is None:
            raise failure
        print(f"bench: {failure}", file=sys.stderr)

    def _read_end(self) -> RunnerError | None:
        """Counters and log at the end of the run, each on its own, so that one that cannot be
        read does not hide the other. What is not read is said in ``_unread``."""
        failure: RunnerError | None = None
        if self._base_counts is None or self._base_log is None:
            self._unread.append("counters and log not read: the baseline was never taken")
            return None
        try:
            self._counts = self._read_counts()
        except RunnerError as error:
            failure = error
            self._unread.append(f"counters not read: {error}")
        try:
            self._log = self._read_log()
        except RunnerError as error:
            failure = failure or error
            self._unread.append(f"fixture server log not read: {error}")
        for role in self.helper_names:
            try:
                self._helper_counts.update(self._read_helper_counts(only=role))
            except RunnerError as error:
                failure = failure or error
                self._unread.append(f"counters of the {role} not read: {error}")
        if self.kind == "postgres":
            try:
                self._pg = self._read_pg_log()
            except RunnerError as error:
                failure = failure or error
                self._unread.append(f"PostgreSQL log not read: {error}")
        return failure

    def _tear_down(self) -> None:
        """Remove what the run made, in reverse, whatever happened; then ask by the label what
        is left. The report is built here. A leftover is a ``RunnerError`` after all of it."""
        for name in reversed(self._containers):
            with contextlib.suppress(OSError):
                bench.remove_container(self.docker, name)
        for command in (
            [self.docker, "volume", "rm", "-f", self.volume],
            [self.docker, "network", "rm", self.network],
        ):
            with contextlib.suppress(RunnerError):
                _sh(command, seconds=60)
        left: dict[str, list[str]] = {}
        for what, command in left_commands(self.docker, self.nonce).items():
            try:
                done = _sh(command, seconds=60)
                if done.returncode != 0:
                    left[what] = [f"<could not be checked: exit {done.returncode}>"]
                else:
                    left[what] = _text(done).split()
            except RunnerError as error:
                left[what] = [f"<could not be checked: {error}>"]
        self.report = self._build_report(left)
        remaining = {what: found for what, found in left.items() if found}
        if remaining:
            raise RunnerError(
                f"left after the run {self.nonce}, remove by hand: "
                + "; ".join(f"{what}: {', '.join(found)}" for what, found in remaining.items())
            )

    def _build_report(self, left: dict[str, list[str]]) -> NetworkReport:
        report = NetworkReport(
            kind=self.kind,
            nonce=self.nonce,
            network=None,
            addresses=None,
            images=self._images,
            probe=self._probe,
            left_after_run=left,
        )
        if self.addresses is not None:
            report.network = {
                "name": self.network,
                "internal": True,
                "options": dict(bench.NETWORK_OPTIONS),
                "label": f"{bench.RUN_LABEL}={self.nonce}",
                "subnet": str(self.addresses.subnet),
            }
            report.addresses = self.addresses.as_dict()
        if self._counts is not None and self._base_counts is not None:
            try:
                since = self._counts.minus(self._base_counts).as_dict()
            except NftError as error:
                report.problems.append(str(error))
            else:
                report.counters = since.pop("counters")
                report.local = since.pop("local4")
                report.sets = since
                if report.counters.get("overflow"):
                    report.problems.append(
                        f"more than {self.set_size} distinct targets; "
                        "the rest counted without target"
                    )
        if self._log is not None and self._base_log is not None:
            since_log = self._log.since(self._base_log)
            report.problems.extend(since_log.problems)
            report.dns_questions = [
                {k: e.get(k) for k in ("name", "type", "answer", "rcode", "client")}
                for e in since_log.of("dns")
            ]
            report.http_requests = [
                {k: e.get(k) for k in ("method", "path", "status", "client", "user_agent")}
                for e in since_log.of("http")
            ]
            for what, listed in (
                ("dns_questions", report.dns_questions),
                ("http_requests", report.http_requests),
            ):
                if len(listed) > REPORT_EVENT_LIMIT:
                    report.problems.append(
                        f"{what}: {len(listed)} in the log, the first {REPORT_EVENT_LIMIT} listed"
                    )
                    del listed[REPORT_EVENT_LIMIT:]
            dropped = since_log.dropped()
            if dropped is not None:
                report.dropped = dropped
                report.problems.append(
                    f"the fixture server dropped events past its limit: {_total(dropped['http'])}"
                    f" requests and {_total(dropped['dns'])} questions are not listed"
                    " (totals so far)"
                )
        self._add_helpers(report)
        report.problems.extend(self._unread)
        return report

    def _add_helpers(self, report: NetworkReport) -> None:
        """What the helper containers tried and were refused, from the baseline; for PostgreSQL
        the sessions and statements as well. A role that was not read is in ``_unread``."""
        for role, counts in self._helper_counts.items():
            base = self._base_helpers.get(role)
            if base is None:
                continue
            try:
                since = counts.minus(base).as_dict()
            except NftError as error:
                report.problems.append(f"{role}: {error}")
                continue
            counters = since.pop("counters")
            local = since.pop("local4")
            entry: dict[str, Any] = {"sets": since, "local": local, "counters": counters}
            report.helpers[role] = entry
            if counters.get("overflow"):
                report.problems.append(
                    f"{role}: more than {self.set_size} distinct targets; "
                    "the rest counted without target"
                )
        if self._pg is not None and self._base_pg is not None:
            since_pg = self._pg.since(self._base_pg)
            report.problems.extend(since_pg.problems)
            report.helpers.setdefault("postgres", {}).update(
                {
                    "sessions": list(since_pg.sessions),
                    "statements": list(since_pg.statements),
                    "failed_logins": list(since_pg.failed_logins),
                }
            )
