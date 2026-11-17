"""The authoritative record, what the probe proved, and the sink's account held against both.

Pure functions over what the reader, the probe and the sink printed; no Docker here.

**The record is the kernel's.** Counters and sets in the ruleset count every attempt with
its original destination, before the redirect rewrites it: TCP once per connection (in the
NAT chain, which sees a connection's first packet only), UDP, ICMP and every other protocol
once per packet. No process without ``CAP_NET_ADMIN`` can read or change them, which is what
the target is denied and the sink never had. So the record is what the sink's account is
checked against, never the other way round.

**A datagram carries its destination's mark.** The ruleset marks every UDP datagram, before
the redirect, with a digest of its original destination and port, and keeps the mark beside
that destination in its set. The sink reads the mark off each datagram it receives
(``SO_RCVMARK``, no capability needed) — so UDP, whose original destination the sink cannot
otherwise read, is matched destination by destination like TCP.

**A full set is a recorded cap, not a gap.** Each class has a counter that is incremented
before the destination is added to its set. When the set is full the destination is lost but
the count is not, and ``counter − sum(set)`` is exactly how many attempts went unrecorded by
destination: the run is complete, and says what it cut and why.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from mcp_kymograph.sandbox.inside import common

#: Set name → (protocol, address family, what the second half of an element is).
SETS: dict[str, tuple[str, int, str]] = {
    "tcp4": ("tcp", 4, "port"),
    "tcp6": ("tcp", 6, "port"),
    "udp4": ("udp", 4, "port"),
    "udp6": ("udp", 6, "port"),
    "icmp4": ("icmp", 4, "type"),
    "icmp6": ("icmp", 6, "type"),
    "other4": ("other", 4, "l4proto"),
    "other6": ("other", 6, "l4proto"),
}
COUNTERS = tuple(f"n_{name}" for name in SETS) + ("n_direct",)

#: What one count means per protocol: TCP is counted per connection, the rest per packet.
UNITS = {"tcp": "connections", "udp": "packets", "icmp": "packets", "other": "packets"}

#: The sets whose elements carry, as a third field, the mark every datagram to them was given.
MARKED = frozenset({"udp4", "udp6"})

#: The name nft gives ICMP echo request in both families.
ECHO_REQUEST = "echo-request"

#: The port a name is asked on, as the target addresses it (the redirect sends it on to
#: :data:`common.DNS_PORT`).
QUERY_PORT = 53


class RecordError(ValueError):
    """The reader's output is not the record of the ruleset that was loaded."""


@dataclass(frozen=True)
class Record:
    counters: dict[str, int]
    #: ``(set, address, second)`` → packets; ``second`` is a port, an ICMP type or a protocol.
    elements: dict[tuple[str, str, Any], int]
    #: ``(set, address, port)`` → the mark every datagram to that destination was given (UDP
    #: only): what the sink reads off each datagram, so the two accounts can be matched.
    marks: dict[tuple[str, str, Any], int] = field(default_factory=dict)

    def capped(self) -> dict[str, int]:
        """Per set: attempts counted but not recorded by destination, because the set was full."""
        out = {}
        for name in SETS:
            listed = sum(n for (s, _, _), n in self.elements.items() if s == name)
            missing = self.counters[f"n_{name}"] - listed
            if missing > 0:
                out[name] = missing
        return out

    def attempts(self) -> list[dict[str, Any]]:
        """Every destination the record holds, as attempts in our own words."""
        out = []
        for (name, address, second), count in sorted(self.elements.items(), key=str):
            proto, family, kind = SETS[name]
            out.append(
                {
                    "proto": proto,
                    "family": family,
                    "destination": address,
                    kind: second,
                    "count": count,
                    "unit": UNITS[proto],
                }
            )
        return out


def parse_record(document: Any) -> Record:
    """The counters and sets of our table, out of ``nft -j list table``. Strict on shape."""
    try:
        items = document["nftables"]
        counters: dict[str, int] = {}
        elements: dict[tuple[str, str, Any], int] = {}
        marks: dict[tuple[str, str, Any], int] = {}
        for item in items:
            if "counter" in item and item["counter"].get("table") == common.TABLE:
                counters[item["counter"]["name"]] = int(item["counter"]["packets"])
            elif "set" in item and item["set"].get("table") == common.TABLE:
                name = item["set"]["name"]
                if name not in SETS:
                    raise RecordError(f"an unknown set {name!r} in the table")
                for entry in item["set"].get("elem", []):
                    values = entry["elem"]["val"]["concat"]
                    if len(values) != (3 if name in MARKED else 2):
                        raise RecordError(f"an element of set {name!r} has {len(values)} fields")
                    key = (name, _address(values[0]), values[1])
                    if key in elements:
                        raise RecordError(f"{key} is in the record twice, under two marks")
                    elements[key] = int(entry["elem"]["counter"]["packets"])
                    if name in MARKED:
                        marks[key] = int(values[2])
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, RecordError):
            raise
        raise RecordError(f"the reader's output is not an nft record: {exc!r}") from None
    missing = [name for name in COUNTERS if name not in counters]
    if missing:
        raise RecordError(f"the table lacks counters {', '.join(missing)}")
    return Record(counters, elements, marks)


def delta(after: Record, before: Record) -> Record:
    """What happened between two readings. A count that went down means the record was reset
    or replaced in between, which nothing in the sandbox does — so it is refused."""
    counters = {}
    for name, value in after.counters.items():
        moved = value - before.counters.get(name, 0)
        if moved < 0:
            raise RecordError(f"counter {name} went backwards between the two readings")
        counters[name] = moved
    elements = {}
    for key, value in after.elements.items():
        moved = value - before.elements.get(key, 0)
        if moved < 0:
            raise RecordError(f"the count for {key} went backwards between the two readings")
        if moved:
            elements[key] = moved
    for key in before.elements:
        if key not in after.elements:
            raise RecordError(f"{key} vanished from the record between the two readings")
    return Record(counters, elements, {k: v for k, v in after.marks.items() if k in elements})


def _address(value: Any) -> str:
    return ipaddress.ip_address(str(value)).compressed


# -- the probe -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """One condition the gate needs: whether it held, and the evidence either way."""

    ok: bool
    detail: dict[str, Any] = field(default_factory=dict)


def judge_report(report: dict[str, Any], resolv_conf: str) -> dict[str, Verdict]:
    """What the probe saw before it made a single attempt: the namespace as the target sees it.

    Judged on the probe's report alone, before anything else is read, so that a condition
    that fails here is reported as itself and not as a later step that could not happen.
    """
    read = report.get("authoritative_read") or {}
    confined = report.get("confinement") or {}
    return {
        # Read from inside, under the target's flags: unprivileged, every capability set
        # empty, no way to gain one, a seccomp filter, and a root file system mounted
        # read-only. What the README promises about the target, checked on every run.
        "confinement": Verdict(
            confined.get("uid") == common.UNPRIVILEGED_UID
            and bool(confined.get("caps"))
            and all(v == common.NO_CAPABILITIES for v in confined["caps"].values())
            and confined.get("no_new_privs") is True
            and confined.get("seccomp") == common.SECCOMP_FILTER
            and confined.get("root_read_only") is True,
            dict(confined),
        ),
        "barrier": Verdict(
            report.get("interfaces") == common.expected_interfaces(),
            {"seen": report.get("interfaces"), "expected": common.expected_interfaces()},
        ),
        "sink_bindings": Verdict(
            report.get("sockets") == common.expected_inventory(),
            {"seen": report.get("sockets"), "expected": common.expected_inventory()},
        ),
        "resolver": Verdict(
            report.get("resolv_conf") == resolv_conf, {"seen": report.get("resolv_conf")}
        ),
        # Refused, and nothing read: under the target's credentials the authoritative record
        # is out of reach. Exactly the argv the reader uses, so it is the same record.
        "authoritative_unreadable": Verdict(
            read.get("returncode") not in (0, None) and read.get("stdout_bytes") == 0,
            {"read": list(common.AUTHORITATIVE_READ), **read},
        ),
    }


def judge_arrivals(
    nonce: str, report: dict[str, Any], sink_events: list[dict[str, Any]], record: Record
) -> dict[str, Verdict]:
    """Whether every attempt arrived — at the sink where it can, and in the record always."""
    plan = common.probe_plan(nonce)
    attempts = report.get("attempts") or {}
    arrivals = {
        name: _arrival(name, spec, attempts.get(name) or {}, sink_events, record, nonce)
        for name, spec in plan.items()
    }
    direct = report.get("direct") or {}
    return {
        # Refused locally, and refused by the rule (the kernel counted it): the sink is
        # reachable through the redirect and in no other way.
        "direct_blocked": Verdict(
            not direct.get("connected") and record.counters.get("n_direct", 0) >= 1,
            {"local": direct, "counted": record.counters.get("n_direct", 0)},
        ),
        "probe": Verdict(all(a["arrived"] for a in arrivals.values()), arrivals),
        "udp_marks": _marks_apart(plan, record),
    }


def _marks_apart(plan: dict[str, dict[str, Any]], record: Record) -> Verdict:
    """The marks tell UDP destinations apart: the probe sent datagrams to two destinations per
    family, and they must carry two marks, neither of them zero — the mark of a datagram the
    ruleset marked not at all. Arriving under the mark the kernel recorded proves that sink and
    kernel agree on a mark; only this proves that the mark says where a datagram was going, and
    that UDP is held destination by destination rather than, silently, family by family."""
    per_family: dict[str, list[int | None]] = {}
    for spec in plan.values():
        if spec["proto"] == "udp":
            name = f"udp{spec['family']}"
            element = (name, _address(spec["destination"]), spec["port"])
            per_family.setdefault(name, []).append(record.marks.get(element))
    held = bool(per_family) and all(
        None not in marks and 0 not in marks and len(set(marks)) == len(marks)
        for marks in per_family.values()
    )
    return Verdict(held, dict(sorted(per_family.items())))


def _arrival(
    name: str,
    spec: dict[str, Any],
    local: dict[str, Any],
    sink_events: list[dict[str, Any]],
    record: Record,
    nonce: str,
) -> dict[str, Any]:
    family = spec["family"]
    destination = _address(spec["destination"])
    proto = spec["proto"]
    if proto == "icmp":
        recorded = record.elements.get((f"icmp{family}", destination, ECHO_REQUEST), 0) >= 1
        return {"arrived": recorded, "sink": None, "record": recorded, "local": local}
    port = spec["port"]
    element = (f"{proto}{family}", destination, port)
    recorded = record.elements.get(element, 0) >= 1
    # A datagram arrived only if it reached the sink under the mark the kernel recorded for
    # its destination: that is what proves, on every run, that UDP can be told apart by it.
    marked = record.marks.get(element)

    def attributed(event: dict[str, Any]) -> bool:
        return proto != "udp" or (marked is not None and event.get("mark") == marked)

    if "qname" in spec:
        asked = any(
            e.get("event") == "dns"
            and e.get("transport") == proto
            and e.get("family") == family
            and e.get("qname") == spec["qname"]
            and attributed(e)
            for e in sink_events
        )
        answered = local.get("answer") == common.DNS_ANSWER_V4
        sink = asked and (proto == "udp" or _tcp_seen(sink_events, family, destination, port))
        return {
            "arrived": sink and recorded and answered,
            "sink": sink,
            "record": recorded,
            "answered": answered,
            "local": local,
        }
    if proto == "tcp":
        sink = _tcp_seen(sink_events, family, destination, port)
    else:
        marker = f"probe {name} {nonce}\n".encode().hex()
        sink = any(
            e.get("event") == "udp"
            and e.get("family") == family
            and e.get("preview") == marker
            and attributed(e)
            for e in sink_events
        )
    return {"arrived": sink and recorded, "sink": sink, "record": recorded, "local": local}


def _tcp_seen(events: list[dict[str, Any]], family: int, destination: str, port: int) -> bool:
    return any(
        e.get("event") == "tcp"
        and e.get("family") == family
        and e.get("port") == port
        and e.get("destination") is not None
        and _address(e["destination"]) == destination
        for e in events
    )


# -- after the target ------------------------------------------------------------------------


@dataclass(frozen=True)
class Reconciliation:
    problems: list[str]
    capped: dict[str, int]
    #: Per class where the counts differ, both counts — recorded, never judged: a count can
    #: differ for reasons that are no gap (a retransmitted query, a datagram the sink's buffer
    #: could not hold), and only what is named on one side and missing on the other is.
    differences: dict[str, dict[str, int]] = field(default_factory=dict)
    #: Per UDP set: datagrams the kernel counted and the sink received, how many it lost, and
    #: how many destinations it never saw a single datagram of because of that.
    loss: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def consistent(self) -> bool:
        return not self.problems


def reconcile(
    record: Record, events: list[dict[str, Any]], totals: dict[str, int], suppressed: int
) -> Reconciliation:
    """Hold the sink's account of the target's phase against the kernel's record of it — by
    membership, never by count, destination by destination.

    **TCP:** every destination the sink names must be in the kernel's set, and every
    destination in the kernel's set must be named by the sink — the first unless the set was
    full, the second unless the sink's own events were capped. **UDP** the same, through the
    mark each datagram carries: every mark the sink names must be one the kernel gave, and
    every destination the kernel recorded must be named — unless the sink lost datagrams, and
    lost at least as many as went to the destinations it never named. A datagram the sink's
    queue could not hold is loss, written down (``loss``) and judged by the verdict; a sink
    that received as much as it says and still cannot place it is not.

    Counts are not compared otherwise: a retransmission moves a count without anything going
    unobserved, and must not invalidate a run. Where counts differ, both are recorded
    (``differences``). Any disagreement in membership makes the observation invalid — the
    kernel's record stands, but the account of what the target sent cannot be trusted.
    """
    problems: list[str] = []
    loss: dict[str, dict[str, int]] = {}
    capped = record.capped()
    for family in (4, 6):
        problems += _tcp_membership(record, events, totals, suppressed, capped, family)
        found, loss[f"udp{family}"] = _udp_membership(
            record, events, totals, suppressed, capped, family
        )
        problems += found
    if totals.get("errors"):
        problems.append(f"the sink failed to handle {totals['errors']} item(s)")
    return Reconciliation(problems, capped, _differences(record, totals, capped), loss)


def _tcp_membership(record, events, totals, suppressed, capped, family) -> list[str]:
    name = f"tcp{family}"
    kernel = {(a, p) for (s, a, p) in record.elements if s == name}
    sink = {
        (_address(e["destination"]), e.get("port"))
        for e in events
        if e.get("event") == "tcp"
        and e.get("family") == family
        and e.get("destination") is not None
    }
    problems = []
    if name not in capped and sink - kernel:
        problems.append(
            f"tcp over IPv{family}: the sink names {len(sink - kernel)} destination(s) the "
            "kernel never recorded"
        )
    if not suppressed and kernel - sink:
        problems.append(
            f"tcp over IPv{family}: the kernel recorded {len(kernel - sink)} destination(s) the "
            "sink never named"
        )
    sink_any = bool(sink) or (bool(suppressed) and int(totals.get(name, 0)) > 0)
    if (record.counters[f"n_{name}"] > 0) != sink_any:
        problems.append(_one_sided(f"tcp over IPv{family}", record.counters[f"n_{name}"] > 0))
    return problems


def _udp_membership(record, events, totals, suppressed, capped, family):
    """UDP destination by destination, through the marks. Returns the disagreements, and what
    the sink lost: datagrams the kernel counted and the sink never received, and the
    destinations it therefore never saw at all.

    A mark is a 32-bit digest, so two destinations can share one — for a full set of 4096,
    about one run in 500; for a few dozen, practically never. The sink naming that mark then
    counts for both, which can only hide a destination it missed, never invent one.
    """
    name = f"udp{family}"
    kernel = {m: k for k, m in record.marks.items() if k[0] == name and k in record.elements}
    received = [
        e
        for e in events
        if e.get("family") == family
        and (e.get("event") == "udp" or (e.get("event") == "dns" and e.get("transport") == "udp"))
    ]
    problems = []
    unmarked = sum(1 for e in received if not _is_mark(e.get("mark")))
    if unmarked:
        problems.append(
            f"udp over IPv{family}: the sink could not tell where {unmarked} datagram(s) were "
            "going (no mark)"
        )
    seen = {(e["mark"], e["event"] == "dns") for e in received if _is_mark(e.get("mark"))}
    named = {m for m, _ in seen}
    if name not in capped and named - kernel.keys():
        problems.append(
            f"udp over IPv{family}: the sink names {len(named - kernel.keys())} destination(s) "
            "the kernel never recorded"
        )
    # Port 53 is redirected to the sink's question socket, everything else to the other one:
    # a destination heard on the wrong one was not redirected as the ruleset says.
    crossed = {m for m, asked in seen if m in kernel and (kernel[m][2] == QUERY_PORT) != asked}
    if crossed:
        problems.append(
            f"udp over IPv{family}: {len(crossed)} destination(s) arrived at the other socket "
            "than their port is redirected to"
        )
    counted = record.counters[f"n_{name}"]
    received_count = int(totals.get(name, 0))
    lost = max(counted - received_count, 0)
    unseen = (
        []
        if suppressed
        else [
            k
            for k, m in record.marks.items()
            if k[0] == name and k in record.elements and m not in named
        ]
    )
    if sum(record.elements[key] for key in unseen) > lost:
        problems.append(
            f"udp over IPv{family}: the kernel recorded {len(unseen)} destination(s) the sink "
            f"never named, more than the {lost} datagram(s) it lost can explain"
        )
    loss = {
        "kernel": counted,
        "sink": received_count,
        "lost": lost,
        "unseen_destinations": len(unseen),
    }
    return problems, loss


def _is_mark(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _one_sided(what: str, kernel: bool) -> str:
    if kernel:
        return f"{what}: the kernel recorded attempts, the sink saw none"
    return f"{what}: the sink saw attempts the kernel never recorded"


def _differences(record: Record, totals: dict[str, int], capped: dict[str, int]) -> dict:
    """Where kernel and sink counts differ, both — for the reader, not for the verdict."""
    out = {}
    for family in (4, 6):
        for proto in ("tcp", "udp"):
            kernel = record.counters[f"n_{proto}{family}"]
            sink = int(totals.get(f"{proto}{family}", 0))
            if kernel != sink:
                out[f"{proto}{family}"] = {"kernel": kernel, "sink": sink}
        if f"udp{family}" not in capped:
            kernel = sum(
                n
                for (s, _, p), n in record.elements.items()
                if s == f"udp{family}" and p == QUERY_PORT
            )
            sink = int(totals.get(f"dns_udp{family}", 0))
            if kernel != sink:
                out[f"dns_udp{family}"] = {"kernel": kernel, "sink": sink}
    return out
