"""The sandbox's logic without Docker: policy, gate, record, reconciliation, delivery.

Everything here is a pure function over what the containers print, so it is tested on its
own. The containers themselves are tested in ``test_sandbox_runc.py``.
"""

from __future__ import annotations

import json
import re
import socket
import stat
import tempfile
import types
from pathlib import Path

import pytest

from mcp_kymograph.identity import from_content
from mcp_kymograph.proxy import failure_phase
from mcp_kymograph.sandbox import docker, policy
from mcp_kymograph.sandbox.egress import (
    Record,
    RecordError,
    Verdict,
    delta,
    judge_arrivals,
    judge_report,
    parse_record,
    reconcile,
)
from mcp_kymograph.sandbox.inside import common, sink
from mcp_kymograph.sandbox.runner import (
    REQUIRED,
    Cleared,
    Delivery,
    Sandbox,
    SandboxFailed,
    clear,
    stage,
)

INSIDE = Path(common.__file__).parent
FIXTURES = Path(__file__).parent / "fixtures"
NONCE = "0123abcd4567"


# -- policy ----------------------------------------------------------------------------------


@pytest.mark.parametrize("provenance", ["reference", "poison"])
def test_own_entries_run_on_the_host_by_default_and_under_runc_when_asked(provenance):
    assert policy.decide(provenance, None) == "host"
    assert policy.decide(provenance, "host") == "host"
    assert policy.decide(provenance, "runc") == "runc"


@pytest.mark.parametrize("requested", [None, "host", "runc", "runsc"])
def test_real_world_is_refused_under_every_isolation_including_none_asked(requested):
    with pytest.raises(policy.Refused, match="refused"):
        policy.decide("real-world", requested)


def test_real_world_has_no_default_to_fall_back_to():
    with pytest.raises(policy.Refused, match="does not provide"):
        policy.decide("real-world", None)


def test_runc_is_named_as_not_permitted_for_real_world_rather_than_tried():
    with pytest.raises(policy.Refused, match="not runc"):
        policy.decide("real-world", "runc")


def test_runsc_is_not_provided_for_anyone():
    with pytest.raises(policy.Refused):
        policy.decide("reference", "runsc")


def test_unknown_isolation_and_provenance_are_refused():
    with pytest.raises(policy.Refused):
        policy.decide("reference", "chroot")
    with pytest.raises(policy.Refused):
        policy.decide("vendor", None)
    with pytest.raises(policy.Refused):
        policy.decide("vendor", "remote", endpoint=True)


@pytest.mark.parametrize("provenance", ["reference", "poison", "real-world"])
@pytest.mark.parametrize("requested", [None, "remote"])
def test_an_endpoint_runs_under_remote_whatever_its_provenance(provenance, requested):
    assert policy.decide(provenance, requested, endpoint=True) == "remote"


@pytest.mark.parametrize("provenance", ["reference", "poison", "real-world"])
@pytest.mark.parametrize("requested", ["host", "runc", "runsc"])
def test_an_endpoint_under_anything_but_remote_is_refused_as_nothing_to_run(provenance, requested):
    with pytest.raises(policy.Refused) as refused:
        policy.decide(provenance, requested, endpoint=True)
    assert str(refused.value) == (
        f"an endpoint entry runs only under remote, not {requested}: its server runs "
        f"elsewhere, so there is nothing here to run under {requested}; it is refused"
    )


@pytest.mark.parametrize("provenance", ["reference", "poison", "real-world"])
def test_a_command_entry_is_never_remote(provenance):
    with pytest.raises(policy.Refused, match="a command entry never runs under remote"):
        policy.decide(provenance, "remote")


def test_the_isolations_and_what_this_version_provides():
    assert policy.ISOLATIONS == ("host", "runc", "runsc", "remote")
    assert policy.PROVIDED == ("host", "runc", "remote")
    assert "runsc" not in policy.PROVIDED
    # remote is no provenance's command isolation: only the endpoint flag reaches it.
    assert all("remote" not in permitted for permitted in policy.PERMITTED.values())


# -- the gate --------------------------------------------------------------------------------


def _all_held() -> dict[str, Verdict]:
    return {name: Verdict(True) for name in REQUIRED}


def test_the_gate_clears_only_when_every_condition_held():
    assert isinstance(clear(_all_held()), Cleared)


@pytest.mark.parametrize("name", REQUIRED)
def test_a_failed_condition_stops_the_gate_by_name(name):
    conditions = _all_held()
    conditions[name] = Verdict(False, {"why": "test"})
    with pytest.raises(SandboxFailed) as failed:
        clear(conditions)
    assert failed.value.condition == name
    assert failed.value.phase == "before_target"


@pytest.mark.parametrize("name", REQUIRED)
def test_a_condition_never_established_counts_as_failed(name):
    conditions = _all_held()
    del conditions[name]
    with pytest.raises(SandboxFailed, match="never established") as failed:
        clear(conditions)
    assert failed.value.condition == name


def test_the_target_command_needs_this_sandbox_s_own_clearance(tmp_path):
    box = Sandbox(Delivery(tmp_path, "/srv", ("python3", "server.py")))
    with pytest.raises(SandboxFailed) as failed:
        box.target_argv(clear(_all_held()))  # a real clearance, of no run of this sandbox
    assert failed.value.condition == "gate"


def test_a_clearance_cannot_be_made_outside_the_gate():
    with pytest.raises(TypeError):
        Cleared({}, key=object())


def test_the_brief_s_four_conditions_are_required():
    for name in ("helper_exit", "ruleset_digest", "armed", "probe"):
        assert name in REQUIRED


def test_the_gate_will_not_clear_without_proof_that_the_marks_tell_destinations_apart():
    """Every attempt arriving is not enough: without ``udp_marks`` UDP could be held family by
    family and nothing would say so."""
    conditions = _all_held()
    del conditions["udp_marks"]
    with pytest.raises(SandboxFailed) as failed:
        clear(conditions)
    assert failed.value.condition == "udp_marks"


# -- the ruleset and the shared constants ----------------------------------------------------


def test_every_sink_port_is_covered_by_the_direct_access_rule():
    """A port added to the sink's bindings and to the expectation together would pass the
    socket check — and be reachable directly unless the ruleset refuses it too."""
    rules = (INSIDE / "rules.nft").read_text()
    blocked = re.findall(r'oifname "lo" (tcp|udp) dport \{ ([0-9, ]+) \}', rules)
    by_proto = {proto: {int(p) for p in ports.split(",")} for proto, ports in blocked}
    for proto, _, port in common.SINK_BINDINGS:
        assert port in by_proto[proto], (proto, port)


def test_the_sink_has_one_place_that_binds_and_it_binds_only_its_listed_sockets():
    """ "Not even briefly": the socket checks at arming and after the target are snapshots, and
    a binding opened and closed between them would pass both. So the sink's code is held to
    one binding site, a loop over SINK_BINDINGS — and to no other way of opening a socket
    others could reach (listen without bind, or a Unix socket)."""
    import ast

    source = (INSIDE / "sink.py").read_text()
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("bind", "listen", "socketpair")
    ]
    assert sorted(c.func.attr for c in calls) == ["bind", "listen"]
    arm = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "arm")
    loop = next(n for n in ast.walk(arm) if isinstance(n, ast.For))
    assert "SINK_BINDINGS" in ast.unparse(loop.iter)
    assert all(any(c is n for n in ast.walk(loop)) for c in calls)
    assert "AF_UNIX" not in source


# -- the sink reads before it writes ---------------------------------------------------------


@pytest.fixture
def udp_pair():
    """A socket in the sink's place, on an ephemeral port, and one to send to it from."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.setblocking(False)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.settimeout(2)
    yield receiver, sender
    receiver.close()
    sender.close()


def _written(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_the_sink_takes_every_queued_datagram_off_its_socket_before_writing_any(udp_pair, capsys):
    """The kernel's receive queue is the part the host bounds; the sink empties it first and
    counts what it took, and writes it down afterwards, a chunk at a time between reads."""
    receiver, sender = udp_pair
    box = sink.Sink()
    for n in range(100):
        sender.sendto(b"d%d" % n, receiver.getsockname())
    box.datagram(receiver, "udp")
    assert (box.totals["udp4"], len(box.pending)) == (100, 100)
    assert _written(capsys) == []
    box.work(sink.CHUNK)
    written = _written(capsys)
    assert [e["preview"] for e in written] == [(b"d%d" % n).hex() for n in range(sink.CHUNK)]
    assert len(box.pending) == 100 - sink.CHUNK


def test_a_mark_writes_down_what_was_read_before_it_in_the_phase_it_closes(udp_pair, capsys):
    receiver, sender = udp_pair
    box = sink.Sink()
    box.phase = "probe"
    for n in range(3):
        sender.sendto(b"p%d" % n, receiver.getsockname())
    box.datagram(receiver, "udp")
    box.command("mark target")
    written = _written(capsys)
    assert [(e["event"], e.get("phase")) for e in written] == [("udp", "probe")] * 3 + [
        ("mark", None)
    ]
    assert written[-1]["closed"] == "probe" and written[-1]["totals"]["udp4"] == 3
    assert (box.phase, box.totals["udp4"], len(box.pending)) == ("target", 0, 0)


def test_the_sink_stops_reading_while_its_backlog_is_full(udp_pair, monkeypatch):
    """Past MAX_PENDING the kernel's queue holds the rest again: bounded memory, and what is
    left behind is still there to be read, not lost by the sink."""
    receiver, sender = udp_pair
    monkeypatch.setattr(sink, "MAX_PENDING", 5)
    box = sink.Sink()
    for n in range(8):
        sender.sendto(b"%d" % n, receiver.getsockname())
    box.datagram(receiver, "udp")
    assert (box.totals["udp4"], len(box.pending)) == (5, 5)
    box.work(5)
    box.datagram(receiver, "udp")
    assert (box.totals["udp4"], len(box.pending)) == (8, 3)


def test_a_question_waiting_in_the_backlog_is_answered_and_the_stop_writes_down_everything(
    udp_pair, capsys
):
    receiver, sender = udp_pair
    box = sink.Sink()
    box.listeners = [receiver]
    sender.sendto(common.dns_query(7, "late.example", common.QTYPE_A), receiver.getsockname())
    box.datagram(receiver, "dns")
    for n in range(4):
        sender.sendto(b"tail %d" % n, receiver.getsockname())
    box.drain()
    answer, _ = sender.recvfrom(512)
    assert common.answered_address(answer) == common.DNS_ANSWER_V4
    written = _written(capsys)
    assert [e["event"] for e in written] == ["dns"] + ["udp"] * 4
    assert written[0]["qname"] == "late.example" and written[0]["answered"] is True
    assert (box.totals["udp4"], box.totals["dns_udp4"], len(box.pending)) == (5, 1, 0)


def test_the_redirect_targets_are_the_sink_s_ports():
    rules = (INSIDE / "rules.nft").read_text()
    targets = {int(p) for p in re.findall(r"redirect to :([0-9]+)", rules)}
    assert targets == {port for _, _, port in common.SINK_BINDINGS}


def test_the_redirected_flows_are_accepted_before_the_direct_access_rule():
    """Without it, DNS to the local resolver address is redirected onto a sink port over lo
    and then refused as direct access: recorded, never arriving."""
    rules = (INSIDE / "rules.nft").read_text()
    assert rules.index("ct status dnat accept") < rules.index('oifname "lo" tcp dport')


def test_the_ruleset_names_both_address_families_in_one_table():
    rules = (INSIDE / "rules.nft").read_text()
    assert rules.startswith(f"table inet {common.TABLE} {{")
    assert rules.count("\ntable ") == 0


def test_the_resolver_file_names_only_the_redirected_address():
    assert (INSIDE / "resolv.conf").read_text() == "nameserver 127.0.0.11\noptions ndots:0\n"


def test_the_authoritative_read_is_of_our_table():
    assert common.AUTHORITATIVE_READ[-3:] == ("table", "inet", common.TABLE)


def test_probe_plan_covers_every_class_the_gate_asks_for():
    plan = common.probe_plan(NONCE)
    assert set(plan) == {
        "tcp4",
        "tcp6",
        "udp4",
        "udp6",
        "dns_udp4",
        "dns_udp6",
        "dns_tcp4",
        "dns_tcp6",
        "icmp4",
        "icmp6",
    }
    assert plan["tcp4"]["port"] != plan["udp4"]["port"]


def test_probe_plan_refuses_a_nonce_it_cannot_derive_from():
    with pytest.raises(ValueError):
        common.probe_plan("short")


# -- DNS, as the sink and the probe speak it -------------------------------------------------


def test_a_question_round_trips_and_is_answered_with_an_unreachable_address():
    query = common.dns_query(7, "exfil.example", common.QTYPE_A)
    assert common.parse_question(query)[:3] == (7, "exfil.example", common.QTYPE_A)
    assert common.answered_address(common.dns_answer(query)) == common.DNS_ANSWER_V4
    six = common.dns_query(8, "exfil.example", common.QTYPE_AAAA)
    assert common.answered_address(common.dns_answer(six)) == common.DNS_ANSWER_V6


def test_other_types_are_answered_without_records():
    query = common.dns_query(9, "exfil.example", 16)  # TXT
    assert common.answered_address(common.dns_answer(query)) is None


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"\x00" * 11,
        common.dns_query(1, "a.example", 1)[:-2],  # cut short
        b"\x00\x01\x81\x80" + b"\x00\x01" + b"\x00" * 6 + b"\x01a\x00\x00\x01\x00\x01",  # answer
        b"\x00\x01\x01\x00\x00\x01" + b"\x00" * 6 + b"\xc0\x0c\x00\x01\x00\x01",  # pointer
        b"\x00\x01\x01\x00\x00\x01"
        + b"\x00" * 6
        + (b"\x3f" + b"a" * 63) * 5
        + b"\x00\x00\x01\x00\x01",
    ],
)
def test_anything_but_a_plain_bounded_question_is_not_read(packet):
    assert common.parse_question(packet) is None
    assert common.dns_answer(packet) is None


# -- reading the namespace -------------------------------------------------------------------


def test_socket_tables_are_read_as_addresses_and_ports(tmp_path):
    (tmp_path / "tcp").write_text(
        "  sl  local_address rem_address   st\n"
        "   0: 0100007F:3A99 00000000:0000 0A 0\n"
        "   1: 0100007F:3A99 0100007F:9C40 01 0\n"
    )
    (tmp_path / "tcp6").write_text(
        "  sl  local_address rem_address st\n"
        "   0: 00000000000000000000000001000000:3A99 00000000000000000000000000000000:0000 0A 0\n"
    )
    (tmp_path / "udp").write_text("  sl  local\n   0: 0100007F:3ACD 00000000:0000 07 0\n")
    (tmp_path / "unix").write_text("Num RefCount\n0000: 00000002 @abstract\n")
    assert common.socket_inventory(str(tmp_path)) == {
        "tcp": [["127.0.0.1", 15001], ["::1", 15001]],
        "udp": [["127.0.0.1", 15053]],
        "raw": 0,
        "unix": 1,
    }


def test_interfaces_are_judged_by_driver_not_by_name():
    links = [
        {"ifname": "lo", "link_type": "loopback"},
        {"ifname": "eth0", "link_type": "ether", "linkinfo": {"info_kind": "veth"}},
    ]
    assert common.interface_inventory(links) != common.expected_interfaces()


# -- the record ------------------------------------------------------------------------------


def _nft(counters: dict[str, int], sets: dict[str, list]) -> dict:
    items: list[dict] = [{"metainfo": {}}]
    for name in [f"n_{s}" for s in ("tcp4", "tcp6", "udp4", "udp6", "icmp4", "icmp6")] + [
        "n_other4",
        "n_other6",
        "n_direct",
    ]:
        items.append(
            {"counter": {"table": common.TABLE, "name": name, "packets": counters.get(name, 0)}}
        )
    for name, elements in sets.items():
        items.append(
            {
                "set": {
                    "table": common.TABLE,
                    "name": name,
                    "elem": [
                        {"elem": {"val": {"concat": list(e[:-1])}, "counter": {"packets": e[-1]}}}
                        for e in elements
                    ],
                }
            }
        )
    return {"nftables": items}


def test_the_record_holds_counters_and_destinations_with_their_counts():
    record = parse_record(
        _nft(
            {"n_tcp4": 2},
            {"tcp4": [("192.0.2.1", 443, 2)], "icmp6": [("2001:DB8::1", "echo-request", 1)]},
        )
    )
    assert record.counters["n_tcp4"] == 2
    assert record.elements[("tcp4", "192.0.2.1", 443)] == 2
    assert record.elements[("icmp6", "2001:db8::1", "echo-request")] == 1  # normalised


def test_a_udp_destination_is_recorded_with_the_mark_its_datagrams_carried():
    record = parse_record(_nft({"n_udp6": 3}, {"udp6": [("2001:DB8::99", 5353, 3746674750, 3)]}))
    assert record.elements[("udp6", "2001:db8::99", 5353)] == 3
    assert record.marks == {("udp6", "2001:db8::99", 5353): 3746674750}


@pytest.mark.parametrize(
    ("sets", "match"),
    [
        ({"udp4": [("192.0.2.9", 9, 1)]}, "has 2 fields"),
        ({"tcp4": [("192.0.2.1", 443, 7, 1)]}, "has 3 fields"),
        ({"udp4": [("192.0.2.9", 9, 7, 1), ("192.0.2.9", 9, 8, 1)]}, "twice"),
    ],
)
def test_an_element_not_shaped_like_its_set_is_refused(sets, match):
    """A UDP destination without its mark could not be matched to the sink's account; a mark
    where none belongs, or one destination under two marks, is not the ruleset we loaded."""
    with pytest.raises(RecordError, match=match):
        parse_record(_nft({}, sets))


def test_a_record_missing_a_counter_is_not_our_table():
    document = _nft({}, {})
    document["nftables"] = [
        i for i in document["nftables"] if i.get("counter", {}).get("name") != "n_direct"
    ]
    with pytest.raises(RecordError, match="n_direct"):
        parse_record(document)


@pytest.mark.parametrize(
    "document", [{}, {"nftables": None}, {"nftables": [{"set": {"table": common.TABLE}}]}]
)
def test_a_malformed_record_is_refused(document):
    with pytest.raises(RecordError):
        parse_record(document)


def test_an_unknown_set_in_our_table_is_refused():
    with pytest.raises(RecordError, match="unknown set"):
        parse_record(_nft({}, {"exfil": []}))


def test_the_target_s_record_is_the_difference_to_the_baseline():
    before = parse_record(
        _nft({"n_udp4": 3}, {"udp4": [("192.0.2.11", 4000, 11, 1), ("127.0.0.11", 53, 53, 2)]})
    )
    after = parse_record(
        _nft(
            {"n_udp4": 7},
            {"udp4": [("192.0.2.11", 4000, 11, 1), ("127.0.0.11", 53, 53, 4),
                      ("203.0.113.9", 9, 9, 2)]},
        )
    )  # fmt: skip
    moved = delta(after, before)
    assert moved.counters["n_udp4"] == 4
    assert moved.elements == {("udp4", "127.0.0.11", 53): 2, ("udp4", "203.0.113.9", 9): 2}
    assert moved.marks == {("udp4", "127.0.0.11", 53): 53, ("udp4", "203.0.113.9", 9): 9}


def test_a_count_going_backwards_is_refused():
    before = parse_record(_nft({"n_udp4": 3}, {}))
    with pytest.raises(RecordError, match="backwards"):
        delta(parse_record(_nft({"n_udp4": 1}, {})), before)


def test_a_destination_vanishing_is_refused():
    before = parse_record(_nft({"n_udp4": 1}, {"udp4": [("192.0.2.1", 1, 7, 1)]}))
    with pytest.raises(RecordError, match="vanished"):
        delta(parse_record(_nft({"n_udp4": 1}, {})), before)


def test_a_full_set_is_a_recorded_cap_with_the_exact_number_missing():
    record = parse_record(_nft({"n_icmp4": 10}, {"icmp4": [("198.18.0.1", "echo-request", 6)]}))
    assert record.capped() == {"icmp4": 4}
    assert (
        parse_record(_nft({"n_icmp4": 6}, {"icmp4": [("198.18.0.1", "echo-request", 6)]})).capped()
        == {}
    )


def test_attempts_are_listed_in_our_words_with_their_unit():
    record = Record(
        {f"n_{s}": 0 for s in ("tcp4",)},
        {("tcp4", "192.0.2.1", 443): 1, ("other4", "203.0.113.8", "udplite"): 2},
    )
    assert record.attempts() == [
        {
            "proto": "other",
            "family": 4,
            "destination": "203.0.113.8",
            "l4proto": "udplite",
            "count": 2,
            "unit": "packets",
        },
        {
            "proto": "tcp",
            "family": 4,
            "destination": "192.0.2.1",
            "port": 443,
            "count": 1,
            "unit": "connections",
        },
    ]


# -- reconciliation --------------------------------------------------------------------------


def _counters(**values: int) -> dict[str, int]:
    base = {
        f"n_{s}": 0 for s in ("tcp4", "tcp6", "udp4", "udp6", "icmp4", "icmp6", "other4", "other6")
    }
    return {**base, "n_direct": 0, **{f"n_{k}": v for k, v in values.items()}}


#: The marks the kernel gave a datagram to the resolver and to 192.0.2.9:9.
DNS_MARK, UDP_MARK = 659264398, 489265911


def _record() -> Record:
    """One TCP destination, one DNS question and one other UDP datagram, over IPv4."""
    return Record(
        _counters(tcp4=1, udp4=2),
        {("tcp4", "192.0.2.1", 443): 1, ("udp4", "127.0.0.11", 53): 1, ("udp4", "192.0.2.9", 9): 1},
        {("udp4", "127.0.0.11", 53): DNS_MARK, ("udp4", "192.0.2.9", 9): UDP_MARK},
    )


#: The sink's account of the same: it names the TCP destination, saw a question, saw a datagram,
#: each datagram under the mark the kernel gave it.
SAW_ALL = [
    {"event": "tcp", "family": 4, "destination": "192.0.2.1", "port": 443},
    {"event": "dns", "transport": "udp", "family": 4, "qname": "x.example", "mark": DNS_MARK},
    {"event": "udp", "family": 4, "preview": "", "mark": UDP_MARK},
]
TOTALS = {"tcp4": 1, "udp4": 2, "dns_udp4": 1}


def test_agreeing_accounts_reconcile():
    checked = reconcile(_record(), SAW_ALL, TOTALS, 0)
    assert checked.consistent, checked.problems
    assert checked.differences == {}


@pytest.mark.parametrize(
    ("drop", "extra", "totals", "problem"),
    [
        (0, [], TOTALS, "tcp over IPv4: the kernel recorded 1 destination(s) the sink never named"),
        (1, [], TOTALS, "udp over IPv4: the kernel recorded 1 destination(s) the sink never named, "
         "more than the 0 datagram(s) it lost can explain"),
        (2, [], TOTALS, "udp over IPv4: the kernel recorded 1 destination(s) the sink never named"),
        (None, [{"event": "tcp", "family": 4, "destination": "192.0.2.5", "port": 1}], TOTALS,
         "the sink names 1 destination(s) the kernel never recorded"),
        (None, [{"event": "udp", "family": 6, "preview": "", "mark": 5}], TOTALS,
         "udp over IPv6: the sink names 1 destination(s) the kernel never recorded"),
        (None, [{"event": "udp", "family": 4, "preview": ""}], TOTALS,
         "udp over IPv4: the sink could not tell where 1 datagram(s) were going"),
        (None, [{"event": "udp", "family": 4, "preview": "", "mark": DNS_MARK}], TOTALS,
         "udp over IPv4: 1 destination(s) arrived at the other socket"),
        (None, [{"event": "dns", "transport": "udp", "family": 4, "mark": UDP_MARK}], TOTALS,
         "udp over IPv4: 1 destination(s) arrived at the other socket"),
        (None, [{"event": "tcp", "family": 6, "destination": "2001:db8::1", "port": 1}], TOTALS,
         "tcp over IPv6"),
        (None, [], {**TOTALS, "errors": 1}, "failed to handle"),
    ],
)  # fmt: skip
def test_what_one_side_names_and_the_other_does_not_makes_the_run_inconsistent(
    drop, extra, totals, problem
):
    events = [e for i, e in enumerate(SAW_ALL) if i != drop] + extra
    checked = reconcile(_record(), events, totals, 0)
    assert not checked.consistent
    assert any(problem in p for p in checked.problems), checked.problems


def test_counts_that_differ_with_the_same_members_are_recorded_not_judged():
    """A retransmitted question, a second connection to the same place, a datagram the sink's
    buffer could not hold: the counts move, nothing went unobserved. Consistent, and the
    difference written down."""
    record = Record(
        _counters(tcp4=3, udp4=7),
        {("tcp4", "192.0.2.1", 443): 3, ("udp4", "127.0.0.11", 53): 2, ("udp4", "192.0.2.9", 9): 5},
        _record().marks,
    )
    checked = reconcile(record, SAW_ALL, TOTALS, 0)
    assert checked.consistent, checked.problems
    assert checked.differences == {
        "tcp4": {"kernel": 3, "sink": 1},
        "udp4": {"kernel": 7, "sink": 2},
        "dns_udp4": {"kernel": 2, "sink": 1},
    }


def test_a_sink_naming_another_destination_than_the_kernel_is_inconsistent():
    record = Record(_counters(tcp6=1), {("tcp6", "2001:db8::1", 443): 1})
    events = [{"event": "tcp", "family": 6, "destination": "2001:db8::2", "port": 443}]
    checked = reconcile(record, events, {"tcp6": 1}, 0)
    assert any("never recorded" in p for p in checked.problems)
    assert any("never named" in p for p in checked.problems)


def test_destinations_are_compared_as_addresses_not_as_spellings():
    record = Record(_counters(tcp6=1), {("tcp6", "2001:db8::1", 443): 1})
    events = [{"event": "tcp", "family": 6, "destination": "2001:0db8:0::1", "port": 443}]
    assert reconcile(record, events, {"tcp6": 1}, 0).consistent


def test_a_full_set_does_not_hold_the_sink_to_destinations_it_lost():
    """The set was full: the sink may name destinations it no longer holds. What the set does
    hold must still be named."""
    record = Record(_counters(tcp4=3), {("tcp4", "192.0.2.1", 443): 1})  # two not listed
    events = [
        {"event": "tcp", "family": 4, "destination": "192.0.2.1", "port": 443},
        {"event": "tcp", "family": 4, "destination": "192.0.2.7", "port": 1},
    ]
    checked = reconcile(record, events, {"tcp4": 3}, 0)
    assert checked.consistent, checked.problems
    assert checked.capped == {"tcp4": 2}
    lost = reconcile(record, events[1:], {"tcp4": 3}, 0)
    assert any("never named" in p for p in lost.problems)


def test_a_capped_sink_is_held_to_what_it_counted():
    """The sink's own events were capped: the kernel's destinations need not all be named. A
    TCP class the kernel saw must be one the sink counted; a UDP datagram it did not count is
    lost, and written down as loss."""
    checked = reconcile(_record(), [], TOTALS, suppressed=5)
    assert checked.consistent, checked.problems
    short = reconcile(_record(), [], {"tcp4": 1, "udp4": 1, "dns_udp4": 1}, suppressed=5)
    assert short.consistent, short.problems
    assert short.loss["udp4"] == {"kernel": 2, "sink": 1, "lost": 1, "unseen_destinations": 0}


#: Two other UDP destinations over IPv4, one datagram each.
TWO = Record(
    _counters(udp4=2),
    {("udp4", "192.0.2.9", 9): 1, ("udp4", "203.0.113.9", 9999): 1},
    {("udp4", "192.0.2.9", 9): UDP_MARK, ("udp4", "203.0.113.9", 9999): 1234},
)


def test_a_udp_destination_the_sink_never_named_is_a_disagreement_when_nothing_was_lost():
    """The case membership by class could not see: the sink names one destination of the
    family and says it received both datagrams. The other one went somewhere it cannot say."""
    events = [{"event": "udp", "family": 4, "preview": "", "mark": UDP_MARK}]
    checked = reconcile(TWO, events, {"udp4": 2}, 0)
    assert checked.problems == [
        "udp over IPv4: the kernel recorded 1 destination(s) the sink never named, more than "
        "the 0 datagram(s) it lost can explain"
    ]


def test_a_udp_destination_unseen_because_the_sink_lost_datagrams_is_loss_not_a_disagreement():
    events = [{"event": "udp", "family": 4, "preview": "", "mark": UDP_MARK}]
    checked = reconcile(TWO, events, {"udp4": 1}, 0)
    assert checked.consistent, checked.problems
    assert checked.loss["udp4"] == {"kernel": 2, "sink": 1, "lost": 1, "unseen_destinations": 1}
    assert checked.loss["udp6"] == {"kernel": 0, "sink": 0, "lost": 0, "unseen_destinations": 0}


def test_a_whole_family_unseen_by_a_sink_that_lost_all_of_it_is_loss_even_where_sets_are_capped():
    """The UDP set was full, so it does not hold every mark the sink may name; the sink that
    lost every datagram of the family names none, and that is loss, not a disagreement. TCP
    keeps its class check when the sink's own events were capped."""
    full = Record(
        _counters(udp4=5000), {("udp4", "192.0.2.9", 9): 4095}, {("udp4", "192.0.2.9", 9): 7}
    )
    checked = reconcile(full, [], {}, 0)
    assert checked.capped == {"udp4": 905}
    assert checked.consistent, checked.problems
    assert checked.loss["udp4"]["lost"] == 5000
    elsewhere = [{"event": "udp", "family": 4, "mark": 8}, {"event": "udp", "family": 4, "mark": 7}]
    assert reconcile(full, elsewhere, {"udp4": 5000}, 0).consistent
    assert not reconcile(full, elsewhere[:1], {"udp4": 5000}, 0).consistent
    tcp = Record(_counters(tcp4=1), {("tcp4", "192.0.2.1", 443): 1})
    quiet = reconcile(tcp, [], {"tcp4": 0}, suppressed=3)
    assert any("tcp over IPv4: the kernel recorded attempts" in p for p in quiet.problems)
    assert reconcile(tcp, [], {"tcp4": 1}, suppressed=3).consistent


# -- the probe's evidence --------------------------------------------------------------------


def _report(**changes) -> dict:
    report = {
        "interfaces": common.expected_interfaces(),
        "sockets": common.expected_inventory(),
        "resolv_conf": "nameserver 127.0.0.11\noptions ndots:0\n",
        "authoritative_read": {"returncode": 1, "stdout_bytes": 0, "stderr": "not permitted"},
        "confinement": {
            "uid": 65534,
            "caps": dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), "0" * 16),
            "no_new_privs": True,
            "seccomp": "2",
            "root_read_only": True,
        },
        "direct": {"error": "ConnectionRefusedError"},
        "attempts": {},
    }
    report.update(changes)
    return report


def test_the_report_conditions_hold_for_a_sound_namespace():
    verdicts = judge_report(_report(), "nameserver 127.0.0.11\noptions ndots:0\n")
    assert all(v.ok for v in verdicts.values())


@pytest.mark.parametrize(
    ("change", "condition"),
    [
        ({"interfaces": [["eth0", "veth"], ["lo", "loopback"]]}, "barrier"),
        ({"interfaces": [["lo", "loopback"]]}, "barrier"),
        (
            {
                "sockets": {
                    **common.expected_inventory(),
                    "tcp": [["127.0.0.1", 15001], ["127.0.0.1", 15099], ["::1", 15001]],
                }
            },
            "sink_bindings",
        ),
        ({"sockets": {**common.expected_inventory(), "unix": 1}}, "sink_bindings"),
        ({"resolv_conf": "nameserver 198.51.100.53\n"}, "resolver"),
        (
            {"authoritative_read": {"returncode": 0, "stdout_bytes": 900}},
            "authoritative_unreadable",
        ),
        ({"authoritative_read": {"returncode": 1, "stdout_bytes": 10}}, "authoritative_unreadable"),
        ({"authoritative_read": {}}, "authoritative_unreadable"),
        ({"confinement": {**_report()["confinement"], "uid": 0}}, "confinement"),
        (
            {
                "confinement": {
                    **_report()["confinement"],
                    "caps": {**_report()["confinement"]["caps"], "CapBnd": "00000000a80425fb"},
                }
            },
            "confinement",
        ),
        ({"confinement": {**_report()["confinement"], "no_new_privs": False}}, "confinement"),
        ({"confinement": {**_report()["confinement"], "seccomp": "0"}}, "confinement"),
        ({"confinement": {**_report()["confinement"], "root_read_only": False}}, "confinement"),
        ({"confinement": {}}, "confinement"),
    ],
)
def test_each_report_condition_fails_on_its_own(change, condition):
    verdicts = judge_report(_report(**change), "nameserver 127.0.0.11\noptions ndots:0\n")
    assert [name for name, v in verdicts.items() if not v.ok] == [condition]


def _arrived_everywhere() -> tuple[dict, list, Record]:
    plan = common.probe_plan(NONCE)
    events: list[dict] = []
    elements: dict = {}
    marks: dict = {}
    attempts: dict = {}
    for number, (name, spec) in enumerate(plan.items()):
        family = spec["family"]
        if spec["proto"] == "icmp":
            elements[(f"icmp{family}", spec["destination"], "echo-request")] = 1
            attempts[name] = {"sent": True}
            continue
        element = (f"{spec['proto']}{family}", spec["destination"], spec["port"])
        elements[element] = 1
        mark = None
        if spec["proto"] == "udp":
            mark = marks[element] = 1000 + number
        if spec["proto"] == "tcp":
            events.append(
                {
                    "event": "tcp",
                    "phase": "probe",
                    "family": family,
                    "destination": spec["destination"],
                    "port": spec["port"],
                }
            )
        if "qname" in spec:
            events.append(
                {
                    "event": "dns",
                    "phase": "probe",
                    "transport": spec["proto"],
                    "family": family,
                    "qname": spec["qname"],
                    **({"mark": mark} if mark is not None else {}),
                }
            )
            attempts[name] = {"answer": common.DNS_ANSWER_V4}
        elif spec["proto"] == "udp":
            events.append(
                {
                    "event": "udp",
                    "phase": "probe",
                    "family": family,
                    "preview": f"probe {name} {NONCE}\n".encode().hex(),
                    "mark": mark,
                }
            )
            attempts[name] = {"sent": True}
        else:
            attempts[name] = {"connected": True}
    return _report(attempts=attempts), events, Record(_counters(direct=1), elements, marks)


def test_the_probe_holds_when_every_attempt_arrived_at_the_sink_and_in_the_record():
    report, events, record = _arrived_everywhere()
    verdicts = judge_arrivals(NONCE, report, events, record)
    assert verdicts["probe"].ok
    assert verdicts["direct_blocked"].ok


@pytest.mark.parametrize("name", list(common.probe_plan(NONCE)))
def test_one_attempt_missing_in_the_record_fails_the_probe(name):
    report, events, record = _arrived_everywhere()
    spec = common.probe_plan(NONCE)[name]
    second = "echo-request" if spec["proto"] == "icmp" else spec["port"]
    del record.elements[(f"{spec['proto']}{spec['family']}", spec["destination"], second)]
    verdict = judge_arrivals(NONCE, report, events, record)["probe"]
    assert not verdict.ok
    assert [n for n, a in verdict.detail.items() if not a["arrived"]] == [name]


@pytest.mark.parametrize(
    "name", [n for n, s in common.probe_plan(NONCE).items() if s["proto"] != "icmp"]
)
def test_one_attempt_missing_at_the_sink_fails_the_probe_even_when_recorded(name):
    """The case that happened: recorded by the kernel, dropped before the sink."""
    report, events, record = _arrived_everywhere()
    spec = common.probe_plan(NONCE)[name]
    kept = [
        e
        for e in events
        if not (
            e.get("qname") == spec.get("qname")
            if "qname" in spec and e["event"] == "dns"
            else e.get("preview") == f"probe {name} {NONCE}\n".encode().hex()
            if spec["proto"] == "udp" and "qname" not in spec
            else e["event"] == "tcp"
            and e.get("destination") == spec["destination"]
            and e.get("port") == spec["port"]
        )
    ]
    assert len(kept) < len(events)
    verdict = judge_arrivals(NONCE, report, kept, record)["probe"]
    assert not verdict.ok
    assert verdict.detail[name]["record"] is True


@pytest.mark.parametrize(
    "name", [n for n, s in common.probe_plan(NONCE).items() if s["proto"] == "udp"]
)
def test_a_datagram_that_reached_the_sink_under_another_mark_fails_the_probe(name):
    """Every run proves that the sink tells datagrams apart by where they were going: a probe
    datagram that arrived without the mark the kernel recorded for it did not arrive."""
    report, events, record = _arrived_everywhere()
    spec = common.probe_plan(NONCE)[name]
    (event,) = [
        e
        for e in events
        if e.get("mark") == record.marks[(f"udp{spec['family']}", spec["destination"], 53
                                          if "qname" in spec else spec["port"])]
    ]  # fmt: skip
    event["mark"] = None
    verdict = judge_arrivals(NONCE, report, events, record)["probe"]
    assert [n for n, a in verdict.detail.items() if not a["arrived"]] == [name]
    assert verdict.detail[name]["record"] is True


def test_the_probe_s_udp_destinations_carry_marks_that_tell_them_apart():
    report, events, record = _arrived_everywhere()
    verdict = judge_arrivals(NONCE, report, events, record)["udp_marks"]
    assert verdict.ok, verdict.detail
    assert sorted(verdict.detail) == ["udp4", "udp6"]
    assert all(len(set(marks)) == 2 for marks in verdict.detail.values())


@pytest.mark.parametrize("same", [7, 0])
def test_marks_that_do_not_tell_destinations_apart_stop_the_run_though_every_datagram_arrived(
    same,
):
    """A ruleset that marked nothing (0) or gave every datagram one mark: sink and kernel still
    agree on each datagram's mark, so every attempt arrived — and UDP would be held family by
    family without anyone noticing. The probe's own destinations show it."""
    report, events, record = _arrived_everywhere()
    for key in record.marks:
        record.marks[key] = same
    for event in events:
        if "mark" in event:
            event["mark"] = same
    verdicts = judge_arrivals(NONCE, report, events, record)
    assert verdicts["probe"].ok
    assert not verdicts["udp_marks"].ok
    assert verdicts["udp_marks"].detail == {"udp4": [same, same], "udp6": [same, same]}


def test_an_unanswered_dns_attempt_fails_the_probe():
    report, events, record = _arrived_everywhere()
    report["attempts"]["dns_udp4"] = {"answer": None}
    assert not judge_arrivals(NONCE, report, events, record)["probe"].ok


def test_direct_access_must_be_refused_locally_and_counted_by_the_rule():
    report, events, record = _arrived_everywhere()
    assert not judge_arrivals(NONCE, {**report, "direct": {"connected": True}}, events, record)[
        "direct_blocked"
    ].ok
    record.counters["n_direct"] = 0
    assert not judge_arrivals(NONCE, report, events, record)["direct_blocked"].ok


# -- delivery --------------------------------------------------------------------------------


def _entry_files() -> list[Path]:
    corpus = FIXTURES / "corpus"
    return [corpus / "poison_server.py", FIXTURES / "discovery_server.py"]


def test_delivery_copies_exactly_the_identified_files_readable_by_the_target():
    files = _entry_files()
    delivery = stage(
        files, from_content(files), FIXTURES / "corpus", ["{python}", "{dir}/poison_server.py"]
    )
    try:
        copied = sorted(
            p.relative_to(delivery.directory).as_posix()
            for p in delivery.directory.rglob("*")
            if p.is_file()
        )
        assert copied == ["corpus/poison_server.py", "discovery_server.py"]
        assert delivery.workdir == "/srv/corpus"
        assert delivery.command == ("python3", "/srv/corpus/poison_server.py")
        for path in delivery.directory.rglob("*"):
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode & 0o004, path
    finally:
        delivery.cleanup()
    assert not delivery.directory.exists()


def test_delivery_refuses_files_that_changed_since_they_were_identified(tmp_path, monkeypatch):
    server = tmp_path / "server.py"
    server.write_text("print(1)\n")
    identity = from_content([server])
    server.write_text("print(2)\n")
    made = []
    real = tempfile.mkdtemp
    monkeypatch.setattr(tempfile, "mkdtemp", lambda **kw: made.append(real(**kw)) or made[-1])
    with pytest.raises(SandboxFailed) as failed:
        stage([server], identity, tmp_path, ["{python}", "{dir}/server.py"])
    assert failed.value.condition == "delivery"
    assert made and not Path(made[0]).exists()  # the refused copy is not left behind


def test_delivery_works_where_temporary_files_lie_behind_a_link(tmp_path, monkeypatch):
    """The copy is identified below its own directory: a symbolic link on the way to where the
    system keeps temporary files is no link inside the server's files."""
    real, link = tmp_path / "real", tmp_path / "tmp"
    real.mkdir()
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(link))
    server = tmp_path / "server.py"
    server.write_text("print(1)\n")
    delivery = stage([server], from_content([server]), tmp_path, ["{python}", "{dir}/server.py"])
    try:
        assert link in delivery.directory.parents
        assert (delivery.directory / "server.py").read_text() == "print(1)\n"
    finally:
        delivery.cleanup()


def test_delivery_refuses_a_dir_placeholder_outside_the_files(tmp_path):
    (tmp_path / "a").mkdir()
    server = tmp_path / "a" / "server.py"
    server.write_text("x\n")
    (tmp_path / "b").mkdir()
    with pytest.raises(SandboxFailed, match="dir"):
        stage([server], from_content([server]), tmp_path / "b", ["{python}", "{dir}/x.py"])


# -- what the recording keeps of it ----------------------------------------------------------


def test_a_credential_smuggled_out_in_a_dns_name_is_masked_like_any_other(tmp_path):
    from mcp_kymograph.masking import PLACEHOLDER, Masker
    from mcp_kymograph.recorder import Recorder

    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="r", masker=Masker()) as recorder:
        recorder.egress_dns(
            1,
            0,
            query={
                "transport": "udp",
                "family": 4,
                "qname": "ghp_ABCDEFGHIJKLMNOPQRSTUVWX.collector.invalid",
                "qtype": 1,
                "answered": True,
            },
        )
    (event,) = [json.loads(line) for line in path.read_text().splitlines()]
    assert "ghp_" not in event["qname"] and PLACEHOLDER in event["qname"]
    assert event["qname_redactions"] == 1


def test_a_sink_that_cannot_be_told_to_stop_fails_after_the_target(tmp_path, monkeypatch):
    """collect runs after the target: a sink that no longer takes its stop command is a failure
    after the target, not one that defaults to before it."""
    box = Sandbox(Delivery(tmp_path, "/srv", ("python3", "server.py")))
    box._baseline = object()
    monkeypatch.setattr(docker, "remove", lambda names: None)
    monkeypatch.setattr(box, "_read_record", lambda *a, **k: object())

    class DeadStdin:
        def write(self, data):
            raise BrokenPipeError

        def flush(self):
            pass

    box._sink = types.SimpleNamespace(stdin=DeadStdin())
    with pytest.raises(SandboxFailed) as failed:
        box.collect()
    assert (failed.value.condition, failed.value.phase) == ("armed", "after_target")


@pytest.mark.parametrize(
    ("raised", "caller", "recorded"),
    [
        (SandboxFailed("armed", "x"), "after_target", "after_target"),
        (SandboxFailed("record", "x", phase="before_target"), "after_target", "after_target"),
        (SandboxFailed("probe", "x"), "before_target", "before_target"),
        (SandboxFailed("record", "x", phase="after_target"), "before_target", "after_target"),
        (OSError("x"), "before_target", "before_target"),
        (OSError("x"), "after_target", "after_target"),
    ],
)
def test_after_the_target_no_failure_is_recorded_as_before_it(raised, caller, recorded):
    assert failure_phase(raised, caller) == recorded
