"""The network of a stage B run (runner/stage_b_net.py).

What it must hold: the counting rules allow exactly the targets of a kind and count the rest, the
resolver of docker is counted before loopback is let through; what nft prints is read exactly or
refused, never read as empty; the fixture server's log is read line by line; every command is
labelled, bounded and has no host path but the two that are named; and whatever fails in
whichever step, everything the run made is removed and asked for by its label. Docker is stood in
for by tests/fixtures/bench/fake_net_docker.py; one test uses the real thing.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import random
import re
import secrets
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "benchmarks" / "local-servers" / "runner"
FAKE_NET_DOCKER = ROOT / "tests" / "fixtures" / "bench" / "fake_net_docker.py"


def _load(name: str, file: str):
    # Not a package (the directory name has a hyphen), so loaded by path and registered before
    # it runs.
    spec = importlib.util.spec_from_file_location(name, RUNNER / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bench = _load("bench_local_servers", "bench.py")
fixtures = _load("bench_fixtures", "fixtures.py")
net = _load("bench_stage_b_net", "stage_b_net.py")

ADDRESSES = net.Addresses(ipaddress.IPv4Network("10.201.7.0/24"))
NONCE = "aabbccdd"
POSTGRES = SimpleNamespace(postgres_image="postgres@sha256:" + "1" * 64)


# -- an example of what nft 1.0.6 prints ---------------------------------------------------


def _counter(name: str, packets: int = 0) -> dict:
    return {
        "counter": {
            "family": "inet",
            "name": name,
            "table": "mcpb",
            "handle": 3,
            "packets": packets,
            "bytes": packets * 60,
        }
    }


def _set(name: str, kind: str, elements: list[tuple[list, int]] | None) -> dict:
    body = {
        "family": "inet",
        "name": name,
        "table": "mcpb",
        "type": [kind, "inet_proto", "inet_service"],
        "handle": 7,
        "flags": ["dynamic"],
        "size": 16,
    }
    if elements is not None:
        body["elem"] = [
            {"elem": {"val": {"concat": key}, "counter": {"packets": n, "bytes": n * 60}}}
            for key, n in elements
        ]
    return {"set": body}


def nft_json(
    refused4=None, allowed=None, resolver=0, other=0, overflow=0, input_dropped=0, local4=None
) -> str:
    items = [
        {
            "metainfo": {
                "version": "1.0.6",
                "release_name": "Lester Gooch #5",
                "json_schema_version": 1,
            }
        },
        {"table": {"family": "inet", "name": "mcpb", "handle": 1}},
        _counter("resolver", resolver),
        _counter("other", other),
        _counter("input_dropped", input_dropped),
        _counter("overflow", overflow),
        _set("allowed", "ipv4_addr", allowed),
        _set("refused4", "ipv4_addr", refused4),
        _set("refused6", "ipv6_addr", None),
        _set("local4", "ipv4_addr", local4),
        {"chain": {"family": "inet", "table": "mcpb", "name": "output", "handle": 4}},
    ]
    return json.dumps({"nftables": items})


EXAMPLE = nft_json(
    refused4=[(["192.0.2.1", "tcp", 9], 2)],
    allowed=[(["10.201.7.10", "udp", 53], 4), (["10.201.7.10", "tcp", 8080], 1)],
)
#: What the counters show right after the probe: its one attempt, rejected, is one packet.
PROBED = nft_json(
    refused4=[(["192.0.2.1", "tcp", 9], 1)],
    allowed=[(["10.201.7.10", "udp", 53], 4), (["10.201.7.10", "tcp", 8080], 1)],
)


# -- the rules -----------------------------------------------------------------------------


def _allowed_targets(text: str) -> set[tuple[str, str, int]]:
    found = re.findall(r"ip daddr (\S+) (tcp|udp) dport (\d+) add @allowed", text)
    return {(a, p, int(n)) for a, p, n in found}


def test_page_may_reach_the_fixture_server_only():
    text = net.nft_ruleset("page", ADDRESSES)
    assert _allowed_targets(text) == {("10.201.7.10", "tcp", 8080), ("10.201.7.10", "udp", 53)}
    assert _allowed_targets(net.nft_ruleset("page-js", ADDRESSES)) == _allowed_targets(text)


def test_postgres_may_reach_its_names_and_the_database_only():
    text = net.nft_ruleset("postgres", ADDRESSES)
    assert _allowed_targets(text) == {("10.201.7.10", "udp", 53), ("10.201.7.11", "tcp", 5432)}


@pytest.mark.parametrize("kind", ["file", "sqlite", "git", "positive", "nothing"])
def test_a_kind_without_a_network_has_no_rules(kind):
    with pytest.raises(ValueError):
        net.nft_ruleset(kind, ADDRESSES)


def test_the_resolver_of_docker_is_counted_before_loopback_is_let_through():
    text = net.nft_ruleset("page", ADDRESSES)
    resolver = text.index('ip daddr 127.0.0.11 counter name "resolver" reject')
    assert resolver < text.index('oif "lo" accept')
    assert resolver < text.index("add @allowed")


def test_both_chains_drop_by_policy_and_the_rest_is_counted():
    text = net.nft_ruleset("postgres", ADDRESSES)
    assert text.count("policy drop;") == 2
    assert "hook output" in text
    assert "hook input" in text
    output, input_ = text.split("chain input")
    assert "add @refused4" in output
    assert "add @refused6" in output
    assert 'counter name "other" drop' in output
    assert "ct state established,related accept" in input_
    assert 'iif "lo" accept' in input_
    assert 'counter name "input_dropped" drop' in input_
    # What is let through is counted per target, and nothing is accepted without a count that
    # the rule above does not name: no bare "accept" but loopback and answers.
    bare = [
        line.strip()
        for line in text.splitlines()
        if line.strip().endswith("accept") and "add @allowed" not in line and "@local4" not in line
    ]
    assert bare == [
        'oif "lo" accept',
        "ct state established,related accept",
        "ct state established,related accept",
        'iif "lo" accept',
    ]


def test_an_attempt_the_full_set_does_not_take_is_rejected_and_counted_as_overflow():
    """``add`` into a full set breaks the rule, reject and all: without the two rules after the
    four, the attempt would fall to ``other`` and be dropped, retried, and counted per packet."""
    output = net.nft_ruleset("page", ADDRESSES).split("chain input")[0]
    rules = [line.strip() for line in output.splitlines()]
    last = max(i for i, rule in enumerate(rules) if "add @refused" in rule)
    assert rules[last + 1 : last + 4] == [
        'meta l4proto tcp counter name "overflow" reject with tcp reset',
        'meta l4proto udp counter name "overflow" reject',
        'counter name "other" drop',
    ]
    assert "counter overflow { }" in output


def test_the_size_of_the_sets_of_refused_targets_is_a_parameter():
    sizes = lambda text: re.findall(r"set refused[46] \{.*?size (\d+)", text, re.S)  # noqa: E731
    assert sizes(net.nft_ruleset("page", ADDRESSES)) == ["4096", "4096"]
    assert sizes(net.nft_ruleset("page", ADDRESSES, 2)) == ["2", "2"]


# -- the rules of the helpers --------------------------------------------------------------


def _served(text: str) -> set[tuple[str, str, int]]:
    """(from, protocol, port) of what the input chain lets in as new, apart from answers and
    loopback."""
    found = re.findall(r"ip saddr (\S+) (tcp|udp) dport (\d+) accept", text)
    return {(a, p, int(n)) for a, p, n in found}


@pytest.mark.parametrize(
    ("role", "served"),
    [
        ("fixture", {("tcp", 8080), ("udp", 53)}),
        ("postgres", {("tcp", 5432)}),
    ],
)
def test_a_helper_lets_in_what_its_role_serves_from_the_subnet_and_nothing_else(role, served):
    text = net.helper_ruleset(role, ADDRESSES)
    assert _served(text) == {("10.201.7.0/24", p, n) for p, n in served}
    output, input_ = text.split("chain input")
    # What comes in otherwise is counted and dropped.
    assert 'counter name "input_dropped" drop' in input_
    assert input_.index("dport") < input_.index("input_dropped")
    assert "policy drop;" in input_
    # The accepted ones are those and answers and loopback: no "accept" without a port.
    bare = [
        line.strip()
        for line in input_.splitlines()
        if line.strip().endswith("accept") and "dport" not in line
    ]
    assert bare == ["ct state established,related accept", 'iif "lo" accept']


@pytest.mark.parametrize("role", ["fixture", "postgres"])
def test_a_helper_lets_nothing_new_out_and_counts_every_attempt_per_target(role):
    output = net.helper_ruleset(role, ADDRESSES).split("chain input")[0]
    assert "policy drop;" in output
    accepted = [
        line.strip()
        for line in output.splitlines()
        if line.strip().endswith("accept") and "@local4" not in line
    ]
    assert accepted == ['oif "lo" accept', "ct state established,related accept"]
    # No rule names a destination to let through: ``daddr`` is only the key of the sets, and the
    # one address named is docker's resolver, which is rejected.
    assert re.findall(r"daddr \d\S*", output) == ["daddr 127.0.0.11"]
    rules = [line.strip() for line in output.splitlines()]
    assert sum("add @refused4" in r for r in rules) == 2
    assert sum("add @refused6" in r for r in rules) == 2
    # Every verdict on a new attempt is a reject, and a full set falls to ``overflow``, still
    # rejected; ``other`` is the one drop.
    assert all("reject" in r for r in rules if "add @refused" in r)
    last = max(i for i, rule in enumerate(rules) if "add @refused" in rule)
    assert rules[last + 1 : last + 4] == [
        'meta l4proto tcp counter name "overflow" reject with tcp reset',
        'meta l4proto udp counter name "overflow" reject',
        'counter name "other" drop',
    ]


def test_a_helper_has_the_sets_and_counters_the_report_reads_and_no_allowed_set():
    text = net.helper_ruleset("postgres", ADDRESSES)
    for name in net.HELPER_SETS:
        assert f"set {name} {{" in text
    for name in net.HELPER_COUNTERS:
        assert f"counter {name} {{ }}" in text
    assert "allowed" not in text


def test_the_size_of_the_sets_of_a_helper_is_a_parameter():
    sizes = lambda text: re.findall(r"set refused[46] \{.*?size (\d+)", text, re.S)  # noqa: E731
    assert sizes(net.helper_ruleset("fixture", ADDRESSES)) == ["4096", "4096"]
    assert sizes(net.helper_ruleset("fixture", ADDRESSES, 3)) == ["3", "3"]
    assert _local_size(net.helper_ruleset("fixture", ADDRESSES, 3)) == "3"


def _local_size(text: str) -> str:
    return re.search(r"set local4 \{.*?size (\d+)", text, re.S).group(1)


@pytest.mark.parametrize("role", ["fixture", "postgres"])
def test_a_helper_counts_and_rejects_the_resolver_of_docker_before_loopback_is_let_through(role):
    """The helpers are on the same docker network as the holder, with the same resolver: what
    they send to it leaves the network, so it is counted and rejected, not let through as part
    of ``127.0.0.0/8``."""
    output = net.helper_ruleset(role, ADDRESSES).split("chain input")[0]
    resolver = output.index('ip daddr 127.0.0.11 counter name "resolver" reject')
    assert resolver < output.index('oif "lo"')
    assert "counter resolver { }" in output
    assert "resolver" in net.HELPER_COUNTERS


def _rules_of(text: str) -> list[str]:
    return [line.strip() for line in text.split("chain input")[0].splitlines()]


@pytest.mark.parametrize(
    "text",
    [
        net.nft_ruleset("page", ADDRESSES),
        net.nft_ruleset("postgres", ADDRESSES),
        net.helper_ruleset("fixture", ADDRESSES),
        net.helper_ruleset("postgres", ADDRESSES),
    ],
    ids=["page", "postgres", "fixture-helper", "postgres-helper"],
)
def test_a_new_connection_over_loopback_is_counted_per_target_and_let_through(text):
    """It does not leave the namespace, so it is accepted, not rejected; but not unseen: it goes
    into the set ``local4`` before the plain loopback rule, after the resolver's."""
    rules = _rules_of(text)
    local = [rule for rule in rules if "@local4" in rule]
    assert [rule.split(" add ")[0] for rule in local] == [
        'oif "lo" ct state new meta nfproto ipv4 meta l4proto tcp',
        'oif "lo" ct state new meta nfproto ipv4 meta l4proto udp',
    ]
    assert all(rule.endswith("accept") and "reject" not in rule for rule in local)
    plain = rules.index('oif "lo" accept')
    resolver = next(i for i, rule in enumerate(rules) if "127.0.0.11" in rule)
    assert resolver < rules.index(local[0]) < rules.index(local[1]) < plain
    assert "set local4 {" in text
    assert "\\" not in text and "{{" not in text and "}}" not in text  # no stray text
    assert _local_size(text) == "4096"
    assert _local_size(text.replace("size 4096", "size 7")) == "7"


def test_the_size_of_the_set_of_loopback_is_the_size_that_was_asked_for():
    assert _local_size(net.nft_ruleset("page", ADDRESSES, 2)) == "2"


@pytest.mark.parametrize("role", ["holder", "server", ""])
def test_a_helper_has_a_role_of_the_list_or_no_rules(role):
    with pytest.raises(ValueError):
        net.helper_ruleset(role, ADDRESSES)


def test_the_counters_of_a_helper_are_read_by_its_own_names():
    text = nft_json(refused4=[(["10.201.7.20", "tcp", 80], 3)], overflow=1)
    counts = net.parse_nft(text, net.HELPER_SETS, net.HELPER_COUNTERS)
    assert set(counts.sets) == set(net.HELPER_SETS)
    assert set(counts.counters) == set(net.HELPER_COUNTERS)
    assert counts.sets["refused4"] == {("10.201.7.20", "tcp", 80): net.Count(3, 180)}
    assert counts.counters["overflow"].packets == 1
    # The holder's reading still wants the holder's sets and counters.
    with pytest.raises(net.NftError, match="allowed"):
        net.parse_nft(
            json.dumps({"nftables": [{"table": {"family": "inet", "name": "mcpb"}}]}),
        )
    only = json.loads(text)
    only["nftables"] = [
        i for i in only["nftables"] if "counter" not in i or i["counter"]["name"] != "overflow"
    ]
    with pytest.raises(net.NftError, match="overflow"):
        net.parse_nft(json.dumps(only), net.HELPER_SETS, net.HELPER_COUNTERS)


# -- PostgreSQL's log ----------------------------------------------------------------------

PG_OWN = "10.201.7.11"
PG_LOG = """\
2026-10-16 10:00:00.100 UTC [1] LOG:  starting PostgreSQL 17.0 on x86_64-pc-linux-gnu
2026-10-16 10:00:01.000 UTC [40] LOG:  connection received: host=10.201.7.11 port=40000
2026-10-16 10:00:01.010 UTC [40] LOG:  connection authorized: user=postgres database=postgres
2026-10-16 10:00:01.020 UTC [40] LOG:  statement: SELECT 1
2026-10-16 10:00:01.030 UTC [40] LOG:  disconnection: session time: 0:00:00.030 user=postgres database=postgres host=10.201.7.11 port=40000
2026-10-16 10:00:05.000 UTC [57] LOG:  connection received: host=10.201.7.20 port=51234
2026-10-16 10:00:05.010 UTC [57] LOG:  connection authorized: user=reader database=postgres application_name=psql
2026-10-16 10:00:05.020 UTC [57] LOG:  statement: SELECT note FROM kanarie
2026-10-16 10:00:05.030 UTC [57] LOG:  statement: SELECT a,
\tb FROM kanarie
2026-10-16 10:00:05.040 UTC [57] LOG:  execute S_1: SELECT $1
2026-10-16 10:00:05.050 UTC [57] DETAIL:  parameters: $1 = '1'
2026-10-16 10:00:05.060 UTC [57] LOG:  disconnection: session time: 0:00:00.060 user=reader database=postgres host=10.201.7.20 port=51234
"""  # noqa: E501 - lines of PostgreSQL's log, as they are


def test_the_log_of_postgres_gives_the_sessions_and_statements_of_the_server():
    log = net.parse_postgres_log(PG_LOG, PG_OWN)
    assert log.sessions == ({"user": "reader", "database": "postgres", "application": "psql"},)
    assert [s["statement"] for s in log.statements] == [
        "SELECT note FROM kanarie",
        "SELECT a,\nb FROM kanarie",
        "SELECT $1",
    ]
    assert {(s["user"], s["database"]) for s in log.statements} == {("reader", "postgres")}
    assert log.problems == ()


def test_the_readiness_check_of_the_runner_is_in_no_session_and_no_statement():
    log = net.parse_postgres_log(PG_LOG, PG_OWN)
    assert "postgres" not in {s["user"] for s in log.sessions}
    assert "SELECT 1" not in [s["statement"] for s in log.statements]
    # Where the address is another one, the same lines are a session like any.
    other = net.parse_postgres_log(PG_LOG, "10.201.7.99")
    assert [s["user"] for s in other.sessions] == ["postgres", "reader"]


def test_the_start_up_text_of_the_image_is_no_problem_but_a_broken_line_after_it_is():
    text = (
        "The files belonging to this database system will be owned by user postgres.\n"
        "waiting for server to start....done\n" + PG_LOG + "garbage in the middle\n"
        "2026-10-16 10:00:09.000 UTC [58] LOG:  connection authorized: user=reader database=db\n"
    )
    log = net.parse_postgres_log(text, PG_OWN)
    n = len(text.splitlines())
    assert log.problems == (f"line {n - 1}: not a log line: 'garbage in the middle'",)
    assert log.sessions[-1] == {"user": "reader", "database": "db", "application": ""}
    assert log.lines == n


@pytest.mark.parametrize(
    "line",
    [
        "",
        "LOG:  connection authorized: user=reader database=postgres",
        "2026-10-16 10:00:05 UTC [x] LOG:  connection authorized: user=reader database=db",
        "2026-10-16 10:00:05.010 UTC [57] LOG:  connection authorized: nothing of the kind",
        "2026-10-16 10:00:05.010 UTC [57] LOG:  statement:",
        "\x00\x01 binary",
    ],
)
def test_a_line_of_the_log_that_is_not_what_it_seems_is_no_session(line):
    log = net.parse_postgres_log(PG_LOG + line + "\n", PG_OWN)
    assert len(log.sessions) == 1
    assert [s["user"] for s in log.sessions] == ["reader"]


def test_the_log_is_cleaned_with_the_function_it_is_given():
    text = (
        "2026-10-16 10:00:05.010 UTC [57] LOG:  connection authorized: user=reader "
        "database=postgres application_name=SECRET-app\n"
        "2026-10-16 10:00:05.020 UTC [57] LOG:  statement: SELECT 'SECRET'\n"
        "boom SECRET\n"
    )
    log = net.parse_postgres_log(text, PG_OWN, lambda s: s.replace("SECRET", "******"))
    assert log.sessions[0]["application"] == "******-app"
    assert log.statements[0]["statement"] == "SELECT '******'"
    assert "SECRET" not in repr(log)


def test_a_statement_is_cut_where_it_is_very_long():
    text = (
        "2026-10-16 10:00:05.010 UTC [57] LOG:  connection authorized: user=r database=d\n"
        f"2026-10-16 10:00:05.020 UTC [57] LOG:  statement: SELECT '{'a' * 5000}'\n"
    )
    (statement,) = net.parse_postgres_log(text, PG_OWN).statements
    assert len(statement["statement"]) == net.PG_STATEMENT_LIMIT


def test_since_the_baseline_only_later_sessions_statements_and_problems_remain():
    base = net.parse_postgres_log(PG_LOG + "late garbage\n", PG_OWN)
    assert len(base.problems) == 1
    more = (
        PG_LOG + "late garbage\n"
        "2026-10-16 10:01:00.000 UTC [60] LOG:  connection authorized: user=reader database=db\n"
        "2026-10-16 10:01:00.010 UTC [60] LOG:  statement: DROP TABLE kanarie\n"
        "more garbage\n"
    )
    log = net.parse_postgres_log(more, PG_OWN).since(base)
    assert [s["database"] for s in log.sessions] == ["db"]
    assert [s["statement"] for s in log.statements] == ["DROP TABLE kanarie"]
    assert [p.split(":")[0] for p in log.problems] == [f"line {len(more.splitlines())}"]
    shorter = net.parse_postgres_log("", PG_OWN).since(base)
    assert shorter.problems == ("the log is shorter than at the baseline",)


#: Connections that did not get in, as PostgreSQL writes them: the runner's own
#: readiness check (host PG_OWN) turned away while it starts; a wrong password; a database that
#: does not exist (after ``authorized``); ``pg_hba``; an unknown role; one received and never
#: authorized; and a session that was fine and ended with a ``FATAL`` of its own.
PG_FAILED = """\
2026-10-16 10:00:01.000 UTC [40] LOG:  connection received: host=10.201.7.11 port=40000
2026-10-16 10:00:01.010 UTC [40] FATAL:  the database system is starting up
2026-10-16 10:00:05.000 UTC [57] LOG:  connection received: host=10.201.7.20 port=51234
2026-10-16 10:00:05.010 UTC [57] FATAL:  password authentication failed for user "postgres"
2026-10-16 10:00:05.011 UTC [57] DETAIL:  Connection matched file "pg_hba.conf" line 128: "host all all all scram-sha-256"
2026-10-16 10:00:06.000 UTC [58] LOG:  connection received: host=10.201.7.20 port=51235
2026-10-16 10:00:06.010 UTC [58] LOG:  connection authorized: user=reader database=nowhere
2026-10-16 10:00:06.020 UTC [58] FATAL:  database "nowhere" does not exist
2026-10-16 10:00:07.000 UTC [59] LOG:  connection received: host=10.201.7.20 port=51236
2026-10-16 10:00:07.010 UTC [59] FATAL:  no pg_hba.conf entry for host "10.201.7.20", user "x", database "y", no encryption
2026-10-16 10:00:08.000 UTC [60] LOG:  connection received: host=10.201.7.20 port=51237
2026-10-16 10:00:08.010 UTC [60] FATAL:  role "ghost" does not exist
2026-10-16 10:00:09.000 UTC [61] LOG:  connection received: host=10.201.7.20 port=51238
2026-10-16 10:00:10.000 UTC [70] LOG:  connection received: host=10.201.7.20 port=51239
2026-10-16 10:00:10.010 UTC [70] LOG:  connection authorized: user=reader database=postgres
2026-10-16 10:00:11.000 UTC [70] FATAL:  terminating connection due to administrator command
"""  # noqa: E501 - lines of PostgreSQL's log, as they are

FAILED = [
    {
        "user": "postgres", "database": None,
        "reason": 'password authentication failed for user "postgres"',
    },
    {"user": "reader", "database": "nowhere", "reason": 'database "nowhere" does not exist'},
    {
        "user": "x", "database": "y",
        "reason": 'no pg_hba.conf entry for host "10.201.7.20", user "x", database "y", '
        "no encryption",
    },
    {"user": "ghost", "database": None, "reason": 'role "ghost" does not exist'},
    {"user": None, "database": None, "reason": net.PG_NEVER_AUTHORIZED},
]  # fmt: skip


def test_a_login_that_failed_is_in_the_log_with_user_database_and_reason():
    log = net.parse_postgres_log(PG_FAILED, PG_OWN)
    assert list(log.failed_logins) == FAILED
    assert log.problems == ()
    # The session of the unknown database was authorized, and is still a session; the readiness
    # check's FATAL and the session that was ended are no failed login.
    assert [s["database"] for s in log.sessions] == ["nowhere", "postgres"]


def test_a_log_of_sessions_that_were_fine_has_no_failed_login():
    assert net.parse_postgres_log(PG_LOG, PG_OWN).failed_logins == ()


def test_a_pid_that_is_used_again_does_not_hide_the_connection_that_never_got_in():
    text = (
        "2026-10-16 10:00:09.000 UTC [61] LOG:  connection received: host=10.201.7.20 port=1\n"
        "2026-10-16 10:00:10.000 UTC [61] LOG:  connection received: host=10.201.7.20 port=2\n"
        "2026-10-16 10:00:10.010 UTC [61] LOG:  connection authorized: user=reader database=db\n"
    )
    log = net.parse_postgres_log(text, PG_OWN)
    assert [f["reason"] for f in log.failed_logins] == [net.PG_NEVER_AUTHORIZED]
    assert len(log.sessions) == 1


def test_the_failed_logins_are_cleaned_with_the_function_it_is_given():
    text = (
        "2026-10-16 10:00:05.000 UTC [57] LOG:  connection received: host=10.201.7.20 port=1\n"
        "2026-10-16 10:00:05.010 UTC [57] FATAL:  "
        'password authentication failed for user "SECRET"\n'
    )
    log = net.parse_postgres_log(text, PG_OWN, lambda s: s.replace("SECRET", "******"))
    assert log.failed_logins[0]["user"] == "******"
    assert "SECRET" not in repr(log)


def test_since_the_baseline_only_later_failed_logins_remain():
    first = PG_FAILED.splitlines()[:5]  # up to the first FATAL of a connection of the server
    base = net.parse_postgres_log("\n".join([*first, ""]), PG_OWN)
    assert len(base.failed_logins) == 1
    log = net.parse_postgres_log(PG_FAILED, PG_OWN).since(base)
    assert [f["reason"] for f in log.failed_logins] == [f["reason"] for f in FAILED[1:]]
    # A connection that was received before the baseline and never authorized is not the run's.
    pending = net.parse_postgres_log(PG_FAILED.splitlines()[12] + "\n", PG_OWN)
    assert [f["reason"] for f in pending.failed_logins] == [net.PG_NEVER_AUTHORIZED]
    assert net.parse_postgres_log(PG_FAILED, PG_OWN).since(pending).failed_logins[-1] == FAILED[-1]
    shorter = net.parse_postgres_log("", PG_OWN).since(base)
    assert shorter.failed_logins == ()


# -- parse_nft -----------------------------------------------------------------------------


def test_parse_nft_reads_the_counts_of_every_set():
    counts = net.parse_nft(EXAMPLE)
    assert counts.sets["refused4"] == {("192.0.2.1", "tcp", 9): net.Count(2, 120)}
    assert counts.sets["allowed"][("10.201.7.10", "tcp", 8080)] == net.Count(1, 60)
    assert counts.sets["refused6"] == {}
    assert counts.counters["resolver"] == net.Count(0, 0)


def test_parse_nft_of_a_table_without_elements_is_empty_and_says_so():
    counts = net.parse_nft(nft_json())
    assert counts.sets == {"allowed": {}, "refused4": {}, "refused6": {}, "local4": {}}
    assert set(counts.counters) == {"resolver", "other", "input_dropped", "overflow"}


def test_parse_nft_reads_a_protocol_number():
    text = nft_json(refused4=[(["192.0.2.1", 17, 53], 1)])
    assert net.parse_nft(text).sets["refused4"] == {("192.0.2.1", "udp", 53): net.Count(1, 60)}


def _without(kind: str, name: str) -> str:
    data = json.loads(EXAMPLE)
    data["nftables"] = [item for item in data["nftables"] if item.get(kind, {}).get("name") != name]
    return json.dumps(data)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "[]",
        '{"nftables": "x"}',
        '{"nftables": []}',
        json.dumps({"nftables": [{"table": {"family": "ip", "name": "mcpb"}}]}),
        _without("set", "refused4"),
        _without("set", "local4"),
        _without("counter", "other"),
        _without("counter", "overflow"),
        EXAMPLE.replace('"packets": 2', '"packets": "2"'),
        EXAMPLE.replace('"bytes": 120', '"bytes": null'),
        EXAMPLE.replace('"concat": ["192.0.2.1", "tcp", 9]', '"concat": ["192.0.2.1", "tcp"]'),
        EXAMPLE.replace('"counter": {"packets": 2, "bytes": 120}', '"timeout": 3'),
    ],
)
def test_parse_nft_refuses_what_it_cannot_read(text):
    with pytest.raises(net.NftError):
        net.parse_nft(text)


def test_the_difference_to_the_baseline_is_what_was_counted_since():
    base = net.parse_nft(nft_json(refused4=[(["192.0.2.1", "tcp", 9], 2)], resolver=1))
    now = net.parse_nft(
        nft_json(
            refused4=[(["192.0.2.1", "tcp", 9], 2), (["1.1.1.1", "tcp", 443], 3)],
            allowed=[(["10.201.7.10", "udp", 53], 2)],
            resolver=4,
            other=1,
        )
    )
    since = now.minus(base).as_dict()
    assert since["refused4"] == [{"target": "1.1.1.1", "protocol": "tcp", "port": 443, "count": 3}]
    assert since["allowed"] == [
        {"target": "10.201.7.10", "protocol": "udp", "port": 53, "count": 2}
    ]
    assert since["counters"] == {"resolver": 3, "other": 1, "input_dropped": 0, "overflow": 0}
    assert now.minus(now).as_dict()["refused4"] == []


def test_a_count_that_went_down_is_an_error_not_a_difference():
    base = net.parse_nft(nft_json(refused4=[(["192.0.2.1", "tcp", 9], 2)]))
    with pytest.raises(net.NftError):
        net.parse_nft(nft_json(refused4=[(["192.0.2.1", "tcp", 9], 1)])).minus(base)
    with pytest.raises(net.NftError):
        net.parse_nft(nft_json()).minus(base)


# -- the fixture server's log --------------------------------------------------------------

READY = json.dumps({"event": "ready", "http_port": 8080})
DNS = json.dumps(
    {"event": "dns", "client": "10.201.7.20", "name": "example.com", "type": "A", "answer": None,
     "rcode": "NXDOMAIN"}
)  # fmt: skip
HTTP = json.dumps(
    {"event": "http", "method": "GET", "path": "/canary.html", "client": "10.201.7.20",
     "user_agent": None, "status": 200}
)  # fmt: skip


def test_the_log_is_read_line_by_line():
    log = net.parse_fixture_log(f"{READY}\n{DNS}\n\n{HTTP}\n")
    assert log.ready
    assert [e["event"] for e in log.events] == ["ready", "dns", "http"]
    assert log.problems == ()
    assert [e["name"] for e in log.of("dns")] == ["example.com"]


@pytest.mark.parametrize("line", ["Traceback (most recent call last):", "[1, 2]", '{"x": 1}', "{"])
def test_a_line_that_is_no_event_is_a_problem(line):
    log = net.parse_fixture_log(f"{READY}\n{line}\n{DNS}\n")
    assert len(log.events) == 2
    assert len(log.problems) == 1
    assert log.problems[0].startswith("line 2:")


def test_a_log_without_the_ready_line_is_not_ready():
    assert not net.parse_fixture_log(DNS).ready
    assert not net.parse_fixture_log("").ready


def test_since_the_baseline_only_later_events_remain():
    base = net.parse_fixture_log(f"{READY}\n{DNS}\n")
    now = net.parse_fixture_log(f"{READY}\n{DNS}\n{HTTP}\n")
    assert [e["event"] for e in now.since(base).events] == ["http"]
    shorter = net.parse_fixture_log(f"{READY}\n").since(base)
    assert shorter.events == ()
    assert shorter.problems


def _dropped(http, dns) -> str:
    return json.dumps({"event": "dropped", "http": http, "dns": dns})


def test_the_line_dropped_of_the_server_gives_the_last_totals():
    log = net.parse_fixture_log(f"{READY}\n{DNS}\n{_dropped(0, 1000)}\n{_dropped(1000, 2000)}\n")
    assert log.problems == ()
    assert log.dropped() == {"http": 1000, "dns": 2000}
    assert net.parse_fixture_log(f"{READY}\n{DNS}\n").dropped() is None


@pytest.mark.parametrize("totals", [(None, 5), ("3", 5), (True, 5), (-1, 5), (3, 1.5)])
def test_totals_of_a_dropped_line_that_are_no_counts_are_none(totals):
    log = net.parse_fixture_log(f"{READY}\n{_dropped(*totals)}\n")
    dropped = log.dropped()
    assert dropped is not None and None in dropped.values()
    assert sum(v is None for v in dropped.values()) == 1


# -- addresses and files -------------------------------------------------------------------


def test_the_resolver_file_names_the_fixture_server_alone():
    assert net.resolv_conf(ADDRESSES) == "nameserver 10.201.7.10\noptions attempts:1 timeout:2\n"


def test_addresses_are_fixed_in_the_subnet():
    assert (ADDRESSES.fixture, ADDRESSES.postgres, ADDRESSES.holder) == (
        "10.201.7.10",
        "10.201.7.11",
        "10.201.7.20",
    )


def test_a_subnet_is_a_slash_24_in_the_range_and_avoids_the_others():
    seeded = random.Random  # noqa: S311 - a seed, for a repeatable test
    rng = seeded(7)
    for _ in range(200):
        subnet = net.choose_subnet(rng)
        assert subnet.prefixlen == 24
        second, third = subnet.network_address.packed[1:3]
        assert 200 <= second <= 254
        assert third <= 255
    free = ipaddress.IPv4Network("10.230.17.0/24")
    avoided = [
        ipaddress.IPv4Network(f"10.{b}.{c}.0/24")
        for b in range(200, 255)
        for c in range(256)
        if (b, c) != (230, 17)
    ]
    assert net.choose_subnet(seeded(1), avoided) == free
    with pytest.raises(bench.RunnerError):
        net.choose_subnet(seeded(1), [*avoided, free])


# -- the commands --------------------------------------------------------------------------


def _all_commands(kind: str = "postgres") -> dict[str, list[str]]:
    script = Path("/tmp/scratch/probe.py")  # noqa: S108 - never opened
    resolv = Path("/out/resolv-x.conf")
    d = "docker"
    server = net.server_command(
        d, NONCE, "mcpb-srv-x", kind, "mcpb-fix-x", "img", ["--serve"], [("A", "b")],
        holder="mcpb-hold-x", resolv=resolv,
    )  # fmt: skip
    return {
        "fill": net.fill_command(d, NONCE, "mcpb-fill-x", "mcpb-fix-x"),
        "postgres": net.postgres_command(
            d,
            NONCE,
            "mcpb-pg-x",
            "mcpb-netb-x",
            ADDRESSES.postgres,
            "postgres@sha256:" + "1" * 64,
            "mcpb-fix-x",
            "a-password",
        ),
        "fixture": net.fixture_server_command(
            d, NONCE, "mcpb-fixsrv-x", "mcpb-netb-x", ADDRESSES, kind, "mcpb-fix-x", "print(1)\n"
        ),
        "holder": net.holder_command(d, NONCE, "mcpb-hold-x", "mcpb-netb-x", ADDRESSES),
        "load": net.nft_command(
            d, NONCE, "mcpb-nft-x", "mcpb-hold-x", "nft-image", ["-f", "-"], True
        ),
        "read": net.nft_command(d, NONCE, "mcpb-nft-x", "mcpb-hold-x", "nft-image", ["-j", "list"]),
        "probe": net.probe_command(
            d, NONCE, "mcpb-probe-x", "mcpb-hold-x", script, ADDRESSES, kind
        ),
        "server": server,
    }


def _pairs(command: list[str], option: str) -> list[str]:
    return [command[i + 1] for i, part in enumerate(command) if part == option]


@pytest.mark.parametrize("kind", ["postgres", "page"])
def test_every_container_of_the_run_carries_its_label(kind):
    for name, command in _all_commands(kind).items():
        assert _pairs(command, "--label") == [f"mcp-kymograph.bench={NONCE}"], name


def test_the_run_creates_network_and_volume_with_the_label():
    network = net.network_create_command("docker", NONCE, ADDRESSES.subnet)
    assert "--internal" in network
    assert "com.docker.network.bridge.inhibit_ipv4=true" in network
    assert _pairs(network, "--subnet") == ["10.201.7.0/24"]
    assert _pairs(network, "--label") == [f"mcp-kymograph.bench={NONCE}"]
    assert network[-1] == f"mcpb-netb-{NONCE}"
    volume = net.volume_create_command("docker", NONCE, "mcpb-fix-x")
    assert _pairs(volume, "--label") == [f"mcp-kymograph.bench={NONCE}"]


def test_the_log_of_the_fixture_server_is_kept_in_one_file_of_at_most_8_mb():
    """A flood of questions must not fill the disk of the host; the fixture server
    limits the events it writes itself."""
    command = _all_commands("page")["fixture"]
    assert _pairs(command, "--log-driver") == ["json-file"]
    assert _pairs(command, "--log-opt") == ["max-size=8m", "max-file=1"]
    assert command.index("--log-driver") < command.index(bench.PYTHON_IMAGE)


def test_nothing_is_published_and_nothing_is_privileged():
    for name, command in _all_commands().items():
        assert "-p" not in command, name
        assert "--publish" not in command, name
        assert "--privileged" not in command, name
        assert not any(part.startswith("--publish") for part in command), name
        assert "--network" in command, name


def test_the_containers_that_hold_foreign_input_are_read_only_and_without_rights():
    commands = _all_commands("page")
    for name in ("fill", "fixture", "holder", "load", "read", "probe", "server"):
        assert "--read-only" in commands[name], name
        assert _pairs(commands[name], "--cap-drop") == ["ALL"], name
    for name in ("fixture", "holder", "probe", "server"):
        assert "--cap-add" not in commands[name], name
        assert _pairs(commands[name], "--user") == ["65534:65534"], name
    assert _pairs(commands["fill"], "--cap-add") == ["CHOWN"]
    assert _pairs(commands["load"], "--cap-add") == ["NET_ADMIN"]
    assert _pairs(commands["read"], "--cap-add") == ["NET_ADMIN"]


def test_no_sysctl_and_no_capability_for_port_53():
    for name, command in _all_commands("page").items():
        assert "--sysctl" not in command, name
    assert "NET_BIND_SERVICE" not in " ".join(_all_commands("page")["fixture"])


def test_the_helpers_and_the_server_join_the_namespace_of_the_holder():
    commands = _all_commands("page")
    for name in ("load", "read", "probe", "server"):
        assert _pairs(commands[name], "--network") == ["container:mcpb-hold-x"], name
    for name in ("fixture", "holder", "postgres"):
        assert _pairs(commands[name], "--network") == ["mcpb-netb-x"], name
    assert _pairs(commands["fixture"], "--ip") == [ADDRESSES.fixture]
    assert _pairs(commands["holder"], "--ip") == [ADDRESSES.holder]
    assert _pairs(_all_commands("postgres")["postgres"], "--ip") == [ADDRESSES.postgres]


def test_what_joins_the_namespace_has_no_dns_option():
    # docker refuses --dns with --network container:, and the resolver file does the work.
    commands = _all_commands("page")
    for name in ("load", "read", "probe", "server"):
        assert "--dns" not in commands[name], name
        assert "--dns-search" not in commands[name], name
    server = commands["server"]
    assert _pairs(server, "-v")[-1] == "/out/resolv-x.conf:/etc/resolv.conf:ro"
    assert "--network" in server
    assert "none" not in _pairs(server, "--network")


def test_no_host_path_but_the_resolver_file_and_the_probe_script():
    allowed = {"/out/resolv-x.conf", "/tmp/scratch/probe.py"}  # noqa: S108 - never opened
    for kind in ("postgres", "page"):
        for name, command in _all_commands(kind).items():
            for mount in _pairs(command, "-v"):
                source = mount.split(":")[0]
                # A named volume has no slash; a path has to be one of the two.
                assert "/" not in source or source in allowed, (name, mount)
            # Any other path of the host in an argument would be outside a mount, and no
            # command has one.
            host = [p for p in command if p.startswith(("/out", "/tmp/scratch", "/home"))]  # noqa: S108
            assert all(any(a in p for a in allowed) for p in host), (name, host)
    # The filling container has no path of the host in it at all.
    assert _pairs(_all_commands()["fill"], "-v") == ["mcpb-fix-x:/srv/fixtures"]


def test_the_fixture_server_script_goes_in_as_text():
    command = _all_commands("page")["fixture"]
    assert command[command.index("-c") + 1] == "print(1)\n"
    assert _pairs(command, "--name")[1:] == ["fixture=10.201.7.10"]
    names = _pairs(_all_commands("postgres")["fixture"], "--name")
    assert names[1:] == ["fixture=10.201.7.10", "postgres=10.201.7.11"]


def test_the_server_reads_the_fixture_read_only_where_it_only_reads():
    def mount(kind: str) -> list[str]:
        command = net.server_command(
            "docker", NONCE, "s", kind, "mcpb-fix-x", "img", [], (), holder=None, resolv=None
        )
        return [m for m in _pairs(command, "-v") if m.startswith("mcpb-fix-x")]

    assert mount("file") == ["mcpb-fix-x:/srv/fixtures:ro"]
    assert mount("positive") == ["mcpb-fix-x:/srv/fixtures:ro"]
    assert mount("sqlite") == ["mcpb-fix-x:/srv/fixtures"]
    assert mount("git") == ["mcpb-fix-x:/srv/fixtures"]
    assert mount("page") == []


def test_a_kind_without_a_network_keeps_network_none():
    command = net.server_command(
        "docker", NONCE, "s", "file", "mcpb-fix-x", "img", ["a"], [("K", "v")]
    )
    assert _pairs(command, "--network") == ["none"]
    assert _pairs(command, "--dns") == ["127.0.0.1"]
    assert command[-2:] == ["img", "a"]
    assert "K=v" in command


def test_the_server_in_the_namespace_needs_a_resolver_file():
    with pytest.raises(bench.RunnerError):
        net.server_command("docker", NONCE, "s", "page", "v", "img", [], (), holder="h")


def test_postgres_comes_by_digest_with_the_script_read_only_and_data_in_memory():
    command = _all_commands()["postgres"]
    image = command.index("postgres@sha256:" + "1" * 64)
    assert command[image + 1 :] == [
        "-c", "log_connections=on", "-c", "log_disconnections=on", "-c", "log_statement=all"
    ]  # fmt: skip
    assert "mcpb-fix-x:/docker-entrypoint-initdb.d:ro" in _pairs(command, "-v")
    assert any(m.startswith("/var/lib/postgresql/data:") for m in _pairs(command, "--tmpfs"))
    assert "POSTGRES_PASSWORD=a-password" in _pairs(command, "-e")


def test_postgres_has_the_rights_of_its_user_and_not_one_more():
    command = _all_commands()["postgres"]
    assert _pairs(command, "--user") == ["999:999"]
    assert "--read-only" in command
    assert _pairs(command, "--cap-drop") == ["ALL"]
    assert "--cap-add" not in command
    assert not any(part.startswith("--cap-add") for part in command)
    assert _pairs(command, "--security-opt") == ["no-new-privileges"]
    assert "--privileged" not in command


def test_what_postgres_writes_is_memory_of_its_own_user():
    tmpfs = {
        m.split(":")[0]: m.split(":")[1].split(",")
        for m in _all_commands()["postgres"]
        if ":" in m and m.startswith("/")
    }
    assert set(tmpfs) == {"/var/lib/postgresql/data", "/var/run/postgresql", "/tmp"}  # noqa: S108
    for path, options in tmpfs.items():
        assert {"rw", "nosuid", "nodev", "uid=999", "gid=999"} <= set(options), path
        assert any(o.startswith("size=") for o in options), path
    assert "mode=0700" in tmpfs["/var/lib/postgresql/data"]
    # The directories the others hold are no tighter than the image makes them.
    assert not any(o.startswith("mode=") for o in tmpfs["/tmp"])  # noqa: S108


def test_postgres_has_no_resolver_of_the_host_like_the_other_helpers():
    command = _all_commands()["postgres"]
    assert _pairs(command, "--dns") == ["127.0.0.1"]
    assert _pairs(command, "--dns-search") == ["."]


def test_the_password_of_the_superuser_is_new_for_each_run_and_is_nowhere_in_the_report(fake):
    passwords = []
    reports = []
    for nonce in ("aabbccdd", "11223344"):
        fixture = fixtures.build(
            "postgres", fixtures.new_canary("t"), reader_password=READER_PASSWORD
        )
        running = net.StageBNetwork(
            "postgres", fixture, POSTGRES, fake.docker, fake.tmp / "out", nonce=nonce,
            reader_password=READER_PASSWORD,
        )  # fmt: skip
        with running:
            pass
        (call,) = [c for c in _calls(fake) if f"mcpb-pg-{nonce}" in c and "-d" in c]
        (given,) = [e for e in _pairs(call, "-e") if e.startswith("POSTGRES_PASSWORD=")]
        passwords.append(given.removeprefix("POSTGRES_PASSWORD="))
        reports.append(json.dumps(running.report.as_dict()))
    assert passwords[0] != passwords[1]
    assert all(len(password) >= 32 for password in passwords)
    assert not hasattr(net, "POSTGRES_PASSWORD")
    for password in passwords:
        assert not any(password in report for report in reports)
        assert not any(password in path.read_text() for path in (fake.tmp / "out").glob("*"))


def test_the_url_of_the_database_is_put_in_where_the_arguments_ask_for_it(fake):
    url = f"postgresql://reader:{READER_PASSWORD}@postgres:5432/postgres"
    with _network(fake, "postgres") as running:
        command = running.server_command(
            "img", ["--db", "{postgres_url}", "--flag", "plain", "x={postgres_url}"]
        )
    image = command.index("img")
    assert command[image + 1 :] == ["--db", url, "--flag", "plain", f"x={url}"]
    # Only the arguments after the image are touched, and the report has nothing of it.
    assert url not in " ".join(command[:image])


def test_a_kind_without_a_database_has_no_url_to_put_in(fake):
    with _network(fake, "page") as running:
        with pytest.raises(bench.RunnerError, match="no database"):
            running.server_command("img", ["{postgres_url}"])
        assert running.server_command("img", ["plain"])[-1] == "plain"


def test_postgres_needs_the_password_of_the_run_for_the_role_it_hands_out(fake):
    fixture = fixtures.build("postgres", fixtures.new_canary("t"), reader_password=READER_PASSWORD)
    for password in (None, ""):
        with pytest.raises(bench.RunnerError, match="password"):
            net.StageBNetwork(
                "postgres", fixture, POSTGRES, fake.docker, fake.tmp, reader_password=password
            )
    assert not hasattr(net, "READER_PASSWORD")


def test_the_secrets_of_a_run_are_both_passwords_and_only_where_there_is_a_database(fake):
    running = _network(fake, "postgres")
    assert set(running.secrets) == {READER_PASSWORD, running._postgres_password}
    assert len(running.secrets) == 2 and running._postgres_password != READER_PASSWORD
    assert _network(fake, "page").secrets == ()
    assert _network(fake, "sqlite").secrets == ()


def test_what_the_caller_hides_is_a_secret_of_the_run_in_every_kind(fake):
    assert _network(fake, "page", hidden=("tok-en-1",)).secrets == ("tok-en-1",)
    assert _network(fake, "sqlite", hidden=("tok-en-1",)).secrets == ("tok-en-1",)
    running = _network(fake, "postgres", hidden=("tok-en-1",))
    assert set(running.secrets) == {READER_PASSWORD, running._postgres_password, "tok-en-1"}


def test_the_log_of_postgres_is_cleaned_of_what_the_caller_hides_too(fake, monkeypatch):
    running = _network(fake, "postgres", hidden=("tok-en-1",))
    (fake.tmp / "pg.log").write_text(
        "2026-10-16 10:00:05.010 UTC [57] LOG:  connection authorized: user=reader "
        "database=postgres application_name=app\n"
        "2026-10-16 10:00:05.020 UTC [57] LOG:  statement: SELECT 'tok-en-1'\n"
    )
    with running:
        monkeypatch.setenv("FAKE_NET_PG_LOG", str(fake.tmp / "pg.log"))
    assert running.report.helpers["postgres"]["statements"][0]["statement"] == "SELECT '********'"


def test_the_passwords_are_nowhere_in_the_report_the_files_or_the_output(fake, monkeypatch, capsys):
    """Not even where PostgreSQL itself wrote them: its log is cleaned with ``scrub``."""
    running = _network(fake, "postgres")
    superuser = running._postgres_password
    (fake.tmp / "pg.log").write_text(
        "2026-10-16 10:00:05.010 UTC [57] LOG:  connection authorized: "
        f"user=reader database=postgres application_name=app-{READER_PASSWORD}\n"
        "2026-10-16 10:00:05.020 UTC [57] LOG:  statement: "
        f"ALTER ROLE postgres PASSWORD '{superuser}' -- {READER_PASSWORD}\n"
        f"not a log line {superuser}\n"
    )
    with running:
        monkeypatch.setenv("FAKE_NET_PG_LOG", str(fake.tmp / "pg.log"))
        running.server_command("img", ["{postgres_url}"])
    report = json.dumps(running.report.as_dict())
    shown = capsys.readouterr()
    helper = running.report.helpers["postgres"]
    assert helper["sessions"] == [
        {"user": "reader", "database": "postgres", "application": "app-" + "*" * 32}
    ]
    assert helper["statements"][0]["statement"].count("*") == len(superuser) + 32
    assert len(running.report.problems) == 1 and superuser not in running.report.problems[0]
    for secret in running.secrets:
        assert secret not in report
        assert secret not in shown.out + shown.err
        assert not any(secret in p.read_text() for p in (fake.tmp / "out").glob("*"))


def test_the_probe_script_is_standard_library_only_and_compiles():
    compile(net.STAGE_B_PROBE_SCRIPT, "probe", "exec")
    imports = set(re.findall(r"^import (\w+)$", net.STAGE_B_PROBE_SCRIPT, re.MULTILINE))
    assert imports <= {"json", "socket", "struct", "sys"}


def test_the_left_commands_ask_by_the_label():
    commands = net.left_commands("docker", NONCE)
    assert set(commands) == {"containers", "volumes", "networks"}
    for command in commands.values():
        assert f"label=mcp-kymograph.bench={NONCE}" in command
    assert commands["containers"][1:3] == ["ps", "-a"]


def test_hardening_without_dns_differs_in_those_two_options_only():
    with_dns = bench._hardening()
    without = bench._hardening(dns=False)
    assert "--dns" in with_dns and "--dns-search" in with_dns
    assert "--dns" not in without and "--dns-search" not in without
    assert len(with_dns) - len(without) == 4
    kept = list(with_dns)
    for option in ("--dns", "--dns-search"):
        del kept[kept.index(option) : kept.index(option) + 2]
    assert kept == without


# -- the run, with a docker that is not one ------------------------------------------------


@pytest.fixture
def fake(tmp_path, monkeypatch):
    """A ``docker`` program that is the fake, with its state in a directory of this test."""
    program = tmp_path / "docker"
    program.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_NET_DOCKER}" "$@"\n')
    program.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    nft = tmp_path / "nft.json"
    nft.write_text(PROBED)
    context, _ = bench.HELPER_IMAGES[net.NFT_IMAGE]
    digest, _ = bench.context_digest(context)
    monkeypatch.setenv("FAKE_NET_STATE", str(state))
    monkeypatch.setenv("FAKE_NET_NFT", str(nft))
    monkeypatch.setenv("FAKE_NET_CONTEXT_DIGEST", digest)
    # The helpers' namespaces have counters of their own: quiet unless a test says otherwise.
    fixture_nft = tmp_path / "nft-fixsrv.json"
    postgres_nft = tmp_path / "nft-pg.json"
    fixture_nft.write_text(nft_json())
    postgres_nft.write_text(nft_json())
    monkeypatch.setenv("FAKE_NET_NFT_FIXSRV", str(fixture_nft))
    monkeypatch.setenv("FAKE_NET_NFT_PG", str(postgres_nft))
    return SimpleNamespace(
        docker=str(program), state=state, nft=nft, tmp=tmp_path,
        fixture_nft=fixture_nft, postgres_nft=postgres_nft,
    )  # fmt: skip


READER_PASSWORD = "r" * 32


def _network(fake, kind="page", **options):
    password = READER_PASSWORD if kind == "postgres" else None
    fixture = fixtures.build(kind, fixtures.new_canary("t"), reader_password=password)
    out = fake.tmp / "out"
    options.setdefault("reader_password", password)
    return net.StageBNetwork(kind, fixture, POSTGRES, fake.docker, out, nonce=NONCE, **options)


def _left(fake) -> dict:
    return json.loads((fake.state / "state.json").read_text())


def _steps(fake) -> int:
    return int((fake.state / "steps").read_text())


def _calls(fake) -> list[list[str]]:
    lines = (fake.state / "calls.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


def test_a_run_builds_the_network_and_removes_it(fake):
    with _network(fake) as running:
        state = _left(fake)
        assert set(state["networks"]) == {f"mcpb-netb-{NONCE}"}
        assert set(state["volumes"]) == {f"mcpb-fix-{NONCE}"}
        assert set(state["containers"]) == {f"mcpb-fixsrv-{NONCE}", f"mcpb-hold-{NONCE}"}
        assert running.report is None
        assert running.resolv_path.read_text() == net.resolv_conf(running.addresses)
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}
    report = running.report
    assert report.left_after_run == {"containers": [], "volumes": [], "networks": []}
    assert report.probe["counting_works"] is True
    assert report.network["internal"] is True
    assert report.addresses["fixture"].endswith(".10")
    assert report.images["python"]["id"].startswith("sha256:")
    assert report.images["nft"]["reference"] == net.NFT_IMAGE
    assert report.sets["refused4"] == []
    assert report.problems == []


def test_a_postgres_run_has_the_database_and_checks_it_is_ready(fake):
    with _network(fake, "postgres") as running:
        assert f"mcpb-pg-{NONCE}" in _left(fake)["containers"]
        assert running.report is None
    assert any(call[:2] == ["exec", f"mcpb-pg-{NONCE}"] for call in _calls(fake))
    assert running.report.images["postgres"]["reference"] == POSTGRES.postgres_image
    assert _left(fake)["containers"] == {}


def test_postgres_needs_its_image_by_digest(fake):
    fixture = fixtures.build("postgres", fixtures.new_canary("t"), reader_password=READER_PASSWORD)
    for definition in (None, SimpleNamespace(postgres_image="postgres:17"), SimpleNamespace()):
        running = net.StageBNetwork(
            "postgres", fixture, definition, fake.docker, fake.tmp / "out", nonce=NONCE,
            reader_password=READER_PASSWORD,
        )  # fmt: skip
        with pytest.raises(bench.RunnerError, match="digest"), running:
            pass
    assert not any(call[:2] == ["volume", "create"] for call in _calls(fake))


def test_a_kind_without_a_network_gets_the_volume_only(fake):
    with _network(fake, "sqlite") as running:
        state = _left(fake)
        assert set(state["volumes"]) == {f"mcpb-fix-{NONCE}"}
        assert state["networks"] == {} and state["containers"] == {}
        command = running.server_command("img", ["--db", "/srv/fixtures/kanarie.db"])
        assert _pairs(command, "--network") == ["none"]
    assert running.report.network is None
    assert running.report.left_after_run == {"containers": [], "volumes": [], "networks": []}
    assert _left(fake)["volumes"] == {}
    assert not any(call[:2] == ["run", "-d"] for call in _calls(fake))


def test_the_report_is_the_difference_to_the_baseline(fake, monkeypatch):
    with _network(fake) as running:
        fake.nft.write_text(
            nft_json(
                refused4=[(["192.0.2.1", "tcp", 9], 1), (["1.1.1.1", "tcp", 443], 1)],
                allowed=[(["10.201.7.10", "udp", 53], 4), (["10.201.7.10", "tcp", 8080], 3)],
                resolver=1,
            )
        )
        (fake.tmp / "log").write_text(f"{DNS}\n{HTTP}\n")
        monkeypatch.setenv("FAKE_NET_LOG", str(fake.tmp / "log"))
    report = running.report
    assert report.sets["refused4"] == [
        {"target": "1.1.1.1", "protocol": "tcp", "port": 443, "count": 1}
    ]
    assert report.sets["allowed"] == [
        {"target": "10.201.7.10", "protocol": "tcp", "port": 8080, "count": 2}
    ]
    assert report.counters == {"resolver": 1, "other": 0, "input_dropped": 0, "overflow": 0}
    # The baseline was taken with the log as it was then: its events are not the run's.
    assert [q["name"] for q in report.dns_questions] == ["example.com"]
    assert report.dns_questions[0]["rcode"] == "NXDOMAIN"
    assert [r["path"] for r in report.http_requests] == ["/canary.html"]


def test_the_report_has_the_loopback_of_the_holder_apart_from_the_sets_of_refused_targets(fake):
    with _network(fake) as running:
        fake.nft.write_text(
            nft_json(
                refused4=[(["192.0.2.1", "tcp", 9], 1)],
                allowed=[(["10.201.7.10", "udp", 53], 4), (["10.201.7.10", "tcp", 8080], 1)],
                local4=[(["10.201.7.20", "tcp", 8080], 2), (["127.0.0.2", "udp", 53], 1)],
            )
        )
    assert running.report.local == [
        {"target": "10.201.7.20", "protocol": "tcp", "port": 8080, "count": 2},
        {"target": "127.0.0.2", "protocol": "udp", "port": 53, "count": 1},
    ]
    assert "local4" not in running.report.sets
    assert running.report.as_dict()["local"] == running.report.local
    assert running.report.problems == []


def test_a_quiet_run_has_no_loopback_and_nothing_dropped(fake):
    with _network(fake) as running:
        pass
    assert running.report.local == []
    assert running.report.dropped == {"http": 0, "dns": 0}
    assert running.report.as_dict()["dropped"] == {"http": 0, "dns": 0}


def test_what_the_fixture_server_dropped_is_in_the_report_with_a_problem(fake, monkeypatch):
    with _network(fake) as running:
        (fake.tmp / "log").write_text(
            f"{DNS}\n{_dropped(0, 1000)}\n{HTTP}\n{_dropped(1000, 2000)}\n"
        )
        monkeypatch.setenv("FAKE_NET_LOG", str(fake.tmp / "log"))
    assert running.report.dropped == {"http": 1000, "dns": 2000}
    (problem,) = running.report.problems
    assert "dropped" in problem and "1000 requests" in problem and "2000 questions" in problem
    assert [q["name"] for q in running.report.dns_questions] == ["example.com"]


def test_a_dropped_line_with_no_count_is_said_and_not_made_up(fake, monkeypatch):
    with _network(fake) as running:
        (fake.tmp / "log").write_text(f"{_dropped('many', 5)}\n")
        monkeypatch.setenv("FAKE_NET_LOG", str(fake.tmp / "log"))
    assert running.report.dropped == {"http": None, "dns": 5}
    assert len(running.report.problems) == 1


def test_the_report_lists_at_most_2000_requests_and_2000_questions(fake, monkeypatch):
    more = net.REPORT_EVENT_LIMIT + 5
    with _network(fake) as running:
        lines = [DNS] * more + [HTTP] * more
        (fake.tmp / "log").write_text("\n".join(lines) + "\n")
        monkeypatch.setenv("FAKE_NET_LOG", str(fake.tmp / "log"))
    assert net.REPORT_EVENT_LIMIT == 2000
    assert len(running.report.dns_questions) == len(running.report.http_requests) == 2000
    assert sorted(running.report.problems) == [
        f"dns_questions: {more} in the log, the first 2000 listed",
        f"http_requests: {more} in the log, the first 2000 listed",
    ]


def test_a_probe_that_finds_a_check_false_stops_the_run_and_cleans_up(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_PROBE", "fail")
    with pytest.raises(bench.RunnerError, match="external_connect_fails"), _network(fake):
        pytest.fail("the body must not run")
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}


def test_each_step_that_earns_a_second_attempt_says_so_by_its_exception(fake, monkeypatch):
    """Filling, readiness and the probe raise SetupFailure with their cause; the runner tries
    once more on exactly these."""
    monkeypatch.setenv("FAKE_NET_PROBE", "fail")
    with pytest.raises(net.SetupFailure) as probe, _network(fake):
        pytest.fail("the body must not run")
    assert probe.value.cause == "network_probe_failed"
    monkeypatch.delenv("FAKE_NET_PROBE")
    (fake.state / "steps").unlink()  # the fake counts its steps per test; start again
    monkeypatch.setenv("FAKE_NET_FAIL_AT", "2")  # 1 is volume create, 2 the fill
    with pytest.raises(net.SetupFailure) as fill, _network(fake, kind="file"):
        pytest.fail("the body must not run")
    assert fill.value.cause == "fixture_fill_failed"
    monkeypatch.delenv("FAKE_NET_FAIL_AT")
    monkeypatch.setattr(net, "READY_SECONDS", 0.2)
    monkeypatch.setattr(net.StageBNetwork, "_read_log", lambda self: net.FixtureLog((), ()))
    with pytest.raises(net.SetupFailure) as ready, _network(fake):
        pytest.fail("the body must not run")
    assert ready.value.cause == "fixture_not_ready"
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}


def test_a_failure_of_the_set_up_that_is_not_one_of_those_is_no_setup_failure(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_FAIL_AT", "1")  # docker volume create
    with pytest.raises(bench.RunnerError) as failed, _network(fake, kind="file"):
        pytest.fail("the body must not run")
    assert not isinstance(failed.value, net.SetupFailure)


def test_counting_that_does_not_show_the_probes_attempt_stops_the_run(fake):
    fake.nft.write_text(nft_json())
    with pytest.raises(bench.RunnerError, match="counting_works"), _network(fake):
        pytest.fail("the body must not run")
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}


def test_an_image_built_from_another_context_is_refused_before_anything_is_made(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_CONTEXT_DIGEST", "0" * 64)
    with pytest.raises(bench.RunnerError, match="build-helpers"), _network(fake):
        pass
    assert not any(call[:2] == ["volume", "create"] for call in _calls(fake))


def test_a_subnet_that_overlaps_is_chosen_again_up_to_five_times(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_OVERLAP", "5")
    with _network(fake):
        pass
    creates = [c for c in _calls(fake) if c[:2] == ["network", "create"]]
    assert len(creates) == 6
    assert len({tuple(c) for c in creates}) > 1


class _SameOrder(random.Random):
    """An rng that shuffles the same way every time: without ``avoid`` it picks one subnet."""

    def shuffle(self, x):  # noqa: ANN001, ANN201
        x.sort()


def test_each_new_try_after_an_overlap_is_another_subnet(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_OVERLAP", "5")
    with _network(fake, rng=_SameOrder()):
        pass
    creates = [c for c in _calls(fake) if c[:2] == ["network", "create"]]
    subnets = [c[c.index("--subnet") + 1] for c in creates]
    assert len(subnets) == 6 and len(set(subnets)) == 6


def test_a_sixth_overlap_ends_the_run(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_OVERLAP", "6")
    with pytest.raises(bench.RunnerError, match="overlapped"), _network(fake):
        pass
    assert _left(fake)["volumes"] == {}


@pytest.mark.parametrize("kind", ["page", "postgres", "file"])
def test_whatever_step_fails_everything_is_removed(fake, monkeypatch, kind):
    # A clean run first, to know how many steps there are.
    with _network(fake, kind):
        pass
    total = _steps(fake)
    assert total >= 2
    raised = 0
    for step in range(1, total + 1):
        (fake.state / "steps").unlink()
        (fake.state / "calls.jsonl").unlink()
        monkeypatch.setenv("FAKE_NET_FAIL_AT", str(step))
        try:
            with _network(fake, kind):
                pass
        except bench.RunnerError:
            raised += 1
        assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}, (kind, step)
    # The one step that may fail without ending the run is PostgreSQL's readiness: it is asked
    # again until its time is up.
    assert raised >= total - 1


def test_an_error_in_the_body_removes_everything(fake):
    class Boom(Exception):
        pass

    with pytest.raises(Boom), _network(fake) as running:
        assert _left(fake)["containers"]
        raise Boom
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}
    assert running.report.left_after_run["containers"] == []


ATTEMPTED = nft_json(
    refused4=[(["192.0.2.1", "tcp", 9], 1), (["1.1.1.1", "tcp", 443], 1)],
    allowed=[(["10.201.7.10", "udp", 53], 4), (["10.201.7.10", "tcp", 8080], 1)],
)


def test_what_was_tried_before_an_error_in_the_body_is_in_the_report(fake, monkeypatch):
    """A server that makes the run fail (a timeout, Ctrl-C) must not make its attempts vanish."""

    class Boom(Exception):
        pass

    with pytest.raises(Boom), _network(fake) as running:
        fake.nft.write_text(ATTEMPTED)
        (fake.tmp / "log").write_text(f"{DNS}\n{HTTP}\n")
        monkeypatch.setenv("FAKE_NET_LOG", str(fake.tmp / "log"))
        raise Boom
    report = running.report
    assert report.sets["refused4"] == [
        {"target": "1.1.1.1", "protocol": "tcp", "port": 443, "count": 1}
    ]
    assert [q["name"] for q in report.dns_questions] == ["example.com"]
    assert [r["path"] for r in report.http_requests] == ["/canary.html"]
    assert report.problems == []
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}


@pytest.mark.parametrize(
    ("after", "said"), [(1, "counters not read"), (2, "fixture server log not read")]
)
def test_what_could_not_be_read_after_an_error_is_said_in_the_problems(
    fake, monkeypatch, after, said
):
    class Boom(Exception):
        pass

    with pytest.raises(Boom), _network(fake) as running:
        monkeypatch.setenv("FAKE_NET_FAIL_AT", str(_steps(fake) + after))
        raise Boom
    (problem,) = running.report.problems
    assert problem.startswith(said) and "fake failure" in problem
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}


def test_a_report_is_never_empty_without_saying_why(fake, monkeypatch):
    """Neither read: two problems, the counts and the log both named."""

    class Boom(Exception):
        pass

    def broken():
        raise bench.RunnerError("no log")

    with pytest.raises(Boom), _network(fake) as running:
        monkeypatch.setenv("FAKE_NET_FAIL_AT", str(_steps(fake) + 1))
        monkeypatch.setattr(running, "_read_log", broken)
        raise Boom
    assert [p.split(" not read")[0] for p in running.report.problems] == [
        "counters",
        "fixture server log",
    ]


def _overflowed(packets: int) -> str:
    """What nft prints after the probe's baseline and ``packets`` attempts the sets did not take."""
    return nft_json(
        refused4=[(["192.0.2.1", "tcp", 9], 1)],
        allowed=[(["10.201.7.10", "udp", 53], 4), (["10.201.7.10", "tcp", 8080], 1)],
        overflow=packets,
    )


def test_a_run_that_overflowed_a_set_says_so_in_the_problems(fake):
    with _network(fake) as running:
        fake.nft.write_text(_overflowed(3))
    assert running.report.counters["overflow"] == 3
    assert running.report.problems == [
        "more than 4096 distinct targets; the rest counted without target"
    ]
    fake.nft.write_text(PROBED)
    with _network(fake, set_size=2) as small:
        fake.nft.write_text(_overflowed(1))
    assert small.report.problems == [
        "more than 2 distinct targets; the rest counted without target"
    ]


def test_the_ruleset_is_loaded_with_the_size_that_was_asked_for(fake, monkeypatch):
    sizes = []
    real = net.nft_ruleset
    monkeypatch.setattr(net, "nft_ruleset", lambda *a: sizes.append(a[2:]) or real(*a))
    with _network(fake):
        pass
    with _network(fake, set_size=2):
        pass
    assert sizes == [(net.SET_SIZE,), (2,)]


def _loads(fake) -> dict[str, int]:
    """Where in the calls each namespace got its rules (``nft -f -``), and the holder was made."""
    found: dict[str, int] = {}
    for index, call in enumerate(_calls(fake)):
        if call[:2] == ["run", "-i"] and "-f" in call:
            found[_pairs(call, "--network")[0].removeprefix("container:")] = index
        if call[:2] == ["run", "-d"] and f"mcpb-hold-{NONCE}" in call:
            found["holder-made"] = index
    return found


@pytest.mark.parametrize(("kind", "roles"), [("page", ["fixsrv"]), ("postgres", ["fixsrv", "pg"])])
def test_each_helper_gets_its_rules_in_its_own_namespace_before_the_holder_exists(
    fake, kind, roles
):
    with _network(fake, kind):
        pass
    loads = _loads(fake)
    holder_made = loads.pop("holder-made")
    expected = {f"mcpb-{role}-{NONCE}" for role in roles}
    assert set(loads) == {*expected, f"mcpb-hold-{NONCE}"}
    for name in expected:
        assert loads[name] < holder_made, name
    assert loads[f"mcpb-hold-{NONCE}"] > holder_made
    fixture_rules = (fake.state / f"rules-mcpb-fixsrv-{NONCE}.nft").read_text()
    assert fixture_rules == net.helper_ruleset("fixture", _addresses_of(fake))
    if kind == "postgres":
        postgres_rules = (fake.state / f"rules-mcpb-pg-{NONCE}.nft").read_text()
        assert postgres_rules == net.helper_ruleset("postgres", _addresses_of(fake))
    else:
        assert not (fake.state / f"rules-mcpb-pg-{NONCE}.nft").exists()


def _addresses_of(fake) -> net.Addresses:
    """The addresses of the run that just ended, from the network the fake was asked for."""
    create = next(c for c in _calls(fake) if c[:3] == ["network", "create", "--internal"])
    return net.Addresses(ipaddress.IPv4Network(_pairs(create, "--subnet")[0]))


def test_each_helper_namespace_also_gets_the_default_route_that_makes_attempts_visible(fake):
    with _network(fake, "postgres"):
        pass
    routes = [c for c in _calls(fake) if c[-5:] == list(net.ROUTE_ARGS)]
    namespaces = {_pairs(c, "--network")[0] for c in routes}
    assert namespaces == {f"container:mcpb-{n}-{NONCE}" for n in ("fixsrv", "pg", "hold")}


@pytest.mark.parametrize("part", ["fixsrv", "pg"])
def test_rules_that_do_not_load_into_a_helper_end_the_run_and_are_no_second_attempt(
    fake, monkeypatch, part
):
    monkeypatch.setenv("FAKE_NET_NFT_LOAD_FAIL", part)
    with (
        pytest.raises(bench.RunnerError, match="loading the counting rules") as failure,
        _network(fake, "postgres"),
    ):
        pytest.fail("the body must not run")
    assert not isinstance(failure.value, net.SetupFailure)
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}
    # The holder was never made: the helpers' rules come first.
    assert "holder-made" not in _loads(fake)


def test_the_report_has_what_each_helper_tried_since_the_baseline(fake):
    with _network(fake, "postgres") as running:
        fake.fixture_nft.write_text(
            nft_json(
                refused4=[(["1.1.1.1", "tcp", 443], 2)],
                other=1,
                overflow=3,
                resolver=2,
                local4=[(["10.201.7.20", "tcp", 8080], 4)],
            )  # fmt: skip
        )
        fake.postgres_nft.write_text(nft_json(refused4=[(["10.201.7.20", "udp", 53], 1)]))
    helpers = running.report.helpers
    assert set(helpers) == {"fixture", "postgres"}
    assert helpers["fixture"]["sets"] == {
        "refused4": [{"target": "1.1.1.1", "protocol": "tcp", "port": 443, "count": 2}],
        "refused6": [],
    }
    assert helpers["fixture"]["local"] == [
        {"target": "10.201.7.20", "protocol": "tcp", "port": 8080, "count": 4}
    ]
    assert helpers["fixture"]["counters"] == {
        "resolver": 2, "other": 1, "input_dropped": 0, "overflow": 3,
    }  # fmt: skip
    assert helpers["postgres"]["sets"]["refused4"] == [
        {"target": "10.201.7.20", "protocol": "udp", "port": 53, "count": 1}
    ]
    assert helpers["postgres"]["local"] == []
    assert helpers["postgres"]["counters"] == {
        "resolver": 0, "other": 0, "input_dropped": 0, "overflow": 0,
    }  # fmt: skip
    assert "fixture: more than 4096 distinct targets; the rest counted without target" in (
        running.report.problems
    )
    # The holder's own counters are the holder's, and the fixture server keeps its own lists.
    assert running.report.sets["refused4"] == []


def test_a_quiet_helper_says_so_with_zeros_and_empty_lists(fake):
    with _network(fake, "page") as running:
        pass
    assert running.report.helpers == {
        "fixture": {
            "sets": {"refused4": [], "refused6": []},
            "local": [],
            "counters": {"resolver": 0, "other": 0, "input_dropped": 0, "overflow": 0},
        }
    }
    assert running.report.problems == []
    assert json.loads(json.dumps(running.report.as_dict()))["helpers"] == running.report.helpers


def test_what_a_helper_counted_before_the_baseline_is_not_the_runs(fake):
    """The probe and the rules' own set-up are before the baseline: a helper that had refused
    something then shows only what came after."""
    before = nft_json(refused4=[(["1.1.1.1", "tcp", 443], 1)], input_dropped=2)
    fake.fixture_nft.write_text(before)
    with _network(fake, "page") as running:
        fake.fixture_nft.write_text(
            nft_json(refused4=[(["1.1.1.1", "tcp", 443], 4)], input_dropped=2)
        )
    entry = running.report.helpers["fixture"]
    assert entry["sets"]["refused4"][0]["count"] == 3
    assert entry["counters"]["input_dropped"] == 0


def test_the_failed_logins_of_postgres_are_in_the_report(fake, monkeypatch):
    monkeypatch.setattr(net, "choose_subnet", lambda *args: ADDRESSES.subnet)  # PG_FAILED's own
    (fake.tmp / "pg.log").write_text(PG_FAILED)
    monkeypatch.setenv("FAKE_NET_PG_LOG", str(fake.tmp / "pg.log"))
    monkeypatch.setenv("FAKE_NET_PG_LOG_AFTER_SERVER", "1")
    with _network(fake, "postgres") as running:
        (fake.state / "server-started").write_text("1")
    pg = running.report.helpers["postgres"]
    assert pg["failed_logins"] == FAILED
    assert json.loads(json.dumps(running.report.as_dict()))["helpers"]["postgres"] == pg


def test_a_postgres_without_a_failed_login_says_so_with_an_empty_list(fake):
    with _network(fake, "postgres") as running:
        pass
    assert running.report.helpers["postgres"]["failed_logins"] == []


def test_the_sessions_and_statements_of_postgres_are_those_after_the_baseline(fake, monkeypatch):
    monkeypatch.setattr(net, "choose_subnet", lambda *args: ADDRESSES.subnet)  # PG_LOG's own
    (fake.tmp / "pg.log").write_text(PG_LOG)
    monkeypatch.setenv("FAKE_NET_PG_LOG", str(fake.tmp / "pg.log"))
    monkeypatch.setenv("FAKE_NET_PG_LOG_AFTER_SERVER", "1")
    with _network(fake, "postgres") as running:
        # Before the server is started the log has nothing (it is the baseline); once it is,
        # the lines are there.
        (fake.state / "server-started").write_text("1")
    pg = running.report.helpers["postgres"]
    assert pg["sessions"] == [{"user": "reader", "database": "postgres", "application": "psql"}]
    assert [s["statement"] for s in pg["statements"]] == [
        "SELECT note FROM kanarie",
        "SELECT a,\nb FROM kanarie",
        "SELECT $1",
    ]
    assert running.report.problems == []


def test_a_postgres_log_that_was_there_at_the_baseline_is_not_the_runs(fake, monkeypatch):
    (fake.tmp / "pg.log").write_text(PG_LOG)
    monkeypatch.setenv("FAKE_NET_PG_LOG", str(fake.tmp / "pg.log"))
    with _network(fake, "postgres") as running:
        pass
    assert running.report.helpers["postgres"]["sessions"] == []
    assert running.report.helpers["postgres"]["statements"] == []


def test_postgres_is_started_with_its_log_on_and_the_log_is_read_at_baseline_and_end(fake):
    with _network(fake, "postgres"):
        pass
    reads = [c for c in _calls(fake) if c[:2] == ["logs", f"mcpb-pg-{NONCE}"]]
    assert len(reads) == 2
    started = next(c for c in _calls(fake) if c[:2] == ["run", "-d"] and f"mcpb-pg-{NONCE}" in c)
    assert started[-6:] == [
        "-c", "log_connections=on", "-c", "log_disconnections=on", "-c", "log_statement=all"
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("what", "said"),
    [("counters of the fixture", "counters of the fixture not read"), ("log", "PostgreSQL log")],
)
def test_what_a_helper_could_not_say_after_an_error_is_in_the_problems(
    fake, monkeypatch, what, said
):
    class Boom(Exception):
        pass

    def broken(*args, **kwargs):
        raise bench.RunnerError("no way")

    with pytest.raises(Boom), _network(fake, "postgres") as running:
        if what == "log":
            monkeypatch.setattr(running, "_read_pg_log", broken)
        else:
            monkeypatch.setattr(
                running,
                "_read_helper_counts",
                lambda only=None: broken() if only == "fixture" else {},
            )
        raise Boom
    problems = [p for p in running.report.problems if p.startswith(said.split(" not")[0])]
    assert len(problems) == 1 and "no way" in problems[0]
    assert _left(fake) == {"containers": {}, "volumes": {}, "networks": {}}


def test_the_readme_names_the_limit_of_ipv6_under_the_known_limits():
    readme = (RUNNER.parent / "README.md").read_text(encoding="utf-8")
    limits = readme.split("## Known limits")[1].split("\n## ")[0]
    assert net.IPV6_LIMIT in " ".join(limits.split())


def test_the_readme_says_what_the_helpers_may_do_and_what_the_report_shows_of_them():
    readme = " ".join((RUNNER.parent / "README.md").read_text(encoding="utf-8").split())
    section = readme.split("**The helper containers are part of the trust boundary.**")[1]
    section = section.split("```sh")[0]
    for word in (
        "{postgres_url}", "999:999", "no capability", "TCP 8080 and UDP 53", "TCP 5432",
        "`helpers`", "`sessions`, `statements` and `failed_logins`", "`overflow`",
        "before the holder exists", "127.0.0.11", "`local`", "`resolver`", "`dropped`",
        "at most 2000", "at most 8 MB",
    ):  # fmt: skip
        assert word in section, word


def test_the_readme_says_which_forms_of_the_id_are_taken_out_and_that_others_may_stay():
    readme = " ".join((RUNNER.parent / "README.md").read_text(encoding="utf-8").split())
    stage = readme.split("## Stage B")[1].split("## Known limits")[0]
    for word in (
        "NFKC", "`%XX` written out", "read backwards", "base64", "the whole exported tree",
        "every value of `server.env` of four characters or more",
        "below its directory", "refuses a place git would track",
    ):  # fmt: skip
        assert word in stage or word in readme, word
    limits = readme.split("## Known limits")[1].split("\n## ")[0]
    assert "not recognised and can stay in the companion" in limits


def test_the_report_names_the_limit_of_ipv6():
    report = net.NetworkReport("page", NONCE, None, None, {}, None)
    assert report.limits == [net.IPV6_LIMIT]
    assert report.as_dict()["limits"] == [net.IPV6_LIMIT]
    assert "no IPv6 address" in net.IPV6_LIMIT and "not counted" in net.IPV6_LIMIT


def test_the_server_container_is_removed_too(fake):
    with _network(fake) as running:
        command = running.server_command("img", [])
        name = _pairs(command, "--name")[0]
        state = _left(fake)
        state["containers"][name] = f"mcp-kymograph.bench={NONCE}"
        (fake.state / "state.json").write_text(json.dumps(state))
    assert _left(fake)["containers"] == {}


def test_something_left_is_an_error_after_the_removal_and_in_the_report(fake, monkeypatch):
    monkeypatch.setenv("FAKE_NET_KEEP", f"mcpb-hold-{NONCE}")
    network = _network(fake)
    with pytest.raises(bench.RunnerError, match=f"mcpb-hold-{NONCE}"), network:
        pass
    assert network.report.left_after_run["containers"] == [f"mcpb-hold-{NONCE}"]
    assert network.report.left_after_run["volumes"] == []
    # Everything else was removed all the same.
    assert _left(fake)["volumes"] == {} and _left(fake)["networks"] == {}


def test_something_left_does_not_hide_the_error_that_ended_the_run(fake, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_NET_KEEP", f"mcpb-hold-{NONCE}")

    class Boom(Exception):
        pass

    with pytest.raises(Boom), _network(fake):
        raise Boom
    assert f"mcpb-hold-{NONCE}" in capsys.readouterr().err


def test_a_fixture_of_another_kind_is_refused(fake):
    fixture = fixtures.build("file", fixtures.new_canary("t"))
    with pytest.raises(bench.RunnerError, match="kind"):
        net.StageBNetwork("page", fixture, None, fake.docker, fake.tmp, nonce=NONCE)
    with pytest.raises(bench.RunnerError, match="unknown"):
        net.StageBNetwork("nothing", fixture, None, fake.docker, fake.tmp, nonce=NONCE)


def test_the_filling_container_reads_the_archive_from_stdin(fake):
    with _network(fake, "file"):
        pass
    fills = [c for c in _calls(fake) if c[:1] == ["run"] and f"mcpb-fill-{NONCE}-1" in c]
    assert len(fills) == 1
    assert "-i" in fills[0]


# -- build-helpers -------------------------------------------------------------------------


def test_the_nft_image_is_built_from_the_pinned_base_with_nothing_else_added():
    context, base = bench.HELPER_IMAGES[net.NFT_IMAGE]
    text = (context / "Dockerfile").read_text()
    assert bench.dockerfile_refusal(text, base) is None
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert len(lines) == 2
    assert "nftables" in lines[1]
    assert not any(line.startswith(("COPY", "ADD", "ENV", "ENTRYPOINT")) for line in lines)


def test_build_helpers_builds_with_the_context_digest_label(fake, capsys):
    assert bench.main(["build-helpers", "--docker", fake.docker]) == 0
    build = next(c for c in _calls(fake) if c[0] == "build")
    context, _ = bench.HELPER_IMAGES[net.NFT_IMAGE]
    digest, _ = bench.context_digest(context)
    assert f"{bench.CONTEXT_LABEL}={digest}" in build
    assert build[build.index("-t") + 1] == net.NFT_IMAGE
    assert net.NFT_IMAGE in capsys.readouterr().out


# -- the real thing ------------------------------------------------------------------------

ATTEMPTS = """\
import socket
import urllib.request


def attempt(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError:
        pass


urllib.request.urlopen("http://fixture:8080/canary.html", timeout=5).read()
attempt("1.1.1.1", 443)
attempt("192.0.2.7", 80)
# Over loopback: let through, and counted per target (nothing listens there).
attempt("127.0.0.1", 9)
attempt("127.0.0.2", 9)
try:
    socket.getaddrinfo("example.com", 80)
except OSError:
    pass
# Past the resolv.conf, straight to docker's own resolver: one datagram, rejected and counted.
resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
resolver.settimeout(2)
try:
    query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    resolver.sendto(query, ("127.0.0.11", 53))
    resolver.recvfrom(512)
except OSError:
    pass
"""


@pytest.mark.docker
def test_docker_counts_the_attempts_of_a_container_in_the_namespace(tmp_path):
    docker = "docker"
    context, _ = bench.HELPER_IMAGES[net.NFT_IMAGE]
    inspected = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", net.NFT_IMAGE], capture_output=True, check=False
    )
    if inspected.returncode != 0:
        pytest.skip(f"no {net.NFT_IMAGE}; run bench.py build-helpers")
    fixture = fixtures.build("page", fixtures.new_canary("t"))
    running = net.StageBNetwork("page", fixture, None, docker, tmp_path)
    with running:
        assert running._probe is not None
        assert all(running._probe[name] is True for name in net.PROBE_CHECKS)
        command = running.server_command(bench.PYTHON_IMAGE, ["python", "-B", "-c", ATTEMPTS])
        done = subprocess.run(  # noqa: S603
            command, input=b"", capture_output=True, check=False, timeout=120
        )
        assert done.returncode == 0, done.stderr.decode()
    report = running.report
    refused = {(e["target"], e["protocol"], e["port"]) for e in report.sets["refused4"]}
    assert refused == {("1.1.1.1", "tcp", 443), ("192.0.2.7", "tcp", 80)}
    local = {(e["target"], e["protocol"], e["port"]) for e in report.local}
    assert local == {("127.0.0.1", "tcp", 9), ("127.0.0.2", "tcp", 9)}
    allowed = {(e["target"], e["protocol"], e["port"]) for e in report.sets["allowed"]}
    fixture_address = report.addresses["fixture"]
    assert allowed == {(fixture_address, "tcp", 8080), (fixture_address, "udp", 53)}
    asked = [q for q in report.dns_questions if q["name"] == "example.com"]
    assert asked
    assert {q["rcode"] for q in asked} == {"NXDOMAIN"}
    assert [r["path"] for r in report.http_requests] == ["/canary.html"]
    assert report.counters["resolver"] == 1
    assert report.problems == []
    assert report.left_after_run == {"containers": [], "volumes": [], "networks": []}
    listed = subprocess.run(  # noqa: S603
        [docker, "ps", "-a", "-q", "--filter", f"label=mcp-kymograph.bench={running.nonce}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert listed.stdout.strip() == ""


OVERFLOWING = """\
import socket

for host, port in (("1.1.1.1", 443), ("192.0.2.7", 80), ("192.0.2.8", 80)):
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError:
        pass
"""


@pytest.mark.docker
def test_docker_counts_the_attempts_a_full_set_does_not_take_as_overflow(tmp_path):
    """A set of two holds the probe's target and one more: of three targets the first fits, the
    other two are rejected all the same (one packet each) and counted in ``overflow``."""
    docker = "docker"
    inspected = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", net.NFT_IMAGE], capture_output=True, check=False
    )
    if inspected.returncode != 0:
        pytest.skip(f"no {net.NFT_IMAGE}; run bench.py build-helpers")
    fixture = fixtures.build("page", fixtures.new_canary("t"))
    running = net.StageBNetwork("page", fixture, None, docker, tmp_path, set_size=2)
    with running:
        command = running.server_command(bench.PYTHON_IMAGE, ["python", "-B", "-c", OVERFLOWING])
        done = subprocess.run(  # noqa: S603
            command, input=b"", capture_output=True, check=False, timeout=120
        )
        assert done.returncode == 0, done.stderr.decode()
    report = running.report
    assert [(e["target"], e["port"]) for e in report.sets["refused4"]] == [("1.1.1.1", 443)]
    assert report.counters["overflow"] == 2
    assert report.counters["other"] == 0
    assert report.problems == ["more than 2 distinct targets; the rest counted without target"]
    assert report.left_after_run == {"containers": [], "volumes": [], "networks": []}


@pytest.mark.docker
def test_docker_counts_what_a_helper_container_tries_in_its_own_namespace(tmp_path):
    """The fixture server is made to try a connection out (``docker exec`` of a program in it):
    the rules of its namespace refuse it, count it per target, and the report has it under
    ``helpers``. The holder's sets are unchanged."""
    docker = "docker"
    inspected = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", net.NFT_IMAGE], capture_output=True, check=False
    )
    if inspected.returncode != 0:
        pytest.skip(f"no {net.NFT_IMAGE}; run bench.py build-helpers")
    fixture = fixtures.build("page", fixtures.new_canary("t"))
    running = net.StageBNetwork("page", fixture, None, docker, tmp_path)
    with running:
        trying = (
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 443), timeout=3).close()\n"
            "except OSError as error:\n"
            "    print(type(error).__name__)\n"
            # Docker's resolver is rejected and counted here as in the holder; loopback is let
            # through and counted per target.
            "udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "udp.settimeout(2)\n"
            "try:\n"
            "    udp.sendto(b'x', ('127.0.0.11', 53))\n"
            "    udp.recvfrom(512)\n"
            "except OSError:\n"
            "    pass\n"
            "try:\n"
            "    socket.create_connection(('127.0.0.1', 9), timeout=3).close()\n"
            "except OSError:\n"
            "    pass\n"
        )
        done = subprocess.run(  # noqa: S603
            [docker, "exec", running.helper_names["fixture"], "python", "-B", "-c", trying],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "ConnectionRefusedError"  # rejected, not waited out
    report = running.report
    refused = report.helpers["fixture"]["sets"]["refused4"]
    assert [(e["target"], e["protocol"], e["port"], e["count"]) for e in refused] == [
        ("1.1.1.1", "tcp", 443, 1)
    ]
    assert report.helpers["fixture"]["counters"] == {
        "resolver": 1, "other": 0, "input_dropped": 0, "overflow": 0,
    }  # fmt: skip
    assert [
        (e["target"], e["protocol"], e["port"], e["count"])
        for e in report.helpers["fixture"]["local"]
    ] == [("127.0.0.1", "tcp", 9, 1)]
    assert report.sets["refused4"] == []
    assert report.problems == []
    assert report.left_after_run == {"containers": [], "volumes": [], "networks": []}


POSTGRES_IMAGE_VARIABLE = "MCPB_TEST_POSTGRES_IMAGE"
#: The PostgreSQL the benchmark's definitions pin; ``$MCPB_TEST_POSTGRES_IMAGE`` may name another.
POSTGRES_IMAGE = (
    "postgres:17-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826"
)


@pytest.mark.docker
def test_docker_postgres_takes_the_runs_password_only_and_the_report_shows_the_one_session(
    tmp_path,
):
    """A container in the holder's namespace logs in as ``reader`` with the run's password and
    selects the canary; as ``postgres`` with the old fixed value, and as ``reader`` with it, it
    is turned away. The report has exactly the one session, its statement, the two logins that
    failed, and no attempt of a helper. The image is :data:`POSTGRES_IMAGE` unless
    ``$MCPB_TEST_POSTGRES_IMAGE`` names another by digest; it must be here already. A missing
    image is a skip, as for the other tests of the network, and the suite counts skipped Docker
    tests: no longer skipped for want of a variable."""
    docker = "docker"
    reference = os.environ.get(POSTGRES_IMAGE_VARIABLE) or POSTGRES_IMAGE
    inspected = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", net.NFT_IMAGE, reference], capture_output=True, check=False
    )
    if inspected.returncode != 0:
        pytest.skip(f"no {net.NFT_IMAGE} or no {reference} here")
    password = secrets.token_urlsafe(24)
    canary = fixtures.new_canary("t")
    fixture = fixtures.build("postgres", canary, reader_password=password)
    definition = SimpleNamespace(postgres_image=reference)
    running = net.StageBNetwork(
        "postgres", fixture, definition, docker, tmp_path,
        canary_id=canary.id, reader_password=password,
    )  # fmt: skip
    old = "reader-test-password-not-a-secret"  # the value this module used to hand out
    attempts: dict[str, subprocess.CompletedProcess] = {}
    with running:
        for label, user, secret, query in (
            ("reader", "reader", password, "SELECT note FROM kanarie"),
            ("superuser-old", "postgres", old, "SELECT 1"),
            ("reader-old", "reader", old, "SELECT 1"),
        ):
            url = f"postgresql://{user}:{secret}@postgres:5432/postgres"
            command = running.server_command(reference, ["psql", url, "-tAc", query])
            attempts[label] = subprocess.run(  # noqa: S603
                command, input=b"", capture_output=True, check=False, timeout=120
            )
    assert attempts["reader"].returncode == 0, attempts["reader"].stderr.decode()
    assert canary.id in attempts["reader"].stdout.decode()
    for label in ("superuser-old", "reader-old"):
        assert attempts[label].returncode != 0, label
        assert b"password authentication failed" in attempts[label].stderr, label
    report = running.report
    postgres = report.helpers["postgres"]
    assert postgres["sessions"] == [
        {"user": "reader", "database": "postgres", "application": "psql"}
    ]
    assert [s["statement"] for s in postgres["statements"]] == ["SELECT note FROM kanarie"]
    # The two turned away are in the report too, with their user (the log names no database).
    assert [(f["user"], f["database"]) for f in postgres["failed_logins"]] == [
        ("postgres", None),
        ("reader", None),
    ]
    assert all("password authentication failed" in f["reason"] for f in postgres["failed_logins"])
    assert canary.id not in json.dumps(report.as_dict())
    assert password not in json.dumps(report.as_dict())
    # No attempt of a helper: neither refused out nor dropped in, in either namespace.
    for role in ("fixture", "postgres"):
        assert report.helpers[role]["sets"] == {"refused4": [], "refused6": []}
        assert report.helpers[role]["counters"] == {
            "resolver": 0, "other": 0, "input_dropped": 0, "overflow": 0,
        }  # fmt: skip
    assert report.problems == []
    assert report.left_after_run == {"containers": [], "volumes": [], "networks": []}
