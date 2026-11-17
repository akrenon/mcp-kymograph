"""The rules a run is judged by have a version of their own.

``verdict.RULES_VERSION`` is kept with every run and every fleet the store files, is part of a
fleet's digest, is in the output of ``kymograph verdict``, and a comparison across two versions
says so. The store's schema moves only with its tables.

"Every change to the rules raises the version" is held by a fingerprint: what the rules make of
a fixed set of recordings — the state, the causes and the exit code of each, and the digest of a
fixed fleet — is pinned per version. A rule that changes without the version fails here, and so
does a version raised without the fingerprint of what it judges.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, fleet, verdict
from mcp_kymograph.events import SCHEMA_VERSION
from mcp_kymograph.fleet import FleetRun, Pins, Result
from mcp_kymograph.store import Store
from test_store import recording

#: What the rules made of :func:`cases` and of the fixed fleet, per version. A new version
#: adds its line, and the lines of earlier versions are never edited — they are what the cases
#: of their day were judged to, by the fingerprint of their day. (A case added without a rule
#: change changes only the current line; so did adding the truncations to the fingerprint while
#: 4 was current.)
FINGERPRINTS = {
    3: "sha256:7b22d0bc033e58226d9aa286a9f53e40eb36af040eeac136c954a0a21c698dba",
    4: "sha256:fc21bf84a6a3732c2da2c921cacf096dcb2a7677764e10b6c22b6082ed9c4127",
    5: "sha256:d055b01295c3ac709c77724f2e5d2a9c1340b773b35433f02c07571e5ec89cb5",
    6: "sha256:fab82e310356bfc591415e440f7d97eb1cc61cd35f9099099341f752b45fbff7",
    7: "sha256:9ce787de4e706824ce9962fb469b1b7f98e1ce72ff9499a4f3ae916ca8da2fb5",
    8: "sha256:449e86a9cc9b3aca035aca99b3815db590b8069db324eaabfc741144da3d5628",
    9: "sha256:e90a3e3f549b284d228f210b7a09002fd8003240df0edc3b9ba859b517c0bafe",
    10: "sha256:2c011f750e266f907f2c10666f4f36fd99c9f20e4af2e12825c552eb6a9191df",
    11: "sha256:5e34e11fadb5ec7a2193af5b3285c3c70af99f2107c0063b72478895c6763187",
    12: "sha256:623f1482faa8f0149d1aecdf0622ee75eb96e1993a9b2c8ea4b2aac2350e8f88",
    13: "sha256:fcf361ea37d780d7f7c1e5b3e83d114cc42e975bb208b4f9720c25f9b158686b",
    14: "sha256:91e76690805f5d3b68268bc75fb0ee96b6e9b848e2ffab5e28b24598a9957d28",
}

SPOKE = {"server_output_bytes": 100, "client_input_bytes": 100, "server_exited_first": False}
ENDED = {"type": "script_finished", "inventory": "complete"}
EXITED = {"type": "server_exited", "exit_code": 0, "signal": None}
CLEAN = {"kernel": 9, "sink": 9, "lost": 0, "unseen_destinations": 0}
HTTP_COUNTED = {"exchanges": 3, "responses": {"2xx": 3}, "streams": 0, "events": 0,
                "framing_errors": 0}  # fmt: skip
HTTPS_COUNTED = {**HTTP_COUNTED, "tls": {"versions": ["TLSv1.3"], "certificates": ["ab" * 32]}}


def started(**extra):
    return {"type": "run_started", "mode": "driver", "isolation": "host", **extra}


def finished(counts=None, **extra):
    return {"type": "run_finished", "findings_by_statement": counts or {}, **SPOKE, **extra}


def egress(consistent=True, loss=CLEAN):
    summary = {"type": "egress_summary", "consistent": consistent}
    if loss is not None:
        summary["udp_loss"] = loss
    return summary


def finding(statement="st", signal="imperative"):
    return {"type": "finding", "key": {"statement": statement, "signal": signal}}


def cases() -> list[list]:
    """A recording for every kind of shortfall, and for the ways a run is complete. Raw strings
    are lines as written; dicts are events."""
    runc = started(isolation="runc")
    pinned = started(
        isolation="runc",
        reproduction={"environment": {"sandbox_image": "sha256:a", "target_image": "sha256:b"}},
    )
    images = {
        "type": "sandbox_step",
        "step": "images",
        "ok": True,
        "detail": {"images": {"sandbox": {"id": "sha256:a"}, "target": {"id": "sha256:x"}}},
    }
    rejected = {"type": "step_skipped", "step": "tools/list", "reason": "observation_rejected"}
    observing = started(transport="streamable-http", auth={"observation": "foreign_audience"})
    refusal = {
        "type": "token_observation",
        "kind": "foreign_audience",
        "exchanges": [
            {"method": "server/discover", "accepted": False, "http_status": 401, "rpc_code": None}
        ],
    }
    cut = {
        "type": "findings_capped",
        "message_seq": 4,
        "cap": 20,
        "made": 22,
        "recorded": 20,
        "cut": {"st": {"imperative": 2}},
    }
    return [
        [started(), ENDED, finished()],
        [runc, egress(), ENDED, finished()],
        [runc, egress(loss={"kernel": 9, "sink": 8, "lost": 1, "unseen_destinations": 0}), ENDED,
         finished()],
        [runc, egress(loss=None), ENDED, finished()],
        [runc, egress(consistent=False), ENDED, finished()],
        [runc, ENDED, finished()],
        [started(isolation="moon"), ENDED, finished()],
        [started(isolation="remote"), ENDED, finished()],
        [pinned, images, egress(), ENDED, finished()],
        [started(), {"type": "step_unanswered", "step": "tools/list", "pages": 0,
                     "reason": "no_answer"}, ENDED, finished()],
        [started(), {"type": "step_skipped", "step": "tools/list", "reason": "no_answer"}, ENDED,
         finished()],
        [started(), {"type": "step_skipped", "step": "tools/list", "reason": "answer_unreadable"},
         ENDED, finished()],
        [started(), {"type": "step_skipped", "step": "tools/list", "reason": "page_limit_reached",
                     "detail": 50}, ENDED, finished()],
        [started(), finished()],
        [started(), ENDED],
        [ENDED, finished()],
        [started(), "not json", ENDED, finished()],
        [started(), {"type": "recording_stopped", "from_seq": 3, "reason": "disk full"}, ENDED,
         finished()],
        [started(), ENDED, finished(unwritten_events=2)],
        [started(), ENDED, finished(inspection_bounded=1)],
        [started(), {"type": "message", "direction": "server_to_client",
                     "parse": {"ok": False, "error_reason": "not_utf8"}}, ENDED,
         finished(inspection_bounded=1)],
        [started(), {"type": "message", "direction": "client_to_server",
                     "parse": {"ok": False, "error_reason": "not_utf8"}}, ENDED,
         finished(client_undecodable=1)],
        [started(), ENDED, finished(client_undecodable=1)],
        [started(), ENDED, finished(client_undecodable="1")],
        [started(), {"type": "step_called", "step": "tools/call", "tool": "t", "arguments": {}},
         ENDED, finished()],
        [started(), {"type": "call_failed", "step": "tools/call", "tool": "t", "kind": "rpc_error",
                     "code": -32000}, ENDED, finished()],
        [started(), {"type": "call_failed", "step": "tools/call", "tool": "t", "kind": "tool_error",
                     "code": None}, ENDED, finished()],
        [started(), {"type": "call_failed", "step": "tools/call", "tool": "t", "kind": "x"}, ENDED,
         finished()],
        [started(), {"type": "step_unanswered", "step": "tools/call", "pages": 0,
                     "reason": "answer_unreadable"}, ENDED, finished()],
        [started(), {"type": "step_skipped", "step": "tools/call", "reason": "tool_not_listed"},
         ENDED, finished()],
        [started(transport="streamable-http"), ENDED, finished()],
        [started(), {"type": "step_skipped", "step": "tools/list", "reason": []}, ENDED,
         finished()],
        [started(transport="streamable-http"), ENDED,
         finished(http={"exchanges": "1", "responses": {}, "streams": 0, "events": 0,
                        "framing_errors": 0})],
        [started(transport="streamable-http"), ENDED, finished(http={})],
        [started(transport="streamable-http"),
         {"type": "server_failed", "reason": "http_unreachable"}, ENDED,
         finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "server_failed", "reason": "http_sse_only"}, ENDED,
         finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"), {"type": "step_unanswered", "step": "tools/list",
         "pages": 0, "reason": "http_status"}, ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"), {"type": "step_unanswered", "step": "tools/list",
         "pages": 1, "reason": "session_lost"}, ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"), ENDED, finished(http=HTTPS_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "server_failed", "reason": "tls", "detail": "certificate verify failed"},
         ENDED, finished(http={**HTTP_COUNTED, "tls": None})],
        [started(transport="streamable-http"), {"type": "step_unanswered", "step": "tools/list",
         "pages": 0, "reason": "tls", "detail": "certificate verify failed"}, ENDED,
         finished(http=HTTPS_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "server_failed", "reason": "unauthorized", "detail": "HTTP 401"},
         ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"), {"type": "step_unanswered", "step": "tools/list",
         "pages": 0, "reason": "unauthorized", "detail": "HTTP 403"}, ENDED,
         finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "server_failed", "reason": "protocol_unsupported", "detail": "modern_refused"},
         ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"), {"type": "step_unanswered", "step": "tools/list",
         "pages": 0, "reason": "stream_broken"}, ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "server_failed", "reason": "rate_limited", "detail": "HTTP 429"},
         ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "paced", "seconds": 1.0, "why": "retry_after", "status": 429},
         {"type": "step_unanswered", "step": "tools/list", "pages": 0,
          "reason": "rate_limited"}, ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"),
         {"type": "paced", "seconds": 1.0, "why": "retry_after", "status": 503}, ENDED,
         finished(http=HTTP_COUNTED)],
        [started(), ENDED, {"type": "run_finished", **SPOKE}],
        [started(), ENDED, finished({"st": {"imperative": 2}})],
        [started(), finding(), ENDED, finished()],
        [started(), {"type": "findings_capped"}, ENDED, finished()],
        [started(), *[finding()] * 20, cut, ENDED, finished({"st": {"imperative": 22}})],
        [started(), {"type": "server_failed", "reason": "no_answer"}, ENDED, finished()],
        [started(), EXITED, ENDED, finished(server_output_bytes=0)],
        [started(), EXITED, ENDED,
         finished(server_output_bytes=0, client_input_bytes=0, server_exited_first=True)],
        [started(), ENDED, {"type": "run_finished", "findings_by_statement": {}}],
        [started(mode="proxy"), EXITED,
         finished(server_output_bytes=0, client_input_bytes=0)],
        [started(mode="proxy"), {"type": "server_failed", "reason": "not_started"},
         finished(server_output_bytes=0, client_input_bytes=0)],
        [runc, {"type": "sandbox_failed", "condition": "probe", "phase": "before_target"},
         finished(server_output_bytes=0, client_input_bytes=0)],
        [runc, egress(), {"type": "sandbox_failed", "condition": "record", "phase": "after_target"},
         ENDED, finished()],
        [runc, {"type": "sandbox_failed", "condition": "probe"}, ENDED, finished()],
        [started(mode="proxy"), EXITED, finished()],
        [started(), {"type": "run_stopped", "signal": "SIGINT"}, ENDED, finished()],
        [started(), {"type": "run_stopped", "signal": "SIGTERM"},
         {"type": "server_failed", "reason": "connection_closed"}, EXITED,
         finished(server_output_bytes=0)],
        [started(), {"type": "server_failed", "reason": "no_answer"},
         {"type": "run_stopped", "signal": "SIGINT"}, ENDED, finished()],
        [observing, rejected,
         ENDED, finished(http=HTTP_COUNTED)],
        [started(transport="streamable-http"),
         rejected, ENDED, finished(http=HTTP_COUNTED)],
        [observing, rejected,
         {"type": "step_unanswered", "step": "tools/call", "pages": 0, "reason": "rate_limited"},
         ENDED, finished(http=HTTP_COUNTED)],
        [observing, refusal, rejected,
         ENDED, finished(http=HTTP_COUNTED, server_output_bytes=0)],
        [started(transport="streamable-http"), refusal, rejected,
         ENDED, finished(http=HTTP_COUNTED, server_output_bytes=0)],
        [observing, rejected,
         ENDED, finished(http=HTTP_COUNTED, server_output_bytes=0)],
    ]  # fmt: skip


def write(path: Path, events: list) -> Path:
    lines = []
    for number, event in enumerate(events, 1):
        if isinstance(event, str):
            lines.append(event)
            continue
        event = {"seq": number, "v": SCHEMA_VERSION, **event}
        if event["type"] == "run_started":
            event["schema_version"] = SCHEMA_VERSION
        lines.append(json.dumps(event))
    path.write_text("\n".join(lines) + "\n")
    return path


def fixed_fleet() -> FleetRun:
    results = [
        Result("a", "scn", "poison", verdict.COMPLETE, run="ra", findings=('["k"]',),
               context={"server_version": "v"}),
        Result("b", "scn", "poison", verdict.INCOMPLETE, run="rb", causes=("udp_loss",),
               context={"server_version": "v"}),
        Result("c", "scn", "real-world", fleet.REFUSED, problems=["refused"]),
    ]  # fmt: skip
    return FleetRun(
        fleet="f",
        started_utc="t",
        finished_utc="t",
        manifest={"source": "m", "digest": "sha256:" + "33" * 32},
        tool={"version": "0", "content": "sha256:" + "11" * 32},
        pins=Pins("runc", "a", "b"),
        parallel=1,
        processed=[r.key for r in results],
        results={r.key: r for r in results},
    )


def fingerprint(tmp_path: Path) -> str:
    judged = []
    for number, events in enumerate(cases()):
        read = verdict.read(write(tmp_path / f"case{number}.jsonl", events))
        kinds = [truncation["kind"] for truncation in read.truncations]
        judged.append([read.state, read.causes, read.exit_code, kinds])
    unreadable = verdict.read(tmp_path / "missing.jsonl")
    judged.append([unreadable.state, unreadable.causes, unreadable.exit_code])
    foreign = write(tmp_path / "foreign.jsonl", [started(), ENDED, finished()])
    foreign.write_text(foreign.read_text().replace(f'"v": {SCHEMA_VERSION}', '"v": 1', 1))
    old = verdict.read(foreign)
    judged.append([old.state, old.causes, old.exit_code])
    judged.append(fixed_fleet().digest)
    text = json.dumps(judged, sort_keys=True)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def test_the_rules_have_not_changed_without_their_version(tmp_path):
    """If this fails after a change to verdict.py (or to what a fleet's digest covers): raise
    verdict.RULES_VERSION, say in its comment what changed, and add the new fingerprint as a
    new line of FINGERPRINTS — the old lines stay as they are."""
    found = fingerprint(tmp_path)
    assert verdict.RULES_VERSION in FINGERPRINTS, (
        f"no fingerprint for rules version {verdict.RULES_VERSION}; it is {found}"
    )
    assert FINGERPRINTS[verdict.RULES_VERSION] == found, (
        f"the rules changed without verdict.RULES_VERSION: they now judge to {found}"
    )


def test_every_kind_of_shortfall_the_verdict_makes_is_in_the_fingerprint(tmp_path):
    """The instrument's own check: a cause no case reaches could change unnoticed."""
    seen = set()
    for number, events in enumerate(cases()):
        seen |= set(verdict.read(write(tmp_path / f"c{number}.jsonl", events)).causes)
    seen |= set(verdict.read(tmp_path / "missing.jsonl").causes) | {"schema"}
    made_elsewhere = {"unfiled_finding"}  # the store's
    assert set(verdict.CAUSES) - made_elsewhere <= seen, set(verdict.CAUSES) - seen


# -- kept with every result --------------------------------------------------------------------


def test_the_store_keeps_the_rules_each_run_was_filed_under(tmp_path, monkeypatch):
    with Store.open(tmp_path / "s.sqlite") as store:
        monkeypatch.setattr(verdict, "RULES_VERSION", 1)
        first = store.ingest(recording(tmp_path, [], name="first"))
        monkeypatch.setattr(verdict, "RULES_VERSION", 2)
        second = store.ingest(
            recording(tmp_path, [], name="second", tool_content="sha256:" + "12" * 32)
        )
        again = store.ingest(recording(tmp_path, [], name="first"))
        assert again.already
        assert (store.run_info(first.run).rules, store.run_info(second.run).rules) == (1, 2)
        assert store.run_info(first.run).to_dict()["rules"] == 1
        compared = store.diff(first.run, second.run)
        assert compared.rules == {"before": 1, "after": 2, "moved": True}
        assert compared.to_dict()["rules"]["moved"] is True
        assert store.diff(first.run, first.run).rules["moved"] is False


def test_a_run_diff_across_rules_says_so_on_the_command_line(tmp_path, monkeypatch, capsys):
    database = str(tmp_path / "s.sqlite")
    monkeypatch.setattr(verdict, "RULES_VERSION", 1)
    one = recording(tmp_path, [], name="one")
    assert cli.main(["store", "ingest", "-q", "--store", database, str(one)]) == 0
    monkeypatch.setattr(verdict, "RULES_VERSION", 2)
    two = recording(tmp_path, [], name="two", tool_content="sha256:" + "12" * 32)
    assert cli.main(["store", "ingest", "-q", "--store", database, str(two)]) == 0
    capsys.readouterr()
    assert cli.main(["store", "diff", "--store", database, str(one), str(two)]) == 0
    said = capsys.readouterr()
    assert json.loads(said.out)["rules"] == {"before": 1, "after": 2, "moved": True}
    assert "judged under different rules (1 and 2)" in said.err


def test_the_store_s_schema_is_13_and_moves_only_with_its_tables():
    from mcp_kymograph import store

    assert store.SCHEMA_VERSION == "13"
    assert "rules INTEGER NOT NULL" in store._SCHEMA


def made_up_launcher():
    from test_fleet import launcher

    return launcher({"reference-server": {}, "poison-server": {}})


def test_a_fleet_keeps_its_rules_and_a_comparison_across_rules_says_so(
    tmp_path, monkeypatch, capsys
):
    """The same corpus, the same results, judged under two versions: not the same result, and
    the comparison names both versions instead of putting the difference down to a server."""
    from test_fleet import PINS, pair

    with Store.open(tmp_path / "s.sqlite") as store:
        monkeypatch.setattr(verdict, "RULES_VERSION", 1)
        first = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                          launcher=made_up_launcher())  # fmt: skip
        same = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                         launcher=made_up_launcher())  # fmt: skip
        monkeypatch.setattr(verdict, "RULES_VERSION", 2)
        second = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                           launcher=made_up_launcher())  # fmt: skip
        assert (store.fleet(first.fleet)["rules"], store.fleet(second.fleet)["rules"]) == (1, 2)
        assert first.to_dict()["rules"] == 1
        unchanged = fleet.compare(store, first.fleet, same.fleet)
        across = fleet.compare(store, same.fleet, second.fleet)
    assert unchanged["rules"] == {"before": 1, "after": 1, "moved": False}
    assert unchanged["same_result"] is True
    assert across["rules"] == {"before": 1, "after": 2, "moved": True}
    assert across["same_result"] is False, "the same states under other rules"
    cli._report_fleet_diff(cli.TerminalView(sys.stderr), across)
    assert "judged under different rules (1 and 2)" in capsys.readouterr().err


def test_the_digest_moves_with_the_rules():
    base = fixed_fleet()
    other = fixed_fleet()
    other.rules = base.rules + 1
    assert base.digest != other.digest


@pytest.mark.parametrize("command", ["verdict"])
def test_the_verdict_names_the_rules_it_judged_by(tmp_path, capsys, command):
    path = write(tmp_path / "events.jsonl", [started(), ENDED, finished()])
    assert cli.main([command, "-q", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["rules"] == verdict.RULES_VERSION
