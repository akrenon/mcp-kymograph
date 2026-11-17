"""Engagement files: the reader, drafts, what may be handed on, what is shown, and the gate."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from mcp_kymograph import authorization, engagement
from mcp_kymograph.engagement import EngagementError, EngagementRefused, GateFacts
from mcp_kymograph.masking import Masker

SCENARIO_TEXT = b"version: 1\nname: listed\n"
SCENARIO_SHA = hashlib.sha256(SCENARIO_TEXT).hexdigest()


def base() -> dict:
    """A complete file, every section given."""
    return {
        "version": 1,
        "id": "acme-2026-10",
        "customer": "ACME Corp",
        "reference": "SOW-17 signed 2026-10-20",
        "contacts": [{"name": "Dana", "role": "CISO", "reach": "+49 30 1234"}],
        "window": {
            "from": "2026-10-27T06:00:00Z",
            "until": "2026-11-07T18:00:00+00:00",
            "tz": "Europe/Berlin",
        },
        "targets": [
            {"host": "mcp.example-customer.test", "ports": [443, 8080], "paths": ["/mcp"]},
            {"host": "127.0.0.1", "isolation": "runc"},
            {"host": "[2001:DB8::1]", "ports": [9000], "paths": ["/mcp"]},
        ],
        "scenarios": [{"path": "scenarios/listed.yaml", "sha256": SCENARIO_SHA}],
        "actions": {"list": True, "call": False},
        "pacing": {"runs_per_origin": 1, "min_interval_seconds": 10},
        "retention": {"delete_after": "2027-01-31"},
        "redaction": {"mask_keys": ["customer_id"], "mask_patterns": ["ACME-INTERNAL"]},
        "supersedes": "a" * 64,
        "declared": {
            "servers": [
                {
                    "name": "billing",
                    "reached_how": "https://mcp.example-customer.test/mcp",
                    "transport": "streamable-http",
                    "version_or_commit": "3.1",
                    "clients_in_use": ["Claude Desktop"],
                    "owner_contact": "",
                    "may_be_run_locally": "no",
                    "change_freeze": "",
                    "entry": "billing-3.1",
                }
            ],
            "constraints": {"hours": "06-18 UTC", "rate": "", "do_not": ["delete data"]},
            "notes": ["[unknown]"],
        },
    }


def write(directory: Path, data: dict, name: str = "engagement.json") -> Path:
    """The file and the scenario it lists, side by side."""
    scenarios = directory / "scenarios"
    scenarios.mkdir(exist_ok=True)
    (scenarios / "listed.yaml").write_bytes(SCENARIO_TEXT)
    path = directory / name
    if name.endswith(".json"):
        path.write_text(json.dumps(data, indent=2))
    else:
        yaml = pytest.importorskip("yaml")
        path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


def refused(tmp_path, data: dict, name: str = "engagement.json") -> EngagementError:
    path = write(tmp_path, data, name)
    with pytest.raises(EngagementError) as raised:
        engagement.load(path)
    assert raised.value.source == str(path)
    assert str(raised.value).startswith(f"{path}: ")
    return raised.value


# -- what a complete file loads to ----------------------------------------------------------


def test_a_complete_file_loads_with_what_the_gate_reads(tmp_path):
    path = write(tmp_path, base())
    loaded = engagement.load(path)
    assert loaded.id == "acme-2026-10"
    assert loaded.digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert loaded.window_from == datetime(2026, 10, 27, 6, tzinfo=timezone.utc)
    assert loaded.window_until == datetime(2026, 11, 7, 18, tzinfo=timezone.utc)
    assert loaded.window_declared() == {
        "from": "2026-10-27T06:00:00Z",
        "until": "2026-11-07T18:00:00Z",
    }
    assert [(t.name, t.ports, t.paths, t.isolation) for t in loaded.targets] == [
        ("mcp.example-customer.test", (443, 8080), ("/mcp",), None),
        ("127.0.0.1", None, None, "runc"),
        ("2001:db8::1", (9000,), ("/mcp",), None),
    ]
    assert loaded.scenarios == (engagement.ListedScenario("scenarios/listed.yaml", SCENARIO_SHA),)
    assert (loaded.actions_list, loaded.actions_call) == (True, False)
    assert loaded.delete_after == date(2027, 1, 31)
    assert loaded.mask_keys == ("customer_id",)
    assert loaded.mask_patterns == ("ACME-INTERNAL",)
    assert loaded.supersedes == "a" * 64
    assert loaded.placeholders == ()
    assert not loaded.is_draft


def test_only_version_id_window_targets_and_actions_are_required(tmp_path):
    data = {key: base()[key] for key in ("version", "id", "window", "targets", "actions")}
    del data["window"]["tz"]
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.scenarios == () and loaded.customer is None and loaded.tz is None
    for key in ("version", "id", "window", "targets", "actions"):
        partial = {k: v for k, v in data.items() if k != key}
        assert f": {key}: missing" in str(refused(tmp_path, partial))


@pytest.mark.parametrize("name", ["engagement.json", "engagement.yaml"])
def test_loads_over_the_bytes_is_load_over_the_file(tmp_path, name):
    if name.endswith(".yaml"):
        pytest.importorskip("yaml")
    path = write(tmp_path, base(), name)
    loaded = engagement.loads(path.read_bytes(), source=str(path), directory=tmp_path)
    assert loaded == engagement.load(path)
    elsewhere = engagement.loads(
        path.read_bytes(), source="sent by mail", directory=tmp_path, suffix=path.suffix
    )
    assert dataclasses.replace(elsewhere, source=str(path)) == loaded


def test_loads_refuses_as_load_does_and_resolves_scenarios_in_its_directory(tmp_path):
    raw = json.dumps(base()).encode()
    with pytest.raises(EngagementError, match="unknown suffix ''"):
        engagement.loads(raw, source="no suffix", directory=tmp_path)
    with pytest.raises(EngagementError, match=r"scenarios\[0\]\.path: cannot read"):
        engagement.loads(raw, source="e.json", directory=tmp_path)
    with pytest.raises(EngagementError, match="larger than"):
        engagement.loads(
            b" " * (engagement.MAX_FILE_BYTES + 1), source="e.json", directory=tmp_path
        )


def test_the_same_file_as_yaml_and_as_json_loads_equal_but_for_the_digest(tmp_path):
    as_json = engagement.load(write(tmp_path, base(), "engagement.json"))
    as_yaml = engagement.load(write(tmp_path, base(), "engagement.yaml"))
    assert as_json.digest != as_yaml.digest
    assert dataclasses.replace(as_yaml, source=as_json.source, digest=as_json.digest) == as_json


def test_unquoted_yaml_times_and_dates_stay_text_and_load(tmp_path):
    pytest.importorskip("yaml")
    (tmp_path / "e.yaml").write_text(
        "version: 1\nid: x\nwindow:\n  from: 2026-10-27T06:00:00Z\n  until: 2026-10-28T06:00:00Z\n"
        "targets:\n  - host: localhost\nactions: {list: true, call: false}\n"
        "retention:\n  delete_after: 2026-10-28\n"
    )
    loaded = engagement.load(tmp_path / "e.yaml")
    assert loaded.data["window"]["from"] == "2026-10-27T06:00:00Z"
    assert loaded.delete_after == date(2026, 10, 28)


def test_yaml_without_the_extra_is_refused_with_words(tmp_path, monkeypatch):
    path = tmp_path / "e.yaml"
    path.write_text("version: 1\n")
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(EngagementError) as raised:
        engagement.load(path)
    assert "mcp-kymograph[yaml]" in raised.value.reason
    assert "scenario" not in raised.value.reason
    assert raised.value.source == str(path)


# -- refused whole, with the file and the place ----------------------------------------------


def _set(path: str, value):
    """A mutation: set the value at a dotted path with [i] indices; a value of ... deletes."""

    def mutate(data):
        node = data
        parts = path.replace("[", ".[").split(".")
        for part in parts[:-1]:
            node = node[int(part[1:-1])] if part.startswith("[") else node[part]
        last = parts[-1]
        key = int(last[1:-1]) if last.startswith("[") else last
        if value is ...:
            del node[key]
        else:
            node[key] = value

    return mutate


REFUSALS = [
    ("unknown key at the top", _set("scope", "all"), ": unknown key 'scope'"),
    ("unknown key in a target", _set("targets[0].prot", "tcp"), "targets[0]: unknown key 'prot'"),
    ("unknown key in a contact", _set("contacts[0].mail", "x"), "contacts[0]: unknown key"),
    ("unknown key in the window", _set("window.zone", "UTC"), "window: unknown key 'zone'"),
    ("unknown key in actions", _set("actions.read", True), "actions: unknown key 'read'"),
    ("unknown key in declared", _set("declared.budget", "1"), "declared: unknown key"),
    ("unknown key in a declared server", _set("declared.servers[0].ip", "1"), "servers[0]: "),
    ("another version", _set("version", 3), "version: unsupported 3"),
    ("a version as text", _set("version", "1"), "version: unsupported '1'"),
    ("an id that is no name", _set("id", "acme 2026"), "id: is not a name"),
    ("a host that is a URL", _set("targets[0].host", "https://x.test"), "targets[0].host: "),
    ("a host with a path", _set("targets[0].host", "x.test/mcp"), "targets[0].host: "),
    ("a host with a port", _set("targets[0].host", "x.test:443"), "list it under ports"),
    ("an unbracketed v6", _set("targets[0].host", "2001:db8::1"), "targets[0].host: "),
    ("an empty host", _set("targets[0].host", ""), "targets[0].host: expected"),
    ("a host with a space", _set("targets[0].host", "a b"), "targets[0].host: "),
    ("port 0", _set("targets[0].ports", [0]), "targets[0].ports[0]: 0 is not a port"),
    ("port 65536", _set("targets[0].ports", [443, 65536]), "targets[0].ports[1]: 65536"),
    ("a port as text", _set("targets[0].ports", ["443"]), "targets[0].ports[0]: '443'"),
    ("a port as boolean", _set("targets[0].ports", [True]), "targets[0].ports[0]: True"),
    ("a repeated port", _set("targets[0].ports", [443, 443]), "ports[1]: 443 is listed twice"),
    ("no ports", _set("targets[0].ports", []), "targets[0].ports: expected a non-empty"),
    ("a relative path", _set("targets[0].paths", ["mcp"]), "targets[0].paths[0]: 'mcp'"),
    ("a path with a query", _set("targets[0].paths", ["/mcp?x=1"]), "paths[0]: '/mcp?x=1'"),
    ("a repeated path", _set("targets[0].paths", ["/a", "/a"]), "paths[1]: '/a' is listed"),
    ("an unknown isolation", _set("targets[1].isolation", "kata"), "targets[1].isolation: "),
    ("no targets", _set("targets", []), "targets: expected a non-empty list"),
    ("a naive time", _set("window.from", "2026-10-27T06:00:00"), "window.from: '2026-10-27T"),
    ("another offset", _set("window.from", "2026-10-27T08:00:00+02:00"), "window.from: "),
    ("a date for a time", _set("window.until", "2026-11-07"), "window.until: '2026-11-07'"),
    ("a month that is not", _set("window.from", "2026-13-01T00:00:00Z"), "time that exists"),
    ("a time as number", _set("window.from", 1761544800), "window.from: expected a non-empty"),
    ("until equal to from", _set("window.until", "2026-10-27T06:00:00Z"), "window.until: is not"),
    ("until before from", _set("window.until", "2026-10-01T00:00:00Z"), "window.until: is not"),
    ("a zone that is no name", _set("window.tz", "Europe/../etc"), "window.tz: "),
    ("a zone with a space", _set("window.tz", "Central Time"), "window.tz: "),
    ("a missing scenario", _set("scenarios[0].path", "scenarios/gone.yaml"), "scenarios[0].path"),
    ("a changed scenario", _set("scenarios[0].sha256", "0" * 64), "scenarios[0].sha256: the "),
    ("an absolute scenario", _set("scenarios[0].path", "/etc/hosts"), "scenarios[0].path: "),
    ("a short digest", _set("scenarios[0].sha256", "abc"), "scenarios[0].sha256: expected"),
    ("an upper-case digest", _set("scenarios[0].sha256", SCENARIO_SHA.upper()), "sha256: "),
    ("actions as text", _set("actions.call", "no"), "actions.call: expected true or false"),
    ("a missing action", _set("actions.list", ...), "actions.list: missing"),
    ("pacing below one", _set("pacing.runs_per_origin", 0), "pacing.runs_per_origin: "),
    ("a negative interval", _set("pacing.min_interval_seconds", -1), "min_interval_seconds: "),
    ("delete before until", _set("retention.delete_after", "2026-11-06"), "ends before window"),
    ("delete_after as time", _set("retention.delete_after", "2027-01-31T00:00:00Z"), "a date"),
    ("an empty pattern", _set("redaction.mask_patterns", ["x", ""]), "mask_patterns[1]: "),
    ("an empty mask key", _set("redaction.mask_keys", [""]), "redaction.mask_keys[0]: "),
    ("a bad supersedes", _set("supersedes", "sha256:" + "a" * 64), "supersedes: expected"),
    ("a declared entry", _set("declared.servers[0].entry", "no name"), "servers[0].entry: "),
    ("a declared number", _set("declared.constraints.rate", 5), "declared.constraints.rate: "),
    ("an empty customer", _set("customer", ""), "customer: expected a non-empty string"),
    ("a contact without name", _set("contacts[0].name", ...), "contacts[0].name: missing"),
]


@pytest.mark.parametrize(
    ("mutate", "words"), [r[1:] for r in REFUSALS], ids=[r[0] for r in REFUSALS]
)
def test_a_file_is_refused_whole_naming_the_file_and_the_place(tmp_path, mutate, words):
    data = base()
    mutate(data)
    assert words in str(refused(tmp_path, data))


def test_delete_after_is_kept_through_its_whole_day(tmp_path):
    """The day ``until`` falls on is enough: the runs are kept through the end of it."""
    data = base()
    data["retention"]["delete_after"] = "2026-11-07"
    assert engagement.load(write(tmp_path, data)).delete_after == date(2026, 11, 7)


def test_a_file_cannot_supersede_itself(tmp_path):
    """The file's own digest cannot be written into it, so the reader is asked directly."""
    data = base()
    data["supersedes"] = "b" * 64
    reader = engagement._Reader(tmp_path, "b" * 64)
    write(tmp_path, data)
    with pytest.raises(engagement._Invalid) as raised:
        reader.engagement(data, "x.json")
    assert raised.value.where == "supersedes"


@pytest.mark.parametrize(
    ("name", "content", "words"),
    [
        ("e.toml", b"", "unknown suffix '.toml'"),
        ("e.json", b"\xff\xfe", "not UTF-8 at byte 0"),
        ("e.json", b"[1, 2]", "must be a mapping"),
        ("e.json", b'{"version": 1, "version": 1}', "duplicate key 'version'"),
        ("e.json", b"{" + b" " * engagement.MAX_FILE_BYTES + b"}", "larger than"),
    ],
)
def test_a_file_that_is_no_engagement_file_is_refused(tmp_path, name, content, words):
    path = tmp_path / name
    path.write_bytes(content)
    with pytest.raises(EngagementError) as raised:
        engagement.load(path)
    assert words in raised.value.reason
    assert raised.value.source == str(path)


def test_a_missing_file_is_refused_with_its_name(tmp_path):
    with pytest.raises(EngagementError) as raised:
        engagement.load(tmp_path / "nowhere.yaml")
    assert raised.value.source == str(tmp_path / "nowhere.yaml")
    assert "cannot read" in raised.value.reason


# -- drafts ------------------------------------------------------------------------------


def test_a_placeholder_makes_a_draft_and_says_where(tmp_path):
    data = base()
    data["customer"] = "[CUSTOMER NAME]"
    data["reference"] = "[DOCUMENT ID]"
    data["contacts"][0]["reach"] = "[HOW TO REACH THEM DURING THE WINDOW]"
    data["window"]["until"] = "[END OF WINDOW]"
    data["targets"][0]["host"] = "[HOST]"
    data["targets"][0]["paths"] = ["[PATH]"]
    data["retention"]["delete_after"] = "[DATE]"
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.is_draft
    assert loaded.placeholders == (
        "customer",
        "reference",
        "contacts[0].reach",
        "window.until",
        "targets[0].host",
        "targets[0].paths[0]",
        "retention.delete_after",
    )
    assert loaded.window_until is None and loaded.window_declared() is None
    assert loaded.targets[0].name is None
    assert loaded.customer is None


def test_a_bracketed_ipv6_host_is_a_host_not_a_placeholder(tmp_path):
    data = base()
    data["targets"][0]["host"] = "[fe80::1]"
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.placeholders == ()
    assert loaded.targets[0].name == "fe80::1"


def test_a_placeholder_in_the_customers_answers_makes_no_draft(tmp_path):
    """``declared`` is the customer's words, kept verbatim; base() holds "[unknown]" there."""
    assert engagement.load(write(tmp_path, base())).placeholders == ()


@pytest.mark.parametrize(
    "mutate",
    [
        _set("id", "[ID]"),
        _set("version", "[VERSION]"),
        _set("targets[0].ports", ["[PORT]"]),
        _set("targets[0].isolation", "[ISOLATION]"),
        _set("actions.call", "[YES OR NO]"),
        _set("scenarios[0].sha256", "[DIGEST]"),
        _set("supersedes", "[DIGEST]"),
    ],
)
def test_a_placeholder_where_none_is_taken_is_refused(tmp_path, mutate):
    data = base()
    mutate(data)
    refused(tmp_path, data)


# -- what may be handed on -------------------------------------------------------------------


def test_sanitized_holds_neither_contacts_reference_mask_patterns_nor_owner_contacts(tmp_path):
    loaded = engagement.load(write(tmp_path, base()))
    sanitized = loaded.sanitized()
    assert engagement.Engagement.removed == (
        "contacts",
        "reference",
        "redaction.mask_patterns",
        "declared.servers[].owner_contact",
        "identities[].token_file",
        "known_values",
        "emergency",
        "salt_env",
        "receiver.key_env",
        "receiver.ssh",
        "receiver.path_prefix",
        "agency.contacts",
    )
    assert "contacts" not in sanitized and "reference" not in sanitized
    expected = {k: v for k, v in base().items() if k not in ("contacts", "reference")}
    del expected["redaction"]["mask_patterns"]
    del expected["declared"]["servers"][0]["owner_contact"]
    assert sanitized == expected
    assert "ACME-INTERNAL" not in json.dumps(sanitized), "the literal to blank is not handed on"
    json.dumps(sanitized)  # JSON-able as it is
    sanitized["targets"].clear()
    assert loaded.data["targets"], "a copy: changing it changes nothing in the engagement"


# -- show ------------------------------------------------------------------------------------


def test_render_says_what_the_file_permits_and_ends_with_the_digest(tmp_path):
    loaded = engagement.load(write(tmp_path, base()))
    text = engagement.render(loaded)
    assert text.rstrip("\n").splitlines()[-1] == f"SHA-256: {loaded.digest}"
    assert "--engagement-confirmed is still needed" in text
    assert "does not imply it" in text
    assert "enforced: runs_per_origin 1 (from the file)" in text
    assert "mcp.example-customer.test" in text and "443, 8080" in text and "/mcp" in text
    assert "call tools, read resources:        NOT permitted" in text
    assert "Dana — CISO — +49 30 1234" in text
    assert "DRAFT" not in text


def test_render_shows_the_window_in_a_known_zone(tmp_path):
    pytest.importorskip("zoneinfo")
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        ZoneInfo("Europe/Berlin")
    except ZoneInfoNotFoundError:
        pytest.skip("no zone database on this machine")
    text = engagement.render(engagement.load(write(tmp_path, base())))
    assert "in Europe/Berlin: 2026-10-27T07:00:00+01:00 to 2026-11-07T19:00:00+01:00" in text


def test_render_says_when_the_zone_is_unknown_here_and_the_file_still_loads(tmp_path):
    data = base()
    data["window"]["tz"] = "Nowhere/Atlantis"
    text = engagement.render(engagement.load(write(tmp_path, data)))
    assert "the zone Nowhere/Atlantis is unknown on this machine" in text


def test_render_marks_a_draft_and_every_placeholder(tmp_path):
    data = base()
    data["customer"] = "[CUSTOMER NAME]"
    data["window"]["from"] = "[START]"
    text = engagement.render(engagement.load(write(tmp_path, data)))
    assert text.startswith("Engagement acme-2026-10\n")
    assert "DRAFT" in text
    assert "  [placeholder] customer" in text and "  [placeholder] window.from" in text
    assert "[CUSTOMER NAME]  <- placeholder" in text


def test_render_keeps_control_and_format_characters_off_the_terminal(tmp_path):
    data = base()
    data["customer"] = "ACME\x1b[2J‮Corp"
    data["contacts"][0]["name"] = "Da\rna​"
    text = engagement.render(engagement.load(write(tmp_path, data)))
    assert "\x1b" not in text and "‮" not in text and "\r" not in text
    assert "​" not in text
    assert "ACME[2JCorp" in text


def test_the_json_form_holds_the_whole_file_and_reads_back(tmp_path):
    data = base()
    data["customer"] = "[CUSTOMER NAME]"
    loaded = engagement.load(write(tmp_path, data))
    shown = json.loads(engagement.to_json(loaded))
    assert shown["digest"] == loaded.digest
    assert shown["placeholders"] == ["customer"]
    assert shown["engagement"]["contacts"] == data["contacts"], "the operator's view"
    # Written back as a file beside the same scenarios, it is the same engagement.
    again = tmp_path / "again.json"
    again.write_text(json.dumps(shown["engagement"]))
    reread = engagement.load(again)
    assert reread.data == loaded.data
    assert reread.placeholders == loaded.placeholders
    assert dataclasses.replace(reread, source=loaded.source, digest=loaded.digest) == loaded


def test_the_parsed_file_is_not_shared_with_the_caller(tmp_path):
    data = base()
    loaded = engagement.load(write(tmp_path, data))
    copied = copy.deepcopy(loaded.data)
    loaded.sanitized()["window"]["from"] = "changed"
    assert loaded.data == copied


# -- what a recording takes from the file ----------------------------------------------------


def test_a_declaration_takes_the_id_the_digest_and_the_window_and_nothing_else(tmp_path):
    from mcp_kymograph.authorization import Declaration

    loaded = engagement.load(write(tmp_path, base()))
    fields = engagement.declaration_fields(loaded)
    assert fields == {
        "engagement_id_declared": "acme-2026-10",
        "engagement_digest": loaded.digest,
        "window_declared": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
    }
    recorded = json.dumps(Declaration(**fields).as_dict())
    for value in ("ACME Corp", "SOW-17", "Dana", "customer_id", "ACME-INTERNAL", "billing"):
        assert value not in recorded
    assert engagement.declaration_fields(None) == dict.fromkeys(fields)
    assert Declaration(**engagement.declaration_fields(None)).as_dict()["engagement"] is None


# -- the gate --------------------------------------------------------------------------------


NOW = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)


def gate_file(tmp_path, **changes) -> engagement.Engagement:
    data = base()
    data["targets"] = [
        {"host": "mcp.example.test", "ports": [443, 8080], "paths": ["/mcp"]},
        {"host": "localhost", "isolation": "runc"},
        {"host": "10.0.0.5", "paths": ["/x", "/anything"]},
        {"host": "[::1]", "ports": [9000]},
    ]
    data["actions"] = {"list": True, "call": True}
    for key, value in changes.items():
        data[key] = value
    return engagement.load(write(tmp_path, data))


def gate(loaded, now=NOW, **facts) -> str | None:
    """The condition the gate refused with, or None when it let the run through."""
    facts.setdefault("command", "drive")
    try:
        engagement.check(loaded, GateFacts(**facts), now)
    except EngagementRefused as refusal:
        assert str(refusal) == f"{refusal.condition}: {refusal.words}"
        return refusal.condition
    return None


def test_a_run_the_file_covers_passes(tmp_path):
    loaded = gate_file(tmp_path)
    assert gate(loaded, declared_target="mcp.example.test:443") is None
    assert gate(loaded, http_url="http://mcp.example.test:8080/mcp") is None
    assert gate(loaded, http_url="https://10.0.0.5/anything") is None, "the default, for a URL"
    assert gate(loaded, isolation="runc") is None, "the child, against the local entry"
    assert gate(loaded, declared_target="[::1]:9000") is None
    assert gate(loaded, declared_target="MCP.Example.Test:443") is None, "hosts compare lower"


def test_a_draft_is_refused(tmp_path):
    loaded = gate_file(tmp_path, customer="[CUSTOMER NAME]")
    with pytest.raises(EngagementRefused) as raised:
        engagement.check(loaded, GateFacts(command="run", isolation="runc"), NOW)
    assert raised.value.condition == "draft"
    assert "customer" in raised.value.words


def test_before_and_after_the_window_is_refused(tmp_path):
    loaded = gate_file(tmp_path)
    opens = datetime(2026, 10, 27, 6, tzinfo=timezone.utc)
    closes = datetime(2026, 11, 7, 18, tzinfo=timezone.utc)
    facts = {"command": "run", "isolation": "runc"}
    assert gate(loaded, opens - timedelta(seconds=1), **facts) == "before_window"
    assert gate(loaded, opens, **facts) is None
    assert gate(loaded, closes - timedelta(microseconds=1), **facts) is None
    assert gate(loaded, closes, **facts) == "after_window"


def test_the_clock_must_be_aware(tmp_path):
    with pytest.raises(ValueError, match="aware"):
        engagement.check(gate_file(tmp_path), GateFacts(command="run"), datetime(2026, 10, 30))
    with pytest.raises(ValueError, match="command"):
        engagement.check(gate_file(tmp_path), GateFacts(command="listen"), NOW)


@pytest.mark.parametrize(
    "facts",
    [
        {"declared_target": "example.com"},
        {"declared_target": "mcp.example.test.evil"},
        {"declared_target": "127.0.0.1"},  # local, but not the local host the file names
        {"declared_target": "http://mcp.example.test"},  # cannot be taken apart
        {"http_url": "http://example.com:443/mcp"},
        {"http_url": "ftp://mcp.example.test:443/mcp"},
        {"http_url": "http://user@mcp.example.test:443/mcp"},
        {"declared_target": "mcp.example.test:443", "http_url": "https://example.com:443/mcp"},
    ],
)
def test_a_target_the_file_does_not_list_is_refused(tmp_path, facts):
    assert gate(gate_file(tmp_path), **facts) == "target_not_listed"


def test_the_child_needs_a_local_entry(tmp_path):
    data_targets = [{"host": "mcp.example.test", "paths": ["/mcp"]}]
    loaded = gate_file(tmp_path, targets=data_targets)
    with pytest.raises(EngagementRefused) as raised:
        engagement.check(loaded, GateFacts(command="run"), NOW)
    assert raised.value.condition == "target_not_listed"
    assert "local child" in raised.value.words


@pytest.mark.parametrize(
    "facts",
    [
        {"declared_target": "mcp.example.test"},  # no port: not one of 443, 8080
        {"declared_target": "mcp.example.test:9443"},
        {"http_url": "http://mcp.example.test/mcp"},  # http without a port is 80
        {"declared_target": "[::1]"},
        {"declared_target": "::1"},
    ],
)
def test_a_port_the_file_does_not_list_is_refused(tmp_path, facts):
    assert gate(gate_file(tmp_path), **facts) == "port_not_listed"


def test_a_url_without_a_port_has_its_schemes_port(tmp_path):
    loaded = gate_file(tmp_path)
    assert gate(loaded, http_url="https://mcp.example.test/mcp") is None, "https is 443"
    assert gate(loaded, http_url="http://mcp.example.test/mcp") == "port_not_listed"


@pytest.mark.parametrize("path", ["/mcp/", "/MCP", "/", "", "/mcp/../mcp", "/other"])
def test_a_path_the_file_does_not_list_is_refused_compared_exactly(tmp_path, path):
    url = f"http://mcp.example.test:443{path}"
    assert gate(gate_file(tmp_path), http_url=url) == "path_not_listed"


def test_a_declared_target_has_no_path_to_compare(tmp_path):
    assert gate(gate_file(tmp_path), declared_target="mcp.example.test:443") is None


@pytest.mark.parametrize(
    ("isolation", "condition"),
    [("host", "below_isolation"), ("runc", None), ("runsc", None), ("remote", "below_isolation")],
)
def test_an_isolation_below_the_floor_is_refused(tmp_path, isolation, condition):
    assert gate(gate_file(tmp_path), command="run", isolation=isolation) == condition


def test_an_http_run_meets_no_floor(tmp_path):
    """Nothing of the server runs here, so a target with a floor refuses every --http run."""
    loaded = gate_file(tmp_path)
    assert gate(loaded, http_url="http://localhost:8080/mcp", isolation="runc") == (
        "below_isolation"
    )


def test_a_floor_this_version_cannot_meet_refuses(tmp_path):
    loaded = gate_file(tmp_path, targets=[{"host": "127.0.0.1", "isolation": "runsc"}])
    assert gate(loaded, command="run", isolation="runc") == "below_isolation"


def test_the_closest_entry_names_the_condition(tmp_path):
    """Two entries for one host: the one whose port matched decides what is said."""
    loaded = gate_file(
        tmp_path,
        targets=[
            {"host": "box.test", "ports": [1], "paths": ["/b"]},
            {"host": "box.test", "ports": [2], "paths": ["/a"]},
        ],
    )
    assert gate(loaded, http_url="http://box.test:2/b") == "path_not_listed"
    assert gate(loaded, http_url="http://box.test:3/a") == "port_not_listed"
    assert gate(loaded, http_url="http://box.test:2/a") is None


def test_both_the_declared_target_and_the_url_are_matched(tmp_path):
    loaded = gate_file(tmp_path)
    assert gate(loaded, declared_target="example.com", http_url="https://10.0.0.5/x") == (
        "target_not_listed"
    )
    url = "https://mcp.example.test/mcp"
    assert gate(loaded, declared_target="mcp.example.test:443", http_url=url) is None


def test_a_scenario_the_file_does_not_list_is_refused(tmp_path):
    loaded = gate_file(tmp_path)
    run = {"declared_target": "mcp.example.test:443"}
    assert gate(loaded, scenario_digest=SCENARIO_SHA, **run) is None
    assert gate(loaded, scenario_digest="0" * 64, **run) == "scenario_not_listed"
    assert gate(gate_file(tmp_path, scenarios=[]), scenario_digest=SCENARIO_SHA, **run) == (
        "scenario_not_listed"
    )


def test_a_builtin_scenario_is_refused_under_a_file(tmp_path):
    loaded = gate_file(tmp_path)
    assert gate(loaded, declared_target="mcp.example.test:443", scenario_builtin=True) == (
        "builtin_scenario"
    )


def test_a_script_that_calls_is_refused_where_calls_are_not_permitted(tmp_path):
    loaded = gate_file(tmp_path, actions={"list": True, "call": False})
    run = {"declared_target": "mcp.example.test:443"}
    assert gate(loaded, script_acts=True, **run) == "calls_not_permitted"
    assert gate(loaded, script_acts=False, **run) is None


@pytest.mark.parametrize(
    ("command", "lists", "condition"),
    [
        ("drive", False, "lists_not_permitted"),
        ("fleet", False, "lists_not_permitted"),
        ("run", True, "lists_not_permitted"),
        # The gate does not refuse run for actions (a client's session is not the tool's script);
        # the guard blocks every call outside the scope (see test_scope_guard.py)
        ("run", False, None),
    ],
)
def test_listing_is_refused_where_lists_are_not_permitted(tmp_path, command, lists, condition):
    loaded = gate_file(tmp_path, actions={"list": False, "call": False})
    facts = {"command": command, "declared_target": "mcp.example.test:443", "script_lists": lists}
    assert gate(loaded, **facts) == condition


def test_the_conditions_are_twenty_two_distinct_keys_and_no_other_is_raised():
    """The closed set, and nothing outside it can be raised."""
    assert len(engagement.CONDITIONS) == len(set(engagement.CONDITIONS)) == 22
    with pytest.raises(ValueError):
        EngagementRefused("not_a_condition", "x")


# -- endpoint targets -----------------------------------------------------------------------


@pytest.mark.parametrize("host", ["mcp.example.test", "10.0.0.5", "[2001:db8::1]", "box.local"])
def test_a_target_that_is_not_local_must_list_its_paths(tmp_path, host):
    data = base()
    data["targets"] = [{"host": host, "ports": [80]}]
    words = str(refused(tmp_path, data))
    assert "targets[0].paths: missing" in words
    assert "not any path" in words


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_a_local_target_may_leave_ports_and_paths_out(tmp_path, host):
    data = base()
    data["targets"] = [{"host": host}]
    (target,) = engagement.load(write(tmp_path, data)).targets
    assert (target.ports, target.paths, target.ports_defaulted) == (None, None, False)


def test_an_endpoint_without_ports_is_read_as_the_port_of_https_and_shown_so(tmp_path):
    data = base()
    data["targets"] = [{"host": "mcp.example.test", "paths": ["/mcp"]}, {"host": "localhost"}]
    loaded = engagement.load(write(tmp_path, data))
    endpoint, local = loaded.targets
    assert (endpoint.ports, endpoint.ports_defaulted) == ((443,), True)
    assert "ports" not in loaded.data["targets"][0], "the file is kept as written"
    text = engagement.render(loaded)
    assert "443 (default for https; not in the file)" in text
    row = next(line for line in text.splitlines() if line.lstrip().startswith("localhost"))
    assert "any" in row
    # The gate reads the default: the URL's port must be it.
    facts = {"command": "drive", "isolation": "host"}
    assert gate(loaded, http_url="https://mcp.example.test/mcp", **facts) is None
    assert gate(loaded, http_url="https://mcp.example.test:443/mcp", **facts) is None
    assert gate(loaded, http_url="https://mcp.example.test:8443/mcp", **facts) == (
        "port_not_listed"
    )
    assert gate(loaded, http_url="http://mcp.example.test/mcp", **facts) == "port_not_listed"
    with pytest.raises(EngagementRefused) as raised:
        engagement.check(loaded, GateFacts(http_url="https://mcp.example.test:8443/mcp",
                                           command="drive"), NOW)  # fmt: skip
    assert "443 (the default for https: the file names no port)" in raised.value.words


def test_the_moved_default_lets_no_plain_http_url_through(tmp_path, monkeypatch):
    """The default moved from 80 to 443 (http-transport.md 8.5). Over the URLs a run could be
    given: every plain-HTTP URL that passes the file and plain HTTP's own rule (only to a
    loopback literal) now passed both under 80 too. What the file now lets through that 80 did
    not is https:// on 443, spoken since TLS, and http://...:443, which that rule refuses before
    the gate."""
    data = base()
    data["targets"] = [{"host": "mcp.example.test", "paths": ["/mcp"]}]
    now = engagement.load(write(tmp_path, data))
    monkeypatch.setattr(engagement, "ENDPOINT_DEFAULT_PORTS", (80,))
    before = engagement.load(write(tmp_path, data))
    monkeypatch.undo()
    assert (before.targets[0].ports, now.targets[0].ports) == ((80,), (443,))
    widened = []
    for scheme in ("http", "https"):
        for port in ("", ":80", ":443", ":8080"):
            url = f"{scheme}://mcp.example.test{port}/mcp"
            refused = authorization.plain_http_refusal(url) is not None
            passes_now = gate(now, http_url=url) is None and not refused
            passes_before = gate(before, http_url=url) is None and not refused
            if passes_now and not passes_before:
                widened.append(url)
            if scheme == "http":
                assert refused, url
                assert not passes_now, url
    assert widened == ["https://mcp.example.test/mcp", "https://mcp.example.test:443/mcp"]
    assert gate(now, http_url="http://mcp.example.test:443/mcp") is None, "the file alone"
    assert authorization.plain_http_refusal("http://mcp.example.test:443/mcp") is not None


def test_a_declared_target_matches_no_entry_whose_ports_were_defaulted(tmp_path):
    """The default is the port of the scheme a URL is spoken to with; a declared target has no
    scheme, and is held to the ports the file lists — on any port, or none, it is refused."""
    data = base()
    data["targets"] = [{"host": "mcp.example.test", "paths": ["/mcp"]}]
    loaded = engagement.load(write(tmp_path, data))
    for target in ("mcp.example.test", "mcp.example.test:80", "mcp.example.test:443"):
        assert gate(loaded, declared_target=target) == "port_not_listed", target
    with pytest.raises(EngagementRefused) as raised:
        engagement.check(loaded, GateFacts(declared_target="mcp.example.test:443",
                                           command="drive"), NOW)  # fmt: skip
    assert raised.value.words == (
        "the target mcp.example.test is on port 443, and the file names no port for "
        "mcp.example.test: its default (443, the port of https) is read only for a URL. A "
        "declared target is held to the ports the file lists; list the port the run is against"
    )
    # Listed, the port is the file's word, and a declared target is held to it as before.
    data["targets"] = [{"host": "mcp.example.test", "ports": [443], "paths": ["/mcp"]}]
    listed = engagement.load(write(tmp_path, data))
    assert gate(listed, declared_target="mcp.example.test:443") is None
    assert gate(listed, declared_target="mcp.example.test:80") == "port_not_listed"
    assert gate(listed, declared_target="mcp.example.test") == "port_not_listed"


def test_the_moved_default_lets_no_declared_target_through(tmp_path):
    """No declared target passes now that was refused under the earlier default, 80. The
    earlier gate read a defaulted entry as if it listed 80; that reading is an entry that does
    list it. Under it ``host:80`` passed and nothing else; now nothing does."""
    data = base()
    data["targets"] = [{"host": "mcp.example.test", "paths": ["/mcp"]}]
    now = engagement.load(write(tmp_path, data))
    data["targets"] = [{"host": "mcp.example.test", "ports": [80], "paths": ["/mcp"]}]
    (tmp_path / "before").mkdir()
    before = engagement.load(write(tmp_path / "before", data))
    passed_before = []
    for port in ("", ":80", ":443", ":8080"):
        target = f"mcp.example.test{port}"
        assert gate(now, declared_target=target) == "port_not_listed", target
        if gate(before, declared_target=target) is None:
            passed_before.append(target)
    assert passed_before == ["mcp.example.test:80"]


def test_a_placeholder_endpoint_host_stays_a_draft_without_paths(tmp_path):
    data = base()
    data["targets"] = [{"host": "[CUSTOMER HOST]"}]
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.placeholders == ("targets[0].host",)


def test_render_says_what_pacing_is_enforced_and_where_each_value_comes_from(tmp_path):
    text = engagement.render(engagement.load(write(tmp_path, base())))
    assert "enforced: runs_per_origin 1 (from the file), min_interval_seconds 10 (from" in text
    data = base()
    del data["pacing"]
    text = engagement.render(engagement.load(write(tmp_path, data)))
    assert "enforced: runs_per_origin 1 (default), min_interval_seconds 10 (default)" in text
    data["pacing"] = {"min_interval_seconds": 4}
    text = engagement.render(engagement.load(write(tmp_path, data)))
    assert "enforced: runs_per_origin 1 (default), min_interval_seconds 4 (from the file)" in text
    assert "pacing_enforced: false" not in text


# -- the remote floor ------------------------------------------------------------------------


@pytest.fixture
def remote_isolation(monkeypatch):
    """``remote`` in the isolations the reader takes, as ``policy.ISOLATIONS`` has it; put there
    for the test should it be missing."""
    if "remote" not in engagement.ISOLATIONS:
        monkeypatch.setattr(engagement, "ISOLATIONS", (*engagement.ISOLATIONS, "remote"))


ENDPOINT = "https://mcp.example.test:443/mcp"


@pytest.mark.parametrize(
    ("isolation", "condition"),
    [("remote", None), ("host", "below_isolation"), ("runc", "below_isolation"),
     ("runsc", "below_isolation")],
)  # fmt: skip
def test_a_remote_floor_is_met_by_a_remote_run_only(tmp_path, remote_isolation, isolation,
                                                    condition):  # fmt: skip
    loaded = gate_file(
        tmp_path, targets=[{"host": "mcp.example.test", "paths": ["/mcp"], "isolation": "remote"}]
    )
    assert loaded.targets[0].isolation == "remote"
    assert gate(loaded, http_url=ENDPOINT, isolation=isolation) == condition


@pytest.mark.parametrize("floor", ["host", "runc", "runsc"])
def test_a_remote_run_meets_no_floor_of_a_server_run_here(tmp_path, remote_isolation, floor):
    loaded = gate_file(
        tmp_path, targets=[{"host": "mcp.example.test", "paths": ["/mcp"], "isolation": floor}]
    )
    assert gate(loaded, http_url=ENDPOINT, isolation="remote") == "below_isolation"
    # And without a floor, a remote run to a listed endpoint passes.
    open_file = gate_file(tmp_path, targets=[{"host": "mcp.example.test", "paths": ["/mcp"]}])
    assert gate(open_file, http_url=ENDPOINT, isolation="remote") is None


def test_the_reader_takes_remote_from_policy_and_nothing_else(tmp_path, monkeypatch):
    monkeypatch.setattr(engagement, "ISOLATIONS", ("host", "runc", "runsc"))
    data = base()
    data["targets"][1]["isolation"] = "remote"
    assert "targets[1].isolation: unknown isolation 'remote'" in str(refused(tmp_path, data))


# -- the file only narrows ---------------------------------------------------------------


def _cli_gate(loaded, *, scenario, target, confirmed, acts, url):
    """The order cli._main runs them in: today's gate with the flag as typed, then the file."""
    gated = [(scenario is not None, target)]
    if acts and url is not None:
        gated.append((False, urlsplit(url).hostname or ""))
    for scenario_active, gated_target in gated:
        authorization.check(
            scenario_active=scenario_active,
            target=gated_target,
            confirmed=confirmed,
            script_calls=acts,
        )
    if loaded is not None:
        facts = GateFacts(
            command="drive",
            declared_target=target,
            http_url=url,
            scenario_digest=None if scenario in (None, "builtin") else scenario,
            scenario_builtin=scenario == "builtin",
            isolation="runc",
            script_acts=acts,
            script_lists=True,
        )
        engagement.check(loaded, facts, NOW)


def test_a_file_never_allows_what_todays_gate_refuses(tmp_path):
    """Over scenario x target x flag x acts x URL x file: wherever ``authorization.check``
    alone refuses, the two together refuse; and the most permissive file lets nothing through
    that is refused without it."""
    permissive = gate_file(
        tmp_path,
        targets=[
            {"host": "localhost"},
            {"host": "127.0.0.1"},
            {"host": "example.com", "paths": ["/mcp"]},
            {"host": "10.0.0.5", "paths": ["/mcp"]},
        ],
    )
    (tmp_path / "narrow").mkdir()
    narrow = gate_file(
        tmp_path / "narrow",
        targets=[{"host": "example.com", "ports": [443], "paths": ["/mcp"]}],
        scenarios=[],
    )
    scenarios = [None, "builtin", SCENARIO_SHA, "0" * 64]
    targets = [None, "localhost", "example.com", "example.com:443", "10.0.0.5", "box.local"]
    urls = [None, "http://example.com:443/mcp", "http://127.0.0.1:8080/mcp"]
    checked = 0
    for scenario in scenarios:
        for target in targets:
            for confirmed in (False, True):
                for acts in (False, True):
                    for url in urls:
                        common = {
                            "scenario": scenario,
                            "target": target,
                            "confirmed": confirmed,
                            "acts": acts,
                            "url": url,
                        }
                        try:
                            _cli_gate(None, **common)
                            alone = True
                        except authorization.Unauthorized:
                            alone = False
                        for loaded in (permissive, narrow):
                            try:
                                _cli_gate(loaded, **common)
                                together = True
                            except (authorization.Unauthorized, EngagementRefused):
                                together = False
                            assert alone or not together, common
                            checked += 1
    assert checked == len(scenarios) * len(targets) * 2 * 2 * len(urls) * 2


def test_a_file_does_not_stand_in_for_the_confirmation(tmp_path):
    """A scenario against a non-local target the file lists is still refused without the
    flag: the refusal is today's gate's, and the file adds nothing to open it."""
    loaded = gate_file(tmp_path)
    with pytest.raises(authorization.Unauthorized):
        _cli_gate(loaded, scenario=SCENARIO_SHA, target="mcp.example.test:443",
                  confirmed=False, acts=False, url=None)  # fmt: skip
    _cli_gate(loaded, scenario=SCENARIO_SHA, target="mcp.example.test:443", confirmed=True,
              acts=False, url=None)  # fmt: skip


# -- the refusal record ----------------------------------------------------------------------

TYPED = [
    "drive",
    "--engagement",
    "e.yaml",
    "--target",
    "example.com",
    "--",
    "/usr/bin/server",
    "--api-key",
    "sk-live-0123456789abcdefghij",
]


def refusal(out_dir, loaded, **changes):
    arguments = {
        "argv": TYPED,
        "masker": Masker(),
        "reason": "target_not_listed",
        "message": "the target example.com is not among the engagement's targets",
        "engagement": loaded,
        "now": NOW,
    }
    arguments.update(changes)
    return engagement.record_refusal(out_dir, **arguments)


def test_a_refusal_is_appended_and_reads_back(tmp_path):
    loaded = gate_file(tmp_path)
    out = tmp_path / "out" / "runs"
    assert refusal(out, loaded) is None
    assert refusal(out, loaded, reason="not_confirmed", message="token=hunter2 was given") is None
    path = out / engagement.REFUSALS_FILE
    first, second = engagement.read_refusals(path)
    assert first.to_dict() == {
        "refused_utc": "2026-10-30T12:00:00Z",
        "command": first.to_dict()["command"],
        "reason": "target_not_listed",
        "message": "the target example.com is not among the engagement's targets",
        "engagement": {
            "engagement_id_declared": "acme-2026-10",
            "engagement_digest": loaded.digest,
        },
        "exit_code": 2,
    }
    assert first.command[:6] == tuple(TYPED[:6]), "as typed, the server command included"
    assert "sk-live-0123456789abcdefghij" not in path.read_text(), "masked as argv is masked"
    assert second.reason == "not_confirmed"
    assert "hunter2" not in second.message, "masked as text is masked"
    lines = path.read_text().splitlines()
    assert [json.loads(line) for line in lines] == [first.to_dict(), second.to_dict()]
    # Nothing of the file but its id and digest.
    for value in ("ACME Corp", "SOW-17", "Dana", "Europe/Berlin"):
        assert value not in path.read_text()


def test_the_record_and_its_directory_are_private(tmp_path):
    out = tmp_path / "a" / "b"
    assert refusal(out, gate_file(tmp_path)) is None
    assert stat.S_IMODE((out / engagement.REFUSALS_FILE).stat().st_mode) == 0o600
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "a").stat().st_mode) == 0o700
    assert [p.name for p in out.iterdir()] == [engagement.REFUSALS_FILE], "no run directory"


def test_a_link_at_the_path_is_not_followed(tmp_path):
    out = tmp_path / "runs"
    out.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere.jsonl"
    elsewhere.write_bytes(b"")
    elsewhere.chmod(0o600)
    (out / engagement.REFUSALS_FILE).symlink_to(elsewhere)
    words = refusal(out, gate_file(tmp_path))
    assert words is not None and "symbolic link" in words
    assert elsewhere.read_bytes() == b""
    with pytest.raises(EngagementError, match="symbolic link"):
        engagement.read_refusals(out / engagement.REFUSALS_FILE)


def test_a_file_of_another_mode_or_kind_is_not_appended_to(tmp_path):
    out = tmp_path / "runs"
    out.mkdir(mode=0o700)
    path = out / engagement.REFUSALS_FILE
    path.write_bytes(b"")
    path.chmod(0o644)
    words = refusal(out, gate_file(tmp_path))
    assert words is not None and "0644" in words
    assert path.read_bytes() == b""
    path.unlink()
    path.mkdir()
    assert refusal(out, gate_file(tmp_path)) is not None


def test_a_refused_destination_records_nothing_and_says_why(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    git = shutil.which("git")
    assert git, "this test needs a git binary"
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=repository, check=True)  # noqa: S603
    out = repository / "runs"
    words = refusal(out, gate_file(tmp_path))
    assert words is not None
    assert "git working tree" in words and "not recorded" in words
    assert not out.exists(), "nothing created, nothing written"


def test_a_run_directory_is_never_written_into(tmp_path):
    loaded = gate_file(tmp_path)
    run = tmp_path / "runs" / "20261030T120000Z-0123abcd"
    run.mkdir(parents=True)
    assert refusal(run, loaded) is not None
    holding = tmp_path / "other"
    holding.mkdir()
    (holding / "events.jsonl").write_text("")
    assert refusal(holding / "below", loaded) is not None
    assert not (run / engagement.REFUSALS_FILE).exists()
    assert not (holding / "below").exists()


def test_a_run_of_a_fleet_records_its_refusal_in_its_own_out_dir(tmp_path):
    """A fleet's directory is named like a run directory, but holds the runs' out-dirs, not a
    recording: a child refused inside it records there."""
    loaded = gate_file(tmp_path)
    fleet_dir = tmp_path / "runs" / "20261030T120000Z-0123abcd"
    fleet_dir.mkdir(parents=True)
    child = fleet_dir / "000-reference-server"
    assert refusal(child, loaded) is None
    (record,) = engagement.read_refusals(child / engagement.REFUSALS_FILE)
    assert record.reason == "target_not_listed"
    # A run directory of that child, with its recording, is one: nothing below it is written.
    recorded = child / "20261030T120001Z-89abcdef"
    recorded.mkdir()
    (recorded / "events.jsonl").write_text("")
    assert refusal(recorded, loaded) is not None
    assert refusal(recorded / "deeper", loaded) is not None
    assert not (recorded / engagement.REFUSALS_FILE).exists()


def test_every_refusals_file_under_an_out_dir_is_found_and_a_bad_one_reported(tmp_path):
    loaded = gate_file(tmp_path)
    out = tmp_path / "runs"
    assert refusal(out, loaded) is None
    child = out / "20261030T120000Z-0123abcd" / "001-poison-server"
    assert refusal(child, loaded, reason="after_window") is None
    broken = out / "20261030T120000Z-0123abcd" / "002-broken"
    broken.mkdir(mode=0o700)
    (broken / engagement.REFUSALS_FILE).write_text("not a record\n")
    too_deep = out / "a" / "b" / "c"
    too_deep.mkdir(parents=True)
    (too_deep / engagement.REFUSALS_FILE).write_text("")
    linked = out / "linked"
    linked.symlink_to(child, target_is_directory=True)

    found = engagement.find_refusals(out)
    assert [item.path for item in found] == [
        child / engagement.REFUSALS_FILE,
        broken / engagement.REFUSALS_FILE,
        out / engagement.REFUSALS_FILE,
    ]
    top = found[2]
    assert top.refused is None and [r.reason for r in top.records] == ["target_not_listed"]
    assert found[0].refused is None and [r.reason for r in found[0].records] == ["after_window"]
    assert found[1].records == () and "line 1" in found[1].refused


def test_a_linked_refusals_file_is_reported_not_followed(tmp_path):
    out = tmp_path / "runs"
    out.mkdir()
    elsewhere = tmp_path / "elsewhere.jsonl"
    elsewhere.write_text("")
    (out / engagement.REFUSALS_FILE).symlink_to(elsewhere)
    (found,) = engagement.find_refusals(out)
    assert found.refused is not None and "symbolic link" in found.refused


def test_find_refusals_refuses_an_out_dir_that_is_none(tmp_path):
    with pytest.raises(EngagementError):
        engagement.find_refusals(tmp_path / "nowhere")
    (tmp_path / "file").write_text("")
    with pytest.raises(EngagementError, match="not a directory"):
        engagement.find_refusals(tmp_path / "file")


@pytest.mark.parametrize("room", [0, -1])
def test_a_full_refusals_file_takes_no_more_and_says_so(tmp_path, monkeypatch, room):
    """Up to the cap the reader reads, and not a byte past it: a line that would cross it
    would make every refusal before it unreadable."""
    loaded = gate_file(tmp_path)
    out = tmp_path / "runs"
    assert refusal(out, loaded) is None
    path = out / engagement.REFUSALS_FILE
    one = path.stat().st_size
    monkeypatch.setattr(engagement, "MAX_REFUSALS_BYTES", 2 * one + room)
    words = refusal(out, loaded)
    if room == 0:
        assert words is None
        assert len(engagement.read_refusals(path)) == 2
    else:
        assert words is not None and "full" in words and "not recorded" in words
        assert path.stat().st_size == one
        assert len(engagement.read_refusals(path)) == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_fifo_at_the_path_neither_blocks_the_writer_nor_the_reader(tmp_path):
    out = tmp_path / "runs"
    out.mkdir(mode=0o700)
    fifo = out / engagement.REFUSALS_FILE
    os.mkfifo(fifo, 0o600)
    words = refusal(out, gate_file(tmp_path))
    assert words is not None and "FIFO" in words and "not recorded" in words
    with pytest.raises(EngagementError, match="not a regular file"):
        engagement.read_refusals(fifo)
    (found,) = engagement.find_refusals(out)
    assert found.refused == "not a regular file"


def test_an_unknown_reason_is_a_mistake_of_the_caller(tmp_path):
    with pytest.raises(ValueError, match="unknown refusal reason"):
        refusal(tmp_path / "runs", gate_file(tmp_path), reason="because")
    assert not (tmp_path / "runs").exists()


def test_the_reasons_are_the_conditions_and_the_command_lines_own():
    assert engagement.REFUSAL_REASONS[: len(engagement.CONDITIONS)] == engagement.CONDITIONS
    assert set(engagement.REFUSAL_REASONS) - set(engagement.CONDITIONS) == {
        "http_options",
        "manifest",
        "plain_http",
        "arguments",
        "script",
        "not_confirmed",
        "scenario",
        "scenario_over_http",
        "identity",
        "token",
        "probe_without_engagement",
        "delivery",
        "destination",
        "pacing",
        "store",
        "fleet",
        "name_holds_known_value",
    }
    assert len(set(engagement.REFUSAL_REASONS)) == len(engagement.REFUSAL_REASONS)


def test_a_plain_http_refusal_is_written_and_read_back_in_its_words(tmp_path):
    # The plain-HTTP refusal goes to refusals.jsonl as the terminal says it: the same words.
    words = authorization.plain_http_refusal("http://mcp.example.test:80/mcp")
    out = tmp_path / "runs"
    assert refusal(out, gate_file(tmp_path), reason="plain_http", message=words) is None
    (read,) = engagement.read_refusals(out / engagement.REFUSALS_FILE)
    assert (read.reason, read.message) == ("plain_http", words)


GOOD = {
    "refused_utc": "2026-10-30T12:00:00Z",
    "command": ["drive"],
    "reason": "draft",
    "message": "x",
    "engagement": {"engagement_id_declared": "a", "engagement_digest": "0" * 64},
    "exit_code": 2,
}


@pytest.mark.parametrize(
    "line",
    [
        b"not json\n",
        b"[]\n",
        json.dumps({**GOOD, "extra": 1}).encode() + b"\n",
        json.dumps({k: v for k, v in GOOD.items() if k != "message"}).encode() + b"\n",
        json.dumps({**GOOD, "reason": "because"}).encode() + b"\n",
        json.dumps({**GOOD, "exit_code": 0}).encode() + b"\n",
        json.dumps({**GOOD, "exit_code": True}).encode() + b"\n",
        json.dumps({**GOOD, "refused_utc": "2026-10-30T12:00:00"}).encode() + b"\n",
        json.dumps({**GOOD, "command": "drive"}).encode() + b"\n",
        json.dumps({**GOOD, "engagement": {"engagement_digest": "0" * 64}}).encode() + b"\n",
        json.dumps(
            {**GOOD, "engagement": {**GOOD["engagement"], "engagement_digest": "x"}}
        ).encode()
        + b"\n",
        json.dumps(GOOD).encode(),  # cut short: no newline
        json.dumps(GOOD).encode()[:-1] + b', "reason": "draft"}\n',  # a duplicate key
    ],
)
def test_a_refusals_file_is_read_whole_or_refused_whole(tmp_path, line):
    path = tmp_path / engagement.REFUSALS_FILE
    path.write_bytes(json.dumps(GOOD).encode() + b"\n" + line)
    with pytest.raises(EngagementError) as raised:
        engagement.read_refusals(path)
    assert raised.value.source == str(path)


def test_an_empty_refusals_file_holds_no_refusal(tmp_path):
    path = tmp_path / engagement.REFUSALS_FILE
    path.write_bytes(b"")
    assert engagement.read_refusals(path) == []
    path.write_bytes(json.dumps(GOOD).encode() + b"\n")
    assert [record.to_dict() for record in engagement.read_refusals(path)] == [GOOD]
