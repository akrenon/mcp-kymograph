"""Intake: the questionnaire, the answers read strictly and leniently, and the draft file."""

from __future__ import annotations

import dataclasses
import json
import socket
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_kymograph import engagement, intake
from mcp_kymograph.engagement import EngagementRefused, GateFacts
from mcp_kymograph.intake import IntakeError

NOW = datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)


def answers() -> dict:
    """Answers to every question, two servers, one of them reached by URL."""
    return {
        "servers": [
            {
                "name": "billing",
                "reached_how": "http://mcp.example.test/mcp",
                "transport": "streamable-http",
                "version_or_commit": "3.1",
                "clients_in_use": ["Claude Desktop", "Cursor"],
                "owner_contact": "Dana, +49 30 1234",
                "may_be_run_locally": "no",
                "change_freeze": "2026-12-20 to 2027-01-06",
            },
            {
                "name": "notes-helper",
                "reached_how": "started by the client as a process",
                "transport": "stdio",
                "clients_in_use": ["Claude Desktop"],
            },
        ],
        "constraints": {
            "hours": "weekdays 09:00-17:00 Berlin",
            "rate": "once an hour",
            "do_not": ["call delete_invoice", "anything on Fridays"],
        },
        "notes": ["[don't know] is an answer too"],
    }


def write_json(directory: Path, data, name: str = "answers.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(data))
    return path


def write_draft(directory: Path, data: dict, engagement_id: str = "acme-2026-11") -> Path:
    loaded = intake.read_answers(write_json(directory, data))
    text, _ = intake.draft(loaded, engagement_id=engagement_id)
    path = directory / "engagement.json"
    path.write_text(text)
    return path


def refused(path: Path) -> IntakeError:
    with pytest.raises(IntakeError) as raised:
        intake.read_answers(path)
    assert raised.value.source == str(path)
    assert str(raised.value).startswith(f"{path}: ")
    return raised.value


# -- the questionnaire ---------------------------------------------------------------------------


def test_the_questions_are_the_declared_blocks_keys_but_the_operators_entry():
    assert frozenset(intake.SERVER_FIELDS) == engagement.DECLARED_SERVER_KEYS - {"entry"}
    assert frozenset(intake.CONSTRAINT_FIELDS) == engagement.CONSTRAINT_KEYS


def test_the_questionnaire_says_nothing_is_checked_and_asks_every_question():
    text = intake.questionnaire()
    assert text.splitlines()[0] == (
        "# Please answer what you can; leave the rest. Nothing here is checked against your "
        "systems."
    )
    for field in (*intake.SERVER_FIELDS, *intake.CONSTRAINT_FIELDS, "notes"):
        assert f"{field}: " in text
    assert "entry" not in text


def test_the_questionnaire_read_back_is_no_answers(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "answers.yaml"
    path.write_text(intake.questionnaire())
    loaded = intake.read_answers(path)
    assert loaded.form == "yaml"
    assert loaded.data == {}
    assert loaded.is_empty


def test_the_text_questionnaire_read_back_is_no_answers(tmp_path):
    path = tmp_path / "answers.txt"
    path.write_text(intake.questionnaire_text())
    loaded = intake.read_answers(path)
    assert loaded.form == "text"
    assert loaded.data == {}
    assert loaded.unplaced == ()


def test_the_text_questionnaires_instructions_hold_no_colon_so_none_reads_as_an_answer():
    text = intake.questionnaire_text()
    assert text.splitlines()[0] == intake.HEADER
    fields = [line for line in text.splitlines() if ":" in line]
    labels = [intake._LABELS[field] for field in intake._TEXT_ORDER]
    assert fields == [f"{label}:" for label in labels]


def test_the_questionnaire_is_written_without_yaml(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    assert intake.questionnaire().startswith("# Please answer")
    assert intake.questionnaire_text().startswith("Please answer")


# -- strict answers ------------------------------------------------------------------------------


def test_json_answers_are_read_as_written(tmp_path):
    loaded = intake.read_answers(write_json(tmp_path, answers()))
    assert loaded.form == "json"
    assert loaded.data == answers()


def test_yaml_answers_filled_into_the_questionnaire_are_read(tmp_path):
    pytest.importorskip("yaml")
    filled = (
        intake.questionnaire()
        .replace('name: ""', 'name: "billing"', 1)
        .replace('reached_how: ""', 'reached_how: "http://mcp.example.test/mcp"', 1)
        .replace("clients_in_use: []", 'clients_in_use: ["Cursor"]', 1)
        .replace('hours: ""', "hours: 09:00-17:00", 1)
    )
    path = tmp_path / "answers.yml"
    path.write_text(filled)
    assert intake.read_answers(path).data == {
        "servers": [
            {
                "name": "billing",
                "reached_how": "http://mcp.example.test/mcp",
                "clients_in_use": ["Cursor"],
            }
        ],
        "constraints": {"hours": "09:00-17:00"},
    }


def test_an_open_question_is_no_answer_and_a_server_with_none_is_left_out(tmp_path):
    data = {
        "servers": [
            {"name": "", "transport": None, "clients_in_use": []},
            {"name": "kept", "clients_in_use": ["", "Cursor", None]},
        ],
        "constraints": {"hours": ""},
        "notes": [],
    }
    loaded = intake.read_answers(write_json(tmp_path, data))
    assert loaded.data == {"servers": [{"name": "kept", "clients_in_use": ["Cursor"]}]}


@pytest.mark.parametrize(
    ("data", "words"),
    [
        ([], "the answers must be a mapping"),
        ({"server": []}, "unknown key 'server'"),
        ({"servers": {}}, "servers: expected a list"),
        ({"servers": ["billing"]}, "servers[0]: expected a mapping"),
        ({"servers": [{"name": "a", "entry": "x"}]}, "servers[0]: unknown key 'entry'"),
        ({"servers": [{"version_or_commit": 3.1}]}, "servers[0].version_or_commit: 3.1 is not"),
        ({"servers": [{"may_be_run_locally": True}]}, 'put the answer in quotes, as "true"'),
        ({"servers": [{"clients_in_use": ["a", 2]}]}, "servers[0].clients_in_use[1]: 2 is not"),
        ({"servers": [{"transport": {"a": "b"}}]}, "servers[0].transport: expected a string"),
        ({"constraints": []}, "constraints: expected a mapping"),
        ({"constraints": {"window": "x"}}, "constraints: unknown key 'window'"),
        ({"constraints": {"do_not": [["nested"]]}}, "constraints.do_not[0]: expected a string"),
        ({"notes": "one note"}, "notes: expected a list of strings"),
        ({"notes": ["a", 1]}, "notes[1]: 1 is not text"),
    ],
)
def test_strict_answers_are_refused_whole_naming_the_file_and_the_place(tmp_path, data, words):
    assert words in refused(write_json(tmp_path, data)).reason


def test_unparseable_json_is_refused_with_the_line(tmp_path):
    path = tmp_path / "answers.json"
    path.write_text('{"servers": [\n  {"name": }\n]}')
    assert refused(path).reason.startswith("line 2 column")


def test_a_duplicate_yaml_key_and_an_alias_are_refused(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "answers.yaml"
    path.write_text("notes: []\nnotes: []\n")
    assert "duplicate key 'notes'" in refused(path).reason
    path.write_text('constraints:\n  hours: &h "9-17"\n  rate: *h\n')
    reason = refused(path).reason
    assert "aliases are not allowed in the answers" in reason
    assert "scenario" not in reason


def test_yaml_answers_without_the_extra_are_refused_with_words(tmp_path, monkeypatch):
    path = tmp_path / "answers.yaml"
    path.write_text(intake.questionnaire())
    monkeypatch.setitem(sys.modules, "yaml", None)
    reason = refused(path).reason
    assert "mcp-kymograph[yaml]" in reason
    assert "write the answers as .json" in reason


@pytest.mark.parametrize(
    ("name", "content", "words"),
    [
        ("answers.toml", b"", "unknown suffix '.toml'"),
        ("answers.json", b"\xff{}", "not UTF-8 at byte 0"),
        ("answers.txt", b"Transport: \xc3(", "not UTF-8 at byte 11"),
        ("answers.json", b" " * (intake.MAX_FILE_BYTES + 1), "larger than"),
    ],
)
def test_a_file_that_cannot_be_read_as_answers_is_refused(tmp_path, name, content, words):
    path = tmp_path / name
    path.write_bytes(content)
    assert words in refused(path).reason


def test_a_missing_file_is_refused_with_its_name(tmp_path):
    assert "cannot read" in refused(tmp_path / "nowhere.json").reason


# -- the text form, leniently --------------------------------------------------------------------


def read_text(tmp_path: Path, text: str) -> intake.Answers:
    path = tmp_path / "answers.txt"
    path.write_bytes(text.encode("utf-8"))
    return intake.read_answers(path)


def test_the_text_form_places_each_line_it_can_and_keeps_the_rest_verbatim(tmp_path):
    loaded = read_text(
        tmp_path,
        "Server name: billing\n"
        "Reached how: http://mcp.example.test/mcp\n"
        "Client in use: Claude Desktop\n"
        "client in use:   Cursor  \n"
        "  we also run a staging copy, ask Dana  \n"
        "\n"
        "SERVER NAME: notes-helper\n"
        "reached_how: started by the client as a process\n"
        "Transport: stdio\n"
        "Transport: or maybe http?\n"
        "\n"
        "Hours: 09:00-17:00\n"
        "Do not: call delete_invoice\n"
        "Do not: anything on Fridays\n"
        "Note: the second server is new\n"
        "Colour: blue\n",
    )
    assert loaded.data == {
        "servers": [
            {
                "name": "billing",
                "reached_how": "http://mcp.example.test/mcp",
                "clients_in_use": ["Claude Desktop", "Cursor"],
            },
            {
                "name": "notes-helper",
                "reached_how": "started by the client as a process",
                "transport": "stdio",
            },
        ],
        "constraints": {
            "hours": "09:00-17:00",
            "do_not": ["call delete_invoice", "anything on Fridays"],
        },
        "notes": [
            "  we also run a staging copy, ask Dana  ",
            "Transport: or maybe http?",
            "the second server is new",
            "Colour: blue",
        ],
    }
    assert loaded.unplaced == (5, 10, 16)


def test_a_second_server_name_in_one_block_begins_the_next_server(tmp_path):
    loaded = read_text(
        tmp_path, "Server name: a\nTransport: stdio\nServer name: b\nTransport: stdio\n"
    )
    assert loaded.data == {
        "servers": [
            {"name": "a", "transport": "stdio"},
            {"name": "b", "transport": "stdio"},
        ]
    }


def test_the_filled_in_text_questionnaire_keeps_its_instructions_out_of_the_notes(tmp_path):
    filled = (
        intake.questionnaire_text()
        .replace("Server name:\n", "Server name: billing\n")
        .replace("Rate:\n", "Rate: once an hour\n")
    )
    loaded = read_text(tmp_path, "﻿" + filled.replace("\n", "\r\n"))
    assert loaded.data == {
        "servers": [{"name": "billing"}],
        "constraints": {"rate": "once an hour"},
    }


def test_a_hostile_line_is_refused_and_kept_nowhere(tmp_path):
    hostile = [
        "Server name: billing\x1b[2K\x1b[1Aevil",
        "Reached how: http://mcp.example.test‮/mcp",
        "Hours: 9-17\x00",
        "Rate:\rhourly",
    ]
    loaded = read_text(tmp_path, "\n".join(hostile) + "\n")
    assert loaded.data == {}
    assert loaded.unplaced == ()
    assert [number for number, _ in loaded.refused] == [1, 2, 3, 4]
    with pytest.raises(
        IntakeError, match=r"line 1 \(name\): holds a character of the category control \(Cc\)"
    ) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert "3 more" in str(raised.value) and "evil" not in str(raised.value)


def test_a_url_in_an_answer_with_an_unprintable_character_is_not_read(tmp_path):
    data = {"servers": [{"reached_how": "http://mcp.example.test​/mcp"}]}
    draft = json.loads(write_draft(tmp_path, data).read_text())
    assert draft["targets"] == [{"host": "[HOST OF SERVER 1]"}]
    assert draft["declared"] == data


# -- the draft -----------------------------------------------------------------------------------


def test_the_draft_loads_as_a_draft_and_the_gate_refuses_it(tmp_path):
    loaded = engagement.load(write_draft(tmp_path, answers()))
    assert loaded.is_draft
    assert loaded.id == "acme-2026-11"
    assert loaded.version == 2
    assert set(loaded.placeholders) == {
        "end_customer.name",
        "abort_criteria[0]",
        "emergency.name",
        "emergency.reach",
        "salt_env",
        "reference",
        "contacts[0].name",
        "contacts[0].role",
        "contacts[0].reach",
        "window.from",
        "window.until",
        "targets[1].host",
        "retention.delete_after",
    }
    with pytest.raises(EngagementRefused) as raised:
        engagement.check(
            loaded,
            GateFacts(command="drive", http_url="http://mcp.example.test/mcp", script_lists=True),
            NOW,
        )
    assert raised.value.condition == "draft"
    assert "DRAFT" in engagement.render(loaded)


def test_the_answers_go_under_declared_unchanged(tmp_path):
    loaded = engagement.load(write_draft(tmp_path, answers()))
    assert loaded.data["declared"] == answers()


def test_yaml_answers_round_trip_into_declared(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "answers.yaml"
    path.write_text(yaml.safe_dump(answers(), sort_keys=False))
    text, _ = intake.draft(intake.read_answers(path), engagement_id="acme-2026-11")
    out = tmp_path / "engagement.json"
    out.write_text(text)
    assert engagement.load(out).data["declared"] == answers()


def test_a_url_answer_gives_a_target_with_its_host_and_its_path(tmp_path):
    loaded = engagement.load(write_draft(tmp_path, answers()))
    first = loaded.targets[0]
    assert (first.host, first.ports, first.paths) == ("mcp.example.test", (80,), ("/mcp",))
    assert not first.ports_defaulted
    assert loaded.targets[1].name is None


def test_every_placeholder_is_named_on_the_missing_list(tmp_path):
    loaded = intake.read_answers(write_json(tmp_path, answers()))
    text, missing = intake.draft(loaded, engagement_id="acme-2026-11")
    path = tmp_path / "engagement.json"
    path.write_text(text)
    named = {line.split(": ", 1)[0] for line in missing}
    assert set(engagement.load(path).placeholders) <= named
    assert {"actions", "scenarios", "pacing", "declared.servers[1].entry"} <= named
    assert any("'notes-helper'" in line for line in missing)


def test_urls_are_read_off_the_customers_words(tmp_path):
    data = {
        "servers": [
            {"name": "a", "reached_how": "via VPN at <http://10.0.0.5:8080/mcp>, see wiki."},
            {"name": "b", "reached_how": ["https://mcp.example.test/v2", "http://[::1]:9000"]},
            {"name": "c", "reached_how": "http://10.0.0.5:8080/other"},
            {"name": "d", "reached_how": "http://user:secret@mcp.example.test/mcp"},
            {"name": "e", "reached_how": "ws://mcp.example.test/socket"},
            {"name": "f", "reached_how": "http://MCP.example.test/caf%C3%A9?x=1#top"},
            {"name": "g", "reached_how": "http://mcp.example.test/café"},
        ]
    }
    loaded = intake.read_answers(write_json(tmp_path, data))
    text, missing = intake.draft(loaded, engagement_id="acme-2026-11")
    assert json.loads(text)["targets"] == [
        {"host": "10.0.0.5", "ports": [8080], "paths": ["/mcp", "/other"]},
        {"host": "mcp.example.test", "ports": [443], "paths": ["/v2"]},
        {"host": "[::1]", "ports": [9000], "paths": ["/"]},
        {"host": "[HOST OF SERVER 4]"},
        {"host": "[HOST OF SERVER 5]"},
        {"host": "mcp.example.test", "ports": [80], "paths": ["/caf%C3%A9"]},
        {"host": "[HOST OF SERVER 7]"},
    ]
    plain = [line.split(":", 1)[0] for line in missing if "over plain HTTP" in line]
    assert plain == ["targets[0]", "targets[0]", "targets[5]"], "https:// and [::1] add none"
    assert any(line.startswith("targets[2].paths: '/' is listed") for line in missing)
    path = tmp_path / "engagement.json"
    path.write_text(text)
    assert engagement.load(path).is_draft


def plain_http_lines(tmp_path: Path, url: str) -> list[str]:
    data = {"servers": [{"name": "a", "reached_how": url}]}
    _, missing = intake.draft(
        intake.read_answers(write_json(tmp_path, data)), engagement_id="acme-2026-11"
    )
    return [line for line in missing if "plain HTTP" in line]


@pytest.mark.parametrize(
    "url",
    ["https://mcp.example.test/mcp", "https://127.0.0.1:8443/mcp", "HTTPS://10.0.0.5:8443/mcp"],
)
def test_an_https_url_adds_no_line(tmp_path, url):
    assert plain_http_lines(tmp_path, url) == []


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/mcp", "http://[::1]:9000/mcp"])
def test_plain_http_to_a_loopback_literal_adds_no_line(tmp_path, url):
    assert plain_http_lines(tmp_path, url) == []


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("http://localhost:8080/mcp", "localhost"),
        ("http://mcp.example.test/mcp", "mcp.example.test"),
        ("HTTP://MCP.Example.Test:443/mcp", "mcp.example.test"),
        ("http://10.0.0.5:8080/mcp", "10.0.0.5"),
        ("http://127.0.0.2:8080/mcp", "127.0.0.2"),
        ("http://[::ffff:127.0.0.1]:8080/mcp", "[::ffff:127.0.0.1]"),
    ],
)
def test_plain_http_to_any_other_host_is_named_as_refused(tmp_path, url, host):
    """By the run's own rule (``authorization.plain_http_refusal``): localhost is
    a name, 127.0.0.2 and ::ffff:127.0.0.1 are not the literals."""
    assert plain_http_lines(tmp_path, url) == [
        f"targets[0]: declared.servers[0] ('a') is reached over plain HTTP to {host}, and a run "
        "to it would be refused: plain HTTP is spoken only to 127.0.0.1 or [::1]; "
        "the server's https:// URL is needed"
    ]


def test_no_answers_still_make_a_draft_that_loads(tmp_path):
    loaded = engagement.load(write_draft(tmp_path, {}))
    assert "targets[0].host" in loaded.placeholders
    assert loaded.data["declared"] == {}


def test_the_drafts_id_must_be_a_name(tmp_path):
    loaded = intake.read_answers(write_json(tmp_path, answers()))
    with pytest.raises(IntakeError, match="is not a name"):
        intake.draft(loaded, engagement_id="acme 2026/11")


def test_a_draft_that_does_not_read_back_is_refused_with_words_not_a_traceback(
    tmp_path, monkeypatch
):
    loaded = intake.read_answers(write_json(tmp_path, answers()))

    def refuses(raw, **kwargs):
        raise engagement.EngagementError("targets[0].host: missing", source=kwargs["source"])

    monkeypatch.setattr(engagement, "loads", refuses)
    with pytest.raises(IntakeError) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert "does not read back" in str(raised.value)
    assert "targets[0].host: missing" in str(raised.value)
    assert "fault in intake" in str(raised.value)


def test_a_draft_whose_placeholders_are_not_the_listed_ones_is_refused(tmp_path, monkeypatch):
    loaded = intake.read_answers(write_json(tmp_path, answers()))
    real = engagement.loads
    monkeypatch.setattr(
        engagement,
        "loads",
        lambda raw, **kwargs: dataclasses.replace(real(raw, **kwargs), placeholders=("customer",)),
    )
    with pytest.raises(IntakeError, match="not at the ones listed as missing"):
        intake.draft(loaded, engagement_id="acme-2026-11")


def test_the_draft_is_json_and_needs_no_yaml(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    loaded = engagement.load(write_draft(tmp_path, answers()))
    assert loaded.source.endswith(".json")


def test_nothing_reaches_a_network(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("intake reached for the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "gethostbyname", no_network)
    path = tmp_path / "answers.txt"
    path.write_text("Server name: billing\nReached how: http://mcp.example.test/mcp\n")
    text, _ = intake.draft(intake.read_answers(path), engagement_id="acme-2026-11")
    out = tmp_path / "engagement.json"
    out.write_text(text)
    assert engagement.load(out).targets[0].host == "mcp.example.test"


# -- the second version's answers ----------------------------------------------------------------

#: A value for a test, put together at run time.
KNOWN = "kv" + "-".join(["secret", "7q2x"])


def made_up(prefix: str) -> str:
    return prefix + "-".join(["9f3k", "27xq", "m4w8"])


PREFIX = "Zm9vYmFyYmF6cXV4MTIzNDU2"


def fields() -> dict:
    """Answers to every question of the second version."""
    return {
        "customer": "ACME Corp",
        "agency": "Example Agency",
        "agency_contacts": ["Kim | PM | kim@agency.test"],
        "tools": ["search | read-only", "create_note | writes"],
        "abort_criteria": ["any write to production data", "the customer asks to stop"],
        "emergency_name": "Lee Ops",
        "emergency_reach": "+49 30 5550100",
        "known_values": [KNOWN],
        "salt_env": "KYMOGRAPH_SALT",
        "canaries": ["c1 | tool_text | the search tool", "c2 | file | a file | /srv/outside/c.txt"],
        "receiver_variant": "reachable",
        "receiver_address": "recv.example.test:8443",
        "receiver_path_prefix": PREFIX,
        "receiver_key_env": "KYMOGRAPH_RECEIVER_KEY",
        "receiver_ssh": "<RECEIVER_SSH>",
        "receiver_retention_seconds": "86400",
        "token_passthrough": "redirect",
    }


def drafted(tmp_path: Path, data: dict) -> tuple[engagement.Engagement, list[str]]:
    loaded = intake.read_answers(write_json(tmp_path, data))
    text, missing = intake.draft(loaded, engagement_id="acme-2026-11")
    path = tmp_path / "engagement.json"
    path.write_text(text)
    return engagement.load(path), missing


def test_the_questionnaire_asks_the_second_versions_questions(tmp_path):
    text = intake.questionnaire()
    for field in intake.FIELD_ORDER:
        assert f"{field}: " in text
    form = intake.questionnaire_text()
    for field in intake.FIELD_ORDER:
        assert f"{intake._LABELS[field]}:" in form.splitlines()
    path = tmp_path / "answers.txt"
    path.write_text(form)
    assert intake.read_answers(path).fields == {}


def test_every_answer_makes_a_file_of_the_second_version_that_the_reader_takes(tmp_path):
    loaded, missing = drafted(tmp_path, {**answers(), **fields()})
    assert loaded.version == 2
    assert loaded.customer == "ACME Corp"
    assert loaded.agency == "Example Agency"
    assert loaded.data["end_customer"] == {"name": "ACME Corp"}
    assert "customer" not in loaded.data
    assert loaded.data["agency"]["contacts"] == [
        {"name": "Kim", "role": "PM", "reach": "kim@agency.test"}
    ]
    assert loaded.tools == (engagement.Tool("search", False), engagement.Tool("create_note", True))
    assert loaded.abort_criteria == ("any write to production data", "the customer asks to stop")
    assert loaded.data["emergency"] == {"name": "Lee Ops", "reach": "+49 30 5550100"}
    assert loaded.known_value_count == 1
    assert loaded.salt_env == "KYMOGRAPH_SALT"
    assert [(c.id, c.kind, c.path, c.removed) for c in loaded.canaries] == [
        ("c1", "tool_text", None, None),
        ("c2", "file", "/srv/outside/c.txt", None),
    ]
    assert loaded.receiver == engagement.Receiver(
        "reachable",
        "recv.example.test:8443",
        PREFIX,
        "KYMOGRAPH_RECEIVER_KEY",
        "<RECEIVER_SSH>",
        86400,
    )
    assert loaded.token_passthrough == "redirect"  # noqa: S105 (a method, not a secret)
    assert loaded.data["declared"] == answers(), "the new answers are not under declared"
    assert set(loaded.placeholders) == {
        "reference",
        "contacts[0].name",
        "contacts[0].role",
        "contacts[0].reach",
        "window.from",
        "window.until",
        "targets[1].host",
        "retention.delete_after",
    }
    assert KNOWN not in json.dumps(missing)


def test_the_answers_of_the_second_version_ask_nothing_of_declared(tmp_path):
    loaded, _ = drafted(tmp_path, fields())
    assert loaded.data["declared"] == {}


def test_missing_answers_to_the_second_versions_required_fields_are_placeholders(tmp_path):
    loaded, missing = drafted(tmp_path, answers())
    assert {
        "end_customer.name",
        "abort_criteria[0]",
        "emergency.name",
        "emergency.reach",
        "salt_env",
    } <= set(loaded.placeholders)
    named = {line.split(": ", 1)[0] for line in missing}
    assert set(loaded.placeholders) <= named
    for absent in ("agency", "tools", "known_values", "canaries", "receiver", "token_passthrough"):
        assert absent not in loaded.data


def test_an_agency_contact_without_an_agency_name_leaves_the_name_a_placeholder(tmp_path):
    loaded, _ = drafted(tmp_path, {"agency_contacts": ["Kim"]})
    assert "agency.name" in loaded.placeholders
    assert loaded.data["agency"]["contacts"] == [{"name": "Kim"}]


def test_a_reachable_receiver_lacking_answers_gets_placeholders(tmp_path):
    loaded, _ = drafted(tmp_path, {"receiver_variant": "reachable", "receiver_ssh": "<SSH>"})
    assert {
        "receiver.address",
        "receiver.path_prefix",
        "receiver.key_env",
        "receiver.retention_seconds",
    } <= set(loaded.placeholders)
    assert loaded.receiver.ssh == "<SSH>"


def test_a_local_receiver_needs_nothing_but_its_variant(tmp_path):
    loaded, _ = drafted(tmp_path, {"receiver_variant": "local"})
    assert loaded.receiver == engagement.Receiver("local")
    assert not any(place.startswith("receiver") for place in loaded.placeholders)


def test_receiver_answers_without_a_variant_write_no_receiver_and_say_so(tmp_path):
    loaded, missing = drafted(tmp_path, {"receiver_address": "recv.example.test"})
    assert loaded.receiver is None
    (line,) = [line for line in missing if line.startswith("receiver: ")]
    assert "receiver_address" in line and "recv.example.test" not in line


def test_an_answer_in_brackets_is_no_answer(tmp_path):
    data = {"customer": "[don't know]", "tools": ["[none]", "search | read-only"]}
    loaded = intake.read_answers(write_json(tmp_path, data))
    assert loaded.fields == {"tools": ["search | read-only"]}


@pytest.mark.parametrize(
    ("data", "words"),
    [
        ({"customer": ["a", "b"]}, "customer: expected one answer"),
        ({"tools": ["search"]}, "tools[0]: expected name | writes or name | read-only"),
        ({"tools": ["search | maybe"]}, "tools[0]: whether the tool writes"),
        ({"tools": ["a | writes", "a | read-only"]}, "tools[1]: listed twice"),
        ({"canaries": ["c1 | mail | x"]}, "canaries[0]: the kind is one of"),
        ({"canaries": ["c1 | file | x"]}, "canaries[0]: a file canary names an absolute path"),
        ({"canaries": ["c1 | resource | x | /p"]}, "canaries[0]: a canary of kind resource"),
        ({"canaries": ["c 1 | resource | x"]}, "canaries[0]: the id is not a name"),
        ({"canaries": ["c1 | prompt | x", "c1 | resource | y"]}, "canaries[1]: listed twice"),
        ({"known_values": ["abc"]}, "known_values[0]: shorter than 4 characters"),
        ({"known_values": ["same-one", "same-one"]}, "known_values[1]: listed twice"),
        ({"salt_env": "not a name"}, "salt_env: expected the name of an environment variable"),
        ({"receiver_variant": "public"}, "receiver_variant: expected one of local, reachable"),
        ({"receiver_address": "https://recv.example.test"}, "receiver_address: expected host"),
        ({"receiver_address": "[::1%u@evil.test]"}, "receiver_address: expected host"),
        ({"receiver_address": "[fe80::1%x?y#z]:443"}, "receiver_address: expected host"),
        ({"receiver_address": "[fe80::1%eth0]"}, "receiver_address: expected host"),
        ({"receiver_path_prefix": "short"}, "receiver_path_prefix: not a path prefix"),
        ({"receiver_key_env": "a key"}, "receiver_key_env: expected the name"),
        ({"receiver_retention_seconds": "0"}, "receiver_retention_seconds: expected a whole"),
        ({"token_passthrough": "copy"}, "token_passthrough: expected one of redirect"),
    ],
)
def test_a_wrong_answer_of_the_second_version_is_refused_with_the_place(tmp_path, data, words):
    assert words in refused(write_json(tmp_path, data)).reason


@pytest.mark.parametrize(
    "data",
    [
        {"known_values": [47110815]},
        {"known_values": [4711.0815]},
        {"known_values": [True]},
        {"known_values": [["47110815"]]},
        {"known_values": 47110815},
        {"salt_env": 47110815},
        {"salt_env": [47110815]},
        {"receiver_key_env": 47110815},
        {"receiver_ssh": 47110815},
        {"receiver_path_prefix": 47110815},
        {"emergency_reach": 47110815},
        {"emergency_reach": 4711.0815},
        {"emergency_reach": False},
        {"emergency_reach": {"a": 47110815}},
    ],
)
def test_a_secret_answer_of_the_wrong_type_is_refused_without_repeating_it(tmp_path, data):
    reason = refused(write_json(tmp_path, data)).reason
    assert next(iter(data)) in reason and "expected a string" in reason
    for written in ("47110815", "4711.0815", "4711", "0815", "true", "True", "false", "False"):
        assert written not in reason


def test_a_refusal_never_repeats_a_known_value_or_a_wrong_variable(tmp_path):
    for data in ({"known_values": ["abc"]}, {"salt_env": "hunter 2 secret"}):
        reason = refused(write_json(tmp_path, data)).reason
        assert "abc" not in reason and "hunter" not in reason


def test_the_text_form_places_the_second_versions_lines_unchecked_and_draft_refuses_them(tmp_path):
    loaded = read_text(
        tmp_path,
        "Customer: ACME Corp\n"
        "Tool: search | read-only\n"
        "Tool: create_note | writes\n"
        "Stop if: any write\n"
        f"Known value: {KNOWN}\n"
        "Known value: abc\n"
        "Receiver: reachable\n"
        "Salt variable: KYMOGRAPH_SALT\n"
        "Salt variable: ANOTHER\n",
    )
    assert loaded.unplaced == ()
    assert "notes" not in loaded.data
    assert loaded.fields["tools"] == ["search | read-only", "create_note | writes"]
    assert loaded.fields["salt_env"] == ["KYMOGRAPH_SALT", "ANOTHER"]
    with pytest.raises(
        IntakeError, match=r"known_values\[1\]: shorter than 4 characters"
    ) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert KNOWN not in str(raised.value)


SECRET_LINES = [
    ("Known value", "known_values"),
    ("Receiver path prefix", "receiver_path_prefix"),
    ("Salt variable", "salt_env"),
    ("Receiver key variable", "receiver_key_env"),
]


@pytest.mark.parametrize("character", ["\u00ad", "\u200b", "\x07"])  # Cf, Cf, Cc
@pytest.mark.parametrize(("label", "field"), SECRET_LINES)
def test_a_line_of_a_secret_field_with_an_unprintable_character_is_refused_and_kept_nowhere(
    tmp_path, label, field, character
):
    value = made_up("sv")
    loaded = read_text(
        tmp_path, f"Customer: ACME Corp\n{label}: {value[:5]}{character}{value[5:]}\n"
    )
    assert loaded.refused == ((2, field),)
    assert loaded.unplaced == () and "notes" not in loaded.data and field not in loaded.fields
    with pytest.raises(IntakeError) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert f"line 2 ({field})" in str(raised.value)
    for part in (value, value[:5], value[5:], value[:3]):
        assert part not in str(raised.value) and part not in repr(loaded)


def test_an_unprintable_character_in_the_label_of_a_secret_line_is_refused_too(tmp_path):
    value = made_up("sv")
    loaded = read_text(tmp_path, f"Known\u00ad value: {value}\nKnown\u200b value:{value}\n")
    assert loaded.refused == ((1, "known_values"), (2, "known_values"))
    assert loaded.unplaced == () and "notes" not in loaded.data
    with pytest.raises(IntakeError, match=r"line 1 \(known_values\).*1 more") as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert value not in str(raised.value) and value not in repr(loaded)


def test_a_label_cut_by_an_invisible_character_is_refused_too(tmp_path):
    value = made_up("sv")
    loaded = read_text(tmp_path, f"Known\u200bvalue: {value}\n")
    assert loaded.refused == ((1, ""),)
    assert loaded.unplaced == () and "notes" not in loaded.data and not loaded.fields
    with pytest.raises(
        IntakeError, match=r"line 1: holds a character of the category format \(Cf\)"
    ) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    for part in (value, value[:5], "\u200b", "u200b"):
        assert part not in str(raised.value) and part not in repr(loaded)


@pytest.mark.parametrize(
    ("line", "field"),
    [
        ("A note about the\x07 weekend: {v}", ""),
        ("Server name\u00ad: {v}", "name"),
        ("Rate: {v}\u00ad", "rate"),
        ("Customer\u00ad: {v}", "customer"),
        ("Customer:\u00ad{v}", "customer"),
    ],
)
def test_an_unprintable_free_note_or_older_field_line_is_refused_and_kept_nowhere(
    tmp_path, line, field
):
    value = made_up("sv")
    loaded = read_text(tmp_path, "Hours: nights only\n" + line.format(v=value) + "\n")
    assert loaded.refused == ((2, field),)
    assert loaded.unplaced == () and "notes" not in loaded.data
    assert loaded.data == {"constraints": {"hours": "nights only"}}
    with pytest.raises(IntakeError, match=r"line 2") as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    for part in (value, value[:5], "\x07", "\u00ad"):
        assert part not in str(raised.value) and part not in repr(loaded)


@pytest.mark.parametrize("line", ["\x0b", "\x0c", "\x1c", "\x1f", "\x85", " \x1c ", "\t\x85"])
def test_a_line_of_nothing_but_controlling_white_space_is_refused_not_blank(tmp_path, line):
    loaded = read_text(tmp_path, f"Hours: nights only\n{line}\nCustomer: ACME\n")
    assert loaded.refused == ((2, ""),)
    assert loaded.unplaced == () and "notes" not in loaded.data
    with pytest.raises(IntakeError, match=r"line 2: holds a character of the category control"):
        intake.draft(loaded, engagement_id="acme-2026-11")


def test_a_line_ending_is_no_part_of_a_blank_line(tmp_path):
    loaded = read_text(tmp_path, "Hours: nights only\r\n \t\r\n\r\nCustomer: ACME\r\n")
    assert loaded.refused == () and loaded.unplaced == ()


def unassigned() -> str:
    """A code point the installed Unicode database does not assign."""
    return next(chr(code) for code in range(0x10FFFF) if unicodedata.category(chr(code)) == "Cn")


def refusal_of(tmp_path, line: str) -> str:
    loaded = read_text(tmp_path, f"Hours: nights only\n{line}\n")
    with pytest.raises(IntakeError) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    return str(raised.value)


@pytest.mark.parametrize(
    ("character", "named"),
    [
        ("\x07", "category control (Cc)"),
        ("\u00ad", "category format (Cf)"),
        ("\ue000", "category private use (Co)"),
        (None, "category unassigned (Cn)"),
        ("\x07\u200b", "categories control (Cc), format (Cf)"),
        ("\u200b\x07\u00ad\ue000\x07", "categories control (Cc), format (Cf), private use (Co)"),
    ],
)
def test_the_refusal_names_the_categories_found_and_not_the_characters(tmp_path, character, named):
    character = unassigned() if character is None else character
    message = refusal_of(tmp_path, f"Rate: a{character}b")
    assert f"line 2 (rate): holds a character of the {named}, which is not allowed" in message
    for part in (character, "a" + character, "Rate"):
        assert part not in message


def test_a_lone_surrogate_is_named_as_surrogate_where_a_line_can_hold_one():
    # A file is decoded as UTF-8, which has no lone surrogate; a string handed to the reader does.
    *_, refused, categories = intake._read_text("Hours: nights only\nRate: a\ud800b\n")
    assert refused == ((2, "rate"),) and categories == (("Cs",),)
    answers = intake.Answers(
        source="answers.txt",
        form="text",
        data={},
        refused=refused,
        refused_categories=categories,
    )
    with pytest.raises(IntakeError) as raised:
        intake.draft(answers, engagement_id="acme-2026-11")
    assert "category surrogate (Cs), which" in str(raised.value)
    assert "ud800" not in str(raised.value).lower()


def test_blank_and_space_only_lines_stay_as_they_are(tmp_path):
    loaded = read_text(tmp_path, "Hours: nights only\n   \n\t\nCustomer: ACME\n")
    assert loaded.refused == () and loaded.unplaced == ()


def test_the_text_form_with_one_answer_each_makes_a_file(tmp_path):
    loaded = read_text(
        tmp_path,
        "Customer: ACME Corp\nStop if: any write\nTool: search | read-only\n"
        "Salt variable: KYMOGRAPH_SALT\nEmergency contact: Lee\nEmergency reach: 555\n",
    )
    text, _ = intake.draft(loaded, engagement_id="acme-2026-11")
    path = tmp_path / "engagement.json"
    path.write_text(text)
    held = engagement.load(path)
    assert held.customer == "ACME Corp" and held.salt_env == "KYMOGRAPH_SALT"
    assert held.tools == (engagement.Tool("search", False),)


# -- close labels of secret fields, the bound of the retention ---------------------------------


def near_refusal(tmp_path, line: str) -> tuple[intake.Answers, str]:
    loaded = read_text(tmp_path, f"Hours: nights only\n{line}\n")
    with pytest.raises(IntakeError) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    return loaded, str(raised.value)


@pytest.mark.parametrize(
    ("line", "field"),
    [
        ("Known value 2: {v}", "known_values"),
        ("Known value (prod): {v}", "known_values"),
        ("- Known value: {v}", "known_values"),
        ("1) Known value {v}", "known_values"),
        ("KNOWN-VALUES = {v}", "known_values"),
        ("Known-Value 2 = {v}", "known_values"),
        ("KNOWN VALUES (prod): {v}", "known_values"),
        ("Emergency reach (night) {v}", "emergency_reach"),
        ("Receiver path prefix 2: {v}", "receiver_path_prefix"),
        ("receiver_path_prefix = {v}", "receiver_path_prefix"),
        ("Salt variable (old): {v}", "salt_env"),
    ],
)
def test_a_line_that_begins_like_a_secret_label_is_refused_and_kept_nowhere(tmp_path, line, field):
    value = made_up("sv")
    loaded, message = near_refusal(tmp_path, line.format(v=value))
    assert loaded.refused == ((2, field),) and loaded.refused_categories == ((),)
    assert loaded.unplaced == () and "notes" not in loaded.data
    assert loaded.data == {"constraints": {"hours": "nights only"}} and not loaded.fields
    assert f"line 2 ({field})" in message
    assert f"'{intake._LABELS[field]}: <value>'" in message and "one line for each" in message
    for part in (value, value[:5], value[5:]):
        assert part not in message and part not in repr(loaded)


def test_a_note_that_only_mentions_a_secret_label_later_stays_a_note(tmp_path):
    loaded = read_text(tmp_path, "Hours: nights only\nNote: Known value 2 is rotated monthly\n")
    assert loaded.refused == () and loaded.unplaced == ()
    assert loaded.data["notes"] == ["Known value 2 is rotated monthly"]


def test_a_false_alarm_is_the_safe_direction(tmp_path):
    loaded, message = near_refusal(tmp_path, "Known values are rotated monthly")
    assert loaded.refused == ((2, "known_values"),) and "notes" not in loaded.data
    assert "line 2 (known_values)" in message


def test_a_line_written_exactly_is_placed_as_before(tmp_path):
    value = made_up("sv")
    loaded = read_text(tmp_path, f"Known value: {value}\nKnown values: {value}x\n")
    assert loaded.refused == () and loaded.unplaced == ()
    assert loaded.fields == {"known_values": [value, value + "x"]}


def test_the_questionnaire_text_is_no_close_label(tmp_path):
    path = tmp_path / "answers.txt"
    path.write_text(intake.questionnaire_text())
    assert intake.read_answers(path).refused == ()


@pytest.mark.parametrize(
    ("seconds", "good"), [("7776000", True), ("7776001", False), ("9" * 5000, False)]
)
def test_the_retention_of_the_intake_is_at_most_90_days(tmp_path, seconds, good):
    data = {"receiver_variant": "local", "receiver_retention_seconds": seconds}
    if good:
        assert intake._read("receiver_retention_seconds", seconds, "x") == 7_776_000
        return
    reason = refused(write_json(tmp_path, data)).reason
    assert "receiver_retention_seconds: expected a whole number of seconds, from 1 to 7776000" in (
        reason
    )
    assert seconds not in reason


def test_5000_digits_of_the_text_form_are_refused_with_exit_2_and_no_traceback(tmp_path, capsys):
    from mcp_kymograph import cli

    answers = tmp_path / "answers.txt"
    answers.write_text("Receiver: reachable\nReceiver retention seconds: " + "9" * 5000 + "\n")
    out = tmp_path / "engagement.json"
    code = cli.main(
        ["engagement", "intake", "--from", str(answers), "--id", "x1", "--out", str(out)]
    )
    captured = capsys.readouterr()
    assert code == 2 and not out.exists()
    assert "receiver_retention_seconds" in captured.err and "7776000" in captured.err
    assert "Traceback" not in captured.err and "9" * 50 not in captured.err


@pytest.mark.parametrize(
    ("line", "field"),
    [
        ("RECEİVER PATH PREFIX: {v}", "receiver_path_prefix"),
        ("Récéiver path prefix 2: {v}", "receiver_path_prefix"),
        ("ＫＮＯＷＮ VALUE: {v}", "known_values"),
        ("ſalt variable: {v}", "salt_env"),
    ],
)
def test_a_close_label_of_other_unicode_spelling_is_refused_without_its_value(
    tmp_path, line, field
):
    value = made_up("sv")
    loaded, message = near_refusal(tmp_path, line.format(v=value))
    assert loaded.refused == ((2, field),) and loaded.unplaced == ()
    assert "notes" not in loaded.data
    for part in (value, value[:5], value[5:]):
        assert part not in message and part not in repr(loaded)


@pytest.mark.parametrize(("text", "seconds"), [("00003600", 3600), ("0" * 5000 + "1", 1)])
def test_leading_zeros_of_the_retention_do_not_count(text, seconds):
    assert intake._read("receiver_retention_seconds", text, "x") == seconds


@pytest.mark.parametrize("text", ["0000", "0", "9" * 5000, "0" * 5000])
def test_a_retention_of_nothing_or_too_many_digits_is_refused_without_a_traceback(text):
    with pytest.raises(ValueError, match="from 1 to 7776000") as raised:
        intake._seconds(text)
    assert len(text) < 50 or text[:50] not in str(raised.value)


# -- short labels, ssh, an IPv6 address --------------------------------------------------------


def intake_run(tmp_path: Path, name: str, text: str, capsys) -> tuple[int, str]:
    """``engagement intake --from`` on the given answers; the exit code, and everything that
    was printed or written, joined."""
    from mcp_kymograph import cli

    answers = tmp_path / name
    answers.write_text(text)
    out = tmp_path / "engagement.json"
    code = cli.main(
        ["engagement", "intake", "--from", str(answers), "--id", "x1", "--out", str(out)]
    )
    captured = capsys.readouterr()
    assert not out.exists(), "no draft is written"
    return code, captured.out + captured.err


def long_value() -> str:
    return "zq" + "-".join(["8r4t", "k2m9", "w7xv", "p3nd"])


SHORT_LABELS = [
    ("Salt: {v}", "salt_env"),
    ("salt = {v}", "salt_env"),
    ("Receiver key: {v}", "receiver_key_env"),
    ("Key: {v}", "receiver_key_env"),
    ("Path prefix: {v}", "receiver_path_prefix"),
    ("Receiver path: {v}", "receiver_path_prefix"),
    ("Receiver prefix: {v}", "receiver_path_prefix"),
    ("Prefix: {v}", "receiver_path_prefix"),
    ("Path: {v}", "receiver_path_prefix"),
    ("Known: {v}", "known_values"),
    ("Emergency: {v}", "emergency_reach"),
    ("SSH: {v}", "receiver_ssh"),
]


@pytest.mark.parametrize(("line", "field"), SHORT_LABELS)
def test_a_shortened_label_of_a_secret_field_is_refused_and_kept_nowhere(
    tmp_path, capsys, line, field
):
    value = long_value()
    text = f"Hours: nights only\n{line.format(v=value)}\n"
    code, shown = intake_run(tmp_path, "answers.txt", text, capsys)
    assert code == 2
    assert f"line 2 ({field})" in shown
    assert "Traceback" not in shown
    for part in (value, value[:6], value[6:]):
        assert part not in shown
    assert [f.name for f in tmp_path.iterdir()] == ["answers.txt"], "no file but the answers"


def test_a_placed_field_or_a_note_is_not_taken_for_a_shortened_label(tmp_path):
    loaded = read_text(
        tmp_path, "Emergency contact: Jo\nNote: Salt rotates monthly\nHours: nights only\n"
    )
    assert loaded.refused == () and loaded.unplaced == ()
    assert loaded.fields == {"emergency_name": "Jo"}
    assert loaded.data["notes"] == ["Salt rotates monthly"]


def test_a_line_that_merely_begins_with_a_short_start_is_a_false_alarm_on_purpose(tmp_path):
    loaded, message = near_refusal(tmp_path, "Keycloak is our IdP")
    assert loaded.refused == ((2, "receiver_key_env"),)
    assert "Keycloak" not in message
    assert read_text(tmp_path, "Note: Keycloak is our IdP\n").refused == ()


def a_key() -> list[str]:
    """The lines of a private key file, put together at run time."""
    return [
        "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----",
        "b3BlbnNzaC1rZXktdjE" + long_value(),
        "-----END " + "OPENSSH PRIVATE KEY" + "-----",
    ]


def test_a_key_in_receiver_ssh_of_the_text_form_is_refused_whole_and_kept_nowhere(tmp_path, capsys):
    lines = a_key()
    text = "Hours: nights only\nReceiver: reachable\nReceiver ssh: " + "\n".join(lines) + "\n"
    code, shown = intake_run(tmp_path, "answers.txt", text, capsys)
    assert code == 2 and "receiver_ssh" in shown
    for line in lines:
        assert line not in shown and line[10:30] not in shown
    assert not [f for f in tmp_path.iterdir() if f.name != "answers.txt"]


def test_a_key_in_receiver_ssh_of_the_yaml_form_is_refused_whole_and_kept_nowhere(tmp_path, capsys):
    pytest.importorskip("yaml")
    lines = a_key()
    text = "receiver_ssh: |\n" + "".join(f"  {line}\n" for line in lines)
    code, shown = intake_run(tmp_path, "answers.yaml", text, capsys)
    assert code == 2 and "receiver_ssh" in shown
    for line in lines:
        assert line not in shown and line[10:30] not in shown
    assert not [f for f in tmp_path.iterdir() if f.name != "answers.yaml"]


def test_a_key_as_the_only_line_of_receiver_ssh_is_refused_with_the_place(tmp_path):
    reason = refused(write_json(tmp_path, {"receiver_ssh": a_key()[0]})).reason
    assert "receiver_ssh: expected a reference" in reason and "PRIVATE" not in reason


@pytest.mark.parametrize("address", ["[2001:db8::7]", "[fe80::1]", "[2001:db8::7]:8443"])
def test_an_ipv6_address_with_letters_is_drafted_as_an_address(tmp_path, address):
    data = {"receiver_variant": "reachable", "receiver_address": address}
    loaded, missing = drafted(tmp_path, data)
    assert loaded.receiver.address == address
    assert "receiver.address" not in loaded.placeholders
    assert not any("receiver.address" in item for item in missing)


def test_an_ipv6_reference_in_ssh_is_drafted_and_a_bracketed_placeholder_is_no_answer(tmp_path):
    loaded, missing = drafted(
        tmp_path,
        {
            "receiver_variant": "reachable",
            "receiver_ssh": "dev@[2001:db8::7]",
            "receiver_address": "[RECEIVER ADDRESS]",
        },
    )
    assert loaded.receiver.ssh == "dev@[2001:db8::7]"
    assert "receiver.address" in loaded.placeholders


@pytest.mark.parametrize("ssh", ["[fe80::1%eth0]", "dev@[fe80::1%eth0]"])
def test_a_scope_id_in_receiver_ssh_is_refused_with_its_place_and_not_its_value(tmp_path, ssh):
    data = {"receiver_variant": "reachable", "receiver_ssh": ssh}
    reason = refused(write_json(tmp_path, data)).reason
    assert reason.startswith("receiver_ssh: expected a reference")
    assert "eth0" not in reason and "fe80" not in reason
    loaded = read_text(tmp_path, f"Receiver: reachable\nReceiver ssh: {ssh}\n")
    assert loaded.fields["receiver_ssh"] == ssh
    with pytest.raises(IntakeError, match="receiver_ssh: expected a reference") as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert "eth0" not in str(raised.value) and "fe80" not in str(raised.value)


def test_the_hint_of_receiver_ssh_names_the_reference_form():
    assert intake._HINTS["receiver_ssh"].endswith(", or <NAME>")


# -- a line directly under a secret field --------------------------------------------------------

#: A private key's frame, put together at run time.
KEY_BEGIN = "-----" + "BEGIN OPENSSH " + "PRIVATE KEY" + "-----"
KEY_END = "-----" + "END OPENSSH " + "PRIVATE KEY" + "-----"
BODY = [made_up("b3") + "A" * 40, made_up("q9") + "B" * 40]

#: The lines of an answer file, the numbers (from 1) of the lines refused and their field.
BELOW_SECRET = {
    "a key under a known value": (
        ["Known value: " + KEY_BEGIN, *BODY, KEY_END],
        [2, 3, 4],
        "known_values",
    ),
    "a key under an emergency reach": (
        ["Emergency reach: " + KEY_BEGIN, *BODY, KEY_END],
        [2, 3, 4],
        "emergency_reach",
    ),
    "a value under an empty label": (["Known value:", BODY[0]], [2], "known_values"),
    "a line under a salt variable": (["Salt variable: MY_SALT", BODY[1]], [2], "salt_env"),
    "a header of a key under a value": (
        ["Known value: " + BODY[0], "Proc-Type: 4,ENCRYPTED", BODY[1]],
        [2, 3],
        "known_values",
    ),
}


@pytest.mark.parametrize("name", BELOW_SECRET)
def test_a_line_directly_under_a_secret_field_is_refused_and_kept_nowhere(tmp_path, capsys, name):
    from mcp_kymograph import cli

    lines, numbers, field = BELOW_SECRET[name]
    text = "Hours: nights only\n" + "\n".join(lines) + "\n"
    loaded = read_text(tmp_path, text)
    shifted = [number + 1 for number in numbers]
    assert loaded.refused == tuple((number, field) for number in shifted)
    assert loaded.refused_categories == (intake._BELOW_SECRET,) * len(shifted)
    assert loaded.unplaced == () and "notes" not in loaded.data
    with pytest.raises(IntakeError) as raised:
        intake.draft(loaded, engagement_id="acme-2026-11")
    assert f"line {shifted[0]} ({field}): directly follows a line of a field that may hold a " in (
        str(raised.value)
    )
    assert "begins like the label" not in str(raised.value)
    out = tmp_path / "engagement.json"
    answers = tmp_path / "answers.txt"
    code = cli.main(
        ["engagement", "intake", "--from", str(answers), "--id", "x1", "--out", str(out)]
    )
    captured = capsys.readouterr()
    assert code == 2 and not out.exists()
    assert f"line {shifted[0]} ({field})" in captured.err
    written = "".join(p.read_text() for p in tmp_path.iterdir() if p != answers and p.is_file())
    shown = captured.out + captured.err + str(raised.value) + repr(loaded) + written
    for line in lines[1:]:
        # The first line is placed, and a piece that it shares with the line is no evidence.
        for part in (line, line[:12], line[12:]):
            assert part in lines[0] or part not in shown


@pytest.mark.parametrize(
    ("text", "notes", "fields"),
    [
        ("Known value: {v}\n\nFreier Text\n", ["Freier Text"], {"known_values": ["{v}"]}),
        ("Customer: X\nFreier Text\n", ["Freier Text"], {"customer": "X"}),
        ("Known value: {v}\nSalt variable: B\n", [], {"known_values": ["{v}"], "salt_env": "B"}),
        (
            "Known value: {v}\nNote: x\nFreier Text\n",
            ["x", "Freier Text"],
            {"known_values": ["{v}"]},
        ),
    ],
)
def test_a_line_not_directly_under_a_secret_field_stays_a_note(tmp_path, text, notes, fields):
    value = made_up("sv")
    loaded = read_text(tmp_path, text.replace("{v}", value))
    assert loaded.refused == ()
    assert loaded.data.get("notes", []) == notes
    assert loaded.fields == {key: [value] if got == ["{v}"] else got for key, got in fields.items()}
    intake.draft(loaded, engagement_id="acme-2026-11")


def test_the_limit_of_the_rule_is_the_blank_line(tmp_path):
    loaded = read_text(tmp_path, f"Known value: {KEY_BEGIN}\n\n{BODY[0]}\n")
    assert loaded.refused == () and loaded.data["notes"] == [BODY[0]]


def test_a_third_line_and_a_new_secret_line_are_refused_too(tmp_path):
    loaded = read_text(
        tmp_path, f"Salt variable: A\n{BODY[0]}\nHours: x\nKnown value: {BODY[1]}\nm\nn\n"
    )
    assert loaded.refused == ((2, "salt_env"), (5, "known_values"), (6, "known_values"))


def test_an_instruction_line_under_a_secret_field_is_passed_over(tmp_path):
    instruction = "Where a line asks for parts, separate them with a vertical bar."
    loaded = read_text(tmp_path, f"Known value: {BODY[0]}\n{instruction}\n")
    assert loaded.refused == () and loaded.unplaced == () and "notes" not in loaded.data


def test_the_questionnaire_text_says_where_free_text_goes():
    text = intake.questionnaire_text()
    assert "write on a line of its own after a blank line; it is kept as" in text


def test_a_completely_filled_in_text_questionnaire_still_reads(tmp_path):
    filled = intake.questionnaire_text()
    for field in intake.FIELD_ORDER:
        label = intake._LABELS[field]
        answer = {"receiver_variant": "local", "receiver_retention_seconds": "60"}.get(
            field, "xx_" + field
        )
        filled = filled.replace(f"{label}:\n", f"{label}: {answer}\n")
    loaded = read_text(tmp_path, filled)
    assert loaded.refused == () and loaded.unplaced == ()
    assert set(loaded.fields) == set(intake.FIELD_ORDER)


# -- many entries ------------------------------------------------------------------------------


def test_150000_known_values_are_read_and_drafted_in_time(tmp_path, monkeypatch):
    import time

    # The cap on a file is lifted: it is what keeps a real file small, not what is under test.
    monkeypatch.setattr(intake, "MAX_FILE_BYTES", 1 << 26)
    monkeypatch.setattr(engagement, "MAX_FILE_BYTES", 1 << 26)
    values = [f"kv{number:07d}" for number in range(150_000)]
    path = write_json(tmp_path, {"known_values": values})
    start = time.monotonic()
    text, _ = intake.draft(intake.read_answers(path), engagement_id="acme-2026-11")
    assert time.monotonic() - start < 30
    assert len(json.loads(text)["known_values"]) == 150_000


# -- the id holds no known value -----------------------------------------------------------------


def test_an_id_holding_a_known_value_is_refused_and_is_no_fault_in_intake(tmp_path):
    loaded = read_text(tmp_path, "Known value: acme\n")

    with pytest.raises(IntakeError) as raised:
        intake.draft(loaded, engagement_id="acme-1")

    assert str(raised.value).endswith(
        ": id: holds known_values[0]; choose an id that names no customer value"
    )
    assert "acme" not in str(raised.value) and "fault in intake" not in str(raised.value)


def test_the_intake_command_writes_no_draft_for_an_id_with_a_known_value(tmp_path, capsys):
    from mcp_kymograph import cli

    answers = tmp_path / "answers.txt"
    answers.write_text("Known value: acme\n")
    draft = tmp_path / "draft.json"

    code = cli.main(
        ["engagement", "intake", "--from", str(answers), "--id", "acme-1", "--out", str(draft)]
    )

    said = capsys.readouterr()
    assert code == 2 and not draft.exists()
    assert "holds known_values[0]" in said.err
    assert "acme" not in said.out + said.err
    assert "fault in intake" not in said.err


def test_an_id_without_the_known_value_is_drafted(tmp_path):
    loaded = read_text(tmp_path, "Known value: acme\n")
    text, _ = intake.draft(loaded, engagement_id="ACME-1")
    assert engagement.loads(text.encode(), source="d.json", directory=tmp_path).id == "ACME-1"
