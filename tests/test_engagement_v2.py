"""Engagement files of the second version: the fields an agency engagement needs, read strictly,
kept out of what is handed on, and shown without a secret. Files of the first version are read as
they always were.
"""

from __future__ import annotations

import copy
import json
import secrets
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from mcp_kymograph import cli, engagement, evidence, report
from mcp_kymograph.engagement import EngagementError, EngagementRefused, GateFacts
from mcp_kymograph.receiver import limits
from mcp_kymograph.receiver.store import Rejected, check_prefix, parse_registration
from mcp_kymograph.store import Store
from test_engagement import _set, base, refused, write

PREFIX = "Zm9vYmFyYmF6cXV4MTIzNDU2"  # Base64url, 24 characters


def made_up(prefix: str = "kv") -> str:
    """A value for a test, put together at run time."""
    return prefix + secrets.token_hex(8)


KNOWN = [made_up("cust"), made_up("host")]


def second() -> dict:
    """A complete file of the second version, every new field given."""
    data = base()
    del data["customer"]
    data["version"] = 2
    data.update(
        {
            "agency": {
                "name": "Example Agency",
                "contacts": [{"name": "Kim", "role": "PM", "reach": "kim@agency.test"}],
            },
            "end_customer": {"name": "ACME Corp"},
            "tools": [{"name": "search", "writes": False}, {"name": "create_note", "writes": True}],
            "abort_criteria": ["any write to production data", "the customer asks to stop"],
            "emergency": {"name": "Lee Ops", "reach": "+49 30 5550100"},
            "known_values": list(KNOWN),
            "salt_env": "KYMOGRAPH_SALT",
            "canaries": [
                {"id": "c-tool", "kind": "tool_text", "where": "the search tool", "removed": None},
                {
                    "id": "c-file",
                    "kind": "file",
                    "where": "a file next to the server",
                    "path": "/srv/outside/canary.txt",
                    "removed": "2026-11-03",
                },
            ],
            "receiver": {
                "variant": "reachable",
                "address": "recv.example.test:8443",
                "path_prefix": PREFIX,
                "key_env": "KYMOGRAPH_RECEIVER_KEY",
                "ssh": "<RECEIVER_SSH>",
                "retention_seconds": 86400,
            },
            "token_passthrough": {"method": "redirect"},
        }
    )
    return data


def without(path: str):
    return _set(path, ...)


# -- loading --------------------------------------------------------------------------------


def test_every_new_field_is_loaded(tmp_path):
    loaded = engagement.load(write(tmp_path, second()))
    assert loaded.version == 2
    assert loaded.agency == "Example Agency"
    assert loaded.customer == "ACME Corp"
    assert loaded.tools == (
        engagement.Tool("search", False),
        engagement.Tool("create_note", True),
    )
    assert loaded.abort_criteria == ("any write to production data", "the customer asks to stop")
    assert loaded.known_value_count == 2
    assert loaded.salt_env == "KYMOGRAPH_SALT"
    assert [(c.id, c.kind, c.path, c.removed) for c in loaded.canaries] == [
        ("c-tool", "tool_text", None, None),
        ("c-file", "file", "/srv/outside/canary.txt", engagement.date(2026, 11, 3)),
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
    assert loaded.placeholders == ()


def test_only_the_required_new_fields_are_needed(tmp_path):
    data = second()
    for key in ("agency", "tools", "known_values", "canaries", "receiver", "token_passthrough"):
        del data[key]
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.agency is None and loaded.tools is None and loaded.receiver is None
    assert loaded.canaries == () and loaded.known_value_count == 0


def test_a_local_receiver_needs_only_its_variant(tmp_path):
    data = second()
    data["receiver"] = {"variant": "local"}
    assert engagement.load(write(tmp_path, data)).receiver == engagement.Receiver("local")


@pytest.mark.parametrize(
    ("key", "place"),
    [
        ("end_customer", "end_customer"),
        ("abort_criteria", "abort_criteria"),
        ("emergency", "emergency"),
        ("salt_env", "salt_env"),
        ("tools[0].writes", "tools[0].writes"),
        ("end_customer.name", "end_customer.name"),
        ("emergency.name", "emergency.name"),
        ("emergency.reach", "emergency.reach"),
        ("agency.name", "agency.name"),
        ("canaries[0].removed", "canaries[0].removed"),
        ("canaries[0].where", "canaries[0].where"),
        ("canaries[0].kind", "canaries[0].kind"),
        ("receiver.variant", "receiver.variant"),
        ("token_passthrough.method", "token_passthrough.method"),
    ],
)
def test_a_missing_required_field_is_refused_with_the_place(tmp_path, key, place):
    data = second()
    without(key)(data)
    assert f": {place}: missing" in str(refused(tmp_path, data))


@pytest.mark.parametrize(
    ("mutate", "words"),
    [
        (_set("customer", "ACME"), "customer: not a key of version 2"),
        (_set("agency.rank", 1), "agency: unknown key 'rank'"),
        (_set("end_customer.contacts", []), "end_customer: unknown key 'contacts'"),
        (_set("tools[0].reads", True), "tools[0]: unknown key 'reads'"),
        (_set("tools[0].writes", "yes"), "tools[0].writes: expected true or false"),
        (_set("tools[1].name", "search"), "tools[1].name: 'search' is listed twice"),
        (_set("tools", []), "tools: expected a non-empty list"),
        (_set("abort_criteria", []), "abort_criteria: expected a non-empty list"),
        (_set("abort_criteria[1]", 3), "abort_criteria[1]: expected a non-empty sentence"),
        (_set("emergency.phone", "1"), "emergency: unknown key 'phone'"),
        (_set("salt_env", "not a name"), "salt_env: expected the name of an environment variable"),
        (_set("canaries[0].kind", "mail"), "canaries[0].kind: expected one of"),
        (_set("canaries[0].removed", "yesterday"), "canaries[0].removed: expected null or a date"),
        (_set("canaries[0].removed", "2026-02-30"), "not a date that exists"),
        (_set("canaries[1].id", "c-tool"), "canaries[1].id: 'c-tool' is listed twice"),
        (_set("canaries[0].extra", 1), "canaries[0]: unknown key 'extra'"),
        (_set("receiver.variant", "public"), "receiver.variant: expected one of"),
        (_set("receiver.mode", "x"), "receiver: unknown key 'mode'"),
        (_set("receiver.path_prefix", "short"), "receiver.path_prefix: expected Base64url"),
        (_set("receiver.path_prefix", "a" * 21 + "="), "receiver.path_prefix: expected Base64url"),
        (_set("receiver.key_env", "a key value"), "receiver.key_env: expected the name"),
        (_set("receiver.retention_seconds", 0), "receiver.retention_seconds: expected a whole"),
        (_set("receiver.retention_seconds", True), "receiver.retention_seconds: expected a whole"),
        (_set("token_passthrough.method", "copy"), "token_passthrough.method: expected one of"),
        (_set("token_passthrough.how", "x"), "token_passthrough: unknown key 'how'"),
        (_set("agency.contacts[0].mail", "x"), "agency.contacts[0]: unknown key 'mail'"),
        (_set("version", "2"), "version: unsupported '2'"),
    ],
)
def test_a_wrong_new_field_is_refused_with_the_place(tmp_path, mutate, words):
    data = second()
    mutate(data)
    assert words in str(refused(tmp_path, data))


def test_a_file_canary_without_a_path_is_refused(tmp_path):
    data = second()
    del data["canaries"][1]["path"]
    assert "canaries[1].path: missing" in str(refused(tmp_path, data))


def test_a_file_canary_needs_an_absolute_path(tmp_path):
    data = second()
    data["canaries"][1]["path"] = "outside/canary.txt"
    assert "canaries[1].path: expected an absolute path" in str(refused(tmp_path, data))


def test_a_path_on_another_kind_of_canary_is_refused(tmp_path):
    data = second()
    data["canaries"][0]["path"] = "/srv/outside/canary.txt"
    assert "canaries[0].path: not allowed for kind tool_text" in str(refused(tmp_path, data))


@pytest.mark.parametrize("key", ["address", "path_prefix", "key_env", "retention_seconds"])
def test_a_reachable_receiver_without_what_it_needs_is_refused(tmp_path, key):
    data = second()
    del data["receiver"][key]
    assert f"receiver.{key}: missing" in str(refused(tmp_path, data))


@pytest.mark.parametrize(
    ("known", "words"),
    [
        (["abc"], "known_values[0]: shorter than 4 characters"),
        ([7], "known_values[0]: expected a string"),
        (["same-value", "same-value"], "known_values[1]: the same value as known_values[0]"),
        (
            ["same-value", "other-one", "same-value", "same-value"],
            "known_values[2]: the same value as known_values[0]",
        ),
    ],
)
def test_known_values_are_checked_and_never_repeated(tmp_path, known, words):
    data = second()
    data["known_values"] = known
    message = str(refused(tmp_path, data))
    assert words in message
    assert "same-value" not in message.replace(words, "")


def test_a_wrong_env_name_is_not_repeated(tmp_path):
    secret = made_up("not a name ")
    data = second()
    data["salt_env"] = secret
    assert secret not in str(refused(tmp_path, data))


# -- the first version ----------------------------------------------------------------------


def test_the_new_keys_are_unknown_keys_in_a_file_of_the_first_version(tmp_path):
    for key, value in second().items():
        if key not in engagement._V2_ONLY_KEYS:
            continue
        data = base()
        data[key] = value
        assert f": unknown key {key!r}" in str(refused(tmp_path, data)), key


def test_a_file_of_the_first_version_is_read_as_before(tmp_path):
    loaded = engagement.load(write(tmp_path, base()))
    assert loaded.version == 1
    assert loaded.customer == "ACME Corp"
    assert loaded.agency is None and loaded.tools is None and loaded.receiver is None
    assert loaded.canaries == () and loaded.salt_env is None and loaded.abort_criteria == ()
    assert loaded.sanitized()["version"] == 1
    assert "end_customer" not in loaded.data


def test_a_file_of_the_second_version_supersedes_one_of_the_first(tmp_path):
    first = engagement.load(write(tmp_path, base(), "first.json"))
    data = second()
    data["supersedes"] = first.digest
    later = engagement.load(write(tmp_path, data, "second.json"))
    assert later.supersedes == first.digest
    assert (first.version, later.version) == (1, 2)


def test_the_chain_from_the_first_version_to_the_second_is_kept_by_a_store(tmp_path):
    from mcp_kymograph.store import Store

    older = base()
    del older["supersedes"]
    first = engagement.load(write(tmp_path, older, "first.json"))
    data = second()
    data["supersedes"] = first.digest
    later = engagement.load(write(tmp_path, data, "second.json"))
    with Store.open(tmp_path / "store.sqlite") as store:
        for held in (first, later):
            store.set_engagement(
                engagement_id_declared=held.id,
                digest=held.digest,
                supersedes=held.supersedes,
                delete_after_declared=None,
                file_declared=held.sanitized(),
                removed=held.removed,
            )
        chain = store.engagement()["chain"]
    assert [entry["digest"] for entry in chain] == [first.digest, later.digest]
    assert [entry["supersedes"] for entry in chain] == [None, first.digest]


# -- what must not go out -------------------------------------------------------------------


def test_sanitized_leaves_out_every_listed_point(tmp_path):
    loaded = engagement.load(write(tmp_path, second()))
    kept = loaded.sanitized()
    assert "known_values" not in kept
    assert "emergency" not in kept
    assert "salt_env" not in kept
    assert "key_env" not in kept["receiver"] and "ssh" not in kept["receiver"]
    assert "contacts" not in kept["agency"]
    assert kept["end_customer"] == {"name": "ACME Corp"}
    text = json.dumps(kept)
    for secret in (*KNOWN, "Lee Ops", "KYMOGRAPH_SALT", "KYMOGRAPH_RECEIVER_KEY", "<RECEIVER_SSH>"):
        assert secret not in text
    assert "kim@agency.test" not in text
    for path in (
        "known_values",
        "emergency",
        "salt_env",
        "receiver.key_env",
        "receiver.ssh",
        "agency.contacts",
    ):
        assert path in loaded.removed


def test_sanitized_changes_nothing_in_the_file_as_parsed(tmp_path):
    loaded = engagement.load(write(tmp_path, second()))
    before = copy.deepcopy(loaded.data)
    loaded.sanitized()
    assert loaded.data == before


# -- showing --------------------------------------------------------------------------------


def test_show_names_the_new_fields_and_no_known_value(tmp_path, capsys):
    path = write(tmp_path, second())
    assert cli.main(["engagement", "show", str(path)]) == 0
    out = capsys.readouterr().out
    for value in KNOWN:
        assert value not in out
    assert "known values, replaced when written: 2 (the values are not shown)" in out
    for shown in (
        "Agency:     Example Agency",
        "Customer:   ACME Corp  (the end customer)",
        "create_note — writes",
        "search — does not write",
        "any write to production data",
        "emergency: Lee Ops",
        "c-tool (tool_text) — OPEN: not removed",
        "c-file (file) — removed 2026-11-03",
        "path: /srv/outside/canary.txt",
        "salt from env: KYMOGRAPH_SALT",
        "key from env: KYMOGRAPH_RECEIVER_KEY",
        "token passthrough: redirect",
        "kim@agency.test",
    ):
        assert shown in out, shown


def test_show_of_the_first_version_is_as_before(tmp_path, capsys):
    path = write(tmp_path, base())
    assert cli.main(["engagement", "show", str(path)]) == 0
    out = capsys.readouterr().out
    assert "Customer:   ACME Corp\n" in out
    assert "Canaries" not in out and "Agency" not in out


def test_the_reader_refuses_a_third_version(tmp_path):
    data = second()
    data["version"] = 3
    assert "version: unsupported 3; this reader reads 1 and 2" in str(refused(tmp_path, data))
    assert issubclass(EngagementError, ValueError)


# -- the receiver's address and prefix, as the receiver takes them ---------------------------


@pytest.mark.parametrize(
    "address",
    [
        "recv.example.test",
        "recv.example.test:443",
        "recv",
        "10.0.0.5",
        "10.0.0.5:8443",
        "[::1]",
        "[2001:db8::7]:65535",
        "a-b.example.test:1",
    ],
)
def test_an_address_is_a_host_or_a_host_and_a_port(tmp_path, address):
    data = second()
    data["receiver"]["address"] = address
    assert engagement.load(write(tmp_path, data)).receiver.address == address


@pytest.mark.parametrize(
    "address",
    [
        "https://recv.example.test",
        "recv.example.test/path",
        "recv.example.test/",
        "recv.example.test?x=1",
        "recv.example.test#top",
        "user@recv.example.test",
        "recv.example.test:0",
        "recv.example.test:65536",
        "recv.example.test:",
        "recv.example.test:80:80",
        "recv.example.test:http",
        "::1",
        "[::1",
        "[10.0.0.5]",
        "[::1]x",
        "-recv.example.test",
        "recv_.example.test",
        "recv..example.test",
        "1.2.3",
        "999.1.1.1",
        "re cv",
        "",
    ],
)
def test_an_address_that_is_more_than_a_host_and_a_port_is_refused(tmp_path, address):
    data = second()
    data["receiver"]["address"] = address
    assert "receiver.address: " in str(refused(tmp_path, data))


@pytest.mark.parametrize(
    "address", ["[::1%u@evil.test]", "[fe80::1%x?y#z]:443", "[fe80::1%eth0]", "[::1%]", "[::1%25]"]
)
def test_an_ipv6_address_with_a_scope_id_is_refused(tmp_path, address):
    data = second()
    data["receiver"]["address"] = address
    assert "receiver.address: " in str(refused(tmp_path, data))
    assert not engagement.good_receiver_address(address)


@pytest.mark.parametrize(
    ("address", "host", "port"),
    [
        ("recv.example.test", "recv.example.test", None),
        ("recv.example.test:443", "recv.example.test", 443),
        ("10.0.0.5:8443", "10.0.0.5", 8443),
        ("[::1]", "::1", None),
        ("[2001:db8::7]:65535", "2001:db8::7", 65535),
    ],
)
def test_an_accepted_address_is_the_host_and_port_a_url_parser_reads(address, host, port):
    assert engagement.good_receiver_address(address)
    parts = urlsplit("https://" + address + "/p")
    assert (parts.hostname, parts.port, parts.username) == (host, port, None)


def test_a_draft_with_a_placeholder_retention_is_refused_by_the_gate(tmp_path):
    data = second()
    data["receiver"]["retention_seconds"] = "[SECONDS]"
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.placeholders == ("receiver.retention_seconds",)
    now = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
    with pytest.raises(EngagementRefused) as raised:
        engagement.check(loaded, GateFacts(command="run", isolation="runc"), now)
    assert raised.value.condition == "draft"
    assert "receiver.retention_seconds" in raised.value.words


def test_a_local_receiver_may_name_an_address_and_it_is_checked_too(tmp_path):
    data = second()
    data["receiver"] = {"variant": "local", "address": "127.0.0.1:9000"}
    assert engagement.load(write(tmp_path, data)).receiver.address == "127.0.0.1:9000"
    data["receiver"]["address"] = "http://127.0.0.1:9000"
    assert "receiver.address: expected host" in str(refused(tmp_path, data))


def test_the_prefix_limits_are_the_receivers_and_named_as_constants():
    assert (
        engagement.RECEIVER_PREFIX_MIN_LENGTH,
        engagement.RECEIVER_PREFIX_MAX_LENGTH,
        engagement.RECEIVER_PREFIX_MIN_DISTINCT,
    ) == (
        limits.MIN_PREFIX_CHARS,
        limits.MAX_PREFIX_CHARS,
        limits.MIN_PREFIX_DISTINCT_CHARS,
    )


@pytest.mark.parametrize(
    ("prefix", "good"),
    [
        ("Zm9vYmFyYmF6cXV4MTIzNDU2", True),
        ("abcdefghij" * 2 + "kl", True),
        ("abcdefghij" * 12 + "abcdefgh", True),  # 128 characters
        ("abcdefghij" * 12 + "abcdefghi", False),  # 129
        ("abcdefghij" * 2 + "k", False),  # 21
        ("a" * 22, False),  # one distinct character
        ("abcdefghi" * 3, False),  # nine distinct characters
        ("abcdefghij" * 2 + "k=", False),  # padding
        ("abcdefghij" * 2 + "k+", False),
        ("abcdefghij" * 2 + "k/", False),
    ],
)
def test_a_path_prefix_is_base64url_of_22_to_128_characters_and_ten_different_ones(
    tmp_path, prefix, good
):
    data = second()
    data["receiver"]["path_prefix"] = prefix
    if good:
        assert engagement.load(write(tmp_path, data)).receiver.path_prefix == prefix
    else:
        assert "receiver.path_prefix: expected Base64url" in str(refused(tmp_path, data))


def spread(length: int, distinct: int) -> str:
    """A prefix of ``length`` Base64url characters, ``distinct`` of them different."""
    alphabet = "abcdefghijklmnopqrstuvwxyz"[:distinct]
    return (alphabet * length)[:length]


#: Values the reader and the receiver must judge alike.
SHARED_PREFIXES = [
    pytest.param(spread(21, 10), False, id="too short"),
    pytest.param(spread(22, 10), True, id="22 characters"),
    pytest.param(spread(128, 10), True, id="128 characters"),
    pytest.param(spread(129, 10), False, id="129 characters"),
    pytest.param(spread(22, 9), False, id="nine different"),
    pytest.param(spread(22, 10), True, id="ten different"),
    pytest.param(spread(21, 10) + "=", False, id="outside Base64url"),
]


def receiver_takes(prefix: str) -> bool:
    """What the receiver decides at ``register``: its shape check and the distinct rule."""
    try:
        parse_registration(
            {
                "prefix": prefix,
                "key": "QUJD" * 11,
                "expires_at": "2999-01-01T00:00:00Z",
                "retention_seconds": 1,
                "secret_headers": [],
            }
        )
    except Rejected as error:
        assert "$.prefix" in str(error)
        return False
    return True


def reader_takes(tmp_path, prefix: str) -> bool:
    data = second()
    data["receiver"]["path_prefix"] = prefix
    try:
        engagement.load(write(tmp_path, data))
    except EngagementError as error:
        assert "receiver.path_prefix" in str(error)
        return False
    return True


def disagreements(tmp_path) -> list[str]:
    """The rows of the table on which the reader and the receiver decide differently."""
    return [
        row.id
        for row in SHARED_PREFIXES
        if reader_takes(tmp_path, row.values[0]) is not receiver_takes(row.values[0])
    ]


@pytest.mark.parametrize(("prefix", "good"), SHARED_PREFIXES)
def test_the_reader_and_the_receiver_judge_a_prefix_alike(tmp_path, prefix, good):
    assert receiver_takes(prefix) is good
    assert reader_takes(tmp_path, prefix) is good


def test_the_table_goes_red_when_the_reader_holds_another_limit(tmp_path, monkeypatch):
    assert disagreements(tmp_path) == []
    monkeypatch.setattr(
        engagement,
        "good_receiver_prefix",
        lambda value: check_prefix(value) and len(set(value)) >= 9,
    )
    assert disagreements(tmp_path) == ["nine different"]
    monkeypatch.setattr(
        engagement,
        "good_receiver_prefix",
        lambda value: check_prefix(value) and len(value) <= 127 and len(set(value)) >= 10,
    )
    assert disagreements(tmp_path) == ["128 characters"]


def test_a_prefix_with_a_trailing_line_feed_is_refused(tmp_path):
    prefix = spread(22, 10) + "\n"
    assert not check_prefix(prefix)
    assert reader_takes(tmp_path, prefix) is False


def test_the_retention_limit_is_the_receivers():
    assert engagement.MAX_RETENTION_SECONDS == limits.MAX_RETENTION_SECONDS


def test_placeholders_stay_allowed_in_the_reachable_receiver_and_make_a_draft(tmp_path):
    data = second()
    data["receiver"].update(
        address="[RECEIVER ADDRESS]",
        path_prefix="[PREFIX]",
        key_env="[KEY VARIABLE]",
        retention_seconds="[SECONDS]",
    )
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.is_draft
    assert set(loaded.placeholders) == {
        "receiver.address",
        "receiver.path_prefix",
        "receiver.key_env",
        "receiver.retention_seconds",
    }
    assert loaded.receiver.retention_seconds is None


# -- the customer's name, in either version -------------------------------------------------


def test_the_customer_is_customer_in_the_first_version_and_the_end_customer_in_the_second():
    assert engagement.declared_customer({"version": 1, "customer": "ACME Corp"}) == "ACME Corp"
    assert engagement.declared_customer({"customer": "ACME Corp"}) == "ACME Corp"
    both = {
        "version": 2,
        "agency": {"name": "Example Agency"},
        "end_customer": {"name": "ACME Corp"},
    }
    assert engagement.declared_customer(both) == "ACME Corp"
    assert (
        engagement.declared_customer({"version": 2, "agency": {"name": "Example Agency"}}) is None
    )
    assert engagement.declared_customer({"version": 2, "customer": "Example Agency"}) is None
    assert engagement.declared_customer({}) is None
    assert engagement.declared_customer({"version": 1, "customer": 7}) is None


def test_a_dossier_of_a_file_of_the_second_version_names_the_end_customer_not_the_agency(
    tmp_path,
):
    held = engagement.load(write(tmp_path, second()))
    database = tmp_path / "store.sqlite"
    with Store.open(database) as store:
        store.set_engagement(
            engagement_id_declared=held.id,
            digest=held.digest,
            file_declared=held.sanitized(),
            supersedes=held.supersedes,
            delete_after_declared=None,
            removed=held.removed,
        )

    ours = report.dossier(customer="ACME Corp", stores=[database])
    agency = report.dossier(customer="Example Agency", stores=[database])

    assert [e.engagement_id for e in ours.engagements] == [held.id]
    assert ours.other_customer == 0
    assert "ACME Corp" in report.render_dossier(ours)
    assert "Example Agency" not in report.render_dossier(ours) + json.dumps(ours.to_dict())
    assert agency.engagements == () and agency.other_customer == 1


def test_the_customer_readme_of_a_file_of_the_second_version_names_the_end_customer_not_the_agency(
    tmp_path,
):
    held = engagement.load(write(tmp_path, second()))
    index = SimpleNamespace(
        engagement_id_declared=held.id, derived_from=None, created_utc="2026-11-04T00:00:00Z",
        files=[],
    )  # fmt: skip
    engaged = json.dumps(held.sanitized()).encode()

    fields = evidence._readme_fields(index, "0" * 64, engaged, None)
    text = evidence.render_customer_readme(fields)

    assert fields.customer_declared == "ACME Corp"
    assert "ACME Corp" in text and "Example Agency" not in text
    assert evidence.parse_customer_readme(text).customer_declared == "ACME Corp"


# -- security: --json, the path prefix, the bounds, the messages ------------------------------


def test_show_json_has_no_known_value_but_their_number(tmp_path, capsys):
    path = write(tmp_path, second())
    assert cli.main(["engagement", "show", "--json", "-q", str(path)]) == 0
    captured = capsys.readouterr()
    for value in KNOWN:
        assert value not in captured.out and value not in captured.err
    shown = json.loads(captured.out)
    assert shown["known_value_count"] == 2
    assert "known_values" not in shown["engagement"]
    # The operator's view otherwise: contacts, emergency, variable names, address and prefix.
    assert shown["engagement"]["emergency"] == {"name": "Lee Ops", "reach": "+49 30 5550100"}
    assert shown["engagement"]["agency"]["contacts"][0]["reach"] == "kim@agency.test"
    assert shown["engagement"]["salt_env"] == "KYMOGRAPH_SALT"
    assert shown["engagement"]["receiver"]["path_prefix"] == PREFIX
    assert shown["engagement"]["receiver"]["key_env"] == "KYMOGRAPH_RECEIVER_KEY"


def test_the_json_view_written_back_loads_without_the_known_values(tmp_path, capsys):
    path = write(tmp_path, second())
    assert cli.main(["engagement", "show", "--json", "-q", str(path)]) == 0
    shown = json.loads(capsys.readouterr().out)
    (tmp_path / "back").mkdir()
    back = write(tmp_path / "back", shown["engagement"])
    loaded = engagement.load(back)
    assert loaded.known_value_count == 0 and loaded.id == "acme-2026-10"


def test_sanitized_leaves_out_the_path_prefix_and_removed_names_it(tmp_path):
    loaded = engagement.load(write(tmp_path, second()))
    assert "path_prefix" not in loaded.sanitized()["receiver"]
    assert PREFIX not in json.dumps(loaded.sanitized())
    assert "receiver.path_prefix" in loaded.removed


def test_a_receiver_prefix_is_not_in_the_file_of_a_store(tmp_path):
    held = engagement.load(write(tmp_path, second()))
    with Store.open(tmp_path / "store.sqlite") as store:
        store.set_engagement(
            engagement_id_declared=held.id,
            digest=held.digest,
            supersedes=held.supersedes,
            delete_after_declared=None,
            file_declared=held.sanitized(),
            removed=held.removed,
        )
    assert PREFIX.encode() not in (tmp_path / "store.sqlite").read_bytes()


@pytest.mark.parametrize(
    ("seconds", "good"),
    [(7_776_000, True), (7_776_001, False)],
    ids=["at the limit", "one over"],
)
def test_retention_is_at_most_90_days(tmp_path, seconds, good):
    assert engagement.MAX_RETENTION_SECONDS == 90 * 24 * 3600
    data = second()
    data["receiver"]["retention_seconds"] = 86400
    path = write(tmp_path, data)
    path.write_text(path.read_text().replace("86400", str(seconds)))
    if good:
        assert engagement.load(path).receiver.retention_seconds == seconds
    else:
        with pytest.raises(EngagementError, match=r"receiver.retention_seconds: .*7776000"):
            engagement.load(path)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("emergency.reach", 47110815),
        ("receiver.ssh", 47110815),
        ("receiver.path_prefix", "pp=" + made_up("pp")),
        ("receiver.key_env", "not a name " + made_up("ke")),
    ],
)
def test_a_refusal_of_a_secret_field_does_not_repeat_the_value(tmp_path, path, value):
    data = second()
    _set(path, value)(data)
    message = str(refused(tmp_path, data))
    assert path in message
    assert str(value) not in message
    assert str(value)[3:] not in message


def test_an_empty_receiver_key_variable_is_not_ready_like_an_unset_one(
    tmp_path, monkeypatch, capsys
):
    path = write(tmp_path, second())
    outcomes = []
    for state in ("unset", "empty"):
        monkeypatch.delenv("KYMOGRAPH_RECEIVER_KEY", raising=False)
        if state == "empty":
            monkeypatch.setenv("KYMOGRAPH_RECEIVER_KEY", "")
        code = cli.main(["engagement", "preflight", str(path)])
        (line,) = [
            line
            for line in capsys.readouterr().out.splitlines()
            if line.lstrip().startswith("receiver key")
        ]
        outcomes.append((code, line.split()[2]))
    assert outcomes[0] == outcomes[1] == (report.EXIT_NOT_READY, "not_ready")


@pytest.mark.parametrize("key", ["known_values", "emergency", "receiver", "canaries"])
def test_a_value_of_the_wrong_type_is_refused_with_the_place(tmp_path, key):
    data = second()
    data[key] = {"a": 1} if key == "canaries" else "text"
    message = str(refused(tmp_path, data))
    assert f": {key}: " in message


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("agency", "Example Agency"),
        ("agency", ["Example Agency"]),
        ("end_customer", "ACME Corp"),
        ("end_customer", ["ACME Corp"]),
        ("token_passthrough", "redirect"),
        ("token_passthrough", ["redirect"]),
        ("tools", {"name": "search", "writes": False}),
        ("tools", "search"),
        ("canaries[0]", "c-tool"),
        ("canaries[0]", ["c-tool"]),
    ],
)
def test_a_mapping_or_list_of_the_wrong_type_is_refused_with_the_place(tmp_path, path, value):
    data = second()
    _set(path, value)(data)
    message = str(refused(tmp_path, data))
    assert f": {path}: " in message
    assert "Traceback" not in message


# -- receiver.ssh is a reference, not a key ---------------------------------------------------


def a_key_header() -> str:
    return "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"


@pytest.mark.parametrize(
    "ssh",
    [
        "<RECEIVER_SSH>",
        "dev@10.8.0.1",
        "dev@receiver.example",
        "dev@receiver.example:2222",
        "dev@[2001:db8::7]",
        "receiver.example",
        "<" + "a" * 64 + ">",
    ],
)
def test_an_ssh_reference_is_a_name_or_a_user_and_a_host(tmp_path, ssh):
    data = second()
    data["receiver"]["ssh"] = ssh
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.receiver.ssh == ssh and not loaded.is_draft


def test_a_bracketed_ssh_placeholder_makes_a_draft(tmp_path):
    data = second()
    data["receiver"]["ssh"] = "[RECEIVER SSH]"
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.is_draft and loaded.placeholders == ("receiver.ssh",)
    assert loaded.receiver.ssh is None


@pytest.mark.parametrize("ssh", ["[fe80::1%eth0]", "dev@[fe80::1%eth0]", "[::1%25]"])
def test_an_ssh_reference_with_a_scope_id_is_refused_and_not_a_placeholder(tmp_path, ssh):
    data = second()
    data["receiver"]["ssh"] = ssh
    message = str(refused(tmp_path, data))
    assert "receiver.ssh: " in message and "never a key" in message
    assert "eth0" not in message and "fe80" not in message
    assert not engagement.good_receiver_ssh(ssh)


SSH_KEYS = [
    a_key_header() + " b3Bl" + made_up("k"),
    "ssh-ed25519 AAAA" + made_up("k"),
    "b3BlbnNzaC1r/" + made_up("k") + "+Zw==",
    "dev@host\n",
    "a b",
    "<",
    "<>",
    "<a b>",
    "<" + "a" * 65 + ">",
    "user@",
    "@host",
    "dev@@host",
    "-dev@host",
    "d" * 33 + "@host",
    47110815,
]


@pytest.mark.parametrize("ssh", SSH_KEYS, ids=range(len(SSH_KEYS)))
def test_an_ssh_value_that_is_no_reference_is_refused_with_the_place_and_not_the_value(
    tmp_path, ssh
):
    data = second()
    data["receiver"]["ssh"] = ssh
    message = str(refused(tmp_path, data))
    assert "receiver.ssh: expected a reference" in message
    assert "47110815" not in message
    if len(str(ssh)) > 12:  # a short value can only collide with the words of the message
        assert str(ssh).strip()[3:] not in message


@pytest.mark.parametrize("show", [["show"], ["show", "--json"]], ids=["text", "json"])
def test_show_of_a_file_with_a_key_in_ssh_prints_no_value_and_exits_2(tmp_path, capsys, show):
    data = second()
    data["receiver"]["ssh"] = a_key_header() + " b3Bl" + made_up("k")
    path = write(tmp_path, data)
    assert cli.main(["engagement", *show, str(path)]) == 2
    said = capsys.readouterr()
    assert said.out == "" and "receiver.ssh" in said.err
    assert "b3Bl" not in said.err and "PRIVATE" not in said.err


# -- an IPv6 address with letters is an address, not a placeholder ------------------------------


@pytest.mark.parametrize("address", ["[2001:db8::7]", "[fe80::1]", "[2001:db8::7]:8443"])
def test_an_ipv6_address_with_letters_is_kept_as_an_address(tmp_path, capsys, address):
    data = second()
    data["receiver"]["address"] = address
    loaded = engagement.load(write(tmp_path, data))
    assert not loaded.is_draft and loaded.placeholders == ()
    assert loaded.receiver.address == address
    assert cli.main(["engagement", "show", str(write(tmp_path, data))]) == 0
    shown = capsys.readouterr().out
    assert address in shown and "<- placeholder" not in shown


def test_an_ipv6_target_host_with_letters_is_a_host_not_a_placeholder(tmp_path, capsys):
    data = second()
    data["targets"][0]["host"] = "[2001:db8::7]"
    loaded = engagement.load(write(tmp_path, data))
    assert loaded.placeholders == () and loaded.targets[0].name is not None
    assert cli.main(["engagement", "show", str(write(tmp_path, data))]) == 0
    shown = capsys.readouterr().out
    assert "[2001:db8::7]" in shown and "<- placeholder" not in shown


def test_a_bracketed_address_placeholder_stays_one_and_a_scope_id_is_refused(tmp_path, capsys):
    data = second()
    data["receiver"]["address"] = "[RECEIVER ADDRESS]"
    path = write(tmp_path, data)
    assert engagement.load(path).placeholders == ("receiver.address",)
    assert cli.main(["engagement", "show", str(path)]) == 0
    assert "[placeholder] receiver.address" in capsys.readouterr().out
    data["receiver"]["address"] = "[fe80::1%eth0]"
    assert "receiver.address: " in str(refused(tmp_path, data))


@pytest.mark.parametrize("name", ["engagement.json", "engagement.yaml"])
def test_a_retention_of_5000_digits_in_a_file_is_refused_with_exit_2_and_no_traceback(
    tmp_path, capsys, name
):
    data = second()
    data["receiver"]["retention_seconds"] = 7
    path = write(tmp_path, data, name)
    text = path.read_text()
    marker = '"retention_seconds": 7' if name.endswith(".json") else "retention_seconds: 7"
    assert marker in text
    path.write_text(text.replace(marker, marker[:-1] + "9" * 5000))
    assert cli.main(["engagement", "show", str(path)]) == 2
    said = capsys.readouterr()
    assert said.out == ""
    assert said.err.startswith(f"kymograph: {path}: ") and len(said.err.strip().splitlines()) == 1
    assert "Traceback" not in said.err and "9" * 50 not in said.err


_BAD_WHOLE_NUMBERS = {
    "octal digits": "0" + "7" * 5000,
    "hexadecimal": "!!int 0x" + "f" * 5000,
    "binary": "!!int 0b" + "1" * 5000,
    "sexagesimal": "!!int 1:2:3",
}


@pytest.mark.parametrize("spelling", _BAD_WHOLE_NUMBERS.values(), ids=_BAD_WHOLE_NUMBERS)
@pytest.mark.parametrize(
    ("before", "after"), [("version: 2\n", "version: "), ("- 443\n", "- ")], ids=["version", "port"]
)
def test_a_yaml_whole_number_in_another_base_is_refused_with_the_line_and_no_traceback(
    tmp_path, capsys, before, after, spelling
):
    path = write(tmp_path, second(), "engagement.yaml")
    text = path.read_text()
    assert before in text
    path.write_text(text.replace(before, after + spelling + "\n", 1))
    assert cli.main(["engagement", "show", str(path)]) == 2
    said = capsys.readouterr()
    assert said.out == ""
    assert said.err.startswith(f"kymograph: {path}: line ")
    assert len(said.err.strip().splitlines()) == 1
    assert "Traceback" not in said.err and "7" * 50 not in said.err and "f" * 50 not in said.err


@pytest.mark.parametrize(
    ("spelling", "seconds"), [("00003600", 3600), ("09", 9)], ids=["octal-looking", "not octal"]
)
def test_a_yaml_retention_with_leading_zeros_is_read_in_decimal(tmp_path, spelling, seconds):
    path = write(tmp_path, second(), "engagement.yaml")
    text = path.read_text()
    assert "retention_seconds: 86400" in text
    path.write_text(text.replace("retention_seconds: 86400", f"retention_seconds: {spelling}"))
    assert engagement.load(path).receiver.retention_seconds == seconds


_TAGGED = [
    "!!bool x",
    "!!timestamp x",
    '!!float ""',
    "!!binary ***",
    "!!set {a}",
    "!!str 1",
    "!foo bar",
    "!<tag:yaml.org,2002:int> 1",
]


@pytest.mark.parametrize("tagged", _TAGGED)
@pytest.mark.parametrize(
    ("before", "after"), [("version: 2\n", "version: "), ("- 443\n", "- ")], ids=["version", "port"]
)
def test_an_explicit_yaml_tag_is_refused_with_the_line_and_no_traceback(
    tmp_path, capsys, before, after, tagged
):
    path = write(tmp_path, second(), "engagement.yaml")
    text = path.read_text()
    assert before in text
    path.write_text(text.replace(before, after + tagged + "\n", 1))
    assert cli.main(["engagement", "show", str(path)]) == 2
    said = capsys.readouterr()
    assert said.out == ""
    assert said.err.startswith(f"kymograph: {path}: line ")
    assert said.err.strip().endswith("YAML tags are not allowed")
    assert len(said.err.strip().splitlines()) == 1
    assert "Traceback" not in said.err


# -- a long list is checked for repeats in linear time ------------------------------------------


def load_in_time(tmp_path, monkeypatch, data, seconds):
    import time

    # The cap on a file is lifted: it is what keeps a real file small, not what is under test.
    monkeypatch.setattr(engagement, "MAX_FILE_BYTES", 1 << 26)
    path = write(tmp_path, data)
    start = time.monotonic()
    loaded = engagement.load(path)
    assert time.monotonic() - start < seconds
    return loaded


def test_150000_known_values_load_in_time(tmp_path, monkeypatch):
    data = second()
    data["known_values"] = [f"kv{number:07d}" for number in range(150_000)]
    loaded = load_in_time(tmp_path, monkeypatch, data, 30)
    assert loaded.known_value_count == 150_000


def test_30000_tools_load_in_time(tmp_path, monkeypatch):
    data = second()
    data["tools"] = [{"name": f"tool{number}", "writes": False} for number in range(30_000)]
    assert len(load_in_time(tmp_path, monkeypatch, data, 20).tools) == 30_000


def test_30000_canaries_load_in_time(tmp_path, monkeypatch):
    data = second()
    data["canaries"] = [
        {"id": f"c{number}", "kind": "tool_text", "where": "x", "removed": None}
        for number in range(30_000)
    ]
    assert len(load_in_time(tmp_path, monkeypatch, data, 20).canaries) == 30_000


# -- the id holds no known value -----------------------------------------------------------------


def with_id(identifier: str, known: list[str]) -> dict:
    data = second()
    data["id"] = identifier
    data["known_values"] = known
    return data


@pytest.mark.parametrize("form", ["{}-2026-10", "acme-{}-10", "acme-2026-{}", "{}"])
def test_an_id_holding_a_known_value_is_refused_by_place_and_index_never_by_value(tmp_path, form):
    value = made_up("cust")
    identifier = form.format(value)
    before = sorted(p.name for p in tmp_path.iterdir())

    error = refused(tmp_path, with_id(identifier, [made_up("host"), value]))

    assert "id: holds known_values[1]; choose an id that names no customer value" in str(error)
    assert value not in str(error) and identifier not in str(error)
    assert sorted(p.name for p in tmp_path.iterdir()) == [*before, "engagement.json", "scenarios"]


def test_an_id_without_a_known_value_loads_and_another_case_is_another_value(tmp_path):
    value = made_up("cust")
    loaded = engagement.load(write(tmp_path, with_id("acme-2026-10", [value])))
    assert loaded.id == "acme-2026-10"
    (tmp_path / "other").mkdir()
    shouting = with_id(f"x-{value.upper()}-y", [value])
    assert engagement.load(write(tmp_path / "other", shouting)).id == f"x-{value.upper()}-y"


@pytest.mark.parametrize(
    "argv",
    [
        ["engagement", "show", "{file}"],
        ["engagement", "preflight", "{file}"],
        ["run", "--engagement", "{file}", "--out-dir", "{out}", "--", "unused"],
        ["fleet", "run", "--engagement", "{file}", "--manifest", "{out}/m.json", "--store",
         "{out}/s.sqlite", "--out-dir", "{out}"],
    ],
)  # fmt: skip
def test_every_command_that_loads_the_file_refuses_an_id_with_a_known_value(tmp_path, capsys, argv):
    value = made_up("cust")
    path = write(tmp_path, with_id(f"{value}-2026-10", [value]))
    out = tmp_path / "out"

    code = cli.main([a.format(file=path, out=out) for a in argv])

    said = capsys.readouterr()
    assert code == 2
    assert "id: holds known_values[0]" in said.err
    assert value not in said.out + said.err
    assert not out.exists() or not (out / "refusals.jsonl").exists()
