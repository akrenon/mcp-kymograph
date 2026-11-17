"""Identities: the engagement file's ``identities`` and ``secret_headers``, ``drive --identity``,
and the four refusals around them — each through ``cli.main``, with the words on stderr and one line
in ``refusals.jsonl``. Against the fixture server over HTTP on loopback, which requires the token
its environment variable holds.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement
from mcp_kymograph.engagement import EngagementError, EngagementRefused, GateFacts
from test_cli_engagement import (
    events_of,
    nothing_starts,
    recording_in,
    refusals_in,
    run_directories,
    started_of,
    write_engagement,
)

__all__ = ["nothing_starts"]  # a fixture of test_cli_engagement, used here

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

DISCOVERY = str(FIXTURES / "discovery_server.py")


def made_up(prefix: str = "tok") -> str:
    """A value for a test, put together at run time."""
    return prefix + secrets.token_hex(12)


# The made-up tokens here are no JWT: the inspector reads nothing and says why.
NOT_A_JWT = {
    "claims": {},
    "expired": None,
    "other_claims": 0,
    "pseudonyms": {},
    "readable": False,
    "reason": "not_jwt",
    "unexpected": [],
    "warnings": [],
}

IDENTITIES = [
    {"name": "reader", "role": "read-only user", "token_env": "TEST_TOKEN_READER"},
    {"name": "admin", "role": "administrator", "token_env": "TEST_TOKEN_ADMIN"},
    {"name": "anonymous", "role": "not signed in", "token": "none"},
]


@pytest.fixture
def tokens(monkeypatch):
    """Two tokens in the environment, the values made up for the test."""
    values = {"reader": made_up("rd"), "admin": made_up("ad")}
    monkeypatch.setenv("TEST_TOKEN_READER", values["reader"])
    monkeypatch.setenv("TEST_TOKEN_ADMIN", values["admin"])
    return values


@pytest.fixture
def serve():
    """Starts fixture servers and stops them at the end."""
    started = []

    def start(**behaviour):
        server = http_server.serve(**behaviour)
        started.append(server)
        return server

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def url_of(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"


def drive(tmp_path, *args, file=None, **changes):
    """``drive --http`` under an engagement file with ``changes``; the exit code, the run
    directory's events (empty for a refused run) and what was said."""
    held = file or write_engagement(tmp_path / "engagement", **changes)
    out_dir = tmp_path / "runs"
    code = cli.main(["drive", "-q", "--engagement", str(held), "--out-dir", str(out_dir), *args])
    runs = run_directories(out_dir)
    events = events_of(runs[0] / "events.jsonl") if runs else []
    return code, events, out_dir


# -- the file -------------------------------------------------------------------------------


def load(tmp_path, **changes):
    return engagement.load(write_engagement(tmp_path / "engagement", **changes))


def test_a_file_declares_identities_each_with_one_source_and_no_value(tmp_path):
    loaded = load(
        tmp_path,
        identities=[
            *IDENTITIES[:2],
            {"name": "filed", "role": "from a file", "token_file": "tokens/filed"},
            IDENTITIES[2],
        ],
        secret_headers=["Ocp-Apim-Subscription-Key", "X-Tenant-Key"],
    )

    assert [(i.name, i.role, i.source) for i in loaded.identities] == [
        ("reader", "read-only user", "env"),
        ("admin", "administrator", "env"),
        ("filed", "from a file", "file"),
        ("anonymous", "not signed in", "none"),
    ]
    assert loaded.identity("filed") == engagement.Identity(
        "filed", "from a file", None, "tokens/filed"
    )
    assert loaded.identity("nobody") is None
    assert loaded.secret_headers == ("Ocp-Apim-Subscription-Key", "X-Tenant-Key")


def test_an_identity_may_send_secret_headers_from_variables(tmp_path):
    headers = {"Ocp-Apim-Subscription-Key": {"env": "TEST_APIM_KEY"}, "X-Extra": {"env": "E2"}}

    loaded = load(tmp_path, identities=[{**IDENTITIES[0], "headers": headers}, IDENTITIES[1]])

    assert loaded.identity("reader").headers == (
        ("Ocp-Apim-Subscription-Key", "TEST_APIM_KEY"),
        ("X-Extra", "E2"),
    )
    assert loaded.identity("admin").headers == ()


@pytest.mark.parametrize(
    ("identity", "where", "words"),
    [
        ({"name": "x", "role": "r"}, "identities[0]", "exactly one of"),
        (
            {"name": "x", "role": "r", "token_env": "A", "token": "none"},
            "identities[0]",
            "exactly one of",
        ),
        (
            {"name": "x", "role": "r", "token_env": "A", "token_file": "f"},
            "identities[0]",
            "exactly one of",
        ),
        (
            {"name": "x", "role": "r", "token": "none-but-a-value"},
            "identities[0].token",
            "no token",
        ),
        ({"name": "x", "role": "r", "token": True}, "identities[0].token", "no token"),
        ({"name": "x", "role": "r", "token_env": "a b"}, "identities[0].token_env", "variable"),
        ({"name": "x", "role": "r", "token_env": 7}, "identities[0].token_env", "variable"),
        (
            {"name": "x", "role": "r", "token_file": "/etc/secret"},
            "identities[0].token_file",
            "relative",
        ),
        ({"name": "x", "role": "r", "token_file": ""}, "identities[0].token_file", "relative"),
        ({"name": "x bad", "role": "r", "token": "none"}, "identities[0].name", "not a name"),
        ({"role": "r", "token": "none"}, "identities[0].name", "missing"),
        ({"name": "x", "token": "none"}, "identities[0].role", "missing"),
        (
            {"name": "x", "role": "r", "token": "none", "bearer": "v"},
            "identities[0]",
            "unknown key",
        ),
        (
            {"name": "x", "role": "r", "token": "none", "headers": {"X-Key": "a-value"}},
            "identities[0].headers[0]",
            "file holds no value",
        ),
        (
            {"name": "x", "role": "r", "token": "none", "headers": {"X-Key": {"value": "v"}}},
            "identities[0].headers[0]",
            "file holds no value",
        ),
        (
            {"name": "x", "role": "r", "token": "none", "headers": {"Authorization": {"env": "A"}}},
            "identities[0].headers[0]",
            "owns",
        ),
        (
            {
                "name": "x",
                "role": "r",
                "token": "none",
                "headers": {"X-Key": {"env": "A"}, "x-key": {"env": "B"}},
            },
            "identities[0].headers[1]",
            "twice",
        ),
    ],
)
def test_an_identity_that_holds_a_value_or_is_not_one_is_refused_whole(
    tmp_path, identity, where, words
):
    held = write_engagement(tmp_path / "engagement", identities=[identity])

    with pytest.raises(EngagementError) as refused:
        engagement.load(held)

    assert f"{where}: " in str(refused.value)
    assert words in str(refused.value)
    for value in ("none-but-a-value", "a-value", "/etc/secret", "a b"):
        assert value not in str(refused.value), "a mistake there may be a credential"


def test_identities_are_a_non_empty_list_of_distinct_names(tmp_path):
    for identities, words in (
        ([], "non-empty list"),
        ("reader", "non-empty list"),
        ([IDENTITIES[0], IDENTITIES[0]], "listed twice"),
    ):
        held = write_engagement(tmp_path / "engagement", identities=identities)
        with pytest.raises(EngagementError, match=words):
            engagement.load(held)


def test_secret_headers_are_header_names_listed_once(tmp_path):
    for listed, words in (
        ("Ocp-Apim-Subscription-Key", "expected a list"),
        ([["x"]], "expected a header name"),
        (["bad name"], "expected a header name"),
        (["X-Key", "x-key"], "listed twice"),
    ):
        held = write_engagement(tmp_path / "engagement", secret_headers=listed)
        with pytest.raises(EngagementError, match=words):
            engagement.load(held)


def test_a_placeholder_for_a_role_makes_the_file_a_draft(tmp_path):
    loaded = load(tmp_path, identities=[{**IDENTITIES[0], "role": "[ROLE OF THIS ACCOUNT]"}])

    assert loaded.is_draft and "identities[0].role" in loaded.placeholders


def test_sanitizing_removes_the_token_file_and_lists_it(tmp_path):
    loaded = load(
        tmp_path,
        identities=[
            {"name": "filed", "role": "from a file", "token_file": "tokens/filed"},
            IDENTITIES[0],
        ],
    )

    kept = loaded.sanitized()

    assert kept["identities"] == [
        {"name": "filed", "role": "from a file"},
        {"name": "reader", "role": "read-only user", "token_env": "TEST_TOKEN_READER"},
    ]
    assert "identities[].token_file" in engagement.Engagement.removed
    assert "tokens/filed" in json.dumps(loaded.data), "the file as parsed still has it"


def test_show_says_where_each_token_comes_from_and_that_the_file_holds_none(tmp_path):
    loaded = load(
        tmp_path,
        identities=[
            {**IDENTITIES[0], "headers": {"X-Key": {"env": "TEST_APIM_KEY"}}},
            {"name": "filed", "role": "from a file", "token_file": "secrets/where-it-is"},
            IDENTITIES[2],
        ],
        secret_headers=["Ocp-Apim-Subscription-Key"],
    )

    shown = engagement.render(loaded)

    assert "reader — read-only user" in shown
    assert "auth: a token from env TEST_TOKEN_READER (declared; the file holds no value)" in shown
    assert "header X-Key: a value from env TEST_APIM_KEY" in shown
    assert "auth: a token from a file (declared; the file holds no value)" in shown
    assert "secrets/where-it-is" not in shown, "a local path is the operator's"
    assert "auth: no token (declared; no Authorization header is sent)" in shown
    assert "Ocp-Apim-Subscription-Key" in shown


# -- the gate ---------------------------------------------------------------------------------


def gate(loaded, **facts):
    try:
        engagement.check(
            loaded,
            GateFacts(command="drive", http_url="http://127.0.0.1:9/mcp", **facts),
            datetime.now(timezone.utc),
        )
    except EngagementRefused as refused:
        return refused.condition
    return None


def test_the_gate_judges_the_identity_and_the_flag_that_names_a_token(tmp_path):
    with_identities = load(tmp_path, identities=IDENTITIES)
    without = load(tmp_path / "other")

    assert gate(with_identities) is None, "a run that sends nothing can only see less"
    assert gate(with_identities, identity="reader") is None
    assert gate(with_identities, identity="anonymous") is None
    assert gate(with_identities, identity="nobody") == "identity_not_declared"
    assert gate(without, identity="reader") == "identity_not_declared"
    assert gate(without) is None
    assert gate(without, source_flag="--token-env") == "token_not_declared"
    assert gate(with_identities, source_flag="--token-file") == "identity_required"
    assert (
        gate(with_identities, identity="reader", source_flag="--token-env")
        == "token_source_differs"
    )
    assert gate(with_identities, identity="nobody", source_flag="--token-env") == (
        "identity_not_declared"
    )


# -- the refusals, through the command line ----------------------------------------------------


def refused(tmp_path, capsys, args, condition, *, words, **changes):
    """A refused ``drive --http``: exit 2, nothing started, no run directory, the words on
    stderr and one line in refusals.jsonl under ``condition``."""
    code, events, out_dir = drive(tmp_path, "--http", "http://127.0.0.1:9/mcp", *args, **changes)

    assert code == cli.EXIT_REFUSED == 2
    assert events == [] and run_directories(out_dir) == []
    said = capsys.readouterr().err
    gate_condition = condition in engagement.CONDITIONS  # the gate names itself; the rest do not
    if gate_condition:
        assert f"{condition}: " in said
    for word in words:
        assert word in said
    (record,) = refusals_in(out_dir)
    assert record.reason == condition and record.exit_code == 2
    if gate_condition:
        assert f"{condition}: " in record.message
    for word in words:
        assert word in record.message, "the record says what the terminal said"
    return said, record


def test_an_identity_the_file_does_not_declare_is_refused(tmp_path, capsys, nothing_starts):
    said, _ = refused(
        tmp_path,
        capsys,
        ["--identity", "nobody"],
        "identity_not_declared",
        words=["'nobody'", "reader, admin, anonymous"],
        identities=IDENTITIES,
    )
    assert "token" not in said.split("identity_not_declared")[0]


def test_an_identity_under_a_file_that_declares_none_is_refused(tmp_path, capsys, nothing_starts):
    refused(
        tmp_path,
        capsys,
        ["--identity", "reader"],
        "identity_not_declared",
        words=["declares (none)"],
    )


@pytest.mark.parametrize("flag", [["--token-env", "TEST_TOKEN_READER"], ["--token-file", "t"]])
def test_a_token_flag_under_identities_needs_an_identity(
    tmp_path, capsys, nothing_starts, tokens, flag
):
    said, record = refused(
        tmp_path,
        capsys,
        flag,
        "identity_required",
        words=[flag[0], "select one with --identity", "the file's"],
        identities=IDENTITIES,
    )
    for value in (*tokens.values(), "TEST_TOKEN_READER"):
        assert value not in json.dumps(record.to_dict()), "argv is masked in the record"


@pytest.mark.parametrize("flag", [["--token-env", "TEST_TOKEN_READER"], ["--token-file", "t"]])
def test_a_token_flag_with_an_identity_is_refused_and_the_source_is_the_files(
    tmp_path, capsys, nothing_starts, tokens, flag
):
    refused(
        tmp_path,
        capsys,
        ["--identity", "reader", *flag],
        "token_source_differs",
        words=[flag[0], "comes from the file", f"drop {flag[0]}"],
        identities=IDENTITIES,
    )


@pytest.mark.parametrize("flag", [["--token-env", "TEST_TOKEN_READER"], ["--token-file", "t"]])
def test_a_token_under_a_file_that_declares_no_identity_is_refused(
    tmp_path, capsys, nothing_starts, tokens, flag
):
    refused(
        tmp_path,
        capsys,
        flag,
        "token_not_declared",
        words=[flag[0], "declares no identity", "outside scope"],
    )


def test_a_token_that_is_not_there_is_refused_by_its_source_before_anything_exists(
    tmp_path, capsys, nothing_starts, monkeypatch
):
    monkeypatch.delenv("TEST_TOKEN_READER", raising=False)

    said, record = refused(
        tmp_path,
        capsys,
        ["--identity", "reader"],
        "token",
        words=["TEST_TOKEN_READER", "is not set"],
        identities=IDENTITIES,
    )
    assert record.engagement_id_declared == "acme-2026-10"


def test_a_token_file_that_cannot_be_used_is_refused_naming_the_identity_and_nothing_of_it(
    tmp_path, capsys, nothing_starts
):
    secret = made_up("sk")
    directory = tmp_path / "engagement"
    directory.mkdir()
    (directory / "bad").write_text(f"{secret} and more words\n")

    said, record = refused(
        tmp_path,
        capsys,
        ["--identity", "filed"],
        "token",
        words=["identity filed: token_file", "not visible ASCII"],
        identities=[{"name": "filed", "role": "r", "token_file": "bad"}],
    )
    assert secret not in said and secret not in json.dumps(record.to_dict())


def test_a_token_file_that_is_missing_is_refused_without_its_path_or_its_name(
    tmp_path, capsys, nothing_starts
):
    name = "no-such-" + secrets.token_hex(4)

    said, record = refused(
        tmp_path,
        capsys,
        ["--identity", "filed"],
        "token",
        words=["identity filed: token_file cannot be read"],
        identities=[{"name": "filed", "role": "r", "token_file": f"tokens/{name}"}],
    )

    for text in (said, json.dumps(record.to_dict())):
        assert name not in text and "tokens/" not in text


# -- a token file stays in the engagement file's directory --------------------------------------


def token_file_engagement(tmp_path, token_file):
    return write_engagement(
        tmp_path / "engagement",
        identities=[IDENTITIES[0], {"name": "filed", "role": "r", "token_file": token_file}],
    )


def test_a_token_file_outside_the_directory_is_refused_by_the_field_and_not_by_the_path(tmp_path):
    outside = "elsewhere-" + secrets.token_hex(4)
    (tmp_path / outside).write_text(made_up() + "\n")

    for written in (f"../{outside}", f"tokens/../../{outside}"):
        held = token_file_engagement(tmp_path, written)

        with pytest.raises(EngagementError) as refused_file:
            engagement.load(held)

        assert "identities[1].token_file: " in str(refused_file.value)
        assert outside not in str(refused_file.value) and ".." not in str(refused_file.value)


def test_a_link_in_the_directory_that_points_outside_is_refused(tmp_path):
    outside = tmp_path / ("elsewhere-" + secrets.token_hex(4))
    outside.write_text(made_up() + "\n")
    held = token_file_engagement(tmp_path, "link")
    (held.parent / "link").symlink_to(outside)

    with pytest.raises(EngagementError) as refused_file:
        engagement.load(held)

    assert "identities[1].token_file: " in str(refused_file.value)
    assert outside.name not in str(refused_file.value)


def test_a_link_that_leaves_the_directory_is_refused_by_the_run_with_exit_2(
    tmp_path, capsys, nothing_starts, monkeypatch
):
    outside = tmp_path / ("elsewhere-" + secrets.token_hex(4))
    outside.write_text(made_up() + "\n")
    held = token_file_engagement(tmp_path, "link")
    (held.parent / "link").symlink_to(outside)

    code, events, out_dir = drive(
        tmp_path, "--http", "http://127.0.0.1:9/mcp", "--identity", "filed", file=held
    )

    assert code == 2 and events == []
    said = capsys.readouterr().err
    assert "identities[1].token_file" in said and outside.name not in said


def test_read_credentials_checks_the_directory_again_before_it_opens(tmp_path, monkeypatch):
    """The file was checked when it was read; a link made after that is caught at the open."""
    value = made_up("fl")
    outside = tmp_path / ("elsewhere-" + secrets.token_hex(4))
    outside.write_text(value + "\n")
    held = engagement.load(token_file_engagement(tmp_path, "tokens/filed"))
    (tmp_path / "engagement" / "tokens").mkdir()
    (tmp_path / "engagement" / "tokens" / "filed").symlink_to(outside)
    args = type("Args", (), {"identity": "filed"})()

    with pytest.raises(cli.CredentialError) as refused_open:
        cli.read_credentials(args, held)

    assert str(refused_open.value) == "identity filed: token_file cannot be read"
    assert value not in str(refused_open.value) and outside.name not in str(refused_open.value)


def swapping_after_the_check(monkeypatch, swap):
    """``engagement.token_file_inside`` as it is, but for what happens after it has said yes to
    the reading of an identity's token (``cli._identity_token``, which ``read_credentials``
    calls; the load of the file asks as well): ``swap()`` runs, once, as another process could
    between the check and the open."""
    checked = engagement.token_file_inside
    done = []

    def check(directory, token_file):
        inside = checked(directory, token_file)
        if inside and not done and sys._getframe(1).f_code.co_name == "_identity_token":
            done.append(True)
            swap()
        return inside

    monkeypatch.setattr(engagement, "token_file_inside", check)
    return done


def swap_directory(directory, outside):
    """``tokens`` replaced by a link to the directory ``outside``, which holds a file of the same
    name."""

    def swap():
        (directory / "tokens").rename(directory / "tokens-before")
        (directory / "tokens").symlink_to(outside.parent)

    return swap


def swap_file(directory, outside):
    """``tokens/filed`` replaced by a link to the file ``outside``."""

    def swap():
        (directory / "tokens" / "filed").unlink()
        (directory / "tokens" / "filed").symlink_to(outside)

    return swap


def outside_the_directory(tmp_path):
    """A file beside the engagement directory, holding a value, named ``filed`` in a directory
    of its own; and the real file in the engagement directory."""
    value = made_up("fl")
    outside = tmp_path / "elsewhere" / "filed"
    outside.parent.mkdir()
    outside.write_text(value + "\n")
    held = token_file_engagement(tmp_path, "tokens/filed")
    (held.parent / "tokens").mkdir()
    (held.parent / "tokens" / "filed").write_text(made_up("in") + "\n")
    return value, outside, held


@pytest.mark.parametrize("swap", [swap_directory, swap_file], ids=["directory", "file"])
def test_read_credentials_reads_the_file_it_checked_and_not_what_the_name_became(
    tmp_path, monkeypatch, swap
):
    """The check said yes; then a part of the path became a link out. The open file is not
    inside the directory, so it is not read, and the words are those of a file outside."""
    value, outside, held = outside_the_directory(tmp_path)
    loaded = engagement.load(held)
    done = swapping_after_the_check(monkeypatch, swap(held.parent, outside))
    args = type("Args", (), {"identity": "filed"})()

    with pytest.raises(cli.CredentialError) as refused_open:
        cli.read_credentials(args, loaded)

    assert done, "the path was swapped between the check and the open"
    assert str(refused_open.value) == "identity filed: token_file cannot be read"
    assert value not in str(refused_open.value) and "elsewhere" not in str(refused_open.value)


def test_the_swap_is_caught_without_any_help_from_the_system_naming_descriptors(
    tmp_path, monkeypatch
):
    """The open walks the path part by part and follows no link, so no /proc name and no
    identity of an inode is needed: with ``os.readlink`` failing, the directory swapped for a
    link out is still refused, and the file inside is still read."""
    value, outside, held = outside_the_directory(tmp_path)
    loaded = engagement.load(held)

    def readlink(*_args, **_kwargs):
        raise OSError("no /proc here")

    monkeypatch.setattr(os, "readlink", readlink)
    args = type("Args", (), {"identity": "filed"})()
    inside = cli.read_credentials(args, loaded)[0]
    assert inside is not None and inside.reveal() != value

    done = swapping_after_the_check(monkeypatch, swap_directory(held.parent, outside))
    with pytest.raises(cli.CredentialError) as refused_open:
        cli.read_credentials(args, loaded)

    assert done, "the directory was swapped between the check and the open"
    assert str(refused_open.value) == "identity filed: token_file cannot be read"
    assert value not in str(refused_open.value)


@pytest.mark.parametrize("swap", [swap_directory, swap_file], ids=["directory", "file"])
def test_a_run_whose_token_file_is_swapped_after_the_check_is_refused_and_sends_nothing(
    tmp_path, capsys, monkeypatch, serve, swap
):
    value, outside, held = outside_the_directory(tmp_path)
    monkeypatch.setenv("TEST_TOKEN_OUTSIDE", value)
    server = serve(token_envs=("TEST_TOKEN_OUTSIDE",))
    swapping_after_the_check(monkeypatch, swap(held.parent, outside))

    code, events, out_dir = drive(
        tmp_path, "--http", url_of(server), "--identity", "filed", file=held
    )

    assert code == 2 and events == []
    assert authorizations(server) == [], "no request left"
    said = capsys.readouterr()
    assert "identity filed: token_file cannot be read" in said.err
    for path in out_dir.rglob("*"):
        if path.is_file():
            assert value.encode() not in path.read_bytes(), path.name
    assert value not in said.out + said.err and "elsewhere" not in said.out + said.err


def test_a_token_file_that_is_a_fifo_is_refused_and_the_open_does_not_wait(tmp_path):
    held = token_file_engagement(tmp_path, "fifo")
    os.mkfifo(held.parent / "fifo")
    loaded = engagement.load(held)
    args = type("Args", (), {"identity": "filed"})()
    outcome = []

    def read():
        try:
            cli.read_credentials(args, loaded)
        except cli.CredentialError as refused_open:
            outcome.append(str(refused_open))

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(5)
    if reader.is_alive():  # an open that waits for a writer: let it go, then fail
        descriptor = os.open(held.parent / "fifo", os.O_WRONLY | os.O_NONBLOCK)
        os.close(descriptor)
        reader.join(5)
        pytest.fail("the open of a FIFO waited for a writer")

    assert outcome == ["identity filed: token_file cannot be read"]


def test_a_subdirectory_and_a_link_that_stays_inside_are_read(tmp_path, monkeypatch, serve):
    value = made_up("fl")
    directory = tmp_path / "engagement"
    (directory / "tokens").mkdir(parents=True)
    (directory / "tokens" / "real").write_text(value + "\n")
    (directory / "inside").symlink_to(directory / "tokens" / "real")
    monkeypatch.setenv("TEST_TOKEN_FILE_SIDE", value)
    server = serve(token_envs=("TEST_TOKEN_FILE_SIDE",))

    for written in ("tokens/real", "inside", "tokens/../tokens/real"):
        held = token_file_engagement(tmp_path, written)
        code, _, _ = drive(tmp_path, "--http", url_of(server), "--identity", "filed", file=held)

        assert code == 0, written
    assert set(authorizations(server)) == {f"Bearer {value}"}


def test_a_secret_header_that_is_not_set_is_refused_by_its_variable(
    tmp_path, capsys, nothing_starts, tokens, monkeypatch
):
    monkeypatch.delenv("TEST_APIM_KEY", raising=False)

    refused(
        tmp_path,
        capsys,
        ["--identity", "reader"],
        "token",
        words=["Ocp-Apim-Subscription-Key", "TEST_APIM_KEY", "is not set"],
        identities=[
            {**IDENTITIES[0], "headers": {"Ocp-Apim-Subscription-Key": {"env": "TEST_APIM_KEY"}}}
        ],
    )


def test_every_new_condition_and_reason_is_one_the_record_knows():
    new = {
        "identity_not_declared",
        "identity_required",
        "token_not_declared",
        "token_source_differs",
    }
    assert new <= set(engagement.CONDITIONS) and new <= set(engagement.REFUSAL_REASONS)
    assert "token" in engagement.REFUSAL_REASONS and "token" not in engagement.CONDITIONS


def test_the_flags_belong_to_an_http_run_and_an_identity_to_a_file(
    tmp_path, capsys, nothing_starts, tokens
):
    out_dir = tmp_path / "runs"
    held = write_engagement(tmp_path / "engagement", identities=IDENTITIES)
    stdio = ["--", sys.executable, DISCOVERY]

    for args, words in (
        (["--token-env", "TEST_TOKEN_READER", *stdio], "belong to a run over HTTP"),
        (["--identity", "reader", *stdio], "belong to a run over HTTP"),
    ):
        code = cli.main(["drive", "--engagement", str(held), "--out-dir", str(out_dir), *args])
        assert code == 2 and words in capsys.readouterr().err
    code = cli.main(["drive", "--http", "http://127.0.0.1:9/mcp", "--identity", "reader"])
    assert code == 2 and "give --engagement" in capsys.readouterr().err
    assert [r.reason for r in refusals_in(out_dir)] == ["arguments", "arguments"]


def test_the_two_token_flags_exclude_each_other(tmp_path, capsys):
    with pytest.raises(SystemExit) as exited:
        cli.main(
            ["drive", "--http", "http://127.0.0.1:9/mcp", "--token-env", "A", "--token-file", "f"]
        )

    assert exited.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_a_value_typed_where_a_variable_s_name_goes_is_not_repeated(tmp_path, capsys):
    typed = made_up("sk") + " with space"

    with pytest.raises(SystemExit):
        cli.main(["drive", "--http", "http://127.0.0.1:9/mcp", "--token-env", typed])

    assert typed not in capsys.readouterr().err


# -- two identities against the fixture --------------------------------------------------------


def authorizations(server) -> list[str | None]:
    return [seen["authorization"] for seen in server.behaviour.received]


def test_each_run_sends_the_token_of_its_identity_and_the_recording_names_it(
    tmp_path, tokens, serve, capsys
):
    server = serve(token_envs=("TEST_TOKEN_READER", "TEST_TOKEN_ADMIN"))
    seen = {}

    for name in ("reader", "admin"):
        server.behaviour.received.clear()
        code, events, _ = drive(
            tmp_path / name,
            "--http", url_of(server), "--identity", name,
            identities=IDENTITIES,
        )  # fmt: skip
        assert code == 0, capsys.readouterr().err
        assert set(authorizations(server)) == {f"Bearer {tokens[name]}"}, name
        seen[name] = next(e for e in events if e["type"] == "run_started")

    assert seen["reader"]["auth"] == {
        "identity": "reader",
        "role": "read-only user",
        "token_used": True,
        "source": "env",
        "env_name": "TEST_TOKEN_READER",
        "token": NOT_A_JWT,
        "observation": None,
    }
    assert seen["admin"]["auth"]["identity"] == "admin"
    assert seen["admin"]["auth"]["role"] == "administrator"


def test_the_recording_names_the_identity_and_the_role_and_never_a_value(tmp_path, tokens, serve):
    server = serve(token_envs=("TEST_TOKEN_READER",))

    code, events, out_dir = drive(
        tmp_path, "--http", url_of(server), "--identity", "reader", identities=IDENTITIES
    )

    assert code == 0
    auth = next(e for e in events if e["type"] == "run_started")["auth"]
    assert auth == {
        "identity": "reader",
        "role": "read-only user",
        "token_used": True,
        "source": "env",
        "env_name": "TEST_TOKEN_READER",
        "token": NOT_A_JWT,
        "observation": None,
    }
    assert tokens["reader"] not in recording_in(out_dir).read_text()


def test_an_identity_from_a_file_is_read_relative_to_the_engagement_file(
    tmp_path, monkeypatch, serve
):
    value = made_up("fl")
    directory = tmp_path / "engagement"
    directory.mkdir()
    (directory / "reader-token").write_text(value + "\n")
    monkeypatch.setenv("TEST_TOKEN_FILE_SIDE", value)
    server = serve(token_envs=("TEST_TOKEN_FILE_SIDE",))
    monkeypatch.chdir(tmp_path)  # not where the file is: the path is the file's, not the shell's

    code, _, _ = drive(
        tmp_path,
        "--http", url_of(server), "--identity", "filed",
        identities=[{"name": "filed", "role": "r", "token_file": "reader-token"}],
    )  # fmt: skip

    assert code == 0
    assert set(authorizations(server)) == {f"Bearer {value}"}


def test_a_token_flag_without_a_file_is_sent_as_it_always_was(tmp_path, tokens, serve):
    server = serve(token_envs=("TEST_TOKEN_READER",))
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "-q", "--http", url_of(server), "--token-env", "TEST_TOKEN_READER",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 0
    assert set(authorizations(server)) == {f"Bearer {tokens['reader']}"}
    assert tokens["reader"] not in recording_in(out_dir).read_text()
    assert started_of(recording_in(out_dir))["auth"] == {
        "identity": None,
        "role": None,
        "token_used": True,
        "source": "env",
        "env_name": "TEST_TOKEN_READER",
        "token": NOT_A_JWT,
        "observation": None,
    }


def test_a_token_from_a_file_flag_is_sent_and_recorded_as_a_file(tmp_path, tokens, serve):
    server = serve(token_envs=("TEST_TOKEN_READER",))
    token_file = tmp_path / "token"
    token_file.write_text(tokens["reader"] + "\n")
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "-q", "--http", url_of(server), "--token-file", str(token_file),
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 0
    assert set(authorizations(server)) == {f"Bearer {tokens['reader']}"}
    assert started_of(recording_in(out_dir))["auth"]["source"] == "file"


# -- an identity with no token ----------------------------------------------------------------


def test_an_identity_with_no_token_sends_no_authorization_header_and_says_so(
    tmp_path, serve, capsys
):
    server = serve()  # asks for nothing

    code, events, _ = drive(
        tmp_path, "--http", url_of(server), "--identity", "anonymous", identities=IDENTITIES
    )

    assert code == 0, capsys.readouterr().err
    assert server.behaviour.received, "requests arrived"
    assert set(authorizations(server)) == {None}, "no Authorization header came"
    headers = [e["headers"] for e in events if e["type"] == "http_request"]
    assert headers and all("authorization" not in h for h in headers)
    assert next(e for e in events if e["type"] == "run_started")["auth"] == {
        "identity": "anonymous",
        "role": "not signed in",
        "token_used": False,
        "source": "none",
        "token": None,
        "observation": None,
    }


def test_an_identity_with_no_token_meets_a_server_that_wants_one(tmp_path, tokens, serve, capsys):
    server = serve(token_envs=("TEST_TOKEN_READER",))

    code, events, _ = drive(
        tmp_path, "--http", url_of(server), "--identity", "anonymous", identities=IDENTITIES
    )

    assert code == cli.EXIT_SERVER_FAILED
    (failed,) = [e for e in events if e["type"] == "server_failed"]
    assert failed["reason"] == "unauthorized"
    assert set(authorizations(server)) == {None}
    assert "unauthorized (401)" in capsys.readouterr().err


# -- secret headers ----------------------------------------------------------------------------


def test_an_identity_sends_its_secret_headers_and_they_are_replaced_whole(
    tmp_path, tokens, serve, monkeypatch, capsys
):
    key = made_up("key")
    monkeypatch.setenv("TEST_APIM_KEY", key)
    server = serve(
        token_envs=("TEST_TOKEN_READER",),
        header_envs={"Ocp-Apim-Subscription-Key": "TEST_APIM_KEY"},
    )

    code, events, out_dir = drive(
        tmp_path,
        "--http", url_of(server), "--identity", "reader",
        identities=[
            {**IDENTITIES[0], "headers": {"Ocp-Apim-Subscription-Key": {"env": "TEST_APIM_KEY"}}}
        ],
    )  # fmt: skip

    assert code == 0, capsys.readouterr().err
    assert {seen["ocp-apim-subscription-key"] for seen in server.behaviour.received} == {key}
    sent = [e["headers"] for e in events if e["type"] == "http_request"]
    assert sent and all(h["ocp-apim-subscription-key"] == "***REDACTED***" for h in sent)
    assert key not in recording_in(out_dir).read_text()


def test_a_declared_secret_header_is_replaced_whole_whether_this_run_sent_it_or_not(
    tmp_path, tokens, serve
):
    # The server sends X-Reflected, which this run never sent; the file names it secret.
    server = serve(token_envs=("TEST_TOKEN_READER",), reflect=("Authorization",))
    out_dir = tmp_path / "runs"
    held = write_engagement(
        tmp_path / "engagement", identities=IDENTITIES, secret_headers=["x-reflected"]
    )

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--http", url_of(server),
         "--identity", "reader", "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 0
    responses = [
        e["headers"] for e in events_of(recording_in(out_dir)) if e["type"] == "http_response"
    ]
    assert responses and all(h["x-reflected"] == "***REDACTED***" for h in responses)
