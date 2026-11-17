"""Reading a token and a secret header (credentials.py): the limits, and that a refusal names the
source and never a byte of what it held."""

from __future__ import annotations

import secrets

import pytest

from mcp_kymograph.credentials import (
    MAX_SECRET_BYTES,
    CredentialError,
    SecretHeader,
    Token,
    auth_record,
)


def made_up(prefix: str = "tok") -> str:
    """A value for a test, put together at run time: no secret scanner has seen it."""
    return prefix + secrets.token_hex(12)


def written(tmp_path, content: bytes, name: str = "token") -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


# -- reading from a file -------------------------------------------------------------------


def test_a_file_is_read_once_with_its_one_trailing_newline_dropped(tmp_path):
    value = made_up()

    for ending in (b"", b"\n", b"\r\n"):
        token = Token.from_file(written(tmp_path, value.encode() + ending))
        assert token.reveal() == value
        assert token.authorization() == f"Bearer {value}"
        assert (token.source, token.env_name) == ("file", None)


def test_only_one_line_ending_is_dropped_and_a_second_one_is_refused(tmp_path):
    with pytest.raises(CredentialError, match="not visible ASCII"):
        Token.from_file(written(tmp_path, made_up().encode() + b"\n\n"))


def test_sixteen_kib_is_read_and_one_byte_more_is_refused(tmp_path):
    exactly = "a" * MAX_SECRET_BYTES

    assert Token.from_file(written(tmp_path, exactly.encode() + b"\n")).reveal() == exactly
    with pytest.raises(CredentialError, match="longer than 16384 bytes"):
        Token.from_file(written(tmp_path, b"a" * (MAX_SECRET_BYTES + 1)))


def test_a_file_that_is_far_too_long_is_not_read_whole(tmp_path):
    path = tmp_path / "huge"
    with path.open("wb") as handle:
        handle.truncate(512 * 1024 * 1024)  # a sparse file: reading it whole would show

    with pytest.raises(CredentialError, match="longer than"):
        Token.from_file(str(path))


@pytest.mark.parametrize(
    "content",
    [b"with space", b"tab\there", b"line\nbreak", "café".encode(), b"nul\x00byte", b"\x7f"],
)
def test_anything_but_visible_ascii_is_refused_without_a_word_of_the_content(tmp_path, content):
    path = written(tmp_path, b"SECRET" + content)

    with pytest.raises(CredentialError) as refused:
        Token.from_file(path)

    words = str(refused.value)
    assert path in words, "the source is named"
    assert "not visible ASCII" in words
    assert "SECRET" not in words and "SECRET" not in repr(refused.value)


@pytest.mark.parametrize("content", [b"", b"\n", b"\r\n"])
def test_an_empty_file_is_refused(tmp_path, content):
    with pytest.raises(CredentialError, match="is empty"):
        Token.from_file(written(tmp_path, content))


def test_a_file_that_is_not_there_is_refused_by_its_path(tmp_path):
    path = str(tmp_path / "missing")

    with pytest.raises(CredentialError, match="cannot be read") as refused:
        Token.from_file(path)

    assert path in str(refused.value)


def test_a_directory_is_not_a_token_file(tmp_path):
    with pytest.raises(CredentialError, match="cannot be read"):
        Token.from_file(str(tmp_path))


# -- reading from the environment -----------------------------------------------------------


def test_a_variable_is_read_as_a_file_is(monkeypatch):
    value = made_up()
    monkeypatch.setenv("TEST_TOKEN_A", value + "\n")

    token = Token.from_env("TEST_TOKEN_A")

    assert token.reveal() == value
    assert (token.source, token.env_name) == ("env", "TEST_TOKEN_A")


@pytest.mark.parametrize("content", ["", "\n", "two words", "café", "a" * (16 * 1024 + 1)])
def test_a_variable_that_cannot_be_used_is_refused_by_its_name(monkeypatch, content):
    monkeypatch.setenv("TEST_TOKEN_A", content)

    with pytest.raises(CredentialError) as refused:
        Token.from_env("TEST_TOKEN_A")

    assert "TEST_TOKEN_A" in str(refused.value)
    assert "two words" not in str(refused.value) and "caf" not in str(refused.value)


def test_a_variable_that_is_not_set_is_refused_by_its_name(monkeypatch):
    monkeypatch.delenv("TEST_TOKEN_A", raising=False)

    with pytest.raises(CredentialError, match="TEST_TOKEN_A.*is not set"):
        Token.from_env("TEST_TOKEN_A")


def test_a_name_that_is_not_a_variable_s_is_refused_and_not_repeated():
    value = made_up()  # a token typed where a name goes

    with pytest.raises(CredentialError) as refused:
        Token.from_env(value + " x")

    assert value not in str(refused.value)


# -- what is never shown --------------------------------------------------------------------


def test_repr_and_str_say_where_a_token_came_from_and_never_what_it_is(tmp_path, monkeypatch):
    value = made_up()
    monkeypatch.setenv("TEST_TOKEN_A", value)

    from_env = Token.from_env("TEST_TOKEN_A")
    from_file = Token.from_file(written(tmp_path, value.encode()))

    assert repr(from_env) == str(from_env) == "<token from env TEST_TOKEN_A>"
    assert repr(from_file) == str(from_file) == "<token from a file>"
    assert value not in f"{from_env!r}{from_file!r}{from_env}{from_file}"
    assert value not in repr((from_env.source, from_env.env_name, from_file.source))


def test_the_value_is_one_private_attribute():
    token = Token("v" * 8, source="file")

    assert not hasattr(token, "__dict__"), "no attribute is added beside the slots"
    assert {name for name in dir(token) if getattr(token, name, None) == "v" * 8} == {"_value"}


# -- secret headers -------------------------------------------------------------------------


def test_a_secret_header_takes_its_value_from_a_variable(monkeypatch):
    value = made_up("key")
    monkeypatch.setenv("TEST_APIM_KEY", value)

    header = SecretHeader.from_env("Ocp-Apim-Subscription-Key", "TEST_APIM_KEY")

    assert (header.name, header.env_name, header.reveal()) == (
        "Ocp-Apim-Subscription-Key",
        "TEST_APIM_KEY",
        value,
    )
    assert value not in repr(header) and "TEST_APIM_KEY" in repr(header)


@pytest.mark.parametrize("name", ["Authorization", "host", "Content-Length", "Mcp-Session-Id"])
def test_a_header_the_tool_owns_is_not_an_identity_s_to_set(monkeypatch, name):
    monkeypatch.setenv("TEST_APIM_KEY", made_up())

    with pytest.raises(CredentialError, match="cannot be a header"):
        SecretHeader.from_env(name, "TEST_APIM_KEY")


def test_a_secret_header_s_value_is_held_to_the_same_limits(monkeypatch):
    monkeypatch.setenv("TEST_APIM_KEY", "two words")

    with pytest.raises(CredentialError, match="Ocp-Apim-Subscription-Key.*TEST_APIM_KEY"):
        SecretHeader.from_env("Ocp-Apim-Subscription-Key", "TEST_APIM_KEY")


# -- what run_started.auth says --------------------------------------------------------------


def test_the_record_of_a_run_names_the_identity_and_the_source_and_no_value(tmp_path, monkeypatch):
    value = made_up()
    monkeypatch.setenv("TEST_TOKEN_A", value)

    assert auth_record(
        identity="reader", role="read-only", token=Token.from_env("TEST_TOKEN_A")
    ) == {
        "identity": "reader",
        "role": "read-only",
        "token_used": True,
        "source": "env",
        "env_name": "TEST_TOKEN_A",
    }
    assert auth_record(token=Token.from_file(written(tmp_path, value.encode()))) == {
        "identity": None,
        "role": None,
        "token_used": True,
        "source": "file",
    }


def test_an_identity_without_a_token_is_recorded_as_sending_none():
    assert auth_record(identity="anonymous", role="not signed in") == {
        "identity": "anonymous",
        "role": "not signed in",
        "token_used": False,
        "source": "none",
    }


def test_a_run_with_no_identity_and_no_token_records_null():
    assert auth_record() is None
