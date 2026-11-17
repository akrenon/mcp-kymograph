"""The canary and the fixtures of the benchmark runner (runner/fixtures.py).

What they must hold: the canary is one sentence the signals recognise and no tool on the way
rewrites; every kind of fixture builds, byte for byte the same for the same canary, with the id
where it belongs and nowhere else; the hash names the shape and does not move with the id; and
nothing of the host is in an archive.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest

from mcp_kymograph import signals

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "bench_fixtures", ROOT / "benchmarks" / "local-servers" / "runner" / "fixtures.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fixtures = _load()

#: The password of the role ``reader`` in the tests that are not about it. A fixture of the kind
#: postgres has none by itself (the runner makes one for each run), so the tests give it.
PASSWORD = "p" * 32
_build_real = fixtures.build


def _build(kind, canary, **options):
    if kind == "postgres":
        options.setdefault("reader_password", PASSWORD)
    return _build_real(kind, canary, **options)


fixtures.build = _build

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git on the host")


def _utc_offset_spelled_out(date: str) -> str:
    """git's strict ISO date with UTC written as ``+00:00``: newer git writes ``%aI`` with a
    ``Z`` where older git wrote ``+00:00``. Only that suffix is rewritten, so any other form or
    offset still fails the comparison."""
    return date[:-1] + "+00:00" if date.endswith("Z") else date


def _members(fixture) -> dict[str, bytes | None]:
    with tarfile.open(fileobj=io.BytesIO(fixture.archive)) as archive:
        result: dict[str, bytes | None] = {}
        for member in archive.getmembers():
            handle = archive.extractfile(member)
            result[member.name] = handle.read() if handle else None
        return result


def _kinds():
    return [pytest.param(kind, id=kind) for kind in fixtures.KINDS if kind != "git"] + [
        pytest.param("git", id="git", marks=needs_git)
    ]


# -- the canary ---------------------------------------------------------------------------


def test_canary_has_its_form():
    canary = fixtures.new_canary("my-server.v2")
    assert re.fullmatch(r"MCPB-CANARY-MY-SERVER-V2-[0-9a-f]{8}", canary.id)
    assert canary.placeholder == "MCPB-CANARY-MY-SERVER-V2-xxxxxxxx"
    assert fixtures.CANARY_PATTERN.fullmatch(canary.id)
    assert fixtures.CANARY_PATTERN.fullmatch(canary.placeholder)
    assert fixtures.new_canary("my-server.v2").id != canary.id


def test_canary_pattern_ignores_what_is_not_a_canary():
    assert not fixtures.CANARY_PATTERN.search("MCPB-CANARY-X-1234")
    assert not fixtures.CANARY_PATTERN.search("MCPB-CANARY-x-abcdef12")
    found = fixtures.CANARY_PATTERN.findall("a MCPB-CANARY-A-0123abcd, b MCPB-CANARY-A-xxxxxxxx.")
    assert found == ["MCPB-CANARY-A-0123abcd", "MCPB-CANARY-A-xxxxxxxx"]


def test_canary_pattern_is_not_quadratic_on_a_text_of_many_starts():
    text = "MCPB-CANARY-" * 100_000
    started = time.monotonic()
    assert fixtures.CANARY_PATTERN.search(text) is None
    assert time.monotonic() - started < 5


def test_the_name_of_a_long_server_is_cut_to_what_the_pattern_reads():
    canary = fixtures.new_canary("s" * 100)
    assert fixtures.CANARY_PATTERN.fullmatch(canary.id)
    assert fixtures.CANARY_PATTERN.fullmatch(canary.placeholder)


def test_canary_text_fires_the_override_signal():
    text = fixtures.canary_text(fixtures.new_canary("fetch").id)
    assert text.endswith(fixtures.PAYLOAD)
    assert signals.fires(signals.Signal.INSTRUCTION_OVERRIDE, text)


def test_canary_text_is_not_rewritten_by_repr_json_or_markdown():
    text = fixtures.canary_text(fixtures.new_canary("fetch").id)
    for character in "\"'\\*_[<>`":
        assert character not in text
    assert repr(text) == "'" + text + "'"
    assert json.dumps(text) == '"' + text + '"'
    assert text.isascii()


# -- every kind ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _kinds())
def test_kind_builds_and_is_deterministic(kind):
    canary = fixtures.new_canary("fetch")
    first = fixtures.build(kind, canary)
    second = fixtures.build(kind, canary)
    assert first.kind == kind
    assert first.archive == second.archive
    assert first.sha256 == second.sha256
    assert first.files == tuple(sorted(first.files))
    assert set(first.files) == set(_members(first))


@pytest.mark.parametrize("kind", _kinds())
def test_archive_carries_no_time_owner_or_host_path(kind, tmp_path, monkeypatch):
    # Built under another temporary directory and home: the bytes must not move.
    canary = fixtures.new_canary("fetch")
    reference = fixtures.build(kind, canary).archive
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("TMPDIR", str(elsewhere))
    monkeypatch.setenv("HOME", str(elsewhere))
    monkeypatch.setattr(fixtures.tempfile, "tempdir", None)
    fixture = fixtures.build(kind, canary)
    assert fixture.archive == reference
    assert str(elsewhere).encode() not in fixture.archive
    assert b"mcpb-fixture-" not in fixture.archive
    with tarfile.open(fileobj=io.BytesIO(fixture.archive)) as archive:
        for member in archive.getmembers():
            assert (member.mtime, member.uid, member.gid) == (0, 0, 0)
            assert (member.uname, member.gname) == ("", "")
            assert member.mode in (0o644, 0o755)
            assert not member.name.startswith("/")
            assert ".." not in member.name.split("/")


@pytest.mark.parametrize("kind", _kinds())
def test_hash_names_the_shape_and_not_the_id(kind):
    first = fixtures.build(kind, fixtures.new_canary("fetch"))
    second = fixtures.build(kind, fixtures.new_canary("fetch"))
    assert first.archive != second.archive
    assert first.sha256 == second.sha256
    canary = fixtures.new_canary("fetch")
    # The password, for the kind that has one, is replaced the same way (see below).
    options = {"reader_password": fixtures.READER_PLACEHOLDER} if kind == "postgres" else {}
    on_placeholder = fixtures.build(
        kind, fixtures.Canary(canary.placeholder, canary.placeholder), **options
    )
    assert first.sha256 == hashlib.sha256(on_placeholder.archive).hexdigest()


def test_hash_changes_with_the_kind():
    canary = fixtures.new_canary("fetch")
    hashes = {fixtures.build(kind, canary).sha256 for kind in fixtures.KINDS if kind != "git"}
    assert len(hashes) == len(fixtures.KINDS) - 1


def test_unknown_kind_is_refused():
    with pytest.raises(ValueError, match="unknown fixture kind"):
        fixtures.build("tarball", fixtures.new_canary("fetch"))


def _only_once(kind: str, name: str) -> tuple[str, bytes]:
    canary = fixtures.new_canary("fetch")
    members = _members(fixtures.build(kind, canary))
    return canary.id, members[name]


def test_file_holds_the_canary_text_once():
    canary_id, content = _only_once("file", "kanarie.txt")
    assert content.decode() == fixtures.canary_text(canary_id) + "\n"


def test_sqlite_is_readable_and_holds_the_canary_once(tmp_path):
    canary = fixtures.new_canary("sqlite")
    fixture = fixtures.build("sqlite", canary)
    assert fixture.files == ("kanarie.db",)
    path = tmp_path / "kanarie.db"
    path.write_bytes(_members(fixture)["kanarie.db"])
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute("SELECT id, note FROM kanarie").fetchall()
        schema = connection.execute("SELECT sql FROM sqlite_master").fetchall()
    finally:
        connection.close()
    assert rows == [(1, fixtures.canary_text(canary.id))]
    assert "note TEXT NOT NULL" in schema[0][0]


@needs_git
def test_git_shows_the_message_and_holds_nothing_of_the_host(tmp_path):
    canary = fixtures.new_canary("git")
    fixture = fixtures.build("git", canary)
    names = set(fixture.files)
    assert "repo/README.txt" in names and "repo/.git/HEAD" in names
    assert "repo/.git/index" not in names
    assert not any("hooks" in name or "logs" in name for name in names)
    with tarfile.open(fileobj=io.BytesIO(fixture.archive)) as archive:
        archive.extractall(tmp_path, filter="data")
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
    }

    def git(*args: str) -> str:
        done = subprocess.run(  # noqa: S603 - fixed program, arguments built here
            ["git", "-C", str(tmp_path / "repo"), *args],  # noqa: S607
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return done.stdout

    assert git("log", "--format=%B").strip() == fixtures.canary_text(canary.id)
    author, committer, authored, committed = (
        git("log", "--format=%an <%ae>|%cn <%ce>|%aI|%cI").strip().split("|")
    )
    assert author == committer == "mcp-kymograph fixture <fixture@example.invalid>"
    assert [_utc_offset_spelled_out(date) for date in (authored, committed)] == [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00+00:00",
    ]
    assert git("rev-parse", "--abbrev-ref", "HEAD").strip() == "main"
    assert git("show", "HEAD:README.txt").strip()
    git("fsck", "--no-dangling")
    assert git("rev-list", "--count", "HEAD").strip() == "1"


def test_postgres_script_grants_reader_select_only():
    canary_id, content = _only_once("postgres", "init.sql")
    sql = content.decode()
    assert sql.count(canary_id) == 1
    assert "CREATE TABLE kanarie (note text NOT NULL);" in sql
    assert f"CREATE ROLE reader LOGIN PASSWORD '{PASSWORD}';" in sql
    assert not hasattr(fixtures, "READER_PASSWORD")
    assert "GRANT SELECT ON TABLE kanarie TO reader;" in sql
    assert "GRANT USAGE ON SCHEMA public TO reader;" in sql
    assert "GRANT CONNECT ON DATABASE" in sql
    assert "REVOKE ALL ON SCHEMA public FROM PUBLIC;" in sql
    grants = [line for line in sql.splitlines() if line.startswith("GRANT")]
    assert not any(
        word in line for line in grants for word in ("ALL", "INSERT", "UPDATE", "DELETE")
    )
    assert sql.count("'") % 2 == 0


def test_the_password_of_reader_is_the_runs_own_and_not_in_the_hash():
    canary = fixtures.new_canary("fetch")
    first = _build_real("postgres", canary, reader_password="a" * 32)
    second = _build_real("postgres", canary, reader_password="b" * 32)
    assert first.archive != second.archive
    assert b"a" * 32 in first.archive and b"a" * 32 not in second.archive
    # The shape does not move with the password, as it does not with the id.
    assert first.sha256 == second.sha256
    on_placeholder = _build_real(
        "postgres",
        fixtures.Canary(canary.placeholder, canary.placeholder),
        reader_password=fixtures.READER_PLACEHOLDER,
    )
    assert first.sha256 == hashlib.sha256(on_placeholder.archive).hexdigest()
    # ... and it is part of the shape in this sense: the hash is of a fixture with a password.
    assert fixtures.READER_PLACEHOLDER.encode() in on_placeholder.archive


def test_a_postgres_fixture_has_no_password_unless_it_is_given_one():
    with pytest.raises(ValueError, match="password"):
        _build_real("postgres", fixtures.new_canary("fetch"))
    assert not any(
        isinstance(value, str) and "password" in name.lower() and name.isupper()
        for name, value in vars(fixtures).items()
    )


@pytest.mark.parametrize(
    "password", ["", "short", "it's-a-quote-" + "x" * 20, "a b" * 10, "a;--" * 8]
)
def test_a_password_that_needs_quoting_is_refused(password):
    with pytest.raises(ValueError, match="password"):
        _build_real("postgres", fixtures.new_canary("fetch"), reader_password=password)


class _Paragraphs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.paragraphs: list[tuple[tuple[str, ...], str]] = []
        self.attrs: dict[str, dict[str, str | None]] = {}
        self.scripts: list[str] = []
        self._text = ""

    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)
        self.attrs.setdefault(tag, dict(attrs))
        self._text = ""

    def handle_endtag(self, tag):
        if tag == "p":
            self.paragraphs.append((tuple(self.stack), self._text))
        if tag == "script":
            self.scripts.append(self._text)
        self.stack.pop()

    def handle_data(self, data):
        self._text += data


def test_page_puts_the_canary_in_the_article_text():
    canary = fixtures.new_canary("fetch")
    fixture = fixtures.build("page", canary)
    assert set(fixture.files) == {"canary.html", "robots.txt"}
    members = _members(fixture)
    assert members["robots.txt"] == b"User-agent: *\nAllow: /\n"
    html = members["canary.html"].decode()
    assert html.startswith("<!DOCTYPE html>")
    assert html.count(canary.id) == 1
    parser = _Paragraphs()
    parser.feed(html)
    assert parser.attrs["html"]["lang"] == "en"
    assert parser.attrs["meta"]["charset"] == "utf-8"
    assert "h1" in parser.attrs
    (stack, text), *rest = parser.paragraphs
    assert not rest
    assert stack[-3:] == ("main", "article", "p")
    assert " ".join(text.split()).count(fixtures.canary_text(canary.id)) == 1
    assert len(text.split(".")) > 3  # several sentences, not a bare line


def test_page_js_does_not_hold_the_id_in_its_source():
    canary = fixtures.new_canary("fetch")
    fixture = fixtures.build("page-js", canary)
    assert set(fixture.files) == {"canary-js.html", "robots.txt"}
    assert canary.id.encode() not in fixture.archive
    assert canary.id.split("-")[-1].encode() not in fixture.archive
    html = _members(fixture)["canary-js.html"].decode()
    assert 'lang="en"' in html and 'charset="utf-8"' in html
    parser = _Paragraphs()
    parser.feed(html)
    (script,) = parser.scripts
    encoded = re.search(r'atob\("([A-Za-z0-9+/=]+)"\)', script).group(1)
    assert base64.b64decode(encoded).decode() == fixtures.canary_text(canary.id)
    assert "textContent" in script


def test_positive_has_the_three_forms():
    canary = fixtures.new_canary("positive")
    content = _members(fixtures.build("positive", canary))["kanarie.txt"].decode()
    plain, comment, hidden = content.splitlines()
    text = fixtures.canary_text(canary.id)
    assert plain == text
    assert comment == f"<!-- {text} -->"
    zero_width_space = chr(0x200B)
    assert zero_width_space in hidden
    assert hidden.replace(zero_width_space, "") == text
    assert not signals.fires(signals.Signal.INVISIBLE_CHARACTERS, plain)
    assert signals.fires(signals.Signal.INVISIBLE_CHARACTERS, hidden)
    assert signals.fires(signals.Signal.HIDDEN_COMMENT, comment)
    assert signals.fires(signals.Signal.INSTRUCTION_OVERRIDE, hidden)
