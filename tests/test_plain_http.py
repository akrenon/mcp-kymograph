"""Plain HTTP only to a loopback literal (http-transport.md 4.4).

From another host, a recording made over plain HTTP is evidence of what arrived, not of what the
server sent, and the answers cross the network readable. So ``drive --http`` and an endpoint entry
alike are refused, exit 2, before the gate and before anything connects, when the URL is plain
``http://`` to anything but ``127.0.0.1`` or ``[::1]`` — a name, ``localhost`` included, or any
other address — and no flag opens it. Under an engagement file the refusal is written to
``refusals.jsonl`` with its own reason. Every refused run here is checked to open no connection.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"
RULE = "which is not a loopback address"


@pytest.fixture
def nothing_connects(monkeypatch):
    """Fails the test at its end if anything tried to connect or to resolve a name — kept in a
    list, because the HTTP channel catches what it is raised and reads it as unreachable."""
    attempts: list[tuple] = []

    def must_not_connect(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("a connection was opened although the run was refused")

    monkeypatch.setattr(socket, "create_connection", must_not_connect)
    monkeypatch.setattr(socket.socket, "connect", must_not_connect)
    monkeypatch.setattr(socket, "getaddrinfo", must_not_connect)
    yield
    assert attempts == [], f"a connection or a name lookup was attempted: {attempts!r}"


def endpoint_manifest(directory: Path, url: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": {"endpoint": url, "version_declared": "3.1"},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, directory)],
                    }
                ],
            }
        )
    )
    return path


def engagement_file(directory: Path, host: str) -> Path:
    """A file that lists ``host`` as a target, so nothing but the plain-HTTP rule refuses."""
    directory.mkdir(parents=True)
    now = datetime.now(timezone.utc)
    path = directory / "engagement.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "id": "acme-2026-10",
                "window": {
                    "from": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "until": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                "targets": [{"host": host, "paths": ["/mcp"]}],
                "scenarios": [
                    {"path": os.path.relpath(ALL_SIGNALS, directory),
                     "sha256": sha256(ALL_SIGNALS.read_bytes()).hexdigest()}
                ],
                "actions": {"list": True, "call": False},
            }
        )
    )  # fmt: skip
    return path


@pytest.mark.parametrize(
    "url",
    [
        "http://mcp.example.test:80/mcp",
        "http://localhost:8080/mcp",
        "http://127.0.0.2:8080/mcp",
        "http://10.0.0.7:8080/mcp",
        "HTTP://MCP.Example.Test:80/mcp",
    ],
)
def test_plain_http_to_anything_but_a_loopback_literal_is_refused_before_connecting(
    tmp_path, nothing_connects, capsys, url
):
    code = cli.main(["drive", "--http", url, "--out-dir", str(tmp_path / "runs")])

    assert code == 2
    said = capsys.readouterr().err
    assert "plain HTTP" in said and RULE in said
    assert "https://" in said, "the message names the fix"
    assert not (tmp_path / "runs").exists()


def test_no_flag_opens_it_the_confirmation_included(tmp_path, nothing_connects, capsys):
    code = cli.main(
        ["drive", "--http", "http://mcp.example.test:80/mcp", "--scenario", str(ALL_SIGNALS),
         "--engagement-confirmed", "--out-dir", str(tmp_path / "runs")]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert RULE in said
    assert "--engagement-confirmed" not in said, "the rule refuses, not the gate"
    assert not (tmp_path / "runs").exists()


def test_an_endpoint_entry_is_refused_as_drive_http_is_and_corpus_check_still_reads_it(
    tmp_path, nothing_connects, capsys
):
    manifest = endpoint_manifest(tmp_path / "manifest", "http://mcp.example.test:80/mcp")

    assert cli.main(["corpus", "check", str(manifest)]) == 0
    capsys.readouterr()
    code = cli.main(
        ["drive", "--manifest", str(manifest), "--entry", "customer-mcp", "--engagement-confirmed",
         "--out-dir", str(tmp_path / "runs")]
    )  # fmt: skip

    assert code == 2
    assert RULE in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_under_an_engagement_file_the_refusal_is_written_with_its_own_reason(
    tmp_path, nothing_connects, capsys
):
    held = engagement_file(tmp_path / "engagement", "mcp.example.test")
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--engagement-confirmed", "--http",
         "http://mcp.example.test:80/mcp", "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    assert RULE in capsys.readouterr().err
    (record,) = engagement.read_refusals(out_dir / engagement.REFUSALS_FILE)
    assert record.reason == "plain_http"
    assert RULE in record.message
    assert record.exit_code == 2
    assert [p.name for p in out_dir.iterdir()] == [engagement.REFUSALS_FILE]


def test_the_words_name_the_host_and_port_and_never_the_url_s_path_or_query(
    tmp_path, nothing_connects, capsys
):
    """A URL with a user or a password is refused earlier, by the URL's reader; a query can
    carry a credential as well, and the words leave it out (the command line in
    ``refusals.jsonl`` is masked as every command line there is)."""
    held = engagement_file(tmp_path / "engagement", "mcp.example.test")
    out_dir = tmp_path / "runs"
    url = "http://mcp.example.test:81/mcp/private?token=s3cr3t"

    assert cli.main(["drive", "--engagement", str(held), "--http", url, "--out-dir",
                     str(out_dir)]) == 2  # fmt: skip

    said = capsys.readouterr().err
    (record,) = engagement.read_refusals(out_dir / engagement.REFUSALS_FILE)
    assert record.reason == "plain_http"
    assert "plain HTTP to mcp.example.test:81, " in said
    for text in (said, record.message):
        assert "s3cr3t" not in text and "/private" not in text
    assert "s3cr3t" not in (out_dir / engagement.REFUSALS_FILE).read_text()


def test_a_loopback_literal_is_not_refused(tmp_path):
    server = http_server.serve(0, variant="reference")
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
        assert cli.main(["drive", "-q", "--http", url, "--out-dir", str(tmp_path / "runs")]) == 0
    finally:
        server.shutdown()
        server.server_close()
    (recording,) = (tmp_path / "runs").glob("*/events.jsonl")
    started = json.loads(recording.read_text().splitlines()[0])
    assert started["endpoint"]["host"] == "127.0.0.1"
