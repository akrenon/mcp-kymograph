"""The ``web`` subcommand as a process: every refusal before serving, the start, and Ctrl-C.

Each refusal is exit 2 with its words on stderr and nothing on stdout, before anything listens.
A start prints the start address on stderr, answers once the token is exchanged, says nothing
else while serving, and ends with 130 on SIGINT, as every command of ours that Ctrl-C ends
with nothing of its own to record.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli
from mcp_kymograph.store import Store

START = re.compile(r"http://127\.0\.0\.1:(\d+)/\?token=([A-Za-z0-9_-]+)")
posix_only = pytest.mark.skipif(os.name != "posix", reason="SIGINT into a process needs POSIX")


def command(*arguments: str) -> list[str]:
    return [sys.executable, "-m", "mcp_kymograph.cli", "web", *arguments]


def refused(tmp_path: Path, *arguments: str) -> str:
    """Run ``web`` with these arguments; it must refuse at once. Returns its stderr."""
    process = subprocess.Popen(  # noqa: S603
        command(*arguments), cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        out, err = process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        pytest.fail(f"web {arguments} served instead of refusing")
    said = err.decode()
    assert process.returncode == cli.EXIT_REFUSED, said
    assert out == b"", "nothing on stdout"
    assert "Traceback" not in said, said
    return said


# -- refused at argument time ------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # noqa: S104 - refused, which is the point
        "::",
        "::1",
        "localhost",
        "192.168.1.10",
        "10.0.0.1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "example.org",
        "127.0.0.1:8765",
        "[::1]",
        "",
        "127.0.0.2",
        "127.255.255.254",
        "0:0::1",
    ],
)
def test_a_bind_that_is_not_127_0_0_1_is_refused_at_argument_time(tmp_path, address):
    said = refused(tmp_path, "--bind", address)
    assert "argument --bind: must be 127.0.0.1, not " in said
    assert repr(address) in said


@pytest.mark.parametrize("port", ["-1", "65536", "x", "80.5"])
def test_a_port_that_is_not_one_is_refused_at_argument_time(tmp_path, port):
    assert "argument --port:" in refused(tmp_path, "--port", port)


# -- refused at start --------------------------------------------------------------------


def test_a_missing_store_is_refused_and_not_created(tmp_path):
    store = tmp_path / "missing.sqlite"
    said = refused(tmp_path, "--store", str(store), "--port", "0")
    assert "no store there" in said
    assert not store.exists(), "opened for reading: nothing is created"


def test_a_store_of_another_schema_is_refused_and_left_as_it_was(tmp_path):
    store = tmp_path / "old.sqlite"
    with sqlite3.connect(store) as connection:
        connection.execute("CREATE TABLE meta (name TEXT, value TEXT)")
        connection.execute("INSERT INTO meta VALUES ('schema', '1')")
    connection.close()
    before = store.read_bytes()
    said = refused(tmp_path, "--store", str(store), "--port", "0")
    assert "store schema 1" in said
    assert store.read_bytes() == before


@pytest.mark.parametrize(
    "content", [b"not a database at all, just bytes" * 40, b""], ids=["garbage", "empty"]
)
def test_a_store_that_is_no_store_is_refused(tmp_path, content):
    store = tmp_path / "store.sqlite"
    store.write_bytes(content)
    refused(tmp_path, "--store", str(store), "--port", "0")
    assert store.read_bytes() == content


def test_a_store_that_is_a_directory_is_refused(tmp_path):
    assert "no store there" in refused(tmp_path, "--store", str(tmp_path), "--port", "0")


def test_runs_that_is_not_a_directory_is_refused(tmp_path):
    a_file = tmp_path / "file"
    a_file.write_text("x")
    for runs in (a_file, tmp_path / "missing"):
        said = refused(tmp_path, "--runs", str(runs), "--port", "0")
        assert f"--runs {runs}: not a directory" in said


@pytest.mark.parametrize("option", ["--manifest", "--scenario", "--attestation"])
def test_a_manifest_or_scenario_that_is_not_a_file_is_refused(tmp_path, option):
    for path in (tmp_path / "missing.yaml", tmp_path):
        said = refused(tmp_path, option, str(path), "--port", "0")
        assert f"{option} {path}: not a file" in said


def test_a_bundle_that_is_not_a_directory_is_refused(tmp_path):
    a_file = tmp_path / "file"
    a_file.write_text("x")
    for bundle in (a_file, tmp_path / "missing"):
        said = refused(tmp_path, "--bundle", str(bundle), "--port", "0")
        assert f"--bundle {bundle}: not a directory" in said


def test_a_port_in_use_is_refused(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = taken.getsockname()[1]
        said = refused(tmp_path, "--port", str(port))
    assert f"cannot listen on 127.0.0.1 port {port}:" in said


# -- the start, the answers, Ctrl-C ------------------------------------------------------


class Running:
    def __init__(self, tmp_path: Path, *arguments: str) -> None:
        self.process = subprocess.Popen(  # noqa: S603
            command(*arguments), cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.first = self.process.stderr.readline().decode()
        found = START.search(self.first)
        if found is None:
            self.stop()
            pytest.fail(f"no start address on stderr: {self.first!r}")
        self.port, self.token = int(found.group(1)), found.group(2)
        self.url = found.group(0)
        self.cookie = f"kymograph-{self.port}"

    def exchange(self) -> str:
        """The token in the start address, for the cookie it sets: ``name=session``."""
        status, headers, _ = self.get(f"/?token={self.token}", cookie=None)
        assert status == 303
        return headers["Set-Cookie"].split(";")[0]

    def get(self, target: str, *, host: str | None = None, cookie: str | None = ""):
        """``cookie``: ``""`` for the session (exchanged first), ``None`` for none."""
        if cookie == "":
            cookie = self.exchange()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.putrequest("GET", target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host or f"127.0.0.1:{self.port}")
            if cookie is not None:
                connection.putheader("Cookie", cookie)
            connection.endheaders()
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def interrupt(self) -> tuple[int, str, bytes]:
        self.process.send_signal(signal.SIGINT)
        out, rest = self.process.communicate(timeout=60)
        return self.process.returncode, rest.decode(), out

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate(timeout=60)


@pytest.fixture
def running(request, tmp_path):
    started: list[Running] = []

    def start(*arguments: str) -> Running:
        started.append(Running(tmp_path, *arguments))
        return started[-1]

    yield start
    for process in started:
        process.stop()


@posix_only
def test_a_start_prints_the_address_answers_on_it_and_ends_with_130_on_ctrl_c(tmp_path, running):
    (tmp_path / "runs").mkdir()
    store = tmp_path / "store.sqlite"
    Store.open(store).close()
    before = store.read_bytes()
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("this: [is not a manifest the loader takes")  # not a start error
    server = running(
        "--store", str(store), "--runs", "runs", "--manifest", str(manifest), "--port", "0"
    )
    assert server.first.startswith("kymograph: serving --store ")
    assert "--runs runs, 1 manifest(s) read-only on http://127.0.0.1:" in server.first
    assert server.first.rstrip("\n").endswith(
        f"/?token={server.token} — a local viewer for this machine's user, no TLS"
    ), server.first
    assert server.port != 0

    assert server.get("/api/runs", cookie=None)[0] == 403, "no cookie, no answer"

    status, headers, body = server.get("/static/no-such-file.css")
    assert status == 404
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Security-Policy"].startswith("default-src 'none';")
    assert json.loads(body)["view"] == "error"
    status, _, body = server.get("/api/runs?unknown=1")
    assert status == 400
    assert json.loads(body)["notices"][0]["kind"] == "bad_request"
    assert server.get("/api/runs", host="evil.example")[0] == 421

    code, rest, out = server.interrupt()
    assert code == cli.EXIT_INTERRUPTED, rest
    assert rest == "kymograph: interrupted\n", "nothing else while serving"
    assert server.token not in rest
    assert out == b""
    assert store.read_bytes() == before


@posix_only
def test_quiet_prints_the_start_address_alone(tmp_path, running):
    server = running("--port", "0", "-q")
    assert server.first == server.url + "\n"
    assert server.interrupt()[0] == cli.EXIT_INTERRUPTED


@posix_only
def test_a_start_without_sources_says_that_each_view_names_its_option(tmp_path, running):
    server = running("--port", "0", "--bind", "127.0.0.1")
    assert "serving no source (each view says which option to give)" in server.first
    assert server.url.startswith(f"http://127.0.0.1:{server.port}/?token=")
    assert server.get("/nothing")[0] == 404
    assert server.interrupt()[0] == cli.EXIT_INTERRUPTED


@posix_only
def test_a_start_with_only_a_bundle_names_it(tmp_path, running):
    (tmp_path / "bundle").mkdir()
    server = running("--bundle", "bundle", "--port", "0")
    assert "serving 1 bundle(s) read-only on http://127.0.0.1:" in server.first
    assert "no source" not in server.first
    assert server.first.rstrip("\n").endswith(
        f"/?token={server.token} — a local viewer for this machine's user, no TLS"
    ), server.first
    assert server.interrupt()[0] == cli.EXIT_INTERRUPTED


@posix_only
def test_a_start_with_only_an_attestation_names_it(tmp_path, running):
    (tmp_path / "attestation.json").write_text("{}")
    server = running("--attestation", "attestation.json", "--port", "0")
    assert "serving 1 attestation(s) read-only on http://127.0.0.1:" in server.first
    assert "no source" not in server.first
    assert server.first.rstrip("\n").endswith(
        f"/?token={server.token} — a local viewer for this machine's user, no TLS"
    ), server.first
    assert server.interrupt()[0] == cli.EXIT_INTERRUPTED


@posix_only
def test_a_start_with_every_source_names_them_in_the_order_of_the_argument_list(tmp_path, running):
    (tmp_path / "runs").mkdir()
    (tmp_path / "bundle").mkdir()
    (tmp_path / "bundle2").mkdir()
    Store.open(tmp_path / "store.sqlite").close()
    for name in ("manifest.yaml", "scenario.yaml", "attestation.json"):
        (tmp_path / name).write_text("x")
    arguments = [
        ("--attestation", "attestation.json"),
        ("--bundle", "bundle"),
        ("--bundle", "bundle2"),
        ("--scenario", "scenario.yaml"),
        ("--manifest", "manifest.yaml"),
        ("--runs", "runs"),
        ("--store", "store.sqlite"),
        ("--port", "0"),
    ]
    server = running(*(word for pair in arguments for word in pair))
    assert server.first.startswith("kymograph: serving --store ")
    assert (
        "--runs runs, 1 manifest(s), 1 scenario file(s), 2 bundle(s), 1 attestation(s)"
        " read-only on http://127.0.0.1:"
    ) in server.first, server.first
    assert server.first.rstrip("\n").endswith(
        f"/?token={server.token} — a local viewer for this machine's user, no TLS"
    ), server.first
    assert server.interrupt()[0] == cli.EXIT_INTERRUPTED


def test_the_web_subcommand_is_in_the_help():
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "web", "--help"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0
    for option in ("--store", "--runs", "--manifest", "--scenario", "--bind", "--port", "-q"):
        assert option in done.stdout.decode()
