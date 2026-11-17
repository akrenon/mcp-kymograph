"""``drive --http`` over TLS (http-transport.md 8.1–8.3, 8.6).

The loopback test server speaks TLS with the test-only certificates in ``fixtures/tls``; a test
trusts their CA through ``SSL_CERT_FILE``, which OpenSSL reads when the run's context is made. No
test connects beyond loopback. What is checked is the recording: the verdict's ``tls`` cause is
not this module's.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

from mcp_kymograph import cli
from mcp_kymograph.events import TLS
from mcp_kymograph.http_client import MAX_FAILURE_DETAIL, HttpClientChannel, _detail, _parse_url

FIXTURES = Path(__file__).parent / "fixtures"
CERTS = FIXTURES / "tls"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"
CA = CERTS / "ca.pem"
TRUSTED = (str(CERTS / "localhost.pem"), str(CERTS / "localhost.key"))
OTHER_NAME = (str(CERTS / "other.pem"), str(CERTS / "other.key"))
FOREIGN = (str(CERTS / "foreign.pem"), str(CERTS / "foreign.key"))
SECOND_ADDRESS = (str(CERTS / "ip-127-0-0-2.pem"), str(CERTS / "ip-127-0-0-2.key"))
#: A directory name no recording has any reason to hold: where the trusted CA is put.
TRUST_DIRECTORY = "trust-store-Kq8Zr3Vw"


def fingerprint(certificate: str) -> str:
    """The SHA-256 of a certificate's DER, as the proxy computes it from the handshake."""
    der = ssl.PEM_cert_to_DER_cert(Path(certificate).read_text())
    return hashlib.sha256(der).hexdigest()


@pytest.fixture
def trust_ca(tmp_path, monkeypatch):
    """The test CA as the machine's trust store, at a path of its own; returns the path."""
    directory = tmp_path / TRUST_DIRECTORY
    directory.mkdir()
    path = directory / "ca.pem"
    path.write_bytes(CA.read_bytes())
    monkeypatch.setenv("SSL_CERT_FILE", str(path))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    return path


@pytest.fixture
def serve():
    servers = []

    def started(host="127.0.0.1", **options):
        server = http_server.serve(0, host, **options)
        servers.append(server)
        return server.server_address[1]

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


def drive_http(tmp_path, url, *extra, name="runs"):
    out = tmp_path / name
    code = cli.main(["drive", "-q", "--http", url, "--out-dir", str(out), *extra])
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


def of(events, kind):
    return [e for e in events if e["type"] == kind]


# -- the certificates ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pair", "host", "name"),
    [
        (TRUSTED, "127.0.0.1", "127.0.0.1"),
        (TRUSTED, "127.0.0.1", "localhost"),
        (SECOND_ADDRESS, "127.0.0.2", "127.0.0.2"),
    ],
)
def test_the_test_certificates_verify_under_the_default_context(trust_ca, serve, pair, host, name):
    """As a run's context makes them: the default context, the CA from ``SSL_CERT_FILE``, and
    from Python 3.13 on the strict X.509 checks it sets by default."""
    port = serve(host, tls=pair)
    context = ssl.create_default_context()
    if sys.version_info >= (3, 13):
        assert context.verify_flags & ssl.VERIFY_X509_STRICT
    with (
        socket.create_connection((host, port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname=name) as wrapped,
    ):
        assert wrapped.version() is not None
        der = wrapped.getpeercert(binary_form=True)
    assert hashlib.sha256(der).hexdigest() == fingerprint(pair[0])


def test_no_private_key_of_a_ca_is_committed():
    assert sorted(path.name for path in CERTS.glob("*ca.*")) == ["ca.pem", "foreign-ca.pem"]
    for path in CERTS.glob("*.pem"):
        assert "PRIVATE KEY" not in path.read_text(), path.name


# -- the URL --------------------------------------------------------------------------------


def test_the_url_reader_takes_http_and_https_and_names_the_scheme():
    assert _parse_url("https://127.0.0.1:8443/mcp?a=1") == ("https", "127.0.0.1", 8443, "/mcp?a=1")
    assert _parse_url("HTTPS://localhost:8443/mcp") == ("https", "localhost", 8443, "/mcp")
    assert _parse_url("http://127.0.0.1:8080/mcp") == ("http", "127.0.0.1", 8080, "/mcp")
    with pytest.raises(ValueError, match="needs a host, a port and a path"):
        _parse_url("https://127.0.0.1/mcp")


@pytest.mark.parametrize("url", ["ftp://127.0.0.1:21/mcp", "ws://127.0.0.1:80/mcp"])
def test_a_url_of_another_scheme_is_refused_with_the_rule(tmp_path, capsys, url):
    out = tmp_path / "runs"
    assert cli.main(["drive", "--http", url, "--out-dir", str(out)]) == cli.EXIT_REFUSED
    assert "only http:// and https:// URLs are spoken" in capsys.readouterr().err
    assert not out.exists()


def test_corpus_check_takes_an_https_endpoint_entry(tmp_path, capsys):
    url = "https://mcp.example.test:443/mcp"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": {"endpoint": url, "version_declared": "3.1"},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, tmp_path)],
                    }
                ],
            }
        )
    )
    assert cli.main(["corpus", "check", "-q", str(manifest)]) == 0
    (entry,) = json.loads(capsys.readouterr().out)["entries"]
    assert entry["endpoint"] == url


# -- a run that verifies ----------------------------------------------------------------------


def test_an_https_run_records_each_connections_certificate_and_the_runs_set(
    tmp_path, trust_ca, serve
):
    port = serve(tls=TRUSTED)
    code, path, events = drive_http(tmp_path, f"https://127.0.0.1:{port}/mcp")
    assert code == 0
    digest = fingerprint(TRUSTED[0])
    (started,) = of(events, "run_started")
    assert started["endpoint"]["scheme"] == "https"
    assert started["trust_store_env"] == {"SSL_CERT_FILE": True, "SSL_CERT_DIR": False}
    requests = of(events, "http_request")
    assert len(requests) >= 3  # initialize, the notification, a listing, the DELETE
    versions = {request["tls"]["version"] for request in requests}
    assert {request["tls"]["certificate_sha256"] for request in requests} == {digest}
    assert len(versions) == 1 and next(iter(versions)).startswith("TLSv1.")
    assert events[-1]["http"]["tls"] == {"versions": sorted(versions), "certificates": [digest]}
    assert of(events, "server_failed") == [] and of(events, "step_unanswered") == []
    raw = path.read_bytes()
    assert TRUST_DIRECTORY.encode() not in raw
    assert str(trust_ca).encode() not in raw


def test_https_to_localhost_is_spoken_as_well(tmp_path, trust_ca, serve):
    """``localhost`` is refused over plain HTTP only; the leaf names it, so TLS verifies."""
    port = serve(tls=TRUSTED)
    code, _, events = drive_http(tmp_path, f"https://localhost:{port}/mcp")
    assert code == 0
    assert of(events, "run_started")[0]["endpoint"]["host"] == "localhost"
    assert events[-1]["http"]["tls"]["certificates"] == [fingerprint(TRUSTED[0])]


@pytest.mark.parametrize(
    ("cert_file", "cert_dir"), [(False, False), (True, True)], ids=["neither", "both"]
)
def test_an_https_recording_always_says_which_trust_store_variables_were_set(
    tmp_path, monkeypatch, serve, cert_file, cert_dir
):
    """An object for every https run, whether its handshake verified or not; never a value."""
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    store = tmp_path / TRUST_DIRECTORY
    store.mkdir()
    if cert_file:
        (store / "ca.pem").write_bytes(CA.read_bytes())
        monkeypatch.setenv("SSL_CERT_FILE", str(store / "ca.pem"))
    if cert_dir:
        monkeypatch.setenv("SSL_CERT_DIR", str(store))
    port = serve(tls=TRUSTED)
    _, path, events = drive_http(tmp_path, f"https://127.0.0.1:{port}/mcp")
    assert of(events, "run_started")[0]["trust_store_env"] == {
        "SSL_CERT_FILE": cert_file,
        "SSL_CERT_DIR": cert_dir,
    }
    assert TRUST_DIRECTORY.encode() not in path.read_bytes()


def test_a_plain_http_run_records_no_tls_anywhere(tmp_path, trust_ca, serve):
    port = serve()
    code, _, events = drive_http(tmp_path, f"http://127.0.0.1:{port}/mcp")
    assert code == 0
    assert of(events, "run_started")[0]["trust_store_env"] is None
    requests = of(events, "http_request")
    assert requests and all(request["tls"] is None for request in requests)
    assert events[-1]["http"]["tls"] is None


# -- a handshake that fails -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pair", "said"),
    [(OTHER_NAME, "mismatch"), (FOREIGN, "unable to get local issuer certificate")],
    ids=["another-name", "unknown-ca"],
)
def test_a_first_handshake_that_fails_is_server_failed_tls_with_the_librarys_text(
    tmp_path, trust_ca, serve, pair, said
):
    port = serve(tls=pair)
    _, _, events = drive_http(tmp_path, f"https://127.0.0.1:{port}/mcp")
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == TLS
    assert "certificate verify failed" in failed["detail"]
    assert said in failed["detail"]
    assert len(failed["detail"]) <= MAX_FAILURE_DETAIL
    assert of(events, "http_request") == []  # nothing reached the server
    assert events[-1]["http"]["tls"] == {"versions": [], "certificates": []}
    assert {skip["reason"] for skip in of(events, "step_skipped")} == {TLS}
    assert of(events, "script_finished")[0]["inventory"] == "none"


def test_a_certificate_that_stops_verifying_later_is_step_unanswered_tls(tmp_path, trust_ca, serve):
    """The first two connections (the probe and ``initialize``) verify; from the third on the
    server presents a certificate of an unknown CA. The listing that follows is unanswered, with
    the text."""
    port = serve(tls=TRUSTED, switch_tls=FOREIGN, switch_after=2)
    _, _, events = drive_http(tmp_path, f"https://127.0.0.1:{port}/mcp")
    assert of(events, "server_failed") == []
    unanswered = of(events, "step_unanswered")
    assert unanswered and unanswered[0]["reason"] == TLS
    assert "certificate verify failed" in unanswered[0]["detail"]
    verified = of(events, "http_request")
    assert len(verified) == 2  # the probe and initialize: the connections that verified
    assert {r["tls"]["certificate_sha256"] for r in verified} == {fingerprint(TRUSTED[0])}
    assert events[-1]["http"]["tls"]["certificates"] == [fingerprint(TRUSTED[0])]
    assert of(events, "script_finished")[0]["inventory"] == "partial"


@contextlib.contextmanager
def listener(behaviour: str):
    """A loopback listener whose every connection is accepted and then, once the client's first
    bytes (its ClientHello) are read, ``hold`` (nothing is ever said), ``reset`` (closed with a
    reset) or ``close`` (closed). Yields its ``https://`` URL."""
    server = socket.create_server(("127.0.0.1", 0))
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        server.settimeout(0.1)
        while not stop.is_set():
            try:
                connection = server.accept()[0]
            except OSError:
                continue
            held.append(connection)
            if behaviour == "hold":
                continue
            with contextlib.suppress(OSError):
                connection.settimeout(5)
                connection.recv(4096)
                if behaviour == "reset":
                    linger = (1).to_bytes(4, sys.byteorder) + (0).to_bytes(4, sys.byteorder)
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                connection.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.getsockname()[1]}/mcp"
    finally:
        stop.set()
        thread.join()
        for connection in held:
            connection.close()
        server.close()


def timed_run(tmp_path, url):
    began = time.monotonic()
    _, _, events = drive_http(tmp_path, url, "--step-timeout", "2")
    return time.monotonic() - began, events


def test_a_handshake_that_never_ends_is_tls_within_the_time_connecting_has(tmp_path, trust_ca):
    """A peer that accepts and says nothing: the connection was made, so it is not unreachable;
    the handshake had what was left of the step's time, and the detail says how much."""
    with listener("hold") as url:
        took, events = timed_run(tmp_path, url)
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == TLS
    assert failed["detail"].startswith("the TLS handshake did not finish within ")
    assert failed["detail"].endswith(" s")
    assert took < 10
    assert events[-1]["http"]["tls"] == {"versions": [], "certificates": []}


@pytest.mark.parametrize("behaviour", ["reset", "close"])
def test_a_handshake_the_peer_breaks_off_is_tls_with_what_was_said(tmp_path, trust_ca, behaviour):
    """Reset or closed after the ClientHello: TLS was begun and did not complete."""
    with listener(behaviour) as url:
        took, events = timed_run(tmp_path, url)
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == TLS
    assert failed["detail"].startswith("the connection ended during the TLS handshake")
    assert took < 10


def test_a_refused_connection_stays_unreachable(tmp_path, trust_ca):
    """No TCP connection, no handshake: an https endpoint that is not there is unreachable."""
    with socket.create_server(("127.0.0.1", 0)) as closed:
        port = closed.getsockname()[1]
    _, events = timed_run(tmp_path, f"https://127.0.0.1:{port}/mcp")
    (failed,) = of(events, "server_failed")
    assert (failed["reason"], failed["detail"]) == (
        "http_unreachable",
        "the HTTP endpoint could not be reached, or closed the connection before it answered",
    )


# -- the channel on its own -------------------------------------------------------------------


def test_the_detail_is_filtered_for_a_terminal_and_cut():
    said = "certificate verify failed: \x1b[31mred\x1b[0m ‮name​" + "x" * 400
    detail = _detail(said)
    assert "\x1b" not in detail and "‮" not in detail and "​" not in detail
    assert detail.startswith("certificate verify failed: [31mred[0m name")
    assert len(detail) == MAX_FAILURE_DETAIL


def test_the_channel_alone_speaks_tls_and_names_a_failure(trust_ca, serve):
    """Without a proxy in front the channel makes the connection itself, as the proxy would."""
    good, bad = serve(tls=TRUSTED), serve(tls=OTHER_NAME)
    hello = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'

    async def first_line(port: int) -> tuple[bytes | None, str | None, str]:
        channel = HttpClientChannel(f"https://127.0.0.1:{port}/mcp")
        try:
            await channel.send(hello)
            line = await channel.read_line(5)
            return line, channel.failure, channel.failure_detail
        finally:
            channel.close()

    line, failure, detail = asyncio.run(first_line(good))
    assert failure is None and detail == ""
    assert json.loads(line)["result"]["serverInfo"]["name"] == "reference-server"
    line, failure, detail = asyncio.run(first_line(bad))
    assert (line, failure) == (None, TLS)
    assert "certificate verify failed" in detail


def test_no_variable_but_openssls_own_is_read(monkeypatch, tmp_path, trust_ca, serve):
    """``HTTPS_PROXY`` and its kin change nothing: the run reaches the endpoint it names."""
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9/")
    port = serve(tls=TRUSTED)
    code, _, events = drive_http(tmp_path, f"https://127.0.0.1:{port}/mcp")
    assert code == 0
    assert events[-1]["http"]["tls"]["certificates"] == [fingerprint(TRUSTED[0])]
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:9/"


def test_a_later_tls_failure_gives_the_driver_its_detail_and_not_the_summary(trust_ca, serve):
    """``DriveOutcome.unanswered`` carries the channel's text for the terminal; the recording's
    ``script_finished`` keeps its three elements, the detail being in ``step_unanswered``."""
    from mcp_kymograph.driver import DISCOVERY, Driver

    port = serve(tls=TRUSTED, switch_tls=FOREIGN, switch_after=1)
    finished: list[dict] = []

    async def ignore(**fields):
        return None

    async def record_finished(**fields):
        finished.append(fields)

    async def drive():
        channel = HttpClientChannel(f"https://127.0.0.1:{port}/mcp")
        driver = Driver(
            DISCOVERY,
            channel,
            record_skipped=ignore,
            record_failed=ignore,
            record_unanswered=ignore,
            record_finished=record_finished,
            step_timeout=5,
        )
        return await driver.run()

    outcome = asyncio.run(drive())
    step, pages, reason, detail = outcome.unanswered[0]
    assert (step, pages, reason) == ("tools/list", 0, TLS)
    assert "certificate verify failed" in detail and len(detail) <= MAX_FAILURE_DETAIL
    assert outcome.server_failed is None and outcome.server_failed_detail == ""
    (summary,) = finished
    assert summary["unanswered"] == ((step, pages, reason),)
