"""The recording's TLS contract (http-transport.md 8.2, 8.3): what the recorder takes and writes.

No network and no TLS: the recorder is given what the channel and the proxy would hand it, and
the file it writes is read back. Every field is additive — recording schema 5 — and reads null
or "" where nothing is said, so a recording without it reads the same.
"""

from __future__ import annotations

import errno
import json

import pytest

from mcp_kymograph import events
from mcp_kymograph.masking import PLACEHOLDER, Masker
from mcp_kymograph.proxy import _NOT_STARTED, _not_started
from mcp_kymograph.recorder import Recorder

# Distinctive values, not real credentials: a search over the raw recording must find none. The
# secret is put together when the test runs, so that no scanner finds it written out here.
SECRET = "".join(("geheim-", "Zx9Q", "w7Lm2", "Vb8K", "d4Rt6"))
DIGEST = "0123456789abcdef" * 4
TLS = {"version": "TLSv1.3", "certificate_sha256": DIGEST}
HTTPS = "https://server:8443/mcp"
#: What OpenSSL says through ``ssl``, as the channel would hand it on: kept as it is.
VERIFY_FAILED = (
    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate "
    "is not valid for 'other.test'. (_ssl.c:1032)"
)


@pytest.fixture
def path(tmp_path):
    return tmp_path / "events.jsonl"


@pytest.fixture
def recorder(path):
    with Recorder.open(path, run_id="tlsrun", masker=Masker()) as recorder:
        yield recorder


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def request(recorder, seq=1, **kwargs):
    recorder.http_request(
        seq, seq, exchange=seq, connection=seq, method="POST", target="/mcp", headers=[], **kwargs
    )


def test_tls_is_a_partial_reason_and_the_schema_stays_5():
    assert events.TLS == "tls"
    assert events.TLS in events.PARTIAL_REASONS
    assert events.SCHEMA_VERSION == 5


# -- http_request.tls ----------------------------------------------------------------------


def test_an_exchange_names_its_tls_and_null_over_plain_http(path, recorder):
    request(recorder, 1, tls=TLS)
    request(recorder, 2)
    first, second = read_events(path)
    assert first["tls"] == {"version": "TLSv1.3", "certificate_sha256": DIGEST}
    assert second["tls"] is None


@pytest.mark.parametrize(
    "tls",
    [
        {},
        {"version": "TLSv1.3"},
        {**TLS, "subject": "CN=server"},
        {"version": None, "certificate_sha256": DIGEST},
        {"version": "", "certificate_sha256": DIGEST},
        {"version": "TLSv1.3" * 10, "certificate_sha256": DIGEST},
        {"version": "TLS v1.3", "certificate_sha256": DIGEST},
        {"version": "TLSv1.3", "certificate_sha256": DIGEST.upper()},
        {"version": "TLSv1.3", "certificate_sha256": DIGEST[:-1]},
        {"version": "TLSv1.3", "certificate_sha256": bytes.fromhex(DIGEST)},
        [("version", "TLSv1.3"), ("certificate_sha256", DIGEST)],
    ],
)
def test_a_tls_of_any_other_shape_is_refused_and_nothing_is_written(path, recorder, tls):
    """Ours: a version ``ssl`` names and a digest we computed. Another shape is our bug."""
    with pytest.raises(ValueError):
        request(recorder, tls=tls)
    assert path.read_text() == ""


# -- step_unanswered.detail and server_failed.detail ----------------------------------------


def test_a_detail_is_empty_unless_given_and_the_librarys_text_is_kept(path, recorder):
    recorder.step_unanswered(1, 1, step="tools/list", pages=0, reason=events.NO_ANSWER)
    recorder.step_unanswered(
        2, 2, step="tools/list", pages=1, reason=events.TLS, detail=VERIFY_FAILED
    )
    recorder.server_failed(3, 3, reason=events.TLS, detail=VERIFY_FAILED)
    plain, tls, failed = read_events(path)
    assert {key: plain[key] for key in ("step", "pages", "reason", "detail")} == {
        "step": "tools/list", "pages": 0, "reason": "no_answer", "detail": "",
    }  # fmt: skip
    assert (tls["reason"], tls["pages"], tls["detail"]) == ("tls", 1, VERIFY_FAILED)
    assert (failed["reason"], failed["detail"]) == ("tls", VERIFY_FAILED)


@pytest.mark.parametrize(
    "said",
    [f"certificate is not valid for 'Bearer {SECRET}'", f"subject CN=api password={SECRET}"],
)
def test_a_secret_in_a_detail_is_masked_in_both_events(path, recorder, said):
    """The library's text can carry what the certificate says; the recorder masks it."""
    recorder.step_unanswered(1, 1, step="tools/list", pages=0, reason=events.TLS, detail=said)
    recorder.server_failed(2, 2, reason=events.TLS, detail=said)
    assert SECRET not in path.read_text()
    for event in read_events(path):
        assert PLACEHOLDER in event["detail"]
        assert event["detail"].startswith(said.split(SECRET)[0])


@pytest.mark.parametrize(
    "number", [*_NOT_STARTED, errno.EIO, None], ids=lambda n: str(n and errno.errorcode[n])
)
def test_masking_leaves_the_proxys_own_details_as_they_are(path, recorder, number):
    """``not_started``'s details are our words; the masker finds nothing in them. The driver's
    sentences are pinned whole by test_driver.py."""
    detail = _not_started(OSError(number, "x") if number else RuntimeError("x"))
    recorder.server_failed(1, 1, reason=events.NOT_STARTED, detail=detail)
    assert read_events(path)[0]["detail"] == detail


# -- run_started.trust_store_env -------------------------------------------------------------


def started(recorder, seq, **kwargs):
    recorder.run_started(seq, seq, argv=[], limits={}, **kwargs)


def test_trust_store_env_is_written_as_given_and_null_without_it(path, recorder):
    env = {"SSL_CERT_FILE": True, "SSL_CERT_DIR": False}
    started(recorder, 1, transport=events.TRANSPORT_HTTP, endpoint=HTTPS, trust_store_env=env)
    started(recorder, 2, transport=events.TRANSPORT_HTTP, endpoint=HTTPS)
    started(recorder, 3)
    lines = read_events(path)
    assert [line["trust_store_env"] for line in lines] == [env, None, None]
    assert lines[0]["endpoint"]["scheme"] == "https"
    assert list(lines[0]).index("trust_store_env") == list(lines[0]).index("endpoint") + 1


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"SSL_CERT_FILE": True},
        {"SSL_CERT_FILE": True, "SSL_CERT_DIR": False, "SSL_CERT_PATH": False},
        {"SSL_CERT_FILE": "/etc/ssl/test-ca.pem", "SSL_CERT_DIR": False},
        {"SSL_CERT_FILE": 1, "SSL_CERT_DIR": 0},
        [("SSL_CERT_FILE", True), ("SSL_CERT_DIR", False)],
    ],
)
def test_a_trust_store_env_of_any_other_shape_is_refused(path, recorder, env):
    """Two booleans and nothing else: a value would be a path on this machine."""
    with pytest.raises(ValueError):
        started(recorder, 1, transport=events.TRANSPORT_HTTP, endpoint=HTTPS, trust_store_env=env)
    assert path.read_text() == ""


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"transport": events.TRANSPORT_HTTP, "endpoint": "http://127.0.0.1:8080/mcp"}],
    ids=["stdio", "plain-http"],
)
def test_trust_store_env_belongs_to_an_https_run_only(path, recorder, kwargs):
    env = {"SSL_CERT_FILE": False, "SSL_CERT_DIR": False}
    with pytest.raises(ValueError):
        started(recorder, 1, trust_store_env=env, **kwargs)
    assert path.read_text() == ""


# -- run_finished.http.tls -------------------------------------------------------------------


def test_run_finished_writes_the_runs_tls_set_through(path, recorder):
    """The recorder keeps every key of ``http``; the set beside the counts is the proxy's."""
    http = {
        "exchanges": 2, "responses": 2, "streams": 0, "events": 0, "framing_errors": 0,
        "tls": {"versions": ["TLSv1.3"], "certificates": [DIGEST, "f" * 64]},
    }  # fmt: skip
    recorder.run_finished(
        1, 1, reason="client_eof", duration_ns=5, http=http,
        server_output_bytes=0, client_input_bytes=0, server_exited_first=False,
    )  # fmt: skip
    assert read_events(path)[0]["http"] == http
