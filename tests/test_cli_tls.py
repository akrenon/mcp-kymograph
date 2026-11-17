"""What the terminal says of a run over TLS (http-transport.md 8.3): a handshake that failed is
named ``tls`` with the library's text, through ``display``, on the first exchange and on a later
one; the exit code is the run's state. Against the fixture server over TLS on loopback, with the
test CA as the machine's trust store (``tests/fixtures/tls``)."""

from __future__ import annotations

import json

from mcp_kymograph import cli
from test_http_tls import FOREIGN, OTHER_NAME, TRUSTED, serve, trust_ca  # noqa: F401

__all__ = ["serve", "trust_ca"]


def run(tmp_path, url, capsys):
    out = tmp_path / "runs"
    code = cli.main(["drive", "--http", url, "--out-dir", str(out)])
    (recording,) = out.glob("*/events.jsonl")
    events = [json.loads(line) for line in recording.read_text().splitlines()]
    return code, capsys.readouterr().err, events


def test_a_first_handshake_that_fails_says_tls_and_the_librarys_text(
    tmp_path, trust_ca, serve, capsys
):
    port = serve(tls=OTHER_NAME)

    code, said, events = run(tmp_path, f"https://127.0.0.1:{port}/mcp", capsys)

    assert code == cli.EXIT_SERVER_FAILED
    assert "server_failed (tls): the TLS handshake with the endpoint failed — " in said
    assert "certificate verify failed" in said
    (failed,) = [e for e in events if e["type"] == "server_failed"]
    assert failed["detail"] in said, "the terminal says what the recording holds"


def test_a_later_handshake_that_fails_says_tls_and_the_librarys_text(
    tmp_path, trust_ca, serve, capsys
):
    port = serve(tls=TRUSTED, switch_tls=FOREIGN, switch_after=2)  # the probe, initialize

    code, said, events = run(tmp_path, f"https://127.0.0.1:{port}/mcp", capsys)

    assert code == cli.EXIT_INCOMPLETE
    assert "not answered: " in said and "(tls: " in said
    assert "certificate verify failed" in said
    assert [e["reason"] for e in events if e["type"] == "step_unanswered"][0] == "tls"


def test_a_run_that_verifies_says_nothing_of_tls_and_is_complete(tmp_path, trust_ca, serve, capsys):
    port = serve(tls=TRUSTED)

    code, said, _ = run(tmp_path, f"https://127.0.0.1:{port}/mcp", capsys)

    assert code == 0
    assert "tls" not in said.lower()
