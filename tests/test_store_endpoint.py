"""An endpoint run in the store: filed, compared, and its version always labelled declared.

Two runs against the loopback HTTP test server (tests/fixtures/http_server.py), each a corpus
run of an endpoint entry: kind ``endpoint``, isolation ``remote``, its egress not observed, and
its ``server_version`` — the operator's word — labelled ``declared`` wherever the store gives it
out: the run, the finding, the comparison. Nothing connects beyond 127.0.0.1.

The run is made by the command line as an operator makes it — ``drive --manifest M --entry E``
— which turns the endpoint entry into an HTTP run under ``remote`` with the entry's triple.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, verdict
from mcp_kymograph.store import Store
from test_store import finding, recording

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"


@pytest.fixture
def poison_url():
    server = http_server.serve(0, variant="poison")
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def remote_known():
    assert "remote" in verdict.ISOLATIONS
    assert "remote" not in verdict.OBSERVED_ISOLATIONS


def endpoint_manifest(directory: Path, url: str, version_declared: str | None) -> Path:
    directory.mkdir()
    source = {"endpoint": url}
    if version_declared is not None:
        source["version_declared"] = version_declared
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "poison",
                        "source": source,
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, directory)],
                    }
                ],
            }
        )
    )
    return path


def endpoint_run(tmp_path, monkeypatch, manifest_path: Path, name: str) -> Path:
    """One run of the manifest's endpoint entry, made by ``drive --manifest --entry``."""
    out = tmp_path / name
    code = cli.main(
        ["drive", "-q", "--manifest", str(manifest_path), "--entry", "customer-mcp",
         "--out-dir", str(out)]
    )  # fmt: skip
    assert code == 0
    (path,) = out.glob("*/events.jsonl")
    return path


def test_two_endpoint_runs_are_filed_and_compared_with_the_version_labelled_declared(
    tmp_path, monkeypatch, poison_url, remote_known
):
    first = endpoint_run(
        tmp_path, monkeypatch, endpoint_manifest(tmp_path / "m1", poison_url, "3.1"), "one"
    )
    second = endpoint_run(
        tmp_path, monkeypatch, endpoint_manifest(tmp_path / "m2", poison_url, "3.2"), "two"
    )
    started = json.loads(first.read_text().splitlines()[0])
    assert started["transport"] == "streamable-http"
    assert started["isolation"] == "remote"
    assert started["reproduction"]["corpus"]["identity"] == {
        "kind": "endpoint",
        "version": "3.1",
        "files": 0,
        "version_declared": "3.1",
    }

    with Store.open(tmp_path / "findings.sqlite") as store:
        filed = [store.ingest(path) for path in (first, second)]
        assert [f.state for f in filed] == ["complete", "complete"]
        assert all(f.findings for f in filed), "the poison variant is found over HTTP"
        runs = {info.server_version: info for info in store.runs()}
        assert set(runs) == {"3.1", "3.2"}
        for info in runs.values():
            row = info.to_dict()
            assert info.server_identity_kind == "endpoint"
            assert (row["server_version_kind"], row["isolation"], row["egress_observed"]) == (
                "declared",
                "remote",
                False,
            )
            assert (row["sandbox_image"], row["target_image"]) == (None, None)

        findings = store.findings_by_provenance("poison")
        assert findings
        assert {f["server_version"] for f in findings} == {"3.1", "3.2"}
        assert {f["server_version_kind"] for f in findings} == {"declared"}

        diff = store.diff(runs["3.1"].run, runs["3.2"].run).to_dict()
    assert diff["server_version_kind"] == {"before": "declared", "after": "declared"}
    assert (diff["before"]["server_version_kind"], diff["after"]["server_version_kind"]) == (
        "declared",
        "declared",
    )
    assert diff["moved_axes"] == ["server"]
    server = diff["axes"]["server"]
    assert server["server_version"] == {"before": "3.1", "after": "3.2"}
    # The same URL: the launch did not move, only the declaration did.
    assert server["launch_digest"]["before"] == server["launch_digest"]["after"]
    assert diff["new"] == [] and diff["gone"] == []
    assert diff["unchanged"], "the same findings under two declared versions"


def test_an_undeclared_endpoint_version_is_the_word_endpoint_still_labelled_declared(
    tmp_path, monkeypatch, poison_url, remote_known
):
    path = endpoint_run(
        tmp_path, monkeypatch, endpoint_manifest(tmp_path / "m", poison_url, None), "runs"
    )
    with Store.open(tmp_path / "findings.sqlite") as store:
        store.ingest(path)
        (info,) = store.runs()
    assert (info.server_version, info.to_dict()["server_version_kind"]) == (
        "endpoint",
        "declared",
    )


# -- the label, from the identity kind and nothing else ---------------------------------------


def kinded(tmp_path, name, kind, version, findings):
    """A synthetic corpus recording whose identity is of ``kind``."""
    path = recording(tmp_path, findings, name=name, version=version)
    lines = path.read_text().splitlines()
    started = json.loads(lines[0])
    started["reproduction"]["corpus"]["identity"]["kind"] = kind
    started["server_identity"]["kind"] = kind
    lines[0] = json.dumps(started)
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.mark.parametrize(
    ("kind", "label"),
    [("content", "content"), ("revision", "revision"), ("endpoint", "declared"),
     ("something-new", "unknown")],
)  # fmt: skip
def test_the_label_is_read_from_the_identity_kind(tmp_path, kind, label):
    # A version string that looks like a content digest is still declared when the kind says so.
    version = "sha256:" + "aa" * 32
    with Store.open(tmp_path / "s.sqlite") as store:
        store.ingest(kinded(tmp_path, "run", kind, version, [finding(5, server_version=version)]))
        (info,) = store.runs()
        assert info.to_dict()["server_version_kind"] == label
        (found,) = store.findings_by_provenance("poison")
        assert found["server_version_kind"] == label


def test_a_finding_whose_runs_disagree_on_the_kind_is_mixed_not_picked(tmp_path):
    version = "sha256:" + "aa" * 32
    with Store.open(tmp_path / "s.sqlite") as store:
        for name, kind in (("content", "content"), ("declared", "endpoint")):
            store.ingest(
                kinded(tmp_path, name, kind, version, [finding(5, server_version=version)])
            )
        (found,) = store.findings_by_provenance("poison")
    assert found["server_version_kind"] == "mixed"


@pytest.mark.parametrize(("isolation", "observed"), [("host", False), ("runc", True)])
def test_egress_observed_is_the_isolation_in_the_observed_ones(tmp_path, isolation, observed):
    egress = (
        [{"seq": 97, "type": "egress_summary", "consistent": True,
          "udp_loss": {"kernel": 0, "sink": 0, "lost": 0}}]
        if isolation == "runc"
        else []
    )  # fmt: skip
    with Store.open(tmp_path / "s.sqlite") as store:
        store.ingest(recording(tmp_path, [], isolation=isolation, extra=egress))
        (info,) = store.runs()
    assert info.to_dict()["egress_observed"] is observed
