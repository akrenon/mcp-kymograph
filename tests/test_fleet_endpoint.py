"""A manifest with an endpoint entry is no fleet's: the whole fleet is refused before anything.

An endpoint entry names a server someone else runs; it is driven through ``drive`` alone. A
fleet over a manifest that holds one is refused whole — by ``fleet.run`` and by ``fleet.gate``,
which the command line asks before ``docker`` is — and nothing is launched, pinned, created or
filed.
"""

from __future__ import annotations

import json
import os

import pytest

from mcp_kymograph import engagement, fleet
from mcp_kymograph.fleet import FleetError
from mcp_kymograph.store import Store
from test_fleet import ALL_SIGNALS, _never, write_manifest
from test_fleet_engagement import NOW, engagement_file


def with_endpoints(tmp_path, *names):
    """The fixture pair's poison entry, and an endpoint entry per name."""
    path = write_manifest(tmp_path, {"name": "poison-server"})
    data = json.loads(path.read_text())
    for name in names:
        data["entries"].append(
            {
                "name": name,
                "provenance": "reference",
                "source": {"endpoint": "http://127.0.0.1:8080/mcp"},
                "launch": {"transport": "streamable-http"},
                "scenarios": [os.path.relpath(ALL_SIGNALS, tmp_path)],
            }
        )
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def no_docker(monkeypatch):
    def asked(*_args, **_kwargs):
        raise AssertionError("docker may not be asked for a fleet that is refused")

    monkeypatch.setattr(fleet, "pin", asked)


@pytest.mark.parametrize(
    ("names", "named"),
    [
        (["customer-mcp"], "endpoint entry 'customer-mcp'"),
        (["one-mcp", "two-mcp"], "endpoint entries 'one-mcp', 'two-mcp'"),
    ],
)
def test_a_fleet_over_a_manifest_with_an_endpoint_entry_is_refused_whole(
    tmp_path, no_docker, names, named
):
    manifest = with_endpoints(tmp_path, *names)
    with Store.open(tmp_path / "s.sqlite") as store:
        with pytest.raises(FleetError) as refused:
            fleet.run(manifest, store, tmp_path / "runs", launcher=_never)
        assert store.fleets() == []
        assert store.runs() == []
    assert str(refused.value) == (
        f"{manifest}: {named}: an endpoint entry runs through drive only in this version, never "
        "as part of a fleet; nothing was started"
    )
    assert refused.value.condition is None
    assert not (tmp_path / "runs").exists()


def test_the_gate_refuses_it_the_same_way_before_docker_is_asked(tmp_path, no_docker):
    manifest = with_endpoints(tmp_path, "customer-mcp")
    loaded = engagement.load(engagement_file(tmp_path))
    with pytest.raises(FleetError, match="runs through drive only in this version"):
        fleet.gate(manifest, loaded, now=NOW)
    with Store.open(tmp_path / "s.sqlite") as store:
        with pytest.raises(FleetError, match="runs through drive only in this version"):
            fleet.run(manifest, store, tmp_path / "runs", launcher=_never, engagement=loaded,
                      now=NOW)  # fmt: skip
        assert store.engagement() is None, "the store did not become the engagement's"
    assert not (tmp_path / "runs").exists()


def test_the_plan_still_gives_an_endpoint_entry_its_refusal(tmp_path):
    """Should anything reach the plan past the refusal, the job is refused, never launched."""
    jobs = fleet.plan(fleet.load_manifest(with_endpoints(tmp_path, "customer-mcp")))
    by_entry = {job.entry: job for job in jobs}
    assert by_entry["poison-server"].refusal is None
    assert "an endpoint entry runs only under remote, not runc" in by_entry["customer-mcp"].refusal
