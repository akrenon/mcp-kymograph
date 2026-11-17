"""What TLS an HTTP run spoke, in the web interface's views (CONTRACT.md 7.3): only as recorded.

The views pass every TLS fact on as the recording or the store has it; the page puts it into
words. One plain-HTTP run is driven against the loopback fixture; what an ``https`` run records
(http-transport.md 8.2, 8.3) is written event by event from it — each certificate set as the
proxy writes one — so that the sets can be chosen: disjoint, overlapping, or left out. The runs
are filed in a store of their own, and its runs and diffs are the store's own
(``RunInfo.endpoint_certificates``, the caveat ``certificate_changed``), passed on unchanged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcp_kymograph import store as store_module
from mcp_kymograph import verdict
from mcp_kymograph.store import Store
from mcp_kymograph.web import views
from mcp_kymograph.web.views import Sources
from test_web_views import (
    before_type,
    checked,
    drive,
    endpoint_manifest,
    event,
    events_of,
    kinds,
    write,
)

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

FIRST = "0123456789abcdef" * 4
SECOND = "a" * 64
THIRD = "f" * 64
#: The TLS library's text as a failure's detail carries it, with what the page must show only as
#: text: a bidi override, markup, a zero-width space.
LIBRARY_TEXT = (
    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate "
    "is not valid for 'evil‮.test' <b>bold</b>​"
)


def copied(events: list[dict]) -> list[dict]:
    return json.loads(json.dumps(events))


def finished_of(events: list[dict]) -> dict:
    return next(e for e in events if e["type"] == "run_finished")


def over_https(
    events: list[dict], certificates: list[str] | None = None, *, file_set: bool = True
) -> list[dict]:
    """The run as an ``https`` run records it: the scheme, whether the trust store's variables
    were set, each exchange's connection, and the run's set on the path that does not drop —
    distinct and sorted, as the proxy writes it. ``certificates`` None leaves the set out
    (``tls`` null), as a run that differs from its twin only there."""
    certificates = [FIRST, SECOND] if certificates is None else certificates
    changed = copied(events)
    changed[0]["endpoint"]["scheme"] = "https"
    changed[0]["trust_store_env"] = {"SSL_CERT_FILE": file_set, "SSL_CERT_DIR": False}
    for e in changed:
        if e["type"] == "http_request":
            e["tls"] = {"version": "TLSv1.3", "certificate_sha256": certificates[0]}
    finished_of(changed)["http"]["tls"] = {
        "versions": ["TLSv1.3"],
        "certificates": sorted(set(certificates)),
    }
    return changed


def without_set(events: list[dict]) -> list[dict]:
    """The same recording with its run's set left out: ``tls`` null."""
    changed = copied(events)
    finished_of(changed)["http"]["tls"] = None
    return changed


class Tls:
    """One plain-HTTP endpoint run against the loopback fixture, and the recordings written from
    it for what an ``https`` run records; the plain run and the ``https`` one filed in a store."""

    def __init__(self, root: Path) -> None:
        self.runs = root / "runs"
        self.refs: dict[str, str] = {}
        server = http_server.serve(0, variant="poison")
        url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
        try:
            manifest = endpoint_manifest(root / "manifest", url, "poison")
            directory = drive(self.runs / "driven", "--manifest", str(manifest), "--entry",
                              "poison-mcp")  # fmt: skip
        finally:
            server.shutdown()
            server.server_close()
        self.manifest = manifest
        base = events_of(directory / "events.jsonl")

        plain = copied(base)
        finished_of(plain)["http"]["tls"] = None
        self._variant("plain", plain)

        before = copied(base)
        before[0].pop("trust_store_env", None)
        for e in before:
            if e["type"] == "http_request":
                e.pop("tls", None)
        finished_of(before)["http"].pop("tls", None)
        self._variant("before-tls", before)

        https = over_https(base)
        self._variant("https", https)
        self._variant("https-machine-store", over_https(base, file_set=False))
        # Another set, sharing none with the first (a rotated certificate); one sharing FIRST;
        # and both sets of the disjoint pair left out, for a diff that differs only there.
        rotated = over_https(base, [THIRD])
        self._variant("rotated", rotated)
        self._variant("overlapping", over_https(base, [FIRST, THIRD]))
        self._variant("https-unset", without_set(https))
        self._variant("rotated-unset", without_set(rotated))

        # A handshake that failed on TLS: nothing exchanged, the library's text in the detail,
        # and the run's set with both lists empty, as the proxy writes it then.
        started = https[0]
        finished = copied([finished_of(https)])[0]
        finished["http"]["tls"] = {"versions": [], "certificates": []}
        finished["seq"] = 2
        self._variant(
            "handshake",
            [
                started,
                event(https, 1, "server_failed", reason="tls", detail=LIBRARY_TEXT),
                finished,
            ],
        )
        # A later step that failed on TLS: the leaf switched after the first exchange.
        self._variant(
            "later",
            before_type(
                https,
                "script_finished",
                event(https, 950, "step_unanswered", step="tools/list", pages=0, reason="tls",
                      detail=LIBRARY_TEXT),
            ),
        )  # fmt: skip

        self.store = root / "store.sqlite"
        with Store.open(self.store) as store:
            filed = ("plain", "https", "rotated", "overlapping", "https-unset", "rotated-unset")
            for name in filed:
                self.refs[f"run:{name}"] = store.ingest(self.recording(name)).run

    def _variant(self, name: str, events: list[dict]) -> None:
        path = write(self.runs / "variants" / name, events)
        self.refs[name] = path.parent.relative_to(self.runs).as_posix()

    def recording(self, name: str) -> Path:
        return self.runs / self.refs[name] / "events.jsonl"

    def recorded(self, name: str) -> list[dict]:
        return events_of(self.recording(name))

    @property
    def sources(self) -> Sources:
        return Sources(store=self.store, runs=self.runs, manifests=(self.manifest,))


@pytest.fixture(scope="module")
def tls(tmp_path_factory) -> Tls:
    return Tls(tmp_path_factory.mktemp("tls"))


def run_of(tls: Tls, name: str) -> dict:
    return checked(views.run(tls.sources, tls.refs[name]), "run")


# -- the run header and its overview ------------------------------------------------------------


def test_an_https_run_s_scheme_trust_store_and_set_are_in_its_overview_as_recorded(tls):
    recorded = tls.recorded("https")
    overview = run_of(tls, "https")["data"]["overview"]
    assert overview["run_started"] == recorded[0]
    assert overview["run_started"]["endpoint"]["scheme"] == "https"
    assert overview["run_started"]["trust_store_env"] == {
        "SSL_CERT_FILE": True,
        "SSL_CERT_DIR": False,
    }
    assert overview["run_finished"]["http"] == finished_of(recorded)["http"]
    assert overview["run_finished"]["http"]["tls"] == {
        "versions": ["TLSv1.3"],
        "certificates": [FIRST, SECOND],
    }
    machine = run_of(tls, "https-machine-store")["data"]["overview"]["run_started"]
    assert machine["trust_store_env"] == {"SSL_CERT_FILE": False, "SSL_CERT_DIR": False}


def test_a_plain_http_run_s_set_is_null_and_its_trust_store_null_as_recorded(tls):
    overview = run_of(tls, "plain")["data"]["overview"]
    assert overview["run_started"]["endpoint"]["scheme"] == "http"
    assert overview["run_started"]["trust_store_env"] is None
    assert "tls" in overview["run_finished"]["http"]
    assert overview["run_finished"]["http"]["tls"] is None


def test_a_recording_made_before_tls_shows_nothing_new_and_nothing_invented(tls):
    envelope = run_of(tls, "before-tls")
    data = envelope["data"]
    assert "trust_store_env" not in data["overview"]["run_started"]
    assert "tls" not in data["overview"]["run_finished"]["http"]
    assert "tls" not in data["http"]["http"]
    assert data["overview"]["server_failed"] == []
    for exchange in data["http"]["exchanges"]:
        assert all("tls" not in request for request in exchange["request"])
    # No notice for what an older recording does not hold: it is not a shortfall.
    assert kinds(envelope) == kinds(run_of(tls, "plain"))


# -- the http tab -------------------------------------------------------------------------------


def test_each_request_s_tls_is_in_the_http_tab_with_its_head_as_recorded(tls):
    recorded = [e for e in tls.recorded("https") if e["type"] == "http_request"]
    data = run_of(tls, "https")["data"]
    assert "http" in data["tabs"]
    requests = [r for x in data["http"]["exchanges"] for r in x["request"]]
    assert requests == recorded
    assert all(r["tls"] == {"version": "TLSv1.3", "certificate_sha256": FIRST} for r in requests)
    assert data["http"]["http"]["tls"]["certificates"] == [FIRST, SECOND]
    plain = run_of(tls, "plain")["data"]["http"]["exchanges"]
    assert all(r["tls"] is None for x in plain for r in x["request"])


# -- a failure's text ---------------------------------------------------------------------------


def test_a_handshake_that_failed_on_tls_is_in_the_overview_with_its_detail_as_recorded(tls):
    recorded = next(e for e in tls.recorded("handshake") if e["type"] == "server_failed")
    envelope = run_of(tls, "handshake")
    data = envelope["data"]
    assert data["overview"]["server_failed"] == [recorded]
    assert data["overview"]["server_failed"][0]["detail"] == LIBRARY_TEXT
    # The verdict beside it, as it judges the recording: the page puts the two side by side.
    judged = verdict.read(tls.recording("handshake"))
    assert data["verdict"]["state"] == judged.state == verdict.SERVER_FAILED
    assert data["verdict"]["causes"] == [
        {"cause": s.cause, "words": s.reason, "state": s.state} for s in judged.shortfalls
    ]
    # The cause the page puts beside the detail: the one the failure's reason names.
    (cause,) = [c for c in data["verdict"]["causes"] if c["cause"] == recorded["reason"]]
    assert cause["cause"] == "tls" and cause["state"] == verdict.SERVER_FAILED
    assert envelope["notices"][0]["kind"] == "not_a_result"
    assert data["overview"]["run_finished"]["http"]["tls"] == {"versions": [], "certificates": []}


def test_a_later_step_that_failed_on_tls_is_in_the_inventory_with_its_detail_as_recorded(tls):
    recorded = next(e for e in tls.recorded("later") if e["type"] == "step_unanswered")
    data = run_of(tls, "later")["data"]
    assert recorded in data["inventory"]["steps"]
    assert recorded["detail"] == LIBRARY_TEXT
    assert data["verdict"]["state"] == verdict.INCOMPLETE
    (cause,) = [c for c in data["verdict"]["causes"] if c["cause"] == recorded["reason"]]
    assert cause["cause"] == "tls" and cause["state"] == verdict.INCOMPLETE
    assert data["overview"]["server_failed"] == []


# -- the store's runs and a diff ----------------------------------------------------------------


def diff_of(tls: Tls, before: str, after: str) -> dict:
    return checked(
        views.store_diff(tls.sources, tls.refs[f"run:{before}"], tls.refs[f"run:{after}"]),
        "store_diff",
    )


def test_the_store_s_runs_give_each_run_s_certificates_as_the_store_files_them(tls):
    rows = checked(views.store_runs(tls.sources), "store_runs")["data"]
    by_run = {r["run"]: r["endpoint_certificates"] for r in rows}
    assert by_run[tls.refs["run:https"]] == [FIRST, SECOND]
    assert by_run[tls.refs["run:rotated"]] == [THIRD]
    assert by_run[tls.refs["run:plain"]] is None
    assert by_run[tls.refs["run:https-unset"]] is None
    with Store.open_read_only(tls.store) as store:
        assert {i.run: i.to_dict()["endpoint_certificates"] for i in store.runs()} == by_run


def test_a_diff_of_disjoint_sets_carries_the_caveat_and_moves_nothing_for_it(tls):
    envelope = diff_of(tls, "https", "rotated")
    data = envelope["data"]
    assert data["before"]["endpoint_certificates"] == [FIRST, SECOND]
    assert data["after"]["endpoint_certificates"] == [THIRD]
    with Store.open_read_only(tls.store) as store:
        given = store.diff(tls.refs["run:https"], tls.refs["run:rotated"]).to_dict()
    assert data == given
    for name in ("new", "gone"):
        assert store_module.CERTIFICATE_CHANGED in data["caveats"][name]
    # The same two runs with their sets left out: only the caveat differs.
    unset = diff_of(tls, "https-unset", "rotated-unset")
    assert unset["data"]["before"]["endpoint_certificates"] is None
    for name in ("new", "gone"):
        assert data["caveats"][name] == [*unset["data"]["caveats"][name],
                                         store_module.CERTIFICATE_CHANGED]  # fmt: skip
    for key in ("axes", "moved_axes", "attribution"):
        assert data[key] == unset["data"][key]
    assert envelope["notices"] == unset["notices"]


def test_a_diff_of_overlapping_sets_or_a_side_without_tls_carries_no_caveat(tls):
    overlapping = diff_of(tls, "https", "overlapping")["data"]
    assert overlapping["before"]["endpoint_certificates"] == [FIRST, SECOND]
    assert overlapping["after"]["endpoint_certificates"] == [FIRST, THIRD]
    plain = diff_of(tls, "plain", "https")["data"]
    assert plain["before"]["endpoint_certificates"] is None
    for data in (overlapping, plain):
        for flags in data["caveats"].values():
            assert store_module.CERTIFICATE_CHANGED not in flags
