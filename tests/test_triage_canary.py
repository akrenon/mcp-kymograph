"""Canaries through the whole chain: what the tool no longer keeps appears nowhere it writes.

Two chains. A real store of schema 12 (built from its own DDL, ``schema12_ddl``) holds a reason and
a severity with its triage rows; they are exported, imported into a store of 13, reported, packed
and shown in every view, and stay in the old store alone. And the operator's private notes with a
canary in every field lie beside the store, under their own name, while a report, a bundle, an
attestation and every view are made, which never read them (the tool never reads the notes).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from mcp_kymograph import cli, engagement, evidence, operator_notes, report
from mcp_kymograph.store import Store
from mcp_kymograph.web import server, views
from mcp_kymograph.web.views import Sources
from test_report_d import (
    FIXTURES,
    NOW,
    POISONED,
    drive,
    fixable_manifest,
    ingest,
    write_engagement,
)
from test_store_engagement import fleet_row
from test_triage_transfer import REASON, SEVERITY, old_store

CANARIES = (REASON, SEVERITY)


def files_under(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*") if p.is_file())


def make_store(root: Path, name: str):
    """A store of 13 with the recordings of a poisoned and a reference server under an
    engagement; its engagement file, the runs directory and the store's path."""
    held = write_engagement(root / f"engagement-{name}")
    runs = root / f"runs-{name}"
    poisoned = drive(held, runs, fixable_manifest(root / f"poisoned-{name}", POISONED),
                     "fixable-server")  # fmt: skip
    reference = drive(held, runs, FIXTURES / "corpus" / "manifest.yaml", "reference-server")
    database = root / f"{name}.sqlite"
    ingest(database, held, poisoned, reference)
    with Store.open(database) as store:
        first, second = (info.run for info in store.runs())
        for name, run in (("f1", first), ("f2", second)):
            store.file_fleet(fleet_row(name), [
                {"entry": "srv", "scenario": "scn", "provenance": "poison", "state": "complete",
                 "exit_code": 0, "run": run, "problems": []},
            ])  # fmt: skip
    return held, runs, database


def report_and_bundle(root: Path, held: Path, runs: Path, database: Path, name: str):
    """The report of ``database``, the bundle packed from it and the attestation of both."""
    built = report.build(engagement_path=held, store=database, runs_dir=runs, now=NOW)
    report_path = root / f"report-{name}.md"
    report_path.write_text(report.render(built))
    bundle = root / f"bundle-{name}"
    packed = evidence.pack(
        engagement=engagement.load(held), store_path=database, runs_dir=runs, out=bundle,
        report=report_path, now=NOW,
    )  # fmt: skip
    with Store.open(database) as store:
        store.file_bundle(
            index_digest=packed.index_digest, path=str(bundle), packed_utc=packed.packed_utc,
            derived_from=None, engagement_digest=packed.engagement_digest,
        )  # fmt: skip
    attestation = report.render_attestation(
        report.attest(
            store=database, engagement_path=held, bundle_dir=bundle, runs_dir=runs, now=NOW
        )  # fmt: skip
    )
    return report_path, bundle, attestation


#: Routes whose view cannot show anything for this store, and why. Empty today: every route has
#: a case. A route is named here only with its reason, never to silence the test.
NOT_SHOWN: dict[str, str] = {}


def every_view_text(database: Path, runs: Path, bundle: Path, attestation: Path) -> str:
    """Every view of the web interface, as the JSON it is sent as (a download as its name and
    text). The views are the routes of ``web.server.ROUTES`` (and the corpus route beside them);
    a route without a case here, or a case without a route, fails the test by name."""
    sources = Sources(
        store=database, runs=runs, manifests=(FIXTURES / "corpus" / "manifest.yaml",),
        scenarios=(FIXTURES / "scenarios" / "all-signals.yaml",), bundles=(bundle,),
        attestations=(attestation,),
    )  # fmt: skip
    with Store.open_read_only(database) as store:
        run_ids = [info.run for info in store.runs()]
        fleet_ids = [info["fleet"] for info in store.fleets()]
    refs = [row["ref"] for row in views.runs(sources)["data"]]
    findings = sum(views.triage(sources)["data"]["findings"].values(), [])
    listed = evidence.read_index(bundle / evidence.INDEX_FILE).files
    assert len(run_ids) >= 2 and len(fleet_ids) >= 2 and refs and findings and listed

    def seqs(ref):
        return [item["seq"] for item in views.messages(sources, ref, 0, 500)["data"]["items"]]

    cases = {
        "about": lambda: [views.about(sources)],
        "runs": lambda: [views.runs(sources)],
        "run": lambda: [views.run(sources, ref) for ref in refs],
        "messages": lambda: [views.messages(sources, ref, 0, 500) for ref in refs],
        "message": lambda: [views.message(sources, ref, seq) for ref in refs for seq in seqs(ref)],
        "store_runs": lambda: [views.store_runs(sources)],
        "store_findings": lambda: [
            views.store_findings(sources, kind) for kind in ("reference", "poison")
        ],
        "store_candidates": lambda: [views.store_candidates(sources)],
        "store_diff": lambda: [views.store_diff(sources, run_ids[0], run_ids[1])],
        "fleets": lambda: [views.fleets(sources)],
        "fleet": lambda: [views.fleet(sources, fleet) for fleet in fleet_ids],
        "fleet_compare": lambda: [
            views.fleet_compare(sources, None, None),
            views.fleet_compare(sources, fleet_ids[0], fleet_ids[1]),
        ],
        "corpora": lambda: [views.corpora(sources)],
        "corpus": lambda: [views.corpus(sources, 0)],
        "scenarios": lambda: [views.scenarios(sources)],
        "scenario": lambda: [views.scenario(sources, 0)],
        "signals": lambda: [views.signals(sources)],
        "store_engagement": lambda: [views.store_engagement(sources)],
        "triage": lambda: [views.triage(sources)],
        "triage_history": lambda: [views.triage_history(sources, f["finding"]) for f in findings],
        "triage_review": lambda: [views.triage_review(sources, f["finding"]) for f in findings],
        "bundles": lambda: [views.bundles(sources)],
        "bundle": lambda: [views.bundle(sources, 0)],
        "bundle_file": lambda: [views.bundle_file(sources, 0, item.path) for item in listed],
        "attestations": lambda: [views.attestations(sources)],
        "attestation": lambda: [views.attestation(sources, 0)],
        "attestation_file": lambda: [views.attestation_file(sources, 0)],
    }  # fmt: skip
    routed = {route.function for route in server.ROUTES.values()} | {server._CORPUS.function}
    assert routed - cases.keys() == set(), "routes without a case"
    assert cases.keys() - routed == set(), "cases without a route"
    assert NOT_SHOWN.keys() <= routed, "excluded views that are no route"
    shown = []
    for name in sorted(routed - NOT_SHOWN.keys()):
        answers = cases[name]()
        assert answers, f"{name} was given nothing to show"
        for answer in answers:
            if isinstance(answer, views.Download):
                shown.append(
                    json.dumps({"name": answer.name, "body": answer.body.decode("latin-1")})
                )
            else:
                assert answer["data"] is not None, f"{name} showed nothing: {answer['notices']}"
                shown.append(json.dumps(answer))
    return "\n".join(shown)


def test_a_reason_and_a_severity_of_a_real_store_of_12_stay_in_it_alone_and_the_status_is_kept(
    tmp_path, capsys
):
    held, runs, database = make_store(tmp_path, "new")
    source = tmp_path / "source.sqlite"
    shutil.copyfile(database, source)
    with Store.open(source) as store:
        finding = store.findings_with_triage("poison")[0]["finding"]
        store.triage_set(finding=finding, role="operator", status="confirmed",
                         author="A. Operator", now=NOW)  # fmt: skip
        store.triage_set(finding=finding, role="customer", status="question",
                         author="C. Customer", now=NOW)  # fmt: skip
        kept = [(r["role"], r["status"], r["author"]) for r in store.triage_history()]
    old = old_store(tmp_path, source)
    assert all(canary.encode() in old.read_bytes() for canary in CANARIES)
    capsys.readouterr()

    exported = tmp_path / "export.json"
    assert cli.main(["store", "triage", "export", "-q", "--store", str(old),
                     "--out", str(exported)]) == 0  # fmt: skip
    assert "nothing is exported" not in capsys.readouterr().err
    assert cli.main(["store", "triage", "import", "-q", "--store", str(database),
                     str(exported)]) == 0  # fmt: skip
    capsys.readouterr()

    report_path, bundle, attestation = report_and_bundle(tmp_path, held, runs, database, "new")
    attestation_path = tmp_path / "attestation.md"
    attestation_path.write_text(attestation)
    shown = every_view_text(database, runs, bundle, attestation_path)

    with Store.open_read_only(database) as store:
        assert [(r["role"], r["status"], r["author"]) for r in store.triage_history()] == kept
    assert "confirmed" in shown and "question" in shown, "the status is shown"
    everything = [p for p in tmp_path.rglob("*") if p.is_file() and p != old]
    assert database in everything and report_path in everything and exported in everything
    assert attestation_path in everything and files_under(bundle) and files_under(runs)
    for canary in CANARIES:
        assert canary.encode() in old.read_bytes(), "only the old store holds it"
        assert canary not in shown and canary not in attestation
        for path in everything:
            assert canary.encode() not in path.read_bytes(), (canary, path)


#: One canary per field of the operator's notes; the key and the vector must be valid, so they
#: are unusual rather than marked.
ENGAGEMENT_CANARY = "NOTES-ENGAGEMENT-CANARY-4731"
KEY_CANARY = "fk-ca11ab1ec0ffee42"
CVSS_CANARY = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/AU:Y/R:I"
RATIONALE_CANARY = "NOTES-RATIONALE-CANARY-4732"
STATUS_CANARY = "partially_fixed"


def test_notes_with_a_canary_in_every_field_beside_the_store_reach_nothing_it_writes(tmp_path):
    held, runs, database = make_store(tmp_path, "noted")
    noted = operator_notes.beside(database)[-1]
    assert noted.name == "noted.sqlite.operator-notes.json"
    noted.write_text(json.dumps({
        "engagement": ENGAGEMENT_CANARY,
        "findings": {KEY_CANARY: {"cvss": CVSS_CANARY, "rationale": RATIONALE_CANARY,
                                  "status": STATUS_CANARY}},
    }))  # fmt: skip
    loaded = operator_notes.load(noted)
    assert loaded.engagement == ENGAGEMENT_CANARY
    assert loaded.findings[KEY_CANARY].status == STATUS_CANARY

    report_path, bundle, attestation = report_and_bundle(tmp_path, held, runs, database, "noted")
    attestation_path = tmp_path / "attestation.md"
    attestation_path.write_text(attestation)
    shown = every_view_text(database, runs, bundle, attestation_path)

    canaries = (ENGAGEMENT_CANARY, KEY_CANARY, CVSS_CANARY, RATIONALE_CANARY, STATUS_CANARY)
    outputs = [p for p in tmp_path.rglob("*") if p.is_file() and p != noted]
    assert database in outputs and report_path in outputs and files_under(bundle)
    for canary in canaries:
        assert canary in noted.read_text()
        assert canary not in shown, canary
        for path in outputs:
            assert canary.encode() not in path.read_bytes(), (canary, path)
