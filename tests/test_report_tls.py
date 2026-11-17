"""What TLS an endpoint spoke, in the report and the re-check: as recorded, and never an axis.

Section 2 names, per run, the certificates the store filed and the versions the recording names
for a run over ``https``, says "no TLS" for one over ``http``, and nothing for a run without an
endpoint. Section 5 says "certificate changed" beside the attribution when the store's comparison
gives the caveat, and the re-check says it beside ``gone``. The https runs here are the fixture's
endpoint run (tests/test_report.py) with its scheme and its ``run_finished.http.tls`` written as an
https run records them — no TLS server is needed to read a recording.
"""

import json
import shlex
import shutil
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, evidence, report
from mcp_kymograph.store import CERTIFICATE_CHANGED, IDENTITY_FIELDS, Store
from test_report import NOW, filed, section  # noqa: F401 - filed is a fixture

A, B = "a" * 64, "b" * 64


def https_copy(source: Path, target: Path, certificates, *, hour: int, fixed=False) -> Path:
    """The endpoint run at ``source`` as if made over https an ``hour`` later, its run's set
    ``certificates``; ``fixed``: without its findings, counted as none."""
    events = [json.loads(line) for line in source.read_text().splitlines()]
    kept = []
    for event in events:
        if event["type"] == "run_started":
            event["endpoint"]["scheme"] = "https"
            event["wall_clock_utc"] = f"2099-01-01T{hour:02d}:00:00.000+00:00"
        if event["type"] == "run_finished":
            event["http"]["tls"] = {"versions": ["TLSv1.3"], "certificates": list(certificates)}
            if fixed:
                event["findings_by_statement"] = {
                    statement: dict.fromkeys(signals, 0)
                    for statement, signals in event["findings_by_statement"].items()
                }
        if fixed and event["type"] == "finding":
            continue
        kept.append(event)
    target.parent.mkdir(parents=True)
    target.write_text("".join(json.dumps(event) + "\n" for event in kept))
    return target


def endpoint_recording(filed) -> Path:  # noqa: F811
    with Store.open_read_only(filed["database"]) as store:
        (run,) = [run for run in store.runs() if run.server == "customer-mcp"]
        return Path(store.recordings()[run.run])


@pytest.fixture(scope="module")
def https_filed(filed, tmp_path_factory):  # noqa: F811
    """Copies of the fixture's store and runs: ``before`` with an https run presenting A,
    packed as the previous bundle; ``after`` with that run and a later one presenting B, which
    no longer sights what the first did."""
    root = tmp_path_factory.mktemp("tls")
    runs = root / "runs"
    shutil.copytree(filed["runs"], runs)
    source = endpoint_recording(filed)
    first = https_copy(source, runs / "https-a" / "events.jsonl", [A], hour=1)
    second = https_copy(source, runs / "https-b" / "events.jsonl", [B], hour=2, fixed=True)
    stores = {}
    for name, recordings in (("before", [first]), ("after", [first, second])):
        database = root / f"{name}.sqlite"
        shutil.copyfile(filed["database"], database)
        assert cli.main(["store", "ingest", "-q", "--store", str(database), "--engagement",
                         str(filed["held"]), *map(str, recordings)]) == 0  # fmt: skip
        stores[name] = database
    bundle = root / "bundle"
    evidence.pack(engagement=engagement.load(filed["held"]), store_path=stores["before"],
                  runs_dir=runs, out=bundle, now=NOW)  # fmt: skip
    with Store.open_read_only(stores["after"]) as store:
        first_run, second_run = store.resolve(str(first)), store.resolve(str(second))
        assert store.run_info(second_run).complete, store.run_info(second_run).problems
    return {**stores, "runs": runs, "bundle": bundle, "held": filed["held"],
            "first": first_run, "second": second_run}  # fmt: skip


def built(https_filed, **options) -> report.ParsedReport:
    with Store.open_read_only(https_filed["after"]) as store:
        made = report.build(engagement_path=https_filed["held"], store=store,
                            runs_dir=https_filed["runs"], now=NOW, **options)  # fmt: skip
    return report.parse(report.render(made))


def test_section_2_names_the_certificates_and_versions_of_an_https_run(https_filed):
    two = section(built(https_filed), 2).sentences
    tls = [s for s in two if s.words.startswith("TLS for run")]
    assert len(tls) == 2 and {s.kind for s in tls} == {report.RECORDED}
    first = next(s for s in tls if https_filed["first"][:12] in s.line())
    assert "version `TLSv1.3`" in first.line()
    presented = (
        "the SHA-256 of the certificate the endpoint presented, as presented and not checked"
    )
    assert f"{presented} here: `{A}`." in first.line()


def test_section_2_says_no_tls_for_an_http_run_and_nothing_for_stdio(https_filed):
    two = section(built(https_filed), 2).sentences
    plain = [s for s in two if s.words.startswith("No TLS for run")]
    assert len(plain) == 1 and plain[0].kind == report.RECORDED
    assert plain[0].line().endswith("its endpoint's scheme is `http`.")
    # Four runs over stdio (reference, poison, hostile, the cut poison run): nothing of TLS.
    said = [s for s in two if "TLS for run" in s.words]
    assert len(said) == 3


def test_section_5_says_certificate_changed_beside_the_attribution(https_filed):
    """A real-world entry's lines are each marked a candidate, so the words are matched in
    lower case."""
    five = section(built(https_filed, previous=https_filed["bundle"]), 5).sentences
    words = [s.line().lower() for s in five]
    attribution = next(n for n, w in enumerate(words) if "moved axes: none; attribution" in w
                       and "nothing recorded moved" in w)  # fmt: skip
    changed = [n for n, w in enumerate(words) if "certificate changed: the endpoint" in w]
    assert len(changed) == 1 and attribution < changed[0] <= attribution + 2
    assert five[changed[0]].kind == report.DERIVED
    assert "moves no axis and no attribution" in words[changed[0]]
    for name in ("new", "gone"):
        caveat = report.CAVEAT_WORDS[CERTIFICATE_CHANGED].lower()
        assert any(f"caveat on {name}: {caveat}." in w for w in words)


def test_section_5_says_nothing_of_certificates_where_none_changed(filed):  # noqa: F811
    bundle = filed["root"] / "unchanged-bundle"
    evidence.pack(engagement=engagement.load(filed["held"]), store_path=filed["database"],
                  runs_dir=filed["runs"], out=bundle, now=NOW)  # fmt: skip
    with Store.open_read_only(filed["database"]) as store:
        made = report.build(engagement_path=filed["held"], store=store, runs_dir=filed["runs"],
                            previous=bundle, now=NOW)  # fmt: skip
    rendered = report.render(made)
    assert "Certificate changed" not in rendered and "certificate_changed" not in rendered


def test_the_re_check_says_certificate_changed_beside_gone(https_filed):
    with Store.open_read_only(https_filed["after"]) as store:
        gone = set(store.findings_of(https_filed["first"])) - set(
            store.findings_of(https_filed["second"])
        )
        named = [
            f["finding"]
            for f in store.findings_with_triage("real-world")
            if tuple(f[n] for n in IDENTITY_FIELDS) in gone
        ]
    assert named

    result = report.recheck(store=https_filed["after"], engagement_path=https_filed["held"],
                            runs_dir=https_filed["runs"], finding_ids=named,
                            after=https_filed["second"])  # fmt: skip

    assert {item.outcome for item in result.items} == {report.GONE}
    assert all(item.certificate_changed and item.server_unpinned for item in result.items)
    lines = report.render_recheck(result).splitlines()
    for number, text in enumerate(lines):
        if text.startswith("  gone: "):
            assert lines[number + 1 : number + 3] == [
                f"  {report.UNPINNED}",
                f"  {CERTIFICATE_CHANGED}",
            ]
    for item in result.items:
        assert "--rationale" not in shlex.split(item.triage_line)
    written = result.to_dict()
    assert {item["certificate_changed"] for item in written["items"]} == {True}
