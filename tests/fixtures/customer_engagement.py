"""One engagement made the way an operator makes it, with every document the customer receives.

Used by the customer walk-through (tests/test_customer_walkthrough.py), the banned-word test
(tests/test_banned_words.py) and the coverage tests (tests/test_report_coverage.py). Fixture
servers only: the corpus's reference and poison entries driven with ``--isolation host``, and an
endpoint entry driven over HTTP against tests/fixtures/http_server.py on loopback (isolation
``remote``). One more run is driven under the engagement and never filed: it is the recording
given beside the store's runs (``evidence pack --session``) in the second of two bundles, so
that one bundle lists no such recording and the other lists one.

:func:`make` returns the paths and the documents.
:func:`banned_in` and :func:`sentence_words` read a document as the banned-word rule reads it:
the tool's own words, never a value in a code span.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from mcp_kymograph import cli, engagement, evidence, handover, report
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

SCENARIO = FIXTURES / "scenarios" / "all-signals.yaml"
MANIFEST = FIXTURES / "corpus" / "manifest.yaml"

#: A banned word as a whole word, without case: not a part of a longer word (``certificate``)
#: nor of a name joined by an underscore (``secure_login``).
BANNED = re.compile(
    r"(?<!\w)(?:" + "|".join(map(re.escape, report.BANNED_WORDS)) + r")(?!\w)", re.IGNORECASE
)

#: The opening line of a fenced code block, and the fence it opened with.
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")


def banned_in(words: str) -> list[str]:
    """Every banned word in ``words``, as it stands there."""
    return BANNED.findall(words)


def sentence_words(markdown: str) -> str:
    """The words of a Markdown document that are the tool's own: every line, without its code
    spans and without fenced code blocks, both of which hold data. An indented line is read as
    words: none of the generated documents has an indented block that is not a command, and a
    reader that took indentation for code would take a list's continued paragraph for it too."""
    kept: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        opened = _FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            continue
        if opened:
            fence = opened.group(1)
            continue
        kept.append(report._spans(line)[1])
    return "\n".join(kept)


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_engagement(directory: Path, now: datetime) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCENARIO, directory / SCENARIO.name)
    data = {
        "version": 1,
        "id": "acme-2026-11",
        "customer": "ACME Corp",
        "contacts": [{"name": "Dana", "reach": "phone"}],
        "window": {"from": utc(now - timedelta(days=1)), "until": utc(now + timedelta(days=3))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": [
            {
                "path": SCENARIO.name,
                "sha256": sha256((directory / SCENARIO.name).read_bytes()).hexdigest(),
            }
        ],
        "actions": {"list": True, "call": False},
        "redaction": {"mask_keys": [], "mask_patterns": []},
    }
    path = directory / "engagement.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def endpoint_manifest(directory: Path, url: str) -> Path:
    directory.mkdir(parents=True)
    shutil.copyfile(SCENARIO, directory / SCENARIO.name)
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
                        "scenarios": [SCENARIO.name],
                    }
                ],
            }
        )
    )
    return path


def drive(held: Path, out_dir: Path, manifest: Path, entry: str, *extra: str) -> Path:
    before = set(out_dir.iterdir()) if out_dir.exists() else set()
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--manifest", str(manifest), "--entry", entry,
         "--out-dir", str(out_dir), *extra]
    )  # fmt: skip
    assert code == 0, code
    (run,) = set(out_dir.iterdir()) - before
    return run / "events.jsonl"


@dataclass
class Made:
    """The engagement's files and the documents made from them."""

    root: Path
    held: Path
    runs: Path
    database: Path
    session: Path
    report_path: Path
    report: str
    bundle: Path
    bundle_with_session: Path
    attestation: str
    attestation_with_session: str
    status: str
    handover: Path
    readmes: dict[int, str]
    #: ``redactions.json`` of the handover bundle, and ``purged.json`` of a purge of a copy of
    #: the store and its runs (taken before any bundle was filed, so that the purge deletes the
    #: copy only).
    redactions: str
    purged: str


def _pack(made_held: Path, database: Path, runs: Path, out: Path, now: datetime, **extra) -> None:
    packed = evidence.pack(
        engagement=engagement.load(made_held), store_path=database, runs_dir=runs, out=out,
        now=now, **extra,
    )  # fmt: skip
    with Store.open(database) as store:
        store.file_bundle(
            index_digest=packed.index_digest, path=str(out), packed_utc=packed.packed_utc,
            derived_from=None, engagement_digest=packed.engagement_digest,
        )  # fmt: skip


def make(root: Path, now: datetime) -> Made:
    held = write_engagement(root / "engagement", now)
    runs = root / "runs"
    host = ("--isolation", "host")
    recordings = [
        drive(held, runs, MANIFEST, "reference-server", *host),
        drive(held, runs, MANIFEST, "poison-server", *host),
    ]
    server = http_server.serve(0, variant="poison")
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
        endpoint = endpoint_manifest(root / "endpoint", url)
        recordings.append(drive(held, runs, endpoint, "customer-mcp", "--engagement-confirmed"))
    finally:
        server.shutdown()
        server.server_close()
    session = drive(held, root / "sessions", MANIFEST, "reference-server", *host)
    database = root / "findings.sqlite"
    ingest = ["store", "ingest", "-q", "--store", str(database), "--engagement", str(held)]
    assert cli.main([*ingest, *map(str, recordings)]) == 0
    purging = root / "purging"
    purging.mkdir()
    shutil.copyfile(database, purging / database.name)
    shutil.copytree(runs, purging / "runs")

    built = report.build(engagement_path=held, store=database, runs_dir=runs, now=now)
    report_text = report.render(built)
    report_path = root / "report.md"
    report_path.write_text(report_text)

    bundle = root / "bundle"
    _pack(held, database, runs, bundle, now, report=report_path)
    with_session = root / "bundle-with-session"
    _pack(held, database, runs, with_session, now, report=report_path, sessions=[session])

    def attest(bundle_dir: Path) -> str:
        made = report.attest(
            store=database, engagement_path=held, bundle_dir=bundle_dir, runs_dir=runs, now=now
        )
        return report.render_attestation(made)

    with Store.open_read_only(database) as store:
        status = report.render_status(report.status(store, out_dir=runs, now=now))

    handed = root / "handover"
    evidence.redact(bundle, engagement_path=held, out=handed, now=now)
    fields = handover.parse_customer_readme((handed / handover.CUSTOMER_README).read_text())
    readmes = {
        version: handover.render_customer_readme(fields, version) for version in handover.WORDINGS
    }

    evidence.purge(
        store_path=purging / database.name, out_dir=purging / "runs", author="Operator",
        out=purging / "purged.json", now=now,
    )  # fmt: skip

    return Made(
        root=root,
        held=held,
        runs=runs,
        database=database,
        session=session,
        report_path=report_path,
        report=report_text,
        bundle=bundle,
        bundle_with_session=with_session,
        attestation=attest(bundle),
        attestation_with_session=attest(with_session),
        status=status,
        handover=handed,
        readmes=readmes,
        redactions=(handed / "redactions.json").read_text(encoding="utf-8"),
        purged=(purging / "purged.json").read_text(encoding="utf-8"),
    )
