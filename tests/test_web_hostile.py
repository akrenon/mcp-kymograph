"""The web interface under hostile strings: every view, review mode, a bundle and an attestation.

``tests/fixtures/web/hostile_server.py`` is a stdio server whose names, titles, descriptions,
schema descriptions, error messages, resource texts and ``serverInfo.name`` are the values of
``HOSTILE_VALUES``. It is driven through a corpus entry of its own, the recording is filed in a
store under an engagement, a finding is decided on, and a bundle and an attestation are made —
all through ``cli.main``, as ``test_web_views.py`` does. No server and no browser: the
envelopes are what the page is given, and ``app.js`` is read as text.
"""

from __future__ import annotations

import copy
import json
import os
import queue
import re
import shutil
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from hashlib import sha256
from pathlib import Path

import pytest
import yaml

from mcp_kymograph import cli, finding_classes, fleet, verdict
from mcp_kymograph.fleet import Launched
from mcp_kymograph.store import Store
from mcp_kymograph.web import views
from mcp_kymograph.web.views import Sources
from test_fleet import CONSISTENT, PINS, REFERENCE, made_up, write_manifest

FIXTURES = Path(__file__).parent / "fixtures" / "web"
sys.path.insert(0, str(FIXTURES))

import hostile_server  # noqa: E402

MANIFEST = FIXTURES / "manifest.yaml"
SCENARIO = FIXTURES / "hostile-scenario.yaml"
SERVER = FIXTURES / "hostile_server.py"
CALL_SCRIPT = FIXTURES / "call-script.yaml"
ALL_SIGNALS = Path(__file__).parent / "fixtures" / "scenarios" / "all-signals.yaml"
STATIC = Path(views.__file__).parent / "static"
APP_JS = STATIC / "app.js"

#: What a fleet is handed beside the server's own strings: the image a run says it ran in, in
#: two fleets, and the last line a run's process left on its stderr. Not the server's, but a
#: recording's and a process's, and as hostile (CONTRACT section 5).
FLEET_ONLY = {
    "COMPOSITE_IMAGE": hostile_server.composite("sandbox-image"),
    "COMPOSITE_IMAGE_AFTER": hostile_server.composite("sandbox-image-after"),
    "COMPOSITE_STDERR": hostile_server.composite("launcher-stderr"),
}

#: The fixture's values by name, so a table below says ``"SCRIPT"`` and not a literal.
VALUES = {
    **{
        name: value
        for name, value in vars(hostile_server).items()
        if name.isupper() and any(value is item for item in hostile_server.HOSTILE_VALUES)
    },
    **FLEET_ONLY,
}

#: What an operator and a customer write into a decision: hostile too. Not with a character a
#: terminal does not show: ``store triage set`` refuses an author holding one. The tool keeps no
#: rationale and no severity (``--rationale`` and ``--severity`` are refused), so the author is
#: the one free text of a decision.
OPERATOR_AUTHOR = hostile_server.MARKUP_LINK
CUSTOMER_AUTHOR = hostile_server.CYRILLIC


#: The entries of both fleets: the hostile server, driven for real; a reference server, whose
#: runs are made up; and an entry the launcher refuses.
ENTRIES = (
    {"name": "hostile-server", "server": SERVER, "command": ["{python}", str(SERVER)]},
    {"name": "reference-server", "provenance": "reference", "server": REFERENCE},
    {"name": "broken-server"},
)


#: The ``source`` of a paced run's values and the ``why`` of its two waits, in a recording this
#: tool did not write: markup and an invisible character, and a bidi override.
PACED_SOURCE = hostile_server.ZERO_WIDTH
PACED_WHY = hostile_server.MARKUP_B
PACED_WHY_AGAIN = hostile_server.BIDI
#: A key of the paced run's ``pacing`` beside the three this version writes, and its value: a
#: bidi override in the name, invisible characters in the value.
PACED_MORE_KEY = hostile_server.BIDI
PACED_MORE = hostile_server.ZERO_WIDTH
#: What a recording of another tool or an earlier version may hold beside ``pacing_enforced``
#: ``false`` (the second run driven) and ``null`` (the run with a script): values it names and
#: does not say were enforced.
DECLARED_PACING = {"runs_per_origin": 3, "min_interval_seconds": 45, "source": "file"}
UNSAID_PACING = {"runs_per_origin": 4, "min_interval_seconds": 60, "source": "default"}
#: Recordings of a paced run whose ``pacing`` holds what this version does not write: a key
#: ``__proto__`` (a number, an object) beside the three it knows, and lists where it writes a
#: scalar. The first holds a ``__proto__`` in its ``run_started`` too (``STARTED_PROTO``). Copies
#: of the second run driven, under a directory of their own (``Hostile.pacing_runs``), so that
#: nothing else of the world changes; their directory is their name.
ODD_PACING = {
    "proto-number": {
        "runs_per_origin": 2,
        "min_interval_seconds": [],
        "source": ["a", "b"],
        "__proto__": 5,
    },
    "proto-object": {
        "runs_per_origin": 2,
        "min_interval_seconds": 30,
        "source": [{"k": 1}],
        "__proto__": {"a": 1},
    },
}
STARTED_PROTO = "proto-of-run-started"


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def command(*args: str, code: int = 0) -> None:
    assert cli.main(list(args)) == code, args


class Hostile:
    """The hostile server driven, filed, decided on, packed and attested to."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.runs = root / "runs"
        listed = root / "engagement" / SCENARIO.name
        listed.parent.mkdir()
        shutil.copyfile(SCENARIO, listed)
        now = datetime.now(timezone.utc)
        self.engagement = root / "engagement" / "engagement.json"
        self.engagement.write_text(
            json.dumps(
                {
                    "version": 1,
                    "id": "hostile-2026-11",
                    "customer": hostile_server.CYRILLIC,
                    "reference": "HT-1",
                    "contacts": [{"name": "A. Contact", "role": "security lead", "reach": "phone"}],
                    "window": {
                        "from": utc(now - timedelta(days=1)),
                        "until": utc(now + timedelta(days=1)),
                    },
                    "targets": [{"host": "127.0.0.1"}],
                    "scenarios": [
                        {"path": SCENARIO.name, "sha256": sha256(listed.read_bytes()).hexdigest()}
                    ],
                    "actions": {"list": True, "call": False},
                    "redaction": {"mask_keys": [], "mask_patterns": []},
                }
            )
        )
        # Two runs of the entry under the file: filed, compared. One run without a scenario
        # and without the file: listed, not filed; two of its calls are answered with an error.
        for _ in range(2):
            command(
                "drive", "-q", "--engagement", str(self.engagement), "--manifest", str(MANIFEST),
                "--entry", "hostile-server", "--isolation", "host", "--out-dir", str(self.runs),
            )  # fmt: skip
        self.driven = sorted(self.runs.glob("*/events.jsonl"))
        self._paced(self.driven[0])
        self._pacing_beside(self.driven[1], False, DECLARED_PACING)
        self._odd_pacing(root, self.driven[1])
        command(
            "drive", "-q", "--out-dir", str(self.runs), "--script", str(CALL_SCRIPT), "--",
            sys.executable, str(SERVER),
            code=verdict.EXIT_CALL_FAILED,
        )  # fmt: skip
        (self.plain,) = set(self.runs.glob("*/events.jsonl")) - set(self.driven)
        self._pacing_beside(self.plain, None, UNSAID_PACING)
        FACTS["composite_steps"] = {
            e["seq"]
            for e in events_of(self.plain)
            if e.get("tool") == hostile_server.COMPOSITE_TOOL_NAME
        }
        self.store = root / "findings.sqlite"
        command(
            "store", "ingest", "-q", "--store", str(self.store), "--engagement",
            str(self.engagement), *map(str, self.driven),
        )  # fmt: skip
        with Store.open_read_only(self.store) as held:
            findings = held.findings_with_triage("poison")
        # The finding on ``result.tools[0].description``, which the dotted key of the same
        # listing names a second time, and the one on ``result.prompts[0].description``.
        self.finding = next(f["finding"] for f in findings if f["signal"] == "hidden_html")
        FACTS["finding"] = self.finding
        self.prompt_finding = next(
            f["finding"] for f in findings if f["signal"] == "instruction_override"
        )
        for role, status, author in (
            ("operator", "confirmed", OPERATOR_AUTHOR),
            ("customer", "question", CUSTOMER_AUTHOR),
        ):
            command(
                "store", "triage", "set", "-q", "--store", str(self.store), "--finding",
                str(self.finding), "--role", role, "--status", status,
                "--author", author,
            )  # fmt: skip
        self.bundle = root / "evidence" / "bundle"
        command(
            "evidence", "pack", "-q", "--engagement", str(self.engagement), "--store",
            str(self.store), "--runs", str(self.runs), "--out", str(self.bundle),
        )  # fmt: skip
        self.handover = root / "evidence" / "handover"
        command(
            "evidence", "redact", str(self.bundle), "--engagement", str(self.engagement),
            "--store", str(self.store), "--out", str(self.handover),
        )  # fmt: skip
        self.attestation = root / "attestation.md"
        command(
            "engagement", "attest", "-q", "--store", str(self.store), "--engagement",
            str(self.engagement), "--runs", str(self.runs), "--bundle", str(self.bundle),
            "--out", str(self.attestation),
        )  # fmt: skip
        self._fleets(root)

    @staticmethod
    def _paced(path: Path) -> None:
        """Makes the recording one of a paced run, as a recording of another tool or an earlier
        version might say it, with strings of the page's own enemies: ``pacing.source``, a key of
        ``pacing`` this version does not write and its value, and the ``why`` of a ``paced``
        event are what the server's strings are elsewhere. A loopback run
        is not paced, so this is not a recording this version writes; the page is asked to show
        it as it stands. Before the run is filed, so the store holds the bytes it filed."""
        lines = path.read_text().splitlines()
        head = json.loads(lines[0])
        head["pacing_enforced"] = True
        head["pacing"] = {
            "runs_per_origin": 1,
            "min_interval_seconds": 10,
            "source": PACED_SOURCE,
            PACED_MORE_KEY: PACED_MORE,
        }
        # The wait stands before run_finished, whose seq moves on by one: nothing refers to it.
        finished = json.loads(lines[-1])
        assert finished["type"] == "run_finished"
        keys = {"v": head["v"], "run_id": head["run_id"], "t_ns": finished["t_ns"]}
        waits = [
            {**keys, "seq": finished["seq"], "type": "paced", "seconds": 2.5, "why": PACED_WHY},
            {
                **keys, "seq": finished["seq"] + 1, "type": "paced", "seconds": 3,
                "why": PACED_WHY_AGAIN, "status": 429,
            },
        ]  # fmt: skip
        finished["seq"] += len(waits)
        lines[0] = json.dumps(head)
        lines[-1:] = [*map(json.dumps, waits), json.dumps(finished)]
        path.write_text("\n".join(lines) + "\n")

    @staticmethod
    def _pacing_beside(path: Path, enforced: bool | None, held: dict) -> None:
        """Gives the recording's ``run_started`` a ``pacing`` beside a ``pacing_enforced`` that is
        not ``true``, as a recording of another tool or an earlier version might: the page is
        asked to show both as they stand. Before the run is filed."""
        lines = path.read_text().splitlines()
        head = json.loads(lines[0])
        head["pacing_enforced"] = enforced
        head["pacing"] = held
        lines[0] = json.dumps(head)
        path.write_text("\n".join(lines) + "\n")

    def _odd_pacing(self, root: Path, recording: Path) -> None:
        """Copies of the recording, each made one of a paced run with a ``pacing`` of
        ``ODD_PACING``, under ``pacing_runs``: shown by a server of their own, not filed."""
        self.pacing_runs = root / "pacing" / "runs"
        for name, held in ODD_PACING.items():
            lines = recording.read_text().splitlines()
            head = json.loads(lines[0])
            head["pacing_enforced"] = True
            head["pacing"] = held
            if name == "proto-number":
                head["__proto__"] = STARTED_PROTO
            lines[0] = json.dumps(head)
            (self.pacing_runs / name).mkdir(parents=True)
            (self.pacing_runs / name / "events.jsonl").write_text("\n".join(lines) + "\n")

    def _fleets(self, root: Path) -> None:
        """Two fleets of the hostile server, run as ``test_web_views.py`` runs its own: through
        ``fleet.run`` with a launcher in place of the one that starts ``drive`` in a container (no
        Docker). The launcher drives the hostile server for real (``cli.main(["drive", ...])``
        under ``host``, as the rest of this world is), so the fleets' recordings carry its values;
        only the environment a recording names is set to the fleet's pins (:meth:`_drive`). The
        reference entry is made up and the refused one answers with a line of stderr. Into a store
        of their own: a store that holds an engagement takes a fleet only under that file
        (``fleet._no_engagement_held``), and a fleet is run under a file only when the file covers
        the manifest's jobs, which a run under ``host`` cannot honestly be."""
        self.fleet_store = root / "fleets" / "findings.sqlite"
        self.fleet_runs = root / "fleets" / "runs"
        self.fleet_store.parent.mkdir()
        self.fleet_manifest = write_manifest(root / "fleets", *ENTRIES)

        # The second fleet's runs are driven under a manifest whose scenario of the same name
        # does not ask for the embedded URL, so that the fleet finds less than the first.
        reduced = root / "reduced"
        reduced.mkdir()
        asked = yaml.safe_load(ALL_SIGNALS.read_text())
        asked["observations"] = [
            o for o in asked["observations"] if o["signals"] != ["embedded_url"]
        ]
        (reduced / "all-signals.yaml").write_text(yaml.safe_dump(asked))
        self.reduced_manifest = write_manifest(reduced, *ENTRIES)
        listed = json.loads(self.reduced_manifest.read_text())
        for entry in listed["entries"]:
            entry["scenarios"] = ["all-signals.yaml"]
        self.reduced_manifest.write_text(json.dumps(listed))

        def launcher(image: str, stderr: str, manifest: Path | None):
            def launch(job, pins, manifest_path, out_dir, **_):
                if job.entry == "broken-server":
                    return Launched(2, None, stderr=f"kymograph: refused\n{stderr}\n")
                if job.entry == "reference-server":
                    return made_up(job, pins, out_dir)
                return self._drive(job, manifest or manifest_path, out_dir, image)

            return launch

        here = Path.cwd()
        os.chdir(root / "fleets")  # ingest runs where the store names recordings relative to it
        try:
            with Store.open(self.fleet_store) as store:
                self.fleet_first = fleet.run(
                    self.fleet_manifest, store, self.fleet_runs, pins=PINS,
                    launcher=launcher(FLEET_ONLY["COMPOSITE_IMAGE"], "refused before", None),
                ).fleet  # fmt: skip
                # The second fleet finds less (the embedded URL is gone), runs under another
                # hostile image, and its refused entry says something hostile.
                self.fleet_second = fleet.run(
                    self.fleet_manifest, store, self.fleet_runs, pins=PINS,
                    launcher=launcher(
                        FLEET_ONLY["COMPOSITE_IMAGE_AFTER"],
                        FLEET_ONLY["COMPOSITE_STDERR"],
                        self.reduced_manifest,
                    ),
                ).fleet  # fmt: skip
        finally:
            os.chdir(here)

    @staticmethod
    def _drive(job, manifest_path: Path, out_dir: Path, image: str):
        """The run of a fleet's job, really driven (``cli.main``, as the rest of the world is,
        under ``host``: no Docker). The recording is the server's own. Only the environment it
        names is changed, to the images the fleet pinned and the one the run is said to have
        been sandboxed in: a host run has none, and the fleet holds every run to its pins."""
        command(
            "drive", "-q", "--out-dir", str(out_dir), "--manifest", str(manifest_path),
            "--entry", job.entry, "--scenario", job.scenario,
            "--isolation", "host",
        )  # fmt: skip
        (path,) = out_dir.glob("*/events.jsonl")
        lines = path.read_text().splitlines()
        head, finished = json.loads(lines[0]), json.loads(lines[-1])
        assert finished["type"] == "run_finished"
        for holder in (head, head["reproduction"]["environment"]):
            holder.update(isolation="runc", sandbox_image=image, target_image=PINS.target_image)
        # A runc run closes with the account of what its target sent.
        egress = {"v": head["v"], "run_id": head["run_id"], "t_ns": finished["t_ns"], **CONSISTENT}
        egress["seq"], finished["seq"] = finished["seq"], finished["seq"] + 1
        lines = [json.dumps(e) for e in (head, *map(json.loads, lines[1:-1]), egress, finished)]
        path.write_text("\n".join(lines) + "\n")
        return Launched(0, path)

    @property
    def sources(self) -> Sources:
        return Sources(
            store=self.store,
            runs=self.runs,
            manifests=(MANIFEST,),
            scenarios=(SCENARIO,),
            bundles=(self.bundle, self.handover),
            attestations=(self.attestation,),
        )

    @property
    def fleet_sources(self) -> Sources:
        return Sources(
            store=self.fleet_store, runs=self.fleet_runs, manifests=(self.fleet_manifest,)
        )

    def ref(self, recording: Path) -> str:
        return recording.parent.relative_to(self.runs).as_posix()


_WORLD: list[Hostile] = []


def built_world(tmp_path_factory) -> Hostile:
    """The world, made once for the whole run: ``test_web_headless.py`` shows the same one in a
    browser."""
    if not _WORLD:
        _WORLD.append(Hostile(tmp_path_factory.mktemp("hostile")))
    return _WORLD[0]


@pytest.fixture(scope="module")
def hostile(tmp_path_factory) -> Hostile:
    return built_world(tmp_path_factory)


# -- what each view is given ---------------------------------------------------------------------


def kind_of(envelope: dict) -> str:
    """What a ``message`` envelope is the message of: its method, or what its answer holds. Its
    label is the run, this, and the count of the messages of the run that are the same."""
    data = envelope["data"]["message"]["payload"]["data"]
    if "method" in data:
        return data["method"]
    if "error" in data:
        return "error"
    return "result:" + ",".join(sorted(data.get("result") or ()))


def labelled_views(h: Hostile) -> dict[str, dict[str, dict]]:
    """Every view of CONTRACT section 6 that has an envelope, with the envelopes it is asked
    for: one per run, finding, bundle or message where the view takes one. Each envelope has a
    label that says which it is, so that a table can say which of them must show a value."""
    src, fleets = h.sources, h.fleet_sources
    runs = {"driven": h.ref(h.driven[0]), "plain": h.ref(h.plain)}
    store_runs = views.store_runs(src)
    ids = [row["run"] for row in store_runs["data"]]
    messages: dict[str, dict[str, dict]] = {"messages": {}, "message": {}}
    for name, ref in runs.items():
        listed = views.messages(src, ref, 0, 500)
        messages["messages"][name] = listed
        counted: dict[str, int] = {}
        for item in listed["data"]["items"]:
            one = views.message(src, ref, item["seq"])
            kind = kind_of(one)
            messages["message"][f"{name}:{kind}#{counted.get(kind, 0)}"] = one
            counted[kind] = counted.get(kind, 0) + 1
    return {
        "about": {"about": views.about(src)},
        "runs": {"runs": views.runs(src)},
        "run": {name: views.run(src, ref) for name, ref in runs.items()},
        **messages,
        "store_runs": {"store_runs": store_runs},
        "store_findings": {p: views.store_findings(src, p) for p in ("reference", "poison")},
        "store_candidates": {"store_candidates": views.store_candidates(src)},
        "store_diff": {"store_diff": views.store_diff(src, ids[0], ids[1])},
        "fleets": {"fleets": views.fleets(fleets)},
        "fleet": {
            "first": views.fleet(fleets, h.fleet_first),
            "second": views.fleet(fleets, h.fleet_second),
        },
        "fleet_compare": {"fleet_compare": views.fleet_compare(fleets, None, None)},
        "corpora": {"corpora": views.corpora(src)},
        "corpus": {"corpus": views.corpus(src, 0)},
        "scenarios": {"scenarios": views.scenarios(src)},
        "scenario": {"scenario": views.scenario(src, 0)},
        "store_engagement": {"store_engagement": views.store_engagement(src)},
        "triage": {"triage": views.triage(src)},
        "triage_history": {"triage_history": views.triage_history(src, h.finding)},
        "triage_review": {
            "hidden_html": views.triage_review(src, h.finding),
            "instruction_override": views.triage_review(src, h.prompt_finding),
        },
        "bundles": {"bundles": views.bundles(src)},
        "bundle": {"bundle": views.bundle(src, 0), "handover": views.bundle(src, 1)},
        "attestations": {"attestations": views.attestations(src)},
        "attestation": {"attestation": views.attestation(src, 0)},
        "signals": {"signals": views.signals(src)},
    }


@pytest.fixture(scope="module")
def labelled(hostile) -> dict[str, dict[str, dict]]:
    return labelled_views(hostile)


@pytest.fixture(scope="module")
def shown(labelled) -> dict[str, list[dict]]:
    return {view: list(named.values()) for view, named in labelled.items()}


#: Views that answer with a file: their bytes are compared with the file's, not walked.
DOWNLOADS = {"bundle_file", "attestation_file"}


def matches(pattern: str, path: str) -> bool:
    """Whether a path is the pattern (``[*]`` is any index)."""
    return re.fullmatch(re.escape(pattern).replace(r"\[\*\]", r"\[\d+\]"), path) is not None


def spelled(value: str) -> str:
    """A value as the tool spells it where it writes it into a message of its own: Python's
    escapes for the characters a terminal does not show, the rest as it is."""
    return repr(value)[1:-1]


class At(str):
    """A place of a table: a path (``[*]`` is any index), and which of the view's envelopes
    must hold the value there and in which of its rows.

    ``on`` are patterns (:func:`fnmatch.fnmatchcase`) of the labels of :func:`labelled_views`;
    none means every envelope of the view. ``rows`` says which items of the list at the first
    ``[*]`` hold the value, each of them by itself: none means every item, a tuple is the indices
    the test knows, a function takes the item and says by what is not the hostile value (a role,
    a name, a reference) whether it belongs to the hostile run or server. Below the first ``[*]``
    any index will do.
    """

    on: tuple[str, ...]
    rows: tuple[int, ...] | Callable[[object], bool] | None

    def __new__(cls, path: str, *, on: tuple[str, ...] = (), rows=None) -> At:
        made = super().__new__(cls, path)
        made.on, made.rows = on, rows
        return made


def at(path: str, *, on: tuple[str, ...] | str = (), rows=None) -> At:
    return At(path, on=((on,) if on else ()) if isinstance(on, str) else on, rows=rows)


@dataclass(frozen=True)
class Where:
    """Where in an envelope a value stands.

    ``paths`` are the places it **must** stand at as the whole string there, exactly as recorded
    (``[*]`` is any index); ``within`` are the places it must stand at inside a longer string (a
    file's text beside its source, a sentence the tool wrote about it). A place is a path, or an
    :class:`At` that says which envelopes and which rows must show it; a bare path is every
    envelope of the view and every row. Every one of them is required, in each envelope and each
    row it names: a view that loses the value at one of them, in one envelope or one row, is red
    though it still stands at another. It stands at no other place. ``escaped`` says the tool
    spells the value with the escapes of :func:`spelled` where it writes it into a sentence of its
    own, so the ``within`` places hold that spelling.
    """

    paths: tuple[str, ...] = ()
    within: tuple[str, ...] = ()
    escaped: bool = False

    def matches(self, path: str) -> bool:
        return any(matches(p, path) for p in (*self.paths, *self.within))

    def needle(self, value: str, path: str) -> str:
        """The string to look for at a place of this table."""
        if self.escaped and path in self.within:
            return spelled(value)
        return value


def where(*paths: str, within: tuple[str, ...] = (), escaped: bool = False) -> Where:
    return Where(paths, within, escaped)


def also(base: Where, *more: str) -> Where:
    """A table's place for a value, with places added: the value stands there as well."""
    return Where((*base.paths, *more), base.within, base.escaped)


#: What the test knows of the hostile run beside the views: the ids a table cannot spell. Set
#: when the world is made.
FACTS: dict[str, object] = {}

SCRIPTED = [
    step["call"]["tool"]
    for step in yaml.safe_load(CALL_SCRIPT.read_text())["steps"]
    if isinstance(step, dict) and "call" in step
]
#: The place of the composite tool among the calls of the script, and among those that fail (all
#: but the first, which the script says: ``plain-tool`` answers).
CALLED_AT = (SCRIPTED.index(hostile_server.COMPOSITE_TOOL_NAME),)
FAILED_AT = (SCRIPTED[1:].index(hostile_server.COMPOSITE_TOOL_NAME),)


def of_kind(kind: str) -> Callable[[object], bool]:
    """Rows that say by their ``kind`` that they are the ones of the hostile run."""
    return lambda row: isinstance(row, dict) and row.get("kind") == kind


def with_(field: str, wanted: object) -> Callable[[object], bool]:
    """Rows that say by a field that is not a hostile value (a role, an entry) which they are."""
    return lambda row: isinstance(row, dict) and row.get(field) == wanted


def of_step_of_the_composite_tool(row: object) -> bool:
    return isinstance(row, dict) and row.get("seq") in FACTS["composite_steps"]


def of_the_decided_finding(row: object) -> bool:
    return isinstance(row, dict) and row.get("finding") == FACTS["finding"]


TOOLS = "data.inventory.listings.tools.items"
#: What the run view shows of the listings it read: the items whole, each at its own place. Both
#: runs list the same server. The run with a script (``plain``) has its calls, and the run of a
#: corpus entry (``driven``) the name its entry declared.
INVENTORY = {
    "CYRILLIC": where(f"{TOOLS}[0].item.name"),
    "BIDI": where(f"{TOOLS}[0].item.title"),
    "SCRIPT": where(f"{TOOLS}[0].item.description"),
    "MARKUP_IMG": where(f"{TOOLS}[0].item.inputSchema.properties.text.description"),
    "MARKUP_LINK": where(f"{TOOLS}[0].item.inputSchema.properties.other.description"),
    "ZERO_WIDTH": where(f"{TOOLS}[1].item.title"),
    "CONTROL": where(f"{TOOLS}[1].item.description"),
    "LONG_LINE": where(f"{TOOLS}[1].item.inputSchema.properties.text.description"),
    "STYLE_LIKE": where(f"{TOOLS}[2].item.title"),
    "URL": where(
        f"{TOOLS}[2].item.description",
        "data.inventory.listings.resources.items[0].item.title",
    ),
    "MARKUP_B": where(f"{TOOLS}[2].item.inputSchema.properties.text.description"),
    "RESOURCE_TEXT": where("data.inventory.listings.resources.items[0].item.description"),
    "PROMPT_INJECTION": where("data.inventory.listings.prompts.items[0].item.description"),
    "COMPOSITE_TOOL_NAME": where(
        f"{TOOLS}[3].item.name",
        at("data.inventory.script_finished.called[*]", on="plain", rows=CALLED_AT),
        at("data.inventory.script_finished.failed[*]", on="plain", rows=FAILED_AT),
        at("data.inventory.steps[*].tool", on="plain", rows=of_step_of_the_composite_tool),
        at("data.overview.script_finished[*].called[*]", on="plain"),
        at("data.overview.script_finished[*].failed[*]", on="plain"),
        within=(
            at("data.verdict.causes[*].words", on="plain", rows=(0,)),
            at("notices[*].causes[*].words", on="plain", rows=of_kind("not_a_result")),
        ),
    ),
    "COMPOSITE_TOOL_TITLE": where(f"{TOOLS}[3].item.title"),
    "COMPOSITE_TOOL_DESCRIPTION": where(f"{TOOLS}[3].item.description"),
    "COMPOSITE_SCHEMA_DESCRIPTION": where(
        f"{TOOLS}[3].item.inputSchema.properties.text.description"
    ),
    "LONG_TOOL": where(f"{TOOLS}[4].item.description"),
    "COMPOSITE_RESOURCE": where("data.inventory.listings.resources.items[1].item.description"),
    "COMPOSITE_PROMPT": where("data.inventory.listings.prompts.items[1].item.description"),
}
RESULT = "data.message.payload.data.result"
#: Which message envelopes of the two runs are asked for a value (the labels of
#: :func:`labelled_views`: the run, what the message is, and its count among the same).
LISTING = "*:result:tools,*"
RESOURCES = "*:result:resources#*"
PROMPTS = "*:result:prompts,*"
OPENING = "*:result:capabilities,*"
CONTENT = "plain:result:content#0"
#: What the message view shows: the whole payload, so the dotted keys stand beside their twins.
#: The server's own error text is in the two errors of the corpus run, the composite error is
#: the answer to the second call of the script, the long one to the third.
PAYLOAD = {
    "ERROR_TEXT": where(at("data.message.payload.data.error.message", on="driven:error#*")),
    "CYRILLIC": where(at(f"{RESULT}.tools[0].name", on=LISTING)),
    "BIDI": where(at(f"{RESULT}.tools[0].title", on=LISTING)),
    "SCRIPT": where(at(f"{RESULT}.tools[0].description", on=LISTING)),
    "DOTTED_SIDE": where(at(f"{RESULT}.tools[0].description", on=LISTING)),
    "MARKUP_IMG": where(
        at(f"{RESULT}.tools[0].inputSchema.properties.text.description", on=LISTING)
    ),
    "MARKUP_LINK": where(
        at(f"{RESULT}.tools[0].inputSchema.properties.other.description", on=LISTING)
    ),
    "ZERO_WIDTH": where(at(f"{RESULT}.tools[1].title", on=LISTING)),
    "CONTROL": where(at(f"{RESULT}.tools[1].description", on=LISTING)),
    "LONG_LINE": where(
        at(f"{RESULT}.tools[1].inputSchema.properties.text.description", on=LISTING)
    ),
    "STYLE_LIKE": where(at(f"{RESULT}.tools[2].title", on=LISTING)),
    "URL": where(
        at(f"{RESULT}.tools[2].description", on=LISTING),
        at(f"{RESULT}.resources[0].title", on=RESOURCES),
    ),
    "MARKUP_B": where(at(f"{RESULT}.tools[2].inputSchema.properties.text.description", on=LISTING)),
    "RESOURCE_TEXT": where(
        at(f"{RESULT}.resources[0].description", on=RESOURCES),
        at(f"{RESULT}.content[1].resource.text", on=CONTENT),
    ),
    "PROMPT_INJECTION": where(at(f"{RESULT}.prompts[0].description", on=PROMPTS)),
    "DOTTED_SIDE_AFTER": where(at(f"{RESULT}.prompts[0].description", on=PROMPTS)),
    "CALL_TEXT": where(at(f"{RESULT}.content[0].text", on=CONTENT)),
    "COMPOSITE_SERVER_NAME": where(at(f"{RESULT}.serverInfo.name", on=OPENING)),
    "COMPOSITE_TOOL_NAME": where(
        at(f"{RESULT}.tools[3].name", on=LISTING),
        at("data.message.payload.data.params.name", on="plain:tools/call#1"),
        within=(at("notices[*].causes[*].words", on="plain:*", rows=of_kind("not_a_result")),),
    ),
    "COMPOSITE_TOOL_TITLE": where(at(f"{RESULT}.tools[3].title", on=LISTING)),
    "COMPOSITE_TOOL_DESCRIPTION": where(at(f"{RESULT}.tools[3].description", on=LISTING)),
    "COMPOSITE_SCHEMA_DESCRIPTION": where(
        at(f"{RESULT}.tools[3].inputSchema.properties.text.description", on=LISTING)
    ),
    "LONG_TOOL": where(at(f"{RESULT}.tools[4].description", on=LISTING)),
    "COMPOSITE_ERROR": where(at("data.message.payload.data.error.message", on="plain:error#0")),
    "LONG_ERROR": where(at("data.message.payload.data.error.message", on="plain:error#1")),
    "COMPOSITE_RESOURCE": where(at(f"{RESULT}.resources[1].description", on=RESOURCES)),
    "COMPOSITE_RESOURCE_TEXT": where(at(f"{RESULT}.content[2].resource.text", on=CONTENT)),
    "LONG_RESOURCE": where(at(f"{RESULT}.content[3].resource.text", on=CONTENT)),
    "COMPOSITE_PROMPT": where(at(f"{RESULT}.prompts[1].description", on=PROMPTS)),
}


def decisions(on: str = "") -> dict[str, Where]:
    """The decision's author, where a triage view puts a row: in the current row of its role, and
    in the row of the history that is that role's."""

    def place(path: str, role: str | None = None) -> At:
        return at(path, on=on, rows=None if role is None else with_("role", role))

    return {
        "MARKUP_LINK": where(
            place("data.triage.operator.author"), place("data.history[*].author", "operator")
        ),
        "CYRILLIC": where(
            place("data.triage.customer.author"), place("data.history[*].author", "customer")
        ),
    }


CANDIDATES = "data.sightings[*].places[*].candidates[*]"


def fleet_stderr(on: str) -> Where:
    return where(
        at("data.results[*].problems[*]", on=on, rows=with_("entry", "broken-server")),
        at("notices[*].problems[*]", on=on, rows=of_kind("not_a_result")),
    )


#: Per view, the hostile values it shows and where. A value the view shows that is not here is
#: red, and so is a value here that the view does not show (nothing is dropped); the views that
#: show none say so with an empty table.
SHOWS: dict[str, dict[str, Where]] = {
    "about": {},
    "runs": {},
    "run": {
        **INVENTORY,
        "COMPOSITE_SERVER_NAME": where(
            "data.verdict.announced_server",
            at("data.overview.server_name_mismatch[*].announced", on="driven"),
        ),
        # The paced run of the world (``Hostile._paced``), the first one driven: the source of
        # its values in the recording and in the engagement header, the value of the key beside
        # them, and the reasons of its waits.
        "ZERO_WIDTH": also(
            INVENTORY["ZERO_WIDTH"],
            at("data.overview.run_started.pacing.source", on="driven"),
            at("data.engagement.pacing.source", on="driven"),
            at(f"data.overview.run_started.pacing.{PACED_MORE_KEY}", on="driven"),
            at(f"data.engagement.pacing.{PACED_MORE_KEY}", on="driven"),
        ),
        "MARKUP_B": also(
            INVENTORY["MARKUP_B"], at("data.overview.paced[*].why", on="driven", rows=(0,))
        ),
        "BIDI": also(INVENTORY["BIDI"], at("data.overview.paced[*].why", on="driven", rows=(1,))),
    },
    "messages": {
        "COMPOSITE_TOOL_NAME": where(
            within=(at("notices[*].causes[*].words", on="plain", rows=of_kind("not_a_result")),)
        )
    },
    "message": PAYLOAD,
    "store_runs": {"COMPOSITE_SERVER_NAME": where("data[*].announced_server")},
    "store_findings": {},
    "store_candidates": {},
    "store_diff": {
        "COMPOSITE_SERVER_NAME": where(
            "data.before.announced_server", "data.after.announced_server"
        )
    },
    "fleets": {
        "COMPOSITE_IMAGE": where(within=(at("data[*].problems[*]", rows=(0,)),), escaped=True),
        "COMPOSITE_IMAGE_AFTER": where(
            within=(at("data[*].problems[*]", rows=(1,)),), escaped=True
        ),
    },
    "fleet": {
        "COMPOSITE_IMAGE": where(within=(at("data.problems[*]", on="first"),), escaped=True),
        "COMPOSITE_IMAGE_AFTER": where(within=(at("data.problems[*]", on="second"),), escaped=True),
        "COMPOSITE_STDERR": fleet_stderr("second"),
    },
    "fleet_compare": {
        "COMPOSITE_IMAGE": where(
            at(
                "data.entries[*].axes.environment.sandbox_image.before",
                rows=with_("entry", "hostile-server"),
            )
        ),
        "COMPOSITE_IMAGE_AFTER": where(
            at(
                "data.entries[*].axes.environment.sandbox_image.after",
                rows=with_("entry", "hostile-server"),
            )
        ),
    },
    "corpora": {},
    "corpus": {
        "MARKUP_LINK": where(within=("data.source",)),
        "MARKUP_IMG": where(within=("data.source",)),
    },
    "scenarios": {},
    "scenario": {"MARKUP_B": where(within=("data.source",))},
    "store_engagement": {"CYRILLIC": where("data.engagement.versions[*].file_declared.customer")},
    "triage": {
        "MARKUP_LINK": where(
            at("data.findings.poison[*].triage.operator.author", rows=of_the_decided_finding)
        ),
        "CYRILLIC": where(
            at("data.findings.poison[*].triage.customer.author", rows=of_the_decided_finding),
            "data.questions.poison[*].row.author",
        ),
    },
    "triage_history": decisions(),
    "triage_review": {
        **decisions("hidden_html"),
        "SCRIPT": where(at(CANDIDATES, on="hidden_html")),
        "DOTTED_SIDE": where(at(CANDIDATES, on="hidden_html")),
        "PROMPT_INJECTION": where(at(CANDIDATES, on="instruction_override")),
        "DOTTED_SIDE_AFTER": where(at(CANDIDATES, on="instruction_override")),
    },
    "bundles": {},
    "bundle": {
        "CYRILLIC": where(at("data.customer_readme.fields.customer_declared", on="handover"))
    },
    "attestations": {},
    "attestation": {},
    "signals": {},
}


def places(value, path: str = "") -> Iterator[tuple[str, dict | list, str | int, str]]:
    """Every string value of a JSON value with the path it stands at (keys joined with ``.``,
    indices as ``[n]``, as the inspector spells them), and the container and key to change it."""
    if isinstance(value, dict):
        for key, item in list(value.items()):
            yield from places_in(value, key, item, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for n, item in enumerate(value):
            yield from places_in(value, n, item, f"{path}[{n}]")


def places_in(container, key, item, path: str):
    if isinstance(item, str):
        yield path, container, key, item
    else:
        yield from places(item, path)


def walk(value, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string value of a JSON value with the path it stands at."""
    if isinstance(value, str):
        yield path, value
    for found, _container, _key, text in places(value, path):
        yield found, text


def resolve(envelope: dict, head: str):
    """What stands at a path of plain keys and indices (no ``[*]``, no dotted key)."""
    node = envelope
    for key, index in re.findall(r"([^.\[\]]+)|\[(\d+)\]", head):
        node = node[int(index)] if index else node[key]
    return node


def under(path: str, prefix: str) -> bool:
    """Whether a path is the prefix or inside it (``a[1]`` is not ``a[10]``)."""
    return path == prefix or (path.startswith(prefix) and path[len(prefix)] in ".[")


def rows_of(envelope: dict, spec: At) -> list[str | None]:
    """The rows of an envelope that must hold the value at this place, as the path of each; one
    ``None`` for a place that is not in a list."""
    if "[*]" not in spec:
        return [None]
    head = spec.split("[*]")[0]
    return [
        f"{head}[{n}]"
        for n, row in enumerate(resolve(envelope, head))
        if spec.rows is None or (n in spec.rows if isinstance(spec.rows, tuple) else spec.rows(row))
    ]


def lost_at(
    view: str,
    name: str,
    spec: At,
    needle: str,
    exact: bool,
    labels: list[str],
    envelopes: list[dict],
) -> list[str]:
    """Each envelope and row of this place that does not hold the value there, and a place no
    envelope or row of the view is asked to hold it at."""
    wrong, asked = [], 0
    for label, envelope in zip(labels, envelopes, strict=True):
        if spec.on and not any(fnmatchcase(label, pattern) for pattern in spec.on):
            continue
        asked += 1
        hits = [
            path
            for path, text in walk(envelope)
            if matches(spec, path) and (text == needle if exact else needle in text)
        ]
        rows = rows_of(envelope, spec)
        if not rows:
            wrong.append(f"{view}: {name} does not stand at {spec}: {label} has no row for it")
        for row in rows:
            if not any(row is None or under(path, row) for path in hits):
                at_row = f", {row}" if row else ""
                wrong.append(f"{view}: {name} does not stand at {spec}: lost in {label}{at_row}")
    if not asked:
        wrong.append(f"{view}: {name} does not stand at {spec}: no envelope is labelled for it")
    return wrong


def what_is_wrong(view: str, envelopes: list[dict], labels: list[str]) -> list[str]:
    """What is wrong with the way a view shows the hostile values, against its table: a value
    the table does not name that the view shows, a value anywhere but at the places the table
    names, a value at a place that is not as recorded, and every place the table names that an
    envelope or a row it names does not hold the value at. Empty if nothing is."""
    wrong = []
    table = SHOWS[view]
    for name, value in VALUES.items():
        place = table.get(name)
        hits = [
            (path, text)
            for envelope in envelopes
            for path, text in walk(envelope)
            if value in text or spelled(value) in text
        ]
        if place is None:
            if hits:
                wrong.append(f"{view} shows {name} at {hits[0][0]}, and the table does not say so")
            continue
        for path, text in hits:
            if any(matches(p, path) for p in place.paths):
                if text != value:
                    wrong.append(f"{view}: {name} at {path} is not as recorded")
            elif any(matches(p, path) for p in place.within):
                if (
                    place.needle(value, next(p for p in place.within if matches(p, path)))
                    not in text
                ):
                    wrong.append(f"{view}: {name} at {path} is not spelled as the table says")
            else:
                wrong.append(
                    f"{view}: {name} stands at {path}, not at {place.paths + place.within}"
                )
        for wanted, exact in [(w, True) for w in place.paths] + [(w, False) for w in place.within]:
            spec = wanted if isinstance(wanted, At) else At(wanted)
            needle = value if exact else place.needle(value, wanted)
            wrong += lost_at(view, name, spec, needle, exact, labels, envelopes)
    return wrong


def without(envelopes: list[dict], needle: str, pattern: str) -> list[dict]:
    """The envelopes as a view would make them that loses the value at the places of the
    pattern, and keeps it everywhere else."""
    return without_in(envelopes, None, None, None, needle, pattern)


def without_in(
    envelopes: list[dict],
    labels: list[str] | None,
    label: str | None,
    row: str | None,
    needle: str,
    pattern: str,
) -> list[dict]:
    """The envelopes as a view would make them that loses the value at the places of the
    pattern in one envelope (``label``, none: every one) and in one row of it (``row``, none:
    every one), and keeps it everywhere else."""
    lost = copy.deepcopy(envelopes)
    for n, envelope in enumerate(lost):
        if label is not None and labels[n] != label:
            continue
        for path, container, key, text in places(envelope):
            if matches(pattern, path) and needle in text and (row is None or under(path, row)):
                container[key] = text.replace(needle, "")
    return lost


def test_the_table_has_every_view_of_the_contract():
    rows = [
        line
        for line in (Path(views.__file__).parent / "CONTRACT.md").read_text().splitlines()
        if line.startswith("| `/api/")
    ]
    cells = [line.replace("\\|", "/").split("|")[2] for line in rows]
    functions = {name for cell in cells for name in re.findall(r"`(\w+)`", cell)}
    assert functions == set(SHOWS) | DOWNLOADS


def test_the_fixture_s_values_are_all_in_the_recordings_it_is_driven_into(hostile):
    recorded = "".join(p.read_text() for p in hostile.driven + [hostile.plain])
    made_up = "".join(p.read_text() for p in hostile.fleet_runs.glob("*/*/*/events.jsonl"))
    filed = "".join(p.read_text() for p in hostile.fleet_runs.glob("*/fleet.json"))
    assert set(VALUES.values()) - set(FLEET_ONLY.values()) == set(hostile_server.HOSTILE_VALUES)
    for name, value in VALUES.items():
        # A fleet's images are in its runs' recordings, the launcher's last line only in the
        # fleet's own record.
        holder = (
            filed if name == "COMPOSITE_STDERR" else made_up if name in FLEET_ONLY else recorded
        )
        assert json.dumps(value)[1:-1] in holder, name


def test_the_call_script_names_the_composite_tool_as_the_fixture_does():
    steps = yaml.safe_load(CALL_SCRIPT.read_text())["steps"]
    called = [step["call"]["tool"] for step in steps if isinstance(step, dict) and "call" in step]
    assert hostile_server.COMPOSITE_TOOL_NAME in called


def test_every_place_has_a_composite_of_every_kind_and_a_line_over_10000_characters_is_in_three():
    kinds = {
        "markup": "<u>u</u>",
        "script": "<script>",
        "Cc": "\x07",
        "bidi": "\u202e",
        "zero-width": "\u200b",
        "Cyrillic": "\u0430pple",
        "Greek": "\u0391dmin",
    }
    composites = [v for n, v in VALUES.items() if n.startswith("COMPOSITE_")]
    assert len(composites) == 12
    for value in composites:
        assert all(kind in value for kind in kinds.values()), value
    long = {n: v for n, v in VALUES.items() if len(v) > 10_000}
    assert {"LONG_TOOL", "LONG_ERROR", "LONG_RESOURCE", "LONG_LINE"} <= set(long)


@pytest.mark.parametrize("view", sorted(SHOWS))
def test_a_view_shows_each_hostile_value_its_table_names_exactly_as_recorded_and_where(
    labelled, view
):
    assert what_is_wrong(view, list(labelled[view].values()), list(labelled[view])) == []


#: Every place the table says a value must stand at, and the string a view that loses it there
#: loses.
MUST = [
    pytest.param(view, name, path, place.needle(VALUES[name], path), id=f"{view}-{name}-{path}")
    for view, table in SHOWS.items()
    for name, place in table.items()
    for path in (*place.paths, *place.within)
]


@pytest.mark.parametrize("view, name, path, needle", MUST)
def test_a_view_that_loses_a_value_at_one_of_its_places_is_red_though_it_stands_at_another(
    labelled, view, name, path, needle
):
    envelopes, labels = list(labelled[view].values()), list(labelled[view])
    lost = without(envelopes, needle, path)
    assert lost != envelopes, "the table names a place the view does not fill"
    wrong = what_is_wrong(view, lost, labels)
    assert wrong, f"{view} loses {name} at {path} and stays green"
    assert any(f"does not stand at {path}" in w for w in wrong), wrong


def cases_of(envelopes: dict[str, dict], path: str) -> list[tuple[str, str | None]]:
    """Every envelope and row of the view that the table asks to hold a value at a place."""
    spec = path if isinstance(path, At) else At(path)
    return [
        (label, row)
        for label, envelope in envelopes.items()
        if not spec.on or any(fnmatchcase(label, pattern) for pattern in spec.on)
        for row in rows_of(envelope, spec)
    ]


@pytest.mark.parametrize("view, name, path, needle", MUST)
def test_a_view_that_loses_a_value_in_one_envelope_or_one_row_is_red_though_the_others_hold_it(
    labelled, view, name, path, needle
):
    envelopes, labels = list(labelled[view].values()), list(labelled[view])
    cases = cases_of(labelled[view], path)
    assert cases, "the table asks for no envelope and no row"
    for label, row in cases:
        lost = without_in(envelopes, labels, label, row, needle, path)
        assert lost != envelopes, f"{label} {row}: the table names a place the view does not fill"
        asked = f"{view}: {name} does not stand at {path}: lost in {label}" + (
            f", {row}" if row else ""
        )
        wrong = what_is_wrong(view, lost, labels)
        assert asked in wrong, f"{view} loses {name} at {path} in {label} {row} and stays green"
        assert len(wrong) == 1, f"{wrong}: and nothing else is lost with it"


@pytest.mark.parametrize(
    "view, name, path, label, row",
    [
        # A run view that loses a value for one of its two runs.
        ("run", "CYRILLIC", f"{TOOLS}[0].item.name", "plain", None),
        ("run", "CYRILLIC", f"{TOOLS}[0].item.name", "driven", None),
        ("run", "COMPOSITE_TOOL_NAME", f"{TOOLS}[3].item.name", "plain", None),
        # One row of the runs in the store.
        (
            "store_runs",
            "COMPOSITE_SERVER_NAME",
            "data[*].announced_server",
            "store_runs",
            "data[0]",
        ),
        (
            "store_runs",
            "COMPOSITE_SERVER_NAME",
            "data[*].announced_server",
            "store_runs",
            "data[1]",
        ),
        # The author at one index of a history.
        (
            "triage_history",
            "MARKUP_LINK",
            "data.history[*].author",
            "triage_history",
            "data.history[0]",
        ),
        (
            "triage_history",
            "CYRILLIC",
            "data.history[*].author",
            "triage_history",
            "data.history[1]",
        ),
        (
            "triage_review",
            "MARKUP_LINK",
            "data.history[*].author",
            "hidden_html",
            "data.history[0]",
        ),
        # The customer's name in the handover bundle alone, and one of the two runs' candidates.
        ("bundle", "CYRILLIC", "data.customer_readme.fields.customer_declared", "handover", None),
        ("triage_review", "SCRIPT", CANDIDATES, "hidden_html", "data.sightings[0]"),
        ("triage_review", "SCRIPT", CANDIDATES, "hidden_html", "data.sightings[1]"),
        # One of the two fleets, one of the two entries a fleet compared.
        ("fleet", "COMPOSITE_IMAGE", "data.problems[*]", "first", "data.problems[0]"),
        ("fleets", "COMPOSITE_IMAGE_AFTER", "data[*].problems[*]", "fleets", "data[1]"),
    ],
)
def test_the_losses_a_review_named_are_red_each_in_the_one_envelope_or_row_it_names(
    labelled, view, name, path, label, row
):
    envelopes, labels = list(labelled[view].values()), list(labelled[view])
    needle = SHOWS[view][name].needle(VALUES[name], path)
    lost = without_in(envelopes, labels, label, row, needle, path)
    assert lost != envelopes
    wrong = what_is_wrong(view, lost, labels)
    asked = f"{view}: {name} does not stand at {path}: lost in {label}" + (
        f", {row}" if row else ""
    )
    assert wrong == [asked]


def test_the_envelopes_and_rows_the_tables_ask_are_those_of_the_hostile_run(hostile, labelled):
    """What a table says by index or by field is what the run recorded, and nothing a view that
    loses a row could hide behind."""
    # Both runs of the entry are filed, and each is a row of the store's runs.
    assert len(labelled["store_runs"]["store_runs"]["data"]) == len(hostile.driven) == 2
    # The fleets are listed first and second, as the table says by index.
    rows = labelled["fleets"]["fleets"]["data"]
    assert [row["fleet"] for row in rows] == [hostile.fleet_first, hostile.fleet_second]
    # The composite tool is the second call of the script, and the first of the two that fail.
    plain = events_of(hostile.plain)
    (done,) = [e for e in plain if e["type"] == "script_finished"]
    assert done["called"].index(hostile_server.COMPOSITE_TOOL_NAME) == CALLED_AT[0]
    assert done["failed"].index(hostile_server.COMPOSITE_TOOL_NAME) == FAILED_AT[0]
    # The steps the table asks are the two events of the recording that name the tool.
    steps = labelled["run"]["plain"]["data"]["inventory"]["steps"]
    asked = [n for n, row in enumerate(steps) if of_step_of_the_composite_tool(row)]
    assert [steps[n]["type"] for n in asked] == ["step_called", "call_failed"]
    assert [steps[n]["tool"] for n in asked] == [hostile_server.COMPOSITE_TOOL_NAME] * 2
    # The decision rows: an operator's and a customer's.
    history = labelled["triage_history"]["triage_history"]["data"]["history"]
    assert [row["role"] for row in history] == ["operator", "customer"]
    # A bundle is not a handover: the customer's README is the handover's alone.
    assert labelled["bundle"]["bundle"]["data"]["customer_readme"]["present"] is False
    assert labelled["bundle"]["handover"]["data"]["customer_readme"]["present"] is True
    # The server's error text is in the two errors of the corpus run, none in the scripted run.
    errors = [label for label in labelled["message"] if label.endswith(":error#0")]
    assert errors == ["driven:error#0", "plain:error#0"]


@pytest.mark.parametrize(
    "view, name, path",
    [
        ("store_diff", "COMPOSITE_SERVER_NAME", "data.after.announced_server"),
        ("triage", "CYRILLIC", "data.questions.poison[*].row.author"),
        ("run", "COMPOSITE_SERVER_NAME", "data.overview.server_name_mismatch[*].announced"),
        ("triage_history", "MARKUP_LINK", "data.triage.operator.author"),
        ("triage_history", "MARKUP_LINK", "data.history[*].author"),
    ],
)
def test_the_places_a_review_found_unchecked_are_places_a_value_must_stand_at(view, name, path):
    assert path in SHOWS[view][name].paths


def test_a_value_the_view_shows_and_the_table_does_not_name_is_red(labelled):
    extra = {**SHOWS["run"]}
    del extra["PROMPT_INJECTION"]
    SHOWS["run"], kept = extra, SHOWS["run"]
    try:
        wrong = what_is_wrong("run", list(labelled["run"].values()), list(labelled["run"]))
    finally:
        SHOWS["run"] = kept
    assert any("PROMPT_INJECTION" in w and "the table does not say so" in w for w in wrong)


@pytest.mark.parametrize("view", sorted(SHOWS))
def test_every_envelope_is_json_that_carries_no_character_a_page_could_mistake(shown, view):
    for envelope in shown[view]:
        sent = json.dumps(envelope, ensure_ascii=True, allow_nan=False)
        assert sent.isascii() and sent.isprintable(), "ensure_ascii: no raw control or bidi"
        assert json.loads(sent) == envelope, "what the page parses is what the view made"


def events_of(recording: Path) -> list[dict]:
    return [json.loads(line) for line in recording.read_text().splitlines() if line.strip()]


def tools_message(recording: Path) -> dict:
    """The ``result`` of the ``tools/list`` answer in a recording."""
    return next(
        e["payload"]["data"]["result"]
        for e in events_of(recording)
        if e["type"] == "message" and "tools" in (e["payload"]["data"].get("result") or {})
    )


def test_a_message_is_shown_whole_as_recorded_with_its_dotted_keys_beside_their_twins(hostile):
    src = hostile.sources
    for recording in (hostile.driven[0], hostile.plain):
        for event in (e for e in events_of(recording) if e["type"] == "message"):
            shown = views.message(src, hostile.ref(recording), event["seq"])["data"]["message"]
            assert shown["payload"]["data"] == event["payload"]["data"]
    listing = tools_message(hostile.plain)
    assert list(listing)[:2] == ["tools[0].description", "tools"], "both keys, the dotted first"
    assert listing["tools"][0]["description"] == hostile_server.SCRIPT
    assert listing["tools[0].description"] == hostile_server.DOTTED_SIDE


def test_a_run_shows_the_listings_and_the_findings_it_recorded_unchanged(hostile):
    for recording in (hostile.driven[0], hostile.plain):
        events = events_of(recording)
        data = views.run(hostile.sources, hostile.ref(recording))["data"]
        items = data["inventory"]["listings"]["tools"]["items"]
        assert [i["item"] for i in items] == tools_message(recording)["tools"]
        # The view adds the class of each finding, derived from its signal and never recorded.
        shown = [{**e} for e in data["findings"]["findings"]]
        classes = [e.pop("finding_class") for e in shown]
        recorded = [e for e in events if e["type"] == "finding"]
        assert shown == recorded
        assert classes == [
            finding_classes.class_of("signal", e["key"]["signal"]).to_dict() for e in recorded
        ]
        assert data["findings"]["observations"] == [e for e in events if e["type"] == "observation"]


def test_a_finding_is_shown_with_the_path_it_fired_on_and_the_item_it_is_in(hostile):
    data = views.run(hostile.sources, hostile.ref(hostile.driven[0]))["data"]
    items = data["inventory"]["listings"]["tools"]["items"]
    paths = {(i["path"], f["path"]) for i in items for f in i["findings"]}
    assert ("result.tools[0]", "result.tools[0].description") in paths
    assert ("result.tools[2]", "result.tools[2].description") in paths
    assert ("result.tools[0]", "result.tools[0].name") in paths


def locator_names(locator: str) -> list[str]:
    """The names a locator selects by: JSON string literals, as the store files them."""
    return [json.loads(m) for m in re.findall(r'\[name=("(?:[^"\\]|\\.)*")\]', locator)]


def test_a_locator_names_the_hostile_tool_as_the_store_filed_it(shown):
    names = set()
    for envelope in (*shown["store_findings"], *shown["triage"], *shown["triage_review"]):
        for path, text in walk(envelope):
            if path.endswith("locator"):
                names.update(locator_names(text))
                assert text.isascii(), "spelled in ASCII: nothing to reorder the page"
    assert names == {
        hostile_server.CYRILLIC,
        hostile_server.COMPOSITE_TOOL_NAME,
        "paypal",
        "plain-tool",
        "summarise",
    }


def test_the_ambiguous_path_is_ambiguous_with_every_candidate_in_review_mode(hostile):
    for finding, signal, wanted in (
        (hostile.finding, "hidden_html", {hostile_server.SCRIPT, hostile_server.DOTTED_SIDE}),
        (
            hostile.prompt_finding,
            "instruction_override",
            {hostile_server.PROMPT_INJECTION, hostile_server.DOTTED_SIDE_AFTER},
        ),
    ):
        data = views.triage_review(hostile.sources, finding)["data"]
        assert data["key"]["signal"] == signal
        assert len(data["sightings"]) == 2, "both runs are complete"
        for sighting in data["sightings"]:
            assert sighting["recording_status"] == "found"
            (place,) = sighting["places"]
            assert place["text_status"] == "ambiguous"
            assert place["text"] is None, "none is picked as what the signal fired on"
            assert set(place["candidates"]) == wanted
            assert len(place["candidates"]) == 2
            assert place["candidates_capped"] is False
            assert re.fullmatch(r"result\.(tools|prompts)\[0\]\.description", place["path"])


def test_review_mode_names_where_a_finding_fired_and_shows_no_other_finding(hostile):
    envelope = views.triage_review(hostile.sources, hostile.finding)
    data = envelope["data"]
    assert data["finding"] == hostile.finding
    assert hostile_server.PROMPT_INJECTION not in json.dumps(envelope), "another entry's"
    seqs = {e["seq"] for e in events_of(hostile.driven[0]) if e["type"] == "message"}
    assert {p["message_seq"] for s in data["sightings"] for p in s["places"]} <= seqs
    assert data["triage"]["operator"]["author"] == OPERATOR_AUTHOR
    assert data["triage"]["customer"]["author"] == CUSTOMER_AUTHOR


def test_a_url_in_the_data_stays_text(shown):
    for view, envelopes in shown.items():
        for envelope in envelopes:
            for path, text in walk(envelope):
                if hostile_server.URL in text:
                    assert path.rsplit(".", 1)[-1] in {"title", "description"}, f"{view}: {path}"
                assert path.rsplit(".", 1)[-1] not in {"href", "url", "link"}, f"{view}: {path}"


def test_a_bundle_serves_the_recording_as_recorded_and_an_attestation_as_written(hostile):
    src = hostile.sources
    entries = views.bundle(src, 0)["data"]["files_by_role"]["recording"]
    assert len(entries) == 2 and all(e["download"] for e in entries)
    for entry in entries:
        served = views.bundle_file(src, 0, entry["path"])
        recorded = (hostile.bundle / entry["path"]).read_bytes()
        assert served.body == recorded
        assert hostile_server.LONG_LINE in json.dumps(recorded.decode(), ensure_ascii=False)
    assert views.attestation_file(src, 0).body == hostile.attestation.read_bytes()


def test_two_fleets_of_the_hostile_server_are_listed_shown_and_compared(hostile):
    src = hostile.fleet_sources
    rows = {row["fleet"]: row for row in views.fleets(src)["data"]}
    assert list(rows) == [hostile.fleet_first, hostile.fleet_second]
    assert all(row["fleet_json"]["state"] == "incomplete" for row in rows.values())

    envelope = views.fleet(src, hostile.fleet_second)
    results = {r["entry"]: r for r in envelope["data"]["results"]}
    assert set(results) == {"hostile-server", "reference-server", "broken-server"}
    assert results["hostile-server"]["state"] == verdict.COMPLETE
    assert results["broken-server"]["state"] == "refused"
    assert results["broken-server"]["problems"] == [FLEET_ONLY["COMPOSITE_STDERR"]]
    on_disk = json.loads((hostile.fleet_runs / hostile.fleet_second / "fleet.json").read_text())
    assert envelope["data"]["findings"] == on_disk["findings"]

    compared = views.fleet_compare(src, None, None)["data"]
    assert (compared["before"], compared["after"]) == (hostile.fleet_first, hostile.fleet_second)
    entries = {e["entry"]: e for e in compared["entries"]}
    gone = entries["hostile-server"]["gone"]
    assert [g["identity"]["signal"] for g in gone] == ["embedded_url"], "what the second lost"
    assert entries["broken-server"]["change"] == "not_comparable"
    assert entries["hostile-server"]["axes"]["environment"]["moved"] is True


def test_the_fleets_hold_the_runs_of_the_server_itself_and_show_the_places_it_made_findings_on(
    hostile,
):
    """The hostile entry of a fleet is driven, not made up: its recording is the server's own
    (its announced name, its tool names, a line over 10 000 characters), and the fleet shows the
    locators of its findings as the run recorded them. A fleet shows no other text of the
    server: its views carry identities, counts and states (the table above says what else)."""
    src = hostile.fleet_sources
    for fleet_id in (hostile.fleet_first, hostile.fleet_second):
        (recording,) = hostile.fleet_runs.glob(f"{fleet_id}/*-hostile-server/*/events.jsonl")
        text = recording.read_text()
        for name in ("COMPOSITE_SERVER_NAME", "COMPOSITE_TOOL_NAME", "LONG_TOOL", "LONG_LINE"):
            assert json.dumps(VALUES[name])[1:-1] in text, name
        recorded = {e["key"]["locator"] for e in events_of(recording) if e["type"] == "finding"}
        envelope = views.fleet(src, fleet_id)
        shown = {
            text
            for path, text in walk(envelope)
            if re.fullmatch(r"data\.findings\.poison\[\d+\]\.key\[\d+\]", path)
        }
        assert recorded and recorded <= shown, "every locator the run recorded, as recorded"
        assert hostile_server.COMPOSITE_TOOL_NAME in {
            n for locator in recorded for n in locator_names(locator)
        }


# -- app.js, read as text -------------------------------------------------------------------------

APP = APP_JS.read_text()


def body_of(source: str, signature: str) -> tuple[int, int]:
    """Where the function that starts with ``signature`` begins and ends (matching braces; none
    of the page's functions named here holds a brace in a string)."""
    start = source.index(signature)
    depth, at = 0, source.index("{", start)
    for end in range(at, len(source)):
        depth += {"{": 1, "}": -1}.get(source[end], 0)
        if depth == 0:
            return start, end + 1
    raise AssertionError(signature)


#: Words after which a ``/`` begins a regular expression and is no division.
BEFORE_REGEX = {
    "return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do",
    "yield", "await",
}  # fmt: skip


def strip_comments(source: str) -> str:
    """The source with every comment replaced by one blank. String literals, template literals
    (with their ``${...}``, which hold code and so may hold comments) and regular expression
    literals are skipped over, so that a ``//`` or ``/*`` in one of them is no comment. A ``/`` is
    a regular expression after an operator, an opening bracket, a separator or one of
    ``BEFORE_REGEX``, and a division after a name, a number or a closing bracket. Raises
    ``ValueError`` for what does not end (a string, a template, a comment, a regular expression)."""
    text, _ = _code(source, 0, nested=False)
    return text


def _code(src: str, at: int, *, nested: bool) -> tuple[str, int]:
    out: list[str] = []
    depth, last = 0, ""
    while at < len(src):
        char = src[at]
        if src.startswith("//", at):
            end = src.find("\n", at)
            out.append(" ")
            at = len(src) if end < 0 else end
        elif src.startswith("/*", at):
            end = src.find("*/", at + 2)
            if end < 0:
                raise ValueError(f"a comment that does not end, at {at}")
            out.append(" ")
            at = end + 2
        elif char in "'\"":
            end = _string(src, at)
            out.append(src[at:end])
            at, last = end, "x"
        elif char == "`":
            piece, end = _template(src, at)
            out.append(piece)
            at, last = end, "x"
        elif char == "/" and (last == "" or last in "(,=:[!&|?{};+-*%<>~^" or last in BEFORE_REGEX):
            end = _regex(src, at)
            out.append(src[at:end])
            at, last = end, "x"
        elif char.isalnum() or char in "_$":
            end = at
            while end < len(src) and (src[end].isalnum() or src[end] in "_$"):
                end += 1
            out.append(src[at:end])
            at, last = end, src[at:end]
        else:
            if nested and char == "{":
                depth += 1
            elif nested and char == "}":
                if depth == 0:
                    return "".join(out), at
                depth -= 1
            out.append(char)
            at += 1
            if not char.isspace():
                last = char
    if nested:
        raise ValueError("a ${ that does not end")
    return "".join(out), at


def _string(src: str, at: int) -> int:
    quote, end = src[at], at + 1
    while end < len(src):
        if src[end] == "\\":
            end += 2
        elif src[end] == quote:
            return end + 1
        elif src[end] == "\n":
            break
        else:
            end += 1
    raise ValueError(f"a string that does not end, at {at}")


def _template(src: str, at: int) -> tuple[str, int]:
    out, end = ["`"], at + 1
    while end < len(src):
        if src[end] == "\\":
            out.append(src[end : end + 2])
            end += 2
        elif src[end] == "`":
            out.append("`")
            return "".join(out), end + 1
        elif src.startswith("${", end):
            piece, close = _code(src, end + 2, nested=True)
            out.append("${" + piece + "}")
            end = close + 1
        else:
            out.append(src[end])
            end += 1
    raise ValueError(f"a template that does not end, at {at}")


def _regex(src: str, at: int) -> int:
    end, in_class = at + 1, False
    while end < len(src) and src[end] != "\n":
        char = src[end]
        if char == "\\":
            end += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            end += 1
            while end < len(src) and src[end].isalpha():
                end += 1
            return end
        end += 1
    raise ValueError(f"a regular expression that does not end, at {at}")


# A heuristic: patterns over the text of app.js. A name put together at run time, a reference
# held in a variable, or a form nobody thought of can get past them. What gives the guarantee is
# the DOM check of the headless run (CONTRACT section 10), which sees every attribute and every
# node of the finished page. These patterns catch the slips and the forms a review thought of,
# early and without a browser.
#: What a computed access follows: a name that is not a keyword, ``)`` or ``]``, then blanks
#: and ``?.`` as the language allows before ``[``.
AFTER_EXPRESSION = (
    r"(?:(?<![\w$])(?!(?:return|typeof|in|of|case|else|yield|await|void|delete|throw|new"
    r"|instanceof|do)\b)[\w$]+|[)\]])\s*(?:\?\.\s*)?"
)
#: A property no one may write, as the last name of a target: an ARIA reflection, ``dataset``, an
#: element's ``title``, an ``on*`` property.
WRITTEN = r"\.\s*(?:aria[A-Z]\w*|dataset|title|on\w+)\b"
#: Such a target in a destructuring: one bracket pair (``[``/``]`` or ``{``/``}``) with the target
#: in it, closed, and then (after the closing brackets of an outer pattern) ``=`` or ``of``/``in``:
#: ``[el.ariaPressed] = [...]``, ``({ v: main.dataset.ready } = o)``, ``for ([el.title] of rows)``.
#: A pattern of a declaration (``const [a, b] = pair``) names no property, so it has no ``.``; a
#: list or an object that is read (``[x.title, y.title]``, ``{ t: x.title }``) is not followed by
#: ``=``, which is the form without a hit in app.js. A target after a nested bracket pair
#: (``[[a], el.title] = x``) is not found: a regular expression does not count brackets.
DESTRUCTURING = (
    r"[\[{][^\[\]{}]*" + WRITTEN + r"[^\[\]{}]*[\]}](?:\s*[\]}])*\s*(?:=(?![=>])|\b(?:of|in)\b)"
)
#: An assignment to what precedes: ``=`` and the compound forms (``+=``, ``??=``, ``||=``, ...),
#: not a comparison and not an arrow.
ASSIGN = r"\s*(?:\?\?|&&|\|\||\*\*|>>>|<<|>>|[-+*/%&|^])?=(?![=>])"
FORBIDDEN = [
    ("innerHTML", r"\binnerHTML\b"),
    ("outerHTML", r"\bouterHTML\b"),
    ("insertAdjacentHTML", r"\binsertAdjacentHTML\b"),
    ("document.write", r"\bdocument\s*\.\s*write(ln)?\b"),
    ("createContextualFragment", r"\bcreateContextualFragment\b"),
    ("DOMParser", r"\bDOMParser\b"),
    ("srcdoc", r"\bsrcdoc\b"),
    ("eval(", r"(?<![\w.])eval\s*\("),
    ("new Function", r"\bnew\s+Function\b|(?<![\w.])Function\s*\("),
    ("setTimeout with a string", r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]"),
    ("setTimeout with a name", r"\bset(?:Timeout|Interval)\s*\(\s*[a-z]\w*\s*[,)]"),
    (".style", r"\.style\b"),
    ("cssText", r"\bcssText\b"),
    ("setAttribute('style'", r"setAttribute\s*\(\s*['\"`]style"),
    ("setAttribute('title'", r"setAttribute\s*\(\s*['\"`]title"),
    ("an element's title", r"(?<!document)\.title" + ASSIGN),
    ("an on* property", r"\.on[a-z]+" + ASSIGN),
    ("ARIA reflection", r"\.aria[A-Z]\w*" + ASSIGN),
    ("an ARIA reflection property in an object", r"\baria[A-Z]\w*\s*:"),
    ("a dataset written", r"\bdataset\s*(?:(?:\?\.|\.)\s*\w+|(?:\?\.\s*)?\[[^\]]*\])" + ASSIGN),
    ("a dataset handed on", r"\bdataset\s*[,)]"),
    ("an access by a string", AFTER_EXPRESSION + r"\[\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`)"),
    ("an access by a name put together", AFTER_EXPRESSION + r"\[(?=[^\]\n]*['\"`])[^\]\n]*\+"),
    ("Reflect", r"\bReflect\s*\."),
    ("a destructuring into a property", DESTRUCTURING),
    ("defineProperty or defineProperties", r"\bdefineProperty\b|\bdefineProperties\b"),
    (
        "Object.assign on anything but a new object",
        r"\bObject\s*\.\s*assign\s*\(\s*(?!\{\s*\}\s*,)",
    ),
    ("['title']", r"\[\s*['\"`]title['\"`]\s*\]"),
    (
        "another way to set an attribute",
        r"\b(?:setAttributeNS|setAttributeNode|toggleAttribute|setNamedItem)\b",
    ),
]

#: Accesses by a string that app.js has: a key with a hyphen of a plain object read from the
#: data, never an element or ``document``. Each is taken out of the text before the patterns
#: run, and each must still be there (a stale entry is red).
EXEMPT = {
    "dc['real-world']": "the disclosure candidates' count, a key of the fleet's JSON",
    "questions['real-world']": "the open questions of one provenance, a key of the triage JSON",
}


def checked_text() -> str:
    """app.js without its comments (a comment between a name and ``=`` hides a slip from every
    pattern), and without the exempt accesses."""
    text = strip_comments(APP)
    for snippet in EXEMPT:
        assert snippet in text, f"{snippet} is no longer in app.js: take it out of EXEMPT"
        text = text.replace(snippet, "")
    return text


@pytest.mark.parametrize("name, pattern", FORBIDDEN, ids=[n for n, _ in FORBIDDEN])
def test_app_js_has_no_way_to_turn_data_into_markup_or_code(name, pattern):
    text = checked_text()
    found = re.search(pattern, text)
    line = text.count("\n", 0, found.start()) + 1 if found else 0
    assert not found, f"{name} at line {line} of app.js, the exempt ones left out (CONTRACT 5)"


#: Forms that must be found: the ones a review showed getting past, and the plain ones.
SLIPS = [
    "el['inner' + 'HTML'] = x",
    'el["inner" + "HTML"] = x',
    "el[`inner` + 'HTML'] = x",
    "el[part + 'HTML'] = x",
    "Reflect.set(el, 'outer' + 'HTML', x)",
    "document['wri' + 'te'](x)",
    "el['title'] = x",
    'el["title"] = x',
    "Object.assign(el, { title: x })",
    "Object.assign(document.body, props)",
    "el.innerHTML = x",
    "el.ariaPressed = 'true'",
    "main.dataset.ready = '1'",
    "main.dataset['ready'] = '1'",
    "Object.assign(main.dataset, x)",
    "el.setAttributeNS(null, 'title', x)",
    "el ['inner' + 'HTML'] = x",
    "document ['wri' + 'te'](x)",
    "el?.['inner' + 'HTML'] = x",
    "el ?. ['inner' + 'HTML'] = x",
    "el.ariaPressed ??= 'true'",
    "el.ariaExpanded ||= 'true'",
    "el.ariaBusy &&= 'true'",
    "el.ariaCurrent += 'page'",
    "main.dataset.ready ||= '1'",
    "main.dataset.ready ??= '1'",
    "main.dataset?.ready = '1'",
    "main.dataset ['ready'] = '1'",
    "main.dataset?.['ready'] ??= '1'",
    "el.onclick ||= f",
    "el.title ??= x",
    "el.ariaPressed /* x */ = 'true'",
    "main.dataset.ready /**/ ||= '1'",
    "el.onclick /**/ = f",
    "el.title /**/ = x",
    "el/**/['inner' + 'HTML'] = x",
    "el.ariaPressed // x\n = 'true'",
    "[el.ariaPressed] = ['true']",
    "({ v: main.dataset.ready } = o)",
    "[a, el.title] = pair",
    "[el.onclick, el.onload] = [f, g]",
    "({ a: { b: el.title } } = o)",
    "for ([el.title] of rows) f()",
    "for ({ t: el.title } of rows) f()",
    "Object.defineProperty(el, 'ariaPressed', { value: 'true' })",
    "Object.defineProperties(el, { title: { value: x } })",
    "Reflect.defineProperty(el, 'title', { value: x })",
]


@pytest.mark.parametrize("slip", SLIPS)
def test_the_patterns_find_every_form_a_review_showed_getting_past(slip):
    text = strip_comments(slip)
    assert [n for n, pattern in FORBIDDEN if re.search(pattern, text)], slip


@pytest.mark.parametrize(
    "source, stripped",
    [
        ("a // b\nc", "a  \nc"),
        ("a/* x */b", "a b"),
        ("a /* x\ny */ b", "a   b"),
        ("a /**/ = b", "a   = b"),
        ("'//x' + \"/*y*/\" // z", "'//x' + \"/*y*/\"  "),
        ("'it\\'s // here' // gone", "'it\\'s // here'  "),
        ("`a // b ${ x /* c */ } d`", "`a // b ${ x   } d`"),
        ("`a ${ `b ${ 1 // c\n} /* d */` } e`", "`a ${ `b ${ 1  \n} /* d */` } e`"),
        ("`a \\` // b`", "`a \\` // b`"),
        ("`x ${ {a: 1}.a } // y` // z", "`x ${ {a: 1}.a } // y`  "),
        ("x.replace(/[\"'`]/g, '') // c", "x.replace(/[\"'`]/g, '')  "),
        ("/a[//]b\\//.test(s) // c", "/a[//]b\\//.test(s)  "),
        ("return /a\\/*b/ // c", "return /a\\/*b/  "),
        ("a / b / c // d", "a / b / c  "),
        ("(a) / 2 + b[0] / 3 // d", "(a) / 2 + b[0] / 3  "),
        ("x = a ? /\"/ : 'b' // c", "x = a ? /\"/ : 'b'  "),
        ("no comment at all", "no comment at all"),
    ],
)
def test_the_scanner_replaces_each_comment_by_one_blank_and_nothing_else(source, stripped):
    assert strip_comments(source) == stripped
    assert strip_comments(stripped) == stripped


@pytest.mark.parametrize(
    "source",
    ["a /* b", "'abc", "'abc\ndef'", "`abc", "`a ${ b", "x = /ab\n/", "`a ${ 'b } `"],
)
def test_the_scanner_refuses_what_does_not_end(source):
    with pytest.raises(ValueError):
        strip_comments(source)


def test_the_scanner_reads_app_js_to_its_end_and_leaves_no_comment_in_it():
    stripped = strip_comments(APP)
    assert "/*" not in stripped and "*/" not in stripped
    assert len(stripped) < len(APP) * 0.95, "the comments of the page are gone"
    # The code is all there: every line after the block comment that opens the file that is no
    # comment and holds no trailing one.
    lines = APP.split("*/", 1)[1].splitlines()
    code = [line for line in lines if line.strip() and not re.search(r"//|/\*|\*/", line)]
    assert len(code) > 1500
    assert all(line in stripped for line in code)
    # A regular expression that holds a comment mark or a quote is no comment and no string.
    assert "/^(tab|listing):(.+)$/" in stripped


def test_the_patterns_pass_what_app_js_does_with_things_that_are_not_elements():
    for fine in (
        "Object.assign({}, wrapped.event, { message_seq: 1 })",
        "rows[i + 1]",
        "const a = ['x', 'y']",
        "return ['x']",
        "f([ 'x' ])",
        "x = cond ? ['a'] : ['b']",
        "tr.dataset_row = 1",
        "return ['x']",
        "return  [ 'x' ]",
        "for (const x of ['a', 'b']) f(x)",
        "x = a ? ['b'] : ['c']",
        "if (el.ariaPressed == 'true') f()",
        "if (el.ariaPressed === 'true' || el.ariaPressed != 'x') f()",
        "if (main.dataset.ready === '1') f()",
        "const f = (a) => a.dataset_x",
        "n >= 2 && m <= 3",
        "const [a, b] = pair",
        "const [a, b] = [x.title, y.title]",
        "const o = { t: x.title, d: y.dataset }",
        "if ([a.title].length) f()",
        "for (const [k, v] of Object.entries(o)) f(k, v)",
        "const { a, b: [c] } = o",
        "const o = { onclick: 1 } // in a comment: el.title = x",
        "x = a /* el.title = 1 */ + b",
    ):
        text = strip_comments(fine)
        assert not [n for n, pattern in FORBIDDEN if re.search(pattern, text)], fine


def test_the_exempt_accesses_are_plain_data_objects():
    for snippet in EXEMPT:
        line = next(line for line in APP.splitlines() if snippet in line)
        assert not re.search(r"\b(?:el|node|document|main|button|tr|td|a)\[", line), line


def test_title_is_no_attribute_h_sets():
    start, end = body_of(APP, "const SAFE_ATTRS")
    assert "title" not in APP[start:end]
    calls = re.findall(r"\bh\(\s*'[a-z0-9]+'\s*,\s*\{([^{}]*)\}", APP)
    assert len(calls) > 100, "the pattern still finds the page's h() calls"
    assert not [c for c in calls if re.search(r"(?:^|[,\s])['\"]?title['\"]?\s*:", c)]
    h_start, h_end = body_of(APP, "function h(")
    assert "SAFE_ATTRS.has(k)" in APP[h_start:h_end], "h() still checks its allowlist"
    assert "startsWith('#/')" in APP[h_start:h_end], "and a link is a route of this page"


def test_every_set_attribute_is_in_h_download_link_or_set_state():
    rest = APP
    for signature in ("function downloadLink(", "function setState(", "function h("):
        start, end = body_of(rest, signature)
        rest = rest[:start] + rest[end:]
    assert "setAttribute" not in rest, "an attribute is set outside h(), downloadLink(), setState()"
    start, end = body_of(APP, "function downloadLink(")
    assert "path !== 'bundle/file'" in APP[start:end], "downloadLink() names its two routes"


def test_set_state_takes_five_names_and_the_pages_own_values_and_throws_on_anything_else():
    start, end = body_of(APP, "function setState(")
    body = APP[start:end]
    assert "throw new Error(" in body
    assert body.count("el.setAttribute(name, value)") == 1
    table = re.search(r"const STATE_VALUES = new Map\(\[(.*?)\]\);", APP, re.S).group(1)
    values = {
        name: re.findall(r"'(\w+)'", listed)
        for name, listed in re.findall(r"\['(aria-[a-z]+)', \[([^\]]*)\]\]", table)
    }
    assert values == {
        "aria-pressed": ["true", "false"],
        "aria-expanded": ["true", "false"],
        "aria-busy": ["true", "false"],
        "aria-current": ["page"],
    }
    assert "name === 'data-ready' && /^[0-9]{1,9}$/.test(value)" in body


def test_the_five_states_the_page_keeps_are_set_through_set_state_with_constants():
    start, end = body_of(APP, "function setState(")
    rest = APP[:start] + APP[end:]
    calls = re.findall(
        r"\bsetState\(([^,()]+(?:\([^)]*\))?[^,()]*),\s*('[a-z-]+'),\s*([^;]*?)\);", rest
    )
    assert {name for _el, name, _value in calls} == {
        "'aria-pressed'",
        "'aria-expanded'",
        "'aria-current'",
        "'aria-busy'",
        "'data-ready'",
    }
    assert len(calls) == rest.count("setState("), "every call is read"
    for _el, name, value in calls:
        if name == "'data-ready'":
            assert value == "String(gen)", value
        else:
            assert any(re.fullmatch(p, value) for p in ALLOWED_VALUES[:2]), value


def expression_after(source: str, at: int) -> str:
    """The value expression that starts at ``at``: up to the first ``,`` or ``}`` outside
    parentheses and quotes."""
    depth, quote = 0, ""
    for end in range(at, len(source)):
        c = source[end]
        if quote:
            quote = "" if c == quote and source[end - 1] != "\\" else quote
        elif c in "'\"`":
            quote = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and c in ",}":
            return source[at:end].strip()
    raise AssertionError(at)


#: What an aria-*, data-* or value attribute may be given: a literal, a choice between
#: literals, the page's own table consulted (a key of it, or 'other'), a row's index, or the
#: whole of ``visText(<name or chain of properties>)`` and nothing joined to it.
LITERAL = r"'(?:[^'\\]|\\.)*'"
ALLOWED_VALUES = [
    LITERAL,
    rf".+?\?\s*(?:{LITERAL}|null)\s*:\s*(?:{LITERAL}|null)",
    r"own\(\w+, [\w.]+\) \? [\w.]+ : 'other'",
    r"String\(i\)",
    r"visText\(\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\)",
]
ATTRIBUTE_VALUE = r"""['"](?:aria|data)-[a-z]+['"]\s*:\s*|h\('option',\s*\{\s*value\s*:\s*"""


def values_not_allowed(source: str) -> list[str]:
    """The values given to an aria-*, data-* or option value attribute that are none of
    :data:`ALLOWED_VALUES`."""
    found = [expression_after(source, m.end()) for m in re.finditer(ATTRIBUTE_VALUE, source)]
    return [e for e in found if not any(re.fullmatch(p, e) for p in ALLOWED_VALUES)]


def test_a_value_from_the_data_in_an_aria_data_or_value_attribute_is_written_with_tokens():
    assert re.search(r"function visText\(value\)", APP), "the function that writes the tokens"
    assert re.search(r"return String\(value\)\.replace\(UNSAFE_ALL,", APP)
    assert "'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')" in APP
    assert len(re.findall(ATTRIBUTE_VALUE, APP)) > 10, (
        "the pattern still finds the page's attributes"
    )
    assert values_not_allowed(APP) == []


#: Lines that are wrong on purpose: data joined to what visText() made, or more than a name in
#: it. Each must be reported.
WRONG_VALUES = [
    "visText(r.a) + String(r.b)",
    "visText(r.a) + r.b",
    "String(r.b) + visText(r.a)",
    "'x' + visText(r.a)",
    "visText(r.a) || r.b",
    "visText(r.a, r.b)",
    "visText(f(r.a))",
    "visText(r.a + r.b)",
    "visText(r.a + 'x')",
    "visText(r.a[0])",
    "visText(r.a).slice(1)",
    "visText(r.a) + visText(r.b)",
    "visText()",
    "r.name",
    "String(r.b)",
    "'x' + r.b",
    "`x${r.b}`",
]


@pytest.mark.parametrize("wrong", WRONG_VALUES)
@pytest.mark.parametrize(
    "line",
    [
        "h('td', { 'aria-label': VALUE })",
        "h('td', { class: 'x', 'data-id': VALUE, id: 'y' })",
        "h('option', { value: VALUE }, label)",
    ],
)
def test_a_value_with_data_joined_to_visText_is_reported(line, wrong):
    assert values_not_allowed(line.replace("VALUE", wrong)) == [wrong], line


@pytest.mark.parametrize(
    "fine", ["visText(r.name)", "visText(name)", "visText(a.b.c)", "visText( r.name )", "'x'"]
)
def test_a_value_that_is_all_visText_of_a_name_or_a_literal_is_allowed(fine):
    assert values_not_allowed(f"h('td', {{ 'aria-label': {fine} }})") == []


def test_the_title_of_the_page_and_the_options_of_a_picker_are_written_with_tokens():
    assert "document.title = (PACKAGE ? visText(PACKAGE)" in APP
    for picker in ("function diffPicker(", "function fleetPicker("):
        start, end = body_of(APP, picker)
        text = APP[start:end]
        assert "visText(" in text and "String(i)" in text, picker
        assert "value: r." not in text, "no value of the data is an option's value"
    start, end = body_of(APP, "function chosen(")
    assert "rows[Number(index)]" in APP[start:end]


def test_h_is_called_with_the_name_of_an_element_the_page_wrote():
    first = re.findall(r"(?<![\w.])h\(\s*([^,)]+)", APP)
    assert len([c for c in first if c.startswith("'")]) > 100
    assert all(re.fullmatch(r"'[a-z0-9]+'|tag", c) for c in first)
    assert set(re.findall(r"createElement\(([^)]*)\)", APP)) == {"'span'", "tag", "'a'"}


def test_the_page_names_its_icon_so_a_browser_does_not_ask_for_favicon_ico():
    # The browser asks for /favicon.ico unless the page names an icon; the answer is a 404,
    # which it writes to the console as an error. The icon is a file of the page's own.
    index = (STATIC / "index.html").read_text()
    (icon,) = re.findall(r'<link rel="icon" href="([\w.-]+)"', index)
    assert (STATIC / icon).is_file() and not (STATIC / icon).is_symlink()
    assert icon.endswith(".svg") and "<script" not in (STATIC / icon).read_text()


def test_a_download_link_sets_its_href_and_no_other_attribute():
    # The browser run found `download` on it: not an attribute the page may set (CONTRACT
    # section 5). The server's Content-Disposition: attachment makes the download.
    start, end = body_of(APP, "function downloadLink(")
    assert re.findall(r"setAttribute\('([^']+)'", APP[start:end]) == ["href"]


def test_json_is_written_by_the_page_so_that_its_strings_carry_tokens():
    # JSON.stringify writes a control character as \u0007, text and not the page's token.
    assert "JSON.stringify(" not in APP
    for signature in ("function jsonText(", "function jsonBlock(", "function asText("):
        start, end = body_of(APP, signature)
        assert "jsonOf(" in APP[start:end], signature
    start, end = body_of(APP, "function jsonOf(")
    assert "vis(" not in APP[start:end], "vis() writes the tokens, on the string it is given"
    start, end = body_of(APP, "function jsonBlock(")
    assert "vis(text, true)" in APP[start:end]


@pytest.mark.parametrize(
    "signature, field",
    [
        ("function storeEngagement(", "file_declared"),
        ("function runInfoBox(", "announced_server"),
        ("async function pageFleets(", "r.problems"),
    ],
)
def test_the_page_shows_a_field_the_browser_run_found_it_left_out(signature, field):
    # Each is in the hostile table (SHOWS) for a view, and was not on the page that shows it.
    start, end = body_of(APP, signature)
    assert field in APP[start:end]


def test_no_name_is_declared_twice_at_the_top_of_the_page_s_code():
    # The first run in a browser found `let generation` beside `function generation`: one
    # SyntaxError, and no view was ever drawn. A parser refuses it; this reads the same slip.
    declared = r"^  (?:async function|function|const|let|var)\s+([A-Za-z_$][\w$]*)"
    names = re.findall(declared, APP, re.M)
    assert len(names) > 150, "the pattern still finds the declarations of the page"
    assert sorted({n for n in names if names.count(n) > 1}) == []


# -- check.py, without a browser ------------------------------------------------------------------


def headless_check():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "headless_check", FIXTURES / "headless" / "check.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_page_may_ask_for_its_own_origin_only_and_not_for_the_other_interface():
    permitted = headless_check().permitted
    main, fleets = "http://127.0.0.1:41001", "http://127.0.0.1:41002"
    assert permitted(main + "/api/about", main)
    assert permitted(fleets + "/app.js", fleets)
    # The page of one interface asking the other: both are the tool's, and only one is open.
    assert not permitted(fleets + "/api/about", main)
    assert not permitted(main + "/api/about", fleets)
    assert not permitted("http://127.0.0.1:41003/", main)
    assert not permitted("https://127.0.0.1:41001/", main)
    assert not permitted("http://127.0.0.1:41001.example/", main)
    assert not permitted("http://example.com/", main)
    assert not permitted(main + "/", None), "no page loaded, nothing may go"


def test_a_page_may_ask_for_no_address_without_a_host():
    # What permitted() says today of an address that names no host: no.
    permitted = headless_check().permitted
    main = "http://127.0.0.1:41001"
    assert permitted(main, main)
    assert not permitted("http://127.0.0.1:41002/", main), "the same host, another port"
    assert not permitted("data:text/html,x", main)
    assert not permitted(f"blob:{main}/0b1c", main)
    assert not permitted("about:blank", main)


def test_a_fault_on_leaving_ends_nothing_and_the_address_stands_as_not_paused():
    check = headless_check()
    subject = object.__new__(check.Check)
    subject.report = {"left": []}
    subject.current = "main"
    subject.interfaces = {"main": type("Interface", (), {"origin": "http://127.0.0.1:41001"})()}

    def fault(url):
        raise SystemExit(f"Chromium did not answer Page.navigate for {url}")

    subject.chromium = type("Chromium", (), {"leave": staticmethod(fault)})()
    subject.leave("{main}/")
    subject.leave("{nobody}/")
    assert subject.report["left"] == [
        {"url": "http://127.0.0.1:41001/", "paused": False, "failed": False},
        {"url": "{nobody}/", "paused": False, "failed": False},
    ]
    assert subject.current is None


def test_an_address_of_leave_is_normalised_as_chromium_asks_for_it():
    normalised = headless_check().normalised
    fleets = "http://127.0.0.1:41002"
    assert normalised(fleets) == fleets + "/"
    for written in (
        "http://elsewhere.example",
        "http://Elsewhere.example/",
        "HTTP://elsewhere.example:80/",
        "http://elsewhere.example/#fragment",
    ):
        assert normalised(written) == "http://elsewhere.example/", written
    assert normalised("https://x:443") == "https://x/"
    assert normalised("http://x:443/") == "http://x:443/", "443 is the default of https only"
    assert normalised("http://x:8080/") != normalised("http://x/")
    assert normalised("https://x:80/") != normalised("https://x/")
    assert normalised("http://x/a/B?q=C") == "http://x/a/B?q=C", "no character to encode"


def test_an_address_of_leave_is_encoded_as_chromium_asks_for_it():
    normalised = headless_check().normalised
    assert normalised("http://x/{main}/y") == "http://x/%7Bmain%7D/y"
    assert normalised("http://x/a b/ä") == "http://x/a%20b/%C3%A4"
    assert normalised("http://x/%7Bmain%7D/a%20b") == "http://x/%7Bmain%7D/a%20b", "not twice"
    assert normalised("http://x/{main}") == normalised("http://x/%7Bmain%7D")
    assert normalised('http://x/<"`>?') == "http://x/%3C%22%60%3E"
    # The query has a set of its own: the braces stay, a quote and a space do not.
    assert normalised("http://x/?q={a} 'b'ä") == "http://x/?q={a}%20%27b%27%C3%A4"
    assert normalised("http://Bücher.Example/") == "http://xn--bcher-kva.example/"
    assert normalised("http://XN--BCHER-KVA.example") == "http://xn--bcher-kva.example/"
    assert normalised("http://[::1]:80/") == "http://[::1]/"
    assert normalised("about:blank") == "about:blank"


def test_two_addresses_of_leave_that_are_one_are_refused(capsys):
    check = headless_check()
    subject = object.__new__(check.Check)
    subject.interfaces = {"main": type("Interface", (), {"origin": "http://127.0.0.1:41001"})()}
    subject.spec = {"pages": [], "leave": ["{main}", "http://Elsewhere.example", "{nobody}/"]}
    subject.refuse_twins()
    for twins in (
        ["http://elsewhere.example/", "http://Elsewhere.example"],
        ["{main}/", "{main}"],
        ["http://127.0.0.1:41001/", "{main}"],
        ["http://x/{main}", "http://x/%7Bmain%7D"],
        ["http://Bücher.example/#a", "http://xn--bcher-kva.example:80"],
        ["{nobody}", "{nobody}"],
    ):
        subject.spec = {"pages": [], "leave": ["http://other.example/", *twins]}
        assert check.guarded(subject.run) == 1, twins
        err = capsys.readouterr().err
        assert f"leave: {twins[0]!r} and {twins[1]!r} are the same address" in err


def test_a_name_is_put_in_at_the_start_of_an_address_only():
    check = headless_check()
    subject = object.__new__(check.Check)
    subject.interfaces = {"main": type("Interface", (), {"origin": "http://127.0.0.1:41001"})()}
    assert subject.address("{main}/x") == "http://127.0.0.1:41001/x"
    assert subject.address("http://elsewhere.example/{main}/") == "http://elsewhere.example/{main}/"
    assert subject.address("http://elsewhere.example/{nobody}") == (
        "http://elsewhere.example/{nobody}"
    )


class Answered:
    """``Chromium._send`` without a browser: what was sent, and a queue for each."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []

    def __call__(self, method, params, session):
        self.sent.append((method, params))
        return queue.Queue()


def chromium_without_a_browser(check):
    subject = object.__new__(check.Chromium)
    subject.origin, subject.session, subject.page = "http://127.0.0.1:41001", "s", "probe/out"
    subject.frame, subject.left, subject.leaving, subject.outside = "MAIN", set(), None, []
    subject._send = Answered()
    return subject


def paused(ident, url, *, kind="Document", frame="MAIN"):
    request = {"requestId": ident, "request": {"url": url}, "resourceType": kind, "frameId": frame}
    return {"method": "Fetch.requestPaused", "params": request}


def test_the_request_of_leave_is_a_document_of_the_main_frame_and_nothing_else():
    check = headless_check()
    subject = chromium_without_a_browser(check)
    subject.left.add("http://elsewhere.example/")
    leaving = {"url": "http://elsewhere.example/", "paused": threading.Event()}
    leaving.update(answer=None, failing=False)
    subject.leaving = leaving
    # A resource of the page at the address, and a frame of it: the page's, and counted.
    subject._event(paused("1", "http://elsewhere.example/", kind="Image"))
    subject._event(paused("2", "http://Elsewhere.example:80/#x", frame="CHILD"))
    assert not leaving["paused"].is_set()
    # The navigation itself, written as Chromium writes it.
    subject._event(paused("3", "http://Elsewhere.example:80/#x"))
    assert leaving["paused"].is_set()
    assert leaving["failing"] is True
    assert [p["requestId"] for m, p in subject._send.sent if m == "Fetch.failRequest"] == [
        "1",
        "2",
        "3",
    ]
    assert [r["url"] for r in subject.outside] == [
        "http://elsewhere.example/",
        "http://Elsewhere.example:80/#x",
    ]


def test_the_request_of_leave_that_comes_late_is_failed_and_not_counted_as_the_page_s():
    check = headless_check()
    subject = chromium_without_a_browser(check)
    subject.left.update({"http://elsewhere.example/", "http://127.0.0.1:41002/"})
    subject._event(paused("1", "http://elsewhere.example"))
    subject._event(paused("2", "http://127.0.0.1:41002/"))
    subject._event(paused("3", "http://127.0.0.1:41001/"))
    assert subject.outside == []
    assert [(m, p["requestId"]) for m, p in subject._send.sent] == [
        ("Fetch.failRequest", "1"),
        ("Fetch.failRequest", "2"),
        ("Fetch.continueRequest", "3"),
    ]
    # An address the check never asked for is the page's.
    subject._event(paused("4", "http://other.example/"))
    assert subject.outside == [{"page": "probe/out", "url": "http://other.example/"}]


def test_a_late_request_of_an_address_before_is_not_the_page_s_nor_the_one_under_way():
    check = headless_check()
    subject = chromium_without_a_browser(check)
    subject.left.update({"http://elsewhere.example/", "http://other.example/"})
    leaving = {"url": "http://other.example/", "paused": threading.Event()}
    leaving.update(answer=None, failing=False)
    subject.leaving = leaving
    subject._event(paused("1", "http://Elsewhere.example"))
    assert subject.outside == []
    assert not leaving["paused"].is_set()
    assert leaving["answer"] is None
    subject._event(paused("2", "http://other.example/"))
    assert leaving["paused"].is_set()
    assert [(m, p["requestId"]) for m, p in subject._send.sent] == [
        ("Fetch.failRequest", "1"),
        ("Fetch.failRequest", "2"),
    ]
    assert subject.outside == []


def test_no_main_frame_known_no_request_is_the_check_s():
    navigation_to = headless_check().navigation_to
    params = paused("1", "http://elsewhere.example/")["params"]
    addresses = {"http://elsewhere.example/"}
    assert navigation_to(params, "MAIN", addresses)
    assert not navigation_to(params, None, addresses)
    assert not navigation_to(params, "MAIN", set())


def test_scrubbed_hides_the_token_in_a_start_line_a_location_and_a_text():
    scrubbed = headless_check().scrubbed
    secret = "".join(["ab", "12", "cd", "34"])
    assert (
        scrubbed(f"open http://127.0.0.1:41001/?token={secret}\n")
        == "open http://127.0.0.1:41001/?token=<token>\n"
    )
    assert (
        scrubbed(f"http://127.0.0.1:41001/?token={secret} complete <div>")
        == "http://127.0.0.1:41001/?token=<token> complete <div>"
    )
    assert scrubbed(f"a token={secret} b token={secret}") == "a token=<token> b token=<token>"
    assert scrubbed("a token=<token> b") == "a token=<token> b"


def test_scrubbed_leaves_a_text_without_a_token_as_it_is():
    scrubbed = headless_check().scrubbed
    text = "http://127.0.0.1:41001/ complete\n  tokens = 3, token: x\n"
    assert scrubbed(text) == text


def test_scrubbed_keeps_a_json_text_valid_and_what_follows_the_token():
    scrubbed = headless_check().scrubbed
    secret = "".join(["ab", "c-", "_1"])
    text = scrubbed(json.dumps({"url": f"http://127.0.0.1:1/?token={secret}", "n": 1}))
    assert json.loads(text) == {"url": "http://127.0.0.1:1/?token=<token>", "n": 1}
    text = scrubbed(json.dumps({"url": "http://127.0.0.1:1/?token=abc&x=1", "n": 1}))
    assert json.loads(text)["url"] == "http://127.0.0.1:1/?token=<token>&x=1"


def raising(error):
    def run():
        raise error

    return run


def test_guarded_scrubs_a_system_exit_text_and_keeps_the_exit(capsys):
    guarded = headless_check().guarded
    secret = "".join(["ab", "cd"])
    assert guarded(raising(SystemExit(f"no load event for http://x/?token={secret}"))) == 1
    err = capsys.readouterr().err
    assert "token=<token>" in err
    assert secret not in err


def test_guarded_scrubs_the_traceback_of_any_other_exception(capsys):
    guarded = headless_check().guarded
    secret = "".join(["ab", "cd"])
    assert guarded(raising(ValueError(f"bad token={secret}"))) == 1
    err = capsys.readouterr().err
    assert "Traceback" in err
    assert "token=<token>" in err
    assert secret not in err


def test_guarded_passes_a_clean_exit_and_a_return_value_silently(capsys):
    guarded = headless_check().guarded
    assert guarded(raising(SystemExit(0))) == 0
    assert guarded(lambda: 1) == 1
    assert capsys.readouterr().err == ""


def test_the_report_and_the_page_texts_hold_no_token(tmp_path, monkeypatch):
    check = headless_check()
    secret = "".join(["ab", "12", "cd", "34"])
    url = f"http://127.0.0.1:41001/?token={secret}"
    monkeypatch.setattr(check, "OUT", tmp_path)
    subject = object.__new__(check.Check)
    subject.report = {"pages": []}
    subject.version = "x"
    subject.interfaces = {}
    subject.chromium = type(
        "Chromium",
        (),
        {
            "outside": [{"url": url, "method": "GET"}],
            "documents": [],
            "console": [{"url": url, "text": f"failed {url}"}],
        },
    )()
    subject.write_report()
    text = (tmp_path / "report.json").read_text(encoding="utf-8")
    assert secret not in text
    report = json.loads(text)
    assert report["console"]["entries"][0]["url"].endswith("token=<token>")
    assert report["outside_requests"]["requests"][0]["url"].endswith("token=<token>")


def test_the_interface_keeps_the_token_in_start_url_only_and_the_other_lines_in_stderr():
    check = headless_check()
    secret = "".join(["ab", "12", "cd", "34"])
    start = f"web: http://127.0.0.1:41001/?token={secret}\n"
    interface = object.__new__(check.Interface)
    interface.process = type("Process", (), {"stderr": iter([start, f"later token={secret}\n"])})()
    interface.stderr = []
    interface.started = check.threading.Event()
    interface._read()
    assert interface.started.is_set()
    assert interface.start_url == f"http://127.0.0.1:41001/?token={secret}"
    assert (interface.port, interface.origin) == (41001, "http://127.0.0.1:41001")
    assert interface.stderr == ["later token=<token>\n"]
