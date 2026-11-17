"""The web interface in headless Chromium, with no network (CONTRACT section 10, "page").

The world of ``test_web_hostile.py`` (the hostile server driven, filed, decided on, packed and
attested to; two fleets of it) is shown by the interface in a container that has no network
(``--network none``, a read-only root), next to Chromium, which ``tests/fixtures/web/headless/
check.py`` drives over ``--remote-debugging-pipe``. The check visits every page and mode, operates
the controls only a browser can work (the pickers, the signal filter, the history toggle) and writes
``report.json``; the tests below read it. The page is judged by what it did in a browser: the
elements and attributes in the rendered DOM, every request that left its origin, every
console error, and where each hostile value stands as text.

Needs the image ``mcp-kymograph-headless:1`` (``IMAGE``, built from the Dockerfile beside the
check); without it the tests are skipped, and an error under ``MCP_KYMOGRAPH_REQUIRE_DOCKER=1``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import unicodedata
from fnmatch import fnmatchcase
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlencode

import pytest

from mcp_kymograph.web import views
from test_web_hostile import (
    APP,
    DECLARED_PACING,
    FIXTURES,
    ODD_PACING,
    PACED_MORE,
    PACED_MORE_KEY,
    SHOWS,
    STARTED_PROTO,
    STATIC,
    UNSAID_PACING,
    VALUES,
    Hostile,
    built_world,
    kind_of,
)

IMAGE = "mcp-kymograph-headless:1"
BUILD = f"docker build -t {IMAGE} tests/fixtures/web/headless"
HEADLESS = FIXTURES / "headless"
CONTRACT = Path(views.__file__).parent / "CONTRACT.md"
SRC = Path(views.__file__).parents[2]
REQUIRE_DOCKER = "MCP_KYMOGRAPH_REQUIRE_DOCKER"

#: Names that look like a hostile value, and are an ordinary one: the tool ``paypal`` of the
#: hostile server, beside the one named ``CYRILLIC``.
TWINS = {"LATIN_PAYPAL": "paypal"}

#: How the page may write a value as text (``check.py``, ``forms_of``): in a line, in a block
#: (a line feed stays), or inside a JSON string of a payload shown whole, where the quote and the
#: backslash are escaped as JSON has it and every invisible character is still a token.
AS_TEXT = {"text", "block", "json"}
#: What a signal's ``reach`` filters, in the order of the buttons after "All".
FILTERS = ("all", "everywhere", "metadata", "declared")

#: Where the views put a value (which view shows which value, by what a person sees): a page of
#: the check, a name, and the place. A value in a cell stands under the header of its column
#: (Triage: the author in the column of its role; Fleets: the line of a problem in the
#: "Problems" column; a run's findings in a table of their own), one in a card under the title of
#: the panel, one in a ``details`` under its summary. Never a heading "every row of this finding"
#: for a value in a column.
PLACES = [
    ("triage", "MARKUP_LINK", "column: Operator"),
    ("triage", "CYRILLIC", "column: Customer"),
    ("store-runs", "COMPOSITE_SERVER_NAME", "column: Run · sha256 of recording"),
    ("fleet-compare", "COMPOSITE_IMAGE", "column: Before → after"),
    ("fleet-second", "COMPOSITE_STDERR", "column: Problems"),
    ("fleet-first", "COMPOSITE_IMAGE", "heading: Fleet problems"),
    ("run-driven-inventory", "CYRILLIC", "heading: Tools tools"),
    ("run-driven-inventory", "SCRIPT", "heading: As recorded (masked)"),
    ("run-driven-overview", "COMPOSITE_SERVER_NAME", "note: server_name_mismatch"),
    ("run-driven-overview", "ZERO_WIDTH", "dt: pacing_enforced"),
    ("run-driven-inventory", "ZERO_WIDTH", "dt: pacing_enforced"),
    ("run-driven-overview", "MARKUP_B", "column: why"),
    ("run-driven-overview", "BIDI", "column: why"),
    ("review-hidden_html", "MARKUP_LINK", "column: Author"),
    ("review-hidden_html", "SCRIPT", "column: The text recorded there"),
]

#: A value that stands in nothing but the markup of a probe, and the markup (written into the main
#: element of a page that has rendered, and observed like a page): what the pass over the page
#: must see, whatever the views make today. ``row``: a value in a cell under a row whose cell holds
#: a ``details``; ``empty``: a column whose header has no label; ``alone``: nothing to name it;
#: ``mixed``: text beside a child element, with an invisible character in it; ``option``: a
#: ``value`` that holds one; ``out``: links and sources that lead away; ``section``, ``nested``,
#: ``own``: the heading stays in its own section; ``note-key``, ``note-kind``, ``note-self``,
#: ``note-plain``: a note that names itself, one whose label is the value, one without a label;
#: ``feff``, ``tab``, ``blank``: a node of one character between the elements of a cell
#: (the first two are raw, the last is white space).
PROBE = "probe value"
PROBES = {
    "row": (
        "<table><thead><tr><th>Name</th><th>Note</th></tr></thead><tbody>"
        "<tr><td><span>first row</span></td><td><details><summary>every row of this finding"
        "</summary>a note</details></td></tr>"
        f"<tr><td><span>{PROBE}</span></td><td>x</td></tr></tbody></table>"
    ),
    "empty": (
        "<h2>Section</h2><table><thead><tr><th></th></tr></thead><tbody>"
        f"<tr><td>{PROBE}</td></tr></tbody></table>"
    ),
    "alone": f"<p>{PROBE}</p>",
    "mixed": f"<p>lead \u202e <b>b</b> {PROBE} tail</p>",
    "option": (
        '<select name="x"><option value="a\u200bb">l</option><option value="12">r</option></select>'
    ),
    "section": f"<section><h2>A</h2><p>x</p></section><section><p>{PROBE}</p></section>",
    "nested": (f"<section><h2>A</h2><section><h3>B</h3><p>x</p></section><p>{PROBE}</p></section>"),
    "own": f"<section><h2>A</h2><div><p>{PROBE}</p></div></section>",
    "note-key": f'<div role="note"><span class="key">kind</span> <code>{PROBE}</code></div>',
    "note-kind": (
        '<section role="note"><div><span class="notice-kind">kind</span></div>'
        f"<p>{PROBE}</p></section>"
    ),
    "note-self": f'<div role="note"><span class="key">{PROBE}</span></div>',
    "note-plain": f'<div role="note"><strong>Read</strong> <code>{PROBE}</code></div>',
    "feff": "<table><tbody><tr><td>\ufeff<b>x</b></td></tr></tbody></table>",
    "tab": "<table><tbody><tr><td>\t<b>x</b></td></tr></tbody></table>",
    "blank": "<table><tbody><tr><td> <b>x</b></td><td>\n<b>y</b></td></tr></tbody></table>",
    "out": (
        '<div href="http://elsewhere.example/x">d</div>'
        '<link rel="alternate" href="http://elsewhere.example/feed">'
        '<source src="http://elsewhere.example/a">'
    ),
}

#: Where the check goes after everything else, from the page of ``main``: a host of no interface,
#: the other interface and its own (``{name}`` is the origin of that interface). All but the last
#: are written as Chromium does not ask for them: a host in capitals and no ``/`` after it; the
#: default port and a fragment; a ``{`` in the path (not a name), a space and a character that is
#: not ASCII; a host that is not ASCII; no ``/`` after the origin. No two are one address.
LEAVE = [
    "http://Elsewhere.example",
    "http://other.example:80/#x",
    "http://elsewhere.example/{main}/a b/ä?q=ü",
    "http://Bücher.example/",
    "{fleets}",
    "{main}/",
]

#: A place: the kind of step that found it, and a label that is not empty.
PLACE = r"(column|dt|aria-label|note|heading): \S.*"

pytestmark = pytest.mark.docker


# -- the image ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def image() -> str:
    reason = None
    if shutil.which("docker") is None:
        reason = "no docker CLI"
    else:
        done = subprocess.run(  # noqa: S603
            ["docker", "image", "inspect", IMAGE],  # noqa: S607
            capture_output=True,
            check=False,
            timeout=60,
        )
        if done.returncode != 0:
            reason = f"image {IMAGE} is missing"
    if reason is not None:
        if os.environ.get(REQUIRE_DOCKER) == "1":
            pytest.fail(f"{REQUIRE_DOCKER}=1, but {reason}; build it with: {BUILD}", pytrace=False)
        pytest.skip(f"Docker: {reason}; build it with: {BUILD}")
    return IMAGE


# -- what the check is told ----------------------------------------------------------------------


#: How many messages the strip of the findings tab gives a column, read from the page's code.
STRIP_COLUMNS = int(re.search(r"const STRIP_COLUMNS = (\d+);", APP).group(1))


class Plan:
    """The pages of the world: for each, where the check goes, and which view of which
    envelope the page shows (so which hostile values it must show)."""

    def __init__(self, world: Hostile) -> None:
        self.world = world
        src, fleets = world.sources, world.fleet_sources
        self.pages: list[dict] = []
        self.expect: dict[str, list[tuple[str, str]]] = {}
        self.tab: dict[str, str] = {}
        self.strip: dict[str, dict] = {}
        self.runs = {"driven": world.ref(world.driven[0]), "plain": world.ref(world.plain)}
        self.run_ids = [row["run"] for row in views.store_runs(src)["data"]]
        self.fleet_ids = [row["fleet"] for row in views.fleets(fleets)["data"]]
        engagement = [("store_engagement", "store_engagement")]

        self.add("main", "runs", "#/runs", [("runs", "runs")])
        for label, ref in self.runs.items():
            tabs = views.run(src, ref)["data"]["tabs"]
            for tab in tabs:
                self.add(
                    "main",
                    f"run-{label}-{tab}",
                    "#/run?" + urlencode({"ref": ref, "tab": tab}),
                    [("run", label)],
                    tab=tab,
                    shot=tab in ("overview", "inventory"),
                )
            if "findings" in tabs:
                listed = [m["seq"] for m in views.messages(src, ref, 0, 500)["data"]["items"]]
                self.strip_pages(label, ref, views.run(src, ref)["data"], listed)
            counted: dict[str, int] = {}
            for item in views.messages(src, ref, 0, 500)["data"]["items"]:
                one = views.message(src, ref, item["seq"])
                kind = kind_of(one)
                n = counted[kind] = counted.get(kind, -1) + 1
                self.add(
                    "main",
                    f"message-{label}-{item['seq']}",
                    "#/run?" + urlencode({"ref": ref, "tab": "messages", "seq": item["seq"]}),
                    [("run", label), ("messages", label), ("message", f"{label}:{kind}#{n}")],
                    tab="messages",
                )
        # The second run driven, whose pacing was declared and not enforced: its overview only.
        self.add(
            "main",
            "run-declared-overview",
            "#/run?" + urlencode({"ref": world.ref(world.driven[1]), "tab": "overview"}),
            [("run", "declared")],
            tab="overview",
        )
        # The runs whose pacing holds what this version does not write, under a server of their
        # own: the header alone (inventory), and header and run_started panel (overview).
        for name in ODD_PACING:
            for tab in ("overview", "inventory"):
                self.add(
                    "pacing",
                    f"run-{name}-{tab}",
                    "#/run?" + urlencode({"ref": name, "tab": tab}),
                    [],
                    tab=tab,
                )
        self.add("main", "store-runs", "#/store/runs", [("store_runs", "store_runs"), *engagement])
        for provenance in ("reference", "poison"):
            self.add(
                "main",
                f"store-findings-{provenance}",
                "#/store/findings?provenance=" + provenance,
                [("store_findings", provenance), *engagement],
            )
        self.add(
            "main",
            "store-candidates",
            "#/store/candidates",
            [("store_candidates", "store_candidates"), *engagement],
        )
        self.add("main", "store-diff-picker", "#/store/diff", engagement)
        self.add(
            "main",
            "store-diff",
            "#/store/diff?" + urlencode({"before": self.run_ids[0], "after": self.run_ids[1]}),
            [("store_diff", "store_diff"), *engagement],
        )
        self.add("main", "triage", "#/store/triage", [("triage", "triage"), *engagement])
        for name, finding in (
            ("hidden_html", world.finding),
            ("instruction_override", world.prompt_finding),
        ):
            self.add(
                "main",
                f"review-{name}",
                "#/review?" + urlencode({"finding": finding}),
                [("triage_review", name)],
                shot=True,
            )
        self.add("main", "corpus-list", "#/corpus", [("corpora", "corpora")])
        self.add("main", "corpus", "#/corpus?i=0", [("corpus", "corpus")])
        self.add("main", "scenarios", "#/scenarios", [("scenarios", "scenarios")])
        self.add("main", "scenario", "#/scenario?i=0", [("scenario", "scenario")])
        self.add("main", "signals", "#/signals", [("signals", "signals")])
        self.add("main", "about", "#/about", [("about", "about")])
        self.add("main", "evidence", "#/evidence", [("bundles", "bundles")])
        self.add("main", "bundle", "#/bundle?i=0", [("bundle", "bundle")])
        self.add("main", "handover", "#/bundle?i=1", [("bundle", "handover")])
        self.add("main", "attestation", "#/attestation?i=0", [("attestation", "attestation")])
        self.add("fleets", "fleet-runs", "#/runs", [("runs", "runs")])
        self.add("fleets", "fleets", "#/fleets", [("fleets", "fleets")])
        for label, fleet_id in (("first", world.fleet_first), ("second", world.fleet_second)):
            self.add(
                "fleets", f"fleet-{label}", "#/fleet?" + urlencode({"id": fleet_id}),
                [("fleet", label)],
            )  # fmt: skip
        self.add(
            "fleets", "fleet-compare-last-two", "#/fleets/compare",
            [("fleet_compare", "fleet_compare")],
        )  # fmt: skip
        self.add(
            "fleets",
            "fleet-compare",
            "#/fleets/compare?"
            + urlencode({"before": self.fleet_ids[0], "after": self.fleet_ids[1]}),
            [("fleet_compare", "fleet_compare")],
        )
        assert len(src.bundles) == 2 and fleets.store is not None

    def strip_pages(self, label: str, ref: str, data: dict, listed: list[int]) -> None:
        """The findings tab of a run that evaluated statements, once per thing its address can
        select: a statement, a name no statement has, an observation of the built-in walk that
        pairs with no finding, a number no such observation has. What the strip has to show is
        worked out here from the recording, apart from the page: its rows, its columns, and the
        words of every cell."""
        findings = data["findings"]
        evaluated = findings["statements_evaluated"]
        if not evaluated:
            return
        made = findings["findings"]
        statements = list(
            dict.fromkeys(
                [*(e["statement"] for e in evaluated), *(f["key"]["statement"] for f in made)]
            )
        )
        walk_only = [
            o
            for o in findings["observations"]
            if not any(
                (f["message_seq"], f["path"], f["key"]["signal"])
                == (o["message_seq"], o["path"], o["signal"])
                for f in made
            )
        ]
        named = sorted({e["message_seq"] for e in (*evaluated, *made, *findings["observations"])})
        columns = listed if len(listed) <= STRIP_COLUMNS else named[:STRIP_COLUMNS]
        assert set(named) <= set(listed)

        def cell(statement: str, seq: int) -> list[str | None]:
            at = (statement, seq)
            events = [e for e in evaluated if (e["statement"], e["message_seq"]) == at]
            held = sum(1 for f in made if (f["key"]["statement"], f["message_seq"]) == at)
            count = sum(n for e in events for n in e["fired"].values()) or held
            if count:
                return ["fired", f"×{count}"]
            if any(e["reason"] is not None for e in events):
                return ["evaluated, with a reason", None]
            return ["read, nothing fired" if events else "no record", None]

        def walk(statement: str) -> str:
            """What the walk's column says of a statement: of its findings, how many have an
            observation of the same message, path and signal recorded beside them."""
            mine = [f for f in made if f["key"]["statement"] == statement]
            seen = sum(
                1
                for f in mine
                if any(
                    (f["message_seq"], f["path"], f["key"]["signal"])
                    == (o["message_seq"], o["path"], o["signal"])
                    for o in findings["observations"]
                )
            )
            if not mine:
                return ""
            if seen in (0, len(mine)):
                return "observed too" if seen else "no observation recorded"
            return f"{seen} of {len(mine)} observed"

        def fired(statement: str) -> bool:
            """By every event of the run, whichever messages have a column."""
            return any(f["key"]["statement"] == statement for f in made) or any(
                n > 0 for e in evaluated if e["statement"] == statement for n in e["fired"].values()
            )

        cells = {name: [cell(name, seq) for seq in columns] for name in statements}
        self.strip[label] = held = {
            "ref": ref,
            "statements": statements,
            "fired": [name for name in statements if fired(name)],
            "walk_only": walk_only,
            "columns": columns,
            "all_columns": len(listed) <= STRIP_COLUMNS,
            "cells": cells,
            "walk": {name: walk(name) for name in statements},
            "events": {
                "Findings": len(made),
                "Observations": len(findings["observations"]),
                "Statements evaluated": len(evaluated),
                "findings_capped": len(findings["findings_capped"]),
            },
        }
        picks = {"st": {"st": held["statements"][-1]}, "st-unknown": {"st": "no-such-statement"}}
        if held["walk_only"]:
            picks["obs"] = {"obs": held["walk_only"][-1]["seq"]}
            picks["obs-unknown"] = {"obs": 0}
        for name, pick in picks.items():
            self.add(
                "main",
                f"run-{label}-findings-{name}",
                "#/run?" + urlencode({"ref": ref, "tab": "findings", **pick}),
                [("run", label)],
                tab="findings",
            )

    def add(self, server, ident, fragment, shows, *, tab=None, shot=False) -> None:
        assert ident not in self.expect, ident
        self.pages.append({"id": ident, "server": server, "hash": fragment, "shot": shot})
        self.expect[ident] = shows
        if tab is not None:
            self.tab[ident] = tab

    def servers(self) -> dict[str, list[str]]:
        src, fleets = self.world.sources, self.world.fleet_sources
        main = ["--store", str(src.store), "--runs", str(src.runs)]
        for path in src.manifests:
            main += ["--manifest", str(path)]
        for path in src.scenarios:
            main += ["--scenario", str(path)]
        for path in src.bundles:
            main += ["--bundle", str(path)]
        for path in src.attestations:
            main += ["--attestation", str(path)]
        other = ["--store", str(fleets.store), "--runs", str(fleets.runs)]
        for path in fleets.manifests:
            other += ["--manifest", str(path)]
        return {"main": main, "fleets": other, "pacing": ["--runs", str(self.world.pacing_runs)]}

    def operate(self) -> dict[str, dict]:
        """The controls only a browser can work: both pickers choose the second row as
        "before" and the first as "after", so that an index taken for an id is seen."""
        review = "#/review?" + urlencode({"finding": self.world.finding})
        strip = {"ref": self.strip["driven"]["ref"], "tab": "findings"}
        return {
            "store_diff": {
                "server": "main", "hash": "#/store/diff", "before_index": 1, "after_index": 0,
            },
            "fleet_compare": {
                "server": "fleets", "hash": "#/fleets", "before_index": 1, "after_index": 0,
            },
            "signals": {"server": "main", "hash": "#/signals"},
            "review_history": {"server": "main", "hash": review},
            "strip": {
                "server": "main",
                "hash": "#/run?" + urlencode(strip),
                "arrive": "#/run?"
                + urlencode({**strip, "st": self.strip["driven"]["statements"][-1]}),
            },
        }  # fmt: skip

    def spec(self) -> dict:
        return {
            "servers": self.servers(),
            "pages": self.pages,
            "values": {**VALUES, "PROBE": PROBE},
            "twins": TWINS,
            "operate": self.operate(),
            "probes": [
                {"id": name, "server": "main", "html": html} for name, html in PROBES.items()
            ],
            "leave": LEAVE,
        }

    def expected(self, ident: str) -> dict[str, set[str]]:
        """The hostile values the views this page shows must hold, each with the forms it may
        stand in. A run's tab shows what the run view holds for that tab, and its notices
        on every tab. A value the tool spells into a sentence of its own (``escaped``) stands
        there with Python's escapes."""
        names: dict[str, set[str]] = {}
        for view, label in self.expect[ident]:
            for name, where in SHOWS[view].items():
                for place in (*where.paths, *where.within):
                    on = getattr(place, "on", ())
                    if on and not any(fnmatchcase(label, pattern) for pattern in on):
                        continue
                    tab = self.tab.get(ident)
                    parts = str(place).split(".")
                    if (
                        view == "run"
                        and parts[0] == "data"
                        and tab != re.sub(r"\[.*", "", parts[1])
                    ):
                        continue
                    forms = names.setdefault(name, set())
                    forms |= {"spelled"} if where.escaped and place in where.within else AS_TEXT
        return names


# -- the run in the container --------------------------------------------------------------------


class Visit:
    def __init__(self, plan: Plan, out: Path, done: subprocess.CompletedProcess) -> None:
        self.plan, self.out, self.done = plan, out, done
        self.report = json.loads((out / "report.json").read_text(encoding="utf-8"))

    @property
    def pages(self) -> dict[str, dict]:
        return {p["id"]: p for p in self.report["pages"]}

    @property
    def operations(self) -> dict[str, dict]:
        return {o["name"]: o for o in self.report["operations"]}

    @property
    def probes(self) -> dict[str, dict]:
        return {p["name"]: p for p in self.report["probes"]}

    def everything(self) -> list[dict]:
        return [*self.report["pages"], *self.report["operations"]]


def drive(image: str, plan: Plan, spec: dict, out: Path) -> subprocess.CompletedProcess:
    """``check.py`` in the container, told ``spec``, writing into ``out``."""
    mounts = {
        SRC: "/src",
        HEADLESS / "check.py": "/check.py",
        plan.world.root: str(plan.world.root),
        FIXTURES: str(FIXTURES),
    }
    command = [
        "docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--tmpfs", "/tmp",  # noqa: S108
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "HOME=/tmp", "-e", "XDG_CONFIG_HOME=/tmp/.config", "-e", "XDG_CACHE_HOME=/tmp/.cache",
        *[arg for path, target in mounts.items() for arg in ("-v", f"{path}:{target}:ro")],
        "-v", f"{out}:/out",
        image, "python3", "-I", "/check.py",
    ]  # fmt: skip
    return subprocess.run(  # noqa: S603
        command, input=json.dumps(spec), capture_output=True, text=True, timeout=280,
        check=False,
    )  # fmt: skip


@pytest.fixture(scope="module")
def visit(image, tmp_path_factory) -> Visit:
    plan = Plan(built_world(tmp_path_factory))
    out = tmp_path_factory.mktemp("headless-out")
    done = drive(image, plan, plan.spec(), out)
    assert (out / "report.json").is_file(), done.stderr[-3000:]
    assert done.returncode == 0, done.stderr[-3000:]
    return Visit(plan, out, done)


@pytest.fixture(scope="module")
def refused(image, visit, tmp_path_factory) -> Visit:
    """The interface asked for an address its ``parseHash()`` turns away, after a page that
    renders: nothing is drawn again, and ``data-ready`` keeps the value of the page before."""
    plan = visit.plan
    spec = {
        "servers": {"main": plan.servers()["main"]},
        "pages": [
            plan.pages[0],
            {"id": "refused-address", "server": "main", "hash": "#nonsense", "shot": False},
        ],
        "values": {},
        "twins": {},
    }
    out = tmp_path_factory.mktemp("headless-refused")
    done = drive(image, plan, spec, out)
    assert (out / "report.json").is_file(), done.stderr[-3000:]
    return Visit(plan, out, done)


# -- what the page's code says it makes ----------------------------------------------------------


class Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()

    def handle_starttag(self, tag, attrs) -> None:
        self.tags.add(tag)


def element_names() -> set[str]:
    """Every element ``app.js`` creates (``h('x'``, ``createElement('x')``) or ``index.html``
    holds (the parser makes ``html``, ``head`` and ``body`` too)."""
    names = set(re.findall(r"\bh\(\s*'([a-z0-9]+)'", APP))
    names |= set(re.findall(r"createElement\(\s*'([a-z0-9]+)'", APP))
    markup = Markup()
    markup.feed((STATIC / "index.html").read_text())
    return names | markup.tags


def safe_attrs() -> set[str]:
    listed = re.search(r"const SAFE_ATTRS = new Set\(\[(.*?)\]\);", APP, re.S).group(1)
    return set(re.findall(r"'([a-z-]+)'", listed))


def links_of_the_page() -> dict[str, str]:
    """The ``<link>`` elements of ``index.html`` (``rel`` to ``href``): the page's own icon and
    style sheet, files of ``static/``."""
    found = dict(
        re.findall(r'<link rel="([a-z]+)" href="([^"]+)"', (STATIC / "index.html").read_text())
    )
    assert set(found) == {"icon", "stylesheet"}
    assert all((STATIC / href).is_file() for href in found.values())
    return found


def test_the_names_the_code_makes_are_read_from_it():
    names = element_names()
    assert {"div", "table", "td", "select", "option", "pre", "details", "template"} <= names
    assert {"script", "img", "svg", "iframe", "style", "u", "b"}.isdisjoint(names - {"script"})
    assert "script" not in re.findall(r"\bh\(\s*'([a-z0-9]+)'", APP)
    assert {"class", "id", "value", "hidden", "colspan"} <= safe_attrs()


# -- the tests -----------------------------------------------------------------------------------


def test_every_page_and_every_mode_was_visited_and_rendered(visit):
    asked = [p["id"] for p in visit.plan.pages]
    assert [p["id"] for p in visit.report["pages"]] == asked
    assert len(asked) > 60
    # "rendered" is the wait for a new value of data-ready; the raw value is "ready_value", and
    # a page that did not render again holds the old one.
    assert [p["id"] for p in visit.everything() if p["rendered"] is not True] == []
    for page in visit.report["pages"]:
        assert re.fullmatch(r"[0-9]{1,9}", page["ready_value"]), page["id"]
        assert page["hash"] == page["requested"], page["id"]
    assert {o["name"] for o in visit.report["operations"]} >= {
        "store-diff-compare", "fleet-compare", "review-history-shown",
    }  # fmt: skip


def test_a_target_that_does_not_render_again_is_a_fault_of_the_check(refused):
    pages = refused.pages
    assert pages["runs"]["rendered"] is True
    assert pages["refused-address"]["rendered"] is False
    # What the old check took for a result: the raw value is the one of the page before.
    assert pages["refused-address"]["ready_value"] == pages["runs"]["ready_value"]
    assert refused.done.returncode == 1
    assert "did not render again: refused-address" in refused.done.stderr
    assert set(re.findall(r"token=\S*", refused.done.stderr)) <= {"token=<token>"}


def test_no_request_left_the_origin_of_the_interface(visit):
    assert visit.report["outside_requests"] == {"count": 0, "requests": []}
    assert len(visit.report["origins"]) == 3


def test_a_request_to_another_origin_is_paused_and_failed_and_one_to_its_own_goes(visit):
    # The check itself leaves the page of "main" after the probes: what it asked for stands under
    # "left", and not in what the page asked for.
    *away, other, own = visit.report["left"]
    main = visit.pages["runs"]["origin"]
    fleets = visit.pages["fleets"]["origin"]
    assert fleets != main and fleets in visit.report["origins"]
    # The address as written, a name put in; a name in the path is none.
    assert [a["url"] for a in away] == LEAVE[:4]
    assert (other["url"], own["url"]) == (fleets, main + "/")
    for gone in (*away, other):
        assert (gone["url"], gone["paused"], gone["failed"]) == (gone["url"], True, True)
    assert (own["paused"], own["failed"]) == (True, False)
    assert visit.report["outside_requests"] == {"count": 0, "requests": []}


def test_the_console_has_no_error_and_no_policy_violation(visit):
    assert visit.report["console"] == {"count": 0, "entries": []}


def test_every_element_is_one_the_code_of_the_page_makes(visit):
    allowed = element_names()
    made = {name for page in visit.everything() for name in page["elements"]}
    assert made - allowed == set()
    assert {"table", "td", "dd", "pre", "details", "select", "option"} <= made


def test_every_attribute_is_one_the_page_sets_and_none_is_an_event(visit):
    allowed = safe_attrs()
    seen = {(tag, name) for page in visit.everything() for tag, name, _ in page["attributes"]}
    assert not [
        (tag, name)
        for tag, name in seen
        if not (name in allowed or name.startswith(("aria-", "data-")) or name == "href")
        or name.startswith("on")
    ]
    assert {"class", "href", "aria-label", "data-ready"} <= {name for _, name in seen}


def foreign_references(record: dict) -> list[tuple[str, str, str]]:
    """The ``href`` of any element that is no route of the page, no download of the interface and
    no file the head names (its icon, its style sheet), and the ``src`` of any element that is of
    another origin than the page."""
    own = set(links_of_the_page().values())
    return [
        (tag, name, value)
        for tag, name, value, origin in record["references"]
        if (
            name == "href"
            and not (re.match(r"#/|api/(bundle|attestation)/file\?", value) or value in own)
        )
        or (name == "src" and origin != record["origin"])
    ]


def test_every_link_is_a_route_of_the_page_or_a_download_of_the_interface(visit):
    # Every href of every element, <head> included: a route, a download, or the page's own icon
    # (and its style sheet, the one other file the head names).
    assert {i: foreign_references(p) for i, p in visit.pages.items() if foreign_references(p)} == {}
    seen = {
        value
        for page in visit.everything()
        for tag, name, value, _ in page["references"]
        if name == "href"
    }
    assert len(seen) > 50
    assert set(links_of_the_page().values()) <= seen
    downloads = [v for v in seen if v.startswith("api/")]
    assert any(v.startswith("api/bundle/file?") for v in downloads)
    assert any(v.startswith("api/attestation/file?") for v in downloads)


def test_every_src_of_the_page_is_of_its_own_origin(visit):
    sources = [
        (tag, value)
        for page in visit.everything()
        for tag, name, value, _ in page["references"]
        if name == "src"
    ]
    assert any(tag == "script" for tag, _ in sources)
    assert [
        (i, foreign_references(p)) for i, p in visit.pages.items() if foreign_references(p)
    ] == []


def test_every_option_value_is_the_index_of_a_row(visit):
    # The value of an option is the row index, and no longer the id the row names. The
    # placeholder ("choose a run") holds no value at all.
    values = [
        (page["id"], value)
        for page in visit.everything()
        for tag, name, value in page["attributes"]
        if tag == "option" and name == "value"
    ]
    assert values, "the pickers were looked at"
    assert [v for v in values if not re.fullmatch(r"[0-9]*", v[1])] == []
    assert any(re.fullmatch(r"[0-9]+", value) for _, value in values)


def test_every_hostile_value_a_page_is_asked_for_stands_there_as_text(visit):
    missing = {}
    for ident, page in visit.pages.items():
        for name, forms in visit.plan.expected(ident).items():
            seen = {hit["form"] for hit in page["found"] if hit["name"] == name}
            if not seen & forms:
                # What else the page did show of it, so that a value written in another form is
                # told from one that is not there at all.
                missing.setdefault(ident, {})[name] = sorted(seen)
    assert missing == {}, json.dumps(missing, indent=1)


def test_every_hostile_value_stands_at_a_named_place(visit):
    nameless = [
        (page["id"], hit["name"], hit["element"], hit["place"])
        for page in visit.everything()
        for hit in page["found"]
        if hit["name"] in VALUES and not re.fullmatch(PLACE, hit["place"])
    ]
    assert nameless == []


def test_a_value_in_a_cell_stands_at_the_header_of_its_column(visit):
    # Not at the note of a row or the heading of the section: a cell has a column.
    cells = [
        (page["id"], hit["name"], hit["place"])
        for page in visit.everything()
        for hit in page["found"]
        if hit["cell"] and hit["headed"]
    ]
    assert len(cells) > 20
    assert [c for c in cells if not c[2].startswith("column: ")] == []


@pytest.mark.parametrize("page, name, place", PLACES)
def test_a_value_stands_at_the_place_the_view_gives_it(visit, page, name, place):
    hits = [h for h in visit.pages[page]["found"] if h["name"] == name]
    assert place in {h["place"] for h in hits}, sorted({h["place"] for h in hits})


# -- pacing, as recorded (CONTRACT: "A run under an engagement", "A paced run's waits") ---------

#: The words the page writes for ``pacing_enforced`` ``true``, before the source.
HELD_TO = "runs_per_origin 1 · min_interval_seconds 10 · source "
#: The words for ``false``.
NOT_ENFORCED = "pacing declared, not enforced by the version that made it"


def text_of(visit: Visit, ident: str) -> str:
    """The text of the main element of a page, as the check wrote it down."""
    return (visit.out / "text" / f"{ident}.txt").read_text(encoding="utf-8")


def held_at_pacing(visit: Visit, ident: str) -> int:
    """How many elements of the page hold the paced run's ``pacing.source`` under the term
    ``pacing_enforced``. The engagement header and the overview's ``run_started`` panel name it
    alike, so the check's place does not tell them apart; the header stands on every tab of a run,
    the panel on the overview alone."""
    return sum(
        hit["count"]
        for hit in visit.pages[ident]["found"]
        if hit["name"] == "ZERO_WIDTH"
        and hit["form"] == "text"
        and hit["place"] == "dt: pacing_enforced"
    )


def recorded_as_kv(held: dict) -> re.Pattern[str]:
    """A ``pacing`` object as the page lists it, each key beside its value."""
    return re.compile(r"\s*".join(re.escape(str(x)) for pair in held.items() for x in pair))


def test_the_engagement_header_says_what_a_paced_run_was_held_to(visit):
    # The inventory tab has the header and no overview: what stands there is the header's.
    assert held_at_pacing(visit, "run-driven-inventory") == 1
    assert text_of(visit, "run-driven-inventory").count(HELD_TO) == 1


def test_the_overview_says_what_a_paced_run_was_held_to_beside_the_header(visit):
    # The header once, and the run_started panel of the overview once more.
    assert held_at_pacing(visit, "run-driven-overview") == 2
    assert text_of(visit, "run-driven-overview").count(HELD_TO) == 2


def as_text(value: str) -> str:
    """A value as the page writes it as text: each character of Cc, Cf, Cs, Co and Cn a token."""
    unsafe = {"Cc", "Cf", "Cs", "Co", "Cn"}
    return "".join(f"U+{ord(c):04X}" if unicodedata.category(c) in unsafe else c for c in value)


def beside_held(visit: Visit, ident: str) -> tuple[int, int]:
    """How many elements of the page hold the key of the paced run's ``pacing`` that this version
    does not write, under the term ``pacing_enforced``, and its value, under the key."""
    found = [h for h in visit.pages[ident]["found"] if h["form"] == "text"]
    key = sum(
        h["count"]
        for h in found
        if h["name"] == "BIDI" and h["whole"] and h["place"] == "dt: pacing_enforced"
    )
    under = "dt: " + as_text(PACED_MORE_KEY)
    value = sum(h["count"] for h in found if h["name"] == "ZERO_WIDTH" and h["place"] == under)
    return key, value


def test_a_key_of_pacing_beside_the_three_known_stands_in_the_header_as_recorded(visit):
    assert (VALUES["BIDI"], VALUES["ZERO_WIDTH"]) == (PACED_MORE_KEY, PACED_MORE)
    # The inventory tab has the header alone.
    assert beside_held(visit, "run-driven-inventory") == (1, 1)


def test_a_key_of_pacing_beside_the_three_known_stands_in_the_overview_as_recorded(visit):
    # The header once, and the run_started panel of the overview once more.
    assert beside_held(visit, "run-driven-overview") == (2, 2)
    assert text_of(visit, "run-driven-overview").count(HELD_TO) == 2


def test_a_run_without_a_wait_has_no_panel_of_waits(visit):
    assert "Waits" in text_of(visit, "run-driven-overview")
    for ident in ("run-plain-overview", "run-declared-overview"):
        text = text_of(visit, ident)
        assert "Waits" not in text, ident
        assert "paced · as recorded" not in text, ident


def test_the_waits_stand_each_as_recorded_with_no_sum(visit):
    text = text_of(visit, "run-driven-overview")
    panel = text.split("paced · as recorded", 1)[1].split("Stops and limits", 1)[0]
    hits = visit.pages["run-driven-overview"]["found"]
    whys = {h["name"] for h in hits if h["place"] == "column: why" and h["form"] == "text"}
    assert {"MARKUP_B", "BIDI"} <= whys
    for column in ("seconds", "why", "status"):
        assert column in panel, column
    assert "2.5" in panel and "429" in panel
    # 2.5 and 3 seconds: the panel adds them nowhere, and has no word for a sum or a judgement.
    assert "5.5" not in panel
    assert not re.search(r"\b(sum|total|too long|too short)\b", panel, re.I), panel


def test_pacing_declared_and_not_enforced_is_shown_with_what_it_declared(visit):
    text = text_of(visit, "run-declared-overview")
    # In the engagement header and in the overview's run_started panel.
    assert text.count(NOT_ENFORCED) == 2
    assert len(recorded_as_kv(DECLARED_PACING).findall(text)) == 2


def test_pacing_beside_a_null_is_shown_as_recorded(visit):
    # A run under no engagement file: its header names none, its overview has the values.
    text = text_of(visit, "run-plain-overview")
    assert len(recorded_as_kv(UNSAID_PACING).findall(text)) == 1
    assert NOT_ENFORCED not in text


def test_a_key_proto_of_pacing_stands_in_the_header_and_the_overview(visit):
    # Not the prototype of the object the page lists the further keys from: a key, with its value.
    for name, value in (("proto-number", r"5"), ("proto-object", r"a\s*1")):
        recorded = re.compile(r"__proto__\s*" + value)
        assert len(recorded.findall(text_of(visit, f"run-{name}-inventory"))) == 1, name
        assert len(recorded.findall(text_of(visit, f"run-{name}-overview"))) == 2, name


def test_a_key_proto_of_run_started_stands_among_its_other_fields(visit):
    text = text_of(visit, "run-proto-number-overview")
    recorded = re.compile(r"__proto__\s*" + re.escape(STARTED_PROTO))
    assert len(recorded.findall(text)) == 1
    assert len(recorded.findall(text.split("Other fields, as given", 1)[1])) == 1


def test_a_list_among_the_three_known_values_stands_as_recorded(visit):
    # Each item apart ("a, b", not "ab"), an empty list as one, an object as its key and value
    # in a table of its own: never "[object Object]", in the header and in the overview alike.
    for name, held in (
        ("proto-number", "runs_per_origin 2 · min_interval_seconds [] · source a, b"),
        ("proto-object", "runs_per_origin 2 · min_interval_seconds 30 · source k1"),
    ):
        for tab, count in (("inventory", 1), ("overview", 2)):
            text = text_of(visit, f"run-{name}-{tab}")
            assert text.count(held) == count, (name, tab)
            assert "[object Object]" not in text, (name, tab)


def test_no_invisible_character_stands_raw_in_the_page(visit):
    raw = {page["id"]: page["raw"] for page in visit.everything() if page["raw"]}
    assert raw == {}


def test_lookalikes_stand_unchanged_beside_each_other_and_their_twins(visit):
    page = visit.pages["run-driven-inventory"]
    whole = {hit["name"] for hit in page["found"] if hit["form"] == "text" and hit["whole"]}
    cyrillic, latin = VALUES["CYRILLIC"], TWINS["LATIN_PAYPAL"]
    assert cyrillic != latin and not cyrillic.isascii() and latin.isascii()
    # Each in a node of its own, as recorded: neither was turned into the other.
    assert {"CYRILLIC", "LATIN_PAYPAL"} <= whole
    # The composites hold a Cyrillic and a Greek lookalike: they stand, whole, as recorded.
    assert {"COMPOSITE_TOOL_NAME", "COMPOSITE_TOOL_TITLE"} <= whole
    review = visit.pages["review-hidden_html"]
    places = {(hit["name"], hit["place"]) for hit in review["found"] if hit["form"] in AS_TEXT}
    # Both readings of the ambiguous path, each a candidate of its own.
    assert {"DOTTED_SIDE", "SCRIPT"} <= {name for name, _ in places}


def test_the_pickers_hold_the_rows_index_and_open_the_runs_they_name(visit):
    ids, fleets = visit.plan.run_ids, visit.plan.fleet_ids
    diff = visit.operations["store-diff-compare"]
    assert diff["chosen"] == ["1", "0"]
    assert diff["address"] == "#/store/diff?" + urlencode({"before": ids[1], "after": ids[0]})
    assert {"Before", "After", "New", "Gone", "Unchanged"} <= set(diff["shown"])
    compare = visit.operations["fleet-compare"]
    assert compare["chosen"] == ["1", "0"]
    assert compare["address"] == "#/fleets/compare?" + urlencode(
        {"before": fleets[1], "after": fleets[0]}
    )
    for counter in ("new", "gone", "unchanged"):
        assert any(text.startswith(counter) for text in compare["shown"]), counter


def test_the_signal_filter_shows_the_rows_of_the_reach_it_says(visit):
    for index, key in enumerate(FILTERS):
        state = visit.operations[f"signals-filter-{index}"]
        assert state["pressed_before"] == "false", key
        assert state["pressed"] == ["true" if n == index else "false" for n in range(4)]
        wanted = [r for r in state["reach"] if key == "all" or r == key]
        assert wanted, key
        assert sorted(state["visible"]) == sorted(wanted), key


def test_the_history_toggle_is_off_when_the_page_opens_and_says_so(visit):
    start = visit.operations["review-history-start"]
    shown = visit.operations["review-history-shown"]
    hidden = visit.operations["review-history-hidden"]
    assert (start["expanded"], start["hidden"], start["state"]) == ("false", True, "history hidden")
    assert start["height"] == 0
    assert (shown["expanded"], shown["hidden"], shown["state"]) == ("true", False, "history shown")
    assert shown["height"] > 0
    assert (hidden["expanded"], hidden["hidden"], hidden["state"]) == (
        "false", True, "history hidden",
    )  # fmt: skip


# -- the strip of the findings tab (CONTRACT: "The findings tab") ---------------------------------

#: The words of the cell of a row the built-in walk made and no finding stands beside.
WALKED = "observed by the built-in walk"
#: The legend of the strip, whole: each line with the words that claim no more than a record.
LEGEND = [
    "no record: the statement did not apply to the message, the message was not inspected,"
    " or the record was not written",
    "read, nothing fired",
    "evaluated, with a reason, or what fired is not recorded as counts",
    "fired, with the count",
    WALKED + "; no finding of the same message, path and signal is recorded",
]
#: What stands above the detail of such a row.
WALK_ALONE = "Observed by the built-in walk, no finding recorded"


def picked_in(address: str) -> dict[str, list[str]]:
    """What an address of the strip selects: its ``st`` and ``obs`` parameters."""
    query = parse_qs(address.partition("?")[2], keep_blank_values=True)
    return {name: query[name] for name in ("st", "obs") if name in query}


def test_the_strip_has_a_row_for_every_statement_and_a_column_for_every_message_it_says(visit):
    start, held = visit.operations["strip-start"], visit.plan.strip["driven"]
    rows, walked = start["bodies"]
    assert [row["name"] for row in rows] == held["statements"]
    assert start["columns"] == [f"#{seq}" for seq in held["columns"]]
    said = "all " if held["all_columns"] else f"{len(held['columns'])} of "
    assert said in start["note"] and f"{len(held['statements'])} statement" in start["note"]
    assert f"{len(held['fired'])} fired" in start["note"]
    assert len(walked) == len(held["walk_only"])
    assert f"{len(walked)} of the walk without a finding" in start["note"]
    assert start["note"].endswith(": those an event of this tab names") or held["all_columns"]
    # the statement is the header of its row: a trace is announced with it
    assert {tuple(row["head"]) for body in start["bodies"] for row in body} == {("th", "row")}


def test_every_cell_of_the_strip_says_in_words_what_the_recording_holds(visit):
    start, held = visit.operations["strip-start"], visit.plan.strip["driven"]
    rows, walked = start["bodies"]
    for row in rows:
        assert row["cells"] == held["cells"][row["name"]], row["name"]
        assert row["walk"] == held["walk"][row["name"]], row["name"]
        assert (row["kind"] == "fired") == (row["name"] in held["fired"]), row["name"]
    kinds = {cell[0] for row in rows for cell in row["cells"]}
    assert {"fired", "no record"} <= kinds
    # a row of the walk alone is not drawn as a statement that fired: one mark, at its message
    for row, observation in zip(walked, held["walk_only"], strict=True):
        assert row["kind"] == "walked" and row["name"].startswith("walk, no finding ")
        at = held["columns"].index(observation["message_seq"])
        assert row["cells"] == [
            [WALKED if n == at else None, None] for n in range(len(held["columns"]))
        ]
    # every line of the strip is named in the legend, with words that claim no more than a record
    assert start["legend"] == LEGEND


def test_the_strip_selects_the_first_statement_that_fired_when_the_address_names_none(visit):
    start, held = visit.operations["strip-start"], visit.plan.strip["driven"]
    assert picked_in(start["address"]) == {}
    assert start["selected"] == [["true", held["fired"][0]]]
    assert (start["eyebrow"], start["heading"]) == ("Selected statement", held["fired"][0])
    # the address names no row: the focus is on the heading of the page, as on any other view
    assert start["focus"][0] == "h1"
    # every statement and every observation the walk made alone has a link of its own
    assert start["links"] == len(held["statements"]) + len(held["walk_only"])


def test_picking_a_row_changes_the_address_and_keeps_the_focus_on_it(visit):
    start, picked = visit.operations["strip-start"], visit.operations["strip-picked"]
    held = visit.plan.strip["driven"]
    name = next(n for n in held["statements"] if n != held["fired"][0])
    assert picked_in(picked["address"]) == {"st": [name]}
    assert picked["selected"] == [["true", name]] and picked["heading"] == name
    # the focus is on the link that was picked, not on the heading of the page
    assert picked["focus"] == ["a", "pick", name]
    assert picked["bodies"] == start["bodies"] and picked["columns"] == start["columns"]


def test_what_the_reader_opened_stays_open_when_a_row_is_picked(visit):
    assert visit.operations["strip-start"]["tables_open"] is False
    for step in ("strip-picked", "strip-picked-again", "strip-back", "strip-back-again"):
        assert visit.operations[step]["tables_open"] is True, step


def test_a_row_of_the_walk_alone_is_picked_like_a_statement(visit):
    again, held = visit.operations["strip-picked-again"], visit.plan.strip["driven"]
    assert picked_in(again["address"]) == {"obs": [str(held["walk_only"][-1]["seq"])]}
    assert len(again["selected"]) == 1 and again["selected"][0][0] == "true"
    assert again["focus"] == ["a", "pick", again["selected"][0][1]]
    assert again["eyebrow"] == WALK_ALONE
    assert again["heading"] == held["walk_only"][-1]["signal"]


def test_back_returns_to_each_row_selected_before(visit):
    start, picked = visit.operations["strip-start"], visit.operations["strip-picked"]
    back, first = visit.operations["strip-back"], visit.operations["strip-back-again"]
    assert back["address"] == picked["address"]
    assert (back["selected"], back["heading"]) == (picked["selected"], picked["heading"])
    assert back["focus"] == picked["focus"]
    assert first["address"] == start["address"]
    assert (first["selected"], first["heading"]) == (start["selected"], start["heading"])
    # an address that names no row puts the focus nowhere in the strip
    assert first["focus"][0] == "h1"


def test_another_tab_of_the_run_is_another_place(visit):
    left = visit.operations["strip-left"]
    assert "tab=findings" not in left["address"] and picked_in(left["address"]) == {}
    assert left["focus"][0] == "h1" and left["links"] == 0 and left["tables_open"] is None


def test_a_row_named_by_an_address_reached_from_elsewhere_is_selected_and_not_focused(visit):
    arrived, held = visit.operations["strip-arrived"], visit.plan.strip["driven"]
    assert picked_in(arrived["address"]) == {"st": [held["statements"][-1]]}
    assert arrived["selected"] == [["true", held["statements"][-1]]]
    # a new place: the focus is on the heading of the page, and nothing is kept open
    assert arrived["focus"][0] == "h1" and arrived["tables_open"] is False


def selected_on(visit: Visit, ident: str) -> list[str]:
    """The values of ``aria-current`` on the links of a page."""
    return [
        value
        for tag, name, value in visit.pages[ident]["attributes"]
        if (tag, name) == ("a", "aria-current") and value != "page"
    ]


def test_a_statement_named_in_the_address_is_the_one_selected(visit):
    held = visit.plan.strip["driven"]
    text = text_of(visit, "run-driven-findings-st")
    assert selected_on(visit, "run-driven-findings-st") == ["true"]
    assert "Selected statement" in text and held["statements"][-1] in text
    assert ("Finding 1 of " in text) == (held["statements"][-1] in held["fired"])
    # the count of the whole run stands apart from the messages
    assert "In run_finished" in text and "count for this statement" in text


def test_a_name_no_statement_has_selects_nothing_and_says_so(visit):
    text = text_of(visit, "run-driven-findings-st-unknown")
    assert selected_on(visit, "run-driven-findings-st-unknown") == []
    assert "This run evaluated no statement of that name." in text
    assert "Select a statement to see what it read." not in text


def test_an_observation_of_the_walk_alone_is_a_row_and_can_be_selected(visit):
    held = visit.plan.strip["driven"]
    assert held["walk_only"], "the hostile run holds observations that pair with no finding"
    text = text_of(visit, "run-driven-findings-obs")
    assert selected_on(visit, "run-driven-findings-obs") == ["true"]
    assert WALK_ALONE in text
    assert "That does not say no statement fired there" in text
    unknown = text_of(visit, "run-driven-findings-obs-unknown")
    assert selected_on(visit, "run-driven-findings-obs-unknown") == []
    assert "This run holds no observation of that number without a finding beside it." in unknown


def test_the_strip_keeps_every_event_of_the_tab_as_tables_under_it(visit):
    start, held = visit.operations["strip-start"], visit.plan.strip["driven"]
    # the pane says "the tables below": they are below
    assert start["tables_after_strip"] is True
    tables = dict(start["tables"])
    for title, count in held["events"].items():
        assert tables[title] == count, title
    assert {"findings_by_statement", "observations_by_method"} <= set(tables)
    text = text_of(visit, "run-driven-findings")
    toggle = (
        "The same events as tables: findings, observations, statement_evaluated,"
        " findings_capped, run_finished"
    )
    assert text.index("Statements against messages") < text.index(toggle)
    # the walk's column says what is recorded, and the note under the strip what that is not
    assert "None recorded does not say the walk looked there and saw nothing" in text


def test_a_run_that_evaluated_no_statement_has_the_tables_and_no_strip(visit):
    assert "plain" not in visit.plan.strip
    text = text_of(visit, "run-plain-findings")
    assert "Statements against messages" not in text and "Statements evaluated" in text


def test_the_review_and_run_views_were_photographed_at_two_sizes(visit):
    shots = visit.report["screenshots"]
    assert len(shots) >= 2 * 2 * 3
    names = sorted(Path(s).name for s in shots)
    assert "review-hidden_html-1920x1080.png" in names
    assert "review-hidden_html-1440x900.png" in names
    assert "run-driven-overview-1920x1080.png" in names
    assert all((visit.out / "shots" / n).stat().st_size > 1000 for n in names)


def test_the_answer_to_the_page_carries_the_policy_of_the_contract(visit):
    text = CONTRACT.read_text()
    found = re.search(r"Content-Security-Policy: (.*?)`", text, re.S)
    wanted = " ".join(found.group(1).split())
    answers = [d for d in visit.report["documents"] if d["path"] == "/"]
    assert len(answers) >= 2
    for answer in answers:
        assert answer["status"] == 200
        assert answer["headers"].get("content-security-policy") == wanted


def test_the_report_holds_no_start_token_and_not_the_start_line(visit):
    text = (visit.out / "report.json").read_text(encoding="utf-8")
    assert set(re.findall(r'token=[^\s"]*', text)) <= {"token=<token>"}
    for name, stderr in visit.report["interface_stderr"].items():
        assert "?token=" not in stderr, name


# -- the pass over the page, shown on markup of its own ----------------------------------------


def hits_of(record: dict) -> list[tuple[str, bool, str]]:
    return [(h["form"], h["whole"], h["place"]) for h in record["found"] if h["name"] == "PROBE"]


def test_a_value_in_a_cell_is_placed_at_its_column_and_not_at_the_note_of_a_row_before(visit):
    # The first row holds a details with the summary "every row of this finding": a value in a
    # column of the next row is not under that.
    assert ("text", True, "column: Name") in hits_of(visit.probes["row"])
    assert {place for _, _, place in hits_of(visit.probes["row"])} == {"column: Name"}


def test_a_column_without_a_label_is_no_place_and_the_search_goes_on(visit):
    assert {place for _, _, place in hits_of(visit.probes["empty"])} == {"heading: Section"}


def test_a_value_with_nothing_to_name_it_has_no_place_and_the_test_is_red(visit):
    assert {place for _, _, place in hits_of(visit.probes["alone"])} == {""}
    assert not re.fullmatch(PLACE, "")
    assert not re.fullmatch(PLACE, "column: ")


def test_text_beside_a_child_element_is_read_as_well(visit):
    probe = visit.probes["mixed"]
    assert probe["raw"] == [["text", "lead \u202e "]]
    assert ("text", False, "") in hits_of(probe)


def test_a_value_of_an_option_with_an_invisible_character_is_seen(visit):
    probe = visit.probes["option"]
    assert probe["raw"] == [["attribute value", "a\u200bb"]]
    values = [v for tag, name, v in probe["attributes"] if (tag, name) == ("option", "value")]
    assert [v for v in values if not re.fullmatch(r"[0-9]*", v)] == ["a\u200bb"]


def test_a_link_or_a_source_that_leads_away_is_seen_on_any_element(visit):
    assert foreign_references(visit.probes["out"]) == [
        ("div", "href", "http://elsewhere.example/x"),
        ("link", "href", "http://elsewhere.example/feed"),
        ("source", "src", "http://elsewhere.example/a"),
    ]


def test_the_filter_is_pressed_through_all_buttons_and_ends_on_all_again(visit):
    # "All" is pressed from the start: its step comes last and has to change the page back.
    steps = [o["name"] for o in visit.report["operations"] if o["name"].startswith("signals-")]
    assert steps == [f"signals-filter-{i}" for i in (1, 2, 3, 0)]
    state = visit.operations["signals-filter-0"]
    assert state["rendered"] is True
    assert sorted(state["visible"]) == sorted(state["reach"])


def test_a_heading_does_not_leave_its_section(visit):
    assert {place for _, _, place in hits_of(visit.probes["section"])} == {""}


def test_a_heading_in_a_section_beside_or_inside_is_not_the_one_of_the_value(visit):
    assert {place for _, _, place in hits_of(visit.probes["nested"])} == {"heading: A"}
    assert {place for _, _, place in hits_of(visit.probes["own"])} == {"heading: A"}


def test_a_note_is_the_place_of_a_value_in_it_by_its_label(visit):
    assert {place for _, _, place in hits_of(visit.probes["note-key"])} == {"note: kind"}
    assert {place for _, _, place in hits_of(visit.probes["note-kind"])} == {"note: kind"}


def test_a_note_whose_label_is_the_value_or_that_has_none_is_no_place(visit):
    assert {place for _, _, place in hits_of(visit.probes["note-self"])} == {""}
    assert {place for _, _, place in hits_of(visit.probes["note-plain"])} == {""}


def test_only_a_space_and_a_line_feed_are_the_white_space_of_the_markup(visit):
    assert visit.probes["feff"]["raw"] == [["text", "\ufeff"]]
    assert visit.probes["tab"]["raw"] == [["text", "\t"]]
    assert visit.probes["blank"]["raw"] == []
