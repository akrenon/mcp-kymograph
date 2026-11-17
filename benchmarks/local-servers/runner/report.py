"""The report over both stages: one row per server and stage, as HTML and as Markdown.

:func:`collect` sets the definitions against the ``result.json`` of the runs (``result_version`` 1,
``results.build_result``) and builds the rows; :func:`markdown` and :func:`html` lay them out. It
rates nothing: a stage that is active and has no run is an ``error`` with the cause ``no_run``,
never an empty line. Every value is escaped for the format it goes into, the excerpt of a signal
as well; an excerpt is shown only where it is asked for.
"""

from __future__ import annotations

import html as html_text
import importlib.util
import json
import string
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RESULT_FILE = "result.json"
RESULT_VERSION = 1
#: How many runs of a stage are looked at: the last ones, by the name of their directory.
RUNS_COMPARED = 2
NO_RUN = "no_run"
SAME, DIFFERENT, SINGLE, NONE = "same", "different", "single", "none"
NO_STAGE_B = "the definition has no stage B"
ISOLATION = {
    "none": "docker, `--network none`",
    "internal": "docker, internal network",
}
COLUMNS = (
    "Server",
    "Stage",
    "Transport",
    "Isolation",
    "State",
    "Outcome",
    "Signals (place)",
    "Canary",
    "Double run",
    "skipped (reason)",
)


def _load_bench() -> Any:
    """The runner module, as already loaded by whoever imports this one: a second copy would
    have a second ``RunnerError``, which the caller's ``except`` would not catch."""
    for name in ("bench_local_servers", "bench"):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "RunnerError"):
            return module
    main = sys.modules.get("__main__")
    if (
        main is not None
        and Path(getattr(main, "__file__", None) or "").name == "bench.py"
        and hasattr(main, "RunnerError")
    ):
        return main
    spec = importlib.util.spec_from_file_location(
        "bench_local_servers", Path(__file__).resolve().parent / "bench.py"
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 - a file next to this one
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bench = _load_bench()


@dataclass(frozen=True)
class Row:
    """One stage of one server. ``outcome`` is ``{"value": …, "causes": […]}``; a signal is
    ``{"signal", "path", "surface", "excerpt"}`` with the excerpt ``None`` unless it was asked
    for. ``canary`` is the result of the observation (stage B), ``isolation`` the words of the
    design and the name of the isolation, ``double_run`` one of ``same``, ``different``,
    ``single``, ``none``. ``state``, ``isolation`` and ``canary`` are ``None`` where no run is
    shown; ``reason`` is the one of a ``skipped`` stage."""

    server: str
    stage: str
    transport: str
    state: str | None
    outcome: dict[str, Any]
    signals: tuple[dict[str, Any], ...]
    canary: str | None
    isolation: str | None
    runs: int
    double_run: str
    reason: str | None


# -- collecting ---------------------------------------------------------------------------


def _refuse(path: Path, why: str) -> Any:
    raise bench.RunnerError(f"{path}: {why}")


def _read(path: Path) -> dict[str, Any]:
    """A ``result.json`` checked for the shape the report reads, or a ``RunnerError``."""
    try:
        data = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError) as exc:
        return _refuse(path, f"cannot be read: {getattr(exc, 'strerror', None) or exc}")
    if not isinstance(data, dict):
        _refuse(path, "not a JSON object")
    version = data.get("result_version")
    if isinstance(version, bool) or version != RESULT_VERSION:
        _refuse(path, f"result_version is {version!r}, not {RESULT_VERSION}")
    if not isinstance(data.get("server"), str) or data.get("stage") not in ("A", "B"):
        _refuse(path, "no server and stage")
    outcome = data.get("outcome")
    if (
        not isinstance(outcome, dict)
        or not isinstance(outcome.get("value"), str)
        or not isinstance(outcome.get("causes"), list)
    ):
        _refuse(path, "no outcome with a value and causes")
    signals = data.get("signals")
    if not isinstance(signals, list) or not all(isinstance(item, dict) for item in signals):
        _refuse(path, "no list of signals")
    if data["stage"] == "B" and not isinstance(data.get("canary"), dict):
        _refuse(path, "a stage B result without a canary observation")
    isolation = data.get("isolation")
    if not isinstance(isolation, dict) or isolation.get("network") not in ISOLATION:
        _refuse(path, "no isolation with a known network")
    return data


def _results(name: str, roots: Sequence[Path]) -> list[tuple[str, dict[str, Any]]]:
    """Every ``<root>/<name>/<run>/result.json``, read, with the name of its run directory."""
    found: list[tuple[str, dict[str, Any]]] = []
    for root in roots:
        parent = Path(root) / name
        try:
            runs = sorted(entry for entry in parent.iterdir() if entry.is_dir())
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise bench.RunnerError(f"{parent}: cannot be read: {exc.strerror or exc}") from None
        for run in runs:
            path = run / RESULT_FILE
            if path.is_file():
                found.append((run.name, _read(path)))
    return found


def run_order(name: str, result: dict[str, Any]) -> tuple[str, str]:
    """The key that orders the runs of a server: when each began, then the name of its directory.

    The names are made to the second plus a random ending, so they do not order runs of the same
    second. A result with no ``started_utc`` comes before all that have one."""
    started = result.get("started_utc")
    return (started if isinstance(started, str) else "", name)


def _pairs(result: dict[str, Any]) -> set[tuple[Any, Any]]:
    return {(item.get("signal"), item.get("path")) for item in result["signals"]}


def _canary(result: dict[str, Any]) -> Any:
    canary = result.get("canary")
    return canary.get("result") if isinstance(canary, dict) else None


def _double_run(runs: list[dict[str, Any]]) -> str:
    if not runs:
        return NONE
    if len(runs) == 1:
        return SINGLE
    first, second = runs
    same = (
        first["outcome"]["value"] == second["outcome"]["value"]
        and first["outcome"]["causes"] == second["outcome"]["causes"]
        and _pairs(first) == _pairs(second)
        and _canary(first) == _canary(second)
    )
    return SAME if same else DIFFERENT


def _signal(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "signal": item.get("signal"),
        "path": item.get("path"),
        "surface": item.get("surface"),
        "excerpt": item.get("excerpt"),
    }


def _isolation(result: dict[str, Any]) -> str:
    isolation = result["isolation"]
    text = ISOLATION[isolation["network"]]
    name = isolation.get("name")
    return text if name is None else f"{text} ({name})"


def _row(server: Any, stage: str, results: list[dict[str, Any]]) -> Row:
    stage_b = server.stage_b
    if stage == "A":
        skipped = server.stage_a_status != "active"
        reason = server.stage_a_reason
    else:
        skipped = stage_b is None or stage_b.status != "active"
        reason = NO_STAGE_B if stage_b is None else stage_b.reason
    base = {"server": server.name, "stage": stage, "transport": server.transport}
    if skipped:
        return Row(
            **base,
            state=None,
            outcome={"value": "skipped", "causes": []},
            signals=(),
            canary=None,
            isolation=None,
            runs=0,
            double_run=NONE,
            reason=reason,
        )
    runs = results[-RUNS_COMPARED:]
    if not runs:
        return Row(
            **base,
            state=None,
            outcome={"value": "error", "causes": [NO_RUN]},
            signals=(),
            canary=None,
            isolation=None,
            runs=0,
            double_run=NONE,
            reason=None,
        )
    last = runs[-1]
    return Row(
        **base,
        state=last.get("state"),
        outcome={"value": last["outcome"]["value"], "causes": list(last["outcome"]["causes"])},
        signals=tuple(_signal(item) for item in last["signals"]),
        canary=_canary(last),
        isolation=_isolation(last),
        runs=len(runs),
        double_run=_double_run(runs),
        # A run that ended skipped after its attempts (stage B) names why, as a skipped stage does.
        reason=last["outcome"].get("reason") if last["outcome"]["value"] == "skipped" else None,
    )


def collect(definitions: dict[str, Any], roots: Sequence[Path]) -> list[Row]:
    """The rows for ``definitions``: both stages of each server, in the order of the definitions.

    The signals carry their excerpts; whether they are shown is up to :func:`markdown` and
    :func:`html`."""
    rows: list[Row] = []
    for server in definitions.values():
        read = _results(server.name, roots)
        for stage in ("A", "B"):
            mine = [
                result
                for _, result in sorted(read, key=lambda item: run_order(*item))
                if result["server"] == server.name
                and result["stage"] == stage
                and result.get("retried") is not True
            ]
            rows.append(_row(server, stage, mine))
    return rows


# -- laying out ---------------------------------------------------------------------------


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _outcome(row: Row) -> str:
    causes = ", ".join(_text(cause) for cause in row.outcome["causes"])
    return f"{_text(row.outcome['value'])} ({causes})" if causes else _text(row.outcome["value"])


def _signal_line(signal: dict[str, Any]) -> str:
    surface = f" [{_text(signal['surface'])}]" if signal["surface"] else ""
    return f"{_text(signal['signal'])}{surface} ({_text(signal['path'])})"


def _cell(value: Any) -> str:
    """A value in a Markdown table cell: ``|`` and the backslash before it, and line breaks."""
    text = _text(value).replace("\\", "\\\\").replace("|", "\\|")
    return " ".join(text.splitlines())


#: What a value from a run is escaped of in Markdown: every ASCII punctuation character, which
#: CommonMark allows to escape with a backslash, one and all.
_PUNCTUATION = frozenset(string.punctuation)


def _literal(value: Any) -> str:
    """A value the server had a hand in (a path made of its keys, an excerpt of its text) in a
    Markdown cell, read as text and nothing else: each ASCII punctuation character escaped, so
    that no image (a request to a third party for whoever reads the report), link, emphasis,
    HTML or ``|`` of the server's comes through as such; line breaks become spaces."""
    text = "".join("\\" + char if char in _PUNCTUATION else char for char in _text(value))
    return " ".join(text.splitlines())


def _fields(row: Row) -> list[str]:
    return [
        row.server,
        row.stage,
        row.transport,
        _text(row.isolation),
        _text(row.state),
        _outcome(row),
        "",
        _text(row.canary),
        row.double_run,
        _text(row.reason),
    ]


def markdown(rows: Sequence[Row], excerpts: bool) -> str:
    """One table. With ``excerpts`` the text of a signal stands under its line."""
    lines = [
        "| " + " | ".join(_cell(name) for name in COLUMNS) + " |",
        "|" + " --- |" * len(COLUMNS),
    ]
    for row in rows:
        cells = [_cell(field) for field in _fields(row)]
        parts = []
        for signal in row.signals:
            part = _literal(_signal_line(signal))
            if excerpts and signal["excerpt"] is not None:
                part += "<br>" + _literal(signal["excerpt"])
            parts.append(part)
        cells[6] = "<br>".join(parts)
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def _escape(value: Any) -> str:
    return html_text.escape(_text(value), quote=True)


STYLE = (
    "body{font-family:sans-serif}table{border-collapse:collapse}"
    "td,th{border:1px solid #888;padding:.2em .5em;vertical-align:top;text-align:left}"
    "pre{margin:0;white-space:pre-wrap}"
)


def html(rows: Sequence[Row], excerpts: bool) -> str:
    """The same table as one page: no script, no link out, one ``<style>``."""
    out = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Benchmark report</title>",
        f"<style>{STYLE}</style></head><body>",
        "<h1>Benchmark report</h1>",
        "<table><thead><tr>" + "".join(f"<th>{_escape(name)}</th>" for name in COLUMNS),
        "</tr></thead><tbody>",
    ]
    for row in rows:
        cells = [f"<td>{_escape(field)}</td>" for field in _fields(row)]
        parts = []
        for signal in row.signals:
            part = f"<div>{_escape(_signal_line(signal))}"
            if excerpts and signal["excerpt"] is not None:
                part += f"<pre>{_escape(signal['excerpt'])}</pre>"
            parts.append(part + "</div>")
        cells[6] = "<td>" + "".join(parts) + "</td>"
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</tbody></table></body></html>")
    return "\n".join(out) + "\n"
