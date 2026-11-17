"""``offenlegung.yaml``: which finding may be published. It lives in the private directory, never
in the repository, and says per finding (server, stage, signal, path) where it stands.

:func:`load` reads and checks the file, :func:`check` sets it against the results of runs
(``results.build_result``), :func:`init` lays it out or adds the findings it lacks. The export
takes along what :func:`released` names and nothing else. It decides nothing about a finding:
the status, the proposal and the dates are written by hand, and :func:`init` never changes one.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from mcp_kymograph.scenario import ScenarioError, parse_yaml

VERSION = 1
STAGES = ("A", "B")
STATUSES = ("unveröffentlicht", "gemeldet", "behoben", "freigegeben")
PROPOSALS = ("meldung", "beobachtung")
REQUIRED = ("server", "stage", "signal", "path", "status")
FIELDS = (*REQUIRED, "proposal", "reported", "deadline", "channel", "note")
DEADLINE_DAYS = 90
RESULT_FILE = "result.json"
RESULT_VERSION = 1
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

Key = tuple[str, str, str, str]


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
class Disclosure:
    """The entries of the file, each as the mapping that was read (all fields, absent ones null)
    and checked, in the order of the file."""

    entries: tuple[dict[str, Any], ...]


def entry_key(entry: dict[str, Any]) -> Key:
    return (entry["server"], entry["stage"], entry["signal"], entry["path"])


def _date(value: Any, where: str) -> date | None:
    if value is None:
        return None
    # ``fromisoformat`` alone also takes spellings like 20260101.
    if not isinstance(value, str) or _DATE.fullmatch(value) is None:
        raise bench.RunnerError(f"{where} is {value!r}, not a date YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise bench.RunnerError(f"{where} is {value!r}, not a date") from None


def _entry(raw: Any, number: int) -> dict[str, Any]:
    where = f"findings[{number}]"
    if not isinstance(raw, dict):
        raise bench.RunnerError(f"{where}: not a mapping")
    unknown = sorted(set(raw) - set(FIELDS))
    if unknown:
        raise bench.RunnerError(f"{where}: unknown field {unknown[0]!r}")
    for name in REQUIRED:
        if raw.get(name) is None:
            raise bench.RunnerError(f"{where}: {name} is missing")
    entry = {name: raw.get(name) for name in FIELDS}
    for name in ("server", "signal", "path"):
        if not isinstance(entry[name], str) or not entry[name]:
            raise bench.RunnerError(f"{where}: {name} is not a text")
    for name in ("channel", "note"):
        if entry[name] is not None and not isinstance(entry[name], str):
            raise bench.RunnerError(f"{where}: {name} is not a text")
    if entry["stage"] not in STAGES:
        raise bench.RunnerError(f"{where}: stage {entry['stage']!r} is neither A nor B")
    if entry["status"] not in STATUSES:
        raise bench.RunnerError(f"{where}: unknown status {entry['status']!r}")
    if entry["proposal"] is not None and entry["proposal"] not in PROPOSALS:
        raise bench.RunnerError(f"{where}: unknown proposal {entry['proposal']!r}")
    reported = _date(entry["reported"], f"{where}: reported")
    deadline = _date(entry["deadline"], f"{where}: deadline")
    expected = None if reported is None else reported + timedelta(days=DEADLINE_DAYS)
    if deadline != expected:
        raise bench.RunnerError(
            f"{where}: deadline is {entry['deadline']!r}, not reported + {DEADLINE_DAYS} days "
            f"({'null' if expected is None else expected.isoformat()})"
        )
    if entry["status"] in ("gemeldet", "behoben") and (
        reported is None or entry["channel"] is None
    ):
        raise bench.RunnerError(f"{where}: status {entry['status']} needs reported and channel")
    return entry


def load(path: Path) -> Disclosure:
    """The disclosure file at ``path``, or a ``RunnerError`` saying what is wrong with it."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise bench.RunnerError(
            f"{path}: cannot be read: {getattr(exc, 'strerror', exc)}"
        ) from None
    try:
        data = parse_yaml(text, source=str(path))
    except ScenarioError as exc:
        raise bench.RunnerError(str(exc)) from None
    if not isinstance(data, dict):
        raise bench.RunnerError(f"{path}: not a mapping")
    unknown = sorted(set(data) - {"version", "findings"})
    if unknown:
        raise bench.RunnerError(f"{path}: unknown field {unknown[0]!r}")
    version = data.get("version")
    if version != VERSION or isinstance(version, bool):
        raise bench.RunnerError(f"{path}: version is {version!r}, not {VERSION}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise bench.RunnerError(f"{path}: findings is not a list")
    entries: list[dict[str, Any]] = []
    seen: set[Key] = set()
    for number, raw in enumerate(findings):
        try:
            entry = _entry(raw, number)
        except bench.RunnerError as exc:
            raise bench.RunnerError(f"{path}: {exc}") from None
        key = entry_key(entry)
        if key in seen:
            raise bench.RunnerError(f"{path}: findings[{number}] repeats {list(key)}")
        seen.add(key)
        entries.append(entry)
    return Disclosure(tuple(entries))


def finding_keys(results: list[dict[str, Any]]) -> set[Key]:
    """``(server, stage, signal, path)`` of the signals in ``results`` (``result_version`` 1),
    from every run, whatever its value: a run that ended ``error`` has its findings as well, and
    ``export_check`` looks at every signal of every ``result.json``. In stage B only those on
    answers to ``tools/call``.

    A result or signal that is not shaped as ``results.build_result`` makes it, is refused: a
    finding must never drop out unseen."""
    keys: set[Key] = set()
    for result in results:
        if not isinstance(result, dict) or result.get("result_version") != RESULT_VERSION:
            raise bench.RunnerError(f"a result that is not of result_version {RESULT_VERSION}")
        outcome = result.get("outcome")
        if not isinstance(outcome, dict) or not isinstance(outcome.get("value"), str):
            raise bench.RunnerError("a result without an outcome value")
        signals = result.get("signals")
        if not isinstance(signals, list):
            raise bench.RunnerError("a result without a list of signals")
        for signal in signals:
            if not isinstance(signal, dict):
                raise bench.RunnerError("a signal that is not a mapping")
            if result.get("stage") == "B" and signal.get("method") != "tools/call":
                continue
            key = (
                result.get("server"),
                result.get("stage"),
                signal.get("signal"),
                signal.get("path"),
            )
            if not all(isinstance(part, str) and part for part in key):
                raise bench.RunnerError(f"a signal without server, stage, signal and path: {key}")
            keys.add(key)  # type: ignore[arg-type]
    return keys


def released(disclosure: Disclosure) -> set[Key]:
    """The findings whose status is ``freigegeben``."""
    return {entry_key(e) for e in disclosure.entries if e["status"] == "freigegeben"}


def check(disclosure: Disclosure, results: list[dict[str, Any]]) -> list[str]:
    """Problems: a finding of the results without an entry. Then notes, which are no problems:
    an entry no run shows. Both kinds are sorted, problems first; a note starts with ``note:``."""
    found = finding_keys(results)
    listed = {entry_key(e) for e in disclosure.entries}
    problems = [f"{list(key)}: not in the disclosure file" for key in sorted(found - listed)]
    notes = [f"note: {list(key)}: no run shows it" for key in sorted(listed - found)]
    return problems + notes


def init(path: Path, results: list[dict[str, Any]]) -> int:
    """Lay out the file at ``path``, or add the findings of ``results`` it lacks as
    ``unveröffentlicht``. An entry already there is written back as it is. Returns how many
    were added. A place git would track, or the public tree, is refused first."""
    import yaml

    path = Path(path)
    refusal = bench.out_dir_refusal(path, subject="disclosures")
    if refusal is not None:
        raise bench.RunnerError(refusal)
    found = finding_keys(results)
    entries = list(load(path).entries) if path.exists() else []
    missing = sorted(found - {entry_key(e) for e in entries})
    for server, stage, signal, where in missing:
        entries.append(
            {
                "server": server,
                "stage": stage,
                "signal": signal,
                "path": where,
                "status": "unveröffentlicht",
                "proposal": None,
                "reported": None,
                "deadline": None,
                "channel": None,
                "note": None,
            }
        )
    entries.sort(key=entry_key)
    text = yaml.safe_dump(
        {"version": VERSION, "findings": entries}, sort_keys=False, allow_unicode=True
    )
    partial = path.with_name(f".{path.name}.partial")
    try:
        # Created 0600 and never wider; the old file is replaced as a whole.
        descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
        os.replace(partial, path)
    except OSError as exc:
        raise bench.RunnerError(f"{path}: cannot be written: {exc.strerror or exc}") from None
    return len(missing)


def read_results(run_dirs: list[Path]) -> list[dict[str, Any]]:
    """The ``result.json`` of each run directory."""
    results: list[dict[str, Any]] = []
    for directory in run_dirs:
        path = Path(directory) / RESULT_FILE
        try:
            data = json.loads(path.read_bytes())
        except (OSError, ValueError, RecursionError) as exc:
            raise bench.RunnerError(
                f"{path}: cannot be read: {getattr(exc, 'strerror', None) or exc}"
            ) from None
        if not isinstance(data, dict):
            raise bench.RunnerError(f"{path}: not a JSON object")
        results.append(data)
    return results
