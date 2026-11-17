"""The result of one benchmark run, in one file: ``result.json`` beside ``container.json``.

A run directory holds the companion (what the runner did) and the recording (what the traffic
was). A report or an export should read neither of them again, so :func:`build_result` lays them
out once: the state and causes the verdict reads from the recording, the value of the run,
the signals with an excerpt of the text they sit in, the canary's observation (stage B), the
protocol version, the companion by name and SHA-256, the isolation.

It judges nothing. The excerpts are taken from the recording, which is masked already, and the
whole result goes through ``bench.scrub_value`` with the id of the run's canary (that id is in
``canary.txt`` and nowhere else) and the run's secrets where the runner gives them. Docker is not
needed; the files are all it reads.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp_kymograph import verdict

RESULT_FILE = "result.json"
RESULT_VERSION = 1
#: The longest excerpt of the text a signal sits in.
EXCERPT_LENGTH = 200
NETWORK_NONE = "none"
NETWORK_INTERNAL = "internal"


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


def _read_companion(run_dir: Path, bench: Any) -> tuple[dict[str, Any], bytes]:
    path = run_dir / bench.COMPANION
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise bench.RunnerError(f"{path}: cannot be read: {exc.strerror or exc}") from None
    try:
        companion = json.loads(raw)
    except ValueError as exc:
        raise bench.RunnerError(f"{path}: cannot be read: {exc}") from None
    if not isinstance(companion, dict):
        raise bench.RunnerError(f"{path}: not a JSON object")
    version = companion.get("companion_version")
    if version in bench.COMPANION_VERSIONS_OLD:
        raise bench.RunnerError(
            f"{path}: a version {version} companion holds a plain SHA-256 of the environment; "
            "the run has to be run again"
        )
    stages = {bench.COMPANION_VERSION: "A", bench.COMPANION_VERSION_B: "B"}
    if stages.get(version) is None or companion.get("stage") != stages[version]:
        raise bench.RunnerError(
            f"{path}: companion_version {version!r} with stage {companion.get('stage')!r} is "
            f"neither {bench.COMPANION_VERSION} with stage A nor {bench.COMPANION_VERSION_B} "
            "with stage B"
        )
    return companion, raw


def _canary_id(run_dir: Path, bench: Any) -> str | None:
    path = run_dir / bench.CANARY_FILE
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError) as exc:
        # Failing closed: a result without the scrub could carry the id.
        raise bench.RunnerError(f"{path}: cannot be read: {exc}") from None
    return text or None


def _strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    """Every string of a JSON document with its path (``result.content[0].text``), in order."""
    if isinstance(value, str):
        return [(path, value)]
    found: list[tuple[str, str]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            found += _strings(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            found += _strings(item, f"{path}.{key}" if path else str(key))
    return found


def excerpt(text: str, at: int | None = None) -> str:
    """At most :data:`EXCERPT_LENGTH` characters of ``text``: centred on ``at`` where the place
    of the hit is known, else from the start."""
    if len(text) <= EXCERPT_LENGTH:
        return text
    if at is None:
        return text[:EXCERPT_LENGTH]
    start = min(max(0, at - EXCERPT_LENGTH // 2), len(text) - EXCERPT_LENGTH)
    return text[start : start + EXCERPT_LENGTH]


class _Texts:
    """The strings of the messages of a recording by ``seq`` and path, read when asked for."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._messages = {
            event["seq"]: event
            for event in events
            if event.get("type") == "message" and isinstance(event.get("seq"), int)
        }
        self._strings: dict[int, dict[str, str]] = {}

    def text(self, seq: Any, path: Any) -> str | None:
        if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(path, str):
            return None
        message = self._messages.get(seq)
        if message is None:
            return None
        if seq not in self._strings:
            payload = message.get("payload")
            data = payload.get("data") if isinstance(payload, dict) else None
            found: dict[str, str] = {}
            for where, text in _strings(data):
                found.setdefault(where, text)
            self._strings[seq] = found
        return self._strings[seq].get(path)


def _signals(
    events: list[dict[str, Any]],
    canary_id: str | None,
    bench: Any,
    stage: str,
    hidden: Sequence[str] = (),
) -> list[dict]:
    texts = _Texts(events)
    # Stage B: only what was found on the answers to the client's calls, as in its outcome
    # (``bench.tool_call_signals``); a finding on ``tools/list`` is stage A's.
    answers = bench.call_answers(events) if stage == "B" else None
    found: list[dict[str, Any]] = []
    for event in events:
        kind = event.get("type")
        if kind == "finding":
            key = event.get("key") if isinstance(event.get("key"), dict) else {}
            statement, surface, signal = key.get("statement"), None, key.get("signal")
        elif kind == "observation":
            statement, surface, signal = None, event.get("surface"), event.get("signal")
        else:
            continue
        if answers is not None and (
            event.get("method") != "tools/call"
            or event.get("direction") != "server_to_client"
            or event.get("message_seq") not in answers
        ):
            continue
        text = texts.text(event.get("message_seq"), event.get("path"))
        found.append(
            {
                "kind": kind,
                "surface": surface,
                "signal": signal,
                "path": event.get("path"),
                "statement": statement,
                "method": event.get("method"),
                # Scrubbed before it is cut, and the scrub keeps the length: no window shows a
                # part of the canary's id or of a secret of the run.
                "excerpt": None if text is None else excerpt(bench.scrub(text, canary_id, hidden)),
            }
        )
    return found


def _protocol_version(events: list[dict[str, Any]]) -> str | None:
    """The protocol version the server answered ``initialize`` with: a string of at most 32
    characters, else None. The server must not set the size of ``result.json`` through it (and
    with that the time of ``export_check``'s ``secret`` windows)."""
    longest = 32
    for event in events:
        if (
            event.get("type") != "message"
            or event.get("direction") != "server_to_client"
            or event.get("responded_method") != "initialize"
        ):
            continue
        payload = event.get("payload")
        data = payload.get("data") if isinstance(payload, dict) else None
        result = data.get("result") if isinstance(data, dict) else None
        version = result.get("protocolVersion") if isinstance(result, dict) else None
        return version if isinstance(version, str) and len(version) <= longest else None
    return None


def _value(companion: dict[str, Any], read: Any, signals: list[dict], bench: Any) -> dict:
    if companion["stage"] == "B":
        outcome = companion.get("outcome")
        if (
            not isinstance(outcome, dict)
            or outcome.get("value") not in bench.OUTCOMES
            or not isinstance(outcome.get("causes"), list)
        ):
            raise bench.RunnerError("the companion has no outcome with a value and causes")
        return {"value": outcome["value"], "causes": list(outcome["causes"])}
    if read.state != verdict.COMPLETE:
        return {"value": "error", "causes": list(read.causes)}
    return {"value": "signal" if signals else "no_signal", "causes": []}


def _network(companion: dict[str, Any], bench: Any) -> str:
    """``internal`` where the run had a closed network (the HTTP server of stage A, a stage B
    kind with a network report), ``none`` where the docker command says ``--network none``;
    else the result is refused, never guessed."""
    report = companion.get("network")
    if isinstance(report, dict):
        if companion["stage"] == "A" and report.get("internal") is True:
            return NETWORK_INTERNAL
        if companion["stage"] == "B" and report.get("network") is not None:
            return NETWORK_INTERNAL
    command = companion.get("docker_command")
    if isinstance(command, list) and "--network" in command:
        at = command.index("--network")
        if at + 1 < len(command) and command[at + 1] == "none":
            return NETWORK_NONE
    raise bench.RunnerError("the companion shows neither a closed network nor --network none")


def _kept(run_dir: Path, bench: Any) -> dict[str, Any]:
    """What ``run_stage_b`` set in an earlier ``result.json`` of the run and the recording does
    not say: ``retried``, and the ``skipped`` outcome of a run whose attempts all failed."""
    path = run_dir / RESULT_FILE
    if not path.exists():
        return {}
    try:
        before = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        # A result that cannot be read is what ``result`` exists to write again.
        return {}
    if not isinstance(before, dict):
        return {}
    kept: dict[str, Any] = {}
    if before.get("retried") is True:
        kept["retried"] = True
    outcome = before.get("outcome")
    skipped = isinstance(outcome, dict) and outcome.get("value") == "skipped"
    if before.get("stage") == "B" and skipped:
        kept["outcome"] = outcome
    return kept


def build_result(run_dir: Path, hidden: Sequence[str] = ()) -> dict[str, Any]:
    """The result of the run in ``run_dir``, from its companion and its recording alone.

    ``hidden`` are the run's secrets (as in ``bench.scrub``): each is masked in every string of
    the result, the excerpts before they are cut. They are in no file of the run; without them
    only the canary's id is taken out."""
    run_dir = Path(run_dir)
    companion, raw = _read_companion(run_dir, bench)
    events_path = run_dir / "events.jsonl"
    try:
        recording = events_path.read_bytes()
    except OSError as exc:
        raise bench.RunnerError(f"{events_path}: cannot be read: {exc.strerror or exc}") from None
    if hashlib.sha256(recording).hexdigest() != companion.get("recording_sha256"):
        raise bench.RunnerError(
            f"{events_path}: the recording changed after its companion was written"
        )
    events, _ = verdict.read_events(recording)
    read = verdict.read(events_path)
    canary_id = _canary_id(run_dir, bench)
    signals = _signals(events, canary_id, bench, companion["stage"], hidden)
    package = companion.get("package")
    version = package.get("version") if isinstance(package, dict) else None
    isolation = companion.get("isolation")
    started = companion.get("started_utc")
    result: dict[str, Any] = {
        "result_version": RESULT_VERSION,
        "server": companion.get("server"),
        "version": version,
        "transport": companion.get("transport", bench.TRANSPORT_STDIO),
        "stage": companion["stage"],
        "state": read.state,
        "causes": list(read.causes),
        "outcome": _value(companion, read, signals, bench),
        "signals": signals,
    }
    if companion["stage"] == "B":
        canary = companion.get("canary")
        if not isinstance(canary, dict):
            raise bench.RunnerError("the companion has no canary observation")
        result["canary"] = {name: item for name, item in canary.items() if name != "file"}
    result.update(_kept(run_dir, bench))
    result.update(
        {
            "protocol_version": _protocol_version(events),
            "companion": {"file": bench.COMPANION, "sha256": hashlib.sha256(raw).hexdigest()},
            "started_utc": started if isinstance(started, str) else None,
            "isolation": {"name": isolation, "network": _network(companion, bench)},
        }
    )
    return bench.scrub_value(result, canary_id, hidden)
