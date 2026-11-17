"""The export's private side: what must not go out, and the public form of the definitions.

:func:`forbidden_for` gathers everything ``export_check`` looks for in an exported tree: the
canary ids and the secrets of every run (not only of the runs exported), the values of
``launch.env``, the suite's keys, the paths of this machine, the names of the servers that drop
out, and the released findings. :func:`dropped_servers` says which servers drop out: one with a
finding that is not ``freigegeben`` drops out for all stages and transports. A finding of
the results that the disclosure file does not list stops the export as a whole.

:func:`public_definitions` and :func:`public_files` are the public form of ``versions.yaml`` and
of what it names, for the servers that stay.

:func:`export` builds the tree beside its target, has ``export_check`` look at it and replaces the
target only if nothing was found. It is the only writer of ``results/``: it writes where it is
told to (the ``bench.py export`` command passes ``results/`` only without ``--out``).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from collections.abc import Collection, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from mcp_kymograph.scenario import ScenarioError, parse_yaml


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
export_check = bench._sibling("export_check")
disclosure_files = bench._sibling("disclosure")

RELEASED = "freigegeben"


# -- what drops out -------------------------------------------------------------------------


def _private_files(run_roots: Sequence[Path], name: str) -> Iterator[Path]:
    """Every file called ``name`` under each of ``run_roots``, sorted, without following a
    link to a directory. A root or directory that cannot be read stops it: what is in there
    could be what has to be looked for."""

    def refuse(error: OSError) -> None:
        raise bench.RunnerError(
            f"{error.filename}: cannot be read: {error.strerror or error}"
        ) from None

    for root in run_roots:
        root = Path(root)
        if not root.is_dir():
            raise bench.RunnerError(f"{root}: not a directory of runs")
        for directory, subdirectories, files in os.walk(root, onerror=refuse):
            subdirectories.sort()
            if name in files:
                yield Path(directory) / name


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise bench.RunnerError(
            f"{path}: cannot be read: {getattr(exc, 'strerror', None) or exc}"
        ) from None


def run_results(run_roots: Sequence[Path]) -> list[dict[str, Any]]:
    """The ``result.json`` of every run under ``run_roots``."""
    files = _private_files(run_roots, disclosure_files.RESULT_FILE)
    return disclosure_files.read_results([path.parent for path in files])


def _package(server: Any) -> tuple[str, str]:
    return server.package["registry"], server.package["name"]


def dropped_servers(
    results: list[dict[str, Any]],
    disclosure: Any,
    names: Collection[str] | Mapping[str, Any] | None = None,
) -> set[str]:
    """The servers with a finding in ``results`` that is not ``freigegeben``, whatever the stage
    or transport. A finding the disclosure file does not list is a ``RunnerError``:
    nothing can be exported until it has an entry.

    With ``names`` (the servers of the definitions) only the results of those servers count:
    those of any other server are never exported and need no entry. Given as the definitions
    themselves (name to ``bench.Server``), a server that drops out takes every definition of the
    same package (``registry`` and ``name``) with it: ``github`` and ``github-http`` are one
    package over two transports."""
    if names is not None:
        results = [result for result in results if result.get("server") in names]
    found = disclosure_files.finding_keys(results)
    status = {disclosure_files.entry_key(e): e["status"] for e in disclosure.entries}
    missing = sorted(found - set(status))
    if missing:
        raise bench.RunnerError(
            f"{list(missing[0])}: not in the disclosure file; "
            f"{len(missing)} finding(s) without an entry, nothing is exported"
        )
    dropped = {key[0] for key in found if status[key] != RELEASED}
    if isinstance(names, Mapping):
        packages = {_package(names[name]) for name in dropped if name in names}
        dropped |= {name for name, server in names.items() if _package(server) in packages}
    return dropped


def _canary_ids(run_roots: Sequence[Path]) -> list[str]:
    ids: set[str] = set()
    for path in _private_files(run_roots, bench.CANARY_FILE):
        found = [line.strip() for line in _read_text(path).splitlines() if line.strip()]
        if not found:
            raise bench.RunnerError(f"{path}: no canary id in it")
        ids.update(found)
    return sorted(ids)


def _secret_digests(run_roots: Sequence[Path]) -> list[tuple[int, str]]:
    digests: set[tuple[int, str]] = set()
    for path in _private_files(run_roots, bench.SECRETS_FILE):
        for number, line in enumerate(_read_text(path).splitlines(), start=1):
            length, _, digest = line.partition(" ")
            if not length.isascii() or not length.isdigit() or not digest:
                raise bench.RunnerError(f"{path}: line {number} is not '<length> <sha256>'")
            digests.add((int(length), digest))
    return sorted(digests)


def _keys(key_paths: Sequence[Path]) -> list[bytes]:
    keys: list[bytes] = []
    for path in key_paths:
        refusal = bench.key_refusal(Path(path))
        if refusal is not None:
            raise bench.RunnerError(refusal)
        keys.append(bench.read_key(Path(path)))
    return keys


def _dropped_names(servers: dict[str, Any], dropped: Collection[str]) -> dict[str, list[str]]:
    """For each dropped server, by its name, the marks it is known by besides: its package and
    image tag, and its source repository unless a server that stays comes from the same one. A
    server that the definitions do not name is known by its name alone (no mark)."""
    kept_sources = {
        server.source["repository"] for name, server in servers.items() if name not in dropped
    }
    names: dict[str, list[str]] = {}
    for name in sorted(dropped):
        server = servers.get(name)
        if server is None:
            names[name] = []
            continue
        known = [server.package["name"], server.image_tag]
        if server.source["repository"] not in kept_sources:
            known.append(server.source["repository"])
        names[name] = known
    return names


def _definitions(definitions_path: Path) -> dict[str, Any]:
    try:
        return bench.load_definitions(Path(definitions_path))
    except bench.DefinitionError as exc:
        raise bench.RunnerError(str(exc)) from None


def forbidden_for(
    definitions_path: Path,
    run_roots: Sequence[Path],
    key_paths: Sequence[Path],
    disclosure: Any,
) -> Any:
    """Everything that must not be in the exported tree, as ``export_check.Forbidden``.

    Canary ids and secrets come from every run under ``run_roots``; the values of ``launch.env``
    from every definition; the keys after ``bench.key_refusal``. The host paths are the
    repository, the home, the directory of the definitions, each run root and each key file,
    resolved, but not the temporary directory: ``/tmp`` is a path inside the container as well.
    """
    definitions_path = Path(definitions_path)
    servers = _definitions(definitions_path)
    dropped = dropped_servers(run_results(run_roots), disclosure, servers)
    host_paths = [
        bench.REPO_ROOT.resolve(),
        Path.home().resolve(),
        definitions_path.resolve().parent,
        *(Path(root).resolve() for root in run_roots),
        *(Path(path).resolve() for path in key_paths),
    ]
    try:
        return export_check.Forbidden(
            canary_ids=_canary_ids(run_roots),
            hmac_keys=_keys(key_paths),
            env_values=sorted({value for server in servers.values() for _, value in server.env}),
            secret_digests=_secret_digests(run_roots),
            host_paths=[str(path) for path in dict.fromkeys(host_paths)],
            dropped=_dropped_names(servers, dropped),
            released=disclosure_files.released(disclosure),
        )
    except ValueError as exc:
        raise bench.RunnerError(f"cannot say what the export must not hold: {exc}") from None


# -- the public form ------------------------------------------------------------------------


def _kept(definitions_path: Path, keep: Collection[str]) -> dict[str, Any]:
    servers = _definitions(definitions_path)
    unknown = sorted(set(keep) - set(servers))
    if unknown:
        raise bench.RunnerError(f"{definitions_path}: no server {unknown[0]!r}")
    if not keep:
        raise bench.RunnerError(f"{definitions_path}: no server stays; nothing to export")
    return {name: server for name, server in servers.items() if name in keep}


def public_definitions(definitions_path: Path, keep: set[str]) -> str:
    """``versions.yaml`` with exactly the servers in ``keep``, every value of ``launch.env``
    replaced by ``bench.ENV_PLACEHOLDER`` (the names stay), ``image.context`` at
    ``servers/<name>`` and ``stage_b.script`` at ``scripts/<file>`` as in :func:`public_files`.
    Comments are not taken along."""
    import yaml

    definitions_path = Path(definitions_path)
    _kept(definitions_path, keep)
    try:
        text = definitions_path.read_text(encoding="utf-8")
        data = parse_yaml(text, source=str(definitions_path))
    except (OSError, ValueError, ScenarioError) as exc:
        raise bench.RunnerError(f"{definitions_path}: cannot be read: {exc}") from None
    servers = []
    for item in data["servers"]:
        if item["name"] not in keep:
            continue
        launch = dict(item["launch"])
        if launch.get("env"):
            launch["env"] = dict.fromkeys(launch["env"], bench.ENV_PLACEHOLDER)
        item = {**item, "launch": launch, "image": {**item["image"]}}
        # Where :func:`public_files` puts them, so that the file loads in the exported tree.
        item["image"]["context"] = f"servers/{item['name']}"
        stage = item.get("stage_b")
        if isinstance(stage, dict) and stage.get("script") is not None:
            item["stage_b"] = {**stage, "script": f"scripts/{Path(stage['script']).name}"}
        servers.append(item)
    return yaml.safe_dump(
        {**data, "servers": servers}, sort_keys=False, allow_unicode=True, width=1000
    )


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise bench.RunnerError(f"{path}: cannot be read: {exc.strerror or exc}") from None


def public_files(definitions_path: Path, keep: set[str]) -> dict[str, bytes]:
    """For each server in ``keep`` the ``Dockerfile`` of its context, as
    ``servers/<name>/Dockerfile``, and its script of stage B, as ``scripts/<file>``. Nothing
    else of the context. Two scripts of one file name and another content are refused."""
    files: dict[str, bytes] = {}
    for name, server in sorted(_kept(Path(definitions_path), keep).items()):
        files[f"servers/{name}/Dockerfile"] = _read_bytes(server.image_context / "Dockerfile")
        stage = server.stage_b
        if stage is None or stage.script is None:
            continue
        target = f"scripts/{Path(stage.script).name}"
        content = _read_bytes(stage.script)
        if files.setdefault(target, content) != content:
            raise bench.RunnerError(f"{target}: two scripts of this name and another content")
    return files


# -- the export -----------------------------------------------------------------------------

NONE_RELEASED = "No server is released."


def server_split(
    definitions_path: Path, run_roots: Sequence[Path], disclosure: Any
) -> tuple[list[str], list[str]]:
    """The servers of the definitions that stay and those that drop out, each sorted; a server
    drops out with every definition of its package (:func:`dropped_servers`)."""
    servers = _definitions(Path(definitions_path))
    dropped = dropped_servers(run_results(run_roots), disclosure, servers)
    stay = sorted(name for name in servers if name not in dropped)
    return stay, sorted(name for name in servers if name in dropped)


def _write(path: Path, data: bytes | str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            path.write_bytes(data)
    except OSError as exc:
        raise bench.RunnerError(f"{path}: cannot be written: {exc.strerror or exc}") from None


def _copy_runs(tree: Path, stay: Collection[str], run_roots: Sequence[Path]) -> None:
    """``results/<server>/<stage>-<run>/`` with ``result.json`` and ``container.json`` of each
    run of the servers that stay: the runs ``report.collect`` shows, per server and stage the
    last ``RUNS_COMPARED`` ones that are not ``retried``."""
    report = bench._sibling("report")
    for name in sorted(stay):
        found: dict[str, list[tuple[str, Path, dict[str, Any]]]] = {"A": [], "B": []}
        for root in run_roots:
            parent = Path(root) / name
            try:
                runs = sorted(entry for entry in parent.iterdir() if entry.is_dir())
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise bench.RunnerError(
                    f"{parent}: cannot be read: {exc.strerror or exc}"
                ) from None
            for run in runs:
                result = run / report.RESULT_FILE
                if not result.is_file():
                    continue
                data = report._read(result)
                if data["server"] != name or data.get("retried") is True:
                    continue
                found[data["stage"]].append((run.name, run, data))
        for stage in ("A", "B"):
            for run_name, run, _ in sorted(
                found[stage], key=lambda item: report.run_order(item[0], item[2])
            )[-report.RUNS_COMPARED :]:
                target = tree / bench.RESULTS_DIR / name / f"{stage}-{run_name}"
                if target.exists():
                    raise bench.RunnerError(f"{target.relative_to(tree)}: two runs of this name")
                _write(target / report.RESULT_FILE, _read_bytes(run / report.RESULT_FILE))
                _write(target / bench.COMPANION, _read_bytes(run / bench.COMPANION))


def _build(tree: Path, definitions_path: Path, run_roots: Sequence[Path], stay: list[str]) -> None:
    report = bench._sibling("report")
    servers = _definitions(definitions_path)
    rows = report.collect({name: servers[name] for name in stay}, run_roots)
    page = report.html(rows, True)
    table = report.markdown(rows, True)
    if not stay:
        page = page.replace("</body>", f"<p>{NONE_RELEASED}</p></body>")
        table += f"\n{NONE_RELEASED}\n"
    _write(tree / "report.html", page)
    _write(tree / "report.md", table)
    _copy_runs(tree, stay, run_roots)
    if stay:
        _write(tree / bench.DEFINITIONS_FILE, public_definitions(definitions_path, set(stay)))
        for name, content in public_files(definitions_path, set(stay)).items():
            _write(tree / name, content)


def _problems(problems: Sequence[Any]) -> str:
    return "; ".join(
        f"{p.file}: {p.rule}" + (f" at {p.where}" if p.where else "") + f" ({p.hint})"
        for p in problems
    )


def export(
    definitions_path: Path,
    run_roots: Sequence[Path],
    disclosure_path: Path,
    key_paths: Sequence[Path],
    out: Path,
) -> Path:
    """Build the public tree and put it at ``out``, replacing what is there.

    The tree is built in ``.<out>.partial`` beside ``out``: ``results/`` with the runs of the
    servers that stay, ``report.html`` and ``report.md`` over them (with excerpts), and the public
    definitions and files. With no server left there are no definitions and files, and the
    report says so. ``export_check.check_tree`` looks at it; with a problem the tree is deleted,
    ``out`` is as it was and a ``RunnerError`` lists the problems (never a value). Without one
    the old ``out`` is renamed, the tree takes its place and the old one is deleted."""
    definitions_path, out = Path(definitions_path), Path(out)
    disclosure = disclosure_files.load(Path(disclosure_path))
    forbidden = forbidden_for(definitions_path, run_roots, key_paths, disclosure)
    stay, _ = server_split(definitions_path, run_roots, disclosure)
    partial = out.with_name("." + out.name + ".partial")
    old = out.with_name("." + out.name + ".old")
    for stale in (partial, old):
        _remove(stale)
    try:
        partial.mkdir(parents=True)
    except OSError as exc:
        raise bench.RunnerError(f"{partial}: cannot be written: {exc.strerror or exc}") from None
    try:
        _build(partial, definitions_path, run_roots, stay)
        try:
            problems = export_check.check_tree(partial, forbidden)
        except ValueError as exc:
            raise bench.RunnerError(f"the export cannot be checked: {exc}") from None
        if problems:
            raise bench.RunnerError(
                f"the export holds {len(problems)} problem(s), nothing is written: "
                + _problems(problems)
            )
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    had_old = os.path.lexists(out)
    try:
        if had_old:
            os.rename(out, old)
        os.rename(partial, out)
    except OSError as exc:
        if had_old and not os.path.lexists(out):
            os.rename(old, out)
        shutil.rmtree(partial, ignore_errors=True)
        raise bench.RunnerError(f"{out}: cannot be replaced: {exc.strerror or exc}") from None
    _remove(old)
    return out


def _remove(path: Path) -> None:
    """Delete a leftover of ours (a file, a link or a tree); what cannot be deleted stops it."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
    except OSError as exc:
        raise bench.RunnerError(f"{path}: cannot be deleted: {exc.strerror or exc}") from None
