"""What the web interface finds under ``--runs``: recordings and fleets, by a bounded walk.

The walk goes at most :data:`MAX_DEPTH` directories deep and follows **no** symbolic link, to
a directory or to a file. It looks for two names and nothing else: ``events.jsonl``, a run's
recording, and ``fleet.json`` in a directory named for its fleet. A run is named by its
``ref``, the POSIX path of its directory relative to ``--runs``; a ref is looked up in what the
walk found, never joined onto a path, so no ref can name a file the walk did not find.

A store row names its recording by the path given at ingest, often relative to wherever ingest
ran. It is resolved under ``--runs`` only (:func:`resolve_filed`) and never looked for anywhere
else. Every file is opened for reading, without following a link, and only if it is a regular
file when it is opened.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

#: How many directories below ``--runs`` the walk descends. A fleet's job lies three deep
#: (``<fleet id>/<NNN>-<entry>/<stamp>-<run id>/events.jsonl``); five leaves room for an
#: out-dir of out-dirs and goes no further.
MAX_DEPTH = 5

RECORDING = "events.jsonl"
FLEET_FILE = "fleet.json"

#: A fleet's ``fleet.json`` is read whole or not at all; one larger than this is not read.
MAX_FLEET_BYTES = 64 * 1024 * 1024

#: The ref of a recording directly in ``--runs``.
ROOT_REF = "."


@dataclass(frozen=True)
class Found:
    """Every recording and every ``fleet.json`` the walk found, by name."""

    root: Path
    #: ref → the recording's path.
    recordings: dict[str, Path]
    #: The name of the directory holding a ``fleet.json`` → (its ref, the file's path), each.
    fleets: dict[str, tuple[tuple[str, Path], ...]]
    #: Directories the walk could not list, as refs: what is in them was not found.
    unreadable: tuple[str, ...] = ()


def search(root: Path) -> Found:
    """Walk ``root`` at most :data:`MAX_DEPTH` directories deep, following no symbolic link.

    A directory that cannot be listed is passed by and named in ``unreadable``: what is in it
    was not found, a ref into it names nothing, and a listing says it is not complete.
    """
    recordings: dict[str, Path] = {}
    fleets: dict[str, list[tuple[str, Path]]] = {}
    unreadable: list[str] = []
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while pending:
        directory, parts = pending.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
        except OSError:
            unreadable.append("/".join(parts) or ROOT_REF)
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if len(parts) < MAX_DEPTH:
                        pending.append((Path(entry.path), (*parts, entry.name)))
                elif entry.is_file(follow_symlinks=False):
                    ref = "/".join(parts) or ROOT_REF
                    if entry.name == RECORDING:
                        recordings[ref] = Path(entry.path)
                    elif entry.name == FLEET_FILE and parts:
                        fleets.setdefault(parts[-1], []).append((ref, Path(entry.path)))
            except OSError:
                continue
    return Found(
        root=root,
        recordings=dict(sorted(recordings.items())),
        fleets={name: tuple(sorted(found)) for name, found in fleets.items()},
        unreadable=tuple(sorted(unreadable)),
    )


class NotFound(LookupError):
    """A ref that names nothing the walk found, or that is not a ref at all."""


def lookup(found: Found, ref: object) -> Path:
    """The recording a ref names, or :class:`NotFound` — never a path built from the ref."""
    if not isinstance(ref, str) or not ref:
        raise NotFound("no run reference given")
    if ref.startswith("/") or ".." in ref.split("/"):
        raise NotFound(f"{ref!r} is not a run reference: refused, nothing outside --runs is read")
    path = found.recordings.get(ref)
    if path is None:
        raise NotFound(f"{ref!r}: no recording of that name was found under --runs")
    return path


def recording_path(ref: str) -> str:
    """The recording's path relative to ``--runs``, as a run's ``recording``."""
    return RECORDING if ref == ROOT_REF else f"{ref}/{RECORDING}"


def resolve_filed(found: Found, filed: str) -> tuple[str, Path] | None:
    """The recording a store row names, under ``--runs`` only, or None.

    It is the recording the walk found whose path relative to ``--runs`` is the longest suffix
    of the filed path's components, at least ``<run directory>/events.jsonl``; a filed run
    directory counts as its ``events.jsonl``. A recording directly in ``--runs`` is matched by
    the name of that directory.
    """
    parts = PurePosixPath(filed).parts
    if not parts:
        return None
    if parts[-1] != RECORDING:
        parts = (*parts, RECORDING)
    best: tuple[int, str, Path] | None = None
    for ref, path in found.recordings.items():
        if ref == ROOT_REF:
            name = os.path.basename(os.path.abspath(found.root))
            mine: tuple[str, ...] = (name, RECORDING) if name else (RECORDING,)
        else:
            mine = (*ref.split("/"), RECORDING)
        if len(mine) < 2 or len(mine) > len(parts) or parts[-len(mine) :] != mine:
            continue
        if best is None or len(mine) > best[0]:
            best = (len(mine), ref, path)
    return None if best is None else (best[1], best[2])


def _open(path: Path) -> int:
    """A descriptor for reading, opened without following a link, of a regular file only."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"{path}: not a regular file")
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def read_bytes(path: Path, limit: int | None = None) -> bytes:
    """A file's bytes, opened without following a link and only if it is a regular file.

    With ``limit``, at most ``limit + 1`` bytes are read, so that a caller can tell a file
    larger than the limit from one exactly as large.
    """
    with os.fdopen(_open(path), "rb") as handle:
        return handle.read() if limit is None else handle.read(limit + 1)


def first_line(path: Path, limit: int) -> bytes:
    """A file's first line, at most ``limit`` bytes of it, opened as :func:`read_bytes` opens."""
    with os.fdopen(_open(path), "rb") as handle:
        return handle.readline(limit)


@dataclass(frozen=True)
class FleetFile:
    """A fleet's ``fleet.json`` as found: its content, or why none was taken from it."""

    #: The file's content, when it was found, read whole and names this fleet; else None.
    content: dict[str, Any] | None
    #: Where it was looked for.
    looked_for: str
    #: Its ref under ``--runs`` when it was taken.
    ref: str | None = None
    #: Why a file found there was not taken, or None.
    problem: str | None = None
    #: The path under ``--runs`` of a file found there and not taken, or None.
    found: str | None = None


def fleet_file(found: Found, fleet: str, digest: str | None = None) -> FleetFile:
    """The ``fleet.json`` of one fleet, from a directory named for it under ``--runs``.

    Taken only when it is read whole, is a JSON object and its ``fleet`` is this fleet's id —
    and, given the ``digest`` the store filed the fleet under, only when its own ``digest`` is
    that one: a file in a directory of that name that says otherwise is not that fleet's, and
    nothing of it is used.
    """
    looked_for = f"{fleet}/{FLEET_FILE} under {found.root}"
    problem = where = None
    for ref, path in found.fleets.get(fleet, ()):
        where = f"{ref}/{FLEET_FILE}"
        try:
            raw = read_bytes(path, MAX_FLEET_BYTES)
        except OSError as exc:
            problem = f"{where} cannot be read: {exc.strerror or exc}"
            continue
        if len(raw) > MAX_FLEET_BYTES:
            problem = f"{where} is larger than {MAX_FLEET_BYTES} bytes and was not read"
            continue
        try:
            content = json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            problem = f"{where} is not JSON"
            continue
        if not isinstance(content, dict) or content.get("fleet") != fleet:
            problem = f"{where} does not name fleet {fleet}; it is not that fleet's"
            continue
        if digest is not None and content.get("digest") != digest:
            problem = (
                f"a fleet.json is there ({where}), but its digest is not the one the store "
                "filed this fleet under; it is not that fleet's"
            )
            continue
        return FleetFile(content, looked_for, ref=ref)
    return FleetFile(None, looked_for, problem=problem, found=where if problem else None)


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON value")
