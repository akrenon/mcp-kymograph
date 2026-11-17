"""What a server *is*, for the finding key: its own content, not the repository it lives in.

``server_version`` in a finding key is what a comparison between runs uses to tell "the
server changed" from "this tool changed". It is therefore taken from the server's own
content and from nothing else, in one of two forms — or, for a server whose content cannot be
read, said to be declared, in a third:

* **content** — for a server whose files sit in a repository it shares with other things
  (the project's own reference and poison servers sit in this one). The version is a SHA-256
  over exactly the files that make up the server, named one by one or as directories. The
  repository's commit is deliberately *not* used: every change to Kymograph would move it,
  the server's version would follow the tool's, and the separation the key exists for would
  be gone. A copy fetched with ``git archive <sha>`` is a way of delivering the files, not
  their identity.
* **revision** — for a server that *is* its repository, the natural content identity is the
  repository at a pinned commit: ``github.com/org/repo@<40 hex>``. A branch name or ``HEAD``
  is refused: it names a moving target, and a version that moves is no version.
* **endpoint** — for a server someone else runs, reached over HTTP. There is no content to
  read, so the version is not established at all: it is what the operator declares, or the
  word ``endpoint``, and the identity says which (``version_declared``). Everything that shows
  such a version labels it declared.

**The digest is over sorted pairs of relative path and content hash**. The
module layout is part of what a server is: two servers that hold the same bytes under
different names are two servers, and a digest over contents alone would let them collide on
one version — the dangerous direction. The other direction is harmless: a refactor that only
moves files counts as a new version, and a comparison between runs takes the version out of
its match anyway. Paths are relative to the deepest directory that holds every file, so where
the checkout lies does not matter; a single file is the one-pair case of the same rule.

Directories are walked; version control (``.git``), bytecode caches (``__pycache__``) and
compiled files (``.pyc``, ``.pyo``) are never part of a server. A symbolic link is refused
rather than followed: it could make the identity depend on a file outside what was named.
That holds for every component of a named path, not only the last: ``link/x.py`` with ``link``
pointing elsewhere is refused as well.

``tool_version`` stays this tool's own version, as in ``run_started``; nothing here reads it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

#: A server is a tree of source files, not a data set. Larger is a mistake.
MAX_CONTENT_FILES = 4096
MAX_CONTENT_BYTES = 64 * 1024 * 1024

#: Never part of what a server is.
EXCLUDED_DIRECTORIES = frozenset({".git", "__pycache__"})
EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})

#: ``host/path@sha``: a commit, spelled in full. Git's SHA-1 ids are 40 hex, SHA-256 ids 64.
_REVISION = re.compile(
    r"(?P<repo>[A-Za-z0-9][A-Za-z0-9._/:-]{0,250})@(?P<sha>[0-9a-f]{40}|[0-9a-f]{64})"
)


class IdentityError(ValueError):
    """A server identity that cannot be formed. Refused before the run starts."""


#: The version of an endpoint whose operator declared none: a word, so that it can never be
#: taken for a digest or a commit.
UNDECLARED_ENDPOINT_VERSION = "endpoint"


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    """How the server's version was established, and the version itself."""

    #: ``content``, ``revision`` or ``endpoint``.
    kind: str
    #: What goes into the finding key as ``server_version``.
    version: str
    #: For ``content``: how many files the digest covers. Recorded, so a reader can see the
    #: digest is over the server and not over one file of it by mistake.
    files: int = 0
    #: For ``endpoint``: the version the operator declared, or None. ``version`` is that string
    #: or :data:`UNDECLARED_ENDPOINT_VERSION`; this says which, without reading the string.
    version_declared: str | None = None

    def to_dict(self) -> dict[str, object]:
        written: dict[str, object] = {
            "kind": self.kind,
            "version": self.version,
            "files": self.files,
        }
        if self.kind == "endpoint":
            written["version_declared"] = self.version_declared
        return written


def from_content(paths: Sequence[str | Path], *, base: Path | None = None) -> ServerIdentity:
    """The digest over the files that make up a server, by relative path and content.

    Each file is hashed on its own; the identity is the hash over the sorted list of
    ``[relative path, file hash]`` pairs, written as JSON so that no file name — not even
    one with a line break in it — can be mistaken for a separator. Sorting makes the order
    the files were named in irrelevant. A file named twice, or reached twice, counts once.
    ``base`` is passed on to :func:`content_files`.
    """
    root, files = content_files(paths, base=base)
    pairs = []
    total = 0
    for file in files:
        try:
            content = file.read_bytes()
        except OSError as exc:
            raise IdentityError(
                f"{_shown(file, base)}: cannot read: {exc.strerror or exc}"
            ) from None
        total += len(content)
        if total > MAX_CONTENT_BYTES:
            raise IdentityError(f"server files larger than {MAX_CONTENT_BYTES} bytes together")
        pairs.append([file.relative_to(root).as_posix(), hashlib.sha256(content).hexdigest()])
    pairs.sort()
    combined = hashlib.sha256(json.dumps(pairs).encode("utf-8", "surrogatepass")).hexdigest()
    return ServerIdentity(kind="content", version=f"sha256:{combined}", files=len(pairs))


def content_files(
    paths: Sequence[str | Path], *, base: Path | None = None
) -> tuple[Path, list[Path]]:
    """The files that make up a server, and the deepest directory that holds them all.

    The pairs :func:`from_content` hashes are paths relative to that directory, so a copy
    that keeps them reproduces the identity — which is how a delivery is checked. ``base`` is
    the directory the caller put the paths together from, if it did: links are then looked for
    below it only, and a refusal names a path relative to it (:func:`_files`).
    """
    files = _files(paths, base)
    return Path(os.path.commonpath([str(file.parent) for file in files])), files


def _shown(path: Path, base: Path | None) -> str:
    """How a refusal writes a path: as it was named, or, with ``base``, relative to it.

    A caller that put the paths together from a directory of its own (the corpus manifest's)
    named only what lies below it, so that is all the refusal says: where the directory lies on
    this machine is not in the message, which may be kept beside a recording.
    """
    if base is None:
        return str(path)
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def _check_components(path: Path, base: Path | None) -> None:
    """Refuse a path in which any component, as it was named, is a symbolic link.

    "As named": a relative path counts from the working directory, an absolute one from the
    root, neither with the starting point itself; with ``base``, from that directory, which
    the path must lie under. What lies above the starting point is not part of what was named:
    the components of the working directory for a relative path, those of ``base`` for a path
    below it. An absolute path names every component from the root, so a link among them (a
    linked home or temporary directory) is refused like any other. ``..`` is not resolved
    first, so one that leads through a link is caught at the link; ``..`` itself stays allowed.
    """
    if base is None:
        current, parts = Path(), path.parts
        if path.is_absolute():
            current, parts = Path(path.anchor), parts[1:]
    else:
        try:
            parts = path.relative_to(base).parts
        except ValueError:
            raise IdentityError(f"{path.name}: not under the directory it was named in") from None
        current = base
    for part in parts:
        current = current / part
        if current.is_symlink():
            # The path once, up to the link: a refusal on a terminal is cut to a line, and a
            # long path written twice would push the reason off it.
            where = "" if current == path else f" on the way to {path.name}"
            raise IdentityError(
                f"{_shown(current, base)} is a symbolic link{where}; name what it points to instead"
            )


def _files(paths: Sequence[str | Path], base: Path | None = None) -> list[Path]:
    """Every file the named paths stand for, absolute and without duplicates.

    Every component of a named path is checked for a symbolic link, see
    :func:`_check_components`; ``base`` limits that to the components below it, for paths
    put together from a directory the caller already holds (the corpus manifest's), and a
    refusal then names a path relative to it, see :func:`_shown`.
    """
    if not paths:
        raise IdentityError("no server files named")
    found: dict[str, Path] = {}
    for name in paths:
        path = Path(name)
        _check_components(path, base)
        if path.is_file():
            resolved = path.resolve()
            found[str(resolved)] = resolved
        elif path.is_dir():
            for file in _walk(path, base):
                found[str(file)] = file
        else:
            raise IdentityError(f"{_shown(path, base)}: neither a file nor a directory")
        if len(found) > MAX_CONTENT_FILES:
            raise IdentityError(f"more than {MAX_CONTENT_FILES} server files")
    if not found:
        raise IdentityError(f"no files under {', '.join(_shown(Path(p), base) for p in paths)}")
    # In the order they were named and walked. The identity's order comes from sorting the
    # pairs in from_content, and only there: one place that defines it.
    return list(found.values())


def _walk(directory: Path, base: Path | None = None) -> list[Path]:
    files = []
    for current, directories, names in os.walk(directory, followlinks=False):
        here = Path(current)
        for name in list(directories):
            if (here / name).is_symlink():
                raise IdentityError(
                    f"{_shown(here / name, base)}: a symbolic link inside the server's files"
                )
        directories[:] = sorted(d for d in directories if d not in EXCLUDED_DIRECTORIES)
        for name in sorted(names):
            file = here / name
            if file.is_symlink():
                raise IdentityError(
                    f"{_shown(file, base)}: a symbolic link inside the server's files"
                )
            if file.suffix not in EXCLUDED_SUFFIXES:
                files.append(file.resolve())
    return files


def from_revision(spec: str) -> ServerIdentity:
    """``repo@sha`` for a server that is its whole repository, pinned to a full commit id."""
    match = _REVISION.fullmatch(spec.strip())
    if match is None:
        raise IdentityError(
            f"{spec!r} is not a pinned revision; expected repo@<full commit sha>, "
            "never a branch, a tag or HEAD"
        )
    return ServerIdentity(kind="revision", version=f"{match['repo']}@{match['sha']}")


def from_endpoint(url: str, version_declared: str | None) -> ServerIdentity:
    """A server someone else runs, at ``url``: there is no content to read and nothing to digest.

    The version is what the operator declares for the deployment, recorded as a claim — or
    :data:`UNDECLARED_ENDPOINT_VERSION` when nothing was declared. The same URL may serve other
    code tomorrow under the same declaration; the identity cannot say otherwise, and does not
    pretend to. The URL itself is not part of the version: it is on the server axis through the
    entry's launch digest (:mod:`mcp_kymograph.corpus`).
    """
    if not isinstance(url, str) or not url:
        raise IdentityError("an endpoint identity needs the endpoint's URL")
    if version_declared is not None and (
        not isinstance(version_declared, str) or not version_declared
    ):
        raise IdentityError("a declared version is a non-empty string, or none is declared")
    return ServerIdentity(
        kind="endpoint",
        version=UNDECLARED_ENDPOINT_VERSION if version_declared is None else version_declared,
        version_declared=version_declared,
    )
