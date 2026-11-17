"""Where a recording is allowed to land, and how the directory for it is created.

A recording is a verbatim log of someone else's traffic. The two ways that goes wrong are
committing it and syncing it, so the destination is checked before anything is written:

* **refused** when the destination sits in a git working tree without being covered by the
  ignore rules that actually apply there — asked of git itself, not guessed from names;
* **warned** when it looks like a place that leaves the machine on its own (the home
  directory itself, a desktop, a cloud-sync folder);
* **silent** otherwise.

Nothing is ever written into the destination directly. Every run gets its own subdirectory,
created fresh: a name that already exists is a refusal, never an overwrite. This module
never deletes and never truncates.

It also never prints. Decisions come back as :class:`Advisory` values so the CLI owns the
presentation and the recorder can put the same advisory into the event stream.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from mcp_kymograph.environment import helper_env

#: git's own storage, refused as a destination whether it is a directory or, in a linked
#: worktree, a file pointing somewhere else.
GIT_METADATA_DIR = ".git"

#: The run directory belongs to its owner alone, like the recording inside it.
DIR_MODE = 0o700

#: git is asked, not trusted to answer quickly. A destination on a stalled network mount
#: must not hang the run before it has begun.
GIT_TIMEOUT_SECONDS = 5.0

#: Matched against path components after lower-casing and removing separators, so
#: "OneDrive - Contoso" and "iCloud Drive" are recognised without listing every variant.
_CLOUD_PREFIXES = ("dropbox", "onedrive", "icloud", "nextcloud")

#: How iCloud Drive appears on macOS, where no single component names the provider.
_ICLOUD_PAIR = ("library", "mobiledocuments")


class Severity(str, Enum):
    REFUSAL = "refusal"
    WARNING = "warning"


class Reason(str, Enum):
    INSIDE_GIT_WORKTREE = "inside_git_worktree"
    INSIDE_GIT_METADATA = "inside_git_metadata"
    GIT_STATUS_UNKNOWN = "git_status_unknown"
    RUN_DIRECTORY_EXISTS = "run_directory_exists"
    UNUSABLE = "unusable"
    HOME_DIRECTORY = "home_directory"
    DESKTOP = "desktop"
    CLOUD_SYNC = "cloud_sync"


@dataclass(frozen=True, slots=True)
class Advisory:
    """One finding about a destination. The message carries no path, ever."""

    severity: Severity
    reason: Reason
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "reason": self.reason.value,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class RunLocation:
    """The directory a run may write into, plus what was noticed on the way."""

    run_id: str
    directory: Path
    events_path: Path
    advisories: tuple[Advisory, ...] = ()


class DestinationRefused(Exception):
    """Raised instead of writing to a destination that failed the check."""

    def __init__(self, advisory: Advisory) -> None:
        super().__init__(advisory.message)
        self.advisory = advisory


def run_directory_name(run_id: str, *, now: Callable[[], datetime] | None = None) -> str:
    stamp = (now() if now else datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{run_id}"


def new_run_id() -> str:
    return secrets.token_hex(4)


def inspect_destination(out_dir: Path, run_dir: Path) -> list[Advisory]:
    """Judge a destination without touching the filesystem beyond reading it.

    Both paths are needed: the git question is about the directory that would actually be
    created, while "this is your home directory" is about the destination the user named.
    """
    advisories: list[Advisory] = []

    git_advisory = _check_git(run_dir)
    if git_advisory is not None:
        advisories.append(git_advisory)

    advisories.extend(_check_location(out_dir))
    return advisories


def prepare_run(
    out_dir: Path,
    *,
    run_id: str | None = None,
    now: Callable[[], datetime] | None = None,
) -> RunLocation:
    """Check the destination, then create this run's directory. Never overwrites."""
    run_id = run_id or new_run_id()
    out_dir = out_dir.expanduser()
    run_dir = out_dir / run_directory_name(run_id, now=now)

    try:
        advisories = inspect_destination(out_dir, run_dir)
    except (OSError, RuntimeError) as exc:
        # A path that cannot even be resolved — a name too long, a symbolic link loop (which
        # Python before 3.13 reports as RuntimeError) — is not a place anything can be written.
        raise DestinationRefused(unusable(exc)) from None
    for advisory in advisories:
        if advisory.severity is Severity.REFUSAL:
            raise DestinationRefused(advisory)

    try:
        make_private_directories(out_dir)
        # os.mkdir, not makedirs(exist_ok=True): a name that is already taken must fail
        # here rather than let a second run write beside an earlier one's evidence.
        os.mkdir(run_dir, mode=DIR_MODE)
    except FileExistsError:
        raise DestinationRefused(
            Advisory(
                severity=Severity.REFUSAL,
                reason=Reason.RUN_DIRECTORY_EXISTS,
                message=(
                    f"A run directory named {run_dir.name} already exists. "
                    "Refusing to write beside or over an existing recording."
                ),
            )
        ) from None
    except OSError as exc:
        # A file where the directory should be, a place that cannot be created or written:
        # the operator's input was wrong, and nothing has been started yet to say otherwise.
        raise DestinationRefused(unusable(exc)) from None

    return RunLocation(
        run_id=run_id,
        directory=run_dir,
        events_path=run_dir / "events.jsonl",
        advisories=tuple(advisories),
    )


def unusable(exc: OSError | RuntimeError) -> Advisory:
    """A destination the system will not let us create or write into, and what it said — in
    its own words where it has them, never with the path."""
    why = getattr(exc, "strerror", None) or (
        "a symbolic link loop" if isinstance(exc, RuntimeError) else type(exc).__name__
    )
    return Advisory(
        severity=Severity.REFUSAL,
        reason=Reason.UNUSABLE,
        message=f"The output directory cannot be created or written into ({why}). "
        "Nothing was started.",
    )


def make_private_directories(path: Path) -> None:
    """Create ``path`` and every missing level above it, each 0700 from the moment it exists.

    ``Path.mkdir(mode=..., parents=True)`` applies the mode only to the last component; every
    level it creates on the way gets the process default instead. No recording is ever
    written into such a parent — the run directory below it is created 0700 by ``os.mkdir``,
    and the file inside that 0600 by ``os.open`` — but a directory we created is a directory
    we should not leave open, and this closes the gap without a chmod after the fact.
    """
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(missing):
        # Suppressed: another process may have won the race to create it. Anything else —
        # a missing parent, a permission error — is a real refusal and must surface.
        with contextlib.suppress(FileExistsError):
            os.mkdir(directory, mode=DIR_MODE)


# -- git ------------------------------------------------------------------------------


def _check_git(run_dir: Path) -> Advisory | None:
    """Ask git whether the destination would be committable, and refuse if it would.

    Fail closed: when a ``.git`` sits above the destination but git cannot give a clear
    answer — missing binary, timeout, unexpected exit status — the run is refused. A
    recording that might end up in a public repository is the outcome worth avoiding, and
    an operator who sees this can point ``--out-dir`` somewhere unambiguous in seconds.
    """
    resolved = run_dir.expanduser().resolve()
    anchor = _existing_ancestor(resolved)
    has_git_metadata = _has_git_ancestor(resolved)

    # Checked on the resolved path, so a symlink cannot walk a destination into .git
    # behind our back — the same bypass the ignore check already has to defend against.
    if any(part == GIT_METADATA_DIR for part in resolved.parts):
        return _git_metadata()

    git = shutil.which("git")
    if git is None:
        return _git_unknown() if has_git_metadata else None

    metadata = _inside_git_metadata(git, resolved, anchor)
    if metadata is not None:
        return metadata

    inside = _run_git([git, "rev-parse", "--is-inside-work-tree"], cwd=anchor)
    if inside is None:
        return _git_unknown() if has_git_metadata else None
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        # Not a working tree (or a bare repository, which has nothing to commit into).
        return None

    ignored = _run_git([git, "check-ignore", "--quiet", "--", str(resolved)], cwd=anchor)
    if ignored is None:
        return _git_unknown()
    if ignored.returncode == 0:
        return None
    if ignored.returncode == 1:
        return Advisory(
            severity=Severity.REFUSAL,
            reason=Reason.INSIDE_GIT_WORKTREE,
            message=(
                "The output directory is inside a git working tree and is not covered by "
                "the ignore rules that apply there. Recordings must not become committable."
            ),
        )
    return _git_unknown()


def _inside_git_metadata(git: str, resolved: Path, anchor: Path) -> Advisory | None:
    """Refuse a destination inside git's own storage, wherever that storage actually is.

    A linked worktree has a ``.git`` *file* pointing at ``<main>/.git/worktrees/<name>``, so
    the name check above never sees a ``.git`` component on the way there. Asking git for
    the directory it really uses covers that case and the ordinary one alike.
    """
    for argument in ("--absolute-git-dir", "--git-common-dir"):
        result = _run_git([git, "rev-parse", argument], cwd=anchor)
        if result is None or result.returncode != 0:
            continue
        reported = result.stdout.strip()
        if not reported:
            continue
        git_dir = Path(reported)
        if not git_dir.is_absolute():
            git_dir = anchor / git_dir
        git_dir = git_dir.resolve()
        if resolved == git_dir or git_dir in resolved.parents:
            return _git_metadata()
    return None


def _git_metadata() -> Advisory:
    return Advisory(
        severity=Severity.REFUSAL,
        reason=Reason.INSIDE_GIT_METADATA,
        message=(
            "The output directory sits inside git's own storage. Nothing there is committed, "
            "but nothing there is cleaned up either, every archive of the repository carries "
            "it along, and nobody looks there for recordings."
        ),
    )


def _git_unknown() -> Advisory:
    return Advisory(
        severity=Severity.REFUSAL,
        reason=Reason.GIT_STATUS_UNKNOWN,
        message=(
            "The output directory sits under a git repository, but whether it is ignored "
            "could not be established. Refusing rather than risk a committable recording."
        ),
    )


def _run_git(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str] | None:
    """Run one git command. Returns ``None`` when git could not be asked at all."""
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, absolute binary, never a shell
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=helper_env(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _existing_ancestor(path: Path) -> Path:
    """The nearest directory that exists, since git needs somewhere to be run from."""
    for candidate in (path, *path.parents):
        if candidate.is_dir():
            return candidate
    return Path(path.anchor or ".")


def _has_git_ancestor(path: Path) -> bool:
    # A ``.git`` file rather than a directory is a linked worktree; both count.
    return any((candidate / ".git").exists() for candidate in (path, *path.parents))


# -- places that leave the machine on their own ----------------------------------------


def _check_location(out_dir: Path) -> list[Advisory]:
    resolved = out_dir.expanduser().resolve()
    parts = [_normalise(part) for part in resolved.parts]
    advisories: list[Advisory] = []

    if resolved == Path.home().expanduser().resolve():
        advisories.append(
            Advisory(
                severity=Severity.WARNING,
                reason=Reason.HOME_DIRECTORY,
                message=(
                    "The output directory is your home directory itself. Recordings will "
                    "be created among your personal files."
                ),
            )
        )

    if "desktop" in parts:
        advisories.append(
            Advisory(
                severity=Severity.WARNING,
                reason=Reason.DESKTOP,
                message="The output directory is on the desktop, in plain view.",
            )
        )

    if _looks_cloud_synced(parts):
        advisories.append(
            Advisory(
                severity=Severity.WARNING,
                reason=Reason.CLOUD_SYNC,
                message=(
                    "The output directory looks like a cloud-sync folder. Recordings "
                    "placed here will be uploaded to a third party."
                ),
            )
        )

    return advisories


def _looks_cloud_synced(parts: list[str]) -> bool:
    if any(part.startswith(_CLOUD_PREFIXES) for part in parts):
        return True
    pairs = zip(parts, parts[1:], strict=False)  # deliberately ragged: adjacent pairs
    return any(pair == _ICLOUD_PAIR for pair in pairs)


def _normalise(part: str) -> str:
    return "".join(character for character in part.lower() if character.isalnum())
