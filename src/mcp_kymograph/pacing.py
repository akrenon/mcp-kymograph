"""Pacing: how often this tool may knock on somebody else's door.

Every HTTP run whose host is not a loopback literal is paced, an endpoint entry and
``drive --http`` alike, with an engagement file or without one; loopback runs are the operator's
own and are not. A run takes one of ``runs_per_origin`` slots for its origin before it connects
and keeps it to its end, and starts no sooner than ``min_interval_seconds`` after the latest end
among the slots. The origin is ``scheme://host:port``; the identity is not part of it, so two
identities of one engagement share the slots.

The slots are files under ``<out-dir>/.pacing/``, one lock file per slot, held with
``fcntl.flock``: the kernel lets go of a lock when its process ends, whatever the way. A run
writes a start note into its slot when it takes it and its end time when it lets go. The note
carries the end time the slot held before (``started <t> after <end|none>``), so a run that
finds the slot held still knows the last end in it: a held slot counts with the end time in it,
or the one in its note. A start note in a slot nobody holds is a run that did not end cleanly
(killed, crashed): its end counts as the moment the next run finds the note.

Reading the slots, choosing one and writing the note (or putting a slot back) happen under a
short lock per origin, ``<digest>.lock`` in the same directory, so no run sees a slot between
its ``flock`` and its note. The lock is not held while a run waits for the interval, and
:meth:`Slot.release` does not need it. Only processes that share an ``--out-dir`` see each
other, and an engagement has one.

Nothing here connects, and no name is resolved: the origin is the text of the URL.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import math
import os
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:  # pragma: no cover - the platform decides
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock; the tool is not run there
    fcntl = None  # type: ignore[assignment]

from mcp_kymograph.authorization import is_loopback
from mcp_kymograph.output import make_private_directories

#: What a run is paced by where the file is silent, or there is none.
DEFAULT_RUNS_PER_ORIGIN = 1
DEFAULT_MIN_INTERVAL_SECONDS = 10

#: The most slots one origin may have (``pacing.runs_per_origin``); each is a file.
MAX_RUNS_PER_ORIGIN = 64

#: The directory under ``--out-dir`` and the mode of its files.
SLOT_DIRECTORY = ".pacing"
SLOT_MODE = 0o600

#: How often a busy origin is looked at again.
POLL_SECONDS = 0.1

#: How often the cleanup after a refusal tries the origin lock before it gives up.
CLEANUP_ATTEMPTS = 5

#: Why a run waited, as ``paced.why`` says it.
INTERVAL = "interval"
ORIGIN_BUSY = "origin_busy"

#: What a held slot contains while its run goes on; an end time is a bare number, never this.
#: The full note is ``started <time> after <end time or none>``.
START_NOTE = "started"

#: The width a slot's content is padded to, so that one write replaces it whole (a slot that is
#: held is read by other runs, and must never be seen cut off).
_WIDTH = 128

_DEFAULT_PORTS = {"http": 80, "https": 443}


class PacingRefused(Exception):
    """The wait would be longer than the step timeout: the run is refused, reason ``pacing``."""


class _LockBusy(Exception):
    """The lock of an origin is held by another process and did not free in the time given."""


@dataclass(frozen=True, slots=True)
class Pacing:
    """What a paced run is held to, and where the values came from."""

    runs_per_origin: int = DEFAULT_RUNS_PER_ORIGIN
    min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS
    #: ``file`` when the engagement file gave at least one of the two, otherwise ``default``.
    source: str = "default"
    #: Which of the two the file gave, for ``engagement show``.
    from_file: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """What ``run_started.pacing`` records."""
        return {
            "runs_per_origin": self.runs_per_origin,
            "min_interval_seconds": self.min_interval_seconds,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class Paced:
    """A wait that happened: ``paced{seconds, why}`` in the recording."""

    seconds: float
    why: str


def settings(declared: Mapping[str, Any] | None) -> Pacing:
    """The values of a run: the file's ``pacing`` (already validated by the engagement reader)
    where it speaks, 1 and 10 where it is silent."""
    declared = declared or {}
    runs = declared.get("runs_per_origin")
    interval = declared.get("min_interval_seconds")
    given = tuple(
        name
        for name, value in (("runs_per_origin", runs), ("min_interval_seconds", interval))
        if value is not None
    )
    return Pacing(
        runs_per_origin=DEFAULT_RUNS_PER_ORIGIN if runs is None else runs,
        min_interval_seconds=DEFAULT_MIN_INTERVAL_SECONDS if interval is None else interval,
        source="file" if given else "default",
        from_file=given,
    )


def applies(url: str | None) -> bool:
    """Whether a run against ``url`` is paced: an HTTP run whose host is not a loopback literal.
    A URL without a host is not one that can be called loopback, so it is paced."""
    return url is not None and not is_loopback(urlsplit(url).hostname)


def origin_of(url: str) -> str:
    """``scheme://host:port`` of a URL, the host in lower case, the port the scheme's own where
    the URL names none. The text of the URL; nothing is resolved."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    shown = f"[{host}]" if ":" in host else host
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{scheme}://{shown}:{port or _DEFAULT_PORTS.get(scheme, 0)}"


def _wall() -> float:
    return time.time()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class Slot:
    """One slot, held, with the start note in its file. :meth:`release` replaces the note with the
    run's end time and lets go. It does not take the origin lock: the content is replaced by one
    write, so a run reading it sees the note or the end time, whole."""

    def __init__(
        self, descriptor: int, paced: Paced | None, clock: Callable[[], float] | None = None
    ) -> None:
        self._descriptor: int | None = descriptor
        #: The wait this run made to get here, or None for a run that did not wait.
        self.paced = paced
        self._clock = clock or _wall

    def release(self) -> None:
        """Write the end time and unlock. May be called again."""
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        try:
            _write_quietly(descriptor, f"{self._clock()!r}\n")
        finally:
            os.close(descriptor)  # closing the descriptor drops the flock

    def __enter__(self) -> Slot:
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


@dataclass(frozen=True, slots=True)
class _Taken:
    """A slot taken: its descriptor and number, the end time it held (None: none known), and the
    latest end among all the slots of the origin (None: none known)."""

    descriptor: int
    number: int
    before: float | None
    latest: float | None


def acquire(
    out_dir: str | Path,
    url: str,
    pacing: Pacing,
    step_timeout: float,
    *,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> Slot:
    """Take a slot for ``url``'s origin, waiting as long as the rules say, or raise
    :class:`PacingRefused`.

    Reading the slots, choosing one and writing its start note (:func:`_take`) happen under the
    origin's lock, which is let go before any waiting. An origin is busy when the runs holding
    slots are as many as ``runs_per_origin`` or more (:func:`_take`); it is waited for, polling,
    up to ``step_timeout``. The note carries the end time the slot held.
    Then the interval: ``min_interval_seconds`` after the latest end among the slots, where a
    slot held by another run counts with the end time in it or in its note, and a note nobody
    holds counts as the moment it was found. A wait longer than ``step_timeout`` is refused and
    the slot put back, under the origin lock, with the end time it held (the run never was). The
    origin lock is tried without blocking, every :data:`POLL_SECONDS`: up to ``step_timeout`` when
    a slot is taken, at most :data:`CLEANUP_ATTEMPTS` times when one is put back (then the start
    note stays and counts as a dead run's). A slot that cannot be read, or whose start note cannot
    be written whole, raises :class:`OSError`: the run is not started, and nothing is written
    back (:func:`_take`). The two limits are each the step's own: a run that was held up and
    then found the interval still open can wait for both. ``clock`` (wall time, as the slot files
    hold it) and ``sleep`` are injectable; the wait reported is the clock's.
    """
    clock = clock or _wall
    sleep = sleep or _sleep
    origin = origin_of(url)
    digest = hashlib.sha256(origin.encode("utf-8")).hexdigest()
    directory = Path(out_dir).expanduser() / SLOT_DIRECTORY
    make_private_directories(directory)
    _make_private(directory)
    started = clock()
    taken = None
    busy = False
    while taken is None:
        try:
            with _origin_lock(directory, digest, clock, sleep, started + step_timeout):
                taken = _take(directory, digest, pacing.runs_per_origin, clock)
        except _LockBusy:
            raise PacingRefused(
                f"the slots of {origin} are locked by another process and did not free "
                f"within --step-timeout ({step_timeout:g} s); nothing was started"
            ) from None
        if taken is None:
            busy = True
            if clock() - started >= step_timeout:
                raise PacingRefused(
                    f"{origin} is in use by as many runs as runs_per_origin allows "
                    f"({pacing.runs_per_origin}), or more, and did not free within "
                    f"--step-timeout ({step_timeout:g} s); nothing was started"
                )
            sleep(POLL_SECONDS)
    try:
        latest = taken.latest
        wait = 0.0 if latest is None else latest + pacing.min_interval_seconds - clock()
        if wait > step_timeout:
            raise PacingRefused(
                f"the last run against {origin} ended less than min_interval_seconds "
                f"({pacing.min_interval_seconds:g} s) ago; the next may start in {wait:.0f} s, "
                f"which is more than --step-timeout ({step_timeout:g} s); nothing was started"
            )
        if wait > 0:
            sleep(wait)
    except BaseException:
        try:
            # never hangs, never replaces the exception: if the slot cannot be put back, its start
            # note stays and counts as a dead run's, the full interval
            with (
                contextlib.suppress(_LockBusy, OSError),
                _origin_lock(directory, digest, clock, sleep, attempts=CLEANUP_ATTEMPTS),
            ):
                _write_quietly(taken.descriptor, _put_back(taken.before))
        finally:
            os.close(taken.descriptor)
        raise
    waited = clock() - started
    paced = None
    if busy or wait > 0:
        paced = Paced(seconds=max(waited, 0.0), why=ORIGIN_BUSY if busy else INTERVAL)
    return Slot(taken.descriptor, paced, clock)


def _make_private(directory: Path) -> None:
    """Set 0700 on a directory that was there already (``make_private_directories`` sets no mode
    on one that exists): the names of the lock files are digests of origins, and other local
    users must not read them to test a guess. Through the descriptor, so a link in its place is
    refused and a directory of another user fails at ``fchmod``; both are an ``OSError``."""
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


def _path(directory: Path, digest: str, number: int) -> Path:
    return directory / f"{digest}.{number}.lock"


@contextlib.contextmanager
def _origin_lock(
    directory: Path,
    digest: str,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    deadline: float | None = None,
    attempts: int | None = None,
) -> Iterator[None]:
    """The short lock of one origin, ``<digest>.lock``: held while slots are read and written, and
    never while a run waits or runs. Tried without blocking, every ``POLL_SECONDS``, until the
    clock reaches ``deadline`` or ``attempts`` tries are made; then :class:`_LockBusy`."""
    descriptor = os.open(
        directory / f"{digest}.lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        SLOT_MODE,
    )
    try:
        os.fchmod(descriptor, SLOT_MODE)
        tried = 0
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                tried += 1
                if (attempts is not None and tried >= attempts) or (
                    deadline is not None and clock() >= deadline
                ):
                    raise _LockBusy from None
                sleep(POLL_SECONDS)
        yield
    finally:
        os.close(descriptor)  # closing the descriptor drops the flock


def _write(descriptor: int, text: str) -> None:
    """Replace the content of a slot file, in one write, strictly: an :class:`OSError` passes, and
    a write that is short counts as one (the message names no path). The start note is written
    like this, so that a run whose note is not in the slot does not start. Every other write goes
    through :func:`_write_quietly`, because it already fails closed: if the end time cannot be
    written in :meth:`Slot.release`, the start note stays and counts as a dead run's (the full
    interval); the same holds for putting a slot back after a refusal and for replacing a dead
    note in a slot that is not taken."""
    data = f"{text:<{_WIDTH}}".encode("ascii")
    if os.pwrite(descriptor, data, 0) != len(data):
        raise OSError(errno.EIO, "the start note was written short")


def _write_quietly(descriptor: int, text: str) -> None:
    """:func:`_write`, where a failure is left as it is: the run goes on, and the next one reads
    what is there."""
    with contextlib.suppress(OSError):
        _write(descriptor, text)


def _note(found: float, before: float | None) -> str:
    return f"{START_NOTE} {found!r} after {'none' if before is None else repr(before)}\n"


def _put_back(before: float | None) -> str:
    """What a slot gets back when its run never began: the end time it held, or nothing."""
    return "" if before is None else f"{before!r}\n"


def _finite(text: str) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _look(path: Path) -> tuple[int, bool, str]:
    """Open a slot file (made if it is not there) and try to lock it without waiting:
    ``(descriptor, whether the lock is ours, what the file holds)``. Under the origin lock a slot
    that cannot be locked is held by a run: nothing else locks one."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, SLOT_MODE)
    try:
        os.fchmod(descriptor, SLOT_MODE)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            free = True
        except OSError:  # BlockingIOError: held by another run
            free = False
        text = os.pread(descriptor, _WIDTH * 2, 0).decode("ascii", "replace")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, free, text


def _read(text: str, free: bool, found: float) -> tuple[float | None, bool]:
    """The end time a slot counts with, and whether that is ``found``; see :func:`_end_in`."""
    if not text.strip():
        return None, False
    if "\n" not in text:
        return found, True  # the line is not whole: a write that did not finish
    words = text.split("\n", 1)[0].split()
    if len(words) == 1:
        end = _finite(words[0])
        return (found, True) if end is None else (end, False)
    if len(words) == 4 and words[0] == START_NOTE and words[2] == "after":
        if _finite(words[1]) is None:
            return found, True
        if free:
            return found, True
        if words[3] == "none":
            return None, False
        after = _finite(words[3])
        return (found, True) if after is None else (after, False)
    return found, True


def _end_in(text: str, free: bool, found: float) -> float | None:
    """The end time a slot counts with. Only the first line is read, and it must be whole: it ends
    in a newline and is exactly one of two forms. An end time is one word that :func:`_finite`
    reads, and that is the end. A start note is ``started <time> after <end time or none>``; in a
    slot nobody holds it is a run that did not end cleanly: ``found``. In a slot a run holds it is
    the note's own ``after`` (what the slot held before that run), or None for ``none``. Anything
    else (a note or an end time cut short by a write that did not finish, over what was there; a
    line with no newline) is ``found``, free or held: it must never count as no end at all, and
    a cut-off number must never read as an end time. An empty slot, or one holding only white
    space, is None."""
    return _read(text, free, found)[0]


def _take(directory: Path, digest: str, slots: int, clock: Callable[[], float]) -> _Taken | None:
    """Look at every slot of the origin, one after the other (each is read and let go before the
    next is opened, so that a large ``runs_per_origin`` does not hold that many descriptors), and
    take the first free one among the run's own ``slots``, or return None when the runs holding
    slots are as many as ``slots`` or more. Only the slot taken stays open, and its start note is
    written after the last slot is looked at: a pass that raises, or ends in None, closes it and
    leaves it as it was. Called under the origin lock.

    The slots belong to the origin, not to a run's number: a slot from ``slots`` up to the most an
    engagement file allows is read when its file is there (a run with a larger
    ``runs_per_origin`` made it), counts as held or with its end time like any other, and is never
    made here. A free slot with a start note, or with anything else that is no end time, is a
    dead run's: it counts as ``found`` (now) and, where it is not the slot taken, is overwritten
    with that as its end, so it is counted once; if that write fails, nothing is said and the next
    run counts it again (it fails closed). A held slot counts with the end time in it or in its
    note (:func:`_end_in`).
    """
    found = clock()
    ends: list[float | None] = []
    held = 0
    chosen: tuple[int, int, float | None] | None = None  # descriptor, number, end it held
    try:
        for number in range(max(slots, MAX_RUNS_PER_ORIGIN)):
            path = _path(directory, digest, number)
            if number >= slots and not os.path.lexists(path):
                continue  # not one of this run's, and no run made it: not there
            descriptor, free, text = _look(path)
            end, dead = _read(text, free, found)
            ends.append(end)
            if not free:
                held += 1
            if free and chosen is None and number < slots:
                chosen = (descriptor, number, end)  # kept open: the run holds the lock
                continue
            try:
                if free and dead:
                    _write_quietly(descriptor, f"{found!r}\n")
            finally:
                os.close(descriptor)  # one at a time: only the slot taken stays open
    except BaseException:
        if chosen is not None:
            os.close(chosen[0])
        raise
    if chosen is None:
        return None
    if held >= slots:
        os.close(chosen[0])  # the origin is busy: the slot is let go as it was
        return None
    try:
        # only now: a pass that raised left it as it was; a note that is not written stops the run
        _write(chosen[0], _note(found, chosen[2]))
    except BaseException:
        # nothing is written back: a short note leaves its first bytes over the rest of what the
        # slot held, and only a second write over that rest could make a valid line of it (an
        # end time that is too early); as it is, :func:`_end_in` reads it as found, or the slot
        # is as it was
        os.close(chosen[0])
        raise
    known = [end for end in ends if end is not None]
    return _Taken(chosen[0], chosen[1], chosen[2], max(known) if known else None)
