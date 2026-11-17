"""What the receiver keeps on disk, and when it lets go of it.

One flat directory, mode 0700, every file 0600::

    reg-<prefix>.json      the registration, including the HMAC key
    state-<prefix>.json    the next sequence number and this hour's entry count
    entries-<prefix>.jsonl one entry per line
    counts.json            requests that were not recorded, one number per day, and under
                           ``over_connection_limit`` the connections past the limit, and under
                           ``unreadable_registration`` the registrations deleted for being damaged,
                           under ``sweep_error`` the registrations whose deadlines the sweep could
                           not enforce, under ``invalid_header_name`` the header names not stored,
                           under ``handler_error`` the requests whose handling raised,
                           and under ``unreadable_counts`` (one number) that a file whose content
                           was not a valid count was replaced
    .lock                  held while any of the above changes

The service and the commands (``register``, ``pull``, ``purge``) are separate processes, so
every change happens under an ``flock`` on ``.lock``. The clock is a parameter: a test hands in
its own and moves it.
"""

import base64
import fcntl
import json
import os
import re
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import limits

Clock = Callable[[], datetime]

#: Both are used with ``fullmatch``: ``$`` would also match before a trailing line feed.
PREFIX_RE = re.compile(r"[A-Za-z0-9_-]+")
HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_FIELDS = ("prefix", "key", "expires_at", "retention_seconds", "secret_headers")
#: Headers the service stores in plain text or evaluates itself; none of them can be a secret.
PLAIN_HEADERS = frozenset({"host", "x-forwarded-for", "x-forwarded-proto"})
#: Name in ``counts.json`` under which connections past the limit are counted, per day.
OVER_LIMIT = "over_connection_limit"
#: Name in ``counts.json`` under which damaged registrations that were deleted are counted.
UNREADABLE = "unreadable_registration"
#: Name in ``counts.json`` under which sweeps that could not handle a registration are counted.
SWEEP_ERROR = "sweep_error"
#: Name in ``counts.json`` under which header names that were not stored are counted, per day.
INVALID_HEADER = "invalid_header_name"
#: Name in ``counts.json`` under which requests whose handling raised are counted, per day.
HANDLER_ERROR = "handler_error"
#: Name in ``counts.json`` of the one number that says the file was unreadable and was replaced.
UNREADABLE_COUNTS = "unreadable_counts"
_PER_DAY = (OVER_LIMIT, UNREADABLE, SWEEP_ERROR, INVALID_HEADER, HANDLER_ERROR)
_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DataDirError(Exception):
    """The data directory is missing, not ours, or not mode 0700."""


class Rejected(Exception):
    """A registration that is refused; the message names the place."""


class Duplicate(Rejected):
    """A registration for a prefix that already has one."""


def format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_time(text: str) -> datetime:
    """Parse an ISO-8601 time that is explicitly UTC (``Z`` or ``+00:00``)."""
    if not text.endswith(("Z", "z")) and not text.endswith("+00:00"):
        raise ValueError("not an explicit UTC time")
    moment = datetime.fromisoformat(text[:-1] + "+00:00" if text[-1] in "Zz" else text)
    return moment.astimezone(timezone.utc)


def check_prefix(prefix: str) -> bool:
    return (
        limits.MIN_PREFIX_CHARS <= len(prefix) <= limits.MAX_PREFIX_CHARS
        and PREFIX_RE.fullmatch(prefix) is not None
    )


def old_line_feed_prefix(prefix: str) -> bool:
    """A prefix that fails ``check_prefix`` only by its trailing line feed.

    Before prefixes were matched whole, ``$`` let one such line feed through, counted in the
    length. A registration under such a name may still be on disk; the sweep deletes it whole.
    """
    return (
        prefix.endswith("\n")
        and limits.MIN_PREFIX_CHARS <= len(prefix) <= limits.MAX_PREFIX_CHARS
        and PREFIX_RE.fullmatch(prefix[:-1]) is not None
    )


@dataclass(frozen=True)
class Registration:
    prefix: str
    key: bytes
    expires_at: datetime
    retention_seconds: int
    secret_headers: tuple[str, ...]

    @property
    def delete_at(self) -> datetime:
        return self.expires_at + timedelta(seconds=self.retention_seconds)


class Unreadable(Exception):
    """A stored registration that fails even the form and type check."""


def parse_registration(document: Any) -> Registration:
    """Validate a new registration: form, types and the rules that apply only at ``register``.

    Unknown keys and wrong types are refused, with place. A stored registration is read with
    ``parse_stored_registration`` instead: the rules added later do not reach back to it.
    """
    return _parse(document, new=True)


def parse_stored_registration(document: Any) -> Registration:
    """Read a registration from disk: form and types only, none of the rules for new ones."""
    return _parse(document, new=False)


def _parse(document: Any, new: bool) -> Registration:
    if not isinstance(document, dict):
        raise Rejected("$: expected an object")
    for name in document:
        if name not in _FIELDS:
            raise Rejected(f"$.{name}: unknown key")
    for name in _FIELDS:
        if name not in document:
            raise Rejected(f"$.{name}: missing")
    prefix, key, expires, retention, secret = (document[name] for name in _FIELDS)
    if not isinstance(prefix, str):
        raise Rejected("$.prefix: expected a string")
    if not check_prefix(prefix):
        raise Rejected(
            f"$.prefix: expected {limits.MIN_PREFIX_CHARS} to {limits.MAX_PREFIX_CHARS} "
            "base64url characters (A-Z a-z 0-9 - _)"
        )
    if new and len(set(prefix)) < limits.MIN_PREFIX_DISTINCT_CHARS:
        raise Rejected(
            f"$.prefix: expected at least {limits.MIN_PREFIX_DISTINCT_CHARS} different "
            f"characters, got {len(set(prefix))}"
        )
    if not isinstance(key, str):
        raise Rejected("$.key: expected a string")
    try:
        raw_key = base64.b64decode(key, validate=True)
    except ValueError:
        raise Rejected("$.key: not valid base64") from None
    if not limits.MIN_KEY_BYTES <= len(raw_key) <= limits.MAX_KEY_BYTES:
        raise Rejected(
            f"$.key: expected {limits.MIN_KEY_BYTES} to {limits.MAX_KEY_BYTES} bytes "
            f"after decoding, got {len(raw_key)}"
        )
    if not isinstance(expires, str):
        raise Rejected("$.expires_at: expected a string")
    try:
        expires_at = parse_time(expires)
    except ValueError:
        raise Rejected(
            "$.expires_at: expected an ISO-8601 UTC time such as 2026-12-01T00:00:00Z"
        ) from None
    if isinstance(retention, bool) or not isinstance(retention, int):
        raise Rejected("$.retention_seconds: expected an integer")
    if not 1 <= retention <= limits.MAX_RETENTION_SECONDS:
        raise Rejected(
            f"$.retention_seconds: expected 1 to {limits.MAX_RETENTION_SECONDS}, got {retention}"
        )
    if not isinstance(secret, list):
        raise Rejected("$.secret_headers: expected a list")
    if len(secret) > limits.MAX_SECRET_HEADERS:
        raise Rejected(f"$.secret_headers: at most {limits.MAX_SECRET_HEADERS} names")
    names: list[str] = []
    for index, name in enumerate(secret):
        if not isinstance(name, str):
            raise Rejected(f"$.secret_headers[{index}]: expected a string")
        # A stored registration keeps what was taken before names were matched whole: one
        # trailing line feed. Such a name never matches a received header; it does no harm.
        shape = name if new else name.removesuffix("\n")
        if not HEADER_NAME_RE.fullmatch(shape):
            raise Rejected(f"$.secret_headers[{index}]: not a header name")
        if new and name.lower() in PLAIN_HEADERS:
            raise Rejected(
                f"$.secret_headers[{index}]: {name} is stored in plain text or evaluated by "
                "the service on purpose (host, sender, scheme), so it cannot be secret"
            )
        if name.lower() not in names:
            names.append(name.lower())
    return Registration(prefix, raw_key, expires_at, retention, tuple(names))


def _dump_registration(reg: Registration) -> dict[str, Any]:
    return {
        "prefix": reg.prefix,
        "key": base64.b64encode(reg.key).decode("ascii"),
        "expires_at": format_time(reg.expires_at),
        "retention_seconds": reg.retention_seconds,
        "secret_headers": list(reg.secret_headers),
    }


class Store:
    def __init__(self, data_dir: str | Path, clock: Clock = utc_now) -> None:
        self.root = Path(data_dir)
        self.clock = clock
        self._pending_lock = threading.Lock()
        #: Counts not yet in ``counts.json``, by (name or None for the plain count, day).
        self._pending: dict[tuple[str | None, str], int] = {}
        #: Prefixes whose deadlines the last sweep could not enforce; ``pull`` refuses them.
        self.unenforced: frozenset[str] = frozenset()
        try:
            info = self.root.stat()
        except OSError as error:
            raise DataDirError(f"data directory {self.root}: {error.strerror}") from None
        if not stat.S_ISDIR(info.st_mode):
            raise DataDirError(f"data directory {self.root}: not a directory")
        if info.st_uid != os.geteuid():
            raise DataDirError(f"data directory {self.root}: not owned by the running user")
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise DataDirError(
                f"data directory {self.root}: mode is {stat.S_IMODE(info.st_mode):04o}, "
                "must be 0700 (chmod 700)"
            )

    # -- files ---------------------------------------------------------------------------

    def _path(self, kind: str, prefix: str) -> Path:
        if not check_prefix(prefix):
            raise ValueError("not a prefix")
        return self._file(kind, prefix)

    def _file(self, kind: str, prefix: str) -> Path:
        return self.root / (f"{kind}-{prefix}" + (".jsonl" if kind == "entries" else ".json"))

    @contextmanager
    def _locked(self) -> Iterator[None]:
        fd = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _write(self, path: Path, data: bytes) -> None:
        temp = path.with_name(path.name + ".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
        os.replace(temp, path)

    def _read_json(self, path: Path) -> Any:
        try:
            return json.loads(path.read_bytes())
        except (OSError, ValueError, RecursionError):
            return None

    def _size(self) -> int:
        total = 0
        with os.scandir(self.root) as listing:
            for item in listing:
                with suppress(OSError):
                    total += item.stat(follow_symlinks=False).st_size
        return total

    def _load_strict(self, prefix: str) -> Registration | None:
        """The stored registration; None if there is none, ``Unreadable`` if it is damaged.

        Any other ``OSError`` is raised: a file that cannot be read now is not a damaged one.
        """
        try:
            raw = self._path("reg", prefix).read_bytes()
        except FileNotFoundError:
            return None
        try:
            reg = parse_stored_registration(json.loads(raw))
        except (ValueError, RecursionError, Rejected):
            raise Unreadable(prefix) from None
        if reg.prefix != prefix:
            raise Unreadable(prefix)
        return reg

    def _load(self, prefix: str) -> Registration | None:
        try:
            return self._load_strict(prefix)
        except (Unreadable, OSError):
            return None

    # -- registrations -------------------------------------------------------------------

    def register(self, reg: Registration) -> None:
        # Only a new registration must not be in the past; a stored one is held until its end.
        now = self.clock()
        if reg.expires_at <= now:
            raise Rejected("$.expires_at: is in the past")
        if reg.expires_at > now + timedelta(seconds=limits.MAX_EXPIRES_AHEAD_SECONDS):
            raise Rejected(
                "$.expires_at: is more than "
                f"{limits.MAX_EXPIRES_AHEAD_SECONDS // 86400} days from now"
            )
        with self._locked():
            path = self._path("reg", reg.prefix)
            if path.exists():
                raise Duplicate("$.prefix: a registration for this prefix already exists")
            self._write(
                self._path("state", reg.prefix),
                json.dumps({"next_seq": 1, "hour": "", "hour_count": 0}).encode(),
            )
            self._write(self._path("entries", reg.prefix), b"")
            self._write(path, json.dumps(_dump_registration(reg)).encode())

    def lookup(self, prefix: str) -> Registration | None:
        """The registration, if the prefix is known *now*. After ``expires_at`` it is not."""
        if not check_prefix(prefix):
            return None
        reg = self._load(prefix)
        if reg is None or self.clock() >= reg.expires_at:
            return None
        return reg

    def exists(self, prefix: str) -> bool:
        """Whether the registration is still held, expired or not."""
        return check_prefix(prefix) and self._path("reg", prefix).exists()

    def purge(self, prefix: str) -> bool | None:
        """Delete everything of a prefix. True if it was held, False if not, None if damaged."""
        with self._locked():
            found = self._path("reg", prefix).exists()
            damaged = False
            if found:
                try:
                    self._load_strict(prefix)
                except Unreadable:
                    damaged = True
                except OSError:
                    pass
            # Removed first, counted after: a count that fails leaves the deletion done.
            self._remove(prefix)
            if damaged:
                self._count_named(UNREADABLE, self.clock())
            return None if damaged else found

    def _remove(self, prefix: str) -> None:
        if not (check_prefix(prefix) or old_line_feed_prefix(prefix)):
            raise ValueError("not a prefix")
        # The registration goes first: with it gone, nothing can append to the rest. A file that
        # cannot be removed does not keep the others; the first such error is raised at the end.
        failure: OSError | None = None
        for kind in ("reg", "state", "entries"):
            path = self._file(kind, prefix)
            for target in (path, path.with_name(path.name + ".tmp")):
                try:
                    target.unlink(missing_ok=True)
                except OSError as error:
                    failure = failure or error
        if failure is not None:
            raise failure

    # -- entries -------------------------------------------------------------------------

    def append_entry(self, prefix: str, entry: dict[str, Any], invalid_headers: int = 0) -> bool:
        """Store one entry, numbering and timing it. False means it was only counted.

        ``invalid_headers`` is how many header names of the request were left out of the entry;
        they are counted per day once the entry is stored.
        """
        with self._locked():
            now = self.clock()
            reg = self._load(prefix)
            state = self._read_json(self._path("state", prefix))
            if reg is None or now >= reg.expires_at or not isinstance(state, dict):
                self._count_named(None, now)
                return False
            hour = now.strftime("%Y-%m-%dT%H")
            if state.get("hour") != hour:
                state["hour"], state["hour_count"] = hour, 0
            if state["hour_count"] >= limits.MAX_ENTRIES_PER_HOUR:
                self._count_named(None, now)
                return False
            line = json.dumps(
                {"seq": state["next_seq"], "time": format_time(now), **entry},
                separators=(",", ":"),
            ).encode()
            if self._size() + len(line) + 1 > limits.MAX_DATA_BYTES:
                self._count_named(None, now)
                return False
            fd = os.open(
                self._path("entries", prefix), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600
            )
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, line + b"\n")
            finally:
                os.close(fd)
            state["next_seq"] += 1
            state["hour_count"] += 1
            self._write(self._path("state", prefix), json.dumps(state).encode())
            if invalid_headers:
                self._count_named(INVALID_HEADER, now, invalid_headers)
            return True

    def count_other(self) -> None:
        """Count a request that is not recorded: one number for the day, nothing else."""
        self._count_now(None)

    def count_handler_error(self) -> None:
        """Count a request whose handling raised: one number for the day, nothing else."""
        self._count_now(HANDLER_ERROR)

    def count_over_limit(self) -> None:
        """Count a connection closed for being past ``MAX_CONNECTIONS``: memory only.

        This runs on the accepting thread, which must not wait for the disk or the lock; the
        next sweep carries the number into ``counts.json``.
        """
        self._remember(OVER_LIMIT, self.clock())

    def _remember(self, name: str | None, now: datetime, number: int = 1) -> None:
        key = (name, now.strftime("%Y-%m-%d"))
        with self._pending_lock:
            self._pending[key] = self._pending.get(key, 0) + number

    def _count_now(self, name: str | None) -> None:
        """Count outside the lock; whatever goes wrong, the number stays in memory."""
        self._remember(name, self.clock())
        with suppress(Exception), self._locked():
            self._flush_pending()

    def _flush_pending(self) -> None:
        """Write the counts waiting in memory into ``counts.json``. The lock must be held.

        Every count goes this way. Whatever fails, the numbers stay in memory for the next
        write; what is still there when the process ends is lost.
        """
        with self._pending_lock:
            pending, self._pending = self._pending, {}
        if not pending:
            return
        try:
            counts = self._read_counts()
            for (name, day), number in pending.items():
                if name is None:
                    counts[day] = counts.get(day, 0) + number
                else:
                    self._add_named(counts, name, day, number)
            self._write_counts(counts)
        except Exception:
            with self._pending_lock:
                for key, number in pending.items():
                    self._pending[key] = self._pending.get(key, 0) + number

    def _read_counts(self) -> dict[str, Any]:
        """The counters; content that is not exactly the expected shape is replaced, and counted.

        Every level is checked: an object, a day as key, a non-negative integer as value. The
        replacement is written with the next write; until then the file stays as it is. A file
        that cannot be read (``OSError``) is not damaged: the error is raised and the file is
        left alone.
        """
        try:
            raw = (self.root / "counts.json").read_bytes()
        except FileNotFoundError:
            return {}
        try:
            counts = json.loads(raw)
        except (ValueError, RecursionError):
            counts = None
        return counts if self._counts_valid(counts) else {UNREADABLE_COUNTS: 1}

    @staticmethod
    def _counts_valid(counts: Any) -> bool:
        def number(value: Any) -> bool:
            return isinstance(value, int) and not isinstance(value, bool) and value >= 0

        def day(name: Any) -> bool:
            if not isinstance(name, str) or not _DAY_RE.fullmatch(name):
                return False
            try:
                datetime.strptime(name, "%Y-%m-%d")
            except ValueError:
                return False
            return True

        if not isinstance(counts, dict):
            return False
        for name, value in counts.items():
            if name == UNREADABLE_COUNTS:
                valid = number(value)
            elif name in _PER_DAY:
                valid = isinstance(value, dict) and all(
                    day(d) and number(n) for d, n in value.items()
                )
            else:
                valid = day(name) and number(value)
            if not valid:
                return False
        return True

    @staticmethod
    def _add_named(counts: dict[str, Any], name: str, day: str, number: int = 1) -> None:
        per_day = counts.get(name)
        per_day = per_day if isinstance(per_day, dict) else {}
        per_day[day] = per_day.get(day, 0) + number
        counts[name] = per_day

    def _count_named(self, name: str | None, now: datetime, number: int = 1) -> None:
        """Count with the lock held. This never raises: a failure leaves the number in memory."""
        self._remember(name, now, number)
        self._flush_pending()

    def _write_counts(self, counts: dict[str, Any]) -> None:
        for name in _PER_DAY:
            per_day = counts.get(name)
            if isinstance(per_day, dict):
                for old in sorted(per_day)[: -limits.COUNT_DAYS]:
                    del per_day[old]
        days = sorted(name for name in counts if name not in (*_PER_DAY, UNREADABLE_COUNTS))
        for old in days[: -limits.COUNT_DAYS]:
            del counts[old]
        self._write(self.root / "counts.json", json.dumps(counts, sort_keys=True).encode())

    def read_entries(self, prefix: str, after: int = 0) -> list[dict[str, Any]]:
        """Entries with a number above ``after``, oldest first, after a sweep.

        The deadlines do not hang on the sweep alone: an entry past its retention is left out
        here, and so is everything of a registration that is itself due. A sweep that could not
        handle ``prefix`` is reported in ``unenforced``. The result is empty only when the
        registration is missing, damaged or due; a registration that cannot be read now raises
        ``OSError``.
        """
        with self._locked():
            self.unenforced = self._sweep()
            try:
                reg = self._load_strict(prefix)
            except Unreadable:
                return []
            now = self.clock()
            try:
                if reg is None or now >= reg.delete_at:
                    return []
            except OverflowError:
                return []
            return [
                e for e in self._entries(prefix) if e["seq"] > after and self._alive(e, reg, now)
            ]

    def _entries(self, prefix: str) -> list[dict[str, Any]]:
        try:
            raw = self._path("entries", prefix).read_bytes()
        except FileNotFoundError:
            return []
        entries = []
        for line in raw.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("seq"), int):
                entries.append(entry)
        return entries

    # -- deadlines -----------------------------------------------------------------------

    def sweep(self) -> None:
        with self._locked():
            self.unenforced = self._sweep()

    def _sweep(self) -> frozenset[str]:
        """Delete what has passed its deadline. Each registration is handled on its own.

        Returns the prefixes whose handling failed: their deadlines are not enforced. An error
        with one registration ends the handling of that one only. A registration that is
        damaged is deleted whole, and so is one under a prefix that fails only by its trailing
        line feed (:func:`old_line_feed_prefix`). One whose deadline cannot be worked out for
        another reason is left as it is and counted under ``sweep_error``. Removal comes before
        counting.
        """
        self._flush_pending()
        now = self.clock()
        seen: set[str] = set()
        failed: set[str] = set()
        for path in sorted(self.root.glob("reg-*.json")):
            prefix = path.name[len("reg-") : -len(".json")]
            if old_line_feed_prefix(prefix):
                seen.add(prefix)
                if not self._sweep_old(prefix, now):
                    failed.add(prefix)
                continue
            if not check_prefix(prefix):
                continue
            seen.add(prefix)
            if not self._sweep_one(prefix, now):
                failed.add(prefix)
        # What outlived its registration (a crash between the removals) goes too, but only when
        # the registration is missing: one that is there and cannot be read keeps its files.
        for kind in ("state", "entries"):
            for path in self.root.glob(f"{kind}-*"):
                stem = path.name[len(kind) + 1 :].split(".")[0]
                if stem in seen or not (check_prefix(stem) or old_line_feed_prefix(stem)):
                    continue
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    failed.add(stem)
                    self._count_named(SWEEP_ERROR, now)
        return frozenset(failed)

    def _sweep_old(self, prefix: str, now: datetime) -> bool:
        """Delete a registration under an old line-feed prefix whole, as a damaged one."""
        try:
            self._remove(prefix)
        except Exception:
            self._count_named(SWEEP_ERROR, now)
            return False
        self._count_named(UNREADABLE, now)
        return True

    def _sweep_one(self, prefix: str, now: datetime) -> bool:
        """Handle one registration. False: its deadlines could not be enforced."""
        try:
            try:
                reg = self._load_strict(prefix)
                if reg is None:
                    return True
                due = now >= reg.delete_at
            except (Unreadable, OverflowError):
                # Damaged: nothing of it stays, least of all the key.
                self._remove(prefix)
                self._count_named(UNREADABLE, now)
                return True
            if due:
                self._remove(prefix)
                return True
            keep = self._entries(prefix)
            kept = [e for e in keep if self._alive(e, reg, now)]
            if len(kept) != len(keep) or len(kept) != self._line_count(prefix):
                data = b"".join(json.dumps(e, separators=(",", ":")).encode() + b"\n" for e in kept)
                self._write(self._path("entries", prefix), data)
        except Exception:
            # Not damage: nothing is deleted on a guess. The registration stays; it is counted.
            self._count_named(SWEEP_ERROR, now)
            return False
        return True

    def _line_count(self, prefix: str) -> int:
        try:
            return len(self._path("entries", prefix).read_bytes().splitlines())
        except OSError:
            return 0

    @staticmethod
    def _alive(entry: dict[str, Any], reg: Registration, now: datetime) -> bool:
        try:
            made = parse_time(str(entry["time"]))
            return now < made + timedelta(seconds=reg.retention_seconds)
        except (KeyError, ValueError, OverflowError):
            return False
