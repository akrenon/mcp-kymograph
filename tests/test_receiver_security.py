"""The callback receiver after the security review: deadlines that nothing can hold up, names
that cannot carry a value, and the behaviours that had no test of their own.

Shares the helpers and fixtures of ``test_receiver.py``. Invented secrets are put together at run
time so that no secret scanner mistakes a test value for a leaked one.
"""

import base64
import errno
import hashlib
import hmac
import json
import os
import re
import signal
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

import test_receiver
from mcp_kymograph.receiver import __main__ as receiver_cli
from mcp_kymograph.receiver import limits
from mcp_kymograph.receiver.entry import is_name
from mcp_kymograph.receiver.server import Receiver
from mcp_kymograph.receiver.store import Registration, Store, parse_registration
from test_receiver import (
    KEY,
    OTHER_PREFIX,
    PREFIX,
    START,
    Clock,
    counts,
    entries,
    files_under,
    get,
    register,
    registration,
    run_register,
    secret,
    send,
    write_stored,
)

# The fixtures of that module, under the same names. Assigned rather than imported, so that a
# test argument of the same name is not taken for a redefinition.
clock = test_receiver.clock
data = test_receiver.data
serve = test_receiver.serve
store = test_receiver.store

DAY = "2026-11-03"
RAW_KEY = base64.b64decode(KEY)


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def expected_hmac(value: str) -> str:
    return hmac.new(RAW_KEY, value.encode(), hashlib.sha256).hexdigest()


def needles(values: list[str]) -> set[bytes]:
    found = set()
    for value in values:
        raw = value.encode()
        found |= {raw, quote(value).encode(), quote(value, safe="").encode()}
        found |= {base64.b64encode(raw), base64.urlsafe_b64encode(raw)}
        found |= {base64.b64encode(raw).rstrip(b"="), raw.hex().encode()}
    return found


def assert_nowhere(data: Path, values: list[str], extra: bytes = b"") -> None:
    """None of the values, in any common encoding, in any file of ``data`` or in ``extra``."""
    assert files_under(data)
    for path in files_under(data):
        content = path.read_bytes()
        for needle in needles(values):
            assert needle not in content, (path.name, needle)
    for needle in needles(values):
        assert needle not in extra, needle


def pull_output(data: Path, clock: Clock, capsys, prefix: str = PREFIX) -> str:
    assert receiver_cli.main(["pull", "--data", str(data), "--prefix", prefix], clock) == 0
    return capsys.readouterr().out


def stored_due(data: Path, prefix: str = OTHER_PREFIX) -> None:
    """A healthy registration whose registration and key are past their deadline at START."""
    document = registration(prefix=prefix, expires_at="2026-11-03T10:00:00Z", retention_seconds=60)
    write_stored(data, document, prefix)


def gone(data: Path, prefix: str) -> bool:
    return not list(data.glob("*-" + prefix + "*"))


# -- 1. expires_at is bounded ------------------------------------------------------------------


def test_register_refuses_an_expiry_near_the_year_9999(data, monkeypatch, capsys):
    document = registration(expires_at="9999-12-31T00:00:00Z")
    code, out = run_register(data, document, monkeypatch, capsys)
    assert code == receiver_cli.EXIT_REFUSED and "$.expires_at" in out
    assert files_under(data) == []


def test_register_takes_the_expiry_limit_and_refuses_one_second_more(data, monkeypatch, capsys):
    limit = START + timedelta(seconds=limits.MAX_EXPIRES_AHEAD_SECONDS)
    assert limits.MAX_EXPIRES_AHEAD_SECONDS == 366 * 24 * 3600
    over = registration(expires_at=iso(limit + timedelta(seconds=1)))
    code, out = run_register(data, over, monkeypatch, capsys)
    assert code == receiver_cli.EXIT_REFUSED and "$.expires_at" in out
    assert files_under(data) == []
    code, out = run_register(data, registration(expires_at=iso(limit)), monkeypatch, capsys)
    assert code == 0 and "registered" in out


def test_the_limit_is_measured_from_the_clock_of_the_store(store, clock):
    clock.advance(3600)
    limit = START + timedelta(seconds=3600 + limits.MAX_EXPIRES_AHEAD_SECONDS)
    register(store, expires_at=iso(limit))
    with pytest.raises(Exception, match=r"\$\.expires_at"):
        register(store, prefix=OTHER_PREFIX, expires_at=iso(limit + timedelta(seconds=1)))


def test_a_stored_expiry_near_the_year_9999_does_not_hold_the_sweep_up(store, data):
    write_stored(data, registration(expires_at="9999-12-31T23:59:59Z"))
    stored_due(data)
    store.sweep()
    assert gone(data, PREFIX) and gone(data, OTHER_PREFIX)
    assert all(KEY.encode() not in p.read_bytes() for p in files_under(data))


def test_pull_of_a_stored_expiry_near_the_year_9999_ends_without_a_traceback(data, clock, capsys):
    write_stored(data, registration(expires_at="9999-12-31T23:59:59Z"))
    args = ["pull", "--data", str(data), "--prefix", PREFIX]
    assert receiver_cli.main(args, clock) == receiver_cli.EXIT_NO_REGISTRATION
    captured = capsys.readouterr()
    assert captured.out == "" and len(captured.err.strip().splitlines()) == 1
    assert gone(data, PREFIX)


# -- 2. deletion hangs on nothing else ---------------------------------------------------------

BAD_COUNT_VALUES = [None, "text", [1]]
BAD_COUNT_IDS = ["null", "string", "list"]


def bad_counts(place: str, value) -> dict:
    if place == "nested":
        return {"unreadable_registration": {DAY: value}}
    return {DAY: value}


@pytest.mark.parametrize("value", BAD_COUNT_VALUES, ids=BAD_COUNT_IDS)
@pytest.mark.parametrize("place", ["nested", "day"])
def test_the_sweep_deletes_despite_unreadable_counts(store, data, place, value):
    (data / "counts.json").write_text(json.dumps(bad_counts(place, value)))
    write_stored(data, b"{broken")
    stored_due(data)
    store.sweep()
    assert gone(data, PREFIX) and gone(data, OTHER_PREFIX)
    assert all(KEY.encode() not in p.read_bytes() for p in files_under(data))
    assert counts(data) == {"unreadable_counts": 1, "unreadable_registration": {DAY: 1}}
    store.sweep()
    assert counts(data) == {"unreadable_counts": 1, "unreadable_registration": {DAY: 1}}


@pytest.mark.parametrize("value", BAD_COUNT_VALUES, ids=BAD_COUNT_IDS)
@pytest.mark.parametrize("place", ["nested", "day"])
def test_purge_deletes_despite_unreadable_counts(store, data, clock, capsys, place, value):
    (data / "counts.json").write_text(json.dumps(bad_counts(place, value)))
    write_stored(data, b"{broken")
    stored_due(data)
    args = ["purge", "--data", str(data), "--prefix", PREFIX]
    assert receiver_cli.main(args, clock) == receiver_cli.EXIT_NO_REGISTRATION
    assert len(capsys.readouterr().err.strip().splitlines()) == 1
    assert gone(data, PREFIX)
    assert counts(data) == {"unreadable_counts": 1, "unreadable_registration": {DAY: 1}}
    store.sweep()
    assert gone(data, OTHER_PREFIX)


@pytest.mark.parametrize(
    "content",
    [b"", b"{", b"[1]", b'{"2026-13-45": 1}', b'{"2026-11-03": -1}', b'{"2026-11-03": true}']
    + [b'{"other": 1}', b'{"over_connection_limit": 3}', b"[" * 100000],
    ids=["empty", "cut", "list", "no-day", "negative", "bool", "name", "per-day", "deep"],
)
def test_an_unreadable_counts_file_is_replaced_and_the_loss_counted(store, data, content):
    (data / "counts.json").write_bytes(content)
    store.count_other()
    assert counts(data) == {"unreadable_counts": 1, DAY: 1}
    store.count_other()
    assert counts(data) == {"unreadable_counts": 1, DAY: 2}


def test_a_counts_file_in_the_expected_shape_is_kept(store, data):
    shape = {"2026-11-02": 4, "over_connection_limit": {"2026-11-02": 2}}
    (data / "counts.json").write_text(json.dumps(shape))
    store.count_other()
    assert counts(data) == {**shape, DAY: 1}


def failing_read(monkeypatch, name: str, error: OSError) -> None:
    """Make ``Path.read_bytes`` fail for the one file called ``name``."""
    original = Path.read_bytes

    def read_bytes(self):
        if self.name == name:
            raise error
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)


def test_a_counts_file_that_cannot_be_read_now_is_not_replaced(store, data, monkeypatch):
    shape = {"2026-11-02": 4, "over_connection_limit": {"2026-11-02": 2}}
    (data / "counts.json").write_text(json.dumps(shape))
    before = (data / "counts.json").read_bytes()
    failing_read(monkeypatch, "counts.json", OSError(errno.EMFILE, "Too many open files"))
    store.count_over_limit()
    store.sweep()
    monkeypatch.undo()
    assert (data / "counts.json").read_bytes() == before
    store.sweep()
    assert counts(data) == {**shape, "over_connection_limit": {"2026-11-02": 2, DAY: 1}}


def test_a_failing_read_of_a_registration_deletes_no_healthy_one(store, data, monkeypatch):
    register(store)
    store.append_entry(PREFIX, {"path": "kept"})
    failing_read(monkeypatch, f"reg-{PREFIX}.json", PermissionError(errno.EACCES, "denied"))
    store.sweep()
    assert (data / f"state-{PREFIX}.json").exists()
    assert b"kept" in (data / f"entries-{PREFIX}.jsonl").read_bytes()
    assert (data / f"reg-{PREFIX}.json").exists()
    assert counts(data) == {"sweep_error": {DAY: 1}}
    assert PREFIX in store.unenforced


def test_the_files_of_a_missing_registration_are_still_removed(store, data):
    register(store)
    (data / f"reg-{PREFIX}.json").unlink()
    store.sweep()
    assert gone(data, PREFIX)
    assert store.unenforced == frozenset()


@pytest.mark.parametrize("command", ["sweep", "purge"])
def test_a_deletion_is_done_before_it_is_counted(store, data, monkeypatch, command):
    def failing(self, counts):
        raise RuntimeError("forced")

    monkeypatch.setattr(Store, "_write_counts", failing)
    write_stored(data, b"{broken")
    stored_due(data)
    if command == "sweep":
        store.sweep()
        assert gone(data, OTHER_PREFIX)
        assert all(KEY.encode() not in p.read_bytes() for p in files_under(data))
    else:
        assert store.purge(PREFIX) is None
    assert gone(data, PREFIX)
    assert not any(KEY.encode() in p.read_bytes() for p in data.glob(f"*{PREFIX}*"))


def test_a_failing_count_over_the_limit_is_kept_and_stops_nothing(store, data, monkeypatch):
    original = Store._write_counts

    def failing(self, counts):
        raise RuntimeError("forced")

    store.count_over_limit()
    stored_due(data)
    monkeypatch.setattr(Store, "_write_counts", failing)
    store.sweep()
    assert gone(data, OTHER_PREFIX)
    monkeypatch.setattr(Store, "_write_counts", original)
    store.sweep()
    assert counts(data) == {"over_connection_limit": {DAY: 1}}


def test_an_evaluation_that_raises_deletes_nothing_and_stops_no_other_deletion(
    store, data, monkeypatch
):
    register(store)
    stored_due(data)
    deadline = Registration.delete_at

    def delete_at(self):
        if self.prefix == PREFIX:
            raise RuntimeError("forced")
        return deadline.fget(self)

    monkeypatch.setattr(Registration, "delete_at", property(delete_at))
    store.sweep()
    # Not due, and not damaged: it stays, key included; the one after it is still deleted.
    assert store.exists(PREFIX) and (data / f"entries-{PREFIX}.jsonl").exists()
    assert gone(data, OTHER_PREFIX)
    assert counts(data) == {"sweep_error": {DAY: 1}}
    assert PREFIX in store.unenforced


def test_a_deadline_beyond_the_date_range_is_damage_and_deleted(store, data):
    write_stored(data, registration(expires_at="9999-12-31T23:59:59Z"))
    store.sweep()
    assert gone(data, PREFIX)
    assert counts(data) == {"unreadable_registration": {DAY: 1}}
    assert store.unenforced == frozenset()


def test_a_failure_in_one_registrations_entries_stops_no_other_deletion(
    store, data, clock, monkeypatch
):
    register(store)
    register(store, prefix=OTHER_PREFIX)
    store.append_entry(PREFIX, {"path": "one"})
    store.append_entry(OTHER_PREFIX, {"path": "two"})
    clock.advance(3601)
    alive = Store._alive

    def failing(entry, reg, now):
        if reg.prefix == PREFIX:
            raise RuntimeError("forced")
        return alive(entry, reg, now)

    monkeypatch.setattr(Store, "_alive", staticmethod(failing))
    store.sweep()
    assert (data / f"entries-{OTHER_PREFIX}.jsonl").read_bytes() == b""
    # Its deadline has not come: the registration stays, and is tried again at the next sweep.
    assert store.exists(PREFIX) and (data / f"entries-{PREFIX}.jsonl").read_bytes() != b""


def test_pull_ends_with_one_line_and_exit_1_when_the_sweep_fails(data, clock, capsys, monkeypatch):
    def failing(self):
        raise RuntimeError("forced")

    monkeypatch.setattr(Store, "_sweep", failing)
    args = ["pull", "--data", str(data), "--prefix", PREFIX]
    assert receiver_cli.main(args, clock) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and len(captured.err.strip().splitlines()) == 1
    assert "Traceback" not in captured.err


def expired_entry(store, clock):
    """A registration with one entry that is past its retention; the sweep has not run."""
    register(store, retention_seconds=100)
    store.append_entry(PREFIX, {"path": "late"})
    clock.advance(101)


def pull_args(data: Path) -> list[str]:
    return ["pull", "--data", str(data), "--prefix", PREFIX]


def assert_refused_unenforced(code: int, captured) -> None:
    assert code == 1 and captured.out == ""
    assert len(captured.err.strip().splitlines()) == 1
    assert "deadlines of this registration could not be enforced" in captured.err


def test_pull_gives_nothing_when_the_entries_cannot_be_rewritten(
    store, data, clock, capsys, monkeypatch
):
    expired_entry(store, clock)

    def failing(self, path, content):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(Store, "_write", failing)
    code = receiver_cli.main(pull_args(data), clock)
    assert_refused_unenforced(code, capsys.readouterr())
    assert b"late" in (data / f"entries-{PREFIX}.jsonl").read_bytes()


def test_pull_gives_nothing_when_a_due_registration_cannot_be_removed(
    store, data, clock, capsys, monkeypatch
):
    register(store, retention_seconds=100)
    store.append_entry(PREFIX, {"path": "late"})
    clock.now = START + timedelta(days=1, seconds=101)

    def failing(self, prefix):
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(Store, "_remove", failing)
    code = receiver_cli.main(pull_args(data), clock)
    assert_refused_unenforced(code, capsys.readouterr())


def test_pull_of_another_prefix_is_not_stopped_by_a_failure_elsewhere(
    store, data, clock, capsys, monkeypatch
):
    register(store)
    stored_due(data)

    def failing(self, prefix):
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(Store, "_remove", failing)
    assert receiver_cli.main(pull_args(data), clock) == 0


def test_read_entries_leaves_out_an_entry_past_its_retention_though_no_sweep_ran(
    store, clock, monkeypatch
):
    expired_entry(store, clock)
    store.append_entry(PREFIX, {"path": "fresh"})
    monkeypatch.setattr(Store, "_sweep", lambda self: frozenset())
    assert [e["path"] for e in store.read_entries(PREFIX)] == ["fresh"]


def test_read_entries_gives_nothing_of_a_due_registration_though_no_sweep_ran(
    store, data, clock, monkeypatch
):
    register(store, retention_seconds=100)
    # An entry stamped after the registration's own end, as a clock set back would leave it.
    entry = {"seq": 1, "time": "2026-11-10T00:00:00.000+00:00", "path": "odd"}
    (data / f"entries-{PREFIX}.jsonl").write_text(json.dumps(entry) + "\n")
    monkeypatch.setattr(Store, "_sweep", lambda self: frozenset())
    clock.now = START + timedelta(days=1, seconds=99)
    assert [e["path"] for e in store.read_entries(PREFIX)] == ["odd"]
    clock.advance(1)
    assert store.read_entries(PREFIX) == []


# -- 3. a value in the place of a name ---------------------------------------------------------

# Over 64 characters: not a name, so also not as `<token>=`, which would be a name followed by `=`.
LONG = secret("lo", "ng-") + "Zq8x" * 20
SHORT = secret("sh", "ort") + "Kd93Lp27"
COLON = secret("gh", "p:") + "A1b2C3d4E5"
UNDERSCORE_HEADER = secret("Tok", "_en_") + "R7s8T9"
LONG_HEADER = "X-" + "Mk4v" * 20


@pytest.mark.parametrize(
    ("target", "headers", "token"),
    [
        (f"/{PREFIX}/job?{SHORT}", [], SHORT),
        (f"/{PREFIX}/job?{LONG}=", [], LONG),
        (f"/{PREFIX}/job?{quote(COLON, safe='')}", [], COLON),
        (f"/{PREFIX}/job?{quote(COLON, safe='')}=1", [], COLON),
        (f"/{PREFIX}/{LONG}", [], LONG),
        (f"/{PREFIX}/job/{COLON}", [], COLON),
        (f"/{PREFIX}/job", [(UNDERSCORE_HEADER, "v")], UNDERSCORE_HEADER),
        (f"/{PREFIX}/job", [(LONG_HEADER, "v")], LONG_HEADER),
    ],
    ids=["bare", "blank", "encoded", "encoded-eq", "path", "path-nested", "header", "header-long"],
)
def test_a_token_in_the_place_of_a_name_is_nowhere(
    store, serve, data, clock, capsys, target, headers, token
):
    register(store)
    port = serve()
    get(port, target, headers=headers)
    assert len(entries(store)) == 1
    out = pull_output(data, clock, capsys)
    assert_nowhere(data, [token, quote(token, safe="")], out.encode())


def test_a_query_element_without_a_name_is_kept_as_an_hmac_only(store, serve):
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/job?{SHORT}&state=abc&{LONG}=&")
    [entry] = entries(store)
    # All elements without a name are one HMAC, over their decoded text joined by "&".
    assert entry["query"] == {
        "(unnamed)": [expected_hmac(SHORT + "&" + LONG + "=")],
        "state": [expected_hmac("abc")],
    }


def test_an_ordinary_query_keeps_its_names(store, serve):
    register(store)
    port = serve()
    ordinary = ["state", "code", "redirect_uri", "client_id", "id_token", "v2"]
    get(port, f"/{PREFIX}/job-17?state=abc&a.b_c-d=1&state=def&empty=")
    get(port, f"/{PREFIX}/" + "/".join(ordinary) + "?" + "&".join(f"{n}=1" for n in ordinary))
    first, second = entries(store)
    assert first["path"] == "job-17"
    assert first["query"] == {
        "state": [expected_hmac("abc"), expected_hmac("def")],
        "a.b_c-d": [expected_hmac("1")],
        "empty": [expected_hmac("")],
    }
    assert second["path"] == "/".join(ordinary)
    assert set(second["query"]) == set(ordinary)


def test_a_path_segment_that_is_not_a_name_becomes_an_hmac(store, serve):
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/{LONG}")
    get(port, f"/{PREFIX}/job-17/{COLON}/x.y/")
    first, second = entries(store)
    assert first["path"] == "hmac:" + expected_hmac(LONG)
    assert second["path"] == f"job-17/hmac:{expected_hmac(COLON)}/x.y/"


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("n" * 29, True),
        ("n" * 30, False),
        ("n" * 29 + "123", True),
        ("n" * 30 + "123", False),
        ("n" * 28 + "1234", False),
        ("a1b", False),
        ("v2", True),
        ("1abc", False),
        ("_abc", False),
        ("", False),
        ("abc\n", False),
    ],
)
def test_the_rule_for_a_name(text, name):
    assert is_name(text) is name


def test_a_name_of_30_letters_is_not_a_name(store, serve):
    register(store)
    port = serve()
    longest, too_long = "n" * 29 + "123", "n" * 30
    get(port, f"/{PREFIX}/{longest}?{longest}=1&{too_long}=1")
    [entry] = entries(store)
    assert entry["path"] == longest
    assert set(entry["query"]) == {longest, "(unnamed)"}


# Tokens as common services issue them, put together here so that no scanner takes them for real.
TOKENS = {
    "ghp": secret("gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "hex32": secret("9f86d081", "884c7d65", "9a2feaa0", "c55ad015"),
    "uuid": secret("3f2b8c1e-", "7a4d-4e9b-", "8c5a-1d6f0e2b9a73"),
    "number": secret("4829", "1057", "3619"),
    "base64url": secret("Kd93Lp27", "Qw8xYz4V", "bN6mRt"),
}


def test_the_tokens_of_the_tests_are_not_names():
    assert not any(is_name(token) for token in TOKENS.values())
    assert (
        len(TOKENS["ghp"]) == 40 and len(TOKENS["hex32"]) == 32 and len(TOKENS["base64url"]) == 22
    )


@pytest.mark.parametrize("form", ["query-blank", "query-bare", "path", "path-after-name"])
@pytest.mark.parametrize("kind", list(TOKENS))
def test_a_common_token_in_the_place_of_a_name_is_nowhere(
    store, serve, data, clock, capsys, kind, form
):
    token = TOKENS[kind]
    target = {
        "query-blank": f"/{PREFIX}/job?{token}=",
        "query-bare": f"/{PREFIX}/job?{token}",
        "path": f"/{PREFIX}/{token}",
        "path-after-name": f"/{PREFIX}/job-1/{token}/done",
    }[form]
    register(store)
    port = serve()
    get(port, target)
    [entry] = entries(store)
    out = pull_output(data, clock, capsys)
    assert_nowhere(data, [token], out.encode())
    if form == "path":
        assert entry["path"] == "hmac:" + expected_hmac(token)
    if form == "path-after-name":
        assert entry["path"] == f"job-1/hmac:{expected_hmac(token)}/done"


# -- 3b. entries do not grow with the request --------------------------------------------------

ENTRY_LIMIT = 2048


def request_size(target: str) -> int:
    return len(f"POST {target} HTTP/1.1\r\nHost: cb.example\r\n\r\n")


def only_entry_size(data: Path) -> int:
    [line] = (data / f"entries-{PREFIX}.jsonl").read_bytes().splitlines()
    return len(line)


def test_many_path_segments_that_are_no_names_are_one_hmac(store, serve, data):
    register(store)
    port = serve()
    target = f"/{PREFIX}/" + "~/" * 7900
    assert request_size(target) < limits.MAX_HEADER_BYTES - 100
    get(port, target)
    [entry] = entries(store)
    assert entry["path"] == "hmac:" + expected_hmac("/".join(["~"] * 7900)) + "/"
    assert only_entry_size(data) < ENTRY_LIMIT


def test_many_query_elements_without_a_name_are_one_hmac(store, serve, data):
    register(store)
    port = serve()
    target = f"/{PREFIX}/job?" + "&".join(["~"] * 7900)
    assert request_size(target) < limits.MAX_HEADER_BYTES - 100
    get(port, target)
    [entry] = entries(store)
    assert entry["query"] == {"(unnamed)": [expected_hmac("&".join(["~"] * 7900))]}
    assert only_entry_size(data) < ENTRY_LIMIT


def test_at_most_32_parts_are_stored_for_a_path_and_a_query(store, serve):
    register(store)
    port = serve()
    names = [f"n{chr(97 + i % 26)}" for i in range(40)]
    get(port, f"/{PREFIX}/" + "/".join(names) + "?" + "&".join(f"{n}=1" for n in names))
    [entry] = entries(store)
    rest = entry["path"].split("/")
    assert len(rest) == 32 and rest[:31] == names[:31]
    assert rest[31] == "hmac:" + expected_hmac("/".join(names[31:]))
    assert sum(len(v) for k, v in entry["query"].items() if k != "(unnamed)") == 31
    unnamed = "&".join(f"{n}=1" for n in names[31:])
    assert entry["query"]["(unnamed)"] == [expected_hmac(unnamed)]


# -- 3c. Host is cut into labels ---------------------------------------------------------------


def test_a_token_in_a_host_label_is_not_stored(store, serve, data, clock, capsys):
    token = TOKENS["hex32"]
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/job", host=f"{token}.cb.example")
    get(port, f"/{PREFIX}/job", host=f"cb.{TOKENS['uuid']}.example:8443")
    first, second = entries(store)
    assert first["host"] == f"hmac:{expected_hmac(token)}.cb.example"
    assert second["host"] == f"cb.hmac:{expected_hmac(TOKENS['uuid'])}.example:8443"
    out = pull_output(data, clock, capsys)
    assert_nowhere(data, [token, TOKENS["uuid"]], out.encode())


def test_a_host_of_names_and_a_port_stays_readable(store, serve):
    register(store)
    port = serve()
    for host in ("cb.example:8443", "cb.example", "localhost:65535"):
        get(port, f"/{PREFIX}/job", host=host)
    get(port, f"/{PREFIX}/job", host="cb.example:65536")
    get(port, f"/{PREFIX}/job", host="cb.example:" + "1" * 6)
    hosts = [e["host"] for e in entries(store)]
    assert hosts[:3] == ["cb.example:8443", "cb.example", "localhost:65535"]
    assert all("hmac:" in host for host in hosts[3:])


def test_labels_of_a_host_that_are_no_names_are_one_hmac(store, serve):
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/job", host="a.4x.5y.b")
    [entry] = entries(store)
    assert entry["host"] == f"a.hmac:{expected_hmac('4x.5y')}.b"


def test_a_header_name_that_is_not_a_name_is_not_stored_and_is_counted(store, serve, data):
    register(store)
    port = serve()
    get(
        port,
        f"/{PREFIX}/job",
        headers=[(UNDERSCORE_HEADER, "v"), ("X-Fine", "v"), (LONG_HEADER, "")],
    )
    [entry] = entries(store)
    assert entry["headers"] == ["Host", "X-Fine"]
    assert counts(data) == {"invalid_header_name": {DAY: 2}}


# -- 4. behaviour that had no test -------------------------------------------------------------


def test_proxy_authorization_is_a_secret_header(store, serve, data):
    register(store, secret_headers=[])
    port = serve()
    value = secret("Basic ", "dXNlcjpw", "YXNzd29yZA==")
    get(port, f"/{PREFIX}/job", headers=[("Proxy-Authorization", value)])
    [entry] = entries(store)
    assert entry["secret_headers"] == {
        "proxy-authorization": {"present": True, "scheme": None, "hmac": expected_hmac(value)}
    }
    assert "Proxy-Authorization" in entry["headers"]
    assert_nowhere(data, [value, value.split(" ")[1]])


def test_repeated_headers_are_joined_before_the_hmac(store, serve):
    register(store)
    port = serve()
    first, second = secret("tok", "A"), secret("tok", "B")
    get(port, f"/{PREFIX}/job", headers=[("X-Api-Token", first), ("x-api-token", second)])
    [entry] = entries(store)
    assert entry["secret_headers"]["x-api-token"]["hmac"] == expected_hmac(f"{first}, {second}")
    assert entry["headers"].count("X-Api-Token") == 1


def test_invalid_http_is_counted(store, serve, data):
    register(store)
    port = serve()
    send(port, b"garbage\r\n\r\n")
    assert counts(data) == {DAY: 1}
    send(port, b"GET /x HTTP/1.1\r\nbad header line\r\n\r\n")
    assert counts(data) == {DAY: 2}
    assert entries(store) == []


def test_a_header_name_with_a_trailing_line_feed_is_invalid_http(store, serve, data):
    register(store)
    port = serve()
    send(port, f"GET /{PREFIX}/job HTTP/1.1\r\nX-Api-Token\n: v\r\n\r\n".encode())
    assert counts(data) == {DAY: 1}
    assert entries(store) == []


def test_the_service_sweeps_by_itself(store, serve, data, clock, monkeypatch):
    monkeypatch.setattr(limits, "SWEEP_INTERVAL_SECONDS", 0.05)
    register(store, expires_at="2026-11-03T12:05:00Z", retention_seconds=60)
    serve()
    assert (data / f"reg-{PREFIX}.json").exists()
    clock.advance(5 * 60 + 60)
    deadline = time.monotonic() + 10
    while not gone(data, PREFIX) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert gone(data, PREFIX)
    assert all(KEY.encode() not in p.read_bytes() for p in files_under(data))


@pytest.mark.skipif(os.geteuid() == 0, reason="root owns everything it can create")
def test_a_data_directory_of_another_owner_stops_everything(clock, capsys):
    code = receiver_cli.main(["purge", "--data", "/usr", "--prefix", PREFIX], clock)
    assert code == receiver_cli.EXIT_DATA_DIR
    assert "not owned" in capsys.readouterr().err


def test_a_data_directory_not_owned_by_the_running_user_stops(data, clock, capsys, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(data).st_uid + 1)
    for command in (["serve", "--port", "0"], ["register"], ["pull", "--prefix", PREFIX]):
        code = receiver_cli.main([command[0], "--data", str(data), *command[1:]], clock)
        assert code == receiver_cli.EXIT_DATA_DIR
        assert "not owned" in capsys.readouterr().err
    assert files_under(data) == []


def test_register_refuses_each_upper_limit(data, monkeypatch, capsys):
    cases = [
        ("$.secret_headers", {"secret_headers": [f"X-H{i}" for i in range(33)]}),
        ("$.prefix", {"prefix": ("abcdefghij" * 13)[:129]}),
        ("$.key", {"key": base64.b64encode(b"k" * 1025).decode()}),
        ("$.retention_seconds", {"retention_seconds": 90 * 24 * 3600 + 1}),
    ]
    assert limits.MAX_SECRET_HEADERS == 32 and limits.MAX_PREFIX_CHARS == 128
    assert limits.MAX_KEY_BYTES == 1024 and limits.MAX_RETENTION_SECONDS == 90 * 24 * 3600
    for place, changes in cases:
        code, out = run_register(data, registration(**changes), monkeypatch, capsys)
        assert code == receiver_cli.EXIT_REFUSED and place in out, place
    assert files_under(data) == []


def test_register_takes_each_upper_limit_exactly(data, monkeypatch, capsys):
    document = registration(
        prefix=("abcdefghij" * 13)[:128],
        key=base64.b64encode(b"k" * 1024).decode(),
        retention_seconds=90 * 24 * 3600,
        secret_headers=[f"X-H{i}" for i in range(32)],
    )
    code, out = run_register(data, document, monkeypatch, capsys)
    assert code == 0 and "registered" in out


def test_serve_with_port_0_prints_the_port_on_stderr(data, clock, capsys, monkeypatch):
    served: list[int] = []

    def serve_forever(self, poll_interval=0.5):
        served.append(self.port)

    monkeypatch.setattr(Receiver, "serve_forever", serve_forever)
    monkeypatch.setattr(signal, "signal", lambda *args: None)
    code = receiver_cli.main(["serve", "--data", str(data), "--port", "0"], clock)
    captured = capsys.readouterr()
    assert code == 0 and captured.out == ""
    [port] = served
    assert port > 0
    assert re.fullmatch(rf"receiver: listening on 127\.0\.0\.1:{port}", captured.err.strip())


def test_parse_registration_still_takes_the_form_without_a_clock():
    reg = parse_registration(registration(expires_at="9999-12-31T00:00:00Z"))
    assert reg.expires_at.year == 9999 and reg.expires_at.tzinfo == timezone.utc


# -- 5. nothing is lost unseen -----------------------------------------------------------------


def test_a_host_port_of_thousands_of_digits_is_stored_without_the_digits(store, serve, data):
    digits = "7" * 5000
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/job", host="cb.example:" + digits)
    [entry] = entries(store)
    assert "hmac:" in entry["host"]
    assert counts(data) == {}
    assert_nowhere(data, [digits])


def test_a_host_port_that_is_not_ascii_is_a_label_not_a_port(store, serve, data):
    register(store)
    port = serve()
    # Header lines are read as latin-1, so the digit must be one latin-1 can carry: "²" is a
    # digit to str.isdigit() and int() refuses it, which is the case the ASCII check guards.
    digit = "\u00b2"
    assert digit.isdigit() and not digit.isascii()
    host = f"cb.example:{digit}"
    send(port, f"POST /{PREFIX}/job HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("latin-1"))
    [entry] = entries(store)
    assert "hmac:" in entry["host"] and digit not in entry["host"]
    assert counts(data) == {}


def test_an_error_in_building_an_entry_is_counted(store, serve, data, monkeypatch):
    def failing(*args):
        raise RuntimeError("forced")

    monkeypatch.setattr("mcp_kymograph.receiver.server.build_entry", failing)
    register(store)
    port = serve()
    assert get(port, f"/{PREFIX}/job").startswith(b"HTTP/1.1 200")
    serve.stop()
    assert entries(store) == []
    assert counts(data) == {"handler_error": {DAY: 1}}


def make_other(store):
    store.count_other()


def make_from_append(store):
    assert store.append_entry(OTHER_PREFIX, {"path": "x"}) is False


def make_sweep_error(store):
    store.sweep()


@pytest.mark.parametrize(
    ("make", "expected"),
    [
        (make_other, {DAY: 1}),
        (make_from_append, {DAY: 1}),
        (make_sweep_error, {"sweep_error": {DAY: 1}}),
    ],
)
def test_every_count_waits_in_memory_while_counts_cannot_be_read(
    store, data, monkeypatch, make, expected
):
    shape = {"2026-11-02": 4}
    (data / "counts.json").write_text(json.dumps(shape))
    before = (data / "counts.json").read_bytes()
    if make is make_sweep_error:
        register(store)

        def failing(self, prefix):
            raise RuntimeError("forced")

        monkeypatch.setattr(Store, "_entries", failing)
    failing_read(monkeypatch, "counts.json", OSError(errno.EMFILE, "Too many open files"))
    make(store)
    monkeypatch.undo()
    assert (data / "counts.json").read_bytes() == before
    store.sweep()
    assert counts(data) == {**shape, **expected}


def test_pull_of_a_registration_that_cannot_be_read_ends_with_1(
    store, data, clock, capsys, monkeypatch
):
    register(store)
    store.append_entry(PREFIX, {"path": "kept"})
    original = Path.read_bytes
    reads = []

    def read_bytes(self):
        if self.name == f"reg-{PREFIX}.json":
            reads.append(self)
            if len(reads) == 2:
                raise OSError(errno.EMFILE, "Too many open files")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    assert receiver_cli.main(pull_args(data), clock) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and len(captured.err.strip().splitlines()) == 1
    assert PREFIX not in captured.err and str(data) not in captured.err
