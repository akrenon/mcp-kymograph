"""The callback receiver: what it keeps, what it never keeps, and when it lets go.

The service runs for real on 127.0.0.1 on a free port; the clock is injected so that a
retention period passes without waiting. Invented secrets are put together at run time so
that no secret scanner mistakes a test value for a leaked one.
"""

import base64
import contextlib
import hashlib
import hmac
import io
import json
import socket
import stat
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from mcp_kymograph.receiver import __main__ as receiver_cli
from mcp_kymograph.receiver import limits
from mcp_kymograph.receiver.server import RESPONSE, Receiver
from mcp_kymograph.receiver.store import Rejected, Store, check_prefix, parse_registration

START = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
KEY = base64.b64encode(bytes(range(32))).decode()
OTHER_KEY = base64.b64encode(bytes(range(1, 33))).decode()
PREFIX = "AbCdEfGhIj0123456789_-"
OTHER_PREFIX = "QrStUvWxYz9876543210ab"


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


#: Name of the thread that runs ``serve_forever`` and so accepts the connections.
ACCEPTING_THREAD = "test-serve"


def secret(*parts: str) -> str:
    return "".join(parts)


def registration(prefix: str = PREFIX, **changes) -> dict:
    document = {
        "prefix": prefix,
        "key": KEY,
        "expires_at": "2026-11-04T12:00:00Z",
        "retention_seconds": 3600,
        "secret_headers": ["X-Api-Token"],
    }
    document.update(changes)
    return document


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def data(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    path.mkdir()
    path.chmod(0o700)
    return path


@pytest.fixture
def store(data: Path, clock: Clock) -> Store:
    return Store(data, clock)


def run_register(data: Path, document, monkeypatch, capsys, clock=None) -> tuple[int, str]:
    raw = document if isinstance(document, bytes) else json.dumps(document).encode()

    class Stdin:
        buffer = io.BytesIO(raw)

    monkeypatch.setattr(sys, "stdin", Stdin)
    code = receiver_cli.main(["register", "--data", str(data)], clock or Clock())
    captured = capsys.readouterr()
    return code, captured.err + captured.out


@pytest.fixture
def serve(store: Store):
    started: list[tuple[Receiver, threading.Thread]] = []

    def start(peer_ip=None) -> int:
        receiver = Receiver(store, 0, peer_ip)
        thread = threading.Thread(target=receiver.serve_forever, name=ACCEPTING_THREAD)
        thread.start()
        started.append((receiver, thread))
        return receiver.port

    def stop() -> None:
        """Shut every service down and wait until its threads, last sweep included, are gone."""
        while started:
            receiver, thread = started.pop()
            receiver.shutdown()
            thread.join()
            receiver._sweeper.join()
            receiver.server_close()

    start.stop = stop
    yield start
    stop()


def send(port: int, raw: bytes) -> bytes:
    # Not create_connection: that resolves the host first, and one test counts resolutions.
    with socket.socket() as sock:
        sock.settimeout(15)
        sock.connect(("127.0.0.1", port))
        sock.sendall(raw)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def get(
    port: int,
    target: str,
    headers=(),
    body: bytes = b"",
    method: str = "POST",
    host: str = "cb.example",
) -> bytes:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}"]
    lines += [f"{name}: {value}" for name, value in headers]
    lines += [f"Content-Length: {len(body)}"] if body else []
    return send(port, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)


def register(store: Store, **changes) -> None:
    store.register(parse_registration(registration(**changes)))


def files_under(data: Path) -> list[Path]:
    return [p for p in data.rglob("*") if p.is_file()]


def names_under(data: Path) -> set[str]:
    return {p.name for p in files_under(data)}


def counts(data: Path) -> dict:
    path = data / "counts.json"
    return json.loads(path.read_text()) if path.exists() else {}


def entries(store: Store, prefix: str = PREFIX, after: int = 0) -> list[dict]:
    return store.read_entries(prefix, after)


def test_every_request_gets_the_same_answer(store, serve):
    register(store)
    port = serve()
    assert get(port, f"/{PREFIX}/payload-1") == RESPONSE
    assert get(port, f"/{OTHER_PREFIX}/payload-1") == RESPONSE
    assert get(port, "/", method="GET") == RESPONSE
    assert send(port, b"garbage\r\n\r\n") == RESPONSE
    assert RESPONSE.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: text/plain" in RESPONSE and b"Content-Length: 0" in RESPONSE


def test_no_value_reaches_the_disk(store, serve, data):
    register(store)
    port = serve()
    token = secret("tok", "en-", "9f3a1c77")
    cookie = secret("sess", "ion=", "c0ffee42")
    api = secret("api", "key ", "55aa77ee&x=1")
    param = secret("par", "am ", "value/+=7")
    body = secret("bo", "dy-", "payload 31337").encode()
    get(
        port,
        f"/{PREFIX}/job-17?q={quote(param)}&plain=visible-name-only",
        headers=[
            ("Authorization", f"Bearer {token}"),
            ("Cookie", cookie),
            ("X-Api-Token", api),
        ],
        body=body,
    )
    [entry] = entries(store)
    assert entry["path"] == "job-17"
    assert entry["body"]["size"] == len(body)
    assert entry["body"]["sha256"] == hashlib.sha256(body).hexdigest()
    assert set(entry["query"]) == {"q", "plain"}

    values = [token, cookie, api, param, body.decode(), f"Bearer {token}", "visible-name-only"]
    needles = set()
    for value in values:
        raw = value.encode()
        needles |= {raw, quote(value).encode(), quote(value, safe="").encode()}
        needles |= {base64.b64encode(raw), base64.urlsafe_b64encode(raw)}
        needles |= {base64.b64encode(raw).rstrip(b"="), raw.hex().encode()}
    found = files_under(data)
    assert found
    for path in found:
        content = path.read_bytes()
        for needle in needles:
            assert needle not in content, (path.name, needle)


def test_hmac_is_the_expected_one_and_depends_on_the_key(store, serve):
    register(store)
    register(store, prefix=OTHER_PREFIX, key=OTHER_KEY)
    port = serve()
    token = secret("Bearer ", "abc", "def 123")
    for prefix in (PREFIX, OTHER_PREFIX):
        get(port, f"/{prefix}/x?k=v1", headers=[("Authorization", token), ("X-Api-Token", "s")])
    mine, other = entries(store)[0], entries(store, OTHER_PREFIX)[0]
    key = base64.b64decode(KEY)
    expected = hmac.new(key, token.encode(), hashlib.sha256).hexdigest()
    assert mine["secret_headers"]["authorization"] == {
        "present": True,
        "scheme": "Bearer",
        "hmac": expected,
    }
    assert mine["secret_headers"]["x-api-token"]["scheme"] is None
    assert mine["query"]["k"] == [hmac.new(key, b"v1", hashlib.sha256).hexdigest()]
    assert other["secret_headers"]["authorization"]["hmac"] != expected
    assert other["query"] != mine["query"]


def test_headers_are_names_only_and_scheme_needs_credentials(store, serve):
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/a", headers=[("Authorization", "justonebareword"), ("X-Other", "v")])
    get(port, f"/{PREFIX}/b", headers=[("Authorization", "Bearer1 x"), ("Cookie", "a=b")])
    first, second = entries(store)
    assert first["secret_headers"]["authorization"]["scheme"] is None
    assert second["secret_headers"]["authorization"]["scheme"] is None
    assert "x-other" not in first["secret_headers"]
    assert first["headers"] == ["Host", "Authorization", "X-Other"]
    assert second["secret_headers"]["cookie"]["present"] is True
    assert first["method"] == "POST" and first["host"] == "cb.example"


def test_unknown_prefix_is_only_counted(store, serve, data):
    port = serve()
    marker = secret("mark", "er-", "7781")
    get(port, f"/{OTHER_PREFIX}/job?x={marker}", headers=[("Authorization", marker)], body=b"zz")
    get(port, "/elsewhere", method="GET")
    assert counts(data) == {"2026-11-03": 2}
    assert names_under(data) == {".lock", "counts.json"}
    assert all(marker.encode() not in p.read_bytes() for p in files_under(data))


def test_an_entry_goes_after_its_retention_unread(store, serve, clock):
    register(store, retention_seconds=100)
    port = serve()
    get(port, f"/{PREFIX}/one")
    clock.advance(60)
    get(port, f"/{PREFIX}/two")
    clock.advance(50)
    store.sweep()
    assert [e["path"] for e in entries(store)] == ["two"]
    clock.advance(60)
    store.sweep()
    assert entries(store) == []
    assert store.lookup(PREFIX) is not None


def test_deadlines_of_the_registration(store, serve, data, clock, capsys):
    register(store, expires_at="2026-11-03T12:05:00Z", retention_seconds=600)
    port = serve()
    get(port, f"/{PREFIX}/before")
    clock.advance(300)
    assert store.lookup(PREFIX) is None
    get(port, f"/{PREFIX}/after")
    assert counts(data) == {"2026-11-03": 1}
    assert receiver_cli.main(["pull", "--data", str(data), "--prefix", PREFIX], clock) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line)["path"] for line in lines] == ["before"]
    clock.advance(599)
    store.sweep()
    assert store.exists(PREFIX) and entries(store) == []
    clock.advance(1)
    code = receiver_cli.main(["pull", "--data", str(data), "--prefix", PREFIX], clock)
    captured = capsys.readouterr()
    assert code == receiver_cli.EXIT_NO_REGISTRATION and captured.out == ""
    assert len(captured.err.strip().splitlines()) == 1
    assert names_under(data) == {".lock", "counts.json"}


def write_stored(data: Path, document, prefix: str = PREFIX) -> None:
    """Put a registration on disk as an older version would have: no check on the way in."""
    raw = document if isinstance(document, bytes) else json.dumps(document).encode()
    state = json.dumps({"next_seq": 1, "hour": "", "hour_count": 0}).encode()
    for name, content in (
        (f"reg-{prefix}.json", raw),
        (f"state-{prefix}.json", state),
        (f"entries-{prefix}.jsonl", b""),
    ):
        (data / name).write_bytes(content)
        (data / name).chmod(0o600)


def test_a_stored_registration_is_not_held_to_the_newer_rules(store, serve, data, clock):
    old = "abcde" * 5
    document = registration(prefix=old, secret_headers=["Host", "X-Forwarded-For"])
    with pytest.raises(Rejected):
        parse_registration(document)
    write_stored(data, document, old)
    assert store.lookup(old) is not None
    port = serve()
    get(port, f"/{old}/job")
    assert [e["path"] for e in entries(store, old)] == ["job"]
    assert counts(data) == {}
    clock.advance(24 * 3600 + 3599)
    store.sweep()
    assert store.exists(old)
    clock.advance(1)
    store.sweep()
    assert not list(data.glob("*-" + old + "*"))
    assert counts(data) == {}


@pytest.mark.parametrize(
    "damaged",
    [
        b"{not json",
        b"",
        [1, 2],
        registration(retention_seconds="3600"),
        registration(expires_at="tomorrow"),
        registration(**{"secret_headers": "X-Api-Token"}),
        registration(extra=1),
        registration(prefix=OTHER_PREFIX),
        # A stored header name may keep exactly one trailing line feed, no more, and no name.
        registration(secret_headers=["X-Api-Token\n\n"]),
        registration(secret_headers=["\n"]),
    ],
    ids=[
        "not-json",
        "empty",
        "wrong-shape",
        "retention",
        "expiry",
        "headers",
        "extra",
        "prefix",
        "header-two-line-feeds",
        "header-line-feed-only",
    ],
)
def test_a_damaged_registration_is_deleted_whole_and_counted(store, data, damaged):
    write_stored(data, damaged)
    (data / f"entries-{PREFIX}.jsonl").write_bytes(b"line-of-an-entry\n")
    assert store.lookup(PREFIX) is None
    store.sweep()
    assert not list(data.glob("*-" + PREFIX + "*"))
    assert all(KEY.encode() not in p.read_bytes() for p in files_under(data))
    assert counts(data) == {"unreadable_registration": {"2026-11-03": 1}}
    store.sweep()
    assert counts(data) == {"unreadable_registration": {"2026-11-03": 1}}


def test_a_registration_under_an_old_line_feed_prefix_is_deleted_whole_and_counted(store, data):
    old = PREFIX[:21] + "\n"
    write_stored(data, registration(prefix=old), old)
    (data / f"entries-{old}.jsonl").write_bytes(b"line-of-an-entry\n")
    (data / f"reg-{old}.json.tmp").write_bytes(json.dumps(registration(prefix=old)).encode())
    (data / f"state-{old}.json.tmp").write_bytes(b"{}")
    (data / f"entries-{old}.jsonl.tmp").write_bytes(b"line-of-an-entry\n")
    orphan = OTHER_PREFIX[:21] + "\n"
    (data / f"state-{orphan}.json").write_bytes(b"{}")
    orphan_entries = OTHER_PREFIX[1:22] + "\n"
    (data / f"entries-{orphan_entries}.jsonl").write_bytes(b"line-of-an-entry\n")
    other = PREFIX[:20] + "\r\n"
    write_stored(data, registration(prefix=other), other)
    # Exactly one trailing line feed: with two, the name is no old prefix either.
    double = PREFIX[:20] + "\n\n"
    write_stored(data, registration(prefix=double), double)
    store.sweep()
    for gone in (old, orphan, orphan_entries):
        assert not list(data.glob("*-" + gone + "*")), gone
    assert counts(data) == {"unreadable_registration": {"2026-11-03": 1}}
    # Any other name that is no prefix is left alone, as before.
    assert len(list(data.glob("*-" + other + "*"))) == 3
    assert len(list(data.glob("*-" + double + "*"))) == 3
    assert sorted(p for p in files_under(data) if KEY.encode() in p.read_bytes()) == sorted(
        [data / f"reg-{other}.json", data / f"reg-{double}.json"]
    )


def test_a_stored_secret_header_name_with_a_trailing_line_feed_is_still_read(store, data):
    document = registration(secret_headers=["X-Api-Token\n"])
    with pytest.raises(Rejected):
        parse_registration(document)
    write_stored(data, document)
    assert store.lookup(PREFIX) is not None
    store.sweep()
    assert store.exists(PREFIX)
    assert counts(data) == {}


def test_a_stored_secret_header_name_with_a_trailing_line_feed_matches_no_header(
    store, serve, data
):
    write_stored(data, registration(secret_headers=["X-Api-Token\n"]))
    port = serve()
    api = secret("api", "key-", "4c1d93e0")
    get(port, f"/{PREFIX}/job", headers=[("X-Api-Token", api)])
    [entry] = entries(store)
    assert "X-Api-Token" in entry["headers"]
    # Neither the name as stored nor the name without its line feed is a secret header here.
    assert set(entry["secret_headers"]) == set()
    assert api not in json.dumps(entry)
    assert all(api.encode() not in p.read_bytes() for p in files_under(data))


@pytest.mark.parametrize("command", ["pull", "purge"])
def test_pull_and_purge_of_a_damaged_registration_exit_3(data, clock, capsys, command):
    write_stored(data, registration(retention_seconds="3600"))
    args = [command, "--data", str(data), "--prefix", PREFIX]
    assert receiver_cli.main(args, clock) == receiver_cli.EXIT_NO_REGISTRATION
    captured = capsys.readouterr()
    assert captured.out == "" and len(captured.err.strip().splitlines()) == 1
    assert not list(data.glob("*-" + PREFIX + "*"))
    assert counts(data) == {"unreadable_registration": {"2026-11-03": 1}}


def test_the_key_is_gone_with_the_registration(store, data, clock):
    register(store, retention_seconds=60)
    assert KEY.encode() in (data / f"reg-{PREFIX}.json").read_bytes()
    clock.now = datetime(2026, 11, 4, 12, 1, 0, tzinfo=timezone.utc)
    store.sweep()
    assert all(KEY.encode() not in p.read_bytes() for p in files_under(data))
    assert not list(data.glob("*-" + PREFIX + "*"))


def test_register_has_no_option_for_the_key():
    parser = receiver_cli.build_parser()
    sub = parser._subparsers._group_actions[0].choices["register"]
    options = {o for action in sub._actions for o in action.option_strings}
    assert options == {"-h", "--help", "--data"}
    with pytest.raises(SystemExit):
        parser.parse_args(["register", "--data", "x", "--key", KEY])


def test_register_stores_and_refuses_a_second(data, monkeypatch, capsys):
    code, out = run_register(data, registration(), monkeypatch, capsys)
    assert code == 0 and PREFIX in out
    code, out = run_register(data, registration(), monkeypatch, capsys)
    assert code == receiver_cli.EXIT_REFUSED and "already exists" in out


@pytest.mark.parametrize(
    ("changes", "place"),
    [
        ({"prefix": "short"}, "$.prefix"),
        ({"prefix": "a" * 21}, "$.prefix"),
        ({"prefix": "a" * 22 + "/x"}, "$.prefix"),
        ({"prefix": PREFIX[:21] + "\n"}, "$.prefix"),
        # Refused before prefixes were matched whole too; kept against a regression.
        ({"prefix": PREFIX[:20] + "\r\n"}, "$.prefix"),
        ({"prefix": 5}, "$.prefix"),
        ({"key": base64.b64encode(b"x" * 31).decode()}, "$.key"),
        ({"key": "not base64!"}, "$.key"),
        ({"expires_at": "2026-11-04T12:00:00"}, "$.expires_at"),
        ({"expires_at": "2026-11-04T12:00:00+02:00"}, "$.expires_at"),
        ({"retention_seconds": "3600"}, "$.retention_seconds"),
        ({"retention_seconds": True}, "$.retention_seconds"),
        ({"retention_seconds": 0}, "$.retention_seconds"),
        ({"secret_headers": "x"}, "$.secret_headers"),
        ({"secret_headers": ["ok", 3]}, "$.secret_headers[1]"),
        ({"secret_headers": ["bad name"]}, "$.secret_headers[0]"),
        ({"secret_headers": ["X-Api-Token\n"]}, "$.secret_headers[0]"),
        # Refused before header names were matched whole too; kept against a regression.
        ({"secret_headers": ["X-Api-Token\r\n"]}, "$.secret_headers[0]"),
        ({"secret_headers": ["ok", "Host"]}, "$.secret_headers[1]"),
        ({"secret_headers": ["x-forwarded-for"]}, "$.secret_headers[0]"),
        ({"secret_headers": ["X-FORWARDED-PROTO"]}, "$.secret_headers[0]"),
        ({"prefix": "a" * 22}, "$.prefix"),
        ({"prefix": "abcdefghi" * 3}, "$.prefix"),
        ({"expires_at": "2026-11-03T11:59:59Z"}, "$.expires_at"),
        ({"expires_at": "2026-11-03T12:00:00Z"}, "$.expires_at"),
        ({"extra": 1}, "$.extra"),
    ],
)
def test_register_refuses_with_a_place(data, monkeypatch, capsys, changes, place):
    code, out = run_register(data, registration(**changes), monkeypatch, capsys)
    assert code == receiver_cli.EXIT_REFUSED and place in out
    assert files_under(data) == []


# crlf was refused before prefixes were matched whole too; it is kept against a regression.
@pytest.mark.parametrize("ending", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_a_trailing_line_break_is_no_prefix(ending):
    # The length counts the line break: with it, 21 or 20 characters reach the minimum of 22.
    prefix = PREFIX[: limits.MIN_PREFIX_CHARS - len(ending)] + ending
    assert len(prefix) == limits.MIN_PREFIX_CHARS
    assert not check_prefix(prefix)


def test_register_accepts_ten_different_prefix_characters(data, monkeypatch, capsys):
    code, out = run_register(data, registration(prefix="abcdefghij" * 3), monkeypatch, capsys)
    assert code == 0 and "registered" in out


def test_register_names_the_reason_for_a_plain_text_header(data, monkeypatch, capsys):
    code, out = run_register(data, registration(secret_headers=["host"]), monkeypatch, capsys)
    assert code == receiver_cli.EXIT_REFUSED
    assert "$.secret_headers[0]" in out and "plain text" in out


def test_the_store_refuses_a_past_expiry_by_its_own_clock(store, clock):
    reg = parse_registration(registration(expires_at="2026-11-03T12:30:00Z"))
    clock.advance(1800)
    with pytest.raises(Rejected, match=r"\$\.expires_at"):
        store.register(reg)
    assert not store.exists(PREFIX)


def test_register_refuses_a_missing_key_and_bad_json(data, monkeypatch, capsys):
    document = registration()
    del document["key"]
    assert "$.key: missing" in run_register(data, document, monkeypatch, capsys)[1]
    assert "$: expected an object" in run_register(data, [1], monkeypatch, capsys)[1]
    assert "not valid JSON" in run_register(data, b"{", monkeypatch, capsys)[1]
    assert files_under(data) == []


def test_pull_gives_only_its_own_entries_after_n(store, serve, data, clock, capsys):
    register(store)
    register(store, prefix=OTHER_PREFIX)
    port = serve()
    for name in ("a", "b", "c"):
        get(port, f"/{PREFIX}/{name}")
    get(port, f"/{OTHER_PREFIX}/theirs")

    def pulled(*extra: str) -> list[dict]:
        args = ["pull", "--data", str(data), "--prefix", PREFIX, *extra]
        assert receiver_cli.main(args, clock) == 0
        return [json.loads(line) for line in capsys.readouterr().out.splitlines()]

    assert [e["path"] for e in pulled()] == ["a", "b", "c"]
    assert [e["seq"] for e in pulled()] == [1, 2, 3]
    assert [e["path"] for e in pulled("--after", "1")] == ["b", "c"]
    assert pulled("--after", "3") == []


def test_purge_deletes_at_once(store, serve, data, clock, capsys):
    register(store)
    register(store, prefix=OTHER_PREFIX)
    port = serve()
    get(port, f"/{PREFIX}/a")
    get(port, f"/{OTHER_PREFIX}/b")
    code = receiver_cli.main(["purge", "--data", str(data), "--prefix", PREFIX], clock)
    assert code == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 1
    assert not list(data.glob("*-" + PREFIX + "*"))
    assert not store.exists(PREFIX) and store.exists(OTHER_PREFIX)
    assert len(entries(store, OTHER_PREFIX)) == 1


def test_oversized_headers_are_counted_not_recorded(store, serve, data):
    register(store)
    port = serve()
    big = "x" * limits.MAX_HEADER_BYTES
    assert get(port, f"/{PREFIX}/h", headers=[("X-Big", big)]) == RESPONSE
    assert entries(store) == []
    assert counts(data) == {"2026-11-03": 1}
    assert get(port, f"/{PREFIX}/h", headers=[("X-Big", "x" * 15000)]) == RESPONSE
    assert len(entries(store)) == 1


def test_a_body_is_read_only_up_to_the_limit(store, serve):
    register(store)
    port = serve()
    body = b"a" * (limits.MAX_BODY_BYTES + 5000)
    assert get(port, f"/{PREFIX}/big", body=body) == RESPONSE
    [entry] = entries(store)
    assert entry["body"] == {
        "size": limits.MAX_BODY_BYTES,
        "sha256": hashlib.sha256(body[: limits.MAX_BODY_BYTES]).hexdigest(),
        "truncated": True,
    }


def test_a_chunked_body_is_hashed(store, serve):
    register(store)
    port = serve()
    raw = (
        f"POST /{PREFIX}/c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
    ).encode()
    assert send(port, raw) == RESPONSE
    [entry] = entries(store)
    assert entry["body"]["size"] == 5
    assert entry["body"]["sha256"] == hashlib.sha256(b"abcde").hexdigest()


def test_entries_per_hour_are_capped_then_counted(store, serve, data, clock, monkeypatch):
    monkeypatch.setattr(limits, "MAX_ENTRIES_PER_HOUR", 3)
    register(store)
    port = serve()
    for _ in range(5):
        get(port, f"/{PREFIX}/n")
    assert len(entries(store)) == 3
    assert counts(data) == {"2026-11-03": 2}
    clock.advance(1800)
    get(port, f"/{PREFIX}/n")
    clock.advance(1800)
    get(port, f"/{PREFIX}/n")
    assert [e["seq"] for e in entries(store)] == [4]


def test_the_data_directory_is_capped(store, serve, data, monkeypatch):
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/fits")
    monkeypatch.setattr(limits, "MAX_DATA_BYTES", sum(p.stat().st_size for p in files_under(data)))
    get(port, f"/{PREFIX}/does-not")
    assert [e["path"] for e in entries(store)] == ["fits"]
    assert counts(data) == {"2026-11-03": 1}


def test_a_silent_connection_is_cut_at_the_time_limit(store, serve, data, monkeypatch):
    monkeypatch.setattr(limits, "CONNECTION_TIMEOUT_SECONDS", 0.5)
    register(store)
    port = serve()
    assert send(port, b"POST /x HTTP/1.1\r\n") == RESPONSE
    assert counts(data) == {"2026-11-03": 1}


def test_at_most_the_connection_limit_at_once(store, serve, monkeypatch):
    monkeypatch.setattr(limits, "MAX_CONNECTIONS", 2)
    port = serve()
    held = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]
    try:
        # Both held connections have a handler thread before the third one arrives.
        with socket.create_connection(("127.0.0.1", port), timeout=5) as third:
            third.sendall(b"GET / HTTP/1.1\r\n\r\n")
            assert third.recv(100) == b""
    finally:
        for sock in held:
            sock.close()


def test_connections_over_the_limit_are_counted_in_memory_then_carried(
    store, serve, data, clock, monkeypatch
):
    monkeypatch.setattr(limits, "MAX_CONNECTIONS", 1)
    port = serve()
    with disk_watching() as touched:
        held = socket.create_connection(("127.0.0.1", port))
        try:
            for _ in range(3):
                with socket.create_connection(("127.0.0.1", port), timeout=5) as extra:
                    extra.sendall(b"GET / HTTP/1.1\r\n\r\n")
                    assert extra.recv(100) == b""
        finally:
            held.close()
        # Each extra connection was closed by the accepting thread before the line above ended.
    assert touched == []
    store.sweep()
    # (The held connection, closed without a request, may add a day count of its own.)
    assert counts(data)["over_connection_limit"] == {"2026-11-03": 3}
    store.sweep()
    assert counts(data)["over_connection_limit"] == {"2026-11-03": 3}
    clock.advance(24 * 3600)
    store.count_over_limit()
    store.sweep()
    assert counts(data)["over_connection_limit"] == {"2026-11-03": 3, "2026-11-04": 1}


def test_files_are_0600_and_a_loose_directory_stops_everything(store, serve, data, clock, capsys):
    register(store)
    port = serve()
    get(port, f"/{PREFIX}/a")
    get(port, "/nothing", method="GET")
    store.sweep()
    assert files_under(data)
    for path in files_under(data):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
    data.chmod(0o755)
    for command in (
        ["serve", "--port", "0"],
        ["register"],
        ["pull", "--prefix", PREFIX],
        ["purge", "--prefix", PREFIX],
    ):
        code = receiver_cli.main([command[0], "--data", str(data), *command[1:]], clock)
        assert code == receiver_cli.EXIT_DATA_DIR
        assert "0700" in capsys.readouterr().err


def test_a_missing_data_directory_stops(tmp_path):
    code = receiver_cli.main(["purge", "--data", str(tmp_path / "no"), "--prefix", PREFIX])
    assert code == receiver_cli.EXIT_DATA_DIR


def test_forwarded_headers_are_believed_from_the_proxy_only(store, serve):
    register(store)
    proxied = [("X-Forwarded-For", "198.51.100.7"), ("X-Forwarded-Proto", "https")]
    port = serve()
    get(port, f"/{PREFIX}/via-proxy", headers=proxied)
    get(port, f"/{PREFIX}/direct")
    port = serve(peer_ip=lambda address: "203.0.113.9")
    get(port, f"/{PREFIX}/stranger", headers=proxied)
    get(port, f"/{PREFIX}/bad-for", headers=[("X-Forwarded-For", "not an address")])
    via_proxy, direct, stranger, bad = entries(store)
    assert (via_proxy["sender"], via_proxy["scheme"]) == ("198.51.100.7", "https")
    assert (direct["sender"], direct["scheme"]) == ("127.0.0.1", "http")
    assert (stranger["sender"], stranger["scheme"]) == ("203.0.113.9", "http")
    assert bad["sender"] == "203.0.113.9"


_events: list[tuple[str, tuple]] = []
_auditing = threading.Event()
_touched: list[tuple[str, tuple]] = []
_disk_auditing = threading.Event()
_DISK_EVENTS = ("open", "os.rename", "os.remove", "os.rmdir", "os.mkdir", "os.truncate")


def _on_accepting_thread() -> bool:
    return threading.current_thread().name == ACCEPTING_THREAD


def _audit(event: str, args: tuple) -> None:
    # Every thread, by design: which thread opened a connection proves nothing.
    if event in ("socket.connect", "socket.getaddrinfo") and _auditing.is_set():
        _events.append((event, args[1:] if event == "socket.connect" else args))
    elif event in _DISK_EVENTS and _disk_auditing.is_set() and _on_accepting_thread():
        _touched.append((event, args))


sys.addaudithook(_audit)


@contextlib.contextmanager
def watching():
    _events.clear()
    _auditing.set()
    try:
        yield _events
    finally:
        _auditing.clear()


@contextlib.contextmanager
def disk_watching():
    """What the accepting thread does to the disk while the block runs: a read counts too."""
    _touched.clear()
    _disk_auditing.set()
    try:
        yield _touched
    finally:
        _disk_auditing.clear()


def foreign(events: list, port: int) -> list:
    """Everything but the test's own connections to the service."""
    return [e for e in events if e != ("socket.connect", (("127.0.0.1", port),))]


def test_the_service_opens_no_connection(store, serve):
    register(store)
    with watching() as events:
        port = serve()
        get(port, f"/{PREFIX}/a", headers=[("X-Forwarded-For", "198.51.100.7")])
        get(port, f"/{OTHER_PREFIX}/b")
        store.sweep()
        # The window closes only when the service thread has ended, last sweep included.
        serve.stop()
    assert foreign(events, port) == []
    # The hook does see the test's own connections, so an empty list above is not a blind hook.
    assert [e for e in events if e[0] == "socket.connect"]


def test_the_disk_hook_sees_the_accepting_thread(store, serve, monkeypatch):
    original = Receiver.process_request

    def writing(self, request, client_address):
        # Directly, not through the store: the first sweep may carry a count off on its own thread.
        scratch = self.store.root / "written-by-the-test"
        scratch.write_bytes(b"")
        scratch.rename(self.store.root / "renamed-by-the-test")
        original(self, request, client_address)

    monkeypatch.setattr(Receiver, "process_request", writing)
    with disk_watching() as touched:
        port = serve()
        get(port, f"/{PREFIX}/a")
    assert {event for event, _ in touched} >= {"open", "os.rename"}


@pytest.mark.parametrize("call", ["connect", "getaddrinfo"])
def test_a_smuggled_call_from_the_service_thread_is_seen(store, serve, monkeypatch, call):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        elsewhere = listener.getsockname()
        original = Receiver.process_request

        def smuggling(self, request, client_address):
            if call == "connect":
                with socket.socket() as sock:
                    sock.connect(elsewhere)
            else:
                socket.getaddrinfo("127.0.0.1", 9)
            original(self, request, client_address)

        monkeypatch.setattr(Receiver, "process_request", smuggling)
        with watching() as events:
            port = serve()
            get(port, f"/{PREFIX}/a")
    [seen] = foreign(events, port)
    assert seen[0] == f"socket.{call}"
