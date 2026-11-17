"""The token inspector: what may enter a recording, and that nothing else does."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone

import pytest

from mcp_kymograph.token_inspector import (
    GRAPH_AUDIENCES,
    KNOWN_REASONS,
    KNOWN_WARNINGS,
    PSEUDONYM_KINDS,
    inspect,
)

KEY = b"".join([b"test-key", b"-not-a-", b"secret"])  # built at run time, not a literal
GUID = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"


def pseudonymize(kind: str, value: str) -> str:
    digest = hmac.new(KEY, f"{kind}\0{value}".encode(), hashlib.sha256).hexdigest()
    return f"{kind}-{digest[:12]}"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make(payload: object, header: object = None, signature: str | None = None) -> str:
    head = {"alg": "RS256", "typ": "JWT"} if header is None else header
    sig = signature if signature is not None else b64(bytes(range(64)))
    return ".".join([b64(json.dumps(head).encode()), b64(json.dumps(payload).encode()), sig])


def view(payload: dict):
    return inspect(make(payload), pseudonymize)


def test_constants():
    assert set(KNOWN_REASONS) == {
        "too_long",
        "not_jwt",
        "encrypted",
        "bad_encoding",
        "bad_json",
        "not_object",
        "inspection_failed",
    }
    assert set(KNOWN_WARNINGS) == {"aud_is_graph", "truncated"}
    assert "tenant" in PSEUDONYM_KINDS


# --- readable claims -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "good", "expected", "bad"),
    [
        ("aud", "api://x", "api://x", 5),
        ("aud", ["a", "b"], ("a", "b"), ["a", 1]),
        ("scp", "read write", "read write", ["read"]),
        ("roles", ["r1", "r2"], ("r1", "r2"), "r1"),
        ("azp", "app-1", "app-1", 1),
        ("appid", "app-2", "app-2", {"a": 1}),
        ("exp", 1700000000, 1700000000, "1700000000"),
        ("exp", 1700000000.9, 1700000000, True),
    ],
)
def test_readable_claims(name, good, expected, bad):
    ok = view({name: good})
    assert ok.readable and ok.reason is None
    assert ok.claims == {name: expected}
    assert ok.unexpected == ()
    wrong = view({name: bad})
    assert wrong.readable
    assert name not in wrong.claims
    assert wrong.unexpected == (name,)


@pytest.mark.parametrize("text", ["NaN", "Infinity", "-Infinity"])
def test_nan_and_infinity_are_bad_json(text):
    assert inspect(raw("{}", '{"exp": ' + text + "}"), pseudonymize).reason == "bad_json"
    assert inspect(raw("{}", '{"x": ' + text + "}"), pseudonymize).reason == "bad_json"
    assert inspect(raw('{"x": ' + text + "}", "{}"), pseudonymize).reason == "bad_json"


def test_exp_beyond_float_range_is_unexpected():
    result = inspect(raw("{}", '{"exp": 1e999}'), pseudonymize)  # parses to inf
    assert result.unexpected == ("exp",)


@pytest.mark.parametrize("exp", [1e308, -1, -0.5, 2**63, 10**19])
def test_exp_out_of_range_is_unexpected(exp):
    result = view({"exp": exp})
    assert result.readable
    assert result.unexpected == ("exp",)
    assert result.claims == {}


@pytest.mark.parametrize(
    ("exp", "expected"),
    [(1767225600, 1767225600), (0, 0), (2**63 - 1, 2**63 - 1), (1767225600.9, 1767225600)],
)
def test_exp_in_range_is_read(exp, expected):
    result = view({"exp": exp})
    assert result.claims == {"exp": expected}
    assert result.unexpected == ()


def test_other_claims_are_counted_not_named():
    result = view({"aud": "a", "secretish_name": "v", "another": 1, "third": [1]})
    assert result.other_claims == 3
    assert "secretish_name" not in repr(result)
    assert "secretish_name" not in json.dumps(result.to_json())


def test_unexpected_is_sorted_and_hides_value():
    result = view({"scp": 1, "azp": "x" * 3, "aud": {"k": "hidden-value-123"}, "exp": "soon"})
    assert result.unexpected == ("aud", "exp", "scp")
    assert "hidden-value-123" not in repr(result)


# --- lone surrogates and failing pseudonymizers ----------------------------------------------

LONE = "alice\ud800@contoso.example"


def strict_pseudonymize(kind: str, value: str) -> str:
    """Like a pseudonymizer that works on bytes: raises on a lone surrogate."""
    return kind + "-" + value.encode("utf-8").hex()[:8]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("upn", LONE),
        ("email", LONE),
        ("aud", LONE),
        ("aud", ["api://ok", LONE]),
        ("scp", LONE),
        ("roles", ["r1", LONE]),
        ("azp", LONE),
        ("appid", LONE),
        ("tid", LONE),
        ("oid", LONE),
        ("iss", LONE),
        ("name", LONE),
    ],
)
def test_lone_surrogate_is_unexpected(name, value):
    calls = []

    def recording(kind, text):
        calls.append(text)
        return strict_pseudonymize(kind, text)

    token = make({name: value})
    assert "\\ud800" in b64decode(token.split(".")[1])  # the escape is in the payload
    for func in (recording, pseudonymize, strict_pseudonymize):
        result = inspect(token, func)
        assert result.readable
        assert result.unexpected == (name,)
        assert result.claims == {} and result.pseudonyms == {}
        out = repr(result) + json.dumps(result.to_json())
        assert "alice" not in out
    assert calls == []


def test_lone_surrogate_in_one_claim_leaves_the_others():
    result = inspect(make({"upn": LONE, "aud": "api://ok", "tid": GUID}), strict_pseudonymize)
    assert result.unexpected == ("upn",)
    assert result.claims == {"aud": "api://ok"}
    assert list(result.pseudonyms) == ["tid"]


def test_surrogate_pair_is_a_valid_string():
    result = view({"scp": "ok-\U0001f600"})  # json.dumps escapes the emoji as a pair
    assert result.claims == {"scp": "ok-\U0001f600"}
    assert result.unexpected == ()


@pytest.mark.parametrize("exc", [RuntimeError, ValueError, RecursionError, KeyError, OSError])
def test_failing_pseudonymizer_gives_inspection_failed(exc):
    marker_text = "plaintext-marker-4711"

    def raising(kind, value):
        raise exc(f"cannot handle {value}")

    result = inspect(make({"upn": marker_text, "aud": "api://x"}), raising)
    assert not result.readable
    assert result.reason == "inspection_failed"
    assert result.claims == {} and result.pseudonyms == {}
    assert result.unexpected == () and result.warnings == () and result.other_claims == 0
    out = repr(result) + json.dumps(result.to_json())
    assert marker_text not in out and "api://x" not in out


def test_unicode_error_from_pseudonymizer_is_caught():
    def raising(kind, value):
        return value.encode("ascii")  # the text of the error holds the value

    result = inspect(make({"name": "Zoë Example"}), raising)
    assert result.reason == "inspection_failed"
    assert "Zo" not in repr(result)


MARK = "plaintext-marker-4711"


class OwnBase(BaseException):
    pass


@pytest.mark.parametrize("exc", [OwnBase, GeneratorExit])
def test_base_exception_gives_inspection_failed(exc):
    def raising(kind, value):
        raise exc(MARK)

    result = inspect(make({"tid": GUID}), raising)
    assert not result.readable
    assert result.reason == "inspection_failed"
    assert MARK not in repr(result) + json.dumps(result.to_json())


def assert_clean(e, expected_type, args=()):
    assert type(e) is expected_type
    assert e.args == args
    assert e.__cause__ is None and e.__context__ is None and e.__suppress_context__ is True
    assert MARK not in "".join(traceback.format_exception(e)) + repr(e) + repr(e.args)


@pytest.mark.parametrize("exc", [MemoryError, KeyboardInterrupt])
def test_interrupts_are_passed_on_without_plaintext(exc):
    def raising(kind, value):
        try:
            raise UnicodeEncodeError("ascii", MARK, 0, 1, MARK)
        except UnicodeEncodeError:
            raise exc(MARK) from None

    with pytest.raises(exc) as info:
        inspect(make({"tid": GUID}), raising)
    assert_clean(info.value, exc)


@pytest.mark.parametrize("exc", [MemoryError, KeyboardInterrupt])
def test_interrupt_raised_in_except_block_has_no_context(exc):
    def raising(kind, value):
        try:
            raise UnicodeEncodeError("ascii", MARK, 0, 1, MARK)
        except UnicodeEncodeError:
            raise exc(MARK)  # noqa: B904  (implicit context on purpose)

    with pytest.raises(exc) as info:
        inspect(make({"tid": GUID}), raising)
    assert_clean(info.value, exc)


def test_memory_error_subclass_is_passed_on_as_the_base_class():
    class OwnMemory(MemoryError):
        def __init__(self, *args):
            super().__init__(MARK)

    def raising(kind, value):
        raise OwnMemory()

    with pytest.raises(MemoryError) as info:
        inspect(make({"tid": GUID}), raising)
    assert_clean(info.value, MemoryError)


def test_keyboard_interrupt_subclass_with_raising_init_is_passed_on_as_the_base_class():
    class OwnInterrupt(KeyboardInterrupt):
        def __init__(self, *args):
            raise OwnBase(MARK)

    def raising(kind, value):
        raise OwnInterrupt.__new__(OwnInterrupt)

    with pytest.raises(KeyboardInterrupt) as info:
        inspect(make({"tid": GUID}), raising)
    assert_clean(info.value, KeyboardInterrupt)


@pytest.mark.parametrize(
    ("code", "expected"),
    [(3, 3), (0, 0), (True, 1), (False, 0), (MARK, 1), (None, 1)],
)
def test_system_exit_keeps_an_int_code(code, expected):
    def raising(kind, value):
        raise SystemExit(code)

    with pytest.raises(SystemExit) as info:
        inspect(make({"tid": GUID}), raising)
    e = info.value
    assert_clean(e, SystemExit, (expected,))
    assert e.code == expected
    assert type(e.code) is int  # a bool code must come out as a plain int


def test_system_exit_with_raising_code_property_gives_code_1():
    class OwnExit(SystemExit):
        @property
        def code(self):
            raise ValueError(MARK)

    def raising(kind, value):
        raise OwnExit(MARK)

    with pytest.raises(SystemExit) as info:
        inspect(make({"tid": GUID}), raising)
    e = info.value
    assert_clean(e, SystemExit, (1,))
    assert e.code == 1


def test_scp_as_list_is_unexpected():
    surrogate = "scope\ud800"
    calls = []

    def recording(kind, text):
        calls.append((kind, text))
        return pseudonymize(kind, text)

    result = inspect(make({"scp": ["read", surrogate, MARK]}), recording)
    assert result.readable
    assert result.unexpected == ("scp",)
    assert result.claims == {} and result.pseudonyms == {}
    out = repr(result) + json.dumps(result.to_json())
    assert MARK not in out and "'read'" not in out and "scope" not in out
    assert calls == []


# --- pseudonymized claims --------------------------------------------------------------------

PSEUDO_PLAIN = {
    "tid": ("tenant", GUID),
    "oid": ("object", "11111111-2222-3333-4444-555555555555"),
    "email": ("email", "alice.example@contoso.example"),
    "name": ("name", "Alice Example"),
    "upn": ("email", "alice.upn@contoso.example"),
}


@pytest.mark.parametrize("name", sorted(PSEUDO_PLAIN))
def test_pseudonymized_claims(name):
    kind, value = PSEUDO_PLAIN[name]
    result = view({name: value})
    assert result.pseudonyms == {name: pseudonymize(kind, value)}
    assert result.claims == {}
    wrong = view({name: 42})
    assert wrong.unexpected == (name,)
    assert wrong.pseudonyms == {}


@pytest.mark.parametrize("name", sorted(PSEUDO_PLAIN) + ["iss"])
@pytest.mark.parametrize("shape", ["object", "list", "number", "bool", "null"])
def test_wrong_typed_pseudonymized_claim_leaks_nothing(name, shape):
    marker = "wrong-type-marker-8642"
    wrong = {
        "object": {"x": marker},
        "list": [marker],
        "number": 7,
        "bool": True,
        "null": None,
    }[shape]
    result = view({name: wrong})
    assert result.unexpected == (name,)
    assert result.pseudonyms == {} and result.claims == {}
    out = repr(result) + json.dumps(result.to_json())
    assert marker not in out


def test_tid_that_is_no_guid_is_passed_unchanged():
    calls = []

    def recording(kind, value):
        calls.append((kind, value))
        return "p"

    inspect(make({"tid": "Contoso-Tenant-ID"}), recording)
    assert calls == [("tenant", "Contoso-Tenant-ID")]


@pytest.mark.parametrize(
    ("upn", "kind"),
    [
        ("a@b", "email"),
        ("a@@b", "account"),
        ("@b", "account"),
        ("a@", "account"),
        ("ab", "account"),
    ],
)
def test_upn_kind(upn, kind):
    assert view({"upn": upn}).pseudonyms == {"upn": pseudonymize(kind, upn)}


def test_issuer_other_is_pseudonymized_whole():
    iss = "https://idp.example/realm/one"
    assert view({"iss": iss}).pseudonyms == {"iss": pseudonymize("issuer", iss)}
    odd = f"https://login.microsoftonline.com/{GUID}/v1.0"
    assert view({"iss": odd}).pseudonyms == {"iss": pseudonymize("issuer", odd)}
    assert view({"iss": 5}).unexpected == ("iss",)


@pytest.mark.parametrize(
    "template",
    ["https://login.microsoftonline.com/{}/v2.0", "https://sts.windows.net/{}/"],
)
def test_entra_issuer_and_tid_share_the_pseudonym(template):
    result = view({"iss": template.format(GUID.upper()), "tid": GUID.upper()})
    pseudo = pseudonymize("tenant", GUID)
    assert result.pseudonyms["tid"] == pseudo
    assert result.pseudonyms["iss"] == template.format(pseudo)
    lower = view({"iss": template.format(GUID), "tid": GUID})
    assert lower.pseudonyms == result.pseudonyms


def test_plaintext_values_do_not_appear():
    payload = {name: value for name, (_, value) in PSEUDO_PLAIN.items()}
    payload["iss"] = f"https://sts.windows.net/{GUID}/"
    payload["aud"] = "api://kept"
    result = view(payload)
    out = repr(result) + json.dumps(result.to_json())
    for value in payload.values():
        if value != "api://kept":
            assert value not in out
    assert GUID not in out and GUID.upper() not in out
    assert "api://kept" in out


# --- unreadable ------------------------------------------------------------------------------


def nesting(depth: int) -> str:
    return "[" * depth + "]" * depth


def raw(head: str, payload: str, sig: str | None = None) -> str:
    sig = b64(b"sig") if sig is None else sig
    return f"{b64(head.encode())}.{b64(payload.encode())}.{sig}"


UNREADABLE = {
    "too_long": "A" * (16 * 1024 + 1),
    "not_jwt": "not-a-token",
    "encrypted": ".".join([b64(b"ABC")] * 5),
    "bad_encoding": ".".join([b64(b"{}"), "A", b64(b"ABC")]),  # "A" is one sextet too short
    "bad_json": raw("{}", "{nope"),
    "not_object": raw("{}", "[1, 2]"),
}


@pytest.mark.parametrize("reason", sorted(UNREADABLE))
def test_unreadable_reasons(reason):
    result = inspect(UNREADABLE[reason], pseudonymize)
    assert not result.readable
    assert result.reason == reason
    assert result.claims == {} and result.pseudonyms == {}
    assert result.unexpected == () and result.warnings == () and result.other_claims == 0
    assert result.expired(datetime.now(timezone.utc)) is None


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        ("", "not_jwt"),
        ("a.b", "not_jwt"),
        ("a.b.c.d", "not_jwt"),
        ("Bearer " + make({"aud": "x"}), "not_jwt"),
        (make({}) + "=", "not_jwt"),
        ("..", "bad_json"),
        (".".join(["", b64(b"{}"), b64(b"sig")]), "bad_json"),
        (".".join([b64(b"{}"), "", b64(b"sig")]), "bad_json"),
        (raw("[]", "{}"), "not_object"),
        (raw("{nope", "{}"), "bad_json"),
        (b64(b"{}") + "." + b64(b"\xff\xfe") + "." + b64(b"sig"), "bad_encoding"),
        ("ä" * 9000, "too_long"),
    ],
)
def test_unreadable_edges(token, reason):
    assert inspect(token, pseudonymize).reason == reason


def padded(total: int) -> str:
    """A readable token of exactly ``total`` characters."""
    for pad in range(total):
        token = raw("{}", '{"aud":"a"}' + " " * pad)
        if len(token) >= total:
            break
    assert len(token) == total
    return token


def test_token_size_limit_is_exact():
    assert inspect(padded(16 * 1024), pseudonymize).claims == {"aud": "a"}
    assert inspect(padded(16 * 1024 + 1), pseudonymize).reason == "too_long"


@pytest.mark.parametrize("value", [None, 5, b"a.b.c", ["a", "b", "c"], {"a": 1}, 1.5])
def test_input_that_is_not_a_string(value):
    result = inspect(value, pseudonymize)  # type: ignore[arg-type]
    assert not result.readable and result.reason == "not_jwt"


@pytest.fixture
def no_digit_limit():
    """Switch off CPython's own limit on integer digits, as ``PYTHONINTMAXSTRDIGITS=0`` does."""
    if not hasattr(
        sys, "get_int_max_str_digits"
    ):  # Python before 3.10.7 has no limit to switch off
        yield
        return
    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    yield
    sys.set_int_max_str_digits(old)


def test_long_integer_without_the_python_limit(no_digit_limit):
    assert int("9" * 12_000) > 0  # the interpreter really converts now
    assert inspect(raw("{}", '{"exp": ' + "9" * 12_000 + "}"), pseudonymize).reason == "bad_json"
    assert inspect(raw('{"x": ' + "9" * 12_000 + "}", "{}"), pseudonymize).reason == "bad_json"


def test_number_length_limits():
    ok = inspect(raw("{}", '{"exp": ' + "9" * 20 + "}"), pseudonymize)
    assert ok.readable and ok.unexpected == ("exp",)
    assert inspect(raw("{}", '{"exp": -' + "9" * 20 + "}"), pseudonymize).readable
    assert inspect(raw("{}", '{"exp": ' + "9" * 21 + "}"), pseudonymize).reason == "bad_json"
    assert inspect(raw("{}", '{"exp": -' + "9" * 21 + "}"), pseudonymize).reason == "bad_json"
    flt = "1." + "0" * 30  # 32 characters
    assert inspect(raw("{}", '{"exp": ' + flt + "}"), pseudonymize).claims == {"exp": 1}
    assert inspect(raw("{}", '{"exp": ' + flt + "0}"), pseudonymize).reason == "bad_json"


def test_huge_number_and_deep_nesting():
    assert inspect(raw("{}", '{"exp": ' + "9" * 5000 + "}"), pseudonymize).reason == "bad_json"
    # 10 000 open lists fit in 16 KiB once encoded; a closed 10 000-deep nest would not
    assert inspect(raw("{}", "[" * 10_000), pseudonymize).reason == "bad_json"
    assert inspect(raw("{}", '{"a": ' + "[" * 9_000), pseudonymize).reason == "bad_json"
    assert inspect(raw("[" * 9_000, "{}"), pseudonymize).reason == "bad_json"
    closed = inspect(raw("{}", nesting(5_000)), pseudonymize)
    assert closed.reason in ("bad_json", "not_object")  # depends on the parser's depth limit


def test_signature_is_not_decoded():
    token = make({"aud": "a"}, signature="A")  # not valid Base64 on its own
    assert inspect(token, pseudonymize).readable


def test_unsigned_token_is_read():
    token = make({"aud": "a", "exp": 5}, header={"alg": "none"}, signature="")
    assert token.endswith(".")
    result = inspect(token, pseudonymize)
    assert result.readable and result.reason is None
    assert result.claims == {"aud": "a", "exp": 5}


def test_header_content_does_not_appear():
    token = make({"aud": "a"}, header={"alg": "none", "kid": "key-id-marker-9876"})
    out = repr(inspect(token, pseudonymize))
    assert "key-id-marker-9876" not in out


# --- no byte of the token --------------------------------------------------------------------


def b64decode(part: str) -> str:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode()


def pieces(text: str, size: int = 8):
    for start in range(len(text) - size + 1):
        yield text[start : start + size]


def test_no_piece_of_the_token_in_output():
    payload = {
        "aud": "api://kept-audience",
        "scp": "kept.scope",
        "exp": 1700000000,
        "tid": GUID,
        "oid": "11111111-2222-3333-4444-555555555555",
        "name": "Alice Example",
        "iss": "https://idp.example/zzzz",
        "extra": "unique-extra-value-xyz",
    }
    tokens = [
        make(payload),
        make(payload, signature=b64(b"signature-bytes-marker-0123456789")),
        make({"aud": 7, "extra": "another-unique-value"}),
        UNREADABLE["bad_json"],
        UNREADABLE["not_object"],
        UNREADABLE["bad_encoding"],
        UNREADABLE["encrypted"],
        UNREADABLE["not_jwt"],
        "x" * 100,
    ]
    allowed = ["api://kept-audience", "kept.scope"]
    for token in tokens:
        result = inspect(token, pseudonymize)
        out = repr(result) + json.dumps(result.to_json())
        stripped = out
        for keep in allowed:
            stripped = stripped.replace(keep, "")
        assert token not in stripped
        for part in token.split("."):
            assert part not in stripped or len(part) < 8
        for piece in pieces(token):
            assert piece not in stripped, piece


# --- Graph -----------------------------------------------------------------------------------


@pytest.mark.parametrize("audience", sorted(GRAPH_AUDIENCES))
def test_graph_audience_warns(audience):
    for form in (audience, audience + "/", audience.upper(), audience.title()):
        assert view({"aud": form}).warnings == ("aud_is_graph",)
        assert view({"aud": ["api://other", form]}).warnings == ("aud_is_graph",)


def test_graph_audience_list_contents():
    assert "00000003-0000-0000-c000-000000000000" in GRAPH_AUDIENCES
    assert "https://graph.microsoft.com" in GRAPH_AUDIENCES
    assert "https://graph.microsoft.us" in GRAPH_AUDIENCES
    assert "https://dod-graph.microsoft.us" in GRAPH_AUDIENCES
    assert "https://microsoftgraph.chinacloudapi.cn" in GRAPH_AUDIENCES


@pytest.mark.parametrize("aud", ["api://other", ["api://a", "https://graph.microsoft.com.x"], []])
def test_other_audience_does_not_warn(aud):
    assert view({"aud": aud}).warnings == ()


# --- truncation ------------------------------------------------------------------------------


def test_long_string_is_cut():
    result = view({"scp": "s" * 300})
    assert result.claims["scp"] == "s" * 256
    assert result.warnings == ("truncated",)


def test_long_list_is_cut():
    result = view({"roles": [f"r{i}" for i in range(100)]})
    assert len(result.claims["roles"]) == 64
    assert result.warnings == ("truncated",)
    assert len(result.to_json()["claims"]["roles"]) == 64


def test_long_entry_in_list_is_cut():
    result = view({"aud": ["a" * 300]})
    assert result.claims["aud"] == ("a" * 256,)
    assert result.warnings == ("truncated",)


def test_no_truncation_at_the_limit():
    assert view({"scp": "s" * 256, "roles": ["r"] * 64}).warnings == ()


def test_warnings_sorted():
    result = view({"aud": "https://graph.microsoft.com", "scp": "s" * 300})
    assert result.warnings == ("aud_is_graph", "truncated")


# --- expired and to_json ---------------------------------------------------------------------


def test_expired():
    exp = datetime(2030, 1, 1, tzinfo=timezone.utc)
    result = view({"exp": int(exp.timestamp())})
    assert result.expired(exp + timedelta(seconds=1)) is True
    assert result.expired(exp - timedelta(seconds=1)) is False
    assert (
        result.expired((exp + timedelta(hours=1)).astimezone(timezone(timedelta(hours=5)))) is True
    )
    assert view({"aud": "a"}).expired(exp) is None
    assert view({"exp": "x"}).expired(exp) is None
    with pytest.raises(ValueError):
        result.expired(datetime(2030, 1, 1))


def test_to_json_shape():
    result = view({"roles": ["b", "a"], "aud": "x", "exp": 5, "tid": GUID, "other": 1, "scp": 3})
    data = result.to_json()
    assert list(data) == sorted(data)
    assert list(data["claims"]) == sorted(data["claims"])
    assert data["claims"]["roles"] == ["b", "a"]
    assert data["unexpected"] == ["scp"]
    assert data["other_claims"] == 1
    assert data["readable"] is True and data["reason"] is None
    assert json.loads(json.dumps(data)) == data
    bad = inspect("nope", pseudonymize).to_json()
    assert bad["readable"] is False and bad["reason"] == "not_jwt"


def test_view_is_frozen():
    result = view({"aud": "a"})
    with pytest.raises(AttributeError):
        result.readable = False  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.claims["aud"] = "b"  # type: ignore[index]


# --- run time --------------------------------------------------------------------------------


def test_adversarial_tokens_are_fast():
    size = 16 * 1024
    shapes = [
        "A" * size,
        "A" * (size // 2) + "." + "A" * (size // 2 - 1),
        "." * size,
        ("A." * (size // 2)),
        "A" * 10 + "." + "A" * (size - 12) + ".",
        "A." + "A" * (size - 4) + ".A",
        ".".join(["A" * (size // 3)] * 3)[:size],
    ]
    start = time.perf_counter()
    for token in shapes:
        inspect(token, pseudonymize)
    assert time.perf_counter() - start < 1.0


def test_a_mask_runs_on_the_whole_value_before_it_is_cut():
    value = "needle-" + "x" * 40
    text = "a" * 240 + value  # the limit lies inside the value

    def mask(text: str) -> str:
        return text.replace(value, "***MASKED***")

    result = inspect(make({"scp": text, "roles": [text], "aud": text}), pseudonymize, mask)

    assert result.claims["scp"] == "a" * 240 + "***MASKED***"
    assert result.claims["roles"] == ("a" * 240 + "***MASKED***",)
    assert result.claims["aud"] == "a" * 240 + "***MASKED***"
    assert "needle" not in json.dumps(result.to_json())
    assert result.warnings == ("truncated",)


def test_a_mask_that_makes_a_value_longer_is_cut_after_it():
    result = inspect(make({"azp": "a" * 250 + "@x.y"}), pseudonymize, lambda t: t + "M" * 20)

    assert result.claims["azp"] == "a" * 250 + "@x.yMM"
    assert result.warnings == ("truncated",)


def test_a_mask_does_not_see_the_entries_a_list_drops():
    seen: list[str] = []

    def mask(text: str) -> str:
        seen.append(text)
        return text

    inspect(make({"roles": [f"r{i}" for i in range(100)]}), pseudonymize, mask)

    assert seen == [f"r{i}" for i in range(64)]


def test_a_mask_that_raises_gives_inspection_failed_and_nothing_of_the_value():
    def mask(text: str) -> str:
        raise RuntimeError(text)

    result = inspect(make({"aud": "api://resource"}), pseudonymize, mask)
    assert result.readable is False
    assert result.reason == "inspection_failed"
    assert result.masked is True
    assert "api://resource" not in json.dumps(result.to_json())
