"""Personal data and the engagement's known values, replaced by pseudonyms when written.

Three shapes that are unambiguous — e-mail addresses, IBANs with a valid check and the length of
their country, ``tel:`` URIs — and the ``known_values`` of the engagement file. Each is replaced in
a header, a body, an error text, an event of a stream and a key; what looks like them and is not
stays byte for byte. A pseudonym is stable inside an engagement (the salt is the value of the
variable the file names) and, without one, inside a run. The salt is never written; a run without
it, or with one shorter than 32 characters, is refused at the gate, and ``engagement purge`` of a
version-2 engagement wants the operator's word that the salt is gone.

Every value is made up when the test runs: addresses and IBANs are put together here, the IBAN's
check digits computed, and none is written out.
"""

from __future__ import annotations

import contextlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, unquote

import pytest

from mcp_kymograph import cli, engagement, eras, events, evidence, masking
from mcp_kymograph.credentials import CredentialError, Token
from mcp_kymograph.events import Direction
from mcp_kymograph.masking import PLACEHOLDER, Masker
from mcp_kymograph.recorder import Recorder
from test_hostile_input_runtime import BOUND, LARGE, SMALL, _best, _Text

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = str(FIXTURES / "discovery_server.py")
SCENARIO = FIXTURES / "scenarios" / "all-signals.yaml"

SALT_ENV = "KYMOGRAPH_TEST_SALT"
HANDLE_SALT = b"a fixed salt for the handles" + b"\x00" * 4
#: A pseudonym of any kind, the way it is written.
PSEUDONYM = re.compile(r"\*\*\*(EMAIL|IBAN|TEL|KNOWN)-[0-9a-f]{12}\*\*\*")


# -- made-up values ----------------------------------------------------------------------------


def iban(country: str = "DE", length: int | None = None, check: str | None = None) -> str:
    """A valid IBAN of ``country`` with a random account part, its check digits computed
    (ISO 7064 mod 97-10); ``check`` puts other check digits in, which makes it invalid."""
    size = (length or masking.IBAN_LENGTHS[country]) - 4
    account = "".join(secrets.choice("0123456789") for _ in range(size))
    moved = account + "".join(str(int(c, 36)) for c in country) + "00"
    digits = f"{98 - int(moved) % 97:02d}"
    if check is not None:
        assert check != digits
        digits = check
    return f"{country}{digits}{account}"


#: Fixed IBANs from the public documentation of the register and of banks, valid, with nothing
#: random about them: the counter-examples are evaluated once, on import. The GB one has letters
#: in its account part, which is what case rules are tested with.
DE_IBAN = "DE89370400440532013000"
BE_IBAN = "BE68539007547034"
GB_IBAN = "GB82WEST12345698765432"


def groups(value: str) -> str:
    return " ".join(value[i : i + 4] for i in range(0, len(value), 4))


def address(name: str = "rene.beispiel") -> str:
    return f"{name}@{'kunden' + secrets.token_hex(2)}.example"


def phone() -> str:
    return "tel:+49-30-" + "".join(secrets.choice("0123456789") for _ in range(7))


def known() -> str:
    return "Kunde-" + secrets.token_hex(5)


def masked(text: str, **more) -> str:
    return Masker(handle_salt=HANDLE_SALT, **more).mask_text(text)[0]


def pseudonyms(text: str) -> list[str]:
    return [found.group() for found in PSEUDONYM.finditer(text)]


# -- every form, with examples and counter-examples ---------------------------------------------

#: A text with one value of the form in it, a frame around it, and the kind it is.
FORMS = {
    "email": lambda: (address(), "write to {} soon", "email"),
    "email, upper case": lambda: (address("RENE.Beispiel").upper(), "From: {}", "email"),
    "email, in angle brackets": lambda: (address("a+tag"), "Name <{}>", "email"),
    "email, at the end of a sentence": lambda: (address(), "Ask {}.", "email"),
    "email, mailto": lambda: (address(), "mailto:{}?subject=x", "email"),
    "email, umlaut in the local part": lambda: (address("jürgen.mueller"), "{} wrote", "email"),
    "email, accent in the local part": lambda: (address("rené"), "Mail: {}", "email"),
    "email, apostrophe in the local part": lambda: (address("o'brien"), "To {} now", "email"),
    "email, combining mark": lambda: (address("re\u0301ne"), "{}", "email"),
    "email, other script": lambda: (address("дмитрий.иванов"), "{}", "email"),
    "email, allowed punctuation": lambda: (address("a.b_c+d-e'f"), "<{}>", "email"),
    "email, typographic apostrophe": lambda: (address("O’Brien"), "To {} now", "email"),
    "email, in typographic quotes": lambda: (address("alice"), "’{}’", "email"),
    "email, dot at the end of the local part": lambda: (address("alice."), "{}", "email"),
    "email, two dots in the local part": lambda: (address("alice..b"), "{}", "email"),
    "email, apostrophe at the end of the local part": lambda: (address("bob'"), "{}", "email"),
    "email, behind a key and =": lambda: (address("alice"), "contact={}", "email"),
    "email, in a query string": lambda: (address("alice"), "?email={}&x=1", "email"),
    "email, in single quotes": lambda: (address("alice"), "'{}'", "email"),
    "email, in double quotes": lambda: (address("alice"), '"{}"', "email"),
    "email, in back ticks": lambda: (address("alice"), "`{}`", "email"),
    "email, behind a dot": lambda: (address("alice"), "Mail me:.{}", "email"),
    "email, international domain": lambda: (
        f"a@münchen{secrets.token_hex(2)}.example",
        "{}",
        "email",
    ),
    "email, international top-level domain": lambda: ("иван@почта.рф", "{}", "email"),
    "email, punycode": lambda: (f"a@xn--mnchen-3ya{secrets.token_hex(2)}.example", "{}", "email"),
    "email, punycode top-level domain": lambda: ("a@x.xn--p1ai", "{}", "email"),
    "iban": lambda: (iban(), "pay to {} today", "iban"),
    "iban, in groups of four": lambda: (groups(iban()), "pay to {}, thanks", "iban"),
    "iban, of another country": lambda: (iban("GB"), "{}", "iban"),
    "iban, with letters in the account": lambda: (GB_IBAN, "{}", "iban"),
    "iban, with letters in the account, in groups": lambda: (groups(GB_IBAN), "{}", "iban"),
    "iban, the longest": lambda: (iban("RU"), "{}", "iban"),
    "iban, the shortest": lambda: (iban("NO"), "{}", "iban"),
    "tel": lambda: (phone(), "call {} now", "tel"),
    "tel, upper case scheme": lambda: (phone().replace("tel:", "TEL:"), "<{}>", "tel"),
    "tel, with a parameter": lambda: (phone() + ";ext=12", "see {}", "tel"),
    "tel, at the end of a sentence": lambda: (phone(), "Call {}.", "tel"),
    "tel, local number": lambda: ("tel:0301234567", "{}", "tel"),
}


@pytest.mark.parametrize("name", FORMS)
def test_each_form_is_replaced_by_a_pseudonym_of_its_kind(name):
    value, frame, kind = FORMS[name]()
    text = frame.format(value)

    result = masked(text)

    assert result.count("***") == 2, result
    (found,) = pseudonyms(result)
    assert found.startswith(f"***{kind.upper()}-")
    assert result == frame.format(found)
    assert value not in result
    if kind == "email":
        local = value.rpartition("@")[0]
        rest = PSEUDONYM.sub("", result)
        assert all(word not in rest for word in re.findall(r"\w\w\w+", local)), rest


def test_a_character_that_ends_the_local_part_stays_with_what_stands_before_it():
    # The limit, stated in the docs: only letters, digits and marks lengthen the local part.
    result = masked("a&b@" + address().partition("@")[2])

    assert result.startswith("a&***EMAIL-") and result.count("***") == 2


def test_a_pseudonym_is_twelve_hex_characters_flanked_like_a_handle():
    result = masked(address())

    assert PSEUDONYM.fullmatch(result)
    assert result.startswith("***EMAIL-") and result.endswith("***")
    assert masking.HANDLE_PREFIX.startswith("***") and masking.HANDLE_SUFFIX == "***"


def test_the_same_value_written_differently_is_one_pseudonym():
    plain = iban()
    mail = address("Rene.Beispiel")

    assert masked(plain) == masked(groups(plain))
    assert masked(mail) == masked(mail.lower()) == masked(mail.upper())
    assert masked(plain) != masked(address())


def test_the_pseudonym_is_the_hmac_of_the_kind_a_nul_and_the_canonical_value():
    import hashlib
    import hmac

    salt = b"s" * 32
    mail = address("Rene.Beispiel")
    expected = hmac.new(salt, b"email\0" + mail.lower().encode(), hashlib.sha256).hexdigest()
    masker = Masker(personal_salt=salt)

    assert masker.mask_text(mail)[0] == f"***EMAIL-{expected[:12]}***"
    assert masker.personal_pseudonym("tel", "tel:+1") != masker.personal_pseudonym(
        "known", "tel:+1"
    )


COUNTER_EXAMPLES = {
    "an address without a dot in its host": "user@localhost and a@b",
    "an address whose last label is no word": "a@b.c and x@y.12 and p@q.c0m",
    "an @ with nothing in front": "@handle and @ alone and ask @ the desk",
    "an @ in a path or a query": "https://h.example/@52.5,13.4/data and https://h/p@x",
    "an address whose local part is too long": "a" * 65
    + "@x.example and "
    + "é" * 65
    + "@y.example",
    "an address whose domain has a digit as its top level": "a@münchen.12 and é@x.c0m",
    "a quoted local part": '"bob smith"@x.example',
    "a quoted local part with a backslash": '"bob' + chr(92) + ' smith"@x.example',
    "a quote and an @ in front of a handle": '"@max.mustermann"',
    "a JSON key in front of a handle": '{"user":"@max.mustermann"}',
    "a quoted value in front of a handle": 'name="Max" handle="@max.mustermann"',
    "an international address without a dot in its host": "jürgen@localhost and rené@münchen",
    "a hex id in lower case that reads like an IBAN": "ad6600000000000000000000",
    "an IBAN in lower case": DE_IBAN.lower() + " and " + groups(BE_IBAN).lower(),
    "an IBAN with letters in lower case": GB_IBAN.lower(),
    "an IBAN with letters in groups of four, in lower case": groups(GB_IBAN).lower(),
    "an IBAN with letters in mixed case": GB_IBAN[:4] + GB_IBAN[4:].lower(),
    "an IBAN with a lower case country": GB_IBAN[:2].lower() + GB_IBAN[2:],
    "a span id in hex that holds a valid IBAN of Belgium": BE_IBAN.lower(),
    "an IBAN with a wrong check": "DE00" + DE_IBAN[4:] + " and " + groups("DE01" + DE_IBAN[4:]),
    "an IBAN one character short": DE_IBAN[:-1] + " and " + DE_IBAN[:-2],
    "an IBAN one character long": DE_IBAN + "1" + " and " + DE_IBAN + "AB",
    "an IBAN of a country there is none of": "XX" + DE_IBAN[2:],
    "an IBAN inside a longer word": "A" + DE_IBAN + " and " + DE_IBAN + "Z",
    "an IBAN in uneven groups": "DE89 37 0400 4405 3201 3000 00",
    "a long number without a valid IBAN check": "1234567890123456789012",
    "a phone number without tel:": "+49 30 1234567 and 030/1234567 and (555) 010-0100",
    "a phone number in a longer scheme": "hotel:+4930123456 and ctel:12345",
    "tel: without a number": "tel: and tel:abc and tel: +4930123 and tel:+",
}


@pytest.mark.parametrize("name", COUNTER_EXAMPLES)
def test_what_looks_like_a_form_and_is_not_one_stays(name):
    text = COUNTER_EXAMPLES[name]

    assert masked(text) == text


def test_the_fixed_ibans_are_valid_and_the_counter_examples_are_made_of_them():
    # The counter-examples hold no random value: the same text on every run, and a guard that the
    # constants are what the cases rely on (a valid IBAN, replaced in capitals).
    for value in (DE_IBAN, BE_IBAN, GB_IBAN, groups(GB_IBAN)):
        assert PSEUDONYM.fullmatch(masked(value))
    assert masked(GB_IBAN) == masked(groups(GB_IBAN))


@pytest.mark.parametrize(
    "text", ['"@max.mustermann"', '"bob smith"@x.example', '{"user":"@max.mustermann"}']
)
def test_a_local_part_in_quotes_is_no_address_and_is_not_counted(text):
    masker = Masker(handle_salt=HANDLE_SALT)

    assert masker.mask_text(text)[0] == text
    assert masker.replacements["email"] == 0


def test_a_card_number_is_no_form_and_stays():
    # Luhn is passed by every tenth sequence of digits: a card number is a known value or nothing.
    card = "4" + "1" * 15
    assert (
        sum(
            int(d) * (1 + i % 2) % 10 + int(d) * (1 + i % 2) // 10 for i, d in enumerate(card[::-1])
        )
        % 10
        == 0
    )
    assert masked(f"card {card}") == f"card {card}"
    assert masked(f"card {card}", known_values=[card]).count("***KNOWN-") == 1


def test_the_negative_values_of_a_server_stay_byte_for_byte():
    """What a server fills its answers with: resource ids, timestamps, order and version
    numbers. None of it is replaced, or the recording would lose what it is for."""
    values = [
        "550e8400-e29b-41d4-a716-446655440000",  # a UUID
        "4711",
        str(2**40),
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # hex
        "deadbeef" * 3,  # 24 hex characters in lower case: an IBAN is read in capitals only
        "ad6600000000000000000000",  # a hex id: AD is a country, 24 is its length
        "SGVsbG8sIHdvcmxkISBhIGJhc2U2NA==",  # base64
        "dGhpcyBpcyBhIHRva2VuLWxpa2Ugc3RyaW5n",
        "2026-11-04T09:15:30Z",
        "2026-11-04T09:15:30.123+01:00",
        "1762247730",  # epoch seconds
        "1762247730123",  # epoch milliseconds
        "ORD-2026-000412",
        "INV/2026/11/0042",
        "1234567890123456789012",  # 22 digits, no IBAN
        "DE12345678901234567890",  # 22 characters in an IBAN's shape, check does not hold
        "GB00ABCD12345678901234",
        "030 1234567",
        "+49 30 1234567",
        "0049301234567",
        "2025-11-25",  # a protocol version
        "2025-06-18",
        "v1.2.3-rc.1",
        "https://h.example/v1/items/42?page=2&sort=name",
        "git@github.com:org/repo.git",
    ]
    for value in values:
        assert masked(value) == value, value
        assert masked(f"id={value};") == f"id={value};", value
    document = {"id": values[0], "n": 7, "at": values[7], "list": values[1:4], "t": 1762247730}
    masker = Masker(handle_salt=HANDLE_SALT)
    assert masker.mask_json(document) == (document, [])
    assert masker.replacements == {"email": 0, "iban": 0, "tel": 0, "known": 0}


# -- where ---------------------------------------------------------------------------------------


def recorder() -> tuple[Recorder, io.StringIO, Masker]:
    stream = io.StringIO()
    masker = Masker(handle_salt=HANDLE_SALT)
    return Recorder(stream, run_id="r", masker=masker), stream, masker


def written(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def start_and_finish(rec: Recorder) -> None:
    rec.run_started(0, 0, argv=["server"], limits={})
    rec.run_finished(
        99, 0, reason="eof", duration_ns=1, server_output_bytes=0, client_input_bytes=0,
        server_exited_first=False,
    )  # fmt: skip


def test_every_form_and_a_known_value_is_replaced_in_header_body_error_text_stream_and_key():
    mail, bank, call, secret = address(), iban(), phone(), known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])
    stream = io.StringIO()
    rec = Recorder(stream, run_id="r", masker=masker)
    values = [mail, bank, call, secret]
    rec.run_started(0, 0, argv=["server"], limits={})
    rec.http_request(
        1, 0, exchange=1, connection=1, method="POST", target="https://h/p?contact=" + mail,
        headers=[("X-Contact", f"{mail} {call}"), ("X-Account", bank), ("X-Customer", secret)],
    )  # fmt: skip
    rec.http_response(
        2, 0, exchange=1, status=500, reason=f"no account {bank}",
        headers=[("X-Reply-To", mail)], content_type="text/plain", framing="json",
    )  # fmt: skip
    body = {"result": {"owner": mail, "iban": groups(bank), "call": call, "by": secret}}
    rec.message(
        3, 0, direction=Direction.SERVER_TO_CLIENT, raw=json.dumps(body).encode(),
    )  # fmt: skip
    error = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": f"no user {mail}"}}
    rec.message(4, 0, direction=Direction.SERVER_TO_CLIENT, raw=json.dumps(error).encode())
    rec.message(5, 0, direction=Direction.SERVER_TO_CLIENT, raw=f"fatal: {secret}".encode())
    rec.message(
        6, 0, direction=Direction.SERVER_TO_CLIENT, transport="streamable-http", exchange=1,
        stream=1, event_id="e1",
        raw=json.dumps({"params": {"message": f"{mail}, {call}"}}).encode(),
    )  # fmt: skip
    rec.message(
        7, 0, direction=Direction.SERVER_TO_CLIENT,
        raw=json.dumps({"result": {mail: 1, "list": [bank, secret]}}).encode(),
    )  # fmt: skip
    rec.run_finished(
        8, 0, reason="eof", duration_ns=1, server_output_bytes=0, client_input_bytes=0,
        server_exited_first=False,
    )  # fmt: skip

    text = stream.getvalue()
    for value in values:
        for form in (value, value.lower(), quote(value, safe=""), groups(value)):
            assert form not in text, form
    events = written(stream)
    request = next(e for e in events if e["type"] == "http_request")
    assert PSEUDONYM.search(request["headers"]["x-contact"]) and PSEUDONYM.search(
        request["headers"]["x-account"]
    )
    assert pseudonyms(json.dumps(request["target"])) == [masker.personal_pseudonym("email", mail)]
    assert "***KNOWN-" in request["headers"]["x-customer"]
    response = next(e for e in events if e["type"] == "http_response")
    assert PSEUDONYM.search(response["reason"]) and PSEUDONYM.search(
        response["headers"]["x-reply-to"]
    )
    messages = [e for e in events if e["type"] == "message"]
    assert PSEUDONYM.search(json.dumps(messages[0]["payload"]))
    assert PSEUDONYM.search(json.dumps(messages[1]["payload"]))
    assert PSEUDONYM.search(json.dumps(messages[2]["payload"])), "a text that is no JSON"
    assert PSEUDONYM.search(json.dumps(messages[3]["payload"])), "an event of a stream"
    keyed = messages[4]["payload"]["data"]["result"]
    assert [key for key in keyed if PSEUDONYM.fullmatch(key)], "the key"
    assert PLACEHOLDER not in text, "a pseudonym is not a credential's blanking"
    assert events[-1]["replacements"] == {"email": 7, "iban": 4, "tel": 3, "known": 4}


def test_the_replaced_values_are_not_counted_as_redactions_the_server_let_out():
    rec, stream, _ = recorder()
    body = {"owner": address(), "iban": iban(), "call": phone()}

    rec.message(1, 0, direction=Direction.SERVER_TO_CLIENT, raw=json.dumps(body).encode())

    assert rec.server_redactions == 0
    (event,) = written(stream)
    assert event["payload"]["redaction_count"] == 0 and event["payload"]["redactions"] == []


def test_a_value_in_a_header_that_only_a_decoding_shows_blanks_the_header():
    mail = address()
    secret = known() + " Co"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])

    headers, _ = masker.mask_headers(
        {
            "Referer": f"https://h.example/?e={quote(mail, safe='')}",
            "X-Twice": quote(quote(secret, safe=""), safe=""),
            "X-Once": quote(secret, safe=""),
        }
    )

    assert headers["referer"] == PLACEHOLDER
    assert headers["x-twice"] == PLACEHOLDER, "fail closed: a reader that decodes twice sees it"
    assert PSEUDONYM.fullmatch(headers["x-once"]), "the encoded form is the known value's own"


def test_a_value_in_a_query_is_replaced_in_its_decoded_form():
    mail = address()
    masker = Masker(handle_salt=HANDLE_SALT)

    fields, _ = masker.mask_query("e=" + quote(mail, safe="") + "&n=1")

    assert PSEUDONYM.fullmatch(fields["e"]) and fields["n"] == "1"


# -- the known values ----------------------------------------------------------------------------


def test_a_known_value_is_replaced_everywhere_plain_encoded_and_inside_a_longer_string():
    secret = known() + " & Co"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])
    found = masker.personal_pseudonym("known", secret)

    assert masker.mask_text(secret)[0] == found
    assert masker.mask_text(quote(secret, safe=""))[0] == found
    assert masker.mask_text(f"prefix-{secret}-suffix and {secret}")[0] == (
        f"prefix-{found}-suffix and {found}"
    )
    assert masker.mask_text(f"{secret}{secret}")[0] == found + found
    document, paths = masker.mask_json({"a": [{"b": f"x {secret}"}], secret: 1})
    assert document == {"a": [{"b": f"x {found}"}], found: 1}
    assert masker.replacements["known"] == 8


def test_a_known_value_is_not_blanked_and_the_longer_of_two_wins():
    short = known()
    long = short + "-Berlin"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[short, long])

    result = masker.mask_text(f"{long} and {short}")[0]

    assert result == masker.personal_pseudonym("known", long) + " and " + masker.personal_pseudonym(
        "known", short
    )
    assert PLACEHOLDER not in result


def test_a_literal_is_blanked_before_a_known_value_is_looked_at():
    token = "tok-" + secrets.token_hex(8)
    masker = Masker(handle_salt=HANDLE_SALT, literals=[token], known_values=[token + "x"])

    assert masker.mask_text(f"{token}x")[0] == PLACEHOLDER + "x"
    assert masker.replacements["known"] == 0


# -- the order and the user information of URLs ---------------------------------------------------


def test_a_known_value_inside_an_address_is_replaced_as_a_known_value_and_counted_once():
    name = known()
    mail = f"{name}@kunden.example"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[name])

    result = masker.mask_text(mail)[0]

    # The ``*`` of the pseudonym ends a local part, so the address rule finds none: the name is
    # gone all the same, replaced as the known value, and the host stays.
    assert re.fullmatch(r"\*\*\*KNOWN-[0-9a-f]{12}\*\*\*@kunden\.example", result), result
    assert masker.replacements == {"email": 0, "iban": 0, "tel": 0, "known": 1}


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("ssh://git@host.example/org/repo", "ssh://{}@host.example/org/repo"),
        ("https://{u}:pw@host.example/x", "https://{}@host.example/x"),
        ("https://{u}@corp.example/x", "https://{}@corp.example/x"),
        ("https%3A//{u}:pw@host.example/x", None),
        ("https://x:{u}@host.example/x", "https://{}@host.example/x"),
    ],
)
def test_the_user_information_of_a_url_is_a_credential_and_not_an_address(text, kept):
    """``ssh://git@host/…`` is the existing rule's: its user goes, as every user name in a URL
    goes (fail closed), and the address rule does not see it first."""
    mail_like = "reader.one"
    masker = Masker(handle_salt=HANDLE_SALT)

    result, hits = masker.mask_text(text.replace("{u}", mail_like))

    assert hits >= 1 and PLACEHOLDER in result
    assert not PSEUDONYM.search(result)
    assert masker.replacements["email"] == 0
    if kept is not None:
        assert result == kept.format(PLACEHOLDER)
    assert mail_like not in result and "pw" not in result.replace("password", "")


def test_git_at_host_colon_path_is_not_an_address_and_a_remote_with_a_scheme_is_a_credential():
    """The decision for ``user@host`` in SSH URLs.

    ``git@github.com:org/repo`` (SCP-style, no scheme) names the account on a host and a path,
    which is no person: it stays. ``ssh://git@github.com/org/repo`` has user information: the
    rule for those replaces the user name by the placeholder, as it did before.
    A real address in the same place is still an address."""
    masker = Masker(handle_salt=HANDLE_SALT)
    mail = address("a")

    assert masker.mask_text("git clone git@github.com:org/repo.git")[0] == (
        "git clone git@github.com:org/repo.git"
    )
    assert masker.mask_text("u@host.example:~/x and u@host.example:/srv")[0] == (
        "u@host.example:~/x and u@host.example:/srv"
    )
    assert masker.mask_text("ssh://git@github.com/org/repo") == (
        f"ssh://{PLACEHOLDER}@github.com/org/repo",
        1,
    )
    assert masker.mask_text(f"{mail}:{mail}")[0].count("***EMAIL-") == 2, "not a path behind it"
    assert masker.mask_text(f"{mail}: thanks")[0].startswith("***EMAIL-")
    assert masker.mask_text(f"{mail}:8080")[0].startswith("***EMAIL-")


# -- stability -----------------------------------------------------------------------------------


def test_a_pseudonym_is_the_same_under_one_salt_and_another_under_another():
    mail = address()
    one = Masker(personal_salt=b"1" * 32)

    assert one.mask_text(mail) == Masker(personal_salt=b"1" * 32).mask_text(mail)
    assert one.mask_text(mail) != Masker(personal_salt=b"2" * 32).mask_text(mail)
    assert one.pseudonyms == "per_engagement"


def test_without_an_engagement_the_salt_is_the_run_s_and_two_runs_differ():
    mail = address()
    first, second = Masker(), Masker()

    assert first.mask_text(mail) == first.mask_text(mail)
    assert first.mask_text(mail) != second.mask_text(mail)
    assert first.pseudonyms == "per_run"


def test_the_handles_keep_their_own_salt_whatever_the_personal_salt_is():
    handle = Masker(handle_salt=HANDLE_SALT, personal_salt=b"1" * 32).pseudonym("call-a")

    assert handle == Masker(handle_salt=HANDLE_SALT, personal_salt=b"2" * 32).pseudonym("call-a")
    assert handle == Masker(handle_salt=HANDLE_SALT).pseudonym("call-a")


# -- the salt: gate, artifacts, purge ------------------------------------------------------------


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def second_file(directory: Path, *, name: str = "acme-2026-10", **changes) -> Path:
    """A file of the second version covering the local child and the all-signals scenario, with
    the salt in the variable :data:`SALT_ENV` and the known values it is given."""
    directory.mkdir(parents=True, exist_ok=True)
    listed = directory / "all-signals.yaml"
    shutil.copyfile(SCENARIO, listed)
    now = datetime.now(timezone.utc)
    data = {
        "version": 2,
        "id": name,
        "end_customer": {"name": "End Customer GmbH"},
        "window": {"from": utc(now - timedelta(days=1)), "until": utc(now + timedelta(days=1))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": [
            {"path": "all-signals.yaml", "sha256": sha256(listed.read_bytes()).hexdigest()}
        ],
        "actions": {"list": True, "call": False},
        "abort_criteria": ["the customer asks to stop"],
        "emergency": {"name": "Ops", "reach": "on call"},
        "salt_env": SALT_ENV,
        "known_values": [],
        "retention": {"delete_after": (now + timedelta(days=30)).date().isoformat()},
    }
    data.update(changes)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def first_file(directory: Path) -> Path:
    from test_cli_engagement import write_engagement

    return write_engagement(directory)


def drive(held: Path, out_dir: Path, *server: str, quiet: bool = True) -> int:
    scenario = held.parent / "all-signals.yaml"
    return cli.main(
        [
            "drive", *(["-q"] if quiet else []), "--engagement", str(held),
            "--scenario", str(scenario), "--out-dir", str(out_dir), "--",
            sys.executable, DISCOVERY, *server,
        ]
    )  # fmt: skip


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def recordings_in(out_dir: Path) -> list[Path]:
    return sorted(out_dir.glob("*/events.jsonl"))


def refusals_in(out_dir: Path) -> list[engagement.RefusalRecord]:
    return engagement.read_refusals(out_dir / engagement.REFUSALS_FILE)


@pytest.fixture
def salt(monkeypatch) -> str:
    value = "salt-" + secrets.token_hex(16)
    monkeypatch.setenv(SALT_ENV, value)
    return value


@pytest.fixture
def nothing_starts(monkeypatch):
    import asyncio

    async def must_not_run(*args, **kwargs):
        raise AssertionError("a process was started although the run was refused")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)


def test_a_run_without_the_salt_variable_is_refused_and_written_down(
    tmp_path, monkeypatch, capsys, nothing_starts
):
    held = second_file(tmp_path / "engagement")
    monkeypatch.delenv(SALT_ENV, raising=False)

    assert drive(held, tmp_path / "runs") == 2

    (record,) = refusals_in(tmp_path / "runs")
    assert record.reason == "salt_missing"
    assert SALT_ENV in record.message and "not set or is empty" in record.message
    assert SALT_ENV in capsys.readouterr().err
    assert recordings_in(tmp_path / "runs") == []


def test_an_empty_salt_variable_is_missing(tmp_path, monkeypatch, nothing_starts):
    held = second_file(tmp_path / "engagement")
    monkeypatch.setenv(SALT_ENV, "")

    assert drive(held, tmp_path / "runs") == 2

    assert [r.reason for r in refusals_in(tmp_path / "runs")] == ["salt_missing"]


def test_a_salt_shorter_than_32_characters_is_refused_and_its_value_is_never_said(
    tmp_path, monkeypatch, capsys, nothing_starts
):
    held = second_file(tmp_path / "engagement")
    short = "short-" + secrets.token_hex(8)
    assert len(short) < 32
    monkeypatch.setenv(SALT_ENV, short)

    assert drive(held, tmp_path / "runs") == 2

    (record,) = refusals_in(tmp_path / "runs")
    assert record.reason == "salt_too_short"
    assert SALT_ENV in record.message and "fewer than 32" in record.message
    said = capsys.readouterr().err
    refusals_file = (tmp_path / "runs" / engagement.REFUSALS_FILE).read_text()
    assert short not in said and short not in refusals_file


def test_a_salt_of_exactly_32_characters_is_enough(tmp_path, monkeypatch):
    held = second_file(tmp_path / "engagement")
    monkeypatch.setenv(SALT_ENV, "k" * 32)

    assert drive(held, tmp_path / "runs") == 0


def test_the_gate_looks_at_the_salt_last_so_another_refusal_keeps_its_reason(
    tmp_path, monkeypatch, nothing_starts
):
    held = second_file(tmp_path / "engagement", actions={"list": False, "call": False})
    monkeypatch.delenv(SALT_ENV, raising=False)

    assert drive(held, tmp_path / "runs") == 2

    assert [r.reason for r in refusals_in(tmp_path / "runs")] == ["lists_not_permitted"]


def test_version_one_is_not_refused_for_a_salt_it_cannot_name(tmp_path, monkeypatch):
    """A version-1 run is not refused without a salt (``engagement.SALT_REQUIRED_VERSIONS``):
    it has the run's own salt, and says so."""
    held = first_file(tmp_path / "engagement")
    monkeypatch.delenv(SALT_ENV, raising=False)

    assert engagement.SALT_REQUIRED_VERSIONS == (engagement.FORMAT_VERSION_2,)
    assert drive(held, tmp_path / "runs") == 0

    (recording,) = recordings_in(tmp_path / "runs")
    assert events_of(recording)[0]["pseudonyms"] == "per_run"


def test_version_one_is_refused_without_a_salt_once_that_one_place_says_so(
    tmp_path, monkeypatch, nothing_starts
):
    held = first_file(tmp_path / "engagement")
    monkeypatch.setattr(engagement, "SALT_REQUIRED_VERSIONS", (1, 2))

    assert drive(held, tmp_path / "runs") == 2

    (record,) = refusals_in(tmp_path / "runs")
    assert record.reason == "salt_missing" and "salt_env" in record.message


def test_a_run_says_how_long_its_pseudonyms_last_and_how_many_it_made(tmp_path, salt):
    held = second_file(tmp_path / "engagement")
    mail, bank, call, secret = address(), iban(), phone(), known()
    held = second_file(tmp_path / "engagement", known_values=[secret])

    assert (
        drive(
            held,
            tmp_path / "runs",
            "--offers",
            "tools",
            "--tool-description",
            f"{mail} {bank} {call} {secret}",
        )
        == 0
    )

    (recording,) = recordings_in(tmp_path / "runs")
    events = events_of(recording)
    assert events[0]["pseudonyms"] == "per_engagement"
    finished = events[-1]
    assert finished["type"] == "run_finished"
    assert set(finished["replacements"]) == {"email", "iban", "tel", "known"}
    assert all(count >= 1 for count in finished["replacements"].values())
    raw = recording.read_text()
    for value in (mail, bank, call, secret):
        assert value not in raw
    listing = next(
        e for e in events if e["type"] == "message" and "description" in json.dumps(e["payload"])
    )
    assert len(pseudonyms(json.dumps(listing["payload"]))) == 4


def test_a_run_without_an_engagement_says_its_pseudonyms_last_a_run(tmp_path):
    out_dir = tmp_path / "runs"
    mail = address()

    assert cli.main(["drive", "-q", "--out-dir", str(out_dir), "--", sys.executable, DISCOVERY,
                     "--offers", "tools", "--tool-description", mail]) == 0  # fmt: skip

    (recording,) = recordings_in(out_dir)
    assert events_of(recording)[0]["pseudonyms"] == "per_run"
    assert mail not in recording.read_text()


def test_the_pseudonym_is_the_same_in_two_runs_of_an_engagement_and_not_in_another(
    tmp_path, monkeypatch, salt
):
    mail = address()
    held = second_file(tmp_path / "one")
    other = second_file(tmp_path / "two", name="other-2026-10")

    def seen(file: Path, runs: str) -> str:
        assert (
            drive(
                file, tmp_path / runs, "--offers", "tools", "--tool-description", f"contact {mail}"
            )
            == 0
        )
        (recording,) = recordings_in(tmp_path / runs)
        (found,) = set(pseudonyms(recording.read_text()))
        return found

    first, again = seen(held, "a"), seen(held, "b")
    monkeypatch.setenv(SALT_ENV, "other-" + secrets.token_hex(16))
    elsewhere = seen(other, "c")

    assert first == again
    assert first != elsewhere


def test_without_an_engagement_the_same_value_is_another_pseudonym_in_the_next_run(tmp_path):
    mail = address()
    found = []
    for runs in ("a", "b"):
        out_dir = tmp_path / runs
        server = [sys.executable, DISCOVERY, "--offers", "tools", "--tool-description"]
        assert (
            cli.main(["drive", "-q", "--out-dir", str(out_dir), "--", *server, f"contact {mail}"])
            == 0
        )
        (recording,) = recordings_in(out_dir)
        found.append(set(pseudonyms(recording.read_text())))

    assert len(found[0]) == len(found[1]) == 1 and found[0] != found[1]


def forms_of(value: str) -> list[str]:
    encoded = quote(value, safe="")
    return list({value, encoded, encoded.lower()})


class Artifacts:
    """Runs against a server that sends the salt back, a refusal of each kind, the store, the
    report and the bundle made from them, and what the commands said."""

    def __init__(
        self, root: Path, salt: str, monkeypatch, *, extra: str = "", known_values=()
    ) -> None:
        self.root = root
        self.captured: list[tuple[str, str]] = []
        self.salt = salt
        self.short = "short-" + secrets.token_hex(6)
        held = second_file(root / "engagement", known_values=list(known_values))
        runs = root / "runs"
        # A corpus entry (the store takes no other run) whose server sends the salt back: it
        # reads the variable itself, so that no file of the engagement holds the salt.
        manifest = root / "corpus" / "manifest.json"
        manifest.parent.mkdir()
        launcher = manifest.parent / "echo_salt.py"
        launcher.write_text(
            "import os, runpy, sys\n"
            f"text = 'echoes ' + os.environ.get({SALT_ENV!r}, '') + ' and {address()}{extra}'\n"
            f"sys.argv = [{DISCOVERY!r}, '--offers', 'tools', '--tool-description', text]\n"
            f"runpy.run_path({DISCOVERY!r}, run_name='__main__')\n"
        )
        manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": [
                        {
                            "name": "echo-server",
                            "provenance": "reference",
                            "source": {"paths": ["echo_salt.py"]},
                            "launch": {
                                "transport": "stdio",
                                "command": ["{python}", "{dir}/echo_salt.py"],
                            },
                            "scenarios": [os.path.relpath(SCENARIO, manifest.parent)],
                        }
                    ],
                }
            )
        )
        corpus = ["--manifest", manifest, "--entry", "echo-server", "--isolation", "host"]
        drive = ["drive", "-q", "--engagement", held, "--out-dir", runs, *corpus]
        for _ in range(2):
            assert self.call(*drive) == 0
        monkeypatch.delenv(SALT_ENV)
        assert self.call(*drive) == 2
        monkeypatch.setenv(SALT_ENV, self.short)
        assert self.call(*drive) == 2
        monkeypatch.setenv(SALT_ENV, salt)
        self.store = root / "store.sqlite"
        self.bundle = root / "bundle"
        self.report = root / "report.md"
        self.held, self.runs = held, runs
        recordings = [str(p) for p in recordings_in(runs)]
        for step in (
            ("store", "ingest", "--store", self.store, "--engagement", held, *recordings),
            ("report", "--engagement", held, "--store", self.store, "--runs", runs,
             "--out-dir", runs, "--out", self.report),
            ("evidence", "pack", "--engagement", held, "--store", self.store, "--runs", runs,
             "--report", self.report, "--out", self.bundle),
            ("engagement", "show", held),
        ):  # fmt: skip
            code = self.call(*step)
            assert code in (0, 3), (step[:2], code, self.captured[-1])

    def call(self, *argv) -> int:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(part) for part in argv])
        self.captured.append((out.getvalue(), err.getvalue()))
        return code

    def artifacts(self) -> list[tuple[str, bytes]]:
        found = [
            (str(path.relative_to(self.root)), path.read_bytes())
            for path in sorted(self.root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        for out, err in self.captured:
            found += [("stdout", out.encode()), ("stderr", err.encode())]
        return found


@pytest.fixture
def artifacts(tmp_path, monkeypatch, salt) -> Artifacts:
    return Artifacts(tmp_path / "world", salt, monkeypatch)


def test_the_salt_is_in_no_artifact(artifacts):
    found = artifacts.artifacts()

    names = {label.split("/")[0] for label, _ in found}
    assert {"runs", "store.sqlite", "bundle", "report.md"} <= names
    assert any(label.endswith("refusals.jsonl") for label, _ in found)
    assert any(content for label, content in found if label == "stdout")
    holding = [
        (label, form)
        for label, content in found
        for value in (artifacts.salt, artifacts.short)
        for form in forms_of(value)
        if form.encode() in content
    ]
    assert holding == []
    recorded = "".join(p.read_text() for p in (artifacts.runs).glob("*/events.jsonl"))
    assert PLACEHOLDER in recorded, "the server did send the salt back, and it was blanked"


def test_the_report_names_the_replacements_of_each_run_as_numbers(tmp_path, monkeypatch, salt):
    value = known()
    # Per run: the address of the server and the two here, one number, one known value.
    extra = f" {address()} {phone()} {value}"
    world = Artifacts(tmp_path / "world", salt, monkeypatch, extra=extra, known_values=[value])

    lines = [
        line
        for line in world.report.read_text().splitlines()
        if "replaced personal data by pseudonyms" in line
    ]

    assert len(lines) == 2
    for line in lines:
        assert re.fullmatch(
            r"\[recorded\] Run `[0-9a-f]{12}` replaced personal data by pseudonyms: "
            r"2 `email`, 0 `iban`, 1 `tel`, 1 `known`\.",
            line,
        ), line
        assert not PSEUDONYM.search(line)


# -- a known value in what a refusal of the fleet holds ------------------------------------------


def fleet_manifest(
    inputs: Path,
    *,
    entry: str = "poison-server",
    scenario: str | None = None,
    directory: Path | None = None,
):
    """The fixture's poison entry named ``entry``, with, where given, a scenario of its own named
    ``scenario``, in ``directory`` (made here) or in the inputs' ``work``. The inputs hold the
    value and lie outside ``tmp_path``, where the outputs are searched for it."""
    from test_fleet import ALL_SIGNALS, write_manifest

    work = inputs / "work" if directory is None else directory
    work.mkdir(parents=True)
    path = write_manifest(work, {"name": entry})
    if scenario is not None:
        copy = path.parent / "named.yaml"
        copy.write_text(
            ALL_SIGNALS.read_text().replace("name: all-signals", f"name: {scenario}", 1)
        )
        data = json.loads(path.read_text())
        data["entries"][0]["scenarios"] = [copy.name]
        path.write_text(json.dumps(data))
    return path


def fleet_call(tmp_path, held, manifest, out_dir, capsys, monkeypatch):
    """``fleet run`` with nothing allowed to be pinned; the exit code, and everything it wrote to
    stdout and stderr."""
    from mcp_kymograph import fleet

    def asked(*_args, **_kwargs):
        raise AssertionError("docker was asked for a fleet that is refused")

    monkeypatch.setattr(fleet, "pin", asked)
    code = cli.main(
        ["fleet", "run", "--engagement", str(held), "--manifest", str(manifest), "--store",
         str(tmp_path / "store.sqlite"), "--out-dir", str(out_dir)]
    )  # fmt: skip
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def written_under(root: Path) -> list[tuple[str, bytes]]:
    return [(str(p), p.read_bytes()) for p in sorted(root.rglob("*")) if p.is_file()]


def holding(value: str, root: Path, said: str, *, apart: Path | None = None) -> list[str]:
    """Where the value stands in a form: in the bytes of a file under ``root`` (not under
    ``apart``, the manifest's own directory) or in what the command said."""
    return [
        where
        for form in forms_of(value)
        for where, content in [
            *(
                (path, data)
                for path, data in written_under(root)
                if apart is None or apart not in Path(path).parents
            ),
            ("stdout and stderr", said.encode()),
        ]
        if form.encode() in content
    ]


@pytest.mark.parametrize(
    ("kwargs", "place"),
    [
        ({"entry": "{}-crm"}, "the name of entry 1"),
        ({"scenario": "{}-scan"}, "the name of scenario 1 of entry 1"),
    ],
)
def test_a_fleet_whose_manifest_names_hold_a_known_value_is_refused_before_anything_exists(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch, kwargs, place
):
    value = known()
    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(inputs / "engagement", known_values=[value])
    manifest = fleet_manifest(inputs, **{k: v.format(value) for k, v in kwargs.items()})
    runs = tmp_path / "runs"

    code, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert place in record.message and place in said
    assert not (tmp_path / "store.sqlite").exists()
    assert [p for p in runs.iterdir() if p.is_dir()] == []
    for form in forms_of(value):
        assert form not in said
        assert [path for path, content in written_under(tmp_path) if form.encode() in content] == []


def test_a_fleet_refusal_writes_no_known_value_of_its_out_dir(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch
):
    from test_fleet_endpoint import with_endpoints

    value = known()
    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(inputs / "engagement", known_values=[value])
    (inputs / "work").mkdir()
    manifest = with_endpoints(inputs / "work", "customer-mcp")
    runs = tmp_path / f"runs-{value}"

    code, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert "--out-dir" in record.message and "--out-dir" in said
    assert "***KNOWN-" in " ".join(record.command)
    for form in forms_of(value):
        assert form not in said
        assert [path for path, content in written_under(tmp_path) if form.encode() in content] == []


def test_a_fleet_entry_without_a_known_value_is_not_refused_for_its_name(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch
):
    inputs = tmp_path_factory.mktemp("inputs")
    value = known()
    held = second_file(inputs / "engagement", known_values=[value])
    manifest = fleet_manifest(inputs, entry="reference-server", scenario="all-signals-2")
    runs = tmp_path / "runs"

    # The manifest fails at the gate, which is no matter here: the names are not why.
    _, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)

    assert not any(r.reason == "name_holds_known_value" for r in refusals_in(runs))
    assert holding(value, tmp_path, said) == []


def test_a_fleet_whose_manifest_path_holds_a_known_value_is_refused_before_anything_exists(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch
):
    value = known()
    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(inputs / "engagement", known_values=[value])
    directory = tmp_path / f"{value}-manifests"
    manifest = fleet_manifest(inputs, directory=directory)
    runs = tmp_path / "runs"

    code, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert "--manifest" in record.message and "--manifest" in said
    assert not (tmp_path / "store.sqlite").exists()
    assert [p for p in runs.iterdir() if p.is_dir()] == []
    assert holding(value, tmp_path, said, apart=directory) == []


def test_a_fleet_manifest_path_without_a_known_value_is_not_refused_for_its_path(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch
):
    value = known()
    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(inputs / "engagement", known_values=[value])
    directory = tmp_path / "manifests"
    manifest = fleet_manifest(inputs, directory=directory)
    runs = tmp_path / "runs"

    # The fleet may get as far as pin(), which the call forbids; its path is not why it stops.
    try:
        _, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)
    except AssertionError:
        captured = capsys.readouterr()
        said = captured.out + captured.err
    assert not (runs / engagement.REFUSALS_FILE).exists() or not any(
        r.reason == "name_holds_known_value" for r in refusals_in(runs)
    )
    assert holding(value, tmp_path, said, apart=directory) == []


# -- engagement purge ----------------------------------------------------------------------------


def snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        str(path): (path.read_bytes() if path.is_file() else None)
        for path in sorted(root.rglob("*"))
    }


def test_purge_of_a_version_two_engagement_wants_the_salt_deleted_and_deletes_nothing_without(
    artifacts, capsys
):
    out = artifacts.root / "record" / "purged.json"
    before = snapshot(artifacts.root)
    arguments = ["engagement", "purge", "--store", artifacts.store, "--out-dir", artifacts.runs,
                 "--author", "A. Operator", "--out", out, "--before-retention", "test"]  # fmt: skip

    assert artifacts.call(*arguments) == 2

    assert "--salt-deleted" in artifacts.captured[-1][1]
    assert snapshot(artifacts.root) == before, "a refused purge deletes nothing and writes nothing"
    with pytest.raises(evidence.EvidenceError, match="--salt-deleted"):
        evidence.purge(
            store_path=artifacts.store, out_dir=artifacts.runs, author="A", out=out,
            before_retention_reason="test",
        )  # fmt: skip

    assert artifacts.call(*arguments, "--salt-deleted") == 0

    purged = evidence.read_purged(out)
    assert purged.salt_deleted_utc is not None
    assert json.loads(out.read_text())["salt_deleted"] == {
        "confirmed": True,
        "utc": purged.salt_deleted_utc,
    }
    assert not artifacts.store.exists()
    assert purged.complete


def test_purge_of_a_version_one_engagement_needs_no_confirmation(tmp_path):
    from test_evidence_purge import AFTER, Work

    work = Work(tmp_path / "work")

    purged = work.purge(now=AFTER)

    assert purged.salt_deleted_utc is None and purged.complete
    assert json.loads(work.out.read_text())["salt_deleted"] is None
    assert evidence.read_purged(work.out) == purged


def test_a_purged_json_from_before_the_salt_still_reads(tmp_path):
    from test_evidence_purge import AFTER, Work

    work = Work(tmp_path / "work")
    work.purge(now=AFTER)
    data = json.loads(work.out.read_text())
    del data["salt_deleted"]
    older = tmp_path / "older.json"
    older.write_text(json.dumps(data))

    assert evidence.read_purged(older).salt_deleted_utc is None


# -- the count -----------------------------------------------------------------------------------


def test_the_count_is_exact_for_a_run_with_a_known_number_of_each_kind():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["Alpha-Kunde", "Beta-Kunde"])
    rec = Recorder(io.StringIO(), run_id="r", masker=masker)
    stream = rec._stream
    rec.run_started(0, 0, argv=["server"], limits={})
    rec.message(
        1, 0, direction=Direction.SERVER_TO_CLIENT,
        raw=json.dumps({"a": f"{address()} {address()} {address()}", "b": [iban(), groups(iban())],
                        "c": phone(), "d": "Alpha-Kunde, Beta-Kunde, Alpha-Kunde"}).encode(),
    )  # fmt: skip
    rec.message(2, 0, direction=Direction.CLIENT_TO_SERVER, raw=f"no JSON {address()}".encode())
    rec.run_finished(
        3, 0, reason="eof", duration_ns=1, server_output_bytes=0, client_input_bytes=0,
        server_exited_first=False,
    )  # fmt: skip

    assert written(stream)[-1]["replacements"] == {"email": 4, "iban": 2, "tel": 1, "known": 3}


def test_what_is_read_to_decide_is_not_counted():
    masker = Masker(handle_salt=HANDLE_SALT)
    name = address()

    masker.mask_headers({name: "x", "X-A": "y"})  # a name that holds an address is not kept
    masker.mask_query(f"{quote(name, safe='')}=1")

    assert masker.replacements == {"email": 0, "iban": 0, "tel": 0, "known": 0}


# -- what is blanked whole because a decoding shows it ------------------------------------------


def one_response(headers: list[tuple[str, str]]) -> tuple[Recorder, dict, Masker]:
    rec, stream, masker = recorder()
    rec.run_started(0, 0, argv=["server"], limits={})
    rec.http_response(
        1, 0, exchange=1, status=200, reason="ok", headers=headers,
        content_type="text/plain", framing="json",
    )  # fmt: skip
    (response,) = [e for e in written(stream) if e["type"] == "http_response"]
    return rec, response, masker


NO_REPLACEMENTS = {"email": 0, "iban": 0, "tel": 0, "known": 0}


def test_a_header_blanked_for_a_decoding_counts_each_value_once_and_is_no_server_redaction():
    written_plain, written_encoded = address("a"), address("b")

    rec, response, masker = one_response(
        [("X-A", f"{written_plain} {quote(written_encoded, safe='')}")]
    )

    assert response["headers"]["x-a"] == PLACEHOLDER
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 2}
    assert rec.server_redactions == 0


def test_a_referer_blanked_for_a_decoding_counts_the_value_once_and_is_no_server_redaction():
    rec, response, masker = one_response(
        [("Referer", f"https://h.example/?e={quote(address(), safe='')}")]
    )

    assert response["headers"]["referer"] == PLACEHOLDER
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}
    assert rec.server_redactions == 0


def test_a_header_that_is_written_counts_what_it_replaced_and_is_no_redaction():
    masker = Masker(handle_salt=HANDLE_SALT)

    headers, paths = masker.mask_headers({"X-A": f"{address()} {address()}"})

    assert PSEUDONYM.sub("", headers["x-a"]) == " " and paths == []
    assert masker.replacements["email"] == 2


# -- an encoded value in a path ------------------------------------------------------------------


def path_recorder(path: str) -> tuple[Recorder, io.StringIO, Masker]:
    """A recorder of a run whose engagement file lets this path be written as it is."""
    stream = io.StringIO()
    masker = Masker(handle_salt=HANDLE_SALT)
    rec = Recorder(stream, run_id="r", masker=masker, verbatim_paths=[("server.example", 80, path)])
    return rec, stream, masker


def start_at(rec: Recorder, path: str) -> None:
    rec.run_started(
        0, 0, argv=[], limits={}, transport="streamable-http",
        endpoint=f"http://server.example{path}",
    )  # fmt: skip


def test_a_value_that_only_a_decoding_of_a_path_shows_is_replaced_where_the_path_is_written():
    call = phone().replace("tel:+", "tel:%2B")
    path = f"/call/{call}"
    rec, stream, masker = path_recorder(path)

    start_at(rec, path)

    (started,) = written(stream)
    written_path = started["endpoint"]["path"]
    assert PSEUDONYM.search(written_path) and "tel:" not in written_path.lower()
    assert "%2B" not in written_path
    assert masker.replacements == {**NO_REPLACEMENTS, "tel": 1}


def test_a_value_that_stands_in_the_path_as_written_is_replaced_there_and_the_escapes_stay():
    path = "/call/tel:+49-30-1234567/a%20b"
    rec, stream, masker = path_recorder(path)

    start_at(rec, path)

    (started,) = written(stream)
    written_path = started["endpoint"]["path"]
    assert re.fullmatch(r"/call/[*]{3}TEL-[0-9a-f]{12}[*]{3}/a%20b", written_path), written_path
    assert masker.replacements == {**NO_REPLACEMENTS, "tel": 1}


def decoded_path(masker: Masker, path: str) -> str:
    """What the recorder's ``_path`` hands ``mask_decoded``: the path and its decodings. An
    ``@`` never gets that far through the recorder (``_holds_at`` blanks the path first), so the
    rule is tested on the masker."""
    forms = [path]
    for _ in range(masking.MAX_DECODINGS):
        decoded = unquote(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    return masker.mask_decoded(forms)


@pytest.mark.parametrize(
    "encoded, literal",
    [("j%C3%BCrgen.mueller", "jürgen.mueller"), ("a%2Btag", "a+tag")],
)
def test_a_path_whose_encoding_cuts_an_address_is_written_decoded_with_the_pseudonym(
    encoded, literal
):
    masker = Masker(handle_salt=HANDLE_SALT)

    written_path = decoded_path(masker, f"/users/{encoded}@firma.example")

    assert re.fullmatch(r"/users/[*]{3}EMAIL-[0-9a-f]{12}[*]{3}", written_path), written_path
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}
    in_text = masker.mask_text(f"mail {literal}@firma.example")[0]
    assert pseudonyms(in_text) == pseudonyms(written_path)


def test_a_path_with_one_address_encoded_and_written_leaves_no_part_of_the_name():
    masker = Masker(handle_salt=HANDLE_SALT)

    written_path = decoded_path(masker, "/u/j%C3%BCrgen@x.example/jürgen@x.example")

    first, second = pseudonyms(written_path)
    assert first == second
    assert written_path == f"/u/{first}/{second}"
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 2}


def test_a_path_that_shows_a_value_as_written_keeps_its_escapes_and_counts_it_once():
    masker = Masker(handle_salt=HANDLE_SALT)

    written_path = decoded_path(masker, "/call/tel:+49-30-1234567/a%20b")

    assert re.fullmatch(r"/call/[*]{3}TEL-[0-9a-f]{12}[*]{3}/a%20b", written_path), written_path
    assert masker.replacements == {**NO_REPLACEMENTS, "tel": 1}


def test_a_path_with_a_value_in_a_decoding_and_a_credential_is_blanked_and_counts_none():
    token = "tok-" + secrets.token_hex(8)
    path = f"/call/{phone().replace('tel:+', 'tel:%2B')}/Bearer%20{token}"
    rec, stream, masker = path_recorder(path)

    start_at(rec, path)

    assert written(stream)[0]["endpoint"]["path"] == PLACEHOLDER
    assert token not in stream.getvalue()
    assert masker.replacements == NO_REPLACEMENTS


def test_a_path_with_a_value_as_it_is_written_counts_it_once():
    path = f"/call/{phone()}"
    rec, stream, masker = path_recorder(path)

    start_at(rec, path)

    assert PSEUDONYM.search(written(stream)[0]["endpoint"]["path"])
    assert masker.replacements == {**NO_REPLACEMENTS, "tel": 1}


# -- a salt the gate does not take ---------------------------------------------------------------


@pytest.mark.parametrize("short", ["SALT", "e"])
def test_a_short_salt_is_no_literal_and_the_refusal_names_its_variable_whole(
    tmp_path, monkeypatch, capsys, nothing_starts, short
):
    held = second_file(tmp_path / "engagement")
    monkeypatch.setenv(SALT_ENV, short)

    assert drive(held, tmp_path / "runs") == 2

    (record,) = refusals_in(tmp_path / "runs")
    expected = (
        f"the environment variable {SALT_ENV}, which holds the salt of the pseudonyms, "
        "holds fewer than 32 characters"
    )
    assert record.reason == "salt_too_short"
    assert record.message.endswith(expected), record.message
    assert expected in capsys.readouterr().err
    assert PLACEHOLDER not in (tmp_path / "runs" / engagement.REFUSALS_FILE).read_text()


def test_a_salt_the_gate_takes_stays_a_literal(tmp_path, monkeypatch):
    held = engagement.load(second_file(tmp_path / "engagement"))
    value = "k" * 31 + "!"
    monkeypatch.setenv(SALT_ENV, value)

    taken = cli.run_masker([], held=held)

    assert taken.mask_text(f"echo {value} echo")[0] == f"echo {PLACEHOLDER} echo"
    monkeypatch.setenv(SALT_ENV, value[1:])
    refused = cli.run_masker([], held=held)
    assert refused.mask_text(f"echo {value[1:]} echo")[0] == f"echo {value[1:]} echo"


# -- the registry of lengths and the check digits ------------------------------------------------


def test_honduras_is_in_the_registry_and_its_iban_is_found():
    assert masking.IBAN_LENGTHS["HN"] == 28
    assert len(masking.IBAN_LENGTHS) == 89
    value = iban("HN")

    assert PSEUDONYM.fullmatch(masked(value)) and PSEUDONYM.fullmatch(masked(groups(value)))


def test_the_check_digits_of_an_iban_are_02_to_98():
    # Mod 97 alone takes 01 where 98 is meant, and 99 and 00 for some accounts.
    value = iban()
    for digits in ("00", "01", "99"):
        other = value[:2] + digits + value[4:]
        assert masked(other) == other


def test_a_hex_id_in_capitals_with_a_country_a_length_and_a_valid_check_is_still_found():
    # The limit of the rule, written down in docs/engagements.md: about one in 64 000 ids of
    # the right length in capital hex (AD, AE, BA, BE, DE or EE, two decimal digits, mod 97).
    value = iban("BE")

    assert masked(value.lower()) == value.lower()
    assert PSEUDONYM.fullmatch(masked(value))


# -- linear time ---------------------------------------------------------------------------------

#: One input per scan that a hostile text can aim at; each is made to two sizes, eight times apart,
#: as in test_hostile_input_runtime.py.
HOSTILE = {
    "only @": "@",
    "a local part in front of every @": "a@",
    "a long local part": ("", "a" * 70 + "@", ""),
    "labels without end": ("a@", "b.", ""),
    "a host that never ends": ("a@b.", "c", ""),
    "an SCP remote behind every address": "a@b.cc:",
    "digits": "0123456789",
    "tel: starts": "tel:",
    "tel: starts with a digit": "tel:1",
    "a tel: number that never ends": ("tel:", "1", ""),
    "a tel: number that ends in full stops": ("tel:1", ".", ""),
    "a tel: number that ends in closing parentheses": ("tel:1", ")", ""),
    "a tel: number that ends in marks of a sentence": ("tel:1", ".,;!)", ""),
    "@, digits and tel: starts": "@1tel:@2tel:",
    "IBAN starts": "DE89 ",
    "IBAN groups that never end": "DE89 " + "3704 " * 5,
    "country codes": "DE12",
    "letters and digits": "ab12cd34 ",
    "a non-ASCII letter in front of every @": "é@",
    "a long non-ASCII local part": ("", "é" * 70 + "@", ""),
    "a non-ASCII label that never ends": ("a@", "é.", ""),
    "a non-ASCII host that never ends": ("a@é.", "é", ""),
    "a quote in front of every @": '"@',
    "a quote and a name in front of every @": '"a"@',
    "a long text in quotes in front of every @": ("", '"' + "é " * 30 + '"@', ""),
    "an open quote in front of every @": ('"', "é ", '"@x.example'),
    "combining marks": "e\u0301@",
}


@pytest.mark.parametrize("name", HOSTILE)
def test_the_scans_for_the_three_forms_run_in_linear_time(name):
    entry = HOSTILE[name]
    scan = masking._personal_spans
    small, large = _Text(entry, SMALL), _Text(entry, LARGE)

    best_small, best_large = _best(
        partial(scan, small.raw),
        partial(scan, large.raw),
        5,
        lambda: partial(scan, _Text(entry, 2 * SMALL).raw),
    )

    assert best_large <= BOUND * max(best_small, 1e-4), (best_small, best_large)


def _old_tel_spans(text: str) -> list[masking._Span]:
    """``_tel_spans`` as it was: the end struck off a copy at a time, the parentheses counted
    again each time."""
    found: list[masking._Span] = []
    done = 0
    for scheme in masking._TEL_SCHEME.finditer(text):
        if scheme.start() < done:
            continue
        body = masking._TEL_BODY.match(text, scheme.end())
        number = "" if body is None else body.group()
        while number and (
            number[-1] in ".,;!" or (number[-1] == ")" and number.count("(") < number.count(")"))
        ):
            number = number[:-1]
        if not number or number[0] not in "+0123456789" or not any(c.isdigit() for c in number):
            continue
        end = scheme.end() + len(number)
        found.append((scheme.start(), end, text[scheme.start() : end]))
        done = end
    return found


def test_the_tel_spans_are_those_of_the_quadratic_version_for_random_texts():
    import random

    chosen = random.Random(20261104)  # noqa: S311 - a fixed seed, no secret
    alphabet = "tel:+0123456789().,;!- "
    for _ in range(200):
        text = "".join(chosen.choice(alphabet) for _ in range(chosen.randint(0, 40)))
        # The scheme is rare in a random text: put it in front of most, in either case.
        text = chosen.choice(["", "tel:", "TEL:", "xtel:"]) + text
        assert masking._tel_spans(text) == _old_tel_spans(text), text


def test_a_megabyte_of_non_ASCII_letters_in_front_of_at_signs_is_masked_in_one_pass():
    unit = "é" * 63 + "@" + "ü" * 40 + '"' + "ö" * 30 + '"@'
    text = unit * (1_000_000 // len(unit))
    masker = Masker(handle_salt=HANDLE_SALT)

    import time

    started = time.process_time()
    masker.mask_text(text)
    elapsed = time.process_time() - started

    assert len(text) >= 900_000
    assert elapsed < 30, f"{elapsed:.1f} s for a megabyte"


def test_a_megabyte_of_at_signs_digits_and_tel_starts_is_masked_in_one_pass():
    text = ("@" * 3 + "0123456789" * 4 + "tel:" * 2 + "+4" + "a@") * (1_000_000 // 55)
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["0123456789012345"])

    import time

    started = time.process_time()
    masker.mask_text(text)
    elapsed = time.process_time() - started

    assert len(text) >= 900_000
    assert elapsed < 30, f"{elapsed:.1f} s for a megabyte"


# -- a known value that stands as a JSON number ----------------------------------------------------

NUMBER_SERVER = """\
import json, sys

for raw in sys.stdin.buffer:
    request = json.loads(raw)
    if "id" not in request:
        continue
    method = request.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "numbers", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "lookup", "description": "Finds a customer.",
                             "inputSchema": {"type": "object"}}]}
    else:
        result = {"content": [{"type": "text", "text": "found"}],
                  "structuredContent": {"customer": NUMBER, "year": 91234, "flag": True}}
    reply = {"jsonrpc": "2.0", "id": request["id"], "result": result}
    sys.stdout.write(json.dumps(reply) + chr(10))
    sys.stdout.flush()
"""


def test_a_known_value_that_is_a_json_number_is_replaced_as_the_string_is():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["123456789", "1234", "0.5"])

    document, paths = masker.mask_json(
        {"id": 123456789, "text": "123456789", "year": 91234, "part": 1234, "half": 0.5,
         "list": [123456789], "flag": True}
    )  # fmt: skip

    stand_in = masker.personal_pseudonym("known", "123456789")
    assert document["id"] == document["text"] == document["list"][0] == stand_in
    assert document["half"] == masker.personal_pseudonym("known", "0.5")
    assert document["year"] == "9" + masker.personal_pseudonym("known", "1234")
    assert document["flag"] is True
    assert document["part"] == masker.personal_pseudonym("known", "1234")
    assert paths == [], "a stand-in for a known value is no redaction, as for a string"
    assert masker.replacements["known"] == 6


def test_a_number_that_holds_the_digits_of_a_known_value_is_masked_as_its_text():
    """As if it had been quoted: the digits around the value stay, the number is a string."""
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["1234"])
    stand_in = masker.personal_pseudonym("known", "1234")

    assert masker.mask_json({"year": 91234, "ratio": 1234.5, "other": 9123}) == (
        {"year": f"9{stand_in}", "ratio": f"{stand_in}.5", "other": 9123},
        [],
    )
    assert masker.replacements["known"] == 2


def test_the_three_shapes_do_not_apply_to_a_number():
    masker = Masker(handle_salt=HANDLE_SALT)
    number = int("49301234567" * 2)

    assert masker.mask_json({"n": number, "t": 1700000000000}) == (
        {"n": number, "t": 1700000000000},
        [],
    )
    assert masker.replacements == dict.fromkeys(masking.PERSONAL_KINDS, 0)


def test_a_boolean_is_no_number_even_where_its_text_is_a_known_value():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["true", "false", "True", "1"])

    assert masker.mask_json({"a": True, "b": False, "c": [True]})[0] == {
        "a": True,
        "b": False,
        "c": [True],
    }


def test_a_number_known_value_is_the_same_pseudonym_in_the_recording_the_store_and_the_bundle(
    tmp_path, salt
):
    value = "".join(secrets.choice("123456789") for _ in range(9))
    held = second_file(
        tmp_path / "engagement",
        known_values=[value, "1234"],
        actions={"list": True, "call": True},
    )
    manifest = tmp_path / "corpus" / "manifest.json"
    manifest.parent.mkdir()
    (manifest.parent / "numbers.py").write_text(f"NUMBER = {value}\n" + NUMBER_SERVER)
    script_file = tmp_path / "engagement" / "call.yaml"
    script_file.write_text(
        "version: 1\nname: probe\nsteps:\n  - initialize\n  - list: tools/list\n"
        f"  - call: {{tool: lookup, arguments: {{customer: {value}, year: 91234}}}}\n"
    )
    launch = {"transport": "stdio", "command": ["{python}", "{dir}/numbers.py"]}
    entry = {
        "name": "numbers",
        "provenance": "reference",
        "source": {"paths": ["numbers.py"]},
        "launch": launch,
        "scenarios": [os.path.relpath(SCENARIO, manifest.parent)],
    }
    manifest.write_text(json.dumps({"version": 1, "entries": [entry]}))
    world = Artifacts.__new__(Artifacts)
    world.root, world.captured = tmp_path, []
    runs = tmp_path / "runs"
    corpus = ["--manifest", manifest, "--entry", "numbers", "--isolation", "host"]
    code = world.call("drive", "-q", "--engagement", held, "--out-dir", runs, *corpus,
                      "--script", script_file)  # fmt: skip
    assert code == 0, world.captured[-1]
    store, bundle, report = tmp_path / "store.sqlite", tmp_path / "bundle", tmp_path / "report.md"
    recordings = [str(p) for p in recordings_in(runs)]
    for step in (
        ("store", "ingest", "--store", store, "--engagement", held, *recordings),
        ("report", "--engagement", held, "--store", store, "--runs", runs,
         "--out-dir", runs, "--out", report),
        ("evidence", "pack", "--engagement", held, "--store", store, "--runs", runs,
         "--report", report, "--out", bundle),
    ):  # fmt: skip
        assert world.call(*step) in (0, 3), (step[:2], world.captured[-1])

    found = world.artifacts()
    names = {label.split("/")[0] for label, _ in found}
    assert {"runs", "store.sqlite", "bundle", "report.md"} <= names
    written = [
        (label, content)
        for label, content in found
        if not label.startswith(("corpus", "engagement"))
    ]
    assert [label for label, content in written if value.encode() in content] == []
    recorded = "".join(p.read_text() for p in runs.glob("*/events.jsonl"))
    stand_in = Masker(handle_salt=HANDLE_SALT, personal_salt=salt.encode()).personal_pseudonym(
        "known", value
    )
    assert recorded.count(stand_in) >= 2, "the reply and the argument, both"
    # 91234 holds the known value 1234: masked as its text, in the reply and in the argument.
    part = Masker(handle_salt=HANDLE_SALT, personal_salt=salt.encode()).personal_pseudonym(
        "known", "1234"
    )
    assert "91234" not in recorded and recorded.count(f'"9{part}"') >= 2
    # Every file that shows the numbers shows them as these pseudonyms and no other.
    for label, content in written:
        assert set(pseudonyms(content.decode("utf-8", "replace"))) <= {stand_in, part}, label
    # The store keeps findings, not messages: the number is not in it, and no other form of it.
    assert any(stand_in.encode() in content for label, content in written if "bundle" in label)


def test_a_number_replaced_by_a_pseudonym_is_no_redaction_of_the_server():
    rec, stream, masker = recorder()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=["123456789"])
    rec = Recorder(stream, run_id="r", masker=masker)
    body = json.dumps({"customer": 123456789}).encode()

    rec.message(1, 0, direction=Direction.SERVER_TO_CLIENT, raw=body)

    assert rec.server_redactions == 0
    (event,) = written(stream)
    assert event["payload"]["redactions"] == [] and event["payload"]["redaction_count"] == 0
    assert event["payload"]["data"] == {"customer": masker.personal_pseudonym("known", "123456789")}
    assert masker.replacements["known"] == 1


# -- numbers in the handover bundle ----------------------------------------------------------------


NUMBER_PATTERN = "123456789"


@pytest.fixture
def number_material(tmp_path, monkeypatch):
    """The material of test_evidence_redact, with a number as the only pattern."""
    import functools

    import test_evidence_redact as redaction

    def with_pattern(pattern: str):
        monkeypatch.setattr(
            redaction,
            "write_engagement",
            functools.partial(
                redaction.write_engagement,
                redaction={"mask_keys": ["customer_id"], "mask_patterns": [pattern]},
            ),
        )
        return redaction.Material(tmp_path / "work")

    return redaction, with_pattern


def put_number(session: Path, direction: str, number) -> None:
    """A number into a message of the recording, where the server's reply or the script's
    arguments would hold it: outside every surface a review lists."""
    lines = []
    for line in session.read_text().splitlines():
        event = json.loads(line)
        data = event.get("payload", {}).get("data", {})
        if event["type"] == "message" and event["direction"] == direction:
            if direction == "server_to_client" and event["responded_method"] == "tools/list":
                data["result"]["customer"] = number
            if direction == "client_to_server" and data.get("method") == "tools/list":
                data["params"] = {"arguments": {"customer": number}}
        lines.append(json.dumps(event))
    session.write_text("\n".join(lines) + "\n")


@pytest.mark.parametrize(
    ("pattern", "number", "direction"),
    [
        ("123456789", 123456789, "server_to_client"),
        ("123456789", 123456789, "client_to_server"),
        ("3456789", 1234567890, "server_to_client"),
        ("3456789", 1234567890, "client_to_server"),
        ("75318642", 0.75318642, "server_to_client"),
    ],
)
def test_a_pattern_in_a_json_number_refuses_the_redaction(
    number_material, tmp_path, pattern, number, direction
):
    redaction, with_pattern = number_material
    material = with_pattern(pattern)
    # Without the number there is no refusal (a pattern a string of the recording holds by
    # chance, a digest, is taken out first), so the refusal below is the number's.
    material.session.write_text(material.session.read_text().replace(pattern, pattern[:-1] + "0"))
    first = tmp_path / "bundle-1"
    material.pack(first)
    redaction.redact(material, first, tmp_path / "handover-1")
    put_number(material.session, direction, number)
    bundle = tmp_path / "bundle"
    material.pack(bundle)

    said = redaction.refused(material, bundle, tmp_path / "handover", "outside the surfaces")

    assert "mask_patterns[0]" in said and str(number) not in said


def test_a_boolean_triggers_no_pattern():
    rules = SimpleNamespace(patterns=(("mask_patterns[0]", "true"), ("mask_patterns[1]", "false")))
    event = {"seq": 1, "a": True, "b": [False], "n": 7}

    evidence._still_in_event("events.jsonl", b"", event, rules, {})
    with pytest.raises(evidence.EvidenceError, match=r"mask_patterns\[0\]"):
        evidence._still_in_event("events.jsonl", b"", {**event, "s": "true"}, rules, {})


# -- the script's name -----------------------------------------------------------------------------


def script_runs(tmp_path: Path, name: str, known: str) -> list[Path]:
    held = second_file(tmp_path / "engagement", known_values=[known])
    script_file = tmp_path / "engagement" / "probe.yaml"
    script_file.write_text(
        f"version: 1\nname: {name}\nsteps:\n  - initialize\n  - list: tools/list\n"
    )
    import test_evidence_redact as redaction

    manifest = redaction.copy_corpus(tmp_path / "work")
    runs = tmp_path / "runs"
    for _ in range(2):
        code = cli.main(
            ["drive", "-q", "--engagement", str(held), "--out-dir", str(runs), "--manifest",
             str(manifest), "--entry", "reference-server", "--isolation", "host", "--script",
             str(script_file)]
        )  # fmt: skip
        assert code == 0
    return recordings_in(runs)


def test_a_known_value_in_the_name_of_a_script_is_replaced_in_the_recording_and_the_report(
    tmp_path, salt
):
    word = "Zorn"
    recordings = script_runs(tmp_path, f"{word}-probe", word)

    names = {events_of(r)[0]["script"] for r in recordings}
    assert len(recordings) == 2 and len(names) == 1, "the same masked name in two runs"
    (name,) = names
    assert PSEUDONYM.search(name) and word not in name and name.endswith("-probe")
    store, report = tmp_path / "store.sqlite", tmp_path / "report.md"
    held = tmp_path / "engagement" / "acme-2026-10.json"
    for step in (
        ["store", "ingest", "-q", "--store", store, "--engagement", held, *recordings],
        ["report", "--engagement", held, "--store", store, "--runs", tmp_path / "runs",
         "--out-dir", tmp_path / "runs", "--out", report],
    ):  # fmt: skip
        assert cli.main([str(part) for part in step]) in (0, 3)
    for recording in recordings:
        assert word not in recording.read_text()
    assert word not in report.read_text()


def test_the_digest_of_a_script_is_that_of_the_unmasked_file(tmp_path, salt):
    recording = script_runs(tmp_path, "Zorn-probe", "Zorn")[0]
    file = tmp_path / "engagement" / "probe.yaml"

    assert events_of(recording)[0]["script_digest"] == sha256(file.read_bytes()).hexdigest()


# -- only the numbers of the traffic refuse --------------------------------------------------------


def put_tool_numbers(session: Path, pattern: str) -> int:
    """The tool's own numbers of every event of the recording, ``t_ns`` and ``size_bytes``
    among them, made to hold ``pattern``; how many numbers were set. A pattern a string of the
    recording happens to hold by chance (a digest) is taken out first, so the test is the same
    every time."""
    lines, count = [], 0
    for line in session.read_text().splitlines():
        event = json.loads(line.replace(pattern, pattern[:-1] + "0"))
        for key in ("t_ns", "size_bytes", "duration_ns", "redaction_count"):
            if type(event.get(key)) is int:
                event[key] = int(f"9{pattern}{event[key]}")
                count += 1
        lines.append(json.dumps(event))
    session.write_text("\n".join(lines) + "\n")
    return count


def test_a_pattern_in_the_numbers_of_the_tool_is_no_refusal_but_in_the_traffic_it_is(
    number_material, tmp_path
):
    redaction, with_pattern = number_material
    material = with_pattern("45678123")
    assert put_tool_numbers(material.session, "45678123") > 5
    recorded = events_of(material.session)
    assert any("45678123" in str(e["t_ns"]) for e in recorded)
    assert any("45678123" in str(e.get("size_bytes")) for e in recorded)
    first = tmp_path / "bundle-1"
    material.pack(first)

    redaction.redact(material, first, tmp_path / "handover-1")

    put_number(material.session, "client_to_server", 9456781230)
    second = tmp_path / "bundle-2"
    material.pack(second)
    said = redaction.refused(material, second, tmp_path / "handover-2", "outside the surfaces")
    assert "mask_patterns[0]" in said and "9456781230" not in said


TOOL_EVENT = {"v": 1, "seq": 4567, "t_ns": 94567, "type": "message", "size_bytes": 4567}
TOOL_EVENT |= {"duration_ns": 4567, "exchange": 4567, "target": {"path_length": 4567}}
TOOL_EVENT |= {"payload": {"redaction_count": 4567}}


def put_at(path: tuple[str, ...], value) -> dict:
    """A dictionary with ``value`` at ``path`` from its root, the levels made on the way."""
    root: dict = {}
    here = root
    for key in path[:-1]:
        here = here.setdefault(key, {})
    here[path[-1]] = value
    return root


def refuses_4567(event: dict) -> bool:
    rules = SimpleNamespace(patterns=(("mask_patterns[0]", "4567"),))
    try:
        evidence._still_in_event("events.jsonl", b"", event, rules, {})
    except evidence.EvidenceError:
        return True
    return False


@pytest.mark.parametrize("path", sorted(evidence.TOOL_NUMBER_PATHS))
def test_a_number_the_tool_writes_is_not_looked_at_at_its_path_only(path):
    event = {"seq": 1, "type": "x"}

    assert not refuses_4567(event | put_at(path, 4567))
    # Never the same name elsewhere: in a list, one level deeper, or as a key of the content.
    assert refuses_4567(event | {"x": [put_at(path, 4567)]})
    assert refuses_4567(event | {"payload": {"data": put_at(path, 4567)}})
    assert refuses_4567(event | {"x": put_at(path, 4567)})


def test_the_traffic_fields_hold_a_number_and_the_envelope_does_not():
    assert not refuses_4567(TOOL_EVENT)
    for field, value in (
        ("payload", {"data": {"n": [1, 24567]}}),
        ("arguments", {"customer": 4567.5}),
        ("headers", {"content-length": 14567}),
        ("parse", {"id": 4567}),
        ("message_id", 4567),
        ("steps", [{"changes": [{"before": 4567}]}]),
    ):
        assert refuses_4567({**TOOL_EVENT, field: value}), field
    for field in ("payload", "arguments", "target", "reason"):
        assert refuses_4567({**TOOL_EVENT, field: "x4567"}), field


@pytest.mark.parametrize(
    ("event", "where"),
    [
        ({"type": "era_decided", "refusal": {"code": 1, "data": {"a": [{"b": 4567}]}}}, "data"),
        ({"type": "era_decided", "probe": {"outcome": "x", "code": 4567}}, "probe.code"),
        ({"type": "era_decided", "exchanges": [["initialize", "error", 4567]]}, "exchanges"),
        ({"type": "call_failed", "kind": "rpc_error", "code": 4567}, "call_failed.code"),
        ({"type": "http_response", "exchange": 1, "status": 4567}, "status"),
        ({"type": "era_decided", "refusal": {"data": {"seq": 4567}}}, "seq in data"),
        ({"type": "message", "payload": {"data": {"redaction_count": 4567}}}, "in the content"),
        ({"type": "server_exited", "exit_code": 4567, "signal": None}, "exit_code"),
    ],
)
def test_a_number_the_server_or_the_script_can_supply_refuses(event, where):
    event = {"v": 1, "seq": 7, "t_ns": 94567, **event}

    assert refuses_4567(event), where
    assert not refuses_4567(json.loads(json.dumps(event).replace("4567", "4568")))


def test_a_status_is_matched_by_its_text():
    rules = SimpleNamespace(patterns=(("mask_patterns[0]", "41"),))
    event = {"seq": 7, "type": "http_response", "exchange": 1}

    evidence._still_in_event("events.jsonl", b"", {**event, "status": 200}, rules, {})
    with pytest.raises(evidence.EvidenceError, match=r"mask_patterns\[0\]"):
        evidence._still_in_event("events.jsonl", b"", {**event, "status": 412}, rules, {})


def test_a_value_a_mask_key_blanks_that_stands_elsewhere_as_a_number_refuses():
    rules = SimpleNamespace(patterns=())
    blanked = {"1234567890": "mask_key:customer_id"}
    tool = {"seq": 7, "t_ns": 1234567890, "type": "message"}

    evidence._still_in_event("events.jsonl", b"", tool, rules, blanked)
    with pytest.raises(evidence.EvidenceError, match="a value mask_key:customer_id blanks") as c:
        evidence._still_in_event(
            "events.jsonl", b"", {**tool, "arguments": {"customer": 1234567890}}, rules, blanked
        )
    assert "1234567890" not in str(c.value)


# -- a known value in the name of an entry or a scenario ----------------------------------------


KNOWN_NAME = "Zorn"


def named_run(
    tmp_path: Path,
    *,
    entry: str = "reference-server",
    scenario: str | None = None,
    work: str = "work",
    inputs: Path | None = None,
    known: str = KNOWN_NAME,
):
    """A corpus run under a file that knows ``known``, with the manifest's entry named ``entry``
    and, where given, the scenario's own ``name`` ``scenario``; the manifest lies in ``work``
    under ``tmp_path``, the file in ``inputs`` (by default beside it)."""
    held = second_file(
        (tmp_path if inputs is None else inputs) / "engagement", known_values=[known]
    )
    import test_evidence_redact as redaction

    manifest = redaction.copy_corpus(tmp_path / work)
    manifest.write_text(manifest.read_text().replace("name: reference-server", f"name: {entry}", 1))
    if scenario is not None:
        # The manifest's entry runs its own copy of the scenario; the file lists it by digest
        # and holds the same bytes beside itself.
        listed = manifest.parent.parent / "scenarios" / "all-signals.yaml"
        listed.write_text(listed.read_text().replace("name: all-signals", f"name: {scenario}", 1))
        (held.parent / "all-signals.yaml").write_bytes(listed.read_bytes())
        data = json.loads(held.read_text())
        digest = sha256(listed.read_bytes()).hexdigest()
        data["scenarios"] = [{"path": "all-signals.yaml", "sha256": digest}]
        held.write_text(json.dumps(data))
    runs = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(runs), "--manifest",
         str(manifest), "--entry", entry, "--isolation", "host"]
    )  # fmt: skip
    return code, runs


@pytest.mark.parametrize(
    ("kwargs", "field"),
    [
        ({"entry": f"{KNOWN_NAME}-crm"}, "server_name"),
        ({"scenario": f"{KNOWN_NAME}-scan"}, "scenario_name"),
    ],
)
def test_a_name_holding_a_known_value_is_refused_before_the_run_starts(
    tmp_path, salt, capsys, nothing_starts, kwargs, field
):
    code, runs = named_run(tmp_path, **kwargs)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert field in record.message and KNOWN_NAME not in record.message
    assert KNOWN_NAME not in capsys.readouterr().err
    assert KNOWN_NAME not in (runs / engagement.REFUSALS_FILE).read_text()
    assert recordings_in(runs) == [] and [p for p in runs.iterdir() if p.is_dir()] == []


def test_a_manifest_path_holding_a_known_value_is_refused_before_the_run_starts(
    tmp_path, tmp_path_factory, salt, capsys, nothing_starts
):
    inputs = tmp_path_factory.mktemp("inputs")
    work = f"{KNOWN_NAME}-manifests"

    code, runs = named_run(tmp_path, work=work, inputs=inputs)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert "--manifest" in record.message
    said = capsys.readouterr()
    assert recordings_in(runs) == [] and [p for p in runs.iterdir() if p.is_dir()] == []
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err, apart=tmp_path / work) == []


def test_a_manifest_path_holding_a_literal_of_the_run_is_refused_before_the_run_starts(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch, nothing_starts
):
    monkeypatch.setattr(
        cli, "read_credentials", lambda args, held: (Token(KNOWN_NAME, source="file"), ())
    )
    inputs = tmp_path_factory.mktemp("inputs")
    work = f"{KNOWN_NAME}-manifests"

    code, runs = named_run(tmp_path, work=work, inputs=inputs, known="Other")

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value" and "--manifest" in record.message
    said = capsys.readouterr()
    assert recordings_in(runs) == []
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err, apart=tmp_path / work) == []


def test_a_manifest_path_without_a_known_value_runs_as_before(
    tmp_path, tmp_path_factory, salt, capsys
):
    inputs = tmp_path_factory.mktemp("inputs")

    code, runs = named_run(tmp_path, inputs=inputs)

    assert code == 0
    said = capsys.readouterr()
    assert not (runs / engagement.REFUSALS_FILE).exists()
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err, apart=tmp_path / "work") == []


def test_names_without_a_known_value_run_as_before(tmp_path, salt):
    code, runs = named_run(tmp_path, entry="reference-server", scenario="all-signals-2")

    assert code == 0
    (recording,) = recordings_in(runs)
    start = events_of(recording)[0]
    assert start["server_name"] == "reference-server" and start["scenario_name"] == "all-signals-2"
    assert not (runs / engagement.REFUSALS_FILE).exists()


def test_a_name_with_the_value_is_no_matter_without_an_engagement(tmp_path):
    import test_evidence_redact as redaction

    manifest = redaction.copy_corpus(tmp_path / "work")
    manifest.write_text(manifest.read_text().replace("name: reference-server", "name: Zorn-crm"))
    code = cli.main(
        ["drive", "-q", "--out-dir", str(tmp_path / "runs"), "--manifest", str(manifest),
         "--entry", "Zorn-crm", "--isolation", "host"]
    )  # fmt: skip

    assert code == 0


# -- a known value in the path of the scenario ---------------------------------------------------


def corpus_at(tmp_path: Path, home: str) -> Path:
    """The corpus fixtures under ``tmp_path/home``; the manifest's path."""
    import test_evidence_redact as redaction

    return redaction.copy_corpus(tmp_path / home)


@pytest.fixture
def inputs(tmp_path_factory) -> Path:
    """Where the engagement file lies: outside ``tmp_path``, where the outputs are searched."""
    return tmp_path_factory.mktemp("inputs")


def path_run(tmp_path: Path, inputs: Path, *argv: str, known: str = KNOWN_NAME):
    """``drive`` of the reference entry under a file that knows ``known``, with ``argv`` for
    where the manifest is."""
    held = second_file(inputs / "engagement", known_values=[known])
    runs = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(runs), "--entry",
         "reference-server", "--isolation", "host", *argv]
    )  # fmt: skip
    return code, runs


def refused_for_a_path(code, runs, tmp_path, capsys, home, field="the scenario path"):
    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value" and field in record.message
    said = capsys.readouterr()
    assert recordings_in(runs) == [] and [p for p in runs.iterdir() if p.is_dir()] == []
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err, apart=tmp_path / home) == []


def test_a_scenario_path_resolved_from_the_working_directory_is_refused(
    tmp_path, inputs, salt, capsys, monkeypatch, nothing_starts
):
    home = f"{KNOWN_NAME}-akten"
    manifest = corpus_at(tmp_path, home)
    monkeypatch.chdir(tmp_path / home)

    code, runs = path_run(
        tmp_path, inputs, "--manifest", str(manifest.relative_to(tmp_path / home))
    )

    refused_for_a_path(code, runs, tmp_path, capsys, home)


def test_a_scenario_path_behind_a_symlink_is_refused(
    tmp_path, inputs, salt, capsys, monkeypatch, nothing_starts
):
    home = f"{KNOWN_NAME}-akten"
    manifest = corpus_at(tmp_path, home)
    (tmp_path / "neutral").mkdir()
    (tmp_path / "neutral" / "link").symlink_to(tmp_path / home)
    monkeypatch.chdir(tmp_path / "neutral")

    code, runs = path_run(
        tmp_path, inputs, "--manifest", str(Path("link") / manifest.relative_to(tmp_path / home))
    )

    refused_for_a_path(code, runs, tmp_path, capsys, home)


def test_the_scenario_path_of_an_ordinary_run_is_refused(
    tmp_path, inputs, salt, capsys, nothing_starts
):
    home = f"{KNOWN_NAME}-akten"
    held = second_file(inputs / "engagement", known_values=[KNOWN_NAME])
    (tmp_path / home).mkdir()
    scenario = tmp_path / home / "all-signals.yaml"
    shutil.copyfile(SCENARIO, scenario)
    runs = tmp_path / "runs"

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--scenario", str(scenario), "--out-dir",
         str(runs), "--", sys.executable, DISCOVERY]
    )  # fmt: skip

    refused_for_a_path(code, runs, tmp_path, capsys, home)


def test_a_literal_of_the_run_in_the_scenario_path_is_refused(
    tmp_path, inputs, salt, capsys, monkeypatch, nothing_starts
):
    monkeypatch.setattr(
        cli, "read_credentials", lambda args, held: (Token(KNOWN_NAME, source="file"), ())
    )
    home = f"{KNOWN_NAME}-akten"
    manifest = corpus_at(tmp_path, home)
    monkeypatch.chdir(tmp_path / home)

    code, runs = path_run(
        tmp_path, inputs, "--manifest", str(manifest.relative_to(tmp_path / home)), known="Other"
    )

    refused_for_a_path(code, runs, tmp_path, capsys, home, field="the scenario path")


def test_a_scenario_path_without_a_known_value_runs_as_before(
    tmp_path, inputs, salt, capsys, monkeypatch
):
    manifest = corpus_at(tmp_path, "akten")
    monkeypatch.chdir(tmp_path / "akten")

    code, runs = path_run(
        tmp_path, inputs, "--manifest", str(manifest.relative_to(tmp_path / "akten"))
    )

    assert code == 0
    assert not (runs / engagement.REFUSALS_FILE).exists()
    said = capsys.readouterr()
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err) == []


def test_a_fleet_run_from_a_directory_holding_a_known_value_refuses_the_entry_s_run(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch
):
    from mcp_kymograph import fleet
    from test_fleet import PINS

    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(
        inputs / "engagement",
        known_values=[KNOWN_NAME],
        targets=[{"host": "127.0.0.1", "isolation": "runc"}],
    )
    home = tmp_path / f"{KNOWN_NAME}-akten"
    manifest = fleet_manifest(inputs, directory=home / "manifests")
    monkeypatch.setattr(fleet, "pin", lambda *args, **kwargs: PINS)
    monkeypatch.chdir(home)
    runs = tmp_path / "runs"

    cli.main(
        ["fleet", "run", "--engagement", str(held), "--manifest",
         str(manifest.relative_to(home)), "--store", str(tmp_path / "store.sqlite"),
         "--out-dir", str(runs)]
    )  # fmt: skip

    said = capsys.readouterr()
    (entry_runs,) = runs.glob("*/000-*")
    (record,) = refusals_in(entry_runs)
    assert record.reason == "name_holds_known_value" and "the scenario path" in record.message
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err, apart=home) == []


def test_a_run_the_engagement_does_not_cover_is_refused_for_the_path_before_anything_is_asked(
    tmp_path, inputs, salt, capsys, monkeypatch, nothing_starts
):
    def asked(*args, **kwargs):
        raise AssertionError("docker was asked for a run that is refused")

    monkeypatch.setattr(cli, "pin_images", asked)
    home = f"{KNOWN_NAME}-akten"
    manifest = corpus_at(tmp_path, home)
    monkeypatch.chdir(tmp_path / home)

    # Not covered: a target the file does not list and the flag does not confirm.
    code, runs = path_run(
        tmp_path, inputs, "--manifest", str(manifest.relative_to(tmp_path / home)),
        "--target", "198.51.100.7", "--isolation", "runc",
    )  # fmt: skip

    refused_for_a_path(code, runs, tmp_path, capsys, home)


# -- a refusal leaves nothing behind -------------------------------------------------------------


@pytest.fixture
def staged(monkeypatch, tmp_path):
    """A ``stage()`` that makes a directory, as the sandbox's copy of the entry's files is one;
    the directory is where the test looks after the run."""
    copy = tmp_path / "staged-copy"

    def stage(*args, **kwargs):
        copy.mkdir()
        return SimpleNamespace(
            command=[sys.executable, DISCOVERY], cleanup=lambda: shutil.rmtree(copy)
        )

    images = {"sandbox_image": ("s", None), "target_image": ("t", None)}
    monkeypatch.setattr(cli, "pin_images", lambda *a: images)
    monkeypatch.setattr(cli, "stage", stage)
    monkeypatch.setattr(cli, "Sandbox", lambda delivery, **kw: SimpleNamespace(delivery=delivery))
    return copy


def staged_run(tmp_path: Path, *, entry: str, known: str):
    held = second_file(
        tmp_path / "engagement",
        known_values=[known],
        targets=[{"host": "127.0.0.1", "isolation": "runc"}],
    )
    import test_evidence_redact as redaction

    manifest = redaction.copy_corpus(tmp_path / "work")
    manifest.write_text(manifest.read_text().replace("name: reference-server", f"name: {entry}", 1))
    runs = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(runs), "--manifest",
         str(manifest), "--entry", entry, "--isolation", "runc"]
    )  # fmt: skip
    return code, runs


def test_a_name_holding_a_literal_of_the_run_leaves_no_copy_of_the_entry(
    tmp_path, salt, staged, monkeypatch, nothing_starts
):
    monkeypatch.setattr(
        cli, "read_credentials", lambda args, held: (Token(KNOWN_NAME, source="file"), ())
    )

    code, runs = staged_run(tmp_path, entry=f"{KNOWN_NAME}-crm", known="Other")

    assert code == 2 and refusals_in(runs)[0].reason == "name_holds_known_value"
    assert not staged.exists(), "the copy was made and removed"


def test_a_name_holding_a_known_value_is_refused_before_the_copy_is_made(
    tmp_path, salt, staged, nothing_starts
):
    code, runs = staged_run(tmp_path, entry=f"{KNOWN_NAME}-crm", known=KNOWN_NAME)

    assert code == 2 and refusals_in(runs)[0].reason == "name_holds_known_value"
    assert not staged.exists(), "the copy was never made"


def test_a_refused_token_leaves_no_copy_of_the_entry(
    tmp_path, salt, staged, monkeypatch, nothing_starts
):
    def unreadable(args, held):
        raise CredentialError("the token cannot be read")

    monkeypatch.setattr(cli, "read_credentials", unreadable)

    code, runs = staged_run(tmp_path, entry="reference-server", known="Other")

    assert code == 2 and refusals_in(runs)[0].reason == "token"
    assert not staged.exists()


# -- the scenario's name before the gate, and the name the triple records ------------------------


def test_a_corpus_run_the_engagement_does_not_cover_is_refused_for_the_scenario_s_name(
    tmp_path, inputs, salt, capsys, monkeypatch, nothing_starts
):
    def asked(*args, **kwargs):
        raise AssertionError("docker was asked for a run that is refused")

    monkeypatch.setattr(cli, "pin_images", asked)
    manifest = corpus_at(tmp_path, "work")
    listed = manifest.parent.parent / "scenarios" / "all-signals.yaml"
    listed.write_text(listed.read_text().replace("name: all-signals", f"name: {KNOWN_NAME}-check"))

    # Not covered: a target the file does not list and the flag does not confirm.
    code, runs = path_run(
        tmp_path, inputs, "--manifest", str(manifest), "--target", "198.51.100.7",
        "--isolation", "runc",
    )  # fmt: skip

    refused_for_a_path(code, runs, tmp_path, capsys, "work", field="scenario_name")


def twin_run(tmp_path: Path, inputs: Path, first: str, *, known: str = KNOWN_NAME):
    """A corpus run of ``--scenario smoke`` for an entry that lists two files of the same bytes,
    ``first`` and ``smoke``, neither with a ``name`` of its own: the stem is the name. The
    triple finds the name by the digest, and so records ``first``'s."""
    manifest = corpus_at(tmp_path, "work")
    scenarios = manifest.parent.parent / "scenarios"
    plain = (scenarios / "all-signals.yaml").read_text().replace("name: all-signals\n", "")
    for stem in (first, "smoke"):
        (scenarios / f"{stem}.yaml").write_text(plain)
    manifest.write_text(
        manifest.read_text().replace(
            "scenarios: [../scenarios/all-signals.yaml]",
            f"scenarios: [../scenarios/{first}.yaml, ../scenarios/smoke.yaml]",
            1,
        )
    )
    held = second_file(inputs / "engagement", known_values=[known])
    data = json.loads(held.read_text())
    data["scenarios"] = [{"path": "smoke.yaml", "sha256": sha256(plain.encode()).hexdigest()}]
    (held.parent / "smoke.yaml").write_text(plain)
    held.write_text(json.dumps(data))
    runs = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(runs), "--manifest",
         str(manifest), "--entry", "reference-server", "--scenario", "smoke",
         "--isolation", "host"]
    )  # fmt: skip
    return code, runs


def test_the_name_the_triple_records_for_the_scenario_is_checked_too(
    tmp_path, inputs, salt, capsys, nothing_starts
):
    code, runs = twin_run(tmp_path, inputs, f"{KNOWN_NAME}-check")

    refused_for_a_path(code, runs, tmp_path, capsys, "work", field="the scenario's name")


def test_two_files_of_one_digest_run_when_neither_name_holds_a_known_value(
    tmp_path, inputs, salt, capsys
):
    code, runs = twin_run(tmp_path, inputs, "other-check")

    assert code == 0
    (recording,) = recordings_in(runs)
    assert events_of(recording)[0]["reproduction"]["scenario"]["name"] == "other-check"
    assert not (runs / engagement.REFUSALS_FILE).exists()
    said = capsys.readouterr()
    assert holding(KNOWN_NAME, tmp_path, said.out + said.err) == []


# -- a known value in any percent-encoding -------------------------------------------------------

MUELLER = "Müller"
MUELLER_GMBH = "Müller GmbH"
#: A value and a form of it: the hex digits in either case or mixed, a character kept as itself
#: beside one that is escaped, the space as %20.
ENCODED = [
    (MUELLER, "M%c3%bcller"),
    (MUELLER, "M%C3%BCller"),
    (MUELLER, "M%c3%BCller"),
    (MUELLER, "%4dü%6cler"),
    (MUELLER_GMBH, "Müller%20GmbH"),
    (MUELLER_GMBH, "M%C3%BCller GmbH"),
    (MUELLER_GMBH, "M%c3%bcller%20GmbH"),
]
#: What of the value must not be left standing, whole or in part.
PARTS = ("ller", "GmbH", "%c3", "%C3", "%20")


@pytest.mark.parametrize(("value", "form"), ENCODED)
def test_a_known_value_in_any_percent_encoding_is_the_pseudonym_of_the_value(value, form):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[value])
    stand_in = masker.personal_pseudonym("known", value)

    assert masker.mask_text(form)[0] == masker.mask_text(value)[0] == stand_in
    text = json.dumps({"a": [f"x {form} y"], "b": f"/p/{form}?q=1"}, ensure_ascii=False)
    result = masker.mask_text(text)[0]
    assert result == text.replace(form, stand_in)
    assert not [part for part in PARTS if part in result]


@pytest.mark.parametrize(("value", "form"), ENCODED)
def test_a_known_value_in_any_percent_encoding_is_replaced_in_server_stderr(value, form):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[value])
    stream = io.StringIO()
    rec = Recorder(stream, run_id="r", masker=masker)
    rec.server_stderr(1, 0, raw=f"fatal: no user {form}\n".encode())

    text = stream.getvalue()
    assert masker.personal_pseudonym("known", value) in text
    assert not [part for part in PARTS if part in text]


def test_a_known_value_with_a_percent_is_found_as_written_and_as_encoded():
    value = "100%sicher"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[value])
    stand_in = masker.personal_pseudonym("known", value)

    assert masker.mask_text(value)[0] == stand_in
    assert masker.mask_text("100%25sicher")[0] == stand_in
    assert masker.mask_text(f"a {value}, b 100%25%73icher")[0] == f"a {stand_in}, b {stand_in}"
    assert masker.replacements["known"] == 4


@pytest.mark.parametrize(
    "form",
    [str, partial(quote, safe=""), lambda text: text.replace("ü", "%c3%BC")],
    ids=["written", "quoted", "mixed"],
)
def test_of_two_known_values_one_in_the_other_the_longer_wins_in_every_form(form):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER, MUELLER_GMBH])

    result = masker.mask_text(f"{form(MUELLER_GMBH)} and {form(MUELLER)}")[0]

    assert result == (
        masker.personal_pseudonym("known", MUELLER_GMBH)
        + " and "
        + masker.personal_pseudonym("known", MUELLER)
    )
    assert masker.replacements["known"] == 2


def test_holds_known_value_finds_every_percent_encoding():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER])

    for form in ("M%c3%bcller", "M%C3%BCller", "x/M%c3%BCller/y", MUELLER):
        assert masker.holds_known_value(form), form
    assert not masker.holds_known_value("M%c3%bcler")


def test_a_manifest_path_with_an_encoded_known_value_is_refused_before_the_run_starts(
    tmp_path, tmp_path_factory, salt, nothing_starts
):
    inputs = tmp_path_factory.mktemp("inputs")

    code, runs = named_run(tmp_path, work="M%c3%bcller-manifests", inputs=inputs, known=MUELLER)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value" and "--manifest" in record.message
    assert recordings_in(runs) == []


def test_a_number_that_is_a_known_value_is_its_pseudonym_and_one_with_a_literal_the_placeholder():
    masker = Masker(handle_salt=HANDLE_SALT, literals=["77"], known_values=["123456789", "5577"])

    document, paths = masker.mask_json({"id": 123456789, "text": "123456789", "token": 5577})

    stand_in = masker.personal_pseudonym("known", "123456789")
    assert document == {"id": stand_in, "text": stand_in, "token": PLACEHOLDER}
    assert paths == ["token"]
    assert masker.replacements["known"] == 2


# -- finding the known values fast, as written and decoded ----------------------------------------

DECODED_VIEWS = {
    "plain text": "no percent here",
    "empty": "",
    "one run": "a%41b",
    "several runs": "%41x%42yy%43",
    "a run of several": "%41%42%43",
    "mixed with text": "id=%4b%75nde&x=1",
    "multi-byte characters": "caf%C3%A9 %e2%82%ac!",
    "multi-byte plain text": "é%41ü",
    "an invalid byte": "x%ffy",
    "an invalid byte beside a valid one": "%c3%28%ff",
    "a percent without hex": "100%sicher",
    "a percent and one hex digit": "50%4",
    "a percent and no hex": "%zz",
    "a cut-off sequence": "ab%c3",
    "a percent at the end": "ab%",
}


@pytest.mark.parametrize("text", DECODED_VIEWS.values(), ids=DECODED_VIEWS)
def test_the_decoded_view_says_where_each_character_stands_in_the_original(text):
    decoded, starts = masking._decoded_view(text)

    assert len(starts) == len(decoded) + 1
    assert starts[-1] == len(text)
    assert all(a < b for a, b in zip(starts, starts[1:], strict=False))
    for index, char in enumerate(decoded):
        written = text[starts[index] : starts[index + 1]]
        escaped = "".join("%" + format(b, "02x") for b in char.encode("utf-8", "surrogateescape"))
        assert written == char or written.lower() == escaped, (index, char, written)


def test_the_decoded_view_decodes_what_it_should():
    assert masking._decoded_view("plain")[0] == "plain"
    assert masking._decoded_view("caf%C3%A9 %e2%82%ac")[0] == "café €"
    assert masking._decoded_view("100%sicher %zz %c3")[0] == "100%sicher %zz \udcc3"
    assert masking._decoded_view("x%ffy")[0] == "x\udcffy"


def test_a_value_written_and_encoded_in_one_text_is_replaced_each_time_and_counted():
    first, second = known(), known() + " & Co"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[first, second])
    one, two = (masker.personal_pseudonym("known", v) for v in (first, second))
    encoded_first, encoded_second = (
        quote(first, safe=""),
        re.sub("%[0-9A-F]{2}", lambda m: m.group().lower(), quote(second, safe="")),
    )
    text = f"a {first} b {encoded_first} c-{encoded_second}-d %41 e"

    result = masker.mask_text(text)[0]

    assert result == f"a {one} b {one} c-{two}-d %41 e"
    assert masker.replacements["known"] == 3


def test_an_encoded_value_beside_multi_byte_text_and_other_escapes_leaves_the_rest_alone():
    secret = known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])
    found = masker.personal_pseudonym("known", secret)
    encoded = quote(secret, safe="")

    result = masker.mask_text(f"é€{encoded}ü%41{encoded}%C3%A9%ff%zz{encoded}x")[0]

    assert result == f"é€{found}ü%41{found}%C3%A9%ff%zz{found}x"
    assert masker.replacements["known"] == 3


def test_a_value_holding_an_escape_is_found_as_written_and_with_the_percent_encoded():
    secret = "a%41" + secrets.token_hex(3)
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])
    found = masker.personal_pseudonym("known", secret)

    assert masker.mask_text(secret)[0] == found
    assert masker.mask_text(secret.replace("%", "%25"))[0] == found
    assert masker.holds_known_value(secret.replace("%", "%25"))
    assert not masker.holds_known_value("%61%41" + secret[4:])


def test_holds_known_value_looks_at_the_decoded_text_too():
    secret = known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])

    assert masker.holds_known_value("x " + secret)
    assert masker.holds_known_value("x " + quote(secret, safe=""))
    assert not masker.holds_known_value("x " + quote(secret[:-1], safe=""))
    assert masker._is_value(quote(secret, safe=""))
    assert masker.replacements["known"] == 0


def _clocked(masker: Masker, text: str) -> float:
    start = time.perf_counter()
    masker.mask_text(text)
    return time.perf_counter() - start


def test_many_known_values_are_found_in_a_second_in_a_short_text():
    values = [f"{n:06d}-" + secrets.token_hex(3) for n in range(10_000)]
    masker = Masker(handle_salt=HANDLE_SALT, known_values=values)
    plain = ("lorem ipsum %41 dolor " * 50)[:1000]
    encoded = plain + quote(values[5000], safe="")

    with_percent, without = _clocked(masker, encoded), _clocked(masker, plain.replace("%", ""))

    print(f"10000 values, 1000 characters: {with_percent:.4f} s, without %: {without:.4f} s")
    assert with_percent < 1
    assert masker.replacements["known"] == 1


def test_a_megabyte_of_text_is_masked_in_five_seconds_with_escapes_in_it():
    values = [secrets.token_hex(16) for _ in range(100)]
    masker = Masker(handle_salt=HANDLE_SALT, known_values=values)
    text = (("x" * 97 + "%41") * (2**20 // 100))[: 2**20]
    without = text.replace("%41", "xxx")

    with_percent, plain = _clocked(masker, text), _clocked(masker, without)

    print(f"100 values, 1 MiB: {with_percent:.4f} s, without %: {plain:.4f} s")
    assert with_percent < 5


# -- the longer known value wins in every form, and a span is counted once ------------------------


@pytest.mark.parametrize("order", [1, -1], ids=["longest last", "longest first"])
@pytest.mark.parametrize(
    "text",
    [
        "Müller%20GmbH",
        "Müller%20%47mbH",
        "M%C3%BCller GmbH",
        "M%c3%bcller%20GmbH",
    ],
)
def test_the_longer_known_value_wins_when_only_the_decoded_text_shows_it_whole(text, order):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER, MUELLER_GMBH][::order])

    assert masker.mask_text(text)[0] == masker.personal_pseudonym("known", MUELLER_GMBH)
    assert masker.replacements["known"] == 1


def test_the_shorter_known_value_alone_is_its_own_pseudonym():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER, MUELLER_GMBH])

    assert masker.mask_text("M%C3%BCller")[0] == masker.personal_pseudonym("known", MUELLER)
    assert masker.replacements["known"] == 1


def test_a_value_both_views_find_in_one_place_is_counted_once():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER])
    found = masker.personal_pseudonym("known", MUELLER)

    assert masker.mask_text(f"{MUELLER} und {MUELLER}%20x")[0] == f"{found} und {found}%20x"
    assert masker.replacements["known"] == 2


def test_a_known_value_with_a_percent_beats_a_shorter_one_it_holds():
    longer = f"{MUELLER}%20GmbH"
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER, longer])

    assert masker.mask_text(longer)[0] == masker.personal_pseudonym("known", longer)
    assert masker.replacements["known"] == 1


def test_the_text_between_the_known_values_stays_when_there_is_a_percent():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER])
    found = masker.personal_pseudonym("known", MUELLER)

    result = masker.mask_text(f"a %20 {MUELLER} b %41 M%C3%BCller c")[0]

    assert result == f"a %20 {found} b %41 {found} c"
    assert masker.replacements["known"] == 2


def test_known_values_are_found_in_time_with_escapes_in_the_text_as_well():
    values = [f"{n:06d}-" + secrets.token_hex(3) for n in range(10_000)]
    masker = Masker(handle_salt=HANDLE_SALT, known_values=values)
    short = ("lorem ipsum %41 %20 dolor " * 50)[:1000] + quote(values[5000], safe="")
    big = Masker(handle_salt=HANDLE_SALT, known_values=[secrets.token_hex(16) for _ in range(100)])
    megabyte = (("x" * 97 + "%41") * (2**20 // 100))[: 2**20]

    short_time, big_time = _clocked(masker, short), _clocked(big, megabyte)

    print(f"10000 values, 1000 characters: {short_time:.4f} s; 100 values, 1 MiB: {big_time:.4f} s")
    assert short_time < 1 and big_time < 5
    assert masker.replacements["known"] == 1


# -- a value in an id, a method or a code is counted where the message wrote it -------------------

KNOWN_NUMBER = 424242


def message_events(stream: io.StringIO) -> list[dict]:
    return [e for e in written(stream) if e["type"] == "message"]


def one_message(masker: Masker, document: dict) -> tuple[Recorder, io.StringIO]:
    stream = io.StringIO()
    rec = Recorder(stream, run_id="r", masker=masker)
    rec.run_started(0, 0, argv=["server"], limits={})
    rec.message(1, 0, direction=Direction.SERVER_TO_CLIENT, raw=json.dumps(document).encode())
    return rec, stream


def test_an_address_in_an_id_is_counted_once_and_masked_in_the_event():
    mail = address()
    masker = Masker(handle_salt=HANDLE_SALT)

    _, stream = one_message(masker, {"jsonrpc": "2.0", "id": mail, "result": {}})

    (event,) = message_events(stream)
    assert masker.replacements["email"] == 1
    assert event["parse"]["id"] == masker.mask_text(mail)[0]
    assert mail not in stream.getvalue()


def test_a_number_that_is_a_known_value_as_an_id_is_counted_once():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[str(KNOWN_NUMBER)])

    _, stream = one_message(masker, {"jsonrpc": "2.0", "id": KNOWN_NUMBER, "result": {}})

    (event,) = message_events(stream)
    assert masker.replacements["known"] == 1
    assert event["parse"]["id"] == masker.personal_pseudonym("known", str(KNOWN_NUMBER))


def test_a_known_value_as_a_method_is_counted_once():
    secret = known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])

    _, stream = one_message(masker, {"jsonrpc": "2.0", "id": 1, "method": secret})

    (event,) = message_events(stream)
    assert masker.replacements["known"] == 1
    assert event["parse"]["method"] == masker.personal_pseudonym("known", secret)


def test_an_error_code_that_is_a_known_value_is_counted_in_the_payload_only():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[str(KNOWN_NUMBER)])
    document = {"jsonrpc": "2.0", "id": 1, "error": {"code": KNOWN_NUMBER, "message": "x"}}

    rec, stream = one_message(masker, document)
    rec.call_failed(
        2, 0, step="tools/call", tool="t", kind=events.CALL_RPC_ERROR, code=KNOWN_NUMBER
    )

    (failed,) = [e for e in written(stream) if e["type"] == "call_failed"]
    assert masker.replacements["known"] == 1
    assert failed["code"] is None


def test_events_that_name_a_recorded_message_leave_the_count_as_it_was():
    secret = known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])
    rec, _ = one_message(masker, {"jsonrpc": "2.0", "id": secret, "method": secret})
    after_message = masker.replacements["known"]

    rec.finding(
        2, 0, key={"locator": secret}, direction=Direction.SERVER_TO_CLIENT, method=secret,
        message_id=secret, message_seq=1, path=f"result.{secret}",
    )  # fmt: skip
    rec.findings_capped(
        3, 0, method=secret, message_id=secret, message_seq=1, cap=1, made=2, recorded=1, cut={}
    )
    rec.statement_evaluated(
        4, 0, statement="s", method=secret, message_id=secret, message_seq=1,
        checked=1, not_strings=0, fired={},
    )  # fmt: skip
    rec.rule_quarantined(
        5, 0, rule="r", reason="raised", detail="ValueError",
        direction=Direction.SERVER_TO_CLIENT, message_id=secret, invalidated_hits=0,
    )  # fmt: skip
    rec.masked_counts({secret: 1})

    # The payload holds the id and the method: two. Nothing else adds to them.
    assert after_message == 2
    assert masker.replacements["known"] == after_message


def test_a_server_name_with_an_address_is_counted_in_the_initialize_reply_only():
    mail = address()
    masker = Masker(handle_salt=HANDLE_SALT)
    reply = {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": mail, "version": "1"}}}
    rec, stream = one_message(masker, reply)

    rec.server_name_mismatch(2, 0, declared="other", announced=mail, message_seq=1)
    rec.run_finished(
        3, 0, reason="eof", duration_ns=1, announced_server=mail,
        server_output_bytes=0, client_input_bytes=0, server_exited_first=True,
    )  # fmt: skip

    (mismatch,) = [e for e in written(stream) if e["type"] == "server_name_mismatch"]
    (finished,) = [e for e in written(stream) if e["type"] == "run_finished"]
    assert masker.replacements["email"] == 1
    assert mismatch["announced"] == masker.mask_text(mail)[0]
    assert finished["announced_server"] == masker.mask_text(mail)[0]
    assert mail not in stream.getvalue()


def test_an_address_in_the_data_of_a_refusal_is_counted_in_the_error_reply_only():
    mail = address()
    masker = Masker(handle_salt=HANDLE_SALT)
    reply = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32602, "message": "no", "data": {"who": mail}},
    }
    rec, stream = one_message(masker, reply)

    rec.era_decided(
        2, 0, era=None, version=None, outcome="stop",
        refusal={"code": -32602, "data": {"who": mail}},
    )  # fmt: skip

    (decided,) = [e for e in written(stream) if e["type"] == "era_decided"]
    assert masker.replacements["email"] == 1
    assert decided["refusal"]["data"] == {"who": masker.mask_text(mail)[0]}
    assert mail not in stream.getvalue()


def test_a_protocol_version_that_is_a_known_value_is_counted_in_the_reply_only():
    secret = known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[secret])
    reply = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": secret}}
    rec, stream = one_message(masker, reply)

    rec.era_decided(2, 0, era=None, version=secret, outcome="stop")

    (decided,) = [e for e in written(stream) if e["type"] == "era_decided"]
    pseudonym = masker.personal_pseudonym("known", secret)
    assert masker.replacements["known"] == 1
    assert decided["version"] == pseudonym[: eras.MAX_VERSION_LENGTH]
    assert secret not in stream.getvalue()


def test_an_intervention_counts_the_value_of_the_payload_and_not_the_one_a_rule_wrote():
    held, by_rule = known(), known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[held, by_rule])
    document = {"jsonrpc": "2.0", "id": 1, "result": {"text": held}}
    rec, stream = one_message(masker, document)
    replacement = {"jsonrpc": "2.0", "id": 1, "result": {"text": by_rule}}
    step = SimpleNamespace(
        rule="r",
        action="replace",
        reason=None,
        changes=[SimpleNamespace(path="result.text", before=held, after=by_rule)],
        skipped=[],
    )

    rec.intervention(
        2, 0, action="replace", direction=Direction.SERVER_TO_CLIENT, message_id=1,
        original=document, replacement=replacement, steps=[step],
    )  # fmt: skip

    (event,) = [e for e in written(stream) if e["type"] == "intervention"]
    held_pseudonym = masker.personal_pseudonym("known", held)
    rule_pseudonym = masker.personal_pseudonym("known", by_rule)
    assert masker.replacements["known"] == 1
    assert event["original"]["data"]["result"]["text"] == held_pseudonym
    assert event["replacement"]["data"]["result"]["text"] == rule_pseudonym
    (change,) = event["steps"][0]["changes"]
    assert change["before"]["data"] == held_pseudonym
    assert change["after"]["data"] == rule_pseudonym
    assert held not in stream.getvalue() and by_rule not in stream.getvalue()


# -- a value in JSON escapes (\uXXXX), and an address cut by an encoding ---------------------------


def escaped(text: str) -> str:
    """``text`` as ``json.dumps`` writes it with ``ensure_ascii``, without the quotes."""
    return json.dumps(text)[1:-1]


def test_the_decoded_view_reads_json_escapes_as_utf16_units():
    view = masking._decoded_view

    assert view(escaped("jürgen Üé"))[0] == "jürgen Üé"
    assert view(escaped("x😀y"))[0] == "x😀y"
    assert view(escaped("\ud800 \udc00 \ud800\U00010000 \ud83d"))[0] == (
        "\ud800 \udc00 \ud800\U00010000 \ud83d"
    )
    short = "\\u12 \\u00g1 \\x00e9"
    assert view(short) == (short, list(range(len(short) + 1)))
    assert view("%C3%BC" + escaped("ü") + "%C3%BC")[0] == "üüü"


def test_a_surrogate_pair_covers_twelve_characters_and_a_lone_one_six():
    text = "a" + escaped("😀") + "b" + escaped("\ud800") + "c"

    decoded, starts = masking._decoded_view(text)

    assert decoded == "a😀b\ud800c"
    assert starts == [0, 1, 13, 14, 20, len(text)]


def test_other_encodings_are_not_read():
    text = "j&uuml;rgen =C3=BC &#252; \\x00fc \\U000000fc"

    assert masking._decoded_view(text) == (text, list(range(len(text) + 1)))


def test_an_address_in_a_json_log_written_with_ensure_ascii_is_replaced_whole():
    masker = Masker(handle_salt=HANDLE_SALT)
    mail = "jürgen.müller@firma.example"
    log = json.dumps({"user": mail})
    assert "\\u00fc" in log

    result = masker.mask_text(log)[0]

    found = masker.personal_pseudonym("email", mail)
    assert result == f'{{"user": "{found}"}}'
    assert not [part for part in ("jü", "rgen", "m\\", "u00f", "ller", "firma") if part in result]
    assert masker.replacements["email"] == 1


@pytest.mark.parametrize(
    "mail", ["rene.müller@x.example", "jürgen.müller@firma.example", "zoë@münchen.example"]
)
@pytest.mark.parametrize(
    "encode", [lambda t: quote(t, safe="@."), escaped], ids=["percent", "json"]
)
def test_an_address_in_an_encoding_is_the_pseudonym_of_the_address(mail, encode):
    masker = Masker(handle_salt=HANDLE_SALT)
    found = masker.personal_pseudonym("email", mail)
    written = encode(mail)
    assert written != mail

    result = masker.mask_text(f"<<{written}>> and ({written}), {mail}.")[0]

    assert result == f"<<{found}>> and ({found}), {found}."
    assert masker.replacements["email"] == 3


@pytest.mark.parametrize(
    "text",
    [
        "user@m%C3%BCller.example",
        "user@m%c3%bcller.example",
        escaped("user@müller.example"),
        "user@müller.example",
        "user@m" + escaped("ü") + "ller.example",
    ],
)
def test_an_address_with_an_encoded_domain_is_replaced_whole(text):
    masker = Masker(handle_salt=HANDLE_SALT)
    found = masker.personal_pseudonym("email", "user@müller.example")

    assert masker.mask_text(f"to {text} now")[0] == f"to {found} now"
    assert masker.replacements["email"] == 1


@pytest.mark.parametrize("sign", ["%40", "\\u0040", "@"])
def test_the_at_sign_itself_may_be_encoded(sign):
    masker = Masker(handle_salt=HANDLE_SALT)
    found = masker.personal_pseudonym("email", "a@b.example")

    assert masker.mask_text(f"mail a{sign}b.example now, a@b.example later")[0] == (
        f"mail {found} now, {found} later"
    )
    assert masker.replacements["email"] == 2


def test_both_encodings_in_one_address_are_one_address():
    masker = Masker(handle_salt=HANDLE_SALT)
    found = masker.personal_pseudonym("email", "jürgen.müller@x.example")

    result = masker.mask_text("{" + escaped("jürgen") + ".m%C3%BCller@x.example}")[0]

    assert result == "{" + found + "}"
    assert masker.replacements["email"] == 1


def test_a_surrogate_pair_and_a_lone_surrogate_in_the_text_raise_nothing_and_stay():
    masker = Masker(handle_salt=HANDLE_SALT)
    mail = address()
    found = masker.personal_pseudonym("email", mail)
    emoji, lone = escaped("😀"), escaped("\ud800")
    assert lone == r"\ud800"

    assert masker.mask_text(f"{emoji} {lone} {mail}")[0] == f"{emoji} {lone} {found}"
    assert masker.mask_text(f"{emoji}, {lone}")[0] == f"{emoji}, {lone}"
    assert masker.mask_text("😀 \ud800 ok")[0] == "😀 \ud800 ok"
    assert (
        masker.mask_text(f"%F0%9F%98%80 %ED%A0%80 {mail}")[0] == f"%F0%9F%98%80 %ED%A0%80 {found}"
    )
    assert masker.replacements["email"] == 2


@pytest.mark.parametrize("encode", [quote, lambda t, safe: escaped(t)], ids=["percent", "json"])
def test_a_known_value_in_an_encoding_is_the_pseudonym_of_the_value(encode):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER_GMBH])
    found = masker.personal_pseudonym("known", MUELLER_GMBH)
    written = encode(MUELLER_GMBH, safe="")

    assert masker.mask_text(f'{{"firm": "{written}"}}')[0] == f'{{"firm": "{found}"}}'
    assert masker.replacements["known"] == 1


@pytest.mark.parametrize("order", [1, -1], ids=["longest last", "longest first"])
@pytest.mark.parametrize(
    "text", [escaped(MUELLER_GMBH), escaped(MUELLER) + "%20GmbH", "M%C3%BCller" + escaped(" GmbH")]
)
def test_the_longer_known_value_wins_in_json_escapes_as_well(text, order):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER, MUELLER_GMBH][::order])

    assert masker.mask_text(text)[0] == masker.personal_pseudonym("known", MUELLER_GMBH)
    assert masker.replacements["known"] == 1


def test_holds_known_value_finds_a_json_escape_and_a_name_in_it_is_a_value():
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER_GMBH])

    assert masker.holds_known_value("x " + escaped(MUELLER_GMBH) + " y")
    assert masker.holds_known_value("x " + escaped(MUELLER) + "%20GmbH y")
    assert not masker.holds_known_value("x " + escaped("Müller GmbX") + " y")
    assert masker._is_value(escaped(MUELLER_GMBH))
    assert masker.replacements["known"] == 0


def test_an_iban_and_a_telephone_number_in_percent_encoding_are_replaced():
    masker = Masker(handle_salt=HANDLE_SALT)
    bank, call = iban(), phone()
    written_bank, written_call = quote(groups(bank), safe=""), quote(call, safe=":-")
    assert "%20" in written_bank and written_call.startswith("tel:%2B49")

    result = masker.mask_text(f"iban={written_bank}&call={written_call}")[0]

    assert result == f"iban={masked(bank)}&call={masked(call)}"
    assert PSEUDONYM.fullmatch(masked(call)) and "IBAN-" in masked(bank)
    assert masker.replacements["iban"] == 1 and masker.replacements["tel"] == 1


def test_a_value_both_views_find_is_counted_once():
    masker = Masker(handle_salt=HANDLE_SALT)
    found = masker.personal_pseudonym("email", "a.b@x.example")

    assert masker.mask_text("100% a.b@x.example %41")[0] == f"100% {found} %41"
    assert masker.replacements["email"] == 1


def test_an_address_written_two_ways_is_counted_once_each():
    masker = Masker(handle_salt=HANDLE_SALT)
    found = masker.personal_pseudonym("email", "a@b.example")

    assert masker.mask_text("a%40b.example and a@b.example")[0] == f"{found} and {found}"
    assert masker.replacements["email"] == 2


def test_text_without_an_escape_is_not_decoded(monkeypatch):
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[MUELLER])
    calls = []
    real = masking._decoded_view
    monkeypatch.setattr(
        masking, "_decoded_view", lambda text, *a: calls.append(text) or real(text, *a)
    )
    text = "plain text with ü, a.b@x.example and \\n and /u00fc"

    masker.mask_text(text)
    masker.holds_known_value(text)
    masker._holds_personal(text)

    assert calls == []


def test_a_header_whose_value_only_a_decoding_shows_is_still_blanked_whole():
    masker = Masker(handle_salt=HANDLE_SALT)

    headers, _ = masker.mask_headers({"X-Mail": "a%40b.test", "X-Plain": "a@b.test"})

    assert headers["x-mail"] == PLACEHOLDER
    assert PSEUDONYM.fullmatch(headers["x-plain"])


def test_a_decoded_path_keeps_the_result_it_had():
    masker = Masker(handle_salt=HANDLE_SALT)
    path = "/users/j%C3%BCrgen@host.example/a%20b"

    assert masker.mask_decoded([path, unquote(path)]) == (
        f"/users/{masker.personal_pseudonym('email', 'jürgen@host.example')}/a b"
    )


def test_a_megabyte_of_each_encoding_is_masked_in_five_seconds():
    masker = Masker(
        handle_salt=HANDLE_SALT, known_values=[secrets.token_hex(16) for _ in range(100)]
    )
    pieces = {"ü": "ü", "%41": "%41", "escaped ü": escaped("ü"), "escaped emoji": escaped("😀")}

    clocks = {
        name: _clocked(masker, (piece * (2**20 // len(piece)))[: 2**20])
        for name, piece in pieces.items()
    }

    print("1 MiB: " + ", ".join(f"{name!r} {seconds:.3f} s" for name, seconds in clocks.items()))
    assert max(clocks.values()) < 5


@pytest.mark.parametrize(
    ("prefixes", "unit"),
    [(["KD-2024-"], "KD-2024-"), (["KD-2024-", "AB-2025-"], "KD-2024-AB-2025-")],
    ids=["one prefix", "two prefixes"],
)
def test_a_thousand_values_that_share_a_prefix_are_found_in_time_in_a_text_of_nothing_else(
    prefixes, unit
):
    values = [f"{prefixes[n % len(prefixes)]}{n:04d}" for n in range(1000)]
    masker = Masker(handle_salt=HANDLE_SALT, known_values=values)
    text = (unit * (2**20 // len(unit)))[: 2**20]

    plain, with_percent = _clocked(masker, text), _clocked(masker, text + " 100%")

    print(f"1000 values, 1 MiB of {unit!r}: {plain:.3f} s, with a %: {with_percent:.3f} s")
    assert plain < 20 and with_percent < 20
    assert masker.replacements["known"] == 0


# -- JSON escapes where %XX is not decoded: header, query, path ---------------------------------

UMLAUT_MAIL = "jürgen.müller@firma.example"


def only_the_pseudonym(masker: Masker, text: str, mail: str = UMLAUT_MAIL) -> None:
    assert text == masker.personal_pseudonym("email", mail), text
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}


def test_a_header_with_an_address_in_json_escapes_is_replaced_whole():
    masker = Masker(handle_salt=HANDLE_SALT)

    headers, _ = masker.mask_headers({"X-User": escaped(UMLAUT_MAIL)})

    only_the_pseudonym(masker, headers["x-user"])


def test_a_query_value_with_an_address_in_json_escapes_is_replaced_whole():
    masker = Masker(handle_salt=HANDLE_SALT)

    fields, _ = masker.mask_query("u=" + quote(escaped(UMLAUT_MAIL), safe=""))

    only_the_pseudonym(masker, fields["u"])


def test_a_query_value_whose_percent_decoding_shows_json_escapes_is_replaced_whole():
    masker = Masker(handle_salt=HANDLE_SALT)

    fields, _ = masker.mask_query("u=j%5Cu00fcrgen@x.example")

    only_the_pseudonym(masker, fields["u"], "jürgen@x.example")


def test_a_decoded_value_with_an_address_in_json_escapes_is_replaced_whole():
    masker = Masker(handle_salt=HANDLE_SALT)
    text = escaped(UMLAUT_MAIL)

    only_the_pseudonym(masker, masker.mask_decoded([text]))
    other = Masker(handle_salt=HANDLE_SALT)
    only_the_pseudonym(other, other.mask_decoded([quote(text, safe=""), text]))


def test_a_recorded_path_with_an_address_in_json_escapes_is_replaced_whole():
    rec, _, masker = recorder()

    path = rec._path("/" + escaped(UMLAUT_MAIL))

    assert path == "/" + masker.personal_pseudonym("email", UMLAUT_MAIL)
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}


def test_a_header_in_json_escapes_leaves_the_name_nowhere_in_the_recording():
    _, response, masker = one_response([("X-User", escaped(UMLAUT_MAIL))])

    assert response["headers"]["x-user"] == masker.personal_pseudonym("email", UMLAUT_MAIL)
    text = json.dumps(response, ensure_ascii=False) + json.dumps(response)
    for part in ("jürgen", "j\\u00fcrgen", "müller", "m\\u00fcller", "firma"):
        assert part not in text, part


# -- a decoded span wins over one that overlaps it as written -----------------------------------


@pytest.mark.parametrize(
    ("text", "before", "mail", "after"),
    [
        ("mail%3Djane@x.example", "mail%3D", "jane@x.example", ""),
        ("%20jane@x.example", "%20", "jane@x.example", ""),
        ("%22jane@x.example%22", "%22", "jane@x.example", "%22"),
        ("<jane@x.example>", "<", "jane@x.example", ">"),
        ("\\ud800alice@x.example", "\\ud800", "alice@x.example", ""),
    ],
    ids=["equals sign", "space", "quotes", "angle brackets", "lone surrogate"],
)
def test_the_whole_address_is_replaced_where_an_encoding_cuts_its_written_form(
    text, before, mail, after
):
    masker = Masker(handle_salt=HANDLE_SALT)

    masked = masker.mask_text(text)[0]

    assert masked == before + masker.personal_pseudonym("email", mail) + after
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}


def test_an_address_that_only_the_written_view_finds_is_still_replaced():
    masker = Masker(handle_salt=HANDLE_SALT)

    masked = masker.mask_text("a%41 jane@x.example %20")[0]

    assert masked == f"a%41 {masker.personal_pseudonym('email', 'jane@x.example')} %20"
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}


# -- an id that is no name is not named in the words --------------------------------------------


@pytest.mark.parametrize("identifier", ["müller-2026", "Müller GmbH"])
def test_the_words_for_an_id_that_is_no_name_do_not_name_it(identifier, tmp_path):
    from mcp_kymograph import intake

    held = second_file(tmp_path / "engagement", name="acme-x", id=identifier)
    with pytest.raises(engagement.EngagementError) as loading:
        engagement.load(held)
    answers = tmp_path / "answers.json"
    answers.write_text("{}")
    with pytest.raises(intake.IntakeError) as taking:
        intake.draft(intake.read_answers(answers), engagement_id=identifier)

    for words in (str(loading.value), str(taking.value)):
        assert "is not a name" in words
        for part in ("müller", "Müller", "2026", "GmbH"):
            assert part not in words, part


# -- a manifest path with the value in JSON escapes ---------------------------------------------


def test_a_manifest_path_with_a_known_value_in_json_escapes_is_refused_before_the_run_starts(
    tmp_path, tmp_path_factory, salt, nothing_starts
):
    inputs = tmp_path_factory.mktemp("inputs")

    code, runs = named_run(
        tmp_path, work=escaped(MUELLER) + "-manifests", inputs=inputs, known=MUELLER
    )

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value" and "--manifest" in record.message
    assert recordings_in(runs) == []


# -- a written span that reaches past the decoded one --------------------------------------------


@pytest.mark.parametrize(
    ("text", "kind", "gone"),
    [
        ("tel:+49%20301234567", "tel", ["301234567", "4567", "%20"]),
        ("tel:+49-30-123%2F4567", "tel", ["4567", "123", "%2F"]),
        ("x%40a.example@c.example", "email", ["c.example", "a.example", "%40"]),
    ],
    ids=["space", "slash", "at sign"],
)
def test_the_rest_of_a_value_behind_the_decoded_span_does_not_stay(text, kind, gone):
    masker = Masker(handle_salt=HANDLE_SALT)

    masked = masker.mask_text(f"call {text} now")[0]

    assert len(pseudonyms(masked)) == 1
    assert re.fullmatch(r"call \*\*\*[A-Z]+-[0-9a-f]{12}\*\*\* now", masked)
    assert masker.replacements == {**NO_REPLACEMENTS, kind: 1}
    for part in gone:
        assert part not in masked, part


def test_a_written_span_over_two_decoded_ones_and_beyond_replaces_all_of_them_once():
    written = [(0, 20, "w")]
    decoded = [(0, 5, "a"), (8, 12, "b")]

    assert masking._prefer_decoded(written, decoded) == [(0, 20, "w")]


def test_a_written_span_that_ends_inside_the_second_decoded_one_leaves_both_alone():
    written = [(0, 10, "w")]
    decoded = [(0, 4, "a"), (6, 12, "b")]

    assert masking._prefer_decoded(written, decoded) == decoded


def test_a_written_span_that_overlaps_none_stays_and_one_that_ends_with_the_last_is_dropped():
    written = [(0, 3, "w"), (5, 9, "x"), (20, 25, "y")]
    decoded = [(6, 9, "a"), (12, 14, "b")]

    assert masking._prefer_decoded(written, decoded) == [
        (0, 3, "w"), (6, 9, "a"), (12, 14, "b"), (20, 25, "y"),
    ]  # fmt: skip


def test_the_union_of_a_written_and_a_decoded_span_gets_the_item_of_the_longer():
    assert masking._prefer_decoded([(3, 23, "w")], [(0, 13, "d")]) == [(0, 23, "w")]
    assert masking._prefer_decoded([(1, 6, "w")], [(0, 3, "d")]) == [(0, 6, "w")]
    assert masking._prefer_decoded([(2, 6, "w")], [(0, 5, "d")]) == [(0, 6, "d")]


@pytest.mark.parametrize(
    ("text", "before", "mail", "after"),
    [
        ("mail%3Djane@x.example", "mail%3D", "jane@x.example", ""),
        ("%20jane@x.example", "%20", "jane@x.example", ""),
        ("%22jane@x.example%22", "%22", "jane@x.example", "%22"),
        ("<jane@x.example>", "<", "jane@x.example", ">"),
        ("\\ud800alice@x.example", "\\ud800", "alice@x.example", ""),
    ],
    ids=["equals sign", "space", "quotes", "angle brackets", "lone surrogate"],
)
def test_the_five_forms_of_a_cut_address_are_as_they_were(text, before, mail, after):
    masker = Masker(handle_salt=HANDLE_SALT)

    masked = masker.mask_text(text)[0]

    assert masked == before + masker.personal_pseudonym("email", mail) + after
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}


# -- --out-dir with a known value ---------------------------------------------------------------


def percent(value: str) -> str:
    """Every byte of ``value`` as ``%XX``."""
    return "".join(f"%{byte:02X}" for byte in value.encode())


@pytest.mark.parametrize("write", [str, percent], ids=["plain", "percent-encoded"])
def test_a_fleet_whose_out_dir_holds_a_known_value_is_refused_before_anything_exists(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch, write
):
    value = known()
    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(inputs / "engagement", known_values=[value])
    manifest = fleet_manifest(inputs)
    runs = tmp_path / f"runs-{write(value)}"

    code, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert "--out-dir" in record.message and "--out-dir" in said
    assert not (tmp_path / "store.sqlite").exists()
    assert [p for p in runs.iterdir() if p.is_dir()] == []
    for form in {*forms_of(value), write(value)}:
        assert form not in said
        assert form not in (runs / engagement.REFUSALS_FILE).read_text()
        assert [path for path, content in written_under(tmp_path) if form.encode() in content] == []
    assert "***KNOWN-" in " ".join(record.command)


def test_a_run_whose_out_dir_holds_a_known_value_is_refused_and_starts_nothing(
    tmp_path, tmp_path_factory, salt, nothing_starts
):
    value = known()
    held = second_file(tmp_path_factory.mktemp("inputs") / "engagement", known_values=[value])
    runs = tmp_path / f"runs-{value}"

    code = drive(held, runs)

    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "name_holds_known_value"
    assert "--out-dir" in record.message
    assert recordings_in(runs) == []
    for form in forms_of(value):
        assert [path for path, content in written_under(tmp_path) if form.encode() in content] == []


def test_a_fleet_with_a_neutral_out_dir_is_not_refused_for_it(
    tmp_path, tmp_path_factory, salt, capsys, monkeypatch
):
    from test_fleet_endpoint import with_endpoints

    value = known()
    inputs = tmp_path_factory.mktemp("inputs")
    held = second_file(inputs / "engagement", known_values=[value])
    (inputs / "work").mkdir()
    manifest = with_endpoints(inputs / "work", "customer-mcp")
    runs = tmp_path / "runs"

    code, said = fleet_call(tmp_path, held, manifest, runs, capsys, monkeypatch)

    # It is refused at the gate, for the entry's endpoint: the out-dir is no reason.
    assert code == 2
    (record,) = refusals_in(runs)
    assert record.reason == "fleet"
    assert "endpoint entry" in record.message and "endpoint entry" in said


# -- a salt with bytes that are not UTF-8 -------------------------------------------------------


def salt_of(monkeypatch, raw: bytes, tmp_path: Path) -> Masker:
    """The masker of a run under a file of version 2, the variable holding ``raw``."""
    monkeypatch.setitem(os.environb, SALT_ENV.encode(), raw)
    return cli.run_masker([], held=engagement.load(second_file(tmp_path / "engagement")))


def test_a_salt_with_a_byte_that_is_not_utf8_keys_the_pseudonyms_as_those_bytes(
    tmp_path, monkeypatch
):
    raw = b"salt-" + secrets.token_hex(12).encode() + b"\xff" + secrets.token_hex(4).encode()
    assert len(raw) >= engagement.MIN_SALT_LENGTH
    masker = salt_of(monkeypatch, raw, tmp_path)
    as_text = raw.decode("utf-8", "surrogateescape")
    mail = address()

    out, _ = masker.mask_text(f"{mail} and the salt {as_text} and again {as_text}")

    expected = hmac.new(raw, f"email\0{mail}".encode(), sha256).hexdigest()[:12]
    assert masker.personal_pseudonym("email", mail) == f"***EMAIL-{expected}***"
    assert out.startswith(f"***EMAIL-{expected}*** and the salt ")
    assert as_text[:20] not in out and as_text[-8:] not in out
    assert "\xff" not in out and "\udcff" not in out


def test_a_salt_with_a_byte_that_is_not_utf8_is_masked_in_its_percent_encoded_forms(
    tmp_path, monkeypatch
):
    raw = b"salt-" + secrets.token_hex(12).encode() + b"\xff" + secrets.token_hex(4).encode()
    masker = salt_of(monkeypatch, raw, tmp_path)
    as_text = raw.decode("utf-8", "surrogateescape")
    head, tail = as_text.split("\udcff")
    for form in ("%FF", "%ff", "\udcff", "%ED%B3%BF", "%ed%b3%bf"):
        out, _ = masker.mask_text(f"a={head}{form}{tail}&b=1")

        assert out.startswith("a=") and out.endswith("&b=1"), form
        assert head not in out and tail not in out, form
        assert "%FF" not in out.upper() and "\udcff" not in out, form


def test_a_literal_without_a_surrogate_gives_the_pattern_it_always_gave():
    text = "a%é@ß-" + secrets.token_hex(4)

    def as_before(char: str) -> str:
        escaped = "".join(
            "%" + "".join(f"[{d.lower()}{d.upper()}]" if d.isalpha() else d for d in f"{b:02x}")
            for b in char.encode("utf-8")
        )
        return f"(?:{escaped}|{re.escape(char)})"

    assert masking._literal_pattern(text) == "".join(as_before(char) for char in text)


def test_a_salt_of_valid_utf8_gives_the_pseudonyms_it_always_gave(tmp_path, monkeypatch):
    text = "sälz-" + secrets.token_hex(16)
    masker = salt_of(monkeypatch, text.encode(), tmp_path)
    mail = address()

    expected = hmac.new(text.encode("utf-8"), f"email\0{mail}".encode(), sha256).hexdigest()[:12]

    assert masker.personal_pseudonym("email", mail) == f"***EMAIL-{expected}***"


# -- a host of 253 characters with a dot behind it -----------------------------------------------


def host_of(size: int) -> str:
    """A valid host name of ``size`` characters: three labels of 63 and a last one of letters."""
    host = ".".join(["a" * 63] * 3 + ["b" * (size - 3 * 64)])
    assert len(host) == size
    return host


@pytest.mark.parametrize("after", [". Danke", ".", ""], ids=["sentence", "dot", "nothing"])
def test_an_address_with_a_host_of_253_characters_is_replaced_whole_with_a_dot_behind_it(after):
    mail = "max.mustermann@" + host_of(253)
    masker = Masker(handle_salt=HANDLE_SALT)

    out = masker.mask_text(mail + after)[0]

    assert out == masker.personal_pseudonym("email", mail) + after
    assert masker.replacements == {**NO_REPLACEMENTS, "email": 1}


@pytest.mark.parametrize(
    "text",
    ["max.mustermann@" + host_of(253) + ".xy", "max.mustermann@" + host_of(254)],
    ids=["a label goes on", "254 characters"],
)
def test_an_address_with_a_host_that_is_too_long_is_left_as_it_was(text):
    masker = Masker(handle_salt=HANDLE_SALT)

    assert masker.mask_text(text)[0] == text
    assert masker.replacements == NO_REPLACEMENTS


# -- the reason of a stop file -------------------------------------------------------------------


def stop_text(held: Path) -> str:
    return engagement.stop_path(held).read_text()


def test_the_reason_of_a_stop_file_holds_neither_a_known_value_nor_the_salt(tmp_path, salt):
    value = known()
    held = second_file(tmp_path / "engagement", known_values=[value])
    # Every form the masker reads: percent() encodes each character, which quote() would not do
    # for this value. A known value is compared case-sensitively, so its lower case is no form.
    forms = [value, percent(value), percent(value).lower(), salt]

    assert cli.main(["engagement", "stop", "-q", str(held), "--reason", " ".join(forms)]) == 0

    written = stop_text(held)
    for form in forms:
        assert form not in written
    assert "***KNOWN-" in written


def test_a_file_that_cannot_be_read_is_stopped_all_the_same(tmp_path, salt):
    held = tmp_path / "engagement.yaml"
    held.write_text("version: [not an engagement file\n")

    assert cli.main(["engagement", "stop", "-q", str(held), "--reason", "customer asks"]) == 0

    assert json.loads(stop_text(held))["reason"] == "customer asks"


# -- what a person typed is not counted ----------------------------------------------------------


def typed_places(rec: Recorder, value: str) -> None:
    """Every event that names a typed value, as a script or a probe would."""
    tool = f"{value}_search"
    rec.run_started(
        0, 0, argv=["server", value], limits={}, script=f"{value}.yaml",
        script_vars={"customer": value}, inputs={"mask_keys": [value]},
        probe={"name": "drive", "options": {"customer": value}},
    )  # fmt: skip
    rec.step_called(1, 0, step="s1", tool=tool, arguments={"customer": value})
    rec.call_failed(2, 0, step="s1", tool=tool, kind=events.CALL_FAILURES[0])
    rec.call_blocked(3, 0, cause="tool_denied", where=events.BLOCKED_BY_DRIVER, tool=tool)
    rec.script_finished(4, 0, inventory="tools", called=[tool], failed=[tool])


def test_a_typed_value_is_replaced_but_not_counted_in_any_event_that_names_it():
    value = known()
    masker = Masker(handle_salt=HANDLE_SALT, known_values=[value])
    stream = io.StringIO()
    rec = Recorder(stream, run_id="r", masker=masker)

    typed_places(rec, value)

    assert value not in stream.getvalue()
    kinds = {e["type"] for e in written(stream) if "***KNOWN-" in json.dumps(e)}
    assert kinds == {
        "run_started", "step_called", "call_failed", "call_blocked", "script_finished",
    }  # fmt: skip
    assert masker.replacements["known"] == 0
    body = {"result": {"customer": value}}
    rec.message(5, 0, direction=Direction.SERVER_TO_CLIENT, raw=json.dumps(body).encode())
    assert masker.replacements["known"] == 1


ECHO_SERVER = """\
import json, sys

for raw in sys.stdin.buffer:
    request = json.loads(raw)
    if "id" not in request:
        continue
    method = request.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "echo", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "lookup", "description": "Finds a customer.",
                             "inputSchema": {"type": "object"}}]}
    else:
        result = {"content": [{"type": "text", "text": json.dumps(request["params"])}]}
    reply = {"jsonrpc": "2.0", "id": request["id"], "result": result}
    sys.stdout.write(json.dumps(reply) + chr(10))
    sys.stdout.flush()
"""


def test_a_driven_script_counts_a_value_in_its_argument_once_per_message_that_holds_it(
    tmp_path, salt
):
    value = known()
    held = second_file(
        tmp_path / "engagement", known_values=[value], actions={"list": True, "call": True}
    )
    server = tmp_path / "echo_server.py"
    server.write_text(ECHO_SERVER)
    script_path = tmp_path / "engagement" / "call.yaml"
    script_path.write_text(
        "version: 1\nname: probe\nsteps:\n  - initialize\n  - list: tools/list\n"
        f"  - call: {{tool: lookup, arguments: {{customer: {value}}}}}\n"
    )
    runs = tmp_path / "runs"

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(runs), "--script",
         str(script_path), "--", sys.executable, str(server)]
    )  # fmt: skip

    assert code == 0
    (recording,) = recordings_in(runs)
    records = events_of(recording)
    carrying = [
        e for e in records if e["type"] == "message" and "***KNOWN-" in json.dumps(e["payload"])
    ]
    assert len(carrying) == 2, "the request and the echo"
    assert records[-1]["replacements"]["known"] == len(carrying)
    assert value not in recording.read_text()
