"""Unicode variants before the key list and the text rules (src/mcp_kymograph/masking.py,
``normalise_key``, ``_normalised_copy``): a secret that only gets past the masking
by its spelling is masked like its plain spelling.
"""

from __future__ import annotations

import json
import time

import pytest

from mcp_kymograph.masking import PLACEHOLDER, Masker

SECRET = "".join(("OPAQUE", "-CREDEN", "TIAL"))
TOKEN = "sk-" + "abcdefghijklmnop"
ZW = chr(0x200B)


def test_a_full_width_key_is_masked_like_its_plain_spelling():
    """The full-width spelling of ``apikey`` is the key ``apikey``."""
    key = "ａｐｉｋｅｙ"
    masked, _ = Masker().mask_json({key: SECRET})
    assert SECRET not in json.dumps(masked)


def test_a_zero_width_character_between_full_width_letters_of_a_key_does_not_hide_it():
    """Full width with a U+200B between: NFKC makes it ``apikey`` (the U+200B the key's own
    reduction to letters and digits drops anyway)."""
    masker = Masker()
    key = "\uff41\uff50\uff49" + ZW + "\uff4b\uff45\uff59"
    assert masker.is_secret_key(key)
    assert SECRET not in json.dumps(masker.mask_json({key: SECRET})[0])


def test_a_zero_width_character_in_the_scheme_is_masked():
    """``Bea<U+200B>rer`` is read as ``Bearer``."""
    text, hits = Masker().mask_text(f"Bea{ZW}rer {SECRET}")
    assert SECRET not in text
    assert hits >= 1


def test_a_doubly_escaped_space_before_a_token_is_masked():
    """A literal backslash-u0020 before ``sk-`` left no word boundary."""
    masked, _ = Masker().mask_json({"note": "\\u0020" + TOKEN})
    assert TOKEN not in json.dumps(masked)


def test_a_full_width_token_in_a_value_is_replaced():
    """The full-width ``sk`` prefix reads as ``sk-`` once normalised."""
    text, hits = Masker().mask_text("ｓｋ-abcdefghijklmnop")
    assert text == PLACEHOLDER
    assert hits == 1


def test_a_zero_width_character_in_a_token_is_replaced():
    """A U+200B in the middle of the token does not end the run."""
    text, hits = Masker().mask_text(f"sk-abc{ZW}defghijklmnop")
    assert text == PLACEHOLDER
    assert hits == 1


def test_a_hex_escaped_character_is_read():
    """``\\x20`` reads as a space, like ``\\u0020``."""
    text, _ = Masker().mask_text("\\x20" + TOKEN)
    assert TOKEN not in text


def test_a_harmless_text_with_non_ascii_is_unchanged():
    """Umlauts, an emoji and a combining sequence hold no secret: text and count stay."""
    harmless = "Grüße aus Köln \U0001f600 café — schön"
    assert Masker().mask_text(harmless) == (harmless, 0)
    assert Masker()._mask_shapes(harmless) == (harmless, 0)


def test_an_ordinary_match_masks_only_its_span():
    """No variant anywhere: the span is replaced, not the whole value, as before."""
    text, hits = Masker().mask_text(f"before {TOKEN} after")
    assert text == f"before {PLACEHOLDER} after"
    assert hits == 1


def test_an_ordinary_match_next_to_non_ascii_keeps_its_span():
    """The copy finds no more than the text, so the original's result stands."""
    text, hits = Masker().mask_text(f"Grüße {TOKEN} ok")
    assert text == f"Grüße {PLACEHOLDER} ok"
    assert hits == 1


def test_a_megabyte_of_non_ascii_and_escapes_masks_quickly():
    """Linear: 1 MB with many non-ASCII characters and ``\\u`` sequences takes under 2 s."""
    unit = f"Grüße \U0001f600 \\u0041\\x42 sk-short {ZW} ｓｋ "
    text = unit * (1_000_000 // len(unit) + 1)
    started = time.perf_counter()
    Masker().mask_text(text)
    assert time.perf_counter() - started < 2


def test_a_match_the_copy_destroys_does_not_pay_for_one_it_reveals():
    """The first token loses its word boundary in the copy, the second only appears there:
    the copy is made of the masked text, so the second still replaces the whole value."""
    text = "x" + ZW + "sk-aaaaaaaaaaaaaaaa \uff53\uff4b-bbbbbbbbbbbbbbbb"
    masked, hits = Masker().mask_text(text)
    assert "bbbbbbbbbbbbbbbb" not in masked and "aaaaaaaaaaaaaaaa" not in masked
    assert (masked, hits) == (PLACEHOLDER, 2)


def test_a_tag_character_inside_a_token_does_not_hide_it():
    """U+E0020 is invisible and breaks the run in the text; the copy drops it."""
    masked, _ = Masker().mask_text("sk-abcdefgh" + chr(0xE0020) + "ijklmnop")
    assert "ijklmnop" not in masked


def test_the_invisible_set_holds_the_one_of_the_signals():
    """What the signals' normalised view drops, the masker drops too, and beside it the marks,
    fillers, operators and variation selectors it names, and nothing else."""
    from mcp_kymograph import masking, signals

    more = {ord(c) for c in masking.MORE_INVISIBLE} | {
        point for first, last in masking.INVISIBLE_RANGES for point in range(first, last + 1)
    }
    assert set(masking._WIDTHLESS_TABLE) == set(signals._STRIP) | more
    assert {0x200E, 0x200F, 0x061C} <= more
    for point in masking._WIDTHLESS_TABLE:
        assert masking._WIDTHLESS.fullmatch(chr(point)), hex(point)


#: What the masker drops beyond the signals' set, written out here and not read from the
#: module: the three bidirectional marks, the combining grapheme joiner, the invisible
#: operators, the Hangul fillers, the Khmer inherent vowels, and the first and the last of each
#: range (variation selectors, deprecated format characters, annotation marks, musical format
#: characters).
MORE = [
    0x200E, 0x200F, 0x061C, 0x034F, 0x2061, 0x2062, 0x2063, 0x2064, 0x115F, 0x1160, 0x3164,
    0xFFA0, 0x17B4, 0x17B5, 0x180F, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF, 0x180B, 0x180D, 0x206A,
    0x206F, 0xFFF9, 0xFFFB, 0x1D173, 0x1D17A,
]  # fmt: skip


@pytest.mark.parametrize("point", MORE, ids=[f"U+{point:04X}" for point in MORE])
def test_an_invisible_character_beyond_the_signals_set_hides_nothing(point):
    """A token, a scheme and a known value split by such a character are read whole."""
    name = "Kunde-Alpha-9"
    masker = Masker(known_values=[name])
    hidden = chr(point)
    for text in (
        f"key {TOKEN[:8]}{hidden}{TOKEN[8:]}",
        f"Bea{hidden}rer {SECRET}",
        f"an {name[:5]}{hidden}{name[5:]} geliefert",
    ):
        masked, hits = masker.mask_text(text)
        assert masked == PLACEHOLDER and hits == 1, ascii(text)


@pytest.mark.parametrize("space", [0x00A0, 0x2007, 0x2009, 0x202F, 0x3000])
def test_a_known_value_written_with_another_space_is_not_let_through(space):
    """NFKC makes a plain space of each of these; the known value is listed with a plain one.
    In a string and in a key."""
    name = "Max Mustermann"
    masker = Masker(known_values=[name])
    spelled = name.replace(" ", chr(space))

    assert masker.mask_text(f"Kunde: {spelled}") == (PLACEHOLDER, 1)
    masked, _ = masker.mask_json({"result": {"name": spelled, spelled: 1}})
    assert "Mustermann" not in json.dumps(masked, ensure_ascii=False)
    assert masker.holds_known_value(f"Kunde: {spelled}")


@pytest.mark.parametrize(
    "hidden",
    [chr(0x034F), chr(0x200B), chr(0x2060), chr(0xFE0F), chr(0x200D), chr(0x00AD), "\\u034f"],
    ids=["U+034F", "U+200B", "U+2060", "U+FE0F", "U+200D", "U+00AD", "escaped"],
)
def test_an_invisible_character_between_a_letter_and_its_accent_hides_no_known_value(hidden):
    """The value is listed composed and sent decomposed, with an invisible character before
    the accent: it goes before NFKC, or the two would not compose."""
    masker = Masker(known_values=["M\u00fcller-Hof"])
    spelled = f"Mu{hidden}\u0308ller-Hof"

    assert masker.mask_text(f"Hof: {spelled}") == (PLACEHOLDER, 1)
    masked, _ = masker.mask_json({"result": {"name": spelled, spelled: 1}})
    assert "ller-Hof" not in json.dumps(masked, ensure_ascii=False)
    assert masker.holds_known_value(f"Hof: {spelled}")


def test_a_hangul_filler_that_nfkc_makes_of_another_is_dropped_too():
    """U+3164 and U+FFA0 become U+1160 under NFKC, which is dropped after it."""
    masker = Masker(known_values=["Kunde-Alpha-9"])
    for filler in (chr(0x3164), chr(0xFFA0)):
        assert masker.mask_text(f"an Kunde{filler}-Alpha-9") == (PLACEHOLDER, 1)


@pytest.mark.parametrize("space", ["%C2%A0", "%c2%a0", "%E3%80%80", "%E2%80%AF"])
def test_a_known_value_with_another_space_percent_encoded_is_not_let_through(space):
    """Decoded it is a no-break space, which only NFKC makes a plain one: in a text, in a JSON
    string and where a text is held to the values."""
    name = "Max Mustermann"
    masker = Masker(known_values=[name])
    spelled = name.replace(" ", space)

    assert masker.mask_text(f"q={spelled}&x=1") == (PLACEHOLDER, 1)
    masked, _ = masker.mask_json({"url": f"https://shop.example/find?q={spelled}"})
    assert "Mustermann" not in json.dumps(masked)
    assert masker.holds_known_value(f"q={spelled}")
    plain = "q=Erika%C2%A0Musterfrau&x=1"
    assert masker.mask_text(plain) == (plain, 0)


@pytest.mark.parametrize(
    "listed",
    [
        "\u2460\u2461\u2462\u2463",
        "\u00a0\u00a0\u00a0\u00a0",
        "e\u0301\ufb01",
        "x\u00b2\u00b3\u2074\u2075",
    ],
    ids=["circled digits", "no-break spaces", "short", "superscripts"],
)
def test_the_nfkc_form_of_a_listed_value_is_no_value_where_the_list_would_not_take_it(listed):
    """Circled digits would make ``1234`` a value in every number, four no-break spaces every
    indentation, and a form of three characters is shorter than a listed value may be."""
    masker = Masker(known_values=[listed])
    document = {"n": 12345, "s": "order 1234,    indented \u00e9fi x2345"}
    assert masker.mask_json(document) == (document, [])


@pytest.mark.parametrize(
    ("listed", "plain"),
    [("Max\u00a0Mustermann", "Max Mustermann"), ("\ufb01rma-12", "firma-12"),
     ("\uff41\uff43\uff4d\uff45-1", "acme-1")],
    ids=["no-break space", "ligature", "full width"],
)  # fmt: skip
def test_a_value_listed_in_a_compatibility_spelling_is_found_plain_and_as_listed(listed, plain):
    """Copied from a document into the list, sent by the server in the ordinary spelling: the
    pseudonym of the listed value either way, and the text around it stays."""
    masker = Masker(known_values=[listed])
    stand_in = masker.personal_pseudonym("known", listed)

    assert masker.mask_text(f"Kunde {plain} hier")[0] == f"Kunde {stand_in} hier"
    assert masker.mask_text(f"Kunde {listed} hier")[0] == f"Kunde {stand_in} hier"
    assert masker.holds_known_value(f"Kunde {plain} hier")


def test_nfkc_makes_no_invisible_character_of_a_visible_one():
    """What the normalised copy relies on when it drops the invisible characters before NFKC
    and not again after it."""
    import unicodedata

    from mcp_kymograph import masking

    for point in range(0x110000):
        if point in masking._WIDTHLESS_TABLE or 0xD800 <= point <= 0xDFFF:
            continue
        folded = unicodedata.normalize("NFKC", chr(point))
        assert masking._WIDTHLESS.search(folded) is None, hex(point)


def test_a_key_with_an_invisible_character_before_an_accent_is_still_its_name():
    """In a key the accent is dropped as no letter, and the letter stays: NFKC first there."""
    masker = Masker()
    assert masker.is_secret_key("tok\u200b\u0301en")
    assert masker.is_secret_key("api_ke\u034f\u0301y")


def test_a_literal_that_shows_once_percent_is_decoded_and_normalised_takes_the_value():
    secret = "geheim Wert-" + "abcdefgh"
    masker = Masker(literals=[secret])
    spelled = secret.replace(" ", "%C2%A0")
    assert masker.mask_text(f"q={spelled}&x=1") == (PLACEHOLDER, 1)
    assert masker.mask_text(f"q={spelled}&x=1", personal=False) == (PLACEHOLDER, 1)
    assert masker.holds_known_value(f"q={spelled}")


def test_a_text_read_for_its_credentials_keeps_a_known_value_beside_an_encoded_character():
    """The reading with ``personal`` false replaces no known value, as written or decoded."""
    masker = Masker(known_values=["Max Mustermann"])
    text = "/kunden/Max%20Mustermann%E2%80%A6/akte"
    assert masker.mask_text(text, personal=False) == (text, 0)


@pytest.mark.parametrize(
    ("known", "literal", "hidden"),
    [("4711", None, "4711"), ("100234", None, "100234"), (None, "deadbeef1234", "deadbeef1234")],
    ids=["four digits", "six digits", "a literal of twelve"],
)
def test_what_only_the_decoding_makes_look_like_a_pseudonym_is_read(known, literal, hidden):
    """A server writes a value in full width and ``%XX`` into the frame of a pseudonym, where
    its digest stands: the digest of a pseudonym is not read, and this is none."""
    from urllib.parse import quote

    masker = Masker(known_values=[known] if known else [], literals=[literal] if literal else [])
    wide = quote("".join(chr(ord(c) + 0xFEE0) for c in hidden))
    text = f"***KNOWN-{wide}{'a' * (12 - len(hidden))}***"

    assert masker.mask_text(f"see {text}") == (PLACEHOLDER, 1)
    assert masker.mask_json({"note": text})[0] == {"note": PLACEHOLDER}
    assert masker.holds_known_value(text)
    headers, _ = masker.mask_headers([("X-Note", text)])
    assert headers == {"x-note": PLACEHOLDER}


def test_a_header_name_with_a_known_value_in_an_encoded_spelling_is_not_written():
    """A name is written whole or not at all, lower-cased: a known value in it is looked for
    in every reading."""
    masker = Masker(known_values=["Max Mustermann", "Mustermann"])
    for name in ("X-Max%C2%A0Mustermann", "X-Kunde-Max%C2%A0Mustermann", "X-Muster%E2%80%8Bmann"):
        headers, _ = masker.mask_headers([(name, "1")])
        (written,) = headers
        assert "muster" not in written and headers[written] == PLACEHOLDER, name
    assert masker.mask_headers([("X-Request-Id", "1")])[0] == {"x-request-id": "1"}


def test_a_value_listed_with_a_no_break_space_before_it_makes_no_short_word_a_value():
    masker = Masker(known_values=["\u00a0Max"])
    text = "in Max Mustermann's file, at the Maximum"
    assert masker.mask_text(text) == (text, 0)
    assert masker.mask_text("x\u00a0Max")[0] != "x\u00a0Max"


def test_a_query_and_a_header_with_a_known_value_keep_what_is_not_the_value():
    """The reading that looks for credentials leaves the known values in place by design: an
    ordinary known value beside an encoded ellipsis or a superscript is no credential, the
    field is not blanked whole and no redaction is declared. Written with ``%C2%A0`` inside,
    it is one."""
    name = "Max Mustermann"
    masker = Masker(known_values=[name, "2026"])
    stand_in = masker.personal_pseudonym("known", name)

    query, paths = masker.mask_query("q=Max%20Mustermann%E2%80%A6&x=1")
    assert PLACEHOLDER not in json.dumps(query) and paths == []
    assert stand_in in json.dumps(query) and "Mustermann" not in json.dumps(query)
    headers, declared = masker.mask_headers(
        [("Referer", "https://example.com/n?v=x%C2%B2+y%C2%B3&year=2026")]
    )
    assert PLACEHOLDER not in json.dumps(headers) and declared == []
    hidden, _ = masker.mask_query("q=Max%C2%A0Mustermann")
    assert "Mustermann" not in json.dumps(hidden)


def test_a_value_in_the_digest_of_a_pseudonym_takes_no_text():
    """A short value that stands in another value's pseudonym by chance, beside an encoded
    character NFKC changes."""
    name, salt = "Max Mustermann", b"a fixed salt for the pseudonyms!!"
    stand_in = Masker(known_values=[name], personal_salt=salt).personal_pseudonym("known", name)
    part = stand_in[len("***KNOWN-") : -len("***")][3:7]
    masker = Masker(known_values=[name, part], personal_salt=salt)
    assert part in stand_in and masker.personal_pseudonym("known", name) == stand_in
    assert masker.mask_text(f"Kunde {name}%E2%80%A6") == (f"Kunde {stand_in}%E2%80%A6", 0)


def test_a_harmless_text_with_a_no_break_space_is_unchanged():
    text = "Gr\u00fc\u00dfe\u00a0aus K\u00f6ln, 12\u202f000\u00a0\u20ac"
    assert Masker(known_values=["Max Mustermann"]).mask_text(text) == (text, 0)


@pytest.mark.parametrize(
    "text",
    [
        "note: \uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44\uff1dhunter2",
        "password\\u003dhunter2",
        "pass" + ZW + "word = hunter2",
    ],
)
def test_a_pair_that_only_the_copy_shows_is_masked(text):
    """Full width, an escaped ``=`` and an invisible character in the name: no shape of a
    credential, only the pair rule on the normalised copy finds the value."""
    masked, hits = Masker().mask_text(text)
    assert "hunter2" not in masked and hits >= 1


def test_a_pseudonym_is_compared_by_its_kind_when_nfkc_composes_the_value():
    """A decomposed accent in an address: the copy holds the composed address, with another
    digest. What was replaced is the same, and the text around it stays."""
    text = "Mail: mu\u0308ller@example.org bitte"
    masked, _ = Masker().mask_text(text)
    assert masked.startswith("Mail: ***EMAIL-") and masked.endswith("*** bitte")


def test_a_character_written_as_an_escaped_surrogate_pair_is_read_as_that_character():
    """JSON writes a character beyond sixteen bits as two escapes; here it is a bold K, which
    NFKC reads as K."""
    name = "Kunde-Alpha-9"
    masker = Masker(known_values=[name])
    assert masker.mask_text("an \\ud835\\udc0a" + name[1:] + " geliefert") == (PLACEHOLDER, 1)
    assert masker.is_secret_key("\\ud835\\udc13oken")
    assert masker.mask_text("ein \\ud835 allein") == ("ein \\ud835 allein", 0)


def test_a_known_value_listed_decomposed_is_found_composed_with_its_own_pseudonym():
    listed = "Mu\u0308ller-Hof"
    masker = Masker(known_values=[listed])
    stand_in = masker.personal_pseudonym("known", listed)

    assert masker.mask_text("Hof: M\u00fcller-Hof")[0] == f"Hof: {stand_in}"
    assert masker.mask_text(f"Hof: {listed}")[0] == f"Hof: {stand_in}"


def test_a_copy_that_outgrows_its_text_is_not_masked_and_the_value_goes_whole():
    """U+FDFA is eighteen characters under NFKC. A text of them is replaced whole, and a
    megabyte of them costs no more than a few megabytes of plain text; a few of them in an
    ordinary text change nothing."""
    masker = Masker()
    assert masker.mask_text("\ufdfa" * 2000) == (PLACEHOLDER, 1)
    ordinary = "Ein Satz mit \ufdfa darin und \u2026 am Ende. " * 50
    assert masker.mask_text(ordinary) == (ordinary, 0)

    started = time.perf_counter()
    masker.mask_text("\ufdfa" * 333_000)
    masker.mask_text("\\ufdfa" * 166_000)
    assert time.perf_counter() - started < 4.0


@pytest.mark.parametrize(
    "text",
    [
        "sk-abcdefghijklmnop" + ZW + "qrstuvwxyz",
        "sk-abcdefghijklmnop\\u0041BCDEFGH",
        "sk-abcdefghijklmnop\uff51\uff52\uff53\uff54",
    ],
)
def test_the_rest_of_a_token_behind_an_invisible_character_goes_too(text):
    """The text matches the token only up to the invisible character; the copy reads it whole.
    Its spans do not map back, so the whole value goes, and no rest of the token stays."""
    masked, _ = Masker().mask_text(text)
    assert masked == PLACEHOLDER


def test_the_rule_without_pairs_reads_the_copy_too():
    """The path the HTTP functions take (_mask_shapes) reads the normalised copy as well."""
    masked, hits = Masker()._mask_shapes("\uff53\uff4b-abcdefghijklmnop")
    assert (masked, hits) == (PLACEHOLDER, 1)


def test_an_escaped_letter_in_a_key_does_not_hide_it():
    """A key sent as ``\\u0074oken`` (the backslash kept by the JSON reader) is ``token``."""
    masked, paths = Masker().mask_json({"\\u0074oken": SECRET})
    assert SECRET not in json.dumps(masked) and paths


def test_a_hex_escaped_letter_in_a_key_does_not_hide_it():
    """The same for ``\\x74oken``."""
    masker = Masker()
    assert masker.is_secret_key("\\x74oken")
    masked, paths = masker.mask_json({"\\x74oken": SECRET})
    assert SECRET not in json.dumps(masked) and paths


@pytest.mark.parametrize("name", ["²", "½", "①", "token²"])
def test_a_number_that_is_no_digit_adds_no_digit_to_a_key(name):
    """NFKC would make ``2`` of ``²``: a mask key of it alone would be a needle of one digit."""
    from mcp_kymograph.masking import normalise_key

    assert normalise_key(name) == name.rstrip("²½①").lower()
