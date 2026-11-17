"""The scheme rule of the text rules (src/mcp_kymograph/masking.py, ``_SchemeValues``, the first of
``_TEXT_RULES``): a credential after ``Bearer``, ``Basic`` or ``Token`` in quotes (double, single,
backticks, typographic in two classes) or brackets, which the bare rule cannot see because a quote
is not a token character. The scheme may be followed by white space, by nothing (``Bearer"x"``) or
by a colon (``Bearer: "x"``), or stand as the key of a pair (``{"Token": "x"}``). Every occurrence
of a scheme is looked at for itself and the union of the values found is masked, so a scheme that
itself stands in quotes (``'Token' or Bearer 'x'``) cannot swallow the real value. A closer ends a
value only with as many backslashes in front as the opener had (``Bearer "a\\"x"``).
An early, simpler form of the rule stays behind it as the lower bound.

``tests`` below also hold the reference the rule must equal on any input (the oracle), and a
later form of the rule as a second lower bound.
"""

from __future__ import annotations

import random
import re
import time

import pytest

from mcp_kymograph.masking import PLACEHOLDER, Masker, _SchemeValues


def _made_up(*parts: str) -> str:
    """Fake credentials are put together when the test runs, never written whole."""
    return "".join(parts)


#: Made up for these tests.
SECRET = _made_up("s3cr", "3t-", "value")
#: Shaped like an API key, so an earlier rule masks it first.
SHAPED_KEY = _made_up("s", "k-", "a" * 20)


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        (f'Bearer "{SECRET}"', f"Bearer {PLACEHOLDER}"),
        (f"Bearer '{SECRET}'", f"Bearer {PLACEHOLDER}"),
        (f"Bearer <{SECRET}>", f"Bearer {PLACEHOLDER}"),
        (f'Authorization: Bearer "{SECRET}" sent', f"Authorization: Bearer {PLACEHOLDER} sent"),
        (f'bEaReR " {SECRET} two "', f"bEaReR {PLACEHOLDER}"),
        (f"BEARER < {SECRET} >.", f"BEARER {PLACEHOLDER}."),
        (f"basic '{SECRET} x'", f"basic {PLACEHOLDER}"),
        (f"Token <{SECRET}>", f"Token {PLACEHOLDER}"),
        (f'Bearer\t\t"{SECRET}"', f"Bearer {PLACEHOLDER}"),
        ('Bearer "x"', f"Bearer {PLACEHOLDER}"),  # any length: the quotes say a value follows
        ('Bearer ""', f"Bearer {PLACEHOLDER}"),
        ("Bearer ''", f"Bearer {PLACEHOLDER}"),
        ("Bearer <>", f"Bearer {PLACEHOLDER}"),
        (f'"Bearer "{SECRET}""', f'"Bearer {PLACEHOLDER}"'),
        (f"say 'Bearer <{SECRET}>' then", f"say 'Bearer {PLACEHOLDER}' then"),
        (f"Bearer \\'{SECRET}\\'", f"Bearer {PLACEHOLDER}"),  # a Python repr
    ],
    ids=range(16),  # the values are no test names: they would carry the secret into logs
)
def test_a_quoted_credential_is_masked_whole(text, masked):
    assert Masker().mask_text(text) == (masked, 1)


def test_an_escaped_quote_opens_too_for_json_recorded_as_text():
    text = f'{{"text": "use Bearer \\"{SECRET} x\\" now"}}'
    masked, hits = Masker().mask_text(text)
    assert (masked, hits) == (f'{{"text": "use Bearer {PLACEHOLDER} now"}}', 1)


@pytest.mark.parametrize("opener", ['"', "'", "<"])
def test_a_quote_that_never_closes_is_masked_to_the_end_of_the_line(opener):
    masked, hits = Masker().mask_text(f"Bearer {opener}{SECRET} and more\nnext line")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER}\nnext line", 1)


def test_two_quoted_credentials_on_one_line_are_two():
    masked, hits = Masker().mask_text(f"Bearer '{SECRET}' or Basic <{SECRET}> here")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} or Basic {PLACEHOLDER} here", 2)


@pytest.mark.parametrize(("opener", "closer"), [('"', '"'), ("'", "'"), ("<", ">"), ('\\"', '\\"')])
def test_a_value_a_later_rule_would_mask_is_masked_whole_by_the_scheme_rule(opener, closer):
    """The scheme rule runs first and replaces the quoted value with its key; the rule for the
    key finds nothing left. One credential, one replacement, and nothing of it left."""
    masked, hits = Masker().mask_text(f"Bearer {opener}{SHAPED_KEY}{closer} ok")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} ok", 1)


@pytest.mark.parametrize(
    ("opener", "other", "closer"),
    [('"', "'", '"'), ("<", '"', ">"), ("'", ">", "'"), ('\\"', "'", '\\"')],
)
def test_a_value_masked_only_in_front_leaves_nothing_behind(opener, other, closer):
    """A key inside the value is no reason to stop; what follows, after a quote character of
    another kind, is still part of it. The scheme rule runs first and takes it whole."""
    text = f"Bearer {opener}{SHAPED_KEY}{other}{SECRET}{closer}"
    masked, hits = Masker().mask_text(text)
    assert SECRET not in masked
    assert (masked, hits) == (f"Bearer {PLACEHOLDER}", 1)


def test_a_value_escaped_twice_is_masked_whole():
    """A JSON document inside a JSON string, recorded as text: the quote is escaped twice."""
    escaped = "\\" * 3 + '"'
    masked, hits = Masker().mask_text(f"Bearer {escaped}{SECRET} x{escaped} now")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} now", 1)


@pytest.mark.parametrize("opener", ['"', "'", "<"])
def test_a_carriage_return_ends_an_unclosed_value_too(opener):
    masked, hits = Masker().mask_text(f"Bearer {opener}{SECRET}\r\nnext")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER}\r\nnext", 1)


@pytest.mark.parametrize("separator", ["\n", "\r", "\u00a0", "  \t "])
def test_any_white_space_may_stand_between_scheme_and_quote(separator):
    masked, hits = Masker().mask_text(f'Bearer{separator}"{SECRET}"')
    assert (masked, hits) == (f"Bearer {PLACEHOLDER}", 1)


@pytest.mark.parametrize(
    "text",
    ["no scheme here", f'xBearer "{SECRET}"', f'Bearers "{SECRET}"', "Bearer", "Bearer   ",
     "Token-based auth", f'xBearer: "{SECRET}"', f"Bearers({SECRET})"],
    ids=range(8),
)  # fmt: skip
def test_what_is_no_quoted_credential_is_left_alone(text):
    assert Masker().mask_text(text) == (text, 0)


@pytest.mark.parametrize("scheme", ["Bearer", "Basic", "Token"])
@pytest.mark.parametrize(
    ("opener", "closer"),
    [
        (': "', '"'),
        (':"', '"'),
        (" :\t'", "'"),
        ('"', '"'),
        ("'", "'"),
        ("<", ">"),
        (" (", ")"),
        ("(", ")"),
        (": (", ")"),
    ],
    ids=[
        "colon",
        "colon, no space",
        "white space around colon",
        "no space",
        "no space, single",
        "no space, angle",
        "parentheses",
        "no space, parentheses",
        "colon, parentheses",
    ],
)
def test_a_credential_after_colon_without_space_or_in_parentheses_is_masked(scheme, opener, closer):
    masked, hits = Masker().mask_text(f"{scheme}{opener}{SECRET}{closer} ok")
    assert (masked, hits) == (f"{scheme} {PLACEHOLDER} ok", 1)


def test_colon_and_parenthesis_go_with_the_value():
    assert Masker().mask_text(f"Token: ({SECRET})") == (f"Token {PLACEHOLDER}", 1)
    assert Masker().mask_text(f'bearer : "{SECRET}"') == (f"bearer {PLACEHOLDER}", 1)


def test_a_parenthesis_that_never_closes_is_masked_to_the_end_of_the_line():
    masked, hits = Masker().mask_text(f"Bearer ({SECRET} and more\nnext line")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER}\nnext line", 1)


def test_two_values_of_the_new_forms_on_one_line_are_two():
    masked, hits = Masker().mask_text(f'Bearer: "{SECRET}" and Basic ({SECRET}) here')
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} and Basic {PLACEHOLDER} here", 2)


def test_prose_with_a_parenthesis_after_the_scheme_is_masked_on_purpose():
    """Deliberate (rule 2): the rule cannot tell prose from a value, and too much masked in
    a recording costs nothing."""
    assert Masker().mask_text("Token (optional)") == (f"Token {PLACEHOLDER}", 1)


@pytest.mark.parametrize(
    "text",
    [
        "Bearer:",
        "Bearer: ",
        "Bearer :  ",
        "Token:\n",
        f'Bearer:: "{SECRET}"',
        f"Bearer:: ({SECRET})",
    ],
    ids=range(6),
)
def test_a_colon_without_value_or_a_second_colon_is_left_alone(text):
    assert Masker().mask_text(text) == (text, 0)


@pytest.mark.parametrize("backslashes", [1, 3, 7])
@pytest.mark.parametrize("quote", ['"', "'"])
def test_a_quote_escaped_for_any_depth_opens(backslashes, quote):
    escaped = "\\" * backslashes + quote
    masked, hits = Masker().mask_text(f"Bearer {escaped}{SECRET} x{escaped} now")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} now", 1)


@pytest.mark.parametrize("separator", ["\x0b", "\u2028", "\x1c"], ids=["vt", "ls", "fs"])
@pytest.mark.parametrize(("opener", "closer"), [('"', '"'), ("'", "'"), ("<", ">")])
def test_only_cr_and_lf_end_a_value(separator, opener, closer):
    """Python splits lines at more characters than these; a value goes on past all the others."""
    masked, hits = Masker().mask_text(f"Bearer {opener}{SECRET}{separator}{SECRET}{closer} ok")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} ok", 1)


TYPOGRAPHIC_DOUBLE = "“”„‟«»"
TYPOGRAPHIC_SINGLE = "‘’‚‛‹›"


@pytest.mark.parametrize("scheme", ["Bearer", "Basic", "Token"])
@pytest.mark.parametrize(
    ("opener", "closer"),
    [("“", "”"), ("„", "“"), ("‘", "’"), ("«", "»"), ("»", "«")],
)
def test_a_value_in_typographic_quotes_is_masked(scheme, opener, closer):
    masked, hits = Masker().mask_text(f"{scheme} {opener}{SECRET}{closer} ok")
    assert (masked, hits) == (f"{scheme} {PLACEHOLDER} ok", 1)


@pytest.mark.parametrize(
    "quotes", [TYPOGRAPHIC_DOUBLE, TYPOGRAPHIC_SINGLE], ids=["double", "single"]
)
def test_every_character_of_a_class_opens_and_closes(quotes):
    for opener in quotes:
        for closer in quotes:
            masked, hits = Masker().mask_text(f"Bearer {opener}{SECRET}{closer} ok")
            assert (masked, hits) == (f"Bearer {PLACEHOLDER} ok", 1)


@pytest.mark.parametrize(
    "quotes", [TYPOGRAPHIC_DOUBLE, TYPOGRAPHIC_SINGLE], ids=["double", "single"]
)
def test_a_typographic_quote_that_never_closes_is_masked_to_the_end_of_the_line(quotes):
    masked, hits = Masker().mask_text(f"Bearer {quotes[0]}{SECRET} and more\nnext line")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER}\nnext line", 1)


@pytest.mark.parametrize(
    "quotes", [TYPOGRAPHIC_DOUBLE, TYPOGRAPHIC_SINGLE], ids=["double", "single"]
)
@pytest.mark.parametrize(
    "separator", [": ", " : ", ":", ""], ids=["colon", "spaced", "bare", "none"]
)
def test_typographic_quotes_after_colon_or_without_white_space(quotes, separator):
    masked, hits = Masker().mask_text(f"Token{separator}{quotes[0]}{SECRET}{quotes[-1]} ok")
    assert (masked, hits) == (f"Token {PLACEHOLDER} ok", 1)


def test_the_other_class_does_not_close_a_typographic_value():
    masked, hits = Masker().mask_text(f"Bearer “{SECRET} ‘a’ more” ok")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} ok", 1)


def test_an_apostrophe_after_the_scheme_is_masked_on_purpose():
    """Deliberate (rule 2): with no white space required ``Bearer’s`` opens a value."""
    assert Masker().mask_text("Bearer’s token") == (f"Bearer {PLACEHOLDER}", 1)


def test_the_bare_rule_is_unchanged():
    assert Masker().mask_text(f"Bearer {SECRET} ok") == (f"Bearer {PLACEHOLDER} ok", 1)
    assert Masker().mask_text("Bearer short") == ("Bearer short", 0)


#: Hostile inputs of size n: many starts, and long runs of white space where the rule could
#: backtrack — after the scheme, inside an opened quote, around a placeholder.
HOSTILE = {
    "many starts": lambda n: "Bearer " * (n // 7),
    "many unclosed": lambda n: 'Bearer "\n' * (n // 9),
    "many brackets": lambda n: "Token <\n" * (n // 8),
    "mixed case": lambda n: "bEaReR\t" * (n // 7),
    "space after scheme": lambda n: "Bearer" + " " * n + "x",
    "space in quote": lambda n: 'Bearer "' + " " * n + "x",
    "space around placeholder": lambda n: 'Bearer "' + " " * n + PLACEHOLDER + " " * n + "x",
    "backslashes": lambda n: "Bearer " + "\\" * n + "x",
    "colon without value": lambda n: "Bearer :" + " " * n + "x",
    "many colons": lambda n: "Token : " * (n // 8),
    "many parentheses": lambda n: "Basic (\n" * (n // 8),
    "space around colon": lambda n: "Bearer" + " " * n + ":" + " " * n + "x",
    "space in parenthesis": lambda n: "Bearer (" + " " * n + "x",
    "chain of quoted schemes": lambda n: "'Token' Bearer " * (n // 15) + "'x'",
    "chain of colons": lambda n: "Token': " * (n // 8) + "'x'",
    "value ending in scheme, no closer": lambda n: "Bearer ' Token\n" * (n // 15),
    "many typographic unclosed": lambda n: "Bearer “\n" * (n // 9) + "Token ‘\n" * (n // 9),
    "many typographic pairs": lambda n: "Basic „x“ " * (n // 10) + "Token »x« " * (n // 10),
    "space in typographic quote": lambda n: "Bearer «" + " " * n + "x",
    "typographic quotes only": lambda n: "Bearer " + "“‘" * (n // 2),
    "space before typographic closer": lambda n: "Bearer ‘" + " " * n + "Token" + " " * n + "’",
    "chain of open values over lines": lambda n: "Token’ Bearer:\n" * (n // 15) + "'x'",
    "space before closer": lambda n: "Bearer '" + " " * n + "Token" + " " * n + "'",
    "many open square brackets": lambda n: "Bearer [" * (n // 8),
    "many open braces": lambda n: "Bearer {" * (n // 8),
    "many open backticks": lambda n: "Bearer `" * (n // 8),
    "many depths": lambda n: (
        "".join("Bearer " + "\\" * k + '"' for k in range(int(n**0.5))) + '"' * n
    ),
    "closers before word characters": lambda n: "Bearer '" + "'a" * (n // 2),
    "long backslash runs before closers": lambda n: 'Bearer "' + ("\\" * 50 + '"') * (n // 51),
    "many key forms": lambda n: '\'"Token": ' * (n // 11),
    "many bare values after a colon": lambda n: "Token: abcdefgh " * (n // 16),
    "many escaped line breaks": lambda n: "Token\\n" * (n // 7),
    "chain of quoted schemes, no closer": lambda n: "'Token' Bearer " * (n // 15),
}


@pytest.mark.parametrize("build", HOSTILE.values(), ids=HOSTILE.keys())
def test_hostile_input_is_masked_in_linear_time(build):
    """Four times the input must cost about four times the time, not sixteen. The best of
    three runs is compared, and the bound is generous so that a slow machine does not fail it."""
    masker = Masker()

    def best(text: str) -> float:
        runs = []
        for _ in range(3):
            started = time.perf_counter()
            masker.mask_text(text)
            runs.append(time.perf_counter() - started)
        return min(runs)

    small = best(build(200_000))
    large = best(build(800_000))
    assert large < 12 * max(small, 0.005)


@pytest.mark.parametrize(
    ("text", "masked", "hits"),
    [
        ("'Token' or Bearer '{s}'", f"'Token {PLACEHOLDER}", 2),
        ('expected "Bearer" scheme, got Bearer "{s}"', f'expected "Bearer {PLACEHOLDER}', 2),
        ('type \\"Token\\" then Bearer \\"{s}\\"', f'type \\"Token {PLACEHOLDER}', 2),
        ("'Token' then Bearer: '{s}'", f"'Token {PLACEHOLDER}", 2),
        ("'Token' then Bearer : '{s}' ok", f"'Token {PLACEHOLDER} ok", 2),
        ("(Token) and Bearer ({s})", f"(Token) and Bearer {PLACEHOLDER}", 1),
        # a chain of three: the value of the first scheme runs to the end of the line, and the
        # spans of the others lie inside it, so there is one replacement for three occurrences
        ("Basic' Token' Bearer '{s}' ok", f"Basic {PLACEHOLDER} ok", 3),
        # the quote in front of the secret is followed by a word character and closes nothing;
        # the span of the first scheme ends behind the quote after it, the next is its own
        ("Token' Bearer '{s}' or Basic '{s}'", f"Token {PLACEHOLDER} or Basic {PLACEHOLDER}", 3),
        # the escape in front of the closing quote belongs to the closer, not to the value: the
        # value still ends in a scheme and its colon
        ('type \\"Token\\" then Bearer: \\"{s}\\"', f'type \\"Token {PLACEHOLDER}', 2),
        ('type \\"Token\\" then Bearer : \\"{s}\\" ok', f'type \\"Token {PLACEHOLDER} ok', 2),
    ],
    ids=range(10),
)
def test_a_quoted_scheme_does_not_swallow_the_opener_of_the_real_value(text, masked, hits):
    """The stretch from the quoted scheme to the real value is replaced once, from the first
    scheme; each match it joins counts."""
    assert Masker().mask_text(text.replace("{s}", SECRET)) == (masked, hits)


@pytest.mark.parametrize(
    ("text", "masked", "hits"),
    [
        ("Token’ Bearer:\n'{s}'", f"Token {PLACEHOLDER}", 2),
        ("‘Token’ or Bearer:\n'{s}'", f"‘Token {PLACEHOLDER}", 2),
        ("'Token' or Bearer:\n'{s}'", f"'Token {PLACEHOLDER}", 2),
        ("Token’ Bearer:\r\n'{s}'", f"Token {PLACEHOLDER}", 2),
        ("Token’ Bearer:\n“{s}”", f"Token {PLACEHOLDER}", 2),
        ("Token’ Bearer:\n'{s}' ok", f"Token {PLACEHOLDER} ok", 2),
        # no value follows the last scheme: as before, the open value to the end of its line
        ("Token’ Bearer:\nnichts", f"Token {PLACEHOLDER}\nnichts", 1),
    ],
    ids=range(7),
)
def test_an_open_value_ending_in_a_scheme_is_carried_on_to_the_next_line(text, masked, hits):
    result = Masker().mask_text(text.replace("{s}", SECRET))
    assert SECRET not in result[0]
    assert result == (masked, hits)


#: The early form of the rule, character for character: the reference for what must never be left.
_OLD_RULE = re.compile(
    r"\b(Bearer|Basic|Token)\s+(?:\\*\"[^\"\r\n]*\"?|\\*'[^'\r\n]*'?|<[^>\r\n]*>?)",
    re.IGNORECASE,
)

_LEAK = "SECRET"

_FIXED_LINES = [
    "'Token' or Bearer 'SECRET'",
    'expected "Bearer" scheme, got Bearer "SECRET"',
    'type \\"Token\\" then Bearer \\"SECRET\\"',
    "'Token' or Bearer\n'SECRET'",
    "'Token' or Bearer\r'SECRET'",
    "'Token' or Bearer\r\n'SECRET'",
    "'Token' or Bearer\n\"SECRET\"",
    "\"Token\" or Bearer\n'SECRET'",
    "Bearer:\n'SECRET'",
    'Bearer :\n"SECRET"',
    "'Token' Bearer " * 3 + "'SECRET'",
    "Token' Bearer\n" * 3 + "'SECRET'",
    "Basic' Token' Bearer 'SECRET' ok",
]


def _random_lines(count):
    rng = random.Random(6971)  # noqa: S311 - a fixed seed makes the cases the same each run
    schemes = ["Bearer", "Basic", "Token", "bEaReR"]
    others = ["'", '"', "(", ")", "<", ">", ":", " ", "  ", "\t", "\n", "\r", "\r\n", "\\", "x"]
    for _ in range(count):
        # some noise, a scheme and a few pieces in front of the secret, then a tail of noise
        parts = [rng.choice(schemes + others) for _ in range(rng.randint(0, 5))]
        parts += [rng.choice(schemes), *(rng.choice(others) for _ in range(rng.randint(0, 3)))]
        parts += [_LEAK, *(rng.choice(schemes + others) for _ in range(rng.randint(0, 5)))]
        yield "".join(parts)


def test_nothing_the_rule_of_007dac0_masked_is_left_by_the_rules_now():
    """A lower bound: where the old rule alone removes the secret from a line, the masker does
    too. The new forms may add to what is masked, never take away."""
    masker = Masker()
    checked = 0
    for text in [*_FIXED_LINES, *_random_lines(20_000)]:
        if _LEAK in _OLD_RULE.sub(rf"\1 {PLACEHOLDER}", text):
            continue
        checked += 1
        assert _LEAK not in masker.mask_text(text)[0], repr(text)
    assert checked > 500


@pytest.mark.parametrize("text", _FIXED_LINES, ids=range(len(_FIXED_LINES)))
def test_the_fixed_lines_leave_no_secret(text):
    assert _LEAK not in Masker().mask_text(text)[0]


#: Where the rule says a value is, with what it must make of the line. ``SECRET`` stands for
#: the made-up secret above.
COVERED = [
    ("'Token' or Bearer: \"it's SECRET\"", "'Token ***REDACTED***", 2),
    ("'Token' or Bearer (it's SECRET)", "'Token ***REDACTED***", 2),
    ("'Token' or Bearer:\n'SECRET'", "'Token ***REDACTED***", 2),
    ("Token’ Bearer:\n'x Basic:\"y' SECRET\"", "Token ***REDACTED***", 3),
    ('Bearer "prefix\\"SECRET"', "Bearer ***REDACTED***", 1),
    ('Bearer: "abc\\"SECRET"', "Bearer ***REDACTED***", 1),
    ("{'Token': 'SECRET'}", "{'Token ***REDACTED***}", 1),
    ('{"Token": "SECRET"}', '{"Token ***REDACTED***}', 1),
    ('{\\"token\\": \\"SECRET\\"}', '{\\"token ***REDACTED***}', 1),
    ('type \\"Token\\" then Bearer: \\"SECRET\\"', 'type \\"Token ***REDACTED***', 2),
    ("'Token' or Bearer 'SECRET'", "'Token ***REDACTED***", 2),
    ("'Token' or Bearer\n'SECRET'", "'Token ***REDACTED***", 2),
    ("Token’ Bearer:\n'SECRET'", "Token ***REDACTED***", 2),
    ("Token’ Bearer:\n[SECRET]", "Token ***REDACTED***", 2),
    ("'Token' Bearer 'Token' Bearer 'Token' Bearer 'SECRET'", "'Token ***REDACTED***", 6),
    (
        "Token' Bearer\nToken' Bearer\nToken' Bearer\n'SECRET'",
        "Token ***REDACTED***\nToken ***REDACTED***\nToken ***REDACTED***",
        4,
    ),
    ("Basic' Token' Bearer 'SECRET' ok", "Basic ***REDACTED*** ok", 3),
    ("Bearer [SECRET]", "Bearer ***REDACTED***", 1),
    ("Bearer {SECRET}", "Bearer ***REDACTED***", 1),
    ("Bearer \\(SECRET\\)", "Bearer ***REDACTED***", 1),
    ("Bearer \\(a\\)SECRET\\)", "Bearer ***REDACTED***", 1),
    ("Bearer: SECRETabcd", "Bearer ***REDACTED***", 1),
    ("Bearer 'it\\'s SECRET'", "Bearer ***REDACTED***", 1),
    ("Bearer (a\\)SECRET)", "Bearer ***REDACTED***", 1),
    ("Bearer <a\\>SECRET>", "Bearer ***REDACTED***", 1),
    ("Bearer “a\\”SECRET”", "Bearer ***REDACTED***", 1),
    (
        '{"text": "use Bearer \\"a\\\\\\"SECRET\\" now"}',
        '{"text": "use Bearer ***REDACTED*** now"}',
        1,
    ),
    ("Bearer 'it's SECRET'", "Bearer ***REDACTED***", 1),
    ("Bearer ‘it’s SECRET’", "Bearer ***REDACTED***", 1),
    ("Bearer `SECRET`", "Bearer ***REDACTED***", 1),
    ("Authorization: Token `SECRET`", "Authorization: Token ***REDACTED***", 1),
    ('Bearer\\n\\"SECRET\\"', "Bearer ***REDACTED***", 1),
    ("Bearer abcdefgh.Token 'SECRET'", "Bearer ***REDACTED***", 2),
    ('{"Token": {"a": "SECRET"}}', '{"Token ***REDACTED***}', 1),
]


def _with_secret(text: str) -> str:
    return text.replace("SECRET", SECRET)


#: What the rule leaves alone on purpose (reasons in the tests at the end of the file), with
#: what it must make of the line.
NOT_COVERED = [
    ('Bearer="SECRET"', 'Bearer="SECRET"', 0),
    ("token = 'SECRET'", "token = 'SECRET'", 0),
    ("token=SECRETabcd&x=1", "token=SECRETabcd&x=1", 0),
    ('Bearer:: "SECRET"', 'Bearer:: "SECRET"', 0),
    ("Bearer;'SECRET'", "Bearer;'SECRET'", 0),
    ('Bearer,"SECRET"', 'Bearer,"SECRET"', 0),
    ('Bearer "abc\nSECRET"', 'Bearer ***REDACTED***\nSECRET"', 1),
    ("Bearer 'abc' SECRET'", "Bearer ***REDACTED*** SECRET'", 1),
    ("Bea\u200brer 'SECRET'", "Bea\u200brer 'SECRET'", 0),
    ("Bearer &quot;SECRET&quot;", "Bearer &quot;SECRET&quot;", 0),
    ("Bearer%20SECRETabcd", "Bearer%20SECRETabcd", 0),
]


@pytest.mark.parametrize(("text", "masked", "hits"), COVERED, ids=range(len(COVERED)))
def test_every_covered_case_gives_exactly_its_text_and_count(text, masked, hits):
    result = Masker().mask_text(_with_secret(text))
    assert SECRET not in result[0]
    assert result == (masked, hits)


@pytest.mark.parametrize(("text", "masked", "hits"), COVERED, ids=range(len(COVERED)))
def test_the_scheme_rule_alone_gives_the_same_on_every_covered_case(text, masked, hits):
    """What the rule makes of the line is what the masker makes of it: no later rule is needed."""
    assert _SchemeValues().subn(PLACEHOLDER, _with_secret(text)) == (masked, hits)


@pytest.mark.parametrize(("text", "masked", "hits"), COVERED, ids=range(len(COVERED)))
def test_the_reference_gives_the_covered_cases(text, masked, hits):
    assert _reference(_with_secret(text)) == (masked, hits)


#: The first three of NOT_COVERED, which the scheme rule leaves alone and the rule for
#: ``name=value`` pairs masks: what the masker makes of them.
MASKED_BY_THE_PAIR_RULE = {
    'Bearer="SECRET"': (f"Bearer={PLACEHOLDER}", 1),
    "token = 'SECRET'": (f"token={PLACEHOLDER}", 1),
    "token=SECRETabcd&x=1": (f"token={PLACEHOLDER}&x=1", 1),
    # The normalised copy: the whole value goes, one match more than the text had.
    "Bea" + chr(0x200B) + "rer 'SECRET'": (PLACEHOLDER, 1),
}


@pytest.mark.parametrize(("text", "masked", "hits"), NOT_COVERED, ids=range(len(NOT_COVERED)))
def test_every_case_left_alone_gives_exactly_its_text_and_count(text, masked, hits):
    """Left alone by the scheme rule; the three pairs are masked by the rule for ``name=value``
    pairs, nothing else changes."""
    if text in MASKED_BY_THE_PAIR_RULE:
        masked, hits = MASKED_BY_THE_PAIR_RULE[text]
    result = Masker().mask_text(_with_secret(text))
    assert SECRET not in result[0] or text not in MASKED_BY_THE_PAIR_RULE
    assert result == (_with_secret(masked), hits)


@pytest.mark.parametrize(("text", "masked", "hits"), NOT_COVERED, ids=range(len(NOT_COVERED)))
def test_the_scheme_rule_alone_gives_the_same_on_every_case_left_alone(text, masked, hits):
    assert _SchemeValues().subn(PLACEHOLDER, _with_secret(text)) == (_with_secret(masked), hits)


@pytest.mark.parametrize(("text", "masked", "hits"), NOT_COVERED, ids=range(len(NOT_COVERED)))
def test_the_reference_gives_the_cases_left_alone(text, masked, hits):
    assert _reference(_with_secret(text)) == (_with_secret(masked), hits)


# The reference: the specification as code, quadratic on purpose. The rule must give the same
# (text, hits) on every input.
_SCHEME_WORD = re.compile(r"\b(?:Bearer|Basic|Token)", re.IGNORECASE)
_PAIRS = {"<": ">", "(": ")", "[": "]", "{": "}"}
_SAME = "\"'`"
_KEY_QUOTES = _SAME + TYPOGRAPHIC_DOUBLE + TYPOGRAPHIC_SINGLE
_BARE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=")
_BARE_MIN = 8
_EOL = "\r\n"


def _ref_closers(opener):
    if opener in _PAIRS:
        return _PAIRS[opener]
    if opener in _SAME:
        return opener
    if opener in TYPOGRAPHIC_DOUBLE:
        return TYPOGRAPHIC_DOUBLE
    if opener in TYPOGRAPHIC_SINGLE:
        return TYPOGRAPHIC_SINGLE
    return None


def _ref_word(ch):
    return ch.isalnum() or ch == "_"


def _ref_skip_space(t, i):
    while i < len(t):
        if t[i].isspace():
            i += 1
            continue
        if t[i] == "\\":
            j = i
            while j < len(t) and t[j] == "\\":
                j += 1
            if j < len(t) and t[j] in "nrt":
                i = j + 1
                continue
        break
    return i


def _ref_value_starts(t, e):
    starts = []
    a = _ref_skip_space(t, e)
    starts.append((a, a > e))
    if a < len(t) and t[a] == ":":
        starts.append((_ref_skip_space(t, a + 1), True))
    j = e
    while j < len(t) and t[j] == "\\":
        j += 1
    if j < len(t) and t[j] in _KEY_QUOTES:
        c = _ref_skip_space(t, j + 1)
        if c < len(t) and t[c] == ":":
            starts.append((_ref_skip_space(t, c + 1), True))
    return starts


def _ref_value_end(t, s, separated):
    j = s
    while j < len(t) and t[j] == "\\":
        j += 1
    depth = j - s
    close = _ref_closers(t[j]) if j < len(t) else None
    if close is not None:
        i = j + 1
        while i < len(t) and t[i] not in _EOL:
            if t[i] in close:
                run = 0
                while t[i - 1 - run] == "\\":
                    run += 1
                after = t[i + 1] if i + 1 < len(t) else ""
                if run == depth and not _ref_word(after):
                    return i + 1
            i += 1
        return i
    if depth == 0 and separated:
        i = s
        while i < len(t) and t[i] in _BARE:
            i += 1
        if i - s >= _BARE_MIN:
            return i
    return None


def _reference(t):
    spans = []
    for m in _SCHEME_WORD.finditer(t):
        ends = [
            v
            for s, sep in _ref_value_starts(t, m.end())
            if (v := _ref_value_end(t, s, sep)) is not None
        ]
        if ends:
            spans.append((m.start(), m.end(), max(ends)))
    out, done, i = [], 0, 0
    while i < len(spans):
        start, scheme_end, stop = spans[i]
        i += 1
        while i < len(spans) and spans[i][0] < stop:
            stop = max(stop, spans[i][2])
            i += 1
        out += [t[done:start], t[start:scheme_end], " ", PLACEHOLDER]
        done = stop
    out.append(t[done:])
    return "".join(out), len(spans)


_ORACLE_PARTS = [
    *["Bearer", "Basic", "Token", "bEaReR", "BASIC", "token"],
    *"<>()[]{}\"'`",
    *TYPOGRAPHIC_DOUBLE,
    *TYPOGRAPHIC_SINGLE,
    *":;,= \t\n\r",
    "\r\n",
    "\u00a0",
    *("\\" * k for k in range(1, 5)),
    "\\n",
    "\\t",
    *"xs_",
    "abcdefgh12",
    PLACEHOLDER,
]


def _oracle_lines(count):
    rng = random.Random(7301)  # noqa: S311 - a fixed seed makes the cases the same each run
    for _ in range(count):
        yield "".join(rng.choice(_ORACLE_PARTS) for _ in range(rng.randint(0, 40)))


def test_the_rule_equals_the_reference_on_random_lines():
    rule = _SchemeValues()
    with_value = 0
    for text in _oracle_lines(25_000):
        expected = _reference(text)
        assert rule.subn(PLACEHOLDER, text) == expected, repr(text)
        with_value += expected[1] > 0
    assert with_value > 5_000  # the lines are not all without a value


class _Rule2d2ac5a:
    """The later form of the rule, character for character: ``_SchemeValue`` with
    ``_carried_on``, the second lower bound."""

    _SCHEME = re.compile(r"Bearer|Basic|Token", re.IGNORECASE)
    _PATTERN = re.compile(
        r"\b(Bearer|Basic|Token)(?:\s*:)?\s*"
        r"(?:\\*\"([^\"\r\n]*)(\"?)|\\*'([^'\r\n]*)('?)|<([^>\r\n]*)(>?)|\(([^)\r\n]*)(\)?)"
        r"|[“”„‟«»]([^“”„‟«»\r\n]*)([“”„‟«»]?)|[‘’‚‛‹›]([^‘’‚‛‹›\r\n]*)([‘’‚‛‹›]?))",
        re.IGNORECASE,
    )

    def subn(self, repl, string):
        pattern = self._PATTERN
        found = pattern.search(string)
        if found is None:
            return string, 0
        out = []
        done = count = 0
        while found is not None:
            first = last = found
            count += 1
            while (nxt := self._carried_on(string, last)) is not None:
                last = nxt
                count += 1
            out.append(string[done : first.start()])
            out.append(first.expand(repl))
            done = last.end()
            found = pattern.search(string, done)
        out.append(string[done:])
        return "".join(out), count

    def _carried_on(self, string, found):
        for branch in (2, 4, 6, 8, 10, 12):
            if found.start(branch) != -1:
                break
        else:
            return None
        floor, end = found.start(branch), found.end(branch)
        if branch in (2, 4):  # the escape in front of the closing quote belongs to the closer
            while end > floor and string[end - 1] == "\\":
                end -= 1
        while end > floor and string[end - 1].isspace():
            end -= 1
        if end > floor and string[end - 1] == ":":
            end -= 1
            while end > floor and string[end - 1].isspace():
                end -= 1
        for length in (5, 6):
            if end - length >= floor and self._SCHEME.fullmatch(string, end - length, end):
                return self._PATTERN.match(string, end - length)
        return None


def _wide_lines(count):
    rng = random.Random(7302)  # noqa: S311 - a fixed seed makes the cases the same each run
    schemes = ["Bearer", "Basic", "Token", "bEaReR"]
    others = [
        *"'\"`()<>[]{}:;, =\t\n\r\\xs_",
        "\r\n",
        "\u00a0",
        *"“”„‟«»‘’‚‛‹›",
        '\\"',
        *("\\" * k for k in range(2, 5)),
        "\\n",
        "\\t",
        "abcdefgh12",
        PLACEHOLDER,
    ]
    for _ in range(count):
        parts = [rng.choice(schemes + others) for _ in range(rng.randint(0, 6))]
        parts += [rng.choice(schemes), *(rng.choice(others) for _ in range(rng.randint(0, 3)))]
        parts += [_LEAK, *(rng.choice(schemes + others) for _ in range(rng.randint(0, 6)))]
        yield "".join(parts)


def test_nothing_the_rule_of_2d2ac5a_masked_is_left_by_the_rules_now():
    """A second lower bound: where that rule alone removes the secret from a line, the masker
    does too."""
    masker, old = Masker(), _Rule2d2ac5a()
    checked = 0
    for text in [*_FIXED_LINES, *_wide_lines(20_000)]:
        if _LEAK in old.subn(rf"\1 {PLACEHOLDER}", text)[0]:
            continue
        checked += 1
        assert _LEAK not in masker.mask_text(text)[0], repr(text)
    assert checked > 500


def test_a_bare_value_after_a_colon_is_eight_characters_at_least():
    assert Masker().mask_text("Bearer: abcdefg") == ("Bearer: abcdefg", 0)
    assert Masker().mask_text("Bearer: abcdefgh") == (f"Bearer {PLACEHOLDER}", 1)


# What the rule leaves alone on purpose, each case with its reason.


def test_a_name_value_pair_with_an_equals_sign_is_left_to_the_pair_rule():
    """``=`` is no separator of this rule: ``name=value`` belongs to the pair rule. With
    ``=`` here ``?X-Amz-Security-Token=...`` would become
    ``?X-Amz-Security-Token ***REDACTED***``. The scheme rule alone leaves them standing; the
    masker masks them by the pair rule."""
    for text in ['Bearer="{s}"', "token = '{s}'", "token={s}&x=1"]:
        text = text.replace("{s}", SECRET)
        assert _SchemeValues().subn(PLACEHOLDER, text) == (text, 0)
        masked, hits = Masker().mask_text(text)
        assert SECRET not in masked
        assert hits == 1


def test_a_double_colon_is_a_path_separator_and_no_separator_of_a_value():
    """``Token::new(...)`` in code: no header or assignment format writes a value after ``::``."""
    text = f'Bearer:: "{SECRET}"'
    assert Masker().mask_text(text) == (text, 0)


@pytest.mark.parametrize("text", ["Bearer;'{s}'", 'Bearer,"{s}"'])
def test_a_semicolon_or_comma_separates_entries_not_a_name_from_its_value(text):
    """A scheme in such a list is found at its own occurrence."""
    text = text.replace("{s}", SECRET)
    assert Masker().mask_text(text) == (text, 0)


def test_a_line_break_in_a_value_ends_it():
    """A secret holds no line break; a value across lines would let an open quote mask the rest
    of a document, and the end of the line keeps the rule linear."""
    masked, hits = Masker().mask_text(f'Bearer "abc\n{SECRET}"')
    assert (masked, hits) == (f'Bearer {PLACEHOLDER}\n{SECRET}"', 1)


def test_a_closer_in_front_of_a_non_word_character_ends_a_value():
    """``Bearer 'abc' x'`` cannot be told from a closed value with text behind it."""
    masked, hits = Masker().mask_text(f"Bearer 'abc' {SECRET}'")
    assert (masked, hits) == (f"Bearer {PLACEHOLDER} {SECRET}'", 1)


def test_a_zero_width_character_in_the_scheme_is_masked_whole_by_the_normalised_copy():
    """The copy finds the scheme, so the whole value is replaced."""
    text = f"Bea\u200brer '{SECRET}'"
    assert Masker().mask_text(text) == (PLACEHOLDER, 1)


@pytest.mark.parametrize("text", ["Bearer &quot;{s}&quot;", "Bearer%20{s}"])
def test_an_encoded_value_is_for_a_layer_of_its_own(text):
    """Decode first, then mask: that needs a layer of its own, which the text rules are not."""
    text = text.replace("{s}", SECRET)
    assert Masker().mask_text(text) == (text, 0)
