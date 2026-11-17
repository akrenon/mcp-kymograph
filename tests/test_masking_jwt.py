"""The JSON Web Token text rule (src/mcp_kymograph/masking.py, ``_JwtShape``): the same matches as
the regular expression it replaces, in time linear in the text.

The expression it replaces is kept here, and only here, as the reference: whatever it found,
the scanner finds, and replaces the same way.

Every token-shaped value is put together when the test runs, never written whole.
"""

from __future__ import annotations

import base64
import itertools
import json
import random
import re
import subprocess
import sys
import time

import pytest

from mcp_kymograph.masking import PLACEHOLDER, Masker, _JwtShape

#: How a header starts: base64url of ``{"``.
H = "ey" + "J"

#: The rule as it was: quadratic in a long run of header-shaped text without a dot at its end.
REFERENCE = re.compile(r"\b" + H + r"[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


def _segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token() -> str:
    """A token in the usual form, made up for these tests and signed by nobody."""
    header = _segment(json.dumps({"alg": "none"}).encode())
    payload = _segment(json.dumps({"sub": "x"}).encode())
    return ".".join((header, payload, _segment(b"signature")))


def _shape(*segments: str) -> str:
    """Header, payload and signature as given, the header behind its usual start."""
    return ".".join((H + segments[0], *segments[1:]))


TOKEN = _token()
UNSIGNED = TOKEN[: TOKEN.rindex(".") + 1]

POSITIVES = [
    TOKEN,
    f"Authorization: Bearer {TOKEN}",
    f"token={TOKEN}&next=1",
    f'{{"id_token": "{TOKEN}"}}',
    f"x-{TOKEN}",
    UNSIGNED,
    f"{TOKEN} and {TOKEN}",
    f"https://example.org/cb#access_token={TOKEN}",
    f"a{_shape('xxxx', 'yyyy', 'zz')} then {TOKEN}",  # the first is no word start
    f"{_shape('abc', 'defg', 'h')} {_shape('abcd', 'efgh', 'i')}",  # first header too short
    f"{_shape('abcd', 'efg', 'h')}-{TOKEN}",  # the first payload too short
    f"é{TOKEN} -{TOKEN}",  # a letter before is no word start; a hyphen is
    f"{TOKEN}.more.dots",
    f"{_shape('abcd', '', 'efgh', 'i')} {_shape('', 'abcd', 'efgh')}",
    f"{UNSIGNED} next",  # no signature, and the word after it is no part of it
    f"x_{TOKEN} _{TOKEN}",  # an underscore before is no word start
    f"1{TOKEN} 1.{TOKEN}",  # nor is a digit
    f"a{H}x-{_shape('abcd', 'efgh', 'ij')}",  # the second header start in the run counts
    f"{TOKEN} {TOKEN}",  # two tokens with one character between them
    f"{TOKEN}\n{TOKEN}",
    f"{UNSIGNED} {TOKEN}",
    f"{_shape('abcd', 'efgh', H + 'ijkl')}.mnop.q",  # a signature is never the next header
]


# Test IDs are numbers: the values are token-shaped, and an ID ends up in logs.
@pytest.mark.parametrize("text", POSITIVES, ids=range(len(POSITIVES)))
def test_the_scanner_finds_what_the_expression_found(text):
    assert _JwtShape().subn(PLACEHOLDER, text) == REFERENCE.subn(PLACEHOLDER, text)


def test_a_token_in_prose_is_masked_whole():
    masked, hits = Masker().mask_text(f"use {TOKEN} now")
    assert (masked, hits) == (f"use {PLACEHOLDER} now", 1)


@pytest.mark.parametrize(
    "text",
    ["", "no token here", H, H + "abcd", _shape("abcd", "efgh"), "x" + _shape("abcd", "efgh", "i"),
     _shape("abc", "efgh", "i"), _shape("abcd", "efg", "i"), H + "abcd efgh.i",
     _shape("abcd", "efgh i", "j")],
    ids=range(10),
)  # fmt: skip
def test_what_is_no_token_is_left_alone(text):
    assert _JwtShape().subn(PLACEHOLDER, text) == (text, 0) == REFERENCE.subn(PLACEHOLDER, text)


def test_the_scanner_agrees_with_the_expression_on_every_short_text():
    """Every text of up to six pieces from a small alphabet that holds all the ways the two
    could part on where a token starts: header starts, letters, a digit, non-word characters, a
    non-ASCII letter, dots. Six pieces are too few for a token; the next test has tokens."""
    rule = _JwtShape()
    for length in range(7):
        for pieces in itertools.product(
            [H, "aa", "a", "1", "-", ".", "_", " ", "é"], repeat=length
        ):
            text = "".join(pieces)
            assert rule.subn(PLACEHOLDER, text) == REFERENCE.subn(PLACEHOLDER, text), pieces


def test_the_scanner_agrees_with_the_expression_on_texts_full_of_tokens():
    """Texts drawn with a fixed seed from whole tokens, near misses and what can stand between
    them: most hold several tokens, many of them directly after each other."""
    rule = _JwtShape()
    pieces = [TOKEN, UNSIGNED, _shape("abcd", "efgh"), H + "abc", " ", "\n", ".", "-", "a", "é"]
    draw = random.Random(20261008)  # noqa: S311 - a fixed seed, so that a failure repeats
    for index in range(20_000):
        text = "".join(draw.choice(pieces) for _ in range(draw.randint(1, 12)))
        assert rule.subn(PLACEHOLDER, text) == REFERENCE.subn(PLACEHOLDER, text), index


def test_a_word_start_is_what_the_expression_takes_it_for():
    """The scanner decides ``\\b`` by ``isalnum()`` or ``_``; ``re`` by its own tables. For
    every code point the two must agree."""
    word = re.compile(r"\w")
    for code in range(sys.maxunicode + 1):
        char = chr(code)
        assert (char.isalnum() or char == "_") == bool(word.match(char)), hex(code)


#: Hostile inputs: a unit repeated to size, an end after it, and the smaller of the two sizes
#: measured. The ends are the ways a long run can fail to be a token — no dot, a payload too
#: short, a payload without its dot — and the way it can succeed; a failing end is what made
#: the old expression quadratic, and it is measured small so that a quadratic rule fails in
#: seconds. The other inputs drive the scanner's own loops, and are measured larger so that a
#: quadratic loop stands out from the noise.
HOSTILE = {
    "header runs, no end": (H + "aaaa-", "", 10_000),
    "header runs, short payload": (H + "aaaa-", ".abc.", 10_000),
    "header runs, payload without dot": (H + "aaaa-", ".abcd", 10_000),
    "header runs, then a payload": (H + "aaaa-", ".abcd.", 25_000),
    "many short runs": (H + "a.", "", 25_000),
    "header starts in one run": ("a" + H, ".abcd.", 25_000),
    "many near misses": (_shape("aaaa", "a."), "", 25_000),
    "many tokens": (_shape("aaaa", "aaaa", "b "), "", 50_000),
    "runs without a header start": ("a.", _shape("abcd", "efgh", "i"), 25_000),
    "runs with a header start inside": ("a" + H + ".", "", 2_500),
}


@pytest.mark.parametrize(("unit", "end", "size"), HOSTILE.values(), ids=HOSTILE.keys())
def test_hostile_input_is_masked_in_linear_time(unit, end, size):
    """Eight times the input must cost about eight times the time, not sixty-four. The best of
    three runs is compared, the bound is three times what linear needs so that a slow machine
    does not fail it; the floor of a millisecond keeps the noise of very short runs out. The
    old expression needed about a second for 80 000 characters of the first input, sixty
    times what it needed for 10 000."""
    rule = _JwtShape()

    def best(text: str) -> float:
        runs = []
        for _ in range(3):
            started = time.perf_counter()
            rule.subn(PLACEHOLDER, text)
            runs.append(time.perf_counter() - started)
        return min(runs)

    small = best(unit * (size // len(unit)) + end)
    large = best(unit * (8 * size // len(unit)) + end)
    assert large < 24 * max(small, 0.001)


#: The most a call may take in a process of its own. Far above what these inputs need (a few
#: milliseconds, an interpreter start besides), so that a slow machine does not trip it.
HARD_LIMIT = 20

#: Texts the masking must come back from, with what it must make of them. The first has a header
#: start behind a letter only, so the search for the next one runs to the end of the run and
#: stops at ``-1``; the others have the one that counts at the start of the text, at the start
#: of a later word, and behind a letter and a hyphen.
NO_PROGRESS = {
    "header starts behind a letter only": (("a" + H) * 20_000 + ".abcd.efgh", None),
    "a header start at the start of the text": (_shape("abcd", "efgh", "ijkl"), PLACEHOLDER),
    "a header start at the start of a later word": (
        "x " + _shape("abcd", "efgh", "ijkl"),
        "x " + PLACEHOLDER,
    ),
    "a header start behind a letter, then one behind a hyphen": (
        "a" + H + "bcd-" + _shape("abcd", "efgh", "ijkl"),
        "a" + H + "bcd-" + PLACEHOLDER,
    ),
}


@pytest.mark.parametrize(("text", "masked"), NO_PROGRESS.values(), ids=NO_PROGRESS.keys())
def test_the_masking_comes_back_in_a_process_of_its_own(text, masked):
    """A search that stops moving forward does not end, and a test in the same process would
    hang with it. This one runs the masking in another process and gives it a hard limit."""
    code = (
        "import sys\n"
        "from mcp_kymograph.masking import Masker\n"
        "print(repr(Masker().mask_text(sys.argv[1])[0]))"
    )
    try:
        run = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code, text],
            capture_output=True,
            text=True,
            timeout=HARD_LIMIT,
        )
    except subprocess.TimeoutExpired:
        run = None
    assert run is not None, f"the masking did not come back within {HARD_LIMIT} s"
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == repr(text if masked is None else masked)
