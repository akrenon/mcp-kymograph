"""Every signal and every masking rule, on large hostile inputs, in time linear in the input.

A server under test chooses every string these rules read. Each input below is one that drives
a rule's pattern hardest: a prefix that starts a match again and again, a run that a bounded
quantifier reads to its end, an opening that never closes. Each is made to two sizes, eight
times apart, and every rule is timed on its own: each test of the signal library on the text
as written and, where it reads content, as normalised; the normalisation itself; each masking
rule. One rule's time must grow about eightfold, not sixtyfourfold. Timed together, a
quadratic rule hides among the linear ones: the sum of all the others grows eightfold and
drowns it.

Only the growth is judged here, not what a rule costs per character: a bounded repetition
started at every position is linear with its bound as a factor, and passes. Each such pattern
has a test of its own that compares its cost with a reference (the opener of a hidden
comment, in test_signals_comment_scan.py).

Token prefixes are put together when the test runs, never written out.
"""

from __future__ import annotations

import math
import sys
import time
from collections.abc import Callable
from functools import partial

import pytest

from mcp_kymograph import masking
from mcp_kymograph.masking import _TEXT_RULES
from mcp_kymograph.signals import LIBRARY, View, normalize

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="processor time there ticks in steps of 15.6 ms"
)

SMALL = 5_000
LARGE = 8 * SMALL

#: How much more than eightfold a rule may take before it counts as too slow: three times
#: what linear needs, so that a slow machine does not fail it. Quadratic needs sixtyfourfold.
BOUND = 24

#: How long one timed sample lasts at the least: a rule faster than this is run as many times
#: over as it takes, and its time is the sample's divided by the count. No time is too short
#: to compare, then, and no comparison falls back on a fixed number of milliseconds. Each size
#: finds its own count, by doubling, so that a run that is slow on the large input is never
#: repeated because it was fast on the small one.
SAMPLE = 0.001

#: A rule already this far past linear needs no more runs to be judged. Above sixtyfourfold, so
#: that only a rule worse than quadratic stops early; a quadratic one is run in full.
HOPELESS = 100

#: A rule this slow on the small input is first tried at twice its size, where linear doubles.
#: One that grows past the cube root of the bound there would grow past the bound itself at
#: eight times the size, so it fails there, rather than taking minutes on the large input.
SLOW = 0.05


def _join(*parts: str) -> str:
    return "".join(parts)


#: The input that drives the rule for JSON Web Tokens: a header start, a run, a hyphen — a
#: start after every hyphen, and no dot anywhere.
JWT_INPUT = "token header starts in one run"

#: One input per pattern it is aimed at; the name says which. A string is a unit repeated to
#: size; a triple is a start, a unit repeated, and an end.
HOSTILE: dict[str, str | tuple[str, str, str]] = {
    "base64 run without end": "A" * 30 + "!",
    "base64 run ending in padding": ("", "A", "==="),
    "html tag opener": "<a ",
    "html tag with spaces": "<p" + " " * 10,
    "comment opener": "<!--",
    "comment opener with text": "<!-- x ",
    "long tag name": "<a" + "b" * 29 + " ",
    "padding": " " * 29 + "x",
    "line markup": "\n   #",
    "blank lines": "\n \n",
    "spaces and tabs": " \t",
    "percent": "%z",
    "markdown comment": "\n   [//",
    "chat template": "<|im_",
    "inst marker": "[/INS",
    "role line": "\n        assistant    x",
    "override": "ignore the ",
    "override, longer": "ignore all previous ",
    "output directive": "print your ",
    "concealment": "do not tell the ",
    "model addressed, role": "you are a ",
    "imperative": ". please    x",
    "sentence end, then only space": (".", " ", ""),
    "second person": "you    x",
    "url host": "www." + "a" * 63,
    "url scheme": "http:/",
    "data scheme": "data",
    "invisible": "\u200b",
    "entity": "&#x",
    # References with more digits than Python turns into a number.
    "decimal reference, long": ("&#", "1", ""),
    "hex reference, long": ("&#x", "f", ""),
    "decimal references, nine digits each": "&#" + "1" * 9,
    "hex references, nine digits each": "&#x" + "f" * 9,
    "decimal reference of zeros": ("&#", "0", ""),
    "hex reference of zeros": ("&#x", "0", ""),
    "references of zeros, one after another": "&#" + "0" * 20,
    "percent encoded": "%25",
    "scheme without value": "Token  ",
    "scheme with short value": "Bearer x.",
    "scheme with colon, no value": "Bearer :  ",
    "scheme with open parenthesis": "Token (",
    "scheme with open typographic quote": "Token “",
    "scheme with open single typographic quote": "Bearer ‘ ",
    "quoted scheme chain": "'Token' Bearer ",
    "quoted scheme chain, colons": "Token': ",
    "typographic quoted scheme chain": "‘Token’ Bearer ",
    "typographic quoted scheme chain, colons": "Token’: ",
    "typographic value ending in scheme, no closer": "Bearer „ Token\n",
    "chain of open values over lines": ("", "Token’ Bearer:\n", "'x'"),
    "scheme with open square bracket": "Bearer [",
    "scheme with open brace": "Bearer {",
    "scheme with open backtick": "Bearer `",
    "scheme with key form": '\'"Token": ',
    "scheme with bare value after colon": "Token: abcdefgh ",
    "scheme with escaped line break": "Token\\n",
    "closers before word characters": ("Bearer '", "'a", ""),
    "long backslash runs before closers": ('Bearer "', "\\" * 50 + '"', ""),
    "depths": 'Bearer \\\\\\"Bearer \\\\"Bearer \\"',
    "quoted scheme chain, no closer": "'Token' Bearer ",
    "typographic quotes only": "Bearer “‘",
    "value ending in scheme, no closer": "Bearer ' Token\n",
    "value ending in scheme, much white space": ("Bearer ' Token", " ", ""),
    "scheme with much white space": ("Basic", " ", "x"),
    "colon with much white space": ("Bearer :", " ", "x"),
    # The rule for name=value pairs (Masker._mask_pairs): names read once whatever follows.
    "names without a pair": "token ",
    "secret names without a value": "token=\n",
    "secret names with an empty value, spaced": "password = ",
    "secret names, values left open": "token='\n",
    "secret names, open quote on one line": 'token="a ',
    "much white space before the equals sign": ("token", " ", "=x"),
    "much white space after the equals sign": ("token=", "\t", "x"),
    "pairs apart": "a=1&token=x&",
    "key prefix": _join("s", "k-ant-"),
    "github prefix": _join("gh", "p_aaaa"),
    "github pat prefix": _join("github", "_pat_a"),
    "slack prefix": _join("xo", "xb-aa"),
    "aws prefix": _join("AK", "IA"),
    "google prefix": _join("AI", "za") + "a" * 34 + "-",
    # The same prefixes with a word boundary after each, so every one is a start of its own.
    "key prefixes apart": _join("s", "k-ant- "),
    "github prefixes apart": _join("gh", "p_aaaa "),
    "github pat prefixes apart": _join("github", "_pat_a "),
    "slack prefixes apart": _join("xo", "xb-aa "),
    "aws prefixes apart": _join("AK", "IA "),
    # Starts of their own inside one run of the characters the rule reads on: a hyphen is a
    # word boundary, and the run never ends where the rule could stop.
    "slack prefixes in one run": _join("xo", "xb-aa-"),
    JWT_INPUT: _join("ey", "J") + "a" * 30 + "-",
    # Near misses: each starts the pattern and never completes it, so a search reads on.
    "tag without hiding": '<a style="color: red; width: 10px">',
    "model addressed, no verb": "ai said that ",
    "concealment, without": "without telling ",
    "concealment, keep": "keep this ",
    "output directive, reply first": "your reply ",
    # The URL rules (test_masking_url.py): an authority over many "://", and the encoded
    # forms the decoding view reads, each a piece of its own.
    "many :// in one authority": ("a://", "u:p://", "@h"),
    "many :// behind a scheme without a letter": "1://a",
    "many encoded @ in one authority": ("a://", "&#64;", ""),
    "many encoded ://": "a%3A//",
    "many twice-encoded ://": "a%253A%252F%252F",
    "many json-escaped ://": "a:\\/\\/",
    "many \\u escapes": "\\u0040",
    "many entities": "&#x40;&commat;&#58;",
    "many full-width forms": "a：／／＠",
    "encoded pieces out of ASCII": "%C3%A9\\u00e9&#233;",
    "many networks of a go dsn": "u:p@unixpacket(@udp6(@tcp4(",
    "go dsn anchors behind a scheme": "m://***REDACTED***@tcp(",
}


def _jwt_rule() -> str:
    """The name of the masking rule for JSON Web Tokens, found by what it does: the one rule
    that masks a token of that shape, put together here."""
    token = ".".join((_join("ey", "J", "hdrx"), "body", "sign"))
    (index,) = [i for i, (rule, repl) in enumerate(_TEXT_RULES) if rule.subn(repl, token)[1]]
    return f"masking rule {index}"


JWT_RULE = _jwt_rule()

#: Whether the linear scan that replaces the quadratic expression is in. Asked of the module,
#: not of the rule list: put back into the list while the scan is still there, the expression
#: would be measured here and fail, not be expected to.
JWT_SCANNER_IS_IN = hasattr(masking, "_JwtShape")


class _Text:
    """One input at one size, with its normalised view made once and only when asked for: a
    normalisation that has turned slow is measured as such, not paid for up front."""

    def __init__(self, entry: str | tuple[str, str, str], size: int) -> None:
        start, unit, end = ("", entry, "") if isinstance(entry, str) else entry
        body = size - len(start) - len(end)
        self.raw = start + (unit * (body // len(unit) + 1))[:body] + end
        self._normalized: str | None = None

    @property
    def normalized(self) -> str:
        if self._normalized is None:
            self._normalized, _ = normalize(self.raw)
        return self._normalized


def _on_normalized(test: Callable[[str], bool], text: _Text) -> bool:
    return test(text.normalized)


def _rules(text: _Text) -> dict[str, Callable[[], object]]:
    """Every rule on its own, ready to run on this text; the normalisation first."""
    rules: dict[str, Callable[[], object]] = {"normalisation": partial(normalize, text.raw)}
    for definition in LIBRARY:
        if definition.test is None:
            continue
        rules[f"{definition.signal.value}, as written"] = partial(definition.test, text.raw)
        if definition.view is View.CONTENT:
            name = f"{definition.signal.value}, normalised"
            rules[name] = partial(_on_normalized, definition.test, text)
    for index, (rule, replacement) in enumerate(_TEXT_RULES):
        rules[f"masking rule {index}"] = partial(rule.subn, replacement, text.raw)
    rules["masking pair rule"] = partial(masking.Masker()._mask_pairs, text.raw)
    return rules


def _clock(run: Callable[[], object], count: int = 1) -> float:
    """The processor time of one run, from ``count`` runs back to back. Not the time on the
    wall: on a busy machine a run of ten milliseconds is interrupted where one of one is not,
    and the wall would grow the large input's time by however many processes share it."""
    started = time.process_time()
    for _ in range(count):
        run()
    return (time.process_time() - started) / count


def _count(run: Callable[[], object]) -> int:
    """How many runs back to back last :data:`SAMPLE`, found by doubling from one."""
    count = 1
    while _clock(run, count) * count < SAMPLE:
        count *= 2
    return count


def _best(
    small: Callable[[], object],
    large: Callable[[], object],
    runs: int,
    double: Callable[[], Callable[[], object]],
) -> tuple[float, float]:
    """The best time of one small and one large run, from a few samples taken in turn, so
    that a busy moment of the machine falls on both sizes alike. A sample repeats a run until
    it lasts :data:`SAMPLE`. ``double`` makes the rule at twice the small size, asked for only
    when the small time is already slow."""
    small()  # the first run of anything pays for what later runs find ready
    best_small = _clock(small)
    if best_small > SLOW:
        at_double = double()
        best_double = min(_clock(at_double) for _ in range(3))
        best_small = min(best_small, _clock(small))
        if best_double > BOUND ** (1 / 3) * best_small:
            return best_small, math.inf
    small_count, large_count = _count(small), _count(large)
    best_large = math.inf
    for _ in range(runs):
        best_small = min(best_small, _clock(small, small_count))
        best_large = min(best_large, _clock(large, large_count))
        if best_large > HOPELESS * best_small:
            break
    return best_small, best_large


def _measure(
    entries: dict, runs: int, rules: dict[str, list[str]] | None = None
) -> dict[tuple[str, str], tuple[float, float]]:
    """The times of the given rules (all, unless named) on each input, in the order
    :func:`_rules` lists them, so that the normalisation comes before what reads its view."""
    times: dict[tuple[str, str], tuple[float, float]] = {}
    for name, entry in entries.items():
        small_text, large_text = _Text(entry, SMALL), _Text(entry, LARGE)
        small, large = _rules(small_text), _rules(large_text)
        for rule in small:
            if rules is not None and rule not in rules.get(name, ()):
                continue
            if rule.endswith(", normalised"):
                if math.isinf(times.get((name, "normalisation"), (0.0, 0.0))[1]):
                    continue  # the normalisation itself failed here, and is reported
                _ = (small_text.normalized, large_text.normalized)  # made now, not timed
            double = partial(lambda entry, rule: _rules(_Text(entry, 2 * SMALL))[rule], entry, rule)
            times[name, rule] = _best(small[rule], large[rule], runs, double)
    return times


def _growth(times: dict) -> dict[tuple[str, str], float]:
    return {
        key: round(large / small, 1) if small else math.inf
        for key, (small, large) in times.items()
        if large > BOUND * small
    }


def _too_slow(
    entries: dict, rules: dict[str, list[str]] | None = None
) -> dict[tuple[str, str], float]:
    """Each input and rule whose time grew past the bound, with its growth.

    One that looks too slow is measured again, at more samples, and each size keeps the best
    time of both rounds: a quadratic rule stays slow however often it runs, a linear one that
    met a busy moment does not, and the best time cannot fall below the true one. One that
    already failed at twice the size is not measured again; that was no busy moment.
    """
    first = _measure(entries, 3, rules)
    suspects = {key for key in _growth(first) if not math.isinf(first[key][1])}
    again_for: dict[str, list[str]] = {}
    for name, rule in suspects:
        again_for.setdefault(name, []).append(rule)
    again = _measure({name: entries[name] for name in again_for}, 7, again_for)
    combined = dict(first)
    for key in suspects:
        combined[key] = (min(first[key][0], again[key][0]), min(first[key][1], again[key][1]))
    return _growth(combined)


def test_every_rule_on_every_hostile_input_runs_in_linear_time():
    """All but one pair: the rule for JSON Web Tokens on the input aimed at it has its own."""
    rules = {name: list(_rules(_Text(entry, 8))) for name, entry in HOSTILE.items()}
    rules[JWT_INPUT].remove(JWT_RULE)
    assert _too_slow(HOSTILE, rules) == {}


@pytest.mark.xfail(
    not JWT_SCANNER_IS_IN,
    reason="the rule for JSON Web Tokens is the quadratic expression until the scanner replaces it",
    raises=AssertionError,
    strict=True,
)
def test_the_rule_for_json_web_tokens_runs_in_linear_time():
    """Strict, and only for a time that is too long: once the scan is in, this passes, and
    then it has to."""
    assert _too_slow({JWT_INPUT: HOSTILE[JWT_INPUT]}, {JWT_INPUT: [JWT_RULE]}) == {}


def test_a_base64_run_past_the_decoding_bound_is_scanned_in_linear_time():
    """The pattern has no upper limit, so a run of any length is found; the part that is
    decoded stays fixed, and the rest costs one pass."""
    from mcp_kymograph.signals import MAX_BASE64_CHARS

    def best(size: int, unit: str) -> float:
        text = unit * size
        times = []
        for _ in range(5):
            started = time.process_time()
            normalize(text)
            times.append(time.process_time() - started)
        return min(times)

    for unit in ("ICAg", "A", "A" * 29 + "!"):
        small = (2 * MAX_BASE64_CHARS) // len(unit) + 1
        assert best(8 * small, unit) <= BOUND * max(best(small, unit), 1e-4), unit
