"""The rule for ``name=value`` pairs in text (src/mcp_kymograph/masking.py, ``Masker._mask_pairs``):
a name that is, or holds, a secret's name loses its value in prose and in JSON values, not only
in HTTP values. It runs after the other text rules. HTTP keeps its own rule.
"""

from __future__ import annotations

import json

import pytest

from mcp_kymograph.masking import PLACEHOLDER, Masker, _SchemeValues


def _made_up(*parts: str) -> str:
    """Fake credentials are put together when the test runs, never written whole."""
    return "".join(parts)


#: Made up for these tests; no earlier text rule knows its shape.
SECRET = _made_up("OPAQUE", "-CREDEN", "TIAL")


def test_a_credential_in_a_url_in_a_json_value_is_masked():
    """A case found in a security review: 0 hits before."""
    document = {"result": f"https://x/cb?access_token={SECRET}"}
    masked, paths = Masker().mask_json(document)
    assert SECRET not in json.dumps(masked)
    assert masked == {"result": f"https://x/cb?access_token={PLACEHOLDER}"}
    assert paths == ["result"]


def test_a_credential_in_a_pair_in_text_is_masked():
    """A second case from that review: 0 hits before."""
    assert Masker().mask_text(f"api_key={SECRET}") == (f"api_key={PLACEHOLDER}", 1)


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ('Bearer="SECRET"', f"Bearer={PLACEHOLDER}"),
        ("token = 'SECRET'", f"token={PLACEHOLDER}"),
        ("token=SECRETabcd&x=1", f"token={PLACEHOLDER}&x=1"),
    ],
    ids=range(3),
)
def test_the_cases_the_scheme_rule_leaves_alone_are_masked_by_the_pair_rule(text, masked):
    text = text.replace("SECRET", SECRET)
    assert _SchemeValues().subn(PLACEHOLDER, text) == (text, 0)
    assert Masker().mask_text(text) == (masked, 1)


@pytest.mark.parametrize(
    "name",
    ["access_token", "api_key", "token", "secret", "password", "apiKey", "client_secret"],
)
def test_a_common_secret_name_stays_and_its_value_goes(name):
    assert Masker().mask_text(f"{name}={SECRET}") == (f"{name}={PLACEHOLDER}", 1)


@pytest.mark.parametrize("name", ["X-Api-Key", "token_abc", "author"])
def test_a_name_holding_a_needle_goes_with_its_value(name):
    """What follows the needle may be the credential; ``auth`` in ``author`` is deliberate."""
    assert Masker().mask_text(f"{name}=x") == (f"{PLACEHOLDER}={PLACEHOLDER}", 1)


@pytest.mark.parametrize("text", ["x=1", "SGVsbG8=", "aGk=", "a=b&c=d", "total=5"])
def test_other_names_and_padding_are_kept(text):
    assert Masker().mask_text(text) == (text, 0)


def test_a_name_that_does_not_read_like_one_is_kept_in_text():
    run = "0123456789abcdef" * 4
    text = f"{run}={SECRET}"
    assert Masker().mask_text(text) == (text, 0)


def test_a_percent_encoded_name_is_read_decoded():
    assert Masker().mask_text("api%5Fkey=x") == (f"api%5Fkey={PLACEHOLDER}", 1)


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ('token="a&b;c" rest', f"token={PLACEHOLDER}"),
        ("password=correct horse", f"password={PLACEHOLDER}"),
        ("token=a b\nnext line", f"token={PLACEHOLDER}\nnext line"),
        ("token=a b\r\nnext=1", f"token={PLACEHOLDER}\r\nnext=1"),
        ("token=abc&next=1", f"token={PLACEHOLDER}&next=1"),
        ("token=abc;next=1", f"token={PLACEHOLDER};next=1"),
        ("see /cb?token=abc#frag", f"see /cb?token={PLACEHOLDER}#frag"),
        ("token =\t'abc'", f"token={PLACEHOLDER}"),
        ("token = <a;b>&x=1", f"token={PLACEHOLDER}&x=1"),
        ('token="open\nnext=1', f"token={PLACEHOLDER}\nnext=1"),
        (
            "go to https://x/cb?code=abc&state=1 now",
            f"go to https://x/cb?code={PLACEHOLDER}&state=1 now",
        ),
    ],
)
def test_the_value_runs_to_its_end(text, masked):
    assert Masker().mask_text(text) == (masked, 1)


def test_a_json_document_recorded_as_text_is_masked_through_its_escapes():
    text = r"{\"x\":\"token=\"a;b\"\"}"
    assert "a;b" not in Masker().mask_text(text)[0]


@pytest.mark.parametrize("text", ["token=", "token=\nnext", "token= \t", "token=&x=1"])
def test_an_empty_value_does_not_count(text):
    assert Masker().mask_text(text) == (text, 0)


def test_each_pair_is_one_hit():
    masked, hits = Masker().mask_text(f"token={SECRET}\npassword={SECRET}\nx=1")
    assert (masked, hits) == (f"token={PLACEHOLDER}\npassword={PLACEHOLDER}\nx=1", 2)


def test_the_pair_runs_after_the_other_text_rules():
    """``Bearer`` must still stand for the scheme rule: the token behind it goes with it."""
    text = f"token=Bearer {SECRET}12345"
    masked, hits = Masker().mask_text(text)
    assert SECRET not in masked
    assert hits >= 1


def test_mask_json_covers_nested_values_and_reports_paths():
    document = {
        "a": {"b": [f"note password={SECRET}", "fine"]},
        "c": [{"d": f"x\ntoken = '{SECRET}'\ny=1"}],
        "e": "x=1",
    }
    masked, paths = Masker().mask_json(document)
    assert SECRET not in json.dumps(masked)
    assert masked["a"]["b"] == [f"note password={PLACEHOLDER}", "fine"]
    assert masked["c"][0]["d"] == f"x\ntoken={PLACEHOLDER}\ny=1"
    assert masked["e"] == "x=1"
    assert paths == ["a.b[0]", "c[0].d"]


def test_the_http_functions_do_not_get_the_pair_rule():
    """``token = abc`` is not a pair to ``_mask_embedded_query``; ``_scrub`` reads as before."""
    masker = Masker()
    assert masker._mask_shapes("token = abc") == ("token = abc", 0)
    assert masker._scrub("token = abc") == ("token = abc", 0)
    assert masker._scrub("token=abc") == (f"token={PLACEHOLDER}", 1)


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ("{api_key=" + SECRET + ", user=x}", f"{PLACEHOLDER}={PLACEHOLDER}"),
        ("Config{apiKey=" + SECRET + "}", f"{PLACEHOLDER}={PLACEHOLDER}"),
        ("a\\napi_key=" + SECRET, f"{PLACEHOLDER}={PLACEHOLDER}"),
        ("api%20key=" + SECRET, f"{PLACEHOLDER}={PLACEHOLDER}"),
        ("x " + "a" * 100 + "token=" + SECRET, f"x {PLACEHOLDER}={PLACEHOLDER}"),
    ],
    ids=["java map", "toString", "escaped line break", "percent space", "long name"],
)
def test_a_name_holding_a_needle_that_reads_like_no_name_goes_with_its_value(text, masked):
    """Fail closed, as in HTTP: what decides is the needle, not whether the name looks like one."""
    assert Masker().mask_text(text) == (masked, 1)


def test_a_name_an_earlier_rule_replaced_still_loses_its_value():
    text = "sk-" + "token-abcdefghijklmnop=" + SECRET
    masked, hits = Masker().mask_text(text)
    assert SECRET not in masked
    assert (masked, hits) == (f"{PLACEHOLDER}={PLACEHOLDER}", 2)


def test_a_value_an_earlier_rule_replaced_whole_is_not_counted_again():
    key = "s" + "k-" + "a" * 24
    assert Masker().mask_text(f"api_key={key}") == (f"api_key={PLACEHOLDER}", 1)
    assert Masker().mask_text(f"api_key = {key}") == (f"api_key={PLACEHOLDER}", 1)


def test_a_value_an_earlier_rule_replaced_in_part_counts_for_the_pair_too():
    """Each rule counts what it replaced, as elsewhere in the module: the scheme rule the
    credential, the pair rule the rest of the value."""
    masked, hits = Masker().mask_text("token=Bearer " + SECRET)
    assert (masked, hits) == (f"token={PLACEHOLDER}", 2)


@pytest.mark.parametrize("space", ["\u00a0", "\u2009", "\u3000", " \t\u00a0"])
def test_any_horizontal_white_space_may_stand_around_the_equals_sign(space):
    text = f"api_key{space}={space}{SECRET} end"
    assert Masker().mask_text(text) == (f"api_key={PLACEHOLDER}", 1)


def test_a_line_break_before_the_equals_sign_makes_no_pair():
    """Deliberate: a pair stands on one line, like its value."""
    text = f"api_key\n={SECRET}"
    assert Masker().mask_text(text) == (text, 0)


@pytest.mark.parametrize("after", ["", " ", "\t", " ", " ", "  \t "])
@pytest.mark.parametrize("before", ["", " ", " ", " "])
def test_any_horizontal_white_space_around_the_equals_sign_is_skipped(before, after):
    """U+00A0 and U+2009 around ``=`` do not keep the value, in text and in JSON. (This does not
    tell the skipping of blanks from a greedy value; the next test does.)"""
    text = f"api_key{before}={after}{SECRET}"
    masked, hits = Masker().mask_text(text)
    assert SECRET not in masked
    assert hits == 1
    document, paths = Masker().mask_json({"v": text})
    assert SECRET not in json.dumps(document)
    assert paths == ["v"]


@pytest.mark.parametrize("blank", [" ", "\t", " ", " "])
@pytest.mark.parametrize("tail", ["", ";next=1", "&next=1"])
def test_white_space_alone_after_the_equals_sign_is_no_value_whatever_it_is(blank, tail):
    """U+00A0 and U+2009 are skipped as a space is, so no value is left to blank;
    skipping only space and tab would take the blank itself for the value."""
    text = f"api_key={blank}{tail}"
    assert Masker().mask_text(text) == (text, 0)
