"""Which ids answer which request: the comparison the clients make, not ``==``."""

import time

import pytest

from mcp_kymograph.correlation import AMBIGUOUS, MAX_NUMERIC_TEXT, key_of, message_id

# -- ids a client takes for the same request ----------------------------------------------


@pytest.mark.parametrize(
    "identifier",
    [1.0, float("1e0"), "1", " 1 ", "+1", "1.0", "1e0", "0x1", "0o1", "0b1", " 1\n"],
)
def test_writings_of_one_are_the_key_of_one(identifier):
    assert key_of(identifier) == key_of(1)


def test_the_empty_and_blank_strings_are_zero():
    assert key_of("") == key_of(0)
    assert key_of("  ") == key_of(0)


def test_negative_zero_is_zero():
    assert key_of(-0.0) == key_of(0)


def test_an_underscore_string_is_the_number_the_python_sdk_reads():
    assert key_of("1_0") == key_of(10)


@pytest.mark.parametrize("identifier", [1.5, "1.5", "abc", "0x1g", "-0x1", "1n"])
def test_other_ids_are_not_the_key_of_one(identifier):
    assert key_of(identifier) != key_of(1)


def test_a_number_and_its_string_keep_their_own_meaning_apart_from_text():
    assert key_of("abc") == "abc"
    assert key_of(1.5) == 1.5


# -- no id --------------------------------------------------------------------------------


@pytest.mark.parametrize("identifier", [None, True, False, {}, []])
def test_what_is_no_id_has_no_key(identifier):
    assert key_of(identifier) is None


# -- ids the clients disagree on ----------------------------------------------------------


@pytest.mark.parametrize(
    "identifier",
    [
        float("nan"),
        float("inf"),
        -float("inf"),
        2**53 + 1,
        -(2**53) - 1,
        float(2**60),
        "Infinity",
        "-Infinity",
        "1e400",
        "9007199254740993",
    ],
)
def test_ids_the_clients_would_not_agree_on_are_ambiguous(identifier):
    assert key_of(identifier) is AMBIGUOUS


@pytest.mark.parametrize("identifier", [2**53, -(2**53)])
def test_the_largest_exact_integers_are_not_ambiguous(identifier):
    assert key_of(identifier) is not AMBIGUOUS
    assert key_of(identifier) == identifier


# -- long strings -------------------------------------------------------------------------


def test_a_long_string_that_could_be_a_number_is_ambiguous():
    assert key_of("1" * (MAX_NUMERIC_TEXT + 1)) is AMBIGUOUS


def test_a_long_string_that_cannot_be_a_number_is_itself():
    text = "a" * 10_000 + "z"
    assert key_of(text) == text


def test_a_very_long_digit_string_is_not_converted():
    started = time.perf_counter()
    assert key_of("9" * 1_000_000) is AMBIGUOUS
    assert time.perf_counter() - started < 1.0


def test_a_very_long_string_no_client_reads_as_a_number_stays_a_string():
    started = time.perf_counter()
    for text in (" " * 1_000_000 + "x", "9" * 1_000_000 + "x", "0x" + "f" * 1_000_000 + "g"):
        assert key_of(text) == text
    assert time.perf_counter() - started < 1.0


def test_a_long_string_a_client_reads_as_a_number_is_ambiguous():
    for text in (" " * 100 + "1", "1_0" * 40, "0x" + "f" * 100, "1" * 100 + ".5e3"):
        assert key_of(text) is AMBIGUOUS


# -- the id as an event carries it --------------------------------------------------------


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        (1.0, 1),
        ("1", "1"),
        (1, 1),
        (1.5, None),
        (True, None),
        (float("nan"), None),
        (float("inf"), None),
        (float(2**53), 2**53),
        (-float(2**53), -(2**53)),
        # a float is read as the same double by every client: 9007199254740993.0 is 2**53
        (9007199254740993.0, 2**53),
        # past 2**53 a recorded int could stand for another id: None
        (1e18, None),
        (float(2**60), None),
    ],
)
def test_message_id(identifier, expected):
    result = message_id(identifier)
    assert result == expected
    assert type(result) is type(expected)
