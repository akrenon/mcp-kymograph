"""The secret scan passes over the test server keys and nothing else: every entry under ``paths``
of ``.gitleaks.toml`` names one file, in full and anchored, and the file exists. A directory, or a
pattern that takes a future file with it, would let a real key into ``tests/fixtures/tls/``
unscanned."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / ".gitleaks.toml"

#: One entry: ``^``, then letters, digits, ``/``, ``_``, ``-`` or an escaped dot, then ``$``. No
#: other character of a regular expression is a path, and none is allowed.
ENTRY = re.compile(r"\^(?:[A-Za-z0-9/_-]|\\\.)+\$")


def toml_reader():
    """The TOML reader of 3.11 on; the test is skipped under 3.10, where the file is not read by
    hand."""
    return pytest.importorskip("tomllib", reason="tomllib is 3.11 on; no hand-made TOML reader")


def allowlisted_paths(text):
    document = toml_reader().loads(text)
    return [path for entry in document["allowlists"] for path in entry.get("paths", [])]


def path_named_by(pattern):
    """The one path ``pattern`` names; ``AssertionError`` for an entry that is anything else."""
    assert ENTRY.fullmatch(pattern), f"{pattern}: not ^<path>$ with escaped dots only"
    path = pattern[1:-1].replace("\\.", ".")
    assert re.fullmatch(pattern, path), f"{pattern}: does not match the path it names"
    return path


def test_the_allowlist_has_entries():
    assert allowlisted_paths(CONFIG.read_text()), "the keys are listed, or no allowlist is needed"


def test_each_entry_names_one_file_that_exists():
    for pattern in allowlisted_paths(CONFIG.read_text()):
        assert (ROOT / path_named_by(pattern)).is_file(), f"{pattern}: no such file"


@pytest.mark.parametrize(
    "entry",
    [
        "^tests/fixtures/tls/[a-z]+\\.key$",
        "^tests/fixtures/tls/localhost.key$",
        "^tests/fixtures/tls/",
        "^tests/fixtures/tls/.*$",
        "^tests/fixtures/tls/a|b$",
        "^tests/fixtures/tls/a\\\\.key$",
    ],
)
def test_an_entry_that_is_more_than_one_path_is_rejected(entry):
    with pytest.raises(AssertionError):
        path_named_by(entry)


def test_an_entry_in_a_character_class_does_not_hide_those_after_it():
    text = """
[[allowlists]]
paths = [
    '''^tests/[a-z]+\\.key$''',
    '''^tests/fixtures/tls/localhost\\.key$''',
]
"""
    assert allowlisted_paths(text) == [
        "^tests/[a-z]+\\.key$",
        "^tests/fixtures/tls/localhost\\.key$",
    ]


def test_basic_strings_and_an_indented_key_are_read():
    text = """
[[allowlists]]
  paths = ["^tests/fixtures/tls/localhost\\\\.key$"]
"""
    assert allowlisted_paths(text) == ["^tests/fixtures/tls/localhost\\.key$"]
    assert path_named_by(allowlisted_paths(text)[0]) == "tests/fixtures/tls/localhost.key"


def test_the_key_files_of_the_directory_are_all_listed():
    """A key added to the directory is a decision to take it out of the scan, made in this file
    and in the allowlist together."""
    listed = {path_named_by(pattern) for pattern in allowlisted_paths(CONFIG.read_text())}
    keys = {
        path.relative_to(ROOT).as_posix() for path in (ROOT / "tests/fixtures/tls").glob("*.key")
    }
    assert listed == keys
