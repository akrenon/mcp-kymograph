"""The web interface's h() only sets attributes from SAFE_ATTRS (plus on, href, aria-*, data-*).
A key outside that makes h() throw at run time and the view shows "could not be drawn". This reads
app.js as text, without a browser, and finds such keys where they can be seen statically."""

import re
from pathlib import Path

import pytest

import mcp_kymograph

APP_JS = Path(mcp_kymograph.__file__).parent / "web" / "static" / "app.js"
EXTRA = {"on", "href"}
PREFIXES = ("aria-", "data-")

CALL = re.compile(r"(?<![\w$.])h\(")
IDENT = re.compile(r"[A-Za-z_$][\w$]*")
SPREAD = "..."
NOT_CHECKABLE = "spread in the attributes of h(), not checkable"
# Spreads in the attributes of h() that are accepted, as {line in app.js: reason}. A spread cannot
# be checked statically, while h() throws at run time on a key it does not allow.
SPREAD_EXCEPTIONS: dict[int, str] = {}
KEY = re.compile(r"""\s*(?:(?P<bare>[A-Za-z_$][\w$-]*)|'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")\s*:""")


def allowed(text: str) -> set[str]:
    """The names in the SAFE_ATTRS set of app.js itself, plus on and href."""
    m = re.search(r"const SAFE_ATTRS = new Set\(\[(.*?)\]\)", text, re.S)
    assert m, "SAFE_ATTRS not found in app.js"
    names = set(re.findall(r"'([^']+)'", m.group(1)))
    assert "class" in names
    return names | EXTRA


def skip(text: str, i: int) -> int:
    """If a string, template or comment starts at i, the index after it; else i."""
    c = text[i]
    if c in "'\"`":
        j = i + 1
        while text[j] != c:
            j += 2 if text[j] == "\\" else 1
        return j + 1
    if text.startswith("//", i):
        j = text.find("\n", i)
        return len(text) if j < 0 else j
    if text.startswith("/*", i):
        return text.index("*/", i) + 2
    return i


def split(text: str, start: int, close: str) -> list[tuple[int, int]]:
    """The top-level pieces between start and the matching close, cut at commas."""
    pieces, depth, begin, i = [], 0, start, start
    while True:
        j = skip(text, i)
        if j != i:
            i = j
            continue
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                assert c == close, f"unbalanced at {i}"
                pieces.append((begin, i))
                return pieces
            depth -= 1
        elif c == "," and depth == 0:
            pieces.append((begin, i))
            begin = i + 1
        i += 1


def literal_keys(text: str, brace: int) -> list[tuple[str, int]]:
    """The keys of the object literal whose opening brace is at ``brace``; nested objects'
    keys are not included. A shorthand ``{ title }`` yields its name, a spread ``...x`` yields
    SPREAD."""
    keys = []
    for a, b in split(text, brace + 1, "}"):
        piece = text[a:b].strip()
        m = KEY.match(text, a)
        if piece.startswith(SPREAD):
            keys.append((SPREAD, a + text[a:b].index(SPREAD)))
        elif m and m.end() <= b:
            group = m.lastgroup
            keys.append((m.group(group), m.start(group)))
        elif IDENT.fullmatch(piece):
            keys.append((piece, a + text[a:b].index(piece)))
    return keys


def line_of(text: str, i: int) -> int:
    return text.count("\n", 0, i) + 1


def violations(text: str) -> list[tuple[int, str]]:
    """(line, key) for every attribute key given to h() that is not allowed; a spread is reported
    as NOT_CHECKABLE unless its line is in SPREAD_EXCEPTIONS."""
    ok = allowed(text)
    found, seen = [], 0

    def check(key: str, i: int) -> None:
        if key == SPREAD:
            if line_of(text, i) not in SPREAD_EXCEPTIONS:
                found.append((line_of(text, i), NOT_CHECKABLE))
        elif key not in ok and not key.startswith(PREFIXES):
            found.append((line_of(text, i), key))

    for m in CALL.finditer(text):
        args = split(text, m.end(), ")")
        if len(args) < 2:
            continue
        a, b = args[1]
        arg = text[a:b].strip()
        if arg.startswith("{"):
            seen += 1
            for key, i in literal_keys(text, a + text[a:b].index("{")):
                check(key, i)
        elif IDENT.fullmatch(arg):
            # a named object: its literal, if declared in place, and each <name>.<key> = ...
            seen += 1
            name = re.escape(arg)
            for d in re.finditer(rf"\b(?:const|let|var)\s+{name}\s*=\s*\{{", text):
                for key, i in literal_keys(text, d.end() - 1):
                    check(key, i)
            for s in re.finditer(rf"(?<![\w$.]){name}\.([A-Za-z_$][\w$]*)\s*=(?!=)", text):
                check(s.group(1), s.start(1))
    assert seen > 100, "the scan found too few h() calls with attributes; it is broken"
    return sorted(set(found))


@pytest.fixture(scope="module")
def source() -> str:
    return APP_JS.read_text(encoding="utf-8")


def test_h_gets_only_allowed_attributes(source):
    assert violations(source) == []


def test_the_check_catches_a_title_in_a_literal(source):
    marker = "h('span', { class: 'sub' }, ...kids)"
    assert marker in source
    bad = source.replace(marker, "h('span', { class: 'sub', title: 'x' }, ...kids)", 1)
    assert [key for _, key in violations(bad)] == ["title"]
    quoted = bad.replace("title: 'x'", "'title': 'x'")
    assert [key for _, key in violations(quoted)] == ["title"]


def test_the_check_catches_an_assigned_attribute(source):
    marker = "chips.push(h('span', { class: 'tag t-find' },"
    assert marker in source
    bad = source.replace(
        marker,
        "const props = { class: 'tag t-find' }; props.title = 'x'; chips.push(h('span', props,",
        1,
    )
    assert [key for _, key in violations(bad)] == ["title"]


def test_the_check_catches_a_shorthand_key(source):
    marker = "h('span', { class: 'sub' }, ...kids)"
    assert marker in source
    for literal in ("{ class: 'sub', title }", "{ title }", "{ class: 'sub', title, }"):
        bad = source.replace(marker, f"h('span', {literal}, ...kids)", 1)
        assert [key for _, key in violations(bad)] == ["title"]
    fine = source.replace(marker, "h('span', { class: 'sub', href }, ...kids)", 1)
    assert violations(fine) == []


def test_the_check_catches_a_spread(source):
    marker = "h('span', { class: 'sub' }, ...kids)"
    assert marker in source
    bad = source.replace(marker, "h('span', { ...extra }, ...kids)", 1)
    assert [key for _, key in violations(bad)] == [NOT_CHECKABLE]
    named = source + "\nconst props = { class: 'x', ...extra }; h('span', props);\n"
    assert [key for _, key in violations(named)] == [NOT_CHECKABLE]


def test_nested_objects_and_prefixes_are_not_attributes(source):
    extra = "\nh('a', { 'aria-label': 'x', 'data-y': 1, on: { click: f, title: 1 } });\n"
    assert violations(source + extra) == []
