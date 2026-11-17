"""A scaffold, not a browser test: how ``app.js`` reads a finding's class (CONTRACT.md).

No script is run. The field names come from the API data of a test run (``finding_class`` of a
finding the views show) and are searched for in ``app.js`` as text: that the script reads
``finding_class``, and that every place it reads one of those fields is a child of an element
(``frag(...)``, or ``h(tag, attrs, ...)`` after the attributes) wrapped in ``String()`` or
``mono()``, or a plain question whether it is there. Never inside an object literal (an
attribute), never in a template string, never assigned to a property, never with ``??``. Each
read is judged on its own, by its position. A tripwire on the raw source fails on every
spelling of the class the checks above do not know (``?.``, ``[``, destructuring, an alias,
passing it on): the new spelling has to be added to this test first. What the page shows is
looked at in a browser.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp_kymograph.web import views
from test_web_views import run_of, world  # noqa: F401

APP_JS = Path(views.__file__).parent / "static" / "app.js"

# The names the script holds a class under: the field itself and the locals made from it.
CLASS = r"\b(?:\w+\.)?(?:finding_class|fc)"
# Only asked whether it is there: ``x ?``, ``x &&``, ``if (x)``. ``??`` and ``?.`` are no question.
ASKED = r"(?:{read}\s*(?:\?(?![?.])|&&)|\bif\s*\(\s*{read}\s*\))"
# What may not follow a read: a further access (``?.``, ``.``, ``[``, a call) is no known form.
ACCESS = r"\s*(?:\?\.|\.|\[|\()"


def class_fields(world) -> dict:  # noqa: F811
    found = run_of(world, "poison")["data"]["findings"]["findings"]
    assert found
    return found[0]["finding_class"]


def masked(source: str) -> str:
    """The source with comments and the text of string literals blanked, same length.

    The code inside a template string's ``${...}`` stays: it is code like any other.
    """
    out: list[str] = []
    mask_code(source, 0, out, nested=False)
    return "".join(out)[: len(source)]


def blank(text: str) -> list[str]:
    return ["\n" if ch == "\n" else " " for ch in text]


def mask_code(source: str, i: int, out: list[str], nested: bool) -> int:
    """Mask from ``i``; when ``nested``, stop at the ``}`` that closes the ``${``."""
    depth = 0
    while i < len(source):
        two, c = source[i : i + 2], source[i]
        if two in ("//", "/*"):
            end = source.find("\n" if two == "//" else "*/", i)
            end = len(source) if end < 0 else end + (2 if two == "/*" else 0)
            out.extend(blank(source[i:end]))
            i = end
        elif c in "'\"":
            end = i + 1
            while end < len(source) and source[end] != c:
                end += 2 if source[end] == "\\" else 1
            end = min(end + 1, len(source))
            out.append(c)
            out.extend(blank(source[i + 1 : end - 1]))
            out.append(c)
            i = end
        elif c == "`":
            out.append(c)
            i = mask_template(source, i + 1, out)
        else:
            if nested and c in "{}":
                if c == "}" and depth == 0:
                    return i
                depth += 1 if c == "{" else -1
            out.append(c)
            i += 1
    return i


def mask_template(source: str, i: int, out: list[str]) -> int:
    """Mask a template string from after its opening backtick; return the index after it."""
    while i < len(source):
        if source[i] == "`":
            out.append("`")
            return i + 1
        if source[i : i + 2] == "${":
            out.append("${")
            i = mask_code(source, i + 2, out, nested=True)
            out.append("}")
            i += 1
        else:
            width = 2 if source[i] == "\\" else 1
            out.extend(blank(source[i : i + width]))
            i += width
    return i


def openers(code: str, at: int) -> list[tuple[str, int]]:
    """The brackets still open at ``at``, outermost first."""
    stack = []
    for i, c in enumerate(code[:at]):
        if c in "([{":
            stack.append((c, i))
        elif c in ")]}" and stack:
            stack.pop()
    return stack


def is_object_literal(code: str, at: int) -> bool:
    before = code[:at].rstrip()
    return before.endswith(("(", ",", ":", "=", "[", "?")) or bool(re.search(r"\breturn$", before))


def argument_spans(code: str, open_at: int) -> list[tuple[int, int]]:
    """The top-level arguments of the call whose ``(`` is at ``open_at``, as positions."""
    depth, parts, start = 0, [], open_at + 1
    for i in range(open_at + 1, len(code)):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                parts.append((start, i))
                return parts
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((start, i))
            start = i + 1
    raise AssertionError("unclosed call")


def whole_argument(code: str, open_at: int, start: int, end: int) -> int | None:
    """The index of the argument of the call at ``open_at`` that is exactly ``code[start:end]``."""
    for i, (a, b) in enumerate(argument_spans(code, open_at)):
        if a <= start < b:
            return i if code[a:b].strip() == code[start:end] else None
    return None


def wrapper_of(code: str, start: int, end: int) -> tuple[int, int] | None:
    """The ``String(...)``/``mono(...)`` call that ``code[start:end]`` is the whole argument of."""
    stack = openers(code, start)
    if stack and stack[-1][0] == "(":
        call = re.search(r"\b(?:String|mono)\s*$", code[: stack[-1][1]])
        spans = argument_spans(code, stack[-1][1])
        if call and len(spans) == 1 and whole_argument(code, stack[-1][1], start, end) == 0:
            return call.start(), spans[0][1] + 1
    return None


def misplaced_reads(source: str, fields) -> list[str]:
    """Each read of a class field in ``source`` that is not text in an element or a question."""
    code = masked(source)
    names = "|".join(map(re.escape, fields))
    read = rf"{CLASS}\.(?:{names})\b"
    bad = []
    for found in re.finditer(read, code):
        start, end = found.span()
        line = code.count("\n", 0, start) + 1
        shown = code[start:end]
        # The read itself, or the String()/mono() calls it is the whole argument of.
        outer, wrapped = (start, end), False
        while wrapper := wrapper_of(code, *outer):
            outer, wrapped = wrapper, True
        if re.match(ACCESS, code[outer[1] :]):
            bad.append(f"line {line}: {shown} followed by a further access")
            continue
        stack = openers(code, outer[0])
        if any(c == "{" and code[max(0, at - 1) : at] == "$" for c, at in stack):
            bad.append(f"line {line}: {shown} inside a template string")
            continue
        if re.search(r"\?\?\s*$", code[: outer[0]]) or re.match(r"\s*\?\?", code[outer[1] :]):
            bad.append(f"line {line}: {shown} with ??")
            continue
        if any(c == "{" and is_object_literal(code, at) for c, at in stack):
            bad.append(f"line {line}: {shown} inside an object literal")
            continue
        statement = re.split(r"[;{}]", code[: outer[0]])[-1]
        if re.search(r"[\w\]]\.\w+\s*=(?![=>])", statement):
            bad.append(f"line {line}: {shown} assigned to a property")
            continue
        if not wrapped:
            if re.match(ASKED.format(read=read), code[start:]) or re.search(
                r"\bif\s*\(\s*$", code[:start]
            ):
                continue
            bad.append(f"line {line}: {shown} neither text in an element nor a question")
            continue
        if child_of_element(code, *outer):
            continue
        bad.append(f"line {line}: {shown} is text, but not a child of an element")
    return bad


def child_of_element(code: str, start: int, end: int) -> bool:
    """Whether ``code[start:end]`` is, by position, a whole child argument of ``frag``/``h``."""
    stack = openers(code, start)
    if stack and stack[-1][0] == "(":
        call = re.search(r"\b(frag|h)\s*$", code[: stack[-1][1]])
        if call:
            at = whole_argument(code, stack[-1][1], start, end)
            # In h(tag, attrs, ...) only the arguments after the attributes are children.
            return at is not None and (call[1] == "frag" or at >= 2)
    # classText is the one helper allowed to put the fields into a string: its result is only
    # ever used as a child (see misplaced_class_text_calls), so the string ends up as text.
    return inside_function(code, start, "classText")


def inside_function(code: str, at: int, name: str) -> bool:
    """Whether ``at`` lies in the body of ``function name(...) {...}``."""
    head = re.search(rf"\bfunction\s+{name}\s*\([^)]*\)\s*{{", code)
    if not head:
        return False
    depth = 1
    for i in range(head.end(), len(code)):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        if depth == 0:
            return head.end() <= at < i
    return False


def misplaced_class_text_calls(source: str) -> list[str]:
    """Each ``classText(`` call that is not a child of ``h(tag, attrs, ...)`` or ``frag(...)``."""
    code = masked(source)
    bad = []
    for found in re.finditer(r"\bclassText\s*\(", code):
        line = code.count("\n", 0, found.start()) + 1
        if re.search(r"\bfunction\s+$", code[: found.start()]):
            continue
        stack = openers(code, found.start())
        call = stack and stack[-1][0] == "(" and re.search(r"\b(frag|h)\s*$", code[: stack[-1][1]])
        if not call:
            bad.append(f"line {line}: classText( outside frag(...) and h(...)")
            continue
        # The whole call, to its closing ``)``.
        depth, i = 1, found.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(code[i], 0)
            i += 1
        # The argument this call stands in, by position, must be nothing but this call.
        at = whole_argument(code, stack[-1][1], found.start(), i)
        if at is None:
            bad.append(f"line {line}: classText( is part of a longer expression")
        elif call[1] == "h" and at < 2:
            bad.append(f"line {line}: classText( is not a child of h(tag, attrs, ...)")
    return bad


def unknown_spellings(source: str, fields) -> list[str]:
    """Each mention of the class that is not one of the spellings the checks above judge.

    On the raw source, so a mention in a string or a comment is no exception.
    """
    names = "|".join(map(re.escape, fields))
    known = [
        # The reads the placement check judges, and the helper's own parameter.
        rf"\b\w+\.finding_class\.(?:{names})\b(?!{ACCESS})",
        rf"\bfc\.(?:{names})\b(?!{ACCESS})",
        r"\bfunction classText\(fc, sep\)",
        # classText( calls are judged by misplaced_class_text_calls; its argument is a class.
        r"\bclassText\(\s*\w+\.finding_class\s*[,)]",
        r"(?<![.\w])classText\(",
        # Asking whether the class is there, and the one binding of ``fc`` to it.
        r"\bisObj\(\s*(?:\w+\.finding_class|fc)\s*\)",
        r"\bfc\s*\?(?![?.])",
        r"\bconst fc = isObj\((\w+)\.finding_class\) \? \1\.finding_class : null;",
        # ``fc`` is also the name of an unrelated list of capped findings.
        r"\bconst fc = asList\(\w+\.findings_capped\)",
        r"\bfc\.(?:length|map)\b",
    ]
    covered = [m.span() for pattern in known for m in re.finditer(pattern, source)]
    bad = []
    for found in re.finditer(r"finding_class|classText|\bfc\b", source):
        if not any(a <= found.start() and found.end() <= b for a, b in covered):
            line = source.count("\n", 0, found.start()) + 1
            bad.append(
                f"line {line}: {found[0]} in a spelling this test does not know; "
                "add it to the test before using it"
            )
    return bad


def problems(source: str, fields) -> list[str]:
    return (
        misplaced_reads(source, fields)
        + misplaced_class_text_calls(source)
        + unknown_spellings(source, fields)
    )


def test_app_js_reads_finding_class_and_the_fields_the_api_gives(world):  # noqa: F811
    fields = class_fields(world)
    assert {"id", "title"} <= set(fields)
    source = APP_JS.read_text()
    assert "finding_class" in source
    for name in ("id", "title"):
        assert re.search(rf"{CLASS}\.{name}\b", source), f"app.js never reads {name}"
    # Only the field itself: ``fc`` is also the name of an unrelated list elsewhere.
    read = set(re.findall(r"\bfinding_class\.(\w+)", source))
    assert read <= set(fields), f"app.js reads {read - set(fields)}, which the API does not give"


def test_app_js_sets_the_class_fields_as_text_only(world):  # noqa: F811
    fields = class_fields(world)
    source = APP_JS.read_text()
    assert problems(source, fields) == []
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in source, sink


# Spellings the scan must refuse, each a line of its own.
REFUSED = [
    "h('span', { title: `${fc.title}` });",
    "el.title = `${fc.title ?? ''}`;",
    "h('b', null, `${fc.title}`);",
    "const { id, title } = fc;",
    "const c = f.finding_class; h('b', null, String(c.title));",
    "h('b', null, fc['id']);",
    "h('b', null, fc?.id);",
    "h('b', null, f.finding_class?.id);",
    "h('span', null, mono(fc.id),fc.title ?? '');",
    "h('span', null, mono(fc.id), fc.title);",
    "const t = fc.title?.trim();",
    "const t = d.finding_class.title?.trim();",
    "h('b', null, fc.id.toString());",
    "h('b', null, fc.title[0]);",
    "h('b', null, String(fc.title).trim());",
    "frag(classText(f.finding_class, ' '), classText(f.finding_class, ' ') + x);",
    "frag(x, classText(f.finding_class, ' ') + x);",
    "rows.map(classText);",
    "show(f.finding_class);",
]
# Spellings it must keep accepting.
ACCEPTED = [
    "h('span', null, mono(f.finding_class.id), ' ', String(f.finding_class.title));",
    "frag(classText(f.finding_class, ' '), classText(f.finding_class, ' '));",
    "frag(classText(f.finding_class, ' '), classText(g.finding_class, ' '));",
    "const t = `${a} ${b}`; h('b', null, String(f.finding_class.title));",
]


def test_the_scan_refuses_every_spelling_it_does_not_know(world):  # noqa: F811
    fields = class_fields(world)
    for line in REFUSED:
        assert problems(line, fields), line
    for line in ACCEPTED:
        assert problems(line, fields) == [], line


# A further access after a read. The tripwire and misplaced_reads each have a check for it
# (``(?!ACCESS)``, ``re.match(ACCESS, ...)``); the lists above only show that one of the two holds.
FURTHER_ACCESS = [
    "const t = fc.title?.trim();",
    "const t = d.finding_class.title?.trim();",
    "h('b', null, fc.id.toString());",
    "h('b', null, fc.title[0]);",
    "const t = fc.title ?.trim();",
    "const t = fc.title\n  ?.trim();",
]


def test_the_tripwire_alone_refuses_a_further_access(world):  # noqa: F811
    fields = class_fields(world)
    for line in FURTHER_ACCESS:
        assert unknown_spellings(line, fields), line


def test_misplaced_reads_alone_refuses_a_further_access(world):  # noqa: F811
    fields = class_fields(world)
    # Only here: the comment is blanked in the masked code, the raw source of the tripwire
    # is not; and classText would otherwise let any read in its body pass as a child.
    only_here = [
        "if (fc.title/**/.includes(x)) { go(); }",
        "function classText(fc, sep) { return String(fc.title).toUpperCase(); }",
    ]
    for line in only_here + FURTHER_ACCESS:
        assert misplaced_reads(line, fields), line
