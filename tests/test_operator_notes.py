"""The operator's private notes: read whole or refused whole, kept nowhere, read by nothing.

The tool keeps no reason for a decision (store schema 13); the operator's notes hold it, with a
CVSS 4.0 vector and a status per finding. ``operator_notes.load`` checks the format and writes
nothing: no byte of the file reaches a store, a bundle or a recording. And no module of the tool
reads the notes — no report, attestation, status, bundle, export or web view: only the module
that defines them names them, and ``engagement purge``, which deletes them by name without
opening them.
"""

import ast
import json
from pathlib import Path

import pytest

import mcp_kymograph
from mcp_kymograph import operator_notes
from mcp_kymograph.operator_notes import OperatorNotesError, cvss_problem, load
from mcp_kymograph.store import Store
from test_store import finding, recording
from test_store_triage import IDENTITY

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
#: Text only the notes hold; it must be found in no other file.
CANARY = "NOTES-CANARY-4718"


# -- the vector ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    [
        BASE,
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L",
        BASE + "/E:A",
        BASE + "/E:X/CR:H/IR:M/AR:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:L/MVA:N",
        BASE + "/MSC:H/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Amber",
        BASE + "/U:Clear",
        BASE + "/AR:L/U:Red",
    ],
)
def test_a_vector_of_the_grammar_is_taken(vector):
    assert cvss_problem(vector) is None


@pytest.mark.parametrize(
    ("vector", "words"),
    [
        ("", "does not start with CVSS:4.0/"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "does not start with CVSS:4.0/"),
        (BASE.replace("CVSS:4.0/", ""), "does not start with CVSS:4.0/"),
        (BASE.lower(), "does not start with CVSS:4.0/"),
        (BASE.replace("/SA:N", ""), "base metric SA is missing"),
        ("CVSS:4.0/AV:N/AC:L", "base metric AT is missing"),
        ("CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "expected metric AV"),
        (BASE.replace("AV:N", "AV:X"), "metric AV has value 'X'"),
        (BASE.replace("AC:L", "AC:N"), "metric AC has value 'N'"),
        (BASE.replace("UI:N", "UI:H"), "metric UI has value 'H'"),
        (BASE.replace("VC:H", "VC:"), "metric VC has value ''"),
        (BASE.replace("VC:H", "VC"), "expected metric VC as VC:VALUE"),
        (BASE + "/", "is not a CVSS 4.0 metric"),
        (BASE + "/E:Z", "metric E has value 'Z'"),
        (BASE + "/Q:A", "metric 'Q' is not a CVSS 4.0 metric"),
        (BASE + "/E:A/E:A", "repeated or out of the specification's order"),
        (BASE + "/CR:H/E:A", "repeated or out of the specification's order"),
        (BASE + "/U:Red/R:A", "repeated or out of the specification's order"),
        (BASE + "/AV:N", "repeated or out of its place"),
        (BASE + "/MSI:N/MSA:Q", "metric MSA has value 'Q'"),
        (BASE + " ", "metric SA has value 'N '"),
        (BASE + "/U:red", "metric U has value 'red'"),
        (None, "is not a text"),
        (4.0, "is not a text"),
    ],
)
def test_a_vector_outside_the_grammar_is_refused_with_the_reason(vector, words):
    problem = cvss_problem(vector)
    assert problem is not None and words in problem, problem


def test_a_long_fragment_of_a_bad_vector_is_cut_in_the_message():
    problem = cvss_problem(BASE + "/" + "Z" * 500)
    assert problem is not None and len(problem) < 100


# -- the file --------------------------------------------------------------------------------


def notes(**changes) -> dict:
    document = {
        "engagement": "acme-2026-10",
        "findings": {
            "fk-0123456789abcdef": {
                "cvss": BASE,
                "rationale": f"The hidden comment reaches the model.\nSecond line. {CANARY}",
                "status": "partially_fixed",
            },
            "fk-fedcba9876543210": {
                "cvss": BASE + "/E:P",
                "rationale": "Cosmetic.",
                "status": "open",
            },
        },
    }
    document.update(changes)
    return document


def written(directory: Path, document, name="store.sqlite.operator-notes.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(document))
    return path


def test_a_valid_file_is_read_as_given(tmp_path):
    loaded = load(written(tmp_path, notes()))

    assert loaded.engagement == "acme-2026-10"
    assert list(loaded.findings) == ["fk-0123456789abcdef", "fk-fedcba9876543210"]
    first = loaded.findings["fk-0123456789abcdef"]
    assert (first.cvss, first.status) == (BASE, "partially_fixed")
    assert CANARY in first.rationale and "\n" in first.rationale
    with pytest.raises(TypeError):
        loaded.findings["new"] = first  # type: ignore[index]


def test_a_yaml_file_is_read_through_the_same_strict_reader(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "store.sqlite.operator-notes.yaml"
    path.write_text(
        "engagement: acme-2026-10\n"
        "findings:\n"
        "  fk-00000000000000a1:\n"
        f"    cvss: {BASE}\n"
        "    rationale: |\n"
        "      Two lines\n"
        "      of text.\n"
        "    status: fixed\n"
    )
    loaded = load(path)
    assert loaded.findings["fk-00000000000000a1"].rationale == "Two lines\nof text.\n"
    path.write_text(
        path.read_text().replace(
            "  fk-00000000000000a1:", "  fk-00000000000000a1:\n    status: open"
        )
    )
    with pytest.raises(OperatorNotesError, match="duplicate key 'status'"):
        load(path)


def test_the_statuses_include_partially_fixed():
    assert "partially_fixed" in operator_notes.STATUSES


@pytest.mark.parametrize("status", operator_notes.STATUSES)
def test_every_listed_status_is_taken(tmp_path, status):
    document = notes()
    document["findings"]["fk-fedcba9876543210"]["status"] = status
    assert load(written(tmp_path, document)).findings["fk-fedcba9876543210"].status == status


def edited(path_in_file: list[str], value) -> dict:
    document = notes()
    target = document
    for step in path_in_file[:-1]:
        target = target[step]
    if value is Ellipsis:
        del target[path_in_file[-1]]
    else:
        target[path_in_file[-1]] = value
    return document


K = "fk-0123456789abcdef"


@pytest.mark.parametrize(
    ("document", "words"),
    [
        (edited(["engagement"], ...), "engagement is missing"),
        (edited(["engagement"], ""), "engagement is not a non-empty text"),
        (edited(["engagement"], 7), "engagement is not a non-empty text"),
        (edited(["findings"], ...), "findings is missing"),
        (edited(["findings"], []), "findings is not a mapping"),
        (edited(["extra"], 1), "top level: a key that is not allowed here"),
        (edited(["findings", K, "cvss"], ...), f"findings['{K}'].cvss is missing"),
        (edited(["findings", K, "rationale"], ...), f"findings['{K}'].rationale is missing"),
        (edited(["findings", K, "status"], ...), f"findings['{K}'].status is missing"),
        (edited(["findings", K, "score"], 9.8), f"findings['{K}']: a key that is not allowed here"),
        (edited(["findings", K, "cvss"], BASE + "/E:Z"), f"findings['{K}'].cvss: metric E"),
        (edited(["findings", K, "cvss"], 9.8), f"findings['{K}'].cvss: is not a text"),
        (edited(["findings", K, "rationale"], ""), "rationale is not a non-empty text"),
        (edited(["findings", K, "rationale"], 3), "rationale is not a non-empty text"),
        (edited(["findings", K, "status"], "done"), "status is not one of open, confirmed"),
        (edited(["findings", K, "status"], "Fixed"), "status is not one of"),
        (edited(["findings", K], "fixed"), "is not a mapping of cvss, rationale and status"),
        (edited(["findings", ""], {}), "a key of findings is not a finding key"),
        (
            edited(["findings", "poison/hidden-comment/1"], {}),
            "a key of findings is not a finding key",
        ),
        (edited(["findings", "fk-0123456789ABCDEF"], {}), "a key of findings is not a finding key"),
        (edited(["findings", "fk-0123456789abcde"], {}), "a key of findings is not a finding key"),
        (
            edited(["findings", "fk-0123456789abcdef0"], {}),
            "a key of findings is not a finding key",
        ),
        (
            edited(["findings", " fk-0123456789abcdef"], {}),
            "a key of findings is not a finding key",
        ),
        (
            edited(["findings", "fk-0123456789abcdef\n"], {}),
            "a key of findings is not a finding key",
        ),
        ([], "the operator's notes are a mapping"),
    ],
)
def test_a_file_is_refused_whole_at_the_first_fault_with_its_place(tmp_path, document, words):
    path = written(tmp_path, document)
    with pytest.raises(OperatorNotesError) as refused:
        load(path)
    assert str(refused.value).startswith(f"{path}: "), refused.value
    assert words in str(refused.value)


def test_the_first_fault_in_the_file_s_order_is_the_one_named(tmp_path):
    document = notes()
    document["findings"]["fk-fedcba9876543210"]["cvss"] = "CVSS:4.0/"
    document["findings"][K]["status"] = "done"
    with pytest.raises(OperatorNotesError, match="status is not one of"):
        load(written(tmp_path, document))


@pytest.mark.parametrize(
    ("name", "content", "words"),
    [
        ("notes.txt", "{}", "unknown suffix '.txt'"),
        ("notes.json", "{not json", "line 1 column 2"),
        ("notes.json", '{"engagement": "a", "engagement": "b"}', "duplicate key 'engagement'"),
        ("notes.json", '{"engagement": NaN}', "NaN is not a JSON value"),
        ("notes.json", "[]", "the operator's notes are a mapping"),
        ("missing.json", None, "cannot read"),
    ],
)
def test_a_file_that_cannot_be_read_is_refused_with_its_name(tmp_path, name, content, words):
    path = tmp_path / name
    if content is not None:
        path.write_text(content)
    with pytest.raises(OperatorNotesError) as refused:
        load(path)
    assert str(path) in str(refused.value) and words in str(refused.value)


def test_a_file_that_is_not_utf8_is_refused(tmp_path):
    path = tmp_path / "notes.json"
    path.write_bytes(b'{"engagement": "\xff"}')
    with pytest.raises(OperatorNotesError, match="not UTF-8 at byte"):
        load(path)


def test_a_refusal_does_not_quote_the_text_of_the_file(tmp_path):
    document = notes()
    document["findings"][K]["status"] = f"{CANARY} done"
    document["findings"][K]["cvss"] = BASE
    with pytest.raises(OperatorNotesError) as refused:
        load(written(tmp_path, document))
    assert CANARY not in str(refused.value)


@pytest.mark.parametrize("where", [["findings", K], []])
def test_a_key_that_is_not_allowed_is_placed_and_never_quoted(tmp_path, where):
    sentence = f"{CANARY} reaches the model through a comment"
    document = edited([*where, sentence], "x")
    with pytest.raises(OperatorNotesError) as refused:
        load(written(tmp_path, document))
    assert "a key that is not allowed here" in str(refused.value)
    assert sentence not in str(refused.value) and CANARY not in str(refused.value)


# -- nothing is kept -------------------------------------------------------------------------


def files_of(directory: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    }


def test_loading_writes_nothing_anywhere(tmp_path, monkeypatch):
    path = written(tmp_path, notes())
    before = files_of(tmp_path)
    monkeypatch.chdir(tmp_path)

    load(path)
    with pytest.raises(OperatorNotesError):
        load(written(tmp_path, notes(engagement=""), name="bad.json"))

    after = files_of(tmp_path)
    assert after.pop("bad.json")
    assert after == before


def test_no_byte_of_the_file_reaches_a_store_a_report_or_a_bundle(tmp_path):
    """The notes sit beside a store that is filed and decided on: the file's text is in the file
    alone."""
    from mcp_kymograph import cli

    noted = written(tmp_path, notes())
    loaded = load(noted)
    assert CANARY in loaded.findings[K].rationale

    database = tmp_path / "findings.sqlite"
    with Store.open(database) as store:
        store.ingest(recording(tmp_path, [finding(5)]))
        store.triage_set(
            identity=IDENTITY, role="operator", status="confirmed", author=loaded.engagement,
            now=None,
        )  # fmt: skip
    export = tmp_path / "export.json"
    assert cli.main(["store", "triage", "export", "-q", "--store", str(database),
                     "--out", str(export)]) == 0  # fmt: skip

    canary = CANARY.encode()
    assert canary in noted.read_bytes()
    for path in (database, export, *(p for p in tmp_path.rglob("*.jsonl"))):
        assert canary not in path.read_bytes(), path


def test_the_module_imports_nothing_that_writes_and_opens_for_reading_only():
    tree = ast.parse(Path(operator_notes.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported <= {
        "__future__", "collections.abc", "dataclasses", "pathlib", "re", "types", "typing",
        "mcp_kymograph.scenario",
    }  # fmt: skip
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called & {"write", "write_text", "write_bytes", "mkdir", "unlink", "touch", "rename"}
    (opening,) = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
    ]  # fmt: skip
    assert [arg.value for arg in opening.args] == ["rb"]


# -- where they lie --------------------------------------------------------------------------


def test_the_notes_lie_beside_the_store_named_after_it(tmp_path):
    store = tmp_path / "acme.sqlite"
    assert operator_notes.beside(store) == (
        tmp_path / "acme.sqlite.operator-notes.yaml",
        tmp_path / "acme.sqlite.operator-notes.yml",
        tmp_path / "acme.sqlite.operator-notes.json",
    )
    assert operator_notes.beside(str(store)) == operator_notes.beside(store)
    assert not list(tmp_path.iterdir()), "naming the paths creates and opens nothing"


def test_two_stores_in_one_directory_have_notes_of_their_own(tmp_path):
    first = set(operator_notes.beside(tmp_path / "acme.sqlite"))
    second = set(operator_notes.beside(tmp_path / "other.sqlite"))
    assert not first & second


# -- read by nothing -------------------------------------------------------------------------

PACKAGE = Path(mcp_kymograph.__file__).parent
MODULE = "mcp_kymograph.operator_notes"
#: The one module beside the definition that may name the notes, the one name it may take from
#: it, and what it binds it to: ``evidence.purge`` deletes them by name. ``beside`` opens
#: nothing; ``load`` and ``build`` read, and are taken by no module.
DELETER = "evidence.py"
DELETER_TAKES = {"beside"}
DELETER_BINDS = "notes_beside"


def modules() -> dict[str, ast.Module]:
    found = {
        str(path.relative_to(PACKAGE)): ast.parse(path.read_text(encoding="utf-8"))
        for path in sorted(PACKAGE.rglob("*.py"))
    }
    assert "operator_notes.py" in found and "cli.py" in found and "web/views.py" in found
    return found


def imports_of_the_notes(name: str, tree: ast.Module) -> list[tuple[str, set[str]]]:
    """Every import in ``tree`` that reaches the notes module, with the names it takes from it
    (``*`` for the module itself or everything)."""
    package = name.rsplit("/", 1)[0] if "/" in name else ""
    reached = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            reached += [(alias.name, {"*"}) for alias in node.names if MODULE in alias.name]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = ["mcp_kymograph", *filter(None, package.split("/"))]
                base = ".".join(parts[: len(parts) - node.level + 1])
                module = f"{base}.{node.module}" if node.module else base
            else:
                module = node.module or ""
            taken = {alias.name for alias in node.names}
            if module == MODULE:
                reached.append((module, taken))
            elif f"{module}.operator_notes" == MODULE and "operator_notes" in taken:
                reached.append((MODULE, {"*"}))
            elif module.startswith(MODULE):
                reached.append((module, {"*"}))
    return reached


def docstrings(tree: ast.Module) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def test_no_module_imports_the_notes_but_purge_which_takes_only_their_names():
    importing = {
        name: reached
        for name, tree in modules().items()
        if name != "operator_notes.py" and (reached := imports_of_the_notes(name, tree))
    }
    assert set(importing) == {DELETER}, importing
    ((module, taken),) = importing[DELETER]
    assert (module, taken) == (MODULE, DELETER_TAKES)


def test_the_deleter_names_the_notes_inside_purge_and_nowhere_else():
    tree = modules()[DELETER]
    (bound,) = [
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == MODULE
        for alias in node.names
    ]
    assert bound == DELETER_BINDS
    users = {
        function.name
        for function in ast.walk(tree)
        if isinstance(function, ast.FunctionDef)
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == bound
    }
    assert users == {"purge"}


def test_no_module_names_the_notes_file_but_the_one_that_defines_it():
    """Reading needs the name: no string a module computes with (its docstrings are prose, and
    are left out) holds the notes' name or their module's, outside ``operator_notes.py`` — but
    the one word ``purged.json`` lists the deleted notes under (``evidence.NOTES_KIND``)."""
    from mcp_kymograph import evidence

    assert evidence.NOTES_KIND == "operator_notes" and evidence.NOTES_KIND in evidence.PURGE_KINDS
    kinds = []
    named = []
    for name, tree in modules().items():
        if name == "operator_notes.py":
            continue
        prose = docstrings(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in prose
                and ("operator-notes" in node.value.lower() or "operator_notes" in node.value)
            ):
                if (name, node.value) == (DELETER, evidence.NOTES_KIND):
                    kinds.append(node.lineno)
                else:
                    named.append((name, node.lineno))
    assert not named
    assert len(kinds) == 1, "the kind is spelled once, where NOTES_KIND is set"


def test_the_name_is_spelled_once_in_the_module_that_defines_it():
    tree = modules()["operator_notes.py"]
    prose = docstrings(tree)
    spelled = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in prose
        and "operator-notes" in node.value
    ]
    assert spelled == ["operator-notes"] == [operator_notes.NAME]
