"""Finding classes: every signal and rule has exactly one, the class is derived and never filed,
and the mapping file is checked."""

import copy
import inspect
import re

import pytest

from mcp_kymograph import finding_classes, rules
from mcp_kymograph.finding_classes import (
    CLASSES,
    MappingError,
    UnknownIdentError,
    class_of,
    load_mapping,
    validate_mapping,
)
from mcp_kymograph.signals import Signal
from mcp_kymograph.store import KEY_FIELDS, Store, canonical_key
from test_store import finding, recording

# -- the classes ----------------------------------------------------------------------------


def rule_names() -> set[str]:
    """Every rule in rules.py, found the way a new one would be: a class with ``name`` and
    ``act``."""
    return {
        cls.name
        for _, cls in inspect.getmembers(rules, inspect.isclass)
        if cls.__module__ == rules.__name__ and hasattr(cls, "act") and hasattr(cls, "name")
    }


def test_classes_have_stable_two_digit_ids_a_title_and_a_description():
    ids = [c.id for c in CLASSES]
    assert ids == sorted(set(ids)), "once each, in order"
    for c in CLASSES:
        assert re.fullmatch(r"AKR-\d\d", c.id)
        assert c.title.strip() and c.description.strip()
        assert c.description.endswith(".")


def test_every_signal_has_exactly_one_class():
    assert set(finding_classes.SIGNAL_CLASSES) == set(Signal), "a new signal needs a class"
    for signal in Signal:
        assert class_of("signal", signal.value) in CLASSES


def test_every_rule_has_exactly_one_class():
    assert rule_names(), "the search found the rules"
    assert set(finding_classes.RULE_CLASSES) == rule_names(), "a new rule needs a class"
    for name in rule_names():
        assert class_of("rule", name) in CLASSES


def test_every_class_holds_something():
    used = {*finding_classes.SIGNAL_CLASSES.values(), *finding_classes.RULE_CLASSES.values()}
    assert used == {c.id for c in CLASSES}


def test_an_id_this_version_does_not_know_has_no_class():
    with pytest.raises(UnknownIdentError):
        class_of("signal", "from_a_newer_version")
    with pytest.raises(UnknownIdentError):
        class_of("rule", "nope")
    with pytest.raises(ValueError, match="kind must be"):
        class_of("severity", "x")
    assert finding_classes.class_label("signal", "from_a_newer_version") is None


def test_a_class_is_no_severity():
    for c in CLASSES:
        assert set(c.to_dict()) == {"id", "title", "description"}


# -- derived, never stored ------------------------------------------------------------------


def test_the_finding_key_is_the_same_before_and_after_a_class_is_derived(tmp_path):
    key = finding(5)["key"]
    pinned = (
        '["srv", "sha256:' + "aa" * 32 + '", "' + key["tool_version"] + '", "scn", "st", '
        '"result.tools[name=\\"w\\"].description", "hidden_comment"]'
    )
    assert KEY_FIELDS == (
        "server", "server_version", "tool_version", "scenario", "statement", "locator", "signal",
    )  # fmt: skip
    assert canonical_key(key) == pinned

    with Store.open(tmp_path / "findings.sqlite") as store:
        run = store.resolve(str(_ingest(store, tmp_path)))
        ((filed, _),) = store.findings_of(run).values()
        assert canonical_key(filed) == pinned
        assert class_of("signal", filed["signal"]).id == "AKR-01"
        ((again, _),) = store.findings_of(run).values()
        assert canonical_key(again) == pinned
        columns = {row[1] for row in store._db.execute("PRAGMA table_info(findings)")}
    assert not {c for c in columns if "class" in c}, "the store has no class field"


def _ingest(store, tmp_path):
    path = recording(tmp_path, [finding(5)])
    store.ingest(path)
    return path


# -- the mapping file -----------------------------------------------------------------------


def framework(ident, name, *, version="1.0", date=None):
    return {
        "id": ident, "name": name, "version": version, "retrieved": "2026-11-04",
        "date": date, "note": "",
    }  # fmt: skip


def good():
    return {
        "frameworks": [
            framework("cosai-mcp", "CoSAI"),
            framework("iso-27001", "ISO", version="2022", date="2022-10-25"),
            framework("acs-llm-pentest", "ACS"),
            framework("nis2-bsig", "BSIG"),
        ],
        "classes": [{"id": c.id, "entries": []} for c in CLASSES],
    }


def refused(data, match):
    with pytest.raises(MappingError, match=match):
        validate_mapping(data, source="m.yaml")


def test_the_mapping_file_in_the_package_is_valid_and_complete():
    pytest.importorskip("yaml")
    mapping = load_mapping()
    assert set(mapping.entries) == {c.id for c in CLASSES}
    assert {f.id for f in mapping.frameworks} >= {
        "owasp-mcp-top10", "owasp-mcp-stg", "acs-llm-pentest", "cosai-mcp", "owasp-llm-top10",
        "mitre-atlas", "iso-27001", "nis2-bsig", "dora", "eu-ai-act",
    }  # fmt: skip
    beta = next(f for f in mapping.frameworks if f.id == "owasp-mcp-top10")
    assert "Beta" in beta.note
    for entries in mapping.entries.values():
        assert all(not e.confirmed for e in entries), "the maintainers confirm, not the code"


CONTEXT_ONLY = {"iso-27001", "nis2-bsig", "dora", "eu-ai-act"}


def test_frameworks_that_are_only_context_have_no_entry_and_the_others_have_one():
    pytest.importorskip("yaml")
    mapping = load_mapping()
    used = {e.framework for entries in mapping.entries.values() for e in entries}
    assert not used & CONTEXT_ONLY
    assert {f.id for f in mapping.frameworks} - CONTEXT_ONLY <= used


def test_every_class_has_an_entry_and_every_framework_a_version_and_a_retrieval_day():
    pytest.importorskip("yaml")
    mapping = load_mapping()
    assert all(mapping.entries[c.id] for c in CLASSES)
    for f in mapping.frameworks:
        assert isinstance(f.version, str) and f.version.strip(), f.id
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", f.retrieved), f.id


def test_the_mapping_file_is_in_the_package_data():
    from importlib import resources

    packaged = resources.files("mcp_kymograph").joinpath("data", finding_classes.MAPPING_RESOURCE)
    assert packaged.is_file()


def test_a_good_mapping_with_entries_is_accepted():
    data = good()
    data["classes"][0]["entries"] = [
        {"framework": "cosai-mcp", "ref": "MCP-T3", "confirmed": False},
        {"framework": "iso-27001", "ref": "A.8.29", "confirmed": True},
        {"framework": "acs-llm-pentest", "ref": "A 6.4.19.1", "confirmed": False},
        {"framework": "nis2-bsig", "ref": "§ 30", "confirmed": False},
    ]
    mapping = validate_mapping(data)
    assert [e.ref for e in mapping.entries["AKR-01"]] == ["MCP-T3", "A.8.29", "A 6.4.19.1", "§ 30"]


def test_the_checker_refuses_an_unknown_framework_with_the_place():
    data = good()
    data["classes"][1]["entries"] = [{"framework": "nist", "ref": "1", "confirmed": False}]
    refused(data, r"m\.yaml: classes\[1\]\.entries\[0\]\.framework: unknown framework 'nist'")


@pytest.mark.parametrize("value", [["AKR-01"], {"AKR-01": 1}], ids=["list", "map"])
def test_the_checker_refuses_a_list_or_map_where_an_id_is_expected_with_the_place(value):
    data = good()
    data["classes"][0]["id"] = value
    refused(data, r"classes\[0\]\.id: must be a string")
    data = good()
    data["classes"][0]["entries"] = [{"framework": value, "ref": "MCP-T3", "confirmed": False}]
    refused(data, r"classes\[0\]\.entries\[0\]\.framework: must be a string")
    data = good()
    data["frameworks"][0]["id"] = value
    refused(data, r"frameworks\[0\]\.id: must be a non-empty string")


def test_the_checker_refuses_a_class_listed_twice_or_missing_or_unknown():
    data = good()
    data["classes"].append(copy.deepcopy(data["classes"][0]))
    refused(data, r"classes\[5\]\.id: class 'AKR-01' listed twice")
    data = good()
    del data["classes"][2]
    refused(data, r"classes: class 'AKR-03' is missing")
    data = good()
    data["classes"][0]["id"] = "AKR-99"
    refused(data, r"classes\[0\]\.id: unknown class 'AKR-99'")


def test_the_checker_refuses_an_unknown_key_at_every_level():
    data = good()
    data["extra"] = 1
    refused(data, r"extra: unknown key")
    data = good()
    data["frameworks"][0]["url"] = "x"
    refused(data, r"frameworks\[0\]\.url: unknown key")
    data = good()
    data["classes"][0]["title"] = "x"
    refused(data, r"classes\[0\]\.title: unknown key")
    data = good()
    data["classes"][0]["entries"] = [
        {"framework": "cosai-mcp", "ref": "MCP-T3", "confirmed": False, "text": "x"}
    ]
    refused(data, r"classes\[0\]\.entries\[0\]\.text: unknown key")


@pytest.mark.parametrize(
    ("framework", "ref"),
    [
        ("cosai-mcp", "T4"),
        ("cosai-mcp", "Tool poisoning"),
        ("cosai-mcp", "T3 tool poisoning"),
        ("iso-27001", "Supplier relationships"),
        ("acs-llm-pentest", "6.4.19.1"),
        ("nis2-bsig", "§ 30 requires measures"),
        ("cosai-mcp", ""),
        ("cosai-mcp", 3),
    ],
)
def test_the_checker_refuses_prose_in_a_ref(framework, ref):
    data = good()
    data["classes"][0]["entries"] = [{"framework": framework, "ref": ref, "confirmed": False}]
    refused(data, r"classes\[0\]\.entries\[0\]\.ref: ")


def test_the_checker_refuses_a_confirmed_that_is_not_a_bool():
    for value in ("false", 0, None):
        data = good()
        data["classes"][0]["entries"] = [
            {"framework": "cosai-mcp", "ref": "MCP-T3", "confirmed": value}
        ]
        refused(data, r"entries\[0\]\.confirmed: must be true or false")


def test_the_checker_refuses_a_bad_version_date_or_a_missing_key():
    data = good()
    data["frameworks"][0]["date"] = "yesterday"
    refused(data, r"frameworks\[0\]\.date")
    data = good()
    data["frameworks"][0]["version"] = 3
    refused(data, r"frameworks\[0\]\.version")
    data = good()
    del data["frameworks"][0]["note"]
    refused(data, r"frameworks\[0\]: missing key 'note'")
    data = good()
    del data["frameworks"][0]["retrieved"]
    refused(data, r"frameworks\[0\]: missing key 'retrieved'")
    data = good()
    data["frameworks"][0]["retrieved"] = "today"
    refused(data, r"frameworks\[0\]\.retrieved")
    data = good()
    data["frameworks"][0]["version"] = None
    refused(data, r"frameworks\[0\]\.version: must be a non-empty string")
    data = good()
    data["frameworks"].append(copy.deepcopy(data["frameworks"][0]))
    refused(data, r"frameworks\[4\]\.id: framework 'cosai-mcp' listed twice")


def test_a_file_that_is_not_yaml_or_not_there_is_refused_with_its_name(tmp_path):
    pytest.importorskip("yaml")
    with pytest.raises(MappingError, match="nowhere.yaml: cannot be read"):
        load_mapping(tmp_path / "nowhere.yaml")
    path = tmp_path / "m.yaml"
    path.write_text("frameworks: [\n", encoding="utf-8")
    with pytest.raises(MappingError, match=r"m\.yaml"):
        load_mapping(path)
    path.write_text("frameworks: []\nclasses: []\nclasses: []\n", encoding="utf-8")
    with pytest.raises(MappingError, match="duplicate key"):
        load_mapping(path)
