"""The generation a target declares in the engagement file (``era``, and ``version`` beside it):
read whole or refused whole, matched to the URL a run reaches the way the gate matches it, shown
by ``engagement show`` — and never a reason to refuse a run.
"""

from __future__ import annotations

import pytest

from mcp_kymograph import cli, engagement
from mcp_kymograph.engagement import EngagementError
from test_cli_engagement import write_engagement


def load(tmp_path, targets):
    return engagement.load(write_engagement(tmp_path / "engagement", targets=targets))


CUSTOMER = {"host": "api.example.test", "paths": ["/mcp", "/v2/mcp"], "ports": [443, 8443]}


def test_a_target_may_say_which_generation_its_server_speaks(tmp_path):
    loaded = load(
        tmp_path,
        [
            {**CUSTOMER, "era": "legacy", "version": "2025-11-25"},
            {"host": "other.example.test", "paths": ["/mcp"], "era": "modern"},
            {"host": "127.0.0.1"},
        ],
    )

    assert [(t.era, t.era_version) for t in loaded.targets] == [
        ("legacy", "2025-11-25"),
        ("modern", None),
        (None, None),
    ]


def test_the_declaration_is_part_of_the_file_and_so_of_its_digest(tmp_path):
    plain = load(tmp_path / "a", [CUSTOMER])
    said = load(tmp_path / "b", [{**CUSTOMER, "era": "legacy"}])

    assert plain.digest != said.digest
    assert said.sanitized()["targets"][0]["era"] == "legacy"


@pytest.mark.parametrize(
    ("target", "where", "words"),
    [
        ({"era": "ancient"}, "targets[0].era", "one of legacy, modern"),
        ({"era": 7}, "targets[0].era", "one of legacy, modern"),
        ({"era": None, "version": "2025-11-25"}, "targets[0].version", "named with an era"),
        ({"version": "2025-11-25"}, "targets[0].version", "named with an era"),
        ({"era": "legacy", "version": "latest"}, "targets[0].version", "protocol version"),
        ({"era": "legacy", "version": 20251125}, "targets[0].version", "protocol version"),
        ({"era": "legacy", "version": "2025-11-25 "}, "targets[0].version", "protocol version"),
        ({"era": "legacy", "versions": ["2025-11-25"]}, "targets[0]", "unknown key"),
    ],
)
def test_a_declaration_that_is_not_one_refuses_the_file_whole(tmp_path, target, where, words):
    held = write_engagement(tmp_path / "engagement", targets=[{**CUSTOMER, **target}])

    with pytest.raises(EngagementError) as refused:
        engagement.load(held)

    assert f"{where}: " in str(refused.value) and words in str(refused.value)


def test_the_generation_declared_is_found_for_the_url_the_gate_would_match(tmp_path):
    loaded = load(tmp_path, [{**CUSTOMER, "era": "legacy", "version": "2025-11-25"}])
    declared = {"era": "legacy", "version": "2025-11-25"}

    assert loaded.declared_era("https://api.example.test/mcp") == declared
    assert loaded.declared_era("https://api.example.test:8443/v2/mcp?x=1") == declared
    assert loaded.declared_era("https://api.example.test:9000/mcp") is None  # another port
    assert loaded.declared_era("https://api.example.test/other") is None  # another path
    assert loaded.declared_era("https://elsewhere.example.test/mcp") is None
    assert loaded.declared_era("not a url") is None


def test_a_target_that_declares_nothing_has_nothing_to_compare(tmp_path):
    loaded = load(tmp_path, [CUSTOMER, {"host": "127.0.0.1"}])

    assert loaded.declared_era("https://api.example.test/mcp") is None
    assert loaded.declared_era("http://127.0.0.1:8080/mcp") is None


def test_the_first_matching_target_that_declares_one_is_the_one(tmp_path):
    loaded = load(
        tmp_path,
        [
            {"host": "api.example.test", "paths": ["/mcp"], "ports": [443]},
            {"host": "api.example.test", "paths": ["/mcp"], "ports": [443], "era": "modern"},
        ],
    )

    assert loaded.declared_era("https://api.example.test/mcp") == {
        "era": "modern",
        "version": None,
    }


def test_show_lists_the_declaration_in_a_column_of_its_own_only_when_there_is_one(tmp_path):
    without = engagement.render(load(tmp_path / "a", [CUSTOMER]))
    with_one = engagement.render(
        load(
            tmp_path / "b",
            [{**CUSTOMER, "era": "legacy", "version": "2025-11-25"}, {"host": "127.0.0.1"}],
        )
    )

    assert "declared era" not in without
    assert "declared era" in with_one
    assert "legacy 2025-11-25" in with_one and "not declared" in with_one


def test_engagement_show_prints_a_file_that_makes_a_declaration(tmp_path, capsys):
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "127.0.0.1", "era": "modern"}]
    )

    assert cli.main(["engagement", "show", str(held)]) == 0
    assert "modern" in capsys.readouterr().out
