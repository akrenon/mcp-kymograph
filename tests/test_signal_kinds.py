"""Every signal says what one hit of it is: evidence or a heuristic (repeated-runs.md 4.1).

The report's last section and the web interface's signal library read the kind from here, so
a reader knows which rows can fire on honest content. A signal without a kind would be read as
one or the other by whoever shows it; the table holds every signal, and no other key.
"""

import pytest

from mcp_kymograph.signals import KINDS, LIBRARY, Kind, Signal


def test_every_signal_carries_a_kind_and_the_table_names_no_other():
    assert set(KINDS) == set(Signal)
    assert all(isinstance(kind, Kind) for kind in KINDS.values())


def test_every_signal_of_the_library_answers_its_kind():
    for definition in LIBRARY:
        assert definition.signal.kind is KINDS[definition.signal]


@pytest.mark.parametrize(
    ("signal", "kind"),
    [
        (Signal.TOOL_NAME_DUPLICATE, Kind.EVIDENCE),
        (Signal.LONE_SURROGATE, Kind.EVIDENCE),
        (Signal.TOOL_NAME_LOOKALIKE, Kind.HEURISTIC),
        (Signal.INVISIBLE_CHARACTERS, Kind.HEURISTIC),
        (Signal.IMPERATIVE, Kind.HEURISTIC),
    ],
)
def test_the_kinds_are_those_of_repeated_runs_4_1(signal, kind):
    assert signal.kind is kind


def test_only_the_two_exact_comparisons_are_evidence():
    assert {signal for signal, kind in KINDS.items() if kind is Kind.EVIDENCE} == {
        Signal.TOOL_NAME_DUPLICATE,
        Signal.LONE_SURROGATE,
    }


def test_a_kind_is_its_name_as_text():
    assert {kind.value for kind in Kind} == {"evidence", "heuristic"}
