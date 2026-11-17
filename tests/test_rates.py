"""The arithmetic of repeated runs (src/mcp_kymograph/rates.py), checked three ways.

* Against the numbers docs/design/repeated-runs.md states: recomputed here, each by the module
  and, where the module sums or searches, also by a second, plainer computation in this file
  that does not share its code.
* Against textbook values: Newcombe's Wilson intervals, Fisher's tea and the dieting table,
  the example of Benjamini and Hochberg's paper.
* At the edges: no runs, every run a hit, a rate of 0 under "absent".
"""

from __future__ import annotations

import itertools
import math

import pytest

from mcp_kymograph import rates
from mcp_kymograph.rates import (
    Decision,
    Interval,
    Outcome,
    Sprt,
    benjamini_hochberg,
    evidence,
    exact_zero_hit_bound,
    fisher_exact,
    holm,
    rejected,
    rule_of_three,
    wilson,
    worst_case_interval,
)

HIT, MISS, UNKNOWN = Outcome.HIT, Outcome.MISS, Outcome.UNKNOWN

#: The four variants of the design's table in 4.3: (p_present, β), with p_absent = 0.01 and
#: α = 0.10 throughout; and the fewest runs for "absent" by the sequential test and by the
#: exact zero-hit bound.
VARIANTS = [
    (0.20, 0.05, 14, 14),
    (0.20, 0.01, 22, 21),
    (0.10, 0.05, 31, 29),
    (0.10, 0.01, 48, 44),
]


def heuristic(p_present: float, beta: float) -> Sprt:
    return Sprt(p0=0.01, p1=p_present, alpha=0.10, beta=beta)


# -- a second computation, sharing no code with the module ---------------------------------


def plain_fewest_misses(p0: float, p1: float, alpha: float, beta: float) -> int:
    """Count runs without a hit until the ratio of the two binomial likelihoods passes A."""
    boundary = (1 - alpha) / beta
    misses = 0
    while True:
        misses += 1
        if ((1 - p0) / (1 - p1)) ** misses >= boundary:
            return misses


def plain_operating(p0, p1, alpha, beta, rate, budget):
    """The truncated test, summed over (runs, hits) with the likelihood ratio taken whole."""
    upper = math.log((1 - alpha) / beta)
    lower = math.log(alpha / (1 - beta))
    running = {0: 1.0}
    absent = expected = 0.0
    for n in range(1, budget + 1):
        expected += sum(running.values())
        following = {}
        for hits, mass in running.items():
            for count, chance in ((hits + 1, rate), (hits, 1 - rate)):
                ratio = count * math.log(p0 / p1) + (n - count) * math.log((1 - p0) / (1 - p1))
                if ratio >= upper:
                    absent += mass * chance
                elif ratio > lower:
                    following[count] = following.get(count, 0.0) + mass * chance
        running = following
    return absent, sum(running.values()), expected


def enumerated_operating(test: Sprt, rate: float, budget: int):
    """Every sequence of ``budget`` outcomes, each read by the test: no sums, no states."""
    absent = present = 0.0
    for sequence in itertools.product((True, False), repeat=budget):
        chance = math.prod(rate if hit else 1 - rate for hit in sequence)
        reading = test.read(HIT if hit else MISS for hit in sequence)
        if reading.decision is Decision.ABSENT:
            absent += chance
        elif reading.decision is Decision.PRESENT:
            present += chance
    return absent, present


def lgamma_fisher(a: int, n_a: int, b: int, n_b: int) -> float:
    """Fisher's test the way the design proposes it: log-factorials, with a relative tolerance."""

    def log_choose(n, k):
        return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)

    hits, total = a + b, n_a + n_b

    def log_p(k):
        return log_choose(n_a, k) + log_choose(n_b, hits - k) - log_choose(total, hits)

    observed = log_p(a)
    ks = range(max(0, hits - n_b), min(hits, n_a) + 1)
    return sum(math.exp(log_p(k)) for k in ks if log_p(k) <= observed + 1e-7)


# -- the numbers of the design -------------------------------------------------------------


@pytest.mark.parametrize(("p_present", "beta", "sprt_runs", "exact_runs"), VARIANTS)
def test_the_fewest_runs_for_absent_are_those_of_the_design(p_present, beta, sprt_runs, exact_runs):
    test = heuristic(p_present, beta)
    assert test.min_runs_absent() == sprt_runs
    assert plain_fewest_misses(0.01, p_present, 0.10, beta) == sprt_runs
    assert exact_zero_hit_bound(p_present, beta) == exact_runs
    # The bound is exact where it lands: one run fewer is not enough.
    assert (1 - p_present) ** exact_runs <= beta < (1 - p_present) ** (exact_runs - 1)


@pytest.mark.parametrize(("p_present", "beta", "sprt_runs", "_exact"), VARIANTS)
def test_the_decision_falls_exactly_at_the_fewest_runs(p_present, beta, sprt_runs, _exact):
    test = heuristic(p_present, beta)
    assert test.decide(0, sprt_runs - 1) is Decision.CONTINUE
    assert test.decide(0, sprt_runs) is Decision.ABSENT
    assert test.read([MISS] * (sprt_runs + 5)) == rates.Reading(Decision.ABSENT, sprt_runs)


def test_the_design_variant_needs_48_runs_and_one_hit():
    test = Sprt()  # the module's constants: 0.01 against 0.10, α = 0.10, β = 0.01
    assert test.min_runs_absent() == 48
    assert test.min_runs_present() == 1
    assert test.absent_boundary == pytest.approx(math.log(0.90 / 0.01))
    assert test.present_boundary == pytest.approx(math.log(0.10 / 0.99))
    # Each run without a result the server may have caused costs 24.2 runs of "absent".
    assert math.log(0.10 / 0.01) / test.miss_step == pytest.approx(24.2, abs=0.05)


def test_the_stable_test_needs_14_runs_with_a_hit():
    stable = Sprt(p0=rates.P_FLAKY, p1=rates.P_STABLE, alpha=0.05, beta=0.05)
    assert stable.min_runs_present() == 14
    assert stable.decide(13, 0) is Decision.CONTINUE
    assert stable.decide(14, 0) is Decision.PRESENT


#: The design's table in 4.3: probability of "absent" for a finding present at rate p,
#: truncated at 100 runs. None stands for "< 0.001".
FALSE_ABSENT = [
    (0.20, 0.05, {0.05: 0.645, 0.10: 0.297, 0.20: 0.048}),
    (0.20, 0.01, {0.05: 0.569, 0.10: 0.166, 0.20: 0.009}),
    (0.10, 0.05, {0.05: 0.332, 0.10: 0.049, 0.20: 0.001}),
    (0.10, 0.01, {0.05: 0.179, 0.10: 0.010, 0.20: None}),
]


@pytest.mark.parametrize(("p_present", "beta", "table"), FALSE_ABSENT)
def test_a_present_finding_is_called_absent_at_budget_100_as_the_design_says(
    p_present, beta, table
):
    test = heuristic(p_present, beta)
    for rate, stated in table.items():
        absent = test.operating(rate, 100).absent
        plain, _, _ = plain_operating(0.01, p_present, 0.10, beta, rate, 100)
        assert absent == pytest.approx(plain, abs=1e-12)
        if stated is None:
            assert absent < 0.001
        else:
            assert absent == pytest.approx(stated, abs=0.0005), (rate, absent)


def test_the_held_miss_rate_holds_at_p_present():
    # β is what Wald's boundaries aim at; truncated at 100 the test stays below it.
    for p_present, beta, _, _ in VARIANTS:
        assert heuristic(p_present, beta).operating(p_present, 100).absent <= beta


#: The design's columns "undecided at worst" and "expected runs at worst" of 4.3, which it
#: says are taken at about 0.03. Recomputed at exactly 0.03. One cell differs from the
#: document: for (0.20, 0.01) it states 0.005; at 0.03 the value is 0.0015 (the largest over
#: all rates is 0.0059, near 0.063).
AT_0_03 = [
    (0.20, 0.05, 0.00005, 15.9),
    (0.20, 0.01, 0.0015, 26.1),
    (0.10, 0.05, 0.062, 42.5),
    (0.10, 0.01, 0.175, 60.7),
]


@pytest.mark.parametrize(("p_present", "beta", "undecided", "expected"), AT_0_03)
def test_undecided_and_expected_runs_at_a_rate_of_0_03(p_present, beta, undecided, expected):
    found = heuristic(p_present, beta).operating(0.03, 100)
    _, plain_undecided, plain_expected = plain_operating(0.01, p_present, 0.10, beta, 0.03, 100)
    assert found.undecided == pytest.approx(plain_undecided, abs=1e-12)
    assert found.expected_runs == pytest.approx(plain_expected, abs=1e-9)
    assert found.undecided == pytest.approx(undecided, abs=0.0005)
    assert found.expected_runs == pytest.approx(expected, abs=0.05)
    assert found.absent + found.present + found.undecided == pytest.approx(1.0)


def test_the_slowest_heuristic_is_undecided_at_100_and_less_so_at_150():
    # 4.7: a true rate around 0.03 is undecided at 100 in 17.5 % of series, 6 % at 150.
    assert Sprt().operating(0.03, 100).undecided == pytest.approx(0.175, abs=0.0005)
    assert Sprt().operating(0.03, 150).undecided == pytest.approx(0.06, abs=0.005)


#: The design's table in 4.2: the exact zero-hit bound at p₁ = 0.10, β = 0.01 (44 runs).
EVIDENCE_TABLE = [
    (0.0, 1.0, 44.0),
    (0.01, 0.643, 35.7),
    (0.02, 0.411, 29.4),
    (0.03, 0.262, 24.6),
    (0.05, 0.105, 17.9),
    (0.10, 0.0097, 9.9),
    (0.20, None, 5.0),
]


@pytest.mark.parametrize(("rate", "absent", "expected"), EVIDENCE_TABLE)
def test_the_evidence_bound_lets_through_what_the_design_says(rate, absent, expected):
    as_test = Sprt(p0=0.0, p1=0.10, alpha=0.0, beta=0.01).operating(rate, 100)
    closed_absent = (1 - rate) ** 44
    closed_expected = sum((1 - rate) ** k for k in range(44))
    assert as_test.absent == pytest.approx(closed_absent, abs=1e-12)
    assert as_test.expected_runs == pytest.approx(closed_expected, abs=1e-9)
    assert as_test.undecided == 0.0
    if absent is None:
        assert closed_absent < 0.001
    else:
        assert closed_absent == pytest.approx(absent, abs=0.0005 if absent > 0.01 else 0.00005)
    # 29.445 at 0.02: the design rounds it down.
    assert closed_expected == pytest.approx(expected, abs=0.051)


def test_the_rule_of_three_against_the_exact_bound_at_10_runs():
    assert rule_of_three(10) == pytest.approx(0.300)
    exact = 1 - 0.05 ** (1 / 10)
    assert exact == pytest.approx(0.259, abs=0.0005)


#: The design's table in 5: what one test can see at 48 against 48.
FISHER_TABLE = [(14, 2, 0.0018), (24, 10, 0.0052), (19, 7, 0.011), (10, 2, 0.027),
                (14, 5, 0.039), (29, 19, 0.066)]  # fmt: skip


@pytest.mark.parametrize(("before", "after", "stated"), FISHER_TABLE)
def test_fisher_at_48_against_48_as_the_design_says(before, after, stated):
    p = fisher_exact(before, 48, after, 48)
    assert p == pytest.approx(lgamma_fisher(before, 48, after, 48), rel=1e-9)
    digits = len(repr(stated).split(".")[1])
    assert round(p, digits) == pytest.approx(stated), p


# -- textbook values -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("hits", "n", "lower", "upper"),
    [(81, 263, 0.2553, 0.3662), (15, 148, 0.0624, 0.1605), (0, 20, 0.0, 0.1611),
     (1, 29, 0.0061, 0.1718)],
)  # fmt: skip
def test_wilson_matches_newcombes_table(hits, n, lower, upper):
    # Newcombe (1998), "Two-sided confidence intervals for the single proportion", method 3.
    interval = wilson(hits, n)
    assert round(interval.lower, 4) == lower
    assert round(interval.upper, 4) == upper


def test_wilson_is_the_score_interval_it_claims_to_be():
    # The bounds are the two rates at which the observed rate lies exactly z standard errors
    # away, the error taken at the bound: (p̂ − p)² = z² p(1 − p)/n.
    z = rates.z_for(0.95)
    for hits, n in [(3, 10), (17, 40), (1, 3), (99, 100)]:
        for bound in (wilson(hits, n).lower, wilson(hits, n).upper):
            assert (hits / n - bound) ** 2 == pytest.approx(z * z * bound * (1 - bound) / n)


def test_the_confidence_gives_the_normal_quantile():
    assert rates.z_for(0.95) == pytest.approx(1.959964, abs=1e-6)
    assert rates.z_for(0.99) == pytest.approx(2.575829, abs=1e-6)


def test_fisher_matches_the_textbook_tables():
    # Fisher's lady tasting tea: 3 of 4 right against 1 of 4, two-sided 34/70.
    assert fisher_exact(3, 4, 1, 4) == pytest.approx(34 / 70)
    # The dieting example of the usual introduction: 1 of 10 men, 11 of 14 women.
    assert fisher_exact(1, 10, 11, 14) == pytest.approx(0.002759, abs=5e-7)
    assert fisher_exact(1, 10, 11, 14) == fisher_exact(11, 14, 1, 10)


def test_holm_and_benjamini_hochberg_on_the_example_of_the_paper():
    # Benjamini & Hochberg (1995), section 4: fifteen p-values; at 0.05 the step-up procedure
    # rejects four, the step-down (Holm's) three.
    pvalues = [0.0201, 0.0001, 0.0004, 0.0019, 0.0095, 0.0278, 0.0298, 0.0344, 0.0459,
               0.3240, 0.4262, 0.5719, 0.6528, 0.7590, 1.000]  # fmt: skip
    smallest = {0.0001, 0.0004, 0.0019, 0.0095}
    bh = rejected(benjamini_hochberg(pvalues), 0.05)
    assert {p for p, r in zip(pvalues, bh, strict=True) if r} == smallest
    by_holm = rejected(holm(pvalues), 0.05)
    assert {p for p, r in zip(pvalues, by_holm, strict=True) if r} == smallest - {0.0095}


def test_holm_and_benjamini_hochberg_adjust_as_by_hand():
    pvalues = [0.01, 0.04, 0.03, 0.005]
    assert holm(pvalues) == pytest.approx([0.03, 0.06, 0.06, 0.02])
    assert benjamini_hochberg(pvalues) == pytest.approx([0.02, 0.04, 0.04, 0.02])
    assert holm([0.5, 0.9]) == [1.0, 1.0]
    # Step-up: the largest p-value that passes carries every smaller one with it.
    assert benjamini_hochberg([0.04, 0.045, 0.05]) == pytest.approx([0.05, 0.05, 0.05])
    assert rejected(benjamini_hochberg([0.04, 0.045, 0.05]), 0.05) == [True, True, True]
    assert holm([]) == [] and benjamini_hochberg([]) == []


# -- worst cases with runs that were not results -------------------------------------------


def test_unknown_runs_are_a_hit_above_and_a_miss_below():
    interval = worst_case_interval(3, 40, 2)
    assert interval.lower == wilson(3, 42).lower
    assert interval.upper == wilson(5, 42).upper
    assert interval.bound == "wilson"
    plain = wilson(3, 40)
    assert interval.lower < plain.lower and interval.upper > plain.upper


def test_no_hit_and_nothing_unknown_is_bounded_by_the_rule_of_three():
    assert worst_case_interval(0, 48, 0) == Interval(0.0, 3 / 48, "rule_of_three")
    assert worst_case_interval(48, 48, 0) == Interval(1 - 3 / 48, 1.0, "rule_of_three")
    # With a run unknown, it is Wilson again: the unknown run may have been the hit.
    assert worst_case_interval(0, 47, 1) == Interval(0.0, wilson(1, 48).upper)


def test_the_sequential_test_reads_an_unknown_run_against_each_decision():
    test = Sprt()
    # "absent": the unknown run counts as a hit, and 72 runs without one are needed, not 48.
    assert test.read([UNKNOWN] + [MISS] * 71).decision is Decision.CONTINUE
    assert test.read([UNKNOWN] + [MISS] * 72) == rates.Reading(Decision.ABSENT, 73)
    # Two fit within 100 runs, a third does not (4.7).
    assert test.read([UNKNOWN] * 2 + [MISS] * 96).decision is Decision.ABSENT
    assert test.read([UNKNOWN] * 3 + [MISS] * 97).decision is Decision.CONTINUE
    # "present": the unknown run counts as a miss, and one hit after it no longer decides.
    assert test.read([HIT]) == rates.Reading(Decision.PRESENT, 1)
    assert test.read([UNKNOWN, HIT]).decision is Decision.CONTINUE


def test_at_the_budget_unknown_runs_tell_incomplete_from_undecided():
    test = Sprt()
    held = [UNKNOWN] * 3 + [MISS] * 97
    assert test.read(held).decision is Decision.CONTINUE
    assert test.held_up_by_unknown(held)
    # A rate between the hypotheses, nothing unknown: the data does not decide.
    undecided = ([MISS] * 24 + [HIT]) * 4
    assert test.read(undecided).decision is Decision.CONTINUE
    assert not test.held_up_by_unknown(undecided)
    # Held up on the side of "present" alone: taken as a miss, the unknown run leaves the data
    # undecided; taken as the hit it may have been, it decides "present" at once.
    one_side = [UNKNOWN] + undecided[1:]
    assert test.read(one_side).decision is Decision.CONTINUE
    assert test.read([MISS if o is UNKNOWN else o for o in one_side]).decision is Decision.CONTINUE
    assert test.held_up_by_unknown(one_side)


def test_evidence_is_present_at_the_first_hit_and_absent_at_the_bound():
    assert evidence([MISS] * 10 + [HIT]) == rates.Reading(Decision.PRESENT, 11)
    assert evidence([MISS] * 50) == rates.Reading(Decision.ABSENT, 44)
    assert evidence([MISS] * 43) == rates.Reading(Decision.CONTINUE, 43)


def test_evidence_is_blocked_by_a_run_the_server_may_have_failed():
    blocked = evidence([MISS] * 5 + [UNKNOWN] + [MISS] * 90)
    assert blocked == rates.Reading(Decision.CONTINUE, 96, blocked=True)
    # A hit still decides.
    assert evidence([UNKNOWN, MISS, HIT]) == rates.Reading(Decision.PRESENT, 3, blocked=True)


# -- edges ---------------------------------------------------------------------------------


def test_no_runs_say_nothing():
    assert wilson(0, 0) == Interval(0.0, 1.0)
    assert worst_case_interval(0, 0, 0) == Interval(0.0, 1.0)
    assert fisher_exact(0, 0, 0, 0) == 1.0
    assert evidence([]) == rates.Reading(Decision.CONTINUE, 0)
    assert Sprt().read([]) == rates.Reading(Decision.CONTINUE, 0)
    with pytest.raises(ValueError):
        rule_of_three(0)
    # Fewer than three runs bound nothing below 1.
    assert rule_of_three(1) == rule_of_three(2) == rule_of_three(3) == 1.0
    assert worst_case_interval(0, 2, 0) == Interval(0.0, 1.0, "rule_of_three")


def test_every_run_a_hit():
    for n in (1, 2, 7, 100):
        interval = wilson(n, n)
        assert interval.upper == 1.0
        assert 0.0 < interval.lower < 1.0
        assert interval.lower == pytest.approx(1 - wilson(0, n).upper)
    assert wilson(0, 7).lower == 0.0
    # Where the formula itself lands a rounding off the edge: 1.4e-17 above 0 at n = 13,
    # 1.1e-16 below 1 at n = 3.
    assert wilson(0, 13).lower == 0.0 and wilson(0, 18).lower == 0.0
    assert wilson(3, 3).upper == 1.0 and wilson(12, 12).upper == 1.0
    assert worst_case_interval(1, 1, 0) == Interval(0.0, 1.0, "rule_of_three")
    assert fisher_exact(5, 5, 5, 5) == 1.0


def test_a_rate_of_zero_under_absent_makes_one_hit_proof():
    test = Sprt(p0=0.0, p1=0.10, alpha=0.10, beta=0.01)
    assert test.hit_step == -math.inf
    assert test.decide(1, 0) is Decision.PRESENT
    assert test.decide(1, 500) is Decision.PRESENT
    assert test.min_runs_present() == 1


@pytest.mark.parametrize(("p_present", "beta", "_sprt", "exact_runs"), VARIANTS)
def test_with_no_false_alarm_to_hold_the_test_is_the_exact_bound(
    p_present, beta, _sprt, exact_runs
):
    test = Sprt(p0=0.0, p1=p_present, alpha=0.0, beta=beta)
    assert test.present_boundary == -math.inf
    assert test.min_runs_absent() == exact_runs
    assert test.read([MISS] * 100) == rates.Reading(Decision.ABSENT, exact_runs)


def test_a_rate_of_one_under_present_makes_one_miss_decide():
    test = Sprt(p0=0.5, p1=1.0, alpha=0.05, beta=0.05)
    assert test.decide(0, 1) is Decision.ABSENT
    assert test.min_runs_absent() == 1
    assert exact_zero_hit_bound(1.0, 0.01) == 1


def test_the_truncated_test_agrees_with_every_sequence_enumerated():
    test = Sprt(p0=0.05, p1=0.40, alpha=0.10, beta=0.05)
    for rate in (0.0, 0.1, 0.3, 0.6):
        found = test.operating(rate, 12)
        absent, present = enumerated_operating(test, rate, 12)
        assert found.absent == pytest.approx(absent, abs=1e-12)
        assert found.present == pytest.approx(present, abs=1e-12)


def test_fisher_agrees_with_log_factorials_over_many_tables():
    for a, n_a, b, n_b in itertools.product(range(0, 9, 2), (8, 13), range(0, 9, 3), (8, 11)):
        assert fisher_exact(a, n_a, b, n_b) == pytest.approx(lgamma_fisher(a, n_a, b, n_b))


def test_the_bound_is_decided_exactly_on_its_boundary():
    # 0.5² = 0.25 exactly: two runs, not three, and no rounding moves it.
    assert exact_zero_hit_bound(0.5, 0.25) == 2
    assert exact_zero_hit_bound(0.5, 0.2499) == 3


@pytest.mark.parametrize(
    "arguments",
    [{"p0": 0.1, "p1": 0.1}, {"p0": 0.2, "p1": 0.1}, {"beta": 0.0},
     {"alpha": 0.6, "beta": 0.5}, {"p0": 0.01, "alpha": 0.0}, {"p1": 1.2}],
)  # fmt: skip
def test_a_test_that_cannot_hold_is_refused(arguments):
    with pytest.raises(ValueError):
        Sprt(**arguments)


def test_counts_that_cannot_be_are_refused():
    for call in (lambda: wilson(3, 2), lambda: wilson(-1, 2), lambda: fisher_exact(4, 3, 0, 3),
                 lambda: worst_case_interval(0, 3, -1), lambda: holm([1.5]),
                 lambda: exact_zero_hit_bound(0.0, 0.01)):  # fmt: skip
        with pytest.raises(ValueError):
            call()


# -- what the module is not ----------------------------------------------------------------


def test_the_module_stands_alone_on_the_standard_library_and_no_run_calls_it_yet():
    import ast
    import sys
    from pathlib import Path

    source = Path(rates.__file__)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}, imported
    names = ("mcp_kymograph.rates", "from mcp_kymograph import rates", "from . import rates")
    callers = [
        path.name
        for path in source.parent.rglob("*.py")
        if path != source and any(name in path.read_text() for name in names)
    ]
    # The false-alarm measurement is a calibration tool beside the runs, not a step of one.
    assert callers == ["false_alarms.py"]
