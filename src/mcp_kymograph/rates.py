"""Rates over repeated runs: the calculations of docs/design/repeated-runs.md, and nothing else.

Pure functions and small value types over counts and outcomes; no I/O, no store, no fleet, and
nothing outside the standard library (``math`` and ``fractions``). The one caller so far is
the false-alarm calibration tool, which is no step of any run, for the Wilson interval, the rule
of three and the default confidence; no run, fleet or report calls this module. The rest is
the arithmetic the design rests on, built and tested before anything depends on it.

What is here, by section of the design:

* the Wilson interval and the rule of three (3.2), and the worst-case bounds a run without a
  result enters as (3.2): as a hit for the upper bound, as a miss for the lower;
* the exact zero-hit bound of the evidence procedure (4.2): the fewest runs without a hit
  after which "absent" holds at β, and the procedure's decision over outcomes, blocked by a run
  the server may have failed;
* Wald's sequential probability ratio test for Bernoulli observations (4.3, 4.5): its
  boundaries, the log-likelihood each observation adds, the decision after each, the fewest
  runs for either decision, the worst-case reading of a run without a result, and the exact
  operating characteristic of the test truncated at a budget;
* Fisher's exact test, two-sided, for two rates (5), over the hypergeometric distribution in
  exact integer arithmetic;
* Holm's and Benjamini–Hochberg's adjustments of a list of p-values (5.1).

The log-likelihood ratio is oriented as in the design: it is ``ln L(p₀) / L(p₁)``, so a run
without a hit moves it up, towards "absent", and a hit moves it down, towards "present".

**What this module does not do: it judges nothing.** It computes from counts and outcomes it
is handed, and answers what a test says about them — never what that means for a server, a
run, a finding or a comparison. In particular, none of the following is here, and none of it
may be inferred from a result of this module alone:

* *what an outcome is* — which run counts as a hit, a miss or a run without a result, and
  whether the server can have caused a run's failure (design 4.6); the caller hands outcomes
  in already sorted;
* *which procedure an identity is tested by* — evidence or heuristic (4.1); the caller picks
  :func:`evidence` or :class:`Sprt`;
* *classes and states* — stable, absent, flaky, undecided or incomplete for an identity, and
  the state of a series (3.1, 4.4); :class:`Decision` is a test's outcome over the sequence it
  was given, and ``CONTINUE`` is only "not yet", not "undecided";
* *when to stop* a series, the budget, the retry limit, the order of outcomes, and what runs in
  parallel (2.3, 4.6–4.8);
* *the comparison of two fleets* — which identities are compared, when a change is real, what
  is reported (5); :func:`fisher_exact` gives a p-value and :func:`holm` and
  :func:`benjamini_hochberg` adjust a list of them, nothing more;
* *recording or storing* anything.

All of that is the verdict's (design 6), and lives with it. The constants below are the
design's, named and used as the defaults here so that its arithmetic can be checked against
it; whether they are the ones a verdict applies is decided there, not here.
"""

from __future__ import annotations

import enum
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fractions import Fraction

# -- the constants of the design -----------------------------------------------------------

#: Confidence of every reported interval (3.2). The design writes z = 1.96; the z used here is
#: the exact two-sided quantile of the standard normal, 1.95996…, which differs from 1.96 in
#: the fourth decimal of an interval at most.
CONFIDENCE = 0.95

#: The rate a heuristic identity may have and still be "absent" (4.3): a background rate of
#: harmless content with the same shape.
P_ABSENT = 0.01
#: The rate at which a finding must not be missed (4.2, 4.3).
P_PRESENT = 0.10
#: A false alarm of the sequential test (4.3): deciding "present" at P_ABSENT. Higher than BETA
#: because a missed finding costs more than a false alarm.
ALPHA = 0.10
#: A missed finding (4.2, 4.3): deciding "absent" at P_PRESENT.
BETA = 0.01

#: The stable test (4.5): stable p = 0.99 against flaky p = 0.80, symmetric at 0.05, because
#: the expensive error ("absent" when present) is not made there.
P_STABLE = 0.99
P_FLAKY = 0.80
STABLE_ALPHA = 0.05
STABLE_BETA = 0.05

#: Scheduled runs per key, retries not counted (4.7).
BUDGET = 100

#: The false discovery rate the comparison of two fleets is held at (5.1).
FDR_Q = 0.05


# -- intervals -----------------------------------------------------------------------------


def z_for(confidence: float) -> float:
    """The two-sided standard normal quantile: ``P(|Z| ≤ z) = confidence``.

    Found by bisection on ``math.erf``, which is exact to the last bit or two; sixty halvings
    of [0, 40] leave an interval far below that.
    """
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must lie strictly between 0 and 1, not {confidence}")
    low, high = 0.0, 40.0
    for _ in range(200):
        middle = (low + high) / 2
        if math.erf(middle / math.sqrt(2.0)) < confidence:
            low = middle
        else:
            high = middle
        if high - low <= 1e-15:
            break
    return (low + high) / 2


def _check_counts(hits: int, n: int) -> None:
    if n < 0 or hits < 0 or hits > n:
        raise ValueError(f"need 0 ≤ hits ≤ n, not hits={hits}, n={n}")


@dataclass(frozen=True, slots=True)
class Interval:
    """A two-sided bound on a rate, and which formula gave it (``wilson``, ``rule_of_three``)."""

    lower: float
    upper: float
    bound: str = "wilson"


def wilson(hits: int, n: int, *, confidence: float = CONFIDENCE) -> Interval:
    """The Wilson score interval for ``hits`` successes in ``n`` runs (3.2).

    ``n = 0`` is no information: the interval is all of [0, 1]. ``hits = 0`` has the lower
    bound 0 and ``hits = n`` the upper bound 1 exactly, not up to rounding.
    """
    _check_counts(hits, n)
    if n == 0:
        return Interval(0.0, 1.0)
    z = z_for(confidence)
    rate = hits / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    centre = (rate + z2 / (2 * n)) / denominator
    half = z * math.sqrt(rate * (1.0 - rate) / n + z2 / (4 * n * n)) / denominator
    lower = 0.0 if hits == 0 else max(0.0, centre - half)
    upper = 1.0 if hits == n else min(1.0, centre + half)
    return Interval(lower, upper)


def rule_of_three(n: int) -> float:
    """The 95 % upper bound on a rate never seen in ``n`` runs: ``3/n``, at most 1 (3.2)."""
    if n <= 0:
        raise ValueError(f"the rule of three needs at least one run, not {n}")
    return min(1.0, 3.0 / n)


def worst_case_interval(
    hits: int, observed: int, unknown: int, *, confidence: float = CONFIDENCE
) -> Interval:
    """The bounds of 3.2 with ``unknown`` runs that were not results.

    ``n = observed + unknown``. The upper bound is taken as if every unknown run had been a
    hit, the lower as if every one had been a miss: ``upper = U(hits + unknown, n)``,
    ``lower = L(hits, n)``. With no hit and nothing unknown the upper bound is the rule of
    three; with every run a hit (``hits = n``) the lower bound is ``1 − 3/n``.
    """
    _check_counts(hits, observed)
    if unknown < 0:
        raise ValueError(f"unknown must not be negative, not {unknown}")
    n = observed + unknown
    if n == 0:
        return Interval(0.0, 1.0)
    if unknown == 0 and hits == 0:
        return Interval(0.0, rule_of_three(n), "rule_of_three")
    if unknown == 0 and hits == n:
        return Interval(max(0.0, 1.0 - 3.0 / n), 1.0, "rule_of_three")
    lower = wilson(hits, n, confidence=confidence).lower
    upper = wilson(hits + unknown, n, confidence=confidence).upper
    return Interval(lower, upper)


# -- outcomes and decisions ----------------------------------------------------------------


class Outcome(enum.Enum):
    """One considered run, as an identity's test sees it."""

    HIT = "hit"
    MISS = "miss"
    #: Not a result, for a cause the server can bring about (4.6): could have been either.
    UNKNOWN = "unknown"


class Decision(enum.Enum):
    PRESENT = "present"
    ABSENT = "absent"
    #: Not decided yet: another run may decide it.
    CONTINUE = "continue"


@dataclass(frozen=True, slots=True)
class Reading:
    """A test's decision over a sequence of outcomes, and after how many of them it fell.

    ``runs`` is the number of outcomes read: the index of the deciding one plus one, or all of
    them while the test continues. ``blocked`` says that "absent" can no longer be reached in
    this series, whatever comes (the evidence procedure after a run without a result).
    """

    decision: Decision
    runs: int
    blocked: bool = False


def _fraction(value: float | Fraction) -> Fraction:
    """A probability at the value it is written as: 0.1 is one tenth, not the nearest double."""
    if isinstance(value, Fraction):
        return value
    return Fraction(repr(value)) if isinstance(value, float) else Fraction(value)


def exact_zero_hit_bound(p_present: float | Fraction, beta: float | Fraction) -> int:
    """The fewest runs without a hit after which "absent" holds at β, when absent means rate 0.

    The smallest ``n`` with ``(1 − p₁)ⁿ ≤ β`` (4.2): a finding present at rate p₁ or more goes
    ``n`` runs without a hit with probability at most β. Compared exactly, in fractions, so a
    bound that lands on the boundary is not moved by rounding.
    """
    p1, b = _fraction(p_present), _fraction(beta)
    if not 0 < p1 <= 1:
        raise ValueError(f"p_present must lie in (0, 1], not {p_present}")
    if not 0 < b < 1:
        raise ValueError(f"beta must lie strictly between 0 and 1, not {beta}")
    if p1 == 1:
        return 1
    estimate = max(1, math.ceil(math.log(float(b)) / math.log(float(1 - p1))))
    while estimate > 1 and (1 - p1) ** (estimate - 1) <= b:
        estimate -= 1
    while (1 - p1) ** estimate > b:
        estimate += 1
    return estimate


def evidence(
    outcomes: Iterable[Outcome],
    *,
    p_present: float | Fraction = P_PRESENT,
    beta: float | Fraction = BETA,
) -> Reading:
    """The evidence procedure (4.2) over outcomes in repetition order.

    "Present" at the first hit. "Absent" once the runs without a hit reach the exact zero-hit
    bound — unless a run without a result came first: that one might have been the hit, so
    "absent" is blocked for the rest of the series, and only a hit can still decide.
    """
    needed = exact_zero_hit_bound(p_present, beta)
    misses = 0
    blocked = False
    runs = 0
    for runs, outcome in enumerate(outcomes, start=1):  # noqa: B007 - runs is read after
        if outcome is Outcome.HIT:
            return Reading(Decision.PRESENT, runs, blocked)
        if outcome is Outcome.UNKNOWN:
            blocked = True
            continue
        misses += 1
        if not blocked and misses >= needed:
            return Reading(Decision.ABSENT, runs)
    return Reading(Decision.CONTINUE, runs, blocked)


# -- the sequential probability ratio test -------------------------------------------------


def _log(value: float) -> float:
    return -math.inf if value == 0 else math.log(value)


def _times(count: int, step: float) -> float:
    """``count · step``, with no run contributing nothing even when a step is infinite."""
    return 0.0 if count == 0 else count * step


def _fewest(target: float, step: float) -> int | None:
    """The smallest ``n ≥ 1`` with ``n · step`` past ``target`` in the direction of ``step``.

    ``None`` when no number of steps gets there. The check is the same multiplication the
    decision uses, so the count and the decision cannot disagree by a rounding.
    """
    if step == 0:
        return None
    reached = (lambda n: n * step >= target) if step > 0 else (lambda n: n * step <= target)
    if math.isinf(step):
        return 1
    if math.isinf(target):
        return None
    n = max(1, math.ceil(target / step))
    while n > 1 and reached(n - 1):
        n -= 1
    while not reached(n):
        n += 1
    return n


@dataclass(frozen=True, slots=True)
class Operating:
    """What a truncated test does at one true rate: how it ends, and how long it takes."""

    absent: float
    present: float
    undecided: float
    expected_runs: float


@dataclass(frozen=True, slots=True)
class Sprt:
    """Wald's sequential probability ratio test for Bernoulli observations.

    H_absent: rate ``p0`` against H_present: rate ``p1``, ``0 ≤ p0 < p1 ≤ 1``. ``alpha`` is
    the false alarm (deciding "present" at p0), ``beta`` the miss (deciding "absent" at p1).
    The same test serves the stable test of 4.5, with the flaky rate as ``p0`` and the stable
    one as ``p1``: there "present" reads "stable".

    ``p0 = 0`` is the evidence case: one hit is impossible under H_absent, so it decides
    "present" at once. With ``alpha = 0`` as well, the test is the exact zero-hit bound.
    """

    p0: float = P_ABSENT
    p1: float = P_PRESENT
    alpha: float = ALPHA
    beta: float = BETA

    def __post_init__(self) -> None:
        if not 0.0 <= self.p0 < self.p1 <= 1.0:
            raise ValueError(f"need 0 ≤ p0 < p1 ≤ 1, not p0={self.p0}, p1={self.p1}")
        if not 0.0 < self.beta < 1.0 or not 0.0 <= self.alpha < 1.0:
            raise ValueError(f"need 0 ≤ alpha < 1 and 0 < beta < 1, not {self.alpha}, {self.beta}")
        if self.alpha + self.beta >= 1.0:
            raise ValueError("alpha + beta must stay below 1, or the boundaries cross")
        if self.alpha == 0.0 and self.p0 > 0.0:
            raise ValueError("alpha = 0 needs p0 = 0: a hit possible under H_absent can mislead")

    # The boundaries and the steps.

    @property
    def absent_boundary(self) -> float:
        """A = ln((1 − α) / β): "absent" once the log-likelihood ratio reaches it."""
        return math.log((1.0 - self.alpha) / self.beta)

    @property
    def present_boundary(self) -> float:
        """B = ln(α / (1 − β)): "present" once the ratio falls to it; −∞ when α = 0."""
        return _log(self.alpha / (1.0 - self.beta))

    @property
    def miss_step(self) -> float:
        """What a run without a hit adds: ln((1 − p0) / (1 − p1)) > 0; +∞ when p1 = 1."""
        return math.inf if self.p1 == 1.0 else math.log((1.0 - self.p0) / (1.0 - self.p1))

    @property
    def hit_step(self) -> float:
        """What a hit adds: ln(p0 / p1) < 0; −∞ when p0 = 0."""
        return _log(self.p0 / self.p1)

    def log_likelihood(self, hits: int, misses: int) -> float:
        """The ratio after ``hits`` hits and ``misses`` runs without one, in any order."""
        return _times(misses, self.miss_step) + _times(hits, self.hit_step)

    def decide(self, hits: int, misses: int) -> Decision:
        """The decision after these counts."""
        ratio = self.log_likelihood(hits, misses)
        if math.isnan(ratio):
            raise ValueError("a hit impossible under H_present and one under H_absent together")
        if ratio >= self.absent_boundary:
            return Decision.ABSENT
        if ratio <= self.present_boundary:
            return Decision.PRESENT
        return Decision.CONTINUE

    def min_runs_absent(self) -> int | None:
        """The fewest runs for "absent": that many without a hit, and none earlier suffices."""
        return _fewest(self.absent_boundary, self.miss_step)

    def min_runs_present(self) -> int | None:
        """The fewest runs for "present": that many hits in a row. ``None`` if none suffice."""
        return _fewest(self.present_boundary, self.hit_step)

    # Over a series.

    def read(self, outcomes: Iterable[Outcome]) -> Reading:
        """The test over outcomes in repetition order, stopping at the first decision.

        A run without a result enters twice, always on the side that makes a decision harder
        (4.3): as a hit on the path that can decide "absent", as a miss on the path that can
        decide "present". A decision falls only when the path worst for it crosses.
        """
        hits = misses = unknown = 0
        runs = 0
        for runs, outcome in enumerate(outcomes, start=1):  # noqa: B007 - runs is read after
            if outcome is Outcome.HIT:
                hits += 1
            elif outcome is Outcome.MISS:
                misses += 1
            else:
                unknown += 1
            decision = self._worst_case(hits, misses, unknown)
            if decision is not Decision.CONTINUE:
                return Reading(decision, runs)
        return Reading(Decision.CONTINUE, runs)

    def _worst_case(self, hits: int, misses: int, unknown: int) -> Decision:
        if self.decide(hits + unknown, misses) is Decision.ABSENT:
            return Decision.ABSENT
        if self.decide(hits, misses + unknown) is Decision.PRESENT:
            return Decision.PRESENT
        return Decision.CONTINUE

    def held_up_by_unknown(self, outcomes: Sequence[Outcome]) -> bool:
        """At the budget, undecided: would the runs without a result, taken favourably, decide?

        Taken favourably for "absent" they are misses, for "present" hits (4.3). If either
        reading crosses its boundary at any point of the series, it is the runs without a
        result that kept the test open — ``incomplete``; if neither does, the data itself
        does not decide — ``undecided``.
        """
        favourable_absent = [Outcome.MISS if o is Outcome.UNKNOWN else o for o in outcomes]
        favourable_present = [Outcome.HIT if o is Outcome.UNKNOWN else o for o in outcomes]
        return (
            self.read(favourable_absent).decision is Decision.ABSENT
            or self.read(favourable_present).decision is Decision.PRESENT
        )

    def operating(self, rate: float, budget: int = BUDGET) -> Operating:
        """The exact behaviour of the test truncated at ``budget`` runs, at a true ``rate``.

        Every run a result. Computed over the number of hits after each run, so the paths are
        summed, not sampled.
        """
        if not 0.0 <= rate <= 1.0:
            raise ValueError(f"rate must lie in [0, 1], not {rate}")
        if budget < 1:
            raise ValueError(f"budget must be at least 1, not {budget}")
        running = {0: 1.0}
        absent = present = expected = 0.0
        for n in range(1, budget + 1):
            expected += sum(running.values())
            following: dict[int, float] = {}
            for hits, mass in running.items():
                for more, chance in ((1, rate), (0, 1.0 - rate)):
                    if chance == 0.0:
                        continue
                    count = hits + more
                    decision = self.decide(count, n - count)
                    if decision is Decision.ABSENT:
                        absent += mass * chance
                    elif decision is Decision.PRESENT:
                        present += mass * chance
                    else:
                        following[count] = following.get(count, 0.0) + mass * chance
            running = following
        return Operating(absent, present, sum(running.values()), expected)


# -- comparing two rates -------------------------------------------------------------------


def fisher_exact(hits_a: int, n_a: int, hits_b: int, n_b: int) -> float:
    """Fisher's exact test, two-sided, for ``hits_a / n_a`` against ``hits_b / n_b`` (5).

    Conditioned on the margins, the hits of the first sample are hypergeometric. The p-value
    is the probability of every table as likely as the one observed or less, summed. Each
    table's probability is an exact integer ratio (``math.comb``), so "as likely" is decided
    without a tolerance.
    """
    _check_counts(hits_a, n_a)
    _check_counts(hits_b, n_b)
    hits = hits_a + hits_b
    total = n_a + n_b
    if total == 0:
        return 1.0

    def weight(k: int) -> int:
        return math.comb(n_a, k) * math.comb(n_b, hits - k)

    observed = weight(hits_a)
    low, high = max(0, hits - n_b), min(hits, n_a)
    tail = sum(w for w in map(weight, range(low, high + 1)) if w <= observed)
    return min(1.0, float(Fraction(tail, math.comb(total, hits))))


def _check_pvalues(pvalues: Sequence[float]) -> None:
    for value in pvalues:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"a p-value lies in [0, 1], not {value}")


def holm(pvalues: Sequence[float]) -> list[float]:
    """Holm's step-down adjustment; adjusted p-values in the order given.

    Reject at level α wherever the adjusted value is ≤ α: that holds the chance of any false
    rejection in the family at α. Products are taken exactly and rounded once, so a p-value
    that lands on the level is not pushed past it by a rounding.
    """
    _check_pvalues(pvalues)
    m = len(pvalues)
    order = sorted(range(m), key=lambda index: pvalues[index])
    adjusted = [0.0] * m
    running = Fraction(0)
    for rank, index in enumerate(order):
        running = max(running, min(Fraction(1), (m - rank) * Fraction(pvalues[index])))
        adjusted[index] = float(running)
    return adjusted


def benjamini_hochberg(pvalues: Sequence[float]) -> list[float]:
    """Benjamini–Hochberg's step-up adjustment; adjusted p-values in the order given.

    Reject at q wherever the adjusted value is ≤ q: that holds the expected share of false
    rejections among the rejections at q (independent or positively dependent tests, 5.1).
    Exact like :func:`holm`.
    """
    _check_pvalues(pvalues)
    m = len(pvalues)
    order = sorted(range(m), key=lambda index: pvalues[index])
    adjusted = [0.0] * m
    running = Fraction(1)
    for rank in range(m - 1, -1, -1):
        index = order[rank]
        running = min(running, Fraction(pvalues[index]) * m / (rank + 1))
        adjusted[index] = float(running)
    return adjusted


def rejected(adjusted: Sequence[float], level: float = FDR_Q) -> list[bool]:
    """Which of the adjusted p-values are rejections at ``level``."""
    return [value <= level for value in adjusted]
