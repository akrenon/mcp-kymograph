# Design: repeated runs and rates

Status: **proposal, not implemented.** No fleet repeats a run: `fleet run` has no `--repeat`,
and a fleet runs every key once. What is built of it: the verdict tells a sandbox failure before
the target from one after it (`sandbox_failed_after_target`, rules version 6; 4.6);
`tool_name_collision` is split into `tool_name_duplicate` (evidence) and `tool_name_lookalike`
(heuristic), and every signal's kind is in `signals.KINDS` (4.1); a fleet's digest carries each
result's causes and is named the full digest (2.3); and `rates.py` holds the arithmetic of
sections 3 to 5, which only `false_alarms.py`, a calibration tool outside every run, uses.
Revised 2026-10-06 with the decisions on the first draft (sections 0, 3, 4, 2.3, 8), and again
the same day with the second round: evidence and heuristics are tested apart (4.1–4.4), runs
without a result are split by whether the server can cause them (4.6), the budget is argued
anew (4.7), and the comparison is corrected over all of it at once (5.1). Decided after that
round: "absent" for evidence is blocked by a run the server may have failed (4.2), the
comparison is corrected by Benjamini–Hochberg (5.1), R = 5 holds only until q is measured
(4.6), and both splits of section 8 are made in the round that builds the evidence path.

Today a fleet runs every corpus entry under every scenario exactly once
(`src/mcp_kymograph/fleet.py`, `plan` and `run`). A single run answers "did finding X appear this
time". The next step asks "how often does it appear, and how sure are we" — and lets a
comparison between two fleets tell a real change from a run that happened to come out
differently. This document says where a run can come out differently, how repetitions are
kept, what is reported, when to stop repeating, how two fleets are compared, and where the
judgement lives.

Three lines hold throughout:

* **A run that is not a result is not an observation** — and it is not silently left out
  either. `incomplete`, `server_failed` and `sandbox_failed` runs (`src/mcp_kymograph/verdict.py`)
  never count as "did not find". Where the server can have caused the run's failure, it enters
  every bound as the worst case for the decision being made (3.2, 4.6); where it cannot, the run
  says nothing about the server, and it is run again — a bounded number of times (4.6).
* **A missed finding costs more than a false alarm.** Every error rate that can let a finding
  pass as absent is held lower than the one that raises an alarm (4.2, 4.3).
* **The judgement is the verdict's.** Rates, intervals, the stopping rule and the comparison of
  rates are part of the verdict. The fleet schedules and files; the store keeps; neither
  computes a rate or decides what one means.

## 0. Opt-in: one run stays the default

Not built: there is no `--repeat`, so every fleet is a single-run fleet and nothing carries the
`statistics` or `basis` words below.

Repetition is switched on per fleet (`fleet run --repeat`); without it a fleet runs every key
once, exactly as today, and the reference/poison pair stays pinned to that. A single run is
never dressed up as a rate: its result carries `statistics: "single run — no statistical
statement"`, the report prints that beside every key, and a comparison involving a single-run
fleet says so on every entry it compares (`basis: "single run"`) — its new and gone are one
run's word, as they are today, and no interval or class is shown for it.

## 1. Where a run can come out differently

Two kinds of variation are kept apart, because they mean different things.

**A. Whether the run is a result at all** (its state). These come from timing and resources,
not from the server's behaviour. Each turns a run into a non-result, never into a different
result — the verdict sees to that:

| Source | Where | What it does under load or bad luck |
|---|---|---|
| Step timeout | `driver.py:73` `DEFAULT_STEP_TIMEOUT = 30.0` | a slow answer becomes `step_unanswered (no_answer)` → `incomplete` |
| Tail after the server exits | `proxy.py:65` `TAIL_SECONDS = 0.5` | the server's last words after its exit may be cut; a finding counted but not written → `incomplete` (count check in `verdict._completeness`) |
| Wait for the script's end | `proxy.py:74`, `Limits.client_settle_seconds` | the driver's `script_finished` misses the closing event → `incomplete`, now named (`limit_exceeded`) |
| Shutdown budget | `proxy.py:86–90` (grace 3 s, budget 8 s, final write 2 s) | events left unwritten → `unwritten_events` → `incomplete` |
| Event queue | `sink.py:58` `DEFAULT_QUEUE_SIZE = 1000`; droppable path `proxy.py:212, 291, 307` | `message`, `finding` and `findings_capped` events are offered, not put; a dropped finding fails the count check → `incomplete`; a dropped message changes nothing judged |
| Rule watchdog | `proxy.py:95` `rule_budget_seconds = 10.0` | a rule stalled by load past the budget ends the tool (exit 70), no closing event → `incomplete` |
| Sandbox timeouts | `sandbox/runner.py:99–103` (container 120 s, sink 60/15 s, probe arrival 5 s) | a step that does not finish in time → `sandbox_failed` |
| Sink capacity | `sandbox/inside/sink.py:86` `MAX_PENDING`, host `net.core.rmem_max` | datagrams lost → `udp_loss` → `incomplete` (`verdict.UDP_LOSS_LIMIT = 0`) |
| Docker daemon | `sandbox/docker.py` | a call that fails or times out → `sandbox_failed` |

**B. What a complete run found.** For the corpus's own fixtures this is deterministic by
construction, and the code adds no randomness of its own to it:

* The inspector cuts findings at 20 per message (`inspection.py:79`) in the order the
  statements and the message's paths are walked (`inspection.py:555–590`): `kept` is a list,
  `over` a dict in insertion order; the only set there (`seen`) is used for membership, never
  iterated. The same message gives the same cut.
* The DNS answer is fixed (`sandbox/inside/common.py`, `DNS_ANSWER_V4`); egress attempts are
  listed sorted (`sandbox/egress.py`, `Record.attempts`).
* What *is* random never reaches a finding key: the masker's handle salt
  (`masking.py:152`), the run id (`output.py:110`), the wall clock (`recorder.py:189`), the
  sandbox nonce (`sandbox/runner.py:285`, probe ports and names only, in the probe's phase).
  They make every recording's bytes — and so its store id, `sha256` of the bytes
  (`store.py:463`) — unique, which is what repetitions need.
* `message_seq` and `path` of a sighting depend on how the server interleaves notifications
  and responses. They are kept as a sighting, never as part of the key (`store.py`, module
  docstring), so this moves no rate.

What varies in a complete run is therefore **the server's own behaviour**: a real server that
reads the clock, draws random numbers, calls a model, or takes another path because its network
is gone. Rates are about that, and only that.

A recorded cap needs care in a rate: a finding cut at the per-message cap
(`findings_capped`) is neither seen nor missed. A run that cut a `(statement, signal)` is not an
observation of the identities under that pair (see 3.3).

## 2. How repetitions are kept

Not built, except the digest a fleet has today (2.3): no repetition index, no `fleet_series`, no
`fleet_rates`, no comparison digest.

### 2.1 The keys stay as they are

* **The finding key is unchanged** — the seven fields of `store.KEY_FIELDS`. Every repetition
  of an entry under a scenario has the same `server_version`, `tool_version` and `scenario`, so
  the same finding in two repetitions is one row in `findings`, sighted in two runs.
* **Every repetition is a run of its own** in `runs`, keyed by the digest of its recording,
  judged by `verdict.assess` and filed in its state — exactly as today. Nothing about a single
  run changes.
* **The result's key stays `(entry, scenario)`.** A repetition is an index under it, never a
  part of it: `fleet_results` gains `repetition INTEGER NOT NULL` and its uniqueness becomes
  `UNIQUE (fleet, entry, scenario, repetition)` (today `store.py:179`). The index is assigned
  when the run is scheduled — 0, 1, 2, … per key — not when it finishes.

### 2.2 The verdict over a series

A new table holds what the verdict concluded per key, the way `runs.state` holds what it
concluded per run:

```
fleet_series (fleet, entry, scenario,
              state,           -- complete | undecided | incomplete | server_failed | sandbox_failed | refused
              runs_scheduled,  -- every repetition started, retries (4.6) included
              runs_complete,   -- of those, results
              runs_considered, -- the decided prefix (2.3)
              non_results,     -- per state and cause, the considered runs that were not results
              retried,         -- runs repeated because nothing the server can cause failed them (4.6)
              problems,
              UNIQUE (fleet, entry, scenario))
fleet_rates  (fleet, entry, scenario, identity,  -- identity: the key without its two version fields
              procedure,                           -- evidence | heuristic (4.1)
              hits, observed, unknown,             -- unknown: considered runs the server may have caused to fail
              lower, upper, bound,                 -- worst-case bounds (3.2); bound: wilson | rule_of_three
              class,                               -- stable | absent | flaky | undecided | incomplete
              UNIQUE (fleet, entry, scenario, identity))
```

Both are written once, at the end of a fleet, from what `verdict` returns — never computed by
the store or the fleet. One more store schema step (the current schema is 13).

### 2.3 Two digests, both independent of order and of parallelism

Repetitions finish in any order, and with more parallelism more of them are in flight when a
key is decided. Neither may move either digest.

* **Order:** the stopping rule (4) reads outcomes in **repetition order**, not completion order.
  A result that arrives early waits until every lower index has arrived.
* **Parallelism:** the key is decided at the first index `n*` at which the rule decides it.
  Repetitions with an index ≥ `n*` that were already running are filed (they are real runs, and
  a reader may look at them) but are **not part of the result**: classes, rates and both
  digests are taken over the prefix `0 … n*−1`, which is the same whatever ran in parallel.

From that prefix, per key sorted by `(entry, scenario)` and per identity sorted:

* **The comparison digest** — provenance, context, the series' state, and per identity its
  **class** only. This is what a comparison between fleets uses (`same_result`): a flaky
  identity is `flaky` in both fleets though its hits differ, and a deterministic corpus is the
  same fleet after fleet.
* **The full digest** — everything in the comparison digest, plus `runs_considered`, the
  non-results per state **and their causes** (`verdict.CAUSES`, per state, counted), and per
  identity `hits`, `observed` and `unknown`. This one pins one fleet exactly: whoever re-reads
  the store can check that the classes follow from the counts, and two fleets have the same
  full digest only if their outcomes did.

Neither contains run ids, times, completion order, parallelism, or a repetition past `n*`.

**Causes belong to the full digest, not to the comparison digest.** Two fleets whose
runs fell short for different reasons did not come out the same, and the full digest says so;
but why a run was not a result says nothing about the server's findings, and the comparison
digest — the one `same_result` will use — is about those. Until the two digests exist, the one
digest a fleet has today (`FleetRun.canonical`) carries each result's causes beside its state:
it is the full digest's predecessor, and `same_result` reads it. A store's fleets digested before
that change compare as different from later ones even when their results agree — the safe
direction.

## 3. What is reported per entry and scenario

Not built: no series, classes or bounds are reported. The Wilson interval, the rule of three and
the worst-case bounds exist as functions in `rates.py`.

### 3.1 The series

`runs_scheduled`, `runs_complete`, `runs_considered`, the runs that were not results (a count per
state and their causes), and the series' state:

* `complete` — every identity decided (4) within the budget.
* `undecided` — the budget ran out with an identity the data itself does not decide: its rate is
  between the hypotheses. A result, reported with its interval; never new or gone in a
  comparison.
* `incomplete` — an identity is left undecided **because of** runs that were not results: had
  they come out favourably, it would have been decided (4.2, 4.3).
* `sandbox_failed` — runs failed for causes the server cannot bring about more often than the
  retries allow (4.6): the environment failed the series, not the server.
* the gravest state of the runs, when not one considered run was a result.

There is no proportion rule ("more than half"): what runs without a result cost is worked out
in the bounds, identity by identity.

### 3.2 Rates and bounds per identity

For every identity seen in at least one considered run, and for every `(statement, signal)` the
scenario asked for (`Verdict.statements`, zeros included):

* `hits` = considered complete runs with a sighting; `observed` = considered complete runs that
  could have sighted it (3.3); `unknown` = considered runs that were not results, which could
  have shown it or not. `n = observed + unknown`.
* **Worst-case bounds.** The upper bound is taken as if every unknown run had been a hit, the
  lower as if every one had been a miss: `upper = U(hits + unknown, n)`,
  `lower = L(hits, n)`, with `U`, `L` the Wilson bounds, 95 % (z = 1.96):
  `centre = (p̂ + z²/2n) / (1 + z²/n)`, `half = z · √(p̂(1−p̂)/n + z²/4n²) / (1 + z²/n)`.
  The rate on complete runs, `hits / observed`, is reported beside them.
* **Zero hits and nothing unknown:** upper bound by the rule of three, `3/n` (95 %) —
  `bound: rule_of_three`. Symmetrically, `hits = n` gives the lower bound `1 − 3/n`. The rule
  of three is conservative for small `n` (exact one-sided bound `1 − 0.05^(1/n)`: 0.259 against
  0.300 at `n = 10`); it is the one that is easy to check by hand.
* **"Absent" never appears without its bound and its β** — in the store, the JSON and the
  report, as the statement the test made: "absent: below 10 % at β = 0.01 (evidence, 44 runs
  without a hit)" or "absent: below 10 % at β = 0.01 (sequential test, 48 runs)". The Wilson
  interval of 3.2 is reported beside it, as for every rate, and is not what "absent" rests on.

### 3.3 Caps and rates

A run that cut findings of `(statement, signal)` at the per-message cap did not observe the
identities under that pair whether they fired or not. For those identities it counts in neither
`hits` nor `observed`. The page limit (`page_limit_reached`) is the same for every identity of
the listing it cut.

## 4. When to stop: two procedures, by what a hit is

Not built as a stopping rule: nothing repeats a run. Built: each signal's kind (4.1, in
`signals.KINDS`), the split of `sandbox_failed` by phase (4.6), and the arithmetic of 4.2, 4.3
and 4.5 in `rates.py` (the exact zero-hit bound, the sequential test and its operating
characteristic).

### 4.1 Evidence and heuristics

Whether one hit settles anything depends on what a hit is, and that decides the procedure an
identity is tested by:

* **Evidence.** The hit is the recorded fact the identity stands for, and it cannot occur
  without it as long as the sandbox and the recording are correct. A server whose behaviour does
  not have it never produces it — not now and then, not by accident. The rate under "absent" is
  therefore exactly 0 (p₀ = 0), and a single hit is proof.
* **Heuristic.** The hit is a shape that harmless content has too. A server can produce it now
  and then without what the shape is looked for being there — a description that varies, a
  document a tool returns. A hit is a measurement, and "absent" has to allow a background rate
  (p₀ > 0).

What each source of findings is, read from the code (signals.py, inspection.py, sandbox/egress.py):

| What | Kind | Why |
|---|---|---|
| `invisible_characters` | heuristic | `_has_invisible` counts every soft hyphen, zero-width space, word joiner and bidi control; i18n libraries wrap placeholders in bidi isolates, documents carry soft hyphens. Its own narrowings (a leading BOM, joiners only between ASCII) are innocent uses already met |
| `chat_template_marker` | heuristic | fixed tokens (`_CHAT_TEMPLATE`), but a server that works with prompts or documents a model's format writes `[INST]` or `<\|im_start\|>` honestly |
| `instruction_override` | heuristic | three word lists within 40 and 30 characters (`_OVERRIDE`); "ignore any rules set previously" in a configuration tool matches (the regex takes the bare verb, so "ignores" does not) |
| `concealment_directive` | heuristic | `_CONCEALMENT`: "never show the API key to anyone" is a safety note and matches |
| `output_directive` | heuristic | `_OUTPUT_DIRECTIVE`: "append a signature to your reply" in a mail tool matches |
| `model_addressed` | heuristic | `_MODEL_ADDRESSED`: "assistant id must be a UUID" matches the second branch |
| `hidden_comment` | heuristic | any complete HTML comment with a 12-character body, or a markdown comment idiom (`_has_hidden_comment`); documentation generators leave them |
| `role_line` | heuristic | `_ROLE_LINE`: "user: the account to query" at the start of a line |
| `whitespace_padding` | heuristic | two blank lines or 30 spaces (`_PADDING`): formatting |
| `imperative`, `second_person`, `embedded_url`, `base64_block`, `hidden_html` | heuristic | declared-only precisely because honest servers are full of them (module docstring, `Reach.DECLARED`) |
| `tool_name_duplicate` | evidence | an identical name twice in one listing (`names.written[raw] >= 2`, `Via.RAW`): the listing as the server sent it, compared character for character. Split from `tool_name_collision` (8) |
| `tool_name_lookalike` | heuristic | names a person reads alike but written differently (`name_key`: case, separators, Cyrillic and Greek lookalikes, `Via.NORMALIZED`) — `get_user` and `getUser` can both exist honestly. Split from `tool_name_collision` (8) |
| `lone_surrogate` (inspector) | evidence | set by the inspector alone, never by the walk or a statement (the scenario is refused): the announced server name held a lone surrogate, replaced by U+FFFD. Surface `server_info`, path `result.serverInfo.name`; recorded, not a finding |
| egress attempt, name asked (sandbox) | evidence | counted by the kernel before the redirect, from the target's own packet (`egress.py`, the record), and held against the sink's account by membership; the positive probe proves the instrument on every run. Not findings yet |
| `server_name_mismatch` (inspector) | evidence | an exact comparison of the announced name with the entry's. Recorded, not a finding |

With the split, `tool_name_duplicate` is the first filed finding that is evidence; every other
filed finding is a heuristic until egress becomes a finding. The evidence procedure
is designed now because those are the findings repetition must never miss; it is not built yet
(6).

### 4.2 Evidence: p₀ = 0 and the exact zero-hit bound

* **Present** at the first considered complete run with a hit. There is no false alarm to hold
  down, so no α.
* **Absent** when the considered complete runs without a hit reach the first `n` with
  `(1 − p₁)ⁿ ≤ β`: with p₁ = 0.10 and β = 0.01, **n = 44** (0.9⁴⁴ = 0.0097). Exact, and valid
  however often the runs are looked at: no hit can come before the decision, so there is one
  look that matters.

What it lets through, exactly — the probability that an identity present at rate p is declared
absent, and the runs it takes:

| true rate p | 0 | 0.01 | 0.02 | 0.03 | 0.05 | 0.10 | 0.20 |
|---|---|---|---|---|---|---|---|
| declared absent | 1 | 0.643 | 0.411 | 0.262 | 0.105 | **0.0097** | < 0.001 |
| expected runs | 44 | 35.7 | 29.4 | 24.6 | 17.9 | 9.9 | 5.0 |

Against the sequential test of 4.3 at the same p₁ and β it takes four runs fewer (44 against 48)
and misses less below p₁ (0.105 against 0.179 at p = 0.05): with no background rate to allow
for, the bound needs no slack for one. It never ends undecided — by run 44 it has decided, or a
hit has.

**Runs without a result** (4.6) — *decided 2026-10-06: blocked, as below.* One the server can
have caused is the worst case for "absent":
had it been observed, it might have been the hit — and with p₀ = 0 one hit decides. Such an
identity can no longer be declared absent in this series; without a hit, its class is
`incomplete`. A run the server cannot have caused is not counted at all and is run again.

*Considered and not proposed:* counting such a run as one hit and deciding "absent" once
`P(Bin(n, p₁) ≤ u) ≤ β` for `u` of them. With one look per `u` that is not exact — a server that
hides every hit behind a failed run reaches "absent" with probability 0.023 at p = 0.10 in 100
runs, not 0.01 (computed exactly). A boundary calibrated over all looks holds 0.0097 with
**48 runs without such a run and 70 with one**; a second is not absorbed within 100. It would
cost every evidence-only key four runs to absorb one failure, and it answers "rate below p₁"
where one hit is proof; the rule above answers what p₀ = 0 says.

### 4.3 Heuristics: the sequential test

Wald's sequential probability ratio test, as before: H_absent p₀ = 0.01 against H_present
p₁ = 0.10, a missed finding (deciding "absent" at p ≥ p₁) held at β = 0.01, a false alarm at
α = 0.10. The log-likelihood ratio gains `ln(0.99/0.90)` per run without a hit and `ln(0.01/0.10)`
per hit; "absent" at `A = ln((1−α)/β)`, "present" at `B = ln(α/(1−β))`. The fewest runs without a
hit for "absent": `⌈A / ln(0.99/0.90)⌉` = **48**.

| p_present, β | p = 0.05 | p = 0.10 | p = 0.20 | undecided at worst | expected runs at worst |
|---|---|---|---|---|---|
| 0.20, 0.05 | 0.645 | 0.297 | 0.048 | < 0.001 | 15.9 |
| 0.20, 0.01 | 0.569 | 0.166 | 0.009 | 0.005 | 26.1 |
| 0.10, 0.05 | 0.332 | 0.049 | 0.001 | 0.062 | 42.5 |
| **0.10, 0.01** | **0.179** | **0.010** | < 0.001 | 0.175 | 60.7 |

(Probability of "absent" for a finding present at rate p, computed exactly for the test truncated
at 100 runs, no runs without a result; "at worst" is the true rate at which the test takes
longest, about 0.03.) A run without a result the server can have caused enters twice, once in
each direction, always on the side that makes a decision harder: as a hit for "absent", as a miss
for "present" — two log-likelihood paths per test, a decision only when the path worst for it
crosses. Each such run costs `ln(0.10/0.01) / ln(0.99/0.90)` = 24.2 runs of "absent".

At the budget, an identity on which no worst-case path has decided is looked at once more with
the unknown runs taken favourably for each side: if that would have decided it, it is
`incomplete`; if not, `undecided`, reported with its interval.

### 4.4 A series with identities of both kinds

Every identity is tested by its own procedure, on the same considered runs in repetition order;
the stable test (4.5) runs for every identity once it is present, whatever its kind. The series
ends when every identity is decided, or can no longer be within the budget — an evidence
identity blocked by a run the server may have failed (4.2), a heuristic one whose worst-case path
cannot reach its boundary in the runs left (4.3). The slowest identity sets the length: 44 runs
for a key with evidence only, 48 as soon as one heuristic is among its identities. The series'
state is worked out as in 3.1, from all of them.

A class means the same whichever procedure gave it, and a comparison (5) treats it alike; the
procedure is kept beside it (`fleet_rates.procedure`) and printed with "absent", so a reader
knows whether "absent" rests on 44 runs of a fact or on 48 of a measurement.

### 4.5 The stable test stays at 0.05

H_stable p = 0.99 against p = 0.80, α = β = 0.05: 14 runs with a hit. It stays symmetric, and at
0.05, because the expensive error is not made here. A finding reported "gone" that is not gone
needs a side that wrongly says "absent", and "absent" is held at β = 0.01. A "stable" that should
have been "flaky" either relabels a real change — "gone" instead of "rate moved" — or lets a
move between two present rates pass as unchanged; either way the finding stays reported as
present on both sides. A wrong "stable" costs a word or a flag, a wrong "absent" a finding: the
second is held tight, the first need not be.

### 4.6 Runs without a result: what the server can cause, and what it cannot

A run's causes (`verdict.CAUSES`) say why it is not a result. Some of them a server can bring
about — and then it can bring them about exactly in the run in which the finding would have
shown. Those stay in the worst-case treatment (4.2, 4.3). The others say nothing about the
server: such a run is not counted, and the repetition is run again.

| Cause | The server can cause it | Why |
|---|---|---|
| `unreadable` | no | the recording is this tool's file, 0600 in a 0700 directory |
| `schema` | no | the schema version is written by the recorder, never taken from the traffic |
| `line` | **yes** | the recorder writes whole escaped lines; a torn last line comes from a kill — the watchdog's `os._exit`, the fleet's SIGKILL after `--job-timeout` — which a server can drive a run into |
| `no_run_started` | no | written before the server's process exists (`Proxy.run`) |
| `no_run_finished` | **yes** | a run killed for wedging or for its timeout has no closing event |
| `recording_stopped` | **yes** | writing failed; a server decides the volume (messages up to `--max-message-bytes`, as many as it likes) |
| `unwritten_events` | **yes** | the queue still full at the shutdown budget: rate and volume are the server's |
| `inspection_bounded` | **yes** | a message past the inspection bounds |
| `message_undecodable` | **yes** | the server's own bytes: a message that is not valid UTF-8, read with replacement characters |
| `client_message_undecodable` | no | the client's bytes: in driver mode the driver, which writes only valid UTF-8; in proxy mode what the client sent |
| `counts_missing` | no | both closing paths always write the counts; only a foreign or damaged recording lacks them |
| `findings_missing` | **yes** | finding events are offered, not put: a flood can make the queue drop them |
| `findings_uncounted` | no | count and event come from the same inspection |
| `cap_unaccounted` | no | `findings_capped` is always written with its cut |
| `step_unanswered` | **yes** | the server does not answer in time, or only with what the driver could not read |
| `step_not_sent` | **yes** | no handshake, no answer, connection closed, an answer the driver could not read (longer than the message limit, or nested too deeply) |
| `no_script_finished` | **yes** | a server that dies or hangs mid-script |
| `unknown_isolation` | no | written by this tool in `run_started` |
| `no_egress_summary` | **yes** | written after the target; missing only where the run was cut short, which a server can cause (above) |
| `udp_loss_unknown` | no | the summary always carries the numbers, and `lost = max(kernel − sink, 0)` cannot exceed them (`egress._udp_membership`) |
| `udp_loss` | **yes** | a burst faster than the sink reads |
| `server_failed` | **yes** | the server's own process: crashing, never answering the handshake |
| `server_silent` | **yes** | the same |
| `http_unreachable` | **yes** | the server's endpoint: not listening, or closing before its answer |
| `http_status` | **yes** | the server's answer: a status that carries no answer |
| `session_lost` | **yes** | the server's session: ended or refused before the script finished |
| `http_sse_only` | **yes** | the server's choice of transport: only the deprecated HTTP+SSE |
| `rate_limited` | **yes** | the endpoint's answer: 429, or 503 with `Retry-After`, again after the one wait this tool makes, or asking for longer than the step has left |
| `http_counts_missing` | no | written by both closing paths of the HTTP proxy; only a foreign or damaged recording lacks them |
| `server_output_unknown` | no | written by both closing paths |
| `empty_session` | no | in driver mode the driver always speaks; in proxy mode the silence is the client's |
| `sandbox_failed` | no | the sandbox failed before the target existed (`phase` `before_target`): `runner.py`, the order and the gate |
| `sandbox_failed_after_target` | **yes** | collecting the account after the target ran can fail under what the target sent (the sink's queue, its replies). A failure whose phase the recording does not name is counted here too: what is not shown to lie before the target may be the server's |
| `egress_inconsistent` | **yes** | membership can be broken from the target's side — connections opened faster than the sink accepts them are counted by the kernel and never named by the sink (plausible, not measured) |
| `images_mismatch` | no | the images are pinned by id before the run; the target cannot change what ran |
| `unfiled_finding` | no | key and context are the inspector's, not the server's |
| `interrupted` | no | the operator's: a signal to the run (`run_stopped`) or a fleet's interruption |
| `call_error` | **yes** | the server's answer to a tool call of the script: a JSON-RPC error |
| `tool_error` | **yes** | the same, a result that says `isError` |
| `call_result_unreadable` | **yes** | the server decides how large and how deep its answer is |
| `call_record_unreadable` | no | `call_failed` is written by this tool from a closed set; only a foreign or damaged recording breaks it |

The rules:

* A run with **at least one** cause the server can bring about stays in the worst case. Only a
  run all of whose causes are "no" is retried.
* A retried run is not considered: not in `n`, not unknown. Its repetition index is run again,
  outside the budget, and the outcomes stay in repetition order (2.3).
* **At most R = 5 retries per key — provisional.** R is fixed only once q, the share of runs
  that fail for causes the server cannot bring about, has been measured; the
  argument below says how R follows from q. The sixth such run makes the series
  `sandbox_failed`: the environment failed it, and saying anything about the server would be
  saying it about the environment. With a share q of runs failing for such causes, five retries are exceeded in a
  series of about 50 runs with probability 1.4·10⁻⁵ at q = 0.01, 4 % at q = 0.05 and 38 % at
  q = 0.10 — a healthy environment practically never reaches it, a broken one does. q itself
  has not been measured yet; the load runs of `--parallel 16` are where to take it from.

### 4.7 The budget

**100 scheduled runs per key, retries not counted**, now argued from both procedures:

* Evidence: 44 runs decide "absent" for a deterministic absent identity, or a hit decides
  earlier (then 14 more settle "stable"). A run the server may have failed before that leaves the
  identity `incomplete` — later runs cannot change it, so the series does not wait for them. The
  evidence procedure never needs more than 44 runs and never ends undecided; it does not set the
  budget.
* Heuristics: 48 runs; each run the server may have failed costs 24.2 more. Two fit
  (48 + 2 · 24.2 = 96.4); a third makes "absent" unreachable, and the series is `incomplete`.
  A heuristic with a true rate around 0.03 — the slowest case — is `undecided` at 100 in 17.5 %
  of series (6 % at 150), reported with its interval.
* Retries (4.6) come on top, at most five.

So every key with a heuristic identity — today every key — is bounded by the heuristics, as
before; the evidence path fits inside with room to spare. 100 stays.

### 4.8 With the parallel limit

`--parallel` stays the bound on runs in flight, for all keys together. Within it:

* Keys are served round-robin, so one slow key cannot hold the pool.
* At most `ceil(parallel / open keys)` repetitions of one key are in flight, and never more than
  the budget leaves. This bounds the overshoot past `n*` at that number minus one.
* The tests read outcomes in repetition order (2.3); a key whose next index is still running
  waits even if later ones are done.

At `--parallel 1` the overshoot is zero and the fleet runs exactly `n*` repetitions per decided
key; at 16 a deterministic two-key corpus runs up to 55 per key and considers 48.

The stop is the verdict's decision: the fleet asks `verdict.rates.decide(outcomes)` after each
result and schedules another repetition only while the answer is "open".

## 5. Comparing two fleets by rates

Not built: `fleet.compare` compares one run per key. Fisher's exact test, Holm and
Benjamini–Hochberg exist as functions in `rates.py`.

`fleet.compare` (`fleet.py:536`) today compares the one run per key through `store.diff`. With
series, it compares identity by identity (matched on the key without its version fields, as
`store.diff` does), and keeps the axes and their attribution exactly as they are.
`same_result` is the comparison digest (2.3).

A change is **real** when the evidence on both sides says so:

1. **new / gone:** `absent → stable` is new, `stable → absent` is gone. Both sides decided by
   their tests; "gone" therefore carries the miss rate of the "absent" decision (β = 0.01) and the
   bound and procedure of the side that calls it absent (3.2, 4.4).
2. **rate moved:** any other pair of classes, or a flaky or undecided identity on either side,
   is compared by **Fisher's exact test** (two-sided) on `hits / observed` before and after,
   corrected for multiple tests **over the whole comparison** — every identity of every entry
   compared by rates is one family (5.1). Reported with both rates, both worst-case intervals and
   the p-value; a flag, like scenario drift, not a new/gone entry.
3. **undecided on both sides, and not moved:** in the diff only as a count per entry ("12
   identities undecided in both fleets, none moved"); the verbose report (`fleet diff
   --verbose`) lists every one with both rates and intervals. They are where the data does not
   decide, twice, and nothing changed — listing them in the diff would bury the changes.
4. **not comparable:** either side's identity `incomplete`, or either series not a result. The
   comparison is then incomplete for that key, exactly as for an incomplete run today (`diff`
   exits 3).
5. **single run on a side:** compared as today, run against run, and marked `basis: "single
   run"` (0).
6. Everything the comparison already says stays: the cap hint for an identity gone in a series
   that cut its `(statement, signal)`, the environment axis, scenario drift.

Fisher's exact test needs only log-factorials (`math.lgamma`); the standard library suffices,
in keeping with the project's no-dependency rule.

### 5.1 One correction over the whole comparison: Benjamini–Hochberg, not Holm

Which identities are tested at all: only those compared by rates (point 2). A deterministic
corpus has none; a real one has those whose servers vary. An example of realistic size: 40
entries, two scenarios, 80 keys of some 40 identities each — 3200 identities, of which perhaps
3 % flaky or undecided on one side: **m ≈ 100 tests**, each on about 48 runs a side (the length
of a heuristic series, 4.7).

What one test can see at 48 against 48 (Fisher, two-sided):

| before → after | 14/48 → 2/48 | 24/48 → 10/48 | 19/48 → 7/48 | 10/48 → 2/48 | 14/48 → 5/48 | 29/48 → 19/48 |
|---|---|---|---|---|---|---|
| p | 0.0018 | 0.0052 | 0.011 | 0.027 | 0.039 | 0.066 |

Holm holds the chance of **any** false flag in the comparison at 0.05 (family-wise); its first
step needs p ≤ 0.05/100 = 0.0005 — none of the moves above passes it on its own. Benjamini–
Hochberg holds the expected **share** of false flags among the flags at q = 0.05; the k-th
smallest p needs only ≤ 0.05·k/100. Simulated (Fisher on binomial draws, 48 runs a side, the
null identities spread over rates from 0.05 to 0.7):

| comparison | Holm: real moves flagged | false flags | BH: real moves flagged | false flags |
|---|---|---|---|---|
| m = 20, 5 moved | 1.63 of 5 | 0.014 | 2.19 of 5 | 0.052 |
| m = 100, 5 moved | 0.95 of 5 | 0.019 | 1.21 of 5 | 0.046 |
| m = 400, 5 moved | 0.52 of 5 | 0.008 | 0.61 of 5 | 0.022 |
| m = 100, 30 moved (a server update) | 5.6 of 30 | 0.019 | 13.1 of 30 | 0.20 (1.5 % of the flags) |

The five moves were 0.30→0.05, 0.50→0.20, 0.40→0.15, 0.30→0.10 and 0.60→0.40; the last row
repeats them six times.

**Decided (2026-10-06): Benjamini–Hochberg at q = 0.05 over the whole comparison.**

* A rate move is a flag a person reads. What that person meets is the share of flags that are
  wrong — the false discovery rate — not the chance that some flag somewhere in a corpus is.
* Holm loses power as the corpus grows (0.95 → 0.52 of 5 from 100 to 400 tests): adding servers
  would hide moves of the servers already there. Under BH a move's chance depends far less on
  how many unrelated identities share the comparison.
* When a server changes, many of its identities move at once; that is where BH gains most (13.1
  against 5.6 of 30), with one wrong flag in about seventy.
* The expensive error is not made here. "Gone" comes from the classes (point 1), held at
  β = 0.01 by the "absent" test; a missed rate move leaves both rates in the report.
* Identities of one key share their runs, so the tests are not independent. The dependence is
  positive (a run that fails or varies moves its identities together), under which BH holds
  (PRDS). Where that cannot be argued, Benjamini–Yekutieli (q / H_m, with H_100 ≈ 5.19) is the
  fallback that holds under any dependence.

Per entry, instead of over the whole comparison, was considered and is not proposed: each entry
would get its own 5 % — forty entries, forty families, the same accumulation the correction is
there to prevent.

## 6. Where the judgement lives

Not built: `verdict.py` is still one module, and the arithmetic is a top-level `rates.py`.

`verdict.py` becomes a package with the same import path for what exists:

* `mcp_kymograph/verdict/__init__.py` — today's `verdict.py`, unchanged: the state of one run.
* `mcp_kymograph/verdict/rates.py` — the series: the Wilson interval and the rule of three, the
  evidence bound and the sequential tests and `decide`, which causes the server can bring about
  and the retry limit, the series' state, and the comparison of two series (classes, Fisher,
  Benjamini–Hochberg). Pure functions over outcomes the store hands it; no I/O. Which procedure a
  signal is tested by is a property of the signal (`signals.Definition`), read here, never
  decided by the fleet.

The fleet calls `decide` and obeys it; the store files what `rates` returned and serves the
outcomes back for a comparison. Neither contains a threshold, a boundary or an interval. Every
constant (α and β of each test, the hypotheses, the budget, the retry limit R, q of the
correction, z) is a named constant in `rates.py`
with its reason beside it, like `UDP_LOSS_LIMIT` in `verdict.py` today, and every rule gets a
mutation killed by exactly one test.

## 7. Real-world entries

Not built: this version provides no `runsc`, so a real-world entry with a command runs nowhere
(an endpoint entry runs under `remote`, which runs nothing here).

Deferred until gVisor (`runsc`) is available: a real-world entry is refused under runc today,
repeated or not. Whether `runsc` supports the packet mark the UDP account depends on
(`SO_RCVMARK`, `meta mark`) is open, and the sandbox under runsc may need another
way to attribute datagrams.

The principle is fixed now: **no lower budget and no weaker error rates for real-world.** A
real-world server is where a missed finding costs most. If repetition costs too much traffic or
time there, the fleet runs fewer repetitions *at once* (`--parallel`), not fewer in all — the
statistical strength stays what it is for every provenance.

## 8. Open questions

Answered in the second round and worked in above: the variant (p₁ = 0.10, β = 0.01, budget 100),
the stable test at 0.05 (4.5), retries for what the server cannot cause (4.6), undecided
identities in the diff (5, point 3), one correction over the whole comparison (5.1).

Decided in the third round:

* **Split `tool_name_collision`** into an identical-name signal (evidence) and a lookalike
  signal (heuristic) — in the round that builds the evidence path. Done:
  `tool_name_duplicate` and `tool_name_lookalike` (4.1); the old ID is gone, and a scenario
  that names it is refused as an unknown signal.
* **Split the `sandbox_failed` cause by phase** (before the target: the server cannot cause it;
  after: it can) — in the same round. Done in rules version 6: `sandbox_failed` and
  `sandbox_failed_after_target` (4.6).
* **Evidence and runs the server may have failed:** "absent" is blocked (4.2). The calibrated
  48/70 bound is not built.
* **Benjamini–Hochberg at q = 0.05** over the whole comparison (5.1).

Still open:

1. **R** (4.6): 5 for now; the final value once q is measured. Still open: q has not been
   measured, and nothing retries a run.
