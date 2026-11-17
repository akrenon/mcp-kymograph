# Contract: the web interface's views

The shapes the data side (`views.py`) produces and the page (`static/`) renders, and the states in
which a view shows nothing or not everything. Both sides build against this file; a state not
named here is a bug on whichever side meets it first. The audit behind it is
`docs/design/web-interface.md` (sections 5, 6 and the decisions in 9); where this file and the
code disagree, the code is right and this file is corrected.

## 0. Who writes what

| Part | Files | Tests |
|---|---|---|
| data | `web/views.py` (and private helpers in `web/_*.py` if it grows) | `tests/test_web_views.py` |
| server | `web/server.py`, the `web` subcommand in `cli.py` | `tests/test_web_server.py`, `tests/test_cli_web.py` |
| page | `web/static/index.html`, `web/static/app.css`, `web/static/app.js`, `web/static/spike.svg` | — (checked in a browser, see 9) |
| shared | this file, `web/__init__.py`, `docs/web.md`, `README.md` | integration |

`web/` is `src/mcp_kymograph/web/`. Nobody edits a file of another part; a change another part
needs is asked for, not made.

## 1. Shape

```
browser ──GET──▶ server.py ──calls──▶ views.py ──reads──▶ recordings, store (read-only),
   ▲              (routing,             (pure functions:          manifests, scenarios,
   │               headers,              Sources + parameters      signals.py
   └── JSON ───────static files)         → envelope dict)
```

* `views.py` holds **pure functions** from `Sources` and parameters to an **envelope** (a dict of
  JSON values). No HTML, no HTTP, no globals, no caches. Each call reads what it needs afresh.
* `server.py` maps routes to view functions, serialises the envelope with
  `json.dumps(…, ensure_ascii=True)`, and serves the static files. It decides nothing about
  content.
* The page is one `index.html` with `<template>` elements, one `app.css`, one `app.js`; it
  fetches the JSON and builds the DOM. Hash routes (`#/run?ref=…`), so the server serves one page.

Nothing writes. The store is opened with `Store.open_read_only` per call and closed after it;
recordings, manifests and scenarios are opened for reading only. No view runs a server, a fleet,
an ingest or a sandbox.

## 2. Sources

```python
@dataclass(frozen=True)
class Sources:  # in views.py
    store: Path | None = None  # --store FILE
    runs: Path | None = None  # --runs DIR
    manifests: tuple[Path, ...] = ()  # --manifest FILE, repeatable
    scenarios: tuple[Path, ...] = ()  # --scenario FILE, repeatable
    bundles: tuple[Path, ...] = ()  # --bundle DIR, repeatable
    attestations: tuple[Path, ...] = ()  # --attestation FILE, repeatable
```

A bundle is read only through `evidence.verify` and `evidence.read_index`, and a file of it only
by a path its index lists, opened one directory at a time with no link followed. An attestation
is opened without following a link, a regular file of at most 1 MiB, and read back through
`report.parse_attestation`.

`--runs` is searched for recordings (`events.jsonl`) and fleets (`<fleet id>/fleet.json`), at most
five directories deep, **following no symbolic link**. Nothing else on disk is looked at.

A store row's `recording` is the path as given at ingest, often relative to wherever ingest ran
(`runs/<stamp>-<id>/events.jsonl` with `--runs runs`). It is resolved **under `--runs` only**: the
recording the search found whose path relative to `--runs` is the longest suffix of the filed
path's components, at least `<run directory>/events.jsonl` (a filed run directory counts as its
`events.jsonl`). None: `recording_not_found`. Found, and the SHA-256 of its bytes is not
`runs.run`: `recording_changed`. Found and equal: that run's recording, with its `ref`.

## 3. The envelope

Every view function returns:

```json
{"view": "run", "notices": [ … ], "data": { … } }
```

* `view` — the view's name (section 6).
* `notices` — a list of notices (section 4), **gravest first**, in the order of section 4. The page
  renders them in that order, before anything of `data`.
* `data` — the view's content, or `null` when the view is refused whole (`not_given`,
  `store_refused`, a whole-file `refused`).

A parameter that names nothing (an unknown run reference, fleet, index, finding, a path a
bundle's index does not list) or is malformed makes the view raise `views.ViewError(status,
words)` with status 404 or 400; a file asked for as a download that is not served as it stands
(a bundle not intact or whose index cannot be read, a file whose bytes are not the listed ones,
an attestation that does not read back) raises it with 409. The server answers with `{"view":
"error", "notices": [{"kind": "not_found" | "bad_request" | "conflict", "text": words}],
"data": null}` and that status. The server's own refusals use the same envelope with the kinds
`forbidden` (403), `method_not_allowed` (405), `misdirected_request` (421) and `internal_error`
(500, a generic text; what went wrong is on the server's stderr only). These are not notices of a
view and not in `NOTICE_KINDS`; the page shows an error envelope by its `text`.

## 4. Notices — when a view shows nothing or not everything

A notice is `{"kind": K, "text": "…", "where": W, …fields}`. `text` is one or two English
sentences for the reader, written by `views.py` (the page shows it as given). `where` names the
part of the view it is about (section 6 lists them per view); `"view"` means all of it. The kinds
are a closed set, `views.NOTICE_KINDS`, in this order of gravity:

| # | `kind` | When | Fields | The page shows |
|---|---|---|---|---|
| 1 | `not_given` | the source the view reads was not given on the command line | `option` (`--store`, `--runs`, `--manifest`, `--scenario`, `--bundle`, `--attestation`) | the option to give; nothing else |
| 2 | `store_refused` | `Store.open_read_only` refused: another schema (whole, never in part), not a store, missing, unreadable | `store`, `words` (the refusal as raised) | the words; nothing of the store |
| 3 | `recording_changed` | a store row's recording found under `--runs`, but its SHA-256 is not `runs.run` | `recording` (as filed), `found` (path under `--runs`), `filed`, `found_digest` (`null` when unreadable), `unreadable` (the words when the file could not be read, else `null`) | graver than not found, styled apart; the file's content is **never** shown as that run's |
| 4 | `recording_not_found` | a store row's recording is not under `--runs` | `recording` (as filed), `looked_in` | that it was looked for and where |
| 5 | `bundle_not_intact` | `evidence.verify` says a bundle is not intact | `directory`, `summary` (`Verified.summary()`), `files` (each listed or unlisted file not `intact`, as `FileState.to_dict()`), `problems` | graver than not found, styled apart; no file of the bundle is offered for download |
| 6 | `refused` | a manifest or scenario refused by the project's own loader; a bundle whose index cannot be read; an attestation that does not read back; a fleet's `engagement` block that `fleet.recorded_engagement` refuses; store engagement rows that `Store.engagement()` refuses | `path`, `words` (the loader's words, place and reason), `source` (the file's text, or `null`) | the words, and for manifests, scenarios and attestations the source text beside them |
| 7 | `not_a_result` | a run's state is not `complete`: `incomplete`, `server_failed`, `sandbox_failed`, and `call_failed` ("not a result about the content", README) | `state`, `exit_code`, `rules`, `causes`: `[{"cause", "words", "state"}]`, one per shortfall, in the verdict's order. On a store's findings or candidates: `state`, `exit_code`, `rules` `null`, `runs: [{"run", "state", "causes"}]`, `count`, `total` — the runs of that provenance that are not results | **first**: state, exit code and every cause key with its words; findings only after it |
| 8 | `comparison_not_complete` | a `store diff` or `fleet diff` with a run or entry that is not a result (`complete: false`) | `before_state`, `after_state` | that the comparison is not complete and why, before the comparison |
| 9 | `fleet_state_not_in_store` | a fleet from the store without its `fleet.json` under `--runs`, or with one that is not its own (another fleet's, not JSON, unreadable, or a `digest` that is not the store's) | `fleet`, `looked_for`, `found` (a file there but not taken, else `null`) | "not recorded in the store" where the state would be; never a state derived from results |
| 10 | `capped` | a listing was cut: `findings_capped`, `page_limit_reached`, `script_finished.inventory` `capped`, `run_finished.inspection_bounded`, the store's first 20 `problems`, a listing this interface cuts, a directory under `--runs` that cannot be listed | `what`, `source` (event or field), `cap`, `shown`, `total` (`null` when not recorded), `unreadable` (directories not listed) | "N of M shown, capped" — never a count that reads as complete |
| 11 | `not_in_this_recording` | an event this version records, absent from this run | `event` | "not in this recording" in place of the part |
| 12 | `not_recorded_by_this_version` | an element the view would show that this version does not record at all (audit 5.2) | `what` | "not recorded by this version" in place of the part |
| 13 | `candidates` | real-world findings or counts | `count` | "candidates for disclosure, not results to publish", always with them |

Rules for both sides:

* **An empty list is never silent.** If a list in `data` can be empty, either it is empty because
  nothing was recorded in a run that is a result, or a notice with the list's `where` says why.
  The page renders an empty list as "none recorded"; with a `not_a_result` notice on the envelope
  as "none recorded — the run is not a result", **never** as "no findings", "0 findings", "clean"
  or a green chip.
* **A run's state comes from `verdict`**, a comparison from `Store.diff` / `fleet.compare`, a fleet's
  state from its `fleet.json`. Nothing is derived around them.
* **Causes keep their keys.** A cause is shown as its key (`interrupted`) with its words, never words
  alone.
* **Real-world findings stay apart**: only in `store_candidates`, under `candidates` of `triage`,
  in `triage_review` and `triage_history` of a real-world finding — each with a `candidates`
  notice — and as counts with one; never mixed into `store_findings`, the publishable findings of
  `triage` or a fleet's publishable findings.

## 5. Strings off the wire

Every string from a recording, a store row, a manifest, a scenario, an engagement file, a bundle
or an attestation is the server's, the customer's or the operator's choice and may be hostile
(prompt injection, markup, `<script>`, bidi overrides, zero-width characters, lookalike letters,
lines of any length, keys holding `.` or `[0]`). `views.py` passes them on **as recorded** — the
recording is already masked; nothing is re-read from anywhere else. The rules below hold for
**every view and mode, every tooltip, every `title` and `aria-*` value**:

* **Text only.** Every such string goes into the page with `textContent` / `createTextNode`
  (through `vis()`), never `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
  `eval`, `Function`, a string to `setTimeout`/`setInterval`, or an attribute string built by
  concatenation.
* **No element or attribute from the data.** Element names, attribute names, event names,
  classes and ids are the page's own constants. Attributes are set through `h()` alone, from its
  allowlist (`SAFE_ATTRS`, `aria-*`, `data-*`); `title` is not on it, so no value from the data
  is ever a tooltip. The one other place is `setState(el, name, value)`, which changes a state
  the page keeps on an element it made: `name` is one of `aria-pressed`, `aria-expanded`,
  `aria-current`, `aria-busy` and `data-ready`, `value` one of the page's constants (`true`,
  `false`, `page`) or, for `data-ready`, the page's render counter (digits only, set when a view
  has rendered, so a check can wait for a new value), anything else throws. No ARIA reflection (`el.ariaPressed`):
  browsers that still run (Firefox before 119) lack it. A value from the data in an `aria-*`, `data-*` or `value` attribute is
  written with the same `U+XXXX` tokens as text (below), never raw, and is never read back to
  build a selector.
* **Invisible characters made visible.** Characters of the Unicode categories `Cc`, `Cf`,
  `Cs`, `Co`, `Cn` — the set `cli.display` drops for the terminal — are shown as a marked
  `U+XXXX` token, so a zero-width or bidi character can be seen and cannot reorder the page.
* **Lookalikes stay text.** Cyrillic or Greek letters that look Latin are not normalised,
  transliterated or flagged by the page; what the page does is name where the value sits (the
  view, the field, the path), so the reader can compare.
* **Any length.** A value of any length wraps inside its own box (`overflow-wrap: anywhere`) or
  is shortened by the view's own rule with the shortening marked; it never overlaps, hides or
  pushes out of sight another value or a notice.
* **No URL from the data is followed.** A URL found in the data (an `endpoint`, an
  `embedded_url` finding) is never followed, fetched or linked: it is text.
* **Into a URL only through `href()`.** No store or recording value (path, run id, finding id,
  file name) goes into a URL except as a parameter encoded by `href()` (`URLSearchParams`), into
  a route of this page (`#/…`), or into `downloadLink()`'s `api/…/file` routes of this server.
* **Into a file-system path only through containment.** No such value reaches the file system
  except through `_found.resolve_filed` (a recording under `--runs`, by the suffix rule of 6.2)
  or a bundle's own index (`evidence.read_index`, only listed files, under its `--bundle`
  directory).
* **A path that names several places names them all.** A locator is keys joined with `.` and
  indices with `[n]`, unescaped, so a key holding a dot or a bracket can make one path name
  several places. Wherever a view reads a value by such a path, every reading is followed,
  whatever the order of the keys: exactly one value is shown as the value; more than one is
  `ambiguous`, with every value among `candidates` (at most 20, `candidates_capped` beyond) and
  none picked as the one a signal fired on (6.2 for review mode).

## 6. The views

All functions take `sources: Sources` first. `ref` is a run's path relative to `--runs` as `runs`
lists it (POSIX, the directory holding `events.jsonl`); it is looked up in what the search finds,
never joined onto a path. Shapes name the code that produces them; where a field is a `to_dict()`
of the code, it is passed unchanged.

| Route | Function | `view` | `data` | `where` keys, and the notices that can occur there |
|---|---|---|---|---|
| `/api/about` | `about` | `about` | `package` (`"mcp-kymograph"`, from the distribution metadata), `version`, `recording_schema`, `store_schema`, `rules`, `isolations` (`verdict.ISOLATIONS`), `observed_isolations` (`verdict.OBSERVED_ISOLATIONS`: the isolations under which this version observes egress; 7.1), `sources` (each path or `null`), `local` (`"read-only · 127.0.0.1 · token at start · no TLS"`) | `view`: `store_refused` |
| `/api/runs` | `runs` | `runs` | list, newest first: `ref`, `run_id`, `wall_clock_utc`, `mode`, `transport`, `isolation`, `egress_observed` (7.1), `server_name`, `scenario_name`, `fleet` (fleet id or `null`), `state`, `exit_code`, `causes` (keys) | `view`: `not_given`, `capped` (`what: "runs"`, cap 1000; unreadable directories) |
| `/api/run?ref=` | `run` | `run` | see 6.1 | see 6.1 |
| `/api/run/messages?ref=[&offset=][&limit=]` (0 and 100 when left out) | `messages` | `messages` | `total`, `offset`, `items`: `seq`, `direction`, `size_bytes`, `truncated`, `incomplete`, `method`, `id`, `kind`, `is_error`, `redaction_count`, `exchange`, `intervened`, `quarantined` (limit ≤ 500) | `view`: `not_a_result` (as on the run) |
| `/api/run/message?ref=&seq=` | `message` | `message` | the `message` event as recorded (masked payload with `redactions`, `parse`) plus the `intervention` and `observation`/`finding` events that name its `seq` | `view`: `capped` (`truncated`/`incomplete`) |
| `/api/store/runs` | `store_runs` | `store_runs` | list of `RunInfo.to_dict()` (with its `server_version_kind` and `egress_observed`, passed as the store gives them), each with `recording_status` (`found`, `not_found`, `changed`) and `ref` when found | `view`: `not_given`, `store_refused`, `capped` (unreadable directories); `run:<run>`: `recording_not_found`, `recording_changed`, `not_a_result`, `capped` (`problems`) |
| `/api/store/findings?provenance=reference\|poison` | `store_findings` | `store_findings` | `Store.findings_by_provenance(p)`: each key with `server_version_kind` beside it; `real-world` is a 400 here | `view`: `not_given`, `store_refused`; `not_a_result` when runs of that provenance are not results |
| `/api/store/candidates` | `store_candidates` | `store_candidates` | `Store.findings_by_provenance("real-world")` | `view`: `not_a_result` (runs that are not results), `candidates` (always), `not_given`, `store_refused` |
| `/api/store/diff?before=&after=` | `store_diff` | `store_diff` | `Store.diff(before, after).to_dict()`, with `server_version_kind` (`{before, after}`) beside the server axis | `view`: `not_given`, `store_refused`, `comparison_not_complete`, `candidates` (a real-world run); `new`/`gone`/`unchanged`: `capped` from `caveats` and `cap_hint` |
| `/api/fleets` | `fleets` | `fleets` | `Store.fleets()` rows without `results`, each with `fleet_json`: `{"state", "interrupted"}` or `null`, and `engagement` (7.1) | `view`: `not_given`, `store_refused`; `fleet:<id>`: `fleet_state_not_in_store`, `refused` (its engagement block), `candidates` |
| `/api/fleet?id=` | `fleet` | `fleet` | `Store.fleet(id)` plus, from `fleet.json` when found, `state`, `interrupted`, `findings`, `disclosure_candidates`, `engagement` (7.1) | `view`: `fleet_state_not_in_store`, `candidates`; `engagement`: `refused`; `result:<entry>/<scenario>`: `not_a_result` |
| `/api/fleets/compare[?before=&after=]` | `fleet_compare` | `fleet_compare` | `fleet.compare(store, before, after)`: both or neither, neither being the last two, as `fleet diff` | `view`: `comparison_not_complete`; `entry:<entry>/<scenario>`: `not_a_result` (causes from the store), `capped`, `candidates` |
| `/api/corpus` | `corpora` | `corpora` | list: `index`, `path`, `ok` | `view`: `not_given` |
| `/api/corpus?i=` | `corpus` | `corpus` | `corpus.load(path)` as a dict: entries with provenance, identity, `server_version_kind` (`store.version_kind` of the identity's kind), `endpoint` (the URL of an endpoint entry, else `null`), launch, scenarios, permitted isolations (`["remote"]` for an endpoint entry, `policy.PERMITTED` of the provenance for a command entry); `source` (the file's text) | `view`: `refused` (with `source`) |
| `/api/scenarios`, `/api/scenario?i=` | `scenarios`, `scenario` | `scenarios`, `scenario` | as corpus, from `scenario.load`: rules, statements, digest, `source` | `view`: `not_given`, `refused` |
| `/api/store/engagement` | `store_engagement` | `store_engagement` | `engagement`: `null` for a store without one, else from `Store.engagement()`: `engagement_id_declared`, `engagement_digest`, `delete_after_declared` (`null` when none is declared) and `versions`, oldest first, each `{"version" (from 1), "digest", "supersedes", "set_utc", "window_declared" (the file's `window`), "removed", "file_declared"}`; `bundles`: `Store.bundles()` | `view`: `not_given`, `store_refused`; `engagement`: `refused` |
| `/api/store/triage` | `triage` | `triage` | `store` (as given), `roles` (`store.TRIAGE_ROLES`), `statuses` (each role's `TRIAGE_STATUSES`, sorted), `findings`: `{"reference", "poison"}` each `Store.findings_with_triage(p)` (every key field, `server_version_kind`, `finding` id, `finding_key` (shown as text), `triage: {operator, customer}` current row or `null`); `candidates`: `findings_with_triage("real-world")`; `questions`: per provenance (all three), `[{"finding", "role", "row", "key"}]` for every current row with status `question` | `view`: `not_given`, `store_refused`; `findings:<p>`: `not_a_result` (runs of `p` that are not results); `candidates`: `not_a_result`, `candidates` (always) |
| `/api/store/triage/history?finding=` | `triage_history` | `triage_history` | `finding`, `provenance`, `key`, `identity`, `triage` (current rows), `history`: `Store.triage_history(identity)`, every row in the order written | `view`: `not_given`, `store_refused`, `candidates` (a real-world finding) |
| `/api/store/triage/review?finding=` | `triage_review` | `triage_review` | see 6.2 | see 6.2 |
| `/api/bundles` | `bundles` | `bundles` | list: `index`, `path`, `bundle` (`intact`, `not_intact`, `refused`), `words` (the summary or the refusal, `null` when intact), `index_digest`, `engagement` (`{engagement_id_declared, engagement_digest}` of the index), `created_utc` | `view`: `not_given` |
| `/api/bundle?i=` | `bundle` | `bundle` | `evidence.verify(dir).to_dict()` passed unchanged, plus `index`, `path`, `triage` (the index's counts or `null`), `roles` (`evidence.ROLES`), `files_by_role`: role → the index's entries (`IndexFile.to_dict()`) each with `state`, `note` and `download` (true only while the whole bundle is intact), `downloadable`, `customer_readme`: `{"present", "check" (`Verified.readme`), "problem" (verify's words about it, or `null`), "fields" (`handover.parse_customer_readme(...).to_dict()`, `null` when it does not read back)}` | `view`: `not_given`, `refused` (index unreadable; `data` `null`), `bundle_not_intact` |
| `/api/bundle/file?i=&path=` | `bundle_file` | — | a download (8): the bytes of the file the index lists at exactly `path`, only while `evidence.verify` (against the digest of the index just read) says the whole bundle is intact, read with no link followed and served only if their SHA-256 and size are the index's — the bytes served are the bytes checked | 404 a path the index does not list (`..`, the index, the README, anything else); 409 not intact, index unreadable, changed, unreadable |
| `/api/attestations` | `attestations` | `attestations` | list: `index`, `path`, `ok`, `engagement_id` (or `null`), `words` (the refusal, or `null`) | `view`: `not_given` |
| `/api/attestation?i=` | `attestation` | `attestation` | `index`, `path`, `sha256`, `size`, `engagement_id`, `items`: `[{"kind", "text"}]` (`recorded`, `derived`, or `heading`), `downloadable` | `view`: `not_given`, `refused` (with `source`; `data` `null`) |
| `/api/attestation/file?i=` | `attestation_file` | — | a download: the bytes read now, only if they read back through `report.parse_attestation` | 404 no such index; 409 does not read back |
| `/api/signals` | `signals` | `signals` | generated at call time from `signals.LIBRARY`, the surfaces of `inspection`, `paths.IDENTITY_FIELDS`, the normalisation order and the caps — never a copied list; each signal with its `kind` (`signals.Signal.kind`), `signal_kinds` (every signal, the inspector-only ones included), `kinds` (`signals.Kind`) and `kind_meaning` (`signals.Kind`'s docstring) | — |

### 6.1 The run

`data` of `run`:

* `ref`, `recording` (path relative to `--runs`).
* `engagement`: `null` for a run under no file (`run_started.authorization.engagement` absent or
  `null`), else `{"engagement_id_declared", "engagement_digest", "window_declared"}` as that
  block records them, with `pacing_enforced` from `run_started` and `window_exceeded` from
  `run_finished` beside them — each as recorded, declared, never checked here. A block that is
  not an object of exactly those three keys is refused whole, as a fleet's is: `engagement`
  `null` and a `refused` notice at `engagement` (`path` the recording, `source` `null`); the
  page shows it refused, never as "none". Not on a recording of another schema.
* `egress_observed`: whether `run_started.isolation` is in `verdict.OBSERVED_ISOLATIONS`;
  `false` for `host`, `remote`, an isolation this version does not know, and none recorded
  (7.1).
* `server_version`, `server_version_kind`: the version of `reproduction.corpus.identity`
  and `store.version_kind` of its `kind` (`content`, `revision`, `declared` for an
  `endpoint`; `unknown` for a kind that is not one of them); both `null` for a run without a
  manifest entry, which pins no version.
* `verdict`: `state`, `exit_code`, `rules` (`verdict.RULES_VERSION`), `causes`
  (`[{"cause", "words", "state"}]` from `Verdict.shortfalls`), `server_exit`, `truncations`,
  `announced_server`, `statements`.
* `tabs`: the tabs this run has, in this order. **Always**: `overview`, `verdict`, `messages`,
  `findings`. `inventory` on every driver run. Only when the recording has their events:
  `interventions` (`intervention`, `rule_quarantined`), `http` (`http_request`/`http_response`/
  `http_end`), `sandbox` (`sandbox_step`, `sandbox_failed`, `egress_*`), `stderr`
  (`server_stderr`).
* One key per tab. Events are passed whole, as recorded (with `seq`), and a key that names an
  event type holds the list of those events, empty when there are none:
  * `overview`: `run_started` (the event, or `null`), and lists `server_exited`,
    `server_name_mismatch`, `run_stopped`, `recording_stopped`, `limit_exceeded`,
    `server_failed`, `era_decided` and `script_finished` (7.4); `run_finished`
    holds of that event `reason`, `message_count`, `duration_ns`, `dropped_events`,
    `unwritten_events`, `server_redactions`, `http` (with its `tls`, 7.3), `window_exceeded` (or
    is `null`). `run_started` is passed whole, `pacing_enforced`, `trust_store_env`, `auth` and
    `authorization.engagement` with it.
  * `verdict`: as above.
  * `messages`: `total`, and the `seq`s of the messages that are `truncated` or `incomplete`; the
    messages themselves come page by page from `/api/run/messages`.
  * `findings`: lists `findings`, `observations`, `statements_evaluated`, `findings_capped`, and
    `findings_by_statement`, `observations_by_method` from `run_finished` (or `null`).
  * `inventory` (driver): `steps` in order — the driver's requests as `{"type": "message", "seq",
    "method", "id", "kind"}` and the `step_skipped`, `step_unanswered`, `step_reissued`,
    `step_called`, `call_failed` events — `script_finished` (the event, or `null`), and `listings`: `tools`,
    `resources`, `resourceTemplates`, `prompts`, each `{"items", "pages", "seqs"}` from the masked
    `result` of the answering messages, every item with the `finding` and `observation` events
    whose `path` points into it.
  * `interventions`: `interventions`, each `{"event", "message_seq", "invalidated_by"}` (the
    `intervention` event, the message it is linked to or `null`, the quarantine that invalidates
    it or `null`); `rule_quarantined`, each `{"event", "invalidates": [seq…]}`;
    `quarantined_rules` from `run_finished`.
  * `http`: `exchanges`, each `{"exchange", "request": […], "response": […], "end": […],
    "messages": [seq…]}` joined by `exchange`; `http` from `run_finished` (or `null`).
  * `sandbox`: `steps` (`sandbox_step` events in order), `sandbox_failed`, `egress_attempt`,
    `egress_dns`, `egress_summary` (the last one, or `null`).
  * `stderr`: `server_stderr`.

`where` keys of the run: `view`, `verdict`, and `tab:<name>`, `listing:<name>` for parts of a tab.

| State | Notice | Where |
|---|---|---|
| state not `complete` | `not_a_result` | `view` (first, always) |
| a recording of another schema | `not_a_result` with cause `schema`; `data` holds `ref`, `recording`, `verdict` and `tabs: ["verdict"]` only | `view` |
| `findings_capped`, `inspection_bounded` | `capped` | `tab:findings` |
| `page_limit_reached`, `script_finished.inventory: capped` | `capped` | `listing:<name>` |
| a truncated or incomplete message | `capped` | `tab:messages` |
| driver run without `script_finished`, a run without `run_finished`, a `runc` run with sandbox events but no `egress_summary` | `not_in_this_recording` | the tab |
| a `runc` run without any sandbox event, a `streamable-http` run without HTTP events (so no such tab) | `not_in_this_recording` (`event`: `egress_summary`, `http_request`) | `view` |
| a run whose `reproduction.corpus.provenance` is `real-world` | `candidates` | `view` |
| pages per listing (counted from messages, not recorded as a number); the characters a signal fired on; the sink's count per destination where it equals the kernel's; a gate or target-started sandbox step; the files-delivered check | `not_recorded_by_this_version` | the tab or listing |

A store row whose recording is `changed` is shown from the store only; the file under `--runs` is
not that run.

### 6.2 Review mode

`data` of `triage_review` — one finding, nothing of any other (docs/engagements.md, 5):

* `finding`, `provenance`, `key` (the seven key fields and `server_version_kind`), `identity`
  (the five a triage row is keyed by), `triage` (`{operator, customer}`: each role's current row
  or `null`), `history` (`Store.triage_history(identity)`, every row in the order written).
* `finding_class`: `{id, title, description}` of the finding's class (`AKR-NN`,
  `finding_classes.class_of("signal", …)`), or `null` for a signal this version does not know.
  Derived from the signal when the view is built, never filed; shown as text (ID and title) beside
  the signal. It is no severity.
* In the run view (the findings tab and the inventory items) and the message view, each finding
  event also carries `finding_class` (the same object, or `null`), derived from `key.signal` when
  the view is built and never filed; the recording and the key are unchanged. The chips and the
  tables show ID and title as text. Observations, `triage_history` and the triage tables
  carry none.
* `sightings`: one per **complete** run of the store that sighted the identity, in the store's
  order: `run`, `state`, `server_version` and `tool_version` of that run's key,
  `server_version_kind`, `isolation`, `egress_observed`, `recording` (as filed),
  `recording_status` (`found`, `not_found`, `changed`, resolved as for `store_runs`), `ref`, and
  `places`: each sighting's `path`, `message_seq`, `normalized`, `text_status` and `text`.
  `text` is the value the path names in that message's masked payload, as recorded, read from
  the recording under `--runs` only when its SHA-256 is the run's: `recorded` (with
  `truncated` and `incomplete` of the message), `not_located` (the path leads to nothing in the
  message as recorded), `ambiguous`, `not_read` (the recording not found or changed; `text`
  `null`). At most 200 places in all. The inspector spells a path by joining keys with `.` and
  indices with `[n]`, unescaped, so a key holding a dot or a bracket can make one path name
  several places (`{"tools[0].description": …, "tools": [{"description": …}]}`). Every reading
  of the path is followed, whatever the order of the keys: exactly one value is `recorded`;
  more than one is `ambiguous`, `text` `null` and every value in `candidates` (at most 20,
  `candidates_capped` when the search stopped there) — none is picked as what the signal fired
  on. `candidates` is `null` otherwise.
* `not_results`: each run that sighted it and is not a result — `run`, `state`, `exit_code`,
  `causes`, `places` (a count) — named, never among `sightings`.
* `line`: `text`, the complete line to copy —
  `kymograph store triage set --store=<the store's absolute path, shell-quoted> --finding
  <ID> --role customer --status '<STATUS>' --author '[NAME]'` — and
  `store` (that absolute path), `role` (`customer`), `statuses` (`TRIAGE_STATUSES["customer"]`,
  sorted), `placeholders`. The path is made absolute against the working directory
  (`Path.absolute()`, no link resolved), so the line pasted in another directory names this
  store; `=` joins it to its option, so a path beginning with `-` is still its value; it reads
  back through `shlex.split` and the CLI's parser as exactly that path, whatever it holds
  (quotes, `$(…)`, backticks, a line break, U+202E). The placeholders are in single quotes,
  where nothing is live for a shell (no `$`, backtick or backslash; an apostrophe is written
  `'\''`), and a line pasted unchanged is refused by the tool. The view writes nothing; the line
  is text.

| State | Notice | Where |
|---|---|---|
| a sighting's recording not under `--runs`, or no `--runs` (`looked_in` `null`) | `recording_not_found` | `sighting:<run>` |
| a file found there that is not the run's bytes, or cannot be read | `recording_changed` | `sighting:<run>` |
| runs that sighted it and are not results | `not_a_result` (`state` `null`, `runs`, `count`, `total`) | `not_results` |
| more places than shown | `capped` | `sightings` |
| a real-world finding | `candidates` | `view` |
| a directory under `--runs` that cannot be listed | `capped` with `unreadable` `null` and `unreadable_count`: counted, never named — the screen is shared, and a directory can name another engagement | `view` |

## 7. The page

* **Notices first, in envelope order**, each styled by `kind`; `not_a_result` with a state chip,
  exit code and every cause key with its words; `recording_changed` graver than
  `recording_not_found`; `candidates` on every real-world surface.
* The mockups' information hierarchy and colour meaning: state chips (`complete`, `call_failed`,
  `incomplete`, `server_failed`, `sandbox_failed`), provenance tags, "egress not observed" (7.1).
  Exact pixels do not matter. No part of a mockup that the audit marks not implemented.
* The rail (the page's `header`, a column on the left; a bar on top below 860 px) shows the
  package name and version from `/api/about` and says it is a local read-only viewer. Review
  mode shows what is left of it as a bar without the navigation.
* The findings tab of a run that recorded a `statement_evaluated` event draws statements against
  messages as a table of traces (`docs/design/web-redesign.md`). It says what is recorded and no
  more. No record of a statement on a message is "no record" (the statement did not apply, the
  message was not inspected, or the record was not written), never "nothing found" and never
  "did not apply" alone. A message the run lists as truncated or incomplete is marked in its
  column and named under the table. A finding without an observation of the built-in walk beside
  it is "no observation recorded", never "not observed", and the page says why that is not the
  same. An observation without a finding of the same message, path and signal is a row of its
  own kind, not drawn as a statement that fired and not called "seen by no statement": a finding
  can be cut by the cap of its message, or its record dropped. Every trace has its words beside
  it for a reader who does not see it, and the statement is the header of its row. A row that
  fired is marked by its events and findings, whatever a cap on the columns leaves visible.
  Every finding, observation and `statement_evaluated` event stays on the page: the tables the
  tab drew before are behind one toggle under the strip, and a run that evaluated no statement
  has the tables alone. At most 12 messages get a column, and 20 messages and 20 findings a
  place in the pane, each cap said where it cuts; "all messages" is said only where the list
  read holds as many as the run counts, and otherwise the columns are "those an event of this
  tab names". A row is selected by the address (`st`: a statement, `obs`: the `seq` of an
  observation without a finding); the value is compared with the events' own and never built
  into a selector. Without either the first statement that fired is selected. An address that
  names a row puts the focus on that row when the tab is already shown, the strip keeps its
  sideways scroll and the tables under it stay open if they were; any other address puts the
  focus on the page's heading. A run's list and the store's keep an identifier on one line
  where there is room.
* The page's look is `app.css` alone: its tokens in `:root`, one accent (forest) beside the
  state, provenance and mark colours; a tag wraps within its box, a state chip does not; a
  table that does not fit scrolls sideways within itself, the page never does.
* No outbound request: no web font, no CDN, no remote image, no analytics; system font stacks
  (`ui-monospace, …, monospace` and `system-ui, …, sans-serif`). No inline `<script>` or `style=`
  attribute (the server's CSP forbids both); styling by class.
* Every off-the-wire string by section 5.
* Capped lists say "N of M shown, capped"; paged message lists say which page of how many.

### 7.1 What a run's isolation, version and engagement say

* **Egress not observed.** Beside every isolation not in `about.observed_isolations` the page
  says "egress not observed": on the run listing, the run header and its overview, the store's
  runs, both runs of a diff, the fleets — for `host` and `remote` alike. A run and a store row
  say it themselves (`egress_observed`, from the run's recording or as the store gives it); the
  page takes theirs and uses `observed_isolations` only where a view gives none (a fleet). An
  isolation not in `about.isolations` is shown as unknown and never as observed; one not
  recorded as "not recorded", egress not observed. The page draws its first view only once
  `/api/about` has answered.
* **A version says what kind it is.** Wherever a server version is shown — the run header
  (`server_version`), the store's runs, findings and candidates, both runs and the server axis of
  a diff, a manifest's entries — it carries its `server_version_kind` beside it: `content`,
  `revision`, `declared` (an endpoint's: the operator's word, not checked; never shown as
  `content`), `mixed`, `unknown`, each as such. The page never works the kind out from the
  version string; a version without a kind given says "kind not given".
* **A run under an engagement**, only as recorded: `run_started.pacing_enforced` `true` is shown
  with what the run was held to, from `run_started.pacing`: `runs_per_origin`,
  `min_interval_seconds` and the one `source` the recording holds (`file` when the file gave
  either value, else `default`; it is not per value). `false`, which only a
  recording of an earlier version says, reads "pacing declared, not enforced by the version that
  made it". `null` shows nothing of its own. Beside any value but `true`, a recorded
  `run_started.pacing` is shown as it stands, so no recorded value goes unseen;
* **A paced run's waits**, only as recorded: every `paced` event on the run's overview, with its
  `seconds`, its `why` and, where it has one, the `status` that asked for the wait. A run without
  one shows nothing. The view adds no sum and no judgement: how long a run waited is what its
  events say. The page shows the numbers as given (`rate_limited`, the cause, stands with the
  run's causes as every cause does);
  `run_finished.window_exceeded` `true` reads "finished after the engagement's window closed",
  `false` is shown as `false` and `null` not at all.
* **The engagement header**. A run's (`run.engagement`) beside its facts; a fleet's
  from its `fleet.json` (`fleet.engagement`, `fleets[].engagement`, through
  `fleet.recorded_engagement`): `null` with `fleet_state_not_in_store` is "not recorded in the
  store", `null` with `refused` at `engagement` (or `fleet:<id>`) is refused, `null` alone is
  "none". The store's (`store_engagement`) above every store page, with its versions and the
  bundles packed from it. Every value the file declared is labelled *declared*: the id, the
  window, `delete_after`; the digest is the file's.
* **A signal's kind** (`evidence`, `heuristic`) is shown on the signal page with one sentence
  saying a heuristic fires on honest content too. It is no severity: both kinds are drawn alike,
  in no colour of danger.

### 7.2 Triage, review mode and evidence

* **Triage** (`#/store/triage`, a store tab): the open questions apart, the publishable findings
  by provenance with each role's current row side by side, a finding's every row fetched only
  when its details are opened, and the real-world candidates apart with their `candidates`
  notice. Read-only: no form; a decision is recorded with `store triage set`.
* **A row carried in** (any triage row, wherever it is shown: Triage, a finding's rows, review
  mode): every row of the store has `imported` — `null` for a row written in this store, or
  `{file_sha256, store_sha256, store_schema, at_utc}` of the `store triage import` that carried
  it (`Store.triage_imports`). A carried row says so beside its author and time (`imported from
  store … (schema …) at …`), review mode with both digests whole; a row written here says
  `written here` in the row table. A store whose import record cannot be read is
  `store_refused`: no row is shown as written here when its origin cannot be told.
* **Review mode** (`#/review?finding=ID`): one finding and nothing else on the screen, so it can
  be shared with the customer — the header's navigation is hidden while it is shown, and nothing
  on it links to another entry. Each role's current row comes first, side by side, as `store
  triage list` prints them; every row of the finding (`history`, the current ones and those a
  later row superseded, as `--history` adds them) follows behind a toggle that is off when the
  page opens, with its state shown in words (`history hidden`, `history shown`) and the number
  of rows beside it — display, not a second edition: the operator's earlier rows are there for
  the customer to ask for. The line to copy is text in a
  `<pre>`, with a button that puts it on the clipboard; nothing is sent anywhere.
* **Evidence** (`#/evidence`, `#/bundle?i=`, `#/attestation?i=`): a download link is only drawn
  for a file whose `download` (or an attestation's `downloadable`) is true; it is the page's one
  link that is not a route — `api/bundle/file?…` or `api/attestation/file?…`, a relative
  same-origin URL with its parameters encoded, never a URL from the data.

### 7.3 What TLS an HTTP run spoke (docs/design/http-transport.md 8)

Only as recorded; nothing here is checked, fetched or worked out anew.

* **The run header and its overview**, for a `streamable-http` run: the endpoint's scheme
  (`run_started.endpoint.scheme`). For `https`, from `run_finished.http.tls`: the protocol
  versions and the SHA-256 of every certificate the endpoint presented, labelled "as presented,
  not checked here" (both lists empty when no handshake completed, each said as none recorded);
  `null` reads "no TLS (plain HTTP to a loopback address)", and on a run whose scheme is `https`,
  which this version never writes, "no TLS recorded for this https run"; a `run_finished`
  without `http`, or an `http` without `tls` (a recording made before TLS was spoken), shows the
  scheme only. `run_started.trust_store_env`, when an object, reads which of `SSL_CERT_FILE` and
  `SSL_CERT_DIR` was set ("the machine's trust store, as OpenSSL found it" when neither) — set or
  not, never a value; `null` shows nothing.
* **The `http` tab**: each request's `tls` (version and certificate) beside its head; `null` and
  absent show nothing.
* **A failure's text.** A `server_failed` or `step_unanswered` with reason `tls` shows its
  `detail` — the library's text, masked when recorded — as text by section 5, with the cause's
  words from the verdict beside it.
* **The store's runs and both runs of a diff**: `endpoint_certificates` as `RunInfo.to_dict()`
  gives it, `null` shown as "no TLS".
* **The diff's caveats**: `certificate_changed` (two runs that each presented certificates and
  share none) is listed among the caveats of `new` and `gone` exactly as the store gives it — its
  name and its words in one string, as every caveat is (a rotated certificate is not a changed
  server) — next to `server_unpinned`. It is a caveat, not an axis: the page moves no axis for it
  and shows the attribution exactly as given.

### 7.4 Which generation a run spoke, and whom it spoke as

Only as recorded; nothing here is detected or worked out anew.

* **The run header and the overview** show `generation`: the era and the protocol version, from
  the last `era_decided` of the recording (`era`, `version`), or, for a run opened by `initialize`
  alone (stdio without an engagement), from the last `script_finished` (`era`, `protocol_version`).
  Beside it, from `era_decided`: how the probe `server/discover` was answered (`probe.outcome`); for
  a stop (`outcome: stop`) the words "stopped at the opening", its `reason` and the error `code` of
  its `refusal` — no listing was sent; and, when `declared` is an object and `differs` is `true`,
  the generation the engagement file declares for the endpoint with "an observation, not a stop".
  A recording with neither event (made before this version), or an `era_decided` whose `era` is
  `null` and nothing else, shows nothing for the field. The overview also lists the `era_decided`
  events whole, under "Generation".
* **`auth`** (`run_started.auth`), in the run header and in the `run_started` panel: `null` reads
  "no token was sent, and no identity was chosen"; an object reads "a token was used" (when
  `token_used` is `true`) with "(env NAME)" for `source: env` and "(a file)" for `source: file`,
  or "no token was sent" with "no Authorization header" for an identity with no token; the
  identity's `identity` and `role` follow "as". Never a value: none is recorded. An absent field
  (a recording from before) shows nothing.
* **The inventory**: `script_finished` shows `era` and `protocol_version`; a `step_reissued` is a
  step like a skip, "asked again", with its reason and page.
* Every string of it is text by section 5: the version, the reason, the identity, the role and the
  environment variable's name.

## 8. The server

* `kymograph web [--store FILE] [--runs DIR] [--manifest FILE]… [--scenario FILE]…
  [--bundle DIR]… [--attestation FILE]… [--bind ADDR] [--port N] [-q]`
  (`--bundle` and `--attestation` each repeatable, passed as
  `Sources(bundles=tuple(...), attestations=tuple(...))` in the order given); `--bind` default
  `127.0.0.1`, `--port` default `8765`, `0` for any free port.
* `--bind` must be `127.0.0.1`, exactly as written (`web.server.BIND_LITERALS`):
  no name, no other address of 127.0.0.0/8, not `::1` or any other IPv6 address. Anything else
  is refused at argument time, exit 2, with the words of the other input errors ("must be
  127.0.0.1, not '…'"). The `Host` names the server answers to are `127.0.0.1` and `localhost`,
  each with the bound port (`web.server.HOST_NAMES`). A store refused by
  `Store.open_read_only`, a `--runs` that is not a directory, a `--manifest`/`--scenario` that
  is not a file: refused at start, exit 2. A manifest or scenario the loader refuses is not a
  start error; its view shows `refused`.
* Prints one line on stderr, naming the sources given and the start address with its token
  (`kymograph: serving --store …, --runs …, N manifest(s), M scenario file(s) read-only on
  http://127.0.0.1:8765/?token=<token> — a local viewer for this machine's user, no TLS`; with
  `-q` that address alone), serves until Ctrl-C, exits 130 as `cli.py` does on an interrupt. No
  request log.
* **Start token and session.** At start the server draws two values with
  `secrets.token_urlsafe(32)`: the **token**, printed in the start address and nowhere else, and
  the **session**, never printed. A `GET` or `HEAD` of `/` whose query is exactly
  `token=<the token>` (compared in constant time) is answered `303 See Other`, `Location: /`,
  with `Set-Cookie: kymograph-<port>=<session>; Path=/; HttpOnly; SameSite=Strict` — the port in
  the name, so two interfaces at once keep their own; no `Domain`, no `Expires`/`Max-Age`; the
  address bar then holds no token. The exchange may be repeated while the server runs (a second
  browser) and always sets the same session. **Every other request** — `/`, every static file,
  every `api/…` route and download — needs that cookie with that value; without it, with another
  value, or with a wrong token it is refused, 403, with the same words whatever was missing
  ("refused: open the address printed when the interface started"), before any route is looked
  up, so a refusal tells nothing about which addresses exist. The token is valid in the start
  address only: as a parameter of any other address it is an unknown parameter (400 with the
  cookie, 403 without), never an exchange. The token and the session appear in no answer body,
  no header but the one `Set-Cookie`, no error output and no file; the start line is the one
  place the token is printed.
* `GET` and `HEAD` only (else 405). A `Host` header that is not `127.0.0.1` or `localhost` with
  the bound port is refused (421) — DNS rebinding: a page that rebinds a name of its own to
  127.0.0.1 sends its own name; a request with an `Origin` that is not the page's own
  (`http://` + the request's own Host) is refused (403). The order: Host (421), method (405),
  Origin (403), session (403), then the route.
* **One user per machine.** Another local user's process can reach 127.0.0.1 too; the token
  keeps it out, but a browser sends the cookie to every port of 127.0.0.1, and the interface
  shows customer data. So customer data is opened in the interface only on a machine with one
  user (docs/web.md).
* Headers on every answer: `Content-Security-Policy: default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`. **No inline script, no inline style, no style
  derived from data:** the policy above allows neither inline script nor inline style, and the
  page sets no `style` attribute, no `element.style` and no class name from a value of the data.
* Static files: only the regular files in `web/static/` (flat, found through
  `importlib.resources`, no symbolic link), by exact name, at `/<name>` and `/static/<name>`; `/`
  is `index.html`. Anything else is 404. The page refers to them, and to `api/…`, by relative
  same-origin URLs.
* Query parameters exactly as section 6: an unknown, repeated or malformed one is a 400 — the page
  adds none of its own.
* `views.ViewError` → its status (400, 404, 409); any other exception → 500 with a generic
  envelope, the details on stderr only, never in the answer.
* **Downloads** (`/api/bundle/file`, `/api/attestation/file`): the view returns
  `views.Download(name, body)`; the answer is `application/octet-stream` with
  `Content-Disposition: attachment; filename="<name, [A-Za-z0-9._-] only>";
  filename*=UTF-8''<name, percent-encoded>`, and the same security headers. `GET` and `HEAD`
  only, like every route; `HEAD` checks as `GET` does and sends no body. Every request does the
  whole work again: the bundle is verified whole (every listed file hashed), then the file is
  read whole into memory, hashed and served as read — nothing is cached between requests. So a
  file of a bundle is served only up to `views.MAX_DOWNLOAD_BYTES`, 256 MiB (its `download` is
  false above it, and a request is a 409); an attestation only up to 1 MiB, the most one is.
* `server.make_server(sources, bind, port, *, views=views)` returns the server, so tests can give
  it a stand-in for `views`.

## 9. Settled while building

What the parts settled where this file was silent or the code had other shapes; binding like the
rest.

* **Causes of a store row or a fleet result.** The store keeps a run's cause keys and its first 20
  `problems` apart, unpaired. A `not_a_result` there carries `causes: [{"cause", "words",
  "state": null}]` with `words` the cause's meaning from `verdict.CAUSES`, and the run's own
  `problems` beside them. Only a recording read under `--runs` has each shortfall's own words and
  state.
* **Run references in `store_diff`** are 8 or more hex characters of a run's SHA-256, matched
  against the store's runs; `Store.resolve`, which also takes a recording's path and reads it
  relative to the working directory, is not called.
* **`store_runs` without `--runs`**: every row is `recording_not_found` with `looked_in: null`; the
  rows are still shown, since they are the store's.
* **Tabs** follow one rule: `sandbox`, `http`, `interventions` and `stderr` only with their
  events; a sandboxed or HTTP run without them says so at `view`.
* **Whether a cause is one the server can bring about** is not in the interface at all
  (`docs/design/web-interface.md` 9, item 4).
* **`not_a_result`** is on `message` too (as on its run), and `fleet_compare` carries
  `fleet_state_not_in_store` for a fleet without `fleet.json`; its `not_a_result` at
  `entry:<entry>/<scenario>` has a `side` (`before`, `after`).
* **A fleet without `fleet.json`**: `fleet` carries `state`, `interrupted`, `findings` and
  `disclosure_candidates` as `null`, always together with `fleet_state_not_in_store`, and only
  then; the page shows "not recorded in the store" for them.
* **An `intervention` names a message by direction and id, not by `seq`** (`events.py`): it is
  linked to the last message recorded before it in its direction, if that message carries its id;
  otherwise to none.
* **A `fleet.json` is the fleet's** only if its `fleet` is the fleet's id and its `digest` the one
  the store filed the fleet under; nothing of any other file is used.
* **Numbers JSON cannot carry** (`1e400`, `NaN`, `Infinity`, which Python's parser takes from a
  recording as floats that are not finite) are passed on as the strings `"Infinity"`, `"NaN"`,
  so a value from the traffic neither breaks the envelope nor makes a run disappear.
* **Order**: runs newest first by the `wall_clock_utc` of `run_started`; a row of another schema
  carries its state and causes and `null` elsewhere.
* **Additive fields** the page may use and need not: `sha256` of the bytes read on `run`,
  `responded_method` on message items, `seqs` on a `capped` notice for messages, `cap_hints` on
  a diff's `capped`.
* **A signal's kind is in the interface now**: `signals.py` marks it, so it is no longer among
  what web-interface.md 9, item 4 keeps out. A signal's
  explanation, "server can bring about" and "canary seen" still are.
* **An endpoint entry's permitted isolation** on the corpus view is `remote` alone, whatever its
  provenance permits a command entry (`policy.decide`); its URL is text, never a link (section 5).
* **The store's engagement columns** (`engagement_id_declared`, `engagement_digest`,
  `engagement_declared` of `RunInfo.to_dict()`) are passed on with the row and shown only among
  its other fields, as given; their own presentation is the engagement header (7.1).

## 10. Tests

* data: pytest, without a server. Recordings made in `tmp_path` by this version — driven against
  `tests/fixtures/` servers as the existing tests do, or written event by event for a state no
  server produces on demand. One test at least per notice kind of section 4 and per row of the
  table in 6.1, and one that every view leaves every file it read byte-for-byte unchanged.
* server: routing, every refusal (bind, Host, Origin, method, path, session), headers, static
  allowlist, the CLI's exit codes; a test that no file in `web/static/` refers to anything outside
  the page (`http:`, `https:`, `//` in `src`/`href`/`url(`, `@import`). For the session: every route
  without the cookie is 403 (`/`, a static file, an `api/…` view, a download); a wrong token 403;
  the right token as a parameter of another address not exchanged; the `Set-Cookie` exactly as
  section 8; `--bind ::1`, `127.0.0.2`, `localhost`, `0.0.0.0` exit 2; a foreign name with the
  bound port as `Host` 421; a foreign `Origin` 403; the token and the session in no answer and,
  over a run of every refusal and a 500, nowhere on stderr but the start line.
* hostile: `tests/fixtures/web/hostile_server.py`, a stdio server whose descriptions,
  titles, schema descriptions, error messages, resource texts and `serverInfo.name` carry
  markup, `<script>`, `Cc`, bidi overrides, zero-width characters, lines over 10 000
  characters, Cyrillic and Greek lookalikes, and keys holding `.` and `[0]`; driven through a
  fixture corpus entry, ingested, triaged and packed, so every view and review mode reads real
  recordings, a store and a bundle. `tests/test_web_hostile.py` over every view's envelope:
  every hostile value arrives as recorded, nothing is dropped or rewritten, and its place is
  named.
* page: rendered in headless Chromium with the network blocked, against envelopes of every notice
  kind and against the hostile fixture, before a change to the page is called done; every page
  and mode, review mode included. The check (`tests/test_web_headless.py`, Docker) runs the
  interface and Chromium together in one container without a network (`--network none`), drives Chromium over
  `--remote-debugging-pipe` with the standard library only, aborts and counts every request that
  is not to the interface's own origin (the count must be 0), and asserts over the rendered DOM:
  no element and no attribute came from the data (every element name and attribute name is one
  the page's code uses; no `on*` attribute; no `href` but `#/…` and the page's own download
  routes), every hostile value present as text with its invisible characters as tokens, and its
  place named.
