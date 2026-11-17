# Design: a read-only web interface — audit of the mockups against the code

Status: **implemented in part.** The read-only interface of sections 5 and 9 is built as
`kymograph web` (`src/mcp_kymograph/web/`, whose `CONTRACT.md` refers to this document), and
has grown past them: triage, review mode, evidence bundles and attestations; what a run's
isolation, TLS, protocol generation and token say; and each signal's kind, which section 9, point
4 had kept out. Its look is now that of `docs/design/web-redesign.md`, not the mockups'. Not
built: everything the mockups take from `repeated-runs.md` (the Series view, classes, rates,
retries, the two digests), `listen`, the legacy GET stream, the ingress bridge, "canary seen",
whether a cause is one the server can bring about, and the terminal artboards (5.3). Written
2026-10-27 as an audit of the mockup export in `docs/design/mockups/` against the version of that
day: package `mcp-kymograph` **0.1.0.dev0**, recording `events.SCHEMA_VERSION` **5**, store
`store.SCHEMA_VERSION` **"10"**, `verdict.RULES_VERSION` **9**. Sections 1 to 4 and 8 describe
that version, and their line numbers refer to it; this version is at store schema "13" and rules
version 14.

The interface proposed here reads and shows; it never runs a server, a fleet or an ingest, never
writes to a store and never writes to a run directory. Every judgement it shows is one the code
already makes — `verdict`, `store.diff`, `fleet.compare` — called, never re-implemented.

Three lines hold throughout:

* **The mockups are not the specification; the code is.** They were drawn as if every proposal
  in `docs/design/` were built, with invented servers, numbers, flags and schema versions. Each
  element below is held against the code and marked `exists`, `partial` or `not implemented`.
* **Shown from the artifact, never derived around it.** A run's state is what `verdict.read`
  says of its recording; a comparison is what `Store.diff` or `fleet.compare` return. Where the
  code has no answer, the interface says "not recorded by this version" — it does not compute one.
* **Nothing from the traffic is trusted on the page.** A recording carries hostile text by
  design (docs/reference.md "Recordings contain sensitive data"; `events.py:5–12`). Every value off the wire
  is escaped, and invisible characters stay visible (the recording is ASCII-escaped,
  `recorder.py:1092`), as `cli.display` does for the terminal (`cli.py:142`).

## 1. What this version records and provides

The version of 2026-10-27, as audited. The code has grown since — among others the subcommands
`signals`, `engagement`, `report`, `evidence` and `web`, `store triage`, `drive --token-env`,
`--token-file`, `--identity` and `--probe`, `--engagement` for both modes, and isolation `remote`
— so `kymograph --help` and the code are current, and this section is not.

### 1.1 Commands and flags (`cli.py:353`, `build_parser`)

| Command | Arguments and flags, exactly |
|---|---|
| `kymograph --version` | |
| `run` (proxy) | `--out-dir` (default `runs`), `--max-message-bytes` (1048576), `--max-duration SECONDS` (86400), `--queue-size` (1000), `--mask-key NAME` (repeatable), `--scenario NAME\|FILE`, `--target HOST`, `--engagement-confirmed`, `--on-rule-error {abort,continue}`, `--server-content FILE` (repeatable) \| `--server-revision REPO@SHA` (mutually exclusive), `-q/--quiet`; server command after `--` |
| `drive` (driver) | everything `run` takes, plus `--script NAME\|FILE` (default `discovery`), `--script-var NAME=VALUE` (repeatable), `--step-timeout SECONDS` (30, at least 2), `--client-settle-timeout SECONDS` (5), `--http URL`, `--manifest FILE`, `--entry NAME`, `--isolation {host,runc,runsc}`, `--sandbox-image REF`, `--target-image REF`, `--sandbox-nonce HEX` |
| `verdict RECORDING` | `events.jsonl` or its run directory; `-q` |
| `corpus check MANIFEST` | `-q` |
| `store ingest` | `--store FILE` (required), `--provenance {reference,poison,real-world}`, `RECORDING…`, `-q` |
| `store diff` | `--store FILE`, `BEFORE AFTER` (run id, 8+ characters of it, or a recording), `-q` |
| `store runs` | `--store FILE`, `-q` |
| `store findings` | `--store FILE`, `--provenance` (required), `-q` |
| `fleet run` | `--manifest FILE`, `--store FILE`, `--out-dir` (`runs`), `--parallel N` (2, at most 16), `--sandbox-image REF` (`mcp-kymograph-sandbox:1`), `--target-image REF` (`python:3.12-slim`), `--step-timeout` (30), `--job-timeout` (600), `--client-settle-timeout` (5), `-q` |
| `fleet diff` | `--store FILE`, `[BEFORE AFTER]` (both or neither; neither = the last two), `-q` |
| `fleet runs` | `--store FILE`, `-q` |

`runsc` is accepted by `--isolation` and refused for every entry: `policy.PROVIDED = ("host",
"runc")` (`sandbox/policy.py:27`). `--http` excludes `--manifest`, `--entry`, `--isolation` and a
server command, and refuses a scenario with rules (`cli.py:1282`, `cli.py:774`). Built-in
scenario: `tool-poisoning` (`cli.py:82`); built-in script: `discovery`.

Exit codes: 0 complete, 2 refused, 3 incomplete, 4 server_failed, 5 sandbox_failed, 6
call_failed (`verdict.py:70–82`), 70 a rule wedged the tool (`proxy.EXIT_RULE_WEDGED`), 74 the
result could not be written to stdout (`cli.py:130`), 130 interrupted with nothing to record it
(`cli.py:125`). `run` hands the server's own code through (`cli.py:109`, `RUN_EXIT_STATUS`).

### 1.2 The recording (`events.py`, schema 5)

Every line is `{"v": 5, "run_id", "seq", "t_ns", "type", …fields}` (`recorder.py:1083–1090`),
JSON with `ensure_ascii`. The event types (`events.py:148`, `EventType`) and their fields:

| Event | Fields |
|---|---|
| `run_started` | `argv`, `argv_redaction_count`, `mode` (`proxy`\|`driver`), `script`, `script_digest`, `script_vars`, `server_identity` (`kind`, `version`, `files`), `scenario_name`, `server_name`, `reproduction` (`manifest{source,digest}`, `corpus{entry,provenance,identity,launch_digest}`, `tool{version,content}`, `scenario{name,digest}`, `environment{isolation,sandbox_image,target_image}`), `authorization` (`scenario`, `scenario_digest`, `declared_target`, `engagement_confirmed_flag`, `rules_loaded`), `virtual_environment`, `isolation`, `transport` (`stdio`\|`streamable-http`), `endpoint`, `limits` (`rule_budget_seconds`, `on_rule_error`, `max_message_bytes`, `max_duration_seconds`, `queue_size`, `terminate_grace_seconds`, `shutdown_budget_seconds`, `client_settle_seconds`), `wall_clock_utc`, `tool_version`, `schema_version` |
| `message` | `direction`, `transport`, `size_bytes`, `truncated`, `incomplete`, `responded_method`, `exchange`, `stream`, `event_id`, `payload{encoding,data,redactions,redaction_count}`, `parse{ok,kind,method,id,is_error,error_reason}` |
| `http_request` | `exchange`, `connection`, `method`, `target`, `headers` (masked map), `session` (ordinal) |
| `http_response` | `exchange`, `status`, `reason`, `headers`, `content_type`, `framing` (`json`\|`sse`\|`empty`\|`other`), `session` |
| `http_end` | `exchange`, `ended` (`complete`, `closed`, `reset`, `timeout`, `client_closed`, `framing_error`, `oversized`), `request_body_bytes`, `response_body_bytes`, `head_bytes`, `events`, `comments` |
| `server_stderr` | `size_bytes`, `truncated`, `payload` |
| `server_exited` | `exit_code`, `signal` |
| `limit_exceeded` | `limit`, `value`, `unit` |
| `intervention` | `action` (`replace`\|`drop`\|`forward`), `direction`, `message_id`, `original`, `replacement`, `steps[{rule, action, reason, changes[{path, before, after}], skipped[{path, reason}]}]` (`recorder.py:515`) |
| `observation` | `direction`, `method`, `message_id`, `message_seq`, `surface`, `path`, `signal`, `normalized` |
| `finding` | `key{server, server_version, tool_version, scenario, statement, locator, signal}`, `direction`, `method`, `message_id`, `message_seq`, `path`, `normalized` |
| `findings_capped` | `method`, `message_id`, `message_seq`, `cap`, `made`, `recorded`, `cut{statement:{signal:n}}` |
| `statement_evaluated` | `statement`, `method`, `message_id`, `message_seq`, `checked`, `not_strings`, `fired{signal:n}`, `reason` (`path_not_found`\|`not_a_string`\|`bounded`) |
| `server_name_mismatch` | `declared`, `announced`, `message_seq` |
| `step_skipped` | `step`, `reason`, `detail` |
| `step_unanswered` | `step`, `pages`, `reason` |
| `step_called` | `step`, `tool`, `arguments`, `check`, `redactions`, `redaction_count` |
| `call_failed` | `step`, `tool`, `kind` (`rpc_error`\|`tool_error`), `code` |
| `script_finished` | `inventory` (`complete`\|`capped`\|`partial`\|`none`), `sent`, `skipped`, `unanswered`, `called`, `failed` |
| `server_failed` | `reason`, `detail` |
| `sandbox_step` | `step`, `ok`, `seconds`, `detail` |
| `sandbox_failed` | `condition`, `phase` (`before_target`\|`after_target`), `detail` |
| `egress_attempt` | `proto`, `family`, `destination`, `port`, `kind`, `count`, `unit` |
| `egress_dns` | `transport`, `family`, `qname`, `qtype`, `answered`, `qname_redactions` |
| `egress_summary` | `consistent`, `problems`, `attempts`, `dns_queries`, `counters`, `capped`, `direct_sink_access`, `sink_suppressed`, `account_differences`, `udp_loss{kernel,sink,lost,unseen_destinations,…}` |
| `rule_quarantined` | `rule`, `reason` (`rule_error`\|`invalid_replacement`), `detail`, `direction`, `message_id`, `invalidated_hits` |
| `recording_stopped` | `reason`, `from_seq` |
| `run_stopped` | `signal` |
| `run_finished` | `reason`, `message_count`, `duration_ns`, `dropped_events`, `unwritten_events`, `quarantined_rules`, `observations_by_method`, `findings_by_statement`, `announced_server`, `server_redactions`, `inspection_bounded`, `server_output_bytes`, `client_input_bytes`, `server_exited_first`, `http{exchanges,responses,streams,events,framing_errors}` (`events.py:64`), `client_undecodable` |

Step reasons (`events.py:70–132`): `capability_not_offered`, `capability_not_an_object`,
`handshake_incomplete`, `no_answer`, `connection_closed`, `page_limit_reached`, `cursor_invalid`,
`driver_error`, `answer_unreadable`, `tool_not_listed`, `http_status`, `session_lost`,
`http_unreachable`, `http_sse_only`, `not_started`. Sandbox steps, in order: `images`, then the
gate's conditions `sink_started`, `helper_exit`, `ruleset_digest`, `armed`, `confinement`,
`barrier`, `sink_bindings`, `resolver`, `authoritative_unreadable`, `direct_blocked`, `probe`,
`udp_marks` (`sandbox/runner.py:86`), the readers `reader_baseline`, `reader_final`, and
`collect` (`runner.py:558`).

### 1.3 The verdict (`verdict.py`, rules 9)

States, gravest first: `sandbox_failed` (5), `server_failed` (4), `incomplete` (3),
`call_failed` (6), `complete` (0) (`verdict.py:68`). `verdict.read(path)` returns a `Verdict`
with `state`, `exit_code`, `causes` (sorted, unique), `problems` (words), `server_exit`,
`truncations` (recorded caps: `findings_per_message`, `page_limit`), `statements`,
`announced_server`. `kymograph verdict` prints `recording, state, exit_code, rules, causes,
problems, server_exit, truncations` (`cli.py:1020`).

`CAUSES` (`verdict.py:152`), all 40: `unreadable`, `schema`, `line`, `no_run_started`,
`no_run_finished`, `recording_stopped`, `unwritten_events`, `inspection_bounded`,
`message_undecodable`, `client_message_undecodable`, `call_error`, `tool_error`,
`call_result_unreadable`, `call_record_unreadable`, `counts_missing`, `findings_missing`,
`findings_uncounted`, `cap_unaccounted`, `step_unanswered`, `step_not_sent`,
`no_script_finished`, `unknown_isolation`, `no_egress_summary`, `udp_loss_unknown`, `udp_loss`,
`server_failed`, `http_unreachable`, `http_status`, `session_lost`, `http_sse_only`,
`http_counts_missing`, `server_silent`, `server_output_unknown`, `empty_session`,
`sandbox_failed`, `sandbox_failed_after_target`, `egress_inconsistent`, `images_mismatch`,
`unfiled_finding`, `interrupted`.

**Which causes a server can bring about is not in the code.** The verdict carries no such
attribute. The only split the code makes is by phase — `sandbox_failed` (before the target) and
`sandbox_failed_after_target` (`verdict.py:420–428`) — and the comment that
`client_message_undecodable` is "not held against the server". The yes/no table exists only in
`docs/design/repeated-runs.md` 4.6, as a proposal.

### 1.4 The store (`store.py`, schema "10")

Tables (`store.py:107`): `meta(name, value)`; `runs` (one row per recording: `run` = SHA-256 of
the recording's bytes, `run_id`, `recording` (the path as given at ingest), `provenance`,
`server`, `announced_server`, `server_version`, `server_identity_kind`, `launch_digest`,
`manifest_digest`, `tool_version`, `tool_content`, `scenario`, `scenario_digest`, `isolation`,
`sandbox_image`, `target_image`, `statements` (JSON), `wall_clock_utc`, `state`,
`problem_count`, `problems` (first 20), `causes`, `truncations`, `rules`); `findings` (one row per
key: `id`, `key` (canonical JSON), the seven key fields, `provenance`); `sightings` (`finding`,
`run`, `path`, `message_seq`, `normalized`); `fleets` (`fleet`, `started_utc`, `finished_utc`,
`manifest_source`, `manifest_digest`, `tool_version`, `tool_content`, `isolation`,
`sandbox_image`, `target_image`, `parallel`, `processed`, `digest`, `complete`, `problems`,
`rules`); `fleet_results` (`fleet`, `entry`, `scenario`, `provenance`, `state` — a run state,
`refused` or `unfiled` — `exit_code`, `run`, `problems`, `causes`). Only driver runs with a
reproduction triple are filed (`store.py:971`, `_read_run`).

**`store diff`** (`Store.diff`, `store.py:766`; `Diff.to_dict`) returns `before`, `after` (each
a `RunInfo`), `complete`, `rules{before,after,moved}`, `same_entry`, `axes` (`server`:
`server_version`, `launch_digest`; `tool`: `tool_version`, `tool_content`; `scenario`:
`scenario`, `scenario_digest`; `environment`: `isolation`, `sandbox_image`, `target_image` —
each `{moved, field:{before,after}}`, `store.py:87`), `moved_axes`,
`attribution{attributable, axis, note}` (`store.py:863`), `caveats{new:[…], gone:[…]}`
(`scenario_drift`, `environment_moved`, `findings_capped`, `listing_capped`), and `new`,
`gone`, `unchanged` — each `{identity, key_before, key_after, sightings_before,
sightings_after, statement_hint (statement_added|statement_removed), cap_hint
(capped_before|capped_after)}`. Exit 0, or 3 when either run is not complete.

**`fleet diff`** (`fleet.compare`, `fleet.py:766`) returns `before`, `after`, `complete`,
`same_result` (digest equality), `rules{before,after,moved}`, `axes` (`manifest`, `tool`,
`environment`, each `{moved, field:{before,after}}`), and `entries[]`, one per `(entry,
scenario)`: `change` (`compared`\|`added`\|`removed`\|`not_comparable`), `states{before,after}`,
and for `compared` also `causes{before,after}`, `complete`, `moved_axes`, `axes`,
`attribution`, `caveats`, `new[{identity, statement_hint, cap_hint}]`, `gone[…]`,
`unchanged` (a count).

**`fleet run`** prints `{"fleet": FleetRun.to_dict(), "diff": …}` (`fleet.py:254`): `fleet`,
`started_utc`, `finished_utc`, `digest`, `rules`, `state`, `complete`, `manifest`, `tool`,
`environment`, `parallel`, `processed`, `interrupted`, `problems`, `results[{entry, scenario,
provenance, state, exit_code, run, findings (count), causes, problems}]`,
`findings{reference:[…], poison:[…]}`, `disclosure_candidates{real-world: n, note}`. A fleet id
is `YYYYMMDDTHHMMSSZ-<8 hex>` (`fleet.py:489`).

Two things the store does not keep: **a fleet's `state`** (only `complete`; `FleetRun.state` is
computed, `fleet.py:214`) and **`interrupted`** (only as words in `problems`). Both are in the
fleet's `fleet.json` (below).

### 1.5 The signal library (`signals.py`, `inspection.py`, `paths.py`)

16 signals in `signals.LIBRARY` (`signals.py:590`), each with a `view` (`raw`, `content`,
`name`) and a `reach`:

| Reach (built-in walk) | Signals |
|---|---|
| `everywhere` | `invisible_characters` (raw), `chat_template_marker`, `instruction_override`, `concealment_directive`, `output_directive`, `model_addressed` (content) |
| `metadata` (tool metadata surfaces only) | `hidden_comment` (raw), `role_line` (content), `whitespace_padding` (raw) |
| `declared` (only a statement asks) | `imperative`, `second_person`, `embedded_url` (content), `base64_block`, `hidden_html` (raw), `tool_name_duplicate`, `tool_name_lookalike` (name) |

A 17th ID, `lone_surrogate`, is set by the inspector alone on `result.serverInfo.name` and may not
be named by a statement (`scenario.py:438`). Surfaces (`inspection.py:131`):
`tool_description`, `tool_title`, `schema_field_description`, `schema_enum_value` (the metadata
surfaces, `inspection.py:148`), `tool_result_text`, `error_message`, `resource_text`, and
`server_info` (inspector only). The walk reads `tools/list`, `tools/call` (content text, embedded
resource text, `structuredContent`) and `resources/read` answers and every `error.message`
(`inspection.py:301`); it does not read prompts, resource listings or `initialize`
instructions — a statement can. Normalisation order (`signals._flatten`, `signals.py:158`): HTML
entities, percent-encoding, NFKC, strip zero-width/bidi/tag characters, peel comments, HTML and
markdown, collapse whitespace; readable base64 blocks decoded alongside. Locator identities
(`paths.IDENTITY_FIELDS`, `paths.py:71`): `result.tools`→`name`, `result.prompts`→`name`,
`result.prompts[].arguments`→`name`, `result.resources`→`uri`,
`result.resourceTemplates`→`uriTemplate`, `result.contents`→`uri`. Caps: 20 observations and 20
findings per message (`inspection.py:77`, `:83`).

**Not in the code:** a signal's kind (evidence or heuristic), its "looks for" text and its
"honest content that matches too" text. They exist in `repeated-runs.md` 4.1 only.

### 1.6 Masking (`masking.py`)

Blanked values become `***REDACTED***` (`masking.py:56`); protocol handles at
`params.progressToken` and `params._meta.progressToken` become `***HANDLE-<12 hex>***`
(`masking.py:61–66`, `:92`); key needles `apikey`, `auth`, `bearer`, `cookie`, `credential`,
`passphrase`, `passw`, `privatekey`, `secret`, `sessionid`, `token` (`masking.py:178`); HTTP
headers blanked whole: `authorization`, `cookie`, `mcp-session-id`, `proxy-authorization`,
`set-cookie` (`masking.py:114`); `www-authenticate` parsed then masked; `last-event-id` a handle;
query strings as maps. Where masking struck is in `payload.redactions` (paths) and
`redaction_count`; handles are not listed separately. `run_finished.server_redactions` counts
server-to-client hits only.

## 2. The design documents, claimed against actual

As of 2026-10-27. The status lines of both documents have been rewritten since, and say what is
built today.

| Document | Claims | Actual | Evidence |
|---|---|---|---|
| `http-transport.md` | "proposal, not implemented. Nothing in the code refers to this document yet." (line 3) | **Partly implemented, and referred to.** Built: one recording format for stdio and HTTP (schema 4, now 5), `http_request`/`http_response`/`http_end`, `message.exchange/stream/event_id`, `run_finished.http`, the driver over Streamable HTTP as **`drive --http URL`** (proposed: `drive --url`), session ordinals and a closing `DELETE`, header/query masking and SSE-id pseudonyms, the causes `http_unreachable`, `http_status`, `session_lost`, `http_sse_only`, `http_counts_missing` (rules 8), refusal of rule scenarios over HTTP. Not built: `listen` (proxy mode over HTTP), era detection and the modern era (`eras.py` exists, "Nothing calls this module yet", `eras.py:3`), `server/discover`, the GET stream, resumption, re-issue, a second session after a 404, `session_started`/`session_ended`/`server_stdout` events, `script_finished.era/protocol_version/session`, the ingress bridge and its four gate conditions, `launch.transport: streamable-http` in a manifest (`corpus.TRANSPORTS = ("stdio",)`, `corpus.py:56`), remote endpoints (isolation `remote`, identity kind `endpoint`), tokens, the causes `unauthorized`, `rate_limited`, `protocol_unsupported`, `http_unparsed`, `ingress_inconsistent`, reason words `not_listening`, `stream_broken` | `events.py:43–63`, `events.py:148–158`; `cli.py:420` (`--http`), `cli.py:1282`; `verdict.py:109–114`, `:125`; `http_client.py:7–9`, `:192`; `src/mcp_kymograph/http/__init__.py:1` and `masking.py:103` cite the document; README:700–726 |
| `http-transport.md` 6.1 item 5 | "`events.SCHEMA_VERSION` 3 → 4" | done, and since raised to 5 | `events.py:43` |
| `repeated-runs.md` | "proposal, not implemented, except two splits from section 8 … Nothing else in the code refers to this document yet." (lines 3–6) | The two splits are real (`sandbox_failed_after_target`, rules 6, `verdict.py:101–103`, `:420–428`; `tool_name_duplicate`/`tool_name_lookalike`, `signals.py:72–73`). **"Nothing else refers to it" is false:** `rates.py` implements its arithmetic (Wilson, rule of three, the evidence bound, SPRT, Fisher, Holm, Benjamini–Hochberg) and names it (`rates.py:1`), though nothing in a run path calls it (`rates.py:4`); `false_alarms.py` uses it; `fleet.py:227` names the document. Not built: `--repeat`, repetition indices, `fleet_series`, `fleet_rates`, classes, the two digests, retries, the budget, `verdict/rates.py`, the cause table of 4.6 | `rates.py:1–4`; `fleet.py:227`; `store.py:107–200` (no series tables) |
| the engagement design of that day (since built: `docs/engagements.md`) | "proposal, not implemented" | not implemented then. It proposed the engagement file and `--engagement FILE` for `run`, `drive`, `fleet run` and a future `listen`, the evidence bundle, the report and **the triage table with a status per real-world finding** — the closest any design came to the Store mockup's disclosure column. Built since; the operator's guide is `docs/engagements.md` | — |
| `repeated-runs.md` 2.2 | "Store schema 9 (8 is the current one, with `causes`)" | the current store schema is 10; 9 added `rules` | `store.py:99–105` |

## 3. The mockup views, element by element

As audited on 2026-10-27: the status words are those of that version. What of it has been built
since is listed at the head of section 4.

The mockups' header strips claim "recording schema 4 · rules v4", "store schema 9" and "tool
0.2.0"; this version is schema 5, rules 9, store schema 10, tool 0.1.0.dev0. Their command lines
are drafts as well; the command is `kymograph`. Neither is repeated in the tables below.

Status words: **exists** — the code produces it today; **partial** — some of it, the rest named;
**not implemented** — with the design document that proposes it, or "no design doc proposes it"
where the mockup invents it.

### 3.1 Corpus — `corpus check` (`extracted/Corpus.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Manifest file name, source path, digest | `corpus.load` → `Manifest.source`, `.digest`; `corpus check` JSON `manifest` (`cli.py:1326`) | exists |
| Header: tool version and source digest | `corpus.tool_identity()` (`corpus.py:162`); JSON `tool{version, content}` | exists |
| Banner "read whole · N entries · N scenarios load" | count of `Manifest.entries`, distinct `ScenarioRef.name`; success = no `ManifestError` | exists |
| Entry name, provenance badge | `Entry.name`, `Entry.provenance` | exists |
| Source: `paths: …` as written | `Entry.paths` (resolved, `corpus.py:106`); `corpus check` gives only `identity.files` (a count); the paths as written are in the manifest file | partial: not in the command's output; read with `corpus.load` or from the file |
| Source: `revision: repo@sha` | `identity.kind == "revision"`, `identity.version` | exists |
| Source: `endpoint: https://…` | — | not implemented: http-transport.md 4.1 |
| server_version digest and file count | `identity.version`, `identity.files` | exists |
| "directory walked" | — | not implemented: no design doc proposes it (the identity does not say whether a path was a directory) |
| "pinned output: 4 findings" | `tests/fixtures/corpus/expected.json` — a test fixture, not product data | not implemented: no design doc proposes it |
| Launch: `stdio` and the command as written | `Entry.transport`, `Entry.command_written`; JSON `transport`, `command` | exists |
| Launch: `streamable-http`, `listen 127.0.0.1:…`, `path /mcp` | `corpus.TRANSPORTS = ("stdio",)` (`corpus.py:56`) | not implemented: http-transport.md 1.1, 2.1, 6.2 |
| Launch: `remote · TLS, system trust store` | — | not implemented: http-transport.md 2.1, 4 |
| Launch digest | `Entry.launch_digest`; JSON `launch_digest` | exists (not drawn in the table, drawn in the triple) |
| Scenarios of the entry | `Entry.scenarios[{name, digest}]` | exists |
| "May run under": host ✓, runc ✓ | `policy.PERMITTED[provenance]` (`sandbox/policy.py:20`); JSON `isolation_permitted` | exists |
| runsc ✗ "not provided yet" | `policy.PROVIDED` (`policy.py:27`) | exists |
| `remote` chip, "needs --engagement-confirmed; one run per origin, 10 s apart" | — | not implemented: http-transport.md 4.1, 4.4, 4.5 |
| "under runc: reached through the ingress bridge's socket file" | — | not implemented: http-transport.md 3.2 |
| "refused under every isolation in this version" | `Entry.refusal_to_run()`; JSON `refused_here` (words) | exists |
| Provenance × isolation matrix | `policy.PERMITTED`, `policy.PROVIDED` | exists (host, runc, runsc columns); the `remote` column: not implemented, http-transport.md 4.1 |
| Reproduction triple panel | `corpus.reproduction(manifest, entry, digest, env)` (`corpus.py:182`); recorded in `run_started.reproduction` of each run. Keys differ from the mockup: `manifest`, `corpus{entry, provenance, identity, launch_digest}`, `tool{version, content}`, `scenario{name, digest}`, `environment{…}` | partial: not in `corpus check` output; a manifest has no environment until a run picks one |
| Refused manifest: file, place and reason | `ManifestError.source`, `.reason`; the reason names the place as a key path (`entries[0].provenance: unknown provenance 'weird'; …`) | exists |
| Refused manifest: the offending line highlighted | — | partial: the place is a key path, not a line number |

### 3.2 Scenario (`extracted/Scenario.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| File name, "read whole", SHA-256 | `scenario.load` → `Scenario.source`, `.digest` (hex, no `sha256:` prefix, unlike manifest digests) | exists |
| Header "scenario format version 1" | `scenario.FORMAT_VERSION` (`scenario.py:54`) | exists |
| Source text with line numbers | the file itself | exists (read the file; not a product output) |
| Rules in file order: name, action badge, direction, method, path | `Scenario.rules[DeclaredRule{name, direction, method, action, path, value, text, position}]` | exists |
| Rule description text ("Appends text and keeps…") | the loader accepts `description` and drops it (`scenario.py:70`) | partial: the per-action explanation is fixed copy; a file's own `description` is not kept by the loader |
| Statements: name, method, path, signals | `Scenario.statements[Statement{name, method, path, signals}]` | exists |
| Engagement-gate note, `authorization.scenario_digest` | `run_started.authorization` | exists |
| From a run: `statement_evaluated` table (places, signals with counts, reason) | `statement_evaluated{statement, checked, not_strings, fired, reason}` | exists |
| From a run: one `intervention` event | `intervention{action, direction, message_id, original, replacement, steps[{rule, action, reason, changes[{path, before, after}], skipped}]}`; the mockup's `changed`, `method` and `message_seq` are not its fields (method via the message, by `message_id`) | partial: field names differ |
| Refused file: place and reason | `ScenarioError` text: `<file>: rules[0].action: unknown action 'explode'; …` | exists |
| Refused file: offending line highlighted | — | partial: place is a key path, not a line |

### 3.3 Signals (`extracted/Signals.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Header "15 signals · deterministic" | `signals.LIBRARY` has 16 | partial: the count is 16 (17 IDs with `lone_surrogate`) |
| Signal ID and built-in walk reach | `Definition.signal`, `.reach` (`signals.py:590`) | exists |
| Filter: every surface / tool metadata / declared only | `Reach.EVERYWHERE / METADATA / DECLARED` | exists |
| `tool_name_collision` row | split into `tool_name_duplicate` and `tool_name_lookalike` (`signals.py:72–73`) | partial: two rows, not one |
| Kind (evidence / heuristic) | — | not implemented: repeated-runs.md 4.1, 6 |
| "Looks for" and "honest content that matches too" | — | not implemented: repeated-runs.md 4.1 has the words, the code does not |
| View (raw / content / name) | `Definition.view` | exists (not drawn; worth showing) |
| Normalisation steps, in order | `signals._flatten`, `normalize` (`signals.py:158`, `:233`) | partial: the mockup draws NFKC first; the code decodes entities and percent-encoding first, then NFKC, strip, peel |
| Raw vs normalised example, `normalized: true` | `observation.normalized`, `finding.normalized`; `signals.normalize(text)` | exists |
| Surfaces: walk vs statement only | `inspection.Surface`, `METADATA_SURFACES`, `surfaces()` | exists; `server_info` and the fact that prompts are not walked are missing from the mockup |
| Locator identity table | `paths.IDENTITY_FIELDS` (`paths.py:71`) | exists |
| Example path → locator | `paths` locator derivation; `finding.path` vs `finding.key.locator` | exists |

### 3.4 Inventory — a driver run (`extracted/Inventory.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Run directory, mode, script | run directory name; `run_started.mode`, `.script`, `.script_digest` | exists |
| Transport and announced protocol version | `run_started.transport`; the driver announces `2025-06-18` (`driver.PROTOCOL_VERSION`, `driver.py:87`) in the recorded `initialize`; the server's version is in its answer | exists (read from the messages) |
| Isolation with "proof held" link | `run_started.isolation`; `sandbox_step` events | exists |
| Server exit "recorded, never handed through" | `server_exited{exit_code, signal}` | exists |
| State and exit badge | `verdict.read(path).state`, `.exit_code` | exists |
| `server_name_mismatch` banner | `server_name_mismatch{declared, announced}` | exists |
| Script steps 1–7 with status | `message` events (requests sent), `step_skipped`, `step_unanswered`, `script_finished{sent, skipped, unanswered}` | exists |
| Pages per listing ("2 pages · nextCursor followed") | count of `tools/list` request `message` events; `step_unanswered.pages` only for a cut listing | partial: counted from messages, not recorded as a number |
| "end of input" step | implied by stdio transport; no event | partial: no event says it; HTTP has a `DELETE` exchange instead |
| `step_called` / `call_failed` for a script file | `step_called`, `call_failed`, `script_finished{called, failed}` | exists — not drawn in the mockup; must be shown |
| Tabs: tools, resources, templates, prompts with counts | the `result` of each listing's answer `message` (masked payload) | exists (reconstructed from messages) |
| "Prompts — not offered" | `step_skipped{step: prompts/list, reason: capability_not_offered}` | exists |
| Tool card: name, title, input fields, description | the tool object in the `tools/list` answer | exists |
| Highlighted span inside the description | `observation`/`finding` give `path` and `signal`, never the span | partial: the field is known, not the characters |
| Signal chips per tool, `· normalized` | `observation` (walk) and `finding` (statement), by `path` index into the answer | exists |
| `tool_name_collision → get_weather` | `tool_name_duplicate` / `tool_name_lookalike`, declared-only: appears only if a statement asks | partial: different IDs, and only as a finding |
| `run_finished` account: observations per method, findings per statement, `server_redactions`, `inspection_bounded`, `quarantined_rules` | `run_finished` fields of the same names | exists |
| "findings · all-signals 4 (pinned: 4)" | the pinned number is `tests/fixtures/corpus/expected.json` | partial: the count exists; "pinned" is test data, no design doc proposes it |
| States and exit codes table | `verdict.EXIT_CODES`, `cli.EXIT_REFUSED`, `EXIT_OUTPUT_FAILED`, `EXIT_INTERRUPTED`, `proxy.EXIT_RULE_WEDGED` | exists; the mockup omits `call_failed` 6 and 70 |

### 3.5 Proxy — a session with a scenario (`extracted/Proxy.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Mode `proxy`, scenario, command | `run_started.mode`, `.scenario_name`, `.argv` (masked) | exists |
| State badge | `verdict.read` | exists |
| Exit code "the server's" | not in the recording; `server_exited.exit_code` is what was handed through, unless the run was `server_failed`/silent (`cli.py:893–937`) | partial: derivable, not recorded as "exit code of Kymograph" |
| Proof of effect: "#5 appended … to 5 tool descriptions" | `intervention.steps[].changes[]` | exists |
| Proof of effect: "#7 the client's next request carried the canary" / "canary seen" chip | — nothing looks for the injected text in later client messages | not implemented: no design doc proposes it (the README calls proof of effect the purpose of proxy mode, but no code or design marks it) |
| `rule_quarantined`: rule, where, invalidated hits | `rule_quarantined{rule, reason, detail, invalidated_hits}`; `run_finished.quarantined_rules` | exists |
| "Its drop at #6 is now invalid too" | every `intervention` step whose `rule` is in `quarantined_rules` | exists (derived by rule name) |
| authorization block | `run_started.authorization`; keys are `declared_target`, `engagement_confirmed_flag`, `scenario`, `scenario_digest`, `rules_loaded` (the mockup's `target_declared` is not a key) | exists |
| Message list: seq, direction, kind, method, id | `message.parse{kind, method, id, is_error}`, `.direction`, `responded_method` | exists |
| Chips: intervention · inject, dropped, invalid | `intervention.action`, steps; quarantine | exists |
| Chip "1 value masked" | `message.payload.redaction_count` | exists |
| Detail pane: steps with before/after, `reason path_not_found`, "did not match" | `intervention.steps`; a rule that did not match leaves no step | partial: "did not match" is not recorded — a non-matching rule leaves nothing |

### 3.6 Recording — an HTTP run in three modes (`extracted/Recording.dc.html`)

Mode "legacy · sessions" (default):

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Breadcrumb "Fleet › entry × scenario › repetition 24" | — | not implemented: repeated-runs.md 2.1 (repetition); HTTP corpus entries: http-transport.md 6.2 |
| Run directory, state and exit | run directory; `verdict.read` | exists |
| `mode drive · script`, `transport streamable-http` | `run_started.mode`, `.script`, `.transport`, `.endpoint` | exists |
| `era legacy · 2025-11-25` | — | not implemented: http-transport.md 2.4 (`script_finished.era`) |
| `listen 127.0.0.1:8931 /mcp` | `run_started.endpoint` (host, port, path) for `drive --http` | partial: the endpoint exists; `listen` as a manifest field does not |
| `isolation runc · ingress bridge` | `drive --http` refuses `--isolation` (`cli.py:1282`) | not implemented: http-transport.md 3.2 |
| `duration 3.84 s` | `run_finished.duration_ns` | exists |
| Era detection panel | — | not implemented: http-transport.md 2.4 |
| Sessions panel: opened at, ended by 404, re-initialised | `http_request.session`/`http_response.session` ordinals; 404 → `session_lost` | partial: ordinals and the loss exist; a second session, `session_started`/`session_ended` do not (http-transport.md 2.5, 2.6) |
| `run_finished.http`: exchanges, sse streams, events, framing errors | `run_finished.http{exchanges, responses, streams, events, framing_errors}` | exists |
| `run_finished.http`: connections, sessions, comments, resumptions, 403s | connections and comments are per-exchange (`http_request.connection`, `http_end.comments`); resumptions and 403s none | partial: resumptions and Origin refusals not implemented, http-transport.md 2.6, 2.1 |
| Exchanges table: #, connection, HTTP method, status, framing, session, how it ended | `http_request{exchange, connection, method, session}`, `http_response{status, framing}`, `http_end{ended, events}` | exists |
| Exchanges table: MCP method per exchange | `message.exchange` joins messages to exchanges; `parse.method` | exists |
| Rows: `server/discover` probe, GET server stream, GET resume | — | not implemented: http-transport.md 2.4, 2.6 |
| Row: `DELETE (end session)` with 405 | `http_client` closing `DELETE` (`http_client.py:192`) | exists |
| `step_skipped` line under the table | `step_skipped` | exists |
| Exchange detail: masked request and response heads, body | `http_request.headers`, `http_response.headers`, the `message` payload | exists |
| Findings table: signal, locator, path, exchange · framing, normalized | `finding` + `message.exchange` + `http_response.framing` | exists |
| `script_finished` with `era`, `protocol_version`, `session`, `reinitialised`, `steps_sent` | `script_finished{inventory, sent, skipped, unanswered, called, failed}` | partial: `era`, `protocol_version`, `session` not implemented (http-transport.md 6.1); `reinitialised`, `steps_sent` invented |
| `verdict` JSON with `transport`, `isolation`, `egress` | `verdict` output has `state, exit_code, rules, causes, problems, server_exit, truncations` | partial: the extra keys are not in it; egress comes from `egress_*` events |
| "What holds in every HTTP run" | README 700–726; `http_end.ended = framing_error` | partial: "a batch element inspected on its own" is not implemented (http-transport.md 1.3) |

Mode "modern · re-issue": entirely **not implemented** — http-transport.md 2.4, 2.6 (modern
era, `_meta`, re-issue with a new id). Mode "401 · remote endpoint": entirely **not
implemented** — http-transport.md 2.8, 4 (remote isolation, tokens, parsed challenge, cause
`unauthorized`); the parsing of `WWW-Authenticate` itself exists in the masker (`masking.py:103`).

### 3.7 Sandbox (`extracted/Sandbox.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Image ids in the header | `run_started.reproduction.environment`; `sandbox_step{step: images}.detail` | exists |
| Diagram: host, sink `--network none`, target, nft redirect + mark | fixed explanation (docs/reference.md "Isolation") | exists (static copy) |
| Diagram: ingress bridge, Unix socket | — | not implemented: http-transport.md 3.2 |
| `sandbox_step` list, in order, held/failed, seconds, evidence | `sandbox_step{step, ok, seconds, detail}` | exists |
| Steps "Ingress bridge listening", "Ingress path proven" | — | not implemented: http-transport.md 3.4 |
| Step "Gate · every condition held" | the conditions of `runner.REQUIRED`; no event named `gate` | partial: derived from the condition steps |
| Step "Target started · accepting after 0.41 s" | no `sandbox_step` for the target; the first answer's time is in the messages | partial |
| Confinement read back: uid, capability sets, NoNewPrivs, seccomp, read-only root | `sandbox_step{step: confinement}.detail` (`egress.py:183`) | exists |
| "files seen = manifest content: 4 · sha256" | staged and checked before the run (`runner.stage`); a mismatch refuses the run | partial: no event records the check that held |
| "kernel counters, as the target: unreadable" | `sandbox_step{step: authoritative_unreadable}` | exists |
| Egress table: event, protocol, original destination, kernel count | `egress_attempt{proto, family, destination, port, count, unit}` | exists |
| Sink count per destination, membership verdict per row | `egress_summary.account_differences` (only where counts differ), `.consistent` | partial: per-row sink count only where it differs |
| `egress_dns` row with qname and types | `egress_dns{qname, qtype, answered}` | exists |
| `egress_summary`: sink ≡ kernel, udp counted/received, `udp_loss` and its limit, `account_differences` | `egress_summary.consistent`, `.udp_loss`, `.account_differences`; `verdict.UDP_LOSS_LIMIT` | exists |
| Mode "Sandbox failed": condition, phase, no target | `sandbox_failed{condition, phase, detail}`; state `sandbox_failed` | exists |

### 3.8 Verdict (`extracted/Verdict.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Command, recording path | `kymograph verdict RECORDING` | exists |
| State and exit code | `Verdict.state`, `.exit_code` | exists |
| Modes: incomplete 3, server_failed 4, sandbox_failed 5, complete-capped 0 | `verdict.STATES`, `EXIT_CODES` | exists; `call_failed` 6 is missing from the mockup |
| Causes with their words | `Verdict.shortfalls[{state, reason, cause}]` (`verdict.py:244`); the CLI prints `causes` and `problems` as two lists, not paired | partial: pairing needs `verdict.read` in-process, not the CLI JSON |
| "server can cause" tag per cause | — | not implemented: repeated-runs.md 4.6 |
| "What the recording holds" strip: event types with counts and the ones that fall short | the recording's events; which ones a shortfall comes from is not returned | partial: counts exist; the link from a cause to its event is not recorded |
| `verdict.CAUSES` split yes/no | `verdict.CAUSES` (40 keys); the yes/no split is not in code | partial: the list exists (the mockup's is the old one, 24 keys, without `call_*`, `http_*`, `message_undecodable`, `client_message_undecodable`, `sandbox_failed_after_target`); the split is not implemented: repeated-runs.md 4.6 |
| "until it is split, sandbox_failed counts as yes" | already split, rules 6 (`verdict.py:420–428`) | the mockup is out of date |
| "A recorded cap is complete": `findings_capped`, `page_limit` | `Verdict.truncations` | exists |
| "Whose exit code is it?" | `cli.RUN_EXIT_STATUS`, `DRIVE_EXIT_STATUS` (`cli.py:109–122`) | exists (static copy) |

### 3.9 Masking (`extracted/Masking.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| A message "as written" with blanked values and handle pseudonyms | `message.payload.data`; the placeholder is `***REDACTED***`, not `***` | exists |
| `redactions` list of paths | `message.payload.redactions`, `.redaction_count` | exists |
| `handles` list | — handles are not listed apart (`recorder.py:1167` keeps them out of the redaction count) | not implemented: no design doc proposes it (findable by the `***HANDLE-` prefix) |
| Field names `body`, top-level `redactions` | the event nests both under `payload` (`payload.data`, `payload.redactions`) | partial: shape differs |
| "Blanked" and "Handle pseudonym" explanations | `masking.DEFAULT_KEY_NEEDLES`, `PROTOCOL_HANDLE_PATHS`, `--mask-key` (`run_started` does not record the extra keys' names) | exists (generated from `masking.py`) |
| Session id blanked, ordinal kept | `BLANKED_HEADERS` includes `mcp-session-id`; `http_request.session` | exists |
| `server_redactions` table by direction and place | `run_finished.server_redactions` (a count); places from server-to-client `message.payload.redactions` | exists |
| HTTP header row ("Set-Cookie header") counted | `recorder.py:335` counts header paths | exists |
| "Where masking reaches": bodies, intervention values, argv | `mask_json`, `recorder._value_payload`, `mask_argv` | exists |
| HTTP headers and query strings as maps; `WWW-Authenticate` parsed — marked "proposed" | `mask_headers`, `mask_query` are called by the recorder (`recorder.py:303`, `:335`, `:451`) | exists — the mockup's "proposed" is out of date |
| "A token never goes on argv: a file or an environment variable" | — | not implemented: http-transport.md 2.8 |

### 3.10 Main — the fleet report (`extracted/Main.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Fleet id and start time | `fleets.fleet`, `.started_utc` (ids are `20261008T091400Z-1a2b3c4d`, not `f-0042`) | exists |
| Command line with `--repeat`, `--include-remote` | — | not implemented: repeated-runs.md 0; http-transport.md 4.5 |
| Chips: repeat, budget, retries, p₀/p₁/α/β | — | not implemented: repeated-runs.md 4.2–4.7 |
| Chips: parallel, sandbox and target image ids | `fleets.parallel`, `.sandbox_image`, `.target_image` | exists |
| Counters: keys, series complete/undecided/incomplete, runs considered/scheduled/retried | keys = rows of `fleet_results`; per-key state = the run's state | partial: one run per key; series counts not implemented, repeated-runs.md 3.1 |
| Counter "Refused" | `fleet_results.state = refused` | exists |
| Table: entry, provenance | `fleet_results.entry`, `.provenance` | exists |
| Table: transport, era | — the fleet runs stdio entries only | not implemented: http-transport.md 2.4, 6.2 |
| Table: isolation | `fleets.isolation` (always `runc`); `remote` not implemented (http-transport.md 4) | partial |
| Table: scenario, state | `fleet_results.scenario`, `.state` | exists (`complete`, `incomplete`, `server_failed`, `sandbox_failed`, `call_failed`, `refused`, `unfiled`) |
| State `undecided` | — | not implemented: repeated-runs.md 3.1 |
| Runs "48 / 55 · 7 past n\*" | — | not implemented: repeated-runs.md 2.3 |
| Identities: stable/flaky/absent/undecided counts | — | not implemented: repeated-runs.md 3.2, 4 |
| Non-results with causes | `fleet_results.causes`, `.problems` | exists (per run); "retried" not implemented, repeated-runs.md 4.6 |
| "Runs that were not results" table with "server can cause" and treatment | causes exist; the column and treatment do not | partial: not implemented, repeated-runs.md 4.6 |
| "How to read a class" | — | not implemented: repeated-runs.md 4 |
| Buttons "Compare with …", "Raw JSON" | `fleet.compare`; `fleet.json` | exists |
| Fleet problems (exit code against recording, environment drift) | `fleets.problems` | exists — not drawn in the mockup; must be shown |
| Publishable findings vs real-world count | `FleetRun.to_dict().findings`, `.disclosure_candidates` (in `fleet.json`) | exists — not drawn |

### 3.11 Series — repeated runs of one key (`extracted/Series.dc.html`)

Every element of this view depends on `repeated-runs.md`, and **none is implemented**: scheduled /
considered / complete / unknown / retried counts (2.2, 3.1), identities with procedure,
hits/observed, worst-case Wilson bars and class (3.2, 4), the statement of "absent" with its β
(3.2), runs in repetition order with re-runs (2.3, 4.6), the sequential-test chart with both
worst-case paths (4.3), the two digests (2.3). The arithmetic exists in `rates.py`, which no run
path calls (`rates.py:4`). The egress identity row ("egress_attempt … evidence") is a finding
that does not exist either: egress is recorded, not filed as a finding (`repeated-runs.md` 4.1). The only parts that exist are the key header — `server_version` and scenario digest
from `runs` — and "sessions … re-initialised after a 404", which is not implemented
(http-transport.md 2.5).

### 3.12 Compare — `fleet diff` / `store diff` (`extracted/Compare.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Before → after fleet ids and dates | `fleet.compare` `before`, `after`; `fleets.started_utc` | exists |
| "both judged under rules …" | `compare.rules{before, after, moved}` | exists |
| `same_result` | `compare.same_result` | exists |
| Exit code 3 · incomplete | `compare.complete`; `cli._fleet_diff` exits 3 | exists |
| Counters new / gone / unchanged | sums over `entries[].new`, `.gone`, `.unchanged` | exists |
| Counter "rate moved (flagged) 2 of 4 tested" | — | not implemented: repeated-runs.md 5, 5.1 |
| Counter "not comparable 1 key" | `entries[].change == not_comparable` | exists |
| New/gone table: change, entry × scenario, locator · signal | `entries[].new[].identity`, `.gone[].identity` | exists |
| Class column "absent → stable 0/48 → 48/48" | — | not implemented: repeated-runs.md 5 point 1 |
| "Attributed to: server — content A → B" | `entries[].attribution{attributable, axis, note}`, `entries[].axes.server` | exists |
| `cap_hint` row "may only be missing" | `gone[].cap_hint` (`capped_after`) and caveat `findings_capped` | exists |
| Scenario drift panel: digest before → after, statements added/removed, marks per finding | `axes.scenario`, `caveats` `scenario_drift`, `new[]/gone[].statement_hint` | exists |
| Drift panel: "statements 3 → 3 · one added, one removed" | `runs.statements` of both runs (from `Store.run_info`) | exists (computed from the two statement sets) |
| Drift class column "– → stable" | — | not implemented: repeated-runs.md 5 |
| Rate moved table: before/after rates, intervals, p, BH-adjusted, flag | — | not implemented: repeated-runs.md 5, 5.1 |
| "1 identity undecided in both fleets", `--verbose` | — | not implemented: repeated-runs.md 5 point 3 |
| "What moved, key by key": server / tool / scenario / environment per key | `entries[].moved_axes`, `entries[].axes` | exists |
| Reading per key ("two axes moved: cannot be attributed", `environment_moved`) | `entries[].attribution.note`, `caveats` | exists |
| Environment "target image rebuilt" | `axes.environment.target_image{before, after}` | exists |
| Environment "remote · not observed" | — | not implemented: http-transport.md 4.3 |
| Fleet-wide axes: manifest, tool, environment | `compare.axes` | exists — not drawn in the mockup |
| Store diff of two runs (single basis) | `Store.diff().to_dict()` (see 3.13) | exists |

### 3.13 Store (`extracted/Store.dc.html`)

| What the view shows | Where the code produces it | Status |
|---|---|---|
| Store file, schema | `meta.schema` | exists |
| Tab "Fleet runs": id, started, state, rules | `fleets.fleet`, `.started_utc`, `.rules`; state: `complete` boolean only | partial: the fleet's `state` is not stored (`fleet.json` has it, or it is recomputed from `fleet_results` by `FleetRun.state`'s rule, `fleet.py:214`) |
| Fleet runs: keys | count of `fleet_results` rows | exists |
| Fleet runs: repeat on/off | — | not implemented: repeated-runs.md 0 |
| Fleet runs: comparison digest · full digest | `fleets.digest` (one digest, with causes) | partial: two digests not implemented, repeated-runs.md 2.3 |
| Fleet runs: "— (not all results there)" for an interrupted fleet | an interrupted fleet is filed with a digest like any other (`fleet.py:584`) | not implemented: no design doc proposes it |
| Fleet runs: interrupted `SIGINT` | `fleet.json` `interrupted`; in the store only inside `problems` text | partial: not a store column |
| Tab "Runs": run (sha256 of recording), entry × scenario, provenance, isolation, state, causes, rules | `store runs` → `RunInfo.to_dict()` | exists |
| Runs: isolation `remote` | — | not implemented: http-transport.md 4.1 |
| Tab "Findings": server, server_version, scenario, statement, locator, signal, tool_version | `store findings --provenance P` → keys | exists |
| Findings: sightings count | `sightings` rows per finding (SQL; not in the command's output) | partial: read from the table |
| Tab "Real-world candidates" kept apart | `store findings --provenance real-world` | exists |
| Real-world: class in last fleet, isolation `remote`, "egress not observed" | — | not implemented: repeated-runs.md 3, http-transport.md 4.3 |
| Real-world: "disclosure" status column | — | not implemented: a draft design's triage table came closest (section 2); the export holds a placeholder for it |
| Tab "Diff two runs": new / gone / unchanged, "moved from tools[0] to tools[1], same key" | `Store.diff`: `unchanged[].sightings_before/after` paths | exists |
| Diff: "basis: single run" | — | not implemented: repeated-runs.md 0 (today every diff is single-run) |
| Diff: axes and attribution, exit 3 note | `Diff.axes`, `.attribution`, `.complete` | exists |

### 3.14 TermHttp, TermFleet, TermInterrupt (terminal reference)

Not UI. Their wording is held against the code only where it names commands and codes:
`drive --url`, `--token-env`, `listen --port … --upstream …`, the era probe, sessions,
`Origin` 403 and remote runs (TermHttp) are not implemented (http-transport.md 2.1, 2.4–2.8, 4);
`fleet run --repeat --include-remote`, series progress, `fleet_series`/`fleet_rates`, two
digests, "rate moved" and `--verbose` (TermFleet) are not implemented (repeated-runs.md);
TermInterrupt's Ctrl-C behaviour exists (`fleet.py:452–590`, `cli.py:1101–1113`: exit 130 for
`store ingest`), as does the proxy notice "exit code N is the server's own" (`cli.py:934`) and
the `--step-timeout` refusal text (`cli.py:253`); its fleet table's "digest —" for an
interrupted fleet does not (3.13).

## 4. What the mockups invent

Written 2026-10-27, when none of this was in the code. Built since: `--token-env` (beside
`--token-file`), `--isolation remote` (for an endpoint entry only), `source.endpoint`, transport
`streamable-http` (for an endpoint entry only), `script_finished.era` and `.protocol_version`,
and the era probe (an exchange of role `era_probe`, decided in an `era_decided` event); and a
triage status per finding and role in the store, though not the single disclosure status drawn.
The versions in parentheses below are today's. The rest is still not in the code.

* **Subcommands and flags not in `cli.py`:** `listen` (with `--port`, `--upstream`),
  `drive --url`, `--token-env`, `fleet run --repeat`, `fleet run --include-remote`,
  `fleet diff --verbose`, `--isolation remote`. (`--url` is `--http` here; the rest are
  proposals.)
* **Versions not in the code:** recording schema 4 (this is 5), store schema 9 (this is 13),
  rules v3/v4 (this is 14), tool 0.2.0 (this is 0.1.0.dev0), fleet ids `f-NNNN` (they are
  `YYYYMMDDTHHMMSSZ-<8 hex>`).
* **Signals and causes:** `tool_name_collision` (gone; two signals replace it); a cause list of
  24 without `sandbox_failed_after_target`; the "server can cause" attribute.
* **Event fields not in `events.py`:** `script_finished.era`, `.protocol_version`, `.session`,
  `.reinitialised`, `.steps_sent`, `.script`; `intervention.method`, `.message_seq`,
  `steps[].changed`; `message.body`, top-level `message.redactions`, `message.handles`;
  `authorization.target_declared`; `verdict` output keys `exit`, `rules_version`, `transport`,
  `isolation`, `egress`; `run_finished.http` keys `connections`, `sessions`, `comments`,
  `resumptions`, `403s`.
* **Events not in `events.py`:** `session_started`, `session_ended`, `server_stdout`, an era
  probe, a "canary seen" marker, a target-started or gate step.
* **Store content not in `store.py`:** `fleet_series`, `fleet_rates`, `fleet_results.repetition`,
  a repeat flag, two digests, a fleet state column, an interrupted column, a disclosure status.
* **Corpus content not in `corpus.py`:** `launch.listen`, `launch.path`, `source.endpoint`,
  transport `streamable-http`, a "pinned output" per entry.

## 5. Scope of the interface

Built, and more: the pages of `CONTRACT.md` 6 add triage, review mode, evidence bundles and
attestations, and the run shows what its isolation, TLS, generation and token say (`CONTRACT.md`
7.1 to 7.4).

### 5.1 Pages

1. **Runs** — a list of run directories under the directory given as `--runs` (and the
   recordings a store names), each with its state from `verdict.read`. One run, with tabs:
   *Overview*, *Verdict*, *Messages* and *Findings and observations* are always there — a missing
   tab on a run that is not a result would read as "nothing found"; *Inventory* on every driver
   run; *Interventions*, *HTTP*, *Sandbox* and *stderr* only when the recording has their events:
   * *Overview*: `run_started` (mode, script, scenario, transport, endpoint, isolation, identity,
     reproduction triple, authorization, limits), `server_exited`, `server_name_mismatch`,
     duration.
   * *Verdict*: state, exit code, rules version, each shortfall as cause + words (in-process
     `Verdict.shortfalls`), truncations, server exit.
   * *Messages*: both directions, parse kind, method, id, size, truncated/incomplete, redaction
     count, interventions and quarantine marked; a detail pane with the masked payload and its
     redaction paths, escaped.
   * *Inventory* (driver runs): script steps from `message`, `step_skipped`, `step_unanswered`,
     `step_called`, `call_failed`, `script_finished`; tools, resources, templates, prompts from
     the answers, with observation and finding chips per element.
   * *Findings and observations*: `finding` (key, path, normalized), `observation`,
     `statement_evaluated`, `findings_capped`, `run_finished` counts.
   * *Interventions* (scenario with rules): each `intervention` with its steps, before/after,
     reasons; `rule_quarantined` and every intervention it invalidates.
   * *HTTP* (`transport == streamable-http`): exchanges joined from `http_request`,
     `http_response`, `http_end` and `message.exchange`; `run_finished.http`.
   * *Sandbox* (`isolation == runc`): `sandbox_step` in order with details, `sandbox_failed`,
     confinement, `egress_attempt`, `egress_dns`, `egress_summary`.
   * *stderr*: `server_stderr`.
2. **Corpus** — a manifest through `corpus.load`: entries, provenance, identity, launch,
   scenarios, permitted isolations, refusal; a refused manifest with its place and reason.
3. **Scenarios** — a scenario file through `scenario.load`: rules, statements, digest; a
   refused file with its place and reason; the source text beside it.
4. **Signals** — generated from `signals.LIBRARY`, `inspection.Surface`/`METADATA_SURFACES`,
   `paths.IDENTITY_FIELDS` and the masking constants (1.5, 1.6).
5. **Store** — runs (`RunInfo`), findings per provenance with sighting counts, real-world
   candidates on a page of their own, a diff of two runs (`Store.diff`).
6. **Fleets** — fleet runs with their results per key (one run per key), problems, publishable
   findings and the real-world count; `fleet.compare` between two fleets, entry by entry, with
   axes, attribution, caveats and `cap_hint`.

### 5.2 Gaps marked in the interface as "not recorded by this version"

Shown in place, never filled in: pages per answered listing (counted from messages, said so);
the characters a signal fired on (the field is shown, not a span); the sink's count per egress
destination where it equals the kernel's; a gate or target-started step; the files-delivered
check; the fleet's state and interruption when only the store is open (taken from `fleet.json`
when it is found, said so otherwise); sighting counts are the store's, not a command's; whether a
cause is one the server can bring about.

### 5.3 Left out entirely

Still left out, except what the interface now shows of the HTTP modern era and era detection,
re-issue, isolation `remote` and tokens (`CONTRACT.md` 7.1, 7.4), and a triage status in place
of the disclosure column (`CONTRACT.md` 7.2).

The Series view; classes, rates, intervals, the sequential test, retries, budgets and the two
digests in Main and Compare; HTTP modern era, era detection, sessions beyond ordinals, the GET
stream, resumption, re-issue and the 401/remote mode of Recording; the ingress bridge; remote
endpoints and isolation `remote`; `listen`; tokens; "canary seen"; the disclosure status column;
the "pinned output" of the fixture corpus; the terminal artboards.

## 6. Data sources

* **Run directories** (`output.py:105`, `prepare_run`): `<out-dir>/<YYYYMMDDTHHMMSSZ>-<run id,
  8 hex>/events.jsonl`, directory `0700`, file owner-only. A fleet writes
  `<out-dir>/<fleet id>/fleet.json` (`fleet.py:588`, `FleetRun.to_dict()`) and one directory per
  job, `<out-dir>/<fleet id>/<NNN>-<entry>/<stamp>-<run id>/events.jsonl` (`fleet.py:528`,
  `launch`). Nothing else is written there.
* **Recordings** are read with `verdict.read_events` (depth-bounded, line problems reported) and
  judged with `verdict.read`/`verdict.assess`; a recording of another schema is shown with its
  `schema` cause and nothing else, as the verdict does (`verdict.py:324`). No recording in
  `tests/fixtures/` is of schema 5 (`realistic_handshake.jsonl` is schema 1), so building and
  testing the interface needs recordings made by this version.
* **The store** is opened read-only: `sqlite3.connect("file:<path>?mode=ro", uri=True)`, then
  the schema check, then `Store(connection)`. **`Store.open` must not be used**: it creates a
  missing file and runs `CREATE TABLE IF NOT EXISTS` (`store.py:443–466`). The schema check is
  `store._schema_refusal(connection, path)` (`store.py:938`), which only reads — private today
  (open question 2). All reading methods (`runs`, `run_info`, `findings_of`,
  `findings_by_provenance`, `fleets`, `fleet`, `diff`, `resolve_fleet`) and `fleet.compare` are
  read-only. `runs.recording` is the path given at ingest, possibly relative to where ingest ran;
  a recording found there is held against `runs.run` (SHA-256 of its bytes) before it is shown as
  that run's.
* **Manifests and scenarios** are parsed with `corpus.load` and `scenario.load` — the project's
  own loaders, so a file the tool refuses is refused here with the same words. YAML needs the
  optional extra. `corpus.load` loads every entry's scenarios and hashes the entries' files and
  this package; it starts nothing.
* **Signals, surfaces, identities, masking rules** are generated from the modules at startup,
  never copied by hand.

## 7. The mockup export, and how it was extracted

The export is a single HTML file written by a design canvas's bundler. Its body holds a small
bootstrap script and four JSON islands in `<script type="__bundler/…">` tags:

* `manifest` — `uuid → {mime, compressed, data}`, `data` base64 and, when `compressed`, gzip;
* `ext_resources` — empty here;
* `page_order` — 16 uuids, the artboards in board order;
* `template` — the root page as a JSON string: one `<section class="board"><h2>N · title</h2>
  <iframe src="about:blank#<uuid>">` per artboard.

Each artboard is itself a complete bundler document stored as a manifest entry: its own
bootstrap, its own manifest (three JavaScript assets per artboard: the canvas's `dc-runtime`,
46 KB; React, 11 KB; ReactDOM, 132 KB — identical across boards) and its own `template`, which is
the artboard's `.dc.html` authoring source: `<x-dc>`, `<helmet>`, inline-styled markup,
`{{holes}}`, `<sc-for>`, `<sc-if>` and a `data-dc-script` block with `renderVals()`. The file
names appear only as links in each artboard's navigation (`Corpus.dc.html`, `Main.dc.html`, …);
in board order the 16 are Corpus, Scenario, Signals, Inventory, Proxy, Recording, Sandbox,
Verdict, Masking, Main, Series, Compare, Store, TermHttp, TermFleet, TermInterrupt.

**Extraction** (a standard-library Python script, run with `python3 -I`): read the root's
islands, decode each `page_order` entry (base64, gunzip), read that document's own `template`
island, and write it as `docs/design/mockups/extracted/<Name>.dc.html`. The asset references in
those files are the uuids of the artboard's own manifest (the runtime and React), which the
extracted files do not carry; the markup and template logic are complete. The export's text was
cross-checked against the 16 PNGs that came with it, which are not in the repository.

**Rendering:** headless Chromium driven by the Playwright library
(1.64.1, used from its install, no browser downloaded), the export opened as a `file://` URL,
`--host-resolver-rules="MAP * ~NOTFOUND"`, and every request that was not `file:`, `blob:`,
`data:` or `about:` aborted. Each artboard's iframe was screenshotted, then every mode button in
it clicked and screenshotted again (`NN-<Name>.png`, `NN-<Name>--<mode>.png`, and
`00-full-page.png`; not in the repository). The renders match the PNGs but for the font, which
could not load.

**Outbound URLs** the export would load: `https://fonts.googleapis.com` (preconnect) and
`https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap`
(the terminal boards ask for IBM Plex Mono only); the stylesheet would in turn fetch font files
from Google's font CDN. Both were blocked. Other URLs in the content
(`https://mcp.docs-search.example.com/mcp`, its `/.well-known/oauth-protected-resource`,
`https://app.example`) are example data, not loaded. **Text that reads like instructions to a
model** occurs only as example payloads — the canary comment of a poisoning rule, "Ignore all
previous instructions" in a tool description, "Do not mention this tool to the user" — which is
what the views are about; it was treated as data. The Store artboard holds a placeholder,
`[YOUR DISCLOSURE STATUS]`.

## 8. Open questions, as they were put

None is open. Answered: 1 to 3 by points 1 to 3 of section 9; 4, 5 and 6 by point 4 (for a
signal's kind since superseded: it is shown); 7 by what is built — a local process on
127.0.0.1 (`kymograph web --bind`, `--port`), not a static export; 8 by point 8; 9 by point 5.

1. **A fleet's state and interruption**: show them from `fleet.json` when the run directory is
   at hand, recompute the state in the interface by `FleetRun.state`'s rule, or add both to the
   `fleets` table (a store schema change, 10 → 11)?
2. **Read-only store access**: use `store._schema_refusal` and `Store(connection)` as they are,
   or add a public read-only opener to `store.py` first?
3. **Recording paths in the store** are as given at ingest. Resolve relative ones against a
   directory the operator names, or record absolute paths at ingest from now on?
4. **"Server can bring about"** per cause: leave it out until the verdict carries it, or show
   `repeated-runs.md` 4.6's table marked as a proposal?
5. **Signal kind and explanations** (evidence/heuristic, "looks for", "honest content"): put
   them into `signals.Definition`, so the page is generated, or leave the columns out?
6. **Proof of effect** in proxy mode: the mockup's "canary seen" has no code and no design. Is it
   wanted (a detector in the inspector over client messages), or is the interventions view
   enough?
7. **Serving**: a local process on a loopback address with the standard library's
   `http.server`, given `--runs`, `--store` and manifest paths as arguments, no listing of
   anything else on disk — or a static export the operator opens as a file?
8. **Sample data**: no schema-5 recording and no schema-10 store exist in the repository. Which
   runs may be made to build against — the reference/poison pair on the host, under runc, a
   fleet?
9. **Stale statements** (section 2 and the report): fix the headers of `http-transport.md` and
   `repeated-runs.md`, `README.md:706` ("schema 4"), the `CHANGELOG.md` versions and its missing
   entries, and the comment at `masking.py:958`, in a change of their own before the interface?

## 9. Decisions (2026-10-27)

The answers to section 8, binding for the implementation, and the order of
`src/mcp_kymograph/web/CONTRACT.md`.

1. **A fleet's state and interruption** are read from the fleet's `fleet.json` under `--runs`
   when it is there; otherwise the interface says "not recorded in the store". A fleet's state is
   never derived from its results: that would be a judgement the store did not make.
2. **The store is read through `Store.open_read_only`**, a public function of its own: SQLite's
   `mode=ro`, so the file can be neither created nor changed, and the schema refusal `open`
   applies — a store of another schema is refused whole, never read in part.
3. **Recording paths in the store** are resolved against `--runs` only, and the file found there
   is held against `runs.run` (SHA-256). Two states stay apart: **recording not found** (no file
   under `--runs`) and **recording changed** (a file, but not the bytes the store filed). The
   second is the graver statement and never folds into the first.
4. **Not implemented means not in the interface** — "server can bring about", a signal's kind
   and explanations, and "canary seen": proof of effect is a derivation across messages that
   neither code nor design defines. The Interventions tab shows the `intervention` events; what
   follows from them is the reader's. All of it stays in this document. *Superseded for a
   signal's kind:* `signals.py` marks each signal's kind, and the signal page shows it
   (`CONTRACT.md` 6, 7.1, 9). The rest of this point stands.
5. **Stale statements** were corrected first, in a commit of their own: docs and one comment;
   in the two design documents only the status line of the header.
6. **The sixteen extracted artboards are in the repository** (`docs/design/mockups/extracted/`,
   with a README); the bundled export and the screenshots are not.
7. **Tests**: quick rounds on the host; the proof before the interface is called done is the
   full suite with `MCP_KYMOGRAPH_REQUIRE_DOCKER=1`, so no Docker test can be skipped silently.
8. **Sample data**: tests make their own recordings; nothing is committed as sample data. The
   demonstration includes at least one run that is not a result (`server_failed`, or
   `incomplete` with cause `interrupted`), and shows that it is not "no findings".
9. **Tabs** as in 5.1: Overview, Verdict and Findings always present.
