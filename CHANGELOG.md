# Changelog

## 0.2.0a1

The tool is renamed. Version 0.1.0 was published as mcp-polygraph; from this version on it is
Kymograph, and the package is `mcp-kymograph`. No earlier name is kept as an alias, which is
why the minor version moves. The version is an alpha: formats, commands and their output may
still change in any later version.

What has another name:

| | 0.1.0 | 0.2.0a1 |
|---|---|---|
| Distribution | `mcp-polygraph` | `mcp-kymograph` |
| Import package | `mcp_polygraph` | `mcp_kymograph` |
| Command | `mcp-polygraph` | `kymograph`, and `mcp-kymograph` as a second name for it |
| Prefix of terminal output | `mcp-polygraph:` | `kymograph:` |
| Environment variables of the test suite | `MCP_POLYGRAPH_*` | `MCP_KYMOGRAPH_*` |
| Docker images and label keys | `mcp-polygraph-sandbox:1`, `mcp-polygraph.run` | `mcp-kymograph-sandbox:1`, `mcp-kymograph.run` |
| `clientInfo.name` of a driven run | `mcp-polygraph` | `mcp-kymograph` |
| Cookie of the web interface | `polygraph-<port>` | `kymograph-<port>` |

Every other identifier that held the name changed in the same way. Among them are the marker
of the built-in `tool-poisoning` scenario (`MCP-KYMOGRAPH-CANARY`), the `Server` header of the
web interface and the version key in a benchmark run's companion file
(`mcp_kymograph_version`).

Docker images built for 0.1.0 must be tagged or built again under the new names. The benchmark
runner refuses an image that carries the earlier label keys.

Data written by 0.1.0 stays readable:

- A recording is read as before. It is identified by its schema numbers, not by a name.
- A handover page made now has page version 2. `evidence verify` still checks a version 1 page
  against its own words.
- A new canary value starts with `kymograph-canary-`. `engagement marking --engagement` still
  finds a canary planted under the earlier prefix. `engagement canary` prints the value with
  the new prefix; the 16 characters after it are the same.
- The benchmark runner's `compare` still reads runs made before.

Also new:

- The README is short. The text of the earlier README is now `docs/reference.md`.
- `examples/unmarked-result/` holds a small server and the files for one driven run.
- A workflow runs lint and the tests without Docker on Python 3.12 and 3.13.

The entries below are as they were published. They use the names of their time.

## 0.1.0

The first public version. mcp-polygraph is pre-alpha: formats, commands and their output may
still change in any later version. What it does today:

- **Records** the traffic between an MCP client and an MCP server, as a stdio proxy that a client
  starts in the server's place (`run`) or as the client itself, speaking a fixed script or a
  script file (`drive`), over stdio or Streamable HTTP (TLS verified; plain HTTP to `127.0.0.1`
  and `[::1]` only), in both protocol generations (2024-11-05 to 2025-11-25, and 2026-07-28).
  Credentials, tokens and personal-data shapes are masked as each event is written.
- **Reads** what the server sends with 17 named signals and with the statements of scenario
  files, which turn hits into findings keyed by a locator; scenario rules inject, replace or drop
  messages over stdio. Every run has one state, read back from its recording (`verdict`).
- **Compares**: corpus manifests pin servers by their content, a finding store (SQLite) files and
  compares corpus runs axis by axis, and a fleet runs a corpus of reference and poison entries in a
  runc sandbox that records every attempt to reach the network.
- **Works under an engagement**: an engagement file narrows the gate to what was agreed, and
  HTTP runs to other hosts are paced. Commands cover intake, preflight, status, triage, re-check,
  the report, evidence bundles (pack, verify, redact, replay), the attestation, the purge and the
  dossier, with tokens per identity, a token inspector, identity comparison, content-marking
  canaries and a callback receiver.
- **Shows** recordings, the store, fleets and evidence in a read-only web interface on
  `127.0.0.1`.
- Runs on Linux with Python 3.12 or later and the standard library (PyYAML optional, for YAML
  files). What it does not do is listed in the README, "What this tool does not do".

## Before 0.1.0

How the tool came to its state at 0.1.0, by topic, the newest at the top. Each entry describes
the state at the time it was written; a later entry can change or take back what an earlier one
says.

### The web interface: a new look

- **The navigation is a rail on the left** (a bar on top below 860 px) with the package, its
  version and "local read-only viewer" at its foot; the work area beside it is light, with one
  accent colour. Review mode keeps a slim bar without the navigation.
- **Tables** have sentence-case headers under one dark rule; a cell is never narrower than ten
  characters, and a table that does not fit scrolls sideways within itself.
- **A run that is not a result** shows a panel framed in its state's colour, the causes as rows
  under it. The state chips keep their colour meaning; `server_failed` is a solid red.
- **Long values stay in their box**: a tag with a sentence or a long name wraps, and recorded
  text breaks anywhere. The inventory, bundle and attestation pages no longer scroll sideways as
  a whole.
- Apart from the two points below, nothing the page shows or builds has changed: the change is
  the stylesheet.
- **The findings tab of a run that evaluated statements** shows statements against messages as
  one table of traces: a dotted line where no reading of a statement on a message is recorded
  (it did not apply, the message was not inspected, or the record was not written), a solid
  line where it read and nothing fired, a dashed line where it was evaluated with a reason, a
  spike with the count where it fired, each with its words for a reader who does not see the
  line. A row that fired is framed; a truncated or incomplete message is marked in its column
  and named under the table. Beside each row: the classes of its findings and whether an
  observation of the built-in walk is recorded beside them ("no observation recorded" is not
  "the walk saw nothing", and the page says why). An observation without a finding of the same
  message, path and signal is a row of its own kind, a dot at its message; that is not "no
  statement fired there", and the page says so. Selecting a row (the address names it, `st` or
  `obs`) shows beside the strip what the statement checked on each message, what fired, its
  count in `run_finished` and each finding with its key. A run with at most 12 messages shows
  all of them as columns, a longer one the first 12 that an event of the tab names, and says
  so. Every event is still on the page as the tables the tab drew before, behind one toggle
  under the strip; a run that evaluated no statement shows the tables alone, as before.
- **The run list** has one column "Server × scenario" and one for mode, transport and isolation,
  and it and the store's list keep a run's name, its start and the pair on one line where there
  is room.

### Masking: what still reached a recording or a handover

- **The `check` of a call step** is masked as text when `step_called` is written, like a string of
  the call's arguments: a known value or a credential quoted in a script's check no longer reaches
  the recording. `evidence pack` masks the script's check the same way, so the placed check is
  exactly what the recording holds and is kept.
- **A JSON number that holds a known value in part** (`94111222233334444` with the known value
  `4111222233334444`, `91234` with `1234`) is masked as its quoted text would be and written as a
  string (`9***KNOWN-…***`), the text `evidence pack` already made of such a number in a placed
  script. Before, only a number that was a known value whole was replaced, and the digits stayed in
  the recording. A short known value now also turns ids and times of the traffic that hold its
  digits into strings.
- **`evidence redact` holds every recording to the check it holds a placed script to.** A
  recording that still holds a known value of the engagement, a credential of the engagement file
  or the salt refuses the handover (exit 2), naming the recording, the run, the event and the
  place, never the value. Before, redact applied only `mask_patterns` and `mask_keys` to a
  recording and looked at nothing else. The masker's own stand-ins, the tool's numbers, the run's
  id and what the tool writes into `run_started` from its clock, its version and the platform,
  with the engagement's window, are not looked at, nor are the counts of the kernel, the sink,
  the inspection and the signals (how many packets, how often a method was looked at or a
  signal fired, how many findings a cap cut: `TALLY_PATHS`, `STEP_TALLY_PATHS`), which a
  target can steer but does not write. A target that knows a short value of digits can make a count of it (that many
  packets), and the handover then holds these digits as a count. A string of the form of a
  digest (64
  hex digits) is refused only where it is a value whole. A key is named in the place only where
  the masker would leave it as it is. Everything else is looked at, also a name or a path the
  operator gave the run. A bundle with a script is refused, as before, where a credential or
  the salt cannot be read; a bundle of recordings only is redacted with a warning that names
  what could not be read, and is checked for the rest. A recording made before the rule for
  numbers above may hold such a number and is refused.
- **A JSON key is masked as a value is.** A key that holds a credential (`sk-…`,
  `password=hunter2…`) lost the value under it and was written in the clear, in the message and in
  every recorded path below it. Every key now goes through the text rules, the pair rule included
  (but for the names of HTTP headers and query parameters, which go through the shapes alone),
  and the masked key stands in the result and in every path under it; a key with a hit is one
  path, however many hits it and its value have. Two keys that read the same once masked are both
  kept, the later ones as `KEY#2`, `KEY#3`, …. A protocol handle is still matched on the keys as
  received. The recorder finds a value placed under a masked key (a rule change at
  `result.<key>.items[3]`) and records the path with the real list position and the masked key.
  The script name in `run_started.script` is masked the same way.
- **`--password -hunter2`**: after a secret flag without `=`, the next argument of the server's
  command line is replaced whatever it is, one that starts with `-` included; only `--` stays.
  If that argument is itself a secret flag (`--token --api-key X`), the one after it goes too.
- **NFKC spellings, `\u` and `\x` escapes and invisible characters no longer walk past the
  rules.** A key name is read with `\uXXXX` and `\xXX` as characters (one round; a surrogate pair
  as its one character), NFKC applied and invisible characters removed (in a key after NFKC, in
  a text before it):
  those the signals drop (zero-width characters, joiners, bidirectional overrides and isolates,
  the tag block), and the bidirectional marks (U+200E, U+200F, U+061C), the combining grapheme
  joiner, the invisible operators, the Hangul fillers, the variation selectors and the
  deprecated, annotation and musical format characters (the list is `MORE_INVISIBLE` and
  `INVISIBLE_RANGES` in `masking.py`; Unicode has more). So `ａpi_key`, `api\u200bkey` and
  `\u0074oken` are secret keys (a number that is no digit, `²`, is dropped from a name rather
  than read as `2`). A text that holds anything this reading could change (not plain ASCII
  without `\u` or `\x`) is masked a second time in that form, known values and the pair rule
  included, and the two results are compared: where they differ (`Ｂearer <token>`,
  `Bea<U+200B>rer`, `\x20sk-…`, the rest of a token behind an invisible character, a known value
  `Max Mustermann` written with a no-break space), the whole value is replaced and counted once
  more. That also takes a value whose own masking had hidden as much but ends elsewhere in the
  copy, a value whose copy is longer than twice the text plus 1024 characters, and a value in
  which a known value or a credential of the run shows once `%XX` is decoded and the result
  normalised (`Max%C2%A0Mustermann`). Where the two are the same
  (a URL whose `@` is written `\u0040`), the text's result stands. Plain ASCII text without a
  backslash-`u` or -`x` is not masked a second time. Not read: other escape forms (`\U…`,
  `&#x…;`, `%u…`), a `%XX` or an escape that only a second decoding shows, letters of another
  script that look the same, upper and lower case of a known value, and a known value whose
  space is written as a tab, a line break or two spaces or whose hyphen is another dash.
- **A known value is also found in its composed form (NFC) and in its NFKC form**: one listed
  with a decomposed accent and sent composed, or listed with a no-break space, a ligature or in
  full width and sent plain, is replaced, with the pseudonym of the value as listed. The NFKC
  form is left out where it is shorter than four characters without the white space around it,
  or where the listed value holds a number that is no digit (a value listed in circled digits
  does not make `1234` a value).
- **What a sandboxed server chooses of its egress goes through the masker**: the address and the
  port of an `egress_attempt` and the query type of an `egress_dns`. The kernel and the sink
  record them, but the server chooses them: an address that is a known value is written as its
  pseudonym, and a port or a query type whose digits hold one as a string, like a number in an
  answer. Before, they were written as they were. The sentences in which the tool says where
  its account of the egress does not add up (`problems`) are masked as text, since they name
  such counts and addresses.

### A server's identity covers only what was named, and a corpus run starts what was hashed

- **A symbolic link in any component of a named server path is refused**, not followed.
  `--server-content link/server.py` and a manifest's `source.paths: [link/server.py]`, with
  `link` pointing to a directory elsewhere, used to hash the file behind the link, and a corpus
  run in the sandbox would have been handed it; only the last component of a path was checked.
  The refusal names the path up to the link, and the file by its name. The components checked
  are those of the path as it was named: a relative path from the working directory, an
  absolute path from the root, a manifest's paths from the manifest's directory. What lies
  above that is not part of the
  server, so a manifest reached through a linked directory keeps its identity. `..` is not
  resolved first: one that leads through a link is refused at the link. An absolute path below a
  linked system directory (`/tmp` on some systems) is refused the same way; name the directory
  it points to.
- **A corpus run on the host starts the server in the manifest's directory**, the one its
  `source.paths` were resolved and hashed against. With `command: ["{python}", "server.py"]`,
  `drive --manifest` called from another directory that held a `server.py` of its own ran that
  file, and the recording carried the identity of the manifest's. Now a relative path in the
  command is resolved in the directory the entry's files were hashed in. The recording gets no
  new field: where the manifest lies is in `run_started` as before, in the path the manifest
  was given by and in the full path of its scenario.
  `drive -- <command>` without a manifest starts in the caller's working directory and records
  what it did before. A working directory that cannot be entered is recorded as that
  (`server_failed`, "the working directory could not be entered"), not as a missing command.
  Where the caller's environment has a `PWD`, the server's names the directory it starts in.
  - What this changes for a manifest in use: a command written to be called from somewhere
    else no longer finds its files. A relative path in it is written with `{dir}` or relative
    to the manifest; `["{python}", "-m", "pkg"]`, meant for a repository's root, needs the
    manifest there. A relative program (`./server`) now starts where it did not. `evidence
    replay` of a host corpus run starts in the manifest's directory too.
  - Host and sandbox still differ where the manifest's directory is not inside the files it
    names (it lies above them, or beside them): the sandbox's copy begins at the files' common
    directory and starts there, and a command that writes `{dir}` is refused in it, because
    the manifest's directory is not part of the copy.
- **What a host run does not promise.** The identity covers the files `source.paths` names and
  nothing else. On the host, a file the command names that is not among them, a module the
  server imports from beside them, and a compiled file left in a `__pycache__` run without
  being part of the identity, and the files are not hashed again before the start. In the
  sandbox only the hashed copy exists, and it is hashed again before it runs.
- **A refused `source.paths` entry is named relative to the manifest.** The reason of the
  refusal (a link, nothing there, a link inside a directory) no longer holds the full path of
  the manifest's directory on the operator's machine.

### A bundle to repeat a run: scripts, image ids, `evidence replay` (docs/engagements.md)

- **`evidence pack --script FILE`** (repeatable) puts the script of a driven run into the bundle
  under the role `script`, matched to its runs by `script_digest`. A file matching no run refuses
  the pack. The script is placed with the customer's values replaced, and only that result is in
  the bundle, as JSON. It is masked in two layers:
  - **First with what `drive` masked.** Each call step is aligned with the calls its runs
    recorded. Wherever a run's recording holds any masked form, the script keeps that key or
    value (the tool's name, the `check` and the script's name alike) only if it is exactly what
    the recording holds, and blanks it whole otherwise, even where pack masked part of it, so a
    token rotated or an identity removed since the run stays out. A call step no run sent has
    its arguments and its tool's name blanked and makes the script not replayable
    (`steps[N].call: sent in no run`). Recorded calls that do not match the script refuse the
    pack.
  - **Then with the engagement's masking as it can be read now:** secret keys, secret header
    names and the mask keys (the engagement's and every `--mask-key` its runs recorded) lose
    their values; every identity's token and secret header values and the salt are blanked;
    known values, e-mail addresses, IBANs and `tel:` URIs become pseudonyms; the literal
    `mask_patterns` are blanked; in strings, keys and numbers alike (a number whose text holds a
    known value is masked as its quoted text would be: `47110815` → `***KNOWN-…***0815`). A
    number is held to the known values as its JSON text, as the loader read it: quote values
    like `0042` in a script.

  Pack holds the result to `redact`'s check and refuses a script in which it would still find
  something. The entry says whose pseudonyms it holds and whether it still loads (`replayable`,
  naming the place, never a value). A credential of the engagement file that cannot be read, a
  salt variable that is not set, and a run whose token came from a flag (the tool cannot know
  that value) refuse the pack.
- **`evidence redact`** checks every placed script once more, against a script changed after the
  pack: it refuses one that still holds a credential, the salt or a known value, or whose runs
  used a token given by a flag, and it refuses when a credential cannot be read or the salt
  variable is not set.
- **Images by id in the index.** Each recording entry of the index names the target and sandbox
  image of its run by image id only (`sha256:` and 64 hex digits, or the 64 digits alone), `null`
  where the run has none. A recording whose `run_started.reproduction` names an image any other
  way (a tag, a registry path) refuses the pack, and an index that does is refused when read
  (verify, redact, replay); replay refuses such a `reproduction` as well. The recording of a
  container run holds, in its `sandbox_step` `images`, the reference as the operator gave it (tag
  or registry path) beside the id, and keeps it in a handover. No bundle, packed or redacted,
  carries an image's content; whoever needs the image gets it from the operator.
- **`evidence replay BUNDLE --run RUN --engagement FILE --out-dir DIR [--manifest PATH]
  [--index-digest HEX]`**
  repeats a run through the normal gate, from the bundle's script copy and the options the run
  recorded unmasked, an endpoint's `--server-revision` among them. The engagement file and the
  manifest are always the reviewer's own. A run that cannot be repeated as recorded is refused
  with exit 2, naming the field and never its value: no script, passive, not replayable, another
  engagement, anything recorded only masked or withheld (any masked form, in
  `inputs.mask_keys[N]`, `auth.identity`, `authorization.declared_target`, the endpoint's host
  or path, and the scenario's and entry's name), a server identity from
  `--server-content`, a container run whose image was not resolved, an endpoint path as long as
  the recorder cuts one, or a recorded field of another shape. A value the bundle holds only as a
  pseudonym goes out as that pseudonym.
  The bundle is verified against its own index first; that does not show the index is the one
  handed over. `--index-digest HEX`, as for verify, is checked while the bundle is verified,
  before the run, the engagement file or the script is read, and refuses another index (exit 2).
- A bundle packed before these fields existed is read and verified as before.

### Definitions in view: what a server offers, compared between runs (docs/definitions.md)

- **A digest per definition.** `store ingest` keeps, for every tool, prompt, resource and
  resource template in a run's `*/list` answers (all pages), a SHA-256 over the definition's
  canonical JSON as the recording holds it (masked), and one per top-level field. The order of a
  list decides nothing. A key listed twice keeps both digests and is marked as a duplicate.
  A lone surrogate in a name is stored as U+FFFD (the digest stays over the name as recorded), so
  such a run is filed, not refused. Nothing new is written to the recording.
- **Listings are complete or partial.** A listing is one `*/list` request with its cursor chain.
  It is complete when it ended with a page that offers no `nextCursor` and no reason was noted;
  otherwise it is partial, with its reasons: a page cut, unreadable or answered with a JSON-RPC
  error, a page unanswered or beyond the page limit, a `nextCursor` never followed, a listing
  begun by a request for a later page (`no_first_page`), or a request whose method cannot be read
  while the listing was open or before it, with no request for a first page of its kind in
  between (`unreadable_request`). A name missing from a partial listing is never called removed,
  and a name the partial side lacks is never called added.
- **`list_changed`** notifications are counted per kind with the sequence number of the first,
  and split the run's listings into segments: `list_changed, re-listed` when a listing began
  after the last one, else `list_changed, not re-listed`.
- **`store diff`** compares the definitions of two runs of the same corpus entry, per kind:
  `added`, `removed`, `changed` with the names of the changed top-level fields (e.g.
  `description`, `inputSchema`), unchanged as a number, and within a run segment against
  segment. A name listed more than once is a hint (`duplicates`, with the count per side), not a
  change. No value of a definition is printed, on the terminal or in the JSON. It is an
  observation, not a finding. A run filed before the tables existed is **not captured**, never
  "unchanged". `store ingest` says per run how many definitions it listed.
- **Store schema 13 holds two more tables**, `definition_runs` and `definitions`, created when a
  store of schema 13 is opened for writing; the schema number does not move. A definition table
  of another shape, from an earlier state of schema 13, is refused with a `StoreError`.

### What a report does not cover, and the banned words

- **The coverage statement.** The report's section 7 opens, and the attestation holds under
  "What this engagement did not do or observe", one derived sentence per thing the engagement did
  not do or did not observe, each present only when its recorded fact holds: the runs called no
  tool (every version of the file declares `actions.call: false`, every recording read, no
  `step_called`, no tool in `script_finished.called`); how a client reacts was not observed (the
  report always — `engagement report` takes no `--session`; the attestation when the bundle's
  index lists no recording with `filed: false`); egress not observed, by isolation and count; the
  server not run by this tool (isolation `remote`); and last the README's rule that an
  observation is where something sat and what shape it had, not whether it has an effect. The
  section's earlier sentences stand under the heading "What a finding says".
- **Each finding names its reference page** in the report: `reference/<signal id>.md` in the
  bundle, a page about the pattern, not about the server (none for a signal the version does not
  know).
- **The banned words are a list and a test**: `report.BANNED_WORDS` (safe, secure, security,
  vulnerable, vulnerability, exploit, risk, clean, compliant, certified, guaranteed — whole
  words, no stems). A test reads every generated document's own words (code spans are data) and
  the generators' source; a code span the source spells out holds a placeholder or an identifier
  of `report.CODE_SPAN_IDENTIFIERS`, never prose.

### The signal reference

- **One reference page per signal**, all 17 of `signals.Signal`, as package data
  (`mcp_polygraph/data/signals/<id>.md`, in the wheel), with `docs/signals/README.md` pointing
  there. Every page has the same five headings in the same order: what the pattern is; why a
  model may read it as instruction; how it looks in honest content; one invented before/after
  example, marked as invented; what the tool does not know (always including whether the
  consuming client reacts). The line under the title gives the signal's kind (evidence or
  heuristic, `signals.KINDS`) and where it is applied. A page describes a pattern, never a
  server: no judgement, no severity, no finding class. `signals.reference(signal)` and
  `signals.reference_pages()` read them from the installed package.
- **A bundle carries the pages of the signals it reports.** `evidence pack` copies the page of
  every signal the bundle's store copy has findings for, and of no other signal, to
  `reference/<id>.md` under the new index role `reference` (additive: an index without it reads
  and verifies as before; `INDEX_VERSION` stays 1). `evidence redact` carries the pages into
  the handover bundle and checks them like every file it copies: a mask pattern found in a page
  refuses the redaction. `Packed.counts` and `Redacted.counts` name the new role.
- **A page the installed package cannot read refuses `evidence pack` whole**, whichever signals
  the findings name: the installation is damaged, and a damaged tool packs no evidence. The
  refusal names the page's signal id, says the installation is incomplete and that nothing was
  packed; `out` is not created.
- **A stop of era detection has a reason of `eras.STOP_REASONS`**, the list the report names
  each stop from; a `Detection` with another reason fails where it is made.
- **`signals list`** prints every signal with its kind and page path (JSON);
  **`signals list --reference`** prints the pages themselves (Markdown), in the library's order.

### The operator's notes, and wording a customer reads

- **The private rating file is the operator's notes**, `operator-notes`: beside the store and
  named after it (`<store>.operator-notes.yaml`, `.yml` or `.json`), module
  `mcp_polygraph.operator_notes` (was `mcp_polygraph.rating`; `OperatorNotesError`,
  `FindingNotes`, `OperatorNotes`, `beside`). Format unchanged; store schema stays 13. **The
  tool never reads them** — no report, attestation, status, bundle, export or web view — and a
  test holds every module to that. The refusals of
  `store triage set --rationale` / `--severity` and the notices of `store triage export` /
  `import` say "the operator's private notes".
- **`engagement purge` deletes the notes** with the store, by name and without opening them;
  `purged.json` lists them as kind `operator_notes` (`deleted`, or `missing` where there were
  none). Notes under the name that are a symbolic link or not a file refuse the purge whole,
  nothing deleted.
- **No generated sentence uses a banned word**, not even quoted to deny it: the report's section
  7 says a finding "is not a judgement of the server"; `CUSTOMER-README.md` speaks of "one
  engagement" and of "not a judgement of the server".
- **`CUSTOMER-README.md` has a page version.** A handover bundle's `index.json` carries
  `page_version` (1), and `evidence verify` rebuilds the page in the wording it names, so a later
  change of wording never fails a handover made before it. An index naming a version this tool
  does not know is refused whole; so is a handover index without one (made before this change:
  make the handover again from its source bundle with `evidence redact`). A bundle packed from a
  store carries none, and a README beside it is not the bundle's.

### Pacing is enforced: one run per origin at a time, an interval, a `Retry-After` waited out once

- **Every HTTP run to a host that is not a loopback literal is paced**, endpoint entry or `drive
  --http`, with a file or without one. The values are the file's `pacing` (`runs_per_origin`,
  `min_interval_seconds`), and where it is silent or there is none, 1 and 10. They hold per origin
  across identities and across processes that share an `--out-dir`. A run to `127.0.0.1` or
  `[::1]` is not paced.
- **A wait is recorded, or the run is refused.** A run that waited records `paced` (`seconds`,
  `why`). A wait longer than `--step-timeout` is refused: exit 2, reason `pacing`, no run
  directory. `run_started.pacing` holds the values and their `source`, and `pacing_enforced` is
  `true`; a run that is not paced has both `null`. A recording of an earlier version that says
  `false` means declared, not enforced by the version that made it.
- **A `429` or `503` with a `Retry-After` in seconds** is waited out once per request, when the wait
  fits the step. A second one, or a wait that does not fit, is the cause `rate_limited`, rules
  version 13, and so is a `429` without the header or with a date in it. A `503` without seconds
  in the header is not waited for and stays `http_status`.
- **The report and the web interface show it.** The report says per run what it was held to and
  its waits, by reason, with their number and sum; where no pacing is declared it names the
  defaults. The web interface shows the values with their source and every `paced` event as
  recorded, with no sum and no judgement.

### The web interface: a start token, `127.0.0.1` only, hostile strings as text in every view

- **`web --bind` takes `127.0.0.1` only.** `::1`, `127.0.0.2`, `localhost`, `0.0.0.0` and every
  name are refused at argument time, exit 2. The `Host` it answers to is `127.0.0.1` or
  `localhost` with the bound port.
- **A start token and a session.** At start the server draws two random values. The token is in the
  start address, which the start line prints, and nowhere else. Opening that address answers with a
  redirect to `/` and sets the cookie `polygraph-<port>` (`HttpOnly`, `SameSite=Strict`, no expiry,
  no `Domain`). Every other request needs that cookie, and is refused with the same words whatever
  is wrong with it. The checks run in the order Host (421), method (405), Origin (403), session
  (403), then the address. A restart draws new values. `docs/web.md` says to open customer data
  only on a machine with one user, and why.
- **Hostile strings through every view.** A server whose names, descriptions, errors and resources
  carry markup and control, bidi and zero-width characters is driven through every view, fleets
  among them, and `app.js` passes a static check of what it may do with a value. `setState` is the
  one place besides `h()` that sets a state attribute, and values outside text are shown as
  tokens. JSON blocks show a control character as a token, not as `\u0007`. The page has its own
  icon, so no request for one fails, and download links no longer carry a `download` attribute,
  which the page's own rules do not allow; the server sends `attachment`.
- **What the views now show besides.** A store's engagement shows what its file declared, the diff
  of two runs shows `announced_server`, and the fleet list opens to each fleet's problems instead
  of giving their number alone.
- **The page in a real browser.** `tests/test_web_headless.py` runs headless Chromium in a
  container with no network and a read-only root, visits every page and mode, fails on any request
  to another origin and on any console error or policy violation, and compares the finished DOM
  with what the page's code may make: every text node, every `href` and `src`, and every hostile
  value as text at a named place. `data-ready` on `<main>` carries the render counter for it.

### TLS to an endpoint on another host (docs/design/http-transport.md, section 8)

- **`https://` is spoken**, by `drive --http` and by endpoint entries, through
  `ssl.create_default_context()`: the machine's trust store as OpenSSL finds it, the host name
  checked, a certificate required. Nothing about it is configurable — no CA flag, no verification
  toggle, no client certificate — and no `HTTPS_PROXY` is read. Plain `http://` stays to
  `127.0.0.1` or `[::1]` only, and its refusal now names the fix: "Use https:// or a loopback
  address."
- **What a run records**, recording schema still 5: per exchange, `http_request.tls` — the
  negotiated protocol version and the SHA-256 of the leaf certificate as presented; per run,
  `run_finished.http.tls`, the set of both, on the path that drops nothing;
  `run_started.trust_store_env`, whether `SSL_CERT_FILE` and `SSL_CERT_DIR` were set, never their
  values.
- **A failed handshake is the cause `tls`** (rules version 11): once the TCP connection is up,
  every way the handshake does not complete — a certificate refused, the connection reset or
  closed, no answer in the step's time — with the library's text (or ours), masked, in `detail`:
  `server_failed` on the first exchange, `step_unanswered` (which gains `detail`) and
  `incomplete` later. A connection that cannot be made stays `http_unreachable`. The terminal
  prints the text through `display`.
- **Store schema 12**: `runs.endpoint_certificates`, shown in `store runs` and both runs of
  `store diff`. The certificates are not an axis: `store diff` adds the caveat
  `certificate_changed` to new and gone when two runs each presented certificates and their sets
  share none — a rotated certificate is not a changed server; a run whose handshake never
  completed presented none and adds nothing — beside `server_unpinned`, with the axes and the
  attribution as they would be without it. A store of 11 is refused whole, and its refusal says
  how its triage is carried.
- **`store triage export --store S --out FILE` and `store triage import --store S FILE`** carry
  the rows a person wrote across the schema step. The export reads, of a store of exactly the
  previous schema or this one, the triage and the engagement's `meta` rows, and beside them only
  the schema row and the list of tables: the one exception to "refused whole". It writes them
  once, `0600`, and reads them back. The import puts them into a store of 12 made from the same
  recordings that holds no triage row yet, with their authors, roles and times, all or nothing,
  and records the import in `meta` (`triage_imports`). The export names the SHA-256 of the store
  it read (`store_sha256`, taken inside its read transaction); every triage row read back has
  `imported` — `null`, or the export's and the store's SHA-256, the store's schema and the time
  of the import — and says so in `store triage list` (with and without `--history`), in the web
  interface's Triage view and review mode ("imported from store …"), and in the report's assessed
  sentences ("(imported from store …)"). A store whose `triage_imports` row cannot be read is
  refused by each of them: no row is shown as written there when its origin cannot be told.
- **An endpoint target that names no port is read as 443**, the port of `https`, where it was 80;
  `engagement show` says "443 (default for https; not in the file)". The default is read for a URL
  only: a `--target` is held to the ports the file lists, so the move lets no declared target
  through that was refused before.
- **`engagement intake`** names a plain-`http://` URL to another host among what is missing: a run
  to it would be refused.
- **The report** gives each `https` run's versions and certificates (section 2) and the caveat
  beside the attribution (section 5) and in `engagement recheck`; preflight's endpoints item says
  again "not contacted; whether it answers is found out by the first run".
- **The web interface** shows the scheme, the run's TLS versions and certificates ("as
  presented, not checked here"), which trust-store variables were set, each request's TLS in the
  HTTP tab, a `tls` failure's text, the store's certificates and the caveat (`src/mcp_polygraph/web/CONTRACT.md`, section 7.3).
- **Tests** speak TLS on loopback only: a test CA and leaves under `tests/fixtures/tls/` (test-only
  keys, the CAs' keys not kept), trusted through `SSL_CERT_FILE`; the gate's cases R had to turn
  into plain-HTTP refusals hold again over `https://`, against a leaf for `127.0.0.2`.

### Plain HTTP only to a loopback address

- **`drive --http` and endpoint entries speak plain `http://` only to `127.0.0.1` or `[::1]`.**
  Any other host — a name, `localhost` included, or any other address — is refused, exit 2,
  before the gate and before anything connects, with words that name the rule and the fix; under
  an engagement file the refusal goes to `refusals.jsonl` with the new reason `plain_http`. No
  flag opens it, `--engagement-confirmed` included. From another host, a recording made over
  plain HTTP is evidence of what arrived, not of what the server sent, and the answers cross the
  network readable. Until TLS (above), no endpoint on another host could be driven; `corpus
  check` still reads such an entry.
- **Loopback has one definition**, `authorization.LOOPBACK_LITERALS` (`127.0.0.1`, `::1`,
  `[::1]`), compared as strings, nothing resolved; the gate's `LOCAL_TARGETS` is it plus
  `localhost`, the same four strings as before.
- **`web --bind` takes `127.0.0.1` or `::1` only, exactly as written**, as docs/web.md already
  said; another address of 127.0.0.0/8, or another spelling of `::1` (`0:0::1`), is refused at
  argument time, exit 2. The `Host` names the server answers to are derived from the same
  definition and are the ones they were.
- **The benchmark runner's driver** joins the server container's network namespace and drives
  `http://127.0.0.1:<port><path>`; it no longer passes `--engagement-confirmed`, which the runner
  now passes nowhere.

### The customer workflow: intake to purge

The steps around the runs, each a command, in the order of an engagement; docs/engagements.md
walks through them.

- **`engagement intake`** writes the questionnaire a customer fills in (YAML with comments, or a
  plain text form with `--text`, read leniently: what it cannot place is kept verbatim under
  `declared.notes`), and with `--from ANSWERS --id ID` a draft engagement file: the answers
  under `declared`, unchanged; every field they cannot fill a bracketed placeholder, listed on
  stderr. The gate refuses a draft until every placeholder is filled in.
- **Triage statuses for the review and the re-check**: `question` (both roles), `intentional`
  (the customer's: "this description is deliberate"), `fixed` (the operator's, after a re-check).
  `store findings` gives each finding's id for `store triage set --finding`.
- **`engagement recheck`** prints the exact commands that make a re-check run, and with `--after
  RUN` what that run showed for each finding — `gone` only when the run is complete and does not
  sight it, `unchanged` when it does, `not_proven` otherwise (exit 3: a re-check run that is not a
  result proves nothing) — with the `store triage set` line that records it. It runs nothing.
- **`evidence review`** lists every text surface of a bundle's recordings with the values as
  recorded; **`evidence redact`** writes the handover bundle: the engagement's literal
  `mask_patterns` (read from the operator's own file, which must be a version of the chain) and
  the given keys blanked in those surfaces, no store, `redactions.json` naming each blanked place
  and its rule as `mask_patterns[i]` or `mask_key:NAME` — never the value —, and
  `CUSTOMER-README.md`, generated from the file and the index, which says what the bundle is and
  how to verify it. The first bundle is not touched; the second's index names it in
  `derived_from` and is filed in the store's `bundles`.
- **`engagement attest`** writes a one-page attestation from recorded facts only — window,
  targets, runs by state, scripts and whether any called a tool, scenarios, isolation, refusals,
  the bundle's and the report's digests — and no finding and no triage row: what a customer can
  show a third party.
- **`engagement purge`** deletes, at the end of `retention.delete_after` (before it only with
  `--before-retention REASON`), the store, every run directory, refusals file and bundle of the
  engagement, refusing whole if any of them names another engagement or is a link, and writes
  `purged.json`: the id and digests, the bundles' index digests, the time, the author, each
  path's outcome, and what it does not reach — no customer data. A filed run whose recording is
  not found under `--out-dir` leaves the purge not complete (exit 3).
- **`engagement history --customer NAME --store …`** reads one customer's engagements across
  their stores, every time, read-only, and lists a store it cannot read rather than skip it.
- **The web interface** shows the engagement on run, fleet and store pages, a Triage view with
  each role's current decision beside the findings, a **review mode** — one finding at a time and
  nothing else on the screen: each role's current row first, every earlier row behind a toggle
  that is off when the page opens and says so, and the complete `store triage set` line to copy,
  since the interface writes nothing —, and bundles (`web --bundle DIR`) and attestations (`web
  --attestation FILE`) as downloads, served only while a bundle is intact and re-hashed when
  served. Signals show their kind.
- **docs/clients.md** shows how Claude Desktop, Claude Code, Cursor and Visual Studio Code are
  pointed at `mcp-polygraph run --engagement …` for a session the customer's own client
  witnesses.

### The report: `mcp-polygraph report`

`report --engagement FILE --store S --runs DIR [--out-dir DIR] [--manifest M] [--previous BUNDLE]
--out FILE`
writes the engagement's report in Markdown, once, `0600`, after reading it back through its own
parser. Every sentence is one of three kinds, marked at the start of its line: `[recorded]` —
what the tool wrote down; `[derived]` — what follows from that by a rule the sentence names (a
count, a comparison, "egress not observed", "server unpinned"); `[assessed]` — a triage row,
with its author, role and time. A report without triage rows has no assessed sentence and says
so. Values from the traffic, the store or a file stand in code spans, so none can start a line,
fake a kind or a heading. The seven sections: the engagement
(every version of the file and what changed between them, the targets, how many literal
redaction patterns it defines — never what they are — and every refusal, with a sentence that
refusals before the file was read are not recorded); what was done (the status's account first,
runs by state with their causes, what was not done); findings of reference and poison entries
with both roles' triage beside them and open questions apart; real-world findings apart, each a
candidate for responsible disclosure; the comparison with a previous bundle, verified first and
compared through `store.compare_runs` only when intact; reproduction; and what the report does
not say, with every signal's kind. A run that is not complete is named so wherever it is used;
the exit is 0 when every run the report uses is complete, 3 otherwise, 2 when refused.

### Evidence, triage and the engagement's state: `evidence`, `store triage`, `store history`

`evidence pack --engagement FILE --store S --runs DIR --out DIR` copies everything an
engagement's store holds into one new directory a reader can check without this tool's store:
every filed recording as written (found under `--runs`; one not found and one whose bytes
changed since filing are two refusals), the scenarios and manifests they name, every
`refusals.jsonl` under `--runs`, the engagement file without what has no place in something
handed on (as `engagement.json`, its entry naming the original file's digest and what was
removed), a copy of the store, the tool's versions, and `--report` if given; sessions the store
cannot hold (a proxy or witnessed session made under the engagement) come in through
`--session` and are listed as not filed. `index.json` names every file with its SHA-256, size
and role, and the triage as it stood (identities no row concerns yet, rows `open` and
`question`): a bundle is a snapshot, not an approval. Files are `0600` in `0700` directories,
nothing is overwritten, and the bundle is filed in the store's `bundles` by the digest of its
index. `evidence verify DIR [--index-digest HEX]` recomputes every digest from the index alone:
each file `intact`, `changed`, `missing` or `unlisted`, the bundle `intact` only when every file
is (exit 0, else 3); a signature file is reported present and not checked.

`store triage set --store S (--finding ID | --identity JSON) --role operator|customer --status
… --rationale … --author … [--severity TEXT]` appends one decision about a finding's identity —
the key without its two version fields, so a decision follows a finding across versions. The
author is never taken from the environment; the severity is the operator's own text, which the
tool neither defines nor compares. A later row of the same role supersedes the earlier one and
both stay readable; the two roles' current rows stand side by side. `store triage list
[--history]` gives the current rows, or every row in order. Nothing of it enters a finding, a
key, a state or a comparison.

`store history --store S --server ENTRY` gives each identity of an entry fleet by fleet and run
by run — sighted, not sighted in a complete run, not a result, or not run — with the server
versions (and their kind) and the current triage rows. `engagement status --store S
[--manifest M] [--out-dir D]` says in a dozen lines where an engagement stands: the window and
the days left, runs by state, findings per entry as counts only (no locator and no text from the
traffic: a status goes by mail), refusals by reason, and what is still planned. `engagement
preflight FILE` checks, item by item and without contacting any target or writing anything,
whether the file, the scenarios, the manifest, the images, the store and the out-dir and the
contacts are ready before the window opens (exit 0 ready, 3 not ready).

### A server someone else runs: endpoint entries, isolation `remote`

A corpus entry can name a server at a URL instead of a command (docs/design/http-transport.md,
section 4.1): `source: {endpoint: URL, version_declared: …}` with `launch: {transport:
streamable-http}`. `drive --manifest M --entry E` drives it as an `--http` run through this
tool's own proxy, with the entry's identity and reproduction triple, under isolation `remote`,
and the store files it like any driver run. Its identity is of kind `endpoint`: there is no
content to read, so `server_version` is the version the operator declared, or the word
`endpoint`, and wherever the store gives a version out — `store runs`, `store findings`, `store
diff` — `server_version_kind` says `declared` (or `content`, `revision`; `mixed` where a
finding's runs disagree), read from `server_identity_kind`, never from the string. Every result
of a run whose isolation keeps no account of the server's egress says so: `egress_observed` in
`store runs`, and a line on the terminal after the run ("egress not observed (isolation
remote)"; under `host` too). The rules move to version 10, which judges a run under `remote` as
one under `host`; under 9 it was incomplete (`unknown_isolation`).

`remote` is for endpoint entries only, whatever their provenance; an endpoint entry under `host`
or `runc` is refused (nothing here to run, the manifest named), and a command entry never runs
under `remote`. A declared version may not be the word `endpoint`, which an undeclared one
reads. The gate only narrows, and over HTTP it has one rule: the URL's host is the target,
of a selected scenario as of a script that acts. A corpus run always selects a scenario, so a
non-local endpoint needs `--engagement-confirmed` even to observe it; and so, from now on, does
`drive --http` with a scenario of statements only against a non-local host, which until now was
gated by `--target` alone. (The benchmark runner passed `--engagement-confirmed` to its runs over
HTTP, to the project's own fixture containers in a closed network; since plain HTTP goes to a
loopback address only, its driver
speaks to `127.0.0.1` in the server's namespace and passes it nowhere — see above.)
`mcp-polygraph verdict` gives a recording's `isolation` and
`egress_observed`, and says so in words where egress was not observed, as `store ingest` does
for each run it files; after a plain `--http` run the words say the server runs elsewhere, not
that it ran as a child. `fleet run` refuses a manifest with an endpoint
entry before anything starts (exit 2): endpoint entries run through `drive` only. `corpus
check` names each entry's `endpoint` and permits `remote` for it.

An endpoint's version is declared, never pinned: the deployment behind one URL can change under
the same declared version. Wherever a finding is new or gone between two runs and a side's
version is declared, it says so — `store diff` with a `server_unpinned` caveat on that set,
`engagement recheck` with "server unpinned" beside a `gone`, beside what the re-check run sighted
new and in the rationale of the line that records it (`--json`: `version_kind_before`,
`version_kind_after`, `server_unpinned` per item, `after_version_kind`), as the report already
did. `engagement recheck` labels a declared version `(declared)`. On the terminal, `store diff`
now names each caveat with the set it is on; until now every caveat — a cut listing, a moved
environment — was announced as a change of the scenario's content.

Under an engagement file, a target that is not local must list its `paths` — scope against
somebody else's server is never "any" — and may leave its `ports` out, which then default to
80, the port of `http`, the one scheme spoken (443 since TLS, above); `engagement show` prints the
default it applied.
A `remote` floor is met by a `remote` run and by nothing else. Pacing stays declared and not
enforced, and every run under a file records `run_started.pacing_enforced: false` (`null`
without a file; additive, recording schema 5).

### An engagement file: the gate held to what was agreed, and a record of it

`--engagement FILE` on `run`, `drive`, `fleet run` and `store ingest` names the written
engagement a run is made under, as a file (`.yaml`, `.yml` with the `[yaml]` extra, or `.json`):
its `id`, the customer, the window (UTC), a closed list of `targets` (host, ports, paths, an
isolation floor), the scenarios by SHA-256, whether the script may list and whether it may call,
pacing, retention, redaction keys, the version it `supersedes`, and what the customer `declared`.
It is read whole or refused whole, every refusal naming the file and the place in it; a file that
still holds a bracketed placeholder (`"[CUSTOMER NAME]"`) is read as a draft, which
`engagement show` marks and the gate refuses. docs/engagements.md walks through an engagement.

**The gate only narrows.** With a file, a run is refused — before any process starts, exit 2,
`mcp-polygraph: FILE: condition: words` — when the clock is outside the window, when what it
reaches is not in `targets` (the local child included), when a port or a URL's path is not
listed, when its isolation is weaker than the target's floor, when its scenario is not listed by
digest or is a built-in one, when its script calls and `actions.call` is false, or when it lists
and `actions.list` is false. Today's gate runs first with `--engagement-confirmed` as typed: the
file does not imply the flag, so a scenario or a calling script against a non-local target needs
it with a file as without one, and the recording keeps the flag as typed. Nothing is resolved;
hosts are compared as strings. `pacing` is shown as declared and not enforced by this version.

**What a run records of the file: its id, its digest, its window, and nothing else.**
`run_started.authorization.engagement` is `{engagement_id_declared, engagement_digest,
window_declared}`, or `null` without a file; `run_finished.window_exceeded` says whether a run
that started inside the window finished after it (`null` without a file) — recorded, never an
abort and never a state. Both are additive: the recording schema stays 5, the verdict reads
neither, and a reader without them reads `null`. Contacts, the customer, the reference and the
rest of the file never enter a recording. The file's `redaction.mask_keys` join `--mask-key`.

**A refusal under a file is written down.** From the moment the file is read, every refusal of
`run` and `drive` is appended to `refusals.jsonl` in `--out-dir`, never inside a run directory:
one JSON line with the UTC time, the command line as typed after masking, the reason from a
closed set, the words, the file's id and digest, and exit code 2. The file is `0600`, opened
append-only, never through a link and never blocking on something that is not a file, and takes
no line beyond 16 MiB; an out-dir that is refused (inside a git working tree) records nothing,
and the terminal says so. A refusal of the file itself is not recorded. A refused `fleet run` is
written to its `--out-dir` the same way, and each of a fleet's runs writes its own refusal
beside its run directories inside the fleet's directory; `engagement.find_refusals` reads every
such file under an out-dir, and names one it cannot read rather than skip it.

**One store per engagement.** `store ingest --engagement FILE` makes a store that holds nothing
an engagement's, or advances it to a version whose `supersedes` is the current one; the store
keeps every version in `meta.engagement_chain` — the original file's digest, the file without
what has no place in something that may be handed on (`contacts`, `reference`, the literal
`redaction.mask_patterns` that are to be blanked, the customer's `owner_contact` per declared
server), and the list of what was removed. It refuses another engagement, a store of one's own
runs, a run under no engagement or under a version its chain does not hold, a run whose
recorded id contradicts the file of its digest, and a fleet run without the file into an
engagement's store, before anything starts. `fleet.json` names the file a fleet was gated
against as a recording does. Each filed run carries
`engagement_id_declared`, `engagement_digest` and the customer's `engagement_declared` (from the
chain, never from the recording) in `store runs`.

`engagement show FILE [--json]` prints the file as a short document a customer can sign off — the
targets as a table, the window in UTC and in `window.tz`, what the script will and will not do,
a line saying `--engagement-confirmed` is still needed where it is, and the digest every run
under the file records, last.

### Store schema 11: what an engagement needs, in one step

`runs` gains `engagement_id_declared`, `engagement_digest` and `engagement_declared`: the
engagement file a run was gated against, as its recording names it, and the customer's
declarations from that file. All three are `NULL` for a run made without an engagement file,
which is what a run against one's own server is. A table `triage` keeps decisions about findings
beside them, never in them: keyed by a finding's identity (the key without its two version
fields), with a `role` (`operator` or `customer`), a status from a closed list, a severity as the
operator's own text, a required rationale and a required author. The database itself refuses to
change or delete a row, so a second decision is a second row and the history stays readable. A
table `bundles` names each evidence bundle packed from the store. Nothing writes those two tables
yet; they exist from this step on so that schema 11 is one layout, whichever way a store is
opened. A finding's key, `store diff` and `fleet diff` are unchanged. Not migrated: a store of 10
is refused whole, as every earlier one.

### A read-only web interface: `mcp-polygraph web`

`mcp-polygraph web [--store FILE] [--runs DIR] [--manifest FILE]... [--scenario FILE]...` serves
recordings, the finding store, fleets, manifests, scenarios and the signal library to a browser,
on a loopback address only (`--bind` refuses anything else, exit 2), without authentication and
without TLS, and says so. It writes nothing and starts nothing; every state and comparison it
shows is the one `verdict`, `store diff` and `fleet diff` give. A view that shows nothing or not
everything says why — a run that is not a result shows its state and every cause with its key
first, a capped listing how much of how much, a store's recording not found under `--runs` and
one whose bytes changed are two statements, real-world findings are candidates on a page of
their own. Strings from the traffic are shown as text, invisible characters as `U+XXXX`; the
page makes no outbound request and runs under a strict Content-Security-Policy, and the server
refuses a `Host` or `Origin` that is not its own. `docs/web.md` says how to use it;
`docs/design/web-interface.md` is the audit of its mockups against the code.

`Store.open_read_only` opens a store through SQLite's `mode=ro`: nothing is created or changed,
a store of another schema is refused whole, and so are a missing file, a file without tables and
a store in write-ahead-log mode, which SQLite cannot read without writing beside it.
`verdict.judge` and `verdict.unreadable` judge a recording whose bytes the caller read itself, as
`verdict.read` judges a file; `Store.recordings` gives each run's recording as filed.

### A script can call tools, and a call answered with an error is a state of its own

`drive --script FILE` speaks a conversation written in a script file (`.yaml`, `.yml` or
`.json`): `initialize`, listings, and `call` steps that send `tools/call` with a tool's name,
its arguments, a path into the answer to check, and a timeout of their own. Placeholders in the
arguments (`{fixture_url}`, `{fixture_dir}`, `{repo_path}`, `{db_path}`, `{canary}`) take their
values from `--script-var NAME=VALUE`. A file that does not load is refused whole before
anything starts. A call goes out only if the server offered `tools` and a `tools/list` of the
same script delivered that tool; otherwise it is recorded as not sent (`tool_not_listed`). A
script with a call acts on the target and is held to the engagement gate as an active scenario
is. Scripts work over stdio and over `--http`; the built-in `discovery` is unchanged.

The recording writes each call when it is sent, as `step_called` with its arguments masked, and
an answer that is a JSON-RPC error or a result with `isError` as `call_failed` (`kind`
`rpc_error` or `tool_error`, the `code`, nothing of the server's text); `run_started` carries
`script_digest` and `script_vars`, `script_finished` `called` and `failed`. Recording schema 5.
The verdict has a new state, `call_failed` (exit 6), between `incomplete` and `complete`: the
server answered, but not with what the call was to deliver (causes `call_error`, `tool_error`).
An answer to a call that cannot be read is `incomplete` (`call_result_unreadable`), a call to a
tool the listing did not deliver was not sent (`step_not_sent`), and a `call_failed` record that
is not one is `incomplete` (`call_record_unreadable`). Rules version 9. A run and a fleet result
may be `call_failed` in the store: store schema 10.

The benchmark runner has a stage B (`bench.py run --stage b`): a script per server calls one
tool against a planted fixture that carries a canary, and the outcome says whether the canary
arrived and what the signals found in the call's answer (`benchmarks/local-servers/README.md`).

### The user information of a URL is masked wherever it stands

In argv, in text and in JSON values, everything between `://` and the last `@` before the end of
a URL's authority is masked, in every scheme: a password, a bare user name and a token in the
user name's place alike (`postgresql://user:password@host`). So is a URL written in part or
whole in an encoded form — `%XX` once or twice, `\/`, `\uXXXX`, the HTML entities `&#NN;`,
`&#xHH;`, `&colon;`, `&sol;`, `&commat;`, full-width `：／＠` — and the DSN of Go's MySQL driver
(`user:pass@tcp(…)`, `@unix(…)`). One URL counts as one redaction; all three rules run in linear
time.

### The driver speaks Streamable HTTP: `drive --http URL`

`drive --http http://host:port/path` drives a server that is already running over Streamable
HTTP (revision 2025-06-18), through the tool's own proxy, which forwards, inspects and records as
it does over stdio: `initialize` with the version header, the session (`Mcp-Session-Id`, sent
back on every request and ended with a `DELETE`), answers as a JSON body or as an event stream,
one connection per exchange, no redirect followed. `--http` takes no `--` command and none of
`--manifest`, `--entry` and `--isolation`; a scenario with rules is refused (`--http` observes
only).

**One recording format for both transports: schema 4.** `run_started` names the `transport`
(`stdio` or `streamable-http`) and, for HTTP, the `endpoint`; `message` carries `exchange`,
`stream` and `event_id`; the events `http_request`, `http_response` and `http_end` record each
exchange's heads and how it ended; `run_finished.http` counts what was forwarded. Headers, the
target and the query go through the masker: `Authorization`, `Cookie` and their kind are
blanked, tokens in the query masked, the user and password of a URL dropped
(`userinfo_dropped` says they were there), a fragment never kept; a session is recorded only as
its ordinal, an SSE id only as a pseudonym. Raised for stdio recordings too: a reader of 3 would
pass the HTTP events by without knowing it.

**Causes only HTTP knows: rules version 8.** A handshake or a step that failed for a reason only
HTTP has is named by it — `http_unreachable`, `http_status` (a status that carries no answer, a
redirect among them), `session_lost`, `http_sse_only` (the endpoint speaks only the deprecated
HTTP+SSE transport, which is detected and not driven) — instead of `server_failed` or
`step_unanswered`; the states are those the same failure has over stdio. An HTTP run whose
`run_finished` lacks the counts of what was forwarded is `incomplete` (`http_counts_missing`).

The benchmark runner drives a server whose definition says `launch.transport: streamable-http`
over HTTP, in a closed network of its own, once a probe has shown that there is no way out
(README, "The benchmark over HTTP").

### A server message that is not valid UTF-8 is incomplete, with a cause of its own

Such a message went past the inspector and the scenario engine without a word. The inspector
now reads it as a client does, with replacement characters, under the same depth and
duplicate-key rules, and counts it toward `inspection_bounded`; the engine learns its id,
forwards it unchanged and, where an active rule could have changed it, says that the rule could
not read it. The recorder marks it `not_utf8`, and the verdict holds every such server message
`incomplete`, cause `message_undecodable`: what was inspected is not exactly what was sent, and
no rule can rewrite bytes it cannot read. A client message that is not valid UTF-8 is counted
apart (`run_finished.client_undecodable`) and is `incomplete` under `client_message_undecodable`
— the client's doing, not held against the server. Rules version 7.

### A sandbox that fails after the target has a cause of its own

`sandbox_failed` is now only a failure before the target existed, which the server cannot have
caused. A failure after the target ran, or in a phase the recording does not name, is still the
state `sandbox_failed` (exit 5), under the cause `sandbox_failed_after_target`: the worst case.
The proxy and the sandbox record the phase after the target. Rules version 6.

### `tool_name_collision` is split into `tool_name_duplicate` and `tool_name_lookalike`

`tool_name_duplicate` fires on a tool name that another tool in the same listing carries
character for character: evidence. `tool_name_lookalike` fires on one that another tool writes
differently but that reads the same (no case, no separators, Cyrillic and Greek lookalikes
mapped): a heuristic. Both are declared only — a statement has to ask. A scenario that names
`tool_name_collision` is refused: the signal is unknown.

### A manifest refusal shortens its path, never its reason

A refusal of `--manifest`/`--entry` (and of `corpus check`) was cut at 200 characters as a
whole. With the manifest deep in a long checkout path, the path took the room and the list of
entries to pick from was cut off. Now only the path gives way, from the front, keeping the file
name; the reason after it, the list of entries included, is shown whole.

### Recordings and stores of earlier versions are refused, never migrated

**A store of any schema but 11 is refused whole.** The store's schema went from 2 (the finding
store and its comparison) through 3 (a state per run instead of complete or not), 4 (recorded
caps), 5 (the environment axis), 6 (fleets), 7, 8, 9 and 10 to 11 now. 7 added no column: it was
raised because what a filed run *means* changed — its state is judged under rules that hold UDP
destination by destination and count what the sandbox's sink missed. 8 adds `causes` to every
run and every fleet result (below). 9 adds the version of the rules (below) to every run and
every fleet, and is the last time the schema moves for anything but the store's tables. 10 lets
a run and a fleet result be `call_failed` (above), which a store of 9 refuses to hold. 11 adds
the engagement a run was gated against, the triage table and the bundles (above). A store of an
earlier schema holds runs
judged under other rules, and a comparison across the two would compare the rules, not the
servers. So it is neither migrated nor read in part: `Store.open` refuses it before anything is
read from it or written to it, says which schema it found and that it is older, and the file is
left exactly as it was. A store of a schema this version does not know — newer, or not a number
— is refused the same way. A file that holds tables but names no schema is no longer taken for
a new store.

**A recording of any schema but 5 is refused whole.** Every line of a recording carries `v`,
and `run_started` carries `schema_version`; both are now 5 (2 added the per-datagram UDP loss,
3 the `run_stopped` event, below, 4 one format for stdio and Streamable HTTP, 5 the events of a
script that calls tools, both above). A recording of an earlier schema — 1 is everything recorded
up to and including the fleet's first stage — or of an unknown schema is refused by
`store ingest`, and `mcp-polygraph verdict` judges nothing of it but its schema (`incomplete`, with
that as the only reason). So is a recording with a line of another schema in it.

**What to do:** drive the runs again, into a new store. Nothing is converted.

### What a server sends cannot stop the run by its size or its depth

A server chooses how long its lines are and how deeply its JSON nests; neither ends a run any
more, and where a limit holds, the run says so.

- **The driver** reads a line up to `--max-message-bytes` (1 MiB unless given), never less than
  the 64 KiB it always read; a longer one used to end the script with `driver_error`. Past the
  limit, a line is read past without being held, and a step that got nothing else is
  `answer_unreadable`, so is one whose answer is nested more than 512 levels deep. Such a step
  leaves the inventory partial: rules version 5. An `initialize` answered that way is now
  `server_failed` (exit 4), where it was `driver_error` (exit 3).
- **The recorder** writes a document as JSON up to 256 levels deep, counted the same on every
  Python version; where the recursion gave out, the recording used to stop. A deeper message,
  one too deep to parse at all, and a deeper value in an intervention are recorded only as a
  note, with `error_reason` `too_deep` for a message: masking by key cannot walk them, and
  their text, masked by shape alone, would let through what a JSON escape hides. Up to 512
  levels, the keys the note withholds that masking would have blanked are counted as
  redactions; deeper, a message is not parsed at all. A message JSON cannot carry (a number such as `1e400`), and one rejected as
  written that `json.loads` still reads (`non_json_constant`, `duplicate_keys`, `not_utf8`),
  is recorded as its masked document's text, every value of a repeated key included — no
  longer unmasked, nor masked by shape alone. Only a message that is not JSON at all is still
  masked by shape alone: there is no document to mask.
- **The inspector** walks a schema 256 levels deep. A message from the server deeper than 512
  levels, or too deep to parse, is not inspected and counts toward `inspection_bounded`.
- **The scenario engine** lets a message deeper than 256 levels pass untouched instead of
  stopping, or blaming the rule. The id of a request that deep is still learned, so that the
  answer to it keeps its method; the inspector learns it too, and the driver knows its own
  answer that way. Past its depth a message is never given to `json.loads`: its brackets are
  counted in one pass, and only its top level is read, for the id. So which message is too
  deep, and what is read of it, is the same on every Python version, whether what lies below
  would be valid JSON or not; brackets that do not pair make no JSON at any depth.
- **The verdict** reads a recording line nested more than 512 levels deep as a problem with that
  line, on every Python version.
- **A stderr line** over the limit is recorded with `truncated: true`.

### A run stopped by a signal is incomplete, not a failure

Ctrl-C or SIGTERM to `run` or `drive` stopped the run, and what the stop brought about was
written down as a failure: a sandbox still being built became `sandbox_failed` (exit 5), a
server killed before it answered became `server_failed` (exit 4). The proxy now writes
`run_stopped {signal}` the moment the signal arrives; the verdict reads the run as `incomplete`
under the cause `interrupted` — the key a fleet's interruption gives a run it cut short — and
holds nothing that came after the stop against the server or the sandbox. What went wrong before
it still counts. A driven run exits 3; a proxied one hands the server's code through and says on
the terminal that its recording is incomplete. Rules version 4.

### The rules have a version of their own

`mcp_polygraph.verdict.RULES_VERSION` says which rules a run is judged by, and moves with every
change to them — what makes a run complete, incomplete or failed, and what a fleet's digest
covers. It is kept with every run and every fleet in the store (`rules`), is part of the fleet's
digest, and is in the output of `mcp-polygraph verdict`. `store diff` and `fleet diff` show both
versions and say so when they differ: two states, or two fleets, may then differ by the rules
alone. The store's schema now moves only with its tables. The version is 10: 1 is the rules
stores of schema 7 and 8 were judged by, 2 makes a session about nothing incomplete
(`empty_session`), 3 puts the causes into the fleet's digest, 4 judges a run stopped by a signal
incomplete, 5 counts a step without a readable answer as partial, 6 gives a sandbox that failed
after the target a cause of its own, 7 judges a message that is not valid UTF-8 incomplete, 8
names the failures only HTTP has, 9 adds the state `call_failed`, 10 judges a run under isolation
`remote` as one under `host` is (4 to 10 above). A test pins
what the rules make of a fixed set of recordings per version, so a rule cannot change without
the number.

### Sandbox observation

- The sink takes every datagram the kernel holds off its socket before it writes any down, and
  asks for the largest receive buffer the host grants. Measured over ten runs of 2000 datagrams
  sent as fast as a process can: a median of 1996.5 received, where it was 550.
- UDP is reconciled destination by destination: the ruleset marks every datagram, before the
  redirect, with a digest of its original destination, and the sink reads the mark
  (`SO_RCVMARK`, no capability needed). The positive probe proves it on every run.
- `egress_summary.udp_loss` records what the sink missed; a run in which it missed any datagram
  is `incomplete`.

### Why a run is not a result, as a key

Every shortfall the verdict finds carries one cause from a fixed vocabulary
(`mcp_polygraph.verdict.CAUSES`): `udp_loss`, `step_unanswered`, `no_script_finished`,
`server_failed`, `egress_inconsistent` and so on. The store keeps a run's causes whole beside its
reasons (which it lists only up to twenty), the fleet keeps them per result and in its
comparison, and the report says them next to the state — so a run incomplete because the sink
missed datagrams is told apart from one incomplete for any other reason without reading words.

### A server that never starts is a server that failed

A server command that could not be started ended with a Python traceback and exit 1. Now, in
proxy and driver mode alike, the recording says `server_failed` with reason `not_started` and
what the system said (command not found, not executable, not an executable format), and the
run exits 4. The closing event also records what the server wrote to its stdout, what the
client wrote, and whether the server ended while its client was still connected; a server
that said nothing although asked, or ended first without a word, is `server_failed`
(cause `server_silent`) — so in proxy mode a server that crashes at start no longer hands its
own exit code through as if it had been observed.

### The fleet's digest carries why a run fell short

Each result's causes are part of the fleet's digest: two fleets whose run was incomplete for
different reasons no longer read as the same result. A fleet digested before this change
compares as different from one after it, even when their results agree.

### A session about nothing is not a result

A proxied session in which neither the server nor its client wrote a byte, ended by the client,
was `complete`. It is now `incomplete` under the new cause `empty_session` — nothing failed, but
nothing was asked or observed — for the same reason a fleet over an empty manifest is refused.
A run whose server never ran (not started, sandbox failed before the target) keeps its graver
state alone. In proxy mode the exit code is still the server's; the terminal says the
recording is incomplete.

### Ctrl-C during a fleet

Ctrl-C (or SIGTERM) during `fleet run` ended in a Python traceback, and the runs it had started
— each in a session of its own — ran on with nobody to file them. Now the fleet stops every run
(SIGTERM to its process group, SIGKILL after 10 s or at a second Ctrl-C), removes whatever a
killed run left (its containers by label, its staging directory, both named by a nonce the fleet
hands it: `drive --sandbox-nonce`), files the runs that had ended, records the others as
`unfiled` with the new cause `interrupted`, and files itself as interrupted and incomplete
(exit 3, or the code of a graver run that had ended). A run stopped by `--job-timeout` is cleaned
up after the same way.

### Command line

- `--step-timeout` (drive, fleet run) is at least 2 s. The first step's wait includes the
  server's own start — under runc its container's: measured 0.37–0.41 s idle and up to 0.89 s
  with every core busy. Below twice that, the setting rather than the server decides whether a
  run is `server_failed`; such a value is an input error (exit 2).
- `fleet run --out-dir` is checked once, before any run starts: a destination inside a git
  working tree that does not ignore it is refused with exit 2. Each run refused it on its own
  before, and the fleet reported every entry `refused`.
- A result that cannot be written to stdout — the process started with stdout closed, or a pipe
  whose reader has gone — ends with exit 74 and a line on stderr that says the result was not
  written and what the exit status would have been. It was lost in silence with exit 0, or
  ended in an interpreter complaint. `run` with stdout closed, which is its client's channel,
  is refused before anything starts (it ended in a traceback).
- Ctrl-C during `store ingest` is a line saying how far it got, and exit 130, instead of a
  traceback; the recording being filed is rolled back whole, as before. Anywhere else no run or
  fleet takes it (before a run began, after it was filed, while a store is read), the same line
  and 130.
- Input errors are refused before anything starts, with exit 2 and a line that names the input:
  a bound of zero or less, `nan` or `inf` (`--max-message-bytes`, `--queue-size`,
  `--max-duration`, `--step-timeout`, `--client-settle-timeout`, `--job-timeout`), and an
  `--out-dir` that is a file or cannot be created (`run`, `drive`, `fleet run`). These ended in a
  Python traceback, or in a run that failed or stopped because of them.
- `mcp-polygraph verdict RECORDING`: a recording's state, read back from it (JSON); exits with the
  state's code. In proxy mode the exit code is the server's own, so this is where a proxied
  run's state is.
- `drive --client-settle-timeout` and `fleet run --client-settle-timeout`: how long the closing
  event waits for the driver's script to end (default 5 s). A wait that runs out is recorded.
