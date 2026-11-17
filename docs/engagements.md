# Working under an engagement

How to test an MCP server somebody else operates, under a written engagement, and hand them the
result. The steps follow the engagement's life:

```
1 intake → 2 scope → 3 kickoff → 4 runs → 5 review → 6 re-check → 7 close-out   (8 dossier)
```

Each step names the command that does it. Three things hold throughout:

* **The engagement file only narrows the gate.** A run the file does not cover is refused before
  anything starts (exit 2); a run the gate refuses without a file is refused with one too.
  `--engagement-confirmed` is still needed wherever it is needed without a file.
* **Claims stay claims.** What the operator or the customer typed is kept as what it is —
  `engagement_id_declared`, `window_declared`, `declared`, a version `declared` — and never
  checked against the world.
* **Nothing becomes a verdict.** Findings are facts with a locator and a signal. A person's
  judgement goes into the triage table, under their name and role, beside the findings and
  never in them.

## 1. Intake: what does the customer operate?

```sh
kymograph engagement intake --out questionnaire.yaml          # or --text for a plain form
# … the customer fills it in …
kymograph engagement intake --from answers.yaml --id acme-2026-11 --out engagement.json
```

The questionnaire asks which servers exist, how they are reached, which version the customer
believes is deployed, which clients use them, constraints on hours and rate, and what must not be
done. A plain text form (`--text`) is read leniently: every line it cannot place is kept
verbatim under `declared.notes`, except a line with a character of the category control (Cc), format (Cf), surrogate (Cs),
private use (Co) or unassigned (Cn): `intake` refuses it by its line number, naming the
categories found in it (never the characters), whatever its label, and keeps it nowhere, because
it may hold a secret. So is a line that no field takes and that begins like the label or the key of a
secret field (`Known value`, `Salt variable`, `Emergency reach`, `Receiver path prefix`, `Receiver key variable`,
`Receiver ssh`): only the letters a to z of the line are compared, after decomposing (NFKD) and case folding, so accents, full width forms and `İ` or `ſ` do not hide a label, and `Known value 2: x`,
`- Known value: x`, `1) Known value x` and `KNOWN VALUES (prod): x` all count. `intake` refuses it by
its line number and the field, never the value; write exactly `<Label>: <value>`, one line for each
value, or delete the line. False alarms are meant: a note such as `Known values are rotated monthly`
is refused too, which is the safe direction (write `Note: …` to keep a note). The same goes for the shorter starts that are a field's own words and no
others: `Known`, `Salt`, `Receiver key`, `Key`, `Receiver path`, `Receiver prefix`, `Path prefix`, `Prefix`, `Path`,
`SSH` and `Emergency` (a line such as `Emergency contact: Jo` is a field of its own and is not
checked). This finds the labels of the form, not secrets: free text can hold a secret that `intake` does not
recognise, also behind `Note:`. So `intake` names the number of every line it keeps verbatim, for you to
read them again. A short start can raise a false alarm on purpose, as `Keycloak is our IdP` does (it begins with `Key`); write `Note: Keycloak is our IdP`. A line that no field takes and that stands **directly under** a line of a secret field (`Known value`, `Salt variable`, `Emergency reach`, `Receiver path prefix`, `Receiver key variable`, `Receiver ssh`), with no blank line between, is refused as well, and kept nowhere: it may be the rest of a key written over several lines, or a value put under an empty label. This holds for the third, fourth and every further line, too. `intake` refuses it by its line number and the field, never the value; a value goes on the field's own line, and a line that is meant to be kept as a note needs a blank line before it. A blank line, or a line that another field takes (`Note:` too), ends this; a further line of a secret field starts it again. The limit is the blank line: after one, a line is free text again, even when it is part of a key. A key belongs in none of these answers. A line counts as blank only if it holds nothing but spaces and tabs; a line
of other white space, such as a form feed, is refused like any other. The answers go into the draft engagement file under `declared`,
unchanged. Every field the answers cannot fill — the window, the customer's name, what the
script may do — is left as a bracketed placeholder and listed on stderr. **A draft runs
nothing**: the gate refuses it (condition `draft`) until every placeholder is filled in.

The draft is a file of **version 2** (section 2). Beside the servers, the constraints and the
notes, the questionnaire asks the fields only that version has, as top-level keys of the answers
(or lines of the text form): `customer` (the end customer's name, which becomes
`end_customer.name`), `agency`, `agency_contacts`, `tools`, `abort_criteria`, `emergency_name`
and `emergency_reach`, `known_values`, `salt_env`, `canaries`, the `receiver_*` questions and
`token_passthrough`. Every answer is text; where a line has parts they are separated by `|`: a
contact as `name | role | reach`, a tool as `name | writes` or `name | read-only`, a canary as
`id | kind | where` and, for a file canary, `| path`. A canary is written as not yet removed
(`removed: null`); the agency's confirmation is entered in the file later. These answers go into
the fields of the file, **not** under `declared`: `known_values` and the variable names are
removed from what may be handed on, `declared` is not. An answer wholly in brackets, as
`[don't know]`, is no answer. What a version-2 file requires and the answers lack —
`end_customer.name`, `abort_criteria`, `emergency`, `salt_env` — is a placeholder; the receiver is
written only when the answers say whether it is `local` or `reachable`, and a reachable one gets a
placeholder for each of its fields that is not answered. The YAML and JSON forms are refused whole
for an answer the file would not take, with its place; the text form places such a line without
checking it, and `--from` then refuses it with its place. No refusal repeats an answer, as a
mistake there may be the secret itself. Never put a salt or a key in the questionnaire: it asks
for the name of the environment variable.

## 2. Scope: one file, agreed, and a new version when it changes

```sh
kymograph engagement show engagement.yaml            # the document the customer signs off
kymograph engagement show --json engagement.yaml     # the file as parsed, without the known values
```

The engagement file (`.yaml`, `.yml` with the `[yaml]` extra, or `.json`) holds the id, the
customer, the window in UTC (`window.tz` for display), a closed list of targets — host, ports,
paths, an isolation floor —, the scenarios by SHA-256, whether the script may list and call,
pacing (`runs_per_origin`, `min_interval_seconds`; enforced, section 4), retention, redaction (`mask_keys`, and literal
`mask_patterns`), and what the customer declared. A target that is not local must list its
`paths`; its `ports` may be left out and default to 443, the port of `https`, the one scheme
another host is spoken to with (a URL's default; a `--target` names a port the file lists). It is
read whole or refused whole,
naming the file and the place. `engagement show` ends with the file's SHA-256: the digest every
run under it records, and the one the customer compares with the file they received.

**The generation the customer names.** A target may say which generation of the protocol its
server speaks: `era: legacy` or `era: modern`, and `version: 2025-11-25` (only beside an `era`;
the version is optional). It is the customer's word, and the run does not rely on it: the driver
finds the generation out by asking, and when the server speaks another than the file declares
(or another version, if the file names one), that is recorded in `era_decided` as an observation
and set down in the report. It never stops a run. It is compared only for a run over HTTP, for the
target the URL matches; `engagement show` lists it in a column of its own when any target names one.

```yaml
targets:
  - {host: api.acme.example, paths: [/mcp], era: legacy, version: 2025-11-25}
```

**Identities.** A file may declare `identities`: who a run speaks as, for an endpoint that wants
a token. Each has a unique `name`, a `role` (text, recorded with every run), and exactly one source
of its token: `token_env: NAME` (an environment variable), `token_file: PATH` (relative to the
file and inside its directory, links followed: a path that leaves it is refused as
`identities[<i>].token_file`, and checked again just before the open, which walks the resolved
path from the engagement file's directory one part at a time without following a link at any part:
a part that has become a link since the check fails the open, and what is read, by its descriptor,
must be a regular file; every refusal reads the same, on every system; a local path, so `sanitized()` removes it from what is stored and handed on) or `token:
none` (the identity sends no `Authorization` header, which is allowed and recorded). The file
holds no token: a value is not a key it knows, and a mistake there is refused without being
repeated. An identity may add secret `headers` from variables, `Ocp-Apim-Subscription-Key:
{env: APIM_KEY}`; `secret_headers: [NAME, …]` declares names whose values are replaced whole in
every recording under the file, sent by this run or not.

```yaml
identities:
  - {name: reader, role: read-only user, token_env: ACME_READER_TOKEN}
  - name: admin
    role: administrator
    token_file: secrets/admin-token
    headers: {Ocp-Apim-Subscription-Key: {env: ACME_APIM_KEY}}
  - {name: anonymous, role: not signed in, token: none}
secret_headers: [X-Tenant-Key]
```

**Version 2.** A file with `version: 2` carries the fields an engagement through an agency
needs. A file with `version: 1` is read as it always was, and the new fields are unknown keys in
it; a file of version 2 may name a file of version 1 in `supersedes`, and the chain stays whole.
In version 2 there is no `customer`: `end_customer: {name}` is required, and `agency: {name,
contacts}` is left out when the client is the end customer. Every field is strict: unknown keys
and wrong types are refused, naming the place.

| field | meaning |
| --- | --- |
| `tools` | `[{name, writes}]`, `writes` required, names unique. With it, only a listed tool is called (section 4, "The scope guard"). Without it only `actions` applies. |
| `actions.probes` | optional, a list of probe module names (lowercase letters, digits, `_` and `-`, each once): the modules `drive --probe` may run under the file (section 4, "Probe modules"). Without it no module is allowed. In a file of version 1, `probes` is an unknown key. |
| `deny_tools` | a non-empty list of exact tool names that are never called, with or without `tools`. A name twice, or a name that is also in `tools`, is refused with its place. Shown by `engagement show`, kept by `sanitized()`. |
| `actions.write` | optional, `true` or `false` (default `false`): whether a tool with `writes: true` may be called. `true` with no tool marked `writes: true` is refused with its place, since the release would name nothing. In a file of version 1, `write` is an unknown key. |
| `abort_criteria` | required, a non-empty list of sentences |
| `emergency` | required, `{name, reach}`, apart from `contacts` |
| `known_values` | strings to be replaced when written, each at least 4 characters, no duplicates. Replaced by a pseudonym wherever they stand in a recording or a refusal (see *Personal data*, below). An error never repeats a value. The `id` may hold none of them (see *Names*). |
| `salt_env` | required, the *name* of an environment variable, never a value. The variable holds the salt of the pseudonyms: at least 32 characters, or the gate refuses the run. |
| `canaries` | `[{id, kind, where, path?, removed}]`; `kind` is `tool_text`, `resource`, `prompt` or `file`; `removed` is `null` or the date (`YYYY-MM-DD`) the agency confirmed the canary gone. |
| `receiver` | `{variant, address?, path_prefix?, key_env?, ssh?, retention_seconds?}`; `variant` is `local` (this machine) or `reachable`, which needs `address`, `path_prefix`, `key_env` and `retention_seconds`. `address` is `host` or `host:port`, with no scheme, path, query, fragment or user: a DNS name or an IP address (IPv6 in square brackets), a port from 1 to 65535. The two parts declare a callback URL `https://<address>/<path_prefix>/…`; no probe of this version builds one (see *What this version does not do*). `path_prefix` is Base64url without padding, 22 to 128 characters, at least 10 of them different (the limits of the receiver's own check). `ssh` is a reference, never a key: `<NAME>` (a letter, then letters, digits or `_`, at most 64 characters between the angle brackets), or `[user@]host[:port]` with the host and port as for `address` and a `user` of `[A-Za-z_][A-Za-z0-9._-]{0,31}`. The check is of the form, not of whether a value is secret: a short password looks like a host. A bracketed placeholder is allowed in each of these, as in the other fields, and makes the file a draft; a value the field accepts is tried first, so an IPv6 address such as `[2001:db8::7]` is an address, not a placeholder (one with a scope ID, `[fe80::1%eth0]`, is refused in `address` and in `ssh`, as is `user@[fe80::1%eth0]`). |
| `token_passthrough` | `{method}`, `redirect` (the upstream is to be bent to the receiver) or `upstream_log` (a sample from the upstream's log); optional. Declared only: `engagement show` prints it and `intake` asks for it, and nothing in this version acts on it. |

A `file` canary names a `path`, absolute, and it must lie outside what the server may read. The
tool cannot check that; the operator does. `path` is refused for any other kind.

The file holds no value for a canary. `engagement canary FILE [--id ID] [--json]` prints each
canary's ID, kind, place and value, derived from the salt, for the agency to plant; and
`engagement marking RUN` reads where a canary came back in a recording and whether the server
marked it as foreign. See [content-marking.md](content-marking.md). `engagement status` names
the canaries without a confirmed removal, by ID and kind, never by path.

`receiver.retention_seconds` is at most 90 days (7,776,000 seconds), the receiver's own limit; the
file reader and `intake` refuse a larger value. A whole number is read as follows, and a file that breaks it is refused like any other invalid document:

- JSON: a number with leading zeros is invalid JSON, and one of more than 4,300 digits is refused.
- YAML: whole numbers are read in decimal, leading zeros do not count (`00003600` is 3600, `09` is 9), more than 4,300 digits are refused, and so is any other base or spelling (`0x`, `0o`, `0b`, `_`, `1:30`), also behind an explicit `!!int`.
- YAML: any other explicit tag (`!!str`, `!!bool`, `!foo`, `!<…>`) is refused with its line, and so is any `%TAG` directive; write a string in quotes instead.
- `intake`: leading zeros do not count (`00003600` is 3600), and a whole number of more than 4,300 digits is refused.

`sanitized()` leaves out, and `removed` names: `known_values`, `emergency`, `salt_env`,
`receiver.key_env`, `receiver.ssh`, `receiver.path_prefix` and `agency.contacts`. The path prefix is the
one part of the receiver's callback URL that cannot be guessed, and no store or bundle may carry it. `end_customer.name` stays, as `customer`
does. The customer's name is read the same way everywhere (`customer` in version 1, `end_customer.name` in version 2, never the agency): `engagement history` and the customer README of a handover bundle name the end customer. `engagement show` lists the new fields, but of `known_values` only the count, and an
environment variable by its name, never a value. `engagement show --json` is the operator's view and
shows the same, contacts and the path prefix included, but never the known values: it has
`known_value_count` beside `engagement`, which lacks `known_values`. Written back to a file, the
JSON's `engagement` loads, without the known values; they are never on stdout.

**A URL's path in a record.** A recording and a refusal write a URL's path only when the file lists
it for the target the run matched (`paths`, compared exactly); without a file, only when the host is
`127.0.0.1` or `[::1]`. A loopback target listed without `paths` lists no path, so its path is
withheld too. Elsewhere the record holds `path: null` with `path_sha256` and `path_length`, and in
text `<path withheld: sha256 …, N characters>`; the scheme, host, port and query are written as
before. The terminal shows the path whole, so the operator sees what was refused. The same holds for
every URL in the server's own command line (`run_started.argv`), wherever in an argument a scheme
and `://` start it, or `//` at its start, after white space or after `=` (`-e MCP_URL=https://…`,
`env URL=wss://…`, `URL=//host/…`), to the next white space or the next scheme; what stands before
it stays. No entry of the file covers it, so its path is withheld, and without a file it is kept
only for a loopback host. A value that names no port, under a scheme with no default one, matches no
entry either. What may stand is a path together with its host and port (the port of the scheme where
the URL names none), so the same path on another host or on another port is withheld, also within
one command line. It holds for the `message` of every refusal in `refusals.jsonl` as well, whichever
refusal it is: the rule is applied where the line is written. It holds for every recorded HTTP
header, in both directions. A URL found the same way, anywhere in a value, has its path withheld
unless the file lists it for that host and port; scheme, host and port stay, so the terminal and a
reader still see where a client is sent. `Location`, `Content-Location`, `Referer` and the
`resource_metadata`, `domain` and `error_uri` of a parsed `WWW-Authenticate` hold a reference, which
keeps less: only scheme, host and port, and a path the file lists. One that is not `http` or `https`
with a plain host and port, a relative one above all, names nothing the file could list, so all of
it before the query is withheld, listed or not. Its query and fragment are withheld too, as a server
may write a URL there in any encoding. A value with white space inside it is withheld whole. A
`Link` value is withheld whole, listed or not, because its form is too loose to say where a path
ends. In a header the digest is over the path as the masker left it, so a path holding a credential
digests differently from the same path in `http_request.target`. The limit is what is neither a URL
nor one of those references: a bare or encoded path in another header or another challenge parameter
(a `realm`, say), and what a server writes in a message, a reason phrase or a body. Those go through
the masker's text rules, not through this rule, so a path repeated there stays, unless a text rule
matches it. The same limit holds for a manifest: a bundle keeps it as the operator wrote it, because
its digest is what a run names, so a URL in a manifest entry stands there with its path. A path that
must not leave the operator's hands is given with `--http`, not in a manifest. A literal in
`redaction.mask_patterns` makes `evidence redact` refuse a handover bundle that still holds it.

A change of scope is a **new version**, never an edit: the new file names the old one's digest
in `supersedes`. A store holds every version in its chain, and a run under either is filed.

## 3. Kickoff: is everything ready?

```sh
kymograph engagement preflight engagement.yaml --manifest corpus.yaml \
  --store acme.sqlite --out-dir runs/acme
```

Item by item — the file, the scenarios, the manifest, the images (asked of the local Docker by
id), the store and the out-dir (existing, empty, `0700`, outside a git working tree), the
contacts — `ready`, `not ready` or `not checked`. For a file of version 2, three more items:

- `canaries` is `ready`, and says which canaries are still open (`removed: null`) by id and kind,
  never by path: before the test, open canaries are wanted. Without `canaries` it is `not checked`.
- `salt` is `not ready` when the environment variable named by `salt_env` is not set, is empty or
  holds fewer than 32 characters, and `ready` otherwise. The words name the variable, never its
  value, and say only that the length is short.
- `receiver key` is the same for `receiver.key_env` when the receiver is `reachable`; with a
  `local` receiver, or none, it is `not checked`.

A file of version 1 declares none of these, and the three items say so (`not checked`). Nothing
talks to a target; whether an endpoint
answers — its certificate included — is found out by the first run inside the window, and
recorded there. An endpoint entry over plain `http://` to anything but `127.0.0.1` or `[::1]` is
named under the manifest as one that will be refused, as plain HTTP to another host always is. Exit 0 ready, 3 not.

For a session through the customer's own client (a witness), send the customer the snippet for
their client from docs/clients.md.

## 4. Runs

```sh
# a corpus entry the operator runs here
kymograph drive --engagement engagement.yaml --manifest corpus.yaml --entry poison-server \
  --isolation host --out-dir runs/acme

# a server the customer runs, at an https:// URL: an endpoint entry of the manifest, under
# remote (plain http:// only to 127.0.0.1 or [::1]; the certificate is verified against the
# machine's trust store and recorded)
kymograph drive --engagement engagement.yaml --manifest corpus.yaml --entry customer-mcp \
  --engagement-confirmed --out-dir runs/acme

# the whole corpus, under the file (endpoint entries are never part of a fleet)
kymograph fleet run --engagement engagement.yaml --manifest corpus.yaml \
  --store acme.sqlite --out-dir runs/acme

# file the runs; the first ingest under the file makes the store the engagement's
kymograph store ingest --store acme.sqlite --engagement engagement.yaml runs/acme/*/events.jsonl

# where the engagement stands, in a dozen lines that can go by mail
kymograph engagement status --store acme.sqlite --manifest corpus.yaml --out-dir runs/acme
```

**Pacing.** Every HTTP run to a host that is not a loopback literal is paced, whether it is an
endpoint entry or `drive --http`, and with a file or without one; a run to `127.0.0.1` or `[::1]`
is the operator's own and is not. The values are the file's `pacing` (`runs_per_origin`, from 1
to 64; `min_interval_seconds`, 0 or more), and where the file is silent, or there is none, 1 and 10.
`engagement show` prints them: "enforced: runs_per_origin 1 (default), min_interval_seconds 10
(from the file)".

The origin is `scheme://host:port`; the identity is not part of it, so two identities of one
engagement take turns. A run takes one of the origin's slots before it connects and keeps it to
its end, and starts no sooner than `min_interval_seconds` after the latest end among the slots.
The slots are files under `<out-dir>/.pacing/` (mode `0700`, one `0600` lock file per slot, held
with `flock`), so only processes that share an `--out-dir` see each other; an engagement has one.
A run that had to wait records `paced` (`seconds`, `why`: `interval` or `origin_busy`) right after
`run_started`; a wait for a `Retry-After` (below) is recorded as `paced` with `why: "retry_after"`
and the `status` that caused it. A slot holds, while its run goes on, a start note that carries the
end time the slot held before (`started <time> after <end time or none>`), so a run that finds the
slot held counts it with that end time and does not skip it. A slot nobody holds that still has a
start note belongs to a run that did not end cleanly (killed, crashed): it counts as ended when
the next run finds it, so that run waits the full interval. Runs with different `runs_per_origin`
on one origin see each other's slots, and a run counts the slots held against its own number.
Reading the slots, choosing one and writing the note (or putting a slot back after a refusal) happen under a short lock per origin, a
`<digest>.lock` file of mode `0600` in the same directory; it is not held while a run waits, so
a run is only ever seen holding a slot, never half-way into taking one, and an origin is called
busy only when runs hold as many slots as the run's own number, or more. The lock is tried without
blocking, so a process that holds it too long does not hang the run: the run is refused with reason
`pacing` once `--step-timeout` has passed. A slot that cannot be read or written (the start note
must be written whole) refuses the run as `destination`, before anything is started. A run does not start at all if
`<out-dir>/.pacing` fails the same destination check the run directory has to pass; it is refused
with reason `destination`, and the message names the directory only as "the pacing directory
`.pacing` in the output directory", never by its path. `run_started.pacing` holds the values and their `source` (`file` or `default`) and
`pacing_enforced` is `true`; for a run that is not paced both are `null`. A recording made before
pacing was enforced may say `pacing_enforced: false`: declared, not enforced by the version that
made it.

A wait that would be longer than `--step-timeout` is refused instead: exit 2, reason `pacing`, one
line in `refusals.jsonl` under a file, and no run directory. A busy origin is waited for up to the
same time. Each of the two waits, for a busy origin and for the interval, has this limit, so
together they can take up to twice `--step-timeout`. Raise `--step-timeout` to wait longer, or
start the run later.

A 429 or 503 that carries a `Retry-After` in seconds is waited for once per request, when the
wait is strictly shorter than what is left of the step; then the same request is sent again, if
any of the step's time is left after the wait (if none is, nothing is sent and the cause is
`rate_limited`). A
`Retry-After` that is an HTTP date is not waited for, and a 503 without the header stays
`http_status`; a 429 without the header is `rate_limited` at once. If the answer after the wait is
again a 429 or 503, with the header or without, the cause is `rate_limited`. Before that request
is sent again the run asks whether it may go on (the end of the window, the stop file, a signal);
if not, nothing is sent and the step is recorded as a halt before it is: `step_skipped` with
`run_halted` for this step and every one after it, no `step_unanswered`, and the same verdict and
exit status; the wait stays in the recording as `paced`. The same holds for the opening (the
probe and `initialize`): the era detection gets nothing and writes no `era_decided`. A listing
of which pages were already answered is the one exception: it stays `step_unanswered` with the
number of pages and `run_halted`, so that it never reads as complete; the steps after it are
skipped. Like any other request, a `tools/call` is sent again after the wait.

**The scope guard.** Under a file of version 2 that sets `tools` or `deny_tools`, every tool call is
checked before it reaches the server, and one outside the scope is **blocked and recorded**, not
only warned about. A call is not allowed when its name is in `deny_tools` (`tool_denied`); when
`tools` is set and the name is not in it (`tool_not_listed`); or when the tool is listed with
`writes: true` and `actions.write` is not `true` (`tool_writes_not_released`). Names are compared
exactly: a server that resolves tool names without regard to case is not fully covered by
`deny_tools`; `tools` is the tight form. Without a file, or with a file that sets neither key (every file of version 1), nothing
is checked here and `actions` stays the gate's alone. The check is made in three places:

* **`drive --script`, before anything starts.** The gate holds every `call` step of the script
  against the rules. A script with one call outside them is refused whole, with a line in
  `refusals.jsonl` under the cause as the reason; `--engagement-confirmed` changes nothing.
* **The driver, before it sends.** The same check runs again for each call. If it ever fires, the
  gate missed something it had to catch: nothing is sent, the call and the steps after it are
  recorded as not sent (`driver_error`), a `call_blocked` event with `where: driver` is written,
  and the run is incomplete.
* **The stdio proxy of `run`.** A `tools/call` that fails the check is not forwarded. The proxy
  answers it itself, to its `id`, with a JSON-RPC error: code **-32050** (the implementation range
  of JSON-RPC, and none of the codes MCP or JSON-RPC define), the fixed message `Not sent to the
  server: the engagement does not allow this call.`, and `data: {"cause": …}`. The answer is not
  recorded as a message, since the server did not say it; a `call_blocked` event is, with `cause`,
  `tool` (cut to 128 characters and masked), `message_id`, `answered` and `batch`. Allowed calls
  go through byte for byte. A call without an `id` is not answered, but is blocked and recorded.

The proxy reads each line the client sends the way the server will, and passes on only what is
clear. Not passed on, and answered where there is an `id` (see below for a key given twice): a
message with a key given twice at its top level or in its `params` (the server's parser may keep
the first, the guard's the last); a
message whose `method` decodes to `tools/call` however it is escaped (`"tools\/call"`) and whose
tool is not allowed; a JSON array (a batch) holding any call that is not allowed (nothing of it is
forwarded, and each request in it is answered with an error; a response or a notification in
it is held back with the rest but gets no error, since only a message with a `method` and an `id`
is a request); and, under the cause
`message_unexamined`, a line longer than `--max-message-bytes` (counted as the recording counts
it: the newline is not part of the line, a carriage return before it is) or nested more deeply than a
message is read, which cannot be read in full, and a call whose tool name the guard cannot read
(`params` a list, or without a string `name`) when the file has `deny_tools` and no `tools`; with
`tools`, such a call is `tool_not_listed`. The tool is read after decoding, so `"re\u0061d"`
is `read`. A non-empty line that is not valid JSON is not passed on either: it is recorded under
`message_unexamined` and not answered, having no readable `id`. Valid means strictly decoded UTF-8,
without `NaN` or `Infinity`, and with nothing after the value (so a comment or a second object
makes it invalid). A carriage return inside a line is held back and recorded the same way, since
a server that reads universal newlines splits the line there; one directly before the line end
stays allowed. A line with a byte order mark is invalid too: RFC 8259 forbids a parser to add
one, some skip it, and the guard cannot know which the server does. A message with a key that is spelled otherwise than `method`, `params`, `id` or `jsonrpc`
but folds to one of them (`Method`, `ID`, `paramſ`), a `Name` in the `params` of a call, or a
`method` that folds to `tools/call` without being it (`Tools/Call`), is held back and recorded
as `message_unexamined`, since a server that matches keys without regard to case may read it
differently; an id under another spelling is no id, so such a message is not answered on that
account. A message with a key given twice, whichever key,
is held back and recorded, and it is answered by one rule: it is a request if any of its `method`
values is a string (`"method":"tools/call","method":null` is one), and the request is answered
only if all its `id` values are the same and valid (a string or a number), a single invalid `id`
(`null`, `true`, `[1]`, `{}`) included. With conflicting or invalid ids the proxy says nothing,
since any choice could hit another open request of the client. Without a key given twice, an
invalid `id` is answered with `null`. The same holds for an item of a
batch. Blank lines pass. Without a
guard (no file, or a file with neither `tools` nor `deny_tools`) every line passes as it always
did. `actions` stays what it is for `run`: it governs this tool's own scripts, not a client's
session, so `actions.call: false` does not stop a client's calls; only the three rules above do.
The guard's reading of lines, with its size limit, is for the path from a client to the server of
`run`; in `drive` the messages are the driver's own, built and not received, so the gate and the
driver's check are what hold a script's calls, and `--max-message-bytes` narrows only the
recording. **Over HTTP the guard is the driver's
only:** the HTTP proxy serves this tool's own driver, never a foreign client.

What a run records of the file: its id, its digest and its window
(`run_started.authorization.engagement`), `pacing` and `pacing_enforced` (section 4), whether it finished
after the window closed (`run_finished.window_exceeded`), and, for a run that was stopped, why
(`run_stopped.because`, below) — nothing else. Every refusal after the
file is read is written to `refusals.jsonl` in `--out-dir`. **One store per engagement**: a store
refuses a run made under another engagement, or under none.

`--mask-key` takes a field name only: a value with `=`, `:`, white space or a control character, one
without an ASCII letter or digit (after lower-casing), or one longer than 64 characters, is
refused with exit 2 before anything is written, and the refusal never repeats it (also with
`-q`). So is an abbreviation of the option with an `=` (`--mas=…`), which is caught before the
argument parser sees it. The recording runs each name through the masker too, but only what the
masker recognises by its shape is caught: a bare value such as `abc123def` cannot be told from a
field name.

**The end of a run: the window, the stop file and a signal.** What the tool does itself ends with
the window; what it only observes does not. A `drive` run (a script or a probe module) is asked
before every step whether it may go on: when the engagement's window has closed (`now` is at or
after `window.until`, the moment from which the gate refuses a run), or the stop file is there, or
the process was sent SIGINT or SIGTERM, no further step is sent to the server. Each step that was
not sent is recorded as `step_skipped` with the reason `run_halted`, the script's end is written,
and the server's child is ended with its process group, as at SIGTERM. The stdio proxy of `run` and
the HTTP proxy do **not** stop at the window's end: they go on forwarding and recording, as they
always did, and the closing event only says `window_exceeded: true`. The scope guard blocks
nothing for the window either. The stop file and a signal stop every kind of run.

A run that was stopped records `run_stopped` as soon as it knows, with `because` one of `signal`,
`stop_file` and `window_closed` (and `signal` holding the signal's name, or the same word for the
other two), and `run_finished.reason` is that word. For the verdict it is an interrupted run,
whichever the reason: incomplete, cause `interrupted`, the same as a run stopped by SIGTERM. Nothing
else in the judgement changes, and the reason is not a cause of its own.

**The stop file** is the kill switch. `engagement stop FILE [--reason TEXT]` makes `FILE.stop`
beside the engagement file (`acme.yaml.stop` for `acme.yaml`), mode 0600, holding JSON with the
time (UTC) and the reason, cut to 200 characters and masked like other text you type, with the
known values and the salt of the file. A file that cannot be read is stopped all the same, and
its reason is masked without them;
`engagement stop FILE --clear` removes it, and says so, with exit 0, when there is none. While it
is there:

* the gate refuses every run under the file (`stop_file`, a line in `refusals.jsonl`), and a
  fleet is refused whole;
* `drive` stops before its next step;
* the stdio proxy and the HTTP proxy look before they pass on each message of the client and at
  least once a second, and end the run in order as at SIGTERM, with the reason `stop_file`; a run
  that is only observed is stopped too. What was read before the stop stands in the recording as
  received from the client, a line not yet complete included, even though it did not go on to the
  server; the block of data in which the stop is seen does not go on and is not in the recording;
* a fleet starts no further run and stops the running ones, as at an interruption (the fleet's
  `interrupted` is `stop_file`).

The stop file lies beside the real engagement file: symlinks of the file and of its directories are
resolved, so every path to the file names the same stop file. Two hard links to one file have a
stop file each; stop by the path the runs were started with.

Repeating `engagement stop` replaces the file without a moment in which it is missing. `--clear`
frees only the runs that start after it: a run that has seen the stop file stays stopped.

A run looks for three stop files: beside the file resolved when it is loaded, beside the path as
it was given (not resolved), and beside that path resolved afresh at every check. Both of the
last two follow a link to a directory that is pointed elsewhere during the run; only the third
follows a link to the file itself.
Any one of them stops the run, so `engagement stop` over the path a run was started with reaches
it however often the link has been repointed. A path that cannot be resolved for any reason but
the file's absence stops too.
Hard links remain the limit: runs started by another hard link are not reached.

The tool only looks whether the file is there; it never reads it. A symlink, a directory or
anything else at that name stops too, and so does a place that cannot be looked at: when in doubt,
the run stops.

**Probe modules.** `drive --probe NAME [--probe-option KEY=VALUE …]` runs a module from
`mcp_kymograph.probes` in place of a script: an active test that makes its requests as it goes.
It needs `--engagement`, the module listed under `actions.probes` (`probe_not_listed` otherwise),
`actions.call: true` (a module acts), and no `--script`; without a file the run is refused as
`probe_without_engagement` (there is no file to write the refusal into). A module has a fixed name,
a description, `max_calls` (at most 64) and a method that makes requests through a context, and
never talks to the server itself. The context holds every request against the window, the stop
file and `max_calls` before it is sent (every page of a listing, and a request made again after a
broken response stream, is a request: a listing that the run's end overtakes stops with a
`run_halted` step that holds the pages it got); a call goes through the scope guard of the driver, and only
names a tool the server's own `tools/list` delivered in this run. A request that is not sent is
recorded as a step that was not (`run_halted`, `probe_calls_exhausted`, `tool_not_listed`), and
ends the module. The script limits (32 steps, 8 calls) are for scripts; a module has its own.
`run_started.probe` records the module and its options (masked), and each call is a `step_called`
as in a script. Before each request the context calls a pacing hook, which has no effect on the gap between a module's requests (no module of this version loads a server); the run as a whole is paced like any HTTP run (section 4).
The one module there is, `echo`, lists the tools and calls the tool `--probe-option tool=NAME`
once, with `{"text": …}` from `--probe-option text=…`; it exists to try the frame.

A run against an endpoint that wants a token names its identity, and sends the token the file
names for it, to that endpoint and nowhere else:

```sh
kymograph drive --engagement engagement.yaml --manifest corpus.yaml --entry customer-mcp \
  --identity reader --out-dir runs/acme
```

`run_started.auth` records `{identity, role, token_used, source: env|file|none, env_name, token}` and
never a value. `token` is what the run read of its own token (below), or `null` without one. Without a file, `--token-env NAME` or `--token-file PATH` (at most 16 KiB, visible
ASCII, one trailing line ending dropped) sends one token the same way. Under a file that declares
identities those flags are refused: with `--identity`, `token_source_differs` (the source is the
file's); without it, `identity_required`; under a file that declares none, `token_not_declared`;
an identity the file does not name, `identity_not_declared`. A token or a header value that cannot
be read is refused as `token`, naming the source (for a token file, `identity NAME: token_file`,
never its path) and never its content. A run that sends less than
the file declares (no `--identity`) is allowed; it can only see less. The value of a token and of a
secret header is blanked in everything the run writes, wherever it stands in a string: as it is
or percent-encoded in any mixture, each character as itself or as the `%XX` of its UTF-8 bytes in
either case of the hex digits; a number whose text holds it is replaced by the placeholder string. That holds for every field
the server controls: the `id` of a message wherever an event names it (an `intervention` and a
`rule_quarantined` included), and an error `code`, which has no room for a string and is written
as `null` instead. The value is recognised as a whole, in the forms named above: a server that cuts it
off (a connection that breaks in the middle of the value), puts it in a body that is not valid JSON,
or writes it in another encoding (`\/`, `\u00XX`, base64) is not covered, and no masker could
cover a server that knows the value and encodes it as it likes. A `401` or
`403` is recorded as `unauthorized` with the server's challenge parsed; the terminal says where the
server sends clients for a token (`resource_metadata`, not fetched) — this tool runs no OAuth flow.

Over HTTP the URL's host is the target: a scenario or a script that calls tools against a host
outside localhost needs `--engagement-confirmed`. The flag does not open plain HTTP: a plain
`http://` URL to anything but `127.0.0.1` or `[::1]` is refused before the gate is asked, with
reason `plain_http` in `refusals.jsonl`. An endpoint's version is what the operator
declared (`source.version_declared`), labelled *declared* wherever it is shown; its egress is not
observed; a deployment that changes under the same URL and version is not seen as a change, so
`store diff`, `engagement recheck` and the report say *server unpinned* beside every finding new
or gone between two runs of an endpoint.

A session through the customer's client (`kymograph run --engagement …`, docs/clients.md) is
recorded but not filed: a session is not reproducible. It enters the bundle through
`evidence pack --session`.

### Personal data in what a run writes

Three shapes that are unambiguous, and the engagement's `known_values`, are replaced by a pseudonym
when a recording or a refusal is written. Nothing else is guessed at, and no pattern comes from the
user. This is a fourth rule beside the handles, the keys and the credential shapes, applied
wherever the literals of a run are: headers, bodies, error texts, the events of a stream, JSON keys,
the query of a URL, the server command line. In this order:

1. the run's literals (tokens), as `***REDACTED***`, as before;
2. the known values;
3. the three shapes;
4. the other text rules (credentials in URLs, `Bearer …`, `name=value`).

A pseudonym is `***EMAIL-<12 hex>***`, `***IBAN-<12 hex>***`, `***TEL-<12 hex>***` or
`***KNOWN-<12 hex>***`, flanked like a protocol handle. The hex is the first 12 digits of
HMAC-SHA256, keyed with the salt, over the kind (`email`, `iban`, `tel`, `known`), a NUL and the
canonical value: an address in lower case, an IBAN without spaces in upper case, a `tel:` URI and
a known value as written. The same value is the same pseudonym, however it was written.

**E-mail addresses.** `local@host`, replaced whole or not at all; no part of the name stays.

- *Local part* (at most 64 characters): letters, digits and combining marks (category M) of any
  script (RFC 6531), and `.`, `_`, `+`, `-` and the apostrophe (`'` and the typographic `’`).
  Any other character, the rest of the `atext` of RFC 5322 (``!#$%&*/=?^`{|}~``) included, ends the
  local part. A `.` or an apostrophe at its start is not part of it: in `'alice@corp.example'` and
  `’alice@corp.example’` only the address is replaced and the quotes stay. At its end it is part
  of it: `alice.@corp.example`, `alice..b@corp.example` and `bob'@corp.example` are no addresses by
  the RFC, but they tell the name, so they are replaced whole, as `email`. `O’Brien@corp.example`
  is one address. Longer than 64 characters: no address.
- *Host*: at least two labels of letters, digits and combining marks of any script and hyphens
  (each 1 to 63 characters, none starting or ending in a hyphen), at most 253 characters in all;
  the last label is letters only (at least 2, in any script) or Punycode (`xn--…`). A `.` after the
  host belongs to the sentence.
- *Quoted local part*: not recognised. `"bob smith"@corp.example` stays as it is. A safe reading
  would need a parser, such addresses are rare in traffic, and a quote taken as an opener would
  swallow text across string borders: `{"user":"@max.mustermann"}` and
  `name="Max" handle="@max.mustermann"` stay whole. This is a limit, not a feature.
- *No remainder*: where a letter, a digit or a combining mark stands directly in front of the start
  found, the replacement starts at the start of that run. `Zoë.O'Brien@corp.example` is one address. The
  run never reaches over a `"`.

`rene.beispiel@kunden.example`, `jürgen.mueller@firma.example`, `rené@kunden.example`,
`o'brien@firma.example`, `O’Brien@firma.example`, `a@münchen.example`,
`a@xn--mnchen-3ya.example`, `Name <a+tag@corp.example>` and `mailto:a@corp.example?subject=x` are
addresses. Not addresses: `user@localhost` and `a@b` (no dot), `a@b.c0m` and `a@münchen.12` (the
last label is no word), `@handle`, and the `@` in `https://h/@52.5,13.4/` or `https://h/p@x`.

Because `=`, `&`, `/`, `:` and the like end the local part, the key in front of an address
stays: `contact=alice@corp.example` keeps `contact=`, `?email=alice@corp.example&x=1` keeps
`?email=` and `&x=1`, and `mailto:alice@corp.example` keeps `mailto:`. The limit, stated plainly:
in `a&b@corp.example` the `&` ends the local part, so `a&` stays and `b@corp.example` is replaced.
That is rare; the rule "no remainder" lengthens a replacement over letters, digits and combining
marks only. A known value inside a local part is replaced first, and its pseudonym ends the local
part (`*`): `***KNOWN-…***@corp.example` is left, the name is gone, and only `known` is counted.

An address and a known value are also found percent-encoded (`%XX`) and in JSON escapes
(`\uXXXX`, as a server writes a log with `ensure_ascii`): replaced whole, under the same
pseudonym as the plain form, and counted once. `\uXXXX` is read everywhere, in a header, a query
and a path too. `%XX` is read there as well, but a header, which is kept as written, blanks a value
that only a percent-decoding shows (`a%40b.test`) whole. Other encodings, such as HTML entities or
quoted-printable, the tool does not read.

**`user@host` in SSH URLs.** The account in front of a host is not a person.
`git@github.com:org/repo.git` (and `u@host:~/x`, `u@host:/srv`) is the SCP-style form: the host is
followed by `:` and a path whose first segment is closed by `/`. It stays as written.
`alice@corp.example:bob@corp.example` and `alice@corp.example: thanks` are addresses, as no path
follows. `ssh://git@github.com/org/repo` has user information in a URL, which the rule for URLs
replaces as a credential, as before: `ssh://***REDACTED***@github.com/org/repo`, one redaction. The
address rule does not see the `@` of user information, plain or written in an encoded form, so it
never turns `https://u:pw@host.example` into a pseudonym with a user name left over.

**IBANs.** A country of the SWIFT IBAN Registry (`masking.IBAN_LENGTHS`, closed), two check
digits and the length that country prescribes, a valid check (mod 97, check digits 02 to 98), in
capital letters only: the electronic form of ISO 13616 (no spaces) or the print form in groups of
four separated by one space (the last may be shorter). It must not touch a letter or a digit.
An IBAN in lower case is no match. A 22-digit order number, a hex id in lower case such as
`ad6600000000000000000000`, an IBAN-shaped string whose check fails, one character too short or
long, or in uneven groups stays. A country added to the registry later is not recognised until it
is added to the list (`masking.IBAN_LENGTHS`: SWIFT IBAN Registry, Release 99, December 2024,
checked against copies, not the original).

The limit, stated plainly: an id in capital hex that begins with a country code made of the
letters A to F (AD, AE, BA, BE, DE, EE), has that country's length (16 to 24 characters), two
decimal digits after it and a valid check is read as an IBAN. For a random id of such a length that
is about one in 64 000. Servers that write their ids in capitals and in those lengths are rare;
the pseudonym would replace an id in the recording, and the count would be one too many.

**`tel:` URIs.** `tel:` in either case, not behind a scheme character (`hotel:` is none), then a
number that starts with `+` or a digit and holds a digit, with `-.()`, `*`, `#` and parameters
(`;ext=12`), up to white space or a quote; a `.`, `,`, `;` or `!` at the end belongs to the
sentence. `tel:+49-30-1234567` is one; `+49 30 1234567`, `030/1234567` and `tel: +49` are not.

**Not a shape.** Phone numbers without `tel:` and card numbers (Luhn passes every tenth
sequence of digits) are replaced only as `known_values`. Resource ids (UUIDs, numbers, hex,
Base64), timestamps (ISO 8601, epoch seconds and milliseconds), order numbers and versions such as
`2025-11-25` stay byte for byte.

**Known values** are replaced wherever they stand, as written or percent-encoded once, whole or in
part, with the hex digits in any case, also as a part of a longer string; the longer of two overlapping values wins. **A JSON number**
whose text (as `json.dumps` writes it) holds a known value is masked as that text would be if it
had been quoted, and written as a string: whole (`123456789` for `known_values: ["123456789"]`
becomes the pseudonym) or in part (`91234` for `1234` becomes `9***KNOWN-…***`), in a reply or in
an argument of a script, the same text `evidence pack` makes of the number in a placed script. It
is counted in `replacements` but, like a string, not declared in a message's `redactions` and not
a server redaction; a number that holds no known value stays a number, and `true` and `false` are
no numbers. The three shapes do not apply to a number: a long integer is mostly an id or a time,
not a phone number. A short known value is found in long numbers too (`1234` in a timestamp or an
id of the traffic), and those are then written as strings: list values long enough to be the
customer's. A message that is also masked as text (a line that is no JSON) replaces the digits as
part of the text, with the same pseudonym. In a header or a query, a value
that only a further decoding shows (`%2520`, or an address as `a%40host.example` in a header) blanks
the header whole (`***REDACTED***`): the form kept cannot be trusted. Each value found in it counts
once for its kind (the replacement happened, only as a blanking), and nothing counts twice:
`X-A: a@corp.example b%40corp.example` is two `email`. The blanking is not a server redaction and
no path of a credential's redaction: `server_redactions` stays 0, unless the header also held a
credential. In a URL path that the file lets be written as it is, a value that only a decoding
shows (`tel:%2B4930…`) is replaced where the path is written, by the pseudonym in place of the
decoded path, and counts once. The path stays as written exactly when masking it and then decoding
it gives the same as decoding it and then masking: `/call/tel:+49-30-1234567/a%20b` becomes
`/call/***TEL-…***/a%20b`, but `/users/j%C3%BCrgen@x.example` is written decoded, as
`/users/***EMAIL-…***`, since the encoding cuts the address in two as written; a credential in a decoding blanks the path, and no personal data in
it is counted.

**The salt.** Under a file of version 2 the salt is the value of the environment variable
`salt_env` names, read as bytes (a byte that is not UTF-8 stays that byte), and is never written: it is a literal of the masker as well, so no
recording, refusal, store, report or bundle holds it. A run is refused at the gate — one line in
`refusals.jsonl` — when the variable is not set or is empty (`salt_missing`), or holds fewer than 32
characters (`salt_too_short`); the words name the variable and never its value, and nothing of the
traffic is written before the refusal. A salt the gate does not take is not made a literal of the
masker, so the refusal still names its variable whole (`KYMOGRAPH_TEST_SALT`, not
`KYMOGRAPH_TEST_***REDACTED***` for a salt `SALT`); a salt it takes is. The pseudonyms are
then the same in every run under the engagement and different under another. Under a file of
version 1, and without a file, the salt is drawn for the run, like the handles' salt: the
pseudonyms hold inside one recording only. `run_started.pseudonyms` says which, `"per_engagement"`
or `"per_run"`. (A run under a version-1 file keeps a salt of its own per run and is not refused without
`salt_env`; `engagement.SALT_REQUIRED_VERSIONS` is the one place that says which versions are.) The handles keep their own
salt, the run's, unchanged.

**Names.** Do not name manifest entries and scenarios after the customer. `server_name` and
`scenario_name` are the operator's and stand unmasked in `run_started` (masking them would break
`store ingest`, which compares them with the reproduction triple), so a run under a file is
refused before it starts (exit 2, `name_holds_known_value` in `refusals.jsonl`, no run directory)
when either holds a known value or a literal of the run, as written or percent-encoded once, whole
or in part, with the hex digits in any case. The words name the field, never the value.

The engagement `id` is such a name: it stands unmasked in `engagement_id_declared` of every
refusal and run, in the store and in the bundle. A file whose `id` holds one of its `known_values`
(compared as written, case-sensitive like the masker) is refused when it is loaded, by every
command (exit 2, nothing in `refusals.jsonl`); the words say `id: holds known_values[2]`, the index
and never the value or the `id`. `engagement intake` refuses an `--id` that holds an answered
known value the same way and writes no draft.

`fleet run --engagement` holds the manifest to the same rule, for every entry and scenario in it,
before the gate, the store and the images: exit 2, `name_holds_known_value`, the words name the
place in the manifest (`the name of entry 2`, `the name of scenario 1 of entry 2`), never the name.
A refusal of the fleet is masked as a run's is, with the known values and the salt, wherever the
value stands: in a name, in `--manifest`, `--out-dir` or `--store`.

**Paths.** Under `--engagement`, a run or a fleet is refused (exit 2, `name_holds_known_value`)
when a name (entry, scenario), the path of `--manifest`, the path of `--out-dir` or the scenario path holds a known value
or a literal of the run, in any percent-encoding as above. The scenario path is the text written to `authorization.scenario`: the
value of `--scenario`, or, in a corpus run, the manifest's scenario as a resolved absolute path,
so a working directory or a symlink that holds the value counts. These values stand unchanged in
the artifacts, because the store and the bundle read them again. Whoever keeps the customer's
files in a directory named after the customer starts the run from a neutrally named directory, or
through a neutrally named path. The names of entries and the paths are checked before the
gate and before the images are asked for. In a corpus run this includes the scenario's name,
which the manifest gives. With a plain `--scenario` the name stands only once the file is read,
which happens after the gate: it is checked right after that, before the engagement file is
held against the run and before the images are asked for. The name that the reproduction triple
records for the scenario is looked up by digest and can differ from the selected one (two files
of the same bytes); it is checked as well, once the triple is built. `--out-dir` is refused
because the store holds the path of each recording (the column `recording`, and `result.problems`
where filing is refused). The limit: `store ingest` does not know the values of the file and so
does not check a path that the operator put there on their own.

**The count.** `run_finished.replacements` is the number of values replaced per kind
(`email`, `iban`, `tel`, `known`), every kind listed. The engagement report names it per run, as
numbers only. They are not part of `server_redactions`: a pseudonym is substituted by design, and
no credential was let out. A value counts once, in the payload of the message that holds it. An
event that names a part of a recorded message again does not count it, and neither does what a
rule writes in its place. What a person typed (a script's arguments and variables, a probe's
options, a tool's name in an event, the command line) is not a message and does not count either.

### What a run records of its token

A run that uses a token (`auth.token_used`, from `env` or from a file) reads it with the token
inspector (docs/token-inspector.md) before `run_started` is written, and `run_started.auth.token`
is the view: `claims`, `pseudonyms`, `readable` (with `reason` if not), `unexpected`,
`other_claims`, `warnings`, and `expired` (`true`, `false` or `null`, by the clock at the start of
the run). Never a byte of the token is written: not the value, not a part, not its signature.

- The readable claim values (`aud`, `scp`, `roles`, `azp`, `appid`) pass the masker as any other
  text: literals, known values, the three shapes. An address in `scp` is a pseudonym. Each value
  is masked in full length, with the run's masker, and only then clipped to 256 characters (64
  entries of a list); a clip may cut a placeholder or a pseudonym, never an unmasked value. The
  `truncated` warning stands when a value was longer than the limit before or after masking. The
  recorder masks nothing a second time and refuses a view that was made without a mask.
- `tid`, `iss`, `oid`, `upn`, `email` and `name` are pseudonyms of the kinds `tenant`, `issuer`,
  `object`, `email` or `account`, and `name`, in the format `***<KIND>-<12 hex>***`, under the
  personal salt above: the engagement's under a file of version 2, the run's otherwise. For
  `email` the canonical value is lower case, so a `upn` that is an address seen in the traffic has
  the pseudonym of that address.
- A token the inspector cannot read is `readable: false` with a reason. The run goes on, without
  a warning.
- If `aud` is Microsoft Graph, the run writes one line to stderr when it starts: `warning: the
  token of identity <name> is for Microsoft Graph (aud), not for the server under test` (`the
  token` without an identity). The line names no claim value.
- A token that a client sends through `kymograph run` (the passive run) is not read. It stays
  `***REDACTED***`, as before.
- Under an engagement file the masker of a run holds the token and the secret headers of every
  identity of the file as literals, read from the sources the file names (`token_env`,
  `token_file`, `headers`), so that a server which hands back the token of another identity, from
  an earlier run, does not put it into an artifact: as a number, as part of a string or
  percent-encoded. The chosen identity must be readable, else the run is refused. Of another
  identity, each value is read on its own, a `token_file` under the same checks as the chosen
  identity's: only a single value that cannot be read at that moment is passed by, with no
  message that names it or its path, and every other value of that identity still counts. A token
  that is not readable at the start of a run cannot be replaced in that run. Only the chosen
  identity is sent; the other values serve the masker and go nowhere else.

### Comparing the answers of two identities

```sh
kymograph engagement compare RUN_A RUN_B [--json]
```

Two driver runs of one engagement and one script, made as two identities (`--identity`), side by
side. The command reads the two recordings (`events.jsonl`, or the run directory), sends no request
and writes nothing. It prints, first, the state of both runs, then the two identities and roles
from `run_started.auth`, and the sentence "an observation, not a severity": there is no severity,
no verdict, and no reading of whether a difference is wanted.

- **Per tool call**, for A and for B: the result (`ok`; `rpc_error` with its code, shown only if it
  is an integer from -32768 to 32767, else `rpc_error (code not shown)` and `code: null` in `--json`; `http_401`;
  `http_403`; `http_other` with the status; `no_answer`; `answer_not_linked`; `not_sent`), whether the two answers are `same`,
  `different` or `not_compared` (on the canonical JSON of the recording, so after masking), and, for `different`,
  the first place that differs, written like the inspector's locator, except that a list item is
  always its index (`result.content[0].text`; `""`, shown as "the answer as a whole", where one
  side has no JSON answer). A key of the answer stands in the path only if the MCP schema has it
  (`CallToolResult` and its content kinds, the contents of a resource, the JSON-RPC error);
  every other key is `*`, and so is every key below `structuredContent`, `_meta` and
  `error.data`, whatever it is called. Never a value from an answer: not the text, not a key
  the server chose, not the uri of a resource, nothing a pseudonym stands for. A line for a step
  that a run did not send names the state and causes of each run that did not.
- **An answer the recording does not tie to its request** is not compared. If a `GET` names a
  `Last-Event-ID` that no earlier message carries (a priming event, which holds an event id and
  no data, is not in the recording) and a message with the request's id stands only there or in a
  `GET` that continues one of these, over any number of steps, the result is `answer_not_linked`, the row says `not_compared` (neither `same` nor `different`, no
  place), and nothing of that message is read or shown; the status of the request still comes first.
  This holds against a step the other run did not send as well (`not_sent`): the row says
  `not_compared`, not `different`. Where both runs did not send it, it stays `none`.
- **Per list** (tools, prompts, resources, all pages): the names only A sees and the names only B
  sees. A resource is named by its `uri`, the other two by their `name`. Names are the server's
  identifiers, and go through the same filter as every name on the terminal; at most 100 of each
  are shown, the rest is counted.
  A list counts as read in a run only if its last page was answered without a `nextCursor`; if
  either run stopped short of that (page limit, a page never answered, a listing that does not
  follow cursors), the line says `not compared: incomplete in A` (`B`, `both`) and names nothing
  (`--json`: `compared: false` with the reason), and the exit status does not change.
- **A run that is not a result** (`incomplete`, `server_failed`, `call_failed`, …) is compared
  all the same, and both states come first. The exit status is that of the gravest of the two
  (3, 4, 5, 6), and 0 for two complete runs.

Refused, with exit 2 and one line on stderr that names the reason and never a value:

| reason | meaning |
| --- | --- |
| not the same engagement | the id or the digest of the engagement file differs, or a run was made under none |
| different scripts | the script digests differ, or only one run has a digest, or both runs name a script (`run_started.script`) and the names differ; where neither run has a digest, the tool of a step both runs sent differs (only those steps are compared) |
| the same identity | both runs name one identity |
| no identity | a run named none (no `--identity`) |
| pseudonyms last a run only | `run_started.pseudonyms` is not `per_engagement` in a run: the pseudonyms of the two runs are not the same values |
| step N differs | the n-th step, sent by both runs, has another tool or other arguments (compared on the masked JSON) |

A step is a step of the script: a tool call. The handshake, the discovery request and the
listings are the driver's, are not counted, and the lists are compared for themselves. The driver
records no step number, so the steps are counted in the recording: each `tools/call` it sent and
each one it recorded as not sent (`step_skipped`), in order. After a failure of the driver, the
recording holds a `step_skipped` for every step of the script, the ones already sent too; the
number of those entries for `tools/call` is the number of calls in the script. The steps seen
before keep their numbers, and the numbers up to that count that were not seen are `not_sent`.
After the scope guard refused a call (a `call_blocked` with `where: driver` stands before), the
driver records a `step_skipped` with `driver_error` only for the refused step and the ones after
it, never for the ones sent: there each such entry is a step of its own, not sent, and takes the
next number.

A wait for a `Retry-After` keeps a step one step, in whichever run it fell. A `tools/call` that the
driver sends again after the wait (a `paced` with `retry_after`, then the same id) is that step, and
its last answer is the step's. If the run stopped in the wait, the step is `not_sent`.

A line of the recording that cannot be read (not JSON, nested too deeply, not an object), with a
line that is not empty after it, is refused: a step on it would be lost and every later step would
move up a number. The refusal says `run A holds a line this version cannot read, before its end:
the steps after it could not be counted` (`B` likewise) and shows nothing of the line. The last
line that is not empty may be unreadable: that is a run cut off while it wrote, nothing moves up
behind it, and the run is compared, `incomplete` with the cause `line`.

That holds for a damaged line. Whoever deletes a line altogether, instead of making it unreadable,
moves the steps up unnoticed: the comparison does not guard against a recording edited on purpose
(whoever deletes a line deletes a step too), and the digests are there for that.

A run that stopped early (a `403` that ends the script, say) is not refused. The comparison runs
over all steps of the longer run; for a step one run never sent, that side's result is `not_sent`,
with the state and causes of that run from its verdict (`incomplete`, `server_failed`, …), never a
value. The check that tool and arguments are the same applies to steps both runs sent.

An answer belongs to a request only if it stands after the request in the recording (`seq`) and, over
HTTP, in the same `exchange` or in one that continues it (a `GET` whose `Last-Event-ID` equals, as
recorded, the `event_id` of the last earlier message, which stands in the exchange continued); of
several, the first counts. A continuation the recording does not show does not count.

### Token observations

An identity of a file of version 2 may carry `observation`, one of `foreign_audience` (a token
issued for another audience), `expired` (an expired token the agency provides) or `no_token`.
`no_token` requires `token: none`; the other two require `token_env` or `token_file`. Any other
combination, and any other value, is refused naming `identities[n].observation`, without the
value. In a file of version 1, `observation` is an unknown key. `engagement show` names the mark
of each identity.

```yaml
identities:
  - {name: wrong-audience, role: token for another API, token_env: ACME_OTHER_AUD, observation: foreign_audience}
  - {name: stale, role: expired token, token_file: secrets/stale, observation: expired}
  - {name: anonymous, role: not signed in, token: none, observation: no_token}
```

A run as such an identity is an observation. It is `drive --script FILE --identity NAME` as any
other run, through the same gate, scope guard and pacing; the script decides the opening, the
listings and the one reading call the file releases.

- `run_started.auth.observation` holds the mark, `null` without one.
- Each request the run sent is recorded as the server answered it, in one `token_observation`
  event at the end of the run, before `script_finished`: `kind`, and `exchanges`, a list of
  `{role, method, accepted, http_status, rpc_code}`. `role` says what the request was within
  the run: `opening` (`initialize`, or `server/discover` in the new era, where it is the opening),
  `era_probe` (`server/discover` when the run goes on to send `initialize`, that is in the old
  era), `list` or `call`; in the run of a probe module (`drive --probe`) the requests after the
  opening are `probe`.
  `accepted` has three values. It is `true` only for a 2xx with a valid JSON-RPC result to that
  request: a `result` and no `error` key. An `error` beside a result, even `"error": null`, makes
  it `null`, as the recording's own reading of messages takes any answer with an `error` for an
  error. It is `false` for a 401 or 403, always and without exception: also when the body
  stalls, breaks off, is no JSON or holds a result. It is `null` in every other case: no answer
  at all, another status (400, 404, 429, 500, …), a 2xx with a JSON-RPC error, a 2xx without a
  valid result, a 2xx with a result and an `error` beside it; `http_status` and `rpc_code` then
  say what came.
  `accepted` is about the token, not about what a call did. A `tools/call` answered with both a
  result and an error is `null` in `token_observation`, while the run's step reads the answer as
  the SDKs do. A result object decides as for any call (a tool error where it says `isError:
  true`), and the error beside it adds no `call_failed` of its own. Without a result object, an
  error object decides: the step records `call_failed` with `rpc_error`. With neither (a result
  that is `null` or a string beside an error that is `null`, a string, a number or a list), the
  answer cannot be read: the step is unanswered with `answer_unreadable`, and no `call_failed`
  is recorded. `http_status` is the
  status when it is between 100 and 599, else `null`. `rpc_code` is the `error.code` of a JSON-RPC
  error answer, and for a 401 or 403 that of its body when the body is a JSON-RPC error object
  with a whole number there; it is a number only within 2^31 and when no value of the run (a
  token, say) stands in its decimal form, else `null`. Nothing else of the body is read or kept.
  The era probe on a legacy server, answered 400 for the method it does not know, is `null`: it
  says nothing of the token.
- The body of a 401 or 403 is read only under `observation`, and only for `rpc_code`, with a time of
  its own: at most 2 seconds and never longer than the rest of the step. A body that does not
  arrive whole in that time, or is no JSON-RPC error, leaves `rpc_code` `null`; the refusal
  stands as it was known from the head. Without `observation` the answer ends at the head.
- A request that was sent again after a `Retry-After` (429 or 503) is one entry, with the answer
  to the repetition. The first answer is in the `paced` event (`why: retry_after`, `status`).
- For `expired` the event also has `expiry`: `expired` if `auth.token.expired` is true,
  `not_expired` if it is false (the run goes on, and the output says so), `not_checkable` if it is
  `null`, an opaque token (the output says: expiry as declared by the engagement, not checkable).
- The event holds no token, no header value and no claim value.
  A token comes into no artifact in any form, not even as a number: a digit token the server
  reflects as a JSON number is written as `***REDACTED***`, like one in a string.
- At the end `drive` writes one line per exchange to stdout: method, role (`era_probe` is followed
  by `(era detection)`), `accepted`, `rejected` or `neither` (for `true`, `false` and `null`),
  `status N`, `code N` (tab separated; `-` for none), or `no answer` in place of the last four
  when nothing answered. On stderr it says nothing about the refusal:
  the hint to obtain a token that a run without `observation` gets is not given. The tool does not say whether the result is
  good or bad: that is for the examiner.

**A 401 or 403 is the result here, not a failure.** The run ends at that exchange. It writes no
`server_failed` and no step with `unauthorized`; the steps after it are recorded as skipped with
the reason `observation_rejected`, not left out, and the script's `inventory` is `none` (the
opening was refused) or `partial`. Under rule 14 of the verdict such a run is `complete`, and the
steps skipped for that are no gap. Rule 14 goes before the check for silence: a refusal with no
body byte (a body that stalls, `Content-Length: 0`, an HTML body the channel does not read) is
the usual answer of a real server, and does not make the run `server_failed`
(`server_silent`). That holds only when `observation` is set, `token_observation` has an exchange
with `accepted: false` and the status 401 or 403, and a step was skipped as `observation_rejected`. The same holds for `drive --probe`: when the module's
request is rejected, the rest of the module is recorded as one skipped step `probe` with the
reason `observation_rejected`. Every other cause (a timeout, `rate_limited`, a connection that
broke off) stands as before. A run as an identity without `observation` that meets a 401 or 403
ends as `unauthorized`, as always.

The exit code of `drive` follows the state: for such a run it is 0, and the silence the proxy
counted is not added to it. This is read from the recording the run has just written. If its end
never reached the disk, the condition does not hold and the silence counts as before.

## 5. Review: walking through the findings together

```sh
kymograph store findings --store acme.sqlite --provenance real-world   # with each finding's id and key
kymograph store triage set --store acme.sqlite --finding 7 --role operator \
  --status confirmed --author "A. Operator"
kymograph store triage set --store acme.sqlite --finding 7 --role customer \
  --status intentional --author "C. Customer"
kymograph store triage list --store acme.sqlite [--history]
kymograph store history --store acme.sqlite --server customer-mcp
```

A decision is a row keyed by the finding's identity (the key without its two version fields), with
a role (`operator` or `customer`), a status and a required author — never taken from the
environment. The tool keeps no rationale and no severity: `--rationale` and `--severity` are
refused (exit 2, nothing written), and the score and the reason for a decision belong in the
operator's private notes (`operator-notes`: a CVSS 4.0 vector, a status and the reason per
finding), which the tool never reads and never copies into a store, a bundle or a recording. Statuses: `open`,
`confirmed`, `false_positive`, `accepted`, `fixed_pending_recheck`, `question` (both roles),
`intentional` (customer only), `fixed` (operator only). A row is never changed or deleted; a
later row of the same role supersedes the earlier one, and both roles' current rows stand side
by side. The web interface's review mode shows one finding at a time: each role's current row
first, as `store triage list` prints them, and every earlier row behind a toggle that is off when
the page opens and says so — the customer sees there is a history and can ask for it —, with the
complete `store triage set` line to copy.

A store made by an earlier version is refused whole, its triage included. What a person wrote
into it is carried, not lost: `store triage export --store OLD --out triage.json` reads of a store
of schema 11 or 12 only the triage and the engagement; then into a new store, after `store
ingest --engagement FILE` of the same recordings (each version of the file in order), `store
triage import --store NEW triage.json` puts every row back with its author, role and time, all or
nothing, and the store records that they were carried. Each carried row says so wherever it is
shown — `store triage list`, the web interface, the report's assessed sentences — with the
SHA-256 and schema of the store it was exported from, the export file's SHA-256 and the time of
the import, so that a decision can be asked about in the store it was made in.

Store schema 13 dropped the rationale and the severity, so this step is also where a store of 11
or 12 loses them (their triage tables are the same, and the export reads either): the export does
not write them (it says how many of each were left behind, on stderr), and an export written
before 13 is imported without them, with one line giving the numbers. Keep them in the
operator's private notes.

### The operator's notes and the finding key

The operator's notes are the operator's own, and the tool never reads them: no report,
attestation, status, bundle, export or web view takes anything from them, and a test holds every
module of the tool to that. They lie beside the store, named after it — the store's file name,
`.operator-notes` and `.yaml`, `.yml` or `.json`, the suffix in any case (for `acme.sqlite`,
`acme.sqlite.operator-notes.yaml`) — so that `engagement purge` deletes them with the store, by
their name and without opening them, and `purged.json` names each file it found as deleted, under
its own name (`….operator-notes.YAML` too); notes kept anywhere else, or under another name, are
the operator's to delete. The operator's assessment reaches the customer only as a part
of the report the operator writes and signs, apart from the generated part. The notes name each
finding by its **finding key**: `fk-` and the first 16 hex characters of the SHA-256 of the finding's
identity — the five fields a triage row is keyed by (server, scenario, statement, locator,
signal), without the two version fields, as the JSON list the store keeps. The key is the same
under every version of the server, so the notes name the same finding at its new version.
`store findings` and `store triage list` print it as `finding_key`, and the web interface's
Triage view shows it as text, to copy into the file. The report does not carry it.

```yaml
engagement: Acme MCP review          # invented values throughout
findings:
  fk-0123456789abcdef:
    cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    status: confirmed                # open, confirmed, false_positive, accepted, partially_fixed, fixed
    rationale: |
      Reachable without credentials; the description changes what the model is told to do.
```

A key in any other form (`fk-` and exactly 16 lowercase hex characters) is refused, with the file
and the place, and the whole file with it, by `mcp_kymograph.operator_notes.load`, the format's
checker; no command of the tool calls it.

## 6. Re-check: the customer says it is fixed

```sh
kymograph engagement recheck --store acme.sqlite --engagement engagement.yaml \
  --runs runs/acme --all-fixed-pending                # the commands to run, nothing run
# … run the printed drive command, then store ingest the new recording …
kymograph engagement recheck --store acme.sqlite --engagement engagement.yaml \
  --runs runs/acme --all-fixed-pending --after <run>  # what that run showed
```

The re-check runs nothing. A finding is `gone` only when the re-check run is complete and does
not sight it, `unchanged` when it still does, and `not_proven` otherwise — a re-check run that
is not a result proves nothing, and the command says so (exit 3). For each outcome it prints the
`store triage set` line that records it. Findings the re-check run sights for the first time
are listed as new, to be triaged from `open`. On an endpoint, whose version is only declared,
`gone` and the new ones carry *server unpinned* beside them: the deployment may have changed
under the same URL and version.

## 7. Close-out: hand over, attest, and end

```sh
kymograph report --engagement engagement.yaml --store acme.sqlite --runs runs/acme \
  --out-dir runs/acme --manifest corpus.yaml --out report.md
kymograph evidence pack --engagement engagement.yaml --store acme.sqlite --runs runs/acme \
  --report report.md --out evidence/acme-2026-11
kymograph evidence verify evidence/acme-2026-11 --index-digest <hex>
kymograph evidence review evidence/acme-2026-11
kymograph evidence redact evidence/acme-2026-11 --engagement engagement.yaml \
  --store acme.sqlite --out evidence/acme-2026-11-handover
kymograph engagement attest --store acme.sqlite --engagement engagement.yaml \
  --runs runs/acme --bundle evidence/acme-2026-11 --out attestation.md
# … on retention.delete_after …
kymograph engagement purge --store acme.sqlite --out-dir runs/acme --author "A. Operator" \
  --out purged.json
```

* **The report** (`report`) is Markdown in seven sections, every sentence marked `[recorded]`,
  `[derived]` or `[assessed]`; real-world findings stand apart as candidates for responsible
  disclosure; a run that is not complete is named so wherever it is used (exit 3); nothing in it
  is prose about impact or risk. It says how many literal redaction patterns the engagement
  defines, never what they are.
* **The bundle** (`evidence pack`) holds every filed recording as written, the scenarios,
  manifests, refusals, the file without what has no place in something handed on, a copy of the
  store, and the report — each listed in `index.json` with its SHA-256. `evidence verify` checks
  every file against the index: one changed byte makes the bundle not intact (exit 3).
  The engagement file in it is the sanitized copy; the operator's own file is never in a bundle.
* **The script of a driven run** has the role `script`. A recording names its script file by
  digest (`script_digest`) and by name, not by path, so `evidence pack --script FILE` (repeatable)
  gives the files and each is matched to the runs by that digest; a file that matches no run
  refuses the pack (exit 2). A run that used a script file whose file is not given has no entry:
  `pack` says so on stderr, one line per run, and packs all the same. A run of a built-in script
  has none to give.
  The file is placed **with the customer's values replaced**. `pack` reads it as the tool reads a
  script (a document, YAML or JSON by its suffix; a file that is no script refuses `--script`,
  exit 2, naming the field) and masks it in two layers.

  **Drive's masking is the floor.** Every call a run sent is in its recording (`step_called`):
  the tool, the arguments and the check (masked as text, like a string of the arguments), as
  `drive` masked them when the run was made. `pack`
  aligns each call step of the script with the calls each of its runs recorded, in order: the
  calls a run sent are the script's call steps in order with some left out (a step skipped, the
  run halted), and every order-keeping choice in which each pair has the same shape and the same
  values, but for what either side holds masked, counts; a string of the script with a
  placeholder (`{fixture_dir}/x`) matches whatever `drive` filled in. Wherever a run's recording
  holds a key or a value with any masked form in it (the placeholder, a pseudonym, any other
  `***…***`), the script keeps that key or value only if it is exactly what the recording holds;
  otherwise the whole key or value is blanked, even where `pack` masked a part of it itself (a
  token rotated since the run beside an address both masked). The same holds for the tool's
  name, the `check` and the script's `name` (`run_started.script`); a string with a placeholder
  whose filled text holds anything masked is never exactly that text, and is blanked whole. Where
  the recording holds a position unmasked, the script keeps what `pack` made of it. Pseudonyms
  made with another salt than the script's (a `per_run` run) are not exactly the same either, and
  blank the value: a value the script needs may then be gone, and a name blanked makes the script
  `replayable: false`. A call step no run recorded as sent (skipped, the run halted before it,
  or one whose arguments were too deep to record) has its arguments blanked (`{}`) and its tool's
  name blanked, and the script is `replayable: false` with `not_replayable`
  `steps[N].call: sent in no run`. A run that
  recorded more calls than the script has call steps, calls that match no choice of steps, a
  script name that is neither the recorded one nor masked, or a recording whose calls cannot be
  read refuses the pack (exit 2, naming the run and the step, never a value). So what `drive`
  replaced at run time stays replaced, whatever changed since: a token rotated, an identity taken
  out of a newer engagement file. Only `arguments`, the tool's name, `check` (a path into the
  answer), `timeout` (seconds, 1 to 120) and `name` of a script can hold a value at all; the
  recording holds the first three of each call sent, and `name`.

  **On top, the engagement's masking as it is now**, the masking the recorder applies to
  arguments: secret keys (`password`, `token` …), every secret header name as a key, and the
  mask keys — the engagement's `mask_keys` and every `--mask-key` the script's runs were given
  (their `inputs.mask_keys`, all runs together) — lose their values; the literals are blanked:
  the token and every secret header value of **every identity of the engagement file as it can
  be read now**, and the salt; the known values, e-mail addresses, IBANs and `tel:` URIs are
  replaced by pseudonyms; then the engagement's literal `mask_patterns` are blanked. All of it in
  strings, in keys and in numbers: a number whose JSON text holds a known value or a literal
  becomes that text masked as a string would be (`47110815` with the known value `4711` becomes
  `***KNOWN-…***0815`), one that a pattern meets becomes the placeholder, as a string; a bool is
  no number. A number is held to the known values and literals as its JSON text, as the loader
  read it: `0042` and `12.50` written without quotes are read as `42` and `12.5`, and a known
  value `0042` or `12.50` is not found in them; quote such values in a script (`"0042"`), where
  they are found as in any string. `drive` sent the same number and recorded it masked the same
  way, so the bundle holds nothing a recording does not. Last, `pack` makes
  redact's check on what it would place (below) and refuses if a credential, the salt or a known
  value is still in it.
  The credentials are read as `drive` reads them, from the variables and files the engagement
  file names; with `--script`, one that cannot be read here refuses the pack (exit 2, naming
  `identities[N].token` or `identities[N].headers[M]`, never a value), and so does a variable
  that `salt_env` names and that is not set here (exit 2, naming the variable). A run that sent a
  token given by a flag (`--token-env`, `--token-file`; `auth` names no identity) used a
  credential no engagement file names: its script refuses the pack (exit 2, naming the run and
  `auth`); pack the bundle without that script.
  A file that is no script is refused naming the field (`steps[1].list`, `name`), never what
  stands there, and "the file" where the loader has no place (a duplicate key, a syntax error);
  below `arguments` the place stops at `arguments`, as a key there may be the customer's.
  Only the result is in the bundle, as JSON
  (`scripts/<digest>.json`, UTF-8, keys in the order of the document); comments are dropped. JSON
  is YAML, so the copy is loaded like any script file.
  The entry's fields, besides `path`, `sha256` and `size`: `source_digest`, the SHA-256 of the
  original file (the `script_digest` of the runs), `sha256` being that of the placed file,
  `runs`, the digests of the recordings that used it, and `pseudonyms`. `pseudonyms` is
  `as_recordings` when every run that used the script had the engagement's salt
  (`pseudonyms: per_engagement`) and a salt is set while packing (the variable `salt_env`
  names). **`pack` cannot check that this salt is the one the runs were made with**; it must be
  the engagement's own, and only then does a value have the same pseudonym in the script as in
  the recordings. With another salt in the variable the field still says `as_recordings`, and
  the pseudonyms differ. Otherwise it is `own`: the script's pseudonyms are made with the salt at
  hand and do not match those of the recordings (the salt of a `per_run` run was never
  recorded), and `pack` says so on stderr, one line, never a value. A bundle without the field
  is read as before.
  The entry also has `replayable`. It is `true` when the placed script loads as a script. A
  known value in the script's name, in a `list:` value or in a key of the format can make the
  masked script load no more (`***KNOWN-…***-probe` is no name); `pack` then places it all the
  same, with `replayable: false` and `not_replayable`, the place that does not load (`name`,
  `steps[1].list`), never a value (`not_replayable` is left out when `replayable` is `true`), and writes one line to stderr with the script's digest and
  the place. `verify` knows both fields; a bundle without them is read as before and is intact,
  and its script is taken as replayable.
* **The images of a run** are in the index: each `recording` entry has `images`, `{target,
  sandbox}`, the digests of the target image and the sandbox image as the run recorded them in
  `reproduction.environment` (`target_image`, `sandbox_image`); `null` where the run has none, as
  for an endpoint or a run without a container. In a run in a container (`isolation: runc`),
  `null` says that the image could not be resolved to an id when the run was made; such a run is
  not repeated (below). A bundle packed before `script` and `images` existed is read and verified
  as before; the fields are optional in an entry.
  The index names an image by its digest only, the image id: `sha256:` and 64 hex digits, or
  the 64 hex digits alone, as some engines give it; never by a name or tag. A recording whose
  `run_started.reproduction.environment` names one otherwise refuses the pack (exit 2), and an
  index that does is refused when read (`verify`, `redact`, `replay`); `replay` refuses such a
  `reproduction` as well. The recording itself is placed as it is: in a run in a container, its
  `sandbox_step` `images` holds, beside each image's id, the reference as the operator gave it
  (a tag or a registry path, `registry.example/billing/app:2.3`), and a handover keeps it. That is
  a reference to the image, not the image. No bundle, packed or redacted, carries an image's
  content, since a customer's image can hold the customer's code and configuration; whoever
  needs the image gets it from the operator separately.
* **Repeating a run** (`evidence replay BUNDLE --run RUN --engagement FILE --out-dir DIR
  [--manifest PATH] [--index-digest HEX] [--engagement-confirmed]`) is `drive` with what the
  bundle holds, through the normal gate:

  ```sh
  kymograph evidence replay evidence/acme-2026-11 --run 3f9a1c2e \
    --engagement engagement.yaml --out-dir runs/replay
  ```

  `RUN` is the run's id or its recording's digest. The bundle is verified first; one that is not
  intact is refused (exit 2). That says the bundle is what its own index lists, not that the
  index is the one handed over: an index replaced and re-hashed with the files it lists is
  consistent. `--index-digest HEX`, the index's SHA-256 as known from elsewhere (the store's
  bundles, an attestation), is checked as `verify` checks it, while the bundle is verified: that
  reads and hashes the bundle's files, and nothing else happens before it (the run, the
  engagement file, the manifest and the script are read after it, and `drive` starts last). An
  index with another digest is refused (exit 2). The engagement file is always the reviewer's
  own and never read from the bundle; its `id` must be the bundle's. The script is the bundle's
  copy; the options are
  those the run recorded unmasked in `run_started`: the target (`--manifest` and `--entry` from
  `reproduction`, or `--http` for an endpoint with its `--server-revision` where the run had
  one), `--isolation` and the image ids, `--identity`, `--scenario`, `--target`, `--script-var`,
  the limits (`limits`: message size, duration, queue size, rule error policy, settle time),
  `--step-timeout` and `--mask-key`. The new recording equals the old one but for its
  environment — time, durations, the run's id, the scenario's path (the bundle's copy is
  loaded), the interpreter and the platform — and its `script_digest` (below).
  Exit 2 with one sentence, naming the field and never its value, for: a run without a script
  file, a passive run (`run`), a script with `replayable: false` (the sentence gives the place
  that does not load), an engagement file of another engagement, a run in a container whose
  image was not resolved (`reproduction.environment.target_image` or `sandbox_image` is `null`;
  without it `drive` would take today's default image) or is named other than by its id, an
  endpoint run whose server identity is a digest over files given with `--server-content`
  (`server_identity`; the files are not in a bundle) or no pinned revision, an endpoint path as
  long as the recorder cuts a path (2048 characters; the cut is not marked, so the path may be
  cut), a field of `run_started` that replay reads and that is not of the shape a recording has
  (`script_vars`, `authorization`, `endpoint.path` …; the field is named), a value replay would
  give `drive` that the run recorded with any masked form in it — the placeholder, a pseudonym,
  a withheld path — in `inputs.mask_keys[N]`, `auth.identity`, `authorization.declared_target`,
  `endpoint.host` or `endpoint.path`, the scenario's or the entry's name, and a run that
  recorded something only withheld or masked — a URL path withheld, a server given only as a
  command (a masked `argv`) with no manifest entry, a token given by a flag, a masked identity,
  and a script variable recorded masked or cut short (`script_vars.<name>`: the placeholder, a
  withheld path, any other stand-in of the masking, or a name as long as the recorder cuts
  names); a variable that holds a pseudonym is not refused and goes out as it is.
  The sentence says to run the original files instead.
  **The manifest** is the reviewer's own and is never loaded from the bundle: the bundle holds a
  copy of the manifest as evidence (`verify` checks it) and not the server files it lists, so
  that copy cannot be loaded. `--manifest PATH` names the reviewer's manifest, with its server
  files, on any machine; without it the path the run recorded is used. Either must have the
  digest the run recorded (`reproduction.manifest.digest`). A path that is gone, a manifest that
  does not load and one of another digest are refused (exit 2); the sentence names the field
  `reproduction.manifest`, the kind of failure and that `--manifest` helps, and never a path.
  **The limit:** a value the bundle holds only as a pseudonym goes out as that pseudonym, in the
  script and in `--script-var`. Repeating a run with the customer's real values needs the
  original script, which only the reviewer's side has: run it with `drive` and the engagement
  file, not with `evidence replay`. The new recording's `script_digest` is that of the bundle's
  copy (a JSON document), not of the original file.
* **The handover bundle** (`evidence redact`) is a second bundle: the engagement's literal
  patterns and the given keys blanked in the surfaces `evidence review` lists, no store,
  `redactions.json` (where and by which rule — `mask_patterns[i]` — never the value), and
  `CUSTOMER-README.md`, which tells the customer what the bundle is and how to verify it.
  A recording's `sandbox_step` events lie outside the surfaces a review lists and are copied as
  they are: the reference by which the operator gave a container run's image (a tag or a
  registry path) stays beside its id (a mask pattern or a blanked value found in it refuses the
  redaction, as anywhere outside those surfaces); no image content is in a handover.
  A placed script is copied as it is, after a check against a script changed after `pack`: one
  that holds a credential of the engagement file as it can be read now, the salt or a known
  value (in a string, a key or a number's JSON text), or one whose runs sent a token given by a
  flag, refuses the redaction (exit 2, naming the file, never the value). The credentials are
  read as `pack` reads them; one that cannot be read, or a variable `salt_env` names that is not
  set, refuses a bundle with a script (exit 2). A credential that changed since `pack` is not
  known to redact; the floor `pack` made of `drive`'s masking is what keeps it out.
  `evidence verify` rebuilds that page byte for byte from the bundle, in the wording its index
  names (`page_version`: 1 since 2026-11-09, 2 since the tool is called Kymograph), so a later
  change of the wording never fails a handover made before it; an index that names no page
  version, or one this version of the tool does not know, is refused whole — make the
  handover again from its source bundle. The
  first bundle is not touched and stays under the operator's retention. A JSON number is no
  surface: if a pattern or a blanked value occurs in its text (`json.dumps`, so `4567` in
  `1234567890`), the redaction is refused rather than the number changed. A number is looked at
  everywhere, except at the fixed places where only the tool writes one (`TOOL_NUMBER_PATHS` in
  `evidence.py`, each a path from the root of the event): the envelope (`seq`, `t_ns`), sizes,
  ordinals and counters the tool keeps, the limits of the run, a payload's `redaction_count`, the
  length of a withheld path, and the operator's own port of the target. The exception holds at
  that path only: a `seq` inside a refusal's `data` or a message's content is looked at, as is
  every code, status, exit code and argument, which the server or the script can supply. A
  pattern that happens to occur in one of the tool's own numbers is no reason to refuse. A
  string is looked at wherever it stands.
  Every recording, once redacted, is also held to the check a placed script is held to: one that
  still holds a known value of the engagement, a credential of the engagement file or the salt,
  in any string, key or number, refuses the redaction (exit 2,
  naming the recording, the run, the event's `seq` and the place, never the value). Numbers are
  looked at as for the patterns, the tool's own excepted; the masker's pseudonyms and handles, a
  withheld path, the run's id and, in `run_started`, the tool's time, version and platform and
  the engagement's window are not held to these values, nor are the counts of the kernel, the
  sink, the inspection and the signals (how many connections or packets, how often a method
  was looked at or a signal fired, how many findings a cap cut), which a target can steer but
  does not write: a target that knows a short value of digits can make a count of it, and the
  handover then holds these digits as a count. A key is named in the place only
  where the masker would leave it as it is, `<key>` otherwise. A string of the form of a
  digest the tool writes (64 hex digits, with or without `sha256:`) is not searched for a value
  in part, whose digits can stand there by chance, and is refused where it is one whole. A
  bundle without a script is redacted also where a credential or the salt cannot be read here:
  a warning names the place or the variable, and its recordings are held to the known values and
  to what can be read. A recording made before a number holding a known value in part was masked
  may hold such a number, and one made before the address and the port of an `egress_attempt`,
  the query type of an `egress_dns` and the sentences of an egress account that does not add up
  were masked may hold a value there; these are refused: make the run again.
* **The attestation** (`engagement attest`) is one page of recorded facts — window, targets,
  runs by state, scripts, scenarios, isolation, refusals, the bundle's index digest and the
  report's — and no finding: what a customer can show a third party.
* **The purge** (`engagement purge`) deletes the store, the operator's notes beside it, every run
  directory, refusals file and bundle of the engagement, refuses before `retention.delete_after` unless given a reason, and
  writes `purged.json` — which holds no customer data — for the customer. It refuses whole when
  anything to delete is a link or names another engagement, is not complete (exit 3) while a filed
  run's recording is not found under `--out-dir`, and says in `purged.json` what it does not
  reach: session recordings kept elsewhere, the report, the attestation, the intake files.
  For an engagement of version 2 it also wants `--salt-deleted`, the operator's word that the salt
  of the pseudonyms is deleted with the raw data; without it the purge is refused and nothing is
  deleted. `purged.json` keeps the confirmation and its time (`salt_deleted`, `null` where none
  was given; version 1 needs none).

## 8. Dossier: one customer, many engagements

```sh
kymograph engagement history --customer "Example Customer" \
  --store acme-2026-10.sqlite --store acme-2026-11.sqlite
```

Each store is read every time, read-only; one that cannot be read is listed as such, never
skipped (exit 3).

## What this version does not do

The limits of this version, those of an engagement among them, are listed in one place: the
reference, [What this tool does not do](reference.md#what-this-tool-does-not-do). Two that belong to
this page: the scope guard blocks calls and never calls anything itself, and `run` and the HTTP
proxy go on recording past the window's end (section 4, "The end of a run"); only the stop file
and a signal stop them.
