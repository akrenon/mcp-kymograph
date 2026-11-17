# The web interface

`kymograph web` shows recordings, the finding store, fleets, manifests, scenarios and the
signal library in a browser. It is a **local, read-only viewer**: it listens on `127.0.0.1`
only, lets in only a browser that was given its start token, has no TLS, writes nothing — not to the store, not to a run
directory — and starts nothing: no server, no fleet, no ingest. Everything it shows is what the
code already says: a run's state is `verdict`'s, a comparison is `store diff`'s or `fleet diff`'s.

## Starting it

```
kymograph web [--store FILE] [--runs DIR] [--manifest FILE]... [--scenario FILE]...
              [--bundle DIR]... [--attestation FILE]... [--bind ADDR] [--port N] [-q]
```

| Option | |
|---|---|
| `--store FILE` | a finding store, opened read-only (SQLite `mode=ro`); a store of another schema is refused whole |
| `--runs DIR` | where recordings are: searched five directories deep for `events.jsonl` and a fleet's `fleet.json`, following no symbolic link |
| `--manifest FILE` | a corpus manifest, read with the same loader as `corpus check` (repeatable) |
| `--scenario FILE` | a scenario file, read with the same loader as `--scenario` (repeatable) |
| `--bundle DIR` | an evidence bundle, verified against its own index (repeatable) |
| `--attestation FILE` | an attestation, read back through its own parser (repeatable) |
| `--bind ADDR` | `127.0.0.1`, the default, written so; anything else (`::1`, `127.0.0.2`, `localhost`, `0.0.0.0`, any name) is refused, exit 2 |
| `--port N` | default 8765; `0` for any free port |
| `-q` | print the start address alone |

Every source is optional; a view whose source was not given says which option to give. Refused at
start, exit 2: a `--bind` other than `127.0.0.1`, a store `--store` cannot open read-only, a `--runs` that is
not a directory, a `--manifest`, `--scenario` or `--attestation` that is not a file, a `--bundle`
that is not a directory, a port in use. A manifest or
scenario the loader refuses is not a start error: its page shows the refusal beside the file.

It prints one line on stderr with the start address and serves until Ctrl-C (exit 130):

```
kymograph: serving --store findings.sqlite read-only on http://127.0.0.1:8765/?token=<token> — a local viewer for this machine's user, no TLS
```

### The start token

At start the server draws two random values. The **token** is in the start address and nowhere
else; open that address in the browser. The server answers it with a redirect to `/` and sets a
cookie, `kymograph-<port>`, that holds the second value, the **session**. From then on the browser
sends the cookie, and the address bar shows `http://127.0.0.1:<port>/` without the token. Every
request without the cookie is refused (403) with the same words, whatever is wrong with it: the
cookie missing, its value wrong, the token wrong. The token works in the start address only; on any
other address it is an unknown parameter, never a login. Opening the start address again, in
a second browser say, sets the same cookie.

The cookie is `HttpOnly` and `SameSite=Strict`, has no expiry and no `Domain`, and is named for
the port, so two interfaces on one machine do not take each other's. The token and the session are
never in an answer (but that one `Set-Cookie`), never in an error message and never in a file. A
restart draws new values: the old address and the old cookie no longer work, and the new start
address has to be opened.

### One user on the machine

Open customer data in the interface only on a machine that has one user. A browser sends the
cookie to every port of `127.0.0.1`, whichever program listens there, and other local users can
reach `127.0.0.1` too. The token keeps their requests out of the interface, but the interface
cannot know what else on the machine is listening or who else is logged in.

### Against the test corpus, with a few driven runs

From the root of a clone, with `uv` (see [Install](../README.md#install)). The runs go under
`runs/`, which the clone's ignore rules cover: an output directory inside a git working tree
that they do not cover is refused.

```
# two corpus runs, filed in a store
uv run kymograph drive -q --out-dir runs/demo \
    --manifest tests/fixtures/corpus/manifest.yaml --entry reference-server --isolation host
uv run kymograph drive -q --out-dir runs/demo \
    --manifest tests/fixtures/corpus/manifest.yaml --entry poison-server --isolation host
uv run kymograph store ingest --store runs/demo/findings.sqlite runs/demo/*/events.jsonl

# two runs that are not a result: a server that exits at once (server_failed, exit 4),
# and a run stopped with Ctrl-C after a few seconds (incomplete, cause interrupted)
uv run kymograph drive -q --out-dir runs/demo -- python -c 'raise SystemExit(3)'
uv run kymograph drive -q --out-dir runs/demo -- python -c 'import time; time.sleep(60)'
#   ^ press Ctrl-C once it has started

uv run kymograph web --store runs/demo/findings.sqlite --runs runs/demo \
    --manifest tests/fixtures/corpus/manifest.yaml \
    --scenario tests/fixtures/scenarios/all-signals.yaml
```

Ingest the two corpus runs before driving the others: the store takes corpus runs only, and refuses
a run without a manifest (exit 2), which is right but noisy. Then open the start address it prints. **Runs**
lists all four; the two that are not a result show their state and causes first — `server_failed`
with `server_failed`, `server_silent`, `step_not_sent`; `incomplete` with `interrupted` and
`step_not_sent` — and their empty findings read "none recorded — the run is not a result", never
"no findings".

## What it shows

The main navigation — a rail on the left, a bar on top in a narrow window — names the package
and its version and leads to **Runs**, **Store**, **Fleets**, **Corpus**, **Scenarios**,
**Evidence** (bundles and attestations), **Signals** and **About** (the tool's version, its
schemas and rules version, and the sources it was given). Review mode has no navigation.

| Page | From |
|---|---|
| **Runs** | every recording under `--runs`, newest first, with its state and causes |
| **Run** | the verdict (state, exit code, rules version, every cause with its key and words), and tabs: overview (`run_started` with the reproduction triple and authorization, the waits of a paced run (`paced`: seconds, reason and, for a `Retry-After`, the status) as recorded and without a sum, `run_finished`), verdict, messages page by page with a message's masked payload, findings and observations (where the run evaluated statements: statements against messages as a table of traces, with the detail of the selected statement beside it and every event as tables behind a toggle), inventory (driver runs), interventions (`intervention`, `rule_quarantined`), HTTP exchanges, the sandbox's steps and egress account, stderr |
| **Store** | runs with where their recording is under `--runs`; findings of reference and poison entries; real-world findings on a page of their own, as candidates for disclosure; the diff of two runs |
| **Fleets** | fleets with their results; a fleet's state from its `fleet.json`; the comparison of two fleets |
| **Corpus**, **Scenarios** | a manifest's entries (provenance, identity, launch, scenarios, permitted isolations), a scenario's rules and statements, each beside the file's text |
| **Signals** | the signal library — each signal's kind, evidence or heuristic —, its reach, the surfaces the built-in walk reads, locator identities, normalisation and caps — generated from the code |
| **Engagement** | on a run, the engagement file it was gated against as its recording names it (id, digest, window as declared), what it was held to when it was paced (`runs_per_origin`, `min_interval_seconds` and their source) or that its recording declares pacing and says it was not enforced, whether it finished after the window; on a fleet, the same from its `fleet.json`; on the store, its engagement and every version of the file |
| **Triage** | the store's findings with each role's current decision beside them, real-world candidates apart, open questions apart, a finding's history of decisions |
| **Review mode** | one finding at a time and nothing else on the screen — its locator, the recorded text at each sighting, the sightings, both roles' current decisions first and every earlier row behind a toggle that is off when the page opens and says so — and the complete `kymograph store triage set --store=… --finding … --role customer --status '<STATUS>' --author '[NAME]'` line to copy (single quotes: nothing inside them is live in the shell, and an apostrophe is written `'\''`): the review meeting can be shared with the customer, and the decision is written at the terminal, not in the browser |
| **Bundles**, **Attestations** | a bundle's state against its index, file by file; its listed files and an attestation as downloads — only while the bundle is intact, re-hashed when served, never a file the index does not list |

## What it never does

* **Show a run that is not a result as one that found nothing.** `incomplete`, `server_failed`,
  `sandbox_failed` and `call_failed` come with their state and every cause key first; an empty list
  in such a run says so.
* **Show a capped listing as complete.** A cut — findings per message, a listing's page limit, the
  store's first 20 problems — says how much of how much.
* **Fold a changed recording into a missing one.** A store row whose recording is not under
  `--runs` is "recording not found"; one whose file is there but whose bytes are not the ones the
  store filed is "recording changed", and the file's content is not shown as that run's.
* **Read a store in part.** A store of another schema is refused whole.
* **Invent a state.** A fleet without its `fleet.json` has "not recorded in the store" where the
  state would be; an event this version does not record is "not recorded by this version"; one it
  records but this run lacks is "not in this recording".
* **Mix real-world findings into results.** They are candidates for disclosure, on their own page.

## Recordings are sensitive

The interface shows recordings as they were written — masked at write time — and reads no traffic
from anywhere else. Every string from a recording is shown as text, never as markup; zero-width,
bidi and other invisible characters are shown as `U+XXXX` tokens. It also
defends itself against other pages in the same browser: `GET`/`HEAD` only, a `Host` that is not
`127.0.0.1` or `localhost` with the bound port is refused (DNS rebinding), an `Origin` that is not
the page's own is refused, a request without the session is refused, every answer carries a strict
Content-Security-Policy and `Cache-Control: no-store`, and the page makes no outbound request — no
fonts, no CDN, no telemetry. The checks run in this order: Host (421), method (405), Origin (403),
session (403), then the address. There is no TLS: the token and the cookie cross the loopback
interface in the clear, which is why the interface is for a machine with one user (see above).

## Checking the page in a browser

The page is also checked in a real browser, in a container with no network. Build the image once
with `docker build -t mcp-kymograph-headless:1 tests/fixtures/web/headless`, then run
`MCP_KYMOGRAPH_REQUIRE_DOCKER=1 uv run pytest tests/test_web_headless.py`. The test builds the
hostile world of `tests/test_web_hostile.py` and starts the container with `--network none`, a
read-only root, the source tree and the data mounted read-only. Inside, `check.py` starts the
interface on a free port (a second one for the fleets' store) and drives headless Chromium over
`--remote-debugging-pipe`: it visits every page and mode, operates the pickers, the signal filter
and the history toggle, fails and counts every request that is not to the origin of the interface
whose page is loaded (it must be none; the other interface is another origin), collects console
errors and policy violations (none), and compares the finished DOM with what the page's code may
make: only its own elements and attributes, every `href` of any element (the head included) a
`#/…` route, one of its own downloads or its own icon and style sheet, every `src` of its own
origin, and every hostile value, in every text node, as text with its place named (the header of
its column, else its `dt`, its `aria-label` or the heading before it). It waits for a new value
of `data-ready` on `<main>`, which the page sets to its render counter when a view is drawn; a
target that does not draw again (an address the page turns away) is a fault of the check and
fails the run. Screenshots at 1920×1080 and 1440×900 and
`report.json` are written to `/out` of the container, which the test keeps in its temporary
directory.

## What it does not do

It starts no run, writes nothing (a triage decision included: review mode shows the line to run,
it does not run it), and marks no run as running: a recording still being written reads as
`incomplete`, like one that ended early. Repeated runs and their rates
([docs/design/repeated-runs.md](design/repeated-runs.md)) are not built, here or anywhere in the
tool. The other limits of this version are in the reference,
[What this tool does not do](reference.md#what-this-tool-does-not-do).

[docs/design/web-interface.md](design/web-interface.md) is the design the interface was built from,
an audit of its mockups against an earlier version; `src/mcp_kymograph/web/CONTRACT.md` holds the
shape of every view.
