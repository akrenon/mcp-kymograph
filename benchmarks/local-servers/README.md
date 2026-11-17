# Benchmark: widely used local MCP servers

Status: **in progress (stages A and B).** No results are published yet. The list of servers,
the results table and each server's pinned definition are written by the export, together,
from released results only. Nothing in this directory is a result until the export has put it
here.

## What stage A measures

What a server says about itself when a client connects, and nothing else. Each server is
driven with Kymograph's discovery script: `initialize`, then `tools/list`, `resources/list`,
`resources/templates/list` and `prompts/list`, each only if the server offered it. No tool is
called, no resource is read, nothing is planted. The built-in walk of Kymograph inspects the
tool listing — each tool's description and title, and the descriptions and enum values in its
schemas — and any error message, for its named signals (see the main README, "What the server
sends that a model could read as instruction").

The walk is joined by an observation file, `scenarios/stage-a-self-description.yaml`. It has no
rules and changes nothing in the traffic. It applies the signals the walk applies to a tool
description to the `instructions` in the `initialize` answer, and to the title and description
of every prompt and each of its arguments, every resource and every resource template. What the
walk sees is an `observation`; what the file sees is a `finding` (statement, signal, place).
Each statement leaves a `statement_evaluated` entry for every message it applies to, so "not
offered" (no such message), "not there" (`path_not_found`) and "checked, nothing" can be told
apart.

A second observation file, `scenarios/stage-b-call-result.yaml`, is for the result of
`tools/call`. Like the first it has no rules and changes nothing in the traffic. It applies the
same nine signals to the text of each content entry and to the text of each embedded resource;
the walk applies only the six that read everywhere to a call result. `structuredContent` is not
reached (the path syntax has no wildcard for a key), so there the walk's six signals are the only
check. False-alarm rates of these signals on third-party content are not measured yet; the
selection is reviewed once there are measured rates per signal.

Each run has one of four results:

| Result | Meaning |
|---|---|
| `signal` | the run is `complete` and the walk or the observation file recorded at least one signal |
| `no_signal` | the run is `complete` and neither recorded one |
| `error` | the run is not `complete` (`incomplete`, `server_failed`, `sandbox_failed`); the cause is given |
| `skipped` | the server was not run; the reason is given |

A run's state is what `kymograph verdict` reads from its recording; the benchmark adds no
judgement of its own. **A signal is "signal X fired at place Y"** — a reproducible, named
observation, and a candidate for a closer look. It is not a statement that a server is
vulnerable, and `no_signal` is not a statement that it is safe: it says that none of the named
signals fired on what the server said about itself.

**Positive control.** The test suite runs the runner against a fixture server that plants, at
each of these places, text that fires every signal, and against one with honest text: every
statement must fire in the first, none in the second, and in both every statement must have
checked its place.

**Negative control.** One server's listing is long, imperative prose of the kind an honest tool
description is written in. A signal there is a defect in the inspector, not in the server. The
results name which server it is.

## How servers run

Every server's definition names its package at an exact version with the registry's integrity
hash (npm, PyPI, or for a built binary a GitHub release asset with the SHA-256 its release
lists) and the source repository at a full commit id; its image context is meant to install every
dependency from a lockfile. The runner itself checks what it can see: the form of the package (an
exact version, no range and no tag that moves, and an integrity of the registry's own kind and
length: `sha512-` and Base64 for npm, `sha256:` and hex for PyPI and GitHub; the hash itself is not
checked against the registry); the base image pinned by
digest; a Dockerfile in UTF-8 read one instruction per line (no continuation, heredoc, byte
order mark, line break other than `\n`, or parser directive), of one stage from exactly that
base, using only `FROM`, `WORKDIR`, `COPY`, `RUN`, `ENV`, `USER`, `LABEL`, `EXPOSE`,
`ENTRYPOINT` and `CMD`, and on `FROM`, `COPY` and `RUN` no build flag but `COPY --chown`,
`--chmod` (plain values) and `--link` — a leading word there that starts with a dash or a quote
is refused otherwise; docker itself refuses flags on the other instructions; and before
a run, that the image's labels match its context and its definition as they are now. It does
not check what a `RUN` step fetches during the build, which has network. Each server is built
into its own image and run from that image by id, without network:

```sh
docker run -i --rm --name <run name> \
  --network none --dns 127.0.0.1 --dns-search . --ipc none \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 \
  --pids-limit 256 --memory 512m \
  -e HTTP_PROXY= -e http_proxy= ... -e all_proxy= [-e NAME=dummy ...] <image id> [args ...]
```

`--ipc none` leaves out `/dev/shm`, which docker otherwise mounts writable; in-memory IPC
objects (`/dev/mqueue`, System V) remain possible inside the container's own namespace. The
resolver entries point at loopback so that the host's name servers do not appear in the
container. The proxy variables are set empty so that the docker client does not fill them from
its own configuration, which the command line would not show. An image that declares a volume
is refused, because docker would mount it writable despite `--read-only`. What the daemon adds
by default (runtime, seccomp and AppArmor profile, log driver) is recorded in the companion.

**Isolation: container (docker), not managed by Kymograph, not gVisor.** Kymograph runs
third-party servers itself only under gVisor, which this version does not provide. Stage A
therefore starts the command above through `kymograph drive` without a corpus manifest:
Kymograph starts the docker CLI as a child process, and its recording says
`isolation: host`, because the container is not one it manages.

**The container is documented beside every recording.** The runner writes `container.json`
next to each `events.jsonl`: the docker command (host paths shown as `<repo>`, `<out>` and
`<scenario>`, the value of every `launch.env` variable as `<env>` — so `compare` sees a
changed name there, not a changed value, which only the private definitions file holds), the
image id, the base image, the start
and end times, the observation file (name, path and SHA-256), and the SHA-256 of the recording.
It writes it only after checking that the recording's own `run_started.argv` is that same
command and that the recording ran with exactly that observation file and loaded no rules. A
reader can check the claim "container" against the recording rather than take it on trust.

The companion also says which inputs the run came from: the SHA-256 of every file of the image
context and of the context as a whole (the text `sha256sum` prints for those files), the digest
of what the definition says about the image (name, provenance, package, source, base), the time
the image was created, the version and commit of Kymograph, the SHA-256 of the runner, the
Docker version and context, the daemon's kernel, default runtime, security options and log
driver, the client's kernel, and the Python version.
The companion never holds a value of the server's environment; `inputs.environment_hmac_sha256` is
the HMAC-SHA256 of the sorted environment the runner sets, each value masked first, and `compare`
uses it as an opaque value to see that two runs had the same environment: a changed ordinary value
shows, while a changed value the masker recognises as a secret (by its name or its shape)
deliberately does not. The key is one per suite (a series of runs with the same definitions file),
32 random bytes in a file of mode 0600 that is never exported and never lies in a git work tree:
`bench.py key --out FILE` creates it (and refuses a place git would track, before it creates the
file), `run` takes it as `--hmac-key FILE`, and the companion names
it only by `inputs.environment_key_id` (16 hex characters of an HMAC of a fixed text). Without the
key the HMAC of an environment of a few possible values cannot be reversed by trying them, which
the plain SHA-256 could be. `compare` of two runs made with different keys says so and does not
compare their environments; `compare --key FILE` also refuses a run that was not made with that
key, and says which. A companion of version 3 or 4 holds the plain SHA-256 and is refused: the run
has to be run again.
`build` puts the two digests on the image as the labels `mcp-kymograph.bench.context-sha256` and
`mcp-kymograph.bench.definition-sha256`; `run` refuses an image whose labels are missing or do not
match the context and the definition as they are now: such an image was built from other
inputs, and has to be built again. File modes and empty directories are not part of the context
digest.

**No credentials.** A server that needs a key or token to start gets an obviously fake value
on the command line. A server that checks its key online when it starts cannot start without
network, and is `skipped`, with that as the reason.

**Protocol version.** The driver offers `2025-06-18` in `initialize`. The version each server
answers with is reported per server. A listing is what the server offers at that version: a
server may list more to a client that speaks a later revision, and where one is known to, the
results say so.

**Every server is run twice.** The runner compares the two runs with
`bench.py compare`. What it compares is each run's state and causes, as `kymograph verdict`
reads them from the recording, and the recordings' observations, findings, `statement_evaluated`
entries and counts. It lists every difference from both sides, and beside them every difference
in the runs' inputs (image, context, observation file, command without the container name, tool
and host). It does not choose a run, sum anything up or rate. An empty list means no difference
in these parts. The exit code is 0 whether there are differences or not.

**HTTP runs before and after 2026-10-29.** A server spoken to over Streamable HTTP is driven from
a second container (`runner/bench.py`, "Streamable HTTP"). Until 2026-10-29 that container reached
the server on the run's own network by the name `server`; since then it joins the server
container's network namespace and calls `127.0.0.1`, because plain HTTP is spoken only to a
loopback address. A recording's
`run_started.endpoint.host` is therefore `server` in the older runs and `127.0.0.1` in the newer
ones. Two runs on either side of that date differ there because the same server was reached by
another path, not because the server moved.

## Stage B

What a server passes on from content it reads or fetches. `bench.py run --stage b` drives a
server with a script of its own (`kymograph drive --script`): `initialize`, `tools/list`, and a
call of one tool that points at a **fixture**, a text the benchmark planted. The text carries
a **canary**, an id that exists once per run (`MCPB-CANARY-<SERVER>-<8 hex>`), in a sentence the
signals recognise. If the id turns up in the answer to the call, the text travelled the path
under test. The observation file `scenarios/stage-b-call-result.yaml` has no rules; it applies
the nine signals to the text of the call's result.

A definition's `stage_b` section names the fixture (`file`, `sqlite`, `git`, `postgres`, `page`,
`page-js`, or `none`), the script (a path relative to the definitions file and below its
directory: an absolute path, or one that leaves the directory by `..` or a symlink, is refused;
the file must load as a script), the start arguments (they replace `launch.args`) and, for `postgres`, the image by
digest. The fixture is poured into a volume of its own for each run and mounted at
`/srv/fixtures`, read-only where the server only reads. A server that needs a network (`page`,
`page-js`, `postgres`) joins a network with the fixture server and nothing else, and every
attempt to reach anything else is counted; the others run with `--network none`. A server
without a `stage_b` section, or with `status: skipped`, is skipped with its reason.

**The outcome** of a run is one of four values, from the recording as `kymograph verdict`
reads it. `error`: the run is not complete, or a call was answered with an error (`call_error`,
`tool_error`) — such a run is never `no_signal` — or nothing was delivered (`canary_not_delivered`).
`signal`: the run is complete and the signals found something in the answer to a `tools/call`,
which the result lists with statement, signal and path. `no_signal`: complete, no signal, and
the canary stands word for word in the answer; the negative control (`role: negative-control`
with the fixture `none`) plants none and needs none. `skipped`: from the definition, or
because a server that did not start, or whose fixture volume, probe or fixture server failed,
was tried twice (each attempt with a directory and a companion of its own where it ran) and did
not get a session; the result then says why and where both attempts lie.

**The companion** is version 6 for stage B (stage A stays at 5). It names the fixture (kind, the
hash of its shape taken with a placeholder for the id, file names), the script and its variables,
the network report (addresses, images, probe, counters, names asked, HTTP requests, what was
left after the run), the result of the canary observation (`delivered` with the places and 80
characters around each, `altered`, or `missing`) and the outcome. **The id is never in the
companion**, only its placeholder: it is in `canary.txt` beside the recording, and in the
recording where the server delivered it. Whatever the server did with it — asked for it as a
page or a name, wrote it into a key of its answer, changed its case or its separators — a last
step over every string of the companion and of the printed result (keys included) turns the id,
its changed forms and its 8 hex characters into `x`. The forms it knows are: any case, any
separators (space, underscore, an invisible character), the compatibility form of the
characters (NFKC: full-width letters), `%XX` written out, and the text read backwards; each as
long as it was, where the length stays, else the whole string becomes `x`. An encoding it does
not know (base64, say) can stay in the companion; checking the whole exported tree for the id
is the work of a later step. The same step takes out every value of `server.env` of four
characters or more, as a run's secret, wherever the server's own requests carried it (an HTTP
path, a DNS name, a statement): the companion never holds a value of the server's environment,
also not by that way. The signals and the
canary are taken from the answer the driver took to each `tools/call` (the first message of the
server with that id), not from a message of the server that only claims to be one, nor from a
second answer. The network report names its limits (`limits`) and, if a set of refused targets
was full (`overflow`), says so under `problems`. `compare` takes a different id as no difference in
input, a different `fixture.sha256` as one, and sets the outcome and the canary's result side
by side.

**The helper containers are part of the trust boundary.** The fixture server and PostgreSQL are
not the server under test, but they sit in its network and hold what it reads, so what they may
do is limited and what they do is reported, as it is for the server.

- *No fixed secrets.* The password of the role `reader` is new for each attempt, like the
  superuser's (`secrets.token_urlsafe`). The fixture's init script holds it; the hash of the
  fixture is taken with a placeholder in its place, as for the id, so it names the shape and not
  the run. A definition writes `{postgres_url}` in `stage_b.args`, and the runner puts in
  `postgresql://reader:<password>@postgres:5432/postgres` when it starts the server. The password
  is in no companion (`stage_b_args` keeps the placeholder, the shown command has the password
  as `*` of its length), no printed output and no network report: the last step over the
  companion takes the run's passwords out as it takes the id out. The recording is the driver's,
  and its `run_started.argv` is the command the server was given, password included, as it holds
  the id where the server delivered it.
- *Rights only as far as needed.* PostgreSQL runs as its own user (`999:999`) with a read-only
  root, no capability at all, `no-new-privileges`, and its data, socket directory and `/tmp` in
  memory owned by that user (the data directory `0700`). The fixture server stays as it was:
  `65534`, no rights, a read-only root.
- *Their behaviour is in the network report.* Each helper's namespace has counting rules of its
  own, loaded before the holder exists (a failure to load them ends the run, it is not tried
  again): in, only what the role serves (fixture server TCP 8080 and UDP 53, PostgreSQL TCP
  5432) and only from the subnet, the rest counted and dropped; out, only answers and loopback,
  every new attempt counted per target (a set that is full counts under `overflow`) and
  refused. Docker's resolver (127.0.0.11) is counted and refused before loopback, as in the
  holder; a new connection over loopback is let through (it does not leave the namespace) and
  counted per target as `local`, in the holder's namespace too. PostgreSQL logs connections,
  disconnections and every statement; the report lists the sessions (user, database,
  application) and statements of the run, leaving out the runner's own readiness check and what
  was there before the baseline, and cleaned of the id and the passwords. It lists the
  connections that did not get in as `failed_logins` (user, database, reason; a `FATAL` of
  authentication, an unknown role or database, `pg_hba`, or a connection that was received and
  never authorized; the log names no database for a wrong password, and then it is null). The
  report has them under `helpers`, per role: `sets`, `local` and `counters` (`resolver`,
  `other`, `input_dropped`, `overflow`) for both, and `sessions`, `statements` and
  `failed_logins` for PostgreSQL. The fixture server's HTTP requests and DNS questions stay in
  `http_requests` and `dns_questions`, at most 2000 of each: the server writes down 2000 single
  events and then only totals, which the report gives as `dropped` (`http`, `dns`) with an entry
  under `problems`; docker keeps its log in one file of at most 8 MB. A helper's own attempts
  show here, not among the server's.

```sh
uv run python benchmarks/local-servers/runner/bench.py build-helpers
uv run python benchmarks/local-servers/runner/bench.py run --stage b --definitions DIR --server NAME --hmac-key KEY
```

Plain Docker, as in stage A: not gVisor. Whether a model would act on what the text says is
not measured; the signals say what the text is, the canary that it arrived.

## Known limits

- **Plain Docker records no connection attempts.** A server that tries to reach the network
  while it lists fails silently there, and the recording shows only what it said afterwards,
  or that it said nothing. Kymograph's own sandbox records every attempt; it is not used
  here, because it is not permitted for third-party servers.
- **IPv6 attempts are not counted (stage B).** The namespace has no IPv6 address: an IPv6
  attempt fails without a packet, leaves nothing and is not counted.
- **The id is taken out in the forms the runner knows (stage B).** Case, separators, NFKC,
  `%XX` and the text backwards; a value the server writes in another encoding (base64, a
  cipher) is not recognised and can stay in the companion.
- **A container is not gVisor.** It shares the host's kernel, and a server inside can read what
  that kernel shows every container: `/proc/version`, `/proc/cpuinfo`, `/proc/meminfo`,
  `/proc/cmdline`, the host paths of docker's own mounts in `/proc/self/mountinfo`, and hardware
  names under `/sys`. A server that put these into what it says about itself would be recorded
  doing so; nothing here stops it.
- **Descriptions and titles are checked; the rest is not.** Names, URIs, `serverInfo` and icons
  are not. The content of prompts (`prompts/get`) and resources (`resources/read`) is not
  fetched in stage A. By the protocol, `instructions` is text for a model, so a
  `model_addressed` there is the form of a text that addresses a model; the result names the
  signal and the place, and what to make of it is left to the reader.
- **Stage A sees only what a server says about itself.** What it passes on from content it
  reads or fetches is stage B (above).
- **The signals are English patterns.** An instruction written in another language passes
  them.

## Reproducing a run

The runner is `runner/bench.py`, standard library plus Kymograph. Server definitions
(`versions.yaml`, one image context per server) are published with the results by the export.

```sh
uv sync --locked
uv run python benchmarks/local-servers/runner/bench.py build --definitions DIR --server NAME
uv run python benchmarks/local-servers/runner/bench.py run   --definitions DIR --server NAME
uv run kymograph verdict runs/local-servers/<run>
uv run python benchmarks/local-servers/runner/bench.py compare runs/local-servers/<run-a> runs/local-servers/<run-b>
```

A rebuilt image can have another id. The inputs are comparable through `inputs.context_sha256`
in each companion, and `compare` lists a difference in either.

Recordings go to `runs/local-servers/` by default, which git ignores. The runner refuses an
output directory inside `benchmarks/` or anywhere a git repository would track it, whichever
repository the directory lies in.
