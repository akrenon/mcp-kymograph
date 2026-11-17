# Kymograph

AKRENON Kymograph (`mcp-kymograph`) is a dynamic security testing tool for
[Model Context Protocol](https://modelcontextprotocol.io) servers. I wrote it to see what an
MCP server really sends, not what its description says it sends.

Formerly published as mcp-polygraph.

This is an alpha version. The commands work and are tested. Output formats can still change
between versions.

## What it does

- It records the message exchange between an MCP client and an MCP server, in both directions,
  into one file per run (`events.jsonl`).
- It reports named signals: text in a tool description or a tool result that a model could
  read as an instruction.
- With a scenario file it can alter messages in flight, so that the reaction of the other side
  is in the recording too.
- It can run a server in a sandbox without a network and record every attempt to reach one.
- It masks credentials at the moment an event is written.
- It has a read-only web interface on `127.0.0.1` for looking at recordings.

Kymograph is placed where you configure it. It starts the server as a child process over
stdio, or it connects to a Streamable HTTP endpoint that you name. It does not intercept
traffic of third parties.

## What it does not do

- It gives no severities. A finding says that a pattern matched at a place in the recording.
- It gives no grades. It does not rate a server as safe or unsafe.
- It makes no statement about individual clients. Whether a text has an effect depends on the
  client and the model that read it, and the wire does not show that.
- A run without findings does not mean a harmless server. Most signals are heuristics. Honest
  text can match them, and other wording can pass them.
- It does not decide what you may test. Use it against servers you operate, against the
  fixture servers in this repository, or against systems for which you hold a written
  engagement.

## Install

Requirements: Linux and Python 3.12 or later. At run time the tool needs only the standard
library. Reading YAML files needs the optional extra `yaml` (PyYAML).

With pip, from the package index:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install 'mcp-kymograph[yaml]'
kymograph --version
```

This installs the tool only. The quick start below uses files from this repository, so it
needs a clone.

Or install from a clone. With [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/akrenon/mcp-kymograph.git
cd mcp-kymograph
uv sync
uv run kymograph --version
```

From a clone with pip:

```sh
git clone https://github.com/akrenon/mcp-kymograph.git
cd mcp-kymograph
python3 -m venv .venv
. .venv/bin/activate
pip install '.[yaml]'
kymograph --version
```

The command is `kymograph`. The same program is also installed as `mcp-kymograph`.
The commands below are written as with the environment active. With uv, activate it
(`. .venv/bin/activate`) or put `uv run` in front of each command.

## Quick start

The folder [examples/unmarked-result](examples/unmarked-result/) holds a small server and
four input files. The server has one tool, `read_file`. Its result is a note with a hidden
HTML comment that holds an instruction, and a canary value.

Run this from the root of the clone:

```sh
kymograph drive \
  --script examples/unmarked-result/c_read-file.yaml \
  --scenario examples/unmarked-result/c_result-observe.yaml \
  --out-dir runs \
  -- python examples/unmarked-result/marking_server.py \
     --file examples/unmarked-result/c_note.txt --kind unmarked
```

Kymograph starts the server, speaks the client half from the script, and stops. The terminal
shows each message and then a summary with three findings (`hidden_comment`,
`instruction_override`, `concealment_directive`). The recording is in a new folder under
`runs/`:

```sh
RUN=$(ls -d runs/2* | tail -n 1)
kymograph verdict "$RUN/events.jsonl"
kymograph engagement marking "$RUN" --canaries-file examples/unmarked-result/c_canaries.json
```

`verdict` prints the state of the run. `engagement marking` says where the canary arrived and
whether the server marked that text as foreign content. Here it reports `unmarked`. That is an
observation, not a severity.

The example needs no network and no Docker. A second run gives the same findings.

## The two modes

| | `kymograph run` (proxy) | `kymograph drive` (driver) |
|---|---|---|
| Who starts the tool | an MCP client, from its own configuration | you, at a terminal |
| Who is the client | that client, with the model behind it | Kymograph itself, from a fixed script |
| What the recording shows | one real session, as it happened | what the server offers when it is asked the same questions every time |

Proxy mode records a session. The client varies, so a session is not repeatable.

Driver mode makes an inventory. There is no foreign client and no model. The same script
against the same server gives the same recording, apart from the run id and the time.

Both modes write the same format. [docs/clients.md](docs/clients.md) shows how to put the
proxy into a client's configuration.

## Limits of isolation

- By default the server runs on the host, as a child process with your user's rights, your
  files and your network. What it sends anywhere else is not observed. The terminal says so on
  every such run. Do not run code you do not trust this way.
- A server that is an entry of a corpus manifest can run under `--isolation runc`
  (`kymograph drive --manifest FILE --entry NAME --isolation runc`). It then runs in a container
  without a route to any network, and every attempt to reach one is recorded. This needs Docker
  on Linux and two images. [docs/reference.md](docs/reference.md) says how to get them.
- The runc sandbox shares the kernel of the host. It keeps a server off the network. It does
  not protect the kernel.
- There is no gVisor runtime. `--isolation runsc` is accepted and always refused.
- For an endpoint that someone else runs, the tool sees only the traffic between itself and
  the endpoint.

## More documentation

- [docs/reference.md](docs/reference.md): the commands and their options, the exit codes, the
  file formats, and the full list of limits.
- [docs/signals/README.md](docs/signals/README.md): what each signal reads.
- [docs/engagements.md](docs/engagements.md): working under a written engagement.
- [docs/web.md](docs/web.md): the web interface.

## The name

A kymograph is an instrument that writes a motion down as a trace over time: it records, and it
does not judge.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
