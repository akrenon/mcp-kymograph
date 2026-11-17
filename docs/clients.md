# Pointing an MCP client at Kymograph

Proxy mode (`kymograph run`) sits where the server was: the client starts Kymograph,
Kymograph starts the server, and everything between the two is recorded. Under an
engagement this is how the **customer's own client** becomes the witness of a session: the
customer changes one entry of their client's configuration,
uses the client as they always do, and the recording says which engagement it was made under.

Nothing here is code. This page shows, for the clients most often met, where the configuration
names a server and what to put there instead. Client configuration formats change; the shapes
below are those the clients documented in October 2026 — check the client's own documentation
when one does not match.

## What every client needs

A client that starts an MCP server over stdio names a **command** and its **arguments**. To
record the session, the command becomes `kymograph` and the arguments become:

```
run --engagement /absolute/path/engagement.yaml --out-dir /absolute/path/runs -q -- <the server's own command> <its arguments>
```

* **Absolute paths.** A client starts the command from a working directory of its own choosing;
  a relative `--engagement` or `--out-dir` would land wherever that is.
* **`--engagement FILE`** ties the session to the engagement by the file, not by memory: the
  recording carries the file's id, digest and window, and a session outside the window, or
  against a target the file does not list, is refused before the server starts (the client then
  sees a server that would not start, and `refusals.jsonl` in `--out-dir` says why).
* **Everything after `--`** is the server's own command line, passed through untouched.
* **`-q`** keeps Kymograph's per-message lines off stderr; some clients show a server's stderr
  to the user.
* **stdout is the protocol channel.** Kymograph claims it at start and writes nothing else to
  it; the client sees only the server's messages.
* The client's environment reaches the server as before; Kymograph masks what looks like a
  credential in the recording (see docs/reference.md, "Recordings contain sensitive data").

The `kymograph` command must be on the client's `PATH`, or named by its absolute path (for
example the virtual environment's `bin/kymograph`).

A witnessed session is **recorded, not filed**: a session through a client is not reproducible,
so the store does not take it. The customer hands the recording (the run directory under
`--out-dir`) to the operator, and it enters the evidence bundle through `evidence pack
--session RECORDING`, listed there as not filed.

## Claude Desktop

`claude_desktop_config.json` names servers under `mcpServers`, each with `command`, `args` and,
optionally, `env`:

```json
{
  "mcpServers": {
    "customer-mcp": {
      "command": "/opt/venvs/mcp-kymograph/bin/kymograph",
      "args": [
        "run", "--engagement", "/srv/engagement/engagement.yaml",
        "--out-dir", "/srv/engagement/runs", "-q",
        "--", "npx", "-y", "@example/customer-mcp-server"
      ]
    }
  }
}
```

Before the change, `command` was `npx` and `args` the server's arguments: they move behind `--`.

## Claude Code

`claude mcp add` takes the server's name and, after `--`, its command; the whole Kymograph
command line goes there:

```sh
claude mcp add customer-mcp -- /opt/venvs/mcp-kymograph/bin/kymograph run \
  --engagement /srv/engagement/engagement.yaml --out-dir /srv/engagement/runs -q \
  -- npx -y @example/customer-mcp-server
```

A project's `.mcp.json` has the same `mcpServers` shape as Claude Desktop's file above.

## Cursor

`.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` for all of them, uses `mcpServers` with
`command` and `args`, as above.

## Visual Studio Code

`.vscode/mcp.json` names servers under `servers`; a stdio server has `"type": "stdio"`, a
`command` and `args`:

```json
{
  "servers": {
    "customer-mcp": {
      "type": "stdio",
      "command": "/opt/venvs/mcp-kymograph/bin/kymograph",
      "args": [
        "run", "--engagement", "/srv/engagement/engagement.yaml",
        "--out-dir", "/srv/engagement/runs", "-q",
        "--", "npx", "-y", "@example/customer-mcp-server"
      ]
    }
  }
}
```

## A server the client reaches over HTTP

A client configured with a URL instead of a command (Streamable HTTP) cannot be pointed at
Kymograph this way: the proxy mode over HTTP is not built (docs/reference.md, "What this tool does not do"). Such a server is
tested by the operator as an **endpoint entry** of the corpus, driven by `drive` under isolation
`remote`, not witnessed through the customer's client.

## Checking the snippet before the window opens

`kymograph engagement preflight engagement.yaml` lists the client templates as *not checked*:
which snippet a customer needs is in this page, not in anything the tool can read. The operator
sends the customer the snippet for each client the customer named in the intake
(`declared.servers[].clients_in_use`), with the paths filled in.
