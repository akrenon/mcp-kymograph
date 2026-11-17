# Design: the HTTP transport

Status: **partly built.** Built, in driver mode against a server that is already running: one
recording format for stdio and Streamable HTTP, with the HTTP events, header and query masking
and SSE-id pseudonyms (recording schema 5); the driver's channel over Streamable HTTP, forwarded
and recorded through the proxy as `drive --http URL` (proposed here as `--url`); both eras — the
era detection of 2.4, the modern script, re-issue of a broken modern stream and resumption of a
legacy one; the closing `DELETE`; a token from a file or an environment variable (2.8); the
waits of 4.5 for `429` and `503`, and its pacing per origin; remote endpoints as corpus entries
driven under isolation `remote` (4.1), with 4.3's marking and 4.4's gate rule and "plain HTTP
only to loopback literals"; TLS to a remote endpoint (section 8); and the HTTP causes of section
5 that these bring. Not built: `listen` (proxy mode over HTTP), a local HTTP server started by
this tool (`launch.listen`, `launch.path`), the legacy GET stream, a second session after a 404,
the events `session_started`, `session_ended` and `server_stdout`, the ingress bridge (section
3), batch elements inspected one by one (1.3), the soft flags of 4.1 other than the certificate,
a fleet with remote entries, rule scenarios over HTTP, and the causes `http_unparsed` and
`ingress_inconsistent`. `src/mcp_kymograph/http/` and the modules that speak HTTP cite this
document.
Written 2026-10-06. Line numbers refer to the code of that day and have moved since; where a
line may have moved, the function name is the anchor. The specification's central claims (the
two eras, the removed handshake, sessions and resumption) were checked a second time against the
versioning page and the changelog of 2026-07-28 before this document was committed.

When this was written, every server ran over stdio. The corpus accepted no other transport
(`corpus.py:56`, refused at `corpus.py:331–335`), the proxy started the server as a child with
three pipes (`proxy.py:722–734`), the driver fed the proxy through two real pipes
(`ClientChannel`, `driver.py:132`), and the README listed the HTTP transport under "not yet"
(`README.md:61–62`).
This document says which HTTP transports to support, how both modes look over HTTP, how an
HTTP server runs inside the runc sandbox without weakening the egress gate, what can be said
about a server nobody here runs, which causes the verdict would need, and what can be built
before the verdict is touched.

Three lines hold throughout:

* **The barrier stays structural.** The target's namespace keeps loopback and a dummy device
  and nothing else (`common.py:61–76`). Inbound traffic gets in through a socket file that only
  our own container can reach, not through an interface, and no rule becomes part of the
  barrier (`runner.py:3–7`).
* **The client goes nowhere the server points it.** An HTTP server can name URLs: a redirect, a
  protected-resource metadata document, an `endpoint` event. A client on the host that followed
  one would be the target's egress, outside every account. The connector this tool builds has
  one destination, fixed before the run, and no code path turns a URL from the traffic into a
  connection.
* **Observation loses, never the connection** (`sink.py:3–4`). Over HTTP the forwarding side
  has to parse HTTP framing to forward at all; it parses no JSON-RPC and no SSE event, and it
  hands copies to an observer that cannot block it, as `Observer` does today
  (`proxy.py:172–176`).

## 0. The specification read

Read online on 2026-10-06. The latest revision is **2026-07-28** (the page
https://modelcontextprotocol.io/specification/latest names `schema/2026-07-28/schema.ts` as
authoritative).

| What | URL |
|---|---|
| Transports overview | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports |
| Streamable HTTP | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http |
| Versioning and compatibility | https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning |
| `server/discover` | https://modelcontextprotocol.io/specification/2026-07-28/server/discover |
| Changelog (against 2025-11-25) | https://modelcontextprotocol.io/specification/2026-07-28/changelog |
| Deprecated features | https://modelcontextprotocol.io/specification/2026-07-28/deprecated |
| Authorization | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization |
| Authorization server discovery | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery |
| Authorization security considerations | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations |
| Streamable HTTP, previous revision | https://modelcontextprotocol.io/specification/2025-11-25/basic/transports |
| Batching still allowed | https://modelcontextprotocol.io/specification/2025-03-26/basic/transports |
| Batching removed, `MCP-Protocol-Version` added | https://modelcontextprotocol.io/specification/2025-06-18/changelog |
| HTTP+SSE | https://modelcontextprotocol.io/specification/2024-11-05/basic/transports |
| RFC 9728 §3.3 (used in 2.8) | https://datatracker.ietf.org/doc/html/rfc9728 |

**The revisions disagree on the shape of Streamable HTTP, and that is the main input to this
design.** 2026-07-28 removed the `initialize` handshake, protocol-level sessions
(`Mcp-Session-Id`), the GET stream, DELETE, server requests on SSE streams, and resumption via
`Last-Event-ID` and SSE event ids. It added per-request `_meta`
(`io.modelcontextprotocol/protocolVersion`, `…/clientCapabilities`, `…/clientInfo`), the
`Mcp-Method` and `Mcp-Name` headers, `server/discover`, `subscriptions/listen` and Multi
Round-Trip Requests. Revisions 2025-03-26 to 2025-11-25 have every removed mechanism. The
versioning page names the two eras **legacy** ("establish a session with an `initialize`
handshake (`2025-11-25` and earlier)") and **modern** ("`2026-07-28` and later"), and describes
a **dual-era** implementation that speaks both.

**This design follows both, as the spec's dual-era model.** The transport layer and the
recording carry either era; which one a run spoke is recorded, never assumed. Proxy mode cannot
choose the era — the client does; the driver announces `2025-06-18` today (`driver.py:63`), a
legacy version; and the spec itself prescribes era detection for a client that must reach both
(2.4). "Legacy" below means the 2025-11-25 text, with 2025-03-26's batches as the one older
difference (1.3).

## 1. Which transports are supported

### 1.1 Decision

Built in driver mode only: proxy mode over HTTP (`listen`, 2.1) is not built, and only an
endpoint entry names `streamable-http` — a server this tool starts still speaks stdio.

| Transport | Revisions | Decision |
|---|---|---|
| stdio | all | unchanged |
| Streamable HTTP, modern | 2026-07-28 | supported, both modes |
| Streamable HTTP, legacy | 2025-03-26 – 2025-11-25 | supported, both modes; sessions, GET, DELETE and resumption as 2025-11-25 has them |
| HTTP+SSE | 2024-11-05 | **not supported**: an entry naming it is refused when the manifest is read, as an unknown transport is today |

An entry names one transport, `launch.transport: streamable-http`. The era is not declared: it
is detected and recorded (2.4).

### 1.2 HTTP+SSE: not supported

Built, with one difference from the last point: when the first `initialize` draws a 400, 404 or
405, one `GET` looks for an `endpoint` event, and if it finds one the step's reason is
`http_sse_only` instead of `http_status`; the URI in the event is never used.

* **The spec is retiring it.** Deprecated since 2025-03-26; in the registry it is "Deprecated"
  with earliest removal "Three months after SEP-2596 reaches Final"; "New implementations
  SHOULD NOT adopt it" (streamable-http page, "HTTP+SSE Transport (2024-11-05)").
* **It makes the server choose where the client sends.** "When a client connects, the server
  MUST send an `endpoint` event containing a URI for the client to use for sending messages.
  All subsequent client messages MUST be sent as HTTP POST requests to this endpoint"
  (2024-11-05). A client that obeys sends every message wherever the server under test says —
  what the second line above excludes. Doing it safely needs a same-origin check on that URI
  and a second connection model, for a transport with a removal date.
* **Which servers still speak it is not measured.** The corpus has none: every entry is stdio
  (`corpus.py:56`). If real-world candidates turn out to need it, it is reconsidered with the
  same-origin check as a hard condition (7, question 6).
* **The fallback is not taken either.** A client that wants old servers issues "a GET request
  to the server URL, expecting … an `endpoint` event" when its POST fails with 400, 404 or 405
  without a modern error body. The driver does not: such an entry's handshake fails, and the
  recording says with which HTTP status (`server_failed`, reason `http_status`, 5).

### 1.3 Batches

Not built: the inspection of each element of a batch (the last point).

2025-03-26 allowed a POST body to be "An array batching one or more requests and/or
notifications", and responses on an SSE stream "MAY be batched". 2025-06-18 removed batching
("Remove support for JSON-RPC batching"). 2025-11-25: the body "MUST be a single JSON-RPC
request, notification, or response". 2026-07-28: "a single JSON-RPC request or notification.
The client MUST NOT send JSON-RPC responses."

* The driver never sends a batch; the proxy forwards one unchanged, like any body.
* The recorder already classifies an array as `batch` (`events.py:973–974`), but the inspector
  does not look into one: `surfaces` returns on a non-object (`inspection.py:282–283`), and so
  does `_responded_method` (`inspection.py:621`). A finding inside a batched response is missed
  without a trace — over stdio under 2025-03-26 as much as over HTTP.
* Proposed: the observer inspects each element of a batch as a message of its own, the batch
  stays one `message` event, and the element's index is part of each finding's path. Not
  HTTP-specific; listed here because HTTP opens a second door to it.

## 2. Driver mode and proxy mode over HTTP

### 2.1 Who listens, who connects

Built: `drive` over HTTP, the driver feeding the proxy through socket pairs, and the upstream to
a remote endpoint (section 8). Not built: `listen` and its `Origin` and `Host` check, a local
server's `launch.listen` and `launch.path`, `Limits.listen_seconds`, `not_listening`, and the
upstream through the ingress bridge.

| | Listens | Connects | Our stdout |
|---|---|---|---|
| `run`, stdio (today) | — | a client starts us; we start the server | the protocol channel (`cli.py:482`) |
| `drive`, stdio (today) | — | we start the server and feed the proxy through pipes | the operator's |
| `drive`, HTTP | the server, on its declared address | our driver → our proxy → the server | the operator's |
| proxy, HTTP | **we**, on a loopback literal; the server on its own address | the client → us → the server | the operator's |

**HTTP proxy mode is a subcommand of its own.** Each process contract gets its own subcommand
so that what stdout means never depends on a flag (`build_parser`, `cli.py:289–296`). An HTTP
proxy is started by the operator, not by a client, and claims no stdout
(`claim_protocol_stdout`, `cli.py:482`, stays `run`'s). Proposed name: `kymograph listen` (7).
It binds `127.0.0.1` or `::1` and nothing else — the spec says a local server "SHOULD bind only
to localhost"; here there is no flag to do otherwise. Standing in the server's place, it does
what the spec requires of a server: "Servers MUST validate the `Origin` header on all incoming
connections … If the `Origin` header is present and invalid, servers MUST respond with HTTP 403
Forbidden." A request whose `Origin` is not a loopback origin, or whose `Host` is not the
listener's own address, is answered 403 by the proxy, recorded, and never forwarded. The
client→proxy leg is plain HTTP on loopback: the proxy presents no certificate and intercepts
nothing it was not pointed at, so "The position is configured, not stolen" (`README.md:10`)
holds.

**The driver feeds the proxy, as today.** "The proxy is not bypassed, it is fed"
(`driver.py:9–14`) stays true. The driver is an HTTP client whose connections are socket pairs
handed to the proxy's front — the HTTP counterpart of `ClientChannel`'s real pipes
(`driver.py:132–151`) — and the proxy forwards them to the server. Observer, masker, inspector,
sink and shutdown budget are the same code in both modes.

**The upstream has one destination, fixed before the run:**

| Server | Upstream connector |
|---|---|
| local child, `--isolation host` | TCP to the declared loopback address and port |
| corpus entry, `--isolation runc` | the ingress bridge's socket file (3.2) |
| remote endpoint (4) | TLS to the declared origin, certificate verified against the system store |

A server this tool starts declares where it listens (`launch.listen`, a loopback literal with
a port; `launch.path`, the MCP endpoint). The proxy waits for it to accept, bounded by a new
`Limits.listen_seconds`; one that never accepts is `server_failed`, reason `not_listening` —
the HTTP counterpart of `not_started` (`events.py:64`).

### 2.2 The forwarding path and the observer path

```
client ──▶ front (HTTP head parser, bounded) ──▶ relay ──▶ upstream connector ──▶ server
              │                                    │
              └────── copy: heads, body bytes ─────┘     synchronous, never raises
                                  ▼
               HttpObserver ─▶ body and SSE framers ─▶ Inspector ─▶ sink.offer ─▶ writer thread
```

* **The forwarding side parses HTTP, never MCP.** To forward over keep-alive connections and
  rewrite `Host` towards the upstream it has to find where a request and a response end: the
  head (bounded, e.g. 64 KiB and 100 fields), `Content-Length`, chunk boundaries. Body bytes go
  on as they arrive — an SSE stream is never held back to an event boundary — and the observer
  gets each slice synchronously, as `Observer.observe` gets each chunk today (`proxy.py:896`).
  JSON-RPC and SSE are parsed on the copy only.
* **A framing error costs observation, not the connection.** `_ForwardFramer` "must never
  *lose* bytes" (`proxy.py:1248–1258`). Over HTTP, a head or a chunk length the forwarder
  cannot read switches that connection to verbatim pass-through until it closes; the observer
  stops interpreting it and says so (`http_end`, `ended: framing_error`, counted in
  `run_finished`).
* **One client connection, one upstream connection.** No pooling, no reordering: what the
  server sees on a connection is what the client sent on one.
* **Nothing the observer learns is needed to forward.** Sessions, event ids and versions are
  read on the copy; the forwarding side never waits for them. The driver tracks its own
  session, as any client must.
* **Counted where forwarded.** `server_output_bytes` and `client_input_bytes` stay counted on
  the forwarding path (`proxy.py:882–885`); over HTTP they count the body bytes of the MCP
  endpoint, not heads.
* **Every connection task is watched centrally**, as every pump is today (`proxy.py:11–13`).

### 2.3 Framing: bodies and SSE events instead of lines

Over stdio one message is one line (`LineFramer`, `framing.py:47`). Over HTTP one message is:

* a POST body (`application/json`): one message, or one batch (1.3);
* a response body with `Content-Type: application/json`: one message;
* one SSE event on a `text/event-stream` response: its `data` lines joined by newlines.
  Comment lines (`:` — the spec recommends them as keep-alives), `retry` fields and events with
  empty data (2025-11-25: the server "SHOULD immediately send an SSE event consisting of an
  event ID and an empty `data` field") are not messages; they are counted and their ids kept.

New pure framers beside `LineFramer`, under its rules (`framing.py:1–17`): no stream, no
writer, nothing to block on, memory bounded by `max_message_bytes`, an oversized message
counted and dropped rather than clipped. The SSE framer accepts CRLF, LF and CR line ends and a
leading BOM. A body that is neither JSON nor SSE is recorded as text, as an unparseable line is
today.

The `message` event keeps its shape. Its `transport` field exists already (`events.py:247`;
`recorder.message` writes `stdio`, `recorder.py:206`) and becomes `streamable-http`; three
fields link a message to the HTTP structure: `exchange` (our ordinal of the request/response
pair), `stream` (our ordinal of the SSE stream, or null) and `event_id` (2.6).

**Which method a response answers** is known on HTTP from the exchange: a response on a POST
answers that POST's request. The observer hands the request's method to the inspector with the
response; the id table (`Inspector.learn`, `inspection.py:458–467`) stays the fallback for a
legacy GET stream. Over stdio nothing changes.

### 2.4 The two eras on the wire

Built, over HTTP always and over stdio under an engagement file; stdio without one is opened by
`initialize` alone.

| | Legacy (2025-11-25) | Modern (2026-07-28) |
|---|---|---|
| Opening | `initialize`, then `notifications/initialized` | none; `server/discover` optional |
| Every POST carries | `MCP-Protocol-Version` (negotiated); `Mcp-Session-Id` if one was issued | `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (for `tools/call`, `resources/read`, `prompts/get`); version and capabilities in `params._meta` |
| Answer to a request | JSON or SSE; the stream may carry server requests and notifications | JSON or SSE scoped to the request; notifications only |
| Notification POST | 202 | 202 (the revision defines no client notifications over HTTP) |
| GET | optional server stream, or 405 | not in the revision; servers "SHOULD" answer 405 |
| DELETE | ends the session, or 405 | not in the revision; 405 |
| Lost stream | resume with GET and `Last-Event-ID` | "A broken response stream loses the in-flight request; clients MUST re-issue it as a new request with a new request ID" |
| Cancellation | `notifications/cancelled` | closing the response stream |

**The driver detects the era as the spec says, and decides as `eras.py` does.** The code is
the arbiter; this paragraph says what it does (amended 2026-10-29). On
HTTP, "attempt a modern request and inspect the body of a `400 Bad Request` before falling back"
(versioning page). The driver's first request is `server/discover` with modern `_meta` and
headers; its answer is read as any answer is, and of an error status only a 400's body. A modern
error is recognised by its shape, not by its code alone: `UnsupportedProtocolVersion` (−32022)
with `data.supported` as a list, `MissingRequiredClientCapability` (−32021) with
`data.requiredCapabilities` as an object, and `HeaderMismatch` (−32020) by its code, the one
exception (`eras.py:22–42`). Then:

* a `DiscoverResult` that lists `2026-07-28`: **modern**; the listings follow, each with `_meta`
  and headers;
* −32021 or −32020: modern, and **the run stops without a listing** — the driver declares no
  client capability and has none to offer, and a header complaint leaves nothing to send that the
  server has not just refused;
* −32022, or a `DiscoverResult` without `2026-07-28`: if it names a legacy version this tool
  knows, **that version's `initialize`** (a server serving both eras); otherwise the run stops;
* anything else — "the body is empty or is not a recognized modern JSON-RPC error", another
  status, a code without the shape the schema gives it — means **legacy**: `initialize`, and the
  script as today.

A probe that gets no answer at all (no connection, a refused handshake, from 2.8 on a refused
token) ends the run with that failure; it says nothing about the era. In legacy, a server that
answers `initialize` with a version this tool does not know — a later one, a modern one, or text
that is no version — stops the run as well; a refusal of our version that names one this tool
knows is answered with one more `initialize` in it, once. Every stop is `server_failed` with
reason `protocol_unsupported`, its own reason (`modern_refused`, `no_common_version`,
`unknown_version`, `malformed_version`), the error code and what the server put in `error.data`,
masked and clipped; the inventory is `none`, and the terminal says in one line what the server
requires that this tool does not offer. The probe, its answer and the decision are in the
recording, the era in `script_finished`. The same answers give the same decision every run: the
detector is a pure function of them.

**Capabilities and the announced name** come from `initialize` in legacy, and from
`DiscoverResult.capabilities` and `_meta['io.modelcontextprotocol/serverInfo']` in modern. The
inspector reads the name from an `initialize` answer only (`_remember_server`,
`inspection.py:610–618`) and needs the second source. The spec's note on the modern field —
"self-reported by the server … SHOULD NOT rely on it for security decisions" — is what the code
already assumes of the legacy one (`inspection.py:613–614`).

`Mcp-Param-*` headers (`x-mcp-header`) concern `tools/call` only, which the discovery script
never sends ("The script does not act", `driver.py:30–32`).

### 2.5 Sessions (legacy)

Built: the session id is sent back and recorded as an ordinal only, and a `DELETE` ends the
session at the end of the run. Not built:
the second session after a 404 — a 404 ends the step as `session_lost` — and the events
`session_started` and `session_ended`.

2025-11-25: a server "MAY assign a session ID at initialization time" in `MCP-Session-Id` on the
response with the `InitializeResult`; clients "MUST include it … on all of their subsequent
HTTP requests"; after ending it the server "MUST respond to requests containing that session ID
with HTTP 404"; on a 404 the client "MUST start a new session by sending a new
`InitializeRequest`"; a client "SHOULD send an HTTP DELETE … to explicitly terminate the
session", which the server may answer with 405.

* **The value is never recorded, not even as a pseudonym.** `masking.py:80–82` settled it: a
  session id "grants access to the session. It is closer to a bearer token than to a
  correlation id, and it stays blanked." The header name normalises to `mcpsessionid`, which the
  needle `sessionid` blanks (`masking.py:111`). What the judgement needs is where sessions
  begin and end, so the observer numbers the distinct values it sees (session 1, 2, …) in
  memory and records the ordinal only.
* **Driver, on a 404: one new session, the script from the top.** At most one
  re-initialisation per run, and the whole script again in the new session. Pages are not
  stitched across sessions: a cursor of one session need not mean anything in the next, and an
  inventory pieced together from two sessions is one no session showed. Both attempts stay in
  the recording; findings in either are sightings. A second 404 ends the script, and the step
  is short by `session_lost` (5).
* **Driver, at the end: DELETE**, the HTTP counterpart of closing stdin, which for stdio "*is*
  the goodbye" (`driver.py:177–183`). A 405 is a legitimate answer and recorded as one.
* **Proxy:** sessions are the client's. `Mcp-Session-Id` is forwarded verbatim both ways and
  recorded as an ordinal. A DELETE ends a session, not the run; the client may initialise again.

### 2.6 Streams, resumption, and what the recording keeps

Built: resumption (legacy) and re-issue (modern). Not built: the legacy GET stream, and the
session rows of the table below.

**Answers.** A request is answered by one JSON body or on an SSE stream. The driver reads the
stream until the response with its id — matched by id, never by position, reading past at most
`MAX_INTERLEAVED` other messages (`driver.py:78`, `_answer_to` at `driver.py:414`). A server
request on a legacy stream is recorded and not answered (`driver.py:418–422`; the driver offers
no capabilities, `driver.py:115`).

**The legacy GET stream.** Proposed: the driver opens it after the handshake and holds it for
the script, because it is where a legacy server sends what is "unrelated to any
concurrently-running JSON-RPC request" — and over stdio everything a server volunteers is in the
recording. A 405 is recorded and is no shortfall; the server "MAY close the SSE stream at any
time". The modern counterpart, `subscriptions/listen`, is a request for change notifications the
inventory does not need; the driver does not send it (7, question 2).

**Resumption (legacy).** After an event with an id the server "MAY close the *connection*
(without terminating the *SSE stream*)" and "SHOULD send an SSE event with a standard `retry`
field"; the client "MUST respect the `retry` field" and resumes with a GET carrying
`Last-Event-ID`; the server "MUST NOT replay messages that would have been delivered on a
different stream". The driver resumes a stream at most three times, waits `retry` if it fits in
the step's remaining time, and records a step whose answer did not come as `step_unanswered`,
reason `stream_broken`. A message replayed twice is recorded twice; the driver acts on the first.

**Re-issue (modern).** A broken response stream loses the request; the driver re-issues it
once, with a new id, recorded as such; then `stream_broken` as above.

**What the recording keeps**, so that completeness is judged from the artifact:

| Kept | Where | Why |
|---|---|---|
| each exchange: our ordinal, connection ordinal, HTTP method, masked target, masked headers | `http_request` | which request a message answers; what was sent |
| status, masked headers, content type, framing (json, sse, empty, other) | `http_response` | an HTTP refusal carries no JSON-RPC and must not read as silence |
| how the exchange ended (complete, closed after an event id, closed without one, reset, timeout, client closed, framing error) and its body bytes each way | `http_end` | a stream that ended early is another fact than one that completed |
| per SSE stream: event ids as pseudonyms, the last one, `retry` values, comment count | `message.event_id`, `http_end` | which resumption continued which stream, after which event |
| per resumption: the stream resumed, the `Last-Event-ID` sent (pseudonym) | `http_request.resumes` | that a resumed stream starts where the broken one stopped |
| per session: ordinal, the exchange that opened it, whether an id was issued, how it ended (404, DELETE and its status, end of run) | `session_started`, `session_ended` | an inventory comes from one session |
| the era, the protocol version, the session the script finished in | `script_finished` | what "complete" was judged against |
| counts of all of the above, made where traffic is forwarded | `run_finished.http` | the cross-check that survives dropped events |

**Event ids become handle pseudonyms.** An SSE id exists to tie a resumption to its stream,
which is what the handle set is for (`masking.py:63–92`); but 2025-11-25 says ids "SHOULD encode
sufficient information to identify the originating stream", and a server may fold its session
into them. Pseudonymised with the run's keyed HMAC (`Masker.pseudonym`, `masking.py:154–165`),
the relation survives and the value does not.

**Droppable or not, as today.** `offer` is for what may be lost, `put` for what may not
(`sink.py:18–20`). What the forwarding side produces is offered, like `message`
(`proxy.py:243`) — a full queue must not hold up forwarding. What the driver writes is put; it
may wait (`record_step_skipped`, `proxy.py:476–488`). Counts made where traffic is forwarded
go into `run_finished`, which is written on the path that does not drop. The verdict judges from
the driver's events and the counts, never from whether a droppable event is present.

### 2.7 Version and request-metadata headers

* Legacy: the client "MUST include the `MCP-Protocol-Version: <protocol-version>` HTTP header
  on all subsequent requests"; without it the server "SHOULD assume protocol version
  `2025-03-26`"; an invalid or unsupported one gets 400.
* Modern: every POST "MUST include an `MCP-Protocol-Version` header", whose value "MUST match"
  the version in `_meta`, else 400 with `HeaderMismatch`; `Mcp-Method` on every request and
  `Mcp-Name` where it applies "are REQUIRED for compliance", values outside visible ASCII
  encoded as `=?base64?…?=`.
* The driver sends what its era requires and the version it negotiated or chose. The proxy adds
  and removes none of them. A header that disagrees with the body is recorded as observed: it
  is the client's or the server's, and a modern server must reject it.

### 2.8 Authorization headers and OAuth

Built for the driver: masking at record time, and a token from a file (`--token-file`) or an
environment variable (`--token-env`). The proxy's part needs `listen`, which is not built.

2026-07-28: authorization is "OPTIONAL"; "Implementations using an STDIO transport SHOULD NOT
follow this specification"; a protected server is an OAuth 2.1 resource server; the token is
sent as `Authorization: Bearer` and "authorization MUST be included in every HTTP request",
never in the query string; a 401 points at the protected-resource metadata with
`WWW-Authenticate: … resource_metadata=`; clients "MUST implement Resource Indicators" naming the
server's canonical URI; servers "MUST NOT accept or transit any other tokens".

**Masking at record time.**

* Headers are recorded as a map through `mask_json`. `Authorization`, `Proxy-Authorization`,
  `Cookie` and `Set-Cookie` are blanked whole by the needles `auth` and `cookie`
  (`masking.py:100–114`).
* `WWW-Authenticate` is the one header parsed before masking: its scheme, then its parameters
  as a map, each masked by the ordinary rules. Unparsed, the needle `auth` blanks it whole, and
  the text rule for `Bearer …` (`masking.py:116–122`) would mangle its parameter list; parsed,
  `resource_metadata`, `scope` and `error` stay legible — where a server sends clients for a
  token is worth seeing. A closed exception anchored on the header's name, as the handle set is
  anchored on paths (`masking.py:63–69`).
* The query string is split into a map and masked the same way.
* Values masked in server-to-client headers count in `server_redactions`
  (`events.py:859–864`), as values in bodies do.

**The driver never runs an OAuth flow.** It fetches no metadata, contacts no authorization
server, opens no browser, registers no client, stores no token. The operator supplies a token —
a file, or the name of an environment variable; never the value in argv, where it would reach
`run_started` behind nothing but `mask_argv` — and the driver sends it to the run's one origin
and nowhere else. A 401 or 403 is recorded with its parsed challenge and ends the step
(`unauthorized`, 5). The terminal says which host the server sends clients to, and that the
operator has to obtain a token.

**The proxy forwards and does not take part.** `Authorization` goes upstream verbatim, to the
configured origin only (the proxy follows no redirect); a 401 and its challenge come back
verbatim. Whether a client's OAuth flow works through the proxy is the client's business, and by
the specifications it does not: RFC 9728 §3.3 requires that the metadata's `resource` "MUST be
identical to the URL that the client used to make the request to the resource server", else
"the data contained in the response MUST NOT be used". A client pointed at
`http://127.0.0.1:PORT/mcp` receives the upstream's identifier and has to refuse it. Rewriting
the metadata until it passes would be the impersonation that check exists to stop (RFC 9728
§7.3); it is not done. Through `listen`, a protected server works with a token the
client already holds as a static header, or not at all (7, question 7).

### 2.9 How a run ends

Built for the driver against a running server. Not built: `listen`, and a local child over HTTP
with its `server_stdout`.

Over stdio the client's end of input ends the run (`_supervise`, `proxy.py:829–837`). HTTP has
no end of input.

* **Driver:** after `script_finished` (and the DELETE, in legacy) the driver closes its
  channel and the proxy stops at once. An HTTP server does not exit because a client left, so
  the grace for a server to exit by itself (`_grace_then_stop`, `proxy.py:847–850`) is stdio's
  only; the child's group is terminated as today. `server_exited_first` keeps its meaning: the
  server ended while the client was still speaking.
* **`listen`:** the operator's signal, `--max-duration`, or the server's exit. Open SSE streams
  are closed by the proxy within the shutdown budget (`proxy.py:18–22`).
* **A local child's stdout is a log over HTTP**, not the protocol channel. It is recorded like
  stderr, as a new `server_stdout` event, and is not server output.
* **`server_silent` and `empty_session`** (`verdict.py:129–151`) are worded on bytes the server
  wrote to its stdout. Over HTTP the count they read is MCP body bytes (2.2): a server that
  answers every POST with an empty 500 said nothing. Their arithmetic can stay; their meaning
  moves, which is the verdict's to state (6.3).

### 2.10 Scenarios with rules

Built as the refusal: a scenario that loads rules is refused over HTTP. Rules over HTTP are not
built.

Rules replace and drop whole messages on the forwarding path (`_forward_intercepted`,
`proxy.py:910–963`). Over HTTP that means re-framing bodies and SSE events and rewriting
`Content-Length` or chunking while forwarding — a design of its own. Until it exists, a scenario
that loads rules is refused over HTTP before anything starts. Observation-only scenarios run,
which is every scenario the corpus has (`tests/fixtures/scenarios/all-signals.yaml`:
"Observation only: no rules").

## 3. The server inside the sandbox, without weakening the egress gate

Not built: nothing in this section exists yet. A corpus entry over HTTP is an endpoint entry
under isolation `remote`; no HTTP server runs inside the sandbox.

Today the target joins the sink's namespace (`_confined`, `runner.py:632–651`) and speaks over
the stdio that `docker run -i` attaches (`target_argv`, `runner.py:499–514`). The namespace has
loopback and a dummy device and nothing else, and that is the barrier (`runner.py:3–7`). An
HTTP server must be reached from outside it.

### 3.1 What is not done

| Way in | Why not |
|---|---|
| `docker run -p`, or any Docker network | an interface that leads to the host's bridge: the barrier is gone |
| a veth into the host or a helper namespace, conntrack admitting only connections opened from outside | `ct state` would then be the barrier, and "A rule that is missing costs observation and opens nothing" (`runner.py:5–6`) would no longer be true |
| `docker exec`, or one `docker run -i` relay per connection | no new socket, but a container start per connection, and one multiplexed pipe would let a stalled SSE stream hold up the next POST |

### 3.2 The ingress bridge

A fourth sandbox role, `bridge`, from the sandbox image, joined to the sink's namespace
(`--network container:<sink>`) with every capability dropped, a read-only root, and one extra
mount: a directory in the run's staging area, read-write. It

1. binds a Unix socket **by path** in that directory and listens; it binds no TCP or UDP socket
   and no abstract Unix socket;
2. for each connection accepted there opens one TCP connection to the entry's declared loopback
   address and port (`launch.listen`, fixed when the bridge starts; it can connect nowhere
   else), and copies bytes both ways with backpressure, parsing nothing;
3. writes its account on stdout, one JSON object per line as the sink does: `listening`,
   `accepted n`, `connected n` or `refused n <errno>`, `closed n <bytes in> <bytes out>`.

The proxy's upstream connector connects to that path and sends `Host: <declared address>`,
which is what the server would see from a local client. The target keeps `-i` with a pipe
nobody writes to, so a server that exits on end of input is not ended by us.

### 3.3 Why the barrier holds, and exactly what changes

**It holds.** The interfaces stay `lo` and the dummy `eth0`, checked before the target
(`barrier`, `egress.py:192–195`) and after it (`_unchanged`, `runner.py:561–571`). The bridge's
connection to the target runs over `lo`, which the ruleset neither records nor redirects
(`oifname "lo" return`, `rules.nft:80` and `:96`), and so do the target's replies on it. So the
replies on the allowed inbound connection are not counted as egress — by the rules as they are,
with nothing added. Every packet the target sends off `lo` is recorded and redirected exactly as
today, inbound connection open or not.

**What changes, all of it:**

1. **A socket the namespace did not have.** A path-bound Unix socket appears in the namespace's
   table (`/proc/net/unix`, counted by `socket_inventory`, `common.py:176`; expected 0 today,
   `common.py:185`). It is reached through the file system, and the target's mounts are the
   delivered files, the resolver file and a `/tmp` of its own (`runner.py:508–509`, `:644`,
   `:650`): it has no path to it. Checked on every run, not assumed (3.4).
2. **The target has a peer it can address in HTTP.** Over stdio its peer was a pipe read by the
   same proxy; the trust relation is the same, but the peer is now an HTTP client a server can
   try to steer (3.6).
3. **A tell.** The bridge's socket shows in `/proc/net/unix`, beside the sink's sockets in
   `/proc/net/tcp`.
4. **What moves after the baseline** was the target's alone ("what moves after it is the
   server's alone", `README.md:531–532`). Now it is the target's or the bridge's — and the
   bridge connects to a loopback address only, which the record never holds
   (`rules.nft:77–82`). So the sentence stays true of the record.

### 3.4 The order, and new gate conditions

The bridge starts after the sink is armed and before the probe, so the probe proves the
target's view with the bridge in place:

1. sink (`--network none`); 2. helper; 3. sink armed; **4. bridge, until it reports
   `listening`**; 5. positive probe, then the baseline; 6. gate; 7. target.

| Condition | Established by | Holds when |
|---|---|---|
| `ingress_bindings` | the probe's socket inventory | the namespace holds the sink's bindings (`SINK_BINDINGS`, `common.py:33–42`) and exactly one Unix socket, bound by path to the bridge's path, and no other listener. A stdio entry keeps `unix: 0`. Needs the inventory to name Unix paths, not count lines |
| `ingress_unreachable` | the probe, under the target's confinement | connecting to the bridge's path fails (it is not in the probe's mount namespace), and so does the abstract name of the same string |
| `ingress_path` | the probe as a stand-in target, with the host | the probe listens on the declared address, the host connects through the bridge, a nonce goes each way. Proves the path before the target exists, so a target that never listens is `server_failed`, not a broken bridge |
| `ingress_uncounted` | the baseline record | no set element names the declared port, and `n_tcp4` and `n_tcp6` equal the TCP attempts of the probe's plan (two per family, `common.py:99–149`): the open inbound connection added nothing to the record |

The probe holds the inbound connection open while it makes its egress attempts, so `probe`
(`judge_arrivals`, `egress.py:212–232`) is proven with an inbound connection in place: an open
ingress neither hides nor misattributes an outbound attempt. The host closes that connection
first, so no `TIME_WAIT` is left on the declared port for the target to trip over. The probe
then no longer runs to completion before it is read (`_run_json`): the host reads its
`listening` line, connects, and reads the rest. The manifest refuses a listen address that is
not a loopback literal, and the sink's ports 15001 and 15053, which the ruleset rejects on `lo`
(`rules.nft:111–112`).

### 3.5 After the target

* **Reconciliation is unchanged.** The sink never sees the inbound connection (it is not
  redirected), the kernel's sets never hold it (`lo`), so membership (`reconcile`,
  `egress.py:341–372`) compares exactly what it compares today: what the target sent off `lo`.
* **Order of removal:** the target, then the bridge after its last account line, then the final
  reader — so `_unchanged` keeps comparing against the sink's bindings alone.
* **One more account, of the instrument: `ingress_account`.** Every connection the host opened
  through the bridge is in the bridge's account and the other way round, with equal byte counts
  each way. Both sides are ours; a difference means the bridge lost or invented bytes, and the
  recording would misstate what the server said. `sandbox_failed` after the target, as
  `reconciliation` is today (`proxy.py:628–639`).
* **Readiness:** until the target listens the bridge reports `refused`, and the host retries
  within `listen_seconds`. The attempts are counted; they are nobody's egress.

### 3.6 The host side cannot be steered

Under runc the upstream connector is built from a socket path, not from a URL. It resolves no
name and has no other destination. Redirects are recorded and not followed; a
`resource_metadata` URL is recorded and not fetched; the one thing from the server it obeys is
`retry`, a delay before reconnecting to the same path, bounded by the step's time. The head
parser is bounded, so a server that sends an endless head or trickles bytes costs the run its
step timeout and nothing else. This is the HTTP half of the barrier: the namespace leads
nowhere, and neither does the client that talks into it.

## 4. Remote HTTP servers

A hosted endpoint is run by someone else. Nothing here can isolate it, observe its network or
pin its code.

### 4.1 Provenance, isolation, identity

Built, except the soft flags of the last point other than the certificate (8.4). The endpoint is
declared as `source.endpoint`, a URL, and the label as `source.version_declared`.

* **Provenance stays `real-world`.** Provenance says whose code it is and what a finding means
  (`corpus.py:16–21`): someone else's, and a disclosure candidate. A fourth provenance would
  change three `CHECK`s and the store's schema (`store.py:112`, `:146`, `:178`) for an answer
  that is the same.
* **Isolation `remote`, new:** not run by this tool, its egress not observed. `policy.decide`
  (`policy.py:34`) learns that an endpoint entry runs under `remote` and nothing else, and that
  a command entry never does.
* **Identity kind `endpoint`, new**, beside `content` and `revision` (`identity.py:99`, `:163`).
  The version cannot come from content — there is none to read. It is the canonical endpoint
  URL and a **label the operator declares** for the deployment (`source.endpoint: {url,
  label}`), recorded as a claim, the way `authorization` is (`authorization.py:47–57`).
* **Observed beside it, never keyed:** the addresses the name resolved to; the TLS leaf
  certificate's SHA-256 fingerprint, subject and names; the announced `serverInfo`; a digest
  over the discovery answers. A comparison shows them on the server axis as a soft flag ("the
  certificate, the announced version or the listing moved; the label did not"). A digest of the
  listing cannot be the version: a server whose descriptions vary would get a new version every
  run, and repetitions of one key would no longer share one (`repeated-runs.md` 2.1).

### 4.2 What can be stated

Built as a caveat: `store diff` adds `server_unpinned` to new and gone when a side's version is
declared; the attribution itself is unchanged.

* **Nothing about egress.** The evidence-kind identities of `repeated-runs.md` 4.1 that come
  from the sandbox — an egress attempt, a name asked — do not exist for a remote entry, and
  "absent" can never be said of them.
* **What it said, not what it did.** The text signals, every one a heuristic
  (`repeated-runs.md` 4.1), and the protocol facts — `server_name_mismatch`, an identical tool
  name twice in one listing — apply to its answers as to any other server's.
* **The server is unpinned.** The same URL and label can serve other code tomorrow. A diff
  between two runs of a remote entry therefore never puts a new or gone finding down to the tool
  or the scenario axis alone: the server axis counts as possibly moved, always. A store rule
  (`store.py`, `_attribute`), not a verdict rule.

### 4.3 Marking

`run_started.isolation` and the environment say `remote`. Wherever a result is shown it says
beside it **"egress not observed"** — for `remote`, and for `host`, which has the same property
today without saying so. The verdict exposes whether egress was observed (isolation in
`OBSERVED_ISOLATIONS`, `verdict.py:78`), and every report prints from that — never from the
absence of `egress_attempt` events.

### 4.4 Authorization and engagement

Built, with two differences: the gate checks the URL's host and a declared `--target` each,
rather than refusing a `--target` that differs; and the driver sends no `User-Agent`.

* **The target becomes a fact.** `--target` is the operator's typed claim today
  (`cli.py:243–249`); `authorization.py:21–23` foresaw that it "gains a transport meaning when
  a networked transport arrives". Over HTTP the gate is fed the host of the run's URL, parsed
  strictly and failing closed as `host_of` does (`authorization.py:100–139`, which refuses a
  URL as such); a `--target` that differs is refused. The gate still resolves no name
  (`authorization.py:15–19`).
* **Every corpus run of a remote entry needs `--engagement-confirmed`** under the rule as it is:
  a corpus run selects its scenario before the gate (`cli.py:560`, gate at `cli.py:589`). A
  `drive` against a URL without a scenario stays observation and needs none.
* **No OAuth on its own** (2.8). **Plain HTTP only to loopback literals**; any other origin must
  be HTTPS with a verified certificate, so a token never travels in clear.
* **`localhost` is local for the gate, and not loopback for plain HTTP** (decided 2026-11-02):
  for the gate, `localhost` is local (`authorization.LOCAL_TARGETS`, unchanged) because the run
  is the operator's own; for the plain-HTTP rule only literals are loopback
  (`authorization.LOOPBACK_LITERALS`) because a name is resolved and plain HTTP has nothing that
  binds the name — TLS has the certificate, which is why `https://localhost` is fine.
* **No disguise.** `clientInfo` already says `mcp-kymograph` (`driver.py:114`); the `User-Agent`
  says the same.

### 4.5 Traffic

Built: one run per origin and 10 s between runs by default, which an engagement file may change;
the one wait for `429` and `503`. A remote entry is refused in a fleet; the opt-in fleet with
remote entries is not built.

* **One run is bounded by the script:** in legacy, one `initialize`, one
  `notifications/initialized` and four listings of at most `MAX_PAGES` = 20 pages
  (`driver.py:68`, `:116–121`) — at most 82 POSTs, plus one GET and one DELETE; in modern, one
  `server/discover` and the same 80.
* **One run per origin at a time**, whatever `--parallel` says, and a minimum interval between
  runs to one origin (proposed: 10 s). A remote entry is never part of an ordinary `fleet run`,
  which runs everything under runc (`fleet.py:63`, `:474–476`); a fleet with remote entries is a
  separate opt-in that needs the confirmation for each origin, scenario or not.
* **`429`, and `503` with `Retry-After`,** are waited out once if the wait fits in the step's
  remaining time; otherwise the step is short by `rate_limited` (5).
* **Repetition:** no lower budget for remote, as `repeated-runs.md` 7 holds for real-world. A
  heuristic series of 48 runs at 84 requests is about 4000 requests per key, spread by the
  interval above: fewer at once, not fewer in all.

## 5. New causes for `verdict.CAUSES` (proposed — `verdict.py` is not edited)

Built since: `unauthorized`, `rate_limited`, `session_lost` (at the first 404, since there is no
second session), `protocol_unsupported` and `http_counts_missing`. Not built: `http_unparsed`
and `ingress_inconsistent`.

"Server can trigger" in the sense of `repeated-runs.md` 4.6. Every key today maps to one state;
these keep that. A failure of the run's opening request stays under `server_failed` with the
HTTP particulars in its reason word (`http_status`, `unauthorized`, `rate_limited`,
`not_listening`); the keys below cover what happens after it — except `protocol_unsupported`,
which says something about this tool's script rather than about a server that failed, and is
therefore its own key under `server_failed`. Which key a short step gets is
chosen by the reason word the driver wrote, as `_step` already chooses between
`step_unanswered`, `step_not_sent` and a truncation; the words live in `events.py` beside the
existing ones (`events.py:44–77`), so the word written and the word judged cannot drift.

| Key | Meaning | State | Server can trigger |
|---|---|---|---|
| `http_unparsed` | an HTTP exchange with the server could not be read (head, chunking, SSE); messages in it may be missing | incomplete | **yes** — it writes the bytes |
| `unauthorized` | a step was refused for authorization (401, 403); the challenge is recorded | incomplete | **yes** — and so does an operator's expired token, which looks the same |
| `rate_limited` | a step got 429, or 503, with a `Retry-After` that did not fit in its time | incomplete | **yes** — and so does other clients' load on the same endpoint |
| `session_lost` | the server ended the session (404) and the script did not finish within one session after the one re-initialisation | incomplete | **yes** |
| `protocol_unsupported` | the server and the script share no protocol version or era: a modern-only rejection of `initialize`, or `UnsupportedProtocolVersionError` listing nothing the script speaks | server_failed | **yes**, deterministically: every repetition shows it |
| `ingress_inconsistent` | the bridge's account of the inbound connections differs from the host's (3.5) | sandbox_failed | **no** by design — the bridge parses nothing and copies with backpressure; plausible, not measured |
| `http_counts_missing` | an HTTP run's `run_finished` has no `http` counts | incomplete | **no** — both closing paths write them |

Not new keys: `not_listening` (a reason under `server_failed`); `stream_broken` and an HTTP
status on a later step (reasons under `step_unanswered`); the four ingress gate conditions of
3.4, recorded as `sandbox_failed` events, which `assess` judges whatever the condition
(`verdict.py:314–319`) — before the target the server cannot cause them, and
the split of `sandbox_failed` by phase (`repeated-runs.md` 4.6) applies to them unchanged.

## 6. What can be built independently of `verdict.py`

The plan of work as it was written; what of it is built is in the status line at the top.

### 6.1 The contract, first

Agreed and written into `events.py` before either side starts:

1. **Events and fields.** New: `http_request`, `http_response`, `http_end`, `session_started`,
   `session_ended`, `server_stdout`. Extended: `message` (`exchange`, `stream`, `event_id`),
   `run_started` (`transport`, masked `endpoint`), `script_finished` (`era`,
   `protocol_version`, `session`), `run_finished` (`http`: exchanges by HTTP method and status
   class, streams opened, completed, broken and resumed, sessions opened and expired, framing
   errors, `Origin` refusals). Which are offered and which put (2.6).
2. **The reason words:** `not_listening`, `stream_broken`, `session_expired`, `http_status`,
   `unauthorized`, `rate_limited`, `protocol_unsupported`; the era names `legacy` and `modern`.
3. **The strings** `streamable-http` (transport), `remote` (isolation), `endpoint` (identity
   kind).
4. **The sandbox's condition names** (3.4, 3.5) — for the recording; the verdict judges
   `sandbox_failed` events whatever their condition.
5. **`events.SCHEMA_VERSION` 3 → 4**, once, when the contract lands (3 came with `run_stopped`).
   It changes what the verdict reads without editing it (`schema_problem`,
   `verdict.py:244–275`): recordings of schema 3 are refused whole from then on.

### 6.2 Independent of `verdict.py`

| Module | What | Waits for |
|---|---|---|
| `framing.py`, or a new `http/` package | head parser, chunk tracker, JSON body and SSE framers — pure, bounded, tested against bytes | nothing |
| `proxy.py` | HTTP front (loopback listener, socket-pair intake), relay, the three connectors, the HTTP observer, `Origin`/`Host` check, closing open streams, `server_stdout`, the HTTP end of a run | framers; 6.1 |
| `driver.py` | HTTP client channel, era detection, the modern script, sessions, GET stream, resumption, re-issue, DELETE, token from a file | 6.1 |
| `recorder.py`, `events.py` | the events and fields of 6.1 | 6.1 |
| `masking.py` | header maps, parsed `WWW-Authenticate`, query maps, event-id pseudonyms (session ordinals live in the observer) | nothing |
| `inspection.py` | the answered method from the exchange; the announced name from `server/discover`; batch elements | nothing — findings move, and the fixture corpus's `expected.json` is re-pinned |
| `sandbox/inside/bridge.py` (new), `runner.py`, `common.py`, `probe.py`, `egress.py` | the bridge, the order, the four gate conditions and `ingress_account`, an inventory that names Unix paths | 6.1, item 4 |
| `corpus.py`, `identity.py`, `policy.py` | `streamable-http`, `launch.listen`, `launch.path`, `source.endpoint`, kind `endpoint`, isolation `remote`; the launch digest takes the new fields for HTTP entries only, so every stdio entry keeps its digest | nothing |
| `authorization.py`, `cli.py` | the URL's host for the gate; `listen`; `drive --url`; token file; `--listen-seconds`; refusing rule scenarios over HTTP | nothing |
| `store.py` | the unpinned server axis for `endpoint` identities; refusing HTTP recordings until 6.3 lands (below) | nothing |
| `fleet.py` | remote entries as an opt-in with per-origin pacing | nothing |

### 6.3 Needs `verdict.py`

* the keys of section 5, and the mapping from events and reason words to them;
* `ISOLATIONS` gains `remote`, outside `OBSERVED_ISOLATIONS`. Until then a remote recording is
  `unknown_isolation` (`_isolation`, `verdict.py:433–440`) — incomplete, which fails safe;
* whether egress was observed, exposed with every verdict (4.3);
* the wording of `server_silent` and `empty_session` over HTTP (2.9), and whether that is a
  rule change;
* reading `run_finished.http` (`http_unparsed`, `http_counts_missing`);
* one `RULES_VERSION` bump for all of the above (pinned by `tests/test_rules_version.py`);
* the rows of section 5 in the table of `repeated-runs.md` 4.6.

### 6.4 Order

Once 6.1 is written, three strands run in parallel: **transport** (framers, proxy, driver,
recorder, masking, CLI), **sandbox** (bridge, runner, probe, conditions — they meet the transport
only in a socket path and a `Host` value), and **judgement** (6.3, against hand-written
recordings of the new schema). Most of what can go wrong over HTTP already reaches the verdict
as `server_failed` or `step_unanswered` through the driver, so today's rules do not take an HTTP
run that lost its answers for complete. What only the observer knows — a framing error on a
connection, `http_unparsed` — they cannot see. So until the judgement lands, the store refuses a
recording whose transport its rules do not cover (`_read_run`, `store.py:962`), and no HTTP run
enters a comparison. `remote` is held at `unknown_isolation` meanwhile.

## 7. Open questions

Answered by what is built: 1, 3, 6, 11 and 12, each marked below. Still open: 2, 4, 5, 7, 8, 9,
10 and 13.

1. **The driver's era order.** Modern probe first, as proposed (2.4), or legacy only for a first
   release? And does the stdio driver get the same `server/discover` probe, which the spec
   recommends for dual-era clients on stdio? *Answered:* the modern probe first, over HTTP
   always; over stdio under an engagement file only.
2. **The legacy GET stream in driver mode** (2.6): opened for parity with stdio, or left out for
   fewer moving parts?
3. **Session expiry** (2.5): one re-initialisation and the script from the top, or incomplete at
   the first 404? *Answered:* incomplete at the first 404, cause `session_lost`.
4. **The bridge's user and the socket directory:** the host user's uid for the bridge alone, or
   uid 65534 with a `0733` directory inside a `0700` one? Rootless Docker and user-namespace
   remapping change the answer; not measured.
5. **gVisor.** Under runsc the target's loopback lives in gVisor's netstack, and a bridge in
   another container does not share it. If the runsc sandbox is built with a veth into a sink
   namespace, the bridge would sit in the sink namespace and the inbound connection would cross
   the interface the rules watch; telling it from egress would then be a conntrack
   matter (`ct direction`): part of the account, still not of the barrier. To be decided with the
   runsc sandbox, which this version does not provide.
6. **HTTP+SSE** stays refused unless real-world candidates need it; then only with the
   `endpoint` URI held to the server's origin as a hard condition. *Answered for now:* refused,
   and detected as `http_sse_only` (1.2).
7. **OAuth through `listen`** (2.8): accept that it works only with a token the client already
   holds? A flow with the operator in the loop (PKCE, `resource`, `iss` validated as the spec
   requires) would be a separate command that never runs inside a fleet.
8. **Rule scenarios over HTTP** (2.10): needed before real-world proxy sessions are the goal, or
   later?
9. **Signals the transport exposes**, declared-only until a false-alarm rate is measured: URLs in `Location`, `Link` and `WWW-Authenticate` (`resource_metadata` naming
   an authorization server elsewhere); an `x-mcp-header` annotation that breaks the 2026-07-28
   constraints; the `inputRequests` of an `InputRequiredResult` as surfaces.
10. **`ingress_uncounted`:** membership only, or exact counter equality as well (3.4)? Measure
    under `--parallel 16` before the counters become a condition.
11. **Pacing for remote entries** (4.5): 10 s and one run per origin, or the endpoint operator's
    word in the manifest? *Answered:* 10 s and one run per origin by default; an engagement file
    may set other values (`pacing`).
12. **Cookies:** the driver sends none back (no state, same run every time); a load balancer that
    pins sessions by cookie then breaks legacy sessions. Accept, or keep cookies within a run?
    *Answered for now:* accepted; the driver sends no cookie.
13. **The subcommand's name:** `listen`.

## 8. Addendum (2026-10-29): TLS to a remote endpoint

Section 2.1's last upstream row — "TLS to the declared origin, certificate verified against the
system store" — made concrete, for the endpoint entries of 4.1. **Built**, after 8.2, 8.3 and
8.4 were amended on 2026-10-29. The version numbers below are those of the step that built it;
this version is at rules version 14 and store schema 13.

**Why now.** Plain HTTP is spoken only to a loopback literal (4.4): from another host, a
recording made over plain HTTP is evidence of what arrived, not of what the server sent — anyone
on the path could have changed it — and the server's answers crossed the network readable. That
refusal leaves an endpoint entry on another host usable only over TLS. Tokens and OAuth (2.8)
stayed out of this step.

### 8.1 The connection

* `https://` URLs are read where `http://` URLs are (`http_client._parse_url`, the manifest's
  `source.endpoint`, `drive --http`), with the same conditions: a host, an explicit port, a path,
  no user, password or fragment.
* TLS is made where the upstream connection is made, `HttpProxy.front_connect`:
  `asyncio.open_connection(host, port, ssl=context, server_hostname=host)`. The driver's leg to
  the proxy stays a socket pair; the observer, masker and inspector see the plaintext as now.
* `context` is `ssl.create_default_context()`, made once per run, and nothing else: the system
  trust store as OpenSSL finds it, the host name checked, a certificate required, the default
  minimum version. No flag for a CA, for turning verification off, for a client certificate,
  for ciphers or for ALPN; no `HTTPS_PROXY` is read. The handshake falls within the time a
  connection already has (`DEFAULT_CONNECT_TIMEOUT`, the step timeout in `drive`).
* What OpenSSL itself reads — `SSL_CERT_FILE`, `SSL_CERT_DIR` — is the machine's trust store, not
  a setting of this tool; the tests use it to trust a test CA (8.6).

### 8.2 What is recorded

* `http_request` gains `tls`: `null` over plain HTTP; over TLS `{"version": "TLSv1.3",
  "certificate_sha256": "<64 hex>"}` — the negotiated protocol version, and the SHA-256 of the
  leaf certificate as presented (`getpeercert(binary_form=True)`, DER). One connection carries one
  exchange, so every exchange names the certificate its own connection presented. Nothing else of
  the certificate (no subject, issuer or chain). Additive: recording schema stays 5, as
  `pacing_enforced` and `window_exceeded` did.
* **The run's set, where nothing is dropped.** An `http_request` can be dropped under the event
  bounds, so the store does not read the fingerprints from it: `run_finished.http` gains `tls`,
  `null` without TLS, else `{"versions": [...], "certificates": [...]}`, each list distinct and
  sorted, gathered where the connections are made. Per exchange in `http_request.tls`, per run in
  `run_finished.http.tls`.
* `run_started.trust_store_env`: `{"SSL_CERT_FILE": bool, "SSL_CERT_DIR": bool}` for an `https`
  run, `null` otherwise — whether each variable was set, never its value (8.1: what OpenSSL reads
  is the machine's trust store, and a recording says which kind it was).
* `run_started.endpoint.scheme` says `https`; the launch digest of an endpoint entry moves with
  the URL, scheme included.

### 8.3 When the handshake fails

The TCP connection is made first; one that cannot be made, in the time connecting has, stays
`http_unreachable`. From the moment it is up, every way the handshake on it does not complete —
a certificate that does not verify, a name that does not match, no common protocol, the
connection reset or closed during it, a peer that does not answer in the time that is left — is
not `http_unreachable`: the channel's failure is `tls`, with `detail`, the library's text, or
ours for a connection that ended or a handshake that did not finish in time (at most 300
characters, filtered for the terminal, masked). No bound of asyncio's longer than the connecting
time decides it (amended after a review found a reset or a stall read as unreachable). Where it is written depends on the exchange, as for every failure over HTTP
(rule 8):

* **on the first exchange** (`initialize`; `server/discover` once the modern era is spoken):
  `server_failed` with reason `tls` and the text in its existing `detail`; the run is
  `server_failed`;
* **later**: `step_unanswered` with reason `tls`, and `step_unanswered` gains `detail` (an empty
  string for every other reason); the run is `incomplete`.

`verdict.HTTP_CAUSES` gains `tls`. `RULES_VERSION` becomes 11.

### 8.4 The store: the certificate as the first pin

* At ingest, the run's set from `run_finished.http.tls.certificates` (8.2) goes into a new
  column `runs.endpoint_certificates` (JSON list, `NULL` without TLS). Store schema 11 → 12, one
  step, additive and not migrated: a store of 11 is refused whole, as every step was. What a
  person wrote into a store of 11 — its triage — is carried across by `store triage export` and
  `store triage import`: the export is the one reader of the previous schema, and reads the
  `triage` table and the engagement rows of `meta` and nothing else.
* **The certificates are not an axis.** `AXES` is unchanged, and so is the attribution. The sets
  are compared as sets: when both runs have one and they share no certificate, `store diff` adds
  the caveat `certificate_changed` to new and gone — the endpoint presented certificates in this
  run that share none with the other's; a rotated certificate is not a changed server. Overlapping
  sets, equal sets, a side without TLS, or a side whose handshake never completed (an empty set:
  nothing was presented to compare) add nothing: an endpoint behind several certificates (a
  load balancer) that met another subset met the same deployment as far as the handshake can say.
  The caveat never moves the server axis alone; `server_unpinned` stays beside it, because the
  fingerprint pins what answered the handshake, not the code behind it, so neither a same nor a
  changed certificate says whether the deployment changed.
* Shown as recorded: `store runs`, report section 2 (per run) and 5 (beside the attribution),
  `engagement recheck` (beside `gone`, with `server_unpinned`), the web interface's run header and
  diff.

### 8.5 The gate and the engagement file

The URL's host is the target, as for every HTTP run. A non-local target that leaves its `ports`
out now defaults to 443 — the port of the one scheme a non-local host is spoken to with — and
`engagement show` prints "443 (default for https; not in the file)"; since plain HTTP is spoken
only to a loopback literal, the earlier default of 80 would reach nothing. The engagement file
gains nothing: a fingerprint the file names would be a claim, and is for a later `declared` field
if ever.

### 8.6 Tests, without a network

A test CA and a leaf certificate for `127.0.0.1` and `localhost`, committed under
`tests/fixtures/tls/` (PEM, made once with `openssl`, long-lived, marked as test-only keys), and
the loopback HTTP fixture served over TLS with an `ssl.SSLContext(PROTOCOL_TLS_SERVER)`; the CA is
trusted through `SSL_CERT_FILE` in the test's environment. Cases: a run over `https://` records
the version and the fingerprint and files them; a certificate for another name and one from an
unknown CA are each `server_failed`, cause `tls`, with the library's text; a certificate that
stops verifying after the first exchange is `step_unanswered`, `tls`, `incomplete`; two runs with
disjoint certificate sets give `certificate_changed` beside `server_unpinned` with the axes and
the attribution they would have without it, overlapping sets nothing; an `https://` URL to a
non-local host is gated as an `http://` one was (a leaf for `127.0.0.2`, which reaches this
machine and is not local to the gate); a store of schema 11 is refused, and its triage exported
and imported into a fresh store of 12. No test connects beyond loopback.

### 8.7 Not in this step

Tokens and OAuth (2.8), client certificates, a CA or verification setting, a fingerprint pinned
by the operator or by an engagement file, HTTP/2, `HTTPS_PROXY`, `listen` (TLS on the proxy's front would
need a certificate the client trusts — interception, which this tool does not do).

**Order and size.** The URL and the context (`http_client.py`, `http_proxy.py`), the record
(`events.py`, rule 11 in `verdict.py`), the store (schema 12, column, caveat, the triage
carried), the default port (`engagement.py`), then `cli.py`, report, web and documentation; a few
hundred lines with the tests, in that order.

**Questions, answered on 2026-10-29.** (1) Schema 12 for the fingerprints — it refuses every
store of 11, the engagement stores made with this version included: yes, shipped with `store
triage export` and `store triage import` (8.4). (2) `detail` on `step_unanswered` for the
library's text, rather than an event of its own: yes (8.3). (3) The set of fingerprints as the
axis value: no — a set per run, compared as sets, the caveat on disjoint sets only, never the axis
alone (8.4).
