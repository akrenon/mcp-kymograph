"""The event schema.

The event stream is the single source for every output: terminal now, report and web view
later. Two properties are load-bearing and are why the shapes below look the way they do.

**Content and analysis stay in separate fields.** ``Payload`` holds what was said;
``ParseResult`` holds what we concluded from it. A renderer must never derive presentation
from the raw field, and must never treat the analysis as trustworthy either — both come
from the traffic, and both are escaped downstream.

**The payload is self-describing.** ``Payload.encoding`` is ``"json"`` or ``"text"``, so a
consumer has to look before touching ``data``. ``"text"`` means unparseable raw content.

Nothing here does I/O, and nothing here masks: masking happens in the recorder, on the way
in. The dataclasses in this module are only ever constructed with values that have already
been through it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

#: The one schema a recording of this version is written in, and the one it reads back. Raised
#: when what a recording must contain for its run to be judged changes; a recording of any
#: other schema is not read, not even in part (mcp_kymograph.verdict), and is driven again rather
#: than migrated. 1: the first format. 2: per-datagram UDP loss in ``egress_summary``
#: (``udp_loss``) and the closing event's wait for the driver in ``limits``
#: (``client_settle_seconds``) — and with them, as required parts, ``reproduction.environment``,
#: ``script_finished``, ``step_unanswered``, ``findings_capped``, which later schema 1
#: recordings carried and earlier ones did not. 3: ``run_stopped`` — a run stopped by a signal
#: says so, and is no longer written down as a sandbox or a server that failed. 4: one format for
#: stdio and Streamable HTTP — ``transport`` and ``endpoint`` in ``run_started``, ``exchange``,
#: ``stream`` and ``event_id`` in ``message``, the events ``http_request``, ``http_response``
#: and ``http_end``, and ``http`` (what was forwarded) in ``run_finished``. Raised for stdio
#: recordings too: a reader of 3 would pass the HTTP events by without knowing it. 5: scripts
#: that act — the events ``step_called`` and ``call_failed``, ``script_digest`` and
#: ``script_vars`` in ``run_started``, ``called`` and ``failed`` in ``script_finished``; a
#: reader of 4 would pass a tool call and its failure by without knowing it.
SCHEMA_VERSION = 5
TRANSPORT_STDIO = "stdio"
TRANSPORT_HTTP = "streamable-http"
TRANSPORTS = (TRANSPORT_STDIO, TRANSPORT_HTTP)

#: How an HTTP response body was framed, and how an HTTP exchange ended. Closed sets: the
#: recorder refuses any other word, because these are ours, never taken from the traffic.
HTTP_FRAMINGS = ("json", "sse", "empty", "other")
HTTP_ENDINGS = (
    "complete",
    "closed",
    "reset",
    "timeout",
    "client_closed",
    "framing_error",
    "oversized",
)

#: What the HTTP proxy counts where traffic is forwarded, the keys of ``run_finished.http``.
#: Written by the proxy and asked for by the verdict, so the word written and the word judged
#: cannot drift apart.
HTTP_COUNTS = ("exchanges", "responses", "streams", "events", "framing_errors")

#: Method names and request ids arrive from the traffic. They are stored, so they are
#: capped: an unbounded string in an "analysis" field is just an unbounded string.
MAX_METHOD_LENGTH = 128
MAX_ID_LENGTH = 128


# -- the driver's own words: why a step was not sent, or not answered ---------------------
#: Recorded in ``step_skipped``, ``step_unanswered`` and ``server_failed``, and read back by
#: mcp_kymograph.verdict. One place, so the words written and the words judged cannot drift.

#: A ``call`` step named a tool that no ``tools/list`` of the script's own had delivered, so it
#: was not sent: the script does not call what the server did not say it has.
TOOL_NOT_LISTED = "tool_not_listed"
#: The server's ``initialize`` answer did not list this capability.
NOT_OFFERED = "capability_not_offered"
#: It listed it, but not as the object the protocol says a capability is. Fail closed.
MALFORMED_CAPABILITY = "capability_not_an_object"
#: The handshake did not complete, so nothing is known about what the server offers.
NO_HANDSHAKE = "handshake_incomplete"
#: An answer did not come within the step's time, so the script stopped.
NO_ANSWER = "no_answer"
#: The server's side of the connection ended before the answer came, or before a step could
#: be sent.
CLOSED = "connection_closed"
#: The driver's page limit was reached: the listing is **not** complete, and says so.
PAGE_LIMIT = "page_limit_reached"
#: A listing's ``nextCursor`` was neither absent, null nor a string, so it cannot be sent
#: back and the listing cannot be followed to its end. Our words; nothing of the server's.
CURSOR_INVALID = "cursor_invalid"
#: The driver itself failed. The remaining steps were not sent, and that is our fault.
DRIVER_ERROR = "driver_error"
#: No answer was read, and lines came that the driver could not read: longer than its line
#: limit, or nested more than :data:`MAX_READ_DEPTH` levels deep. The answer may have been
#: among them. The server decides both, so this is not the driver's fault. The recording has
#: each such line: as a cut message with its size if it was too long, as a note that it was
#: too deep to record if it was.
UNREADABLE = "answer_unreadable"
#: Over HTTP: a request was answered with a status that carries no answer (anything but 200,
#: and 202 for a notification). Our word for the status, not the server's.
HTTP_STATUS = "http_status"
#: Over HTTP: 404 on a request that carried a session. The server ended or forgot it.
SESSION_LOST = "session_lost"
#: Over HTTP: no connection to the endpoint, or it ended before the head of the answer.
HTTP_UNREACHABLE = "http_unreachable"
#: Over HTTP: the endpoint speaks only the deprecated HTTP+SSE transport (detected, not driven).
HTTP_SSE_ONLY = "http_sse_only"
#: Over HTTP: the connection to the endpoint was made and the TLS handshake on it did not complete
#: — a certificate that does not verify, a name that does not match, no protocol both sides speak,
#: a connection broken off or a handshake not finished in time. The library's or the system's
#: text, or ours for the time, is in ``detail``, masked, since it can name what the certificate
#: says; the word is ours.
TLS = "tls"
#: Over HTTP: the endpoint answered 401 or 403. Our word for the status, not the server's: the
#: tool sends the token it was given and runs no flow to get another. The response is recorded
#: as every response is, with ``WWW-Authenticate`` parsed.
UNAUTHORIZED = "unauthorized"
#: Over HTTP, in the modern era: the head of the answer came (200) and its body ended before the
#: answer to the request's id did — closed, reset, a framing error — twice, the second time on
#: the request issued again. In legacy: the stream was resumed as far as it would be, and the
#: answer did not come. Our word.
STREAM_BROKEN = "stream_broken"
#: Over HTTP: the endpoint answered 429, or 503 with ``Retry-After`` in delta-seconds, and the
#: wait that header asks for was not made or did not help: it is longer than the step has left,
#: it is an HTTP-date (not waited for), or the same request drew it again. A 429 without the
#: header is this at once; a 503 without it stays :data:`HTTP_STATUS`. Our word for the status.
RATE_LIMITED = "rate_limited"
#: A token observation (``run_started.auth.observation`` is set) was answered with 401 or 403:
#: that is its result, not a failure. The step that drew it is in ``token_observation``; the
#: steps after it were not sent, and say this. Ours.
OBSERVATION_REJECTED = "observation_rejected"
#: The detection of the server's generation ended with a stop: the server requires what this tool
#: does not offer, or speaks no version it knows (``era_decided`` has the particular reason).
PROTOCOL_UNSUPPORTED = "protocol_unsupported"
#: The server's command could not be started at all — not found, not executable, not a format
#: the system can run. The proxy's word, in either mode: there was no process to talk to.
NOT_STARTED = "not_started"
#: An active run was stopped before this step (:data:`STOPPED_BECAUSE`): the step was not sent.
#: The stop itself is ``run_stopped``, which the verdict reads; this only says where it fell.
RUN_HALTED = "run_halted"
#: A probe module asked for more requests than its ``max_calls``: the one over the limit was not
#: sent, and what the module would have shown after it is missing.
PROBE_CALLS_EXHAUSTED = "probe_calls_exhausted"

#: Why a run was stopped before it ended on its own, as :class:`RunStopped` records it in
#: ``because``: a signal to this process, the engagement's stop file, or the end of the
#: engagement's window (only a run this tool drives itself is stopped by that one).
STOPPED_BY_SIGNAL = "signal"
STOPPED_BY_STOP_FILE = "stop_file"
STOPPED_BY_WINDOW = "window_closed"
STOPPED_BECAUSE = (STOPPED_BY_SIGNAL, STOPPED_BY_STOP_FILE, STOPPED_BY_WINDOW)

#: Why a step leaves the inventory short when it was not sent. Not offering a capability,
#: or offering it in a shape nothing can be read from, is something the server said about
#: itself; these are not.
PARTIAL_REASONS = frozenset(
    {
        NO_HANDSHAKE,
        NO_ANSWER,
        CLOSED,
        DRIVER_ERROR,
        PROBE_CALLS_EXHAUSTED,
        UNREADABLE,
        HTTP_STATUS,
        SESSION_LOST,
        HTTP_UNREACHABLE,
        HTTP_SSE_ONLY,
        TLS,
        UNAUTHORIZED,
        STREAM_BROKEN,
        RATE_LIMITED,
        PROTOCOL_UNSUPPORTED,
        OBSERVATION_REJECTED,
    }
)

#: How a tool call failed, as :class:`CallFailed` records it: a JSON-RPC error answer, or a
#: result that says ``isError``.
CALL_RPC_ERROR = "rpc_error"
CALL_TOOL_ERROR = "tool_error"
CALL_FAILURES = (CALL_RPC_ERROR, CALL_TOOL_ERROR)

#: Why a message was not passed on although no rule of the scope named it: the guard could not read
#: it in full (longer than the message limit, nested more deeply than a message is read), and
#: fails closed. Ours; the three other causes of a blocked call are those of the engagement gate.
MESSAGE_UNEXAMINED = "message_unexamined"
#: Every cause :class:`CallBlocked` records: the three of the engagement's tool rules
#: (``mcp_kymograph.engagement.tool_cause``) and :data:`MESSAGE_UNEXAMINED`. Spelled out here
#: because the engagement module reads the recorder, not the other way round; a test holds the
#: words to the engagement's.
BLOCK_CAUSES = (
    "tool_not_listed",
    "tool_writes_not_released",
    "tool_denied",
    MESSAGE_UNEXAMINED,
)
#: Where a call was blocked, as :class:`CallBlocked` records it.
BLOCKED_BY_PROXY = "proxy"
BLOCKED_BY_DRIVER = "driver"

#: How a script ended, as :class:`ScriptFinished` records it.
INVENTORY_COMPLETE = "complete"
#: Every step answered or legitimately not sent, and some listing cut at the page limit.
INVENTORY_CAPPED = "capped"
INVENTORY_PARTIAL = "partial"
#: No handshake: nothing is known about what the server offers.
INVENTORY_NONE = "none"


class EventType(str, Enum):
    RUN_STARTED = "run_started"
    MESSAGE = "message"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    HTTP_END = "http_end"
    SERVER_STDERR = "server_stderr"
    SERVER_EXITED = "server_exited"
    LIMIT_EXCEEDED = "limit_exceeded"
    INTERVENTION = "intervention"
    OBSERVATION = "observation"
    FINDING = "finding"
    FINDINGS_CAPPED = "findings_capped"
    STATEMENT_EVALUATED = "statement_evaluated"
    SERVER_NAME_MISMATCH = "server_name_mismatch"
    STEP_SKIPPED = "step_skipped"
    STEP_UNANSWERED = "step_unanswered"
    STEP_REISSUED = "step_reissued"
    ERA_DECIDED = "era_decided"
    STEP_CALLED = "step_called"
    CALL_FAILED = "call_failed"
    CALL_BLOCKED = "call_blocked"
    SCRIPT_FINISHED = "script_finished"
    SERVER_FAILED = "server_failed"
    SANDBOX_STEP = "sandbox_step"
    SANDBOX_FAILED = "sandbox_failed"
    EGRESS_ATTEMPT = "egress_attempt"
    EGRESS_DNS = "egress_dns"
    EGRESS_SUMMARY = "egress_summary"
    RULE_QUARANTINED = "rule_quarantined"
    RECORDING_STOPPED = "recording_stopped"
    RUN_STOPPED = "run_stopped"
    PACED = "paced"
    TOKEN_OBSERVATION = "token_observation"  # noqa: S105 - an event type, no password
    RUN_FINISHED = "run_finished"


class Mode(str, Enum):
    """Who produced the client half of the conversation.

    ``PROXY``: a foreign client did, and this tool sat between it and the server. What such a
    recording shows is a real session, whatever the client happened to do in it.

    ``DRIVER``: this tool did, from a fixed script, with no model involved. What such a
    recording shows is what the server offers when asked the same questions every time — an
    inventory. Which of the two a recording is cannot be inferred from its messages, and a
    report that mixed them up would be claiming one kind of evidence while holding the other.
    """

    PROXY = "proxy"
    DRIVER = "driver"


class Direction(str, Enum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class ParseKind(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    BATCH = "batch"
    UNKNOWN = "unknown"


class Encoding(str, Enum):
    JSON = "json"
    TEXT = "text"


@dataclass(frozen=True, slots=True)
class ParseResult:
    """What we concluded about a message. Never the message itself."""

    ok: bool
    kind: ParseKind = ParseKind.UNKNOWN
    method: str | None = None
    id: str | int | None = None
    is_error: bool = False
    error_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "kind": self.kind.value,
            "method": self.method,
            "id": self.id,
            "is_error": self.is_error,
            "error_reason": self.error_reason,
        }


@dataclass(frozen=True, slots=True)
class Payload:
    """Masked message content, plus a note of where masking struck."""

    encoding: Encoding
    data: Any
    redactions: tuple[str, ...] = ()
    redaction_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "encoding": self.encoding.value,
            "data": self.data,
            "redactions": list(self.redactions),
            "redaction_count": self.redaction_count,
        }


@dataclass(frozen=True, slots=True)
class RunStarted:
    argv: tuple[str, ...]
    limits: dict[str, Any]
    wall_clock_utc: str
    tool_version: str
    argv_redaction_count: int = 0
    #: What determined the run besides the server and the scenario: ``python`` (``implementation``,
    #: ``version``), ``platform`` (``platform.platform()``), ``step_timeout`` in seconds (``null``
    #: where there is none, as in proxy modes) and ``mask_keys``, the names of the mask keys given
    #: in addition to the built-in ones, run through the masker as a person types them. Nothing
    #: random is held. A reader without the field reads an empty mapping. It stands here, not
    #: beside ``limits`` in the dict, because a field with a default cannot precede the required
    #: ones; in ``to_dict`` it follows ``limits``. Only the ``--mask-key`` names of the command
    #: line are held: from an engagement file comes what ``declaration_fields`` names, and its
    #: digest is recorded, not its ``mask_keys``.
    inputs: dict[str, Any] = field(default_factory=dict)
    #: The run's authorization posture: which scenario was selected, which target the operator
    #: declared, and whether they passed the confirmation flag. Recorded as a claim, not as a
    #: finding — see :class:`mcp_kymograph.authorization.Declaration`. Without it a recording
    #: cannot say afterwards whether traffic-altering was asserted to be covered, and a
    #: scenario that never matched anything is indistinguishable from pure observation.
    authorization: dict[str, Any] = field(default_factory=dict)
    #: Which half of the conversation this tool produced, and — in driver mode — the name
    #: of the script it spoke. The script's contents are not recorded: the messages it sent
    #: are in the recording already, and a name is what a report needs to say which run this
    #: was. ``script`` is None in proxy mode, where there is no script.
    mode: str = Mode.PROXY.value
    script: str | None = None
    #: How the server's version was established — a digest over its own files, or a pinned
    #: revision — and the version itself, which every finding key carries as
    #: ``server_version``. None when the operator gave neither (mcp_kymograph.identity).
    server_identity: dict[str, Any] | None = None
    #: The scenario's name as every finding key carries it (the file's ``name`` or its stem;
    #: the built-in name for a built-in scenario), or None without one. Recorded here as well,
    #: so a run that found nothing still says which scenario it was the run of.
    scenario_name: str | None = None
    #: The corpus entry's name — what every finding key carries as ``server`` — or None for a
    #: run outside a corpus. Never the name the server announces (see ``run_finished``).
    server_name: str | None = None
    #: The reproduction triple of every run: which entry at which content, which tool at which
    #: content, which scenario at which digest, which environment (mcp_kymograph.corpus). Outside
    #: a corpus ``manifest`` and ``corpus`` are ``null`` and the rest is there.
    reproduction: dict[str, Any] | None = None
    #: Whether a virtual environment was already active around us. A wrapper that ran before
    #: this process — an activation script, ``uv run``, a launcher in a client config — has
    #: already changed PATH by the time we exist, and the server inherits that. We cannot see
    #: what changed, but we can record that something did. One boolean, no names, no values.
    virtual_environment: bool = False
    #: Where the server ran: ``host`` (a child process of this tool) or ``runc`` (the sandbox,
    #: mcp_kymograph.sandbox). Decided from the corpus entry's provenance before anything started.
    isolation: str = "host"
    #: ``stdio`` or ``streamable-http``, and — over HTTP only — where the server was reached:
    #: scheme, host, port, path, the query as a masked map, and whether the URL carried a user
    #: or password (which are never recorded). None over stdio.
    #:
    #: The path is written only when the engagement file lists it for the target the run
    #: matched, or, without a file, when the host is a loopback literal.
    #: Otherwise ``path`` is ``null`` and ``path_sha256`` (the SHA-256 of the path as sent,
    #: UTF-8, before any masking) and ``path_length`` (its length in characters) stand beside it;
    #: the same holds for ``http_request.target``. A reader without the two fields reads a path
    #: it cannot show; the verdict does not read a path. The same rule holds for a URL in the
    #: server's own command line, ``argv`` above: its path is withheld as text, unless the run
    #: has no file and the URL's host is a loopback literal. What may stand is a path with its
    #: host and port, so the same path on another host or port is withheld.
    transport: str = TRANSPORT_STDIO
    endpoint: dict[str, Any] | None = None
    #: Over HTTP only: whom the run spoke as — ``identity`` and ``role`` (``null`` for a token
    #: given by a flag outside an engagement file), ``token_used``, ``source`` (``env``,
    #: ``file`` or ``none``) and, for ``env``, ``env_name``. ``none`` is an identity that sends
    #: no token: no ``Authorization`` header went out. Never a value: not the token's and not a
    #: secret header's (the names of those stand in the ``http_request`` headers, their values
    #: blanked). ``token`` is ``null`` without a token; else what the token inspector read of
    #: it (docs/token-inspector.md): ``claims``, ``pseudonyms``, ``readable`` with ``reason``,
    #: ``unexpected``, ``other_claims``, ``warnings`` and ``expired`` (``true``, ``false`` or
    #: ``null``, by the start of the run). The readable claim values passed the masker as text.
    #: ``null`` for a run that sent no token and chose no identity, and over stdio.
    #: Written as ``authorization`` is, but for the literals of the run. A reader without the
    #: field reads null.
    auth: dict[str, Any] | None = None
    #: Over ``https`` only: whether ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` were set when the run
    #: started, ``{"SSL_CERT_FILE": bool, "SSL_CERT_DIR": bool}`` — what OpenSSL reads to find
    #: the machine's trust store, so a recording says which kind of store judged the endpoint's
    #: certificate. Never a value, which is a path on this machine. ``null`` for any other run. A
    #: reader without the field reads null.
    trust_store_env: dict[str, bool] | None = None
    #: SHA-256 of the script file's bytes as they were read, like the scenario's digest; None for
    #: a built-in script and in proxy mode. And the variables the operator set for the file's
    #: placeholders (``--script-var``): their names, with the values masked.
    script_digest: str | None = None
    script_vars: dict[str, str] = field(default_factory=dict)
    #: Whether this run was paced (mcp_kymograph.pacing): ``true`` for a run that took a slot of
    #: its origin and kept the interval, ``null`` where pacing does not apply (a run to a loopback
    #: literal, or over stdio). ``false`` is no longer written; a recording of an earlier version
    #: that says it — a file's ``pacing`` declared and nothing enforced — keeps it, and a reader
    #: takes it as "declared, not enforced by the version that made it". The tool's statement
    #: about itself, beside ``authorization`` and not in it. A reader without the field reads null.
    pacing_enforced: bool | None = None
    #: What a paced run was held to: ``{runs_per_origin, min_interval_seconds, source}``, the
    #: source ``file`` or ``default``. ``null`` for a run that was not paced. A reader without the
    #: field reads null.
    pacing: dict[str, Any] | None = None
    #: How long the pseudonyms of personal data last (``masking.PSEUDONYM_SCOPES``):
    #: ``"per_engagement"`` where the salt is the engagement's, so the same value is the same
    #: pseudonym in every run under it, ``"per_run"`` where it is the run's own and the
    #: pseudonyms mean something inside this recording only. Never the salt. A reader without
    #: the field reads null.
    pseudonyms: str | None = None
    #: A run of a probe module (``drive --probe``): ``{"name": …, "options": {…}}``, the options as
    #: the operator typed them, masked. None for any other run. A reader without the field reads
    #: null.
    probe: dict[str, Any] | None = None

    TYPE: ClassVar[EventType] = EventType.RUN_STARTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "argv_redaction_count": self.argv_redaction_count,
            "mode": self.mode,
            "script": self.script,
            "script_digest": self.script_digest,
            "script_vars": dict(self.script_vars),
            "server_identity": None if self.server_identity is None else dict(self.server_identity),
            "scenario_name": self.scenario_name,
            "server_name": self.server_name,
            "reproduction": None if self.reproduction is None else dict(self.reproduction),
            "authorization": dict(self.authorization),
            "virtual_environment": self.virtual_environment,
            "isolation": self.isolation,
            "transport": self.transport,
            "endpoint": None if self.endpoint is None else dict(self.endpoint),
            "trust_store_env": None if self.trust_store_env is None else dict(self.trust_store_env),
            "auth": None if self.auth is None else dict(self.auth),
            "pacing_enforced": self.pacing_enforced,
            "pacing": None if self.pacing is None else dict(self.pacing),
            "pseudonyms": self.pseudonyms,
            "probe": None if self.probe is None else dict(self.probe),
            "limits": self.limits,
            "inputs": dict(self.inputs),
            "wall_clock_utc": self.wall_clock_utc,
            "tool_version": self.tool_version,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class Message:
    direction: Direction
    transport: str
    size_bytes: int
    truncated: bool
    payload: Payload
    parse: ParseResult
    incomplete: bool = False
    #: The method of the request this message answers, or None when it answers nothing or
    #: its request was never seen. Kept apart from ``parse.method``, which is the method this
    #: message carries itself: that one is read out of this document, while this one is a
    #: correlation across two messages and can therefore be missing for reasons that say
    #: nothing about the message in hand. It is what lets a *response* — which carries only
    #: an id — be located by method afterwards, a redaction inside it included.
    responded_method: str | None = None
    #: Over HTTP: the ordinal of the exchange the message travelled in, the ordinal of the SSE
    #: stream within the run (None for a plain body), and the stream event's id as a pseudonym.
    #: All None over stdio.
    exchange: int | None = None
    stream: int | None = None
    event_id: str | None = None

    TYPE: ClassVar[EventType] = EventType.MESSAGE

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction.value,
            "transport": self.transport,
            "size_bytes": self.size_bytes,
            "truncated": self.truncated,
            "incomplete": self.incomplete,
            "responded_method": self.responded_method,
            "exchange": self.exchange,
            "stream": self.stream,
            "event_id": self.event_id,
            "payload": self.payload.to_dict(),
            "parse": self.parse.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """The head of one HTTP request, masked. ``session`` is the session's ordinal in this run,
    never its id."""

    exchange: int
    connection: int
    method: str
    target: dict[str, Any]
    headers: dict[str, Any]
    session: int | None
    #: The connection's TLS, ``{"version": "TLSv1.3", "certificate_sha256": "<64 hex>"}``: the
    #: negotiated protocol version and the SHA-256 of the leaf certificate as presented (DER).
    #: One connection carries one exchange, so each exchange names its own connection's
    #: certificate. ``null`` over plain HTTP. Droppable like the event; the run's set is in
    #: ``run_finished.http.tls``. A reader without the field reads null.
    tls: dict[str, Any] | None = None

    TYPE: ClassVar[EventType] = EventType.HTTP_REQUEST

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange": self.exchange,
            "connection": self.connection,
            "method": self.method,
            "target": dict(self.target),
            "headers": dict(self.headers),
            "session": self.session,
            "tls": None if self.tls is None else dict(self.tls),
        }


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """The head of one HTTP response, masked, and how its body is framed."""

    exchange: int
    status: int
    reason: str
    headers: dict[str, Any]
    content_type: str | None
    framing: str
    session: int | None

    TYPE: ClassVar[EventType] = EventType.HTTP_RESPONSE

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange": self.exchange,
            "status": self.status,
            "reason": self.reason,
            "headers": dict(self.headers),
            "content_type": self.content_type,
            "framing": self.framing,
            "session": self.session,
        }


@dataclass(frozen=True, slots=True)
class HttpEnd:
    """How one HTTP exchange ended, and what it moved in bytes and stream events."""

    exchange: int
    ended: str
    request_body_bytes: int
    response_body_bytes: int
    head_bytes: int
    events: int
    comments: int

    TYPE: ClassVar[EventType] = EventType.HTTP_END

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange": self.exchange,
            "ended": self.ended,
            "request_body_bytes": self.request_body_bytes,
            "response_body_bytes": self.response_body_bytes,
            "head_bytes": self.head_bytes,
            "events": self.events,
            "comments": self.comments,
        }


@dataclass(frozen=True, slots=True)
class ServerStderr:
    size_bytes: int
    truncated: bool
    payload: Payload

    TYPE: ClassVar[EventType] = EventType.SERVER_STDERR

    def to_dict(self) -> dict[str, Any]:
        return {
            "size_bytes": self.size_bytes,
            "truncated": self.truncated,
            "payload": self.payload.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ServerExited:
    exit_code: int | None
    signal: int | None

    TYPE: ClassVar[EventType] = EventType.SERVER_EXITED

    def to_dict(self) -> dict[str, Any]:
        return {"exit_code": self.exit_code, "signal": self.signal}


@dataclass(frozen=True, slots=True)
class LimitExceeded:
    limit: str
    value: float
    unit: str

    TYPE: ClassVar[EventType] = EventType.LIMIT_EXCEEDED

    def to_dict(self) -> dict[str, Any]:
        return {"limit": self.limit, "value": self.value, "unit": self.unit}


@dataclass(frozen=True, slots=True)
class Intervention:
    """What the scenario's rules did to one message on the way through.

    Original and replacement are held side by side and never merged, the same separation of
    content from analysis the message events keep. Both are masked Payloads: an intervention
    log is as much a record of hostile traffic as any other event. ``replacement`` is None
    when the message was dropped rather than rewritten; both are None when every rule that
    took part changed nothing (``action`` is then ``forward``).

    ``steps`` is one entry per rule that took part, in chain order: the rule, its action, and
    for each value it changed the concrete path with the value before and after — each masked
    in its place in the document, so a key name on the way down still masks it. A rule that
    took part and changed nothing has a ``reason`` instead of changes. One event per message
    rather than one per step: a chain is recorded whole or, if the queue drops it, not at all,
    never as a fragment that would describe a message nobody received.
    """

    action: str  # "replace" | "drop" | "forward"
    direction: Direction
    message_id: str | int | None
    original: Payload | None
    replacement: Payload | None
    steps: tuple[dict[str, Any], ...] = ()

    TYPE: ClassVar[EventType] = EventType.INTERVENTION

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "direction": self.direction.value,
            "message_id": self.message_id,
            "original": None if self.original is None else self.original.to_dict(),
            "replacement": None if self.replacement is None else self.replacement.to_dict(),
            "steps": [dict(step) for step in self.steps],
        }


@dataclass(frozen=True, slots=True)
class Observation:
    """Content the server delivered that a model could read as instruction.

    **This is an observation, not a finding.** It says where something sat and what shape it
    had; it says nothing about whether that matters, and it carries no severity, no verdict
    and no recommendation. Whether such content has an effect depends on what the consuming
    side does with a tool description or a tool result, which is not visible on the wire.

    It carries no excerpt of what was seen. The message itself is recorded, masked, under
    ``message_seq``; ``path`` points into it. That keeps hostile text out of the analysis
    fields entirely and leaves exactly one copy of it in the recording.

    ``message_seq`` is the number of the message event this refers to. If that number is
    missing from the recording, the message event was dropped from a full queue and this is
    the only remaining trace of it — which is what sequence gaps are for.
    """

    direction: Direction
    method: str | None
    message_id: str | int | None
    message_seq: int
    surface: str
    path: str
    #: A signal ID from :mod:`mcp_kymograph.signals`.
    signal: str
    #: True when only the normalised text carried the signal. The recorded message then shows
    #: the raw text, in which the reader will not find it spelled out — this says why.
    normalized: bool = False

    TYPE: ClassVar[EventType] = EventType.OBSERVATION

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction.value,
            "method": self.method,
            "message_id": self.message_id,
            "message_seq": self.message_seq,
            "surface": self.surface,
            "path": self.path,
            "signal": self.signal,
            "normalized": self.normalized,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A place where a scenario statement's signal fired: a structured, comparable entry.

    ``key`` is the finding's whole identity — ``server``, ``server_version``,
    ``tool_version``, ``scenario``, ``statement``, ``locator``, ``signal`` — and the only thing
    a store or a comparison between runs keys on, so that it can tell a finding that is new
    from one that has come back. ``locator`` names the place (``result.tools[name="search"]
    .description``); it is never a position. The rest says where it sat in this run: which
    message, which ``path`` — the position, recorded as the place to look and never as
    identity.

    **A finding carries no severity, no verdict and no recommendation.** It is a statement
    the operator wrote ("this, here, counts") meeting the traffic. One language rule
    applies to anything phrased from it: a finding describes the
    binding between server and consuming side, never "the server is vulnerable".

    Like an observation it carries no excerpt; ``message_seq`` and ``path`` point into the
    message, which is recorded once and masked. ``server`` and ``server_version`` are the
    server's own words from its ``initialize`` answer, capped, and None before that answer.
    """

    key: dict[str, Any]
    direction: Direction
    method: str | None
    message_id: str | int | None
    message_seq: int
    path: str
    normalized: bool = False

    TYPE: ClassVar[EventType] = EventType.FINDING

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": dict(self.key),
            "direction": self.direction.value,
            "method": self.method,
            "message_id": self.message_id,
            "message_seq": self.message_seq,
            "path": self.path,
            "normalized": self.normalized,
        }


@dataclass(frozen=True, slots=True)
class FindingsCapped:
    """One message made more findings than one message may record, and this is what was cut.

    **A recorded cap, not a gap**. ``made`` is the true number of findings in the
    message, ``recorded`` how many ``finding`` events it was given, and ``cut`` names every
    (statement, signal) with how many of its findings went unrecorded. Together with the
    run's per-statement count, the recording then says exactly what is missing and why, and a
    run with nothing else wrong is complete.

    Rides the droppable observer path like the findings themselves: if this event is lost,
    the count no longer adds up and the run is incomplete — the safe direction.
    """

    method: str | None
    message_id: str | int | None
    message_seq: int
    cap: int
    made: int
    recorded: int
    cut: dict[str, dict[str, int]]

    TYPE: ClassVar[EventType] = EventType.FINDINGS_CAPPED

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "message_id": self.message_id,
            "message_seq": self.message_seq,
            "cap": self.cap,
            "made": self.made,
            "recorded": self.recorded,
            "cut": {statement: dict(signals) for statement, signals in self.cut.items()},
        }


@dataclass(frozen=True, slots=True)
class StatementEvaluated:
    """What one scenario statement did with one message it applied to.

    Written for every statement whose ``match`` fits the message, **whether or not anything
    fired** — the reading half's counterpart of a rule step without effect. ``fired`` names
    every signal the statement asked for, zero included. ``reason`` says why fewer places
    were checked than the path names: ``path_not_found``, ``not_a_string`` or ``bounded``.
    A statement whose ``match`` does not fit leaves nothing, as a rule does.
    """

    statement: str
    method: str | None
    message_id: str | int | None
    message_seq: int
    checked: int
    not_strings: int
    fired: dict[str, int]
    reason: str | None = None

    TYPE: ClassVar[EventType] = EventType.STATEMENT_EVALUATED

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "method": self.method,
            "message_id": self.message_id,
            "message_seq": self.message_seq,
            "checked": self.checked,
            "not_strings": self.not_strings,
            "fired": dict(self.fired),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ServerNameMismatch:
    """The server announced a name other than the corpus entry it was run as.

    The findings are keyed on ``declared`` — the operator's name for the entry — and never on
    ``announced``, which the server under test chose. A server that calls itself something
    else is worth writing down: it may be misconfigured in the manifest, or it may be passing
    itself off as another server. No verdict either way; a later signal may use it.

    ``announced`` is capped like every name off the wire, and None when the server gave no
    name as a string. ``message_seq`` is the ``initialize`` answer it came in.
    """

    declared: str
    announced: str | None
    message_seq: int

    TYPE: ClassVar[EventType] = EventType.SERVER_NAME_MISMATCH

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared": self.declared,
            "announced": self.announced,
            "message_seq": self.message_seq,
        }


@dataclass(frozen=True, slots=True)
class StepSkipped:
    """A step of the driver's script that was not sent, and why it was not.

    **An omission is not an empty result.** "The server offers no prompts capability" and
    "the server has no prompts" are different statements about a system, and without this
    event a recording carries neither — the reader sees only that no ``prompts/list`` went
    out and has to guess whether the script never asked or the tool forgot. The same
    confusion ``inspection_bounded`` exists to prevent.

    ``reason`` is one of a closed set of our own words (see :mod:`mcp_kymograph.driver`), never
    text from the server. ``detail`` is likewise ours: a bound that was reached, or empty.
    Neither is a Payload and neither passes the masker, because neither came off the wire.

    Written on the non-droppable path. An absence that was itself dropped reads as nothing
    at all, which is precisely the state this event exists to rule out.
    """

    step: str
    reason: str
    detail: str = ""

    TYPE: ClassVar[EventType] = EventType.STEP_SKIPPED

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "reason": self.reason, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class StepUnanswered:
    """A step of the driver's script that was sent and never answered in full.

    The other half of :class:`StepSkipped`: this step went out, and the answer — or, in a
    paginated listing, a later page of it — never came. ``pages`` is how many pages had been
    answered before that; a listing with ``pages`` above zero is a partial one. ``reason`` is
    ours: ``no_answer`` (the step's time ran out), ``answer_unreadable`` (something came that
    the driver could not read: longer than its limit, or nested too deeply),
    ``connection_closed`` (the server's side ended first), ``cursor_invalid`` (a page's cursor
    cannot be sent back), or over HTTP ``http_status``, ``session_lost``, ``http_unreachable``,
    ``http_sse_only`` and ``tls`` (the handshake with the endpoint failed on a later
    connection). ``detail`` is empty for every reason but ``tls``, where it is the TLS
    library's text — cut and filtered by the channel, masked by the recorder, because it came
    from the endpoint's certificate as much as from us. A reader without the field reads "".
    Non-droppable, like a skip: a listing that stopped halfway and did not say so reads as a
    server that has only that much.
    """

    step: str
    pages: int
    reason: str
    detail: str = ""

    TYPE: ClassVar[EventType] = EventType.STEP_UNANSWERED

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "pages": self.pages,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ScriptFinished:
    """The driver's script reached its end, and what that end was.

    **Evidence of an end, not the absence of a failure.** A script that was cut off — its
    task cancelled because the run ended under it — writes nothing at all, and nothing in the
    recording would say that the inventory stops early. So a driven run is only complete
    when this event is there. ``inventory`` is ``complete``, ``capped`` (a listing reached the
    page limit, recorded as such), ``partial`` (a step went unanswered or was not sent for a
    reason that leaves the inventory short) or ``none`` (no handshake). The lists repeat the
    step events in brief; those are the record, this is the summary. Non-droppable.
    """

    inventory: str
    sent: tuple[str, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()
    unanswered: tuple[tuple[str, int, str], ...] = ()
    #: The names of the tools whose call was sent, and of those whose call came back as an
    #: error (:class:`CallFailed`), in script order. Names the operator wrote, capped.
    called: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    #: The generation the script was spoken in (``legacy`` or ``modern``) and the protocol
    #: version, as the opening settled them; over stdio without an engagement, ``legacy`` and
    #: what ``initialize`` answered. None when the opening did not get that far, and for a
    #: reader without the fields.
    era: str | None = None
    protocol_version: str | None = None

    TYPE: ClassVar[EventType] = EventType.SCRIPT_FINISHED

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory,
            "sent": list(self.sent),
            "skipped": [list(pair) for pair in self.skipped],
            "unanswered": [list(item) for item in self.unanswered],
            "called": list(self.called),
            "failed": list(self.failed),
            "era": self.era,
            "protocol_version": self.protocol_version,
        }


@dataclass(frozen=True, slots=True)
class EraDecided:
    """How the server's generation was settled, written when the detection ends.

    ``era`` is ``legacy`` or ``modern``; ``version`` the protocol version spoken (None for a
    stop that settled none); ``outcome`` is ``proceed`` or ``stop``, and ``reason`` the
    detector's own reason for a stop (``modern_refused``, ``no_common_version``,
    ``unknown_version``, ``malformed_version``, ``handshake_refused`` …), None for a proceed.
    ``probe`` is how the probe's answer was read — ``outcome``, ``code`` and ``supported`` — and
    ``exchanges`` every message the detection sent, as ``[method, outcome, code]``. All of it is
    ours, or a value from the traffic clipped by :mod:`~mcp_kymograph.eras`.

    ``refusal`` is, for a stop that came with an error, its ``code`` and the server's
    ``error.data`` (masked and clipped by the recorder); None otherwise. ``declared`` is the
    generation the engagement file names for the target (``era``, and ``version`` when it says),
    None without one, and ``differs`` whether the detected generation (or version, if the file
    names one) is another: an observation, never a stop. ``observations`` are what the detection
    noticed without judging it. Non-droppable.
    """

    era: str | None
    version: str | None
    outcome: str
    reason: str | None = None
    probe: dict[str, Any] | None = None
    exchanges: tuple[tuple[str, str, int | None], ...] = ()
    refusal: dict[str, Any] | None = None
    declared: dict[str, Any] | None = None
    differs: bool | None = None
    observations: tuple[str, ...] = ()

    TYPE: ClassVar[EventType] = EventType.ERA_DECIDED

    def to_dict(self) -> dict[str, Any]:
        return {
            "era": self.era,
            "version": self.version,
            "outcome": self.outcome,
            "reason": self.reason,
            "probe": None if self.probe is None else dict(self.probe),
            "exchanges": [list(item) for item in self.exchanges],
            "refusal": None if self.refusal is None else dict(self.refusal),
            "declared": None if self.declared is None else dict(self.declared),
            "differs": self.differs,
            "observations": list(self.observations),
        }


@dataclass(frozen=True, slots=True)
class StepReissued:
    """A request whose response stream broke was sent again, once, with a new id (modern era:
    "clients MUST re-issue it as a new request with a new request ID").

    ``step`` is the method, ``page`` the page of the listing it was (0 for the first) and
    ``reason`` ours (``stream_broken``). A second break is the step's ``step_unanswered``.
    Non-droppable: a listing that was asked for twice must say so.
    """

    step: str
    page: int
    reason: str

    TYPE: ClassVar[EventType] = EventType.STEP_REISSUED

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "page": self.page, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class StepCalled:
    """A tool call of the script was sent: which tool, with what, and what the script was to
    look at in the answer.

    Written when the call is on its way, so that a call that was never answered still has its
    cause in the recording. ``tool`` is the name the script gave, capped like a method name;
    ``arguments`` are the arguments as sent, after the masker like every argument in the
    recording, with the paths it struck in ``redactions``; ``check`` is the path the script
    names for the answer, as text, or None. Non-droppable, like a skip.
    """

    step: str
    tool: str
    arguments: Any
    check: str | None = None
    redactions: tuple[str, ...] = ()
    redaction_count: int = 0

    TYPE: ClassVar[EventType] = EventType.STEP_CALLED

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "tool": self.tool,
            "arguments": self.arguments,
            "check": self.check,
            "redactions": list(self.redactions),
            "redaction_count": self.redaction_count,
        }


@dataclass(frozen=True, slots=True)
class CallFailed:
    """A tool call was answered with an error, and the script went on.

    ``kind`` is ``rpc_error`` (an answer without ``result`` that carries ``error``; ``code``
    is its number, or None when it has none as a number) or ``tool_error`` (a result with
    ``isError`` true; no code). Nothing the server wrote is in it, not even the error's text:
    that is in the message, where the masker and the inspector have been. Non-droppable.
    """

    step: str
    tool: str
    kind: str
    code: int | None = None

    TYPE: ClassVar[EventType] = EventType.CALL_FAILED

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "tool": self.tool, "kind": self.kind, "code": self.code}


@dataclass(frozen=True, slots=True)
class CallBlocked:
    """A tool call that an engagement's scope did not allow, and that was not sent on.

    **A blocked call is recorded, not only warned about.** ``cause`` is one of our fixed words
    (:data:`mcp_kymograph.engagement.CONDITIONS` for the first three: ``tool_not_listed``,
    ``tool_writes_not_released``, ``tool_denied``; and ``message_unexamined``, for a message the
    guard could not read in full and so did not pass on). Nothing from the traffic is part of it.
    ``tool`` is the name the call carried, cut like a method name and masked, or None when the
    message named none a guard can read; it is a field of its own because it came off the wire.
    ``where`` is ``proxy`` (a client's message, refused before the server saw it) or ``driver``
    (our own script's call, refused by the driver's second check: a mistake of the tool, since
    the gate had to catch it). ``answered`` says whether the proxy answered the client with an
    error; ``batch`` whether the call was one of a JSON-RPC batch, none of which was passed on.
    Non-droppable. A reader without the event passes it by: no verdict reads it.
    """

    cause: str
    where: str
    tool: str | None = None
    message_id: str | int | None = None
    answered: bool = False
    batch: bool = False

    TYPE: ClassVar[EventType] = EventType.CALL_BLOCKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "cause": self.cause,
            "where": self.where,
            "tool": self.tool,
            "message_id": self.message_id,
            "answered": self.answered,
            "batch": self.batch,
        }


@dataclass(frozen=True, slots=True)
class RunStopped:
    """Whoever runs this tool stopped the run — SIGINT or SIGTERM — before it ended on its own.

    Written the moment the signal arrives, so that what follows it in the recording reads as
    the stop's consequence: a server that is killed by the stop before it answered has not
    failed, a sandbox that is not finished being built has not failed. The run is incomplete
    (mcp_kymograph.verdict, cause ``interrupted``), the same as a run a fleet's interruption cut
    short. ``signal`` is the signal's name. Non-droppable.

    A run is also stopped by the engagement's stop file and, for a run this tool drives itself,
    by the end of the window; ``because`` says which, in the words of :data:`STOPPED_BECAUSE`.
    ``signal`` then holds the same word, since the verdict names the stop by it; a reader without
    ``because`` reads a signal.
    """

    signal: str
    because: str = STOPPED_BY_SIGNAL

    TYPE: ClassVar[EventType] = EventType.RUN_STOPPED

    def to_dict(self) -> dict[str, Any]:
        return {"signal": self.signal, "because": self.because}


#: Why a run waited before it began, as :class:`Paced` records it (mcp_kymograph.pacing).
PACED_RETRY_AFTER = "retry_after"
PACED_WHY = ("interval", "origin_busy", PACED_RETRY_AFTER)


@dataclass(frozen=True, slots=True)
class Paced:
    """The run waited (mcp_kymograph.pacing): ``seconds`` it took, and ``why`` —
    ``interval`` (the last run against the origin ended less than ``min_interval_seconds``
    before) or ``origin_busy`` (every slot of the origin was held by a run that was going).
    Those two are written right after ``run_started``. The third, ``retry_after``, is a wait in
    the middle of the run: the endpoint answered ``status`` (429 or 503) with ``Retry-After`` in
    seconds, and the same request was sent again after it; ``status`` is in the event for that
    one only. Non-droppable: a recording that waited and does not say
    so would pass for a run that was quick. Ours; nothing to mask. A reader without the event
    passes it by: no verdict reads it."""

    seconds: float
    why: str
    status: int | None = None

    TYPE: ClassVar[EventType] = EventType.PACED

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {"seconds": self.seconds, "why": self.why}
        if self.status is not None:
            record["status"] = self.status
        return record


#: The kinds of token observation an engagement file may mark an identity with
#: (``mcp_kymograph.engagement.OBSERVATIONS`` spells the same words; a test holds them together):
#: a token issued for another audience, an expired token the agency provides, no token.
TOKEN_OBSERVATIONS = ("foreign_audience", "expired", "no_token")
#: The largest JSON-RPC error code recorded as a number (``driver.MAX_CODE``): a server may put
#: any number there, a token among them.
MAX_RPC_CODE = 2**31
#: What an exchange of a token observation was within the run (``role``): the opening
#: (``initialize``, or ``server/discover`` in the new era), the request that detects the server's
#: era (``server/discover``, when the run goes on to ``initialize``), a listing, a call, and — in
#: the run of a probe module (``drive --probe``) — each request the module made. Ours.
ROLE_ERA_PROBE = "era_probe"
ROLE_OPENING = "opening"
ROLE_LIST = "list"
ROLE_CALL = "call"
ROLE_PROBE = "probe"
EXCHANGE_ROLES = (ROLE_ERA_PROBE, ROLE_OPENING, ROLE_LIST, ROLE_CALL, ROLE_PROBE)
#: What a token observation says of its token's expiry, as :class:`TokenObservation` records it
#: for the kind ``expired``: the recording's ``auth.token.expired`` true, false or null.
EXPIRY_EXPIRED = "expired"
EXPIRY_NOT_EXPIRED = "not_expired"
EXPIRY_NOT_CHECKABLE = "not_checkable"
EXPIRIES = (EXPIRY_EXPIRED, EXPIRY_NOT_EXPIRED, EXPIRY_NOT_CHECKABLE)


@dataclass(frozen=True, slots=True)
class TokenObservation:
    """How the server answered each exchange of a run made as an identity marked with an
    ``observation`` (the engagement file). ``kind`` is that mark; each request sent has an
    exchange with ``role`` (:data:`EXCHANGE_ROLES`), ``method``, ``accepted``, ``http_status`` and
    ``rpc_code``. ``accepted`` is true only for a 2xx with a JSON-RPC result to the request,
    false for 401 and 403 whatever became of the body, null in every other case; ``rpc_code`` is
    the code of a JSON-RPC error answer, or of the body of a 401 or 403 that is one, within
    :data:`MAX_RPC_CODE` and holding no literal of the run, else null; ``http_status`` is from
    100 to 599, else null. The tool does
    not say whether the result is good or bad: that is the examiner's. For the kind ``expired``,
    ``expiry`` says whether the token was expired when the run started (``auth.token.expired``);
    ``not_checkable`` is the engagement's declaration, which the tool cannot check. Never a token,
    a header or a claim. Written at the end of the run, before it is closed. Non-droppable. Ours.
    A reader without the event passes it by."""

    kind: str
    exchanges: tuple[dict[str, Any], ...] = ()
    expiry: str | None = None

    TYPE: ClassVar[EventType] = EventType.TOKEN_OBSERVATION

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "kind": self.kind,
            "exchanges": [dict(exchange) for exchange in self.exchanges],
        }
        if self.expiry is not None:
            record["expiry"] = self.expiry
        return record


@dataclass(frozen=True, slots=True)
class ServerFailed:
    """The server never completed the handshake: nothing the script asks about was observed.

    **A run that observed nothing is not a run that found nothing.** Without this event a
    server that crashed on start, or answered ``initialize`` with an error, leaves a recording
    whose statements all count zero — which reads exactly like a clean server. ``reason`` is
    the driver's own word for why (``no_answer``, ``answer_unreadable``, ``connection_closed``,
    ``handshake_incomplete``, and over HTTP the channel's), or the proxy's (``not_started``: the
    command could not be started, with what the system said in ``detail``). ``reason`` never
    came off the wire. ``detail`` is our own sentence for every reason but ``tls`` — over HTTP,
    the TLS handshake with the endpoint failed on the first exchange — where it is the TLS
    library's text, which can name what the certificate says; so the recorder masks every
    ``detail``. Non-droppable.
    """

    reason: str
    detail: str = ""

    TYPE: ClassVar[EventType] = EventType.SERVER_FAILED

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class SandboxStep:
    """One step of building and proving the sandbox, with its evidence, whether it held or not.

    Written for every step, in the order they ran, on the non-droppable path: the recording
    shows *why* the target was allowed to start — or why not — rather than only that it did.
    ``detail`` is the sandbox's own account (exit codes, digests, what the probe saw); the
    sandbox's containers are ours, so it passes no masker.
    """

    step: str
    ok: bool
    seconds: float
    detail: Any = None

    TYPE: ClassVar[EventType] = EventType.SANDBOX_STEP

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "ok": self.ok, "seconds": self.seconds, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class SandboxFailure:
    """The sandbox did not hold, and which condition it was.

    ``phase`` ``before_target``: the target was never created. ``after_target``: it ran, but
    the account of what it sent cannot be trusted in full (the sink and the kernel disagree,
    or the record could not be read). Either way the run is not a result, and never reads as
    one with nothing in it.
    """

    condition: str
    phase: str
    detail: Any = None

    TYPE: ClassVar[EventType] = EventType.SANDBOX_FAILED

    def to_dict(self) -> dict[str, Any]:
        return {"condition": self.condition, "phase": self.phase, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class EgressAttempt:
    """One destination the target tried to reach, from the kernel's record, with the count.

    ``count`` is connections for TCP and packets otherwise (``unit`` says which). ``port`` is
    set for TCP and UDP; ``kind`` is the ICMP type or, for other protocols, the protocol.
    The destination is the original one, before the redirect rewrote it. Both are masked like
    a value of the traffic: a port whose digits hold a known value is a string. The count is
    the kernel's and stays a number.
    """

    proto: str
    family: int
    destination: str
    port: int | str | None
    kind: str | None
    count: int
    unit: str

    TYPE: ClassVar[EventType] = EventType.EGRESS_ATTEMPT

    def to_dict(self) -> dict[str, Any]:
        return {
            "proto": self.proto,
            "family": self.family,
            "destination": self.destination,
            "port": self.port,
            "kind": self.kind,
            "count": self.count,
            "unit": self.unit,
        }


@dataclass(frozen=True, slots=True)
class EgressDns:
    """A name the target asked for, as the sink read it. The name came from the target and
    went through the masker like any other text from it, and so did the query type: one whose
    digits hold a known value is a string."""

    transport: str
    family: int
    qname: str | None
    qtype: int | str | None
    answered: bool
    qname_redactions: int = 0

    TYPE: ClassVar[EventType] = EventType.EGRESS_DNS

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "family": self.family,
            "qname": self.qname,
            "qtype": self.qtype,
            "answered": self.answered,
            "qname_redactions": self.qname_redactions,
        }


@dataclass(frozen=True, slots=True)
class EgressSummary:
    """The target's egress as a whole, and whether the sink's account matched the kernel's.

    ``capped`` is per class the number of attempts counted but not recorded by destination,
    because a set was full: a recorded cap, complete in the sense that what was cut and why
    is known. ``consistent`` false means the run's observation is invalid, and a
    ``sandbox_failed`` event says so as well. It is judged by membership: what one side names
    and the other does not. ``account_differences`` lists, per class, the kernel's and the
    sink's counts where they differ — a retransmission moves a count without anything going
    unobserved, so a difference is recorded and never judged. ``udp_loss`` is what the sink
    missed of the target's UDP — counted by the kernel, received by the sink, lost, the
    destinations it saw not once, and the rate — judged by mcp_kymograph.verdict.
    """

    consistent: bool
    problems: tuple[str, ...]
    attempts: int
    dns_queries: int
    counters: dict[str, int]
    capped: dict[str, int]
    direct_sink_access: int
    sink_suppressed: int
    account_differences: dict[str, dict[str, int]] = field(default_factory=dict)
    udp_loss: dict[str, Any] = field(default_factory=dict)

    TYPE: ClassVar[EventType] = EventType.EGRESS_SUMMARY

    def to_dict(self) -> dict[str, Any]:
        return {
            "consistent": self.consistent,
            "problems": list(self.problems),
            "attempts": self.attempts,
            "dns_queries": self.dns_queries,
            "counters": dict(self.counters),
            "capped": dict(self.capped),
            "direct_sink_access": self.direct_sink_access,
            "sink_suppressed": self.sink_suppressed,
            "account_differences": {k: dict(v) for k, v in self.account_differences.items()},
            "udp_loss": dict(self.udp_loss),
        }


@dataclass(frozen=True, slots=True)
class RuleQuarantined:
    """One rule failed and was stilled; the rest of the run went on without it.

    Written only under the ``continue`` policy for rule errors. It is the statement that
    makes a report readable afterwards: **every** intervention carrying this ``rule`` is
    invalid, the ones already written as much as any that would have followed, because a
    rule that failed once cannot be trusted to have been right before. ``invalidated_hits``
    is how many it had already made, counted where the engine decided rather than where the
    event was written, so a hit whose intervention was dropped from a full queue is still
    counted here.

    ``RunFinished.quarantined_rules`` repeats the names. This event rides the droppable
    observer path like every other, and a report that lost it would otherwise read a
    quarantined rule's hits as valid.
    """

    rule: str
    reason: str  # "rule_error" | "invalid_replacement"
    detail: str
    direction: Direction
    message_id: str | int | None
    invalidated_hits: int

    TYPE: ClassVar[EventType] = EventType.RULE_QUARANTINED

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "reason": self.reason,
            "detail": self.detail,
            "direction": self.direction.value,
            "message_id": self.message_id,
            "invalidated_hits": self.invalidated_hits,
        }


@dataclass(frozen=True, slots=True)
class RecordingStopped:
    """Everything from ``from_seq`` onwards is missing, not merely thinned out.

    A separate type because "blind from here" is a different statement from "some events are
    missing", and a consumer has to treat them differently. ``from_seq`` bounds the blind
    stretch instead of leaving it as "somewhere after this".
    """

    reason: str
    from_seq: int

    TYPE: ClassVar[EventType] = EventType.RECORDING_STOPPED

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "from_seq": self.from_seq}


@dataclass(frozen=True, slots=True)
class RunFinished:
    reason: str
    message_count: int
    duration_ns: int
    dropped_events: int = 0
    unwritten_events: int = 0
    #: Rules stilled during the run. Repeated here because the closing event is written on
    #: the one path that is not droppable: if a ``rule_quarantined`` event was lost, this is
    #: what still tells a report which rule's hits it must not believe.
    quarantined_rules: tuple[str, ...] = ()
    #: How many observations the built-in walk made, per method the message answered.
    #: Counted where the inspection happened, not where the event was written, so it stays
    #: true when an observation event was dropped or when one message held more than a
    #: message may record.
    observations_by_method: dict[str, int] = field(default_factory=dict)
    #: How many findings each scenario statement made, per signal it names — every statement
    #: and every signal listed, zero included, so "asked and never seen" is a line in the
    #: summary and not an absence. Counted the same way, so it survives dropped events.
    findings_by_statement: dict[str, dict[str, int]] = field(default_factory=dict)
    #: The name the server gave for itself in ``initialize``, capped, or None. Repeated here
    #: on the path that cannot drop it, beside the declared name in ``run_started``.
    announced_server: str | None = None
    #: How many values the masker replaced inside **server-to-client** messages. A masked
    #: value in a client request is ordinary — the client is sending its own credential —
    #: while one on the way back is a place worth looking at. Pseudonymised protocol handles
    #: are not counted: those are correlation ids the masker substitutes by design, not
    #: something the server let out.
    server_redactions: int = 0
    #: How many messages a work bound stopped the inspector's walk on. Anything above zero
    #: means the run's observation is incomplete for those messages, and says so rather than
    #: letting an exhausted budget read as a clean result.
    inspection_bounded: int = 0
    #: What the server wrote to its stdout and what the client wrote to us, in bytes, counted
    #: where they were forwarded — not where they were recorded, so a dropped message event
    #: does not make a server look silent. And whether the server ended while the client was
    #: still connected. Facts for mcp_kymograph.verdict, which decides what a silent server means.
    server_output_bytes: int = 0
    client_input_bytes: int = 0
    server_exited_first: bool = False
    #: Over HTTP: what was forwarded, counted on the forwarding path so that it survives a
    #: dropped event; the counts of :data:`HTTP_COUNTS`, and ``tls``: ``null`` without TLS, else
    #: ``{"versions": [...], "certificates": [...]}``, the negotiated versions and the leaf
    #: certificates' SHA-256 of every connection, each list distinct and sorted — the run's
    #: set, where nothing is dropped, which the store reads. None over stdio.
    http: dict[str, Any] | None = None
    #: How many whole client-to-server messages were not valid UTF-8. The client's count, not
    #: the server's: it is never added to ``inspection_bounded``, so the server is not charged
    #: for what the client sent. Counted where the message is inspected, so it survives
    #: dropped message events. A reader without the field reads 0.
    client_undecodable: int = 0
    #: Whether the run finished at or after the end of the window its engagement file declares
    #: (``authorization.engagement.window_declared.until``), by the proxy's clock when it closed;
    #: None for a run without a file. Recorded, never acted on: the gate checks the window at the
    #: start, and a run that outlasts it is not cut short, which would end a recording for a
    #: reason the server did not cause. Not a state, and nothing judged reads it. A reader
    #: without the field reads null.
    window_exceeded: bool | None = None
    #: How many values the masker replaced by a pseudonym, per kind: ``email``, ``iban``, ``tel``
    #: and ``known`` (``masking.PERSONAL_KINDS``), every kind listed, zero included. Counted in
    #: the masker, where the text is written, so it holds where an event was dropped. Not part of
    #: ``server_redactions``: a pseudonym is substituted by design. A reader without the field
    #: reads null.
    replacements: dict[str, int] | None = None

    TYPE: ClassVar[EventType] = EventType.RUN_FINISHED

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "message_count": self.message_count,
            "duration_ns": self.duration_ns,
            "dropped_events": self.dropped_events,
            "unwritten_events": self.unwritten_events,
            "quarantined_rules": list(self.quarantined_rules),
            "observations_by_method": dict(self.observations_by_method),
            "findings_by_statement": {
                name: dict(counts) for name, counts in self.findings_by_statement.items()
            },
            "announced_server": self.announced_server,
            "server_redactions": self.server_redactions,
            "inspection_bounded": self.inspection_bounded,
            "server_output_bytes": self.server_output_bytes,
            "client_input_bytes": self.client_input_bytes,
            "server_exited_first": self.server_exited_first,
            "http": None if self.http is None else dict(self.http),
            "client_undecodable": self.client_undecodable,
            "window_exceeded": self.window_exceeded,
            "replacements": None if self.replacements is None else dict(self.replacements),
        }


class _RejectedConstant(ValueError):
    """Raised for the JSON extensions CPython accepts but JSON-RPC does not."""


def _reject_constant(name: str) -> Any:
    raise _RejectedConstant(name)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a document that cannot be represented faithfully as a dict.

    ``json.loads`` keeps the last of a repeated key and silently drops the rest. A recording
    that loses one half of ``{"result": "ok", "result": "evil"}`` is worse than no parse at
    all, so such a message falls back to being recorded as text: as written, unless the
    recorder's masking of every value it carries finds something to blank.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _RejectedConstant("duplicate_keys")
        seen[key] = value
    return seen


#: How deeply a parsed document may nest, in objects and lists counted from its root, and still
#: be walked by the parts that walk it by recursion: the masking and the recorder's JSON, the
#: scenario engine's rules. A fixed number, because where the recursion limit falls moves with
#: the Python version (3.10 and 3.11 spend two frames on a level of a list) and with the
#: caller's own stack, and what a server can make happen must not. Real messages are a handful
#: of levels deep.
MAX_DOCUMENT_DEPTH = 256

#: How deeply a message may nest and still be read for what is in it, by the driver and the
#: inspector, and a recording line by the verdict. Below where ``json.loads`` gives out on every
#: supported version (about a thousand levels less the caller's stack on 3.10 and 3.11, ten
#: thousand on 3.12 and later), so that which message counts as too deep does not depend on
#: the version; above :data:`MAX_DOCUMENT_DEPTH`, so that a recording line around a document
#: of that depth is always read back.
MAX_READ_DEPTH = 512


def deeper_than(document: Any, limit: int) -> bool:
    """Whether a parsed document nests more than ``limit`` objects and lists, counted from its
    root and without recursion: a document too deep to walk is exactly the one asked about.
    Only objects and lists with something in them are held while it looks."""
    if not isinstance(document, (dict, list)):
        return False
    if limit < 1:
        return True
    pending = [(document, 1)]
    while pending:
        node, depth = pending.pop()
        for child in node.values() if isinstance(node, dict) else node:
            if isinstance(child, (dict, list)):
                if depth >= limit:
                    return True
                if child:
                    pending.append((child, depth + 1))
    return False


#: What :func:`nesting` and :func:`top_level` read of a JSON text: an escape, a quote, a
#: bracket. Everything else is skipped over by the expression, never looked at one character
#: at a time.
_STRUCTURE = re.compile(r'\\.|["\[\]{}]', re.DOTALL)

_OPENING = {"]": "[", "}": "{"}


def nesting(text: str) -> int | None:
    """How deeply a JSON text nests its objects and lists, read without parsing it: in one
    pass and without recursion, the brackets inside strings skipped. None if its brackets do
    not pair up, or a string never ends — then it is no JSON at any depth."""
    opened: list[str] = []
    deepest = 0
    in_string = False
    for match in _STRUCTURE.finditer(text):
        mark = match.group()
        if mark == '"':
            in_string = not in_string
        elif in_string or mark[0] == "\\":
            continue
        elif mark in "[{":
            opened.append(mark)
            if len(opened) > deepest:
                deepest = len(opened)
        elif not opened or opened.pop() != _OPENING[mark]:
            return None
    return None if opened or in_string else deepest


def load(text: str, limit: int) -> tuple[Any, bool]:
    """A JSON text as ``(document, too_deep)``: the document, or None for a text that is no
    JSON; and whether it nests deeper than ``limit``, which must not be above
    :data:`MAX_READ_DEPTH`.

    A text that deep is never given to ``json.loads``: which text is too deep, and what is read
    of it, is then the same on every Python version, wherever its parser would give out. Of
    such a text only :func:`top_level` is read, for its id and method; what lies below is
    not checked, so it is too deep whether or not it would be valid JSON.
    """
    if text.count("[") + text.count("{") > limit:  # deeper at all only with this many
        depth = nesting(text)
        if depth is None:
            return None, False
        if depth > limit:
            return top_level(text), True
    try:
        return json.loads(text), False
    except ValueError:
        return None, False
    except RecursionError:  # within the limit, from a stack already nearly spent
        return top_level(text), True


def load_bytes(raw: bytes, limit: int) -> tuple[Any, bool]:
    """:func:`load` for bytes, decoded as ``json.loads`` decodes them — UTF-8, -16 or -32, a
    leading byte order mark dropped, a lone surrogate let through — and otherwise strictly:
    bytes that do not decode are no JSON."""
    try:
        text = raw.decode(json.detect_encoding(raw), "surrogatepass")
    except UnicodeDecodeError:
        return None, False
    return load(text, limit)


def top_level(text: str) -> dict[str, Any] | None:
    """The members of a JSON object with every object and list inside it read as null, or
    None if the text is not an object.

    For a message too deep for ``json.loads``: its id and method are still read, the same on
    every Python version, without parsing a single level below them. Read in one pass over
    the text and without recursion; the brackets inside strings are skipped.
    """
    parts: list[str] = []
    depth = 0
    in_string = False
    kept = 0  # where the text not yet cut begins
    for match in _STRUCTURE.finditer(text):
        mark = match.group()
        if mark[0] == "\\":
            continue
        if mark == '"':
            in_string = not in_string
        elif in_string:
            continue
        elif mark in "[{":
            depth += 1
            if depth == 2:
                parts.append(text[kept : match.start()])
                parts.append("null")
        else:
            depth -= 1
            if depth == 1:
                kept = match.end()
    if depth > 1:
        return None  # it never closed
    parts.append(text[kept:])
    try:
        document = json.loads("".join(parts))
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def decode(raw: bytes) -> tuple[str, bool]:
    """Decode a copy of a message. Never raises; a replacement char is not a crash."""
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), False


def inspect_message(
    raw: bytes, *, truncated: bool = False, incomplete: bool = False
) -> tuple[str, Any, ParseResult]:
    """Decode and analyse a copy of one message.

    Returns ``(text, document, parse)``. ``document`` is ``None`` when the message could not
    be parsed faithfully; the caller then records ``text`` instead. Parsing a copy never
    affects what is forwarded — a message that fails here still goes through untouched.

    ``truncated`` and ``incomplete`` both mean there is nothing worth parsing: the framer
    either dropped an oversized message or ran out of stream mid-line. ``truncated`` wins
    when both hold, because a discarded buffer is the more specific fact — an incomplete
    tail still carries its bytes, a truncated one carries none.
    """
    text, valid_utf8 = decode(raw)

    if truncated:
        return text, None, ParseResult(ok=False, error_reason="truncated")

    if incomplete:
        return text, None, ParseResult(ok=False, error_reason="incomplete")

    if text.count("[") + text.count("{") > MAX_READ_DEPTH:
        # Deeper than that, it is not parsed at all, so that where json.loads would give out
        # on this Python version decides nothing; brackets that do not pair are no JSON.
        # Before the bytes are judged: one that is not UTF-8 is read by the recorder too.
        depth = nesting(text)
        if depth is None:
            return text, None, ParseResult(ok=False, error_reason="invalid_json")
        if depth > MAX_READ_DEPTH:
            return text, None, ParseResult(ok=False, error_reason="too_deep")

    if not valid_utf8:
        return text, None, ParseResult(ok=False, error_reason="not_utf8")

    try:
        document = json.loads(
            text, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicates
        )
    except _RejectedConstant as exc:
        reason = "duplicate_keys" if str(exc) == "duplicate_keys" else "non_json_constant"
        return text, None, ParseResult(ok=False, error_reason=reason)
    except RecursionError:
        return text, None, ParseResult(ok=False, error_reason="too_deep")
    except ValueError:
        return text, None, ParseResult(ok=False, error_reason="invalid_json")

    return text, document, analyse(document)


def analyse(document: Any) -> ParseResult:
    """Classify a parsed JSON-RPC document."""
    if isinstance(document, list):
        return ParseResult(ok=True, kind=ParseKind.BATCH)

    if not isinstance(document, dict):
        return ParseResult(ok=True, kind=ParseKind.UNKNOWN)

    method = _clip_method(document.get("method"))
    identifier = _clip_id(document.get("id"))
    has_id = "id" in document

    if method is not None:
        kind = ParseKind.REQUEST if has_id else ParseKind.NOTIFICATION
        return ParseResult(ok=True, kind=kind, method=method, id=identifier)

    if "error" in document:
        return ParseResult(ok=True, kind=ParseKind.RESPONSE, id=identifier, is_error=True)

    if "result" in document:
        return ParseResult(ok=True, kind=ParseKind.RESPONSE, id=identifier)

    return ParseResult(ok=True, kind=ParseKind.UNKNOWN, id=identifier)


def _clip_method(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value[:MAX_METHOD_LENGTH]


#: A JSON-RPC id is a string or a number. CPython will happily parse a ten-thousand-digit
#: integer, which then cannot be serialised again on Python 3.11+ (int/str conversion limit).
#: Anything wider than this is dropped rather than allowed to break the writer.
MAX_ID_BITS = 256


def _clip_id(value: Any) -> str | int | None:
    if isinstance(value, bool):  # bool is an int subclass; not a valid JSON-RPC id
        return None
    if isinstance(value, int):
        return value if value.bit_length() <= MAX_ID_BITS else None
    if isinstance(value, str):
        return value[:MAX_ID_LENGTH]
    return None
