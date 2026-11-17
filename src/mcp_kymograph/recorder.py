"""The recorder: the only place an event comes into existence.

Every event is masked here, on the way in. There is no function in this module that hands
back an unmasked event, and no caller ever constructs an event body itself — callers pass
raw bytes and the recorder decides what may be written. That is the property the tests
check: put a credential in, read the file back, and it is not there in the clear.

The envelope arrives from outside. Sequence numbers and timestamps are assigned by the sink
when an event is submitted, not when it is written, so a dropped event still shows as a gap
and a timestamp records when something happened rather than when it reached the disk.

Every method here runs on the writer thread. Nothing in this module is safe to call from two
threads at once, and nothing needs to be: there is one writer.

Written as JSON Lines, one file per run, flushed after every line so an abort loses at most
the event in flight rather than the whole recording.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import platform
import re
import sys
import urllib.parse
from collections.abc import Callable, Collection, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol

from mcp_kymograph import __version__, eras, events
from mcp_kymograph.events import (
    HTTP_ENDINGS,
    HTTP_FRAMINGS,
    CallBlocked,
    CallFailed,
    Direction,
    EgressAttempt,
    EgressDns,
    EgressSummary,
    Encoding,
    EraDecided,
    EventType,
    Finding,
    FindingsCapped,
    HttpEnd,
    HttpRequest,
    HttpResponse,
    Intervention,
    LimitExceeded,
    Message,
    Mode,
    Observation,
    Paced,
    ParseResult,
    Payload,
    RecordingStopped,
    RuleQuarantined,
    RunFinished,
    RunStarted,
    RunStopped,
    SandboxFailure,
    SandboxStep,
    ScriptFinished,
    ServerExited,
    ServerFailed,
    ServerNameMismatch,
    ServerStderr,
    StatementEvaluated,
    StepCalled,
    StepReissued,
    StepSkipped,
    StepUnanswered,
    TokenObservation,
)
from mcp_kymograph.masking import (
    MAX_DECODINGS,
    PARSED_HEADER,
    PLACEHOLDER,
    PROTOCOL_HANDLE_PATHS,
    Masker,
    VerbatimPath,
    url_reach,
    withheld_path,
    withhold_url_path,
)
from mcp_kymograph.paths import Index
from mcp_kymograph.paths import parse as parse_path
from mcp_kymograph.token_inspector import TokenView

#: A single event carries at most this many redaction paths. ``redaction_count`` still
#: reports the true total, so a capped list never reads as a smaller number of hits.
MAX_RECORDED_REDACTIONS = 100

#: The most characters of a refusing error's ``data`` that ``era_decided`` keeps.
MAX_REFUSAL_DATA = 1000

#: A failure's detail is cut to this many characters, after masking (the TLS channel's own
#: cut, ``http_client.MAX_FAILURE_DETAIL``, is the same number).
MAX_FAILURE_DETAIL = 300

#: What is recorded in place of a message or a value nested too deeply to mask.
TOO_DEEP_TO_RECORD = "(nested too deeply to record)"

#: How deeply a document may nest, in objects and lists, and still be masked and written as
#: JSON: :data:`mcp_kymograph.events.MAX_DOCUMENT_DEPTH`, counted without recursion. A deeper
#: message, one deeper than :data:`mcp_kymograph.events.MAX_READ_DEPTH` that is not parsed at
#: all, and a deeper value in an intervention are recorded only as
#: :data:`TOO_DEEP_TO_RECORD`. Never as their text masked by shape: masking by key
#: cannot walk them, and the rules by shape miss a value written with a JSON escape in it, so
#: the text would carry what the masking of the parsed document would have blanked.
MAX_RECORDED_DEPTH = events.MAX_DOCUMENT_DEPTH

#: An observation's field path is built from key names the server chose, so it is capped
#: exactly like a redaction path.
MAX_PATH_LENGTH = 200

#: A recording belongs to its owner alone; the default umask is not a good enough answer for
#: a verbatim log of someone else's traffic.
FILE_MODE = 0o600

#: HTTP words that come off the wire are stored, so they are capped like a method name.
MAX_HTTP_METHOD_LENGTH = 32
MAX_HTTP_TEXT_LENGTH = 200
#: A path, a host, and the fields of a query map as recorded: capped after masking, so a
#: server or a client cannot make one event as large as it likes.
MAX_HTTP_PATH_LENGTH = 2048
MAX_HTTP_HOST_LENGTH = 255
MAX_HTTP_QUERY_FIELDS = 64
MAX_HTTP_QUERY_TEXT = 512
#: A request target in absolute form (RFC 9112 3.2.2): a scheme, then ``//``.
_ABSOLUTE_FORM = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

#: Headers whose value is one URI reference (RFC 9110), which may be relative; a relative one
#: names no host, so no listing can cover it.
_REFERENCE_HEADERS = frozenset({"location", "content-location", "referer"})
#: The only origin a reference keeps: ``http(s)``, a plain host (or an IPv6 literal) and a port
#: of digits, then a path or the end. Anything else (user info, a backslash, a lone slash) is no
#: origin the rule can vouch for.
_PLAIN_ORIGIN = re.compile(
    r"https?://(?:[A-Za-z0-9._~-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]+)?(?=/|\Z)", re.IGNORECASE
)
#: The parameters of a parsed challenge that hold one URI reference (RFC 9728 5.1, RFC 6750 3,
#: RFC 7616 3.3); the others go by the URL rule. ``domain`` may list several, which is no
#: reference and is withheld whole. Stands in for the header name while the walk is inside one.
_REFERENCE_PARAMS = frozenset({"resource_metadata", "domain", "error_uri"})
_REFERENCE_PARAM = "www-authenticate parameter holding a reference"

#: An exchange's TLS as :meth:`Recorder.http_request` takes it: the version ``ssl`` names
#: (``TLSv1.3``) and the leaf certificate's SHA-256 in lower-case hex. Ours, so a value of any
#: other shape is the caller's bug and refused, never cut to fit.
TLS_KEYS = frozenset({"version", "certificate_sha256"})
_TLS_VERSION = re.compile(r"[A-Za-z0-9._-]{1,32}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _inputs(
    given: Mapping[str, Any] | None, mask_text: Callable[[str], tuple[str, int]]
) -> dict[str, Any]:
    """What ``run_started.inputs`` records: Python and platform from here, the caller's step
    timeout (None where there is none) and mask key names, each run through ``mask_text``.
    Nothing else of ``given`` is kept."""
    given = given or {}
    return {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": platform.platform(),
        "step_timeout": given.get("step_timeout"),
        "mask_keys": [mask_text(str(name))[0] for name in given.get("mask_keys") or ()],
    }


#: The variables OpenSSL reads to find the trust store, as ``run_started.trust_store_env`` names
#: them: whether each was set, never its value.
TRUST_STORE_VARIABLES = ("SSL_CERT_FILE", "SSL_CERT_DIR")


class EventBody(Protocol):
    TYPE: EventType

    def to_dict(self) -> dict[str, Any]: ...


def utc_now() -> datetime:
    """The clock ``run_started`` reads, once: its ``wall_clock_utc`` and the token's ``expired``."""
    return datetime.now(timezone.utc)


def in_virtual_environment() -> bool:
    """Whether something had already reshaped the environment before this process began."""
    return sys.prefix != sys.base_prefix or "VIRTUAL_ENV" in os.environ


def wire_code(masker: Masker, code: Any) -> int | None:
    """A JSON-RPC error code from the wire: None when it is no whole number, or when the masker
    would not leave it a number in a document — its digits hold a literal of the run or a known
    value, whole or in part. Any other code stays as it is. Not counted: the payload of the
    message that holds the code has counted it. The one test for a code, wherever one is
    written: ``call_failed``, the probes' events and a token observation's ``rpc_code``."""
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    with masker.uncounted():
        masked, _ = masker.mask_json(code)
    return code if isinstance(masked, int) else None


class Recorder:
    """Writes the event stream for one run."""

    def __init__(
        self,
        stream: Any,
        *,
        run_id: str,
        masker: Masker,
        on_event: Callable[[int, EventBody], None] | None = None,
        verbatim_paths: Collection[VerbatimPath] = (),
    ) -> None:
        self._stream = stream
        self._run_id = run_id
        self._masker = masker
        #: What ``run_started.auth.token.expired`` said, once ``run_started`` is written: true,
        #: false, or None for a token with no readable ``exp`` and for a run with no token.
        self.token_expired: bool | None = None
        # The URL paths this run may write as they are, each with its host
        # and port: the ones the cli decided after the gate, or none. Every other path is written
        # as its SHA-256 and length. A request target in origin form has no host of its own; it is
        # the run's endpoint's, which ``run_started`` names (none before it: nothing verbatim).
        self._verbatim_paths = frozenset(verbatim_paths)
        self._reached: tuple[str, int | None] | None = None
        self._on_event = on_event
        self._message_count = 0
        self._server_redactions = 0
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        run_id: str,
        masker: Masker,
        on_event: Callable[[int, EventBody], None] | None = None,
        verbatim_paths: Collection[VerbatimPath] = (),
    ) -> Recorder:
        """Open the recording file exclusively, readable by its owner alone.

        ``O_EXCL``: an existing name is an error, never an overwrite. The directory it lives
        in was created and checked by :mod:`mcp_kymograph.output`.
        """
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        return cls(
            stream,
            run_id=run_id,
            masker=masker,
            on_event=on_event,
            verbatim_paths=verbatim_paths,
        )

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def message_count(self) -> int:
        return self._message_count

    @property
    def server_redactions(self) -> int:
        """How many values the masker replaced in server-to-client messages so far.

        Counted here, on the write path, because this is where masking happens and therefore
        the only place that knows a value was taken out at all. Pseudonymised protocol
        handles are excluded: those are substituted by design, in a closed set of known
        paths, and counting them would report a progress notification as a place a server
        let something out.
        """
        return self._server_redactions

    # -- events ---------------------------------------------------------------------

    def run_started(
        self,
        seq: int,
        t_ns: int,
        *,
        argv: Sequence[str],
        limits: Mapping[str, Any],
        inputs: Mapping[str, Any] | None = None,
        authorization: Mapping[str, Any] | None = None,
        mode: str = Mode.PROXY.value,
        script: str | None = None,
        script_digest: str | None = None,
        script_vars: Mapping[str, str] | None = None,
        server_identity: Mapping[str, Any] | None = None,
        scenario_name: str | None = None,
        server_name: str | None = None,
        reproduction: Mapping[str, Any] | None = None,
        isolation: str = "host",
        transport: str = events.TRANSPORT_STDIO,
        endpoint: str | None = None,
        auth: Mapping[str, Any] | None = None,
        trust_store_env: Mapping[str, bool] | None = None,
        pacing_enforced: bool | None = None,
        pacing: Mapping[str, Any] | None = None,
        probe: Mapping[str, Any] | None = None,
    ) -> None:
        if transport not in events.TRANSPORTS:
            raise ValueError(f"unknown transport {transport!r}")
        if endpoint is not None and transport != events.TRANSPORT_HTTP:
            raise ValueError("an endpoint belongs to the streamable-http transport only")
        # One reading of the clock for the whole event: the start of the run is what
        # ``wall_clock_utc`` says and what the token's ``expired`` is reckoned by. Cut to whole
        # milliseconds, as ``isoformat(timespec="milliseconds")`` writes it, so both agree.
        started_at = utc_now()
        started_at = started_at.replace(microsecond=started_at.microsecond // 1000 * 1000)
        recorded_endpoint = None if endpoint is None else self._endpoint(endpoint)
        if auth is not None and recorded_endpoint is None:
            raise ValueError("auth belongs to a run against an endpoint only")
        if pacing is not None and recorded_endpoint is None:
            raise ValueError("pacing belongs to a run against an endpoint only")
        if trust_store_env is not None and (
            recorded_endpoint is None or recorded_endpoint["scheme"] != "https"
        ):
            raise ValueError("trust_store_env belongs to an https run only")
        # What a person typed (the script, its variables, the options, the inputs, the identity,
        # the arguments of the command) is not a message: no value in it is counted, the payload
        # of a message that holds the value counts it.
        with self._masker.uncounted():
            masked_argv, redactions = self._masker.mask_argv(argv, self._verbatim_paths)
            event = RunStarted(
                argv=tuple(masked_argv),
                argv_redaction_count=redactions,
                # Not passed through the masker: these are a hostname the operator typed and
                # two booleans about our own flags, none of them traffic. Masking a target
                # would defeat the only reason to record it.
                authorization=dict(authorization or {}),
                # Ours, not the traffic's: which half of the conversation we produced and
                # under which script name. The name is the operator's file name, and may hold
                # a known value: masked as a key is.
                mode=mode,
                script=None if script is None else self._masker.mask_key(script),
                # A digest we computed, and the values the operator set, masked: a value is
                # typed by a person and may be a path, or something next to a credential.
                script_digest=script_digest,
                script_vars={
                    str(name)[: events.MAX_METHOD_LENGTH]: self._masker.mask_text(str(value))[0]
                    for name, value in (script_vars or {}).items()
                },
                # Ours: a digest we computed or a pinned revision the operator gave.
                server_identity=None if server_identity is None else dict(server_identity),
                scenario_name=scenario_name,
                # The operator's name for the corpus entry and the reproduction triple: ours,
                # from the manifest and from digests we computed. Nothing to mask.
                server_name=server_name,
                reproduction=None if reproduction is None else dict(reproduction),
                limits=dict(limits),
                # The interpreter and platform we read here and the step timeout the caller ran
                # with are ours. The mask key names are typed by a person and may be a value,
                # so they are masked.
                inputs=_inputs(inputs, self._masker.mask_text),
                wall_clock_utc=started_at.isoformat(timespec="milliseconds"),
                tool_version=__version__,
                virtual_environment=in_virtual_environment(),
                isolation=isolation,
                transport=transport,
                endpoint=recorded_endpoint,
                # Ours: the operator's names for an identity and its role, whether a token went
                # out and where it was read from. Names, never a value; masked all the same, for
                # the literals of the run.
                auth=None if auth is None else self._auth(auth, started_at),
                # Ours: two booleans, whether a variable was set. Its value is a path on this
                # machine and is never handed to us.
                trust_store_env=_trust_store_env(trust_store_env),
                # Ours: whether the run was paced, and by what (mcp_kymograph.pacing). Numbers and
                # one of two words.
                pacing_enforced=pacing_enforced,
                pacing=None if pacing is None else dict(pacing),
                # Ours: whether the salt of the pseudonyms is the engagement's or the run's.
                # Read from the masker, which holds the salt; the salt itself is not handed on.
                pseudonyms=self._masker.pseudonyms,
                # The module's name is ours; its options were typed by a person, as a script's
                # variables were, and are masked the same way.
                probe=None
                if probe is None
                else {
                    "name": str(probe["name"])[: events.MAX_METHOD_LENGTH],
                    "options": {
                        str(name)[: events.MAX_METHOD_LENGTH]: self._masker.mask_text(str(value))[0]
                        for name, value in dict(probe.get("options") or {}).items()
                    },
                },
            )
        self._emit(seq, t_ns, event)

    def message(
        self,
        seq: int,
        t_ns: int,
        *,
        direction: Direction,
        raw: bytes,
        size_bytes: int | None = None,
        truncated: bool = False,
        incomplete: bool = False,
        transport: str = events.TRANSPORT_STDIO,
        responded_method: str | None = None,
        exchange: int | None = None,
        stream: int | None = None,
        event_id: str | None = None,
    ) -> None:
        payload, parse = self._payload_for(raw, truncated=truncated, incomplete=incomplete)
        self._message_count += 1
        if direction is Direction.SERVER_TO_CLIENT:
            self._server_redactions += _credential_redactions(payload)
        self._emit(
            seq,
            t_ns,
            Message(
                direction=direction,
                transport=transport,
                size_bytes=len(raw) if size_bytes is None else size_bytes,
                truncated=truncated,
                incomplete=incomplete,
                # The method of the request this answers: a server's own, when the client
                # answers a request of the server's, so masked like ``parse.method``.
                responded_method=self._wire_method(responded_method),
                exchange=exchange,
                stream=stream,
                # A pseudonym, the same for the same id within the run; the id itself may
                # have a session folded into it, so it is never kept.
                event_id=None if event_id is None else self._masker.mask_event_id(event_id),
                payload=payload,
                parse=parse,
            ),
        )

    def http_request(
        self,
        seq: int,
        t_ns: int,
        *,
        exchange: int,
        connection: int,
        method: str,
        target: str,
        headers: Sequence[tuple[str, str]],
        session: int | None = None,
        tls: Mapping[str, Any] | None = None,
    ) -> None:
        """Record the head of one request. Method, target and headers are the wire's, so all
        three are masked here; the session is only ever its ordinal, never its id. ``tls`` is
        ours — the version ``ssl`` negotiated and a digest we computed — and written as given,
        after its shape is checked (:data:`TLS_KEYS`); None over plain HTTP."""
        recorded_tls = _tls(tls)
        method_text, _ = self._masker.mask_text(method)
        masked_headers, _ = self._masker.mask_headers(headers)
        masked_headers = self._withhold_header_paths(masked_headers)
        self._emit(
            seq,
            t_ns,
            HttpRequest(
                exchange=exchange,
                connection=connection,
                method=method_text[:MAX_HTTP_METHOD_LENGTH],
                target=self._target(target),
                headers=masked_headers,
                session=_ordinal(session),
                tls=recorded_tls,
            ),
        )

    def _withhold_header_paths(self, masked: Any, name: str | None = None) -> Any:
        """The masked headers with the path of every URL in any text of them withheld, as in the
        request target: a ``Location``, a ``Referer``, a ``resource_metadata`` names the
        endpoint's path as much as the target does. Keys stay; only texts are walked, in lists
        and in the parsed ``WWW-Authenticate`` alike. The masker keeps the whole value, so that
        the challenge parser and the terminal still read it. ``name`` is the header a text
        belongs to: in a reference header, or in the ``resource_metadata``, ``domain`` or
        ``error_uri`` of a challenge, the value may be a relative reference, whose path is
        withheld whether the file lists it or not, as it names no host; :meth:`_withhold_reference`
        withholds the rest of it. A ``Link`` value is
        withheld whole: its form is too loose to say where a path ends. The masker runs first,
        so the digest of a header's path is over the path as the masker left it."""
        if isinstance(masked, str):
            if name in _REFERENCE_HEADERS or name == _REFERENCE_PARAM:
                return self._withhold_reference(masked)
            if name == "link":
                return masked if masked == PLACEHOLDER else withheld_path(masked)
            return withhold_url_path(masked, self._verbatim_paths)
        if isinstance(masked, list):
            return [self._withhold_header_paths(item, name) for item in masked]
        if isinstance(masked, dict):
            return {
                key: self._withhold_header_paths(item, self._walk_name(name, key))
                for key, item in masked.items()
            }
        return masked

    @staticmethod
    def _walk_name(name: str | None, key: str) -> str:
        """The name the texts under ``key`` belong to: the header, or inside a parsed challenge
        the reference marker for the parameters that hold a reference."""
        if name is None:
            return key
        if name == PARSED_HEADER and key.lower() in _REFERENCE_PARAMS:
            return _REFERENCE_PARAM
        return name

    def _withhold_reference(self, text: str) -> str:
        """One URI reference keeps scheme, host and port, and a path the file lists; all else is
        withheld. The part before the first ``?`` or ``#`` is kept only as a plain ``http(s)``
        origin (:data:`_PLAIN_ORIGIN`) followed by one path, which is withheld unless the file
        lists it with that host and port; otherwise all of it is withheld as a path, a relative
        one included. A second scheme inside the path is part of that path. The query and the
        fragment are withheld, as a server may write a URL there in any encoding. White space at
        the edges is dropped; white space inside makes the value no single reference, and it is
        withheld whole. The masker's placeholder stays."""
        body = text.strip()
        if body == PLACEHOLDER:
            return body
        if re.search(r"\s", body):
            return withheld_path(body)
        ends = [i for i in (body.find("?"), body.find("#")) if i >= 0]
        cut = min(ends) if ends else len(body)
        base, mark, tail = body[:cut], body[cut : cut + 1], body[cut + 1 :]
        origin = _PLAIN_ORIGIN.match(base)
        if origin:
            path = base[origin.end() :]
            reach = url_reach(origin.group())
            kept = not path or (reach is not None and (*reach, path) in self._verbatim_paths)
            shown = base if kept else origin.group() + withheld_path(path)
        elif base:
            shown = withheld_path(base)
        else:
            shown = ""
        return shown + (mark + withheld_path(tail) if mark else "")

    def http_response(
        self,
        seq: int,
        t_ns: int,
        *,
        exchange: int,
        status: int,
        reason: str,
        headers: Sequence[tuple[str, str]],
        content_type: str | None,
        framing: str,
        session: int | None = None,
    ) -> None:
        """Record the head of one response. Every hit the header masking makes counts in
        :attr:`server_redactions`, like a value in a server message: a header is the server
        letting something out too."""
        if framing not in HTTP_FRAMINGS:
            raise ValueError(f"unknown framing {framing!r}")
        masked_headers, paths = self._masker.mask_headers(headers)
        masked_headers = self._withhold_header_paths(masked_headers)
        self._server_redactions += len(paths)
        reason_text, _ = self._masker.mask_text(reason)
        self._emit(
            seq,
            t_ns,
            HttpResponse(
                exchange=exchange,
                status=status,
                reason=reason_text[:MAX_HTTP_TEXT_LENGTH],
                headers=masked_headers,
                content_type=(
                    None
                    if content_type is None
                    else self._masker.mask_text(content_type)[0][:MAX_HTTP_TEXT_LENGTH]
                ),
                framing=framing,
                session=_ordinal(session),
            ),
        )

    def http_end(
        self,
        seq: int,
        t_ns: int,
        *,
        exchange: int,
        ended: str,
        request_body_bytes: int,
        response_body_bytes: int,
        head_bytes: int,
        events: int = 0,
        comments: int = 0,
    ) -> None:
        """Ours: how the exchange ended, and counts."""
        if ended not in HTTP_ENDINGS:
            raise ValueError(f"unknown ending {ended!r}")
        self._emit(
            seq,
            t_ns,
            HttpEnd(
                exchange=exchange,
                ended=ended,
                request_body_bytes=request_body_bytes,
                response_body_bytes=response_body_bytes,
                head_bytes=head_bytes,
                events=events,
                comments=comments,
            ),
        )

    def _auth(self, auth: Mapping[str, Any], started_at: datetime) -> dict[str, Any]:
        """``run_started.auth``: exactly ``identity``, ``role``, ``token_used``, ``source`` and
        ``token``, and ``env_name`` for a token read from the environment — refused rather than
        repaired. The names go through the masker as text, so a literal of the run in one is
        blanked. ``token`` is null without a token, else the inspector's :class:`TokenView` of
        it (:meth:`_token`), judged against ``started_at``."""
        keys = {"identity", "role", "token_used", "source", "token"}
        if not isinstance(auth, Mapping) or set(auth) - {"env_name", "observation"} != keys:
            raise ValueError(
                f"auth is {sorted(keys)}, env_name for a token from env, and observation"
            )
        observation = auth.get("observation")
        if observation is not None and observation not in events.TOKEN_OBSERVATIONS:
            raise ValueError(
                f"auth.observation is one of {', '.join(events.TOKEN_OBSERVATIONS)}, or null"
            )
        source = auth["source"]
        if source not in ("env", "file", "none") or type(auth["token_used"]) is not bool:
            raise ValueError("auth.source is env, file or none; auth.token_used is a boolean")
        if (source == "env") != ("env_name" in auth) or auth["token_used"] != (source != "none"):
            raise ValueError("auth.env_name is there for env only, and token_used is not none")
        if (auth["token"] is None) != (not auth["token_used"]):
            raise ValueError("auth.token is null exactly when no token was used")
        recorded: dict[str, Any] = {}
        for key in ("identity", "role", "token_used", "source", "env_name", "token"):
            if key not in auth:
                continue
            value = auth[key]
            if key == "token":
                value = None if value is None else self._token(value, started_at)
            elif key in ("identity", "role", "env_name"):
                if value is None and key != "env_name":
                    recorded[key] = None
                    continue
                if not isinstance(value, str):
                    raise ValueError(f"auth.{key} is text")
                value = self._masker.mask_text(value)[0]
            recorded[key] = value
        # Ours, one of three words: which token observation this run is, or null.
        recorded["observation"] = observation
        return recorded

    def _token(self, token: TokenView, started_at: datetime) -> dict[str, Any]:
        """``auth.token``: a ``TokenView.to_json()`` and ``expired`` (true, false or null),
        reckoned here by ``started_at``, the time ``run_started`` writes as ``wall_clock_utc``.
        The claims are taken as the inspector made them, masked in full before they were clipped
        (its ``mask``); nothing is masked here, so a view made without a mask is refused, as is
        anything that is not a view."""
        if not isinstance(token, TokenView) or not token.masked:
            raise ValueError("auth.token is a TokenView made with a mask")
        view = {**token.to_json(), "expired": token.expired(started_at)}
        self.token_expired = view["expired"]
        for name, value in view["claims"].items():
            if name == "exp":
                if type(value) is not int:
                    raise ValueError("auth.token.claims.exp is an integer")
            elif not isinstance(value, str) and not (
                isinstance(value, list) and all(isinstance(v, str) for v in value)
            ):
                raise ValueError(f"auth.token.claims.{name} is text or a list of text")
        return view

    def _endpoint(self, url: str) -> dict[str, Any]:
        """The URL taken apart and masked. A user or password in the authority is dropped and
        only said to have been there; a fragment is never kept. Refused: a URL without a scheme
        or without ``//`` and a host, and one whose path holds an ``@`` as sent or in any
        percent-decoding — there a parser and its reader disagree about where the user
        information ends (``http://u:8080/pw@h/x``), and none of it is written down. The path
        is written only when it, with its host and port, is one of the run's verbatim paths
        (:meth:`_path_fields`)."""
        refusal = endpoint_refusal(url)
        if refusal is not None:
            raise ValueError(refusal)
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        self._reached = url_reach(url)
        return {
            "scheme": parts.scheme.lower(),
            "host": None
            if host is None
            else self._masker.mask_text(host)[0][:MAX_HTTP_HOST_LENGTH],
            "port": parts.port,
            **self._path_fields(self._reached, parts.path),
            "query": self._query(parts.query),
            "userinfo_dropped": "@" in parts.netloc,
        }

    def _target(self, target: str) -> dict[str, Any]:
        """A request target, taken apart the way an endpoint is: in origin form (``/mcp?x``)
        cut by hand, so ``//x`` stays a path; in absolute form (``http://u:p@h/mcp``) parsed
        as a URL, the user and password dropped; in any other form whatever stands before an
        ``@`` in its first segment dropped. Then one rule for all of them, failing closed: a
        path that holds an ``@``, as sent or in any percent-decoding, is not kept at all. The path
        is written only when it, with its host and port, is one of the run's verbatim paths
        (:meth:`_path_fields`)."""
        without_fragment = target.partition("#")[0]
        userinfo = False
        reach = self._reached
        if _ABSOLUTE_FORM.match(without_fragment):
            parts = urllib.parse.urlsplit(without_fragment)
            userinfo = "@" in parts.netloc
            reach = url_reach(without_fragment)
            path, query = parts.path, parts.query
        else:
            path, _, query = without_fragment.partition("?")
            if not path.startswith("/"):
                first, slash, rest = path.partition("/")
                if "@" in first:
                    userinfo = True
                    path = first.rpartition("@")[2] + slash + rest
        if _holds_at(path):
            return {"path": PLACEHOLDER, "query": self._query(query), "userinfo_dropped": True}
        return {
            **self._path_fields(reach, path),
            "query": self._query(query),
            "userinfo_dropped": userinfo,
        }

    def _path_fields(self, reach: tuple[str, int | None] | None, path: str) -> dict[str, Any]:
        """The fields a URL's path is written as: the path, masked, when
        it is empty (an empty path holds nothing) or, on the host and port ``reach`` (None when
        not known), one of the run's verbatim paths; otherwise
        ``path: null`` with the SHA-256 of the path as sent (UTF-8, before any masking) and its
        length in characters beside it."""
        if not path or (reach is not None and (*reach, path) in self._verbatim_paths):
            return {"path": self._path(path)}
        return {
            "path": None,
            "path_sha256": hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest(),
            "path_length": len(path),
        }

    def _path(self, path: str) -> str:
        """A URL path, masked as text the way ``Masker._scrub`` treats a header value: kept as
        sent, but blanked whole if any of its percent-decodings (``masking.MAX_DECODINGS`` of
        them) holds something the text rules mask, or if it still decodes after the last:
        ``Bearer%20<token>`` is the text rule's ``Bearer <token>``. The path stays as written
        (``/a%20b``) exactly when masking it and then decoding it gives what decoding it and then
        masking gives; otherwise the decoded form is masked and written
        (:meth:`Masker.mask_decoded`). Capped after masking."""
        forms = [path]
        for _ in range(MAX_DECODINGS):
            decoded = urllib.parse.unquote(forms[-1])
            if decoded == forms[-1]:
                break
            forms.append(decoded)
        if urllib.parse.unquote(forms[-1]) != forms[-1]:
            return PLACEHOLDER
        if any(self._masker.mask_text(form, personal=False)[1] for form in forms[1:]):
            return PLACEHOLDER
        return self._masker.mask_decoded(forms)[:MAX_HTTP_PATH_LENGTH]

    def _query(self, query: str) -> dict[str, Any]:
        """A query string as ``mask_query`` maps it, each key and value capped, at most
        :data:`MAX_HTTP_QUERY_FIELDS` fields (the rest counted under ``"…"``)."""
        mapped, _ = self._masker.mask_query(query)
        capped: dict[str, Any] = {}
        for index, (key, value) in enumerate(mapped.items()):
            if index >= MAX_HTTP_QUERY_FIELDS:
                capped["…"] = len(mapped) - MAX_HTTP_QUERY_FIELDS
                break
            capped[str(key)[:MAX_HTTP_QUERY_TEXT]] = _capped_value(value)
        return capped

    def server_stderr(
        self,
        seq: int,
        t_ns: int,
        *,
        raw: bytes,
        size_bytes: int | None = None,
        truncated: bool = False,
    ) -> None:
        text, _ = events.decode(raw)
        self._emit(
            seq,
            t_ns,
            ServerStderr(
                size_bytes=len(raw) if size_bytes is None else size_bytes,
                truncated=truncated,
                payload=self._text_payload(text),
            ),
        )

    def intervention(
        self,
        seq: int,
        t_ns: int,
        *,
        action: str,
        direction: Direction,
        message_id: str | int | None,
        original: Any,
        replacement: Any | None,
        steps: Sequence[Any] = (),
    ) -> None:
        """Record what the rules did to one message. Every side is masked here, separately.

        ``original`` and ``replacement`` are the parsed documents from the engine, not bytes:
        the engine already parsed them to decide, and masking a document is stronger than
        masking its serialised text. They are kept apart, never merged.

        ``message_id`` is the server's and is masked like an observation's.

        ``steps`` are the engine's :class:`~mcp_kymograph.engine.Step` objects. Each changed
        value is masked *where it sat*: masking the bare string would let a value under a key
        like ``api_key`` through, because the key is what the structural rule reads.

        Not counted: every part of a document here is a part of a message that was recorded,
        and counted, in its payload. What a rule wrote in its place comes from the scenario.
        """
        with self._masker.uncounted():
            original_payload = None if original is None else self._document_payload(original)
            replacement_payload = (
                None if replacement is None else self._document_payload(replacement)
            )
            step_records = tuple(self._step_record(step) for step in steps)
        self._emit(
            seq,
            t_ns,
            Intervention(
                action=action,
                direction=direction,
                message_id=self._wire_id(message_id),
                original=original_payload,
                replacement=replacement_payload,
                steps=step_records,
            ),
        )

    def _step_record(self, step: Any) -> dict[str, Any]:
        return {
            "rule": step.rule,
            "action": step.action,
            "reason": step.reason,
            "changes": [
                {
                    "path": self._wire_path(change.path),
                    "before": self._value_payload(change.path, change.before).to_dict(),
                    "after": self._value_payload(change.path, change.after).to_dict(),
                }
                for change in step.changes
            ],
            "skipped": [
                {"path": self._wire_path(path), "reason": reason} for path, reason in step.skipped
            ],
        }

    def _value_payload(self, path: str, value: Any) -> Payload:
        """Mask one value as if it sat at ``path`` in a message, and return it alone.

        The value is placed into a skeleton that has every key of the path on the way down,
        so the structural rule sees the same names it would see in the whole message, and a
        protocol handle at its listed path is pseudonymised exactly as in a message event.
        ``""`` is the whole document.
        """
        if not path:
            return self._document_payload(value)
        steps = parse_path(path).steps
        masking = self._mask(_place(steps, value))
        if masking is None:
            return self._note(self._secret_keys(value))
        masked, paths = masking
        data = _take(steps, masked)
        # The skeleton puts every list position at 0, so its paths are respelled with the
        # real positions. A path that stops above the value — an ancestor's key masked the
        # whole subtree — is recorded as the real path to that ancestor.
        names = _skeleton_names(steps, masked)
        paths = [_respell(found, steps, names) for found in paths]
        if not _is_serialisable(data):
            return self._unrepresentable_payload(repr(value), data, paths)
        return Payload(
            encoding=Encoding.JSON,
            data=data,
            redactions=tuple(paths[:MAX_RECORDED_REDACTIONS]),
            redaction_count=len(paths),
        )

    def observation(
        self,
        seq: int,
        t_ns: int,
        *,
        direction: Direction,
        method: str | None,
        message_id: str | int | None,
        message_seq: int,
        surface: str,
        path: str,
        signal: str,
        normalized: bool = False,
    ) -> None:
        """Record one place where the server delivered model-addressable content.

        ``surface`` and ``signal`` are our own vocabulary. The text itself stays where it
        already is, in the message event at ``message_seq``, masked once. What the server
        chose is masked here: ``method`` and ``message_id`` as the message event masks them,
        and ``path``, which is built from key names the server chose, and clipped for the
        same reason the recorder clips redaction paths.
        """
        self._emit(
            seq,
            t_ns,
            Observation(
                direction=direction,
                method=self._wire_method(method),
                message_id=self._wire_id(message_id),
                message_seq=message_seq,
                surface=surface,
                path=self._wire_path(path),
                signal=signal,
                normalized=normalized,
            ),
        )

    def scrub(self, text: str) -> str:
        """The text with what this run keeps secret blanked: the masking every text of the
        server goes through, for a text the recorder is not handed as a payload."""
        return self._masker.mask_text(text)[0]

    def masked_counts(self, counts: Mapping[str, int]) -> dict[str, int]:
        """Counts by method name, the names masked as every method off the wire is. Two names
        that come out the same are one key, their counts added. What ``run_finished`` records
        and what the terminal says, so that the two cannot differ."""
        masked: dict[str, int] = {}
        for method, count in counts.items():
            name = self._wire_method(method) or ""
            masked[name] = masked.get(name, 0) + count
        return masked

    def _wire_text(self, text: str | None) -> str | None:
        """A text the server chose, masked as text; None stays None."""
        return None if text is None else self._masker.mask_text(text)[0]

    def _repeated_text(self, text: str | None) -> str | None:
        """A text that names a part of a message that was recorded, masked as :meth:`_wire_text`
        masks it and not counted: its value is counted where the message's payload holds it."""
        with self._masker.uncounted():
            return self._wire_text(text)

    def _wire_method(self, method: str | None) -> str | None:
        """A method name from the wire, masked as the server wrote it and clipped after, so
        that a literal cut by the clip does not leave its head behind."""
        return _clip_method(self._repeated_text(method))

    def _wire_path(self, path: str) -> str:
        """A position built from key names the server chose, masked, then clipped."""
        return (self._repeated_text(path) or "")[:MAX_PATH_LENGTH]

    def _wire_id(self, message_id: str | int | None) -> str | int | None:
        """A JSON-RPC id from the wire: a string as text, a number as the placeholder when its
        digits hold a literal; clipped after masking like ``parse.id``."""
        if message_id is None:
            return None
        masked = self._mask_id(message_id)
        return masked[: events.MAX_ID_LENGTH] if isinstance(masked, str) else masked

    def _wire_code(self, code: Any) -> int | None:
        """A JSON-RPC error code from the wire, as :func:`wire_code` keeps it."""
        return wire_code(self._masker, code)

    def finding(
        self,
        seq: int,
        t_ns: int,
        *,
        key: Mapping[str, Any],
        direction: Direction,
        method: str | None,
        message_id: str | int | None,
        message_seq: int,
        path: str,
        normalized: bool = False,
    ) -> None:
        """Record one finding. ``key`` holds our own words and names from the operator's
        file, which stay, and a locator, built from names the server chose, which is masked;
        ``method``, ``message_id`` and ``path`` are masked as an observation's are."""
        self._emit(
            seq,
            t_ns,
            Finding(
                key={
                    name: self._repeated_text(value) if name == "locator" else value
                    for name, value in key.items()
                },
                direction=direction,
                method=self._wire_method(method),
                message_id=self._wire_id(message_id),
                message_seq=message_seq,
                path=self._wire_path(path),
                normalized=normalized,
            ),
        )

    def findings_capped(
        self,
        seq: int,
        t_ns: int,
        *,
        method: str | None,
        message_id: str | int | None,
        message_seq: int,
        cap: int,
        made: int,
        recorded: int,
        cut: Mapping[str, Mapping[str, int]],
    ) -> None:
        """Ours: counts, statement names from the operator's file and signal names; the
        ``method`` and ``message_id`` of the message are the server's, and masked."""
        self._emit(
            seq,
            t_ns,
            FindingsCapped(
                method=self._wire_method(method),
                message_id=self._wire_id(message_id),
                message_seq=message_seq,
                cap=cap,
                made=made,
                recorded=recorded,
                cut={statement: dict(signals) for statement, signals in cut.items()},
            ),
        )

    def server_name_mismatch(
        self, seq: int, t_ns: int, *, declared: str, announced: str | None, message_seq: int
    ) -> None:
        self._emit(
            seq,
            t_ns,
            ServerNameMismatch(
                declared=declared,
                announced=self._repeated_text(announced),
                message_seq=message_seq,
            ),
        )

    def statement_evaluated(
        self,
        seq: int,
        t_ns: int,
        *,
        statement: str,
        method: str | None,
        message_id: str | int | None,
        message_seq: int,
        checked: int,
        not_strings: int,
        fired: Mapping[str, int],
        reason: str | None = None,
    ) -> None:
        self._emit(
            seq,
            t_ns,
            StatementEvaluated(
                statement=statement,
                method=self._wire_method(method),
                message_id=self._wire_id(message_id),
                message_seq=message_seq,
                checked=checked,
                not_strings=not_strings,
                fired=dict(fired),
                reason=reason,
            ),
        )

    def _mask(self, document: Any) -> tuple[Any, list[str]] | None:
        """The masked copy and the paths hit, or None for a document deeper than
        :data:`MAX_RECORDED_DEPTH`."""
        if events.deeper_than(document, MAX_RECORDED_DEPTH):
            return None
        try:
            return self._masker.mask_json(document)
        except RecursionError:
            return None  # within the depth, but called from a stack already nearly spent

    def _secret_keys(self, document: Any) -> int:
        """How many keys anywhere in the document are ones the masking blanks by name, counted
        without recursion: what a note in its place withholds, so that it is counted. Not
        below such a key: the masking blanks its whole value as one. A handle the masking
        replaces by a pseudonym rather than blanking it counts too, where its key is one."""
        found = 0
        pending = [document]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if self._masker.is_secret_key(str(key)):
                        found += 1
                    else:
                        pending.append(value)
            elif isinstance(node, list):
                pending.extend(node)
        return found

    def _note(self, withheld: int = 0) -> Payload:
        """:data:`TOO_DEEP_TO_RECORD` in place of the content, counting what it withholds."""
        return Payload(encoding=Encoding.TEXT, data=TOO_DEEP_TO_RECORD, redaction_count=withheld)

    def _unrepresentable_payload(self, as_written: str, masked: Any, paths: list[str]) -> Payload:
        """A document JSON cannot carry, or one parsed only to be masked, as text: a number
        such as ``1e400`` became infinite, or the message was rejected as written.

        The masked document's text, with every string and key decoded and masked by shape
        once more: never the unmasked one's, and never text in which a JSON escape hides what
        the masking blanks. As written only when neither found anything, so that such a number
        keeps its digits and a rejected message its spelling.
        """
        text, hits = self._masker.mask_text(
            json.dumps(masked, ensure_ascii=False, allow_nan=True, default=repr)
        )
        if not paths and not hits:
            return self._text_payload(as_written)
        return Payload(
            encoding=Encoding.TEXT,
            data=text,
            redactions=tuple(paths[:MAX_RECORDED_REDACTIONS]),
            redaction_count=len(paths) + hits,
        )

    def _document_payload(self, document: Any) -> Payload:
        masking = self._mask(document)
        if masking is None:
            return self._note(self._secret_keys(document))
        masked, paths = masking
        if not _is_serialisable(masked):
            return self._unrepresentable_payload(repr(document), masked, paths)
        return Payload(
            encoding=Encoding.JSON,
            data=masked,
            redactions=tuple(paths[:MAX_RECORDED_REDACTIONS]),
            redaction_count=len(paths),
        )

    def server_exited(
        self, seq: int, t_ns: int, *, exit_code: int | None, signal: int | None = None
    ) -> None:
        self._emit(seq, t_ns, ServerExited(exit_code=exit_code, signal=signal))

    def rule_quarantined(
        self,
        seq: int,
        t_ns: int,
        *,
        rule: str,
        reason: str,
        detail: str,
        direction: Direction,
        message_id: str | int | None,
        invalidated_hits: int,
    ) -> None:
        """Record that one rule was stilled and everything it produced is to be distrusted.

        ``detail`` names the failure in our own words (the exception type, not its message):
        an exception message comes from rule code that may have interpolated traffic into it,
        and this field is not a Payload and never passes the masker. ``message_id`` is the
        server's and is masked like an observation's.
        """
        self._emit(
            seq,
            t_ns,
            RuleQuarantined(
                rule=rule,
                reason=reason,
                detail=detail,
                direction=direction,
                message_id=self._wire_id(message_id),
                invalidated_hits=invalidated_hits,
            ),
        )

    def step_skipped(
        self, seq: int, t_ns: int, *, step: str, reason: str, detail: str = ""
    ) -> None:
        """Record that a step of the script was not sent, and in whose words why.

        Nothing here is a Payload and nothing passes the masker: ``step`` is a method name
        out of our own script table and ``reason``/``detail`` are our own vocabulary. None of
        it came off the wire.
        """
        self._emit(seq, t_ns, StepSkipped(step=step, reason=reason, detail=detail))

    def step_unanswered(
        self, seq: int, t_ns: int, *, step: str, pages: int, reason: str, detail: str = ""
    ) -> None:
        """Ours, like a skip: a method from our own script table, a count, our own word. Not
        ``detail``: under ``tls`` it is the TLS library's text, which can name what the
        endpoint's certificate says, so a detail is masked like text off the wire."""
        self._emit(
            seq,
            t_ns,
            StepUnanswered(step=step, pages=pages, reason=reason, detail=self._detail(detail)),
        )

    def step_called(
        self,
        seq: int,
        t_ns: int,
        *,
        step: str,
        tool: str,
        arguments: Any,
        check: str | None = None,
    ) -> None:
        """A tool call that was sent. The step is ours; the tool, the arguments and the check
        are the script file's (or ``--probe-option``'s), so the arguments go through the masker
        like any argument in the recording, and the tool name is masked and then cut like a
        method name. Masked first: a cut would split a token the masker no longer recognises.
        The check is a path, and a quoted string in it is the script's text: it is masked as
        text, as a string of the arguments is, and like them it is not counted."""
        with self._masker.uncounted():
            masking = self._mask(arguments)
            if masking is None:
                shown, paths, count = TOO_DEEP_TO_RECORD, [], self._secret_keys(arguments)
            else:
                shown, paths = masking
                count = len(paths)
            if check is not None:
                check = self._masker.mask_text(check)[0]
        self._emit(
            seq,
            t_ns,
            StepCalled(
                step=step,
                tool=self._tool_name(tool),
                arguments=shown,
                check=check,
                redactions=tuple(paths[:MAX_RECORDED_REDACTIONS]),
                redaction_count=count,
            ),
        )

    def _tool_name(self, tool: str) -> str:
        """A tool's name as the event records it: masked, then cut like a method name. Not
        counted: the name is a script's or the wire's, and the payload of the message that holds
        it has counted it, if there is one."""
        with self._masker.uncounted():
            return _clip_method(self._masker.mask_text(tool)[0])

    def call_failed(
        self, seq: int, t_ns: int, *, step: str, tool: str, kind: str, code: int | None = None
    ) -> None:
        """A call that was answered with an error. The kind is ours, from a closed set; the code
        is the server's ``error.code``, written as None when its digits hold a literal of the
        run (:meth:`_wire_code`). The server's words are in the message."""
        if kind not in events.CALL_FAILURES:
            raise ValueError(f"unknown kind of failed call {kind!r}")
        code = self._wire_code(code)
        name = self._tool_name(tool)
        self._emit(seq, t_ns, CallFailed(step=step, tool=name, kind=kind, code=code))

    def call_blocked(
        self,
        seq: int,
        t_ns: int,
        *,
        cause: str,
        where: str,
        tool: str | None = None,
        message_id: str | int | None = None,
        answered: bool = False,
        batch: bool = False,
    ) -> None:
        """A tool call the engagement's scope did not allow. The cause and the place are ours,
        closed sets; the tool's name and the id came off the wire (or out of a script file), so
        the name is masked and then cut like a method name, and the id is masked and then capped as
        every id is. Masked first: a cut would split a token the masker no longer recognises."""
        if cause not in events.BLOCK_CAUSES:
            raise ValueError(f"unknown cause of a blocked call {cause!r}")
        if where not in (events.BLOCKED_BY_PROXY, events.BLOCKED_BY_DRIVER):
            raise ValueError(f"unknown place of a blocked call {where!r}")
        name = None if tool is None else self._tool_name(tool)
        self._emit(
            seq,
            t_ns,
            CallBlocked(
                cause=cause,
                where=where,
                tool=name,
                message_id=events._clip_id(self._mask_id(message_id)),
                answered=answered,
                batch=batch,
            ),
        )

    def script_finished(
        self,
        seq: int,
        t_ns: int,
        *,
        inventory: str,
        sent: Sequence[str] = (),
        skipped: Sequence[tuple[str, str]] = (),
        unanswered: Sequence[tuple[str, int, str]] = (),
        called: Sequence[str] = (),
        failed: Sequence[str] = (),
        era: str | None = None,
        protocol_version: str | None = None,
    ) -> None:
        """Ours: the driver's summary of its own script. The names in ``called`` and ``failed``
        come from the script or from ``--probe-option``, and they run through the masker like
        anything a person typed, then are cut. ``protocol_version`` came off the wire and is
        masked here and cut after."""
        self._emit(
            seq,
            t_ns,
            ScriptFinished(
                inventory=inventory,
                sent=tuple(sent),
                skipped=tuple(tuple(pair) for pair in skipped),
                unanswered=tuple(tuple(item) for item in unanswered),
                called=tuple(self._tool_name(name) for name in called),
                failed=tuple(self._tool_name(name) for name in failed),
                era=era,
                protocol_version=self._version_text(protocol_version),
            ),
        )

    def era_decided(
        self,
        seq: int,
        t_ns: int,
        *,
        era: str | None,
        version: str | None,
        outcome: str,
        reason: str | None = None,
        probe: Mapping[str, Any] | None = None,
        exchanges: Sequence[tuple[str, str, int | None]] = (),
        refusal: Mapping[str, Any] | None = None,
        declared: Mapping[str, Any] | None = None,
        differs: bool | None = None,
        observations: Sequence[str] = (),
    ) -> None:
        """How the server's generation was settled. The words are ours; the versions are the
        server's, whole from ``eras``, masked here as text and then cut; ``refusal.data`` is
        the server's ``error.data``, masked as a document and clipped to
        :data:`MAX_REFUSAL_DATA`."""
        shown_probe = None
        if probe is not None:
            shown_probe = {
                "outcome": probe.get("outcome"),
                "code": self._wire_code(probe.get("code")),
                "supported": [self._version_text(v) for v in probe.get("supported", ())],
            }
        shown_refusal = None
        if refusal is not None:
            shown_refusal = {
                "code": self._wire_code(refusal.get("code")),
                "data": self._refusal_data(refusal),
            }
        self._emit(
            seq,
            t_ns,
            EraDecided(
                era=era,
                version=self._version_text(version),
                outcome=outcome,
                reason=reason,
                probe=shown_probe,
                exchanges=tuple((str(m), str(o), self._wire_code(c)) for m, o, c in exchanges),
                refusal=shown_refusal,
                declared=None if declared is None else dict(declared),
                differs=differs,
                observations=tuple(observations),
            ),
        )

    def step_reissued(self, seq: int, t_ns: int, *, step: str, page: int, reason: str) -> None:
        """Ours, like a skip: a method from the script's table, a page number, our own word."""
        self._emit(seq, t_ns, StepReissued(step=step, page=page, reason=reason))

    def _version_text(self, version: str | None) -> str | None:
        """A protocol version from the traffic, masked as text and cut after, to
        :data:`~mcp_kymograph.eras.MAX_VERSION_LENGTH`; None stays None. Not counted: the
        message that carried the version has counted it."""
        if not isinstance(version, str):
            return None
        return self._repeated_text(version)[: eras.MAX_VERSION_LENGTH]

    def _refusal_data(self, refusal: Mapping[str, Any]) -> Any:
        """An error's ``data``, masked like any document off the wire and, when its text is
        longer than :data:`MAX_REFUSAL_DATA` characters, replaced by its first characters. Not
        counted: the payload of the message that carried the error has counted it."""
        data = refusal.get("data")
        if data is None:
            return None
        with self._masker.uncounted():
            masking = self._mask(data)
        if masking is None:
            return TOO_DEEP_TO_RECORD
        text = json.dumps(masking[0], ensure_ascii=False, separators=(",", ":"))
        return masking[0] if len(text) <= MAX_REFUSAL_DATA else text[:MAX_REFUSAL_DATA]

    def run_stopped(
        self, seq: int, t_ns: int, *, signal: str, because: str = events.STOPPED_BY_SIGNAL
    ) -> None:
        """Ours: the run was stopped before it ended on its own, by a signal to this process or,
        as ``because`` says, by the engagement's stop file or the end of its window."""
        if because not in events.STOPPED_BECAUSE:
            raise ValueError(f"unknown reason for a stop {because!r}")
        self._emit(seq, t_ns, RunStopped(signal=signal, because=because))

    def paced(
        self, seq: int, t_ns: int, *, seconds: float, why: str, status: int | None = None
    ) -> None:
        """Ours: the run waited ``seconds`` for ``why`` (mcp_kymograph.pacing): before it began,
        or, as ``retry_after`` with the ``status`` that asked for it, in the middle of it."""
        if why not in events.PACED_WHY:
            raise ValueError(f"unknown reason for a wait {why!r}")
        self._emit(seq, t_ns, Paced(seconds=round(seconds, 3), why=why, status=status))

    def token_observation(
        self,
        seq: int,
        t_ns: int,
        *,
        kind: str,
        exchanges: Sequence[Mapping[str, Any]],
        expiry: str | None = None,
    ) -> None:
        """Ours: how the server answered each exchange of a token observation. Closed words and
        numbers only (a method the driver built, capped; two statuses), and a value that is not
        one is refused rather than repaired. ``rpc_code`` is the server's number all the same: it
        is held to :func:`wire_code` here as well, as ``call_failed`` holds its code, whatever
        the caller asked of it before; not counted."""
        if kind not in events.TOKEN_OBSERVATIONS:
            raise ValueError(f"unknown kind of token observation {kind!r}")
        if (expiry is None) != (kind != "expired") or (
            expiry is not None and expiry not in events.EXPIRIES
        ):
            raise ValueError("expiry belongs to the kind expired, and is one of events.EXPIRIES")
        kept = []
        for exchange in exchanges:
            role, method = exchange["role"], exchange["method"]
            accepted = exchange["accepted"]
            status, code = exchange["http_status"], exchange["rpc_code"]
            if (
                role not in events.EXCHANGE_ROLES
                or not isinstance(method, str)
                or not (accepted is None or type(accepted) is bool)
                or not all(x is None or type(x) is int for x in (status, code))
                or (code is not None and abs(code) > events.MAX_RPC_CODE)
                or (status is not None and not 100 <= status <= 599)
            ):
                raise ValueError(
                    "an exchange is a role, a method, accepted, http_status and rpc_code"
                )
            kept.append(
                {
                    "role": role,
                    "method": method[: events.MAX_METHOD_LENGTH],
                    "accepted": accepted,
                    "http_status": status,
                    "rpc_code": None if code is None else self._wire_code(code),
                }
            )
        self._emit(seq, t_ns, TokenObservation(kind=kind, exchanges=tuple(kept), expiry=expiry))

    def server_failed(self, seq: int, t_ns: int, *, reason: str, detail: str = "") -> None:
        """Ours: the driver's word for why the handshake did not complete. ``detail`` is our own
        sentence for every reason but ``tls``, where it is the TLS library's text and can name
        what the endpoint's certificate says; so every detail is masked like text off the wire.
        Our own sentences hold nothing the masker takes."""
        self._emit(seq, t_ns, ServerFailed(reason=reason, detail=self._detail(detail)))

    def _detail(self, detail: str) -> str:
        """A failure's detail, masked and cut after, to :data:`MAX_FAILURE_DETAIL`. The
        channel has cut its own text and dropped the characters a terminal must not be
        handed; our sentence for a stop holds server text whole, so the cut is here."""
        return self._masker.mask_text(detail)[0][:MAX_FAILURE_DETAIL] if detail else ""

    def sandbox_step(
        self, seq: int, t_ns: int, *, step: str, ok: bool, seconds: float, detail: Any
    ) -> None:
        """Ours: the sandbox's evidence from its own containers. What the probe saw of the
        namespace is the namespace we built, not the target's traffic. The problems of the
        account are the exception (:meth:`_problems_said`)."""
        self._emit(
            seq,
            t_ns,
            SandboxStep(step=step, ok=ok, seconds=seconds, detail=self._problems_said(detail)),
        )

    def sandbox_failed(
        self, seq: int, t_ns: int, *, condition: str, phase: str, detail: Any
    ) -> None:
        self._emit(
            seq,
            t_ns,
            SandboxFailure(condition=condition, phase=phase, detail=self._problems_said(detail)),
        )

    def _problems_said(self, detail: Any) -> Any:
        """The ``problems`` of an egress account are the tool's sentences around what the target
        steered: a count of its packets, an address it chose. Each is masked as text and not
        counted, so that a count whose digits hold a known value is not written into a
        sentence. The rest of a detail is as it was."""
        if not isinstance(detail, Mapping) or not isinstance(detail.get("problems"), (list, tuple)):
            return detail
        with self._masker.uncounted():
            said = [
                self._masker.mask_text(problem)[0] if isinstance(problem, str) else problem
                for problem in detail["problems"]
            ]
        return {**detail, "problems": said}

    def egress_attempt(self, seq: int, t_ns: int, *, attempt: Mapping[str, Any]) -> None:
        """From the kernel's record: addresses, ports and protocol names, nothing the target
        wrote into a payload. The target chose the address and the port all the same, so both
        go through the masker: an address that is a known value is its pseudonym, and a port
        whose digits hold one is written as a number in an answer is, as text. The count stays
        the number the kernel counted."""
        kind = attempt.get("type", attempt.get("l4proto"))
        port = attempt.get("port")
        if isinstance(port, int) and not isinstance(port, bool):
            port = self._masker.mask_json(port)[0]
        self._emit(
            seq,
            t_ns,
            EgressAttempt(
                proto=str(attempt["proto"]),
                family=int(attempt["family"]),
                destination=self._masker.mask_text(str(attempt["destination"]))[0],
                port=port,
                kind=None if kind is None else str(kind),
                count=int(attempt["count"]),
                unit=str(attempt["unit"]),
            ),
        )

    def egress_dns(self, seq: int, t_ns: int, *, query: Mapping[str, Any]) -> None:
        """A name is text the target chose, so it is masked like any other: a credential
        smuggled out in a DNS label is still a credential. The query type is a number the
        target chose, and goes through the masker like a number in an answer."""
        qname = query.get("qname")
        hits = 0
        if isinstance(qname, str):
            qname, hits = self._masker.mask_text(qname)
        qtype = query.get("qtype")
        if isinstance(qtype, int) and not isinstance(qtype, bool):
            qtype = self._masker.mask_json(qtype)[0]
        else:
            qtype = None
        self._emit(
            seq,
            t_ns,
            EgressDns(
                transport=str(query.get("transport")),
                family=int(query.get("family") or 0),
                qname=qname if isinstance(qname, str) else None,
                qtype=qtype,
                answered=query.get("answered") is True,
                qname_redactions=hits,
            ),
        )

    def egress_summary(self, seq: int, t_ns: int, *, summary: Mapping[str, Any]) -> None:
        self._emit(
            seq,
            t_ns,
            EgressSummary(
                consistent=bool(summary["consistent"]),
                problems=tuple(self._problems_said(summary)["problems"]),
                attempts=int(summary["attempts"]),
                dns_queries=int(summary["dns_queries"]),
                counters=dict(summary["counters"]),
                capped=dict(summary["capped"]),
                direct_sink_access=int(summary["direct_sink_access"]),
                sink_suppressed=int(summary["sink_suppressed"]),
                account_differences={
                    str(k): dict(v) for k, v in (summary.get("account_differences") or {}).items()
                },
                udp_loss=dict(summary.get("udp_loss") or {}),
            ),
        )

    def limit_exceeded(self, seq: int, t_ns: int, *, limit: str, value: float, unit: str) -> None:
        self._emit(seq, t_ns, LimitExceeded(limit=limit, value=value, unit=unit))

    def recording_stopped(self, seq: int, t_ns: int, *, reason: str, from_seq: int) -> None:
        self._emit(seq, t_ns, RecordingStopped(reason=reason, from_seq=from_seq))

    def run_finished(
        self,
        seq: int,
        t_ns: int,
        *,
        reason: str,
        duration_ns: int,
        dropped_events: int = 0,
        unwritten_events: int = 0,
        quarantined_rules: tuple[str, ...] = (),
        observations_by_method: Mapping[str, int] | None = None,
        findings_by_statement: Mapping[str, Mapping[str, int]] | None = None,
        inspection_bounded: int = 0,
        announced_server: str | None = None,
        server_output_bytes: int,
        client_input_bytes: int,
        server_exited_first: bool,
        http: Mapping[str, Any] | None = None,
        client_undecodable: int = 0,
        window_exceeded: bool | None = None,
    ) -> None:
        self._emit(
            seq,
            t_ns,
            RunFinished(
                reason=reason,
                message_count=self._message_count,
                duration_ns=duration_ns,
                dropped_events=dropped_events,
                unwritten_events=unwritten_events,
                quarantined_rules=tuple(quarantined_rules),
                observations_by_method=self.masked_counts(observations_by_method or {}),
                findings_by_statement={
                    name: dict(counts) for name, counts in (findings_by_statement or {}).items()
                },
                announced_server=self._repeated_text(announced_server),
                inspection_bounded=inspection_bounded,
                server_output_bytes=server_output_bytes,
                client_input_bytes=client_input_bytes,
                server_exited_first=server_exited_first,
                http=None if http is None else dict(http),
                client_undecodable=client_undecodable,
                # Ours: the proxy's clock against the window the operator's file declares.
                window_exceeded=window_exceeded,
                # Read from our own counter rather than passed in: the caller never saw the
                # masking, because masking happens here and nowhere else.
                server_redactions=self._server_redactions,
                # Likewise the count of what was replaced by a pseudonym, per kind.
                replacements=self._masker.replacements,
            ),
        )

    # -- internals ------------------------------------------------------------------

    def _payload_for(
        self, raw: bytes, *, truncated: bool, incomplete: bool
    ) -> tuple[Payload, ParseResult]:
        text, document, parse = events.inspect_message(
            raw, truncated=truncated, incomplete=incomplete
        )

        if document is None:
            if parse.error_reason == "too_deep":
                # Too deep to be parsed at all: nothing of it can be masked by key, so nothing
                # of it is written. Said to be too deep, never a reason to stop.
                return self._note(), parse
            if parse.error_reason in _PARSED_TO_MASK:
                return self._rejected_payload(text), parse
            # Not JSON at all: there is no document to mask, only its text by shape.
            return self._text_payload(text), parse

        masking = self._mask(document)
        if masking is None:
            # Too deep to mask, though not too deep to parse: the same note, counting the keys
            # it withholds that the masking would have blanked.
            too_deep = ParseResult(ok=False, error_reason="too_deep")
            return self._note(self._secret_keys(document)), too_deep
        masked, paths = masking
        if not _is_serialisable(masked):
            # Numbers CPython accepts but JSON cannot round-trip (1e400 becomes inf). Recorded
            # as the masked document's text, rather than lost or written unmasked.
            unrepresentable = ParseResult(ok=False, error_reason="unrepresentable")
            return self._unrepresentable_payload(text, masked, paths), unrepresentable

        return (
            Payload(
                encoding=Encoding.JSON,
                data=masked,
                redactions=tuple(paths[:MAX_RECORDED_REDACTIONS]),
                redaction_count=len(paths),
            ),
            self._masked_parse(parse, document),
        )

    def _masked_parse(self, parse: ParseResult, document: Any) -> ParseResult:
        """``parse`` with the two fields that come off the wire, ``id`` and ``method``, masked
        as the payload is. Masked as the server wrote them and clipped after, so that a literal
        cut by the clip does not leave its head behind. The other fields (``ok``, ``kind``,
        ``is_error``, ``error_reason``) are ours and stay."""
        if not isinstance(document, dict):
            return parse
        method = parse.method
        if method is not None:
            method = self._repeated_text(document["method"])[: events.MAX_METHOD_LENGTH]
        identifier = parse.id
        if identifier is not None:
            identifier = self._mask_id(document["id"])
            if isinstance(identifier, str):
                identifier = identifier[: events.MAX_ID_LENGTH]
        return dataclasses.replace(parse, method=method, id=identifier)

    def _mask_id(self, value: Any) -> Any:
        """A JSON-RPC id as the masker would leave it in the payload: a string as text, a
        number as the placeholder when its digits hold a literal. Not counted: the payload of the
        message that holds the id has counted it."""
        with self._masker.uncounted():
            if isinstance(value, str):
                return self._masker.mask_text(value)[0]
            masked, _ = self._masker.mask_json(value)
            return masked

    def _rejected_payload(self, text: str) -> Payload:
        """A message rejected as written but JSON all the same, masked as its document: with
        every value it gave a repeated key, so that none escapes the masking. Too deep, only
        the note; otherwise as :meth:`_unrepresentable_payload` writes it."""
        try:
            document = json.loads(text, object_pairs_hook=_every_value)
        except ValueError:
            return self._text_payload(text)  # the replaced bytes broke it: not JSON after all
        except RecursionError:
            return self._note()
        masking = self._mask(document)
        if masking is None:
            return self._note(self._secret_keys(document))
        masked, paths = masking
        return self._unrepresentable_payload(text, masked, paths)

    def _text_payload(self, text: str) -> Payload:
        masked, hits = self._masker.mask_text(text)
        return Payload(encoding=Encoding.TEXT, data=masked, redactions=(), redaction_count=hits)

    def _emit(self, seq: int, t_ns: int, body: EventBody) -> None:
        if self._closed:
            raise RuntimeError("recorder is closed")
        record = {
            "v": events.SCHEMA_VERSION,
            "run_id": self._run_id,
            "seq": seq,
            "t_ns": t_ns,
            "type": body.TYPE.value,
            **body.to_dict(),
        }
        # ensure_ascii stays on. The payload field carries hostile content, and
        # zero-width characters, bidi controls, tag characters and homoglyphs are exactly
        # what a later phase is meant to find: escaped, they stay visible instead of
        # disappearing into the rendering. Raw umlauts are no loss, because this file is
        # not a reading medium.
        self._stream.write(json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n")
        self._stream.flush()

        # Display happens after the event is safely on disk, and on this thread: a slow or
        # blocked terminal then costs observation, never the connection. Its failure is
        # suppressed because there is nowhere left to report a failure to report.
        if self._on_event is not None:
            with contextlib.suppress(Exception):
                self._on_event(seq, body)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stream.close()

    def __enter__(self) -> Recorder:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _place(steps: Sequence[Any], value: Any) -> Any:
    """Build the smallest document that holds ``value`` at the path ``steps``.

    Every list is one element long. The masker's decisions depend on key names and on the
    full spelling of a handle path, and no handle path has a list position in it, so the
    position changes nothing about what gets masked — while padding a list up to position
    40 000 would cost exactly what a hostile ``tools/list`` wants it to.
    """
    for step in reversed(steps):
        value = [value] if isinstance(step, Index) else {step.name: value}
    return value


def _take(steps: Sequence[Any], document: Any) -> Any:
    """The value back out of a masked skeleton — or the placeholder that replaced an ancestor."""
    for step in steps:
        if isinstance(step, Index):
            if not isinstance(document, list):
                return document
            document = document[0]
        else:
            if not isinstance(document, dict) or len(document) != 1:
                return document
            # The skeleton's one key, under whatever name the masker gave it: a key is masked
            # like a value, and its raw name may no longer be there.
            (document,) = document.values()
    return document


def _skeleton_names(steps: Sequence[Any], document: Any) -> list[str | None]:
    """Each key of the path as the masked skeleton spells it (a key is masked like a value), or
    None for a list position, and for every step below a point where the skeleton stops (an
    ancestor's key masked the whole subtree)."""
    names: list[str | None] = []
    for step in steps:
        if isinstance(step, Index):
            names.append(None)
            document = document[0] if isinstance(document, list) and document else None
        elif isinstance(document, dict) and len(document) == 1:
            ((name, document),) = document.items()
            names.append(name)
        else:
            names.extend([None] * (len(steps) - len(names)))
            break
    return names


def _respell(found: str, steps: Sequence[Any], names: Sequence[str | None]) -> str:
    """Turn a path in the skeleton back into the path in the real message: the real list
    positions, the keys as the skeleton spells them (masked where they were masked)."""
    skeleton = real = ""
    for step, name in zip(steps, names, strict=True):
        if isinstance(step, Index):
            skeleton, real = f"{skeleton}[0]", f"{real}[{step.position}]"
        elif name is None:
            return found  # below where the skeleton stops: no path of it reaches here
        else:
            skeleton = f"{skeleton}.{name}" if skeleton else name
            real = f"{real}.{name}" if real else name
        if found == skeleton:
            return real
    if found.startswith(skeleton):
        return real + found[len(skeleton) :]
    return found


def _credential_redactions(payload: Payload) -> int:
    """Redactions in this payload that were not protocol-handle pseudonyms.

    Exact rather than heuristic: :data:`~mcp_kymograph.masking.PROTOCOL_HANDLE_PATHS` is a
    closed set of full paths, so a path is a handle or it is not. A text payload reports no
    paths at all, only a count, and every hit there came from a shape-based rule — none of
    which is a handle.
    """
    if not payload.redactions:
        return payload.redaction_count
    handles = sum(1 for path in payload.redactions if path in PROTOCOL_HANDLE_PATHS)
    return payload.redaction_count - handles


def endpoint_refusal(url: str) -> str | None:
    """Why :meth:`Recorder.run_started` would not take an endpoint apart, or None. For whoever
    must refuse the URL before a run starts: refused there, it would refuse ``run_started``."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as unparsed:
        return str(unparsed)  # what _endpoint said before the rule moved here
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return "an endpoint is an http:// or https:// URL with a host"
    if _holds_at(parts.path):
        return "an endpoint whose path holds an @ is not taken apart"
    return None


def _holds_at(path: str) -> bool:
    """Whether a URL path holds an ``@`` as sent or in one of its percent-decodings (as many as
    ``masking.MAX_DECODINGS``), or still decodes after the last of them: user information may
    stand there, wherever a reader takes the authority to end."""
    form = path
    for _ in range(MAX_DECODINGS + 1):
        if "@" in form:
            return True
        decoded = urllib.parse.unquote(form)
        if decoded == form:
            return False
        form = decoded
    return True


def _capped_value(value: Any) -> Any:
    """A masked query value, capped: strings to :data:`MAX_HTTP_QUERY_TEXT`, lists element by
    element (a field sent more than once maps to a list)."""
    if isinstance(value, str):
        return value[:MAX_HTTP_QUERY_TEXT]
    if isinstance(value, list):
        return [_capped_value(item) for item in value[:MAX_HTTP_QUERY_FIELDS]]
    return value


def _ordinal(session: int | None) -> int | None:
    """A session is recorded as its ordinal. Anything else — a string most of all — is the
    caller handing over a session id, which is refused rather than written."""
    if session is None:
        return None
    if isinstance(session, bool) or not isinstance(session, int):
        raise ValueError("a session is recorded by its ordinal, never by its id")
    return session


def _tls(tls: Mapping[str, Any] | None) -> dict[str, str] | None:
    """An exchange's TLS as recorded, or None over plain HTTP. Ours, so refused rather than
    repaired: exactly :data:`TLS_KEYS`, a version as ``ssl`` names one, a SHA-256 in lower-case
    hex."""
    if tls is None:
        return None
    if not isinstance(tls, Mapping) or set(tls) != TLS_KEYS:
        raise ValueError(f"tls is {sorted(TLS_KEYS)} and nothing else")
    version, digest = tls["version"], tls["certificate_sha256"]
    if not isinstance(version, str) or not _TLS_VERSION.fullmatch(version):
        raise ValueError("tls.version is the protocol version ssl names, such as TLSv1.3")
    if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
        raise ValueError("tls.certificate_sha256 is 64 lower-case hex digits")
    return {"version": version, "certificate_sha256": digest}


def _trust_store_env(env: Mapping[str, bool] | None) -> dict[str, bool] | None:
    """Whether each of :data:`TRUST_STORE_VARIABLES` was set, or None. Two booleans and
    nothing else: a value here would be a path on this machine."""
    if env is None:
        return None
    if not isinstance(env, Mapping) or set(env) != set(TRUST_STORE_VARIABLES):
        raise ValueError(f"trust_store_env is {list(TRUST_STORE_VARIABLES)} and nothing else")
    if not all(isinstance(env[name], bool) for name in TRUST_STORE_VARIABLES):
        raise ValueError("trust_store_env says whether each variable was set, as a boolean")
    return {name: env[name] for name in TRUST_STORE_VARIABLES}


def _clip_method(method: str | None) -> str | None:
    """A method name that reached us through correlation is still a string from the wire."""
    return None if method is None else method[: events.MAX_METHOD_LENGTH]


#: Why a message was rejected that ``json.loads`` still reads: a constant JSON has not
#: (``NaN``), a key given twice, bytes that are not UTF-8 (read with replacement characters).
#: Such a message is masked as its document, never by shape alone.
_PARSED_TO_MASK = frozenset({"non_json_constant", "duplicate_keys", "not_utf8"})


def _every_value(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """An object with each repeated key's values gathered into one list under it, in order:
    ``json.loads`` would keep only the last, and the masking would never see the others."""
    document: dict[str, Any] = {}
    repeated: set[str] = set()
    for key, value in pairs:
        if key in repeated:
            document[key].append(value)
        elif key in document:
            document[key] = [document[key], value]
            repeated.add(key)
        else:
            document[key] = value
    return document


def _is_serialisable(value: Any) -> bool:
    try:
        json.dumps(value, ensure_ascii=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        return False
    return True
