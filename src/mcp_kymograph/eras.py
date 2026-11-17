"""Which protocol era and version an MCP server speaks.

The driver calls this module to talk to a server of either era. It holds the decisions as pure
functions and a small state machine with no I/O: it says what to send, and reads what came
back. Whoever drives the conversation sends, waits, matches the answer to the request by its
id, and feeds it in; an answer that comes after its wait is the caller's to read past.

The two eras (MCP 2026-07-28, "Versioning and Compatibility"):

* **legacy** (2024-11-05 to 2025-11-25): a session opens with ``initialize``. The client names
  a version; the server answers with that version if it supports it, otherwise with one it
  does, and the client goes on with it if it knows it.
* **modern** (2026-07-28): no handshake. Every request carries version and client
  capabilities in ``params._meta``; ``server/discover`` says which versions a server supports.

Over stdio a client that speaks both sends ``server/discover`` first (2026-07-28, stdio,
"Backward Compatibility"): a ``DiscoverResult`` or a recognized modern error means modern; any
other error, or no answer in time, means legacy, and ``initialize`` follows. Over HTTP the same,
with the body of a 400 as the one error status that is read (2026-07-28, versioning); any other
status, or a body that is no JSON-RPC answer, is :data:`NOT_JSON_RPC` and means legacy.

**What this module decides, and why.**

* *A modern error is recognized by its shape, not by its code alone.* JSON-RPC leaves −32000
  to −32099 to implementations, and servers written before 2026-07-28 use them freely. So
  ``UnsupportedProtocolVersion`` (−32022) counts only with ``data.supported`` as a list, and
  ``MissingRequiredClientCapability`` (−32021) only with ``data.requiredCapabilities`` as an
  object, as the schema has them. Anything not recognized falls back to legacy: wrongly taken
  for legacy, a modern server costs one more exchange and refuses ``initialize``; wrongly taken
  for modern, a legacy server would never be asked at all.
* *``HeaderMismatch`` (−32020) is the one exception, decided, not derived.* It counts as a
  sign of the modern era by its code alone — the schema gives it no data to check — and a
  probe answered with it ends with ``stop``, ``modern_refused``, without an ``initialize``.
  That knowingly takes the costlier mistake for this one code: a legacy server that uses
  −32020 for something of its own is taken for modern and never asked.
* *A header error over a transport without headers is written down, not judged.* −32020 is
  about HTTP headers; over stdio, which has none, whenever an error answer carries it — to the
  probe or to an ``initialize`` — the detection keeps the observation
  :data:`HEADER_ERROR_WITHOUT_HEADERS` (``Detection.observations``). What it means, if
  anything, is for whoever reads the recording. Over HTTP (``transport=TRANSPORT_HTTP``) the
  code is about headers that were there, and the observation is not made.
* *The versions it knows are those of the specification.* :data:`LEGACY_VERSIONS` lists every
  handshake revision; the discovery listings the driver asks for read the same in all of them.
  The handshake asks first for the version the detector was given (``request_version``:
  :data:`LEGACY_REQUEST_VERSION` unless the driver is under an engagement, which asks for
  :data:`NEWEST_LEGACY_VERSION`), wherever a choice is made — first, and on a server of both
  eras if it is offered — and otherwise for the newest one offered that this module knows.
* *A version it does not know is not spoken.* A legacy server that answers ``initialize`` with
  a version outside :data:`LEGACY_VERSIONS` — a later one, a modern one, or text that is no
  version at all — ends the detection with ``stop``. The legacy specification has a client
  that does not support the server's version disconnect; reading a listing in a revision this
  tool has never seen would record it under rules it does not know. The version the server
  named is kept, whole, as data.
* *A server that refuses our version but names others is asked once more.* Some servers answer
  an ``initialize`` whose version they do not support with an error listing the ones they do,
  instead of answering with one of them. If that list holds a version this module knows, the
  ``initialize`` is sent once more; a second refusal stops.
* *A modern server is spoken to in a version both know.* :data:`MODERN_VERSION` if its
  ``DiscoverResult`` lists it; otherwise, if it lists a legacy version this module knows (a
  server serving both eras), ``initialize`` with it; otherwise ``stop``,
  ``no_common_version``. A capability it requires stops with ``modern_refused``: the driver
  declares none, and has none to offer. So does a probe refused with ``HeaderMismatch``.
* *A server that closes on the probe is legacy, and not started again here.* That is a matter
  for whoever runs the process. The detection ends with ``stop``, ``closed_on_probe``, era
  legacy; a new process can be asked without the probe (``Detector.start(probe=False)``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

# -- the versions ---------------------------------------------------------------------------

#: The handshake-based revisions this module knows, oldest first.
LEGACY_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
#: The per-request revisions this module knows, oldest first.
MODERN_VERSIONS = ("2026-07-28",)
#: The version announced in the probe and in every request to a modern server.
MODERN_VERSION = MODERN_VERSIONS[-1]
#: The version the legacy handshake asks for where it has a choice: the driver's.
LEGACY_REQUEST_VERSION = "2025-06-18"
#: What it asks for under an engagement: the newest legacy version this module knows.
NEWEST_LEGACY_VERSION = LEGACY_VERSIONS[-1]

#: Over which transport a detection runs. Only over stdio is a header error noted as one made
#: where there are no headers.
TRANSPORT_STDIO = "stdio"
TRANSPORT_HTTP = "http"

#: What a protocol version looks like: ASCII digits only. Anything else is not a version.
_VERSION_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
#: A version a server sent is data from the traffic. This module keeps all of its text; a sink
#: shows only this much of it, and cuts after masking.
MAX_VERSION_LENGTH = 40
#: And only this many of a list of them, taken from its start before anything is filtered.
MAX_VERSIONS = 20
#: A JSON-RPC error code is a 32-bit integer; anything outside is no code.
_CODE_RANGE = range(-(2**31), 2**31)

ERA_LEGACY = "legacy"
ERA_MODERN = "modern"

# -- the wire -------------------------------------------------------------------------------

PROBE_METHOD = "server/discover"
INITIALIZE_METHOD = "initialize"
INITIALIZED_NOTIFICATION = "notifications/initialized"

HEADER_MISMATCH = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022

META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# -- what an answer was ---------------------------------------------------------------------

#: The probe came back as a ``DiscoverResult``.
DISCOVERED = "discover_result"
#: The probe came back as a recognized modern error.
MODERN_ERROR = "modern_error"
#: Any other error.
OTHER_ERROR = "other_error"
#: Any other answer with a result: a result that is no ``DiscoverResult``, or the ``initialize``
#: result.
OTHER_RESULT = "other_result"
#: An answer with neither an error nor an object as its result.
NO_RESULT = "no_result"
#: Nothing came back in time. Fed in by the caller, who keeps the time.
NO_ANSWER = "no_answer"
#: The server's side closed before an answer came. Fed in by the caller.
CLOSED = "connection_closed"
#: Over HTTP: the probe was answered, but not with a JSON-RPC message — another status than 400,
#: an empty body, a body that is no JSON. Fed in by the caller. Legacy.
NOT_JSON_RPC = "not_json_rpc"

# -- what the detection ended with ----------------------------------------------------------

PROCEED = "proceed"
STOP = "stop"

#: Why a detection stopped.
CLOSED_ON_PROBE = "closed_on_probe"
NO_COMMON_VERSION = "no_common_version"
MODERN_REFUSED = "modern_refused"
UNKNOWN_VERSION = "unknown_version"
MALFORMED_VERSION = "malformed_version"
HANDSHAKE_REFUSED = "handshake_refused"
HANDSHAKE_UNANSWERED = "handshake_unanswered"
HANDSHAKE_CLOSED = "handshake_closed"

#: Every reason a detection may stop with. The report names each stop reason from a fixed list
#: (``report.ERA_STOP_REASONS``, the same reasons); a :class:`Detection` that stops with a
#: reason this set does not hold is refused where it is made (:meth:`Detection.__post_init__`).
STOP_REASONS = frozenset(
    {
        CLOSED_ON_PROBE,
        NO_COMMON_VERSION,
        MODERN_REFUSED,
        UNKNOWN_VERSION,
        MALFORMED_VERSION,
        HANDSHAKE_REFUSED,
        HANDSHAKE_UNANSWERED,
        HANDSHAKE_CLOSED,
        NO_RESULT,
    }
)

# -- what the detection saw along the way ---------------------------------------------------

#: An answer carried ``HeaderMismatch`` (−32020), an error about HTTP headers, over stdio,
#: which has no headers. An observation, not a finding.
HEADER_ERROR_WITHOUT_HEADERS = "header_error_without_headers"


def meta(client_info: Mapping[str, Any], capabilities: Mapping[str, Any]) -> dict[str, Any]:
    """What a modern request carries in ``params._meta`` in place of a handshake."""
    return {
        META_VERSION: MODERN_VERSION,
        META_CLIENT_INFO: dict(client_info),
        META_CLIENT_CAPABILITIES: dict(capabilities),
    }


def probe_request(
    identifier: int, client_info: Mapping[str, Any], capabilities: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": PROBE_METHOD,
        "params": {"_meta": meta(client_info, capabilities)},
    }


def initialize_request(
    identifier: int,
    version: str,
    client_info: Mapping[str, Any],
    capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": INITIALIZE_METHOD,
        "params": {
            "protocolVersion": version,
            "capabilities": dict(capabilities),
            "clientInfo": dict(client_info),
        },
    }


def initialized_notification() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": INITIALIZED_NOTIFICATION}


# -- reading one answer ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProbeReading:
    """What the answer to the probe says: the era, what kind of answer it was, the error code,
    and the versions the server named (from a ``DiscoverResult``, or from the ``supported``
    list of an ``UnsupportedProtocolVersion`` error)."""

    era: str
    outcome: str
    code: int | None = None
    supported: tuple[str, ...] = ()


def classify_probe(answer: Mapping[str, Any]) -> ProbeReading:
    """The era an answer to the probe shows.

    Modern for a ``DiscoverResult`` — a result naming ``supportedVersions`` as a list — for a
    modern error of the shape the schema gives it, and for ``HeaderMismatch`` (−32020) by its
    code alone. Legacy for anything else: the fallback
    "MUST NOT be keyed to one specific error code" (2026-07-28, stdio). Something that is no
    object at all is no result either.
    """
    if not isinstance(answer, Mapping):
        return ProbeReading(ERA_LEGACY, NO_RESULT)
    result = answer.get("result")
    if isinstance(result, dict) and isinstance(result.get("supportedVersions"), list):
        return ProbeReading(ERA_MODERN, DISCOVERED, None, _versions(result["supportedVersions"]))
    code = _error_code(answer)
    data = _error_data(answer)
    if code == UNSUPPORTED_PROTOCOL_VERSION and isinstance(data.get("supported"), list):
        return ProbeReading(ERA_MODERN, MODERN_ERROR, code, _versions(data["supported"]))
    if code == MISSING_REQUIRED_CLIENT_CAPABILITY and isinstance(
        data.get("requiredCapabilities"), dict
    ):
        return ProbeReading(ERA_MODERN, MODERN_ERROR, code)
    if code == HEADER_MISMATCH:
        return ProbeReading(ERA_MODERN, MODERN_ERROR, code)
    if "error" in answer:
        return ProbeReading(ERA_LEGACY, OTHER_ERROR, code)
    if isinstance(result, dict):
        return ProbeReading(ERA_LEGACY, OTHER_RESULT)
    return ProbeReading(ERA_LEGACY, NO_RESULT)


def is_known_legacy(version: Any) -> bool:
    return isinstance(version, str) and version in LEGACY_VERSIONS


def choose_legacy(offered: Iterable[str], preferred: str = LEGACY_REQUEST_VERSION) -> str | None:
    """The legacy version to ask for from those a server named: the preferred one if it is among
    them, otherwise the newest one this module knows, otherwise none."""
    offered = set(offered)
    if preferred in offered:
        return preferred
    for version in reversed(LEGACY_VERSIONS):
        if version in offered:
            return version
    return None


def _text(value: Any) -> str | None:
    """A version from the traffic, as text and whole: whoever records it masks it first and
    clips it after (:data:`MAX_VERSION_LENGTH`), since the masker needs all of a literal."""
    return value if isinstance(value, str) else None


def _versions(values: list[Any]) -> tuple[str, ...]:
    """At most :data:`MAX_VERSIONS` of them, the text as it came."""
    return tuple(v for v in values[:MAX_VERSIONS] if isinstance(v, str))


def _error_code(answer: Mapping[str, Any]) -> int | None:
    error = answer.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    if isinstance(code, int) and not isinstance(code, bool) and code in _CODE_RANGE:
        return code
    return None


def _error_data(answer: Mapping[str, Any]) -> dict[str, Any]:
    error = answer.get("error")
    data = error.get("data") if isinstance(error, dict) else None
    return data if isinstance(data, dict) else {}


def _error_of(answer: Mapping[str, Any]) -> dict[str, Any] | None:
    """The code and ``data`` of an error answer, as sent; None for an answer with no error."""
    if not isinstance(answer.get("error"), dict):
        return None
    data = answer["error"].get("data")
    return {"code": _error_code(answer), "data": dict(data) if isinstance(data, dict) else None}


def _same_id(received: Any, awaited: int | None) -> bool:
    """JSON-RPC ids compare by type and value: ``true`` and ``1.0`` are not ``1``."""
    return type(received) is int and received == awaited


def _object(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, dict) else None


def _offered(answer: Mapping[str, Any]) -> tuple[str, ...]:
    """The versions an error's ``data.supported`` lists — many legacy servers that refuse an
    ``initialize`` name them there."""
    supported = _error_data(answer).get("supported")
    return _versions(supported) if isinstance(supported, list) else ()


# -- the conversation -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Send:
    """The next message to send, and the id its answer will carry."""

    message: dict[str, Any]

    @property
    def identifier(self) -> int:
        return self.message["id"]


@dataclass(frozen=True, slots=True)
class Detection:
    """How the detection ended.

    ``action`` is ``proceed`` (speak ``version`` in ``era``; for legacy, send ``followup``
    first) or ``stop`` (with ``reason``). ``capabilities`` and ``server_info`` are what the
    server said about itself — from the ``DiscoverResult`` or the ``initialize`` answer — each
    an object or nothing, copied one level deep and otherwise unchecked: bounding and masking
    them is for whoever records them. ``exchanges`` lists what was asked and how it was
    answered, in order, for the recording: ``(method, outcome, error code)``. ``observations``
    lists what the detection noticed without judging it (:data:`HEADER_ERROR_WITHOUT_HEADERS`),
    each once, in the order first seen.
    """

    action: str
    era: str | None = None
    version: str | None = None
    reason: str | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    server_info: dict[str, Any] | None = None
    probe: ProbeReading | None = None
    exchanges: tuple[tuple[str, str, int | None], ...] = ()
    followup: tuple[dict[str, Any], ...] = ()
    observations: tuple[str, ...] = ()
    #: For a stop that came with an error answer, its ``code`` and ``data`` as the server sent
    #: them (``data`` an object or None), for whoever records it to mask and clip: the
    #: capabilities a refusal requires and the versions an ``UnsupportedProtocolVersion`` lists
    #: are in it.
    error: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """A stop carries one of :data:`STOP_REASONS`. The report names each stop reason from a
        fixed list; a reason the list does not know — a new stop path, a subclass's default, a
        ``dataclasses.replace`` — fails here, where it is made, rather than be shown later as a
        reason this version does not know. The reason is always one of this module's constants,
        never what a server sent, so the error may name it."""
        if self.action == STOP and self.reason not in STOP_REASONS:
            raise ValueError(
                f"a detection that stops needs a reason of STOP_REASONS: {self.reason!r}"
            )

    @property
    def known(self) -> bool:
        return self.version in LEGACY_VERSIONS + MODERN_VERSIONS


class Detector:
    """The era detection as a state machine: :meth:`start`, then :meth:`answer` with each answer
    (or :data:`NO_ANSWER`, :data:`CLOSED`) until it returns a :class:`Detection`.

    It sends at most three messages: the probe, an ``initialize``, and one more ``initialize``
    if the first was refused with versions offered. Ids are ``first_id``, ``first_id + 1``, ….
    ``request_version`` is the legacy version asked for where there is a choice, and
    ``transport`` is :data:`TRANSPORT_STDIO` or :data:`TRANSPORT_HTTP`.
    """

    def __init__(
        self,
        client_info: Mapping[str, Any],
        capabilities: Mapping[str, Any],
        *,
        first_id: int = 1,
        request_version: str = LEGACY_REQUEST_VERSION,
        transport: str = TRANSPORT_STDIO,
    ) -> None:
        if type(first_id) is not int:
            raise TypeError("first_id must be an int")
        if request_version not in LEGACY_VERSIONS:
            raise ValueError(f"not a legacy version this module knows: {request_version!r}")
        if transport not in (TRANSPORT_STDIO, TRANSPORT_HTTP):
            raise ValueError(f"unknown transport {transport!r}")
        self._request_version = request_version
        self._transport = transport
        self._error: dict[str, Any] | None = None
        self._client_info = dict(client_info)
        self._capabilities = dict(capabilities)
        self._next_id = first_id
        self._state = "new"
        self._awaiting: int | None = None
        self._probe: ProbeReading | None = None
        self._exchanges: list[tuple[str, str, int | None]] = []
        self._requested: str | None = None
        self._retried = False

    def start(self, *, probe: bool = True) -> Send:
        """The first message: the probe, or — for a server known to be legacy, such as one that
        closed on the probe before — the ``initialize`` straight away."""
        if self._state != "new":
            raise RuntimeError("the detection has started already")
        if not probe:
            return self._initialize(self._request_version)
        self._state = "probe"
        return self._send(probe_request(self._id(), self._client_info, self._capabilities))

    def answer(self, answer: Mapping[str, Any] | str) -> Send | Detection:
        """Feed the answer to the last message sent: the JSON-RPC response to it — no
        ``method``, and the id of the message sent, the same number of the same type — or
        :data:`NO_ANSWER` or :data:`CLOSED`. Anything else is the caller's mistake, and raises.

        A server may send requests of its own before the handshake is done (``ping``, say),
        and their ids may be any; answering them, or not, is the caller's business, not this
        detector's, and none of them is fed here."""
        if self._state not in ("probe", "initialize"):
            raise RuntimeError(f"no answer is awaited (state {self._state})")
        if isinstance(answer, str):
            if answer not in (NO_ANSWER, CLOSED, NOT_JSON_RPC):
                raise ValueError(f"not an answer: {answer!r}")
        elif not isinstance(answer, Mapping):
            raise ValueError(f"not an answer: {type(answer).__name__}")
        elif "method" in answer or not _same_id(answer.get("id"), self._awaiting):
            raise ValueError("not the response to the message sent: match it by its id first")
        if self._state == "probe":
            return self._after_probe(answer)
        return self._after_initialize(answer)

    # -- steps ------------------------------------------------------------------------------

    def _after_probe(self, answer: Mapping[str, Any] | str) -> Send | Detection:
        if answer == CLOSED:
            self._exchanges.append((PROBE_METHOD, CLOSED, None))
            self._probe = ProbeReading(ERA_LEGACY, CLOSED)
            return self._end(STOP, era=ERA_LEGACY, reason=CLOSED_ON_PROBE)
        if answer == NO_ANSWER:
            # No answer in time: a legacy server that does not answer what it does not know.
            self._exchanges.append((PROBE_METHOD, NO_ANSWER, None))
            self._probe = ProbeReading(ERA_LEGACY, NO_ANSWER)
            return self._initialize(self._request_version)
        if answer == NOT_JSON_RPC:
            # Answered, with nothing that is a JSON-RPC message: not a modern server.
            self._exchanges.append((PROBE_METHOD, NOT_JSON_RPC, None))
            self._probe = ProbeReading(ERA_LEGACY, NOT_JSON_RPC)
            return self._initialize(self._request_version)
        self._probe = reading = classify_probe(answer)
        self._exchanges.append((PROBE_METHOD, reading.outcome, reading.code))
        if reading.era == ERA_LEGACY:
            return self._initialize(self._request_version)
        if reading.code in (MISSING_REQUIRED_CLIENT_CAPABILITY, HEADER_MISMATCH):
            # Modern, and refused without a DiscoverResult: nothing to speak to it with.
            self._error = _error_of(answer)
            return self._end(STOP, era=ERA_MODERN, reason=MODERN_REFUSED)
        if reading.outcome == DISCOVERED and MODERN_VERSION in reading.supported:
            result = answer["result"]
            capabilities = result.get("capabilities")
            server_meta = result.get("_meta")
            return self._end(
                PROCEED,
                era=ERA_MODERN,
                version=MODERN_VERSION,
                capabilities=dict(capabilities) if isinstance(capabilities, dict) else {},
                server_info=_object(server_meta.get(META_SERVER_INFO))
                if isinstance(server_meta, dict)
                else None,
            )
        legacy = choose_legacy(reading.supported, self._request_version)
        if legacy is not None:
            # A server of both eras that does not serve our modern version: its legacy side.
            return self._initialize(legacy)
        self._error = _error_of(answer)
        return self._end(STOP, era=ERA_MODERN, reason=NO_COMMON_VERSION)

    def _after_initialize(self, answer: Mapping[str, Any] | str) -> Send | Detection:
        if answer in (NO_ANSWER, CLOSED):
            self._exchanges.append((INITIALIZE_METHOD, answer, None))
            reason = HANDSHAKE_CLOSED if answer == CLOSED else HANDSHAKE_UNANSWERED
            return self._end(STOP, era=ERA_LEGACY, reason=reason)
        result = answer.get("result")
        if not isinstance(result, dict):
            if "error" not in answer:
                self._exchanges.append((INITIALIZE_METHOD, NO_RESULT, None))
                return self._end(STOP, era=ERA_LEGACY, reason=NO_RESULT)
            code = _error_code(answer)
            self._exchanges.append((INITIALIZE_METHOD, OTHER_ERROR, code))
            offered = choose_legacy(_offered(answer), self._request_version)
            if not self._retried and offered is not None and offered != self._requested:
                self._retried = True
                return self._initialize(offered)
            return self._end(STOP, era=ERA_LEGACY, reason=HANDSHAKE_REFUSED)
        self._exchanges.append((INITIALIZE_METHOD, OTHER_RESULT, None))
        version = result.get("protocolVersion")
        capabilities = result.get("capabilities")
        found = {
            "capabilities": dict(capabilities) if isinstance(capabilities, dict) else {},
            "server_info": _object(result.get("serverInfo")),
        }
        if not isinstance(version, str) or not _VERSION_SHAPE.fullmatch(version):
            return self._end(
                STOP,
                era=ERA_LEGACY,
                version=_text(version),
                reason=MALFORMED_VERSION,
                **found,
            )
        if not is_known_legacy(version):
            return self._end(
                STOP, era=ERA_LEGACY, version=_text(version), reason=UNKNOWN_VERSION, **found
            )
        return self._end(
            PROCEED,
            era=ERA_LEGACY,
            version=version,
            followup=(initialized_notification(),),
            **found,
        )

    # -- helpers ----------------------------------------------------------------------------

    def _initialize(self, version: str) -> Send:
        self._state = "initialize"
        self._requested = version
        return self._send(
            initialize_request(self._id(), version, self._client_info, self._capabilities)
        )

    def _send(self, message: dict[str, Any]) -> Send:
        self._awaiting = message["id"]
        return Send(message)

    def _end(self, action: str, **found: Any) -> Detection:
        self._state = "done"
        self._awaiting = None
        # Every answer's error code is in the exchanges, the probe's and each initialize's.
        header_error = any(code == HEADER_MISMATCH for _, _, code in self._exchanges)
        noted = header_error and self._transport == TRANSPORT_STDIO
        return Detection(
            action=action,
            probe=self._probe,
            exchanges=tuple(self._exchanges),
            observations=(HEADER_ERROR_WITHOUT_HEADERS,) if noted else (),
            error=found.pop("error", self._error),
            **found,
        )

    def _id(self) -> int:
        identifier = self._next_id
        self._next_id += 1
        return identifier
