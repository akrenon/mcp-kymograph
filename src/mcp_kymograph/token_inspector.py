"""Token inspector: what of a bearer token may enter a recording.

A pure function reads a bearer token and returns a :class:`TokenView`. Readable stay ``aud``,
``scp``/``roles``, ``azp``/``appid`` and ``exp``. Person and tenant identifiers leave only as a
pseudonym made by a function the caller hands in. No byte of the token itself, and none of its
signature, is ever in the result. A token that is not a readable JWT yields a view with
``readable=False`` and a reason, never an exception.

The signature is neither decoded nor checked: the result says nothing about authenticity.
Where the view is stored and where the salt comes from are decided elsewhere.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType

Pseudonymize = Callable[[str, str], str]  # (kind, value) -> pseudonym
MaskText = Callable[[str], str]  # a readable claim value -> the same text, masked

KNOWN_REASONS = (
    "too_long",
    "not_jwt",
    "encrypted",
    "bad_encoding",
    "bad_json",
    "not_object",
    "inspection_failed",
)
KNOWN_WARNINGS = ("aud_is_graph", "truncated")
PSEUDONYM_KINDS = ("tenant", "issuer", "object", "email", "account", "name")

MAX_TOKEN_BYTES = 16 * 1024
MAX_STRING = 256
MAX_LIST = 64
MAX_INT_DIGITS = 20  # longer integers make the payload ``bad_json`` before any conversion
MAX_FLOAT_CHARS = 32
MAX_EXP = 2**63 - 1

# Microsoft Graph as an audience, lower case; a trailing "/" is ignored when comparing.
GRAPH_AUDIENCES = frozenset(
    {
        "00000003-0000-0000-c000-000000000000",
        "https://graph.microsoft.com",
        "https://graph.microsoft.us",
        "https://dod-graph.microsoft.us",
        "https://microsoftgraph.chinacloudapi.cn",
    }
)

_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX = frozenset("0123456789abcdef")
_ENTRA_ISSUERS = (
    ("https://login.microsoftonline.com/", "/v2.0"),
    ("https://sts.windows.net/", "/"),
)
_STRING_CLAIMS = ("scp", "azp", "appid")
_PSEUDONYM_CLAIMS = ("tid", "iss", "oid", "upn", "email", "name")
_KNOWN_CLAIMS = frozenset(("aud", "roles", "exp", *_STRING_CLAIMS, *_PSEUDONYM_CLAIMS))
_EMPTY: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True)
class TokenView:
    readable: bool
    reason: str | None = None
    claims: Mapping[str, object] = field(default_factory=lambda: _EMPTY)
    pseudonyms: Mapping[str, str] = field(default_factory=lambda: _EMPTY)  # type: ignore[arg-type]
    unexpected: tuple[str, ...] = ()
    other_claims: int = 0
    warnings: tuple[str, ...] = ()
    masked: bool = False  # made with a mask; the recorder takes no view without one

    def expired(self, now: datetime) -> bool | None:
        """True if ``exp`` lies before ``now``; None without a readable ``exp``."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        exp = self.claims.get("exp")
        if not isinstance(exp, int):
            return None
        return exp < now.timestamp()

    def to_json(self) -> dict:
        claims = {
            name: list(value) if isinstance(value, tuple) else value
            for name, value in sorted(self.claims.items())
        }
        return {
            "claims": claims,
            "other_claims": self.other_claims,
            "pseudonyms": dict(sorted(self.pseudonyms.items())),
            "readable": self.readable,
            "reason": self.reason,
            "unexpected": list(self.unexpected),
            "warnings": list(self.warnings),
        }


def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise ValueError("integer too long")
    return int(text)


def _parse_float(text: str) -> float:
    if len(text) > MAX_FLOAT_CHARS:
        raise ValueError("number too long")
    return float(text)


def _reject_constant(text: str) -> float:
    raise ValueError("NaN and Infinity are not accepted")


def _decode_object(part: str) -> dict | str:
    """The JSON object in a Base64url part, or the reason it is not one."""
    if len(part) % 4 == 1:
        return "bad_encoding"
    try:
        text = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return "bad_encoding"
    try:
        value = json.loads(
            text,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        return "bad_json"
    if not isinstance(value, dict):
        return "not_object"
    return value


def _is_guid(text: str) -> bool:
    if len(text) != 36:
        return False
    return all(c == "-" if i in (8, 13, 18, 23) else c in _HEX for i, c in enumerate(text.lower()))


def _entra_issuer(iss: str) -> tuple[str, str, str] | None:
    """(prefix, guid, suffix) of an Entra issuer URL, else None."""
    for prefix, suffix in _ENTRA_ISSUERS:
        if iss.startswith(prefix) and iss.endswith(suffix):
            guid = iss[len(prefix) : len(iss) - len(suffix)]
            if _is_guid(guid):
                return prefix, guid.lower(), suffix
    return None


def _is_email(value: str) -> bool:
    local, at, domain = value.partition("@")
    return bool(at) and bool(local) and bool(domain) and "@" not in domain


def _is_graph(audience: str) -> bool:
    lowered = audience.lower()
    if lowered.endswith("/"):
        lowered = lowered[:-1]
    return lowered in GRAPH_AUDIENCES


def _is_text(value: object) -> bool:
    """A string that can be encoded; one with a lone surrogate counts as the wrong type."""
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(_is_text(item) for item in value)


def inspect(token: str, pseudonymize: Pseudonymize, mask: MaskText | None = None) -> TokenView:
    """Read ``token`` (the bare value, without ``Bearer ``) into a :class:`TokenView`.

    ``mask``, if given, is applied to every readable claim value in full length and only then is
    the value clipped, so a cut never leaves the head of a value the mask would have caught.
    ``truncated`` is warned when a value was longer than the limit before or after masking.
    ``masked`` is set only when a mask was given; it is not part of :meth:`TokenView.to_json`.

    Never raises: anything from ``pseudonymize``, from ``mask`` or from the reading itself, down
    to ``BaseException``, gives ``inspection_failed``, and nothing from it enters the result.
    The exceptions ``KeyboardInterrupt``, ``MemoryError`` and ``SystemExit`` are passed on as a
    fresh instance of the built-in class, without arguments, raised ``from None``: never the
    subclass, no cause, no context, and no code of the original is called. A ``SystemExit``
    keeps its code if that is an ``int`` (read guarded), otherwise the code is ``1``.
    """
    kind = ""
    exit_code = 1
    try:
        return _inspect(token, pseudonymize, mask)
    except (KeyboardInterrupt, MemoryError, SystemExit) as exc:
        exc_type = type(exc)
        if issubclass(exc_type, SystemExit):
            kind = "exit"
            try:
                raw = exc.code
                if issubclass(type(raw), int):
                    exit_code = int.__int__(raw)
            except BaseException:
                exit_code = 1
        elif issubclass(exc_type, KeyboardInterrupt):
            kind = "interrupt"
        else:
            kind = "memory"
    except BaseException:
        # the exception may hold plaintext: it is dropped, neither chained nor logged
        return TokenView(readable=False, reason="inspection_failed", masked=mask is not None)
    # raised outside the handler, so that the original is not even the implicit context
    if kind == "exit":
        raise SystemExit(exit_code) from None
    if kind == "interrupt":
        raise KeyboardInterrupt() from None
    raise MemoryError() from None


def _inspect(token: str, pseudonymize: Pseudonymize, mask: MaskText | None) -> TokenView:
    masked = mask is not None

    def unreadable(reason: str) -> TokenView:
        return TokenView(readable=False, reason=reason, masked=masked)

    if not isinstance(token, str):
        return unreadable("not_jwt")
    if len(token) > MAX_TOKEN_BYTES or len(token.encode("utf-8", "replace")) > MAX_TOKEN_BYTES:
        return unreadable("too_long")
    parts = token.split(".")
    if len(parts) == 5:
        return unreadable("encrypted")
    if len(parts) != 3 or not all(_B64URL.issuperset(part) for part in parts):
        return unreadable("not_jwt")
    # The signature (parts[2]) may be empty (``alg: none``); it is never decoded or looked at.
    # An empty header or payload is decoded like any other part and ends as ``bad_json``.
    header = _decode_object(parts[0])
    if isinstance(header, str):
        return unreadable(header)
    payload = _decode_object(parts[1])
    if isinstance(payload, str):
        return unreadable(payload)

    claims: dict[str, object] = {}
    pseudonyms: dict[str, str] = {}
    unexpected: set[str] = set()
    warnings: set[str] = set()

    def clip(text: str) -> str:
        longer = len(text) > MAX_STRING
        if mask is not None:
            text = mask(text)
        if longer or len(text) > MAX_STRING:
            warnings.add("truncated")
        return text[:MAX_STRING]

    def clip_list(items: list) -> tuple[str, ...]:
        if len(items) > MAX_LIST:
            warnings.add("truncated")
            items = items[:MAX_LIST]
        return tuple(clip(item) for item in items)

    if "aud" in payload:
        aud = payload["aud"]
        if _is_text(aud):
            claims["aud"] = clip(aud)
            if _is_graph(aud):
                warnings.add("aud_is_graph")
        elif _is_str_list(aud):
            claims["aud"] = clip_list(aud)
            if any(_is_graph(item) for item in aud):
                warnings.add("aud_is_graph")
        else:
            unexpected.add("aud")
    if "roles" in payload:
        if _is_str_list(payload["roles"]):
            claims["roles"] = clip_list(payload["roles"])
        else:
            unexpected.add("roles")
    for name in _STRING_CLAIMS:
        if name in payload:
            if _is_text(payload[name]):
                claims[name] = clip(payload[name])
            else:
                unexpected.add(name)
    if "exp" in payload:
        exp = payload["exp"]
        is_number = isinstance(exp, (int, float)) and not isinstance(exp, bool)
        if is_number and math.isfinite(exp) and 0 <= exp <= MAX_EXP:
            claims["exp"] = math.floor(exp)
        else:
            unexpected.add("exp")

    for name in _PSEUDONYM_CLAIMS:
        if name not in payload:
            continue
        value = payload[name]
        if not _is_text(value):
            unexpected.add(name)
        elif name == "tid":
            tid = value.lower() if _is_guid(value) else value
            pseudonyms[name] = pseudonymize("tenant", tid)
        elif name == "iss":
            entra = _entra_issuer(value)
            if entra is None:
                pseudonyms[name] = pseudonymize("issuer", value)
            else:
                prefix, guid, suffix = entra
                pseudonyms[name] = prefix + pseudonymize("tenant", guid) + suffix
        elif name == "upn":
            pseudonyms[name] = pseudonymize("email" if _is_email(value) else "account", value)
        elif name == "oid":
            pseudonyms[name] = pseudonymize("object", value)
        else:
            pseudonyms[name] = pseudonymize(name, value)  # "email" and "name" are kinds too

    return TokenView(
        readable=True,
        reason=None,
        claims=MappingProxyType(claims),
        pseudonyms=MappingProxyType(pseudonyms),
        unexpected=tuple(sorted(unexpected)),
        other_claims=sum(1 for name in payload if name not in _KNOWN_CLAIMS),
        warnings=tuple(sorted(warnings)),
        masked=masked,
    )
