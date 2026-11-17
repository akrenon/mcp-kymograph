"""Credential masking.

Everything in this module is pure given its inputs: no I/O and no clock. The per-run state is
the salt a :class:`Masker` draws at construction to pseudonymise protocol handles (pass
``handle_salt`` to make that deterministic in a test) and the count of what it replaced. It runs
on the write path of the recorder, so a masked value is the only form a credential ever takes on
disk.

Four mechanisms are applied together:

* **protocol handles** — a small set of known *field paths* whose value exists only to tie
  two messages together. These are replaced by a stable pseudonym rather than blanked, so
  the correlation survives while the value does not. See :data:`PROTOCOL_HANDLE_PATHS`;
* **structural** — a JSON object key whose normalised name contains a known needle has its
  entire value replaced, whatever that value is;
* **textual** — patterns that identify a credential by its own shape, applied to every
  string that survives the structural pass, because secrets also travel inside prose. After
  them comes the rule for a ``name=value`` pair whose name says it is a secret
  (``api_key=…``, ``token = '…'``): the value goes, to the next ``&``, ``;`` or ``#`` outside
  quotes or to the end of the line (:meth:`Masker._mask_pairs`);
* **personal data** — three shapes that are unambiguous (an e-mail address, an IBAN with a
  valid check and its country's length, a ``tel:`` URI) and the engagement's known values,
  replaced by a pseudonym that is keyed with a salt (:meth:`Masker.personal_pseudonym`): the
  engagement's, so that it is the same in every run under it, or the run's own. They are
  applied wherever the run's literals are, in this order: literals, known values, the three
  shapes, the other text rules (:meth:`Masker._mask_shapes`). Never a pattern from the user, and
  never a shape that is not unambiguous: a phone number without ``tel:`` and a card number are
  known values or nothing. A pseudonym is not a credential's redaction and is not counted as
  one; :attr:`Masker.replacements` counts it.

Matching is deliberately greedy. Normalised substring matching means ``token`` also masks
``total_tokens``, and ``auth`` also masks ``author``. Losing a token count or an author
name from a recording is a nuisance; leaking a credential into one is not.

**Why handles need their own mechanism.** The structural pass keys on names, and a protocol
puts words like ``token``, ``key`` and ``session`` in field names that hold no secret at all.
``progressToken`` was the first such collision found, and it will not be the last. Blanking
those destroys exactly what this tool exists to show — which progress notification belongs to
which call — while passing them through in clear would hand back a value we cannot vouch for.
A pseudonym is neither: the recording keeps the *relationship* and never the value.

The handle set is anchored on **paths, not key names**, and it is closed: a field that is not
in it is masked by the ordinary rules. A name that merely looks like a handle somewhere else
in the document — ``params.arguments.progressToken``, sent by a caller — is payload, and gets
the blanking treatment like anything else.

Every rule here runs in time linear in the text — no nested quantifiers, and no pattern that
can start a long scan at every position — because the text being matched arrives from the
traffic under test and must not be able to trigger catastrophic backtracking. Where a regular
expression could not say a shape in linear time, a small scanner says it (:class:`_JwtShape`,
:func:`_personal_spans`).
"""

from __future__ import annotations

import bisect
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import unicodedata
import urllib.parse
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from typing import Any, Protocol, TypeVar

from mcp_kymograph.signals import (
    BIDI,
    JOINERS,
    NORMALIZED_GROWTH,
    NORMALIZED_SLACK,
    TAG_BLOCK,
    ZERO_WIDTH,
)
from mcp_kymograph.token_inspector import PSEUDONYM_KINDS as TOKEN_KINDS

#: What a masked value is replaced with. Constant on purpose: it reveals neither the
#: length nor the shape of what it replaced.
PLACEHOLDER = "***REDACTED***"

#: How a pseudonymised protocol handle appears. Flanked like PLACEHOLDER so it is obvious at
#: a glance that it is not a real value, and greppable as its own thing so a reader can tell
#: "the correlation is intact but the value is gone" from "this is gone".
HANDLE_PREFIX = "***HANDLE-"
HANDLE_SUFFIX = "***"

#: How many hex characters of the digest a pseudonym carries. 48 bits: far more than enough
#: to keep the handles of one session apart, far too few to be walked back to a value.
HANDLE_DIGEST_LENGTH = 12

#: Field paths whose value is a **protocol handle**: it exists only so that two messages can
#: be tied to each other, and it carries no meaning of its own.
#:
#: Anchored on the path from the root of the message, never on the key name alone — a name is
#: not evidence about what a value is, only its position in the protocol is. The set is
#: closed and fails closed: anything not listed here is masked by the ordinary rules.
#:
#: What is in it today, and why exactly this:
#:
#: * ``params.progressToken`` — the handle in a ``notifications/progress``. Its whole purpose
#:   is to say which request the progress belongs to. Blanked, a recording shows that progress
#:   was reported and never for what.
#: * ``params._meta.progressToken`` — the same handle in the other position it occupies, where
#:   a client declares it on the request that wants progress. Both ends of one correlation.
#:
#: What is deliberately **not** in it:
#:
#: * ``sessionId`` and anything like it. An MCP session identifier is not a mere handle: over
#:   a networked transport, holding it is what grants access to the session. It is closer to a
#:   bearer token than to a correlation id, and it stays blanked.
#: * ``id``, ``requestId``, ``cursor`` and the other correlation fields the protocol uses —
#:   they are not masked in the first place, because no needle matches their names. They need
#:   no exception; adding them would only create a way for one to start being pseudonymised
#:   if a needle were ever widened.
PROTOCOL_HANDLE_PATHS = frozenset(
    {
        "params.progressToken",
        "params._meta.progressToken",
    }
)

#: Recorded redaction paths are capped so a hostile message full of secret-looking keys
#: cannot inflate a single event without bound.
MAX_PATH_LENGTH = 200

#: The one HTTP header parsed before it is masked (docs/design/http-transport.md, 2.8). Its
#: name holds the needle ``auth``, so unparsed it would be blanked whole, and the text rule for
#: ``Bearer …`` would mangle its parameter list; parsed, where a server sends clients for a
#: token (``resource_metadata``, ``scope``, ``error``) stays legible. Anchored on the header's
#: name, compared without case, and closed: no other header is parsed, and one that does not
#: parse is blanked whole.
PARSED_HEADER = "www-authenticate"

#: The headers blanked whole whatever the needles are: what carries a client's credential or
#: its session. The needles blank them too; this set does not depend on the needles staying
#: what they are.
BLANKED_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "mcp-session-id"}
)

#: HTTP headers whose value is a protocol handle, pseudonymised like the handle paths above:
#: ``Last-Event-ID`` names the SSE event a resumed stream continues after (2.6), and its
#: pseudonym is the one the event's own id gets (:meth:`Masker.mask_event_id`). Closed, as the
#: handle paths are. Not an exception to the masking but a stricter form of it: the value is
#: never kept, only its relation to the event. ``Mcp-Session-Id`` is deliberately not here: it
#: grants access to the session and stays blanked.
HEADER_HANDLES = frozenset({"last-event-id"})

#: Authentication schemes kept by name in a parsed ``WWW-Authenticate`` (the IANA registry, and
#: NTLM). Closed: any other word in a scheme's place is blanked — the parser cannot tell a
#: scheme it does not know from a credential standing where a scheme would.
KNOWN_SCHEMES = frozenset(
    {"basic", "bearer", "concealed", "digest", "dpop", "gnap", "hoba", "mutual", "negotiate",
     "ntlm", "oauth", "privatetoken", "scram-sha-1", "scram-sha-256", "vapid"}
)  # fmt: skip

#: Challenge parameters kept by name, their values masked by the ordinary rules (RFC 6750,
#: RFC 7616, RFC 9449, RFC 9728). Closed: any other parameter keeps neither its name nor its
#: value — the name becomes a pseudonym, the value is blanked.
#: The ordinary rules see a value's shape, not its randomness: ``realm="<random word>"`` is kept
#: as it is. And a server that writes a URL or a scope unquoted (``scope=files:read``), against
#: RFC 9110, has its whole header blanked — the parser does not guess.
KNOWN_CHALLENGE_PARAMS = frozenset(
    {"realm", "charset", "scope", "error", "error_description", "error_uri",
     "resource_metadata", "algs", "algorithm", "qop", "stale", "domain", "userhash"}
)  # fmt: skip

#: Query names that name a credential, in normalised form. Kept as names, and their values
#: blanked whatever the needles are — some hold no needle at all (``code``, the OAuth
#: authorization code; ``sig`` and ``X-Amz-Signature``, a signed URL's signature). A query name
#: holding a needle that is not one of these — ``token_<something>`` — is not kept: whatever
#: follows the needle may be the credential itself.
COMMON_SECRET_NAMES = frozenset(
    {"accesstoken", "refreshtoken", "idtoken", "token", "apikey", "clientsecret", "secret",
     "password", "sessionid", "auth", "authorization", "credential", "credentials", "cookie",
     "bearer", "code", "key", "sig", "signature", "pwd", "otp", "xamzsignature",
     "xamzcredential", "xamzsecuritytoken", "xgoogsignature", "xgoogcredential"}
)  # fmt: skip

#: Bounds on what one header or query is split into; past them it is blanked whole.
MAX_CHALLENGES = 64
MAX_QUERY_FIELDS = 256

#: How often a value from HTTP is percent-decoded at most before it is matched: what a server
#: that decodes twice reads, the masking reads too, and one round more.
MAX_DECODINGS = 3

#: What a name — a header's, a query field's, one inside a URL — may look like and still be
#: kept as written (:func:`_plain_name`). Counted per run of letters and digits: its length,
#: its digits, and how often it changes between lower case, upper case and digits (a capital
#: starting a word, ``Id`` in ``requestId``, is not a change). ``includeDeletedItems`` and
#: ``X-B3-TraceId`` pass; a random token, a hex key or a long number does not.
MAX_NAME_RUN = 24
MAX_NAME_DIGITS = 4
MAX_NAME_CHANGES = 4
#: Longer names are not kept: a header's, and a name inside a URL in a value.
MAX_NAME_LENGTH = 64

#: Needles are matched as substrings of the *normalised* key (lower-cased, non-alphanumeric
#: characters stripped), so ``apikey`` covers ``api_key``, ``apiKey`` and ``X-API-Key``.
DEFAULT_KEY_NEEDLES = frozenset(
    {
        "auth",
        "token",
        "secret",
        "passw",
        "passphrase",
        "apikey",
        "cookie",
        "credential",
        "privatekey",
        "sessionid",
        "bearer",
    }
)


class _Rule(Protocol):
    """What a text rule is: a compiled pattern, or anything that replaces like one."""

    def subn(self, repl: str, string: str, /) -> tuple[str, int]: ...


#: A run of the characters a JSON Web Token's segments are made of (base64url).
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")


class _JwtShape:
    """A JSON Web Token by its shape: ``eyJ`` and at least four more characters, a dot, at least
    four, a dot, and the rest of the signature — what ``\\beyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}
    \\.[A-Za-z0-9_-]*`` matches, replaced the same way, in linear time.

    That pattern is quadratic: in a long run of token characters with an ``eyJ`` after every
    ``-`` and no dot at its end, each ``eyJ`` starts a scan to the end of the run, which fails
    there. Here the text is split once into runs of token characters; a run is a header only if
    the run after the next dot is a payload, and within a run only the first ``eyJ`` that
    starts a word with four characters after it counts — exactly where the pattern would have
    matched, and nowhere else.

    ``repl`` is put in as it is: unlike ``re``, no backslash escapes and no group references.
    """

    def subn(self, repl: str, string: str, /) -> tuple[str, int]:
        if "eyJ" not in string:
            return string, 0
        # One pass over the runs, holding no more than three at a time: a list of them all
        # would cost memory in proportion to the text, for a text that is the server's to size.
        runs = _JWT_RUN.finditer(string)
        out: list[str] = []
        done = count = 0
        current, payload = next(runs, None), next(runs, None)
        while current is not None and payload is not None:
            after = next(runs, None)
            header = _jwt_header(string, current.start(), current.end())
            if (
                header is not None
                and payload.start() == current.end() + 1
                and string[current.end()] == "."
                and payload.end() - payload.start() >= 4
                and string[payload.end() : payload.end() + 1] == "."
            ):
                stop = payload.end() + 1
                if after is not None and after.start() == stop:
                    stop = after.end()  # the signature, as long as it runs
                    after = next(runs, None)
                out.append(string[done:header])
                out.append(repl)
                done = stop
                count += 1
                current, payload = after, next(runs, None)
            else:
                current, payload = payload, after
        if not count:
            return string, 0
        out.append(string[done:])
        return "".join(out), count


def _jwt_header(text: str, start: int, end: int) -> int | None:
    """Where a token's header starts in the run ``text[start:end]``: the first ``eyJ`` at the
    start of a word (``\\b``) with at least four characters after it in the run, or ``None``."""
    at = text.find("eyJ", start, end)
    while at != -1:
        if at == 0 or not (text[at - 1].isalnum() or text[at - 1] == "_"):
            return at if end - (at + 3) >= 4 else None
        at = text.find("eyJ", at + 1, end)
    return None


#: A scheme word at the start of a word, case-insensitive. No boundary is asked of what
#: follows: ``Bearer"x"`` and ``Bearer’s`` are occurrences, ``Bearers(x)`` is none only because
#: ``s`` is neither a separator nor an opener.
_SCHEME = re.compile(r"\b(?:Bearer|Basic|Token)", re.IGNORECASE)

#: The characters of a bare value, the same as in the bare rule.
_BARE_VALUE = re.compile(r"[A-Za-z0-9\-._~+/=]+")
_BARE_MIN = 8

_TYPOGRAPHIC_DOUBLE = "“”„‟«»"
_TYPOGRAPHIC_SINGLE = "‘’‚‛‹›"
_KEY_QUOTES = "\"'`" + _TYPOGRAPHIC_DOUBLE + _TYPOGRAPHIC_SINGLE

#: The class of closers an opener belongs to, as the string of the characters that close it.
_CLOSERS: dict[str, str] = {
    "<": ">",
    "(": ")",
    "[": "]",
    "{": "}",
    '"': '"',
    "'": "'",
    "`": "`",
    **dict.fromkeys(_TYPOGRAPHIC_DOUBLE, _TYPOGRAPHIC_DOUBLE),
    **dict.fromkeys(_TYPOGRAPHIC_SINGLE, _TYPOGRAPHIC_SINGLE),
}

#: The class a closer closes, by the closer.
_CLASS_OF: dict[str, str] = {ch: cls for cls in set(_CLOSERS.values()) for ch in cls}

#: What a scan for the end of values has to stop at: the end of a line, and any closer.
_SCAN_STOPS = re.compile("[\r\n" + re.escape("".join(sorted(_CLASS_OF))) + "]")


def _is_word(char: str) -> bool:
    return char.isalnum() or char == "_"


def _skip_space(text: str, at: int) -> int:
    """The first position from ``at`` that is neither white space nor an escaped line break or
    tab (a run of backslashes and then ``n``, ``r`` or ``t``: JSON recorded as text)."""
    size = len(text)
    while at < size:
        if text[at].isspace():
            at += 1
            continue
        if text[at] == "\\":
            stop = at
            while stop < size and text[stop] == "\\":
                stop += 1
            if stop < size and text[stop] in "nrt":
                at = stop + 1
                continue
        break
    return at


class _SchemeValues:
    """A scheme (``Bearer``, ``Basic``, ``Token``) and every value that can follow it, replaced
    as ``<scheme> `` and ``repl`` say.

    Each occurrence of a scheme is looked at for itself, in three forms of where a value
    starts: after white space or nothing; after white space, one colon and white space; and
    after the key form, a quote, white space, a colon and white space (``"Token": "x"``). A value
    is quoted or bracketed, in any class, or bare after a separator (eight characters of the
    bare rule). A quoted value ends behind the first closer of its class with as many
    backslashes in front as it was opened with (its depth) and no word character behind, else
    at the end of the line. An occurrence with a value gives a span from its scheme to the
    latest end of its values; spans that overlap are one, and each is replaced once, with the
    scheme of its first occurrence; each occurrence with a value counts. No chain is followed: a
    scheme in quotes that swallows the opener of the real value is covered, because the real
    occurrence finds its own value.

    Linear: the separators and backslash runs of an occurrence are read by it alone, a bare
    value is measured where it stands, and the ends of all quoted values come from one pass
    over the closers and line ends of the text. A value waits in a list for its class and
    depth, and the first closer that fits ends all of them at once. Memory is in proportion to
    the occurrences, not to the closers.
    """

    def subn(self, repl: str, string: str, /) -> tuple[str, int]:
        found = _SCHEME.search(string)
        if found is None:
            return string, 0
        text = string
        occurrences: list[tuple[int, int]] = []
        #: (position of the opener, class, depth, occurrence)
        requests: list[tuple[int, str, int, int]] = []
        stops: list[int] = []  # the latest end of the values of each occurrence, or -1
        while found is not None:
            index = len(occurrences)
            occurrences.append((found.start(), found.end()))
            stops.append(-1)
            for start, separated in self._starts(text, found.end()):
                bare = self._read(text, start, separated, index, requests)
                if bare > stops[index]:
                    stops[index] = bare
            found = _SCHEME.search(text, found.end())
        self._close(text, requests, stops)
        out: list[str] = []
        done = 0
        count = sum(1 for stop in stops if stop >= 0)  # one for each occurrence with a value
        index = 0
        while index < len(occurrences):
            if stops[index] < 0:
                index += 1
                continue
            start, scheme_end = occurrences[index]
            stop = stops[index]
            index += 1
            while index < len(occurrences) and (stops[index] < 0 or occurrences[index][0] < stop):
                if stops[index] >= 0:  # starts inside this span: the same one
                    stop = max(stop, stops[index])
                index += 1
            out += [text[done:start], text[start:scheme_end], " ", repl]
            done = stop
        out.append(text[done:])
        return "".join(out), count

    @staticmethod
    def _starts(text: str, end: int) -> list[tuple[int, bool]]:
        """Where a value may start behind a scheme ending at ``end``, with whether a separator
        (white space, or a colon) stands in front of it."""
        size = len(text)
        first = _skip_space(text, end)
        starts = [(first, first > end)]
        if first < size and text[first] == ":":
            starts.append((_skip_space(text, first + 1), True))
        quote = end
        while quote < size and text[quote] == "\\":
            quote += 1
        if quote < size and text[quote] in _KEY_QUOTES:
            colon = _skip_space(text, quote + 1)
            if colon < size and text[colon] == ":":
                starts.append((_skip_space(text, colon + 1), True))
        return starts

    @staticmethod
    def _read(
        text: str,
        start: int,
        separated: bool,
        index: int,
        requests: list[tuple[int, str, int, int]],
    ) -> int:
        """The end of a bare value at ``start``, or -1; an opener becomes a request."""
        size = len(text)
        at = start
        while at < size and text[at] == "\\":
            at += 1
        if at < size and text[at] in _CLOSERS:
            requests.append((at, _CLOSERS[text[at]], at - start, index))
            return -1
        if at == start and separated:
            run = _BARE_VALUE.match(text, start)
            if run is not None and run.end() - start >= _BARE_MIN:
                return run.end()
        return -1

    @staticmethod
    def _close(text: str, requests: list[tuple[int, str, int, int]], stops: list[int]) -> None:
        """Find the end of every quoted value in one pass, and put the latest into ``stops``."""
        requests.sort()  # made in order already, which makes this linear
        size = len(text)
        waiting: dict[tuple[str, int], list[int]] = {}
        taken = pos = 0
        while True:
            if not waiting:
                if taken == len(requests):
                    return
                pos = max(pos, requests[taken][0] + 1)
            event = _SCAN_STOPS.search(text, pos)
            if event is None:
                break
            at = event.start()
            pos = at + 1
            while taken < len(requests) and requests[taken][0] < at:
                _, cls, depth, index = requests[taken]
                waiting.setdefault((cls, depth), []).append(index)
                taken += 1
            if not waiting:
                continue
            if text[at] in "\r\n":
                end = at
                ended = [index for group in waiting.values() for index in group]
                waiting.clear()
            else:
                run = 0
                while text[at - 1 - run] == "\\":
                    run += 1
                if at + 1 < size and _is_word(text[at + 1]):
                    continue
                end = at + 1
                ended = waiting.pop((_CLASS_OF[text[at]], run), [])
            for index in ended:
                stops[index] = max(stops[index], end)
        # No event is left: everything still open runs to the end of the text.
        for _, _, _, index in requests[taken:]:
            stops[index] = size
        for group in waiting.values():
            for index in group:
                stops[index] = size


#: The characters of a URL scheme (RFC 3986): a letter, then letters, digits, ``+``, ``.``, ``-``.
_URL_SCHEME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-")
#: The quotes that end a URL's authority.
_URL_QUOTES = "\"'`"
#: Where the authority of a URL ends: a path, a query, a fragment, white space, a quote, an
#: angle bracket; but not a ``/`` of a further ``://`` (:func:`_authority_end`). The end of the
#: text ends it too.
_AUTHORITY_END = re.compile(r"[/?#\s<>" + _URL_QUOTES + "]")
#: The encoded forms the decoding view reads (:class:`_DecodedUrlUserinfo`), each one ASCII
#: character: ``%XX`` and ``%25XX`` (encoded twice), the JSON escapes ``\/`` and ``\uXXXX``, the
#: HTML entities ``&#NN;``, ``&#xHH;``, ``&colon;``, ``&sol;``, ``&commat;``, and the full-width
#: colon, solidus and commercial at. Each starts at a character of its own and has a bound.
_ENCODED_PIECE = re.compile(
    r"%25[0-9A-Fa-f]{2}|%[0-9A-Fa-f]{2}|\\/|\\u[0-9A-Fa-f]{4}"
    r"|&#[0-9]{1,7};|&#[xX][0-9A-Fa-f]{1,6};|&(?:colon|sol|commat);|[\uff1a\uff0f\uff20]"
)
#: The pieces of :data:`_ENCODED_PIECE` that stand for one character by their name.
_NAMED_PIECES = {
    "\\/": "/",
    "&colon;": ":",
    "&sol;": "/",
    "&commat;": "@",
    "\uff1a": ":",
    "\uff0f": "/",
    "\uff20": "@",
}
#: A Go MySQL DSN's anchor: ``@`` and a network of the driver, ``tcp``, ``tcp4``, ``tcp6``,
#: ``udp``, ``udp4``, ``udp6``, ``unix``, ``unixgram``, ``unixpacket``, and ``(``.
_DSN_ANCHOR = re.compile(r"@(?:tcp[46]?|udp[46]?|unix(?:gram|packet)?)\(")
#: What a Go MySQL DSN's credentials run back to (white space), or its anchor.
_DSN_EVENT = re.compile(r"\s|" + _DSN_ANCHOR.pattern)


def _authority_end(text: str, start: int, repl: str) -> int:
    """Where the authority from ``start`` ends (:data:`_AUTHORITY_END`), or the end of the text.

    A ``/`` of a further ``://`` does not end it: that ``://`` is part of the userinfo
    (``postgresql://u:pa://ss@h/db``), and the authority runs on to the last ``@``. White space
    right in front of ``repl`` does not end it either: that is how :class:`_SchemeValues`,
    which runs first, leaves a scheme in a userinfo (``x-access-Token ***REDACTED***@host``),
    and the rest of that userinfo must go too. Fail closed: both only ever widen what goes."""
    found = _AUTHORITY_END.search(text, start)
    while found is not None:
        at = found.start()
        if text[at].isspace():
            if not text.startswith(repl, found.end()):
                break
        elif text[at] != "/" or not (
            text.startswith("://", at - 1) or text.startswith("://", at - 2)
        ):
            break
        found = _AUTHORITY_END.search(text, found.end())
    return len(text) if found is None else found.start()


def _has_scheme(text: str, at: int) -> bool:
    """Whether ``[A-Za-z][A-Za-z0-9+.-]*`` ends right before ``at``: the run of scheme characters
    in front of it holds a letter. The runs in front of two ``://`` never overlap, since neither
    ``:`` nor ``/`` is a scheme character, so reading them is linear in the text."""
    while at > 0 and text[at - 1] in _URL_SCHEME_CHARS:
        at -= 1
        if text[at].isascii() and text[at].isalpha():
            return True
    return False


def _is_scheme(text: str, start: int, end: int) -> bool:
    """Whether ``text[start:end]`` is a scheme and nothing else: scheme characters only, a letter
    among them. Read from ``end`` back, so the run in front of a ``://`` is read once, as in
    :func:`_has_scheme`."""
    letter = False
    while end > start and text[end - 1] in _URL_SCHEME_CHARS:
        end -= 1
        letter = letter or (text[end].isascii() and text[end].isalpha())
    return end == start and letter


def _userinfo_spans(text: str, repl: str) -> list[tuple[int, int]]:
    """Where the userinfo of each URL in ``text`` starts and where its last ``@`` stands: from
    behind ``scheme://`` to the last ``@`` before the end of the authority. Empty userinfo is
    none. A ``://`` without a scheme in front of it starts no URL.

    Linear: an authority runs over the ``://`` inside it, so no two overlap; the next ``://``
    is looked for behind the end of this one. The runs read for the schemes do not overlap
    either (:func:`_has_scheme`)."""
    spans: list[tuple[int, int]] = []
    at = text.find("://")
    while at != -1:
        start = at + 3
        if not _has_scheme(text, at):
            at = text.find("://", start)
            continue
        end = _authority_end(text, start, repl)
        sign = text.rfind("@", start, end)
        if sign > start:
            spans.append((start, sign))
        at = text.find("://", max(start, end - 2))
    return spans


class _UrlUserinfo:
    """The ``userinfo`` of a URL: everything between ``scheme://`` and the last ``@`` before the
    end of the authority (:func:`_authority_end`) is replaced; scheme, ``@``, host, port, path
    and query stay. A user name alone goes too (``ssh://git@host``): fail closed. Empty
    ``userinfo`` (``https://@host``) holds nothing and is left. A ``://`` inside the userinfo
    does not start a URL of its own (``a://reader:pw://v:q@i``: all of ``reader:pw://v:q``).

    One URL counts once: a userinfo with ``repl`` in it, which an earlier rule has replaced in
    already (``https://x-access-Token ***REDACTED***@github.com``), is replaced whole and not
    counted again. Linear (:func:`_userinfo_spans`).
    """

    def subn(self, repl: str, string: str, /) -> tuple[str, int]:
        if "://" not in string:
            return string, 0
        out: list[str] = []
        done = count = 0
        for start, sign in _userinfo_spans(string, repl):
            out += [string[done:start], repl]
            count += string.find(repl, start, sign) == -1
            done = sign
        if not out:
            return string, 0
        out.append(string[done:])
        return "".join(out), count


def _piece_char(piece: str) -> str | None:
    """The ASCII character a piece of :data:`_ENCODED_PIECE` stands for, or ``None`` for one
    that stands for another: its characters are then read as they are."""
    named = _NAMED_PIECES.get(piece)
    if named is not None:
        return named
    if piece[0] == "%":
        code = int(piece[-2:], 16)
    elif piece[0] == "\\":
        code = int(piece[2:], 16)
    elif piece[2] in "xX":
        code = int(piece[3:-1], 16)
    else:
        code = int(piece[2:-1])
    return chr(code) if code < 0x80 else None


class _DecodedUrlUserinfo:
    """The ``userinfo`` of a URL written in part or whole in an encoded form: percent-encoded,
    once or twice (``next=https%3A//u%3Apw%40h``, ``https%253A%252F%252Fu%253Apw%2540h``), as
    JSON escapes (``https:\\/\\/u:pw\\u0040h``), as HTML entities (``https://u:pw&#64;h``), in
    full-width forms (``https://u：pw＠h``), or mixed.

    The text is read as pieces (start, end, character): each form of :data:`_ENCODED_PIECE` is
    one, any other character is one of its own. On the characters of the pieces the grammar of
    :class:`_UrlUserinfo` holds: scheme, ``://``, the ends of the authority, the last ``@``.
    Replaced in the text as written is the span from the piece behind ``://`` to the ``@``
    piece; scheme, separator, ``@`` and host stay as they were written. One URL counts once, as
    there.

    The rule runs only on a text with an encoded piece in it; a URL written plainly is
    :class:`_UrlUserinfo`'s, which runs first and leaves ``repl`` in it, so this one does not
    count it again.

    Not read: white space in a userinfo (it ends the authority, as in a plain URL), a URL
    encoded three times, and HTML entities other than those above.

    Linear: one pass for the pieces, one for the grammar (:func:`_userinfo_spans`), and the
    spans are mapped back to the text in their order. Memory goes with the encoded pieces.
    """

    def subn(self, repl: str, string: str, /) -> tuple[str, int]:
        located = self.located(string, repl)
        if located is None:
            return string, 0
        decoded, found = located
        out: list[str] = []
        done = count = 0
        for first, last, start, sign in found:
            out += [string[done:first], repl]
            count += decoded.find(repl, start, sign) == -1
            done = last
        if not out:
            return string, 0
        out.append(string[done:])
        return "".join(out), count

    @staticmethod
    def located(string: str, repl: str) -> tuple[str, list[tuple[int, int, int, int]]] | None:
        """The decoded text and, for each userinfo in it, where it stands as written (its first
        character, the ``@``) and in the decoded text (the same two); ``None`` for a text with
        no encoded piece in it. The one reading the rule and :func:`_personal_spans` share."""
        parts: list[str] = []
        decoded_at: list[int] = []  # where each encoded piece stands in the decoded text
        written_at: list[tuple[int, int]] = []  # and in the text as written
        done = 0
        size = 0
        for found in _ENCODED_PIECE.finditer(string):
            char = _piece_char(found.group())
            if char is None:
                continue
            parts.append(string[done : found.start()])
            size += found.start() - done
            decoded_at.append(size)
            written_at.append((found.start(), found.end()))
            parts.append(char)
            size += 1
            done = found.end()
        if not decoded_at:
            return None
        parts.append(string[done:])
        decoded = "".join(parts)
        index = 0  # the last encoded piece at or before the position asked for, if any

        def written(position: int) -> int:
            """Where the piece at ``position`` of ``decoded`` starts in ``string``; asked for in
            rising order, so the walk over the encoded pieces is made once."""
            nonlocal index
            while index + 1 < len(decoded_at) and decoded_at[index + 1] <= position:
                index += 1
            if decoded_at[index] > position:
                return position  # in front of the first encoded piece
            if decoded_at[index] == position:
                return written_at[index][0]
            return written_at[index][1] + position - decoded_at[index] - 1

        return decoded, [
            (written(start), written(sign), start, sign)
            for start, sign in _userinfo_spans(decoded, repl)
        ]


class _GoMysqlDsn:
    """The DSN of Go's MySQL driver, ``user:pass@tcp(host:3306)/db``, ``user:pass@unix(/path)/db``
    or with any other network of the driver (:data:`_DSN_ANCHOR`): everything in front of the
    anchor back to the previous white space or the start of the text is replaced. A password in
    a DSN is not encoded, so ``=``, quotes, ``:`` and ``/`` in front of the anchor are part of
    it; a ``dsn=`` or a quote in front of the DSN goes with it: fail closed. Two anchors with no
    white space between them make one span, replaced once.

    What :class:`_UrlUserinfo` has masked already is left where a scheme and nothing else stands
    in front of its ``://`` (``mysql://***REDACTED***@tcp(…)``), so the scheme stays; in any
    other span with ``://`` in it the whole span goes (``user:pa://ss@tcp(…)``). So is a span
    that is the placeholder alone. A span with the placeholder in it is replaced and not counted
    again: one DSN counts once.

    Not read: a password with white space in it, in a DSN in prose; only what follows the white
    space goes.

    Linear: one pass over the white space and anchors, holding the latest white space; the
    scheme in front of a ``://`` is read back once (:func:`_is_scheme`).
    """

    def subn(self, repl: str, string: str, /) -> tuple[str, int]:
        # One search, not two substring tests: CPython picks its substring search by the length
        # of the text, and the two grew about three times faster than the text between 5 000 and
        # 40 000 characters (tests/test_hostile_input_runtime.py).
        if "@" not in string or _DSN_ANCHOR.search(string) is None:
            return string, 0
        out: list[str] = []
        done = count = cut = 0
        stop = -1  # the end of the span open since ``cut``, or -1
        masked = "://" + repl
        for event in _DSN_EVENT.finditer(string):
            at = event.start()
            if string[at] != "@":
                if string.startswith(repl, event.end()):
                    continue  # a scheme _SchemeValues left, as in _authority_end
                if stop != -1:
                    out += [string[done:cut], repl]
                    count += string.find(repl, cut, stop) == -1
                    done, stop = stop, -1
                cut = event.end()
                continue
            # Compared in place: a slice would copy the span for every anchor in it.
            whole = at - cut == len(repl) and string.startswith(repl, cut)
            behind_scheme = string.endswith(masked, cut, at) and _is_scheme(
                string, cut, at - len(masked)
            )
            if at == cut or whole or behind_scheme:
                continue
            stop = at
        if stop != -1:
            out += [string[done:cut], repl]
            count += string.find(repl, cut, stop) == -1
            done = stop
        if not out:
            return string, 0
        out.append(string[done:])
        return "".join(out), count


_TEXT_RULES: tuple[tuple[_Rule, str], ...] = (
    # The schemes with a quoted, bracketed or bare-after-a-colon value, every occurrence on its
    # own and the union of what they find (:class:`_SchemeValues`). It runs first: no earlier
    # replacement can take an anchor from it (``Bearer abcdefgh.Token 'x'``: the bare rule
    # below would eat ``Token``), and the next pass would cut a value at an escaped quote
    # before this one sees it (``Bearer "a\"x"``).
    (_SchemeValues(), PLACEHOLDER),
    # The userinfo of a URL, written plainly or in an encoded form, and a Go MySQL DSN's
    # credentials. Before the token shapes, so that a token as the user name
    # (``https://ghp_…@github.com``) is one replacement and one hit.
    (_UrlUserinfo(), PLACEHOLDER),
    (_DecodedUrlUserinfo(), PLACEHOLDER),
    (_GoMysqlDsn(), PLACEHOLDER),
    # Keep the scheme, drop the credential: an "Authorization: Bearer <x>" line stays
    # recognisable as one without carrying the token.
    (
        re.compile(r"\b(Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/=]{8,}", re.IGNORECASE),
        r"\1 " + PLACEHOLDER,
    ),
    (_JwtShape(), PLACEHOLDER),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}"), PLACEHOLDER),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), PLACEHOLDER),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), PLACEHOLDER),
    (re.compile(r"\bxox[baprse]-[A-Za-z0-9-]{10,}"), PLACEHOLDER),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), PLACEHOLDER),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), PLACEHOLDER),
    # The same schemes with the credential quoted or bracketed: ``Bearer "x"``, ``Bearer 'x'``,
    # ``Bearer <x>``, spaces inside allowed. The quotes are what say a value follows, so any
    # length counts, and an opened quote that never closes is masked to the end of the line:
    # the rule never has to look for a closing quote it may not find, which keeps it linear.
    # An escaped quote opens too, escaped once or more: ``\"`` in a JSON document recorded as
    # text, ``\'`` in a Python repr. The value is always replaced whole, even where an earlier
    # rule replaced part of it already; that one credential is then counted twice is the price
    # of never leaving a remainder behind. This pass is the rule as it stood before the forms
    # of :class:`_SchemeValues` were added, unchanged, and it runs behind that rule: the lower
    # bound. Whatever it masked, it still masks; behind that rule it usually finds nothing.
    (
        re.compile(
            r"\b(Bearer|Basic|Token)\s+(?:\\*\"[^\"\r\n]*\"?|\\*'[^'\r\n]*'?|<[^>\r\n]*>?)",
            re.IGNORECASE,
        ),
        r"\1 " + PLACEHOLDER,
    ),
)

#: The kinds of personal data replaced by a pseudonym, in the words the pseudonym's digest and
#: ``run_finished.replacements`` use. ``known`` is a value the engagement file lists
#: (``known_values``); the other three are shapes found in the text (:func:`_personal_spans`).
PERSONAL_KINDS = ("email", "iban", "tel", "known")

#: How long a pseudonym of personal data lasts, by the salt it is made with: the engagement's
#: (``run_started.pseudonyms``), or the run's own. Indexed by whether the salt is the run's.
PSEUDONYM_SCOPES = ("per_engagement", "per_run")

#: How the length of an IBAN is told by its country: the SWIFT IBAN Registry, the registry of
#: ISO 13616 (SWIFT IBAN Registry, Release 99, Dec 2024; checked against copies, not the
#: original). Total length of the IBAN, country code and check digits included.
#: Closed: a code not listed here is no IBAN. A country the registry adds later is missed until
#: it is added here, which is the safe side of a closed list for a rule that must not fire on
#: look-alikes.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22,
    "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28,
    "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22,
    "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}  # fmt: skip

#: Bounds that keep the scan of every candidate constant: an address is at most 64 characters
#: before the ``@`` and 253 after it (RFC 5321, 4.5.3.1), and the first path segment of an
#: SCP-style remote is read to 128.
MAX_EMAIL_LOCAL = 64
MAX_EMAIL_DOMAIN = 253
MAX_SCP_SEGMENT = 128

#: The characters besides letters, digits and combining marks that the local part of an address
#: may hold: the dot, ``_``, ``+``, ``-`` and the apostrophe, straight or typographic. The other
#: ``atext`` of RFC 5322 (``!#$%&*/=?^`{|}~``) ends the local part, so that ``contact=`` and the key
#: of a query string stay in front of an address.
_LOCAL_PUNCTUATION = frozenset(".'\u2019_+-")
#: A dot or an apostrophe at the start of a local part is not part of it (``'alice@x.example'``);
#: at its end it is (``alice.@x.example`` is replaced whole: it is no address by the RFC, but it
#: tells the name).
_LOCAL_EDGE = frozenset(".'\u2019")
_SCP_SEGMENT = re.compile(r"[A-Za-z0-9_.~-]*")
#: The body of an IBAN: capital letters and digits. The run is read with this and the character
#: behind it is looked at (:func:`_iban_end`), so a lower case letter behind it is a boundary.
_IBAN_RUN = re.compile(r"[A-Z0-9]*")
#: Where an IBAN may start: two capital letters and two digits (the check for what stands in
#: front of them is made in :func:`_iban_spans`).
_IBAN_START = re.compile(r"[A-Z]{2}[0-9]{2}")
#: ``tel:`` at the start of a URI, not behind a character of a scheme (``hotel:``).
_TEL_SCHEME = re.compile(r"(?<![A-Za-z0-9+.\-])tel:", re.IGNORECASE)
#: What a ``tel:`` URI runs over (RFC 3966): digits and ``+``, the visual separators ``-.()``,
#: ``*`` and ``#``, and the characters of parameters (``;ext=5``). Not white space, not a quote.
_TEL_BODY = re.compile(r"[0-9A-Za-z+\-.()*#;=%_~!$,]*")

#: A span of the text and the canonical value its pseudonym is made of.
_Span = tuple[int, int, str]
#: The user information of the URLs in a text, as the starts and the ends of their spans.
_Userinfo = tuple[list[int], list[int]]


def _is_letter_or_mark(character: str) -> bool:
    """A letter or a digit of any script, or a character of category M (a combining mark)."""
    return character.isalnum() or (character > "\x7f" and unicodedata.category(character)[0] == "M")


def _email_spans(text: str) -> list[_Span]:
    """The e-mail addresses in ``text``: ``local@domain``, canonical in lower case.

    The local part is made of letters, digits and combining marks of any script (RFC 6531), the
    ``.``, ``_``, ``+``, ``-`` and the apostrophe (``'`` and ``\u2019``), at most
    :data:`MAX_EMAIL_LOCAL` characters. Any other character ends it (``contact=alice@x.example``
    keeps ``contact=``). A dot or an apostrophe at its start is not part of it, so
    ``'alice@x.example'`` keeps its quotes; at its end it is, and ``alice.@x.example`` is replaced
    whole, though no address by the RFC, as the name would show. A local part in
    quotes (``"bob smith"@x.example``) is not recognised: a safe reading would need a parser, and
    such addresses are rare in traffic. A quote ends the local part and the run of "no rest"
    alike, so ``{"user":"@max.mustermann"}`` is left as it is. The domain is a host name of at least
    two labels (:func:`_domain_end`).

    An address is replaced whole or not at all, and no part of the name stays. Where a letter, a
    digit or a combining mark stands directly in front of the start found, the span starts at the
    start of that run: ``Zoë.O'Brien@x.example`` is one address; the run never reaches over a quote.

    Not an address: a ``@`` that lies in the user information of a URL (``ssh://git@host``,
    ``https://u:pw@host``, also written in an encoded form; the rules for it replace that as a
    credential), a host without a dot (``user@localhost``), and an SCP-style remote, where the
    host is followed by ``:`` and a path (``git@github.com:org/repo``): in front of the ``@``
    there is the account on a host, not a person. Linear: each ``@`` is looked at once, with a
    scan in either direction that is bounded.
    """
    found: list[_Span] = []
    at = text.find("@")
    if at == -1:
        return found
    protected = _protected_at_signs(text)
    floor = 0  # the end of the last address: a local part never reaches back into it
    while at != -1:
        start = _local_start(text, at, floor)
        end = None
        if start is not None and not _is_protected(protected, at):
            end = _domain_end(text, at + 1)
            if end is not None and _scp_remote(text, end):
                end = None
        if end is None:
            at = text.find("@", at + 1)
            continue
        while start > floor and _is_letter_or_mark(text[start - 1]):
            start -= 1
        found.append((start, end, text[start:end].lower()))
        floor = end
        at = text.find("@", floor)
    return found


def _local_start(text: str, at: int, floor: int) -> int | None:
    """Where the local part in front of the ``@`` at ``at`` starts, or ``None``: it is empty or
    longer than :data:`MAX_EMAIL_LOCAL`. Never in front of ``floor``."""
    if at == floor:
        return None
    limit = max(floor, at - MAX_EMAIL_LOCAL - 1)
    start = at
    while start > limit and (
        text[start - 1] in _LOCAL_PUNCTUATION or _is_letter_or_mark(text[start - 1])
    ):
        start -= 1
    if at - start > MAX_EMAIL_LOCAL:
        return None
    while start < at and text[start] in _LOCAL_EDGE:
        start += 1
    return start if start < at else None


def _domain_end(text: str, begin: int) -> int | None:
    """Where the host name that starts at ``begin`` ends, or ``None`` where there is none. At
    least two labels of letters, digits and combining marks of any script and hyphens, each of
    one to 63 characters that neither starts nor ends in a hyphen, the whole at most
    :data:`MAX_EMAIL_DOMAIN`. The last is a word of letters (a top-level domain in any script) or
    Punycode (``xn--…``, which may hold digits). The name ends at the last label that is one: in
    ``a@x.example.`` the dot belongs to the sentence. Not a host name if a letter, a digit or a
    hyphen follows the end (a label too long, or one that ends in a hyphen)."""
    size = len(text)
    stop = min(size, begin + MAX_EMAIL_DOMAIN + 1)
    labels = 0
    end = position = begin
    while True:
        label_end = position
        while label_end < stop and (_is_letter_or_mark(text[label_end]) or text[label_end] == "-"):
            label_end += 1
        label = text[position:label_end]
        # An empty label at the stop is the end of a sentence, unless a label goes on after it.
        if (
            label_end == stop
            and stop < size
            and (label or _is_letter_or_mark(text[stop]) or text[stop] == "-")
        ):
            return None  # longer than a host name may be
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            break
        labels += 1
        end = label_end
        if not text.startswith(".", end):
            break
        position = end + 1
    if labels < 2 or end - begin > MAX_EMAIL_DOMAIN:
        return None
    if end < size and (_is_letter_or_mark(text[end]) or text[end] == "-"):
        return None
    last = text[text.rfind(".", begin, end) + 1 : end]
    if last[:4].lower() == "xn--" and len(last) > 4:
        return end
    if len(last) < 2 or not all(c.isalpha() or unicodedata.category(c)[0] == "M" for c in last):
        return None
    return end


def _scp_remote(text: str, end: int) -> bool:
    """Whether the host ending at ``end`` is followed by ``:`` and a path whose first segment is
    closed by ``/`` (or that starts with it): ``git@host:org/repo``, ``u@host:~/x``,
    ``u@host:/srv``. ``alice@corp.test:bob@corp.test`` is not: the segment ends at the ``@``."""
    if not text.startswith(":", end):
        return False
    segment = _SCP_SEGMENT.match(text, end + 1, end + 2 + MAX_SCP_SEGMENT)
    return segment is not None and text.startswith("/", segment.end())


def _protected_at_signs(text: str) -> list[_Userinfo]:
    """Where the user information of each URL in ``text`` runs, from its first character to its
    last ``@``: for the URLs written plainly, and for those written in an encoded form. Each
    list is sorted and its spans do not overlap."""
    plain = _userinfo_spans(text, PLACEHOLDER) if "://" in text else []
    located = _DecodedUrlUserinfo.located(text, PLACEHOLDER)
    encoded = [] if located is None else [(first, last) for first, last, _, _ in located[1]]
    return [([a for a, _ in spans], [b for _, b in spans]) for spans in (plain, encoded)]


def _is_protected(protected: list[_Userinfo], at: int) -> bool:
    for starts, ends in protected:
        index = bisect.bisect_right(starts, at) - 1
        if index >= 0 and ends[index] >= at:
            return True
    return False


def _iban_spans(text: str) -> list[_Span]:
    """The IBANs in ``text``: a country of :data:`IBAN_LENGTHS`, two check digits and the rest of
    the length that country prescribes, capital letters and digits, with a valid check (ISO 7064
    mod 97-10), written without spaces (the electronic form of ISO 13616) or in groups of four
    separated by one space (the print form; the last group may be shorter). Capitals only: an
    IBAN in lower case is no match, which keeps the ids that servers hand out in hex from being
    read as one. Not behind or in front of a letter or a digit. Canonical: without spaces.
    Linear: a candidate starts at a country code and two digits, and reads at most 34 characters
    (nine groups) from there."""
    found: list[_Span] = []
    done = 0
    for candidate in _IBAN_START.finditer(text):
        start = candidate.start()
        if start < done or (start and text[start - 1].isalnum()):
            continue
        length = IBAN_LENGTHS.get(candidate.group()[:2])
        if length is None:
            continue
        end = _iban_end(text, start, length)
        if end is None:
            continue
        compact = "".join(text[start:end].split())
        if _iban_check(compact):
            found.append((start, end, compact))
            done = end
    return found


def _iban_end(text: str, start: int, length: int) -> int | None:
    """Where an IBAN of ``length`` characters starting at ``start`` ends, in either written
    form, or ``None``."""
    first = _run_end(text, start, start + length + 1)
    if first - start == length:
        return None if text[first : first + 1].isalnum() else first  # in one piece
    if first - start != 4:
        return None
    total, end = 4, first
    while total < length:
        if not text.startswith(" ", end):
            return None
        group = _run_end(text, end + 1, end + 6)
        size = group - end - 1
        if size == 0 or size > 4 or total + size > length or (size < 4 and total + size < length):
            return None
        total += size
        end = group
    return None if text[end : end + 1].isalnum() else end


def _run_end(text: str, start: int, stop: int) -> int:
    """Where the run of capital letters and digits from ``start`` ends, looking no further than
    ``stop``."""
    found = _IBAN_RUN.match(text, start, stop)
    return start if found is None else found.end()


def _iban_check(compact: str) -> bool:
    """Whether the IBAN has a valid check: the first four characters moved to the end, letters
    read as 10 to 35, the number mod 97 is 1, and the check digits are 02 to 98 (ISO 13616: mod 97
    alone also takes 01 where 98 is meant). Done digit by digit, so no number grows."""
    if not 2 <= int(compact[2:4]) <= 98:
        return False
    rest = 0
    for character in compact[4:] + compact[:4]:
        value = int(character, 36)
        rest = (rest * (100 if value > 9 else 10) + value) % 97
    return rest == 1


def _tel_spans(text: str) -> list[_Span]:
    """The ``tel:`` URIs in ``text`` (RFC 3966): the scheme in either case, not behind a character
    of a scheme, then a number that starts with ``+`` or a digit and holds a digit, with its
    visual separators and parameters, up to white space, a quote or a character no URI of the
    kind holds. A ``.``, ``,``, ``;`` or ``!`` at the end, and a ``)`` that closes nothing the URI
    opened, belong to the sentence. Canonical: as written. Linear: the text is searched once and
    each URI is read once."""
    found: list[_Span] = []
    done = 0
    for scheme in _TEL_SCHEME.finditer(text):
        if scheme.start() < done:
            continue
        body = _TEL_BODY.match(text, scheme.end())
        number = "" if body is None else body.group()
        # The end, found in one pass backwards over the indices; the parentheses are counted
        # once and followed as they are struck off.
        stop = len(number)
        opened = number.count("(")
        closed = number.count(")")
        while stop:
            last = number[stop - 1]
            if last in ".,;!":
                stop -= 1
            elif last == ")" and opened < closed:
                stop -= 1
                closed -= 1
            else:
                break
        number = number[:stop]
        if not number or number[0] not in "+0123456789" or not any(c.isdigit() for c in number):
            continue
        end = scheme.end() + len(number)
        found.append((scheme.start(), end, text[scheme.start() : end]))
        done = end
    return found


def _personal_spans(text: str) -> list[tuple[int, int, str, str]]:
    """The three shapes found in ``text``, sorted by position and not overlapping, each as
    ``(start, end, kind, canonical)``. Where two overlap, ``tel:`` wins over an address and an
    address over an IBAN: the scheme says most, then the ``@``."""
    kept: list[tuple[int, int, str, str]] = []
    for kind, spans in (
        ("tel", _tel_spans(text)),
        ("email", _email_spans(text)),
        ("iban", _iban_spans(text)),
    ):
        if not spans:
            continue
        # Both lists are sorted, so one walk over the two tells what overlaps, and sorting two
        # sorted runs is linear.
        fresh: list[tuple[int, int, str, str]] = []
        index = 0
        for start, end, canonical in spans:
            while index < len(kept) and kept[index][1] <= start:
                index += 1
            if index < len(kept) and kept[index][0] < end:
                continue
            fresh.append((start, end, kind, canonical))
        kept = sorted([*kept, *fresh])
    return kept


_NON_ALNUM = re.compile(r"[^a-z0-9]")

#: Characters a reader does not see beyond those the signals' normalised view drops, and which
#: split a value just as well: the three bidirectional marks, the combining grapheme joiner, the
#: invisible operators, the Hangul fillers, the two Khmer inherent vowels and the fourth
#: Mongolian variation selector.
MORE_INVISIBLE = frozenset(
    "\u061c\u200e\u200f\u034f\u2061\u2062\u2063\u2064\u115f\u1160\u3164\uffa0\u17b4\u17b5\u180f"
)

#: Ranges of such characters, first and last: the tag block, the variation selectors (the
#: Mongolian ones too), the deprecated format characters, the interlinear annotation marks and
#: the musical format characters.
INVISIBLE_RANGES = (
    (TAG_BLOCK.start, TAG_BLOCK.stop - 1),
    (0xFE00, 0xFE0F),
    (0xE0100, 0xE01EF),
    (0x180B, 0x180D),
    (0x206A, 0x206F),
    (0xFFF9, 0xFFFB),
    (0x1D173, 0x1D17A),
)

_INVISIBLE = ZERO_WIDTH | JOINERS | BIDI | MORE_INVISIBLE

#: What a reader does not see, dropped from a key and from the normalised copy of a text: the
#: set the signals' normalised view drops (zero-width characters, joiners, bidirectional
#: overrides and isolates, the tag block), and :data:`MORE_INVISIBLE` and
#: :data:`INVISIBLE_RANGES` beside it.
_WIDTHLESS_TABLE = dict.fromkeys(
    [ord(c) for c in _INVISIBLE]
    + [point for first, last in INVISIBLE_RANGES for point in range(first, last + 1)],
    None,
)

#: The two escape forms read as characters in a key and in the normalised copy of a text, one
#: round.
_ESCAPED_CHARACTER = re.compile(r"\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})")

_SURROGATE = re.compile("[\ud800-\udfff]")


def _unescape(match: re.Match[str]) -> str:
    return chr(int(match.group(1) or match.group(2), 16))


def _escapes_read(text: str) -> str:
    """``text`` with ``\\uXXXX`` and ``\\xXX`` read as characters, one round. A high and a low
    surrogate in a row, as JSON writes a character beyond the sixteen bits, are that one
    character; a surrogate without its partner stays."""
    text = _ESCAPED_CHARACTER.sub(_unescape, text)
    if _SURROGATE.search(text) is not None:
        text = text.encode("utf-16", "surrogatepass").decode("utf-16", "surrogatepass")
    return text


def normalise_key(key: str) -> str:
    """Reduce a key to the form needles are matched against.

    ``\\uXXXX`` and ``\\xXX`` read as characters (one round), then NFKC, so a full-width
    ``ａｐｉｋｅｙ`` or an escaped ``\\u0074oken`` reads as a plain name, and the characters of
    :data:`_WIDTHLESS_TABLE` are dropped, so one slipped into a name does not hide it; then lower
    case, and only letters and digits. A character that is a number but no digit (Unicode ``No``:
    ``²``, ``½``, ``①``) is dropped before NFKC would make digits of it: it spells no name, and
    a mask key of it alone would become a needle of one digit.
    """
    if not key.isascii() or "\\" in key:
        key = _escapes_read(key)
        if not key.isascii():
            key = "".join(c for c in key if unicodedata.category(c) != "No")
        # NFKC first, then the invisible characters: an accent that an invisible character
        # keeps apart from its letter is dropped below as no letter, and the letter stays.
        key = unicodedata.normalize("NFKC", key).translate(_WIDTHLESS_TABLE)
    return _NON_ALNUM.sub("", key.lower())


def _normalised_copy(text: str) -> str | None:
    """The text as a reader would take it: ``\\uXXXX`` and ``\\xXX`` read as characters (one
    round), NFKC, the characters of :data:`_WIDTHLESS_TABLE` removed. ``None`` when the text
    holds nothing this could change (no ``\\u`` or ``\\x``, and ASCII, or already in NFKC and
    without an invisible character), so the common case costs a scan or two and no copy."""
    if (
        "\\u" not in text
        and "\\x" not in text
        and (
            text.isascii()
            or (unicodedata.is_normalized("NFKC", text) and _WIDTHLESS.search(text) is None)
        )
    ):
        return None
    # The invisible characters go before NFKC: one that stands between a letter and its accent
    # keeps the two from composing. NFKC makes no invisible character of a visible one (a test
    # holds that over all of Unicode), so none is left after it. By a search, and a substitution
    # only where it finds one: a table lookup per character costs more than NFKC itself on a
    # long copy.
    copy = _escapes_read(text)
    if _WIDTHLESS.search(copy) is not None:
        copy = _WIDTHLESS.sub("", copy)
    return unicodedata.normalize("NFKC", copy)


#: How much longer than its text a normalised copy may be and still be masked (the bound of the
#: signals' normalised view): a few characters grow eighteenfold under NFKC, and a megabyte of
#: them would be masked as eighteen. Past the bound the value is replaced whole.
_COPY_GROWTH = NORMALIZED_GROWTH
_COPY_SLACK = NORMALIZED_SLACK

#: Horizontal white space of any kind: NFKC turns U+00A0 or U+2009 into a plain space, and two
#: masked texts that differ in that alone say the same (:func:`_compared`).
_HORIZONTAL_SPACE = re.compile(r"[^\S\r\n]")

#: How many keys a masker remembers as holding nothing (:attr:`Masker._clean_keys`), and how
#: long a key may be to be remembered: a name a protocol repeats is short, and what a server
#: sends as a key is not kept for the length of the run.
_CLEAN_KEYS = 4096
_CLEAN_KEY_LENGTH = 128

#: Any character of :data:`_WIDTHLESS_TABLE`, to tell quickly that a text holds none: each range
#: as a range, which keeps the search fast.
_WIDTHLESS = re.compile(
    "["
    + re.escape("".join(sorted(_INVISIBLE)))
    + "".join(f"{chr(first)}-{chr(last)}" for first, last in INVISIBLE_RANGES)
    + "]"
)

#: A pseudonym as the text rules write it, its digest apart (:func:`_compared`).
_PSEUDONYM_DIGEST = re.compile(r"(\*\*\*[A-Z]+)-[0-9a-f]{12}(\*\*\*)")

#: The least length of a known value in its NFKC form (:class:`Masker`): what the engagement
#: file takes as the least length of a listed value.
_MIN_FOLDED_VALUE = 4


def _compared(text: str) -> str:
    """A masked text as two of them are compared: any horizontal white space as a space, and a
    pseudonym by its kind alone."""
    return _PSEUDONYM_DIGEST.sub(r"\1\2", _HORIZONTAL_SPACE.sub(" ", text))


def _literal_pattern(text: str) -> str:
    """A regular expression for ``text`` in any percent-encoding: each character as itself or
    as the ``%XX`` of its UTF-8 bytes, hex digits in either case, mixed within one string.
    The search stays linear: all alternatives have a fixed length and differ at the second
    character at the latest (a ``%`` itself is tried as ``%25`` first), so matching falls back
    over a fixed number of characters per character, not over the literal's length. A
    character in U+DC80 to U+DCFF, which stands for one byte that is no UTF-8
    (``surrogateescape``), has the ``%XX`` of that byte as one more alternative."""
    parts = []
    for char in text:
        forms = [char.encode("utf-8", "surrogatepass")]
        if "\udc80" <= char <= "\udcff":
            forms.append(bytes([ord(char) - 0xDC00]))
        alternatives = [
            "".join(
                "%" + "".join(f"[{d.lower()}{d.upper()}]" if d.isalpha() else d for d in f"{b:02x}")
                for b in form
            )
            for form in forms
        ]
        parts.append(f"(?:{'|'.join([*alternatives, re.escape(char)])})")
    return "".join(parts)


_T = TypeVar("_T")

_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_ESCAPED_RUN = re.compile(r"(?:\\u[0-9A-Fa-f]{4})+")
_ENCODED_RUN = re.compile(f"{_PERCENT_RUN.pattern}|{_ESCAPED_RUN.pattern}")


def _is_encoded(text: str, *, percent: bool = True) -> bool:
    """Whether ``text`` may hold a run :func:`_decoded_view` decodes."""
    return ("%" in text and percent) or "\\u" in text


def _decoded_view(text: str, percent: bool = True) -> tuple[str, list[int]]:
    """``text`` with every run of ``%XX`` decoded as UTF-8 and every run of ``\\uXXXX`` read as
    UTF-16 units (JSON's escape, as ``ensure_ascii`` writes it), and for each character of the
    result the place where it starts in ``text``, plus a last entry, ``len(text)``. A byte that
    is no UTF-8 becomes a lone surrogate, which no value holds, and still covers its three
    characters; so does a unit that is a surrogate without its partner, covering its six. A high
    and a low surrogate in a row are one character and cover twelve. No other encoding is read.
    With ``percent`` false the ``%XX`` runs stay as they are and only the ``\\uXXXX`` are read.
    Linear in the text."""
    out: list[str] = []
    starts: list[int] = []
    done = 0
    runs = _ENCODED_RUN if percent else _ESCAPED_RUN
    for run in runs.finditer(text):
        out.append(text[done : run.start()])
        starts.extend(range(done, run.start()))
        if run.group().startswith("%"):
            decoded = bytes.fromhex(run.group().replace("%", "")).decode("utf-8", "surrogateescape")
            widths = [3 * len(char.encode("utf-8", "surrogateescape")) for char in decoded]
        else:
            units = [int(unit, 16) for unit in run.group()[2:].split("\\u")]
            chars: list[str] = []
            widths = []
            index = 0
            while index < len(units):
                unit = units[index]
                if 0xD800 <= unit < 0xDC00 and index + 1 < len(units):
                    low = units[index + 1]
                    if 0xDC00 <= low < 0xE000:
                        chars.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
                        widths.append(12)
                        index += 2
                        continue
                chars.append(chr(unit))
                widths.append(6)
                index += 1
            decoded = "".join(chars)
        out.append(decoded)
        at = run.start()
        for width in widths:
            starts.append(at)
            at += width
        done = run.end()
    out.append(text[done:])
    starts.extend(range(done, len(text) + 1))
    return "".join(out), starts


def _merge_spans(found: list[tuple[int, int, _T]]) -> list[tuple[int, int, _T]]:
    """The spans ``(start, end, item)`` with those that overlap merged into one, which runs from
    the first start to the last end and keeps the item of the longest span among them (the
    first, of equal ones). Sorted, not overlapping. Linear, but for sorting."""
    found = sorted(found, key=lambda span: (span[0], span[0] - span[1]))
    merged: list[tuple[int, int, _T]] = []
    longest = 0
    for start, end, item in found:
        if merged and start < merged[-1][1]:
            first, last, kept = merged[-1]
            if end - start > longest:
                longest, kept = end - start, item
            merged[-1] = (first, max(last, end), kept)
        else:
            merged.append((start, end, item))
            longest = end - start
    return merged


def _prefer_decoded(
    written: list[tuple[int, int, _T]], decoded: list[tuple[int, int, _T]]
) -> list[tuple[int, int, _T]]:
    """The spans of the decoded view, with those of the text as written, sorted. A written span
    that overlaps decoded ones and ends at or before the end of the last of them is dropped: the
    decoded one is the value, and the written one only a piece of it cut by an encoding
    (``3Djane@x.example`` for ``mail%3Djane@x.example``). One that reaches further stays, and it
    and the decoded ones it overlaps are merged (:func:`_merge_spans`) into their union, so no
    rest of the value stands after the decoded span (``%20301234567`` after ``tel:+49``). A
    written span that overlaps none is kept as it is. Both lists are sorted and not overlapping,
    so one walk tells what overlaps; linear, but for sorting the result."""
    kept: list[tuple[int, int, _T]] = []
    index = 0
    for span in written:
        while index < len(decoded) and decoded[index][1] <= span[0]:
            index += 1
        last = index  # the last decoded span that starts before the written one ends
        while last < len(decoded) and decoded[last][0] < span[1]:
            last += 1
        # decoded[index:last] overlap the span; the walk goes on from the last of them, which
        # may overlap the next written span too.
        if last > index and decoded[last - 1][1] >= span[1]:
            continue
        kept.append(span)
    return _merge_spans([*decoded, *kept])


class Masker:
    """Applies the handle, structural, textual and personal-data rules. Immutable once
    constructed, but for the count of what it replaced (:attr:`replacements`)."""

    __slots__ = (
        "_clean_keys",
        "_counts",
        "_known",
        "_known_values",
        "_literals",
        "_needles",
        "_personal_salt",
        "_salt",
        "_secret_headers",
    )

    def __init__(
        self,
        extra_keys: Iterable[str] = (),
        *,
        handle_salt: bytes | None = None,
        literals: Iterable[str] = (),
        secret_headers: Iterable[str] = (),
        known_values: Iterable[str] = (),
        personal_salt: bytes | None = None,
    ) -> None:
        extra = {normalise_key(key) for key in extra_keys}
        self._needles = frozenset(DEFAULT_KEY_NEEDLES | {n for n in extra if n})
        # Values this run holds and must never write, in any percent-encoding (the token
        # of an identity, the value of a secret header): blanked wherever they stand in a
        # string, whatever the string is (:meth:`_blank_literals`). Longest first, so a literal
        # that holds another is blanked whole. Never kept apart from the pattern, which is
        # not reachable from outside.
        held = {text for text in literals if text}
        self._literals = (
            re.compile(
                "|".join(_literal_pattern(text) for text in sorted(held, key=len, reverse=True))
            )
            if held
            else None
        )
        # The engagement's known values, replaced by a pseudonym wherever they stand, as written
        # or percent-encoded (:func:`_decoded_view`), longest first (:meth:`_pseudonymise`). A
        # plain alternation of the escaped values: it is searched twice, in the text and in its
        # decoded view, and the match is the value.
        # A value is looked for as listed, in its composed form, NFC (one listed with a
        # decomposed accent, as some systems write file names, and sent composed), and in its
        # NFKC form (one listed with a no-break space, a ligature or in full width, as copied
        # from a document, and sent plain); each is the listed value, with its pseudonym. The
        # NFKC form only where it is a value the list would take: long enough without the white
        # space around it, and of a listed value that holds no number that is no digit, or a
        # value listed in circled digits would make the digits ``1234`` a value in every number.
        listed = sorted({text for text in known_values if text})
        forms = {text: text for text in listed}
        for text in listed:
            forms.setdefault(unicodedata.normalize("NFC", text), text)
        for text in listed:
            folded = unicodedata.normalize("NFKC", text)
            if len(folded.strip()) >= _MIN_FOLDED_VALUE and not any(
                unicodedata.category(c) == "No" for c in text
            ):
                forms.setdefault(folded, text)
        known = sorted(forms, key=len, reverse=True)
        self._known_values = forms
        self._known = re.compile("|".join(re.escape(text) for text in known)) if known else None
        self._counts = dict.fromkeys(PERSONAL_KINDS, 0)
        # Keys the walk found nothing in, so that the names a protocol repeats in every message
        # (``name``, ``type``, ``description``) are not masked again each time. Only a key whose
        # masking changed nothing and counted nothing is kept, and the set is bounded: what the
        # masker finds in a key does not change during a run. Short keys only
        # (:data:`_CLEAN_KEY_LENGTH`).
        self._clean_keys: set[str] = set()
        # Header names this run treats as secret, compared without case: blanked whole in a
        # request and in a response, as :data:`BLANKED_HEADERS` are, sent by us or not.
        self._secret_headers = frozenset(name.strip().lower() for name in secret_headers if name)
        # Fresh per Masker, and a Masker lives for one run. That is what keeps a pseudonym
        # stable inside a recording and meaningless between two of them: the same handle
        # seen in two sessions gets two unrelated pseudonyms, so recordings cannot be
        # cross-referenced by them. The salt is never recorded and never leaves this object.
        self._salt = secrets.token_bytes(16) if handle_salt is None else handle_salt
        # The salt of the personal-data pseudonyms: the engagement's, which makes them stable
        # across its runs, or, where none is given, the run's own, which keeps them stable inside
        # this run only. Never recorded either.
        self._personal_salt = self._salt if personal_salt is None else personal_salt

    @property
    def pseudonyms(self) -> str:
        """How long the pseudonyms of personal data last (:data:`PSEUDONYM_SCOPES`): across the
        runs of an engagement where it gave the salt, inside this run otherwise."""
        return PSEUDONYM_SCOPES[self._personal_salt is self._salt]

    @property
    def replacements(self) -> dict[str, int]:
        """How many values of each of :data:`PERSONAL_KINDS` this masker has replaced so far, in
        text it returned. Not counted in what :meth:`mask_text` returns: a pseudonym is
        substituted by design, as a handle is, and no credential was let out."""
        return dict(self._counts)

    @contextlib.contextmanager
    def uncounted(self) -> Iterator[None]:
        """Mask inside the block as usual, but leave :attr:`replacements` as it was. For text that
        names a value of a message that was recorded, and counted, where it was first written
        (its payload): the same masking, the value not counted twice."""
        before = dict(self._counts)
        try:
            yield
        finally:
            self._counts = before

    def personal_pseudonym(self, kind: str, canonical: str) -> str:
        """The stand-in for one value of ``kind`` in :data:`PERSONAL_KINDS` or in the kinds of the
        token inspector (``token_inspector.PSEUDONYM_KINDS``), flanked like a handle:
        ``***EMAIL-<12 hex>***`` and so on. HMAC-SHA256 under the personal salt over the kind, a
        NUL and the canonical value; for ``email`` that is the address in lower case, so a ``upn``
        that is an address seen in the traffic gives the same pseudonym. Any other kind is
        refused."""
        if kind not in PERSONAL_KINDS and kind not in TOKEN_KINDS:
            raise ValueError(f"no pseudonym for the kind {kind!r}")
        if kind == "email":
            canonical = canonical.lower()
        # surrogatepass, as for handles: the traffic may hold a lone surrogate.
        material = f"{kind}\0{canonical}".encode("utf-8", "surrogatepass")
        digest = hmac.new(self._personal_salt, material, hashlib.sha256).hexdigest()
        return f"***{kind.upper()}-{digest[:HANDLE_DIGEST_LENGTH]}***"

    def _pseudonymise(self, text: str, *, percent: bool = True) -> str:
        """The known values, then the three shapes (:func:`_personal_spans`), each replaced by
        its pseudonym and counted. The known values go first, and so what they hold is not
        looked at again. With a ``%`` or a ``\\u`` in the text the shapes are looked for in two
        views, as written and decoded (:func:`_decoded_view`). A span of the decoded view that
        overlaps one as written replaces it, or, if the written one reaches further, is merged
        with it (:func:`_prefer_decoded`), and each is replaced by
        the pseudonym of its canonical value, counted once for its kind (``j\\u00fcrgen@x.example``
        and ``jürgen@x.example`` get one pseudonym; ``mail%3Djane@x.example`` is ``mail%3D`` and
        the pseudonym of ``jane@x.example``). With ``percent`` false the ``%XX`` runs are not
        decoded in that view, as for a header, where :meth:`_scrub` blanks an address that only
        a percent-decoding shows; ``\\uXXXX`` is read as ever, and so are the known values in
        every view."""
        if self._known is not None:
            text = self._replace_known(self._known, text)
        found = [
            (start, end, (kind, canonical)) for start, end, kind, canonical in _personal_spans(text)
        ]
        if _is_encoded(text, percent=percent):
            decoded, starts = _decoded_view(text, percent)
            found = _prefer_decoded(
                found,
                [
                    (starts[start], starts[end], (kind, canonical))
                    for start, end, kind, canonical in _personal_spans(decoded)
                ],
            )
        if not found:
            return text
        out: list[str] = []
        done = 0
        for start, end, (kind, canonical) in found:
            out += [text[done:start], self.personal_pseudonym(kind, canonical)]
            self._counts[kind] += 1
            done = end
        out.append(text[done:])
        return "".join(out)

    def _replace_known(self, pattern: re.Pattern[str], text: str) -> str:
        """The known values in ``text`` replaced by their pseudonyms and counted. Without a ``%``
        or a ``\\u`` that is one plain substitution. With one, the matches are collected first,
        as spans of ``text``: those of the text as written, and those of its decoded view
        (:func:`_decoded_view`), mapped back to the span they cover in the original. Spans that
        overlap are merged into one (:func:`_merge_spans`), replaced whole by the pseudonym of
        the value of the longest span among them and counted once: the longer value wins in
        whatever form it is written (``M%C3%BCller%20GmbH`` is ``Müller GmbH``, not ``Müller``
        and ``%20GmbH``), and a value both views find at the same place counts once. The text
        between the spans stays as it is. Linear in the text, but for sorting the matches.

        A value that holds ``%XX`` itself (``a%41``) is found as written and with the ``%``
        fully encoded (``a%2541``), but not in a mixture that decodes to something else
        (``%61%41``)."""
        if not _is_encoded(text):

            def known(found: re.Match[str]) -> str:
                self._counts["known"] += 1
                return self.personal_pseudonym("known", self._known_values[found.group()])

            return pattern.sub(known, text)
        found = [(m.start(), m.end(), m.group()) for m in pattern.finditer(text)]
        decoded, starts = _decoded_view(text)
        found += [
            (starts[m.start()], starts[m.end()], m.group()) for m in pattern.finditer(decoded)
        ]
        if not found:
            return text
        out: list[str] = []
        done = 0
        for start, end, value in _merge_spans(found):
            out += [text[done:start], self.personal_pseudonym("known", self._known_values[value])]
            self._counts["known"] += 1
            done = end
        out.append(text[done:])
        return "".join(out)

    def _finds_known(self, text: str) -> bool:
        """Whether ``text`` holds a known value as written or, if it has a ``%`` or a ``\\u``,
        decoded."""
        if self._known is None:
            return False
        if self._known.search(text) is not None:
            return True
        return _is_encoded(text) and self._known.search(_decoded_view(text)[0]) is not None

    def _holds_personal(self, text: str) -> bool:
        """Whether ``text`` holds a known value or one of the three shapes; nothing is counted."""
        if self._finds_known(text) or _personal_spans(text):
            return True
        return _is_encoded(text) and bool(_personal_spans(_decoded_view(text)[0]))

    @property
    def looks_for_values(self) -> bool:
        """Whether :meth:`holds_known_value` can find anything at all: this masker has a literal
        or a known value."""
        return self._literals is not None or self._known is not None

    def holds_known_value(self, text: str) -> bool:
        """Whether ``text`` holds a known value or a literal of this run, as written or
        percent-encoded, in the text, in its normalised copy (:func:`_normalised_copy`) or in
        the normalised copy of its decoded view: the search the masker itself makes, and no
        other. The three shapes are no part of it. Nothing is counted."""
        if self._literals is None and self._known is None:
            return False
        copy = _normalised_copy(text)
        for form in (text,) if copy is None or copy == text else (text, copy):
            if self._literals is not None and self._literals.search(form) is not None:
                return True
            if self._finds_known(form):
                return True
        return self._shows_when_decoded(text)

    def _shows_when_decoded(self, text: str, *, known: bool = True) -> bool:
        """Whether ``text``, percent-decoded and then read as its normalised copy, holds a
        literal or, with ``known``, a known value: a spelling NFKC folds, written as ``%XX`` (a
        no-break space as ``%C2%A0`` in a known value). Asked of a text after it was masked, it
        says whether such a value still shows; the caller then replaces the whole value.
        ``known`` is false where the text was read without its known values replaced
        (``personal`` false): they stand in it by design. A pseudonym is read by its kind
        alone, so that no value is found in a digest: one as it stands in the text, taken out
        before the decoding. What only the decoding makes look like a pseudonym is none, and
        is read."""
        if "%" not in text or (self._literals is None and (self._known is None or not known)):
            return False
        decoded = _decoded_view(_PSEUDONYM_DIGEST.sub(r"\1\2", text))[0]
        copy = _normalised_copy(decoded)
        if copy is None or copy == decoded:
            return False
        if self._literals is not None and self._literals.search(copy) is not None:
            return True
        return known and self._known is not None and self._known.search(copy) is not None

    def is_known_value(self, text: str) -> bool:
        """Whether ``text`` is, whole, a literal of this run (in any percent-encoding) or a known
        value as written: for a text in which a part that reads like a value can stand by chance
        and the whole cannot. Nothing is counted."""
        if self._literals is not None and self._literals.fullmatch(text) is not None:
            return True
        return self._known is not None and self._known.fullmatch(text) is not None

    def _is_value(self, name: str) -> bool:
        """Whether a name holds a value this run replaces: a literal, a credential's shape, a
        known value or one of the three shapes. Counts nothing. A name is shown or replaced
        whole, never masked in part, so a known value is looked for in every reading of it
        (:meth:`holds_known_value`)."""
        return (
            bool(self._mask_shapes(name, personal=False)[1])
            or self._holds_personal(name)
            or self.holds_known_value(name)
        )

    def pseudonym(self, value: Any) -> str:
        """The stable stand-in for one protocol handle, within this run.

        Keyed HMAC rather than a plain hash: without the salt the digest cannot be compared
        against a guessed value, so a recording does not become an oracle for whoever reads
        it. The value's type is part of the input, so the number ``1`` and the string ``"1"``
        do not collapse into one handle.
        """
        tag = "n" if isinstance(value, (int, float)) and not isinstance(value, bool) else "s"
        # surrogatepass: a name from the traffic may hold a lone surrogate, and must not raise.
        material = f"{tag}:{value}".encode("utf-8", "surrogatepass")
        digest = hmac.new(self._salt, material, hashlib.sha256).hexdigest()
        return f"{HANDLE_PREFIX}{digest[:HANDLE_DIGEST_LENGTH]}{HANDLE_SUFFIX}"

    @property
    def needles(self) -> frozenset[str]:
        return self._needles

    def is_secret_key(self, key: str) -> bool:
        normalised = normalise_key(key)
        return any(needle in normalised for needle in self._needles)

    def mask_text(self, text: str, *, personal: bool = True) -> tuple[str, int]:
        """Apply the shape-based rules to a single string, then the rule for ``name=value``
        pairs (:meth:`_mask_pairs`): a name that is, or holds, a secret's name loses its value,
        in prose and in JSON values alike (``api_key=…``, ``token = '…'``). With ``personal``
        false the text is read to see what is in it and nothing of personal data is replaced or
        counted."""
        return self._mask_text(text, personal=personal)

    def _mask_text(
        self, text: str, *, personal: bool = True, percent: bool = True
    ) -> tuple[str, int]:
        """:meth:`mask_text`, with ``percent`` as in :meth:`_mask_shapes`, and the normalised
        copy read as there (:meth:`_copy_differs`), the pair rule included."""
        masked, count = self._shapes(text, personal=personal, percent=percent)
        masked, hits = self._mask_pairs(masked)
        if self._copy_differs(
            text, masked, pairs=True, personal=personal, percent=percent
        ) or self._shows_when_decoded(masked, known=personal):
            return PLACEHOLDER, count + hits + 1
        return masked, count + hits

    def mask_decoded(self, forms: Sequence[str]) -> str:
        """The text of a value that is written as it was sent (``forms[0]``) and has been
        percent-decoded (``forms[1:]``, the last the most decoded), masked. The written form
        stays exactly when both ways give the same text: masking it and then decoding it as far
        as ``forms[-1]`` (``urllib.parse.unquote``, once per step), or decoding first and then
        masking, ``decode(mask(forms[0])) == mask(forms[-1])``. Otherwise an encoding cuts a
        value in two (``j%C3%BCrgen@host`` has ``BCrgen@host`` as its local part as written),
        and the most decoded form is the one masked and written, with the pseudonym of the whole
        value. A value that already stands in the written form is masked there, and the other
        escapes stay (``/call/tel:+49…/a%20b`` keeps ``%20``). A pseudonym and the placeholder
        hold no ``%``, so decoding leaves them as they are. Only the form written is counted.
        The shapes are looked for in each form as written and with its ``\\uXXXX`` read, not with
        its ``%XX`` decoded (the forms are that already). Credentials in a decoding are not this
        method's: a caller blanks the value for them first (``mask_text(…, personal=False)``)."""
        if len(forms) < 2:
            return self._mask_text(forms[0], percent=False)[0]
        before = dict(self._counts)
        written = self._mask_text(forms[0], percent=False)[0]
        counted, self._counts = self._counts, before
        decoded = self._mask_text(forms[-1], percent=False)[0]
        way_round = written
        for _ in range(len(forms) - 1):
            way_round = urllib.parse.unquote(way_round)
        if way_round != decoded:
            return decoded
        self._counts = counted
        return written

    def _blank_literals(self, text: str) -> tuple[str, int]:
        """Every occurrence of a literal of this run as :data:`PLACEHOLDER`: one in which each
        character stands as itself or as the ``%XX`` of its UTF-8 bytes, either case of the hex
        digits (:func:`_literal_pattern`)."""
        if self._literals is None:
            return text, 0
        return self._literals.subn(PLACEHOLDER, text)

    def mask_key(self, key: str) -> str:
        """A name that stands where a JSON key would, masked as a key is: as a value is
        (:meth:`mask_text`). A key can carry a literal, a known value, personal data or a
        credential (a server that echoes a name, a ``name=secret`` pair written as a key)."""
        return self.mask_text(key)[0]

    def _mask_shapes(
        self, text: str, *, personal: bool = True, percent: bool = True
    ) -> tuple[str, int]:
        """The text rules alone, without the pair rule: what the HTTP functions read with, since
        they have their own (:meth:`_mask_embedded_query`). In this order: the run's literals,
        the known values and the three shapes of personal data (:meth:`_pseudonymise`), the
        other rules. The count is that of the credentials replaced; the personal data is
        counted in :attr:`replacements`, and not at all with ``personal`` false, which is for a
        text read to see what is in it. With ``percent`` false the ``%XX`` runs are not decoded
        for the three shapes (:meth:`_pseudonymise`).

        A normalised copy of the text is read as well (:meth:`_copy_differs`): where a reader of
        the copy would see something the masking of the copy takes out, the whole value is
        replaced and counted as one more match."""
        masked, count = self._shapes(text, personal=personal, percent=percent)
        if self._copy_differs(
            text, masked, pairs=False, personal=personal, percent=percent
        ) or self._shows_when_decoded(masked, known=personal):
            return PLACEHOLDER, count + 1
        return masked, count

    def _shapes(self, text: str, *, personal: bool = True, percent: bool = True) -> tuple[str, int]:
        """:meth:`_mask_shapes` on the text as written, without the normalised copy."""
        text, count = self._blank_literals(text)
        if personal:
            text = self._pseudonymise(text, percent=percent)
        return self._rules(text, count)

    @staticmethod
    def _rules(text: str, count: int = 0) -> tuple[str, int]:
        for pattern, replacement in _TEXT_RULES:
            text, hits = pattern.subn(replacement, text)
            count += hits
        return text, count

    def _copy_differs(
        self, text: str, masked: str, *, pairs: bool, personal: bool, percent: bool
    ) -> bool:
        """Whether ``masked``, read as its normalised copy (:func:`_normalised_copy`), is
        anything other than the normalised copy of ``text`` masked by the same rules (the pair
        rule only with ``pairs``), horizontal white space aside. Where the two differ in any
        way, the caller replaces the whole value: also where the text's own masking hid as much
        (a match that only ends elsewhere in the copy), since spans are not compared. A copy
        that outgrows its text (:data:`_COPY_GROWTH`) is not masked, and counts as differing.

        Spans of the copy are not mapped back onto the text. Where they differ, a match of the
        copy is one the spelling hid (``Ｂearer``, ``Bea<U+200B>rer``, ``\\x20sk-…``), or the
        rest of a token the text matched only up to an invisible character, or a match the
        normalisation destroyed beside one it revealed; comparing counts instead would let the
        last pay for the second. Where they are equal, the text's own masking already shows a
        reader of the copy nothing that masking the copy would not (a URL whose ``@`` is written
        ``\\u0040``, masked by the rule for encoded URLs), and its spans stand. A pseudonym is
        compared by its kind alone: NFKC may compose the canonical form of a value (``re`` and a
        combining accent), and with it the digest, but not what was replaced. Nothing of the
        second masking is counted. Costs nothing where the copy is the text."""
        copy = _normalised_copy(text)
        if copy is None or copy == text:
            return False
        if len(copy) > _COPY_GROWTH * len(text) + _COPY_SLACK:
            return True
        with self.uncounted():
            seen, _ = self._shapes(copy, personal=personal, percent=percent)
            if pairs:
                seen, _ = self._mask_pairs(seen)
        shown = _normalised_copy(masked)
        if shown is None:
            shown = masked
        return _compared(seen) != _compared(shown)

    def _mask_pairs(self, text: str) -> tuple[str, int]:
        """Blank the value of a ``name=value`` in text whose name is a secret's.

        The name is read as in :meth:`_mask_embedded_query` (after the start or a character of
        :data:`_SEPARATORS`, percent-decoded), with horizontal white space allowed around the
        ``=``. What decides is the needle: a name holding none is kept with its value — base64
        padding (``SGVsbG8=``) and hex runs fill text, and unlike in HTTP they are not blanked.
        A name holding one, one of :data:`COMMON_SECRET_NAMES` (``code``, ``sig``), or one an
        earlier rule has replaced already (``sk-token-…=``), loses
        its value; it keeps itself only as one of :data:`COMMON_SECRET_NAMES` that reads like a
        name (:data:`_EMBEDDED_NAME`, :func:`_plain_name`), and otherwise goes too
        (``token_abc``, ``author``, ``{api_key``, ``Config{apiKey``): fail closed, as in HTTP.
        The value runs to the end of the line or the next ``&``, ``;`` or ``#`` outside quotes
        and angle brackets (:func:`_value_end`), whichever is first; an empty one does not
        count, nor does one an earlier rule has replaced whole behind a name that stays.
        Meant to run after the other text rules, which need ``Bearer`` still standing.
        Linear: a name is read once, a blanked value is skipped once, and the white space
        before an ``=`` is read only for the name in front of it.
        """
        count = 0
        rewritten = False
        out: list[str] = []
        position = 0
        for match in _PAIR_NAME_AT.finditer(text):
            if match.start(2) < position:
                continue  # inside a value already blanked
            written = match.group(2)
            name = _decodings(written)[-1]
            replaced = PLACEHOLDER in written
            common = normalise_key(name) in COMMON_SECRET_NAMES
            if not replaced and not common and not self.is_secret_key(name):
                continue
            readable = (
                not replaced
                and len(name) <= MAX_NAME_LENGTH
                and _EMBEDDED_NAME.fullmatch(name) is not None
                and _plain_name(name)
            )
            shown = written if readable and common else PLACEHOLDER
            start = _skip_blanks(text, _skip_blanks(text, match.end(2)) + 1)
            stop = _value_end(text, start, lines=True)
            if stop == start:
                continue
            out.append(text[position : match.start(2)])
            out.append(f"{shown}={PLACEHOLDER}")
            position = stop
            # A value an earlier rule replaced whole, behind a name that stays, was counted there.
            count += not (shown == written and text[start:stop] == PLACEHOLDER)
            rewritten = True
        if not rewritten:
            return text, 0
        out.append(text[position:])
        return "".join(out), count

    def mask_json(self, value: Any) -> tuple[Any, list[str]]:
        """Mask a parsed JSON document, returning the copy and the paths that were hit."""
        paths: list[str] = []
        return self._walk(value, "", paths), paths

    def _mask_json_http(self, value: Any) -> tuple[Any, list[str]]:
        """:meth:`mask_json` without the pair rule, for what HTTP has scrubbed already."""
        paths: list[str] = []
        return self._walk(value, "", paths, pairs=False), paths

    def mask_argv(
        self, argv: Sequence[str], verbatim_paths: Collection[VerbatimPath] = ()
    ) -> tuple[list[str], int]:
        """Reduce a server command line to what is safe to record.

        Two reductions, both deliberate: ``argv[0]`` keeps only its basename, because a
        full path says where a client's tooling lives; and any argument that carries a
        credential is replaced. Both ``--api-key=VALUE`` and ``--api-key VALUE`` are
        handled, since a secret passed on the command line is at least as common as one
        sent over the wire.

        After a secret flag without ``=`` (``--password``) the next argument is replaced
        whatever it is, ``-hunter2`` and ``--x`` included, except exactly ``--``. If that
        argument is itself a secret flag (``--token --api-key X``), the one after it is
        replaced too: fail closed.

        Every URL in an argument (:func:`withhold_url_path`), wherever it starts (alone, behind
        ``--flag=``, behind ``NAME=``), keeps its path only when its host, effective port and
        path are one of ``verbatim_paths``; otherwise the path's place holds :func:`withheld_path`.
        """
        masked: list[str] = []
        count = 0
        previous_flag_is_secret = False

        for index, argument in enumerate(argv):
            if index == 0:
                masked.append(os.path.basename(argument))
                previous_flag_is_secret = False
                continue

            if previous_flag_is_secret and argument != "--":
                masked.append(PLACEHOLDER)
                count += 1
                previous_flag_is_secret = argument.startswith("-") and self.is_secret_key(
                    argument.lstrip("-")
                )
                continue

            if argument.startswith("-") and "=" in argument:
                flag, _, _value = argument.partition("=")
                if self.is_secret_key(flag.lstrip("-")):
                    masked.append(f"{flag}={PLACEHOLDER}")
                    count += 1
                    previous_flag_is_secret = False
                    continue

            previous_flag_is_secret = argument.startswith("-") and self.is_secret_key(
                argument.lstrip("-")
            )
            # The text rules run over each URL with a stand-in for its path, so that they see
            # the shape they always saw; the withheld form takes the stand-in's place after.
            urls = _urls_to_withhold(argument, verbatim_paths)
            if urls:
                argument = _replace_paths(
                    argument, urls, [f"{_PATH_STAND_IN}{n}_" for n in range(len(urls))]
                )
            text, hits = self.mask_text(argument)
            for n, url in enumerate(urls):
                text = text.replace(f"{_PATH_STAND_IN}{n}_", withheld_path(url["path"]), 1)
            masked.append(text)
            count += hits

        return masked, count

    # -- HTTP (docs/design/http-transport.md, 2.5, 2.6, 2.8). The recorder calls these.

    def mask_headers(
        self, headers: Mapping[str, str] | Iterable[tuple[str, str]]
    ) -> tuple[dict[str, Any], list[str]]:
        """Mask HTTP headers as a map, returning the map and the paths that were hit.

        Header names compare without case, so the map is keyed by the lower-cased name; a
        header sent more than once maps to the list of its values, in order.

        * :data:`BLANKED_HEADERS` are blanked whole, and so are the run's secret headers.
        * ``WWW-Authenticate`` is parsed first (:data:`PARSED_HEADER`); if it does not parse,
          it is blanked whole.
        * ``Last-Event-ID`` is pseudonymised (:data:`HEADER_HANDLES`).
        * A name that does not read like one (:func:`_plain_name`, at most
          :data:`MAX_NAME_LENGTH` characters) keeps neither name nor value: the name becomes a
          pseudonym, the value is blanked.
        * Every other header goes through the ordinary rules as one key of a JSON object, and a
          credential in a ``name=value`` inside its value (``?access_token=…``,
          ``#access_token=…``) is blanked too (:meth:`_scrub`).

        Names are stripped of surrounding whitespace before they are compared. Anything but
        pairs of strings — bytes, ``None``, a pair of the wrong length — blanks the whole map.
        """
        pairs = headers.items() if isinstance(headers, Mapping) else headers
        if isinstance(pairs, (str, bytes)) or not isinstance(pairs, Iterable):
            return {PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER]
        grouped: dict[str, list[str]] = {}
        for pair in pairs:
            if not (
                isinstance(pair, (tuple, list))
                and len(pair) == 2
                and isinstance(pair[0], str)
                and isinstance(pair[1], str)
            ):
                return {PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER]
            grouped.setdefault(pair[0].strip(), []).append(pair[1])
        lowered: dict[str, list[str]] = {}
        for written, values in grouped.items():
            name = written.lower()
            if not (
                _HEADER_NAME.fullmatch(written)
                and _plain_name(written)
                and not self._is_value(written)
            ):
                name = self.pseudonym(name)
                values = [PLACEHOLDER] * len(values)
            lowered.setdefault(name, []).extend(values)
        masked: dict[str, Any] = {}
        paths: list[str] = []
        for name, values in lowered.items():
            if name.startswith(HANDLE_PREFIX):
                masked[name] = values[0] if len(values) == 1 else values
                paths.append(_clip(name))
                continue
            if name in BLANKED_HEADERS or name in self._secret_headers:
                masked[name] = PLACEHOLDER
                paths.append(_clip(name))
                continue
            if name == PARSED_HEADER:
                challenges = self._mask_challenges(name, values, paths)
                masked[name] = PLACEHOLDER if challenges is None else challenges
                if challenges is None:
                    paths.append(_clip(name))
                continue
            if name in HEADER_HANDLES:
                handles = [self.mask_event_id(value) for value in values]
                masked[name] = handles[0] if len(handles) == 1 else handles
                paths.append(_clip(name))
                continue
            cleaned = []
            for value in values:
                text, hits = self._scrub(value)
                cleaned.append(text)
                if hits:
                    paths.append(_clip(name))
            document, hit = self._mask_json_http(
                {name: cleaned[0] if len(cleaned) == 1 else cleaned}
            )
            masked.update(document)
            paths.extend(path for path in hit if path not in paths)
        return masked, list(dict.fromkeys(paths))

    def mask_query(self, query: str) -> tuple[dict[str, Any], list[str]]:
        """Mask a URL's query string as a map, returning the map and the paths that were hit.

        Split at ``&`` and at ``;`` — some servers read both — and percent-decoded until
        nothing changes (at most :data:`MAX_DECODINGS` times; ``+`` is a space in the first
        round only), so ``api%5Fkey`` and ``api%255Fkey`` meet the needle ``apikey``, and
        ``Bearer%2520…`` the text rule for ``Bearer …``. A value whose earlier decodings hold a
        credential is blanked whole (:meth:`_scrub`). A name given more than once maps to the
        list of its values, in order; names keep their case. Then masked like a JSON object.

        A name is kept as written only if it reads like one: at most 32 characters of letters,
        digits, ``_``, ``-``, ``.`` and brackets, plain (:func:`_plain_name`), no credential
        shape, and — if it holds a needle — one of :data:`COMMON_SECRET_NAMES`. Any other name,
        and a field without ``=`` (a bare token in the query), keeps neither name nor value: the
        name becomes a pseudonym, the value is blanked. The value of a name in
        :data:`COMMON_SECRET_NAMES` is blanked whatever the needles are. More than
        :data:`MAX_QUERY_FIELDS` fields, and the query is blanked whole.

        A fragment passed along (``a=1#access_token=…``, where an OAuth server puts a token) is
        masked the same way and kept under the key ``#``: a field cannot be named ``#``, since
        the query is cut there.
        """
        if not isinstance(query, str):
            return {PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER]
        query, hash_mark, fragment = query.partition("#")
        masked, paths = self._mask_fields(query)
        if hash_mark:
            inner, inner_paths = self._mask_fields(fragment)
            masked["#"] = inner
            paths.extend(_clip(f"#.{path}") for path in inner_paths)
        return masked, list(dict.fromkeys(paths))

    def _mask_fields(self, query: str) -> tuple[dict[str, Any], list[str]]:
        fields: list[str] = []
        for match in _QUERY_FIELD.finditer(query):
            if len(fields) == MAX_QUERY_FIELDS:
                return {PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER]
            fields.append(match.group(0))
        grouped: dict[str, list[str]] = {}
        paths: list[str] = []
        for field in fields:
            raw_name, equals, raw_value = field.partition("=")
            name = _decodings(raw_name, form=True)[-1]
            if not equals or not self._readable_name(name):
                key = self.pseudonym(name)
                grouped.setdefault(key, []).append(PLACEHOLDER)
                paths.append(_clip(key))
                continue
            if normalise_key(name) in COMMON_SECRET_NAMES:
                value, hits = PLACEHOLDER, 1
            else:
                value, hits = self._scrub(raw_value, form=True)
            if hits:
                paths.append(_clip(name))
            grouped.setdefault(name, []).append(value)
        document = {
            name: values[0] if len(values) == 1 else values for name, values in grouped.items()
        }
        masked, hit = self._mask_json_http(document)
        return masked, paths + [path for path in hit if path not in paths]

    def mask_event_id(self, event_id: str) -> str:
        """The pseudonym of one SSE event id, the same one its ``Last-Event-ID`` gets (2.6).

        An id ties a resumption to its stream, which is what a handle is for; a server may fold
        its session into it, so the value is never kept. The empty id is kept as it is: it
        resets the stream's last event id and carries no value.
        """
        return "" if event_id == "" else self.pseudonym(event_id)

    def _readable_name(self, name: str) -> bool:
        if not _READABLE_NAME.fullmatch(name) or not _plain_name(name):
            return False
        if self._is_value(name):
            return False
        return not self.is_secret_key(name) or normalise_key(name) in COMMON_SECRET_NAMES

    def _scrub(self, text: str, *, form: bool = False) -> tuple[str, int]:
        """One value from HTTP, masked in the form it is kept in, or blanked whole.

        The value is read as written and percent-decoded up to :data:`MAX_DECODINGS` times —
        ``+`` read as a space only in the first round and only in a query (``form``): form
        encoding is one layer, and ``%252B`` decoded twice is a ``+``, not a space that would
        cut a token in two. A header keeps the value as written, a query its last decoding.

        The value is blanked whole if any other form holds a credential — a text rule or a
        ``name=value`` that :meth:`_mask_embedded_query` would blank — and if any form does
        once each ``+`` is read as a space (a reader that takes the value as a form does), or
        if it still decodes after the last round: the form kept cannot be trusted to hide it.
        """
        forms = _decodings(text, form=form)
        kept = len(forms) - 1 if form else 0
        if urllib.parse.unquote(forms[-1]) != forms[-1]:
            return PLACEHOLDER, 1
        for index, other in enumerate(forms):
            # In a query, the first round already read "+" as a space.
            plus = "+" in other and not (form and index == 0)
            readings = [other.replace("+", " ")] if plus else []
            if index != kept:
                readings.append(other)
            if any(
                self._mask_shapes(r, personal=False)[1] or self._mask_embedded_query(r)[1]
                for r in readings
            ):
                return PLACEHOLDER, 1
        # The text rules first: blanking a pair's value would otherwise take "Bearer" with it
        # and leave the token behind it standing for the rule that needs both.
        counted = dict(self._counts)
        text, hits = self._mask_shapes(forms[kept], percent=False)
        text, more = self._mask_embedded_query(text)
        # A known value or an address that the form kept does not show but another decoding of it
        # does (``a%40b.test`` in a header) is not replaced where it stands: blanked whole, as a
        # credential in another decoding is. What was replaced in the text is not written, so it
        # is not counted: each value in the most decoded form is, once, for its kind. The
        # blanking is no credential's: only the credentials found count as hits.
        for other in _decodings(text)[1:]:
            if self._holds_personal(other):
                self._counts.update(counted)
                self._pseudonymise(forms[-1])
                return PLACEHOLDER, hits + more
        return text, hits + more

    def _mask_embedded_query(self, text: str) -> tuple[str, int]:
        """Blank what a credential in a ``name=value`` inside ``text`` could be: in a URL's query
        or fragment that a header or a parameter carries, or standing on its own.

        A name is read after any of :data:`_SEPARATORS` — ``?``, ``&``, ``;``, ``#``, ``=``,
        ``,``, ``|``, ``/``, ``:``, whitespace, a quote, an opening bracket, an angle bracket —
        or at the start, so a pair inside another pair's value (``a=1,access_token=…``,
        ``note=access_token=…``, ``<b>token=…``) is read too: no value is passed over unread.
        What it does with the name, percent-decoded:

        * it does not read like one — longer than :data:`MAX_NAME_LENGTH`, not plain
          (:func:`_plain_name`), outside letters, digits, ``_``, ``-``, ``.``, brackets and a
          final ``*`` (RFC 8187), or a credential's shape: name and value are blanked;
        * it holds a needle and is not one of :data:`COMMON_SECRET_NAMES` (``token_<x>``): name
          and value are blanked, as in a query;
        * it is one of :data:`COMMON_SECRET_NAMES`, or holds a needle: the value is blanked;
        * anything else is kept.

        A blanked value runs from the ``=`` to the next ``&``, ``;`` or ``#`` outside quotes and
        angle brackets, or to the end (:func:`_value_end`): greedy, so neither spaces, nor
        quotes, nor markup leave part of it standing. Linear: no character that may stand
        before a name can be part of one, and a blanked value is skipped once.
        """
        count = 0
        out: list[str] = []
        position = 0
        for match in _EMBEDDED_NAME_AT.finditer(text):
            if match.start(2) < position:
                continue  # inside a value already blanked
            written = match.group(2)
            name = _decodings(written)[-1]
            if (
                len(name) > MAX_NAME_LENGTH
                or not _EMBEDDED_NAME.fullmatch(name)
                or not _plain_name(name)
                or self._is_value(name)
            ):
                shown = PLACEHOLDER
            elif normalise_key(name) in COMMON_SECRET_NAMES:
                shown = written
            elif self.is_secret_key(name):
                shown = PLACEHOLDER
            else:
                continue
            stop = _value_end(text, match.end() + 1)
            out.append(text[position : match.start(2)])
            out.append(f"{shown}={PLACEHOLDER}")
            position = stop
            count += 1
        if not count:
            return text, 0
        out.append(text[position:])
        return "".join(out), count

    def _mask_challenges(
        self, name: str, values: Sequence[str], paths: list[str]
    ) -> list[dict[str, Any]] | None:
        """``WWW-Authenticate`` parsed and masked; ``None`` if it does not parse."""
        challenges: list[dict[str, Any]] = []
        for value in values:
            parsed = parse_challenges(value)
            if parsed is None:
                return None
            challenges.extend(parsed)
        if len(challenges) > MAX_CHALLENGES:
            return None
        masked: list[dict[str, Any]] = []
        found: list[str] = []
        for index, challenge in enumerate(challenges):
            where = f"{name}[{index}]"
            scheme = challenge["scheme"]
            if scheme.lower() not in KNOWN_SCHEMES:
                scheme = PLACEHOLDER
                found.append(_clip(f"{where}.scheme"))
            entry: dict[str, Any] = {"scheme": scheme}
            if "token68" in challenge:
                # A bare token after the scheme (Negotiate, for one) is a credential's shape.
                entry["token68"] = PLACEHOLDER
                found.append(_clip(f"{where}.token68"))
                masked.append(entry)
                continue
            params: dict[str, Any] = {}
            for key, value in challenge["params"].items():
                if key not in KNOWN_CHALLENGE_PARAMS:
                    hidden = self.pseudonym(key)
                    params[hidden] = PLACEHOLDER
                    found.append(_clip(f"{where}.params.{hidden}"))
                    continue
                value, hits = self._scrub(value)
                document, hit = self._mask_json_http({key: value})
                params.update(document)
                if hits or hit:
                    found.append(_clip(f"{where}.params.{key}"))
            entry["params"] = params
            masked.append(entry)
        paths.extend(found)
        return masked

    def _walk(
        self,
        value: Any,
        path: str,
        paths: list[str],
        *,
        pairs: bool = True,
        origin: str | None = None,
    ) -> Any:
        """Copy ``value`` with its strings, and the keys of its objects, masked.

        ``path`` is the path as recorded (keys masked); ``origin`` is the same path with the
        keys as received, which is what the protocol-handle paths are matched against.
        """
        if origin is None:
            origin = path
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            # Where the search for a free number goes on, per masked text: many keys that mask
            # alike must not cost a search from #2 each, or the walk is quadratic in them.
            numbers: dict[Any, int] = {}
            for key, item in value.items():
                # A key is masked as a value is: it can carry a literal, a known value or a
                # credential (a server that echoes, a pair written as a key), and a path in
                # `paths` is made of keys.
                if not isinstance(key, str) or key in self._clean_keys:
                    shown, hits = key, 0
                else:
                    shown, hits = self.mask_text(key) if pairs else self._mask_shapes(key)
                    # Clean under the pair rule is clean without it; not the other way round.
                    if (
                        pairs
                        and shown == key
                        and not hits
                        and len(key) <= _CLEAN_KEY_LENGTH
                        and len(self._clean_keys) < _CLEAN_KEYS
                    ):
                        self._clean_keys.add(key)
                if shown in result:
                    # Two keys that read the same once masked: neither may be lost.
                    number = numbers.get(shown, 2)
                    while f"{shown}#{number}" in result:
                        number += 1
                    numbers[shown] = number + 1
                    shown = f"{shown}#{number}"
                child = f"{path}.{shown}" if path else str(shown)
                source = f"{origin}.{key}" if origin else str(key)
                if _is_protocol_handle(source, item):
                    # Substituted, not blanked, and still declared in `paths`: a reader has
                    # to be able to see that something was replaced here either way.
                    result[shown] = self.pseudonym(item)
                    paths.append(_clip(child))
                elif self.is_secret_key(str(key)):
                    result[shown] = PLACEHOLDER
                    paths.append(_clip(child))
                else:
                    # The key's own path, once per field and without a search: only a string
                    # value puts the very same path there itself, when it has a hit of its own.
                    if hits and not isinstance(item, str):
                        paths.append(_clip(child))
                    before = len(paths)
                    result[shown] = self._walk(item, child, paths, pairs=pairs, origin=source)
                    if hits and isinstance(item, str) and len(paths) == before:
                        paths.append(_clip(child))
            return result

        if isinstance(value, list):
            return [
                self._walk(item, f"{path}[{i}]", paths, pairs=pairs, origin=f"{origin}[{i}]")
                for i, item in enumerate(value)
            ]

        if isinstance(value, str):
            text, hits = self.mask_text(value) if pairs else self._mask_shapes(value)
            if hits:
                paths.append(_clip(path))
            return text

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            masked, blanked = self._mask_number(value)
            if blanked:
                paths.append(_clip(path))
            return masked

        return value

    def _mask_number(self, value: int | float) -> tuple[Any, bool]:
        """A JSON number as it is recorded, and whether it was blanked as a literal.

        A literal made of digits can come back as a number: the number goes, as the placeholder,
        if its text (``json.dumps``) holds one. A number whose text holds a known value, whole
        (``123456789``) or in part (``91234`` for ``1234``), becomes that text with the value
        replaced by its pseudonym, as if it had been quoted: the text ``evidence pack`` makes of
        the same number in a placed script. Counted, not declared in `paths`: a stand-in for a
        known value is no redaction of a credential, for a number as for a string. The three
        shapes do not apply (a long integer is mostly an id or a time); any other number stays
        a number."""
        text = json.dumps(value)
        if self._literals is not None and self._literals.search(text):
            return PLACEHOLDER, True
        if self._known is not None and self._known.search(text) is not None:
            return self._replace_known(self._known, text), False
        return value, False


#: RFC 9110 ``tchar``: what a token (a scheme, a parameter name, an unquoted value) is made of.
_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
#: RFC 9110 ``token68`` without its trailing ``=`` padding.
_TOKEN68 = frozenset("-._~+/0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
#: A query name kept as written (:meth:`Masker.mask_query`).
_READABLE_NAME = re.compile(r"[A-Za-z0-9_.\-\[\]]{1,32}")
#: A name inside a URL in a value kept as written; its length is bounded apart.
_EMBEDDED_NAME = re.compile(r"[A-Za-z0-9_.\-\[\]]+\*?")
#: A header name kept as written: RFC 9110 ``token``, bounded.
_HEADER_NAME = re.compile(rf"[!#$%&'*+\-.^_`|~0-9A-Za-z]{{1,{MAX_NAME_LENGTH}}}")
#: One field of a query.
_QUERY_FIELD = re.compile(r"[^&;]+")
#: A name followed by ``=`` inside a longer text (:meth:`Masker._mask_embedded_query`). The
#: ``=`` is looked at, not taken, so it can stand before the next name. No character that may
#: stand before a name can be part of one: each name is scanned once.
_SEPARATORS = "?&;#=,|/:\\s\"'(<>"
_EMBEDDED_NAME_AT = re.compile(rf"(^|[{_SEPARATORS}])([^{_SEPARATORS}]+)(?==)")
#: The same for text (:meth:`Masker._mask_pairs`), with horizontal white space allowed before
#: the ``=``: any white space but a line break (a space, a tab, U+00A0, U+2009 …). A line
#: break does not join a name to a value on the next line: a pair stands on one line.
_PAIR_NAME_AT = re.compile(rf"(^|[{_SEPARATORS}])([^{_SEPARATORS}]+)(?=[^\S\r\n]*=)")
#: Inside a blanked value, what opens a stretch that only its close ends.
_CLOSES = {'"': '"', "'": "'", "<": ">"}
_RUN = re.compile(r"[A-Za-z0-9]+")


def _skip_blanks(text: str, at: int) -> int:
    """The first position from ``at`` that is no horizontal white space (any white space but
    ``\r`` and ``\n``)."""
    while at < len(text) and text[at].isspace() and text[at] not in "\r\n":
        at += 1
    return at


def _value_end(text: str, start: int, *, lines: bool = False) -> int:
    """Where the value of a pair to be blanked ends, if it starts at ``start``: at the first
    ``&``, ``;`` or ``#`` outside quotes and angle brackets, or at the end of the text.

    Greedy on purpose. Spaces, quotes, markup and a scheme word (``Bearer <x>``) do not end
    it: what follows a credential's name goes, however it was written. Read twice — once with
    a backslash escaping the character after it, once without — and the later end taken: in a
    header that carries JSON, ``token=\\"a;b\\"`` is a quoted value one decoding further on.
    An unclosed quote or bracket runs to the end. Two passes, so linear. With ``lines``, a line
    break ends it as well, inside quotes too (text, where a value is one line's).
    """
    return max(
        _value_end_reading(text, start, True, lines), _value_end_reading(text, start, False, lines)
    )


def _value_end_reading(text: str, start: int, escapes: bool, lines: bool = False) -> int:
    position, end, close = start, len(text), ""
    while position < end:
        character = text[position]
        if lines and character in "\r\n":
            return position
        if escapes and character == "\\":
            position += (
                2 if not lines or text[position + 1 : position + 2] not in ("\r", "\n") else 1
            )
            continue
        if close:
            if character == close:
                close = ""
        elif character in _CLOSES:
            close = _CLOSES[character]
        elif character in "&;#":
            return position
        position += 1
    return end


def _decodings(text: str, *, form: bool = False) -> list[str]:
    """``text`` and each of its percent-decodings that differs from the one before, at most
    :data:`MAX_DECODINGS`. With ``form``, ``+`` is a space in the first round only."""
    forms = [text]
    for round_ in range(MAX_DECODINGS):
        unquote = urllib.parse.unquote_plus if form and round_ == 0 else urllib.parse.unquote
        decoded = unquote(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    return forms


def _kind(character: str) -> str:
    return "d" if character.isdigit() else "u" if character.isupper() else "l"


def _plain_name(name: str) -> bool:
    """Whether a name reads like one someone chose rather than like a value
    (:data:`MAX_NAME_RUN`, :data:`MAX_NAME_DIGITS`, :data:`MAX_NAME_CHANGES`).

    A heuristic, and a one-sided one: a name it lets through is still masked by the needles and
    the text rules; a name it stops loses only its legibility. An all-lower-case random word
    passes it — that is a stated limit.
    """
    changes = 0
    for run in _RUN.findall(name):
        if len(run) > MAX_NAME_RUN or sum(c.isdigit() for c in run) > MAX_NAME_DIGITS:
            return False
        for before, after in zip(run, run[1:], strict=False):
            if _kind(before) != _kind(after) and not (before.isupper() and after.islower()):
                changes += 1
    return changes <= MAX_NAME_CHANGES


def parse_challenges(value: str) -> list[dict[str, Any]] | None:
    """The challenges of one ``WWW-Authenticate`` value (RFC 9110, 11.6.1), or ``None``.

    The value is a comma-separated list; each element is one of

    * ``scheme`` — a challenge without parameters;
    * ``scheme token68`` — a challenge with a bare token;
    * ``scheme name=value`` — a challenge and its first parameter;
    * ``name=value`` — the next parameter of the challenge before it.

    A value is a token or a quoted string (escapes undone). Each challenge comes back as
    ``{"scheme": …, "params": {name: value}}``, names lower-cased (they compare without case),
    or as ``{"scheme": …, "token68": …}``. Anything else gives ``None`` and the caller blanks
    the header whole — an unterminated quote, a parameter before any scheme or after a token68,
    a parameter twice in one challenge, a word where only a parameter or a token68 may stand,
    an empty header, more than :data:`MAX_CHALLENGES` elements. It narrows what is kept, never
    widens it. Linear in the value; no regular expression.
    """
    elements = _split_elements(value)
    if elements is None:
        return None
    challenges: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for element in elements:
        if not element:
            continue
        word, rest = _take_token(element, 0)
        if not word:
            return None
        after = _skip_spaces(element, rest)
        if after < len(element) and element[after] == "=":
            # name=value: a parameter of the challenge before it.
            if current is None or "params" not in current:
                return None
            parameter = _param_value(element, after + 1)
            if parameter is None or word.lower() in current["params"]:
                return None
            current["params"][word.lower()] = parameter
            continue
        current = {"scheme": word, "params": {}}
        challenges.append(current)
        if after == len(element):
            continue
        if after == rest:
            return None  # no space between the scheme and what follows
        name, name_end = _take_token(element, after)
        equals = _skip_spaces(element, name_end)
        if name and equals < len(element) and element[equals] == "=":
            parameter = _param_value(element, equals + 1)
            if parameter is None:
                # Not a parameter after all; perhaps a token68 with its padding.
                token68 = _token68(element, after)
                if token68 is None:
                    return None
                del current["params"]
                current["token68"] = token68
                continue
            current["params"][name.lower()] = parameter
            continue
        token68 = _token68(element, after)
        if token68 is None:
            return None
        del current["params"]
        current["token68"] = token68
    return challenges or None


def parse_challenge(values: Iterable[str]) -> dict[str, Any] | None:
    """The first ``Bearer`` challenge among the ``WWW-Authenticate`` values of one response, as
    :func:`parse_challenges` gives it (``{"scheme": …, "params": {name: value}}``), or ``None``
    when there is none or a value does not parse. Unmasked: for the channel, which reads
    ``resource_metadata`` and ``scope`` from it and hands on what it says through the masker and
    ``display`` only. The recorder parses and masks the header itself."""
    for value in values:
        parsed = parse_challenges(value)
        if parsed is None:
            return None
        for challenge in parsed:
            if challenge["scheme"].lower() == "bearer" and "params" in challenge:
                return challenge
    return None


def _split_elements(value: str) -> list[str] | None:
    """The list elements of a header value, split at commas outside quoted strings."""
    elements: list[str] = []
    start = 0
    index = 0
    quoted = False
    length = len(value)
    while index < length:
        character = value[index]
        if quoted:
            if character == "\\":
                index += 1
                if index == length:
                    return None
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character == ",":
            elements.append(value[start:index].strip(" \t"))
            start = index + 1
            if len(elements) >= MAX_CHALLENGES:
                return None  # the element after this comma would be one too many
        index += 1
    if quoted:
        return None
    elements.append(value[start:].strip(" \t"))
    return elements


def _skip_spaces(text: str, at: int) -> int:
    while at < len(text) and text[at] in " \t":
        at += 1
    return at


def _take_token(text: str, at: int) -> tuple[str, int]:
    end = at
    while end < len(text) and text[end] in _TCHAR:
        end += 1
    return text[at:end], end


def _param_value(element: str, at: int) -> str | None:
    """A parameter's value from ``at`` to the end of the element: a token or a quoted string,
    nothing after it but spaces."""
    at = _skip_spaces(element, at)
    if at < len(element) and element[at] == '"':
        text: list[str] = []
        at += 1
        while at < len(element) and element[at] != '"':
            if element[at] == "\\":
                at += 1
            text.append(element[at])
            at += 1
        at += 1
        value = "".join(text)
    else:
        value, at = _take_token(element, at)
        if not value:
            return None
    return value if _skip_spaces(element, at) == len(element) else None


def _token68(element: str, at: int) -> str | None:
    """A token68 from ``at`` to the end of the element, padding included, or ``None``."""
    end = at
    while end < len(element) and element[end] in _TOKEN68:
        end += 1
    if end == at:
        return None
    while end < len(element) and element[end] == "=":
        end += 1
    return element[at:end] if _skip_spaces(element, end) == len(element) else None


def withheld_path(path: str) -> str:
    """What stands in text where a URL's path is not written: its SHA-256 (of the path as
    sent, UTF-8, before any masking) and its length in characters. Neither says what the path
    was; the SHA-256 lets whoever holds a path check that it is the one."""
    digest = hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()
    return f"<path withheld: sha256 {digest}, {len(path)} characters>"


#: A URL anywhere in an argument: any scheme followed by ``//`` starts one, and so does a ``//``
#: at the start of the text, after white space or after ``=``. It runs to the next white space or
#: the end, or to the next scheme with ``//``, which starts another. What comes before the path
#: (scheme, authority), the path, and the query and fragment. The scheme is at most 32 characters
#: on purpose: the look-ahead at each character then reads a bounded stretch, so the match stays
#: linear in the text. A longer scheme is found from its last 32 characters on.
_URL_SCHEME = r"[A-Za-z][A-Za-z0-9+.-]{0,31}:"
_NOT_ANOTHER_URL = rf"(?!{_URL_SCHEME}//)"
_URL_ARGUMENT = re.compile(
    rf"(?P<head>(?:{_URL_SCHEME}|(?<![^\s=]))//(?:{_NOT_ANOTHER_URL}[^/?#\s])*)"
    rf"(?P<path>(?:{_NOT_ANOTHER_URL}[^?#\s])*)"
    rf"(?P<tail>(?:{_NOT_ANOTHER_URL}\S)*)",
    re.IGNORECASE,
)
#: The port a URL without one is spoken to on.
DEFAULT_URL_PORTS = {"http": 80, "https": 443}
#: A path that may be written as it is, with the target it belongs to: host, effective port
#: (:func:`url_reach`) and the path exactly. The same path on another host or port is not it.
VerbatimPath = tuple[str, int | None, str]
#: What stands in a URL's path while the text rules run over it: a path as a URL has one, so
#: that what the rules see of the URL keeps its shape, and no rule matches it.
_PATH_STAND_IN = "/pathwithheld"


def url_reach(url: str) -> tuple[str, int | None] | None:
    """The host and the effective port of a URL, as a pair to compare as it is: the host as
    ``urlsplit(url).hostname`` gives it (lower case, an IPv6 literal's brackets removed), the port
    as written or, where none is, the scheme's. None for a URL without a host, with a port that
    is not one, or that cannot be taken apart; a caller treats that as nothing verbatim."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if host is None:
        return None
    return host, DEFAULT_URL_PORTS.get(parts.scheme.lower()) if port is None else port


def _urls_to_withhold(text: str, verbatim_paths: Collection[VerbatimPath]) -> list[re.Match[str]]:
    """Every URL in ``text`` whose path is to be withheld: not empty (an empty path holds
    nothing) and not, with its host and effective port, one of ``verbatim_paths``."""
    found = []
    for url in _URL_ARGUMENT.finditer(text):
        if not url["path"]:
            continue
        reach = url_reach(url["head"])
        if reach is not None and (*reach, url["path"]) in verbatim_paths:
            continue
        found.append(url)
    return found


def _replace_paths(text: str, urls: Sequence[re.Match[str]], shown: Sequence[str]) -> str:
    """``text`` with the path of each of ``urls`` (matches in it, in order) replaced by the
    matching one of ``shown``."""
    pieces = []
    end = 0
    for url, replacement in zip(urls, shown, strict=True):
        pieces += [text[end : url.start("path")], replacement]
        end = url.end("path")
    return "".join(pieces) + text[end:]


def withhold_url_path(text: str, verbatim_paths: Collection[VerbatimPath] = ()) -> str:
    """``text`` with the path of every URL in it (a scheme and ``//`` anywhere, or ``//`` at the
    start, after white space or after ``=``, to the next white space) replaced by
    :func:`withheld_path`, unless the path is empty or its host, effective port and path are one
    of ``verbatim_paths``. A scheme with no default port gives no port, so it matches none. What
    stands before a URL stays."""
    urls = _urls_to_withhold(text, verbatim_paths)
    return _replace_paths(text, urls, [withheld_path(url["path"]) for url in urls])


def _is_protocol_handle(path: str, value: Any) -> bool:
    """Whether this exact field, holding this shape of value, is a known protocol handle.

    Two conditions, both required. The **path** must be listed: a key name on its own says
    nothing about what a value is. And the **value** must be the scalar a handle is — a
    string or a number. A handle arriving as an object or a list is not the protocol's
    handle any more, whatever the field is called, so it falls through to being blanked.
    Fail closed: this only ever narrows what gets pseudonymised.
    """
    if path not in PROTOCOL_HANDLE_PATHS:
        return False
    if isinstance(value, bool) or value is None:
        return False
    return isinstance(value, (str, int, float))


def _clip(path: str) -> str:
    return path if len(path) <= MAX_PATH_LENGTH else path[:MAX_PATH_LENGTH] + "…"
