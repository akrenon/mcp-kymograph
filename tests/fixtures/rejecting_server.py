"""A token-judging server (``token_server``) that is awkward in the body of its refusals and
reflects the token it was sent in every form it controls.

``serve(policy, rejection=..., mirror=..., code_method=...)``, besides what ``token_server`` and
``http_server`` take:

* ``rejection`` shapes the body of a 401 or 403, which keeps ``Content-Type: application/json``
  (but for ``"html"``): ``"stall"`` sends the head with the length of a body and then nothing,
  until ``STALL_SECONDS`` are over; ``"long_stall"`` the same for ``LONG_STALL_SECONDS``;
  ``"drip"`` sends the body a byte every ``DRIP_INTERVAL`` seconds, ``DRIP_SECONDS`` long;
  ``"abort"`` sends half of a body and closes the connection; ``"not_json"`` a body that is no
  JSON; ``"result"`` a JSON-RPC ``result`` where an ``error`` is expected; ``"empty"`` has
  ``Content-Length: 0``; ``"html"`` a ``text/html`` body.
* ``mirror`` reflects the bearer token of the request: as a JSON number where it is made of
  digits (``result``, ``error.code``, ``error.data``), as part of a string and percent-encoded
  (``content[].text``, ``error.message``), in a response header (``X-Echo``), and in the body of
  a 401 or 403.
* ``mirror_header="X-Api-Key"`` reflects the value of that header of the request instead of the
  bearer token, in every form ``mirror`` and ``code_method`` use.
* ``behaviour.mirrored`` lists ``(form, value)`` for each value handed back, once the bytes that
  carry it were written: ``"text"`` for the ``X-Echo`` header (with every head of ``mirror``,
  that of a refusal too) and for a string in a body, ``"number"`` for a JSON number in a body.
  A body counts for what the bytes written of it hold: an answer of ``mirror`` whose result is
  no object (``call_result="string-result"``, ``"no-result"``) holds nothing of the token, one
  cut in half (``failure="aborted-stream"``) only what is in its first half, one without its
  last character (``"missing-end"``) all of it; ``cut_method="tools/call"`` sends the answer
  to that method up to the end of the first ``seen<token>`` and closes the connection. The
  token counts as text where it stands (as it is or percent-encoded) in a string of what was
  written, as a number where it stands as one. The body of a 401 or 403 counts only where it is
  the whole JSON-RPC error (no ``rejection``): with a ``rejection`` it is another body, one that
  stalls, or half of one, and what it would have held was not sent. ``mirrored_by_method``
  holds the same, by the method of the request answered (``None`` for a refusal before any).
  A test proves with it that a value was handed back.
* ``echo="<value>"`` reflects that value instead of the bearer token of the request, as a
  server does that hands back a token it was sent in an earlier run, as another identity.
* ``code_method`` is answered 200 with a JSON-RPC error whose ``code`` is the token as a number
  (``-32001`` where the token is not made of digits).
* ``both_method="tools/call"`` answers that method 200 with a ``result`` and an ``error`` (code
  ``-32001``) at once, which is no valid JSON-RPC answer; ``both_null_id=True`` names the id
  ``null`` in it, as the body of a refusal does, beside an empty ``result``; ``both_error=``
  puts that value where the error object would be (``None`` for ``"error": null``), and
  ``both_result=`` that value where the result would be (unless ``None``).
* ``head_delay=SECONDS`` waits that long before the head of a 401 or 403 (with ``rejection``
  or ``mirror``), so that a step has only the rest of its time left when the refusal comes.
* ``bodiless=True`` answers every request 200 with ``Content-Length: 0``: a server that is
  silent without refusing.
* ``limit_once={"tools/list": (429, "1")}`` answers the first request of a method with that status
  and ``Retry-After``, and every later one as usual.

Test-only; made up values, no real secrets.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import quote

import token_server
from token_server import STALL_SECONDS, Policy

__all__ = [
    "DRIP_INTERVAL",
    "DRIP_SECONDS",
    "LONG_STALL_SECONDS",
    "REJECTIONS",
    "STALL_SECONDS",
    "Handler",
    "Policy",
    "serve",
]

#: The error ``both_method`` sends beside a result unless ``both_error`` names another value.
BOTH_ERROR = {"code": -32001, "message": "failed"}
REJECTIONS = ("stall", "abort", "not_json", "result", "empty", "html", "long_stall", "drip")
#: More than the old wait for the body of a refusal (10 s) less the room a step is given.
LONG_STALL_SECONDS = 8.0
DRIP_INTERVAL = 0.3
DRIP_SECONDS = 10.0


class Handler(token_server.Handler):
    def do_POST(self) -> None:  # noqa: N802 - the name http.server calls
        self._method = None  # set by _answer, for the request this connection answers now
        if self.server.behaviour.bodiless:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._status(200)  # Content-Length: 0, for every request
            return
        super().do_POST()

    def _bearer(self) -> str | None:
        if self.server.behaviour.echo is not None:
            return self.server.behaviour.echo
        if self.server.behaviour.mirror_header is not None:
            return self.headers.get(self.server.behaviour.mirror_header)
        given = self.headers.get("Authorization")
        return given.removeprefix("Bearer ") if given is not None else None

    def _number(self) -> int:
        """The token as a JSON number, when it is made of digits."""
        token = self._bearer()
        if token is None or not (token.isascii() and token.isdigit()):
            return -32001
        return int(token)

    def _text(self) -> str:
        """The token inside a string, and again percent-encoded, between words."""
        token = self._bearer()
        if token is None:
            return "no token"
        return f"seen<{token}> and {quote(token, safe='')}"

    def _answer(self, request: dict, headers: dict[str, str]) -> None:
        behaviour = self.server.behaviour
        self._method = request.get("method")
        limited = behaviour.limit_once.pop(request.get("method"), None)
        if limited is not None:
            self._status(limited[0], {"Retry-After": limited[1]})
            return
        if behaviour.both_method is not None and request.get("method") == behaviour.both_method:
            reply = behaviour.answer(request, self._reflected)
            result = reply.get("result")
            both = {
                "jsonrpc": "2.0",
                "id": None if behaviour.both_null_id else request.get("id"),
                "result": behaviour.both_result
                if behaviour.both_result is not None
                else result
                if isinstance(result, dict) and not behaviour.both_null_id
                else {},
                "error": behaviour.both_error,
            }
            self._json(200, both, headers)
            return
        if behaviour.code_method is not None and request.get("method") == behaviour.code_method:
            error = {"code": self._number(), "message": "failed"}
            self._json(200, {"jsonrpc": "2.0", "id": request.get("id"), "error": error})
            self._handed_back("number")
            return
        super()._answer(request, headers)

    def _json(
        self, status: int, reply: dict, headers: dict[str, str] | None = None, failure=None
    ) -> None:
        behaviour = self.server.behaviour
        mirrored = behaviour.mirror and status == 200 and self._bearer() is not None
        if mirrored:
            reply, headers = self._mirrored(reply), {**(headers or {}), "X-Echo": self._text()}
        body = json.dumps(reply).encode()  # as http_server writes it
        cut = (
            mirrored
            and failure is None
            and behaviour.cut_method is not None
            and getattr(self, "_method", None) == behaviour.cut_method
            and b"seen<" in body
        )
        if cut:
            body = self._cut_after_seen(body, headers or {})
        else:
            super()._json(status, reply, headers, failure)
            if failure == "aborted-stream":
                body = body[: len(body) // 2]
            elif failure == "missing-end":
                body = body[:-1]
        if not mirrored:
            return
        self._handed_back("text")  # the X-Echo header, written in full with the head
        text, number = self._held(body)
        if text:
            self._handed_back("text")
        if number:
            self._handed_back("number")

    def _cut_after_seen(self, body: bytes, headers: dict[str, str]) -> bytes:
        """Send the head of the whole answer and its body up to the end of the first
        ``seen<token>``, then close the connection; the bytes that were sent."""
        sent = body[: body.index(b">", body.index(b"seen<")) + 1]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(sent)
        self.wfile.flush()
        self.close_connection = True
        return sent

    def _held(self, sent: bytes) -> tuple[bool, bool]:
        """Whether the bytes sent of a body hold the token as text (as it is or percent-encoded,
        inside a string) and as a JSON number (after ``": "`` or ``[``)."""
        token = self._bearer() or ""
        digits = token.isascii() and token.isdigit()
        text = number = False
        for needle in {token, quote(token, safe="")}:
            for found in re.finditer(re.escape(needle.encode()), sent):
                before = sent[max(0, found.start() - 2) : found.start()]
                if digits and needle == token and (before == b": " or before.endswith(b"[")):
                    number = True
                else:
                    text = True
        return text, number

    def _handed_back(self, *forms: str) -> None:
        """Note the token as handed back in ``forms``, after the bytes went out: a number only
        where it is made of digits (else -32001 went in its place)."""
        token = self._bearer()
        if token is None:
            return
        for form in forms:
            if form == "text" or (token.isascii() and token.isdigit()):
                self.server.behaviour.mirrored.append((form, token))
                by_method = self.server.behaviour.mirrored_by_method
                by_method.setdefault(getattr(self, "_method", None), []).append((form, token))

    def _mirrored(self, reply: dict) -> dict:
        reply = json.loads(json.dumps(reply))
        number, text = self._number(), self._text()
        result = reply.get("result")
        if isinstance(result, dict):
            result["echo"] = {"number": number, "numbers": [number], "text": text}
            if isinstance(result.get("content"), list):
                result["content"].append({"type": "text", "text": text})
        error = reply.get("error")
        if isinstance(error, dict):
            error["message"] = f"{error.get('message', '')} {text}"
            error["data"] = number
        return reply

    def _unauthorized(self) -> None:
        behaviour = self.server.behaviour
        if behaviour.rejection is None and not behaviour.mirror:
            super()._unauthorized()
            return
        number = self._number()
        document: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": number, "message": f"not authorized {self._text()}", "data": number},
        }
        body = json.dumps(document).encode()
        kind = "application/json"
        if behaviour.rejection == "not_json":
            body = b"<html>not authorized</html>"
        elif behaviour.rejection == "html":
            body, kind = b"<html><body>not authorized</body></html>", "text/html"
        elif behaviour.rejection == "empty":
            body = b""
        elif behaviour.rejection == "result":
            body = json.dumps({"jsonrpc": "2.0", "id": None, "result": {"ok": True}}).encode()
        elif behaviour.rejection == "drip":
            body = b" " * int(DRIP_SECONDS / DRIP_INTERVAL)
        time.sleep(behaviour.head_delay)
        self.send_response(behaviour.deny_status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        echoed = behaviour.mirror and self._bearer() is not None
        if echoed:
            self.send_header("X-Echo", self._text())
        self.end_headers()
        self.close_connection = True
        if echoed:
            self._handed_back("text")
        if behaviour.rejection in ("stall", "long_stall"):
            self.wfile.flush()
            time.sleep(LONG_STALL_SECONDS if behaviour.rejection == "long_stall" else STALL_SECONDS)
            return
        if behaviour.rejection == "drip":
            try:
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(DRIP_INTERVAL)
            except OSError:
                pass  # the client has gone
            return
        self.wfile.write(body[: len(body) // 2] if behaviour.rejection == "abort" else body)
        self.wfile.flush()
        if behaviour.rejection is None:
            self._handed_back("text", "number")  # the whole JSON-RPC error, as built above


def serve(
    policy: Policy,
    *,
    rejection: str | None = None,
    mirror: bool = False,
    code_method: str | None = None,
    limit_once: dict[str, tuple[int, str]] | None = None,
    echo: str | None = None,
    bodiless: bool = False,
    both_method: str | None = None,
    both_null_id: bool = False,
    both_error: Any = BOTH_ERROR,
    both_result: Any = None,
    cut_method: str | None = None,
    head_delay: float = 0.0,
    mirror_header: str | None = None,
    **behaviour: Any,
):
    """A running server that applies ``policy``; stop it with ``shutdown()``."""
    if rejection is not None and rejection not in REJECTIONS:
        raise ValueError(f"no such rejection: {rejection}")
    server = token_server.serve(policy, **behaviour)
    server.behaviour.rejection = rejection
    server.behaviour.mirror = mirror
    server.behaviour.code_method = code_method
    server.behaviour.limit_once = dict(limit_once or {})
    server.behaviour.echo = echo
    server.behaviour.bodiless = bodiless
    server.behaviour.both_method = both_method
    server.behaviour.both_null_id = both_null_id
    server.behaviour.both_error = both_error
    server.behaviour.both_result = both_result
    server.behaviour.cut_method = cut_method
    server.behaviour.head_delay = head_delay
    server.behaviour.mirror_header = mirror_header
    server.behaviour.mirrored = []
    server.behaviour.mirrored_by_method = {}
    server.RequestHandlerClass = Handler
    return server
