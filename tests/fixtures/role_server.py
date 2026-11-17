"""A Streamable HTTP server whose answers depend on who asks, for comparing two identities.

Built on ``http_server`` (sessions, headers and framing are its), with what a role decides added:
the bearer token names the role (``serve(roles={token: role})``), and a request with any other
token is answered 401.

* **Lists:** every role sees the tool ``probe``, the prompt ``shared`` and the resource
  ``public://about``; only ``admin`` sees the tool ``admin_only``, the prompt ``admin_prompt``
  and the resource ``admin://notes``.
* **Calls:** ``probe`` answers the same to every role; ``whoami`` answers each role its own
  words and reflects the token it was sent; ``restricted`` is answered 403 (at HTTP level) to
  every role but ``admin``; ``broken`` is answered with a JSON-RPC error to every role but
  ``admin``; ``keyed`` carries the role's mark as a key of its ``structuredContent`` and
  ``shaped`` as the ``uri`` of an item of a ``contents`` array. All of them are listed to every
  role, so a script may call them; ``admin_only`` is listed to ``admin`` alone.
* **Marks:** every distinct answer carries a mark nobody could guess, put together at run time.
  Two answers that are the same carry the same mark. ``serve(...).behaviour.marks`` holds every
  mark handed out, so a test can look for each of them in what a command printed.
* **Pages:** with ``page_size`` the tool list is delivered that many tools at a time, each page
  but the last with a ``nextCursor`` (the cursor is the offset of the next page); ``extra_tools``
  adds that many tools, named ``extra00``…, to every role's list. Both are attributes of
  ``serve(...).behaviour``, so a test may change them between two runs.
* **Answers over a resumption:** with ``close_early="once"``, ``respond="stream"`` and
  ``failure_method`` a method, the answer to that method comes only after the stream, which holds
  a notification with an event id and ends, is resumed with ``GET`` and ``Last-Event-ID``; with
  ``resumptions=N`` N more such streams come first. The base server's priming event holds no data,
  so the recording would hold no message with its id; with ``priming=True`` the first stream is
  that priming event, and the answer comes in a stream nothing in the recording leads to.
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import http_server  # noqa: E402

ADMIN_TOOLS = ("admin_only",)
ADMIN_PROMPTS = ("admin_prompt",)
ADMIN_RESOURCES = ("admin://notes",)


class RoleBehaviour(http_server.Behaviour):
    def __init__(
        self,
        roles: dict[str, str],
        page_size: int | None = None,
        extra_tools: int = 0,
        resumptions: int = 0,
        priming: bool = False,
        **behaviour: Any,
    ) -> None:
        super().__init__(**behaviour)
        self.roles = dict(roles)
        self.page_size = page_size
        self.extra_tools = extra_tools
        #: With ``close_early="once"`` and ``respond="stream"``: how many streams that end after a
        #: notice with an id come between the request and the one that holds the answer.
        self.resumptions = resumptions
        #: With ``close_early="once"`` and ``respond="stream"``: the first stream is the base
        #: server's priming event (an id, no data) rather than a notification with an id.
        self.priming = priming
        #: Every mark handed out, in order.
        self.marks: list[str] = []
        self._by_answer: dict[tuple[str, str], str] = {}

    def mark(self, kind: str, answer: str) -> str:
        """The mark of one distinct answer: made on first use, the same for the same answer."""
        with self.lock:
            if (kind, answer) not in self._by_answer:
                made = "MARK" + secrets.token_hex(10)
                self._by_answer[(kind, answer)] = made
                self.marks.append(made)
            return self._by_answer[(kind, answer)]

    def answer_for(self, role: str, token: str, request: dict) -> dict | None:
        """The answer to one request for ``role``; None where the server answers 403."""
        method, identifier = request.get("method"), request.get("id")
        params = request.get("params")
        params = params if isinstance(params, dict) else {}
        admin = role == "admin"
        if method == "tools/list":
            names = ["probe", "whoami", "restricted", "broken", "keyed", "shaped"]
            names += list(ADMIN_TOOLS) if admin else []
            names += [f"extra{n:02}" for n in range(self.extra_tools)]
            start = _offset(params.get("cursor")) if self.page_size else 0
            end = start + self.page_size if self.page_size else len(names)
            tools = [
                {"name": n, "description": self.mark("list", n), "inputSchema": {"type": "object"}}
                for n in names[start:end]
            ]
            body: dict[str, Any] = {"tools": tools}
            if end < len(names):
                body["nextCursor"] = f"offset-{end}"
            return _result(identifier, body)
        if method == "prompts/list":
            names = ["shared", *(ADMIN_PROMPTS if admin else ())]
            return _result(identifier, {"prompts": [{"name": n} for n in names]})
        if method == "resources/list":
            uris = ["public://about", *(ADMIN_RESOURCES if admin else ())]
            return _result(identifier, {"resources": [{"uri": u, "name": "r"} for u in uris]})
        if method == "tools/call":
            tool = params.get("name")
            if tool == "probe":
                return _text(identifier, self.mark("probe", "all"))
            if tool == "whoami":
                body = _text(identifier, self.mark("whoami", role))
                body["result"]["structuredContent"] = {"role": role, "token": token}
                return body
            if tool == "keyed":
                # The role's mark is a key of the structured content.
                body = _text(identifier, self.mark("probe", "all"))
                body["result"]["structuredContent"] = {self.mark("key", role): 1}
                return body
            if tool == "shaped":
                # An array whose items are named by a uri, which carries the role's mark.
                body = _text(identifier, self.mark("probe", "all"))
                body["result"]["contents"] = [{"uri": self.mark("uri", role), "text": "t"}]
                return body
            if tool == "restricted":
                return _text(identifier, self.mark("restricted", role)) if admin else None
            if tool == "broken":
                if admin:
                    return _text(identifier, self.mark("broken", role))
                error = {"code": -32010, "message": self.mark("broken", role)}
                return {"jsonrpc": "2.0", "id": identifier, "error": error}
        return self.answer(request)

    def answer(self, request: dict, reflected: str = "") -> dict:
        """The base server's answer, but for ``initialize`` offering all three lists."""
        reply = super().answer(request, reflected)
        if request.get("method") == "initialize" and "result" in reply:
            reply["result"]["capabilities"] = {"tools": {}, "prompts": {}, "resources": {}}
        return reply


class RoleHandler(http_server.Handler):
    _role = ""
    _token = ""

    def _notice(self, event_id: str) -> None:
        """A stream of one event, a notification with an id (so the recording holds a message
        with it), then the end of the connection."""
        notice = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}}
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        data = json.dumps(notice)
        self.wfile.write(f"id: {event_id}\nretry: 10\nevent: message\ndata: {data}\n\n".encode())
        self.close_connection = True

    def _resume(self, last: str) -> None:
        """A GET that names an id handed out: another such stream while ``resumptions`` says so,
        then the answer."""
        behaviour = self.server.behaviour
        with behaviour.lock:
            reply, count = behaviour.pending[last]
            more = count < behaviour.resumptions
            if more:
                event_id = f"{last.rpartition('-')[0]}-{count + 1}"
                behaviour.pending[event_id] = (reply, count + 1)
        if more:
            self._notice(event_id)
        else:
            super()._resume(last)

    def _authorized(self) -> bool:
        given = self.headers.get("Authorization") or ""
        token = given.removeprefix("Bearer ") if given.startswith("Bearer ") else ""
        role = self.server.behaviour.roles.get(token)
        self._role, self._token = role or "", token
        return role is not None

    def _answer(self, request: dict, headers: dict[str, str]) -> None:
        behaviour = self.server.behaviour
        if request.get("method") in ("initialize", "server/discover"):
            super()._answer(request, headers)
            return
        reply = behaviour.answer_for(self._role, self._token, request)
        if reply is None:
            self._status(403)
            return
        if behaviour.close_early and request.get("method") == behaviour.failure_method:
            # A notice with an id, then the end of the connection: the answer comes with the
            # GET that names the id (``_resume``).
            with behaviour.lock:
                behaviour.early += 1
                event_id = f"e{behaviour.early}-0"
                behaviour.pending[event_id] = (reply, 0)
            if behaviour.priming:
                self._priming_event(event_id)
            else:
                self._notice(event_id)
            return
        self._json(200, reply, headers)


def _offset(cursor: Any) -> int:
    """Where the page a cursor names begins; the first page for a cursor never given."""
    text = cursor if isinstance(cursor, str) else ""
    return int(text.removeprefix("offset-")) if text.removeprefix("offset-").isdigit() else 0


def _result(identifier: Any, body: dict) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "result": body}


def _text(identifier: Any, text: str) -> dict:
    return _result(identifier, {"content": [{"type": "text", "text": text}]})


def serve(roles: dict[str, str], **behaviour: Any) -> http_server._Server:
    """A running server in a thread of this process; stop it with ``shutdown()``."""
    server = http_server._Server(0, RoleBehaviour(roles, **behaviour))
    server.RequestHandlerClass = RoleHandler
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    return server
