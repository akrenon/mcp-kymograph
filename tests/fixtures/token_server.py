"""The HTTP fixture (``http_server``) with a server that judges the token it is given.

``serve(policy, **behaviour)`` is ``http_server.serve`` whose authorization looks into the bearer
token instead of comparing it with a value in the environment:

* no ``Authorization`` header: accepted if ``policy.anonymous_ok``, else 401 (``deny_status`` 403
  for the other);
* a header: accepted unless ``policy.audience`` is set and the token's ``aud`` is another, or
  ``policy.check_exp`` is set and the token's ``exp`` is not after ``policy.now()``. A token that
  is not three Base64 parts with a JSON payload has no ``aud`` and no ``exp``.

``statuses={"tools/call": 500}`` answers that method with the status and no body (401 and 403
without a JSON body too); ``stall="tools/call"`` leaves it unanswered for ``STALL_SECONDS``, so a
run with the shortest step time gets no answer at all.

``http_server`` is not changed: the handler is swapped on the running server, before the first
connection, and the policy rides on its behaviour. Test-only; made up values, no real secrets.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import http_server


@dataclass
class Policy:
    """What the server accepts. The default accepts everything that has a header, and no header."""

    audience: str | None = None
    check_exp: bool = False
    anonymous_ok: bool = False
    now: Callable[[], float] = field(default=time.time)


def payload_of(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        document = json.loads(raw)
    except ValueError:
        return {}
    return document if isinstance(document, dict) else {}


#: Longer than the shortest time a step may be given (``driver.MIN_STEP_TIMEOUT``).
STALL_SECONDS = 4.0


class Handler(http_server.Handler):
    def _answer(self, request: dict, headers: dict[str, str]) -> None:
        behaviour = self.server.behaviour
        method = request.get("method")
        if method == behaviour.stall:
            time.sleep(STALL_SECONDS)
            return
        if method == behaviour.unauthorized_method:
            self._unauthorized()  # in the modern era too, which http_server does not ask
            return
        if method in behaviour.statuses:
            self._status(behaviour.statuses[method])
            return
        super()._answer(request, headers)

    def _authorized(self) -> bool:
        policy: Policy = self.server.behaviour.policy
        given = self.headers.get("Authorization")
        if given is None:
            return policy.anonymous_ok
        claims = payload_of(given.removeprefix("Bearer "))
        if policy.audience is not None and claims.get("aud") != policy.audience:
            return False
        if policy.check_exp:
            expires = claims.get("exp")
            if type(expires) is not int or expires <= policy.now():
                return False
        return True


def serve(policy: Policy, **behaviour: Any):
    """A running server that applies ``policy``; stop it with ``shutdown()``."""
    statuses = behaviour.pop("statuses", {})
    stall = behaviour.pop("stall", None)
    server = http_server.serve(**behaviour)
    server.behaviour.policy = policy
    server.behaviour.statuses = statuses
    server.behaviour.stall = stall
    server.RequestHandlerClass = Handler
    return server
