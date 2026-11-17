"""The fixture server of ``http_server``, with some of its answers replaced by a status.

``serve(limits, ...)`` is ``http_server.serve`` whose POSTs are first held against ``limits``:
a list of ``(method, status, headers)``, each used once, by the first request that has that
method (``None`` for any). A request that matches is answered with the status, the headers and
no body; every other request is the fixture server's own. ``server.limits`` is what is left.
"""

from __future__ import annotations

import io
import json
import threading
from typing import Any

import http_server


class _Limited(http_server.Handler):
    def do_POST(self) -> None:  # noqa: N802 - the name http.server calls
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        try:
            method = json.loads(body).get("method")
        except (ValueError, AttributeError):
            method = None
        limit = None
        with self.server.limits_lock:
            for candidate in self.server.limits:
                if candidate[0] in (None, method):
                    self.server.limits.remove(candidate)
                    limit = candidate
                    break
        if limit is not None:
            self._status(limit[1], limit[2])
            return
        self.rfile = io.BytesIO(body)  # the fixture server reads the body itself
        super().do_POST()


def serve(
    limits: list[tuple[str | None, int, dict[str, str]]], **options: Any
) -> http_server._Server:
    """A running fixture server that answers ``limits`` before it answers anything else."""
    server = http_server.serve(0, **options)
    server.limits = list(limits)
    server.limits_lock = threading.Lock()
    server.RequestHandlerClass = _Limited
    return server
