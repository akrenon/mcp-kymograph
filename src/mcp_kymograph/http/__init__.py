"""Pure framers for the Streamable HTTP transport (docs/design/http-transport.md, 2.2, 2.3).

It is the part of the transport that is built and tested against bytes alone, and what
:mod:`mcp_kymograph.http_proxy` and :mod:`mcp_kymograph.http_client` frame HTTP with:

* :mod:`~mcp_kymograph.http.head` — the head of a request or a response, bounded and strict;
* :mod:`~mcp_kymograph.http.message` — where a message ends (``Content-Length``, chunked, the
  close), for the forwarding side, which must never lose a byte;
* :mod:`~mcp_kymograph.http.body` — a JSON body as one frame, a message or a batch;
* :mod:`~mcp_kymograph.http.sse` — an event stream as events.

All of them keep the rules of :class:`~mcp_kymograph.framing.LineFramer`: no stream, no writer,
nothing to wait for, memory bounded, an oversized message counted and dropped, never clipped.
"""
