"""A server of the modern era only (MCP 2026-07-28): no handshake, ``_meta`` on every request.

It answers ``server/discover`` with a ``DiscoverResult`` naming ``--supported``, and serves
``tools/list`` to a request whose ``_meta`` names a version it supports. A request without that
``_meta`` — ``initialize`` among them — is rejected (−32602), naming the versions it supports;
a version it does not support gets ``UnsupportedProtocolVersion`` (−32022) with the list.

    python modern_server.py [--supported 2026-07-28[,2025-11-25]] [--refuse CODE]

``--refuse CODE`` answers every request carrying ``_meta`` with that error instead: −32021 with
the ``requiredCapabilities`` the schema gives it, any other code bare.
"""

import argparse
import json
import sys

VERSION_KEY = "io.modelcontextprotocol/protocolVersion"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--supported", default="2026-07-28")
    parser.add_argument("--refuse", type=int, default=None)
    args = parser.parse_args()
    supported = [version for version in args.supported.split(",") if version]
    out = sys.stdout.buffer

    def write(payload: dict) -> None:
        out.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        out.flush()

    def error(identifier, code: int, message: str, data=None) -> None:
        body = {"code": code, "message": message}
        if data is not None:
            body["data"] = data
        write({"jsonrpc": "2.0", "id": identifier, "error": body})

    for raw in sys.stdin.buffer:
        try:
            request = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(request, dict) or "id" not in request:
            continue
        identifier, method = request["id"], request.get("method")
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        version = meta.get(VERSION_KEY)
        if version is None:
            error(identifier, -32602, f"missing {VERSION_KEY}; supported: {', '.join(supported)}")
            continue
        if args.refuse == -32021:
            data = {"requiredCapabilities": {"elicitation": {}}}
            error(identifier, -32021, "Missing required client capability", data)
            continue
        if args.refuse is not None:
            error(identifier, args.refuse, "refused")
            continue
        if version not in supported:
            data = {"supported": supported, "requested": version}
            error(identifier, -32022, "Unsupported protocol version", data)
            continue
        if method == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": supported,
                "capabilities": {"tools": {}},
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "modern", "version": "1"}},
            }
            write({"jsonrpc": "2.0", "id": identifier, "result": result})
        elif method == "tools/list":
            tools = [{"name": "echo", "description": "Returns the text."}]
            write({"jsonrpc": "2.0", "id": identifier, "result": {"tools": tools}})
        else:
            error(identifier, -32601, f"method not found: {method}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
