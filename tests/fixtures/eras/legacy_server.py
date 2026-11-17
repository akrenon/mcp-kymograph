"""A server of the legacy era only (an ``initialize`` handshake).

How it meets a method it does not know before the handshake — what a client of both eras has
to survive:

``--unknown error``   JSON-RPC "Method not found" (−32601), as most legacy servers answer;
``--unknown silent``  no answer, and it goes on reading;
``--unknown exit``    it ends its process, unanswered.

Which version it speaks: ``--versions`` lists the ones it supports, newest last. Asked for one
of them, it answers with that one; asked for another, it answers with its newest, as the legacy
specification has it — or, with ``--strict``, refuses with an error listing them, as some
servers do.

    python legacy_server.py [--unknown error|silent|exit] [--versions 2025-06-18] [--strict]
"""

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unknown", choices=("error", "silent", "exit"), default="error")
    parser.add_argument("--versions", default="2025-06-18")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    versions = [version for version in args.versions.split(",") if version]
    out = sys.stdout.buffer

    def write(payload: dict) -> None:
        out.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        out.flush()

    for raw in sys.stdin.buffer:
        try:
            request = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(request, dict) or "id" not in request:
            continue
        identifier, method = request["id"], request.get("method")
        if method == "initialize":
            asked = (request.get("params") or {}).get("protocolVersion")
            if asked not in versions and args.strict:
                body = {"code": -32602, "message": "Unsupported protocol version",
                        "data": {"supported": versions, "requested": asked}}  # fmt: skip
                write({"jsonrpc": "2.0", "id": identifier, "error": body})
                continue
            result = {
                "protocolVersion": asked if asked in versions else versions[-1],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "legacy", "version": "1"},
            }
            write({"jsonrpc": "2.0", "id": identifier, "result": result})
            continue
        if args.unknown == "silent":
            continue
        if args.unknown == "exit":
            return 3
        write(
            {
                "jsonrpc": "2.0",
                "id": identifier,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
