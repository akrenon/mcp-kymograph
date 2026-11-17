"""A server that answers a discovery script, with every part of it switchable.

Exists for the driver tests, and each switch is here because some path in the driver needs
proving: which capabilities are offered decides which steps are sent at all, how many pages a
listing has decides whether cursors are followed, and answering nothing or answering an error
decides what the script does when the handshake does not happen.

    python3 discovery_server.py [--offers tools,resources,prompts] [--pages N]
                                [--malformed-capability NAME] [--fail-initialize]
                                [--silent] [--silent-after-handshake] [--chatter]
                                [--tool-description TEXT] [--leading-tool NAME]
                                [--tool-name NAME] [--server-name NAME]
                                [--tool-count N] [--exit-code N]
                                [--answer-limit N] [--exit-after N]
                                [--self-description TEXT]
                                [--call-result MODE] [--call-text TEXT]

``--call-result`` makes ``tools/call`` answerable (see :data:`CALL_RESULTS`): the text of a
content entry, of an embedded resource or of ``structuredContent``; a JSON-RPC error or an
``isError`` result, or one whose ``isError`` is the string ``"true"``; an answer over the
driver's line limit; no answer; or a message in front of the answer that is not the answer (a
request with the call's id, a response to an id nobody asked).

Newline-delimited JSON-RPC on stdin/stdout, like every other fixture here. No network, no
filesystem, nothing that outlives the process.
"""

from __future__ import annotations

import argparse
import json
import sys

PROTOCOL_VERSION = "2025-06-18"


def build_capabilities(offers: list[str], malformed: str | None) -> dict:
    capabilities: dict = {name: {} for name in offers}
    if malformed is not None:
        # Not an object. The protocol says a capability is one; anything else is something
        # the driver must refuse to read intent out of rather than guess at.
        capabilities[malformed] = "yes"
    return capabilities


def listing(
    method: str,
    page: int,
    pages: int,
    tool_description: str,
    leading_tool: str | None = None,
    tool_name: str | None = None,
    tool_count: int = 1,
    self_description: str | None = None,
) -> dict:
    """One page of a listing. Item names carry the page, so a dropped page is visible.

    ``leading_tool`` puts one more, clean tool in front of the others: the same server with
    an inserted tool, which moves every other tool's position and nothing else.
    ``tool_count`` repeats the tool under further names (``tool_<page>_<n>``), each with the
    same description: one message with that many times the findings of one tool.
    ``self_description`` puts one text into every title and description a prompt, a prompt
    argument, a resource and a resource template can carry; without it the items are as before.
    """
    last = page >= pages - 1
    if method == "tools/list":
        leading = (
            [{"name": leading_tool, "description": "Returns nothing in particular."}]
            if leading_tool is not None
            else []
        )
        names = [tool_name if tool_name is not None else f"tool_{page}"]
        names += [f"tool_{page}_{n}" for n in range(1, tool_count)]
        body: dict = {
            "tools": [
                *leading,
                *(
                    {
                        "name": name,
                        "description": tool_description,
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string", "description": "Some text."}},
                        },
                    }
                    for name in names
                ),
            ]
        }
    elif method == "resources/list":
        resource: dict = {"uri": f"test://r{page}", "name": f"Resource {page}"}
        if self_description is not None:
            resource |= {"title": self_description, "description": self_description}
        body = {"resources": [resource]}
    elif method == "resources/templates/list":
        template: dict = {"uriTemplate": f"test://t{page}/{{id}}"}
        if self_description is not None:
            template |= {
                "name": f"template_{page}",
                "title": self_description,
                "description": self_description,
            }
        body = {"resourceTemplates": [template]}
    elif method == "prompts/list":
        prompt: dict = {"name": f"prompt_{page}", "description": "A prompt."}
        if self_description is not None:
            prompt |= {
                "title": self_description,
                "description": self_description,
                "arguments": [
                    {"name": "subject", "title": self_description, "description": self_description}
                ],
            }
        body = {"prompts": [prompt]}
    else:
        return {}
    if not last:
        body["nextCursor"] = f"page-{page + 1}"
    return body


CALL_RESULTS = (
    "text",
    "resource",
    "structured",
    "rpc-error",
    "tool-error",
    "string-is-error",
    "oversized",
    "silent",
    "request-same-id",
    "orphan",
    "null-result",
    "string-result",
    "no-result",
)

#: Longer than the driver's line limit with the default message limit (1 MiB).
OVERSIZED_BYTES = 2 * 1024 * 1024


def call_answers(mode: str, text: str, identifier: object) -> list[dict]:
    """The messages a ``tools/call`` is answered with, in order; the last is the answer.

    ``request-same-id`` and ``orphan`` put one message in front of it that is *not* the
    answer — a request of the server's own with the id of the call, and a response to an id
    nobody asked — which a client that pairs carelessly would take for one. ``silent`` is
    no message at all.
    """
    if mode not in CALL_RESULTS:
        raise ValueError(f"no such call result: {mode}")
    if mode == "silent":
        return []
    if mode == "rpc-error":
        return [{"jsonrpc": "2.0", "id": identifier, "error": {"code": -32000, "message": text}}]
    # Answers that are no result and no error: what a client cannot read anything out of.
    if mode == "null-result":
        return [{"jsonrpc": "2.0", "id": identifier, "result": None,
                 "error": {"code": -32000, "message": text}}]  # fmt: skip
    if mode == "string-result":
        return [{"jsonrpc": "2.0", "id": identifier, "result": text}]
    if mode == "no-result":
        return [{"jsonrpc": "2.0", "id": identifier}]
    result: dict = {"content": [{"type": "text", "text": text}]}
    if mode == "resource":
        result = {
            "content": [{"type": "resource", "resource": {"uri": "test://note", "text": text}}]
        }
    elif mode == "structured":
        result = {
            "content": [{"type": "text", "text": "done"}],
            "structuredContent": {"note": text},
        }
    elif mode == "tool-error":
        result["isError"] = True
    elif mode == "string-is-error":
        result["isError"] = "true"
    elif mode == "oversized":
        result = {"content": [{"type": "text", "text": "x" * OVERSIZED_BYTES}]}
    answer = {"jsonrpc": "2.0", "id": identifier, "result": result}
    if mode == "request-same-id":
        return [
            {"jsonrpc": "2.0", "id": identifier, "method": "sampling/createMessage", "params": {}},
            answer,
        ]
    if mode == "orphan":
        return [{"jsonrpc": "2.0", "id": 987654, "result": {}}, answer]
    return [answer]


def cursor_page(request: dict) -> int:
    cursor = request.get("params", {}).get("cursor")
    if isinstance(cursor, str) and cursor.startswith("page-"):
        with_number = cursor[len("page-") :]
        if with_number.isdigit():
            return int(with_number)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offers", default="tools", help="comma-separated capability names")
    parser.add_argument("--pages", type=int, default=1, help="pages per listing")
    parser.add_argument("--malformed-capability", default=None)
    parser.add_argument("--fail-initialize", action="store_true")
    parser.add_argument("--silent", action="store_true", help="never answer anything")
    parser.add_argument(
        "--silent-after-handshake",
        action="store_true",
        help="answer initialize, then stop answering — a server that dies mid-inventory",
    )
    parser.add_argument("--tool-description", default="Returns the text it is given.")
    parser.add_argument("--leading-tool", default=None, metavar="NAME")
    parser.add_argument("--tool-name", default=None, metavar="NAME", help="rename the tool")
    parser.add_argument("--server-name", default="discovery-fixture", metavar="NAME")
    parser.add_argument("--tool-count", type=int, default=1, metavar="N")
    parser.add_argument(
        "--self-description",
        default=None,
        metavar="TEXT",
        help="put TEXT into the instructions and into every title and description of the "
        "prompts, their arguments, the resources and the resource templates",
    )
    parser.add_argument(
        "--exit-code", type=int, default=0, metavar="N", help="end with this code at end of input"
    )
    parser.add_argument(
        "--answer-limit",
        type=int,
        default=None,
        metavar="N",
        help="answer N requests after the handshake, then stop answering (a page or a step "
        "left hanging)",
    )
    parser.add_argument(
        "--exit-after",
        type=int,
        default=None,
        metavar="N",
        help="answer N requests after the handshake, then die on the next one, unanswered",
    )
    parser.add_argument(
        "--call-result",
        choices=CALL_RESULTS,
        default=None,
        metavar="MODE",
        help="answer tools/call as MODE: " + ", ".join(CALL_RESULTS) + "; without it a call "
        "is a method not found, as before",
    )
    parser.add_argument(
        "--call-text",
        default="ok",
        metavar="TEXT",
        help="the text a call result carries (the note of structured, the message of rpc-error)",
    )
    parser.add_argument(
        "--chatter",
        action="store_true",
        help="emit a log notification before every listing answer, so the answer is not "
        "the next line on the wire",
    )
    args = parser.parse_args()

    offers = [name for name in args.offers.split(",") if name]
    out = sys.stdout.buffer
    handshaken = False
    answered = 0

    def write(payload: dict) -> None:
        out.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        out.flush()

    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        try:
            request = json.loads(raw)
        except ValueError:
            continue
        if args.silent or "id" not in request:
            continue  # a notification draws no answer, and neither does anything in silence

        identifier = request["id"]
        method = request.get("method")

        if method != "initialize" and args.silent_after_handshake and handshaken:
            continue
        if method != "initialize" and args.exit_after is not None and answered >= args.exit_after:
            return 9  # dies with the question unanswered
        if (
            method != "initialize"
            and args.answer_limit is not None
            and answered >= args.answer_limit
        ):
            continue

        if method == "initialize":
            handshaken = True
            if args.fail_initialize:
                write(
                    {
                        "jsonrpc": "2.0",
                        "id": identifier,
                        "error": {"code": -32602, "message": "unsupported protocol version"},
                    }
                )
                continue
            write(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": build_capabilities(offers, args.malformed_capability),
                        "serverInfo": {"name": args.server_name, "version": "1"},
                        **(
                            {"instructions": args.self_description}
                            if args.self_description is not None
                            else {}
                        ),
                    },
                }
            )
            continue

        if args.chatter:
            # A notification carries no id and is owed no answer. It sits between the
            # question and its answer, which is where a client that pairs by position
            # rather than by id comes apart.
            write(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {"level": "info", "logger": "fixture", "data": f"handling {method}"},
                }
            )

        if method == "tools/call" and args.call_result is not None:
            answered += 1
            for message in call_answers(args.call_result, args.call_text, identifier):
                write(message)
            continue

        body = listing(
            method,
            cursor_page(request),
            args.pages,
            args.tool_description,
            args.leading_tool,
            args.tool_name,
            args.tool_count,
            args.self_description,
        )
        answered += 1
        if body:
            write({"jsonrpc": "2.0", "id": identifier, "result": body})
        else:
            write(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )
    return args.exit_code


if __name__ == "__main__":
    sys.exit(main())
