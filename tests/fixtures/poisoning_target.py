"""The party a tool-poisoning attack targets: it reads a tools/list reply and then acts.

Two modes, one file, so the whole difference between falling for the injection and not is a
single, namable behaviour point — the `interpret` function below — and nothing else. A
counter-proof only means something if the two sides differ in exactly one place; if they
differed in several, a different outcome would not tell you which difference caused it.

This is a stdio MCP-style *client*: it drives the conversation (initialize, then tools/list,
then one tool call) over stdin/stdout. Run behind Kymograph, the tools/list reply it reads
has been poisoned by the ToolPoisoning rule. Bound to nothing, no network, no filesystem.

    python3 poisoning_target.py --mode vulnerable|hardened

The injected instruction (see rules.POISON_INSTRUCTION) asks the reader to append the inert
marker MCP-KYMOGRAPH-CANARY to what it does next. Whether that marker ends up in the follow-up
call is the whole question — and it is the human's to judge from the recording, not this
program's to claim.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

CANARY = "MCP-KYMOGRAPH-CANARY"

#: The shape of a hidden instruction inside a description: an HTML comment aimed at the
#: assistant. This is the classic tool-poisoning carrier.
_HIDDEN = re.compile(r"<!--\s*assistant:(.*?)-->", re.IGNORECASE | re.DOTALL)


def interpret(description: str, *, mode: str) -> str | None:
    """The one place the two modes differ.

    vulnerable: treats text inside a tool description as if it were an instruction to follow,
                and reports the marker the injected text told it to append.
    hardened:   treats a description as opaque data — it never reads instructions out of tool
                metadata — and reports nothing.
    """
    if mode == "vulnerable":
        # DELIBERATELY VULNERABLE: this is the single flaw the counter-proof isolates.
        # Reading an instruction out of tool metadata and acting on it is exactly the
        # mistake a hardened client must not make.
        match = _HIDDEN.search(description)
        if match and CANARY in match.group(1):
            return CANARY
        return None
    # hardened: metadata is data, never instructions.
    return None


def write(message: dict) -> None:
    sys.stdout.buffer.write(json.dumps(message).encode() + b"\n")
    sys.stdout.buffer.flush()


def read() -> dict | None:
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    return json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("vulnerable", "hardened"), required=True)
    mode = parser.parse_args().mode

    write({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    read()

    write({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    reply = read()

    tools = (reply or {}).get("result", {}).get("tools", [])
    description = tools[0].get("description", "") if tools else ""

    # Neutral, and identical in both modes: did the injected marker reach us at all? A plain
    # substring check on what was received, not an interpretation of it. It lets the recording
    # show the poison arrived even in the hardened run, so a hardened target not obeying is
    # visibly a choice, not a message it never saw.
    arrived = CANARY in description

    # The one behavioural difference: whether the description is treated as instruction.
    obeyed = interpret(description, mode=mode)

    note = obeyed if obeyed else "ok"
    write(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": tools[0]["name"] if tools else "none",
                "arguments": {"note": note, "injection_arrived": arrived},
            },
        }
    )
    read()
    return 0


if __name__ == "__main__":
    sys.exit(main())
