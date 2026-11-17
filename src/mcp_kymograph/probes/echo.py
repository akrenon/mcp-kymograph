"""The test module: lists the tools and calls one of them, once, with a text.

It exists to run the frame end to end against a real server without doing anything of its own: the
tool is the operator's choice (``--probe-option tool=NAME``) and so are its arguments
(``--probe-option text=…`` becomes ``{"text": …}``; without it the tool is called with none). A
tool the server did not list is not called (the frame ends the module with ``tool_not_listed``), and
one the engagement does not allow is stopped by the scope guard.
"""

from __future__ import annotations

from collections.abc import Mapping

from mcp_kymograph.probes.base import Context, Probe


class Echo(Probe):
    name = "echo"
    description = "list the tools, then call the one named by tool=NAME once, with text=… if given"
    max_calls = 21  # a listing of 20 pages (the driver's MAX_PAGES) and the one call
    required = ("tool",)
    optional = ("text",)

    async def run(self, context: Context, options: Mapping[str, str]) -> None:
        await context.tools()
        arguments = {"text": options["text"]} if "text" in options else {}
        await context.call(options["tool"], arguments)
