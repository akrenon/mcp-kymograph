"""Prints, as JSON, what the installed `fetch` server (SDK 1.x) offers: its tools, resources and
prompts, as the SDK's own list handlers answer them. Run inside the image by
tests/test_real_servers.py (``python -c``), where the package is installed.
"""

import asyncio
import contextlib
import json

import mcp.types as types
import mcp_server_fetch.server as fetch


class Captured(Exception):
    pass


built = []


class Recording(fetch.Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        built.append(self)


@contextlib.asynccontextmanager
async def not_stdio():
    raise Captured
    yield  # pragma: no cover


async def ask(server, request, key):
    handler = server.request_handlers.get(type(request))
    if handler is None:
        return []
    return getattr(((await handler(request)).root), key)


async def main():
    fetch.Server = Recording
    fetch.stdio_server = not_stdio
    with contextlib.suppress(Captured):
        await fetch.serve()
    (server,) = built
    tools = await ask(server, types.ListToolsRequest(method="tools/list"), "tools")
    prompts = await ask(server, types.ListPromptsRequest(method="prompts/list"), "prompts")
    resources = await ask(server, types.ListResourcesRequest(method="resources/list"), "resources")
    print(
        json.dumps(
            {
                "tools": [t.name for t in tools],
                "resources": [[str(r.uri), r.name] for r in resources],
                "prompts": [p.name for p in prompts],
                "latest": types.LATEST_PROTOCOL_VERSION,
            }
        )
    )


asyncio.run(main())
