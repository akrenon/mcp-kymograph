"""Prints, as JSON, what the installed `fetch` server (SDK 2.x) offers: its tools, resources and
prompts, as the SDK's own lists answer them. Run inside the image by tests/test_real_servers.py
(``python -c``), where the package is installed.
"""

import asyncio
import json

import mcp_server_fetch.server as fetch
from mcp.types.version import LATEST_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSIONS


async def main():
    server = fetch.create_server()
    tools = await server.list_tools()
    prompts = await server.list_prompts()
    resources = await server.list_resources()
    print(
        json.dumps(
            {
                "tools": [t.name for t in tools],
                "resources": [[str(r.uri), r.name] for r in resources],
                "prompts": [p.name for p in prompts],
                "latest": LATEST_PROTOCOL_VERSION,
                "modern": list(MODERN_PROTOCOL_VERSIONS),
            }
        )
    )


asyncio.run(main())
