"""A small server on the official Python SDK (mcp 2.3.0), Streamable HTTP, protocol 2026-07-28.

One tool, one resource, one prompt. EXPECTED is what tests/test_real_servers.py reads from this
file (not by importing it) to know what the recording must show.
"""

from mcp.server.mcpserver import MCPServer

EXPECTED = {
    "tools": ["echo"],
    "resources": [["reference://greeting", "greeting"]],
    "prompts": ["greet"],
}

server = MCPServer("reference-http")


@server.tool()
def echo(text: str) -> str:
    """Return the text it is given."""
    return text


@server.resource("reference://greeting", name="greeting")
def greeting() -> str:
    """A fixed greeting."""
    return "hello"


@server.prompt()
def greet(name: str) -> str:
    """Ask for a greeting to someone."""
    return f"Greet {name}."


if __name__ == "__main__":
    server.run("streamable-http", host="0.0.0.0", port=8000)  # noqa: S104 (in a container)
