"""The project's reference server: the discovery fixture with one clean tool description.

A corpus entry with an **expected output**, not arbitrary material to compare: against the
scenario that asks for every signal (``scenarios/all-signals.yaml``) it yields no finding at
all. If it ever does, a signal has become too loose or the normalisation reaches too far,
and the pair notices before any real server is involved.

Its own file, rather than the discovery fixture with arguments, so that its content identity
(``mcp_kymograph.identity.from_content`` over this file and ``discovery_server.py``) is its own:
the reference and the poison server differ in content, and so in ``server_version``.
Further arguments are passed through to the base, so a test can still insert or rename a tool.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discovery_server  # noqa: E402

DESCRIPTION = "Returns the text it is given."

if __name__ == "__main__":
    sys.argv = [
        sys.argv[0],
        "--server-name",
        "reference-server",
        "--tool-description",
        DESCRIPTION,
        *sys.argv[1:],
    ]
    sys.exit(discovery_server.main())
