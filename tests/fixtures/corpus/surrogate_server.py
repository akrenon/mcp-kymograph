"""A server that announces a name holding a lone surrogate, the way a hostile one could.

``"srv\\ud800"`` is what the wire carries as a JSON escape; the name cannot be written as UTF-8
by anything that takes it at its word. The rest is the discovery server's, so a run against it
is a complete driver run (the proxy and the store must cope with the name, not with a gap).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discovery_server  # noqa: E402

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--server-name", "srv\ud800", *sys.argv[1:]]
    sys.exit(discovery_server.main())
