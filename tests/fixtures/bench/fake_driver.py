"""``kymograph`` as the driver container runs it, on the host, for the fake docker.

The container shares the server's network namespace and speaks to it at 127.0.0.1, which on the
host is where the fake server listens. Nothing is changed: the arguments are the ones the runner
gave, with the mounts as host paths.
"""

from __future__ import annotations

import runpy
import sys

sys.argv = ["kymograph", *sys.argv[1:]]
runpy.run_module("mcp_kymograph.cli", run_name="__main__", alter_sys=True)
