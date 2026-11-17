"""The one-shot helper: the only process that ever changes the namespace, and only once.

Runs with ``CAP_NET_ADMIN`` and nothing else, joined to the sink's namespace, before the target
exists, and is gone before the target is created. In this order, every step a hard failure:

1. The namespace is untouched: loopback only, no ruleset. Anything else means this is not
   the namespace the sandbox just made, and nothing here is built on top of it.
2. The ruleset goes in first, in one transaction for both address families. From here on,
   every packet that will ever leave a process is redirected or recorded.
3. Only then the dummy device and the default routes. Before this step there was no route,
   so nothing could be sent anywhere; after it, everything sent goes into a device that
   discards it. There is no moment with a route and without the ruleset.
4. The ruleset is read back as the kernel holds it, and its digest printed for the host to
   compare. The host decides; the helper only reports.

Prints one JSON object on stdout and exits 0, or exits 1 with the reason.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

try:
    from . import common
except ImportError:  # run as a script inside the container
    import common  # type: ignore[no-redef]


def run(argv: tuple[str, ...] | list[str]) -> bytes:
    done = subprocess.run(argv, capture_output=True, check=False)  # noqa: S603
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()[:300]
        raise RuntimeError(f"{' '.join(argv)}: exit {done.returncode}: {detail}")
    return done.stdout


def untouched() -> None:
    links = json.loads(run(("ip", "-j", "-d", "link")))
    names = common.interface_inventory(links)
    if names != [["lo", "loopback"]]:
        raise RuntimeError(f"the namespace is not fresh: interfaces {names}")
    if run(("nft", "list", "ruleset")).strip():
        raise RuntimeError("the namespace is not fresh: it already holds a ruleset")


def main() -> int:
    rules = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.nft")
    try:
        untouched()
        run(("nft", "-f", rules))
        for step in common.INTERFACE_SETUP:
            run(step)
        readback = run(common.READBACK)
        version = run(("nft", "--version")).decode("utf-8", "replace").strip()
    except (RuntimeError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:500]}))
        return 1
    print(
        json.dumps(
            {"ok": True, "readback": common.ruleset_digest(readback), "nft_version": version}
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
