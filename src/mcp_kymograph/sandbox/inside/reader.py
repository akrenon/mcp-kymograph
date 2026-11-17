"""The reader: takes the authoritative record out of the namespace, and changes nothing.

One-shot, ``CAP_NET_ADMIN`` only, joined to the sink's namespace — once after the probe (the
baseline) and once after the target is gone. The counters and sets it reads are kernel state
no process without ``CAP_NET_ADMIN`` can read or alter, which is what makes them the record
the sink's own account is checked against: the target shares the namespace with the sink,
and the sink reads what the target sends. The reader never runs while the target does.

Besides the record: the ruleset as read back, the interfaces and the socket tables, so the
host can see that none of them moved.

Prints one JSON object; the host interprets it. Exits 1 if any read fails.
"""

from __future__ import annotations

import json
import subprocess
import sys

try:
    from . import common
except ImportError:  # run as a script inside the container
    import common  # type: ignore[no-redef]


def run(argv: tuple[str, ...]) -> bytes:
    done = subprocess.run(argv, capture_output=True, check=False)  # noqa: S603
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()[:300]
        raise RuntimeError(f"{' '.join(argv)}: exit {done.returncode}: {detail}")
    return done.stdout


def main() -> int:
    try:
        record = json.loads(run(common.AUTHORITATIVE_READ))
        readback = common.ruleset_digest(run(common.READBACK))
        links = json.loads(run(("ip", "-j", "-d", "link")))
    except (RuntimeError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:500]}))
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "record": record,
                "readback": readback,
                "interfaces": common.interface_inventory(links),
                "sockets": common.socket_inventory(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
