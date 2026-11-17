"""A server that talks on the network before it answers: a run of datagrams to one place,
then the discovery fixture.

For the sandbox's tests only, and only under ``--isolation runc``: 200 datagrams fit the
sink's receive queue many times over, so a healthy sink receives every one, and a sink made to
hold almost nothing cannot.
"""

import contextlib
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import discovery_server  # noqa: E402

DATAGRAMS = 200


def chatter() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for number in range(DATAGRAMS):
            with contextlib.suppress(OSError):
                sock.sendto(b"chatter %d" % number, ("203.0.113.20", 5000))


if __name__ == "__main__":
    chatter()
    sys.argv = [sys.argv[0], "--server-name", "chatty-server", *sys.argv[1:]]
    sys.exit(discovery_server.main())
