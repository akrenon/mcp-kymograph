"""``python -m mcp_kymograph.receiver <serve|register|pull|purge>`` — see ``docs/receiver.md``.

The HMAC key of a registration is read from stdin and from nowhere else: there is no option
for it, because an argument is visible in the process list and in shell history.

Exit codes: 0 done; 1 the data directory is unusable, or the sweep before ``pull`` failed, or it
could not enforce the deadlines of the registration asked for, or the registration could not be
read; 2 the input is refused (a
registration that does not validate, a duplicate, a bad option); 3 ``pull`` found no
registration, or ``purge`` found only a damaged one (it is deleted all the same).
"""

import argparse
import json
import signal
import sys
import threading
from collections.abc import Sequence

from . import limits
from .store import Clock, DataDirError, Rejected, Store, check_prefix, parse_registration, utc_now

EXIT_OK = 0
EXIT_DATA_DIR = 1
EXIT_REFUSED = 2
EXIT_NO_REGISTRATION = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m mcp_kymograph.receiver", description="Callback receiver."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, help: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help)
        sub.add_argument("--data", required=True, metavar="DIR", help="data directory, mode 0700")
        return sub

    serve = command("serve", "accept callbacks on 127.0.0.1")
    serve.add_argument("--port", type=int, required=True, metavar="N")
    command("register", "read a registration as JSON from stdin")
    pull = command("pull", "write entries as JSON Lines to stdout")
    pull.add_argument("--prefix", required=True, metavar="P")
    pull.add_argument("--after", type=int, default=0, metavar="N")
    purge = command("purge", "delete a registration, its key and its entries now")
    purge.add_argument("--prefix", required=True, metavar="P")
    return parser


def main(argv: Sequence[str] | None = None, clock: Clock = utc_now) -> int:
    args = build_parser().parse_args(argv)
    try:
        store = Store(args.data, clock)
    except DataDirError as error:
        print(f"receiver: {error}", file=sys.stderr)
        return EXIT_DATA_DIR
    if args.command == "serve":
        return serve(store, args.port)
    if args.command == "register":
        return register(store)
    if not check_prefix(args.prefix):
        print("receiver: --prefix is not a valid prefix", file=sys.stderr)
        return EXIT_REFUSED
    if args.command == "pull":
        return pull(store, args.prefix, args.after)
    return purge(store, args.prefix)


def serve(store: Store, port: int) -> int:
    from .server import Receiver

    if not 0 <= port <= 65535:
        print("receiver: --port out of range", file=sys.stderr)
        return EXIT_REFUSED
    receiver = Receiver(store, port)
    # shutdown() waits for serve_forever, so it must not run on the thread that serves.
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=receiver.shutdown).start())
    print(f"receiver: listening on {limits.BIND_ADDRESS}:{receiver.port}", file=sys.stderr)
    try:
        receiver.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        receiver.server_close()
    return EXIT_OK


def register(store: Store) -> int:
    raw = sys.stdin.buffer.read(limits.MAX_REGISTRATION_BYTES + 1)
    if len(raw) > limits.MAX_REGISTRATION_BYTES:
        print("receiver: registration refused: $: too large", file=sys.stderr)
        return EXIT_REFUSED
    try:
        try:
            document = json.loads(raw)
        except ValueError:
            raise Rejected("$: not valid JSON") from None
        reg = parse_registration(document)
        store.register(reg)
    except Rejected as error:
        print(f"receiver: registration refused: {error}", file=sys.stderr)
        return EXIT_REFUSED
    print(f"registered {reg.prefix}")
    return EXIT_OK


def pull(store: Store, prefix: str, after: int) -> int:
    try:
        entries = store.read_entries(prefix, after)
    except Exception as error:
        print(f"receiver: reading failed ({type(error).__name__}), nothing pulled", file=sys.stderr)
        return EXIT_DATA_DIR
    if prefix in store.unenforced:
        print(
            "receiver: deadlines of this registration could not be enforced, nothing pulled",
            file=sys.stderr,
        )
        return EXIT_DATA_DIR
    if not store.exists(prefix):
        print(f"receiver: no registration for {prefix} (expired or deleted)", file=sys.stderr)
        return EXIT_NO_REGISTRATION
    for entry in entries:
        print(json.dumps(entry, separators=(",", ":")))
    return EXIT_OK


def purge(store: Store, prefix: str) -> int:
    found = store.purge(prefix)
    if found is None:
        print(f"receiver: no usable registration for {prefix} (damaged, deleted)", file=sys.stderr)
        return EXIT_NO_REGISTRATION
    print(f"purged {prefix}" if found else f"nothing to purge for {prefix}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
