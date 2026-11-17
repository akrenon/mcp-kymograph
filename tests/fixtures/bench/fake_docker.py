"""Stands in for the docker CLI in the benchmark runner's tests.

Answers the few calls the runner makes, and for ``run`` becomes the discovery fixture server,
so that a real ``kymograph drive`` speaks to a real process without Docker. Every call is
appended to ``$FAKE_DOCKER_LOG`` (one JSON list per line) when that is set.

``$FAKE_DOCKER_LEFTOVER=1`` makes ``ps`` report the run's container as still present.
``$FAKE_DOCKER_SERVER_ARGS`` (a JSON list of strings) is appended to the fixture server's
arguments on ``run``, to switch on what the server says about itself.
``image inspect --format '{{json .}}'`` prints an inspect object: the image id, a fixed
creation time, ``Config.Labels`` from ``$FAKE_DOCKER_LABELS`` (a JSON object; ``{}`` if unset)
and ``Config.Volumes`` from ``$FAKE_DOCKER_VOLUMES`` (JSON; ``null`` if unset). Any other
``image inspect`` prints the image id; ``$FAKE_DOCKER_INSPECT=broken`` makes the inspect object
unreadable. ``version`` prints ``0.0.0-fake``, ``context show`` prints ``default``, and
``info --format '{{json .}}'`` prints the few daemon facts the runner records (``INFO``), or
something unreadable with ``$FAKE_DOCKER_INFO=broken``.

For a run over Streamable HTTP, ``$FAKE_DOCKER_STATE`` (a directory) holds what exists:
``network create`` and ``network rm`` keep a file per network (``$FAKE_DOCKER_NETWORK=fail``
makes ``create`` fail); ``run -d`` starts the HTTP fixture server in the background on
127.0.0.1 at ``$FAKE_DOCKER_HTTP_PORT``, with ``$FAKE_DOCKER_SERVER_ARGS`` appended; ``rm -f``
stops it; ``ps`` lists a container the state holds. A ``run`` named ``mcpb-probe-…`` prints a
probe result (``$FAKE_DOCKER_PROBE``: ``fail`` fails one check, ``broken`` prints no JSON), and
one named ``mcpb-driver-…`` runs ``kymograph drive`` for real (``fake_driver.py``), with the
mounts translated to host paths. The driver has to be in the namespace of the run's server
(``--network container:NAME``, NAME a container ``run -d`` started with the driver's nonce) and
without an option docker refuses there; anything else is refused, exit 125, as docker would.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

IMAGE_ID = "sha256:" + "ab" * 32
CREATED = "2026-01-02T03:04:05.123456789Z"
SERVER = Path(__file__).resolve().parent.parent / "discovery_server.py"
HTTP_SERVER = Path(__file__).resolve().parent.parent / "http_server.py"
DRIVER = Path(__file__).resolve().parent / "fake_driver.py"
INFO = {
    "KernelVersion": "0.0.0-fake-kernel",
    "DefaultRuntime": "runc",
    "SecurityOptions": ["name=seccomp,profile=builtin"],
    "LoggingDriver": "json-file",
}


def _state() -> Path | None:
    directory = os.environ.get("FAKE_DOCKER_STATE")
    if not directory:
        return None
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _option(args: list[str], name: str) -> str:
    return args[args.index(name) + 1]


def _network(args: list[str]) -> int:
    state = _state()
    if args[1] == "create":
        if os.environ.get("FAKE_DOCKER_NETWORK") == "fail":
            print("Error response from daemon: fake failure", file=sys.stderr)
            return 1
        if state is not None:
            (state / f"net-{args[-1]}").write_text("")
        print("0123456789ab")
        return 0
    if args[1] == "rm":
        if os.environ.get("FAKE_DOCKER_NETWORK") == "keep":
            print("Error response from daemon: network has active endpoints", file=sys.stderr)
            return 1
        marker = None if state is None else state / f"net-{args[-1]}"
        if marker is None or not marker.exists():
            print(f"Error: No such network: {args[-1]}", file=sys.stderr)
            return 1
        marker.unlink()
        print(args[-1])
    return 0


def _start_server(args: list[str]) -> int:
    state = _state()
    port = os.environ["FAKE_DOCKER_HTTP_PORT"]
    extra = json.loads(os.environ.get("FAKE_DOCKER_SERVER_ARGS", "[]"))
    process = subprocess.Popen(  # noqa: S603 - test fixture
        [sys.executable, str(HTTP_SERVER), "--port", port, *extra],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        # Not the pipe of the caller, which would wait for the server to end.
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    if state is not None:
        (state / f"ctr-{_option(args, '--name')}").write_text(str(process.pid))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", int(port)), timeout=1).close()
            break
        except OSError:
            time.sleep(0.05)
    print("deadbeef")
    return 0


def _probe() -> int:
    mode = os.environ.get("FAKE_DOCKER_PROBE", "")
    if mode == "broken":
        print("not json")
        return 0
    result = {
        "external_name_unresolved": True,
        "ipv6_off": mode != "fail",
        "no_default_route": True,
        "no_gateway_connection": True,
        "server_accepts": True,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


#: What docker refuses beside ``--network container:…``.
CONFLICTS = ("--dns", "--dns-search", "--network-alias", "--hostname", "-h", "--publish", "-p",
             "--publish-all", "-P", "--add-host", "--mac-address", "--expose")  # fmt: skip


def _joins_the_server(args: list[str]) -> bool:
    """Whether the driver joins the namespace of its own run's server and nothing docker refuses."""
    network = _option(args, "--network") if "--network" in args else ""
    holder = network.removeprefix("container:")
    nonce = _option(args, "--name").rsplit("-", 1)[-1]
    state = _state()
    if not network.startswith("container:") or not holder.endswith(f"-{nonce}"):
        print(f"fake docker: the driver is not in its server's namespace: {network!r}",
              file=sys.stderr)  # fmt: skip
        return False
    if state is None or not (state / f"ctr-{holder}").exists():
        print(f"Error response from daemon: No such container: {holder}", file=sys.stderr)
        return False
    image = next((at for at, part in enumerate(args) if part.startswith("python:")), len(args))
    refused = [part for part in args[:image] if part.split("=")[0] in CONFLICTS]
    if refused:
        print(f"docker: conflicting options: {' '.join(refused)} and the network mode",
              file=sys.stderr)  # fmt: skip
        return False
    return True


def _drive(args: list[str]) -> int:
    if not _joins_the_server(args):
        return 125
    mounts = {}
    for index, part in enumerate(args):
        if part == "-v":
            host, inside = args[index + 1].split(":")[:2]
            mounts[inside] = host
    inner = args[args.index("-m") + 2 :]
    translated = [mounts.get(part, part) for part in inner]
    # The scenario is mounted as a file under /scenario: translated by its whole path.
    return subprocess.run(  # noqa: S603 - test fixture
        [sys.executable, str(DRIVER), *translated], check=False
    ).returncode


def _remove(name: str) -> None:
    state = _state()
    marker = None if state is None else state / f"ctr-{name}"
    if marker is not None and marker.exists():
        with contextlib.suppress(OSError):
            os.killpg(int(marker.read_text()), signal.SIGKILL)
        marker.unlink()


def main() -> None:
    args = sys.argv[1:]
    log = os.environ.get("FAKE_DOCKER_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(args) + "\n")
    command = args[0] if args else ""
    if command == "image":
        wanted = args[args.index("--format") + 1] if "--format" in args else ""
        if wanted == "{{json .}}" and os.environ.get("FAKE_DOCKER_INSPECT") == "broken":
            print("not json")
        elif wanted == "{{json .}}":
            config = {
                "Labels": json.loads(os.environ.get("FAKE_DOCKER_LABELS", "{}")),
                "Volumes": json.loads(os.environ.get("FAKE_DOCKER_VOLUMES", "null")),
            }
            print(json.dumps({"Id": IMAGE_ID, "Created": CREATED, "Config": config}))
        else:
            print(IMAGE_ID)
    elif command == "version":
        print("0.0.0-fake")
    elif command == "info":
        print("not json" if os.environ.get("FAKE_DOCKER_INFO") == "broken" else json.dumps(INFO))
    elif command == "context":
        print("default")
    elif command == "network":
        sys.exit(_network(args))
    elif command == "rm":
        _remove(args[-1])
    elif command == "ps":
        state = _state()
        wanted = args[args.index("--filter") + 1].removeprefix("name=^").removesuffix("$")
        held = state is not None and (state / f"ctr-{wanted}").exists()
        print("c0ffee" if held or os.environ.get("FAKE_DOCKER_LEFTOVER") == "1" else "")
    elif command == "run" and "-d" in args:
        sys.exit(_start_server(args))
    elif command == "run" and _option(args, "--name").startswith("mcpb-probe-"):
        sys.exit(_probe())
    elif command == "run" and _option(args, "--name").startswith("mcpb-driver-"):
        sys.exit(_drive(args))
    elif command == "run":
        extra = json.loads(os.environ.get("FAKE_DOCKER_SERVER_ARGS", "[]"))
        os.execv(sys.executable, [sys.executable, str(SERVER), *extra])  # noqa: S606 - test fixture


if __name__ == "__main__":
    main()
