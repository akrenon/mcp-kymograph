"""Stands in for the docker CLI in the tests of ``bench.py run --stage b``.

Three fakes in one. The calls of the network module (volume, network, helpers, probe, counters,
logs, removal) are answered by ``fake_net_docker.py`` and need what that one needs
(``$FAKE_NET_STATE``, ``$FAKE_NET_NFT``, ``$FAKE_NET_CONTEXT_DIGEST``). A server without a
volume or a network (the kind ``none``) is stage A's: ``fake_docker.py`` becomes the discovery
server. What this one adds:

* ``image``: an image has the id of its kind (the server's, the helper's, the pinned python),
  and the server's labels are ``$FAKE_DOCKER_LABELS`` (JSON); the helper's context label is
  ``$FAKE_NET_CONTEXT_DIGEST``.
* The filling container (``mcpb-fill-…``) unpacks the tar on its stdin into a directory of the
  state, one per volume (``vol-<volume>``). ``$FAKE_B_FILL_FAIL=N`` makes the first N fills fail.
* The server of the run (``mcpb-srv-<nonce>``) becomes ``tests/fixtures/bench/stage_b_server.py``
  with ``$STAGE_B_ROOT`` the directory of the run's volume, for every kind: a kind with a
  network mounts no volume in the server, but a stand-in has no fixture server to ask.
  ``$FAKE_B_SERVER_DIE=N`` makes the first N servers end at once, without a word.
* ``$FAKE_B_CALLS`` is a file; the command of every ``run`` of a server is appended to it as one
  JSON list per line.
"""

from __future__ import annotations

import json
import os
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fake_docker  # noqa: E402 - the fakes sit next to this file
import fake_net_docker  # noqa: E402

SERVER = HERE / "stage_b_server.py"
FIXTURES_PATH = "/srv/fixtures"
CONTEXT_LABEL = "mcp-kymograph.bench.context-sha256"
IDS = {"nft": "ee", "python": "dd", "server": "ab"}


def _image_id(reference: str) -> str:
    kind = "nft" if "helper-nft" in reference else "python" if "python:" in reference else "server"
    return "sha256:" + IDS[kind] * 32


def _image(args: list[str]) -> int:
    reference = args[-1]
    if "{{json .}}" in args:
        if reference == "sha256:" + IDS["nft"] * 32:
            labels = {CONTEXT_LABEL: os.environ.get("FAKE_NET_CONTEXT_DIGEST")}
        else:
            labels = json.loads(os.environ.get("FAKE_DOCKER_LABELS", "{}"))
        config = {"Labels": labels, "Volumes": None}
        print(json.dumps({"Id": reference, "Created": fake_docker.CREATED, "Config": config}))
    else:
        print(_image_id(reference) if not reference.startswith("sha256:") else reference)
    return 0


def _option_values(args: list[str], name: str) -> list[str]:
    return [args[i + 1] for i, part in enumerate(args[:-1]) if part == name]


def _counted(what: str) -> int:
    """How many times ``what`` has been asked before, counting this one."""
    path = fake_net_docker._state_dir() / f"count-{what}"
    done = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(done))
    return done


def _volume_dir(volume: str) -> Path:
    return fake_net_docker._state_dir() / f"vol-{volume}"


def _fill(args: list[str]) -> int:
    if _counted("fill") <= int(os.environ.get("FAKE_B_FILL_FAIL", "0")):
        sys.stdin.buffer.read()
        print("Error response from daemon: fake fill failure", file=sys.stderr)
        return 1
    mount = next(v for v in _option_values(args, "-v") if v.endswith(f":{FIXTURES_PATH}"))
    target = _volume_dir(mount.split(":")[0])
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        archive.extractall(target, filter="data")
    return 0


def _server(args: list[str]) -> int:
    log = os.environ.get("FAKE_B_CALLS")
    if log:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(args) + "\n")
    if _counted("server") <= int(os.environ.get("FAKE_B_SERVER_DIE", "0")):
        return 1
    (fake_net_docker._state_dir() / "server-started").write_text("1")
    nonce = _option_values(args, "--name")[0].removeprefix("mcpb-srv-")
    after = args[next(i for i, part in enumerate(args) if part.startswith("sha256:")) + 1 :]
    env = dict(os.environ, STAGE_B_ROOT=str(_volume_dir(f"mcpb-fix-{nonce}")))
    os.execve(sys.executable, [sys.executable, "-B", str(SERVER), *after], env)  # noqa: S606
    return 0  # not reached: the process is replaced


def main() -> int:
    args = sys.argv[1:]
    command = args[0] if args else ""
    if command == "image" and args[1] == "inspect":
        return _image(args)
    if command == "run" and "--name" in args:
        name = _option_values(args, "--name")[0]
        if name.startswith("mcpb-fill-"):
            return _fill(args)
        if name.startswith("mcpb-srv-"):
            return _server(args)
        if "-d" not in args and not name.startswith(("mcpb-probe-", "mcpb-nft-", "mcpb-route-")):
            # The server of kind ``none``: stage A's command, with its own name.
            fake_docker.main()
            return 0
    return fake_net_docker.main()


if __name__ == "__main__":
    sys.exit(main())
