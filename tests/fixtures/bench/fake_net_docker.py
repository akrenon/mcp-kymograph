"""Stands in for the docker CLI in the tests of the stage B network (runner/stage_b_net.py).

It keeps what exists — containers, volumes, networks, each with the run's label — in
``$FAKE_NET_STATE/state.json`` and answers the calls the module makes. Every call is appended to
``$FAKE_NET_STATE/calls.jsonl``.

``$FAKE_NET_FAIL_AT=N`` fails the Nth call that makes or asks for something (``network create``,
``volume create``, ``run``, ``exec``, ``logs``) and creates nothing in it; the removals and the
questions about what is left never fail that way. ``$FAKE_NET_KEEP=NAME`` makes ``rm -f`` leave
that container; ``$FAKE_NET_OVERLAP=N`` fails the first N ``network create`` with the answer of a
subnet that overlaps. ``$FAKE_NET_CONTEXT_DIGEST`` is the context label of the helper image.
``$FAKE_NET_NFT`` is a file with what ``nft -j list`` prints; ``$FAKE_NET_LOG`` one with what the
fixture server's log holds (``ready`` is always first; ``@ID@``, ``@id@``, ``@ID SPACED@`` and
``@HEX@`` in it become the canary's id of the volume in these forms, and with
``$FAKE_NET_LOG_AFTER_SERVER`` the lines come only after a server was started);
``$FAKE_NET_PROBE=fail`` makes one check of the probe false. The helpers in the namespaces of
the fixture server and PostgreSQL: see :func:`_nft` (``$FAKE_NET_NFT_FIXSRV``,
``$FAKE_NET_NFT_PG``, ``$FAKE_NET_NFT_LOAD_FAIL``; the rules loaded are kept in the state) and
:func:`_pg_logs` (``$FAKE_NET_PG_LOG``, ``$FAKE_NET_PG_LOG_AFTER_SERVER``).
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

IMAGE_ID = "sha256:" + "cd" * 32
STEPS = {("network", "create"), ("volume", "create"), ("run",), ("exec",), ("logs",)}


def _state_dir() -> Path:
    path = Path(os.environ["FAKE_NET_STATE"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load() -> dict:
    path = _state_dir() / "state.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"containers": {}, "volumes": {}, "networks": {}}


def _save(state: dict) -> None:
    (_state_dir() / "state.json").write_text(json.dumps(state))


def _option(args: list[str], name: str) -> str:
    return args[args.index(name) + 1]


def _label_of(args: list[str]) -> str:
    return _option(args, "--label") if "--label" in args else ""


def _is_step(args: list[str]) -> bool:
    return any(tuple(args[: len(step)]) == step for step in STEPS)


def _fail(message: str) -> int:
    print(f"Error response from daemon: {message}", file=sys.stderr)
    return 1


def _count_step() -> int:
    path = _state_dir() / "steps"
    done = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(done))
    return done


def _probe() -> int:
    result = {
        "dns_answers_fixture": True,
        "dns_nxdomain": True,
        "errors": {},
        "external_connect_fails": os.environ.get("FAKE_NET_PROBE") != "fail",
        "fixture": "10.0.0.10",
        "fixture_accepts": True,
        "default_route_without_gateway": True,
        "no_ipv6_address": True,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


def _run(args: list[str], state: dict) -> int:
    name = _option(args, "--name")
    if "-d" in args:
        state["containers"][name] = _label_of(args)
        _save(state)
        print("c0ffee")
        return 0
    if name.startswith("mcpb-probe-"):
        return _probe()
    if name.startswith("mcpb-nft-"):
        return _nft(args, name)
    if "-i" in args:
        sys.stdin.buffer.read()
    return 0


def _nft(args: list[str], name: str) -> int:
    """The helper in some container's namespace (``--network container:X``). The rules it is
    given are kept as ``rules-X.nft``; ``$FAKE_NET_NFT_LOAD_FAIL=PART`` fails the load into a
    container whose name has PART in it; a listing is ``$FAKE_NET_NFT``'s file, or, for a helper
    container, ``$FAKE_NET_NFT_FIXSRV`` / ``$FAKE_NET_NFT_PG`` where set."""
    target = _option(args, "--network").removeprefix("container:")
    if "-f" in args:
        rules = sys.stdin.buffer.read().decode("ascii")
        part = os.environ.get("FAKE_NET_NFT_LOAD_FAIL")
        if part and part in target:
            return _fail(f"fake failure loading rules into {target}")
        (_state_dir() / f"rules-{target}.nft").write_text(rules)
        return 0
    if "list" in args:
        variable = "FAKE_NET_NFT"
        if target.startswith("mcpb-fixsrv-"):
            variable = os.environ.get("FAKE_NET_NFT_FIXSRV") and "FAKE_NET_NFT_FIXSRV" or variable
        if target.startswith("mcpb-pg-"):
            variable = os.environ.get("FAKE_NET_NFT_PG") and "FAKE_NET_NFT_PG" or variable
        print(Path(os.environ[variable]).read_text())
    return 0


def _canary_id() -> str | None:
    """The id of the canary in the files of a fixture volume (``vol-*`` of the state), if any."""
    for path in sorted(_state_dir().glob("vol-*/*")):
        found = re.search(r"MCPB-CANARY-[A-Z0-9-]+-[0-9a-f]{8}", path.read_text(errors="ignore"))
        if found:
            return found.group(0)
    return None


#: What a log line may hold in place of the canary's id, as the fixture server would have
#: written what a server did with it: the id, in lower case, with spaces, its hex alone.
FORMS = {
    "@ID@": lambda i: i,
    "@id@": lambda i: i.lower(),
    "@ID SPACED@": lambda i: i.replace("-", " "),
    "@HEX@": lambda i: i[-8:].upper(),
}


def _pg_logs() -> int:
    """PostgreSQL's log: the image's start-up text on stdout, the log proper (``$FAKE_NET_PG_LOG``,
    a file) on stderr, and with ``$FAKE_NET_PG_LOG_AFTER_SERVER`` only once a server was started."""
    print("The files belonging to this database system will be owned by user postgres.")
    print("PostgreSQL init process complete; ready for start up.")
    extra = os.environ.get("FAKE_NET_PG_LOG")
    marked = (_state_dir() / "server-started").exists()
    if extra and (marked or not os.environ.get("FAKE_NET_PG_LOG_AFTER_SERVER")):
        print(Path(extra).read_text(), end="", file=sys.stderr)
    return 0


def _logs(args: list[str]) -> int:
    if args[-1].startswith("mcpb-pg-"):
        return _pg_logs()
    print(json.dumps({"event": "ready", "http_port": 8080, "dns_port": 53}))
    extra = os.environ.get("FAKE_NET_LOG")
    # ``$FAKE_NET_LOG_AFTER_SERVER``: the lines come only once a server of the run was started
    # (fake_b_docker leaves the mark), so that they are not part of the baseline.
    marked = (_state_dir() / "server-started").exists()
    if extra and (marked or not os.environ.get("FAKE_NET_LOG_AFTER_SERVER")):
        text = Path(extra).read_text()
        canary = _canary_id()
        if canary is not None:
            for form, make in FORMS.items():
                text = text.replace(form, make(canary))
        print(text, end="")
    return 0


def _ps(args: list[str], state: dict) -> int:
    filtered = _option(args, "--filter")
    if filtered.startswith("name="):
        name = filtered.removeprefix("name=^").removesuffix("$")
        print("c0ffee" if name in state["containers"] else "")
        return 0
    label = filtered.removeprefix("label=")
    print("\n".join(n for n, found in state["containers"].items() if found == label))
    return 0


def _rm(args: list[str], state: dict) -> int:
    name = args[-1]
    if name != os.environ.get("FAKE_NET_KEEP"):
        state["containers"].pop(name, None)
        _save(state)
    return 0


def main() -> int:
    args = sys.argv[1:]
    with (_state_dir() / "calls.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(args) + "\n")
    state = _load()
    command = args[0] if args else ""
    if command == "image":
        if "{{json .}}" in args:
            labels = {
                "mcp-kymograph.bench.context-sha256": os.environ.get("FAKE_NET_CONTEXT_DIGEST")
            }
            print(json.dumps({"Id": IMAGE_ID, "Config": {"Labels": labels, "Volumes": None}}))
        else:
            print(IMAGE_ID)
        return 0
    if _is_step(args):
        step = _count_step()
        if step == int(os.environ.get("FAKE_NET_FAIL_AT", "0")):
            return _fail(f"fake failure at step {step}")
    if command == "network" and args[1] == "create":
        overlaps = _state_dir() / "overlaps"
        done = int(overlaps.read_text()) if overlaps.exists() else 0
        if done < int(os.environ.get("FAKE_NET_OVERLAP", "0")):
            overlaps.write_text(str(done + 1))
            return _fail("invalid pool request: Pool overlaps with other one on this address space")
        state["networks"][args[-1]] = _label_of(args)
        _save(state)
        print("0123456789ab")
        return 0
    if command == "network" and args[1] == "rm":
        state["networks"].pop(args[-1], None)
        _save(state)
        return 0
    if command == "volume" and args[1] == "create":
        state["volumes"][args[-1]] = _label_of(args)
        _save(state)
        print(args[-1])
        return 0
    if command == "volume" and args[1] == "rm":
        state["volumes"].pop(args[-1], None)
        _save(state)
        return 0
    if command in ("volume", "network") and args[1] == "ls":
        label = _option(args, "--filter").removeprefix("label=")
        print("\n".join(n for n, found in state[command + "s"].items() if found == label))
        return 0
    if command == "run":
        return _run(args, state)
    if command == "exec":
        return 0
    if command == "logs":
        return _logs(args)
    if command == "ps":
        return _ps(args, state)
    if command == "rm":
        return _rm(args, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
