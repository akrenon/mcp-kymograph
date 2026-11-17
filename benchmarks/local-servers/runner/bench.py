"""Benchmark runner for MCP servers that are not this project's own: build, drive, keep evidence.

Stage A only lists. Each server is driven with Kymograph's discovery script — ``initialize``
and the listings, nothing called, nothing planted — and the built-in walk inspects what the
server says about itself. Beside the walk comes an observation file without rules
(``scenarios/stage-a-self-description.yaml``): the same signals, applied to the ``instructions``
of the ``initialize`` answer and to the titles and descriptions in the prompt and resource
listings, which the walk does not read. It changes no traffic, and the companion names it. The
runner judges nothing: a run's state is what ``kymograph
verdict`` reads from the recording, and a signal is what the walk recorded.

**Why there is a companion file.** These servers are third-party code. Kymograph runs such
code only under gVisor, which it does not provide yet, so a corpus entry for one is refused.
Stage A therefore drives each server through ``kymograph drive`` without a manifest, with
``docker run`` as the server command: Kymograph starts the docker CLI as an ordinary child
process and records ``isolation: host``, because the container is not one it manages. Beside
every recording the runner writes ``container.json`` — the exact docker command, the image id,
the times, the observation file and the SHA-256 of the recording — and writes it only after
checking that the recording's own ``run_started.argv`` is that same command and that it ran
that observation file, with no rules. "Ran in a container" is then
something a reader can check against the recording, not a claim beside it.

**What the container is, and is not.** Plain Docker: no network and no host name servers in its
resolver file, a private IPC namespace without ``/dev/shm``, a read-only root with ``/tmp`` as
the one writable directory, no capabilities, no privilege escalation, an unprivileged user,
bounded processes and memory, and no proxy setting from the docker client's own configuration.
In-memory IPC objects (``/dev/mqueue``, System V) remain possible inside that namespace and
vanish with it. An image that declares a volume is refused: docker would mount a writable one
despite the read-only root. Not gVisor, and not Kymograph's runc sandbox: an attempt to reach
the network fails and is not recorded anywhere. Which daemon ran it, with which runtime,
security options and log driver, is in the companion.

**The image is the one the definitions describe.** ``build`` builds one stage from the pinned
base and labels the image with the digest of its context and of the definition's claims;
``run`` refuses an image whose labels do not match both as they are now.

**Nothing here writes into the public tree.** Recordings go to ``--out-dir`` (default
``runs/local-servers``, which git ignores). A directory inside ``benchmarks/``, or anywhere else
in the repository that git would track, is refused before anything starts.

    python benchmarks/local-servers/runner/bench.py build --definitions DIR --server NAME
    python benchmarks/local-servers/runner/bench.py run --definitions DIR --server NAME
    python benchmarks/local-servers/runner/bench.py compare RUN_DIR RUN_DIR

``compare`` lists where two runs of one server differ, from both sides, and where their inputs
differ (the transport among them). It does not rate: an empty ``differences`` list is the whole
statement.

**Streamable HTTP.** A server whose definition says ``launch.transport: streamable-http`` (with
``port`` and ``path``) is driven over HTTP by a second container, not through a pipe. ``run``
makes a network of its own (``--internal``, and ``inhibit_ipv4`` so that the host has no address
in it), starts the server in it under the name ``server`` with no published port, lets a probe
in the same network show that there is no way out (no route, no connection to the gateway, no
outside name, no IPv6) and that the server takes a connection, and only then starts the driver:
``kymograph drive --http http://127.0.0.1:<port><path>`` in a container of the pinned
``python:3.12-slim`` that joins the server's network namespace, with the repository's
``src/``, the runner's own ``yaml`` package and the observation file mounted read-only and the
output directory the one writable mount. Containers and network are removed afterwards,
whatever happened. The companion is then version 5. Plain Docker does not record connection
attempts: the probe shows that there is no way out, not what the server tried.

**Stage B** (``run --stage b``) drives the server with the script its definition names and the
observation file ``scenarios/stage-b-call-result.yaml``, against a fixture that holds a canary
(``fixtures.py``; ``stage_b_net.py`` for the volume and, for the kinds that need one, the
network). It judges nothing either: the outcome is a function of what ``kymograph verdict``
reads from the recording and of whether the canary's id stands in the answers to ``tools/call``
(:func:`stage_b_outcome`). An attempt that ended ``server_failed``, or that did not run because
the volume, the probe or the fixture server failed, is tried once more, and then skipped with
where both lie. The companion is version 6, and the id of the canary is in no companion.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import importlib.util
import json
import os
import platform
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import mcp_kymograph
from mcp_kymograph import script as script_files
from mcp_kymograph import verdict
from mcp_kymograph.masking import Masker
from mcp_kymograph.scenario import Scenario, ScenarioError, parse_yaml
from mcp_kymograph.scenario import load as load_scenario

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT_DIR = Path("runs/local-servers")
DEFINITIONS_FILE = "versions.yaml"
#: Where the public results go: the target of ``export`` without ``--out``, and the directory of
#: the runs inside an exported tree. No other module of the runner writes there.
RESULTS_DIR = "results"
EXPORT_TARGET = Path("benchmarks") / "local-servers" / RESULTS_DIR
#: The observation file every stage A run carries. Fixed, not an option: the results all say
#: the same thing about what was looked at.
SCENARIO = Path(__file__).resolve().parents[1] / "scenarios" / "stage-a-self-description.yaml"
#: The observation file every stage B run carries: the nine signals on the result of
#: ``tools/call``, no rules.
SCENARIO_B = Path(__file__).resolve().parents[1] / "scenarios" / "stage-b-call-result.yaml"
COMPANION = "container.json"
#: Version 6 is stage B's: the fixture, the canary's observation, the script, the network and the
#: outcome are in it; everything else is as in version 5.
COMPANION_VERSION_B = 6
#: Version 5: the environment enters as an HMAC under a key of the suite, with the key's id.
#: Stdio and HTTP runs share it; the field ``transport`` tells them apart.
COMPANION_VERSION = 5
#: Companions of these versions carry ``inputs.environment_sha256``; ``compare`` refuses them.
COMPANION_VERSIONS_OLD = (3, 4)
KEY_BYTES = 32
#: What the key id is the HMAC of: the first 16 hex characters of it name the key, and nothing
#: else about it. A fixed input, not the tool's name: it is the text of before the tool was
#: renamed and stays so, or a key would get another id than the one the companions of the runs
#: made with it carry, and ``compare --key`` would refuse them.
KEY_ID_TEXT = b"mcp-polygraph bench key id 1"
IMAGE_REPOSITORY = "mcp-kymograph-bench"
#: The image label that carries the digest of the context the image was built from.
CONTEXT_LABEL = "mcp-kymograph.bench.context-sha256"
#: The image label that carries the digest of what the definition says about the image.
DEFINITION_LABEL = "mcp-kymograph.bench.definition-sha256"
COMPARE_VERSION = 1

#: What the methodology and every companion call the isolation. The recording says ``host``.
ISOLATION = "container (docker), not managed by Kymograph, not gVisor"

#: The container's bounds, the same for every server. No network at all: stage A lists, and a
#: listing needs nothing from outside. ``/tmp`` is the one writable directory, small and not
#: executable; ``--ipc none`` leaves out ``/dev/shm``, which docker otherwise mounts writable.
#: The resolver entries are set to loopback, so the host's name servers do not appear in the
#: container's ``/etc/resolv.conf`` even though they could not be reached.
HARDENING: tuple[str, ...] = (
    "--network", "none",
    "--dns", "127.0.0.1",
    "--dns-search", ".",
    "--ipc", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",  # noqa: S108 - the container's /tmp
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "65534:65534",
    "--pids-limit", "256",
    "--memory", "512m",
)  # fmt: skip

#: The proxy variables the docker CLI copies into a container from its own configuration
#: (``proxies`` in ``config.json``) unless the command sets them: set here, empty, so that
#: nothing reaches the container that the command line does not show.
PROXY_VARIABLES: tuple[str, ...] = (
    "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "FTP_PROXY", "ftp_proxy",
    "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
)  # fmt: skip

#: Over Streamable HTTP the server gets a container in a network of its own: ``--internal`` (no
#: way out), and without an address of the host on the bridge, which ``--internal`` alone leaves
#: (measured: a container reached the host's sshd through the gateway). The server answers to
#: this name there, for the probe. The driver joins the server's namespace and speaks to it at
#: :data:`DRIVER_HOST`. No port is published.
SERVER_ALIAS = "server"
#: The host of the driver's URL: a loopback literal, which the server's namespace has.
DRIVER_HOST = "127.0.0.1"
NETWORK_OPTIONS: dict[str, str] = {"com.docker.network.bridge.inhibit_ipv4": "true"}
#: Every container and the network of one HTTP run carry this label, with the run's nonce.
RUN_LABEL = "mcp-kymograph.bench"
#: The label before the tool was renamed, and the key under which a companion of then names the
#: tool's version. Nothing is written with them; ``compare`` reads a companion made then.
EARLIER_RUN_LABEL = "mcp-polygraph.bench"
EARLIER_VERSION_KEY = "mcp_polygraph_version"

#: What the companion shows as the value of every variable of ``launch.env``.
ENV_PLACEHOLDER = "<env>"
#: What goes into the environment digest for a value the masker changed, whatever the value:
#: JSON null, which no value of ``launch.env`` (always a string) can be.
MASKED_VALUE = None
#: From this length on, a value of ``launch.env`` is hidden inside a longer argument as well.
MIN_HIDDEN_VALUE = 6
#: From this length on, a value of ``server.env`` is one of the secrets of a stage B run: what
#: the server tries in its network (a path, a name, a statement) is written down, and its own
#: value must not come back in the companion through that (``scrub``, last step).
MIN_SECRET_VALUE = 4
#: The image of the probe and of the driver, pinned. Not built, not pulled: it has to be here.
PYTHON_IMAGE = (
    "python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
)
#: The helper images of stage B, built from the runner's own contexts: tag -> (context, pinned
#: base). ``build-helpers`` builds them with the network; the runs use them without it.
HELPER_IMAGES: dict[str, tuple[Path, str]] = {
    f"{IMAGE_REPOSITORY}/helper-nft:1": (
        Path(__file__).resolve().parent / "images" / "nft",
        "debian:bookworm-slim@sha256:"
        "7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587",
    ),
}
#: How long the probe waits for the server to take a connection.
PROBE_WAIT_SECONDS = 30
#: What the probe must find, each as true when it held. The probe writes more than this; the
#: runner trusts none of it but these five, and each has to be exactly true.
PROBE_CHECKS: tuple[str, ...] = (
    "no_default_route",
    "no_gateway_connection",
    "external_name_unresolved",
    "ipv6_off",
    "server_accepts",
)

#: The probe, run in a container of the run's network with the driver's bounds. It makes no
#: claim it cannot show: a check that raises is false. Prints one JSON line.
PROBE_SCRIPT = """\
import json
import socket
import sys
import time


def default_routes():
    with open("/proc/net/route", encoding="ascii") as handle:
        rows = [line.split() for line in handle.read().splitlines()[1:]]
    zero = "00000000"
    return [row[0] for row in rows if len(row) >= 8 and row[1] == zero and row[7] == zero]


def gateway_address():
    own = socket.gethostbyname(socket.gethostname())
    return own.rsplit(".", 1)[0] + ".1"


def gateway_connects(address):
    try:
        socket.create_connection((address, 22), timeout=3).close()
    except OSError:
        return False
    return True


def name_resolves():
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError:
        return False
    return True


def ipv6_addresses():
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as handle:
            rows = [line.split() for line in handle.read().splitlines() if line.strip()]
    except FileNotFoundError:
        return []
    return [row[0] for row in rows if row[0] != "0" * 31 + "1"]


def server_accepts(host, port, seconds):
    deadline = time.monotonic() + seconds
    while True:
        try:
            socket.create_connection((host, port), timeout=2).close()
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    seconds = float(sys.argv[3]) if len(sys.argv) > 3 else 30
    result = {"server": host, "port": port}
    errors = {}

    def check(name, test):
        try:
            result[name] = test() is True
        except Exception as error:  # a check that cannot be made did not hold
            result[name] = False
            errors[name] = type(error).__name__

    check("no_default_route", lambda: not default_routes())
    def no_gateway():
        result["gateway"] = gateway_address()
        return not gateway_connects(result["gateway"])

    check("no_gateway_connection", no_gateway)
    check("external_name_unresolved", lambda: not name_resolves())
    check("ipv6_off", lambda: not ipv6_addresses())
    check("server_accepts", lambda: server_accepts(host, port, seconds))
    result["errors"] = errors
    print(json.dumps(result, sort_keys=True))


main()
"""

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_PINNED = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")

#: The instructions a server's Dockerfile may use. Anything else — ADD, ONBUILD, HEALTHCHECK,
#: SHELL, VOLUME, ARG — is refused rather than understood.
DOCKERFILE_INSTRUCTIONS = frozenset(
    {"FROM", "WORKDIR", "COPY", "RUN", "ENV", "USER", "LABEL", "EXPOSE", "ENTRYPOINT", "CMD"}
)
#: The build flags an instruction may carry, as whole words. Docker reads the flags at the start
#: of ``FROM``, ``COPY`` and ``RUN`` and drops quotes and backslashes inside a flag word before it
#: looks at its name, so a flag is accepted only in exactly this plain form, and any other
#: leading word that starts with a dash or a quote is refused. Words are split where docker
#: splits them, at spaces and tabs only: any other blank stays inside the word and fails it.
_ALLOWED_FLAGS: dict[str, re.Pattern[str] | None] = {
    "FROM": None,
    "COPY": re.compile(r"--(?:chown|chmod)=[A-Za-z0-9_.:-]+|--link"),
    "RUN": None,
}
#: What git says, untranslated, when a directory lies in no repository at all.
_NO_REPOSITORY = "fatal: not a git repository (or any of the parent directories)"
#: Everything ``str.splitlines`` would also break a line at; docker breaks at ``\n`` only.
_OTHER_LINE_BREAKS = frozenset("\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")
#: The variables that point git at another repository or stop its search early.
_GIT_REDIRECTS = frozenset(
    {"GIT_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
     "GIT_NAMESPACE", "GIT_PREFIX", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"}
)  # fmt: skip
_TAG_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")

_TOP_KEYS = frozenset({"version", "servers"})
_SERVER_KEYS = frozenset(
    {"name", "provenance", "archived", "role", "package", "source", "image", "launch", "stage_a",
     "stage_b"}
)  # fmt: skip
#: What an argument of ``stage_b.args`` says for the URL of the fixture's database with the
#: password of the run (the runner puts it in when it starts the server; see stage_b_net.py).
POSTGRES_URL_PLACEHOLDER = "{postgres_url}"
_STAGE_B_KEYS = frozenset({"status", "reason", "fixture", "script", "args", "postgres_image"})
#: A stage B server without a fixture: it is started as in stage A, with no volume and no
#: network. Only the negative control has no canary to deliver.
FIXTURE_NONE = "none"
#: What a script file is loaded with when the definitions are read, to see that it is one: the
#: placeholders it may use, each given a value. The run gives the real ones.
PROBE_VARIABLES = {
    "fixture_url": "http://fixture:8080",
    "fixture_dir": "/srv/fixtures",
    "repo_path": "/srv/fixtures/repo",
    "db_path": "/srv/fixtures/kanarie.db",
    "canary": "MCPB-CANARY-PROBE-xxxxxxxx",
}
_PACKAGE_KEYS = frozenset({"registry", "name", "version", "integrity"})
_SOURCE_KEYS = frozenset({"repository", "commit", "path"})
_IMAGE_KEYS = frozenset({"context", "base"})
_LAUNCH_KEYS = frozenset({"args", "env", "transport", "port", "path"})
TRANSPORT_STDIO = "stdio"
TRANSPORT_HTTP = "streamable-http"
TRANSPORTS = (TRANSPORT_STDIO, TRANSPORT_HTTP)
#: A path in a definition: begins with ``/``, printable ASCII only (the driver refuses any other
#: character in a URL), and nothing that would end it or change what the URL says (a blank,
#: ``?``, ``#``, ``@``).
_HTTP_PATH = re.compile(r"/[\x21\x22\x24-\x3e\x41-\x7e]*")
_STAGE_KEYS = frozenset({"status", "reason"})
#: Where a package comes from. ``github`` is a release asset of the source repository (a
#: built binary), its integrity the SHA-256 of the asset as the release's checksums list it.
REGISTRIES = ("npm", "pypi", "github")
ROLES = ("negative-control",)
STATUSES = ("active", "skipped")


class DefinitionError(ValueError):
    """A definitions file that cannot be used, with the place in it."""


class ScenarioRefused(ValueError):
    """The observation file is not one stage A may run with; the message says why."""


class RunnerError(RuntimeError):
    """Something the runner needed did not happen; the message says what."""


@dataclass(frozen=True)
class StageB:
    """What a definition says about stage B of one server.

    ``fixture`` is a kind of :mod:`fixtures` or ``none``, ``script`` the script file (absolute,
    as found next to the definitions) and ``script_name`` the path as the definition wrote it.
    ``args`` replace ``launch.args``. ``postgres_image`` is the attribute the network module
    reads for the kind ``postgres``.
    """

    status: str
    reason: str | None
    fixture: str | None = None
    script: Path | None = None
    script_name: str | None = None
    args: tuple[str, ...] = ()
    postgres_image: str | None = None


@dataclass(frozen=True)
class Server:
    name: str
    provenance: str
    archived: bool
    role: str | None
    package: dict[str, str]
    source: dict[str, str]
    image_context: Path
    image_base: str
    args: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    stage_a_status: str
    stage_a_reason: str | None
    transport: str = TRANSPORT_STDIO
    port: int | None = None
    path: str | None = None
    #: None when the definition has no ``stage_b`` section: stage B is then skipped.
    stage_b: StageB | None = None

    @property
    def endpoint(self) -> str | None:
        """The URL the driver container speaks to: loopback, in the server's own namespace."""
        if self.transport != TRANSPORT_HTTP:
            return None
        return f"http://{DRIVER_HOST}:{self.port}{self.path}"

    @property
    def image_tag(self) -> str:
        return f"{IMAGE_REPOSITORY}/{self.name}:{_TAG_UNSAFE.sub('-', self.package['version'])}"

    @property
    def revision(self) -> str:
        return f"{self.source['repository']}@{self.source['commit']}"


# -- definitions --------------------------------------------------------------------------


def load_definitions(path: Path) -> dict[str, Server]:
    """Read the definitions file whole, or refuse it whole, like a scenario or a manifest."""
    source = str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DefinitionError(f"{source}: cannot read: {exc.strerror or exc}") from None
    try:
        data = parse_yaml(text, source=source)
    except ScenarioError as exc:
        raise DefinitionError(str(exc)) from None
    _mapping(data, source, "the file must be a mapping")
    _only(data, _TOP_KEYS, source)
    if data.get("version") != 1 or type(data.get("version")) is not int:
        raise DefinitionError(f"{source}: version: this runner reads version 1")
    listed = data.get("servers")
    if not isinstance(listed, list) or not listed:
        raise DefinitionError(f"{source}: servers: expected a non-empty list")
    servers: dict[str, Server] = {}
    for index, item in enumerate(listed):
        server = _server(item, f"{source}: servers[{index}]", path.parent)
        if server.name in servers:
            raise DefinitionError(f"{source}: servers[{index}].name: {server.name!r} twice")
        servers[server.name] = server
    return servers


def _server(item: Any, where: str, directory: Path) -> Server:
    _mapping(item, where, "expected a mapping")
    _only(item, _SERVER_KEYS, where)
    name = _string(item, "name", where)
    if not _NAME.fullmatch(name):
        raise DefinitionError(f"{where}.name: {name!r}: lower-case letters, digits and '-'")
    provenance = _string(item, "provenance", where)
    if provenance != "real-world":
        raise DefinitionError(
            f"{where}.provenance: {provenance!r}; this runner is for real-world servers only — "
            "the project's own servers belong in a corpus manifest"
        )
    archived = item.get("archived")
    if not isinstance(archived, bool):
        raise DefinitionError(f"{where}.archived: expected true or false")
    role = item.get("role")
    if role is not None and role not in ROLES:
        raise DefinitionError(f"{where}.role: {role!r}; expected one of {', '.join(ROLES)}")

    package = _section(item, "package", _PACKAGE_KEYS, where)
    if package["registry"] not in REGISTRIES:
        raise DefinitionError(f"{where}.package.registry: expected one of {', '.join(REGISTRIES)}")
    _package_form(package, where)
    source = _section(item, "source", _SOURCE_KEYS, where)
    if not _COMMIT.fullmatch(source["commit"]):
        raise DefinitionError(f"{where}.source.commit: a full 40-character commit id")
    image = _section(item, "image", _IMAGE_KEYS, where)
    if not _PINNED.fullmatch(image["base"]):
        raise DefinitionError(f"{where}.image.base: pin the base image by digest (name@sha256:…)")

    launch = item.get("launch")
    _mapping(launch, f"{where}.launch", "expected a mapping")
    _only(launch, _LAUNCH_KEYS, f"{where}.launch")
    args = launch.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise DefinitionError(f"{where}.launch.args: expected a list of strings")
    env = launch.get("env") or {}
    _mapping(env, f"{where}.launch.env", "expected a mapping")
    for key, value in env.items():
        if not _ENV_NAME.fullmatch(key):
            raise DefinitionError(f"{where}.launch.env: {key!r} is not a variable name")
        if key in PROXY_VARIABLES:
            raise DefinitionError(
                f"{where}.launch.env: {key!r} is a proxy variable; the runner sets it empty"
            )
        if not isinstance(value, str) or "\n" in value:
            raise DefinitionError(f"{where}.launch.env.{key}: expected a one-line string")

    transport = launch.get("transport", TRANSPORT_STDIO)
    if transport not in TRANSPORTS:
        raise DefinitionError(
            f"{where}.launch.transport: {transport!r}; expected one of {', '.join(TRANSPORTS)}"
        )
    port = launch.get("port")
    path = launch.get("path")
    if transport == TRANSPORT_STDIO:
        for key in ("port", "path"):
            if key in launch:
                raise DefinitionError(f"{where}.launch.{key}: only with transport {TRANSPORT_HTTP}")
    else:
        if "port" not in launch or "path" not in launch:
            raise DefinitionError(f"{where}.launch: {TRANSPORT_HTTP} needs both port and path")
        if type(port) is not int or not 1 <= port <= 65535:
            raise DefinitionError(f"{where}.launch.port: expected a number from 1 to 65535")
        if not isinstance(path, str) or not _HTTP_PATH.fullmatch(path):
            raise DefinitionError(
                f"{where}.launch.path: expected a path that begins with '/' and holds no blank, "
                "control character, '?', '#' or '@'"
            )

    stage = item.get("stage_a")
    _mapping(stage, f"{where}.stage_a", "expected a mapping")
    _only(stage, _STAGE_KEYS, f"{where}.stage_a")
    status = stage.get("status")
    if status not in STATUSES:
        raise DefinitionError(f"{where}.stage_a.status: expected one of {', '.join(STATUSES)}")
    reason = stage.get("reason")
    if (status == "skipped") != isinstance(reason, str) or (reason is not None and not reason):
        raise DefinitionError(f"{where}.stage_a.reason: required when skipped, and only then")
    stage_b = _stage_b(item.get("stage_b"), f"{where}.stage_b", directory)
    # The negative control is the one server given no fixture, and the only one: a fixture
    # forgotten elsewhere would end every run as canary_not_delivered, without a word why.
    if (
        stage_b is not None
        and stage_b.status == "active"
        and (stage_b.fixture == FIXTURE_NONE) != (role == "negative-control")
    ):
        raise DefinitionError(
            f"{where}.stage_b.fixture: 'none' goes with role negative-control, and only then"
        )

    return Server(
        name=name,
        provenance=provenance,
        archived=archived,
        role=role,
        package=package,
        source=source,
        image_context=directory / image["context"],
        image_base=image["base"],
        args=tuple(args),
        env=tuple(sorted(env.items())),
        stage_a_status=status,
        stage_a_reason=reason,
        transport=transport,
        port=port if transport == TRANSPORT_HTTP else None,
        path=path if transport == TRANSPORT_HTTP else None,
        stage_b=stage_b,
    )


def _stage_b(section: Any, where: str, directory: Path) -> StageB | None:
    """The ``stage_b`` section of a server, or None if there is none.

    An active section names a fixture, a script that loads (with probe values for the
    placeholders) and the start arguments; ``postgres_image`` goes with the kind ``postgres``
    alone, by digest. A skipped one says why.
    """
    if section is None:
        return None
    _mapping(section, where, "expected a mapping")
    _only(section, _STAGE_B_KEYS, where)
    status = section.get("status")
    if status not in STATUSES:
        raise DefinitionError(f"{where}.status: expected one of {', '.join(STATUSES)}")
    reason = section.get("reason")
    if (status == "skipped") != isinstance(reason, str) or (reason is not None and not reason):
        raise DefinitionError(f"{where}.reason: required when skipped, and only then")
    if status == "skipped":
        return StageB(status=status, reason=reason)

    kinds = _fixtures().KINDS
    fixture = section.get("fixture")
    if fixture not in (*kinds, FIXTURE_NONE):
        raise DefinitionError(
            f"{where}.fixture: {fixture!r}; expected one of {', '.join((*kinds, FIXTURE_NONE))}"
        )
    name = _string(section, "script", where)
    script = (directory / name).resolve()
    if Path(name).is_absolute() or directory.resolve() not in script.parents:
        raise DefinitionError(
            f"{where}.script: {name!r} is not below the directory of the definitions; "
            "name a file under it"
        )
    try:
        script_files.load(script, PROBE_VARIABLES)
    except script_files.ScriptError as refusal:
        raise DefinitionError(f"{where}.script: {refusal}") from None
    args = section.get("args")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise DefinitionError(f"{where}.args: expected a list of strings")
    if fixture != "postgres" and any(POSTGRES_URL_PLACEHOLDER in a for a in args):
        raise DefinitionError(
            f"{where}.args: {POSTGRES_URL_PLACEHOLDER} stands for the database of the fixture "
            "postgres, and there is none"
        )
    image = section.get("postgres_image")
    if (fixture == "postgres") != (image is not None):
        raise DefinitionError(
            f"{where}.postgres_image: required for the fixture postgres, and only then"
        )
    if image is not None and (not isinstance(image, str) or not _PINNED.fullmatch(image)):
        raise DefinitionError(f"{where}.postgres_image: pin the image by digest (name@sha256:…)")
    return StageB(
        status=status,
        reason=None,
        fixture=fixture,
        script=script,
        script_name=name,
        args=tuple(args),
        postgres_image=image,
    )


def _sibling(stem: str) -> Any:
    """A module next to this one (``fixtures``, ``stage_b_net``), loaded once per copy of this
    module. This module is not on the path as a package, and the network module looks its
    runner up by name: while it loads, that name is this very module, not another copy."""
    if stem in _SIBLINGS:
        return _SIBLINGS[stem]
    spec = importlib.util.spec_from_file_location(
        f"bench_sibling_{stem}", Path(__file__).resolve().parent / f"{stem}.py"
    )
    assert spec is not None and spec.loader is not None  # noqa: S101 - a file next to this one
    module = importlib.util.module_from_spec(spec)
    me = sys.modules.get(__name__)
    before = sys.modules.get("bench_local_servers")
    if me is not None:
        sys.modules["bench_local_servers"] = me
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if before is None:
            sys.modules.pop("bench_local_servers", None)
        else:
            sys.modules["bench_local_servers"] = before
    _SIBLINGS[stem] = module
    return module


_SIBLINGS: dict[str, Any] = {}


def _fixtures() -> Any:
    return _sibling("fixtures")


def _mapping(value: Any, where: str, message: str) -> None:
    if not isinstance(value, dict):
        raise DefinitionError(f"{where}: {message}")


def _only(mapping: dict, allowed: frozenset[str], where: str) -> None:
    for key in mapping:
        if key not in allowed:
            expected = ", ".join(sorted(allowed))
            raise DefinitionError(f"{where}: unknown key {key!r}; expected one of {expected}")


#: What a package's ``version`` and ``integrity`` look like, per registry. An exact version, not
#: a range or a tag that moves; an integrity of the registry's own kind and length.
_SEMVER_IDENTIFIER = r"(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(-{_SEMVER_IDENTIFIER}(\.{_SEMVER_IDENTIFIER})*)?"
    r"(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"
)
_PEP440 = re.compile(
    r"([0-9]+!)?[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?"
    r"(\+[a-z0-9]+([._-][a-z0-9]+)*)?"
)
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
#: 64 bytes of SHA-512 in Base64: 86 characters and two of padding.
_NPM_INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
_PYPI_INTEGRITY = re.compile(r"sha256:[0-9a-f]{64}")
_GITHUB_INTEGRITY = re.compile(r"sha256:[0-9A-Fa-f]{64}")
_PACKAGE_FORMS = {
    "npm": (_SEMVER, "an exact semantic version (MAJOR.MINOR.PATCH)",
            _NPM_INTEGRITY, "sha512- and 88 characters of Base64"),
    "pypi": (_PEP440, "an exact PEP 440 version, no operator and no '*'",
             _PYPI_INTEGRITY, "sha256: and 64 lower-case hex digits"),
    "github": (_TAG, "a release tag",
               _GITHUB_INTEGRITY, "sha256: and 64 hex digits"),
}  # fmt: skip


def _package_form(package: dict[str, str], where: str) -> None:
    """A package whose version or integrity is not pinned in the registry's form is refused."""
    version_form, version_text, integrity_form, integrity_text = _PACKAGE_FORMS[package["registry"]]
    if not version_form.fullmatch(package["version"]):
        raise DefinitionError(
            f"{where}.package.version: {package['version']!r}: expected {version_text}"
        )
    if not integrity_form.fullmatch(package["integrity"]):
        raise DefinitionError(
            f"{where}.package.integrity: {package['integrity']!r}: expected {integrity_text}"
        )


def _string(mapping: dict, key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise DefinitionError(f"{where}.{key}: expected a non-empty string")
    return value


def _section(item: dict, key: str, keys: frozenset[str], where: str) -> dict[str, str]:
    section = item.get(key)
    _mapping(section, f"{where}.{key}", "expected a mapping")
    _only(section, keys, f"{where}.{key}")
    return {name: _string(section, name, f"{where}.{key}") for name in sorted(keys)}


# -- what runs ----------------------------------------------------------------------------


def docker_command(server: Server, image_id: str, container: str, docker: str) -> list[str]:
    """The exact command the server is started with: what runs, and what the companion names.

    The environment goes in only as ``-e NAME=value``. A bare ``-e NAME`` would hand the
    container whatever the caller's environment holds under that name — a real token, say —
    and the command line would not show it. The proxy variables come first, empty: otherwise
    the docker CLI fills them from its own configuration, out of sight of the command line.
    """
    env: list[str] = []
    for name in PROXY_VARIABLES:
        env += ["-e", f"{name}="]
    for name, value in server.env:
        env += ["-e", f"{name}={value}"]
    return [
        docker, "run", "-i", "--rm", "--name", container,
        *HARDENING, *env, image_id, *server.args,
    ]  # fmt: skip


def out_dir_refusal(
    out_dir: Path, repo_root: Path = REPO_ROOT, subject: str = "recordings"
) -> str | None:
    """Why recordings may not go to ``out_dir``, or None. Checked before anything starts.

    Not into this repository's public tree, and nowhere any repository would track: the one
    the directory lies in decides, a nested one or another one entirely included. The key file
    goes through the same check, with ``subject`` ``"keys"``.
    """
    target = out_dir.resolve()
    public = repo_root / "benchmarks"
    if target == public or public in target.parents:
        return f"{out_dir} is inside the public tree ({public}); {subject} stay private"
    try:
        top = _work_tree(target)
    except RunnerError as unclear:
        return f"{out_dir}: cannot tell whether git would track it ({unclear}); refused"
    if top is None:
        return None
    if target == top:
        return f"{out_dir} is the root of a repository; {subject} stay in a directory git ignores"
    done = subprocess.run(  # noqa: S603 - fixed program, a path as its one argument
        ["git", "-C", str(top), "check-ignore", "-q", "--no-index", str(target.relative_to(top))],  # noqa: S607
        capture_output=True,
        check=False,
        env=_git_environment(),
    )
    if done.returncode == 0:
        return None
    return f"{out_dir} is in a repository ({top}) and git would track it; {subject} stay private"


def _git_environment() -> dict[str, str]:
    """The caller's environment for git: nothing that points it elsewhere, plain English.

    A ``GIT_DIR`` or ``GIT_CEILING_DIRECTORIES`` from the caller would answer for another
    repository or stop the search early; the message that says "no repository here" is told
    apart from every other failure by its text, so the text has to be the untranslated one.
    The search crosses mount points: a ``git add`` in the repository would too.
    """
    env = {key: value for key, value in os.environ.items() if key not in _GIT_REDIRECTS}
    env.update(LC_ALL="C", LANGUAGE="", GIT_DISCOVERY_ACROSS_FILESYSTEM="1")
    return env


def _work_tree(target: Path) -> Path | None:
    """The top of the git work tree ``target`` lies in, or None if it lies in none.

    ``target`` need not exist. Only git's own "not a git repository (or any of the parent
    directories)" means none; any other failure (an owner git distrusts, a ``.git`` file that
    points nowhere) raises, and the caller refuses rather than guesses.
    """
    existing = target
    while not existing.is_dir():
        existing = existing.parent
    try:
        done = subprocess.run(  # noqa: S603 - fixed program, a path as its one argument
            ["git", "-C", str(existing), "rev-parse", "--show-toplevel"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            env=_git_environment(),
        )
    except OSError as exc:
        raise RunnerError(f"git cannot be run: {exc.strerror or exc}") from None
    if done.returncode == 0 and done.stdout.strip():
        top = Path(done.stdout.strip()).resolve()
        if target != top and top not in target.parents:
            raise RunnerError(f"git names {top}, which does not contain {target}")
        return top
    if done.stderr.startswith(_NO_REPOSITORY):
        return None
    raise RunnerError(done.stderr.strip() or f"git rev-parse exited {done.returncode}")


def image_id(docker: str, tag: str) -> str:
    done = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
        [docker, "image", "inspect", "--format", "{{.Id}}", tag],
        capture_output=True,
        text=True,
        check=False,
    )
    found = done.stdout.strip()
    if done.returncode != 0 or not found.startswith("sha256:"):
        raise RunnerError(f"no image {tag}; build it first (bench.py build)")
    return found


def context_digest(directory: Path) -> tuple[str, dict[str, str]]:
    """The digest of an image context, and the SHA-256 of each file in it.

    Every regular file below ``directory``, sorted by relative POSIX path as a string. Anything
    else that is not a directory (a symlink, a device, a socket) is refused: it would leave the
    digest saying less than what the build reads. So is a name a line cannot carry plainly — a
    line break, a backslash (``sha256sum`` escapes both), anything unprintable or not UTF-8 —
    because two contexts could then print the same text. The digest is the SHA-256 of the lines
    ``<sha256>  <path>`` in that order, which is the text ``sha256sum`` prints for these files.
    File modes and empty directories are not part of it.
    """
    files: dict[str, str] = {}
    for path in sorted(directory.rglob("*"), key=lambda p: p.relative_to(directory).as_posix()):
        relative = path.relative_to(directory).as_posix()
        if not relative.isprintable() or "\\" in relative:
            raise RunnerError(f"{path!r}: a name a sha256sum line cannot carry plainly; not hashed")
        if path.is_symlink():
            raise RunnerError(f"{path}: a symlink in the image context; not hashed")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RunnerError(f"{path}: not a regular file; not hashed")
        files[relative] = sha256(path)
    text = "".join(f"{digest}  {relative}\n" for relative, digest in files.items())
    return hashlib.sha256(text.encode("utf-8")).hexdigest(), files


def _docker_text(docker: str, *args: str) -> str | None:
    """The output of one docker call, or None if it failed or the program is missing."""
    try:
        done = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
            [docker, *args], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def image_inspect(docker: str, image: str) -> dict[str, Any]:
    """What docker says about an image, by id: its whole ``inspect`` object."""
    text = _docker_text(docker, "image", "inspect", "--format", "{{json .}}", image)
    try:
        found = json.loads(text) if text else None
    except ValueError:
        found = None
    if not isinstance(found, dict):
        raise RunnerError(f"cannot inspect the image {image}")
    return found


def key_refusal(path: Path) -> str | None:
    """Why ``path`` may not be the suite's key, or None. Checked before anything starts.

    It has to exist as a regular file of exactly 32 bytes, readable by its owner alone, and
    lie where git would not track it: the key is never committed. A symlink is not accepted:
    where it points is not what was checked (``lstat``).
    """
    try:
        found = path.lstat()
    except OSError as exc:
        return f"{path}: cannot be read: {exc.strerror or exc}"
    if stat.S_ISLNK(found.st_mode):
        return f"{path}: a symlink; name the key file itself"
    if not stat.S_ISREG(found.st_mode):
        return f"{path}: not a regular file"
    if found.st_size != KEY_BYTES:
        return f"{path}: {found.st_size} bytes, not {KEY_BYTES}"
    if found.st_mode & 0o077:
        return f"{path}: readable by group or others (mode {found.st_mode & 0o777:04o}); use 0600"
    return out_dir_refusal(path, subject="keys")


def read_key(path: Path) -> bytes:
    """The key in ``path``, after :func:`key_refusal` has accepted it."""
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"{path}: cannot be read: {exc.strerror or exc}") from None
    if len(key) != KEY_BYTES:
        raise RunnerError(f"{path}: {len(key)} bytes, not {KEY_BYTES}")
    return key


def key_id(key: bytes) -> str:
    """Names a key without giving it away: 16 hex characters of an HMAC of a fixed text."""
    return hmac.new(key, KEY_ID_TEXT, hashlib.sha256).hexdigest()[:16]


def create_key(path: Path) -> None:
    """Write a new random key to ``path``, mode 0600. An existing file is never overwritten."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise RunnerError(f"{path}: not created: {exc.strerror or exc}") from None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(secrets.token_bytes(KEY_BYTES))


def environment_digest(env: Sequence[tuple[str, str]], key: bytes) -> str:
    """The HMAC-SHA256 under ``key`` of the environment the runner sets, values masked.

    The key is the suite's and never leaves the machine: the plain SHA-256 of an environment
    of a few possible values could be reversed by trying them.

    The same for stdio and HTTP: the proxy variables, empty, and the pairs of ``server.env``.
    A value the masker changes (replaces, empties, pseudonymises) goes in as the fixed
    :data:`MASKED_VALUE` — null, never a string, so no ordinary value can stand for it — not as
    the masker's output: the digest of a weak secret would be an oracle for it, and a pseudonym
    with a salt would still depend on the value. A change of such a value therefore does not
    show; a change of any other value does.
    """
    pairs = []
    for name, value in sorted(env):
        masked, _ = Masker().mask_json({name: value})
        pairs.append([name, value if masked == {name: value} else MASKED_VALUE])
    text = json.dumps(pairs, ensure_ascii=False, separators=(",", ":"))
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def _set_environment(server: Server) -> list[tuple[str, str]]:
    """The container's environment: the proxy variables, empty, then ``server.env``."""
    return [(name, "") for name in PROXY_VARIABLES] + list(server.env)


def definition_digest(server: Server) -> str:
    """The digest of what the companion copies from the definition rather than reads off the image.

    Name, provenance, archive state, role, package, source and base image, and for a server
    that speaks Streamable HTTP its transport, port and path. Carried on the image
    as a label, so that a definition edited after the build is not written beside a run of the
    image as if it described it.
    """
    claims = {
        "name": server.name,
        "provenance": server.provenance,
        "archived": server.archived,
        "role": server.role,
        "package": server.package,
        "source": server.source,
        "image_base": server.image_base,
    }
    if server.transport == TRANSPORT_HTTP:
        # Only where they say something: a stdio definition keeps the digest it always had.
        claims.update(transport=server.transport, port=server.port, path=server.path)
    text = json.dumps(claims, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dockerfile_refusal(text: str, base: str) -> str | None:
    """Why a Dockerfile does not build exactly from the pinned base, or None.

    The file is read the simple way only, one instruction per line, and whatever would make
    docker read it otherwise is refused, not interpreted: a byte order mark, a line break other
    than ``\\n``, a line continuation, a heredoc, a parser directive (``syntax`` loads a build
    frontend from a registry, ``escape`` changes the continuation). Then one ``FROM``, exactly
    the pinned base, only :data:`DOCKERFILE_INSTRUCTIONS`, and no build flag but the plain ones
    in ``_ALLOWED_FLAGS`` — so no ``--from`` or ``--mount``, which bring in another image or
    stage, however they are spelled. What the ``RUN`` steps fetch is not checked here.
    """
    if text.startswith("\ufeff"):
        return "a byte order mark; docker drops it and reads the first line differently"
    froms: list[tuple[int, str]] = []
    for number, line in enumerate(text.split("\n"), 1):
        if _OTHER_LINE_BREAKS & set(line):
            return f"line {number}: a line break other than \\n; docker would read it differently"
        stripped = line.strip()
        if re.match(r"(?:#|//)\s*(?:syntax|escape|check)\s*=", stripped, re.IGNORECASE):
            return f"line {number}: a parser directive"
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            return f"line {number}: a line continuation; one instruction per line"
        if "<<" in stripped:
            return f"line {number}: a heredoc; one instruction per line"
        words = stripped.split(None, 1)
        instruction = words[0].upper()
        if instruction not in DOCKERFILE_INSTRUCTIONS:
            return f"line {number}: {words[0]} is not an instruction this runner accepts"
        if instruction in _ALLOWED_FLAGS:
            allowed = _ALLOWED_FLAGS[instruction]
            for word in re.split(r"[ \t]+", stripped)[1:]:
                if not word.startswith(("-", '"', "'")):
                    break
                if allowed is None or not allowed.fullmatch(word):
                    return f"line {number}: the flag {word!r} is not one this runner accepts"
        if instruction == "FROM":
            froms.append((number, words[1].strip() if len(words) > 1 else ""))
    if not froms:
        return "no FROM line"
    if len(froms) > 1:
        return f"line {froms[1][0]}: a second FROM; the image is built in one stage"
    number, first = froms[0]
    if first != base:
        return (
            f"line {number}: FROM {first} is not the pinned base {base}; "
            "the definitions and the Dockerfile must agree"
        )
    return None


def _git(*args: str) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603 - fixed program, arguments built here
            ["git", "-C", str(REPO_ROOT), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            env=_git_environment(),
        )
    except OSError:
        return None
    return done.stdout if done.returncode == 0 else None


def tool_metadata() -> dict[str, Any]:
    """Which Kymograph and which runner made a run. A value that cannot be had is None."""
    commit = _git("rev-parse", "HEAD")
    changes = _git("status", "--porcelain", "--untracked-files=no")
    return {
        "mcp_kymograph_version": mcp_kymograph.__version__,
        "repository_commit": None if commit is None else commit.strip(),
        "repository_tracked_changes": None if changes is None else bool(changes.strip()),
        "runner_sha256": sha256(Path(__file__).resolve()),
    }


def host_metadata(docker: str) -> dict[str, Any]:
    """Where a run ran, and what the daemon adds to every container without the command saying so.

    The container shares the daemon's kernel, which need not be the client's; the daemon's
    default runtime, security options (seccomp, AppArmor) and log driver apply to it as well.
    """
    text = _docker_text(docker, "info", "--format", "{{json .}}")
    try:
        info = json.loads(text) if text else {}
    except ValueError:
        info = {}
    info = info if isinstance(info, dict) else {}
    return {
        "docker_server_version": _docker_text(docker, "version", "--format", "{{.Server.Version}}"),
        "docker_context": _docker_text(docker, "context", "show"),
        "daemon_kernel": info.get("KernelVersion"),
        "default_runtime": info.get("DefaultRuntime"),
        "security_options": info.get("SecurityOptions"),
        "logging_driver": info.get("LoggingDriver"),
        "client_kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def remove_container(docker: str, name: str) -> bool:
    """Remove the run's container by its name if it is still there. True if it was.

    ``--rm`` removes it when the server ends on its own; a run that was stopped can kill the
    docker CLI and leave the container behind. Only this run's own name is ever removed.
    """
    listed = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
        [docker, "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.ID}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if not listed.stdout.strip():
        return False
    subprocess.run([docker, "rm", "-f", name], capture_output=True, check=False)  # noqa: S603
    return True


def stage_a_scenario() -> Scenario:
    """The observation file, loaded, or refused: stage A changes no traffic."""
    try:
        scenario = load_scenario(SCENARIO)
    except ScenarioError as error:
        raise ScenarioRefused(str(error)) from None
    if scenario.rules:
        raise ScenarioRefused(
            f"stage A changes no traffic: {SCENARIO} has {len(scenario.rules)} rule(s)"
        )
    if not scenario.statements:
        raise ScenarioRefused(f"{SCENARIO} has no statement; there would be nothing to observe")
    return scenario


def run_started(events: Path) -> dict[str, Any]:
    """The ``run_started`` event of a recording: its first line."""
    with events.open("rb") as handle:
        first = handle.readline()
    try:
        event = json.loads(first)
    except ValueError:
        raise RunnerError(f"{events}: the first line is not JSON") from None
    if not isinstance(event, dict) or event.get("type") != "run_started":
        raise RunnerError(f"{events}: does not begin with run_started")
    return event


def recorded_argv(events: Path) -> list[str]:
    """``run_started.argv`` of a recording."""
    event = run_started(events)
    argv = event.get("argv")
    if not isinstance(argv, list):
        raise RunnerError(f"{events}: run_started has no argv")
    return argv


def scenario_mismatch(events: Path, scenario: Scenario) -> str | None:
    """How the recording's own ``run_started`` differs from the observation file, or None.

    The recording has to show the digest and the name of this file, and that no rule was
    loaded; the runner's word that it passed the file is not enough.
    """
    started = run_started(events)
    authorization = started.get("authorization")
    if not isinstance(authorization, dict):
        return "run_started has no authorization"
    if authorization.get("scenario_digest") != scenario.digest:
        return "run_started.authorization.scenario_digest is not the digest of the file"
    if started.get("scenario_name") != scenario.name:
        return "run_started.scenario_name is not the name of the file"
    if authorization.get("rules_loaded") is not False:
        return "run_started.authorization.rules_loaded is not false"
    return None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _run_dirs(out_dir: Path) -> set[str]:
    return {entry.name for entry in out_dir.iterdir() if entry.is_dir()}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    partial = path.with_name(f".{path.name}.partial")
    partial.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(partial, path)


def write_result(run_dir: Path, hidden: Sequence[str] = ()) -> None:
    """Write ``result.json`` beside the companion of ``run_dir`` (``results.build_result``).

    ``hidden`` are the run's secrets, masked in the result as in the companion. A run passes
    them; ``bench.py result``, which writes the file again later, has none (they are in no file),
    and then the check of the exported tree is all that keeps them out of the export."""
    results = _sibling("results")
    _write_json(run_dir / results.RESULT_FILE, results.build_result(run_dir, hidden))


# -- commands -----------------------------------------------------------------------------


def build(server: Server, docker: str) -> int:
    """Build the server's image. Needs the network (npm ci); the runs never do."""
    dockerfile = server.image_context / "Dockerfile"
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RunnerError(f"{dockerfile}: cannot read: {exc}") from None
    refusal = dockerfile_refusal(text, server.image_base)
    if refusal is not None:
        raise RunnerError(f"{dockerfile}: {refusal}")
    digest, _ = context_digest(server.image_context)
    done = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
        [
            docker, "build", "--label", f"mcp-kymograph.bench.server={server.name}",
            "--label", f"{CONTEXT_LABEL}={digest}",
            "--label", f"{DEFINITION_LABEL}={definition_digest(server)}",
            "-t", server.image_tag, str(server.image_context),
        ],
        check=False,
    )  # fmt: skip
    if done.returncode != 0:
        raise RunnerError(f"docker build failed for {server.name} (exit {done.returncode})")
    print(f"{server.name}: {server.image_tag} {image_id(docker, server.image_tag)}")
    return EXIT_OK


def build_helpers(docker: str) -> int:
    """Build the helper images of stage B. Needs the network; the runs never do."""
    for tag, (context, base) in HELPER_IMAGES.items():
        dockerfile = context / "Dockerfile"
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RunnerError(f"{dockerfile}: cannot read: {exc}") from None
        refusal = dockerfile_refusal(text, base)
        if refusal is not None:
            raise RunnerError(f"{dockerfile}: {refusal}")
        digest, _ = context_digest(context)
        done = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
            [docker, "build", "--label", f"{CONTEXT_LABEL}={digest}", "-t", tag, str(context)],
            check=False,
        )
        if done.returncode != 0:
            raise RunnerError(f"docker build failed for {tag} (exit {done.returncode})")
        print(f"{tag} {image_id(docker, tag)}")
    return EXIT_OK


def _checked_image(
    server: Server, docker: str
) -> tuple[str, dict[str, Any], str, dict[str, str], str]:
    """The server's image as the definitions describe it, or a ``RunnerError``.

    Returns the image id, what docker says about it, the digest of the context and of each file
    in it, and the digest of the definition.
    """
    image = image_id(docker, server.image_tag)
    inspected = image_inspect(docker, image)
    config = inspected.get("Config") if isinstance(inspected.get("Config"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    digest, files = context_digest(server.image_context)
    if labels.get(CONTEXT_LABEL) != digest:
        raise RunnerError(
            f"{server.image_tag} was not built from the context as it is now: the image "
            f"says {labels.get(CONTEXT_LABEL)}, the context is {digest}; build it again"
        )
    definition = definition_digest(server)
    if labels.get(DEFINITION_LABEL) != definition:
        raise RunnerError(
            f"{server.image_tag} was not built from the definition as it is now: the image "
            f"says {labels.get(DEFINITION_LABEL)}, the definition is {definition}; build it again"
        )
    if config.get("Volumes"):
        raise RunnerError(
            f"{server.image_tag} declares volumes ({', '.join(sorted(config['Volumes']))}); "
            "docker would mount them writable despite --read-only"
        )
    return image, inspected, digest, files, definition


def run(server: Server, out_dir: Path, docker: str, scenario: Scenario, key: bytes) -> int:
    """Drive one server once in its container and write the companion beside the recording."""
    if server.transport == TRANSPORT_HTTP:
        return run_http(server, out_dir, docker, scenario, key)
    image, inspected, digest, files, definition = _checked_image(server, docker)
    container = f"mcpb-{server.name}-{secrets.token_hex(4)}"
    command = docker_command(server, image, container, docker)
    drive = [
        sys.executable, "-m", "mcp_kymograph.cli", "drive", "--out-dir", str(out_dir), "-q",
        "--server-revision", server.revision, "--scenario", scenario.source, "--", *command,
    ]  # fmt: skip

    out_dir.mkdir(parents=True, exist_ok=True)
    before = _run_dirs(out_dir)
    started = _now()
    # Its own session, so that a stop reaches Kymograph through us, as one signal to its own
    # group — and nothing is ever looked up by pattern.
    process = subprocess.Popen(drive, start_new_session=True)  # noqa: S603
    try:
        exit_code = process.wait()
    except KeyboardInterrupt:
        os.killpg(process.pid, signal.SIGINT)
        process.wait()
        raise
    finally:
        present_after = remove_container(docker, container)
    finished = _now()

    new = _run_dirs(out_dir) - before
    if len(new) != 1:
        raise RunnerError(
            f"expected one new run directory in {out_dir}, found {len(new)} "
            f"(Kymograph exit {exit_code})"
        )
    run_dir = out_dir / new.pop()
    events = run_dir / "events.jsonl"
    expected, _ = Masker().mask_argv(command)
    if recorded_argv(events) != expected:
        raise RunnerError(
            f"{events}: run_started.argv is not the command the runner gave; no companion "
            "written, so this recording cannot be said to have run in a container"
        )
    mismatch = scenario_mismatch(events, scenario)
    if mismatch is not None:
        raise RunnerError(
            f"{events}: {mismatch}; no companion written, so this recording cannot be said to "
            "have run with the observation file"
        )
    recorded_isolation = run_started(events).get("isolation")
    if recorded_isolation != "host":
        raise RunnerError(
            f"{events}: run_started.isolation is {recorded_isolation!r}, not 'host'; no companion "
            "written, because it would describe a different kind of run"
        )

    # As given and as resolved: the command line carries the first, a symlink may make it differ.
    roles = [
        (str(out_dir), "<out>"),
        (str(out_dir.resolve()), "<out>"),
        (scenario.source, "<scenario>"),
        (str(Path(scenario.source).resolve()), "<scenario>"),
        (str(REPO_ROOT), "<repo>"),
    ]
    shown_docker = shown_command(command, roles, server.env)
    shown_drive = shown_command(drive, roles, server.env)
    # The docker program follows ``--``; as argv[0] of the command it shows its basename only,
    # and so it does here.
    shown_drive[drive.index("--") + 1] = os.path.basename(docker)
    _write_json(
        run_dir / COMPANION,
        {
            "companion_version": COMPANION_VERSION,
            "stage": "A",
            "server": server.name,
            "provenance": server.provenance,
            "archived": server.archived,
            "role": server.role,
            "package": server.package,
            "source": server.source,
            "isolation": ISOLATION,
            "recorded_isolation": recorded_isolation,
            "docker_command": shown_docker,
            "image": {
                "id": image,
                "tag": server.image_tag,
                "base": server.image_base,
                "created": inspected.get("Created"),
            },
            "inputs": {
                "context_sha256": digest,
                "files": files,
                "definition_sha256": definition,
                "environment_hmac_sha256": environment_digest(_set_environment(server), key),
                "environment_key_id": key_id(key),
            },
            "tool": tool_metadata(),
            "host": host_metadata(docker),
            "container_name": container,
            "container_present_after_run": present_after,
            "scenario": {
                "name": scenario.name,
                "file": Path(scenario.source).resolve().relative_to(REPO_ROOT).as_posix(),
                "sha256": scenario.digest,
            },
            "mcp_kymograph_command": shown_drive,
            "mcp_kymograph_exit": exit_code,
            "started_utc": started,
            "finished_utc": finished,
            "recording": events.name,
            "recording_sha256": sha256(events),
        },
    )
    write_result(run_dir, [value for _, value in server.env if len(value) >= MIN_SECRET_VALUE])
    print(f"{server.name}: {run_dir} (Kymograph exit {exit_code})")
    return EXIT_OK


# -- Streamable HTTP ----------------------------------------------------------------------


def _hardening(user: str | None = None, dns: bool = True) -> list[str]:
    """:data:`HARDENING` without ``--network none``, for a container that is in a network.

    Everything else stays as it is, ``--dns 127.0.0.1`` included. ``user`` replaces the user
    (the driver writes into the output directory, as the runner's own user). ``dns=False`` leaves
    out ``--dns`` and ``--dns-search``, which docker refuses with ``--network container:``.
    """
    if HARDENING[:2] != ("--network", "none"):
        raise RunnerError("HARDENING no longer begins with --network none; not adapted blindly")
    parts = list(HARDENING[2:])
    if user is not None:
        parts[parts.index("--user") + 1] = user
    if not dns:
        for option in ("--dns", "--dns-search"):
            at = parts.index(option)
            del parts[at : at + 2]
    return parts


def _proxies_empty() -> list[str]:
    return [part for name in PROXY_VARIABLES for part in ("-e", f"{name}=")]


def server_http_command(
    server: Server, image: str, container: str, network: str, nonce: str, docker: str
) -> list[str]:
    """The server's container in the run's network, detached, with no port published."""
    env: list[str] = []
    for name, value in server.env:
        env += ["-e", f"{name}={value}"]
    return [
        docker, "run", "-d", "--rm", "--name", container, "--label", f"{RUN_LABEL}={nonce}",
        "--network", network, "--network-alias", SERVER_ALIAS,
        *_hardening(), *_proxies_empty(), *env, image, *server.args,
    ]  # fmt: skip


def probe_command(
    server: Server, container: str, network: str, nonce: str, script: Path, docker: str
) -> list[str]:
    return [
        docker, "run", "--rm", "--name", container, "--label", f"{RUN_LABEL}={nonce}",
        "--network", network, *_hardening(), *_proxies_empty(),
        "-v", f"{script}:/probe.py:ro",
        PYTHON_IMAGE, "python", "-B", "/probe.py", SERVER_ALIAS, str(server.port),
    ]  # fmt: skip


def yaml_package() -> Path:
    """The directory of the ``yaml`` package this runner reads its definitions with. The
    observation file is YAML and the pinned image has no PyYAML: the driver's container gets
    this directory read-only, beside ``src/``."""
    import yaml  # noqa: PLC0415 - installed wherever the runner can read a definition

    return Path(yaml.__file__).resolve().parent


def drive_http_command(server: Server, scenario: Scenario) -> list[str]:
    """What the driver container runs: ``drive`` against the server at 127.0.0.1."""
    # No --engagement-confirmed: the URL's host is a loopback literal, local by the gate's own
    # rule, so the runner confirms nothing on anyone's behalf.
    return [
        "python", "-B", "-m", "mcp_kymograph.cli", "drive", "--http", str(server.endpoint),
        "--out-dir", "/out", "-q", "--server-revision", server.revision,
        "--scenario", f"/scenario/{Path(scenario.source).name}",
    ]  # fmt: skip


def driver_command(
    server: Server, scenario: Scenario, out_dir: Path, container: str, holder: str, nonce: str,
    docker: str,
) -> list[str]:  # fmt: skip
    """The driver's container: the runner's code and the scenario read-only, ``/out`` writable.

    It joins the network namespace of ``holder``, the server's container: no interface and no
    route of its own, and the server at 127.0.0.1. Docker refuses ``--dns`` there; the
    namespace's resolver file is the server's.
    """
    return [
        docker, "run", "--rm", "--name", container, "--label", f"{RUN_LABEL}={nonce}",
        "--network", f"container:{holder}",
        *_hardening(user=f"{os.getuid()}:{os.getgid()}", dns=False),
        *_proxies_empty(),
        "-v", f"{REPO_ROOT / 'src'}:/opt/mcp-kymograph/src:ro",
        "-v", f"{yaml_package()}:/opt/mcp-kymograph/deps/yaml:ro",
        "-v", f"{Path(scenario.source).resolve()}:/scenario/{Path(scenario.source).name}:ro",
        "-v", f"{out_dir}:/out",
        "-e", "PYTHONPATH=/opt/mcp-kymograph/src:/opt/mcp-kymograph/deps",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        PYTHON_IMAGE, *drive_http_command(server, scenario),
    ]  # fmt: skip


def shown_command(
    command: Sequence[str],
    roles: Sequence[tuple[str, str]],
    env: Sequence[tuple[str, str]] = (),
) -> list[str]:
    """A command for the companion: host paths replaced by their role, then masked.

    The longest path first, so that a path inside another is not half replaced. Every
    ``-e NAME=value`` of ``env`` shows :data:`ENV_PLACEHOLDER` as the value, whatever the name
    sounds like: the runner knows each value it sets, and a guess at which are secret is none.
    """
    # Only absolute paths stand for a role: a relative one ("." or "runs") is a piece of text
    # that other arguments hold as well, and it says nothing about the machine.
    ordered = sorted(
        (role for role in roles if Path(role[0]).is_absolute()),
        key=lambda role: len(role[0]),
        reverse=True,
    )
    set_by_us = {f"{name}={value}" for name, value in env}
    # A value of the environment wherever else it stands — an argument that takes the same
    # token — is hidden too: as a whole argument always, inside a longer one from
    # MIN_HIDDEN_VALUE characters on (a shorter value would hide parts of unrelated text).
    values = sorted({value for _, value in env if value}, key=len, reverse=True)
    replaced = []
    hidden: list[tuple[int, str]] = []
    for index, part in enumerate(command):
        if part in set_by_us and index > 0 and command[index - 1] == "-e":
            hidden.append((index, f"{part.partition('=')[0]}={ENV_PLACEHOLDER}"))
        for value in values:
            if part == value:
                part = ENV_PLACEHOLDER
            elif len(value) >= MIN_HIDDEN_VALUE:
                part = part.replace(value, ENV_PLACEHOLDER)
        for path, role in ordered:
            part = part.replace(path, role)
        replaced.append(part)
    masked, _ = Masker().mask_argv(replaced)
    if len(masked) != len(replaced):
        raise RunnerError("the masker changed the number of arguments; no command can be shown")
    for index, text in hidden:
        masked[index] = text
    return masked


def probe_failures(result: Any) -> list[str]:
    """Which checks of the probe did not hold. An answer that is no object fails all of them."""
    if not isinstance(result, dict):
        return list(PROBE_CHECKS)
    return [name for name in PROBE_CHECKS if result.get(name) is not True]


def run_probe(command: list[str]) -> dict[str, Any]:
    """Run the probe and read its one JSON line; any failure to do so is a ``RunnerError``."""
    try:
        done = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
            command, capture_output=True, text=True, check=False, timeout=PROBE_WAIT_SECONDS + 90
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"the probe could not be run: {exc}") from None
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    try:
        result = json.loads(lines[-1]) if lines else None
    except ValueError:
        result = None
    if not isinstance(result, dict):
        raise RunnerError(
            f"the probe gave no result (exit {done.returncode}): "
            f"{(done.stderr or done.stdout).strip()[-400:]}"
        )
    failed = probe_failures(result)
    if failed:
        raise RunnerError(
            f"the network is not isolated as required; failed: {', '.join(failed)}; "
            f"probe: {json.dumps(result, sort_keys=True)}"
        )
    return result


def http_mismatch(events: Path, server: Server) -> str | None:
    """How the recording's ``run_started`` differs from an HTTP run of this server, or None."""
    started = run_started(events)
    if started.get("transport") != TRANSPORT_HTTP:
        return f"run_started.transport is {started.get('transport')!r}, not {TRANSPORT_HTTP!r}"
    endpoint = started.get("endpoint")
    if not isinstance(endpoint, dict):
        return "run_started has no endpoint"
    wanted = {"scheme": "http", "host": DRIVER_HOST, "port": server.port, "path": server.path}
    for key, value in wanted.items():
        if endpoint.get(key) != value:
            return f"run_started.endpoint.{key} is {endpoint.get(key)!r}, not {value!r}"
    if endpoint.get("query"):
        return "run_started.endpoint has a query"
    if started.get("argv") != []:
        return "run_started.argv is not empty, though no command was started"
    return None


def remove_run(docker: str, containers: Sequence[str], network: str) -> tuple[bool, bool]:
    """Remove the containers of one HTTP run by name, then its network.

    Returns whether the server's container (the first) was still there, and whether the
    network is gone. The containers go last to first, so the driver, which lives in the server's
    namespace, goes before the server; the network goes last: docker refuses to remove one with a
    container in it.
    """
    present = [remove_container(docker, name) for name in reversed(containers)][::-1]
    try:
        done = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
            [docker, "network", "rm", network], capture_output=True, check=False
        )
        gone = done.returncode == 0
    except OSError:
        gone = False
    return present[0], gone


def run_http(server: Server, out_dir: Path, docker: str, scenario: Scenario, key: bytes) -> int:
    """Drive a server that speaks Streamable HTTP, in a network of its own, and write the companion.

    Network, server, probe, driver, in this order, each labelled with the run's nonce; the probe
    has to find the network closed before a driver starts; everything is removed at the end,
    whatever happened.
    """
    image, inspected, digest, files, definition = _checked_image(server, docker)
    python_id = image_id(docker, PYTHON_IMAGE)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir = out_dir.resolve()
    nonce = secrets.token_hex(4)
    network = f"mcpb-net-{nonce}"
    names = [f"mcpb-{server.name}-{nonce}", f"mcpb-probe-{nonce}", f"mcpb-driver-{nonce}"]
    label = f"{RUN_LABEL}={nonce}"
    options = [part for key, value in NETWORK_OPTIONS.items() for part in ("-o", f"{key}={value}")]
    before = _run_dirs(out_dir)

    server_command = server_http_command(server, image, names[0], network, nonce, docker)
    drive_command = driver_command(server, scenario, out_dir, names[2], names[0], nonce, docker)
    roles = [
        (str(REPO_ROOT / "src"), "<repo>/src"),
        (str(yaml_package()), "<deps>/yaml"),
        (str(out_dir), "<out>"),
        (str(Path(scenario.source).resolve()), "<scenario>"),
    ]
    shown_server = shown_command(server_command, roles, server.env)
    shown_driver = shown_command(drive_command, roles, server.env)

    probe: dict[str, Any] | None = None
    exit_code = -1
    server_present = False
    network_gone = False
    started = _now()
    try:
        created = subprocess.run(  # noqa: S603 - the docker CLI, arguments built here
            [docker, "network", "create", "--internal", *options, "--label", label, network],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        if created.returncode != 0:
            raise RunnerError(f"docker network create failed: {created.stderr.strip()}")
        begun = subprocess.run(  # noqa: S603
            server_command, capture_output=True, text=True, check=False
        )
        if begun.returncode != 0:
            raise RunnerError(f"the server's container did not start: {begun.stderr.strip()}")
        with tempfile.TemporaryDirectory(prefix="mcpb-probe-") as scratch:
            script = Path(scratch) / "probe.py"
            script.write_text(PROBE_SCRIPT, encoding="utf-8")
            script.chmod(0o644)
            probe = run_probe(probe_command(server, names[1], network, nonce, script, docker))
        # Its own session, so that a stop reaches the docker CLI through us, as one signal to
        # its own group.
        process = subprocess.Popen(drive_command, start_new_session=True)  # noqa: S603
        try:
            exit_code = process.wait()
        except KeyboardInterrupt:
            os.killpg(process.pid, signal.SIGINT)
            process.wait()
            raise
    finally:
        server_present, network_gone = remove_run(docker, names, network)
        if not network_gone:
            # Said here as well: when the run failed, the error that ends it names something
            # else, and the network would be left without a word.
            print(f"bench: the network {network} could not be removed; remove it by hand",
                  file=sys.stderr)  # fmt: skip
    finished = _now()
    if not network_gone:
        raise RunnerError(f"the network {network} could not be removed; remove it by hand")

    new = _run_dirs(out_dir) - before
    if len(new) != 1:
        raise RunnerError(
            f"expected one new run directory in {out_dir}, found {len(new)} "
            f"(Kymograph exit {exit_code})"
        )
    run_dir = out_dir / new.pop()
    events = run_dir / "events.jsonl"
    mismatch = http_mismatch(events, server) or scenario_mismatch(events, scenario)
    if mismatch is not None:
        raise RunnerError(
            f"{events}: {mismatch}; no companion written, so this recording cannot be said to "
            "have run as an HTTP run of this server with the observation file"
        )
    recorded_isolation = run_started(events).get("isolation")
    if recorded_isolation != "host":
        raise RunnerError(
            f"{events}: run_started.isolation is {recorded_isolation!r}, not 'host'; no companion "
            "written, because it would describe a different kind of run"
        )

    _write_json(
        run_dir / COMPANION,
        {
            "companion_version": COMPANION_VERSION,
            "stage": "A",
            "server": server.name,
            "provenance": server.provenance,
            "archived": server.archived,
            "role": server.role,
            "package": server.package,
            "source": server.source,
            "isolation": ISOLATION,
            "recorded_isolation": recorded_isolation,
            "transport": server.transport,
            "endpoint": server.endpoint,
            "network": {
                "name": network,
                "options": NETWORK_OPTIONS,
                "internal": True,
                "label": label,
            },
            "probe": probe,
            "probe_script_sha256": hashlib.sha256(PROBE_SCRIPT.encode("utf-8")).hexdigest(),
            "driver": {
                "image": {"reference": PYTHON_IMAGE, "id": python_id},
                "command": shown_driver,
            },
            "server_command": shown_server,
            "docker_command": shown_server,
            "image": {
                "id": image,
                "tag": server.image_tag,
                "base": server.image_base,
                "created": inspected.get("Created"),
            },
            "inputs": {
                "context_sha256": digest,
                "files": files,
                "definition_sha256": definition,
                "environment_hmac_sha256": environment_digest(_set_environment(server), key),
                "environment_key_id": key_id(key),
            },
            "tool": tool_metadata(),
            "host": host_metadata(docker),
            "container_name": names[0],
            "container_present_after_run": server_present,
            "scenario": {
                "name": scenario.name,
                "file": Path(scenario.source).resolve().relative_to(REPO_ROOT).as_posix(),
                "sha256": scenario.digest,
            },
            "mcp_kymograph_command": drive_http_command(server, scenario),
            "mcp_kymograph_exit": exit_code,
            "started_utc": started,
            "finished_utc": finished,
            "recording": events.name,
            "recording_sha256": sha256(events),
        },
    )
    write_result(run_dir, [value for _, value in server.env if len(value) >= MIN_SECRET_VALUE])
    print(f"{server.name}: {run_dir} (Kymograph exit {exit_code})")
    return EXIT_OK


# -- Stage B ------------------------------------------------------------------------------

#: A server that does not start, or whose fixture cannot be reached, is tried this often.
STAGE_B_ATTEMPTS = 2
#: Where the server finds the fixture, and what the script's placeholders stand for.
STAGE_B_VARIABLES = {
    "fixture_url": "http://fixture:8080",
    "fixture_dir": "/srv/fixtures",
    "repo_path": "/srv/fixtures/repo",
    "db_path": "/srv/fixtures/kanarie.db",
}
#: The canary's id, in a file of its own beside the recording and nowhere in the companion.
CANARY_FILE = "canary.txt"
#: The length and SHA-256 of each secret of a run, beside the recording: private, never exported.
SECRETS_FILE = "secrets.sha256"
#: How much text of a string is kept on each side of the canary where it was found.
CANARY_CONTEXT = 80
#: The hex characters at the end of a canary's id: what tells one run's id from another's.
CANARY_HEX = 8
CANARY_DELIVERED = "delivered"
CANARY_ALTERED = "altered"
CANARY_MISSING = "missing"
#: What the observation says where no canary was planted (the negative control).
CANARY_NOT_PLANTED = "not_planted"
OUTCOMES = ("no_signal", "signal", "skipped", "error")
#: What the runner can tell of a failure to set a run up, from the network module's own words:
#: only these end an attempt that did not run. Any other failure of the set-up is not retried.
NO_STAGE_B_REASON = "no stage B definition"


def stage_b_scenario() -> Scenario:
    """The stage B observation file, loaded, or refused: it changes no traffic."""
    try:
        scenario = load_scenario(SCENARIO_B)
    except ScenarioError as error:
        raise ScenarioRefused(str(error)) from None
    if scenario.rules:
        raise ScenarioRefused(
            f"stage B observes only: {SCENARIO_B} has {len(scenario.rules)} rule(s)"
        )
    if not scenario.statements:
        raise ScenarioRefused(f"{SCENARIO_B} has no statement; there would be nothing to observe")
    return scenario


def setup_failure_cause(failure: RunnerError) -> str | None:
    """The cause of an attempt that did not run (``stage_b_net.SetupFailure``), or None for any
    other failure of the set-up, which ends the run. Taken from the exception, never from its
    words: a changed message must not decide whether a failure is tried again."""
    if isinstance(failure, _sibling("stage_b_net").SetupFailure):
        return str(failure.cause)
    return None


def _strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    """Every string in a JSON document with its path (``result.content[0].text``), in order.
    Keys are not strings of the document."""
    if isinstance(value, str):
        return [(path, value)]
    found: list[tuple[str, str]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            found += _strings(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            found += _strings(item, f"{path}.{key}" if path else str(key))
    return found


_NOT_ALNUM = re.compile(r"[^a-z0-9]")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")


def _normalised(text: str) -> str:
    """Lower case, and nothing but letters and digits: what a rewrite of case or of the
    separators (a space, an underscore, an invisible character) leaves."""
    return _NOT_ALNUM.sub("", text.lower())


#: What a secret of the run becomes in a text: as many of these as the secret had characters.
SECRET_MASK = "*"  # noqa: S105 - the mask, not a secret


def _pieces(text: str, percent: bool) -> list[tuple[int, int, str]]:
    """``text`` as pieces ``(start, end, decoded)``: a character is a piece of its own; with
    ``percent``, so is each ``%XX`` of an ASCII character, decoded. A piece is replaced whole,
    so a replacement keeps the length."""
    pieces: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        triple = text[index : index + 3]
        if percent and _PERCENT.fullmatch(triple) and int(triple[1:], 16) < 0x80:
            pieces.append((index, index + 3, chr(int(triple[1:], 16))))
            index += 3
        else:
            pieces.append((index, index + 1, text[index]))
            index += 1
    return pieces


def _hide(text: str, canary_id: str, percent: bool) -> str:
    """The letters and digits of every span of ``text`` that is the id once case, separators and
    the compatibility form (NFKC: full-width letters …) are taken away, and every span that is
    the 8 hex characters alone, turned to ``x``; with ``percent`` also where the span is written
    with ``%XX``. Same length."""
    pieces = _pieces(text, percent)
    decoded = [unicodedata.normalize("NFKC", char) for _, _, char in pieces]
    owner: list[int] = []  # the piece each character of the decoded text comes from
    where: list[int] = []  # the piece of each character of the normal form
    letters: list[str] = []
    for number, form in enumerate(decoded):
        owner.extend([number] * len(form))
        for part in _normalised(form):
            where.append(number)
            letters.append(part)
    flat = "".join(letters)
    wanted = _normalised(canary_id)
    hidden: set[int] = set()
    at = flat.find(wanted)
    while at != -1:
        first, last = where[at], where[at + len(wanted) - 1]
        hidden.update(n for n in range(first, last + 1) if _normalised(decoded[n]))
        at = flat.find(wanted, at + 1)
    hex_part = re.escape(canary_id[-CANARY_HEX:])
    for found in re.finditer(hex_part, "".join(decoded), flags=re.IGNORECASE):
        hidden.update(range(owner[found.start()], owner[found.end() - 1] + 1))
    if not hidden:
        return text
    out = list(text)
    for number in hidden:
        start, end, _ = pieces[number]
        out[start:end] = "x" * (end - start)
    return "".join(out)


def _hide_whole(text: str, canary_id: str, form: str) -> str:
    """The id in a form of the whole text that the pieces do not reach: ``nfkc``, the
    compatibility form of the string (a letter and its accent, joined), or ``percent``, every
    ``%XX`` decoded, UTF-8 included. Where that form is as long as the text, the spans found are
    replaced in place; else the whole text is: nothing says where the span lies."""
    other = unicodedata.normalize("NFKC", text) if form == "nfkc" else unquote(text)
    if other == text:
        return text
    cleaned = _hide(other, canary_id, False)
    cleaned = re.sub(r"(?i)" + re.escape(canary_id), lambda m: "x" * len(m[0]), cleaned)
    if cleaned == other:
        return text
    if len(other) != len(text):
        return "x" * len(text)
    return "".join("x" if a != b else c for a, b, c in zip(cleaned, other, text, strict=True))


def scrub(text: str, canary_id: str | None, hidden: Sequence[str] = ()) -> str:
    """``text`` without the canary's id in any form, and as long as it was (positions stay).

    ``hidden`` are the run's secrets (the passwords of the database, the values of the server's
    environment); each is replaced, as often as it occurs, by as many :data:`SECRET_MASK`
    characters as it has. With no ``canary_id`` only the secrets are taken out.

    The id itself, in any case, becomes the placeholder. Then every span that is the id once
    case and separators are taken away (what ``canary_observation`` calls ``altered``) has its
    letters and digits turned into ``x``, and so has every span of the 8 hex characters alone, in
    any case: a part of the id, cut off or left over, tells one run from another as the whole
    does. This is done for the text as it is, with its characters in their compatibility form
    (NFKC: full-width letters …), with ``%XX`` of ASCII characters decoded, and for the text
    read backwards. Where the compatibility form of the whole string or ``%XX`` of other
    characters shows the id and the length changes, the whole text becomes ``x``. An encoding
    not named here (base64, say) is not found.
    """
    for secret in sorted((h for h in hidden if h), key=len, reverse=True):
        text = text.replace(secret, SECRET_MASK * len(secret))
    if canary_id is None:
        return text
    placeholder = canary_id[:-CANARY_HEX] + "x" * CANARY_HEX
    text = re.sub(re.escape(canary_id), lambda _: placeholder, text, flags=re.IGNORECASE)
    for percent in (False, True):
        text = _hide(text, canary_id, percent)
    for percent in (False, True):
        text = _hide(text[::-1], canary_id, percent)[::-1]
    text = _hide_whole(text, canary_id, "nfkc")
    return _hide_whole(text, canary_id, "percent")


def scrub_value(value: Any, canary_id: str | None, hidden: Sequence[str] = ()) -> Any:
    """``value`` (JSON-like) with :func:`scrub` applied to every string in it, keys included."""
    if canary_id is None and not any(hidden):
        return value
    if isinstance(value, str):
        return scrub(value, canary_id, hidden)
    if isinstance(value, list):
        return [scrub_value(item, canary_id, hidden) for item in value]
    if isinstance(value, dict):
        return {
            scrub(str(k), canary_id, hidden): scrub_value(v, canary_id, hidden)
            for k, v in value.items()
        }
    return value


def call_answers(events: list[dict[str, Any]]) -> set[int]:
    """The ``seq`` of the messages that are the answers to the client's calls: for each
    ``tools/call`` request of the client (its id), the first message of the server after it
    that is a response with that id. What else the server sends — a message of its own with
    the method ``tools/call``, a second answer to the same id — is no answer: the driver took
    the first and read no other."""
    waiting: set[Any] = set()
    answers: set[int] = set()
    for event in events:
        parse = event.get("parse")
        if event.get("type") != "message" or not isinstance(parse, dict):
            continue
        ident = parse.get("id")
        if ident is None or isinstance(ident, bool):
            continue
        if (
            event.get("direction") == "client_to_server"
            and parse.get("kind") == "request"
            and parse.get("method") == "tools/call"
        ):
            waiting.add(ident)
        elif (
            event.get("direction") == "server_to_client"
            and parse.get("kind") == "response"
            and ident in waiting
            and isinstance(event.get("seq"), int)
        ):
            waiting.discard(ident)
            answers.add(event["seq"])
    return answers


def canary_observation(events: list[dict[str, Any]], canary_id: str, placeholder: str) -> dict:
    """Where the canary's id stands in what the server answered to ``tools/call``.

    The answers are those :func:`call_answers` names, as recorded (after the masker). The id
    in a string, word for word: ``delivered``, with every place in order — the message, the
    path in it and ``CANARY_CONTEXT`` characters on each side, cut from the string after
    :func:`scrub`, so that no window shows a part of the id. Else the id found once case and
    separators are taken away: ``altered``, with the places. Else ``missing``. The id itself
    is never in the result.
    """
    delivered: list[dict[str, Any]] = []
    altered: list[dict[str, Any]] = []
    wanted = _normalised(canary_id)
    answers = call_answers(events)
    for event in events:
        if (
            event.get("type") != "message"
            or event.get("direction") != "server_to_client"
            or event.get("seq") not in answers
        ):
            continue
        payload = event.get("payload")
        data = payload.get("data") if isinstance(payload, dict) else None
        for path, text in _strings(data):
            clean = scrub(text, canary_id)
            at = text.find(canary_id)
            while at != -1:
                end = at + len(canary_id)
                delivered.append(
                    {
                        "message_seq": event.get("seq"),
                        "path": path,
                        "before": clean[max(0, at - CANARY_CONTEXT) : at],
                        "after": clean[end : end + CANARY_CONTEXT],
                    }
                )
                at = text.find(canary_id, end)
            if wanted in _normalised(text):
                altered.append({"message_seq": event.get("seq"), "path": path})
    if delivered:
        return {"placeholder": placeholder, "result": CANARY_DELIVERED, "found": delivered}
    if altered:
        return {"placeholder": placeholder, "result": CANARY_ALTERED, "found": altered}
    return {"placeholder": placeholder, "result": CANARY_MISSING, "found": []}


def tool_call_signals(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings and observations on an answer of the server to ``tools/call``
    (:func:`call_answers`), in order: the statement (of a finding), the surface (of an
    observation), the signal and the path."""
    found: list[dict[str, Any]] = []
    answers = call_answers(events)
    for event in events:
        if (
            event.get("method") != "tools/call"
            or event.get("direction") != "server_to_client"
            or event.get("message_seq") not in answers
        ):
            continue
        if event.get("type") == "finding":
            key = event.get("key") if isinstance(event.get("key"), dict) else {}
            found.append(
                {
                    "kind": "finding", "statement": key.get("statement"), "surface": None,
                    "signal": key.get("signal"), "path": event.get("path"),
                }
            )  # fmt: skip
        elif event.get("type") == "observation":
            found.append(
                {
                    "kind": "observation", "statement": None, "surface": event.get("surface"),
                    "signal": event.get("signal"), "path": event.get("path"),
                }
            )  # fmt: skip
    return found


def _outcome(value: str, causes: Sequence[str] = (), signals: Sequence[dict] = ()) -> dict:
    return {"value": value, "causes": list(causes), "signals": list(signals)}


def stage_b_outcome(
    read: Any, events: list[dict[str, Any]], observation: dict[str, Any], negative_control: bool
) -> dict[str, Any]:
    """What one stage B run came to: ``no_signal``, ``signal`` or ``error``.

    ``read`` is the verdict on the recording. A run that is not ``complete`` is an ``error``
    with the verdict's causes — a ``call_failed`` run too (``call_error``, ``tool_error``):
    the content the call was to deliver did not come, and that is no absence of a signal.
    A complete run with a finding or an observation on an answer to ``tools/call`` is a
    ``signal``. Without one it is ``no_signal`` only if the canary was delivered word for word
    — or, for the negative control, which plants none — and else an ``error``,
    ``canary_not_delivered``: the text may not have travelled the path at all.
    """
    if read.state != verdict.COMPLETE:
        return _outcome("error", read.causes)
    signals = tool_call_signals(events)
    if signals:
        return _outcome("signal", signals=signals)
    if negative_control or observation.get("result") == CANARY_DELIVERED:
        return _outcome("no_signal")
    return _outcome("error", ["canary_not_delivered"])


@dataclass
class _Attempt:
    """One try of a stage B run: what became of it, and where it lies."""

    number: int
    #: Why it did not run (set-up failure), else None.
    setup_cause: str | None = None
    setup_detail: str | None = None
    run_dir: Path | None = None
    state: str | None = None
    causes: list[str] = dataclasses.field(default_factory=list)
    outcome: dict[str, Any] | None = None
    #: The id of the attempt's canary and the run's secrets: nothing :meth:`as_dict` says has them.
    canary_id: str | None = None
    hidden: tuple[str, ...] = ()

    @property
    def retry(self) -> bool:
        """Whether the attempt ended as one that is tried again: it did not run, or the server
        never completed the handshake."""
        return self.setup_cause is not None or self.state == verdict.SERVER_FAILED

    def as_dict(self) -> dict[str, Any]:
        return scrub_value(
            {
                "attempt": self.number,
                "run_dir": None if self.run_dir is None else str(self.run_dir),
                "recording": None if self.run_dir is None else str(self.run_dir / "events.jsonl"),
                "state": self.state,
                "causes": [self.setup_cause] if self.setup_cause else self.causes,
                "detail": self.setup_detail,
            },
            self.canary_id,
            self.hidden,
        )


def _drive_stage_b(
    server: Server, stage: StageB, scenario: Scenario, out_dir: Path, docker: str,
    command: list[str], container: str, variables: dict[str, str],
) -> dict[str, Any]:  # fmt: skip
    """``kymograph drive --script`` against the server command, once. Returns what ran."""
    assert stage.script is not None  # noqa: S101 - an active section has a script
    given: list[str] = []
    for name, value in sorted(variables.items()):
        given += ["--script-var", f"{name}={value}"]
    drive = [
        sys.executable, "-m", "mcp_kymograph.cli", "drive", "--out-dir", str(out_dir), "-q",
        "--server-revision", server.revision, "--scenario", scenario.source,
        "--script", str(stage.script), *given, "--", *command,
    ]  # fmt: skip
    before = _run_dirs(out_dir)
    started = _now()
    process = subprocess.Popen(drive, start_new_session=True)  # noqa: S603
    try:
        exit_code = process.wait()
    except KeyboardInterrupt:
        os.killpg(process.pid, signal.SIGINT)
        process.wait()
        raise
    finally:
        present_after = remove_container(docker, container)
    finished = _now()
    new = _run_dirs(out_dir) - before
    if len(new) != 1:
        raise RunnerError(
            f"expected one new run directory in {out_dir}, found {len(new)} "
            f"(Kymograph exit {exit_code})"
        )
    return {
        "drive": drive, "command": command, "container": container,
        "run_dir": out_dir / new.pop(), "exit": exit_code, "started": started,
        "finished": finished, "present_after": present_after,
    }  # fmt: skip


def _stage_b_attempt(
    server: Server, stage: StageB, scenario: Scenario, checked: tuple, out_dir: Path,
    docker: str, key: bytes, number: int,
) -> _Attempt:  # fmt: skip
    """One attempt: the canary, the fixture, the drive, the checks of the recording, the
    companion. An attempt whose set-up failed in a way that is tried again has no run directory.

    As soon as the run directory is there, :data:`SECRETS_FILE` is written into it, mode 0600:
    one line ``<length> <sha256 hex>`` per secret of the run (the helpers' passwords, the values
    of the environment), the length in bytes of UTF-8, sorted, never the value. It is private
    and never exported; only ``export_check`` reads it, to look for the secrets in an exported
    tree. A run without secrets has no such file."""
    image, inspected, digest, files, definition = checked
    assert stage.fixture is not None  # noqa: S101 - an active section has a fixture
    plant = stage.fixture != FIXTURE_NONE
    canary = _fixtures().new_canary(server.name) if plant else None
    canary_id = None if canary is None else canary.id
    # The password of the database role the server is given: new for each attempt, in the
    # fixture's init script and the server's arguments, and in no file or output of the runner.
    reader_password = secrets.token_urlsafe(24) if stage.fixture == "postgres" else None
    environment = tuple(sorted({v for _, v in server.env if len(v) >= MIN_SECRET_VALUE}))
    hidden: tuple[str, ...] = (
        environment if reader_password is None else (reader_password, *environment)
    )
    fixture = (
        _fixtures().build(stage.fixture, canary, reader_password=reader_password) if plant else None
    )
    variables = dict(STAGE_B_VARIABLES)
    if canary is not None:
        variables["canary"] = canary.id

    out_dir.mkdir(parents=True, exist_ok=True)
    net = None
    entered = False
    try:
        if fixture is None:
            container = f"mcpb-{server.name}-{secrets.token_hex(4)}"
            command = docker_command(
                dataclasses.replace(server, args=stage.args), image, container, docker
            )
            driven = _drive_stage_b(
                server, stage, scenario, out_dir, docker, command, container, variables
            )
        else:
            net = _sibling("stage_b_net").StageBNetwork(
                stage.fixture, fixture, stage, docker, out_dir,
                canary_id=canary_id, reader_password=reader_password, hidden=environment,
            )  # fmt: skip
            hidden = net.secrets
            with net:
                entered = True
                container = net.server_name
                command = net.server_command(image, list(stage.args), server.env)
                driven = _drive_stage_b(
                    server, stage, scenario, out_dir, docker, command, container, variables
                )
    except RunnerError as failure:
        cause = None if entered else setup_failure_cause(failure)
        if cause is None:
            raise
        shown = scrub_value(str(failure), canary_id, hidden)
        print(f"bench: attempt {number}: {cause}: {shown}", file=sys.stderr)
        return _Attempt(
            number, setup_cause=cause, setup_detail=shown, canary_id=canary_id, hidden=hidden
        )

    run_dir: Path = driven["run_dir"]
    # Before any check of the recording that may refuse it: the run directory stays either way,
    # and the export has to look for the secrets of every run there is.
    encoded = {secret.encode("utf-8") for secret in hidden if secret}
    digests = sorted(f"{len(data)} {hashlib.sha256(data).hexdigest()}\n" for data in encoded)
    if digests:
        descriptor = os.open(
            run_dir / SECRETS_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write("".join(digests))
    events_path = run_dir / "events.jsonl"
    expected, _ = Masker().mask_argv(driven["command"])
    if recorded_argv(events_path) != expected:
        raise RunnerError(
            f"{events_path}: run_started.argv is not the command the runner gave; no companion "
            "written, so this recording cannot be said to have run in a container"
        )
    mismatch = scenario_mismatch(events_path, scenario)
    if mismatch is not None:
        raise RunnerError(
            f"{events_path}: {mismatch}; no companion written, so this recording cannot be said "
            "to have run with the observation file"
        )
    started_event = run_started(events_path)
    if started_event.get("script_digest") != sha256(stage.script):
        raise RunnerError(
            f"{events_path}: run_started.script_digest is not the digest of the script file; "
            "no companion written, so this recording cannot be said to have run that script"
        )
    recorded_isolation = started_event.get("isolation")
    if recorded_isolation != "host":
        raise RunnerError(
            f"{events_path}: run_started.isolation is {recorded_isolation!r}, not 'host'; no "
            "companion written, because it would describe a different kind of run"
        )

    read = verdict.read(events_path)
    events, _ = verdict.read_events(events_path.read_bytes())
    if canary is not None:
        observation = canary_observation(events, canary.id, canary.placeholder)
        (run_dir / CANARY_FILE).write_text(canary.id + "\n", encoding="utf-8")
    else:
        observation = {"placeholder": None, "result": CANARY_NOT_PLANTED, "found": []}
    negative = server.role == "negative-control" and not plant
    outcome = scrub_value(stage_b_outcome(read, events, observation, negative), canary_id, hidden)

    def hide(text: str) -> str:
        return text if canary is None else text.replace(canary.id, canary.placeholder)

    roles = [
        (str(out_dir), "<out>"),
        (str(out_dir.resolve()), "<out>"),
        (scenario.source, "<scenario>"),
        (str(Path(scenario.source).resolve()), "<scenario>"),
        (str(stage.script), "<script>"),
        (str(REPO_ROOT), "<repo>"),
    ]
    shown_docker = shown_command(driven["command"], roles, server.env)
    shown_drive = [hide(part) for part in shown_command(driven["drive"], roles, server.env)]
    shown_drive[driven["drive"].index("--") + 1] = os.path.basename(docker)
    recorded_vars = started_event.get("script_vars")
    script_vars = {
        name: hide(value) for name, value in (recorded_vars or {}).items() if isinstance(value, str)
    }
    # The last step before the file is written: whatever way the id found into any string of
    # the companion (the network report, a path made of a key), it does not stay. canary.txt is
    # the one place it is. The run's passwords (the argument {postgres_url} stands for, shown in
    # the docker command) are taken out the same way, and are in no file at all.
    companion = {
        "companion_version": COMPANION_VERSION_B,
        "stage": "B",
        "attempt": number,
        "server": server.name,
        "provenance": server.provenance,
        "archived": server.archived,
        "role": server.role,
        "package": server.package,
        "source": server.source,
        "isolation": ISOLATION,
        "recorded_isolation": recorded_isolation,
        "fixture": {
            "kind": stage.fixture,
            "sha256": None if fixture is None else fixture.sha256,
            "files": [] if fixture is None else list(fixture.files),
        },
        "canary": {**observation, "file": CANARY_FILE if canary is not None else None},
        "script": {"file": stage.script_name, "sha256": sha256(stage.script)},
        "script_vars": script_vars,
        "stage_b_args": list(stage.args),
        "network": None if net is None or net.report is None else net.report.as_dict(),
        "docker_command": shown_docker,
        "image": {
            "id": image,
            "tag": server.image_tag,
            "base": server.image_base,
            "created": inspected.get("Created"),
        },
        "inputs": {
            "context_sha256": digest,
            "files": files,
            "definition_sha256": definition,
            "environment_hmac_sha256": environment_digest(_set_environment(server), key),
            "environment_key_id": key_id(key),
        },
        "tool": tool_metadata(),
        "host": host_metadata(docker),
        "container_name": driven["container"],
        "container_present_after_run": driven["present_after"],
        "scenario": {
            "name": scenario.name,
            "file": Path(scenario.source).resolve().relative_to(REPO_ROOT).as_posix(),
            "sha256": scenario.digest,
        },
        "mcp_kymograph_command": shown_drive,
        "mcp_kymograph_exit": driven["exit"],
        "started_utc": driven["started"],
        "finished_utc": driven["finished"],
        "recording": events_path.name,
        "recording_sha256": sha256(events_path),
        "outcome": outcome,
    }
    _write_json(run_dir / COMPANION, scrub_value(companion, canary_id, hidden))
    write_result(run_dir, hidden)
    return _Attempt(
        number, run_dir=run_dir, state=read.state, causes=list(read.causes), outcome=outcome,
        canary_id=canary_id, hidden=hidden,
    )  # fmt: skip


def _amend_result(run_dir: Path, fields: dict[str, Any]) -> None:
    """Set ``fields`` in the ``result.json`` of ``run_dir``; a result that is not there or not
    a JSON object is an error, not a skip."""
    path = run_dir / "result.json"
    try:
        data = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError) as exc:
        why = getattr(exc, "strerror", None) or exc
        raise RunnerError(f"{path}: cannot be read: {why}") from None
    if not isinstance(data, dict):
        raise RunnerError(f"{path}: not a JSON object")
    data.update(fields)
    _write_json(path, data)


def run_stage_b(server: Server, out_dir: Path, docker: str, key: bytes) -> dict[str, Any]:
    """Drive one server in stage B, with a second attempt if the first did not get a session.

    An attempt that ends ``server_failed``, whose fixture volume could not be filled, or whose
    network probe or fixture server stopped the run, is tried once more, with a canary and
    fixture of its own. If the second ends the same way the result is ``skipped`` with the
    cause and where both attempts lie. Everything else is the outcome of the last attempt.
    Returns the result: the outcome and each attempt.
    """
    stage = server.stage_b
    if stage is None or stage.status != "active":
        reason = NO_STAGE_B_REASON if stage is None else stage.reason
        outcome = {"value": "skipped", "reason": reason}
        return {"server": server.name, "stage": "B", "outcome": outcome, "attempts": []}
    if server.transport != TRANSPORT_STDIO:
        raise RunnerError(f"{server.name}: stage B drives servers over stdio only")
    scenario = stage_b_scenario()
    checked = _checked_image(server, docker)
    attempts: list[_Attempt] = []
    for number in range(1, STAGE_B_ATTEMPTS + 1):
        attempt = _stage_b_attempt(server, stage, scenario, checked, out_dir, docker, key, number)
        attempts.append(attempt)
        if not attempt.retry:
            break
    last = attempts[-1]
    # The attempt that carries the run's result is the last one that has a run directory; each
    # attempt before it is marked ``retried`` and left out of the report.
    carriers = [a for a in attempts if a.run_dir is not None]
    carrier = carriers[-1] if carriers else None
    for attempt in attempts:
        if attempt.run_dir is not None and attempt is not carrier and attempt.number < last.number:
            _amend_result(attempt.run_dir, {"retried": True})
    if last.retry:
        causes = last.as_dict()["causes"]
        outcome: dict[str, Any] = {
            "value": "skipped",
            "reason": f"no session in {len(attempts)} attempt(s): {', '.join(causes)}",
            "found_at": [a.as_dict() for a in attempts],
        }
        if carrier is not None and carrier.run_dir is not None:
            # ``causes`` is what a result's outcome always has; the report reads it. The result
            # may be exported: of each attempt it names the run directory and the recording by
            # name, never by path, and no detail. The output above keeps them (it is private).
            places = []
            for shown in (a.as_dict() for a in attempts):
                run_dir, recording = shown["run_dir"], shown["recording"]
                places.append(
                    {
                        "attempt": shown["attempt"],
                        "run_dir": None if run_dir is None else Path(run_dir).name,
                        "recording": None if recording is None else Path(recording).name,
                        "state": shown["state"],
                        "causes": shown["causes"],
                    }
                )
            written = {**outcome, "found_at": places, "causes": list(causes)}
            _amend_result(carrier.run_dir, {"outcome": written})
    else:
        assert last.outcome is not None  # noqa: S101 - an attempt that ran has one
        outcome = last.outcome
    return {
        "server": server.name, "stage": "B", "outcome": outcome,
        "attempts": [a.as_dict() for a in attempts],
    }  # fmt: skip


# -- compare ------------------------------------------------------------------------------

#: The fields of the companion whose difference is listed beside the runs' differences, in
#: this order. ``docker_command`` is compared without the run's own ``--name <container>``,
#: which differs by design; a ``--name`` among the server's arguments stays.
_INPUT_FIELDS: tuple[str, ...] = (
    "transport",
    "image.id",
    "image.created",
    "inputs.context_sha256",
    "inputs.definition_sha256",
    "inputs.environment_hmac_sha256",
    "scenario.sha256",
    # Stage B. The canary's id is no input: it differs in every run, by design, like the nonce.
    # The fixture's hash is the shape of the fixture, taken with the placeholder.
    "stage",
    "fixture.kind",
    "fixture.sha256",
    "script.sha256",
    "stage_b_args",
    "docker_command",
    "tool.mcp_kymograph_version",
    "tool.repository_commit",
    "tool.repository_tracked_changes",
    "tool.runner_sha256",
    "host.docker_server_version",
    "host.docker_context",
    "host.default_runtime",
    "host.security_options",
    "host.logging_driver",
    "host.daemon_kernel",
    "host.client_kernel",
    "host.machine",
    "host.python",
)


class CompareRefused(ValueError):
    """Two run directories that are not to be compared; the message says why."""


@dataclass(frozen=True)
class Loaded:
    """One run directory as ``compare`` reads it."""

    given: str
    companion: dict[str, Any]
    events: list[dict[str, Any]]
    state: str
    causes: list[str]


def _field(companion: dict[str, Any], dotted: str) -> Any:
    if dotted == "transport":
        # A version 3 companion is a stdio run and does not say so.
        return companion.get("transport", TRANSPORT_STDIO)
    if dotted == "docker_command":
        command = companion.get("docker_command")
        if not isinstance(command, list):
            return command
        image = _field(companion, "image.id")
        end = command.index(image) if image in command else len(command)
        # A stage B run with a network names its own nonce in the volume, the holder, the label
        # and the resolver file.
        network = companion.get("network")
        nonce = network.get("nonce") if isinstance(network, dict) else None
        kept: list[Any] = []
        skip = False
        for index, part in enumerate(command):
            if skip:
                skip = False
            elif part == "--name" and index < end:
                skip = True
            elif index < end and isinstance(part, str):
                # An HTTP run's label and network carry the run's own nonce: different in every
                # run, by design, and so no input.
                part = _RUN_NONCE.sub("<run>", part)
                if isinstance(nonce, str) and nonce:
                    part = part.replace(nonce, "<run>")
                kept.append(part)
            else:
                kept.append(part)
        return kept
    if dotted == "tool.mcp_kymograph_version":
        tool = companion.get("tool")
        if isinstance(tool, dict) and "mcp_kymograph_version" not in tool:
            return tool.get(EARLIER_VERSION_KEY)
    value: Any = companion
    for part in dotted.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


#: The nonce of one HTTP run where the docker command carries it: in the run's label (under
#: either name of the label) and in the name of its network.
_RUN_NONCE = re.compile(
    rf"(?<=^{re.escape(RUN_LABEL)}=)[0-9a-f]+$"
    rf"|(?<=^{re.escape(EARLIER_RUN_LABEL)}=)[0-9a-f]+$"
    r"|(?<=^mcpb-net-)[0-9a-f]+$"
)


def _load_run(directory: Path) -> Loaded:
    companion_path = directory / COMPANION
    events_path = directory / "events.jsonl"
    for needed in (companion_path, events_path):
        if not needed.is_file():
            raise CompareRefused(f"{directory}: no {needed.name}")
    try:
        companion = json.loads(companion_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RunnerError(f"{companion_path}: cannot be read: {exc}") from None
    if not isinstance(companion, dict):
        raise RunnerError(f"{companion_path}: not a JSON object")
    if companion.get("companion_version") in COMPANION_VERSIONS_OLD:
        raise CompareRefused(
            f"{companion_path}: a version {companion['companion_version']} companion holds a "
            "plain SHA-256 of the environment; the run has to be run again"
        )
    if companion.get("companion_version") not in (COMPANION_VERSION, COMPANION_VERSION_B):
        raise CompareRefused(
            f"{companion_path}: companion_version is neither {COMPANION_VERSION} (stage A) "
            f"nor {COMPANION_VERSION_B} (stage B)"
        )
    try:
        raw = events_path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"{events_path}: cannot be read: {exc.strerror or exc}") from None
    if hashlib.sha256(raw).hexdigest() != companion.get("recording_sha256"):
        raise RunnerError(f"{events_path}: the recording changed after its companion was written")
    # The parser the verdict uses; a line that is no event is in the state, not in the sets.
    events, _ = verdict.read_events(raw)
    read = verdict.read(events_path)
    return Loaded(str(directory), companion, events, read.state, list(read.causes))


def _multiset(events: list[dict[str, Any]], kind: str, shape: Any) -> Counter:
    return Counter(shape(event) for event in events if event.get("type") == kind)


def _observation_key(event: dict[str, Any]) -> tuple:
    keys = ("method", "surface", "path", "signal", "normalized")
    return tuple(event.get(name) for name in keys)


def _finding_key(event: dict[str, Any]) -> tuple:
    key = event.get("key") if isinstance(event.get("key"), dict) else {}
    return (
        key.get("statement"), key.get("signal"), key.get("locator"),
        event.get("method"), event.get("path"), event.get("normalized"),
    )  # fmt: skip


def _evaluated_key(event: dict[str, Any]) -> tuple:
    return tuple(event.get(name) for name in ("statement", "method", "reason", "checked"))


def _sorted_entries(counter: Counter, names: tuple[str, ...]) -> list[dict[str, Any]]:
    entries = [
        {**dict(zip(names, key, strict=True)), "count": count} for key, count in counter.items()
    ]
    return sorted(entries, key=lambda e: json.dumps(e, sort_keys=True, ensure_ascii=False))


def _multiset_difference(
    aspect: str, a: Counter, b: Counter, names: tuple[str, ...]
) -> dict[str, Any] | None:
    only_a, only_b = a - b, b - a
    if not only_a and not only_b:
        return None
    return {
        "aspect": aspect,
        "only_in_a": _sorted_entries(only_a, names),
        "only_in_b": _sorted_entries(only_b, names),
    }


def _finished(run: Loaded, name: str) -> Any:
    for event in reversed(run.events):
        if event.get("type") == "run_finished":
            return event.get(name)
    return None


def _outcome_view(companion: dict[str, Any]) -> dict[str, Any] | None:
    """The outcome of a stage B run as ``compare`` sets it side by side: the value, the causes
    and the signals. None for a run that has none (stage A)."""
    outcome = companion.get("outcome")
    if not isinstance(outcome, dict):
        return None
    return {key: outcome.get(key) for key in ("value", "causes", "signals")}


def _canary_view(companion: dict[str, Any]) -> dict[str, Any] | None:
    canary = companion.get("canary")
    if not isinstance(canary, dict):
        return None
    found = canary.get("found")
    places = (
        [item.get("path") for item in found if isinstance(item, dict)]
        if isinstance(found, list)
        else None
    )
    return {"result": canary.get("result"), "paths": places}


def compare(first: Path, second: Path, key: bytes | None = None) -> dict[str, Any]:
    """Where two runs of one server differ. Reports; rates nothing.

    The environment's HMAC is an opaque value. Runs made with different keys have HMACs that
    say nothing about each other: that is reported on its own, not as a difference of the
    environment. With ``key`` both runs have to have been made with it.

    The state and its causes are what ``verdict.read`` returns for each recording. The rest is
    the recordings' own observations, findings, evaluations and counts, and the companions'
    inputs.
    """
    a, b = _load_run(first), _load_run(second)
    if a.companion.get("server") != b.companion.get("server"):
        raise CompareRefused(
            f"the runs are of different servers: {a.companion.get('server')!r} "
            f"and {b.companion.get('server')!r}"
        )
    if key is not None:
        for label, loaded in (("a", a), ("b", b)):
            found = _field(loaded.companion, "inputs.environment_key_id")
            if found != key_id(key):
                raise CompareRefused(
                    f"run {label} ({loaded.given}) was not made with this key: its key id is "
                    f"{found!r}, the key's is {key_id(key)!r}"
                )
    keys_differ = _field(a.companion, "inputs.environment_key_id") != _field(
        b.companion, "inputs.environment_key_id"
    )
    inputs = []
    for name in _INPUT_FIELDS:
        if keys_differ and name == "inputs.environment_hmac_sha256":
            continue
        left, right = _field(a.companion, name), _field(b.companion, name)
        if left != right:
            inputs.append({"field": name, "a": left, "b": right})

    differences: list[dict[str, Any]] = []
    if a.state != b.state:
        differences.append({"aspect": "state", "a": a.state, "b": b.state})
    if a.causes != b.causes:
        differences.append({"aspect": "causes", "a": a.causes, "b": b.causes})
    multisets = (
        ("observations", "observation", _observation_key,
         ("method", "surface", "path", "signal", "normalized")),
        ("findings", "finding", _finding_key,
         ("statement", "signal", "locator", "method", "path", "normalized")),
        ("statements_evaluated", "statement_evaluated", _evaluated_key,
         ("statement", "method", "reason", "checked")),
    )  # fmt: skip
    for aspect, kind, shape, names in multisets:
        found = _multiset_difference(
            aspect, _multiset(a.events, kind, shape), _multiset(b.events, kind, shape), names
        )
        if found is not None:
            differences.append(found)
    for aspect, name in (
        ("observation_counts", "observations_by_method"),
        ("finding_counts", "findings_by_statement"),
    ):
        left, right = _finished(a, name), _finished(b, name)
        if left != right:
            differences.append({"aspect": aspect, "a": left, "b": right})
    # Stage B: what the run came to, and what became of the canary: the result of the
    # observation and the paths it was found at. The text around the canary is not compared.
    for aspect, shape in (("outcome", _outcome_view), ("canary", _canary_view)):
        left, right = shape(a.companion), shape(b.companion)
        if left != right:
            differences.append({"aspect": aspect, "a": left, "b": right})

    return {
        "compare_version": COMPARE_VERSION,
        "runs": [
            {"dir": r.given, "server": r.companion.get("server"), "state": r.state,
             "causes": r.causes}
            for r in (a, b)
        ],
        "inputs_differ": inputs,
        "environment_keys_differ": keys_differ,
        "differences": differences,
    }  # fmt: skip


# -- command line -------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bench.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    compared = commands.add_parser(
        "compare",
        help="list where two runs of one server differ",
        description="List, from both sides, where two runs of one server differ and where "
        "their inputs differ. It reports and does not rate: an empty list of differences is "
        "the whole statement. Exit 0 once the comparison is printed, whatever it holds.",
    )
    compared.add_argument("run_dirs", nargs=2, type=Path, metavar="RUN_DIR")
    compared.add_argument(
        "--key",
        type=Path,
        metavar="FILE",
        help="the suite's key: refuse a run that was not made with it",
    )
    written = commands.add_parser(
        "result",
        help="write result.json again for run directories that exist",
        description="Write result.json beside the companion of each run directory, from the "
        "companion and the recording alone. One line per directory.",
    )
    written.add_argument("run_dirs", nargs="+", type=Path, metavar="RUN_DIR")
    disclosed = commands.add_parser(
        "disclosure",
        help="the private file that says which findings may be published",
        description="Lay out or check the disclosure file against the result.json of run "
        "directories. Exit 0 without a problem, else 1; notes go to stderr.",
    )
    disclosure_commands = disclosed.add_subparsers(dest="disclosure_command", required=True)
    for name, text in (
        ("init", "create the file or add the findings it lacks, as unveröffentlicht"),
        ("check", "list findings of the runs that the file lacks"),
    ):
        sub = disclosure_commands.add_parser(name, help=text)
        sub.add_argument("--file", type=Path, required=True, metavar="F")
        sub.add_argument("run_dirs", nargs="+", type=Path, metavar="RUN_DIR")
    reported = commands.add_parser(
        "report",
        help="write report.html and report.md over both stages",
        description="Write report.html and report.md into --out: one row per server and stage, "
        "from the definitions and the result.json of the runs under each --runs directory "
        "(<DIR>/<server>/<run>/result.json). Excerpts of signals only with --excerpts.",
    )
    reported.add_argument("--definitions", type=Path, required=True, metavar="DIR")
    reported.add_argument("--runs", type=Path, action="append", required=True, metavar="DIR")
    reported.add_argument("--out", type=Path, required=True, metavar="DIR")
    reported.add_argument("--excerpts", action="store_true", help="show the excerpt of a signal")
    exported = commands.add_parser(
        "export",
        help="write the public results: the only way into the public results directory",
        description="Build the public tree from the runs under each --runs directory and check "
        "it; only then replace the target. Without --out the target is "
        f"{EXPORT_TARGET.as_posix()}/ in the repository; with --out (a trial export) it must be "
        "outside the public tree and where git does not track it. Servers with a finding that "
        "is not freigegeben in the disclosure file are left out; their names are not printed.",
    )
    exported.add_argument("--definitions", type=Path, required=True, metavar="DIR")
    exported.add_argument("--runs", type=Path, action="append", required=True, metavar="DIR")
    exported.add_argument("--disclosure", type=Path, required=True, metavar="F")
    exported.add_argument("--key", type=Path, action="append", required=True, metavar="K")
    exported.add_argument("--out", type=Path, metavar="DIR")
    helpers = commands.add_parser("build-helpers", help="build the helper images of stage B")
    helpers.add_argument(
        "--docker", default="docker", metavar="PROGRAM", help="the docker CLI to call"
    )
    made = commands.add_parser("key", help="create the key of a suite")
    made.add_argument("--out", type=Path, required=True, metavar="FILE")
    for name, text in (("build", "build a server's image"), ("run", "drive a server once")):
        sub = commands.add_parser(name, help=text)
        sub.add_argument(
            "--definitions",
            type=Path,
            required=True,
            metavar="DIR",
            help=f"the directory holding {DEFINITIONS_FILE} and the image contexts",
        )
        sub.add_argument("--server", required=True, metavar="NAME")
        sub.add_argument(
            "--docker", default="docker", metavar="PROGRAM", help="the docker CLI to call"
        )
        if name == "run":
            sub.add_argument(
                "--stage",
                choices=("a", "b"),
                default="a",
                help="a: the self-description (default); b: the result of a tool call, against "
                "the fixture the definition names",
            )
            sub.add_argument(
                "--hmac-key",
                type=Path,
                required=True,
                metavar="FILE",
                help="the suite's key (32 bytes, mode 0600, outside any repository)",
            )
            sub.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, metavar="DIR")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "key":
        refusal = out_dir_refusal(args.out, subject="keys")
        if refusal is not None:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        try:
            create_key(args.out)
        except RunnerError as failure:
            print(f"bench: {failure}", file=sys.stderr)
            return EXIT_FAILED
        print(f"bench: key written to {args.out}", file=sys.stderr)
        return EXIT_OK
    if args.command == "build-helpers":
        try:
            return build_helpers(args.docker)
        except RunnerError as failure:
            print(f"bench: {failure}", file=sys.stderr)
            return EXIT_FAILED
    if args.command == "result":
        for directory in args.run_dirs:
            try:
                write_result(directory)
            except RunnerError as failure:
                print(f"bench: {failure}", file=sys.stderr)
                return EXIT_FAILED
            print(f"{directory}: {_sibling('results').RESULT_FILE} written")
        return EXIT_OK
    if args.command == "report":
        refusal = out_dir_refusal(args.out, subject="reports")
        if refusal is not None:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        report = _sibling("report")
        try:
            rows = report.collect(load_definitions(args.definitions / DEFINITIONS_FILE), args.runs)
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / "report.html").write_text(
                report.html(rows, args.excerpts), encoding="utf-8"
            )
            (args.out / "report.md").write_text(
                report.markdown(rows, args.excerpts), encoding="utf-8"
            )
        except DefinitionError as refusal:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        except (RunnerError, OSError) as failure:
            print(f"bench: {getattr(failure, 'strerror', None) or failure}", file=sys.stderr)
            return EXIT_FAILED
        print(f"bench: report written to {args.out}", file=sys.stderr)
        return EXIT_OK
    if args.command == "export":
        if args.out is not None:
            refusal = out_dir_refusal(args.out, repo_root=REPO_ROOT, subject="exports")
            if refusal is not None:
                print(f"bench: {refusal}", file=sys.stderr)
                return EXIT_REFUSED
        target = args.out if args.out is not None else REPO_ROOT / EXPORT_TARGET
        exporter = _sibling("export")
        definitions = args.definitions / DEFINITIONS_FILE
        try:
            disclosed = _sibling("disclosure").load(args.disclosure)
            stay, dropped = exporter.server_split(definitions, args.runs, disclosed)
            written = exporter.export(definitions, args.runs, args.disclosure, args.key, target)
        except DefinitionError as refusal:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        except (RunnerError, OSError) as failure:
            print(f"bench: {getattr(failure, 'strerror', None) or failure}", file=sys.stderr)
            return EXIT_FAILED
        print(written)
        print(
            f"bench: {len(stay)} server(s) in the export, {len(dropped)} left out",
            file=sys.stderr,
        )
        return EXIT_OK
    if args.command == "disclosure":
        disclosure = _sibling("disclosure")
        try:
            results = disclosure.read_results(args.run_dirs)
            if args.disclosure_command == "init":
                added = disclosure.init(args.file, results)
                print(f"bench: {args.file}: {added} finding(s) added", file=sys.stderr)
                return EXIT_OK
            lines = disclosure.check(disclosure.load(args.file), results)
        except RunnerError as failure:
            print(f"bench: {failure}", file=sys.stderr)
            return EXIT_FAILED
        for line in lines:
            print(f"bench: {line}", file=sys.stderr)
        return EXIT_FAILED if any(not line.startswith("note: ") for line in lines) else EXIT_OK
    if args.command == "compare":
        first, second = args.run_dirs
        try:
            if args.key is not None:
                refusal = key_refusal(args.key)
                if refusal is not None:
                    print(f"bench: {refusal}", file=sys.stderr)
                    return EXIT_REFUSED
            result = compare(first, second, read_key(args.key) if args.key else None)
        except CompareRefused as refusal:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        except RunnerError as failure:
            print(f"bench: {failure}", file=sys.stderr)
            return EXIT_FAILED
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if result["environment_keys_differ"]:
            print(
                "bench: the runs were made with different keys; their environments cannot be "
                "compared",
                file=sys.stderr,
            )
        print(
            f"bench: compared {first} and {second}: {len(result['differences'])} "
            f"difference(s), {len(result['inputs_differ'])} input difference(s)",
            file=sys.stderr,
        )
        return EXIT_OK
    try:
        servers = load_definitions(args.definitions / DEFINITIONS_FILE)
    except DefinitionError as refusal:
        print(f"bench: {refusal}", file=sys.stderr)
        return EXIT_REFUSED
    server = servers.get(args.server)
    if server is None:
        known = ", ".join(sorted(servers))
        print(f"bench: no server {args.server!r}; defined: {known}", file=sys.stderr)
        return EXIT_REFUSED
    if args.command == "run" and args.stage == "b":
        refusal = key_refusal(args.hmac_key) or out_dir_refusal(args.out_dir)
        if refusal is not None:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        try:
            result = run_stage_b(server, args.out_dir, args.docker, read_key(args.hmac_key))
        except ScenarioRefused as refusal:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        except RunnerError as failure:
            print(f"bench: {failure}", file=sys.stderr)
            return EXIT_FAILED
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return EXIT_OK
    if args.command == "run":
        if server.stage_a_status != "active":
            print(f"bench: {server.name} is skipped in stage A: {server.stage_a_reason}",
                  file=sys.stderr)  # fmt: skip
            return EXIT_REFUSED
        refusal = key_refusal(args.hmac_key) or out_dir_refusal(args.out_dir)
        if refusal is not None:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
        try:
            scenario = stage_a_scenario()
        except ScenarioRefused as refusal:
            print(f"bench: {refusal}", file=sys.stderr)
            return EXIT_REFUSED
    try:
        if args.command == "build":
            return build(server, args.docker)
        return run(server, args.out_dir, args.docker, scenario, read_key(args.hmac_key))
    except RunnerError as failure:
        print(f"bench: {failure}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
