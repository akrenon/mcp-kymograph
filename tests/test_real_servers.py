"""The driver against real servers of both generations, each in a container from an image pinned
by id (tests/real_servers: ``python3 tests/real_servers/build.py`` builds the four and writes
their ids to images.json, and the tests start an image by that id and by nothing else).

``fetch`` is the official reference server on PyPI, once per generation, over stdio. The two
``reference-http`` servers are small servers on the official Python SDK, over Streamable HTTP.
No real server of this generation over Streamable HTTP could be built here (its reference
server, ``fetch``, speaks stdio only), so these two stand in for it; their tests say so.

A stdio server runs with no network, a read-only root and ``--rm``; an HTTP server runs alone in
a Docker network of its own, made for it, and is reachable only through a port published on
127.0.0.1. Every container and network carries the label ``LABEL`` and is removed at the end of
the module, whether or not the tests passed. The tests are marked ``real_server``: they need the
Docker daemon and the four images, not the sandbox's. Without the daemon or the image of a server
the tests are skipped, naming the reason (for an image, the build command); with
``MCP_KYMOGRAPH_REQUIRE_DOCKER=1`` that is a failure, as for the sandbox's images. Every test
against a reference server warns with ``StandInServerWarning``, so the note shows in the warnings
summary of the run.
"""

from __future__ import annotations

import ast
import contextlib
import http.server
import io
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass
from pathlib import Path

import pytest

from conftest import docker_required
from mcp_kymograph import cli
from mcp_kymograph.environment import helper_env
from mcp_kymograph.masking import PLACEHOLDER
from test_cli_engagement import events_of, recording_in, write_engagement
from test_token_artifacts import forms, made_up

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

import http_server  # noqa: E402

REAL = Path(__file__).parent / "real_servers"
BUILD = "python3 tests/real_servers/build.py"
LABEL = "mcp-kymograph.real-server"
NONCE = secrets.token_hex(6)
NO_REFERENCE_SERVER = (
    "no real server of this generation over Streamable HTTP could be built here; "
    "reference server on the official SDK"
)


class StandInServerWarning(UserWarning):
    """A test ran against a reference server, not a real one: the note is in the run's report."""


STDIO = ("fetch-2025-11-25", "fetch-2026-07-28")
HTTP = ("reference-http-2025-11-25", "reference-http-2026-07-28")
LEGACY_HTTP = "reference-http-2025-11-25"
MODERN_HTTP = "reference-http-2026-07-28"
#: Which inventory script of tests/real_servers reads a ``fetch`` image's own lists.
INVENTORY = {"fetch-2025-11-25": "inventory_1x.py", "fetch-2026-07-28": "inventory_2x.py"}
#: The protocol constant of the SDK installed in each image, as that SDK names it.
LATEST = {"fetch-2025-11-25": "2025-11-25", "fetch-2026-07-28": "2026-07-28"}

#: What each server is held to, with and without an engagement: the ``era_decided`` event as
#: (era, version) or None for no such event, the ``script_finished`` event's (era, version), the
#: version the ``initialize`` asks for (None: none is sent) and the one the server answers with.
#: Where a case is not set by the specification but is what the server does, it is held as that.
GENERATION = {
    ("fetch-2025-11-25", True): {
        "decided": ("legacy", "2025-11-25"),
        "finished": ("legacy", "2025-11-25"),
        "asked": "2025-11-25",
        "answered": "2025-11-25",
    },
    ("fetch-2025-11-25", False): {
        "decided": None,
        "finished": ("legacy", "2025-06-18"),
        "asked": "2025-06-18",
        "answered": "2025-06-18",
    },
    ("fetch-2026-07-28", True): {
        "decided": ("modern", "2026-07-28"),
        "finished": ("modern", "2026-07-28"),
        "asked": None,
        "answered": None,
    },
    # The stdio opening without an engagement is the one before the probe existed: initialize
    # alone, for 2025-06-18. This server, of both generations, answers it in 2025-06-18.
    ("fetch-2026-07-28", False): {
        "decided": None,
        "finished": ("legacy", "2025-06-18"),
        "asked": "2025-06-18",
        "answered": "2025-06-18",
    },
    (LEGACY_HTTP, True): {
        "decided": ("legacy", "2025-11-25"),
        "finished": ("legacy", "2025-11-25"),
        "asked": "2025-11-25",
        "answered": "2025-11-25",
    },
    (LEGACY_HTTP, False): {
        "decided": ("legacy", "2025-06-18"),
        "finished": ("legacy", "2025-06-18"),
        "asked": "2025-06-18",
        "answered": "2025-06-18",
    },
    (MODERN_HTTP, True): {
        "decided": ("modern", "2026-07-28"),
        "finished": ("modern", "2026-07-28"),
        "asked": None,
        "answered": None,
    },
    (MODERN_HTTP, False): {
        "decided": ("modern", "2026-07-28"),
        "finished": ("modern", "2026-07-28"),
        "asked": None,
        "answered": None,
    },
}

CALL = """\
version: 1
name: echo
steps:
  - initialize
  - list: tools/list
  - call:
      tool: echo
      arguments: {text: "one"}
"""
META = "io.modelcontextprotocol/"


def unusable(reason: str) -> None:
    if docker_required():
        pytest.fail(f"MCP_KYMOGRAPH_REQUIRE_DOCKER=1, but {reason}", pytrace=False)
    pytest.skip(reason)


def docker(*args: str, stdin: str | None = None, timeout: float = 120):
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        input=stdin,
        capture_output=True,
        text=True,
        env=helper_env(),
        timeout=timeout,
        check=False,
    )


def image_of(name: str) -> str:
    """The id of the server's image from images.json, once it is known to be here."""
    try:
        ids = json.loads((REAL / "images.json").read_text())
        image = ids[name]
    except (OSError, ValueError, KeyError):
        unusable(f"tests/real_servers/images.json has no id for {name}; build it with: {BUILD}")
    if docker("image", "inspect", image).returncode != 0:
        unusable(f"image {image} of {name} is not here; build it with: {BUILD}")
    return image


def hardened() -> list[str]:
    return [
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--label",
        f"{LABEL}={NONCE}",
    ]


def reference_expectation(name: str) -> dict:
    """What a reference server offers, read from its source (the ``EXPECTED`` it defines)."""
    tree = ast.parse((REAL / name / "server.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "EXPECTED":
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name}/server.py defines no EXPECTED")


class Spy:
    """A pipe on 127.0.0.1 in front of a server's published port that keeps both directions'
    bytes: what the server was really sent (a token) and really answered (a session id), to hold
    the recording against."""

    def __init__(self, port: int) -> None:
        self.target = port
        self.to_server = bytearray()
        self.from_server = bytearray()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        # A timeout, so that the thread notices ``close`` and ends: closing the socket does not
        # wake a thread blocked in its accept(), which would wait there for good.
        self.listener.settimeout(http_server.ACCEPT_SECONDS)
        self._closed = False
        self._acceptor = threading.Thread(target=self.accept, daemon=True)
        self._acceptor.start()

    def accept(self) -> None:
        while not self._closed:
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self.pipe, args=(client,), daemon=True).start()

    def pipe(self, client: socket.socket) -> None:
        upstream = socket.create_connection(("127.0.0.1", self.target))

        def pump(source, sink, kept) -> None:
            with contextlib.suppress(OSError):
                while data := source.recv(65536):
                    kept.extend(data)
                    sink.sendall(data)
                sink.shutdown(socket.SHUT_WR)

        back = threading.Thread(target=pump, args=(upstream, client, self.from_server))
        back.start()
        pump(client, upstream, self.to_server)
        back.join()
        client.close()
        upstream.close()

    def mark(self) -> tuple[int, int]:
        return len(self.to_server), len(self.from_server)

    def close(self) -> None:
        self._closed = True
        self._acceptor.join(5)
        self.listener.close()


def session_ids(heard: bytes) -> set[str]:
    """The ids of the sessions a server gave out in the bytes it sent."""
    found = re.findall(rb"(?i)^mcp-session-id: *(\S+)\r?$", heard, re.M)
    return {value.decode() for value in found}


@dataclass
class Run:
    code: int
    events: list[dict]
    out_dir: Path
    stdout: str
    stderr: str
    sent: bytes = b""  # what the server was sent during the run, and what it answered
    heard: bytes = b""
    token: str | None = None


def wait_until_answering(url: str, attempts: int = 120, pause: float = 0.5) -> bool:
    """Whether something answers at the URL within the attempts. Any HTTP answer, whatever its
    status, means it is listening; each is closed. Only a failure to connect is tried again."""
    for _ in range(attempts):
        try:
            urllib.request.urlopen(url, timeout=2).close()  # noqa: S310
            return True
        except urllib.error.HTTPError as error:
            error.close()
            return True
        except OSError:
            time.sleep(pause)
    return False


class Servers:
    """The servers started so far, the runs made against them, and the ending of both."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.http: dict[str, tuple[str, Spy]] = {}
        self.runs: dict[tuple, Run] = {}
        self.inventories: dict[str, dict] = {}

    def start_http(self, name: str) -> Spy:
        if name not in self.http:
            # The image first, before any Docker call that leaves something behind: with no image
            # this skips or fails with the build command, and no network stands for the next test.
            image = image_of(name)
            # A network of its own and alone in it, with no masquerading, so the container has
            # no way out (``--internal`` would also stop the published port). The host reaches
            # the container by its bridge address as well as by the port; that is accepted, the
            # host being the tester itself.
            network = f"{LABEL}-{NONCE}-{name}"
            made = docker(
                "network", "create", "--driver", "bridge",
                "--opt", "com.docker.network.bridge.enable_ip_masquerade=false",
                "--label", f"{LABEL}={NONCE}", network,
            )  # fmt: skip
            assert made.returncode == 0, made.stderr
            started = docker(
                "run", "--detach", "--rm", *hardened(), "--network", network,
                "--publish", "127.0.0.1::8000", image,
            )  # fmt: skip
            if started.returncode != 0:
                docker("network", "rm", network)
                raise AssertionError(started.stderr)
            container = started.stdout.strip()
            self.http[name] = (container, Spy(self.published(container)))
            self.wait_until_answering(name, container)
        return self.http[name][1]

    def published(self, container: str) -> int:
        shown = docker("port", container, "8000/tcp").stdout.split()
        (port,) = {line.rsplit(":", 1)[1] for line in shown if line.startswith("127.0.0.1:")}
        return int(port)

    def wait_until_answering(self, name: str, container: str) -> None:
        url = f"http://127.0.0.1:{self.http[name][1].port}/mcp"
        if not wait_until_answering(url):
            logs = docker("logs", container)
            raise AssertionError(f"{name} never answered: {logs.stdout}{logs.stderr}")

    def inventory_of(self, name: str) -> dict:
        """A ``fetch`` image's tools, resources and prompts, from the SDK installed in it."""
        if name not in self.inventories:
            script = (REAL / INVENTORY[name]).read_text()
            done = docker(
                "run", "--interactive", "--rm", "--network", "none", *hardened(),
                "--entrypoint", "python", image_of(name), "-", stdin=script,
            )  # fmt: skip
            assert done.returncode == 0, done.stderr
            self.inventories[name] = json.loads(done.stdout)
        return self.inventories[name]

    def drive(self, name: str, *, engaged: bool, call: bool = False, token: bool = False) -> Run:
        if name in HTTP:
            # From this line whatever line of a test calls: one entry per server in the summary.
            warnings.warn(f"{name}: {NO_REFERENCE_SERVER}", StandInServerWarning, stacklevel=1)
        key = (name, engaged, call, token)
        if key in self.runs:
            return self.runs[key]
        where = self.root / f"run-{len(self.runs)}"
        out = where / "runs"
        argv = ["drive", "--out-dir", str(out), "--step-timeout", "30"]
        extra = {}
        secret = None
        if call:
            where.mkdir(parents=True)
            (where / "call.yaml").write_text(CALL)
            argv += ["--script", str(where / "call.yaml")]
            extra["actions"] = {"list": True, "call": True}
        if token:
            secret = made_up("rd")
            os.environ["TEST_TOKEN_REAL"] = secret
            extra["identities"] = [
                {"name": "reader", "role": "read-only user", "token_env": "TEST_TOKEN_REAL"}
            ]
            argv += ["--identity", "reader"]
        if engaged:
            argv += ["--engagement", str(write_engagement(where / "engagement", **extra))]
        spy = marked = None
        if name in HTTP:
            spy = self.start_http(name)
            marked = spy.mark()
            argv += ["--http", f"http://127.0.0.1:{spy.port}/mcp"]
        else:
            argv += ["--", "docker", "run", "--interactive", "--rm", "--network", "none"]
            argv += [*hardened(), image_of(name)]
        out_text, err_text = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out_text), contextlib.redirect_stderr(err_text):
                code = cli.main(argv)
        finally:
            os.environ.pop("TEST_TOKEN_REAL", None)
        sent = heard = b""
        if spy is not None:
            sent, heard = bytes(spy.to_server[marked[0] :]), bytes(spy.from_server[marked[1] :])
        run = Run(
            code, events_of(recording_in(out)), where, out_text.getvalue(), err_text.getvalue(),
            sent, heard, secret,
        )  # fmt: skip
        self.runs[key] = run
        return run

    def close(self) -> None:
        for _, spy in self.http.values():
            spy.close()
        left = docker("ps", "--all", "--quiet", "--filter", f"label={LABEL}={NONCE}")
        for container in left.stdout.split():
            docker("rm", "--force", container)
        # Containers first: a network with one in it cannot be removed.
        nets = docker("network", "ls", "--quiet", "--filter", f"label={LABEL}={NONCE}")
        for network in nets.stdout.split():
            docker("network", "rm", network)


@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    made = Servers(tmp_path_factory.mktemp("real-servers"))
    try:
        yield made
    finally:
        made.close()


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def requests_of(events):
    return [e for e in of(events, "message") if e["direction"] == "client_to_server"]


def method_of_id(events) -> dict:
    return {m["parse"]["id"]: m["parse"]["method"] for m in requests_of(events) if m["parse"]["id"]}


def inventory(events) -> dict:
    """The names in the recording's answers to the three listings."""
    methods = method_of_id(events)
    found: dict = {"tools": [], "resources": [], "prompts": []}
    for message in of(events, "message"):
        if message["direction"] != "server_to_client":
            continue
        data = message["payload"]["data"]
        result = data.get("result") if isinstance(data, dict) else None
        method = methods.get(data.get("id")) if isinstance(data, dict) else None
        if method == "tools/list":
            found["tools"] += [t["name"] for t in result["tools"]]
        elif method == "resources/list":
            found["resources"] += [[str(r["uri"]), r["name"]] for r in result["resources"]]
        elif method == "prompts/list":
            found["prompts"] += [p["name"] for p in result["prompts"]]
    return {kind: sorted(names) for kind, names in found.items()}


def answered_version(events) -> str | None:
    methods = method_of_id(events)
    for message in of(events, "message"):
        data = message["payload"]["data"]
        if (
            message["direction"] == "server_to_client"
            and isinstance(data, dict)
            and methods.get(data.get("id")) == "initialize"
        ):
            return data["result"]["protocolVersion"]
    return None


def asked_version(events) -> str | None:
    for message in requests_of(events):
        if message["parse"]["method"] == "initialize":
            return message["payload"]["data"]["params"]["protocolVersion"]
    return None


# -- 1. the inventory ------------------------------------------------------------------------


@pytest.mark.real_server
@pytest.mark.parametrize("engaged", [True, False], ids=["engaged", "unengaged"])
@pytest.mark.parametrize("name", [*STDIO, *HTTP])
def test_the_recording_holds_every_tool_resource_and_prompt_the_server_has(servers, name, engaged):
    run = servers.drive(name, engaged=engaged)

    expected = servers.inventory_of(name) if name in STDIO else reference_expectation(name)
    wanted = {kind: sorted(expected[kind]) for kind in ("tools", "resources", "prompts")}
    assert run.code == 0, run.stderr
    assert inventory(run.events) == wanted
    assert wanted["tools"] and wanted["prompts"]  # the expectation is not empty


@pytest.mark.real_server
@pytest.mark.parametrize("name", STDIO)
def test_the_protocol_constant_in_the_image_is_the_generations(servers, name):
    inventory_of = servers.inventory_of(name)

    assert inventory_of["latest"] == LATEST[name]
    if name == "fetch-2026-07-28":
        assert inventory_of["modern"] == ["2026-07-28"]


# -- 2. the generation -----------------------------------------------------------------------


@pytest.mark.real_server
@pytest.mark.parametrize("engaged", [True, False], ids=["engaged", "unengaged"])
@pytest.mark.parametrize("name", [*STDIO, *HTTP])
def test_the_generation_decided_and_spoken_is_the_servers(servers, name, engaged):
    held = GENERATION[(name, engaged)]
    run = servers.drive(name, engaged=engaged)

    assert run.code == 0, run.stderr
    decided = of(run.events, "era_decided")
    if held["decided"] is None:
        assert decided == []
    else:
        (found,) = decided
        assert (found["era"], found["version"]) == held["decided"]
        assert found["outcome"] == "proceed"
    (end,) = of(run.events, "script_finished")
    assert (end["era"], end["protocol_version"]) == held["finished"]
    assert asked_version(run.events) == held["asked"]
    assert answered_version(run.events) == held["answered"]


@pytest.mark.real_server
@pytest.mark.parametrize("name", HTTP)
def test_a_test_against_a_reference_server_warns_that_it_is_not_a_real_one(servers, name):
    """The reason these two are not real servers shows in the warnings summary of the run."""
    with pytest.warns(StandInServerWarning, match=re.escape(f"{name}: {NO_REFERENCE_SERVER}")):
        run = servers.drive(name, engaged=True)

    assert run.code == 0, run.stderr


@pytest.mark.real_server
@pytest.mark.parametrize("name", HTTP)
def test_an_http_server_runs_alone_in_a_network_of_its_own_with_no_way_out(servers, name):
    with pytest.warns(StandInServerWarning):
        servers.drive(name, engaged=True)

    container, _ = servers.http[name]
    shown = json.loads(docker("inspect", container).stdout)[0]
    (network,) = shown["NetworkSettings"]["Networks"]
    assert network == f"{LABEL}-{NONCE}-{name}"
    inside = json.loads(docker("network", "inspect", network).stdout)[0]
    assert list(inside["Containers"]) == [shown["Id"]]
    assert inside["Options"]["com.docker.network.bridge.enable_ip_masquerade"] == "false"
    ports = shown["NetworkSettings"]["Ports"]["8000/tcp"]
    assert {p["HostIp"] for p in ports} == {"127.0.0.1"}
    # A connection to a public address from inside gets no answer.
    reach = "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"
    tried = docker("exec", container, "python", "-c", reach)
    assert tried.returncode != 0, "the container reached a public address"
    assert "Traceback" in tried.stderr


# -- 3. the headers of every request ---------------------------------------------------------


def posts_of(events):
    return [e for e in of(events, "http_request") if e["method"] == "POST"]


@pytest.mark.real_server
def test_a_legacy_server_is_sent_the_negotiated_version_and_its_session_on_every_request(servers):
    run = servers.drive(LEGACY_HTTP, engaged=True)

    requests = of(run.events, "http_request")
    probe, initialize, *later = requests
    assert probe["headers"]["mcp-method"] == "server/discover"
    assert probe["headers"]["mcp-protocol-version"] == "2026-07-28"  # the probe, before any answer
    assert "mcp-protocol-version" not in initialize["headers"]
    assert "mcp-session-id" not in initialize["headers"]
    assert later and {r["headers"]["mcp-protocol-version"] for r in later} == {"2025-11-25"}
    # The server gave out a session with its answer to initialize, and it is sent from then on.
    assert {r["headers"]["mcp-session-id"] for r in later} == {PLACEHOLDER}
    assert [r["method"] for r in later][-1] == "DELETE"


@pytest.mark.real_server
def test_the_session_id_the_server_gave_is_in_no_file_of_the_run(servers):
    run = servers.drive(LEGACY_HTTP, engaged=True)

    given = session_ids(run.heard)
    assert given and all(len(value) >= 16 for value in given)
    for path in sorted(run.out_dir.rglob("*")):
        if path.is_file():
            content = path.read_bytes()
            assert not [v for v in given if v.encode() in content], path
    assert not [v for v in given if v in run.stdout + run.stderr]
    answers = [r["headers"] for r in of(run.events, "http_response")]
    responses = [h for h in answers if "mcp-session-id" in h]
    assert responses and {h["mcp-session-id"] for h in responses} == {PLACEHOLDER}


@pytest.mark.real_server
def test_a_legacy_server_asked_without_an_engagement_is_sent_the_version_it_answered_with(servers):
    run = servers.drive(LEGACY_HTTP, engaged=False)

    later = of(run.events, "http_request")[2:]
    assert asked_version(run.events) == answered_version(run.events) == "2025-06-18"
    assert later and {r["headers"]["mcp-protocol-version"] for r in later} == {"2025-06-18"}
    assert {r["headers"]["mcp-session-id"] for r in later} == {PLACEHOLDER}


@pytest.mark.real_server
@pytest.mark.parametrize("engaged", [True, False], ids=["engaged", "unengaged"])
def test_a_modern_server_is_sent_method_and_name_headers_meta_and_no_session(servers, engaged):
    run = servers.drive(MODERN_HTTP, engaged=engaged, call=True)

    posts = posts_of(run.events)
    bodies = [m["payload"]["data"] for m in requests_of(run.events)]
    assert len(posts) == len(bodies) and posts
    for post, body in zip(posts, bodies, strict=True):
        headers = post["headers"]
        assert headers["mcp-protocol-version"] == "2026-07-28"
        assert headers["mcp-method"] == body["method"]
        assert "mcp-session-id" not in headers
        meta = body["params"]["_meta"]
        assert meta[META + "protocolVersion"] == "2026-07-28"
        assert META + "clientCapabilities" in meta
        assert body["method"] != "initialize"
    (call,) = [b for b in bodies if b["method"] == "tools/call"]
    (named,) = [p for p, b in zip(posts, bodies, strict=True) if b is call]
    assert named["headers"]["mcp-name"] == "echo"
    assert [p["headers"]["mcp-name"] for p in posts if "mcp-name" in p["headers"]] == ["echo"]
    assert not [r for r in of(run.events, "http_request") if r["method"] != "POST"]
    assert session_ids(run.heard) == set()


# -- 4. no secret ----------------------------------------------------------------------------


@pytest.mark.real_server
@pytest.mark.parametrize("name", HTTP)
def test_a_token_sent_to_a_real_server_is_in_no_artifact_of_the_run(servers, name):
    run = servers.drive(name, engaged=True, token=True)

    assert run.code == 0, run.stderr
    wire = f"Bearer {run.token}".encode()
    # Sent with every request, so the server was sent it as often as the recording has requests.
    assert run.sent.count(wire) == len(of(run.events, "http_request"))
    seen = [
        (str(path.relative_to(run.out_dir)), path.read_bytes())
        for path in sorted(run.out_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]
    seen += [("stdout", run.stdout.encode()), ("stderr", run.stderr.encode())]
    assert any(label.endswith("events.jsonl") for label, _ in seen)
    found = [
        (label, form)
        for label, content in seen
        for form in forms(run.token)
        if form.encode() in content
    ]
    assert found == []
    assert all(
        e["headers"].get("authorization") in (None, PLACEHOLDER)
        for e in of(run.events, "http_request")
    )


# -- the wait for a server -------------------------------------------------------------------


@pytest.fixture
def local_server():
    """A server on 127.0.0.1 that answers every GET with the status set on it."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(self.server.status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    class Server(http_server.BoundedAccept, http.server.HTTPServer):
        pass

    httpd = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("status", [200, 202, 404, 500])
def test_any_http_answer_means_a_server_is_listening(local_server, status):
    local_server.status = status
    port = local_server.server_address[1]

    assert wait_until_answering(f"http://127.0.0.1:{port}/mcp", attempts=1)


def test_the_local_server_bounds_its_accept(local_server):
    """A blocking accept() that finds no connection after the poll would hold up ``shutdown()``
    in the teardown of the fixture until the next client: for good, when none comes."""
    assert local_server.socket.gettimeout() == http_server.ACCEPT_SECONDS


def test_a_closed_spy_leaves_no_thread_behind():
    """Its accept() would otherwise wait for good on the closed socket: closing does not wake it."""
    before = set(threading.enumerate())
    spy = Spy(1)  # nothing connects, so nothing is piped to the port
    spy.close()
    deadline = time.monotonic() + 5
    while (left := set(threading.enumerate()) - before) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert left == set()


def test_nothing_listening_is_not_an_answer_and_is_tried_again_after_a_pause():
    unused = socket.create_server(("127.0.0.1", 0))
    free = unused.getsockname()[1]
    unused.close()
    started = time.monotonic()

    assert not wait_until_answering(f"http://127.0.0.1:{free}/mcp", attempts=3, pause=0.2)
    assert time.monotonic() - started >= 0.4
