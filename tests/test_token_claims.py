"""The token inspector at the recording (docs/token-inspector.md, docs/engagements.md): a run that
uses a token reads it with ``inspect`` before ``run_started`` is written, and ``auth.token`` holds
what it read — claims through the masker, the identifiers as pseudonyms of the personal salt,
``expired`` by the start of the run. Against the HTTP fixture with identities, through
``cli.main``. No byte of a token, nor any part or piece of it, is in any artifact.
"""

from __future__ import annotations

import base64
import contextlib
import inspect
import io
import json
import os
import re
import secrets
import shutil
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from mcp_kymograph import cli, engagement, recorder
from mcp_kymograph.masking import Masker
from mcp_kymograph.recorder import Recorder
from mcp_kymograph.token_inspector import inspect as inspect_token
from mcp_kymograph.web import views
from mcp_kymograph.web.views import Sources
from test_cli_engagement import events_of, run_directories, write_engagement
from test_personal_data import SALT_ENV, iban, second_file
from test_token_artifacts import every_view

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"
PSEUDONYM = re.compile(r"\*\*\*([A-Z]+)-([0-9a-f]{12})\*\*\*")
GRAPH_WARNING = "is for Microsoft Graph (aud), not for the server under test"
READER = {"name": "reader", "role": "read-only user", "token_env": "TEST_TOKEN_READER"}
ANONYMOUS = {"name": "anonymous", "role": "not signed in", "token": "none"}


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def made_up_jwt(payload: dict) -> tuple[str, list[str]]:
    """A token of three parts put together at run time, and the parts. The header holds a random
    ``kid`` and the signature is random bytes: nothing a scanner has seen, nothing that repeats."""
    header = {"alg": "RS256", "typ": "JWT", "kid": secrets.token_hex(8)}
    parts = [
        b64(json.dumps(header).encode()),
        b64(json.dumps(payload).encode()),
        b64(secrets.token_bytes(48)),
    ]
    return ".".join(parts), parts


def guid() -> str:
    raw = secrets.token_hex(16)
    return f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"


def address(name: str = "rene.beispiel") -> str:
    return f"{name}.{secrets.token_hex(3)}@kunden.example"


def in_an_hour() -> int:
    return int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())


class Entra:
    """The values of an Entra-shaped token, made up once."""

    def __init__(self) -> None:
        self.tenant = guid()
        self.mail = address("Upn.Person")
        self.contact = address("scope.contact")
        self.object = guid()
        self.name = "Person " + secrets.token_hex(4)
        self.exp = in_an_hour()
        self.payload = {
            "aud": "api://" + secrets.token_hex(4),
            "scp": f"Files.Read {self.contact}",
            "roles": ["Reader", "Auditor"],
            "azp": guid(),
            "appid": guid(),
            "exp": self.exp,
            "tid": self.tenant.upper(),
            "iss": f"https://login.microsoftonline.com/{self.tenant}/v2.0",
            "oid": self.object,
            "upn": self.mail,
            "email": self.mail.lower(),
            "name": self.name,
            "wids": ["not read"],
        }


# -- running ------------------------------------------------------------------------------------


def url_of(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"


@pytest.fixture
def serve():
    started = []

    def start(**behaviour):
        server = http_server.serve(**behaviour)
        started.append(server)
        return server

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def drive_with(held: Path, out_dir: Path, url: str, *more: str) -> int:
    return cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(out_dir), "--http", url, *more]
    )


def started_in(out_dir: Path) -> dict:
    (run,) = run_directories(out_dir)
    return next(e for e in events_of(run / "events.jsonl") if e["type"] == "run_started")


@pytest.fixture
def reader(monkeypatch, serve):
    """A server that wants the token in ``TEST_TOKEN_READER``, and a function that sets that
    variable to a token and drives as ``reader``: the exit code, the recorded ``auth`` and
    what stderr said."""
    server = serve(token_envs=("TEST_TOKEN_READER",))

    def run(token: str, directory: Path, *, identities=(READER,)) -> tuple[int, dict, str]:
        monkeypatch.setenv("TEST_TOKEN_READER", token)
        held = write_engagement(directory / "engagement", identities=list(identities))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = drive_with(held, directory / "runs", url_of(server), "--identity", "reader")
        return code, started_in(directory / "runs")["auth"], err.getvalue()

    return run


# -- the claims table, one row each ---------------------------------------------------------------


@pytest.fixture(scope="module")
def entra_run(tmp_path_factory):
    entra = Entra()
    token, _ = made_up_jwt(entra.payload)
    root = tmp_path_factory.mktemp("claims")
    patch = pytest.MonkeyPatch()
    server = http_server.serve(token_envs=("TEST_TOKEN_READER",))
    try:
        patch.setenv("TEST_TOKEN_READER", token)
        held = write_engagement(root / "engagement", identities=[READER])
        assert drive_with(held, root / "runs", url_of(server), "--identity", "reader") == 0
        (run,) = run_directories(root / "runs")
        yield entra, started_in(root / "runs")["auth"], (run / "events.jsonl").read_text()
    finally:
        server.shutdown()
        server.server_close()
        patch.undo()


def test_the_recording_names_the_token_and_what_was_read_of_it(entra_run):
    _, auth, _ = entra_run

    assert auth["identity"] == "reader" and auth["token_used"] is True
    token = auth["token"]
    assert token["readable"] is True and token["reason"] is None
    assert token["unexpected"] == [] and token["warnings"] == []
    assert token["expired"] is False


@pytest.mark.parametrize("claim", ["aud", "roles", "azp", "appid", "exp"])
def test_a_readable_claim_stands_as_it_is_in_the_token(entra_run, claim):
    entra, auth, _ = entra_run

    assert auth["token"]["claims"][claim] == entra.payload[claim]


def test_an_address_in_scp_is_a_pseudonym_and_the_rest_of_it_stays(entra_run):
    entra, auth, raw = entra_run

    scp = auth["token"]["claims"]["scp"]
    assert re.fullmatch(r"Files\.Read \*\*\*EMAIL-[0-9a-f]{12}\*\*\*", scp)
    assert entra.contact not in raw


@pytest.mark.parametrize(
    ("claim", "kind"),
    [("tid", "TENANT"), ("oid", "OBJECT"), ("upn", "EMAIL"), ("email", "EMAIL"), ("name", "NAME")],
)
def test_an_identifier_is_a_pseudonym_of_its_kind(entra_run, claim, kind):
    entra, auth, raw = entra_run

    found = PSEUDONYM.fullmatch(auth["token"]["pseudonyms"][claim])
    assert found and found.group(1) == kind
    assert str(entra.payload[claim]).lower() not in raw.lower()


def test_the_issuer_keeps_its_url_and_only_the_tenant_is_a_pseudonym(entra_run):
    entra, auth, _ = entra_run

    issuer = auth["token"]["pseudonyms"]["iss"]
    assert re.fullmatch(
        r"https://login\.microsoftonline\.com/\*\*\*TENANT-[0-9a-f]{12}\*\*\*/v2\.0", issuer
    )
    assert entra.tenant not in issuer


def test_the_same_tenant_in_iss_and_tid_is_one_pseudonym(entra_run):
    _, auth, _ = entra_run
    pseudonyms = auth["token"]["pseudonyms"]

    assert PSEUDONYM.search(pseudonyms["iss"]).group() == pseudonyms["tid"]


def test_the_upn_and_the_email_of_one_address_are_one_pseudonym(entra_run):
    _, auth, _ = entra_run
    pseudonyms = auth["token"]["pseudonyms"]

    assert pseudonyms["upn"] == pseudonyms["email"]


def test_other_claims_are_counted_and_nothing_of_them_is_recorded(entra_run):
    _, auth, raw = entra_run

    assert auth["token"]["other_claims"] == 1
    assert "wids" not in raw and "not read" not in raw


def test_the_view_of_a_token_holds_exactly_the_documented_keys(entra_run):
    _, auth, _ = entra_run

    assert set(auth["token"]) == {
        "claims", "other_claims", "pseudonyms", "readable", "reason", "unexpected", "warnings",
        "expired",
    }  # fmt: skip


# -- the pseudonyms and the masker ------------------------------------------------------------


def test_a_upn_that_is_an_address_in_the_traffic_gives_the_traffic_s_pseudonym():
    mail = address("Upn.Person")
    token, _ = made_up_jwt({"upn": mail})
    masker = Masker(personal_salt=b"s" * 32)

    shown = inspect_token(token, masker.personal_pseudonym)
    in_traffic = masker.mask_text(f"contact {mail.upper()} please")[0]

    assert in_traffic == f"contact {shown.pseudonyms['upn']} please"


def test_the_masker_gives_a_pseudonym_for_the_inspector_s_kinds_and_for_no_other():
    masker = Masker(personal_salt=b"s" * 32)

    for kind in ("tenant", "issuer", "object", "email", "account", "name", "tel", "known"):
        assert re.fullmatch(
            rf"\*\*\*{kind.upper()}-[0-9a-f]{{12}}\*\*\*", masker.personal_pseudonym(kind, "x")
        )
    for kind in ("password", "TENANT", ""):
        with pytest.raises(ValueError, match="no pseudonym"):
            masker.personal_pseudonym(kind, "x")


# -- expiry -------------------------------------------------------------------------------------


@pytest.mark.parametrize(("offset", "expired"), [(-1, True), (1, False)])
def test_expired_is_reckoned_by_the_time_run_started_writes(
    tmp_path, monkeypatch, reader, offset, expired
):
    """The clock the recorder takes ``wall_clock_utc`` from is replaced; ``exp`` lies a second
    before or after it. The record cannot contradict itself, whatever the real time is."""
    start = datetime(2031, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(recorder, "utc_now", lambda: start)
    token, _ = made_up_jwt({"exp": int(start.timestamp()) + offset, "aud": "api://x"})

    code, auth, _ = reader(token, tmp_path)

    assert code == 0
    assert started_in(tmp_path / "runs")["wall_clock_utc"].startswith("2031-05-17T12:00:00")
    assert auth["token"]["expired"] is expired


@pytest.mark.parametrize(("microsecond", "expired"), [(700, False), (1000, True)])
def test_expired_is_reckoned_in_the_milliseconds_run_started_writes(
    tmp_path, monkeypatch, reader, microsecond, expired
):
    """``wall_clock_utc`` is written in whole milliseconds; ``expired`` is reckoned by that
    value and not by the microseconds the clock gave."""
    start = datetime(2031, 5, 17, 12, 0, 0, microsecond, tzinfo=timezone.utc)
    monkeypatch.setattr(recorder, "utc_now", lambda: start)
    token, _ = made_up_jwt({"exp": int(start.timestamp()), "aud": "api://x"})

    code, auth, _ = reader(token, tmp_path)

    assert code == 0
    assert started_in(tmp_path / "runs")["wall_clock_utc"].startswith("2031-05-17T12:00:00.00")
    assert auth["token"]["expired"] is expired


def test_a_token_without_exp_is_neither_expired_nor_not(tmp_path, reader):
    code, auth, _ = reader(made_up_jwt({"aud": "api://x"})[0], tmp_path)

    assert code == 0 and auth["token"]["expired"] is None


def test_a_token_that_has_expired_is_recorded_so_and_still_sent(tmp_path, reader):
    token, _ = made_up_jwt({"exp": 1_000_000_000, "aud": "api://x"})

    code, auth, _ = reader(token, tmp_path)

    assert code == 0
    assert auth["token"]["expired"] is True


# -- not readable -------------------------------------------------------------------------------


def test_a_token_that_cannot_be_read_is_recorded_so_and_the_run_goes_on(tmp_path, reader):
    code, auth, err = reader("opaque" + secrets.token_hex(12), tmp_path)

    assert code == 0
    assert auth["token_used"] is True
    assert auth["token"]["readable"] is False and auth["token"]["reason"] == "not_jwt"
    assert auth["token"]["claims"] == {} and auth["token"]["expired"] is None
    assert "warning" not in err


def test_a_token_with_a_header_that_is_no_json_says_why(tmp_path, reader):
    token = f"{b64(b'not json')}.{b64(b'{}')}.{b64(secrets.token_bytes(8))}"

    code, auth, err = reader(token, tmp_path)

    assert code == 0 and auth["token"]["reason"] == "bad_json" and "warning" not in err


# -- no token -----------------------------------------------------------------------------------


def test_an_identity_without_a_token_has_token_null(tmp_path, serve):
    server = serve()
    held = write_engagement(tmp_path / "engagement", identities=[READER, ANONYMOUS])

    assert drive_with(held, tmp_path / "runs", url_of(server), "--identity", "anonymous") == 0

    auth = started_in(tmp_path / "runs")["auth"]
    assert auth["token_used"] is False and auth["token"] is None


# -- the graph warning ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "audience", ["https://graph.microsoft.com", "00000003-0000-0000-c000-000000000000"]
)
def test_a_token_for_graph_is_said_once_by_identity_and_names_no_value(tmp_path, reader, audience):
    entra = Entra()
    token, _ = made_up_jwt({**entra.payload, "aud": audience})

    code, auth, err = reader(token, tmp_path)

    assert code == 0 and auth["token"]["warnings"] == ["aud_is_graph"]
    lines = [line for line in err.splitlines() if "Graph" in line]
    assert lines == [f"kymograph: warning: the token of identity reader {GRAPH_WARNING}"]
    for value in (audience, entra.tenant, entra.mail, entra.contact, entra.name, entra.object):
        assert value not in err


def test_a_token_without_an_identity_is_the_token(tmp_path, monkeypatch, serve):
    server = serve(token_envs=("TEST_TOKEN_READER",))
    monkeypatch.setenv("TEST_TOKEN_READER", made_up_jwt({"aud": "https://graph.microsoft.com"})[0])
    err = io.StringIO()

    with contextlib.redirect_stderr(err):
        code = cli.main(
            ["drive", "-q", "--http", url_of(server), "--token-env", "TEST_TOKEN_READER",
             "--out-dir", str(tmp_path / "runs")]
        )  # fmt: skip

    assert code == 0
    assert err.getvalue().count(f"warning: the token {GRAPH_WARNING}") == 1


def test_a_refused_run_draws_no_graph_warning(tmp_path, monkeypatch, serve):
    """The destination is refused after the token is read: the run never starts, so nothing is
    said of its token."""
    server = serve(token_envs=("TEST_TOKEN_READER",))
    monkeypatch.setenv("TEST_TOKEN_READER", made_up_jwt({"aud": "https://graph.microsoft.com"})[0])
    not_a_directory = tmp_path / "file"
    not_a_directory.write_text("")
    err = io.StringIO()

    with contextlib.redirect_stderr(err):
        code = cli.main(
            ["drive", "-q", "--http", url_of(server), "--token-env", "TEST_TOKEN_READER",
             "--out-dir", str(not_a_directory)]
        )  # fmt: skip

    assert code == 2
    assert "Nothing was started" in err.getvalue() and "Graph" not in err.getvalue()


def test_a_token_for_the_server_draws_no_warning(tmp_path, reader):
    code, auth, err = reader(made_up_jwt({"aud": "api://" + secrets.token_hex(4)})[0], tmp_path)

    assert code == 0 and auth["token"]["warnings"] == []
    assert "Graph" not in err


# -- the pseudonyms across runs -------------------------------------------------------------------


@pytest.fixture
def salt(monkeypatch) -> str:
    value = "salt-" + secrets.token_hex(16)
    monkeypatch.setenv(SALT_ENV, value)
    return value


def pseudonyms_of(auth: dict) -> dict:
    return auth["token"]["pseudonyms"]


def test_under_an_engagement_of_version_two_the_pseudonyms_are_the_same_in_two_runs(
    tmp_path, monkeypatch, serve, salt
):
    token, _ = made_up_jwt(Entra().payload)
    monkeypatch.setenv("TEST_TOKEN_READER", token)
    server = serve(token_envs=("TEST_TOKEN_READER",))
    held = second_file(tmp_path / "engagement", identities=[READER])

    seen = []
    for runs in ("a", "b"):
        assert drive_with(held, tmp_path / runs, url_of(server), "--identity", "reader") == 0
        started = started_in(tmp_path / runs)
        assert started["pseudonyms"] == "per_engagement"
        seen.append(pseudonyms_of(started["auth"]))

    assert seen[0] == seen[1] and seen[0]
    monkeypatch.setenv(SALT_ENV, "other-" + secrets.token_hex(16))
    assert drive_with(held, tmp_path / "c", url_of(server), "--identity", "reader") == 0
    assert pseudonyms_of(started_in(tmp_path / "c")["auth"]) != seen[0]


def test_without_a_file_the_pseudonyms_differ_from_run_to_run(tmp_path, monkeypatch, serve):
    monkeypatch.setenv("TEST_TOKEN_READER", made_up_jwt(Entra().payload)[0])
    server = serve(token_envs=("TEST_TOKEN_READER",))

    seen = []
    for runs in ("a", "b"):
        out_dir = tmp_path / runs
        argv = ["drive", "-q", "--http", url_of(server), "--token-env", "TEST_TOKEN_READER"]
        assert cli.main([*argv, "--out-dir", str(out_dir)]) == 0
        started = started_in(out_dir)
        assert started["pseudonyms"] == "per_run"
        seen.append(pseudonyms_of(started["auth"]))

    assert seen[0].keys() == seen[1].keys()
    assert all(seen[0][claim] != seen[1][claim] for claim in seen[0])


def test_under_an_engagement_of_version_one_the_pseudonyms_differ_from_run_to_run(
    tmp_path, monkeypatch, serve
):
    monkeypatch.setenv("TEST_TOKEN_READER", made_up_jwt(Entra().payload)[0])
    server = serve(token_envs=("TEST_TOKEN_READER",))
    held = write_engagement(tmp_path / "engagement", identities=[READER])

    seen = []
    for runs in ("a", "b"):
        assert drive_with(held, tmp_path / runs, url_of(server), "--identity", "reader") == 0
        started = started_in(tmp_path / runs)
        assert started["pseudonyms"] == "per_run"
        seen.append(pseudonyms_of(started["auth"]))

    assert seen[0].keys() == seen[1].keys() and seen[0]
    assert all(seen[0][claim] != seen[1][claim] for claim in seen[0])


# -- passive runs ---------------------------------------------------------------------------------


def test_a_run_without_token_or_identity_has_no_auth_at_all(tmp_path, serve):
    server = serve()

    assert cli.main(["drive", "-q", "--http", url_of(server), "--out-dir", str(tmp_path)]) == 0

    assert started_in(tmp_path)["auth"] is None


# -- no byte of the token, in any artifact --------------------------------------------------------


def pieces(parts: list[str], token: str) -> list[str]:
    """The token, each part, and every run of 16 characters inside any of them: the shortest
    piece of Base64 that still tells what it came from."""
    found = {token, *parts}
    for part in parts:
        found |= {part[start : start + 16] for start in range(len(part) - 15)}
    return sorted(found)


class World:
    """Runs with two JWT identities against reflecting servers, a refusal, and the store, the
    report and the bundle made from them."""

    def __init__(self, root: Path, monkey: pytest.MonkeyPatch) -> None:
        self.root = root
        self.captured: list[tuple[str, str, str]] = []
        entra = Entra()
        self.secrets: dict[str, tuple[str, list[str]]] = {
            "reader": made_up_jwt(entra.payload),
            "graph": made_up_jwt({**entra.payload, "aud": "https://graph.microsoft.com"}),
        }
        monkey.setenv("TEST_TOKEN_READER", self.secrets["reader"][0])
        monkey.setenv("TEST_TOKEN_GRAPH", self.secrets["graph"][0])
        self.servers = [
            http_server.serve(reflect=("Authorization",), variant="poison", token_envs=(env,))
            for env in ("TEST_TOKEN_READER", "TEST_TOKEN_GRAPH")
        ]
        self.manifest = root / "corpus" / "manifest.json"
        self.manifest.parent.mkdir()
        self.manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": [
                        {
                            "name": name,
                            "provenance": "poison",
                            "source": {"endpoint": url_of(server)},
                            "launch": {"transport": "streamable-http"},
                            "scenarios": [os.path.relpath(ALL_SIGNALS, self.manifest.parent)],
                        }
                        for name, server in zip(
                            ("reader-mcp", "graph-mcp"), self.servers, strict=True
                        )
                    ],
                }
            )
        )
        self.held = write_engagement(
            root / "engagement",
            identities=[
                READER,
                {"name": "graph", "role": "wrong audience", "token_env": "TEST_TOKEN_GRAPH"},
            ],
        )
        self.runs = root / "runs"
        self.recordings = {}
        for run, entry in {"reader": "reader-mcp", "graph": "graph-mcp"}.items():
            code = self.call(
                "drive", "--manifest", self.manifest, "--entry", entry, "--engagement", self.held,
                "--out-dir", self.runs / run, "--identity", run,
            )  # fmt: skip
            assert code in (0, 3, 4), (run, code, self.captured[-1][2])
            (self.recordings[run],) = (self.runs / run).glob("*/events.jsonl")
        # Refused: a flag beside an identity.
        assert self.call(
            "drive", "--manifest", self.manifest, "--entry", "reader-mcp", "--engagement",
            self.held, "--out-dir", self.runs / "refused", "--identity", "reader",
            "--token-env", "TEST_TOKEN_READER",
        ) == 2  # fmt: skip
        self.store, self.bundle, self.report = root / "store.sqlite", root / "bundle", root / "r.md"
        self.attestation = root / "attestation.md"
        for step in (
            ("store", "ingest", "--store", self.store, "--engagement", self.held,
             *self.recordings.values()),
            ("report", "--engagement", self.held, "--store", self.store, "--runs", self.runs,
             "--manifest", self.manifest, "--out-dir", self.runs, "--out", self.report),
            ("evidence", "pack", "--engagement", self.held, "--store", self.store,
             "--runs", self.runs, "--manifest", self.manifest, "--report", self.report,
             "--out", self.bundle),
            ("engagement", "attest", "--store", self.store, "--engagement", self.held,
             "--runs", self.runs, "--bundle", self.bundle, "--out", self.attestation),
        ):  # fmt: skip
            code = self.call(*step)
            assert code in (0, 3, 4), (step[:2], code, self.captured[-1][2])

    def call(self, *argv) -> int:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(part) for part in argv])
        self.captured.append((" ".join(str(p) for p in argv[:2]), out.getvalue(), err.getvalue()))
        return code

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()

    def artifacts(self) -> list[tuple[str, bytes]]:
        found = [
            (str(path.relative_to(self.root)), path.read_bytes())
            for path in sorted(self.root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        for label, out, err in self.captured:
            found += [(f"stdout of {label}", out.encode()), (f"stderr of {label}", err.encode())]
        return found


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    made = World(tmp_path_factory.mktemp("token-claims"), patch)
    try:
        yield made
    finally:
        made.close()
        patch.undo()


def test_the_runs_of_the_world_read_their_tokens_and_the_servers_saw_them(world):
    for name, server in zip(("reader", "graph"), world.servers, strict=True):
        token, _ = world.secrets[name]
        assert {s["authorization"] for s in server.behaviour.received} == {f"Bearer {token}"}
        started = next(e for e in events_of(world.recordings[name]) if e["type"] == "run_started")
        assert started["auth"]["token"]["readable"] is True
    graph = next(e for e in events_of(world.recordings["graph"]) if e["type"] == "run_started")
    assert graph["auth"]["token"]["warnings"] == ["aud_is_graph"]
    assert "Graph" in world.captured[1][2]
    assert "Graph" not in world.captured[0][2]


def test_every_kind_of_artifact_was_made(world):
    names = [label for label, _ in world.artifacts()]

    assert sum(n.startswith("runs/") and n.endswith("events.jsonl") for n in names) == 2
    assert any(label.endswith("refusals.jsonl") for label in names)
    assert "store.sqlite" in names and "r.md" in names and "attestation.md" in names
    assert any(label.startswith("bundle/") for label in names)
    assert any(label.startswith("stdout of") and content for label, content in world.artifacts())
    refused = engagement.read_refusals(world.runs / "refused" / engagement.REFUSALS_FILE)
    assert [r.reason for r in refused] == ["token_source_differs"]


def test_no_artifact_holds_a_byte_of_a_token_a_part_of_it_or_a_piece_of_base64(world):
    artifacts = world.artifacts()

    holding = [
        (label, name, piece)
        for name, (token, parts) in world.secrets.items()
        for piece in pieces(parts, token)
        for label, content in artifacts
        if piece.encode() in content
    ]
    assert holding == []


def test_the_pieces_are_the_token_its_parts_and_the_signature_and_the_artifacts_hold_claims(world):
    token, parts = world.secrets["reader"]

    assert token in pieces(parts, token) and parts[2] in pieces(parts, token)
    assert len(pieces(parts, token)) > 3 * 16
    recorded = world.recordings["reader"].read_text()
    assert '"readable": true' in recorded or '"readable":true' in recorded


def test_every_view_of_the_web_interface_is_free_of_every_piece_of_a_token(world):
    sources = Sources(
        store=world.store,
        runs=world.runs,
        manifests=(world.manifest,),
        scenarios=(ALL_SIGNALS,),
        bundles=(world.bundle,),
        attestations=(world.attestation,),
    )
    shown = every_view(sources, world)

    names = {name for name, _ in shown}
    public = {
        name
        for name, function in inspect.getmembers(views, inspect.isfunction)
        if function.__module__ == views.__name__
        and not name.startswith("_")
        and "sources" in inspect.signature(function).parameters
    }
    assert public <= names, f"views this test does not call: {sorted(public - names)}"
    assert len(shown) > 40
    holding = [
        (name, piece)
        for secret, parts in world.secrets.values()
        for piece in pieces(parts, secret)
        for name, text in shown
        if piece in text
    ]
    assert holding == []


# -- a value the limit of 256 characters cuts through -------------------------------------------


KEY_ENV = "TEST_LITERAL_KEY"
KEY_HEADER = "Ocp-Apim-Subscription-Key"
KINDS = ("address", "literal", "known")
CASES = [(kind, claim) for kind in KINDS for claim in ("scp", "roles", "aud")]


def straddling(value: str) -> str:
    """Text in which the 256th character lies in the middle of ``value``."""
    padding = 255 - len(value) // 2
    return "a" * padding + " " + value


def heads_of(value: str) -> list[str]:
    """What a cut would leave: the first 8 characters, and for an address the local part with
    its ``@`` and the start of the domain."""
    found = [value[:8]]
    if "@" in value:
        local, _, domain = value.partition("@")
        found += [local + "@", local + "@" + domain[:2]]
    return found


def made_up_value(kind: str) -> str:
    if kind == "address":
        return f"{secrets.token_hex(6)}.{secrets.token_hex(4)}@kunden.example"
    if kind == "literal":
        return f"lit{secrets.token_hex(8)}+{secrets.token_hex(4)}/{secrets.token_hex(2)}"
    return "KV-" + secrets.token_hex(12)


def keyed_identity() -> dict:
    return {**READER, "headers": {KEY_HEADER: {"env": KEY_ENV}}}


def artifacts_under(root: Path, captured: str) -> list[tuple[str, bytes]]:
    found = [
        (str(path.relative_to(root)), path.read_bytes())
        for path in sorted((root / "runs").rglob("*"))
        if path.is_file()
    ]
    return [*found, ("stdout and stderr", captured.encode())]


class Chain:
    """Runs against one reflecting server by manifest, and the store, the report, the bundle and
    the attestation made from them: the artifacts a token must not reach."""

    call = World.call
    close = World.close
    artifacts = World.artifacts

    def __init__(self, root: Path, server, held: Path) -> None:
        self.root = root
        self.captured: list[tuple[str, str, str]] = []
        self.servers = [server]
        self.held = held
        self.manifest = root / "corpus" / "manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": [
                        {
                            "name": "chain-mcp",
                            "provenance": "poison",
                            "source": {"endpoint": url_of(server)},
                            "launch": {"transport": "streamable-http"},
                            "scenarios": [os.path.relpath(ALL_SIGNALS, self.manifest.parent)],
                        }
                    ],
                }
            )
        )
        self.runs = root / "runs"
        self.recordings: dict[str, Path] = {}
        self.unfiled: dict[str, Path] = {}

    def drive(self, name: str, *more, unfiled: bool = False) -> Path:
        """One run; ``unfiled`` keeps it from the store, which refuses a run made under no
        engagement. It stays in ``runs``, where the report, the bundle and the attestation look."""
        out_dir = self.runs / name
        code = self.call(
            "drive", "--manifest", self.manifest, "--entry", "chain-mcp",
            "--out-dir", out_dir, *more,
        )  # fmt: skip
        assert code in (0, 3, 4), (name, code, self.captured[-1][2])
        (recording,) = out_dir.glob("*/events.jsonl")
        (self.unfiled if unfiled else self.recordings)[name] = recording
        return recording

    def publish(self) -> None:
        self.store, self.bundle, self.report = (
            self.root / "store.sqlite",
            self.root / "bundle",
            self.root / "r.md",
        )
        self.attestation = self.root / "attestation.md"
        for step in (
            ("store", "ingest", "--store", self.store, "--engagement", self.held,
             *self.recordings.values()),
            ("report", "--engagement", self.held, "--store", self.store, "--runs", self.runs,
             "--manifest", self.manifest, "--out-dir", self.runs, "--out", self.report),
            ("evidence", "pack", "--engagement", self.held, "--store", self.store,
             "--runs", self.runs, "--manifest", self.manifest, "--report", self.report,
             "--out", self.bundle),
            ("engagement", "attest", "--store", self.store, "--engagement", self.held,
             "--runs", self.runs, "--bundle", self.bundle, "--out", self.attestation),
        ):  # fmt: skip
            code = self.call(*step)
            assert code in (0, 3, 4), (step[:2], code, self.captured[-1][2])
        # The web views count the runs of ``runs`` against the store's; the unfiled ones are
        # shown from a directory of their own.
        for name, recording in self.unfiled.items():
            moved = self.root / "unfiled" / name
            shutil.move(self.runs / name, moved)
            self.unfiled[name] = moved / recording.relative_to(self.runs / name)

    def views(self) -> list[tuple[str, str]]:
        """Every view of the web interface, as the JSON it would send; those of the unfiled runs
        too: the list of runs, a run, its messages and each of them, which the HTTP tab reads."""
        sources = Sources(
            store=self.store,
            runs=self.runs,
            manifests=(self.manifest,),
            scenarios=(ALL_SIGNALS,),
            bundles=(self.bundle,),
            attestations=(self.attestation,),
        )
        shown = every_view(sources, self)
        if self.unfiled:
            shown += self.unfiled_views(replace(sources, runs=self.root / "unfiled"))
        return shown

    def unfiled_views(self, sources: Sources) -> list[tuple[str, str]]:
        shown: list[tuple[str, str]] = []

        def call(name, *arguments):
            try:
                body = getattr(views, name)(sources, *arguments)
            except views.ViewError as refused:
                shown.append((name, refused.words))
                return None
            shown.append((name, json.dumps(body, default=str)))
            return body

        refs = [row["ref"] for row in call("runs")["data"]]
        assert len(refs) == len(self.unfiled)
        for ref in refs:
            assert "http" in call("run", ref)["data"]["tabs"]
            call("messages", ref, 0, 500)
            for seq in range(1, 60):
                call("message", ref, seq)
        return shown

    def made_everything(self) -> bool:
        names = [label for label, _ in self.artifacts()]
        return (
            any(n.startswith("runs/") and n.endswith("events.jsonl") for n in names)
            and "store.sqlite" in names
            and "r.md" in names
            and "attestation.md" in names
            and any(label.startswith("bundle/") for label in names)
            and any(
                label.startswith("stdout of") and content for label, content in self.artifacts()
            )
            and len(self.views()) > 40
        )


class Straddle(Chain):
    """One run for each of :data:`CASES`, each with a value across the limit in one claim."""

    def __init__(self, root: Path, monkey: pytest.MonkeyPatch) -> None:
        self.values = {kind: made_up_value(kind) for kind in KINDS}
        monkey.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
        monkey.setenv(KEY_ENV, self.values["literal"])
        server = http_server.serve(
            reflect=("Authorization",),
            variant="poison",
            token_envs=("TEST_TOKEN_READER",),
            header_envs={KEY_HEADER: KEY_ENV},
        )
        held = second_file(
            root / "engagement",
            identities=[keyed_identity()],
            known_values=[self.values["known"]],
        )
        super().__init__(root, server, held)
        for kind, claim in CASES:
            text = straddling(self.values[kind])
            payload = {"roles": ["Reader", text]} if claim == "roles" else {claim: text}
            monkey.setenv("TEST_TOKEN_READER", made_up_jwt({**payload, "exp": in_an_hour()})[0])
            self.drive(f"{kind}-{claim}", "--engagement", self.held, "--identity", "reader")
        self.publish()


@pytest.fixture(scope="module")
def straddle(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    made = Straddle(tmp_path_factory.mktemp("straddle"), patch)
    try:
        yield made
    finally:
        made.close()
        patch.undo()


@pytest.mark.parametrize(("kind", "claim"), CASES)
def test_a_value_across_the_limit_is_masked_before_it_is_clipped(straddle, kind, claim):
    started = next(
        e for e in events_of(straddle.recordings[f"{kind}-{claim}"]) if e["type"] == "run_started"
    )
    token = started["auth"]["token"]

    shown = token["claims"][claim][1] if claim == "roles" else token["claims"][claim]
    assert len(shown) <= 256
    assert "truncated" in token["warnings"]


@pytest.mark.parametrize("kind", KINDS)
def test_no_artifact_holds_the_head_of_a_value_the_limit_cut_through(straddle, kind):
    # The engagement file is the input that names the known value; it is not an artifact.
    artifacts = [(n, c) for n, c in straddle.artifacts() if not n.startswith("engagement/")]

    holding = [
        (label, head)
        for head in heads_of(straddle.values[kind])
        for label, content in artifacts
        if head.encode() in content or quote(head, safe="").encode() in content
    ]
    assert holding == []


def test_every_artifact_of_the_straddling_runs_was_made(straddle):
    names = [label for label, _ in straddle.artifacts()]

    assert sum(n.startswith("runs/") and n.endswith("events.jsonl") for n in names) == len(CASES)
    assert "store.sqlite" in names and "r.md" in names and "attestation.md" in names
    assert any(label.startswith("bundle/") for label in names)
    assert any(label.startswith("stdout of") and content for label, content in straddle.artifacts())


def test_no_view_of_the_web_interface_holds_the_head_of_a_value_the_limit_cut_through(straddle):
    sources = Sources(
        store=straddle.store,
        runs=straddle.runs,
        manifests=(straddle.manifest,),
        scenarios=(ALL_SIGNALS,),
        bundles=(straddle.bundle,),
        attestations=(straddle.attestation,),
    )
    shown = every_view(sources, straddle)

    assert len(shown) > 40
    holding = [
        (name, head)
        for value in straddle.values.values()
        for head in heads_of(value)
        for name, text in shown
        if head in text or quote(head, safe="") in text
    ]
    assert holding == []


# -- a token from a file --------------------------------------------------------------------------


def reflecting(serve, monkeypatch, **behaviour):
    return serve(
        reflect=("Authorization",),
        variant="poison",
        token_envs=("TEST_TOKEN_READER",),
        **behaviour,
    )


def holds_nothing_of(chain: Chain, needles: list[str]) -> list[tuple[str, str]]:
    """Which needle is in which artifact: the files, stdout and stderr, every view of the web
    interface."""
    artifacts = chain.artifacts()
    views = chain.views()
    return [
        *(
            (label, needle)
            for needle in needles
            for label, content in artifacts
            if needle.encode() in content
        ),
        *((name, needle) for needle in needles for name, text in views if needle in text),
    ]


@pytest.mark.parametrize("how", ["identity", "flag"])
def test_a_token_from_a_file_is_read_like_one_from_the_environment(
    tmp_path, monkeypatch, serve, capsys, how
):
    token, parts = made_up_jwt(Entra().payload)
    server = reflecting(serve, monkeypatch)
    monkeypatch.setenv("TEST_TOKEN_READER", token)
    (tmp_path / "token").write_text(token + "\n")
    reference = tmp_path / "reference"
    held_env = write_engagement(reference / "engagement", identities=[READER])
    assert drive_with(held_env, reference / "runs", url_of(server), "--identity", "reader") == 0
    capsys.readouterr()

    filed = {"name": "filed", "role": "from a file", "token_file": "token"}
    (tmp_path / "engagement").mkdir()
    (tmp_path / "engagement" / "token").write_text(token + "\n")
    held = write_engagement(tmp_path / "engagement", identities=[filed, READER])
    chain = Chain(tmp_path / "chain", server, held)
    if how == "identity":
        recording = chain.drive("filed", "--engagement", held, "--identity", "filed")
    else:  # a token flag is for a run without an engagement file, which the store refuses
        recording = chain.drive("filed", "--token-file", tmp_path / "token", unfiled=True)
        chain.drive("under", "--engagement", held, "--identity", "reader")
    chain.publish()
    if how == "flag":
        # The report and the bundle ran over ``runs`` with it in; they take their runs from the
        # store and neither read it nor refuse it. The store refuses it, naming the engagement.
        (packed,) = [err for label, _, err in chain.captured if label.startswith("evidence pack")]
        assert "1 recording," in packed
        recording = chain.unfiled["filed"]
        assert (
            chain.call("store", "ingest", "--store", chain.store, "--engagement", held, recording)
            == 2
        )
        assert "made under no engagement" in chain.captured[-1][2]

    (auth,) = [e for e in events_of(recording) if e["type"] == "run_started"]
    auth = auth["auth"]
    assert auth["source"] == "file" and auth["token_used"] is True and "env_name" not in auth
    expected = started_in(reference / "runs")["auth"]["token"]
    same = {name: PSEUDONYM.sub(r"***\1***", str(v)) for name, v in auth["token"]["claims"].items()}
    assert same == {n: PSEUDONYM.sub(r"***\1***", str(v)) for n, v in expected["claims"].items()}
    assert same and "***EMAIL***" in same["scp"]  # the pseudonyms differ from run to run
    assert auth["token"]["readable"] is True and auth["token"]["expired"] is False
    assert chain.made_everything()
    assert holds_nothing_of(chain, pieces(parts, token)) == []


# -- a literal and a known value in a short claim -------------------------------------------------


def test_a_literal_in_azp_and_a_known_value_in_appid_are_masked_and_nowhere_else(
    tmp_path, monkeypatch, serve, salt
):
    literal, known = made_up_value("literal"), made_up_value("known")
    monkeypatch.setenv(KEY_ENV, literal)
    token, _ = made_up_jwt({"azp": "app-" + literal, "appid": "id-" + known})
    monkeypatch.setenv("TEST_TOKEN_READER", token)
    server = reflecting(serve, monkeypatch, header_envs={KEY_HEADER: KEY_ENV})
    held = second_file(tmp_path / "engagement", identities=[keyed_identity()], known_values=[known])
    chain = Chain(tmp_path / "chain", server, held)

    chain.drive("short", "--engagement", held, "--identity", "reader")
    chain.publish()

    (started,) = [e for e in events_of(chain.recordings["short"]) if e["type"] == "run_started"]
    claims = started["auth"]["token"]["claims"]
    assert claims["azp"] == "app-***REDACTED***"
    assert re.fullmatch(r"id-\*\*\*KNOWN-[0-9a-f]{12}\*\*\*", claims["appid"])
    assert chain.made_everything()
    # The engagement file names the known value; it is the input, not an artifact.
    artifacts = [(n, c) for n, c in chain.artifacts() if not n.startswith("engagement/")]
    needles = [literal, known, quote(literal, safe="")]
    assert [
        (label, value)
        for value in needles
        for label, content in artifacts
        if value.encode() in content
    ] == []
    assert [(n, v) for v in needles for n, text in chain.views() if v in text] == []


# -- the recorder masks nothing a second time -----------------------------------------------------


def test_a_value_that_is_no_iban_in_full_length_is_no_pseudonym_after_the_cut():
    masker = Masker(handle_salt=b"a fixed salt for the handles" + b"\0" * 4)
    number = iban("NO")
    text = "a" * 240 + " " + number + "X" + "b" * 10  # the cut at 256 ends on the IBAN
    assert masker.mask_text(number)[0] != number and masker.mask_text(text)[0] == text
    view = inspect_token(
        made_up_jwt({"scp": text})[0],
        masker.personal_pseudonym,
        lambda value: masker.mask_text(value)[0],
    )

    recorded = Recorder(io.StringIO(), run_id="r", masker=masker)._token(
        view, datetime.now(timezone.utc)
    )

    assert len(recorded["claims"]["scp"]) <= 256
    assert "***IBAN-" not in recorded["claims"]["scp"]
    assert "truncated" in recorded["warnings"]


def test_a_view_made_without_a_mask_is_refused_and_masked_does_not_leave_the_recording():
    masker = Masker(handle_salt=b"a fixed salt for the handles" + b"\0" * 4)
    token = made_up_jwt({"scp": "Files.Read"})[0]
    recorder = Recorder(io.StringIO(), run_id="r", masker=masker)
    now = datetime.now(timezone.utc)

    with pytest.raises(ValueError):
        recorder._token(inspect_token(token, masker.personal_pseudonym), now)
    with pytest.raises(ValueError):
        recorder._token(inspect_token("not a jwt", masker.personal_pseudonym), now)
    masked = inspect_token(token, masker.personal_pseudonym, lambda value: value)
    assert masked.masked is True
    assert "masked" not in masked.to_json() and "masked" not in recorder._token(masked, now)


def test_an_issuer_that_is_no_entra_url_and_a_upn_that_is_no_address_are_pseudonyms(
    tmp_path, monkeypatch, serve
):
    host = f"idp.{secrets.token_hex(6)}.example"
    issuer, account = f"https://{host}/", "svc" + secrets.token_hex(6)
    token, _ = made_up_jwt({"iss": issuer, "upn": account, "exp": in_an_hour()})
    monkeypatch.setenv("TEST_TOKEN_READER", token)
    server = reflecting(serve, monkeypatch)
    held = write_engagement(tmp_path / "engagement", identities=[READER])
    chain = Chain(tmp_path / "chain", server, held)

    chain.drive("odd", "--engagement", held, "--identity", "reader")
    chain.publish()

    (started,) = [e for e in events_of(chain.recordings["odd"]) if e["type"] == "run_started"]
    seen = started["auth"]["token"]["pseudonyms"]
    assert set(seen) == {"iss", "upn"}
    for claim, kind in (("iss", "ISSUER"), ("upn", "ACCOUNT")):
        found = PSEUDONYM.fullmatch(seen[claim])
        assert found and found.group(1) == kind
    assert chain.made_everything()
    # The engagement file holds neither; the plain values and their heads must be nowhere.
    needles = [issuer, host, host[:10], quote(issuer, safe=""), *heads_of(account)]
    artifacts = [(n, c) for n, c in chain.artifacts() if not n.startswith("engagement/")]
    assert [
        (label, value)
        for value in needles
        for label, content in artifacts
        if value.encode() in content
    ] == []
    assert [(n, v) for v in needles for n, text in chain.views() if v in text] == []
