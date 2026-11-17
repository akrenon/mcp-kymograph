"""The command line: one run, from arguments to exit code.

Three things here are load-bearing and are why the order of operations looks the way it
does.

**Our stdout belongs to the client.** Under the stdio transport it *is* the JSON-RPC
channel, so it is claimed once at startup and file descriptor 1 is pointed at stderr. After
that no stray print, traceback or library can reach the client, because the channel is only
reachable through the descriptor the proxy holds. Structure, not discipline.

**The destination is checked before anything is started.** A refused destination must leave
no server process behind, so the check runs before the child exists rather than alongside
it. A user who sees a refusal and still has a server running would not notice.

**Nothing from the traffic reaches the terminal unfiltered.** The recording is escaped to
pure ASCII; a terminal is not. Every value that came off the wire — the method name, the
request id, anything else that ever gets interpolated into a line — goes through the same
filter. A single unfiltered insert is enough to let a server rewrite what the operator sees.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import math
import os
import sqlite3
import stat
import sys
import unicodedata
from collections.abc import Callable, Collection, Sequence
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import IO
from urllib.parse import urlsplit

from mcp_kymograph import (
    __version__,
    eras,
    events,
    evidence,
    fleet,
    identity_compare,
    intake,
    marking,
    pacing,
    report,
    signals,
    verdict,
)
from mcp_kymograph import engagement as engagement_files
from mcp_kymograph import script as script_files
from mcp_kymograph.authorization import (
    Declaration,
    Unauthorized,
    is_loopback,
    plain_http_refusal,
)
from mcp_kymograph.authorization import check as check_authorization
from mcp_kymograph.corpus import _NAME, ManifestError, unlisted_reproduction
from mcp_kymograph.corpus import environment as corpus_environment
from mcp_kymograph.corpus import load as load_manifest
from mcp_kymograph.corpus import reproduction as corpus_reproduction
from mcp_kymograph.corpus import tool_identity as corpus_tool_identity
from mcp_kymograph.credentials import ENV_NAME, CredentialError, SecretHeader, Token, auth_record
from mcp_kymograph.definitions import NOT_CAPTURED, NOT_RE_LISTED, RE_LISTED
from mcp_kymograph.driver import (
    DEFAULT_STEP_TIMEOUT,
    DISCOVERY,
    MIN_LINE_BYTES,
    MIN_STEP_TIMEOUT,
    SCRIPTS,
    CallStep,
    ClientChannel,
    Driver,
    Opening,
    probe_script,
    run_driven,
)
from mcp_kymograph.engagement import EngagementError
from mcp_kymograph.engine import Engine, RuleErrorPolicy
from mcp_kymograph.events import (
    PROTOCOL_UNSUPPORTED,
    TLS,
    Direction,
    Message,
    Mode,
    ParseKind,
    RunStarted,
)
from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES
from mcp_kymograph.guard import ScopeGuard
from mcp_kymograph.http_client import HttpClientChannel
from mcp_kymograph.http_proxy import HttpProxy
from mcp_kymograph.identity import IdentityError, ServerIdentity
from mcp_kymograph.identity import from_content as identity_from_content
from mcp_kymograph.identity import from_revision as identity_from_revision
from mcp_kymograph.masking import (
    Masker,
    VerbatimPath,
    normalise_key,
    url_reach,
    withhold_url_path,
)
from mcp_kymograph.output import (
    DestinationRefused,
    Severity,
    inspect_destination,
    make_private_directories,
    prepare_run,
    unusable,
)
from mcp_kymograph.probes import PROBES, Probe, ProbeError
from mcp_kymograph.proxy import CLIENT_SETTLE_SECONDS, EXIT_RULE_WEDGED, Limits, Proxy
from mcp_kymograph.recorder import Recorder, endpoint_refusal, wire_code
from mcp_kymograph.rules import ToolPoisoning
from mcp_kymograph.sandbox import docker
from mcp_kymograph.sandbox.policy import ENDPOINT_ISOLATION, ISOLATIONS, PERMITTED
from mcp_kymograph.sandbox.runner import SANDBOX_IMAGE, TARGET_IMAGE, Sandbox, SandboxFailed, stage
from mcp_kymograph.scenario import ScenarioError
from mcp_kymograph.scenario import load as load_scenario
from mcp_kymograph.sink import DEFAULT_QUEUE_SIZE
from mcp_kymograph.store import (
    PROVENANCES,
    Store,
    StoreError,
    export_triage_counting,
    ingest_all,
    legacy_dropped,
)
from mcp_kymograph.token_inspector import inspect as inspect_token
from mcp_kymograph.web import server as web_server

DEFAULT_OUT_DIR = Path("runs")

#: The built-in scenarios: a fixed table, not a plugin surface. Each entry builds the rules
#: of one scenario, and it returns a *sequence* rather than a single rule: a scenario is
#: allowed to consist of none, one or several rules, and the gate below must behave the same
#: for all three. A scenario file builds the same sequence (see :func:`select_scenario`).
SCENARIOS: dict[str, Callable[[], Sequence[object]]] = {
    "tool-poisoning": lambda: (ToolPoisoning(),),
}

#: What makes a ``--scenario`` value a file rather than a table name. Explicit on purpose: a
#: file in the working directory that happens to share a built-in's name must not quietly
#: win over it, or the other way round.
SCENARIO_SUFFIXES = (".yaml", ".yml", ".json")

#: Exit code for a destination we refuse to write to. Distinct from a server's own codes.
EXIT_REFUSED = 2
#: A driven run that lacks data, or a comparison of which at least one run does: what it calls
#: gone may only be missing. Distinct from success so a batch cannot read it as a clean result.
EXIT_INCOMPLETE = verdict.EXIT_INCOMPLETE
#: A driven run whose server never completed the handshake: nothing was observed.
EXIT_SERVER_FAILED = verdict.EXIT_SERVER_FAILED
#: A driven run whose sandbox did not hold: nothing it shows is an observation.
EXIT_SANDBOX_FAILED = verdict.EXIT_SANDBOX_FAILED
#: A driven run whose script called a tool and was answered with an error.
EXIT_CALL_FAILED = verdict.EXIT_CALL_FAILED

#: Every exit status this tool gives of its own accord. In proxy mode a server's own status is
#: handed through and can be any of these; the run's state is then only in its recording.
OWN_EXIT_CODES = frozenset({EXIT_REFUSED, *verdict.EXIT_CODES.values(), EXIT_RULE_WEDGED}) - {0}

#: What the exit status means, per mode — said in each subcommand's help.
RUN_EXIT_STATUS = (
    "exit status: the server's own, handed through — a client started Kymograph in the "
    "server's place and sees the server's outcome. A server that ends with 2, 3, 4, 5, 6 or 70 "
    "is therefore indistinguishable by exit status from Kymograph's own codes (refused, "
    "incomplete, server_failed, sandbox_failed, call_failed, rule wedged). The run's state is "
    "in its recording, never in the exit status: kymograph verdict RECORDING."
)
DRIVE_EXIT_STATUS = (
    "exit status: the run's state, read back from its recording — 0 complete, 3 incomplete, "
    "4 server_failed, 5 sandbox_failed, 6 call_failed (a tool call of the script answered with "
    "an error); 2 refused before anything started, 70 a rule wedged "
    "the tool. The server's own exit status is recorded (server_exited), never handed through."
)

#: A command ended by Ctrl-C where it had nothing of its own to record: 128 + SIGINT, the code a
#: shell gives a command its SIGINT ended. A driven run and a fleet record their interruption
#: and exit with the state it left them in instead.
EXIT_INTERRUPTED = 130

#: A command whose result could not be written to stdout — closed, or a pipe whose reader has
#: gone. 74 is EX_IOERR of sysexits.h, as 70 for a wedged rule is EX_SOFTWARE. The result is not
#: lost in silence: stderr says it was not written, and what the exit status would have been.
EXIT_OUTPUT_FAILED = 74

#: Store messages carry a recording's path before their reason; 200 characters cut the reason.
STORE_NOTICE_LIMIT = 600

#: Unicode categories with no business on a terminal: controls, format characters (which is
#: where zero-width and bidi overrides live), surrogates, and unassigned code points.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

_ARROWS = {Direction.CLIENT_TO_SERVER: "→", Direction.SERVER_TO_CLIENT: "←"}


def display(value: object, *, limit: int = 60) -> str:
    """Make one value safe to put on a terminal, whatever it came from.

    Used for every insert that originates in the traffic, not only the obvious ones: a
    request id is as much a server's choice as a method name is.
    """
    text = "".join(
        character
        for character in str(value)
        if unicodedata.category(character) not in _UNSAFE_CATEGORIES
    )
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def masked_display(value: object, masker: Masker | None, *, limit: int = 60) -> str:
    """:func:`display` of a value that came from the server, after the masker: cut after
    masking, so that no beginning of a masked value is left standing. ``None`` for a masker only
    where the caller has none (the run is not yet masked)."""
    text = str(value)
    return display(masker.mask_text(text)[0] if masker is not None else text, limit=limit)


def manifest_refusal(
    refusal: ManifestError | EngagementError | intake.IntakeError, *, limit: int = 200
) -> str:
    """A manifest's or an engagement file's refusal for the terminal, shortened in the path and
    nowhere else.

    The path comes first and can be as long as the checkout it lies in; the reason after it
    is what the operator acts on, often the list of entries to pick from. So it is the path
    that gives way, from the front, keeping its end and the file name; the reason stays whole.
    """
    reason = display(refusal.reason, limit=len(refusal.reason) + 1)
    if refusal.source is None:
        return reason
    source = display(refusal.source, limit=len(refusal.source) + 1)
    whole = f"{source}: {reason}"
    if len(whole) <= limit:
        return whole
    room = max(limit - len(reason) - 2, len(Path(source).name) + 2)
    # From room == len(source) on, "…" plus the last room - 1 characters is no shorter than the
    # path itself: the mark would hide one character, or none and lengthen the line.
    if room >= len(source):
        return whole
    return f"…{source[-(room - 1) :]}: {reason}"


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} kB"
    return f"{size / (1024 * 1024):.1f} MB"


class TerminalView:
    """One compact line per message, on stderr, never on stdout."""

    def __init__(self, stream: IO[str], *, quiet: bool = False) -> None:
        self._stream = stream
        self._quiet = quiet
        #: The run's masker, set once it exists: what a line shows of a message passes it.
        self.masker: Masker | None = None

    def notice(self, message: str, *, limit: int = 200) -> None:
        print(f"kymograph: {display(message, limit=limit)}", file=self._stream, flush=True)

    def event(self, _seq: int, body: object) -> None:
        if self._quiet or not isinstance(body, Message):
            return
        arrow = _ARROWS.get(body.direction, "?")
        print(
            f"  {arrow}  {self._label(body):<34}{human_size(body.size_bytes):>10}",
            file=self._stream,
            flush=True,
        )

    def _label(self, body: Message) -> str:
        parse = body.parse
        if not parse.ok:
            reason = masked_display(parse.error_reason or "unknown", self.masker, limit=20)
            return f"unparsed   ({reason})"
        if parse.kind in (ParseKind.REQUEST, ParseKind.NOTIFICATION):
            method = masked_display(parse.method or "", self.masker, limit=40)
            return f"{parse.kind.value:<10} {method}"
        if parse.kind is ParseKind.RESPONSE:
            marker = "error" if parse.is_error else "result"
            return f"{marker:<10} #{masked_display(parse.id, self.masker, limit=20)}"
        return display(parse.kind.value, limit=40)


def positive_count(text: str) -> int:
    """A bound that counts: a whole number above zero. Checked when the arguments are read, so
    a bound that cannot hold is an input error (exit 2) before anything starts — never a run
    that ends in some state because of it."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be a whole number above 0, not {text}")
    return value


def positive_seconds(text: str) -> float:
    """A bound in seconds: finite and above zero. Zero or less would end every wait at once,
    and nan or inf cannot be written into the recording (it is JSON) — each would come back as
    a run that failed or stopped, when it is the input that was wrong."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"must be a finite number of seconds above 0, not {text}")
    return value


def env_name(text: str) -> str:
    """The name of an environment variable. Never echoed: a value typed here by mistake is a
    credential on argv already, and is not repeated on the terminal."""
    if not ENV_NAME.fullmatch(text):
        raise argparse.ArgumentTypeError("must be the name of an environment variable")
    return text


def identity_name(text: str) -> str:
    """The name of an identity of the engagement file."""
    if not _NAME.fullmatch(text):
        raise argparse.ArgumentTypeError("must be a name: 1-64 letters, digits, . _ -")
    return text


def sandbox_nonce(text: str) -> str:
    """Twelve lowercase hex digits, as the sandbox makes its own: part of container names."""
    if len(text) != 12 or any(character not in "0123456789abcdef" for character in text):
        raise argparse.ArgumentTypeError(f"must be 12 lowercase hex digits, not {text!r}")
    return text


def step_seconds(text: str) -> float:
    """A step's wait: a bound in seconds, and at least :data:`MIN_STEP_TIMEOUT` — the first
    step includes the server's own start, and less than that would decide for the server."""
    value = positive_seconds(text)
    if value < MIN_STEP_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"must be at least {MIN_STEP_TIMEOUT:g} s, not {text}: the first step includes the "
            "server's own start, and a shorter wait would decide the run, not the server"
        )
    return value


def script_choice(text: str) -> str:
    """A ``--script`` argument: a built-in script's name, or the path of a script file, known
    by its suffix. Anything else is refused here, not guessed at — a file without one too."""
    if text in SCRIPTS or script_files.is_file_name(text):
        return text
    if Path(text).is_file():
        raise argparse.ArgumentTypeError(
            f"{text!r} is a file without the suffix of a script file "
            f"({', '.join(script_files.SUFFIXES)}), which says how it is read"
        )
    raise argparse.ArgumentTypeError(
        f"{text!r} is neither a built-in script ({', '.join(sorted(SCRIPTS))}) nor a script "
        f"file ({', '.join(script_files.SUFFIXES)})"
    )


def loopback_address(text: str) -> str:
    """A ``--bind`` address: ``127.0.0.1``, nothing else (web.server.loopback).
    Checked when the arguments are read, so what the interface shows — hostile traffic among
    it — is never offered beyond this machine, not even for the moment before a refusal."""
    try:
        return str(web_server.loopback(text))
    except ValueError as refusal:
        raise argparse.ArgumentTypeError(str(refusal)) from None


def port_number(text: str) -> int:
    """A ``--port``: 0 for any free port, otherwise a port number from 1 to 65535."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if not 0 <= value <= 65535:
        raise argparse.ArgumentTypeError(
            f"must be 0 (any free port) or a port number from 1 to 65535, not {text}"
        )
    return value


def _add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    """Everything both modes take. Shared by construction, so neither can drift from the
    other on the flags that decide what may be recorded and against what."""
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--max-message-bytes", type=positive_count, default=DEFAULT_MAX_MESSAGE_BYTES
    )
    parser.add_argument("--max-duration", type=positive_seconds, default=86400.0, metavar="SECONDS")
    parser.add_argument("--queue-size", type=positive_count, default=DEFAULT_QUEUE_SIZE)
    parser.add_argument(
        "--mask-key",
        action="append",
        default=[],
        metavar="NAME",
        help="an extra field name whose value must never be recorded (repeatable)",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        metavar="NAME|FILE",
        help=(
            "activate a traffic-altering scenario: a built-in name "
            f"({', '.join(sorted(SCENARIOS))}) or a .yaml/.json scenario file "
            "(default: observe only)"
        ),
    )
    parser.add_argument(
        "--target",
        default=None,
        metavar="HOST",
        help=(
            "the target you are testing, for the engagement gate. stdio always spawns a "
            "local child, so for stdio this only affects authorization"
        ),
    )
    parser.add_argument(
        "--engagement-confirmed",
        action="store_true",
        help=(
            "confirm a written engagement covers this target, required to run a scenario, "
            "or a script that calls tools, against a non-local one"
        ),
    )
    parser.add_argument(
        "--engagement",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "the engagement file the run is held to (.yaml, .yml or .json): only what it lists "
            "runs, and only inside its window; it narrows the gate and never widens it, so "
            "--engagement-confirmed is still needed wherever it is needed without a file. A "
            "refusal under a file is written to refusals.jsonl in --out-dir"
        ),
    )
    parser.add_argument(
        "--on-rule-error",
        choices=[policy.value for policy in RuleErrorPolicy],
        default=RuleErrorPolicy.ABORT.value,
        help=(
            "what a failing rule costs: abort ends the run (default), continue stills only "
            "that rule and marks its hits invalid, leaving the others running"
        ),
    )
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument(
        "--server-content",
        action="append",
        default=[],
        metavar="FILE",
        help=(
            "a file that makes up the server (repeatable): its version in every finding key "
            "becomes a digest over these files' contents, not a repository commit"
        ),
    )
    identity.add_argument(
        "--server-revision",
        default=None,
        metavar="REPO@SHA",
        help="a server that is its whole repository, pinned to a full commit id",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="no per-message lines")


def build_parser() -> argparse.ArgumentParser:
    """Two subcommands, because the two modes are two different process contracts.

    ``run`` is started *by a client*: our stdout is the protocol channel and is claimed at
    startup, so nothing else can reach it. ``drive`` is started by a person: there is no
    foreign client, our stdout belongs to whoever typed the command, and the client half of
    the conversation is produced here. A flag on one command would have made what stdout
    means depend on a flag, which is exactly the kind of thing that is debugged for hours.
    """
    parser = argparse.ArgumentParser(
        prog="kymograph",
        description="Record the traffic between an MCP client and an MCP server.",
        epilog="The server command follows a -- separator: kymograph run -- my-server --flag",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser(
        "run", help="sit between a client and a server, and record the session",
        epilog=RUN_EXIT_STATUS,
    )  # fmt: skip
    _add_shared_arguments(run)

    drive = subcommands.add_parser(
        "drive",
        help="be the client too: run a fixed script against the server and record it",
        epilog=DRIVE_EXIT_STATUS,
    )
    _add_shared_arguments(drive)
    drive.add_argument(
        "--script",
        type=script_choice,
        default=None,
        metavar="NAME|FILE",
        help=f"which fixed conversation to speak: a built-in ({', '.join(sorted(SCRIPTS))}) or "
        "a script file (.yaml, .yml or .json); a file that calls tools needs the engagement "
        "confirmation against a target outside localhost (default: discovery)",
    )
    drive.add_argument(
        "--probe",
        default=None,
        metavar="NAME",
        help=f"run a probe module instead of a script ({', '.join(sorted(PROBES))}): an active "
        "test that makes its requests as it goes. Needs --engagement, the module listed under "
        "the file's actions.probes, and no --script",
    )
    drive.add_argument(
        "--probe-option",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help="an option of the probe module (what it takes is in the module's description); "
        "may be given more than once",
    )
    drive.add_argument(
        "--script-var",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help="the value of a placeholder in a script file's arguments "
        f"({', '.join(script_files.PLACEHOLDERS)}); may be given more than once",
    )
    drive.add_argument(
        "--step-timeout",
        type=step_seconds,
        default=DEFAULT_STEP_TIMEOUT,
        metavar="SECONDS",
        help="how long one step waits for its answer before the script stops "
        f"(default {DEFAULT_STEP_TIMEOUT:g}, at least {MIN_STEP_TIMEOUT:g})",
    )
    drive.add_argument(
        "--client-settle-timeout",
        type=positive_seconds,
        default=CLIENT_SETTLE_SECONDS,
        metavar="SECONDS",
        help="how long the recording's closing event waits for the script to write how it "
        f"ended (default {CLIENT_SETTLE_SECONDS:g}); a wait that runs out is recorded",
    )
    drive.add_argument(
        "--http",
        default=None,
        metavar="URL",
        help="drive a server that is already running, over Streamable HTTP at this https:// or "
        "http:// URL (host, port and path), through this tool's own proxy; plain http:// only to "
        "127.0.0.1 or [::1], https:// verified against the system trust store with nothing to "
        "configure; no -- command, and not with --manifest, --entry or --isolation. Scenario "
        "rules are not carried out over HTTP",
    )
    token = drive.add_mutually_exclusive_group()
    token.add_argument(
        "--token-env",
        type=env_name,
        default=None,
        metavar="NAME",
        help="send the bearer token in this environment variable as Authorization to the HTTP "
        "endpoint, and to nowhere else; the name is on argv, the value never is. Under an "
        "engagement file that declares identities, --identity names the source instead",
    )
    token.add_argument(
        "--token-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="send the bearer token in this file (at most 16 KiB, visible ASCII, one trailing "
        "line ending dropped) as Authorization to the HTTP endpoint, and to nowhere else. Under "
        "an engagement file that declares identities, --identity names the source instead",
    )
    drive.add_argument(
        "--identity",
        type=identity_name,
        default=None,
        metavar="NAME",
        help="speak as this identity of the engagement file: its token source and its secret "
        "headers come from the file, which holds no value; the recording names the identity "
        "and its role. An identity the file does not declare is refused",
    )
    drive.add_argument(
        "--manifest",
        type=Path,
        default=None,
        metavar="FILE",
        help="drive a corpus entry: the server, its identity and its scenarios come from here",
    )
    drive.add_argument(
        "--entry",
        default=None,
        metavar="NAME",
        help="which entry of --manifest to drive; --scenario then picks one of its scenarios",
    )
    drive.add_argument(
        "--isolation",
        choices=ISOLATIONS,
        default=None,
        help=(
            "where the entry's server runs: host (a child process) or runc (the sandbox: no "
            "network, every attempt recorded). The entry's provenance decides what is allowed; "
            "a real-world entry needs runsc, which this version does not provide"
        ),
    )
    drive.add_argument(
        "--sandbox-image",
        default=None,
        metavar="REF",
        help=f"the sandbox's own image, by tag or id (default {SANDBOX_IMAGE}); resolved to its "
        "id before the run, and that id is what runs and what the recording names",
    )
    drive.add_argument(
        "--target-image",
        default=None,
        metavar="REF",
        help=f"the image the entry's server runs in, by tag or id (default {TARGET_IMAGE})",
    )
    drive.add_argument(
        "--sandbox-nonce",
        type=sandbox_nonce,
        default=None,
        metavar="HEX",
        help="what names this run's containers (label mcp-kymograph.run=HEX) and its staging "
        "directory, so that whoever started the run can remove them if it has to kill it, as "
        "fleet run does (default: random)",
    )

    judge = subcommands.add_parser(
        "verdict",
        help="the state of one recording, read back from it (JSON); the exit status is that "
        "state's code",
        epilog="exit status: 0 complete, 3 incomplete, 4 server_failed, 5 sandbox_failed, "
        "6 call_failed — of the recording, whichever mode made it.",
    )
    judge.add_argument(
        "recording", type=Path, metavar="RECORDING", help="events.jsonl or its run directory"
    )
    judge.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    library = subcommands.add_parser(
        "signals", help="the signal library: each signal's kind, and its reference page"
    )
    library_actions = library.add_subparsers(dest="signals_command", required=True)
    listed = library_actions.add_parser(
        "list",
        help="every signal with its kind (JSON on stdout); with --reference, the reference "
        "pages instead (Markdown on stdout)",
        epilog="exit status: 0 listed; 2 refused, nothing printed (a reference page the "
        "installed package cannot read: the installation is incomplete).",
    )
    listed.add_argument(
        "--reference",
        action="store_true",
        help="print every signal's reference page, in the library's order: what the pattern "
        "is, how it looks in honest content, and what the tool does not know — a pattern, "
        "never a server",
    )
    listed.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    corpus = subcommands.add_parser("corpus", help="check a corpus manifest (JSON on stdout)")
    corpus_actions = corpus.add_subparsers(dest="corpus_command", required=True)
    check = corpus_actions.add_parser("check", help="validate a manifest and show what it pins")
    check.add_argument("manifest", type=Path, metavar="MANIFEST")
    check.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    store = subcommands.add_parser(
        "store", help="file findings from corpus runs by their key, and compare two runs"
    )
    actions = store.add_subparsers(dest="store_command", required=True)
    ingest = actions.add_parser("ingest", help="file the findings of driver recordings")
    ingest.add_argument("--store", type=Path, required=True, metavar="FILE")
    ingest.add_argument(
        "--provenance",
        default=None,
        choices=PROVENANCES,
        help="a cross-check: the provenance comes from the manifest entry each run recorded, "
        "and a run that says otherwise is refused",
    )
    ingest.add_argument(
        "--engagement",
        type=Path,
        default=None,
        metavar="FILE",
        help="the engagement this store is for: set on a store that holds nothing yet, "
        "advanced to a version that supersedes the current one, refused otherwise; one store "
        "per engagement",
    )
    ingest.add_argument("recordings", nargs="+", metavar="RECORDING")
    diff = actions.add_parser("diff", help="new, gone and unchanged between two runs (JSON)")
    diff.add_argument("--store", type=Path, required=True, metavar="FILE")
    diff.add_argument("before", metavar="BEFORE", help="run id, 8+ characters of it, or recording")
    diff.add_argument("after", metavar="AFTER")
    listing = actions.add_parser("runs", help="the runs in a store (JSON)")
    listing.add_argument("--store", type=Path, required=True, metavar="FILE")
    found = actions.add_parser(
        "findings",
        help="every filed finding of one provenance (JSON); real-world ones are disclosure "
        "candidates and are queried here, apart, never in a fleet's report",
    )
    found.add_argument("--store", type=Path, required=True, metavar="FILE")
    found.add_argument("--provenance", required=True, choices=PROVENANCES)
    triage = actions.add_parser(
        "triage",
        help="decisions about findings, kept beside them and never in them: append a row, or "
        "list the current ones",
    )
    triage_actions = triage.add_subparsers(dest="triage_command", required=True)
    decide = triage_actions.add_parser(
        "set",
        help="append one decision about a finding's identity, with its author and role; nothing "
        "is changed or deleted, a later row supersedes an earlier one of the same role",
        epilog="exit status: 0 appended; 2 refused, nothing written (no such finding, an empty "
        "author, a status the role may not set, a rationale or a severity given, a store that does "
        "not exist).",
    )
    decide.add_argument("--store", type=Path, required=True, metavar="FILE")
    which = decide.add_mutually_exclusive_group(required=True)
    which.add_argument(
        "--identity",
        default=None,
        metavar="JSON",
        help="the finding's identity, as store diff prints it",
    )
    which.add_argument(
        "--finding",
        type=int,
        default=None,
        metavar="ID",
        help="the store's id of a finding with that identity (store findings shows it)",
    )
    decide.add_argument("--role", required=True, choices=("operator", "customer"))
    decide.add_argument("--status", required=True, metavar="STATUS")
    # Not options any more: kept to be refused in words, not by argparse's usage text.
    # Any number of values, so that a bare option, or one before another option, is refused in
    # words too and not by the usage text.
    decide.add_argument("--severity", nargs="*", default=None, help=argparse.SUPPRESS)
    decide.add_argument("--rationale", nargs="*", default=None, help=argparse.SUPPRESS)
    decide.add_argument(
        "--author", required=True, metavar="NAME", help="who decided; never taken from elsewhere"
    )
    decisions = triage_actions.add_parser(
        "list", help="the current decision per identity and role (JSON)"
    )
    decisions.add_argument("--store", type=Path, required=True, metavar="FILE")
    decisions.add_argument("--history", action="store_true", help="every row, in the order written")
    carry_out = triage_actions.add_parser(
        "export",
        help="write every triage row and the store's engagement chain to a new file (JSON), to "
        "carry them into a store of this version's schema; reads a store of this schema or of "
        "the one before it, and of it the triage and the engagement only",
        epilog="exit status: 0 written and read back; 2 refused, nothing written (a store of "
        "another schema or one that is not whole, a destination that exists, lies in a run "
        "directory or would be tracked by git).",
    )
    carry_out.add_argument("--store", type=Path, required=True, metavar="FILE")
    carry_out.add_argument("--out", type=Path, required=True, metavar="FILE")
    carry_in = triage_actions.add_parser(
        "import",
        help="carry the rows of a triage export into a store of this schema that holds no "
        "triage row yet, with their authors, roles and times; ingest the same recordings, and "
        "the engagement file's versions with store ingest --engagement, first",
        epilog="exit status: 0 carried; 2 refused, nothing written (a store that does not exist "
        "or holds triage already, a file that is not an export, a row whose finding or "
        "engagement this store does not hold).",
    )
    carry_in.add_argument("--store", type=Path, required=True, metavar="FILE")
    carry_in.add_argument("file", type=Path, metavar="EXPORT")
    timeline = actions.add_parser(
        "history",
        help="for one entry, each identity across every fleet and run: sighted, not sighted, "
        "not a result, not asked, capped (JSON)",
    )
    timeline.add_argument("--store", type=Path, required=True, metavar="FILE")
    timeline.add_argument("--server", required=True, metavar="ENTRY")
    for action in (ingest, diff, listing, found, decide, decisions, carry_out, carry_in, timeline):
        action.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    batch = subcommands.add_parser(
        "fleet", help="run the whole corpus under runc, file every run, compare with the last"
    )
    batch_actions = batch.add_subparsers(dest="fleet_command", required=True)
    start = batch_actions.add_parser(
        "run", help="every entry and scenario of a manifest, one result each (JSON)"
    )
    start.add_argument("--manifest", type=Path, required=True, metavar="FILE")
    start.add_argument("--store", type=Path, required=True, metavar="FILE")
    start.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    start.add_argument(
        "--engagement",
        type=Path,
        default=None,
        metavar="FILE",
        help="the engagement file every run is held to, checked for every job before the "
        "first starts and handed to each; the store becomes this engagement's",
    )
    start.add_argument(
        "--parallel",
        type=int,
        default=fleet.DEFAULT_PARALLEL,
        metavar="N",
        help=f"runs at a time, at most {fleet.MAX_PARALLEL} (default {fleet.DEFAULT_PARALLEL})",
    )
    start.add_argument("--sandbox-image", default=SANDBOX_IMAGE, metavar="REF")
    start.add_argument("--target-image", default=TARGET_IMAGE, metavar="REF")
    start.add_argument("--step-timeout", type=step_seconds, default=DEFAULT_STEP_TIMEOUT)
    start.add_argument("--job-timeout", type=positive_seconds, default=fleet.DEFAULT_JOB_TIMEOUT)
    start.add_argument(
        "--client-settle-timeout",
        type=positive_seconds,
        default=CLIENT_SETTLE_SECONDS,
        metavar="SECONDS",
        help="handed to every run (drive --client-settle-timeout)",
    )
    against = batch_actions.add_parser(
        "diff", help="two fleet runs entry by entry (JSON); by default the last two"
    )
    against.add_argument("--store", type=Path, required=True, metavar="FILE")
    against.add_argument("before", nargs="?", default=None, metavar="BEFORE")
    against.add_argument("after", nargs="?", default=None, metavar="AFTER")
    fleets = batch_actions.add_parser("runs", help="the fleet runs in a store (JSON)")
    fleets.add_argument("--store", type=Path, required=True, metavar="FILE")
    for action in (start, against, fleets):
        action.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    engagement = subcommands.add_parser(
        "engagement", help="the engagement file: what it permits, read back from it"
    )
    engagement_actions = engagement.add_subparsers(dest="engagement_command", required=True)
    show = engagement_actions.add_parser(
        "show",
        help="the file as a short document, its digest last (the digest every run under it "
        "records); a draft is shown with what is still a placeholder",
        epilog="exit status: 0 shown (a draft too, marked as one); 2 the file is refused.",
    )
    show.add_argument("engagement_file", type=Path, metavar="FILE")
    show.add_argument(
        "--json", action="store_true", help="the file as parsed, with its digest (JSON)"
    )
    show.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    halt = engagement_actions.add_parser(
        "stop",
        help="the kill switch: make the stop file beside the engagement file (FILE.stop). While it "
        "is there the gate refuses every run under the file, a driven run ends before its next "
        "step, a proxy ends its run, and a fleet starts no run and stops the running ones",
        epilog="exit status: 0 the stop file is written (or, with --clear, removed, or there was "
        "none); 2 refused (no such file, the stop file cannot be written).",
    )
    halt.add_argument("engagement_file", type=Path, metavar="FILE")
    halt.add_argument(
        "--reason",
        default=None,
        metavar="TEXT",
        help="why, kept in the stop file: cut to "
        f"{engagement_files.MAX_STOP_REASON} characters and masked like other text you type",
    )
    halt.add_argument(
        "--clear", action="store_true", help="remove the stop file: runs may start again"
    )
    halt.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    standing = engagement_actions.add_parser(
        "status",
        help="where the engagement stands, in a dozen lines a customer can be sent: window, runs "
        "by state, findings by entry (counts only), refusals, what is still planned",
        epilog="exit status: 0 shown; 3 shown, but a refusals file could not be read or the "
        "store holds no engagement; 2 refused (a store or manifest that cannot be read).",
    )
    standing.add_argument("--store", type=Path, required=True, metavar="FILE")
    standing.add_argument("--manifest", type=Path, default=None, metavar="FILE")
    standing.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="where the runs and their refusals.jsonl are; without it, refusals are not read",
    )
    standing.add_argument("--json", action="store_true", help="the status as JSON")
    standing.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    compare = engagement_actions.add_parser(
        "compare",
        help="the answers of two identities to the same script, side by side: how each was "
        "answered per tool call, whether the answers are the same, where the first difference "
        "is, and what only one of them lists; sends nothing and writes nothing",
        epilog="exit status: 0 compared, both runs complete; 3, 4, 5, 6 compared, but the "
        "gravest of the two states is not complete (named first, and not a result); 2 refused "
        "(not the same engagement, script or steps, the same identity twice, a run without an "
        "identity, or pseudonyms that last a run only).",
    )
    compare.add_argument("run_a", type=Path, metavar="RUN_A", help="events.jsonl or its directory")
    compare.add_argument("run_b", type=Path, metavar="RUN_B")
    compare.add_argument("--json", action="store_true", help="the comparison as JSON")
    compare.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    planted = engagement_actions.add_parser(
        "canary",
        help="the canaries of the file, each with its ID, kind, place and value, for the agency "
        "to plant; the value is derived from the salt and is no instruction; writes nothing",
        epilog="exit status: 0 shown; 2 refused (a file that cannot be read, none or no such "
        "canary, no salt in the environment).",
    )
    planted.add_argument("engagement_file", type=Path, metavar="FILE")
    planted.add_argument("--id", default=None, metavar="ID", help="one canary only")
    planted.add_argument("--json", action="store_true", help="the canaries as JSON")
    planted.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    marked = engagement_actions.add_parser(
        "marking",
        help="whether the server marked planted content as foreign, for each place where a "
        "canary came back in the recording: " + marking.OBSERVATION + "; sends nothing and "
        "writes nothing",
        epilog="exit status: 0 shown (the state of the run first; a run that is not a result is "
        "read all the same); 2 refused.",
    )
    marked.add_argument("run", type=Path, metavar="RUN", help="events.jsonl or its directory")
    where = marked.add_mutually_exclusive_group(required=True)
    where.add_argument(
        "--engagement",
        type=Path,
        default=None,
        metavar="FILE",
        help="the values of the canaries come from this file and the salt in the environment",
    )
    where.add_argument(
        "--canaries-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="a JSON object {id: value}, for a run without an engagement",
    )
    marked.add_argument("--json", action="store_true", help="the result as JSON")
    marked.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    ready = engagement_actions.add_parser(
        "preflight",
        help="whether everything is ready before the window opens, item by item; contacts no "
        "target and writes nothing",
        epilog="exit status: 0 every item ready or not checked; 3 an item not ready; 2 the file "
        "is refused.",
    )
    ready.add_argument("engagement_file", type=Path, metavar="FILE")
    ready.add_argument("--manifest", type=Path, default=None, metavar="FILE")
    ready.add_argument("--store", type=Path, default=None, metavar="FILE")
    ready.add_argument("--out-dir", type=Path, default=None, metavar="DIR")
    ready.add_argument("--sandbox-image", default=None, metavar="REF")
    ready.add_argument("--target-image", default=None, metavar="REF")
    ready.add_argument("--json", action="store_true", help="the items as JSON")
    ready.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    again = engagement_actions.add_parser(
        "recheck",
        help="after the customer's fix: the exact commands that make the re-check run, or, with "
        "--after, what that run showed for each finding; runs nothing and writes nothing",
        epilog="exit status: 0 every finding's outcome is proven (or only commands were asked "
        "for); 3 a finding is not proven — a re-check run that is not a result proves nothing; "
        "2 refused.",
    )
    again.add_argument("--store", type=Path, required=True, metavar="FILE")
    again.add_argument("--engagement", type=Path, required=True, metavar="FILE")
    again.add_argument("--runs", type=Path, required=True, metavar="DIR")
    chosen = again.add_mutually_exclusive_group(required=True)
    chosen.add_argument(
        "--identity", action="append", default=None, metavar="JSON", help="repeatable"
    )
    chosen.add_argument(
        "--finding", type=int, action="append", default=None, metavar="ID", help="repeatable"
    )
    chosen.add_argument(
        "--all-fixed-pending",
        action="store_true",
        help="every finding whose current row, of either role, is fixed_pending_recheck",
    )
    again.add_argument(
        "--after", default=None, metavar="RUN", help="the re-check run, once it is filed"
    )
    again.add_argument("--json", action="store_true", help="the re-check as JSON")
    again.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    attest = engagement_actions.add_parser(
        "attest",
        help="a one-page statement of what was done and not done, from recorded facts only: no "
        "finding, no triage; what a customer can show a third party",
        epilog="exit status: 0 written; 2 refused, nothing written (a bundle that is not intact or "
        "not filed in the store, an existing --out).",
    )
    attest.add_argument("--store", type=Path, required=True, metavar="FILE")
    attest.add_argument(
        "--engagement",
        type=Path,
        required=True,
        metavar="FILE",
        help="the operator's own engagement file, a version of the store's chain: no literal "
        "redaction pattern of it may appear on the page",
    )
    attest.add_argument("--runs", type=Path, required=True, metavar="DIR")
    attest.add_argument("--bundle", type=Path, required=True, metavar="DIR")
    attest.add_argument("--out", type=Path, required=True, metavar="FILE")
    attest.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    dossier = engagement_actions.add_parser(
        "history",
        help="one customer's engagements across their stores, read every time: windows, runs by "
        "state, findings by provenance and triage status, bundles",
        epilog="exit status: 0 every store read; 3 a store could not be read, and is listed as "
        "such; 2 refused.",
    )
    dossier.add_argument("--customer", required=True, metavar="NAME")
    dossier.add_argument(
        "--store", type=Path, action="append", required=True, metavar="FILE", help="repeatable"
    )
    dossier.add_argument("--json", action="store_true", help="the dossier as JSON")
    dossier.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    asked = engagement_actions.add_parser(
        "intake",
        help="the questionnaire a customer fills in (YAML, or --text for a plain form); with "
        "--from, a draft engagement file made from the answers, which the gate refuses until "
        "every placeholder is filled in",
        epilog="exit status: 0 written; 2 refused, nothing written. The answers are the "
        "customer's word, kept under declared and checked against nothing.",
    )
    asked.add_argument("--out", type=Path, required=True, metavar="FILE")
    asked.add_argument("--text", action="store_true", help="the questionnaire as a plain text form")
    asked.add_argument(
        "--from",
        dest="answers",
        type=Path,
        default=None,
        metavar="ANSWERS",
        help="the filled-in questionnaire (.yaml, .yml, .json, or .txt read leniently)",
    )
    asked.add_argument(
        "--id", dest="engagement_id", default=None, metavar="ID", help="the engagement's id"
    )
    asked.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    end = engagement_actions.add_parser(
        "purge",
        help="at the end of retention: delete the store, the operator's notes beside it, every "
        "run directory, refusals file and bundle of the engagement, and write purged.json, which "
        "holds no customer data",
        epilog="exit status: 0 everything gone; 3 a path could not be deleted (listed); 2 refused, "
        "nothing deleted (before retention without a reason, version 2 without --salt-deleted, a "
        "recording or bundle of another engagement).",
    )
    end.add_argument("--store", type=Path, required=True, metavar="FILE")
    end.add_argument("--out-dir", type=Path, required=True, metavar="DIR")
    end.add_argument("--author", required=True, metavar="NAME")
    end.add_argument("--out", type=Path, required=True, metavar="FILE")
    end.add_argument(
        "--before-retention",
        default=None,
        metavar="REASON",
        help="purge before the engagement's retention.delete_after, for this reason, which goes "
        "into purged.json",
    )
    end.add_argument(
        "--salt-deleted",
        action="store_true",
        help="confirm that the salt of the pseudonyms was deleted with the raw data; required for "
        "an engagement of version 2, and recorded in purged.json with the time",
    )
    end.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    written = subcommands.add_parser(
        "report",
        help="the engagement's report in Markdown: every sentence recorded, derived or assessed, "
        "in seven sections; generated from the store, the recordings and the refusals",
        epilog="exit status: 0 written, every run it uses complete; 3 written, but a run it uses "
        "is not complete (the report says so where the run is used); 2 refused, nothing written.",
    )
    written.add_argument(
        "--engagement",
        type=Path,
        required=True,
        metavar="FILE",
        help="the operator's own engagement file, a version the store's chain holds",
    )
    written.add_argument("--store", type=Path, required=True, metavar="FILE")
    written.add_argument("--runs", type=Path, required=True, metavar="DIR")
    written.add_argument(
        "--manifest",
        type=Path,
        default=None,
        metavar="FILE",
        help="the corpus manifest, so that section 2 names the entries still planned, as "
        "engagement status --manifest does",
    )
    written.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="where the refusals.jsonl files are; without it the report says refusals were not "
        "read",
    )
    written.add_argument(
        "--previous",
        type=Path,
        default=None,
        metavar="BUNDLE",
        help="the previous engagement's bundle to compare with, verified before it is read",
    )
    written.add_argument("--out", type=Path, required=True, metavar="FILE")
    written.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    bundle = subcommands.add_parser(
        "evidence", help="the evidence bundle: pack an engagement's runs, verify a bundle"
    )
    bundle_actions = bundle.add_subparsers(dest="evidence_command", required=True)
    pack = bundle_actions.add_parser(
        "pack",
        help="copy every run of the engagement's store, its scenarios, manifests, refusals and "
        "a copy of the store into a new directory with an index of their digests",
        epilog="exit status: 0 packed; 2 refused, nothing written (a recording not found or "
        "changed, a destination that exists or lies in a git working tree, a store of another "
        "engagement).",
    )
    pack.add_argument("--engagement", type=Path, required=True, metavar="FILE")
    pack.add_argument("--store", type=Path, required=True, metavar="FILE")
    pack.add_argument(
        "--runs",
        type=Path,
        required=True,
        metavar="DIR",
        help="where the store's recordings are found (the store keeps their paths as given)",
    )
    pack.add_argument(
        "--session",
        type=Path,
        action="append",
        default=[],
        metavar="RECORDING",
        help="a recording the store does not hold — a proxy session, one a customer watched — made "
        "under this engagement (repeatable); listed as not filed",
    )
    pack.add_argument(
        "--manifest",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="where else to look for a manifest the runs name (repeatable)",
    )
    pack.add_argument(
        "--script",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="a script file a driven run used (repeatable): matched to the runs by the digest "
        "they recorded, placed with the engagement's values replaced; one that matches no run "
        "is refused, a run whose script is not given has no script in the bundle (said on "
        "stderr, one line per run)",
    )
    pack.add_argument("--report", type=Path, default=None, metavar="FILE")
    pack.add_argument("--out", type=Path, required=True, metavar="DIR")
    pack.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    check_bundle = bundle_actions.add_parser(
        "verify",
        help="every file of a bundle against its index: intact, changed, missing or unlisted "
        "(JSON)",
        epilog="exit status: 0 intact; 3 not intact; 2 the index cannot be read whole. A "
        "signature file is reported as present and not checked: signing is the operator's tool's "
        "business.",
    )
    check_bundle.add_argument("bundle", type=Path, metavar="DIR")
    check_bundle.add_argument(
        "--index-digest",
        default=None,
        metavar="HEX",
        help="the index's SHA-256 as known from elsewhere (the store's bundles, an attestation): "
        "without it, a replaced index cannot be told from the original",
    )
    check_bundle.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    again = bundle_actions.add_parser(
        "replay",
        help="repeat one driven run of a bundle: its script and options from the bundle, the "
        "engagement file from you, through the normal gate",
        epilog="exit status: 2 refused (a bundle that is not intact or whose index is not the "
        "one --index-digest names, a run without a script, a "
        "passive run, a script that does not load once masked, an engagement file of another "
        "engagement, a manifest whose digest is not the recorded one, an option the run recorded "
        "only withheld or masked); otherwise the exit status of drive. A value the bundle holds "
        "only as a pseudonym goes out as that pseudonym: replaying with the customer's real "
        "values needs the original script.",
    )
    again.add_argument("bundle", type=Path, metavar="BUNDLE")
    again.add_argument("--run", required=True, metavar="RUN", help="the run's id or its digest")
    again.add_argument(
        "--engagement",
        type=Path,
        required=True,
        metavar="FILE",
        help="your own engagement file, of the bundle's engagement; never read from the bundle",
    )
    again.add_argument(
        "--manifest",
        type=Path,
        default=None,
        metavar="PATH",
        help="your own copy of the manifest the run used, with the server files it lists; its "
        "digest must be the one the run recorded. Without it the path the run recorded is used, "
        "with the same check",
    )
    again.add_argument("--out-dir", type=Path, required=True, metavar="DIR")
    again.add_argument(
        "--engagement-confirmed",
        action="store_true",
        help="as for drive: confirm a written engagement covers this target",
    )
    again.add_argument(
        "--index-digest",
        default=None,
        metavar="HEX",
        help="the index's SHA-256 as known from elsewhere (the store's bundles, an attestation), "
        "checked as the bundle is verified, before the run, the engagement file or the script "
        "is read and before drive starts: without it, replay checks only that the bundle is what "
        "its own index lists, not that the index is the one handed over",
    )
    again.add_argument("-q", "--quiet", action="store_true", help="no per-message lines")
    look = bundle_actions.add_parser(
        "review",
        help="every text surface of every recording in a bundle, by entry and method, with the "
        "values as recorded — what a person reads before a bundle is handed over (JSON)",
        epilog="exit status: 0 listed (how many strings lie outside the listed surfaces is said "
        "per message); 2 refused (a bundle that is not intact).",
    )
    look.add_argument("bundle", type=Path, metavar="DIR")
    look.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    blank = bundle_actions.add_parser(
        "redact",
        help="a second bundle for handover: the engagement's literal patterns and the given keys "
        "blanked in the reviewed surfaces, no store, redactions.json and CUSTOMER-README.md; the "
        "first bundle is not touched",
        epilog="exit status: 0 written and filed; 3 written, but the store did not file it; 2 "
        "refused, nothing written.",
    )
    blank.add_argument("bundle", type=Path, metavar="DIR")
    blank.add_argument(
        "--engagement",
        type=Path,
        required=True,
        metavar="FILE",
        help="the operator's own engagement file, a version of the bundle's chain: its "
        "redaction.mask_patterns are the literal strings blanked",
    )
    blank.add_argument("--store", type=Path, required=True, metavar="FILE")
    blank.add_argument(
        "--mask-key",
        action="append",
        default=[],
        metavar="NAME",
        help="a field name whose values are blanked too (repeatable), matched as --mask-key is",
    )
    blank.add_argument("--out", type=Path, required=True, metavar="DIR")
    blank.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    web = subcommands.add_parser(
        "web",
        help="a read-only web interface on 127.0.0.1: recordings, the store, fleets, "
        "manifests and scenarios; a local viewer, opened by the address with a token it prints",
        epilog="exit status: 2 refused before serving (an address that is not 127.0.0.1, a "
        "source that cannot be opened, a port that cannot be had); 130 ended by Ctrl-C. Nothing "
        "is read but what is given here and what a given manifest names (its scenarios, its "
        "servers' files, this package's source, which corpus.load hashes); nothing is written.",
    )
    web.add_argument(
        "--store",
        type=Path,
        default=None,
        metavar="FILE",
        help="a store to show, opened read-only: neither created nor changed",
    )
    web.add_argument(
        "--runs",
        type=Path,
        default=None,
        metavar="DIR",
        help="where to look for recordings and fleets (five directories deep, no symbolic link "
        "followed); a store's recordings are found here",
    )
    web.add_argument(
        "--manifest",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="a corpus manifest to show (repeatable); one the loader refuses is shown refused",
    )
    web.add_argument(
        "--scenario",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="a scenario file to show (repeatable); one the loader refuses is shown refused",
    )
    web.add_argument(
        "--bundle",
        type=Path,
        action="append",
        default=[],
        metavar="DIR",
        help="an evidence bundle to show, verified against its index; its listed files are "
        "offered as downloads only while it is intact (repeatable)",
    )
    web.add_argument(
        "--attestation",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="an attestation to show and offer as a download, read back first (repeatable)",
    )
    web.add_argument(
        "--bind",
        type=loopback_address,
        default="127.0.0.1",
        metavar="ADDR",
        help="the address to listen on: 127.0.0.1, the default, and no other; no name, "
        "not even localhost, and no other address",
    )
    web.add_argument(
        "--port",
        type=port_number,
        default=8765,
        metavar="N",
        help="the port to listen on, 0 for any free one (default 8765)",
    )
    web.add_argument("-q", "--quiet", action="store_true", help="the start address alone on stderr")
    return parser


def split_server_command(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Everything after the first -- is the server's, verbatim and unparsed by us."""
    argv = list(argv)
    if "--" not in argv:
        return argv, []
    separator = argv.index("--")
    return argv[:separator], argv[separator + 1 :]


def claim_protocol_stdout() -> IO[bytes]:
    """Take the protocol channel and point descriptor 1 at stderr.

    Descriptor 2 is checked before being duplicated over 1. A client may start us without a
    stderr at all, and pointing 1 at a closed descriptor would leave the protocol channel
    aimed at whatever gets opened next — a failure that looks exactly like a protocol bug
    and would be hunted for hours. When there is no stderr, the null device stands in.
    """
    sys.stdout.flush()

    # Ask the interpreter, not descriptor 2. A process started without a stderr does not
    # keep that slot empty: the first file the runtime opens takes it, so by the time this
    # runs, fstat(2) succeeds and reports somebody else's module file. Pointing descriptor 1
    # at that would be worse than doing nothing. ``sys.stderr`` is what the interpreter
    # concluded at startup, before anything could refill the slot.
    stderr_fd = _usable_stderr()

    protocol = os.dup(1)
    replacement = stderr_fd if stderr_fd is not None else os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(replacement, 1)
    finally:
        if stderr_fd is None:
            os.close(replacement)
    return os.fdopen(protocol, "wb", buffering=0)


class _Output:
    """Whether a command's result reached stdout. One command per process; reset by main."""

    failure: str | None = None


def emit(document: object) -> None:
    """Write a command's result to stdout as JSON, whole — or remember why it could not be.

    A closed stdout (the process was started with descriptor 1 closed, so Python has none) or a
    pipe whose reader has gone is a write error, never a result lost in silence: :func:`main`
    turns it into :data:`EXIT_OUTPUT_FAILED` and a line on stderr once the command is done. The
    command itself runs to its end — a fleet is still filed — and nothing more is written.
    """
    emit_text(json.dumps(document, indent=2) + "\n")


def emit_text(text: str) -> None:
    """Write a command's result that is a document for people to stdout, whole, under the same
    rules as :func:`emit`."""
    if _Output.failure is not None:
        return
    stream = sys.stdout
    if stream is None:
        _Output.failure = "stdout is closed"
        return
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError) as exc:
        _Output.failure = getattr(exc, "strerror", None) or str(exc) or type(exc).__name__
        _discard_stdout()


def _discard_stdout() -> None:
    """Point descriptor 1 at the null device, so that what is still buffered for the broken
    stdout is not flushed into it again at exit, with a second complaint."""
    with contextlib.suppress(OSError, ValueError, AttributeError):
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, sys.stdout.fileno())
        os.close(null)


def _usable_stdout() -> bool:
    """Whether there is a stdout to speak the protocol on. Asked of the interpreter, which
    decided at startup — not of descriptor 1, which a file opened since may have taken over
    (the same reason as for stderr, :func:`claim_protocol_stdout`)."""
    return sys.stdout is not None


def _usable_stderr() -> int | None:
    """The descriptor our stderr actually sits on, or None if we have none."""
    stream = sys.stderr
    if stream is None:
        return None
    try:
        descriptor = stream.fileno()
        os.fstat(descriptor)
    except (AttributeError, OSError, ValueError):
        return None
    return descriptor


def main(argv: Sequence[str] | None = None) -> int:
    _Output.failure = None
    try:
        code = _main(argv)
    except KeyboardInterrupt:
        # Ctrl-C where no command of ours was there to take it: before a run or a fleet began,
        # after it was filed, or while a store or a manifest was read. Whatever was under way
        # has cleaned up on the way out (a staging directory, a store's open transaction).
        print("kymograph: interrupted", file=sys.stderr, flush=True)
        return EXIT_INTERRUPTED
    if _Output.failure is not None:
        print(
            f"kymograph: the result could not be written to stdout ({_Output.failure}); it is "
            f"lost, and the exit status is {EXIT_OUTPUT_FAILED} instead of {code}",
            file=sys.stderr,
            flush=True,
        )
        return EXIT_OUTPUT_FAILED
    return code


MAX_MASK_KEY_LENGTH = 64


_MASK_KEY_REFUSAL = (
    f"--mask-key takes a field name: an ASCII letter or digit in it, no '=', ':', blank or "
    f"control character, at most {MAX_MASK_KEY_LENGTH} characters"
)


def _is_mask_key_name(name: str) -> bool:
    """Whether ``name`` can be a field name: short, not empty after ``normalise_key`` (the
    condition ``evidence`` asks, so it is called, not rebuilt), and without ``=`` or ``:`` (the
    separators between a name and a value), white space or any control character (what
    ``unicodedata`` files under ``C``)."""
    return (
        len(name) <= MAX_MASK_KEY_LENGTH
        and normalise_key(name) != ""
        and not any(
            ch in "=:" or ch.isspace() or unicodedata.category(ch).startswith("C") for ch in name
        )
    )


def _abbreviated_mask_key_with_value(ours: Sequence[str]) -> bool:
    """Whether an argument is ``--<prefix>=<rest>`` with ``--<prefix>`` a proper prefix of
    ``--mask-key`` of at least four characters. argparse would take it, or call it ambiguous
    and print it whole, so it is looked for before the parser runs."""
    for arg in ours:
        option, equals, _ = arg.partition("=")
        if (
            equals
            and len(option) >= 4
            and option != "--mask-key"
            and "--mask-key".startswith(option)
        ):
            return True
    return False


def _main(argv: Sequence[str] | None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    ours, server_command = split_server_command(raw)
    if _abbreviated_mask_key_with_value(ours):
        # Refused before the parser, which would print the argument in its own message. The
        # notice is not held back by ``-q``.
        TerminalView(sys.stderr, quiet=False).notice(_MASK_KEY_REFUSAL)
        return EXIT_REFUSED
    refusal = _refused_triage_option(ours)
    if refusal is not None:
        # Before the parser: a value that begins with "-" would otherwise be answered by its
        # usage text, and the value with it.
        TerminalView(sys.stderr, quiet=False).notice(refusal)
        return EXIT_REFUSED
    args = build_parser().parse_args(ours)

    view = TerminalView(sys.stderr, quiet=args.quiet)
    # A mask key is a name, never a value: one with an ``=``, a blank or a control character is
    # a value typed in (``session=<value>``) and would be written to ``inputs`` or to a
    # handover's redactions. Refused for every command that takes the option, before anything is
    # read or written, naming the option and never the value.
    if any(not _is_mask_key_name(name) for name in getattr(args, "mask_key", None) or ()):
        view.notice(_MASK_KEY_REFUSAL)
        return EXIT_REFUSED

    if args.command == "store":
        return _store(args, view)
    if args.command == "signals":
        return _signals_list(args, view)
    if args.command == "corpus":
        return _corpus_check(args, view)
    if args.command == "fleet":
        return _fleet(args, view, raw)
    if args.command == "verdict":
        return _verdict(args, view)
    if args.command == "web":
        return _web(args, view)
    if args.command == "engagement":
        return _engagement(args, view)
    if args.command == "evidence":
        return _evidence(args, view)
    if args.command == "report":
        return _report_engagement(args, view)

    # The engagement file first of all, before any other refusal: from here on, a run refused
    # under a file is written down (refusals.jsonl in --out-dir) as well as said, because a
    # refusal is part of what happened during an engagement. A file that cannot be read gates
    # nothing and records nothing; it is refused whole, before anything else is looked at.
    held = None
    mask_keys = list(args.mask_key)
    if args.engagement is not None:
        try:
            held = engagement_files.load(args.engagement)
        except EngagementError as refusal:
            message = manifest_refusal(refusal)
            view.notice(message, limit=len(message))
            return EXIT_REFUSED
        mask_keys.extend(held.mask_keys)
    masker = run_masker(mask_keys, held.secret_headers if held else (), held=held)
    view.masker = masker

    # The URL paths this run may write as they are, decided once after the gate (below); until
    # then none, and a refusal's record names no path.
    verbatim_paths: tuple[VerbatimPath, ...] = ()

    def refused(reason: str, message: str, *, limit: int = 200, recorded: str | None = None) -> int:
        """Say why the run is refused and, under a file, write it down; 2 either way. The
        terminal gets ``message``; the record gets ``recorded`` where that differs, as it does
        for words that name a URL's path."""
        # Masked first, then cut by the notice: a token in a value the operator or a script gave
        # must not reach the terminal whole or in part.
        view.notice(masker.mask_text(message)[0], limit=limit)
        if held is not None:
            write_refusal(
                view,
                held,
                args.out_dir,
                raw,
                masker,
                reason,
                message if recorded is None else recorded,
                verbatim_paths,
            )
        return EXIT_REFUSED

    # A corpus run takes its server, its identity and its scenario from the manifest, and
    # nothing of the kind from the command line: two sources for one of them would leave the
    # recording unable to say which one it ran.
    corpus_run = None
    isolation = "host"
    http_url = getattr(args, "http", None)
    if http_url is not None:
        problem = http_refusal(args, server_command)
        if problem is not None:
            return refused("http_options", problem)
    if getattr(args, "manifest", None) is not None or getattr(args, "entry", None) is not None:
        try:
            corpus_run = select_corpus_entry(args, server_command)
        except ManifestError as refusal:
            message = manifest_refusal(refusal)
            return refused("manifest", message, limit=len(message))
        server_command = list(corpus_run[1].command)
        args.scenario = str(corpus_run[2].path)
        isolation = corpus_run[3]
        if corpus_run[1].endpoint is not None:
            # An endpoint entry names a server someone else runs, at a URL: the run is an
            # --http run, under isolation remote, with the entry's identity and triple. The URL
            # was read by the same checks as --http's when the manifest was loaded.
            http_url = args.http = corpus_run[1].endpoint
    elif getattr(args, "isolation", None) is not None:
        return refused(
            "arguments",
            "--isolation belongs to a corpus run: it is decided per entry, by provenance",
        )
    if http_url is not None:
        # Plain HTTP only to a loopback literal (http-transport.md 4.4): from another
        # host a recording made over it is evidence of what arrived, not of what the server sent,
        # and the answers cross the network readable. Here, where the URL is final for --http and
        # an endpoint entry alike, and before the gate, so the reason recorded is this rule: no
        # flag opens it, the confirmation included.
        problem = plain_http_refusal(http_url)
        if problem is not None:
            return refused("plain_http", problem, limit=len(problem))
    source_flag = _source_flag(args)
    if (
        source_flag is not None or getattr(args, "identity", None) is not None
    ) and http_url is None:
        # http-transport.md 2.8: stdio "SHOULD NOT" follow the authorization specification; a
        # credential has nowhere to go but an endpoint.
        return refused(
            "arguments",
            "--token-env, --token-file and --identity belong to a run over HTTP: there is no "
            "endpoint to send a credential to",
        )
    if getattr(args, "identity", None) is not None and held is None:
        return refused(
            "arguments", "--identity names an identity of an engagement file: give --engagement"
        )
    images_given = [getattr(args, name, None) for name in ("sandbox_image", "target_image")]
    if any(given is not None for given in images_given) and isolation != "runc":
        return refused(
            "arguments", "--sandbox-image and --target-image belong to a run under --isolation runc"
        )
    nonce = getattr(args, "sandbox_nonce", None)
    if nonce is not None and isolation != "runc":
        return refused("arguments", "--sandbox-nonce belongs to a run under --isolation runc")
    if not server_command and http_url is None:
        return refused("arguments", "no server command given; put it after a -- separator")
    if args.command == "run" and not _usable_stdout():
        # The protocol channel is our stdout; without one the client could hear nothing.
        return refused(
            "arguments", "stdout is closed: there is no channel to the client; nothing was started"
        )

    # The names the operator gave stand unmasked in run_started, and masking them would break
    # the store's comparison with the reproduction triple: so a name that holds a known value or
    # a literal of the run is refused, and so is the path of --manifest, which the triple records
    # as manifest.source, and the scenario path, which authorization.scenario records as it is
    # given (a corpus run's resolved): the bundle reads it again to find the file. The words name
    # the field, never the value. The known values of the paths are all here, before the gate
    # and before anything is asked of Docker. A corpus run's scenario name is known from the
    # manifest, and is checked here with them; a plain --scenario run's stands once the file is
    # read, after the gate, and is checked again with the others. The name the triple records
    # may be another one (two files of one digest), so it is checked once the triple is built.
    # The literals of the credentials are checked once they are read.
    server_name = None if corpus_run is None else corpus_run[1].name
    scenario_name = None if corpus_run is None else corpus_run[2].name
    reproduction = None

    def name_refusal(by: Masker) -> int | None:
        if held is None:
            return None
        fields = [("server_name", server_name), ("scenario_name", scenario_name)]
        if reproduction is not None:
            fields.append(("the scenario's name", reproduction["scenario"]["name"]))
        if corpus_run is not None:
            # The path as it was given, and as the triple records it, if that is another text.
            fields.append(("--manifest", str(args.manifest)))
            fields.append(("--manifest", corpus_run[0].source))
        fields.append(("the scenario path", args.scenario))
        for field_name, name in fields:
            if name is not None and by.holds_known_value(name):
                return refused(
                    "name_holds_known_value",
                    f"{field_name} holds a value the engagement knows or a literal of this run; "
                    "name entries and scenarios by something other than the customer",
                )
        # The path of the recording stands unmasked in the store (the column recording) once it
        # is ingested, and in a refusal at filing: as it was given.
        if by.holds_known_value(str(args.out_dir)):
            return refused(
                "name_holds_known_value",
                "--out-dir holds a value the engagement knows or a literal of this run; "
                "keep the runs in a directory named by something other than the customer",
            )
        return None

    name_refused = name_refusal(masker)
    if name_refused is not None:
        return name_refused

    # The engagement gate runs first of all, before the destination is even prepared: a
    # refused run must start no process and leave nothing behind. It runs here, in the one
    # place both modes pass through, so the driver cannot become a side entrance: driving a
    # scenario against a non-local target is the same act as proxying one, and is refused the
    # same way.
    #
    # What opens the gate is the operator *selecting* a scenario, never how many rules that
    # scenario turned out to load. Reading `engine.active` here — as an earlier version did —
    # means a scenario that loads nothing (an empty file, a parse error, every rule filtered
    # out) silently counts as pure observation and runs unconfirmed against any target. The
    # intent to alter traffic is what needs covering, and the intent is in the selection.
    #
    # A script file that calls tools is read first, because the gate has to know: such a script
    # acts on the target as a scenario does. Over HTTP the target of that is the endpoint's host
    # as well as whatever the operator declared.
    script = None
    probe = None
    probe_options: dict[str, str] = {}
    if args.command == "drive":
        if args.probe is None and args.probe_option:
            return refused("arguments", "--probe-option belongs to a run with --probe")
        if args.probe is not None:
            problem = _select_probe(args, held)
            if isinstance(problem[0], str):
                return refused(*problem)
            probe, probe_options = problem
            script = probe_script(probe)
        else:
            try:
                script = select_script(args)
            except script_files.ScriptError as refusal:
                return refused("script", str(refusal))
    # A probe module calls tools as it goes, so it acts, whatever its options.
    acting = script is not None and (script.acts or probe is not None)
    gated = [(args.scenario is not None, args.target)]
    if http_url is not None:
        # One rule for every HTTP run, a corpus endpoint's and --http's alike: the URL's host is
        # the target, of a selected scenario as of a script that acts. A corpus run always
        # selects a scenario, so a non-local endpoint needs the confirmation even to observe
        # (http-transport.md 4.4); so does --http with a scenario of statements only, since
        # selecting a scenario is what opens the gate (above). No host is no local host: an
        # empty string is not recognised, and so asks.
        gated.append((args.scenario is not None, urlsplit(http_url).hostname or ""))
    try:
        for scenario_active, target in gated:
            check_authorization(
                scenario_active=scenario_active,
                target=target,
                confirmed=args.engagement_confirmed,
                script_calls=acting,
            )
    except Unauthorized as refusal:
        return refused("not_confirmed", str(refusal))

    # Then the scenario itself, still before anything exists on disk or in the process table.
    # A file that does not load is refused whole: running with the part of it that did would
    # make the recording claim a scenario it did not carry out.
    try:
        rules, statements, digest, scenario_name = select_scenario(args.scenario)
    except ScenarioError as refusal:
        return refused("scenario", str(refusal))
    # The scenario's own name stands only now, the file being read; the images are not yet asked.
    name_refused = name_refusal(masker)
    if name_refused is not None:
        return name_refused
    if http_url is not None and Engine(rules).active:
        # Changing a message needs it whole, and over HTTP that means re-framing bodies and
        # event streams on their way: not built. Refused here, before anything exists.
        return refused(
            "scenario_over_http",
            "a scenario with rules is not carried out over HTTP: --http observes only",
        )
    # Then the engagement file, once everything it is held against is known and still before
    # anything exists: what the run reaches, its scenario by digest, its isolation, what its
    # script does. Today's gate has passed with the flag as typed; this can only refuse more.
    gate_facts = None
    if held is not None:
        salt = engagement_salt(held)
        gate_facts = engagement_files.GateFacts(
            command=args.command,
            declared_target=args.target,
            http_url=http_url,
            scenario_digest=digest,
            scenario_builtin=args.scenario is not None and digest is None,
            isolation=isolation,
            script_acts=acting,
            script_lists=script is not None,
            script_tools=_script_tools(script),
            identity=getattr(args, "identity", None),
            source_flag=source_flag,
            salt_read=True,
            salt_length=None if salt is None else len(salt),
            stopped=engagement_files.stopped(held),
            probe=None if probe is None else probe.name,
        )
        try:
            engagement_files.check(held, gate_facts, datetime.now(timezone.utc))
        except engagement_files.EngagementRefused as refusal:
            message = f"{held.source}: {refusal}"
            return refused(
                refusal.condition,
                message,
                limit=len(message),
                recorded=f"{held.source}: {refusal.recorded}",
            )
    # The URL's path is written as it is only if the file lists it for the target the run
    # matched, or, without a file, if the host is a loopback literal; decided here, once, for
    # the recorder, the refusals after this point and the declared target.
    verbatim_paths = verbatim_url_paths(held, gate_facts, http_url, server_command)
    # The server's identity, from its own content, before anything exists: a file that cannot
    # be read is refused here, like a scenario that cannot be loaded.
    try:
        server_identity = (
            corpus_run[1].identity if corpus_run is not None else select_server_identity(args)
        )
    except IdentityError as refusal:
        return refused("identity", str(refusal))
    # The images by id, once, before anything is recorded: the ids the sandbox starts are the
    # ids the environment names. One that cannot be resolved is named as None, and the sandbox
    # then fails on it as its first step — recorded, not refused.
    images = {}
    env = corpus_environment(isolation)
    if isolation == "runc":
        images = pin_images(args.sandbox_image or SANDBOX_IMAGE, args.target_image or TARGET_IMAGE)
        env = corpus_environment(
            isolation, **{role: pinned for role, (_, pinned) in images.items()}
        )
    if corpus_run is not None:
        manifest, entry, _, _ = corpus_run
        server_name = entry.name
        reproduction = corpus_reproduction(manifest, entry, digest, env)
    else:
        reproduction = unlisted_reproduction(scenario_name, digest, env)

    # The sandbox's copy of the entry's files, checked against the identity just recorded in
    # the triple. A file that changed since the manifest was read is another server, and is
    # refused here, before anything else exists — like an identity that cannot be formed.
    sandbox = None
    if isolation == "runc":
        try:
            delivery = stage(
                entry.paths,
                entry.identity,
                manifest.directory,
                entry.command_written,
                nonce=nonce,
            )
        except SandboxFailed as refusal:
            return refused("delivery", f"the entry's files cannot be delivered: {refusal}")
        server_command = list(delivery.command)
        sandbox = Sandbox(
            delivery,
            nonce=nonce,
            **{role: pinned or given for role, (given, pinned) in images.items()},
        )

    engine = Engine(rules)
    declaration = Declaration(
        scenario=args.scenario,
        scenario_digest=digest,
        declared_target=None
        if args.target is None
        else withhold_url_path(args.target, verbatim_paths),
        engagement_confirmed_flag=args.engagement_confirmed,
        **engagement_files.declaration_fields(held),
    )

    # Then the credentials, read once, after the gate and the engagement check and before
    # anything exists: a token that cannot be read leaves nothing behind. From here the masker
    # holds every value as a literal, and so does every refusal that follows.
    try:
        token, secret_headers = read_credentials(args, held)
    except CredentialError as refusal:
        if sandbox is not None:
            sandbox.delivery.cleanup()
        return refused("token", str(refusal), limit=len(str(refusal)))
    others = other_credentials(args, held)
    if token is not None or secret_headers or others:
        masker = run_masker(
            mask_keys,
            [*(held.secret_headers if held else ()), *(header.name for header in secret_headers)],
            [
                *([token.reveal()] if token is not None else []),
                *(header.reveal() for header in secret_headers),
                *others,
            ],
            held,
        )
        view.masker = masker
    # The literals of the credentials, where the masker is complete.
    name_refused = name_refusal(masker)
    if name_refused is not None:
        if sandbox is not None:
            sandbox.delivery.cleanup()
        return name_refused
    named = getattr(args, "identity", None)
    chosen = held.identity(named) if held is not None and named is not None else None
    auth = auth_record(
        identity=None if chosen is None else chosen.name,
        role=None if chosen is None else chosen.role,
        token=token,
    )
    if auth is not None:
        # Which token observation this run is, from the file; null for any other run. Ours.
        auth["observation"] = None if chosen is None else chosen.observation
        # Read before the recorder writes run_started: the view of the token, its claims and
        # pseudonyms under the run's masker (claims masked in full, then clipped), never a byte
        # of the token itself. The recorder judges its expiry, by the time it writes as the
        # start of the run.
        auth["token"] = (
            None
            if token is None
            else inspect_token(
                token.reveal(), masker.personal_pseudonym, lambda text: masker.mask_text(text)[0]
            )
        )

    # Then pacing, before the destination is made: an HTTP run to a host that
    # is not a loopback literal takes a slot of its origin and keeps the interval, whichever way it
    # was asked for. The slot is held to the end of the run. A wait that would outlast the step
    # is a refusal: nothing is connected and no run directory is made.
    pacing_run = None
    slot = None
    if pacing.applies(http_url):
        pacing_run = pacing.settings(held.data.get("pacing") if held is not None else None)
        try:
            slot = _take_slot(args, http_url, pacing_run)
        except pacing.PacingRefused as refusal:
            if sandbox is not None:
                sandbox.delivery.cleanup()
            return refused("pacing", str(refusal), limit=len(str(refusal)))
        except DestinationRefused as refusal:
            if sandbox is not None:
                sandbox.delivery.cleanup()
            # the directory by its fixed name: a message never carries a path
            message = (
                f"{refusal.advisory.message} (checked: the pacing directory "
                f"{pacing.SLOT_DIRECTORY} in the output directory)"
            )
            return refused("destination", message, limit=len(message))
        except OSError as exc:
            if sandbox is not None:
                sandbox.delivery.cleanup()
            return refused("destination", unusable(exc).message)
        if slot.paced is not None:
            view.notice(
                f"paced: waited {slot.paced.seconds:.1f} s before the run began "
                f"({slot.paced.why}) for {masker.mask_text(pacing.origin_of(http_url))[0]}"
            )

    # ``pacing_enforced: true`` is written for a run that holds a slot, and for no other.
    if pacing_run is not None and slot is None:  # _take_slot returns a slot or raises
        raise RuntimeError("a paced run without its slot")
    with slot if slot is not None else contextlib.nullcontext():
        # Then the destination: check it before starting anything.
        try:
            location = prepare_run(args.out_dir)
        except DestinationRefused as refusal:
            if sandbox is not None:
                sandbox.delivery.cleanup()
            return refused("destination", refusal.advisory.message)

        for advisory in location.advisories:
            if advisory.severity is Severity.WARNING:
                view.notice(f"warning: {advisory.message}")

        limits = Limits(
            max_message_bytes=args.max_message_bytes,
            max_duration_seconds=args.max_duration,
            queue_size=args.queue_size,
            on_rule_error=RuleErrorPolicy(args.on_rule_error),
            client_settle_seconds=getattr(args, "client_settle_timeout", CLIENT_SETTLE_SECONDS),
        )
        driving = args.command == "drive"

        # Only in proxy mode. There, descriptor 1 *is* the protocol channel and has to be taken
        # away from everything else in the process. In driver mode there is no client on the
        # other end of it, so claiming it would take the operator's own stdout away for nothing.
        protocol_out = None if driving else claim_protocol_stdout()

        opening = _opening(held, http_url) if driving else None

        # What the proxy is built with in either mode; only its client side differs.
        common = {
            "argv": server_command,
            "limits": limits,
            # Names only, never a value, and only those typed on this command line: an engagement
            # file's keys stay in the file. The step timeout is the driver's; proxy mode has none.
            "inputs": {
                "step_timeout": getattr(args, "step_timeout", None) if driving else None,
                "mask_keys": list(dict.fromkeys(args.mask_key)),
            },
            "engine": engine,
            "declaration": declaration,
            "notice": view.notice,
            "statements": statements,
            "scenario_name": scenario_name,
            "server_identity": server_identity,
            "server_name": server_name,
            "reproduction": reproduction,
            "sandbox": sandbox,
            "isolation": isolation,
            "auth": auth,
            # The engagement's tool rules, held against each call before it is sent on; None without
            # a file, and for a file with no rule about tools.
            "guard": ScopeGuard.of(held),
            # The kill switch: whether the engagement's stop file is there, asked before each
            # message a client sends on and every second, in every kind of run; None without a
            # file.
            "stop_check": None if held is None else (lambda: engagement_files.stopped(held)),
            # ``run_started.probe``: the module and its options, for a run of one.
            "probe": None if probe is None else {"name": probe.name, "options": probe_options},
        }
        if corpus_run is not None and isolation == "host":
            # A host run of a corpus entry starts in the directory its source.paths were resolved
            # and hashed against, so a relative path in its command is looked up among the
            # entry's files and not where the operator happens to stand. The recording gets no
            # field for it: where the manifest lies is there as before, in the manifest's path
            # as it was given and in the scenario's full path.
            common["cwd"] = corpus_run[0].directory
        if pacing_run is not None and slot is not None:
            # Only an HTTP run to a host that is not loopback, and only with its slot held: the
            # proxy writes these into ``run_started`` (``pacing_enforced`` follows ``pacing``)
            # and, for a run that waited, ``paced`` right after.
            common["pacing"] = pacing_run.as_dict()
            common["paced"] = slot.paced
        with Recorder.open(
            location.events_path,
            run_id=location.run_id,
            masker=masker,
            on_event=_graph_warned(view),
            verbatim_paths=verbatim_paths,
        ) as recorder:
            server_failed = None
            failed_detail = ""
            if driving:
                outcome, server_failed, failed_detail = _drive(
                    args,
                    recorder,
                    view,
                    common,
                    script,
                    (token, secret_headers, masker),
                    opening,
                    (probe, probe_options),
                )
            else:
                proxy = Proxy(
                    recorder=recorder,
                    client_in=sys.stdin.buffer,
                    client_out=protocol_out,
                    **common,
                )
                outcome = asyncio.run(proxy.run())

        _report(view, outcome, recorder)
        if isolation not in verdict.OBSERVED_ISOLATIONS:
            view.notice(egress_not_observed(isolation, over_http=http_url is not None))
        if not driving:
            # A client started us in the server's place, and sees the server's own outcome — when
            # there was a server to observe. One that never started, or never said anything, has
            # no outcome worth handing through: the run is server_failed, and exits so.
            if outcome.server_failed is not None or outcome.server_silent:
                why = (
                    "its command could not be started"
                    if outcome.server_failed is not None
                    else "it wrote nothing to its stdout"
                )
                view.notice(
                    f"server_failed: {why}; nothing was observed, and the exit code is this run's "
                    "state, not the server's"
                )
            # Stopped by a signal: not the server's failure, and not a result either. The server's
            # code is handed through; the run's state is in the recording.
            elif getattr(outcome, "stopped", None) is not None:
                whose = (
                    "this run's state: the server was never started"
                    if outcome.reason == "stopped"
                    else "the server's"
                )
                view.notice(
                    f"stopped by {outcome.stopped}: the recording is incomplete (interrupted); "
                    f"exit code {outcome.exit_code} is {whose}",
                    limit=STORE_NOTICE_LIMIT,
                )
            # A session about nothing is not a result, though nobody failed: the server's code is
            # handed through, and the run's state is in the recording.
            elif outcome.empty_session:
                view.notice(
                    f"nobody said anything in this session: its recording is incomplete "
                    f"(empty_session); exit code {outcome.exit_code} is the server's own",
                    limit=STORE_NOTICE_LIMIT,
                )
            # Where the server's outcome reads like one of ours, say whose it is and where the
            # run's state is.
            elif outcome.exit_code in OWN_EXIT_CODES and outcome.sandbox_failed is None:
                view.notice(
                    f"exit code {outcome.exit_code} is the server's own, handed through, not this "
                    f"run's state; that is in the recording: kymograph verdict "
                    f"{location.events_path}",
                    limit=STORE_NOTICE_LIMIT,
                )
            return outcome.exit_code
        return _driven_exit(
            view, location.events_path, outcome, server_failed, failed_detail, masker
        )


def verbatim_url_paths(
    held: engagement_files.Engagement | None,
    facts: engagement_files.GateFacts | None,
    http_url: str | None,
    server_command: Sequence[str] = (),
) -> tuple[VerbatimPath, ...]:
    """The URL paths a run may write as they are, each with the host and effective port it
    belongs to (:func:`masking.url_reach`): the endpoint's path when the engagement file lists
    it for the entry the gate met for this run (:func:`engagement.matched_target`, the path
    exactly), or, without a file, when the URL's host is a loopback literal. An entry listed
    without ``paths`` lists no path, so nothing is verbatim there, a loopback one included. The
    same rule holds for a URL in the server's own command line, which ``run_started.argv``
    records: the gate matches no entry for it, so under a file none of its paths is verbatim,
    and without one only a loopback URL's path is. The same path on another host or port is not
    the pair. Called after the gate."""
    paths: list[VerbatimPath] = []
    if http_url is not None:
        reach = url_reach(http_url)
        path = urlsplit(http_url).path
        if reach is not None:
            if held is None or facts is None:
                if is_loopback(reach[0]):
                    paths.append((*reach, path))
            else:
                target = engagement_files.matched_target(held, facts)
                if target is not None and target.paths is not None and path in target.paths:
                    paths.append((*reach, path))
    if held is None:
        for argument in server_command:
            # A flag's ``=`` value is read like an argument, as ``Masker.mask_argv`` does.
            value = argument.partition("=")[2] if argument.startswith("-") else argument
            if not value.lower().startswith(("http://", "https://")):
                continue
            reach = url_reach(value)
            if reach is not None and is_loopback(reach[0]):
                paths.append((*reach, urlsplit(value).path))
    return tuple(paths)


def write_refusal(
    view: TerminalView,
    held: engagement_files.Engagement,
    out_dir: Path,
    argv: Sequence[str],
    masker: Masker,
    reason: str,
    message: str,
    verbatim_paths: Collection[VerbatimPath] = (),
) -> None:
    """Write a refusal under an engagement file to ``refusals.jsonl`` in ``out_dir``, or say on
    the terminal why it could not be written; the refusal stands either way."""
    missed = engagement_files.record_refusal(
        out_dir,
        argv=argv,
        masker=masker,
        reason=reason,
        message=message,
        engagement=held,
        now=datetime.now(timezone.utc),
        verbatim_paths=verbatim_paths,
    )
    if missed is not None:
        view.notice(
            f"the refusal is not written to {engagement_files.REFUSALS_FILE}: {missed}",
            limit=STORE_NOTICE_LIMIT,
        )


def _take_slot(args, http_url: str, settings: pacing.Pacing) -> pacing.Slot:
    """The slot of the run's origin (:func:`pacing.acquire`). A run that is paced never goes on
    without one: if the destination check refuses ``<out-dir>/.pacing`` or cannot judge it, that
    is :class:`DestinationRefused` with the check's own words and the path it looked at, before
    anything is made there or connected. (``prepare_run`` judges the run directory, and the two
    can differ, a ``.gitignore`` that covers one and not the other.)"""
    out_dir = args.out_dir.expanduser()
    try:
        advisories = inspect_destination(out_dir, out_dir / pacing.SLOT_DIRECTORY)
    except (OSError, RuntimeError) as exc:
        raise DestinationRefused(unusable(exc)) from None
    for advisory in advisories:
        if advisory.severity is Severity.REFUSAL:
            raise DestinationRefused(advisory)
    return pacing.acquire(out_dir, http_url, settings, args.step_timeout)


def _select_probe(args, held) -> tuple[Probe, dict[str, str]] | tuple[str, str]:
    """The probe module ``--probe`` names and its options, or the refusal as ``(reason, words)``.
    Before the gate: what the gate can only hold the engagement against once it is known."""
    if args.script is not None or args.script_var:
        return "arguments", "--probe and --script are two ways to drive: give one"
    if held is None:
        return (
            "probe_without_engagement",
            "--probe runs a module that acts on the server: give --engagement, and list the "
            "module under its actions.probes",
        )
    probe = PROBES.get(args.probe)
    if probe is None:
        return (
            "arguments",
            f"{display(args.probe, limit=len(args.probe) + 1)!r} is not a probe module; there are "
            f"{', '.join(sorted(PROBES))}",
        )
    options: dict[str, str] = {}
    for given in args.probe_option or ():
        key, found, value = given.partition("=")
        if not found or not key:
            return "arguments", "--probe-option is a key, an equals sign and a value"
        if key in options:
            return "arguments", f"--probe-option {display(key, limit=len(key) + 1)} is given twice"
        options[key] = value
    try:
        probe.check(options)
    except ProbeError as refusal:
        return "arguments", str(refusal)
    return probe, options


def select_script(args):
    """The script ``drive`` speaks: a built-in one, or a file read whole with its placeholders
    filled in — or :class:`ScriptError`. ``--script-var`` belongs to a file only."""
    if args.script is None:
        args.script = DISCOVERY.name
    if args.script in SCRIPTS:
        if args.script_var:
            raise script_files.ScriptError(
                "--script-var belongs to a script file: the built-in scripts have no placeholders"
            )
        return SCRIPTS[args.script]
    return script_files.load(args.script, script_files.parse_variables(args.script_var))


def egress_not_observed(isolation: str, *, over_http: bool) -> str:
    """What the terminal says beside a result of a run whose isolation keeps no account of the
    server's egress, so that no finding list reads as all the server did. Over HTTP there is
    no child, whatever the recording's isolation: the server is at the URL."""
    if isolation == "remote" or over_http:
        where = "the server runs elsewhere, reached over HTTP"
    else:
        where = "the server ran as this tool's child, outside the sandbox"
    return (
        f"egress not observed (isolation {display(isolation)}): {where}; what it sends anywhere "
        "but to this tool is not in the recording"
    )


def _driven_exit(
    view: TerminalView,
    events_path: Path,
    outcome,
    server_failed,
    failed_detail: str = "",
    masker: Masker | None = None,
) -> int:
    """A driven run's exit code: its state, never the server's own code.

    The state is read back from the recording this run just wrote — the artifact, not what
    this process believes about it — and what the process itself saw of a failed sandbox or a
    failed server is added, so neither can be lost on the way to disk. The server's exit
    status is in the recording (``server_exited``) and is said here; it is not handed through,
    or a server that ends with 3 would read as a run the tool found incomplete.
    """
    judged = verdict.read(events_path)
    states = [shortfall.state for shortfall in judged.shortfalls]
    stopped = getattr(outcome, "stopped", None)
    if outcome.sandbox_failed is not None:
        states.append(verdict.SANDBOX_FAILED)
    if stopped is not None:
        # Stopped by a signal: the recording says so first, and what the driver saw after it —
        # a connection closed by the stop — is the stop's, not the server's (run_stopped).
        server_failed = None
        states.append(verdict.INCOMPLETE)
    if server_failed is not None:
        states.append(verdict.SERVER_FAILED)
    # The server's command could not be started, or the server said nothing: seen by this
    # process, so neither is lost if the recording's end never reached the disk.
    # (An observation the endpoint turned away is no silence, by the recording just read: rule 14.)
    if getattr(outcome, "server_failed", None) is not None or (
        getattr(outcome, "server_silent", False) and not judged.refused
    ):
        states.append(verdict.SERVER_FAILED)
        server_failed = server_failed or getattr(outcome, "server_failed", None) or "silent"
    state = verdict.gravest(states)
    ended = judged.server_exit or {}
    if ended.get("exit_code") not in (None, 0) or ended.get("signal") is not None:
        how = (
            f"exit code {ended['exit_code']}"
            if ended.get("exit_code") is not None
            else f"signal {ended.get('signal')}"
        )
        view.notice(f"the server ended with {how}; recorded, not handed through")
    if state == verdict.SANDBOX_FAILED:
        view.notice(
            f"sandbox_failed ({outcome.sandbox_failed or 'see the recording'}): this run is not "
            "a result, and nothing it shows reads as nothing found"
        )
    elif state == verdict.SERVER_FAILED and server_failed == TLS and failed_detail:
        # The library's text, which can name what the endpoint's certificate says: through
        # the masker and display, as every insert that did not come from us (http-transport.md
        # 8.3).
        view.notice(
            "server_failed (tls): the TLS handshake with the endpoint failed — "
            f"{masked_display(failed_detail, masker, limit=300)}; nothing was observed, and the "
            "run is not a result",
            limit=500,
        )
    elif state == verdict.SERVER_FAILED and server_failed == PROTOCOL_UNSUPPORTED:
        view.notice(
            "server_failed (protocol_unsupported): the server requires what this tool does not "
            "offer, or speaks no protocol version it knows; nothing was inventoried, and the run "
            "is not a result"
        )
    elif state == verdict.SERVER_FAILED:
        view.notice(
            f"server_failed ({server_failed or 'see the recording'}): the server never started "
            "or never completed the handshake, nothing was observed, and the run is not a result"
        )
    elif state == verdict.INCOMPLETE:
        reasons = [s.reason for s in judged.shortfalls if s.state == verdict.INCOMPLETE]
        causes = sorted({s.cause for s in judged.shortfalls if s.state == verdict.INCOMPLETE})
        first = reasons[0] if reasons else "see the recording"
        view.notice(
            f"incomplete [{', '.join(causes)}] ({len(reasons)} reason(s), first: "
            f"{display(first, limit=120)}): data is missing, and the run is not a result"
        )
    elif state == verdict.CALL_FAILED:
        causes = sorted({s.cause for s in judged.shortfalls if s.state == verdict.CALL_FAILED})
        first = next(s.reason for s in judged.shortfalls if s.state == verdict.CALL_FAILED)
        view.notice(
            f"call_failed [{', '.join(causes)}] ({display(first, limit=120)}): the server "
            "answered a tool call with an error; not a result about the content it was to deliver"
        )
    return verdict.EXIT_CODES[state]


def _verdict(args, view: TerminalView) -> int:
    """One recording's state, read back from it: what neither mode's exit status has to carry.

    Machine output on stdout, a line in words on stderr; the exit status is the state's code.
    The judgement is mcp_kymograph.verdict's, as for drive and the store — never made here.
    """
    path = args.recording / "events.jsonl" if args.recording.is_dir() else args.recording
    judged = verdict.read(path)
    isolation, over_http = recorded_isolation(path)
    observed = None if isolation is None else isolation in verdict.OBSERVED_ISOLATIONS
    emit(
        {
            "recording": str(path),
            "state": judged.state,
            "exit_code": judged.exit_code,
            "rules": verdict.RULES_VERSION,
            "causes": judged.causes,
            "problems": judged.problems,
            "server_exit": judged.server_exit,
            "truncations": judged.truncations,
            "isolation": isolation,
            "egress_observed": observed,
        }
    )
    if not args.quiet:
        ended = judged.server_exit or {}
        view.notice(
            f"{judged.state} ({len(judged.problems)} problem(s))"
            + (
                f"; the server ended with exit code {ended['exit_code']}"
                if ended.get("exit_code") not in (None, 0)
                else ""
            )
        )
        if observed is False:
            view.notice(egress_not_observed(isolation, over_http=over_http))
    return judged.exit_code


def recorded_isolation(path: Path) -> tuple[str | None, bool]:
    """The isolation ``run_started`` names, and whether the run was over HTTP — or None where
    the recording cannot be read: then nothing is said about its egress either way."""
    try:
        with open(path, "rb") as handle:
            started = json.loads(handle.readline())
    except (OSError, ValueError):
        return None, False
    if not isinstance(started, dict) or started.get("type") != "run_started":
        return None, False
    isolation = started.get("isolation", "host")
    if not isinstance(isolation, str):
        return None, False
    return isolation, started.get("transport") == "streamable-http"


def select_scenario(
    value: str | None,
) -> tuple[Sequence[object], Sequence[object], str | None, str | None]:
    """Rules, statements, file digest and scenario name for a ``--scenario`` value.

    A value with a path separator or a scenario suffix is a file; anything else must be a
    built-in name. Unknown names are refused rather than tried as files: a typo should say
    "unknown", not "cannot read".
    """
    if value is None:
        return (), (), None, None
    if os.sep in value or "/" in value or Path(value).suffix.lower() in SCENARIO_SUFFIXES:
        loaded = load_scenario(value)
        return loaded.rules, loaded.statements, loaded.digest, loaded.name
    if value not in SCENARIOS:
        raise ScenarioError(
            f"unknown scenario {value!r}; built-in: {', '.join(sorted(SCENARIOS))}, "
            f"or give a path to a {'/'.join(SCENARIO_SUFFIXES)} file"
        )
    return SCENARIOS[value](), (), None, value


def _store(args, view: TerminalView) -> int:
    """The store subcommands. Machine output on stdout, a summary in words on stderr."""
    if args.store_command in ("triage", "history"):
        return _store_triage(args, view)
    # An engagement file is read before the store is even opened: a file that is refused
    # leaves no new store behind.
    held = None
    if getattr(args, "engagement", None) is not None:
        try:
            held = engagement_files.load(args.engagement)
        except EngagementError as refusal:
            message = manifest_refusal(refusal)
            view.notice(message, limit=len(message))
            return EXIT_REFUSED
    try:
        store = Store.open(args.store)
    except (StoreError, sqlite3.Error, OSError) as refusal:
        view.notice(f"{args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    with store:
        if args.store_command == "ingest":
            if held is not None:
                try:
                    set_engagement(store, held)
                except StoreError as refusal:
                    view.notice(
                        f"{held.source}: the store {args.store} refused it: {refusal}",
                        limit=STORE_NOTICE_LIMIT,
                    )
                    return EXIT_REFUSED
            return _store_ingest(store, args, view)
        if args.store_command == "runs":
            emit([run.to_dict() for run in store.runs()])
            return 0
        if args.store_command == "findings":
            # Each finding with the id `store triage set --finding` takes, and its current
            # decision per role beside it (docs/engagements.md, 5), never in it.
            try:
                emit(store.findings_with_triage(args.provenance))
            except StoreError as refusal:
                view.notice(f"refused: {args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
                return EXIT_REFUSED
            return 0
        try:
            earlier, later = store.resolve(args.before), store.resolve(args.after)
            result = store.diff(earlier, later)
            observed = store.definition_diff(earlier, later)
        except (StoreError, sqlite3.Error) as refusal:
            view.notice(str(refusal), limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
        emit({**result.to_dict(), "definitions": observed})
        _report_diff(view, result, quiet=args.quiet)
        _report_definitions(view, observed, quiet=args.quiet)
        return 0 if result.complete else EXIT_INCOMPLETE


#: What ``store triage set --rationale`` and ``--severity`` are answered with: the tool keeps no
#: reason and no score; both belong in the operator's private notes, which it never reads.
RATIONALE_REFUSED = (
    "refused: the tool does not store a rationale; it belongs in the operator's private notes"
)
SEVERITY_REFUSED = (
    "refused: the tool does not store a severity; it belongs in the operator's private notes"
)


def _refused_triage_option(argv: Sequence[str]) -> str | None:
    """The refusal for a ``--rationale`` or ``--severity`` of ``store triage set``, in any form
    argparse reads as one (exact, with ``=``, an unambiguous abbreviation), or None.

    Looks at the arguments after ``store triage set`` up to a lone ``--``. Neither the option's
    value nor any other argument goes into the answer."""
    for start in range(len(argv) - 2):
        if tuple(argv[start : start + 3]) == ("store", "triage", "set"):
            break
    else:
        return None
    for argument in argv[start + 3 :]:
        if argument == "--":
            return None
        if not argument.startswith("--"):
            continue
        name = argument.split("=", 1)[0]
        if len(name) > 2 and "--rationale".startswith(name):
            return RATIONALE_REFUSED
        if len(name) > 2 and "--severity".startswith(name):
            return SEVERITY_REFUSED
    return None


def _dropped_words(counts: dict[str, int]) -> str:
    """``3 rationale(s) and 2 severity(ies)`` for the non-zero counts of a legacy triage, or
    an empty string when there are none."""
    named = {"rationale": "rationale(s)", "severity": "severity(ies)"}
    return " and ".join(f"{counts[n]} {word}" for n, word in named.items() if counts[n])


def _store_triage(args, view: TerminalView) -> int:
    """``store triage set`` appends one row to an existing store; ``store triage list`` and
    ``store history`` read the store through ``mode=ro`` and change nothing; ``store triage
    export`` and ``import`` carry the rows across a schema step."""
    if args.store_command == "triage" and args.triage_command == "export":
        return _triage_export(args, view)
    if args.store_command == "triage" and args.triage_command == "import":
        return _triage_import(args, view)
    writing = args.store_command == "triage" and args.triage_command == "set"
    if writing and args.rationale is not None:
        view.notice(RATIONALE_REFUSED)
        return EXIT_REFUSED
    if writing and args.severity is not None:
        view.notice(SEVERITY_REFUSED)
        return EXIT_REFUSED
    if writing and not args.store.is_file():
        # Store.open would create it: a decision about a finding no store holds is refused.
        view.notice(f"refused: {args.store}: no such store; a decision is about a filed finding")
        return EXIT_REFUSED
    try:
        store = Store.open(args.store) if writing else Store.open_read_only(args.store)
    except (StoreError, sqlite3.Error, OSError) as refusal:
        view.notice(f"refused: {args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    with store:
        if args.store_command == "history":
            try:
                emit(store.history(args.server))
            except StoreError as refusal:
                view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
                return EXIT_REFUSED
            return 0
        if args.triage_command == "list":
            try:
                emit(store.triage_history() if args.history else store.triage_current())
            except StoreError as refusal:
                view.notice(f"refused: {args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
                return EXIT_REFUSED
            return 0
        identity = None
        if args.identity is not None:
            try:
                identity = json.loads(args.identity)
            except ValueError as exc:
                view.notice(f"refused: --identity is not JSON: {exc}")
                return EXIT_REFUSED
        try:
            row = store.triage_set(
                identity=identity,
                finding=args.finding,
                role=args.role,
                status=args.status,
                author=args.author,
            )
        except StoreError as refusal:
            view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
    emit(row)
    if not args.quiet:
        superseded = (
            f", superseding row {row['supersedes']}" if row.get("supersedes") is not None else ""
        )
        view.notice(
            f"row {row['id']}: {display(row['role'])} {display(row['status'])} by "
            f"{display(row['author'])}{superseded}"
        )
    return 0


def _triage_export(args, view: TerminalView) -> int:
    """``store triage export``: the one reader of a store of the schema before this one, and of
    it only the triage and the engagement (:func:`mcp_kymograph.store.export_triage`) — rows a
    person wrote, which no run can produce again. Written once, ``0600``, and read back."""
    if refused_destination(view, args.out, "a triage export"):
        return EXIT_REFUSED
    try:
        document, counts = export_triage_counting(args.store)
    except (StoreError, sqlite3.Error, OSError) as refusal:
        view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    dropped = _dropped_words(counts)
    data = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if not write_once(view, args.out, data):
        return EXIT_REFUSED
    try:
        back = args.out.read_bytes()
    except OSError as exc:
        view.notice(f"{args.out}: written, and could not be read back: {exc.strerror or exc}")
        return EXIT_OUTPUT_FAILED
    if back != data or json.loads(back) != document:
        view.notice(f"{args.out}: written, and does not read back as it was written")
        return EXIT_OUTPUT_FAILED
    if dropped:
        # The migration to 13 is this export and the import after it: both stay behind.
        view.notice(
            f"{dropped} of the store are dropped, not written to the export: the tool keeps "
            "none; keep them in the operator's private notes"
        )
    if not args.quiet:
        view.notice(
            f"{len(document['rows'])} triage row(s) of a store of schema "
            f"{document['store_schema']} written to {display(str(args.out), limit=120)}: sha256 "
            f"{hashlib.sha256(data).hexdigest()}",
            limit=STORE_NOTICE_LIMIT,
        )
    return 0


#: The largest export file ``store triage import`` reads; the file comes from outside.
TRIAGE_IMPORT_MAX_BYTES = 64 << 20


class _TooLarge(Exception):
    """The export file is over :data:`TRIAGE_IMPORT_MAX_BYTES`."""


class _NotRegular(Exception):
    """The export path does not name a regular file (a FIFO, a device, a directory)."""


def _triage_import(args, view: TerminalView) -> int:
    """``store triage import``: the rows of an export into a store of this schema that holds
    none, all or nothing (:meth:`mcp_kymograph.store.Store.import_triage`); what the store holds
    afterwards is read back and counted against the file."""
    if not args.store.is_file():
        # Store.open would create it, and a store without the findings refuses every row.
        view.notice(f"refused: {args.store}: no such store; ingest the same recordings first")
        return EXIT_REFUSED
    try:
        # The path is asked for its kind first, so that a socket or a device is refused as what it
        # is and not by what opening it does. Opened without blocking, so that a FIFO with no
        # writer does not hold the open; what was opened is asked again, for a swap in between,
        # for its kind and size before anything is read, and the read itself stops one byte past
        # the limit, for a file that grows in between.
        if not stat.S_ISREG(os.stat(args.file).st_mode):
            raise _NotRegular
        descriptor = os.open(args.file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise _NotRegular
            if opened.st_size > TRIAGE_IMPORT_MAX_BYTES:
                raise _TooLarge
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                data = handle.read(TRIAGE_IMPORT_MAX_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(data) > TRIAGE_IMPORT_MAX_BYTES:
            raise _TooLarge
    except _NotRegular:
        view.notice(f"refused: {args.file}: not a regular file; nothing is written")
        return EXIT_REFUSED
    except _TooLarge:
        view.notice(
            f"refused: {args.file}: larger than {TRIAGE_IMPORT_MAX_BYTES >> 20} MiB, "
            "which no triage export is; nothing is written"
        )
        return EXIT_REFUSED
    except OSError as exc:
        view.notice(f"refused: {args.file}: {exc.strerror or exc}")
        return EXIT_REFUSED
    try:
        document = json.loads(data)
    except ValueError as exc:
        view.notice(f"refused: {args.file} is not JSON: {exc}")
        return EXIT_REFUSED
    except RecursionError:
        view.notice(f"refused: {args.file} is nested deeper than this reads; nothing is written")
        return EXIT_REFUSED
    digest = hashlib.sha256(data).hexdigest()
    dropped = _dropped_words(legacy_dropped(document))
    try:
        with Store.open(args.store) as store:
            rows = store.import_triage(document, source_sha256=digest)
    except (StoreError, sqlite3.Error, OSError) as refusal:
        view.notice(f"refused: {args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    differs = _carried_differently(document["rows"], rows)
    if differs is not None:
        view.notice(
            f"{args.store}: the rows carried do not read back as the file has them: {differs}",
            limit=STORE_NOTICE_LIMIT,
        )
        return EXIT_OUTPUT_FAILED
    emit(rows)
    if dropped:
        view.notice(
            f"{dropped} in the file are dropped, not carried: the tool keeps none; keep them in "
            "the operator's private notes"
        )
    if not args.quiet:
        view.notice(
            f"{len(rows)} triage row(s) carried into {display(str(args.store), limit=120)} from "
            f"{display(str(args.file), limit=120)} (sha256 {digest}), with their authors, roles "
            "and times; the store records the import",
            limit=STORE_NOTICE_LIMIT,
        )
    return 0


#: What a carried triage row must read back as, field by field; ``id`` is the store's own, and
#: ``supersedes`` is compared through the ids of both sides.
_CARRIED_FIELDS = (
    "identity", "role", "status", "author", "at_utc", "engagement_digest",
)  # fmt: skip


def _carried_differently(given: list, read: list) -> str | None:
    """Where the rows a store reads back after an import differ from the file's, or None: the
    same number, in the same order, every field as written, and each ``supersedes`` naming the
    row at the same place."""
    if len(given) != len(read):
        return f"{len(given)} in the file, {len(read)} read back"
    given_place = {row["id"]: number for number, row in enumerate(given)}
    read_place = {row["id"]: number for number, row in enumerate(read)}
    for number, (written, back) in enumerate(zip(given, read, strict=True)):
        for name in _CARRIED_FIELDS:
            if written[name] != back[name]:
                return f"row {number + 1}: {name}"
        before = written["supersedes"]
        after = back["supersedes"]
        if (None if before is None else given_place.get(before)) != (
            None if after is None else read_place.get(after)
        ):
            return f"row {number + 1}: supersedes"
    return None


def set_engagement(store: Store, held: engagement_files.Engagement) -> None:
    """Make the store this engagement's, or advance it to this version of the file
    (:meth:`Store.set_engagement`); a :class:`StoreError` says why not."""
    store.set_engagement(
        engagement_id_declared=held.id,
        digest=held.digest,
        file_declared=held.sanitized(),
        supersedes=held.supersedes,
        delete_after_declared=None if held.delete_after is None else held.delete_after.isoformat(),
        removed=held.removed,
    )


def _store_ingest(store: Store, args, view: TerminalView) -> int:
    """File each recording. The exit code is a refusal, or the gravest state filed."""
    handled: list[str | None] = []
    try:
        return _ingest_each(store, args, view, handled)
    except KeyboardInterrupt:
        # Each recording is filed in a transaction of its own: the one under way when Ctrl-C
        # came is rolled back whole, those before it stay filed. Filing again is safe.
        view.notice(
            f"interrupted after {len(handled)} of {len(args.recordings)} recording(s); the one "
            "being filed is not in the store, nothing is half filed — run it again to file "
            "the rest (what is filed already is said so)"
        )
        return EXIT_INTERRUPTED


def _ingest_each(store: Store, args, view: TerminalView, handled: list[str | None]) -> int:
    """Each recording in turn; ``handled`` gets its state, or None for a refusal."""
    for recording, outcome in ingest_all(store, args.recordings, args.provenance):
        if isinstance(outcome, StoreError):
            handled.append(None)
            # Our own words around a path the operator gave: long enough to keep the reason,
            # which is what says how to get the run accepted.
            view.notice(f"refused: {outcome}", limit=STORE_NOTICE_LIMIT)
            continue
        handled.append(outcome.state)
        state = (
            "complete"
            if outcome.complete
            else f"{outcome.state.upper()} [{', '.join(outcome.causes)}] "
            f"({len(outcome.problems)} problem(s))"
        )
        verb = "already filed" if outcome.already else "filed"
        view.notice(
            f"{verb} {outcome.run[:12]} from {display(str(recording), limit=80)} "
            f"({outcome.provenance}): {outcome.findings} finding sighting(s), {state}"
        )
        for problem in outcome.problems[:5]:
            view.notice(f"  problem: {display(problem, limit=160)}")
        summary = store.definition_summary(outcome.run)
        if summary is None:
            view.notice(f"  definitions: {NOT_CAPTURED}")
        else:
            listed = ", ".join(f"{part['definitions']} {kind}" for kind, part in summary.items())
            view.notice(f"  definitions: {listed or 'none listed'}")
            for kind, part in summary.items():
                for reasons in part["partial"]:
                    view.notice(
                        f"  {kind}: a partial listing ({', '.join(display(r) for r in reasons)})"
                    )
                notified = part["list_changed"]
                if notified:
                    view.notice(
                        f"  {kind} list_changed x{notified['count']}, first at seq "
                        f"{notified['first_seq']}: "
                        f"{RE_LISTED if notified['relisted'] else NOT_RE_LISTED}"
                    )
        isolation = store.run_info(outcome.run).isolation
        if isolation not in verdict.OBSERVED_ISOLATIONS:
            view.notice(f"  {egress_not_observed(isolation, over_http=isolation == 'remote')}")
    if None in handled:
        return EXIT_REFUSED
    return verdict.EXIT_CODES[verdict.gravest(handled)]


def _engagement(args, view: TerminalView) -> int:
    """The engagement subcommands. ``show``: the file as a short document on stdout — or as JSON
    with ``--json`` — and what it is in one line on stderr. It reads the file and the scenarios
    it lists, and nothing else; it writes nothing."""
    if args.engagement_command == "stop":
        return _engagement_stop(args, view)
    if args.engagement_command == "status":
        return _engagement_status(args, view)
    if args.engagement_command == "compare":
        return _engagement_compare(args, view)
    if args.engagement_command == "canary":
        return _engagement_canary(args, view)
    if args.engagement_command == "marking":
        return _engagement_marking(args, view)
    if args.engagement_command == "preflight":
        return _engagement_preflight(args, view)
    if args.engagement_command == "recheck":
        return _engagement_recheck(args, view)
    if args.engagement_command == "attest":
        return _engagement_attest(args, view)
    if args.engagement_command == "history":
        return _engagement_history(args, view)
    if args.engagement_command == "intake":
        return _engagement_intake(args, view)
    if args.engagement_command == "purge":
        return _engagement_purge(args, view)
    try:
        held = engagement_files.load(args.engagement_file)
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    if args.json:
        emit(json.loads(engagement_files.to_json(held)))
    else:
        rendered = engagement_files.render(held)
        emit_text(rendered if rendered.endswith("\n") else rendered + "\n")
    if not args.quiet:
        what = (
            f"a draft, {len(held.placeholders)} placeholder(s) still to fill in; the gate "
            "refuses every run under it"
            if held.is_draft
            else "read whole"
        )
        view.notice(f"engagement {display(held.id)}: {what}; digest {held.digest}")
    return 0


def _engagement_stop(args, view: TerminalView) -> int:
    """``engagement stop``: write the stop file beside the engagement file, or with ``--clear``
    remove it. The engagement file is not read for its permissions: a file that cannot be read is
    still stopped (its masking keys and values are then not known, and the reason is masked
    without them)."""
    file = args.engagement_file
    if not file.is_file():
        view.notice(f"refused: {display(str(file), limit=120)} is not an engagement file here")
        return EXIT_REFUSED
    path = engagement_files.stop_path(file)
    shown = display(str(path), limit=160)
    if args.clear:
        if args.reason is not None:
            view.notice("refused: --reason belongs to writing the stop file, not to --clear")
            return EXIT_REFUSED
        try:
            removed = engagement_files.clear_stop_file(path)
        except OSError as refusal:
            view.notice(f"refused: {shown} cannot be removed: {display(refusal.strerror)}")
            return EXIT_REFUSED
        if not args.quiet:
            view.notice(
                f"{shown} removed: runs under the engagement may start again"
                if removed
                else f"there is no stop file {shown}: nothing to remove"
            )
        return 0
    try:
        loaded = engagement_files.load(file)
    except EngagementError:
        masker = run_masker(())
    else:
        masker = run_masker(list(loaded.mask_keys), held=loaded)
    try:
        engagement_files.write_stop_file(
            path, reason=args.reason, masker=masker, now=datetime.now(timezone.utc)
        )
    except OSError as refusal:
        view.notice(f"refused: {shown} cannot be written: {display(refusal.strerror)}")
        return EXIT_REFUSED
    if not args.quiet:
        view.notice(
            f"{shown} written: every run under the engagement is refused, and a run going on "
            "ends in order; remove it with engagement stop FILE --clear"
        )
    return 0


def _engagement_status(args, view: TerminalView) -> int:
    """``engagement status``: the store read-only, the refusals under ``--out-dir``; nothing is
    written and nothing is started."""
    try:
        with Store.open_read_only(args.store) as store:
            standing = report.status(
                store,
                manifest=args.manifest,
                out_dir=args.out_dir,
                now=datetime.now(timezone.utc),
            )
    except (
        StoreError,
        ManifestError,
        EngagementError,
        report.ReportError,
        sqlite3.Error,
        OSError,
    ) as refusal:
        view.notice(f"refused: {args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    if args.json:
        emit(standing.to_dict())
    else:
        rendered = report.render_status(standing)
        emit_text(rendered if rendered.endswith("\n") else rendered + "\n")
    return standing.exit_code


def _engagement_compare(args, view: TerminalView) -> int:
    """``engagement compare``: two recordings read, one table (or JSON) on stdout; nothing is
    sent and nothing is written. A refusal is one line naming the reason, never a value."""
    try:
        one = identity_compare.load(args.run_a, "A")
        other = identity_compare.load(args.run_b, "B")
        compared = identity_compare.compare(one, other)
    except identity_compare.Refused as refusal:
        view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    if args.json:
        emit(compared.to_dict(display))
    else:
        emit_text(compared.render(display))
    if not args.quiet:
        for label, held in (("A", one), ("B", other)):
            if not held.complete:
                view.notice(f"run {label} is {held.state}: not a result; compared all the same")
        view.notice(f"compared {len(compared.calls)} tool call(s); {identity_compare.OBSERVATION}")
    return compared.exit_code


#: An ID is never cut short in ``engagement canary`` and ``marking`` (an ID is at most 64
#: characters); this is the bound for a value that is none. A place is not bound by it.
ID_LIMIT = 400

#: Said after a place in the text output when ``display`` had to take characters out of it.
NOT_PRINTABLE = "(not printable as given; --json has it exactly)"


def _place_line(label: str, value: str) -> str:
    """A place (``where``, ``path``) for the text output: whole, with the invisible characters
    taken out, and the fixed note when what is shown is not the value."""
    shown = display(value, limit=len(value) + 1)
    return f"  {label}: {shown}" + ("" if shown == value else f" {NOT_PRINTABLE}")


def _engagement_canary(args, view: TerminalView) -> int:
    """``engagement canary``: the canaries of the file with their values, on stdout. The values are
    the output; they never go to stderr. Nothing is written."""
    try:
        held = engagement_files.load(args.engagement_file)
        salt = marking.checked_salt(held.salt_env, engagement_salt(held))
        if not held.canaries:
            raise marking.Refused("the file lists no canaries")
        chosen = [item for item in held.canaries if args.id in (None, item.id)]
        if not chosen:
            raise marking.Refused("the file lists no canary with this ID")
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    except marking.Refused as refusal:
        view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    values = {item.id: marking.canary_value(salt, held.id, item.id) for item in chosen}
    if args.json:
        emit(
            {
                "engagement": display(held.id, limit=ID_LIMIT),
                "canaries": [
                    {
                        "id": display(item.id, limit=ID_LIMIT),
                        "kind": item.kind,
                        # exactly as in the file; emit escapes what is not printable
                        "where": item.where,
                        "path": item.path,
                        "value": values[item.id],
                    }
                    for item in chosen
                ],
            }
        )
    else:
        lines = []
        for item in chosen:
            lines.append(f"{display(item.id, limit=ID_LIMIT)} ({item.kind})")
            lines.append(
                _place_line("where", item.where) if item.where else "  where: not yet given"
            )
            if item.path is not None:
                lines.append(_place_line("path", item.path))
            lines.append(f"  value: {values[item.id]}")
        emit_text("\n".join(lines) + "\n")
    if not args.quiet:
        view.notice(f"{len(chosen)} canary value(s) on stdout; nothing was written")
    return 0


def _engagement_marking(args, view: TerminalView) -> int:
    """``engagement marking``: one recording read, the result on stdout; nothing is sent and
    nothing is written. A refusal is one line naming the reason, never a value."""

    def show(value: object) -> str:
        return display(value, limit=ID_LIMIT)

    try:
        patterns = marking.load_patterns()
        if args.engagement is not None:
            held = engagement_files.load(args.engagement)
            salt = marking.checked_salt(held.salt_env, engagement_salt(held))
            if not held.canaries:
                raise marking.Refused("the file lists no canaries")
            values = marking.canary_values(held, salt)
            earlier = marking.earlier_values(values)
            engagement_id = held.id
        else:
            values = marking.read_values(args.canaries_file)
            earlier = None
            engagement_id = None
        result = marking.read(
            args.run, values, patterns, engagement_id=engagement_id, earlier=earlier
        )
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    except marking.Refused as refusal:
        view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    if args.json:
        emit(result.to_dict(show))
    else:
        emit_text(result.render(show))
    if not args.quiet:
        view.notice(f"{len(result.deliveries)} delivery(ies); {marking.OBSERVATION}")
    return 0


def _engagement_preflight(args, view: TerminalView) -> int:
    """``engagement preflight``: each item ready, not ready or not checked; no target is
    contacted and nothing is written. Docker is asked for the images' ids, locally."""
    try:
        result = report.preflight(
            args.engagement_file,
            manifest=args.manifest,
            store=args.store,
            out_dir=args.out_dir,
            sandbox_image=args.sandbox_image,
            target_image=args.target_image,
            now=datetime.now(timezone.utc),
        )
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    if args.json:
        emit(result.to_dict())
    else:
        rendered = report.render_preflight(result)
        emit_text(rendered if rendered.endswith("\n") else rendered + "\n")
    return result.exit_code


def _evidence_redact(args, view: TerminalView) -> int:
    """``evidence redact``: the handover bundle, written whole, then filed in the store with the
    bundle it derives from."""
    if not args.store.is_file():
        view.notice(f"refused: {args.store}: no such store; the handover bundle is filed in it")
        return EXIT_REFUSED
    # The handover bundle is filed in the store of the bundle it derives from, and in no other:
    # purge and attest look for it there.
    try:
        index = evidence.read_index(Path(args.bundle) / evidence.INDEX_FILE)
        with Store.open_read_only(args.store) as store:
            held = store.engagement()
    except (evidence.EvidenceError, StoreError, sqlite3.Error, OSError) as refusal:
        view.notice(refusal_words(refusal), limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    chain = [] if held is None else [entry["digest"] for entry in held["chain"]]
    if index.engagement_digest not in chain:
        view.notice(
            f"refused: {args.store} does not hold the engagement the bundle was packed under "
            f"(digest {index.engagement_digest}); the handover bundle is filed in that "
            "engagement's store",
            limit=STORE_NOTICE_LIMIT,
        )
        return EXIT_REFUSED
    # Every recording, and a placed script, is checked again for every credential of the
    # engagement file as it can be read now, the salt and the known values. A credential that
    # cannot be read here, or a salt variable the file names that is not set, refuses a bundle
    # with a script: nothing but this check stands between a script and the customer. A bundle
    # of recordings only is checked for what can be read, and once it is written a warning names
    # what could not be: its recordings were masked when they were made. A credential that
    # changed since the bundle was packed is not known here: what drive masked in the runs was
    # made the floor of the script when it was packed (evidence.pack).
    unchecked = None
    try:
        loaded = engagement_files.load(args.engagement)
        values, names, unreadable = engagement_credentials(loaded)
        if any(entry.role == "script" for entry in index.files):
            refusal = _script_masker_refusal(loaded, unreadable)
            if refusal is not None:
                view.notice(refusal, limit=STORE_NOTICE_LIMIT)
                return EXIT_REFUSED
        else:
            unchecked = _unchecked_words(loaded, unreadable)
        masker = pack_masker(loaded, values, names)
        made = evidence.redact(
            args.bundle,
            engagement_path=args.engagement,
            out=args.out,
            mask_keys=tuple(args.mask_key),
            masker=masker,
        )
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        message = message if message.startswith("refused") else f"refused: {message}"
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    except (evidence.EvidenceError, StoreError, sqlite3.Error, OSError) as refusal:
        text = str(refusal)
        view.notice(text if text.startswith("refused") else f"refused: {text}", limit=10_000)
        return EXIT_REFUSED
    if unchecked is not None:
        view.notice(unchecked, limit=STORE_NOTICE_LIMIT)
    for advisory in made.advisories:
        view.notice(f"warning: {advisory.message}")
    emit(made.to_dict())
    try:
        with Store.open(args.store) as store:
            store.file_bundle(
                index_digest=made.index_digest,
                path=str(Path(made.path).absolute()),
                packed_utc=made.packed_utc,
                derived_from=made.derived_from,
                engagement_digest=made.engagement_digest,
            )
    except (StoreError, sqlite3.Error) as refusal:
        view.notice(
            f"redacted {made.path}, but the store did not file it ({refusal}); the bundle stands "
            "as written",
            limit=STORE_NOTICE_LIMIT,
        )
        return EXIT_INCOMPLETE
    if not args.quiet:
        view.notice(
            f"handover bundle {display(str(made.path), limit=120)}: index {made.index_digest}, "
            f"derived from {made.derived_from}; {made.values_redacted} value(s) blanked by "
            f"{made.rules} rule(s); CUSTOMER-README.md beside its index",
            limit=STORE_NOTICE_LIMIT,
        )
    return 0


def refusal_words(refusal: BaseException) -> str:
    """A refusal's words, prefixed ``refused:`` once: some say so themselves."""
    text = str(refusal)
    return text if text.startswith("refused") else f"refused: {text}"


def inside_run_directory(path: Path) -> Path | None:
    """The run directory ``path`` would lie in — a directory above it that holds a recording —
    or None. Nothing this tool writes beside the recorder goes into one."""
    for directory in Path(path).absolute().parents:
        if (directory / "events.jsonl").exists():
            return directory
    return None


def write_once(view: TerminalView, out: Path, data: bytes) -> bool:
    """Write a document once, ``0600``, to a file that does not exist yet, its directory made
    ``0700`` where missing; False after saying why it was not written."""
    try:
        make_private_directories(out.parent)
        descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        view.notice(f"refused: {out}: {exc.strerror or exc}")
        return False
    return True


def refused_destination(view: TerminalView, out: Path, what: str) -> bool:
    """Whether ``out`` is refused as a destination — it exists, or lies in a git working tree —
    after saying so; nothing is written then."""
    if out.exists() or out.is_symlink():
        view.notice(f"refused: {out} exists; {what} is written once, never over another")
        return True
    run_directory = inside_run_directory(out)
    if run_directory is not None:
        view.notice(
            f"refused: {out} lies in the run directory {run_directory}; nothing but the "
            "recording is written into one"
        )
        return True
    for advisory in inspect_destination(out.parent, out.parent):
        if advisory.severity is Severity.REFUSAL:
            view.notice(f"refused: {advisory.message}")
            return True
    return False


def _engagement_recheck(args, view: TerminalView) -> int:
    """``engagement recheck``: commands, or the outcome of a re-check run; runs nothing and
    writes nothing."""
    identities = None
    if args.identity is not None:
        try:
            identities = [json.loads(text) for text in args.identity]
        except ValueError as exc:
            view.notice(f"refused: --identity is not JSON: {exc}")
            return EXIT_REFUSED
    try:
        result = report.recheck(
            store=args.store,
            engagement_path=args.engagement,
            runs_dir=args.runs,
            identities=identities,
            finding_ids=args.finding,
            all_fixed_pending=args.all_fixed_pending,
            after=args.after,
        )
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    except (StoreError, report.ReportError, sqlite3.Error, OSError) as refusal:
        view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    if args.json:
        emit(result.to_dict())
    else:
        rendered = report.render_recheck(result)
        emit_text(rendered if rendered.endswith("\n") else rendered + "\n")
    return result.exit_code


def _engagement_attest(args, view: TerminalView) -> int:
    """``engagement attest``: built from recorded facts, read back through its own parser, and
    written once, ``0600``."""
    out = Path(args.out)
    if refused_destination(view, out, "an attestation"):
        return EXIT_REFUSED
    try:
        made = report.attest(
            store=args.store,
            engagement_path=args.engagement,
            bundle_dir=args.bundle,
            runs_dir=args.runs,
            now=datetime.now(timezone.utc),
        )
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    except (StoreError, report.ReportError, evidence.EvidenceError, sqlite3.Error, OSError) as e:
        view.notice(refusal_words(e), limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    text = report.render_attestation(made)
    try:
        report.parse_attestation(text)
    except report.ReportParseError as refusal:
        view.notice(
            f"refused: the attestation does not read back ({refusal}); nothing was written",
            limit=STORE_NOTICE_LIMIT,
        )
        return EXIT_REFUSED
    data = text.encode("utf-8")
    if not write_once(view, out, data):
        return EXIT_REFUSED
    if not args.quiet:
        view.notice(
            f"attestation {display(str(out), limit=120)} written: sha256 "
            f"{hashlib.sha256(data).hexdigest()}; no finding and no triage row in it",
            limit=STORE_NOTICE_LIMIT,
        )
    return 0


def _engagement_intake(args, view: TerminalView) -> int:
    """``engagement intake``: the questionnaire, or a draft engagement file from its answers;
    written once, ``0600``. A draft runs nothing: the gate refuses it (condition ``draft``)."""
    out = Path(args.out)
    if args.answers is None:
        if args.engagement_id is not None:
            view.notice("refused: --id belongs to --from: a questionnaire names no engagement")
            return EXIT_REFUSED
        if refused_destination(view, out, "a questionnaire"):
            return EXIT_REFUSED
        text = intake.questionnaire_text() if args.text else intake.questionnaire()
        if not write_once(view, out, text.encode("utf-8")):
            return EXIT_REFUSED
        if not args.quiet:
            view.notice(f"questionnaire {display(str(out), limit=120)} written")
        return 0
    if args.text:
        view.notice("refused: --text belongs to the questionnaire, not to --from")
        return EXIT_REFUSED
    if args.engagement_id is None:
        view.notice("refused: --from needs --id, the engagement's id")
        return EXIT_REFUSED
    if refused_destination(view, out, "a draft"):
        return EXIT_REFUSED
    try:
        answers = intake.read_answers(args.answers)
        text, missing = intake.draft(answers, engagement_id=args.engagement_id)
    except intake.IntakeError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    if not write_once(view, out, text.encode("utf-8")):
        return EXIT_REFUSED
    if not args.quiet:
        if answers.unplaced:
            view.notice(
                f"{len(answers.unplaced)} line(s) of the text form placed nowhere, kept verbatim "
                "under declared.notes"
            )
        view.notice(
            f"draft {display(str(out), limit=120)} written; still to fill in before the gate "
            f"lets anything run under it ({len(missing)}):"
        )
        for item in missing:
            view.notice(f"  {display(item, limit=160)}")
    return 0


def _engagement_history(args, view: TerminalView) -> int:
    """``engagement history``: every store read through ``mode=ro``, every time; one that cannot
    be read is listed as such, never skipped."""
    result = report.dossier(customer=args.customer, stores=list(args.store))
    if args.json:
        emit(result.to_dict())
    else:
        rendered = report.render_dossier(result)
        emit_text(rendered if rendered.endswith("\n") else rendered + "\n")
    return result.exit_code


def _engagement_purge(args, view: TerminalView) -> int:
    """``engagement purge``: refused whole before anything is deleted, or every path deleted and
    its outcome written to ``purged.json``."""
    try:
        purged = evidence.purge(
            store_path=args.store,
            out_dir=args.out_dir,
            author=args.author,
            out=args.out,
            before_retention_reason=args.before_retention,
            salt_deleted=args.salt_deleted,
        )
    except (evidence.EvidenceError, StoreError, sqlite3.Error, OSError) as refusal:
        view.notice(refusal_words(refusal), limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    emit(purged.to_dict())
    stayed = [item for item in purged.paths if not item.gone]
    for item in stayed:
        view.notice(f"not gone: {display(item.path, limit=120)}: {display(item.outcome)}")
    if not args.quiet:
        view.notice(
            f"purged engagement {display(purged.engagement_id_declared)}: "
            f"{len(purged.paths) - len(stayed)} of {len(purged.paths)} path(s) gone; "
            f"{display(str(args.out), limit=120)} written"
        )
    return 0 if purged.complete else EXIT_INCOMPLETE


def _evidence(args, view: TerminalView) -> int:
    """The evidence subcommands: ``pack`` writes a new bundle and files it in the store's
    ``bundles``; ``verify`` and ``review`` read a bundle and write nothing; ``redact`` writes a
    second bundle and files it, the first untouched."""
    if args.evidence_command == "review":
        try:
            found = evidence.review(args.bundle)
        except evidence.EvidenceError as refusal:
            view.notice(refusal_words(refusal), limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
        emit(found.to_dict())
        if not args.quiet and not found.complete:
            view.notice(
                "strings lie outside the listed surfaces (counted per message): a review of the "
                "listed ones is not a review of every byte"
            )
        return 0
    if args.evidence_command == "redact":
        return _evidence_redact(args, view)
    if args.evidence_command == "replay":
        return _evidence_replay(args, view)
    if args.evidence_command == "verify":
        try:
            found = evidence.verify(args.bundle, index_digest=args.index_digest)
        except evidence.EvidenceError as refusal:
            view.notice(refusal_words(refusal), limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
        emit(found.to_dict())
        if not args.quiet:
            view.notice(found.summary(), limit=STORE_NOTICE_LIMIT)
        return 0 if found.intact else EXIT_INCOMPLETE
    try:
        held = engagement_files.load(args.engagement)
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    # A script is masked with the engagement's masker, the --mask-key names its runs recorded,
    # and every credential of the engagement file as it can be read now and the salt as
    # literals. Then drive's masking is the floor (evidence.pack): wherever a call its runs
    # recorded holds a masked form, the script keeps only exactly what the recording holds there,
    # and is blanked otherwise, whatever changed since the run. A credential that cannot be read
    # here, or a salt variable the file names that is not set, refuses the pack before anything
    # is read.
    masker_for = None
    if args.script:
        values, names, unreadable = engagement_credentials(held)
        refusal = _script_masker_refusal(held, unreadable)
        if refusal is not None:
            view.notice(refusal, limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED

        def masker_for(keys: Sequence[str]) -> Masker:
            return pack_masker(held, values, names, keys)

    try:
        packed = evidence.pack(
            engagement=held,
            store_path=args.store,
            runs_dir=args.runs,
            sessions=args.session,
            report=args.report,
            out=args.out,
            manifests=args.manifest,
            scripts=args.script,
            masker_for=masker_for,
        )
    except (StoreError, evidence.EvidenceError, sqlite3.Error, OSError) as refusal:
        text = str(refusal)
        view.notice(text if text.startswith("refused") else f"refused: {text}", limit=10_000)
        return EXIT_REFUSED
    for advisory in packed.advisories:
        view.notice(f"warning: {advisory.message}")
    for line in (
        *packed.scripts_unplaced,
        *packed.scripts_own_pseudonyms,
        *packed.scripts_not_replayable,
    ):
        view.notice(line, limit=1_000)
    # The bundle is written whole before it is named in the store; a store that will not name it
    # leaves the bundle as it is, and says so.
    try:
        if not args.store.is_file():
            # Store.open would create one: the bundle is filed in the store it was packed from.
            raise StoreError(f"{args.store}: no such store any more")
        with Store.open(args.store) as store:
            store.file_bundle(
                index_digest=packed.index_digest,
                path=str(Path(packed.path).absolute()),
                packed_utc=packed.packed_utc,
                derived_from=packed.derived_from,
                engagement_digest=packed.engagement_digest,
            )
    except (StoreError, sqlite3.Error) as refusal:
        emit(packed.to_dict())
        view.notice(
            f"packed {packed.path}, but the store did not file it ({refusal}); the bundle stands "
            "as written",
            limit=STORE_NOTICE_LIMIT,
        )
        return EXIT_INCOMPLETE
    emit(packed.to_dict())
    if not args.quiet:
        view.notice(
            f"packed {display(str(packed.path), limit=120)}: index {packed.index_digest}; "
            + ", ".join(f"{count} {role}" for role, count in packed.counts.items() if count),
            limit=STORE_NOTICE_LIMIT,
        )
    return 0


def _evidence_replay(args, view: TerminalView) -> int:
    """``evidence replay``: the bundle is verified, the run's script and options are read from
    it, and ``drive`` is run with them under the operator's own engagement file — through the
    same gate as any drive."""
    try:
        plan = evidence.replay_plan(
            args.bundle,
            run=args.run,
            engagement_path=args.engagement,
            manifest=args.manifest,
            index_digest=args.index_digest,
        )
    except evidence.EvidenceError as refusal:
        view.notice(refusal_words(refusal), limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    arguments = [
        "drive",
        *(["-q"] if args.quiet else []),
        "--engagement",
        str(args.engagement),
        "--out-dir",
        str(args.out_dir),
        *(["--engagement-confirmed"] if args.engagement_confirmed else []),
        *plan.arguments,
    ]
    return _main(arguments)


def _report_engagement(args, view: TerminalView) -> int:
    """``report``: built from the store (read-only), the recordings under ``--runs`` and the
    refusals under ``--out-dir``; read back through ``report.parse`` before it is written, and
    written once, ``0600``, to a file that did not exist."""
    out = Path(args.out)
    if refused_destination(view, out, "a report"):
        return EXIT_REFUSED
    advisories = inspect_destination(out.parent, out.parent)
    try:
        built = report.build(
            engagement_path=args.engagement,
            store=args.store,
            runs_dir=args.runs,
            out_dir=args.out_dir,
            previous=args.previous,
            manifest=args.manifest,
            now=datetime.now(timezone.utc),
        )
    except EngagementError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    except (StoreError, report.ReportError, ManifestError, sqlite3.Error, OSError) as refusal:
        view.notice(f"refused: {refusal}", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    text = report.render(built)
    # Read what is written back: a report its own reader cannot place is not written.
    try:
        report.parse(text)
    except report.ReportParseError as refusal:
        view.notice(
            f"refused: the report does not read back ({refusal}); nothing was written",
            limit=STORE_NOTICE_LIMIT,
        )
        return EXIT_REFUSED
    data = text.encode("utf-8")
    if not write_once(view, out, data):
        return EXIT_REFUSED
    for advisory in advisories:
        view.notice(f"warning: {advisory.message}")
    if not args.quiet:
        whole = (
            "every run it uses is complete"
            if built.complete
            else ("a run it uses is not complete, and it says so where that run is used")
        )
        view.notice(
            f"report {display(str(out), limit=120)} written: sha256 "
            f"{hashlib.sha256(data).hexdigest()}; {whole}",
            limit=STORE_NOTICE_LIMIT,
        )
    return built.exit_code


def _fleet(args, view: TerminalView, argv: Sequence[str]) -> int:
    """The fleet subcommands. Machine output on stdout, a summary in words on stderr."""
    # Under an engagement file, the file first, then every job held to it — before the store is
    # opened and before the images are pinned, which starts docker. From the file on, a refusal
    # of the fleet is written to refusals.jsonl in --out-dir, as a run's is.
    held = None
    masker = Masker(extra_keys=[])
    if args.fleet_command == "run" and args.engagement is not None:
        try:
            held = engagement_files.load(args.engagement)
        except EngagementError as refusal:
            message = manifest_refusal(refusal)
            view.notice(message, limit=len(message))
            return EXIT_REFUSED
        # The masker of a run, with the known values and the salt: a refusal never writes a
        # known value, whether it stands in a name, in --manifest, --out-dir or --store.
        masker = run_masker(list(held.mask_keys), held=held)

    def refused(reason: str, message: str) -> int:
        view.notice(masker.mask_text(message)[0], limit=STORE_NOTICE_LIMIT)
        if held is not None:
            write_refusal(view, held, args.out_dir, argv, masker, reason, message)
        return EXIT_REFUSED

    # The names in the manifest stand unmasked in the store and the run directories, so one that
    # holds a known value refuses the fleet, as it refuses a run: before the gate, whose words
    # name entries, before the store is opened and before anything is pinned. The words name the
    # place in the manifest, never the name.
    if held is not None:
        for place, name in fleet.manifest_names(args.manifest):
            if masker.holds_known_value(name):
                return refused(
                    "name_holds_known_value",
                    f"{place} holds a value the engagement knows or a literal of this run; "
                    "name entries and scenarios by something other than the customer",
                )

    # The path of --manifest stands unmasked in the store (fleets.manifest_source), in fleet.json
    # and on stdout, and in each run's run_started: refused the same way, as it was given and as
    # the manifest records it, if that is another text. The words name the flag, never the path.
    if held is not None:
        paths = [str(args.manifest)]
        with contextlib.suppress(ValueError):  # the gate says why
            paths.append(load_manifest(args.manifest).source)
        if any(masker.holds_known_value(path) for path in paths):
            return refused(
                "name_holds_known_value",
                "--manifest holds a value the engagement knows or a literal of this run; "
                "keep the manifest in a directory named by something other than the customer",
            )

    # The path of --out-dir stands unmasked in the store, which holds the path of each recording
    # (the column recording) and, for a run filed with a refusal, in result.problems. Refused the
    # same way, for a fleet run, before the gate and before the store is opened.
    if held is not None and masker.holds_known_value(str(args.out_dir)):
        return refused(
            "name_holds_known_value",
            "--out-dir holds a value the engagement knows or a literal of this run; "
            "keep the runs in a directory named by something other than the customer",
        )

    if args.fleet_command == "run":
        try:
            fleet.gate(args.manifest, held)
        except fleet.FleetError as refusal:
            return refused(refusal.condition or "fleet", str(refusal))
    try:
        store = Store.open(args.store)
    except (StoreError, sqlite3.Error, OSError) as refusal:
        return refused("store", f"{args.store}: {refusal}")
    with store:
        if args.fleet_command == "runs":
            listed = [{k: v for k, v in info.items() if k != "results"} for info in store.fleets()]
            emit(listed)
            return 0
        if args.fleet_command == "diff":
            return _fleet_diff(store, args, view)
        # A store that is an engagement's takes no fleet run without that engagement's file:
        # every run would be refused at filing, after the whole corpus had been run for nothing.
        holds = store.engagement() if held is None else None
        if holds is not None:
            return refused(
                "fleet",
                f"{args.store}: this store holds engagement "
                f"{display(holds['engagement_id_declared'])} (digest {holds['engagement_digest']})"
                " and files only runs made under it; run the fleet with --engagement and that "
                "file, or into a store of its own. Nothing was started.",
            )
        try:
            pins = fleet.pin(args.sandbox_image, args.target_image)
            record = fleet.run(
                args.manifest,
                store,
                args.out_dir,
                pins=pins,
                parallel=args.parallel,
                step_timeout=args.step_timeout,
                job_timeout=args.job_timeout,
                client_settle_timeout=args.client_settle_timeout,
                engagement=held,
            )
        except fleet.FleetError as refusal:
            return refused(refusal.condition or "fleet", str(refusal))
        before = fleet.previous(store, record.fleet)
        compared = None if before is None else fleet.compare(store, before, record.fleet)
        emit({"fleet": record.to_dict(), "diff": compared})
        if not args.quiet:
            _report_fleet(view, record, compared)
        return verdict.EXIT_CODES[record.state]


def _fleet_diff(store: Store, args, view: TerminalView) -> int:
    try:
        if args.before is None and args.after is None:
            ids = [info["fleet"] for info in store.fleets()]
            if len(ids) < 2:
                raise StoreError("fewer than two fleet runs in the store")
            before, after = ids[-2], ids[-1]
        elif args.before is None or args.after is None:
            raise StoreError("give both fleet runs, or neither for the last two")
        else:
            before, after = store.resolve_fleet(args.before), store.resolve_fleet(args.after)
        compared = fleet.compare(store, before, after)
    except StoreError as refusal:
        view.notice(str(refusal))
        return EXIT_REFUSED
    emit(compared)
    if not args.quiet:
        _report_fleet_diff(view, compared)
    return 0 if compared["complete"] else EXIT_INCOMPLETE


def _web(args, view: TerminalView) -> int:
    """The web interface: every source checked, the port taken, then served until Ctrl-C.

    The sources are checked before the port is taken, as a run's destination is before anything
    starts: a refused start leaves nothing listening. Only that a source can be opened is
    checked here; a manifest or a scenario its loader refuses is shown refused, in its view.
    Nothing is written to stdout, and while serving nothing to stderr but a view's failure —
    there is no request log, and the start line is the one place the token is printed. Ctrl-C
    ends it as any command of ours: :func:`main` says so and exits with
    :data:`EXIT_INTERRUPTED`, the socket closed on the way out.
    """
    if args.store is not None:
        try:
            Store.open_read_only(args.store).close()
        except StoreError as refusal:
            view.notice(str(refusal), limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
        except (sqlite3.Error, OSError) as refusal:
            view.notice(f"{args.store}: {refusal}", limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
    if args.runs is not None and not args.runs.is_dir():
        view.notice(f"--runs {args.runs}: not a directory", limit=STORE_NOTICE_LIMIT)
        return EXIT_REFUSED
    for option, paths in (
        ("--manifest", args.manifest),
        ("--scenario", args.scenario),
        ("--attestation", args.attestation),
    ):
        for path in paths:
            if not path.is_file():
                view.notice(f"{option} {path}: not a file", limit=STORE_NOTICE_LIMIT)
                return EXIT_REFUSED
    for path in args.bundle:
        if not path.is_dir():
            view.notice(f"--bundle {path}: not a directory", limit=STORE_NOTICE_LIMIT)
            return EXIT_REFUSED
    sources = web_server.Sources(
        store=args.store,
        runs=args.runs,
        manifests=tuple(args.manifest),
        scenarios=tuple(args.scenario),
        bundles=tuple(args.bundle),
        attestations=tuple(args.attestation),
    )
    try:
        server = web_server.make_server(sources, args.bind, args.port)
    except OSError as refusal:
        view.notice(f"cannot listen on {args.bind} port {args.port}: {refusal.strerror or refusal}")
        return EXIT_REFUSED
    with server:
        if args.quiet:
            print(server.start_url, file=sys.stderr, flush=True)
        else:
            given = [
                f"{option} {display(path, limit=80)}"
                for option, path in (("--store", args.store), ("--runs", args.runs))
                if path is not None
            ]
            if args.manifest:
                given.append(f"{len(args.manifest)} manifest(s)")
            if args.scenario:
                given.append(f"{len(args.scenario)} scenario file(s)")
            if args.bundle:
                given.append(f"{len(args.bundle)} bundle(s)")
            if args.attestation:
                given.append(f"{len(args.attestation)} attestation(s)")
            what = ", ".join(given) or "no source (each view says which option to give)"
            line = (
                f"serving {what} read-only on {server.start_url} — a local viewer for this "
                "machine's user, no TLS"
            )
            view.notice(line, limit=len(line) + 1)
        server.serve_forever()
    return 0


def _report_fleet(view: TerminalView, record, compared) -> None:
    states: dict[str, int] = {}
    for result in record.results.values():
        states[result.state] = states.get(result.state, 0) + 1
    view.notice(
        f"fleet {record.fleet}: {len(record.results)} run(s), "
        + ", ".join(f"{state} {n}" for state, n in sorted(states.items()))
        + f"; {record.state}"
    )
    for key in sorted(record.results):
        result = record.results[key]
        if result.state != verdict.COMPLETE:
            reason = result.problems[0] if result.problems else ""
            causes = f" [{', '.join(result.causes)}]" if result.causes else ""
            view.notice(
                f"  {display(result.entry, limit=40)}/{display(result.scenario, limit=40)}: "
                f"{result.state}{causes} {display(reason, limit=120)}"
            )
    for problem in record.problems[:5]:
        view.notice(f"  fleet problem: {display(problem, limit=200)}")
    if compared is None:
        view.notice("the first fleet run in this store: nothing to compare with")
    else:
        _report_fleet_diff(view, compared)


def _report_fleet_diff(view: TerminalView, compared) -> None:
    moved = [name for name, axis in compared["axes"].items() if axis["moved"]]
    changed = [e for e in compared["entries"] if e["change"] != "compared" or e["new"] or e["gone"]]
    view.notice(
        f"against fleet {compared['before']}: "
        + ("the same result" if compared["same_result"] else f"{len(changed)} entr(y/ies) differ")
        + (f"; moved: {', '.join(moved)}" if moved else "")
        + ("" if compared["complete"] else "; INCOMPLETE comparison")
    )
    rules = compared["rules"]
    if rules["moved"]:
        view.notice(
            f"the two fleets were judged under different rules ({rules['before']} and "
            f"{rules['after']}): states, and so the result, may differ by the rules alone"
        )


def _report_diff(view: TerminalView, result, *, quiet: bool) -> None:
    if quiet:
        return
    view.notice(
        f"{len(result.new)} new, {len(result.gone)} gone, {len(result.unchanged)} unchanged"
        + (f"; moved between the runs: {', '.join(result.moved)}" if result.moved else "")
    )
    view.notice(display(result.attribution.note, limit=200))
    if result.rules["moved"]:
        view.notice(
            f"the two runs were judged under different rules ({result.rules['before']} and "
            f"{result.rules['after']}): their states may differ by the rules alone"
        )
    new, gone = result.caveats.get("new", ()), result.caveats.get("gone", ())
    for caveat in dict.fromkeys((*new, *gone)):
        sets = " and ".join(
            name for name, flags in (("new", new), ("gone", gone)) if caveat in flags
        )
        view.notice(f"caveat on {sets}: {caveat}", limit=400)
    if not result.complete:
        view.notice(
            "at least one run is incomplete: a finding it lacks may be missing rather than gone"
        )


#: How many definitions of one kind and one change ``store diff`` names on the terminal; the
#: JSON on stdout holds them all.
MAX_DEFINITIONS_NAMED = 20


def _definition_lines(sets: dict, prefix: str) -> list[str]:
    """The terminal lines for added, removed and changed definitions: names, and for a changed
    one the names of its fields — never a value. A name that occurs more than once in a listing
    is a hint of its own (``duplicate``), not a change: it carries the number of occurrences on each
    side, and ``(partial)`` behind the number of a side whose listing was read only in part."""
    lines = []
    for change in ("added", "removed", "changed"):
        for entry in sets[change][:MAX_DEFINITIONS_NAMED]:
            fields = (
                f" ({', '.join(display(f) for f in entry['fields'])})" if "fields" in entry else ""
            )
            doubled = " [name listed more than once]" if entry["duplicate"] else ""
            lines.append(f"{prefix}{change} {display(entry['name'], limit=80)}{fields}{doubled}")
        more = len(sets[change]) - MAX_DEFINITIONS_NAMED
        if more > 0:
            lines.append(f"{prefix}... and {more} more {change}")
    doubles = sets.get("duplicates", ())
    for entry in doubles[:MAX_DEFINITIONS_NAMED]:
        counts = ", ".join(
            f"{side}: {entry[side]}" + (" (partial)" if side in sets["partial"] else "")
            for side in entry
            if side not in ("name", "side")
        )
        lines.append(f"{prefix}duplicate {display(entry['name'], limit=80)} [{counts}]")
    if len(doubles) > MAX_DEFINITIONS_NAMED:
        lines.append(f"{prefix}... and {len(doubles) - MAX_DEFINITIONS_NAMED} more duplicates")
    return lines


def _partial_line(kind: str, sides: dict, where: str = "") -> str:
    """Which side of a comparison read a kind's listing only in part, and why."""
    said = "; ".join(
        f"{side}: {', '.join(display(r) for r in why['reasons'])}"
        + (f", {why['unreadable']} unreadable page(s)" if why["unreadable"] else "")
        for side, why in sides.items()
    )
    return (
        f"definitions ({kind}){where}: partial ({said}); a name missing from a partial "
        "listing is not called removed or added"
    )


def _report_definitions(view: TerminalView, observed: dict, *, quiet: bool) -> None:
    """What changed in the definitions, as an observation: counts, names and field names."""
    if quiet:
        return
    if "note" in observed:
        view.notice(f"definitions: {observed['note']}", limit=300)
    for kind, sets in observed["kinds"].items():
        if sets["state"] != "compared":
            if sets["state"] != "not listed in before and after":
                view.notice(f"definitions ({kind}): {sets['state']}")
            continue
        view.notice(
            f"definitions ({kind}): {len(sets['added'])} added, {len(sets['removed'])} removed, "
            f"{len(sets['changed'])} changed, {sets['unchanged']} unchanged"
        )
        if sets["partial"]:
            view.notice(_partial_line(kind, sets["partial"]), limit=300)
        for line in _definition_lines(sets, "  "):
            view.notice(line)
    for side in ("before", "after"):
        for kind, pairs in observed["within_run"][side].items():
            for pair in pairs:
                view.notice(
                    f"definitions ({kind}), within the {side} run, segment {pair['from_segment']} "
                    f"to {pair['to_segment']}: {len(pair['added'])} added, "
                    f"{len(pair['removed'])} removed, {len(pair['changed'])} changed, "
                    f"{pair['unchanged']} unchanged"
                )
                if pair["partial"]:
                    view.notice(
                        _partial_line(kind, pair["partial"], f", within the {side} run"), limit=300
                    )
                for line in _definition_lines(pair, "  "):
                    view.notice(line)
        for kind, notified in observed["list_changed"][side].items():
            view.notice(
                f"{kind} {notified['status']} in the {side} run "
                f"({notified['count']} notification(s), first at seq {notified['first_seq']})"
                + (" but the new listing is partial" if "partial" in notified else "")
            )


def pin_images(sandbox_image: str, target_image: str) -> dict[str, tuple[str, str | None]]:
    """Each image as given and by its id, or None where Docker cannot say. Resolved once, here:
    a tag that moves during the run cannot change what the recording says ran."""
    pinned = {}
    for role, given in (("sandbox_image", sandbox_image), ("target_image", target_image)):
        try:
            pinned[role] = (given, docker.image_id(given))
        except docker.DockerError:
            pinned[role] = (given, None)
    return pinned


def http_refusal(args, server_command: Sequence[str]) -> str | None:
    """Why ``drive --http`` cannot run as given, or None. The server is already running, at
    an address: a command to start one, a corpus entry (which names a command) and an
    isolation (which wraps one) are three ways of saying something that is not there."""
    if server_command:
        return "--http drives a server that is already running: drop the -- command"
    for flag, value in (
        ("--manifest", args.manifest),
        ("--entry", args.entry),
        ("--isolation", args.isolation),
    ):
        if value is not None:
            return f"--http cannot be combined with {flag}: there is no server command to run"
    try:
        HttpClientChannel(args.http)  # reads the URL, and does nothing else
    except ValueError as refusal:
        return f"--http: {refusal}"
    # What the channel can drive, the recording may still not write down: refused here, not
    # in the writer, where it would leave a recording without its run_started.
    recorded = endpoint_refusal(args.http)
    if recorded is not None:
        return f"--http: {recorded}"
    return None


def select_corpus_entry(args, server_command: Sequence[str]):
    """The manifest, the entry and the scenario of a corpus run — or a refusal saying why."""
    if args.command != "drive":
        raise ManifestError("--manifest and --entry belong to drive")
    if args.manifest is None or args.entry is None:
        raise ManifestError("a corpus run needs both --manifest and --entry")
    if server_command or args.server_content or args.server_revision is not None:
        raise ManifestError(
            "a corpus run takes its server and its identity from the manifest; "
            "drop the -- command, --server-content and --server-revision"
        )
    manifest = load_manifest(args.manifest)
    entry = manifest.entry(args.entry)
    # Before anything else is looked at: the refusal is one of the conditions to start, not
    # a check made later. Raises for a real-world entry under every isolation there is.
    try:
        isolation = entry.isolation(args.isolation)
    except ManifestError as refusal:
        if refusal.source is not None:
            raise
        raise ManifestError(refusal.reason, source=manifest.source) from None
    return manifest, entry, entry.scenario(args.scenario), isolation


def _signals_list(args, view: TerminalView) -> int:
    """``signals list``: every signal and its kind, or with ``--reference`` every page.

    Only ``--reference`` reads the pages, all of them before it prints any: a page the
    installed package cannot read refuses the listing, named by its signal id, with nothing on
    stdout. The JSON names each page by its path in a bundle and needs none of them."""
    listed = list(signals.Signal)
    if args.reference:
        pages: list[str] = []
        for signal in listed:
            try:
                pages.append(signals.reference(signal))
            except (OSError, ValueError) as exc:
                message = f"{evidence.reference_page_refusal(signal, exc)}, and nothing was listed"
                view.notice(message, limit=len(message))
                return EXIT_REFUSED
        emit_text("\n".join(pages))
    else:
        emit(
            {
                "signals": [
                    {
                        "signal": signal.value,
                        "kind": signal.kind.value,
                        "reference": f"{evidence.REFERENCE_DIR}/{signal.value}.md",
                    }
                    for signal in listed
                ]
            }
        )
    if not args.quiet:
        view.notice(f"{len(listed)} signal(s)")
    return 0


def _corpus_check(args, view: TerminalView) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as refusal:
        message = manifest_refusal(refusal)
        view.notice(message, limit=len(message))
        return EXIT_REFUSED
    listing = {
        "manifest": {"source": manifest.source, "digest": manifest.digest},
        "tool": corpus_tool_identity(),
        "entries": [
            {
                "name": entry.name,
                "provenance": entry.provenance,
                "identity": entry.identity.to_dict(),
                "launch_digest": entry.launch_digest,
                "transport": entry.transport,
                "endpoint": entry.endpoint,
                "command": list(entry.command_written),
                "scenarios": [{"name": r.name, "digest": r.digest} for r in entry.scenarios],
                "isolation_permitted": (
                    [ENDPOINT_ISOLATION]
                    if entry.endpoint is not None
                    else list(PERMITTED[entry.provenance])
                ),
                "refused_here": entry.refusal_to_run(),
            }
            for entry in manifest.entries
        ],
    }
    emit(listing)
    if not args.quiet:
        view.notice(f"{manifest.source}: {len(manifest.entries)} entr(y/ies), valid")
    return 0


def select_server_identity(args) -> ServerIdentity | None:
    """The server's version for the finding key, from its files or its pinned repository.

    None when neither was given: the run is recorded, but its findings carry no server
    version, and the store refuses them rather than compare versions it does not have.
    """
    if args.server_content:
        return identity_from_content(args.server_content)
    if args.server_revision is not None:
        return identity_from_revision(args.server_revision)
    return None


class _EraRecords:
    """What a proxy that a driver feeds records of the opening: the decision of the era detection
    and a listing asked for again. Non-droppable, like every event the client half writes."""

    async def record_era_decided(self, **fields) -> None:
        await self._sink.put(partial(self._recorder.era_decided, **fields), kind="era_decided")

    async def record_token_observation(self, **fields) -> None:
        await self._sink.put(
            partial(self._recorder.token_observation, **fields), kind="token_observation"
        )

    async def record_step_reissued(self, *, step: str, page: int, reason: str) -> None:
        await self._sink.put(
            partial(self._recorder.step_reissued, step=step, page=page, reason=reason),
            kind="step_reissued",
        )


class _DrivenProxy(_EraRecords, Proxy):
    pass


class _DrivenHttpProxy(_EraRecords, HttpProxy):
    pass


def _opening(held, http_url: str | None) -> Opening | None:
    """How the driver opens: with the era detection over HTTP always, and over stdio under an
    engagement only. Under an engagement ``initialize`` asks for the newest legacy version this
    tool knows; without one, for the version the driver has always announced, and stdio is
    opened by ``initialize`` alone. The generation the file declares for the endpoint rides
    along, to be compared with the one found."""
    if http_url is None and held is None:
        return None
    return Opening(
        transport=eras.TRANSPORT_HTTP if http_url is not None else eras.TRANSPORT_STDIO,
        request_version=eras.NEWEST_LEGACY_VERSION
        if held is not None
        else eras.LEGACY_REQUEST_VERSION,
        declared=held.declared_era(http_url) if held is not None and http_url is not None else None,
    )


def _script_tools(script) -> tuple[str, ...]:
    """The tool of each call step of the script, in order: what the gate holds the engagement's
    tool rules against, before anything starts."""
    if script is None:
        return ()
    return tuple(step.tool for step in script.steps if isinstance(step, CallStep))


def _drive(
    args,
    recorder,
    view,
    common,
    script,
    credentials=(None, (), None),
    opening=None,
    probing=(None, {}),
) -> tuple[object, str | None, str]:
    """Run the server with our own client half in front of it.

    The proxy is built exactly as in the other mode; only its client side is different — two
    pipes instead of the process's own stdin and stdout, or, with ``--http``, a channel that
    speaks to the front of an :class:`HttpProxy`. Everything the recording depends on
    sits downstream of that and does not know the difference.
    """
    # What the recording says of the script: its name, the file's digest and the variables set.
    named = {"script": script.name, "script_digest": script.digest, "script_vars": script.variables}
    # The driver reads lines as long as the proxy holds messages, so that what one records
    # whole, the other can read — and never less than it always read, so that a small message
    # limit narrows the recording and not the conversation.
    line_bytes = max(args.max_message_bytes, MIN_LINE_BYTES)
    token, secret_headers, masker = credentials
    channel = None
    try:
        if args.http is not None:
            # No pipes and no child: the channel speaks HTTP through the proxy's front, which
            # forwards each connection to the endpoint. The proxy is built with the same, less
            # what only a child process has.
            proxy = _DrivenHttpProxy(
                endpoint=args.http,
                recorder=recorder,
                mode=Mode.DRIVER,
                **named,
                **{k: v for k, v in common.items() if k not in ("argv", "sandbox", "guard")},
            )
            channel = HttpClientChannel(
                args.http,
                connect=proxy.front_connect,
                connect_timeout=args.step_timeout,
                max_message_bytes=line_bytes,
                notice=view.notice,
                token=token,
                headers=secret_headers,
                observe=(common["auth"] or {}).get("observation") is not None,
            )
        else:
            channel = ClientChannel(max_line_bytes=line_bytes)
            proxy = _DrivenProxy(
                recorder=recorder,
                client_in=channel.proxy_in,
                client_out=channel.proxy_out,
                mode=Mode.DRIVER,
                **named,
                # The guard in the driver's own proxy would hold back the driver's built messages
                # by size: it is for a client's lines (``run``). The gate and ``Driver._call`` check
                # a script's calls.
                **{k: v for k, v in common.items() if k != "guard"},
            )
        driver = Driver(
            script,
            channel,
            record_skipped=proxy.record_step_skipped,
            record_failed=proxy.record_server_failed,
            record_unanswered=proxy.record_step_unanswered,
            record_finished=proxy.record_script_finished,
            record_called=proxy.record_step_called,
            record_call_failed=proxy.record_call_failed,
            record_era=proxy.record_era_decided,
            record_reissued=proxy.record_step_reissued,
            record_paced=proxy.record_paced,
            record_blocked=proxy.record_call_blocked,
            record_observation=proxy.record_token_observation,
            observation=(common["auth"] or {}).get("observation"),
            is_literal=lambda number: wire_code(masker, number) is None,
            expiry=(
                (lambda: _expiry_word(recorder.token_expired))
                if (common["auth"] or {}).get("observation") == "expired"
                else None
            ),
            guard=common["guard"],
            halt=proxy.halt_reason,
            stop=proxy.stop_run,
            probe=probing[0],
            probe_options=probing[1],
            opening=opening,
            notice=view.notice,
            step_timeout=args.step_timeout,
        )
        outcome = asyncio.run(run_driven(proxy, driver))
    finally:
        if channel is not None:
            channel.close()
    _report_script(view, script.name, driver.outcome, masker)
    _report_exchanges(view, driver.outcome, common["auth"])
    _report_era(view, driver.outcome, masker)
    # Under a token observation the refusal is the result, and the hint to obtain a token would
    # judge it: the exchanges on stdout are all the terminal says of it.
    observed = (common["auth"] or {}).get("observation") is not None
    if (
        isinstance(channel, HttpClientChannel)
        and channel.unauthorized_status is not None
        and not observed
    ):
        _report_unauthorized(view, channel, masker)
    return outcome, driver.outcome.server_failed, driver.outcome.server_failed_detail


def run_masker(
    mask_keys: Sequence[str],
    secret_headers: Sequence[str] = (),
    literals: Sequence[str] = (),
    held: engagement_files.Engagement | None = None,
) -> Masker:
    """The run's masker: the keys, and, only where there are any, the secret headers' names and
    the literals — values the run holds and must never write (credentials.py).

    Under an engagement file, also its known values, and the salt of its pseudonyms from the
    variable ``salt_env`` names: the salt is a literal as well, so that no artifact holds it, if
    the gate takes it (:data:`engagement.MIN_SALT_LENGTH` characters at least). Where the
    variable is not set, or the file names none, the pseudonyms get the run's own salt; the
    gate refuses such a run where the version requires the salt
    (:data:`engagement.SALT_REQUIRED_VERSIONS`)."""
    more: dict[str, object] = {}
    if secret_headers:
        more["secret_headers"] = secret_headers
    salt = engagement_salt(held)
    # A salt the gate does not take (shorter than the least) is no literal and no key: the run is
    # refused before anything of the traffic is written, and the words of a refusal never hold the
    # value. Taken as a literal, a short one would blank itself wherever it occurs, in the name of
    # its own variable too.
    if salt and len(salt) >= engagement_files.MIN_SALT_LENGTH:
        literals = [*literals, salt]
        more["personal_salt"] = salt.encode("utf-8", "surrogateescape")
    if literals:
        more["literals"] = literals
    known = held.data.get("known_values") if held is not None else None
    if isinstance(known, list) and known:
        more["known_values"] = known
    return Masker(extra_keys=mask_keys, **more)


def _graph_warned(view: TerminalView) -> Callable[[int, object], None]:
    """The recorder's display: the terminal view, and once ``run_started`` is written, the
    warning that a token is for Microsoft Graph. The words come from the recorded ``auth``
    (names already masked), never from a claim. Not said for a run that never starts."""

    def on_event(seq: int, body: object) -> None:
        if isinstance(body, RunStarted) and body.auth is not None:
            token = body.auth.get("token")
            if token is not None and "aud_is_graph" in token["warnings"]:
                of = "the token"
                if body.auth.get("identity") is not None:
                    of += f" of identity {body.auth['identity']}"
                view.notice(
                    f"warning: {of} is for Microsoft Graph (aud), not for the server under test"
                )
        view.event(seq, body)

    return on_event


def engagement_salt(held: engagement_files.Engagement | None) -> str | None:
    """The value of the variable the file's ``salt_env`` names, or None: no file, no name, the
    variable not set or empty. The only place the salt is read."""
    if held is None or held.salt_env is None:
        return None
    return os.environ.get(held.salt_env) or None


def _source_flag(args) -> str | None:
    """The flag that named a token's source, or None."""
    if getattr(args, "token_env", None) is not None:
        return "--token-env"
    return "--token-file" if getattr(args, "token_file", None) is not None else None


def read_credentials(args, held) -> tuple[Token | None, tuple[SecretHeader, ...]]:
    """The token and the secret headers this run sends, read from the sources they name: the
    identity's in the engagement file (the gate has checked it is declared), or, without an
    identity, the flag's. Raises :class:`CredentialError`, whose words name the source."""
    name = getattr(args, "identity", None)
    if name is not None:
        return _identity_credentials(held, held.identity(name))
    if getattr(args, "token_env", None) is not None:
        return Token.from_env(args.token_env), ()
    if getattr(args, "token_file", None) is not None:
        return Token.from_file(args.token_file), ()
    return None, ()


def _identity_token(directory: Path, who) -> Token | None:
    """The token of one identity, read from the source the file names, or None: it names none.
    A ``token_file`` is checked again here, as the engagement file's check is: directly before
    the open. What is opened is the resolved path, and the open file is checked once more."""
    if who.token_env is not None:
        return Token.from_env(who.token_env)
    if who.token_file is None:
        return None
    where = f"identity {who.name}: token_file"
    try:
        resolved = (directory / who.token_file).resolve()
    except (OSError, RuntimeError, ValueError):  # a link loop, a name the system refuses
        raise CredentialError(f"{where} cannot be read") from None
    if not engagement_files.token_file_inside(directory, who.token_file):
        raise CredentialError(f"{where} cannot be read")
    return Token.from_file(resolved, label=where, within=directory)


def _identity_credentials(held, who) -> tuple[Token | None, tuple[SecretHeader, ...]]:
    """The token and the secret headers of one identity, read from the sources the file names."""
    token = _identity_token(Path(held.source).resolve().parent, who)
    return token, tuple(SecretHeader.from_env(header, env) for header, env in who.headers)


def other_credentials(args, held) -> list[str]:
    """The values of the token and the secret headers of every identity of the file but the
    chosen one, for the masker only: a server may hand back the token of another identity that an
    earlier run sent, and no artifact may hold it. Each value is read on its own: only the single
    value that cannot be read now is passed by, without a word, and every other value of that
    identity still counts; a token that is not readable at the start of a run cannot be replaced
    in that run. These values are sent nowhere."""
    if held is None:
        return []
    chosen = getattr(args, "identity", None)
    directory = Path(held.source).resolve().parent
    values: list[str] = []
    for who in held.identities:
        if who.name == chosen:
            continue
        try:
            token = _identity_token(directory, who)
        except (CredentialError, OSError):
            token = None
        values += [token.reveal()] if token is not None else []
        for header, env in who.headers:
            try:
                values.append(SecretHeader.from_env(header, env).reveal())
            except (CredentialError, OSError):
                continue
    return values


def engagement_credentials(held) -> tuple[list[str], list[str], list[str]]:
    """The values of the token and the secret headers of every identity of the file, the names
    of those headers, and the place of each value that cannot be read now
    (``identities[0].token``, ``identities[1].headers[0]``), never a value: what a script placed
    in a bundle is masked and checked with, since any of them may have been a run's literal."""
    directory = Path(held.source).resolve().parent
    values: list[str] = []
    names: list[str] = []
    unreadable: list[str] = []
    for number, who in enumerate(held.identities):
        try:
            token = _identity_token(directory, who)
        except (CredentialError, OSError):
            unreadable.append(f"identities[{number}].token")
            token = None
        values += [token.reveal()] if token is not None else []
        for place, (header, env) in enumerate(who.headers):
            names.append(header)
            try:
                values.append(SecretHeader.from_env(header, env).reveal())
            except (CredentialError, OSError):
                unreadable.append(f"identities[{number}].headers[{place}]")
    return values, names, unreadable


def _script_masker_refusal(held, unreadable: Sequence[str]) -> str | None:
    """Why a script cannot be placed in a bundle or checked in one here, or None: a credential
    of the file that cannot be read now, or the salt's variable (``salt_env``) not set or too
    short. The words name the places and the variable, never a value."""
    if unreadable:
        return (
            f"refused: {', '.join(unreadable)} of the engagement file cannot be read here; a "
            "script in a bundle is masked and checked with every credential of the file, as a "
            "run could have held any of them, so each must be readable (its variable set, its "
            "file there); nothing is written"
        )
    salt = engagement_salt(held)
    if held.salt_env is not None and (salt is None or len(salt) < engagement_files.MIN_SALT_LENGTH):
        return (
            f"refused: the environment variable {held.salt_env} that salt_env names is not set "
            f"here (or holds fewer than {engagement_files.MIN_SALT_LENGTH} characters); a script "
            "in a bundle is masked and checked with the salt; nothing is written"
        )
    return None


def _unchecked_words(held, unreadable: Sequence[str]) -> str | None:
    """What the recordings of a bundle without a script are not checked for here, or None: a
    credential of the file that cannot be read now, the salt whose variable (``salt_env``) is not
    set or too short. A warning, where :func:`_script_masker_refusal` refuses: the words name the
    places and the variable, never a value."""
    missing = list(unreadable)
    salt = engagement_salt(held)
    if held.salt_env is not None and (salt is None or len(salt) < engagement_files.MIN_SALT_LENGTH):
        missing.append(f"the salt (the environment variable {held.salt_env})")
    if not missing:
        return None
    return (
        f"warning: {', '.join(missing)} of the engagement file cannot be read here; the "
        "recordings are checked for the known values and for every credential that can be "
        "read, and not for these"
    )


def pack_masker(
    held, values: Sequence[str], names: Sequence[str], mask_keys: Sequence[str] = ()
) -> Masker:
    """The masker of a script placed in a bundle: the engagement's (:func:`run_masker`), with
    ``mask_keys`` (those its runs recorded) beside the file's, every secret header name both as a
    header and as a key (a script's argument named like one loses its value), and every
    credential of the file (:func:`engagement_credentials`) and the salt as literals."""
    headers = [*held.secret_headers, *names]
    return run_masker([*held.mask_keys, *mask_keys, *headers], headers, values, held)


def _report_unauthorized(view: TerminalView, channel: HttpClientChannel, masker: Masker) -> None:
    """The endpoint answered 401 or 403: where it sends clients for a token, if it says, and
    that this tool runs no flow to get one. The challenge is the server's, so what is shown of it
    passes the masker and ``display``."""
    host = ""
    metadata = ((channel.challenge or {}).get("params") or {}).get("resource_metadata")
    if isinstance(metadata, str):
        try:
            host = urlsplit(metadata).netloc.rpartition("@")[2]
        except ValueError:
            host = ""
    if host:
        place = (
            f"the server sends clients to {display(masker.mask_text(host)[0], limit=100)} for a "
            "token (resource_metadata, not fetched)"
        )
    else:
        place = "the server names no place to get a token"
    view.notice(
        f"unauthorized ({channel.unauthorized_status}): {place}; this tool runs no OAuth flow "
        "— obtain a token and pass --token-file or --token-env",
        limit=400,
    )


def _report_era(view: TerminalView, drive_outcome, masker: Masker | None) -> None:
    """What the opening settled, when it is worth a line of its own: a stop with
    ``protocol_unsupported`` — one line on what the server requires that this tool does not offer —
    and a generation other than the one the engagement file declares. The server's words go
    through the masker and ``display``."""
    stop = drive_outcome.stop
    if stop is not None:
        view.notice(_stop_line(stop, masker), limit=500)
    if drive_outcome.declared_differs:
        declared = drive_outcome.declared or {}
        said = display(declared.get("era"), limit=20) + (
            f" {display(declared['version'], limit=20)}" if declared.get("version") else ""
        )
        found = display(drive_outcome.era, limit=20) + (
            f" {masked_display(drive_outcome.protocol_version, masker, limit=20)}"
            if drive_outcome.protocol_version
            else ""
        )
        view.notice(
            f"the engagement file declares {said} for this endpoint; the server speaks {found} "
            "— recorded as an observation, and the run goes on"
        )


def _stop_line(stop: dict, masker: Masker | None) -> str:
    """The one line for a run that stopped with ``protocol_unsupported``."""

    def shown(values, limit=40) -> str:
        return ", ".join(masked_display(v, masker, limit=limit) for v in values) or "none"

    reason = stop.get("reason")
    code = stop.get("code")
    if reason == eras.MODERN_REFUSED and stop.get("required"):
        what = (
            "the server requires client capabilities this tool does not offer: "
            f"{shown(stop['required'])} (error {code})"
        )
    elif reason == eras.MODERN_REFUSED:
        what = (
            f"the server says the headers and the body of the request disagree (error {code}); "
            "this tool has no other request to send"
        )
    elif reason == eras.NO_COMMON_VERSION and eras.MODERN_VERSION in (stop.get("versions") or []):
        what = (
            f"the server rejected protocol version {eras.MODERN_VERSION} although it names it "
            f"as supported: it names {shown(stop['versions'])}"
        )
    elif reason == eras.NO_COMMON_VERSION:
        what = (
            "the server speaks no protocol version this tool does: it names "
            f"{shown(stop.get('versions') or [])}"
        )
    elif reason == eras.UNKNOWN_VERSION:
        what = (
            f"the server answered initialize with protocol version {shown([stop.get('version')])},"
            " which this tool does not know"
        )
    else:
        what = "the server answered initialize with a protocolVersion that is no version"
    return f"protocol_unsupported: {what}; no listing was sent, and the run is not a result"


def _expiry_word(expired: bool | None) -> str:
    """What a token observation says of the token's expiry, from ``auth.token.expired``."""
    if expired is None:
        return events.EXPIRY_NOT_CHECKABLE
    return events.EXPIRY_EXPIRED if expired else events.EXPIRY_NOT_EXPIRED


def _exchange_line(exchange: dict) -> str:
    """One exchange on stdout: method, role, accepted, rejected, neither or no answer, status and
    code."""
    role = exchange["role"]
    if role == events.ROLE_ERA_PROBE:
        role += " (era detection)"
    if exchange["accepted"] is None and exchange["http_status"] is None:
        return f"{exchange['method']}\t{role}\tno answer\n"
    status = exchange["http_status"] if exchange["http_status"] is not None else "-"
    code = exchange["rpc_code"] if exchange["rpc_code"] is not None else "-"
    word = {True: "accepted", False: "rejected", None: "neither"}[exchange["accepted"]]
    return f"{exchange['method']}\t{role}\t{word}\tstatus {status}\tcode {code}\n"


def _report_exchanges(view: TerminalView, outcome, auth) -> None:
    """The end of a token observation: one line on stdout per exchange (method, role, accepted,
    rejected or no answer, status, code), and on the terminal what the token's expiry was. The
    tool does not say whether the result is good or bad. Facts of ours and numbers; nothing the
    server wrote but a status and an error code, which are whole numbers."""
    kind = (auth or {}).get("observation")
    if kind is None:
        return
    if kind == "expired":
        view.notice(
            "token observation (expired): "
            + {
                events.EXPIRY_EXPIRED: "the token was expired when the run began",
                events.EXPIRY_NOT_EXPIRED: "the token was not expired when the run began; the "
                "run went on",
                events.EXPIRY_NOT_CHECKABLE: "expiry as declared by the engagement, not checkable",
            }[outcome.expiry or events.EXPIRY_NOT_CHECKABLE]
        )
    lines = [_exchange_line(exchange) for exchange in outcome.exchanges]
    emit_text("".join(lines))


def _report_script(view: TerminalView, name: str, drive_outcome, masker: Masker | None) -> None:
    """What the script did, in facts. The server's own words go through the masker and then
    ``display``: cut after masking, so that no beginning of a masked value is left standing."""

    def shown(value: object, limit: int) -> str:
        return masked_display(value, masker, limit=limit)

    view.notice(
        f"script {display(name, limit=40)}: {len(drive_outcome.sent)} message(s) sent"
        + (
            f", server speaks {shown(drive_outcome.protocol_version, 20)}"
            + (f" ({drive_outcome.era})" if drive_outcome.era else "")
            if drive_outcome.protocol_version
            else ""
        )
        + (
            f", offers {', '.join(shown(c, 20) for c in drive_outcome.capabilities)}"
            if drive_outcome.capabilities
            else ", offers nothing"
        )
    )
    for step, pages, reason, detail in drive_outcome.unanswered:
        # Under tls, the library's text beside the reason, through the masker and display: it
        # can name what the endpoint's certificate says (http-transport.md 8.3).
        why = shown(reason, 40)
        if detail:
            why += f": {shown(detail, 300)}"
        view.notice(
            f"not answered: {display(step, limit=40)} after {pages} page(s) ({why})", limit=500
        )
    for step, reason in drive_outcome.skipped:
        # Said on the terminal as well as in the recording: a step that was not sent is the
        # one thing a reader cannot see by looking at what is there.
        view.notice(f"not sent: {display(step, limit=40)} ({display(reason, limit=40)})")
    if drive_outcome.blocked is not None:
        cause, tool = drive_outcome.blocked
        if name.startswith("probe:"):
            view.notice(
                f"scope guard: the call of {shown(tool, 60)!r} was not sent ({cause}); "
                "the engagement does not allow it, and the run is incomplete"
            )
        else:
            view.notice(
                f"scope guard: the call of {shown(tool, 60)!r} was not sent ({cause}); "
                "the gate should have refused this script, so this is a mistake of the tool, "
                "and the run is incomplete"
            )
    if drive_outcome.halted is not None:
        view.notice(
            f"stopped: {display(drive_outcome.halted, limit=40)}; no further step was sent, and "
            "the run is incomplete (interrupted)"
        )


def _report(view: TerminalView, outcome, recorder: Recorder) -> None:
    parts = [f"{outcome.message_count} messages", f"ended: {outcome.reason}"]
    if outcome.dropped_events:
        parts.append(f"{outcome.dropped_events} events dropped")
    if outcome.unwritten_events:
        parts.append(f"{outcome.unwritten_events} events unwritten")
    if outcome.recording_stopped:
        parts.append("recording stopped early")
    view.notice(", ".join(parts))
    _report_observations(view, outcome, recorder)
    if outcome.quarantined_rules:
        # Said again at the end, and separately: a rule stilled early in a long run would
        # otherwise scroll away, and every hit it made is to be read as invalid.
        names = ", ".join(display(name, limit=40) for name in outcome.quarantined_rules)
        view.notice(f"stilled after failing, their hits invalid: {names}")


def _report_observations(view: TerminalView, outcome, recorder: Recorder) -> None:
    """Say what was observed and what each scenario statement found, and nothing more.

    No count of "issues", no severity and no advice: the tool says where content addressed
    at a model appeared, which declared signals fired how often, and where a value was masked
    out of server traffic, and stops there. Method names come off the wire, so they are
    masked as the recording masks them (``masked_counts``, the numbers ``run_finished``
    records) and go through ``display`` like every other insert; statement names are the
    operator's, and go through it all the same.
    """
    by_method_counts = recorder.masked_counts(outcome.observations_by_method)
    total = sum(by_method_counts.values())
    if total:
        by_method = ", ".join(
            f"{display(method, limit=40)} {count}"
            for method, count in sorted(by_method_counts.items())
        )
        view.notice(f"observed {total} model-addressable item(s) in server content: {by_method}")
    for statement, counts in outcome.findings_by_statement.items():
        # Every statement, zero included: a statement that never fired is worth a line.
        fired = ", ".join(f"{signal} {count}" for signal, count in counts.items())
        view.notice(
            f"statement {display(statement, limit=40)}: {sum(counts.values())} finding(s) ({fired})"
        )
    if outcome.inspection_bounded:
        view.notice(
            f"{outcome.inspection_bounded} message(s) were too large to inspect in full; "
            "what is past the bound was not looked at"
        )
    if outcome.client_undecodable:
        view.notice(
            f"{outcome.client_undecodable} client message(s) were not valid UTF-8; "
            "the client's doing, not counted against the server"
        )
    if outcome.server_redactions:
        view.notice(
            f"{outcome.server_redactions} value(s) masked in server-to-client traffic; "
            "see the redactions field of those message events for where"
        )


if __name__ == "__main__":  # pragma: no cover - exercised through a subprocess in tests
    sys.exit(main())
