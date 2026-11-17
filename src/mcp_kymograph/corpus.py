"""The corpus manifest: which servers are tested, pinned, how they start, what runs against them.

A manifest orchestrates and nothing more. It names a server, pins what that server is, says
how to start it and which scenarios run against it; what counts as a finding is still the
inspector's alone.

**Every entry is pinned by its content, never by a moving name.** An in-repo entry names
the files and directories it is made of (``source.paths``), and its version is the content
digest over them (:mod:`mcp_kymograph.identity`, sorted relative paths with file hashes). An
external entry names its repository at a full commit id (``source.revision``); ``HEAD``, a
branch, a tag or a short id is refused. No entry runs without one or the other.

**An endpoint entry is the one exception, and says so** (docs/design/http-transport.md 4.1).
It names a server someone else runs, at a URL (``source.endpoint``), driven over
``streamable-http`` with no command. There is no content to pin: its version is what the
operator declares (``source.version_declared``) or the word ``endpoint``, labelled declared
wherever it is shown, and its URL is on the server axis through the launch digest. It runs
under ``remote`` and nothing else — this tool starts, wraps and observes nothing of it — and its
scenarios only observe.

**The entry's name is the finding key's ``server``**. It is the operator's name for
the entry, not what the server announces about itself, which the server under test chooses.

**Provenance is part of the entry**: ``reference``, ``poison`` or ``real-world``. It decides
what a finding against it is — expected, or a disclosure candidate — and under which
isolation the entry may run at all (mcp_kymograph.sandbox.policy): the project's own entries on
the host or in the runc sandbox, a real-world entry only under ``runsc``, which this version
does not provide — so it is refused, never downgraded. An external entry is refused as well:
nothing delivers its pinned code yet.

**A run against an entry records the reproduction triple**: the entry at its content, this
tool at its content, the scenario at its digest. Without all three, "this finding is new"
cannot be told apart from "the server moved", "the tool moved" or "the question moved".
Beside it, the **environment** the run observed in: the isolation and the images it ran.
Not part of any finding's identity — the same finding under runc and under the
host is one finding — but recorded, so that a comparison can say when only it moved.

The file is read like a scenario — the same strict JSON and YAML front ends, refused whole on
the first thing that is wrong, with the place. Paths are relative to the manifest's own
directory. In a command, ``{python}`` stands for the interpreter running Kymograph and
``{dir}`` for the manifest's directory; nothing else is substituted.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_kymograph import __version__
from mcp_kymograph.http_client import HttpClientChannel
from mcp_kymograph.identity import (
    UNDECLARED_ENDPOINT_VERSION,
    IdentityError,
    ServerIdentity,
    from_content,
    from_endpoint,
    from_revision,
)
from mcp_kymograph.recorder import endpoint_refusal
from mcp_kymograph.sandbox.policy import Refused
from mcp_kymograph.sandbox.policy import decide as decide_isolation
from mcp_kymograph.scenario import MAX_FILE_BYTES, ScenarioError, parse_json, parse_yaml
from mcp_kymograph.scenario import load as load_scenario

FORMAT_VERSION = 1

PROVENANCES = ("reference", "poison", "real-world")
TRANSPORTS = ("stdio", "streamable-http")

#: The transport of an endpoint entry: the one this version speaks to a server it does not
#: start (docs/design/http-transport.md).
ENDPOINT_TRANSPORT = "streamable-http"

#: The longest declared version an endpoint entry may carry: a label, not a document.
MAX_VERSION_DECLARED = 128

#: The Unicode categories ``cli.display`` drops before anything reaches a terminal: control,
#: format, surrogate, private-use and unassigned characters. Text an operator declares is
#: refused when it holds one, rather than shown other than it was written.
UNDISPLAYABLE = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_TOP_KEYS = frozenset({"version", "description", "entries"})
_ENTRY_KEYS = frozenset({"name", "description", "provenance", "source", "launch", "scenarios"})
_SOURCE_KEYS = frozenset({"paths", "revision", "endpoint", "version_declared"})
_LAUNCH_KEYS = frozenset({"transport", "command"})


class ManifestError(ValueError):
    """A manifest that cannot be used, with the file and the place in it.

    The file is kept apart from the reason, as ``source``: a path can be as long as the
    checkout it lies in, and whoever has to shorten the message shortens the path, never the
    reason (which may be the list of entries the operator has to pick from).
    """

    def __init__(self, reason: str, *, source: str | None = None) -> None:
        super().__init__(reason if source is None else f"{source}: {reason}")
        self.source = source
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ScenarioRef:
    """One scenario of an entry: its file, the name findings carry, its digest."""

    path: Path
    name: str
    digest: str


@dataclass(frozen=True, slots=True)
class Entry:
    name: str
    provenance: str
    identity: ServerIdentity
    transport: str
    #: The command as written in the manifest, placeholders unsubstituted: what the launch
    #: digest is over, so it does not change from one machine to the next.
    command_written: tuple[str, ...]
    #: The command to run here, placeholders substituted.
    command: tuple[str, ...]
    scenarios: tuple[ScenarioRef, ...]
    #: SHA-256 over transport and written command — for an endpoint entry, over transport and
    #: URL. The server's content is not all of what runs: the same files started with other
    #: arguments are another target, and a change here must be visible when a comparison asks
    #: what moved.
    launch_digest: str
    #: The files and directories ``source.paths`` names, resolved against the manifest: what
    #: the identity is over, and what a sandbox delivers. Empty for a revision entry.
    paths: tuple[Path, ...] = ()
    #: For an endpoint entry, the URL of the server someone else runs; ``command`` and
    #: ``command_written`` are then empty. None for every entry this tool starts itself.
    endpoint: str | None = None

    def scenario(self, name: str | None) -> ScenarioRef:
        """The entry's scenario by name; with one scenario, the name may be left out."""
        names = ", ".join(ref.name for ref in self.scenarios)
        if name is None:
            if len(self.scenarios) == 1:
                return self.scenarios[0]
            raise ManifestError(f"entry {self.name!r} runs several scenarios; pick one of {names}")
        for ref in self.scenarios:
            if ref.name == name:
                return ref
        raise ManifestError(f"entry {self.name!r} has no scenario {name!r}; it has {names}")

    def isolation(self, requested: str | None) -> str:
        """The isolation this entry runs under, or :class:`ManifestError` saying why it may not.

        Refused, never downgraded. The provenance decides what is permitted (``real-world``
        only under ``runsc``, which this version does not provide); a flag can only ask. An
        external entry's pinned code has not been delivered by anything yet, and running
        whatever checkout happens to be at hand would record a revision it did not run. An
        endpoint entry runs under ``remote`` and nothing else, and a command entry never does.
        """
        if self.identity.kind == "revision":
            raise ManifestError(
                f"entry {self.name!r} is pinned to {self.identity.version}, and nothing in "
                "this version delivers that code; it is refused rather than run unverified"
            )
        try:
            return decide_isolation(self.provenance, requested, endpoint=self.endpoint is not None)
        except Refused as refused:
            raise ManifestError(f"entry {self.name!r}: {refused}") from None

    def refusal_to_run(self, requested: str | None = None) -> str | None:
        """Why this entry may not run under the isolation asked for, or None if it may."""
        try:
            self.isolation(requested)
        except ManifestError as refused:
            return str(refused)
        return None


@dataclass(frozen=True, slots=True)
class Manifest:
    source: str
    digest: str
    directory: Path
    entries: tuple[Entry, ...]

    def entry(self, name: str) -> Entry:
        for entry in self.entries:
            if entry.name == name:
                return entry
        known = ", ".join(entry.name for entry in self.entries) or "none"
        raise ManifestError(f"no entry {name!r}; entries: {known}", source=self.source)


def tool_identity() -> dict[str, str]:
    """This tool, as the triple records it: its version, and a digest over its own source.

    The version alone does not move between development commits; the content digest does.
    It is computed like a server's, over this package's own files.
    """
    package = Path(__file__).resolve().parent
    return {"version": __version__, "content": from_content([package]).version}


def environment(
    isolation: str, sandbox_image: str | None = None, target_image: str | None = None
) -> dict[str, Any]:
    """Where a run observed: the isolation, and the images by id (None where none ran).

    The image ids are content addresses: a rebuilt image with other packages in it is another
    id, so a change in what observes is a visible move here, not a silent one."""
    return {"isolation": isolation, "sandbox_image": sandbox_image, "target_image": target_image}


def reproduction(
    manifest: Manifest,
    entry: Entry,
    scenario_digest: str | None,
    env: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The reproduction triple for one run, and its environment, as ``run_started`` records
    them."""
    ref = next((r for r in entry.scenarios if r.digest == scenario_digest), None)
    return {
        "manifest": {"source": manifest.source, "digest": manifest.digest},
        "corpus": {
            "entry": entry.name,
            "provenance": entry.provenance,
            "identity": entry.identity.to_dict(),
            "launch_digest": entry.launch_digest,
        },
        "tool": tool_identity(),
        "scenario": {
            "name": None if ref is None else ref.name,
            "digest": scenario_digest,
        },
        "environment": dict(env) if env is not None else environment("host"),
    }


def unlisted_reproduction(
    scenario_name: str | None,
    scenario_digest: str | None,
    env: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The triple of a run without a corpus entry, in the form of :func:`reproduction`: no
    manifest and no entry (both ``None``), the tool, the scenario as far as there is one, and
    the environment."""
    return {
        "manifest": None,
        "corpus": None,
        "tool": tool_identity(),
        "scenario": {"name": scenario_name, "digest": scenario_digest},
        "environment": dict(env) if env is not None else environment("host"),
    }


# -- reading ------------------------------------------------------------------------------


def load(path: str | Path) -> Manifest:
    """Read, parse and validate one manifest, or raise :class:`ManifestError`."""
    path = Path(path)
    source = str(path)
    suffix = path.suffix.lower()
    if suffix not in (".json", ".yaml", ".yml"):
        raise ManifestError(f"unknown suffix {suffix!r}; use .yaml, .yml or .json", source=source)
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ManifestError(f"cannot read: {exc.strerror or exc}", source=source) from None
    if len(raw) > MAX_FILE_BYTES:
        raise ManifestError(f"larger than {MAX_FILE_BYTES} bytes", source=source)
    try:
        text = raw.decode("utf-8")
        data = (
            parse_json(text, source=source)
            if suffix == ".json"
            else parse_yaml(text, source=source)
        )
    except UnicodeDecodeError as exc:
        raise ManifestError(f"not UTF-8 at byte {exc.start}", source=source) from None
    except ScenarioError as exc:
        # The parser names the file it was given first, as ``source: reason``.
        raise ManifestError(str(exc).removeprefix(f"{source}: "), source=source) from None
    directory = path.resolve().parent
    try:
        entries = _entries(data, directory)
    except _Invalid as invalid:
        where = f"{invalid.where}: " if invalid.where else ""
        raise ManifestError(f"{where}{invalid.message}", source=source) from None
    return Manifest(source, "sha256:" + hashlib.sha256(raw).hexdigest(), directory, entries)


class _Invalid(Exception):
    def __init__(self, where: str, message: str) -> None:
        super().__init__(message)
        self.where = where
        self.message = message


def _entries(data: Any, directory: Path) -> tuple[Entry, ...]:
    _mapping(data, "", "the manifest must be a mapping")
    _only(data, _TOP_KEYS, "")
    if "version" not in data:
        raise _Invalid("version", f"missing; this loader reads version: {FORMAT_VERSION}")
    if type(data["version"]) is not int or data["version"] != FORMAT_VERSION:
        raise _Invalid("version", f"unsupported {data['version']!r}; this loader reads 1")
    listed = data.get("entries")
    if listed is None:
        return ()
    if not isinstance(listed, list):
        raise _Invalid("entries", "expected a list")
    names: set[str] = set()
    return tuple(_entry(item, f"entries[{i}]", directory, names) for i, item in enumerate(listed))


def _entry(item: Any, where: str, directory: Path, names: set[str]) -> Entry:
    _mapping(item, where, "expected a mapping")
    _only(item, _ENTRY_KEYS, where)
    name = _required(item, "name", where)
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise _Invalid(f"{where}.name", f"{name!r} is not a name: 1-64 letters, digits, . _ -")
    if name in names:
        raise _Invalid(f"{where}.name", f"{name!r} is already an entry")
    names.add(name)

    provenance = _required(item, "provenance", where)
    if provenance not in PROVENANCES:
        raise _Invalid(
            f"{where}.provenance",
            f"unknown provenance {provenance!r}; expected one of {', '.join(PROVENANCES)}",
        )
    identity, paths, endpoint = _identity(
        _required(item, "source", where), f"{where}.source", directory
    )
    transport, written = _launch(
        _required(item, "launch", where), f"{where}.launch", endpoint is not None
    )
    scenarios = _scenarios(
        _required(item, "scenarios", where),
        f"{where}.scenarios",
        directory,
        endpoint=endpoint is not None,
    )
    command = tuple(
        part.replace("{python}", sys.executable).replace("{dir}", str(directory))
        for part in written
    )
    if endpoint is None:
        # Built exactly as before endpoints existed: every stdio entry keeps its digest.
        launch = json.dumps({"transport": transport, "command": list(written)}, ensure_ascii=True)
    else:
        launch = json.dumps({"transport": transport, "endpoint": endpoint}, ensure_ascii=True)
    return Entry(
        name=name,
        provenance=provenance,
        identity=identity,
        transport=transport,
        command_written=written,
        command=command,
        scenarios=scenarios,
        launch_digest="sha256:" + hashlib.sha256(launch.encode("ascii")).hexdigest(),
        paths=paths,
        endpoint=endpoint,
    )


def _identity(
    source: Any, where: str, directory: Path
) -> tuple[ServerIdentity, tuple[Path, ...], str | None]:
    """In-repo paths, an external revision or an endpoint — exactly one; there is no default."""
    _mapping(source, where, "expected a mapping with paths, revision or endpoint")
    _only(source, _SOURCE_KEYS, where)
    given = [key for key in ("paths", "revision", "endpoint") if key in source]
    if len(given) != 1:
        raise _Invalid(
            where,
            "name the server's content: either paths (in-repo files and directories) or "
            "revision (repo@<full commit id>) — or, for a server someone else runs, its "
            "endpoint; exactly one",
        )
    if "version_declared" in source and given[0] != "endpoint":
        raise _Invalid(
            f"{where}.version_declared",
            "belongs to an endpoint entry; the version of paths or a revision is established "
            "from what they name, not declared",
        )
    try:
        if given[0] == "endpoint":
            url = _endpoint_url(source["endpoint"], f"{where}.endpoint")
            declared = _version_declared(source, f"{where}.version_declared")
            return from_endpoint(url, declared), (), url
        if given[0] == "revision":
            revision = source["revision"]
            if not isinstance(revision, str):
                raise _Invalid(f"{where}.revision", "expected a string")
            return from_revision(revision), (), None
        paths = source["paths"]
        if not isinstance(paths, list) or not paths:
            raise _Invalid(f"{where}.paths", "expected a non-empty list of paths")
        resolved = []
        for index, entry in enumerate(paths):
            if not isinstance(entry, str) or not entry or Path(entry).is_absolute():
                raise _Invalid(
                    f"{where}.paths[{index}]", "expected a path relative to the manifest"
                )
            resolved.append(directory / entry)
        return from_content(resolved, base=directory), tuple(resolved), None
    except IdentityError as exc:
        raise _Invalid(where, str(exc)) from None


def _endpoint_url(url: Any, where: str) -> str:
    """The URL of an endpoint entry, held to what ``drive --http`` holds a URL to: the channel
    that will speak to it, and the recorder that will write it down — both asked, neither
    copied, so a URL the manifest takes is one a run can take."""
    if not isinstance(url, str) or not url:
        raise _Invalid(where, "expected the server's URL as a string")
    try:
        HttpClientChannel(url)  # reads the URL, and does nothing else
    except ValueError as refusal:
        raise _Invalid(where, str(refusal)) from None
    recorded = endpoint_refusal(url)
    if recorded is not None:
        raise _Invalid(where, recorded)
    return url


def _version_declared(source: dict, where: str) -> str | None:
    """The operator's word for the deployment's version, or None: a claim, kept as typed."""
    if "version_declared" not in source or source["version_declared"] is None:
        return None
    declared = source["version_declared"]
    if not isinstance(declared, str) or not declared:
        raise _Invalid(where, "expected a non-empty string, or leave it out")
    if len(declared) > MAX_VERSION_DECLARED:
        raise _Invalid(where, f"longer than {MAX_VERSION_DECLARED} characters")
    if declared == UNDECLARED_ENDPOINT_VERSION:
        raise _Invalid(
            where,
            f"{UNDECLARED_ENDPOINT_VERSION!r} is the version of an endpoint whose version nobody "
            "declared; a declared version that reads the same would make the two one server "
            "version; declare another, or leave it out",
        )
    if undisplayable(declared):
        raise _Invalid(
            where,
            "holds a control, format or other character a terminal does not show; a declared "
            "version is shown wherever its findings are, and must read as it was written",
        )
    return declared


def undisplayable(text: str, *, allowed: str = "") -> bool:
    """Whether ``text`` holds a character ``cli.display`` would drop (:data:`UNDISPLAYABLE`),
    other than one of ``allowed``."""
    return any(
        unicodedata.category(character) in UNDISPLAYABLE
        for character in text
        if character not in allowed
    )


def _launch(launch: Any, where: str, endpoint: bool) -> tuple[str, tuple[str, ...]]:
    """The transport and the written command. An endpoint entry speaks streamable HTTP to a
    server that is already running, so it has no command, and only it has that transport."""
    _mapping(launch, where, "expected a mapping")
    _only(launch, _LAUNCH_KEYS, where)
    transport = _required(launch, "transport", where)
    if transport not in TRANSPORTS:
        raise _Invalid(
            f"{where}.transport",
            f"unsupported transport {transport!r}; this version runs {', '.join(TRANSPORTS)}",
        )
    if endpoint != (transport == ENDPOINT_TRANSPORT):
        raise _Invalid(
            f"{where}.transport",
            f"an entry with source.endpoint is driven over {ENDPOINT_TRANSPORT}, and only such "
            f"an entry is; {transport!r} does not go with "
            f"{'an endpoint' if endpoint else 'paths or a revision'}",
        )
    if endpoint:
        if "command" in launch:
            raise _Invalid(
                f"{where}.command",
                "an endpoint entry's server is already running elsewhere; there is no command "
                "to start it",
            )
        return transport, ()
    command = _required(launch, "command", where)
    if not isinstance(command, list) or not command:
        raise _Invalid(f"{where}.command", "expected a non-empty list of arguments")
    for index, part in enumerate(command):
        if not isinstance(part, str) or not part:
            raise _Invalid(f"{where}.command[{index}]", "expected a non-empty string")
    return transport, tuple(command)


def _scenarios(
    listed: Any, where: str, directory: Path, *, endpoint: bool = False
) -> tuple[ScenarioRef, ...]:
    """Every scenario is loaded now, so a broken one stops the manifest, not a later run.

    An endpoint entry's scenario only observes: rules are not carried out over HTTP
    (:mod:`mcp_kymograph.http_proxy`), and a run would refuse one at its start.
    """
    if not isinstance(listed, list) or not listed:
        raise _Invalid(where, "expected a non-empty list of scenario files")
    refs: list[ScenarioRef] = []
    for index, entry in enumerate(listed):
        if not isinstance(entry, str) or not entry or Path(entry).is_absolute():
            raise _Invalid(f"{where}[{index}]", "expected a path relative to the manifest")
        try:
            loaded = load_scenario(directory / entry)
        except ScenarioError as exc:
            raise _Invalid(f"{where}[{index}]", str(exc)) from None
        if any(ref.name == loaded.name for ref in refs):
            raise _Invalid(f"{where}[{index}]", f"a second scenario named {loaded.name!r}")
        if endpoint and loaded.rules:
            raise _Invalid(
                f"{where}[{index}]",
                f"scenario {loaded.name!r} loads {len(loaded.rules)} rule(s); rules are not "
                "carried out over HTTP, so an endpoint entry's scenario only observes",
            )
        refs.append(ScenarioRef(directory / entry, loaded.name, loaded.digest))
    return tuple(refs)


def _mapping(value: Any, where: str, message: str) -> None:
    if not isinstance(value, dict):
        raise _Invalid(where, message)


def _only(mapping: dict, allowed: frozenset[str], where: str) -> None:
    for key in mapping:
        if key not in allowed:
            raise _Invalid(
                where, f"unknown key {key!r}; expected one of {', '.join(sorted(allowed))}"
            )


def _required(mapping: dict, key: str, where: str) -> Any:
    if key not in mapping or mapping[key] is None:
        raise _Invalid(f"{where}.{key}", "missing")
    return mapping[key]
