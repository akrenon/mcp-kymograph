"""The credentials a run sends, read once from the source it names
(docs/design/http-transport.md 2.8).

A :class:`Token` is the bearer token of one identity; a :class:`SecretHeader` is the value of one
more header an identity sends (``Ocp-Apim-Subscription-Key``). Both come from an environment
variable or, for a token, a file: there is no way to hand either a value on the command line or
in an engagement file. A source that cannot be used is a :class:`CredentialError`, and its
words name the source and what is wrong with it, never a byte of what it held.

The value is one private attribute, read through :meth:`reveal` by the two places that need it —
the channel, which writes it, and the masker, which blanks it — and by nothing else. ``repr`` and
``str`` say where it came from. Python cannot wipe it; the objects end with the run.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path
from typing import Any, Final

#: The most a token or a header value may be, after one trailing line ending is dropped.
MAX_SECRET_BYTES: Final = 16 * 1024

#: What a name of an environment variable may be: the portable set.
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")

#: A header's name: RFC 9110 ``token``, bounded.
HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}")

#: The headers a run sends by itself or whose meaning the channel owns; an identity cannot
#: set them, because a second ``Authorization`` is no extra header but a different request.
RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "host",
        "content-length",
        "content-type",
        "accept",
        "connection",
        "transfer-encoding",
        "mcp-session-id",
        "mcp-protocol-version",
        "proxy-authorization",
        "expect",
        "upgrade",
        "te",
        "trailer",
    }
)


class CredentialError(ValueError):
    """A credential's source cannot be used. The words name the source, never its content."""


def _visible(raw: bytes, where: str) -> str:
    """``raw`` as a value: one trailing line ending dropped, at most :data:`MAX_SECRET_BYTES`,
    visible ASCII (``0x21``-``0x7E``) throughout, not empty — or :class:`CredentialError`."""
    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
    if len(raw) > MAX_SECRET_BYTES:
        raise CredentialError(f"{where} is longer than {MAX_SECRET_BYTES} bytes")
    if not raw:
        raise CredentialError(f"{where} is empty")
    if any(not 0x21 <= byte <= 0x7E for byte in raw):
        raise CredentialError(
            f"{where} holds a character that is not visible ASCII (0x21-0x7E): no space, no "
            "line break inside, no other encoding"
        )
    return raw.decode("ascii")


def _from_env(name: str, where: str) -> str:
    if not ENV_NAME.fullmatch(name):
        raise CredentialError("an environment variable's name is letters, digits and _ only")
    value = os.environ.get(name)
    if value is None:
        raise CredentialError(f"{where} is not set")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise CredentialError(
            f"{where} holds a character that is not visible ASCII (0x21-0x7E)"
        ) from None
    return _visible(raw, where)


def _from_file(
    path: str | os.PathLike[str], where: str, within: str | os.PathLike[str] | None = None
) -> str:
    if within is not None:
        return _visible(_read_inside(path, where, within), where)
    try:
        with Path(path).open("rb") as handle:
            # Past the limit by a line ending and a byte: enough to see that it is too long.
            raw = handle.read(MAX_SECRET_BYTES + 3)
    except OSError as error:
        raise CredentialError(f"{where} cannot be read ({error.strerror or 'an error'})") from None
    return _visible(raw, where)


def _read_inside(path: str | os.PathLike[str], where: str, within: str | os.PathLike[str]) -> bytes:
    """The bytes of the regular file that ``path`` (resolved already) names inside ``within``
    (resolved already), opened part by part from ``within`` without following a link at any
    step: a part that is a link now (a swap since the path was resolved) fails the open, and
    the run is refused. What is read is the file the last open returned, by its descriptor,
    after ``fstat`` says it is a regular file. Every refusal for where the file is says the
    same words, and none names the path."""
    refused = CredentialError(f"{where} cannot be read")
    try:
        parts = Path(path).relative_to(within).parts
    except ValueError:
        raise refused from None
    if not parts or ".." in parts or "." in parts:
        raise refused
    follow = getattr(os, "O_NOFOLLOW", 0)
    opened: list[int] = []
    try:
        current = os.open(within, os.O_RDONLY | os.O_DIRECTORY)
        opened.append(current)
        for part in parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | follow, dir_fd=current)
            opened.append(current)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | follow, dir_fd=current)
        opened.append(descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise refused
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read(MAX_SECRET_BYTES + 3)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):  # a part is a link now
            raise refused from None
        raise CredentialError(f"{where} cannot be read ({error.strerror or 'an error'})") from None
    finally:
        for descriptor in opened:
            os.close(descriptor)


class _Secret:
    """A value held for one run: where it came from is public, what it is is not."""

    __slots__ = ("_origin", "_value")

    def __init__(self, value: str, origin: str) -> None:
        self._value = value
        self._origin = origin

    def reveal(self) -> str:
        """The value. For the channel that writes it and the masker that blanks it."""
        return self._value

    def __repr__(self) -> str:
        return f"<{self._origin}>"

    __str__ = __repr__


class Token(_Secret):
    """The bearer token of one identity, or of a run without an engagement file."""

    __slots__ = ("env_name", "source")

    def __init__(self, value: str, *, source: str, env_name: str | None = None) -> None:
        origin = f"token from env {env_name}" if source == "env" else "token from a file"
        super().__init__(value, origin)
        #: ``env`` or ``file``, as ``run_started.auth.source`` says it.
        self.source = source
        self.env_name = env_name

    @classmethod
    def from_env(cls, name: str) -> Token:
        """The token in the environment variable ``name``, read now."""
        where = f"the token in the environment variable {name!r}"
        return cls(_from_env(name, where), source="env", env_name=name)

    @classmethod
    def from_file(
        cls,
        path: str | os.PathLike[str],
        *,
        label: str | None = None,
        within: str | os.PathLike[str] | None = None,
    ) -> Token:
        """The token in the file at ``path``, read now. With ``label``, the words of a refusal
        name the file by it, not by its path (an identity's file is local to the operator).
        With ``within`` (a resolved directory), ``path`` must be resolved too, and the file
        opened must be a regular file inside it (:func:`_read_inside`)."""
        return cls(
            _from_file(path, label or f"the token file {str(path)!r}", within), source="file"
        )

    def authorization(self) -> str:
        """The value of the ``Authorization`` header (RFC 6750)."""
        return f"Bearer {self._value}"


def auth_record(
    *, identity: str | None = None, role: str | None = None, token: Token | None = None
) -> dict[str, Any] | None:
    """What ``run_started.auth`` says of a run: whom it spoke as and where its token came from,
    never a value — or None for a run that chose no identity and sent no token.

    An identity that sends no token is ``source: "none"`` and ``token_used: false``: that run
    sent no ``Authorization`` header, and the recording says so."""
    if identity is None and token is None:
        return None
    record: dict[str, Any] = {
        "identity": identity,
        "role": role,
        "token_used": token is not None,
        "source": "none" if token is None else token.source,
    }
    if token is not None and token.env_name is not None:
        record["env_name"] = token.env_name
    return record


class SecretHeader(_Secret):
    """One more header an identity sends, its value read from an environment variable."""

    __slots__ = ("env_name", "name")

    def __init__(self, name: str, env_name: str, value: str) -> None:
        super().__init__(value, f"value of header {name} from env {env_name}")
        self.name = name
        self.env_name = env_name

    @classmethod
    def from_env(cls, name: str, env_name: str) -> SecretHeader:
        """The header ``name`` with the value of the environment variable ``env_name``."""
        if not HEADER_NAME.fullmatch(name) or name.lower() in RESERVED_HEADERS:
            raise CredentialError(f"{name!r} cannot be a header an identity sends")
        where = f"the value of the header {name} in the environment variable {env_name!r}"
        return cls(name, env_name, _from_env(env_name, where))
