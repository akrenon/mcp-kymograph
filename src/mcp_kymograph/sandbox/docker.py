"""The Docker command line, as far as the sandbox uses it: a few calls, each bounded in time.

The CLI runs with the helper environment (``PATH`` and ``HOME`` only), like every program this
tool asks a question of: ``DOCKER_HOST`` or ``DOCKER_CONTEXT`` from the caller's environment
would otherwise decide which daemon the sandbox is built on, without that being visible
anywhere. ``HOME`` keeps the CLI's own configuration, which is the operator's choice.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

from mcp_kymograph.environment import helper_env

DOCKER = "docker"


class DockerError(RuntimeError):
    """A Docker call that failed, timed out, or could not be made."""


def run(
    args: Sequence[str], *, timeout: float, stdin: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    """One call, its output captured. Raises only when it could not complete at all."""
    try:
        return subprocess.run(  # noqa: S603 - fixed program, arguments built here
            [DOCKER, *args],
            input=stdin,
            capture_output=True,
            timeout=timeout,
            env=helper_env(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise DockerError(f"docker {args[0]} did not finish within {timeout:g} s") from None
    except OSError as exc:
        raise DockerError(f"docker could not be run: {exc.strerror or exc}") from None


def checked(args: Sequence[str], *, timeout: float) -> bytes:
    done = run(args, timeout=timeout)
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()[:300]
        raise DockerError(f"docker {args[0]}: exit {done.returncode}: {detail}")
    return done.stdout


def image_id(reference: str) -> str:
    """The immutable id behind a reference, so a tag that moves mid-run cannot swap the image."""
    found = checked(["image", "inspect", "--format", "{{.Id}}", reference], timeout=30).strip()
    return found.decode("ascii", "replace")


def server_version() -> str:
    return checked(["version", "--format", "{{.Server.Version}}"], timeout=30).decode().strip()


def remove(names: Sequence[str]) -> None:
    """Force-remove containers by name. Missing ones are not an error: removal is the goal."""
    if names:
        run(["rm", "-f", *names], timeout=60)


def leftovers(label: str) -> list[str]:
    """Containers still carrying the label, running or not."""
    out = checked(["ps", "-aq", "--filter", f"label={label}"], timeout=30)
    return out.decode("ascii", "replace").split()
