"""Which isolation a corpus entry may run under: decided by its provenance, never by a flag alone.

A flag can only ask for an isolation. Whether that isolation is allowed is decided by the
entry's provenance — the same marking the store files its findings under — and whether it is
available is decided by this version. The decision is made before anything is started, so a
refusal leaves no process, no container and no recording behind.

**Refused, never downgraded.** A ``real-world`` entry is foreign code under adversarial
stimulus. It runs under ``runsc`` or not at all. This version provides no ``runsc`` path (the
sink design for gVisor is still open), so a real-world entry is refused under every isolation
there is — including when none was asked for: there is no default for it to fall back to.

**An endpoint is not run here** (docs/design/http-transport.md 4.1). An entry that names a
server someone else runs, at a URL, has nothing for this tool to start, wrap or observe: its
isolation is ``remote``, whatever its provenance, and nothing else — under ``host`` or ``runc``
there is nothing to run. ``remote`` isolates nothing and observes no egress; it says only that
the server is elsewhere. A command entry is never ``remote``: its server runs here.
"""

from __future__ import annotations

ISOLATIONS = ("host", "runc", "runsc", "remote")

#: What each provenance may run under, the first being what it runs under when none is asked
#: for. The project's own reference and poison servers are code this repository holds. For a
#: command entry only: an endpoint entry runs under :data:`ENDPOINT_ISOLATION` and nothing else.
PERMITTED: dict[str, tuple[str, ...]] = {
    "reference": ("host", "runc"),
    "poison": ("host", "runc"),
    "real-world": ("runsc",),
}

#: The one isolation of an endpoint entry, whatever its provenance.
ENDPOINT_ISOLATION = "remote"

#: What this version can actually run. ``runsc`` is not among them.
PROVIDED = ("host", "runc", "remote")


class Refused(ValueError):
    """The entry may not run under the isolation asked for, or under any this version has."""


def decide(provenance: str, requested: str | None, *, endpoint: bool = False) -> str:
    """The isolation to run under, or :class:`Refused` saying why there is none.

    ``endpoint`` says the entry names a server at a URL rather than a command to start.
    """
    if provenance not in PERMITTED:
        raise Refused(f"unknown provenance {provenance!r}")
    if requested is not None and requested not in ISOLATIONS:
        raise Refused(f"unknown isolation {requested!r}; expected one of {', '.join(ISOLATIONS)}")
    if endpoint:
        if requested is not None and requested != ENDPOINT_ISOLATION:
            raise Refused(
                f"an endpoint entry runs only under {ENDPOINT_ISOLATION}, not {requested}: its "
                f"server runs elsewhere, so there is nothing here to run under {requested}; "
                "it is refused"
            )
        return ENDPOINT_ISOLATION
    if requested == ENDPOINT_ISOLATION:
        raise Refused(
            f"a command entry never runs under {ENDPOINT_ISOLATION}: its server is started "
            f"here, and {ENDPOINT_ISOLATION} would observe nothing of it; it is refused"
        )
    permitted = PERMITTED[provenance]
    isolation = permitted[0] if requested is None else requested
    if isolation not in permitted:
        raise Refused(
            f"a {provenance} entry runs only under {' or '.join(permitted)}, not {isolation}; "
            "it is refused, not run under a weaker isolation"
        )
    if isolation not in PROVIDED:
        raise Refused(
            f"a {provenance} entry runs only under {' or '.join(permitted)}, which this "
            "version does not provide; it is refused, not run under anything weaker"
        )
    return isolation
