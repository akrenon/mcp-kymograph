"""The probe modules: active tests of a server, run by ``drive --probe NAME``.

The frame is :mod:`mcp_kymograph.probes.base`; the modules there are, are listed in
:data:`PROBES`, a fixed table like the driver's scripts. A module is used only under an
engagement that lists it in ``actions.probes``.
"""

from __future__ import annotations

from mcp_kymograph.probes.base import MAX_CALLS, Context, Probe, ProbeEnded, ProbeError
from mcp_kymograph.probes.echo import Echo

#: The modules there are, by name.
PROBES: dict[str, Probe] = {probe.name: probe for probe in (Echo(),)}

__all__ = ["MAX_CALLS", "PROBES", "Context", "Probe", "ProbeEnded", "ProbeError"]
