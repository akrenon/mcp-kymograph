"""The environment a subprocess is allowed to see.

Two policies, named apart on purpose, because picking the wrong one is silent.

**Helpers** are programs we run to answer a question for us, and git is the reason this
module exists. ``git check-ignore`` decides whether a recording could end up committed, and
its answer is steerable from the environment: ``GIT_DIR`` makes it answer about a different
repository, and ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n`` inject a
``core.excludesFile`` of the caller's choosing. Either turns a safety check into a
fail-open, which is the one direction a safety check must never fail in.

That is why this is an **allowlist**. A list of variables to strip is the same mistake one
level up: the first version of this code named five, and the injection vector above was not
among them. Naming what may pass through cannot be incomplete in the dangerous direction —
a variable nobody thought of is absent, not admitted.

**Inherited** is the opposite policy and belongs to exactly one caller: the MCP server
under test. It gets the environment verbatim, because a server that is started with a
different environment than the client would have given it is a server behaving differently
because we are there. Transparency wins; it is a deliberate choice, not an oversight.
"""

from __future__ import annotations

import os

#: What a helper subprocess may see.
#:
#: ``HOME`` is kept deliberately. Without it git stops reading ``~/.gitconfig``, and a
#: ``core.excludesFile`` configured there is a real ignore rule that a destination may
#: legitimately rely on — dropping it would refuse destinations that are genuinely safe.
#: The residual is stated rather than hidden: whoever can set ``HOME`` can shape git's
#: answer. Nothing here defends against that, and nothing can, since the same person can
#: edit ``.gitignore`` directly.
HELPER_ALLOWLIST = frozenset({"PATH", "HOME"})


def helper_env() -> dict[str, str]:
    """The environment for a subprocess we run to answer a question for ourselves."""
    return {key: value for key, value in os.environ.items() if key in HELPER_ALLOWLIST}


def inherited_env() -> dict[str, str]:
    """The environment for the server under test: the caller's own, unchanged.

    Separate from :func:`helper_env` so the choice is visible at every call site. A proxy
    that scrubs the server's environment changes the behaviour it exists to observe.
    """
    return dict(os.environ)
