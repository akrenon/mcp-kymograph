"""What a probe module is, and what it is given to work with.

A probe module is the frame for an active test of a server: a fixed name, a short description, an
upper bound on its requests (``max_calls``, at most :data:`MAX_CALLS`) and a method that makes
requests through a :class:`Context`. **A module never speaks to the server itself.** The context
is the only way out, and it is made by the driver (``Driver``): every request passes the scope
guard (``Driver._call``) and, before it, a look at the engagement's window, its stop file and the
module's own ``max_calls``. A request any of them refuses is not sent, and the module is ended
with a cause (:class:`ProbeEnded`) instead of being left to go on.

This module has no connection, no file and no import from the rest of the package, so that both
the engagement (which names modules it allows) and the driver (which runs them) can read it.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol

#: The most requests a module may be given, whatever it asks for.
MAX_CALLS = 64

#: What the name of a module looks like (and what ``actions.probes`` of an engagement file lists).
NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")

#: The longest value of one ``--probe-option``, in characters.
MAX_OPTION_VALUE = 1000


class ProbeError(ValueError):
    """The options given to a module are not ones it takes. The words are ours and name the
    option's key, never its value."""


class ProbeEnded(Exception):
    """The context ends the module: ``reason`` is a fixed word of the recording's vocabulary
    (``run_halted``, ``probe_calls_exhausted``, ``tool_not_listed``, a step's failure, …). The
    request that caused it was not sent, or was sent and not answered. A module does not catch
    this; the driver does, and the run goes on to its end."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CallResult:
    """What a module learns of a request that was answered: whether the answer was an error.
    The content is read by the run's inspector, as everything the server says is, and not here."""

    failed: bool = False


class Context(Protocol):
    """What a module is given. Every method is one request (``tools`` and ``call``) or none."""

    async def tools(self) -> frozenset[str]:
        """List the server's tools, following cursors; the names it delivered."""
        ...

    async def call(
        self, tool: str, arguments: Mapping[str, Any] | None = None, *, timeout: float | None = None
    ) -> CallResult:
        """Call a tool the server's own ``tools/list`` delivered in this run. Raises
        :class:`ProbeEnded` instead of sending when the window has closed, the stop file is
        there, the module has used up ``max_calls``, or the tool is not in the inventory — and
        when the scope guard does not allow the call."""
        ...

    async def pace(self) -> None:
        """The hook called before every request. It has no effect on the gap between a module's
        requests: this version keeps no interval per request. A run of a module is paced as a run
        (mcp_kymograph.pacing): it takes its origin's slot and keeps the interval before it
        connects."""
        ...


class Probe(ABC):
    """One module. Subclasses set :attr:`name`, :attr:`description` and :attr:`max_calls`, and
    the options they take in :attr:`required` and :attr:`optional`; :meth:`run` is the test.

    A module holds no state between runs: one instance is shared, and a run's facts are in the
    context and the recording."""

    name: ClassVar[str]
    description: ClassVar[str]
    #: The most requests the module makes (``tools`` and ``call`` each count one), 1 to
    #: :data:`MAX_CALLS`.
    max_calls: ClassVar[int]
    #: The option keys the module needs, and those it may be given besides.
    required: ClassVar[tuple[str, ...]] = ()
    optional: ClassVar[tuple[str, ...]] = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not NAME.fullmatch(getattr(cls, "name", "")):
            raise TypeError(f"{cls.__name__}: name must match {NAME.pattern}")
        if not getattr(cls, "description", ""):
            raise TypeError(f"{cls.__name__}: a module has a description")
        calls = getattr(cls, "max_calls", 0)
        if type(calls) is not int or not 1 <= calls <= MAX_CALLS:
            raise TypeError(f"{cls.__name__}: max_calls must be 1 to {MAX_CALLS}")

    def check(self, options: Mapping[str, str]) -> None:
        """Raise :class:`ProbeError` unless the options are exactly the module's: every required
        key, no key it does not know, no value over :data:`MAX_OPTION_VALUE`."""
        known = (*self.required, *self.optional)
        for key in options:
            if key not in known:
                raise ProbeError(
                    f"the probe {self.name} takes no option {key!r}; it takes "
                    + (", ".join(known) or "none")
                )
        for key in self.required:
            if key not in options:
                raise ProbeError(f"the probe {self.name} needs the option {key}")
        for key, value in options.items():
            if len(value) > MAX_OPTION_VALUE:
                raise ProbeError(f"the option {key} is longer than {MAX_OPTION_VALUE} characters")

    @abstractmethod
    async def run(self, context: Context, options: Mapping[str, str]) -> None:
        """Make the module's requests through ``context``. May raise :class:`ProbeEnded` (from the
        context); nothing else is expected of it."""
