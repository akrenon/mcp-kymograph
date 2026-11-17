"""Which request a response answers: a JSON-RPC id compared the way the clients compare it.

A response carries only an id, and the inspector and the engine tie it to the method of the
request that id asked. Whether a response *is* the answer to a request is decided by the
client, not by us, so the comparison has to be the client's. Two clients set the bar, and they
are looser than ``==`` on the parsed JSON:

* the TypeScript SDK accepts a response whose id is a string or an integral number
  (``RequestIdSchema``, ``z.union([z.string(), z.number().int()])``) and then looks the
  handler up by ``Number(response.id)`` (``protocol.ts``, ``_onresponse``): ``1.0``, ``"1"``,
  ``"1.0"``, ``" 1 "``, ``"0x1"`` and ``"1e0"`` all answer request ``1``, and ``""`` answers
  request ``0``;
* the Python SDK accepts a strict integer or a string (``RequestId = Annotated[int,
  Field(strict=True)] | str``) and coerces a string id with ``int()`` before it looks it up
  (``coerce_request_id`` in ``mcp/shared/dispatcher.py``): ``"1"``, ``"+1"`` and ``"1_0"``
  (ten) answer requests ``1`` and ``10``.

Neither takes a boolean, null, an object or a list as the id of an answer: both reject such a
message by its schema before they look at the id, so it answers nothing and needs no key.

:func:`key_of` maps an id to one key that is equal for everything either client would match,
so a server cannot slip a response past the inspection by writing its id differently.
Merging more ids than one client would merge costs nothing here: it only means a response is
inspected as the answer some client takes it for.

Where the clients would **not** agree, there is no key to give: a number beyond 2**53, which
a JavaScript client rounds and a Python one does not, and a number that is not finite (``NaN``,
``Infinity``, ``1e400``; Python's ``json`` reads them). :data:`AMBIGUOUS` says so, and the
inspector reports such a response as not inspected in full instead of passing it over
silently.

Linear in the id: no conversion of a long digit string (whose cost grows faster than its
length). An id longer than :data:`MAX_NUMERIC_TEXT` that one of the clients reads as a number is
ambiguous; any other is a plain string.
"""

from __future__ import annotations

import math
import re
from enum import Enum
from typing import Any

#: The largest integer every client holds exactly: a JavaScript number is a double.
MAX_EXACT = 2**53

#: Ids longer than this are not converted to a number (see the module docstring).
MAX_NUMERIC_TEXT = 64

#: What JavaScript's ``Number()`` strips around a string (white space and line terminators).
_JS_SPACE = " \t\n\v\f\r                 　﻿"

#: A decimal literal as ``Number()`` reads it, after the white space is stripped.
_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
#: Hexadecimal, octal and binary literals, which ``Number()`` reads without a sign.
_RADIX = re.compile(r"0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+")
#: A string Python's ``int()`` reads: white space, a sign, decimal digits in any script, single
#: underscores between them.
_PYTHON_INT = re.compile(r"\s*[+-]?\d+(?:_\d+)*\s*")


class Unmatchable(Enum):
    """A number the clients would not agree on: no key, and the response is reported."""

    AMBIGUOUS = "ambiguous"


AMBIGUOUS = Unmatchable.AMBIGUOUS

#: A correlation key: an int for every whole number in range, a float for a fraction, a
#: string for an id no client reads as a number.
Key = int | float | str


def key_of(identifier: Any) -> Key | Unmatchable | None:
    """The correlation key of an ``id`` member, :data:`AMBIGUOUS`, or None for no id at all
    (missing, null, a boolean, an object or a list)."""
    if isinstance(identifier, bool):
        return None
    if isinstance(identifier, (int, float)):
        return _number_key(identifier)
    if isinstance(identifier, str):
        number = _number_in(identifier)
        if number is None:
            return identifier
        return number if isinstance(number, Unmatchable) else _number_key(number)
    return None


def message_id(identifier: Any) -> str | int | None:
    """The id as a recorded event carries it: a string or an int as sent, a whole number sent
    as a float as that int while it is exact (up to 2**53), anything else None."""
    if isinstance(identifier, bool):
        return None
    if isinstance(identifier, (str, int)):
        return identifier
    if isinstance(identifier, float) and math.isfinite(identifier) and identifier.is_integer():
        # What every client reads: the same double. Past 2**53 the doubles are no longer every
        # integer, and an int recorded there could stand for another id; None instead.
        return int(identifier) if -MAX_EXACT <= identifier <= MAX_EXACT else None
    return None


def _number_key(value: int | float) -> Key | Unmatchable:
    if isinstance(value, float):
        if not math.isfinite(value):
            return AMBIGUOUS
        if not value.is_integer():
            return value
        value = int(value)
    return value if -MAX_EXACT <= value <= MAX_EXACT else AMBIGUOUS


def _number_in(text: str) -> int | float | Unmatchable | None:
    """The number one of the clients reads in a string id, or None if neither reads one."""
    if len(text) > MAX_NUMERIC_TEXT:
        return AMBIGUOUS if _reads_as_number(text) else None
    try:
        return int(text)  # the Python SDK: white space, a sign, underscores, any decimal digits
    except ValueError:
        pass
    stripped = text.strip(_JS_SPACE)
    if not stripped:
        return 0  # Number("") and Number(" ") are 0
    if _DECIMAL.fullmatch(stripped):
        return float(stripped)
    if _RADIX.fullmatch(stripped):
        return int(stripped, 0)
    if stripped in _INFINITY:
        return AMBIGUOUS
    return None


_INFINITY = frozenset({"Infinity", "+Infinity", "-Infinity"})


def _reads_as_number(text: str) -> bool:
    """Whether one of the clients reads a number in ``text``, by its shape alone."""
    if _PYTHON_INT.fullmatch(text):
        return True
    stripped = text.strip(_JS_SPACE)
    return (
        not stripped
        or _DECIMAL.fullmatch(stripped) is not None
        or _RADIX.fullmatch(stripped) is not None
        or stripped in _INFINITY
    )
