"""The definitions a run saw: one digest each, read from the recording, compared run against run.

**An observation, never a finding.** A tool, a prompt, a resource or a resource template that a
server lists is a *definition*. The store keeps, for every definition a run's ``*/list`` answers
held, a SHA-256 over its canonical JSON, and says afterwards which definitions were added, removed
or changed between two runs of the same server — and, for a server that sent
``notifications/<kind>/list_changed``, within one run. It never says whether a change is harmless,
and it names the top-level *fields* that changed, never a value.

**Read from what the recording holds.** Nothing is added to the recording: the definitions are the
``items`` of the server's answers to ``tools/list``, ``prompts/list``, ``resources/list`` and
``resources/templates/list``, all pages, as the recorder wrote them — masked. The digest is over
the canonical JSON of the item (keys sorted, no whitespace, UTF-8), so the order of a list
decides nothing.

**The key** of a definition is its kind and its name; for a resource its ``uri``, for a resource
template its ``uriTemplate``. A key that occurs twice in one listing keeps both digests and is
marked ``duplicate``. An item that has no usable key is counted (``unkeyed``), not filed.

**Listings and segments.** A *listing* is one ``*/list`` request with every page of its cursor
chain. It is *complete* when it ended, with a page read that offers no ``nextCursor``, and no
reason was noted against it; otherwise it is *partial*, with its reasons: a page that cannot be
read (``truncated``, ``incomplete``, ``unreadable``, :data:`ERROR_ANSWER`), the reason a
``step_unanswered`` gives, the page limit, :data:`NO_FIRST_PAGE`, :data:`UNREADABLE_REQUEST`, or
:data:`UNFINISHED` where nothing else says why. A ``list_changed`` notification of a kind starts a
new segment of that kind's listings: the listings that began before it are segment 0, those that
began after the first notification segment 1, and so on. A listing belongs whole to the segment in
which it began, so a notification between two of its pages moves nothing. Where a segment holds
several listings, the last complete one stands for it (the last, if none is). A key is a duplicate
only within one listing, so listing twice is not doubling.

A comparison across two runs reads the last segment each run listed; one within a run reads each
segment against the one listed before it. A name missing from a partial listing is never removed,
and a name the partial side lacks is never added: the comparison says ``partial`` with the reason
and claims no more than both sides read. A name on both sides is compared by the *set* of its
digests: ``changed`` for two whole listings when the sets differ, for one partial listing when it
read a digest the whole one lacks, for two partial ones only when each read the name once, with
different digests. A name that occurs more than once in a listing is a ``duplicate``, a hint and
not a change.

A ``*/list`` request for its first page (see :func:`read`) begins a listing whatever comes
back; one that no page was read of (an error answer, no answer, an aborted run) is partial, with
the reason of what came instead.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from mcp_kymograph.events import PAGE_LIMIT

#: Per kind: the member of the answer's ``result`` that holds the items, the method that asks for
#: them, and the item field that names the definition.
LISTINGS: dict[str, tuple[str, str, str]] = {
    "tool": ("tools", "tools/list", "name"),
    "prompt": ("prompts", "prompts/list", "name"),
    "resource": ("resources", "resources/list", "uri"),
    "resource_template": ("resourceTemplates", "resources/templates/list", "uriTemplate"),
}

#: The notification each kind has. A resource template has none of its own.
LIST_CHANGED = {
    "tool": "notifications/tools/list_changed",
    "prompt": "notifications/prompts/list_changed",
    "resource": "notifications/resources/list_changed",
}

#: What a comparison says of a run filed before definitions were kept: not that nothing changed.
NOT_CAPTURED = "not captured"

#: What the comparison says of a ``list_changed`` that no listing followed.
NOT_RE_LISTED = "list_changed, not re-listed"
RE_LISTED = "list_changed, re-listed"

#: Why a listing is not complete when nothing else says: its last page offered a cursor that was
#: never followed, or its last request was never answered.
UNFINISHED = "unfinished"

#: Why a listing is not complete when the server answered its request with a JSON-RPC error.
ERROR_ANSWER = "error_answer"

#: Why a listing is not complete when a client request whose method cannot be read (no string, in
#: a damaged or foreign recording) stood while it was open, or before it began and no first-page
#: request of its kind came between: which list that request asked for, and from which cursor, is
#: unknown, so no page after it can be said to complete a listing.
UNREADABLE_REQUEST = "unreadable_request"

#: Why a listing is not complete when it began with a request for a later page (one that sends a
#: cursor back, or whose document or params cannot be read) and no listing of its kind was open: a
#: recording that starts in the middle of a chain. Its first page was never seen.
NO_FIRST_PAGE = "no_first_page"

_BY_METHOD = {method: kind for kind, (_, method, _) in LISTINGS.items()}
_BY_NOTIFICATION = {method: kind for kind, method in LIST_CHANGED.items()}

#: A lone surrogate (a JSON ``\ud800`` escape) is no text, and the store's database cannot
#: encode it: in a definition's name it becomes U+FFFD before the name is kept, as the announced
#: server name does (:func:`mcp_kymograph.inspection.server_field`). The digest is over the item
#: as the recording holds it, surrogate and all.
_LONE_SURROGATES = dict.fromkeys(range(0xD800, 0xE000), "\N{REPLACEMENT CHARACTER}")


def canonical(value: Any) -> bytes:
    """The canonical JSON of a value: keys sorted, no whitespace, UTF-8. A lone surrogate, which
    UTF-8 cannot hold, is written as the codec's pass-through so that a hostile string still has
    one digest and not a crash."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8", "surrogatepass"
    )


def digest(definition: Any) -> str:
    """The SHA-256 of a definition's canonical JSON, as 64 lowercase hex characters."""
    return hashlib.sha256(canonical(definition)).hexdigest()


@dataclass(frozen=True, slots=True)
class Definition:
    kind: str
    name: str
    digest: str
    #: Per top-level field, the SHA-256 of its canonical JSON: what lets a later comparison name
    #: the fields that changed without keeping a value.
    fields: Mapping[str, str]
    segment: int = 0
    #: The listing of its kind that held it: the index in ``listings[kind]["listings"]``.
    listing: int = 0
    duplicate: bool = False


@dataclass
class Captured:
    """What :func:`read` found in one recording."""

    definitions: list[Definition] = field(default_factory=list)
    #: Per kind that was listed or notified of: ``listings`` (per listing, in the order it began:
    #: ``segment``, ``pages``, ``unkeyed`` and ``unreadable`` counts, ``complete`` and the
    #: ``reasons`` it is not) and ``list_changed`` (``count``, ``first_seq``, ``relisted``) or None.
    listings: dict[str, dict[str, Any]] = field(default_factory=dict)


def read(events: Sequence[Mapping[str, Any]]) -> Captured:
    """The definitions and the ``list_changed`` notifications of a recording's events.

    A listing begins with the request for its first page (:func:`_first_page`: no params member, or
    params that are an object with no cursor or a null one), or with an answer no listing of its
    kind is open for. It ends with the page read that offers no ``nextCursor``, with a JSON-RPC
    error answer (partial, :data:`ERROR_ANSWER`), with a request whose method cannot be read
    (partial, :data:`UNREADABLE_REQUEST`), or where the next request for a first page of its kind
    begins another listing (partial, :data:`UNFINISHED`, if nothing else says why). A request for a
    later page continues the open listing of its kind; where none is open it begins one that is
    partial (:data:`NO_FIRST_PAGE`). A listing belongs whole to the segment in which it began, so a
    notification between two of its pages changes nothing for it. It is complete when it ended and
    nothing says otherwise.

    A request whose method cannot be read fails closed: every listing open at that point is
    partial (:data:`UNREADABLE_REQUEST`), and so is every listing that begins after it, by an
    answer or by a request for a later page, until a readable request of the kind for its first
    page begins one. Only such a request lifts it.
    """
    captured = Captured()
    changed: dict[str, dict[str, Any]] = {}
    current: dict[str, dict[str, Any] | None] = {}
    starts: dict[str, list[int]] = {}
    last_notice: dict[str, int] = {}
    #: The kinds for which a request whose method cannot be read stands since the last readable
    #: first-page request of the kind.
    unread: set[str] = set()

    def begin(kind: str, position: int, *, first: bool = False) -> dict[str, Any]:
        entry = _listing(captured, kind)
        meta: dict[str, Any] = {
            "segment": changed.get(kind, {}).get("count", 0),
            "pages": 0,
            "unkeyed": 0,
            "unreadable": 0,
            "complete": False,
            "reasons": [],
        }
        entry["listings"].append(meta)
        starts.setdefault(kind, []).append(position)
        current[kind] = meta
        if first:
            unread.discard(kind)
        elif kind in unread:
            _note(meta, UNREADABLE_REQUEST)
        return meta

    for position, event in enumerate(events):
        if event.get("type") in ("step_unanswered", "step_skipped"):
            kind = _kind(_BY_METHOD, event.get("step"))
            held = captured.listings.get(kind, {}).get("listings") if kind else None
            reason = event.get("reason")
            if (
                held
                and isinstance(reason, str)
                and (event["type"] == "step_unanswered" or reason == PAGE_LIMIT)
            ):
                _note(held[-1], reason)
            continue
        if event.get("type") != "message":
            continue
        parse = event.get("parse") if isinstance(event.get("parse"), dict) else {}
        if event.get("direction") == "client_to_server":
            asked = (
                _kind(_BY_METHOD, parse.get("method")) if parse.get("kind") == "request" else None
            )
            if asked is not None and _first_page(event):
                begin(asked, position, first=True)
            elif asked is not None and current.get(asked) is None:
                # A later page with no listing open: the chain's first page was never seen.
                _note(begin(asked, position), NO_FIRST_PAGE)
            elif asked is None and parse.get("kind") == "request" and _unread(parse):
                # It may have asked for any list, from any cursor: no listing that was open, or
                # that begins after it, ends complete until a readable first-page request of its
                # kind begins one.
                for meta in current.values():
                    if meta is not None:
                        _note(meta, UNREADABLE_REQUEST)
                current.clear()
                unread.update(LISTINGS)
            continue
        if event.get("direction") != "server_to_client":
            continue
        notified = (
            _kind(_BY_NOTIFICATION, parse.get("method"))
            if parse.get("kind") == "notification"
            else None
        )
        if notified is not None:
            seen = changed.setdefault(notified, {"count": 0, "first_seq": event.get("seq")})
            seen["count"] += 1
            last_notice[notified] = position
            continue
        kind = _kind(_BY_METHOD, event.get("responded_method"))
        if kind is None:
            continue
        meta = current.get(kind)
        if _is_error(event):
            # An error answer ends the chain, and the listing it answers has begun all the same:
            # a listing without a page read, partial for the word "error_answer".
            if meta is None:
                meta = begin(kind, position)
            meta["unreadable"] += 1
            _note(meta, ERROR_ANSWER)
            current[kind] = None
            continue
        if meta is None:
            meta = begin(kind, position)
        index = len(captured.listings[kind]["listings"]) - 1
        members = _page(event, LISTINGS[kind][0])
        if members is None:
            meta["unreadable"] += 1
            _note(meta, _unreadable(event))
            continue
        meta["pages"] += 1
        if _next(event) is None:
            meta["complete"] = True
            current[kind] = None
        for item in members:
            name = item.get(LISTINGS[kind][2]) if isinstance(item, dict) else None
            if not isinstance(name, str) or not name:
                meta["unkeyed"] += 1
                continue
            captured.definitions.append(
                Definition(
                    kind,
                    # Two names that differ only in their lone surrogates are one name now, and
                    # so a duplicate in the listing, which _marked says.
                    name.translate(_LONE_SURROGATES),
                    digest(item),
                    {key: digest(value) for key, value in item.items() if isinstance(key, str)},
                    meta["segment"],
                    index,
                )
            )
    for kind, seen in changed.items():
        entry = _listing(captured, kind)
        entry["list_changed"] = {
            **seen,
            "relisted": any(start > last_notice[kind] for start in starts.get(kind, ())),
        }
    for entry in captured.listings.values():
        for meta in entry["listings"]:
            if not meta["reasons"] and not meta["complete"]:
                meta["reasons"].append(UNFINISHED)
            # The last page read offered no cursor, but a reason stands against the listing (a
            # page before it that could not be read, no first page, an unreadable request, a
            # step_unanswered or the page limit after it): not complete.
            meta["complete"] = meta["complete"] and not meta["reasons"]
    captured.definitions = _marked(captured.definitions)
    return captured


def _kind(table: Mapping[str, str], method: object) -> str | None:
    """The kind a method names, or None. A value that is no string, as a damaged or foreign
    recording may hold (a list cannot even be looked up), names no kind: the event matches
    nothing, and a listing it would have begun or answered stays as the rules leave it."""
    return table.get(method) if isinstance(method, str) else None


def _unread(parse: Mapping[str, Any]) -> bool:
    """Whether a request's method cannot be read: absent or no string. A readable method that
    names no list (``tools/call``) is no concern of the listings."""
    return not isinstance(parse.get("method"), str)


def _listing(captured: Captured, kind: str) -> dict[str, Any]:
    return captured.listings.setdefault(kind, {"listings": [], "list_changed": None})


def _note(meta: dict[str, Any], reason: str) -> None:
    if reason not in meta["reasons"]:
        meta["reasons"].append(reason)


def _first_page(event: Mapping[str, Any]) -> bool:
    """Whether a ``*/list`` request asks for the first page: it has no params member, or params
    is an object with no cursor (or a null one). A request that sends any other cursor back, or
    whose document or params cannot be read (``"params": null`` included, which is no object),
    is taken for a later page: failing closed, it never begins a listing that can end complete."""
    payload = event.get("payload")
    document = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(document, dict):
        return False
    if "params" not in document:
        return True
    params = document["params"]
    return isinstance(params, dict) and params.get("cursor") is None


def _unreadable(event: Mapping[str, Any]) -> str:
    if event.get("truncated"):
        return "truncated"
    return "incomplete" if event.get("incomplete") else "unreadable"


def _next(event: Mapping[str, Any]) -> object:
    """What the page offers after itself: None at the end of a listing."""
    payload = event.get("payload")
    document = payload.get("data") if isinstance(payload, dict) else None
    result = document.get("result") if isinstance(document, dict) else None
    return result.get("nextCursor") if isinstance(result, dict) else None


def _page(event: Mapping[str, Any], member: str) -> list[Any] | None:
    """The items of one list answer, or None when it holds none that can be read."""
    payload = event.get("payload")
    document = payload.get("data") if isinstance(payload, dict) else None
    result = document.get("result") if isinstance(document, dict) else None
    members = result.get(member) if isinstance(result, dict) else None
    if event.get("truncated") or event.get("incomplete") or not isinstance(members, list):
        return None
    return members


def _is_error(event: Mapping[str, Any]) -> bool:
    """An answer that is a JSON-RPC error: it ends the open listing of its kind, or begins one
    where none is open, partial either way (``error_answer``)."""
    payload = event.get("payload")
    document = payload.get("data") if isinstance(payload, dict) else None
    return isinstance(document, dict) and "error" in document


def _marked(definitions: list[Definition]) -> list[Definition]:
    """The definitions with ``duplicate`` set on each key held more than once in a listing."""
    counts: dict[tuple[str, int, str], int] = {}
    for item in definitions:
        key = (item.kind, item.listing, item.name)
        counts[key] = counts.get(key, 0) + 1
    return [
        Definition(
            item.kind,
            item.name,
            item.digest,
            item.fields,
            item.segment,
            item.listing,
            counts[(item.kind, item.listing, item.name)] > 1,
        )
        for item in definitions
    ]


# -- comparing ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Recorded:
    """What the store holds of one run's definitions."""

    listings: Mapping[str, Mapping[str, Any]]
    definitions: Sequence[Definition]

    def segments(self, kind: str) -> list[int]:
        """The segments of a kind in which a listing began."""
        return sorted({meta["segment"] for meta in self.listings.get(kind, {}).get("listings", ())})

    def chosen(self, kind: str, segment: int) -> int:
        """The listing standing for a segment: the last complete one, failing that the last."""
        metas = self.listings[kind]["listings"]
        in_segment = [i for i, meta in enumerate(metas) if meta["segment"] == segment]
        complete = [i for i in in_segment if metas[i]["complete"]]
        return (complete or in_segment)[-1]

    def segment(self, kind: str, segment: int) -> dict[str, list[Definition]]:
        index = self.chosen(kind, segment)
        grouped: dict[str, list[Definition]] = {}
        for item in self.definitions:
            if item.kind == kind and item.listing == index:
                grouped.setdefault(item.name, []).append(item)
        return grouped

    def partial(self, kind: str, segment: int) -> dict[str, Any] | None:
        """Why the listing that stands for a segment is partial, None when it is complete."""
        meta = self.listings[kind]["listings"][self.chosen(kind, segment)]
        if meta["complete"]:
            return None
        return {"reasons": list(meta["reasons"]), "unreadable": meta["unreadable"]}

    def total(self, kind: str, name: str) -> int:
        return sum(meta[name] for meta in self.listings.get(kind, {}).get("listings", ()))


def compare(
    before: Recorded | None, after: Recorded | None, *, same_entry: bool = True
) -> dict[str, Any]:
    """What changed in the definitions between two runs, and within each of them.

    ``before`` or ``after`` is None for a run the store holds no definitions of
    (:data:`NOT_CAPTURED`). Per kind and name only ``added``, ``removed`` and ``changed`` are
    listed; a changed definition carries the names of its top-level fields that differ; what is
    unchanged is a number. A kind whose listing is partial on one side says ``partial`` with the
    reason: a name missing from a partial listing is not removed, and one the other side's partial
    listing lacks is not added. No value of a definition is in the result.
    """
    result: dict[str, Any] = {
        "captured": {"before": before is not None, "after": after is not None},
        "status": "compared",
        "kinds": {},
        "within_run": {"before": {}, "after": {}},
        "list_changed": {"before": {}, "after": {}},
    }
    if before is None or after is None:
        result["status"] = NOT_CAPTURED
        result["note"] = (
            f"{NOT_CAPTURED}: the definitions of "
            f"{'the earlier run' if before is None else 'the later run'} were not kept when it "
            "was filed; nothing is said of whether they changed"
        )
    elif not same_entry:
        result["status"] = "different corpus entries"
        result["note"] = "different corpus entries: their definitions are not compared"
    for side, held in (("before", before), ("after", after)):
        if held is None:
            continue
        result["list_changed"][side] = _list_changed(held)
        result["within_run"][side] = {
            kind: pairs for kind in LISTINGS if (pairs := _within(held, kind))
        }
    if before is not None and after is not None and result["status"] == "compared":
        for kind in LISTINGS:
            result["kinds"][kind] = _across(before, after, kind)
    return result


def _list_changed(held: Recorded) -> dict[str, Any]:
    found = {}
    for kind, entry in held.listings.items():
        notified = entry.get("list_changed")
        if notified:
            found[kind] = {
                "count": notified["count"],
                "first_seq": notified["first_seq"],
                "relisted": notified["relisted"],
                "status": RE_LISTED if notified["relisted"] else NOT_RE_LISTED,
            }
            partial = held.partial(kind, held.segments(kind)[-1]) if notified["relisted"] else None
            if partial is not None:
                found[kind]["partial"] = partial
    return found


def _within(held: Recorded, kind: str) -> list[dict[str, Any]]:
    segments = held.segments(kind)
    return [
        {"from_segment": earlier, "to_segment": later}
        | _sets(
            held.segment(kind, earlier),
            held.segment(kind, later),
            ("from", held.partial(kind, earlier)),
            ("to", held.partial(kind, later)),
        )
        for earlier, later in zip(segments, segments[1:], strict=False)
    ]


def _across(before: Recorded, after: Recorded, kind: str) -> dict[str, Any]:
    first, second = before.segments(kind), after.segments(kind)
    if not first or not second:
        said = [side for side, segments in (("before", first), ("after", second)) if not segments]
        return {"state": f"not listed in {' and '.join(said)}"}
    return {
        "state": "compared",
        **_sets(
            before.segment(kind, first[-1]),
            after.segment(kind, second[-1]),
            ("before", before.partial(kind, first[-1])),
            ("after", after.partial(kind, second[-1])),
        ),
        "unlisted": {
            side: {name: held.total(kind, name) for name in ("unkeyed", "unreadable")}
            for side, held in (("before", before), ("after", after))
        },
    }


def _sets(
    old: Mapping[str, list[Definition]],
    new: Mapping[str, list[Definition]],
    older: tuple[str, dict[str, Any] | None],
    newer: tuple[str, dict[str, Any] | None],
) -> dict[str, Any]:
    """Added, removed and changed names, the number unchanged, and the names that occur more than
    once in a listing. Each side comes with its name and why its listing is partial, or None.

    A name is removed only when the new side was read whole, and added only when the old side
    was. For a name on both sides the *sets* of its digests are compared, never their number:

    * both sides whole: changed exactly when the sets differ;
    * one side partial: changed exactly when the partial side read a digest the whole side lacks;
    * both partial: changed only for a name each side read exactly once, with different digests.

    Every name that occurs more than once in a listing of either side is listed under
    ``duplicates``, a hint and not a change: the name, the side (``older``'s or ``newer``'s label,
    or ``both``) and, under each label, how often the listing holds it.
    """
    old_partial, new_partial = older[1], newer[1]
    added, removed, changed, duplicates, unchanged = [], [], [], [], 0
    for name in sorted(old.keys() | new.keys()):
        counts = {older[0]: len(old.get(name, ())), newer[0]: len(new.get(name, ()))}
        if any(count > 1 for count in counts.values()):
            doubled_on = [side for side, count in counts.items() if count > 1]
            duplicates.append(
                {"name": name, "side": doubled_on[0] if len(doubled_on) == 1 else "both"} | counts
            )
        if name not in old:
            if old_partial is None:
                added.append({"name": name, "duplicate": len(new[name]) > 1})
        elif name not in new:
            if new_partial is None:
                removed.append({"name": name, "duplicate": len(old[name]) > 1})
        else:
            doubled = len(old[name]) > 1 or len(new[name]) > 1
            moved = _moved(old[name], new[name], old_partial, new_partial)
            if moved is None:
                unchanged += 1
            else:
                changed.append({"name": name, "duplicate": doubled, "fields": moved})
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "duplicates": duplicates,
        "partial": {side: why for side, why in (older, newer) if why is not None},
    }


def _moved(
    old: Sequence[Definition],
    new: Sequence[Definition],
    old_partial: dict[str, Any] | None,
    new_partial: dict[str, Any] | None,
) -> list[str] | None:
    """The top-level fields that differ for a name on both sides, or None when it is not changed.

    Only a digest that both sides can explain counts. What a whole side holds and a partial side
    lacks may sit on a page that was not read, so it is no difference; what a partial side read
    and the whole side lacks is one. The fields named come from every definition read on both
    sides: a field differs when a definition of one side has a value in it (an absent field counts
    as a value) that no definition of the other side has. A changed name names none only when its
    digests cover each other: every value occurs on the other side, combined otherwise.
    """
    if old_partial is not None and new_partial is not None and (len(old) > 1 or len(new) > 1):
        return None
    seen_old, seen_new = {d.digest for d in old}, {d.digest for d in new}
    # A side's digests count when the other side is whole, or both sides are partial.
    only_old = (
        [d for d in old if d.digest not in seen_new]
        if new_partial is None or old_partial is not None
        else []
    )
    only_new = (
        [d for d in new if d.digest not in seen_old]
        if old_partial is None or new_partial is not None
        else []
    )
    if not only_old and not only_new:
        return None
    # A field differs when the sets of its values on the two sides differ: a value of one side
    # that the other lacks. Each side's sets are built once, so a name held tens of thousands of
    # times on each side costs time in proportion to its fields, not to their square.
    held_old, held_new = _values(old), _values(new)
    return sorted(
        name
        for name in held_old.keys() | held_new.keys()
        if held_old.get(name, _ABSENT) != held_new.get(name, _ABSENT)
    )


#: The values of a field that no definition of a side has: absent, which counts as a value.
_ABSENT: frozenset[str | None] = frozenset({None})


def _values(items: Sequence[Definition]) -> dict[str, set[str | None]]:
    """Per top-level field, the digests the definitions hold in it, with None for a definition
    that lacks the field. One pass over the definitions and their fields."""
    values: dict[str, set[str | None]] = {}
    present: dict[str, int] = {}
    for item in items:
        for key, value in item.fields.items():
            values.setdefault(key, set()).add(value)
            present[key] = present.get(key, 0) + 1
    for key, count in present.items():
        if count < len(items):
            values[key].add(None)
    return values
