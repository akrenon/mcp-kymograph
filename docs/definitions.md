# Definitions

A server tells a client what it offers in its `tools/list`, `prompts/list`, `resources/list` and
`resources/templates/list` answers. Each item is a **definition**. The store keeps one digest per
definition of every run, so that a later run of the same server can be asked: did what it offers
change? The answer is an **observation**: it carries no finding, no severity and no judgement of
whether a change matters.

## What is kept

For each tool, prompt, resource and resource template in the run's `*/list` answers, over all
pages, the store keeps a SHA-256 over the definition's canonical JSON: keys sorted, no
whitespace, UTF-8. The definition is read from the recording as the recording holds it, that is
masked; nothing is added to the recording for this. The order of a list decides nothing.

A definition is keyed by its kind and its name; a resource by its `uri`, a resource template by
its `uriTemplate`. If a key occurs twice in one **listing**, both digests are kept and the key is
marked as a duplicate. An item with no usable key is counted, not filed, and so is a list answer
that cannot be read: one the recorder cut at the size limit (`truncated`) or marked `incomplete`,
one that is not JSON or whose result holds no list of items (`unreadable`), and a JSON-RPC error
answer (`error_answer`). These are the *unreadable pages* a comparison counts. A lone surrogate
in a name (a JSON `\ud800` escape) is stored as U+FFFD, while the digest is over the item as
recorded; two names that differ only there are one name, a duplicate in its listing.

A *listing* is one `*/list` request with every page of its cursor chain. It is **complete** when
it ended, with a page read that offers no `nextCursor`, and no reason was noted against it.
Otherwise it is **partial**, with its reasons; all of them are listed under
[Partial listings](#store-diff) below. A partial listing is never a short one: a name it lacks
may be one the server offered on a page that was not read.

A listing begins with the request for its first page: one with no params, or with params that
are an object sending no cursor back. A request that sends a cursor back, or whose document or
params cannot be read (`"params": null` among them), continues the open listing of its kind;
where none is open (a recording that starts in the middle of a chain), the listing it begins is
partial with the reason `no_first_page`. A client request whose method cannot be read, which
only a damaged recording holds, may have asked for any list from any cursor: every listing open
at that point is partial with the reason `unreadable_request`, and so is every listing that
begins after it, by an answer or by a request for a later page, until a readable request of that
kind for its first page begins one. Only such a request lifts it.

Beside each digest the store keeps, per top-level field of the definition, the SHA-256 of that
field's canonical JSON. That is what lets a comparison name the fields that changed without the
store holding a value. One digest per field means that a field with few possible values (a
`title`, a boolean in `annotations`) can be guessed by trying values. That is accepted: the store
and a bundle hold the recordings, with the values, beside the digests.

### Store schema 13

Two tables hold this, created when a store of schema 13 is opened for writing. The schema number
does not move.

| Table | Columns |
|---|---|
| `definition_runs` | `run`, `listings` (JSON: per kind its listings, each with its `segment`, `pages`, `unkeyed` and `unreadable` counts, whether it is `complete` and the `reasons` it is not, and the `list_changed` notifications seen) |
| `definitions` | `run`, `segment`, `listing` (the index among the kind's listings), `kind` (`tool`, `prompt`, `resource`, `resource_template`), `name`, `digest`, `fields` (JSON: field name to digest), `duplicate` |

A store whose `definitions` or `definition_runs` table has other columns than these comes from an
earlier state of schema 13. It is refused with a `store error` that names the table and says the
store must be created anew (`store ingest` and `store diff` exit with 2, without a traceback). There
is no migration: a table of another shape only ever came from an unreleased build of this step.
A store of schema 13 made before this step has neither table; it gets both the first time it is
opened for writing.

A run filed before these tables existed has no row in `definition_runs`. A comparison says
**not captured** for it, never "unchanged". Filing the same recording again does not add rows to
a run already filed; to capture the definitions of an older run, drive and file it again into a
store.

## `list_changed`

A `notifications/tools/list_changed` (and the same for prompts and resources) in the recording is
counted at `store ingest`, per kind, with the sequence number of the first. A notification
starts a new *segment* of that kind: the listings that began before it are segment 0, those that
began after the first notification segment 1, and so on. A listing belongs whole to the segment
in which it began: with the request for its first page, or with a request for a later page or an
answer when no listing of its kind is open. A notification in the middle of a listing, between
two of its pages, starts the new segment only with the next listing that begins after it. A resource
template has no notification of its own and stays in segment 0.

Where a segment holds several listings (the client asked twice without a notification between),
the last complete one stands for the segment, or the last if none is complete. Listing twice
therefore doubles nothing: a key is a duplicate only within one listing.

If a listing of that kind **began** after the last notification, the run is `list_changed,
re-listed`, and its segments are kept apart, even when that listing is partial. What is reported as
partial then is the listing that stands for the last segment: where no listing of that segment is
complete, the last one, with its reasons; where a listing of the segment is complete, it stands, and
nothing is reported as partial. A `*/list` request for its first page (as defined above: no params,
or params that are an object sending no cursor back) begins a listing whatever comes back: a
JSON-RPC error answer, no answer, an aborted run. A listing without a page read is partial, with the
reason of what came instead, among them `error_answer`; `truncated`, `incomplete` or `unreadable`
for an answer that cannot be read (a result without a list of items is one); the reason the
recording gives for a missing answer (`no_answer`, `connection_closed`, ...); `unreadable_request`
where a request whose method cannot be read came while the listing was open or before it began; and `unfinished` where nothing says why. If no
listing of that kind began after the last notification, the run is `list_changed, not re-listed`:
the server said its list changed and the run never listed again.

## `store diff`

```
kymograph store diff --store FILE BEFORE AFTER [-q]
```

Besides the findings, `store diff` compares the definitions of the two runs. This is only done
for two runs of the same corpus entry; for two entries it says so and compares nothing.

* **Across the runs**, per kind, over the last segment each run listed: each definition is
  `added`, `removed` or `changed`, and what is unchanged is a number. A name is compared by the
  **set** of its digests in the listing, never by their number, and only by a digest that both
  sides can explain:
  * both listings complete: `changed` exactly when the sets differ;
  * one listing partial: `changed` exactly when the partial side read a digest the complete side
    lacks (what only the complete side holds may be on a page the partial side never read);
  * both partial: `changed` only for a name each side read exactly once, with different digests.

  Every name that occurs more than once in a listing of either side is named under `duplicates`,
  a hint and not a change: the name, the side and how often each
  side's listing holds it. The `side` is `before`, `after` or `both`, within a run `from`, `to` or
  `both`. The listing that counts is the one that stands for the side, also where it is partial;
  other listings of the same side do not count. The terminal says it as `[before: 0, after: 3]`,
  with ` (partial)` behind the number of a side read only in part (`[before: 0 (partial), after:
  2]`), and `... and N more duplicates` beyond the first 20. The same content twice against
  once is not `changed`. A `changed` definition lists the names of its top-level fields in which
  a digest read on one side has a value (a missing field counts as a value) that no digest read on
  the other side has, such as `description` or `inputSchema`; a field that one side drops is
  named. The list is empty only when the digests cover each other: every value occurs on the other
  side, only combined differently. No value of a definition is printed, on the
  terminal or in the JSON on stdout (`definitions`). A kind that one of the runs never listed is
  not compared: it is reported as not listed, not as removed.
* **Partial listings.** Where the listing that stands for a kind is partial on one side, the
  comparison says `partial` for that kind, with its reasons and the number of unreadable pages
  (as counted under [What is kept](#what-is-kept)), on the terminal and in the JSON, and no value.
  The reasons are: a page that cannot be read (`truncated`, `incomplete`, `unreadable`,
  `error_answer`); the reason a `step_unanswered` gives for a page asked for and not answered in
  full (`no_answer`, `connection_closed`, `cursor_invalid`, ... as the recording says); the page
  limit (`page_limit_reached`); `no_first_page`; `unreadable_request`; and `unfinished`, for a
  listing whose last page offered a cursor never followed, or whose request went unanswered,
  where nothing else says why. A name missing from a partial listing is never
  `removed`, and a name the partial side lacks is never `added`. `changed` still holds where both
  sides read the name, by the rules above. A partial listing is never a short one.
* **Within a run**, for a run with a `list_changed` and a later listing: each segment against the
  one listed before it, with the same three sets.
* A run without captured definitions is reported as **not captured**.

The names printed are the keys of the definitions (tool and prompt names, resource URIs) and the
names of fields. Both come from the server; the terminal output limits and escapes them as it does
any text of the server's.
