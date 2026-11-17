# The web interface's look: workbench with strip

Status: **built.** The page of `kymograph web` in this version is this design: the tokens
below in `:root` of `app.css`, the workbench, and the strip with its pane on a run's findings tab,
as `CONTRACT.md` 7 describes the page. One thing is not built; it is the last section.

The design the page of `kymograph web` follows. It is two things:

1. **The workbench.** A forest rail on the left with the navigation, a calm light work area, one
   accent colour, state colours only where a state is said.
2. **The strip.** On a run's findings tab, statements against messages as one table of traces: a
   dotted line where no reading is recorded, a solid line where it read and nothing fired, a
   dashed line where it was evaluated with a reason, a spike where it fired. Selecting a row
   shows its detail in a pane beside the strip.

`docs/design/web-interface.md` audits the earlier mockups and stays as history. Where this note and
`src/mcp_kymograph/web/CONTRACT.md` disagree, the contract is right.

## What does not move

- No inline `style=`, no inline script, no outbound request, no web font: system font stacks.
- Attributes only through `h()` and `setState()`; no element or attribute from data.
- Every string off the wire through `vis()` or `visText()`; a value of any length stays in its box.
- Links only to `#/…` routes through `href()`.
- Notices first, in envelope order. A run that is not a result shows its state and every cause key
  before anything else, and its empty lists say that the run is not a result.
- A capped listing says how much of how much.
- Real-world findings stay apart, always with the `candidates` notice.
- The colour meaning of the state chips: `complete` green, `call_failed` yellow, `incomplete`
  orange, `server_failed` red, `sandbox_failed` purple.

## Tokens

All in `:root` of `app.css`. A rule uses the variable, never the value.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#F4F6F5` | page ground, sunken blocks (`pre`, `.inplace`) |
| `--surface` | `#FFFFFF` | panels, detail pane |
| `--ink` / `--ink-2` | `#17201C` / `#33403A` | text |
| `--muted` | `#55615C` | labels, notes, table headers |
| `--faint` | `#8A9690` | dashed frames, input borders; not for text (3.1:1 on white) |
| `--line` / `--line-2` | `#DDE3E0` / `#EEF1EF` | panel borders / row rules |
| `--line-strong` | `#17201C` | the rule under a table head |
| `--forest` | `#0A271B` | rail, primary button, active tab, selected fired row, spike |
| `--forest-raised` | `#12382A` | active and hovered rail item |
| `--mint` | `#F0FFF9` | text on forest |
| `--rail-muted` | `#C3D3CC` | inactive rail text |
| `--tint` | `#E3EFE8` | selected table row, `complete` chip |
| `--focus` | `#1F6F8B` | focus ring, 2px with 2px offset (`#7CC8E6` inside the rail) |
| `--radius` / `--radius-sm` | `8px` / `6px` | panels and notices / chips, buttons, inputs, `pre` |
| `--gap` | `24px` | between blocks of a page |
| `--rail` | `220px` | width of the rail |
| `--trace-none` / `--trace-quiet` | `#8A9690` / `#55615C` | dotted and solid trace, 3:1 and more |

Type: `--sans` 14px/1.45 for text, `--mono` 12.5px for identifiers, paths, digests and recorded
values. Page title 24px/600, panel title 16px/600, table header 12.5px/500 in `--muted`, sentence
case. No capitals for labels, with one exception that carries meaning: the label of
`recording_changed` and `bundle_not_intact`, which must read graver than "not found".

## The workbench

- `index.html` is unchanged. The rail is `header.top`, laid out by CSS: `body` is a grid of
  `var(--rail)` and the rest, `.top-in` is sticky and as tall as the window, `.top-meta` sits at
  its foot. Below 860 px the rail is a bar on top and its navigation wraps.
- Review mode: a slim bar with the meta line only, the content centred; no navigation.
- Tables: sentence-case headers, one dark rule under the head, light row rules. A cell wraps
  anywhere but is never narrower than ten characters; a table that does not fit scrolls sideways
  in its `.tablewrap`. The page itself never scrolls sideways.
- A tag (`.tag`) wraps within its box, since it can hold a sentence or a name of any length; a
  state chip (`.chip`) does not. Recorded text (`.wire`) breaks anywhere.
- `not_a_result`: a white panel framed in the state's colour, the label in that colour, the causes
  as rows under one dark rule. `not_recorded_by_this_version`: a quiet grey block without a frame.
- No animation: nothing moves on load, on hover or on selection.

## The strip

Drawn on the findings tab when the run recorded at least one `statement_evaluated` event;
otherwise the tab is the tables alone, as before. Every event of the tab stays on the page: the
tables are behind one toggle under the strip and the pane, over the whole width.

The strip says what is recorded and nothing about why. Three things it never says: that a
statement "did not apply" (no record can also mean the message was never inspected, or the record
was dropped), that the walk "did not observe" something (the walk does not look everywhere), and
that "no statement" saw what the walk observed (a finding can be cut by the cap of its message).

- **Rows.** One per statement, in the order of its first event; then one per statement that only
  a finding names (a recording cut short); then, in a second `tbody`, one per observation of the
  built-in walk without a finding of the same message, path and signal, marked "walk, no
  finding". The statement or the observation is the header of its row (`th scope="row"`).
- **Columns.** Every message where the run has at most 12 and the list read from the server holds
  exactly as many as the run view counts; else the messages an event of the tab names, the first
  12 in order. The panel's note says which of the two, and how many of how many. A message the
  run view lists as truncated or incomplete has a mark in its header, and a sentence under the
  table names it by number and says which: such a message is never inspected. A header's arrow
  has its words (direction and method) for a reader who does not see it. A message column is
  59px wide with up to five of them and 55px with more; with more than five the strip takes the
  whole width and the pane goes under it, so that twelve fit at 1440 px. Where the table does
  not fit it scrolls sideways within itself.
- **Cells.** For a statement and a message: no `statement_evaluated` event is a dotted line, "no
  record": the statement did not apply to the message, the message was not inspected, or the
  record was not written (the event is one the recorder may drop under load). It is never
  "nothing found". Events with nothing fired and no reason, a solid line; a reason and nothing
  fired, a dashed line; a count above zero, the spike with the count beside it; an event whose
  `fired` is not counts, the dashed line too, with words of its own. Each trace has its words
  for a reader who does not see it.
- **Class and built-in walk.** The classes of the row's findings; and of how many of them an
  observation of the same message, path and signal is recorded: "observed too", "K of N
  observed", "no observation recorded". The last is not "the walk looked and saw nothing": the
  walk does not look at every place a statement can point at, looks only for the signals that
  reach everywhere or the metadata, keeps a limited number of observations per message, can be
  stopped, and a record can be dropped. A note under the legend says so.
- **A row that fired** is framed and bold, by its events and findings and not by what a column cap
  leaves visible.
- **A row of the walk without a finding** is not a statement and is not drawn as one that fired:
  a dot at its message, the tag, the signal and the path. It does not say that no statement
  fired there: findings are capped per message and a record can be dropped. Where a
  `findings_capped` event names its message, the row and the pane say so. What else the walk
  read is not recorded per message.
- **A run that is not a result** says so in the panel's note beside the count of what fired, as
  the tables' panels do; a capped tab says so there too.
- **Selection.** The statement is a link to the same tab with `st` (a row of the walk: `obs`,
  the `seq` of its event). The value goes into the address through `href()` only and is compared
  with `===` against the events' own values, never used to build a selector. Without `st` and
  `obs` the first statement that fired is selected, never a row of the walk. An address that
  differs from the one shown in `st` and `obs` alone is the same place: the focus goes to the
  selected row where the address names one, the strip keeps its sideways scroll (also after the
  focus moved) and the tables under it are drawn open if they were. Any other address is
  another place, and the focus goes to the page's heading.
- **The pane.** The statement; per message what was checked, what fired and the reason, the
  messages it fired on or gave a reason for first; in a block of its own, since it is no one
  message's, the count `run_finished` holds for the statement; each
  finding with signal, class, locator, path, message, reading, whether an observation of the walk
  is recorded beside it, and its key in the store. Where the findings recorded for a message and
  the count in `statement_evaluated` differ, the pane says so in either direction. More than 20
  messages or 20 findings are capped in the pane and said so; the tables hold all.
- **Widths of identifiers.** In the run list and the store's list the cells of a run's name
  (`w-ref`), its start (`w-time`) and the pair (`w-pair`) have a least width, so that each stays
  on one line where there is room; the lists do not scroll sideways at 1440 px.

## Not built

- The recorded text of the field a signal fired on, in the pane. The run view does not carry it;
  review mode does (`CONTRACT.md` 6.2). Showing it here needs the run view's contract extended.
