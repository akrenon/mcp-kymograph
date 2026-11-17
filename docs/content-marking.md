# Marking of foreign content

A server hands content it does not own (a web page, a file, a row of a database) on to a model.
The question is whether it says so. The tool establishes this per delivery, at a canary that the
examiner has put into the foreign source before the run. The result is **an observation, not a
severity**: it is not a finding, and nothing ranks it.

## The two commands

`engagement marking` reads the open pattern list, which is YAML, so it needs the optional `yaml`
extra (`pip install 'mcp-kymograph[yaml]'`); without it the command is refused (exit `2`) and
says so. `engagement canary` needs nothing beyond what reading the engagement file needs.

```bash
# the canaries of the file with their values, for the person running the engagement to plant (stdout; writes nothing)
kymograph engagement canary engagement.yaml [--id ID] [--json]

# where each canary came back in a recording, and how it was marked (reads the recording only)
kymograph engagement marking RUN (--engagement engagement.yaml | --canaries-file canaries.json) [--json]
```

**`engagement canary`** prints, for each canary, its ID, kind, place (`where`, and `path` for a
`file` canary) and value, on stdout. Nothing is written. A place is never cut short. `--json`
has `where` and `path` exactly as the file has them (non-ASCII and control characters escaped);
the text has them with invisible characters taken out, and a line where that changed something
ends with `(not printable as given; --json has it exactly)`. The value is
`kymograph-canary-` and the first 16 hex characters of HMAC-SHA256, keyed with the engagement's
salt (the variable `salt_env` names), over `canary`, the engagement's ID and the canary's ID,
each separated by a NUL byte. It is unique per engagement and place, and it is no instruction, no
URL, nothing a model could follow. A file whose salt is not in the environment (or is shorter than
32 characters, as for a run) is refused.

A canary planted before the tool was called Kymograph has the same 16 characters after another
prefix. `engagement canary` prints the value as it is made today, so to find or remove such a
canary, search for the 16 characters. `engagement marking --engagement` looks for each canary
under both prefixes, so a recording made then is read as before. A `--canaries-file` holds the
values as they are and is read as it is.

**`engagement marking`** reads the recording and nothing else: it sends nothing and writes
nothing. Exactly one of `--engagement` (the values come from the file and the salt) and
`--canaries-file` (a JSON object `{id: value}`, for a run made without an engagement) is required.
With `--engagement`, the run must say it was made under that engagement's ID.

The canaries file is read up to 1 MiB (the bound of the other file inputs); a larger file, a file
nested too deeply to parse, a file that is not a non-empty object of non-empty strings, and a value
with a comma, which could stand across two IDs of a list in the output, are
refused (exit `2`, no traceback). Each ID has the form of a canary ID in an engagement file: 1 to
64 characters of letters, digits, `.`, `_` and `-`, the first a letter or a digit. Any other ID
is refused, and the refusal does not name it. An ID that contains the value of a canary is
refused too, because every output shows the IDs; the refusal names neither. At most 256 canaries are read at once, from the file and from an engagement file alike; more are
refused, because the work is the number of values times the number of strings of the recording
(the refusal names the number, never an ID or a value). A value is at least 8 characters: a shorter one
would hit nearly every place of a message and fill the output, so it is refused (the refusal does
not name the value).

It searches every message of the server whose payload is JSON (`server_to_client`), the whole
JSON: results, errors, `initialize.instructions`, and the descriptions in the `*/list` answers.
A hit is the exact string in a string, also in a key.

Exit status: `0` shown, `2` refused. The state of the run (`verdict.judge`) is the first line; a
run that is not a result is read all the same and says so there.

## The rule

Each **delivery** (one place of a canary in one string of one message) is given four properties:

* **A** the source is named in the same result;
* **B** the beginning of the foreign block is delimited;
* **C** its end is;
* **D** the block is structurally apart.

**The recording does not show who wrote a text: the server or the foreign content. That holds
for the canary's string and for its neighbours alike, because a server may spread foreign content
over several blocks (`[{text: "Page URL: https://x/"}, {text: "<canary>"}]`): the foreign content
then writes the preamble into the neighbouring string. Text therefore never makes a delivery
`delimited`.**

A is **firm** only if it comes from a `uri`: a resource block with a `uri` in `content` or in
`prompts/get`, or an entry of `contents` with a `uri` (mechanical, see *D is mechanical*). A
pattern that gives A is text, in any string, and never firm; it still gives A and stays under
`to_confirm`.

| Marking | Condition |
|---|---|
| `unmarked` | none of the four |
| `delimited` | A from a `uri` (which brings D with it) **and** no note of doubt |
| `partial` | everything between |

A, B, C and D stay observations and are shown in the output. A is true also when it comes from
text alone; it is then not firm.

This holds also for a server that really marks that way: a server that names the source in text,
in the canary's block or in the neighbouring one, is `partial` with `possibly_forged`, because the
foreign content could have written the same. A server that writes `Contents of <url>:` and a fence
around the content into one string is `partial`; so is one that writes `Contents of <url>:` into a
block of its own and the fenced content into the next. A person confirms the marking through
`to_confirm`; the tool does not carry that confirmation back into the marking.

A run counts as its **weakest** delivery (`unmarked` before `partial` before `delimited`); every
delivery is listed. A run with no delivery at all has no marking: `none`, not `unmarked`.
`openWorldHint` does not count.

### Notes of doubt

Each of these notes keeps a delivery from `delimited`, also beside a `uri`:

| Note | When |
|---|---|
| `broken_out` | The foreign content closed the server's block, and the server's closer is left over (see *Breakout*). B and C go. |
| `ambiguous_blocks` | Two complete blocks of the same delimiter, the canary in the second or a later one or between two of them, and nothing left over. The tool cannot tell whether the server wrote two blocks or the foreign content closed the block and opened a new one. B and C go. |
| `possibly_forged` | The delivery is not `delimited`, and at least one of A, B and C comes from text (in any string) and has not gone. An A from a `uri` is no text. |
| `quoted` | The marking stands in a string of the text (see below). It gives no A, B and C. |
| `encoded` | An encoded opener of a tag pair stands before the canary in its string, and no whole pair gives B and C there. It gives no property. |

**`possibly_forged` is no proof of a forgery.** It says that what marks the canary is text, in
the canary's string or beside it, where the foreign content could have written it, and that no
`uri` makes the delivery `delimited`. B and C come from the canary's string only; A from text may
stand in any string of the result. It is a consequence, not a cause: it stands at every delivery
that is not `delimited` and has such a property, also beside a `uri` when another note keeps it
from `delimited` (a resource block with a `uri` whose text has `&lt;untrusted&gt;` and a fence
around the canary: `encoded`, B and C from the fence, and `possibly_forged`). A `delimited`
delivery never carries it, also not with a fence around the canary. An A that a `uri` gives as
well does not count for it.

**`quoted`** has exactly two cases, and there is no looser parser:

1. The **whole** string, white space outside taken off, is JSON (an object, a list or a string:
   it parses, also with an integer of any number of digits; a string that begins with `{` or `[`
   and is nested too deeply to parse counts as JSON too, so that the failing way never gives more
   than the reading one) or a whole `repr`
   (the same `'` or
   `"` first and last, at least two characters). A pattern in it gives no A, B and C. This holds
   also for **another** string of the result in which a pattern would give A: that string gives
   no A, and the note stands at the delivery.
2. In the canary's string, a beginning of the marking stands before the canary in the same `"…"`
   literal of one line: between a pair of unescaped `"` on one line (a line ends at LF, CR or
   CRLF, as everywhere), counted in pairs from the beginning of the line. **Every** match of a
   label and **every** opener of a pair counts, not only the first in the string: in
   `Message: a` and, on the next line, `log: "Message: <canary>"`, the second `Message: ` quotes
   the canary although the first stands outside. The pattern then gives nothing for that
   delivery. A match after the canary in its literal, or in another literal of the line, quotes
   nothing.

A `"` in prose before a whole pair, outside a literal, quotes nothing; nor does a string that
only begins with `{` and is no JSON.

**`encoded`**: the opener is `&lt;`, `&#60;`, `&#x3c;`, `\u003c`, `\x3c` or `%3C` (any case)
followed by `untrusted` or `external`. The recogniser is fixed in the tool, not an entry of the
pattern list. A masked delimiter **inside** a whole pair stays what it is: no note
(`<untrusted>&lt;/untrusted&gt;<canary></untrusted>` has B and C).

`breakout_unchecked` is no note of doubt.

### D is mechanical

D is read from the path in the JSON, not from the text:

* in `result.content` (or `result.contents`): the block is one of several;
* in `result.structuredContent`: the string sits in a field beside other fields, at any level on
  the way down; the only field of `structuredContent` is not D;
* in `result.messages` (`prompts/get`): one of several messages, or one of several blocks in the
  `content` of a message;
* an embedded resource block with a `uri` that is neither empty nor only white space, with the canary in its `text` or
  its `blob`, not in its `uri`, its `mimeType`, its `_meta` or a field below them (`content[n].resource`, and in `prompts/get`
  `messages[i].content.resource` or `messages[i].content[j].resource`) or an item of `contents`
  with such a `uri` is D **and** A, without a need to confirm.

A single block without visible separation is not D. Elsewhere (`initialize`, `*/list`, errors)
D is not established.

### A, B and C are read against a list, and are to be confirmed

They are checked against the open list `src/mcp_kymograph/data/marking-patterns.yaml`. Every
textual match is listed under `to_confirm` with the ID of its pattern: a person reads the answer
and says whether it really marks the content.

| Pattern | Gives | Note |
|---|---|---|
| `code-fence` | B, C | `breakout_unchecked` |
| `untrusted-tag` (`<untrusted…>` … `</untrusted…>`) | B, C | |
| `external-tag` (`<external…>` … `</external…>`) | B, C | |
| `begin-end` (`BEGIN …` / `END …` on lines of their own) | B, C | |
| `contents-of` (`Contents of <url>:`) | A, B | |
| `page-url` (`Page URL: <url>`) | A, B | |
| `message-label` (`Message: `) | B | |
| `commit-label` (`Commit: <hash>`) | A, B | never C: a hash names where text comes from, and nothing marks its end |

A pair or the fence counts only with both ends, one before the canary and one after it; a
preamble counts before the canary. A match counts as "before" only if it ends before the canary
begins, so a line `BEGIN x <canary>` opens no block around the canary.

**A batch** (a JSON-RPC message that is a list) is read element by element: each element is a
result of its own for D and for A, and a pattern that gives A in another element of the batch does
not count. The path shown keeps the index of the element, as in `[0].result.content[0].text`.

**A is the result's.** A pattern that gives A counts if it matches in *any* string of the same
result, before or after the canary, also in a neighbouring block; the pattern is then under
`to_confirm`. Such an A is never firm, in the canary's string or in another: only a `uri` is.
A `quoted` other string gives no A and sets the note. B and C come from the
same string only, and B only from before the canary. The boundaries of JSON or Python strings
(quotes, `repr`) are **not** B and C. The list is open and small; a pattern is added by editing
the file.

### Breakout

If, between the opening delimiter and the last closing one, another delimiter of the same kind
stands before the canary, and it is not masked, the foreign content has closed the server's
block: B and C go for that delivery and `broken_out` is noted. A masked delimiter (backslashes in
the fence, `&lt;/untrusted&gt;`) does not. The code fence keeps the note `breakout_unchecked`:
the rule does not check that the foreign content did not write it.

For a pair, if the first closer after the first opener begins before the canary, also one that
holds the canary in an attribute (`</untrusted q=<canary>>`), the delimiters are read in their
order. A closer behind the canary needs a block: one still open at the canary, or an
opener between the canary and it. A closer before an opener closes nothing the opener opened, and
an opener after a closer takes nothing from it. If a closer finds no block, it is left over:
`broken_out`. If they balance, the tool cannot tell a server's blocks from ones the foreign content
closed and opened anew: `ambiguous_blocks`.

A fence is a line the `code-fence` expression matches, read as in Markdown. A line ends at a line feed or at a bare carriage return, as in Markdown; the `begin-end` lines read the same. Backticks and
tildes are evaluated **each for itself**: a backtick fence does not close a tilde block and the
other way round.

The blocks are found once per string, in one pass over the fence lines in their order, as
Markdown reads them. With no block open, a line that can open one does (a backtick fence whose
line has another backtick after the run is inline code, `` ```x``` ``, and opens nothing). With
a block open, a line closes it only if it has the same character, is at least as long, and has
nothing but white space after it; every other line is content, and so are the info string
(`` ```<canary> ``) and a fence of the other character. A block without a closer at the end is no
block.

* **Inside:** a canary in a complete block (the line of the opener ends before it, the closer
  begins after it) has B and C. **Outside:** a canary in no block has no B and C.
* **Left over:** behind the canary stands a bare fence that is neither opener nor closer of a
  complete block, of a character whose first complete block ends before the canary, and at least
  as long as the shortest opener of a complete block of that character: any of them can be the
  block the foreign content closed. It may be still open at the end of the pass, or content of a block
  that is never closed or of a block of the other character: foreign content that opens a `~~~` or
  a `` ```` `` with an info string after the canary hides the server's closer that way, and it
  counts all the same. The foreign content closed the block and the server's closer stands after
  it: `broken_out`. So foreign content that closes the server's tilde block and opens a backtick
  block around the canary breaks out, although the backticks surround the canary. A shorter fence
  of the same character inside a complete block is that block's content and nothing else, and a
  fence with an info string left open after the canary, with no bare fence behind it, is no closer.
* **Balanced:** nothing is left over, and the first complete block of a character ends before the
  canary, and a closer of that character stands behind the canary: the canary is in a later block,
  in the info string of a later opener, or a complete block follows it.
  The tool cannot tell a server's blocks from ones the foreign content closed and opened anew:
  `ambiguous_blocks`.
* With `broken_out` or `ambiguous_blocks`, B and C go; with neither inside nor a note there is no
  match.

So a longer outer fence around a shorter one, a `~~~` inside a backtick fence, and a line
`` ```python `` inside do not break out; a bare fence of the same character, as long or longer,
does. An earlier tilde block that is closed before the canary, with no tilde fence after the
canary, does not take a backtick fence around the canary from it. A breakout by a fence takes B
and C of the whole delivery, also from a tag pair that is whole beside it.

## What the output shows

For each delivery: the canary's ID, the `seq` of the message, the JSON path in it, the
`occurrence` (the place of the canary in that message and path, from 1; the text line names it
only where there are several), A, B, C and D,
the marking, the IDs of the patterns to confirm, and the notes (`breakout_unchecked`,
`broken_out`, `ambiguous_blocks`, `possibly_forged`, `quoted`, `encoded`). `--json` states the
run first, then the sentence, as the text does. Then the canaries with no place (`not_delivered`) and the number of messages of
the server that were not read (`not_read`: a payload that is no JSON, or was cut off; a delivery
may sit in one). Every output says: *an observation, not a severity*.

**No value is ever shown**: not a canary's value, not the salt, not a word of an answer, also not
in `--json` and not in a refusal. A delivery points at the message and the path instead of
copying. A key stands in the path only if the MCP schema has it and it holds no canary value (a value
such as `description` or `Template` is `*` wherever it would stand as a key of the schema, and a value that reaches across keys, such as
`content[0].text`, makes the whole path `*`); any
other key, and everything
below `structuredContent`, `_meta` and the schemas, is `*`. A canary in a key is found, and its
path shows `*` for the key. An ID is never cut short (the bound of 400 characters is far above
the 64 an ID may have, in an engagement file and in a canaries file alike). A value that equals a
fixed word of the output or its own ID cannot be avoided and is for the examiner to choose. A value in a
canaries file that reads like a fixed word and an ID together (`delivered: a` for the ID `a`, in
the line `not delivered: a`) is the examiner's choice as well: the code does not check for it, the
value comes from the examiner, and with `--engagement` it does not occur.

## What the tool cannot do

* A canary the server **changed** (cut, encoded, case-folded, split) is not found. The search is
  for the exact string; `not_delivered` does not say the content was not delivered.
* The recording is masked and may be cut: a payload that is no JSON, or was cut off, is counted
  in `not_read` and not searched.
* Foreign content can write a marking itself. If a server that marks nothing delivers a file that
  begins with `Contents of …:` and has a fence around the canary, the tool cannot tell it from a
  server that writes those words: both are `partial` with `possibly_forged`. The same holds for a
  preamble in the neighbouring block: foreign content that the server spreads over several blocks
  can write it there. A server that names the source in text, in the same block or in the
  neighbouring one, is therefore never `delimited`; only a `uri` is. A person confirms it through
  `to_confirm`, and the tool does not carry that back into the marking.
* **Two blocks of the same delimiter in one string are ambiguous.** In
  `` ```\na\n```\nText\n```\n<canary>\n``` `` and in
  `<untrusted>a</untrusted> … <untrusted><canary></untrusted>` the tool cannot tell whether the
  foreign content closed the first block and opened a new one, or the server wrote two blocks. It
  notes `ambiguous_blocks`, takes B and C, and a person reads the answer. With a closer left
  over after the canary's block (`<untrusted>a</untrusted><untrusted><canary></untrusted></untrusted>`)
  the foreign content broke out: `broken_out`, for a pair as for the fence.
* A file with fences of its own, delivered in a resource block with a `uri`, is `partial`
  (`ambiguous_blocks`) if the canary stands in its second fence or between two of them. That is why
  the examiner lays the canary in a file without fences.
* `quoted` and `encoded` read exactly the cases above. A marking quoted or encoded in another way
  is read as text; a marking in a string the tool does not see as one may still give B and C.
* Only the place of the canary is checked. If the foreign content closes the block only after
  the canary, the tool does not see it.
* A source in a field of its own (`{"url": …, "text": …}`) is D, but not A, as long as no pattern
  matches its value. That is to be confirmed, not guessed.
* A pattern match says that wording is there, not that it marks the content. That is why each
  one is to be confirmed. The `commit-label` gives A and B only.
* Whether the model keeps the marking in mind is not looked at; nor is `openWorldHint`.
* The tool does not put a canary in the source itself (the person running the engagement does), and shows nothing of
  this in the report, the store or the web interface.
