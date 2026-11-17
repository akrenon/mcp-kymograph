# `lone_surrogate`

Kind: evidence. Applied: by the inspector alone, on the server name announced in answer to
`initialize`; no statement can name it.

## What the pattern is

The announced name (`result.serverInfo.name`) held a lone surrogate: half of a UTF-16 pair, a
code point from U+D800 to U+DFFF standing on its own, which is not a character of valid UTF-8
text. The inspector replaces it with U+FFFD before the name is kept, and records that it did.

## Why a model may read it as instruction

A lone surrogate is not an instruction in itself. What it changes is how the name is read:
parsers, logs and clients handle it differently, replacing it, dropping it or refusing the whole
message, so the name a person sees, the name a log keeps and the name a model is given need not
be the same string.

## How it looks in honest content

A server written in a language whose strings are UTF-16 cuts a name in the middle of a pair,
for instance when it shortens a name that ends in an emoji.

## Example (invented)

Invented for this page; not taken from any server.

Before (as JSON escapes; the second half of the pair is missing):

    "name": "notes-\ud83d"

After:

    "name": "notes-\ud83d\udcdd"

## What the tool does not know

Whether the half pair was cut by accident; what each component between the server and a model
makes of it; and whether the client that consumes this name reacts to it at all.
