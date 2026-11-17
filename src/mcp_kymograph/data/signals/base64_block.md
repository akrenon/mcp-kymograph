# `base64_block`

Kind: heuristic. Applied: only where a scenario statement asks for it.

## What the pattern is

The text contains a run of at least 24 base64 characters, in the standard alphabet or the one
for URLs (`-` and `_`), that decodes to readable text: valid UTF-8, printable characters and
line breaks only, at least one letter. The built-in walk never applies it; a statement has to
name it.

## Why a model may read it as instruction

A person scanning the text sees a string of letters and digits; a model may decode base64 it
meets and read the sentence inside. The content signals decode such blocks too, one level, and
match what they find; this signal says only that a readable block is there.

## How it looks in honest content

Encoded example payloads, the parts of a JSON Web Token (its header decodes to readable JSON),
examples of basic authentication, small data embedded in documentation.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Example payload: eyJ1bml0Ijoia20iLCJ2YWx1ZSI6MTJ9

After:

    Example payload: {"unit": "km", "value": 12}

## What the tool does not know

What the block means to the people who wrote it; whether a given model decodes it; and whether
the client that consumes this text reacts to it at all.
