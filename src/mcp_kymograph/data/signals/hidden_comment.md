# `hidden_comment`

Kind: heuristic. Applied: by the built-in walk, on tool metadata only.

## What the pattern is

The text contains a complete HTML comment, `<!--` … `-->`, with at least twelve and at most
4000 characters of content, or a line that starts with one of the two markdown comment idioms,
`[//]: ` or `[comment]: `. Both render to nothing in an HTML or markdown view.

## Why a model may read it as instruction

A rendered view of the text, in a user interface or on a documentation page, shows nothing
where the comment is; a model given the raw text reads the comment's content like any other
sentence. A person who reviews the description as rendered and the model that reads it are then
looking at different text, and only the model sees the part inside the comment.

## How it looks in honest content

Documentation generators and templates leave markers: `<!-- generated from tools.yaml -->`,
`<!-- BEGIN PARAMETERS -->`. Markdown sources keep notes for maintainers in `[//]: # (...)`
lines.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Creates a note. <!-- generated from notes.yaml, edit there -->

After:

    Creates a note.

## What the tool does not know

Whether the client renders the text or passes it on raw; whether the comment was written for the
people maintaining the text; and whether the client that consumes this text reacts to it at all.
