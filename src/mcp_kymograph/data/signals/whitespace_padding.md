# `whitespace_padding`

Kind: heuristic. Applied: by the built-in walk, on tool metadata only.

## What the pattern is

The text contains two blank lines in a row, or a run of thirty or more spaces or tabs. Either
can move what follows out of sight in a view that shows only the first lines or the first part
of a line.

## Why a model may read it as instruction

A person reading a description in a narrow or truncated view may stop at the empty space and
never see the rest; a model is given the whole text. What follows the padding can then be read
by the model and not by the person who looked at the description.

## How it looks in honest content

Formatting: paragraphs separated generously, tables aligned with spaces, text assembled from
templates that leave empty lines behind.

## Example (invented)

Invented for this page; not taken from any server.

Before (two blank lines between the sentences):

    Lists files.


    Paths are relative to the workspace root.

After:

    Lists files. Paths are relative to the workspace root.

## What the tool does not know

What the client's view shows of the text and where it cuts it; whether the empty space is
formatting; and whether the client that consumes this text reacts to it at all.
