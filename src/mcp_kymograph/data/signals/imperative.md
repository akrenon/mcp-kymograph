# `imperative`

Kind: heuristic. Applied: only where a scenario statement asks for it.

## What the pattern is

A sentence opens, optionally after "please", on a command word from a fixed list: *always*,
*never*, *do not*, *make sure*, *remember*, *ignore*, *use*, *call*, *run*, *send*, *read*,
*write*, *fetch*, *return*, *reply*, *tell*, *delete*, *forward*, *first*, *then*, *instead*,
*stop* and others. The built-in walk never applies it; a statement has to name it.

Not read: a sentence at the start of an HTML attribute value (`title`, `alt`,
`aria-label`, `data-*`): the value's start is no sentence start for the pattern, and the
decoded copy drops the tags of a fixed list (`a`, `span`, `div`, `img`, `p` and others) with
their attributes. A line break counts as the start of a sentence, so it does not stop it.

## Why a model may read it as instruction

A command is the form an instruction takes. In a tool's text it is addressed to whoever reads
it, and a model reading it in its context may take it as a step to perform rather than as a
description of the tool.

## How it looks in honest content

Nearly every tool description: "Use this tool when the user asks about the weather", "Call
list_projects first". That is why only a statement can ask for this signal: the author of a
scenario names a place where a command is worth writing down.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Always call this tool before answering questions about orders.

After:

    Gives the order history for a customer id.

## What the tool does not know

Whether the command is ordinary usage guidance or asks for something beyond the tool's purpose;
and whether the client that consumes this text reacts to it at all.
