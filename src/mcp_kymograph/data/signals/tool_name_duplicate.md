# `tool_name_duplicate`

Kind: evidence. Applied: only where a scenario statement asks for it.

## What the pattern is

Two or more tools in the same listing carry the same name, compared character for character as
they were sent. The hit is that fact itself, read from the listing as recorded.

## Why a model may read it as instruction

A client that keeps tools by name has to pick one of the two, merge them, or show both. Which
description a model then reads under that name, and which tool a call by that name reaches,
depends on that choice; a model can rely on one tool's description and have its call reach the
other.

## How it looks in honest content

As evidence, the hit does not come from a shape that ordinary text also has: the name did stand
twice in one listing. Ordinary causes of that fact exist, such as two modules that each register
a tool of the same name, or one tool registered twice at start-up.

## Example (invented)

Invented for this page; not taken from any server.

Before (two tools in one listing, one searching files and one searching tickets):

    search
    search

After:

    search_files
    search_tickets

## What the tool does not know

Whether the two entries are one tool registered twice or two different tools; which of them a
client keeps; and whether the client that consumes this listing reacts to it at all.
