# `second_person`

Kind: heuristic. Applied: only where a scenario statement asks for it.

## What the pattern is

The text tells "you" what to do or what its task is: *you must* (should, shall, need to, have
to, will now, may not, cannot, always, never), *you are required* (instructed, expected, not
allowed, now), or *your task* (job, instructions, goal, role, purpose, objective, mission). The
built-in walk never applies it; a statement has to name it.

Not read: text that only decoding shows, inside an attribute (`title`, `alt`, `aria-label`,
`data-*`) of an HTML element of the fixed list the decoded copy removes (`a`, `span`, `div`,
`img`, `p` and others): the tag goes with its attributes, so the value is read only as spelled.
A line break between the words does not stop it.

## Why a model may read it as instruction

To a model reading the text, the "you" can read as itself. A sentence that gives that reader a duty
or a task has the shape of the instructions the model was given, and may be weighed as one of
them.

## How it looks in honest content

Field descriptions and error messages written for the developer who calls the tool: "You must
provide a valid project id", "You cannot delete a project that has open tasks".

## Example (invented)

Invented for this page; not taken from any server.

Before:

    You must provide a valid project id.

After:

    project_id: a valid project id (required).

## What the tool does not know

Whether "you" is the developer who calls the tool or the model that reads it; and whether the
client that consumes this text reacts to it at all.
