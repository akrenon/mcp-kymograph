# `role_line`

Kind: heuristic. Applied: by the built-in walk, on tool metadata only.

## What the pattern is

A line of the text starts, after at most a little indentation, with *assistant*, *system*,
*user* or *human* followed by a colon. It is the way a turn of a conversation is labelled in a
transcript.

Not read: a label at the start of an HTML attribute value (`title`, `alt`,
`aria-label`, `data-*`): the value's start is no line start, and the decoded copy drops the
tags of a fixed list (`a`, `span`, `div`, `img`, `p` and others) with their attributes.

## Why a model may read it as instruction

Transcripts mark who speaks this way, and some prompt formats mark turns the same way. A line
such as "System: …" inside a tool's text can look to a model like a turn by another speaker,
the system or the user, rather than a part of the tool's description, and its content may be
weighed as that speaker's words.

## How it looks in honest content

Parameter lists written one per line ("user: the account to query"), log formats, and tools
that export or display chat transcripts and show one as an example.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Looks up an account.
    user: the account name
    system: the directory to search

After:

    Looks up an account. Parameters: "user", the account name; "system", the directory to search.

## What the tool does not know

Whether the label is a parameter name, a transcript or meant to be read as a turn; whether the
client's prompt format uses such labels; and whether the client that consumes this text reacts
to it at all.
