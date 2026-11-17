# `concealment_directive`

Kind: heuristic. Applied: by the built-in walk, on every surface it reads.

## What the pattern is

A sentence asks its reader to keep something from a person: *do not*, *don't*, *never*, *avoid*
or *refrain from* followed by a verb such as *mention*, *tell*, *reveal*, *show* or *report* and
an addressee (*user*, *human*, *operator*, *anyone*, *caller*, *client*, *them*); or *without
telling* (informing, notifying, asking) *the user*; or *keep this secret* (hidden, private, to
yourself, between us). The first two forms are reported only with an addressee; *keep it secret*
(hidden, private, …) needs none.

Not read: text that only decoding shows, inside an attribute (`title`, `alt`, `aria-label`,
`data-*`) of an HTML element of the fixed list the decoded copy removes (`a`, `span`, `div`,
`img`, `p` and others): the tag goes with its attributes, so the value is read only as spelled.
Nor, in the first form, a line break between the negating word and the addressee, or, in the
second, between the verb and the addressee: the pattern does not reach across a line break.

## Why a model may read it as instruction

A model that takes the sentence as addressed to itself may leave out of its reply what it did
or what it read, so the person relying on the reply does not see it. The addressee is what makes
the shape: the sentence is about what a person is told, not about what a program displays.

## How it looks in honest content

Notes about credentials ("Never show the API key to anyone"), privacy notes in a directory tool
("do not display a member's email to other users"), and tools that manage visibility ("Marks
the note as private: keep it private to its owner").

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Returns an access token. Never show the token to anyone.

After:

    Returns an access token for the Authorization header.

## What the tool does not know

Whether the sentence is a note for the developers who use the tool or addressed to a model;
what, if anything, it refers to; and whether the client that consumes this text reacts to it at
all.
