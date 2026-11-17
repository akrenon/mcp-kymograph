# `invisible_characters`

Kind: heuristic. Applied: by the built-in walk, on every surface it reads.

## What the pattern is

The text carries a character that has no visible mark: a zero-width space, a word joiner, a
soft hyphen, the Mongolian vowel separator (U+180E), a byte-order mark anywhere but at the
start, a bidirectional embedding, override or isolate (U+202A to U+202E, U+2066 to U+2069), a
character from the Unicode tag block, or a zero-width joiner or non-joiner between two ASCII
characters. What a person sees on screen and what a program receives are then not the same text.

## Why a model may read it as instruction

A model is given the characters, not their rendering. Tag-block characters can spell letters
that no display draws, and bidirectional controls change the order a person sees while the order
in the text stays as sent. A person reviewing the rendered text and a model reading the
characters can therefore be reading two different things, and only the model reads all of it.

## How it looks in honest content

Soft hyphens in text copied from a word processor or a hyphenated document; bidirectional
isolates that internationalisation libraries put around placeholders in right-to-left
languages; a word joiner in a typeset name. The check already leaves out a byte-order mark at the
very start and joiners next to non-ASCII characters, where emoji sequences and several scripts
need them.

## Example (invented)

Invented for this page; not taken from any server.

Before (written here as `\u00ad`; in the field it is one invisible character):

    Returns the in\u00advoice total.

After:

    Returns the invoice total.

## What the tool does not know

Whether the character was placed on purpose or arrived through a copy, a library or an editor;
what a run of hidden characters spells to a given model; whether the client removes such
characters before a model sees the text; and whether the client that consumes this text reacts
to it at all.
