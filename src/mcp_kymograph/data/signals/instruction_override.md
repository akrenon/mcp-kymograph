# `instruction_override`

Kind: heuristic. Applied: by the built-in walk, on every surface it reads.

## What the pattern is

Within one sentence, one of the verbs *ignore*, *disregard*, *forget*, *override*, *bypass* or
*set aside* is followed closely by one of *the*, *all*, *any*, *your*, *these*, *those*,
*previous*, *prior*, *earlier*, *above* or *preceding*, and then by *instruction(s)*,
*prompt(s)*, *rule(s)*, *direction(s)*, *guideline(s)*, *system message* or *context*, each as
a whole word ("ignores" is not "ignore"). It is also reported when the
sentence only appears after decoding.

Not read: text that only decoding shows, inside an attribute (`title`, `alt`, `aria-label`,
`data-*`) of an HTML element of the fixed list the decoded copy removes (`a`, `span`, `div`,
`img`, `p` and others): the tag goes with its attributes, so the value is read only as spelled.
Nor a sentence broken by a line break between the verb and the last word: the pattern does
not reach across a line break.

## Why a model may read it as instruction

A model reads a tool's text in the same context as the instructions it was given. A sentence
telling its reader to set earlier instructions aside is phrased as a command to that reader, and
a model that follows instructions found in its context may give it weight over what came before
it.

## How it looks in honest content

Configuration and policy tools describe what they do with rules: "reset: ignore the previous
rules file and start from the defaults", "template: a template to override the default prompt".
Help text for a command-line option: "--force: bypass the rules file".

## Example (invented)

Invented for this page; not taken from any server.

Before:

    With "reset", ignore all earlier rules and apply only the new set.

After:

    With "reset", the stored rule set is replaced by the new one.

## What the tool does not know

Who the sentence is written for, a person reading documentation or a model; whether it
describes what the tool does or tells the reader what to do; and whether the client that
consumes this text reacts to it at all.
