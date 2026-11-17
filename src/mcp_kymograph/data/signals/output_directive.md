# `output_directive`

Kind: heuristic. Applied: by the built-in walk, on every surface it reads.

## What the pattern is

The text tells its reader what to put into *their own* reply: a verb such as *append*,
*include*, *insert*, *print*, *repeat* or *start* followed within a sentence by *your reply*
(response, answer, output, message); or *your reply must* (should, has to, needs to) *contain*,
*include*, *append*, *start with*, *begin with* or *end with*. The possessive *your* is the
tell.

Not read: text that only decoding shows, inside an attribute (`title`, `alt`, `aria-label`,
`data-*`) of an HTML element of the fixed list the decoded copy removes (`a`, `span`, `div`,
`img`, `p` and others): the tag goes with its attributes, so the value is read only as spelled.
Nor a line break between the verb and *your reply* (or, in the second form, after it): the
pattern does not reach across a line break.

## Why a model may read it as instruction

Text from a tool that speaks of "your reply" addresses whoever writes the reply; where a model
writes the reply, it can read the text as addressed to itself. A model that follows it may add,
change or repeat content in what it says to the person, content that came from the tool rather
than from the person's request.

## How it looks in honest content

Mail and chat tools describing their own fields: "signature: text to append to your reply".
Helpdesk tools whose user is a person answering tickets: "Include the ticket number in your reply
to the customer".

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Sends the draft. Append the account signature to your reply.

After:

    Sends the draft with the account signature appended.

## What the tool does not know

Whether "your" means a person using the tool or the model; whether the text describes the
tool's own behaviour or asks the reader to act; and whether the client that consumes this text
reacts to it at all.
