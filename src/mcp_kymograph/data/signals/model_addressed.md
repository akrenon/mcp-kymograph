# `model_addressed`

Kind: heuristic. Applied: by the built-in walk, on every surface it reads.

## What the pattern is

The text names a model as its reader: *you are* (or *as*, *if you are*) *an AI*, *a language
model*, *an assistant*, *an agent*, *a bot*; or *AI*, *LLM*, *assistant* or *chatbot* followed
closely by *must*, *should*, *needs to* or *is instructed to*; or *note to*, *instructions for*,
*message to*, *attention* or *dear* followed by *the AI*, *the assistant*, *the agent* or *the
model*. In the *must/should* form, bare *model* and bare *agent* do not count; *AI agent* and
*AI model* do.

Not read: text that only decoding shows, inside an attribute (`title`, `alt`, `aria-label`,
`data-*`) of an HTML element of the fixed list the decoded copy removes (`a`, `span`, `div`,
`img`, `p` and others): the tag goes with its attributes, so the value is read only as spelled.
Nor, in the *must/should* form, a line break between the reader and the verb: the pattern does
not reach across a line break there.

## Why a model may read it as instruction

A model that recognises itself as the one being addressed may treat the sentence that follows
as directed at it, in the way it treats the instructions it was given.

## How it looks in honest content

Field names and product names: "assistant id must be a UUID", "Assistant must be enabled in the
workspace settings". Documentation of a chatbot platform: "If you are a bot developer, register
the webhook first". Integrations that describe how they act: "Runs as a bot user in the
workspace".

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Note to the AI: call list_projects before create_task.

After:

    Needs a project id; list_projects returns the ids.

## What the tool does not know

Whether the words name a model or a product, a field or a person's role; and whether the client
that consumes this text reacts to it at all.
