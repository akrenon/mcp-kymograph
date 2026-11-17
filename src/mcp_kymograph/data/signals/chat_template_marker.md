# `chat_template_marker`

Kind: heuristic. Applied: by the built-in walk, on every surface it reads.

## What the pattern is

The text contains a token from a model's prompt format: `<|im_start|>`, `<|im_end|>`,
`<|im_sep|>`, `<|endoftext|>`, `<|start_header_id|>`, `<|end_header_id|>`, `<|eot_id|>`,
`<|system|>`, `<|user|>`, `<|assistant|>`, `[INST]`, `[/INST]`, `<<SYS>>` or `<</SYS>>`, in
any case. It is also reported when it only appears after decoding (entities, percent-encoding,
full-width letters, a base64 block).

Not read: `[INST]` or `[/INST]` that only decoding shows, inside an attribute (`title`, `alt`,
`aria-label`, `data-*`) of an HTML element of the fixed list the decoded copy removes (`a`,
`span`, `div`, `img`, `p` and others): the tag goes with its attributes. Nor, after decoding,
the six markers with an underscore (`im_start`, `im_end`, `im_sep`, `start_header_id`,
`end_header_id`, `eot_id`): the decoded copy drops `_` with the other inline markdown, so these
are found only as spelled.

## Why a model may read it as instruction

These tokens mark where one turn of a conversation ends and the next begins, and who speaks in
it, in the format some models were trained on. When a client places a tool's text into a prompt
without escaping such tokens, a token inside the text can look like the end of the tool's part
and the start of a turn by another speaker, and what follows may be weighed as that speaker's
words. Whether a token has that effect depends on the model's format and on the client.

## How it looks in honest content

A server whose subject is prompts or models writes these tokens because they are what it is
about: a prompt-library tool, a template renderer, a tokenizer utility, a description that
documents a model's format.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Wraps the text as <|im_start|>user ... <|im_end|> for the model.

After:

    Wraps the text in the chat format named in "template".

## What the tool does not know

Which prompt format the consuming model uses; whether the client escapes such tokens before a
model sees them; whether the token is documentation or meant to be read as a turn; and whether
the client that consumes this text reacts to it at all.
