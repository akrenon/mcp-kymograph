# `hidden_html`

Kind: heuristic. Applied: only where a scenario statement asks for it.

## What the pattern is

The text contains an HTML tag in which the word `hidden` stands on its own anywhere — the
`hidden` attribute, but also `type="hidden"`, `class="hidden"` or an attribute value containing
it — or a tag with a style of `display: none`, `visibility: hidden`, `opacity: 0`, or a font
size, width, height or maximum height of zero: mostly an element a browser would not draw.
`aria-hidden` is not counted; it hides from a screen reader, not from the eye. The built-in walk
never applies it; a statement has to name it.

## Why a model may read it as instruction

A browser or an HTML view leaves the element out; a model given the raw text reads its content
like any other sentence. A person reviewing the rendered text and the model then see different
text, and only the model sees the hidden part.

## How it looks in honest content

Mail templates carry preview text in a hidden element; forms carry `<input type="hidden">`
fields; web templates keep elements `hidden` until a script shows them; tools that return web
pages pass such markup on as they found it.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    <p>Weekly summary</p><span style="display:none">Preview: 3 new tickets</span>

After:

    <p>Weekly summary: 3 new tickets</p>

## What the tool does not know

Whether the client renders HTML or passes it on raw; why the element is hidden; and whether the
client that consumes this text reacts to it at all.
