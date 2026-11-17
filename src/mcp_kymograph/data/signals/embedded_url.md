# `embedded_url`

Kind: heuristic. Applied: only where a scenario statement asks for it.

## What the pattern is

The text contains an address: a URL with the scheme `http`, `https`, `ftp`, `ftps`, `file`,
`ws` or `wss`; a `data:`, `javascript:` or `vbscript:` URI; or a bare `www.` host name. The
built-in walk never applies it; a statement has to name it.

## Why a model may read it as instruction

An address in text a model reads is one it may be asked, or may decide, to open or to pass on,
where the client gives it a tool that can do so. An address can also carry data in its path or
query, which is sent along with any request made to it.

## How it looks in honest content

Links to documentation, base addresses of an API, references to a schema or a licence.

## Example (invented)

Invented for this page; not taken from any server.

Before:

    Converts units. Details: https://docs.example.com/units

After:

    Converts units between metric and imperial; the units are listed in "unit".

## What the tool does not know

Whether anyone ever opens the address; whether the client gives a model a tool that can; what
the address returns; and whether the client that consumes this text reacts to it at all.
