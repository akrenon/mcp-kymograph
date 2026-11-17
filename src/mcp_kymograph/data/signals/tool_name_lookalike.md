# `tool_name_lookalike`

Kind: heuristic. Applied: only where a scenario statement asks for it.

## What the pattern is

Another tool in the same listing has a name written differently that reads the same once case,
invisible characters, compatibility forms such as full-width letters, every character that is
not a letter or digit, and the common Cyrillic and Greek lookalikes are set aside: `read_file`,
`readFile`, `Read-File`, and `re\u0430d_file` with a Cyrillic `a` (written here as `\u0430`) all
read as one name.

## Why a model may read it as instruction

A model picks a tool by its name and its description. Two names that read alike can lead it to
call one while relying on the description of the other, and a name spelled with a letter from
another script looks the same as the name written in Latin letters to a person reading the
listing.

## How it looks in honest content

An old and a new interface kept side by side (`get_user` and `getUser`), or names offered in two
spellings for compatibility (`list-items` and `list_items`).

## Example (invented)

Invented for this page; not taken from any server.

Before (one returns a profile, the other a session):

    get_user
    getUser

After:

    get_user_profile
    get_user_session

## What the tool does not know

Whether the names were meant to differ; which of them a model picks; lookalike letters other
than these, which are not compared; and whether the client that consumes
this listing reacts to it at all.
