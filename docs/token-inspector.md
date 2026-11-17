# Token inspector

`mcp_kymograph.token_inspector.inspect(token, pseudonymize)` reads a bearer token (the bare
value, without `Bearer `) and returns a `TokenView`: what of the token may enter a recording.
It is a pure function. Where the view is stored and where the pseudonymization salt comes from
are decided elsewhere; the pseudonymization is a function the caller passes in,
`(kind, value) -> pseudonym`.

## What is read

Kept as they are in the token (strings cut at 256 characters, lists at 64 entries; a cut adds
the warning `truncated`):

| Claim | Expected type |
|---|---|
| `aud` | string or list of strings |
| `scp` | string |
| `roles` | list of strings |
| `azp`, `appid` | string |
| `exp` | number (not bool) from 0 to 2^63 − 1, finite; output as int (floats are rounded down) |

A known claim of the wrong type is listed by name in `unexpected`; its value appears nowhere.
This includes an `exp` outside that range and any string with a lone surrogate (such as
`"\ud800"` in the JSON), also as a list entry; in every claim, readable or pseudonymized. Such a
string never reaches the pseudonymization function.

## What is pseudonymized

`tid` (`tenant`), `iss` (`issuer`), `oid` (`object`), `upn` (`email` if it has the shape of an
address, else `account`), `email` (`email`), `name` (`name`). The kinds are `PSEUDONYM_KINDS`.

An Entra issuer (`https://login.microsoftonline.com/<GUID>/v2.0` or
`https://sts.windows.net/<GUID>/`) keeps its URL; only the GUID is replaced, by the `tenant`
pseudonym of the lower-cased GUID. `tid` is lower-cased the same way when it is a GUID, so `iss`
and `tid` of one tenant give the same pseudonym.

## What never comes out

No byte of the token or its signature, nothing from the header, and no name or value of any
other claim (they are only counted, in `other_claims`). Values of pseudonymized claims appear
only as pseudonyms.

## Not readable

`readable=False` with one reason, never an exception:

- `too_long`: more than 16 KiB (UTF-8); the token is not looked at further.
- `not_jwt`: not three parts separated by dots, each made only of Base64url characters without
  padding (this includes a leading `Bearer `). The signature may be empty: an unsigned JWT
  (`alg: none`, form `<header>.<payload>.`) is valid under RFC 7519 and is read.
- `encrypted`: five parts (a JWE).
- `bad_encoding`: a header or payload that is not Base64url and UTF-8.
- `bad_json`: invalid JSON, including an empty header or payload, nesting too deep, `NaN` and
  `Infinity`, an integer of more than 20 digits and a float of more than 32 characters. The
  limits are checked by the inspector itself, before any conversion, and do not depend on
  Python's own digit limit.
- `not_object`: header or payload is JSON but not an object.

- `inspection_failed`: an unexpected exception, for example from the pseudonymization function.
  `inspect` catches `BaseException` at its boundary, so exceptions that do not derive from
  `Exception` (such as `GeneratorExit` or `asyncio.CancelledError`) end here too; nothing from
  the exception enters the result.
  The exceptions `KeyboardInterrupt`, `MemoryError` and `SystemExit` are the only ones passed
  on. Each leaves as a fresh instance of the built-in class, without arguments, raised
  `from None`: never a subclass, no cause, no context, and no code of the original exception is
  called. The class is chosen with `issubclass(type(exc), ...)`. A `SystemExit` keeps its code
  if it is an `int` (also a subclass of `int`, read as a plain `int`; `True` gives `1`);
  otherwise the code is `1`. The code is read in a guarded block: if reading it raises, the code
  is `1`.

Reading is linear in the length of the token.

## Microsoft Graph

The warning `aud_is_graph` is set when `aud` (or an entry of it) is Microsoft Graph: the app ID
`00000003-0000-0000-c000-000000000000` or one of the Graph URLs in `GRAPH_AUDIENCES` (national
clouds included), case-insensitive, with or without a trailing `/`.

## Authenticity

The signature is neither decoded nor verified, so the result says nothing about whether the
token is genuine. `TokenView.expired(now)` only compares `exp` with a timezone-aware `now`.

## In the recording

A run that uses a token (`drive` with an identity or `--token-env` / `--token-file`) passes it to
`inspect` before `run_started` is written. The pseudonymization function is
`Masker.personal_pseudonym`, which takes the kinds in `PSEUDONYM_KINDS` as well as its own and
lower-cases the value of an `email`; its salt is the personal salt of docs/engagements.md (the
engagement's under a file of version 2, otherwise the run's). `run_started.auth.token` is
`TokenView.to_json()` plus `expired`, `TokenView.expired(<start of the run>)`; the claim values
`aud`, `scp`, `roles`, `azp` and `appid` also pass the masker as text. `auth.token` is `null`
without a token. Tokens that a client sends through `kymograph run` are not read and stay
`***REDACTED***`. See docs/engagements.md, "What a run records of its token".
