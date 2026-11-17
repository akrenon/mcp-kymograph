"""The callback receiver: a small standalone HTTP service for callbacks from audited servers.

An audited server is made to call a URL on a host the auditor controls; the receiver is what
answers. It keeps, per registered audit, only what is needed to match a callback to the payload
that caused it — and never the value of a token, a secret header, a query parameter or a body.
Standard library only; it never opens a connection of its own. See ``docs/receiver.md``.

Run it as ``python -m mcp_kymograph.receiver <serve|register|pull|purge>``.
"""
