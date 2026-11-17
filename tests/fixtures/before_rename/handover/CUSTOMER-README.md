# Evidence bundle

This directory is the evidence of one engagement, handed over by the operator who made it.
It holds what was recorded — the recordings of every run, the scenarios and the corpus
manifest the runs were made with, the engagement file the runs were checked against (without
contacts, references and the operator's redaction patterns), and the refusals the tool wrote
down — and `index.json`, which lists every file with its SHA-256, its size and what it is.

- Engagement (as declared): "acme-2026-11"
- Customer (as declared): "End Customer GmbH"
- Window from (UTC): "2026-11-16T00:00:00Z"
- Window until (UTC): "2026-11-19T00:00:00Z"
- Index digest (SHA-256 of index.json): "b2ad40f365ead1e8d1f98526ce945fbe54546d6455422e7f538fd7d2189e283a"
- Derived from the bundle with index digest: "0994dddb3d5a40092ffe443330b3bf4a0a5e55560be7a51f48d6e34537ce442f"
- Made (UTC): "2026-11-17T11:41:44.118130Z"
- Recordings: 1
- Recordings with egress not observed: 1
- Redaction rules applied for this handover: 0
- Values redacted for this handover: 0
- Report included: false

## Checking it

With mcp-polygraph installed, run:

    mcp-polygraph evidence verify DIR --index-digest b2ad40f365ead1e8d1f98526ce945fbe54546d6455422e7f538fd7d2189e283a

where DIR is this directory. It recomputes the digest of every file the index lists and says
of each whether it is intact, changed or missing, and names any file the index does not list.
The bundle is intact only when every file is. Compare the index digest above with the one the
operator gave you by another way: this page lies beside the index and is not covered by it, so
it cannot vouch for itself. The check needs nothing but this directory and the tool; it does
not need the operator's store.

## What was done to the recordings

Every recording was masked when it was written: what looked like a credential was replaced
before it reached the disk. For this handover the recordings were redacted once more, with the
number of rules named above, which the operator agreed with you; the rules themselves are not
named here, and `redactions.json` lists each place a value was blanked and which rule did it,
never the value. A redacted recording differs from the one first filed, so its entry in the
index names the digest of the original, and the operator's store is not included.

## What "egress not observed" means

A run is marked so when the server ran on the operator's machine without the sandbox that
records what it sends out, or ran elsewhere and was reached over the network. Whatever such a
server sent anywhere but back to the tool was not seen; the recording says nothing about it,
in either direction.

## What this is not

Nothing in this bundle is a verdict. A finding is a fact about what a server sent — which
signal, on which surface — not a judgement of the server; the judgement of each finding is a
person's, recorded apart with that person's name. A finding against a server someone else
runs (real-world) is a candidate for responsible disclosure, never a confirmed weakness.
