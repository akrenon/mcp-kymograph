# Signal reference

One page per signal of `mcp_kymograph.signals.Signal`, kept as package data in
[`src/mcp_kymograph/data/signals/`](../../src/mcp_kymograph/data/signals/), so that an installed
tool can read them (`signals.reference(signal)`, `signals.reference_pages()`) and a bundle can
carry them: `evidence pack` copies the pages of the signals its store's findings name to
`reference/<id>.md`, index role `reference`, and `evidence redact` carries them into the handover
bundle.

Each page describes a pattern, never a server. Its headings, in this order:

1. What the pattern is
2. Why a model may read it as instruction
3. How it looks in honest content
4. Example (invented)
5. What the tool does not know

The line under the title gives the signal's kind (`signals.KINDS`: evidence or heuristic; no
severity) and where it is applied (the built-in walk, a scenario statement, or the inspector).

| Page | Kind |
|---|---|
| [`invisible_characters`](../../src/mcp_kymograph/data/signals/invisible_characters.md) | heuristic |
| [`chat_template_marker`](../../src/mcp_kymograph/data/signals/chat_template_marker.md) | heuristic |
| [`instruction_override`](../../src/mcp_kymograph/data/signals/instruction_override.md) | heuristic |
| [`concealment_directive`](../../src/mcp_kymograph/data/signals/concealment_directive.md) | heuristic |
| [`output_directive`](../../src/mcp_kymograph/data/signals/output_directive.md) | heuristic |
| [`model_addressed`](../../src/mcp_kymograph/data/signals/model_addressed.md) | heuristic |
| [`hidden_comment`](../../src/mcp_kymograph/data/signals/hidden_comment.md) | heuristic |
| [`role_line`](../../src/mcp_kymograph/data/signals/role_line.md) | heuristic |
| [`whitespace_padding`](../../src/mcp_kymograph/data/signals/whitespace_padding.md) | heuristic |
| [`imperative`](../../src/mcp_kymograph/data/signals/imperative.md) | heuristic |
| [`second_person`](../../src/mcp_kymograph/data/signals/second_person.md) | heuristic |
| [`embedded_url`](../../src/mcp_kymograph/data/signals/embedded_url.md) | heuristic |
| [`base64_block`](../../src/mcp_kymograph/data/signals/base64_block.md) | heuristic |
| [`hidden_html`](../../src/mcp_kymograph/data/signals/hidden_html.md) | heuristic |
| [`tool_name_duplicate`](../../src/mcp_kymograph/data/signals/tool_name_duplicate.md) | evidence |
| [`tool_name_lookalike`](../../src/mcp_kymograph/data/signals/tool_name_lookalike.md) | heuristic |
| [`lone_surrogate`](../../src/mcp_kymograph/data/signals/lone_surrogate.md) | evidence |

The pages are reviewed like code: every sentence against three rules — a page adds no
judgement (it describes a pattern, never a server), adds no measurement, and says nothing the
operator does not see too — and against the words the report does not use
(`report.BANNED_WORDS`). A test holds that there is a page for every signal and for no other id, that the
headings stand in this order, that the example is marked invented, that a page whose
pattern reads instruction text says what it does not read in an HTML attribute value and across a
line break, and that the pages are in the installed package.
