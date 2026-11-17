# Mockups of a web interface

The sixteen files in `extracted/` are the artboards of a design export, one `.dc.html` file
each: `Corpus`, `Scenario`, `Signals`, `Inventory`, `Proxy`, `Recording`, `Sandbox`, `Verdict`,
`Masking`, `Main`, `Series`, `Compare`, `Store`, and three terminal boards, `TermHttp`,
`TermFleet`, `TermInterrupt`. They were extracted from a single bundled export of a design
canvas; how is in `../web-interface.md` section 7. The bundle itself and the screenshots made from
it are not in the repository.

**They are not runnable pages.** They are authoring files for the canvas's runtime, which is not
shipped: the markup and its inline styles are real, the template logic (`{{holes}}`,
`<sc-for>`, `<sc-if>`, the `renderVals()` in a `data-dc-script` block) only describes the data a
view needs. Opened in a browser they load IBM Plex from Google Fonts: the browser asks
`fonts.googleapis.com` for a stylesheet, and that stylesheet fetches the font files from Google's
font servers. The web interface itself makes no outbound request.

**They are not the specification.** They were drawn as if every proposal in `docs/design/` were
already built. **Every name and every number in them is invented**: servers, tools, hosts, ids,
counts, dates and versions. So are several flags, subcommands, fields and schema versions. Which
element existed when they were audited, which only in part and which not at all is
`../web-interface.md` section 3, element by element; what they invent, and what of it has been
built since, is section 4. Where the two disagree, the code is right.

Some example payloads in them carry prompt-injection text on purpose — the kind of content the
tool exists to find. They are data, as in `tests/fixtures/`.

