# Finding classes

A finding class groups the signals and rules that look for the same kind of thing. It gives a
finding a stable name to talk about, in the report and in the web interface, and a place to hang
references to outside frameworks.

## What a class is

* An ID `AKR-NN` (two digits). IDs are stable and never reused: a class that is dropped leaves its
  number unused.
* An English title and one sentence of description.
* Every signal ID and every rule ID belongs to exactly one class. The table lives in
  `src/mcp_kymograph/finding_classes.py`; `class_of(kind, ident)` answers for `"signal"` or
  `"rule"`. A test fails when a signal or rule has no class.

A class is not a severity and has no rank. It says what kind of thing was seen, nothing about how
much it matters.

## Derived, never stored

The class is worked out from the signal or rule ID when a finding is rendered. The store has no
field for it and the finding key is unchanged, so changing the table never changes what a finding
is filed under. A finding whose signal this version does not know is shown without a class and
says so.

The tool's report names the class (ID and title) in the sentence after each finding's signal. The
web interface shows it as text: in review mode beside the signal, and in the run view and the
message view beside each finding (ID and title as text, in the chips and in the tables). The triage history
and the triage tables do not show it.

## The mapping file

`src/mcp_kymograph/data/finding-classes-mapping.yaml` is open data shipped in the wheel. It lists
the frameworks and, for every class, a list of entries `{framework, ref, confirmed}`.

* A framework has `id`, `name`, `version`, `retrieved`, `date` and `note`. `version` is a required
  string. `retrieved` is required and is the day (`YYYY-MM-DD`) the IDs were read from the
  source. `date` is the date of the edition (`YYYY-MM-DD`) or `null`; when it is not the
  publication date, the `note` says which date it is.
* `ref` holds only a number or an ID, such as `MCP-T3` or `A.8.29`. It never holds a title or text
  from the source. The spelling is checked per framework (for example `MCP03:2025` for the OWASP
  MCP Top 10 and `MCP-T3` for CoSAI).
* An entry with `confirmed: false` is a draft. Every entry in the shipped file is a draft until a
  maintainer has checked it against the source; only then is `confirmed` set to `true`.
* Every class has at least one entry in the shipped file. The checker still allows an empty list:
  a class with no entry claims no match.
* The OWASP MCP Top 10 is a beta; its note says so and its references may change.
* The frameworks that concern an audit as a whole (ISO/IEC 27001, BSIG, DORA, the EU AI Act) are
  listed with their version and date and have no class entries.

`load_mapping()` reads and checks the file (reading YAML needs the optional `yaml` extra, as for
scenarios). It refuses, naming the file and the place in it: an unknown framework, a class listed
twice or missing, an unknown key, a missing `retrieved`, a `version` that is not a string, a `ref`
that is prose, a value of the wrong type (such as a list where an ID belongs), and a `confirmed`
that is not a boolean.
