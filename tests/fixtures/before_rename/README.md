# Data from before the rename

This tool had another name until November 2026. The files here were written by it under that
name, at commit `ede3a20`, and are kept as they were written: nothing in this directory is
edited or made again. `tests/test_before_rename.py` reads them with the tool as it is now.

They are synthetic. The server was a fixture server of this repository, the engagement, its
customer and its salt are made up, and Docker was stood in by the test suite's stand-in.

| Path | What it is |
|---|---|
| `engagement/acme-2026-11.json` | an engagement file with two canaries; it names the salt's variable as `POLYGRAPH_SALT` |
| `runs/20261117T114140Z-80f72f28/` | a driven run under that engagement (recording schema 5); the server handed on the value of canary `page-1`, which begins with `polygraph-canary-` |
| `handover/` | a handover bundle of that run; its customer page is page version 1 |
| `bench/<run>/` | two HTTP runs of the benchmark runner against one server, made with one key: the companion and the recording of each |
| `expected/` | what the tool printed for this data at that commit |

The salt was `before-rename-fixture-salt-not-a-secret-0001`. The benchmark key is in the test
file. Both were made for these fixtures and are public: never use them for anything else.

## How it was made

From the root of the repository at that commit, with every path relative to it. `D` stands for
the directory the data was made in, and `mcp-polygraph` was the command then.

```sh
export POLYGRAPH_SALT=before-rename-fixture-salt-not-a-secret-0001
mcp-polygraph engagement canary D/engagement/acme-2026-11.json --json    # expected/canary.json
# D/laid.txt: three lines, the middle one the value of page-1
# D/script.yaml: initialize, tools/list, one call of read_file
mcp-polygraph drive -q --engagement D/engagement/acme-2026-11.json --script D/script.yaml \
  --out-dir D/runs -- python3 tests/fixtures/marking_server.py --file D/laid.txt --kind delimited
mcp-polygraph verdict D/runs/20261117T114140Z-80f72f28                   # expected/verdict.json
mcp-polygraph engagement marking D/runs/20261117T114140Z-80f72f28 \
  --engagement D/engagement/acme-2026-11.json                            # expected/marking.txt
mcp-polygraph engagement marking D/runs/20261117T114140Z-80f72f28 \
  --engagement D/engagement/acme-2026-11.json --json                     # expected/marking.json
mcp-polygraph evidence pack --engagement D/engagement/acme-2026-11.json \
  --store D/findings.sqlite --runs D/runs \
  --session D/runs/20261117T114140Z-80f72f28/events.jsonl --script D/script.yaml --out D/bundle
mcp-polygraph evidence redact D/bundle --engagement D/engagement/acme-2026-11.json \
  --store D/findings.sqlite --out D/handover
mcp-polygraph evidence verify D/handover \
  --index-digest b2ad40f365ead1e8d1f98526ce945fbe54546d6455422e7f538fd7d2189e283a
                                                                 # expected/verify-handover.json
python benchmarks/local-servers/runner/bench.py compare D/bench/http/runs/20261117T114150Z-c7e81a68 \
  D/bench/http/runs/20261117T114151Z-494a4c56 --key D/bench/key  # expected/compare-http.json
```

The two benchmark runs were made by the runner's own `run` command (`bench.main(["run", ...])`)
with `tests/fixtures/bench/fake_docker.py` as the docker CLI, the way the test suite makes them.

Three things differ from what an operator would do, so that no file holds an absolute path:

- The run was driven without a manifest and went into the bundle as a session (`--session`). A
  run driven through a manifest records the absolute path of its scenario.
- For the benchmark runs the runner's scenario path was set to the relative one, and the docker
  stand-in was given the scenario mount by its relative path.
- The bundle before the handover is not kept: only `handover/` is.
