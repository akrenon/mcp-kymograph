"""``engagement compare``: the answers of two identities side by side (docs/engagements.md).

Two identities of one engagement drive the same script against ``role_server``, whose tool set
and answers depend on the role. The command reads the two recordings and nothing else.
"""

from __future__ import annotations

import json
import secrets
import sys
import types
from pathlib import Path

import pytest

from mcp_kymograph import cli, events, identity_compare, verdict
from test_cli_engagement import run_directories
from test_personal_data import SALT_ENV, second_file

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402
import role_server  # noqa: E402

LISTS = """\
  - initialize
  - list: tools/list
  - list: prompts/list
  - list: resources/list
"""
CLEAN = (
    "version: 1\nname: clean\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: whoami, arguments: {text: "one"}}
"""
)
#: The same call twice, so that a step lost from the recording would still leave a likeness.
TWICE = (
    "version: 1\nname: twice\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: probe, arguments: {text: "one"}}
"""
)
#: Calls that go wrong for one role: a JSON-RPC error, then a 403, which ends the script.
FAILS = (
    "version: 1\nname: fails\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: whoami, arguments: {text: "one"}}
  - call: {tool: broken, arguments: {text: "one"}}
  - call: {tool: restricted, arguments: {text: "one"}}
"""
)
#: A 403 in the second of three steps ends the script for the role that gets it.
ENDS = (
    "version: 1\nname: ends\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: restricted, arguments: {text: "one"}}
  - call: {tool: whoami, arguments: {text: "one"}}
"""
)
#: Three calls, for a failure of the driver after the first.
THREE = (
    "version: 1\nname: three\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: whoami, arguments: {text: "one"}}
  - call: {tool: probe, arguments: {text: "one"}}
"""
)
#: The second of three calls is a tool only the administrator is listed.
SKIPS = (
    "version: 1\nname: skips\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: admin_only, arguments: {text: "one"}}
  - call: {tool: whoami, arguments: {text: "one"}}
"""
)
#: Answers that carry a mark in a key and in the uri of an array's item.
SHAPES = (
    "version: 1\nname: shapes\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: keyed, arguments: {text: "one"}}
  - call: {tool: shaped, arguments: {text: "one"}}
"""
)
#: A call that is answered with a JSON-RPC error to the reader and is fine for the administrator.
BROKEN = (
    "version: 1\nname: broken\nsteps:\n"
    + LISTS
    + """\
  - call: {tool: probe, arguments: {text: "one"}}
  - call: {tool: broken, arguments: {text: "one"}}
"""
)
OTHER = (
    "version: 1\nname: other\nsteps:\n"
    + LISTS
    + '  - call: {tool: probe, arguments: {text: "two"}}\n'
)

IDENTITIES = [
    {"name": "reader", "role": "read-only user", "token_env": "TEST_TOKEN_READER"},
    {"name": "admin", "role": "administrator", "token_env": "TEST_TOKEN_ADMIN"},
]
#: Steps are those of the script: the probe is the first, whatever the handshake and the listings
#: before it sent.
PROBE_STEP = 1
PAGE_SIZE = 4
#: More tools than the driver follows pages at one to a page (driver.MAX_PAGES is 20).
EXTRA_TOOLS = 24
MANY_TOOLS = 120


class World:
    """A running role server, two tokens in the environment, and the runs driven against it."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.tokens = {
            "reader": "rd" + secrets.token_hex(12),
            "admin": "ad" + secrets.token_hex(12),
        }
        self.salt = "salt" + secrets.token_hex(20)
        self.server = role_server.serve(
            {self.tokens["reader"]: "reader", self.tokens["admin"]: "admin"}
        )
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}{http_server.PATH}"
        self.engagements = {
            name: second_file(
                base / f"engagement-{name}",
                name=name,
                identities=IDENTITIES,
                actions={"list": True, "call": True},
            )
            for name in ("acme-2026-10", "other-2026-10")
        }
        self.scripts = {}
        for name, text in (
            ("clean", CLEAN),
            ("fails", FAILS),
            ("ends", ENDS),
            ("other", OTHER),
            ("three", THREE),
            ("skips", SKIPS),
            ("shapes", SHAPES),
            ("broken", BROKEN),
            ("twice", TWICE),
        ):
            self.scripts[name] = base / f"{name}.yaml"
            self.scripts[name].write_text(text)
        self.count = 0

    @property
    def marks(self) -> list[str]:
        return self.server.behaviour.marks

    def drive(self, who: str | None, script: str, engagement: str = "acme-2026-10") -> Path:
        """One run as ``who`` (None: no identity) of ``script``; its run directory."""
        self.count += 1
        out_dir = self.base / f"runs-{self.count}"
        argv = ["drive", "-q", "--engagement", str(self.engagements[engagement])]
        argv += ["--http", self.url, "--script", str(self.scripts[script])]
        argv += ["--out-dir", str(out_dir)]
        if who is not None:
            argv += ["--identity", who]
        cli.main(argv)
        (run,) = run_directories(out_dir)
        return run

    def everything_secret(self) -> list[str]:
        return [*self.tokens.values(), self.salt, *self.marks]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    base = tmp_path_factory.mktemp("compare")
    made = {}
    patch = pytest.MonkeyPatch()
    this = World(base)
    patch.setenv("TEST_TOKEN_READER", this.tokens["reader"])
    patch.setenv("TEST_TOKEN_ADMIN", this.tokens["admin"])
    patch.setenv(SALT_ENV, this.salt)
    made["clean"] = (this.drive("reader", "clean"), this.drive("admin", "clean"))
    made["fails"] = (this.drive("reader", "fails"), this.drive("admin", "fails"))
    made["ends"] = (this.drive("admin", "ends"), this.drive("reader", "ends"))
    made["three"] = (this.drive("reader", "three"), this.drive("admin", "three"))
    made["skips"] = (this.drive("reader", "skips"), this.drive("admin", "skips"))
    made["shapes"] = (this.drive("reader", "shapes"), this.drive("admin", "shapes"))
    made["broken"] = (this.drive("reader", "broken"), this.drive("admin", "broken"))
    made["twice"] = (this.drive("reader", "twice"), this.drive("admin", "twice"))
    # The tool list in pages: four tools to a page, so the administrator's tool is on the second.
    behaviour = this.server.behaviour
    behaviour.page_size = PAGE_SIZE
    made["paged"] = (this.drive("reader", "clean"), this.drive("admin", "clean"))
    # One tool to a page and more tools than the driver follows pages: the reader stops at the
    # limit, the administrator (four to a page) reads to the end.
    behaviour.extra_tools = EXTRA_TOOLS
    behaviour.page_size = 1
    limited = this.drive("reader", "clean")
    behaviour.page_size = PAGE_SIZE
    made["limited"] = (limited, this.drive("admin", "clean"))
    # More names than are shown, in one page.
    behaviour.page_size, behaviour.extra_tools = None, MANY_TOOLS
    made["many"] = (this.drive("reader", "clean"), this.drive("admin", "clean"))
    behaviour.page_size, behaviour.extra_tools = None, 0
    # Legacy over HTTP, the answer only after the stream was resumed with GET and Last-Event-ID:
    # to every tool call, to the tool list, and to a tool call after two streams that end first.
    behaviour.close_early, behaviour.respond = "once", "stream"
    behaviour.failure_method = "tools/call"
    made["resumed_call"] = (this.drive("reader", "clean"),)
    behaviour.resumptions = 2
    made["resumed_chain"] = (this.drive("reader", "clean"),)
    behaviour.resumptions = 0
    behaviour.failure_method = "tools/list"
    made["resumed_list"] = (this.drive("reader", "clean"),)
    # The same with the base server's priming event, an id and no data: the recording holds no
    # message with that id, so the GET that names it continues nothing the recording shows.
    behaviour.priming = True
    behaviour.failure_method = "tools/call"
    made["primed_call"] = (this.drive("reader", "clean"), this.drive("admin", "clean"))
    # The same with streams that end after a notification with an id between the priming event
    # and the answer: one, and two. Each GET continues the one before.
    behaviour.resumptions = 1
    made["primed_chain"] = (this.drive("reader", "clean"),)
    behaviour.resumptions = 2
    made["primed_chain_3"] = (this.drive("reader", "clean"),)
    behaviour.resumptions = 0
    behaviour.failure_method = "tools/list"
    made["primed_list"] = (this.drive("reader", "clean"),)
    behaviour.priming = False
    behaviour.close_early, behaviour.respond = None, "json"
    behaviour.failure_method = "tools/list"
    this.runs = made
    this.other_script = this.drive("admin", "other")
    this.other_engagement = this.drive("admin", "clean", "other-2026-10")
    this.nobody = this.drive(None, "clean")
    yield this
    patch.undo()
    this.server.shutdown()
    this.server.server_close()


def compare(capsys, world, one, other, *extra):
    """The command's exit status, stdout and stderr; no mark and no token may be in the words."""
    capsys.readouterr()
    code = cli.main(["engagement", "compare", str(one), str(other), *extra])
    said = capsys.readouterr()
    for secret in world.everything_secret():
        assert secret not in said.out and secret not in said.err
    return code, said.out, said.err


def rows(table: str) -> dict[str, list[str]]:
    """The table's rows by step number: the words of each."""
    found = {}
    for line in table.splitlines():
        words = line.split()
        if words and words[0].isdigit():
            found[words[0]] = words
    return found


def edited(source: Path, tmp_path: Path, name: str, change) -> Path:
    """A copy of a run's recording with ``change`` applied to each event (it edits in place)."""
    events = [json.loads(line) for line in (source / "events.jsonl").read_text().splitlines()]
    for event in events:
        change(event)
    target = tmp_path / name
    target.mkdir()
    (target / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return target


def rewritten(source: Path, tmp_path: Path, name: str, build) -> Path:
    """A copy of a run's recording whose events are what ``build`` makes of the list."""
    held = [json.loads(line) for line in (source / "events.jsonl").read_text().splitlines()]
    made = build(held)
    for seq, event in enumerate(made, 1):
        event["seq"] = seq
    target = tmp_path / name
    target.mkdir()
    (target / "events.jsonl").write_text("\n".join(json.dumps(e) for e in made) + "\n")
    return target


def driver_failed(source: Path, tmp_path: Path, name: str, after: int) -> Path:
    """The recording of a run whose driver failed after ``after`` tool calls: the driver then
    records a ``step_skipped`` for every step of the script (driver.py, ``Driver.run``:
    ``_skip_remaining(self._script.steps, DRIVER_ERROR)``), those it had sent included, and,
    after the ``except`` branch, the ``script_finished`` it writes on every path that is not a
    cancellation: what it sent, all the steps as skipped, the inventory ``partial``."""

    def build(held):
        calls = [i for i, e in enumerate(held) if e["type"] == "step_called"]
        (finished,) = [e for e in held if e["type"] == "script_finished"]
        script = ["initialize", "tools/list", "prompts/list", "resources/list"]
        script += ["tools/call"] * len(calls)
        skipped = [
            {
                "v": held[0]["v"],
                "type": "step_skipped",
                "step": step,
                "reason": events.DRIVER_ERROR,
                "detail": "",
            }
            for step in script
        ]
        # The calls sent are the first ``after`` of the ``tools/call`` in ``sent``.
        sent, seen = [], 0
        for method in finished["sent"]:
            if method == "tools/call":
                seen += 1
                if seen > after:
                    continue
            sent.append(method)
        closing = {
            **finished,
            "inventory": events.INVENTORY_PARTIAL,
            "sent": sent,
            "skipped": [[step, events.DRIVER_ERROR] for step in script],
            "unanswered": [],
            "called": finished["called"][:after],
            "failed": [tool for tool in finished["failed"] if tool in finished["called"][:after]],
        }
        return [*held[: calls[after]], *skipped, closing, held[-1]]

    return rewritten(source, tmp_path, name, build)


# -- what is shown ------------------------------------------------------------------------------


def test_the_same_answer_is_the_same_and_the_other_is_located(world, capsys):
    reader, admin = world.runs["clean"]

    code, out, err = compare(capsys, world, reader, admin)

    assert code == 0, err
    steps = rows(out)
    assert steps[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
    # whoami answers each role in its own words; the first place that differs is a locator.
    assert steps[str(PROBE_STEP + 1)][1:] == [
        "whoami", "ok", "ok", "different", "result.content[0].text",
    ]  # fmt: skip


def waited_before_first_call(source: Path, tmp_path: Path, name: str, after) -> Path:
    """A copy of a run in which the first ``tools/call`` drew a 429 with a ``Retry-After``, as the
    driver records it: the attempt in an exchange of its own, then ``paced``. ``after(attempt,
    rest)`` says what stands behind them, ``rest`` being the events from the call on."""

    def build(events):
        at = next(
            i
            for i, event in enumerate(events)
            if event["type"] == "message"
            and event["direction"] == "client_to_server"
            and (event["payload"].get("data") or {}).get("method") == "tools/call"
        )
        request, message = events[at - 1 : at + 1]
        exchange = message["exchange"]
        response = next(
            e for e in events if e["type"] == "http_response" and e["exchange"] == exchange
        )
        end = next(e for e in events if e["type"] == "http_end" and e["exchange"] == exchange)
        attempt = [
            {**json.loads(json.dumps(event)), "exchange": 9000}
            for event in (request, message, {**response, "status": 429}, end)
        ]
        attempt.append(
            {
                "v": events[0]["v"],
                "type": "paced",
                "seconds": 1.0,
                "why": "retry_after",
                "status": 429,
            }
        )
        return events[: at - 1] + after(attempt, events[at - 1 :])

    return rewritten(source, tmp_path, name, build)


def test_a_call_sent_again_after_a_retry_after_is_one_step_with_the_last_answer(
    world, capsys, tmp_path
):
    reader, admin = world.runs["clean"]
    waited = waited_before_first_call(
        reader, tmp_path, "waited", lambda attempt, rest: attempt + rest
    )

    code, out, err = compare(capsys, world, waited, admin)

    assert code == 0, err
    steps = rows(out)
    assert sorted(steps) == [str(PROBE_STEP), str(PROBE_STEP + 1)], "no step more"
    assert steps[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
    assert steps[str(PROBE_STEP + 1)][1:5] == ["whoami", "ok", "ok", "different"]


def test_a_run_stopped_in_the_wait_has_that_step_not_sent_and_no_step_more(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def stopped(attempt, rest):
        skipped = {
            "v": attempt[0]["v"],
            "type": "step_skipped",
            "step": "tools/call",
            "reason": "run_halted",
            "detail": "",
        }
        finished = [event for event in rest if event["type"] == "run_finished"]
        return [*attempt, dict(skipped), dict(skipped), *finished]

    halted = waited_before_first_call(reader, tmp_path, "halted", stopped)

    _, out, err = compare(capsys, world, halted, admin)

    steps = rows(out)
    assert sorted(steps) == [str(PROBE_STEP), str(PROBE_STEP + 1)], err
    assert steps[str(PROBE_STEP)][1:3] == ["probe", "not_sent"]
    assert steps[str(PROBE_STEP + 1)][1:3] == ["whoami", "not_sent"]


def test_another_request_after_a_wait_is_a_step_of_its_own(world, capsys, tmp_path):
    """The id says it is not the request sent again, so it is not folded in: the steps then stand
    apart, and the second is another tool than the other run's second."""
    reader, admin = world.runs["clean"]

    def other_id(attempt, rest):
        attempt[1]["payload"]["data"]["id"] = 777
        return attempt + rest

    other = waited_before_first_call(reader, tmp_path, "other", other_id)

    code, out, err = compare(capsys, world, other, admin)

    assert code == 2 and out == ""
    assert "step 2: the tool is not the same in both runs" in err


def test_the_output_names_both_identities_and_roles_and_calls_itself_an_observation(world, capsys):
    reader, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, reader, admin)

    assert "identity A: reader, role read-only user" in out
    assert "identity B: admin, role administrator" in out
    assert "an observation, not a severity" in out
    assert "run A: complete" in out and "run B: complete" in out


def test_a_tool_only_one_role_sees_is_in_the_difference_of_the_lists(world, capsys):
    reader, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, reader, admin)

    assert "tools only A sees: none" in out
    assert "tools only B sees: admin_only" in out
    assert "prompts only B sees: admin_prompt" in out
    assert "resources only B sees: admin://notes" in out
    _, back, _ = compare(capsys, world, admin, reader)
    assert "tools only A sees: admin_only" in back
    assert "tools only B sees: none" in back


def test_a_403_for_one_role_is_shown_as_http_403_and_an_error_with_its_code(world, capsys):
    reader, admin = world.runs["fails"]

    code, out, _ = compare(capsys, world, reader, admin, "--json")

    document = json.loads(out)
    by_tool = {row["tool"]: row for row in document["calls"]}
    assert by_tool["probe"]["answers"] == "same" and by_tool["probe"]["first_difference"] is None
    assert by_tool["broken"]["a"] == {"result": "rpc_error", "code": -32010, "status": 200}
    assert by_tool["broken"]["b"]["result"] == "ok"
    assert by_tool["broken"]["first_difference"] == "error"
    assert by_tool["restricted"]["a"]["result"] == "http_403"
    assert by_tool["restricted"]["b"]["result"] == "ok"
    assert by_tool["restricted"]["answers"] == "different"
    assert by_tool["restricted"]["first_difference"] == ""
    assert code == cli.EXIT_INCOMPLETE


def test_the_text_shows_the_error_code_and_the_403(world, capsys):
    reader, admin = world.runs["fails"]

    _, out, _ = compare(capsys, world, reader, admin)

    steps = rows(out)
    assert steps["3"][1:4] == ["broken", "rpc_error", "-32010"]
    assert steps["4"][1:4] == ["restricted", "http_403", "ok"]
    assert "(the answer as a whole)" in out


def test_a_run_that_is_not_a_result_is_compared_and_both_states_come_first(world, capsys):
    reader, admin = world.runs["fails"]

    code, out, err = compare(capsys, world, reader, admin)

    first = out.splitlines()[:2]
    assert first[0].startswith("run A: incomplete") and "not a result" in first[0]
    assert first[1] == "run B: complete"
    assert code == verdict.EXIT_INCOMPLETE
    assert "run A is incomplete: not a result" in err


def test_a_run_given_by_its_recording_file_reads_the_same(world, capsys):
    reader, admin = world.runs["clean"]

    by_directory = compare(capsys, world, reader, admin, "--json")
    by_file = compare(capsys, world, reader / "events.jsonl", admin / "events.jsonl", "--json")

    assert by_file == by_directory


# -- what is refused ----------------------------------------------------------------------------


def refused(capsys, world, one, other, *words):
    code, out, err = compare(capsys, world, one, other)
    assert code == cli.EXIT_REFUSED
    assert out == ""
    assert err.startswith("kymograph: refused: ") and len(err.splitlines()) == 1
    for word in words:
        assert word in err
    return err


def test_two_engagements_are_refused(world, capsys):
    reader, _ = world.runs["clean"]

    refused(capsys, world, reader, world.other_engagement, "not of the same engagement")


def test_two_scripts_are_refused_by_their_digest(world, capsys):
    reader, _ = world.runs["clean"]

    refused(capsys, world, reader, world.other_script, "different scripts")


def test_two_scripts_without_a_digest_are_refused_by_the_method_and_tool_of_each_step(
    world, capsys, tmp_path
):
    reader, admin = world.runs["clean"]

    def without_digest(event):
        if event["type"] == "run_started":
            event["script_digest"] = None

    def other_tool(event):
        without_digest(event)
        data = event.get("payload", {}).get("data")
        if (
            event["type"] == "message"
            and isinstance(data, dict)
            and data.get("method") == "tools/call"
            and data["params"]["name"] == "whoami"
        ):
            data["params"]["name"] = "broken"

    one = edited(reader, tmp_path, "one", without_digest)
    other = edited(admin, tmp_path, "other", other_tool)

    refused(capsys, world, one, other, "different scripts")


def without_digest(event):
    if event["type"] == "run_started":
        event["script_digest"] = None


def test_a_digest_on_one_side_only_is_refused_whatever_the_steps(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    bare_reader = edited(reader, tmp_path, "r", without_digest)
    bare_admin = edited(admin, tmp_path, "a", without_digest)

    # The steps of the two are the same, and so are the names: only the digest is on one side.
    refused(capsys, world, bare_reader, admin, "different scripts")
    refused(capsys, world, reader, bare_admin, "different scripts")


def test_two_script_names_that_differ_are_refused_with_or_without_a_digest(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def renamed(event):
        if event["type"] == "run_started":
            event["script"] = "another"

    def bare_renamed(event):
        without_digest(event)
        renamed(event)

    refused(capsys, world, reader, edited(admin, tmp_path, "a", renamed), "different scripts")
    refused(
        capsys, world, edited(reader, tmp_path, "r", without_digest),
        edited(admin, tmp_path, "b", bare_renamed), "different scripts",
    )  # fmt: skip


def test_without_a_digest_or_a_name_only_the_tools_both_sent_are_compared(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def bare(event):
        without_digest(event)
        if event["type"] == "run_started":
            event["script"] = None

    code, out, err = compare(
        capsys, world, edited(reader, tmp_path, "r", bare), edited(admin, tmp_path, "a", bare)
    )

    assert code == 0, err
    assert sorted(rows(out)) == ["1", "2"]


def test_the_same_identity_twice_is_refused(world, capsys):
    reader, _ = world.runs["clean"]

    refused(capsys, world, reader, reader, "same identity")


def test_a_run_without_an_identity_is_refused(world, capsys):
    reader, _ = world.runs["clean"]

    refused(capsys, world, reader, world.nobody, "run B has no identity")
    refused(capsys, world, world.nobody, reader, "run A has no identity")


def test_a_run_whose_pseudonyms_last_a_run_only_is_refused(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def per_run(event):
        if event["type"] == "run_started":
            event["pseudonyms"] = "per_run"

    refused(capsys, world, edited(reader, tmp_path, "r", per_run), admin, "run A", "pseudonyms")
    refused(capsys, world, reader, edited(admin, tmp_path, "a", per_run), "run B", "pseudonyms")


@pytest.mark.parametrize(
    ("said", "change"),
    [
        ("the tool is not", lambda params, data: params.update(name="broken")),
        ("the arguments are not", lambda params, data: params.update(arguments={"text": "x"})),
    ],
)
def test_a_step_that_is_not_the_same_is_refused_with_its_number(
    world, capsys, tmp_path, said, change
):
    reader, admin = world.runs["clean"]

    def edit(event):
        data = event.get("payload", {}).get("data")
        if (
            event["type"] == "message"
            and isinstance(data, dict)
            and data.get("method") == "tools/call"
            and data["params"]["name"] == "probe"
        ):
            change(data["params"], data)

    refused(
        capsys, world, reader, edited(admin, tmp_path, "b", edit),
        f"step {PROBE_STEP}", said,
    )  # fmt: skip


def test_a_step_one_run_never_sent_is_not_sent_with_the_state_of_its_run(world, capsys):
    admin, reader = world.runs["ends"]

    code, out, err = compare(capsys, world, admin, reader)

    steps = rows(out)
    assert sorted(steps) == ["1", "2", "3"]
    assert steps["2"][1:5] == ["restricted", "ok", "http_403", "different"]
    assert steps["3"][1:4] == ["whoami", "ok", "not_sent"]
    assert "run B did not send it: incomplete" in out
    assert out.splitlines()[1].startswith("run B: incomplete")
    document = json.loads(compare(capsys, world, admin, reader, "--json")[1])
    third = document["calls"][2]
    assert third["step"] == 3 and third["answers"] == "different"
    assert third["a"]["result"] == "ok" and third["b"]["result"] == "not_sent"
    assert third["b"]["state"] == document["runs"]["b"]["state"] == "incomplete"
    assert third["b"]["causes"] == document["runs"]["b"]["causes"]
    assert code == verdict.EXIT_INCOMPLETE and err


def test_the_steps_are_those_of_the_script_not_the_requests_of_the_driver(world, capsys):
    reader, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, reader, admin)

    # CLEAN has two calls; the discovery request, initialize and three listings do not count.
    assert sorted(rows(out)) == ["1", "2"]


def test_a_recording_that_cannot_be_read_is_refused(world, capsys, tmp_path):
    reader, _ = world.runs["clean"]

    refused(capsys, world, reader, tmp_path / "nothing", "run B cannot be read")


# -- the first place that differs: a path, never a value --------------------------


def test_a_mark_in_a_key_below_structured_content_is_a_star(world, capsys):
    reader, admin = world.runs["shapes"]

    # compare() looks for every mark in stdout and stderr.
    _, out, _ = compare(capsys, world, reader, admin)
    _, said, _ = compare(capsys, world, reader, admin, "--json")

    assert rows(out)["1"][1:5] == ["keyed", "ok", "ok", "different"]
    assert rows(out)["1"][5] == "result.structuredContent.*"
    by_tool = {row["tool"]: row for row in json.loads(said)["calls"]}
    assert by_tool["keyed"]["first_difference"] == "result.structuredContent.*"


def test_an_array_is_addressed_by_its_index_and_its_uri_is_not_a_selector(world, capsys):
    reader, admin = world.runs["shapes"]

    _, said, _ = compare(capsys, world, reader, admin, "--json")

    by_tool = {row["tool"]: row for row in json.loads(said)["calls"]}
    assert by_tool["shaped"]["first_difference"] == "result.contents[0].uri"


@pytest.mark.parametrize(
    ("one", "other", "path"),
    [
        # a key the schema does not have, and a key of the server that looks like one
        ({"result": {"KUNDE-4711": 1}}, {"result": {}}, "result.*"),
        ({"result": {"x": {"text": 1}}}, {"result": {"x": {"text": 2}}}, "result.*.*"),
        ({"result": {"structuredContent": {"text": 1}}},
         {"result": {"structuredContent": {"text": 2}}}, "result.structuredContent.*"),
        ({"result": {"_meta": {"code": 1}}}, {"result": {"_meta": {"code": 2}}}, "result._meta.*"),
        ({"error": {"code": 1, "data": {"message": 1}}},
         {"error": {"code": 1, "data": {"message": 2}}}, "error.data.*"),
        ({"error": {"code": 1, "message": "x"}}, {"error": {"code": 2, "message": "x"}},
         "error.code"),
        # two keys that differ at one place end the path there with a star
        ({"result": {"structuredContent": {"a": 1}}}, {"result": {"structuredContent": {"b": 1}}},
         "result.structuredContent.*"),
        # an array by its index, though the table of identities knows ``result.tools``; the
        # key ``tools`` is not one of a call's answer
        ({"result": {"tools": [{"name": "a"}, {"name": "b"}]}},
         {"result": {"tools": [{"name": "a"}, {"name": "c"}]}}, "result.*[1].*"),
        ({"result": {"content": [{"type": "text", "text": "a"}]}},
         {"result": {"content": [{"type": "text", "text": "b"}]}}, "result.content[0].text"),
    ],
)  # fmt: skip
def test_only_a_key_of_the_schema_stands_in_the_path(one, other, path):
    assert identity_compare._first(one, other, identity_compare._Trail("")) == path


# -- the steps of a run that stopped ------------------------------------------------


def test_a_failure_of_the_driver_leaves_the_steps_of_the_script_and_no_more(
    world, capsys, tmp_path
):
    reader, admin = world.runs["three"]
    failed = driver_failed(reader, tmp_path, "failed", after=1)

    _, out, _ = compare(capsys, world, failed, admin)
    _, said, _ = compare(capsys, world, failed, admin, "--json")

    steps = rows(out)
    assert sorted(steps) == ["1", "2", "3"]
    assert steps["1"][1:5] == ["probe", "ok", "ok", "same"]
    assert steps["2"][1:4] == ["whoami", "not_sent", "ok"]
    assert steps["3"][1:4] == ["probe", "not_sent", "ok"]
    document = json.loads(said)
    assert [row["step"] for row in document["calls"]] == [1, 2, 3]
    for row in document["calls"][1:]:
        assert row["a"]["state"] == document["runs"]["a"]["state"]
        assert row["a"]["causes"] == document["runs"]["a"]["causes"]


def test_a_failure_of_the_driver_on_the_other_side_reads_the_same(world, capsys, tmp_path):
    reader, admin = world.runs["three"]
    failed = driver_failed(admin, tmp_path, "failed", after=1)

    _, said, _ = compare(capsys, world, reader, failed, "--json")

    assert [row["step"] for row in json.loads(said)["calls"]] == [1, 2, 3]


def test_a_call_skipped_in_the_middle_keeps_the_next_step_at_the_same_tool(world, capsys):
    reader, admin = world.runs["skips"]

    _, out, _ = compare(capsys, world, reader, admin)

    steps = rows(out)
    assert sorted(steps) == ["1", "2", "3"]
    assert steps["2"][1:3] == ["admin_only", "not_sent"]
    assert steps["3"][1:4] == ["whoami", "ok", "ok"]


def test_the_line_of_a_step_neither_run_sent_names_both_states(world, capsys, tmp_path):
    admin, reader = world.runs["ends"]
    # A ends on its 403 after step 2; B's driver failed after step 1: the states differ.
    failed = driver_failed(admin, tmp_path, "failed", after=1)

    code, out, _ = compare(capsys, world, reader, failed)
    _, said, _ = compare(capsys, world, reader, failed, "--json")

    runs = json.loads(said)["runs"]
    assert code == verdict.EXIT_INCOMPLETE
    assert runs["a"]["state"] == runs["b"]["state"] == verdict.INCOMPLETE
    assert (runs["a"]["state"], runs["a"]["causes"]) != (runs["b"]["state"], runs["b"]["causes"])
    # the difference is of two causes of a run, not of a script_finished the helper left out
    for run in runs.values():
        assert "no_script_finished" not in run["causes"]
    assert "unauthorized" in runs["a"]["causes"] and "unauthorized" not in runs["b"]["causes"]
    (third,) = [line for line in out.splitlines() if line.startswith("3 ")]
    for label, run in (("A", runs["a"]), ("B", runs["b"])):
        causes = f" ({', '.join(run['causes'])})" if run["causes"] else ""
        assert f"run {label} did not send it: {run['state']}{causes}" in third


# -- what is not shown, and what is not done ----------------------------------------


@pytest.mark.parametrize("pair", ["clean", "fails", "ends", "shapes"])
@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_no_value_of_an_answer_and_no_token_is_in_any_output(world, capsys, pair, flags):
    reader, admin = world.runs[pair]

    # compare() looks for every mark, token and the salt in stdout and in stderr.
    _, out, err = compare(capsys, world, reader, admin, *flags)

    assert world.marks and out
    if flags:
        assert json.loads(out)["observation"] == "an observation, not a severity"


def test_the_fixture_does_reflect_the_tokens_and_carries_marks(world):
    # Without this the test above would pass against a server that says nothing.
    reader, _ = world.runs["clean"]
    recording = (reader / "events.jsonl").read_text()

    assert '"token": "***REDACTED***"' in recording
    assert not any(token in recording for token in world.tokens.values())
    assert any(mark in recording for mark in world.marks)


@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_no_verdict_is_given_in_words(world, capsys, flags):
    reader, admin = world.runs["fails"]

    _, out, err = compare(capsys, world, reader, admin, *flags)

    for word in ("vulnerable", "safe", "secure", "critical", "high", "medium", "low", "verdict"):
        assert word not in (out + err).lower().replace("an observation, not a severity", "")


def test_nothing_is_sent_and_nothing_is_written(world, capsys):
    reader, admin = world.runs["clean"]
    before = sorted(str(p) for p in world.base.rglob("*"))
    sent = len(world.server.behaviour.heads)

    compare(capsys, world, reader, admin)
    compare(capsys, world, reader, admin, "--json")

    assert sorted(str(p) for p in world.base.rglob("*")) == before
    assert len(world.server.behaviour.heads) == sent


def test_a_name_goes_through_the_filter_of_the_terminal(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def hide_in_name(event):
        data = event.get("payload", {}).get("data")
        if event["type"] != "message" or not isinstance(data, dict):
            return
        tools = (data.get("result") or {}).get("tools")
        if event["direction"] == "server_to_client" and tools:
            tools.append({"name": "sneaky\x1b[31m‮tool"})

    _, out, _ = compare(capsys, world, edited(reader, tmp_path, "r", hide_in_name), admin)

    assert "\x1b" not in out and "‮" not in out
    assert "sneaky[31mtool" in out


def test_a_name_goes_through_the_filter_of_the_terminal_in_json_too(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def hide_in_name(event):
        data = event.get("payload", {}).get("data")
        if event["type"] != "message" or not isinstance(data, dict):
            return
        tools = (data.get("result") or {}).get("tools")
        if event["direction"] == "server_to_client" and tools:
            tools.append({"name": "sneaky\x1b[31m‮tool"})

    _, out, _ = compare(capsys, world, edited(reader, tmp_path, "r", hide_in_name), admin, "--json")

    names = json.loads(out)["lists"]["tools"]["only_a"]
    assert "sneaky[31mtool" in names
    assert not any("\x1b" in name or "‮" in name for name in names)


def masked_pair(world, tmp_path, token: str | None = None) -> tuple[Path, Path]:
    """The reader's and the administrator's ``clean`` runs with the reader's ``whoami`` answer
    set to the administrator's, but for the token the server reflects: that stays what each run
    recorded, and the two raw tokens are not the same. With ``token``, the reader's is that."""
    reader, admin = world.runs["clean"]

    def reflected(source: Path):
        held = [json.loads(line) for line in (source / "events.jsonl").read_text().splitlines()]
        found = [
            event["payload"]["data"]["result"]
            for event in held
            if event["type"] == "message"
            and event["direction"] == "server_to_client"
            and "token"
            in ((event["payload"]["data"].get("result") or {}).get("structuredContent") or {})
        ]
        assert len(found) == 1
        return found[0]

    def same_but_token(event):
        data = event.get("payload", {}).get("data")
        if event["type"] != "message" or not isinstance(data, dict):
            return
        result = data.get("result") or {}
        if event["direction"] == "server_to_client" and "token" in (
            result.get("structuredContent") or {}
        ):
            result["content"] = reflected(admin)["content"]
            result["structuredContent"]["role"] = reflected(admin)["structuredContent"]["role"]
            if token is not None:
                result["structuredContent"]["token"] = token

    assert world.tokens["reader"] != world.tokens["admin"]
    return edited(reader, tmp_path, "r", same_but_token), admin


def test_answers_that_differ_raw_only_in_a_masked_value_are_the_same(world, capsys, tmp_path):
    reader, admin = masked_pair(world, tmp_path)
    reflected = [
        '"token": "***REDACTED***"' in (run / "events.jsonl").read_text() for run in (reader, admin)
    ]

    _, out, _ = compare(capsys, world, reader, admin)

    assert reflected == [True, True]
    assert rows(out)[str(PROBE_STEP + 1)][1:5] == ["whoami", "ok", "ok", "same"]


def test_answers_that_differ_in_a_value_the_recording_does_not_mask_are_not_the_same(
    world, capsys, tmp_path
):
    reader, admin = masked_pair(world, tmp_path, token="unmasked-" + secrets.token_hex(6))

    _, out, _ = compare(capsys, world, reader, admin)

    assert rows(out)[str(PROBE_STEP + 1)][1:5] == ["whoami", "ok", "ok", "different"]
    assert "unmasked-" not in out


# -- a list not read to its end is not a difference -----------------------------------------


def listing_calls(held: list[dict], method: str) -> list[tuple[int, int]]:
    """For each request of ``method`` in a recording: the index of the request and of its answer
    (None where no answer stands after it)."""
    found = []
    for index, event in enumerate(held):
        data = (event.get("payload") or {}).get("data") if event["type"] == "message" else None
        if isinstance(data, dict) and data.get("method") == method:
            answer = next(
                (
                    later
                    for later, other in enumerate(held[index + 1 :], index + 1)
                    if other["type"] == "message"
                    and other["direction"] == "server_to_client"
                    and other["payload"]["data"].get("id") == data["id"]
                ),
                None,
            )
            found.append((index, answer))
    return found


def listing_cut(source: Path, tmp_path: Path, name: str, *, keep: int, answered: bool) -> Path:
    """A copy of a run in which the tool list stops after ``keep`` requests: the last of them
    answered or not, and none after it (what a listing that does not follow cursors leaves, or
    one whose next page never came)."""

    def build(held):
        asked = listing_calls(held, "tools/list")
        gone = {i for index, answer in asked[keep:] for i in (index, answer)}
        if not answered:
            gone.add(asked[keep - 1][1])
        return [event for i, event in enumerate(held) if i not in gone]

    return rewritten(source, tmp_path, name, build)


def tools_line(out: str, side: str) -> str:
    (line,) = [line for line in out.splitlines() if line.startswith(f"tools only {side} sees")]
    return line


def test_a_list_both_runs_read_over_its_pages_is_compared_over_all_of_them(world, capsys):
    reader, admin = world.runs["paged"]

    _, out, _ = compare(capsys, world, reader, admin)

    # admin_only is on the second page of the administrator's list
    assert tools_line(out, "B") == "tools only B sees: admin_only"
    assert tools_line(out, "A") == "tools only A sees: none"


def test_a_list_cut_at_the_page_limit_is_not_compared(world, capsys):
    reader, admin = world.runs["limited"]
    assert "page_limit_reached" in (reader / "events.jsonl").read_text()

    code, out, err = compare(capsys, world, reader, admin)
    _, said, _ = compare(capsys, world, reader, admin, "--json")

    assert "tools: not compared: incomplete in A" in out
    assert "tools only" not in out
    # none of the names the reader never asked for stands as a difference, in words or in JSON
    assert "extra" not in out and "admin_only" not in out
    tools = json.loads(said)["lists"]["tools"]
    assert tools["compared"] is False and tools["reason"] == "incomplete in A"
    assert tools["only_a"] == tools["only_b"] == []
    # the other lists are read to their end and compared; the exit status is the runs'
    assert "prompts only B sees: admin_prompt" in out
    assert (
        code
        == verdict.EXIT_CODES[verdict.gravest(json.loads(said)["runs"][k]["state"] for k in "ab")]
    )


def test_the_same_cut_on_the_other_side_reads_the_same(world, capsys):
    reader, admin = world.runs["limited"]

    _, out, _ = compare(capsys, world, admin, reader)

    assert "tools: not compared: incomplete in B" in out


def test_a_list_cut_in_both_runs_says_both(world, capsys, tmp_path):
    reader, admin = world.runs["paged"]
    one = listing_cut(reader, tmp_path, "r", keep=1, answered=True)
    other = listing_cut(admin, tmp_path, "a", keep=1, answered=True)

    _, out, _ = compare(capsys, world, one, other)

    assert "tools: not compared: incomplete in both" in out


def test_a_listing_that_does_not_follow_cursors_is_not_compared(world, capsys, tmp_path):
    reader, admin = world.runs["paged"]
    # paginate false: the first page, which offers a next one, and no request for it
    first_only = listing_cut(reader, tmp_path, "r", keep=1, answered=True)

    _, out, _ = compare(capsys, world, first_only, admin)

    assert "tools: not compared: incomplete in A" in out
    assert "admin_only" not in out


def test_a_page_that_was_never_answered_is_not_compared(world, capsys, tmp_path):
    reader, admin = world.runs["paged"]
    unanswered = listing_cut(admin, tmp_path, "a", keep=2, answered=False)

    _, out, _ = compare(capsys, world, reader, unanswered)
    _, said, _ = compare(capsys, world, reader, unanswered, "--json")

    assert "tools: not compared: incomplete in B" in out
    assert "admin_only" not in out
    assert json.loads(said)["lists"]["tools"]["reason"] == "incomplete in B"


def test_a_cut_list_is_the_only_one_not_compared(world, capsys, tmp_path):
    reader, admin = world.runs["paged"]
    first_only = listing_cut(reader, tmp_path, "r", keep=1, answered=True)

    _, said, _ = compare(capsys, world, first_only, admin, "--json")

    lists = json.loads(said)["lists"]
    assert [lists[k]["compared"] for k in ("tools", "prompts", "resources")] == [False, True, True]
    assert lists["prompts"]["reason"] is None


# -- the code of an error: only a small integer ------------------------------------------------

#: Integers too long to write with json.dumps (or to read: from 4300 digits Python refuses
#: the number, and the line of the recording that holds it is a problem, not an event).
BIG = "@@4000@@"
HUGE = "@@5000@@"


def with_code(source: Path, tmp_path: Path, name: str, code) -> Path:
    """A copy of a run in which the error of tool ``broken`` carries ``code``. ``BIG`` stands for
    an integer of 4000 digits and ``HUGE`` one of 5000, which json.dumps will not write."""

    def change(event):
        data = (event.get("payload") or {}).get("data") if event["type"] == "message" else None
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            data["error"]["code"] = code

    target = edited(source, tmp_path, name, change)
    held = target / "events.jsonl"
    text = held.read_text()
    for marker, digits in ((BIG, 4000), (HUGE, 5000)):
        text = text.replace('"' + marker + '"', "9" * digits)
    held.write_text(text)
    return target


def test_a_small_integer_code_is_shown(world, capsys):
    reader, admin = world.runs["fails"]

    _, out, _ = compare(capsys, world, reader, admin)
    _, said, _ = compare(capsys, world, reader, admin, "--json")

    assert rows(out)["3"][1:4] == ["broken", "rpc_error", "-32010"]
    assert json.loads(said)["calls"][2]["a"]["code"] == -32010


@pytest.mark.parametrize("code", [-32601, -32768, 32767, 0])
def test_a_code_in_the_range_is_shown(world, capsys, tmp_path, code):
    reader, admin = world.runs["fails"]

    _, out, _ = compare(capsys, world, with_code(reader, tmp_path, "r", code), admin)

    assert rows(out)["3"][1:4] == ["broken", "rpc_error", str(code)]


@pytest.mark.parametrize(
    "code", [49170012345, 32768, -32769, BIG, "-32601", 1.5, True, None, [1], {"a": 1}]
)
def test_any_other_code_is_not_shown(world, capsys, tmp_path, code):
    reader, admin = world.runs["fails"]
    odd = with_code(reader, tmp_path, "r", code)

    _, out, _ = compare(capsys, world, odd, admin)
    _, said, _ = compare(capsys, world, odd, admin, "--json")

    (line,) = [line for line in out.splitlines() if line.startswith("3 ")]
    assert "rpc_error (code not shown)" in line
    assert "9999999" not in out and "49170012345" not in out and "32768" not in out
    assert "-32769" not in out and "1.5" not in out
    first = json.loads(said)["calls"][2]["a"]
    assert first == {"result": "rpc_error", "code": None, "status": 200}
    assert "9999999" not in said and "49170012345" not in said


def test_an_integer_too_long_to_read_is_refused_and_not_shown(world, capsys, tmp_path):
    reader, admin = world.runs["fails"]
    odd = with_code(reader, tmp_path, "r", HUGE)

    # The recorder writes a message it cannot read as JSON as text, so the line stays readable
    # and no server can bring this about: only a recording built by hand holds such a line, and
    # a line that is no event, before the end of the recording, is refused.
    code, out, err = compare(capsys, world, odd, admin)
    assert code == cli.EXIT_REFUSED
    assert out == ""
    assert err == (
        "kymograph: refused: run A holds a line this version cannot read, before its end: "
        "the steps after it could not be counted\n"
    )
    assert "999" not in err
    code, out, err = compare(capsys, world, odd, admin, "--json")
    assert code == cli.EXIT_REFUSED
    assert out == ""
    assert "999" not in err


def test_an_integer_too_long_to_read_from_a_server_is_recorded_as_a_readable_line(
    world, capsys, monkeypatch
):
    reader, admin = world.runs["fails"]
    real = http_server.json

    def dumps(document, *args, **kwargs):
        text = real.dumps(document, *args, **kwargs)
        return text.replace('"code": -32010', '"code": ' + "9" * 5000)

    # The fixture server writes the number; the recorder and the driver read it as ever.
    monkeypatch.setattr(http_server, "json", types.SimpleNamespace(dumps=dumps, loads=real.loads))
    held = world.drive("reader", "fails")
    monkeypatch.undo()

    raw = (held / "events.jsonl").read_bytes()
    problems = verdict.read_events(raw)[1]
    assert problems == []
    assert b"9" * 5000 in raw
    (line,) = [e for e in map(json.loads, raw.splitlines()) if "9" * 5000 in json.dumps(e)]
    assert line["type"] == "message" and line["payload"]["encoding"] == "text"
    code, out, _ = compare(capsys, world, held, admin)
    assert code != cli.EXIT_REFUSED
    assert rows(out)["3"][1:3] == ["broken", "no_answer"]
    assert "999" not in out


# -- an answer belongs to its request -----------------------------------------------------------

FAKE_PREFIX = "FAKE"


def with_extra_message(source: Path, tmp_path: Path, name: str, where: str) -> Path:
    """A copy of a run with one more message of the server, carrying the ``id`` of the first
    tool call and a text of its own, put ``where``: ``before`` the request in the same exchange,
    ``elsewhere`` after the request but in the exchange before its own, or ``after`` the true
    answer."""
    fake = FAKE_PREFIX + secrets.token_hex(8)

    def build(held):
        index, answer = listing_calls(held, "tools/call")[0]
        extra = json.loads(json.dumps(held[answer]))
        extra["payload"]["data"]["result"] = {"content": [{"type": "text", "text": fake}]}
        if where == "before":
            held.insert(index, extra)
        elif where == "elsewhere":
            extra["exchange"] = held[index]["exchange"] - 1
            held.insert(index + 1, extra)
        else:
            held.insert(answer + 1, extra)
        return held

    return rewritten(source, tmp_path, name, build)


@pytest.mark.parametrize("where", ["before", "elsewhere"])
def test_a_message_that_is_not_after_its_request_in_its_exchange_is_not_its_answer(
    world, capsys, tmp_path, where
):
    reader, admin = world.runs["clean"]
    sent_ahead = with_extra_message(admin, tmp_path, "a", where)

    _, out, _ = compare(capsys, world, reader, sent_ahead)
    _, said, _ = compare(capsys, world, reader, sent_ahead, "--json")

    # the true answer is the one compared: probe answers every role the same
    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
    first = json.loads(said)["calls"][PROBE_STEP - 1]
    assert first["answers"] == "same" and first["first_difference"] is None


def test_of_several_answers_the_first_counts(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    twice = with_extra_message(admin, tmp_path, "a", "after")

    _, out, _ = compare(capsys, world, reader, twice)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]


# -- an answer that comes over a resumption -------------------------------------------------------


def resuming_gets(source: Path) -> list[dict]:
    held = [json.loads(line) for line in (source / "events.jsonl").read_text().splitlines()]
    return [e for e in held if e["type"] == "http_request" and e["method"] == "GET"]


def test_the_runs_of_the_resumptions_hold_what_the_rule_reads(world):
    (resumed,) = world.runs["resumed_call"]
    held = [json.loads(line) for line in (resumed / "events.jsonl").read_text().splitlines()]
    gets = resuming_gets(resumed)
    assert len(gets) == 2 and all(len(g["headers"]["last-event-id"]) > 0 for g in gets)
    for get in gets:
        # a message of the exchange continued carries the id the GET names
        before = [
            e
            for e in held
            if e["type"] == "message" and e["seq"] < get["seq"] and e["event_id"] is not None
        ]
        assert before[-1]["event_id"] == get["headers"]["last-event-id"]
        assert before[-1]["exchange"] < get["exchange"]
    assert len(resuming_gets(world.runs["resumed_chain"][0])) == 6  # three for each call


def test_an_answer_that_comes_over_a_resumption_is_the_answer_of_its_request(world, capsys):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, resumed, admin)
    _, said, _ = compare(capsys, world, resumed, admin, "--json")

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
    first = json.loads(said)["calls"][PROBE_STEP - 1]
    assert first["answers"] == "same" and first["first_difference"] is None
    # the other call is answered, too, and differs by what it says
    assert rows(out)["2"][1:5] == ["whoami", "ok", "ok", "different"]


def test_the_same_reads_the_same_on_the_other_side(world, capsys):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, admin, resumed)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]


def test_a_list_page_that_comes_over_a_resumption_is_read(world, capsys):
    (resumed,) = world.runs["resumed_list"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, resumed, admin)
    _, said, _ = compare(capsys, world, resumed, admin, "--json")

    assert "tools: not compared" not in out
    assert "admin_only" in tools_line(out, "B")
    listed = json.loads(said)["lists"]["tools"]
    assert listed["compared"] is True and listed["only_b"] == ["admin_only"]


def test_a_chain_of_two_resumptions_leads_to_the_answer(world, capsys):
    (chained,) = world.runs["resumed_chain"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, chained, admin)
    _, said, _ = compare(capsys, world, chained, admin, "--json")

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
    # the place too: a wrong message that differs elsewhere would show another one
    assert rows(out)["2"][1:] == ["whoami", "ok", "ok", "different", "result.content[0].text"]
    whoami = json.loads(said)["calls"][1]
    assert whoami["answers"] == "different"
    assert whoami["first_difference"] == "result.content[0].text"


def test_the_name_of_the_header_may_be_in_any_case(world, capsys, tmp_path):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]

    def change(event):
        if event["type"] == "http_request" and event["method"] == "GET":
            event["headers"] = {
                ("Last-Event-ID" if name == "last-event-id" else name): value
                for name, value in event["headers"].items()
            }

    spelled = edited(resumed, tmp_path, "r", change)

    _, out, _ = compare(capsys, world, spelled, admin)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]


def test_a_get_whose_last_event_id_fits_no_earlier_event_continues_nothing(world, capsys, tmp_path):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]
    first = resuming_gets(resumed)[0]["exchange"]

    def change(event):
        if event["type"] == "http_request" and event["exchange"] == first:
            event["headers"]["last-event-id"] = "no-such-event"

    cut = edited(resumed, tmp_path, "r", change)

    _, out, _ = compare(capsys, world, cut, admin)
    _, said, _ = compare(capsys, world, cut, admin, "--json")

    # the answer stands only in a continuation the recording does not show: not linked
    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "answer_not_linked", "ok", "not_compared"]
    assert json.loads(said)["calls"][PROBE_STEP - 1]["a"]["result"] == "answer_not_linked"
    # the second call keeps its own resumption
    assert rows(out)["2"][1:5] == ["whoami", "ok", "ok", "different"]


def test_a_get_without_the_header_continues_nothing(world, capsys, tmp_path):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]
    first = resuming_gets(resumed)[0]["exchange"]

    def change(event):
        if event["type"] == "http_request" and event["exchange"] == first:
            del event["headers"]["last-event-id"]

    bare = edited(resumed, tmp_path, "r", change)

    _, out, _ = compare(capsys, world, bare, admin)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "no_answer", "ok", "different"]


def test_a_get_that_names_the_event_of_another_exchange_continues_that_one(world, capsys, tmp_path):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]
    first, second = resuming_gets(resumed)

    def change(event):
        if event["type"] == "http_request" and event["exchange"] == second["exchange"]:
            event["headers"]["last-event-id"] = first["headers"]["last-event-id"]

    crossed = edited(resumed, tmp_path, "r", change)

    _, out, _ = compare(capsys, world, crossed, admin)

    # the second call's answer stands in an exchange that continues the first call's
    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
    assert rows(out)["2"][1:5] == ["whoami", "no_answer", "ok", "different"]


def test_a_post_with_the_header_continues_nothing(world, capsys, tmp_path):
    (resumed,) = world.runs["resumed_call"]
    _, admin = world.runs["clean"]
    first = resuming_gets(resumed)[0]["exchange"]

    def change(event):
        if event["type"] == "http_request" and event["exchange"] == first:
            event["method"] = "POST"

    posted = edited(resumed, tmp_path, "r", change)

    _, out, _ = compare(capsys, world, posted, admin)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "no_answer", "ok", "different"]


# -- an answer whose continuation the recording does not show -------------------------------


def test_the_runs_of_the_priming_event_hold_no_message_with_its_id(world):
    (primed, _) = world.runs["primed_call"]
    held = [json.loads(line) for line in (primed / "events.jsonl").read_text().splitlines()]
    gets = resuming_gets(primed)
    assert len(gets) == 2
    for get in gets:
        named = get["headers"]["last-event-id"]
        assert not [e for e in held if e["type"] == "message" and e["event_id"] == named]


def test_an_answer_over_a_priming_event_is_not_linked_and_not_compared(world, capsys):
    primed, _ = world.runs["primed_call"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, primed, admin)
    _, said, _ = compare(capsys, world, primed, admin, "--json")

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "answer_not_linked", "ok", "not_compared"]
    assert rows(out)["2"][1:5] == ["whoami", "answer_not_linked", "ok", "not_compared"]
    assert len(rows(out)[str(PROBE_STEP)]) == 5  # no place
    for row in json.loads(said)["calls"]:
        assert row["a"]["result"] == "answer_not_linked" and row["b"]["result"] == "ok"
        assert row["answers"] == "not_compared" and row["first_difference"] is None


def test_the_same_reads_the_same_on_the_other_side_of_a_priming_event(world, capsys):
    primed, _ = world.runs["primed_call"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, admin, primed)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "answer_not_linked", "not_compared"]
    assert rows(out)["2"][1:5] == ["whoami", "ok", "answer_not_linked", "not_compared"]


def test_both_sides_not_linked_are_not_compared(world, capsys):
    reader, admin = world.runs["primed_call"]

    _, out, _ = compare(capsys, world, reader, admin)
    _, said, _ = compare(capsys, world, reader, admin, "--json")

    both = ["answer_not_linked", "answer_not_linked", "not_compared"]
    assert rows(out)[str(PROBE_STEP)][2:5] == both
    first = json.loads(said)["calls"][PROBE_STEP - 1]
    assert first["answers"] == "not_compared" and first["first_difference"] is None


def test_the_content_of_a_message_not_linked_is_in_no_output(world, capsys, tmp_path):
    primed, _ = world.runs["primed_call"]
    _, admin = world.runs["clean"]
    exchange = resuming_gets(primed)[0]["exchange"]
    fake = FAKE_PREFIX + secrets.token_hex(8)

    def change(event):
        if event["type"] == "message" and event["exchange"] == exchange:
            data = event["payload"]["data"]
            if "result" in data:
                data["result"] = {"content": [{"type": "text", "text": fake}], fake: fake}

    swapped = edited(primed, tmp_path, "p", change)

    for flags in ([], ["--json"]):
        for pair in ((swapped, admin), (admin, swapped)):
            _, out, err = compare(capsys, world, *pair, *flags)
            assert fake not in out and fake not in err
            assert "answer_not_linked" in out


@pytest.mark.parametrize(("status", "result"), [(401, "http_401"), (403, "http_403")])
def test_the_status_of_the_request_goes_before_a_message_not_linked(
    world, capsys, tmp_path, status, result
):
    primed, _ = world.runs["primed_call"]
    _, admin = world.runs["clean"]
    exchange = first_call_exchange(primed)

    def change(event):
        if event["type"] == "http_response" and event["exchange"] == exchange:
            event["status"] = status

    refused_one = edited(primed, tmp_path, "p", change)

    _, out, _ = compare(capsys, world, refused_one, admin)

    assert rows(out)[str(PROBE_STEP)][1:4] == ["probe", result, "ok"]
    assert rows(out)[str(PROBE_STEP)][4] == "different"


def test_a_message_with_another_id_in_a_continuation_not_shown_is_no_answer(
    world, capsys, tmp_path
):
    primed, _ = world.runs["primed_call"]
    _, admin = world.runs["clean"]
    exchange = resuming_gets(primed)[0]["exchange"]

    def change(event):
        if event["type"] == "message" and event["exchange"] == exchange:
            data = event["payload"]["data"]
            if "result" in data:
                data["id"] = "not-" + str(data["id"])

    foreign = edited(primed, tmp_path, "p", change)

    _, out, _ = compare(capsys, world, foreign, admin)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "no_answer", "ok", "different"]
    # the second call is still only answered in a continuation not shown
    assert rows(out)["2"][1:5] == ["whoami", "answer_not_linked", "ok", "not_compared"]


@pytest.mark.parametrize(("run", "gets"), [("primed_chain", 2), ("primed_chain_3", 3)])
def test_a_continuation_of_a_continuation_not_shown_is_not_linked_either(world, capsys, run, gets):
    (chained,) = world.runs[run]
    _, admin = world.runs["clean"]
    held = [json.loads(line) for line in (chained / "events.jsonl").read_text().splitlines()]
    shown = {e["event_id"] for e in held if e["type"] == "message" and e.get("event_id")}
    named = [get["headers"]["last-event-id"] for get in resuming_gets(chained)]
    # two calls, `gets` GETs each; the first names the priming event, the rest a notification
    assert len(named) == 2 * gets
    assert [n in shown for n in named[:gets]] == [False] + [True] * (gets - 1)

    _, out, _ = compare(capsys, world, chained, admin)
    _, said, _ = compare(capsys, world, chained, admin, "--json")

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "answer_not_linked", "ok", "not_compared"]
    assert rows(out)["2"][1:5] == ["whoami", "answer_not_linked", "ok", "not_compared"]
    assert len(rows(out)[str(PROBE_STEP)]) == 5  # no place
    for row in json.loads(said)["calls"]:
        assert row["a"]["result"] == "answer_not_linked" and row["b"]["result"] == "ok"
        assert row["answers"] == "not_compared" and row["first_difference"] is None


def test_an_answer_shown_wins_over_a_later_message_in_a_continuation_not_shown(
    world, capsys, tmp_path
):
    reader, admin = world.runs["clean"]
    fake = FAKE_PREFIX + secrets.token_hex(8)

    def build(held):
        shown = max(e["exchange"] for e in held if isinstance(e.get("exchange"), int))
        template = next(e for e in held if e["type"] == "http_request")
        for number, (_, answer) in enumerate(reversed(listing_calls(held, "tools/call")), 1):
            # a GET that names an event no earlier message carries, right after the true answer
            get = json.loads(json.dumps(template))
            get["method"], get["exchange"] = "GET", shown + number
            get["headers"] = {"last-event-id": "no-such-event"}
            extra = json.loads(json.dumps(held[answer]))
            extra["exchange"], extra["event_id"] = shown + number, None
            extra["payload"]["data"]["result"] = {"content": [{"type": "text", "text": fake}]}
            held[answer + 1 : answer + 1] = [get, extra]
        return held

    later = rewritten(reader, tmp_path, "l", build)

    for pair in ((later, admin), (admin, later)):
        _, out, err = compare(capsys, world, *pair)
        _, said, _ = compare(capsys, world, *pair, "--json")
        assert fake not in out + err + said
        assert "answer_not_linked" not in out + said
        assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]
        # whoami answers each role in its own words: the answer shown is the one read
        assert rows(out)["2"][1:] == ["whoami", "ok", "ok", "different", "result.content[0].text"]
        calls = json.loads(said)["calls"]
        assert calls[0]["answers"] == "same" and calls[0]["first_difference"] is None
        assert calls[1]["answers"] == "different" and calls[1]["first_difference"]


def test_a_message_with_another_id_in_a_continuation_of_one_not_shown_is_no_answer(
    world, capsys, tmp_path
):
    chained = world.runs["primed_chain"][0]
    _, admin = world.runs["clean"]
    # the second GET is the last of the first call
    last = resuming_gets(chained)[1]["exchange"]

    def change(event):
        if event["type"] == "message" and event["exchange"] == last:
            data = event["payload"]["data"]
            if "result" in data:
                data["id"] = "not-" + str(data["id"])

    foreign = edited(chained, tmp_path, "c", change)

    _, out, _ = compare(capsys, world, foreign, admin)

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "no_answer", "ok", "different"]
    assert rows(out)["2"][1:5] == ["whoami", "answer_not_linked", "ok", "not_compared"]


def test_a_list_answered_only_over_a_priming_event_is_not_read_and_says_nothing(world, capsys):
    (primed,) = world.runs["primed_list"]
    _, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, primed, admin)
    _, said, _ = compare(capsys, world, primed, admin, "--json")

    assert "tools: not compared: incomplete in A" in out
    assert "tools only" not in out and "admin_only" not in out
    listed = json.loads(said)["lists"]["tools"]
    assert listed["compared"] is False and listed["only_b"] == [] and listed["only_b_count"] == 0


# -- the states of a call and of a run ----------------------------------------------------------


def first_call_exchange(source: Path) -> int:
    held = [json.loads(line) for line in (source / "events.jsonl").read_text().splitlines()]
    index, _ = listing_calls(held, "tools/call")[0]
    return held[index]["exchange"]


@pytest.mark.parametrize(("status", "result"), [(401, "http_401"), (418, "http_other")])
def test_an_http_status_of_a_call_is_its_result(world, capsys, tmp_path, status, result):
    reader, admin = world.runs["clean"]
    exchange = first_call_exchange(reader)

    def change(event):
        if event["type"] == "http_response" and event["exchange"] == exchange:
            event["status"] = status

    refused_one = edited(reader, tmp_path, "r", change)

    _, out, _ = compare(capsys, world, refused_one, admin)
    _, said, _ = compare(capsys, world, refused_one, admin, "--json")

    expected = [result, str(status)] if result == "http_other" else [result]
    assert rows(out)[str(PROBE_STEP)][1 : 2 + len(expected)] == ["probe", *expected]
    row = json.loads(said)["calls"][PROBE_STEP - 1]
    assert row["a"] == {"result": result, "code": None, "status": status}
    assert row["b"]["result"] == "ok" and row["answers"] == "different"
    assert row["first_difference"] == ""


def test_a_call_with_no_message_of_the_server_is_no_answer(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def build(held):
        _, answer = listing_calls(held, "tools/call")[0]
        del held[answer]
        return held

    silent = rewritten(reader, tmp_path, "r", build)

    _, out, _ = compare(capsys, world, silent, admin)
    _, said, _ = compare(capsys, world, silent, admin, "--json")

    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "no_answer", "ok", "different"]
    row = json.loads(said)["calls"][PROBE_STEP - 1]
    assert row["a"] == {"result": "no_answer", "code": None, "status": 200}


# -- more names than are shown --------------------------------------------------------------------


def test_more_than_a_hundred_names_are_cut_and_counted(world, capsys):
    reader, _ = world.runs["clean"]
    _, many = world.runs["many"]

    _, out, _ = compare(capsys, world, reader, many)
    _, said, _ = compare(capsys, world, reader, many, "--json")

    # admin_only and MANY_TOOLS more, which only the second run's list has
    line = tools_line(out, "B")
    assert line.endswith(f" and {MANY_TOOLS + 1 - identity_compare.MAX_NAMES} more")
    shown = line.removeprefix("tools only B sees: ").rsplit(" and ", 1)[0].split(", ")
    assert len(shown) == identity_compare.MAX_NAMES == 100
    assert shown == sorted(shown) and len(set(shown)) == 100 and shown[0] == "admin_only"
    assert tools_line(out, "A") == "tools only A sees: none"
    tools = json.loads(said)["lists"]["tools"]
    assert len(tools["only_b"]) == 100 and tools["only_b_count"] == MANY_TOOLS + 1
    assert tools["only_a"] == [] and tools["only_a_count"] == 0


def test_up_to_a_hundred_names_are_not_cut(world, capsys):
    reader, admin = world.runs["clean"]

    _, out, _ = compare(capsys, world, reader, admin)

    assert " more" not in out


# -- the exit status is that of the gravest of the two states ----------------------------------


def with_event(source: Path, tmp_path: Path, name: str, **event) -> Path:
    """A copy of a run with one event more, before the last one (``run_finished``)."""

    def build(held):
        return [*held[:-1], dict(v=held[0]["v"], **event), held[-1]]

    return rewritten(source, tmp_path, name, build)


def states_of(world, capsys, one, other) -> tuple[int, str, str]:
    code, said, _ = compare(capsys, world, one, other, "--json")
    runs = json.loads(said)["runs"]
    return code, runs["a"]["state"], runs["b"]["state"]


def test_a_call_answered_with_an_error_is_call_failed_and_its_exit_status_is_6(world, capsys):
    reader, admin = world.runs["broken"]

    code, one, other = states_of(world, capsys, reader, admin)

    assert (one, other) == (verdict.CALL_FAILED, verdict.COMPLETE)
    assert code == verdict.EXIT_CALL_FAILED == 6


def test_a_server_that_failed_gives_exit_4(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    failed = with_event(admin, tmp_path, "a", type="server_failed", reason="no_answer", detail="")

    code, one, other = states_of(world, capsys, reader, failed)

    assert (one, other) == (verdict.COMPLETE, verdict.SERVER_FAILED)
    assert code == verdict.EXIT_SERVER_FAILED == 4


def test_a_sandbox_that_failed_gives_exit_5(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    failed = with_event(
        reader, tmp_path, "r", type="sandbox_failed", condition="probe", phase="before_target"
    )

    code, one, other = states_of(world, capsys, failed, admin)

    assert (one, other) == (verdict.SANDBOX_FAILED, verdict.COMPLETE)
    assert code == verdict.EXIT_SANDBOX_FAILED == 5


@pytest.mark.parametrize("swapped", [False, True])
def test_of_two_runs_that_are_not_results_the_gravest_decides(world, capsys, tmp_path, swapped):
    reader, admin = world.runs["clean"]
    server = with_event(reader, tmp_path, "s", type="server_failed", reason="no_answer", detail="")
    sandbox = with_event(
        admin, tmp_path, "b", type="sandbox_failed", condition="probe", phase="before_target"
    )
    pair = (sandbox, server) if swapped else (server, sandbox)

    code, *states = states_of(world, capsys, *pair)

    assert sorted(states) == [verdict.SANDBOX_FAILED, verdict.SERVER_FAILED]
    assert code == verdict.EXIT_SANDBOX_FAILED


@pytest.mark.parametrize("swapped", [False, True])
def test_the_gravest_is_not_the_highest_number(world, capsys, tmp_path, swapped):
    # call_failed is 6 and server_failed 4, and the server that failed is the graver of the two
    called, admin = world.runs["broken"]
    server = with_event(admin, tmp_path, "s", type="server_failed", reason="no_answer", detail="")
    pair = (server, called) if swapped else (called, server)

    code, *states = states_of(world, capsys, *pair)

    assert sorted(states) == [verdict.CALL_FAILED, verdict.SERVER_FAILED]
    assert code == verdict.EXIT_SERVER_FAILED


# -- the engagement must be the same ----------------------------------------------------------


def test_the_same_engagement_id_with_another_digest_is_refused(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def other_file(event):
        if event["type"] == "run_started":
            event["authorization"]["engagement"]["engagement_digest"] = "sha256:" + "0" * 64

    changed = edited(admin, tmp_path, "a", other_file)

    err = refused(capsys, world, reader, changed, "not of the same engagement")
    assert "0" * 64 not in err


def test_a_run_made_under_no_engagement_is_refused(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def none(event):
        if event["type"] == "run_started":
            event["authorization"]["engagement"] = None

    bare = edited(admin, tmp_path, "a", none)

    refused(capsys, world, reader, bare, "run B", "no engagement")
    refused(capsys, world, bare, reader, "run A", "no engagement")


# -- a field of the recording of the wrong type is a refusal or a comparison, never a traceback -


#: Every field of ``events.jsonl`` the module reads: the event type, and the path to the field
#: (a number is the index in a list). ``load`` reads the ``run_started`` ones, ``_read_steps`` the
#: others, ``_answer`` and ``_lists`` the ones below ``result`` and ``error``.
READ_FIELDS = [
    ("run_started", ("mode",)),
    ("run_started", ("transport",)),
    ("run_started", ("auth",)),
    ("run_started", ("auth", "identity")),
    ("run_started", ("auth", "role")),
    ("run_started", ("authorization",)),
    ("run_started", ("authorization", "engagement")),
    ("run_started", ("authorization", "engagement", "engagement_id_declared")),
    ("run_started", ("authorization", "engagement", "engagement_digest")),
    ("run_started", ("pseudonyms",)),
    ("run_started", ("script_digest",)),
    ("run_started", ("script",)),
    ("http_request", ("exchange",)),
    ("http_request", ("method",)),
    ("http_request", ("headers",)),
    ("http_request", ("headers", "last-event-id")),
    ("http_response", ("exchange",)),
    ("http_response", ("status",)),
    ("step_skipped", ("step",)),
    ("step_skipped", ("reason",)),
    ("message", ("seq",)),
    ("message", ("exchange",)),
    ("message", ("event_id",)),
    ("message", ("direction",)),
    ("message", ("payload",)),
    ("message", ("payload", "encoding")),
    ("message", ("payload", "data")),
    ("message", ("payload", "data", "id")),
    ("message", ("payload", "data", "method")),
    ("message", ("payload", "data", "params")),
    ("message", ("payload", "data", "params", "name")),
    ("message", ("payload", "data", "params", "arguments")),
    ("message", ("payload", "data", "result")),
    ("message", ("payload", "data", "error")),
    ("message", ("payload", "data", "error", "code")),
    ("message", ("payload", "data", "result", "tools")),
    ("message", ("payload", "data", "result", "tools", 0, "name")),
    ("message", ("payload", "data", "result", "prompts")),
    ("message", ("payload", "data", "result", "prompts", 0, "name")),
    ("message", ("payload", "data", "result", "resources")),
    ("message", ("payload", "data", "result", "resources", 0, "uri")),
    ("message", ("payload", "data", "result", "nextCursor")),
]
#: The runs a field is changed in, where the first (``clean``, the reader) does not hold it: the
#: one with an error, the one skipping a step, the one with a list in pages (``nextCursor``).
#: Only the runs named have the field; a row whose run lacks it fails in :func:`with_field`.
CARRIED_BY = {
    ("http_request", ("headers", "last-event-id")): "resumed_call",
    ("step_skipped", ("step",)): "skips",
    ("step_skipped", ("reason",)): "skips",
    ("message", ("payload", "data", "error")): "broken",
    ("message", ("payload", "data", "error", "code")): "broken",
    ("message", ("payload", "data", "result", "nextCursor")): "paged",
}
#: The names of what a server lists, which are shown.
NAMES = [
    ("payload", "data", "result", "tools", 0, "name"),
    ("payload", "data", "result", "prompts", 0, "name"),
    ("payload", "data", "result", "resources", 0, "uri"),
]
#: A value of each wrong type, with a mark that no output may carry.
WRONG_TYPES = {
    "text": "zqx-text",
    "list": ["zqx-list", 1],
    "object": {"zqx-object": 1},
    "number": 7,
    "float": 1.5,
    "true": True,
    "null": None,
    "list in list": [["zqx-nested"]],
}


def with_field(source: Path, tmp_path: Path, kind: str, path: tuple, value) -> Path:
    """A copy of a run in which the field at ``path`` of every event of ``kind`` that has it is
    ``value``. A run that has the field in no event fails: the row would test nothing."""
    found = []

    def has(held, name) -> bool:
        if isinstance(held, dict):
            return name in held
        return isinstance(held, list) and isinstance(name, int) and name < len(held)

    def change(event):
        if event["type"] != kind:
            return
        held = event
        for name in path[:-1]:
            if not has(held, name):
                return
            held = held[name]
        if has(held, path[-1]):
            held[path[-1]] = value
            found.append(event)

    target = edited(source, tmp_path, "f", change)
    assert found, f"no {kind} event of the run has {path}"
    return target


@pytest.mark.parametrize("wrong", WRONG_TYPES)
@pytest.mark.parametrize(
    ("kind", "path"),
    READ_FIELDS,
    ids=[f"{kind}.{'.'.join(map(str, path))}" for kind, path in READ_FIELDS],
)
@pytest.mark.parametrize("side", ["A", "B"])
def test_a_field_of_the_wrong_type_ends_in_a_refusal_or_a_comparison(
    world, capsys, tmp_path, kind, path, wrong, side
):
    reader, admin = world.runs["clean"]
    if (kind, path) in CARRIED_BY:
        sources = [world.runs[CARRIED_BY[kind, path]][0]]
    else:
        # The resumed run holds the GET with its Last-Event-ID and the messages that continue it.
        (resumed,) = world.runs["resumed_call"]
        sources = [reader, resumed]
    for number, run in enumerate(sources):
        (tmp_path / str(number)).mkdir()
        changed = with_field(run, tmp_path / str(number), kind, path, WRONG_TYPES[wrong])
        pair = (changed, admin) if side == "A" else (admin, changed)
        code, out, err = compare(capsys, world, *pair)
        if code == cli.EXIT_REFUSED:
            assert out == ""
            assert err.startswith("kymograph: refused: ") and len(err.splitlines()) == 1
        else:
            assert code in set(verdict.EXIT_CODES.values()) and out
        # A text is the right type for a name, and a name is shown (through the filter).
        shown = (("auth", "identity"), ("auth", "role"), *NAMES)
        if not (wrong == "text" and path in shown):
            assert "zqx" not in out + err


ALL = tuple(WRONG_TYPES)


def but(*right: str) -> tuple[str, ...]:
    """The wrong types but those that are right for the field."""
    return tuple(name for name in ALL if name not in right)


#: The fields the alignment depends on, the words of the refusal and the wrong types to put in.
#: An id may be a text or a whole number, a method and a direction a text, an exchange over HTTP a
#: whole number: the others are wrong, and ``null`` too (for a request without an id see below).
DEPENDED_ON = [
    ("run_started", ("authorization",), "run A has an authorization", ("text", "list")),
    ("http_request", ("exchange",), "run A: the recording holds an HTTP request", ("text", "list")),
    ("http_request", ("method",), "run A: the recording holds an HTTP request", ("list", "object")),
    ("http_request", ("headers",), "run A: the recording holds an HTTP request", ("text", "list")),
    (
        "http_response",
        ("exchange",),
        "run A: the recording holds an HTTP response",
        ("text", "list"),
    ),
    ("http_response", ("status",), "run A: the recording holds an HTTP response", ("text", "list")),
    ("message", ("seq",), "run A: the recording holds a message", ("text", "list")),
    ("message", ("exchange",), "run A: the recording holds a message", but("number")),
    # A text that is neither direction is as wrong as a number.
    ("message", ("direction",), "run A: the recording holds a message", ALL),
    ("message", ("payload",), "run A: the recording holds a message", ALL),
    # Another encoding than "json" is left as it is: only a text is right for it.
    ("message", ("payload", "encoding"), "run A: the recording holds a message", but("text")),
    # Of the data of a message of the client, a batch (a list) is no object either.
    ("message", ("payload", "data"), "run A: the recording holds a message", but("object")),
    (
        "message",
        ("payload", "data", "method"),
        "run A: the recording holds a message",
        but("text"),
    ),
    (
        "message",
        ("payload", "data", "id"),
        "run A: the recording holds a message",
        ("list", "object", "float", "true", "null", "list in list"),
    ),
    ("run_started", ("transport",), "run A: the recording holds a message", ALL),
]


@pytest.mark.parametrize(
    ("kind", "path", "words", "wrong"),
    [(kind, path, words, one) for kind, path, words, wrongs in DEPENDED_ON for one in wrongs],
)
def test_a_field_the_comparison_depends_on_is_refused_with_a_fixed_line(
    world, capsys, tmp_path, kind, path, words, wrong
):
    reader, admin = world.runs["clean"]
    changed = with_field(reader, tmp_path, kind, path, WRONG_TYPES[wrong])

    err = refused(capsys, world, changed, admin, words)

    assert "zqx" not in err


# -- a step does not vanish from the recording, and an exchange is there over HTTP ------------


def with_call(source: Path, tmp_path: Path, name: str, change, which: int = 0) -> Path:
    """A copy of a run in which ``change`` edits the ``which``-th request of a ``tools/call``."""
    calls = []

    def edit(event):
        data = event.get("payload", {}).get("data") if event["type"] == "message" else None
        if isinstance(data, dict) and data.get("method") == "tools/call":
            calls.append(event)
            if len(calls) == which + 1:
                change(event)

    return edited(source, tmp_path, name, edit)


def test_a_repeated_call_whose_id_is_null_in_the_first_is_refused_never_the_same(
    world, capsys, tmp_path
):
    reader, admin = world.runs["twice"]

    def no_id(event):
        event["payload"]["data"]["id"] = None

    lost = with_call(reader, tmp_path, "r", no_id)

    refused(capsys, world, lost, admin, "run A: the recording holds a message")
    refused(capsys, world, admin, lost, "run B: the recording holds a message")


def test_a_request_without_an_id_is_no_step_in_both_runs(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def no_id(event):
        del event["payload"]["data"]["id"]

    quiet_reader = with_call(reader, tmp_path, "r", no_id)
    quiet_admin = with_call(admin, tmp_path, "a", no_id)

    code, out, _ = compare(capsys, world, quiet_reader, quiet_admin)

    assert code in set(verdict.EXIT_CODES.values())
    # The probe is gone from the table; the call that follows is the first step.
    assert [row[1] for row in rows(out).values()] == ["whoami"]


def test_an_http_call_without_an_exchange_loses_no_403(world, capsys, tmp_path):
    ended, reader = world.runs["ends"]

    def no_exchange(event):
        if event["type"] == "message":
            event["exchange"] = None

    lost = edited(reader, tmp_path, "r", no_exchange)

    refused(capsys, world, ended, lost, "run B: the recording holds a message")
    # ... where the recording as it is shows the 403.
    _, out, _ = compare(capsys, world, ended, reader)
    assert "http_403" in out


def test_a_message_over_stdio_has_no_exchange_and_is_compared_as_before(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]

    def over_stdio(source: Path, name: str) -> Path:
        def build(held):
            for event in held:
                if event["type"] == "run_started":
                    event["transport"] = events.TRANSPORT_STDIO
                if event["type"] == "message":
                    event["exchange"] = None
            return [e for e in held if not e["type"].startswith("http_")]

        return rewritten(source, tmp_path, name, build)

    code, out, err = compare(capsys, world, over_stdio(reader, "r"), over_stdio(admin, "a"))

    assert code in set(verdict.EXIT_CODES.values()), err
    assert rows(out)[str(PROBE_STEP)][1:5] == ["probe", "ok", "ok", "same"]


# -- a message that is not an object, and the answers of the server ------------------------------


def with_inserted(source: Path, tmp_path: Path, name: str, call: int, make) -> Path:
    """A copy of a run in which ``make`` builds a message (from a copy of the answer to the
    ``call``-th ``tools/call``) that is put in front of that answer."""

    def build(held):
        _, answer = listing_calls(held, "tools/call")[call]
        extra = make(json.loads(json.dumps(held[answer])))
        return [*held[:answer], extra, *held[answer:]]

    return rewritten(source, tmp_path, name, build)


def test_a_message_of_the_server_whose_data_is_no_object_drops_no_step(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    _, plain, _ = compare(capsys, world, reader, admin)

    def batch(extra):
        extra["payload"]["data"] = [1]
        return extra

    odd = with_inserted(reader, tmp_path, "r", 0, batch)

    code, out, err = compare(capsys, world, odd, admin)

    assert code == 0, err
    assert out == plain


def test_a_message_with_another_encoding_than_json_is_left_as_it_is(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    _, plain, _ = compare(capsys, world, reader, admin)

    def binary(extra):
        extra["payload"]["encoding"] = "base64"
        return extra

    odd = with_inserted(reader, tmp_path, "r", 0, binary)

    code, out, err = compare(capsys, world, odd, admin)

    assert code == 0, err
    assert out == plain


def with_answer_id(source: Path, tmp_path: Path, name: str, identifier) -> Path:
    """A copy of a run in which the answer to its first ``tools/call`` has ``identifier``."""

    def build(held):
        _, answer = listing_calls(held, "tools/call")[0]
        held[answer]["payload"]["data"]["id"] = identifier
        return held

    return rewritten(source, tmp_path, name, build)


@pytest.mark.parametrize("wrong", but("text", "number"))
@pytest.mark.parametrize("side", ["A", "B"])
def test_an_answer_whose_id_is_of_the_wrong_type_is_refused(world, capsys, tmp_path, wrong, side):
    reader, admin = world.runs["clean"]
    odd = with_answer_id(reader, tmp_path, "r", WRONG_TYPES[wrong])
    pair = (odd, admin) if side == "A" else (admin, odd)

    err = refused(capsys, world, *pair, f"run {side}: the recording holds a message")

    assert "zqx" not in err


def null_error(extra):
    extra["payload"]["data"] = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700}}
    return extra


def null_result(extra):
    extra["payload"]["data"] = {"jsonrpc": "2.0", "id": None, "result": {}}
    return extra


def test_an_answer_of_the_server_with_a_null_id_and_an_error_is_left_out(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    _, plain, _ = compare(capsys, world, reader, admin)
    _, plain_json, _ = compare(capsys, world, reader, admin, "--json")
    odd = with_inserted(reader, tmp_path, "r", 0, null_error)

    code, out, err = compare(capsys, world, odd, admin)
    _, said, _ = compare(capsys, world, odd, admin, "--json")

    assert code == 0, err
    assert out == plain
    assert said == plain_json


def test_an_answer_of_the_server_with_a_null_id_and_a_result_is_refused(world, capsys, tmp_path):
    reader, admin = world.runs["clean"]
    odd = with_inserted(reader, tmp_path, "r", 0, null_result)

    refused(capsys, world, odd, admin, "run A: the recording holds a message")
    refused(capsys, world, admin, odd, "run B: the recording holds a message")


# -- the scope guard refuses a call: the steps after it are the script's, not sent -------------


def guard_refused(source: Path, tmp_path: Path, name: str, after: int) -> Path:
    """The recording of a run whose driver sent ``after`` tool calls and then refused the next:
    ``Driver._call`` finds the guard's cause and calls ``Driver._refuse``, which writes a
    ``call_blocked`` (``where: BLOCKED_BY_DRIVER``) and a ``step_skipped`` with ``driver_error``
    and the ``detail`` "the engagement does not allow this call" for the refused step;
    ``Driver._converse`` then calls ``_skip_remaining(self._script.steps[index + 1 :],
    self._failure)`` for the steps after it, with an empty ``detail``, none for the ones sent
    (driver.py). ``script_finished.skipped`` holds every one of them, the inventory is
    ``partial``. This is the form ``test_a_refusal_after_a_sent_call_skips_the_refused_step_and_
    the_later_ones_only`` (test_scope_guard.py) shows on the real driver, for a script with a
    closing ``tools/list``. The scripts of these tests have none; the helper adds that listing
    to the steps not sent, as the real driver would record it for a script that had one."""

    def build(held):
        calls = [i for i, e in enumerate(held) if e["type"] == "step_called"]
        (finished,) = [e for e in held if e["type"] == "script_finished"]
        blocked = {
            "v": held[0]["v"],
            "type": "call_blocked",
            "cause": "tool_writes_not_released",
            "where": events.BLOCKED_BY_DRIVER,
            "tool": held[calls[after]]["tool"],
            "message_id": None,
            "answered": False,
            "batch": False,
        }
        steps = ["tools/call"] * len(calls[after:]) + ["tools/list"]
        skipped = [
            {
                "v": held[0]["v"],
                "type": "step_skipped",
                "step": step,
                "reason": events.DRIVER_ERROR,
                "detail": "the engagement does not allow this call" if number == 0 else "",
            }
            for number, step in enumerate(steps)
        ]
        sent, seen = [], 0
        for method in finished["sent"]:
            if method == "tools/call":
                seen += 1
                if seen > after:
                    continue
            sent.append(method)
        closing = {
            **finished,
            "inventory": events.INVENTORY_PARTIAL,
            "sent": sent,
            "skipped": [[step, events.DRIVER_ERROR] for step in steps],
            "unanswered": [],
            "called": finished["called"][:after],
            "failed": [tool for tool in finished["failed"] if tool in finished["called"][:after]],
        }
        return [*held[: calls[after]], blocked, *skipped, closing, held[-1]]

    return rewritten(source, tmp_path, name, build)


@pytest.mark.parametrize("after", [0, 1, 2])
def test_a_refusal_of_the_guard_in_both_runs_leaves_every_step_of_the_script(
    world, capsys, tmp_path, after
):
    # Against a run that sent every call the longer run would supply the rows: both are cut short.
    reader, admin = world.runs["three"]
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    one = guard_refused(reader, tmp_path / "one", "refused", after=after)
    other = guard_refused(admin, tmp_path / "two", "refused", after=after)

    _, out, _ = compare(capsys, world, one, other)
    _, said, _ = compare(capsys, world, one, other, "--json")

    assert sorted(rows(out)) == ["1", "2", "3"]
    document = json.loads(said)
    assert [row["step"] for row in document["calls"]] == [1, 2, 3]
    for number, row in enumerate(document["calls"]):
        sent = number < after
        assert row["a"]["result"] == row["b"]["result"] == ("ok" if sent else "not_sent")
        assert (row["answers"] == "none") is (not sent)
        if not sent:
            assert row["a"]["state"] == document["runs"]["a"]["state"]
            assert row["b"]["causes"] == document["runs"]["b"]["causes"]


@pytest.mark.parametrize("after", [0, 1, 2])
def test_a_refusal_of_the_guard_against_a_run_that_sent_every_call(world, capsys, tmp_path, after):
    reader, admin = world.runs["three"]
    refusal = guard_refused(reader, tmp_path, "refused", after=after)

    _, out, _ = compare(capsys, world, refusal, admin)
    _, said, _ = compare(capsys, world, refusal, admin, "--json")

    steps = rows(out)
    assert sorted(steps) == ["1", "2", "3"]
    document = json.loads(said)
    assert [row["step"] for row in document["calls"]] == [1, 2, 3]
    for number, row in enumerate(document["calls"]):
        if number < after:
            assert row["a"]["result"] == row["b"]["result"] == "ok"
            continue
        assert (row["a"]["result"], row["b"]["result"], row["answers"]) == (
            "not_sent",
            "ok",
            "different",
        )
        assert row["a"]["state"] == document["runs"]["a"]["state"]
        assert row["a"]["causes"] == document["runs"]["a"]["causes"]
        assert steps[str(number + 1)][1:5] == [row["tool"], "not_sent", "ok", "different"]


def test_a_refusal_of_the_guard_on_the_other_side_reads_the_same(world, capsys, tmp_path):
    reader, admin = world.runs["three"]
    refusal = guard_refused(admin, tmp_path, "refused", after=1)

    _, out, _ = compare(capsys, world, reader, refusal)
    _, said, _ = compare(capsys, world, reader, refusal, "--json")

    assert sorted(rows(out)) == ["1", "2", "3"]
    document = json.loads(said)
    assert [row["b"]["result"] for row in document["calls"]] == ["ok", "not_sent", "not_sent"]
    assert document["calls"][2]["b"]["causes"] == document["runs"]["b"]["causes"]


def test_a_refusal_at_different_steps_reads_as_the_steps_neither_sent(world, capsys, tmp_path):
    reader, admin = world.runs["three"]
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    one = guard_refused(reader, tmp_path / "one", "refused", after=2)
    other = guard_refused(admin, tmp_path / "two", "refused", after=1)

    _, out, _ = compare(capsys, world, one, other)
    _, said, _ = compare(capsys, world, one, other, "--json")

    assert sorted(rows(out)) == ["1", "2", "3"]
    document = json.loads(said)
    seen = [(row["a"]["result"], row["b"]["result"], row["answers"]) for row in document["calls"]]
    assert [seen[0][:2], seen[1][:2], seen[2]] == [
        ("ok", "ok"),
        ("ok", "not_sent"),
        ("not_sent", "not_sent", "none"),
    ]


def test_a_refusal_of_the_guard_and_a_failure_of_the_driver_each_keep_their_count(
    world, capsys, tmp_path
):
    reader, admin = world.runs["three"]
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    refusal = guard_refused(reader, tmp_path / "one", "refused", after=1)
    failure = driver_failed(admin, tmp_path / "two", "failed", after=1)

    _, said, _ = compare(capsys, world, refusal, failure, "--json")

    document = json.loads(said)
    seen = [(row["a"]["result"], row["b"]["result"]) for row in document["calls"]]
    assert seen == [("ok", "ok"), ("not_sent", "not_sent"), ("not_sent", "not_sent")]


# -- a step not sent against an answer not tied to its request ---------------------------------


def test_a_step_not_sent_against_an_answer_not_linked_is_not_compared(world, capsys, tmp_path):
    primed = world.runs["primed_call"][0]
    unsent = driver_failed(world.runs["primed_call"][1], tmp_path, "failed", after=0)

    for one, other in ((unsent, primed), (primed, unsent)):
        _, out, _ = compare(capsys, world, one, other)
        _, said, _ = compare(capsys, world, one, other, "--json")

        for number in ("1", "2"):
            assert rows(out)[number][4] == "not_compared"
        document = json.loads(said)
        for row in document["calls"]:
            assert row["answers"] == "not_compared" and row["first_difference"] is None
            assert sorted([row["a"]["result"], row["b"]["result"]]) == [
                "answer_not_linked",
                "not_sent",
            ]


def test_a_step_neither_run_sent_stays_none_and_not_different(world, capsys, tmp_path):
    reader, admin = world.runs["three"]
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    one = driver_failed(reader, tmp_path / "one", "failed", after=1)
    other = driver_failed(admin, tmp_path / "two", "failed", after=1)

    _, said, _ = compare(capsys, world, one, other, "--json")

    assert [row["answers"] for row in json.loads(said)["calls"]] == ["same", "none", "none"]


# -- a line that cannot be read, before the end of the recording -------------------------------

LINE_REFUSAL = (
    "holds a line this version cannot read, before its end: the steps after it could not be counted"
)
#: Lines that are not an event: no JSON, nested deeper than a recording is read, no object. Each
#: carries a mark that no output may show.
UNREADABLE_LINES = {
    "not JSON": b"zqx-not-json {",
    "too deep": b'{"zqx":' * 600 + b"1" + b"}" * 600,
    "not an object": b'["zqx-list", 1]',
}


def with_line(source: Path, tmp_path: Path, name: str, put: dict[int, bytes]) -> Path:
    """A copy of a run in which the lines at the positions of ``put`` (counted from 0) are the
    bytes given. The other lines stay."""
    lines = (source / "events.jsonl").read_bytes().splitlines()
    for position, text in put.items():
        lines[position] = text
    target = tmp_path / name
    target.mkdir()
    (target / "events.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    return target


def first_call_line(source: Path) -> int:
    """The position of the line that holds the first request of a ``tools/call``."""
    for position, line in enumerate((source / "events.jsonl").read_bytes().splitlines()):
        data = json.loads(line).get("payload", {}).get("data")
        if isinstance(data, dict) and data.get("method") == "tools/call":
            return position
    raise AssertionError("no tools/call in the run")


@pytest.mark.parametrize("kind", UNREADABLE_LINES)
@pytest.mark.parametrize("side", ["A", "B"])
def test_a_line_that_cannot_be_read_in_the_middle_is_refused(world, capsys, tmp_path, kind, side):
    # TWICE: two equal steps, so that the step lost would leave a likeness, not a refusal.
    reader, admin = world.runs["twice"]
    source = reader if side == "A" else admin
    damaged = with_line(source, tmp_path, "d", {first_call_line(source): UNREADABLE_LINES[kind]})
    one, other = (damaged, admin) if side == "A" else (reader, damaged)

    err = refused(capsys, world, one, other, f"run {side} {LINE_REFUSAL}")

    assert err.strip() == f"kymograph: refused: run {side} {LINE_REFUSAL}"
    assert "zqx" not in err
    code = cli.main(["engagement", "compare", str(one), str(other), "--json"])
    assert code == cli.EXIT_REFUSED and capsys.readouterr().out == ""


def with_started(source: Path, tmp_path: Path, name: str, **changed) -> Path:
    """A copy of a run whose ``run_started`` has the keys of ``changed``, and an unreadable line
    in the middle, where the first call stood."""
    lines = (source / "events.jsonl").read_bytes().splitlines()
    started = json.loads(lines[0])
    started.update(changed)
    lines[0] = json.dumps(started).encode()
    lines[first_call_line(source)] = UNREADABLE_LINES["not JSON"]
    target = tmp_path / name
    target.mkdir()
    (target / "events.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    return target


@pytest.mark.parametrize("side", ["A", "B"])
def test_a_file_that_is_no_recording_with_unreadable_lines_is_not_a_recording(
    world, capsys, tmp_path, side
):
    reader, admin = world.runs["twice"]
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "events.jsonl").write_bytes(b"zqx one\nzqx two\nzqx three\n")
    one, other = (junk, admin) if side == "A" else (reader, junk)

    err = refused(capsys, world, one, other, f"run {side} is not a recording this version reads")

    assert "could not be counted" not in err and "zqx" not in err


@pytest.mark.parametrize("side", ["A", "B"])
def test_a_foreign_schema_with_an_unreadable_line_is_not_a_recording(world, capsys, tmp_path, side):
    reader, admin = world.runs["twice"]
    source = reader if side == "A" else admin
    foreign = with_started(source, tmp_path, "f", schema_version=events.SCHEMA_VERSION + 1)
    one, other = (foreign, admin) if side == "A" else (reader, foreign)

    err = refused(capsys, world, one, other, f"run {side} is not a recording this version reads")

    assert "could not be counted" not in err and "zqx" not in err


@pytest.mark.parametrize("side", ["A", "B"])
def test_a_run_that_is_not_a_driver_run_with_an_unreadable_line_is_not_a_driver_run(
    world, capsys, tmp_path, side
):
    reader, admin = world.runs["twice"]
    source = reader if side == "A" else admin
    proxy = with_started(source, tmp_path, "p", mode="proxy")
    one, other = (proxy, admin) if side == "A" else (reader, proxy)

    err = refused(capsys, world, one, other, f"run {side} is not a driver run")

    assert "could not be counted" not in err and "zqx" not in err


@pytest.mark.parametrize("kind", UNREADABLE_LINES)
def test_the_last_line_that_cannot_be_read_is_compared_and_the_run_is_incomplete(
    world, capsys, tmp_path, kind
):
    reader, admin = world.runs["clean"]
    last = len((reader / "events.jsonl").read_bytes().splitlines()) - 1
    cut = with_line(reader, tmp_path, "c", {last: UNREADABLE_LINES[kind]})

    code, out, _ = compare(capsys, world, cut, admin)
    _, said, _ = compare(capsys, world, cut, admin, "--json")

    assert code == verdict.EXIT_INCOMPLETE
    assert out.startswith("run A: incomplete")
    document = json.loads(said)
    assert document["runs"]["a"]["state"] == "incomplete"
    assert "line" in document["runs"]["a"]["causes"]
    assert [row["step"] for row in document["calls"]] == [1, 2]


def test_an_unreadable_last_line_with_line_ends_behind_it_is_still_the_last(
    world, capsys, tmp_path
):
    reader, admin = world.runs["clean"]
    last = len((reader / "events.jsonl").read_bytes().splitlines()) - 1
    cut = with_line(reader, tmp_path, "c", {last: UNREADABLE_LINES["not JSON"]})
    path = cut / "events.jsonl"
    path.write_bytes(path.read_bytes() + b"\n\r\n  \n\n")

    code, _, _ = compare(capsys, world, cut, admin)
    _, said, _ = compare(capsys, world, cut, admin, "--json")

    assert code == verdict.EXIT_INCOMPLETE
    assert "line" in json.loads(said)["runs"]["a"]["causes"]


def test_two_lines_that_cannot_be_read_the_last_and_one_before_are_refused(world, capsys, tmp_path):
    reader, admin = world.runs["twice"]
    last = len((reader / "events.jsonl").read_bytes().splitlines()) - 1
    damaged = with_line(
        reader,
        tmp_path,
        "d",
        {first_call_line(reader): UNREADABLE_LINES["not JSON"], last: UNREADABLE_LINES["not JSON"]},
    )

    err = refused(capsys, world, damaged, admin, f"run A {LINE_REFUSAL}")

    assert "zqx" not in err
