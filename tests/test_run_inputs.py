"""What ``run_started`` records of a run besides the server and the scenario: ``inputs`` and the
reproduction triple, in every mode — and that no reader falls over a run outside a corpus."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, report, verdict
from mcp_kymograph.driver import DEFAULT_STEP_TIMEOUT
from mcp_kymograph.events import Mode
from mcp_kymograph.http_proxy import HttpProxy
from mcp_kymograph.masking import PLACEHOLDER, Masker
from mcp_kymograph.proxy import Limits, Proxy
from mcp_kymograph.recorder import Recorder
from mcp_kymograph.store import Store, StoreError
from mcp_kymograph.web import views
from mcp_kymograph.web.views import Sources
from test_cli_engagement import MANIFEST, write_engagement
from test_cli_phase_d import engaged_with_pattern
from test_report import build, filed  # noqa: F401  (``filed`` is the module's fixture)

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

DISCOVERY = FIXTURES / "discovery_server.py"
TOY = FIXTURES / "toy_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"

#: Keys whose values are the time or the run's name, and nothing else. ``duration_ns`` of
#: ``run_finished`` is a measured span of time, as ``t_ns`` is a point in it.
VOLATILE = {"t_ns", "duration_ns", "run_id", "wall_clock_utc"}


@pytest.fixture
def http_url():
    server = http_server.serve(0, variant="poison")
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
    finally:
        server.shutdown()
        server.server_close()


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def drive(out: Path, *args: str) -> list[dict]:
    code = cli.main(["drive", "-q", "--out-dir", str(out), *args])
    assert code == 0, code
    (path,) = out.glob("*/events.jsonl")
    return events_of(path)


def over_stdio(out: Path, *args: str) -> list[dict]:
    return drive(out, *args, "--", sys.executable, str(DISCOVERY))


def stable(value, *, racing: bool = False):
    """The recording without its time and its run id. ``racing`` is for the events of an HTTP
    run that is compared with another: it leaves out the ``seq`` of an event, because the write
    order of two exchanges in flight at once is a race and ``seq`` follows it, and the ``date``
    header of a response, which is the clock of the server. No other ``seq`` or ``date`` goes."""
    if isinstance(value, dict):
        leave = VOLATILE | {"seq"} if racing else VOLATILE
        kept = {k: stable(v) for k, v in value.items() if k not in leave}
        if racing and value.get("type") == "http_response" and "headers" in kept:
            kept["headers"] = {k: v for k, v in kept["headers"].items() if k.lower() != "date"}
        return kept
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


def by_exchange(events: list[dict]) -> dict[int | None, list[dict]]:
    """The events of an HTTP run by their ``exchange``, each in the order it was written in;
    the key ``None`` holds the events that belong to no exchange."""
    grouped: dict[int | None, list[dict]] = {}
    for event in events:
        grouped.setdefault(event.get("exchange"), []).append(stable(event, racing=True))
    return grouped


def assert_inputs(started: dict, *, step_timeout, mask_keys) -> None:
    assert started["inputs"] == {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": platform.platform(),
        "step_timeout": step_timeout,
        "mask_keys": mask_keys,
    }


def assert_unlisted_triple(started: dict, *, name: str | None, digest: str | None) -> None:
    triple = started["reproduction"]
    assert triple["manifest"] is None and triple["corpus"] is None
    assert triple["tool"]["version"] == started["tool_version"]
    assert set(triple["tool"]) == {"version", "content"}
    assert triple["scenario"] == {"name": name, "digest": digest}
    assert triple["environment"] == {
        "isolation": "host",
        "sandbox_image": None,
        "target_image": None,
    }


# -- the fields are there, in every mode -------------------------------------------------------


def test_a_driven_stdio_run_records_its_inputs_and_the_triple(tmp_path):
    started = over_stdio(
        tmp_path / "runs", "--step-timeout", "7", "--mask-key", "session", "--mask-key", "pin"
    )[0]

    assert_inputs(started, step_timeout=7.0, mask_keys=["session", "pin"])
    assert_unlisted_triple(started, name=None, digest=None)


def test_a_run_without_options_records_the_default_step_timeout_and_no_mask_keys(tmp_path):
    started = over_stdio(tmp_path / "runs")[0]

    assert started["inputs"]["step_timeout"] == DEFAULT_STEP_TIMEOUT
    assert started["inputs"]["mask_keys"] == []


def test_a_scenario_is_named_in_the_triple_with_its_digest(tmp_path):
    started = over_stdio(tmp_path / "runs", "--scenario", str(ALL_SIGNALS))[0]

    digest = started["authorization"]["scenario_digest"]
    assert digest and started["scenario_name"]
    assert_unlisted_triple(started, name=started["scenario_name"], digest=digest)


def test_a_driven_http_run_records_its_inputs_and_the_triple(tmp_path, http_url):
    started = drive(tmp_path / "runs", "--http", http_url, "--step-timeout", "9")[0]

    assert started["transport"] == "streamable-http"
    assert_inputs(started, step_timeout=9.0, mask_keys=[])
    assert_unlisted_triple(started, name=None, digest=None)


def test_the_stdio_proxy_records_its_inputs_without_a_step_timeout(tmp_path):
    path = tmp_path / "events.jsonl"

    async def scenario():
        read, write = os.pipe()
        os.close(write)  # the client has nothing to say
        with (
            os.fdopen(read, "rb", buffering=0) as client_in,
            open(os.devnull, "wb") as client_out,
            Recorder.open(path, run_id="proxy", masker=Masker()) as recorder,
        ):
            proxy = Proxy(
                argv=[sys.executable, str(TOY)],
                recorder=recorder,
                limits=Limits(max_duration_seconds=30.0, terminate_grace_seconds=0.5),
                client_in=client_in,
                client_out=client_out,
                inputs={"step_timeout": None, "mask_keys": ["session"]},
            )
            await asyncio.wait_for(proxy.run(), 30)

    asyncio.run(scenario())

    assert_inputs(events_of(path)[0], step_timeout=None, mask_keys=["session"])


def test_the_http_proxy_records_its_inputs(tmp_path, http_url):
    path = tmp_path / "events.jsonl"

    async def scenario():
        with Recorder.open(path, run_id="http", masker=Masker()) as recorder:
            proxy = HttpProxy(
                endpoint=http_url,
                recorder=recorder,
                limits=Limits(),
                mode=Mode.DRIVER,
                inputs={"step_timeout": None, "mask_keys": []},
            )
            settled = asyncio.Event()
            proxy.client_settled = settled

            async def converse():
                await proxy.launched.wait()
                settled.set()

            task = asyncio.create_task(converse())
            await proxy.run()
            await task

    asyncio.run(scenario())

    assert_inputs(events_of(path)[0], step_timeout=None, mask_keys=[])


def test_a_recorder_given_no_inputs_still_records_what_it_reads_itself(tmp_path):
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="r", masker=Masker()) as recorder:
        recorder.run_started(0, 0, argv=["srv"], limits={})

    assert_inputs(events_of(path)[0], step_timeout=None, mask_keys=[])


# -- no value of a mask key -------------------------------------------------------------------


def test_a_mask_key_with_a_value_is_refused_and_the_value_is_nowhere(tmp_path, capsys):
    secret = "val-" + "".join(["q7", "x2", "m9"])  # put together here, not written down
    out = tmp_path / "runs"

    code = cli.main(
        ["drive", "--out-dir", str(out), "--mask-key", f"session={secret}",
         "--", sys.executable, str(DISCOVERY)]
    )  # fmt: skip

    err = capsys.readouterr().err
    assert code == 2
    assert "--mask-key" in err and secret not in err
    assert not out.exists()
    assert not [p for p in tmp_path.rglob("*") if p.is_file() and secret in p.read_text()]


@pytest.mark.parametrize(
    "name",
    ["a b", "a\tb", "a\nb", "a\x00b", "k" * 65],
    ids=["blank", "tab", "newline", "nul", "too long"],
)
def test_a_mask_key_that_is_no_field_name_is_refused(tmp_path, name):
    out = tmp_path / "runs"

    code = cli.main(["drive", "-q", "--out-dir", str(out), "--mask-key", name, "--", "srv"])

    assert code == 2 and not out.exists()


def test_a_mask_key_refusal_under_an_engagement_file_writes_nothing(tmp_path):
    secret = "val-" + "".join(["q7", "x2", "m9"])
    held = write_engagement(tmp_path / "engagement")
    out = tmp_path / "runs"

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(out),
         "--mask-key", f"session={secret}", "--", sys.executable, str(DISCOVERY)]
    )  # fmt: skip

    assert code == 2 and not out.exists()  # no refusals.jsonl either


def test_a_name_of_the_longest_length_is_taken(tmp_path):
    name = "k" * 64
    started = over_stdio(tmp_path / "runs", "--mask-key", name)[0]

    assert started["inputs"]["mask_keys"] == [name]


def test_the_file_s_mask_keys_are_not_recorded_in_the_inputs(tmp_path):
    held = write_engagement(tmp_path / "engagement")  # its redaction holds ``customer_id``
    started = over_stdio(tmp_path / "runs", "--engagement", str(held), "--mask-key", "tenant")[0]

    assert started["inputs"]["mask_keys"] == ["tenant"]
    assert "customer_id" not in json.dumps(started["inputs"])


def test_the_proxy_command_records_its_mask_keys_and_no_step_timeout(tmp_path):
    out = tmp_path / "runs"
    read, write = os.pipe()
    os.close(write)  # the client has nothing to say
    saved = os.dup(0)
    os.dup2(read, 0)
    try:
        code = cli.main(
            ["run", "-q", "--out-dir", str(out), "--mask-key", "X", "--", sys.executable, str(TOY)]
        )
    finally:
        os.dup2(saved, 0)
        os.close(saved)
        os.close(read)

    assert code == 0, code
    (path,) = out.glob("*/events.jsonl")
    started = events_of(path)[0]
    assert started["inputs"]["mask_keys"] == ["X"]
    assert started["inputs"]["step_timeout"] is None
    assert_unlisted_triple(started, name=None, digest=None)


# -- the same run twice -----------------------------------------------------------------------


def test_the_same_run_twice_is_the_same_recording_over_stdio(tmp_path):
    first = over_stdio(tmp_path / "one", "--mask-key", "session")
    second = over_stdio(tmp_path / "two", "--mask-key", "session")

    assert stable(first) == stable(second)


def test_the_same_run_twice_is_the_same_recording_over_http(tmp_path, http_url):
    first = drive(tmp_path / "one", "--http", http_url)
    second = drive(tmp_path / "two", "--http", http_url)

    assert stable(first[0]) == stable(second[0])
    # Only how two exchanges interleave is free: each exchange, and the events that belong to
    # none (the findings, ``run_finished``), keep their order, and nothing is added or missing.
    assert by_exchange(first) == by_exchange(second)


# -- readers ----------------------------------------------------------------------------------


def test_a_reader_without_inputs_takes_a_recording_with_them_the_way_one_without_goes(tmp_path):
    recorded = over_stdio(tmp_path / "runs")
    older = json.loads(json.dumps(recorded))
    del older[0]["inputs"]

    assert verdict.judge(recorded).state == verdict.judge(older).state


def test_the_store_refuses_a_run_outside_a_corpus_in_its_own_words(tmp_path):
    over_stdio(tmp_path / "runs")
    (recording,) = (tmp_path / "runs").glob("*/events.jsonl")

    with (
        Store.open(tmp_path / "findings.sqlite") as store,
        pytest.raises(StoreError, match="ran outside a corpus; the store takes corpus runs only"),
    ):
        store.ingest(recording)


def test_the_web_interface_shows_a_run_outside_a_corpus(tmp_path):
    over_stdio(tmp_path / "runs", "--scenario", str(ALL_SIGNALS))
    sources = Sources(runs=tmp_path / "runs")

    (row,) = views.runs(sources)["data"]
    shown = views.run(sources, row["ref"])

    assert shown["data"]["server_version"] is None


def test_the_report_reads_recordings_whose_triple_has_no_manifest(filed, monkeypatch):  # noqa: F811
    # The store files corpus runs only, so a recording outside a corpus cannot be filed and
    # held against its digest; the recordings the report reads are the filed ones, with the
    # triple of a run outside a corpus put in their ``run_started``.
    read = report._read_recordings

    def outside(store, runs, runs_dir):
        recordings = read(store, runs, runs_dir)
        for recording in recordings.values():
            assert recording.state == "read"
            recording.started["reproduction"]["manifest"] = None
            recording.started["reproduction"]["corpus"] = None
        return recordings

    monkeypatch.setattr(report, "_read_recordings", outside)

    text = report.render(build(filed))

    assert "the manifest is not known: the run ran outside a corpus" in text
    assert "the recording was not read" not in text
    assert "None" not in text.replace("None of", "")


# -- the refusal holds for every command with the option --------------------------------------


def test_evidence_redact_refuses_a_mask_key_with_a_value_and_writes_nothing(tmp_path, capsys):
    secret = "val-" + "".join(["q7", "x2", "m9"])
    out = tmp_path / "handover"

    code = cli.main(
        ["evidence", "redact", str(tmp_path / "bundle"), "--engagement", str(tmp_path / "e.json"),
         "--store", str(tmp_path / "s.db"), "--mask-key", f"session={secret}", "--out", str(out)]
    )  # fmt: skip

    err = capsys.readouterr().err
    assert code == 2
    assert "--mask-key" in err and secret not in err
    assert not out.exists()
    assert not [p for p in tmp_path.rglob("*") if p.is_file() and secret in p.read_text()]


def test_evidence_redact_refuses_a_mask_key_of_special_characters_and_an_equals_sign(
    tmp_path, capsys
):
    value = "=" + "".join(["!", "?", "#"])
    out = tmp_path / "handover"

    code = cli.main(
        ["evidence", "redact", str(tmp_path / "bundle"), "--engagement", str(tmp_path / "e.json"),
         "--store", str(tmp_path / "s.db"), "--mask-key", value, "--out", str(out)]
    )  # fmt: skip

    err = capsys.readouterr().err
    assert code == 2
    assert "--mask-key" in err and value not in err
    assert not out.exists()


def _parsers_with_mask_key(parser, path=()):
    """Every (path, parser) below ``parser`` that offers ``--mask-key``, found by walking."""
    found = []
    if any("--mask-key" in action.option_strings for action in parser._actions):
        found.append((path, parser))
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                found.extend(_parsers_with_mask_key(sub, (*path, name)))
    return found


def _argv_for(path, parser):
    """The command line of ``path`` with every required argument given a placeholder."""
    argv = list(path)
    for action in parser._actions:
        if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):
            continue
        if not action.option_strings:
            argv.append("x")
        elif action.required:
            argv.extend([action.option_strings[0], "x"])
    return argv


def test_every_command_with_a_mask_key_refuses_a_name_with_an_equals_sign(capsys):
    found = _parsers_with_mask_key(cli.build_parser())

    assert {path for path, _ in found} >= {("drive",), ("run",), ("evidence", "redact")}
    for path, parser in found:
        code = cli.main([*_argv_for(path, parser), "--mask-key", "x=y"])

        err = capsys.readouterr().err
        assert code == 2, path
        assert "--mask-key" in err and "x=y" not in err, path


@pytest.mark.parametrize("name", ["!?#", "---", ".."])
def test_every_command_with_a_mask_key_refuses_a_name_without_letter_or_digit(
    tmp_path, capsys, monkeypatch, name
):
    monkeypatch.chdir(tmp_path)
    for path, parser in _parsers_with_mask_key(cli.build_parser()):
        code = cli.main([*_argv_for(path, parser), f"--mask-key={name}"])  # "---" is no value

        err = capsys.readouterr().err
        assert code == 2, path
        assert err.count("\n") == 1 and "--mask-key" in err and name not in err, path
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]


@pytest.mark.parametrize("name", ["пароль", "é", "ß", "μ", "²", "日本"])
def test_every_command_with_a_mask_key_refuses_a_name_normalise_key_empties(
    tmp_path, capsys, monkeypatch, name
):
    monkeypatch.chdir(tmp_path)
    for path, parser in _parsers_with_mask_key(cli.build_parser()):
        code = cli.main([*_argv_for(path, parser), "--mask-key", name])

        captured = capsys.readouterr()
        assert code == 2, path
        assert captured.err.count("\n") == 1 and "--mask-key" in captured.err, path
        assert name not in captured.out and name not in captured.err, path
    assert not [p for p in tmp_path.rglob("*") if p.is_file() and name in p.read_text()]


def test_evidence_redact_refuses_a_non_ascii_mask_key_in_its_own_words_not_evidence_s(
    tmp_path, capsys
):
    # A valid store and bundle: without the check in ``cli`` the call would reach ``evidence``.
    held, _, database, bundle = engaged_with_pattern(tmp_path, capsys)
    name = "пароль"
    out = tmp_path / "handover"

    code = cli.main(
        ["evidence", "redact", str(bundle), "--engagement", str(held), "--store", str(database),
         "--mask-key", name, "--out", str(out)]
    )  # fmt: skip

    err = capsys.readouterr().err
    assert code == 2
    assert "--mask-key" in err and name not in err and "has no letter or digit" not in err
    assert not out.exists()


def test_the_mask_key_refusal_names_the_rule_as_an_ascii_letter_or_digit(capsys):
    code = cli.main(["drive", "--mask-key", "пароль"])

    assert code == 2
    assert "an ASCII letter or digit" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["x-1", "Ä1", "\N{KELVIN SIGN}"])
def test_a_name_normalise_key_does_not_empty_is_taken(tmp_path, name):
    started = over_stdio(tmp_path / "runs", "--mask-key", name)[0]

    assert started["inputs"]["mask_keys"] == [name]


@pytest.mark.parametrize(
    "argv",
    [
        ["drive", "--ma=session=abc123"],
        ["run", "--mas=a=b"],
        ["drive", "--mask=session=abc123"],
        ["drive", "--mask-k=session=abc123"],
    ],
)
def test_an_abbreviated_mask_key_with_an_equals_sign_is_refused_without_the_value(
    tmp_path, capsys, argv
):
    out = tmp_path / "runs"

    code = cli.main([*argv, "--out-dir", str(out), "--", "srv"])

    err = capsys.readouterr().err
    assert code == 2
    assert err.count("\n") == 1 and "--mask-key" in err
    assert "session" not in err and "abc123" not in err and "a=b" not in err
    assert not out.exists()


def test_the_scan_for_an_abbreviated_mask_key_stops_at_the_separator():
    ours, _ = cli.split_server_command(["drive", "--", "--mas=a=b"])

    assert not cli._abbreviated_mask_key_with_value(ours)


@pytest.mark.parametrize(
    "arg", ["--max-duration", "--max-message-bytes=100", "--mask-key=a", "--m=x", "--mask-key"]
)
def test_other_options_are_no_abbreviated_mask_key(arg):
    assert not cli._abbreviated_mask_key_with_value(["drive", arg, "5"])


def test_a_mask_key_refusal_is_shown_with_q_too(tmp_path, capsys):
    code = cli.main(
        [
            "drive",
            "-q",
            "--out-dir",
            str(tmp_path / "runs"),
            "--mask-key",
            "k=secretish",
            "--",
            "srv",
        ]
    )

    err = capsys.readouterr().err
    assert code == 2
    assert err.count("\n") == 1 and "--mask-key" in err and "secretish" not in err


# -- a name that passes for a field name is not kept as typed ---------------------------------


def a_key_and_a_token() -> dict[str, str]:
    """Values of the shapes the masker knows, put together here and written down nowhere."""
    return {
        "an AWS key": "AKIA" + "ABCDEFGHIJKLMNOP",
        "an sk- token": "sk-" + "".join(["q7x2", "m9k4", "w8z1", "p3r5", "t6y0"]),
    }


@pytest.mark.parametrize("kind", ["an AWS key", "an sk- token"])
def test_a_mask_key_that_is_a_value_is_masked_in_the_inputs_and_is_nowhere_else(
    tmp_path, capsys, kind
):
    value = a_key_and_a_token()[kind]

    started = over_stdio(tmp_path / "runs", "--mask-key", value)[0]

    seen = capsys.readouterr()
    assert value not in seen.out and value not in seen.err
    assert started["inputs"]["mask_keys"] == [PLACEHOLDER]
    assert not [p for p in tmp_path.rglob("*") if p.is_file() and value in p.read_text()]

    # without ``-q`` the run says more on stdout and stderr; the value is not in that either
    loud = tmp_path / "loud"
    code = cli.main(
        ["drive", "--out-dir", str(loud), "--mask-key", value, "--", sys.executable, str(DISCOVERY)]
    )
    assert code == 0, code
    seen = capsys.readouterr()
    assert value not in seen.out and value not in seen.err
    (path,) = loud.glob("*/events.jsonl")
    assert events_of(path)[0]["inputs"]["mask_keys"] == [PLACEHOLDER]


def test_an_ordinary_field_name_is_recorded_as_typed(tmp_path):
    started = over_stdio(tmp_path / "runs", "--mask-key", "session", "--mask-key", "x-api-key")[0]

    assert started["inputs"]["mask_keys"] == ["session", "x-api-key"]


def test_a_recorder_masks_the_mask_keys_it_is_given(tmp_path):
    value = a_key_and_a_token()["an AWS key"]
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="r", masker=Masker()) as recorder:
        recorder.run_started(
            0, 0, argv=["srv"], limits={}, inputs={"mask_keys": [value, "session"]}
        )

    names = events_of(path)[0]["inputs"]["mask_keys"]
    assert value not in path.read_text()
    assert names == [PLACEHOLDER, "session"]


def test_a_mask_key_with_a_colon_is_refused_and_the_value_is_nowhere(tmp_path, capsys):
    secret = "val-" + "".join(["q7", "x2", "m9"])
    out = tmp_path / "runs"

    code = cli.main(
        ["drive", "--out-dir", str(out), "--mask-key", f"session:{secret}",
         "--", sys.executable, str(DISCOVERY)]
    )  # fmt: skip

    err = capsys.readouterr().err
    assert code == 2
    assert "--mask-key" in err and secret not in err
    assert not out.exists()


def test_evidence_redact_refuses_a_mask_key_with_a_colon_and_writes_nothing(tmp_path, capsys):
    held, _, database, bundle = engaged_with_pattern(tmp_path, capsys)
    secret = "val-" + "".join(["q7", "x2", "m9"])
    out = tmp_path / "handover"

    code = cli.main(
        ["evidence", "redact", str(bundle), "--engagement", str(held), "--store", str(database),
         "--mask-key", f"session:{secret}", "--out", str(out)]
    )  # fmt: skip

    err = capsys.readouterr().err
    assert code == 2
    assert "--mask-key" in err and secret not in err
    assert not out.exists()


def test_the_mask_key_refusal_names_the_colon(capsys):
    code = cli.main(["drive", "--mask-key", "a:b"])

    assert code == 2
    assert "':'" in capsys.readouterr().err


# -- a run from the corpus --------------------------------------------------------------------


def test_a_run_from_the_corpus_records_its_inputs_and_the_triple_of_the_manifest(tmp_path):
    held = write_engagement(tmp_path / "engagement")
    out = tmp_path / "runs"

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--manifest", str(MANIFEST), "--entry",
         "reference-server", "--isolation", "host", "--out-dir", str(out)]
    )  # fmt: skip

    assert code == 0, code
    (path,) = out.glob("*/events.jsonl")
    started = events_of(path)[0]
    assert_inputs(started, step_timeout=DEFAULT_STEP_TIMEOUT, mask_keys=[])
    triple = started["reproduction"]
    assert triple["manifest"] is not None and triple["corpus"] is not None
    assert triple["tool"]["version"] == started["tool_version"]
    assert triple["scenario"] is not None
    assert triple["environment"]["isolation"] == "host"
