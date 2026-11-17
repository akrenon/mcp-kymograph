"""A URL's path in a record: written only when the engagement file lists it for the target the run
matched, or, without a file, when the host is a loopback literal. Otherwise the record holds the
path's SHA-256 and length, and the terminal shows the path whole.

The segment the tests put in a path is joined at run time and is not a credential; it stands for
one that no rule would catch by its shape.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from mcp_kymograph import cli, corpus, engagement
from mcp_kymograph.masking import PLACEHOLDER, Masker, withheld_path, withhold_url_path
from mcp_kymograph.recorder import Recorder
from mcp_kymograph.store import Store
from test_cli_engagement import events_of, recording_in, refusals_in, write_engagement
from test_http_tls import SECOND_ADDRESS, serve, trust_ca  # noqa: F401

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"

import http_server  # noqa: E402

__all__ = ["serve", "trust_ca"]

#: Where a customer's tenant name sits in a URL; nothing a masking rule knows by its shape.
SEGMENT = "tenant-" + "Zq7w" + "Xk29" + "Lm4p"
PATH = f"/{SEGMENT}/mcp"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def everything_under(directory: Path) -> bytes:
    return b"".join(path.read_bytes() for path in sorted(directory.rglob("*")) if path.is_file())


def recorder(*verbatim: str) -> tuple[Recorder, io.StringIO]:
    """A recorder whose run may write ``verbatim`` as they are on ``https://h``."""
    stream = io.StringIO()
    paths = [("h", 443, path) for path in verbatim]
    return Recorder(stream, run_id="r", masker=Masker(), verbatim_paths=paths), stream


def started(stream: io.StringIO) -> dict:
    return next(
        json.loads(line)
        for line in stream.getvalue().splitlines()
        if json.loads(line)["type"] == "run_started"
    )


def requested(stream: io.StringIO) -> dict:
    return next(
        json.loads(line)
        for line in stream.getvalue().splitlines()
        if json.loads(line)["type"] == "http_request"
    )


# -- the words and the masker -------------------------------------------------------------------


def test_withheld_path_names_the_digest_and_the_length_and_nothing_of_the_path():
    said = withheld_path(PATH)

    assert said == f"<path withheld: sha256 {sha(PATH)}, {len(PATH)} characters>"
    assert SEGMENT not in said


def test_an_argument_that_is_a_url_has_its_path_withheld_unless_it_is_verbatim():
    masker = Masker()
    argv = ["kymograph", "--http", f"https://h.example:8443{PATH}?a=1", "--x=" + "y"]

    withheld, _ = masker.mask_argv(argv)
    verbatim, _ = masker.mask_argv(argv, verbatim_paths=[("h.example", 8443, PATH)])

    assert withheld[2] == f"https://h.example:8443{withheld_path(PATH)}?a=1"
    assert SEGMENT not in " ".join(withheld)
    assert verbatim[2] == f"https://h.example:8443{PATH}?a=1"


def test_the_same_path_on_another_host_or_port_is_withheld_in_text():
    pair = [("127.0.0.1", 9, PATH)]
    near = f"http://127.0.0.1:9{PATH}"
    far = f"https://far.example{PATH}"
    other_port = f"http://127.0.0.1:10{PATH}"
    shouted = f"HTTP://127.0.0.1:9{PATH}"

    assert withhold_url_path(near, pair) == near
    assert withhold_url_path(shouted, pair) == shouted, "the host and scheme compare lower case"
    assert withhold_url_path(far, pair) == f"https://far.example{withheld_path(PATH)}"
    assert withhold_url_path(other_port, pair) == f"http://127.0.0.1:10{withheld_path(PATH)}"
    # No port is the scheme's: 80 here, which is not 9.
    assert withhold_url_path(f"http://127.0.0.1{PATH}", pair).endswith(withheld_path(PATH))
    assert withhold_url_path(f"http://h.example{PATH}", [("h.example", 80, PATH)]) == (
        f"http://h.example{PATH}"
    )
    argv = ["kymograph", "--a", near, "--b", far]
    masked, _ = Masker().mask_argv(argv, verbatim_paths=pair)
    assert masked[2] == near and masked[4] == f"https://far.example{withheld_path(PATH)}"


def test_a_flag_s_url_value_and_a_text_that_is_no_url_are_handled_as_they_read():
    assert withhold_url_path(f"--http=http://127.0.0.1:9{PATH}") == (
        f"--http=http://127.0.0.1:9{withheld_path(PATH)}"
    )
    assert withhold_url_path("localhost:8080") == "localhost:8080"
    # A URL starts wherever its scheme stands; what is in front of it stays.
    assert withhold_url_path(f"see https://h.example{PATH}") == (
        f"see https://h.example{withheld_path(PATH)}"
    )


def test_the_text_rules_still_see_the_url_whose_path_is_withheld():
    user, password = "reader77", "s3cret" + "Value123"
    argv = ["kymograph", f"https://{user}:{password}@h.example{PATH}"]

    masked, hits = Masker().mask_argv(argv)

    assert user not in masked[1] and password not in masked[1] and SEGMENT not in masked[1]
    assert masked[1].endswith(withheld_path(PATH)) and hits == 1


def test_an_empty_path_holds_nothing_and_is_written_as_it_is():
    assert withhold_url_path("https://h.example?a=1") == "https://h.example?a=1"
    kept, stream = recorder()
    kept.run_started(
        0, 0, argv=["s"], limits={}, transport="streamable-http", endpoint="https://h.example"
    )
    assert started(stream)["endpoint"]["path"] == ""


# -- the recorder -------------------------------------------------------------------------------


def test_the_recorder_writes_an_endpoint_s_path_only_when_it_is_verbatim():
    kept, stream = recorder(PATH)
    kept.run_started(
        0, 0, argv=["s"], limits={}, transport="streamable-http", endpoint=f"https://h{PATH}"
    )
    assert started(stream)["endpoint"]["path"] == PATH
    assert "path_sha256" not in started(stream)["endpoint"]

    held, stream = recorder()
    held.run_started(
        0, 0, argv=["s"], limits={}, transport="streamable-http", endpoint=f"https://h{PATH}?q=1"
    )
    endpoint = started(stream)["endpoint"]
    assert endpoint["path"] is None
    assert endpoint["path_sha256"] == sha(PATH)
    assert endpoint["path_length"] == len(PATH)
    assert endpoint["query"] == {"q": "1"}, "the query is masked as it was, verbatim path or not"
    assert SEGMENT not in stream.getvalue()


@pytest.mark.parametrize("target", [PATH + "?q=1", f"https://h{PATH}?q=1"])
def test_every_request_target_is_written_by_the_same_rule(target):
    held, stream = recorder()
    held.run_started(
        0, 0, argv=["s"], limits={}, transport="streamable-http", endpoint="https://h/mcp"
    )
    held.http_request(1, 1, exchange=1, connection=1, method="POST", target=target, headers=[])
    kept, kept_stream = recorder(PATH)
    kept.run_started(
        0, 0, argv=["s"], limits={}, transport="streamable-http", endpoint="https://h/mcp"
    )
    kept.http_request(1, 1, exchange=1, connection=1, method="POST", target=target, headers=[])

    written = requested(stream)["target"]
    assert written["path"] is None and written["path_sha256"] == sha(PATH)
    assert written["path_length"] == len(PATH)
    assert SEGMENT not in stream.getvalue()
    assert requested(kept_stream)["target"]["path"] == PATH


def test_the_same_path_on_another_host_or_port_is_withheld_by_the_recorder():
    # An origin-form target is the run's endpoint's; an absolute-form one has a host of its own.
    cases = [
        (f"https://h{PATH}", PATH),  # the pair itself
        (f"https://other{PATH}", PATH),  # another host, the run's endpoint
        (f"https://h:8443{PATH}", PATH),  # another port, the run's endpoint
        (f"https://h{PATH}", "https://other" + PATH),
        (f"https://h{PATH}", "https://h:8443" + PATH),
    ]
    written = []
    for endpoint, target in cases:
        kept, stream = recorder(PATH)
        kept.run_started(
            0, 0, argv=["s"], limits={}, transport="streamable-http", endpoint=endpoint
        )
        kept.http_request(1, 1, exchange=1, connection=1, method="POST", target=target, headers=[])
        written.append((started(stream)["endpoint"]["path"], requested(stream)["target"]["path"]))

    assert written == [(PATH, PATH), (None, None), (None, None), (PATH, None), (PATH, None)]


def test_a_request_before_any_endpoint_has_no_host_and_its_path_is_withheld():
    kept, stream = recorder(PATH)
    kept.http_request(1, 1, exchange=1, connection=1, method="POST", target=PATH, headers=[])

    assert requested(stream)["target"]["path"] is None
    assert SEGMENT not in stream.getvalue()


# -- the command line ---------------------------------------------------------------------------


def test_a_path_the_file_does_not_list_is_refused_whole_on_the_terminal_and_withheld_in_the_record(
    tmp_path, capsys
):
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "127.0.0.1", "ports": [9], "paths": ["/mcp"]}]
    )
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--http", f"http://127.0.0.1:9{PATH}",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    assert SEGMENT in capsys.readouterr().err, "the terminal shows the path in full"
    (record,) = refusals_in(out_dir)
    assert record.reason == "path_not_listed"
    assert withheld_path(PATH) in record.message
    assert withheld_path(PATH) in " ".join(record.command), "the command line is rewritten too"
    assert SEGMENT.encode() not in everything_under(out_dir)


def test_a_url_that_cannot_be_taken_apart_is_not_quoted_in_the_record(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"

    # The command line's own checks pass it (a host, a port, a path); the gate's reading of a
    # host name is narrower, and `~` is not in it. That `_url_reach` is what refused it is
    # shown by the reason and the words.
    code = cli.main(
        ["drive", "--engagement", str(held), "--http", f"https://h~x.example:8443{PATH}",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert "cannot be taken apart into host, port and path" in said
    assert SEGMENT in said, "the terminal quotes the URL"
    (record,) = refusals_in(out_dir)
    assert record.reason == "target_not_listed"
    assert "cannot be taken apart into host, port and path" in record.message
    assert "the URL given" in record.message
    assert SEGMENT.encode() not in everything_under(out_dir)


def test_a_listed_path_stays_verbatim_in_the_recording(tmp_path):
    served = http_server.serve(0, "127.0.0.1")
    try:
        port = served.server_address[1]
        held = write_engagement(
            tmp_path / "engagement",
            targets=[{"host": "127.0.0.1", "ports": [port], "paths": [PATH]}],
        )
        out_dir = tmp_path / "runs"
        code = cli.main(
            ["drive", "-q", "--engagement", str(held), "--http", f"http://127.0.0.1:{port}{PATH}",
             "--out-dir", str(out_dir)]
        )  # fmt: skip
    finally:
        served.shutdown()
        served.server_close()

    assert code in (0, cli.EXIT_INCOMPLETE, cli.EXIT_SERVER_FAILED)
    events = events_of(recording_in(out_dir))
    (first,) = [e for e in events if e["type"] == "run_started"]
    assert first["endpoint"]["path"] == PATH
    assert all("path_sha256" not in e["target"] for e in events if e["type"] == "http_request")


def test_a_loopback_target_the_file_lists_without_paths_has_no_listed_path(tmp_path):
    served = http_server.serve(0, "127.0.0.1")
    try:
        port = served.server_address[1]
        held = write_engagement(
            tmp_path / "engagement", targets=[{"host": "127.0.0.1", "ports": [port]}]
        )
        out_dir = tmp_path / "runs"
        cli.main(
            ["drive", "-q", "--engagement", str(held), "--http", f"http://127.0.0.1:{port}{PATH}",
             "--out-dir", str(out_dir)]
        )  # fmt: skip
    finally:
        served.shutdown()
        served.server_close()

    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    assert first["endpoint"]["path"] is None
    assert first["endpoint"]["path_sha256"] == sha(PATH)
    assert SEGMENT.encode() not in everything_under(out_dir)


def test_without_a_file_a_loopback_path_is_verbatim(tmp_path):
    served = http_server.serve(0, "127.0.0.1")
    try:
        port = served.server_address[1]
        out_dir = tmp_path / "runs"
        cli.main(
            ["drive", "-q", "--http", f"http://127.0.0.1:{port}{PATH}", "--out-dir", str(out_dir)]
        )
    finally:
        served.shutdown()
        served.server_close()

    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    assert first["endpoint"]["path"] == PATH


def test_without_a_file_a_path_on_another_host_is_withheld_everywhere(
    tmp_path,
    trust_ca,
    serve,
    capsys,
):
    port = serve("127.0.0.2", tls=SECOND_ADDRESS)
    out_dir = tmp_path / "runs"

    cli.main(["drive", "--http", f"https://127.0.0.2:{port}{PATH}", "--out-dir", str(out_dir)])

    said = capsys.readouterr().err
    events = events_of(recording_in(out_dir))
    (first,) = [e for e in events if e["type"] == "run_started"]
    endpoint = first["endpoint"]
    assert endpoint["path"] is None and endpoint["path_sha256"] == sha(PATH)
    requests = [e for e in events if e["type"] == "http_request"]
    assert requests and all(e["target"]["path"] is None for e in requests)
    assert SEGMENT.encode() not in everything_under(out_dir)
    assert said, "the terminal still says what happened"


def test_a_declared_target_that_is_a_url_has_its_path_withheld_in_the_authorization(tmp_path):
    out_dir = tmp_path / "runs"
    toy = str(FIXTURES / "toy_server.py")

    cli.main(
        ["drive", "-q", "--target", f"https://h.example{PATH}", "--out-dir", str(out_dir),
         "--", sys.executable, toy]
    )  # fmt: skip

    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    declared = first["authorization"]["declared_target"]
    assert declared == f"https://h.example{withheld_path(PATH)}"
    assert SEGMENT.encode() not in everything_under(out_dir)


def test_the_engagement_module_still_builds_the_words_twice():
    refused = engagement.EngagementRefused("path_not_listed", "full", "recorded")

    assert str(refused) == "path_not_listed: full"
    assert refused.recorded == "path_not_listed: recorded"
    assert engagement.EngagementRefused("draft", "same").recorded == "draft: same"


# -- a brace in a path --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("listed", "asked"),
    [
        ("/api/{tenant}", "/other"),
        ("/x{}", "/x"),
        ("/x}", "/x{"),
        ("/mcp", "/a{b"),
        ("/mcp", "/{}"),
        ("/api/{tenant}", "/api/{tenant}/{0}"),
    ],
)
def test_a_brace_in_a_listed_or_asked_path_is_a_refusal_and_not_a_crash(
    tmp_path, capsys, listed, asked
):
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "127.0.0.1", "ports": [9], "paths": [listed]}]
    )
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--http", f"http://127.0.0.1:9{asked}",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    assert asked in capsys.readouterr().err, "the terminal shows the path whole, braces too"
    (record,) = refusals_in(out_dir)
    assert record.reason == "path_not_listed"
    assert withheld_path(asked) in record.message
    assert listed in record.message, "the file's own words stay in the record"


def test_a_url_with_braces_that_cannot_be_taken_apart_is_refused_too(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--http", "https://h{}x.example:8443/{x}{}",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    assert "https://h{}x.example:8443/{x}{}" in capsys.readouterr().err
    (record,) = refusals_in(out_dir)
    assert record.reason == "target_not_listed"
    assert "the URL given cannot be taken apart" in record.message


# -- the server's own command line --------------------------------------------------------------


def stdio_argv(tmp_path, url, *, held=None):
    out_dir = tmp_path / "runs"
    file = [] if held is None else ["--engagement", str(held)]
    cli.main(
        ["drive", "-q", *file, "--out-dir", str(out_dir), "--",
         sys.executable, str(FIXTURES / "toy_server.py"), "--tool-desc", url]
    )  # fmt: skip
    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    return first["argv"], out_dir


def test_a_url_in_the_server_s_command_line_has_its_path_withheld_in_run_started(tmp_path):
    argv, out_dir = stdio_argv(tmp_path, f"https://h.example{PATH}")

    assert argv[-1] == f"https://h.example{withheld_path(PATH)}"
    assert SEGMENT.encode() not in everything_under(out_dir)


def test_a_loopback_url_in_the_server_s_command_line_keeps_its_path_without_a_file(tmp_path):
    argv, _ = stdio_argv(tmp_path, f"http://127.0.0.1:9{PATH}")

    assert argv[-1] == f"http://127.0.0.1:9{PATH}"


def two_url_run(tmp_path, *urls, target=None):
    """A stdio run whose server command holds ``urls`` (the server exits at once; the record is
    what is looked at): its ``run_started`` and the out-dir."""
    out_dir = tmp_path / "runs"
    flag = [] if target is None else ["--target", target]
    cli.main(
        ["drive", "-q", *flag, "--out-dir", str(out_dir), "--", sys.executable, "-c", "pass", *urls]
    )  # fmt: skip
    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    return first, out_dir


def test_a_loopback_path_and_the_same_path_on_a_far_host_are_told_apart_in_run_started(tmp_path):
    near, far = f"http://127.0.0.1:9{PATH}", f"https://far.example{PATH}"

    first, out_dir = two_url_run(tmp_path, near, far)

    assert first["argv"][-2:] == [near, f"https://far.example{withheld_path(PATH)}"]
    assert everything_under(out_dir).count(SEGMENT.encode()) == 1, "only the loopback one"


@pytest.mark.parametrize(
    "target, said",
    [
        (f"https://far.example{PATH}", f"https://far.example{withheld_path(PATH)}"),
        (f"http://127.0.0.1:10{PATH}", f"http://127.0.0.1:10{withheld_path(PATH)}"),
        (f"http://127.0.0.1:9{PATH}", f"http://127.0.0.1:9{PATH}"),
    ],
)
def test_a_declared_target_keeps_its_path_only_as_the_pair_the_run_has(tmp_path, target, said):
    first, _ = two_url_run(tmp_path, f"http://127.0.0.1:9{PATH}", target=target)

    assert first["authorization"]["declared_target"] == said


def test_verbatim_url_paths_holds_the_host_and_the_effective_port():
    held = cli.verbatim_url_paths(
        None,
        None,
        f"http://127.0.0.1:9{PATH}",
        ["s", f"--u=HTTP://[::1]{PATH}", f"https://x{PATH}"],
    )

    assert held == (("127.0.0.1", 9, PATH), ("::1", 80, PATH))


def test_under_a_file_no_path_in_the_server_s_command_line_is_verbatim(tmp_path):
    held = write_engagement(tmp_path / "engagement")

    argv, out_dir = stdio_argv(tmp_path, f"http://127.0.0.1:9{PATH}", held=held)

    assert argv[-1] == f"http://127.0.0.1:9{withheld_path(PATH)}"
    assert SEGMENT.encode() not in everything_under(out_dir)


def test_the_launch_digest_is_not_computed_from_the_recorded_argv(tmp_path):
    """A corpus entry whose command holds a URL: the digest is that of the command as written,
    in the manifest, the recording and the store, while the recorded argv is the withheld form."""
    url = f"https://h.example{PATH}"
    written = ["{python}", "{dir}/toy_server.py", "--tool-desc", url]
    manifest = tmp_path / "corpus" / "manifest.json"
    manifest.parent.mkdir()
    (manifest.parent / "toy_server.py").write_bytes((FIXTURES / "toy_server.py").read_bytes())
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "toy",
                        "provenance": "reference",
                        "source": {"paths": ["toy_server.py"]},
                        "launch": {"transport": "stdio", "command": written},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, manifest.parent)],
                    }
                ],
            }
        )
    )
    (entry,) = corpus.load(manifest).entries
    launch = json.dumps({"transport": "stdio", "command": written}, ensure_ascii=True)
    digest = "sha256:" + sha(launch)
    assert entry.launch_digest == digest, "the digest is of the command as written"
    out_dir = tmp_path / "runs"

    cli.main(
        ["drive", "-q", "--manifest", str(manifest), "--entry", "toy", "--isolation", "host",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    recording = recording_in(out_dir)
    (first,) = [e for e in events_of(recording) if e["type"] == "run_started"]
    assert first["argv"][-1] == f"https://h.example{withheld_path(PATH)}"
    assert first["reproduction"]["corpus"]["launch_digest"] == digest
    database = tmp_path / "findings.sqlite"
    cli.main(["store", "ingest", "-q", "--store", str(database), str(recording)])
    with Store.open_read_only(database) as store:
        (run,) = store.runs()
    assert run.launch_digest == digest
    assert SEGMENT.encode() not in database.read_bytes()


# -- the entry the gate meets -------------------------------------------------------------------


def two_entries(port):
    return [
        {"host": "127.0.0.1", "ports": [port], "paths": ["/x"], "isolation": "runc"},
        {"host": "127.0.0.1", "ports": [port]},
    ]


def test_matched_target_is_the_entry_check_lets_the_run_through_on(tmp_path):
    held = engagement.load(write_engagement(tmp_path / "engagement", targets=two_entries(9)))
    facts = engagement.GateFacts(command="drive", http_url="http://127.0.0.1:9/x")
    now = datetime.now(timezone.utc)

    engagement.check(held, facts, now)
    matched = engagement.matched_target(held, facts)

    assert matched is held.targets[1], "the first entry is dropped by its isolation floor"
    assert matched.paths is None
    assert engagement.matched_target(held, engagement.GateFacts(command="drive")) is None
    assert cli.verbatim_url_paths(held, facts, facts.http_url) == ()


def test_the_path_stays_withheld_when_the_gate_met_another_entry_than_the_one_listing_it(tmp_path):
    served = http_server.serve(0, "127.0.0.1")
    try:
        port = served.server_address[1]
        held = write_engagement(tmp_path / "engagement", targets=two_entries(port))
        out_dir = tmp_path / "runs"
        cli.main(
            ["drive", "-q", "--engagement", str(held), "--http", f"http://127.0.0.1:{port}/x",
             "--out-dir", str(out_dir)]
        )  # fmt: skip
    finally:
        served.shutdown()
        served.server_close()

    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    assert first["endpoint"]["path"] is None
    assert first["endpoint"]["path_sha256"] == sha("/x")
    requests = [e for e in events_of(recording_in(out_dir)) if e["type"] == "http_request"]
    assert requests and all(e["target"]["path"] is None for e in requests)


# -- store, bundle and report -------------------------------------------------------------------


def endpoint_manifest(directory: Path, **urls: str) -> Path:
    """A corpus manifest with one endpoint entry per ``name=url``."""
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": name,
                        "provenance": "reference",
                        "source": {"endpoint": url},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, directory)],
                    }
                    for name, url in urls.items()
                ],
            }
        )
    )
    return manifest


def test_a_refused_path_is_nowhere_in_the_store_the_bundle_or_the_report(tmp_path, capsys):
    served = http_server.serve(0, "127.0.0.1")
    try:
        port = served.server_address[1]
        listed = http_server.PATH
        # The refused entry sits in a manifest of its own: a filed run names the first one only,
        # so the bundle copies nothing that holds the segment because the operator wrote it.
        good = endpoint_manifest(tmp_path / "good", good=f"http://127.0.0.1:{port}{listed}")
        bad = endpoint_manifest(tmp_path / "bad", bad=f"http://127.0.0.1:{port}{PATH}")
        held = write_engagement(
            tmp_path / "engagement",
            targets=[{"host": "127.0.0.1", "ports": [port], "paths": [listed]}],
        )
        runs = tmp_path / "runs"
        asked = ["--engagement", str(held), "--out-dir", str(runs)]
        code = cli.main(["drive", "-q", "--manifest", str(good), "--entry", "good", *asked])
        assert code in (0, cli.EXIT_INCOMPLETE, cli.EXIT_SERVER_FAILED)
        capsys.readouterr()
        assert cli.main(["drive", "--manifest", str(bad), "--entry", "bad", *asked]) == 2
        on_stderr = capsys.readouterr().err
    finally:
        served.shutdown()
        served.server_close()

    assert SEGMENT in on_stderr, "the terminal shows the path in full"
    (record,) = refusals_in(runs)
    assert record.reason == "path_not_listed" and withheld_path(PATH) in record.message
    store, report, bundle = tmp_path / "findings.sqlite", tmp_path / "report.md", tmp_path / "pack"
    (recording,) = runs.glob("*/events.jsonl")
    steps = [
        ["store", "ingest", "-q", "--store", store, "--engagement", held, recording],
        ["report", "--engagement", held, "--store", store, "--runs", runs, "--manifest", good,
         "--out-dir", runs, "--out", report],
        ["evidence", "pack", "-q", "--engagement", held, "--store", store, "--runs", runs,
         "--manifest", good, "--report", report, "--out", bundle],
    ]  # fmt: skip
    shown = ""
    for step in steps:
        code = cli.main([str(part) for part in step])
        captured = capsys.readouterr()
        shown += captured.out + captured.err
        assert code in (0, cli.EXIT_INCOMPLETE), (step[:2], code, shown)

    assert SEGMENT not in shown
    assert SEGMENT.encode() not in everything_under(runs)
    assert SEGMENT.encode() not in store.read_bytes()
    assert SEGMENT.encode() not in report.read_bytes()
    assert SEGMENT.encode() not in everything_under(bundle)
    assert list(bundle.rglob("refusals.jsonl")), "the bundle holds the refusal it was checked for"


def test_without_a_file_a_path_on_another_host_is_nowhere_in_the_store(
    tmp_path, trust_ca, serve, capsys, monkeypatch
):
    # The fixture answers on one path only; it answers on this one, so the run completes and
    # there is a run to file.
    monkeypatch.setattr(http_server, "PATH", PATH)
    port = serve("127.0.0.2", tls=SECOND_ADDRESS)
    manifest = endpoint_manifest(tmp_path / "corpus", far=f"https://127.0.0.2:{port}{PATH}")
    runs = tmp_path / "runs"

    code = cli.main(
        ["drive", "--manifest", str(manifest), "--entry", "far", "--engagement-confirmed",
         "--out-dir", str(runs)]
    )  # fmt: skip

    assert code in (0, cli.EXIT_INCOMPLETE, cli.EXIT_SERVER_FAILED)
    said = capsys.readouterr().err
    (recording,) = runs.glob("*/events.jsonl")
    (first,) = [e for e in events_of(recording) if e["type"] == "run_started"]
    assert first["endpoint"]["path"] is None and first["endpoint"]["path_sha256"] == sha(PATH)
    store = tmp_path / "findings.sqlite"
    assert cli.main(["store", "ingest", "-q", "--store", str(store), str(recording)]) in (0, 3, 4)
    capsys.readouterr()
    # No report and no bundle: `report --engagement` and `evidence pack --engagement` are
    # required, and a run without a file has none to give.
    assert SEGMENT.encode() not in everything_under(runs)
    assert SEGMENT.encode() not in store.read_bytes()
    with Store.open_read_only(store) as filed:
        assert len(filed.runs()) == 1, "the run was filed, so the store check looks at something"
    # A run that goes through prints no URL, so there is no segment on the terminal to show whole;
    # that half is the refused run's, above.
    assert SEGMENT not in said


def test_the_endpoint_s_path_in_a_challenge_s_resource_metadata_is_nowhere_in_the_artifacts(
    tmp_path, capsys, monkeypatch
):
    # RFC 9728 3.1: the metadata URL carries the resource's own path after the well-known one.
    monkeypatch.setattr(http_server, "PATH", PATH)
    monkeypatch.setenv("TEST_TOKEN_OTHER", "other-" + "Qw3r" + "Ty82")
    served = http_server.serve(0, "127.0.0.1", token_envs=("TEST_TOKEN_OTHER",), metadata_path=PATH)
    try:
        port = served.server_address[1]
        manifest = endpoint_manifest(tmp_path / "corpus", held=f"http://127.0.0.1:{port}{PATH}")
        held = write_engagement(
            tmp_path / "engagement", targets=[{"host": "127.0.0.1", "ports": [port]}]
        )
        runs = tmp_path / "runs"
        code = cli.main(
            ["drive", "--engagement", str(held), "--manifest", str(manifest), "--entry", "held",
             "--out-dir", str(runs)]
        )  # fmt: skip
        on_stderr = capsys.readouterr().err
    finally:
        served.shutdown()
        served.server_close()

    assert code == cli.EXIT_SERVER_FAILED, on_stderr
    assert "auth.example.test" in on_stderr, "the terminal still shows the host"
    (recording,) = runs.glob("*/events.jsonl")
    (response,) = [e for e in events_of(recording) if e["type"] == "http_response"]
    (challenge,) = response["headers"]["www-authenticate"]
    metadata = challenge["params"]["resource_metadata"]
    assert metadata.startswith("https://auth.example.test")
    assert withheld_path(f"/.well-known/oauth-protected-resource{PATH}") in metadata
    store, report, bundle = tmp_path / "findings.sqlite", tmp_path / "report.md", tmp_path / "pack"
    steps = [
        ["store", "ingest", "-q", "--store", store, "--engagement", held, recording],
        ["report", "--engagement", held, "--store", store, "--runs", runs, "--manifest", manifest,
         "--out-dir", runs, "--out", report],
        ["evidence", "pack", "-q", "--engagement", held, "--store", store, "--runs", runs,
         "--manifest", manifest, "--report", report, "--out", bundle],
    ]  # fmt: skip
    shown = ""
    for step in steps:
        code = cli.main([str(part) for part in step])
        captured = capsys.readouterr()
        shown += captured.out + captured.err
        assert code in (0, cli.EXIT_INCOMPLETE, cli.EXIT_SERVER_FAILED), (step[:2], code, shown)

    assert SEGMENT.encode() not in everything_under(runs)
    assert SEGMENT.encode() not in store.read_bytes()
    assert SEGMENT.encode() not in report.read_bytes()
    # The bundle copies the manifest, whose entry the operator wrote with the path; nothing else.
    holders = [
        p.relative_to(bundle)
        for p in bundle.rglob("*")
        if p.is_file() and SEGMENT.encode() in p.read_bytes()
    ]
    assert all(p.parts[0] == "manifest" for p in holders), holders
    assert SEGMENT not in shown


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("Location", f"https://h{PATH}"),
        ("Content-Location", f"https://h{PATH}?q=1"),
        ("Referer", f"https://h{PATH}#top"),
    ],
)
def test_a_url_in_a_header_has_its_path_withheld_in_both_directions(name, value):
    kept, stream = recorder()
    kept.http_request(
        0, 0, exchange=1, connection=1, method="GET", target="/", headers=[(name, value)]
    )
    kept.http_response(
        1, 1, exchange=1, status=302, reason="Found", headers=[(name, value)],
        content_type=None, framing="empty",
    )  # fmt: skip

    assert SEGMENT not in stream.getvalue()
    assert "https://h" in stream.getvalue(), "scheme and host stay"
    # the path, and the query or the fragment behind it, are withheld in each direction
    assert stream.getvalue().count("path withheld") == (2 if value.endswith(PATH) else 4)


def test_a_header_url_keeps_a_listed_path_on_its_host_and_withholds_it_on_another():
    kept, stream = recorder(PATH)
    kept.http_response(
        0, 0, exchange=1, status=302, reason="Found", content_type=None, framing="empty",
        headers=[("Location", f"https://h{PATH}"), ("Content-Location", f"https://far{PATH}")],
    )  # fmt: skip

    (event,) = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert event["headers"]["location"] == f"https://h{PATH}"
    assert event["headers"]["content-location"] == f"https://far{withheld_path(PATH)}"


def both_directions(*headers):
    """The events of a request and of a response that carry ``headers``."""
    kept, stream = recorder(PATH)
    kept.http_request(
        0, 0, exchange=1, connection=1, method="GET", target="/", headers=list(headers)
    )
    kept.http_response(
        1, 1, exchange=1, status=302, reason="Found", headers=list(headers),
        content_type=None, framing="empty",
    )  # fmt: skip
    return [json.loads(line) for line in stream.getvalue().splitlines()], stream


@pytest.mark.parametrize("name", ["Location", "Content-Location", "Referer"])
@pytest.mark.parametrize(
    ("reference", "path"),
    [
        (f"{PATH}/next", f"{PATH}/next"),
        (f"{SEGMENT}/mcp/next", f"{SEGMENT}/mcp/next"),
        (f"//kunde.example{PATH}", f"//kunde.example{PATH}"),
        (f"wss://kunde.example{PATH}", f"wss://kunde.example{PATH}"),
    ],
)
def test_a_relative_reference_in_a_header_has_its_path_withheld_in_both_directions(
    name, reference, path
):
    events, stream = both_directions((name, reference))

    assert SEGMENT not in stream.getvalue()
    assert stream.getvalue().count(sha(path)) == 2
    assert [e["headers"][name.lower()] for e in events if "headers" in e] == [
        withheld_path(path)
    ] * 2


def test_a_listed_path_is_withheld_as_a_relative_reference_and_kept_as_an_absolute_one():
    events, _ = both_directions(("Location", PATH), ("Content-Location", f"https://h{PATH}"))

    for event in events:
        assert event["headers"]["location"] == withheld_path(PATH)
        assert event["headers"]["content-location"] == f"https://h{PATH}"


def test_the_query_and_the_fragment_of_a_relative_reference_are_withheld():
    events, _ = both_directions(
        ("Location", f"{PATH}/x?page=2"),
        ("Referer", f" {PATH}#top"),
        ("Content-Location", "?page=2"),
    )

    for event in events:
        assert event["headers"]["location"] == withheld_path(f"{PATH}/x") + "?" + withheld_path(
            "page=2"
        )
        assert event["headers"]["referer"] == withheld_path(PATH) + "#" + withheld_path("top")
        assert event["headers"]["content-location"] == "?" + withheld_path("page=2")


def test_the_masker_s_placeholder_stays_as_it_is_character_for_character():
    events, _ = both_directions(("Location", PLACEHOLDER), ("Referer", f" {PLACEHOLDER} "))

    for event in events:
        assert event["headers"]["location"] == PLACEHOLDER
        assert event["headers"]["referer"] == PLACEHOLDER


def test_an_empty_path_stays_empty_and_a_fragment_is_withheld():
    events, _ = both_directions(("Location", "#"), ("Referer", "#top"))

    for event in events:
        assert event["headers"]["location"] == "#" + withheld_path("")
        assert event["headers"]["referer"] == "#" + withheld_path("top")


@pytest.mark.parametrize("name", ["Location", "Content-Location", "Referer"])
@pytest.mark.parametrize(
    "reference",
    [
        "/login?next=https://far/tenant/x",
        "?next=https://far/tenant/x",
        "/a#https://far/tenant/x",
        "//h/a?u=https://far/tenant/x",
        "wss://h/a?u=https://far/tenant/x",
    ],
)
def test_a_url_behind_the_path_of_a_relative_reference_is_withheld_with_its_host(name, reference):
    events, stream = both_directions((name, reference))

    assert "/tenant" not in stream.getvalue()
    assert "https://far" not in stream.getvalue(), "the query and the fragment are withheld whole"
    base, _, tail = reference.partition("?") if "?" in reference else reference.partition("#")
    for event in events:
        assert event["headers"][name.lower()].endswith(withheld_path(tail))


#: Values whose ``tenant`` must not reach the record, as a reference in any header that holds one.
TENANT_REFERENCES = [
    "/login?next=https%3A%2F%2Fh%2Ftenant%2Fx",
    "/login#https%253A%252F%252Fh%252Ftenant",
    "https://idp/authorize?resource=https%3A%2F%2Fh%2Ftenant",
    "https://h/a#tenant",
    "https://h/a?tenant=1",
    "https://user:tenant@h/a",
    "https://h\\tenant\\x",
    "https:/h/tenant",
    "HTTP://h/tenant",
    "https://h:notaport/tenant",
    "/a?x /tenant/y",
    "/a#f /tenant/y",
]


@pytest.mark.parametrize("name", ["Location", "Content-Location", "Referer"])
@pytest.mark.parametrize("value", TENANT_REFERENCES)
def test_a_reference_keeps_no_tenant_in_any_form(name, value):
    _, stream = both_directions((name, value))

    assert "tenant" not in stream.getvalue()


@pytest.mark.parametrize("param", ["resource_metadata", "domain", "error_uri"])
@pytest.mark.parametrize(
    "value",
    [v for v in TENANT_REFERENCES if "\\" not in v],  # the parser unescapes it to a host
)
def test_a_challenge_reference_keeps_no_tenant_in_any_form(param, value):
    _, stream = both_directions(("WWW-Authenticate", f'Bearer realm="x", {param}="{value}"'))

    assert "tenant" not in stream.getvalue()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f"https://h{PATH}", f"https://h{PATH}"),
        (f"https://h{PATH}?q=1", f"https://h{PATH}?" + withheld_path("q=1")),
        (
            "https://h/other?q=1",
            "https://h" + withheld_path("/other") + "?" + withheld_path("q=1"),
        ),
        ("/a?q#f", withheld_path("/a") + "?" + withheld_path("q#f")),
        ("?q=1", "?" + withheld_path("q=1")),
        ("https://[::1]:8443/a", "https://[::1]:8443" + withheld_path("/a")),
    ],
)
def test_a_reference_keeps_its_origin_and_a_listed_path_and_nothing_else(value, expected):
    events, _ = both_directions(("Location", value))

    for event in events:
        assert event["headers"]["location"] == expected


#: A second scheme in the path of a reference is part of that path: the reference keeps its
#: origin and one withheld path, and no host behind the path.
@pytest.mark.parametrize("name", ["Location", "Content-Location", "Referer"])
@pytest.mark.parametrize(
    ("value", "path"),
    [
        ("https://h/a/https://far/b", "/a/https://far/b"),
        ("https://h/x/https://tenant-x", "/x/https://tenant-x"),
        ("https://h/x/wss://tenant-x/y", "/x/wss://tenant-x/y"),
    ],
)
def test_a_second_scheme_in_the_path_of_a_reference_is_withheld_with_it(name, value, path):
    events, stream = both_directions((name, value))

    assert "tenant-x" not in stream.getvalue()
    assert "far" not in stream.getvalue()
    for event in events:
        assert event["headers"][name.lower()] == "https://h" + withheld_path(path)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f"https://h{PATH}", f"https://h{PATH}"),
        ("https://h/a/https://far/b", "https://h" + withheld_path("/a/https://far/b")),
        ("https://h/x/https://tenant-x", "https://h" + withheld_path("/x/https://tenant-x")),
        ("wss://h/tenant/x", withheld_path("wss://h/tenant/x")),
    ],
)
@pytest.mark.parametrize("param", ["resource_metadata", "domain", "error_uri"])
def test_a_reference_in_a_challenge_is_written_as_in_a_reference_header(param, value, expected):
    events, _ = both_directions(("WWW-Authenticate", f'Bearer realm="x", {param}="{value}"'))

    for event in events:
        (challenge,) = event["headers"]["www-authenticate"]
        assert challenge["params"][param] == expected


@pytest.mark.parametrize("value", ["wss://h/tenant/x", "ws://h/tenant/x", "//h/tenant/x"])
def test_a_url_of_another_scheme_in_a_header_has_its_path_withheld(value):
    events, stream = both_directions(("X-Other", value))

    assert "tenant" not in stream.getvalue()
    for event in events:
        assert event["headers"]["x-other"] == withhold_url_path(value)
        assert event["headers"]["x-other"].startswith(value[: value.index("/tenant")])


def link_values(value):
    events, _ = both_directions(("Link", value))
    return [event["headers"]["link"] for event in events]


@pytest.mark.parametrize(
    "value",
    [
        '</tenant/x>; rel="next"',
        '</tenant/x; rel="next"',
        "/tenant/x",
        "<https://h/>; anchor=/tenant/x",
        '<https://h/a>; title="x, </tenant/x>; rel="next"',
        f'<https://h{PATH}>; rel="next"',
    ],
)
def test_a_link_value_is_withheld_whole_listed_or_not(value):
    _, stream = both_directions(("Link", value))

    assert link_values(value) == [withheld_path(value)] * 2
    assert "tenant" not in stream.getvalue()


def test_the_masker_s_placeholder_in_a_link_stays():
    assert link_values(PLACEHOLDER) == [PLACEHOLDER] * 2


@pytest.mark.parametrize(
    "value",
    [
        'Digest realm="x", domain="/tenant/x"',
        'Digest realm="x", domain="/tenant/x /tenant/y"',
        'Bearer realm="x", resource_metadata="/.well-known/oauth-protected-resource/tenant/x"',
        'Bearer realm="x", error_uri="/tenant/x"',
    ],
)
def test_a_relative_reference_in_a_parsed_challenge_has_its_path_withheld(value):
    events, stream = both_directions(("WWW-Authenticate", value))

    assert "tenant" not in stream.getvalue()
    for event in events:
        (challenge,) = event["headers"]["www-authenticate"]
        assert challenge["params"]["realm"] == "x"
        assert "path withheld" in json.dumps(challenge["params"])


def test_an_absolute_resource_metadata_keeps_its_host_and_withholds_its_path():
    value = 'Bearer resource_metadata="https://auth.example.test/.well-known/x/tenant/x"'
    events, _ = both_directions(("WWW-Authenticate", value))

    for event in events:
        (challenge,) = event["headers"]["www-authenticate"]
        assert challenge["params"]["resource_metadata"] == (
            "https://auth.example.test" + withheld_path("/.well-known/x/tenant/x")
        )


def test_a_bare_path_in_a_realm_stays_as_the_named_limit():
    events, _ = both_directions(("WWW-Authenticate", 'Bearer realm="/tenant/x"'))

    for event in events:
        assert event["headers"]["www-authenticate"][0]["params"]["realm"] == "/tenant/x"


def test_an_encoded_path_in_another_header_stays_as_the_named_limit():
    value = "https://h/a?u=https%3A%2F%2Fh%2Ftenant"
    events, _ = both_directions(("X-Other", value))

    for event in events:
        assert "https%3A%2F%2Fh%2Ftenant" in event["headers"]["x-other"]


@pytest.mark.parametrize("value", ["https://h/a, /tenant/x", "/tenant/x /tenant/y"])
def test_a_reference_with_white_space_inside_is_withheld_whole(value):
    events, stream = both_directions(("Location", value))

    assert "tenant" not in stream.getvalue()
    assert [e["headers"]["location"] for e in events if "headers" in e] == [
        withheld_path(value)
    ] * 2


# -- the order of the masker and the path rule --------------------------------------------------


def test_a_header_path_digests_as_the_masker_left_it():
    literal = "lit" + "Zq7wXk29Lm4p"
    stream = io.StringIO()
    kept = Recorder(stream, run_id="r", masker=Masker(literals=[literal]))
    kept.http_response(
        0, 0, exchange=1, status=302, reason="Found", content_type=None, framing="empty",
        headers=[("Location", f"/x/{literal}/mcp")],
    )  # fmt: skip

    (event,) = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert literal not in stream.getvalue()
    assert event["headers"]["location"] == withheld_path(f"/x/{PLACEHOLDER}/mcp")
    assert kept.server_redactions == 1


def test_a_credential_in_the_query_of_a_relative_reference_is_blanked_before_it_is_withheld():
    token = "Zq7wXk29" + "Lm4pVb3nTy6h" + "Rc8dFg1sJ5aW"
    events, stream = both_directions(("Location", f"/cb?access_token={token}"))

    assert token not in stream.getvalue()
    for event in events:
        assert event["headers"]["location"] == (
            withheld_path("/cb") + "?" + withheld_path("access_token=" + PLACEHOLDER)
        )


# -- a URL anywhere in an argument ----------------------------------------------------------------

HOST = "https://kunde.example"
TENANT = f"{HOST}{PATH}"
OTHER = "https://other.example/p/q"


def masked_argv(*arguments, verbatim=()):
    return Masker().mask_argv(["server", *arguments], verbatim_paths=verbatim)[0][1:]


def shown(url: str) -> str:
    """The URL as a record holds it: everything but its path, which is withheld."""
    parts = urlsplit(url)
    head = f"{parts.scheme}://{parts.netloc}"
    return head + withheld_path(parts.path) + url[len(head) + len(parts.path) :]


@pytest.mark.parametrize(
    "arguments, expected",
    [
        (
            ["docker", "run", "-e", f"MCP_URL={TENANT}", "img"],
            ["docker", "run", "-e", f"MCP_URL={shown(TENANT)}", "img"],
        ),
        (["env", f"URL={HOST}/x/y", "cmd"], ["env", f"URL={shown(HOST + '/x/y')}", "cmd"]),
        ([f"--opt={TENANT}"], [f"--opt={shown(TENANT)}"]),
        ([f"see:{TENANT}?a=1#top"], [f"see:{shown(TENANT + '?a=1#top')}"]),
        ([f"A={TENANT} B={OTHER}"], [f"A={shown(TENANT)} B={shown(OTHER)}"]),
        (
            [f"{TENANT},HTTP://other.example/p/q"],
            # A URL runs to white space (here the comma is its path's), or to the next scheme.
            [f"{HOST}{withheld_path(PATH + ',')}HTTP://other.example{withheld_path('/p/q')}"],
        ),
        (
            [f"{HOST}/a/b?next={OTHER}"],
            [f"{HOST}{withheld_path('/a/b')}?next=https://other.example{withheld_path('/p/q')}"],
        ),
    ],
)
def test_every_url_in_an_argument_has_its_path_withheld_wherever_it_starts(arguments, expected):
    assert masked_argv(*arguments) == expected


#: A path that stays under any scheme but ``http`` and ``https``: no port to name, no listing.
@pytest.mark.parametrize(
    ("text", "head"),
    [
        ("wss://h/tenant/x", "wss://h"),
        ("ws://h/tenant/x", "ws://h"),
        ("ftp://h/tenant/x", "ftp://h"),
        ("file:///tenant/x", "file://"),
        ("URL=//h/tenant/x", "URL=//h"),
        ("--upstream=wss://h/tenant/x", "--upstream=wss://h"),
        ("HTTP://h/tenant/x", "HTTP://h"),
        ("env URL=//h/tenant/x", "env URL=//h"),
        ("python //tenant/x", "python //tenant"),
    ],
)
def test_a_url_of_any_scheme_has_its_path_withheld_in_an_argument(text, head):
    path = text[len(head) :]
    assert masked_argv(text) == [head + withheld_path(path)]
    assert withhold_url_path(text) == head + withheld_path(path)
    # `python //tenant/x` counts as `//` after white space: the rule cannot tell it from a URL
    assert "tenant/x" not in masked_argv(text)[0]


def test_a_text_that_holds_no_url_stays():
    assert masked_argv("a//tenant", "a//tenant/x", "x=a//tenant") == [
        "a//tenant",
        "a//tenant/x",
        "x=a//tenant",
    ]


def test_a_scheme_of_more_than_32_characters_still_has_the_rest_of_the_path_withheld():
    # The scheme is looked for in 32 characters at most (and the colon), so the match starts at
    # the 8 characters in: what stands before it stays, and so does the host.
    text = "a" * 40 + "://h/tenant/x"

    assert withhold_url_path(text) == "a" * 40 + "://h" + withheld_path("/tenant/x")


@pytest.mark.parametrize("scheme", ["wss", "ws", "ftp", "file"])
def test_a_scheme_without_a_default_port_matches_no_listed_path(scheme):
    listed = [("h", port, "/tenant/x") for port in (80, 443, 8080)]

    assert withhold_url_path(f"{scheme}://h/tenant/x", listed) == (
        f"{scheme}://h" + withheld_path("/tenant/x")
    )


def test_a_listed_path_stays_where_a_url_stands_inside_an_argument():
    held = [("kunde.example", 443, PATH)]

    assert masked_argv("-e", f"MCP_URL={TENANT}", f"B={HOST}/x", verbatim=held) == [
        "-e",
        f"MCP_URL={TENANT}",
        f"B={shown(HOST + '/x')}",
    ]
    assert withhold_url_path(f"A={TENANT} B={TENANT}x", held) == (
        f"A={TENANT} B={HOST}{withheld_path(PATH + 'x')}"
    )


def test_a_url_inside_an_argument_is_withheld_in_run_started_and_in_the_refusal(tmp_path, capsys):
    now = datetime.now(timezone.utc)
    held = write_engagement(
        tmp_path / "engagement",
        window={
            "from": (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "until": (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )
    out_dir = tmp_path / "runs"
    argv = ["docker", "run", "-e", f"MCP_URL={TENANT}", "env", f"URL={HOST}/x/y", "cmd"]

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--out-dir", str(out_dir), "--", *argv]
    )

    capsys.readouterr()
    assert code == 2
    (record,) = refusals_in(out_dir)
    assert f"MCP_URL={shown(TENANT)}" in record.command
    assert f"URL={shown(HOST + '/x/y')}" in record.command
    assert SEGMENT.encode() not in everything_under(out_dir)
    assert b"/x/y" not in everything_under(out_dir)


def test_a_url_inside_an_argument_is_withheld_in_run_started(tmp_path):
    out_dir = tmp_path / "runs"
    argv = [sys.executable, "-c", "pass", f"MCP_URL={TENANT}", f"--opt={HOST}/x/y"]

    cli.main(["drive", "-q", "--out-dir", str(out_dir), "--", *argv])

    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    assert first["argv"][-2:] == [f"MCP_URL={shown(TENANT)}", f"--opt={shown(HOST + '/x/y')}"]
    assert SEGMENT.encode() not in everything_under(out_dir)
    assert b"/x/y" not in everything_under(out_dir)


# -- the words of any refusal -------------------------------------------------------------------


def test_a_target_that_is_a_url_with_a_path_is_withheld_in_the_message_as_in_the_command(
    tmp_path, capsys
):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"
    url = f"https://kunde.example{PATH}"

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--target", url, "--out-dir", str(out_dir),
         "--", sys.executable, "-c", "pass"]
    )  # fmt: skip

    assert code == 2
    assert SEGMENT in capsys.readouterr().err, "the terminal shows the path whole"
    (record,) = refusals_in(out_dir)
    assert record.reason == "target_not_listed"
    assert "cannot be taken apart" in record.message
    # The record's words have the URL bare, so its digest and length are the command's.
    stated = f"sha256 {sha(PATH)}, {len(PATH)} characters"
    assert stated in " ".join(record.command)
    assert stated in record.message
    for text in (record.message, " ".join(record.command)):
        assert SEGMENT not in text
    assert SEGMENT.encode() not in everything_under(out_dir)


@pytest.mark.parametrize(
    "flag, url",
    [
        ("--target", "wss://kunde.example/tenant-x/mcp"),
        ("--http", "ws://kunde.example/tenant-x/mcp"),
    ],
)
def test_a_url_of_another_scheme_is_withheld_in_the_refusal_and_shown_on_the_terminal(
    tmp_path, capsys, flag, url
):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"
    server = ["--", sys.executable, "-c", "pass"] if flag == "--target" else []

    code = cli.main(
        ["drive", "-q", "--engagement", str(held), flag, url, "--out-dir", str(out_dir), *server]
    )

    assert code == 2
    err = capsys.readouterr().err
    if flag == "--target":
        assert "tenant-x" in err, "the terminal shows the path whole"
    else:  # `--http` says why it refuses a scheme, and does not quote the URL
        assert "only http:// and https://" in err
        assert "tenant-x" not in err
    (record,) = refusals_in(out_dir)
    assert "tenant-x" not in record.message
    assert "tenant-x" not in " ".join(record.command)
    assert b"tenant-x" not in everything_under(out_dir)
    assert "://kunde.example<path withheld" in " ".join(record.command)


def test_a_server_option_of_another_scheme_is_withheld_in_run_started(tmp_path):
    out_dir = tmp_path / "runs"
    argv = [sys.executable, "-c", "pass", "--upstream=wss://kunde.example/tenant-x/mcp"]

    cli.main(
        ["drive", "-q", "--out-dir", str(out_dir), "--", *argv, "URL=//kunde.example/tenant-y"]
    )

    (first,) = [e for e in events_of(recording_in(out_dir)) if e["type"] == "run_started"]
    assert first["argv"][-2:] == [
        "--upstream=wss://kunde.example" + withheld_path("/tenant-x/mcp"),
        "URL=//kunde.example" + withheld_path("/tenant-y"),
    ]
    assert b"tenant-" not in everything_under(out_dir)


def test_a_path_the_gate_withheld_already_is_not_withheld_a_second_time(tmp_path, capsys):
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "127.0.0.1", "ports": [9], "paths": ["/mcp"]}]
    )
    out_dir = tmp_path / "runs"

    cli.main(
        ["drive", "--engagement", str(held), "--http", f"http://127.0.0.1:9{PATH}",
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    capsys.readouterr()
    (record,) = refusals_in(out_dir)
    # The gate's words with the path's place holding the withheld text once, behind the file's
    # name and the condition as the CLI writes them.
    assert record.message == (
        f"{held}: path_not_listed: the URL's path {withheld_path(PATH)} is not among the paths "
        "the engagement lists for 127.0.0.1 (/mcp); paths are compared exactly"
    )


def test_a_listed_path_stays_whole_in_the_words_of_a_refusal(tmp_path):
    loaded = engagement.load(write_engagement(tmp_path / "engagement"))
    out_dir = tmp_path / "runs"
    message = f"asked https://kunde.example{PATH} and https://other.example{PATH}"

    wrote = engagement.record_refusal(
        out_dir,
        argv=["drive"],
        masker=Masker(),
        reason="target_not_listed",
        message=message,
        engagement=loaded,
        now=datetime.now(timezone.utc),
        verbatim_paths=[("kunde.example", 443, PATH)],
    )

    assert wrote is None
    (record,) = refusals_in(out_dir)
    assert record.message == f"asked https://kunde.example{PATH} and https://other.example" + (
        withheld_path(PATH)
    )
