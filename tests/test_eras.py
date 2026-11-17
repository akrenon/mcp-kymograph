"""The era detection (src/mcp_kymograph/eras.py): which protocol era and version a server speaks.

The module has no I/O; the driver calls it. It is tested two ways: answer by answer, with
scripted responses; and over stdio, against fixture servers of one era each
(tests/fixtures/eras/), with a minimal client in this file that does only what the module
says — send, wait, match the answer by its id, feed it back. No Docker, no driver, no proxy.
"""

from __future__ import annotations

import dataclasses
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_kymograph import driver, eras
from mcp_kymograph.eras import (
    CLOSED,
    CLOSED_ON_PROBE,
    DISCOVERED,
    ERA_LEGACY,
    ERA_MODERN,
    HANDSHAKE_CLOSED,
    HANDSHAKE_REFUSED,
    HANDSHAKE_UNANSWERED,
    HEADER_ERROR_WITHOUT_HEADERS,
    INITIALIZE_METHOD,
    LEGACY_REQUEST_VERSION,
    MALFORMED_VERSION,
    MODERN_ERROR,
    MODERN_REFUSED,
    MODERN_VERSION,
    NEWEST_LEGACY_VERSION,
    NO_ANSWER,
    NO_COMMON_VERSION,
    NO_RESULT,
    NOT_JSON_RPC,
    OTHER_ERROR,
    OTHER_RESULT,
    PROBE_METHOD,
    PROCEED,
    STOP,
    TRANSPORT_HTTP,
    UNKNOWN_VERSION,
    Detection,
    Detector,
    ProbeReading,
    Send,
    classify_probe,
)

ERAS = Path(__file__).parent / "fixtures" / "eras"
MODERN = str(ERAS / "modern_server.py")
LEGACY = str(ERAS / "legacy_server.py")
CLIENT = {"name": "mcp-kymograph", "version": "test"}


# -- a client that does what the module says, over real pipes -------------------------------


def converse(
    server: str, *args: str, wait: float = 2.0, probe: bool = True
) -> tuple[Detection, list[dict], int]:
    """Detect the era of one server process. Returns the detection, what was sent, and how the
    process ended once its input was closed."""
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, server, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    buffered = b""
    sent: list[dict] = []

    def send(message: dict) -> bool:
        sent.append(message)
        try:
            process.stdin.write(json.dumps(message).encode() + b"\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            return False
        return True

    def answer_to(identifier: int):
        nonlocal buffered
        deadline = time.monotonic() + wait
        while True:
            while b"\n" in buffered:
                line, buffered = buffered.split(b"\n", 1)
                try:
                    document = json.loads(line)
                except ValueError:
                    continue
                if isinstance(document, dict) and document.get("id") == identifier:
                    return document
            left = deadline - time.monotonic()
            if left <= 0 or not selector.select(left):
                return NO_ANSWER
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                return CLOSED
            buffered += chunk

    try:
        detector = Detector(CLIENT, {})
        step: Send | Detection = detector.start(probe=probe)
        while isinstance(step, Send):
            step = detector.answer(answer_to(step.identifier) if send(step.message) else CLOSED)
        for message in step.followup:
            send(message)
        process.stdin.close()
        code = process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        selector.close()
    return step, sent, code


def methods(sent: list[dict]) -> list[str]:
    return [message["method"] for message in sent]


# -- over stdio, one era per server ---------------------------------------------------------


def test_a_modern_server_is_modern_and_gets_no_handshake():
    found, sent, _ = converse(MODERN)
    assert (found.action, found.era, found.version) == (PROCEED, ERA_MODERN, "2026-07-28")
    assert found.capabilities == {"tools": {}}
    assert found.server_info == {"name": "modern", "version": "1"}
    assert methods(sent) == [PROBE_METHOD]
    assert found.exchanges == ((PROBE_METHOD, DISCOVERED, None),)
    assert found.known and found.followup == ()


def test_a_legacy_server_of_2025_06_18_answering_method_not_found_is_legacy():
    found, sent, _ = converse(LEGACY, "--unknown", "error", "--versions", "2025-06-18")
    assert (found.action, found.era, found.version) == (PROCEED, ERA_LEGACY, "2025-06-18")
    assert methods(sent) == [PROBE_METHOD, INITIALIZE_METHOD, "notifications/initialized"]
    assert sent[1]["params"]["protocolVersion"] == LEGACY_REQUEST_VERSION
    assert found.exchanges == (
        (PROBE_METHOD, OTHER_ERROR, -32601),
        (INITIALIZE_METHOD, OTHER_RESULT, None),
    )
    assert found.server_info == {"name": "legacy", "version": "1"}


def test_a_legacy_server_that_never_answers_the_probe_is_legacy_after_the_wait():
    started = time.monotonic()
    found, sent, _ = converse(LEGACY, "--unknown", "silent", wait=1.0)
    assert time.monotonic() - started >= 1.0
    assert (found.action, found.era, found.version) == (PROCEED, ERA_LEGACY, "2025-06-18")
    assert found.probe.outcome == NO_ANSWER
    assert methods(sent)[:2] == [PROBE_METHOD, INITIALIZE_METHOD]


def test_a_legacy_server_that_ends_on_the_probe_stops_as_legacy():
    found, sent, code = converse(LEGACY, "--unknown", "exit")
    assert (found.action, found.era, found.reason) == (STOP, ERA_LEGACY, CLOSED_ON_PROBE)
    assert methods(sent) == [PROBE_METHOD]
    assert found.exchanges == ((PROBE_METHOD, CLOSED, None),)
    assert found.probe.outcome == CLOSED and code == 3


def test_a_server_known_to_be_legacy_can_be_asked_without_the_probe():
    # A new process of the server that closed on the probe: initialize straight away.
    found, sent, _ = converse(LEGACY, "--unknown", "exit", probe=False)
    assert (found.action, found.era, found.version) == (PROCEED, ERA_LEGACY, "2025-06-18")
    assert sent[0]["params"]["protocolVersion"] == LEGACY_REQUEST_VERSION
    assert methods(sent) == [INITIALIZE_METHOD, "notifications/initialized"]
    assert found.probe is None


def test_a_server_that_knows_only_2024_11_05_answers_with_it_and_it_is_spoken():
    # Asked for 2025-06-18, a conforming server answers with the version it does support.
    found, sent, _ = converse(LEGACY, "--versions", "2024-11-05")
    assert (found.action, found.era, found.version) == (PROCEED, ERA_LEGACY, "2024-11-05")
    assert methods(sent) == [PROBE_METHOD, INITIALIZE_METHOD, "notifications/initialized"]


def test_a_server_that_knows_only_2024_11_05_and_refuses_ours_is_asked_once_more():
    found, sent, _ = converse(LEGACY, "--versions", "2024-11-05", "--strict")
    assert (found.action, found.version) == (PROCEED, "2024-11-05")
    assert [m["params"]["protocolVersion"] for m in sent if m["method"] == INITIALIZE_METHOD] == [
        LEGACY_REQUEST_VERSION,
        "2024-11-05",
    ]
    assert found.exchanges == (
        (PROBE_METHOD, OTHER_ERROR, -32601),
        (INITIALIZE_METHOD, OTHER_ERROR, -32602),
        (INITIALIZE_METHOD, OTHER_RESULT, None),
    )


def test_a_version_the_module_does_not_know_stops_the_detection():
    found, sent, _ = converse(LEGACY, "--versions", "2031-01-01")
    assert (found.action, found.era, found.reason) == (STOP, ERA_LEGACY, UNKNOWN_VERSION)
    assert found.version == "2031-01-01" and not found.known
    assert "notifications/initialized" not in methods(sent)


def test_a_version_that_is_no_version_stops_the_detection():
    found, _, _ = converse(LEGACY, "--versions", "latest")
    assert (found.action, found.reason, found.version) == (STOP, MALFORMED_VERSION, "latest")


def test_a_refusal_offering_only_unknown_versions_is_not_retried():
    found, sent, _ = converse(LEGACY, "--versions", "2031-01-01", "--strict")
    assert (found.action, found.reason) == (STOP, HANDSHAKE_REFUSED)
    assert methods(sent).count(INITIALIZE_METHOD) == 1


def test_a_modern_server_with_no_version_in_common_stops():
    found, sent, _ = converse(MODERN, "--supported", "2099-01-01")
    assert (found.action, found.era, found.reason) == (STOP, ERA_MODERN, NO_COMMON_VERSION)
    assert found.probe == ProbeReading(ERA_MODERN, MODERN_ERROR, -32022, ("2099-01-01",))
    assert methods(sent) == [PROBE_METHOD]  # a modern server is not sent initialize blindly


def test_a_capability_the_modern_server_requires_stops_as_refused():
    found, sent, _ = converse(MODERN, "--refuse", "-32021")
    assert (found.action, found.era, found.reason) == (STOP, ERA_MODERN, MODERN_REFUSED)
    assert methods(sent) == [PROBE_METHOD]


def test_a_header_mismatch_over_stdio_is_modern_and_written_down_as_an_observation():
    found, sent, _ = converse(MODERN, "--refuse", "-32020")
    assert (found.probe.era, found.probe.outcome, found.probe.code) == (
        ERA_MODERN,
        MODERN_ERROR,
        -32020,
    )
    assert (found.action, found.era, found.reason) == (STOP, ERA_MODERN, MODERN_REFUSED)
    assert methods(sent) == [PROBE_METHOD]
    # A header error came over a transport without headers: noted, not judged.
    assert found.observations == (HEADER_ERROR_WITHOUT_HEADERS,)


# -- answer by answer -----------------------------------------------------------------------


def run(*answers) -> tuple[Detection, list[dict]]:
    """Feed scripted answers; a dict answer gets the id of the message it answers."""
    detector = Detector(CLIENT, {}, first_id=7)
    step = detector.start()
    sent = [step.message]
    for answer in answers:
        if isinstance(answer, dict):
            answer = {**answer, "id": step.identifier}
        step = detector.answer(answer)
        if isinstance(step, Detection):
            return step, sent
        sent.append(step.message)
    raise AssertionError(f"the detection did not end; it would send {step.message}")


def result(**fields) -> dict:
    return {"jsonrpc": "2.0", "id": 0, "result": fields}


def error(code, **data) -> dict:
    return {"jsonrpc": "2.0", "id": 0, "error": {"code": code, "message": "x", **data}}


def unsupported(*versions) -> dict:
    return error(-32022, data={"supported": list(versions), "requested": MODERN_VERSION})


def test_the_probe_is_a_complete_request_with_the_modern_meta():
    message = Detector(CLIENT, {}).start().message
    assert message == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": PROBE_METHOD,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": CLIENT,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }


def test_the_initialize_is_a_complete_request_with_version_capabilities_and_client():
    _, sent = run(error(-32601), result(protocolVersion="2025-06-18"))
    assert sent[1] == {
        "jsonrpc": "2.0",
        "id": 8,
        "method": INITIALIZE_METHOD,
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": CLIENT},
    }


def test_ids_count_up_from_the_first():
    _, sent = run(error(-32601), result(protocolVersion="2025-06-18"))
    assert [m["id"] for m in sent] == [7, 8]


def test_a_server_of_both_eras_without_our_modern_version_is_spoken_to_in_a_legacy_one():
    found, sent = run(
        unsupported("2030-01-01", "2025-03-26", "2025-11-25"),
        result(protocolVersion="2025-11-25"),
    )
    assert sent[1]["params"]["protocolVersion"] == "2025-11-25"  # the newest known
    assert (found.action, found.era, found.version) == (PROCEED, ERA_LEGACY, "2025-11-25")


def test_the_drivers_legacy_version_is_preferred_where_it_is_offered():
    _, sent = run(unsupported("2025-11-25", "2025-06-18"), result(protocolVersion="2025-06-18"))
    assert sent[1]["params"]["protocolVersion"] == LEGACY_REQUEST_VERSION


def test_a_discover_result_without_our_version_but_a_known_legacy_one_initializes():
    found, sent = run(
        result(supportedVersions=["2025-06-18"], capabilities={}),
        result(protocolVersion="2025-06-18"),
    )
    assert methods(sent) == [PROBE_METHOD, INITIALIZE_METHOD]
    assert (found.era, found.version) == (ERA_LEGACY, "2025-06-18")


def test_an_unsupported_version_error_naming_ours_still_does_not_proceed_modern():
    # An odd answer: "unsupported", and our version listed. Not a DiscoverResult: no crash,
    # no modern session on it.
    found, _ = run(unsupported("2026-07-28"))
    assert (found.action, found.reason) == (STOP, NO_COMMON_VERSION)


@pytest.mark.parametrize(
    ("meta", "capabilities", "server_info", "read"),
    [(None, {"tools": {}}, None, {"tools": {}}), ("x", [1], None, {}),
     ({"io.modelcontextprotocol/serverInfo": {"name": "m"}}, None, {"name": "m"}, {})],
)  # fmt: skip
def test_a_discover_result_of_odd_shape_is_read_without_trusting_it(
    meta, capabilities, server_info, read
):
    fields = {"supportedVersions": ["2026-07-28"]}
    if meta is not None:
        fields["_meta"] = meta
    if capabilities is not None:
        fields["capabilities"] = capabilities
    found, _ = run(result(**fields))
    assert (found.action, found.capabilities, found.server_info) == (PROCEED, read, server_info)


def test_a_second_refusal_stops_and_is_not_asked_a_third_time():
    offered = {"data": {"supported": ["2024-11-05"]}}
    found, sent = run(error(-32601), error(-32602, **offered), error(-32602, **offered))
    assert (found.action, found.reason) == (STOP, HANDSHAKE_REFUSED)
    assert methods(sent).count(INITIALIZE_METHOD) == 2


def test_a_second_refusal_offering_yet_another_version_still_stops():
    # A server that names a different version on every refusal must not keep the detection
    # going: one more initialize, never two.
    first = {"data": {"supported": ["2024-11-05"]}}
    second = {"data": {"supported": ["2025-03-26"]}}
    found, sent = run(error(-32601), error(-32602, **first), error(-32602, **second))
    assert (found.action, found.reason) == (STOP, HANDSHAKE_REFUSED)
    assert methods(sent).count(INITIALIZE_METHOD) == 2


def test_a_refusal_offering_the_version_already_asked_for_is_not_retried():
    offered = {"data": {"supported": [LEGACY_REQUEST_VERSION]}}
    found, sent = run(error(-32601), error(-32602, **offered))
    assert (found.reason, methods(sent).count(INITIALIZE_METHOD)) == (HANDSHAKE_REFUSED, 1)
    assert found.exchanges[-1] == (INITIALIZE_METHOD, OTHER_ERROR, -32602)


@pytest.mark.parametrize(
    ("answer", "reason", "outcome"),
    [(NO_ANSWER, HANDSHAKE_UNANSWERED, NO_ANSWER), (CLOSED, HANDSHAKE_CLOSED, CLOSED),
     ({"jsonrpc": "2.0"}, NO_RESULT, NO_RESULT),
     ({"jsonrpc": "2.0", "result": "ok"}, NO_RESULT, NO_RESULT)],
)  # fmt: skip
def test_an_initialize_that_comes_to_nothing_stops_with_why(answer, reason, outcome):
    found, _ = run(error(-32601), answer)
    assert (found.action, found.era, found.reason) == (STOP, ERA_LEGACY, reason)
    assert found.exchanges[-1] == (INITIALIZE_METHOD, outcome, None)


@pytest.mark.parametrize(
    ("version", "reason"),
    [("2026-07-28", UNKNOWN_VERSION), ("2031-01-01", UNKNOWN_VERSION),
     ("2025-6-18", MALFORMED_VERSION), ("2025-06-18junk", MALFORMED_VERSION),
     ("٢٠٢٥-٠٦-١٨", MALFORMED_VERSION),
     (20250618, MALFORMED_VERSION), (None, MALFORMED_VERSION), ("x" * 500, MALFORMED_VERSION)],
)  # fmt: skip
def test_a_handshake_version_outside_the_known_legacy_ones_stops(version, reason):
    found, _ = run(error(-32601), result(protocolVersion=version))
    assert (found.action, found.reason) == (STOP, reason)
    assert found.version == (version if isinstance(version, str) else None)


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
def test_every_known_legacy_version_is_spoken(version):
    found, _ = run(error(-32601), result(protocolVersion=version, capabilities={"prompts": {}}))
    assert (found.action, found.version, found.capabilities) == (PROCEED, version, {"prompts": {}})
    assert found.followup == ({"jsonrpc": "2.0", "method": "notifications/initialized"},)


def test_capabilities_that_are_no_object_are_read_as_none():
    found, _ = run(error(-32601), result(protocolVersion="2025-06-18", capabilities=["tools"]))
    assert found.capabilities == {}


@pytest.mark.parametrize(
    ("answer", "reading"),
    [
        (result(supportedVersions=["2026-07-28"], capabilities={}),
         (ERA_MODERN, DISCOVERED, None, ("2026-07-28",))),
        (result(capabilities={}), (ERA_LEGACY, OTHER_RESULT, None, ())),
        (result(supportedVersions="2026-07-28"), (ERA_LEGACY, OTHER_RESULT, None, ())),
        (unsupported("2026-07-28", 7), (ERA_MODERN, MODERN_ERROR, -32022, ("2026-07-28",))),
        (error(-32021, data={"requiredCapabilities": {"sampling": {}}}),
         (ERA_MODERN, MODERN_ERROR, -32021, ())),
        # The same codes without the shape the schema gives them: no sign of the modern era.
        (error(-32022), (ERA_LEGACY, OTHER_ERROR, -32022, ())),
        (error(-32022, data={"supported": "2026-07-28"}), (ERA_LEGACY, OTHER_ERROR, -32022, ())),
        (error(-32021), (ERA_LEGACY, OTHER_ERROR, -32021, ())),
        (error(-32021, data={"requiredCapabilities": ["sampling"]}),
         (ERA_LEGACY, OTHER_ERROR, -32021, ())),
        # HeaderMismatch is the modern specification's own code, with no data to check.
        (error(-32020), (ERA_MODERN, MODERN_ERROR, -32020, ())),
        (error(-32020, data=[1]), (ERA_MODERN, MODERN_ERROR, -32020, ())),
        (error(-32020, data={"x": 1}), (ERA_MODERN, MODERN_ERROR, -32020, ())),
        (error(-32601), (ERA_LEGACY, OTHER_ERROR, -32601, ())),
        (error(-32602), (ERA_LEGACY, OTHER_ERROR, -32602, ())),
        (error("-32022"), (ERA_LEGACY, OTHER_ERROR, None, ())),
        (error(True), (ERA_LEGACY, OTHER_ERROR, None, ())),
        (error(2**40), (ERA_LEGACY, OTHER_ERROR, None, ())),
        ({"jsonrpc": "2.0", "id": 0, "error": "nope"}, (ERA_LEGACY, OTHER_ERROR, None, ())),
        ({"jsonrpc": "2.0", "id": 0}, (ERA_LEGACY, NO_RESULT, None, ())),
        ({"jsonrpc": "2.0", "id": 0, "result": [1]}, (ERA_LEGACY, NO_RESULT, None, ())),
    ],
)  # fmt: skip
def test_only_a_discover_result_or_a_modern_error_of_its_shape_means_modern(answer, reading):
    assert classify_probe(answer) == ProbeReading(*reading)


def test_versions_from_the_traffic_are_bounded_in_number_and_kept_whole():
    # The text is cut by whoever records it, after masking; here nothing is.
    reading = classify_probe(result(supportedVersions=["v" * 100] * 50))
    assert len(reading.supported) == eras.MAX_VERSIONS
    assert all(version == "v" * 100 for version in reading.supported)


def test_a_version_that_starts_like_a_known_one_is_not_that_one():
    long = "2025-06-18" + "0" * 50
    found, _ = run(error(-32601), result(protocolVersion=long))
    assert (found.action, found.reason, found.version) == (STOP, MALFORMED_VERSION, long)
    assert not eras.is_known_legacy(long[: eras.MAX_VERSION_LENGTH])
    assert eras.choose_legacy(classify_probe(result(supportedVersions=[long])).supported) is None


def test_the_detector_is_used_in_order():
    detector = Detector(CLIENT, {})
    with pytest.raises(RuntimeError):
        detector.answer(NO_ANSWER)
    detector.start()
    with pytest.raises(RuntimeError):
        detector.start()
    detector.answer(CLOSED)
    with pytest.raises(RuntimeError):
        detector.answer(NO_ANSWER)


@pytest.mark.parametrize(
    "answer",
    ["late", [{}], 7, {"jsonrpc": "2.0", "id": 2, "result": {}},
     {"jsonrpc": "2.0", "method": "notifications/message", "params": {}},
     {"jsonrpc": "2.0", "id": 1, "method": "roots/list"},
     {"jsonrpc": "2.0", "id": True, "result": {"supportedVersions": ["2026-07-28"]}},
     {"jsonrpc": "2.0", "id": 1.0, "result": {"supportedVersions": ["2026-07-28"]}},
     {"jsonrpc": "2.0", "id": "1", "result": {"supportedVersions": ["2026-07-28"]}}],
)  # fmt: skip
def test_what_is_not_the_answer_to_the_message_sent_is_refused(answer):
    detector = Detector(CLIENT, {})
    detector.start()
    with pytest.raises(ValueError):
        detector.answer(answer)


def test_the_legacy_version_asked_for_first_is_the_drivers():
    # The driver announces this today; the building block asks for the same, unchanged.
    assert LEGACY_REQUEST_VERSION == driver.PROTOCOL_VERSION == "2025-06-18"


# -- more edge cases -------------------------------------------------------------------------


def test_the_versions_are_cut_to_their_bound_before_they_are_filtered():
    from mcp_kymograph.eras import MAX_VERSIONS, NO_COMMON_VERSION

    listed = [1] * MAX_VERSIONS + ["2026-07-28"]
    found, sent = run(result(supportedVersions=listed))
    assert (found.action, found.era, found.reason) == (STOP, ERA_MODERN, NO_COMMON_VERSION)
    assert found.probe.supported == ()


@pytest.mark.parametrize("data", [["supported"], "2024-11-05", 7, None])
def test_error_data_of_the_wrong_type_is_read_as_none(data):
    found, sent = run(error(-32601), error(-32602, data=data))
    assert (found.action, found.reason) == (STOP, HANDSHAKE_REFUSED)
    assert methods(sent) == [PROBE_METHOD, INITIALIZE_METHOD]


@pytest.mark.parametrize("supported", ["2024-11-05", {"2024-11-05": True}])
def test_versions_offered_as_anything_but_a_list_are_not_read(supported):
    found, sent = run(error(-32601), error(-32602, data={"supported": supported}))
    assert (found.action, found.reason) == (STOP, HANDSHAKE_REFUSED)
    assert len(sent) == 2


def test_an_unanswered_probe_is_written_down_among_the_exchanges():
    found, _ = run(NO_ANSWER, result(protocolVersion="2025-06-18"))
    assert found.exchanges[0] == (PROBE_METHOD, NO_ANSWER, None)


def test_an_error_that_is_no_object_refuses_the_handshake_without_a_code():
    found, _ = run(error(-32601), {"jsonrpc": "2.0", "error": "nope"})
    assert (found.action, found.reason) == (STOP, HANDSHAKE_REFUSED)
    assert found.exchanges[-1] == (INITIALIZE_METHOD, OTHER_ERROR, None)


@pytest.mark.parametrize(
    ("code", "read"),
    [(-(2**31), -(2**31)), (2**31 - 1, 2**31 - 1), (-(2**31) - 1, None), (2**31, None),
     (-32022.0, None), (True, None)],
)  # fmt: skip
def test_an_error_code_is_an_int32_and_nothing_else(code, read):
    reading = eras.classify_probe(error(code))
    assert reading.code == read
    assert (
        eras.classify_probe(error(-32022.0, data={"supported": ["2026-07-28"]})).era == ERA_LEGACY
    )


def test_what_a_server_says_about_itself_is_an_object_copied_or_nothing():
    info = {"name": "s", "version": "1"}
    found, _ = run(error(-32601), result(protocolVersion="2025-06-18", serverInfo=info))
    assert found.server_info == info and found.server_info is not info
    found, _ = run(error(-32601), result(protocolVersion="2025-06-18", serverInfo="s"))
    assert found.server_info is None
    meta = {"io.modelcontextprotocol/serverInfo": info}
    found, _ = run(result(supportedVersions=["2026-07-28"], capabilities={}, _meta=meta))
    assert found.server_info == info and found.server_info is not info
    capabilities = {"tools": {}}
    found, _ = run(result(supportedVersions=["2026-07-28"], capabilities=capabilities))
    assert found.capabilities == capabilities and found.capabilities is not capabilities


def test_a_first_id_that_is_no_int_is_refused():
    for wrong in (True, 1.0, "1"):
        with pytest.raises(TypeError):
            Detector(CLIENT, {}, first_id=wrong)


def test_classifying_something_that_is_no_object_reads_as_no_result():
    assert eras.classify_probe([]) == eras.ProbeReading(ERA_LEGACY, NO_RESULT)


# -- a header error over stdio ---------------------------------------------------------------


def test_a_header_mismatch_answering_the_initialize_is_observed_too():
    found, _ = run(error(-32601), error(-32020))
    assert (found.action, found.era, found.reason) == (STOP, ERA_LEGACY, HANDSHAKE_REFUSED)
    assert found.observations == (HEADER_ERROR_WITHOUT_HEADERS,)


def test_the_observation_is_made_once_and_only_for_a_header_mismatch():
    found, _ = run(error(-32020))
    assert found.observations == (HEADER_ERROR_WITHOUT_HEADERS,)
    for answers in (
        (result(supportedVersions=["2026-07-28"], capabilities={}),),
        (error(-32601), result(protocolVersion="2025-06-18")),
        (error(-32021, data={"requiredCapabilities": {}}),),
        (error(-32601), error(-32602, data={"supported": ["2024-11-05"]}), error(-32019)),
        (error(-32601), error(-32020.0)),
    ):
        assert run(*answers)[0].observations == (), answers


def test_a_header_mismatch_on_any_initialize_is_observed_whatever_follows():
    retried = error(-32020, data={"supported": ["2024-11-05"]})
    found, sent = run(error(-32601), retried, result(protocolVersion="2024-11-05"))
    assert (found.action, found.version) == (PROCEED, "2024-11-05") and len(sent) == 3
    assert found.observations == (HEADER_ERROR_WITHOUT_HEADERS,)
    offered = error(-32602, data={"supported": ["2024-11-05"]})
    found, _ = run(error(-32601), offered, error(-32020))
    assert found.observations == (HEADER_ERROR_WITHOUT_HEADERS,)
    found, _ = run(error(-32601), retried, error(-32020))
    assert found.observations == (HEADER_ERROR_WITHOUT_HEADERS,)


# -- under an engagement, and over HTTP -------------------------------------------------------


def run_with(*answers, **options) -> tuple[Detection, list[dict]]:
    detector = Detector(CLIENT, {}, first_id=1, **options)
    step = detector.start()
    sent = [step.message]
    for answer in answers:
        if isinstance(answer, dict):
            answer = {**answer, "id": step.identifier}
        step = detector.answer(answer)
        if isinstance(step, Detection):
            return step, sent
        sent.append(step.message)
    raise AssertionError(f"the detection did not end; it would send {step.message}")


def test_the_newest_legacy_version_is_what_an_engagement_asks_for():
    assert NEWEST_LEGACY_VERSION == "2025-11-25" and NEWEST_LEGACY_VERSION > LEGACY_REQUEST_VERSION
    found, sent = run_with(
        error(-32601), result(protocolVersion="2025-11-25"), request_version=NEWEST_LEGACY_VERSION
    )
    assert sent[1]["params"]["protocolVersion"] == "2025-11-25"
    assert (found.action, found.era, found.version) == (PROCEED, ERA_LEGACY, "2025-11-25")


def test_a_server_answering_with_the_older_version_is_spoken_to_in_it():
    found, _ = run_with(
        error(-32601), result(protocolVersion="2025-06-18"), request_version=NEWEST_LEGACY_VERSION
    )
    assert (found.action, found.version) == (PROCEED, "2025-06-18")


def test_a_refusal_naming_the_older_version_is_answered_with_it_once():
    found, sent = run_with(
        error(-32601),
        error(-32602, data={"supported": ["2025-06-18"]}),
        result(protocolVersion="2025-06-18"),
        request_version=NEWEST_LEGACY_VERSION,
    )
    versions = [m["params"]["protocolVersion"] for m in sent if m["method"] == INITIALIZE_METHOD]
    assert versions == ["2025-11-25", "2025-06-18"] and found.version == "2025-06-18"


def test_a_server_of_both_eras_is_asked_in_the_newest_version_it_offers_under_an_engagement():
    offered = result(supportedVersions=["2025-06-18", "2025-11-25"], capabilities={})
    _, sent = run_with(offered, result(protocolVersion="2025-11-25"), request_version="2025-11-25")
    assert sent[1]["params"]["protocolVersion"] == "2025-11-25"
    _, sent = run_with(offered, result(protocolVersion="2025-06-18"))
    assert sent[1]["params"]["protocolVersion"] == "2025-06-18"  # not under one: the driver's


def test_choosing_a_legacy_version_prefers_the_one_given_then_the_newest_known():
    assert eras.choose_legacy(["2025-06-18", "2025-11-25"]) == "2025-06-18"
    assert eras.choose_legacy(["2025-06-18", "2025-11-25"], "2025-11-25") == "2025-11-25"
    assert eras.choose_legacy(["2025-03-26", "2024-11-05"], "2025-11-25") == "2025-03-26"
    assert eras.choose_legacy(["2030-01-01"], "2025-11-25") is None


def test_a_version_the_detector_does_not_know_cannot_be_asked_for():
    with pytest.raises(ValueError):
        Detector(CLIENT, {}, request_version="2026-07-28")
    with pytest.raises(ValueError):
        Detector(CLIENT, {}, transport="smoke-signals")


def test_a_probe_answered_with_no_json_rpc_message_is_legacy():
    found, sent = run_with(NOT_JSON_RPC, result(protocolVersion="2025-06-18"))
    assert methods(sent) == [PROBE_METHOD, INITIALIZE_METHOD]
    assert found.probe == ProbeReading(ERA_LEGACY, NOT_JSON_RPC)
    assert found.exchanges == (
        (PROBE_METHOD, NOT_JSON_RPC, None),
        (INITIALIZE_METHOD, OTHER_RESULT, None),
    )
    assert (found.action, found.era) == (PROCEED, ERA_LEGACY)


def test_something_that_is_no_answer_is_still_refused():
    detector = Detector(CLIENT, {})
    detector.start()
    with pytest.raises(ValueError):
        detector.answer("not an answer")


def test_a_header_mismatch_over_http_is_not_a_header_error_made_where_there_are_none():
    found, _ = run_with(error(-32020), transport=TRANSPORT_HTTP)
    assert (found.action, found.era, found.reason) == (STOP, ERA_MODERN, MODERN_REFUSED)
    assert found.observations == ()
    found, _ = run_with(error(-32601), error(-32020), transport=TRANSPORT_HTTP)
    assert found.observations == ()


def test_a_stop_with_an_error_keeps_its_code_and_data_as_the_server_sent_them():
    found, _ = run_with(error(-32021, data={"requiredCapabilities": {"elicitation": {}}}))
    assert found.error == {"code": -32021, "data": {"requiredCapabilities": {"elicitation": {}}}}
    found, _ = run_with(error(-32020))
    assert found.error == {"code": -32020, "data": None}
    found, _ = run_with(result(supportedVersions=["2030-01-01"], capabilities={}))
    assert (found.reason, found.error) == (NO_COMMON_VERSION, None)
    found, _ = run_with(error(-32601), result(protocolVersion="2099-01-01"))
    assert (found.reason, found.version, found.error) == (UNKNOWN_VERSION, "2099-01-01", None)


# -- a stop carries a reason the report knows --------------------------------------------------


def test_a_stop_is_made_with_each_reason_of_stop_reasons_and_proceeding_needs_none():
    for reason in eras.STOP_REASONS:
        assert Detection(action=STOP, era=ERA_LEGACY, reason=reason).reason == reason
    assert Detection(action=PROCEED, era=ERA_MODERN, version=MODERN_VERSION).reason is None


@pytest.mark.parametrize("reason", ["something_new", None], ids=["unknown", "none"])
def test_a_stop_with_a_reason_stop_reasons_does_not_hold_is_refused_where_it_is_made(reason):
    with pytest.raises(ValueError, match="STOP_REASONS"):
        Detection(action=STOP, era=ERA_LEGACY, reason=reason)


def test_a_stop_replaced_with_an_unknown_reason_is_refused():
    made = Detection(action=STOP, era=ERA_LEGACY, reason=NO_RESULT)
    with pytest.raises(ValueError, match="STOP_REASONS"):
        dataclasses.replace(made, reason="new")


def test_a_subclass_whose_default_reason_stop_reasons_does_not_hold_is_refused():
    @dataclasses.dataclass(frozen=True, slots=True)
    class LegacyStop(Detection):
        action: str = STOP
        reason: str | None = "new"

    with pytest.raises(ValueError, match="STOP_REASONS"):
        LegacyStop()
