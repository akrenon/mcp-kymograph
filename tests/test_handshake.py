"""The realistic handshake: id-less notifications and answers that are not the next line.

Held against `tests/fixtures/realistic_handshake.jsonl`, which is the reference for the shape
a real client/server pair produces. The two properties under test are the ones that shape
breaks in a proxy that took shortcuts:

* a message without an id is a **notification**. Nothing may book it as a request that is
  owed an answer, because no answer will ever come.
* an answer belongs to its question by **id**, never by position. The reference interleaves
  notifications so that counting would give the wrong pairing.
"""

import json
from pathlib import Path

import pytest

from mcp_kymograph.engine import Engine
from mcp_kymograph.events import Direction
from mcp_kymograph.masking import HANDLE_PREFIX, HANDLE_SUFFIX, PLACEHOLDER
from test_proxy import TOY, Session, run

#: Stands in for "this document carried no id at all", which is not the same as id null.
ABSENT = object()

REFERENCE = Path(__file__).parent / "fixtures" / "realistic_handshake.jsonl"
REALISTIC_ARGS = [__import__("sys").executable, TOY, "--mode", "realistic"]


def reference_events() -> list[dict]:
    return [json.loads(line) for line in REFERENCE.read_text().splitlines() if line]


def reference_messages() -> list[dict]:
    return [event for event in reference_events() if event["type"] == "message"]


def client_lines() -> list[bytes]:
    """The client half of the reference, replayed verbatim and in order.

    Driving the run from the reference rather than from a hand-written copy is the point: if
    the two ever drift apart, the test is exercising the shape it claims to.
    """
    return [
        json.dumps(event["payload"]["data"], separators=(",", ":")).encode() + b"\n"
        for event in reference_messages()
        if event["direction"] == "client_to_server"
    ]


class Watcher:
    """Records what the engine concluded about every message it decided on.

    A rule, because `responded_method` is only handed to a rule — it is the engine's own
    answer to "which question is this the answer to", and asking it any other way would test
    a reimplementation rather than the thing itself.
    """

    name = "watcher"
    #: Both directions, so the client's own requests are seen too. A question must not be
    #: told it is the answer to itself, and that case only exists on the client side.
    directions = frozenset({Direction.SERVER_TO_CLIENT, Direction.CLIENT_TO_SERVER})

    def __init__(self) -> None:
        self.seen: list[tuple] = []

    def act(self, direction, document, responded_method):
        identifier = document.get("id", ABSENT)
        self.seen.append((identifier, document.get("method"), responded_method))
        return

    def _of_kind(self, kind: str) -> list[tuple]:
        def classify(seen):
            identifier, method, _ = seen
            if method is None:
                return "response"
            return "notification" if identifier is ABSENT else "request"

        return [seen for seen in self.seen if classify(seen) == kind]

    @property
    def responses(self) -> list[tuple]:
        return self._of_kind("response")

    @property
    def requests(self) -> list[tuple]:
        return self._of_kind("request")

    @property
    def notifications(self) -> list[tuple]:
        return self._of_kind("notification")


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    """One proxied run against the realistic mode, shared by every check below.

    Driven **conversationally**, one turn at a time, because that is what produces the
    reference's interleaving. Sending all four client lines at once instead puts every
    request in the recording ahead of every answer — a legitimate recording of a different
    conversation, and not the shape under test here.
    """
    watcher = Watcher()
    tmp_path = tmp_path_factory.mktemp("handshake")
    initialize, initialized, tools_list, tools_call = client_lines()

    async def scenario():
        async with Session(tmp_path, REALISTIC_ARGS, engine=Engine([watcher])) as s:
            s.send(initialize)
            await s.until_received(1)
            # The notification draws no answer, so it is sent together with the request that
            # follows it — exactly as the reference has them, back to back.
            s.send(initialized + tools_list)
            await s.until_received(3)  # the tools/list answer, then the server's log line
            s.send(tools_call)
            await s.until_received(5)  # progress, then the result it belongs to
        return s

    done = run(scenario)
    done.watcher = watcher
    return done


def messages_of(session) -> list[dict]:
    return [
        json.loads(line)
        for line in session.path.read_text().splitlines()
        if json.loads(line)["type"] == "message"
    ]


# -- the produced recording against the reference --------------------------------------


def shape(event) -> tuple:
    """Everything the correlation claims rest on: who spoke, what it was, and which id."""
    parse = event["parse"]
    return (event["direction"], parse["kind"], parse["method"], parse["id"])


def test_the_run_produces_the_shape_the_reference_describes(session):
    assert [shape(m) for m in messages_of(session)] == [shape(m) for m in reference_messages()]


def test_the_message_contents_match_the_reference_except_where_masking_applies(session):
    """Exactly one message differs from the reference, and only in one field: the
    `params.progressToken` of the progress notification, which is a **protocol handle** and
    is therefore carried as a stable pseudonym rather than as itself.

    The reference shows the raw value because it is a hand-written transcript of what went
    over the wire. What the recording holds is deliberately not that: the correlation is kept
    and the value is not (see masking.PROTOCOL_HANDLE_PATHS). Anything
    beyond this one field differing would be a fault."""
    produced = messages_of(session)
    expected = reference_messages()

    differing = [
        (p["payload"]["data"], r["payload"]["data"])
        for p, r in zip(produced, expected, strict=True)
        if p["payload"]["data"] != r["payload"]["data"]
    ]
    assert len(differing) == 1, "only the known handle substitution may differ"
    produced_data, reference_data = differing[0]
    assert reference_data["method"] == "notifications/progress"

    handle = produced_data["params"]["progressToken"]
    assert handle.startswith(HANDLE_PREFIX) and handle.endswith(HANDLE_SUFFIX)
    assert handle != PLACEHOLDER, "a handle is pseudonymised, not blanked"
    assert "echo-3" not in json.dumps(produced_data), "and the real value is nowhere in it"
    assert reference_data["params"]["progressToken"] == "echo-3"

    # And everything else in that same message came through untouched.
    assert produced_data["params"]["progress"] == reference_data["params"]["progress"]
    assert produced_data["params"]["total"] == reference_data["params"]["total"]


def test_the_real_handle_appears_nowhere_in_the_whole_recording(session):
    """The narrow check above looks at one message. This looks at the file."""
    assert "echo-3" not in session.path.read_text()


def test_the_substitution_is_declared_rather_than_silent(session):
    """A substituted value is only acceptable because the recording says where it happened —
    and that holds for a pseudonym exactly as it does for a blanked field."""
    progress = next(
        m for m in messages_of(session) if m["parse"]["method"] == "notifications/progress"
    )
    assert progress["payload"]["redactions"] == ["params.progressToken"]
    assert progress["payload"]["redaction_count"] == 1


def test_the_bytes_match_the_reference_too(session):
    """size_bytes is the only place byte fidelity is readable at all, so it is compared
    rather than skipped: the proxy must not have reserialised anything on the way through."""
    produced = [m["size_bytes"] for m in messages_of(session)]
    assert produced == [m["size_bytes"] for m in reference_messages()]


# -- a message without an id is a notification -----------------------------------------


def test_every_id_less_message_is_recorded_as_a_notification(session):
    notifications = [m for m in messages_of(session) if m["parse"]["kind"] == "notification"]

    assert [m["parse"]["method"] for m in notifications] == [
        "notifications/initialized",
        "notifications/message",
        "notifications/progress",
    ], "all three, in both directions, and none of them missing"
    for notification in notifications:
        assert notification["parse"]["id"] is None
        assert "id" not in notification["payload"]["data"], "no id was invented for it either"


def test_a_notification_is_never_treated_as_a_question_awaiting_an_answer(session):
    """The engine keeps exactly one correlation table, id -> method, and it is the only place
    a message could be booked as outstanding. A notification must not enter it: nothing will
    ever arrive carrying that id, so a proxy that remembered one would be holding a row that
    can never be cleared."""
    engine = Engine([Watcher()])
    for event in reference_messages():
        direction = Direction(event["direction"])
        raw = json.dumps(event["payload"]["data"], separators=(",", ":")).encode()
        engine.observe(direction, raw)

    remembered = engine._method_by_id  # noqa: SLF001 - the table under test
    assert set(remembered) == {1, 2, 3}, "only the three requests, never a notification"
    assert "notifications/initialized" not in remembered.values()


def test_the_notifications_did_not_stall_the_run(session):
    """The behavioural half of the same claim: the run ends by itself, on the server's own
    exit, rather than on a timeout or a torn-down pump."""
    assert session.outcome.reason == "server_exited"
    assert session.outcome.exit_code == 0
    assert session.outcome.closing_event_written is True


def test_nothing_warned_about_the_notifications(session):
    """There is no orphaned-request warning in this tool to trigger — it holds no pending-request
    state — so the check is that the run stayed quiet rather than that a specific warning was
    absent. A future pending-request table would have to keep this true."""
    assert session.notices == [], f"a clean realistic run must say nothing: {session.notices}"


# -- an answer belongs to its question by id, not by position --------------------------


def test_each_answer_is_matched_to_its_own_request(session):
    """id 3 is the case that matters: `notifications/progress` sits between the tools/call
    request and its result, so the result is *not* the next thing on the wire after the
    question. ids 1 and 2 are adjacent in the reference and would come out right under
    positional matching too — they are here as the control, not as the evidence."""
    assert session.watcher.responses == [
        (1, None, "initialize"),
        (2, None, "tools/list"),
        (3, None, "tools/call"),
    ]


def test_the_notification_between_a_question_and_its_answer_is_not_mistaken_for_one(session):
    """The same interleaving read from the other side: the notifications carry no id and are
    correlated to nothing, even though one of them sits inside an open exchange."""
    assert session.watcher.notifications == [
        (ABSENT, "notifications/initialized", None),
        (ABSENT, "notifications/message", None),
        (ABSENT, "notifications/progress", None),
    ]


def test_a_question_is_never_reported_as_the_answer_to_itself(session):
    """A request carries both a method and an id, and its id is in the correlation table —
    its own row, just written. Correlating on the id alone would hand a request back the
    method it just declared, and a rule keying on "this answers tools/list" would then fire
    on the tools/list *request* as well as on its answer."""
    assert session.watcher.requests == [
        (1, "initialize", None),
        (2, "tools/list", None),
        (3, "tools/call", None),
    ]


def test_positional_matching_would_have_got_this_wrong(session):
    """States plainly what the interleaving is worth. Pairing the n-th server message with
    the n-th client request pairs a notification with tools/call — so a green result above is
    evidence about correlation, not a coincidence of ordering."""
    from_server = [
        m["payload"]["data"] for m in messages_of(session) if m["direction"] == "server_to_client"
    ]
    positional = from_server[2]  # third thing the server said
    assert positional.get("method") == "notifications/message", "the third is a notification"
    assert "id" not in positional, "so counting would have answered id 3 with a notification"
