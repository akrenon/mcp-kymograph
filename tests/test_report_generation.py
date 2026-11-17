"""Which generation of the protocol each run spoke, and whether it sent a token, in the report:
as recorded, one sentence each, never a value.

The words are tested on recordings as they are read (``_Recording``), and once through the report
of the fixture engagement (tests/test_report.py), whose runs were made by this version.
"""

from __future__ import annotations

import pytest

from mcp_kymograph import eras, report
from mcp_kymograph.report import RECORDED, _generation_words, _Recording, _token_words
from test_report import NOW, filed, section  # noqa: F401 - filed is a fixture


def recording(**fields) -> _Recording:
    return _Recording("read", **fields)


def decided(**fields) -> dict:
    return {
        "type": "era_decided",
        "era": "legacy",
        "version": "2025-11-25",
        "outcome": "proceed",
        "reason": None,
        "probe": {"outcome": "other_error", "code": -32600, "supported": []},
        "exchanges": [],
        "refusal": None,
        "declared": None,
        "differs": None,
        "observations": [],
        **fields,
    }


def test_a_legacy_run_says_its_version_and_how_the_probe_was_answered():
    ((kind, words),) = _generation_words("run 3", recording(decided=decided()))

    assert kind == RECORDED
    assert words == (
        "Generation for run 3: `legacy`, protocol version `2025-11-25`; the probe "
        "`server/discover` was answered as `other_error`."
    )


def test_a_modern_run_says_so():
    modern = decided(era="modern", version="2026-07-28", probe={"outcome": "discover_result"})
    ((_, words),) = _generation_words("run 1", recording(decided=modern))

    assert "`modern`, protocol version `2026-07-28`" in words and "`discover_result`" in words


def test_a_stop_names_its_reason_and_the_code_and_says_no_listing_was_sent():
    stop = decided(
        era="modern",
        version=None,
        outcome="stop",
        reason="modern_refused",
        probe={"outcome": "modern_error", "code": -32021, "supported": []},
        refusal={"code": -32021, "data": {"requiredCapabilities": {"x": {}}}},
    )
    ((kind, words),) = _generation_words("run 2", recording(decided=stop))

    assert kind == RECORDED
    assert words.startswith("Opening stopped for run 2: `modern`; reason `modern_refused`")
    assert "error code `-32021`" in words and words.endswith("No listing was sent.")
    assert "requiredCapabilities" not in words  # the server's data stays in the recording


def test_a_missing_reason_and_a_missing_answer_are_said_without_a_span():
    """A value the recording lacks is said in words; ``none`` in a span would read as data. A
    probe without an outcome is not said to have been sent: only that no answer is recorded."""
    stop = decided(era="modern", version=None, outcome="stop", reason=None, probe={})
    ((_, stopped),) = _generation_words("run 2", recording(decided=stop))
    ((_, spoken),) = _generation_words("run 3", recording(decided=decided(probe={})))

    assert stopped == (
        "Opening stopped for run 2: `modern`; no reason recorded; no answer to the probe is "
        "recorded. No listing was sent."
    )
    assert spoken == (
        "Generation for run 3: `legacy`, protocol version `2025-11-25`; no answer to the probe "
        "`server/discover` is recorded."
    )
    assert "none" not in report.CODE_SPAN_IDENTIFIERS


@pytest.mark.parametrize(
    ("outcome", "said"),
    [
        (eras.NO_ANSWER, "the probe `server/discover` got no answer (`no_answer`)."),
        (
            eras.CLOSED,
            "the connection was closed before the probe `server/discover` was answered "
            "(`connection_closed`).",
        ),
    ],
)
def test_a_probe_that_got_no_answer_is_not_said_to_have_been_answered(outcome, said):
    ((_, spoken),) = _generation_words(
        "run 3", recording(decided=decided(probe={"outcome": outcome}))
    )

    assert spoken.endswith(said)
    assert "answered as" not in spoken


@pytest.mark.parametrize(
    ("outcome", "said"),
    [
        (eras.NO_ANSWER, "; the probe got no answer (`no_answer`). No listing was sent."),
        (
            eras.CLOSED,
            "; the connection was closed before the probe was answered (`connection_closed`). "
            "No listing was sent.",
        ),
    ],
)
def test_a_stop_after_a_probe_that_got_no_answer_says_so(outcome, said):
    stop = decided(outcome="stop", reason=eras.HANDSHAKE_UNANSWERED, probe={"outcome": outcome})
    ((_, stopped),) = _generation_words("run 2", recording(decided=stop))

    assert stopped.endswith(said)
    assert "reason `handshake_unanswered`" in stopped and "answered as" not in stopped


def test_a_stop_reason_this_version_does_not_know_is_said_without_it():
    stop = decided(outcome="stop", reason="a secure reason", probe={})
    ((_, stopped),) = _generation_words("run 2", recording(decided=stop))

    assert "a reason this version does not know" in stopped and "secure" not in stopped


def test_a_generation_the_file_declares_and_the_server_did_not_speak_is_an_observation():
    said = decided(declared={"era": "modern", "version": None}, differs=True)
    sentences = _generation_words("run 4", recording(decided=said))

    assert len(sentences) == 2
    assert sentences[1][1] == (
        "The engagement file declares `modern` for the endpoint of run 4, and the server spoke "
        "`legacy`, protocol version `2025-11-25`: an observation, which stopped nothing."
    )
    agreeing = decided(declared={"era": "legacy", "version": None}, differs=False)
    assert len(_generation_words("run 4", recording(decided=agreeing))) == 1


def test_a_recording_with_no_decision_says_nothing_of_a_generation():
    assert _generation_words("run 5", recording()) == []


def test_what_the_server_sent_is_shown_as_a_code_span_and_not_as_markdown():
    odd = decided(era="legacy", version="`**x**`")
    ((_, words),) = _generation_words("run 6", recording(decided=odd))

    assert "protocol version `` `**x**` ``" in words


@pytest.mark.parametrize(
    ("auth", "words"),
    [
        (
            {"identity": "reader", "role": "read-only", "token_used": True, "source": "env",
             "env_name": "ACME_TOKEN"},
            "A token was used for run 1 as identity `reader` (role `read-only`) "
            "(env `ACME_TOKEN`).",
        ),
        (
            {"identity": None, "role": None, "token_used": True, "source": "file"},
            "A token was used for run 1 (a file).",
        ),
        (
            {"identity": "anonymous", "role": "not signed in", "token_used": False,
             "source": "none"},
            "No token was sent for run 1 as identity `anonymous` (role `not signed in`): the "
            "identity sends no `Authorization` header.",
        ),
    ],
)  # fmt: skip
def test_the_token_is_said_to_be_used_with_where_it_came_from_and_never_its_value(auth, words):
    assert _token_words("run 1", recording(auth=auth)) == words


def test_a_run_that_sent_no_token_and_chose_no_identity_says_nothing_of_one():
    assert _token_words("run 1", recording(auth=None)) is None


def test_the_report_of_the_fixture_engagement_says_the_generation_of_every_run(filed):  # noqa: F811
    with report.Store.open_read_only(filed["database"]) as store:
        made = report.build(
            engagement_path=filed["held"],
            store=store,
            runs_dir=filed["runs"],
            out_dir=filed["runs"],
            now=NOW,
        )
    parsed = report.parse(report.render(made))

    two = section(parsed, 2).sentences
    generation = [s for s in two if s.words.startswith(("Generation for run", "Opening stopped"))]
    assert len(generation) == 5  # the four runs, and the poison run cut short
    assert {s.kind for s in generation} == {report.RECORDED}
    assert all("`legacy`" in s.line() for s in generation)
    assert all("`server/discover`" in s.line() for s in generation)
