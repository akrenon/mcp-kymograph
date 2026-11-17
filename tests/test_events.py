"""The schema: classification of messages, and the parse failures that must not crash us."""

from mcp_kymograph.events import (
    MAX_ID_LENGTH,
    MAX_METHOD_LENGTH,
    ParseKind,
    analyse,
    inspect_message,
)


def parse_of(raw: bytes, **kwargs):
    _, _, parse = inspect_message(raw, **kwargs)
    return parse


def test_request_is_a_method_with_an_id():
    parse = analyse({"jsonrpc": "2.0", "id": 3, "method": "tools/call"})
    assert (parse.kind, parse.method, parse.id) == (ParseKind.REQUEST, "tools/call", 3)


def test_notification_is_a_method_without_an_id():
    parse = analyse({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert parse.kind is ParseKind.NOTIFICATION
    assert parse.id is None


def test_result_response():
    parse = analyse({"jsonrpc": "2.0", "id": 3, "result": {"ok": True}})
    assert parse.kind is ParseKind.RESPONSE
    assert parse.is_error is False


def test_error_response_is_flagged():
    parse = analyse({"jsonrpc": "2.0", "id": 3, "error": {"code": -32600}})
    assert parse.kind is ParseKind.RESPONSE
    assert parse.is_error is True


def test_batch_is_recognised_rather_than_misread():
    parse = analyse([{"jsonrpc": "2.0", "method": "a"}])
    assert parse.kind is ParseKind.BATCH


def test_method_and_id_are_capped_because_they_come_from_the_traffic():
    parse = analyse({"method": "m" * 5000, "id": "i" * 5000})
    assert len(parse.method) == MAX_METHOD_LENGTH
    assert len(parse.id) == MAX_ID_LENGTH


def test_an_absurdly_wide_id_is_dropped_rather_than_breaking_the_writer():
    assert analyse({"id": 10**400, "result": 1}).id is None


def test_a_boolean_is_not_a_valid_id():
    assert analyse({"id": True, "result": 1}).id is None


def test_unparseable_message_is_marked_not_dropped():
    text, document, parse = inspect_message(b"{not json")
    assert document is None
    assert parse.ok is False
    assert parse.error_reason == "invalid_json"
    assert text == "{not json"


def test_truncated_message_is_not_parsed_at_all():
    parse = parse_of(b'{"jsonrpc":"2.0"', truncated=True)
    assert parse.error_reason == "truncated"


def test_invalid_utf8_survives_as_replacement_text():
    text, document, parse = inspect_message(b'{"a": "\xff\xfe"}')
    assert document is None
    assert parse.error_reason == "not_utf8"
    assert text  # decoded with replacement rather than raising


def test_nan_is_not_json_and_is_refused():
    # CPython accepts NaN/Infinity; JSON does not, and json.dumps would then refuse to
    # write the event back out. Refusing at parse time keeps the recording writable.
    assert parse_of(b'{"x": NaN}').error_reason == "non_json_constant"


def test_duplicate_keys_fall_back_to_text_rather_than_losing_half_the_message():
    text, document, parse = inspect_message(b'{"result":"ok","result":"evil"}')
    assert document is None
    assert parse.error_reason == "duplicate_keys"
    assert "ok" in text and "evil" in text


# -- the flags the framer sets ------------------------------------------------------
# These only mean something once inspect_message honours them, so the seam is checked
# rather than left to the proxy to discover.


def test_an_incomplete_frame_is_not_parsed():
    _, document, parse = inspect_message(b'{"half":', incomplete=True)
    assert document is None
    assert parse.error_reason == "incomplete"


def test_truncated_outranks_incomplete_because_it_carries_no_bytes():
    _, _, parse = inspect_message(b"", truncated=True, incomplete=True)
    assert parse.error_reason == "truncated"
