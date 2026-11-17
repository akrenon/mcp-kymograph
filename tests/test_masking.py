"""Masking is the part most likely to cause trouble later, so it is tested on its own.

No I/O, no network, no clock.
"""

import json

from mcp_kymograph.masking import (
    HANDLE_PREFIX,
    HANDLE_SUFFIX,
    PLACEHOLDER,
    PROTOCOL_HANDLE_PATHS,
    Masker,
    normalise_key,
)


def test_normalise_key_strips_separators_and_case():
    assert normalise_key("X-API-Key") == "xapikey"
    assert normalise_key("api_key") == "apikey"
    assert normalise_key("apiKey") == "apikey"


def test_structural_masking_replaces_the_whole_value():
    masker = Masker()
    masked, paths = masker.mask_json({"api_key": "hunter2", "name": "fetch"})
    assert masked == {"api_key": PLACEHOLDER, "name": "fetch"}
    assert paths == ["api_key"]


def test_structural_masking_covers_key_spelling_variants():
    masker = Masker()
    document = {"X-API-Key": "a", "apiKey": "b", "access_token": "c", "Set-Cookie": "d"}
    masked, _ = masker.mask_json(document)
    assert set(masked.values()) == {PLACEHOLDER}


def test_a_masked_value_is_replaced_whatever_its_type():
    masker = Masker()
    masked, _ = masker.mask_json({"secret": {"nested": ["structure", 1, True]}})
    assert masked == {"secret": PLACEHOLDER}


def test_placeholder_reveals_nothing_about_length():
    masker = Masker()
    short, _ = masker.mask_json({"token": "a"})
    long, _ = masker.mask_json({"token": "a" * 5000})
    assert short == long


def test_paths_point_through_objects_and_arrays():
    masker = Masker()
    document = {"params": {"items": [{"ok": 1}, {"password": "x"}]}}
    _, paths = masker.mask_json(document)
    assert paths == ["params.items[1].password"]


def test_greedy_matching_over_masks_and_that_is_the_accepted_trade():
    # Pinned deliberately: 'token' matches 'total_tokens' and 'auth' matches 'author'.
    # Losing these from a recording is a nuisance; leaking a credential is not.
    masker = Masker()
    masked, _ = masker.mask_json({"usage": {"total_tokens": 5}, "author": "someone"})
    assert masked == {"usage": {"total_tokens": PLACEHOLDER}, "author": PLACEHOLDER}


def test_extra_keys_are_honoured():
    masker = Masker(extra_keys=["licenceRef"])
    masked, _ = masker.mask_json({"licence_ref": "L-1", "other": "keep"})
    assert masked == {"licence_ref": PLACEHOLDER, "other": "keep"}


def test_secrets_inside_prose_are_masked_by_shape():
    masker = Masker()
    text = "call with Authorization: Bearer abcdefghijklmnop and you are in"
    masked, hits = masker.mask_text(text)
    assert hits == 1
    assert "abcdefghijklmnop" not in masked
    assert "Bearer " + PLACEHOLDER in masked


def test_shape_rules_cover_the_common_credential_formats():
    masker = Masker()
    samples = [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
        "sk-abcdefghijklmnopqrstuvwx",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "github_pat_abcdefghijklmnopqrstuvwxyz01",
        "xoxb-1234567890-abcdefg",
        "AKIAIOSFODNN7EXAMPLE",
    ]
    for sample in samples:
        masked, hits = masker.mask_text(f"value is {sample} ok")
        assert hits >= 1, sample
        assert sample not in masked, sample


def test_prose_masking_reaches_strings_nested_in_a_document():
    masker = Masker()
    document = {"content": [{"text": "my key is sk-abcdefghijklmnopqrstuvwx"}]}
    masked, paths = masker.mask_json(document)
    assert "sk-abcdefghijklmnopqrstuvwx" not in str(masked)
    assert paths == ["content[0].text"]


def test_argv_keeps_only_the_basename_of_the_server_binary():
    masker = Masker()
    masked, _ = masker.mask_argv(["/opt/vendor/bin/mcp-server", "--verbose"])
    assert masked == ["mcp-server", "--verbose"]


def test_argv_masks_credentials_in_both_flag_styles():
    masker = Masker()
    argv = ["srv", "--api-key=hunter2", "--token", "abc123", "--port", "8080"]
    masked, count = masker.mask_argv(argv)
    assert masked == ["srv", f"--api-key={PLACEHOLDER}", "--token", PLACEHOLDER, "--port", "8080"]
    assert count == 2


def test_argv_masks_a_bare_credential_by_shape():
    masker = Masker()
    masked, count = masker.mask_argv(["srv", "sk-abcdefghijklmnopqrstuvwx"])
    assert masked == ["srv", PLACEHOLDER]
    assert count == 1


# -- protocol handles: pseudonymised, never blanked and never passed through -------------

SALT = b"a fixed salt so a test can compare two maskers"
PROGRESS = {"jsonrpc": "2.0", "method": "notifications/progress"}


def progress(token):
    return {**PROGRESS, "params": {"progressToken": token, "progress": 1, "total": 2}}


def test_a_protocol_handle_is_substituted_not_blanked():
    """Blanking it would destroy the only thing it carries — which call the progress belongs
    to — and that correlation is what this tool exists to show."""
    masked, paths = Masker().mask_json(progress("echo-3"))
    handle = masked["params"]["progressToken"]

    assert handle.startswith(HANDLE_PREFIX) and handle.endswith(HANDLE_SUFFIX)
    assert handle != PLACEHOLDER
    assert paths == ["params.progressToken"], "still declared, like any other substitution"
    assert masked["params"]["progress"] == 1, "nothing around it is touched"


def test_the_original_value_survives_nowhere():
    masked, _ = Masker().mask_json(progress("echo-3"))
    assert "echo-3" not in json.dumps(masked)


def test_the_same_handle_reads_the_same_way_all_through_one_run():
    """The whole point: two progress notifications for the same call must still be readable
    as belonging together."""
    masker = Masker()
    first, _ = masker.mask_json(progress("call-a"))
    second, _ = masker.mask_json(progress("call-a"))
    other, _ = masker.mask_json(progress("call-b"))

    assert first["params"]["progressToken"] == second["params"]["progressToken"]
    assert first["params"]["progressToken"] != other["params"]["progressToken"]


def test_two_runs_do_not_share_pseudonyms():
    """Stable within a recording, meaningless between two. Otherwise the pseudonyms would
    themselves become a way to cross-reference one session against another."""
    assert Masker().pseudonym("call-a") != Masker().pseudonym("call-a")
    assert Masker(handle_salt=SALT).pseudonym("call-a") == Masker(handle_salt=SALT).pseudonym(
        "call-a"
    )


def test_a_number_and_the_string_of_it_are_different_handles():
    masker = Masker(handle_salt=SALT)
    assert masker.pseudonym(1) != masker.pseudonym("1")


def test_the_pseudonym_cannot_be_checked_against_a_guess_without_the_salt():
    """Keyed, not a plain digest. A reader holding the recording and a suspected value must
    not be able to confirm the match by hashing their guess.

    Several encodings are tried rather than the one the implementation happens to use: the
    claim is "this is not a plain digest of the value", and pinning it to one guess at the
    internal format would let the claim pass while being false for another."""
    import hashlib

    masker = Masker(handle_salt=SALT)
    pseudonym = masker.pseudonym("call-a")
    for guess in (b"call-a", b"s:call-a", b"n:call-a", b"call-a\n"):
        assert hashlib.sha256(guess).hexdigest()[:12] not in pseudonym, guess


# -- and everything the rule deliberately does not cover --------------------------------


def test_the_same_key_name_elsewhere_is_payload_and_stays_blanked():
    """Anchored on the path, not the name. A caller's own argument that happens to be called
    progressToken is data someone sent, not a handle the protocol issued."""
    masked, paths = Masker().mask_json(
        {"params": {"name": "echo", "arguments": {"progressToken": "hunter2"}}}
    )
    assert masked["params"]["arguments"]["progressToken"] == PLACEHOLDER
    assert paths == ["params.arguments.progressToken"]


def test_a_session_identifier_is_not_a_handle():
    """Over a networked transport, holding an MCP session id is what grants access to the
    session. It is closer to a bearer token than to a correlation id, so it stays blanked."""
    masked, _ = Masker().mask_json({"params": {"sessionId": "s-1"}})
    assert masked["params"]["sessionId"] == PLACEHOLDER


def test_a_handle_that_is_not_a_scalar_falls_back_to_blanking():
    """Fail closed on shape as well as on path: whatever this is, it is not the scalar the
    protocol calls a progress token, so it does not get the gentler treatment."""
    for value in ({"nested": 1}, ["a"], True, None):
        masked, _ = Masker().mask_json({"params": {"progressToken": value}})
        assert masked["params"]["progressToken"] == PLACEHOLDER, value


def test_the_handle_set_is_closed():
    """A reader of this test should be able to see the whole list at a glance, and adding to
    it should be a deliberate act that shows up in a diff."""
    assert {"params.progressToken", "params._meta.progressToken"} == PROTOCOL_HANDLE_PATHS


def test_the_declared_path_is_reached_in_both_of_its_protocol_positions():
    masked, paths = Masker().mask_json(
        {"params": {"_meta": {"progressToken": "echo-9"}, "name": "echo"}}
    )
    assert masked["params"]["_meta"]["progressToken"].startswith(HANDLE_PREFIX)
    assert paths == ["params._meta.progressToken"]


def _sk() -> str:
    """A made-up key of a known shape, put together when the test runs."""
    return "".join(["sk", "-abcdefgh", "ijklmnop"])


def test_a_secret_shaped_key_is_masked_in_the_result_and_in_paths():
    """A key of a credential's shape never reaches the recording, nor its paths."""
    masked, paths = Masker().mask_json({_sk(): 1})
    assert _sk() not in repr(masked)
    assert _sk() not in repr(paths)
    assert paths


def test_a_key_that_holds_a_pair_loses_the_secret_in_key_and_paths():
    """``name=secret`` as a key leaves the secret neither in the key nor in a path."""
    masked, paths = Masker().mask_json({f"access_token={_sk()}": 1})
    assert _sk() not in repr(masked)
    assert _sk() not in repr(paths)
    assert list(masked.values()) == [PLACEHOLDER]


def test_a_secret_shaped_key_is_in_no_path_below_it():
    """The masked key stands in the path of every child, one that is masked itself too."""
    document = {"a": {_sk(): {"b": "x", "c": f"Bearer {_sk()}"}}}
    masked, paths = Masker().mask_json(document)
    assert _sk() not in repr(masked)
    assert _sk() not in repr(paths)
    assert len(paths) == 2
    assert any(path.endswith(".c") for path in paths)


def test_keys_that_read_the_same_masked_are_all_kept():
    """A collision of masked keys numbers the later ones and loses no entry."""
    masker = Masker()
    other = _sk()[:-1] + "q"
    shown, _ = masker.mask_text(_sk())
    assert masker.mask_text(other)[0] == shown
    masked, paths = masker.mask_json({_sk(): 1, other: 2, shown + "#2": 3})
    assert len(masked) == 3
    assert sorted(masked.values()) == [1, 2, 3]
    assert masked[shown] == 1
    assert masked[shown + "#2"] == 2
    assert len(set(paths)) == len(paths)


def test_harmless_keys_stay_as_they_are():
    """Keys without a hit are unchanged and add nothing to paths."""
    masked, paths = Masker().mask_json({"name": "echo", "tools": [{"name": "t"}]})
    assert masked == {"name": "echo", "tools": [{"name": "t"}]}
    assert paths == []


def test_mask_argv_replaces_what_follows_a_secret_flag_whatever_it_is():
    """A value that starts with ``-`` after a secret flag is replaced, except ``--``."""
    masker = Masker()
    assert masker.mask_argv(["srv", "--password", "-hunter2"]) == (
        ["srv", "--password", PLACEHOLDER],
        1,
    )
    assert masker.mask_argv(["srv", "--token", "--weird"]) == (["srv", "--token", PLACEHOLDER], 1)
    assert masker.mask_argv(["srv", "--password", "--"]) == (["srv", "--password", "--"], 0)
    assert masker.mask_argv(["srv", "--token", "--api-key", "X"]) == (
        ["srv", "--token", PLACEHOLDER, PLACEHOLDER],
        2,
    )


def test_many_keys_that_mask_alike_are_walked_in_linear_time():
    """Each collision goes on from the last number taken, not from #2."""
    import time

    keys = {f"sk-{i:020d}abcdefgh": i for i in range(20_000)}
    started = time.perf_counter()
    masked, _ = Masker().mask_json(keys)
    assert time.perf_counter() - started < 2.0
    assert len(masked) == len(keys)


def test_a_key_and_its_value_that_both_hold_a_secret_are_one_path():
    """One field, one entry in paths: the redaction count is the count of fields."""
    masked, paths = Masker().mask_json({"sk-abcdefghijklmnop": "sk-abcdefghijklmnop"})
    assert "abcdefghijklmnop" not in repr(masked)
    assert len(paths) == 1


def test_a_value_placed_under_a_secret_shaped_key_comes_back_out():
    """The recorder masks a value in a skeleton of its path and takes it back out: the key it
    put there may come back masked, and the value is still found."""
    from mcp_kymograph.paths import parse
    from mcp_kymograph.recorder import _place, _take

    steps = parse("result.ghp_A1b2A1b2A1b2A1b2A1b2.items[3]").steps
    masked, paths = Masker().mask_json(_place(steps, "kept"))
    assert "ghp_A1b2" not in repr(masked) and "ghp_A1b2" not in repr(paths)
    assert _take(steps, masked) == "kept"


def test_a_rule_change_under_a_secret_shaped_key_is_recorded_with_its_real_position(tmp_path):
    """The skeleton puts every list position at 0; the recorded redaction has the real one,
    and the key as it was masked — under a masked key as under any other."""
    from mcp_kymograph.recorder import Recorder

    with Recorder.open(tmp_path / "e.jsonl", run_id="r", masker=Masker()) as recorder:
        payload = recorder._value_payload(
            "result.ghp_A1b2A1b2A1b2A1b2A1b2.items[3]", "sk-abcdefghijklmnop"
        )
    assert "abcdefghijklmnop" not in repr(payload) and "ghp_A1b2" not in repr(payload)
    assert payload.redactions and all(p.endswith("items[3]") for p in payload.redactions[-1:])


def test_a_deep_chain_of_secret_shaped_keys_is_walked_in_linear_time():
    """Each key's path is one append, not a search through what its subtree put there."""
    import time

    document = {"leaf": ["sk-abcdefghijklmnop"] * 5_000}
    for depth in range(250):
        document = {f"sk-{depth:016d}abcd": document}
    started = time.perf_counter()
    _, paths = Masker().mask_json(document)
    assert time.perf_counter() - started < 2.0
    assert len(paths) == 250 + 5_000


def test_two_fields_whose_clipped_paths_read_alike_are_two_entries():
    """A long path is clipped; the key with a hit and the string below it are still two."""
    document = {"x" * 250: {"sk-abcdefghijklmnop": {"v": "sk-abcdefghijklmnoq"}}}
    _, paths = Masker().mask_json(document)
    assert len(paths) == 2


def test_a_key_seen_again_is_masked_the_same_and_counted_each_time():
    """The walk remembers keys that hold nothing; one that holds a value is masked every time."""
    masker = Masker(known_values=["Zornbach"])
    document = [{"name": "a", "Zornbach": 1, _sk(): 2} for _ in range(3)]

    masked, paths = masker.mask_json(document)

    assert all(list(item)[0] == "name" for item in masked)
    assert "Zornbach" not in repr(masked) and _sk() not in repr(masked)
    assert masked[0] == masked[1] == masked[2]
    assert len(paths) == 3, "the secret-shaped key, once per element"
    assert masker.replacements["known"] == 3


def test_a_pair_written_as_a_key_loses_its_value_in_the_key_and_in_the_paths():
    """No shape of a credential in it: only the pair rule finds the value in the key."""
    masked, paths = Masker().mask_json(
        {"password=hunter2": 1, "note": {"secret = s3cr3tvalue": {"a": 2}}}
    )
    written = json.dumps([masked, paths])
    assert "hunter2" not in written and "s3cr3tvalue" not in written
    assert set(masked) == {f"password={PLACEHOLDER}", "note"}


def test_a_name_that_stands_where_a_key_would_is_masked_by_shape_and_by_pair():
    """``mask_key`` is what the name of a script in ``run_started`` goes through."""
    masker = Masker()
    token = "sk-" + "abcdefghijklmnopqrst"
    assert token not in masker.mask_key(f"{token}.yaml")
    assert "hunter2" not in masker.mask_key("password=hunter2.yaml")
    assert masker.mask_key("discovery.yaml") == "discovery.yaml"


def test_only_short_keys_are_remembered_as_clean():
    """A name a protocol repeats is remembered; what a server sends as a long key is not kept
    for the length of the run, and is masked again each time all the same."""
    masker = Masker()
    long_key = "k" * 5000
    for _ in range(2):
        masked, paths = masker.mask_json({"description": "x", long_key: 1})
        assert masked == {"description": "x", long_key: 1} and paths == []
    assert masker._clean_keys == {"description"}
