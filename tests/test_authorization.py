"""The engagement gate. Pure logic."""

import pytest

from mcp_kymograph.authorization import (
    LOCAL_TARGETS,
    LOOPBACK_LITERALS,
    Declaration,
    Unauthorized,
    check,
    host_of,
    is_local,
    is_loopback,
    plain_http_refusal,
    requires_confirmation,
    split_target,
)
from mcp_kymograph.http_client import _parse_url


def test_stdio_child_and_localhost_names_are_local():
    assert is_local(None) is True
    for name in ("localhost", "127.0.0.1", "::1", "[::1]", "LocalHost", " 127.0.0.1 "):
        assert is_local(name) is True, name


def test_anything_unrecognised_is_treated_as_non_local():
    # Fail closed: an unknown target must ask for confirmation, not skip it.
    for name in ("example.com", "10.0.0.5", "192.168.1.1", "::2", "totally-made-up"):
        assert is_local(name) is False, name


def test_observation_without_a_scenario_never_needs_confirmation():
    assert requires_confirmation(scenario_active=False, target="example.com") is False
    check(scenario_active=False, target="example.com", confirmed=False)  # does not raise


def test_a_scenario_against_localhost_needs_no_confirmation():
    check(scenario_active=True, target=None, confirmed=False)
    check(scenario_active=True, target="127.0.0.1", confirmed=False)


def test_a_scenario_against_a_non_local_target_without_confirmation_is_refused():
    with pytest.raises(Unauthorized):
        check(scenario_active=True, target="example.com", confirmed=False)


def test_the_same_run_is_allowed_once_confirmed():
    check(scenario_active=True, target="example.com", confirmed=True)  # does not raise


# -- a port does not move a target -----------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["localhost:8080", "[::1]:8080", "127.0.0.1:443", "  LocalHost:8080  ", "localhost:65535"],
)
def test_a_local_host_stays_local_when_it_carries_a_port(target):
    assert is_local(target) is True, target


@pytest.mark.parametrize(
    "target",
    [
        "box.local:8080",  # a name is never resolved, port or not
        "127.0.0.2:80",  # loopback range, but not the literal we accept
        "::ffff:127.0.0.1",  # unbracketed and multi-colon: port or address? unanswerable
        "http://localhost:8080",  # a URL is not a host; refused rather than interpreted
        "localhost:",  # no port where a port was promised
        "localhost:abc",
        "localhost:0",  # reserved, never something you are engaged against
        "localhost:65536",  # out of range
        "localhost:-1",
        ":8080",  # no host at all
        "[::1:8080",  # unclosed bracket
        "[::1]8080",  # bracket not followed by a colon
        "",
    ],
)
def test_anything_that_does_not_split_cleanly_stays_non_local(target):
    assert is_local(target) is False, target


@pytest.mark.parametrize("target", ["localhost:٣", "localhost:²"])
def test_a_unicode_digit_is_not_a_port(target):
    """str.isdigit() is true for these. int() reads '٣' as 3 and rejects '²'
    outright, so trusting isdigit() alone would either invent a port or raise from inside a
    gate. Neither may happen."""
    assert is_local(target) is False, target


def test_the_split_reports_what_it_could_not_take_apart():
    assert host_of("localhost:8080") == "localhost"
    assert host_of("[::1]:8080") == "[::1]"
    assert host_of("::ffff:127.0.0.1") is None, "None is the fail-closed answer"
    assert host_of(":8080") is None, "an empty host is a refusal, not a host that is empty"
    assert host_of("localhost:80:90") is None


def test_a_port_does_not_let_an_unknown_host_through():
    """The point of the split is convenience for local targets, not a new way past the gate."""
    with pytest.raises(Unauthorized):
        check(scenario_active=True, target="example.com:8080", confirmed=False)


# -- what the run records about its own authorization ----------------------------------


def test_the_declaration_says_which_parts_were_only_claimed():
    """Field names are the whole documentation a reader has months later. `declared_` and
    `_flag` are there to stop the record being read as a finding."""
    recorded = Declaration(
        scenario="tool-poisoning",
        declared_target="10.0.0.5",
        engagement_confirmed_flag=True,
        rules_loaded=True,
    ).as_dict()
    assert recorded == {
        "scenario": "tool-poisoning",
        "scenario_digest": None,
        "declared_target": "10.0.0.5",
        "engagement_confirmed_flag": True,
        "rules_loaded": True,
        "engagement": None,
    }


def test_an_undeclared_run_records_the_posture_it_actually_had():
    assert Declaration().as_dict() == {
        "scenario": None,
        "scenario_digest": None,
        "declared_target": None,
        "engagement_confirmed_flag": False,
        "rules_loaded": False,
        "engagement": None,
    }


def test_an_engagement_file_is_recorded_as_its_id_digest_and_window_and_nothing_else():
    recorded = Declaration(
        declared_target="mcp.example.test:443",
        engagement_confirmed_flag=True,
        engagement_id_declared="acme-2026-10",
        engagement_digest="ab" * 32,
        window_declared={"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
    ).as_dict()
    assert recorded["engagement"] == {
        "engagement_id_declared": "acme-2026-10",
        "engagement_digest": "ab" * 32,
        "window_declared": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
    }
    assert set(recorded) == {
        "scenario",
        "scenario_digest",
        "declared_target",
        "engagement_confirmed_flag",
        "rules_loaded",
        "engagement",
    }
    assert recorded["engagement_confirmed_flag"] is True, "the flag as typed, not implied"


def test_the_recorded_window_is_a_copy():
    window = {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"}
    recorded = Declaration(engagement_digest="ab" * 32, window_declared=window).as_dict()
    recorded["engagement"]["window_declared"]["until"] = "2099-01-01T00:00:00Z"
    assert window["until"] == "2026-11-07T18:00:00Z"


# -- the invariant that replaced a guard which only restated it -------------------------

#: Everything the splitter has ever been pointed at, well-formed and not. The invariant below
#: must hold for all of it, which is what makes it worth more than a comment.
EVERY_SHAPE = [
    "localhost",
    "127.0.0.1",
    "::1",
    "[::1]",
    "localhost:8080",
    "127.0.0.1:443",
    "[::1]:8080",
    "[::1]:0",
    # Bracketed hosts that carry letters, so a test can tell "selected" from "rewritten".
    # Without one of these, an implementation that upper-cased its result would look correct.
    "[fe80::1]",
    "[fe80::1]:8080",
    "box.local",
    "box.local:8080",
    "::ffff:127.0.0.1",
    "http://localhost:8080",
    "localhost:",
    "localhost:abc",
    "localhost:80:90",
    ":8080",
    "[::1:8080",
    "[::1]8080",
    "[]",
    "[]:80",
    "[",
    "]",
    "[]]",
    "",
    ":",
    "::",
]


@pytest.mark.parametrize("target", EVERY_SHAPE)
def test_host_of_never_returns_a_malformed_host(target):
    """The bracket branch used to carry a guard for the unclosed case whose removal changed
    no outcome — the slicing refuses it anyway. A comment saying so protects the reader but
    not the next refactor: someone who removes the *load-bearing* condition and leaves the
    guard standing sees a line that looks like it still guards.

    So the guard is gone and the invariant it restated is pinned here instead: whatever
    `host_of` hands back is a host that could be compared against the local literals — never
    an empty string, never half a bracketed address. Break the slicing and this goes red."""
    host = host_of(target)
    if host is None:
        return  # the fail-closed answer is always allowed

    assert host, "an empty string is not a host; None is how refusal is spelled"
    if host.startswith("["):
        assert host.endswith("]"), f"half a bracketed address escaped: {host!r}"
        assert len(host) > 2, f"an empty bracketed address escaped: {host!r}"
    else:
        assert ":" not in host, f"an unbracketed host may not carry a colon: {host!r}"


@pytest.mark.parametrize("target", EVERY_SHAPE)
def test_a_returned_host_is_the_prefix_of_what_was_handed_in(target):
    """The second half of the same invariant: the splitter *selects*, it never rewrites. A
    host that is not literally at the front of the input would mean the function had started
    interpreting addresses, which is exactly what this gate must not do."""
    host = host_of(target)
    if host is not None:
        assert target.startswith(host), f"{host!r} was not taken from {target!r}"


def test_a_script_that_calls_tools_is_held_to_the_gate_like_a_scenario():
    """A call acts on the target; a script that only lists does not."""
    assert requires_confirmation(scenario_active=False, target="10.0.0.5", script_calls=True)
    assert not requires_confirmation(scenario_active=False, target="10.0.0.5", script_calls=False)
    assert not requires_confirmation(scenario_active=False, target="localhost", script_calls=True)
    with pytest.raises(Unauthorized, match="script that calls tools"):
        check(scenario_active=False, target="10.0.0.5", confirmed=False, script_calls=True)
    check(scenario_active=False, target="10.0.0.5", confirmed=True, script_calls=True)


# -- split_target: the same refusals, a bare host and a bare bracketed address taken ---------


@pytest.mark.parametrize(
    ("target", "split"),
    [
        ("example.com", ("example.com", None)),
        ("Example.COM", ("example.com", None)),
        ("  example.com:443  ", ("example.com", 443)),
        ("localhost", ("localhost", None)),
        ("localhost:8080", ("localhost", 8080)),
        ("127.0.0.1", ("127.0.0.1", None)),
        ("10.0.0.5:65535", ("10.0.0.5", 65535)),
        ("[::1]", ("::1", None)),
        ("::1", ("::1", None)),
        ("[::1]:8080", ("::1", 8080)),
        ("[FE80::1]", ("fe80::1", None)),
        ("[2001:db8::1]:443", ("2001:db8::1", 443)),
        ("[::ffff:127.0.0.1]", ("::ffff:127.0.0.1", None)),
        ("[0:0::1]", ("0:0::1", None)),  # a string, not normalised: nothing is interpreted
        ("box_1.internal-net", ("box_1.internal-net", None)),
    ],
)
def test_split_target_takes_a_host_with_or_without_a_port(target, split):
    assert split_target(target) == split


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        ":",
        "::",
        ":8080",
        "::ffff:127.0.0.1",  # unbracketed, several colons: is the tail a port?
        "2001:db8::1",
        "localhost:",
        "localhost:0",
        "localhost:65536",
        "localhost:80:90",
        "localhost:abc",
        "localhost:\u0663",  # an Arabic-Indic three: int() would read it as 3
        "localhost:\u00b2",
        "localhost:+80",
        "localhost: 80",
        "http://localhost:8080",
        "https://example.com",
        "example.com/mcp",
        "user@example.com",
        "exa mple.com",
        "\u212aelvin.test",  # lower-cases into ASCII "k": refused before it can
        "b\u00fccher.test",
        "\u0661\u0662\u0667.0.0.1",
        "[::1",
        "[::1]8080",
        "[::1]:",
        "[::1]:0",
        "[]",
        "[]:80",
        "[localhost]",
        "[fe80::1%eth0]",
        "[127.0.0.1]",
        "[[::1]]",
        "-",
        ".example.com",
    ],
)
def test_split_target_refuses_what_it_cannot_take_apart(target):
    assert split_target(target) is None


@pytest.mark.parametrize("target", EVERY_SHAPE)
def test_split_target_agrees_with_host_of_where_host_of_takes_a_port(target):
    """Narrower, never wider: where ``host_of`` refuses a ``host:port``, so does this."""
    split = split_target(target)
    if split is not None and split[1] is not None:
        host = host_of(target.strip().lower())
        assert host is not None
        assert host.strip("[]") == split[0]


def test_the_gate_takes_the_same_four_strings_as_before_loopback_had_a_name():
    # Every user of is_local keeps its behaviour: the gate's set is unchanged, and it is the
    # loopback literals with one name added.
    assert {"localhost", "127.0.0.1", "::1", "[::1]"} == LOCAL_TARGETS
    assert isinstance(LOCAL_TARGETS, frozenset)
    assert LOOPBACK_LITERALS < LOCAL_TARGETS
    assert {"localhost"} == LOCAL_TARGETS - LOOPBACK_LITERALS


@pytest.mark.parametrize("host", sorted(LOOPBACK_LITERALS))
def test_each_loopback_literal_is_loopback(host):
    assert is_loopback(host) is True


@pytest.mark.parametrize(
    "host",
    # A name, another address of 127.0.0.0/8, and other spellings of the two literals: each may
    # reach this machine, and none is loopback, because nothing is resolved or interpreted.
    ["localhost", "127.0.0.2", "::ffff:127.0.0.1", "0:0::1", "127.1", "127.0.0.1.", "", None],
)
def test_nothing_but_a_loopback_literal_is_loopback(host):
    assert is_loopback(host) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:1/x",
        "https://anything",
        "https://mcp.example.test:443/mcp",
        "HTTP://127.0.0.1:8080/",
    ],
)
def test_plain_http_to_loopback_and_https_are_not_refused_here(url):
    assert plain_http_refusal(url) is None


@pytest.mark.parametrize(
    ("url", "where"),
    [
        ("http://localhost:8080/", "localhost:8080"),
        ("http://mcp.example.test:80/mcp", "mcp.example.test:80"),
        ("http://user:secret@host.test:81/p?q=1", "host.test:81"),
        ("HTTP://Host.Test/", "host.test"),
        ("http://127.0.0.2:8080/mcp", "127.0.0.2:8080"),
        ("http://[::ffff:127.0.0.1]:8080/mcp", "[::ffff:127.0.0.1]:8080"),
        ("http://[2001:db8::1]/mcp", "[2001:db8::1]"),
    ],
)
def test_plain_http_to_anything_else_is_refused_naming_the_host_and_port(url, where):
    words = plain_http_refusal(url)
    assert words is not None
    assert words.startswith(f"plain HTTP to {where}, which is not a loopback address")
    assert "no name, not even localhost" in words
    assert words.endswith("Use https:// or a loopback address.")


def test_the_refusal_names_nothing_of_the_url_but_its_host_and_port():
    # A URL can carry a credential, and the words reach a terminal and refusals.jsonl.
    words = plain_http_refusal("http://user:secret@host.test:81/p?q=1")
    assert "host.test:81" in words
    for part in ("secret", "user", "/p", "q=1"):
        assert part not in words, part


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.test:99999/mcp",  # a port that is not a port
        "http://evil.test:x/mcp",
        "http://[::1/mcp",  # urlsplit refuses it
        "http:///mcp",  # no host
        "http://user@:80/mcp",
        "http://\u00e9vil.test:80/mcp",  # not ASCII
        "http://evil.test:80/\x1b[31m",  # a character a terminal would act on
        " http://evil.test:80/mcp",
    ],
)
def test_what_this_leaves_alone_the_url_reader_refuses(url):
    # Not this function's business: the reader refuses such a URL, before anything connects.
    assert plain_http_refusal(url) is None
    with pytest.raises(ValueError):
        _parse_url(url)
