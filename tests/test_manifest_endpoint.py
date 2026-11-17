"""Endpoint entries: a server someone else runs, named by its URL and a version declared for it.

Read whole or refused whole, with the place, as every entry is. The URL is held to what
``drive --http`` holds a URL to, by the same two checks; the version is the operator's word or
the word ``endpoint``; the launch digest is over the transport and the URL, and every stdio
entry keeps the digest it had. Such an entry runs under ``remote`` and nothing else.
"""

import hashlib
import json
import os

import pytest

from mcp_kymograph import cli, corpus
from mcp_kymograph.corpus import ManifestError, load
from test_manifest import ALL_SIGNALS, EMPTY, FIXTURES, PROJECT, SHA, entry, write

URL = "http://127.0.0.1:8080/mcp"
POISONING = FIXTURES / "scenarios" / "tool-poisoning.yaml"


def endpoint_entry(here, **changes) -> dict:
    """A valid endpoint entry: a server someone else runs, driven over streamable HTTP."""
    base = {
        "name": "customer-mcp",
        "provenance": "real-world",
        "source": {"endpoint": URL, "version_declared": "3.1"},
        "launch": {"transport": "streamable-http"},
        "scenarios": [os.path.relpath(ALL_SIGNALS, here)],
    }
    return {**base, **changes}


def test_an_endpoint_entry_has_a_url_a_declared_version_and_no_command(tmp_path):
    (loaded,) = load(write(tmp_path, endpoint_entry(tmp_path))).entries
    assert loaded.endpoint == URL
    assert (loaded.command, loaded.command_written, loaded.paths) == ((), (), ())
    assert loaded.transport == "streamable-http"
    assert loaded.identity.to_dict() == {
        "kind": "endpoint",
        "version": "3.1",
        "files": 0,
        "version_declared": "3.1",
    }
    launch = json.dumps({"transport": "streamable-http", "endpoint": URL})
    assert loaded.launch_digest == "sha256:" + hashlib.sha256(launch.encode()).hexdigest()
    assert loaded.isolation(None) == "remote"
    assert loaded.isolation("remote") == "remote"
    assert loaded.refusal_to_run("remote") is None


def test_an_endpoint_without_a_declared_version_is_the_word_endpoint(tmp_path):
    for source in ({"endpoint": URL}, {"endpoint": URL, "version_declared": None}):
        (loaded,) = load(write(tmp_path, endpoint_entry(tmp_path, source=source))).entries
        assert (loaded.identity.version, loaded.identity.version_declared) == ("endpoint", None)


def test_another_url_is_another_launch_and_the_declared_version_is_not_part_of_it(tmp_path):
    one = load(write(tmp_path, endpoint_entry(tmp_path))).entries[0]
    elsewhere = {"endpoint": "http://127.0.0.1:8081/mcp", "version_declared": "3.1"}
    two = load(write(tmp_path, endpoint_entry(tmp_path, source=elsewhere))).entries[0]
    relabelled = {"endpoint": URL, "version_declared": "3.2"}
    three = load(write(tmp_path, endpoint_entry(tmp_path, source=relabelled))).entries[0]
    assert one.launch_digest != two.launch_digest
    assert one.launch_digest == three.launch_digest
    assert one.identity != three.identity


def test_every_stdio_entry_keeps_its_launch_digest():
    """Pinned: the endpoint form of the digest leaves the stdio form exactly as it was."""
    by_name = {loaded.name: loaded.launch_digest for loaded in load(PROJECT).entries}
    assert by_name == {
        "reference-server": (
            "sha256:10855c8515560f8d4d9a9766ddeeb8efd747b7aebf95a94d6f194040340ea2af"
        ),
        "poison-server": "sha256:cb814e4117afa3c45db672a9d36233baef722a5737fe3eb07e237a9dde5bb426",
    }
    assert all(loaded.endpoint is None for loaded in load(PROJECT).entries)


@pytest.mark.parametrize("requested", ["host", "runc", "runsc"])
@pytest.mark.parametrize("provenance", ["reference", "poison", "real-world"])
def test_an_endpoint_entry_under_anything_but_remote_is_refused(tmp_path, provenance, requested):
    (loaded,) = load(write(tmp_path, endpoint_entry(tmp_path, provenance=provenance))).entries
    assert loaded.refusal_to_run(requested) == (
        f"entry 'customer-mcp': an endpoint entry runs only under remote, not {requested}: its "
        f"server runs elsewhere, so there is nothing here to run under {requested}; it is refused"
    )


def test_a_command_entry_under_remote_is_refused(tmp_path):
    (loaded,) = load(write(tmp_path, entry(tmp_path))).entries
    assert loaded.refusal_to_run("remote") == (
        "entry 'poison-server': a command entry never runs under remote: its server is started "
        "here, and remote would observe nothing of it; it is refused"
    )


@pytest.mark.parametrize(
    ("change", "place", "fragment"),
    [
        (
            {"launch": {"transport": "stdio", "command": ["x"]}},
            "entries[0].launch.transport",
            "an entry with source.endpoint is driven over streamable-http, and only such an "
            "entry is; 'stdio' does not go with an endpoint",
        ),
        ({"source": {"endpoint": URL, "paths": ["a.py"]}}, "entries[0].source", "exactly one"),
        (
            {"source": {"endpoint": URL, "revision": f"github.com/x/y@{SHA}"}},
            "entries[0].source",
            "exactly one",
        ),
        (
            {"launch": {"transport": "streamable-http", "command": ["x"]}},
            "entries[0].launch.command",
            "there is no command to start it",
        ),
        (
            {"source": {"endpoint": URL, "version_declared": ""}},
            "entries[0].source.version_declared",
            "expected a non-empty string, or leave it out",
        ),
        (
            {"source": {"endpoint": URL, "version_declared": 3.1}},
            "entries[0].source.version_declared",
            "expected a non-empty string, or leave it out",
        ),
        (
            {"source": {"endpoint": URL, "version_declared": "v" * 129}},
            "entries[0].source.version_declared",
            "longer than 128 characters",
        ),
        (
            {"source": {"endpoint": URL, "version_declared": "3.1‮"}},
            "entries[0].source.version_declared",
            "a terminal does not show",
        ),
        (
            {"source": {"endpoint": URL, "version_declared": "3.1\n"}},
            "entries[0].source.version_declared",
            "a terminal does not show",
        ),
        ({"source": {"endpoint": 7}}, "entries[0].source.endpoint", "expected the server's URL"),
        ({"source": {"endpoint": ""}}, "entries[0].source.endpoint", "expected the server's URL"),
        (
            {"source": {"endpoint": "ftp://127.0.0.1:21/mcp"}},
            "entries[0].source.endpoint",
            "only http:// and https:// URLs are spoken",
        ),
        (
            {"source": {"endpoint": "http://127.0.0.1/mcp"}},
            "entries[0].source.endpoint",
            "needs a host, a port and a path",
        ),
        (
            {"source": {"endpoint": "http://127.0.0.1:8080"}},
            "entries[0].source.endpoint",
            "needs a host, a port and a path",
        ),
        (
            {"source": {"endpoint": "http://user:pw@127.0.0.1:8080/mcp"}},
            "entries[0].source.endpoint",
            "no user, password or fragment",
        ),
        (
            {"source": {"endpoint": "http://127.0.0.1:8080/mcp#x"}},
            "entries[0].source.endpoint",
            "no user, password or fragment",
        ),
        (
            {"source": {"endpoint": "http://127.0.0.1:8080/m cp"}},
            "entries[0].source.endpoint",
            "printable ASCII",
        ),
        (
            {"source": {"endpoint": "http://127.0.0.1:8080/a%40b/mcp"}},
            "entries[0].source.endpoint",
            "whose path holds an @",
        ),
    ],
)
def test_a_wrong_endpoint_entry_is_refused_whole_with_the_place(tmp_path, change, place, fragment):
    with pytest.raises(ManifestError) as refused:
        load(write(tmp_path, endpoint_entry(tmp_path, **change)))
    assert refused.value.reason.startswith(f"{place}: "), refused.value.reason
    assert fragment in refused.value.reason


def test_a_scenario_that_loads_rules_is_refused_for_an_endpoint(tmp_path):
    data = endpoint_entry(tmp_path, scenarios=[os.path.relpath(POISONING, tmp_path)])
    with pytest.raises(ManifestError) as refused:
        load(write(tmp_path, data))
    assert refused.value.reason == (
        "entries[0].scenarios[0]: scenario 'tool-poisoning' loads 1 rule(s); rules are not "
        "carried out over HTTP, so an endpoint entry's scenario only observes"
    )
    # The same scenario stays a command entry's to run.
    command = entry(tmp_path, scenarios=[os.path.relpath(POISONING, tmp_path)])
    assert load(write(tmp_path, command)).entries[0].scenarios[0].name == "tool-poisoning"


def test_a_scenario_with_no_rules_runs_against_an_endpoint(tmp_path):
    """empty.yaml has a rules key with every rule commented out: it observes only."""
    data = endpoint_entry(tmp_path, scenarios=[os.path.relpath(EMPTY, tmp_path)])
    (loaded,) = load(write(tmp_path, data)).entries
    assert [ref.name for ref in loaded.scenarios] == ["empty"]


def test_paths_driven_over_streamable_http_are_refused(tmp_path):
    with pytest.raises(ManifestError) as refused:
        load(write(tmp_path, entry(tmp_path, launch={"transport": "streamable-http"})))
    assert refused.value.reason.startswith("entries[0].launch.transport: ")
    assert "'streamable-http' does not go with paths or a revision" in refused.value.reason


def test_a_declared_version_without_an_endpoint_is_refused(tmp_path):
    data = entry(tmp_path)
    data["source"] = {**data["source"], "version_declared": "1.0"}
    with pytest.raises(ManifestError) as refused:
        load(write(tmp_path, data))
    assert refused.value.reason.startswith(
        "entries[0].source.version_declared: belongs to an endpoint entry"
    )


def test_the_categories_a_declared_version_may_not_hold_are_the_ones_display_drops():
    assert corpus.UNDISPLAYABLE == cli._UNSAFE_CATEGORIES
    assert corpus.undisplayable("a\nb")
    assert not corpus.undisplayable("a\nb", allowed="\n")
    assert not corpus.undisplayable("3.1-ä")
