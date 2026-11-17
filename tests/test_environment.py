"""The environment a subprocess is allowed to see."""

from mcp_kymograph.environment import HELPER_ALLOWLIST, helper_env, inherited_env


def test_a_helper_sees_only_what_is_named(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("SOME_UNRELATED_SETTING", "x")

    assert set(helper_env()) <= HELPER_ALLOWLIST
    assert helper_env()["PATH"] == "/usr/bin"


def test_a_variable_nobody_thought_of_is_absent_rather_than_admitted(monkeypatch):
    # The point of an allowlist: this test keeps passing for vectors invented later.
    monkeypatch.setenv("GIT_SOMETHING_INVENTED_TOMORROW", "1")
    assert "GIT_SOMETHING_INVENTED_TOMORROW" not in helper_env()


def test_the_allowlist_stays_small_enough_to_read():
    assert set(HELPER_ALLOWLIST) == {"PATH", "HOME"}


def test_the_server_under_test_gets_the_environment_unchanged(monkeypatch):
    # Transparency: a server started with a different environment behaves differently
    # because we are there, which is the one thing this tool must not cause.
    monkeypatch.setenv("VENDOR_API_BASE", "https://example.test")
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    environment = inherited_env()
    assert environment["VENDOR_API_BASE"] == "https://example.test"
    assert environment["GIT_DIR"] == "/elsewhere/.git"
