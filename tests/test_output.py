"""Where a recording may land.

Real git repositories in ``tmp_path``, no network, no mocking of git itself: the point of
the check is that it asks git rather than guessing from names, so the test has to ask too.
"""

import os
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_kymograph.output import (
    Advisory,
    DestinationRefused,
    Reason,
    Severity,
    inspect_destination,
    prepare_run,
    run_directory_name,
)

FIXED_TIME = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)


def at_fixed_time() -> datetime:
    return FIXED_TIME


def make_repo(path: Path, *, gitignore: str | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git")
    assert git, "these tests ask git itself; a git binary is required"
    # noqa justified: fixed argv, absolute binary, no shell, no value from traffic.
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=path, check=True)  # noqa: S603
    if gitignore is not None:
        (path / ".gitignore").write_text(gitignore)
    return path


def advise(out_dir: Path) -> list[Advisory]:
    return inspect_destination(out_dir, out_dir / run_directory_name("abcd1234", now=at_fixed_time))


def reasons(advisories: list[Advisory]) -> set[Reason]:
    return {advisory.reason for advisory in advisories}


# -- the git question -----------------------------------------------------------------


def test_a_destination_outside_any_repository_is_silent(tmp_path):
    assert advise(tmp_path / "runs") == []


def test_a_destination_in_a_working_tree_without_an_ignore_rule_is_refused(tmp_path):
    repo = make_repo(tmp_path / "repo", gitignore="/something-else/\n")
    (advisory,) = advise(repo / "runs")
    assert advisory.severity is Severity.REFUSAL
    assert advisory.reason is Reason.INSIDE_GIT_WORKTREE


def test_a_destination_covered_by_gitignore_is_allowed(tmp_path):
    repo = make_repo(tmp_path / "repo", gitignore="/runs/\n")
    assert advise(repo / "runs") == []


def test_the_check_honours_every_applying_ignore_rule_not_just_gitignore(tmp_path):
    # info/exclude is a real ignore source and is invisible to any name comparison.
    repo = make_repo(tmp_path / "repo")
    (repo / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text("/runs/\n")
    assert advise(repo / "runs") == []


def test_a_nested_destination_inherits_the_rule_that_covers_its_parent(tmp_path):
    repo = make_repo(tmp_path / "repo", gitignore="/out/\n")
    assert advise(repo / "out" / "deep" / "runs") == []


def test_git_environment_variables_cannot_talk_the_check_into_a_wrong_answer(tmp_path, monkeypatch):
    # GIT_DIR pointing at a repository that *does* ignore /runs/ must not make the
    # destination in a repository that does not look acceptable.
    unprotected = make_repo(tmp_path / "unprotected", gitignore="/something-else/\n")
    permissive = make_repo(tmp_path / "permissive", gitignore="/runs/\n")
    monkeypatch.setenv("GIT_DIR", str(permissive / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(permissive))

    (advisory,) = advise(unprotected / "runs")
    assert advisory.reason is Reason.INSIDE_GIT_WORKTREE


def test_an_unanswerable_git_question_fails_closed(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", gitignore="/runs/\n")
    monkeypatch.setattr("mcp_kymograph.output.shutil.which", lambda _name: None)

    (advisory,) = advise(repo / "runs")
    assert advisory.severity is Severity.REFUSAL
    assert advisory.reason is Reason.GIT_STATUS_UNKNOWN


def test_no_git_available_and_no_repository_in_sight_is_still_silent(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_kymograph.output.shutil.which", lambda _name: None)
    assert advise(tmp_path / "runs") == []


# -- places that leave the machine on their own ----------------------------------------


def test_the_home_directory_itself_warns(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert reasons(advise(home)) == {Reason.HOME_DIRECTORY}


def test_a_directory_below_home_does_not_warn(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert advise(home / "work" / "runs") == []


@pytest.mark.parametrize(
    ("relative", "reason"),
    [
        ("Desktop/runs", Reason.DESKTOP),
        ("Dropbox/runs", Reason.CLOUD_SYNC),
        ("OneDrive - Contoso/runs", Reason.CLOUD_SYNC),
        ("Nextcloud/work/runs", Reason.CLOUD_SYNC),
        ("iCloud Drive/runs", Reason.CLOUD_SYNC),
        ("Library/Mobile Documents/runs", Reason.CLOUD_SYNC),
    ],
)
def test_synced_and_visible_places_warn(tmp_path, monkeypatch, relative, reason):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    advisories = advise(tmp_path / relative)
    assert reasons(advisories) == {reason}
    assert all(advisory.severity is Severity.WARNING for advisory in advisories)


def test_a_warning_does_not_stop_the_run(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    location = prepare_run(tmp_path / "Dropbox" / "runs", run_id="abcd1234", now=at_fixed_time)
    assert location.directory.is_dir()
    assert reasons(list(location.advisories)) == {Reason.CLOUD_SYNC}


# -- creating the run directory --------------------------------------------------------


def test_nothing_is_written_into_the_destination_directly(tmp_path):
    out_dir = tmp_path / "runs"
    location = prepare_run(out_dir, run_id="abcd1234", now=at_fixed_time)

    assert location.directory.parent == out_dir
    assert location.directory.name == "20260909T120000Z-abcd1234"
    assert location.events_path == location.directory / "events.jsonl"
    assert [child.name for child in out_dir.iterdir()] == ["20260909T120000Z-abcd1234"]


def test_two_runs_do_not_share_a_directory(tmp_path):
    first = prepare_run(tmp_path / "runs", run_id="aaaa1111", now=at_fixed_time)
    second = prepare_run(tmp_path / "runs", run_id="bbbb2222", now=at_fixed_time)
    assert first.directory != second.directory


def test_a_colliding_run_directory_is_refused_and_left_untouched(tmp_path):
    out_dir = tmp_path / "runs"
    prepare_run(out_dir, run_id="abcd1234", now=at_fixed_time)
    existing = out_dir / "20260909T120000Z-abcd1234" / "events.jsonl"
    existing.write_text("earlier evidence\n")

    with pytest.raises(DestinationRefused) as raised:
        prepare_run(out_dir, run_id="abcd1234", now=at_fixed_time)

    assert raised.value.advisory.reason is Reason.RUN_DIRECTORY_EXISTS
    assert existing.read_text() == "earlier evidence\n"


def test_a_refused_destination_creates_nothing(tmp_path):
    repo = make_repo(tmp_path / "repo", gitignore="/something-else/\n")
    with pytest.raises(DestinationRefused):
        prepare_run(repo / "runs", run_id="abcd1234", now=at_fixed_time)
    assert not (repo / "runs").exists()


def test_the_run_directory_is_closed_to_group_and_others(tmp_path):
    location = prepare_run(tmp_path / "runs", run_id="abcd1234", now=at_fixed_time)
    assert stat.S_IMODE(os.stat(location.directory).st_mode) & 0o077 == 0


# -- what the advisories are allowed to say ---------------------------------------------


def collect_every_message(tmp_path, monkeypatch) -> list[str]:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    messages: list[str] = []

    repo = make_repo(tmp_path / "repo", gitignore="/something-else/\n")
    messages += [advisory.message for advisory in advise(repo / "runs")]
    messages += [advisory.message for advisory in advise(tmp_path / "home")]
    messages += [advisory.message for advisory in advise(tmp_path / "Desktop" / "runs")]
    messages += [advisory.message for advisory in advise(tmp_path / "Dropbox" / "runs")]

    monkeypatch.setattr("mcp_kymograph.output.shutil.which", lambda _name: None)
    messages += [advisory.message for advisory in advise(repo / "runs")]
    monkeypatch.undo()

    prepare_run(tmp_path / "runs", run_id="abcd1234", now=at_fixed_time)
    with pytest.raises(DestinationRefused) as raised:
        prepare_run(tmp_path / "runs", run_id="abcd1234", now=at_fixed_time)
    messages.append(raised.value.advisory.message)

    return messages


def test_no_message_leaks_a_path(tmp_path, monkeypatch):
    messages = collect_every_message(tmp_path, monkeypatch)
    assert len(messages) >= 6
    for message in messages:
        assert "/" not in message, message
        assert os.sep not in message, message
        assert str(tmp_path) not in message, message


def test_an_advisory_can_go_into_the_event_stream(tmp_path):
    repo = make_repo(tmp_path / "repo", gitignore="/something-else/\n")
    (advisory,) = advise(repo / "runs")
    assert advisory.to_dict() == {
        "severity": "refusal",
        "reason": "inside_git_worktree",
        "message": advisory.message,
    }


# -- git's own storage ----------------------------------------------------------------


def test_a_destination_inside_git_metadata_is_refused(tmp_path):
    repo = make_repo(tmp_path / "repo")
    assert Reason.INSIDE_GIT_METADATA in reasons(advise(repo / ".git" / "runs"))


def test_the_refusal_reaches_deep_inside_git_metadata(tmp_path):
    repo = make_repo(tmp_path / "repo")
    assert Reason.INSIDE_GIT_METADATA in reasons(advise(repo / ".git" / "objects" / "x" / "y"))


def test_a_symlink_cannot_walk_a_destination_into_git_metadata(tmp_path):
    repo = make_repo(tmp_path / "repo")
    disguise = tmp_path / "disguise"
    disguise.symlink_to(repo / ".git")
    assert Reason.INSIDE_GIT_METADATA in reasons(advise(disguise / "runs"))


def test_a_linked_worktrees_real_git_dir_is_refused(tmp_path):
    """The case a name check cannot see: ``.git`` is a file, the storage is elsewhere."""
    repo = make_repo(tmp_path / "repo")
    git = shutil.which("git")
    (repo / "a.txt").write_text("x")
    run = ["-c", "user.name=t", "-c", "user.email=t@e"]
    subprocess.run([git, "add", "a.txt"], cwd=repo, check=True)  # noqa: S603
    subprocess.run([git, *run, "commit", "-qm", "i"], cwd=repo, check=True)  # noqa: S603
    worktree = tmp_path / "wt"
    subprocess.run(  # noqa: S603
        [git, "worktree", "add", "-q", "--detach", str(worktree)], cwd=repo, check=True
    )
    assert (worktree / ".git").is_file(), "precondition: a linked worktree has a .git file"

    real_git_dir = repo / ".git" / "worktrees" / "wt"
    assert Reason.INSIDE_GIT_METADATA in reasons(advise(real_git_dir / "runs"))


# -- configuration injection ----------------------------------------------------------


def test_injected_git_config_cannot_make_an_unprotected_destination_look_ignored(
    tmp_path, monkeypatch
):
    """GIT_CONFIG_COUNT injects core.excludesFile. It was on no denylist; the allowlist
    covers it without having had to know about it."""
    repo = make_repo(tmp_path / "repo")
    excludes = tmp_path / "excludes.txt"
    excludes.write_text("/runs/\n")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(excludes))

    assert Reason.INSIDE_GIT_WORKTREE in reasons(advise(repo / "runs"))


def test_an_injected_global_config_file_cannot_launder_a_destination(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    config = tmp_path / "gitconfig"
    excludes = tmp_path / "excludes.txt"
    excludes.write_text("/runs/\n")
    config.write_text(f"[core]\n\texcludesFile = {excludes}\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))

    assert Reason.INSIDE_GIT_WORKTREE in reasons(advise(repo / "runs"))


def test_every_directory_we_create_is_private_from_the_moment_it_exists(tmp_path, monkeypatch):
    """No "create with the default, then chmod" window anywhere on the path. The mode goes to
    mkdir and to open directly, so there is no instant at which a recording's directory is
    readable by anyone else. Run under a permissive umask, because a strict one would hide
    the very mistake this is guarding against."""
    previous = os.umask(0o000)
    try:
        location = prepare_run(tmp_path / "deep" / "nested" / "runs", run_id="abcd1234")
    finally:
        os.umask(previous)

    for directory in (
        tmp_path / "deep",
        tmp_path / "deep" / "nested",
        tmp_path / "deep" / "nested" / "runs",
        location.directory,
    ):
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700, f"{directory} is not private"
