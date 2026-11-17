"""``store triage set`` answers a rationale or a severity in one line, in every form of the option
and before the parser or the store sees the value."""

import pytest

from mcp_kymograph import cli
from mcp_kymograph.store import Store


def set_command(*extra: str, store="findings.sqlite") -> list[str]:
    return ["store", "triage", "set", "--store", store, "--finding", "1", "--role", "operator",
            "--status", "open", "--author", "a", *extra]  # fmt: skip


@pytest.mark.parametrize(
    ("extra", "values"),
    [
        (["--rationale", "-x"], ["-x"]),
        (["--severity", "--high"], ["--high"]),
        (["--rat", "x"], ["x"]),
        (["--sev=x"], ["x"]),
        (["--rationale=-x"], ["-x"]),
        (["--rationale"], []),
        (["--severity"], []),
    ],
)
def test_every_form_of_the_option_ends_in_one_line_without_its_value(
    extra, values, tmp_path, monkeypatch, capsys
):
    def opened(*_args, **_kwargs):
        raise AssertionError("the store was opened")

    monkeypatch.setattr(Store, "open", opened)
    monkeypatch.setattr(Store, "open_read_only", opened)
    database = tmp_path / "findings.sqlite"

    code = cli.main(set_command(*extra, store=str(database)))

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1, captured.err
    assert captured.err.startswith("kymograph: refused: the tool does not store a ")
    for value in values:
        assert value not in captured.err
    assert not database.exists()


def test_after_a_lone_double_dash_the_arguments_are_not_options():
    assert cli._refused_triage_option(set_command("--", "--rationale")) is None
    assert cli._refused_triage_option(["store", "triage", "list", "--rationale"]) is None
    assert cli._refused_triage_option(set_command("--role=customer")) is None


def test_the_help_of_set_names_neither_option(capsys):
    with pytest.raises(SystemExit) as left:
        cli.main(["store", "triage", "set", "--help"])
    assert left.value.code == 0
    shown = capsys.readouterr().out
    assert "--rationale" not in shown and "--severity" not in shown
