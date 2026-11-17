"""``signals list`` and ``signals list --reference``."""

import json

import pytest

from mcp_kymograph import cli, signals
from mcp_kymograph.signals import KINDS, Signal


def test_signals_list_names_every_signal_with_its_kind_and_page(capsys):
    assert cli.main(["signals", "list", "-q"]) == 0

    shown = json.loads(capsys.readouterr().out)
    assert shown == {
        "signals": [
            {"signal": s.value, "kind": KINDS[s].value, "reference": f"reference/{s.value}.md"}
            for s in Signal
        ]
    }


def test_signals_list_reference_prints_every_page_in_library_order(capsys):
    assert cli.main(["signals", "list", "--reference", "-q"]) == 0

    out = capsys.readouterr().out
    assert out == "\n".join(signals.reference_pages().values())
    titles = [line for line in out.splitlines() if line.startswith("# ")]
    assert titles == [f"# `{s.value}`" for s in Signal]


def test_signals_list_says_how_many_on_stderr_unless_quiet(capsys):
    assert cli.main(["signals", "list"]) == 0
    assert f"{len(Signal)} signal(s)" in capsys.readouterr().err


#: Two ways a page of the installed package fails to read: gone, and not UTF-8.
UNREADABLE = pytest.mark.parametrize(
    ("failure", "why"),
    [
        (FileNotFoundError(2, "No such file or directory"), "No such file or directory"),
        (
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
        ),
    ],
    ids=["missing", "not-utf-8"],
)


def _break_page(monkeypatch, broken: Signal, failure: Exception) -> None:
    shipped = signals.reference

    def reference(signal):
        if Signal(signal) is broken:
            raise failure
        return shipped(signal)

    monkeypatch.setattr(signals, "reference", reference)


@UNREADABLE
def test_signals_list_does_not_read_the_pages_it_does_not_print(capsys, monkeypatch, failure, why):
    """The JSON names each page by its path, not its content: an unreadable page does not
    concern it, and the listing is the same as ever."""
    for signal in Signal:
        _break_page(monkeypatch, signal, failure)

    assert cli.main(["signals", "list"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["signals"] == [
        {"signal": s.value, "kind": KINDS[s].value, "reference": f"reference/{s.value}.md"}
        for s in Signal
    ]
    assert f"{len(Signal)} signal(s)" in captured.err


@UNREADABLE
@pytest.mark.parametrize("broken", [list(Signal)[0], list(Signal)[-1]], ids=["first", "last"])
def test_signals_list_reference_refuses_an_unreadable_page_and_prints_nothing(
    capsys, monkeypatch, failure, why, broken
):
    """A page the installed package cannot read ends ``--reference`` with a refusal on stderr
    that names the page by its signal id and says the installation is incomplete; stdout stays
    empty, not even the pages read before it."""
    _break_page(monkeypatch, broken, failure)

    assert cli.main(["signals", "list", "--reference"]) == cli.EXIT_REFUSED

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"kymograph: refused: the reference page of {broken.value} cannot be read from the "
        f"installed package ({why}); the installation is incomplete, and nothing was listed\n"
    )
