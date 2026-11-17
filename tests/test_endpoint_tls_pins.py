"""Two rules that no other test holds to: ``report`` and ``engagement recheck`` refuse a store whose
record of imported triage cannot be read, and nothing about the TLS an endpoint is spoken to with is
configurable on ``drive``, ``run`` or ``engagement``."""

from __future__ import annotations

import argparse
import re
import sqlite3
from contextlib import closing

import pytest

from mcp_kymograph import cli
from test_cli_phase_b import engagement_with_runs, finding_id

#: Words that, anywhere in an option's name (``ca`` as a part of its own or at the start of a
#: part), would set a CA, a client certificate, the check of the server's certificate, or a
#: proxy. ``no-check`` is two parts and is read as one.
FORBIDDEN_WORDS = ("cert", "insecure", "verify", "proxy", "tls")
FORBIDDEN_PHRASES = ("no-check",)
#: ``ca`` as a part of its own, or a part that starts with it and goes on with one of these.
CA_PART = re.compile(r"ca(?:file|path|cert|bundle|store)")
CHECKED_COMMANDS = ("drive", "run", "engagement")


# -- a store whose imports cannot be read --------------------------------------------------------


@pytest.fixture
def unreadable_imports(tmp_path, capsys):
    """An engagement with runs and a store that holds one triage row and a ``triage_imports``
    that is not a list of imports."""
    held, out_dir, database = engagement_with_runs(tmp_path, capsys)
    found = finding_id(database)
    assert cli.main(["store", "triage", "set", "-q", "--store", str(database), "--finding",
                     str(found), "--role", "operator", "--status", "confirmed",
                     "--author", "A. Operator"]) == 0  # fmt: skip
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("INSERT OR REPLACE INTO meta VALUES ('triage_imports', '7')")
    capsys.readouterr()
    return held, out_dir, database, found


def test_report_refuses_a_store_whose_triage_imports_cannot_be_read(
    unreadable_imports, tmp_path, capsys
):
    held, out_dir, database, _ = unreadable_imports
    out = tmp_path / "reports" / "report.md"

    code = cli.main(
        ["report", "--engagement", str(held), "--store", str(database), "--runs", str(out_dir),
         "--out-dir", str(out_dir), "--out", str(out)]
    )  # fmt: skip

    said = capsys.readouterr()
    assert code == cli.EXIT_REFUSED
    assert said.out == "" and not out.exists()
    assert "which triage rows were carried here cannot be told" in said.err
    assert "Traceback" not in said.err


def test_recheck_refuses_a_store_whose_triage_imports_cannot_be_read(unreadable_imports, capsys):
    held, out_dir, database, found = unreadable_imports

    code = cli.main(
        ["engagement", "recheck", "--store", str(database), "--engagement", str(held),
         "--runs", str(out_dir), "--finding", str(found)]
    )  # fmt: skip

    said = capsys.readouterr()
    assert code == cli.EXIT_REFUSED
    assert said.out == ""
    assert "which triage rows were carried here cannot be told" in said.err
    assert "Traceback" not in said.err


# -- nothing about the TLS is configurable --------------------------------------------------------


def options_of(parser: argparse.ArgumentParser, path: tuple[str, ...]):
    """Every option string of ``parser`` and of all its subcommands, with the command it is on."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield from options_of(sub, (*path, name))
        else:
            for option in action.option_strings:
                yield " ".join(path), option


def forbidden(option: str) -> bool:
    """Whether ``option`` is named for a CA, a certificate, the check of the server's certificate,
    or a proxy: a word of the list anywhere in the name, whatever the joining (``--cacert``,
    ``--noverify``, ``--tlsv1.2``). ``ca`` is too short for that: it counts as a part of
    the name, alone or with ``file``, ``path``, ``cert``, ``bundle`` or ``store`` after it
    (``--client-cafile``), and not in ``--cache``, ``--case`` or ``--cancel``. No option of the
    parsers needs an exception."""
    name = option.lstrip("-").lower()
    parts = re.split(r"[-_.]", name)
    joined = "".join(parts)
    return (
        any(word in name for word in FORBIDDEN_WORDS)
        or any(part == "ca" or CA_PART.match(part) for part in parts)
        or any(phrase.replace("-", "") in joined for phrase in FORBIDDEN_PHRASES)
    )


def test_no_option_of_drive_run_or_engagement_configures_the_tls():
    top = next(
        action for action in cli.build_parser()._actions
        if isinstance(action, argparse._SubParsersAction)
    )  # fmt: skip
    seen = []
    for command in CHECKED_COMMANDS:
        seen += list(options_of(top.choices[command], (command,)))
    assert {path.split()[0] for path, _ in seen} == set(CHECKED_COMMANDS)
    assert any(path.startswith("engagement ") for path, _ in seen), "subcommands are walked"
    assert [(path, option) for path, option in seen if forbidden(option)] == []


@pytest.mark.parametrize(
    "option",
    ["--ca-bundle", "--client-cert", "--insecure", "--verify-tls", "--no-check",
     "--no-check-certificate", "--https-proxy", "--tls-version", "--ca_file", "--cacert",
     "--cafile", "--certfile", "--noverify", "--tlsv1.2", "--nocheck", "--ca",
     "--client-cafile", "--trust-cabundle", "--custom-capath"],
)  # fmt: skip
def test_the_check_finds_an_option_of_the_kind_it_forbids(option):
    assert forbidden(option)


@pytest.mark.parametrize("option", ["--cache", "--case", "--cancel", "--cap", "--cache-dir"])
def test_the_check_leaves_an_ordinary_name_with_ca_alone(option):
    assert not forbidden(option)
