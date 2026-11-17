"""``store triage import`` reads a file from outside and fails closed: a file over the size limit
is refused before it is read, a file nested past what the JSON reader takes is refused as one
that is not read, and the rows of a large file are checked in time linear in their number.
Every refusal exits 2 on one line, with no traceback, and writes nothing."""

import os
import socket
import tempfile
import threading
import time

import pytest

from mcp_kymograph import cli
from mcp_kymograph import store as store_module
from mcp_kymograph.store import IDENTITY_FIELDS, StoreError
from test_store_engagement import tables
from test_triage_transfer import engaged_store

DIGEST = "ab" * 32


def import_into(tmp_path, file, capsys, *, armed=lambda: None):
    fresh = engaged_store(tmp_path / "new.sqlite", tmp_path)
    before = tables(fresh)
    armed()
    code = cli.main(["store", "triage", "import", "--store", str(fresh), str(file)])
    said = capsys.readouterr()
    assert tables(fresh) == before, "nothing is written"
    return code, said


def test_a_file_nested_past_the_reader_is_refused_without_a_traceback(tmp_path, capsys):
    deep = tmp_path / "deep.json"
    deep.write_bytes(b"[" * 100_000)

    code, said = import_into(tmp_path, deep, capsys)

    assert code == cli.EXIT_REFUSED
    assert said.out == ""
    assert said.err.count("\n") == 1 and "Traceback" not in said.err
    assert "nested deeper than this reads" in said.err
    assert "[[[" not in said.err, "no value of the file is in the line"


def read_bytes():
    """``rchar`` of this process: what it has asked the kernel to read, whatever the way it opened
    the file (``os.read``, ``open``, ``Path.open`` or ``io.open``)."""
    with open("/proc/self/io") as counters:
        for line in counters:
            name, _, value = line.partition(":")
            if name == "rchar":
                return int(value)
    raise AssertionError("no rchar in /proc/self/io")


needs_io_counters = pytest.mark.skipif(
    not os.path.exists("/proc/self/io"), reason="no /proc/self/io here to count reads with"
)
READ_ALLOWED = 1 << 20


class Counted:
    """The bytes read from the moment ``start`` is called (the store of the test is made before)."""

    def start(self):
        self.began = read_bytes()

    def read(self):
        return read_bytes() - self.began


@needs_io_counters
def test_a_file_over_the_limit_is_refused_before_it_is_read(tmp_path, capsys):
    big = tmp_path / "big.json"
    with big.open("wb") as handle:
        handle.truncate(cli.TRIAGE_IMPORT_MAX_BYTES + 1)  # sparse: no disk is used
    assert cli.TRIAGE_IMPORT_MAX_BYTES == 64 << 20
    counted = Counted()

    code, said = import_into(tmp_path, big, capsys, armed=counted.start)
    read = counted.read()

    assert code == cli.EXIT_REFUSED
    assert said.err.count("\n") == 1 and "larger than 64 MiB" in said.err
    assert "Traceback" not in said.err
    assert read < READ_ALLOWED, f"{read} bytes were read of a file refused for its size"


def refused_within(seconds, tmp_path, file, capsys):
    """Run the import in a thread that is given up on after ``seconds``: a read that blocks must
    fail the test and not hold it."""
    outcome = []
    worker = threading.Thread(
        target=lambda: outcome.append(import_into(tmp_path, file, capsys)), daemon=True
    )
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "the import blocked on the file"
    return outcome[0]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_fifo_with_no_writer_is_refused_at_once(tmp_path, capsys):
    fifo = tmp_path / "export.fifo"
    os.mkfifo(fifo)

    code, said = refused_within(5, tmp_path, fifo, capsys)

    assert code == cli.EXIT_REFUSED
    assert said.err.count("\n") == 1 and "not a regular file" in said.err
    assert "Traceback" not in said.err


@needs_io_counters
@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="no /dev/zero here")
def test_a_device_is_refused_without_a_read(tmp_path, capsys):
    counted = Counted()

    code, said = import_into(tmp_path, "/dev/zero", capsys, armed=counted.start)
    read = counted.read()

    assert code == cli.EXIT_REFUSED
    assert said.err.count("\n") == 1 and "not a regular file" in said.err
    assert read < READ_ALLOWED, f"{read} bytes were read of a device"


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no Unix-domain sockets here")
def test_a_socket_is_refused_as_not_a_regular_file(tmp_path, capsys):
    # A socket path is limited in length, which a test directory can exceed.
    with tempfile.TemporaryDirectory(prefix="tri") as short:
        path = os.path.join(short, "s")
        with socket.socket(socket.AF_UNIX) as listening:
            listening.bind(path)

            code, said = import_into(tmp_path, path, capsys)

    assert code == cli.EXIT_REFUSED
    assert said.err.count("\n") == 1 and "Traceback" not in said.err
    assert said.err.endswith(f"refused: {path}: not a regular file; nothing is written\n")


def test_a_directory_is_refused_as_not_a_regular_file(tmp_path, capsys):
    code, said = import_into(tmp_path, tmp_path, capsys)

    assert code == cli.EXIT_REFUSED and "not a regular file" in said.err


def test_a_symlink_to_a_regular_file_is_still_read(tmp_path, capsys):
    target = tmp_path / "target.json"
    target.write_text("not json")
    link = tmp_path / "link.json"
    link.symlink_to(target)

    code, said = import_into(tmp_path, link, capsys)

    assert code == cli.EXIT_REFUSED and "is not JSON" in said.err


def test_a_file_at_the_limit_is_still_read(tmp_path, capsys):
    """The limit is on size and not a reason to refuse: a file at it is read, and refused for
    what it holds."""
    at_limit = tmp_path / "at-limit.json"
    with at_limit.open("wb") as handle:
        handle.truncate(cli.TRIAGE_IMPORT_MAX_BYTES)

    code, said = import_into(tmp_path, at_limit, capsys)

    assert code == cli.EXIT_REFUSED and "is not JSON" in said.err


def rows_of(count, *, same_identity=False):
    return [
        {
            "id": number,
            "identity": dict.fromkeys(IDENTITY_FIELDS, "same" if same_identity else str(number)),
            "role": "operator",
            "status": "confirmed",
            "author": "A. Operator",
            "at_utc": "2026-11-02T08:00:00.000+00:00",
            "engagement_digest": None,
            "supersedes": number - 1 if same_identity and number > 1 else None,
        }
        for number in range(1, count + 1)
    ]


def export_of(rows):
    return {
        "triage_export_version": store_module.TRIAGE_EXPORT_VERSION,
        "store_schema": store_module.TRIAGE_EXPORT_SCHEMAS[0],
        "store_sha256": DIGEST,
        "engagement_chain_digests": [],
        "rows": rows,
    }


def checked(rows):
    return store_module._export_rows(export_of(rows), store_module._import_refused)


@pytest.mark.parametrize("same_identity", [False, True])
def test_many_rows_are_checked_in_linear_time(same_identity):
    rows = rows_of(20_000, same_identity=same_identity)

    started = time.perf_counter()
    checked(rows)

    # Quadratic, this took tens of seconds; the margin is for a slow machine.
    assert time.perf_counter() - started < 1.0


def test_a_row_that_repeats_an_earlier_decision_is_still_found_among_many():
    rows = rows_of(20_000)
    rows.append({**rows[5], "id": 20_001})

    with pytest.raises(StoreError) as refused:
        checked(rows)

    assert "row 20001: it supersedes None, where the decision of its identity" in str(refused.value)
    assert "before it is 6" in str(refused.value)


def test_a_supersession_naming_no_earlier_row_is_still_found_among_many():
    rows = rows_of(1_000)
    rows[-1] = {**rows[-1], "supersedes": 5_000}

    with pytest.raises(StoreError) as refused:
        checked(rows)

    assert "which is no earlier row of the file" in str(refused.value)
