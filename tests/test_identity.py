"""The server's version in a finding key: its own content, never the repository or this tool."""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli
from mcp_kymograph.identity import (
    UNDECLARED_ENDPOINT_VERSION,
    IdentityError,
    from_content,
    from_endpoint,
    from_revision,
)

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = FIXTURES / "discovery_server.py"
REFERENCE = FIXTURES / "corpus" / "reference_server.py"
POISON = FIXTURES / "corpus" / "poison_server.py"


def digest_of(*pairs: tuple[str, bytes]) -> str:
    """The definition, written out independently: sorted [relative path, file hash] pairs,
    as JSON, hashed together."""
    listed = sorted([name, hashlib.sha256(content).hexdigest()] for name, content in pairs)
    return "sha256:" + hashlib.sha256(json.dumps(listed).encode()).hexdigest()


def test_the_version_is_a_digest_over_relative_paths_and_contents_and_nothing_else(tmp_path):
    """Nothing about the repository and nothing about this tool goes in: the digest is
    reproduced here from names and bytes alone. That is the decoupling the key needs — a
    change to Kymograph cannot move the version of a server whose files did not change."""
    a, b = tmp_path / "server.py", tmp_path / "base.py"
    a.write_bytes(b"print('server')\n")
    b.write_bytes(b"print('base')\n")
    identity = from_content([a, b])
    assert identity.version == digest_of(("server.py", a.read_bytes()), ("base.py", b.read_bytes()))
    assert (identity.kind, identity.files) == ("content", 2)


def test_the_version_is_the_same_in_every_process(tmp_path):
    """Hash randomisation must not reach the version. Computed in processes with different
    fixed hash seeds, it is the same everywhere — so a run on another day, or in a batch,
    files its findings under the same key. Fixed seeds make this deterministic: an ordering
    that leaked from a set would differ between them every time, not only sometimes."""
    files = []
    for number in range(8):
        path = tmp_path / f"part{number}.py"
        path.write_bytes(f"value = {number}\n".encode())
        files.append(str(path))
    program = (
        "import sys; from mcp_kymograph.identity import from_content; "
        "print(from_content(sys.argv[1:]).version)"
    )
    versions = {
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", program, *files],
            env={**os.environ, "PYTHONHASHSEED": str(seed)},
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        for seed in range(4)
    }
    assert versions == {digest_of(*((Path(f).name, Path(f).read_bytes()) for f in files))}


def layout(root: Path, files: dict[str, bytes]) -> list[Path]:
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(content)
    return [root / name for name in files]


def test_location_and_order_do_not_matter_and_one_byte_does(tmp_path):
    one = layout(tmp_path / "one", {"server.py": b"x = 1\n", "lib/base.py": b"y = 2\n"})
    two = layout(
        tmp_path / "elsewhere/deeper", {"server.py": b"x = 1\n", "lib/base.py": b"y = 2\n"}
    )
    assert from_content(one) == from_content(list(reversed(two)))
    two[0].write_bytes(b"x = 2\n")
    assert from_content(two) != from_content(one)


def test_the_same_bytes_under_another_layout_are_another_server(tmp_path):
    """The dangerous direction: two different servers must not collide on one
    version because their files happen to hold the same bytes."""
    one = layout(tmp_path / "one", {"server.py": b"x = 1\n", "util.py": b"y = 2\n"})
    two = layout(tmp_path / "two", {"main.py": b"x = 1\n", "helpers.py": b"y = 2\n"})
    assert from_content(one) != from_content(two)
    moved = layout(tmp_path / "three", {"server.py": b"x = 1\n", "pkg/util.py": b"y = 2\n"})
    assert from_content(moved) != from_content(one), "a file moved is a new layout"


def test_a_directory_is_its_files_without_caches_and_version_control(tmp_path):
    server = tmp_path / "server"
    layout(server, {"main.py": b"m\n", "pkg/mod.py": b"p\n"})
    plain = from_content([server])
    layout(
        server,
        {
            "__pycache__/main.cpython-312.pyc": b"cache",
            "__pycache__/CACHEDIR.TAG": b"not a .pyc, and still not the server",
            "pkg/__pycache__/mod.cpython-312.pyc": b"cache",
            ".git/HEAD": b"ref: refs/heads/main\n",
            "stray.pyc": b"compiled",
        },
    )
    assert from_content([server]) == plain
    assert plain.files == 2
    assert plain.version == digest_of(("main.py", b"m\n"), ("pkg/mod.py", b"p\n"))


def test_a_file_named_twice_or_also_through_its_directory_counts_once(tmp_path):
    server = tmp_path / "server"
    (main,) = layout(server, {"main.py": b"m\n"})
    assert from_content([server, main, main]) == from_content([main])


@pytest.mark.parametrize("where", ["named", "inside"])
def test_a_symbolic_link_is_refused_rather_than_followed(tmp_path, where):
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"secret = 1\n")
    server = tmp_path / "server"
    layout(server, {"main.py": b"m\n"})
    link = (tmp_path if where == "named" else server) / "link.py"
    link.symlink_to(outside)
    with pytest.raises(IdentityError, match="symbolic link"):
        from_content([link] if where == "named" else [server])


def test_the_reference_and_the_poison_server_are_different_servers():
    """Same base, different entry file: different content, different version."""
    reference = from_content([REFERENCE, DISCOVERY])
    poison = from_content([POISON, DISCOVERY])
    assert reference.version != poison.version


@pytest.mark.parametrize("bad", ["no files", "an empty directory", "missing"])
def test_a_server_that_cannot_be_named_by_its_files_is_refused(tmp_path, bad):
    (tmp_path / "empty").mkdir()
    names = {
        "no files": [],
        "an empty directory": [tmp_path / "empty"],
        "missing": [tmp_path / "absent.py"],
    }
    with pytest.raises(IdentityError):
        from_content(names[bad])


def test_a_revision_must_be_a_full_commit():
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert from_revision(f"github.com/org/server@{sha}").version == f"github.com/org/server@{sha}"
    assert from_revision(f"github.com/org/server@{'a' * 64}").kind == "revision"
    for moving in (
        "github.com/org/server@HEAD",
        "github.com/org/server@main",
        "github.com/org/server@v1.2.0",
        "github.com/org/server@0123456",
        f"github.com/org/server@{sha.upper()}",
        "github.com/org/server",
    ):
        with pytest.raises(IdentityError, match="pinned"):
            from_revision(moving)


def test_an_endpoint_version_is_the_declared_string_or_the_word_endpoint_and_says_which():
    declared = from_endpoint("http://127.0.0.1:8080/mcp", "3.1")
    assert (declared.kind, declared.version, declared.files) == ("endpoint", "3.1", 0)
    assert declared.to_dict() == {
        "kind": "endpoint",
        "version": "3.1",
        "files": 0,
        "version_declared": "3.1",
    }
    undeclared = from_endpoint("http://127.0.0.1:8080/mcp", None)
    assert undeclared.version == UNDECLARED_ENDPOINT_VERSION == "endpoint"
    assert undeclared.to_dict() == {
        "kind": "endpoint",
        "version": "endpoint",
        "files": 0,
        "version_declared": None,
    }
    # Declaring the word itself is still a declaration, and the dict says so.
    assert from_endpoint("http://127.0.0.1:8080/mcp", "endpoint").to_dict()["version_declared"]
    for url, version in (("", None), (None, None), ("http://h:1/", ""), ("http://h:1/", 3)):
        with pytest.raises(IdentityError):
            from_endpoint(url, version)


def test_content_and_revision_identities_keep_their_dict(tmp_path):
    """No version_declared beside a version that was established, not declared."""
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert set(from_content([DISCOVERY]).to_dict()) == {"kind", "version", "files"}
    assert from_revision(f"github.com/org/server@{sha}").to_dict() == {
        "kind": "revision",
        "version": f"github.com/org/server@{sha}",
        "files": 0,
    }


def run_cli(tmp_path, *ours):
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "drive",
            "--out-dir",
            str(tmp_path / "runs"),
            *ours,
            "--",
            sys.executable,
            str(DISCOVERY),
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_the_identity_is_recorded_in_run_started(tmp_path):
    done = run_cli(tmp_path, "--server-content", str(DISCOVERY))
    assert done.returncode == 0, done.stderr
    (recording,) = (tmp_path / "runs").glob("*/events.jsonl")
    started = json.loads(recording.read_text().splitlines()[0])
    assert started["server_identity"] == {
        "kind": "content",
        "version": digest_of(("discovery_server.py", DISCOVERY.read_bytes())),
        "files": 1,
    }


def test_a_server_file_that_cannot_be_read_is_refused_before_the_run(tmp_path):
    done = run_cli(tmp_path, "--server-content", str(tmp_path / "absent.py"))
    assert done.returncode == cli.EXIT_REFUSED
    assert b"absent.py" in done.stderr
    assert not (tmp_path / "runs").exists(), "refused before anything was created"


def test_the_refusal_of_a_link_names_the_path_once(tmp_path, monkeypatch):
    """Up to the link, and the file by its name; a link that is the named path itself is all
    there is to say."""
    layout(tmp_path / "real" / "b", {"x.py": b"x = 1\n"})
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "last.py").symlink_to(tmp_path / "real" / "b" / "x.py")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(IdentityError) as through:
        from_content(["a/link/b/x.py"])
    assert str(through.value) == (
        "a/link is a symbolic link on the way to x.py; name what it points to instead"
    )
    with pytest.raises(IdentityError) as itself:
        from_content(["last.py"])
    assert str(itself.value) == "last.py is a symbolic link; name what it points to instead"


def test_two_dots_without_a_link_stay_allowed(tmp_path):
    """``..`` is only refused where it leads through a link; by itself it names the same file."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "x.py").write_text("x = 1\n")
    direct = from_content([tmp_path / "b" / "x.py"])
    assert from_content([tmp_path / "a" / ".." / "b" / "x.py"]) == direct


def test_server_content_through_a_linked_directory_is_refused_before_the_run(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "x.py").write_text("x = 1\n")
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    done = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "drive",
            "--out-dir",
            "runs",
            "--server-content",
            "link/x.py",
            "--",
            sys.executable,
            str(DISCOVERY),
        ],
        capture_output=True,
        timeout=60,
        check=False,
        cwd=tmp_path,
    )
    assert done.returncode == cli.EXIT_REFUSED
    assert b"link is a symbolic link on the way to x.py; name what it points to instead" in (
        done.stderr
    )
    assert not (tmp_path / "runs").exists(), "refused before anything was created"


def test_content_and_revision_cannot_both_be_given(tmp_path):
    sha = "0123456789abcdef0123456789abcdef01234567"
    done = run_cli(
        tmp_path, "--server-content", str(DISCOVERY), "--server-revision", f"github.com/x/y@{sha}"
    )
    assert done.returncode == 2
    assert b"not allowed with" in done.stderr


def test_a_symbolic_link_to_a_directory_inside_the_server_is_refused(tmp_path):
    outside = tmp_path / "outside"
    layout(outside, {"secret.py": b"s = 1\n"})
    server = tmp_path / "server"
    layout(server, {"main.py": b"m\n"})
    (server / "lib").symlink_to(outside, target_is_directory=True)
    with pytest.raises(IdentityError, match="a symbolic link inside the server's files"):
        from_content([server])


def test_the_bounds_on_the_number_and_the_size_of_the_files_hold(tmp_path, monkeypatch):
    from mcp_kymograph import identity

    server = tmp_path / "server"
    layout(server, {"a.py": b"12345", "b.py": b"67890", "c.py": b"x"})
    monkeypatch.setattr(identity, "MAX_CONTENT_FILES", 3)
    monkeypatch.setattr(identity, "MAX_CONTENT_BYTES", 11)
    assert from_content([server]).files == 3
    layout(server, {"d.py": b""})
    with pytest.raises(IdentityError, match="more than 3 server files"):
        from_content([server])
    monkeypatch.setattr(identity, "MAX_CONTENT_FILES", 4)
    monkeypatch.setattr(identity, "MAX_CONTENT_BYTES", 10)
    with pytest.raises(IdentityError, match="larger than 10 bytes together"):
        from_content([server])


def test_a_file_that_cannot_be_read_is_refused_with_the_reason(tmp_path, monkeypatch):
    server = tmp_path / "server"
    (main,) = layout(server, {"main.py": b"m\n"})
    real = type(main).read_bytes

    def refuse(self):
        if self.name == "main.py":
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(type(main), "read_bytes", refuse)
    with pytest.raises(IdentityError, match="main.py: cannot read: Permission denied"):
        from_content([server])


@pytest.mark.parametrize("inside", [False, True])
def test_a_symbolic_link_as_an_intermediate_component_is_refused(tmp_path, inside):
    """A link above the last component is refused like a last one, wherever it points."""
    real = tmp_path / ("server/real" if inside else "outside")
    layout(real, {"x.py": b"x = 1\n"})
    link = tmp_path / "server" / "link"
    link.parent.mkdir(exist_ok=True)
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(IdentityError, match="link is a symbolic link"):
        from_content([link / "x.py"])
    with pytest.raises(IdentityError, match="link is a symbolic link"):
        from_content([link / ".." / "server" / "link" / "x.py"])


def test_a_relative_path_is_checked_from_the_working_directory_on(tmp_path, monkeypatch):
    """Links above the working directory are not the server's; those below it are."""
    layout(tmp_path / "work", {"ok/x.py": b"x = 1\n"})
    layout(tmp_path / "other", {"x.py": b"y = 1\n"})
    (tmp_path / "work" / "link").symlink_to(tmp_path / "other", target_is_directory=True)
    (tmp_path / "alias").symlink_to(tmp_path / "work", target_is_directory=True)
    monkeypatch.chdir(tmp_path / "alias")
    from_content(["ok/x.py"])
    with pytest.raises(IdentityError, match="link is a symbolic link"):
        from_content(["link/x.py"])


def test_a_base_limits_the_check_to_the_components_below_it(tmp_path):
    """Through a link above the base the files are accepted, with the identity of the real path."""
    (real,) = layout(tmp_path / "real", {"x.py": b"x = 1\n"})
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(IdentityError, match="alias is a symbolic link"):
        from_content([alias / "x.py"])
    assert from_content([alias / "x.py"], base=alias) == from_content([real])
    (real.parent / "sub").mkdir()
    (real.parent / "sub" / "l").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(IdentityError, match="l is a symbolic link"):
        from_content([alias / "sub" / "l" / "real" / "x.py"], base=alias)
    with pytest.raises(IdentityError, match="not under"):
        from_content([real], base=tmp_path / "other")


def test_an_absolute_path_is_checked_from_the_first_component_below_the_root(tmp_path, monkeypatch):
    """A system directory that is a link (``/tmp`` on some systems) is a link in the path as it
    was named. No test can make one below the root, so the first component is said to be one."""
    (file,) = layout(tmp_path, {"x.py": b"x = 1\n"})
    first = Path(file.anchor) / file.parts[1]
    real = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == first or real(self))
    with pytest.raises(IdentityError, match=f"{re.escape(str(first))} is a symbolic link"):
        from_content([file])
