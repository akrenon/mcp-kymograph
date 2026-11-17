"""Builds the four images of the real servers and writes their ids to images.json.

    python3 tests/real_servers/build.py

The tests (tests/test_real_servers.py) start an image only by the id written here. Each
directory beside this file holds a Dockerfile and a requirements.txt (every package pinned by
version and hash); the build fetches from PyPI and from nothing else.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMES = (
    "fetch-2025-11-25",
    "fetch-2026-07-28",
    "reference-http-2025-11-25",
    "reference-http-2026-07-28",
)
IMAGES = HERE / "images.json"


def run(*command: str) -> str:
    done = subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, check=False, timeout=1800
    )
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        raise SystemExit(f"failed: {' '.join(command)}")
    return done.stdout.strip()


def main() -> int:
    ids = {}
    for name in NAMES:
        tag = f"mcp-kymograph-real-server/{name}:build"
        run("docker", "build", "--quiet", "--tag", tag, str(HERE / name))
        ids[name] = run("docker", "image", "inspect", "--format", "{{.Id}}", tag)
        if not ids[name].startswith("sha256:"):
            raise SystemExit(f"{name}: not an image id: {ids[name]!r}")
        print(f"{name}: {ids[name]}")
    IMAGES.write_text(json.dumps(ids, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
