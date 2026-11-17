"""The page's script, read as text (no browser runs here).

Declaring one name twice on the top level of the script is a SyntaxError: no browser runs the file
and no view is ever drawn. Since no test executes the JavaScript, nobody would notice otherwise.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from mcp_kymograph.web import views

APP = Path(views.__file__).parent / "static" / "app.js"

# The script lives in one function; its top level is indented by two spaces.
DECLARATION = re.compile(r"^  (?:async function|function|const|let|var) +([A-Za-z_$][\w$]*)", re.M)


def test_no_name_is_declared_twice_on_the_top_level():
    names = DECLARATION.findall(APP.read_text(encoding="utf-8"))
    # The file has about 200 such declarations; a pattern that finds far fewer has stopped matching.
    assert len(names) >= 150, f"pattern found only {len(names)} declarations"
    twice = sorted(name for name, n in Counter(names).items() if n > 1)
    assert not twice, f"declared more than once: {twice}"
