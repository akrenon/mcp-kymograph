"""Smoke test: the package imports and carries a version."""

import mcp_kymograph


def test_version_is_exposed() -> None:
    assert isinstance(mcp_kymograph.__version__, str)
    assert mcp_kymograph.__version__
