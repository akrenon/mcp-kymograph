"""Every field the web API gives for TLS is read by ``app.js``.

A scaffold only, until the headless check of the page (a later phase) shows what is drawn: this
reads the page's source, not its output, so it finds a field the page never names — one that would
be silently dropped from view — and says nothing of how a field that is named is shown. The field
names come from the API data of a test run, not from a list written here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mcp_kymograph.store import Store
from mcp_kymograph.web import views
from mcp_kymograph.web.views import Sources
from test_store_triage import IDENTITY, finding_id
from test_triage_transfer import carried, engaged_store, exported
from test_web_tls import Tls, run_of
from test_web_views import checked

APP_JS = Path(views.__file__).parent / "static" / "app.js"


@pytest.fixture(scope="module")
def tls(tmp_path_factory) -> Tls:
    return Tls(tmp_path_factory.mktemp("tls-fields"))


def names_in(value: object) -> set[str]:
    """The keys of a mapping, or of every mapping in a list; nothing for anything else."""
    if isinstance(value, dict):
        return set(value)
    if isinstance(value, list):
        return {name for item in value for name in names_in(item)}
    return set()


def tls_fields(tls: Tls) -> set[str]:
    """What the API gives for TLS in a run's overview and HTTP tab, and in the store's runs."""
    fields: set[str] = set()
    for name in ("https", "https-machine-store", "handshake"):
        data = run_of(tls, name)["data"]
        started = data["overview"]["run_started"]
        finished = data["overview"]["run_finished"]
        assert "trust_store_env" in started and "tls" in finished["http"]
        fields |= {"trust_store_env", "tls"}
        fields |= names_in(started["trust_store_env"]) | names_in(finished["http"]["tls"])
    data = run_of(tls, "https")["data"]
    for exchange in data["http"]["exchanges"]:
        for request in exchange["request"]:
            fields |= {"tls"} | names_in(request["tls"])
    rows = checked(views.store_runs(tls.sources), "store_runs")["data"]
    assert any(row["endpoint_certificates"] for row in rows)
    fields.add("endpoint_certificates")
    return fields


def import_fields(tmp_path) -> set[str]:
    """What the API gives for a triage row carried from another store: ``imported`` and its own
    fields, the schema of the import among them."""
    document, digest = carried(exported(tmp_path))
    fresh = engaged_store(tmp_path / "carried.sqlite", tmp_path)
    with Store.open(fresh) as store:
        store.import_triage(document, source_sha256=digest)
    found = finding_id(fresh, IDENTITY)
    history = checked(views.triage_history(Sources(store=fresh), found), "triage_history")["data"]
    imported = [row["imported"] for row in history["history"]]
    assert imported and all(imported)
    assert "store_schema" in names_in(imported)
    return {"imported"} | names_in(imported)


def test_every_tls_field_the_api_gives_is_read_in_app_js(tls):
    source = APP_JS.read_text()
    fields = tls_fields(tls)
    assert {"tls", "trust_store_env", "certificates", "endpoint_certificates"} <= fields
    missing = sorted(
        name for name in fields if not re.search(rf"(?:\.|')\b{re.escape(name)}\b", source)
    )
    assert missing == [], f"app.js never reads {missing}"


def test_every_field_of_a_carried_triage_row_s_origin_is_read_in_app_js(tmp_path):
    source = APP_JS.read_text()
    fields = import_fields(tmp_path)
    assert {"imported", "store_schema", "store_sha256", "file_sha256"} <= fields
    missing = sorted(
        name for name in fields if not re.search(rf"(?:\.|')\b{re.escape(name)}\b", source)
    )
    assert missing == [], f"app.js never reads {missing}"
