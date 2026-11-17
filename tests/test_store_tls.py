"""The certificates an endpoint presented over TLS: filed, compared as sets, never an axis.

A run's set is read from ``run_finished.http.tls`` — the path nothing is dropped from — and filed
in ``runs.endpoint_certificates``, ``NULL`` for a run that spoke no TLS. A set that is present and
not one is refused whole, as every value the store files is. Two runs whose sets share no
certificate are said to have changed certificates, beside new and gone; the axes and the
attribution are exactly what they are without it (docs/design/http-transport.md 8.4).
"""

import itertools
import json
import sqlite3
from contextlib import closing

import pytest

from mcp_kymograph import cli
from mcp_kymograph.store import CERTIFICATE_CHANGED, SERVER_UNPINNED, Store, StoreError
from test_store import finding, recording

A, B, C, D = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
COUNTS = {"exchanges": 3, "responses": {"2xx": 3}, "streams": 0, "events": 0, "framing_errors": 0}
_ABSENT = object()
_DIFFS = itertools.count()


def tls(*certificates, versions=("TLSv1.3",)):
    return {"versions": list(versions), "certificates": list(certificates)}


def over_http(tmp_path, findings=(), *, name="run", tls=_ABSENT, http=_ABSENT, kind="content"):
    """A corpus recording over Streamable HTTP whose ``run_finished.http`` carries ``tls`` —
    absent when not given — or is ``http`` itself when that is given."""
    path = recording(tmp_path, list(findings), name=name)
    lines = path.read_text().splitlines()
    started, ended = json.loads(lines[0]), json.loads(lines[-1])
    started["transport"] = "streamable-http"
    started["reproduction"]["corpus"]["identity"]["kind"] = kind
    started["server_identity"]["kind"] = kind
    if http is _ABSENT:
        http = dict(COUNTS) if tls is _ABSENT else {**COUNTS, "tls": tls}
    ended["http"] = http
    lines[0], lines[-1] = json.dumps(started), json.dumps(ended)
    path.write_text("\n".join(lines) + "\n")
    return path


def column(database):
    with closing(sqlite3.connect(database)) as connection:
        return [row[0] for row in connection.execute("SELECT endpoint_certificates FROM runs")]


# -- filed with the run ------------------------------------------------------------------------


def test_an_https_run_files_its_certificates_as_a_sorted_json_list(tmp_path):
    database = tmp_path / "s.sqlite"
    with Store.open(database) as store:
        filed = store.ingest(over_http(tmp_path, tls=tls(A, B, versions=("TLSv1.2", "TLSv1.3"))))
        info = store.run_info(filed.run)
    assert column(database) == [json.dumps([A, B])]
    assert info.endpoint_certificates == (A, B)
    assert info.to_dict()["endpoint_certificates"] == [A, B]
    assert filed.complete, filed.problems


@pytest.mark.parametrize(
    "made",
    [
        lambda tmp_path: recording(tmp_path, []),
        lambda tmp_path: over_http(tmp_path),
        lambda tmp_path: over_http(tmp_path, tls=None),
        lambda tmp_path: over_http(tmp_path, http=None),
        lambda tmp_path: over_http(tmp_path, http="not an account"),
        lambda tmp_path: recording(tmp_path, [], finished=False),
    ],
    ids=["stdio", "http-without-tls", "tls-null", "http-null", "http-not-an-object", "unfinished"],
)
def test_a_run_that_spoke_no_tls_files_null(tmp_path, made):
    """Over stdio, plain HTTP, a recording from before TLS was spoken, or one whose account of
    HTTP the verdict judges as missing: no set, and nothing refused for it."""
    database = tmp_path / "s.sqlite"
    with Store.open(database) as store:
        filed = store.ingest(made(tmp_path))
        info = store.run_info(filed.run)
    assert column(database) == [None]
    assert info.endpoint_certificates is None
    assert info.to_dict()["endpoint_certificates"] is None


@pytest.mark.parametrize(
    "value",
    [
        "TLSv1.3",
        [A],
        {"certificates": [A]},
        {"versions": ["TLSv1.3"]},
        {**tls(A), "extra": 1},
        tls(A.upper()),
        tls("a" * 63),
        tls(B, A),
        tls(A, A),
        tls(A, versions=("TLSv1.3", "TLSv1.2")),
        tls(A, versions=("",)),
        {"versions": "TLSv1.3", "certificates": [A]},
        {"versions": ["TLSv1.3"], "certificates": None},
        tls(A, versions=(3,)),
    ],
)
def test_a_tls_set_that_is_not_one_refuses_the_whole_run(tmp_path, value):
    database = tmp_path / "s.sqlite"
    with Store.open(database) as store:
        with pytest.raises(StoreError, match=r"run_finished's http\.tls"):
            store.ingest(over_http(tmp_path, [finding(5)], tls=value))
        assert store.runs() == []
        assert store.findings_by_provenance("poison") == []


def test_an_empty_set_is_a_set(tmp_path):
    """An https run whose handshakes all failed presented nothing: filed as an empty list."""
    database = tmp_path / "s.sqlite"
    with Store.open(database) as store:
        filed = store.ingest(over_http(tmp_path, tls=tls(versions=())))
        assert store.run_info(filed.run).endpoint_certificates == ()
    assert column(database) == ["[]"]


def test_store_runs_and_store_diff_give_the_set(tmp_path, capsys):
    database = str(tmp_path / "s.sqlite")
    before = over_http(tmp_path, name="before", tls=tls(A))
    after = over_http(tmp_path, name="after")
    assert cli.main(["store", "ingest", "-q", "--store", database, str(before), str(after)]) == 0
    capsys.readouterr()
    assert cli.main(["store", "runs", "--store", database]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert sorted(run["endpoint_certificates"] or [] for run in listed) == [[], [A]]
    assert cli.main(["store", "diff", "--store", database, str(before), str(after)]) == 0
    compared = json.loads(capsys.readouterr().out)
    assert compared["before"]["endpoint_certificates"] == [A]
    assert compared["after"]["endpoint_certificates"] is None


# -- compared as sets, never an axis -----------------------------------------------------------


def diff(tmp_path, first, second, *, before=(), after=(), kind="content"):
    """The diff between a run with the set ``first`` and one with ``second`` (None: no TLS),
    sighting ``before`` and ``after``."""
    where = tmp_path / f"diff-{next(_DIFFS)}"
    where.mkdir()
    with Store.open(where / "s.sqlite") as store:
        runs = []
        for name, certificates, findings in (("one", first, before), ("two", second, after)):
            value = _ABSENT if certificates is None else tls(*certificates)
            path = over_http(where, findings, name=name, tls=value, kind=kind)
            runs.append(store.ingest(path).run)
        return store.diff(*runs)


FIRST_FINDINGS = [finding(5)]
SECOND_FINDINGS = [finding(6, statement="other")]


@pytest.mark.parametrize(
    ("first", "second"),
    [((A,), (B,)), ((A, B), (C, D)), ((A,), (C, D))],
)
def test_sets_that_share_no_certificate_are_said_on_new_and_gone(tmp_path, first, second):
    compared = diff(tmp_path, first, second, before=FIRST_FINDINGS, after=SECOND_FINDINGS)
    assert CERTIFICATE_CHANGED in compared.caveats["new"]
    assert CERTIFICATE_CHANGED in compared.caveats["gone"]
    assert compared.to_dict()["caveats"]["new"].count(CERTIFICATE_CHANGED) == 1


def test_the_caveat_is_given_whether_or_not_the_sets_of_findings_hold_entries(tmp_path):
    """As a scenario's drift is: the question changed, whatever the answer was."""
    compared = diff(tmp_path, (A,), (B,), before=FIRST_FINDINGS, after=FIRST_FINDINGS)
    assert (compared.new, compared.gone) == ((), ())
    assert compared.caveats == {"new": (CERTIFICATE_CHANGED,), "gone": (CERTIFICATE_CHANGED,)}


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ((A,), (A,)),
        ((A, B), (B, C)),
        ((A,), (A, B)),
        ((A,), None),
        (None, (A,)),
        (None, None),
        ((), (A,)),
        ((), ()),
    ],
    ids=["equal", "overlapping", "subset", "after-no-tls", "before-no-tls", "neither",
         "empty-before", "both-empty"],
)  # fmt: skip
def test_sets_that_share_a_certificate_or_a_side_without_one_add_nothing(tmp_path, first, second):
    """Another subset of an endpoint's certificates met the same deployment as far as the
    handshake can say; a side that presented none has nothing to compare."""
    compared = diff(tmp_path, first, second, before=FIRST_FINDINGS, after=SECOND_FINDINGS)
    assert CERTIFICATE_CHANGED not in compared.caveats["new"] + compared.caveats["gone"]


@pytest.mark.parametrize("kind", ["content", "endpoint"])
def test_the_caveat_moves_no_axis_and_no_attribution(tmp_path, kind):
    """Two diffs that differ only in the certificate sets: equal axes, equal attribution."""
    kept = diff(tmp_path, (A,), (A,), before=FIRST_FINDINGS, after=SECOND_FINDINGS, kind=kind)
    changed = diff(tmp_path, (A,), (B,), before=FIRST_FINDINGS, after=SECOND_FINDINGS, kind=kind)
    without = diff(tmp_path, None, None, before=FIRST_FINDINGS, after=SECOND_FINDINGS, kind=kind)
    assert kept.axes == changed.axes == without.axes
    assert kept.attribution == changed.attribution == without.attribution
    assert kept.moved == changed.moved == without.moved
    assert CERTIFICATE_CHANGED in changed.caveats["new"]
    assert CERTIFICATE_CHANGED not in kept.caveats["new"]
    # Everything else is the same; only the caveat stands beside it.
    for name in ("new", "gone"):
        others = tuple(c for c in changed.caveats[name] if c != CERTIFICATE_CHANGED)
        assert others == kept.caveats[name]


def test_server_unpinned_stays_beside_it(tmp_path):
    compared = diff(tmp_path, (A,), (B,), before=FIRST_FINDINGS, after=SECOND_FINDINGS,
                    kind="endpoint")  # fmt: skip
    for name in ("new", "gone"):
        assert SERVER_UNPINNED in compared.caveats[name]
        assert CERTIFICATE_CHANGED in compared.caveats[name]
