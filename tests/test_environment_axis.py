"""Isolation and images are the environment, not the server.

Runs of the same servers under two isolations showed the findings do not depend on the isolation. So
where a run observed is not part of what a finding is: the same finding under runc and on the host
is one finding, and the diff matches it as unchanged. But it is recorded — the isolation and both
images by id, in the triple — and the diff knows it as a fourth axis: when only it moved and
findings differ anyway, the diff says exactly that and flags it, rather than putting it down to the
server or swallowing it. A rebuilt image with other packages is another id, so drift in what
observes is a visible move on that axis.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_kymograph import cli, verdict
from mcp_kymograph.environment import helper_env
from mcp_kymograph.store import ENVIRONMENT_MOVED, IDENTITY_FIELDS, KEY_FIELDS, Store, StoreError
from test_store import finding, recording

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT = FIXTURES / "corpus" / "manifest.yaml"
SANDBOX_ID = "sha256:" + "5a" * 32
TARGET_ID = "sha256:" + "7a" * 32
CONSISTENT = {
    "seq": 60,
    "type": "egress_summary",
    "consistent": True,
    "udp_loss": {"kernel": 0, "sink": 0, "lost": 0, "unseen_destinations": 0, "rate": 0.0},
}


def runc(**changes):
    """A runc recording's environment and the egress account such a run carries."""
    return {
        "isolation": "runc",
        "sandbox_image": SANDBOX_ID,
        "target_image": TARGET_ID,
        "extra": [CONSISTENT],
        **changes,
    }


def compare(tmp_path, before, after):
    with Store.open(tmp_path / "store.sqlite") as store:
        store.ingest(before)
        store.ingest(after)
        return store.diff(store.resolve(str(before)), store.resolve(str(after)))


def test_the_environment_is_in_no_key():
    for name in ("isolation", "sandbox_image", "target_image", "environment"):
        assert name not in KEY_FIELDS and name not in IDENTITY_FIELDS


def test_the_same_finding_under_the_host_and_under_runc_is_one_finding(tmp_path):
    before = recording(tmp_path, [finding(5)], name="host")
    after = recording(tmp_path, [finding(5)], name="runc", **runc())
    result = compare(tmp_path, before, after)
    assert result.complete
    assert [c.identity["signal"] for c in result.unchanged] == ["hidden_comment"]
    assert result.new == () and result.gone == ()
    assert result.moved == ("environment",)
    axis = result.axes["environment"]
    assert axis["isolation"] == {"before": "host", "after": "runc"}
    assert axis["sandbox_image"] == {"before": None, "after": SANDBOX_ID}
    assert result.caveats == {"new": (), "gone": ()}, "nothing differs, nothing to flag"


def test_a_finding_that_moves_when_only_the_environment_moved_is_flagged_not_blamed(tmp_path):
    """Against expectation, a finding is gone under runc. Only the environment moved: the
    diff names that axis, says the difference is not the server's, flags the set softly —
    and stays complete."""
    before = recording(tmp_path, [finding(5), finding(6, statement="other")], name="host")
    after = recording(tmp_path, [finding(5)], name="runc", asked=[("other", "hidden_comment")],
                      **runc())  # fmt: skip
    result = compare(tmp_path, before, after)
    assert result.complete
    assert [c.identity["statement"] for c in result.gone] == ["other"]
    assert result.attribution.axis == "environment"
    assert "only the environment axis moved" in result.attribution.note
    assert "not the server's" in result.attribution.note
    assert ENVIRONMENT_MOVED in result.caveats["gone"]
    assert ENVIRONMENT_MOVED not in result.caveats["new"], "an empty set has nothing to flag"


def test_a_rebuilt_image_is_a_move_on_the_environment_axis(tmp_path):
    """Same isolation, the sandbox image rebuilt with other packages: another id."""
    before = recording(tmp_path, [finding(5)], name="a", **runc())
    after = recording(tmp_path, [finding(5)], name="b", **runc(sandbox_image="sha256:" + "5b" * 32))
    result = compare(tmp_path, before, after)
    assert result.moved == ("environment",)
    assert result.axes["environment"]["sandbox_image"]["after"] == "sha256:" + "5b" * 32
    assert result.axes["environment"]["isolation"] == {"before": "runc", "after": "runc"}


def test_the_environment_moving_with_another_axis_is_attributed_to_neither(tmp_path):
    before = recording(tmp_path, [finding(5)], name="host")
    after = recording(
        tmp_path, [], name="runc", asked=[("st", "hidden_comment")],
        launch="sha256:" + "23" * 32, **runc(),
    )  # fmt: skip
    result = compare(tmp_path, before, after)
    assert set(result.moved) == {"server", "environment"}
    assert result.attribution.attributable is False


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ("drop", "names no environment"),
        ("mismatch", "the triple's isolation differs"),
    ],
)
def test_a_run_whose_environment_is_missing_or_contradicted_is_refused(tmp_path, change, fragment):
    path = recording(tmp_path, [finding(5)])
    events = [json.loads(line) for line in path.read_text().splitlines()]
    if change == "drop":
        del events[0]["reproduction"]["environment"]
    else:
        events[0]["isolation"] = "runc"
    path.write_text("".join(json.dumps(e) + "\n" for e in events))
    with Store.open(tmp_path / "store.sqlite") as store, pytest.raises(StoreError, match=fragment):
        store.ingest(path)


def test_images_that_ran_but_are_not_the_ones_named_make_the_run_not_a_result():
    images = {"sandbox": {"id": SANDBOX_ID}, "target": {"id": "sha256:other"}}
    ran = {"type": "sandbox_step", "step": "images", "ok": True, "detail": {"images": images}}
    events = [
        {"type": "run_started", "mode": "driver", "isolation": "runc",
         "reproduction": {"environment": {"isolation": "runc", "sandbox_image": SANDBOX_ID,
                                          "target_image": TARGET_ID}}},
        ran, CONSISTENT, {"type": "script_finished"},
        {"type": "run_finished", "findings_by_statement": {}, "server_output_bytes": 100,
         "client_input_bytes": 100, "server_exited_first": False},
    ]  # fmt: skip
    judged = verdict.assess(events)
    assert judged.state == verdict.SANDBOX_FAILED
    assert any("target image that ran is not the one" in p for p in judged.problems)
    images["target"]["id"] = TARGET_ID
    assert verdict.assess(events).state == verdict.COMPLETE


def test_image_flags_belong_to_a_runc_run(tmp_path):
    code = cli.main(
        ["drive", "-q", "--out-dir", str(tmp_path / "runs"), "--manifest", str(PROJECT),
         "--entry", "poison-server", "--sandbox-image", "anything"]
    )  # fmt: skip
    assert code == cli.EXIT_REFUSED
    assert not (tmp_path / "runs").exists()


# -- end to end, with Docker -------------------------------------------------------------------


def _image_id(reference: str) -> str | None:
    if shutil.which("docker") is None:
        return None
    done = subprocess.run(  # noqa: S603
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],  # noqa: S607
        capture_output=True, env=helper_env(), check=False,
    )  # fmt: skip
    return done.stdout.decode().strip() if done.returncode == 0 else None


SANDBOX_REAL = _image_id("mcp-kymograph-sandbox:1")
TARGET_REAL = _image_id("python:3.12-slim")
docker = pytest.mark.docker


def drive(out: Path, *flags):
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), "--manifest", str(PROJECT), "--entry",
         "poison-server", *flags]
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


@docker
def test_a_runc_run_names_the_images_it_ran_by_id_and_the_pair_is_unchanged_across(tmp_path):
    """Images given by tag, recorded by id — the ids Docker itself gives — and the same ids in
    the sandbox's own first step. The poison entry on the host and under runc: four findings,
    all unchanged; only the environment moved."""
    code, under_runc, events = drive(tmp_path / "runc", "--isolation", "runc")
    assert code == 0
    env = events[0]["reproduction"]["environment"]
    assert env == {"isolation": "runc", "sandbox_image": SANDBOX_REAL, "target_image": TARGET_REAL}
    (step,) = [e for e in events if e["type"] == "sandbox_step" and e["step"] == "images"]
    assert step["detail"]["images"]["sandbox"]["id"] == SANDBOX_REAL
    assert step["detail"]["images"]["target"]["id"] == TARGET_REAL

    code, on_host, events = drive(tmp_path / "host")
    assert code == 0
    assert events[0]["reproduction"]["environment"]["isolation"] == "host"
    result = compare(tmp_path, on_host, under_runc)
    assert result.complete
    assert len(result.unchanged) == 4 and not result.new and not result.gone
    assert result.moved == ("environment",)


@docker
def test_an_image_that_cannot_be_resolved_is_named_as_none_and_the_sandbox_fails_on_it(tmp_path):
    code, path, events = drive(
        tmp_path, "--isolation", "runc", "--target-image", "mcp-kymograph-no-such-image:0"
    )
    assert code == cli.EXIT_SANDBOX_FAILED
    env = events[0]["reproduction"]["environment"]
    assert env["target_image"] is None and env["sandbox_image"] == SANDBOX_REAL
    assert [e["condition"] for e in events if e["type"] == "sandbox_failed"] == ["images"]
    assert verdict.read(path).state == verdict.SANDBOX_FAILED
