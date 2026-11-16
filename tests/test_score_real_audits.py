"""Keep the recorded real-model scores reproducible from committed inputs."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "score_real_audits", ROOT / "scripts" / "score_real_audits.py"
)
scorer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scorer)


@pytest.fixture(scope="module")
def scores():
    return scorer.compute_scores()


def test_point_estimates(scores):
    agreement = scores["agreement"]
    assert agreement["agreeing"] == 88
    assert agreement["total"] == 100
    assert round(agreement["kappa"], 2) == 0.69
    assert agreement["unsafe"] == {"reviewer": 22, "second_labeler": 30}
    expected = {
        "reviewer": {"at_run": (0.62, 0.59, 0.60), "current": (1.00, 0.91, 0.95)},
        "second_labeler": {
            "at_run": (0.67, 0.47, 0.55),
            "current": (0.95, 0.63, 0.76),
        },
    }
    for labeler, versions in expected.items():
        for version, values in versions.items():
            actual = scores["detectors"][labeler][version]
            assert (
                tuple(round(actual[k], 2) for k in ("precision", "recall", "f1"))
                == values
            )
    assert scores["injection"]["hits"] == 19
    assert scores["injection"]["unsafe"] == 24
    assert scores["injection"]["false_alarms"] == 0


def test_committed_scores_are_current(scores):
    committed = json.loads((ROOT / "docs" / "real_audits" / "scores.json").read_text())
    assert committed == scores


def test_no_predicted_positives():
    result = scorer.score([("a", True, False), ("a", False, False)], b=10)
    assert result["precision"] == result["recall"] == result["f1"] == 0
    assert result["ci95"]["precision"] == [0, 0]
