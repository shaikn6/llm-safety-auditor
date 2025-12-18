"""Tests for replay/attack_replay.py"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from auditor.detector import SafetyDetector
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM
from replay.attack_replay import (
    DiffReport,
    ReplayStore,
    StoredAttackRun,
    TimelinePoint,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db():
    with tempfile.TemporaryDirectory() as tmp:
        yield str(Path(tmp) / "test_replay.db")


@pytest.fixture
def store(tmp_db):
    s = ReplayStore(db_path=tmp_db)
    yield s
    s.close()


def _make_report(seed: int = 42, session_id: str = "test"):
    llm = MockLLM(global_seed=seed)
    det = SafetyDetector(use_semantic=False)
    ev = SafetyEvaluator(llm=llm, detector=det, session_id=session_id)
    return ev.run()


# ---------------------------------------------------------------------------
# Store creation and schema
# ---------------------------------------------------------------------------


class TestReplayStoreInit:
    def test_creates_db_file(self, tmp_db):
        store = ReplayStore(db_path=tmp_db)
        store.close()
        assert Path(tmp_db).exists()

    def test_context_manager(self, tmp_db):
        with ReplayStore(db_path=tmp_db) as store:
            assert store is not None

    def test_idempotent_schema_creation(self, tmp_db):
        # Creating twice should not raise
        s1 = ReplayStore(db_path=tmp_db)
        s1.close()
        s2 = ReplayStore(db_path=tmp_db)
        s2.close()


# ---------------------------------------------------------------------------
# Save and retrieve runs
# ---------------------------------------------------------------------------


class TestSaveAndRetrieve:
    def test_save_run_stores_attack_rows(self, store):
        report = _make_report(seed=42, session_id="save-test")
        store.save_run("run-001", "model-v1", report)
        runs = store.get_runs_for_model("model-v1")
        assert len(runs) == report.total_attacks

    def test_stored_run_fields(self, store):
        report = _make_report(seed=42)
        store.save_run("run-001", "model-v1", report)
        runs = store.get_runs_for_model("model-v1")
        r = runs[0]
        assert isinstance(r, StoredAttackRun)
        assert r.model_version == "model-v1"
        assert r.run_id == "run-001"
        assert isinstance(r.is_safe, bool)
        assert 0.0 <= r.confidence <= 1.0
        assert isinstance(r.triggered_rules, list)

    def test_list_audit_runs(self, store):
        report = _make_report(seed=42)
        store.save_run("run-001", "model-v1", report)
        runs = store.list_audit_runs()
        assert len(runs) >= 1
        assert any(r["run_id"] == "run-001" for r in runs)

    def test_get_attack_history(self, store):
        report = _make_report(seed=42)
        store.save_run("run-001", "model-v1", report)
        store.save_run("run-002", "model-v2", report)
        first_id = report.attack_results[0].attack.id
        history = store.get_attack_history(first_id)
        assert len(history) == 2

    def test_get_latest_run_id(self, store):
        report = _make_report(seed=42)
        store.save_run("run-001", "model-v1", report)
        latest = store.get_latest_run_id("model-v1")
        assert latest == "run-001"

    def test_get_latest_run_id_none_for_unknown_model(self, store):
        assert store.get_latest_run_id("unknown-model") is None


# ---------------------------------------------------------------------------
# Diff report
# ---------------------------------------------------------------------------


class TestDiffReport:
    def test_diff_report_structure(self, store):
        r1 = _make_report(seed=42)
        r2 = _make_report(seed=99)
        store.save_run("run-v1", "model-v1", r1)
        store.save_run("run-v2", "model-v2", r2)
        diff = store.diff_report("model-v1", "model-v2")
        assert isinstance(diff, DiffReport)
        assert diff.model_v1 == "model-v1"
        assert diff.model_v2 == "model-v2"

    def test_diff_report_counts_add_up(self, store):
        r1 = _make_report(seed=42)
        r2 = _make_report(seed=99)
        store.save_run("run-v1", "model-v1", r1)
        store.save_run("run-v2", "model-v2", r2)
        diff = store.diff_report("model-v1", "model-v2")
        total_compared = (
            len(diff.regressions)
            + len(diff.improvements)
            + diff.unchanged_safe
            + diff.unchanged_unsafe
        )
        assert total_compared == r1.total_attacks

    def test_diff_report_same_seed_no_regressions(self, store):
        report = _make_report(seed=42)
        store.save_run("run-v1", "same-v1", report)
        store.save_run("run-v2", "same-v2", report)
        diff = store.diff_report("same-v1", "same-v2")
        assert len(diff.regressions) == 0
        assert len(diff.improvements) == 0

    def test_diff_net_change(self, store):
        r1 = _make_report(seed=42)
        r2 = _make_report(seed=99)
        store.save_run("run-v1", "nc-v1", r1)
        store.save_run("run-v2", "nc-v2", r2)
        diff = store.diff_report("nc-v1", "nc-v2")
        expected = len(diff.regressions) - len(diff.improvements)
        assert diff.net_change == expected

    def test_diff_includes_safety_scores(self, store):
        r1 = _make_report(seed=42)
        r2 = _make_report(seed=99)
        store.save_run("run-v1", "sc-v1", r1)
        store.save_run("run-v2", "sc-v2", r2)
        diff = store.diff_report("sc-v1", "sc-v2")
        assert diff.v1_safety_score is not None
        assert diff.v2_safety_score is not None

    def test_diff_summary_string(self, store):
        r1 = _make_report(seed=42)
        r2 = _make_report(seed=99)
        store.save_run("run-v1", "sum-v1", r1)
        store.save_run("run-v2", "sum-v2", r2)
        diff = store.diff_report("sum-v1", "sum-v2")
        summary = diff.summary()
        assert "Regressions" in summary
        assert "Improvements" in summary


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TestTimeline:
    def test_empty_timeline(self, store):
        timeline = store.safety_timeline()
        assert timeline == []

    def test_timeline_after_runs(self, store):
        r1 = _make_report(seed=42)
        r2 = _make_report(seed=99)
        store.save_run("run-v1", "tl-v1", r1)
        store.save_run("run-v2", "tl-v2", r2)
        timeline = store.safety_timeline()
        assert len(timeline) == 2
        assert all(isinstance(p, TimelinePoint) for p in timeline)

    def test_timeline_scores_in_range(self, store):
        report = _make_report(seed=42)
        store.save_run("run-v1", "tl-score", report)
        timeline = store.safety_timeline()
        for p in timeline:
            assert 0.0 <= p.safety_score <= 100.0


# ---------------------------------------------------------------------------
# Regression runner
# ---------------------------------------------------------------------------


class TestRegressionRunner:
    def test_run_regression_stores_results(self, store):
        llm = MockLLM(global_seed=42)
        det = SafetyDetector(use_semantic=False)
        report = store.run_regression("test-model", llm=llm, detector=det)
        runs = store.get_runs_for_model("test-model")
        assert len(runs) == report.total_attacks
