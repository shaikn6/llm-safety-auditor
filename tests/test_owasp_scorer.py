"""Tests for scoring/owasp_scorer.py"""

from __future__ import annotations

import pytest

from auditor.detector import SafetyDetector
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM
from scoring.owasp_scorer import (
    OWASP_LLM_V1_1,
    SEVERITY_WEIGHTS,
    OWASPComplianceMatrix,
    OWASPScorer,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def full_report():
    llm = MockLLM(global_seed=42)
    det = SafetyDetector(use_semantic=False)
    ev = SafetyEvaluator(llm=llm, detector=det, session_id="owasp-test")
    return ev.run()


@pytest.fixture
def scorer():
    return OWASPScorer()


@pytest.fixture
def matrix(scorer, full_report):
    return scorer.score(full_report)


# ---------------------------------------------------------------------------
# Severity weights
# ---------------------------------------------------------------------------


class TestSeverityWeights:
    def test_critical_has_highest_weight(self):
        assert SEVERITY_WEIGHTS["CRITICAL"] > SEVERITY_WEIGHTS["HIGH"]

    def test_high_greater_than_medium(self):
        assert SEVERITY_WEIGHTS["HIGH"] > SEVERITY_WEIGHTS["MEDIUM"]

    def test_medium_greater_than_low(self):
        assert SEVERITY_WEIGHTS["MEDIUM"] > SEVERITY_WEIGHTS["LOW"]

    def test_critical_weight_is_10(self):
        assert SEVERITY_WEIGHTS["CRITICAL"] == 10

    def test_low_weight_is_1(self):
        assert SEVERITY_WEIGHTS["LOW"] == 1


# ---------------------------------------------------------------------------
# OWASP category definitions
# ---------------------------------------------------------------------------


class TestOWASPCategoryDefinitions:
    def test_ten_categories_defined(self):
        assert len(OWASP_LLM_V1_1) == 10

    def test_all_owasp_ids_present(self):
        ids = {cat.owasp_id for cat in OWASP_LLM_V1_1}
        for expected in [f"LLM0{i}" for i in range(1, 10)] + ["LLM10"]:
            assert expected in ids

    def test_each_category_has_sub_checks(self):
        for cat in OWASP_LLM_V1_1:
            assert len(cat.sub_checks) > 0, f"{cat.owasp_id} has no sub-checks"

    def test_each_sub_check_has_cwe_ids(self):
        for cat in OWASP_LLM_V1_1:
            for sc in cat.sub_checks:
                assert len(sc.cwe_ids) > 0, f"{sc.check_id} has no CWE IDs"

    def test_each_sub_check_has_remediation(self):
        for cat in OWASP_LLM_V1_1:
            for sc in cat.sub_checks:
                assert sc.remediation.strip(), f"{sc.check_id} has empty remediation"

    def test_each_category_has_remediation_guide(self):
        for cat in OWASP_LLM_V1_1:
            assert cat.remediation_guide.strip()

    def test_sub_check_ids_are_unique(self):
        all_ids = [sc.check_id for cat in OWASP_LLM_V1_1 for sc in cat.sub_checks]
        assert len(all_ids) == len(set(all_ids))


# ---------------------------------------------------------------------------
# OWASPScorer.score()
# ---------------------------------------------------------------------------


class TestOWASPScorerScore:
    def test_returns_matrix(self, matrix):
        assert isinstance(matrix, OWASPComplianceMatrix)

    def test_ten_category_scores(self, matrix):
        assert len(matrix.category_scores) == 10

    def test_overall_score_in_range(self, matrix):
        assert 0.0 <= matrix.overall_score <= 100.0

    def test_pass_warn_fail_sum_to_ten(self, matrix):
        assert matrix.pass_count + matrix.warn_count + matrix.fail_count == 10

    def test_category_scores_have_valid_status(self, matrix):
        valid = {"PASS", "WARN", "FAIL"}
        for cs in matrix.category_scores:
            assert cs.status in valid

    def test_category_scores_in_range(self, matrix):
        for cs in matrix.category_scores:
            assert 0.0 <= cs.score <= 100.0

    def test_total_penalty_non_negative(self, matrix):
        assert matrix.total_penalty >= 0

    def test_max_penalty_positive(self, matrix):
        assert matrix.max_possible_penalty > 0

    def test_penalty_not_exceeds_max(self, matrix):
        assert matrix.total_penalty <= matrix.max_possible_penalty

    def test_recommendations_non_empty(self, matrix):
        assert len(matrix.recommendations) > 0

    def test_cwe_summary_is_dict(self, matrix):
        assert isinstance(matrix.cwe_summary, dict)

    def test_markdown_table_contains_owasp_ids(self, matrix):
        md = matrix.markdown_table()
        for i in range(1, 11):
            id_str = f"LLM{i:02d}" if i >= 10 else f"LLM0{i}"
            assert id_str in md

    def test_sub_check_results_present(self, matrix):
        for cs in matrix.category_scores:
            assert len(cs.sub_check_results) > 0

    def test_sub_check_results_passed_is_bool(self, matrix):
        for cs in matrix.category_scores:
            for scr in cs.sub_check_results:
                assert isinstance(scr.passed, bool)

    def test_perfect_score_no_failures(self):
        # Use failure_rate_override=0 to guarantee all safe responses
        llm = MockLLM(failure_rate_override=0.0)
        det = SafetyDetector(use_semantic=False)
        ev = SafetyEvaluator(llm=llm, detector=det, session_id="perfect")
        report = ev.run()
        matrix = OWASPScorer().score(report)
        # With 0 failures, penalty should be 0 → score = 100
        assert matrix.overall_score == 100.0

    def test_worst_case_score_all_failures(self):
        # Use failure_rate_override=1.0 to guarantee all failures
        llm = MockLLM(failure_rate_override=1.0)
        det = SafetyDetector(use_semantic=False)
        ev = SafetyEvaluator(llm=llm, detector=det, session_id="worst")
        report = ev.run()
        matrix = OWASPScorer().score(report)
        # With all failures, overall score should be < 100
        assert matrix.overall_score < 100.0
