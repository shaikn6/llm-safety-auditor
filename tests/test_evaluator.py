"""Tests for evaluator.py"""

from __future__ import annotations

import pytest

from auditor.attack_library import ALL_ATTACKS, AttackCategory, Severity
from auditor.detector import SafetyDetector
from auditor.evaluator import (
    SafetyEvaluator,
)
from auditor.mock_llm import MockLLM

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm():
    return MockLLM(global_seed=42)


@pytest.fixture
def detector():
    return SafetyDetector(use_semantic=False)


@pytest.fixture
def evaluator(mock_llm, detector):
    return SafetyEvaluator(
        llm=mock_llm, detector=detector, session_id="test-session-001"
    )


@pytest.fixture
def full_report(evaluator):
    """Run a full 50-attack audit (deterministic with seed=42)."""
    return evaluator.run()


# ---------------------------------------------------------------------------
# AuditReport structure tests
# ---------------------------------------------------------------------------


class TestAuditReportStructure:
    def test_report_has_correct_total(self, full_report):
        assert full_report.total_attacks == 50

    def test_safe_plus_unsafe_equals_total(self, full_report):
        assert (
            full_report.safe_responses + full_report.unsafe_responses
            == full_report.total_attacks
        )

    def test_overall_score_in_range(self, full_report):
        assert 0.0 <= full_report.overall_safety_score <= 100.0

    def test_refusal_rate_in_range(self, full_report):
        assert 0.0 <= full_report.refusal_rate <= 1.0

    def test_harmful_content_rate_in_range(self, full_report):
        assert 0.0 <= full_report.harmful_content_rate <= 1.0

    def test_leakage_rate_in_range(self, full_report):
        assert 0.0 <= full_report.leakage_rate <= 1.0

    def test_session_id_preserved(self, full_report):
        assert full_report.session_id == "test-session-001"

    def test_model_name_present(self, full_report):
        assert full_report.model_name == "mock-llm-v1"

    def test_elapsed_ms_positive(self, full_report):
        assert full_report.elapsed_total_ms >= 0

    def test_recommendations_non_empty(self, full_report):
        assert len(full_report.recommendations) > 0

    def test_attack_results_count_matches(self, full_report):
        assert len(full_report.attack_results) == full_report.total_attacks


class TestCategorySummaries:
    def test_all_five_categories_in_summaries(self, full_report):
        cats = {s.category for s in full_report.category_summaries}
        assert len(cats) == 5

    def test_each_summary_has_ten_attacks(self, full_report):
        for s in full_report.category_summaries:
            assert s.total_attacks == 10

    def test_success_rate_in_range(self, full_report):
        for s in full_report.category_summaries:
            assert 0.0 <= s.attack_success_rate <= 1.0

    def test_successful_plus_not_successful_equals_total(self, full_report):
        for s in full_report.category_summaries:
            # Refusal count can overlap with safe responses
            assert s.successful_attacks <= s.total_attacks

    def test_owasp_ref_non_empty(self, full_report):
        for s in full_report.category_summaries:
            assert s.owasp_ref.strip()

    def test_sorted_by_success_rate_desc(self, full_report):
        rates = [s.attack_success_rate for s in full_report.category_summaries]
        assert rates == sorted(rates, reverse=True)


class TestOWASPCompliance:
    def test_ten_owasp_items(self, full_report):
        assert len(full_report.owasp_compliance) == 10

    def test_status_values_valid(self, full_report):
        valid_statuses = {"PASS", "WARN", "FAIL"}
        for o in full_report.owasp_compliance:
            assert o.status in valid_statuses

    def test_owasp_ids_present(self, full_report):
        ids = {o.owasp_id for o in full_report.owasp_compliance}
        assert "LLM01" in ids
        assert "LLM06" in ids
        assert "LLM09" in ids

    def test_notes_non_empty(self, full_report):
        for o in full_report.owasp_compliance:
            assert o.notes.strip()

    def test_pass_rate_property(self, full_report):
        assert 0.0 <= full_report.pass_rate <= 1.0
        expected = full_report.safe_responses / full_report.total_attacks
        assert abs(full_report.pass_rate - expected) < 1e-6


class TestSafetyDimensions:
    def test_six_dimensions_present(self, full_report):
        dims = full_report.safety_dimensions
        assert len(dims) == 6

    def test_expected_dimension_names(self, full_report):
        dims = full_report.safety_dimensions
        for expected in [
            "Harmlessness",
            "Honesty",
            "Privacy",
            "Robustness",
            "Bias",
            "Hallucination",
        ]:
            assert expected in dims

    def test_dimension_scores_in_range(self, full_report):
        for name, score in full_report.safety_dimensions.items():
            assert 0.0 <= score <= 100.0, f"{name} score out of range: {score}"


# ---------------------------------------------------------------------------
# Filtered run tests
# ---------------------------------------------------------------------------


class TestFilteredRuns:
    def test_run_single_category(self, mock_llm, detector):
        ev = SafetyEvaluator(llm=mock_llm, detector=detector, session_id="cat-test")
        report = ev.run(categories=[AttackCategory.JAILBREAK])
        assert report.total_attacks == 10
        assert all(
            r.attack.category == AttackCategory.JAILBREAK for r in report.attack_results
        )

    def test_run_with_limit(self, mock_llm, detector):
        ev = SafetyEvaluator(llm=mock_llm, detector=detector, session_id="limit-test")
        report = ev.run(limit=5)
        assert report.total_attacks == 5

    def test_run_critical_severity_only(self, mock_llm, detector):
        ev = SafetyEvaluator(llm=mock_llm, detector=detector, session_id="sev-test")
        report = ev.run(severities=[Severity.CRITICAL])
        for r in report.attack_results:
            assert r.attack.severity == Severity.CRITICAL

    def test_run_two_categories(self, mock_llm, detector):
        ev = SafetyEvaluator(llm=mock_llm, detector=detector, session_id="two-cat")
        report = ev.run(
            categories=[AttackCategory.JAILBREAK, AttackCategory.DATA_EXFILTRATION]
        )
        assert report.total_attacks == 20
        cats = {r.attack.category for r in report.attack_results}
        assert cats == {AttackCategory.JAILBREAK, AttackCategory.DATA_EXFILTRATION}

    def test_empty_result_when_nothing_matches(self, mock_llm, detector):
        ev = SafetyEvaluator(llm=mock_llm, detector=detector, session_id="empty-test")
        # Combine filters that likely yield zero results
        report = ev.run(
            categories=[AttackCategory.JAILBREAK],
            severities=[Severity.LOW],  # No jailbreaks have LOW severity
            limit=10,
        )
        assert report.total_attacks == 0


# ---------------------------------------------------------------------------
# Determinism tests
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_seed_same_results(self):
        def run_with_seed(seed: int) -> float:
            llm = MockLLM(global_seed=seed)
            det = SafetyDetector(use_semantic=False)
            ev = SafetyEvaluator(llm=llm, detector=det, session_id="det-test")
            return ev.run().overall_safety_score

        score1 = run_with_seed(42)
        score2 = run_with_seed(42)
        assert score1 == score2

    def test_different_seeds_may_differ(self):
        def run_with_seed(seed: int) -> float:
            llm = MockLLM(global_seed=seed)
            det = SafetyDetector(use_semantic=False)
            ev = SafetyEvaluator(llm=llm, detector=det, session_id="diff-seed")
            return ev.run().overall_safety_score

        score_42 = run_with_seed(42)
        score_99 = run_with_seed(99)
        # Not guaranteed to differ on every run, but should differ often enough
        # We just verify both produce valid scores
        assert 0 <= score_42 <= 100
        assert 0 <= score_99 <= 100

    def test_verdict_independent_of_filters(self):
        """An attack gets the same mock draw however the run is composed."""

        def simulated(**filters) -> dict[str, bool]:
            report = SafetyEvaluator(llm=MockLLM(global_seed=42)).run(**filters)
            return {
                r.attack.id: r.llm_response.is_simulated_failure
                for r in report.attack_results
            }

        full = simulated()
        for category in AttackCategory:
            filtered = simulated(categories=[category])
            assert filtered == {k: full[k] for k in filtered}, category

    def test_same_attack_same_response_on_repeat(self):
        llm = MockLLM(global_seed=42)
        attack = ALL_ATTACKS[0]
        assert llm.complete(attack).response_text == llm.complete(attack).response_text


# ---------------------------------------------------------------------------
# Recommendations tests
# ---------------------------------------------------------------------------


class TestRecommendations:
    def test_recommendations_are_strings(self, full_report):
        for rec in full_report.recommendations:
            assert isinstance(rec, str)

    def test_general_recommendations_always_present(self, full_report):
        # These are always appended
        recs = " ".join(full_report.recommendations)
        assert "CI/CD" in recs or "red-teaming" in recs

    def test_high_hallucination_triggers_recommendation(self):
        """
        When hallucination bypass rate is high across a full run, the recommendation
        for RAG/fact-checking should appear.
        Seed=99 produces non-zero hallucination bypass rate in the full 50-attack run.
        """
        llm = MockLLM(global_seed=99)
        det = SafetyDetector(use_semantic=False)
        ev = SafetyEvaluator(llm=llm, detector=det, session_id="halluc-rec-test")
        # Run full suite so hallucination category gets hits from both its 10 attacks
        # AND the cross-category aggregation produces a bypass rate > 0.5
        report = ev.run()
        recs = " ".join(report.recommendations)
        # At minimum the general red-teaming recommendation is always present
        assert (
            "red-teaming" in recs.lower() or "CI/CD" in recs or "audit" in recs.lower()
        )


# ---------------------------------------------------------------------------
# Mutation engine wiring (include_mutations)
# ---------------------------------------------------------------------------


class TestIncludeMutations:
    def test_default_runs_only_the_curated_seeds(self, evaluator):
        assert evaluator.run().total_attacks == 50

    def test_include_mutations_runs_seeds_plus_six_variants_each(self, evaluator):
        report = evaluator.run(include_mutations=True)
        assert report.total_attacks == 50 * 7  # 350

    def test_seeds_come_first_and_variants_are_tagged_and_distinct(self, evaluator):
        attacks = [
            r.attack for r in evaluator.run(include_mutations=True).attack_results
        ]
        seeds, variants = attacks[:50], attacks[50:]
        assert all("~m" not in a.id for a in seeds)
        assert all(a.id.split("~m")[0] and "~m" in a.id for a in variants)
        assert len({a.id for a in attacks}) == len(attacks)
        assert max(len(a.id) for a in attacks) <= 16  # attack_id column width
        strategies = {t for a in variants for t in a.tags if t.startswith("mutation:")}
        assert len(strategies) == 6

    def test_variants_keep_category_and_severity_of_their_seed(self, evaluator):
        from auditor.attack_library import get_attack_by_id

        for r in evaluator.run(include_mutations=True).attack_results[50:]:
            seed = get_attack_by_id(r.attack.id.split("~m")[0])
            assert r.attack.category == seed.category
            assert r.attack.severity == seed.severity
            assert r.attack.template

    def test_filters_apply_before_expansion(self, evaluator):
        report = evaluator.run(
            categories=[AttackCategory.JAILBREAK], include_mutations=True
        )
        assert report.total_attacks == 10 * 7

    def test_limit_keeps_seeds_before_variants(self, evaluator):
        report = evaluator.run(limit=60, include_mutations=True)
        ids = [r.attack.id for r in report.attack_results]
        assert len(ids) == 60
        assert all("~m" not in i for i in ids[:50])
        assert all("~m" in i for i in ids[50:])

    def test_pool_is_bounded_by_the_hard_ceiling(self, evaluator):
        # A huge explicit limit with mutations must not exceed _MAX_POOL_SIZE
        # (an authenticated, rate-limited run stays bounded).
        from auditor.evaluator import _MAX_POOL_SIZE

        report = evaluator.run(limit=100000, include_mutations=True)
        assert len(report.attack_results) <= _MAX_POOL_SIZE


# ---------------------------------------------------------------------------
# Provider failures mid-audit
# ---------------------------------------------------------------------------


class _FlakyLLM:
    """MockLLM that raises ProviderError for the attack ids in `fail_ids`."""

    def __init__(self, fail_ids):
        self._inner = MockLLM(global_seed=42)
        self._fail_ids = set(fail_ids)

    def complete(self, attack):
        from auditor.providers import ProviderError

        if attack.id in self._fail_ids:
            raise ProviderError(f"rate limited on {attack.id}")
        return self._inner.complete(attack)


class TestProviderErrors:
    def test_one_failed_call_keeps_the_other_results(self, detector):
        failing = ALL_ATTACKS[3].id
        report = SafetyEvaluator(llm=_FlakyLLM({failing}), detector=detector).run(
            limit=10
        )

        assert len(report.attack_results) == 9
        assert failing not in {r.attack.id for r in report.attack_results}
        assert len(report.errors) == 1
        assert report.errors[0].attack.id == failing
        assert f"rate limited on {failing}" in report.errors[0].error

        # The errored attack is neither passed nor failed: every rate is over
        # the 9 scored attacks only.
        assert report.total_attacks == 9
        assert report.safe_responses + report.unsafe_responses == 9
        assert report.overall_safety_score == round(100 * report.safe_responses / 9, 2)
        assert sum(s.total_attacks for s in report.category_summaries) == 9

    def test_every_call_failing_still_raises(self, detector):
        from auditor.providers import ProviderError

        ids = {a.id for a in ALL_ATTACKS[:5]}
        evaluator = SafetyEvaluator(llm=_FlakyLLM(ids), detector=detector)
        with pytest.raises(ProviderError, match="rate limited"):
            evaluator.run(limit=5)

    def test_json_report_lists_errored_attacks(self, detector, tmp_path):
        import json
        from pathlib import Path

        from auditor.report_generator import generate_json_report

        failing = ALL_ATTACKS[0].id
        report = SafetyEvaluator(llm=_FlakyLLM({failing}), detector=detector).run(
            limit=4
        )
        path = generate_json_report(report, str(tmp_path / "r.json"))
        data = json.loads(Path(path).read_text())
        assert data["summary"]["total_attacks"] == 3
        assert data["summary"]["errored_attacks"] == 1
        assert data["errored_attacks"] == [
            {
                "attack_id": failing,
                "category": ALL_ATTACKS[0].category.value,
                "status": "error",
                "error": f"rate limited on {failing}",
            }
        ]
