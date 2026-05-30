"""Tests for ci/github_actions_generator.py"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from auditor.detector import SafetyDetector
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM
from ci.github_actions_generator import (
    SarifReport,
    SarifRule,
    SarifResult,
    WorkflowConfig,
    build_sarif_from_report,
    generate_badge_markdown,
    generate_github_actions_workflow,
    write_sarif_file,
    write_workflow_file,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_report():
    llm = MockLLM(global_seed=42)
    det = SafetyDetector(use_semantic=False)
    ev = SafetyEvaluator(llm=llm, detector=det, session_id="ci-test")
    return ev.run()


@pytest.fixture
def sarif_report(sample_report):
    return build_sarif_from_report(sample_report)


# ---------------------------------------------------------------------------
# WorkflowConfig
# ---------------------------------------------------------------------------

class TestWorkflowConfig:
    def test_defaults(self):
        cfg = WorkflowConfig()
        assert cfg.fail_on_critical_count == 0
        assert cfg.warn_on_high_count == 3
        assert cfg.python_version == "3.11"
        assert cfg.attack_limit == 50
        assert cfg.enable_sarif_upload is True

    def test_custom_config(self):
        cfg = WorkflowConfig(fail_on_critical_count=2, warn_on_high_count=10, python_version="3.12")
        assert cfg.fail_on_critical_count == 2
        assert cfg.warn_on_high_count == 10
        assert cfg.python_version == "3.12"


# ---------------------------------------------------------------------------
# GitHub Actions YAML generation
# ---------------------------------------------------------------------------

class TestGithubActionsGenerator:
    def test_generates_yaml_string(self):
        yaml_str = generate_github_actions_workflow()
        assert isinstance(yaml_str, str)
        assert len(yaml_str) > 100

    def test_yaml_contains_on_pull_request(self):
        yaml_str = generate_github_actions_workflow()
        assert "pull_request" in yaml_str

    def test_yaml_contains_sarif_upload(self):
        yaml_str = generate_github_actions_workflow()
        assert "upload-sarif" in yaml_str

    def test_yaml_contains_python_version(self):
        yaml_str = generate_github_actions_workflow(WorkflowConfig(python_version="3.12"))
        assert "3.12" in yaml_str

    def test_yaml_contains_fail_threshold(self):
        yaml_str = generate_github_actions_workflow(WorkflowConfig(fail_on_critical_count=3))
        assert "3" in yaml_str

    def test_write_workflow_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_workflow_file(tmp)
            assert path.exists()
            content = path.read_text()
            assert "safety-audit" in content

    def test_write_workflow_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_workflow_file(tmp)
            assert path.parent.name == "workflows"


# ---------------------------------------------------------------------------
# SARIF generation
# ---------------------------------------------------------------------------

class TestSarifGeneration:
    def test_sarif_report_has_rules(self, sarif_report):
        assert len(sarif_report.rules) > 0

    def test_sarif_rules_have_ids(self, sarif_report):
        for rule in sarif_report.rules:
            assert rule.rule_id
            assert rule.name

    def test_sarif_to_dict_has_required_schema(self, sarif_report):
        d = sarif_report.to_dict()
        assert "$schema" in d
        assert "version" in d
        assert d["version"] == "2.1.0"
        assert "runs" in d
        assert len(d["runs"]) == 1

    def test_sarif_to_json_is_valid_json(self, sarif_report):
        json_str = sarif_report.to_json()
        parsed = json.loads(json_str)
        assert "runs" in parsed

    def test_sarif_results_have_valid_levels(self, sarif_report):
        valid_levels = {"error", "warning", "note"}
        for result in sarif_report.results:
            assert result.level in valid_levels

    def test_sarif_results_reference_known_rules(self, sarif_report):
        rule_ids = {r.rule_id for r in sarif_report.rules}
        for result in sarif_report.results:
            assert result.rule_id in rule_ids, f"Unknown rule_id: {result.rule_id}"

    def test_write_sarif_file(self, sample_report):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "results.sarif"
            written = write_sarif_file(sample_report, out_path)
            assert written.exists()
            content = json.loads(written.read_text())
            assert "runs" in content

    def test_sarif_tool_name(self, sarif_report):
        assert sarif_report.tool_name == "LLM Safety Auditor"
        assert sarif_report.tool_version == "2.0.0"


# ---------------------------------------------------------------------------
# Badge generator
# ---------------------------------------------------------------------------

class TestBadgeGenerator:
    def test_green_badge_for_high_score(self):
        badge = generate_badge_markdown(92.0)
        assert "3fb950" in badge
        assert "92" in badge

    def test_yellow_badge_for_medium_score(self):
        badge = generate_badge_markdown(70.0)
        assert "d29922" in badge
        assert "70" in badge

    def test_red_badge_for_low_score(self):
        badge = generate_badge_markdown(45.0)
        assert "f85149" in badge
        assert "45" in badge

    def test_badge_contains_markdown_image_syntax(self):
        badge = generate_badge_markdown(85.0)
        assert badge.startswith("![")
        assert "img.shields.io" in badge

    def test_badge_score_boundary_80(self):
        green = generate_badge_markdown(80.0)
        yellow = generate_badge_markdown(79.9)
        assert "3fb950" in green
        assert "d29922" in yellow

    def test_badge_score_boundary_60(self):
        yellow = generate_badge_markdown(60.0)
        red = generate_badge_markdown(59.9)
        assert "d29922" in yellow
        assert "f85149" in red
