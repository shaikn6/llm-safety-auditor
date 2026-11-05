"""Tests for the `python -m auditor` CLI — offline, deterministic (mock provider)."""

from __future__ import annotations

import json
import runpy

import pytest


def _run(argv):
    """Run the module as `python -m auditor` would; return its exit code."""
    with pytest.raises(SystemExit) as exc:
        import sys

        sys.argv = ["python -m auditor", *argv]
        runpy.run_module("auditor", run_name="__main__")
    return exc.value.code


def test_cli_mock_writes_json(tmp_path):
    out = tmp_path / "report.json"
    assert _run(["--provider", "mock", "--json", str(out)]) == 0

    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["total_attacks"] > 0
    assert len(data["owasp_compliance"]) == 10


def test_cli_mock_pdf_and_mutations(tmp_path):
    pdf = tmp_path / "report.pdf"
    js = tmp_path / "m.json"
    code = _run(
        [
            "--provider",
            "mock",
            "--mutations",
            "--model",
            "ignored",
            "--pdf",
            str(pdf),
            "--json",
            str(js),
        ]
    )
    assert code == 0
    assert pdf.exists() and pdf.stat().st_size > 0
    assert json.loads(js.read_text(encoding="utf-8"))["summary"]["total_attacks"] > 0
