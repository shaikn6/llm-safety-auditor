"""python -m auditor — run the OWASP LLM Top 10 audit and write the scored report.

One command, offline by default (seeded mock provider, no API key):

    python -m auditor --provider mock --pdf report.pdf --json report.json

Point it at a real model with --provider anthropic|openai (needs the matching
API key in the environment, as auditor.providers documents).
"""

from __future__ import annotations

import argparse
import os
import sys

from .evaluator import SafetyEvaluator
from .providers import build_provider
from .report_generator import generate_json_report, generate_pdf_report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m auditor",
        description="Run the OWASP LLM Top 10 safety audit and write the scored report.",
    )
    ap.add_argument(
        "--provider",
        choices=["mock", "anthropic", "openai"],
        default="mock",
        help="model under audit (default: offline seeded mock, no API key)",
    )
    ap.add_argument(
        "--model",
        default="",
        help="model name for the anthropic/openai provider (ignored for mock)",
    )
    ap.add_argument(
        "--base-url",
        default="",
        help="OpenAI-compatible endpoint base URL (openai provider only)",
    )
    ap.add_argument(
        "--mutations",
        action="store_true",
        help="also run the mutation engine's variants of every seed attack",
    )
    ap.add_argument(
        "--json", dest="json_path", metavar="PATH", help="write JSON report here"
    )
    ap.add_argument(
        "--pdf", dest="pdf_path", metavar="PATH", help="write PDF report here"
    )
    ap.add_argument(
        "--seed", type=int, default=42, help="mock provider seed (default: 42)"
    )
    args = ap.parse_args(argv)

    env = {**os.environ, "LLM_PROVIDER": args.provider}
    if args.model:
        env["LLM_MODEL"] = args.model
    if args.base_url:
        env["OPENAI_BASE_URL"] = args.base_url

    llm = build_provider(seed=args.seed, env=env)
    report = SafetyEvaluator(llm=llm, session_id=f"cli-{args.provider}").run(
        include_mutations=args.mutations
    )

    print(
        f"{report.model_name}: {report.unsafe_responses}/{report.total_attacks} flagged, "
        f"safety score {report.overall_safety_score}, "
        f"OWASP {report.owasp_pass_count}/10 PASS"
    )
    if args.json_path:
        print(f"JSON report: {generate_json_report(report, args.json_path)}")
    if args.pdf_path:
        print(f"PDF report: {generate_pdf_report(report, args.pdf_path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
