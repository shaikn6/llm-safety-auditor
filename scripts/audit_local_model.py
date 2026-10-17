"""Audit a model behind an OpenAI-compatible server with the full attack library and save every response.

Example (any server works; this one is `pip install mlx-lm`, Apple silicon):

    mlx_lm.server --model Qwen/Qwen2.5-0.5B-Instruct --port 8099
    python scripts/audit_local_model.py Qwen/Qwen2.5-0.5B-Instruct --base-url http://127.0.0.1:8099/v1 \
        --out docs/real_audits/qwen2.5-0.5b-instruct.json

Needs `pip install openai`. The server does not check the key, so a placeholder is used unless OPENAI_API_KEY is set.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor.evaluator import SafetyEvaluator
from auditor.providers import build_provider


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("model", help="model name the server expects")
    ap.add_argument(
        "--base-url",
        required=True,
        help="OpenAI-compatible endpoint, e.g. http://127.0.0.1:8099/v1",
    )
    ap.add_argument(
        "--out", type=Path, required=True, help="where to write the JSON results"
    )
    args = ap.parse_args()

    env = {
        **os.environ,
        "LLM_PROVIDER": "openai",
        "LLM_MODEL": args.model,
        "OPENAI_BASE_URL": args.base_url,
    }
    env.setdefault("OPENAI_API_KEY", "local")
    os.environ["OPENAI_API_KEY"] = env[
        "OPENAI_API_KEY"
    ]  # the SDK reads the real environment
    llm = build_provider(env=env)
    report = SafetyEvaluator(llm=llm, session_id=f"local-{args.model}").run()
    result = {
        "model": args.model,
        "total": report.total_attacks,
        "flagged": report.unsafe_responses,
        "refusal_rate": report.refusal_rate,
        "score": report.overall_safety_score,
        "per_category": {
            c.category.value: {
                "n": c.total_attacks,
                "flagged": c.successful_attacks,
                "refused": c.refusal_count,
            }
            for c in report.category_summaries
        },
        "rows": [
            {
                "id": r.attack.id,
                "category": r.attack.category.value,
                "severity": r.attack.severity.value,
                "prompt": r.attack.template,
                "response": r.llm_response.response_text,
                "flagged": not r.detection.is_safe,
            }
            for r in report.attack_results
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        f"{args.model}: {result['flagged']}/{result['total']} flagged, refusal rate {result['refusal_rate']:.0%}, score {result['score']}"
    )


if __name__ == "__main__":
    main()
