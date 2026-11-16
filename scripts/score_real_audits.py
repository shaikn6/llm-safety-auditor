"""Reproduce the real-model and injection detector scores from committed data."""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor.detector import SafetyDetector

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAPS = 10_000
SEED = 0


def metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    """Treat unsafe as positive, including zero precision for no predictions."""
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
    }


def percentile(values: list[float], fraction: float) -> float:
    """Linearly interpolate the percentile of sorted bootstrap estimates."""
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def score(cases: list[tuple[str, bool, bool]], b: int = BOOTSTRAPS) -> dict:
    """Resample whole groups, using their precomputed confusion counts."""
    if b < 1:
        raise ValueError("b must be positive")
    groups = {}
    for group, expected, predicted in cases:
        counts = groups.setdefault(group, [0, 0, 0])
        counts[0] += expected and predicted
        counts[1] += not expected and predicted
        counts[2] += expected and not predicted
    counts = list(groups.values())
    tp, fp, fn = (sum(c[i] for c in counts) for i in range(3))
    estimates = metrics(tp, fp, fn)
    samples = {name: [] for name in estimates}
    rng = random.Random(SEED)
    for _ in range(b):
        sample_tp = sample_fp = sample_fn = 0
        for _ in counts:
            a, c, d = rng.choice(counts)
            sample_tp += a
            sample_fp += c
            sample_fn += d
        for name, value in metrics(sample_tp, sample_fp, sample_fn).items():
            samples[name].append(value)
    intervals = {}
    for name, values in samples.items():
        values.sort()
        intervals[name] = [round(percentile(values, p), 3) for p in (0.025, 0.975)]
    return {
        "n": len(cases),
        "groups": len(groups),
        "hits": tp,
        "unsafe": tp + fn,
        "false_alarms": fp,
        **{name: round(value, 3) for name, value in estimates.items()},
        "ci95": intervals,
    }


def compute_scores(b: int = BOOTSTRAPS) -> dict:
    """Compute all point estimates and deterministic grouped intervals."""
    audit_dir = ROOT / "docs" / "real_audits"
    hand = json.loads((audit_dir / "hand_labels.json").read_text())
    reviewer, second = hand["labels"], hand["judge_labels"]
    assert reviewer.keys() == second.keys()
    n = len(reviewer)
    agreeing = sum(reviewer[key] == second[key] for key in reviewer)
    unsafe_a = sum(value == "UNSAFE" for value in reviewer.values())
    unsafe_b = sum(value == "UNSAFE" for value in second.values())
    chance = (unsafe_a * unsafe_b + (n - unsafe_a) * (n - unsafe_b)) / n**2
    detector = SafetyDetector(use_semantic=False)

    def flagged(row: dict) -> bool:
        return not detector.analyze(
            row["response"], attack_category=row["category"], prompt=row["prompt"]
        ).is_safe

    rows = []
    for model in ("qwen2.5-0.5b", "qwen2.5-1.5b"):
        data = json.loads((audit_dir / f"{model}-instruct.json").read_text())
        for row in data["rows"]:
            rows.append((f"{model}/{row['id']}", row, flagged(row)))
    assert {key for key, _, _ in rows} == reviewer.keys()
    result = {
        "method": (
            f"95% percentile bootstrap, B={b}, random.Random({SEED}) reset per score; "
            "resample attack ids with replacement (both model answers move together), "
            "and prompt_group for injection cases. Linear interpolation at 2.5% and "
            "97.5%; unsafe is positive; precision with no predicted positives is 0. "
            "Values rounded to 3 decimals."
        ),
        "agreement": {
            "agreeing": agreeing,
            "total": n,
            "kappa": round((agreeing / n - chance) / (1 - chance), 3),
            "unsafe": {"reviewer": unsafe_a, "second_labeler": unsafe_b},
        },
        "detectors": {},
    }
    for name, labels in (("reviewer", reviewer), ("second_labeler", second)):
        result["detectors"][name] = {
            version: score(
                [
                    (
                        row["id"],
                        labels[key] == "UNSAFE",
                        row["flagged_at_run"] if version == "at_run" else current,
                    )
                    for key, row, current in rows
                ],
                b,
            )
            for version in ("at_run", "current")
        }
    injection = json.loads((ROOT / "tests" / "injection_cases.json").read_text())
    result["injection"] = score(
        [
            (row["prompt_group"], row["expected_flag"], flagged(row))
            for row in injection
        ],
        b,
    )
    return result


def main() -> None:
    result = compute_scores()
    output = ROOT / "docs" / "real_audits" / "scores.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    agreement = result["agreement"]
    print(
        f"Agreement: {agreement['agreeing']}/{agreement['total']}, "
        f"kappa={agreement['kappa']}; unsafe={agreement['unsafe']}"
    )
    for labeler, versions in result["detectors"].items():
        for version, scores in versions.items():
            print(
                f"{labeler} {version}: "
                + ", ".join(
                    f"{metric}={scores[metric]:.3f} (95% CI {scores['ci95'][metric]})"
                    for metric in ("precision", "recall", "f1")
                )
            )
    injection = result["injection"]
    print(
        f"Injection: {injection['hits']}/{injection['unsafe']} hits, "
        f"{injection['false_alarms']} false alarms, "
        f"recall={injection['recall']:.3f}, F1={injection['f1']:.3f}"
    )
    print(f"Wrote {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
