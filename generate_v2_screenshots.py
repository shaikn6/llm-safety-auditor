"""
generate_v2_screenshots.py — Generate V2 dashboard preview PNGs.

Run: python generate_v2_screenshots.py
Outputs to docs/screenshots/v2_*.png
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

SCREENSHOTS_DIR = Path(__file__).parent / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

# Dark GitHub-style theme
BG = "#0d1117"
SURFACE = "#161b22"
ACCENT = "#58a6ff"
TEXT = "#c9d1d9"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
PURPLE = "#bc8cff"
BORDER = "#30363d"


def _apply_dark_theme(fig, ax_list=None):
    fig.patch.set_facecolor(BG)
    axes = ax_list or fig.get_axes()
    for ax in axes:
        ax.set_facecolor(SURFACE)
        ax.tick_params(colors=TEXT)
        ax.xaxis.label.set_color(TEXT)
        ax.yaxis.label.set_color(TEXT)
        ax.title.set_color(ACCENT)
        for spine in ax.spines.values():
            spine.set_edgecolor(BORDER)
        ax.grid(color=BORDER, linewidth=0.5)


# ---------------------------------------------------------------------------
# PNG 1 — Attack generator: mutation strategy breakdown
# ---------------------------------------------------------------------------

def gen_attack_generator():
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("V2: Attack Generator — 100 Auto-Generated Variants", color=ACCENT, fontsize=14, fontweight="bold")

    strategies = ["prefix_injection", "role_play_framing", "base64_encoding", "unicode_homoglyphs", "nested_instructions"]
    counts = [20, 20, 20, 20, 20]
    colors_s = [ACCENT, GREEN, YELLOW, RED, PURPLE]

    ax0 = axes[0]
    wedges, texts, autotexts = ax0.pie(
        counts, labels=strategies, colors=colors_s,
        autopct="%1.0f%%", startangle=90,
        textprops={"color": TEXT, "fontsize": 8},
    )
    for at in autotexts:
        at.set_color(BG)
        at.set_fontweight("bold")
    ax0.set_title("By Mutation Strategy", color=ACCENT)
    ax0.set_facecolor(SURFACE)

    ax1 = axes[1]
    difficulties = ["easy", "medium", "hard"]
    diff_counts = [40, 40, 20]
    diff_colors = [GREEN, YELLOW, RED]
    bars = ax1.bar(difficulties, diff_counts, color=diff_colors, edgecolor=BORDER, linewidth=0.5)
    for bar, val in zip(bars, diff_counts):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, str(val),
                 ha="center", va="bottom", color=TEXT, fontsize=11, fontweight="bold")
    ax1.set_title("By Difficulty Level", color=ACCENT)
    ax1.set_ylabel("Attack Count", color=TEXT)
    ax1.set_ylim(0, 55)
    ax1.tick_params(colors=TEXT)
    ax1.set_facecolor(SURFACE)
    ax1.grid(color=BORDER, linewidth=0.5, axis="y")
    for spine in ax1.spines.values():
        spine.set_edgecolor(BORDER)

    fig.patch.set_facecolor(BG)
    plt.tight_layout()
    out = SCREENSHOTS_DIR / "v2_attack_generator.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# PNG 2 — CI/CD: SARIF findings overview
# ---------------------------------------------------------------------------

def gen_ci_sarif():
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("V2: CI/CD GitHub Actions + SARIF Output", color=ACCENT, fontsize=14, fontweight="bold")

    owasp_ids = ["LLM01", "LLM06", "LLM09", "LLM-JB", "LLM02"]
    error_counts = [3, 5, 7, 4, 1]
    warn_counts = [2, 1, 3, 2, 0]
    x = np.arange(len(owasp_ids))

    ax0 = axes[0]
    w = 0.35
    ax0.bar(x - w / 2, error_counts, w, label="error", color=RED, edgecolor=BORDER)
    ax0.bar(x + w / 2, warn_counts, w, label="warning", color=YELLOW, edgecolor=BORDER)
    ax0.set_xticks(x)
    ax0.set_xticklabels(owasp_ids, color=TEXT, fontsize=9)
    ax0.set_title("SARIF Findings by Rule", color=ACCENT)
    ax0.set_ylabel("Finding Count", color=TEXT)
    ax0.legend(facecolor=SURFACE, edgecolor=BORDER, labelcolor=TEXT)
    ax0.tick_params(colors=TEXT)
    ax0.set_facecolor(SURFACE)
    ax0.grid(color=BORDER, linewidth=0.5, axis="y")
    for sp in ax0.spines.values():
        sp.set_edgecolor(BORDER)

    ax1 = axes[1]
    scores = [78, 82, 85, 88, 91, 87, 90, 93, 92, 95]
    versions = [f"v{i}" for i in range(1, 11)]
    ax1.plot(versions, scores, color=ACCENT, marker="o", linewidth=2, markersize=6)
    ax1.axhline(y=80, color=GREEN, linestyle="--", linewidth=1, label="Pass threshold (80)")
    ax1.fill_between(range(len(versions)), [80] * len(versions), scores,
                     where=[s >= 80 for s in scores], alpha=0.15, color=GREEN)
    ax1.fill_between(range(len(versions)), [80] * len(versions), scores,
                     where=[s < 80 for s in scores], alpha=0.15, color=RED)
    ax1.set_xticks(range(len(versions)))
    ax1.set_xticklabels(versions, color=TEXT, fontsize=8)
    ax1.set_ylim(60, 100)
    ax1.set_title("Safety Score Per PR (CI Gate)", color=ACCENT)
    ax1.set_ylabel("Safety Score", color=TEXT)
    ax1.legend(facecolor=SURFACE, edgecolor=BORDER, labelcolor=TEXT)
    ax1.tick_params(colors=TEXT)
    ax1.set_facecolor(SURFACE)
    ax1.grid(color=BORDER, linewidth=0.5)
    for sp in ax1.spines.values():
        sp.set_edgecolor(BORDER)

    fig.patch.set_facecolor(BG)
    plt.tight_layout()
    out = SCREENSHOTS_DIR / "v2_ci_sarif.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# PNG 3 — Replay regression suite
# ---------------------------------------------------------------------------

def gen_replay_regression():
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("V2: Attack Replay Regression Suite", color=ACCENT, fontsize=14, fontweight="bold")

    ax0 = axes[0]
    model_versions = ["gpt-4o-v1", "gpt-4o-v2", "gpt-4o-v3", "claude-3", "claude-3.5"]
    safety_scores = [72.4, 78.6, 82.0, 88.4, 92.0]
    bar_colors = [RED if s < 75 else (YELLOW if s < 80 else GREEN) for s in safety_scores]
    bars = ax0.barh(model_versions, safety_scores, color=bar_colors, edgecolor=BORDER)
    for bar, score in zip(bars, safety_scores):
        ax0.text(score + 0.5, bar.get_y() + bar.get_height() / 2,
                 f"{score:.1f}", va="center", color=TEXT, fontsize=9)
    ax0.axvline(x=80, color=GREEN, linestyle="--", linewidth=1.5, label="Target (80)")
    ax0.set_xlim(0, 105)
    ax0.set_title("Safety Score by Model Version", color=ACCENT)
    ax0.set_xlabel("Safety Score (/100)", color=TEXT)
    ax0.legend(facecolor=SURFACE, edgecolor=BORDER, labelcolor=TEXT)
    ax0.tick_params(colors=TEXT)
    ax0.set_facecolor(SURFACE)
    ax0.grid(color=BORDER, linewidth=0.5, axis="x")
    for sp in ax0.spines.values():
        sp.set_edgecolor(BORDER)

    ax1 = axes[1]
    comparisons = ["v1→v2", "v2→v3", "v3→v4", "v4→v5"]
    regressions = [3, 1, 0, 0]
    improvements = [5, 6, 4, 3]
    x = np.arange(len(comparisons))
    ax1.bar(x, regressions, 0.4, label="Regressions", color=RED, edgecolor=BORDER)
    ax1.bar(x, improvements, 0.4, bottom=regressions, label="Improvements", color=GREEN, edgecolor=BORDER)
    ax1.set_xticks(x)
    ax1.set_xticklabels(comparisons, color=TEXT)
    ax1.set_title("Regression vs Improvement per Version Diff", color=ACCENT)
    ax1.set_ylabel("Attack Count", color=TEXT)
    ax1.legend(facecolor=SURFACE, edgecolor=BORDER, labelcolor=TEXT)
    ax1.tick_params(colors=TEXT)
    ax1.set_facecolor(SURFACE)
    ax1.grid(color=BORDER, linewidth=0.5, axis="y")
    for sp in ax1.spines.values():
        sp.set_edgecolor(BORDER)

    fig.patch.set_facecolor(BG)
    plt.tight_layout()
    out = SCREENSHOTS_DIR / "v2_replay_regression.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# PNG 4 — OWASP compliance matrix with CWE mapping
# ---------------------------------------------------------------------------

def gen_owasp_matrix():
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("V2: Full OWASP LLM Top 10 v1.1 Compliance Matrix", color=ACCENT, fontsize=14, fontweight="bold")

    owasp_cats = ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
                  "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"]
    scores = [72, 95, 88, 90, 85, 68, 93, 91, 74, 96]
    statuses = ["FAIL", "PASS", "PASS", "PASS", "PASS", "WARN", "PASS", "PASS", "WARN", "PASS"]
    bar_colors = [GREEN if st == "PASS" else (YELLOW if st == "WARN" else RED) for st in statuses]

    ax0 = axes[0]
    y_pos = np.arange(len(owasp_cats))
    bars = ax0.barh(y_pos, scores, color=bar_colors, edgecolor=BORDER, height=0.6)
    for bar, score, status in zip(bars, scores, statuses):
        ax0.text(score + 0.5, bar.get_y() + bar.get_height() / 2,
                 f"{score} ({status})", va="center", color=TEXT, fontsize=8)
    ax0.set_yticks(y_pos)
    ax0.set_yticklabels(owasp_cats, color=TEXT, fontsize=9)
    ax0.axvline(x=80, color=GREEN, linestyle="--", linewidth=1, label="PASS threshold")
    ax0.axvline(x=50, color=RED, linestyle=":", linewidth=1, label="FAIL threshold")
    ax0.set_xlim(0, 115)
    ax0.set_title("Score per OWASP Category", color=ACCENT)
    ax0.set_xlabel("Score (/100)", color=TEXT)
    ax0.legend(facecolor=SURFACE, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)
    ax0.tick_params(colors=TEXT)
    ax0.set_facecolor(SURFACE)
    ax0.grid(color=BORDER, linewidth=0.5, axis="x")
    for sp in ax0.spines.values():
        sp.set_edgecolor(BORDER)

    # CWE heatmap-style bar
    ax1 = axes[1]
    cwes = ["CWE-77", "CWE-79", "CWE-200", "CWE-20", "CWE-359", "CWE-400", "CWE-89", "CWE-693"]
    cwe_findings = [8, 4, 12, 5, 9, 3, 2, 6]
    cwe_colors = [RED if f >= 9 else (YELLOW if f >= 5 else ACCENT) for f in cwe_findings]
    ax1.barh(cwes, cwe_findings, color=cwe_colors, edgecolor=BORDER, height=0.6)
    for i, (cwe, cnt) in enumerate(zip(cwes, cwe_findings)):
        ax1.text(cnt + 0.1, i, str(cnt), va="center", color=TEXT, fontsize=9)
    ax1.set_title("CWE Finding Frequency", color=ACCENT)
    ax1.set_xlabel("Finding Count", color=TEXT)
    ax1.tick_params(colors=TEXT)
    ax1.set_facecolor(SURFACE)
    ax1.grid(color=BORDER, linewidth=0.5, axis="x")
    for sp in ax1.spines.values():
        sp.set_edgecolor(BORDER)

    legend_patches = [
        mpatches.Patch(color=GREEN, label="PASS (≥80)"),
        mpatches.Patch(color=YELLOW, label="WARN (50–79)"),
        mpatches.Patch(color=RED, label="FAIL (<50)"),
    ]
    ax1.legend(handles=legend_patches, facecolor=SURFACE, edgecolor=BORDER, labelcolor=TEXT, fontsize=8)

    fig.patch.set_facecolor(BG)
    plt.tight_layout()
    out = SCREENSHOTS_DIR / "v2_owasp_matrix.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


if __name__ == "__main__":
    gen_attack_generator()
    gen_ci_sarif()
    gen_replay_regression()
    gen_owasp_matrix()
    print("All V2 screenshots generated.")
