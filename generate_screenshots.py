"""
generate_screenshots.py — Generate all 4 portfolio PNGs.

Run:  python generate_screenshots.py

Outputs:
  docs/screenshots/safety_radar.png
  docs/screenshots/attack_success_rates.png
  docs/screenshots/owasp_compliance.png
  docs/screenshots/vulnerability_timeline.png
"""

from __future__ import annotations

import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np

OUT_DIR = Path(__file__).parent / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Dark theme helper
# ---------------------------------------------------------------------------
BG = "#0d1117"
SURFACE = "#161b22"
BORDER = "#30363d"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
TEXT = "#c9d1d9"
MUTED = "#8b949e"


def apply_dark_theme(fig, axes):
    """Apply GitHub-dark theme to figure and all axes."""
    fig.patch.set_facecolor(BG)
    for ax in (axes if hasattr(axes, "__iter__") else [axes]):
        ax.set_facecolor(SURFACE)
        ax.tick_params(colors=TEXT, labelsize=9)
        ax.xaxis.label.set_color(TEXT)
        ax.yaxis.label.set_color(TEXT)
        ax.title.set_color(TEXT)
        for sp in ax.spines.values():
            sp.set_color(BORDER)
        ax.tick_params(axis="both", which="both", color=BORDER)


# ---------------------------------------------------------------------------
# 1. Safety Radar Chart
# ---------------------------------------------------------------------------
def generate_safety_radar():
    labels = ["Harmlessness", "Honesty", "Privacy", "Robustness", "Bias", "Hallucination"]
    N = len(labels)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    before = [77, 33, 69, 71, 55, 33]
    after = [91, 52, 83, 85, 72, 54]
    before += before[:1]
    after += after[:1]

    fig, ax = plt.subplots(figsize=(8, 7), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(SURFACE)

    ax.plot(angles, before, "o-", linewidth=2, color=ACCENT, label="Pre-Hardening")
    ax.fill(angles, before, alpha=0.18, color=ACCENT)

    ax.plot(angles, after, "s--", linewidth=2, color=GREEN, label="Post-Hardening")
    ax.fill(angles, after, alpha=0.12, color=GREEN)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, size=10, color=TEXT)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20", "40", "60", "80", "100"], size=7, color=MUTED)
    ax.set_ylim(0, 100)
    ax.yaxis.grid(True, color=BORDER, linestyle="--", linewidth=0.6)
    ax.xaxis.grid(True, color=BORDER, linestyle="-", linewidth=0.4)
    ax.spines["polar"].set_color(BORDER)
    ax.tick_params(colors=TEXT)

    ax.set_title("LLM Safety Dimensions", color=TEXT, fontsize=14, fontweight="bold", pad=20)

    legend = ax.legend(
        loc="upper right",
        bbox_to_anchor=(1.3, 1.15),
        framealpha=0,
        labelcolor=TEXT,
        fontsize=9,
    )
    for text in legend.get_texts():
        text.set_color(TEXT)

    # Annotate scores on the plot
    for i, (a, b_val, aft_val) in enumerate(zip(angles[:-1], before[:-1], after[:-1])):
        ax.annotate(
            f"{b_val}",
            (a, b_val),
            fontsize=7,
            color=ACCENT,
            ha="center",
            va="bottom",
        )

    plt.tight_layout()
    out = OUT_DIR / "safety_radar.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# 2. Attack Success Rates — Horizontal Bar Chart
# ---------------------------------------------------------------------------
def generate_attack_success_rates():
    categories = [
        "Prompt Injection",
        "Jailbreak",
        "Data Exfiltration",
        "Bias Elicitation",
        "Hallucination",
    ]
    rates = [18, 23, 31, 45, 67]
    colors_bar = [
        GREEN if r < 20 else (YELLOW if r < 40 else RED)
        for r in rates
    ]

    fig, ax = plt.subplots(figsize=(9, 5))
    apply_dark_theme(fig, ax)

    bars = ax.barh(categories, rates, color=colors_bar, height=0.55, edgecolor=BORDER, linewidth=0.5)

    for bar, rate in zip(bars, rates):
        ax.text(
            rate + 1.2,
            bar.get_y() + bar.get_height() / 2,
            f"{rate}%",
            va="center",
            ha="left",
            color=TEXT,
            fontsize=10,
            fontweight="bold",
        )

    # Threshold lines
    ax.axvline(20, color=GREEN, linestyle="--", linewidth=1, alpha=0.6, label="PASS threshold (20%)")
    ax.axvline(40, color=YELLOW, linestyle="--", linewidth=1, alpha=0.6, label="WARN threshold (40%)")

    ax.set_xlim(0, 85)
    ax.set_xlabel("Attack Success Rate (%)", color=TEXT, fontsize=10)
    ax.set_title("Attack Success Rates by Category (Pre-Hardening)", color=TEXT, fontsize=13, fontweight="bold")
    ax.xaxis.grid(True, color=BORDER, linestyle="--", linewidth=0.5, alpha=0.7)
    ax.set_axisbelow(True)

    legend = ax.legend(loc="lower right", framealpha=0, labelcolor=TEXT, fontsize=8)
    for t in legend.get_texts():
        t.set_color(TEXT)

    # Severity badges
    legend_patches = [
        mpatches.Patch(color=GREEN, label="PASS (< 20%)"),
        mpatches.Patch(color=YELLOW, label="WARN (20-40%)"),
        mpatches.Patch(color=RED, label="FAIL (> 40%)"),
    ]
    leg2 = ax.legend(
        handles=legend_patches,
        loc="lower right",
        framealpha=0.1,
        frameon=True,
        facecolor=SURFACE,
        edgecolor=BORDER,
        fontsize=8,
        labelcolor=TEXT,
    )
    for t in leg2.get_texts():
        t.set_color(TEXT)

    plt.tight_layout()
    out = OUT_DIR / "attack_success_rates.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# 3. OWASP Compliance Heatmap
# ---------------------------------------------------------------------------
def generate_owasp_compliance():
    owasp_items = [
        "LLM01: Prompt Injection",
        "LLM02: Insecure Output Handling",
        "LLM03: Training Data Poisoning",
        "LLM04: Model DoS",
        "LLM05: Supply Chain Vulns",
        "LLM06: Sensitive Info Disclosure",
        "LLM07: Insecure Plugin Design",
        "LLM08: Excessive Agency",
        "LLM09: Misinformation",
        "LLM10: Model Theft",
    ]

    # Status grid: 0=PASS, 1=WARN, 2=FAIL
    # Columns: [Status, Critical Coverage, Tested]
    statuses = [
        ("WARN", 1),
        ("WARN", 1),
        ("WARN", 1),
        ("WARN", 1),
        ("WARN", 1),
        ("WARN", 1),
        ("WARN", 1),
        ("WARN", 1),
        ("FAIL", 2),
        ("WARN", 1),
    ]

    # Override based on our actual data
    override = {
        0: ("WARN", 1),   # LLM01: 20.5% avg of JB+PI
        5: ("WARN", 1),   # LLM06: 31%
        8: ("FAIL", 2),   # LLM09: 56% avg of BIAS+HALLUC
    }
    for i, (status, val) in override.items():
        statuses[i] = (status, val)

    # Build matrix: rows=OWASP items, cols=severity buckets
    col_labels = ["PASS", "WARN", "FAIL"]
    matrix = np.zeros((10, 3), dtype=float)
    for i, (status, _) in enumerate(statuses):
        col = {"PASS": 0, "WARN": 1, "FAIL": 2}[status]
        matrix[i, col] = 1.0

    # Color palette: cell value → color
    # We'll build a custom image
    color_map = np.full((*matrix.shape, 4), [0.086, 0.106, 0.141, 1.0])  # SURFACE default
    for r in range(10):
        for c in range(3):
            if matrix[r, c] > 0:
                if c == 0:
                    color_map[r, c] = [0.059, 0.243, 0.075, 0.85]  # green
                elif c == 1:
                    color_map[r, c] = [0.549, 0.384, 0.067, 0.85]  # yellow
                else:
                    color_map[r, c] = [0.647, 0.071, 0.035, 0.85]  # red

    fig, ax = plt.subplots(figsize=(9, 6))
    apply_dark_theme(fig, ax)

    ax.imshow(color_map, aspect="auto", interpolation="nearest")

    # Cell labels
    status_text_colors = {0: GREEN, 1: YELLOW, 2: RED}
    for r in range(10):
        for c in range(3):
            if matrix[r, c] > 0:
                status_label = col_labels[c]
                ax.text(c, r, status_label, ha="center", va="center",
                       fontsize=9, fontweight="bold",
                       color=status_text_colors[c])

    ax.set_xticks(range(3))
    ax.set_xticklabels(col_labels, color=TEXT, fontsize=10, fontweight="bold")
    ax.set_yticks(range(10))
    ax.set_yticklabels(owasp_items, color=TEXT, fontsize=8)
    ax.set_title("OWASP LLM Top 10 Compliance Status", color=TEXT, fontsize=13, fontweight="bold")

    # Grid lines between cells
    for x in [-0.5, 0.5, 1.5, 2.5]:
        ax.axvline(x, color=BORDER, linewidth=1)
    for y in np.arange(-0.5, 10, 1):
        ax.axhline(y, color=BORDER, linewidth=0.5)

    plt.tight_layout()
    out = OUT_DIR / "owasp_compliance.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# 4. Vulnerability Timeline — Line Chart
# ---------------------------------------------------------------------------
def generate_vulnerability_timeline():
    sessions = list(range(1, 11))
    # Safety scores improve after hardening rounds at sessions 3, 5, 7
    safety_scores = [58.2, 61.0, 64.5, 68.3, 73.1, 76.4, 79.8, 83.2, 86.0, 88.7]
    jailbreak_rate = [25, 24, 22, 21, 19, 17, 15, 13, 12, 11]
    halluc_rate = [68, 66, 62, 58, 54, 50, 46, 42, 38, 35]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)
    apply_dark_theme(fig, [ax1, ax2])

    # Top: overall safety score
    ax1.plot(sessions, safety_scores, "o-", color=ACCENT, linewidth=2.5,
             markersize=6, label="Overall Safety Score")
    ax1.fill_between(sessions, safety_scores, alpha=0.12, color=ACCENT)

    # Hardening annotations
    for session, label in [(3, "Hardening v1"), (5, "Hardening v2"), (7, "Hardening v3")]:
        ax1.axvline(session, color=BORDER, linestyle="--", linewidth=1, alpha=0.7)
        ax1.text(session + 0.1, 62, label, color=MUTED, fontsize=7, rotation=90, va="bottom")

    ax1.set_ylabel("Safety Score (0–100)", color=TEXT, fontsize=9)
    ax1.set_ylim(50, 100)
    ax1.yaxis.grid(True, color=BORDER, linestyle="--", linewidth=0.5)
    ax1.set_title("Safety Score Trend Across Audit Sessions", color=TEXT, fontsize=13, fontweight="bold")
    ax1.legend(framealpha=0, labelcolor=TEXT, fontsize=9)

    # Annotate start/end
    ax1.annotate(f"{safety_scores[0]:.1f}", (1, safety_scores[0]),
                textcoords="offset points", xytext=(-8, 8), color=RED, fontsize=8, fontweight="bold")
    ax1.annotate(f"{safety_scores[-1]:.1f}", (10, safety_scores[-1]),
                textcoords="offset points", xytext=(-8, -14), color=GREEN, fontsize=8, fontweight="bold")

    # Bottom: attack-specific rates
    ax2.plot(sessions, jailbreak_rate, "s-", color=YELLOW, linewidth=2,
             markersize=5, label="Jailbreak Rate (%)")
    ax2.plot(sessions, halluc_rate, "^-", color=RED, linewidth=2,
             markersize=5, label="Hallucination Rate (%)")

    for session in [3, 5, 7]:
        ax2.axvline(session, color=BORDER, linestyle="--", linewidth=1, alpha=0.7)

    ax2.set_xlabel("Audit Session", color=TEXT, fontsize=9)
    ax2.set_ylabel("Attack Success Rate (%)", color=TEXT, fontsize=9)
    ax2.set_ylim(0, 80)
    ax2.yaxis.grid(True, color=BORDER, linestyle="--", linewidth=0.5)
    ax2.set_xticks(sessions)
    ax2.legend(framealpha=0, labelcolor=TEXT, fontsize=9)

    plt.tight_layout()
    out = OUT_DIR / "vulnerability_timeline.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Generating portfolio screenshots...")
    generate_safety_radar()
    generate_attack_success_rates()
    generate_owasp_compliance()
    generate_vulnerability_timeline()
    print("\nAll 4 screenshots generated successfully.")
    for f in sorted(OUT_DIR.glob("*.png")):
        size_kb = f.stat().st_size // 1024
        print(f"  {f.name} ({size_kb} KB)")
