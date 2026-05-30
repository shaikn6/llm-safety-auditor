"""
dashboard/app.py — Streamlit interactive red-teaming dashboard.

Run:  streamlit run dashboard/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow imports from project root when running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from auditor.attack_library import (
    ALL_ATTACKS,
    AttackCategory,
    Severity,
    get_category_stats,
)
from auditor.detector import SafetyDetector
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM, CATEGORY_FAILURE_RATES

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="LLM Safety Auditor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark security theme
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    :root {
        --color-bg: #0d1117;
        --color-surface: #161b22;
        --color-border: #30363d;
        --color-accent: #58a6ff;
        --color-text: #c9d1d9;
        --color-danger: #f85149;
        --color-warn: #d29922;
        --color-success: #3fb950;
    }
    .stApp { background-color: var(--color-bg); color: var(--color-text); }
    section[data-testid="stSidebar"] { background-color: var(--color-surface); }
    .metric-card {
        background: var(--color-surface);
        border: 1px solid var(--color-border);
        border-radius: 8px;
        padding: 1.2rem 1.5rem;
        text-align: center;
    }
    .metric-value { font-size: 2rem; font-weight: 700; color: var(--color-accent); }
    .metric-label { font-size: 0.85rem; color: var(--color-text); margin-top: 0.3rem; }
    .status-pass  { color: var(--color-success); font-weight: 700; }
    .status-warn  { color: var(--color-warn); font-weight: 700; }
    .status-fail  { color: var(--color-danger); font-weight: 700; }
    .section-header {
        border-bottom: 2px solid var(--color-accent);
        padding-bottom: 0.4rem;
        margin-bottom: 1rem;
        font-size: 1.1rem;
        font-weight: 700;
        color: var(--color-accent);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/shaikn6/llm-safety-auditor/main/frontend/shield.svg",
        use_container_width=True,
        caption=None,
    ) if False else st.markdown("## 🔒 LLM Safety Auditor")

    st.markdown("---")
    st.markdown("### Audit Configuration")

    all_categories = [c.value for c in AttackCategory]
    selected_categories = st.multiselect(
        "Attack Categories",
        options=all_categories,
        default=all_categories,
    )

    all_severities = [s.value for s in Severity]
    selected_severities = st.multiselect(
        "Severity Levels",
        options=all_severities,
        default=all_severities,
    )

    attack_limit = st.slider("Max Attacks", min_value=5, max_value=50, value=50, step=5)
    llm_seed = st.number_input("LLM Seed (reproducibility)", value=42, step=1)
    use_semantic = st.checkbox("Enable Semantic Detector", value=False,
                               help="Requires sentence-transformers installed")

    st.markdown("---")
    run_button = st.button("▶ Run Red-Team Audit", use_container_width=True, type="primary")
    st.markdown("---")
    st.markdown("**Detect Custom Text**")
    custom_text = st.text_area("Paste LLM response to analyze", height=100)
    detect_button = st.button("🔍 Analyze Response", use_container_width=True)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "report" not in st.session_state:
    st.session_state.report = None

if "detection_result" not in st.session_state:
    st.session_state.detection_result = None

# ---------------------------------------------------------------------------
# Run audit
# ---------------------------------------------------------------------------
if run_button:
    with st.spinner("Running adversarial audit..."):
        categories = [AttackCategory(c) for c in selected_categories] if selected_categories else None
        severities = [Severity(s) for s in selected_severities] if selected_severities else None

        llm = MockLLM(global_seed=int(llm_seed))
        detector = SafetyDetector(use_semantic=use_semantic)
        evaluator = SafetyEvaluator(
            llm=llm,
            detector=detector,
            session_id=f"ui-session-seed{llm_seed}",
        )
        report = evaluator.run(categories=categories, severities=severities, limit=attack_limit)
        st.session_state.report = report
    st.success(f"Audit complete — {report.total_attacks} attacks in {report.elapsed_total_ms:,}ms")

# ---------------------------------------------------------------------------
# Run detector
# ---------------------------------------------------------------------------
if detect_button and custom_text.strip():
    with st.spinner("Analyzing..."):
        detector = SafetyDetector(use_semantic=use_semantic)
        st.session_state.detection_result = detector.analyze(custom_text)

# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------
report = st.session_state.report

if report is None:
    st.markdown("## LLM Safety Auditor")
    st.markdown(
        "**Select attack categories and click ▶ Run Red-Team Audit** in the sidebar to begin."
    )

    # Static preview from attack library
    st.markdown("---")
    st.markdown("### Attack Library Preview")
    preview_data = [
        {
            "ID": a.id,
            "Category": a.category.value,
            "Severity": a.severity.value,
            "OWASP": a.owasp_ref.split(":")[0],
            "Expected Behavior": a.expected_behavior,
        }
        for a in ALL_ATTACKS[:15]
    ]
    st.dataframe(pd.DataFrame(preview_data), use_container_width=True, height=400)

    # Category stats
    stats = get_category_stats()
    col1, col2, col3, col4, col5 = st.columns(5)
    for col, (cat, count) in zip([col1, col2, col3, col4, col5], stats.items()):
        col.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value">{count}</div>'
            f'<div class="metric-label">{cat.replace("_", " ").title()}</div>'
            f"</div>",
            unsafe_allow_html=True,
        )

else:
    # -----------------------------------------------------------------------
    # Header metrics
    # -----------------------------------------------------------------------
    score = report.overall_safety_score
    score_color = "#3fb950" if score >= 80 else ("#d29922" if score >= 60 else "#f85149")

    st.markdown(f"## Session: `{report.session_id}`")
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="color:{score_color}">{score:.1f}</div>'
            f'<div class="metric-label">Safety Score / 100</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value">{report.total_attacks}</div>'
            f'<div class="metric-label">Attacks Run</div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="color:#f85149">{report.unsafe_responses}</div>'
            f'<div class="metric-label">Bypassed Safety</div></div>',
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value">{report.refusal_rate:.0%}</div>'
            f'<div class="metric-label">Refusal Rate</div></div>',
            unsafe_allow_html=True,
        )
    with col5:
        owasp_pass = sum(1 for o in report.owasp_compliance if o.status == "PASS")
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value">{owasp_pass}/10</div>'
            f'<div class="metric-label">OWASP Controls Passed</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # Row 2: Radar + Bar chart side by side
    # -----------------------------------------------------------------------
    col_radar, col_bar = st.columns(2)

    with col_radar:
        st.markdown('<div class="section-header">Safety Dimensions Radar</div>', unsafe_allow_html=True)
        dims = report.safety_dimensions
        categories_list = list(dims.keys())
        values = list(dims.values())

        # Simulated "after hardening" values (+15% each, capped at 100)
        hardened_values = [min(v + 15, 100) for v in values]

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=values + [values[0]],
            theta=categories_list + [categories_list[0]],
            fill="toself",
            name="Current",
            line_color="#58a6ff",
            fillcolor="rgba(88,166,255,0.2)",
        ))
        fig_radar.add_trace(go.Scatterpolar(
            r=hardened_values + [hardened_values[0]],
            theta=categories_list + [categories_list[0]],
            fill="toself",
            name="After Hardening",
            line_color="#3fb950",
            fillcolor="rgba(63,185,80,0.1)",
            line_dash="dash",
        ))
        fig_radar.update_layout(
            polar=dict(
                bgcolor="#161b22",
                radialaxis=dict(visible=True, range=[0, 100], color="#8b949e", gridcolor="#30363d"),
                angularaxis=dict(color="#c9d1d9", gridcolor="#30363d"),
            ),
            paper_bgcolor="#0d1117",
            plot_bgcolor="#0d1117",
            font_color="#c9d1d9",
            legend=dict(bgcolor="#161b22", bordercolor="#30363d", borderwidth=1),
            margin=dict(l=40, r=40, t=20, b=20),
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    with col_bar:
        st.markdown('<div class="section-header">Attack Success Rates by Category</div>', unsafe_allow_html=True)
        cat_data = [
            {"Category": s.category.value.replace("_", " ").title(),
             "Success Rate (%)": s.attack_success_rate * 100,
             "Attacks": s.total_attacks}
            for s in report.category_summaries
        ]
        df_cat = pd.DataFrame(cat_data).sort_values("Success Rate (%)", ascending=True)

        colors_bar = [
            "#f85149" if r >= 40 else ("#d29922" if r >= 20 else "#3fb950")
            for r in df_cat["Success Rate (%)"]
        ]
        fig_bar = go.Figure(go.Bar(
            x=df_cat["Success Rate (%)"],
            y=df_cat["Category"],
            orientation="h",
            marker_color=colors_bar,
            text=[f"{r:.0f}%" for r in df_cat["Success Rate (%)"]],
            textposition="outside",
        ))
        fig_bar.update_layout(
            paper_bgcolor="#0d1117",
            plot_bgcolor="#161b22",
            font_color="#c9d1d9",
            xaxis=dict(color="#8b949e", gridcolor="#30363d", range=[0, 100]),
            yaxis=dict(color="#c9d1d9"),
            margin=dict(l=10, r=60, t=10, b=40),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # -----------------------------------------------------------------------
    # Row 3: OWASP compliance grid
    # -----------------------------------------------------------------------
    st.markdown('<div class="section-header">OWASP LLM Top 10 Compliance</div>', unsafe_allow_html=True)
    owasp_rows = []
    for o in report.owasp_compliance:
        status_class = {
            "PASS": "status-pass", "WARN": "status-warn", "FAIL": "status-fail"
        }.get(o.status, "")
        owasp_rows.append({
            "ID": o.owasp_id,
            "Vulnerability": o.title,
            "Status": o.status,
            "Attack Success Rate": f"{o.attack_success_rate:.0%}" if o.attack_success_rate > 0 else "N/A",
            "Notes": o.notes,
        })

    df_owasp = pd.DataFrame(owasp_rows)
    st.dataframe(
        df_owasp.style.apply(
            lambda col: [
                "color: #3fb950; font-weight: bold" if v == "PASS"
                else "color: #d29922; font-weight: bold" if v == "WARN"
                else "color: #f85149; font-weight: bold" if v == "FAIL"
                else ""
                for v in col
            ] if col.name == "Status" else [""] * len(col),
            axis=0,
        ),
        use_container_width=True,
        height=350,
    )

    # -----------------------------------------------------------------------
    # Row 4: Individual attack results table
    # -----------------------------------------------------------------------
    st.markdown('<div class="section-header">Attack Results Detail</div>', unsafe_allow_html=True)
    result_rows = [
        {
            "ID": r.attack.id,
            "Category": r.attack.category.value,
            "Severity": r.attack.severity.value,
            "Safe?": "✓" if not r.is_successful_attack else "✗ BYPASSED",
            "Safety Score": f"{r.safety_score:.2f}",
            "Refusal": "Yes" if r.detection.refusal_detected else "No",
            "Rules Triggered": len(r.detection.triggered_rules),
        }
        for r in report.attack_results
    ]
    df_results = pd.DataFrame(result_rows)
    st.dataframe(df_results, use_container_width=True, height=350)

    # -----------------------------------------------------------------------
    # Row 5: Recommendations
    # -----------------------------------------------------------------------
    st.markdown('<div class="section-header">Security Recommendations</div>', unsafe_allow_html=True)
    for rec in report.recommendations:
        if "[CRITICAL]" in rec:
            st.error(rec)
        elif "[HIGH]" in rec:
            st.warning(rec)
        elif "[MEDIUM]" in rec:
            st.info(rec)
        else:
            st.markdown(f"- {rec}")

# ---------------------------------------------------------------------------
# Detection result panel (bottom of page, always visible if result present)
# ---------------------------------------------------------------------------
det = st.session_state.detection_result
if det is not None:
    st.markdown("---")
    st.markdown('<div class="section-header">Custom Detection Result</div>', unsafe_allow_html=True)
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if det.is_safe:
            st.success(f"SAFE — Confidence: {det.confidence:.0%}")
        else:
            st.error(f"UNSAFE — Confidence: {det.confidence:.0%}")
    with col_b:
        st.metric("Refusal Detected", "Yes" if det.refusal_detected else "No")
    with col_c:
        st.metric("Rules Triggered", len(det.triggered_rules))

    if det.triggered_rules:
        st.markdown("**Triggered Rules:**")
        for rule in det.triggered_rules:
            st.code(rule, language=None)

    st.markdown(f"**Layers Checked:** {', '.join(det.layers_checked)}")
    if det.category:
        st.markdown(f"**Violation Category:** `{det.category}`")
