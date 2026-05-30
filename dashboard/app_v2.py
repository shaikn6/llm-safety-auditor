"""
dashboard/app_v2.py — V2 Streamlit dashboard with 4 tabs.

  Tab 1: Full Audit       (V1 functionality)
  Tab 2: Attack Generator + live testing (mutation engine)
  Tab 3: Replay Regression Suite
  Tab 4: OWASP Compliance Matrix (v1.1 with CWE mapping)

Run: streamlit run dashboard/app_v2.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from attacks.attack_generator import (
    AttackTemplateLibrary,
    Difficulty,
    MutationEngine,
    MutationStrategy,
    detect_success,
)
from auditor.attack_library import ALL_ATTACKS, AttackCategory, Severity, get_category_stats
from auditor.detector import SafetyDetector
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM, CATEGORY_FAILURE_RATES
from ci.github_actions_generator import (
    WorkflowConfig,
    build_sarif_from_report,
    generate_badge_markdown,
    generate_github_actions_workflow,
)
from replay.attack_replay import ReplayStore
from scoring.owasp_scorer import OWASPScorer

# ---------------------------------------------------------------------------
# Page config + CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="LLM Safety Auditor V2",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
        --color-purple: #bc8cff;
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
    .tag-easy   { background: #1f4e3d; color: #3fb950; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }
    .tag-medium { background: #4e3a1f; color: #d29922; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }
    .tag-hard   { background: #4e1f1f; color: #f85149; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🔒 LLM Safety Auditor V2")
    st.markdown("---")
    st.markdown("**Global Settings**")
    llm_seed = st.number_input("LLM Seed", value=42, step=1)
    use_semantic = st.checkbox("Semantic Detector", value=False,
                               help="Requires sentence-transformers")
    st.markdown("---")
    st.markdown("*V2: mutation engine, CI/CD generator, replay regression, OWASP v1.1*")


# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
_DEFAULTS = {
    "v2_report": None,
    "generated_attacks": None,
    "replay_store_path": None,
    "owasp_matrix": None,
    "gen_test_results": None,
}
for k, v in _DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ---------------------------------------------------------------------------
# Tab layout
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Full Audit",
    "⚡ Attack Generator",
    "🔁 Replay Regression",
    "🛡️ OWASP Matrix",
])


# ===========================================================================
# TAB 1 — Full Audit (V1 functionality preserved)
# ===========================================================================
with tab1:
    st.markdown("### Full Red-Team Audit")

    col_cfg, col_run = st.columns([3, 1])
    with col_cfg:
        all_categories = [c.value for c in AttackCategory]
        sel_cats = st.multiselect(
            "Attack Categories", options=all_categories, default=all_categories, key="t1_cats"
        )
        all_severities = [s.value for s in Severity]
        sel_sevs = st.multiselect(
            "Severity Levels", options=all_severities, default=all_severities, key="t1_sevs"
        )
        attack_limit = st.slider("Max Attacks", 5, 50, 50, 5, key="t1_limit")
    with col_run:
        st.markdown("<br><br>", unsafe_allow_html=True)
        run_btn = st.button("▶ Run Audit", type="primary", use_container_width=True, key="t1_run")

    if run_btn:
        with st.spinner("Running adversarial audit..."):
            cats = [AttackCategory(c) for c in sel_cats] if sel_cats else None
            sevs = [Severity(s) for s in sel_sevs] if sel_sevs else None
            llm = MockLLM(global_seed=int(llm_seed))
            det = SafetyDetector(use_semantic=use_semantic)
            ev = SafetyEvaluator(llm=llm, detector=det, session_id=f"v2-audit-seed{llm_seed}")
            report = ev.run(categories=cats, severities=sevs, limit=attack_limit)
            st.session_state.v2_report = report

            # Also compute OWASP matrix
            scorer = OWASPScorer()
            st.session_state.owasp_matrix = scorer.score(report)

        st.success(f"Audit complete — {report.total_attacks} attacks in {report.elapsed_total_ms:,}ms")

    report = st.session_state.v2_report
    if report:
        score = report.overall_safety_score
        score_color = "#3fb950" if score >= 80 else ("#d29922" if score >= 60 else "#f85149")

        st.markdown(f"#### Session: `{report.session_id}`")
        c1, c2, c3, c4, c5 = st.columns(5)
        metrics = [
            (f"{score:.1f}", "Safety Score / 100", score_color),
            (str(report.total_attacks), "Attacks Run", None),
            (str(report.unsafe_responses), "Bypassed Safety", "#f85149"),
            (f"{report.refusal_rate:.0%}", "Refusal Rate", None),
            (f"{report.owasp_pass_count}/10", "OWASP Passed", None),
        ]
        for col, (val, label, color) in zip([c1, c2, c3, c4, c5], metrics):
            color_str = f' style="color:{color}"' if color else ""
            col.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value"{color_str}>{val}</div>'
                f'<div class="metric-label">{label}</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)

        col_r, col_b = st.columns(2)
        with col_r:
            st.markdown('<div class="section-header">Safety Dimensions Radar</div>', unsafe_allow_html=True)
            dims = report.safety_dimensions
            cats_list = list(dims.keys())
            vals = list(dims.values())
            hardened = [min(v + 15, 100) for v in vals]
            fig_radar = go.Figure()
            for trace_vals, name, color, fill in [
                (vals, "Current", "#58a6ff", "rgba(88,166,255,0.2)"),
                (hardened, "After Hardening", "#3fb950", "rgba(63,185,80,0.1)"),
            ]:
                fig_radar.add_trace(go.Scatterpolar(
                    r=trace_vals + [trace_vals[0]],
                    theta=cats_list + [cats_list[0]],
                    fill="toself", name=name,
                    line_color=color, fillcolor=fill,
                    line_dash="solid" if name == "Current" else "dash",
                ))
            fig_radar.update_layout(
                polar=dict(
                    bgcolor="#161b22",
                    radialaxis=dict(visible=True, range=[0, 100], color="#8b949e", gridcolor="#30363d"),
                    angularaxis=dict(color="#c9d1d9", gridcolor="#30363d"),
                ),
                paper_bgcolor="#0d1117", font_color="#c9d1d9",
                legend=dict(bgcolor="#161b22"), margin=dict(l=40, r=40, t=20, b=20),
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        with col_b:
            st.markdown('<div class="section-header">Attack Success by Category</div>', unsafe_allow_html=True)
            cat_data = [
                {"Category": s.category.value.replace("_", " ").title(),
                 "Rate (%)": s.attack_success_rate * 100}
                for s in report.category_summaries
            ]
            df_cat = pd.DataFrame(cat_data).sort_values("Rate (%)", ascending=True)
            colors_bar = ["#f85149" if r >= 40 else ("#d29922" if r >= 20 else "#3fb950")
                          for r in df_cat["Rate (%)"]]
            fig_bar = go.Figure(go.Bar(
                x=df_cat["Rate (%)"], y=df_cat["Category"], orientation="h",
                marker_color=colors_bar,
                text=[f"{r:.0f}%" for r in df_cat["Rate (%)"]],
                textposition="outside",
            ))
            fig_bar.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#161b22", font_color="#c9d1d9",
                xaxis=dict(range=[0, 100], gridcolor="#30363d"),
                yaxis=dict(color="#c9d1d9"),
                margin=dict(l=10, r=60, t=10, b=40),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown('<div class="section-header">Attack Results Detail</div>', unsafe_allow_html=True)
        rows = [
            {
                "ID": r.attack.id, "Category": r.attack.category.value,
                "Severity": r.attack.severity.value,
                "Safe?": "Safe" if not r.is_successful_attack else "BYPASSED",
                "Score": f"{r.safety_score:.2f}",
                "Refusal": "Yes" if r.detection.refusal_detected else "No",
            }
            for r in report.attack_results
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=350)

        # Recommendations
        st.markdown('<div class="section-header">Recommendations</div>', unsafe_allow_html=True)
        for rec in report.recommendations:
            if "[CRITICAL]" in rec:
                st.error(rec)
            elif "[HIGH]" in rec:
                st.warning(rec)
            elif "[MEDIUM]" in rec:
                st.info(rec)
            else:
                st.markdown(f"- {rec}")

        # Badge + CI download
        st.markdown("---")
        st.markdown("**CI/CD Artifacts**")
        badge = generate_badge_markdown(score)
        st.code(badge, language=None)
        workflow_yaml = generate_github_actions_workflow()
        st.download_button(
            "Download GitHub Actions Workflow",
            data=workflow_yaml,
            file_name="safety-audit.yml",
            mime="text/yaml",
        )
    else:
        st.info("Configure and click **Run Audit** to begin.")


# ===========================================================================
# TAB 2 — Attack Generator + Live Testing
# ===========================================================================
with tab2:
    st.markdown("### Automated Attack Generator")
    st.markdown(
        "Mutation engine generates 100 attack variants from 10 seed templates "
        "(5 strategies × 2 seeds per category = 10 variants each)."
    )

    col_gen, col_filt = st.columns([2, 1])
    with col_filt:
        sel_strategy = st.selectbox(
            "Filter by Strategy",
            ["All"] + [s.value for s in MutationStrategy],
            key="gen_strategy",
        )
        sel_difficulty = st.selectbox(
            "Filter by Difficulty",
            ["All"] + [d.value for d in Difficulty],
            key="gen_diff",
        )
        gen_seed = st.number_input("Mutation Seed", value=0, step=1, key="gen_seed")

    with col_gen:
        gen_btn = st.button("Generate 100 Attack Variants", type="primary", key="gen_btn")

    if gen_btn:
        with st.spinner("Generating mutations..."):
            engine = MutationEngine(variants_per_seed=10, seed=int(gen_seed))
            lib = AttackTemplateLibrary(engine=engine)
            st.session_state.generated_attacks = lib.generated_attacks

    attacks = st.session_state.generated_attacks
    if attacks:
        # Filters
        filtered = attacks
        if sel_strategy != "All":
            filtered = [a for a in filtered if a.strategy.value == sel_strategy]
        if sel_difficulty != "All":
            filtered = [a for a in filtered if a.difficulty.value == sel_difficulty]

        # Stats cards
        library = AttackTemplateLibrary(engine=MutationEngine(variants_per_seed=10, seed=int(gen_seed)))
        stats = library.stats()
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Generated", stats["total"])
        c2.metric("Easy", stats["by_difficulty"]["easy"])
        c3.metric("Hard", stats["by_difficulty"]["hard"])

        st.markdown(f"**Showing {len(filtered)} variants** (filtered from {len(attacks)} total)")

        gen_rows = [
            {
                "ID": a.id,
                "Seed": a.seed_id,
                "Category": a.category.value,
                "Strategy": a.strategy.value,
                "Difficulty": a.difficulty.value,
                "Layers": a.obfuscation_layers,
                "Severity": a.severity.value,
                "Template (truncated)": a.template[:100] + "..." if len(a.template) > 100 else a.template,
            }
            for a in filtered
        ]
        st.dataframe(pd.DataFrame(gen_rows), use_container_width=True, height=350)

        # Live test a selected attack
        st.markdown("---")
        st.markdown("#### Live Test Generated Attack")
        attack_ids = [a.id for a in filtered]
        if attack_ids:
            sel_attack_id = st.selectbox("Select attack to test", attack_ids, key="live_attack")
            test_btn = st.button("Test Against Mock LLM", key="live_test_btn")

            if test_btn and sel_attack_id:
                sel_attack = next(a for a in filtered if a.id == sel_attack_id)
                llm = MockLLM(global_seed=int(llm_seed))
                prompt_obj = sel_attack.to_attack_prompt()
                response = llm.complete(prompt_obj)
                succeeded = detect_success(response.response_text)

                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Attack Template:**")
                    st.text_area("Template", value=sel_attack.template, height=120, disabled=True)
                    st.markdown(f"**Strategy:** `{sel_attack.strategy.value}`  "
                                f"**Difficulty:** `{sel_attack.difficulty.value}`")
                with col_b:
                    st.markdown("**Mock LLM Response:**")
                    st.text_area("Response", value=response.response_text, height=120, disabled=True)
                    if succeeded:
                        st.error("Attack SUCCEEDED — prohibited content detected")
                    else:
                        st.success("Attack BLOCKED — response appears safe")


# ===========================================================================
# TAB 3 — Replay Regression Suite
# ===========================================================================
with tab3:
    st.markdown("### Replay Regression Suite")
    st.markdown(
        "Store audit results per model version and compare across versions "
        "to detect safety regressions or improvements."
    )

    # Temp DB for demo; in production point to a persistent path
    if st.session_state.replay_store_path is None:
        tmp = tempfile.mkdtemp()
        st.session_state.replay_store_path = str(Path(tmp) / "replay_store.db")

    store = ReplayStore(db_path=st.session_state.replay_store_path)

    col_v1, col_v2 = st.columns(2)
    with col_v1:
        v1_name = st.text_input("Model V1 name", value="gpt-4o-v1", key="v1_name")
        v1_seed = st.number_input("V1 seed", value=42, step=1, key="v1_seed")
        v1_btn = st.button("Run & Store V1 Audit", key="v1_btn")
        if v1_btn:
            with st.spinner(f"Running audit for {v1_name}..."):
                llm = MockLLM(global_seed=int(v1_seed))
                det = SafetyDetector(use_semantic=use_semantic)
                report = store.run_regression(
                    model_version=v1_name, llm=llm, detector=det,
                    run_id=f"regression-{v1_name}", notes="V1 baseline"
                )
            st.success(f"Stored {v1_name}: safety score {report.overall_safety_score:.1f}")

    with col_v2:
        v2_name = st.text_input("Model V2 name", value="gpt-4o-v2", key="v2_name")
        v2_seed = st.number_input("V2 seed", value=99, step=1, key="v2_seed")
        v2_btn = st.button("Run & Store V2 Audit", key="v2_btn")
        if v2_btn:
            with st.spinner(f"Running audit for {v2_name}..."):
                llm = MockLLM(global_seed=int(v2_seed))
                det = SafetyDetector(use_semantic=use_semantic)
                report = store.run_regression(
                    model_version=v2_name, llm=llm, detector=det,
                    run_id=f"regression-{v2_name}", notes="V2 candidate"
                )
            st.success(f"Stored {v2_name}: safety score {report.overall_safety_score:.1f}")

    # Diff report
    st.markdown("---")
    st.markdown("#### Compare Versions")
    diff_v1 = st.text_input("Diff base version", value="gpt-4o-v1", key="diff_v1")
    diff_v2 = st.text_input("Diff comparison version", value="gpt-4o-v2", key="diff_v2")
    diff_btn = st.button("Generate Diff Report", key="diff_btn")

    if diff_btn:
        with st.spinner("Comparing..."):
            diff = store.diff_report(diff_v1, diff_v2)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Regressions", len(diff.regressions), delta=None)
        c2.metric("Improvements", len(diff.improvements), delta=None)
        c3.metric("Unchanged Safe", diff.unchanged_safe)
        c4.metric("Net Change", f"{diff.net_change:+d}")

        if diff.v1_safety_score and diff.v2_safety_score:
            delta = diff.v2_safety_score - diff.v1_safety_score
            st.metric(
                f"Safety Score: {diff_v1} → {diff_v2}",
                f"{diff.v2_safety_score:.1f}",
                delta=f"{delta:+.1f}",
            )

        if diff.regressions:
            st.markdown("**Regressions (attacks that now bypass safety):**")
            reg_rows = [
                {
                    "Attack ID": r.attack_id,
                    "Category": r.category,
                    "Severity": r.severity,
                    "Template": r.template[:80] + "...",
                }
                for r in diff.regressions
            ]
            st.dataframe(pd.DataFrame(reg_rows), use_container_width=True)
        else:
            st.success("No regressions detected.")

        if diff.improvements:
            st.markdown("**Improvements (attacks now blocked that previously bypassed):**")
            imp_rows = [
                {"Attack ID": r.attack_id, "Category": r.category, "Severity": r.severity}
                for r in diff.improvements
            ]
            st.dataframe(pd.DataFrame(imp_rows), use_container_width=True)

    # Timeline
    st.markdown("---")
    st.markdown("#### Safety Score Timeline")
    timeline = store.safety_timeline()
    if timeline:
        df_tl = pd.DataFrame([
            {
                "Run": f"{p.model_version}\n{p.created_at[:10]}",
                "Safety Score": p.safety_score,
                "Model": p.model_version,
            }
            for p in timeline
        ])
        fig_tl = px.line(
            df_tl, x="Run", y="Safety Score", markers=True, color="Model",
            title="Safety Score Over Model Versions",
            color_discrete_sequence=["#58a6ff", "#3fb950", "#f85149", "#d29922"],
        )
        fig_tl.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
            font_color="#c9d1d9",
            yaxis=dict(range=[0, 100], gridcolor="#30363d"),
            xaxis=dict(gridcolor="#30363d"),
        )
        st.plotly_chart(fig_tl, use_container_width=True)
    else:
        st.info("Run audits for at least one model version to see the timeline.")

    store.close()


# ===========================================================================
# TAB 4 — OWASP Compliance Matrix
# ===========================================================================
with tab4:
    st.markdown("### OWASP LLM Top 10 v1.1 Compliance Matrix")
    st.markdown(
        "Full weighted scoring with CWE mapping and concrete remediation guidance. "
        "Run an audit in Tab 1 first, or click below to run a quick audit for this tab."
    )

    if st.button("Run Quick Audit for OWASP Matrix", key="owasp_quick"):
        with st.spinner("Running..."):
            llm = MockLLM(global_seed=int(llm_seed))
            det = SafetyDetector(use_semantic=use_semantic)
            ev = SafetyEvaluator(llm=llm, detector=det, session_id=f"owasp-quick-seed{llm_seed}")
            report = ev.run()
            scorer = OWASPScorer()
            st.session_state.owasp_matrix = scorer.score(report)
            st.session_state.v2_report = report
        st.success("OWASP scoring complete.")

    matrix = st.session_state.owasp_matrix
    if matrix:
        # Summary metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Overall OWASP Score", f"{matrix.overall_score:.1f} / 100")
        c2.metric("PASS", matrix.pass_count, delta=None)
        c3.metric("WARN", matrix.warn_count, delta=None)
        c4.metric("FAIL", matrix.fail_count, delta=None)

        st.markdown("---")

        # Compliance table
        st.markdown('<div class="section-header">Category Scores</div>', unsafe_allow_html=True)
        matrix_rows = [
            {
                "OWASP ID": cs.category.owasp_id,
                "Title": cs.category.title,
                "Score": f"{cs.score:.0f}/100",
                "Status": cs.status,
                "Penalty": f"{cs.total_penalty}/{cs.max_possible_penalty}",
                "CWE IDs": ", ".join(cs.cwe_ids[:3]) if cs.cwe_ids else "—",
            }
            for cs in matrix.category_scores
        ]
        df_matrix = pd.DataFrame(matrix_rows)
        st.dataframe(df_matrix, use_container_width=True, height=380)

        # Score bar chart
        st.markdown('<div class="section-header">Category Scores (Visual)</div>', unsafe_allow_html=True)
        scores_df = pd.DataFrame([
            {"Category": cs.category.owasp_id + ": " + cs.category.title[:25],
             "Score": cs.score}
            for cs in matrix.category_scores
        ]).sort_values("Score")
        bar_colors = [
            "#f85149" if s < 50 else ("#d29922" if s < 80 else "#3fb950")
            for s in scores_df["Score"]
        ]
        fig_owasp = go.Figure(go.Bar(
            x=scores_df["Score"],
            y=scores_df["Category"],
            orientation="h",
            marker_color=bar_colors,
            text=[f"{s:.0f}" for s in scores_df["Score"]],
            textposition="outside",
        ))
        fig_owasp.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
            font_color="#c9d1d9",
            xaxis=dict(range=[0, 110], gridcolor="#30363d"),
            yaxis=dict(color="#c9d1d9"),
            margin=dict(l=10, r=60, t=10, b=40),
        )
        st.plotly_chart(fig_owasp, use_container_width=True)

        # CWE summary
        if matrix.cwe_summary:
            st.markdown('<div class="section-header">CWE Finding Summary</div>', unsafe_allow_html=True)
            cwe_df = pd.DataFrame(
                sorted(matrix.cwe_summary.items(), key=lambda x: x[1], reverse=True),
                columns=["CWE ID", "Finding Count"],
            )
            st.dataframe(cwe_df, use_container_width=True, height=250)

        # Sub-check detail (expandable per category)
        st.markdown('<div class="section-header">Sub-Check Detail</div>', unsafe_allow_html=True)
        for cs in matrix.category_scores:
            with st.expander(
                f"{cs.category.owasp_id}: {cs.category.title} — {cs.status} ({cs.score:.0f}/100)"
            ):
                for scr in cs.sub_check_results:
                    icon = "✓" if scr.passed else "✗"
                    color = "success" if scr.passed else ("warning" if scr.sub_check.severity.value == "MEDIUM" else "error")
                    getattr(st, color)(
                        f"{icon} [{scr.sub_check.check_id}] {scr.sub_check.description} "
                        f"— {scr.notes} "
                        f"(CWE: {', '.join(scr.sub_check.cwe_ids)})"
                    )
                    if not scr.passed:
                        st.markdown(f"  *Remediation:* {scr.sub_check.remediation}")

                st.markdown("**Remediation Guide:**")
                st.markdown(cs.category.remediation_guide)

        # Recommendations
        st.markdown('<div class="section-header">Recommendations</div>', unsafe_allow_html=True)
        for rec in matrix.recommendations:
            if "[CRITICAL]" in rec:
                st.error(rec)
            elif "[HIGH]" in rec:
                st.warning(rec)
            elif "[MEDIUM]" in rec:
                st.info(rec)
            else:
                st.markdown(f"- {rec}")

        # Markdown export
        st.markdown("---")
        md_table = matrix.markdown_table()
        st.download_button(
            "Download Compliance Matrix (Markdown)",
            data=md_table,
            file_name="owasp_compliance_matrix.md",
            mime="text/markdown",
        )
    else:
        st.info("Run an audit (Tab 1) or click **Run Quick Audit** above to see the OWASP matrix.")
