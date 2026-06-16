# ============================================================
# Page 2: Analytics — Security Analytics Dashboard
# ============================================================


def render():
    """
    Interactive analytics dashboard with Plotly charts:
    - Daily attacks time series
    - Risk score distribution histogram
    - Attack category breakdown (donut chart)
    - Top attack patterns (bar chart)
    - Severity distribution
    - OWASP mapping treemap
    """

    import os
    import sys
    from datetime import datetime

    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)

    import streamlit as st
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd

    from src.database import init_db
    from src.analytics import (
        get_dashboard_stats,
        get_daily_attacks,
        get_attack_category_data,
        get_risk_distribution_data,
        get_severity_data,
        get_top_attack_patterns,
        get_owasp_mapping_data,
        get_hourly_distribution,
    )

    # ─── Page Config ──────────────────────────────────────────────

    init_db()

    # ─── Custom CSS ───────────────────────────────────────────────
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        .analytics-header {
            background: linear-gradient(135deg, #0a0e17 0%, #1a1f2e 50%, #0d1521 100%);
            border: 1px solid rgba(0, 212, 255, 0.15);
            border-radius: 16px;
            padding: 1.5rem 2rem;
            margin-bottom: 1.5rem;
            position: relative;
        }
        .analytics-header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, #7c3aed, #00d4ff, #2ed573);
        }
        .analytics-header h2 { color: #fff; font-size: 1.5rem; font-weight: 700; margin: 0; }
        .analytics-header p { color: #8b95a5; font-size: 0.9rem; margin: 0.25rem 0 0 0; }

        .chart-card {
            background: linear-gradient(145deg, #1a1f2e 0%, #151a27 100%);
            border: 1px solid rgba(0, 212, 255, 0.08);
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .chart-card h4 {
            color: #e0e6ed;
            font-size: 0.95rem;
            font-weight: 600;
            margin: 0 0 0.5rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(0, 212, 255, 0.1);
        }

        .stat-mini {
            background: rgba(26, 31, 46, 0.8);
            border: 1px solid rgba(0, 212, 255, 0.1);
            border-radius: 10px;
            padding: 1rem;
            text-align: center;
        }
        .stat-mini .value {
            font-size: 1.8rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }
        .stat-mini .label {
            color: #8b95a5;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

    # ─── Plotly Theme ─────────────────────────────────────────────
    PLOTLY_LAYOUT = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#8b95a5", family="Inter", size=12),
        margin=dict(l=40, r=20, t=40, b=40),
        xaxis=dict(gridcolor="rgba(0,212,255,0.06)", color="#8b95a5"),
        yaxis=dict(gridcolor="rgba(0,212,255,0.06)", color="#8b95a5"),
        legend=dict(font=dict(color="#c0c8d4")),
    )

    CATEGORY_COLORS = {
        "Safe": "#2ed573",
        "Prompt Injection": "#ff4757",
        "Jailbreak": "#ffd32a",
        "Role Hijacking": "#ff9f43",
        "System Prompt Extraction": "#00d4ff",
        "Data Exfiltration": "#7c3aed",
        "Indirect Prompt Injection": "#a4b0be",
        "Tool Abuse Attempt": "#ff6b81",
    }

    SEVERITY_COLORS = {
        "Low": "#2ed573",
        "Medium": "#ffd32a",
        "High": "#ff9f43",
        "Critical": "#ff4757",
    }

    # ─── Header ──────────────────────────────────────────────────
    st.markdown("""
    <div class="analytics-header">
        <h2>📊 Security Analytics</h2>
        <p>Real-time security intelligence and threat analysis dashboard</p>
    </div>
    """, unsafe_allow_html=True)

    # ─── Controls ────────────────────────────────────────────────
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1, 1, 2])
    with ctrl_col1:
        days_range = st.selectbox("Time Range", [7, 14, 30, 60, 90], index=2, format_func=lambda x: f"Last {x} days")
    with ctrl_col2:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    # ─── Summary Stats ───────────────────────────────────────────
    stats = get_dashboard_stats()

    s1, s2, s3, s4, s5 = st.columns(5)
    with s1:
        st.markdown(f"""
        <div class="stat-mini">
            <div class="label">Total Scans</div>
            <div class="value" style="color: #00d4ff;">{stats['total_scans']:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with s2:
        st.markdown(f"""
        <div class="stat-mini">
            <div class="label">Attacks Detected</div>
            <div class="value" style="color: #ff4757;">{stats['attacks_detected']:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with s3:
        st.markdown(f"""
        <div class="stat-mini">
            <div class="label">High Risk</div>
            <div class="value" style="color: #ff9f43;">{stats['high_risk_count']:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with s4:
        st.markdown(f"""
        <div class="stat-mini">
            <div class="label">Detection Rate</div>
            <div class="value" style="color: #2ed573;">{stats['detection_rate']:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)
    with s5:
        st.markdown(f"""
        <div class="stat-mini">
            <div class="label">Avg Risk Score</div>
            <div class="value" style="color: #7c3aed;">{stats['avg_risk_score']:.1f}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # ─── Row 1: Daily Attacks + Category Breakdown ───────────────
    row1_col1, row1_col2 = st.columns([2, 1])

    with row1_col1:
        st.markdown('<div class="chart-card"><h4>📈 Daily Attack Activity</h4></div>', unsafe_allow_html=True)

        daily_df = get_daily_attacks(days=days_range)

        if not daily_df.empty:
            fig_daily = go.Figure()
            fig_daily.add_trace(go.Scatter(
                x=daily_df["date"], y=daily_df["total_scans"],
                name="Total Scans",
                line=dict(color="#00d4ff", width=2),
                fill="tozeroy",
                fillcolor="rgba(0, 212, 255, 0.05)",
            ))
            fig_daily.add_trace(go.Scatter(
                x=daily_df["date"], y=daily_df["attacks_detected"],
                name="Attacks",
                line=dict(color="#ff4757", width=2),
                fill="tozeroy",
                fillcolor="rgba(255, 71, 87, 0.05)",
            ))
            fig_daily.add_trace(go.Scatter(
                x=daily_df["date"], y=daily_df["high_risk_count"],
                name="High Risk",
                line=dict(color="#ff9f43", width=2, dash="dot"),
            ))
            fig_daily.update_layout(**PLOTLY_LAYOUT, height=350, showlegend=True)
            fig_daily.update_layout(legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
            st.plotly_chart(fig_daily, use_container_width=True)
        else:
            st.info("No scan data available yet. Start scanning prompts to populate analytics.")

    with row1_col2:
        st.markdown('<div class="chart-card"><h4>🎯 Attack Categories</h4></div>', unsafe_allow_html=True)

        cat_df = get_attack_category_data()

        if not cat_df.empty:
            colors = [CATEGORY_COLORS.get(c, "#8b95a5") for c in cat_df["attack_type"]]
            fig_cat = go.Figure(go.Pie(
                labels=cat_df["attack_type"],
                values=cat_df["count"],
                hole=0.55,
                marker=dict(colors=colors, line=dict(color="#0a0e17", width=2)),
                textinfo="label+percent",
                textfont=dict(size=11, color="#e0e6ed"),
                hoverinfo="label+value+percent",
            ))
            fig_cat.update_layout(**PLOTLY_LAYOUT, height=350, showlegend=False)
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.info("No category data yet.")

    # ─── Row 2: Risk Distribution + Severity ─────────────────────
    row2_col1, row2_col2 = st.columns(2)

    with row2_col1:
        st.markdown('<div class="chart-card"><h4>📊 Risk Score Distribution</h4></div>', unsafe_allow_html=True)

        risk_df = get_risk_distribution_data()

        if not risk_df.empty:
            fig_hist = go.Figure(go.Histogram(
                x=risk_df["risk_score"],
                nbinsx=20,
                marker=dict(
                    color=[
                        "#2ed573" if x <= 25 else "#ffd32a" if x <= 50
                        else "#ff9f43" if x <= 75 else "#ff4757"
                        for x in risk_df["risk_score"]
                    ],
                    line=dict(color="#0a0e17", width=1),
                ),
            ))
            # Use colorscale bins instead
            fig_hist = go.Figure()
            bins = [
                (risk_df[risk_df["risk_score"] <= 25]["risk_score"], "#2ed573", "Low"),
                (risk_df[(risk_df["risk_score"] > 25) & (risk_df["risk_score"] <= 50)]["risk_score"], "#ffd32a", "Medium"),
                (risk_df[(risk_df["risk_score"] > 50) & (risk_df["risk_score"] <= 75)]["risk_score"], "#ff9f43", "High"),
                (risk_df[risk_df["risk_score"] > 75]["risk_score"], "#ff4757", "Critical"),
            ]
            for data, color, name in bins:
                if not data.empty:
                    fig_hist.add_trace(go.Histogram(
                        x=data, name=name,
                        marker_color=color,
                        opacity=0.85,
                        nbinsx=10,
                    ))
            fig_hist.update_layout(**PLOTLY_LAYOUT, height=320, barmode="stack",
                xaxis_title="Risk Score", yaxis_title="Count")
            fig_hist.update_layout(legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
            st.plotly_chart(fig_hist, use_container_width=True)
        else:
            st.info("No risk score data yet.")

    with row2_col2:
        st.markdown('<div class="chart-card"><h4>⚡ Severity Breakdown</h4></div>', unsafe_allow_html=True)

        sev_df = get_severity_data()

        if not sev_df.empty:
            # Ensure correct order
            severity_order = ["Low", "Medium", "High", "Critical"]
            sev_df["sort_key"] = sev_df["severity"].map(
                {s: i for i, s in enumerate(severity_order)}
            )
            sev_df = sev_df.sort_values("sort_key")

            colors = [SEVERITY_COLORS.get(s, "#8b95a5") for s in sev_df["severity"]]
            fig_sev = go.Figure(go.Bar(
                x=sev_df["severity"],
                y=sev_df["count"],
                marker_color=colors,
                text=sev_df["count"],
                textposition="auto",
                textfont=dict(color="#e0e6ed", size=14, family="JetBrains Mono"),
            ))
            fig_sev.update_layout(**PLOTLY_LAYOUT, height=320,
                xaxis_title="Severity", yaxis_title="Count")
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No severity data yet.")

    # ─── Row 3: Top Patterns + OWASP Mapping ─────────────────────
    row3_col1, row3_col2 = st.columns(2)

    with row3_col1:
        st.markdown('<div class="chart-card"><h4>🔥 Top Attack Patterns</h4></div>', unsafe_allow_html=True)

        patterns = get_top_attack_patterns(limit=10)

        if patterns:
            pat_df = pd.DataFrame(patterns)
            fig_pat = go.Figure(go.Bar(
                y=pat_df["description"],
                x=pat_df["count"],
                orientation="h",
                marker_color="#00d4ff",
                text=pat_df["count"],
                textposition="auto",
                textfont=dict(color="#e0e6ed", size=11, family="JetBrains Mono"),
            ))
            fig_pat.update_layout(**PLOTLY_LAYOUT, height=400,
                xaxis_title="Occurrences")
            fig_pat.update_layout(yaxis=dict(autorange="reversed", color="#c0c8d4"))
            st.plotly_chart(fig_pat, use_container_width=True)
        else:
            st.info("No attack patterns detected yet. Scan some prompts to populate this chart.")

    with row3_col2:
        st.markdown('<div class="chart-card"><h4>🏛️ OWASP LLM Top 10 Distribution</h4></div>', unsafe_allow_html=True)

        owasp_data = get_owasp_mapping_data()

        if owasp_data:
            owasp_df = pd.DataFrame(owasp_data)

            fig_owasp = go.Figure(go.Treemap(
                labels=owasp_df["attack_type"],
                parents=owasp_df["owasp_id"],
                values=owasp_df["count"],
                textinfo="label+value",
                marker=dict(
                    colors=[CATEGORY_COLORS.get(c, "#8b95a5") for c in owasp_df["attack_type"]],
                    line=dict(color="#0a0e17", width=2),
                ),
                textfont=dict(color="#e0e6ed", size=12),
            ))
            fig_owasp.update_layout(**PLOTLY_LAYOUT, height=400)
            st.plotly_chart(fig_owasp, use_container_width=True)
        else:
            st.info("No OWASP mapping data yet.")

    # ─── Footer ──────────────────────────────────────────────────
    st.markdown(f"""
    <div style="text-align: center; padding: 1.5rem 0; border-top: 1px solid rgba(0,212,255,0.1); margin-top: 2rem;">
        <p style="color: #4b5563; font-size: 0.8rem;">Analytics last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """, unsafe_allow_html=True)
