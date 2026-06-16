# ============================================================
# Page 3: Scan History — Searchable/Filterable Scan Log
# ============================================================


def render():
    """
    Paginated scan history page with:
    - Text search by prompt content
    - Multi-select filter by attack category
    - Multi-select filter by severity level
    - Sortable columns (timestamp, risk_score, attack_type)
    - CSV export
    - Detail view on row expansion
    """

    import os
    import sys
    from datetime import datetime

    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)

    import streamlit as st
    import pandas as pd

    from src.database import init_db, get_scan_history, get_total_scan_count

    # ─── Page Config ──────────────────────────────────────────────

    init_db()

    # ─── Custom CSS ───────────────────────────────────────────────
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        .history-header {
            background: linear-gradient(135deg, #0a0e17 0%, #1a1f2e 50%, #0d1521 100%);
            border: 1px solid rgba(0, 212, 255, 0.15);
            border-radius: 16px;
            padding: 1.5rem 2rem;
            margin-bottom: 1.5rem;
            position: relative;
        }
        .history-header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, #2ed573, #00d4ff, #7c3aed);
        }
        .history-header h2 { color: #fff; font-size: 1.5rem; font-weight: 700; margin: 0; }
        .history-header p { color: #8b95a5; font-size: 0.9rem; margin: 0.25rem 0 0 0; }

        .filter-card {
            background: linear-gradient(145deg, #1a1f2e 0%, #151a27 100%);
            border: 1px solid rgba(0, 212, 255, 0.08);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 16px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-safe { background: rgba(46,213,115,0.15); color: #2ed573; }
        .badge-medium { background: rgba(255,234,0,0.12); color: #ffd32a; }
        .badge-high { background: rgba(255,159,67,0.15); color: #ff9f43; }
        .badge-critical { background: rgba(255,71,87,0.15); color: #ff4757; }

        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
    </style>
    """, unsafe_allow_html=True)

    # ─── Header ──────────────────────────────────────────────────
    st.markdown("""
    <div class="history-header">
        <h2>📋 Scan History</h2>
        <p>Browse, search, and export all previous prompt scan results</p>
    </div>
    """, unsafe_allow_html=True)

    # ─── Attack categories and severity options ──────────────────
    ATTACK_CATEGORIES = [
        "Safe", "Prompt Injection", "Jailbreak", "Role Hijacking",
        "System Prompt Extraction", "Data Exfiltration",
        "Indirect Prompt Injection", "Tool Abuse Attempt",
    ]
    SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

    # ─── Filters ─────────────────────────────────────────────────
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([2, 1.5, 1.5, 1])

    with filter_col1:
        search_query = st.text_input(
            "🔍 Search prompts",
            placeholder="Type to search in prompt text...",
            key="history_search",
        )

    with filter_col2:
        category_filter = st.multiselect(
            "🎯 Attack Category",
            ATTACK_CATEGORIES,
            default=[],
            key="history_category",
        )

    with filter_col3:
        severity_filter = st.multiselect(
            "⚡ Severity",
            SEVERITY_LEVELS,
            default=[],
            key="history_severity",
        )

    with filter_col4:
        sort_options = {
            "Newest First": ("timestamp", "desc"),
            "Oldest First": ("timestamp", "asc"),
            "Highest Risk": ("risk_score", "desc"),
            "Lowest Risk": ("risk_score", "asc"),
        }
        sort_choice = st.selectbox("Sort By", list(sort_options.keys()), key="history_sort")
        sort_by, sort_order = sort_options[sort_choice]

    # ─── Pagination Setup ────────────────────────────────────────
    PAGE_SIZE = 25
    total_count = get_total_scan_count(
        search_query=search_query if search_query else None,
        category_filter=category_filter if category_filter else None,
        severity_filter=severity_filter if severity_filter else None,
    )
    total_pages = max(1, (total_count + PAGE_SIZE - 1) // PAGE_SIZE)

    # Page selector
    page_col1, page_col2, page_col3 = st.columns([1, 2, 1])
    with page_col2:
        if total_pages > 1:
            current_page = st.number_input(
                f"Page (1-{total_pages})",
                min_value=1,
                max_value=total_pages,
                value=1,
                step=1,
                key="history_page",
            )
        else:
            current_page = 1

    offset = (current_page - 1) * PAGE_SIZE

    # ─── Fetch Data ──────────────────────────────────────────────
    records = get_scan_history(
        limit=PAGE_SIZE,
        offset=offset,
        search_query=search_query if search_query else None,
        category_filter=category_filter if category_filter else None,
        severity_filter=severity_filter if severity_filter else None,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    # ─── Display Summary ─────────────────────────────────────────
    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin: 0.5rem 0 1rem 0;">
        <span style="color: #8b95a5; font-size: 0.85rem;">
            Showing {offset + 1}–{min(offset + PAGE_SIZE, total_count)} of <strong style="color: #00d4ff;">{total_count:,}</strong> records
        </span>
    </div>
    """, unsafe_allow_html=True)

    # ─── Results Table ───────────────────────────────────────────
    if records:
        df = pd.DataFrame(records)

        # Format timestamp for display
        df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")

        # Truncate long prompts for table display
        df["prompt_preview"] = df["prompt"].apply(
            lambda x: x[:80] + "..." if len(str(x)) > 80 else x
        )

        # Display columns
        display_df = df[["timestamp", "prompt_preview", "risk_score", "attack_type", "severity", "confidence"]].copy()
        display_df.columns = ["Timestamp", "Prompt", "Risk Score", "Attack Type", "Severity", "Confidence"]

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            height=min(600, len(display_df) * 35 + 50),
            column_config={
                "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "Prompt": st.column_config.TextColumn("Prompt", width="large"),
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%.1f",
                ),
                "Attack Type": st.column_config.TextColumn("Attack Type", width="medium"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Confidence": st.column_config.NumberColumn(
                    "Confidence",
                    format="%.1f%%",
                ),
            },
        )

        # ─── Detail View ─────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 🔎 Record Details")

        if len(df) > 0:
            selected_idx = st.selectbox(
                "Select a record to view details",
                range(len(df)),
                format_func=lambda i: f"#{df.iloc[i]['id']} — {df.iloc[i]['prompt_preview']}",
                key="detail_select",
            )

            record = df.iloc[selected_idx]

            detail_col1, detail_col2 = st.columns(2)

            with detail_col1:
                st.markdown("**Full Prompt:**")
                st.code(record["prompt"], language=None)

                st.markdown("**Explanation:**")
                explanation = record.get("explanation", "No explanation available")
                if explanation:
                    for part in str(explanation).split("; "):
                        if part.strip():
                            st.markdown(f"- {part.strip()}")
                else:
                    st.markdown("_No explanation available_")

            with detail_col2:
                severity_colors = {
                    "Low": "#2ed573", "Medium": "#ffd32a",
                    "High": "#ff9f43", "Critical": "#ff4757",
                }
                color = severity_colors.get(record["severity"], "#8b95a5")

                st.markdown(f"""
                <div style="background: rgba(26,31,46,0.8); border: 1px solid rgba(0,212,255,0.1); border-radius: 10px; padding: 1rem;">
                    <p style="color: #8b95a5; margin: 0 0 0.5rem 0;">Risk Score</p>
                    <p style="color: {color}; font-size: 2rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; margin: 0;">{record['risk_score']}</p>
                    <p style="color: #8b95a5; margin: 0.75rem 0 0.25rem 0;">Attack Type: <strong style="color: #e0e6ed;">{record['attack_type']}</strong></p>
                    <p style="color: #8b95a5; margin: 0 0 0.25rem 0;">Severity: <strong style="color: {color};">{record['severity']}</strong></p>
                    <p style="color: #8b95a5; margin: 0 0 0.25rem 0;">Confidence: <strong style="color: #e0e6ed;">{record['confidence']}%</strong></p>
                    <p style="color: #8b95a5; margin: 0;">Scanned: <strong style="color: #e0e6ed;">{record['timestamp']}</strong></p>
                </div>
                """, unsafe_allow_html=True)

        # ─── CSV Export ──────────────────────────────────────────
        st.markdown("---")

        # Get ALL records matching current filters for export
        all_records = get_scan_history(
            limit=10000,
            offset=0,
            search_query=search_query if search_query else None,
            category_filter=category_filter if category_filter else None,
            severity_filter=severity_filter if severity_filter else None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        if all_records:
            export_df = pd.DataFrame(all_records)
            export_cols = ["timestamp", "prompt", "risk_score", "attack_type", "severity", "confidence", "explanation"]
            available_cols = [c for c in export_cols if c in export_df.columns]
            csv_data = export_df[available_cols].to_csv(index=False)

            st.download_button(
                label=f"⬇️ Export {len(all_records)} Records as CSV",
                data=csv_data,
                file_name=f"scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
    else:
        st.info("No scan records found. Start scanning prompts from the Prompt Scanner page to populate history.")
        st.markdown("""
        <div style="text-align: center; padding: 3rem; color: #4b5563;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">📋</div>
            <p style="font-size: 1.1rem;">Your scan history will appear here</p>
            <p style="font-size: 0.9rem;">Navigate to the <strong>Prompt Scanner</strong> page to start analyzing prompts</p>
        </div>
        """, unsafe_allow_html=True)
