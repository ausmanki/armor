import streamlit as st
import asyncio
import aiohttp
import pandas as pd
from pathlib import Path
from io import BytesIO
import matplotlib.pyplot as plt
from collections import Counter
from fuzzywuzzy import fuzz
import hashlib
from st_aggrid import AgGrid, GridOptionsBuilder

# --- API Client ---
class ArmorCodeClient:
    def __init__(self, api_key, base_url="https://app.armorcode.com"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = aiohttp.ClientSession(headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        })

    async def post(self, endpoint, json, retries=3):
        url = f"{self.base_url}{endpoint}"
        for _ in range(retries):
            async with self.session.post(url, json=json) as resp:
                if resp.status >= 400:
                    raise aiohttp.ClientResponseError(
                        status=resp.status,
                        message=await resp.text(),
                        request_info=resp.request_info,
                        history=resp.history
                    )
                return await resp.json()

    async def close(self):
        await self.session.close()

# --- Utilities ---
def get_api_key():
    return Path(__file__).parent.joinpath("ArmorCode_API_key.txt").read_text().strip()

def simplify_finding(f):
    cvss_data = f.get("cvss", {})
    base_score = cvss_data.get("baseScore", "N/A") if isinstance(cvss_data, dict) else "N/A"

    return {
        "title": f.get("title", "Untitled"),
        "description": f.get("description", ""),
        "severity": f.get("severity", "Unspecified"),
        "status": f.get("status", "Unknown"),
        "source": f.get("source", "Unknown"),
        "scanType": f.get("scanType", "Unknown"),
        "componentName": f.get("componentName", "Unknown"),
        "componentVersion": f.get("componentVersion", "Unknown"),
        "product": f.get("product", {}).get("name", "Unknown"),
        "subProduct": f.get("subProduct", {}).get("name", "Unknown"),
        "environmentName": f.get("environment", {}).get("name", "Unknown"),
        "cve": f.get("cve", []),
        "cvssScore": base_score,  # <-- notice this now
        "category": f.get("category", "Uncategorized"),
        "slaBreached": f.get("slaBreached", False)
    }
def defectdojo_dedupe_key(finding):
    title = (finding.get("title") or "").lower().strip()
    component = (finding.get("componentName") or "").lower().strip()
    version = (finding.get("componentVersion") or "").lower().strip()
    combined = f"{title}:{component}:{version}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def deduplicate_findings(findings, strategy):
    seen = {}
    deduped = []
    for f in findings:
        title = (f.get("title") or "").lower()
        comp = (f.get("componentName") or "").lower()
        version = (f.get("componentVersion") or "").lower()
        product = (f.get("product") or "").lower()
        category = (f.get("category") or "").lower()
        scan_raw = f.get("scanType")
        scan = ", ".join(scan_raw) if isinstance(scan_raw, list) else (scan_raw or "")

        key = {
            "Component-based": (title, comp, version),
            "Title-based": title,
            "CVE-based": tuple(sorted(f.get("cve") or [])),
            "Custom": (product, scan, category, title),
            "Title + Component + Version": defectdojo_dedupe_key(f)
        }.get(strategy, title)

        f["is_duplicate"] = key in seen
        seen[key] = True
        deduped.append(f)
    return deduped

def render_cve(cves):
    return ", ".join(f"[{c}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={c})" for c in cves) if cves else ""

# --- AgGrid Helper Functions ---
# --- AgGrid Helper Functions ---
def aggrid_display(df, enable_grouping=False, key=None):
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=1000)
    gb.configure_default_column(filter=True, sortable=True, resizable=True, minWidth=120, autoHeight=True)

    # --- Fix nested object types ---
    df = df.copy()
    for col in df.columns:
        if df[col].apply(lambda x: isinstance(x, (dict, list))).any():
            df[col] = df[col].apply(str)

    # --- Severity coloring ---
    if "severity" in df.columns:
        gb.configure_column(
            "severity",
            headerName="Severity",
            cellRenderer="""
            function(params) {
                var color = '';
                var textColor = 'black';
                if (String(params.value) === 'Critical') {
                    color = 'red'; textColor = 'white';
                } else if (String(params.value) === 'High') {
                    color = 'orange';
                } else if (String(params.value) === 'Medium') {
                    color = 'yellow';
                } else if (String(params.value) === 'Low') {
                    color = 'lightgreen';
                }
                return `<div style="background-color:${color};color:${textColor};padding:2px;">${String(params.value)}</div>`;
            }
            """
        )

    # your other code continues...

    gridOptions = gb.build()

    AgGrid(
        df,
        gridOptions=gridOptions,
        height=800,
        theme="alpine",
        fit_columns_on_grid_load=False,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True,
        key=key
    )

# --- Async Fetch ---
async def fetch_all_findings(user_filters=None, max_results=10000, size=100, progress_callback=None):
    api_key = get_api_key()
    client = ArmorCodeClient(api_key)
    results, page = [], 0
    try:
        while len(results) < max_results:
            payload = {
                "size": size,
                "page": page,
                "filters": user_filters or {},
                "filterOperations": {
                    "source": "OR", "severity": "OR", "scanType": "OR",
                    "status": "OR", "environmentName": "OR"
                },
                "sortColumns": [{"property": "riskScore", "direction": "desc"}],
                "ticketStatusRequired": False
            }
            response = await client.post("/user/findings/", json=payload)
            batch = response.get("content", [])
            if not batch:
                break
            results.extend([simplify_finding(f) for f in batch])
            page += 1
            if progress_callback:
                progress_callback(len(results), max_results)
    finally:
        await client.close()
    return results[:max_results]

def fetch_all_findings_sync(filters=None):
    progress = st.session_state.get("progress_callback", None)
    return asyncio.run(fetch_all_findings(user_filters=filters, progress_callback=progress))



# --- Grouping Functions ---
def fuzzy_group_findings(findings, threshold=85):
    clustered = []
    remaining = findings.copy()

    while remaining:
        base = remaining.pop(0)
        group = [base]
        to_remove = []
        for other in remaining:
            score = (
                fuzz.partial_ratio(base.get('title') or '', other.get('title') or '') +
                fuzz.partial_ratio(base.get('componentName') or '', other.get('componentName') or '') +
                fuzz.partial_ratio(base.get('componentVersion') or '', other.get('componentVersion') or '')
            ) / 3
            if score >= threshold:
                group.append(other)
                to_remove.append(other)

        for item in to_remove:
            remaining.remove(item)

        # Only pick base (main) + record how many grouped
        base["fuzzy_cluster_size"] = len(group)
        clustered.append(base)

    return pd.DataFrame(clustered)

def cluster_findings_by_key(findings):
    clusters = {}
    for f in findings:
        key = defectdojo_dedupe_key(f)
        clusters.setdefault(key, []).append(f)

    clustered = []
    for group in clusters.values():
        representative = group[0]  # take only 1 finding per cluster
        clustered.append(representative)

    return pd.DataFrame(clustered)

# --- Dashboard ---
def run_dashboard():
    st.set_page_config(layout="wide")
    st.title("🛡️ ArmorCode Findings Dashboard")

    # --- Sidebar: Filters and Grouping ---
    st.sidebar.title("🔎 Apply Filters")

    # Clear filters button
    if st.sidebar.button("🧹 Clear All Filters"):
        st.session_state["severity_filter"] = []
        st.session_state["env_filter"] = []
        st.session_state["sla_only_filter"] = False
        st.session_state["component_filter"] = []

    # Initialize session states
    if "severity_filter" not in st.session_state:
        st.session_state["severity_filter"] = []
    if "env_filter" not in st.session_state:
        st.session_state["env_filter"] = []
    if "sla_only_filter" not in st.session_state:
        st.session_state["sla_only_filter"] = False
    if "component_filter" not in st.session_state:
        st.session_state["component_filter"] = []

    # Grouping columns (Dynamic from sidebar)
    default_group_cols = ["product", "subProduct", "componentName"]
    group_by_columns = st.sidebar.multiselect(
        "Group findings by (choose columns)",
        options=["product", "subProduct", "componentName", "environmentName", "severity", "category", "status"],
        default=default_group_cols,
        help="Select columns to group findings."
    )

    # Expand/Collapse toggle
    expand_groups_toggle = st.sidebar.toggle("Expand All Groups", value=False, key="expand_groups_toggle")

    # Deduplication strategy
    strat = st.sidebar.selectbox(
        "Deduplication Strategy",
        ["Component-based", "Title-based", "CVE-based", "Custom", "Title + Component + Version"]
    )

    show_cve_links = st.sidebar.checkbox("Render CVE Links", value=False)

    # Sidebar filters (only after findings loaded)
    if "findings_data" in st.session_state and st.session_state["findings_data"]:
        full_df = pd.DataFrame(st.session_state["findings_data"])

        st.sidebar.multiselect(
            "Filter by Severity",
            options=full_df["severity"].dropna().unique().tolist(),
            default=st.session_state["severity_filter"],
            key="severity_filter"
        )
        st.sidebar.multiselect(
            "Filter by Environment",
            options=full_df["environmentName"].dropna().unique().tolist(),
            default=st.session_state["env_filter"],
            key="env_filter"
        )
        st.sidebar.checkbox(
            "Show Only SLA Breached Findings",
            value=st.session_state["sla_only_filter"],
            key="sla_only_filter"
        )
        st.sidebar.multiselect(
            "Filter by Component Name",
            options=full_df["componentName"].dropna().unique().tolist(),
            default=st.session_state["component_filter"],
            key="component_filter"
        )
    else:
        st.sidebar.info("🔵 Load findings to unlock more filters.")

    # Load findings
    if st.sidebar.button("🔄 Load Findings"):
        progress_bar = st.sidebar.progress(0)

        def update_progress(current, total):
            percent = min(current / total, 1.0)
            progress_bar.progress(percent)

        st.session_state["progress_callback"] = update_progress
        st.session_state["findings_data"] = fetch_all_findings_sync()
        st.session_state["progress_callback"] = None
        progress_bar.empty()

    # Load findings
    findings = st.session_state.get("findings_data", [])
    if not findings:
        st.info("🔍 Click 'Load Findings' to begin.")
        return

    deduped = deduplicate_findings(findings, strat)
    full_df = pd.DataFrame(findings)

    # Apply filters
    filtered_df = full_df.copy()
    if st.session_state["severity_filter"]:
        filtered_df = filtered_df[filtered_df["severity"].isin(st.session_state["severity_filter"])]
    if st.session_state["env_filter"]:
        filtered_df = filtered_df[filtered_df["environmentName"].isin(st.session_state["env_filter"])]
    if st.session_state["sla_only_filter"]:
        filtered_df = filtered_df[filtered_df["slaBreached"] == True]
    if st.session_state["component_filter"]:
        filtered_df = filtered_df[filtered_df["componentName"].isin(st.session_state["component_filter"])]

    # Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Findings", len(filtered_df))
    with col2:
        st.metric("Unique Findings", sum(not f.get("is_duplicate", False) for f in deduplicate_findings(filtered_df.to_dict(orient="records"), strat)))
    with col3:
        st.metric("SLA Breaches", sum(filtered_df["slaBreached"]))

    # Tabs
    tabs = st.tabs([
        "📋 All",
        "🧹 Deduplicated",
        "⏰ SLA Breached",
        "📦 Grouped Findings",
        "🔍 Fuzzy Clustered",
        "🔗 Title Clusters",
        "📊 Summary"
    ])

    # 📋 All Findings
    with tabs[0]:
        st.subheader("📋 All Findings")
        df = filtered_df.copy()
        if show_cve_links and "cve" in df.columns:
            df["cve"] = df["cve"].apply(render_cve)
        aggrid_display(df, key="grid_all_findings")

    # 🧹 Deduplicated Findings
    with tabs[1]:
        st.subheader("🧹 Deduplicated Findings")
        show_unique_only = st.checkbox("Show Only Unique Findings", value=True)
        deduped_df = pd.DataFrame(deduplicate_findings(filtered_df.to_dict(orient="records"), strat))
        if show_unique_only:
            deduped_df = deduped_df[deduped_df["is_duplicate"] == False]
        aggrid_display(deduped_df, key="grid_deduped_findings")

    # ⏰ SLA Breached
    with tabs[2]:
        st.subheader("⏰ SLA Breached Findings")
        sla_df = filtered_df[filtered_df["slaBreached"] == True]
        aggrid_display(sla_df, key="grid_sla_breached")

    # 📦 Grouped Findings (Expandable)
    with tabs[3]:
        st.subheader("📦 Grouped Findings (Expandable)")

        with st.spinner("Preparing grouped findings..."):
            gb = GridOptionsBuilder.from_dataframe(filtered_df)
            gb.configure_pagination(paginationAutoPageSize=True)
            gb.configure_default_column(
                filter=True,
                sortable=True,
                resizable=True,
                minWidth=120,
                autoHeight=True
            )

            group_cols = group_by_columns if group_by_columns else default_group_cols
            gb.configure_columns(group_cols, rowGroup=True, hide=True)

            # Use toggle for Expand/Collapse
            group_expansion_level = -1 if expand_groups_toggle else 0
            gb.configure_grid_options(
                groupDisplayType="multipleColumns",
                groupDefaultExpanded=group_expansion_level
            )

            gb.configure_grid_options(groupRowRendererParams={
    "innerRenderer": """
        function(params) {
            return String(params.node.key) + ' (' + params.node.allChildrenCount + ')';
        }
    """
})

            gridOptions = gb.build()

            AgGrid(
                filtered_df,
                gridOptions=gridOptions,
                height=800,
                theme="alpine",
                fit_columns_on_grid_load=False,
                allow_unsafe_jscode=True,
                enable_enterprise_modules=True,
                key="grid_grouped_findings_dynamic"
            )

    # 🔍 Fuzzy Clustered
    with tabs[4]:
        st.subheader("🔍 Fuzzy Clustered Findings")
        fuzzy_df = fuzzy_group_findings(filtered_df.to_dict(orient="records"))
        aggrid_display(fuzzy_df, key="grid_fuzzy_clustered")

    # 🔗 Title Clusters
    with tabs[5]:
        st.subheader("🔗 Title + Component + Version Clusters")
        clustered_df = cluster_findings_by_key(filtered_df.to_dict(orient="records"))
        aggrid_display(clustered_df, key="grid_title_clusters")

    # 📊 Summary
    with tabs[6]:
        st.subheader("📊 Findings by Source")
        counts = Counter(f.get("source", "Unknown") for f in filtered_df.to_dict(orient="records"))
        fig, ax = plt.subplots()
        ax.bar(counts.keys(), counts.values())
        plt.xticks(rotation=45)
        st.pyplot(fig)

    # 📥 Excel Export
    st.markdown("### 📥 Export All Findings to Excel")
    excel_buf = BytesIO()
    with pd.ExcelWriter(excel_buf, engine="openpyxl") as writer:
        filtered_df.to_excel(writer, sheet_name="Filtered Findings", index=False)
        deduped_df.to_excel(writer, sheet_name="Deduplicated", index=False)
        sla_df.to_excel(writer, sheet_name="SLA Breached", index=False)
        fuzzy_df.to_excel(writer, sheet_name="Fuzzy Clustered", index=False)
        clustered_df.to_excel(writer, sheet_name="Title Clusters", index=False)

    st.download_button(
        "📤 Download Excel",
        excel_buf.getvalue(),
        file_name="armorcode_dashboard_export.xlsx"
    )

# --- Dashboard ---
# --- Entry ---
if __name__ == "__main__":
    run_dashboard()  