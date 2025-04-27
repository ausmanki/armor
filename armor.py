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
        "cvss": f.get("cvss", {}),
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
def aggrid_display(df, enable_grouping=False):
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=1000)
    gb.configure_default_column(filter=True, sortable=True, resizable=True, minWidth=120, autoHeight=True)

    if "severity" in df.columns:
        gb.configure_column("severity", cellStyle={"backgroundColor": "red", "color": "white"})

    if "environmentName" in df.columns:
        gb.configure_column(
            "environmentName",
            cellStyle={"backgroundColor": "green", "color": "white"}
        )

    if enable_grouping:
        gb.configure_side_bar()
        gb.configure_grid_options(groupDisplayType="multipleColumns")
        gb.configure_columns(["product", "subProduct", "componentName"], rowGroup=True, hide=True)

    gridOptions = gb.build()

    AgGrid(
        df,
        gridOptions=gridOptions,
        height=800,
        theme="alpine",
        fit_columns_on_grid_load=False,
        allow_unsafe_jscode=True,
        enable_enterprise_modules=True
    )

# --- Async Fetch ---
async def fetch_all_findings(user_filters=None, max_results=10000, size=100):
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
    finally:
        await client.close()
    return results[:max_results]

@st.cache_data(show_spinner="Fetching findings...")
def fetch_all_findings_sync(filters=None):
    return asyncio.run(fetch_all_findings(filters))

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
        clustered.extend(group)
    return pd.DataFrame(clustered)

def cluster_findings_by_key(findings):
    clusters = {}
    for f in findings:
        key = defectdojo_dedupe_key(f)
        clusters.setdefault(key, []).append(f)
    clustered = []
    for group in clusters.values():
        clustered.extend(group)
    return pd.DataFrame(clustered)

# --- Dashboard ---
def run_dashboard():
    st.set_page_config(layout="wide")
    st.title("🛡️ ArmorCode Findings Dashboard")

    env = st.sidebar.multiselect("Environment", ["Production", "Staging", "Development"])
    sev = st.sidebar.multiselect("Severity", ["Critical", "High", "Medium", "Low"])
    strat = st.sidebar.selectbox(
        "Deduplication Strategy",
        ["Component-based", "Title-based", "CVE-based", "Custom", "Title + Component + Version"]
    )
    show_cve_links = st.sidebar.checkbox("Render CVE Links", value=False)

    filters = {}
    if env: filters["environmentName"] = env
    if sev: filters["severity"] = sev

    if st.sidebar.button("🔄 Load Findings"):
        st.session_state["findings_data"] = fetch_all_findings_sync(filters)

    findings = st.session_state.get("findings_data", [])
    if not findings:
        st.info("🔍 Click 'Load Findings' to begin.")
        return

    deduped = deduplicate_findings(findings, strat)
    sla_violations = [f for f in findings if f.get("slaBreached")]

    tabs = st.tabs(["📋 All", "🧹 Deduplicated", "⏰ SLA Breached", "📦 Grouped Findings", "🔍 Fuzzy Clustered", "🔗 Title Clusters", "📊 Summary"])

    with tabs[0]:
        st.subheader("📋 All Findings")
        df = pd.DataFrame(findings)
        if show_cve_links and "cve" in df.columns:
            df["cve"] = df["cve"].apply(render_cve)
        aggrid_display(df)

    with tabs[1]:
        st.subheader("🧹 Deduplicated Findings")
        show_unique_only = st.checkbox("Show Only Unique Findings", value=True)
        df = pd.DataFrame(deduped)
        if show_unique_only:
            df = df[df["is_duplicate"] == False]
        aggrid_display(df)

    with tabs[2]:
        st.subheader("⏰ SLA Breached Findings")
        df = pd.DataFrame(sla_violations)
        aggrid_display(df)

    with tabs[3]:
        st.subheader("📦 Grouped Findings (Expandable)")
        grouped_df = pd.DataFrame(findings)
        aggrid_display(grouped_df, enable_grouping=True)

    with tabs[4]:
        st.subheader("🔍 Fuzzy Clustered Findings")
        fuzzy_df = fuzzy_group_findings(findings)
        aggrid_display(fuzzy_df)

    with tabs[5]:
        st.subheader("🔗 Title + Component + Version Clusters")
        clustered_df = cluster_findings_by_key(findings)
        aggrid_display(clustered_df)

    with tabs[6]:
        st.subheader("📊 Findings by Source")
        counts = Counter(f.get("source", "Unknown") for f in findings)
        fig, ax = plt.subplots()
        ax.bar(counts.keys(), counts.values())
        plt.xticks(rotation=45)
        st.pyplot(fig)

    st.markdown("### 📥 Export All Findings to Excel")
    excel_buf = BytesIO()
    with pd.ExcelWriter(excel_buf, engine="openpyxl") as writer:
        pd.DataFrame(findings).to_excel(writer, sheet_name="All Findings", index=False)
        pd.DataFrame(deduped).to_excel(writer, sheet_name="Deduplicated", index=False)
        pd.DataFrame(sla_violations).to_excel(writer, sheet_name="SLA Breached", index=False)
        fuzzy_df.to_excel(writer, sheet_name="Fuzzy Clustered", index=False)
        clustered_df.to_excel(writer, sheet_name="Title Clusters", index=False)
    st.download_button("📤 Download Excel", excel_buf.getvalue(), file_name="armorcode_dashboard_export.xlsx")

# --- Entry ---
if __name__ == "__main__":
    run_dashboard()
