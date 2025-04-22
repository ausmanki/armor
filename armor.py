# Final updated and corrected script that fixes the scanType list issue, ready to display to the user.
# The script will be provided in text form due to its length and formatting.

import streamlit as st
import asyncio
import aiohttp
import pandas as pd
from pathlib import Path
from io import BytesIO
import matplotlib.pyplot as plt
from collections import Counter
from fuzzywuzzy import fuzz

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
        "environmentName": f.get("environmentName", "Unknown"),
        "cve": f.get("cve", []),
        "cvss": f.get("cvss", {}),
        "category": f.get("category", "Uncategorized"),
        "slaBreached": f.get("slaBreached", False)
    }

def deduplicate_findings(findings, strategy):
    seen = set()
    deduped, duplicates = [], []
    for f in findings:
        title = f.get("title") or ""
        comp = f.get("componentName") or ""
        version = f.get("componentVersion") or ""
        product = f.get("product") or ""
        category = f.get("category") or ""
        scan_raw = f.get("scanType")
        scan = ", ".join(scan_raw) if isinstance(scan_raw, list) else (scan_raw or "")

        key = {
            "Component-based": (title.lower(), comp.lower(), version.lower()),
            "Title-based": title.lower(),
            "CVE-based": tuple(sorted(f.get("cve") or [])),
            "Custom": (product.lower(), scan.lower(), category.lower(), title.lower())
        }.get(strategy, title.lower())

        f["is_duplicate"] = key in seen
        (duplicates if f["is_duplicate"] else deduped).append(f)
        seen.add(key)
    return deduped + duplicates

def render_cve(cves):
    return ", ".join(f"[{c}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={c})" for c in cves) if cves else ""

def color_severity(val):
    return f"color: {dict(critical='red', high='orange', medium='gold', low='green').get(val.lower(), '')}"

def paginate(data, size=100):
    page = st.session_state.get("page", 0)
    total = len(data)
    return data[page*size:(page+1)*size], page, (total + size - 1) // size

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
            if not batch: break
            results.extend([simplify_finding(f) for f in batch])
            page += 1
    finally:
        await client.close()
    return results[:max_results]

@st.cache_data(show_spinner="Fetching findings...")
def fetch_all_findings_sync(filters=None):
    return asyncio.run(fetch_all_findings(filters))

# --- Fuzzy Grouping ---
def fuzzy_group_findings(findings, threshold=85):
    clustered = []
    remaining = findings.copy()
    while remaining:
        base = remaining.pop(0)
        group = [base]
        to_remove = []
        for other in remaining:
            score = (
                fuzz.partial_ratio(base['title'], other['title']) +
                fuzz.partial_ratio(base['componentName'], other['componentName']) +
                fuzz.partial_ratio(base['componentVersion'], other['componentVersion'])
            ) / 3
            if score >= threshold:
                group.append(other)
                to_remove.append(other)
        for item in to_remove:
            remaining.remove(item)
        clustered.append({
            "group_key": base["title"],
            "title": base["title"],
            "componentName": base["componentName"],
            "componentVersion": base["componentVersion"],
            "groupSize": len(group)
        })
    return pd.DataFrame(clustered)

# --- Dashboard ---
def run_dashboard():
    st.set_page_config(layout="wide")
    st.title("🛡️ ArmorCode Findings Dashboard")

    env = st.sidebar.multiselect("Environment", ["Production", "Staging", "Development"])
    sev = st.sidebar.multiselect("Severity", ["Critical", "High", "Medium", "Low"])
    strat = st.sidebar.selectbox("Deduplication Strategy", ["Component-based", "Title-based", "CVE-based", "Custom"])
    show_cve_links = st.sidebar.checkbox("Render CVE Links", value=False)

    filters = {}
    if env: filters["environmentName"] = env
    if sev: filters["severity"] = sev

    # 🔄 Manual trigger for fetching
    if st.sidebar.button("🔄 Load Findings"):
        st.session_state["findings_data"] = fetch_all_findings_sync(filters)
        st.session_state["page"] = 0

    findings = st.session_state.get("findings_data", [])
    if not findings:
        st.info("🔍 Click 'Load Findings' to begin.")
        return

    # Deduplicate and Grouping
    deduped = deduplicate_findings(findings, strat)
    sla_violations = [f for f in findings if f.get("slaBreached")]
    grouped_df = pd.DataFrame(findings).groupby(["product", "subProduct", "componentName"]).size().reset_index(name="count")

    # Tabs
    tabs = st.tabs(["📋 All", "🧹 Deduplicated", "⏰ SLA Breached", "📊 Summary", "📦 Grouped", "🔍 Fuzzy Groups"])
    tab_labels = ["All", "Deduplicated", "SLA"]

    for tab, data, label in zip(tabs[:3], [findings, deduped, sla_violations], tab_labels):
        with tab:
            view, page, pages = paginate(data, size=50)
            df = pd.DataFrame(view)
            if "cve" in df.columns and show_cve_links:
                df["cve"] = df["cve"].apply(render_cve)
            st.dataframe(df.style.map(color_severity, subset=["severity"]) if "severity" in df else df,
                         use_container_width=True)

            col1, col2, col3 = st.columns([1, 2, 1])
            with col1:
                if st.button(f"⬅️ Prev ({label})") and page > 0:
                    st.session_state.page -= 1
                    st.rerun()
            with col3:
                if st.button(f"Next ➡️ ({label})") and page + 1 < pages:
                    st.session_state.page += 1
                    st.rerun()

    # 📊 Summary
    with tabs[3]:
        st.subheader("Findings by Source")
        counts = Counter(f.get("source", "Unknown") for f in findings)
        fig, ax = plt.subplots()
        ax.bar(counts.keys(), counts.values())
        plt.xticks(rotation=45)
        st.pyplot(fig)

    # 📦 Grouped
    with tabs[4]:
        st.subheader("Grouped Findings (Product > SubProduct > Component)")
        st.dataframe(grouped_df, use_container_width=True)

    # 🔍 Fuzzy Grouped (Lazy eval)
    with tabs[5]:
        st.subheader("🔍 Fuzzy Grouped Findings")
        with st.spinner("Clustering similar findings..."):
            fuzzy_df = fuzzy_group_findings(findings)
            st.dataframe(fuzzy_df, use_container_width=True)

    # 📥 Export
    st.markdown("### 📥 Export to Excel")
    excel_buf = BytesIO()
    with pd.ExcelWriter(excel_buf, engine="openpyxl") as writer:
        pd.DataFrame(findings).to_excel(writer, sheet_name="All Findings", index=False)
        pd.DataFrame(deduped).to_excel(writer, sheet_name="Deduplicated", index=False)
        pd.DataFrame(sla_violations).to_excel(writer, sheet_name="SLA Breached", index=False)
        grouped_df.to_excel(writer, sheet_name="Grouped Findings", index=False)
        fuzzy_df.to_excel(writer, sheet_name="Fuzzy Groups", index=False)
    st.download_button("📤 Download Excel", excel_buf.getvalue(), file_name="armorcode_dashboard_export.xlsx")

# --- Entry ---
if __name__ == "__main__":
    run_dashboard()