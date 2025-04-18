import os
import asyncio
import aiohttp
import streamlit as st
from pathlib import Path
import nest_asyncio
from collections import defaultdict
import pandas as pd
from collections import defaultdict
import numpy as np
import random
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import AgglomerativeClustering
import async_timeout
# Lazy load for performance
@st.cache_resource(show_spinner="Loading AI model...")
def get_embedding_model():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer("all-MiniLM-L6-v2")

# Torch issue workaround (Windows/Streamlit combo)
os.environ["STREAMLIT_WATCHDOG_USE_POLLING"] = "true"
nest_asyncio.apply()

# ------------ API KEY ------------- #
def get_api_key():
    api_key = os.getenv("ARMORCODE_API_KEY")
    if not api_key:
        key_file = Path(__file__).parent / "ArmorCode_API_key.txt"
        with open(key_file, "r") as f:
            api_key = f.read().strip()
    return api_key

# ------------ Hybrid Deduplication ------------- #
def hybrid_deduplicate_findings(findings, threshold=0.85):
    model = get_embedding_model()
    texts = [(f.get("title", "") or "") + " " + (f.get("description", "") or "") for f in findings]
    embeddings = model.encode(texts, show_progress_bar=True)
    keep = []
    seen = np.zeros(len(texts))
    explanations = []

    for i, emb in enumerate(embeddings):
        if seen[i]:
            continue
        current = findings[i]
        keep.append(current)
        sim = cosine_similarity([emb], embeddings)[0]

        for j in range(i + 1, len(sim)):
            if seen[j]:
                continue
            other = findings[j]
            same_id = (
                str(current.get("title", "") or "")[:20] +
                str(current.get("componentName", "") or "") +
                str(current.get("componentVersion", "") or "")
            ) == (
                str(other.get("title", "") or "")[:20] +
                str(other.get("componentName", "") or "") +
                str(other.get("componentVersion", "") or "")
            )
            if sim[j] >= threshold and same_id:
                seen[j] = 1
                explanations.append({
                    "Duplicate Of": current.get("title", ""),
                    "Removed": other.get("title", ""),
                    "Similarity": round(sim[j], 3),
                    "Reason": "Title+Component+Version match with high embedding similarity",
                    "Product": other.get("product", {}).get("name", ""),
                    "Sub Product": other.get("subProduct", {}).get("name", "")
                })

    st.session_state["dedup_explanations"] = explanations
    return keep
# ------------ Group by CVE ------------- #
def group_findings_by_cve(findings_data):
    grouped = defaultdict(lambda: {"vendor": "", "components": []})
    for finding in findings_data:
        title = finding.get("title", "")
        component = finding.get("componentName", "")
        version = finding.get("componentVersion", "")
        vendor = finding.get("product", {}).get("name", "")
        cve_id = title.split(" - ")[0] if " - " in title else title
        full_component = f"{component}:{version}".strip(":")
        grouped[cve_id]["vendor"] = vendor
        grouped[cve_id]["components"].append(full_component)
    return grouped

# ------------ ArmorCode API Client ------------- #
class ArmorCodeClient:
    def __init__(self, api_key: str, base_url="https://app.armorcode.com"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = aiohttp.ClientSession(headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        })

    async def post(self, endpoint: str, json: dict, retries=3):
        url = f"{self.base_url}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
        for attempt in range(retries):
            try:
                async with self.session.post(url, json=json) as resp:
                    if resp.status == 429:
                        wait_time = random.uniform(1.5, 3.0)
                        await asyncio.sleep(wait_time)
                        continue
                    resp.raise_for_status()
                    return await resp.json()
            except aiohttp.ClientResponseError as e:
                if e.status == 429 and attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise

    async def close(self):
        await self.session.close()

# ------------ Discover Sources ------------- #
# ------------ Discover Sources Dynamically from /user/findings ------------- #
async def discover_sources_from_findings(client: ArmorCodeClient, max_pages=20):  # ⬅️ increase page count
    seen_sources = set()
    page = 0

    st.sidebar.markdown("🔍 Discovering available tools...")
    with st.spinner("Collecting sources from findings..."):

        while page < max_pages:
            payload = {
                "size": 100,
                "page": page,
                "filters": {},
                "sortColumns": [{"property": "riskScore", "direction": "desc"}],
                "filterOperations": {},
                "ticketStatusRequired": False,
                "ignoreMitigated": None,
                "ignoreDuplicate": True
            }

            try:
                result = await client.post("/user/findings/", json=payload)
                findings = result.get("content", [])

                if not findings:
                    break

                for finding in findings:
                    source = finding.get("source")
                    if source:
                        seen_sources.add(source)

                if len(findings) < 100:
                    break
                page += 1

            except Exception as e:
                st.warning(f"⚠️ Failed to fetch sources on page {page}: {e}")
                break

    if not seen_sources:
        st.warning("⚠️ No sources discovered. Check API or filters.")

    return sorted(seen_sources)


# ------------ Fetch Filters & Findings ------------- #
# ------------ Fetch Filters & Findings ------------- #
# ------------ Fetch Filters & Findings ------------- #
# ------------ Fetch Filters & Findings ------------- #
async def fetch_all_findings(user_filters=None, max_pages=20, size=100):
    api_key = get_api_key()
    client = ArmorCodeClient(api_key)
    all_findings = []

    def simplify_finding(raw):
        return {
        "title": raw.get("title", ""),
        "description": raw.get("description", ""),
        "severity": raw.get("severity", ""),
        "status": raw.get("status", ""),
        "source": raw.get("source", ""),
        "scanType": raw.get("scanType", []),
        "componentName": raw.get("componentName", ""),
        "componentVersion": raw.get("componentVersion", ""),
        "product": {"name": raw.get("product", {}).get("name", "")},
        "subProduct": {"name": raw.get("subProduct", {}).get("name", "")},
        "environmentName": raw.get("environmentName", ""),  # ✅ ADD THIS
        "cve": raw.get("cve", []),
        "cvss": raw.get("cvss", {}),
        "findingCategory": raw.get("findingCategory") or raw.get("category", ""),
        "category": raw.get("category", "")
    }

    try:
        for page in range(max_pages):
            filters = {
                "status": ["OPEN", "TRIAGE", "CONFIRMED"],
                "severity": ["CRITICAL", "High", "Medium", "Low"],
                "environmentName": ["Production", "Staging", "Development"]
            }

            if user_filters:
                filters.update(user_filters)

            payload = {
                "size": size,
                "page": page,
                "sortColumns": [{"property": "riskScore", "direction": "desc"}],
                "filters": filters,
                "filterOperations": {
                    "source": "OR",
                    "severity": "OR",
                    "scanType": "OR",
                    "status": "OR",
                    "environmentName": "OR"
                },
                "ticketStatusRequired": False,
                "ignoreMitigated": None,
                "ignoreDuplicate": False
            }

            if page == 0:
                with st.sidebar.expander("🧪 Active API Filters"):
                    st.json(payload["filters"])

            try:
                response = await client.post("/user/findings/", json=payload)

                # ✅ Fix: Add null check with correct indentation
                if not response or "content" not in response:
                    st.warning(f"⚠️ No valid response on page {page}")
                    break

                batch = response.get("content", [])
                if not batch:
                    st.info(f"🔍 No results found on page {page}")
                    break

                simplified_batch = [simplify_finding(f) for f in batch]
                all_findings.extend(simplified_batch)

                if len(batch) < size:
                    break

            except Exception as e:
                st.warning(f"⚠️ Failed to fetch page {page + 1}: {e}")
                break

            await asyncio.sleep(0.3)

    finally:
        await client.close()

    return all_findings

def show_source_summary(findings_data):
    import pandas as pd
    from collections import Counter

    if not findings_data:
        st.sidebar.info("No findings to summarize yet.")
        return

    source_counts = Counter(f.get("source", "Unknown") or "Unknown" for f in findings_data)
    summary_df = pd.DataFrame(source_counts.items(), columns=["Source", "Findings Count"]).sort_values(
        "Findings Count", ascending=False
    )

    st.sidebar.markdown("### 📊 Findings by Tool/Source")
    st.sidebar.dataframe(summary_df, use_container_width=True)
async def get_all_findings_summary(user_filters=None, max_pages=20, size=100):
    import pandas as pd
    from collections import Counter

    api_key = get_api_key()
    client = ArmorCodeClient(api_key)
    all_findings = []

    def simplify_finding(raw):
        return {
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", ""),
            "status": raw.get("status", ""),
            "source": raw.get("source", ""),
            "scanType": raw.get("scanType", []),
            "componentName": raw.get("componentName", ""),
            "componentVersion": raw.get("componentVersion", ""),
            "product": {"name": raw.get("product", {}).get("name", "")},
            "subProduct": {"name": raw.get("subProduct", {}).get("name", "")},
            "cve": raw.get("cve", []),
            "cvss": raw.get("cvss", {}),
            "findingCategory": raw.get("findingCategory") or raw.get("category", ""),
            "category": raw.get("category", "")
        }

    try:
        for page in range(max_pages):
            filters = {}
            if user_filters:
                filters.update(user_filters)

            payload = {
                "size": size,
                "page": page,
                "filters": filters,
                "filterOperations": {
                    "source": "OR",
                    "severity": "OR",
                    "scanType": "OR",
                    "status": "OR",
                    "environmentName": "OR"
                },
                "sortColumns": [{"property": "riskScore", "direction": "desc"}],
                "ticketStatusRequired": False,
                "ignoreMitigated": False,
                "ignoreDuplicate": False
            }

            if page == 0:
                with st.sidebar.expander("🧪 Active API Filters"):
                    st.json(payload["filters"])

            try:
                response = await client.post("/user/findings/", json=payload)
                batch = response.get("content", [])
                if not batch:
                    st.info(f"🔍 No results found on page {page}")
                    break

                simplified = [simplify_finding(f) for f in batch]
                all_findings.extend(simplified)

                if len(batch) < size:
                    break

            except Exception as e:
                st.warning(f"⚠️ Error fetching page {page + 1}: {e}")
                break

            await asyncio.sleep(0.2)

    finally:
        await client.close()

    # ✅ Show source breakdown
    if all_findings:
        source_counts = Counter(f.get("source", "Unknown") or "Unknown" for f in all_findings)
        summary_df = pd.DataFrame(source_counts.items(), columns=["Source", "Findings Count"]).sort_values(
            "Findings Count", ascending=False
        )

        st.sidebar.markdown("### 📊 Findings by Tool/Source")
        st.sidebar.dataframe(summary_df, use_container_width=True)
    else:
        st.sidebar.info("🛑 No findings to summarize.")

    return all_findings

# ------------ Fetch ALL Findings (All Pages) ------------- #
# ------------ Fetch ALL Findings (Safe) ------------- #
async def fetch_filters_and_findings(user_filters=None, page=0, size=50):
    api_key = get_api_key()
    client = ArmorCodeClient(api_key)
    try:
        filters = await client.post("/user/findings/findings-filters", json={
            "fields": ["environmentName", "status", "severity", "scanType"],
            "ignoreMitigated": None,
            "ignoreDuplicate": True
        })

        if "fields" not in filters:
            filters["fields"] = {}

        findings_payload = {
            "size": size,
            "page": page,
            "sortColumns": [{"property": "riskScore", "direction": "desc"}],
            "filters": {
                "status": ["TRIAGE", "OPEN", "CONFIRMED"],
                "severity": ["Critical", "High", "Medium"],
                "environmentName": ["Production"]
            },
            "filterOperations": {
                "source": "OR",       # ✅ Allow multiple sources
                "severity": "OR",     # ✅ Optional
                "scanType": "OR"      # ✅ Optional
            },
            "ticketStatusRequired": True,
            "ignoreMitigated": None,
            "ignoreDuplicate": True
        }

        if user_filters:
            findings_payload["filters"].update(user_filters)

        findings = await client.post("/user/findings/", json=findings_payload)
        return filters, findings

    finally:
        await client.close()

# ------------ Pagination Helper ------------- #
def paginate_findings(findings, page_size=50):
    total = len(findings)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = st.session_state.get("page", 0)
    start = page * page_size
    end = start + page_size
    return findings[start:end], total, total_pages
def safe_extract_cvss_fields(finding):
    cve = finding.get("cve", {})
    cvss = finding.get("cvss", {})

    # Normalize CVE
    if isinstance(cve, list):
        cve = cve[0] if cve else {}
    elif isinstance(cve, str):
        cve = {"id": cve}
    elif not isinstance(cve, dict):
        cve = {}

    # Normalize CVSS
    if not isinstance(cvss, dict):
        if isinstance(cve, dict):
            cvss = cve.get("cvss", {})
        if not isinstance(cvss, dict):
            cvss = {}

    return cve, cvss
def render_finding_row(finding):
    cve, cvss = safe_extract_cvss_fields(finding)
    return {
        "Title": finding.get("title", ""),
        "Component": finding.get("componentName", ""),
        "Version": finding.get("componentVersion", ""),
        "Severity": finding.get("severity", ""),
        "Environment": finding.get("environmentName", ""),
        "Status": finding.get("status", ""),
        "Source": finding.get("source", ""),
        "Published": cve.get("published", ""),
        "Description": finding.get("description", "")
    }

# ------------ Dashboard Page ------------- #
async def run_dashboard():
    st.markdown("### 📊 Dashboard View")

    # Sidebar filters
    st.sidebar.header("🧪 Filters")
    environment_filter = st.sidebar.multiselect("Environment", ["Production", "Staging", "Development"], default=["Production"])
    severity_filter = st.sidebar.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium"])
    show_desc = st.sidebar.checkbox("Show Description", True)

    user_filters = {
        "environmentName": environment_filter,
        "severity": severity_filter
    }

    findings = await fetch_all_findings(user_filters=user_filters, max_pages=5)
    if not findings:
        st.warning("⚠️ No findings found.")
        return

    # Pagination logic
    total = len(findings)
    page_size = st.session_state.page_size
    page = st.session_state.page
    start = page * page_size
    end = start + page_size
    current_page_data = findings[start:end]

    st.success(f"✅ Showing {len(current_page_data)} of {total} findings")

    # Display
    rows = []
    for f in current_page_data:
        row = {
            "Title": f.get("title", ""),
            "Component": f.get("componentName", ""),
            "Version": f.get("componentVersion", ""),
            "Severity": f.get("severity", ""),
            "Environment": f.get("environmentName", ""),
            "Status": f.get("status", ""),
            "Source": f.get("source", "")
        }
        if show_desc:
            row["Description"] = f.get("description", "")
        rows.append(row)

    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        if st.button("⬅️ Previous") and page > 0:
            st.session_state.page -= 1
            st.rerun()
    with col3:
        if st.button("Next ➡️") and (start + page_size) < total:
            st.session_state.page += 1
            st.rerun()
    with col2:
        st.markdown(f"<div style='text-align:center;'>Page {page + 1}</div>", unsafe_allow_html=True)

# ------------ Dedup Report ------------- #
def run_dedup_report():
    st.markdown("## 🧠 AI Deduplication Report")

    if "deduped_data" not in st.session_state:
        st.warning("No deduplication run yet.")
        return

    deduped = st.session_state.get("deduped_data", [])
    if isinstance(deduped, list) and deduped and isinstance(deduped[0], list):
        deduped = deduped[0]  # Flatten if nested

    removed = st.session_state.get("dedup_removed", 0)
    total = st.session_state.get("original_count", 0)
    kept = len(deduped)

    st.metric("📦 Total Findings Before", total)
    st.metric("✅ After Deduplication", kept)
    st.metric("🗑️ Duplicates Removed", removed)

    table_data = [render_finding_row(f) for f in deduped]
    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True)

    st.download_button(
        "📥 Download Deduplicated CSV",
        df.to_csv(index=False).encode("utf-8"),
        file_name="deduplicated_findings.csv",
        mime="text/csv"
    )

    if st.checkbox("🧾 Show Deduplication Explanation"):
        show_dedup_explanations()
# ------------ Dedup Explanation Viewer ------------- #
def show_dedup_explanations():
    explanations = st.session_state.get("dedup_explanations", [])

    if not explanations:
        st.info("No explanations to show. Run deduplication first.")
        return

    st.markdown("### 🧠 Deduplication Explanations")
    st.caption("Details of removed findings based on semantic and rule-based similarity.")

    df = pd.DataFrame(explanations)
    st.dataframe(df, use_container_width=True)

    st.download_button(
        label="📥 Download as CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="dedup_explanations.csv",
        mime="text/csv"
    )

# ------------ Dedup Report ------------- #
def run_dedup_report():
    st.markdown("## 🧠 AI Deduplication Report")

    if "deduped_data" not in st.session_state:
        st.warning("No deduplication run yet.")
        return

    removed = st.session_state.get("dedup_removed", 0)
    total = st.session_state.get("original_count", 0)
    kept = len(st.session_state.get("deduped_data", []))

    st.metric("📦 Total Findings Before", total)
    st.metric("✅ After Deduplication", kept)
    st.metric("🗑️ Duplicates Removed", removed)

    show_cvss = st.session_state.get("show_cvss", True)
    show_cisa = st.session_state.get("show_cisa", True)
    show_desc = st.session_state.get("show_desc", True)

    rows = []
    for f in st.session_state.deduped_data:
        row = {
            "Title": f.get("title", ""),
            "Component": f.get("componentName", ""),
            "Version": f.get("componentVersion", ""),
            "Severity": f.get("severity", ""),
            "Product": f.get("product", {}).get("name", ""),
            "Sub Product": f.get("subProduct", {}).get("name", ""),
            "Category": f.get("findingCategory") or f.get("category", "")
        }

        if show_cvss:
            row.update({
                "CVSS": f.get("cvssScore") or f.get("cvss", {}).get("baseScore", ""),
                "Exploitability": f.get("cvss", {}).get("exploitabilityScore", ""),
                "Impact": f.get("cvss", {}).get("impactScore", ""),
                "Overall Score": f.get("cvss", {}).get("score", ""),
            })

        if show_cisa:
            row["Published"] = f.get("cvss", {}).get("publishedDate") or f.get("cve", {}).get("published", "")
            row["Updated"] = f.get("cvss", {}).get("lastModifiedDate") or f.get("cve", {}).get("updated", "")

        if show_desc:
            row["Description"] = (
                f.get("description") or
                f.get("cvss", {}).get("description") or
                f.get("cve", {}).get("description") or
                f.get("cve", {}).get("summary") or ""
            )

        rows.append(row)

    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    # Export
    st.download_button("📥 Download CSV", pd.DataFrame(rows).to_csv(index=False).encode("utf-8"), "dedup_results.csv")

    if st.checkbox("🧾 Show Deduplication Explanation"):
        show_dedup_explanations()

# 2️⃣ --- FAISS-accelerated Deduplication ---
def faiss_deduplicate(findings, threshold=0.85):
    model = get_embedding_model()
    texts = [(f.get("title", "") or "") + " " + (f.get("description", "") or "") for f in findings]
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
    dim = embeddings.shape[1]

    index = faiss.IndexFlatIP(dim)
    normalized = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    index.add(normalized.astype('float32'))

    _, neighbors = index.search(normalized.astype('float32'), 10)
    seen = np.zeros(len(findings))
    deduped = []
    explanations = []

    for i in range(len(findings)):
        if seen[i]:
            continue
        deduped.append(findings[i])
        for j in neighbors[i][1:]:
            if j == i or seen[j]:
                continue
            sim = np.dot(normalized[i], normalized[j])
            if sim >= threshold:
                seen[j] = 1
                explanations.append({
                    "Duplicate Of": findings[i]["title"],
                    "Removed": findings[j]["title"],
                    "Similarity": round(sim, 3),
                    "Method": "FAISS cosine"
                })

    st.session_state["dedup_explanations"] = explanations
    return deduped

# 3️⃣ --- Smart Merge Suggestion Logic ---
def suggest_smart_merges(findings):
    st.markdown("### 🤖 Smart Merge Suggestions")
    suggestions = []
    grouped = defaultdict(list)

    for f in findings:
        cve = f.get("title", "").split(" - ")[0]
        key = (cve, f.get("componentVersion", ""))
        grouped[key].append(f)

    for (cve, version), items in grouped.items():
        if len(items) > 1:
            components = [i.get("componentName") or "Unknown" for i in items]
            suggestions.append({
                "CVE": cve,
                "Version": version,
                "Components": ", ".join(str(c) for c in set(components)),
                "Suggestion": "May be same vulnerability across components"
            })

    if suggestions:
        df = pd.DataFrame(suggestions)
        st.dataframe(df, use_container_width=True)
        st.download_button("📥 Download Smart Merges", df.to_csv(index=False).encode("utf-8"), "smart_merge_suggestions.csv")
    else:
        st.info("No smart merge suggestions found.")
async def load_sidebar_filters():
    user_filters = {}
    fallback = {
        "environmentName": ["Production", "Staging", "Development"],
        "status": ["TRIAGE", "OPEN", "CONFIRMED", "RESOLVED"],
        "severity": ["Critical", "High", "Medium", "Low"],
        "scanType": ["SAST", "DAST", "SCA"],
        "source": []
    }

    seen_fields = {
        "environmentName": set(),
        "status": set(),
        "severity": set(),
        "scanType": set(),
        "source": set()
    }

    api_key = get_api_key()
    client = ArmorCodeClient(api_key)

    try:
        page = 0
        while page < 5:  # Limiting discovery to 5 pages max for performance
            payload = {
                "size": 100,
                "page": page,
                "filters": {},
                "sortColumns": [{"property": "riskScore", "direction": "desc"}],
                "filterOperations": {},
                "ticketStatusRequired": False,
                "ignoreMitigated": None,
                "ignoreDuplicate": False
            }

            try:
                response = await client.post("/user/findings/", json=payload)
                findings = response.get("content", [])
                if not findings:
                    break

                for f in findings:
                    seen_fields["environmentName"].add(f.get("environmentName", ""))
                    seen_fields["status"].add(f.get("status", ""))
                    seen_fields["severity"].add(f.get("severity", ""))
                    if isinstance(f.get("scanType", []), list):
                        seen_fields["scanType"].update(f.get("scanType", []))
                    else:
                        seen_fields["scanType"].add(f.get("scanType", ""))
                    seen_fields["source"].add(f.get("source", ""))

                if len(findings) < 100:
                    break
                page += 1

            except Exception as e:
                st.warning(f"⚠️ Failed to fetch findings for filters: {e}")
                break

        # Normalize
        for key in seen_fields:
            seen_fields[key] = sorted(filter(None, seen_fields[key]))

        # Sidebar filters
        for field in ["environmentName", "status", "severity", "scanType", "source"]:
            options = seen_fields[field] or fallback[field]
            selected = st.sidebar.multiselect(
                label=field.title(),
                options=options,
                default=options[:2],
                key=f"{field}_filter"
            )
            if selected:
                user_filters[field] = selected

    finally:
        await client.close()

    return user_filters

async def discover_all_sources_from_findings(max_pages=10):
    api_key = get_api_key()
    client = ArmorCodeClient(api_key)
    all_sources = set()

    try:
        for page in range(max_pages):
            payload = {
                "size": 100,
                "page": page,
                "filters": {},
                "sortColumns": [{"property": "riskScore", "direction": "desc"}],
                "filterOperations": {},
                "ticketStatusRequired": False,
                "ignoreMitigated": None,
                "ignoreDuplicate": False
            }

            try:
                response = await client.post("/user/findings/", json=payload)

                if not response or "content" not in response:
                    st.warning(f"⚠️ No valid response on page {page}")
                    break

                findings = response.get("content", [])
                if not findings:
                    break

                for f in findings:
                    source = f.get("source", "")
                    if source:
                        all_sources.add(source)

                if len(findings) < 100:
                    break

            except Exception as e:
                st.warning(f"⚠️ Failed to fetch sources on page {page}: {e}")
                break

            await asyncio.sleep(0.2)

    finally:
        await client.close()

    return sorted(all_sources)
def extract_filter_options(findings):
    envs = set()
    statuses = set()
    severities = set()
    scan_types = set()
    sources = set()

    for f in findings:
        envs.add(f.get("environmentName", ""))
        statuses.add(f.get("status", ""))
        severities.add(f.get("severity", ""))
        
        scan_type = f.get("scanType", [])
        if isinstance(scan_type, list):
            scan_types.update(scan_type)
        else:
            scan_types.add(scan_type)
        
        sources.add(f.get("source", ""))

    return {
        "environmentName": sorted(filter(None, envs)),
        "status": sorted(filter(None, statuses)),
        "severity": sorted(filter(None, severities)),
        "scanType": sorted(filter(None, scan_types)),
        "source": sorted(filter(None, sources)),
    }
import pandas as pd

def run_deduplication(findings, threshold=0.85):
    st.markdown("## 🧠 AI Deduplication")

    # Trigger logic
    if st.button("🧠 Run Deduplication"):
        with st.spinner("Running AI deduplication..."):
            deduped = hybrid_deduplicate_findings(findings, threshold=threshold)
            st.session_state.deduped_data = deduped
            st.session_state.dedup_removed = len(findings) - len(deduped)
            findings = deduped
        st.success(f"✅ Deduplication complete! {st.session_state.dedup_removed} duplicates removed.")
    
    # Use deduped data if already in session
    elif "deduped_data" in st.session_state:
        findings = st.session_state.deduped_data
        st.info(f"🧠 Deduplication active — {st.session_state.dedup_removed} duplicates removed.")

    # Show explanation viewer
    if "dedup_explanations" in st.session_state:
        if st.checkbox("🧾 Show Deduplication Details"):
            explanations = st.session_state["dedup_explanations"]
            if explanations:
                st.markdown("### 🧠 Deduplication Explanations")
                df = pd.DataFrame(explanations)
                st.dataframe(df, use_container_width=True)

                st.download_button(
                    label="📥 Download Explanations CSV",
                    data=df.to_csv(index=False).encode("utf-8"),
                    file_name="dedup_explanations.csv",
                    mime="text/csv"
                )
            else:
                st.info("No explanations to show.")
    
    return st.session_state.get("deduped_data", findings)
async def run_deduplication_page():
    st.markdown("### 🧠 AI Deduplication")

    similarity_threshold = st.slider("Similarity Threshold", 0.7, 0.99, 0.85, step=0.01)

    findings = await fetch_all_findings(max_pages=5)
    if not findings:
        st.warning("⚠️ No findings available.")
        return

    findings = run_deduplication(findings, threshold=similarity_threshold)

    rows = [render_finding_row(f) for f in findings]
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    st.download_button("📥 Download Deduplicated CSV",
                       pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                       file_name="deduped_findings.csv")
async def run_smart_merge_page():
    st.markdown("### 🤖 Smart Merge Suggestions")

    findings = await fetch_all_findings(max_pages=5)
    if not findings:
        st.warning("⚠️ No findings available.")
        return

    suggest_smart_merges(findings)
async def run_group_by_cve_page():
    st.markdown("### 🧩 Group by Vulnerability ID")

    findings = await fetch_all_findings(max_pages=5)
    if not findings:
        st.warning("⚠️ No findings available.")
        return

    grouped = group_findings_by_cve(findings)

    data = [{
        "CVE / Title": cve_id,
        "Vendor": info["vendor"],
        "Components": ", ".join(info["components"])
    } for cve_id, info in grouped.items()]

    st.dataframe(pd.DataFrame(data), use_container_width=True)

# ------------ MAIN ------------- #
async def main():
    st.set_page_config(page_title="ArmorCode Dashboard", layout="wide")
    st.title("🛡️ ArmorCode Findings Dashboard")
async def main():
    st.set_page_config(page_title="ArmorCode Dashboard", layout="wide")
    st.title("🛡️ ArmorCode Findings Dashboard")

    page = st.sidebar.selectbox("📂 Select Page", [
        "Dashboard",
        "AI Deduplication",
        "Smart Merge Suggestions",
        "Group by Vulnerability ID"
    ])

    if "page" not in st.session_state:
        st.session_state.page = 0

    if page == "Dashboard":
        await run_dashboard()

    elif page == "AI Deduplication":
        await run_deduplication_page()

    elif page == "Smart Merge Suggestions":
        await run_smart_merge_page()

    elif page == "Group by Vulnerability ID":
        await run_group_by_cve_page()

    # Sidebar Filters
    st.sidebar.header("🧪 Filters")
    environment_filter = st.sidebar.multiselect("Environment", ["Production", "Staging", "Development"], default=["Production", "Staging"])
    severity_filter = st.sidebar.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium"])

    st.sidebar.header("🧮 Display Options")
    show_desc = st.sidebar.checkbox("Show Description", True)

    st.sidebar.header("🧠 AI Deduplication")
    enable_dedup = st.sidebar.checkbox("Enable Deduplication", value=True)
    similarity_threshold = st.sidebar.slider("Similarity Threshold", 0.7, 0.99, 0.85, step=0.01)

    user_filters = {
        "environmentName": environment_filter,
        "severity": severity_filter
    }

    # Page State
    if "page" not in st.session_state:
        st.session_state.page = 0
    if "page_size" not in st.session_state:
        st.session_state.page_size = 50

    try:
        with st.spinner("Fetching all findings..."):
            findings = await fetch_all_findings(user_filters=user_filters, max_pages=5)
    except Exception as e:
        st.error(f"❌ Error fetching data: {e}")
        return

    if not findings:
        st.warning("⚠️ No findings returned.")
        return

    # ✅ Run deduplication if enabled
    if enable_dedup:
        findings = run_deduplication(findings, threshold=similarity_threshold)

    total = len(findings)
    page_size = st.session_state.page_size
    total_pages = max(1, (total + page_size - 1) // page_size)

    # Handle Pagination
    page = st.session_state.page
    start = page * page_size
    end = start + page_size
    current_page_data = findings[start:end]

    st.success(f"✅ Loaded {total} total findings | Page {page + 1} of {total_pages}")

    # Show Page Data
    display_rows = []
    for f in current_page_data:
        row = {
            "Title": f.get("title", ""),
            "Component": f.get("componentName", ""),
            "Version": f.get("componentVersion", ""),
            "Severity": f.get("severity", ""),
            "Environment": f.get("environmentName", ""),
            "Status": f.get("status", ""),
            "Source": f.get("source", "")
        }
        if show_desc:
            row["Description"] = f.get("description", "")
        display_rows.append(row)

    st.dataframe(pd.DataFrame(display_rows), use_container_width=True)

    # Navigation Buttons
    col1, col2, col3 = st.columns([1, 2, 1])
    with col1:
        if st.button("⬅️ Previous") and st.session_state.page > 0:
            st.session_state.page -= 1
            st.rerun()

    with col3:
        if st.button("Next ➡️") and st.session_state.page < total_pages - 1:
            st.session_state.page += 1
            st.rerun()

    with col2:
        st.markdown(f"<div style='text-align:center;'>Page {page + 1} of {total_pages}</div>", unsafe_allow_html=True)

# ------------ ENTRY POINT ------------ #

async def entry():
    await main()

# Streamlit already has an event loop running, so we use this approach
if __name__ == "__main__" or "streamlit" in __name__:
    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.ensure_future(entry())  # Schedules main if loop already running
    else:
        loop.run_until_complete(entry())
