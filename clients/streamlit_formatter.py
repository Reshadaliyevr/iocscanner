import streamlit as st
import pandas as pd

def render_ip_summary(data):
    st.subheader("🧠 IP Scan Summary")
    reasons = []
    verdict = "safe"

    vt = data.get("virustotal", {})
    stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    if stats:
        st.markdown("**VirusTotal Analysis:**")
        st.table(pd.DataFrame(stats.items(), columns=["Category", "Count"]))
        if stats.get("malicious", 0) >= 1:
            reasons.append(f"Flagged as malicious by {stats['malicious']} VT engines")
            verdict = "suspicious"

    ab = data.get("abuseipdb", {}).get("data", {})
    if ab:
        abuse_score = ab.get("abuseConfidenceScore", 0)
        total_reports = ab.get("totalReports", 0)
        st.markdown(f"**AbuseIPDB Score:** `{abuse_score}/100`, Reports: `{total_reports}`")
        if abuse_score >= 70:
            reasons.append(f"AbuseIPDB confidence score is high: {abuse_score}")
            verdict = "suspicious"

    if not vt and not ab:
        st.warning("🟡 Inconclusive — no data returned")
        return

    _render_final_verdict(verdict, reasons)
    _render_json(data)

def render_url_summary(data):
    st.subheader("🔗 URL Scan Summary")
    reasons = []
    verdict = "safe"

    vt = data.get("virustotal", {})
    stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    if stats:
        st.markdown("**VirusTotal Analysis:**")
        st.table(pd.DataFrame(stats.items(), columns=["Category", "Count"]))
        if stats.get("malicious", 0) >= 1:
            reasons.append(f"Flagged as malicious by {stats['malicious']} VT engines")
            verdict = "suspicious"

    urlscan = data.get("urlscan", {})
    url_verdict = urlscan.get("verdicts", {}).get("overall")
    if url_verdict:
        st.markdown(f"**URLScan Verdict:** `{url_verdict}`")
        if url_verdict == "malicious":
            reasons.append("URLScan flagged this as malicious")
            verdict = "suspicious"

    if not vt and not urlscan:
        st.warning("🟡 Inconclusive — no data returned")
        return

    _render_final_verdict(verdict, reasons)
    _render_json(data)

def render_file_summary(data):
    st.subheader("📁 File Scan Summary")
    reasons = []
    verdict = "safe"

    vt = data.get("virustotal", {})
    vt_data = vt.get("data", {})
    vt_type = vt_data.get("type", "")
    attributes = vt_data.get("attributes", {})

    malicious_count = 0

    if vt_type == "file":
        stats = attributes.get("last_analysis_stats", {})
        if stats:
            st.markdown("**VirusTotal Analysis:**")
            st.table(pd.DataFrame(stats.items(), columns=["Category", "Count"]))
            malicious_count = stats.get("malicious", 0)
    elif vt_type == "analysis":
        engine_results = attributes.get("results", {})
        for engine, result in engine_results.items():
            if result.get("category") == "malicious":
                malicious_count += 1
        if malicious_count:
            st.markdown(f"**VirusTotal:** Flagged by `{malicious_count}` engines")

    if malicious_count >= 1:
        reasons.append(f"VirusTotal: {malicious_count} engines flagged as malicious")
        verdict = "suspicious"

    # HYBRID ANALYSIS INTEGRATION
    hybrid = data.get("hybrid_analysis", {})
    if isinstance(hybrid, dict):
        score = hybrid.get("threat_score")
        tags = hybrid.get("tags", [])
        env = hybrid.get("environment_description", "N/A")

        if score:
            st.markdown(f"**Hybrid Threat Score:** `{score}`")
            if score > 70:
                reasons.append(f"HybridAnalysis threat score is high: {score}")
                verdict = "suspicious"

        if tags:
            st.markdown(f"**Hybrid Tags:** {', '.join(tags)}")

        st.markdown(f"**Environment:** `{env}`")

    if not vt and not hybrid:
        st.warning("🟡 Inconclusive — no threat data returned")
        return

    _render_final_verdict(verdict, reasons)
    _render_json(data)



def _render_final_verdict(verdict, reasons):
    if verdict == "suspicious":
        st.error("⚠️ Verdict: Suspicious\n" + "\n".join(f"- {r}" for r in reasons))
    else:
        st.success("✅ Verdict: Safe")

def _render_json(data):
    with st.expander("Show raw JSON"):
        st.json(data)