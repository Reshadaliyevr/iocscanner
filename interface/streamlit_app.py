import streamlit as st
from engine.processor import IOCProcessor
from clients.streamlit_formatter import render_ip_summary, render_url_summary, render_file_summary 
import logging
from logging.handlers import RotatingFileHandler
import os


st.set_page_config(page_title="IOCScanner", layout="wide")
st.title("🛡️ IOCScanner – Multi-Source Threat Intelligence Automation")

tabs = st.tabs(["📁 File Upload", "🌐 URL Check", "🔢 IP Scan"])


# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Thread-level and scan-level logging
scan_log = logging.getLogger("iocscanner.processor")
scan_log.setLevel(logging.INFO)
if not scan_log.hasHandlers():
    scan_handler = RotatingFileHandler("logs/iocscanner_threads.log", maxBytes=1_000_000, backupCount=3)
    scan_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    scan_log.addHandler(scan_handler)

# Retry-specific logging (tenacity)
retry_log = logging.getLogger("iocscanner.retry")
retry_log.setLevel(logging.WARNING)
if not retry_log.hasHandlers():
    retry_handler = RotatingFileHandler("logs/retry.log", maxBytes=1_000_000, backupCount=3)
    retry_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    retry_log.addHandler(retry_handler)


processor = IOCProcessor()

with tabs[0]:  # File Tab
    st.subheader("📁 Upload suspicious file(s)")

    files = st.file_uploader("Select one or more files", type=None, accept_multiple_files=True)
    use_upload = st.checkbox("Upload file to VirusTotal (instead of hash-only scan)", value=False)

    if files and st.button("🚀 Scan Files"):
        for file in files:
            st.info(f"Scanning `{file.name}` {'with upload' if use_upload else '(hash-only)'}...")
            result = processor.scan_file(file, upload=use_upload)
            st.subheader(f"🧪 Result: {file.name}")
            render_file_summary(result)


with tabs[1]:  # URL Tab
    st.subheader("🌐 Scan URLs – Paste or Upload")

    url_mode = st.radio("Input method:", ["Paste URLs manually", "Upload file"], horizontal=True, key="url_mode")
    url_text = ""
    url_file = None

    if url_mode == "Paste URLs manually":
        url_text = st.text_area("Enter one URL per line", height=150, key="url_input")
    else:
        url_file = st.file_uploader("Upload a .txt or .csv file with URLs", type=["txt", "csv"], key="url_file")

    if st.button("🚀 Scan URLs"):
        urls = set()

        # Parse textarea input
        if url_text:
            urls.update([u.strip() for u in url_text.splitlines() if u.strip()])

        # Parse uploaded file
        if url_file:
            content = url_file.read().decode("utf-8")
            urls.update([line.strip() for line in content.splitlines() if line.strip()])

        urls = list(urls)
        if not urls:
            st.warning("No valid URLs found.")
        else:
            st.success(f"Scanning {len(urls)} unique URL(s)...")
            results = processor.scan_bulk(urls, target_type="url", max_workers=5)

            for r in results:
                render_url_summary(r)


with tabs[2]:  # IP Tab
    st.subheader("🔢 Scan IPs – Paste or Upload")

    input_mode = st.radio("Input method:", ["Paste IPs manually", "Upload file"], horizontal=True)
    ip_text = ""
    ip_file = None

    if input_mode == "Paste IPs manually":
        ip_text = st.text_area("Enter one IP per line", height=150)
    else:
        ip_file = st.file_uploader("Upload a .txt or .csv file with IPs", type=["txt", "csv"])

    if st.button("🚀 Scan IPs"):
        ips = set()

        # Parse pasted input
        if ip_text:
            ips.update([ip.strip() for ip in ip_text.splitlines() if ip.strip()])

        # Parse uploaded file
        if ip_file:
            content = ip_file.read().decode("utf-8")
            ips.update([line.strip() for line in content.splitlines() if line.strip()])

        ips = list(ips)
        if not ips:
            st.warning("No valid IPs found.")
        else:
            st.success(f"Scanning {len(ips)} unique IP(s)...")
            results = processor.scan_bulk(ips, target_type="ip", max_workers=5)

            for r in results:
                render_ip_summary(r)  # ✅ streamlit_formatter
