# 🛡️ IOCScanner – Multi-Source Threat Intelligence Automation

IOCScanner is a Streamlit-based security automation platform for scanning files, IPs, and URLs against multiple threat intelligence providers including:

- ✅ VirusTotal
- 🌐 URLScan
- 🚨 AbuseIPDB
- 🔍 Hybrid Analysis

This tool is designed for **SOC Tier 1+ analysts**, **incident responders**, and **cybersecurity researchers** who want a reliable and extensible interface for detecting malicious indicators across multiple sources.

---

## 🔧 Features

- 🎛️ **Streamlit Web UI** – upload or paste IOCs for scanning
- 🚀 **Multithreading** – optimized for bulk scans with ThreadPoolExecutor
- ⏳ **API Rate Monitoring + Queuing** – built-in token bucket logic using threading
- 📦 **Modular Design** – independent clients for VirusTotal, Hybrid Analysis, etc.
- 📊 **Formatted Output** – readable summaries, risk verdicts (safe, suspicious)
- 📁 **Raw JSON Viewer** – show complete API results for validation
- 📈 **Snort & Wazuh Integration** – generate security rules from scan results
- 🧪 **Real Unit Tests** – run actual scans with live keys and track logs

---

## 🚀 Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/iocscanner.git
cd iocscanner
```

2. Install dependecies:
```bash
pip install -r requirements.txt
```

3. Set up your .env file:
```bash
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
URLSCAN_API_KEY=your_urlscan_key
HYBRID_API_KEY=your_hybrid_key
```

4. Set path to the main directory and run the app:
```bash
set PYTHONPATH=.
python -m streamlit run interface/streamlit_app.py
```

🖼️ UI Overview
📁 File Upload: Scan file hashes or upload directly to VirusTotal.

🌐 URL Tab: Input manually or upload a file with multiple URLs.

🔢 IP Tab: Scan one or more IPs, either by pasting or uploading.

🧪 Running Unit Tests
```bash
python -m pytest -v tests/ --capture=tee-sys
```
✅ All test cases are real, not mocked. EICAR test file is used to simulate malware detection. So it is suggested to turn of your antivirus in order to create EICAR file successfully.

🗂️ Directory Structure
```bash
├── clients/
│   ├── abuseipdb.py
│   ├── firewall_blocker.py
│   ├── formatter.py
│   ├── hybrid.py
│   ├── scanner.py
│   ├── snort_generator.py
│   ├── streamlit_formatter.py
│   ├── urlscan.py
│   ├── virustotal.py
│   └── wazuh_writer.py
│
├── engine/
│   ├── api_monitor.py
│   ├── api_rate_limiter.py
│   ├── monitor.py
│   ├── processor.py
│   └── retry_policy.py
│
├── interface/
│   └── streamlit_app.py
│
├── logs/
│   ├── iocscanner_threads.log
│   └── retry.log
│
├── tests/
│   ├── conftest.py
│   ├── test_bulk_scanning.py
│   ├── test_file_upload_scan.py
│   ├── test_hybrid_analysis_live.py
│   ├── test_path_handling.py
│   └── test_virustotal_live.py
│
├── .env
├── LICENSE
├── main.py
└── requirements.txt
```

📋 Example Output
IP Scan Summary
```bash
- VirusTotal flagged as malicious by 3 engines
- AbuseIPDB confidence score 80
⚠️ Final Verdict: SUSPICIOUS
```


