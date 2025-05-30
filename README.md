
# 🛡️ IOCScanner - Automated Threat Intelligence & Defense Toolkit

## Overview

**IOCScanner** is a full-featured, modular threat intelligence automation tool designed for Blue Team operations. It scans Indicators of Compromise (IOCs) such as IPs, URLs, and file hashes across multiple threat intel sources. Based on detection results, it can:

- Generate **Snort** and **Wazuh** rules dynamically
- Automatically **block malicious IPs** via firewall
- Present results in a clean **Streamlit web interface**
- Respect **API rate limits** with built-in queuing and backoff
- Support **unit testing** with real API endpoints and logs

---

## 🌐 Features

### 🔍 IOC Scanning
- IPs: VirusTotal + AbuseIPDB
- URLs: VirusTotal + URLScan.io
- Files/Hashes: VirusTotal + Hybrid Analysis

### 📜 Rule Generation
- **Snort rules** (based on detection type and threat level)
- **Wazuh rules** (for endpoint detection and response)
- Auto-blocking via firewall integration

### 🧠 Automation
- Rate-limiting and retry logic with queue
- Bulk IOC scanning using multi-threaded workers
- Environment variable support with `.env`

### 📊 Interface
- Simple web GUI using **Streamlit**
- Separate summary views for each IOC type

---

## 📁 Project Structure

```
.
├── clients/                 # API wrappers, logic for VT, HA, AbuseIPDB, etc.
├── engine/                  # Core processing engine (scanner logic, decorators)
├── interface/               # Streamlit UI
├── logs/                    # Log files for debugging and audit
├── snort_rules/             # Generated Snort rules
├── wazuh_rules/             # Generated Wazuh rule XMLs
├── tests/                   # Pytest-based test suite (live and offline)
├── .env                     # Store API keys and config variables
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation
```

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.9+
- API keys for:
  - VirusTotal
  - Hybrid Analysis
  - AbuseIPDB
  - URLScan

### ⚙️ Setup

```bash
git clone https://github.com/yourname/iocscanner.git
cd iocscanner
pip install -r requirements.txt
cp .env.example .env  # then fill your API keys
```

### ▶️ Run the Streamlit App

```bash
set PYTHONPATH=.
python -m streamlit run interface/streamlit_app.py
```

### 🧪 Run Tests

```bash
pytest tests/
```

---

## 🛠️ Technologies Used

- `streamlit` — frontend GUI
- `requests` — HTTP API communication
- `tenacity` — retry + backoff
- `pandas` — structured data display
- `pytest` — test framework
- `rich` — optional CLI formatting
