import streamlit as st
from engine.processor import IOCProcessor
from clients.streamlit_formatter import render_ip_summary, render_url_summary, render_file_summary 
from clients.firewall_blocker import FirewallBlocker
from clients.snort_generator import SnortRuleGenerator
from clients.wazuh_writer import WazuhRuleWriter
import logging
from logging.handlers import RotatingFileHandler
import os
import socket

st.set_page_config(page_title="IOCScanner", layout="wide")
st.title("🛡️ IOCScanner – Multi-Source Threat Intelligence Automation")

# Initialize rule generators
@st.cache_resource
def init_rule_generators():
    return {
        'firewall': FirewallBlocker(),
        'snort': SnortRuleGenerator(),
        'wazuh': WazuhRuleWriter()
    }

rule_generators = init_rule_generators()

# Sidebar for rule generation settings
st.sidebar.title("🔧 Auto-Response Settings")
auto_block_enabled = st.sidebar.checkbox("Enable Automatic Firewall Blocking", value=False)
auto_snort_enabled = st.sidebar.checkbox("Generate Snort Rules", value=True)
auto_wazuh_enabled = st.sidebar.checkbox("Generate Wazuh Rules", value=True)

if auto_block_enabled:
    st.sidebar.warning("⚠️ Firewall blocking requires admin privileges!")

tabs = st.tabs(["📁 File Upload", "🌐 URL Check", "🔢 IP Scan", "📋 Generated Rules"])

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)
os.makedirs("generated_rules", exist_ok=True)

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

def safe_url_to_ip_resolution(url):
    """Safely resolve URL to IP with proper error handling"""
    try:
        # Clean URL - remove protocol if present
        clean_url = url.replace('http://', '').replace('https://', '').replace('www.', '')
        
        # Extract domain from URL (remove path)
        if '/' in clean_url:
            domain = clean_url.split('/')[0]
        else:
            domain = clean_url
            
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Resolve to IP
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"error: Could not resolve {url} - {str(e)}"

def handle_malicious_detection(result, target_type, target_value):
    """
    Handle automatic rule generation when malicious content is detected.
    """
    
    # Initialize session state for generated rules if not exists
    if 'generated_rules' not in st.session_state:
        st.session_state.generated_rules = []
    
    is_malicious = False
    threat_details = []
    
    # Check based on target type and your actual detection logic
    if target_type == "ip":
        # VirusTotal check
        vt = result.get("virustotal", {})
        if isinstance(vt, dict):
            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats and stats.get("malicious", 0) >= 1:
                is_malicious = True
                threat_details.append(f"VirusTotal: {stats['malicious']} engines flagged as malicious")
        
        # AbuseIPDB check
        ab = result.get("abuseipdb", {})
        if isinstance(ab, dict):
            ab_data = ab.get("data", {})
            if ab_data:
                abuse_score = ab_data.get("abuseConfidenceScore", 0)
                if abuse_score >= 70:
                    is_malicious = True
                    threat_details.append(f"AbuseIPDB confidence score: {abuse_score}/100")
    
    elif target_type == "url":
        # VirusTotal check
        vt = result.get("virustotal", {})
        if isinstance(vt, dict):
            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats and stats.get("malicious", 0) >= 1:
                is_malicious = True
                threat_details.append(f"VirusTotal: {stats['malicious']} engines flagged as malicious")
        
        # URLScan check
        urlscan = result.get("urlscan", {})
        if isinstance(urlscan, dict):
            url_verdict = urlscan.get("verdicts", {}).get("overall")
            if url_verdict == "malicious":
                is_malicious = True
                threat_details.append("URLScan flagged as malicious")
    
    elif target_type == "file":
        # VirusTotal check
        vt = result.get("virustotal", {})
        if isinstance(vt, dict):
            vt_data = vt.get("data", {})
            vt_type = vt_data.get("type", "")
            attributes = vt_data.get("attributes", {})
            
            malicious_count = 0
            
            if vt_type == "file":
                stats = attributes.get("last_analysis_stats", {})
                if stats:
                    malicious_count = stats.get("malicious", 0)
            elif vt_type == "analysis":
                engine_results = attributes.get("results", {})
                for engine, engine_result in engine_results.items():
                    if engine_result.get("category") == "malicious":
                        malicious_count += 1
            
            if malicious_count >= 1:
                is_malicious = True
                threat_details.append(f"VirusTotal: {malicious_count} engines flagged as malicious")
        
        # Hybrid Analysis check
        hybrid = result.get("hybrid_analysis", {})
        if isinstance(hybrid, dict):
            score = hybrid.get("threat_score")
            if score and score > 70:
                is_malicious = True
                threat_details.append(f"Hybrid Analysis threat score: {score}")
    
    if is_malicious:
        # Display threat details with clear target identification
        threat_summary = " | ".join(threat_details)
        st.error(f"🚨 **MALICIOUS {target_type.upper()} DETECTED: `{target_value}`**")
        st.error(f"**Threat Details:** {threat_summary}")
        
        # Generate rules based on target type
        if target_type == "ip":
            # Firewall blocking
            if auto_block_enabled:
                with st.spinner(f"Blocking malicious IP {target_value} via firewall..."):
                    try:
                        block_result = rule_generators['firewall'].block_ip(target_value)
                        st.info(f"🔥 **Firewall Block Result:** {block_result}")
                        st.session_state.generated_rules.append({
                            'timestamp': st.session_state.get('current_time', 'Unknown'),
                            'type': 'Firewall Block',
                            'target': target_value,
                            'result': block_result,
                            'threat_details': threat_summary
                        })
                    except Exception as e:
                        st.error(f"❌ Failed to block IP via firewall: {e}")
            
            # Snort rule generation
            if auto_snort_enabled:
                try:
                    with st.spinner(f"Generating Snort rule for malicious IP {target_value}..."):
                        snort_file = rule_generators['snort'].generate_and_save_ip_rule(target_value)
                        st.success(f"📝 **Snort rule generated:** `{os.path.basename(snort_file)}`")
                        st.session_state.generated_rules.append({
                            'timestamp': st.session_state.get('current_time', 'Unknown'),
                            'type': 'Snort Rule',
                            'target': target_value,
                            'file': snort_file,
                            'threat_details': threat_summary
                        })
                except Exception as e:
                    st.error(f"❌ Failed to generate Snort rule for {target_value}: {e}")
        
        elif target_type == "url":
            # For URLs, extract IP and block it
            if auto_block_enabled or auto_snort_enabled:
                with st.spinner(f"Resolving malicious URL {target_value} to IP..."):
                    ip = safe_url_to_ip_resolution(target_value)
                    
                if not ip.startswith("error"):
                    st.info(f"🔍 **Resolved {target_value} → {ip}**")
                    
                    if auto_block_enabled:
                        try:
                            block_result = rule_generators['firewall'].block_ip(ip)
                            st.info(f"🔥 **Firewall Block (URL→IP):** {block_result}")
                            st.session_state.generated_rules.append({
                                'timestamp': st.session_state.get('current_time', 'Unknown'),
                                'type': 'Firewall Block (URL)',
                                'target': f"{target_value} → {ip}",
                                'result': block_result,
                                'threat_details': threat_summary
                            })
                        except Exception as e:
                            st.error(f"❌ Failed to block resolved IP {ip}: {e}")
                    
                    # Snort rule for the resolved IP
                    if auto_snort_enabled:
                        try:
                            snort_file = rule_generators['snort'].generate_and_save_ip_rule(ip)
                            st.success(f"📝 **Snort rule generated for resolved IP:** `{os.path.basename(snort_file)}`")
                            st.session_state.generated_rules.append({
                                'timestamp': st.session_state.get('current_time', 'Unknown'),
                                'type': 'Snort Rule (URL)',
                                'target': f"{target_value} → {ip}",
                                'file': snort_file,
                                'threat_details': threat_summary
                            })
                        except Exception as e:
                            st.error(f"❌ Failed to generate Snort rule for resolved IP {ip}: {e}")
                else:
                    st.warning(f"⚠️ {ip}")
        
        elif target_type == "file":
            # For files, generate Wazuh rules based on file hash
            sha256 = result.get('sha256')
            if auto_wazuh_enabled and sha256:
                try:
                    with st.spinner(f"Generating Wazuh rule for malicious file {target_value}..."):
                        wazuh_file = rule_generators['wazuh'].create_rule(
                            sha256, 
                            f"Malicious file detected: {target_value}"
                        )
                        st.success(f"📝 **Wazuh rule generated:** `{os.path.basename(wazuh_file)}`")
                        st.session_state.generated_rules.append({
                            'timestamp': st.session_state.get('current_time', 'Unknown'),
                            'type': 'Wazuh Rule',
                            'target': f"{target_value} (SHA256: {sha256[:16]}...)",
                            'file': wazuh_file,
                            'threat_details': threat_summary
                        })
                except Exception as e:
                    st.error(f"❌ Failed to generate Wazuh rule for {target_value}: {e}")
            elif auto_wazuh_enabled:
                st.warning(f"⚠️ Cannot generate Wazuh rule for {target_value}: SHA256 hash not available")
    
    else:
        st.success(f"✅ **{target_type.upper()} appears safe:** `{target_value}`")

with tabs[0]:  # File Tab
    st.subheader("📁 Upload suspicious file(s)")

    files = st.file_uploader("Select one or more files", type=None, accept_multiple_files=True)
    use_upload = st.checkbox("Upload file to VirusTotal (instead of hash-only scan)", value=False)

    if files and st.button("🚀 Scan Files"):
        import datetime
        st.session_state.current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for file in files:
            st.info(f"🔍 Scanning `{file.name}` {'with upload' if use_upload else '(hash-only)'}...")
            
            try:
                result = processor.scan_file(file, upload=use_upload)
                st.subheader(f"🧪 Result: {file.name}")
                render_file_summary(result)
                
                # Handle automatic rule generation
                handle_malicious_detection(result, "file", file.name)
                
            except Exception as e:
                st.error(f"❌ Failed to scan {file.name}: {e}")
            
            st.divider()

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
        import datetime
        st.session_state.current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        urls = set()

        # Parse textarea input
        if url_text:
            urls.update([u.strip() for u in url_text.splitlines() if u.strip()])

        # Parse uploaded file
        if url_file:
            try:
                content = url_file.read().decode("utf-8")
                urls.update([line.strip() for line in content.splitlines() if line.strip()])
            except Exception as e:
                st.error(f"❌ Failed to read uploaded file: {e}")

        urls = list(urls)
        if not urls:
            st.warning("No valid URLs found.")
        else:
            st.success(f"🔍 Scanning {len(urls)} unique URL(s)...")
            
            try:
                results = processor.scan_bulk(urls, target_type="url", max_workers=5)

                for i, result in enumerate(results):
                    current_url = urls[i] if i < len(urls) else "Unknown URL"
                    
                    # Get the target URL from result if available
                    if isinstance(result, dict) and 'target' in result:
                        current_url = result['target']
                    
                    st.subheader(f"🧪 Result: {current_url}")
                    render_url_summary(result)
                    
                    # Handle automatic rule generation
                    handle_malicious_detection(result, "url", current_url)
                    st.divider()
                    
            except Exception as e:
                st.error(f"❌ Failed to scan URLs: {e}")

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
        import datetime
        st.session_state.current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        ips = set()

        # Parse pasted input
        if ip_text:
            ips.update([ip.strip() for ip in ip_text.splitlines() if ip.strip()])

        # Parse uploaded file
        if ip_file:
            try:
                content = ip_file.read().decode("utf-8")
                ips.update([line.strip() for line in content.splitlines() if line.strip()])
            except Exception as e:
                st.error(f"❌ Failed to read uploaded file: {e}")

        ips = list(ips)
        if not ips:
            st.warning("No valid IPs found.")
        else:
            st.success(f"🔍 Scanning {len(ips)} unique IP(s)...")
            
            try:
                results = processor.scan_bulk(ips, target_type="ip", max_workers=5)

                for i, result in enumerate(results):
                    current_ip = ips[i] if i < len(ips) else "Unknown IP"
                    
                    # Get the target IP from result if available
                    if isinstance(result, dict) and 'target' in result:
                        current_ip = result['target']
                    
                    st.subheader(f"🧪 Result: {current_ip}")
                    render_ip_summary(result)
                    
                    # Handle automatic rule generation
                    handle_malicious_detection(result, "ip", current_ip)
                    st.divider()
                    
            except Exception as e:
                st.error(f"❌ Failed to scan IPs: {e}")

with tabs[3]:  # Generated Rules Tab
    st.subheader("📋 Generated Security Rules")
    
    if 'generated_rules' in st.session_state and st.session_state.generated_rules:
        st.success(f"✅ Total rules generated: **{len(st.session_state.generated_rules)}**")
        
        # Display rules in a table format
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🗑️ Clear All Rules"):
                st.session_state.generated_rules = []
                st.success("All generated rules cleared!")
                st.rerun()
        
        for i, rule in enumerate(reversed(st.session_state.generated_rules)):
            with st.expander(f"🔒 Rule #{len(st.session_state.generated_rules)-i}: {rule['type']} - {rule.get('target', 'Unknown')[:50]}..."):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**🕐 Timestamp:** {rule['timestamp']}")
                    st.write(f"**📋 Type:** {rule['type']}")
                    st.write(f"**🎯 Target:** {rule.get('target', 'Unknown')}")
                    if 'threat_details' in rule:
                        st.write(f"**⚠️ Threat Details:** {rule['threat_details']}")
                
                with col2:
                    if 'result' in rule:
                        if "✅" in str(rule['result']):
                            st.success("✅ Success")
                        elif "❌" in str(rule['result']) or "⚠️" in str(rule['result']):
                            st.error("❌ Failed")
                        else:
                            st.info("ℹ️ Info")
                
                if 'file' in rule:
                    st.write(f"**📁 File:** `{rule['file']}`")
                    # Try to display file contents
                    try:
                        with open(rule['file'], 'r') as f:
                            content = f.read()
                            if len(content) > 1000:
                                st.code(content[:1000] + "\n...[truncated]", language='xml' if 'wazuh' in rule['type'].lower() else 'text')
                            else:
                                st.code(content, language='xml' if 'wazuh' in rule['type'].lower() else 'text')
                    except Exception as e:
                        st.write(f"❌ Could not display file contents: {e}")
                
                if 'result' in rule:
                    st.write(f"**📊 Result:** {rule['result']}")
        
        # Summary statistics
        st.divider()
        rule_types = {}
        for rule in st.session_state.generated_rules:
            rule_type = rule['type']
            rule_types[rule_type] = rule_types.get(rule_type, 0) + 1
        
        st.subheader("📊 Rule Generation Summary")
        if rule_types:
            cols = st.columns(len(rule_types))
            for i, (rule_type, count) in enumerate(rule_types.items()):
                with cols[i]:
                    st.metric(rule_type, count)
        
    else:
        st.info("No rules have been generated yet. Scan some malicious content to see automatic rule generation in action!")
        st.write("""
        **How it works:**
        - 🔥 **Firewall Blocking**: Automatically blocks malicious IPs using system firewall
        - 📝 **Snort Rules**: Generates detection rules for network monitoring  
        - 🛡️ **Wazuh Rules**: Creates file hash detection rules for SIEM
        
        **Detection Thresholds:**
        - **IPs**: VirusTotal ≥1 detection OR AbuseIPDB ≥70% confidence
        - **URLs**: VirusTotal ≥1 detection OR URLScan flagged as malicious
        - **Files**: VirusTotal ≥1 detection OR Hybrid Analysis score >70
        
        Enable the features you want in the sidebar, then scan suspicious content!
        """)
        
        # Clear rules button (even when no rules exist)
        if st.button("🗑️ Clear All Generated Rules"):
            st.session_state.generated_rules = []
            st.success("All generated rules cleared!")
            st.rerun()