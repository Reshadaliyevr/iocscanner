from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def render_summary(verdict: str, reasons: list):
    """Render a final verdict panel"""
    emoji = "✅" if verdict == "safe" else ("⚠️" if verdict == "suspicious" else "❓")
    title = f"{emoji} Final Verdict: {verdict.upper()}"
    body = "\n".join([f"- {reason}" for reason in reasons])
    console.print(Panel(body, title=title, style="bold cyan", box=box.ROUNDED))

def format_ip_result(data):
    console.rule("[bold green]IP Scan Summary")
    reasons = []

    vt = data.get("virustotal", {})
    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    vt_malicious = vt_stats.get("malicious", 0)
    
    table = Table(title="VirusTotal", box=box.SIMPLE)
    table.add_column("Category")
    table.add_column("Count")
    for k, v in vt_stats.items():
        table.add_row(k, str(v))
    console.print(table)
    if vt_malicious >= 1:
        reasons.append(f"VirusTotal flagged as malicious by {vt_malicious} engines")

    ab = data.get("abuseipdb", {}).get("data", {})
    abuse_score = ab.get("abuseConfidenceScore", 0)
    total_reports = ab.get("totalReports", 0)
    console.print(f"[bold yellow]AbuseIPDB Score: {abuse_score}/100, Reports: {total_reports}")
    if abuse_score >= 70:
        reasons.append(f"AbuseIPDB confidence score {abuse_score}")

    if reasons:
        render_summary("suspicious", reasons)
    elif not vt and not ab:
        render_summary("inconclusive", ["No data from any source."])
    else:
        render_summary("safe", ["No major risk indicators found."])

def format_url_result(data):
    console.rule("[bold blue]URL Scan Summary")
    reasons = []

    vt = data.get("virustotal", {})
    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    vt_malicious = vt_stats.get("malicious", 0)

    table = Table(title="VirusTotal", box=box.SIMPLE)
    table.add_column("Category")
    table.add_column("Count")
    for k, v in vt_stats.items():
        table.add_row(k, str(v))
    console.print(table)
    if vt_malicious >= 1:
        reasons.append(f"VirusTotal flagged as malicious by {vt_malicious} engines")

    urlscan = data.get("urlscan", {})
    verdict = urlscan.get("verdicts", {}).get("overall")
    if verdict:
        console.print(f"[bold magenta]URLScan Verdict: {verdict}")
        if verdict == "malicious":
            reasons.append("URLScan labeled this URL as malicious")

    if reasons:
        render_summary("suspicious", reasons)
    elif not vt and not urlscan:
        render_summary("inconclusive", ["No data from any source."])
    else:
        render_summary("safe", ["No major risk indicators found."])

def format_hash_result(data):
    console.rule("[bold red]File Hash Scan Summary")
    reasons = []

    vt = data.get("virustotal", {})
    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    vt_malicious = vt_stats.get("malicious", 0)

    table = Table(title="VirusTotal", box=box.SIMPLE)
    table.add_column("Category")
    table.add_column("Count")
    for k, v in vt_stats.items():
        table.add_row(k, str(v))
    console.print(table)
    if vt_malicious >= 1:
        reasons.append(f"VirusTotal flagged as malicious by {vt_malicious} engines")

    hybrid = data.get("hybrid_analysis", {})
    if isinstance(hybrid, dict):
        score = hybrid.get("threat_score")
        tags = hybrid.get("tags", [])
        if score:
            console.print(f"[bold green]Hybrid Threat Score: {score}")
            if score > 70:
                reasons.append(f"Hybrid Analysis threat score: {score}")
        if tags:
            console.print("Tags:", ", ".join(tags))

    if reasons:
        render_summary("suspicious", reasons)
    elif not vt and not hybrid:
        render_summary("inconclusive", ["No data from any source."])
    else:
        render_summary("safe", ["No major risk indicators found."])
