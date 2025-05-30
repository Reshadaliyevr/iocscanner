from clients.virustotal import VirusTotalClient
from clients.abuseipdb import AbuseIPDBClient
from clients.urlscan import URLScanClient
from clients.hybrid import HybridAnalysisClient

class IOCScanner:
    def __init__(self, vt_key, abuse_key, urlscan_key, hybrid_key):
        self.vt_client = VirusTotalClient(vt_key)
        self.abuse_client = AbuseIPDBClient(abuse_key)
        self.urlscan_client = URLScanClient(urlscan_key)
        self.hybrid_client = HybridAnalysisClient(hybrid_key)

    def scan_ip(self, ip: str) -> dict:
        vt = self.vt_client.lookup_ip(ip)
        abuse = self.abuse_client.lookup_ip(ip)
        return {
            "virustotal": vt,
            "abuseipdb": abuse
        }

    def scan_url(self, url: str) -> dict:
        vt = self.vt_client.lookup_url(url)
        urlscan = self.urlscan_client.submit_url(url)
        return {
            "virustotal": vt,
            "urlscan": urlscan
        }

    def scan_hash(self, sha256: str) -> dict:
        vt = self.vt_client.lookup_file_hash(sha256)
        hybrid = self.hybrid_client.search_by_hash(sha256)
        return {
            "virustotal": vt,
            "hybrid": hybrid
        }

    # ✅ Expose the clients explicitly for direct use in processor
    @property
    def virustotal(self):
        return self.vt_client

    @property
    def hybrid(self):
        return self.hybrid_client
