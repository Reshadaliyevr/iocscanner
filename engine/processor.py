import hashlib
import os
import time
import threading
from clients.scanner import IOCScanner
from clients.hybrid import HybridAnalysisClient
from clients.virustotal import VirusTotalClient
from dotenv import load_dotenv
import logging
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

load_dotenv()

MAX_WORKERS = int(os.getenv("MAX_THREAD_WORKERS", 5))

logger = logging.getLogger("iocscanner.processor")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("logs/iocscanner_threads.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class IOCProcessor:
    def __init__(self):
        load_dotenv()
        self.scanner = IOCScanner(
            vt_key=os.getenv("VT_API_KEY"),
            abuse_key=os.getenv("ABUSEIPDB_API_KEY"),
            urlscan_key=os.getenv("URLSCAN_API_KEY"),
            hybrid_key=os.getenv("HYBRID_API_KEY")
        )
        # from engine.api_monitor import load_keys
        # keys = load_keys()
        self.vt = VirusTotalClient(os.getenv("VT_API_KEY"))
        self.hybrid = HybridAnalysisClient(os.getenv("HYBRID_API_KEY"))
    @retry(wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type(Exception))
    def scan_ip(self, ip: str) -> dict:
        try:
            return self.scanner.scan_ip(ip)
        except Exception as e:
            logger.error(f"[scan_ip] Failed for {ip}: {e}")
            raise

    @retry(wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type(Exception))
    def scan_url(self, url: str) -> dict:
        try:
            return self.scanner.scan_url(url)
        except Exception as e:
            logger.error(f"[scan_url] Failed for {url}: {e}")
            raise

    def scan_file(self, file_obj, upload=False) -> dict:
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_obj.read())
            tmp_path = tmp.name

        sha256 = self.get_sha256(tmp_path)

        vt_result = (
            self.vt.upload_file(tmp_path) if upload
            else self.vt.lookup_file_hash(sha256)
        )

        hybrid_result = self.hybrid.search_by_hash(sha256)

        return {
            "file_name": file_obj.name,
            "sha256": sha256,
            "virustotal": vt_result,
            "hybrid_analysis": hybrid_result
        }

    def get_sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    def _calculate_sha256(self, path: str) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def scan_bulk(self, targets: list, target_type: str, max_workers: int = MAX_WORKERS) -> list:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        start_time = time.time()
        logger.info(f"[scan_bulk] Starting {len(targets)} {target_type} scans with {max_workers} workers")

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for t in targets:
                if target_type == "ip":
                    futures.append(executor.submit(self.scan_ip, t))
                elif target_type == "url":
                    futures.append(executor.submit(self.scan_url, t))

            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.error(f"[scan_bulk] Thread failed: {e}")
                    results.append({"error": str(e)})

        duration = time.time() - start_time
        logger.info(f"[scan_bulk] Completed in {duration:.2f}s — {len(results)} results, active threads: {threading.active_count()}")

        return results
