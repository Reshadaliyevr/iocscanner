import time
import threading
from collections import defaultdict, deque

class APIMonitorQueue:
    """
    Manages API rate-limiting and request queuing per provider.
    Thread-safe and designed for shared use in bulk scans.
    """

    def __init__(self, limits_per_minute=None):
        """
        limits_per_minute: dict like {'virustotal': 4, 'abuseipdb': 30}
        """
        self.limits = limits_per_minute or {
            "virustotal": 4,
            "abuseipdb": 30,
            "urlscan": 60,
            "hybrid": 5
        }
        self.lock = threading.Lock()
        self.request_log = defaultdict(deque)  # provider -> deque[timestamps]

    def allow_request(self, provider: str) -> bool:
        """
        Check if a request to the given provider is allowed right now.
        """
        with self.lock:
            now = time.time()
            window_start = now - 60
            log = self.request_log[provider]

            # Remove timestamps older than 60 seconds
            while log and log[0] < window_start:
                log.popleft()

            if len(log) < self.limits[provider]:
                log.append(now)
                return True
            return False

    def wait_and_proceed(self, provider: str):
        """
        Blocks until a request to the given provider is allowed.
        """
        while not self.allow_request(provider):
            time.sleep(1)
