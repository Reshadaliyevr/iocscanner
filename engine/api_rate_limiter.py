# engine/api_rate_limiter.py

import threading
import time
from collections import defaultdict, deque
import logging

logger = logging.getLogger("iocscanner.ratelimit")
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler("logs/rate_limiter.log", maxBytes=1_000_000, backupCount=2)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

class APIRateLimiter:
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
        self.timestamps = defaultdict(deque)

    def wait_and_acquire(self, provider: str):
        while True:
            with self.lock:
                now = time.time()
                window_start = now - 60
                queue = self.timestamps[provider]

                # Drop timestamps older than 60 seconds
                while queue and queue[0] < window_start:
                    queue.popleft()

                if len(queue) < self.limits[provider]:
                    queue.append(now)
                    logger.info(f"[{provider}] Slot acquired. Total in window: {len(queue)}")
                    return
                else:
                    logger.info(f"[{provider}] Limit hit. Waiting... Queue size: {len(queue)}")

            time.sleep(0.5)
