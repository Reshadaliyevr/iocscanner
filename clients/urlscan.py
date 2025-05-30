import requests
import time
from engine.retry_policy import retry_on_throttle

class URLScanClient:
    def __init__(self, api_key: str):
        """Initialize the URLScan API client."""
        self.api_key = api_key
        self.submit_endpoint = "https://urlscan.io/api/v1/scan/"
        self.result_base_url = "https://urlscan.io/api/v1/result/"
        self.headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json"
        }

    @retry_on_throttle
    def submit_url(self, url: str, wait: int = 5) -> dict:
        """
        Submit a URL for scanning.
        
        Parameters:
        - url: URL to scan
        - wait: Seconds to wait before attempting result fetch (default: 5)

        Returns:
        - Dict with scan result (or error)
        """
        payload = {
            "url": url,
            "visibility": "public"
        }

        try:
            response = requests.post(self.submit_endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            scan_data = response.json()
            result_url = scan_data.get("api", None)

            if not result_url:
                return {"error": "URL submission succeeded, but result link missing."}

            # Optionally wait and fetch result
            time.sleep(wait)
            return self.get_scan_result(scan_data.get("uuid"))
        except requests.exceptions.HTTPError as e:
            return {"error": str(e), "details": response.text}
        except Exception as e:
            return {"error": str(e)}

    @retry_on_throttle
    def get_scan_result(self, uuid: str) -> dict:
        """
        Retrieve the result of a previously submitted scan.
        
        Parameters:
        - uuid: UUID from the submission

        Returns:
        - Dict containing scan result
        """
        try:
            url = f"{self.result_base_url}{uuid}/"
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            return {"error": str(e), "details": response.text}
        except Exception as e:
            return {"error": str(e)}