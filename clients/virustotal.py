import requests
import base64
import time
from engine.monitor import api_monitor
from engine.retry_policy import retry_on_throttle
import os

class VirusTotalClient:
    def __init__(self, api_key: str):
        """Initialize the VirusTotal API client."""
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key
        }

    @retry_on_throttle
    def lookup_ip(self, ip: str) -> dict:
        """Query VirusTotal for IP reputation."""
        url = f"{self.base_url}/ip_addresses/{ip}"
        return self._make_request(url)

    def _poll_analysis(self, analysis_id: str, timeout: int = 30, interval: int = 5) -> dict:
        """
        Poll VirusTotal for analysis results using analysis_id.
        """
        status_url = f"{self.base_url}/analyses/{analysis_id}"
        elapsed = 0

        while elapsed < timeout:
            try:
                api_monitor.wait_and_proceed("virustotal")
                response = requests.get(status_url, headers=self.headers)
                response.raise_for_status()

                data = response.json()
                status = data.get("data", {}).get("attributes", {}).get("status")

                if status == "completed":
                    return data
            except Exception as e:
                return {"error": str(e)}

            time.sleep(interval)
            elapsed += interval

        return {"error": f"Timeout reached while polling analysis_id: {analysis_id}"}

    @retry_on_throttle
    def upload_file(self, file_path: str) -> dict:
        """
        Upload a file to VirusTotal for scanning and return results.
        """
        upload_url = f"{self.base_url}/files"

        try:
            # Normalize the file path to handle Windows path issues
            normalized_path = os.path.normpath(file_path)
            
            # Verify file exists before attempting to open
            if not os.path.exists(normalized_path):
                return {"error": f"File not found: {normalized_path}"}
            
            api_monitor.wait_and_proceed("virustotal")
            with open(normalized_path, "rb") as f:
                files = {"file": (os.path.basename(normalized_path), f)}
                response = requests.post(upload_url, headers={"x-apikey": self.api_key}, files=files)
                response.raise_for_status()

            analysis_id = response.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "Upload succeeded, but no analysis_id returned."}

            # Wait & poll for results
            return self._poll_analysis(analysis_id)

        except FileNotFoundError as e:
            return {"error": f"File not found: {str(e)}"}
        except PermissionError as e:
            return {"error": f"Permission denied: {str(e)}"}
        except OSError as e:
            return {"error": f"OS error: {str(e)}"}
        except Exception as e:
            return {"error": str(e)}

    @retry_on_throttle
    def lookup_url(self, url: str) -> dict:
        """Submit and retrieve analysis of a URL."""
        # Step 1: Submit URL
        submit_url = f"{self.base_url}/urls"
        data = {"url": url}
        response = requests.post(submit_url, headers=self.headers, data=data)
        if response.status_code != 200:
            return {"error": f"URL submission failed: {response.text}"}

        analysis_id = response.json()["data"]["id"]
        encoded_url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Step 2: Retrieve URL analysis
        report_url = f"{self.base_url}/urls/{encoded_url_id}"
        return self._make_request(report_url)

    @retry_on_throttle
    def lookup_file_hash(self, sha256: str) -> dict:
        """Query VirusTotal for a file hash."""
        url = f"{self.base_url}/files/{sha256}"
        return self._make_request(url)

    @retry_on_throttle
    def _make_request(self, url: str) -> dict:
        """Send a GET request and return JSON response."""
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            return {"error": str(e), "details": response.text}
        except Exception as e:
            return {"error": str(e)}