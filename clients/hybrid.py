import requests
from engine.retry_policy import retry_on_throttle

class HybridAnalysisClient:
    def __init__(self, api_key: str):
        """Initialize Hybrid Analysis API client."""
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

    @retry_on_throttle
    def search_by_hash(self, sha256: str) -> dict:
        """
        Search Hybrid Analysis for a given file hash.
        
        Parameters:
        - sha256: File hash (SHA256, MD5, or SHA1)
        """
        url = f"{self.base_url}/search/hash"
        data = {"hash": sha256}

        try:
            response = requests.post(url, headers=self.headers, data=data)
            response.raise_for_status()
            result = response.json()

            if isinstance(result, list) and len(result) > 0:
                return result[0]
            else:
                return {"message": "No results found in Hybrid Analysis."}
        except requests.exceptions.HTTPError as e:
            return {"error": str(e), "details": response.text}
        except Exception as e:
            return {"error": str(e)}
