import requests
from engine.retry_policy import retry_on_throttle

class AbuseIPDBClient:
    def __init__(self, api_key: str):
        """Initialize the AbuseIPDB API client."""
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    @retry_on_throttle
    def lookup_ip(self, ip: str, max_age_in_days: int = 90) -> dict:
        """
        Query AbuseIPDB for IP address reputation.
        
        Parameters:
        - ip: IP address to check
        - max_age_in_days: How far back to search (default: 90 days)

        Returns:
        - Dict containing report summary
        """
        url = f"{self.base_url}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_in_days
        }

        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            return {"error": str(e), "details": response.text}
        except Exception as e:
            return {"error": str(e)}
