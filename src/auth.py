import requests
from typing import Optional, Tuple

class FleetAuthenticator:
    def __init__(self, fleet_url: str, verify: bool = True, timeout: int = 15):
        self.fleet_url = fleet_url.rstrip('/')
        self.verify = verify
        self.timeout = timeout

    def login(self, email: str, password: str, debug: bool = False) -> Optional[str]:
        """Attempt login and return API token or None.

        Debug mode prints status code and first 300 chars of response text.
        If SSL verification fails and verify=False was not set, caller can retry with verify disabled.
        """
        url = f"{self.fleet_url}/api/v1/fleet/login"
        try:
            response = requests.post(
                url,
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=self.timeout,
                verify=self.verify
            )
        except requests.exceptions.SSLError as e:
            if debug:
                print(f"[auth] SSL error: {e}. Retry with --insecure if using self-signed cert.")
            return None
        except requests.exceptions.RequestException as e:
            if debug:
                print(f"[auth] Request exception: {e}")
            return None

        if debug:
            snippet = response.text[:300].replace('\n', ' ')
            print(f"[auth] Status={response.status_code} Body[0:300]='{snippet}'")

        if response.status_code == 200:
            data = response.json()
            # Common token locations
            token = data.get("token") or data.get("access_token") or data.get("api_token")
            if not token and debug:
                print(f"[auth] Token not found in response keys: {list(data.keys())}")
            return token
        return None

    def probe_login(self, email: str, password: str) -> Tuple[int, str]:
        """Return (status_code, truncated_body) for diagnostics without parsing token."""
        url = f"{self.fleet_url}/api/v1/fleet/login"
        try:
            r = requests.post(url, json={"email": email, "password": password}, verify=self.verify, timeout=self.timeout)
            return r.status_code, r.text[:500]
        except Exception as e:
            return 0, f"error: {e}"
