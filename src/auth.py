from typing import Optional, Tuple

import requests

class FleetAuthenticator:
    def __init__(
        self,
        fleet_url: str,
        verify: bool = True,
        timeout: int = 15,
        session: Optional[requests.Session] = None,
    ):
        self.fleet_url = fleet_url.rstrip('/')
        self.verify = verify
        self.timeout = timeout
        self._session = session or requests.Session()

    def login(self, email: str, password: str, debug: bool = False) -> Optional[str]:
        """Attempt login and return API token or None.

        Debug mode prints status code and first 300 chars of response text.
        If SSL verification fails and verify=False was not set, caller can retry with verify disabled.
        """
        url = f"{self.fleet_url}/api/v1/fleet/login"
        try:
            response = self._session.post(
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
            try:
                data = response.json()
            except ValueError:
                if debug:
                    print("[auth] Login response was not valid JSON")
                return None
            # Common token locations
            token = data.get("token") or data.get("access_token") or data.get("api_token")
            if not token and debug:
                print(f"[auth] Token not found in response keys: {list(data.keys())}")
            return token
        return None

    def probe_login(self, email: str, password: str) -> Tuple[int, str]:
        """Return (status_code, sanitized_message) for diagnostics."""
        url = f"{self.fleet_url}/api/v1/fleet/login"
        try:
            r = self._session.post(
                url,
                json={"email": email, "password": password},
                verify=self.verify,
                timeout=self.timeout,
            )
            # Sanitize: Do NOT return r.text directly to avoid leaking server internals.
            # Instead, return a short summary of the situation.
            msg = "OK" if r.status_code == 200 else f"Failed (content_type={r.headers.get('Content-Type', 'unknown')})"
            return r.status_code, msg
        except requests.exceptions.RequestException as e:
            return 0, f"connection_error"
