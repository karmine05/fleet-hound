import logging
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)


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
                logger.error("SSL error: %s; retry with --insecure if using self-signed cert", e)
            return None
        except requests.exceptions.RequestException as e:
            if debug:
                logger.warning("request exception: %s", e)
            return None

        if debug:
            snippet = response.text[:300].replace('\n', ' ')
            logger.debug("login status=%d body[0:300]=%r", response.status_code, snippet)

        if response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                if debug:
                    logger.warning("login response was not valid JSON")
                return None
            # Common token locations
            token = data.get("token") or data.get("access_token") or data.get("api_token")
            if not token and debug:
                logger.warning("token not found in response keys=%s", list(data.keys()))
            return token
        return None

    def probe_login(self, email: str, password: str) -> Tuple[int, str]:
        """Return (status_code, truncated_body) for diagnostics without parsing token."""
        url = f"{self.fleet_url}/api/v1/fleet/login"
        try:
            r = self._session.post(
                url,
                json={"email": email, "password": password},
                verify=self.verify,
                timeout=self.timeout,
            )
            return r.status_code, r.text[:500]
        except requests.exceptions.RequestException as e:
            return 0, f"error: {e}"
