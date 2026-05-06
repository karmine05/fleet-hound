import time

import requests


class FleetGraphExtractor:
    def extract_all_users(self):
        """Fetch all users from Fleet's /api/v1/fleet/users endpoint."""
        users = []
        per_page = 500
        page = 0
        while True:
            resp = self._get(
                "/api/v1/fleet/users",
                params={
                    'page': page,
                    'per_page': per_page,
                }
            )
            if not resp or resp.status_code != 200:
                break
            try:
                data = resp.json()
            except ValueError:
                if self.debug:
                    print("[extractor] Failed to parse users JSON")
                break
            page_users = data.get('users', [])
            users.extend(page_users)
            if len(page_users) < per_page:
                break
            page += 1
            # Reduced sleep time - only needed between pages
            time.sleep(0.5)
        if self.debug:
            print(f"[extractor] Extracted {len(users)} users from /users endpoint")
        return users

    def extract_teams(self):
        """Fetch all teams available to the user."""
        teams = []
        page = 0
        while True:
            resp = self._get(
                "/api/v1/fleet/teams",
                params={'page': page, 'per_page': 100}
            )
            if not resp or resp.status_code != 200:
                break
            try:
                data = resp.json()
            except ValueError:
                break
            
            page_teams = data.get('teams', [])
            teams.extend(page_teams)
            
            if len(page_teams) < 100:
                break
            page += 1
        return teams

    def __init__(self, fleet_url, api_token, verify: bool = True, timeout: int = 20, debug: bool = False, session=None):
        self.fleet_url = fleet_url.rstrip('/')
        self.headers = {'Authorization': f'Bearer {api_token}', 'Accept': 'application/json'}
        self.verify = verify
        self.timeout = timeout
        self.debug = debug
        self.session = session or requests.Session()

    def _get(self, path: str, retries: int = 3, **kwargs):
        url = f"{self.fleet_url}{path}"
        last_resp = None
        for attempt in range(retries):
            try:
                resp = self.session.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify,
                    **kwargs,
                )
                last_resp = resp

                # Simple retry policy for transient/ratelimit errors.
                if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                    retry_after = resp.headers.get('Retry-After')
                    backoff = 0.5 * (2 ** attempt)
                    if resp.status_code == 429 and retry_after and retry_after.isdigit():
                        backoff = max(backoff, int(retry_after))
                    if self.debug:
                        print(f"[extractor] GET {path} status={resp.status_code} retrying in {backoff:.1f}s")
                    time.sleep(backoff)
                    continue

                if self.debug:
                    print(f"[extractor] GET {path} status={resp.status_code}")
                return resp
            except requests.exceptions.SSLError as e:
                if self.debug:
                    print(f"[extractor] SSL error on {path}: {e}")
                return None
            except requests.exceptions.RequestException as e:
                if self.debug:
                    print(f"[extractor] Request error on {path}: {e}")
                if attempt < retries - 1:
                    backoff = 0.5 * (2 ** attempt)
                    time.sleep(backoff)
                    continue
                return None

        return last_resp

    def extract_host_data(self, team_ids: list = None, since: str = None, since_map: dict = None):
        """
        Extract host data with optimized pagination and filtering.
        
        Args:
            team_ids: Optional list of team IDs to filter by.
            since: Global fallback ISO timestamp.
            since_map: Optional dict mapping team_id (str) to ISO timestamp.
        """
        hosts_data = []
        
        # If no teams specified, use a single None entry to trigger the loop once (default fetch)
        target_teams = team_ids if team_ids else [None]
        
        for team_id in target_teams:
            # Determine effective 'since' for this specific iteration
            # Determine effective 'since' - use the LATEST of global or team-specific
            current_since = since
            if since_map and team_id is not None:
                team_since = since_map.get(str(team_id))
                if team_since and current_since:
                    # If we have both, taking the MAX ensures we don't re-fetch calls covered by a global sync
                    current_since = max(current_since, team_since)
                elif team_since:
                    current_since = team_since

            if self.debug:
                t_label = f"Team {team_id}" if team_id is not None else "All Teams"
                s_label = f" (since {current_since})" if current_since else " (full scan)"
                print(f"[extractor] Fetching hosts for: {t_label}{s_label}")

            # Define base parameters
            per_page = 500
            params = {
                'per_page': per_page,
                'populate_users': True,
                'populate_software': True
            }
            if team_id is not None:
                params['team_id'] = team_id

            # If doing differential fetch, ensure we sort by updated_at desc
            if current_since:
                params['order_key'] = 'updated_at'
                params['order_direction'] = 'desc'

            # Sequential pagination driven by meta.has_next_results.
            # Fleet's PaginationMetadata does not serialize TotalResults
            # (json tag "-"), so the only reliable signal that more pages
            # exist is meta.has_next_results. Walk pages 0..N until that
            # flag is false, the differential cutoff is crossed, or an
            # error occurs.
            page = 0
            while True:
                p_params = params.copy()
                p_params['page'] = page

                if self.debug:
                    print(f"[extractor] Fetching hosts page {page}...")

                resp = self._get("/api/v1/fleet/hosts", params=p_params)
                if not resp or resp.status_code != 200:
                    break

                try:
                    data = resp.json()
                except ValueError:
                    if self.debug:
                        print("[extractor] Failed to parse hosts JSON")
                    break

                page_hosts = data.get('hosts', [])
                valid_hosts, stop = self._filter_hosts(page_hosts, current_since)
                hosts_data.extend(valid_hosts)

                if stop and current_since:
                    if self.debug:
                        print(f"[extractor] Differential cutoff reached on page {page}; stopping.")
                    break

                meta = data.get('meta', {})
                if not meta.get('has_next_results', False):
                    break

                page += 1
                # Light pacing between pages to avoid hammering Fleet.
                time.sleep(0.2)

        if self.debug:
            print(f"[extractor] Extracted {len(hosts_data)} hosts total (differential={bool(since)})")

        return hosts_data

    def _filter_hosts(self, hosts, current_since):
        """Helper to filter hosts based on 'since'."""
        valid = []
        stop = False
        for host in hosts:
            if current_since:
                updated_at = host.get('updated_at')
                if updated_at:
                    if updated_at > current_since:
                        valid.append(host)
                    else:
                        stop = True
                        break # Optimization: since sorted desc, rest are old
                else:
                    valid.append(host)
            else:
                valid.append(host)
        return valid, stop

    def extract_software_per_host(self, host_id):
        resp = self._get(f"/api/v1/fleet/hosts/{host_id}/software")
        if resp and resp.status_code == 200:
            try:
                return resp.json().get('software', [])
            except ValueError:
                if self.debug:
                    print(f"[extractor] Failed to parse software JSON for host {host_id}")
        return []

    def extract_users_for_host(self, host_id):
        """Attempt to retrieve per-host user list via detail endpoint.

        Tries multiple parameter variants because Fleet may differ by version.
        Returns list of username strings.
        """
        candidates = []
        # Variants to try
        variants = [
            {"additional_info_filters": "users"},
            {"include": "users"},
            {}
        ]
        for params in variants:
            resp = self._get(f"/api/v1/fleet/hosts/{host_id}", params=params)
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            # Possible locations
            raw_users = data.get('users') or data.get('host_users') or data.get('logged_in_users')
            if isinstance(raw_users, list):
                for u in raw_users:
                    if isinstance(u, dict):
                        name = u.get('username') or u.get('user') or u.get('name') or u.get('login')
                        if name:
                            candidates.append(name)
                    elif isinstance(u, str):
                        candidates.append(u)
            # Sometimes a count instead of list; ignore counts
            if candidates:
                break
        # Deduplicate
        out = []
        seen = set()
        for c in candidates:
            if c not in seen:
                seen.add(c)
                out.append(c)
        if self.debug:
            print(f"[extractor] Users for host {host_id}: {out}")
        return out
