import requests
import time
import concurrent.futures
from typing import List, Dict, Any, Optional

class FleetGraphExtractor:
    def extract_all_users(self) -> List[Dict[str, Any]]:
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

            # Define base parameters (starting with page 0)
            params = {
                'page': 0,
                'per_page': 500,
                'populate_users': True,
                'populate_software': True
            }
            if team_id is not None:
                params['team_id'] = team_id
            
            # If doing differential fetch, ensure we sort by updated_at desc
            if current_since:
                params['order_key'] = 'updated_at'
                params['order_direction'] = 'desc'

            # 1. Fetch first page to get metadata and check initial data
            first_page_params = params.copy()
            first_page_params['page'] = 0
            
            if self.debug:
                print(f"[extractor] Fetching first page for metadata...")

            resp = self._get("/api/v1/fleet/hosts", params=first_page_params)
            if not resp or resp.status_code != 200:
                continue

            try:
                data = resp.json()
            except ValueError:
                if self.debug:
                    print("[extractor] Failed to parse hosts JSON")
                continue

            # Process first page
            hosts_p0 = data.get('hosts', [])
            meta = data.get('meta', {})
            total_count = meta.get('total', 0)
            
            # Initial filtering check on Page 0
            # If we hit the age limit on page 0, we might stop immediately
            valid_hosts_p0, stop_fetching_team = self._filter_hosts(hosts_p0, current_since)
            hosts_data.extend(valid_hosts_p0)

            if stop_fetching_team:
                if self.debug:
                    print("[extractor] Stop condition met on Page 0.")
                continue

            # 2. Calculate remaining pages
            # Fleet API uses 0-indexed pages? No, usually 0 is page 1?
            # Code used 'page': page (starting 0).
            # If total is 501, per_page 500. Page 0 = 0-499. Page 1 = 500.
            # Total pages = ceil(total / per_page).
            if total_count > 0:
                 total_pages = (total_count + 499) // 500
            else:
                 total_pages = 0
            
            if total_pages <= 1:
                continue

            if self.debug:
                print(f"[extractor] Total pages: {total_pages}. Fetching pages 1 to {total_pages-1} in parallel...")

            # 3. Parallel fetch for remaining pages
            pages_to_fetch = range(1, total_pages)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                pool_map = {executor.submit(self._fetch_host_page, p, params): p for p in pages_to_fetch}
                
                for future in concurrent.futures.as_completed(pool_map):
                    page_num = pool_map[future]
                    try:
                        p_hosts = future.result()
                        if p_hosts:
                            valid_p, stop_p = self._filter_hosts(p_hosts, current_since)
                            hosts_data.extend(valid_p)
                            # Note: in parallel, 'stop_p' just means this page had old data.
                            # We don't abort other in-flight requests (complexity adds up),
                            # but we assume valid data is gathered.
                    except Exception as exc:
                        if self.debug:
                            print(f"[extractor] Page {page_num} generated an exception: {exc}")

            if self.debug:
                print(f"[extractor] Finished fetching {total_pages} pages.")

        if self.debug:
            print(f"[extractor] Extracted {len(hosts_data)} hosts total (differential={bool(since)})")

        return hosts_data

    def _fetch_host_page(self, page_num, base_params):
        """Helper for parallel fetching"""
        p_params = base_params.copy()
        p_params['page'] = page_num
        resp = self._get("/api/v1/fleet/hosts", params=p_params)
        if resp and resp.status_code == 200:
            try:
                return resp.json().get('hosts', [])
            except ValueError:
                pass
        return []

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
