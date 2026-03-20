import argparse
import os
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Optional, Dict, List, Any

# Suppress SSL warnings when using --insecure flag
import urllib3

from src.auth import FleetAuthenticator
from src.extractor import FleetGraphExtractor
from src.ingestion import MemgraphIngestion
from categorize_software import run_categorization
import json
import datetime
from neo4j import GraphDatabase

STATE_FILE = '.state.json'


def load_env_file(env_path: str = '.env') -> Dict[str, str]:
    """Load environment variables from .env file."""
    env_vars = {}
    env_file = Path(env_path)

    if not env_file.exists():
        return env_vars

    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]

                env_vars[key] = value

    return env_vars


def str_to_bool(value: str) -> bool:
    """Convert string to boolean."""
    return value.lower() in ('true', '1', 'yes', 'on')


from typing import Optional, Dict, Any, List, Tuple


def load_state() -> Dict[str, Any]:
    """Load the state file."""
    if Path(STATE_FILE).exists():
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"⚠️  WARNING: Ignoring invalid JSON in {STATE_FILE}: {e}")
        except OSError as e:
            print(f"⚠️  WARNING: Failed to read {STATE_FILE}: {e}")
    return {}


def save_state(state: Dict[str, Any]) -> None:
    """Save the state file."""
    tmp_path = None
    try:
        state_path = Path(STATE_FILE)
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            delete=False,
            dir=str(state_path.parent),
            prefix=state_path.name + '.',
            suffix='.tmp',
        ) as tf:
            tmp_path = tf.name
            json.dump(state, tf, indent=2)
            tf.flush()
            os.fsync(tf.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            # Best-effort on platforms that don't support chmod semantics.
            pass
        os.replace(tmp_path, STATE_FILE)
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        print(f"⚠️  WARNING: Failed to save state file: {e}")


def main():
    # Load .env file first
    env_vars = load_env_file('.env')

    # If .env doesn't exist, check for .env.example and warn user
    if not env_vars and not Path('.env').exists():
        if Path('.env.example').exists():
            print("⚠️  WARNING: .env file not found!")
            print("📝 Please copy .env.example to .env and configure your settings:")
            print("   cp .env.example .env")
            print("\nYou can still use command-line arguments, but .env is recommended.\n")

    parser = argparse.ArgumentParser(
        description="Fleet Hound: Extract Fleet data and ingest into Memgraph",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="""
Examples:
  # Using .env file (recommended):
  python3 main.py

  # Using command-line arguments:
  python3 main.py --fleet-url https://fleet.example.com --email admin@example.com --password secret

  # Override .env with command-line:
  python3 main.py --insecure --debug-auth
        """
    )

    # Make arguments optional - fallback to .env
    parser.add_argument('--fleet-url', help='Fleet server URL (default: from .env)')
    parser.add_argument('--email', help='Fleet user email (default: from .env)')
    parser.add_argument('--memgraph-uri', help='Memgraph URI (default: from .env or bolt://localhost:7687)')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification for self-signed certs (development only)')
    parser.add_argument('--debug-auth', action='store_true', help='Print auth response diagnostics')
    parser.add_argument('--dump-host-sample', action='store_true', help='Write first host object to hosts_sample.json then exit')
    parser.add_argument('--teams', help='Comma-separated list of Team IDs to fetch (e.g., 1,2). Default: All teams.')
    parser.add_argument('--full-scan', action='store_true', help='Ignore last run time and fetch ALL data.')
    parser.add_argument('--complete-enrichment', action='store_true', help='Enrich ALL software in database with Wikidata (warning: may take long)')
    parser.add_argument('--enrich-software', help='Comma-separated list of specific software names to enrich immediately')
    parser.add_argument('--force', action='store_true', help='Force enrichment limit to exceed 250 (uses 3% of total hosts)')

    args = parser.parse_args()

    # Get configuration from args or .env (args take precedence)
    fleet_url = args.fleet_url or env_vars.get('FLEET_URL')
    email = args.email or env_vars.get('FLEET_EMAIL')
    # Secrets MUST come from .env or environment variables, not CLI arguments
    password = env_vars.get('FLEET_PASSWORD')
    api_token = env_vars.get('FLEET_API_TOKEN')
    memgraph_uri = args.memgraph_uri or env_vars.get('MEMGRAPH_URI', 'bolt://localhost:7687')
    insecure = args.insecure or str_to_bool(env_vars.get('INSECURE', 'false'))
    debug_auth = args.debug_auth or str_to_bool(env_vars.get('DEBUG', 'false'))

    # Validate required configuration
    if not fleet_url:
        print("❌ ERROR: FLEET_URL is required (set in .env or use --fleet-url)")
        sys.exit(1)

    # Suppress SSL warnings ONLY when using insecure mode
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("⚠️  WARNING: SSL verification disabled (--insecure mode)")
        print("   This should only be used in development with self-signed certificates!\n")
    else:
        # Ensure warnings are enabled for valid certificates
        warnings.filterwarnings('default')

    # Authenticate - Prioritize API token (recommended method)
    if api_token:
        # Use API token directly (recommended/production mode)
        print("🔑 Using API token authentication")
        token = api_token
    elif email and password:
        # Fallback to email/password login (legacy/development mode)
        print("🔐 Authenticating with email/password (consider using API token instead)...")
        auth = FleetAuthenticator(fleet_url, verify=not insecure)
        token = auth.login(email, password, debug=debug_auth)
        if not token:
            print("❌ Login failed. Check credentials or use --debug-auth / --insecure if self-signed cert.")
            if debug_auth:
                status, msg = auth.probe_login(email, password)
                print(f"Auth probe status={status} diagnostic_msg='{msg}'")
            sys.exit(1)
        print("✅ Login successful.")
    else:
        # No authentication method provided
        print("❌ ERROR: Authentication required!")
        print("\n📝 Recommended: Set FLEET_API_TOKEN in .env file")
        print("   Alternative: Set FLEET_EMAIL and FLEET_PASSWORD in .env")
        print("\n💡 To get an API token:")
        print("   1. Log in to Fleet web interface")
        print("   2. Go to Settings → Account → API Token")
        print("   3. Copy token to .env file: FLEET_API_TOKEN=your-token-here")
        sys.exit(1)

    # Determine 'since' timestamp logic
    # State structure can be: { "last_run_timestamp": "...", "team_syncs": { "1": "..." } }
    state = load_state()
    global_since = None
    since_map = state.get('team_syncs', {})
    
    if not args.full_scan:
        global_since = state.get('last_run_timestamp')
        
    current_timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # Extract
    print(f"📡 Extracting data from Fleet: {fleet_url}")
    extractor = FleetGraphExtractor(fleet_url, token, verify=not insecure, debug=debug_auth)

    # Parse teams or prompt interactively
    team_ids = []
    if args.teams:
        try:
            team_ids = [int(t.strip()) for t in args.teams.split(',') if t.strip()]
        except ValueError:
            print("❌ ERROR: Teams must be a comma-separated list of integers (e.g. --teams 1,2)")
            sys.exit(1)
    elif sys.stdin.isatty() and not args.full_scan:
        # Interactive mode: Fetch teams and prompt user
        print("⏳ Fetching teams...")
        teams = extractor.extract_teams()
        if teams:
            print("\n🏢 Available Teams:")
            print(f"   {'[0]':<6} No Team (Unassigned)")
            for t in teams:
                # Safe access to ID and name
                tid = t.get('id', '?')
                tname = t.get('name', 'Unknown')
                print(f"   [{tid}]:   {tname}")
            
            print("\n👉 Select teams by ID (comma-separated, e.g. '1,2') or press ENTER for ALL:")
            selection = input("   > ").strip()
            if selection:
                try:
                    # distinct ints
                    team_ids = list(set([int(x.strip()) for x in selection.split(',') if x.strip()]))
                except ValueError:
                    print("❌ Invalid input. Fetching ALL teams.")
                    team_ids = []
            else:
                print("ℹ️  No specific teams selected. Fetching ALL data.")
        else:
            print("ℹ️  No teams found (or insufficient permissions). Fetching ALL data.")

    hosts = extractor.extract_host_data(team_ids=team_ids, since=global_since, since_map=since_map)
    
    # If using teams, we might want to only get users relevant to those hosts, 
    # but the API doesn't easily support filtering /users by team without iterating hosts.
    # For now, we keep global user fetch as is (it's usually fast enough via pagination).
    global_users = extractor.extract_all_users()

    if args.dump_host_sample and hosts:
        import json
        with open('hosts_sample.json', 'w') as hf:
            json.dump(hosts[0], hf, indent=2)
        print('📄 Wrote hosts_sample.json (first host object). Exiting by request (--dump-host-sample).')
        return

    print(f"✅ Extracted {len(hosts)} hosts.")
    print(f"✅ Extracted {len(global_users)} users from /users endpoint.")

    # Ingest
    print(f"💾 Ingesting data into Memgraph: {memgraph_uri}")
    with MemgraphIngestion(memgraph_uri) as ingestion:
        ingestion.create_constraints()
        ingestion.create_graph_relationships(hosts, extractor, global_users=global_users)
        print("✅ Data ingested into Memgraph.")
        ingestion.print_stats()

    print("\n🔍 Starting automatic software categorization (targeting Shadow IT outliers)...")
    try:
        # Prioritize rare software (outliers) to enrich Shadow IT detections
        # If --enrich-software is provided, we prioritize those.
        target_names = [n.strip() for n in args.enrich_software.split(',') if n.strip()] if args.enrich_software and args.enrich_software.strip() else None
        
        limit = None
        if args.complete_enrichment:
            limit = None
            print("🚀 Full enrichment requested (no limit).")
        else:
            # Calculate dynamic limit: 3% of total hosts, capped at 250 (unless forced)
            try:
                # We need a quick driver check to get total hosts. 
                # (Ingestion just closed its driver, categorize opens its own, checking here is safe)
                with GraphDatabase.driver(memgraph_uri) as driver:
                    with driver.session() as session:
                        result = session.run("MATCH (h:Host) RETURN count(h) as count")
                        record = result.single()
                        total_hosts = record['count'] if record else 0
                        
                        # 3% threshold
                        target_limit = int(total_hosts * 0.03)
                        # Ensure at least minimal enrichment happens (e.g. top 10) if fleet is tiny
                        target_limit = max(10, target_limit) 
                        
                        if args.force:
                            limit = target_limit
                            print(f"🎯 Auto-calculated enrichment limit: {limit} (3% of {total_hosts} hosts) -- FORCE ENABLED (ignoring 250 cap)")
                        else:
                            limit = min(target_limit, 250)
                            cap_msg = "(capped at 250)" if target_limit > 250 else ""
                            print(f"🎯 Auto-calculated enrichment limit: {limit} (3% of {total_hosts} hosts) {cap_msg}")
                            
            except Exception as e:
                print(f"⚠️  Could not query total hosts for limit calculation, defaulting to 250. Error: {e}")
                limit = 250

        run_categorization(memgraph_uri=memgraph_uri, limit=limit, target_names=target_names)
    except Exception as e:
        print(f"⚠️  WARNING: Software categorization failed: {e}")

    print("\n🎉 Fleet Hound extraction complete!")
    
    # Update state logic
    if not args.dump_host_sample:
        if team_ids:
            # Update specific teams
            if 'team_syncs' not in state:
                state['team_syncs'] = {}
            for tid in team_ids:
                state['team_syncs'][str(tid)] = current_timestamp
            print(f"💾 Updated sync state for teams: {team_ids}")
        else:
            # Update global state (implies all teams synced)
            # Update global state AND fast-forward all teams
            state['last_run_timestamp'] = current_timestamp
            
            # Fetch all teams to ensure their individual states are also up to date
            # This prevents a future team-specific run from seeing a stale timestamp
            try:
                all_teams = extractor.extract_teams()
                if 'team_syncs' not in state:
                    state['team_syncs'] = {}
                for t in all_teams:
                    tid = t.get('id')
                    if tid is not None:
                        state['team_syncs'][str(tid)] = current_timestamp
                print(f"💾 Updated global sync state and sync timestamps for {len(all_teams)} teams")
            except Exception as e:
                print(f"⚠️  WARNING: Failed to update per-team state during global sync: {e}")
            
        save_state(state)

    print(f"🌐 Access dashboard at: http://localhost:8080")

if __name__ == "__main__":
    main()
