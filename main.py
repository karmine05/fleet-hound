"""Fleet Hound CLI — thin shim over `src.etl.run_etl`.

The substantive work lives in `src/etl.py`. This file owns:
  * argparse + .env loading
  * interactive team selection (only meaningful for a TTY)
  * ad-hoc operator switches: --dump-host-sample, --enrich-software, etc.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from src.etl import ETLConfig, run_etl
from src.extractor import FleetGraphExtractor


STATE_FILE = '.state.json'
SNAPSHOT_DIR = 'config/snapshots'

logger = logging.getLogger("fleethound.main")


def load_env_file(env_path: str = '.env') -> dict:
    env_vars: dict[str, str] = {}
    env_file = Path(env_path)
    if not env_file.exists():
        return env_vars
    with env_file.open('r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                env_vars[key] = value
    return env_vars


def str_to_bool(value: str) -> bool:
    return value.lower() in ('true', '1', 'yes', 'on')


def _interactive_team_select(fleet_url: str, token: str, insecure: bool, debug: bool) -> list[int]:
    extractor = FleetGraphExtractor(fleet_url, token, verify=not insecure, debug=debug)
    logger.info("fetching teams")
    teams = extractor.extract_teams()
    if not teams:
        logger.info("no teams found or insufficient permissions; fetching ALL data")
        return []
    print("\nAvailable teams:")
    print(f"   {'[0]':<6} No Team (Unassigned)")
    for t in teams:
        tid = t.get('id', '?')
        tname = t.get('name', 'Unknown')
        print(f"   [{tid}]:   {tname}")
    print("\nSelect teams by ID (comma-separated, e.g. '1,2') or press ENTER for ALL:")
    selection = input("   > ").strip()
    if not selection:
        logger.info("no specific teams selected; fetching ALL data")
        return []
    try:
        return list({int(x.strip()) for x in selection.split(',') if x.strip()})
    except ValueError:
        logger.warning("invalid team input; fetching ALL teams")
        return []


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-7s %(name)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )

    env_vars = load_env_file('.env')
    if not env_vars and not Path('.env').exists() and Path('.env.example').exists():
        logger.warning(".env file not found; copy .env.example to .env first (`cp .env.example .env`)")

    parser = argparse.ArgumentParser(
        description="Fleet Hound: Extract Fleet data and ingest into Memgraph",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--fleet-url', help='Fleet server URL (default: from .env)')
    parser.add_argument('--email', help='Fleet user email (default: from .env)')
    parser.add_argument('--password', help='Fleet user password (default: from .env)')
    parser.add_argument('--api-token', help='Fleet API token (preferred)')
    parser.add_argument('--memgraph-uri', help='Memgraph URI (default: from .env or bolt://localhost:7687)')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification (dev only)')
    parser.add_argument('--debug-auth', action='store_true', help='Print auth diagnostics')
    parser.add_argument('--dump-host-sample', action='store_true', help='Write first host object to hosts_sample.json then exit')
    parser.add_argument('--teams', help="Comma-separated Team IDs (e.g. '1,2'). Default: all teams.")
    parser.add_argument('--full-scan', action='store_true', help='Ignore last run timestamp and refetch everything')
    parser.add_argument('--complete-enrichment', action='store_true', help='Enrich ALL uncategorized software (slow)')
    parser.add_argument('--enrich-software', help='Comma-separated software names to enrich immediately')
    args = parser.parse_args()

    fleet_url = args.fleet_url or env_vars.get('FLEET_URL')
    email = args.email or env_vars.get('FLEET_EMAIL')
    password = args.password or env_vars.get('FLEET_PASSWORD')
    api_token = args.api_token or env_vars.get('FLEET_API_TOKEN')
    memgraph_uri = args.memgraph_uri or env_vars.get('MEMGRAPH_URI', 'bolt://localhost:7687')
    insecure = args.insecure or str_to_bool(env_vars.get('INSECURE', 'false'))
    debug = args.debug_auth or str_to_bool(env_vars.get('DEBUG', 'false'))

    if not fleet_url:
        logger.error("FLEET_URL is required (set in .env or use --fleet-url)")
        return 1
    if not (api_token or (email and password)):
        logger.error("provide FLEET_API_TOKEN (preferred) or FLEET_EMAIL+FLEET_PASSWORD in .env")
        return 1

    # --dump-host-sample bypasses the full ETL — keep it as a thin diagnostic.
    if args.dump_host_sample:
        from src.auth import FleetAuthenticator
        if api_token:
            token = api_token
        else:
            auth = FleetAuthenticator(fleet_url, verify=not insecure)
            token = auth.login(email, password, debug=debug)
            if not token:
                logger.error("login failed")
                return 1
        ext = FleetGraphExtractor(fleet_url, token, verify=not insecure, debug=debug)
        hosts = ext.extract_host_data(team_ids=[], since=None, since_map={})
        if hosts:
            with open('hosts_sample.json', 'w') as fh:
                json.dump(hosts[0], fh, indent=2)
            logger.info("wrote hosts_sample.json (first host object)")
        else:
            logger.info("no hosts extracted")
        return 0

    team_ids: list[int] = []
    if args.teams:
        try:
            team_ids = [int(t.strip()) for t in args.teams.split(',') if t.strip()]
        except ValueError:
            logger.error("--teams must be comma-separated integers")
            return 1
    elif sys.stdin.isatty() and not args.full_scan:
        # Interactive selection requires an authenticated extractor.
        if api_token:
            tok = api_token
        else:
            from src.auth import FleetAuthenticator
            auth = FleetAuthenticator(fleet_url, verify=not insecure)
            tok = auth.login(email, password, debug=debug)
            if not tok:
                logger.error("login failed")
                return 1
        team_ids = _interactive_team_select(fleet_url, tok, insecure, debug)

    target_names = (
        [n.strip() for n in args.enrich_software.split(',')] if args.enrich_software else None
    )
    cfg = ETLConfig(
        fleet_url=fleet_url,
        memgraph_uri=memgraph_uri,
        api_token=api_token,
        email=email,
        password=password,
        insecure=insecure,
        debug=debug,
        team_ids=team_ids,
        full_scan=args.full_scan,
        state_path=STATE_FILE,
        snapshot_dir=SNAPSHOT_DIR,
        enrich_limit=None if args.complete_enrichment else 250,
        enrich_target_names=target_names,
    )

    logger.info("extracting from Fleet url=%s", fleet_url)
    if insecure:
        logger.warning("TLS verification disabled (dev only)")

    result = run_etl(cfg)

    if result.error:
        logger.error("ETL failed: %s", result.error)
        return 1
    logger.info("hosts extracted count=%d", result.hosts_extracted)
    logger.info("users extracted count=%d", result.users_extracted)
    if result.enrichment_error:
        logger.warning("enrichment: %s", result.enrichment_error)
    if result.snapshot_path:
        logger.info("snapshot path=%s", result.snapshot_path)
    elif result.snapshot_error:
        logger.warning("snapshot: %s", result.snapshot_error)
    logger.info("duration elapsed=%.1fs", result.duration_sec)
    logger.info("synced teams=%s", result.teams_synced or "all")
    logger.info("dashboard url=http://localhost:8080")
    return 0


if __name__ == "__main__":
    sys.exit(main())
