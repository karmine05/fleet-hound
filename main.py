"""Fleet Hound CLI — thin shim over `src.etl.run_etl`.

The substantive work lives in `src/etl.py`. This file owns:
  * argparse + .env loading
  * interactive team selection (only meaningful for a TTY)
  * ad-hoc operator switches: --dump-host-sample, --enrich-software, etc.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from src.etl import ETLConfig, run_etl
from src.extractor import FleetGraphExtractor


# Docker runs webviz with a read-only rootfs, so the compose file points this
# at the writable config mount. Host runs keep the historical repo-root file.
STATE_FILE = os.environ.get('STATE_FILE', '.state.json')
SNAPSHOT_DIR = os.environ.get('SNAPSHOT_DIR', 'config/snapshots')

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


def _parse_team_ids(raw: str) -> list[int]:
    """Parse '1,2' into [1, 2]. Raises ValueError on non-integers."""
    return sorted({int(x.strip()) for x in raw.split(',') if x.strip()})


def _list_teams(fleet_url: str, token: str, insecure: bool, debug: bool) -> list[dict]:
    extractor = FleetGraphExtractor(fleet_url, token, verify=not insecure, debug=debug)
    return extractor.extract_teams() or []


def _print_teams(teams: list[dict]) -> None:
    print("\nAvailable teams:")
    print(f"   {'[0]':<8} No team (unassigned hosts)")
    for t in teams:
        print(f"   [{t.get('id', '?')}]".ljust(11) + f" {t.get('name', 'Unknown')}")


def _interactive_team_select(teams: list[dict]) -> list[int]:
    """Prompt until the operator names at least one valid team. No 'all' default."""
    valid = {0} | {int(t['id']) for t in teams if t.get('id') is not None}
    _print_teams(teams)
    while True:
        print("\nSelect team IDs to scan (comma-separated, e.g. '1,2'):")
        try:
            picked = _parse_team_ids(input("   > "))
        except ValueError:
            print("   team IDs must be integers")
            continue
        unknown = [t for t in picked if t not in valid]
        if not picked:
            print("   at least one team is required")
        elif unknown:
            print(f"   unknown team IDs: {unknown}")
        else:
            return picked


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-7s %(name)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )

    # Process environment wins over the file: inside Docker the values come
    # from Compose (env_file + environment), and `.env` is not baked into the
    # image. Host runs still work from the checkout's `.env`.
    env_vars = {**load_env_file('.env'), **os.environ}
    if not env_vars and not Path('.env').exists() and Path('.env.example').exists():
        logger.warning(".env file not found; copy .env.example to .env first (`cp .env.example .env`)")

    parser = argparse.ArgumentParser(
        description="Fleet Hound: Extract Fleet data and ingest into Memgraph",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--fleet-url', help='Fleet server URL (default: from .env)')
    parser.add_argument('--email', help='Fleet user email (default: from .env)')
    parser.add_argument('--api-token', help='Fleet API token (preferred)')
    parser.add_argument('--memgraph-uri', help='Memgraph URI (default: from .env or bolt://localhost:7687)')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification (dev only)')
    parser.add_argument('--debug-auth', action='store_true', help='Print auth diagnostics')
    parser.add_argument('--dump-host-sample', action='store_true', help='Write first host object to hosts_sample.json then exit')
    parser.add_argument('--teams', help="Comma-separated Team IDs (e.g. '1,2'). Required unless OODA_TEAMS is set; prompts on a TTY.")
    parser.add_argument('--full-scan', action='store_true', help='Ignore last run timestamp and refetch everything')
    parser.add_argument('--complete-enrichment', action='store_true', help='Enrich ALL uncategorized software (slow)')
    parser.add_argument('--enrich-software', help='Comma-separated software names to enrich immediately')
    args = parser.parse_args()

    fleet_url = args.fleet_url or env_vars.get('FLEET_URL')
    email = args.email or env_vars.get('FLEET_EMAIL')
    # No --password flag: a CLI password leaks via `ps` and shell history.
    password = env_vars.get('FLEET_PASSWORD')
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

    # Resolve the Fleet token once: team listing and --dump-host-sample need it.
    def _token() -> str | None:
        if api_token:
            return api_token
        from src.auth import FleetAuthenticator
        auth = FleetAuthenticator(fleet_url, verify=not insecure)
        return auth.login(email, password, debug=debug)

    # Team scope is mandatory: never fall back to scanning every team.
    teams_raw = args.teams or env_vars.get('OODA_TEAMS', '')
    try:
        team_ids = _parse_team_ids(teams_raw)
    except ValueError:
        logger.error("--teams / OODA_TEAMS must be comma-separated integers")
        return 1
    if not team_ids:
        tok = _token()
        if not tok:
            logger.error("login failed")
            return 1
        teams = _list_teams(fleet_url, tok, insecure, debug)
        if sys.stdin.isatty():
            team_ids = _interactive_team_select(teams)
        else:
            _print_teams(teams)
            logger.error("no teams selected; pass --teams or set OODA_TEAMS")
            return 1

    # --dump-host-sample bypasses the full ETL — keep it as a thin diagnostic.
    if args.dump_host_sample:
        tok = _token()
        if not tok:
            logger.error("login failed")
            return 1
        ext = FleetGraphExtractor(fleet_url, tok, verify=not insecure, debug=debug)
        first_page = next(ext.extract_host_pages(team_ids=team_ids, since=None, since_map={}), [])
        if first_page:
            # Same directory as the watermark so it stays inside the writable
            # config mount when a container runs this diagnostic.
            sample_path = Path(STATE_FILE).parent / 'hosts_sample.json'
            with open(sample_path, 'w') as fh:
                json.dump(first_page[0], fh, indent=2)
            logger.info("wrote %s (first host object)", sample_path)
        else:
            logger.info("no hosts extracted")
        return 0

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
        # The in-container enricher worker already categorizes in the background
        # (OODA skips inline enrichment for the same reason); inline it only on request.
        skip_enrichment=(str_to_bool(env_vars.get('ENRICHER_ENABLED', 'false'))
                         and not (args.complete_enrichment or target_names)),
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
    logger.info("synced teams=%s", result.teams_synced)
    logger.info("dashboard url=http://localhost:8080")
    return 0


if __name__ == "__main__":
    sys.exit(main())
