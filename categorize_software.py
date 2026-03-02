"""Enrich Software nodes in Memgraph with Wikidata categories/description.

This script is intentionally "dev" scoped, but we still treat it as production-grade:
- defensive network timeouts and rate-limit handling
- safe escaping for SPARQL literal injection/quote issues
- ensures DB driver is closed
"""

import argparse
import os
import time
from typing import Optional, Tuple, List

import requests
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError

# Load environment variables (simplified loader)
def load_env(env_path='.env'):
    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    k, v = line.split('=', 1)
                    env_vars[k.strip()] = v.strip().strip('"').strip("'")
    return env_vars

ENV = load_env()
MEMGRAPH_URI = os.environ.get('MEMGRAPH_URI') or ENV.get('MEMGRAPH_URI', 'bolt://localhost:7687')
WIKIDATA_URL = "https://query.wikidata.org/sparql"
USER_AGENT = 'FleetBloodhoundSoftwareCategorizer/1.0 (+https://github.com/fleetdm/Fleet-Bloodhound)'


def _escape_sparql_string_literal(value: str) -> str:
    """Escape a Python string so it is safe inside a SPARQL double-quoted literal."""
    # Escape backslash first, then other special characters
    return (
        value.replace('\\', '\\\\')
        .replace('"', '\\"')
        .replace('\n', '\\n')
        .replace('\r', '\\r')
        .replace('\t', '\\t')
    )

def get_wikidata_info(software_name: str, session: requests.Session) -> Optional[Tuple[List[str], Optional[str]]]:
    """
    Query Wikidata for categories and description.
    """
    safe_name = _escape_sparql_string_literal(software_name)
    # Refined query to target software items
    query = f"""
    SELECT DISTINCT ?itemLabel ?itemDescription ?instanceOfLabel ?useLabel WHERE {{
      ?item rdfs:label "{safe_name}"@en.
      ?item (wdt:P31/wdt:P279*) wd:Q7397. 
      ?item wdt:P31 ?instanceOf.
      OPTIONAL {{ ?item wdt:P366 ?use. }}
      OPTIONAL {{ ?item schema:description ?itemDescription . FILTER(LANG(?itemDescription) = "en") }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    LIMIT 10
    """
    
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/sparql-results+json'
    }
    
    try:
        response = session.get(
            WIKIDATA_URL,
            params={'query': query, 'format': 'json'},
            headers=headers,
            timeout=15,
        )
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            wait_s = int(retry_after) if (retry_after and retry_after.isdigit()) else 30
            print(f"⚠️ Rate limited by Wikidata. Waiting {wait_s}s...")
            time.sleep(wait_s)
            return None

        response.raise_for_status()
        data = response.json()
        
        categories = set()
        description = None
        
        for result in data.get('results', {}).get('bindings', []):
            if 'instanceOfLabel' in result:
                categories.add(result['instanceOfLabel']['value'])
            if 'useLabel' in result:
                categories.add(result['useLabel']['value'])
            if 'itemDescription' in result and not description:
                description = result['itemDescription']['value']
        
        return list(categories), description
    except Exception as e:
        print(f"Error querying Wikidata for '{software_name}': {e}")
        return None

def run_query_with_retry(session, query, params, max_retries=3):
    for attempt in range(max_retries):
        try:
            session.run(query, **params)
            return True
        except (TransientError, ServiceUnavailable, SessionExpired) as e:
            if attempt < max_retries - 1:
                wait_time = 0.5 * (2 ** attempt)
                time.sleep(wait_time)
            else:
                print(f"   ⚠️ Failed after {max_retries} attempts: {e}")
                return False
    return False

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', print_end="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        print_end   - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)
    # Print New Line on Complete
    if iteration == total:
        print()

def run_categorization(memgraph_uri: str = MEMGRAPH_URI, limit: Optional[int] = 500, target_names=None):
    print(f"🔗 Connecting to Memgraph at {memgraph_uri}...")
    driver = None
    try:
        driver = GraphDatabase.driver(memgraph_uri)
        with driver.session() as session:
            # Test connection
            session.run("RETURN 1")
    except Exception as e:
        if driver is not None:
            driver.close()
        print(f"❌ Could not connect to Memgraph: {e}")
        return

    if target_names:
        print(f"🔍 Fetching specific software items: {', '.join(target_names[:5])}{'...' if len(target_names) > 5 else ''}")
        software_list = target_names
    else:
        limit_clause = f"LIMIT {limit}" if limit else ""
        print(f"🔍 Fetching software without categories (prioritizing outliers/least frequent{' - ' + str(limit) + ' max' if limit else ' - ALL'})...")
        with driver.session() as session:
            result = session.run(f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE s.category IS NULL
                WITH s.name AS name, COUNT(DISTINCT h) AS host_count
                RETURN name
                ORDER BY host_count ASC
                {limit_clause}
            """)
            software_list = [record['name'] for record in result]

    if not software_list:
        print("✅ No software to process.")
        return

    total = len(software_list)
    print(f"🚀 Processing {total} items.")
    
    processed = 0
    updated = 0
    
    http = requests.Session()
    try:
        with driver.session() as session:
            # Initialize bar
            print_progress_bar(0, total, prefix='Enriching:', suffix='Complete', length=50)

            for name in software_list:
                info = get_wikidata_info(name, http)
                if info:
                    # info is (categories, desc)
                    categories, desc = info
                    if categories:
                        # Update Memgraph with retry
                        success = run_query_with_retry(
                            session,
                            """
                                MATCH (s:Software {name: $name})
                                SET s.category = $category,
                                    s.wikidata_description = $desc,
                                    s.last_categorized = datetime()
                            """,
                            {'name': name, 'category': categories, 'desc': desc},
                        )
                        if success:
                            updated += 1

                processed += 1
                print_progress_bar(processed, total, prefix='Enriching:', suffix=f'({updated} updated)', length=50)

                # Defensive sleep to avoid aggressive rate limiting
                time.sleep(0.2)
    finally:
        http.close()
        if driver is not None:
            driver.close()

    print(f"\n🎉 Enrichment finished! Updated {updated} items in Memgraph.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enrich software nodes with Wikidata categories.")
    parser.add_argument('--memgraph-uri', default=MEMGRAPH_URI, help="Memgraph Bolt URI (default: from MEMGRAPH_URI or .env)")
    parser.add_argument('--limit', type=int, default=500, help="Maximum items to process (default: 500, use 0 for ALL)")
    parser.add_argument('--names', help="Comma-separated list of specific software names to enrich")
    args = parser.parse_args()
    
    name_list = [n.strip() for n in args.names.split(',') if n.strip()] if args.names and args.names.strip() else None
    run_categorization(memgraph_uri=args.memgraph_uri, limit=None if args.limit == 0 else args.limit, target_names=name_list)
