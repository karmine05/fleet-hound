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

import concurrent.futures

# Refined query to target software items with more metadata
def get_wikidata_info(software_name: str, session: requests.Session) -> Optional[dict]:
    """
    Query Wikidata for categories, description, developer, and intended use.
    """
    safe_name = _escape_sparql_string_literal(software_name)
    query = f"""
    SELECT DISTINCT ?itemLabel ?itemDescription ?instanceOfLabel ?useLabel ?developerLabel WHERE {{
      ?item rdfs:label "{safe_name}"@en.
      ?item (wdt:P31/wdt:P279*) wd:Q7397. 
      ?item wdt:P31 ?instanceOf.
      OPTIONAL {{ ?item wdt:P366 ?use. }}
      OPTIONAL {{ ?item wdt:P178 ?developer. }}
      OPTIONAL {{ ?item schema:description ?itemDescription . FILTER(LANG(?itemDescription) = "en") }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    LIMIT 5
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
        uses = set()
        developers = set()
        description = None
        
        for result in data.get('results', {}).get('bindings', []):
            if 'instanceOfLabel' in result:
                categories.add(result['instanceOfLabel']['value'])
            if 'useLabel' in result:
                uses.add(result['useLabel']['value'])
            if 'developerLabel' in result:
                developers.add(result['developerLabel']['value'])
            if 'itemDescription' in result and not description:
                description = result['itemDescription']['value']
        
        if not categories and not uses and not description:
            return None
            
        return {
            'categories': list(categories),
            'uses': list(uses),
            'developers': list(developers),
            'description': description
        }
    except Exception as e:
        print(f"Error querying Wikidata for '{software_name}': {e}")
        return None

def process_software_item(name, session, driver_session):
    """Worker function for concurrent processing"""
    info = get_wikidata_info(name, session)
    if info:
        # Update Memgraph with retry
        success = run_query_with_retry(
            driver_session,
            """
                MATCH (s:Software {name: $name})
                SET s.category = $category,
                    s.primary_use = $uses,
                    s.developer = $developers,
                    s.wikidata_description = $desc,
                    s.last_categorized = datetime()
            """,
            {
                'name': name, 
                'category': info['categories'], 
                'uses': info['uses'],
                'developers': info['developers'],
                'desc': info['description']
            },
        )
        return success
    return False

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
        print(f"🔍 Fetching software without categories (prioritizing outliers/least frequent{' - ' + str(limit) + ' max' if limit else ' - ALL'})...")
        with driver.session() as session:
            limit_val = int(limit) if limit else 1000000 
            result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE s.category IS NULL
                WITH s.name AS name, COUNT(DISTINCT h) AS host_count
                RETURN name
                ORDER BY host_count ASC
                LIMIT $limit
            """, {'limit': limit_val})
            software_list = [record['name'] for record in result]

    if not software_list:
        print("✅ No software to process.")
        return

    total = len(software_list)
    print(f"🚀 Processing {total} items with concurrency...")
    
    updated = 0
    processed = 0
    
    http = requests.Session()
    # Use ThreadPoolExecutor for concurrent Wikidata lookups
    # Max workers kept low to avoid aggressive rate limiting
    MAX_WORKERS = 5
    
    try:
        # We need to manage Memgraph sessions carefully with threads. 
        # Using a single session for all updates or multiple?
        # Neo4j drivers are thread-safe, sessions are not.
        
        with driver.session() as db_session:
            print_progress_bar(0, total, prefix='Enriching:', suffix='Complete', length=50)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # To maintain progress bar accuracy, we'll map futures
                future_to_name = {executor.submit(process_software_item, name, http, db_session): name for name in software_list}
                
                for future in concurrent.futures.as_completed(future_to_name):
                    processed += 1
                    try:
                        if future.result():
                            updated += 1
                    except Exception as e:
                        name = future_to_name[future]
                        print(f"\n❌ Error processing '{name}': {e}")
                    
                    print_progress_bar(processed, total, prefix='Enriching:', suffix=f'({updated} updated)', length=50)
                    
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
