#!/usr/bin/env python3
"""Clear all data from Memgraph database."""

from neo4j import GraphDatabase

def clear_memgraph():
    """Clear all nodes and relationships from Memgraph."""
    print("Connecting to Memgraph...")
    driver = GraphDatabase.driver("bolt://localhost:7687")
    
    with driver.session() as session:
        print("Clearing all data from Memgraph...")
        session.run("MATCH (n) DETACH DELETE n")
        
        print("Dropping all constraints...")
        try:
            session.run("DROP CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;")
        except:
            pass
        try:
            session.run("DROP CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;")
        except:
            pass
        try:
            session.run("DROP CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;")
        except:
            pass
        
        # Verify database is empty
        result = session.run("MATCH (n) RETURN count(n) AS count")
        count = result.single()["count"]
        print(f"Database cleared. Remaining nodes: {count}")
    
    driver.close()
    print("✅ Memgraph database cleared successfully!")

if __name__ == "__main__":
    clear_memgraph()