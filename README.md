# Fleet Hound 🩸🐶
> **High-Performance Infrastructure Graph Analysis & Risk Quantization for Fleet.**

[![Security: Risk Management](https://img.shields.io/badge/Security-Risk%20Management-red?style=for-the-badge&logo=securityscorecard)](https://github.com/fleetdm/fleet)
[![Platform: Fleet](https://img.shields.io/badge/Platform-Fleet-blue?style=for-the-badge&logo=fleet)](https://fleetdm.com)
[![Graph: Memgraph](https://img.shields.io/badge/Graph-Memgraph-brightgreen?style=for-the-badge&logo=neo4j)](https://memgraph.com)

---

## 🛡️ Executive Summary

**Fleet Hound** is a tier-one security asset designed for Vulnerability Management, Incident Response, and GRC teams. It transforms passive inventory data from **Fleet** into an interactive, multi-dimensional **Security Graph**, enabling teams to visualize hidden relationships, quantify attack vectors, and identify Shadow IT at scale.

![Universal Security Graph](assets/graph_view.png)

---

## ⚡ Core Capabilities

### ⚛️ Blast Radius & Impact Quantization
*Quantify the "So What?" of a compromise.*
- **Lateral Movement Modeling**: Mathematically identify potential pivot points from any compromised node.
- **Dynamic Risk Radar**: Visualize impact across Host Reach, User Exposure, and Platform Diversity.
- **Smart Exclusion Engine**: Tunable whitelisting to filter out system noise (e.g., service accounts).

<p align="center">
  <img src="assets/blast_radius.png" width="48%" />
  <img src="assets/blast_exclusion.png" width="48%" />
</p>

### 🕵️ Shadow IT & Anomaly Detection
*Reveal the "Unknown Unknowns" in your desktop and server fleet.*
- **Software Outlier Analysis**: Automatically flag applications installed on a statistically insignificant number of hosts.
- **Dynamic Enrichment**: Automatically fetch software categories and descriptions from **Wikidata** to reveal hidden risks (e.g., Identifying "VoIP" or "Remote Access" categories dynamically).
- **High-Risk Category Tagging**: Instant identification of unauthorized Remote Access, File Sharing, and Dev tools.
- **Version Sprawl Detection**: Identify fragmentation risks where outdated versions persist despite patching policies.

<p align="center">
  <img src="assets/shadow_it.png" width="48%" alt="Shadow IT Detection List" />
  <img src="assets/shadow_details.png" width="48%" alt="Detection Details Modal" />
</p>

## Technical Architecture

### Backend (Flask)
- **`/api/graph/full`**: Returns filtered overview graph (important software only)
- **`/api/host/<hostname>/software`**: Returns ALL software for specific host
- **`/api/software/<name>/hosts`**: Returns ALL hosts with specific software
- **Error Handling**: Graceful fallback for failed requests
- **Performance**: Optimized queries for 2K+ assets

### Frontend (D3.js)
- **Force Simulation**: Interactive physics-based layout
- **Node Types**: Hosts (blue), Users (green), Software (red)  
- **Drag & Drop**: Repositionable nodes with physics
- **Zoom & Pan**: Navigate large graphs efficiently
- **Type-aware Expansion**: Different endpoints for different node types

## Docker Deployment

### Build and Run
```bash
# Build the dashboard
docker build -t fleet-webviz .

# Run with custom network (recommended)
docker run -d --name fleet-webviz --network fleet-network -p 8080:8080 fleet-webviz

# Access at http://localhost:8080
```

### Development Mode
```bash
# Local development
cd webviz
python3 app.py

# Access at http://localhost:8080
```

## Configuration

### Environment Variables
- **`MEMGRAPH_URI`**: Database connection (default: `bolt://memgraph:7687`)
- **`PORT`**: Web server port (default: `8080`)

### Network Requirements
- Dashboard must be on same Docker network as Memgraph
- Uses container name `memgraph` for database connection
- External access via port 8080

## API Endpoints

### Graph Data
- `GET /api/graph/full` - Complete graph with filtering
- `GET /api/host/<hostname>/software` - All software for host
- `GET /api/software/<name>/hosts` - All hosts with software

### Response Format
```json
{
  "nodes": [
    {"id": "hostname", "type": "Host", "details": {...}},
    {"id": "software", "type": "Software", "details": {...}}
  ],
  "links": [
    {"source": "software", "target": "hostname", "type": "INSTALLED_ON"}
  ]
}
```

## Performance Optimizations

### Graph Filtering
- Shows only "important" software in main view (Chrome, Office, etc.)
- Full data available via node expansion
- Prevents visualization overload with 1800+ software packages

### API Design
- Type-specific endpoints for complete data access
- Caching-friendly structure
- Minimal payload for initial load

### Frontend Optimization
- Efficient D3.js force simulation
- Lazy loading of extended relationships
- Debounced search and filtering

## Troubleshooting

### Common Issues
```bash
# Dashboard not connecting to database
docker logs fleet-webviz

# Network connectivity issues
docker network inspect fleet-network

# Performance issues
# Check browser console for JavaScript errors
# Verify Memgraph is responsive at localhost:3000
```

### Dependencies
- Python 3.11+
- Flask web framework
- Neo4j driver for Memgraph
- D3.js for frontend visualization

---

This dashboard provides comprehensive Fleet security analysis with BloodHound-style relationship mapping and modern web interface.