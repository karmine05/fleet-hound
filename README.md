# Fleet Hound 🩸🐶
> **High-Performance Infrastructure Graph Analysis & Risk Quantization for Fleet.**

[![Security: Risk Management](https://img.shields.io/badge/Security-Risk%20Management-red?style=for-the-badge&logo=securityscorecard)](https://github.com/fleetdm/fleet)
[![Platform: Fleet](https://img.shields.io/badge/Platform-Fleet-blue?style=for-the-badge&logo=fleet)](https://fleetdm.com)
[![Graph: Memgraph](https://img.shields.io/badge/Graph-Memgraph-brightgreen?style=for-the-badge&logo=neo4j)](https://memgraph.com)

---

## 🛡️ Executive Summary

**Fleet Hound** transforms passive inventory data from **Fleet** into an interactive **Security Graph**. It enables security teams to visualize hidden relationships, quantify attack vectors, and identify Shadow IT at scale.

<img width="2546" height="1268" alt="image" src="https://github.com/user-attachments/assets/a1eab684-8732-49e8-b12a-b7e872fa152e" />

---

## ⚡ Core Capabilities

- **Blast Radius & Impact Quantization**: Mathematically identify potential pivot points from any compromised node.
- **Shadow IT & Anomaly Detection**: Automatically flag applications installed on a statistically insignificant number of hosts.
- **Dynamic Enrichment**: Automatically fetch software categories from **Wikidata** to reveal hidden risks.
- **Version Sprawl Detection**: Identify fragmentation risks where outdated versions persist despite patching policies.

---

## 🚀 Quick Start

### 1. Prerequisites
- **Docker & Docker Compose**
- **Python 3.11+** (for data extraction)

### 2. Setup and Start Services
The easiest way to get started is using the provided scripts:

```bash
# Clone the repository
git clone https://github.com/fleetdm/fleet-bloodhound.git
cd fleet-bloodhound/prod

# Start Memgraph and the Web Dashboard
./start.sh
```

`./start.sh` will:
1. Verify Docker installation.
2. Start Memgraph and the Web Dashboard using Docker Compose.
3. Wait for Memgraph to become healthy.
4. Optionally start the data extraction process (if credentials provided).

### 3. Access the Platform
Once started, you can access the following interfaces:

- **📊 Web Dashboard**: [http://localhost:8080](http://localhost:8080)
- **🗄️ Memgraph Lab**: [http://localhost:3000](http://localhost:3000)

### 4. Stop Services
To shut down the platform safely:

```bash
./stop.sh
```

---

## 📡 Data Extraction

Fleet Hound needs data from your Fleet server to build the security graph.

### Method A: Using `.env` (Recommended)
1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and provide your Fleet URL and API Token:
   ```env
   FLEET_URL=https://your-fleet-server.com
   FLEET_API_TOKEN=your-token-here
   ```
3. Run the extraction:
   ```bash
   python3 main.py
   ```

### Method B: Command Line Arguments
You can also provide credentials directly:
```bash
python3 main.py --fleet-url https://your-fleet-url \
               --email admin@example.com \
               --password your-password
```

> [!TIP]
> Use the `--insecure` flag if your Fleet server uses a self-signed certificate.

### Advanced Extraction Options
For fine-grained control over the data extraction process, `main.py` supports several advanced arguments:

| Argument | Description |
| :--- | :--- |
| `--teams ID,ID` | Fetch only specific Team IDs (e.g., `--teams 1,5`). |
| `--full-scan` | Ignore last run time and fetch ALL data (performs a full sync). |
| `--complete-enrichment` | Enrich ALL software in the database with Wikidata (may take a long time). |
| `--enrich-software NAME` | Comma-separated list of specific software names to enrich immediately. |
| `--insecure` | Disable TLS verification (useful for self-signed certificates). |
| `--debug-auth` | Enable verbose authentication diagnostics. |
| `--dump-host-sample` | Write a sample host object to `hosts_sample.json` and exit. |

**Example: Syncing specific teams with a full scan:**
```bash
python3 main.py --teams 1,2 --full-scan
```

---

## 📁 Technical Architecture

### Backend (Flask)
- Provides APIs for graph data (`/api/graph/full`), host-specific software, and more.
- Optimized for performance with 2K+ assets.

### Frontend (D3.js)
- Physics-based interactive graph visualization.
- Type-aware node expansion and lazy loading for large datasets.

### Database (Memgraph)
- High-performance graph database compatible with Neo4j Bolt protocol.

---

## 🔧 Troubleshooting

### View Service Logs
```bash
docker compose logs -f
```

### Reset the Database
If you need to clear all ingested data:
```bash
python3 clear_db.py --yes
```

### Common Connectivity Issues
- Ensure `fleet-webviz` and `fleet-memgraph` are running: `docker compose ps`
- Verify network connectivity: `docker network inspect fleet-network`

---

## 📄 License
This project is licensed under the MIT License - see the `LICENSE` file for details.

