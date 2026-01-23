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
- **High-Risk Category Tagging**: Instant identification of unauthorized Remote Access, File Sharing, and Dev tools.
- **Version Sprawl Detection**: Identify fragmentation risks where outdated versions persist despite patching policies.

<p align="center">
  <img src="assets/shadow_it.png" width="48%" alt="Shadow IT Detection List" />
  <img src="assets/shadow_details.png" width="48%" alt="Detection Details Modal" />
</p>

---

## 🏗️ Technical Architecture

Fleet Hound utilizes a high-performance ETL pipeline to bridge device management and graph theory.

```mermaid
graph LR
    Fleet["Fleet API"] -->|Extract| ETL["Python ETL Engine (Multithreaded)"]
    ETL -->|State Check| Persistence[".state.json"]
    ETL -->|LOAD| Memgraph[("Memgraph (In-Memory Graph)")]
    Memgraph <-->|Query/Visual| WebUI["Flask Web Dashboard (D3.js)"]
    
    subgraph "Infrastructure Layer"
    Memgraph
    WebUI
    end
```

---

## 📦 Rapid Deployment

### 1. Environment Preparation
```bash
cp .env.example .env
# Configure FLEET_URL and FLEET_API_TOKEN
```

### 2. Orchestration
```bash
./start.sh
```
- **Web Dashboard**: `http://localhost:8080`
- **Bolt Protocol**: `bolt://localhost:7687`

### 3. Data Synchronization
| Mode | Command | Frequency |
| :--- | :--- | :--- |
| **Full Baseline** | `python3 main.py --full-scan` | Weekly / Initial |
| **Delta Sync** | `python3 main.py` | Hourly / On-Demand |
| **Targeted Sync** | `python3 main.py --teams 5` | Per Incident |

---

## 🔐 Data Privacy & Sanitization
*Fleet Hound is designed with privacy-first principles.*
- **Local Sovereignty**: All graph data remains within your local Docker volumes.
- **Sanitized Exports**: Built-in capabilities to obscure PII (Usernames/Hostnames) for reporting.
- **Audit Logs**: All whitelisting/authorization actions are recorded in `audit.log`.

---

## 📄 Governance
Licensed under the **MIT License**. Maintained for modern security operations.
*Built for Security Engineers. Loved by Risk Professionals.*
