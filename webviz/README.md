# Fleet Hound Web Dashboard

Interactive BloodHound-style security analysis dashboard with D3.js force-directed graph visualization.

## Features

### 🎨 Modern Interface
- **Light/Dark Mode**: Toggle themes for different environments
- **Interactive Graph**: D3.js force-directed visualization with physics
- **Node Expansion**: Click any node to see all related connections
- **Search & Filter**: Find specific hosts, users, or software
- **Responsive Design**: Works on desktop and mobile

### 🔍 Security Analysis
- **Host Relationships**: Click hosts to see all installed software
- **Software Distribution**: Click software to see all hosts that have it installed
- **User Access**: Visualize user-to-host relationships
- **Complete Coverage**: Bidirectional relationship mapping

### 📊 Data Views
- **Graph View**: Force-directed network visualization
- **Table View**: Sortable data tables for hosts, users, software
- **Relationship View**: Detailed connection information

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