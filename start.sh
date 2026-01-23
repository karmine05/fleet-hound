# Fleet Hound Quick Start Script
# This script automates the entire setup process

set -e

echo "🩸 Fleet Hound Security Analysis Platform"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Determine docker compose command
if docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

print_success "Docker and Docker Compose are installed"
echo ""

# Step 1: Start services
print_info "Step 1: Starting Memgraph and Web Dashboard..."
$DOCKER_COMPOSE up -d --build

echo ""
print_info "Waiting for services to be healthy..."
sleep 5

# Wait for Memgraph to be ready
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if echo "RETURN 1;" | docker exec -i fleet-memgraph mgconsole --host 127.0.0.1 --port 7687 &> /dev/null; then
        print_success "Memgraph is ready!"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo -n "."
    sleep 2
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    print_error "Memgraph failed to start. Check logs with: docker logs fleet-memgraph"
    exit 1
fi

echo ""
print_success "Services are running!"
echo ""

# Step 2: Extract Fleet data
print_info "Step 2: Extract Fleet data"
echo ""

# Check if Fleet credentials are provided as arguments
if [ $# -eq 0 ]; then
    print_warning "No Fleet credentials provided. Please run data extraction manually:"
    echo ""
    echo "  python3 main.py --fleet-url https://your-fleet-url \\"
    echo "                  --email admin@example.com \\"
    echo "                  --password your-password"
    echo ""
    echo "  For self-signed certificates, add: --insecure"
    echo ""
else
    print_info "Extracting data from Fleet..."
    python3 main.py "$@"
    print_success "Data extraction complete!"
    echo ""
fi

# Display access information
echo ""
echo "=============================================="
print_success "Fleet Hound is ready!"
echo "=============================================="
echo ""
echo "📊 Web Dashboard:    http://localhost:8080"
echo "🗄️  Memgraph Lab:     http://localhost:3000"
echo "🔌 Bolt Protocol:    bolt://localhost:7687"
echo ""
echo "Useful commands:"
echo "  View logs:         $DOCKER_COMPOSE logs -f"
echo "  Stop services:     $DOCKER_COMPOSE down"
echo "  Restart services:  $DOCKER_COMPOSE restart"
echo "  Clear database:    python3 clear_db.py"
echo ""
print_info "Press Ctrl+C to stop following logs, or close this terminal."
echo ""

# Follow logs
$DOCKER_COMPOSE logs -f

