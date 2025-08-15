#!/bin/bash

# PAVE MVP - Run All Services
# This script starts all services for the PAVE demo

set -e

echo "🚀 Starting PAVE MVP Services..."
echo ""

# Check if running from correct directory
if [[ ! -f "requirements.txt" ]]; then
    echo "❌ Error: Please run this script from the PAVE root directory"
    exit 1
fi

# Function to start service in background
start_service() {
    local name="$1"
    local dir="$2"
    local port="$3"
    local cmd="$4"
    
    echo "Starting $name on port $port..."
    cd "$dir"
    $cmd &
    local pid=$!
    echo "$pid" > "../.${name,,}_pid"
    cd - > /dev/null
    sleep 1
}

# Clean up any existing PIDs
cleanup() {
    echo ""
    echo "🛑 Stopping all services..."
    
    for service in issuer guest_list verifier site_a site_b; do
        pid_file=".${service}_pid"
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Stopping $service (PID $pid)..."
                kill "$pid" 2>/dev/null || true
            fi
            rm -f "$pid_file"
        fi
    done
    
    echo "✅ All services stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start all services
start_service "Issuer" "services/issuer" "8001" "py app.py"
start_service "Guest_List" "services/guest_list" "8002" "py app.py"
start_service "Verifier" "services/verifier" "8003" "py app.py"
start_service "Site_A" "site_a" "9001" "py -m http.server 9001"
start_service "Site_B" "site_b" "9002" "py -m http.server 9002"

echo ""
echo "🎉 All services started successfully!"
echo ""
echo "📝 Service URLs:"
echo "  • Issuer:     http://localhost:8001"
echo "  • Guest List: http://localhost:8002"  
echo "  • Verifier:   http://localhost:8003"
echo "  • Site A:     http://localhost:9001"
echo "  • Site B:     http://localhost:9002"
echo ""
echo "🔧 Debug URLs:"
echo "  • JWKS:       http://localhost:8001/.well-known/jwks.json"
echo "  • Head:       http://localhost:8002/log/head"
echo "  • Viewer:     http://localhost:8002/viewer?kid=fastage-k1"
echo ""
echo "💡 Demo Flow:"
echo "  1. Open http://localhost:9001 in browser"
echo "  2. Click 'Get 18+ Pass' to issue receipt"
echo "  3. Click 'Verify Pass' to verify (should succeed)"
echo "  4. Click 'Suspend Issuer' to disable issuer"
echo "  5. Click 'Verify Pass' again (should fail)"
echo "  6. Open http://localhost:9002 to test cross-origin"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for services to keep running
wait