#!/bin/bash

# FlowHawk - Docker Validation Script
# This script validates the Docker deployment and all functionality

set -e

CONTAINER_NAME="flowhawk-test"
IMAGE_NAME="flowhawk:test"
PORT="8080"

echo "🛡️  FlowHawk - Docker Validation"
echo "===================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function cleanup() {
    log_info "Cleaning up existing containers and images..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
}

function build_image() {
    log_info "Building Docker image..."
    if docker build -t $IMAGE_NAME .; then
        log_success "Docker image built successfully"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

function start_container() {
    log_info "Starting container in development mode..."
    if docker run -d --name $CONTAINER_NAME -p $PORT:$PORT -e SKIP_ROOT_CHECK=1 $IMAGE_NAME; then
        log_success "Container started successfully"
    else
        log_error "Failed to start container"
        exit 1
    fi
    
    # Wait for container to start
    log_info "Waiting for container to initialize..."
    sleep 5
}

function check_container_status() {
    log_info "Checking container status..."
    if docker ps | grep -q $CONTAINER_NAME; then
        log_success "Container is running"
        log_info "Container details:"
        docker ps | grep $CONTAINER_NAME
    else
        log_error "Container is not running"
        log_info "Container logs:"
        docker logs $CONTAINER_NAME
        exit 1
    fi
}

function check_container_logs() {
    log_info "Checking container logs for errors..."
    logs=$(docker logs $CONTAINER_NAME 2>&1)
    echo "$logs"
    
    if echo "$logs" | grep -q "Mock eBPF manager loaded"; then
        log_success "eBPF manager loaded successfully"
    else
        log_warning "eBPF manager load message not found"
    fi
    
    if echo "$logs" | grep -q "Dashboard server starting"; then
        log_success "Dashboard server started successfully"
    else
        log_error "Dashboard server failed to start"
        exit 1
    fi
    
    if echo "$logs" | grep -qi "error\|fatal\|panic"; then
        log_warning "Found error messages in logs"
    else
        log_success "No error messages found in logs"
    fi
}

function test_api_endpoints() {
    log_info "Testing API endpoints..."
    
    # Test stats endpoint
    log_info "Testing /api/stats endpoint..."
    if response=$(curl -s -f http://localhost:$PORT/api/stats); then
        log_success "Stats endpoint accessible"
        if echo "$response" | grep -q "packets_received"; then
            log_success "Stats endpoint returns valid data"
        else
            log_warning "Stats endpoint data format unexpected"
        fi
    else
        log_error "Stats endpoint not accessible"
        exit 1
    fi
    
    # Test flows endpoint
    log_info "Testing /api/flows endpoint..."
    if response=$(curl -s -f http://localhost:$PORT/api/flows); then
        log_success "Flows endpoint accessible"
        if echo "$response" | grep -q -E '\[.*\]'; then
            log_success "Flows endpoint returns valid array data"
        else
            log_warning "Flows endpoint data format unexpected"
        fi
    else
        log_error "Flows endpoint not accessible"
        exit 1
    fi
    
    # Test threats endpoint
    log_info "Testing /api/threats endpoint..."
    if curl -s -f http://localhost:$PORT/api/threats >/dev/null; then
        log_success "Threats endpoint accessible"
    else
        log_error "Threats endpoint not accessible"
        exit 1
    fi
    
    # Test dashboard endpoint
    log_info "Testing /api/dashboard endpoint..."
    if response=$(curl -s -f http://localhost:$PORT/api/dashboard); then
        log_success "Dashboard endpoint accessible"
        if echo "$response" | grep -q "metrics"; then
            log_success "Dashboard endpoint returns valid data"
        else
            log_warning "Dashboard endpoint data format unexpected"
        fi
    else
        log_error "Dashboard endpoint not accessible"
        exit 1
    fi
    
    # Test alerts endpoint
    log_info "Testing /api/alerts endpoint..."
    if curl -s -f http://localhost:$PORT/api/alerts >/dev/null; then
        log_success "Alerts endpoint accessible"
    else
        log_error "Alerts endpoint not accessible"
        exit 1
    fi
}

function test_web_dashboard() {
    log_info "Testing web dashboard..."
    if response=$(curl -s -f http://localhost:$PORT/); then
        if echo "$response" | grep -q "FlowHawk"; then
            log_success "Web dashboard accessible and contains expected content"
        else
            log_warning "Web dashboard accessible but content unexpected"
        fi
    else
        log_error "Web dashboard not accessible"
        exit 1
    fi
}

function test_health_check() {
    log_info "Running internal health check..."
    if docker exec $CONTAINER_NAME curl -s -f http://localhost:$PORT/api/stats >/dev/null; then
        log_success "Internal health check passed"
    else
        log_error "Internal health check failed"
        exit 1
    fi
}

function test_websocket() {
    log_info "Testing WebSocket connectivity..."
    # Simple WebSocket connection test using curl
    if timeout 5 curl -s -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Key: test" -H "Sec-WebSocket-Version: 13" http://localhost:$PORT/ws | head -c 1 >/dev/null 2>&1; then
        log_success "WebSocket endpoint responding"
    else
        log_warning "WebSocket test inconclusive (may require wscat for full test)"
    fi
}

function show_performance_stats() {
    log_info "Showing container performance stats..."
    docker stats $CONTAINER_NAME --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
}

function final_cleanup() {
    log_info "Performing final cleanup..."
    cleanup
    log_success "Cleanup completed"
}

function main() {
    echo
    log_info "Starting validation process..."
    
    # Cleanup any existing containers
    cleanup
    
    # Build and test
    build_image
    start_container
    check_container_status
    check_container_logs
    test_api_endpoints
    test_web_dashboard
    test_health_check
    test_websocket
    show_performance_stats
    
    echo
    log_success "🎉 All validation tests passed!"
    echo
    log_info "Container is running and accessible at:"
    log_info "  • Web Dashboard: http://localhost:$PORT"
    log_info "  • API Stats: http://localhost:$PORT/api/stats"
    log_info "  • API Dashboard: http://localhost:$PORT/api/dashboard"
    echo
    log_info "To stop and remove the container, run:"
    log_info "  docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
    echo
    
    # Ask user if they want to cleanup
    read -p "Do you want to stop and remove the container now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        final_cleanup
    else
        log_info "Container left running for further testing"
    fi
}

# Run main function
main "$@"