# Installation Guide

This guide covers various installation methods for FlowHawk.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Binary Installation](#binary-installation)
- [Docker Installation](#docker-installation)
- [From Source](#from-source)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Linux kernel 4.15+ with eBPF support
- **Architecture**: x86_64, ARM64
- **Memory**: Minimum 512MB RAM, 2GB+ recommended for high traffic
- **CPU**: 2+ cores recommended
- **Network**: Root privileges required for eBPF operations

### Kernel Requirements

Check if your kernel supports eBPF:

```bash
# Check kernel version
uname -r

# Verify eBPF support
cat /proc/config.gz | gunzip | grep CONFIG_BPF
# Should show CONFIG_BPF=y and CONFIG_BPF_SYSCALL=y

# Check for XDP support
ethtool -i eth0 | grep driver
# Modern drivers (e1000e, ixgbe, i40e, etc.) support XDP
```

### Development Dependencies

For building from source:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-generic \
    linux-headers-$(uname -r) \
    golang-1.23 \
    make \
    git

# RHEL/CentOS/Fedora
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    golang \
    make \
    git

# Arch Linux
sudo pacman -S \
    clang \
    llvm \
    libbpf \
    linux-headers \
    go \
    make \
    git
```

## Binary Installation

### Download Pre-built Binary

```bash
# Download latest release
curl -LO https://github.com/alexhraber/flowhawk/releases/latest/download/flowhawk-linux-amd64.tar.gz

# Extract and install
tar -xzf flowhawk-linux-amd64.tar.gz
sudo cp flowhawk /usr/local/bin/
sudo chmod +x /usr/local/bin/flowhawk

# Create configuration directory
sudo mkdir -p /etc/flowhawk
sudo cp configs/production.yaml /etc/flowhawk/

# Create log directory
sudo mkdir -p /var/log/flowhawk
```

### Install as System Service

```bash
# Copy systemd service file
sudo cp configs/flowhawk.service /etc/systemd/system/

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable flowhawk
sudo systemctl start flowhawk

# Check status
sudo systemctl status flowhawk
```

## Docker Installation

### 🛡️ Security Notice

This tool operates in two distinct security modes:

- **🟢 Development Mode (Mock eBPF)**: Safe, simulated data, no privileges required
- **🔴 Production Mode (Real eBPF)**: ⚠️ **SIGNIFICANT SECURITY RISKS** - see warnings below

### Quick Start (Development Mode) - **RECOMMENDED**

```bash
# Build the image locally
docker build -t flowhawk:latest .

# Run in development mode (no root required)
docker run -d \
  --name flowhawk \
  -p 8080:8080 \
  -e SKIP_ROOT_CHECK=1 \
  flowhawk:latest

# Check status
docker ps
docker logs flowhawk
```

**Development Mode Features:**
- ✅ Safe for testing and demonstrations
- ✅ No system privileges required
- ✅ Complete UI/API functionality
- ✅ Cannot affect host system
- ❌ Shows simulated/fake data only

### Validation

#### Automated Validation Script

```bash
# Run comprehensive validation
./scripts/validate-docker.sh

# The script will:
# 1. Build the Docker image
# 2. Start the container
# 3. Test all API endpoints
# 4. Validate web dashboard
# 5. Run health checks
# 6. Show performance stats
# 7. Optional cleanup
```

#### Manual Validation

```bash
# Test API endpoints
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/flows
curl http://localhost:8080/api/dashboard

# Access web dashboard
open http://localhost:8080

# Health check
docker exec flowhawk curl -f http://localhost:8080/api/stats

# Check container logs
docker logs flowhawk
```

### ⚠️ Production Deployment (Real eBPF) - **SECURITY WARNING**

> **🚨 CRITICAL SECURITY WARNING**
>
> Production mode enables real eBPF monitoring with **SIGNIFICANT SECURITY RISKS**:
>
> **⚠️ Kernel-Level Access Risks:**
> - Direct access to kernel memory and data structures
> - Potential for system crashes or kernel panics
> - Access to sensitive kernel information
>
> **⚠️ Network Privacy Risks:**
> - Can intercept ALL network traffic on the host
> - May expose passwords, API keys, and private communications
> - Potential for data exfiltration
>
> **⚠️ Container Security Risks:**
> - Privileged mode provides near-root system access
> - Ability to mount host filesystems and load kernel modules
> - Risk of container escape and host compromise
>
> **⚠️ Resource Exhaustion Risks:**
> - Unlimited memory consumption potential
> - CPU exhaustion from processing loops
> - Network buffer exhaustion
>
> **Only proceed if you:**
> - Fully understand and accept these security risks
> - Have implemented appropriate security measures
> - Require real network monitoring (not just testing)
> - Are running in a controlled, isolated environment

```bash
# ⚠️ SECURITY WARNING: Read all warnings above before proceeding! ⚠️
docker run -d \
  --name flowhawk \
  --privileged \
  --network host \
  --user root \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  -p 8080:8080 \
  flowhawk:latest

# With custom configuration
docker run -d \
  --name flowhawk \
  --privileged \
  --network host \
  --restart unless-stopped \
  -v $(pwd)/configs/production.yaml:/app/configs/production.yaml:ro \
  -v /var/log/flowhawk:/app/logs \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  flowhawk:latest
```

### Teardown

```bash
# Stop and remove container
docker stop flowhawk
docker rm flowhawk

# Remove image (optional)
docker rmi flowhawk:latest
```

### Docker Compose

#### Development Mode

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  flowhawk:
    build:
      context: .
      dockerfile: Dockerfile.simple
    container_name: flowhawk
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./configs/development.yaml:/app/configs/flowhawk.yaml:ro
      - flowhawk-logs:/app/logs
    environment:
      - SKIP_ROOT_CHECK=1
      - GOMAXPROCS=4
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/stats"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  flowhawk-logs:
```

#### Production Mode

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  flowhawk:
    build:
      context: .
      dockerfile: Dockerfile.simple
    container_name: flowhawk
    privileged: true
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./configs/production.yaml:/app/configs/flowhawk.yaml:ro
      - /sys:/sys:ro
      - /proc:/proc:ro
      - flowhawk-logs:/app/logs
    environment:
      - GOMAXPROCS=4
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/stats"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  flowhawk-logs:
```

```bash
# Deploy development mode
docker-compose -f docker-compose.dev.yml up -d

# Deploy production mode
docker-compose -f docker-compose.prod.yml up -d

# Check logs
docker-compose logs -f flowhawk

# Teardown
docker-compose down
```

## From Source

### Clone and Build

```bash
# Clone repository
git clone https://github.com/alexhraber/flowhawk.git
cd flowhawk

# Install dependencies
make deps

# Build eBPF programs and Go binary
make build

# Run locally (requires root)
sudo ./build/flowhawk -config ./configs/development.yaml
```

### Development Setup

```bash
# Install development tools
make dev-setup

# Run tests
make test

# Run with live reload (development)
go run cmd/flowhawk/main.go -config ./configs/flowhawk.yaml
```

## Kubernetes Deployment

### RBAC and Security Context

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: flowhawk
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: flowhawk
rules:
- apiGroups: [""]
  resources: ["nodes", "pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: flowhawk
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flowhawk
subjects:
- kind: ServiceAccount
  name: flowhawk
  namespace: monitoring
```

### DaemonSet Deployment

```yaml
# daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: flowhawk
  namespace: monitoring
  labels:
    app: flowhawk
spec:
  selector:
    matchLabels:
      app: flowhawk
  template:
    metadata:
      labels:
        app: flowhawk
    spec:
      serviceAccountName: ebpf-monitor
      hostNetwork: true
      hostPID: true
      containers:
      - name: ebpf-monitor
        image: your-org/ebpf-net-monitor:latest
        imagePullPolicy: Always
        securityContext:
          privileged: true
          capabilities:
            add: ["SYS_ADMIN", "NET_ADMIN", "BPF"]
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        ports:
        - containerPort: 8080
          name: http
        volumeMounts:
        - name: config
          mountPath: /etc/ebpf-net-monitor
          readOnly: true
        - name: sys
          mountPath: /sys
          readOnly: true
        - name: proc
          mountPath: /proc
          readOnly: true
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        livenessProbe:
          httpGet:
            path: /api/stats
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/stats
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: flowhawk-config
      - name: sys
        hostPath:
          path: /sys
      - name: proc
        hostPath:
          path: /proc
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
```

### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: flowhawk-config
  namespace: monitoring
data:
  production.yaml: |
    ebpf:
      xdp:
        interface: "eth0"
        mode: "native"
        enable: true
      tc:
        direction: "both"
        enable: true
    monitoring:
      sampling_rate: 1000
      flow_timeout: 300s
      max_flows: 1000000
      ring_buffer_size: 1048576
      metrics_interval: 10s
    threats:
      enable: true
      port_scan:
        enable: true
        threshold: 100
        window: 60s
      ddos:
        enable: true
        pps_threshold: 100000
        bps_threshold: 1000000000
        window: 10s
    alerts:
      enable: true
      webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      severity_threshold: "medium"
    dashboard:
      listen_addr: ":8080"
      enable_auth: false
      retention_days: 7
      update_interval: 1s
    logging:
      level: "info"
      format: "json"
      output: "stdout"
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: flowhawk
  namespace: monitoring
  labels:
    app: flowhawk
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  selector:
    app: ebpf-monitor
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace monitoring

# Apply all resources
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f daemonset.yaml
kubectl apply -f service.yaml

# Check deployment
kubectl get pods -n monitoring
kubectl logs -f daemonset/flowhawk -n monitoring
```

## Verification

### Basic Functionality

```bash
# Check if service is running
sudo systemctl status flowhawk

# Test API endpoints
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/flows
curl http://localhost:8080/api/threats

# Check logs
sudo journalctl -u flowhawk -f

# Verify eBPF programs are loaded
sudo bpftool prog list | grep monitor
sudo bpftool map list | grep monitor
```

### Network Interface Testing

```bash
# Check interface configuration
ip link show eth0

# Verify XDP program attachment
sudo bpftool net list dev eth0

# Monitor packet processing
sudo bpftool prog show | grep xdp
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep ebpf
```

### Dashboard Access

```bash
# Open dashboard in browser
open http://localhost:8080

# Test WebSocket connection
wscat -c ws://localhost:8080/ws

# Check metrics endpoint
curl -s http://localhost:8080/api/dashboard | jq .
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied

```bash
# Ensure running as root
sudo ./flowhawk

# Check capabilities
getcap /usr/local/bin/flowhawk

# Verify kernel permissions
ls -la /sys/fs/bpf/
```

#### 2. eBPF Program Load Failures

```bash
# Check kernel version
uname -r

# Verify eBPF support
cat /boot/config-$(uname -r) | grep CONFIG_BPF

# Check dmesg for eBPF errors
dmesg | grep -i bpf

# Increase verbosity
sudo ./flowhawk -config ./configs/flowhawk.yaml -v
```

#### 3. Network Interface Issues

```bash
# List available interfaces
ip link show

# Check interface capabilities
ethtool -i eth0
ethtool -k eth0 | grep xdp

# Test with different XDP mode
# Edit config: mode: "skb" instead of "native"
```

#### 4. High Memory Usage

```bash
# Check memory limits in config
# Reduce max_flows, ring_buffer_size, sampling_rate

# Monitor memory usage
top -p $(pidof flowhawk)

# Check for memory leaks
valgrind --tool=memcheck ./flowhawk
```

#### 5. Docker Privileged Mode

```bash
# Ensure privileged mode
docker run --privileged ...

# Check container capabilities
docker run --rm --privileged alexhraber/flowhawk:latest \
  capsh --print

# Verify /sys and /proc mounts
docker exec -it flowhawk ls -la /sys/fs/bpf/
```

### Debug Mode

```bash
# Enable debug logging
export FLOWHAWK_DEBUG=1
sudo ./flowhawk -config ./configs/flowhawk.yaml

# Use verbose flags
sudo ./flowhawk -config ./configs/flowhawk.yaml -v -debug

# Check eBPF verifier logs
sudo bpftool prog load ./ebpf-programs/packet_monitor.o /sys/fs/bpf/test 2>&1
```

### Performance Tuning

```bash
# Optimize for high traffic
# In production.yaml:
monitoring:
  sampling_rate: 10000    # Higher sampling
  ring_buffer_size: 8388608  # 8MB buffer
  max_flows: 10000000     # 10M flows

# CPU affinity for performance
taskset -c 0,1 sudo ./flowhawk

# Check packet drop rates
cat /proc/net/dev | grep eth0
```

### Log Analysis

```bash
# Real-time log monitoring
sudo journalctl -u flowhawk -f

# Search for specific errors
sudo journalctl -u flowhawk | grep -i error

# Export logs for analysis
sudo journalctl -u flowhawk --since "1 hour ago" > flowhawk.log
```

### Quick Validation

For a complete automated validation of your Docker deployment, use the provided script:

```bash
# From the project root directory
./scripts/validate-docker.sh
```

This script performs comprehensive testing including:

- Docker image building
- Container startup validation
- All API endpoint testing
- Web dashboard verification
- Health checks
- Performance monitoring
- Optional cleanup

For additional support, please check the [troubleshooting documentation](TROUBLESHOOTING.md) or open an issue on GitHub.
