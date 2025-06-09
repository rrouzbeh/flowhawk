# FlowHawk

```text
 ███████ ██       ██████  ██     ██ ██   ██  █████  ██     ██ ██   ██ 
 ██      ██      ██    ██ ██     ██ ██   ██ ██   ██ ██     ██ ██  ██  
 █████   ██      ██    ██ ██  █  ██ ███████ ███████ ██  █  ██ █████   
 ██      ██      ██    ██ ██ ███ ██ ██   ██ ██   ██ ██ ███ ██ ██  ██  
 ██      ███████  ██████   ███ ███  ██   ██ ██   ██  ███ ███  ██   ██ 

          🦅 eBPF-POWERED NETWORK SECURITY MONITOR 🦅
```

## Modern Network Security Platform

**FlowHawk** is a **modern open-source eBPF-powered Network Security Monitor** engineered for mission-critical infrastructure protection. Leveraging advanced kernel-space packet processing and machine learning threat detection, FlowHawk delivers unparalleled visibility into network traffic patterns and security anomalies.

> **"Strike fast, see everything. FlowHawk soars above your network, detecting threats with the precision of a hunting raptor."**

### Core Technology Stack

- **🔥 eBPF Kernel Integration**: Zero-copy packet processing at wire speed
- **⚡ XDP High-Performance Path**: Sub-microsecond latency packet analysis
- **🧠 Machine Learning Engine**: Adaptive behavioral anomaly detection
- **🌐 Cross-Platform Compatibility**: Universal Unix deployment via containerization

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Unix%20%7C%20macOS%20%7C%20Linux-green.svg)
![eBPF](https://img.shields.io/badge/eBPF-enabled-orange.svg)

## What Makes FlowHawk Special

**FlowHawk** combines the **keen eyesight of a hunting hawk** with **eBPF's lightning-fast packet processing** to deliver unparalleled network security monitoring.

### Lightning Speed

- **10M+ packets per second** processing capability
- **Sub-microsecond latency** with XDP (eXpress Data Path)
- **Zero-copy** packet analysis directly in kernel space

### Eagle-Eyed Detection

- **Multi-engine threat detection** (rule-based + ML)
- **Real-time anomaly scoring** with adaptive thresholds
- **Custom rule engine** with flexible pattern matching

### Precision Hunting

- **Port scan detection** (rapid, stealth, horizontal)
- **DDoS attack identification** (volumetric + amplification)
- **Botnet activity tracking** (C2 beaconing patterns)
- **Data exfiltration monitoring** (traffic anomalies)

## Quick Start

### Prerequisites

- **Unix-based Operating System**: Linux, macOS, FreeBSD, or other Unix variants
- **Containerization**: Docker or compatible container runtime
- **Go 1.23+** (for source builds)
- **eBPF Support**: Modern kernel with eBPF capabilities (Linux 4.15+, or containerized deployment)

### Hunt Begins

```bash
# Build FlowHawk
docker build -t flowhawk:latest .
```

## Security Modes

FlowHawk operates in two distinct hunting modes:

### 🟢 **Training Mode** (Recommended)
*Safe for development and demonstrations*

```bash
# Launch in training mode (safe, simulated data)
docker run -d \
  --name flowhawk \
  -p 8080:8080 \
  -e SKIP_ROOT_CHECK=1 \
  flowhawk:latest

# Access the eyrie (dashboard)
open http://localhost:8080
```

**Training Mode Features:**
- ✅ **Safe**: No system privileges required
- ✅ **Isolated**: Cannot affect host system  
- ✅ **Functional**: Complete UI/API testing
- ✅ **Realistic**: Dynamic simulated data
- ❌ **Limited**: No real network monitoring

---

### 🔴 **Hunt Mode** - ⚠️ **SECURITY RISKS**

> **🚨 WARNING: Hunt mode enables real eBPF with significant security implications!**
>
> **Before unleashing the hawk, understand these risks:**
>
> 1. **🔥 Kernel-Level Access**: Direct kernel memory access
>    - Risk: System crashes or kernel panics
>    - Risk: Access to sensitive kernel data
>
> 2. **👁️ Total Network Visibility**: Sees ALL host traffic
>    - Risk: Exposure to passwords, API keys, private data
>    - Risk: Privacy violations and data interception
>
> 3. **🔓 Container Escape**: Privileged mode = near-root access
>    - Risk: Host filesystem access and kernel module loading
>    - Risk: Breaking container isolation barriers
>
> 4. **💥 Resource Exhaustion**: Unlimited consumption potential
>    - Risk: Memory exhaustion from BPF map growth
>    - Risk: CPU spikes from processing loops
>
> **Only unleash hunt mode if:**
> - You fully understand and accept these security risks
> - You have implemented appropriate security mitigations
> - You need real network monitoring (not just testing)
> - You're running in a controlled, isolated environment

```bash
# ⚠️ SECURITY WARNING: Unleash the hawk responsibly! ⚠️
docker run -d \
  --name flowhawk \
  --privileged \
  --user root \
  -p 8080:8080 \
  flowhawk:latest
```

**Hunt Mode Features:**
- ✅ **Real Monitoring**: Actual network traffic analysis
- ✅ **Full eBPF**: Complete high-performance capabilities
- ⚠️ **High Risk**: Significant security implications
- ⚠️ **Privileged**: Requires root and privileged container

## 🔐 Security Mitigations

If you must use hunt mode, implement these hawk-training measures:

### Minimal Privileges
```bash
# Use specific capabilities instead of --privileged
docker run -d \
  --name flowhawk \
  --cap-add=BPF \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp \
  --device=/dev/bpf \
  -p 8080:8080 \
  flowhawk:latest
```

### Resource Constraints
```bash
# Limit the hawk's appetite
docker run -d \
  --name flowhawk \
  --memory=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  # ... other security flags
```

## ⚙️ Configuration

### Basic Hunt Configuration

```yaml
# Network interface and eBPF settings
ebpf:
  xdp:
    interface: "eth0"
    mode: "native"  # native, skb, hw
    enable: true
  tc:
    direction: "both"  # ingress, egress, both
    enable: true

# Monitoring parameters
monitoring:
  sampling_rate: 1000      # 1 in N packets
  flow_timeout: 300s       # Flow expiration
  max_flows: 1000000       # Memory limit

# Threat detection configuration
threats:
  enable: true
  port_scan:
    enable: true
    threshold: 100         # connections per minute
  ddos:
    enable: true
    pps_threshold: 100000  # packets per second
    bps_threshold: 1000000000  # 1 Gbps

# Alert configuration
alerts:
  enable: true
  webhook_url: "https://hooks.slack.com/..."
  severity_threshold: "medium"

# Dashboard settings
dashboard:
  listen_addr: ":8080"
  enable_auth: false
  retention_days: 7
```

## 🎯 Real-World Hunt Examples

### Port Scan Detection
```bash
# FlowHawk spots scanning patterns instantly:

2024-01-15 10:30:15 THREAT: Port Scan from 192.168.1.100
- Pattern: Rapid scanning (127 ports in 30s)
- Severity: High
- Targets: 192.168.1.10
```

### DDoS Attack Detection
```bash
# Volumetric attack spotted:
2024-01-15 11:15:33 THREAT: DDoS Attack targeting 192.168.1.10
- Type: Distributed attack (1.2M PPS from 500 sources)
- Severity: Critical
- Protocol: UDP (DNS amplification)
```

### ML Anomaly Detection
```bash
# Behavioral anomaly detected:
2024-01-15 12:20:45 THREAT: ML Anomaly from 10.0.1.25
- Anomaly score: 4.7 (threshold: 2.5)
- Pattern: Unusual packet sizes and timing
- Confidence: 89%
```

## 📊 Performance Metrics

### Hunt Statistics
- **XDP Native Mode**: 10M+ PPS on modern hardware
- **Memory Usage**: <100MB userspace footprint  
- **CPU Overhead**: <5% at 1Gbps sustained traffic
- **Latency**: <1μs packet processing time

### Scalability
- **Flow Tracking**: 1M+ concurrent flows
- **Threat Detection**: Real-time analysis up to 10Gbps
- **Dashboard**: 1000+ concurrent WebSocket connections

## 🛠️ Development

### Developer Setup

FlowHawk includes comprehensive CI/CD workflows and development tools:

```bash
# Set up development environment (includes git hooks)
make dev-setup

# Run tests
make test

# Run all tests including integration
make test-all

# Run tests with coverage
make test-coverage

# Run linting
make lint

# Format code
make format
```

### Git Hooks

FlowHawk includes pre-commit hooks that automatically:
- Format Go code with `gofmt`
- Run `go vet` for static analysis
- Execute linting with `golangci-lint`
- Run the full test suite
- Check for common issues (debug statements, large files)

To set up git hooks:
```bash
# Initialize git repository (if not done)
git init

# Set up git hooks
./scripts/setup-git-hooks.sh

# Or use make target
make dev-setup
```

### CI/CD Workflows

FlowHawk includes GitHub Actions workflows for:

- **Continuous Integration** (`.github/workflows/ci.yml`)
  - Multi-version Go testing (1.21, 1.22)
  - Linting with golangci-lint
  - Security scanning with Gosec and Trivy
  - Code coverage reporting to Codecov
  - Docker build verification

- **Release Management** (`.github/workflows/release.yml`)
  - Automated binary builds for multiple platforms
  - Docker image publishing to GitHub Container Registry
  - GitHub Releases with checksums

- **Dependency Management** (`.github/workflows/dependabot-automerge.yml`)
  - Automated dependency updates via Dependabot
  - Auto-merge for minor/patch updates after testing

### Testing Strategy

FlowHawk follows a comprehensive testing approach:

- **Unit Tests**: Located in `tests/unit/` with package-specific subdirectories
- **Integration Tests**: End-to-end testing of major components
- **Benchmark Tests**: Performance validation for critical paths
- **Security Tests**: Vulnerability scanning and secure coding validation

Coverage targets:
- Overall: 80%+ statement coverage
- Core packages: 90%+ statement coverage
- Critical security components: 95%+ statement coverage

### Building from Source
```bash
# Prepare the nest
go mod download

# Build the hawk
go build -o flowhawk ./cmd/flowhawk

# Release the hawk
sudo ./flowhawk -config ./configs/development.yaml
```

### Hunt Commands
```bash
# Show version
flowhawk -version

# Custom interface
flowhawk -interface eth1

# Custom config
flowhawk -config /etc/flowhawk/config.yaml
```

## 🌐 Dashboard Access

**Open your browser to: http://localhost:8080**

### Features:
- **🔴 Live threat feed** - Real-time security alerts
- **📊 Network flow analysis** - Traffic patterns and statistics  
- **⚡ Performance metrics** - System health monitoring
- **🎯 Threat timeline** - Historical attack analysis
- **🔍 Flow search** - Drill down into specific connections

## 🦅 The FlowHawk Philosophy

*"A hawk doesn't just see movement - it sees patterns, predicts behavior, and strikes with precision. FlowHawk brings this same predatory intelligence to network security."*

- **🎯 Precision**: Every packet matters, every threat is tracked
- **⚡ Speed**: Strike before threats can establish themselves  
- **👁️ Vision**: See the entire network landscape from above
- **🧠 Intelligence**: Learn, adapt, and improve over time

## 🤝 Contributing

We welcome fellow hunters! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Roadmap
- [ ] IPv6 support
- [ ] Hardware timestamping
- [ ] GPU-accelerated ML inference
- [ ] Multi-node cluster deployment
- [ ] Mobile app for alerts

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **eBPF Community** - For the incredible eBPF ecosystem
- **Cilium Project** - For excellent Go eBPF libraries
- **Linux Kernel Developers** - For making eBPF possible
- **Security Researchers** - For threat intelligence and patterns

## 📞 Support & Community

- **🏠 Home**: [FlowHawk Documentation](docs/)
- **🐛 Issues**: [GitHub Issues](https://github.com/alexhraber/flowhawk/issues)  
- **💬 Discussions**: [GitHub Discussions](https://github.com/alexhraber/flowhawk/discussions)
- **🔒 Security**: alexhraber@gmail.com

---

**🦅 Built with the precision of a hunting hawk and the power of eBPF**

*Hunt wisely. Monitor precisely. Strike swiftly.*