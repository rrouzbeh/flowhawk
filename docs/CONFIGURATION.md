# Configuration Guide

This guide covers all configuration options for FlowHawk.

## Table of Contents

- [Configuration File Format](#configuration-file-format)
- [eBPF Settings](#ebpf-settings)
- [Monitoring Parameters](#monitoring-parameters)
- [Threat Detection](#threat-detection)
- [Alert Configuration](#alert-configuration)
- [Dashboard Settings](#dashboard-settings)
- [Logging Configuration](#logging-configuration)
- [Environment Variables](#environment-variables)
- [Advanced Configuration](#advanced-configuration)
- [Examples](#examples)

## Configuration File Format

FlowHawk uses YAML configuration files. The default configuration file is `configs/development.yaml`.

```bash
# Specify custom config file
sudo ./flowhawk -config /path/to/config.yaml

# Use environment variable
export FLOWHAWK_CONFIG_FILE=/path/to/config.yaml
sudo ./flowhawk
```

## eBPF Settings

### XDP Configuration

```yaml
ebpf:
  xdp:
    interface: "eth0"        # Network interface to monitor
    mode: "native"           # XDP attachment mode
    enable: true             # Enable/disable XDP monitoring
```

**XDP Modes:**
- `native`: Best performance, requires driver support
- `skb`: Software fallback, works with all drivers
- `hw`: Hardware offload (requires specific hardware)

**Interface Selection:**
```bash
# List available interfaces
ip link show

# Check XDP support
ethtool -i eth0 | grep driver
```

### TC (Traffic Control) Configuration

```yaml
ebpf:
  tc:
    direction: "both"        # Traffic direction to monitor
    enable: true             # Enable/disable TC monitoring
```

**Direction Options:**
- `ingress`: Monitor incoming traffic only
- `egress`: Monitor outgoing traffic only  
- `both`: Monitor both directions (recommended)

## Monitoring Parameters

### Basic Monitoring

```yaml
monitoring:
  sampling_rate: 1000      # Sample 1 in N packets (1 = all packets)
  flow_timeout: 300s       # Flow expiration time
  max_flows: 1000000       # Maximum concurrent flows to track
  ring_buffer_size: 1048576 # Ring buffer size in bytes (1MB)
  metrics_interval: 10s    # Statistics collection interval
```

**Performance Tuning:**

| Traffic Level | Sampling Rate | Max Flows | Buffer Size |
|---------------|---------------|-----------|-------------|
| Low (< 1Gbps) | 100-1000     | 100K      | 1MB         |
| Medium (1-5Gbps) | 1000-5000 | 1M        | 4MB         |
| High (> 5Gbps) | 5000-10000  | 5M        | 8MB         |

### Memory Management

```yaml
monitoring:
  # Memory limits
  max_flows: 1000000           # Max flows in memory
  flow_cleanup_interval: 60s   # Cleanup frequency
  flow_timeout: 300s           # Flow expiration time
  
  # Buffer sizes
  ring_buffer_size: 1048576    # Packet ring buffer
  event_buffer_size: 512       # Event queue size
  
  # Sampling for high traffic
  sampling_rate: 1000          # 1 in 1000 packets
  adaptive_sampling: true      # Dynamic sampling based on load
```

## Threat Detection

### Global Threat Settings

```yaml
threats:
  enable: true                 # Master enable/disable
  detection_interval: 1s       # How often to run detection
  max_events_per_second: 1000  # Rate limit for events
```

### Port Scan Detection

```yaml
threats:
  port_scan:
    enable: true
    threshold: 100             # Connections per window
    window: 60s                # Detection window
    min_ports: 10              # Minimum ports for detection
    max_failed_ratio: 0.8      # Maximum failure rate
    whitelist:                 # Excluded source IPs
      - "192.168.1.0/24"
      - "10.0.0.0/8"
```

**Detection Algorithms:**
- **Rapid Scanning**: High connection rate in short time
- **Horizontal Scanning**: Many targets from single source
- **Stealth Scanning**: Slow but persistent attempts
- **Failed Connections**: High ratio of failed attempts

### DDoS Detection

```yaml
threats:
  ddos:
    enable: true
    pps_threshold: 100000      # Packets per second
    bps_threshold: 1000000000  # Bytes per second (1Gbps)
    window: 10s                # Detection window
    min_sources: 10            # Minimum sources for distributed attack
    amplification_ratio: 5.0   # Min ratio for amplification detection
    protocols:                 # Monitor specific protocols
      - udp
      - tcp
      - icmp
```

**Attack Types Detected:**
- **Volumetric Attacks**: High packet/byte rates
- **Distributed Attacks**: Many sources targeting single destination
- **Amplification Attacks**: DNS, NTP, Memcached reflection
- **Protocol-Specific**: SYN floods, UDP floods

### Botnet Detection

```yaml
threats:
  botnet:
    enable: true
    beacon_interval: 30s       # Expected beacon frequency
    beacon_tolerance: 0.2      # Timing variance tolerance
    min_beacons: 10            # Minimum beacons for detection
    dns_tunneling: true        # Enable DNS tunneling detection
    c2_domains:                # Known C2 domains
      - "malware-c2.com"
      - "botnet-controller.net"
      - "*.suspicious-tld"
    suspicious_ports:          # Non-standard ports
      - 8080
      - 8443
      - 9050
```

**Detection Methods:**
- **Beaconing Analysis**: Regular communication patterns
- **Domain Reputation**: Known malicious domains
- **DNS Tunneling**: Suspicious DNS query patterns
- **Port Analysis**: Unusual port combinations

### Data Exfiltration Detection

```yaml
threats:
  data_exfiltration:
    enable: true
    byte_threshold: 104857600  # 100MB threshold
    time_window: 3600s         # 1 hour window
    min_destinations: 3        # Multiple destinations indicator
    encrypted_ratio: 0.7       # High encryption ratio
    unusual_hours:             # Off-hours detection
      - 0  # Midnight
      - 1
      - 2
      - 23
```

### Lateral Movement Detection

```yaml
threats:
  lateral_movement:
    enable: true
    scan_threshold: 20         # Internal hosts scanned
    admin_port_threshold: 5    # Administrative port attempts
    time_window: 3600s         # Detection window
    admin_ports:               # Administrative services
      - 22   # SSH
      - 23   # Telnet
      - 135  # RPC
      - 139  # NetBIOS
      - 445  # SMB
      - 3389 # RDP
      - 5985 # WinRM
    internal_networks:         # Internal IP ranges
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
```

### Machine Learning Detection

```yaml
threats:
  ml_detection:
    enable: true
    training_window: 86400s    # 24 hours
    update_interval: 3600s     # 1 hour
    anomaly_threshold: 2.5     # Standard deviations
    min_samples: 100           # Minimum samples for model
    features:                  # Enabled features
      - packet_size
      - inter_arrival_time
      - protocol_distribution
      - port_entropy
      - time_patterns
```

## Alert Configuration

### Global Alert Settings

```yaml
alerts:
  enable: true
  severity_threshold: "medium"  # Minimum severity to alert
  rate_limit: 100              # Max alerts per minute
  deduplication_window: 300s   # Suppress duplicate alerts
```

### Webhook Alerts (Slack/Discord/Teams)

```yaml
alerts:
  webhook:
    enable: true
    url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    timeout: 10s
    retry_attempts: 3
    retry_delay: 5s
    headers:
      Content-Type: "application/json"
      Authorization: "Bearer TOKEN"
    template: "slack"          # slack, discord, teams, custom
    custom_template: |
      {
        "text": "🚨 Security Alert",
        "attachments": [{
          "color": "{{ .SeverityColor }}",
          "title": "{{ .ThreatType }}",
          "text": "{{ .Description }}"
        }]
      }
```

### Email Alerts

```yaml
alerts:
  email:
    enable: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "alerts@company.com"
    password: "app-password"
    from: "FlowHawk <alerts@company.com>"
    to:
      - "security@company.com"
      - "soc@company.com"
    cc:
      - "management@company.com"
    subject_template: "[SECURITY] {{ .Severity }} - {{ .ThreatType }}"
    html_template: true
    attachment_logs: false
```

### Syslog Integration

```yaml
alerts:
  syslog:
    enable: true
    network: "udp"             # tcp, udp, unix
    address: "localhost:514"
    facility: "local0"         # syslog facility
    severity: "warning"        # syslog severity
    tag: "flowhawk"
    format: "rfc3164"          # rfc3164, rfc5424
```

### Custom Alert Channels

```yaml
alerts:
  custom:
    enable: true
    command: "/usr/local/bin/custom-alert.sh"
    timeout: 30s
    environment:
      ALERT_ENDPOINT: "https://api.custom-siem.com/alerts"
      API_KEY: "your-api-key"
    template: |
      {
        "timestamp": "{{ .Timestamp }}",
        "severity": "{{ .Severity }}",
        "source": "{{ .SrcIP }}",
        "destination": "{{ .DstIP }}",
        "description": "{{ .Description }}"
      }
```

## Dashboard Settings

### Basic Dashboard Configuration

```yaml
dashboard:
  listen_addr: ":8080"         # Listen address and port
  enable_auth: false           # Enable authentication
  retention_days: 7            # Data retention period
  update_interval: 1s          # Real-time update frequency
  max_connections: 1000        # Maximum WebSocket connections
```

### TLS Configuration

```yaml
dashboard:
  tls:
    enable: true
    cert_file: "/etc/ssl/certs/monitor.crt"
    key_file: "/etc/ssl/private/monitor.key"
    min_version: "1.2"         # Minimum TLS version
    cipher_suites:             # Allowed cipher suites
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### Authentication

```yaml
dashboard:
  auth:
    enable: true
    method: "basic"            # basic, oauth, ldap
    users:                     # Basic auth users
      admin:
        password_hash: "$2a$10$..."
        roles: ["admin"]
      viewer:
        password_hash: "$2a$10$..."
        roles: ["read-only"]
    session_timeout: 3600s     # Session expiration
    max_login_attempts: 5      # Rate limiting
```

### CORS Configuration

```yaml
dashboard:
  cors:
    enabled: true
    allowed_origins:
      - "https://dashboard.company.com"
      - "https://monitoring.company.com"
    allowed_methods:
      - "GET"
      - "POST"
    allowed_headers:
      - "Authorization"
      - "Content-Type"
    max_age: 86400
```

## Logging Configuration

### Basic Logging

```yaml
logging:
  level: "info"                # debug, info, warn, error
  format: "json"               # json, text
  output: "stdout"             # stdout, file, syslog
  file_path: "/var/log/flowhawk.log"
  max_size: 100                # Max file size in MB
  max_backups: 10              # Number of backup files
  max_age: 30                  # Days to retain logs
  compress: true               # Compress old logs
```

### Structured Logging

```yaml
logging:
  structured: true
  fields:                      # Additional fields in all logs
    service: "flowhawk"
    version: "1.0.0"
    environment: "production"
  correlation_id: true         # Add correlation IDs
  request_logging: true        # Log HTTP requests
  sensitive_fields:            # Fields to redact
    - "password"
    - "token"
    - "key"
```

### Log Levels by Component

```yaml
logging:
  levels:
    root: "info"
    ebpf: "debug"              # eBPF program logs
    threats: "info"            # Threat detection logs
    alerts: "warn"             # Alert system logs
    dashboard: "error"         # Dashboard logs
```

## Environment Variables

Configuration can be overridden with environment variables:

```bash
# eBPF settings
export FLOWHAWK_XDP_INTERFACE="eth1"
export FLOWHAWK_XDP_MODE="skb"

# Monitoring settings
export FLOWHAWK_SAMPLING_RATE="5000"
export FLOWHAWK_MAX_FLOWS="500000"

# Threat detection
export FLOWHAWK_THREATS_ENABLE="true"
export FLOWHAWK_THREATS_PORT_SCAN_THRESHOLD="50"

# Alerts
export FLOWHAWK_ALERTS_WEBHOOK_URL="https://hooks.slack.com/..."
export FLOWHAWK_ALERTS_EMAIL_SMTP="smtp.company.com:587"

# Dashboard
export FLOWHAWK_DASHBOARD_LISTEN_ADDR=":9090"
export FLOWHAWK_DASHBOARD_ENABLE_AUTH="true"

# Logging
export LOG_LEVEL="debug"
export LOG_FORMAT="json"
```

## Advanced Configuration

### Performance Optimization

```yaml
performance:
  cpu_affinity: [0, 1]         # Pin to specific CPU cores
  numa_node: 0                 # NUMA node preference
  hugepages: true              # Use hugepages for buffers
  zero_copy: true              # Enable zero-copy optimizations
  batch_size: 64               # Event batch processing size
  worker_threads: 4            # Number of worker threads
```

### Custom eBPF Programs

```yaml
ebpf:
  custom_programs:
    - name: "custom_filter"
      path: "/etc/flowhawk/custom_filter.o"
      attach_point: "xdp"
      priority: 100
    - name: "custom_tracer"
      path: "/etc/flowhawk/custom_tracer.o"
      attach_point: "tracepoint"
      event: "syscalls:sys_enter_connect"
```

### Integration Settings

```yaml
integrations:
  prometheus:
    enable: true
    listen_addr: ":9090"
    path: "/metrics"
    namespace: "flowhawk"
  
  grafana:
    enable: true
    datasource_url: "http://prometheus:9090"
    dashboard_path: "/etc/grafana/dashboards"
  
  elasticsearch:
    enable: true
    hosts:
      - "https://elasticsearch:9200"
    index: "flowhawk"
    username: "elastic"
    password: "password"
```

## Examples

### Development Configuration

```yaml
# configs/development.yaml
ebpf:
  xdp:
    interface: "lo"
    mode: "skb"
    enable: true

monitoring:
  sampling_rate: 1
  max_flows: 10000
  ring_buffer_size: 65536

threats:
  enable: true
  port_scan:
    threshold: 5
    window: 10s

alerts:
  enable: false

dashboard:
  listen_addr: ":8080"
  enable_auth: false

logging:
  level: "debug"
  format: "text"
  output: "stdout"
```

### High-Traffic Production

```yaml
# configs/high-traffic.yaml
ebpf:
  xdp:
    interface: "eth0"
    mode: "native"
    enable: true

monitoring:
  sampling_rate: 10000
  max_flows: 10000000
  ring_buffer_size: 8388608
  metrics_interval: 5s

threats:
  enable: true
  detection_interval: 1s
  max_events_per_second: 10000

alerts:
  enable: true
  rate_limit: 500
  webhook:
    url: "https://hooks.slack.com/..."

dashboard:
  listen_addr: ":8080"
  max_connections: 5000
  update_interval: 2s

logging:
  level: "warn"
  format: "json"
  output: "file"
  file_path: "/var/log/flowhawk.log"

performance:
  cpu_affinity: [0, 1, 2, 3]
  worker_threads: 8
  batch_size: 128
```

### Security-Focused Configuration

```yaml
# configs/security.yaml
ebpf:
  xdp:
    interface: "eth0"
    mode: "native"
    enable: true

threats:
  enable: true
  port_scan:
    enable: true
    threshold: 10
    window: 30s
  ddos:
    enable: true
    pps_threshold: 50000
    window: 5s
  botnet:
    enable: true
    c2_domains:
      - "*.tk"
      - "*.ml"
      - "dyndns.org"
  lateral_movement:
    enable: true
    scan_threshold: 5
    admin_port_threshold: 3

alerts:
  enable: true
  severity_threshold: "low"
  email:
    enable: true
    to: ["security@company.com"]
  webhook:
    enable: true
    url: "https://hooks.slack.com/..."

dashboard:
  enable_auth: true
  tls:
    enable: true
    cert_file: "/etc/ssl/certs/monitor.crt"
    key_file: "/etc/ssl/private/monitor.key"

logging:
  level: "info"
  format: "json"
  output: "file"
  structured: true
```

For more examples, see the `configs/` directory in the repository.