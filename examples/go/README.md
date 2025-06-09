# Go Client Example

This example demonstrates how to interact with the FlowHawk API using Go.

## Features

- 📊 **System Statistics** - Real-time performance metrics
- 🚨 **Threat Monitoring** - View and acknowledge threats
- 🌊 **Flow Analysis** - Monitor network flows
- ⚡ **Real-time Updates** - WebSocket connection for live data
- 🛡️ **Custom Rules** - Create threat detection rules
- 🔧 **Command Line Interface** - Easy to use CLI

## Installation

```bash
cd examples/go
go mod tidy
go build -o monitor-client .
```

## Usage Examples

### Basic Statistics
```bash
# Get current system stats
./monitor-client -stats-only

# Output:
# ✅ Connected to eBPF Monitor
# ============================================================
# SYSTEM STATISTICS
# ============================================================
# Timestamp: 2024-01-15 10:30:15
# Packets Received: 1.2M
# Bytes Received: 987.7MB
# Active Flows: 5.4K
# Threats Detected: 42
# Packets/sec: 1500.20
# Bytes/sec: 12.3MB/s
```

### Threat Monitoring
```bash
# View recent threats only
./monitor-client -threats-only

# Output:
# ============================================================
# RECENT THREATS
# ============================================================
# 
# 🔴 PORT SCAN - HIGH
#    ID: threat-001-1642248615
#    Time: 2024-01-15 10:30:15
#    Source: 192.168.1.100:45123
#    Destination: 10.0.1.50:22
#    Description: Rapid port scan: 127 ports in 30s
#    Process: nmap (PID: 1337)
#    Metadata:
#      total_attempts: 127
#      failed_attempts: 120
#      unique_ports: 50
```

### Real-time Monitoring
```bash
# Connect to real-time WebSocket feed
./monitor-client -realtime

# Output:
# 🔴 Starting real-time monitoring (Ctrl+C to stop)...
# 🔴 Connecting to WebSocket: ws://localhost:8080/ws
# ✅ Connected to real-time stream
# 
# 🔴 REAL-TIME THREAT #1
# Type: Port Scan
# Severity: HIGH
# Source: 192.168.1.100
# Description: Rapid port scan detected
# Time: 2024-01-15 10:30:15
```

### Periodic Updates
```bash
# Monitor with 5-second intervals
./monitor-client -interval 5

# Monitor with authentication
./monitor-client -username admin -password secret

# Monitor different endpoint
./monitor-client -url http://remote-monitor:8080
```

### Create Custom Rules
```bash
# Create cryptocurrency mining detection rule
./monitor-client -create-mining-rule

# Output:
# ✅ Connected to eBPF Monitor
# ✅ Created cryptocurrency mining detection rule
```

## Command Line Options

```bash
Usage of ./monitor-client:
  -url string
        Monitor URL (default "http://localhost:8080")
  -username string
        Username for authentication
  -password string
        Password for authentication
  -stats-only
        Only print stats and exit
  -threats-only
        Only print threats and exit
  -realtime
        Monitor real-time events via WebSocket
  -interval int
        Update interval in seconds (default 10)
  -create-mining-rule
        Create example mining detection rule
```

## Code Examples

### Basic Client Usage

```go
package main

import (
    "fmt"
    "log"
)

func main() {
    // Create client
    client := NewClient("http://localhost:8080", "", "")
    
    // Get system statistics
    stats, err := client.GetStats()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Packets received: %d\n", stats.PacketsReceived)
    fmt.Printf("Active flows: %d\n", stats.ActiveFlows)
    fmt.Printf("Threats detected: %d\n", stats.ThreatsDetected)
}
```

### Threat Analysis

```go
func analyzeThreatsTrends(client *Client) {
    // Get high severity threats from last hour
    since := time.Now().Add(-time.Hour)
    threatsResp, err := client.GetThreats(100, "high", "", "", &since)
    if err != nil {
        log.Fatal(err)
    }
    
    // Analyze threat patterns
    threatTypes := make(map[string]int)
    sourceIPs := make(map[string]int)
    
    for _, threat := range threatsResp.Threats {
        threatTypes[threat.Type]++
        sourceIPs[threat.SrcIP]++
    }
    
    fmt.Println("Threat Type Distribution:")
    for threatType, count := range threatTypes {
        fmt.Printf("  %s: %d\n", threatType, count)
    }
    
    fmt.Println("Top Attack Sources:")
    for ip, count := range sourceIPs {
        if count > 5 { // Only show IPs with multiple threats
            fmt.Printf("  %s: %d threats\n", ip, count)
        }
    }
}
```

### Automated Response

```go
func automatedThreatResponse(client *Client) {
    // Get unacknowledged high severity threats
    since := time.Now().Add(-10 * time.Minute)
    threatsResp, err := client.GetThreats(50, "high", "", "", &since)
    if err != nil {
        log.Printf("Error getting threats: %v", err)
        return
    }
    
    for _, threat := range threatsResp.Threats {
        // Auto-acknowledge certain threat types
        if threat.Type == "Port Scan" {
            err := client.AcknowledgeThreat(
                threat.ID,
                "Auto-acknowledged: Known scanning pattern",
                "security_automation",
            )
            if err != nil {
                log.Printf("Failed to acknowledge threat %s: %v", threat.ID, err)
            } else {
                fmt.Printf("✅ Auto-acknowledged port scan from %s\n", threat.SrcIP)
            }
        }
        
        // Generate reports for critical threats
        if threat.Severity == "critical" {
            generateIncidentReport(threat)
        }
    }
}

func generateIncidentReport(threat ThreatEvent) {
    fmt.Printf("🚨 CRITICAL INCIDENT REPORT\n")
    fmt.Printf("Threat ID: %s\n", threat.ID)
    fmt.Printf("Type: %s\n", threat.Type)
    fmt.Printf("Source: %s:%d\n", threat.SrcIP, threat.SrcPort)
    fmt.Printf("Time: %s\n", threat.Timestamp.Format("2006-01-02 15:04:05"))
    fmt.Printf("Description: %s\n", threat.Description)
    
    // Here you could:
    // - Send to SIEM system
    // - Create JIRA ticket
    // - Send urgent notifications
    // - Trigger automated blocking
}
```

### Custom Rule Creation

```go
func createCustomSecurityRules(client *Client) {
    // Rule for detecting SQL injection attempts
    sqlInjectionRule := map[string]interface{}{
        "name":        "SQL Injection Detection",
        "description": "Detects potential SQL injection in web traffic",
        "enabled":     true,
        "conditions": []map[string]interface{}{
            {
                "field":    "dst_port",
                "operator": "in",
                "value":    []int{80, 443, 8080},
                "logic":    "and",
            },
            {
                "field":    "packet_size",
                "operator": "gt", 
                "value":    1000, // Large packets may contain injection
            },
        },
        "actions": []map[string]interface{}{
            {
                "type":     "alert",
                "severity": "high",
                "message":  "Potential SQL injection detected in web traffic",
            },
        },
    }
    
    err := client.CreateCustomRule(sqlInjectionRule)
    if err != nil {
        log.Printf("Failed to create SQL injection rule: %v", err)
    } else {
        fmt.Println("✅ Created SQL injection detection rule")
    }
    
    // Rule for detecting data exfiltration
    exfiltrationRule := map[string]interface{}{
        "name":        "Large Data Transfer Detection", 
        "description": "Detects unusually large outbound data transfers",
        "enabled":     true,
        "conditions": []map[string]interface{}{
            {
                "field":    "packet_size",
                "operator": "gt",
                "value":    8192, // Large packets
                "logic":    "and",
            },
            {
                "field":    "hour",
                "operator": "in",
                "value":    []int{0, 1, 2, 3, 4, 5}, // Off hours
            },
        },
        "actions": []map[string]interface{}{
            {
                "type":     "alert",
                "severity": "medium",
                "message":  "Large data transfer during off-hours detected",
            },
        },
    }
    
    err = client.CreateCustomRule(exfiltrationRule)
    if err != nil {
        log.Printf("Failed to create exfiltration rule: %v", err)
    } else {
        fmt.Println("✅ Created data exfiltration detection rule")
    }
}
```

### WebSocket Real-time Monitoring

```go
func advancedRealtimeMonitoring(client *Client) {
    // Channel for threat events
    threatChan := make(chan ThreatEvent, 100)
    
    // Start WebSocket monitoring in goroutine
    go func() {
        monitor := NewMonitor(client)
        
        // Custom event handler
        monitor.handleRealtimeEvent = func(msg WebSocketMessage) {
            if msg.Type == "threat_detected" {
                dataBytes, _ := json.Marshal(msg.Data)
                var threat ThreatEvent
                json.Unmarshal(dataBytes, &threat)
                
                threatChan <- threat
            }
        }
        
        monitor.MonitorRealtime()
    }()
    
    // Process threats as they arrive
    for threat := range threatChan {
        fmt.Printf("🚨 Real-time threat: %s from %s\n", threat.Type, threat.SrcIP)
        
        // Implement real-time response logic
        switch threat.Severity {
        case "critical":
            handleCriticalThreat(threat)
        case "high":
            handleHighThreat(threat)
        default:
            logThreat(threat)
        }
    }
}

func handleCriticalThreat(threat ThreatEvent) {
    fmt.Printf("🚨 CRITICAL THREAT - Immediate action required!\n")
    // Implement emergency response
    // - Block source IP
    // - Alert security team
    // - Create incident ticket
}

func handleHighThreat(threat ThreatEvent) {
    fmt.Printf("🔴 HIGH THREAT - Investigation needed\n")
    // Implement standard response
    // - Log for investigation
    // - Send alert to SOC
}

func logThreat(threat ThreatEvent) {
    fmt.Printf("📝 Threat logged: %s\n", threat.Description)
    // Standard logging
}
```

## Integration Examples

### Prometheus Metrics Export

```go
func exportPrometheusMetrics(client *Client) {
    stats, err := client.GetStats()
    if err != nil {
        return
    }
    
    // Export to Prometheus format
    fmt.Printf("# HELP ebpf_packets_received_total Total packets received\n")
    fmt.Printf("# TYPE ebpf_packets_received_total counter\n")
    fmt.Printf("ebpf_packets_received_total %d\n", stats.PacketsReceived)
    
    fmt.Printf("# HELP ebpf_threats_detected_total Total threats detected\n")
    fmt.Printf("# TYPE ebpf_threats_detected_total counter\n")
    fmt.Printf("ebpf_threats_detected_total %d\n", stats.ThreatsDetected)
    
    fmt.Printf("# HELP ebpf_flows_active Current active flows\n")
    fmt.Printf("# TYPE ebpf_flows_active gauge\n")
    fmt.Printf("ebpf_flows_active %d\n", stats.ActiveFlows)
}
```

### JSON Export for SIEM

```go
func exportSIEMData(client *Client) {
    since := time.Now().Add(-time.Hour)
    threatsResp, err := client.GetThreats(1000, "", "", "", &since)
    if err != nil {
        return
    }
    
    // Convert to SIEM format
    siemEvents := make([]map[string]interface{}, 0)
    
    for _, threat := range threatsResp.Threats {
        event := map[string]interface{}{
            "timestamp":    threat.Timestamp.Unix(),
            "source":       "ebpf-monitor",
            "event_type":   "security_threat",
            "severity":     threat.Severity,
            "threat_type":  threat.Type,
            "src_ip":       threat.SrcIP,
            "dst_ip":       threat.DstIP,
            "src_port":     threat.SrcPort,
            "dst_port":     threat.DstPort,
            "description":  threat.Description,
            "process_name": threat.ProcessName,
            "process_id":   threat.ProcessID,
        }
        siemEvents = append(siemEvents, event)
    }
    
    // Output JSON for SIEM ingestion
    jsonData, _ := json.MarshalIndent(siemEvents, "", "  ")
    fmt.Println(string(jsonData))
}
```

This Go client provides a robust foundation for integrating the eBPF Network Security Monitor into your security infrastructure and automation workflows!