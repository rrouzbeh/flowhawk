package models

import (
	"net"
	"time"
)

// Severity levels for threats and alerts
type Severity uint8

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Protocol types
type Protocol uint8

const (
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
	ProtocolICMP Protocol = 1
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolICMP:
		return "ICMP"
	default:
		return "Unknown"
	}
}

// PacketEvent represents a network packet event from eBPF
type PacketEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       net.IP    `json:"src_ip"`
	DstIP       net.IP    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    Protocol  `json:"protocol"`
	PacketSize  uint32    `json:"packet_size"`
	Payload     []byte    `json:"payload,omitempty"`
	Flags       uint32    `json:"flags"`
	ProcessID   uint32    `json:"process_id"`
	ProcessName string    `json:"process_name"`
}

// FlowKey uniquely identifies a network flow
type FlowKey struct {
	SrcIP    net.IP   `json:"src_ip"`
	DstIP    net.IP   `json:"dst_ip"`
	SrcPort  uint16   `json:"src_port"`
	DstPort  uint16   `json:"dst_port"`
	Protocol Protocol `json:"protocol"`
}

// FlowMetrics contains statistics about a network flow
type FlowMetrics struct {
	Key       FlowKey   `json:"key"`
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Flags     uint32    `json:"flags"`
}

// ThreatType represents different types of network threats
type ThreatType uint8

const (
	ThreatPortScan ThreatType = iota
	ThreatDDoS
	ThreatBotnet
	ThreatDataExfiltration
	ThreatLateralMovement
	ThreatDNSTunneling
	ThreatProcessAnomaly
)

func (t ThreatType) String() string {
	switch t {
	case ThreatPortScan:
		return "Port Scan"
	case ThreatDDoS:
		return "DDoS Attack"
	case ThreatBotnet:
		return "Botnet Activity"
	case ThreatDataExfiltration:
		return "Data Exfiltration"
	case ThreatLateralMovement:
		return "Lateral Movement"
	case ThreatDNSTunneling:
		return "DNS Tunneling"
	case ThreatProcessAnomaly:
		return "Process Anomaly"
	default:
		return "Unknown Threat"
	}
}

// ThreatEvent represents a detected security threat
type ThreatEvent struct {
	ID          string                 `json:"id"`
	Type        ThreatType             `json:"type"`
	Severity    Severity               `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	SrcIP       net.IP                 `json:"src_ip"`
	DstIP       net.IP                 `json:"dst_ip"`
	SrcPort     uint16                 `json:"src_port"`
	DstPort     uint16                 `json:"dst_port"`
	Protocol    Protocol               `json:"protocol"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	ProcessID   uint32                 `json:"process_id,omitempty"`
	ProcessName string                 `json:"process_name,omitempty"`
}

// HTTPEvent represents an HTTP request or response (Zeek-style fields)
type HTTPEvent struct {
	Timestamp  time.Time `json:"ts"`
	SrcIP      net.IP    `json:"id.orig_h"`
	SrcPort    uint16    `json:"id.orig_p"`
	DstIP      net.IP    `json:"id.resp_h"`
	DstPort    uint16    `json:"id.resp_p"`
	Method     string    `json:"method,omitempty"`
	Host       string    `json:"host,omitempty"`
	URI        string    `json:"uri,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Version    string    `json:"version,omitempty"`
	Direction  string    `json:"direction"` // request or response
}

// AlertAction represents what action to take when a threat is detected
type AlertAction uint8

const (
	ActionLog AlertAction = iota
	ActionAlert
	ActionBlock
	ActionDrop
)

func (a AlertAction) String() string {
	switch a {
	case ActionLog:
		return "log"
	case ActionAlert:
		return "alert"
	case ActionBlock:
		return "block"
	case ActionDrop:
		return "drop"
	default:
		return "unknown"
	}
}

// ThreatRule defines how to detect and respond to a specific threat
type ThreatRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        ThreatType             `json:"type"`
	Severity    Severity               `json:"severity"`
	Action      AlertAction            `json:"action"`
	Enabled     bool                   `json:"enabled"`
	Parameters  map[string]interface{} `json:"parameters"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// SystemMetrics contains overall system performance metrics
type SystemMetrics struct {
	Timestamp       time.Time `json:"timestamp"`
	PacketsReceived uint64    `json:"packets_received"`
	PacketsDropped  uint64    `json:"packets_dropped"`
	BytesReceived   uint64    `json:"bytes_received"`
	ActiveFlows     uint64    `json:"active_flows"`
	ThreatsDetected uint64    `json:"threats_detected"`
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     uint64    `json:"memory_usage"`
	PacketsPerSec   float64   `json:"packets_per_sec"`
	BytesPerSec     float64   `json:"bytes_per_sec"`
}

// DashboardState represents the current state for the web dashboard
type DashboardState struct {
	Metrics       SystemMetrics `json:"metrics"`
	TopFlows      []FlowMetrics `json:"top_flows"`
	RecentThreats []ThreatEvent `json:"recent_threats"`
	RecentHTTP    []HTTPEvent   `json:"recent_http"`
	ActiveRules   []ThreatRule  `json:"active_rules"`
	Timestamp     time.Time     `json:"timestamp"`
}

// AlertConfig represents configuration for a specific alert channel
type AlertConfig struct {
	Type        string            `json:"type"` // webhook, email, syslog
	Enabled     bool              `json:"enabled"`
	Parameters  map[string]string `json:"parameters"`
	MinSeverity Severity          `json:"min_severity"`
}
