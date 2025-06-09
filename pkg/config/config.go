package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	EBPF       EBPFConfig       `yaml:"ebpf"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Threats    ThreatsConfig    `yaml:"threats"`
	Alerts     AlertsConfig     `yaml:"alerts"`
	Dashboard  DashboardConfig  `yaml:"dashboard"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// EBPFConfig contains eBPF-specific configuration
type EBPFConfig struct {
	XDP      XDPConfig      `yaml:"xdp"`
	TC       TCConfig       `yaml:"tc"`
	MapSizes MapSizesConfig `yaml:"map_sizes"`
	Sampling SamplingConfig `yaml:"sampling"`
}

// MapSizesConfig contains eBPF map size configuration
type MapSizesConfig struct {
	FlowMap   int `yaml:"flow_map"`
	StatsMap  int `yaml:"stats_map"`
	ConfigMap int `yaml:"config_map"`
}

// SamplingConfig contains packet sampling configuration
type SamplingConfig struct {
	Rate   int `yaml:"rate"`
	Offset int `yaml:"offset"`
}

// XDPConfig contains XDP program configuration
type XDPConfig struct {
	Interface string `yaml:"interface"`
	Mode      string `yaml:"mode"` // native, skb, hw
	Enable    bool   `yaml:"enable"`
}

// TCConfig contains TC program configuration
type TCConfig struct {
	Direction string `yaml:"direction"` // ingress, egress, both
	Enable    bool   `yaml:"enable"`
}

// MonitoringConfig contains monitoring parameters
type MonitoringConfig struct {
	SamplingRate    int           `yaml:"sampling_rate"`
	FlowTimeout     time.Duration `yaml:"flow_timeout"`
	MaxFlows        int           `yaml:"max_flows"`
	RingBufferSize  int           `yaml:"ring_buffer_size"`
	MetricsInterval time.Duration `yaml:"metrics_interval"`
}

// ThreatsConfig contains threat detection configuration
type ThreatsConfig struct {
	PortScan PortScanConfig `yaml:"port_scan"`
	DDoS     DDoSConfig     `yaml:"ddos"`
	Botnet   BotnetConfig   `yaml:"botnet"`
	Enable   bool           `yaml:"enable"`
}

// PortScanConfig contains port scan detection parameters
type PortScanConfig struct {
	Threshold int           `yaml:"threshold"` // connections per minute
	Window    time.Duration `yaml:"window"`
	Enable    bool          `yaml:"enable"`
}

// DDoSConfig contains DDoS detection parameters
type DDoSConfig struct {
	PPSThreshold uint64 `yaml:"pps_threshold"`
	BPSThreshold uint64 `yaml:"bps_threshold"`
	Window       time.Duration `yaml:"window"`
	Enable       bool   `yaml:"enable"`
}

// BotnetConfig contains botnet detection parameters
type BotnetConfig struct {
	C2Domains      []string      `yaml:"c2_domains"`
	DNSTunneling   bool          `yaml:"dns_tunneling"`
	BeaconInterval time.Duration `yaml:"beacon_interval"`
	Enable         bool          `yaml:"enable"`
}

// AlertsConfig contains alerting configuration
type AlertsConfig struct {
	WebhookURL        string `yaml:"webhook_url"`
	EmailSMTP         string `yaml:"email_smtp"`
	EmailUser         string `yaml:"email_user"`
	EmailPassword     string `yaml:"email_password"`
	EmailTo           string `yaml:"email_to"`
	SeverityThreshold string `yaml:"severity_threshold"` // low, medium, high, critical
	Enable            bool   `yaml:"enable"`
}

// DashboardConfig contains web dashboard configuration
type DashboardConfig struct {
	ListenAddr     string        `yaml:"listen_addr"`
	EnableAuth     bool          `yaml:"enable_auth"`
	RetentionDays  int           `yaml:"retention_days"`
	TLSCert        string        `yaml:"tls_cert"`
	TLSKey         string        `yaml:"tls_key"`
	UpdateInterval time.Duration `yaml:"update_interval"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level    string `yaml:"level"`    // debug, info, warn, error
	Format   string `yaml:"format"`   // json, text
	Output   string `yaml:"output"`   // stdout, file, syslog
	FilePath string `yaml:"file_path"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		EBPF: EBPFConfig{
			XDP: XDPConfig{
				Interface: "eth0",
				Mode:      "native",
				Enable:    true,
			},
			TC: TCConfig{
				Direction: "both",
				Enable:    true,
			},
			MapSizes: MapSizesConfig{
				FlowMap:   65536,
				StatsMap:  1024,
				ConfigMap: 64,
			},
			Sampling: SamplingConfig{
				Rate:   1,
				Offset: 0,
			},
		},
		Monitoring: MonitoringConfig{
			SamplingRate:    1000,
			FlowTimeout:     5 * time.Minute,
			MaxFlows:        1000000,
			RingBufferSize:  1024 * 1024, // 1MB
			MetricsInterval: 10 * time.Second,
		},
		Threats: ThreatsConfig{
			PortScan: PortScanConfig{
				Threshold: 100,
				Window:    time.Minute,
				Enable:    true,
			},
			DDoS: DDoSConfig{
				PPSThreshold: 100000,
				BPSThreshold: 1000000000, // 1Gbps
				Window:       10 * time.Second,
				Enable:       true,
			},
			Botnet: BotnetConfig{
				C2Domains:      []string{},
				DNSTunneling:   true,
				BeaconInterval: 30 * time.Second,
				Enable:         true,
			},
			Enable: true,
		},
		Alerts: AlertsConfig{
			SeverityThreshold: "medium",
			Enable:            false,
		},
		Dashboard: DashboardConfig{
			ListenAddr:     ":8080",
			EnableAuth:     false,
			RetentionDays:  7,
			UpdateInterval: time.Second,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
	}
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// SaveToFile saves configuration to a YAML file
func (c *Config) SaveToFile(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate XDP mode
	validModes := map[string]bool{"native": true, "skb": true, "hw": true}
	if !validModes[c.EBPF.XDP.Mode] {
		return fmt.Errorf("invalid XDP mode: %s", c.EBPF.XDP.Mode)
	}

	// Validate TC direction
	validDirections := map[string]bool{"ingress": true, "egress": true, "both": true}
	if !validDirections[c.EBPF.TC.Direction] {
		return fmt.Errorf("invalid TC direction: %s", c.EBPF.TC.Direction)
	}

	// Validate severity threshold
	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validSeverities[c.Alerts.SeverityThreshold] {
		return fmt.Errorf("invalid severity threshold: %s", c.Alerts.SeverityThreshold)
	}

	// Validate log level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}