package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowhawk/pkg/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg == nil {
		t.Fatal("Expected default config to be created, got nil")
	}

	// Test EBPF defaults
	if cfg.EBPF.XDP.Interface != "eth0" {
		t.Errorf("Expected default XDP interface eth0, got %s", cfg.EBPF.XDP.Interface)
	}
	if cfg.EBPF.XDP.Mode != "native" {
		t.Errorf("Expected default XDP mode native, got %s", cfg.EBPF.XDP.Mode)
	}
	if !cfg.EBPF.XDP.Enable {
		t.Errorf("Expected XDP to be enabled by default")
	}
	if cfg.EBPF.TC.Direction != "both" {
		t.Errorf("Expected default TC direction both, got %s", cfg.EBPF.TC.Direction)
	}
	if !cfg.EBPF.TC.Enable {
		t.Errorf("Expected TC to be enabled by default")
	}

	// Test Monitoring defaults
	if cfg.Monitoring.SamplingRate != 1000 {
		t.Errorf("Expected default sampling rate 1000, got %d", cfg.Monitoring.SamplingRate)
	}
	if cfg.Monitoring.FlowTimeout != 5*time.Minute {
		t.Errorf("Expected default flow timeout 5m, got %v", cfg.Monitoring.FlowTimeout)
	}
	if cfg.Monitoring.MaxFlows != 1000000 {
		t.Errorf("Expected default max flows 1000000, got %d", cfg.Monitoring.MaxFlows)
	}
	if cfg.Monitoring.MetricsInterval != 10*time.Second {
		t.Errorf("Expected default metrics interval 10s, got %v", cfg.Monitoring.MetricsInterval)
	}

	// Test Threats defaults
	if !cfg.Threats.Enable {
		t.Errorf("Expected threats to be enabled by default")
	}
	if cfg.Threats.PortScan.Threshold != 100 {
		t.Errorf("Expected default port scan threshold 100, got %d", cfg.Threats.PortScan.Threshold)
	}
	if cfg.Threats.DDoS.PPSThreshold != 100000 {
		t.Errorf("Expected default DDoS PPS threshold 100000, got %d", cfg.Threats.DDoS.PPSThreshold)
	}

	// Test Alerts defaults
	if cfg.Alerts.Enable {
		t.Errorf("Expected alerts to be disabled by default")
	}
	if cfg.Alerts.SeverityThreshold != "medium" {
		t.Errorf("Expected default severity threshold medium, got %s", cfg.Alerts.SeverityThreshold)
	}

	// Test Dashboard defaults
	if cfg.Dashboard.ListenAddr != ":8080" {
		t.Errorf("Expected default listen addr :8080, got %s", cfg.Dashboard.ListenAddr)
	}
	if cfg.Dashboard.EnableAuth {
		t.Errorf("Expected auth to be disabled by default")
	}

	// Test Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("Expected default log level info, got %s", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Expected default log format text, got %s", cfg.Logging.Format)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		modifyFunc  func(*config.Config)
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "valid default config",
			modifyFunc:  func(c *config.Config) {},
			shouldError: false,
		},
		{
			name: "invalid XDP mode",
			modifyFunc: func(c *config.Config) {
				c.EBPF.XDP.Mode = "invalid"
			},
			shouldError: true,
			errorMsg:    "invalid XDP mode",
		},
		{
			name: "invalid TC direction",
			modifyFunc: func(c *config.Config) {
				c.EBPF.TC.Direction = "invalid"
			},
			shouldError: true,
			errorMsg:    "invalid TC direction",
		},
		{
			name: "invalid severity threshold",
			modifyFunc: func(c *config.Config) {
				c.Alerts.SeverityThreshold = "invalid"
			},
			shouldError: true,
			errorMsg:    "invalid severity threshold",
		},
		{
			name: "invalid log level",
			modifyFunc: func(c *config.Config) {
				c.Logging.Level = "invalid"
			},
			shouldError: true,
			errorMsg:    "invalid log level",
		},
		{
			name: "valid XDP modes",
			modifyFunc: func(c *config.Config) {
				c.EBPF.XDP.Mode = "skb"
			},
			shouldError: false,
		},
		{
			name: "valid TC directions",
			modifyFunc: func(c *config.Config) {
				c.EBPF.TC.Direction = "ingress"
			},
			shouldError: false,
		},
		{
			name: "valid severity thresholds",
			modifyFunc: func(c *config.Config) {
				c.Alerts.SeverityThreshold = "critical"
			},
			shouldError: false,
		},
		{
			name: "valid log levels",
			modifyFunc: func(c *config.Config) {
				c.Logging.Level = "debug"
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			tt.modifyFunc(cfg)

			err := cfg.Validate()
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected validation error but got none")
				} else if tt.errorMsg != "" && !containsSubstring(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no validation error, got: %v", err)
				}
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Test valid config file
	validConfigPath := filepath.Join(tmpDir, "valid.yaml")
	validConfigContent := `
ebpf:
  xdp:
    interface: "eth1"
    mode: "skb"
    enable: true
  tc:
    direction: "ingress"
    enable: false
monitoring:
  sampling_rate: 500
  flow_timeout: "2m"
  max_flows: 500000
  ring_buffer_size: 512000
  metrics_interval: "5s"
threats:
  enable: true
  port_scan:
    threshold: 50
    window: "30s"
    enable: true
  ddos:
    pps_threshold: 50000
    bps_threshold: 500000000
    window: "5s"
    enable: true
  botnet:
    c2_domains: ["evil.com", "badactor.net"]
    dns_tunneling: false
    beacon_interval: "60s"
    enable: false
alerts:
  webhook_url: "https://example.com/webhook"
  email_smtp: "smtp.example.com:587"
  email_user: "test@example.com"
  email_password: "secret"
  email_to: "admin@example.com"
  severity_threshold: "high"
  enable: true
dashboard:
  listen_addr: ":9090"
  enable_auth: true
  retention_days: 14
  tls_cert: "/path/to/cert.pem"
  tls_key: "/path/to/key.pem"
  update_interval: "2s"
logging:
  level: "debug"
  format: "json"
  output: "file"
  file_path: "/var/log/flowhawk.log"
`

	err := os.WriteFile(validConfigPath, []byte(validConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := config.LoadFromFile(validConfigPath)
	if err != nil {
		t.Fatalf("LoadFromFile returned error: %v", err)
	}

	// Verify loaded values
	if cfg.EBPF.XDP.Interface != "eth1" {
		t.Errorf("Expected interface eth1, got %s", cfg.EBPF.XDP.Interface)
	}
	if cfg.EBPF.XDP.Mode != "skb" {
		t.Errorf("Expected mode skb, got %s", cfg.EBPF.XDP.Mode)
	}
	if cfg.Monitoring.SamplingRate != 500 {
		t.Errorf("Expected sampling rate 500, got %d", cfg.Monitoring.SamplingRate)
	}
	if cfg.Threats.PortScan.Threshold != 50 {
		t.Errorf("Expected port scan threshold 50, got %d", cfg.Threats.PortScan.Threshold)
	}
	if cfg.Alerts.SeverityThreshold != "high" {
		t.Errorf("Expected severity threshold high, got %s", cfg.Alerts.SeverityThreshold)
	}
	if cfg.Dashboard.ListenAddr != ":9090" {
		t.Errorf("Expected listen addr :9090, got %s", cfg.Dashboard.ListenAddr)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level debug, got %s", cfg.Logging.Level)
	}

	// Test non-existent file
	_, err = config.LoadFromFile("/non/existent/file.yaml")
	if err == nil {
		t.Errorf("Expected error for non-existent file")
	}

	// Test invalid YAML
	invalidConfigPath := filepath.Join(tmpDir, "invalid.yaml")
	invalidConfigContent := `
invalid: yaml: content: [
`
	err = os.WriteFile(invalidConfigPath, []byte(invalidConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	_, err = config.LoadFromFile(invalidConfigPath)
	if err == nil {
		t.Errorf("Expected error for invalid YAML")
	}

	// Test invalid config values
	invalidValuesPath := filepath.Join(tmpDir, "invalid_values.yaml")
	invalidValuesContent := `
ebpf:
  xdp:
    mode: "invalid_mode"
`
	err = os.WriteFile(invalidValuesPath, []byte(invalidValuesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid values config file: %v", err)
	}

	_, err = config.LoadFromFile(invalidValuesPath)
	if err == nil {
		t.Errorf("Expected validation error for invalid config values")
	}
}

func TestSaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_save.yaml")

	cfg := config.DefaultConfig()
	cfg.EBPF.XDP.Interface = "test0"
	cfg.Monitoring.SamplingRate = 2000

	err := cfg.SaveToFile(configPath)
	if err != nil {
		t.Fatalf("SaveToFile returned error: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("Config file was not created")
	}

	// Load the saved config and verify it matches
	loadedCfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if loadedCfg.EBPF.XDP.Interface != "test0" {
		t.Errorf("Expected interface test0, got %s", loadedCfg.EBPF.XDP.Interface)
	}
	if loadedCfg.Monitoring.SamplingRate != 2000 {
		t.Errorf("Expected sampling rate 2000, got %d", loadedCfg.Monitoring.SamplingRate)
	}

	// Test save to invalid path
	err = cfg.SaveToFile("/invalid/path/config.yaml")
	if err == nil {
		t.Errorf("Expected error when saving to invalid path")
	}
}

func TestConfigStructures(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test that all nested structures are properly initialized
	if cfg.EBPF.XDP.Interface == "" {
		t.Errorf("XDP interface should not be empty")
	}
	if cfg.EBPF.TC.Direction == "" {
		t.Errorf("TC direction should not be empty")
	}
	if cfg.Monitoring.FlowTimeout == 0 {
		t.Errorf("Flow timeout should not be zero")
	}
	if cfg.Threats.PortScan.Window == 0 {
		t.Errorf("Port scan window should not be zero")
	}
	if cfg.Threats.DDoS.Window == 0 {
		t.Errorf("DDoS window should not be zero")
	}
	if cfg.Threats.Botnet.BeaconInterval == 0 {
		t.Errorf("Botnet beacon interval should not be zero")
	}
	if cfg.Dashboard.UpdateInterval == 0 {
		t.Errorf("Dashboard update interval should not be zero")
	}

	// Test that slices are properly initialized (even if empty)
	if cfg.Threats.Botnet.C2Domains == nil {
		t.Errorf("C2Domains slice should be initialized")
	}
}

func TestTimeoutFields(t *testing.T) {
	// Test that duration fields parse correctly from YAML
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "duration_test.yaml")

	configContent := `
monitoring:
  flow_timeout: "10m"
  metrics_interval: "30s"
threats:
  port_scan:
    window: "2m"
  ddos:
    window: "15s"
  botnet:
    beacon_interval: "45s"
dashboard:
  update_interval: "500ms"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write duration test config: %v", err)
	}

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile returned error: %v", err)
	}

	if cfg.Monitoring.FlowTimeout != 10*time.Minute {
		t.Errorf("Expected flow timeout 10m, got %v", cfg.Monitoring.FlowTimeout)
	}
	if cfg.Monitoring.MetricsInterval != 30*time.Second {
		t.Errorf("Expected metrics interval 30s, got %v", cfg.Monitoring.MetricsInterval)
	}
	if cfg.Threats.PortScan.Window != 2*time.Minute {
		t.Errorf("Expected port scan window 2m, got %v", cfg.Threats.PortScan.Window)
	}
	if cfg.Threats.DDoS.Window != 15*time.Second {
		t.Errorf("Expected DDoS window 15s, got %v", cfg.Threats.DDoS.Window)
	}
	if cfg.Threats.Botnet.BeaconInterval != 45*time.Second {
		t.Errorf("Expected botnet beacon interval 45s, got %v", cfg.Threats.Botnet.BeaconInterval)
	}
	if cfg.Dashboard.UpdateInterval != 500*time.Millisecond {
		t.Errorf("Expected dashboard update interval 500ms, got %v", cfg.Dashboard.UpdateInterval)
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}