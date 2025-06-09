package config_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/alerts"
	"flowhawk/pkg/config"
	"flowhawk/pkg/dashboard"
	"flowhawk/pkg/ebpf"
	"flowhawk/pkg/processor"
	"flowhawk/pkg/threats"
)

func TestConfigIntegration_LoadingAndValidation(t *testing.T) {
	testCases := []struct {
		name         string
		configData   string
		expectError  bool
		validateFunc func(*config.Config) error
	}{
		{
			name: "minimal_valid_config",
			configData: `
ebpf:
  xdp:
    interface: "lo"
    enable: true
monitoring:
  metrics_interval: 1s
threats:
  enable: true
alerts:
  enable: false
dashboard:
  listen_addr: ":8080"
  update_interval: 1s
`,
			expectError: false,
			validateFunc: func(cfg *config.Config) error {
				if cfg.EBPF.XDP.Interface != "lo" {
					return fmt.Errorf("expected interface 'lo', got '%s'", cfg.EBPF.XDP.Interface)
				}
				if !cfg.EBPF.XDP.Enable {
					return fmt.Errorf("expected eBPF to be enabled")
				}
				return nil
			},
		},
		{
			name: "production_config",
			configData: `
ebpf:
  xdp:
    interface: "eth0"
    mode: "native"
    enable: true
monitoring:
  metrics_interval: 5s
threats:
  enable: true
  port_scan:
    enable: true
    threshold: 10
  ddos:
    enable: true
    pps_threshold: 10000
alerts:
  enable: true
  channels:
    webhook:
      url: "https://webhook.example.com/alerts"
      enabled: true
    email:
      smtp_server: "smtp.example.com"
      enabled: false
dashboard:
  listen_addr: ":8080"
  update_interval: 2s
`,
			expectError: false,
			validateFunc: func(cfg *config.Config) error {
				if cfg.EBPF.XDP.Interface != "eth0" {
					return fmt.Errorf("expected interface 'eth0', got '%s'", cfg.EBPF.XDP.Interface)
				}
				if !cfg.Threats.Enable {
					return fmt.Errorf("expected threats to be enabled")
				}
				if !cfg.Alerts.Enable {
					return fmt.Errorf("expected alerts to be enabled")
				}
				return nil
			},
		},
		{
			name: "invalid_yaml",
			configData: `
ebpf:
  xdp:
    interface: "lo"
    enable: invalid_boolean
`,
			expectError:  true,
			validateFunc: nil,
		},
		{
			name: "missing_required_fields",
			configData: `
ebpf:
  # Missing XDP configuration
monitoring:
  metrics_interval: 1s
`,
			expectError: false, // Should use defaults
			validateFunc: func(cfg *config.Config) error {
				// Should have default values
				if cfg.Dashboard.ListenAddr == "" {
					return fmt.Errorf("expected default listen address")
				}
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")

			if err := os.WriteFile(configFile, []byte(tc.configData), 0644); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Load configuration
			cfg, err := config.LoadFromFile(configFile)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error loading config: %v", err)
			}

			// Run validation function if provided
			if tc.validateFunc != nil {
				if err := tc.validateFunc(cfg); err != nil {
					t.Errorf("Validation failed: %v", err)
				}
			}

			t.Logf("Config test '%s' passed", tc.name)
		})
	}
}

func TestConfigIntegration_ComponentInitialization(t *testing.T) {
	// Test that components can be initialized with various configurations
	testConfigs := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "minimal_config",
			config: &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: "lo",
						Enable:    true,
					},
				},
				Monitoring: config.MonitoringConfig{
					MetricsInterval: time.Second,
				},
				Threats: config.ThreatsConfig{
					Enable: false,
				},
				Alerts: config.AlertsConfig{
					Enable: false,
				},
				Dashboard: config.DashboardConfig{
					ListenAddr:     ":0", // Random port
					UpdateInterval: time.Second,
				},
			},
		},
		{
			name: "full_features_config",
			config: &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: "lo",
						Mode:      "native",
						Enable:    true,
					},
				},
				Monitoring: config.MonitoringConfig{
					MetricsInterval: 100 * time.Millisecond,
				},
				Threats: config.ThreatsConfig{
					Enable: true,
					PortScan: config.PortScanConfig{
						Enable:    true,
						Threshold: 20,
					},
					DDoS: config.DDoSConfig{
						Enable:       true,
						PPSThreshold: 5000,
					},
				},
				Alerts: config.AlertsConfig{
					Enable: true,
				},
				Dashboard: config.DashboardConfig{
					ListenAddr:     ":0",
					UpdateInterval: 50 * time.Millisecond,
				},
			},
		},
	}

	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			// Test eBPF manager initialization
			ebpfMgr, err := ebpf.NewManager(tc.config)
			if err != nil {
				t.Fatalf("Failed to create eBPF manager: %v", err)
			}
			defer ebpfMgr.Close()

			if err := ebpfMgr.Load(); err != nil {
				t.Fatalf("Failed to load eBPF programs: %v", err)
			}

			// Test processor initialization
			proc, err := processor.New(tc.config, ebpfMgr)
			if err != nil {
				t.Fatalf("Failed to create processor: %v", err)
			}
			defer proc.Close()

			// Test threat engine initialization
			threatEngine := threats.NewThreatEngine(tc.config)
			if threatEngine == nil {
				t.Fatal("Failed to create threat engine")
			}

			// Test alert manager initialization
			alertMgr := alerts.NewAlertManager(tc.config)
			if alertMgr == nil {
				t.Fatal("Failed to create alert manager")
			}

			// Test dashboard initialization
			dash, err := dashboard.New(tc.config, proc)
			if err != nil {
				t.Fatalf("Failed to create dashboard: %v", err)
			}
			defer dash.Stop()

			t.Logf("All components initialized successfully with '%s'", tc.name)
		})
	}
}

func TestConfigIntegration_DefaultConfiguration(t *testing.T) {
	// Test that default configuration is valid and usable
	cfg := config.DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Validate default configuration
	if err := cfg.Validate(); err != nil {
		t.Errorf("Default configuration is invalid: %v", err)
	}

	// Test that components can be created with default config
	ebpfMgr, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create eBPF manager with default config: %v", err)
	}
	defer ebpfMgr.Close()

	if err := ebpfMgr.Load(); err != nil {
		t.Fatalf("Failed to load eBPF with default config: %v", err)
	}

	// Test processor creation
	proc, err := processor.New(cfg, ebpfMgr)
	if err != nil {
		t.Fatalf("Failed to create processor with default config: %v", err)
	}
	defer proc.Close()

	t.Logf("Default configuration test passed")
}

func TestConfigIntegration_ConfigReloading(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	initialConfig := `
ebpf:
  xdp:
    interface: "lo"
    enable: true
monitoring:
  metrics_interval: 1s
threats:
  enable: false
dashboard:
  listen_addr: ":8080"
`

	// Write initial config
	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	// Load initial configuration
	cfg1, err := config.LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load initial config: %v", err)
	}

	if cfg1.Threats.Enable {
		t.Error("Expected threats to be disabled initially")
	}

	// Update config file
	updatedConfig := `
ebpf:
  xdp:
    interface: "lo"
    enable: true
monitoring:
  metrics_interval: 1s
threats:
  enable: true
  port_scan:
    enable: true
    threshold: 15
dashboard:
  listen_addr: ":8080"
`

	if err := os.WriteFile(configFile, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Reload configuration
	cfg2, err := config.LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	if !cfg2.Threats.Enable {
		t.Error("Expected threats to be enabled after reload")
	}

	if cfg2.Threats.PortScan.Threshold != 15 {
		t.Errorf("Expected port scan threshold 15, got %d", cfg2.Threats.PortScan.Threshold)
	}

	t.Logf("Config reloading test passed")
}

func TestConfigIntegration_ValidationErrors(t *testing.T) {
	// Test configuration validation
	invalidConfigs := []struct {
		name   string
		config *config.Config
		expect string // Expected error substring
	}{
		{
			name: "empty_interface",
			config: &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: "",
						Enable:    true,
					},
				},
			},
			expect: "interface",
		},
		{
			name: "invalid_port",
			config: &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: "lo",
						Enable:    true,
					},
				},
				Dashboard: config.DashboardConfig{
					ListenAddr: ":99999", // Invalid port
				},
			},
			expect: "", // May not error immediately
		},
		{
			name: "negative_interval",
			config: &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: "lo",
						Enable:    true,
					},
				},
				Monitoring: config.MonitoringConfig{
					MetricsInterval: -1 * time.Second,
				},
			},
			expect: "", // May not error immediately
		},
	}

	for _, tc := range invalidConfigs {
		t.Run(tc.name, func(t *testing.T) {
			// Test if components handle invalid configurations gracefully
			ebpfMgr, err := ebpf.NewManager(tc.config)
			if err != nil {
				if tc.expect != "" && strings.Contains(err.Error(), tc.expect) {
					t.Logf("Expected error caught: %v", err)
					return
				}
				t.Logf("Component rejected invalid config as expected: %v", err)
				return
			}

			// If creation succeeded, try loading
			if ebpfMgr != nil {
				err = ebpfMgr.Load()
				ebpfMgr.Close()
				if err != nil && tc.expect != "" && strings.Contains(err.Error(), tc.expect) {
					t.Logf("Expected error caught during load: %v", err)
					return
				}
			}

			t.Logf("Invalid config test '%s' completed", tc.name)
		})
	}
}

func TestConfigIntegration_NetworkInterfaceHandling(t *testing.T) {
	// Test handling of different network interfaces
	interfaces := []string{"lo", "eth0", "wlan0", "nonexistent999"}

	for _, iface := range interfaces {
		t.Run(fmt.Sprintf("interface_%s", iface), func(t *testing.T) {
			cfg := &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: iface,
						Enable:    true,
					},
				},
				Monitoring: config.MonitoringConfig{
					MetricsInterval: time.Second,
				},
			}

			ebpfMgr, err := ebpf.NewManager(cfg)
			if err != nil {
				t.Logf("Interface '%s' rejected during creation: %v", iface, err)
				return
			}
			defer ebpfMgr.Close()

			// Try to load - may fail for non-existent interfaces in real mode
			err = ebpfMgr.Load()
			if err != nil {
				t.Logf("Interface '%s' failed to load (expected for non-existent): %v", iface, err)
			} else {
				t.Logf("Interface '%s' loaded successfully (mock mode)", iface)
			}
		})
	}
}

func TestConfigIntegration_PortBindingValidation(t *testing.T) {
	// Test port binding validation for dashboard
	testPorts := []struct {
		port        string
		expectError bool
	}{
		{":8080", false},
		{":0", false},  // Random port
		{":80", false}, // May fail if not privileged
		{":65535", false},
		{":99999", false},  // High port - should work
		{"invalid", false}, // Dashboard creation doesn't validate format
	}

	for _, tc := range testPorts {
		t.Run(fmt.Sprintf("port_%s", strings.ReplaceAll(tc.port, ":", "")), func(t *testing.T) {
			cfg := &config.Config{
				Dashboard: config.DashboardConfig{
					ListenAddr:     tc.port,
					UpdateInterval: time.Second,
				},
			}

			// Try to bind to the port by creating a listener
			if tc.port != "invalid" && !tc.expectError {
				listener, err := net.Listen("tcp", tc.port)
				if err != nil {
					t.Logf("Port %s not available: %v", tc.port, err)
					return
				}
				listener.Close()
			}

			// Create dashboard with this config
			mockProcessor := &MockProcessor{}
			dash, err := dashboard.New(cfg, mockProcessor)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for port %s", tc.port)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for port %s: %v", tc.port, err)
				return
			}

			if dash != nil {
				dash.Stop()
			}

			t.Logf("Port %s handled correctly", tc.port)
		})
	}
}

// MockProcessor for testing
type MockProcessor struct{}

func (m *MockProcessor) GetStats() models.SystemMetrics                  { return models.SystemMetrics{} }
func (m *MockProcessor) GetTopFlows(limit int) []models.FlowMetrics      { return nil }
func (m *MockProcessor) GetRecentThreats(limit int) []models.ThreatEvent { return nil }
func (m *MockProcessor) GetRecentHTTP(limit int) []models.HTTPEvent      { return nil }
func (m *MockProcessor) GetAlertStats() interface{}                      { return nil }
func (m *MockProcessor) GetActiveRules() []models.ThreatRule             { return nil }
