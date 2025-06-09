package workflow_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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

// IntegrationTestSuite represents a complete FlowHawk test environment
type IntegrationTestSuite struct {
	config    *config.Config
	ebpfMgr   *ebpf.Manager
	processor *processor.EventProcessor
	dashboard *dashboard.Dashboard
	threats   *threats.ThreatEngine
	alerts    *alerts.AlertManager
	baseURL   string
}

// SetupIntegrationSuite creates a complete test environment with all components
func SetupIntegrationSuite(t *testing.T) *IntegrationTestSuite {
	// Find available port for dashboard
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Create comprehensive test configuration
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Mode:      "native",
				Enable:    true,
			},
		},
		Monitoring: config.MonitoringConfig{
			MetricsInterval: 50 * time.Millisecond,
		},
		Threats: config.ThreatsConfig{
			Enable: true,
		},
		Alerts: config.AlertsConfig{
			Enable: true,
		},
		Dashboard: config.DashboardConfig{
			ListenAddr:     fmt.Sprintf(":%d", port),
			UpdateInterval: 50 * time.Millisecond,
		},
	}

	// Create eBPF manager (mock mode)
	ebpfMgr, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create eBPF manager: %v", err)
	}

	// Load eBPF programs
	if err := ebpfMgr.Load(); err != nil {
		t.Fatalf("Failed to load eBPF programs: %v", err)
	}

	// Create threat detection engine
	threatsEngine := threats.NewThreatEngine(cfg)

	// Create alert manager
	alertMgr := alerts.NewAlertManager(cfg)

	// Create processor (central component that connects everything)
	proc, err := processor.New(cfg, ebpfMgr)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Create dashboard
	dash, err := dashboard.New(cfg, proc)
	if err != nil {
		t.Fatalf("Failed to create dashboard: %v", err)
	}

	// Start dashboard server
	ctx := context.Background()
	if err := dash.Start(ctx); err != nil {
		t.Fatalf("Failed to start dashboard: %v", err)
	}

	// Give everything time to start
	time.Sleep(100 * time.Millisecond)

	return &IntegrationTestSuite{
		config:    cfg,
		ebpfMgr:   ebpfMgr,
		processor: proc,
		dashboard: dash,
		threats:   threatsEngine,
		alerts:    alertMgr,
		baseURL:   fmt.Sprintf("http://localhost:%d", port),
	}
}

func (suite *IntegrationTestSuite) Cleanup() {
	if suite.dashboard != nil {
		suite.dashboard.Stop()
	}
	if suite.processor != nil {
		suite.processor.Close()
	}
	if suite.ebpfMgr != nil {
		suite.ebpfMgr.Close()
	}
}

func TestCompleteWorkflow_EBPFToAPIFlow(t *testing.T) {
	suite := SetupIntegrationSuite(t)
	defer suite.Cleanup()

	// Start the processor to begin event processing
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := suite.processor.Start(ctx); err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}

	// Give processor time to collect initial metrics
	time.Sleep(200 * time.Millisecond)

	// Test 1: Verify basic stats are being collected and available via API
	resp, err := http.Get(suite.baseURL + "/api/stats")
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for stats, got %d", resp.StatusCode)
	}

	var stats models.SystemMetrics
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode stats: %v", err)
	}

	// Verify we're getting realistic data (mock mode should provide sample data)
	if stats.PacketsReceived == 0 {
		t.Error("Expected non-zero packets received from eBPF manager")
	}

	// Test 2: Verify flows are being processed and available
	resp, err = http.Get(suite.baseURL + "/api/flows")
	if err != nil {
		t.Fatalf("Failed to get flows: %v", err)
	}
	defer resp.Body.Close()

	var flows []models.FlowMetrics
	if err := json.NewDecoder(resp.Body).Decode(&flows); err != nil {
		t.Fatalf("Failed to decode flows: %v", err)
	}

	// Should have at least some flows from mock data
	if len(flows) == 0 {
		t.Error("Expected flows to be processed and available via API")
	}

	// Test 3: Verify complete dashboard state integration
	resp, err = http.Get(suite.baseURL + "/api/dashboard")
	if err != nil {
		t.Fatalf("Failed to get dashboard state: %v", err)
	}
	defer resp.Body.Close()

	var dashState models.DashboardState
	if err := json.NewDecoder(resp.Body).Decode(&dashState); err != nil {
		t.Fatalf("Failed to decode dashboard state: %v", err)
	}

	// Verify integrated data
	if dashState.Metrics.PacketsReceived == 0 {
		t.Error("Dashboard should show metrics from processor")
	}
	if dashState.Timestamp.IsZero() {
		t.Error("Dashboard should have valid timestamp")
	}

	t.Logf("Integration test successful - packets: %d, flows: %d, threats: %d", 
		dashState.Metrics.PacketsReceived, 
		len(dashState.TopFlows), 
		len(dashState.RecentThreats))
}

func TestWorkflow_ThreatDetectionFlow(t *testing.T) {
	suite := SetupIntegrationSuite(t)
	defer suite.Cleanup()

	// Start processor with threat detection enabled
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := suite.processor.Start(ctx); err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}

	// Give processor time to run and potentially detect threats
	time.Sleep(300 * time.Millisecond)

	// Test threats endpoint
	resp, err := http.Get(suite.baseURL + "/api/threats")
	if err != nil {
		t.Fatalf("Failed to get threats: %v", err)
	}
	defer resp.Body.Close()

	var threats []models.ThreatEvent
	if err := json.NewDecoder(resp.Body).Decode(&threats); err != nil {
		t.Fatalf("Failed to decode threats: %v", err)
	}

	// Note: In mock mode, we may not generate actual threats
	// but the endpoint should respond correctly
	t.Logf("Threats detected: %d", len(threats))

	// Test alert stats endpoint
	resp, err = http.Get(suite.baseURL + "/api/alerts")
	if err != nil {
		t.Fatalf("Failed to get alert stats: %v", err)
	}
	defer resp.Body.Close()

	var alertStats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&alertStats); err != nil {
		t.Fatalf("Failed to decode alert stats: %v", err)
	}

	// Should have alert stats structure even if no alerts triggered
	if alertStats == nil {
		t.Error("Expected alert stats structure")
	}

	t.Logf("Alert stats retrieved successfully")
}

func TestWorkflow_ConfigurationIntegration(t *testing.T) {
	// Test different configuration scenarios
	testCases := []struct {
		name      string
		modifyConfig func(*config.Config)
		expectError  bool
	}{
		{
			name: "threatsDisabled",
			modifyConfig: func(cfg *config.Config) {
				cfg.Threats.Enable = false
			},
			expectError: false,
		},
		{
			name: "alertsDisabled", 
			modifyConfig: func(cfg *config.Config) {
				cfg.Alerts.Enable = false
			},
			expectError: false,
		},
		{
			name: "fastMetrics",
			modifyConfig: func(cfg *config.Config) {
				cfg.Monitoring.MetricsInterval = 10 * time.Millisecond
				cfg.Dashboard.UpdateInterval = 10 * time.Millisecond
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Find available port
			listener, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatalf("Failed to find available port: %v", err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()

			cfg := &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: "lo",
						Enable:    true,
					},
				},
				Monitoring: config.MonitoringConfig{
					MetricsInterval: 100 * time.Millisecond,
				},
				Threats: config.ThreatsConfig{
					Enable: true,
				},
				Alerts: config.AlertsConfig{
					Enable: true,
				},
				Dashboard: config.DashboardConfig{
					ListenAddr:     fmt.Sprintf(":%d", port),
					UpdateInterval: 100 * time.Millisecond,
				},
			}

			// Apply test-specific configuration
			tc.modifyConfig(cfg)

			// Test component initialization with modified config
			ebpfMgr, err := ebpf.NewManager(cfg)
			if err != nil {
				if !tc.expectError {
					t.Fatalf("Unexpected error creating eBPF manager: %v", err)
				}
				return
			}
			defer ebpfMgr.Close()

			if err := ebpfMgr.Load(); err != nil {
				if !tc.expectError {
					t.Fatalf("Unexpected error loading eBPF: %v", err)
				}
				return
			}

			proc, err := processor.New(cfg, ebpfMgr)
			if err != nil {
				if !tc.expectError {
					t.Fatalf("Unexpected error creating processor: %v", err)
				}
				return
			}
			defer proc.Close()

			dash, err := dashboard.New(cfg, proc)
			if err != nil {
				if !tc.expectError {
					t.Fatalf("Unexpected error creating dashboard: %v", err)
				}
				return
			}
			defer dash.Stop()

			// Test that configuration was applied correctly
			if tc.expectError {
				t.Errorf("Expected error but components initialized successfully")
			}

			t.Logf("Configuration test '%s' passed", tc.name)
		})
	}
}

func TestWorkflow_ComponentLifecycle(t *testing.T) {
	suite := SetupIntegrationSuite(t)

	// Test component startup
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := suite.processor.Start(ctx); err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}

	// Give components time to initialize
	time.Sleep(100 * time.Millisecond)

	// Test that all components are responsive
	resp, err := http.Get(suite.baseURL + "/api/stats")
	if err != nil {
		t.Fatalf("Components not responsive after startup: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected healthy response after startup, got %d", resp.StatusCode)
	}

	// Test graceful shutdown
	suite.Cleanup()

	// Verify components are shut down
	time.Sleep(50 * time.Millisecond)
	
	// Dashboard should be unreachable after shutdown
	client := &http.Client{Timeout: 100 * time.Millisecond}
	_, err = client.Get(suite.baseURL + "/api/stats")
	if err == nil {
		t.Error("Expected dashboard to be unreachable after shutdown")
	}

	t.Logf("Component lifecycle test passed")
}

func TestWorkflow_ErrorRecovery(t *testing.T) {
	suite := SetupIntegrationSuite(t)
	defer suite.Cleanup()

	// Start processor 
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := suite.processor.Start(ctx); err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}

	// Give initial time to start
	time.Sleep(100 * time.Millisecond)

	// Verify system is working
	resp, err := http.Get(suite.baseURL + "/api/stats")
	if err != nil {
		t.Fatalf("System not responsive: %v", err)
	}
	resp.Body.Close()

	// Test that system continues to work even under stress
	// (In mock mode, this tests the resilience of the integration)
	for i := 0; i < 10; i++ {
		resp, err := http.Get(suite.baseURL + "/api/dashboard")
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Request %d returned status %d", i, resp.StatusCode)
		}
	}

	t.Logf("Error recovery test passed")
}

func TestWorkflow_RealTimeUpdates(t *testing.T) {
	suite := SetupIntegrationSuite(t)
	defer suite.Cleanup()

	// Start processor
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := suite.processor.Start(ctx); err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}

	// Take initial snapshot
	resp1, err := http.Get(suite.baseURL + "/api/stats")
	if err != nil {
		t.Fatalf("Failed to get initial stats: %v", err)
	}
	defer resp1.Body.Close()

	var stats1 models.SystemMetrics
	if err := json.NewDecoder(resp1.Body).Decode(&stats1); err != nil {
		t.Fatalf("Failed to decode initial stats: %v", err)
	}

	// Wait for processing time
	time.Sleep(200 * time.Millisecond)

	// Take second snapshot
	resp2, err := http.Get(suite.baseURL + "/api/stats")
	if err != nil {
		t.Fatalf("Failed to get updated stats: %v", err)
	}
	defer resp2.Body.Close()

	var stats2 models.SystemMetrics
	if err := json.NewDecoder(resp2.Body).Decode(&stats2); err != nil {
		t.Fatalf("Failed to decode updated stats: %v", err)
	}

	// Verify timestamps are updating (real-time behavior)
	if !stats2.Timestamp.After(stats1.Timestamp) {
		t.Error("Expected stats timestamp to update over time")
	}

	// In mock mode, packet counts should be consistent or increasing
	if stats2.PacketsReceived < stats1.PacketsReceived {
		t.Error("Expected packet count to be stable or increasing")
	}

	t.Logf("Real-time updates test passed - timestamps updating correctly")
}