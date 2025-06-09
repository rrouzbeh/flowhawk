package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
	"flowhawk/pkg/dashboard"
)

// MockProcessor implements dashboard.ProcessorInterface for integration testing
type MockProcessor struct {
	stats         models.SystemMetrics
	topFlows      []models.FlowMetrics
	recentThreats []models.ThreatEvent
	recentHTTP    []models.HTTPEvent
	alertStats    map[string]interface{}
	activeRules   []models.ThreatRule
}

func (m *MockProcessor) GetStats() models.SystemMetrics {
	return m.stats
}

func (m *MockProcessor) GetTopFlows(limit int) []models.FlowMetrics {
	if len(m.topFlows) > limit {
		return m.topFlows[:limit]
	}
	return m.topFlows
}

func (m *MockProcessor) GetRecentThreats(limit int) []models.ThreatEvent {
	if len(m.recentThreats) > limit {
		return m.recentThreats[:limit]
	}
	return m.recentThreats
}

func (m *MockProcessor) GetRecentHTTP(limit int) []models.HTTPEvent {
	if len(m.recentHTTP) > limit {
		return m.recentHTTP[:limit]
	}
	return m.recentHTTP
}

func (m *MockProcessor) GetAlertStats() interface{} {
	return m.alertStats
}

func (m *MockProcessor) GetActiveRules() []models.ThreatRule {
	return m.activeRules
}

// SetupTestDashboard creates a dashboard server for integration testing
func SetupTestDashboard() (*dashboard.Dashboard, string, *MockProcessor) {
	mockProcessor := &MockProcessor{
		stats: models.SystemMetrics{
			PacketsReceived: 1500000,
			PacketsDropped:  1500,
			BytesReceived:   750000000,
			ActiveFlows:     2500,
			ThreatsDetected: 15,
			PacketsPerSec:   1500.75,
			BytesPerSec:     750000.5,
			Timestamp:       time.Now(),
		},
		topFlows: []models.FlowMetrics{
			{
				Key: models.FlowKey{
					SrcIP:    net.ParseIP("192.168.1.100"),
					DstIP:    net.ParseIP("10.0.1.50"),
					SrcPort:  8080,
					DstPort:  443,
					Protocol: models.ProtocolTCP,
				},
				Packets:   25000,
				Bytes:     37500000,
				FirstSeen: time.Now().Add(-2 * time.Hour),
				LastSeen:  time.Now(),
				Flags:     0x18,
			},
			{
				Key: models.FlowKey{
					SrcIP:    net.ParseIP("10.0.1.20"),
					DstIP:    net.ParseIP("8.8.8.8"),
					SrcPort:  53,
					DstPort:  53,
					Protocol: models.ProtocolUDP,
				},
				Packets:   5000,
				Bytes:     2500000,
				FirstSeen: time.Now().Add(-1 * time.Hour),
				LastSeen:  time.Now(),
				Flags:     0,
			},
		},
		recentThreats: []models.ThreatEvent{
			{
				ID:          "threat-001",
				Type:        models.ThreatPortScan,
				Severity:    models.SeverityHigh,
				Timestamp:   time.Now().Add(-30 * time.Minute),
				SrcIP:       net.ParseIP("203.0.113.45"),
				DstIP:       net.ParseIP("10.0.1.50"),
				SrcPort:     12345,
				DstPort:     22,
				Protocol:    models.ProtocolTCP,
				Description: "Port scan detected: 50 ports scanned in 60 seconds",
				ProcessID:   8888,
				ProcessName: "nmap",
			},
			{
				ID:          "threat-002",
				Type:        models.ThreatDDoS,
				Severity:    models.SeverityMedium,
				Timestamp:   time.Now().Add(-15 * time.Minute),
				SrcIP:       net.ParseIP("198.51.100.25"),
				DstIP:       net.ParseIP("10.0.1.50"),
				SrcPort:     80,
				DstPort:     80,
				Protocol:    models.ProtocolTCP,
				Description: "DDoS attack detected: 5000 packets/sec from single source",
				ProcessID:   0,
				ProcessName: "",
			},
		},
		recentHTTP: []models.HTTPEvent{
			{
				Timestamp: time.Now(),
				SrcIP:     net.ParseIP("192.168.1.1"),
				DstIP:     net.ParseIP("10.0.0.1"),
				SrcPort:   12345,
				DstPort:   80,
				Method:    "GET",
				URI:       "/index.html",
				Host:      "example.com",
				Direction: "request",
			},
		},
		alertStats: map[string]interface{}{
			"total_alerts":  45,
			"alerts_today":  12,
			"alerts_sent":   43,
			"alerts_failed": 2,
			"last_alert":    time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			"channel_stats": map[string]int{"webhook": 25, "email": 18, "slack": 2},
		},
		activeRules: []models.ThreatRule{
			{
				ID:          "rule-001",
				Name:        "Port Scan Detection",
				Description: "Detects rapid port scanning activity",
				Enabled:     true,
				Severity:    models.SeverityHigh,
			},
			{
				ID:          "rule-002",
				Name:        "DDoS Protection",
				Description: "Detects distributed denial of service attacks",
				Enabled:     true,
				Severity:    models.SeverityMedium,
			},
		},
	}

	// Find available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(fmt.Sprintf("Failed to find available port: %v", err))
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &config.Config{
		Dashboard: config.DashboardConfig{
			ListenAddr:     fmt.Sprintf(":%d", port),
			UpdateInterval: 100 * time.Millisecond,
		},
	}

	dash, err := dashboard.New(cfg, mockProcessor)
	if err != nil {
		panic(fmt.Sprintf("Failed to create dashboard: %v", err))
	}

	// Start the dashboard server
	ctx := context.Background()
	if err := dash.Start(ctx); err != nil {
		panic(fmt.Sprintf("Failed to start dashboard: %v", err))
	}

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	return dash, baseURL, mockProcessor
}

func TestDashboardAPI_StatsEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/api/stats")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response status
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Parse and verify response body
	var stats models.SystemMetrics
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify expected values
	if stats.PacketsReceived != 1500000 {
		t.Errorf("Expected PacketsReceived=1500000, got %d", stats.PacketsReceived)
	}
	if stats.PacketsDropped != 1500 {
		t.Errorf("Expected PacketsDropped=1500, got %d", stats.PacketsDropped)
	}
	if stats.ActiveFlows != 2500 {
		t.Errorf("Expected ActiveFlows=2500, got %d", stats.ActiveFlows)
	}
	if stats.ThreatsDetected != 15 {
		t.Errorf("Expected ThreatsDetected=15, got %d", stats.ThreatsDetected)
	}
}

func TestDashboardAPI_FlowsEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/api/flows")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var flows []models.FlowMetrics
	if err := json.NewDecoder(resp.Body).Decode(&flows); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify we got flows
	if len(flows) != 2 {
		t.Errorf("Expected 2 flows, got %d", len(flows))
	}

	// Verify first flow structure
	if len(flows) > 0 {
		flow := flows[0]
		if flow.Packets == 0 {
			t.Error("Expected non-zero packet count")
		}
		if flow.Bytes == 0 {
			t.Error("Expected non-zero byte count")
		}
		if flow.Key.SrcPort == 0 && flow.Key.DstPort == 0 {
			t.Error("Expected valid port numbers")
		}
	}
}

func TestDashboardAPI_ThreatsEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/api/threats")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var threats []models.ThreatEvent
	if err := json.NewDecoder(resp.Body).Decode(&threats); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify we got threats
	if len(threats) != 2 {
		t.Errorf("Expected 2 threats, got %d", len(threats))
	}

	// Verify first threat structure
	if len(threats) > 0 {
		threat := threats[0]
		if threat.ID == "" {
			t.Error("Expected threat ID")
		}
		if threat.Type.String() == "" {
			t.Error("Expected threat type")
		}
		if threat.Description == "" {
			t.Error("Expected threat description")
		}
		if threat.Severity.String() == "" {
			t.Error("Expected threat severity")
		}
	}
}

func TestDashboardAPI_DashboardEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/api/dashboard")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var dashboardState models.DashboardState
	if err := json.NewDecoder(resp.Body).Decode(&dashboardState); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify dashboard state includes all components
	if dashboardState.Metrics.PacketsReceived == 0 {
		t.Error("Expected metrics data")
	}
	if len(dashboardState.TopFlows) == 0 {
		t.Error("Expected top flows data")
	}
	if len(dashboardState.RecentThreats) == 0 {
		t.Error("Expected recent threats data")
	}
	if dashboardState.Timestamp.IsZero() {
		t.Error("Expected valid timestamp")
	}
}

func TestDashboardAPI_AlertsEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/api/alerts")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var alertStats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&alertStats); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify alert stats structure
	if alertStats["total_alerts"] == nil {
		t.Error("Expected total_alerts field")
	}
	if alertStats["alerts_today"] == nil {
		t.Error("Expected alerts_today field")
	}
	if alertStats["channel_stats"] == nil {
		t.Error("Expected channel_stats field")
	}
}

func TestDashboardAPI_IndexEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify content type for HTML
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html" {
		t.Errorf("Expected Content-Type 'text/html', got '%s'", contentType)
	}
}

func TestDashboardAPI_InvalidEndpoint(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	resp, err := http.Get(baseURL + "/api/invalid")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestDashboardAPI_ConcurrentRequests(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	// Test concurrent API requests
	endpoints := []string{
		"/api/stats",
		"/api/flows",
		"/api/threats",
		"/api/dashboard",
		"/api/alerts",
	}

	done := make(chan bool, len(endpoints))

	for _, endpoint := range endpoints {
		go func(url string) {
			defer func() { done <- true }()

			resp, err := http.Get(baseURL + url)
			if err != nil {
				t.Errorf("Failed request to %s: %v", url, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200 for %s, got %d", url, resp.StatusCode)
			}
		}(endpoint)
	}

	// Wait for all requests to complete
	for i := 0; i < len(endpoints); i++ {
		<-done
	}
}

func TestDashboardAPI_ErrorHandling(t *testing.T) {
	// Test with processor that returns empty data
	errorProcessor := &MockProcessor{
		stats:         models.SystemMetrics{},   // Empty stats
		topFlows:      []models.FlowMetrics{},   // Empty flows
		recentThreats: []models.ThreatEvent{},   // Empty threats
		recentHTTP:    []models.HTTPEvent{},     // Empty HTTP events
		alertStats:    map[string]interface{}{}, // Empty alert stats
		activeRules:   []models.ThreatRule{},    // Empty rules
	}

	// Find available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &config.Config{
		Dashboard: config.DashboardConfig{
			ListenAddr:     fmt.Sprintf(":%d", port),
			UpdateInterval: 100 * time.Millisecond,
		},
	}

	dash, err := dashboard.New(cfg, errorProcessor)
	if err != nil {
		t.Fatalf("Failed to create dashboard: %v", err)
	}
	defer dash.Stop()

	ctx := context.Background()
	if err := dash.Start(ctx); err != nil {
		t.Fatalf("Failed to start dashboard: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	baseURL := fmt.Sprintf("http://localhost:%d", port)

	// Test endpoints still respond even with empty data
	endpoints := []string{"/api/stats", "/api/flows", "/api/threats"}
	for _, endpoint := range endpoints {
		resp, err := http.Get(baseURL + endpoint)
		if err != nil {
			t.Errorf("Failed request to %s: %v", endpoint, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for %s with empty data, got %d", endpoint, resp.StatusCode)
		}
	}
}

func TestDashboardAPI_PerformanceUnderLoad(t *testing.T) {
	dash, baseURL, _ := SetupTestDashboard()
	defer dash.Stop()

	// Simulate load with multiple rapid requests
	const numRequests = 50
	done := make(chan bool, numRequests)

	start := time.Now()

	for i := 0; i < numRequests; i++ {
		go func() {
			defer func() { done <- true }()

			resp, err := http.Get(baseURL + "/api/stats")
			if err != nil {
				t.Errorf("Failed request: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}

	duration := time.Since(start)
	avgDuration := duration / numRequests

	// Performance assertion - should handle 50 requests reasonably fast
	if avgDuration > 100*time.Millisecond {
		t.Errorf("Average request took too long: %v (expected < 100ms)", avgDuration)
	}

	t.Logf("Handled %d requests in %v (avg: %v per request)", numRequests, duration, avgDuration)
}
