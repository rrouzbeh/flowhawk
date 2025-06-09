package benchmarks

import (
	"net"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/alerts"
	"flowhawk/pkg/config"
)

// createAlertsConfig creates a configuration for alerts benchmarking
func createAlertsConfig() *config.Config {
	return &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			WebhookURL:        "http://localhost:8080/webhook",
			EmailSMTP:         "smtp.example.com",
			EmailUser:         "alerts@flowhawk.local",
			EmailPassword:     "password",
			EmailTo:           "admin@example.com",
			SeverityThreshold: "low",
		},
	}
}

// createMockThreatEvent creates a mock threat event for testing
func createMockThreatEvent(threatType models.ThreatType, severity models.Severity) *models.ThreatEvent {
	return &models.ThreatEvent{
		ID:          "test-threat-123",
		Type:        threatType,
		Severity:    severity,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		Description: "Benchmark threat event for testing alert system performance",
		Metadata: map[string]interface{}{
			"test_run":     true,
			"packet_count": 1000,
			"duration":     "5m",
		},
		ProcessID:   1234,
		ProcessName: "test-process",
	}
}

// BenchmarkAlertManagerCreation benchmarks alert manager creation
func BenchmarkAlertManagerCreation(b *testing.B) {
	cfg := createAlertsConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alertManager := alerts.NewAlertManager(cfg)
		_ = alertManager
	}
}

// BenchmarkSingleAlertSending benchmarks sending a single alert
func BenchmarkSingleAlertSending(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	threat := createMockThreatEvent(models.ThreatPortScan, models.SeverityMedium)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alertManager.SendAlert(threat)
	}
}

// BenchmarkHighVolumeAlerts benchmarks high-volume alert sending
func BenchmarkHighVolumeAlerts(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	// Pre-generate different threat events to avoid allocation overhead
	threats := []*models.ThreatEvent{
		createMockThreatEvent(models.ThreatPortScan, models.SeverityLow),
		createMockThreatEvent(models.ThreatDDoS, models.SeverityHigh),
		createMockThreatEvent(models.ThreatBotnet, models.SeverityMedium),
		createMockThreatEvent(models.ThreatDataExfiltration, models.SeverityHigh),
		createMockThreatEvent(models.ThreatLateralMovement, models.SeverityMedium),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		threat := threats[i%len(threats)]
		threat.ID = threat.ID + string(rune(i)) // Make each alert unique
		threat.Timestamp = time.Now()
		alertManager.SendAlert(threat)
	}
}

// BenchmarkAlertFiltering benchmarks alert filtering by severity
func BenchmarkAlertFiltering(b *testing.B) {
	// Create config with higher minimum severity to test filtering
	cfg := createAlertsConfig()
	cfg.Alerts.SeverityThreshold = "high"
	
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	lowSeverityThreat := createMockThreatEvent(models.ThreatPortScan, models.SeverityLow)
	highSeverityThreat := createMockThreatEvent(models.ThreatDDoS, models.SeverityHigh)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			// This should be filtered out
			alertManager.SendAlert(lowSeverityThreat)
		} else {
			// This should pass through
			alertManager.SendAlert(highSeverityThreat)
		}
	}
}

// BenchmarkRateLimiting benchmarks rate limiting functionality
func BenchmarkRateLimiting(b *testing.B) {
	cfg := createAlertsConfig()
	// Note: Rate limiting might be implemented in alert manager logic
	
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	threat := createMockThreatEvent(models.ThreatDDoS, models.SeverityHigh)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		threat.ID = threat.ID + string(rune(i))
		threat.Timestamp = time.Now()
		alertManager.SendAlert(threat)
	}
}

// BenchmarkAlertManagerConcurrency benchmarks concurrent alert sending
func BenchmarkAlertManagerConcurrency(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	threat := createMockThreatEvent(models.ThreatBotnet, models.SeverityMedium)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		localThreat := *threat // Create local copy
		counter := 0
		for pb.Next() {
			localThreat.ID = threat.ID + string(rune(counter))
			localThreat.Timestamp = time.Now()
			alertManager.SendAlert(&localThreat)
			counter++
		}
	})
}

// BenchmarkAlertStats benchmarks alert statistics retrieval
func BenchmarkAlertStats(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	// Send a few alerts first to have some stats
	threat := createMockThreatEvent(models.ThreatPortScan, models.SeverityMedium)
	for i := 0; i < 10; i++ {
		threat.ID = threat.ID + string(rune(i))
		alertManager.SendAlert(threat)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats := alertManager.GetStats()
		_ = stats
	}
}

// BenchmarkDifferentSeverityLevels benchmarks alerts with different severity levels
func BenchmarkDifferentSeverityLevels(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	severities := []models.Severity{
		models.SeverityLow,
		models.SeverityMedium,
		models.SeverityHigh,
		models.SeverityCritical,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		severity := severities[i%len(severities)]
		threat := createMockThreatEvent(models.ThreatDDoS, severity)
		threat.ID = threat.ID + string(rune(i))
		threat.Timestamp = time.Now()
		alertManager.SendAlert(threat)
	}
}

// BenchmarkAlertManagerMemory benchmarks memory allocation patterns
func BenchmarkAlertManagerMemory(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	threat := createMockThreatEvent(models.ThreatPortScan, models.SeverityMedium)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		threat.ID = threat.ID + string(rune(i))
		threat.Timestamp = time.Now()
		alertManager.SendAlert(threat)
	}
}

// BenchmarkAlertFormatting benchmarks alert message formatting
func BenchmarkAlertFormatting(b *testing.B) {
	cfg := createAlertsConfig()
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	// Create threats with different metadata sizes
	threats := make([]*models.ThreatEvent, 5)
	for i := 0; i < len(threats); i++ {
		threat := createMockThreatEvent(models.ThreatBotnet, models.SeverityHigh)
		
		// Add varying amounts of metadata
		for j := 0; j < i*10; j++ {
			threat.Metadata[string(rune('a'+j))] = j
		}
		
		threats[i] = threat
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		threat := threats[i%len(threats)]
		threat.Timestamp = time.Now()
		alertManager.SendAlert(threat)
	}
}

// BenchmarkBurstAlerts benchmarks burst alert scenarios
func BenchmarkBurstAlerts(b *testing.B) {
	cfg := createAlertsConfig()
	
	alertManager := alerts.NewAlertManager(cfg)
	defer alertManager.Close()
	
	threat := createMockThreatEvent(models.ThreatDDoS, models.SeverityCritical)
	
	b.ResetTimer()
	
	// Simulate burst scenarios
	for i := 0; i < b.N; i++ {
		// Send bursts of 10 alerts
		for j := 0; j < 10; j++ {
			threat.ID = threat.ID + string(rune(i*10+j))
			threat.Timestamp = time.Now()
			alertManager.SendAlert(threat)
		}
		
		// Small delay between bursts to simulate real-world patterns
		if i%100 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// BenchmarkAlertManagerLifecycle benchmarks complete alert manager lifecycle
func BenchmarkAlertManagerLifecycle(b *testing.B) {
	cfg := createAlertsConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alertManager := alerts.NewAlertManager(cfg)
		
		// Send a few alerts
		threat := createMockThreatEvent(models.ThreatPortScan, models.SeverityMedium)
		threat.ID = threat.ID + string(rune(i))
		alertManager.SendAlert(threat)
		
		// Get stats
		stats := alertManager.GetStats()
		_ = stats
		
		alertManager.Close()
	}
}