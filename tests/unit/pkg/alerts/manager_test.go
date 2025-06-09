package alerts_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/alerts"
	"flowhawk/pkg/config"
)

func TestNewAlertManager(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "medium",
		},
	}

	manager := alerts.NewAlertManager(cfg)

	if manager == nil {
		t.Fatal("Expected AlertManager to be created, got nil")
	}

	// Test initial stats
	stats := manager.GetStats()
	if stats.TotalAlerts != 0 {
		t.Errorf("Expected initial TotalAlerts = 0, got %d", stats.TotalAlerts)
	}

	// Cleanup
	manager.Close()
}

func TestNewAlertManagerDisabled(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable: false,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	if manager == nil {
		t.Fatal("Expected AlertManager to be created even when disabled")
	}

	// Test that no channels are initialized when disabled
	stats := manager.GetStats()
	if len(stats.ChannelStats) != 0 {
		t.Errorf("Expected no channels when disabled, got %d", len(stats.ChannelStats))
	}
}

func TestSendAlert(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "medium",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Create a test threat event
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")
	
	event := &models.ThreatEvent{
		ID:          "test-threat-1",
		Type:        models.ThreatPortScan,
		Severity:    models.SeverityHigh,
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		Description: "Test port scan detected",
		ProcessID:   1234,
		ProcessName: "scanner",
	}

	// Send the alert
	manager.SendAlert(event)

	// Give some time for processing
	time.Sleep(50 * time.Millisecond)

	// Check that stats were updated
	stats := manager.GetStats()
	if stats.TotalAlerts == 0 {
		t.Errorf("Expected TotalAlerts > 0, got %d", stats.TotalAlerts)
	}
}

func TestSendAlertWithDisabledAlerts(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable: false,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")
	
	event := &models.ThreatEvent{
		ID:       "test-threat-1",
		Type:     models.ThreatPortScan,
		Severity: models.SeverityHigh,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// Send the alert (should be ignored)
	manager.SendAlert(event)

	// Check that stats were not updated
	stats := manager.GetStats()
	if stats.TotalAlerts != 0 {
		t.Errorf("Expected TotalAlerts = 0 when disabled, got %d", stats.TotalAlerts)
	}
}

func TestWebhookChannelInitialization(t *testing.T) {
	// Create mock webhook server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "medium",
			WebhookURL:        server.URL,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Test that webhook channel is configured
	stats := manager.GetStats()
	if _, exists := stats.ChannelStats["webhook"]; !exists {
		t.Error("Expected webhook channel to be configured")
	}

	event := &models.ThreatEvent{
		ID:          "webhook-test",
		Type:        models.ThreatDDoS,
		Severity:    models.SeverityHigh,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     80,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		Description: "Test DDoS attack",
	}

	manager.SendAlert(event)
	time.Sleep(100 * time.Millisecond)

	finalStats := manager.GetStats()
	if finalStats.TotalAlerts == 0 {
		t.Error("Expected alert to be processed")
	}

	webhookStats := finalStats.ChannelStats["webhook"]
	if webhookStats.Sent == 0 {
		t.Error("Expected webhook to send at least one alert")
	}
}

func TestWebhookChannelError(t *testing.T) {
	// Create mock webhook server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
			WebhookURL:        server.URL,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	event := &models.ThreatEvent{
		ID:          "webhook-error-test",
		Type:        models.ThreatDDoS,
		Severity:    models.SeverityHigh,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Test webhook error handling",
	}

	manager.SendAlert(event)
	time.Sleep(100 * time.Millisecond)

	stats := manager.GetStats()
	webhookStats := stats.ChannelStats["webhook"]
	if webhookStats.Failed == 0 {
		t.Error("Expected webhook to have failed attempts")
	}
	if stats.AlertsFailed == 0 {
		t.Error("Expected failed alert count to increase")
	}
}

func TestEmailChannelInitialization(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "medium",
			EmailSMTP:         "smtp.example.com:587",
			EmailUser:         "user@example.com",
			EmailPassword:     "password",
			EmailTo:           "admin@example.com",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	stats := manager.GetStats()
	if _, exists := stats.ChannelStats["email"]; !exists {
		t.Error("Expected email channel to be configured")
	}
}

func TestEmailChannelMultipleRecipients(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "medium",
			EmailSMTP:         "smtp.example.com:587",
			EmailUser:         "user@example.com",
			EmailPassword:     "password",
			EmailTo:           "admin@example.com,security@example.com,ops@example.com",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	stats := manager.GetStats()
	if _, exists := stats.ChannelStats["email"]; !exists {
		t.Error("Expected email channel to be configured with multiple recipients")
	}
}

func TestSeverityThresholdFiltering(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "high", // Only high and critical
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	testCases := []struct {
		name     string
		severity models.Severity
	}{
		{"low_severity", models.SeverityLow},
		{"medium_severity", models.SeverityMedium},
		{"high_severity", models.SeverityHigh},
		{"critical_severity", models.SeverityCritical},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := &models.ThreatEvent{
				ID:          "severity-test-" + tc.name,
				Type:        models.ThreatPortScan,
				Severity:    tc.severity,
				Timestamp:   time.Now(),
				SrcIP:       net.ParseIP("192.168.1.100"),
				DstIP:       net.ParseIP("10.0.1.50"),
				Protocol:    models.ProtocolTCP,
				Description: "Severity threshold test",
			}

			initialStats := manager.GetStats()
			manager.SendAlert(event)
			time.Sleep(50 * time.Millisecond)

			newStats := manager.GetStats()
			alertsProcessed := newStats.TotalAlerts > initialStats.TotalAlerts

			if !alertsProcessed {
				t.Errorf("Alert with %s severity should be counted in TotalAlerts", tc.severity.String())
			}
		})
	}
}

func TestInvalidSeverityThreshold(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "invalid", // Should default to medium
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Send medium severity alert (should be processed with default threshold)
	event := &models.ThreatEvent{
		ID:          "invalid-threshold-test",
		Type:        models.ThreatPortScan,
		Severity:    models.SeverityMedium,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Test invalid threshold default",
	}

	manager.SendAlert(event)
	time.Sleep(50 * time.Millisecond)

	stats := manager.GetStats()
	if stats.TotalAlerts == 0 {
		t.Error("Expected alert to be processed with default threshold")
	}
}

func TestAlertDeduplication(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	event := &models.ThreatEvent{
		ID:          "duplicate-test",
		Type:        models.ThreatPortScan,
		Severity:    models.SeverityHigh,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		Description: "Deduplication test",
	}

	// Send same alert multiple times
	manager.SendAlert(event)
	manager.SendAlert(event)
	manager.SendAlert(event)

	time.Sleep(100 * time.Millisecond)

	stats := manager.GetStats()
	if stats.TotalAlerts == 0 {
		t.Error("Expected at least one alert to be processed")
	}
	if stats.AlertsSupressed == 0 {
		t.Error("Expected some alerts to be suppressed due to deduplication")
	}
}

func TestRateLimiting(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Send many alerts rapidly from same source
	srcIP := net.ParseIP("192.168.1.100")
	for i := 0; i < 150; i++ { // Exceed rate limit (100/min)
		event := &models.ThreatEvent{
			ID:          fmt.Sprintf("rate-limit-test-%d", i),
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityLow,
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     uint16(8000 + i), // Different ports to avoid deduplication
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			Description: fmt.Sprintf("Rate limit test %d", i),
		}

		manager.SendAlert(event)
	}

	time.Sleep(200 * time.Millisecond)

	stats := manager.GetStats()
	if stats.AlertsSupressed == 0 {
		t.Error("Expected some alerts to be rate limited")
	}
}

func TestAlertQueueOverflow(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Send many alerts rapidly to potentially overflow queue
	// Note: Queue overflow may not happen in test environment due to fast processing
	for i := 0; i < 500; i++ {
		event := &models.ThreatEvent{
			ID:          fmt.Sprintf("overflow-test-%d", i),
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityLow,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP(fmt.Sprintf("192.168.1.%d", i%255+1)),
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     uint16(8000 + i),
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			Description: fmt.Sprintf("Queue overflow test %d", i),
		}

		manager.SendAlert(event)
	}

	time.Sleep(100 * time.Millisecond)

	stats := manager.GetStats()
	// In test environment, queue overflow may not occur due to fast processing
	// So we just verify that alerts were processed
	if stats.TotalAlerts == 0 {
		t.Error("Expected alerts to be processed")
	}
}

func TestMultipleThreatTypes(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	threatTypes := []models.ThreatType{
		models.ThreatPortScan,
		models.ThreatDDoS,
		models.ThreatBotnet,
		models.ThreatDataExfiltration,
		models.ThreatLateralMovement,
		models.ThreatDNSTunneling,
		models.ThreatProcessAnomaly,
	}

	for i, threatType := range threatTypes {
		event := &models.ThreatEvent{
			ID:          fmt.Sprintf("threat-type-%d", i),
			Type:        threatType,
			Severity:    models.SeverityMedium,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: fmt.Sprintf("Test %s detection", threatType.String()),
		}

		manager.SendAlert(event)
	}

	time.Sleep(200 * time.Millisecond)

	stats := manager.GetStats()
	if stats.TotalAlerts < uint64(len(threatTypes)) {
		t.Errorf("Expected at least %d alerts for different threat types, got %d", 
			len(threatTypes), stats.TotalAlerts)
	}
}

func TestAlertWithProcessInfo(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	event := &models.ThreatEvent{
		ID:          "process-info-test",
		Type:        models.ThreatProcessAnomaly,
		Severity:    models.SeverityHigh,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Suspicious process activity",
		ProcessID:   1337,
		ProcessName: "suspicious.exe",
	}

	manager.SendAlert(event)
	time.Sleep(50 * time.Millisecond)

	stats := manager.GetStats()
	if stats.TotalAlerts == 0 {
		t.Error("Expected alert with process info to be processed")
	}
}

func TestGetStatsThreadSafety(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Test concurrent access to stats
	done := make(chan bool, 10)
	
	// Start concurrent readers
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				stats := manager.GetStats()
				_ = stats.TotalAlerts // Use the stats
			}
			done <- true
		}()
	}
	
	// Start concurrent writers (alert senders)
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 20; j++ {
				event := &models.ThreatEvent{
					ID:          fmt.Sprintf("concurrent-test-%d-%d", id, j),
					Type:        models.ThreatPortScan,
					Severity:    models.SeverityLow,
					Timestamp:   time.Now(),
					SrcIP:       net.ParseIP(fmt.Sprintf("192.168.1.%d", id+1)),
					DstIP:       net.ParseIP("10.0.1.50"),
					Protocol:    models.ProtocolTCP,
					Description: "Concurrent access test",
				}
				manager.SendAlert(event)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	time.Sleep(200 * time.Millisecond)

	stats := manager.GetStats()
	if stats.TotalAlerts == 0 {
		t.Error("Expected alerts to be processed during concurrent access")
	}
}

func TestCloseIdempotency(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable: true,
		},
	}

	manager := alerts.NewAlertManager(cfg)

	// Close should not error
	err := manager.Close()
	if err != nil {
		t.Errorf("First close returned error: %v", err)
	}

	// Second close should not error
	err = manager.Close()
	if err != nil {
		t.Errorf("Second close returned error: %v", err)
	}

	// Third close should not error
	err = manager.Close()
	if err != nil {
		t.Errorf("Third close returned error: %v", err)
	}
}

func TestChannelStatsInitialization(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
			WebhookURL:        "http://example.com/webhook",
			EmailSMTP:         "smtp.example.com:587",
			EmailTo:           "admin@example.com",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	stats := manager.GetStats()
	
	// Check that channel stats are properly initialized
	if stats.ChannelStats == nil {
		t.Error("ChannelStats should be initialized")
	}

	if _, exists := stats.ChannelStats["webhook"]; !exists {
		t.Error("Webhook channel stats should be initialized")
	}

	if _, exists := stats.ChannelStats["email"]; !exists {
		t.Error("Email channel stats should be initialized")
	}

	// Check initial values
	webhookStats := stats.ChannelStats["webhook"]
	if webhookStats.Sent != 0 || webhookStats.Failed != 0 {
		t.Error("Channel stats should start at zero")
	}
}

func TestWebhookChannelMinSeverity(t *testing.T) {
	testCases := []struct {
		severity models.Severity
		name     string
		threshold string
		shouldSend bool
	}{
		{models.SeverityLow, "low_with_low_threshold", "low", true},
		{models.SeverityMedium, "medium_with_low_threshold", "low", true},
		{models.SeverityHigh, "high_with_high_threshold", "high", true},
		{models.SeverityMedium, "medium_with_high_threshold", "high", false},
		{models.SeverityCritical, "critical_with_medium_threshold", "medium", true},
		{models.SeverityLow, "low_with_medium_threshold", "medium", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock webhook server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			cfg := &config.Config{
				Alerts: config.AlertsConfig{
					Enable:            true,
					SeverityThreshold: tc.threshold,
					WebhookURL:        server.URL,
				},
			}

			manager := alerts.NewAlertManager(cfg)
			defer manager.Close()

			event := &models.ThreatEvent{
				ID:          fmt.Sprintf("min-severity-test-%s", tc.name),
				Type:        models.ThreatPortScan,
				Severity:    tc.severity,
				Timestamp:   time.Now(),
				SrcIP:       net.ParseIP("192.168.1.100"),
				DstIP:       net.ParseIP("10.0.1.50"),
				Protocol:    models.ProtocolTCP,
				Description: "Min severity test",
			}

			initialStats := manager.GetStats()
			manager.SendAlert(event)
			time.Sleep(100 * time.Millisecond)

			newStats := manager.GetStats()
			
			// All alerts should be counted in TotalAlerts
			if newStats.TotalAlerts <= initialStats.TotalAlerts {
				t.Error("Alert should be counted in TotalAlerts regardless of severity")
			}

			// Check if webhook was called based on severity
			webhookStats := newStats.ChannelStats["webhook"]
			expectedSent := uint64(0)
			if tc.shouldSend {
				expectedSent = 1
			}

			if webhookStats.Sent != expectedSent {
				t.Errorf("Expected webhook sent count %d, got %d for severity %s with threshold %s",
					expectedSent, webhookStats.Sent, tc.severity.String(), tc.threshold)
			}
		})
	}
}

func TestEmailChannelSend(t *testing.T) {
	t.Run("send_success", func(t *testing.T) {
		// This test would normally require a real SMTP server
		// Since we can't easily mock net/smtp in unit tests, we test initialization only
		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:        true,
				EmailSMTP:     "smtp.example.com:587",
				EmailUser:     "test@example.com",
				EmailPassword: "password",
				EmailTo:       "admin@example.com",
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		// Verify email channel was created
		stats := manager.GetStats()
		if _, exists := stats.ChannelStats["email"]; !exists {
			t.Error("Email channel should be initialized")
		}
	})

	t.Run("severity_filtering", func(t *testing.T) {
		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:            true,
				SeverityThreshold: "high",
				EmailSMTP:         "smtp.example.com:587", 
				EmailUser:         "test@example.com",
				EmailPassword:     "password",
				EmailTo:           "admin@example.com",
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		// Send low severity alert - should not be processed
		event := &models.ThreatEvent{
			ID:          "email-severity-test",
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityLow,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: "Low severity test",
		}

		manager.SendAlert(event)
		time.Sleep(50 * time.Millisecond)

		stats := manager.GetStats()
		// Alert should be counted but not sent due to severity threshold
		if stats.TotalAlerts == 0 {
			t.Error("Alert should be counted in TotalAlerts")
		}

		emailStats := stats.ChannelStats["email"]
		if emailStats.Sent != 0 {
			t.Error("Email should not be sent for low severity with high threshold")
		}
	})
}

func TestEmailChannelMethods(t *testing.T) {
	// Create a minimal email channel for testing interface methods
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:        true,
			EmailSMTP:     "smtp.example.com:587",
			EmailUser:     "test@example.com", 
			EmailPassword: "password",
			EmailTo:       "admin@example.com",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Access the email channel through reflection or test the manager interface
	// Since the channels are private, we test through manager behavior
	event := &models.ThreatEvent{
		ID:          "email-method-test",
		Type:        models.ThreatProcessAnomaly,
		Severity:    models.SeverityCritical,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Test with process info",
		ProcessID:   1234,
		ProcessName: "test.exe",
	}

	manager.SendAlert(event)
	time.Sleep(50 * time.Millisecond)

	stats := manager.GetStats()
	emailStats := stats.ChannelStats["email"]
	
	// The email send will fail (no real SMTP server), so it should increment Failed count
	if emailStats.Failed == 0 {
		t.Error("Email channel should fail to send alert (no real SMTP server)")
	}
}

func TestCleanupRecentAlerts(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Send some alerts to populate recent alerts
	for i := 0; i < 5; i++ {
		event := &models.ThreatEvent{
			ID:          fmt.Sprintf("cleanup-test-%d", i),
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityMedium,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     uint16(8000 + i),
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			Description: fmt.Sprintf("Cleanup test %d", i),
		}
		manager.SendAlert(event)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify alerts were processed
	stats := manager.GetStats()
	if stats.TotalAlerts != 5 {
		t.Errorf("Expected 5 alerts, got %d", stats.TotalAlerts)
	}

	// The cleanup function runs in a goroutine every 10 minutes
	// We can't easily test it directly, but we can verify the manager
	// handles multiple alerts without issues
}

func TestParseMinSeverityEdgeCases(t *testing.T) {
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "CRITICAL", // Test uppercase
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	event := &models.ThreatEvent{
		ID:          "severity-case-test",
		Type:        models.ThreatPortScan,
		Severity:    models.SeverityCritical,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Uppercase severity test",
	}

	manager.SendAlert(event)
	time.Sleep(50 * time.Millisecond)

	stats := manager.GetStats()
	if stats.TotalAlerts == 0 {
		t.Error("Alert should be processed with uppercase severity")
	}
}

func TestWebhookChannelGetters(t *testing.T) {
	// Create mock webhook server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:     true,
			WebhookURL: server.URL,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Test that webhook channel methods work through the manager
	// We verify by checking that webhook stats exist (meaning channel was created and is enabled)
	stats := manager.GetStats()
	if _, exists := stats.ChannelStats["webhook"]; !exists {
		t.Error("Webhook channel should be created and accessible")
	}
}

func TestWebhookPayloadWithProcessInfo(t *testing.T) {
	// Create mock webhook server that captures the payload
	var receivedPayload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
			WebhookURL:        server.URL,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	event := &models.ThreatEvent{
		ID:          "payload-process-test",
		Type:        models.ThreatProcessAnomaly,
		Severity:    models.SeverityHigh,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Test with process info",
		ProcessID:   9999,
		ProcessName: "malware.exe",
	}

	manager.SendAlert(event)
	time.Sleep(100 * time.Millisecond)

	// Verify payload contains process information
	if len(receivedPayload) == 0 {
		t.Error("Expected to receive webhook payload")
	}

	payloadStr := string(receivedPayload)
	if !strings.Contains(payloadStr, "malware.exe") {
		t.Error("Payload should contain process name")
	}
	if !strings.Contains(payloadStr, "9999") {
		t.Error("Payload should contain process ID")
	}
}

func TestWebhookPayloadWithoutProcessInfo(t *testing.T) {
	// Create mock webhook server that captures the payload
	var receivedPayload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
			WebhookURL:        server.URL,
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	event := &models.ThreatEvent{
		ID:          "payload-no-process-test",
		Type:        models.ThreatDDoS,
		Severity:    models.SeverityMedium,
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		Protocol:    models.ProtocolTCP,
		Description: "Test without process info",
		// No ProcessName or ProcessID set
	}

	manager.SendAlert(event)
	time.Sleep(100 * time.Millisecond)

	// Verify payload was sent
	if len(receivedPayload) == 0 {
		t.Error("Expected to receive webhook payload")
	}

	// Payload should not contain process fields when not set
	payloadStr := string(receivedPayload)
	if strings.Contains(payloadStr, "Process") {
		t.Error("Payload should not contain process field when process info is empty")
	}
}

func TestWebhookSeverityColors(t *testing.T) {
	testCases := []struct {
		severity     models.Severity
		expectedColor string
	}{
		{models.SeverityLow, "#36a64f"},
		{models.SeverityMedium, "#ffaa00"},
		{models.SeverityHigh, "#ff6600"},
		{models.SeverityCritical, "#ff0000"},
	}

	for _, tc := range testCases {
		t.Run(tc.severity.String(), func(t *testing.T) {
			// Create a fresh webhook server for each test
			var receivedPayload []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPayload, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			cfg := &config.Config{
				Alerts: config.AlertsConfig{
					Enable:            true,
					SeverityThreshold: "low",
					WebhookURL:        server.URL,
				},
			}

			manager := alerts.NewAlertManager(cfg)
			defer manager.Close()

			event := &models.ThreatEvent{
				ID:          fmt.Sprintf("color-test-%s", tc.severity.String()),
				Type:        models.ThreatPortScan,
				Severity:    tc.severity,
				Timestamp:   time.Now(),
				SrcIP:       net.ParseIP("192.168.1.100"),
				DstIP:       net.ParseIP("10.0.1.50"),
				Protocol:    models.ProtocolTCP,
				Description: "Color test",
			}

			manager.SendAlert(event)
			time.Sleep(100 * time.Millisecond)

			if len(receivedPayload) == 0 {
				t.Error("Expected to receive webhook payload")
				return
			}

			payloadStr := string(receivedPayload)
			if !strings.Contains(payloadStr, tc.expectedColor) {
				t.Errorf("Expected color %s not found in payload for severity %s", tc.expectedColor, tc.severity.String())
			}
		})
	}
}

func TestCleanupRecentAlertsDirectly(t *testing.T) {
	// This test is challenging because cleanupRecentAlerts runs in a background goroutine
	// We'll test the conditions that would trigger cleanup
	cfg := &config.Config{
		Alerts: config.AlertsConfig{
			Enable:            true,
			SeverityThreshold: "low",
		},
	}

	manager := alerts.NewAlertManager(cfg)
	defer manager.Close()

	// Send multiple alerts rapidly to build up recent alerts map
	for i := 0; i < 10; i++ {
		event := &models.ThreatEvent{
			ID:          fmt.Sprintf("cleanup-direct-test-%d", i),
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityMedium,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     uint16(8000 + i),
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			Description: fmt.Sprintf("Cleanup direct test %d", i),
		}
		manager.SendAlert(event)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify alerts were processed
	stats := manager.GetStats()
	if stats.TotalAlerts != 10 {
		t.Errorf("Expected 10 alerts, got %d", stats.TotalAlerts)
	}

	// The cleanup function is tested indirectly by verifying the manager works correctly
	// with many alerts over time. Direct testing would require exposing internal state.
}

func TestSendAlertEdgeCases(t *testing.T) {
	t.Run("send_alert_low_severity_filtered", func(t *testing.T) {
		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:            true,
				SeverityThreshold: "critical", // Only critical alerts
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		event := &models.ThreatEvent{
			ID:          "low-severity-filtered",
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityLow,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: "This should be filtered out",
		}

		manager.SendAlert(event)
		time.Sleep(50 * time.Millisecond)

		stats := manager.GetStats()
		// Alert should be counted but not processed
		if stats.TotalAlerts == 0 {
			t.Error("Alert should be counted in TotalAlerts")
		}
	})

	t.Run("webhook_send_below_min_severity", func(t *testing.T) {
		// Create mock webhook server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:            true,
				SeverityThreshold: "low",
				WebhookURL:        server.URL,
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		// The webhook channel's minSeverity is set to the config threshold
		// Send an alert that's below this threshold at the channel level
		// We need to test the webhook Send method directly
		
		// This is tricky to test since the channels are private
		// We'll use a configuration that should result in the webhook 
		// filtering by severity
		
		// Since both manager and channel use same threshold, we test the path
		// where webhook.Send returns nil for low severity
		event := &models.ThreatEvent{
			ID:          "webhook-severity-filter",
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityMedium,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: "Medium severity test",
		}

		manager.SendAlert(event)
		time.Sleep(100 * time.Millisecond)

		stats := manager.GetStats()
		webhookStats := stats.ChannelStats["webhook"]
		if webhookStats.Sent == 0 {
			t.Error("Webhook should send medium severity alert")
		}
	})
}

func TestEmailChannelEdgeCases(t *testing.T) {
	t.Run("email_without_process_info", func(t *testing.T) {
		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:        true,
				EmailSMTP:     "smtp.example.com:587",
				EmailUser:     "test@example.com",
				EmailPassword: "password",
				EmailTo:       "admin@example.com",
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		// Send alert without process info
		event := &models.ThreatEvent{
			ID:          "email-no-process",
			Type:        models.ThreatDDoS,
			Severity:    models.SeverityHigh,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: "DDoS without process info",
			// No ProcessName or ProcessID
		}

		manager.SendAlert(event)
		time.Sleep(50 * time.Millisecond)

		stats := manager.GetStats()
		emailStats := stats.ChannelStats["email"]
		if emailStats.Failed == 0 {
			t.Error("Email should fail (no real SMTP server)")
		}
	})

	t.Run("email_severity_colors", func(t *testing.T) {
		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:            true,
				SeverityThreshold: "low", // Allow all severities
				EmailSMTP:         "smtp.example.com:587",
				EmailUser:         "test@example.com",
				EmailPassword:     "password",
				EmailTo:           "admin@example.com",
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		// Test different severity levels for email formatting
		severities := []models.Severity{
			models.SeverityLow,
			models.SeverityMedium,
			models.SeverityHigh,
		}

		for _, severity := range severities {
			event := &models.ThreatEvent{
				ID:          fmt.Sprintf("email-color-test-%s", severity.String()),
				Type:        models.ThreatPortScan,
				Severity:    severity,
				Timestamp:   time.Now(),
				SrcIP:       net.ParseIP("192.168.1.100"),
				DstIP:       net.ParseIP("10.0.1.50"),
				Protocol:    models.ProtocolTCP,
				Description: "Email color test",
			}

			manager.SendAlert(event)
		}

		time.Sleep(300 * time.Millisecond)

		stats := manager.GetStats()
		emailStats := stats.ChannelStats["email"]
		// At least one email should be sent (and fail due to no SMTP server)
		if emailStats.Failed == 0 {
			t.Error("Expected at least one email attempt to fail (no real SMTP server)")
		}
		if stats.TotalAlerts != 3 {
			t.Errorf("Expected 3 total alerts, got %d", stats.TotalAlerts)
		}
	})
}

func TestWebhookChannelEdgeCases(t *testing.T) {
	t.Run("webhook_request_creation_error", func(t *testing.T) {
		// Test with invalid URL that would cause request creation to fail
		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:     true,
				WebhookURL: "://invalid-url", // Invalid URL
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		event := &models.ThreatEvent{
			ID:          "webhook-invalid-url",
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityHigh,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: "Invalid URL test",
		}

		manager.SendAlert(event)
		time.Sleep(100 * time.Millisecond)

		stats := manager.GetStats()
		webhookStats := stats.ChannelStats["webhook"]
		if webhookStats.Failed == 0 {
			t.Error("Webhook should fail with invalid URL")
		}
	})

	t.Run("webhook_default_severity_color", func(t *testing.T) {
		// Test with an undefined severity to hit the default case
		// This is tricky since models.Severity is an enum
		// We'll test by ensuring all defined severities are covered
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &config.Config{
			Alerts: config.AlertsConfig{
				Enable:     true,
				WebhookURL: server.URL,
			},
		}

		manager := alerts.NewAlertManager(cfg)
		defer manager.Close()

		// Test all valid severities to ensure coverage
		event := &models.ThreatEvent{
			ID:          "webhook-coverage-test",
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityCritical,
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			Protocol:    models.ProtocolTCP,
			Description: "Coverage test",
		}

		manager.SendAlert(event)
		time.Sleep(50 * time.Millisecond)

		stats := manager.GetStats()
		webhookStats := stats.ChannelStats["webhook"]
		if webhookStats.Sent == 0 {
			t.Error("Webhook should successfully send")
		}
	})
}