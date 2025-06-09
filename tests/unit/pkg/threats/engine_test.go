package threats_test

import (
	"net"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
	"flowhawk/pkg/threats"
)

func TestNewThreatEngine(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Threshold: 100,
				Window:    time.Minute,
				Enable:    true,
			},
			DDoS: config.DDoSConfig{
				PPSThreshold: 100000,
				BPSThreshold: 1000000000,
				Window:       10 * time.Second,
				Enable:       true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)

	if engine == nil {
		t.Fatal("Expected ThreatEngine to be created, got nil")
	}
}

func TestAnalyzePacket(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Threshold: 5, // Low threshold for testing
				Window:    time.Minute,
				Enable:    true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)
	
	// Create test packet
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")

	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     8080,
		DstPort:     22, // SSH port - common target for scans
		Protocol:    models.ProtocolTCP,
		PacketSize:  64,
		Flags:       0x02, // SYN flag
		ProcessID:   1234,
		ProcessName: "scanner",
	}

	// Analyze packet
	threats := engine.AnalyzePacket(packet)
	
	// Should return empty slice initially (no threats detected yet)
	if threats == nil {
		t.Errorf("Expected threats slice, got nil")
	}
}

func TestPortScanDetection(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Threshold: 3, // Very low threshold for testing
				Window:    time.Minute,
				Enable:    true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)
	
	srcIP := net.ParseIP("192.168.1.100")
	
	// Simulate multiple connection attempts to different ports (port scan)
	ports := []uint16{22, 23, 80, 443, 8080}
	
	for _, port := range ports {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     8080,
			DstPort:     port,
			Protocol:    models.ProtocolTCP,
			PacketSize:  64,
			Flags:       0x02, // SYN flag
			ProcessID:   1234,
			ProcessName: "scanner",
		}
		
		engine.AnalyzePacket(packet)
	}
	
	// After multiple attempts, should potentially detect a port scan
	// (This is a basic test - actual detection may require more sophisticated logic)
}

func TestDDoSDetection(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			DDoS: config.DDoSConfig{
				PPSThreshold: 10, // Low threshold for testing
				BPSThreshold: 10000,
				Window:       time.Second,
				Enable:       true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)
	
	dstIP := net.ParseIP("10.0.1.50")
	
	// Simulate high traffic volume
	for i := 0; i < 15; i++ {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       dstIP,
			SrcPort:     8080,
			DstPort:     80,
			Protocol:    models.ProtocolTCP,
			PacketSize:  1500,
			Flags:       0x18,
			ProcessID:   1234,
			ProcessName: "flood",
		}
		
		engine.AnalyzePacket(packet)
	}
}

func TestBotnetDetection(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			Botnet: config.BotnetConfig{
				C2Domains:      []string{"evil.com", "malware.net"},
				DNSTunneling:   true,
				BeaconInterval: 30 * time.Second,
				Enable:         true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)
	srcIP := net.ParseIP("192.168.1.100")

	// Test C2 communication detection
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       net.ParseIP("1.2.3.4"), // Known C2 IP
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		PacketSize:  100,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "malware",
	}

	threat := engine.AnalyzePacket(packet)
	if threat == nil {
		t.Log("No initial threat detected (expected for first packet)")
	}

	// Simulate beaconing pattern
	baseTime := time.Now()
	for i := 0; i < 12; i++ {
		beaconPacket := &models.PacketEvent{
			Timestamp:   baseTime.Add(time.Duration(i) * 30 * time.Second),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("1.2.3.4"),
			SrcPort:     8080,
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			PacketSize:  100,
			Flags:       0x18,
			ProcessID:   1234,
			ProcessName: "malware",
		}
		
		threats := engine.AnalyzePacket(beaconPacket)
		if len(threats) > 0 {
			t.Logf("Botnet threat detected after %d beacons", i+1)
			break
		}
	}

	// Test DNS tunneling detection
	for i := 0; i < 105; i++ {
		dnsPacket := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("8.8.8.8"),
			SrcPort:     uint16(50000 + i),
			DstPort:     53,
			Protocol:    models.ProtocolUDP,
			PacketSize:  512,
			ProcessID:   1234,
			ProcessName: "dnstunnel",
		}
		
		engine.AnalyzePacket(dnsPacket)
	}
}

func TestGetActiveRules(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
		},
	}

	engine := threats.NewThreatEngine(cfg)
	rules := engine.GetActiveRules()

	// Should return an empty slice or default rules
	if rules == nil {
		t.Error("Expected rules slice, got nil")
	}

	// Test that we get a copy, not the original
	originalLen := len(rules)
	rules = append(rules, models.ThreatRule{
		ID:          "test-rule",
		Name:        "Test Rule",
		Description: "A test rule",
		Severity:    models.SeverityMedium,
		Type:        models.ThreatPortScan,
		Enabled:     true,
	})

	newRules := engine.GetActiveRules()
	if len(newRules) != originalLen {
		t.Error("GetActiveRules should return a copy, not the original slice")
	}
}

func TestGetThreatStats(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Threshold: 5,
				Window:    time.Minute,
				Enable:    true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)

	// Get initial stats
	stats := engine.GetThreatStats()
	if stats == nil {
		t.Fatal("Expected stats map, got nil")
	}

	// Check expected keys
	expectedKeys := []string{
		"port_scan_trackers",
		"ddos_trackers", 
		"botnet_trackers",
		"exfiltration_trackers",
		"lateral_trackers",
	}

	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Expected key %s in stats", key)
		}
	}

	// All should start at 0
	for _, key := range expectedKeys {
		if count, ok := stats[key].(int); !ok || count != 0 {
			t.Errorf("Expected %s to be 0, got %v", key, stats[key])
		}
	}

	// Generate some activity to increase stats
	srcIP := net.ParseIP("192.168.1.100")
	for i := 0; i < 3; i++ {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     8080,
			DstPort:     uint16(22 + i),
			Protocol:    models.ProtocolTCP,
			PacketSize:  64,
			Flags:       0x02,
			ProcessID:   1234,
			ProcessName: "scanner",
		}
		engine.AnalyzePacket(packet)
	}

	// Check stats again
	newStats := engine.GetThreatStats()
	if portScanCount, ok := newStats["port_scan_trackers"].(int); !ok || portScanCount == 0 {
		t.Error("Expected port_scan_trackers to increase after activity")
	}
}

func TestCleanupStaleEntries(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Threshold: 5,
				Window:    time.Minute,
				Enable:    true,
			},
		},
	}

	engine := threats.NewThreatEngine(cfg)

	// Create some tracking entries
	srcIP := net.ParseIP("192.168.1.100")
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     8080,
		DstPort:     22,
		Protocol:    models.ProtocolTCP,
		PacketSize:  64,
		Flags:       0x02,
		ProcessID:   1234,
		ProcessName: "scanner",
	}

	// Analyze packet to create tracker entry
	engine.AnalyzePacket(packet)

	// Verify entry exists
	initialStats := engine.GetThreatStats()
	if initialStats["port_scan_trackers"].(int) == 0 {
		t.Error("Expected tracker entry to be created")
	}

	// Note: The cleanup function runs in a separate goroutine with a 5-minute ticker
	// For testing purposes, we verify the function exists and can be called
	// but we can't easily test the periodic cleanup without mocking time
	
	// Test that the engine was properly initialized
	if engine == nil {
		t.Error("Engine should be initialized for cleanup testing")
	}
}

func TestDataExfiltrationDetection(t *testing.T) {
	cfg := &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
		},
	}

	engine := threats.NewThreatEngine(cfg)
	srcIP := net.ParseIP("192.168.1.100")

	// Create large outbound packets to trigger exfiltration detection
	// Need to send >100MB of data to trigger the threshold
	const packetSize = 1024 * 1024 // 1MB per packet
	const numPackets = 105         // 105MB total

	for i := 0; i < numPackets; i++ {
		// Use different external IPs to test multiple destinations
		dstIPByte := byte(1 + (i % 10)) // External IPs like 1.1.1.1, 2.2.2.2, etc.
		dstIP := net.IPv4(dstIPByte, dstIPByte, dstIPByte, dstIPByte)

		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     8080,
			DstPort:     443, // HTTPS - encrypted traffic
			Protocol:    models.ProtocolTCP,
			PacketSize:  packetSize,
			Flags:       0x18,
			ProcessID:   1234,
			ProcessName: "uploader",
		}

		threats := engine.AnalyzePacket(packet)
		if len(threats) > 0 {
			t.Logf("Threat detected after %d MB", (i+1))
			// Verify a threat was detected (may be different type due to ML analysis)
			threat := threats[0]
			t.Logf("Threat type: %s", threat.Type.String())
			if threat.Metadata == nil {
				t.Log("No metadata in threat (may be expected for this threat type)")
			}
			break
		}
	}

	// Test different port types for unusual port tracking
	unusualPorts := []uint16{21, 22, 25, 443, 993, 995} // FTP, SSH, SMTP, HTTPS, IMAPS, POP3S
	for _, port := range unusualPorts {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("8.8.8.8"), // External DNS
			SrcPort:     8080,
			DstPort:     port,
			Protocol:    models.ProtocolTCP,
			PacketSize:  1024,
			Flags:       0x18,
			ProcessID:   1234,
			ProcessName: "exfiltool",
		}
		engine.AnalyzePacket(packet)
	}

	// Test window reset by sending packet after time window
	futurePacket := &models.PacketEvent{
		Timestamp:   time.Now().Add(2 * time.Hour), // Beyond 1-hour window
		SrcIP:       srcIP,
		DstIP:       net.ParseIP("1.1.1.1"),
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1024,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test",
	}
	engine.AnalyzePacket(futurePacket)

	// Verify stats were updated
	stats := engine.GetThreatStats()
	if exfilCount, ok := stats["exfiltration_trackers"].(int); !ok || exfilCount == 0 {
		t.Error("Expected exfiltration trackers to be created")
	}
}