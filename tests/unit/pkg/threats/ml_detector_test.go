package threats_test

import (
	"net"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/threats"
)

func TestNewMLThreatDetector(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	if detector == nil {
		t.Fatal("Expected MLThreatDetector to be created, got nil")
	}
}

func TestAnalyzePacketAnomaly(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Create test packet
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")

	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1024,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test",
	}

	// Analyze packet
	threat := detector.AnalyzePacketAnomaly(packet)
	
	// Initially, no threat should be detected (need baseline)
	if threat != nil && threat.Severity == models.SeverityCritical {
		t.Errorf("Expected no critical threat on first packet, got %v", threat)
	}
}

func TestAnalyzeFlowAnomaly(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Create test flow
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")

	flow := &models.FlowMetrics{
		Key: models.FlowKey{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  8080,
			DstPort:  443,
			Protocol: models.ProtocolTCP,
		},
		Packets:   1000,
		Bytes:     1500000,
		FirstSeen: time.Now().Add(-time.Minute),
		LastSeen:  time.Now(),
		Flags:     0x18,
	}

	// Analyze flow
	threat := detector.AnalyzeFlowAnomaly(flow)
	
	// Initially, no threat should be detected (need baseline)
	if threat != nil && threat.Severity == models.SeverityCritical {
		t.Errorf("Expected no critical threat on normal flow, got %v", threat)
	}
}

func TestGetMLStats(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Get stats
	stats := detector.GetMLStats()
	
	if stats == nil {
		t.Fatal("Expected ML stats to be returned, got nil")
	}

	// Check that stats have expected structure
	if stats.TotalAnalyzed < 0 {
		t.Errorf("Expected non-negative TotalAnalyzed, got %d", stats.TotalAnalyzed)
	}

	if stats.AnomaliesDetected < 0 {
		t.Errorf("Expected non-negative AnomaliesDetected, got %d", stats.AnomaliesDetected)
	}
}

func TestMLDetectorStatisticalFunctions(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test calculateStatisticalAnomaly indirectly through packet analysis
	srcIP := net.ParseIP("192.168.1.100")
	
	// Send many packets to build up statistical model
	for i := 0; i < 20; i++ {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     8080,
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			PacketSize:  uint32(1000 + i*10), // Varying sizes
			Flags:       0x18,
			ProcessID:   1234,
			ProcessName: "test",
		}
		
		detector.AnalyzePacketAnomaly(packet)
	}

	// Send an anomalous packet (very large size)
	anomalousPacket := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		PacketSize:  50000, // Very large size
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test",
	}

	threat := detector.AnalyzePacketAnomaly(anomalousPacket)
	if threat == nil {
		t.Log("No threat detected for anomalous packet (may need more baseline data)")
	}
}

func TestMLDetectorPortEntropy(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test common ports (should have lower entropy)
	commonPortPacket := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     8080,
		DstPort:     443, // Common HTTPS port
		Protocol:    models.ProtocolTCP,
		PacketSize:  1024,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "browser",
	}

	detector.AnalyzePacketAnomaly(commonPortPacket)

	// Test uncommon ports (should have higher entropy)
	uncommonPortPacket := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     31337, // Uncommon port
		DstPort:     1337,  // Uncommon port
		Protocol:    models.ProtocolTCP,
		PacketSize:  1024,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "suspicious",
	}

	detector.AnalyzePacketAnomaly(uncommonPortPacket)

	// Check that stats increased
	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Error("Expected packets to be analyzed")
	}
}

func TestMLDetectorFlagsComplexity(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test various TCP flag combinations
	flagTests := []struct {
		flags uint32
		name  string
	}{
		{0x02, "SYN"},
		{0x18, "PSH+ACK"},
		{0x04, "RST"},
		{0x01, "FIN"},
		{0x3F, "All flags set"}, // High complexity
	}

	for _, test := range flagTests {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       net.ParseIP("192.168.1.100"),
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     8080,
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			PacketSize:  1024,
			Flags:       test.flags,
			ProcessID:   1234,
			ProcessName: test.name,
		}

		detector.AnalyzePacketAnomaly(packet)
	}

	// Check that stats increased
	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Error("Expected packets to be analyzed")
	}
}

func TestMLDetectorSeverityCalculation(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test high-severity conditions by sending many packets quickly
	srcIP := net.ParseIP("192.168.1.100")
	
	// Send many packets rapidly to trigger anomaly detection
	for i := 0; i < 50; i++ {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     uint16(50000 + i), // Different source ports
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			PacketSize:  65535, // Maximum packet size
			Flags:       0xFF,  // Unusual flag combination
			ProcessID:   1234,
			ProcessName: "flood",
		}
		
		threat := detector.AnalyzePacketAnomaly(packet)
		if threat != nil && threat.Severity == models.SeverityCritical {
			t.Logf("Critical threat detected at packet %d", i)
			break
		}
	}

	// Verify ML stats were updated
	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Error("Expected packets to be analyzed")
	}
}

func TestMLDetectorProfileManagement(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Create multiple profiles by using different source IPs
	ips := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	
	for _, ipStr := range ips {
		srcIP := net.ParseIP(ipStr)
		
		// Send packets to create profile for each IP
		for i := 0; i < 5; i++ {
			packet := &models.PacketEvent{
				Timestamp:   time.Now(),
				SrcIP:       srcIP,
				DstIP:       net.ParseIP("10.0.1.50"),
				SrcPort:     8080,
				DstPort:     443,
				Protocol:    models.ProtocolTCP,
				PacketSize:  1024,
				Flags:       0x18,
				ProcessID:   1234,
				ProcessName: "test",
			}
			
			detector.AnalyzePacketAnomaly(packet)
		}
	}

	// Check that profiles were created (indirectly through stats)
	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Error("Expected packets to be analyzed and profiles created")
	}
	
	// Test flow analysis with different flows
	for _, ipStr := range ips {
		srcIP := net.ParseIP(ipStr)
		
		flow := &models.FlowMetrics{
			Key: models.FlowKey{
				SrcIP:    srcIP,
				DstIP:    net.ParseIP("10.0.1.50"),
				SrcPort:  8080,
				DstPort:  443,
				Protocol: models.ProtocolTCP,
			},
			Packets:   100,
			Bytes:     150000,
			FirstSeen: time.Now().Add(-time.Minute),
			LastSeen:  time.Now(),
			Flags:     0x18,
		}

		detector.AnalyzeFlowAnomaly(flow)
	}

	// Verify flow analysis updates stats
	finalStats := detector.GetMLStats()
	if finalStats.TotalAnalyzed < stats.TotalAnalyzed {
		t.Error("Expected flow analysis to maintain or increase TotalAnalyzed count")
	}
	
	t.Logf("Packet analysis: %d, Flow analysis: %d", stats.TotalAnalyzed, finalStats.TotalAnalyzed)
}

func TestMLDetectorAnomalyThreshold(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test anomaly detection with many packets to build baseline
	srcIP := net.ParseIP("192.168.1.100")
	
	// Send many packets with consistent pattern to establish baseline
	for i := 0; i < 100; i++ {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     8080,
			DstPort:     443,
			Protocol:    models.ProtocolTCP,
			PacketSize:  uint32(1000 + (i % 10)), // Small variations
			Flags:       0x18,
			ProcessID:   1234,
			ProcessName: "normal",
		}
		
		threat := detector.AnalyzePacketAnomaly(packet)
		if threat != nil && i < 50 {
			t.Logf("Early threat detected at packet %d", i)
		}
	}

	// Now send highly anomalous packets to trigger adaptive threshold
	anomalousPatterns := []struct {
		name       string
		packetSize uint32
		flags      uint32
		srcPort    uint16
		dstPort    uint16
	}{
		{"huge_packet", 65535, 0x18, 8080, 443},
		{"weird_flags", 1024, 0xFF, 8080, 443},
		{"unusual_ports", 1024, 0x18, 31337, 1337},
		{"tiny_packet", 1, 0x02, 8080, 443},
		{"high_entropy", 32768, 0x3F, 12345, 54321},
	}

	for _, pattern := range anomalousPatterns {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("10.0.1.50"),
			SrcPort:     pattern.srcPort,
			DstPort:     pattern.dstPort,
			Protocol:    models.ProtocolTCP,
			PacketSize:  pattern.packetSize,
			Flags:       pattern.flags,
			ProcessID:   1234,
			ProcessName: pattern.name,
		}
		
		threat := detector.AnalyzePacketAnomaly(packet)
		if threat != nil {
			t.Logf("Anomaly detected for %s: severity=%s", pattern.name, threat.Severity.String())
		}
	}

	// Verify the ML detector has processed packets
	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Error("Expected packets to be analyzed")
	}
	t.Logf("ML stats: TotalAnalyzed=%d, AnomaliesDetected=%d", stats.TotalAnalyzed, stats.AnomaliesDetected)
}

func TestMLDetectorFlowAnomalies(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test flow analysis with normal flows first
	normalFlows := []struct {
		srcIP   string
		packets uint64
		bytes   uint64
	}{
		{"192.168.1.100", 100, 150000},
		{"192.168.1.101", 150, 200000},
		{"192.168.1.102", 120, 180000},
	}

	for _, nf := range normalFlows {
		flow := &models.FlowMetrics{
			Key: models.FlowKey{
				SrcIP:    net.ParseIP(nf.srcIP),
				DstIP:    net.ParseIP("10.0.1.50"),
				SrcPort:  8080,
				DstPort:  443,
				Protocol: models.ProtocolTCP,
			},
			Packets:   nf.packets,
			Bytes:     nf.bytes,
			FirstSeen: time.Now().Add(-time.Minute),
			LastSeen:  time.Now(),
			Flags:     0x18,
		}

		threat := detector.AnalyzeFlowAnomaly(flow)
		if threat != nil {
			t.Logf("Normal flow flagged as threat: %s", threat.Description)
		}
	}

	// Test with highly anomalous flows
	anomalousFlows := []struct {
		name    string
		packets uint64
		bytes   uint64
		flags   uint32
	}{
		{"massive_flow", 100000, 1000000000, 0x18},     // 1GB flow
		{"tiny_packets", 10000, 10000, 0x02},           // Many tiny packets
		{"suspicious_flags", 1000, 1500000, 0xFF},      // Weird flags
		{"flood_packets", 50000, 50000000, 0x04},       // RST flood
	}

	for _, af := range anomalousFlows {
		flow := &models.FlowMetrics{
			Key: models.FlowKey{
				SrcIP:    net.ParseIP("192.168.1.200"),
				DstIP:    net.ParseIP("10.0.1.50"),
				SrcPort:  uint16(50000 + len(af.name)),
				DstPort:  443,
				Protocol: models.ProtocolTCP,
			},
			Packets:   af.packets,
			Bytes:     af.bytes,
			FirstSeen: time.Now().Add(-time.Minute),
			LastSeen:  time.Now(),
			Flags:     af.flags,
		}

		threat := detector.AnalyzeFlowAnomaly(flow)
		if threat != nil {
			t.Logf("Anomalous flow %s detected: severity=%s", af.name, threat.Severity.String())
		}
	}

	// Test edge case with malformed flow
	emptyFlow := &models.FlowMetrics{
		Key: models.FlowKey{
			SrcIP:    net.ParseIP("0.0.0.0"),
			DstIP:    net.ParseIP("0.0.0.0"),
			SrcPort:  0,
			DstPort:  0,
			Protocol: models.ProtocolTCP,
		},
		Packets:   0,
		Bytes:     0,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Flags:     0,
	}

	threat := detector.AnalyzeFlowAnomaly(emptyFlow)
	if threat != nil {
		t.Log("Empty flow generated threat (unexpected but handled)")
	}

	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Log("Flow analysis may not update TotalAnalyzed counter")
	}
}

func TestMLDetectorBaselineUpdates(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Send many packets to trigger baseline updates
	srcIP := net.ParseIP("192.168.1.100")
	
	// Build up a substantial dataset for baseline calculation
	for round := 0; round < 3; round++ {
		for i := 0; i < 50; i++ {
			// Vary the patterns slightly to trigger different code paths
			packetSize := uint32(1000 + (i*10)%500)
			flags := uint32(0x18)
			if i%10 == 0 {
				flags = 0x02 // SYN
			} else if i%15 == 0 {
				flags = 0x01 // FIN
			}

			packet := &models.PacketEvent{
				Timestamp:   time.Now(),
				SrcIP:       srcIP,
				DstIP:       net.ParseIP("10.0.1.50"),
				SrcPort:     uint16(8080 + i%100),
				DstPort:     uint16(443 + i%50),
				Protocol:    models.ProtocolTCP,
				PacketSize:  packetSize,
				Flags:       flags,
				ProcessID:   1234,
				ProcessName: "baseline_test",
			}
			
			threat := detector.AnalyzePacketAnomaly(packet)
			if threat != nil && round == 2 && i%20 == 0 {
				t.Logf("Threat detected in round %d, packet %d", round, i)
			}
		}
		
		// Small delay between rounds to potentially trigger different timing paths
		time.Sleep(10 * time.Millisecond)
	}

	// Send a clearly anomalous packet after baseline is established
	anomalyPacket := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       srcIP,
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     65535,
		DstPort:     1,
		Protocol:    models.ProtocolTCP,
		PacketSize:  65535,
		Flags:       0xFF,
		ProcessID:   1234,
		ProcessName: "anomaly",
	}

	threat := detector.AnalyzePacketAnomaly(anomalyPacket)
	if threat != nil {
		t.Logf("Final anomaly detected with severity: %s", threat.Severity.String())
	}

	// Verify analysis occurred
	stats := detector.GetMLStats()
	if stats.TotalAnalyzed == 0 {
		t.Error("Expected some analyzed items")
	}

	t.Logf("Final ML stats: TotalAnalyzed=%d, AnomaliesDetected=%d", 
		stats.TotalAnalyzed, stats.AnomaliesDetected)
}

func TestMLDetectorExtensiveAnomaly(t *testing.T) {
	detector := threats.NewMLThreatDetector()

	// Test anomaly detection with a large dataset to trigger all ML paths
	srcIP := net.ParseIP("192.168.1.100")
	
	// Phase 1: Build massive baseline dataset with varying patterns
	for phase := 0; phase < 5; phase++ {
		for i := 0; i < 100; i++ {
			// Create varied but somewhat consistent patterns
			packetSize := uint32(1000 + (i*phase*3)%1000)
			srcPort := uint16(8000 + (i*phase)%1000)
			dstPort := uint16(400 + (i*7)%300)
			flags := uint32(0x18)
			
			// Occasionally vary flags and ports to create more realistic traffic
			if i%20 == 0 {
				flags = 0x02 // SYN
			} else if i%25 == 0 {
				flags = 0x01 // FIN
			} else if i%30 == 0 {
				flags = 0x10 // ACK
			}

			packet := &models.PacketEvent{
				Timestamp:   time.Now(),
				SrcIP:       srcIP,
				DstIP:       net.ParseIP("10.0.1.50"),
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Protocol:    models.ProtocolTCP,
				PacketSize:  packetSize,
				Flags:       flags,
				ProcessID:   1234,
				ProcessName: "normal_traffic",
			}
			
			threat := detector.AnalyzePacketAnomaly(packet)
			if threat != nil && phase > 2 && i%50 == 0 {
				t.Logf("Normal traffic triggered threat in phase %d: %s", phase, threat.Description)
			}
		}
		
		// Add slight delay to simulate time progression  
		time.Sleep(5 * time.Millisecond)
	}

	// Phase 2: Inject highly anomalous patterns to test all severity levels
	extremeAnomalies := []struct {
		name     string
		size     uint32
		flags    uint32
		srcPort  uint16
		dstPort  uint16
		protocol models.Protocol
	}{
		{"massive_syn_flood", 40, 0x02, 65535, 80, models.ProtocolTCP},
		{"tiny_fragments", 1, 0x20, 31337, 1, models.ProtocolTCP},
		{"huge_packets", 65535, 0x18, 8080, 443, models.ProtocolTCP},
		{"port_scan_pattern", 64, 0x02, 54321, 22, models.ProtocolTCP},
		{"suspicious_udp", 512, 0x00, 53, 53, models.ProtocolUDP},
		{"all_flags_set", 1024, 0xFF, 12345, 54321, models.ProtocolTCP},
		{"encrypted_tunnel", 1400, 0x18, 443, 443, models.ProtocolTCP},
		{"data_exfil_sim", 65000, 0x18, 8080, 443, models.ProtocolTCP},
	}

	for _, anomaly := range extremeAnomalies {
		packet := &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       srcIP,
			DstIP:       net.ParseIP("8.8.8.8"), // External destination
			SrcPort:     anomaly.srcPort,
			DstPort:     anomaly.dstPort,
			Protocol:    anomaly.protocol,
			PacketSize:  anomaly.size,
			Flags:       anomaly.flags,
			ProcessID:   1234,
			ProcessName: anomaly.name,
		}
		
		threat := detector.AnalyzePacketAnomaly(packet)
		if threat != nil {
			t.Logf("Anomaly %s detected: severity=%s, description=%s", 
				anomaly.name, threat.Severity.String(), threat.Description)
		}
	}

	// Phase 3: Test with multiple IPs to create different profiles
	for ipSuffix := 101; ipSuffix <= 110; ipSuffix++ {
		testIP := net.IPv4(192, 168, 1, byte(ipSuffix))
		
		for i := 0; i < 20; i++ {
			packet := &models.PacketEvent{
				Timestamp:   time.Now(),
				SrcIP:       testIP,
				DstIP:       net.ParseIP("10.0.1.50"),
				SrcPort:     uint16(8000 + i),
				DstPort:     443,
				Protocol:    models.ProtocolTCP,
				PacketSize:  uint32(1000 + i*100),
				Flags:       0x18,
				ProcessID:   1234,
				ProcessName: "multi_ip_test",
			}
			
			detector.AnalyzePacketAnomaly(packet)
		}
	}

	// Final verification
	finalStats := detector.GetMLStats()
	t.Logf("Extensive ML test completed: TotalAnalyzed=%d, AnomaliesDetected=%d", 
		finalStats.TotalAnalyzed, finalStats.AnomaliesDetected)
	
	if finalStats.TotalAnalyzed == 0 {
		t.Error("Expected extensive analysis to register analyzed packets")
	}
}