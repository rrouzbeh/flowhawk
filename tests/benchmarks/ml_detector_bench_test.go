package benchmarks

import (
	"net"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/threats"
)

// BenchmarkMLDetectorCreation benchmarks ML detector creation
func BenchmarkMLDetectorCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector := threats.NewMLThreatDetector()
		_ = detector
	}
}

// BenchmarkPacketAnomalyDetection benchmarks packet anomaly detection
func BenchmarkPacketAnomalyDetection(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1500,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test-process",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.Timestamp = time.Now()
		packet.SrcPort = uint16(40000 + (i % 10000)) // Vary port
		threat := detector.AnalyzePacketAnomaly(packet)
		_ = threat
	}
}

// BenchmarkFlowAnomalyDetection benchmarks flow anomaly detection
func BenchmarkFlowAnomalyDetection(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	flowMetrics := &models.FlowMetrics{
		Key: models.FlowKey{
			SrcIP:    net.ParseIP("192.168.1.100"),
			DstIP:    net.ParseIP("10.0.1.50"),
			SrcPort:  40000,
			DstPort:  80,
			Protocol: models.ProtocolTCP,
		},
		Packets:   1000,
		Bytes:     1500000,
		FirstSeen: time.Now().Add(-5 * time.Minute),
		LastSeen:  time.Now(),
		Flags:     0x18,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flowMetrics.Packets = uint64(1000 + i%5000)
		flowMetrics.Bytes = uint64(1500000 + i*1000)
		flowMetrics.LastSeen = time.Now()
		threat := detector.AnalyzeFlowAnomaly(flowMetrics)
		_ = threat
	}
}

// BenchmarkVariousPacketSizes benchmarks detection with various packet sizes
func BenchmarkVariousPacketSizes(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	basePack := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test-process",
	}
	
	packetSizes := []uint32{64, 128, 256, 512, 1024, 1500}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := *basePack
		packet.PacketSize = packetSizes[i%len(packetSizes)]
		packet.Timestamp = time.Now()
		threat := detector.AnalyzePacketAnomaly(&packet)
		_ = threat
	}
}

// BenchmarkDifferentProtocols benchmarks detection across different protocols
func BenchmarkDifferentProtocols(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	basePack := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     80,
		PacketSize:  1000,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test-process",
	}
	
	protocols := []models.Protocol{
		models.ProtocolTCP,
		models.ProtocolUDP,
		models.ProtocolICMP,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := *basePack
		packet.Protocol = protocols[i%len(protocols)]
		packet.Timestamp = time.Now()
		threat := detector.AnalyzePacketAnomaly(&packet)
		_ = threat
	}
}

// BenchmarkHighVolumeFlows benchmarks with high volume of different flows
func BenchmarkHighVolumeFlows(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	// Pre-generate flows to avoid allocation overhead
	flows := make([]*models.FlowMetrics, 1000)
	baseTime := time.Now()
	
	for i := 0; i < len(flows); i++ {
		flows[i] = &models.FlowMetrics{
			Key: models.FlowKey{
				SrcIP:    net.IPv4(192, 168, 1, byte(100+i%150)),
				DstIP:    net.IPv4(10, 0, 1, byte(50+i%200)),
				SrcPort:  uint16(40000 + i),
				DstPort:  uint16(80 + (i % 100)),
				Protocol: models.Protocol(6 + (i % 3)),
			},
			Packets:   uint64(100 + i*10),
			Bytes:     uint64(150000 + i*1000),
			FirstSeen: baseTime.Add(-time.Duration(i) * time.Second),
			LastSeen:  baseTime,
			Flags:     0x18,
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flow := flows[i%len(flows)]
		flow.LastSeen = time.Now()
		threat := detector.AnalyzeFlowAnomaly(flow)
		_ = threat
	}
}

// BenchmarkMLDetectorConcurrency benchmarks concurrent ML detection
func BenchmarkMLDetectorConcurrency(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1000,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test-process",
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		localPacket := *packet // Create local copy
		counter := 0
		for pb.Next() {
			localPacket.SrcPort = uint16(40000 + counter)
			localPacket.Timestamp = time.Now()
			threat := detector.AnalyzePacketAnomaly(&localPacket)
			_ = threat
			counter++
		}
	})
}

// BenchmarkAnomalyPatterns benchmarks different anomaly patterns
func BenchmarkAnomalyPatterns(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	// Create patterns that might trigger anomaly detection
	patterns := []struct {
		name   string
		packet *models.PacketEvent
	}{
		{
			"normal_web_traffic",
			&models.PacketEvent{
				SrcIP: net.ParseIP("192.168.1.100"), DstIP: net.ParseIP("8.8.8.8"),
				SrcPort: 45000, DstPort: 80, Protocol: models.ProtocolTCP, PacketSize: 1400,
			},
		},
		{
			"dns_query",
			&models.PacketEvent{
				SrcIP: net.ParseIP("192.168.1.100"), DstIP: net.ParseIP("8.8.8.8"),
				SrcPort: 53000, DstPort: 53, Protocol: models.ProtocolUDP, PacketSize: 64,
			},
		},
		{
			"large_upload",
			&models.PacketEvent{
				SrcIP: net.ParseIP("192.168.1.100"), DstIP: net.ParseIP("1.2.3.4"),
				SrcPort: 55000, DstPort: 443, Protocol: models.ProtocolTCP, PacketSize: 1500,
			},
		},
		{
			"port_scan_attempt",
			&models.PacketEvent{
				SrcIP: net.ParseIP("1.2.3.4"), DstIP: net.ParseIP("192.168.1.100"),
				SrcPort: 40000, DstPort: 22, Protocol: models.ProtocolTCP, PacketSize: 64,
			},
		},
		{
			"icmp_ping",
			&models.PacketEvent{
				SrcIP: net.ParseIP("192.168.1.100"), DstIP: net.ParseIP("8.8.8.8"),
				SrcPort: 0, DstPort: 0, Protocol: models.ProtocolICMP, PacketSize: 84,
			},
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern := patterns[i%len(patterns)]
		packet := *pattern.packet
		packet.Timestamp = time.Now()
		packet.ProcessID = uint32(1000 + i)
		packet.ProcessName = "bench-" + pattern.name
		
		threat := detector.AnalyzePacketAnomaly(&packet)
		_ = threat
	}
}

// BenchmarkFlowDurationVariations benchmarks flows with different durations
func BenchmarkFlowDurationVariations(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	baseFlow := &models.FlowMetrics{
		Key: models.FlowKey{
			SrcIP:    net.ParseIP("192.168.1.100"),
			DstIP:    net.ParseIP("10.0.1.50"),
			SrcPort:  40000,
			DstPort:  80,
			Protocol: models.ProtocolTCP,
		},
		Packets: 1000,
		Bytes:   1500000,
		Flags:   0x18,
	}
	
	durations := []time.Duration{
		1 * time.Second,
		10 * time.Second,
		1 * time.Minute,
		10 * time.Minute,
		1 * time.Hour,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flow := *baseFlow
		duration := durations[i%len(durations)]
		now := time.Now()
		flow.FirstSeen = now.Add(-duration)
		flow.LastSeen = now
		
		threat := detector.AnalyzeFlowAnomaly(&flow)
		_ = threat
	}
}

// BenchmarkMLDetectorMemory benchmarks memory allocation patterns
func BenchmarkMLDetectorMemory(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1000,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "test-process",
	}
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		packet.Timestamp = time.Now()
		packet.SrcPort = uint16(40000 + i)
		threat := detector.AnalyzePacketAnomaly(packet)
		_ = threat
	}
}

// BenchmarkBatchAnalysis benchmarks analyzing batches of packets
func BenchmarkBatchAnalysis(b *testing.B) {
	detector := threats.NewMLThreatDetector()
	
	// Pre-generate a batch of packets
	batchSize := 100
	packets := make([]*models.PacketEvent, batchSize)
	
	for i := 0; i < batchSize; i++ {
		packets[i] = &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       net.IPv4(192, 168, 1, byte(100+i%50)),
			DstIP:       net.IPv4(10, 0, 1, byte(50+i%50)),
			SrcPort:     uint16(40000 + i),
			DstPort:     uint16(80 + (i % 10)),
			Protocol:    models.Protocol(6 + (i % 3)),
			PacketSize:  uint32(64 + (i % 1400)),
			Flags:       0x18,
			ProcessID:   uint32(1000 + i),
			ProcessName: "batch-proc",
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Analyze a batch of packets
		for j := 0; j < batchSize; j++ {
			packet := packets[j]
			packet.Timestamp = time.Now()
			threat := detector.AnalyzePacketAnomaly(packet)
			_ = threat
		}
	}
}