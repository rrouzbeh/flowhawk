package benchmarks

import (
	"net"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
	"flowhawk/pkg/threats"
)

// createThreatEngineConfig creates a configuration optimized for threat detection benchmarking
func createThreatEngineConfig() *config.Config {
	return &config.Config{
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Enable:    true,
				Threshold: 20,
				Window:    60 * time.Second,
			},
			DDoS: config.DDoSConfig{
				Enable:       true,
				PPSThreshold: 10000,
				BPSThreshold: 10000000,
				Window:       30 * time.Second,
			},
			Botnet: config.BotnetConfig{
				Enable:          true,
				BeaconInterval:  300 * time.Second,
				C2Domains:       []string{"malicious.com", "evil-c2.net", "botnet.bad"},
			},
		},
	}
}

// BenchmarkThreatEngineCreation benchmarks threat engine creation
func BenchmarkThreatEngineCreation(b *testing.B) {
	cfg := createThreatEngineConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := threats.NewThreatEngine(cfg)
		_ = engine
	}
}

// BenchmarkPortScanDetection benchmarks port scan detection
func BenchmarkPortScanDetection(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Create a packet that would trigger port scan detection
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     22, // SSH port
		Protocol:    models.ProtocolTCP,
		PacketSize:  64,
		Flags:       0x02, // SYN flag
		ProcessID:   1234,
		ProcessName: "nmap",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.DstPort = uint16(22 + (i % 65000)) // Vary destination port
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkDDoSDetection benchmarks DDoS detection
func BenchmarkDDoSDetection(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Create packets for DDoS simulation
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("1.2.3.4"),
		DstIP:       net.ParseIP("192.168.1.100"), // Target
		SrcPort:     40000,
		DstPort:     80,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1500,
		Flags:       0x18, // PSH + ACK
		ProcessID:   1234,
		ProcessName: "flood-tool",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate different source IPs
		packet.SrcIP = net.IPv4(byte(i%256), byte((i/256)%256), byte((i/65536)%256), byte(i%256))
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkBotnetDetection benchmarks botnet detection
func BenchmarkBotnetDetection(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Create packets for botnet communication simulation
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.150"),
		DstIP:       net.ParseIP("1.2.3.4"), // C2 server
		SrcPort:     45000,
		DstPort:     443, // HTTPS
		Protocol:    models.ProtocolTCP,
		PacketSize:  256,
		Flags:       0x18,
		ProcessID:   5678,
		ProcessName: "suspicious-proc",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.Timestamp = time.Now().Add(time.Duration(i) * time.Second)
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkDataExfiltrationDetection benchmarks data exfiltration detection
func BenchmarkDataExfiltrationDetection(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Create packets for data exfiltration simulation (outbound traffic)
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.200"), // Internal source
		DstIP:       net.ParseIP("8.8.8.8"),       // External destination
		SrcPort:     50000,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1450, // Large packets
		Flags:       0x18,
		ProcessID:   9999,
		ProcessName: "data-stealer",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkLateralMovementDetection benchmarks lateral movement detection
func BenchmarkLateralMovementDetection(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Create packets for lateral movement simulation (internal-to-internal)
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("192.168.1.200"),
		SrcPort:     45000,
		DstPort:     445, // SMB
		Protocol:    models.ProtocolTCP,
		PacketSize:  128,
		Flags:       0x02, // SYN
		ProcessID:   3333,
		ProcessName: "lateral-tool",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Vary target IP to simulate scanning
		packet.DstIP = net.IPv4(192, 168, 1, byte(100+(i%150)))
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkMultipleThreatTypes benchmarks detection of multiple threat types
func BenchmarkMultipleThreatTypes(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Create different types of packets
	packets := []*models.PacketEvent{
		// Port scan packet
		{
			Timestamp: time.Now(), SrcIP: net.ParseIP("1.1.1.1"), DstIP: net.ParseIP("192.168.1.100"),
			SrcPort: 40000, DstPort: 22, Protocol: models.ProtocolTCP, PacketSize: 64,
			Flags: 0x02, ProcessID: 1111, ProcessName: "scanner",
		},
		// DDoS packet
		{
			Timestamp: time.Now(), SrcIP: net.ParseIP("2.2.2.2"), DstIP: net.ParseIP("192.168.1.100"),
			SrcPort: 50000, DstPort: 80, Protocol: models.ProtocolTCP, PacketSize: 1500,
			Flags: 0x18, ProcessID: 2222, ProcessName: "flooder",
		},
		// Botnet packet
		{
			Timestamp: time.Now(), SrcIP: net.ParseIP("192.168.1.150"), DstIP: net.ParseIP("3.3.3.3"),
			SrcPort: 45000, DstPort: 443, Protocol: models.ProtocolTCP, PacketSize: 256,
			Flags: 0x18, ProcessID: 3333, ProcessName: "bot",
		},
		// Exfiltration packet
		{
			Timestamp: time.Now(), SrcIP: net.ParseIP("192.168.1.200"), DstIP: net.ParseIP("4.4.4.4"),
			SrcPort: 55000, DstPort: 443, Protocol: models.ProtocolTCP, PacketSize: 1400,
			Flags: 0x18, ProcessID: 4444, ProcessName: "exfil",
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkThreatEngineConcurrency benchmarks concurrent threat analysis
func BenchmarkThreatEngineConcurrency(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
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
		ProcessName: "test-proc",
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		localPacket := *packet // Create local copy
		for pb.Next() {
			localPacket.Timestamp = time.Now()
			threats := engine.AnalyzePacket(&localPacket)
			_ = threats
		}
	})
}

// BenchmarkGetActiveRules benchmarks rule retrieval
func BenchmarkGetActiveRules(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rules := engine.GetActiveRules()
		_ = rules
	}
}

// BenchmarkThreatEngineMemory benchmarks memory allocation patterns
func BenchmarkThreatEngineMemory(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	packet := &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       net.ParseIP("192.168.1.100"),
		DstIP:       net.ParseIP("10.0.1.50"),
		SrcPort:     40000,
		DstPort:     22,
		Protocol:    models.ProtocolTCP,
		PacketSize:  64,
		Flags:       0x02,
		ProcessID:   1234,
		ProcessName: "test",
	}
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		packet.DstPort = uint16(22 + (i % 1000))
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}

// BenchmarkHighVolumeAnalysis benchmarks analysis under high packet volume
func BenchmarkHighVolumeAnalysis(b *testing.B) {
	cfg := createThreatEngineConfig()
	engine := threats.NewThreatEngine(cfg)
	
	// Pre-generate packets to avoid allocation overhead in benchmark
	packets := make([]*models.PacketEvent, 1000)
	for i := 0; i < len(packets); i++ {
		packets[i] = &models.PacketEvent{
			Timestamp:   time.Now(),
			SrcIP:       net.IPv4(192, 168, 1, byte(100+i%50)),
			DstIP:       net.IPv4(10, 0, 1, byte(50+i%50)),
			SrcPort:     uint16(40000 + i),
			DstPort:     uint16(22 + (i % 100)),
			Protocol:    models.ProtocolTCP,
			PacketSize:  uint32(64 + (i % 1400)),
			Flags:       0x02,
			ProcessID:   uint32(1000 + i),
			ProcessName: "bench-proc",
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		packet.Timestamp = time.Now()
		threats := engine.AnalyzePacket(packet)
		_ = threats
	}
}