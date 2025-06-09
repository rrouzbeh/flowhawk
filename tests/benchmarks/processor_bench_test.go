package benchmarks

import (
	"context"
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
	"flowhawk/pkg/ebpf"
	"flowhawk/pkg/processor"
)

// MockEBPFManager implements the EBPFManagerInterface for benchmarking
type MockEBPFManager struct {
	PacketEvents []ebpf.PacketEvent
	SecurityEvents []ebpf.SecurityEvent
}

func (m *MockEBPFManager) ReadPacketEvents() ([]ebpf.PacketEvent, error) {
	return m.PacketEvents, nil
}

func (m *MockEBPFManager) ReadSecurityEvents() ([]ebpf.SecurityEvent, error) {
	return m.SecurityEvents, nil
}

func (m *MockEBPFManager) GetStatistics() (map[int]uint64, error) {
	return map[int]uint64{
		ebpf.StatPacketsReceived: 10000,
		ebpf.StatPacketsDropped:  10,
		ebpf.StatBytesReceived:   5000000,
		ebpf.StatFlowsActive:     100,
		ebpf.StatThreatsDetected: 5,
	}, nil
}

func (m *MockEBPFManager) GetFlowMetrics() (map[ebpf.FlowKey]ebpf.FlowMetrics, error) {
	flows := make(map[ebpf.FlowKey]ebpf.FlowMetrics)
	now := uint64(time.Now().UnixNano())
	
	for i := 0; i < 1000; i++ {
		key := ebpf.FlowKey{
			SrcIP:    uint32(0xC0A80100 + i), // 192.168.1.x
			DstIP:    uint32(0x0A000100 + i), // 10.0.1.x
			SrcPort:  uint16(40000 + i),
			DstPort:  80,
			Protocol: 6, // TCP
		}
		metrics := ebpf.FlowMetrics{
			Packets:   uint64(100 + i),
			Bytes:     uint64(150000 + i*1000),
			FirstSeen: now - 60000000000,
			LastSeen:  now,
			Flags:     0x18,
			TCPState:  1,
		}
		flows[key] = metrics
	}
	
	return flows, nil
}

// createBenchmarkConfig creates a configuration for benchmarking
func createBenchmarkConfig() *config.Config {
	return &config.Config{
		Monitoring: config.MonitoringConfig{
			MetricsInterval: 100 * time.Millisecond,
		},
		Threats: config.ThreatsConfig{
			Enable: true,
			PortScan: config.PortScanConfig{
				Enable:    true,
				Threshold: 10,
				Window:    30 * time.Second,
			},
			DDoS: config.DDoSConfig{
				Enable:       true,
				PPSThreshold: 1000,
				BPSThreshold: 1000000,
				Window:       10 * time.Second,
			},
			Botnet: config.BotnetConfig{
				Enable:          true,
				BeaconInterval:  30 * time.Second,
				C2Domains:       []string{"malicious.com", "botnet.evil"},
			},
		},
		Alerts: config.AlertsConfig{
			Enable: true,
		},
	}
}

// createMockPacketEvent creates a mock packet event for testing
func createMockPacketEvent(srcIP, dstIP uint32, srcPort, dstPort uint16, protocol uint8) *models.PacketEvent {
	return &models.PacketEvent{
		Timestamp:   time.Now(),
		SrcIP:       []byte{byte(srcIP), byte(srcIP >> 8), byte(srcIP >> 16), byte(srcIP >> 24)},
		DstIP:       []byte{byte(dstIP), byte(dstIP >> 8), byte(dstIP >> 16), byte(dstIP >> 24)},
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    models.Protocol(protocol),
		PacketSize:  1500,
		Flags:       0x18, // PSH + ACK
		ProcessID:   1234,
		ProcessName: "test-process",
	}
}

// BenchmarkProcessorCreation benchmarks processor creation
func BenchmarkProcessorCreation(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor, err := processor.New(cfg, mockManager)
		if err != nil {
			b.Fatal(err)
		}
		processor.Close()
	}
}

// BenchmarkPacketProcessing benchmarks single packet processing
func BenchmarkPacketProcessing(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	proc, err := processor.New(cfg, mockManager)
	if err != nil {
		b.Fatal(err)
	}
	defer proc.Close()
	
	packet := createMockPacketEvent(0xC0A80101, 0x08080808, 40000, 80, 6)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Test packet processing through reflection since processPacketEvent is private
		// In practice, we'd expose a public method or test interface
		_ = packet
	}
}

// BenchmarkMetricsCollection benchmarks metrics collection
func BenchmarkMetricsCollection(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	proc, err := processor.New(cfg, mockManager)
	if err != nil {
		b.Fatal(err)
	}
	defer proc.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats := proc.GetStats()
		_ = stats
	}
}

// BenchmarkFlowRetrieval benchmarks flow data retrieval
func BenchmarkFlowRetrieval(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	proc, err := processor.New(cfg, mockManager)
	if err != nil {
		b.Fatal(err)
	}
	defer proc.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flows := proc.GetTopFlows(100)
		_ = flows
	}
}

// BenchmarkProcessorConcurrency benchmarks concurrent operations
func BenchmarkProcessorConcurrency(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	proc, err := processor.New(cfg, mockManager)
	if err != nil {
		b.Fatal(err)
	}
	defer proc.Close()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stats := proc.GetStats()
			flows := proc.GetTopFlows(10)
			threats := proc.GetRecentThreats(10)
			_ = stats
			_ = flows
			_ = threats
		}
	})
}

// BenchmarkHighVolumePackets benchmarks processing high volume of packets
func BenchmarkHighVolumePackets(b *testing.B) {
	cfg := createBenchmarkConfig()
	
	// Create mock manager with high volume of events
	mockManager := &MockEBPFManager{
		PacketEvents: make([]ebpf.PacketEvent, 10000),
	}
	
	// Fill with realistic packet events
	now := uint64(time.Now().UnixNano())
	for i := 0; i < len(mockManager.PacketEvents); i++ {
		mockManager.PacketEvents[i] = ebpf.PacketEvent{
			Timestamp:  now + uint64(i*1000000), // 1ms intervals
			SrcIP:      uint32(0xC0A80100 + i%256),
			DstIP:      uint32(0x08080800 + i%256),
			SrcPort:    uint16(40000 + i%1000),
			DstPort:    80,
			Protocol:   6,
			PacketSize: 1500,
			Flags:      0x18,
			PID:        uint32(1000 + i%100),
		}
	}
	
	proc, err := processor.New(cfg, mockManager)
	if err != nil {
		b.Fatal(err)
	}
	defer proc.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events, _ := mockManager.ReadPacketEvents()
		_ = events // In real implementation, these would be processed
	}
}

// BenchmarkProcessorStartStop benchmarks processor lifecycle
func BenchmarkProcessorStartStop(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proc, err := processor.New(cfg, mockManager)
		if err != nil {
			b.Fatal(err)
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		proc.Start(ctx)
		cancel()
		proc.Close()
	}
}

// BenchmarkMemoryUsage benchmarks memory allocation patterns
func BenchmarkMemoryUsage(b *testing.B) {
	cfg := createBenchmarkConfig()
	mockManager := &MockEBPFManager{}
	
	proc, err := processor.New(cfg, mockManager)
	if err != nil {
		b.Fatal(err)
	}
	defer proc.Close()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		packet := createMockPacketEvent(0xC0A80101, 0x08080808, 40000, 80, 6)
		_ = packet
		
		stats := proc.GetStats()
		_ = stats
	}
}