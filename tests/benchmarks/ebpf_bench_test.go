package benchmarks

import (
	"context"
	"testing"
	"time"

	"flowhawk/pkg/config"
	"flowhawk/pkg/ebpf"
)

// createEBPFConfig creates a configuration for eBPF benchmarking
func createEBPFConfig() *config.Config {
	return &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo", // Use loopback for testing
				Mode:      "driver",
			},
			MapSizes: config.MapSizesConfig{
				FlowMap:   65536,
				StatsMap:  1024,
				ConfigMap: 64,
			},
			Sampling: config.SamplingConfig{
				Rate:   1,
				Offset: 0,
			},
		},
	}
}

// BenchmarkEBPFManagerCreation benchmarks eBPF manager creation
func BenchmarkEBPFManagerCreation(b *testing.B) {
	cfg := createEBPFConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager, err := ebpf.NewManager(cfg)
		if err != nil {
			b.Fatal(err)
		}
		_ = manager
	}
}

// BenchmarkEBPFManagerLoad benchmarks eBPF program loading
func BenchmarkEBPFManagerLoad(b *testing.B) {
	cfg := createEBPFConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager, err := ebpf.NewManager(cfg)
		if err != nil {
			b.Fatal(err)
		}
		
		err = manager.Load()
		if err != nil {
			b.Fatal(err)
		}
		
		manager.Close()
	}
}

// BenchmarkPacketEventReading benchmarks packet event reading
func BenchmarkPacketEventReading(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events, err := manager.ReadPacketEvents()
		if err != nil {
			b.Fatal(err)
		}
		_ = events
	}
}

// BenchmarkSecurityEventReading benchmarks security event reading
func BenchmarkSecurityEventReading(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		events, err := manager.ReadSecurityEvents()
		if err != nil {
			b.Fatal(err)
		}
		_ = events
	}
}

// BenchmarkFlowMetricsRetrieval benchmarks flow metrics retrieval
func BenchmarkFlowMetricsRetrieval(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flows, err := manager.GetFlowMetrics()
		if err != nil {
			b.Fatal(err)
		}
		_ = flows
	}
}

// BenchmarkStatisticsRetrieval benchmarks statistics retrieval
func BenchmarkStatisticsRetrieval(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats, err := manager.GetStatistics()
		if err != nil {
			b.Fatal(err)
		}
		_ = stats
	}
}

// BenchmarkEBPFConcurrentReads benchmarks concurrent data reading
func BenchmarkEBPFConcurrentReads(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate concurrent access patterns
			stats, _ := manager.GetStatistics()
			flows, _ := manager.GetFlowMetrics()
			events, _ := manager.ReadPacketEvents()
			secEvents, _ := manager.ReadSecurityEvents()
			
			_ = stats
			_ = flows
			_ = events
			_ = secEvents
		}
	})
}

// BenchmarkEBPFEventProcessing benchmarks event processing with context
func BenchmarkEBPFEventProcessing(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		eventChan := make(chan interface{}, 100)
		
		go manager.ProcessEvents(ctx, eventChan)
		
		cancel()
		close(eventChan)
	}
}

// BenchmarkGetStats benchmarks statistics getter
func BenchmarkGetStats(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats := manager.GetStats()
		_ = stats
	}
}

// BenchmarkGetFlows benchmarks flow retrieval with limits
func BenchmarkGetFlows(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flows := manager.GetFlows(100)
		_ = flows
	}
}

// BenchmarkHighFrequencyPolling benchmarks high-frequency data polling
func BenchmarkHighFrequencyPolling(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ResetTimer()
	
	// Simulate high-frequency polling scenario
	for i := 0; i < b.N; i++ {
		// This simulates a polling loop that might run every few milliseconds
		manager.ReadPacketEvents()
		manager.ReadSecurityEvents()
		manager.GetStatistics()
		
		if i%10 == 0 { // Less frequent flow retrieval
			manager.GetFlowMetrics()
		}
	}
}

// BenchmarkEBPFMemoryUsage benchmarks memory allocation patterns
func BenchmarkEBPFMemoryUsage(b *testing.B) {
	cfg := createEBPFConfig()
	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	err = manager.Load()
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Close()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		events, _ := manager.ReadPacketEvents()
		flows, _ := manager.GetFlowMetrics()
		stats, _ := manager.GetStatistics()
		
		_ = events
		_ = flows
		_ = stats
	}
}

// BenchmarkIPConversion benchmarks IP address conversion functions
func BenchmarkIPConversion(b *testing.B) {
	// Test IP conversion performance
	event := &ebpf.PacketEvent{
		SrcIP: 0xC0A80101, // 192.168.1.1
		DstIP: 0x08080808, // 8.8.8.8
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		srcIP := event.SrcIPString()
		dstIP := event.DstIPString()
		_ = srcIP
		_ = dstIP
	}
}

// BenchmarkCommStringExtraction benchmarks process name extraction
func BenchmarkCommStringExtraction(b *testing.B) {
	event := &ebpf.PacketEvent{
		Comm: [16]byte{'t', 'e', 's', 't', '-', 'p', 'r', 'o', 'c', 'e', 's', 's', 0, 0, 0, 0},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		comm := event.CommString()
		_ = comm
	}
}

// BenchmarkEBPFManagerLifecycle benchmarks complete manager lifecycle
func BenchmarkEBPFManagerLifecycle(b *testing.B) {
	cfg := createEBPFConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager, err := ebpf.NewManager(cfg)
		if err != nil {
			b.Fatal(err)
		}
		
		err = manager.Load()
		if err != nil {
			b.Fatal(err)
		}
		
		// Simulate some work
		manager.GetStatistics()
		manager.ReadPacketEvents()
		
		manager.Close()
	}
}