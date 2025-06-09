package ebpf_test

import (
	"context"
	"os"
	"testing"
	"time"

	"flowhawk/pkg/config"
	"flowhawk/pkg/ebpf"
)

func TestNewManager(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "eth0",
				Mode:      "native",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	if manager == nil {
		t.Fatal("Expected manager to be created, got nil")
	}

	// Test Load
	err = manager.Load()
	if err != nil {
		t.Errorf("Load returned error: %v", err)
	}

	// Test GetStats
	stats := manager.GetStats()
	if stats == nil {
		t.Errorf("Expected stats, got nil")
	}

	// Test Close
	err = manager.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestNewManagerWithDifferentConfigs(t *testing.T) {
	testCases := []struct {
		name      string
		iface     string
		mode      string
	}{
		{"eth0_native", "eth0", "native"},
		{"lo_generic", "lo", "generic"},
		{"any_skb", "any", "skb"},
		{"wlan0_native", "wlan0", "native"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				EBPF: config.EBPFConfig{
					XDP: config.XDPConfig{
						Interface: tc.iface,
						Mode:      tc.mode,
						Enable:    true,
					},
				},
			}

			manager, err := ebpf.NewManager(cfg)
			if err != nil {
				t.Fatalf("NewManager() returned error: %v", err)
			}

			if manager == nil {
				t.Fatal("Expected manager to be created, got nil")
			}
		})
	}
}

func TestManagerLoad(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo", // Use loopback which should always exist
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test Load in mock mode (SKIP_ROOT_CHECK set or non-root)
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Errorf("Load() returned error: %v", err)
	}
}

func TestManagerLoadWithInvalidInterface(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "nonexistent999",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Force non-mock mode by unsetting SKIP_ROOT_CHECK and running as non-root
	os.Unsetenv("SKIP_ROOT_CHECK")
	if os.Geteuid() != 0 {
		// Should succeed in mock mode for non-root
		err = manager.Load()
		if err != nil {
			t.Errorf("Load() in mock mode should not fail: %v", err)
		}
	}
}

func TestReadPacketEvents(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test reading events before load (should error)
	_, err = manager.ReadPacketEvents()
	if err == nil {
		t.Error("Expected error when reading events before Load(), got nil")
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test reading events after load
	events, err := manager.ReadPacketEvents()
	if err != nil {
		t.Errorf("ReadPacketEvents() returned error: %v", err)
	}

	if events == nil {
		t.Error("Expected events slice, got nil")
	}

	// Events should be empty in mock mode
	if len(events) != 0 {
		t.Errorf("Expected 0 events in mock mode, got %d", len(events))
	}
}

func TestReadSecurityEvents(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test reading events before load (should error)
	_, err = manager.ReadSecurityEvents()
	if err == nil {
		t.Error("Expected error when reading security events before Load(), got nil")
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test reading events after load
	events, err := manager.ReadSecurityEvents()
	if err != nil {
		t.Errorf("ReadSecurityEvents() returned error: %v", err)
	}

	if events == nil {
		t.Error("Expected events slice, got nil")
	}

	// Events should be empty in mock mode
	if len(events) != 0 {
		t.Errorf("Expected 0 security events in mock mode, got %d", len(events))
	}
}

func TestGetFlowMetrics(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test getting flows before load (should error)
	_, err = manager.GetFlowMetrics()
	if err == nil {
		t.Error("Expected error when getting flow metrics before Load(), got nil")
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test getting flows after load
	flows, err := manager.GetFlowMetrics()
	if err != nil {
		t.Errorf("GetFlowMetrics() returned error: %v", err)
	}

	if flows == nil {
		t.Error("Expected flows map, got nil")
	}

	// In mock mode, should have at least one sample flow
	if len(flows) == 0 {
		t.Error("Expected at least one sample flow in mock mode")
	}

	// Validate flow structure
	for key, metrics := range flows {
		if key.SrcPort == 0 && key.DstPort == 0 {
			t.Error("Expected valid ports in flow key")
		}
		if metrics.Packets == 0 {
			t.Error("Expected non-zero packet count in flow metrics")
		}
		if metrics.Bytes == 0 {
			t.Error("Expected non-zero byte count in flow metrics")
		}
		if metrics.FirstSeen == 0 || metrics.LastSeen == 0 {
			t.Error("Expected valid timestamps in flow metrics")
		}
	}
}

func TestGetStatistics(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test getting stats before load (should error)
	_, err = manager.GetStatistics()
	if err == nil {
		t.Error("Expected error when getting statistics before Load(), got nil")
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test getting stats after load
	stats, err := manager.GetStatistics()
	if err != nil {
		t.Errorf("GetStatistics() returned error: %v", err)
	}

	if stats == nil {
		t.Error("Expected stats map, got nil")
	}

	// Validate required statistics
	requiredStats := []int{
		ebpf.StatPacketsReceived,
		ebpf.StatPacketsDropped,
		ebpf.StatBytesReceived,
		ebpf.StatFlowsActive,
		ebpf.StatThreatsDetected,
	}

	for _, stat := range requiredStats {
		if _, exists := stats[stat]; !exists {
			t.Errorf("Expected statistic %d to exist", stat)
		}
	}

	// In mock mode, should have reasonable values
	if stats[ebpf.StatPacketsReceived] == 0 {
		t.Error("Expected non-zero packets received in mock mode")
	}
}

func TestGetStats(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test getting stats before load (should return empty stats)
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats object, got nil")
	}

	// All stats should be zero before load
	if stats.PacketsReceived != 0 || stats.PacketsDropped != 0 {
		t.Error("Expected zero stats before Load()")
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test getting stats after load
	stats = manager.GetStats()
	if stats == nil {
		t.Error("Expected stats object, got nil")
	}

	// Should have non-zero values in mock mode
	if stats.PacketsReceived == 0 {
		t.Error("Expected non-zero packets received after Load()")
	}
}

func TestGetFlows(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test getting flows before load (should return empty)
	flows := manager.GetFlows(10)
	if flows == nil {
		t.Error("Expected flows slice, got nil")
	}
	if len(flows) != 0 {
		t.Errorf("Expected 0 flows before Load(), got %d", len(flows))
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test getting flows after load
	flows = manager.GetFlows(10)
	if flows == nil {
		t.Error("Expected flows slice, got nil")
	}

	// Should have at least one flow in mock mode
	if len(flows) == 0 {
		t.Error("Expected at least one flow after Load()")
	}

	// Test limit functionality
	flows = manager.GetFlows(1)
	if len(flows) > 1 {
		t.Errorf("Expected at most 1 flow with limit 1, got %d", len(flows))
	}

	flows = manager.GetFlows(0)
	if len(flows) != 0 {
		t.Errorf("Expected 0 flows with limit 0, got %d", len(flows))
	}

	// Validate flow structure
	flows = manager.GetFlows(10)
	for _, flow := range flows {
		if flow.SrcIP == "" || flow.DstIP == "" {
			t.Error("Expected valid IP addresses in flow")
		}
		if flow.SrcPort == 0 && flow.DstPort == 0 {
			t.Error("Expected valid ports in flow")
		}
		if flow.Packets == 0 {
			t.Error("Expected non-zero packet count")
		}
		if flow.Bytes == 0 {
			t.Error("Expected non-zero byte count")
		}
	}
}

func TestProcessEvents(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test ProcessEvents with context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	eventChan := make(chan interface{}, 10)

	// This should complete when context is cancelled
	manager.ProcessEvents(ctx, eventChan)

	// Should not panic or error
	close(eventChan)
}

func TestClose(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	manager, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	// Test close before load
	err = manager.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Load manager
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	err = manager.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Test close after load
	err = manager.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Operations should fail after close
	_, err = manager.ReadPacketEvents()
	if err == nil {
		t.Error("Expected error after Close(), got nil")
	}

	// Multiple closes should not error
	err = manager.Close()
	if err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}
}

func TestPacketEventMethods(t *testing.T) {
	event := &ebpf.PacketEvent{
		SrcIP: 0xC0A80164, // 192.168.1.100
		DstIP: 0x0A000132, // 10.0.1.50
		Comm:  [16]byte{'t', 'e', 's', 't', 0},
	}

	srcIP := event.SrcIPString()
	if srcIP != "100.1.168.192" {
		t.Errorf("Expected SrcIPString() = '100.1.168.192', got '%s'", srcIP)
	}

	dstIP := event.DstIPString()
	if dstIP != "50.1.0.10" {
		t.Errorf("Expected DstIPString() = '50.1.0.10', got '%s'", dstIP)
	}

	comm := event.CommString()
	if comm != "test" {
		t.Errorf("Expected CommString() = 'test', got '%s'", comm)
	}
}

func TestSecurityEventMethods(t *testing.T) {
	event := &ebpf.SecurityEvent{
		SrcIP: 0xC0A80164, // 192.168.1.100
		DstIP: 0x0A000132, // 10.0.1.50
		Comm:  [16]byte{'s', 'c', 'a', 'n', 'n', 'e', 'r', 0},
	}

	srcIP := event.SrcIPString()
	if srcIP != "100.1.168.192" {
		t.Errorf("Expected SrcIPString() = '100.1.168.192', got '%s'", srcIP)
	}

	dstIP := event.DstIPString()
	if dstIP != "50.1.0.10" {
		t.Errorf("Expected DstIPString() = '50.1.0.10', got '%s'", dstIP)
	}

	comm := event.CommString()
	if comm != "scanner" {
		t.Errorf("Expected CommString() = 'scanner', got '%s'", comm)
	}
}

func TestCommStringWithFullBuffer(t *testing.T) {
	// Test with full comm buffer (no null terminator)
	event := &ebpf.PacketEvent{
		Comm: [16]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
	}

	comm := event.CommString()
	expected := "abcdefghijklmnop"
	if comm != expected {
		t.Errorf("Expected CommString() = '%s', got '%s'", expected, comm)
	}
}

func TestManagerMockVsRealMode(t *testing.T) {
	cfg := &config.Config{
		EBPF: config.EBPFConfig{
			XDP: config.XDPConfig{
				Interface: "lo",
				Enable:    true,
			},
		},
	}

	// Test mock mode (SKIP_ROOT_CHECK set)
	os.Setenv("SKIP_ROOT_CHECK", "1")
	defer os.Unsetenv("SKIP_ROOT_CHECK")

	manager1, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	err = manager1.Load()
	if err != nil {
		t.Errorf("Load() in mock mode returned error: %v", err)
	}

	stats1, err := manager1.GetStatistics()
	if err != nil {
		t.Errorf("GetStatistics() in mock mode returned error: %v", err)
	}

	// Test without SKIP_ROOT_CHECK (still mock if non-root)
	os.Unsetenv("SKIP_ROOT_CHECK")

	manager2, err := ebpf.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() returned error: %v", err)
	}

	err = manager2.Load()
	if err != nil {
		t.Errorf("Load() returned error: %v", err)
	}

	stats2, err := manager2.GetStatistics()
	if err != nil {
		t.Errorf("GetStatistics() returned error: %v", err)
	}

	// Both should work (both in mock mode for non-root)
	if len(stats1) == 0 || len(stats2) == 0 {
		t.Error("Expected non-empty statistics in both modes")
	}
}

func TestConstants(t *testing.T) {
	// Test that constants are defined and have reasonable values
	if ebpf.StatPacketsReceived != 0 {
		t.Error("Expected StatPacketsReceived = 0")
	}
	if ebpf.StatPacketsDropped != 1 {
		t.Error("Expected StatPacketsDropped = 1")
	}
	if ebpf.StatBytesReceived != 2 {
		t.Error("Expected StatBytesReceived = 2")
	}

	// Test event type constants
	if ebpf.EventPortScan != 1 {
		t.Error("Expected EventPortScan = 1")
	}
	if ebpf.EventDDoSAttack != 2 {
		t.Error("Expected EventDDoSAttack = 2")
	}
}