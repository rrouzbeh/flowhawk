package models_test

import (
	"net"
	"testing"
	"time"

	"flowhawk/internal/models"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity models.Severity
		expected string
	}{
		{models.SeverityLow, "low"},
		{models.SeverityMedium, "medium"},
		{models.SeverityHigh, "high"},
		{models.SeverityCritical, "critical"},
		{models.Severity(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.expected {
				t.Errorf("Severity.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProtocolString(t *testing.T) {
	tests := []struct {
		protocol models.Protocol
		expected string
	}{
		{models.ProtocolTCP, "TCP"},
		{models.ProtocolUDP, "UDP"},
		{models.ProtocolICMP, "ICMP"},
		{models.Protocol(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.protocol.String(); got != tt.expected {
				t.Errorf("Protocol.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestThreatTypeString(t *testing.T) {
	tests := []struct {
		threatType models.ThreatType
		expected   string
	}{
		{models.ThreatPortScan, "Port Scan"},
		{models.ThreatDDoS, "DDoS Attack"},
		{models.ThreatBotnet, "Botnet Activity"},
		{models.ThreatType(99), "Unknown Threat"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.threatType.String(); got != tt.expected {
				t.Errorf("ThreatType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPacketEventStructure(t *testing.T) {
	now := time.Now()
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")

	event := models.PacketEvent{
		Timestamp:   now,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		PacketSize:  1024,
		Flags:       0x18,
		ProcessID:   1234,
		ProcessName: "nginx",
	}

	// Test that all fields are set correctly
	if !event.Timestamp.Equal(now) {
		t.Errorf("Expected timestamp %v, got %v", now, event.Timestamp)
	}
	if !event.SrcIP.Equal(srcIP) {
		t.Errorf("Expected SrcIP %v, got %v", srcIP, event.SrcIP)
	}
	if !event.DstIP.Equal(dstIP) {
		t.Errorf("Expected DstIP %v, got %v", dstIP, event.DstIP)
	}
	if event.SrcPort != 8080 {
		t.Errorf("Expected SrcPort 8080, got %d", event.SrcPort)
	}
	if event.DstPort != 443 {
		t.Errorf("Expected DstPort 443, got %d", event.DstPort)
	}
	if event.Protocol != models.ProtocolTCP {
		t.Errorf("Expected Protocol TCP, got %v", event.Protocol)
	}
	if event.PacketSize != 1024 {
		t.Errorf("Expected PacketSize 1024, got %d", event.PacketSize)
	}
	if event.ProcessID != 1234 {
		t.Errorf("Expected ProcessID 1234, got %d", event.ProcessID)
	}
	if event.ProcessName != "nginx" {
		t.Errorf("Expected ProcessName nginx, got %s", event.ProcessName)
	}
}

func TestThreatEventStructure(t *testing.T) {
	now := time.Now()
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.1.50")

	threatEvent := models.ThreatEvent{
		ID:          "threat-123",
		Type:        models.ThreatPortScan,
		Severity:    models.SeverityHigh,
		Timestamp:   now,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     8080,
		DstPort:     443,
		Protocol:    models.ProtocolTCP,
		Description: "Port scan detected",
		Metadata: map[string]interface{}{
			"scan_count": 100,
			"duration":   "30s",
		},
		ProcessID:   1234,
		ProcessName: "scanner",
	}

	if threatEvent.ID != "threat-123" {
		t.Errorf("Expected ID threat-123, got %s", threatEvent.ID)
	}
	if threatEvent.Type != models.ThreatPortScan {
		t.Errorf("Expected Type PortScan, got %v", threatEvent.Type)
	}
	if threatEvent.Severity != models.SeverityHigh {
		t.Errorf("Expected Severity High, got %v", threatEvent.Severity)
	}
	if !threatEvent.Timestamp.Equal(now) {
		t.Errorf("Expected Timestamp %v, got %v", now, threatEvent.Timestamp)
	}
	if !threatEvent.SrcIP.Equal(srcIP) {
		t.Errorf("Expected SrcIP %v, got %v", srcIP, threatEvent.SrcIP)
	}
	if threatEvent.Description != "Port scan detected" {
		t.Errorf("Expected Description 'Port scan detected', got %s", threatEvent.Description)
	}
	if threatEvent.Metadata["scan_count"] != 100 {
		t.Errorf("Expected Metadata scan_count 100, got %v", threatEvent.Metadata["scan_count"])
	}
	if threatEvent.ProcessID != 1234 {
		t.Errorf("Expected ProcessID 1234, got %d", threatEvent.ProcessID)
	}
	if threatEvent.ProcessName != "scanner" {
		t.Errorf("Expected ProcessName scanner, got %s", threatEvent.ProcessName)
	}
}