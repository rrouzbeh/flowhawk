package protocols_test

import (
	"testing"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/protocols"
)

func TestHTTPParserRequest(t *testing.T) {
	parser := protocols.NewHTTPParser()
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	event := &models.PacketEvent{
		Timestamp: time.Now(),
		SrcIP:     []byte{1, 1, 1, 1},
		DstIP:     []byte{2, 2, 2, 2},
		SrcPort:   12345,
		DstPort:   80,
		Protocol:  models.ProtocolTCP,
		Payload:   payload,
	}
	httpEvent := parser.ParsePacket(event)
	if httpEvent == nil || httpEvent.Method != "GET" || httpEvent.Host != "example.com" {
		t.Errorf("failed to parse http request")
	}
}

func TestHTTPParserResponse(t *testing.T) {
	parser := protocols.NewHTTPParser()
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	event := &models.PacketEvent{
		Timestamp: time.Now(),
		SrcIP:     []byte{2, 2, 2, 2},
		DstIP:     []byte{1, 1, 1, 1},
		SrcPort:   80,
		DstPort:   54321,
		Protocol:  models.ProtocolTCP,
		Payload:   payload,
	}
	httpEvent := parser.ParsePacket(event)
	if httpEvent == nil || httpEvent.StatusCode != 200 {
		t.Errorf("failed to parse http response")
	}
}
