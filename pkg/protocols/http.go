package protocols

import (
	"bufio"
	"bytes"
	"net/http"

	"flowhawk/internal/models"
)

// HTTPParser parses HTTP requests and responses from packet payloads.
type HTTPParser struct{}

func NewHTTPParser() *HTTPParser { return &HTTPParser{} }

// ParsePacket attempts to parse an HTTP event from a PacketEvent.
func (p *HTTPParser) ParsePacket(pkt *models.PacketEvent) *models.HTTPEvent {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil
	}
	if pkt.SrcPort != 80 && pkt.DstPort != 80 {
		return nil
	}

	reader := bufio.NewReader(bytes.NewReader(pkt.Payload))

	if bytes.HasPrefix(pkt.Payload, []byte("HTTP/")) {
		// Response
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil
		}
		return &models.HTTPEvent{
			Timestamp:  pkt.Timestamp,
			SrcIP:      pkt.SrcIP,
			SrcPort:    pkt.SrcPort,
			DstIP:      pkt.DstIP,
			DstPort:    pkt.DstPort,
			StatusCode: resp.StatusCode,
			Version:    resp.Proto,
			Direction:  "response",
		}
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil
	}
	return &models.HTTPEvent{
		Timestamp: pkt.Timestamp,
		SrcIP:     pkt.SrcIP,
		SrcPort:   pkt.SrcPort,
		DstIP:     pkt.DstIP,
		DstPort:   pkt.DstPort,
		Method:    req.Method,
		Host:      req.Host,
		URI:       req.URL.RequestURI(),
		UserAgent: req.UserAgent(),
		Version:   req.Proto,
		Direction: "request",
	}
}
