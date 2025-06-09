package protocols

import "flowhawk/internal/models"

// Manager holds protocol parsers.
type Manager struct {
	http *HTTPParser
}

func NewManager() *Manager {
	return &Manager{http: NewHTTPParser()}
}

// ParsePacket processes a packet and returns protocol events.
func (m *Manager) ParsePacket(pkt *models.PacketEvent) []*models.HTTPEvent {
	if m == nil {
		return nil
	}
	if ev := m.http.ParsePacket(pkt); ev != nil {
		return []*models.HTTPEvent{ev}
	}
	return nil
}
