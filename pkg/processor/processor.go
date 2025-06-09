package processor

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/alerts"
	"flowhawk/pkg/config"
	"flowhawk/pkg/ebpf"
	"flowhawk/pkg/protocols"
	"flowhawk/pkg/threats"
)

// EventProcessor handles events from eBPF programs and processes them
type EventProcessor struct {
	config      *config.Config
	ebpfManager EBPFManagerInterface

	// Threat detection engines
	threatEngine *threats.ThreatEngine
	mlDetector   *threats.MLThreatDetector
	httpParser   *protocols.Manager

	// Alert management
	alertManager *alerts.AlertManager

	// Event channels
	packetChan chan *models.PacketEvent
	threatChan chan *models.ThreatEvent

	// Statistics
	stats      *models.SystemMetrics
	statsMutex sync.RWMutex

	// Flow tracking
	flows      map[string]*models.FlowMetrics
	flowsMutex sync.RWMutex

	// Recent events for dashboard
	recentPackets []models.PacketEvent
	recentThreats []models.ThreatEvent
	recentHTTP    []models.HTTPEvent
	eventsMutex   sync.RWMutex

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// EBPFManagerInterface defines the interface for eBPF manager
type EBPFManagerInterface interface {
	ReadPacketEvents() ([]ebpf.PacketEvent, error)
	ReadSecurityEvents() ([]ebpf.SecurityEvent, error)
	GetStatistics() (map[int]uint64, error)
	GetFlowMetrics() (map[ebpf.FlowKey]ebpf.FlowMetrics, error)
}

// New creates a new event processor
func New(cfg *config.Config, manager EBPFManagerInterface) (*EventProcessor, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize threat detection engines
	threatEngine := threats.NewThreatEngine(cfg)
	mlDetector := threats.NewMLThreatDetector()

	// Initialize alert manager
	alertManager := alerts.NewAlertManager(cfg)
	httpParser := protocols.NewManager()

	return &EventProcessor{
		config:        cfg,
		ebpfManager:   manager,
		threatEngine:  threatEngine,
		mlDetector:    mlDetector,
		httpParser:    httpParser,
		alertManager:  alertManager,
		packetChan:    make(chan *models.PacketEvent, 10000),
		threatChan:    make(chan *models.ThreatEvent, 1000),
		stats:         &models.SystemMetrics{},
		flows:         make(map[string]*models.FlowMetrics),
		recentPackets: make([]models.PacketEvent, 0, 1000),
		recentThreats: make([]models.ThreatEvent, 0, 100),
		recentHTTP:    make([]models.HTTPEvent, 0, 100),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// Start begins processing events from eBPF
func (p *EventProcessor) Start(ctx context.Context) error {
	p.ctx = ctx

	// Start event readers
	p.wg.Add(3)
	go p.packetEventReader()
	go p.securityEventReader()
	go p.metricsCollector()

	// Start event processors
	p.wg.Add(2)
	go p.packetProcessor()
	go p.threatProcessor()

	log.Println("Event processor started")
	return nil
}

// packetEventReader reads packet events from eBPF ring buffer
func (p *EventProcessor) packetEventReader() {
	defer p.wg.Done()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			events, err := p.ebpfManager.ReadPacketEvents()
			if err != nil {
				log.Printf("Error reading packet events: %v", err)
				continue
			}

			for _, event := range events {
				packetEvent := p.convertPacketEvent(&event)

				select {
				case p.packetChan <- packetEvent:
				case <-p.ctx.Done():
					return
				default:
					// Channel full, drop event
					p.updateStats(func(s *models.SystemMetrics) {
						s.PacketsDropped++
					})
				}
			}
		}
	}
}

// securityEventReader reads security events from eBPF ring buffer
func (p *EventProcessor) securityEventReader() {
	defer p.wg.Done()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			events, err := p.ebpfManager.ReadSecurityEvents()
			if err != nil {
				log.Printf("Error reading security events: %v", err)
				continue
			}

			for _, event := range events {
				threatEvent := p.convertSecurityEvent(&event)

				select {
				case p.threatChan <- threatEvent:
				case <-p.ctx.Done():
					return
				default:
					// Channel full, drop event
					log.Printf("Threat channel full, dropping event: %s", threatEvent.Description)
				}
			}
		}
	}
}

// metricsCollector periodically collects metrics from eBPF maps
func (p *EventProcessor) metricsCollector() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.Monitoring.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.collectMetrics(); err != nil {
				log.Printf("Error collecting metrics: %v", err)
			}
		}
	}
}

// collectMetrics retrieves current metrics from eBPF maps
func (p *EventProcessor) collectMetrics() error {
	// Get statistics from eBPF
	stats, err := p.ebpfManager.GetStatistics()
	if err != nil {
		return fmt.Errorf("failed to get statistics: %w", err)
	}

	// Get flow metrics
	flows, err := p.ebpfManager.GetFlowMetrics()
	if err != nil {
		return fmt.Errorf("failed to get flow metrics: %w", err)
	}

	// Update system metrics
	p.updateStats(func(s *models.SystemMetrics) {
		s.Timestamp = time.Now()
		s.PacketsReceived = stats[ebpf.StatPacketsReceived]
		s.PacketsDropped = stats[ebpf.StatPacketsDropped]
		s.BytesReceived = stats[ebpf.StatBytesReceived]
		s.ActiveFlows = uint64(len(flows))
		s.ThreatsDetected = stats[ebpf.StatThreatsDetected]

		// Calculate rates (simplified)
		if s.PacketsReceived > 0 {
			s.PacketsPerSec = float64(s.PacketsReceived) / time.Since(s.Timestamp).Seconds()
			s.BytesPerSec = float64(s.BytesReceived) / time.Since(s.Timestamp).Seconds()
		}
	})

	// Update flow cache
	p.updateFlows(flows)

	return nil
}

// packetProcessor processes packet events
func (p *EventProcessor) packetProcessor() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case event := <-p.packetChan:
			p.processPacketEvent(event)
		}
	}
}

// threatProcessor processes threat events
func (p *EventProcessor) threatProcessor() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case event := <-p.threatChan:
			p.processThreatEvent(event)
		}
	}
}

// processPacketEvent handles individual packet events
func (p *EventProcessor) processPacketEvent(event *models.PacketEvent) {
	// Add to recent events (for dashboard)
	p.eventsMutex.Lock()
	p.recentPackets = append(p.recentPackets, *event)
	if len(p.recentPackets) > 1000 {
		p.recentPackets = p.recentPackets[1:]
	}
	p.eventsMutex.Unlock()

	// Update statistics
	p.updateStats(func(s *models.SystemMetrics) {
		s.PacketsReceived++
		s.BytesReceived += uint64(event.PacketSize)
	})

	// Protocol parsers (HTTP, etc.)
	if parsed := p.httpParser.ParsePacket(event); len(parsed) > 0 {
		p.eventsMutex.Lock()
		for _, h := range parsed {
			p.recentHTTP = append(p.recentHTTP, *h)
			if len(p.recentHTTP) > 100 {
				p.recentHTTP = p.recentHTTP[1:]
			}
		}
		p.eventsMutex.Unlock()
	}

	// Run threat detection algorithms
	if p.config.Threats.Enable {
		// Rule-based threat detection
		threats := p.threatEngine.AnalyzePacket(event)
		for _, threat := range threats {
			select {
			case p.threatChan <- threat:
			default:
				// Channel full, log and drop
				log.Printf("Threat channel full, dropping threat: %s", threat.Description)
			}
		}

		// ML-based anomaly detection
		if mlThreat := p.mlDetector.AnalyzePacketAnomaly(event); mlThreat != nil {
			select {
			case p.threatChan <- mlThreat:
			default:
				log.Printf("Threat channel full, dropping ML threat: %s", mlThreat.Description)
			}
		}
	}
}

// processThreatEvent handles security threat events
func (p *EventProcessor) processThreatEvent(event *models.ThreatEvent) {
	log.Printf("THREAT DETECTED: %s from %s:%d to %s:%d - %s",
		event.Type.String(),
		event.SrcIP.String(), event.SrcPort,
		event.DstIP.String(), event.DstPort,
		event.Description)

	// Add to recent threats (for dashboard)
	p.eventsMutex.Lock()
	p.recentThreats = append(p.recentThreats, *event)
	if len(p.recentThreats) > 100 {
		p.recentThreats = p.recentThreats[1:]
	}
	p.eventsMutex.Unlock()

	// Update threat counter
	p.updateStats(func(s *models.SystemMetrics) {
		s.ThreatsDetected++
	})

	// Send alerts through alert manager
	if p.config.Alerts.Enable {
		p.alertManager.SendAlert(event)
	}
}

// Close stops the event processor
func (p *EventProcessor) Close() error {
	p.cancel()
	p.wg.Wait()

	close(p.packetChan)
	close(p.threatChan)

	// Close alert manager
	if p.alertManager != nil {
		p.alertManager.Close()
	}

	return nil
}

// convertPacketEvent converts eBPF packet event to internal model
func (p *EventProcessor) convertPacketEvent(event *ebpf.PacketEvent) *models.PacketEvent {
	return &models.PacketEvent{
		Timestamp:   time.Unix(0, int64(event.Timestamp)),
		SrcIP:       parseIP(event.SrcIP),
		DstIP:       parseIP(event.DstIP),
		SrcPort:     event.SrcPort,
		DstPort:     event.DstPort,
		Protocol:    models.Protocol(event.Protocol),
		PacketSize:  event.PacketSize,
		Payload:     event.Payload[:event.PayloadLen],
		Flags:       event.Flags,
		ProcessID:   event.PID,
		ProcessName: event.CommString(),
	}
}

// convertSecurityEvent converts eBPF security event to internal model
func (p *EventProcessor) convertSecurityEvent(event *ebpf.SecurityEvent) *models.ThreatEvent {
	threatType := models.ThreatType(event.EventType - 1) // eBPF uses 1-based indexing

	var description string
	switch event.EventType {
	case ebpf.EventPortScan:
		description = fmt.Sprintf("Port scan detected: %d connection attempts", event.Metadata[0])
	case ebpf.EventDDoSAttack:
		description = fmt.Sprintf("DDoS attack detected: %d PPS", event.Metadata[0])
	case ebpf.EventSuspicious:
		description = "Suspicious network activity detected"
	case ebpf.EventBotnet:
		description = "Potential botnet communication detected"
	default:
		description = "Unknown threat detected"
	}

	return &models.ThreatEvent{
		ID:          fmt.Sprintf("threat-%d-%d", event.Timestamp, event.SrcIP),
		Type:        threatType,
		Severity:    models.Severity(event.Severity),
		Timestamp:   time.Unix(0, int64(event.Timestamp)),
		SrcIP:       parseIP(event.SrcIP),
		DstIP:       parseIP(event.DstIP),
		SrcPort:     event.SrcPort,
		DstPort:     event.DstPort,
		Protocol:    models.Protocol(event.Protocol),
		Description: description,
		Metadata: map[string]interface{}{
			"metadata_0": event.Metadata[0],
			"metadata_1": event.Metadata[1],
			"metadata_2": event.Metadata[2],
			"metadata_3": event.Metadata[3],
		},
		ProcessID:   event.PID,
		ProcessName: event.CommString(),
	}
}

// Helper functions
func (p *EventProcessor) updateStats(updater func(*models.SystemMetrics)) {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()
	updater(p.stats)
}

func (p *EventProcessor) updateFlows(ebpfFlows map[ebpf.FlowKey]ebpf.FlowMetrics) {
	p.flowsMutex.Lock()
	defer p.flowsMutex.Unlock()

	// Clear old flows
	p.flows = make(map[string]*models.FlowMetrics)

	// Convert eBPF flows to internal model
	for key, metrics := range ebpfFlows {
		flowKey := models.FlowKey{
			SrcIP:    parseIP(key.SrcIP),
			DstIP:    parseIP(key.DstIP),
			SrcPort:  key.SrcPort,
			DstPort:  key.DstPort,
			Protocol: models.Protocol(key.Protocol),
		}

		flowMetrics := &models.FlowMetrics{
			Key:       flowKey,
			Packets:   metrics.Packets,
			Bytes:     metrics.Bytes,
			FirstSeen: time.Unix(0, int64(metrics.FirstSeen)),
			LastSeen:  time.Unix(0, int64(metrics.LastSeen)),
			Flags:     metrics.Flags,
		}

		// Use string key for map
		flowKeyStr := fmt.Sprintf("%s:%d->%s:%d/%d",
			flowKey.SrcIP.String(), flowKey.SrcPort,
			flowKey.DstIP.String(), flowKey.DstPort,
			flowKey.Protocol)

		p.flows[flowKeyStr] = flowMetrics

		// Run ML flow anomaly detection
		if p.config.Threats.Enable {
			if mlThreat := p.mlDetector.AnalyzeFlowAnomaly(flowMetrics); mlThreat != nil {
				select {
				case p.threatChan <- mlThreat:
				default:
					log.Printf("Threat channel full, dropping ML flow threat: %s", mlThreat.Description)
				}
			}
		}
	}
}

func parseIP(ip uint32) []byte {
	return []byte{
		byte(ip),
		byte(ip >> 8),
		byte(ip >> 16),
		byte(ip >> 24),
	}
}

// Public getters for dashboard
func (p *EventProcessor) GetStats() models.SystemMetrics {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()
	return *p.stats
}

func (p *EventProcessor) GetTopFlows(limit int) []models.FlowMetrics {
	p.flowsMutex.RLock()
	defer p.flowsMutex.RUnlock()

	flows := make([]models.FlowMetrics, 0, len(p.flows))
	for _, flow := range p.flows {
		flows = append(flows, *flow)
	}

	// Sort by bytes descending (highest first)
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].Bytes > flows[j].Bytes
	})

	if len(flows) > limit {
		flows = flows[:limit]
	}

	return flows
}

func (p *EventProcessor) GetRecentThreats(limit int) []models.ThreatEvent {
	p.eventsMutex.RLock()
	defer p.eventsMutex.RUnlock()

	if len(p.recentThreats) > limit {
		return p.recentThreats[len(p.recentThreats)-limit:]
	}

	return append([]models.ThreatEvent(nil), p.recentThreats...)
}

func (p *EventProcessor) GetRecentHTTP(limit int) []models.HTTPEvent {
	p.eventsMutex.RLock()
	defer p.eventsMutex.RUnlock()

	if len(p.recentHTTP) > limit {
		return p.recentHTTP[len(p.recentHTTP)-limit:]
	}

	return append([]models.HTTPEvent(nil), p.recentHTTP...)
}

// GetAlertStats returns current alert statistics
func (p *EventProcessor) GetAlertStats() interface{} {
	if p.alertManager != nil {
		return p.alertManager.GetStats()
	}
	return nil
}

// GetActiveRules returns current threat detection rules
func (p *EventProcessor) GetActiveRules() []models.ThreatRule {
	if p.threatEngine != nil {
		return p.threatEngine.GetActiveRules()
	}
	return []models.ThreatRule{}
}
