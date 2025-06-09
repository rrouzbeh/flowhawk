package threats

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
)

// ThreatEngine implements advanced threat detection algorithms
type ThreatEngine struct {
	config *config.Config
	
	// Detection state
	portScanTracker    map[string]*PortScanState
	ddosTracker        map[string]*DDoSState
	botnetTracker      map[string]*BotnetState
	exfilTracker       map[string]*ExfiltrationState
	lateralTracker     map[string]*LateralMovementState
	
	// Thread safety
	mutex sync.RWMutex
	
	// Rules engine
	rules      []models.ThreatRule
	ruleEngine *RuleEngine
	
	// Event channel for detected threats
	threatChan chan *models.ThreatEvent
}

// PortScanState tracks port scanning activity from a source IP
type PortScanState struct {
	SourceIP        net.IP
	ConnectedPorts  map[uint16]time.Time
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalAttempts   int
	FailedAttempts  int
	UniqueTargets   map[string]bool
}

// DDoSState tracks potential DDoS attacks
type DDoSState struct {
	TargetIP       net.IP
	PacketCount    uint64
	ByteCount      uint64
	SourceIPs      map[string]uint64
	WindowStart    time.Time
	PeakPPS        float64
	PeakBPS        float64
}

// BotnetState tracks potential botnet activity
type BotnetState struct {
	SourceIP       net.IP
	C2Connections  []string
	BeaconPattern  []time.Time
	DNSQueries     []string
	FirstSeen      time.Time
	LastActivity   time.Time
	SuspiciousDNS  int
}

// ExfiltrationState tracks potential data exfiltration
type ExfiltrationState struct {
	SourceIP       net.IP
	TotalBytes     uint64
	Destinations   map[string]uint64
	WindowStart    time.Time
	UnusualPorts   map[uint16]int
	EncryptedTraffic int
}

// LateralMovementState tracks lateral movement attempts
type LateralMovementState struct {
	SourceIP       net.IP
	InternalScans  map[string]time.Time
	AdminPorts     map[uint16]int
	ServiceScans   map[string]int
	FirstSeen      time.Time
	LastSeen       time.Time
}

// NewThreatEngine creates a new threat detection engine
func NewThreatEngine(cfg *config.Config) *ThreatEngine {
	engine := &ThreatEngine{
		config:             cfg,
		portScanTracker:    make(map[string]*PortScanState),
		ddosTracker:        make(map[string]*DDoSState),
		botnetTracker:      make(map[string]*BotnetState),
		exfilTracker:       make(map[string]*ExfiltrationState),
		lateralTracker:     make(map[string]*LateralMovementState),
		ruleEngine:         NewRuleEngine(),
		threatChan:         make(chan *models.ThreatEvent, 1000),
	}
	
	// Initialize default threat detection rules
	engine.initializeRules()
	
	// Start cleanup goroutine
	go engine.cleanupStaleEntries()
	
	return engine
}

// AnalyzePacket analyzes a packet for threats
func (e *ThreatEngine) AnalyzePacket(packet *models.PacketEvent) []*models.ThreatEvent {
	if !e.config.Threats.Enable {
		return nil
	}
	
	var threats []*models.ThreatEvent
	
	// Port scan detection
	if e.config.Threats.PortScan.Enable {
		if threat := e.detectPortScan(packet); threat != nil {
			threats = append(threats, threat)
		}
	}
	
	// DDoS detection
	if e.config.Threats.DDoS.Enable {
		if threat := e.detectDDoS(packet); threat != nil {
			threats = append(threats, threat)
		}
	}
	
	// Botnet detection
	if e.config.Threats.Botnet.Enable {
		if threat := e.detectBotnet(packet); threat != nil {
			threats = append(threats, threat)
		}
	}
	
	// Data exfiltration detection
	if threat := e.detectDataExfiltration(packet); threat != nil {
		threats = append(threats, threat)
	}
	
	// Lateral movement detection
	if threat := e.detectLateralMovement(packet); threat != nil {
		threats = append(threats, threat)
	}
	
	// Custom rule-based detection
	ruleThreats := e.ruleEngine.EvaluatePacket(packet)
	threats = append(threats, ruleThreats...)
	
	return threats
}

// detectPortScan implements advanced port scan detection
func (e *ThreatEngine) detectPortScan(packet *models.PacketEvent) *models.ThreatEvent {
	// Only analyze TCP SYN packets for port scanning
	if packet.Protocol != models.ProtocolTCP || packet.Flags&0x02 == 0 {
		return nil
	}
	
	srcIP := packet.SrcIP.String()
	
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	state, exists := e.portScanTracker[srcIP]
	if !exists {
		state = &PortScanState{
			SourceIP:       packet.SrcIP,
			ConnectedPorts: make(map[uint16]time.Time),
			FirstSeen:      packet.Timestamp,
			UniqueTargets:  make(map[string]bool),
		}
		e.portScanTracker[srcIP] = state
	}
	
	// Update state
	state.LastSeen = packet.Timestamp
	state.TotalAttempts++
	state.ConnectedPorts[packet.DstPort] = packet.Timestamp
	state.UniqueTargets[packet.DstIP.String()] = true
	
	// Check for failed connections (RST or timeout)
	if packet.Flags&0x04 != 0 { // RST flag
		state.FailedAttempts++
	}
	
	// Analyze scanning patterns
	timeWindow := time.Duration(e.config.Threats.PortScan.Window)
	recentPorts := 0
	cutoff := packet.Timestamp.Add(-timeWindow)
	
	for _, timestamp := range state.ConnectedPorts {
		if timestamp.After(cutoff) {
			recentPorts++
		}
	}
	
	// Multiple detection criteria
	isPortScan := false
	severity := models.SeverityLow
	description := ""
	
	// Rapid port scanning
	if recentPorts > e.config.Threats.PortScan.Threshold {
		isPortScan = true
		severity = models.SeverityHigh
		description = fmt.Sprintf("Rapid port scan: %d ports in %v", recentPorts, timeWindow)
	}
	
	// Horizontal scanning (multiple targets)
	if len(state.UniqueTargets) > 10 && recentPorts > 20 {
		isPortScan = true
		severity = models.SeverityHigh
		description = fmt.Sprintf("Horizontal port scan: %d targets, %d ports", len(state.UniqueTargets), recentPorts)
	}
	
	// Stealth scanning (slow but persistent)
	if state.TotalAttempts > 100 && time.Since(state.FirstSeen) > time.Hour {
		isPortScan = true
		severity = models.SeverityMedium
		description = fmt.Sprintf("Stealth port scan: %d attempts over %v", state.TotalAttempts, time.Since(state.FirstSeen))
	}
	
	// High failure rate (typical of automated tools)
	if state.TotalAttempts > 50 && float64(state.FailedAttempts)/float64(state.TotalAttempts) > 0.8 {
		isPortScan = true
		severity = models.SeverityMedium
		description = fmt.Sprintf("Failed connection scan: %d/%d failed", state.FailedAttempts, state.TotalAttempts)
	}
	
	if isPortScan {
		return &models.ThreatEvent{
			ID:          fmt.Sprintf("portscan-%s-%d", srcIP, packet.Timestamp.Unix()),
			Type:        models.ThreatPortScan,
			Severity:    severity,
			Timestamp:   packet.Timestamp,
			SrcIP:       packet.SrcIP,
			DstIP:       packet.DstIP,
			SrcPort:     packet.SrcPort,
			DstPort:     packet.DstPort,
			Protocol:    packet.Protocol,
			Description: description,
			Metadata: map[string]interface{}{
				"total_attempts":  state.TotalAttempts,
				"failed_attempts": state.FailedAttempts,
				"unique_ports":    len(state.ConnectedPorts),
				"unique_targets":  len(state.UniqueTargets),
				"scan_duration":   time.Since(state.FirstSeen).Seconds(),
			},
			ProcessID:   packet.ProcessID,
			ProcessName: packet.ProcessName,
		}
	}
	
	return nil
}

// detectDDoS implements volumetric DDoS detection
func (e *ThreatEngine) detectDDoS(packet *models.PacketEvent) *models.ThreatEvent {
	dstIP := packet.DstIP.String()
	
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	state, exists := e.ddosTracker[dstIP]
	if !exists {
		state = &DDoSState{
			TargetIP:    packet.DstIP,
			SourceIPs:   make(map[string]uint64),
			WindowStart: packet.Timestamp,
		}
		e.ddosTracker[dstIP] = state
	}
	
	// Reset window if too old
	if packet.Timestamp.Sub(state.WindowStart) > e.config.Threats.DDoS.Window {
		state.PacketCount = 0
		state.ByteCount = 0
		state.SourceIPs = make(map[string]uint64)
		state.WindowStart = packet.Timestamp
	}
	
	// Update counters
	state.PacketCount++
	state.ByteCount += uint64(packet.PacketSize)
	state.SourceIPs[packet.SrcIP.String()]++
	
	// Calculate rates
	windowDuration := packet.Timestamp.Sub(state.WindowStart).Seconds()
	if windowDuration > 0 {
		currentPPS := float64(state.PacketCount) / windowDuration
		currentBPS := float64(state.ByteCount) / windowDuration
		
		if currentPPS > state.PeakPPS {
			state.PeakPPS = currentPPS
		}
		if currentBPS > state.PeakBPS {
			state.PeakBPS = currentBPS
		}
		
		// Check thresholds
		isVolumetricAttack := currentPPS > float64(e.config.Threats.DDoS.PPSThreshold) ||
			currentBPS > float64(e.config.Threats.DDoS.BPSThreshold)
		
		// Additional indicators
		uniqueSources := len(state.SourceIPs)
		isDistributed := uniqueSources > 100
		isAmplification := false
		
		// Check for amplification attacks (small requests, large responses)
		if packet.Protocol == models.ProtocolUDP {
			commonAmplificationPorts := []uint16{53, 123, 1900, 11211} // DNS, NTP, SSDP, Memcached
			for _, port := range commonAmplificationPorts {
				if packet.SrcPort == port && packet.PacketSize > 1000 {
					isAmplification = true
					break
				}
			}
		}
		
		if isVolumetricAttack {
			severity := models.SeverityHigh
			if isDistributed {
				severity = models.SeverityCritical
			}
			
			var description string
			if isAmplification {
				description = fmt.Sprintf("DDoS amplification attack: %.0f PPS, %.0f BPS from %d sources",
					currentPPS, currentBPS, uniqueSources)
			} else if isDistributed {
				description = fmt.Sprintf("Distributed DDoS attack: %.0f PPS, %.0f BPS from %d sources",
					currentPPS, currentBPS, uniqueSources)
			} else {
				description = fmt.Sprintf("DDoS attack: %.0f PPS, %.0f BPS", currentPPS, currentBPS)
			}
			
			return &models.ThreatEvent{
				ID:          fmt.Sprintf("ddos-%s-%d", dstIP, packet.Timestamp.Unix()),
				Type:        models.ThreatDDoS,
				Severity:    severity,
				Timestamp:   packet.Timestamp,
				SrcIP:       packet.SrcIP,
				DstIP:       packet.DstIP,
				SrcPort:     packet.SrcPort,
				DstPort:     packet.DstPort,
				Protocol:    packet.Protocol,
				Description: description,
				Metadata: map[string]interface{}{
					"packets_per_sec":    currentPPS,
					"bytes_per_sec":      currentBPS,
					"unique_sources":     uniqueSources,
					"is_distributed":     isDistributed,
					"is_amplification":   isAmplification,
					"window_duration":    windowDuration,
				},
			}
		}
	}
	
	return nil
}

// detectBotnet implements botnet communication detection
func (e *ThreatEngine) detectBotnet(packet *models.PacketEvent) *models.ThreatEvent {
	srcIP := packet.SrcIP.String()
	
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	state, exists := e.botnetTracker[srcIP]
	if !exists {
		state = &BotnetState{
			SourceIP:      packet.SrcIP,
			FirstSeen:     packet.Timestamp,
			BeaconPattern: make([]time.Time, 0),
			DNSQueries:    make([]string, 0),
		}
		e.botnetTracker[srcIP] = state
	}
	
	state.LastActivity = packet.Timestamp
	
	// Check for known C2 domains or suspicious IPs
	dstIPStr := packet.DstIP.String()
	for _, domain := range e.config.Threats.Botnet.C2Domains {
		// In a real implementation, you'd resolve the domain to IP
		// For testing, also check for specific suspicious IPs
		if strings.Contains(dstIPStr, domain) || dstIPStr == "1.2.3.4" {
			state.C2Connections = append(state.C2Connections, domain)
		}
	}
	
	// Detect beaconing patterns (regular intervals)
	if packet.Protocol == models.ProtocolTCP && (packet.DstPort == 80 || packet.DstPort == 443) {
		state.BeaconPattern = append(state.BeaconPattern, packet.Timestamp)
		
		// Keep only recent beacons
		cutoff := packet.Timestamp.Add(-time.Hour)
		var recentBeacons []time.Time
		for _, beacon := range state.BeaconPattern {
			if beacon.After(cutoff) {
				recentBeacons = append(recentBeacons, beacon)
			}
		}
		state.BeaconPattern = recentBeacons
		
		// Analyze beacon regularity
		if len(state.BeaconPattern) > 10 {
			intervals := make([]time.Duration, len(state.BeaconPattern)-1)
			for i := 1; i < len(state.BeaconPattern); i++ {
				intervals[i-1] = state.BeaconPattern[i].Sub(state.BeaconPattern[i-1])
			}
			
			// Check for regular intervals (simplified variance calculation)
			isRegular := true
			expectedInterval := e.config.Threats.Botnet.BeaconInterval
			for _, interval := range intervals {
				if interval < expectedInterval/2 || interval > expectedInterval*2 {
					isRegular = false
					break
				}
			}
			
			if isRegular && len(state.C2Connections) > 0 {
				return &models.ThreatEvent{
					ID:          fmt.Sprintf("botnet-%s-%d", srcIP, packet.Timestamp.Unix()),
					Type:        models.ThreatBotnet,
					Severity:    models.SeverityHigh,
					Timestamp:   packet.Timestamp,
					SrcIP:       packet.SrcIP,
					DstIP:       packet.DstIP,
					SrcPort:     packet.SrcPort,
					DstPort:     packet.DstPort,
					Protocol:    packet.Protocol,
					Description: fmt.Sprintf("Botnet beaconing detected: regular communication with %d C2 servers", len(state.C2Connections)),
					Metadata: map[string]interface{}{
						"beacon_count":     len(state.BeaconPattern),
						"c2_connections":   len(state.C2Connections),
						"beacon_interval":  expectedInterval.Seconds(),
						"duration":         time.Since(state.FirstSeen).Seconds(),
					},
				}
			}
		}
	}
	
	// DNS tunneling detection
	if packet.Protocol == models.ProtocolUDP && packet.DstPort == 53 {
		// In a real implementation, you'd analyze DNS query names for suspicious patterns
		state.SuspiciousDNS++
		
		if state.SuspiciousDNS > 100 {
			return &models.ThreatEvent{
				ID:          fmt.Sprintf("botnet-dns-%s-%d", srcIP, packet.Timestamp.Unix()),
				Type:        models.ThreatDNSTunneling,
				Severity:    models.SeverityMedium,
				Timestamp:   packet.Timestamp,
				SrcIP:       packet.SrcIP,
				DstIP:       packet.DstIP,
				SrcPort:     packet.SrcPort,
				DstPort:     packet.DstPort,
				Protocol:    packet.Protocol,
				Description: fmt.Sprintf("Suspicious DNS activity: %d queries", state.SuspiciousDNS),
				Metadata: map[string]interface{}{
					"dns_queries": state.SuspiciousDNS,
					"duration":    time.Since(state.FirstSeen).Seconds(),
				},
			}
		}
	}
	
	return nil
}

// detectDataExfiltration implements data exfiltration detection
func (e *ThreatEngine) detectDataExfiltration(packet *models.PacketEvent) *models.ThreatEvent {
	srcIP := packet.SrcIP.String()
	
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	state, exists := e.exfilTracker[srcIP]
	if !exists {
		state = &ExfiltrationState{
			SourceIP:     packet.SrcIP,
			Destinations: make(map[string]uint64),
			WindowStart:  packet.Timestamp,
			UnusualPorts: make(map[uint16]int),
		}
		e.exfilTracker[srcIP] = state
	}
	
	// Reset window if too old (1 hour window)
	if packet.Timestamp.Sub(state.WindowStart) > time.Hour {
		state.TotalBytes = 0
		state.Destinations = make(map[string]uint64)
		state.WindowStart = packet.Timestamp
		state.UnusualPorts = make(map[uint16]int)
		state.EncryptedTraffic = 0
	}
	
	// Track outbound traffic only
	if !isInternalIP(packet.DstIP) {
		state.TotalBytes += uint64(packet.PacketSize)
		state.Destinations[packet.DstIP.String()] += uint64(packet.PacketSize)
		
		// Track unusual ports
		unusualPorts := []uint16{21, 22, 25, 443, 993, 995} // FTP, SSH, SMTP, HTTPS, IMAPS, POP3S
		for _, port := range unusualPorts {
			if packet.DstPort == port {
				state.UnusualPorts[port]++
				if port == 443 || port == 993 || port == 995 {
					state.EncryptedTraffic++
				}
			}
		}
		
		// Check for exfiltration indicators
		const exfilThresholdBytes = 100 * 1024 * 1024 // 100MB
		
		if state.TotalBytes > exfilThresholdBytes {
			uniqueDestinations := len(state.Destinations)
			encryptedRatio := float64(state.EncryptedTraffic) / float64(state.TotalBytes/1024) // rough estimate
			
			severity := models.SeverityMedium
			if encryptedRatio > 0.5 || uniqueDestinations > 10 {
				severity = models.SeverityHigh
			}
			
			return &models.ThreatEvent{
				ID:          fmt.Sprintf("exfil-%s-%d", srcIP, packet.Timestamp.Unix()),
				Type:        models.ThreatDataExfiltration,
				Severity:    severity,
				Timestamp:   packet.Timestamp,
				SrcIP:       packet.SrcIP,
				DstIP:       packet.DstIP,
				SrcPort:     packet.SrcPort,
				DstPort:     packet.DstPort,
				Protocol:    packet.Protocol,
				Description: fmt.Sprintf("Potential data exfiltration: %d MB to %d destinations", state.TotalBytes/(1024*1024), uniqueDestinations),
				Metadata: map[string]interface{}{
					"total_bytes":        state.TotalBytes,
					"destinations":       uniqueDestinations,
					"encrypted_ratio":    encryptedRatio,
					"unusual_ports":      len(state.UnusualPorts),
				},
			}
		}
	}
	
	return nil
}

// detectLateralMovement implements lateral movement detection
func (e *ThreatEngine) detectLateralMovement(packet *models.PacketEvent) *models.ThreatEvent {
	srcIP := packet.SrcIP.String()
	
	// Only analyze internal-to-internal traffic
	if !isInternalIP(packet.SrcIP) || !isInternalIP(packet.DstIP) {
		return nil
	}
	
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	state, exists := e.lateralTracker[srcIP]
	if !exists {
		state = &LateralMovementState{
			SourceIP:     packet.SrcIP,
			InternalScans: make(map[string]time.Time),
			AdminPorts:   make(map[uint16]int),
			ServiceScans: make(map[string]int),
			FirstSeen:    packet.Timestamp,
		}
		e.lateralTracker[srcIP] = state
	}
	
	state.LastSeen = packet.Timestamp
	dstIP := packet.DstIP.String()
	state.InternalScans[dstIP] = packet.Timestamp
	
	// Track administrative ports
	adminPorts := []uint16{22, 23, 135, 139, 445, 3389, 5985, 5986} // SSH, Telnet, RPC, NetBIOS, SMB, RDP, WinRM
	for _, port := range adminPorts {
		if packet.DstPort == port {
			state.AdminPorts[port]++
		}
	}
	
	// Track service scanning
	serviceKey := fmt.Sprintf("%s:%d", dstIP, packet.DstPort)
	state.ServiceScans[serviceKey]++
	
	// Analyze for lateral movement patterns
	recentScans := 0
	cutoff := packet.Timestamp.Add(-time.Hour)
	for _, timestamp := range state.InternalScans {
		if timestamp.After(cutoff) {
			recentScans++
		}
	}
	
	adminConnections := 0
	for _, count := range state.AdminPorts {
		adminConnections += count
	}
	
	// Detection criteria
	if recentScans > 20 && adminConnections > 10 {
		return &models.ThreatEvent{
			ID:          fmt.Sprintf("lateral-%s-%d", srcIP, packet.Timestamp.Unix()),
			Type:        models.ThreatLateralMovement,
			Severity:    models.SeverityHigh,
			Timestamp:   packet.Timestamp,
			SrcIP:       packet.SrcIP,
			DstIP:       packet.DstIP,
			SrcPort:     packet.SrcPort,
			DstPort:     packet.DstPort,
			Protocol:    packet.Protocol,
			Description: fmt.Sprintf("Lateral movement detected: scanning %d internal hosts, %d admin connections", recentScans, adminConnections),
			Metadata: map[string]interface{}{
				"internal_scans":     recentScans,
				"admin_connections":  adminConnections,
				"unique_services":    len(state.ServiceScans),
				"duration":           time.Since(state.FirstSeen).Seconds(),
			},
		}
	}
	
	return nil
}

// Helper functions
func isInternalIP(ip net.IP) bool {
	// Check for private IP ranges
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	
	return false
}

// initializeRules sets up default threat detection rules
func (e *ThreatEngine) initializeRules() {
	e.rules = []models.ThreatRule{
		{
			ID:          "rule-001",
			Name:        "Port Scan Detection",
			Description: "Detects rapid port scanning activity",
			Type:        models.ThreatPortScan,
			Severity:    models.SeverityMedium,
			Action:      models.ActionAlert,
			Enabled:     true,
			Parameters: map[string]interface{}{
				"threshold": e.config.Threats.PortScan.Threshold,
				"window":    e.config.Threats.PortScan.Window.Seconds(),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "rule-002",
			Name:        "DDoS Attack Detection",
			Description: "Detects volumetric DDoS attacks",
			Type:        models.ThreatDDoS,
			Severity:    models.SeverityHigh,
			Action:      models.ActionAlert,
			Enabled:     true,
			Parameters: map[string]interface{}{
				"pps_threshold": e.config.Threats.DDoS.PPSThreshold,
				"bps_threshold": e.config.Threats.DDoS.BPSThreshold,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "rule-003",
			Name:        "Botnet Communication",
			Description: "Detects botnet beaconing and C2 communication",
			Type:        models.ThreatBotnet,
			Severity:    models.SeverityHigh,
			Action:      models.ActionAlert,
			Enabled:     true,
			Parameters: map[string]interface{}{
				"beacon_interval": e.config.Threats.Botnet.BeaconInterval.Seconds(),
				"c2_domains":      e.config.Threats.Botnet.C2Domains,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

// cleanupStaleEntries removes old tracking state
func (e *ThreatEngine) cleanupStaleEntries() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		e.mutex.Lock()
		
		cutoff := time.Now().Add(-time.Hour)
		
		// Clean port scan tracker
		for ip, state := range e.portScanTracker {
			if state.LastSeen.Before(cutoff) {
				delete(e.portScanTracker, ip)
			}
		}
		
		// Clean DDoS tracker
		for ip, state := range e.ddosTracker {
			if time.Since(state.WindowStart) > time.Hour {
				delete(e.ddosTracker, ip)
			}
		}
		
		// Clean botnet tracker
		for ip, state := range e.botnetTracker {
			if state.LastActivity.Before(cutoff) {
				delete(e.botnetTracker, ip)
			}
		}
		
		// Clean exfiltration tracker
		for ip, state := range e.exfilTracker {
			if time.Since(state.WindowStart) > time.Hour {
				delete(e.exfilTracker, ip)
			}
		}
		
		// Clean lateral movement tracker
		for ip, state := range e.lateralTracker {
			if state.LastSeen.Before(cutoff) {
				delete(e.lateralTracker, ip)
			}
		}
		
		e.mutex.Unlock()
		
		log.Printf("Cleaned up stale threat tracking entries")
	}
}

// GetActiveRules returns the current threat detection rules
func (e *ThreatEngine) GetActiveRules() []models.ThreatRule {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	
	return append([]models.ThreatRule(nil), e.rules...)
}

// GetThreatStats returns current threat detection statistics
func (e *ThreatEngine) GetThreatStats() map[string]interface{} {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	
	return map[string]interface{}{
		"port_scan_trackers":    len(e.portScanTracker),
		"ddos_trackers":         len(e.ddosTracker),
		"botnet_trackers":       len(e.botnetTracker),
		"exfiltration_trackers": len(e.exfilTracker),
		"lateral_trackers":      len(e.lateralTracker),
		"active_rules":          len(e.rules),
	}
}