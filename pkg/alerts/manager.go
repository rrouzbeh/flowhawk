package alerts

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
)

// AlertManager handles sending alerts through various channels
type AlertManager struct {
	config         *config.Config
	channels       map[string]AlertChannel
	rateLimiter    *RateLimiter
	alertQueue     chan *models.ThreatEvent
	ctx            chan struct{}
	wg             sync.WaitGroup
	closed         bool
	closeMutex     sync.Mutex
	
	// Alert history for deduplication
	recentAlerts   map[string]time.Time
	alertsMutex    sync.RWMutex
	
	// Statistics
	stats          *AlertStats
	statsMutex     sync.RWMutex
}

// AlertChannel interface for different alert delivery methods
type AlertChannel interface {
	Send(event *models.ThreatEvent) error
	GetName() string
	IsEnabled() bool
}

// AlertStats tracks alerting statistics
type AlertStats struct {
	TotalAlerts      uint64    `json:"total_alerts"`
	AlertsSent       uint64    `json:"alerts_sent"`
	AlertsFailed     uint64    `json:"alerts_failed"`
	AlertsSupressed  uint64    `json:"alerts_suppressed"`
	LastAlert        time.Time `json:"last_alert"`
	ChannelStats     map[string]*ChannelStats `json:"channel_stats"`
}

// ChannelStats tracks per-channel statistics
type ChannelStats struct {
	Sent         uint64    `json:"sent"`
	Failed       uint64    `json:"failed"`
	LastSent     time.Time `json:"last_sent"`
	AvgLatency   float64   `json:"avg_latency_ms"`
}

// RateLimiter prevents alert flooding
type RateLimiter struct {
	maxAlerts     int
	timeWindow    time.Duration
	alertCounts   map[string][]time.Time
	mutex         sync.RWMutex
}

// WebhookChannel sends alerts via HTTP webhooks (Slack, Discord, Teams, etc.)
type WebhookChannel struct {
	name        string
	url         string
	enabled     bool
	template    string
	headers     map[string]string
	client      *http.Client
	minSeverity models.Severity
}

// EmailChannel sends alerts via SMTP
type EmailChannel struct {
	name        string
	enabled     bool
	smtpHost    string
	smtpPort    string
	username    string
	password    string
	from        string
	to          []string
	minSeverity models.Severity
}

// SyslogChannel sends alerts to syslog
type SyslogChannel struct {
	name        string
	enabled     bool
	facility    string
	severity    string
	minSeverity models.Severity
}

// NewAlertManager creates a new alert manager
func NewAlertManager(cfg *config.Config) *AlertManager {
	manager := &AlertManager{
		config:       cfg,
		channels:     make(map[string]AlertChannel),
		rateLimiter:  NewRateLimiter(100, time.Minute), // 100 alerts per minute max
		alertQueue:   make(chan *models.ThreatEvent, 1000),
		ctx:          make(chan struct{}),
		recentAlerts: make(map[string]time.Time),
		stats: &AlertStats{
			ChannelStats: make(map[string]*ChannelStats),
		},
	}
	
	// Initialize alert channels based on configuration
	manager.initializeChannels()
	
	// Start alert processing worker
	manager.wg.Add(1)
	go manager.alertProcessor()
	
	// Start cleanup worker
	manager.wg.Add(1)
	go manager.cleanupWorker()
	
	return manager
}

// initializeChannels sets up alert channels based on configuration
func (am *AlertManager) initializeChannels() {
	if !am.config.Alerts.Enable {
		return
	}
	
	minSeverity := am.parseMinSeverity(am.config.Alerts.SeverityThreshold)
	
	// Webhook channel (Slack, Discord, etc.)
	if am.config.Alerts.WebhookURL != "" {
		webhook := &WebhookChannel{
			name:        "webhook",
			url:         am.config.Alerts.WebhookURL,
			enabled:     true,
			template:    am.getWebhookTemplate(),
			headers:     map[string]string{"Content-Type": "application/json"},
			minSeverity: minSeverity,
			client: &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
				},
			},
		}
		am.channels["webhook"] = webhook
		am.stats.ChannelStats["webhook"] = &ChannelStats{}
	}
	
	// Email channel
	if am.config.Alerts.EmailSMTP != "" && am.config.Alerts.EmailTo != "" {
		email := &EmailChannel{
			name:        "email",
			enabled:     true,
			smtpHost:    strings.Split(am.config.Alerts.EmailSMTP, ":")[0],
			smtpPort:    strings.Split(am.config.Alerts.EmailSMTP, ":")[1],
			username:    am.config.Alerts.EmailUser,
			password:    am.config.Alerts.EmailPassword,
			from:        am.config.Alerts.EmailUser,
			to:          strings.Split(am.config.Alerts.EmailTo, ","),
			minSeverity: minSeverity,
		}
		am.channels["email"] = email
		am.stats.ChannelStats["email"] = &ChannelStats{}
	}
	
	log.Printf("Initialized %d alert channels", len(am.channels))
}

// SendAlert queues an alert for delivery
func (am *AlertManager) SendAlert(event *models.ThreatEvent) {
	if !am.config.Alerts.Enable {
		return
	}
	
	am.statsMutex.Lock()
	am.stats.TotalAlerts++
	am.stats.LastAlert = time.Now()
	am.statsMutex.Unlock()
	
	// Check if alert should be suppressed (deduplication)
	if am.shouldSuppressAlert(event) {
		am.statsMutex.Lock()
		am.stats.AlertsSupressed++
		am.statsMutex.Unlock()
		return
	}
	
	// Check rate limiting
	if !am.rateLimiter.Allow(event.SrcIP.String()) {
		am.statsMutex.Lock()
		am.stats.AlertsSupressed++
		am.statsMutex.Unlock()
		log.Printf("Rate limiting alert from %s", event.SrcIP.String())
		return
	}
	
	// Record alert for deduplication (regardless of channels)
	alertKey := am.generateAlertKey(event)
	am.alertsMutex.Lock()
	am.recentAlerts[alertKey] = time.Now()
	am.alertsMutex.Unlock()

	// Queue alert for processing
	select {
	case am.alertQueue <- event:
		// Alert queued successfully
	default:
		// Queue is full, drop alert
		am.statsMutex.Lock()
		am.stats.AlertsFailed++
		am.statsMutex.Unlock()
		log.Printf("Alert queue full, dropping alert: %s", event.Description)
	}
}

// alertProcessor processes queued alerts
func (am *AlertManager) alertProcessor() {
	defer am.wg.Done()
	
	for {
		select {
		case event := <-am.alertQueue:
			am.processAlert(event)
		case <-am.ctx:
			return
		}
	}
}

// processAlert sends an alert through all configured channels
func (am *AlertManager) processAlert(event *models.ThreatEvent) {
	minSeverity := am.parseMinSeverity(am.config.Alerts.SeverityThreshold)
	
	// Skip if event severity is below threshold
	if event.Severity < minSeverity {
		return
	}
	
	// Send through all enabled channels
	for name, channel := range am.channels {
		if !channel.IsEnabled() {
			continue
		}
		
		start := time.Now()
		err := channel.Send(event)
		latency := time.Since(start).Milliseconds()
		
		am.statsMutex.Lock()
		channelStats := am.stats.ChannelStats[name]
		if err != nil {
			channelStats.Failed++
			am.stats.AlertsFailed++
			log.Printf("Failed to send alert via %s: %v", name, err)
		} else {
			channelStats.Sent++
			channelStats.LastSent = time.Now()
			am.stats.AlertsSent++
			
			// Update average latency
			if channelStats.AvgLatency == 0 {
				channelStats.AvgLatency = float64(latency)
			} else {
				channelStats.AvgLatency = (channelStats.AvgLatency + float64(latency)) / 2
			}
		}
		am.statsMutex.Unlock()
	}
	
}

// shouldSuppressAlert checks if an alert should be suppressed due to deduplication
func (am *AlertManager) shouldSuppressAlert(event *models.ThreatEvent) bool {
	alertKey := am.generateAlertKey(event)
	
	am.alertsMutex.RLock()
	lastSeen, exists := am.recentAlerts[alertKey]
	am.alertsMutex.RUnlock()
	
	if !exists {
		return false
	}
	
	// Suppress if same alert was sent within the last 5 minutes
	return time.Since(lastSeen) < 5*time.Minute
}

// generateAlertKey creates a unique key for alert deduplication
func (am *AlertManager) generateAlertKey(event *models.ThreatEvent) string {
	return fmt.Sprintf("%s:%s:%s:%d:%d",
		event.Type.String(),
		event.SrcIP.String(),
		event.DstIP.String(),
		event.SrcPort,
		event.DstPort)
}

// cleanupWorker periodically cleans up old alert records
func (am *AlertManager) cleanupWorker() {
	defer am.wg.Done()
	
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			am.cleanupRecentAlerts()
		case <-am.ctx:
			return
		}
	}
}

// cleanupRecentAlerts removes old alert records
func (am *AlertManager) cleanupRecentAlerts() {
	cutoff := time.Now().Add(-time.Hour)
	
	am.alertsMutex.Lock()
	for key, timestamp := range am.recentAlerts {
		if timestamp.Before(cutoff) {
			delete(am.recentAlerts, key)
		}
	}
	am.alertsMutex.Unlock()
}

// parseMinSeverity converts string severity to models.Severity
func (am *AlertManager) parseMinSeverity(severity string) models.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return models.SeverityLow
	case "medium":
		return models.SeverityMedium
	case "high":
		return models.SeverityHigh
	case "critical":
		return models.SeverityCritical
	default:
		return models.SeverityMedium
	}
}

// WebhookChannel implementation

func (wc *WebhookChannel) Send(event *models.ThreatEvent) error {
	if event.Severity < wc.minSeverity {
		return nil // Skip alerts below minimum severity
	}
	
	payload := wc.formatWebhookPayload(event)
	
	req, err := http.NewRequest("POST", wc.url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	for key, value := range wc.headers {
		req.Header.Set(key, value)
	}
	
	resp, err := wc.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	
	return nil
}

func (wc *WebhookChannel) formatWebhookPayload(event *models.ThreatEvent) []byte {
	// Create Slack-compatible payload
	payload := map[string]interface{}{
		"text": fmt.Sprintf("🚨 *%s Threat Detected*", event.Severity.String()),
		"attachments": []map[string]interface{}{
			{
				"color": wc.getSeverityColor(event.Severity),
				"fields": []map[string]interface{}{
					{
						"title": "Threat Type",
						"value": event.Type.String(),
						"short": true,
					},
					{
						"title": "Source",
						"value": fmt.Sprintf("%s:%d", event.SrcIP.String(), event.SrcPort),
						"short": true,
					},
					{
						"title": "Destination", 
						"value": fmt.Sprintf("%s:%d", event.DstIP.String(), event.DstPort),
						"short": true,
					},
					{
						"title": "Protocol",
						"value": event.Protocol.String(),
						"short": true,
					},
					{
						"title": "Description",
						"value": event.Description,
						"short": false,
					},
					{
						"title": "Time",
						"value": event.Timestamp.Format(time.RFC3339),
						"short": true,
					},
				},
				"footer": "eBPF Network Security Monitor",
				"ts": event.Timestamp.Unix(),
			},
		},
	}
	
	if event.ProcessName != "" {
		fields := payload["attachments"].([]map[string]interface{})[0]["fields"].([]map[string]interface{})
		fields = append(fields, map[string]interface{}{
			"title": "Process",
			"value": fmt.Sprintf("%s (PID: %d)", event.ProcessName, event.ProcessID),
			"short": true,
		})
		payload["attachments"].([]map[string]interface{})[0]["fields"] = fields
	}
	
	data, _ := json.Marshal(payload)
	return data
}

func (wc *WebhookChannel) getSeverityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityLow:
		return "#36a64f" // Green
	case models.SeverityMedium:
		return "#ffaa00" // Orange
	case models.SeverityHigh:
		return "#ff6600" // Red-Orange
	case models.SeverityCritical:
		return "#ff0000" // Red
	default:
		return "#808080" // Gray
	}
}

func (wc *WebhookChannel) GetName() string {
	return wc.name
}

func (wc *WebhookChannel) IsEnabled() bool {
	return wc.enabled
}

// EmailChannel implementation

func (ec *EmailChannel) Send(event *models.ThreatEvent) error {
	if event.Severity < ec.minSeverity {
		return nil
	}
	
	subject := fmt.Sprintf("[SECURITY ALERT] %s - %s", event.Severity.String(), event.Type.String())
	body := ec.formatEmailBody(event)
	
	// Setup authentication
	auth := smtp.PlainAuth("", ec.username, ec.password, ec.smtpHost)
	
	// Compose message
	msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		strings.Join(ec.to, ","), subject, body)
	
	// Send email
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", ec.smtpHost, ec.smtpPort),
		auth,
		ec.from,
		ec.to,
		[]byte(msg),
	)
	
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	
	return nil
}

func (ec *EmailChannel) formatEmailBody(event *models.ThreatEvent) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .alert { border-left: 4px solid %s; padding: 15px; background: #f9f9f9; }
        .header { color: %s; font-size: 24px; font-weight: bold; margin-bottom: 15px; }
        .field { margin: 10px 0; }
        .label { font-weight: bold; color: #333; }
        .value { color: #666; }
        .metadata { background: #f0f0f0; padding: 10px; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="alert">
        <div class="header">🚨 Security Threat Detected</div>
        
        <div class="field">
            <span class="label">Threat Type:</span>
            <span class="value">%s</span>
        </div>
        
        <div class="field">
            <span class="label">Severity:</span>
            <span class="value">%s</span>
        </div>
        
        <div class="field">
            <span class="label">Source:</span>
            <span class="value">%s:%d</span>
        </div>
        
        <div class="field">
            <span class="label">Destination:</span>
            <span class="value">%s:%d</span>
        </div>
        
        <div class="field">
            <span class="label">Protocol:</span>
            <span class="value">%s</span>
        </div>
        
        <div class="field">
            <span class="label">Time:</span>
            <span class="value">%s</span>
        </div>
        
        <div class="field">
            <span class="label">Description:</span>
            <span class="value">%s</span>
        </div>
        
        %s
        
        <div class="metadata">
            <strong>Alert ID:</strong> %s<br>
            <strong>Generated by:</strong>FlowHawk - eBPF Network Security Monitor
        </div>
    </div>
</body>
</html>`,
		ec.getSeverityColor(event.Severity),
		ec.getSeverityColor(event.Severity),
		event.Type.String(),
		event.Severity.String(),
		event.SrcIP.String(), event.SrcPort,
		event.DstIP.String(), event.DstPort,
		event.Protocol.String(),
		event.Timestamp.Format("2006-01-02 15:04:05 MST"),
		event.Description,
		ec.formatProcessInfo(event),
		event.ID,
	)
}

func (ec *EmailChannel) formatProcessInfo(event *models.ThreatEvent) string {
	if event.ProcessName == "" {
		return ""
	}
	
	return fmt.Sprintf(`
        <div class="field">
            <span class="label">Process:</span>
            <span class="value">%s (PID: %d)</span>
        </div>`, event.ProcessName, event.ProcessID)
}

func (ec *EmailChannel) getSeverityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityLow:
		return "#28a745"
	case models.SeverityMedium:
		return "#ffc107"
	case models.SeverityHigh:
		return "#fd7e14"
	case models.SeverityCritical:
		return "#dc3545"
	default:
		return "#6c757d"
	}
}

func (ec *EmailChannel) GetName() string {
	return ec.name
}

func (ec *EmailChannel) IsEnabled() bool {
	return ec.enabled
}

// getWebhookTemplate returns the default webhook template
func (am *AlertManager) getWebhookTemplate() string {
	return "slack" // Default to Slack format
}

// RateLimiter implementation

func NewRateLimiter(maxAlerts int, timeWindow time.Duration) *RateLimiter {
	return &RateLimiter{
		maxAlerts:   maxAlerts,
		timeWindow:  timeWindow,
		alertCounts: make(map[string][]time.Time),
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-rl.timeWindow)
	
	// Get existing timestamps for this key
	timestamps := rl.alertCounts[key]
	
	// Remove old timestamps
	var validTimestamps []time.Time
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	
	// Check if we can allow another alert
	if len(validTimestamps) >= rl.maxAlerts {
		return false
	}
	
	// Add current timestamp
	validTimestamps = append(validTimestamps, now)
	rl.alertCounts[key] = validTimestamps
	
	return true
}

// GetStats returns current alert statistics
func (am *AlertManager) GetStats() AlertStats {
	am.statsMutex.RLock()
	defer am.statsMutex.RUnlock()
	
	// Deep copy to avoid race conditions
	stats := AlertStats{
		TotalAlerts:     am.stats.TotalAlerts,
		AlertsSent:      am.stats.AlertsSent,
		AlertsFailed:    am.stats.AlertsFailed,
		AlertsSupressed: am.stats.AlertsSupressed,
		LastAlert:       am.stats.LastAlert,
		ChannelStats:    make(map[string]*ChannelStats),
	}
	
	for name, channelStats := range am.stats.ChannelStats {
		stats.ChannelStats[name] = &ChannelStats{
			Sent:       channelStats.Sent,
			Failed:     channelStats.Failed,
			LastSent:   channelStats.LastSent,
			AvgLatency: channelStats.AvgLatency,
		}
	}
	
	return stats
}

// Close shuts down the alert manager
func (am *AlertManager) Close() error {
	am.closeMutex.Lock()
	defer am.closeMutex.Unlock()
	
	if am.closed {
		return nil // Already closed
	}
	
	close(am.ctx)
	am.wg.Wait()
	close(am.alertQueue)
	am.closed = true
	return nil
}
