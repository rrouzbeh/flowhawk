package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// Client represents a FlowHawk API client
type Client struct {
	baseURL    string
	httpClient *http.Client
	username   string
	password   string
}

// SystemMetrics represents system performance metrics
type SystemMetrics struct {
	Timestamp       time.Time `json:"timestamp"`
	PacketsReceived uint64    `json:"packets_received"`
	PacketsDropped  uint64    `json:"packets_dropped"`
	BytesReceived   uint64    `json:"bytes_received"`
	ActiveFlows     uint64    `json:"active_flows"`
	ThreatsDetected uint64    `json:"threats_detected"`
	CPUUsage        float64   `json:"cpu_usage"`
	MemoryUsage     uint64    `json:"memory_usage"`
	PacketsPerSec   float64   `json:"packets_per_sec"`
	BytesPerSec     float64   `json:"bytes_per_sec"`
}

// ThreatEvent represents a detected threat
type ThreatEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	SrcIP       string                 `json:"src_ip"`
	DstIP       string                 `json:"dst_ip"`
	SrcPort     uint16                 `json:"src_port"`
	DstPort     uint16                 `json:"dst_port"`
	Protocol    uint8                  `json:"protocol"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	ProcessID   uint32                 `json:"process_id,omitempty"`
	ProcessName string                 `json:"process_name,omitempty"`
}

// FlowKey represents a network flow identifier
type FlowKey struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}

// Flow represents a network flow
type Flow struct {
	Key       FlowKey   `json:"key"`
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Flags     uint32    `json:"flags"`
}

// ThreatsResponse represents the response from /api/threats
type ThreatsResponse struct {
	Threats    []ThreatEvent `json:"threats"`
	TotalCount int           `json:"total_count"`
	Timestamp  time.Time     `json:"timestamp"`
}

// FlowsResponse represents the response from /api/flows
type FlowsResponse struct {
	Flows      []Flow    `json:"flows"`
	TotalCount int       `json:"total_count"`
	Timestamp  time.Time `json:"timestamp"`
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// NewClient creates a new FlowHawk client
func NewClient(baseURL, username, password string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		username: username,
		password: password,
	}
}

// makeRequest performs an HTTP request with authentication
func (c *Client) makeRequest(method, endpoint string, body interface{}) (*http.Response, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	var req *http.Request
	var err error
	
	if reqBody != nil {
		req, err = http.NewRequest(method, c.baseURL+"/api"+endpoint, reqBody)
	} else {
		req, err = http.NewRequest(method, c.baseURL+"/api"+endpoint, nil)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	
	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	return c.httpClient.Do(req)
}

// GetStats retrieves system statistics
func (c *Client) GetStats() (*SystemMetrics, error) {
	resp, err := c.makeRequest("GET", "/stats", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var stats SystemMetrics
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &stats, nil
}

// GetThreats retrieves detected threats with optional filtering
func (c *Client) GetThreats(limit int, severity, threatType, srcIP string, since *time.Time) (*ThreatsResponse, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	
	if severity != "" {
		params.Set("severity", severity)
	}
	if threatType != "" {
		params.Set("type", threatType)
	}
	if srcIP != "" {
		params.Set("src_ip", srcIP)
	}
	if since != nil {
		params.Set("since", since.Format(time.RFC3339))
	}

	endpoint := "/threats"
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var threatsResp ThreatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&threatsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &threatsResp, nil
}

// GetFlows retrieves active network flows
func (c *Client) GetFlows(limit int, protocol, srcIP, dstIP, sort, order string) (*FlowsResponse, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("sort", sort)
	params.Set("order", order)
	
	if protocol != "" {
		params.Set("protocol", protocol)
	}
	if srcIP != "" {
		params.Set("src_ip", srcIP)
	}
	if dstIP != "" {
		params.Set("dst_ip", dstIP)
	}

	endpoint := "/flows?" + params.Encode()

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var flowsResp FlowsResponse
	if err := json.NewDecoder(resp.Body).Decode(&flowsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &flowsResp, nil
}

// AcknowledgeThreat acknowledges a threat
func (c *Client) AcknowledgeThreat(threatID, comment, acknowledgedBy string) error {
	body := map[string]string{
		"comment":         comment,
		"acknowledged_by": acknowledgedBy,
	}

	resp, err := c.makeRequest("POST", "/threats/"+threatID+"/acknowledge", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// CreateCustomRule creates a new custom threat detection rule
func (c *Client) CreateCustomRule(rule map[string]interface{}) error {
	resp, err := c.makeRequest("POST", "/rules", rule)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// Monitor represents a threat monitoring application
type Monitor struct {
	client      *Client
	threatCount int
	lastStats   *SystemMetrics
}

// NewMonitor creates a new monitor instance
func NewMonitor(client *Client) *Monitor {
	return &Monitor{
		client: client,
	}
}

// PrintStats displays current system statistics
func (m *Monitor) PrintStats() {
	stats, err := m.client.GetStats()
	if err != nil {
		log.Printf("❌ Error getting stats: %v", err)
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SYSTEM STATISTICS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Timestamp: %s\n", stats.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Packets Received: %s\n", formatNumber(stats.PacketsReceived))
	fmt.Printf("Bytes Received: %s\n", formatBytes(stats.BytesReceived))
	fmt.Printf("Active Flows: %s\n", formatNumber(stats.ActiveFlows))
	fmt.Printf("Threats Detected: %s\n", formatNumber(stats.ThreatsDetected))
	fmt.Printf("Packets/sec: %.2f\n", stats.PacketsPerSec)
	fmt.Printf("Bytes/sec: %s/s\n", formatBytes(uint64(stats.BytesPerSec)))

	// Calculate rates if we have previous stats
	if m.lastStats != nil {
		timeDiff := stats.Timestamp.Sub(m.lastStats.Timestamp).Seconds()
		if timeDiff > 0 {
			packetRate := float64(stats.PacketsReceived-m.lastStats.PacketsReceived) / timeDiff
			byteRate := float64(stats.BytesReceived-m.lastStats.BytesReceived) / timeDiff
			fmt.Printf("Actual Packet Rate: %.2f PPS\n", packetRate)
			fmt.Printf("Actual Byte Rate: %s/s\n", formatBytes(uint64(byteRate)))
		}
	}

	m.lastStats = stats
}

// PrintRecentThreats displays recent threat detections
func (m *Monitor) PrintRecentThreats(limit int) {
	since := time.Now().Add(-time.Hour) // Last hour
	threatsResp, err := m.client.GetThreats(limit, "", "", "", &since)
	if err != nil {
		log.Printf("❌ Error getting threats: %v", err)
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("RECENT THREATS")
	fmt.Println(strings.Repeat("=", 60))

	if len(threatsResp.Threats) == 0 {
		fmt.Println("No threats detected in the last hour")
		return
	}

	for _, threat := range threatsResp.Threats {
		severitySymbol := getSeveritySymbol(threat.Severity)
		
		fmt.Printf("\n%s %s - %s\n", severitySymbol, 
			strings.ToUpper(threat.Type), strings.ToUpper(threat.Severity))
		fmt.Printf("   ID: %s\n", threat.ID)
		fmt.Printf("   Time: %s\n", threat.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Source: %s:%d\n", threat.SrcIP, threat.SrcPort)
		fmt.Printf("   Destination: %s:%d\n", threat.DstIP, threat.DstPort)
		fmt.Printf("   Description: %s\n", threat.Description)

		if threat.ProcessName != "" {
			fmt.Printf("   Process: %s (PID: %d)\n", threat.ProcessName, threat.ProcessID)
		}

		// Print metadata
		if len(threat.Metadata) > 0 {
			fmt.Println("   Metadata:")
			for key, value := range threat.Metadata {
				fmt.Printf("     %s: %v\n", key, value)
			}
		}
	}
}

// PrintTopFlows displays top network flows by bytes
func (m *Monitor) PrintTopFlows(limit int) {
	flowsResp, err := m.client.GetFlows(limit, "", "", "", "bytes", "desc")
	if err != nil {
		log.Printf("❌ Error getting flows: %v", err)
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("TOP NETWORK FLOWS")
	fmt.Println(strings.Repeat("=", 60))

	if len(flowsResp.Flows) == 0 {
		fmt.Println("No active flows")
		return
	}

	fmt.Printf("%-20s %-20s %-8s %-10s %-15s\n", 
		"Source", "Destination", "Protocol", "Packets", "Bytes")
	fmt.Println(strings.Repeat("-", 80))

	for _, flow := range flowsResp.Flows {
		src := fmt.Sprintf("%s:%d", flow.Key.SrcIP, flow.Key.SrcPort)
		dst := fmt.Sprintf("%s:%d", flow.Key.DstIP, flow.Key.DstPort)
		protocol := getProtocolName(flow.Key.Protocol)

		fmt.Printf("%-20s %-20s %-8s %-10s %-15s\n",
			truncateString(src, 20),
			truncateString(dst, 20),
			protocol,
			formatNumber(flow.Packets),
			formatBytes(flow.Bytes))
	}
}

// MonitorRealtime connects to WebSocket for real-time monitoring
func (m *Monitor) MonitorRealtime() error {
	wsURL := strings.Replace(m.client.baseURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/ws"

	log.Printf("🔴 Connecting to WebSocket: %s", wsURL)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}
	defer conn.Close()

	log.Println("✅ Connected to real-time stream")

	for {
		var msg WebSocketMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("❌ WebSocket read error: %v", err)
			break
		}

		m.handleRealtimeEvent(msg)
	}

	return nil
}

// handleRealtimeEvent processes real-time WebSocket events
func (m *Monitor) handleRealtimeEvent(msg WebSocketMessage) {
	switch msg.Type {
	case "threat_detected":
		m.threatCount++
		
		// Convert the data to ThreatEvent
		dataBytes, _ := json.Marshal(msg.Data)
		var threat ThreatEvent
		json.Unmarshal(dataBytes, &threat)

		severitySymbol := getSeveritySymbol(threat.Severity)
		
		fmt.Printf("\n%s REAL-TIME THREAT #%d\n", severitySymbol, m.threatCount)
		fmt.Printf("Type: %s\n", threat.Type)
		fmt.Printf("Severity: %s\n", strings.ToUpper(threat.Severity))
		fmt.Printf("Source: %s\n", threat.SrcIP)
		fmt.Printf("Description: %s\n", threat.Description)
		fmt.Printf("Time: %s\n", threat.Timestamp.Format("2006-01-02 15:04:05"))

	case "dashboard_update":
		// Handle dashboard updates if needed
		
	case "flow_update":
		// Handle flow updates if needed
		fmt.Printf("📊 Flow update received\n")
	}
}

// Utility functions
func getSeveritySymbol(severity string) string {
	switch severity {
	case "low":
		return "🟡"
	case "medium":
		return "🟠"
	case "high":
		return "🔴"
	case "critical":
		return "🚨"
	default:
		return "⚪"
	}
}

func getProtocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", protocol)
	}
}

func formatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	} else if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	} else {
		return fmt.Sprintf("%.1fB", float64(n)/1000000000)
	}
}

func formatBytes(bytes uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	size := float64(bytes)
	unit := 0

	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}

	return fmt.Sprintf("%.1f%s", size, units[unit])
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ExampleCreateMiningRule demonstrates creating a custom rule for crypto mining detection
func ExampleCreateMiningRule(client *Client) {
	rule := map[string]interface{}{
		"name":        "Cryptocurrency Mining Detection",
		"description": "Detects connections to known mining pools",
		"enabled":     true,
		"conditions": []map[string]interface{}{
			{
				"field":    "dst_port",
				"operator": "in",
				"value":    []int{4444, 8333, 9999, 14444},
				"logic":    "or",
			},
			{
				"field":    "dst_ip",
				"operator": "regex",
				"value":    ".*\\.mining\\..*",
			},
		},
		"actions": []map[string]interface{}{
			{
				"type":     "alert",
				"severity": "high",
				"message":  "Potential cryptocurrency mining activity detected",
			},
		},
	}

	err := client.CreateCustomRule(rule)
	if err != nil {
		log.Printf("❌ Failed to create mining detection rule: %v", err)
	} else {
		log.Println("✅ Created cryptocurrency mining detection rule")
	}
}

func main() {
	var (
		url        = flag.String("url", "http://localhost:8080", "Monitor URL")
		username   = flag.String("username", "", "Username for authentication")
		password   = flag.String("password", "", "Password for authentication")
		statsOnly  = flag.Bool("stats-only", false, "Only print stats and exit")
		threatsOnly = flag.Bool("threats-only", false, "Only print threats and exit")
		realtime   = flag.Bool("realtime", false, "Monitor real-time events")
		interval   = flag.Int("interval", 10, "Update interval in seconds")
		createRule = flag.Bool("create-mining-rule", false, "Create example mining detection rule")
	)
	flag.Parse()

	// Create client
	client := NewClient(*url, *username, *password)

	// Test connection
	stats, err := client.GetStats()
	if err != nil {
		log.Fatalf("❌ Failed to connect to monitor: %v", err)
	}

	fmt.Printf("✅ Connected to FlowHawk\n")
	fmt.Printf("Last update: %s\n", stats.Timestamp.Format("2006-01-02 15:04:05"))

	monitor := NewMonitor(client)

	// Handle different modes
	if *createRule {
		ExampleCreateMiningRule(client)
		return
	}

	if *statsOnly {
		monitor.PrintStats()
		return
	}

	if *threatsOnly {
		monitor.PrintRecentThreats(20)
		return
	}

	if *realtime {
		fmt.Println("🔴 Starting real-time monitoring (Ctrl+C to stop)...")
		
		// Handle interrupt signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		
		go func() {
			<-sigChan
			fmt.Println("\n👋 Monitoring stopped")
			os.Exit(0)
		}()
		
		if err := monitor.MonitorRealtime(); err != nil {
			log.Fatalf("❌ Real-time monitoring failed: %v", err)
		}
		return
	}

	// Default: periodic updates
	fmt.Printf("📊 Starting periodic monitoring (interval: %ds, Ctrl+C to stop)...\n", *interval)

	// Handle interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	// Initial display
	monitor.PrintStats()
	monitor.PrintTopFlows(10)
	monitor.PrintRecentThreats(10)

	for {
		select {
		case <-ticker.C:
			monitor.PrintStats()
			monitor.PrintTopFlows(10)
			monitor.PrintRecentThreats(10)
			fmt.Printf("\n⏱️  Next update in %d seconds...\n", *interval)

		case <-sigChan:
			fmt.Println("\n👋 Monitoring stopped")
			return
		}
	}
}

