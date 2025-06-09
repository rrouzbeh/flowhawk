package dashboard

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"flowhawk/internal/models"
	"flowhawk/pkg/config"
)

// ProcessorInterface defines the interface needed by dashboard
type ProcessorInterface interface {
	GetStats() models.SystemMetrics
	GetTopFlows(limit int) []models.FlowMetrics
	GetRecentThreats(limit int) []models.ThreatEvent
	GetAlertStats() interface{}
	GetActiveRules() []models.ThreatRule
}

// Dashboard serves the web interface and API
type Dashboard struct {
	config    *config.Config
	processor ProcessorInterface
	server    *http.Server
	upgrader  websocket.Upgrader
}

// New creates a new dashboard server
func New(cfg *config.Config, proc ProcessorInterface) (*Dashboard, error) {
	return &Dashboard{
		config:    cfg,
		processor: proc,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for demo
			},
		},
	}, nil
}

// Start starts the dashboard server
func (d *Dashboard) Start(ctx context.Context) error {
	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/stats", d.handleStats).Methods("GET")
	api.HandleFunc("/flows", d.handleFlows).Methods("GET")
	api.HandleFunc("/threats", d.handleThreats).Methods("GET")
	api.HandleFunc("/dashboard", d.handleDashboard).Methods("GET")
	api.HandleFunc("/alerts", d.handleAlerts).Methods("GET")
	
	// WebSocket endpoint for real-time updates
	router.HandleFunc("/ws", d.handleWebSocket)
	
	// Static files (basic HTML interface)
	router.HandleFunc("/", d.handleIndex).Methods("GET")
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./web/static/"))))
	
	d.server = &http.Server{
		Addr:    d.config.Dashboard.ListenAddr,
		Handler: router,
	}
	
	// Start server in goroutine
	go func() {
		log.Printf("Dashboard server starting on %s", d.config.Dashboard.ListenAddr)
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Dashboard server error: %v", err)
		}
	}()
	
	return nil
}

// Stop stops the dashboard server
func (d *Dashboard) Stop() error {
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return d.server.Shutdown(ctx)
	}
	return nil
}

// handleIndex serves the main dashboard page
func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>FlowHawk - eBPF Network Security Monitor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .section { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .threat { padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; background: #fdf2f2; }
        .threat.high { border-color: #e74c3c; }
        .threat.medium { border-color: #f39c12; }
        .threat.low { border-color: #f1c40f; }
        .flow { padding: 10px; margin: 5px 0; border-left: 4px solid #3498db; background: #f8f9fa; }
        .status { color: #27ae60; font-weight: bold; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>FlowHawk - eBPF Network Security Monitor</h1>
            <p>Real-time network monitoring and threat detection</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="packets-received">0</div>
                <div class="stat-label">Packets Received</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="active-flows">0</div>
                <div class="stat-label">Active Flows</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="threats-detected">0</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="packets-per-sec">0</div>
                <div class="stat-label">Packets/sec</div>
            </div>
        </div>
        
        <div class="section">
            <h2>System Status</h2>
            <p class="status" id="status">🟢 Monitoring Active</p>
            <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        </div>
        
        <div class="section">
            <h2>Recent Threats</h2>
            <div id="threats-list">No threats detected</div>
        </div>
        
        <div class="section">
            <h2>Top Flows</h2>
            <div id="flows-list">No flows detected</div>
        </div>
    </div>

    <script>
        let ws = null;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                document.getElementById('status').innerHTML = '🟢 Monitoring Active (Live)';
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                updateDashboard(data);
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                document.getElementById('status').innerHTML = '🔴 Connection Lost';
                setTimeout(connectWebSocket, 3000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function updateDashboard(data) {
            // Update statistics
            document.getElementById('packets-received').textContent = data.metrics.packets_received.toLocaleString();
            document.getElementById('active-flows').textContent = data.metrics.active_flows.toLocaleString();
            document.getElementById('threats-detected').textContent = data.metrics.threats_detected.toLocaleString();
            document.getElementById('packets-per-sec').textContent = Math.round(data.metrics.packets_per_sec).toLocaleString();
            
            // Update threats
            const threatsList = document.getElementById('threats-list');
            if (data.recent_threats && data.recent_threats.length > 0) {
                threatsList.innerHTML = data.recent_threats.map(threat => 
                    '<div class="threat ' + threat.severity + '">' +
                        '<strong>' + threat.type + '</strong> - ' + threat.description + '<br>' +
                        '<small>From ' + threat.src_ip + ':' + threat.src_port + ' → ' + threat.dst_ip + ':' + threat.dst_port + '</small><br>' +
                        '<span class="timestamp">' + new Date(threat.timestamp).toLocaleString() + '</span>' +
                    '</div>'
                ).join('');
            } else {
                threatsList.innerHTML = 'No threats detected';
            }
            
            // Update flows
            const flowsList = document.getElementById('flows-list');
            if (data.top_flows && data.top_flows.length > 0) {
                flowsList.innerHTML = data.top_flows.map(flow => 
                    '<div class="flow">' +
                        '<strong>' + flow.key.src_ip + ':' + flow.key.src_port + ' → ' + flow.key.dst_ip + ':' + flow.key.dst_port + '</strong> (' + flow.key.protocol + ')<br>' +
                        '<small>Packets: ' + flow.packets.toLocaleString() + ', Bytes: ' + flow.bytes.toLocaleString() + '</small>' +
                    '</div>'
                ).join('');
            } else {
                flowsList.innerHTML = 'No flows detected';
            }
        }
        
        function refreshData() {
            fetch('/api/dashboard')
                .then(response => response.json())
                .then(data => updateDashboard(data))
                .catch(error => console.error('Error fetching data:', error));
        }
        
        // Initialize
        connectWebSocket();
        refreshData();
        
        // Auto-refresh every 5 seconds as fallback
        setInterval(refreshData, 5000);
    </script>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// handleStats returns system statistics
func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := d.processor.GetStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleFlows returns top network flows
func (d *Dashboard) handleFlows(w http.ResponseWriter, r *http.Request) {
	flows := d.processor.GetTopFlows(20)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flows)
}

// handleThreats returns recent threats
func (d *Dashboard) handleThreats(w http.ResponseWriter, r *http.Request) {
	threats := d.processor.GetRecentThreats(20)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

// handleDashboard returns complete dashboard state
func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	dashboardState := models.DashboardState{
		Metrics:       d.processor.GetStats(),
		TopFlows:      d.processor.GetTopFlows(10),
		RecentThreats: d.processor.GetRecentThreats(10),
		Timestamp:     time.Now(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboardState)
}

// handleAlerts returns alert statistics
func (d *Dashboard) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alertStats := d.processor.GetAlertStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alertStats)
}

// handleWebSocket handles real-time WebSocket connections
func (d *Dashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := d.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()
	
	log.Printf("WebSocket client connected: %s", r.RemoteAddr)
	
	// Send initial data
	dashboardState := models.DashboardState{
		Metrics:       d.processor.GetStats(),
		TopFlows:      d.processor.GetTopFlows(10),
		RecentThreats: d.processor.GetRecentThreats(10),
		ActiveRules:   d.processor.GetActiveRules(),
		Timestamp:     time.Now(),
	}
	
	if err := conn.WriteJSON(dashboardState); err != nil {
		log.Printf("WebSocket write error: %v", err)
		return
	}
	
	// Send updates every second
	ticker := time.NewTicker(d.config.Dashboard.UpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			dashboardState := models.DashboardState{
				Metrics:       d.processor.GetStats(),
				TopFlows:      d.processor.GetTopFlows(10),
				RecentThreats: d.processor.GetRecentThreats(10),
				ActiveRules:   d.processor.GetActiveRules(),
				Timestamp:     time.Now(),
			}
			
			if err := conn.WriteJSON(dashboardState); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
		}
	}
}
