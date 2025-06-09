# API Documentation

FlowHawk provides a comprehensive REST API and WebSocket interface for programmatic access to monitoring data, threat information, and system controls.

## Table of Contents

- [Base URL and Authentication](#base-url-and-authentication)
- [REST API Endpoints](#rest-api-endpoints)
- [WebSocket API](#websocket-api)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Examples](#examples)

## Base URL and Authentication

### Base URL
```
http://localhost:8080/api
```

### Authentication
If authentication is enabled in the configuration:

```bash
# Basic Authentication
curl -u username:password http://localhost:8080/api/stats

# Bearer Token (if JWT is configured)
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/stats
```

## REST API Endpoints

### System Information

#### GET /api/stats
Returns current system statistics and performance metrics.

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:15Z",
  "packets_received": 1234567,
  "packets_dropped": 123,
  "bytes_received": 987654321,
  "active_flows": 5432,
  "threats_detected": 42,
  "cpu_usage": 15.5,
  "memory_usage": 268435456,
  "packets_per_sec": 1500.2,
  "bytes_per_sec": 12345678.9
}
```

#### GET /api/health
Health check endpoint for monitoring systems.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "2h45m30s",
  "ebpf_programs_loaded": true,
  "interfaces_monitored": ["eth0"],
  "timestamp": "2024-01-15T10:30:15Z"
}
```

### Network Flows

#### GET /api/flows
Returns active network flows with optional filtering.

**Query Parameters:**
- `limit` (int): Maximum number of flows to return (default: 100, max: 1000)
- `protocol` (string): Filter by protocol (tcp, udp, icmp)
- `src_ip` (string): Filter by source IP
- `dst_ip` (string): Filter by destination IP
- `min_bytes` (int): Minimum bytes threshold
- `sort` (string): Sort field (bytes, packets, duration)
- `order` (string): Sort order (asc, desc)

**Example Request:**
```bash
curl "http://localhost:8080/api/flows?limit=50&protocol=tcp&sort=bytes&order=desc"
```

**Response:**
```json
{
  "flows": [
    {
      "key": {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.1.50",
        "src_port": 45123,
        "dst_port": 80,
        "protocol": 6
      },
      "packets": 1234,
      "bytes": 567890,
      "first_seen": "2024-01-15T10:25:30Z",
      "last_seen": "2024-01-15T10:30:15Z",
      "flags": 24
    }
  ],
  "total_count": 5432,
  "timestamp": "2024-01-15T10:30:15Z"
}
```

#### GET /api/flows/{flow_id}
Returns detailed information about a specific flow.

**Response:**
```json
{
  "flow": {
    "key": {
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.1.50",
      "src_port": 45123,
      "dst_port": 80,
      "protocol": 6
    },
    "packets": 1234,
    "bytes": 567890,
    "first_seen": "2024-01-15T10:25:30Z",
    "last_seen": "2024-01-15T10:30:15Z",
    "flags": 24,
    "tcp_state": "ESTABLISHED",
    "anomaly_score": 0.15,
    "threat_indicators": []
  }
}
```

### Threat Detection

#### GET /api/threats
Returns detected threats with optional filtering.

**Query Parameters:**
- `limit` (int): Maximum number of threats to return (default: 100)
- `severity` (string): Filter by severity (low, medium, high, critical)
- `type` (string): Filter by threat type
- `src_ip` (string): Filter by source IP
- `since` (string): ISO 8601 timestamp for time filtering
- `status` (string): Filter by status (active, resolved, suppressed)

**Example Request:**
```bash
curl "http://localhost:8080/api/threats?severity=high&limit=25&since=2024-01-15T09:00:00Z"
```

**Response:**
```json
{
  "threats": [
    {
      "id": "threat-001-1642248615",
      "type": "Port Scan",
      "severity": "high",
      "timestamp": "2024-01-15T10:30:15Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.1.50",
      "src_port": 45123,
      "dst_port": 22,
      "protocol": 6,
      "description": "Rapid port scan: 127 ports in 30s",
      "metadata": {
        "total_attempts": 127,
        "failed_attempts": 120,
        "unique_ports": 50,
        "unique_targets": 1,
        "scan_duration": 30.5
      },
      "process_id": 1337,
      "process_name": "nmap",
      "status": "active"
    }
  ],
  "total_count": 15,
  "timestamp": "2024-01-15T10:30:15Z"
}
```

#### GET /api/threats/{threat_id}
Returns detailed information about a specific threat.

#### POST /api/threats/{threat_id}/acknowledge
Acknowledges a threat (marks as reviewed).

**Request Body:**
```json
{
  "acknowledged_by": "security_analyst",
  "comment": "Investigated - confirmed legitimate security scan"
}
```

#### POST /api/threats/{threat_id}/suppress
Suppresses future alerts for similar threats.

**Request Body:**
```json
{
  "duration": "1h",
  "reason": "Planned maintenance scan"
}
```

### Alert Management

#### GET /api/alerts
Returns alert statistics and recent alerts.

**Response:**
```json
{
  "statistics": {
    "total_alerts": 1234,
    "alerts_sent": 1200,
    "alerts_failed": 34,
    "alerts_suppressed": 45,
    "last_alert": "2024-01-15T10:29:45Z",
    "channel_stats": {
      "webhook": {
        "sent": 800,
        "failed": 15,
        "last_sent": "2024-01-15T10:29:45Z",
        "avg_latency_ms": 250.5
      },
      "email": {
        "sent": 400,
        "failed": 19,
        "last_sent": "2024-01-15T10:25:30Z",
        "avg_latency_ms": 1500.2
      }
    }
  },
  "recent_alerts": [
    {
      "id": "alert-001",
      "threat_id": "threat-001-1642248615",
      "timestamp": "2024-01-15T10:29:45Z",
      "channels": ["webhook", "email"],
      "status": "sent",
      "retry_count": 0
    }
  ]
}
```

#### POST /api/alerts/test
Tests alert configuration by sending a test alert.

**Request Body:**
```json
{
  "channels": ["webhook", "email"],
  "message": "Test alert from FlowHawk"
}
```

### Dashboard Data

#### GET /api/dashboard
Returns complete dashboard state for real-time updates.

**Response:**
```json
{
  "metrics": {
    "timestamp": "2024-01-15T10:30:15Z",
    "packets_received": 1234567,
    "bytes_received": 987654321,
    "active_flows": 5432,
    "threats_detected": 42,
    "packets_per_sec": 1500.2,
    "bytes_per_sec": 12345678.9
  },
  "top_flows": [
    {
      "key": {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.1.50",
        "src_port": 45123,
        "dst_port": 80,
        "protocol": 6
      },
      "packets": 1234,
      "bytes": 567890
    }
  ],
  "recent_threats": [
    {
      "id": "threat-001",
      "type": "Port Scan",
      "severity": "high",
      "timestamp": "2024-01-15T10:30:15Z",
      "src_ip": "192.168.1.100",
      "description": "Rapid port scan detected"
    }
  ],
  "active_rules": [
    {
      "id": "rule-001",
      "name": "Port Scan Detection",
      "enabled": true,
      "last_triggered": "2024-01-15T10:30:15Z"
    }
  ],
  "timestamp": "2024-01-15T10:30:15Z"
}
```

### Configuration Management

#### GET /api/config
Returns current configuration (sensitive fields redacted).

#### PUT /api/config
Updates configuration (requires admin privileges).

**Request Body:**
```json
{
  "threats": {
    "port_scan": {
      "threshold": 50,
      "window": "30s"
    }
  },
  "alerts": {
    "severity_threshold": "medium"
  }
}
```

#### POST /api/config/reload
Reloads configuration from file.

### Custom Rules

#### GET /api/rules
Returns custom threat detection rules.

**Response:**
```json
{
  "rules": [
    {
      "id": "custom-001",
      "name": "Crypto Mining Detection",
      "description": "Detects connections to mining pools",
      "enabled": true,
      "conditions": [
        {
          "field": "dst_port",
          "operator": "in",
          "value": [4444, 8333, 9999],
          "logic": "and"
        }
      ],
      "actions": [
        {
          "type": "alert",
          "severity": "high",
          "message": "Cryptocurrency mining detected"
        }
      ],
      "created_at": "2024-01-15T09:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z"
    }
  ]
}
```

#### POST /api/rules
Creates a new custom rule.

#### PUT /api/rules/{rule_id}
Updates an existing rule.

#### DELETE /api/rules/{rule_id}
Deletes a rule.

## WebSocket API

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
```

### Real-time Events

The WebSocket connection provides real-time updates for:
- Dashboard state updates (every 1 second)
- New threat detections
- Flow updates
- System metrics

**Dashboard Updates:**
```json
{
  "type": "dashboard_update",
  "data": {
    "metrics": { /* system metrics */ },
    "top_flows": [ /* current top flows */ ],
    "recent_threats": [ /* latest threats */ ],
    "timestamp": "2024-01-15T10:30:15Z"
  }
}
```

**Threat Notifications:**
```json
{
  "type": "threat_detected",
  "data": {
    "id": "threat-001",
    "type": "Port Scan",
    "severity": "high",
    "src_ip": "192.168.1.100",
    "description": "Rapid port scan detected",
    "timestamp": "2024-01-15T10:30:15Z"
  }
}
```

**Flow Events:**
```json
{
  "type": "flow_update",
  "data": {
    "action": "created", // created, updated, expired
    "flow": { /* flow data */ }
  }
}
```

## Data Models

### System Metrics
```typescript
interface SystemMetrics {
  timestamp: string;
  packets_received: number;
  packets_dropped: number;
  bytes_received: number;
  active_flows: number;
  threats_detected: number;
  cpu_usage: number;
  memory_usage: number;
  packets_per_sec: number;
  bytes_per_sec: number;
}
```

### Flow
```typescript
interface Flow {
  key: {
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: number;
  };
  packets: number;
  bytes: number;
  first_seen: string;
  last_seen: string;
  flags: number;
}
```

### Threat Event
```typescript
interface ThreatEvent {
  id: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  description: string;
  metadata: Record<string, any>;
  process_id?: number;
  process_name?: string;
}
```

### Custom Rule
```typescript
interface CustomRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: RuleCondition[];
  actions: RuleAction[];
  created_at: string;
  updated_at: string;
}

interface RuleCondition {
  field: string;
  operator: string;
  value: any;
  logic?: "and" | "or";
}

interface RuleAction {
  type: string;
  severity: string;
  message: string;
  parameters?: Record<string, any>;
}
```

## Error Handling

### HTTP Status Codes
- `200 OK`: Successful request
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient privileges
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Error Response Format
```json
{
  "error": {
    "code": "INVALID_PARAMETER",
    "message": "Invalid value for parameter 'limit': must be between 1 and 1000",
    "details": {
      "parameter": "limit",
      "provided_value": "5000",
      "valid_range": "1-1000"
    },
    "timestamp": "2024-01-15T10:30:15Z"
  }
}
```

### Common Error Codes
- `INVALID_PARAMETER`: Invalid request parameter
- `RESOURCE_NOT_FOUND`: Requested resource doesn't exist
- `AUTHENTICATION_REQUIRED`: Valid authentication required
- `INSUFFICIENT_PRIVILEGES`: User lacks required permissions
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INTERNAL_ERROR`: Server-side error

## Rate Limiting

### Limits
- **Anonymous users**: 100 requests per minute
- **Authenticated users**: 1000 requests per minute
- **WebSocket connections**: 100 per IP address

### Headers
Rate limit information is included in response headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248675
```

## Examples

### Python Client
```python
import requests
import json

class FlowHawkClient:
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url
        self.session = requests.Session()
        if username and password:
            self.session.auth = (username, password)
    
    def get_stats(self):
        """Get system statistics"""
        response = self.session.get(f"{self.base_url}/stats")
        response.raise_for_status()
        return response.json()
    
    def get_threats(self, severity=None, limit=100):
        """Get detected threats"""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        
        response = self.session.get(f"{self.base_url}/threats", params=params)
        response.raise_for_status()
        return response.json()
    
    def acknowledge_threat(self, threat_id, comment):
        """Acknowledge a threat"""
        data = {"comment": comment, "acknowledged_by": "api_client"}
        response = self.session.post(
            f"{self.base_url}/threats/{threat_id}/acknowledge",
            json=data
        )
        response.raise_for_status()
        return response.json()

# Usage
client = FlowHawkClient("http://localhost:8080/api")
stats = client.get_stats()
print(f"Active flows: {stats['active_flows']}")

threats = client.get_threats(severity="high", limit=10)
for threat in threats["threats"]:
    print(f"Threat: {threat['type']} from {threat['src_ip']}")
```

### JavaScript Client
```javascript
class FlowHawkClient {
  constructor(baseUrl, authToken = null) {
    this.baseUrl = baseUrl;
    this.authToken = authToken;
  }

  async request(endpoint, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  async getStats() {
    return this.request('/stats');
  }

  async getThreats(filters = {}) {
    const params = new URLSearchParams(filters);
    return this.request(`/threats?${params}`);
  }

  async getDashboardData() {
    return this.request('/dashboard');
  }

  // WebSocket connection for real-time updates
  connectWebSocket() {
    const wsUrl = this.baseUrl.replace('http', 'ws').replace('/api', '/ws');
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handleRealtimeUpdate(data);
    };

    return ws;
  }

  handleRealtimeUpdate(data) {
    switch (data.type) {
      case 'threat_detected':
        console.log('New threat:', data.data);
        break;
      case 'dashboard_update':
        this.updateDashboard(data.data);
        break;
    }
  }
}

// Usage
const client = new FlowHawkClient('http://localhost:8080/api');

// Get current stats
client.getStats().then(stats => {
  console.log('System stats:', stats);
});

// Connect to real-time updates
const ws = client.connectWebSocket();
```

### Bash/curl Examples
```bash
#!/bin/bash

API_BASE="http://localhost:8080/api"

# Get system statistics
curl -s "$API_BASE/stats" | jq .

# Get high severity threats from last hour
SINCE=$(date -d '1 hour ago' -Iseconds)
curl -s "$API_BASE/threats?severity=high&since=$SINCE" | jq '.threats[]'

# Test alerts
curl -X POST "$API_BASE/alerts/test" \
  -H "Content-Type: application/json" \
  -d '{"channels": ["webhook"], "message": "Test alert"}'

# Create custom rule
curl -X POST "$API_BASE/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Suspicious Port Access",
    "description": "Detects access to unusual ports",
    "enabled": true,
    "conditions": [
      {
        "field": "dst_port",
        "operator": "in",
        "value": [4444, 5555, 6666]
      }
    ],
    "actions": [
      {
        "type": "alert",
        "severity": "medium",
        "message": "Access to suspicious port detected"
      }
    ]
  }'
```

For more examples and integration guides, see the `examples/` directory in the repository.