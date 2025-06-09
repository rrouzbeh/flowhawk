package threats

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"flowhawk/internal/models"
)

// RuleEngine implements a flexible rule-based threat detection system
type RuleEngine struct {
	rules       []models.ThreatRule
	customRules []CustomRule
	matchers    map[string]RuleMatcher
}

// CustomRule represents a user-defined threat detection rule
type CustomRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Conditions  []RuleCondition        `json:"conditions"`
	Actions     []RuleAction           `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// RuleCondition represents a condition that must be met for a rule to trigger
type RuleCondition struct {
	Field    string      `json:"field"`    // src_ip, dst_ip, src_port, dst_port, protocol, packet_size, etc.
	Operator string      `json:"operator"` // eq, ne, lt, gt, le, ge, in, not_in, regex, contains
	Value    interface{} `json:"value"`
	Logic    string      `json:"logic"`    // and, or (for combining with next condition)
}

// RuleAction represents an action to take when a rule triggers
type RuleAction struct {
	Type       string                 `json:"type"`       // alert, block, log, drop
	Severity   string                 `json:"severity"`   // low, medium, high, critical
	Message    string                 `json:"message"`
	Parameters map[string]interface{} `json:"parameters"`
}

// RuleMatcher interface for different types of rule matching
type RuleMatcher interface {
	Match(packet *models.PacketEvent, condition RuleCondition) bool
	GetName() string
}

// IPMatcher handles IP address matching
type IPMatcher struct{}

// PortMatcher handles port matching
type PortMatcher struct{}

// ProtocolMatcher handles protocol matching
type ProtocolMatcher struct{}

// SizeMatcher handles packet size matching
type SizeMatcher struct{}

// RegexMatcher handles regex pattern matching
type RegexMatcher struct{}

// TimeWindowMatcher handles time-based matching
type TimeWindowMatcher struct{}

// NewRuleEngine creates a new rule engine
func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{
		rules:       make([]models.ThreatRule, 0),
		customRules: make([]CustomRule, 0),
		matchers:    make(map[string]RuleMatcher),
	}
	
	// Register built-in matchers
	engine.matchers["ip"] = &IPMatcher{}
	engine.matchers["port"] = &PortMatcher{}
	engine.matchers["protocol"] = &ProtocolMatcher{}
	engine.matchers["size"] = &SizeMatcher{}
	engine.matchers["regex"] = &RegexMatcher{}
	engine.matchers["time"] = &TimeWindowMatcher{}
	
	// Load default rules
	engine.loadDefaultRules()
	
	return engine
}

// EvaluatePacket evaluates a packet against all active rules
func (re *RuleEngine) EvaluatePacket(packet *models.PacketEvent) []*models.ThreatEvent {
	var threats []*models.ThreatEvent
	
	// Evaluate custom rules
	for _, rule := range re.customRules {
		if !rule.Enabled {
			continue
		}
		
		if re.evaluateRule(packet, rule) {
			threat := re.createThreatFromRule(packet, rule)
			threats = append(threats, threat)
		}
	}
	
	return threats
}

// evaluateRule evaluates a single rule against a packet
func (re *RuleEngine) evaluateRule(packet *models.PacketEvent, rule CustomRule) bool {
	if len(rule.Conditions) == 0 {
		return false
	}
	
	result := true
	currentLogic := "and"
	
	for i, condition := range rule.Conditions {
		conditionResult := re.evaluateCondition(packet, condition)
		
		if i == 0 {
			result = conditionResult
		} else {
			switch currentLogic {
			case "and":
				result = result && conditionResult
			case "or":
				result = result || conditionResult
			}
		}
		
		// Set logic for next iteration
		if condition.Logic != "" {
			currentLogic = condition.Logic
		}
	}
	
	return result
}

// evaluateCondition evaluates a single condition
func (re *RuleEngine) evaluateCondition(packet *models.PacketEvent, condition RuleCondition) bool {
	// Get the field value from the packet
	fieldValue := re.getFieldValue(packet, condition.Field)
	if fieldValue == nil {
		return false
	}
	
	// Use appropriate matcher based on field type
	var matcher RuleMatcher
	switch condition.Field {
	case "src_ip", "dst_ip":
		matcher = re.matchers["ip"]
	case "src_port", "dst_port":
		matcher = re.matchers["port"]
	case "protocol":
		matcher = re.matchers["protocol"]
	case "packet_size":
		matcher = re.matchers["size"]
	default:
		matcher = re.matchers["regex"] // Default to regex for custom fields
	}
	
	if matcher == nil {
		return false
	}
	
	return matcher.Match(packet, condition)
}

// getFieldValue extracts field value from packet
func (re *RuleEngine) getFieldValue(packet *models.PacketEvent, field string) interface{} {
	switch field {
	case "src_ip":
		return packet.SrcIP.String()
	case "dst_ip":
		return packet.DstIP.String()
	case "src_port":
		return packet.SrcPort
	case "dst_port":
		return packet.DstPort
	case "protocol":
		return uint8(packet.Protocol)
	case "packet_size":
		return packet.PacketSize
	case "flags":
		return packet.Flags
	case "process_id":
		return packet.ProcessID
	case "process_name":
		return packet.ProcessName
	case "hour":
		return packet.Timestamp.Hour()
	case "day_of_week":
		return int(packet.Timestamp.Weekday())
	default:
		return nil
	}
}

// createThreatFromRule creates a threat event from a triggered rule
func (re *RuleEngine) createThreatFromRule(packet *models.PacketEvent, rule CustomRule) *models.ThreatEvent {
	// Determine severity from actions
	severity := models.SeverityMedium
	message := rule.Description
	
	for _, action := range rule.Actions {
		switch action.Severity {
		case "low":
			if severity == models.SeverityMedium {
				severity = models.SeverityLow
			}
		case "high":
			severity = models.SeverityHigh
		case "critical":
			severity = models.SeverityCritical
		}
		
		if action.Message != "" {
			message = action.Message
		}
	}
	
	return &models.ThreatEvent{
		ID:          fmt.Sprintf("rule-%s-%d", rule.ID, packet.Timestamp.Unix()),
		Type:        models.ThreatProcessAnomaly, // Default type, could be configurable
		Severity:    severity,
		Timestamp:   packet.Timestamp,
		SrcIP:       packet.SrcIP,
		DstIP:       packet.DstIP,
		SrcPort:     packet.SrcPort,
		DstPort:     packet.DstPort,
		Protocol:    packet.Protocol,
		Description: message,
		Metadata: map[string]interface{}{
			"rule_id":     rule.ID,
			"rule_name":   rule.Name,
			"detection_method": "custom_rule",
		},
		ProcessID:   packet.ProcessID,
		ProcessName: packet.ProcessName,
	}
}

// Matcher implementations

// Match implements IP address matching
func (m *IPMatcher) Match(packet *models.PacketEvent, condition RuleCondition) bool {
	var targetIP string
	
	switch condition.Field {
	case "src_ip":
		targetIP = packet.SrcIP.String()
	case "dst_ip":
		targetIP = packet.DstIP.String()
	default:
		return false
	}
	
	switch condition.Operator {
	case "eq":
		return targetIP == condition.Value.(string)
	case "ne":
		return targetIP != condition.Value.(string)
	case "in":
		if networks, ok := condition.Value.([]string); ok {
			ip := net.ParseIP(targetIP)
			for _, network := range networks {
				if strings.Contains(network, "/") {
					_, cidr, err := net.ParseCIDR(network)
					if err == nil && cidr.Contains(ip) {
						return true
					}
				} else if network == targetIP {
					return true
				}
			}
		}
		return false
	case "not_in":
		return !m.Match(packet, RuleCondition{
			Field:    condition.Field,
			Operator: "in",
			Value:    condition.Value,
		})
	}
	
	return false
}

func (m *IPMatcher) GetName() string {
	return "ip"
}

// Match implements port matching
func (m *PortMatcher) Match(packet *models.PacketEvent, condition RuleCondition) bool {
	var targetPort uint16
	
	switch condition.Field {
	case "src_port":
		targetPort = packet.SrcPort
	case "dst_port":
		targetPort = packet.DstPort
	default:
		return false
	}
	
	switch condition.Operator {
	case "eq":
		if port, ok := condition.Value.(float64); ok {
			return targetPort == uint16(port)
		}
		return false
	case "ne":
		if port, ok := condition.Value.(float64); ok {
			return targetPort != uint16(port)
		}
		return false
	case "lt":
		if port, ok := condition.Value.(float64); ok {
			return targetPort < uint16(port)
		}
		return false
	case "gt":
		if port, ok := condition.Value.(float64); ok {
			return targetPort > uint16(port)
		}
		return false
	case "in":
		if ports, ok := condition.Value.([]interface{}); ok {
			for _, p := range ports {
				if port, ok := p.(float64); ok && targetPort == uint16(port) {
					return true
				}
			}
		}
		return false
	}
	
	return false
}

func (m *PortMatcher) GetName() string {
	return "port"
}

// Match implements protocol matching
func (m *ProtocolMatcher) Match(packet *models.PacketEvent, condition RuleCondition) bool {
	targetProtocol := uint8(packet.Protocol)
	
	switch condition.Operator {
	case "eq":
		if proto, ok := condition.Value.(float64); ok {
			return targetProtocol == uint8(proto)
		}
		return false
	case "ne":
		if proto, ok := condition.Value.(float64); ok {
			return targetProtocol != uint8(proto)
		}
		return false
	case "in":
		if protocols, ok := condition.Value.([]interface{}); ok {
			for _, p := range protocols {
				if proto, ok := p.(float64); ok && targetProtocol == uint8(proto) {
					return true
				}
			}
		}
		return false
	}
	
	return false
}

func (m *ProtocolMatcher) GetName() string {
	return "protocol"
}

// Match implements packet size matching
func (m *SizeMatcher) Match(packet *models.PacketEvent, condition RuleCondition) bool {
	targetSize := packet.PacketSize
	
	switch condition.Operator {
	case "eq":
		if size, ok := condition.Value.(float64); ok {
			return targetSize == uint32(size)
		}
		return false
	case "ne":
		if size, ok := condition.Value.(float64); ok {
			return targetSize != uint32(size)
		}
		return false
	case "lt":
		if size, ok := condition.Value.(float64); ok {
			return targetSize < uint32(size)
		}
		return false
	case "gt":
		if size, ok := condition.Value.(float64); ok {
			return targetSize > uint32(size)
		}
		return false
	}
	
	return false
}

func (m *SizeMatcher) GetName() string {
	return "size"
}

// Match implements regex pattern matching
func (m *RegexMatcher) Match(packet *models.PacketEvent, condition RuleCondition) bool {
	var targetValue string
	
	switch condition.Field {
	case "process_name":
		targetValue = packet.ProcessName
	case "src_ip":
		targetValue = packet.SrcIP.String()
	case "dst_ip":
		targetValue = packet.DstIP.String()
	default:
		return false
	}
	
	switch condition.Operator {
	case "regex":
		if pattern, ok := condition.Value.(string); ok {
			if matched, err := regexp.MatchString(pattern, targetValue); err == nil {
				return matched
			}
		}
		return false
	case "contains":
		if substr, ok := condition.Value.(string); ok {
			return strings.Contains(targetValue, substr)
		}
		return false
	}
	
	return false
}

func (m *RegexMatcher) GetName() string {
	return "regex"
}

// Match implements time window matching
func (m *TimeWindowMatcher) Match(packet *models.PacketEvent, condition RuleCondition) bool {
	currentHour := packet.Timestamp.Hour()
	currentDay := int(packet.Timestamp.Weekday())
	
	switch condition.Field {
	case "hour":
		return m.matchTimeRange(currentHour, condition)
	case "day_of_week":
		return m.matchTimeRange(currentDay, condition)
	default:
		return false
	}
}

func (m *TimeWindowMatcher) matchTimeRange(value int, condition RuleCondition) bool {
	switch condition.Operator {
	case "eq":
		if target, ok := condition.Value.(float64); ok {
			return value == int(target)
		}
		return false
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			for _, v := range values {
				if target, ok := v.(float64); ok && value == int(target) {
					return true
				}
			}
		}
		return false
	case "between":
		if rangeVal, ok := condition.Value.([]interface{}); ok && len(rangeVal) == 2 {
			if start, ok1 := rangeVal[0].(float64); ok1 {
				if end, ok2 := rangeVal[1].(float64); ok2 {
					return value >= int(start) && value <= int(end)
				}
			}
		}
		return false
	}
	
	return false
}

func (m *TimeWindowMatcher) GetName() string {
	return "time"
}

// Rule management methods

// AddCustomRule adds a new custom rule
func (re *RuleEngine) AddCustomRule(rule CustomRule) error {
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	
	// Validate rule
	if err := re.validateRule(rule); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}
	
	re.customRules = append(re.customRules, rule)
	return nil
}

// UpdateCustomRule updates an existing custom rule
func (re *RuleEngine) UpdateCustomRule(ruleID string, rule CustomRule) error {
	for i, existingRule := range re.customRules {
		if existingRule.ID == ruleID {
			rule.ID = ruleID
			rule.CreatedAt = existingRule.CreatedAt
			rule.UpdatedAt = time.Now()
			
			if err := re.validateRule(rule); err != nil {
				return fmt.Errorf("invalid rule: %w", err)
			}
			
			re.customRules[i] = rule
			return nil
		}
	}
	
	return fmt.Errorf("rule not found: %s", ruleID)
}

// DeleteCustomRule removes a custom rule
func (re *RuleEngine) DeleteCustomRule(ruleID string) error {
	for i, rule := range re.customRules {
		if rule.ID == ruleID {
			re.customRules = append(re.customRules[:i], re.customRules[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("rule not found: %s", ruleID)
}

// GetCustomRules returns all custom rules
func (re *RuleEngine) GetCustomRules() []CustomRule {
	return append([]CustomRule(nil), re.customRules...)
}

// validateRule validates a rule's syntax and logic
func (re *RuleEngine) validateRule(rule CustomRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}
	
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}
	
	if len(rule.Conditions) == 0 {
		return fmt.Errorf("rule must have at least one condition")
	}
	
	// Validate conditions
	for _, condition := range rule.Conditions {
		if condition.Field == "" {
			return fmt.Errorf("condition field cannot be empty")
		}
		
		if condition.Operator == "" {
			return fmt.Errorf("condition operator cannot be empty")
		}
		
		if condition.Value == nil {
			return fmt.Errorf("condition value cannot be nil")
		}
	}
	
	return nil
}

// loadDefaultRules loads default threat detection rules
func (re *RuleEngine) loadDefaultRules() {
	// Suspicious port scan rule
	re.customRules = append(re.customRules, CustomRule{
		ID:          "default-001",
		Name:        "Suspicious Port Range Scan",
		Description: "Detects scanning of common administrative ports",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "dst_port",
				Operator: "in",
				Value:    []interface{}{22.0, 23.0, 135.0, 139.0, 445.0, 3389.0},
				Logic:    "and",
			},
			{
				Field:    "protocol",
				Operator: "eq",
				Value:    6.0, // TCP
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "medium",
				Message:  "Suspicious port scan targeting administrative services",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	
	// Large packet size rule
	re.customRules = append(re.customRules, CustomRule{
		ID:          "default-002",
		Name:        "Abnormally Large Packet",
		Description: "Detects unusually large packets that might indicate attacks",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "packet_size",
				Operator: "gt",
				Value:    8192.0, // 8KB
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "low",
				Message:  "Abnormally large packet detected",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	
	// Off-hours activity rule
	re.customRules = append(re.customRules, CustomRule{
		ID:          "default-003",
		Name:        "Off-Hours Network Activity",
		Description: "Detects network activity during unusual hours",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "hour",
				Operator: "in",
				Value:    []interface{}{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 22.0, 23.0},
				Logic:    "and",
			},
			{
				Field:    "dst_port",
				Operator: "in",
				Value:    []interface{}{22.0, 443.0, 3389.0}, // SSH, HTTPS, RDP
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "medium",
				Message:  "Network activity detected during off-hours",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
}