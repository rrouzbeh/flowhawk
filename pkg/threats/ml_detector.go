package threats

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"flowhawk/internal/models"
)

// MLThreatDetector implements machine learning-based threat detection
type MLThreatDetector struct {
	// Feature extractors
	packetFeatures   []PacketFeature
	flowFeatures     []FlowFeature
	timeFeatures     []TimeFeature
	
	// Anomaly detection models
	packetAnomalyModel *AnomalyDetector
	flowAnomalyModel   *AnomalyDetector
	
	// Training data
	normalProfiles     map[string]*TrafficProfile
	trainingWindow     time.Duration
	updateInterval     time.Duration
	
	// Thread safety
	mutex sync.RWMutex
	
	// Statistics
	detectionStats *MLDetectionStats
}

// PacketFeature represents a packet-level feature
type PacketFeature struct {
	Name        string
	Value       float64
	Weight      float64
	Normalizer  func(float64) float64
}

// FlowFeature represents a flow-level feature
type FlowFeature struct {
	Name         string
	Value        float64
	Weight       float64
	WindowSize   time.Duration
	Aggregator   func([]float64) float64
}

// TimeFeature represents time-based features
type TimeFeature struct {
	Name           string
	Values         []float64
	WindowSize     time.Duration
	PatternMatcher func([]float64) float64
}

// TrafficProfile represents normal traffic patterns for an entity
type TrafficProfile struct {
	EntityID       string
	PacketSizes    *StatisticalModel
	FlowDurations  *StatisticalModel
	InterArrival   *StatisticalModel
	PortUsage      map[uint16]float64
	ProtocolDist   map[uint8]float64
	TimePatterns   map[int]float64 // hour of day
	LastUpdated    time.Time
	SampleCount    int
}

// StatisticalModel represents statistical properties of a feature
type StatisticalModel struct {
	Mean         float64
	Variance     float64
	Percentiles  map[int]float64 // 25th, 50th, 75th, 90th, 95th, 99th
	Min          float64
	Max          float64
	SampleCount  int
}

// AnomalyDetector implements statistical anomaly detection
type AnomalyDetector struct {
	Threshold       float64
	WindowSize      int
	RecentScores    []float64
	BaselineScores  []float64
	AdaptiveMode    bool
	SensitivityFactor float64
}

// MLDetectionStats tracks ML detection performance
type MLDetectionStats struct {
	TotalAnalyzed      uint64
	AnomaliesDetected  uint64
	FalsePositives     uint64
	TruePositives      uint64
	ModelUpdates       uint64
	LastModelUpdate    time.Time
	DetectionAccuracy  float64
}

// NewMLThreatDetector creates a new ML-based threat detector
func NewMLThreatDetector() *MLThreatDetector {
	detector := &MLThreatDetector{
		normalProfiles:     make(map[string]*TrafficProfile),
		trainingWindow:     24 * time.Hour,
		updateInterval:     time.Hour,
		detectionStats:     &MLDetectionStats{},
	}
	
	// Initialize anomaly detection models
	detector.packetAnomalyModel = &AnomalyDetector{
		Threshold:         2.5, // 2.5 standard deviations
		WindowSize:        1000,
		RecentScores:      make([]float64, 0),
		BaselineScores:    make([]float64, 0),
		AdaptiveMode:      true,
		SensitivityFactor: 1.0,
	}
	
	detector.flowAnomalyModel = &AnomalyDetector{
		Threshold:         2.0,
		WindowSize:        100,
		RecentScores:      make([]float64, 0),
		BaselineScores:    make([]float64, 0),
		AdaptiveMode:      true,
		SensitivityFactor: 1.2,
	}
	
	// Start background model update process
	go detector.periodicModelUpdate()
	
	return detector
}

// AnalyzePacketAnomaly performs ML-based packet anomaly detection
func (ml *MLThreatDetector) AnalyzePacketAnomaly(packet *models.PacketEvent) *models.ThreatEvent {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()
	
	// Extract packet features
	features := ml.extractPacketFeatures(packet)
	
	// Get or create traffic profile for source IP
	profileKey := packet.SrcIP.String()
	profile := ml.getOrCreateProfile(profileKey)
	
	// Calculate anomaly score
	anomalyScore := ml.calculatePacketAnomalyScore(features, profile)
	
	// Update anomaly detector
	ml.packetAnomalyModel.AddScore(anomalyScore)
	
	// Check if anomalous
	if ml.packetAnomalyModel.IsAnomalous(anomalyScore) {
		ml.detectionStats.AnomaliesDetected++
		
		return &models.ThreatEvent{
			ID:          fmt.Sprintf("ml-packet-%s-%d", profileKey, packet.Timestamp.Unix()),
			Type:        models.ThreatProcessAnomaly,
			Severity:    ml.calculateSeverityFromScore(anomalyScore),
			Timestamp:   packet.Timestamp,
			SrcIP:       packet.SrcIP,
			DstIP:       packet.DstIP,
			SrcPort:     packet.SrcPort,
			DstPort:     packet.DstPort,
			Protocol:    packet.Protocol,
			Description: fmt.Sprintf("ML packet anomaly detected (score: %.2f)", anomalyScore),
			Metadata: map[string]interface{}{
				"anomaly_score":      anomalyScore,
				"threshold":          ml.packetAnomalyModel.Threshold,
				"feature_count":      len(features),
				"profile_samples":    profile.SampleCount,
				"detection_method":   "machine_learning",
			},
			ProcessID:   packet.ProcessID,
			ProcessName: packet.ProcessName,
		}
	}
	
	// Update traffic profile with this packet
	ml.updateProfile(profile, packet)
	ml.detectionStats.TotalAnalyzed++
	
	return nil
}

// AnalyzeFlowAnomaly performs ML-based flow anomaly detection
func (ml *MLThreatDetector) AnalyzeFlowAnomaly(flow *models.FlowMetrics) *models.ThreatEvent {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()
	
	// Extract flow features
	features := ml.extractFlowFeatures(flow)
	
	// Get traffic profile for flow
	profileKey := flow.Key.SrcIP.String()
	profile := ml.getOrCreateProfile(profileKey)
	
	// Calculate anomaly score
	anomalyScore := ml.calculateFlowAnomalyScore(features, profile)
	
	// Update anomaly detector
	ml.flowAnomalyModel.AddScore(anomalyScore)
	
	// Check if anomalous
	if ml.flowAnomalyModel.IsAnomalous(anomalyScore) {
		ml.detectionStats.AnomaliesDetected++
		
		severity := ml.calculateSeverityFromScore(anomalyScore)
		
		return &models.ThreatEvent{
			ID:          fmt.Sprintf("ml-flow-%s-%d", profileKey, time.Now().Unix()),
			Type:        models.ThreatProcessAnomaly,
			Severity:    severity,
			Timestamp:   time.Now(),
			SrcIP:       flow.Key.SrcIP,
			DstIP:       flow.Key.DstIP,
			SrcPort:     flow.Key.SrcPort,
			DstPort:     flow.Key.DstPort,
			Protocol:    flow.Key.Protocol,
			Description: fmt.Sprintf("ML flow anomaly detected (score: %.2f)", anomalyScore),
			Metadata: map[string]interface{}{
				"anomaly_score":    anomalyScore,
				"threshold":        ml.flowAnomalyModel.Threshold,
				"flow_duration":    flow.LastSeen.Sub(flow.FirstSeen).Seconds(),
				"packet_count":     flow.Packets,
				"byte_count":       flow.Bytes,
				"detection_method": "machine_learning",
			},
		}
	}
	
	return nil
}

// extractPacketFeatures extracts features from a packet for ML analysis
func (ml *MLThreatDetector) extractPacketFeatures(packet *models.PacketEvent) []PacketFeature {
	features := []PacketFeature{
		{
			Name:   "packet_size",
			Value:  float64(packet.PacketSize),
			Weight: 1.0,
			Normalizer: func(v float64) float64 {
				return math.Log(v + 1) // Log normalization for packet sizes
			},
		},
		{
			Name:   "hour_of_day",
			Value:  float64(packet.Timestamp.Hour()),
			Weight: 0.8,
			Normalizer: func(v float64) float64 {
				// Circular encoding for hour
				return math.Sin(2 * math.Pi * v / 24)
			},
		},
		{
			Name:   "protocol",
			Value:  float64(packet.Protocol),
			Weight: 1.2,
			Normalizer: func(v float64) float64 {
				return v / 255.0 // Normalize protocol to [0,1]
			},
		},
		{
			Name:   "port_entropy",
			Value:  ml.calculatePortEntropy(packet.SrcPort, packet.DstPort),
			Weight: 1.5,
			Normalizer: func(v float64) float64 {
				return v // Already normalized
			},
		},
		{
			Name:   "flags_complexity",
			Value:  ml.calculateFlagsComplexity(packet.Flags),
			Weight: 1.3,
			Normalizer: func(v float64) float64 {
				return v
			},
		},
	}
	
	return features
}

// extractFlowFeatures extracts features from a flow for ML analysis
func (ml *MLThreatDetector) extractFlowFeatures(flow *models.FlowMetrics) []FlowFeature {
	duration := flow.LastSeen.Sub(flow.FirstSeen).Seconds()
	if duration == 0 {
		duration = 1 // Avoid division by zero
	}
	
	features := []FlowFeature{
		{
			Name:   "duration",
			Value:  duration,
			Weight: 1.0,
		},
		{
			Name:   "packet_rate",
			Value:  float64(flow.Packets) / duration,
			Weight: 1.2,
		},
		{
			Name:   "byte_rate",
			Value:  float64(flow.Bytes) / duration,
			Weight: 1.1,
		},
		{
			Name:   "avg_packet_size",
			Value:  float64(flow.Bytes) / float64(flow.Packets),
			Weight: 1.0,
		},
		{
			Name:   "protocol_consistency",
			Value:  1.0, // Simplified - always consistent within a flow
			Weight: 0.8,
		},
	}
	
	return features
}

// calculatePacketAnomalyScore calculates anomaly score for a packet
func (ml *MLThreatDetector) calculatePacketAnomalyScore(features []PacketFeature, profile *TrafficProfile) float64 {
	if profile.SampleCount < 10 {
		return 0.0 // Not enough data for anomaly detection
	}
	
	totalScore := 0.0
	totalWeight := 0.0
	
	for _, feature := range features {
		normalizedValue := feature.Normalizer(feature.Value)
		
		var featureScore float64
		switch feature.Name {
		case "packet_size":
			featureScore = ml.calculateStatisticalAnomaly(normalizedValue, profile.PacketSizes)
		case "hour_of_day":
			hour := int(feature.Value)
			expectedProb := profile.TimePatterns[hour]
			if expectedProb == 0 {
				expectedProb = 1.0 / 24.0 // Uniform prior
			}
			featureScore = -math.Log(expectedProb + 1e-10) // Negative log likelihood
		case "protocol":
			protocol := uint8(feature.Value)
			expectedProb := profile.ProtocolDist[protocol]
			if expectedProb == 0 {
				expectedProb = 0.01 // Small prior for unseen protocols
			}
			featureScore = -math.Log(expectedProb + 1e-10)
		default:
			featureScore = 0.0
		}
		
		totalScore += featureScore * feature.Weight
		totalWeight += feature.Weight
	}
	
	if totalWeight > 0 {
		return totalScore / totalWeight
	}
	
	return 0.0
}

// calculateFlowAnomalyScore calculates anomaly score for a flow
func (ml *MLThreatDetector) calculateFlowAnomalyScore(features []FlowFeature, profile *TrafficProfile) float64 {
	if profile.SampleCount < 5 {
		return 0.0
	}
	
	totalScore := 0.0
	totalWeight := 0.0
	
	for _, feature := range features {
		var featureScore float64
		
		switch feature.Name {
		case "duration":
			featureScore = ml.calculateStatisticalAnomaly(feature.Value, profile.FlowDurations)
		case "packet_rate", "byte_rate":
			// Use z-score for rate features
			if profile.FlowDurations != nil && profile.FlowDurations.Variance > 0 {
				mean := profile.FlowDurations.Mean
				stddev := math.Sqrt(profile.FlowDurations.Variance)
				featureScore = math.Abs((feature.Value - mean) / stddev)
			}
		case "avg_packet_size":
			featureScore = ml.calculateStatisticalAnomaly(feature.Value, profile.PacketSizes)
		default:
			featureScore = 0.0
		}
		
		totalScore += featureScore * feature.Weight
		totalWeight += feature.Weight
	}
	
	if totalWeight > 0 {
		return totalScore / totalWeight
	}
	
	return 0.0
}

// calculateStatisticalAnomaly calculates statistical anomaly score
func (ml *MLThreatDetector) calculateStatisticalAnomaly(value float64, model *StatisticalModel) float64 {
	if model == nil || model.SampleCount < 3 {
		return 0.0
	}
	
	// Use modified z-score with median and MAD for robustness
	if model.Variance > 0 {
		stddev := math.Sqrt(model.Variance)
		zScore := math.Abs((value - model.Mean) / stddev)
		return zScore
	}
	
	return 0.0
}

// calculatePortEntropy calculates entropy of port usage
func (ml *MLThreatDetector) calculatePortEntropy(srcPort, dstPort uint16) float64 {
	// Simplified entropy calculation based on port characteristics
	commonPorts := map[uint16]bool{
		80: true, 443: true, 22: true, 21: true, 25: true,
		53: true, 110: true, 143: true, 993: true, 995: true,
	}
	
	entropy := 0.0
	if !commonPorts[srcPort] {
		entropy += 0.5
	}
	if !commonPorts[dstPort] {
		entropy += 0.5
	}
	
	// Add randomness factor for high ports
	if srcPort > 1024 && srcPort < 65000 {
		entropy += 0.2
	}
	if dstPort > 1024 && dstPort < 65000 {
		entropy += 0.2
	}
	
	return math.Min(entropy, 1.0)
}

// calculateFlagsComplexity calculates complexity of TCP flags
func (ml *MLThreatDetector) calculateFlagsComplexity(flags uint32) float64 {
	// Count number of flags set
	complexity := 0.0
	for i := 0; i < 8; i++ {
		if flags&(1<<i) != 0 {
			complexity += 0.125
		}
	}
	
	// Unusual flag combinations get higher complexity
	if flags&0x02 != 0 && flags&0x10 != 0 { // SYN+ACK
		complexity *= 0.8 // Normal combination
	} else if flags&0x04 != 0 { // RST
		complexity *= 2.0 // More suspicious
	} else if flags == 0 { // No flags (scan)
		complexity *= 1.5 // Suspicious
	}
	
	return math.Min(complexity, 1.0)
}

// getOrCreateProfile gets existing profile or creates new one
func (ml *MLThreatDetector) getOrCreateProfile(entityID string) *TrafficProfile {
	profile, exists := ml.normalProfiles[entityID]
	if !exists {
		profile = &TrafficProfile{
			EntityID:      entityID,
			PacketSizes:   &StatisticalModel{},
			FlowDurations: &StatisticalModel{},
			InterArrival:  &StatisticalModel{},
			PortUsage:     make(map[uint16]float64),
			ProtocolDist:  make(map[uint8]float64),
			TimePatterns:  make(map[int]float64),
			LastUpdated:   time.Now(),
			SampleCount:   0,
		}
		ml.normalProfiles[entityID] = profile
	}
	
	return profile
}

// updateProfile updates traffic profile with new data
func (ml *MLThreatDetector) updateProfile(profile *TrafficProfile, packet *models.PacketEvent) {
	profile.SampleCount++
	profile.LastUpdated = time.Now()
	
	// Update packet size statistics
	ml.updateStatisticalModel(profile.PacketSizes, float64(packet.PacketSize))
	
	// Update protocol distribution
	protocol := uint8(packet.Protocol)
	profile.ProtocolDist[protocol] = (profile.ProtocolDist[protocol]*float64(profile.SampleCount-1) + 1.0) / float64(profile.SampleCount)
	
	// Update time patterns
	hour := packet.Timestamp.Hour()
	profile.TimePatterns[hour] = (profile.TimePatterns[hour]*float64(profile.SampleCount-1) + 1.0) / float64(profile.SampleCount)
	
	// Update port usage
	profile.PortUsage[packet.DstPort] = (profile.PortUsage[packet.DstPort]*float64(profile.SampleCount-1) + 1.0) / float64(profile.SampleCount)
}

// updateStatisticalModel updates statistical model incrementally
func (ml *MLThreatDetector) updateStatisticalModel(model *StatisticalModel, value float64) {
	model.SampleCount++
	
	if model.SampleCount == 1 {
		model.Mean = value
		model.Variance = 0
		model.Min = value
		model.Max = value
		return
	}
	
	// Update using Welford's online algorithm
	delta := value - model.Mean
	model.Mean += delta / float64(model.SampleCount)
	delta2 := value - model.Mean
	model.Variance += delta * delta2
	
	// Update min/max
	if value < model.Min {
		model.Min = value
	}
	if value > model.Max {
		model.Max = value
	}
	
	// Finalize variance calculation
	if model.SampleCount > 1 {
		model.Variance /= float64(model.SampleCount - 1)
	}
}

// AddScore adds a score to the anomaly detector
func (ad *AnomalyDetector) AddScore(score float64) {
	ad.RecentScores = append(ad.RecentScores, score)
	
	// Maintain window size
	if len(ad.RecentScores) > ad.WindowSize {
		ad.RecentScores = ad.RecentScores[1:]
	}
	
	// Update baseline if in adaptive mode
	if ad.AdaptiveMode && len(ad.RecentScores) > ad.WindowSize/2 {
		ad.updateBaseline()
	}
}

// IsAnomalous determines if a score is anomalous
func (ad *AnomalyDetector) IsAnomalous(score float64) bool {
	if len(ad.RecentScores) < 10 {
		return false // Not enough data
	}
	
	// Calculate dynamic threshold
	threshold := ad.Threshold
	if ad.AdaptiveMode {
		threshold = ad.calculateAdaptiveThreshold()
	}
	
	return score > threshold
}

// updateBaseline updates the baseline scores for adaptive detection
func (ad *AnomalyDetector) updateBaseline() {
	// Use lower percentile scores as baseline (normal behavior)
	scores := make([]float64, len(ad.RecentScores))
	copy(scores, ad.RecentScores)
	sort.Float64s(scores)
	
	// Take bottom 80% as baseline
	cutoff := int(0.8 * float64(len(scores)))
	if cutoff > 0 {
		ad.BaselineScores = scores[:cutoff]
	}
}

// calculateAdaptiveThreshold calculates adaptive threshold based on recent data
func (ad *AnomalyDetector) calculateAdaptiveThreshold() float64 {
	if len(ad.BaselineScores) < 5 {
		return ad.Threshold
	}
	
	// Calculate mean and standard deviation of baseline
	sum := 0.0
	for _, score := range ad.BaselineScores {
		sum += score
	}
	mean := sum / float64(len(ad.BaselineScores))
	
	variance := 0.0
	for _, score := range ad.BaselineScores {
		variance += (score - mean) * (score - mean)
	}
	variance /= float64(len(ad.BaselineScores) - 1)
	stddev := math.Sqrt(variance)
	
	// Adaptive threshold: mean + (sensitivity * stddev)
	return mean + (ad.SensitivityFactor * stddev)
}

// calculateSeverityFromScore maps anomaly score to threat severity
func (ml *MLThreatDetector) calculateSeverityFromScore(score float64) models.Severity {
	if score > 5.0 {
		return models.SeverityCritical
	} else if score > 3.0 {
		return models.SeverityHigh
	} else if score > 2.0 {
		return models.SeverityMedium
	}
	return models.SeverityLow
}

// periodicModelUpdate performs periodic model updates
func (ml *MLThreatDetector) periodicModelUpdate() {
	ticker := time.NewTicker(ml.updateInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		ml.mutex.Lock()
		
		// Clean up old profiles
		cutoff := time.Now().Add(-ml.trainingWindow)
		for entityID, profile := range ml.normalProfiles {
			if profile.LastUpdated.Before(cutoff) {
				delete(ml.normalProfiles, entityID)
			}
		}
		
		// Update detection statistics
		ml.detectionStats.LastModelUpdate = time.Now()
		ml.detectionStats.ModelUpdates++
		
		ml.mutex.Unlock()
	}
}

// GetMLStats returns ML detection statistics
func (ml *MLThreatDetector) GetMLStats() *MLDetectionStats {
	ml.mutex.RLock()
	defer ml.mutex.RUnlock()
	
	// Calculate detection accuracy (simplified)
	total := ml.detectionStats.TruePositives + ml.detectionStats.FalsePositives
	if total > 0 {
		ml.detectionStats.DetectionAccuracy = float64(ml.detectionStats.TruePositives) / float64(total)
	}
	
	return &MLDetectionStats{
		TotalAnalyzed:      ml.detectionStats.TotalAnalyzed,
		AnomaliesDetected:  ml.detectionStats.AnomaliesDetected,
		FalsePositives:     ml.detectionStats.FalsePositives,
		TruePositives:      ml.detectionStats.TruePositives,
		ModelUpdates:       ml.detectionStats.ModelUpdates,
		LastModelUpdate:    ml.detectionStats.LastModelUpdate,
		DetectionAccuracy:  ml.detectionStats.DetectionAccuracy,
	}
}