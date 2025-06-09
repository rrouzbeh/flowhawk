# FlowHawk Benchmark Tests

This directory contains comprehensive benchmark tests for the FlowHawk network security monitor. These benchmarks help measure and track performance characteristics of critical components.

## Overview

The benchmark suite covers all major components of FlowHawk:

- **eBPF Manager**: Core packet capture and kernel-space operations
- **Event Processor**: Packet processing and flow management
- **Threat Engine**: Threat detection algorithms and rule evaluation
- **Alert Manager**: Alert generation, filtering, and delivery
- **ML Detector**: Machine learning-based anomaly detection

## Benchmark Files

| File | Description | Focus Areas |
|------|-------------|-------------|
| `ebpf_bench_test.go` | eBPF manager benchmarks | Packet reading, flow metrics, statistics |
| `processor_bench_test.go` | Event processor benchmarks | Packet processing, metrics collection |
| `threats_bench_test.go` | Threat detection benchmarks | Detection algorithms, pattern matching |
| `alerts_bench_test.go` | Alert system benchmarks | Alert generation, rate limiting |
| `ml_detector_bench_test.go` | ML detector benchmarks | Anomaly detection, pattern analysis |

## Running Benchmarks

### Quick Start

```bash
# Run all benchmarks
make bench

# Run specific component benchmarks
make bench-processor
make bench-threats
make bench-ebpf
make bench-alerts
make bench-ml
```

### Detailed Analysis

```bash
# Generate timestamped benchmark report
make bench-report

# Run multiple iterations for statistical analysis
make bench-stats

# Run with CPU and memory profiling
make bench-compare
```

### Manual Execution

```bash
# Run specific benchmark functions
go test -bench=BenchmarkProcessorCreation ./tests/benchmarks/

# Run with memory allocation reporting
go test -bench=. -benchmem ./tests/benchmarks/

# Run with specific patterns
go test -bench=BenchmarkThreat ./tests/benchmarks/

# Run with profiling
go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof ./tests/benchmarks/
```

## Benchmark Categories

### Performance Benchmarks
- Component creation and initialization
- Single operation performance
- High-volume data processing
- Concurrent operation handling

### Scalability Benchmarks
- Memory allocation patterns
- Throughput under load
- Resource utilization efficiency
- Concurrent access performance

### Real-World Scenarios
- Burst traffic handling
- Mixed workload patterns
- Long-running operation stability
- Resource cleanup efficiency

## Interpreting Results

### Example Output
```
BenchmarkProcessorCreation-8           1000    1045231 ns/op    2048 B/op      15 allocs/op
BenchmarkPacketProcessing-8           50000     28456 ns/op     512 B/op       8 allocs/op
BenchmarkThreatDetection-8            30000     41234 ns/op     768 B/op      12 allocs/op
```

### Understanding Metrics
- **Operations/second**: Higher is better (more ops per second)
- **ns/op**: Nanoseconds per operation (lower is better)
- **B/op**: Bytes allocated per operation (lower is better)
- **allocs/op**: Number of allocations per operation (lower is better)

### Performance Targets
| Component | Target (ns/op) | Memory (B/op) | Notes |
|-----------|----------------|---------------|-------|
| Packet Processing | < 50,000 | < 1,024 | Per packet |
| Threat Detection | < 100,000 | < 2,048 | Per analysis |
| Alert Generation | < 10,000 | < 512 | Per alert |
| Flow Retrieval | < 5,000 | < 256 | Per flow |

## Mock Data and Testing

The benchmarks use realistic mock data to simulate production conditions:

### Packet Events
- Varied source/destination IPs
- Multiple protocols (TCP, UDP, ICMP)
- Different packet sizes (64B - 1500B)
- Realistic timing patterns

### Flow Metrics
- Long-lived and short-lived flows
- Various throughput patterns
- Different connection states
- Realistic byte/packet ratios

### Threat Scenarios
- Port scanning patterns
- DDoS attack simulations
- Botnet communication patterns
- Data exfiltration scenarios

## Continuous Integration

### Regression Testing
- Benchmark results are tracked over time
- Performance regressions trigger alerts
- Optimization efforts are measurable

### Environment Considerations
- Run on consistent hardware
- Minimize background processes
- Use dedicated benchmark environment
- Account for CPU thermal throttling

## Profiling and Analysis

### CPU Profiling
```bash
go test -bench=BenchmarkProcessor -cpuprofile=cpu.prof ./tests/benchmarks/
go tool pprof cpu.prof
```

### Memory Profiling
```bash
go test -bench=BenchmarkProcessor -memprofile=mem.prof ./tests/benchmarks/
go tool pprof mem.prof
```

### Trace Analysis
```bash
go test -bench=BenchmarkProcessor -trace=trace.out ./tests/benchmarks/
go tool trace trace.out
```

## Performance Optimization Tips

### Code Optimization
- Minimize allocations in hot paths
- Use object pooling for frequent allocations
- Optimize data structures for access patterns
- Consider lock-free algorithms for concurrent access

### Memory Management
- Reuse buffers where possible
- Implement proper cleanup in defer statements
- Monitor goroutine leaks in concurrent benchmarks
- Use appropriate data types for memory efficiency

### I/O Optimization
- Batch operations when possible
- Use buffered I/O for file operations
- Implement proper backpressure handling
- Consider async processing for non-critical paths

## Benchmark Best Practices

### Writing Benchmarks
- Use `b.ResetTimer()` after setup
- Avoid allocations in benchmark loops
- Test with realistic data sizes
- Include both single-threaded and concurrent tests

### Measurement Accuracy
- Run multiple iterations (`-count=N`)
- Account for warm-up time
- Minimize system noise during testing
- Use consistent hardware configurations

### Documentation
- Document expected performance characteristics
- Include context for performance targets
- Explain any mock data or simulation logic
- Note any platform-specific considerations

## Troubleshooting

### Common Issues
- **Inconsistent results**: Check for background processes, thermal throttling
- **Memory leaks**: Ensure proper cleanup in test teardown
- **Compilation errors**: Verify all dependencies are available
- **Missing mock data**: Check that mock managers are properly configured

### Debug Mode
```bash
# Run with verbose output
go test -bench=. -v ./tests/benchmarks/

# Run specific test with detailed output
go test -bench=BenchmarkProcessorCreation -v ./tests/benchmarks/

# Check for race conditions
go test -bench=. -race ./tests/benchmarks/
```

## Contributing

When adding new benchmarks:

1. Follow existing naming conventions (`BenchmarkComponentFunction`)
2. Include both single-threaded and concurrent variants
3. Test with realistic data volumes
4. Document expected performance characteristics
5. Update this README with new benchmark descriptions

### Example Benchmark Structure
```go
func BenchmarkNewFeature(b *testing.B) {
    // Setup (not measured)
    setup := createSetup()
    
    b.ResetTimer() // Start measuring here
    for i := 0; i < b.N; i++ {
        // Operation to benchmark
        result := feature.Process(input)
        _ = result // Prevent optimization
    }
}
```

## Reports and Monitoring

Benchmark reports are saved to `./reports/` with timestamps for historical tracking. Monitor these metrics for:

- Performance regressions
- Memory usage trends
- Scalability improvements
- Optimization verification

Regular benchmark execution helps maintain performance standards and catch regressions early in development.