# FlowHawk Network Security Monitor - Makefile

.PHONY: all build clean deps ebpf run test install uninstall

# Build variables
BINARY_NAME := flowhawk
BINARY_PATH := ./cmd/flowhawk
BUILD_DIR := ./build
EBPF_DIR := ./ebpf-programs
CLANG := clang
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /lib/modules/$(KERNEL_VERSION)/build

# eBPF programs
EBPF_SOURCES := $(wildcard $(EBPF_DIR)/*.c)
EBPF_OBJECTS := $(EBPF_SOURCES:.c=.o)

# Go build flags
LDFLAGS := -w -s
BUILD_FLAGS := -ldflags "$(LDFLAGS)"

all: deps ebpf build

# Install dependencies
deps:
	@echo "Installing Go dependencies..."
	@go mod download
	@go mod tidy
	@echo "Checking for required system tools..."
	@which clang > /dev/null || (echo "Error: clang not found. Install with: sudo apt-get install clang" && exit 1)
	@which llvm-strip > /dev/null || (echo "Error: llvm-strip not found. Install with: sudo apt-get install llvm" && exit 1)
	@test -d $(KERNEL_HEADERS) || (echo "Error: Kernel headers not found at $(KERNEL_HEADERS)" && exit 1)

# Build eBPF programs
ebpf: $(EBPF_OBJECTS)

%.o: %.c
	@echo "Compiling eBPF program: $<"
	@$(CLANG) \
		-target bpf \
		-D __TARGET_ARCH_x86 \
		-I$(KERNEL_HEADERS)/arch/x86/include \
		-I$(KERNEL_HEADERS)/arch/x86/include/generated \
		-I$(KERNEL_HEADERS)/include \
		-I$(KERNEL_HEADERS)/arch/x86/include/uapi \
		-I$(KERNEL_HEADERS)/arch/x86/include/generated/uapi \
		-I$(KERNEL_HEADERS)/include/uapi \
		-I$(KERNEL_HEADERS)/include/generated/uapi \
		-O2 -g -Wall -Werror \
		-c $< -o $@
	@llvm-strip -g $@

# Build Go binary
build: ebpf
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)

# Run the monitor (requires root)
run: build
	@echo "Running $(BINARY_NAME) (requires root privileges)..."
	@sudo $(BUILD_DIR)/$(BINARY_NAME)

# Run with config file
run-config: build
	@echo "Running $(BINARY_NAME) with config..."
	@sudo $(BUILD_DIR)/$(BINARY_NAME) -config ./configs/development.yaml

# Run basic tests (package tests only)
test:
	@echo "Running package tests..."
	@go test -v ./tests/unit/pkg/config ./tests/unit/pkg/alerts ./tests/unit/pkg/dashboard ./tests/unit/pkg/ebpf ./tests/unit/internal/models

# Run all tests including unit tests
test-all:
	@echo "Running all tests..."
	@go test -v ./tests/unit/...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./tests/unit/pkg/config ./tests/unit/pkg/alerts ./tests/unit/pkg/dashboard ./tests/unit/pkg/ebpf ./tests/unit/internal/models
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@go tool cover -func=coverage.out | tail -1

# Run tests with detailed coverage report
test-coverage-detail:
	@echo "Running tests with detailed coverage..."
	@go test -v -coverprofile=coverage.out ./tests/unit/pkg/config ./tests/unit/pkg/alerts ./tests/unit/pkg/dashboard ./tests/unit/pkg/ebpf ./tests/unit/internal/models
	@go tool cover -func=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Detailed coverage report generated: coverage.html"

# Run benchmark tests
bench:
	@echo "Running benchmark tests..."
	@go test -bench=. -benchmem ./tests/benchmarks/

# Run specific benchmark categories
bench-processor:
	@echo "Running processor benchmarks..."
	@go test -bench=BenchmarkProcessor -benchmem ./tests/benchmarks/

bench-threats:
	@echo "Running threat detection benchmarks..."
	@go test -bench=BenchmarkThreat -benchmem ./tests/benchmarks/

bench-ebpf:
	@echo "Running eBPF benchmarks..."
	@go test -bench=BenchmarkEBPF -benchmem ./tests/benchmarks/

bench-alerts:
	@echo "Running alert system benchmarks..."
	@go test -bench=BenchmarkAlert -benchmem ./tests/benchmarks/

bench-ml:
	@echo "Running ML detector benchmarks..."
	@go test -bench=BenchmarkML -benchmem ./tests/benchmarks/

# Run benchmarks and save results
bench-report:
	@echo "Running benchmarks and generating report..."
	@mkdir -p ./reports
	@go test -bench=. -benchmem ./tests/benchmarks/ | tee ./reports/benchmark-$(shell date +%Y%m%d-%H%M%S).txt
	@echo "Benchmark report saved to ./reports/"

# Run benchmarks multiple times for statistical analysis
bench-stats:
	@echo "Running benchmarks multiple times for statistical analysis..."
	@mkdir -p ./reports
	@go test -bench=. -benchmem -count=5 ./tests/benchmarks/ | tee ./reports/benchmark-stats-$(shell date +%Y%m%d-%H%M%S).txt

# Run performance comparison benchmarks
bench-compare:
	@echo "Running performance comparison benchmarks..."
	@go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./tests/benchmarks/
	@echo "CPU profile: cpu.prof, Memory profile: mem.prof"

# Install system-wide (requires root)
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin/"
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Creating systemd service..."
	@sudo cp ./configs/flowhawk.service /etc/systemd/system/
	@sudo systemctl daemon-reload

# Uninstall
uninstall:
	@echo "Removing $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@sudo systemctl stop flowhawk.service || true
	@sudo systemctl disable flowhawk.service || true
	@sudo rm -f /etc/systemd/system/flowhawk.service
	@sudo systemctl daemon-reload

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(EBPF_OBJECTS)
	@rm -f coverage.out coverage.html

# Development helpers
dev-setup:
	@echo "Setting up development environment..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/goreleaser/goreleaser@latest
	@./scripts/setup-git-hooks.sh

lint:
	@echo "Running linter..."
	@golangci-lint run

format:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

# Generate eBPF Go bindings
generate:
	@echo "Generating eBPF Go bindings..."
	@go generate ./...

# Docker build
docker-build:
	@echo "Building Docker image..."
	@docker build -t flowhawk:latest .

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build everything (deps + ebpf + go binary)"
	@echo "  deps         - Install dependencies"
	@echo "  ebpf         - Compile eBPF programs"
	@echo "  build        - Build Go binary"
	@echo "  run          - Run the monitor (requires root)"
	@echo "  run-config   - Run with config file"
	@echo "  test         - Run tests"
	@echo "  test-all     - Run all tests including unit tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  bench        - Run all benchmark tests"
	@echo "  bench-*      - Run specific benchmark categories"
	@echo "  bench-report - Run benchmarks and save timestamped report"
	@echo "  bench-stats  - Run benchmarks multiple times for statistics"
	@echo "  install      - Install system-wide"
	@echo "  clean        - Clean build artifacts"
	@echo "  dev-setup    - Set up development tools"
	@echo "  lint         - Run linter"
	@echo "  format       - Format code"
	@echo "  help         - Show this help"