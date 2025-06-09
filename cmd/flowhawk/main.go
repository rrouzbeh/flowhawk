package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"flowhawk/pkg/config"
	"flowhawk/pkg/ebpf"
	"flowhawk/pkg/processor"
	"flowhawk/pkg/dashboard"
)

const version = "0.1.0"

func main() {
	var (
		configPath = flag.String("config", "./configs/development.yaml", "Path to configuration file")
		showVersion = flag.Bool("version", false, "Show version information")
		iface      = flag.String("interface", "", "Network interface to monitor (overrides config)")
		help       = flag.Bool("help", false, "Show help information")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *showVersion {
		fmt.Printf("FlowHawk Network Security Monitor v%s\n", version)
		return
	}

	// Security mode determination and warnings
	isMockMode := os.Geteuid() != 0 || os.Getenv("SKIP_ROOT_CHECK") != ""
	
	if isMockMode {
		log.Println("🛡️  SECURITY: Starting in MOCK MODE for development safety")
		log.Println("📊 Data shown will be simulated/fake - no real network monitoring")
		log.Println("💡 To enable real eBPF monitoring, see documentation security warnings")
		log.Println(strings.Repeat("=", 70))
	} else {
		log.Println("⚠️  SECURITY WARNING: RUNNING IN PRODUCTION MODE")
		log.Println("🚨 This mode has significant security implications:")
		log.Println("   • Kernel-level access with potential for system crashes")
		log.Println("   • Full visibility into ALL network traffic (including sensitive data)")
		log.Println("   • Privileged container access (potential container escape)")
		log.Println("   • High resource consumption risk (memory/CPU exhaustion)")
		log.Println("📖 See documentation for security mitigations and best practices")
		log.Println("🔐 Ensure you understand the risks before proceeding")
		log.Println(strings.Repeat("=", 70))
	}

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Override interface if provided via command line
	if *iface != "" {
		cfg.EBPF.XDP.Interface = *iface
	}

	log.Printf("Starting FlowHawk Network Security Monitor v%s", version)
	log.Printf("Monitoring interface: %s", cfg.EBPF.XDP.Interface)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize eBPF manager
	ebpfManager, err := ebpf.NewManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize eBPF manager: %v", err)
	}
	defer ebpfManager.Close()

	// Initialize event processor
	eventProcessor, err := processor.New(cfg, ebpfManager)
	if err != nil {
		log.Fatalf("Failed to initialize event processor: %v", err)
	}
	defer eventProcessor.Close()

	// Initialize web dashboard
	dashboardServer, err := dashboard.New(cfg, eventProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize dashboard: %v", err)
	}

	// Start all components
	log.Println("Loading eBPF programs...")
	if err := ebpfManager.Load(); err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}

	log.Println("Starting event processor...")
	if err := eventProcessor.Start(ctx); err != nil {
		log.Fatalf("Failed to start event processor: %v", err)
	}

	log.Println("Starting web dashboard...")
	if err := dashboardServer.Start(ctx); err != nil {
		log.Fatalf("Failed to start dashboard: %v", err)
	}

	log.Printf("FlowHawk Network Security Monitor is running")
	log.Printf("Web dashboard available at http://localhost%s", cfg.Dashboard.ListenAddr)
	log.Println("Press Ctrl+C to stop...")

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down gracefully...")

	// Cancel context to signal all components to stop
	cancel()

	// Stop dashboard
	if err := dashboardServer.Stop(); err != nil {
		log.Printf("Error stopping dashboard: %v", err)
	}

	log.Println("Shutdown complete")
}

// loadConfig loads configuration from file or returns default config
func loadConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Config file %s not found, using defaults", path)
		return config.DefaultConfig(), nil
	}

	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
	}

	return cfg, nil
}

// showHelp displays usage information
func showHelp() {
	fmt.Printf(`FlowHawk - eBPF Network Security Monitor v%s

DESCRIPTION:
    Real-time network security monitoring using eBPF programs.
    Detects threats like port scans, DDoS attacks, and suspicious traffic patterns.

USAGE:
    %s [OPTIONS]

OPTIONS:
    -config string
        Path to configuration file (default: "./configs/development.yaml")
    
    -interface string
        Network interface to monitor (overrides config file setting)
    
    -version
        Show version information and exit
    
    -help
        Show this help message

EXAMPLES:
    # Run with default configuration
    sudo %s

    # Run with custom config file
    sudo %s -config /etc/flowhawk/config.yaml

    # Monitor specific interface
    sudo %s -interface eth1

    # Show version
    %s -version

REQUIREMENTS:
    - Root privileges (required for eBPF operations)
    - Linux kernel 4.15+ with eBPF support
    - Network interface with XDP support (for best performance)

CONFIGURATION:
    See configs/flowhawk.yaml for configuration options including:
    - Network interface settings
    - Threat detection parameters
    - Alert configuration
    - Dashboard settings

WEB DASHBOARD:
    Access the real-time dashboard at http://localhost:8080
    (port configurable in config file)

SIGNALS:
    SIGINT, SIGTERM - Graceful shutdown

For more information, visit: https://github.com/alexhraber/flowhawk
`, version, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}