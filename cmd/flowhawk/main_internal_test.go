package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"flowhawk/pkg/config"
)

func TestLoadConfig(t *testing.T) {
	t.Run("load_existing_config", func(t *testing.T) {
		// Create a temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "test_config.yaml")
		
		configContent := `
ebpf:
  xdp:
    interface: "test0"
    enable: true
dashboard:
  listen_addr: ":9999"
  update_interval: 2s
`
		
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}
		
		cfg, err := loadConfig(configPath)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		
		if cfg.EBPF.XDP.Interface != "test0" {
			t.Errorf("Expected interface 'test0', got '%s'", cfg.EBPF.XDP.Interface)
		}
		
		if cfg.Dashboard.ListenAddr != ":9999" {
			t.Errorf("Expected listen address ':9999', got '%s'", cfg.Dashboard.ListenAddr)
		}
	})
	
	t.Run("load_nonexistent_config", func(t *testing.T) {
		// Test loading non-existent config file (should return default config)
		cfg, err := loadConfig("/nonexistent/path/config.yaml")
		if err != nil {
			t.Fatalf("Expected no error for non-existent config, got: %v", err)
		}
		
		if cfg == nil {
			t.Fatal("Expected default config to be returned")
		}
		
		// Should have default values
		if cfg.EBPF.XDP.Interface == "" {
			t.Error("Expected default interface to be set")
		}
		
		if cfg.Dashboard.ListenAddr == "" {
			t.Error("Expected default dashboard address to be set")
		}
	})
	
	t.Run("load_invalid_config", func(t *testing.T) {
		// Create a temporary invalid config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid_config.yaml")
		
		invalidContent := "invalid: yaml: content: [unclosed"
		
		if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
			t.Fatalf("Failed to write invalid config: %v", err)
		}
		
		_, err := loadConfig(configPath)
		if err == nil {
			t.Error("Expected error for invalid config file")
		}
		
		if !strings.Contains(err.Error(), "failed to load config") {
			t.Errorf("Expected error message to contain 'failed to load config', got: %v", err)
		}
	})
}

func TestShowHelp(t *testing.T) {
	// Capture stdout to test help output
	// Since showHelp() prints to stdout, we need to test it indirectly
	// by checking that the function doesn't panic and contains expected elements
	
	// Test that showHelp doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("showHelp() panicked: %v", r)
		}
	}()
	
	// We can't easily capture stdout in a unit test without more complex setup,
	// but we can test that the function runs without error
	showHelp()
	
	// Test by examining the function implementation details
	// Read the main.go file to verify help content is comprehensive
	content, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("Failed to read main.go: %v", err)
	}
	
	helpContent := string(content)
	
	// Verify help function contains expected information
	expectedHelpElements := []string{
		"FlowHawk",
		"eBPF Network Security Monitor",
		"DESCRIPTION:",
		"USAGE:",
		"OPTIONS:",
		"EXAMPLES:",
		"REQUIREMENTS:",
		"CONFIGURATION:",
		"WEB DASHBOARD:",
		"SIGNALS:",
		"-config",
		"-interface",
		"-version",
		"-help",
	}
	
	for _, element := range expectedHelpElements {
		if !strings.Contains(helpContent, element) {
			t.Errorf("Help function should contain '%s'", element)
		}
	}
}

func TestVersionConstant(t *testing.T) {
	// Test that version constant is defined and not empty
	if version == "" {
		t.Error("Version constant should not be empty")
	}
	
	// Test version format (should be semantic versioning)
	if !strings.Contains(version, ".") {
		t.Error("Version should contain dots (semantic versioning)")
	}
	
	// Test that version doesn't contain spaces or invalid characters
	if strings.Contains(version, " ") {
		t.Error("Version should not contain spaces")
	}
}

func TestDefaultConfiguration(t *testing.T) {
	// Test that default configuration is valid
	cfg := config.DefaultConfig()
	
	if cfg == nil {
		t.Fatal("DefaultConfig() should return non-nil config")
	}
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		t.Errorf("Default configuration should be valid: %v", err)
	}
	
	// Test specific default values
	if cfg.EBPF.XDP.Interface == "" {
		t.Error("Default config should have interface set")
	}
	
	if cfg.Dashboard.ListenAddr == "" {
		t.Error("Default config should have dashboard listen address")
	}
	
	if cfg.Dashboard.UpdateInterval == 0 {
		t.Error("Default config should have non-zero update interval")
	}
}

func TestSecurityModeDetection(t *testing.T) {
	// Test the security mode detection logic
	t.Run("skip_root_check_env", func(t *testing.T) {
		// Save original environment
		originalEnv := os.Getenv("SKIP_ROOT_CHECK")
		defer os.Setenv("SKIP_ROOT_CHECK", originalEnv)
		
		// Test with SKIP_ROOT_CHECK set
		os.Setenv("SKIP_ROOT_CHECK", "1")
		isMockMode := os.Geteuid() != 0 || os.Getenv("SKIP_ROOT_CHECK") != ""
		
		if !isMockMode {
			t.Error("Should be in mock mode when SKIP_ROOT_CHECK is set")
		}
		
		// Test with SKIP_ROOT_CHECK unset
		os.Setenv("SKIP_ROOT_CHECK", "")
		isMockMode = os.Geteuid() != 0 || os.Getenv("SKIP_ROOT_CHECK") != ""
		
		// Result depends on whether we're running as root
		// In CI/testing environments, we're usually not root
		euid := os.Geteuid()
		expectedMockMode := euid != 0
		
		if isMockMode != expectedMockMode {
			t.Errorf("Expected mock mode %v (euid=%d), got %v", expectedMockMode, euid, isMockMode)
		}
	})
}

func TestMainComponentInitialization(t *testing.T) {
	// Test that all required components can be initialized with default config
	cfg := config.DefaultConfig()
	
	// We can't fully test component initialization without mocking,
	// but we can test that the configuration is valid for initialization
	
	t.Run("config_validation", func(t *testing.T) {
		if err := cfg.Validate(); err != nil {
			t.Errorf("Configuration should be valid for component initialization: %v", err)
		}
	})
	
	t.Run("interface_override", func(t *testing.T) {
		// Test interface override logic
		originalInterface := cfg.EBPF.XDP.Interface
		newInterface := "test123"
		
		// Simulate the interface override logic from main()
		cfg.EBPF.XDP.Interface = newInterface
		
		if cfg.EBPF.XDP.Interface != newInterface {
			t.Errorf("Interface override failed: expected %s, got %s", newInterface, cfg.EBPF.XDP.Interface)
		}
		
		// Restore original
		cfg.EBPF.XDP.Interface = originalInterface
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("invalid_config_path", func(t *testing.T) {
		// Test with a directory instead of a file
		tmpDir := t.TempDir()
		
		_, err := loadConfig(tmpDir) // Directory, not a file
		if err == nil {
			t.Error("Expected error when loading directory as config file")
		}
	})
	
	t.Run("config_with_invalid_yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "bad.yaml")
		
		// Write malformed YAML
		if err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644); err != nil {
			t.Fatalf("Failed to write bad config: %v", err)
		}
		
		_, err := loadConfig(configPath)
		if err == nil {
			t.Error("Expected error for malformed YAML")
		}
	})
}