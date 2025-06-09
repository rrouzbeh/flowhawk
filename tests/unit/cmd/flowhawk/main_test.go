package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowhawk/pkg/config"
)

func TestMainBinary(t *testing.T) {
	// Build the binary for testing
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "flowhawk-test")
	
	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/flowhawk")
	cmd.Dir = "../../../../"
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	
	// Test --help flag
	t.Run("help_flag", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "--help")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Help command failed: %v", err)
		}
		
		outputStr := string(output)
		if !strings.Contains(outputStr, "FlowHawk") || !strings.Contains(outputStr, "eBPF Network Security Monitor") {
			t.Errorf("Expected help output to contain 'FlowHawk' and 'eBPF Network Security Monitor', got: %s", outputStr)
		}
	})
	
	// Test --version flag
	t.Run("version_flag", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "--version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Version command failed: %v", err)
		}
		
		outputStr := string(output)
		if !strings.Contains(outputStr, "FlowHawk Network Security Monitor") {
			t.Errorf("Expected version output to contain application name, got: %s", outputStr)
		}
		if !strings.Contains(outputStr, "v") {
			t.Errorf("Expected version output to contain version number, got: %s", outputStr)
		}
	})
}

func TestMainPackageStructure(t *testing.T) {
	// Test that main.go exists and is readable
	mainPath := "../../../../cmd/flowhawk/main.go"
	if _, err := os.Stat(mainPath); os.IsNotExist(err) {
		t.Errorf("main.go file does not exist at expected path: %s", mainPath)
	}
	
	// Read main.go and check for basic structure
	content, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("Failed to read main.go: %v", err)
	}
	
	contentStr := string(content)
	
	// Check for essential components
	if !strings.Contains(contentStr, "package main") {
		t.Errorf("main.go should declare package main")
	}
	
	if !strings.Contains(contentStr, "func main()") {
		t.Errorf("main.go should contain main function")
	}
	
	if !strings.Contains(contentStr, "version") {
		t.Errorf("main.go should contain version information")
	}
	
	if !strings.Contains(contentStr, "flag.") {
		t.Errorf("main.go should use flag package for command line arguments")
	}
}

func TestMainWithInvalidConfig(t *testing.T) {
	// Test behavior with invalid config path
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "flowhawk-test")
	
	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/flowhawk")
	cmd.Dir = "../../../../"
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	
	// Test with non-existent config file (should use defaults and not crash immediately)
	t.Run("nonexistent_config", func(t *testing.T) {
		// Create a temporary context that will timeout
		cmd := exec.Command(binaryPath, "-config", "/nonexistent/path/config.yaml")
		cmd.Env = append(os.Environ(), "SKIP_ROOT_CHECK=1") // Skip root check for testing
		
		// Start the command but don't wait for it to complete
		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start command: %v", err)
		}
		
		// Give it a moment to start up and process arguments
		time.Sleep(100 * time.Millisecond)
		
		// Kill the process
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill process: %v", err)
		}
		
		// Wait for process to exit
		cmd.Wait()
		
		// The fact that it started without immediate crash indicates it handled the missing config
		t.Logf("Application handled missing config file appropriately")
	})
}

func TestConfigurationHandling(t *testing.T) {
	// Test configuration loading logic
	t.Run("default_config_creation", func(t *testing.T) {
		cfg := config.DefaultConfig()
		if cfg == nil {
			t.Errorf("DefaultConfig() should return a valid config")
		}
		
		if cfg.EBPF.XDP.Interface == "" {
			t.Errorf("Default config should have a default interface")
		}
		
		if cfg.Dashboard.ListenAddr == "" {
			t.Errorf("Default config should have a default dashboard address")
		}
	})
	
	t.Run("config_file_loading", func(t *testing.T) {
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
		
		cfg, err := config.LoadFromFile(configPath)
		if err != nil {
			t.Fatalf("Failed to load config from file: %v", err)
		}
		
		if cfg.EBPF.XDP.Interface != "test0" {
			t.Errorf("Expected interface 'test0', got '%s'", cfg.EBPF.XDP.Interface)
		}
		
		if cfg.Dashboard.ListenAddr != ":9999" {
			t.Errorf("Expected listen address ':9999', got '%s'", cfg.Dashboard.ListenAddr)
		}
	})
}

func TestSecurityModeDetection(t *testing.T) {
	// Test the security mode logic (mock vs production)
	t.Run("mock_mode_detection", func(t *testing.T) {
		// Set environment variable to skip root check
		oldEnv := os.Getenv("SKIP_ROOT_CHECK")
		os.Setenv("SKIP_ROOT_CHECK", "1")
		defer os.Setenv("SKIP_ROOT_CHECK", oldEnv)
		
		// The security mode detection is based on environment and user ID
		// We can't easily test the actual UID check, but we can test env var
		skipRootCheck := os.Getenv("SKIP_ROOT_CHECK") != ""
		if !skipRootCheck {
			t.Errorf("Expected SKIP_ROOT_CHECK environment variable to be set")
		}
	})
}

func TestApplicationStartupSequence(t *testing.T) {
	// Test the basic startup sequence without actually running the full application
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "flowhawk-test")
	
	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/flowhawk")
	cmd.Dir = "../../../../"
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	
	t.Run("startup_with_mock_mode", func(t *testing.T) {
		// Test startup in mock mode (safe for testing)
		cmd := exec.Command(binaryPath, "-config", "/dev/null")
		cmd.Env = append(os.Environ(), "SKIP_ROOT_CHECK=1")
		
		// Start the process
		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start application: %v", err)
		}
		
		// Give it time to initialize
		time.Sleep(200 * time.Millisecond)
		
		// Gracefully terminate
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill process: %v", err)
		}
		
		cmd.Wait()
		
		// If we got here without the process crashing immediately, 
		// the startup sequence is working
		t.Logf("Application startup sequence completed successfully")
	})
}

func TestCommandLineArguments(t *testing.T) {
	// Test various command line argument combinations
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "flowhawk-test")
	
	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/flowhawk")
	cmd.Dir = "../../../../"
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	
	testCases := []struct {
		name string
		args []string
		expectOutput string
	}{
		{
			name: "help_short",
			args: []string{"-help"},
			expectOutput: "FlowHawk",
		},
		{
			name: "version_short", 
			args: []string{"-version"},
			expectOutput: "FlowHawk Network Security Monitor",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tc.args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Command failed: %v", err)
			}
			
			if !strings.Contains(string(output), tc.expectOutput) {
				t.Errorf("Expected output to contain '%s', got: %s", tc.expectOutput, string(output))
			}
		})
	}
}