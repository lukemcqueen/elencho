package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.TargetDir != "." {
		t.Errorf("expected TargetDir='.', got '%s'", cfg.TargetDir)
	}
	if cfg.OutputFormat != "text" {
		t.Errorf("expected OutputFormat='text', got '%s'", cfg.OutputFormat)
	}
	if !cfg.AutoUpdate {
		t.Error("AutoUpdate should default to true")
	}
	if cfg.ExcludePatterns == nil {
		t.Error("ExcludePatterns should not be nil")
	}
	if len(cfg.ExcludePatterns) != 0 {
		t.Errorf("expected empty ExcludePatterns, got %d items", len(cfg.ExcludePatterns))
	}
	if cfg.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("expected MaxFileSize=%d, got %d", DefaultMaxFileSize, cfg.MaxFileSize)
	}
	if cfg.DockerImage != "ubuntu:24.04" {
		t.Errorf("expected DockerImage='ubuntu:24.04', got '%s'", cfg.DockerImage)
	}
	if cfg.ConfidenceThreshold != 0.0 {
		t.Errorf("expected ConfidenceThreshold=0.0, got %.2f", cfg.ConfidenceThreshold)
	}
}

func TestDefaultConfigFlags(t *testing.T) {
	cfg := DefaultConfig()

	// Set various flags
	cfg.Verbose = true
	cfg.ListRules = true
	cfg.SelfScan = true
	cfg.StrictMode = true
	cfg.UpdateOnly = true
	cfg.VerifyRules = true
	cfg.DockerMode = true

	if !cfg.Verbose {
		t.Error("Verbose should be true")
	}
	if !cfg.ListRules {
		t.Error("ListRules should be true")
	}
	if !cfg.SelfScan {
		t.Error("SelfScan should be true")
	}
	if !cfg.StrictMode {
		t.Error("StrictMode should be true")
	}
	if !cfg.UpdateOnly {
		t.Error("UpdateOnly should be true")
	}
	if !cfg.VerifyRules {
		t.Error("VerifyRules should be true")
	}
	if !cfg.DockerMode {
		t.Error("DockerMode should be true")
	}
}

func TestUpdateBaseURL(t *testing.T) {
	if UpdateBaseURL == "" {
		t.Error("UpdateBaseURL should not be empty")
	}
	if len(AppName) == 0 {
		t.Error("AppName should not be empty")
	}
	if len(AppDescription) == 0 {
		t.Error("AppDescription should not be empty")
	}
}

func TestDefaultMaxFileSize(t *testing.T) {
	if DefaultMaxFileSize <= 0 {
		t.Error("DefaultMaxFileSize should be positive")
	}
	if DefaultMaxFileSize != 10*1024*1024 {
		t.Errorf("expected 10MB, got %d", DefaultMaxFileSize)
	}
}
