// Package ui tests for the AIP Human-in-the-Loop prompt system.
package ui

import (
	"context"
	"testing"
	"time"
)

// TestNewPrompterDefaults tests that NewPrompter uses default values correctly.
func TestNewPrompterDefaults(t *testing.T) {
	p := NewPrompter(nil)

	if p.cfg.Timeout != DefaultTimeout {
		t.Errorf("Default timeout = %v, want %v", p.cfg.Timeout, DefaultTimeout)
	}
	if p.cfg.Title != "AIP Security Alert" {
		t.Errorf("Default title = %q, want %q", p.cfg.Title, "AIP Security Alert")
	}
}

// TestNewPrompterCustomConfig tests that NewPrompter respects custom config.
func TestNewPrompterCustomConfig(t *testing.T) {
	cfg := &PrompterConfig{
		Timeout: 30 * time.Second,
		Title:   "Custom Title",
	}
	p := NewPrompter(cfg)

	if p.cfg.Timeout != 30*time.Second {
		t.Errorf("Custom timeout = %v, want %v", p.cfg.Timeout, 30*time.Second)
	}
	if p.cfg.Title != "Custom Title" {
		t.Errorf("Custom title = %q, want %q", p.cfg.Title, "Custom Title")
	}
}

// TestBuildMessage tests that the dialog message is formatted correctly.
func TestBuildMessage(t *testing.T) {
	p := NewPrompter(nil)

	tests := []struct {
		name     string
		tool     string
		args     map[string]any
		contains []string
	}{
		{
			name:     "Basic tool without args",
			tool:     "test_tool",
			args:     nil,
			contains: []string{"test_tool", "{}", "allow this action"},
		},
		{
			name:     "Tool with simple args",
			tool:     "fetch_url",
			args:     map[string]any{"url": "https://example.com"},
			contains: []string{"fetch_url", "url", "https://example.com"},
		},
		{
			name:     "Tool with multiple args",
			tool:     "run_query",
			args:     map[string]any{"database": "prod", "query": "SELECT *"},
			contains: []string{"run_query", "database", "prod", "query", "SELECT *"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := p.buildMessage(tt.tool, tt.args)

			for _, substr := range tt.contains {
				if !containsString(msg, substr) {
					t.Errorf("Message missing %q:\n%s", substr, msg)
				}
			}
		})
	}
}

// TestAskUserContextCancellation tests that context cancellation returns false.
func TestAskUserContextCancellation(t *testing.T) {
	p := NewPrompter(&PrompterConfig{
		Timeout: 10 * time.Second, // Long timeout to ensure context cancels first
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// Should return false immediately due to cancelled context
	start := time.Now()
	result := p.AskUserContext(ctx, "test_tool", nil)
	elapsed := time.Since(start)

	if result {
		t.Error("Expected false when context is cancelled")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Should return immediately on cancelled context, took %v", elapsed)
	}
}

// TestAskUserContextTimeout tests that timeout returns false.
func TestAskUserContextTimeout(t *testing.T) {
	p := NewPrompter(&PrompterConfig{
		Timeout: 100 * time.Millisecond, // Very short timeout
	})

	// In headless test environment, dialog will fail, so this tests
	// that the timeout mechanism works correctly
	start := time.Now()
	result := p.AskUserContext(context.Background(), "test_tool", nil)
	elapsed := time.Since(start)

	// Should return false (either from dialog failure or timeout)
	if result {
		t.Error("Expected false in headless test environment")
	}

	// Should complete within reasonable time (timeout + buffer)
	if elapsed > 2*time.Second {
		t.Errorf("Took too long: %v (expected < 2s)", elapsed)
	}
}

// TestIsHeadless tests headless environment detection.
func TestIsHeadless(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Actual result depends on environment
	_ = IsHeadless()
}

// containsString checks if str contains substr.
func containsString(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(substr) == 0 ||
		(len(str) > 0 && containsSubstring(str, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
