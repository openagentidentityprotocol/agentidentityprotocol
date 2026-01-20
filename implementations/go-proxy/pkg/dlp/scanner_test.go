package dlp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/pkg/policy"
)

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *policy.DLPConfig
		wantNil bool
		wantErr bool
	}{
		{
			name:    "nil config returns nil scanner",
			cfg:     nil,
			wantNil: true,
			wantErr: false,
		},
		{
			name: "disabled config returns nil scanner",
			cfg: &policy.DLPConfig{
				Enabled:  boolPtr(false),
				Patterns: []policy.DLPPattern{{Name: "Test", Regex: "test"}},
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid patterns compile successfully",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
					{Name: "Secret", Regex: `(?i)secret`},
				},
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "invalid regex returns error",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "Bad", Regex: `[invalid`},
				},
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "pattern missing name returns error",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "", Regex: `test`},
				},
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "pattern missing regex returns error",
			cfg: &policy.DLPConfig{
				Patterns: []policy.DLPPattern{
					{Name: "Test", Regex: ""},
				},
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.cfg)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil && scanner != nil {
				t.Fatal("expected nil scanner")
			}
			if !tt.wantNil && !tt.wantErr && scanner == nil {
				t.Fatal("expected non-nil scanner")
			}
		})
	}
}

func TestScanner_Redact(t *testing.T) {
	// Set up scanner with common patterns
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
			{Name: "Generic Secret", Regex: `(?i)(api_key|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9-_]+)['"]?`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name       string
		input      string
		wantOutput string
		wantRules  []string
	}{
		{
			name:       "no sensitive data",
			input:      "Hello, this is a normal message",
			wantOutput: "Hello, this is a normal message",
			wantRules:  nil,
		},
		{
			name:       "email redaction",
			input:      "Contact me at user@example.com",
			wantOutput: "Contact me at [REDACTED:Email]",
			wantRules:  []string{"Email"},
		},
		{
			name:       "multiple emails",
			input:      "Email alice@test.org or bob@company.com",
			wantOutput: "Email [REDACTED:Email] or [REDACTED:Email]",
			wantRules:  []string{"Email"},
		},
		{
			name:       "AWS key redaction",
			input:      "The key is AKIAIOSFODNN7EXAMPLE",
			wantOutput: "The key is [REDACTED:AWS Key]",
			wantRules:  []string{"AWS Key"},
		},
		{
			name:       "generic secret redaction",
			input:      `api_key: "my-secret-key-123"`,
			wantOutput: `[REDACTED:Generic Secret]`,
			wantRules:  []string{"Generic Secret"},
		},
		{
			name:       "password redaction",
			input:      "password = supersecret123",
			wantOutput: "[REDACTED:Generic Secret]",
			wantRules:  []string{"Generic Secret"},
		},
		{
			name:       "multiple pattern types",
			input:      "Contact user@test.com with key AKIAIOSFODNN7EXAMPLE",
			wantOutput: "Contact [REDACTED:Email] with key [REDACTED:AWS Key]",
			wantRules:  []string{"Email", "AWS Key"},
		},
		{
			name:       "case insensitive secret",
			input:      "SECRET: myvalue",
			wantOutput: "[REDACTED:Generic Secret]",
			wantRules:  []string{"Generic Secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, events := scanner.Redact(tt.input)

			if output != tt.wantOutput {
				t.Errorf("Redact() output = %q, want %q", output, tt.wantOutput)
			}

			if len(events) != len(tt.wantRules) {
				t.Errorf("Redact() events count = %d, want %d", len(events), len(tt.wantRules))
			}

			for i, wantRule := range tt.wantRules {
				if i < len(events) && events[i].RuleName != wantRule {
					t.Errorf("Redact() events[%d].RuleName = %q, want %q", i, events[i].RuleName, wantRule)
				}
			}
		})
	}
}

func TestScanner_Redact_NilScanner(t *testing.T) {
	var scanner *Scanner
	input := "sensitive@email.com"

	output, events := scanner.Redact(input)

	if output != input {
		t.Errorf("nil scanner should return input unchanged, got %q", output)
	}
	if events != nil {
		t.Error("nil scanner should return nil events")
	}
}

func TestScanner_RedactJSON(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		},
	}
	scanner, _ := NewScanner(cfg)

	input := []byte(`{"text": "Contact user@example.com"}`)
	output, events := scanner.RedactJSON(input)

	expected := `{"text": "Contact [REDACTED:Email]"}`
	if string(output) != expected {
		t.Errorf("RedactJSON() = %s, want %s", output, expected)
	}
	if len(events) != 1 || events[0].RuleName != "Email" {
		t.Errorf("RedactJSON() events = %v, want [{Email, 1}]", events)
	}
}

func TestScanner_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		scanner *Scanner
		want    bool
	}{
		{
			name:    "nil scanner",
			scanner: nil,
			want:    false,
		},
		{
			name:    "empty patterns",
			scanner: &Scanner{enabled: true, patterns: nil},
			want:    false,
		},
		{
			name: "enabled with patterns",
			scanner: &Scanner{
				enabled:  true,
				patterns: []compiledPattern{{name: "Test"}},
			},
			want: true,
		},
		{
			name: "disabled with patterns",
			scanner: &Scanner{
				enabled:  false,
				patterns: []compiledPattern{{name: "Test"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scanner.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanner_PatternCount(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "P1", Regex: "a"},
			{Name: "P2", Regex: "b"},
			{Name: "P3", Regex: "c"},
		},
	}
	scanner, _ := NewScanner(cfg)

	if scanner.PatternCount() != 3 {
		t.Errorf("PatternCount() = %d, want 3", scanner.PatternCount())
	}

	var nilScanner *Scanner
	if nilScanner.PatternCount() != 0 {
		t.Error("nil scanner should have PatternCount() = 0")
	}
}

func TestScanner_PatternNames(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: "a"},
			{Name: "AWS Key", Regex: "b"},
		},
	}
	scanner, _ := NewScanner(cfg)

	names := scanner.PatternNames()
	if len(names) != 2 {
		t.Fatalf("PatternNames() len = %d, want 2", len(names))
	}
	if names[0] != "Email" || names[1] != "AWS Key" {
		t.Errorf("PatternNames() = %v, want [Email, AWS Key]", names)
	}
}

// Test case from the spec
func TestScanner_TestCase_FromSpec(t *testing.T) {
	// Configure DLP rule: regex: "SECRET"
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Generic Secret", Regex: "SECRET"},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Mock Tool Output content text
	input := "This is a SECRET code"
	expected := "This is a [REDACTED:Generic Secret] code"

	output, events := scanner.Redact(input)

	if output != expected {
		t.Errorf("Redact() = %q, want %q", output, expected)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].RuleName != "Generic Secret" {
		t.Errorf("event.RuleName = %q, want %q", events[0].RuleName, "Generic Secret")
	}
	if events[0].MatchCount != 1 {
		t.Errorf("event.MatchCount = %d, want 1", events[0].MatchCount)
	}
}

// boolPtr is a helper to create *bool values
func boolPtr(b bool) *bool {
	return &b
}

// -----------------------------------------------------------------------------
// Deep/Recursive Scanning Tests
// -----------------------------------------------------------------------------

// TestRedactDeep_NestedMaps tests that secrets in nested map structures are found.
// This is the key security test - prevents the bypass attack via nested args.
func TestRedactDeep_NestedMaps(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `AKIA[A-Z0-9]{16}`},
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name      string
		input     any
		wantRules []string
		checkFunc func(t *testing.T, result any)
	}{
		{
			name: "single level map with secret",
			input: map[string]any{
				"key": "AKIAIOSFODNN7EXAMPLE",
			},
			wantRules: []string{"AWS Key"},
			checkFunc: func(t *testing.T, result any) {
				m := result.(map[string]any)
				if m["key"] != "[REDACTED:AWS Key]" {
					t.Errorf("expected redacted key, got %v", m["key"])
				}
			},
		},
		{
			name: "two levels deep - THE BYPASS ATTACK",
			input: map[string]any{
				"config": map[string]any{
					"aws": map[string]any{
						"access_key": "AKIAIOSFODNN7EXAMPLE",
					},
				},
			},
			wantRules: []string{"AWS Key"},
			checkFunc: func(t *testing.T, result any) {
				m := result.(map[string]any)
				config := m["config"].(map[string]any)
				aws := config["aws"].(map[string]any)
				if aws["access_key"] != "[REDACTED:AWS Key]" {
					t.Errorf("nested secret not redacted: %v", aws["access_key"])
				}
			},
		},
		{
			name: "three levels deep",
			input: map[string]any{
				"level1": map[string]any{
					"level2": map[string]any{
						"level3": map[string]any{
							"secret": "AKIAIOSFODNN7EXAMPLE",
						},
					},
				},
			},
			wantRules: []string{"AWS Key"},
			checkFunc: func(t *testing.T, result any) {
				m := result.(map[string]any)
				l1 := m["level1"].(map[string]any)
				l2 := l1["level2"].(map[string]any)
				l3 := l2["level3"].(map[string]any)
				if l3["secret"] != "[REDACTED:AWS Key]" {
					t.Errorf("deep nested secret not redacted: %v", l3["secret"])
				}
			},
		},
		{
			name: "multiple secrets at different levels",
			input: map[string]any{
				"email": "user@example.com",
				"nested": map[string]any{
					"aws_key": "AKIAIOSFODNN7EXAMPLE",
				},
			},
			wantRules: []string{"Email", "AWS Key"},
			checkFunc: func(t *testing.T, result any) {
				m := result.(map[string]any)
				if m["email"] != "[REDACTED:Email]" {
					t.Errorf("top-level email not redacted")
				}
				nested := m["nested"].(map[string]any)
				if nested["aws_key"] != "[REDACTED:AWS Key]" {
					t.Errorf("nested aws_key not redacted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, events := scanner.RedactDeep(tt.input)

			// Check events
			if len(events) != len(tt.wantRules) {
				t.Errorf("expected %d events, got %d: %v", len(tt.wantRules), len(events), events)
			}

			// Check result
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

// TestRedactDeep_Arrays tests that secrets in arrays are found.
func TestRedactDeep_Arrays(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name      string
		input     any
		wantCount int
	}{
		{
			name: "array of strings with secrets",
			input: map[string]any{
				"emails": []any{
					"user1@example.com",
					"user2@example.com",
					"not-an-email",
				},
			},
			wantCount: 2,
		},
		{
			name: "array of objects with secrets",
			input: map[string]any{
				"users": []any{
					map[string]any{"email": "alice@test.org"},
					map[string]any{"email": "bob@test.org"},
					map[string]any{"name": "charlie"},
				},
			},
			wantCount: 2,
		},
		{
			name: "nested arrays",
			input: map[string]any{
				"data": []any{
					[]any{
						"nested@email.com",
					},
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, events := scanner.RedactDeep(tt.input)

			totalMatches := 0
			for _, e := range events {
				totalMatches += e.MatchCount
			}

			if totalMatches != tt.wantCount {
				t.Errorf("expected %d matches, got %d: %v", tt.wantCount, totalMatches, events)
			}
		})
	}
}

// TestRedactDeep_Primitives tests that non-string primitives pass through unchanged.
func TestRedactDeep_Primitives(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `AKIA[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	input := map[string]any{
		"string":  "no sensitive data here",
		"int":     42,
		"float":   3.14,
		"bool":    true,
		"null":    nil,
		"int64":   int64(100),
		"float32": float32(1.5),
	}

	result, events := scanner.RedactDeep(input)

	// No events expected (no AWS keys in primitives)
	if len(events) != 0 {
		t.Errorf("expected no events for clean primitives, got %v", events)
	}

	// Verify primitives unchanged
	m := result.(map[string]any)
	if m["int"] != 42 {
		t.Errorf("int changed: %v", m["int"])
	}
	if m["float"] != 3.14 {
		t.Errorf("float changed: %v", m["float"])
	}
	if m["bool"] != true {
		t.Errorf("bool changed: %v", m["bool"])
	}
	if m["string"] != "no sensitive data here" {
		t.Errorf("clean string was modified: %v", m["string"])
	}
}

// TestRedactDeep_NilScanner tests that nil scanner returns input unchanged.
func TestRedactDeep_NilScanner(t *testing.T) {
	var scanner *Scanner

	input := map[string]any{
		"secret": "AKIAIOSFODNN7EXAMPLE",
	}

	result, events := scanner.RedactDeep(input)

	// Should return original (check by comparing the secret value)
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("nil scanner should return map")
	}
	if resultMap["secret"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Error("nil scanner should return input unchanged")
	}
	if events != nil {
		t.Error("nil scanner should return nil events")
	}
}

// TestRedactDeep_OriginalUnchanged verifies that the original input is not modified.
func TestRedactDeep_OriginalUnchanged(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `AKIA[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	original := map[string]any{
		"nested": map[string]any{
			"key": "AKIAIOSFODNN7EXAMPLE",
		},
	}

	// Store original value
	originalKey := original["nested"].(map[string]any)["key"]

	// Redact
	result, _ := scanner.RedactDeep(original)

	// Verify original unchanged
	if original["nested"].(map[string]any)["key"] != originalKey {
		t.Error("original map was modified!")
	}

	// Verify result is redacted
	resultNested := result.(map[string]any)["nested"].(map[string]any)
	if resultNested["key"] == originalKey {
		t.Error("result should be redacted")
	}
}

// TestRedactMap_Convenience tests the RedactMap convenience method.
func TestRedactMap_Convenience(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	input := map[string]any{
		"contact": map[string]any{
			"email": "test@example.com",
		},
	}

	result, events := scanner.RedactMap(input)

	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}

	contact := result["contact"].(map[string]any)
	if contact["email"] != "[REDACTED:Email]" {
		t.Errorf("email not redacted: %v", contact["email"])
	}
}

// TestRedactDeep_SecurityBypassPrevention is the key security test.
// It simulates the exact attack vector from the security review.
func TestRedactDeep_SecurityBypassPrevention(t *testing.T) {
	// This is the exact attack scenario:
	// Attacker hides AWS key in nested structure to bypass shallow DLP
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Attack payload - secret hidden in nested structure
	attackPayload := map[string]any{
		"url": "https://allowed-domain.com/api",
		"body": map[string]any{
			"data": []any{
				map[string]any{
					"secret": "AKIAIOSFODNN7EXAMPLE",
				},
			},
		},
	}

	result, events := scanner.RedactDeep(attackPayload)

	// CRITICAL: The secret MUST be detected
	if len(events) == 0 {
		t.Fatal("SECURITY FAILURE: Nested secret was not detected!")
	}

	// Verify the secret is redacted in the result
	body := result.(map[string]any)["body"].(map[string]any)
	data := body["data"].([]any)
	item := data[0].(map[string]any)

	if item["secret"] == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatal("SECURITY FAILURE: Secret was not redacted in output!")
	}

	if item["secret"] != "[REDACTED:AWS Key]" {
		t.Errorf("unexpected redaction format: %v", item["secret"])
	}
}

// -----------------------------------------------------------------------------
// Encoding Detection Tests
// -----------------------------------------------------------------------------

// TestEncodingDetection_Base64 tests detection of base64 encoded secrets.
func TestEncodingDetection_Base64(t *testing.T) {
	// AWS Key: AKIAIOSFODNN7EXAMPLE
	// Base64:  QUtJQUlPU0ZPRE5ON0VYQU1QTEU=
	cfg := &policy.DLPConfig{
		DetectEncoding: true,
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name           string
		input          string
		wantRedacted   bool
		wantEventCount int
	}{
		{
			name:           "plain secret detected",
			input:          "Key: AKIAIOSFODNN7EXAMPLE",
			wantRedacted:   true,
			wantEventCount: 1,
		},
		{
			name:           "base64 encoded secret detected",
			input:          "Encoded: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=",
			wantRedacted:   true,
			wantEventCount: 1,
		},
		{
			name:           "no false positive on random base64",
			input:          "Random: SGVsbG8gV29ybGQh", // "Hello World!"
			wantRedacted:   false,
			wantEventCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, events := scanner.Redact(tt.input)

			if tt.wantRedacted && output == tt.input {
				t.Error("expected redaction but got unchanged output")
			}
			if !tt.wantRedacted && output != tt.input {
				t.Errorf("unexpected redaction: %s", output)
			}
			if len(events) != tt.wantEventCount {
				t.Errorf("event count = %d, want %d", len(events), tt.wantEventCount)
			}
		})
	}
}

// TestEncodingDetection_Hex tests detection of hex encoded secrets.
func TestEncodingDetection_Hex(t *testing.T) {
	// AWS Key: AKIAIOSFODNN7EXAMPLE
	// Hex:     414b4941494f53464f444e4e374558414d504c45
	cfg := &policy.DLPConfig{
		DetectEncoding: true,
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name           string
		input          string
		wantRedacted   bool
		wantEventCount int
	}{
		{
			name:           "hex encoded secret detected",
			input:          "Hex key: 414b4941494f53464f444e4e374558414d504c45",
			wantRedacted:   true,
			wantEventCount: 1,
		},
		{
			name:           "hex with 0x prefix detected",
			input:          "Key: 0x414b4941494f53464f444e4e374558414d504c45",
			wantRedacted:   true,
			wantEventCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, events := scanner.Redact(tt.input)

			if tt.wantRedacted && output == tt.input {
				t.Error("expected redaction but got unchanged output")
			}
			if len(events) != tt.wantEventCount {
				t.Errorf("event count = %d, want %d", len(events), tt.wantEventCount)
			}
		})
	}
}

// TestEncodingDetection_Disabled tests that encoding detection is off by default.
func TestEncodingDetection_Disabled(t *testing.T) {
	// AWS Key: AKIAIOSFODNN7EXAMPLE  →  Base64: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=
	cfg := &policy.DLPConfig{
		DetectEncoding: false, // Explicitly disabled (also default)
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Encoded secret should NOT be detected when encoding detection is disabled
	input := "Encoded: QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	output, events := scanner.Redact(input)

	if output != input {
		t.Errorf("encoding detection should be disabled, but got redaction: %s", output)
	}
	if len(events) != 0 {
		t.Errorf("expected no events, got %d", len(events))
	}
}

// TestEncodingDetection_SecurityBypass is the key security test.
// Simulates the exact attack from the security review.
func TestEncodingDetection_SecurityBypass(t *testing.T) {
	cfg := &policy.DLPConfig{
		DetectEncoding: true,
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
			{Name: "Password", Regex: `(?i)password\s*[:=]\s*\S+`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Attack scenario: Agent encodes secret to bypass DLP
	// Original: {"secret": "AKIAIOSFODNN7EXAMPLE"}
	// Encoded:  {"secret": "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="}
	attackPayload := `{"secret": "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="}`

	output, events := scanner.Redact(attackPayload)

	// CRITICAL: The encoded secret MUST be detected
	if len(events) == 0 {
		t.Fatal("SECURITY FAILURE: Base64-encoded secret was not detected!")
	}

	// Verify original encoded string is replaced
	if output == attackPayload {
		t.Fatal("SECURITY FAILURE: Output unchanged - encoded secret passed through!")
	}

	// Verify it mentions encoding
	foundEncoded := false
	for _, e := range events {
		if e.RuleName == "AWS Key (encoded)" {
			foundEncoded = true
			break
		}
	}
	if !foundEncoded {
		t.Errorf("expected event with '(encoded)' suffix, got: %v", events)
	}
}

// TestEncodingDetection_NoFalsePositives tests that legitimate base64 isn't flagged.
func TestEncodingDetection_NoFalsePositives(t *testing.T) {
	cfg := &policy.DLPConfig{
		DetectEncoding: true,
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Legitimate base64 content that doesn't contain secrets
	legitimateInputs := []string{
		"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk",
		"Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=", // "username:password"
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",          // JWT header (no secret pattern)
	}

	for _, input := range legitimateInputs {
		output, events := scanner.Redact(input)
		if output != input {
			t.Errorf("false positive on legitimate content:\n  input:  %s\n  output: %s", input, output)
		}
		if len(events) != 0 {
			t.Errorf("unexpected events for: %s", input)
		}
	}
}

// TestDetectsEncoding tests the DetectsEncoding() method.
func TestDetectsEncoding(t *testing.T) {
	// nil scanner
	var nilScanner *Scanner
	if nilScanner.DetectsEncoding() {
		t.Error("nil scanner should return false")
	}

	// With detection enabled
	cfg := &policy.DLPConfig{
		DetectEncoding: true,
		Patterns:       []policy.DLPPattern{{Name: "Test", Regex: "test"}},
	}
	scanner, _ := NewScanner(cfg)
	if !scanner.DetectsEncoding() {
		t.Error("scanner with detect_encoding=true should return true")
	}

	// With detection disabled
	cfg2 := &policy.DLPConfig{
		DetectEncoding: false,
		Patterns:       []policy.DLPPattern{{Name: "Test", Regex: "test"}},
	}
	scanner2, _ := NewScanner(cfg2)
	if scanner2.DetectsEncoding() {
		t.Error("scanner with detect_encoding=false should return false")
	}
}

// -----------------------------------------------------------------------------
// Filtered Writer Tests
// -----------------------------------------------------------------------------

// TestFilteredWriter_RedactsOutput tests that the filtered writer redacts secrets.
func TestFilteredWriter_RedactsOutput(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
		},
	}
	scanner, err := NewScanner(cfg)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	var buf bytes.Buffer
	filtered := NewFilteredWriter(&buf, scanner, nil, "")

	// Write output containing a secret
	input := "Error: failed to connect with key AKIAIOSFODNN7EXAMPLE\n"
	n, err := filtered.Write([]byte(input))

	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(input) {
		t.Errorf("Write returned %d, want %d", n, len(input))
	}

	// Verify secret was redacted
	output := buf.String()
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("secret was not redacted in output")
	}
	if !strings.Contains(output, "[REDACTED:AWS Key]") {
		t.Errorf("expected redaction placeholder, got: %s", output)
	}
}

// TestFilteredWriter_NilScanner tests passthrough when scanner is nil.
func TestFilteredWriter_NilScanner(t *testing.T) {
	var buf bytes.Buffer
	filtered := NewFilteredWriter(&buf, nil, nil, "")

	input := "Error: key is AKIAIOSFODNN7EXAMPLE\n"
	_, err := filtered.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// With nil scanner, output should be unchanged
	if buf.String() != input {
		t.Errorf("expected passthrough, got: %s", buf.String())
	}
}

// TestFilteredWriter_MultipleWrites tests that each write is independently scanned.
func TestFilteredWriter_MultipleWrites(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "Secret", Regex: `secret_[a-z]+`},
		},
	}
	scanner, _ := NewScanner(cfg)

	var buf bytes.Buffer
	filtered := NewFilteredWriter(&buf, scanner, nil, "")

	// Multiple writes
	_, _ = filtered.Write([]byte("Line 1: secret_alpha\n"))
	_, _ = filtered.Write([]byte("Line 2: no secrets here\n"))
	_, _ = filtered.Write([]byte("Line 3: secret_beta\n"))

	output := buf.String()

	// Both secrets should be redacted
	if strings.Contains(output, "secret_alpha") || strings.Contains(output, "secret_beta") {
		t.Error("secrets not redacted in multi-write output")
	}
	if !strings.Contains(output, "no secrets here") {
		t.Error("non-secret content was incorrectly modified")
	}
}

// TestFilteredWriter_StderrSecurityBypass is the key security test.
// Simulates the attack from the security review.
func TestFilteredWriter_StderrSecurityBypass(t *testing.T) {
	cfg := &policy.DLPConfig{
		Patterns: []policy.DLPPattern{
			{Name: "AWS Key", Regex: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`},
			{Name: "Password", Regex: `(?i)password\s*[:=]\s*\S+`},
		},
	}
	scanner, _ := NewScanner(cfg)

	var buf bytes.Buffer
	filtered := NewFilteredWriter(&buf, scanner, nil, "[subprocess]")

	// Simulate subprocess error output containing secrets
	stderrOutput := `
2024-01-15 10:23:45 ERROR Database connection failed
  host: db.example.com
  user: admin
  password: SuperSecret123!
  
Stack trace:
  at AWSClient.connect(key=AKIAIOSFODNN7EXAMPLE)
  at main.py:42
`
	if _, err := filtered.Write([]byte(stderrOutput)); err != nil {
		t.Fatalf("Failed to write to filtered writer: %v", err)
	}

	output := buf.String()

	// CRITICAL: Secrets MUST be redacted
	if strings.Contains(output, "SuperSecret123!") {
		t.Fatal("SECURITY FAILURE: Password leaked through stderr!")
	}
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("SECURITY FAILURE: AWS key leaked through stderr!")
	}

	// Non-sensitive data should be preserved
	if !strings.Contains(output, "Database connection failed") {
		t.Error("Non-sensitive error message was incorrectly removed")
	}
	if !strings.Contains(output, "db.example.com") {
		t.Error("Non-sensitive hostname was incorrectly removed")
	}
}
