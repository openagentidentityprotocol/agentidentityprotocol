// Package policy tests for the AIP policy engine.
package policy

import (
	"testing"
)

// TestGeminiJackDefense tests the "GeminiJack" attack defense.
//
// Attack scenario: An attacker tricks an agent into calling fetch_url with
// a malicious URL like "https://attacker.com/steal" instead of the intended
// "https://github.com/..." URL.
//
// Defense: The policy engine validates the url argument against a regex
// that only allows GitHub URLs.
func TestGeminiJackDefense(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: gemini-jack-defense-test
spec:
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://github\\.com/.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		args        map[string]any
		wantAllowed bool
		wantFailArg string
	}{
		{
			name:        "Valid GitHub URL should pass",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://github.com/my-repo"},
			wantAllowed: true,
		},
		{
			name:        "Attacker URL should fail",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://attacker.com/steal"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "HTTP GitHub URL should fail (not https)",
			tool:        "fetch_url",
			args:        map[string]any{"url": "http://github.com/my-repo"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "GitHub subdomain attack should fail",
			tool:        "fetch_url",
			args:        map[string]any{"url": "https://github.com.evil.com/my-repo"},
			wantAllowed: false,
			wantFailArg: "url",
		},
		{
			name:        "Missing url argument should fail",
			tool:        "fetch_url",
			args:        map[string]any{},
			wantAllowed: false,
			wantFailArg: "url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.tool, tt.args)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", result.Allowed, tt.wantAllowed)
			}

			if tt.wantFailArg != "" && result.FailedArg != tt.wantFailArg {
				t.Errorf("FailedArg = %q, want %q", result.FailedArg, tt.wantFailArg)
			}
		})
	}
}

// TestToolLevelDeny tests that tools not in allowed_tools are denied.
func TestToolLevelDeny(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: tool-level-test
spec:
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		tool        string
		wantAllowed bool
	}{
		{"Allowed tool passes", "safe_tool", true},
		{"Allowed tool case-insensitive", "SAFE_TOOL", true},
		{"Unknown tool denied", "dangerous_tool", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.tool, nil)
			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.tool, result.Allowed, tt.wantAllowed)
			}
		})
	}
}

// TestToolWithNoArgRulesAllowsAllArgs tests that tools in tool_rules
// without allow_args allow all arguments.
func TestToolWithNoArgRulesAllowsAllArgs(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: no-arg-rules-test
spec:
  allowed_tools:
    - unrestricted_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool is allowed, no arg rules = allow any args
	result := engine.IsAllowed("unrestricted_tool", map[string]any{
		"any_arg":    "any_value",
		"another":    12345,
		"dangerous":  "../../etc/passwd",
	})

	if !result.Allowed {
		t.Errorf("Expected unrestricted_tool to allow all args, got denied")
	}
}

// TestMultipleArgConstraints tests that multiple arguments are all validated.
func TestMultipleArgConstraints(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: multi-arg-test
spec:
  tool_rules:
    - tool: run_query
      allow_args:
        database: "^(prod|staging)$"
        query: "^SELECT\\s+.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		args        map[string]any
		wantAllowed bool
		wantFailArg string
	}{
		{
			name:        "Valid SELECT on prod",
			args:        map[string]any{"database": "prod", "query": "SELECT * FROM users"},
			wantAllowed: true,
		},
		{
			name:        "Valid SELECT on staging",
			args:        map[string]any{"database": "staging", "query": "SELECT id FROM orders"},
			wantAllowed: true,
		},
		{
			name:        "DROP query should fail",
			args:        map[string]any{"database": "prod", "query": "DROP TABLE users"},
			wantAllowed: false,
			wantFailArg: "query",
		},
		{
			name:        "Invalid database should fail",
			args:        map[string]any{"database": "master", "query": "SELECT * FROM users"},
			wantAllowed: false,
			wantFailArg: "database",
		},
		{
			name:        "DELETE query should fail",
			args:        map[string]any{"database": "prod", "query": "DELETE FROM users"},
			wantAllowed: false,
			wantFailArg: "query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed("run_query", tt.args)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", result.Allowed, tt.wantAllowed)
			}

			if !tt.wantAllowed && tt.wantFailArg != "" && result.FailedArg != tt.wantFailArg {
				t.Errorf("FailedArg = %q, want %q", result.FailedArg, tt.wantFailArg)
			}
		})
	}
}

// TestInvalidRegexReturnsError tests that invalid regex patterns cause Load() to fail.
func TestInvalidRegexReturnsError(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-regex-test
spec:
  tool_rules:
    - tool: bad_tool
      allow_args:
        pattern: "[invalid(regex"
`

	engine := NewEngine()
	err := engine.Load([]byte(policyYAML))

	if err == nil {
		t.Error("Expected Load() to fail with invalid regex, but it succeeded")
	}
}

// TestArgToString tests conversion of various types to strings.
func TestArgToString(t *testing.T) {
	tests := []struct {
		input any
		want  string
	}{
		{"hello", "hello"},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{true, "true"},
		{false, "false"},
		{int(100), "100"},
	}

	for _, tt := range tests {
		got := argToString(tt.input)
		if got != tt.want {
			t.Errorf("argToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestToolRulesImplicitlyAllowTool tests that defining a tool_rule
// implicitly adds the tool to allowed_tools.
func TestToolRulesImplicitlyAllowTool(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: implicit-allow-test
spec:
  # Note: fetch_url NOT in allowed_tools, but has a tool_rule
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool should be allowed because it has a rule defined
	result := engine.IsAllowed("fetch_url", map[string]any{"url": "https://example.com"})
	if !result.Allowed {
		t.Error("Expected fetch_url to be implicitly allowed via tool_rules")
	}
}

// -----------------------------------------------------------------------------
// Monitor Mode Tests (Phase 4)
// -----------------------------------------------------------------------------

// TestMonitorModeAllowsViolations tests that monitor mode allows through
// requests that would otherwise be blocked, but flags ViolationDetected.
func TestMonitorModeAllowsViolations(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: monitor-mode-test
spec:
  mode: monitor
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Verify mode is set correctly
	if engine.GetMode() != ModeMonitor {
		t.Errorf("GetMode() = %q, want %q", engine.GetMode(), ModeMonitor)
	}
	if !engine.IsMonitorMode() {
		t.Error("IsMonitorMode() = false, want true")
	}

	tests := []struct {
		name              string
		tool              string
		wantAllowed       bool
		wantViolation     bool
	}{
		{
			name:              "Allowed tool - no violation",
			tool:              "safe_tool",
			wantAllowed:       true,
			wantViolation:     false,
		},
		{
			name:              "Blocked tool - allowed in monitor mode with violation flag",
			tool:              "dangerous_tool",
			wantAllowed:       true,  // MONITOR: allowed through
			wantViolation:     true,  // but flagged as violation
		},
		{
			name:              "Another blocked tool - same behavior",
			tool:              "rm_rf_slash",
			wantAllowed:       true,
			wantViolation:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed(tt.tool, nil)

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
		})
	}
}

// TestEnforceModeBlocksViolations tests that enforce mode (default) blocks
// violations and sets ViolationDetected appropriately.
func TestEnforceModeBlocksViolations(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: enforce-mode-test
spec:
  mode: enforce
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Verify mode is set correctly
	if engine.GetMode() != ModeEnforce {
		t.Errorf("GetMode() = %q, want %q", engine.GetMode(), ModeEnforce)
	}
	if engine.IsMonitorMode() {
		t.Error("IsMonitorMode() = true, want false")
	}

	tests := []struct {
		name              string
		tool              string
		wantAllowed       bool
		wantViolation     bool
	}{
		{
			name:              "Allowed tool - no violation",
			tool:              "safe_tool",
			wantAllowed:       true,
			wantViolation:     false,
		},
		{
			name:              "Blocked tool - denied with violation flag",
			tool:              "dangerous_tool",
			wantAllowed:       false, // ENFORCE: blocked
			wantViolation:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed(tt.tool, nil)

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
		})
	}
}

// TestDefaultModeIsEnforce tests that omitting mode defaults to enforce.
func TestDefaultModeIsEnforce(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: default-mode-test
spec:
  # mode not specified - should default to enforce
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if engine.GetMode() != ModeEnforce {
		t.Errorf("Default mode = %q, want %q", engine.GetMode(), ModeEnforce)
	}

	// Verify enforce behavior: blocked tool is denied
	decision := engine.IsAllowed("blocked_tool", nil)
	if decision.Allowed {
		t.Error("Default mode should block disallowed tools, but Allowed=true")
	}
	if !decision.ViolationDetected {
		t.Error("ViolationDetected should be true for blocked tool")
	}
}

// TestInvalidModeReturnsError tests that invalid mode values cause Load() to fail.
func TestInvalidModeReturnsError(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-mode-test
spec:
  mode: invalid_mode
  allowed_tools:
    - safe_tool
`

	engine := NewEngine()
	err := engine.Load([]byte(policyYAML))

	if err == nil {
		t.Error("Expected Load() to fail with invalid mode, but it succeeded")
	}
}

// TestMonitorModeWithArgValidation tests monitor mode with argument-level
// validation failures.
func TestMonitorModeWithArgValidation(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: monitor-args-test
spec:
  mode: monitor
  tool_rules:
    - tool: fetch_url
      allow_args:
        url: "^https://github\\.com/.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name              string
		args              map[string]any
		wantAllowed       bool
		wantViolation     bool
		wantFailedArg     string
	}{
		{
			name:              "Valid GitHub URL - no violation",
			args:              map[string]any{"url": "https://github.com/my-repo"},
			wantAllowed:       true,
			wantViolation:     false,
			wantFailedArg:     "",
		},
		{
			name:              "Attacker URL - allowed in monitor but flagged",
			args:              map[string]any{"url": "https://evil.com/steal"},
			wantAllowed:       true,  // MONITOR: allowed through
			wantViolation:     true,  // flagged as violation
			wantFailedArg:     "url",
		},
		{
			name:              "Missing URL - allowed in monitor but flagged",
			args:              map[string]any{},
			wantAllowed:       true,
			wantViolation:     true,
			wantFailedArg:     "url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed("fetch_url", tt.args)

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
			if tt.wantFailedArg != "" && decision.FailedArg != tt.wantFailedArg {
				t.Errorf("FailedArg = %q, want %q", decision.FailedArg, tt.wantFailedArg)
			}
		})
	}
}

// TestDecisionReason tests that decisions include helpful reason strings.
func TestDecisionReason(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: reason-test
spec:
  mode: monitor
  allowed_tools:
    - allowed_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Test that reason is populated
	decision := engine.IsAllowed("blocked_tool", nil)
	if decision.Reason == "" {
		t.Error("Decision.Reason should not be empty")
	}

	// Allowed tool should also have a reason
	decision = engine.IsAllowed("allowed_tool", nil)
	if decision.Reason == "" {
		t.Error("Decision.Reason should not be empty for allowed tools")
	}
}

// -----------------------------------------------------------------------------
// Human-in-the-Loop (ASK Action) Tests (Phase 5)
// -----------------------------------------------------------------------------

// TestAskActionReturnsAskDecision tests that action="ask" returns a Decision
// with Action=ActionAsk, requiring user approval.
func TestAskActionReturnsAskDecision(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: ask-action-test
spec:
  tool_rules:
    - tool: dangerous_tool
      action: ask
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	decision := engine.IsAllowed("dangerous_tool", nil)

	if decision.Action != ActionAsk {
		t.Errorf("Action = %q, want %q", decision.Action, ActionAsk)
	}
	if decision.Allowed {
		t.Error("Allowed should be false for ASK decision (requires user approval)")
	}
	if decision.ViolationDetected {
		t.Error("ViolationDetected should be false for ASK (not a policy violation)")
	}
}

// TestBlockActionReturnsBlockDecision tests that action="block" unconditionally
// blocks the tool call.
func TestBlockActionReturnsBlockDecision(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: block-action-test
spec:
  tool_rules:
    - tool: forbidden_tool
      action: block
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	decision := engine.IsAllowed("forbidden_tool", nil)

	if decision.Action != ActionBlock {
		t.Errorf("Action = %q, want %q", decision.Action, ActionBlock)
	}
	if decision.Allowed {
		t.Error("Allowed should be false for BLOCK decision")
	}
	if !decision.ViolationDetected {
		t.Error("ViolationDetected should be true for BLOCK")
	}
}

// TestAskActionWithArgValidation tests that action="ask" still validates
// arguments before prompting the user.
func TestAskActionWithArgValidation(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: ask-with-args-test
spec:
  tool_rules:
    - tool: sensitive_tool
      action: ask
      allow_args:
        target: "^(staging|prod)$"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		name           string
		args           map[string]any
		wantAction     string
		wantAllowed    bool
		wantViolation  bool
		wantFailedArg  string
	}{
		{
			name:           "Valid args returns ASK",
			args:           map[string]any{"target": "staging"},
			wantAction:     ActionAsk,
			wantAllowed:    false, // Needs user approval
			wantViolation:  false,
			wantFailedArg:  "",
		},
		{
			name:           "Invalid args returns BLOCK (not ASK)",
			args:           map[string]any{"target": "production-eu"},
			wantAction:     ActionBlock,
			wantAllowed:    false,
			wantViolation:  true,
			wantFailedArg:  "target",
		},
		{
			name:           "Missing required arg returns BLOCK",
			args:           map[string]any{},
			wantAction:     ActionBlock,
			wantAllowed:    false,
			wantViolation:  true,
			wantFailedArg:  "target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.IsAllowed("sensitive_tool", tt.args)

			if decision.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", decision.Action, tt.wantAction)
			}
			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}
			if decision.ViolationDetected != tt.wantViolation {
				t.Errorf("ViolationDetected = %v, want %v", decision.ViolationDetected, tt.wantViolation)
			}
			if tt.wantFailedArg != "" && decision.FailedArg != tt.wantFailedArg {
				t.Errorf("FailedArg = %q, want %q", decision.FailedArg, tt.wantFailedArg)
			}
		})
	}
}

// TestInvalidActionReturnsError tests that invalid action values cause Load() to fail.
func TestInvalidActionReturnsError(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-action-test
spec:
  tool_rules:
    - tool: bad_tool
      action: invalid_action
`

	engine := NewEngine()
	err := engine.Load([]byte(policyYAML))

	if err == nil {
		t.Error("Expected Load() to fail with invalid action, but it succeeded")
	}
}

// TestDefaultActionIsAllow tests that omitting action defaults to "allow".
func TestDefaultActionIsAllow(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: default-action-test
spec:
  tool_rules:
    - tool: some_tool
      # action not specified - should default to allow
      allow_args:
        param: "^valid$"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Valid args should be allowed directly (not ASK)
	decision := engine.IsAllowed("some_tool", map[string]any{"param": "valid"})
	if decision.Action != ActionAllow {
		t.Errorf("Default action = %q, want %q", decision.Action, ActionAllow)
	}
	if !decision.Allowed {
		t.Error("Tool with valid args should be allowed")
	}
}

// TestMixedActionsInPolicy tests a policy with multiple tools using different actions.
func TestMixedActionsInPolicy(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: mixed-actions-test
spec:
  allowed_tools:
    - safe_tool
  tool_rules:
    - tool: ask_tool
      action: ask
    - tool: block_tool
      action: block
    - tool: allow_tool
      action: allow
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	tests := []struct {
		tool       string
		wantAction string
	}{
		{"safe_tool", ActionAllow},
		{"ask_tool", ActionAsk},
		{"block_tool", ActionBlock},
		{"allow_tool", ActionAllow},
		{"unknown_tool", ActionBlock}, // Not in allowed_tools
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			decision := engine.IsAllowed(tt.tool, nil)
			if decision.Action != tt.wantAction {
				t.Errorf("Action for %q = %q, want %q", tt.tool, decision.Action, tt.wantAction)
			}
		})
	}
}

// TestDecisionIncludesAction tests that all decisions include the Action field.
func TestDecisionIncludesAction(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: action-field-test
spec:
  allowed_tools:
    - allowed_tool
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Allowed tool
	decision := engine.IsAllowed("allowed_tool", nil)
	if decision.Action == "" {
		t.Error("Decision.Action should not be empty for allowed tool")
	}
	if decision.Action != ActionAllow {
		t.Errorf("Action = %q, want %q", decision.Action, ActionAllow)
	}

	// Blocked tool
	decision = engine.IsAllowed("blocked_tool", nil)
	if decision.Action == "" {
		t.Error("Decision.Action should not be empty for blocked tool")
	}
	if decision.Action != ActionBlock {
		t.Errorf("Action = %q, want %q", decision.Action, ActionBlock)
	}
}

// -----------------------------------------------------------------------------
// Rate Limiting Tests (Phase 6)
// -----------------------------------------------------------------------------

// TestParseRateLimit tests parsing of rate limit strings.
func TestParseRateLimit(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLimit float64 // approximate rate per second
		wantBurst int
		wantErr   bool
	}{
		{
			name:      "Empty string - no rate limiting",
			input:     "",
			wantLimit: 0,
			wantBurst: 0,
			wantErr:   false,
		},
		{
			name:      "5 per second",
			input:     "5/second",
			wantLimit: 5.0,
			wantBurst: 5,
			wantErr:   false,
		},
		{
			name:      "5 per sec (short form)",
			input:     "5/sec",
			wantLimit: 5.0,
			wantBurst: 5,
			wantErr:   false,
		},
		{
			name:      "60 per minute",
			input:     "60/minute",
			wantLimit: 1.0, // 60/60 = 1 per second
			wantBurst: 60,
			wantErr:   false,
		},
		{
			name:      "2 per minute",
			input:     "2/minute",
			wantLimit: 2.0 / 60.0,
			wantBurst: 2,
			wantErr:   false,
		},
		{
			name:      "3600 per hour",
			input:     "3600/hour",
			wantLimit: 1.0, // 3600/3600 = 1 per second
			wantBurst: 3600,
			wantErr:   false,
		},
		{
			name:      "100 per hour",
			input:     "100/hour",
			wantLimit: 100.0 / 3600.0,
			wantBurst: 100,
			wantErr:   false,
		},
		{
			name:    "Invalid format - no slash",
			input:   "5minute",
			wantErr: true,
		},
		{
			name:    "Invalid format - too many slashes",
			input:   "5/per/minute",
			wantErr: true,
		},
		{
			name:    "Invalid count - not a number",
			input:   "abc/minute",
			wantErr: true,
		},
		{
			name:    "Invalid count - zero",
			input:   "0/minute",
			wantErr: true,
		},
		{
			name:    "Invalid count - negative",
			input:   "-5/minute",
			wantErr: true,
		},
		{
			name:    "Invalid duration",
			input:   "5/day",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, burst, err := ParseRateLimit(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRateLimit(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseRateLimit(%q) unexpected error: %v", tt.input, err)
				return
			}

			if burst != tt.wantBurst {
				t.Errorf("ParseRateLimit(%q) burst = %d, want %d", tt.input, burst, tt.wantBurst)
			}

			// Compare limits with some tolerance for floating point
			gotLimit := float64(limit)
			if gotLimit < tt.wantLimit*0.99 || gotLimit > tt.wantLimit*1.01 {
				t.Errorf("ParseRateLimit(%q) limit = %f, want %f", tt.input, gotLimit, tt.wantLimit)
			}
		})
	}
}

// TestRateLimitEnforcement tests that rate limits are enforced correctly.
// This is the key test: "2/minute" should allow first 2 calls, block subsequent.
func TestRateLimitEnforcement(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: rate-limit-test
spec:
  tool_rules:
    - tool: fast_tool
      rate_limit: "2/minute"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Simulate 5 rapid calls to fast_tool
	// First 2 should succeed (burst), remaining 3 should be rate limited
	var allowed, rateLimited int

	for i := 0; i < 5; i++ {
		decision := engine.IsAllowed("fast_tool", nil)

		if decision.Allowed {
			allowed++
		} else if decision.Action == ActionRateLimited {
			rateLimited++
			// Verify the error message format
			if decision.Reason == "" {
				t.Errorf("Call %d: Rate limited but no reason provided", i+1)
			}
		} else {
			t.Errorf("Call %d: Unexpected action %q", i+1, decision.Action)
		}
	}

	// Assert: first 2 succeed, next 3 fail
	if allowed != 2 {
		t.Errorf("Expected 2 allowed calls, got %d", allowed)
	}
	if rateLimited != 3 {
		t.Errorf("Expected 3 rate limited calls, got %d", rateLimited)
	}
}

// TestRateLimitPerTool tests that rate limits are per-tool, not global.
func TestRateLimitPerTool(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: per-tool-rate-limit-test
spec:
  allowed_tools:
    - unlimited_tool
  tool_rules:
    - tool: limited_tool
      rate_limit: "1/minute"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// First call to limited_tool should succeed
	decision := engine.IsAllowed("limited_tool", nil)
	if !decision.Allowed {
		t.Error("First call to limited_tool should be allowed")
	}

	// Second call should be rate limited
	decision = engine.IsAllowed("limited_tool", nil)
	if decision.Allowed || decision.Action != ActionRateLimited {
		t.Error("Second call to limited_tool should be rate limited")
	}

	// Calls to unlimited_tool should still work (no rate limit)
	for i := 0; i < 10; i++ {
		decision = engine.IsAllowed("unlimited_tool", nil)
		if !decision.Allowed {
			t.Errorf("Call %d to unlimited_tool should be allowed", i+1)
		}
	}
}

// TestRateLimitWithArgValidation tests that rate limits and arg validation work together.
func TestRateLimitWithArgValidation(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: rate-limit-with-args-test
spec:
  tool_rules:
    - tool: api_tool
      rate_limit: "2/minute"
      allow_args:
        endpoint: "^/api/.*"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Call 1: Valid args - should succeed
	decision := engine.IsAllowed("api_tool", map[string]any{"endpoint": "/api/users"})
	if !decision.Allowed {
		t.Errorf("Call 1 should be allowed, got action=%s, reason=%s", decision.Action, decision.Reason)
	}

	// Call 2: Valid args - should succeed (within burst)
	decision = engine.IsAllowed("api_tool", map[string]any{"endpoint": "/api/orders"})
	if !decision.Allowed {
		t.Errorf("Call 2 should be allowed, got action=%s, reason=%s", decision.Action, decision.Reason)
	}

	// Call 3: Even with valid args - should be rate limited
	decision = engine.IsAllowed("api_tool", map[string]any{"endpoint": "/api/products"})
	if decision.Allowed || decision.Action != ActionRateLimited {
		t.Errorf("Call 3 should be rate limited, got action=%s", decision.Action)
	}
}

// TestRateLimitDecisionFields tests that rate limited decisions have correct fields.
func TestRateLimitDecisionFields(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: rate-limit-fields-test
spec:
  tool_rules:
    - tool: test_tool
      rate_limit: "1/minute"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Exhaust the rate limit
	_ = engine.IsAllowed("test_tool", nil) // First call succeeds

	// Second call should be rate limited
	decision := engine.IsAllowed("test_tool", nil)

	// Verify all decision fields
	if decision.Allowed {
		t.Error("Allowed should be false")
	}
	if decision.Action != ActionRateLimited {
		t.Errorf("Action should be %q, got %q", ActionRateLimited, decision.Action)
	}
	if !decision.ViolationDetected {
		t.Error("ViolationDetected should be true")
	}
	if decision.Reason == "" {
		t.Error("Reason should not be empty")
	}
	if !containsSubstring(decision.Reason, "rate limit") {
		t.Errorf("Reason should mention rate limit, got: %s", decision.Reason)
	}
}

// TestInvalidRateLimitReturnsError tests that invalid rate limit values cause Load() to fail.
func TestInvalidRateLimitReturnsError(t *testing.T) {
	tests := []struct {
		name       string
		rateLimit  string
		wantErrMsg string
	}{
		{
			name:       "Invalid format",
			rateLimit:  "invalid",
			wantErrMsg: "invalid rate_limit",
		},
		{
			name:       "Invalid duration",
			rateLimit:  "5/week",
			wantErrMsg: "invalid rate_limit",
		},
		{
			name:       "Zero count",
			rateLimit:  "0/minute",
			wantErrMsg: "invalid rate_limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: invalid-rate-limit-test
spec:
  tool_rules:
    - tool: test_tool
      rate_limit: "` + tt.rateLimit + `"
`
			engine := NewEngine()
			err := engine.Load([]byte(policyYAML))

			if err == nil {
				t.Error("Expected Load() to fail with invalid rate_limit, but it succeeded")
			} else if !containsSubstring(err.Error(), tt.wantErrMsg) {
				t.Errorf("Error message should contain %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

// TestResetLimiter tests that rate limiters can be reset.
func TestResetLimiter(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: reset-limiter-test
spec:
  tool_rules:
    - tool: test_tool
      rate_limit: "1/minute"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Exhaust the rate limit
	decision := engine.IsAllowed("test_tool", nil)
	if !decision.Allowed {
		t.Error("First call should be allowed")
	}

	decision = engine.IsAllowed("test_tool", nil)
	if decision.Allowed {
		t.Error("Second call should be rate limited")
	}

	// Reset the limiter
	engine.ResetLimiter("test_tool")

	// Now it should work again
	decision = engine.IsAllowed("test_tool", nil)
	if !decision.Allowed {
		t.Error("After reset, call should be allowed")
	}
}

// TestRateLimitCaseInsensitive tests that rate limits work case-insensitively.
func TestRateLimitCaseInsensitive(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: case-insensitive-test
spec:
  tool_rules:
    - tool: Test_Tool
      rate_limit: "1/minute"
`

	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Call with different case - should hit the same limiter
	decision := engine.IsAllowed("TEST_TOOL", nil)
	if !decision.Allowed {
		t.Error("First call should be allowed")
	}

	decision = engine.IsAllowed("test_tool", nil)
	if decision.Action != ActionRateLimited {
		t.Error("Second call with different case should be rate limited")
	}
}

// containsSubstring is a helper to check if a string contains a substring.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
