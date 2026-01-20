// Package policy implements the AIP policy engine for tool call authorization.
//
// The policy engine is the core security primitive of AIP. It evaluates every
// tool call against a declarative manifest (agent.yaml) and returns an allow/deny
// decision. This package provides a minimal MVP implementation that supports
// simple allow-list based authorization.
//
// Future versions will support:
//   - Deny lists and explicit deny rules
//   - Argument-level constraints (e.g., "only SELECT queries")
//   - Pattern matching (e.g., "github_*" allows all GitHub tools)
//   - Rate limiting enforcement
//   - CEL/Rego expressions for complex policies
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// Policy Configuration Types
// -----------------------------------------------------------------------------

// AgentPolicy represents the parsed agent.yaml manifest.
//
// This struct maps to the policy file that defines what an agent is allowed
// to do. In the MVP, we focus on the allowed_tools list for basic tool-level
// authorization.
//
// Example agent.yaml:
//
//	apiVersion: aip.io/v1alpha1
//	kind: AgentPolicy
//	metadata:
//	  name: code-review-agent
//	spec:
//	  allowed_tools:
//	    - github_get_repo
//	    - github_list_pulls
//	    - github_create_review
type AgentPolicy struct {
	// APIVersion identifies the policy schema version.
	// Current version: aip.io/v1alpha1
	APIVersion string `yaml:"apiVersion"`

	// Kind must be "AgentPolicy" for this struct.
	Kind string `yaml:"kind"`

	// Metadata contains identifying information about the policy.
	Metadata PolicyMetadata `yaml:"metadata"`

	// Spec contains the actual policy rules.
	Spec PolicySpec `yaml:"spec"`
}

// PolicyMetadata contains identifying information about the policy.
type PolicyMetadata struct {
	// Name is a human-readable identifier for the agent.
	Name string `yaml:"name"`

	// Version is the semantic version of this policy.
	Version string `yaml:"version,omitempty"`

	// Owner is the team/person responsible for this policy.
	Owner string `yaml:"owner,omitempty"`
}

// PolicySpec contains the actual authorization rules.
type PolicySpec struct {
	// AllowedTools is a list of tool names that the agent may invoke.
	// If a tool is not in this list, it will be blocked.
	// Supports exact matches only in MVP; patterns in future versions.
	AllowedTools []string `yaml:"allowed_tools"`

	// ToolRules defines granular argument-level validation for specific tools.
	// Each rule specifies regex patterns that arguments must match.
	// If a tool has a rule here, its arguments are validated; if not, only
	// tool-level allow/deny applies.
	ToolRules []ToolRule `yaml:"tool_rules,omitempty"`

	// DeniedTools is a list of tools that are explicitly forbidden.
	// Takes precedence over AllowedTools (deny wins).
	// TODO: Implement in v0.2
	DeniedTools []string `yaml:"denied_tools,omitempty"`

	// Mode controls policy enforcement behavior.
	// Values:
	//   - "enforce" (default): Violations are blocked, error returned to client
	//   - "monitor": Violations are logged but allowed through (dry run mode)
	//
	// Monitor mode is useful for:
	//   - Testing new policies before enforcement
	//   - Understanding agent behavior in production
	//   - Gradual policy rollout
	Mode string `yaml:"mode,omitempty"`

	// DLP (Data Loss Prevention) configuration for output redaction.
	// When enabled, the proxy scans downstream responses from the tool
	// and redacts sensitive information (PII, API keys, secrets) before
	// forwarding to the client.
	DLP *DLPConfig `yaml:"dlp,omitempty"`
}

// DLPConfig configures Data Loss Prevention (output redaction) rules.
//
// Example YAML:
//
//	dlp:
//	  enabled: true
//	  patterns:
//	    - name: "Email"
//	      regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
//	    - name: "AWS Key"
//	      regex: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
type DLPConfig struct {
	// Enabled controls whether DLP scanning is active (default: true if dlp block exists)
	Enabled *bool `yaml:"enabled,omitempty"`

	// Patterns defines the sensitive data patterns to detect and redact.
	Patterns []DLPPattern `yaml:"patterns"`
}

// DLPPattern defines a single sensitive data detection rule.
type DLPPattern struct {
	// Name is a human-readable identifier for the pattern (used in redaction placeholder)
	Name string `yaml:"name"`

	// Regex is the pattern to match sensitive data
	Regex string `yaml:"regex"`
}

// IsEnabled returns true if DLP scanning is enabled.
func (d *DLPConfig) IsEnabled() bool {
	if d == nil {
		return false
	}
	if d.Enabled == nil {
		return true // Default to enabled if dlp block exists
	}
	return *d.Enabled
}

// ToolRule defines argument-level validation for a specific tool.
//
// Example YAML:
//
//	tool_rules:
//	  - tool: fetch_url
//	    allow_args:
//	      url: "^https://github\\.com/.*"
//	  - tool: run_query
//	    allow_args:
//	      query: "^SELECT\\s+.*"
//	  - tool: dangerous_tool
//	    action: ask
//	  - tool: expensive_api_call
//	    rate_limit: "5/minute"
type ToolRule struct {
	// Tool is the name of the tool this rule applies to.
	Tool string `yaml:"tool"`

	// Action specifies what happens when this tool is called.
	// Values: "allow" (default), "block", "ask"
	// - "allow": Permit the tool call (subject to arg validation)
	// - "block": Deny the tool call unconditionally
	// - "ask": Prompt user via native OS dialog for approval
	Action string `yaml:"action,omitempty"`

	// RateLimit specifies the maximum call rate for this tool.
	// Format: "N/duration" where duration is "second", "minute", or "hour".
	// Examples: "5/minute", "100/hour", "10/second"
	// If empty, no rate limiting is applied.
	RateLimit string `yaml:"rate_limit,omitempty"`

	// AllowArgs maps argument names to regex patterns.
	// Each argument value must match its corresponding regex.
	// Key = argument name, Value = regex pattern string.
	AllowArgs map[string]string `yaml:"allow_args"`

	// compiledArgs holds pre-compiled regex patterns for performance.
	// Populated during Load() to avoid recompilation on every request.
	compiledArgs map[string]*regexp.Regexp

	// parsedRateLimit holds the parsed rate limit value (requests per second).
	// Zero means no rate limiting.
	parsedRateLimit rate.Limit

	// parsedBurst holds the burst size for rate limiting.
	// Defaults to the rate limit count (N in "N/duration").
	parsedBurst int
}

// ParseRateLimit parses a rate limit string like "5/minute" into rate.Limit and burst.
// Returns (0, 0, nil) if the input is empty (no rate limiting).
// Returns error if the format is invalid.
//
// Supported formats:
//   - "N/second" - N requests per second
//   - "N/minute" - N requests per minute
//   - "N/hour"   - N requests per hour
func ParseRateLimit(s string) (rate.Limit, int, error) {
	if s == "" {
		return 0, 0, nil // No rate limiting
	}

	s = strings.TrimSpace(s)
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid rate limit format %q: expected 'N/duration'", s)
	}

	count, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || count <= 0 {
		return 0, 0, fmt.Errorf("invalid rate limit count %q: must be positive integer", parts[0])
	}

	duration := strings.ToLower(strings.TrimSpace(parts[1]))
	var perSecond float64

	switch duration {
	case "second", "sec", "s":
		perSecond = float64(count)
	case "minute", "min", "m":
		perSecond = float64(count) / 60.0
	case "hour", "hr", "h":
		perSecond = float64(count) / 3600.0
	default:
		return 0, 0, fmt.Errorf("invalid rate limit duration %q: must be 'second', 'minute', or 'hour'", duration)
	}

	// Burst is set to the count to allow the full quota to be used in a burst
	return rate.Limit(perSecond), count, nil
}

// -----------------------------------------------------------------------------
// Policy Engine
// -----------------------------------------------------------------------------

// PolicyMode constants for enforcement behavior.
const (
	// ModeEnforce blocks violations and returns errors to client (default).
	ModeEnforce = "enforce"
	// ModeMonitor logs violations but allows requests through (dry run).
	ModeMonitor = "monitor"
)

// ActionType constants for rule actions.
const (
	// ActionAllow permits the tool call (default).
	ActionAllow = "allow"
	// ActionBlock denies the tool call.
	ActionBlock = "block"
	// ActionAsk prompts the user for approval via native OS dialog.
	ActionAsk = "ask"
	// ActionRateLimited indicates the call was blocked due to rate limiting.
	ActionRateLimited = "rate_limited"
)

// Engine evaluates tool calls against the loaded policy.
//
// The engine is the "brain" of the AIP proxy. It maintains the parsed policy
// and provides fast lookups to determine if a tool call should be allowed.
//
// Thread-safety: The engine is safe for concurrent use after initialization.
// The allowedSet and toolRules maps are read-only after Load().
// The limiters map is thread-safe via its own internal mutex.
type Engine struct {
	// policy holds the parsed agent.yaml configuration.
	policy *AgentPolicy

	// allowedSet provides O(1) lookup for allowed tools.
	// Populated during Load() from policy.Spec.AllowedTools.
	allowedSet map[string]struct{}

	// toolRules provides O(1) lookup for tool-specific argument rules.
	// Key = normalized tool name, Value = ToolRule with compiled regexes.
	toolRules map[string]*ToolRule

	// mode controls enforcement behavior: "enforce" (default) or "monitor".
	// In monitor mode, violations are logged but allowed through.
	mode string

	// limiters holds per-tool rate limiters.
	// Key = normalized tool name, Value = token bucket limiter.
	// Populated during Load() for tools with rate_limit defined.
	limiters map[string]*rate.Limiter

	// limiterMu protects concurrent access to limiters map.
	limiterMu sync.RWMutex
}

// NewEngine creates a new policy engine instance.
//
// The engine is not usable until Load() or LoadFromFile() is called.
func NewEngine() *Engine {
	return &Engine{
		allowedSet: make(map[string]struct{}),
		toolRules:  make(map[string]*ToolRule),
		limiters:   make(map[string]*rate.Limiter),
	}
}

// Load parses a policy from YAML bytes and initializes the engine.
//
// This method builds the internal allowedSet for fast IsAllowed() lookups
// and compiles all regex patterns in tool_rules for argument validation.
// Tool names are normalized to lowercase for case-insensitive matching.
//
// Returns an error if:
//   - YAML parsing fails
//   - Required fields are missing
//   - Any regex pattern in allow_args is invalid
func (e *Engine) Load(data []byte) error {
	var policy AgentPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	// Validate required fields
	if policy.APIVersion == "" {
		return fmt.Errorf("policy missing required field: apiVersion")
	}
	if policy.Kind != "AgentPolicy" {
		return fmt.Errorf("unexpected kind %q, expected AgentPolicy", policy.Kind)
	}

	// Build the allowed set for O(1) lookups
	// Normalize to lowercase for case-insensitive matching
	e.allowedSet = make(map[string]struct{}, len(policy.Spec.AllowedTools))
	for _, tool := range policy.Spec.AllowedTools {
		normalized := strings.ToLower(strings.TrimSpace(tool))
		e.allowedSet[normalized] = struct{}{}
	}

	// Compile tool rules with regex patterns and initialize rate limiters
	e.toolRules = make(map[string]*ToolRule, len(policy.Spec.ToolRules))
	e.limiters = make(map[string]*rate.Limiter)
	for i := range policy.Spec.ToolRules {
		rule := &policy.Spec.ToolRules[i]
		normalized := strings.ToLower(strings.TrimSpace(rule.Tool))

		// Normalize and validate action field
		rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
		if rule.Action == "" {
			rule.Action = ActionAllow // Default to allow
		}
		if rule.Action != ActionAllow && rule.Action != ActionBlock && rule.Action != ActionAsk {
			return fmt.Errorf("invalid action %q for tool %q, must be 'allow', 'block', or 'ask'", rule.Action, rule.Tool)
		}

		// Parse rate limit if specified
		if rule.RateLimit != "" {
			limit, burst, err := ParseRateLimit(rule.RateLimit)
			if err != nil {
				return fmt.Errorf("invalid rate_limit for tool %q: %w", rule.Tool, err)
			}
			rule.parsedRateLimit = limit
			rule.parsedBurst = burst
			// Create the rate limiter for this tool
			e.limiters[normalized] = rate.NewLimiter(limit, burst)
		}

		// Compile all regex patterns for this tool
		rule.compiledArgs = make(map[string]*regexp.Regexp, len(rule.AllowArgs))
		for argName, pattern := range rule.AllowArgs {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex for tool %q arg %q: %w", rule.Tool, argName, err)
			}
			rule.compiledArgs[argName] = compiled
		}

		e.toolRules[normalized] = rule

		// Implicitly add tool to allowed set if it has rules defined
		// (even if action=block or action=ask, we track the tool for rule lookup)
		e.allowedSet[normalized] = struct{}{}
	}

	// Set enforcement mode (default to enforce if not specified)
	e.mode = strings.ToLower(strings.TrimSpace(policy.Spec.Mode))
	if e.mode == "" {
		e.mode = ModeEnforce
	}
	if e.mode != ModeEnforce && e.mode != ModeMonitor {
		return fmt.Errorf("invalid mode %q, must be 'enforce' or 'monitor'", policy.Spec.Mode)
	}

	e.policy = &policy
	return nil
}

// LoadFromFile reads and parses a policy file from disk.
func (e *Engine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file %q: %w", path, err)
	}
	return e.Load(data)
}

// Decision contains the result of a tool call authorization check.
//
// This struct supports both enforce and monitor modes:
//   - In enforce mode: Allowed=false means the request is blocked
//   - In monitor mode: Allowed=true but ViolationDetected=true means
//     the request passed through but would have been blocked
//
// The ViolationDetected field is critical for audit logging to identify
// "dry run blocks" in monitor mode.
//
// The Action field supports human-in-the-loop approval:
//   - ActionAllow: Forward request to server
//   - ActionBlock: Return error to client
//   - ActionAsk: Prompt user for approval via native OS dialog
type Decision struct {
	// Allowed indicates if the request should be forwarded to the server.
	// In enforce mode: false = blocked
	// In monitor mode: always true (violations pass through)
	// Note: When Action=ActionAsk, Allowed is not the final answer.
	Allowed bool

	// Action specifies the required action for this tool call.
	// Values: "allow", "block", "ask"
	// When Action="ask", the proxy should prompt the user for approval.
	Action string

	// ViolationDetected indicates if a policy violation was found.
	// true = policy would block this request (or did block in enforce mode)
	// This field is essential for audit logging in monitor mode.
	ViolationDetected bool

	// FailedArg is the name of the argument that failed validation (if any).
	FailedArg string

	// FailedRule is the regex pattern that failed to match (if any).
	FailedRule string

	// Reason provides a human-readable explanation of the decision.
	Reason string
}

// ValidationResult is an alias for Decision for backward compatibility.
// Deprecated: Use Decision instead.
type ValidationResult = Decision

// IsAllowed checks if the given tool name and arguments are permitted by policy.
//
// This is the primary authorization check called by the proxy for every
// tools/call request. The check flow is:
//
//  1. Check if tool has a rule with action="block" → Return BLOCK decision
//  2. Check if tool has a rule with action="ask" → Return ASK decision
//  3. Check if tool is in allowed_tools list (O(1) lookup)
//  4. If tool has argument rules in tool_rules, validate each argument
//  5. Return detailed Decision for error reporting and audit logging
//
// Tool names are normalized to lowercase for case-insensitive matching.
//
// Authorization Logic:
//   - Tool has action="block" → Block unconditionally
//   - Tool has action="ask" → Return ASK (requires user approval)
//   - Tool not in allowed_tools → Violation detected
//   - Tool allowed, no argument rules → Allow (implicit allow all args)
//   - Tool allowed, has argument rules → Validate each constrained arg
//   - Any argument fails regex match → Violation detected
//
// Monitor Mode Behavior:
//   - When mode="monitor", violations set ViolationDetected=true but Allowed=true
//   - This enables "dry run" testing of policies before enforcement
//   - The proxy should log these as "ALLOW_MONITOR" decisions
//   - Note: action="ask" rules still require user approval in monitor mode
//
// Example:
//
//	decision := engine.IsAllowed("fetch_url", map[string]any{"url": "https://evil.com"})
//	if decision.Action == ActionAsk {
//	    // Prompt user for approval via native OS dialog
//	} else if decision.ViolationDetected {
//	    if !decision.Allowed {
//	        // ENFORCE mode: Return JSON-RPC Forbidden error
//	    } else {
//	        // MONITOR mode: Log violation but forward request
//	    }
//	}
func (e *Engine) IsAllowed(toolName string, args map[string]any) Decision {
	if e.allowedSet == nil {
		// No policy loaded = deny all (fail closed)
		return Decision{
			Allowed:           false,
			Action:            ActionBlock,
			ViolationDetected: true,
			Reason:            "no policy loaded",
		}
	}

	// Normalize tool name for case-insensitive comparison
	normalized := strings.ToLower(strings.TrimSpace(toolName))

	// Step 0: Check rate limiting FIRST (before any other checks)
	// Rate limits are enforced regardless of mode (even in monitor mode)
	if limiter := e.getLimiter(normalized); limiter != nil {
		if !limiter.Allow() {
			return Decision{
				Allowed:           false,
				Action:            ActionRateLimited,
				ViolationDetected: true,
				Reason:            fmt.Sprintf("rate limit exceeded for tool %q", toolName),
			}
		}
	}

	// Step 1: Check if tool has a specific rule with action
	rule, hasRule := e.toolRules[normalized]
	if hasRule {
		// Check action type first
		switch rule.Action {
		case ActionBlock:
			// Unconditionally block this tool
			return Decision{
				Allowed:           false,
				Action:            ActionBlock,
				ViolationDetected: true,
				Reason:            "tool has action=block in tool_rules",
			}
		case ActionAsk:
			// Requires user approval - validate args first if present
			if len(rule.compiledArgs) > 0 {
				// Validate arguments before asking user
				for argName, compiledRegex := range rule.compiledArgs {
					argValue, exists := args[argName]
					if !exists {
						return e.makeDecision(false, "required argument missing", argName, rule.AllowArgs[argName])
					}
					strValue := argToString(argValue)
					if !compiledRegex.MatchString(strValue) {
						return e.makeDecision(false, "argument failed regex validation", argName, rule.AllowArgs[argName])
					}
				}
			}
			// Arguments valid (or no arg rules), return ASK decision
			return Decision{
				Allowed:           false, // Not automatically allowed
				Action:            ActionAsk,
				ViolationDetected: false, // Not a violation, just needs approval
				Reason:            "tool requires user approval (action=ask)",
			}
		}
		// action="allow" falls through to normal validation
	}

	// Step 2: Check if tool is in allowed list
	if _, allowed := e.allowedSet[normalized]; !allowed {
		return e.makeDecision(false, "tool not in allowed_tools list", "", "")
	}

	// Step 3: Check for argument-level rules (for action=allow)
	if !hasRule || len(rule.compiledArgs) == 0 {
		// No argument rules = implicit allow all args
		return Decision{
			Allowed:           true,
			Action:            ActionAllow,
			ViolationDetected: false,
			Reason:            "tool allowed, no argument constraints",
		}
	}

	// Step 4: Validate each constrained argument
	for argName, compiledRegex := range rule.compiledArgs {
		argValue, exists := args[argName]
		if !exists {
			// Argument not provided - this is a policy decision.
			// For security, we require constrained args to be present.
			return e.makeDecision(false, "required argument missing", argName, rule.AllowArgs[argName])
		}

		// Convert argument value to string for regex matching
		strValue := argToString(argValue)

		// Validate against the compiled regex
		if !compiledRegex.MatchString(strValue) {
			return e.makeDecision(false, "argument failed regex validation", argName, rule.AllowArgs[argName])
		}
	}

	// All argument validations passed
	return Decision{
		Allowed:           true,
		Action:            ActionAllow,
		ViolationDetected: false,
		Reason:            "tool and arguments permitted",
	}
}

// makeDecision creates a Decision based on violation and current mode.
//
// In enforce mode: violations result in Allowed=false, Action=ActionBlock
// In monitor mode: violations result in Allowed=true, Action=ActionAllow, ViolationDetected=true
func (e *Engine) makeDecision(wouldAllow bool, reason, failedArg, failedRule string) Decision {
	if wouldAllow {
		return Decision{
			Allowed:           true,
			Action:            ActionAllow,
			ViolationDetected: false,
			Reason:            reason,
			FailedArg:         failedArg,
			FailedRule:        failedRule,
		}
	}

	// Violation detected
	if e.mode == ModeMonitor {
		// Monitor mode: allow through but flag as violation
		return Decision{
			Allowed:           true,
			Action:            ActionAllow, // Monitor mode allows through
			ViolationDetected: true,
			Reason:            reason + " (monitor mode: allowed for dry run)",
			FailedArg:         failedArg,
			FailedRule:        failedRule,
		}
	}

	// Enforce mode: block the request
	return Decision{
		Allowed:           false,
		Action:            ActionBlock,
		ViolationDetected: true,
		Reason:            reason,
		FailedArg:         failedArg,
		FailedRule:        failedRule,
	}
}

// argToString converts an argument value to string for regex matching.
// Handles common JSON types: string, number, bool.
func argToString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%v", val)
	case int:
		return fmt.Sprintf("%d", val)
	case bool:
		return fmt.Sprintf("%t", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// GetPolicyName returns the name of the loaded policy for logging.
func (e *Engine) GetPolicyName() string {
	if e.policy == nil {
		return "<no policy>"
	}
	return e.policy.Metadata.Name
}

// GetMode returns the current enforcement mode ("enforce" or "monitor").
func (e *Engine) GetMode() string {
	if e.mode == "" {
		return ModeEnforce
	}
	return e.mode
}

// IsMonitorMode returns true if the engine is in monitor/dry-run mode.
func (e *Engine) IsMonitorMode() bool {
	return e.mode == ModeMonitor
}

// GetAllowedTools returns a copy of the allowed tools list for inspection.
func (e *Engine) GetAllowedTools() []string {
	if e.policy == nil {
		return nil
	}
	result := make([]string, len(e.policy.Spec.AllowedTools))
	copy(result, e.policy.Spec.AllowedTools)
	return result
}

// GetDLPConfig returns the DLP configuration from the policy.
// Returns nil if no DLP config is defined.
func (e *Engine) GetDLPConfig() *DLPConfig {
	if e.policy == nil {
		return nil
	}
	return e.policy.Spec.DLP
}

// getLimiter returns the rate limiter for a tool, or nil if none configured.
// Thread-safe via read lock.
func (e *Engine) getLimiter(normalizedTool string) *rate.Limiter {
	e.limiterMu.RLock()
	defer e.limiterMu.RUnlock()
	return e.limiters[normalizedTool]
}

// ResetLimiter resets the rate limiter for a specific tool.
// Useful for testing or administrative reset.
func (e *Engine) ResetLimiter(toolName string) {
	normalized := strings.ToLower(strings.TrimSpace(toolName))
	e.limiterMu.Lock()
	defer e.limiterMu.Unlock()

	if rule, ok := e.toolRules[normalized]; ok && rule.parsedRateLimit > 0 {
		e.limiters[normalized] = rate.NewLimiter(rule.parsedRateLimit, rule.parsedBurst)
	}
}

// ResetAllLimiters resets all rate limiters to their initial state.
// Useful for testing or administrative reset.
func (e *Engine) ResetAllLimiters() {
	e.limiterMu.Lock()
	defer e.limiterMu.Unlock()

	for normalized, rule := range e.toolRules {
		if rule.parsedRateLimit > 0 {
			e.limiters[normalized] = rate.NewLimiter(rule.parsedRateLimit, rule.parsedBurst)
		}
	}
}
