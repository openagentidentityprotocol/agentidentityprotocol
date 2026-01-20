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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	// AllowedMethods specifies which JSON-RPC methods are permitted.
	// This is the FIRST line of defense - checked before tool-level policy.
	//
	// If empty, defaults to safe methods: tools/call, tools/list, initialize,
	// initialized, ping, notifications/*, completion/complete.
	//
	// SECURITY: Methods like "resources/read", "resources/list", "prompts/get"
	// are NOT in the default allowlist. If your MCP server needs them, you must
	// explicitly add them here.
	//
	// Use "*" to allow all methods (NOT RECOMMENDED for production).
	AllowedMethods []string `yaml:"allowed_methods,omitempty"`

	// DeniedMethods explicitly blocks specific JSON-RPC methods.
	// Takes precedence over AllowedMethods (deny wins).
	// Useful for blocking specific methods while allowing most others.
	DeniedMethods []string `yaml:"denied_methods,omitempty"`

	// StrictArgsDefault sets the default strict_args value for all tool rules.
	// When true, tools reject any arguments not declared in allow_args.
	// Individual tool rules can override this with their own strict_args setting.
	// Default: false (lenient mode for backward compatibility)
	StrictArgsDefault bool `yaml:"strict_args_default,omitempty"`

	// ProtectedPaths is a list of file paths that tools may not read, write, or modify.
	// Any tool argument containing a protected path will be blocked.
	//
	// The policy file itself is ALWAYS protected (added automatically).
	// Use this to protect additional sensitive files like:
	//   - Configuration files
	//   - SSH keys (~/.ssh/*)
	//   - Environment files (.env)
	//   - Credentials
	//
	// Example:
	//   protected_paths:
	//     - ~/.ssh
	//     - ~/.aws/credentials
	//     - .env
	ProtectedPaths []string `yaml:"protected_paths,omitempty"`

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

	// DetectEncoding enables automatic detection and decoding of base64/hex encoded
	// strings before pattern matching. This catches secrets encoded to bypass DLP.
	//
	// When enabled:
	//   - Strings matching base64 patterns are decoded and scanned
	//   - Strings matching hex patterns (0x prefix or long hex) are decoded and scanned
	//   - If a secret is found in decoded content, the original encoded string is redacted
	//
	// Example attack prevented:
	//   Secret:  AKIAIOSFODNN7EXAMPLE
	//   Encoded: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=
	//   Without detect_encoding: Passes through (no match)
	//   With detect_encoding:    Redacted (decoded, matched, original replaced)
	//
	// Default: false (for backward compatibility and performance)
	DetectEncoding bool `yaml:"detect_encoding,omitempty"`

	// FilterStderr applies DLP scanning to subprocess stderr output.
	// When enabled, any sensitive data in error logs is redacted before display.
	//
	// This prevents information leakage through error messages, stack traces,
	// and debug output that might contain secrets.
	//
	// Default: false (for backward compatibility)
	FilterStderr bool `yaml:"filter_stderr,omitempty"`

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
//	  - tool: high_security_tool
//	    strict_args: true
//	    allow_args:
//	      param: "^valid$"
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

	// StrictArgs when true rejects any arguments not explicitly declared in AllowArgs.
	// Default: nil (inherit from strict_args_default)
	// Set to true/false to override the global default for this specific tool.
	//
	// Use strict_args: true for high-security tools where unknown arguments
	// could be used for data exfiltration or bypass attacks.
	//
	// Example attack prevented:
	//   Policy validates: url: "^https://github.com/.*"
	//   Attacker sends:   {"url": "https://github.com/ok", "headers": {"X-Exfil": "secret"}}
	//   Without strict:   headers passes through unchecked
	//   With strict:      BLOCKED - "headers" not in allow_args
	StrictArgs *bool `yaml:"strict_args,omitempty"`

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
	// ActionProtectedPath indicates the call was blocked due to accessing a protected path.
	// This is a security-critical event that should be audited separately.
	ActionProtectedPath = "protected_path"
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

	// allowedMethods provides O(1) lookup for allowed JSON-RPC methods.
	// Populated during Load() from policy.Spec.AllowedMethods.
	allowedMethods map[string]struct{}

	// deniedMethods provides O(1) lookup for denied JSON-RPC methods.
	// Takes precedence over allowedMethods.
	deniedMethods map[string]struct{}

	// protectedPaths holds paths that tools may not access.
	// Always includes the policy file itself.
	protectedPaths []string

	// mode controls enforcement behavior: "enforce" (default) or "monitor".
	// In monitor mode, violations are logged but allowed through.
	mode string

	// limiters holds per-tool rate limiters.
	// Key = normalized tool name, Value = ToolRule with compiled regexes.
	// Populated during Load() for tools with rate_limit defined.
	limiters map[string]*rate.Limiter

	// limiterMu protects concurrent access to limiters map.
	limiterMu sync.RWMutex
}

// DefaultAllowedMethods are safe JSON-RPC methods permitted when no explicit list is provided.
// These methods are considered safe because they either:
//   - Are required for MCP protocol handshake (initialize, initialized, ping)
//   - Are already policy-checked at the tool level (tools/call)
//   - Are read-only metadata operations (tools/list)
//   - Are client-side notifications that don't access resources
//
// SECURITY NOTE: The following methods are intentionally EXCLUDED:
//   - resources/read, resources/list (can read arbitrary files)
//   - prompts/get, prompts/list (can access prompt templates)
//   - logging/* (could leak information)
//
// If your MCP server needs these methods, explicitly add them to allowed_methods.
var DefaultAllowedMethods = []string{
	"initialize",
	"initialized",
	"ping",
	"tools/call",
	"tools/list",
	"completion/complete",
	"notifications/initialized",
	"notifications/progress",
	"notifications/message",
	"notifications/resources/updated",
	"notifications/resources/list_changed",
	"notifications/tools/list_changed",
	"notifications/prompts/list_changed",
	"cancelled",
}

// NewEngine creates a new policy engine instance.
//
// The engine is not usable until Load() or LoadFromFile() is called.
func NewEngine() *Engine {
	return &Engine{
		allowedSet:     make(map[string]struct{}),
		toolRules:      make(map[string]*ToolRule),
		allowedMethods: make(map[string]struct{}),
		deniedMethods:  make(map[string]struct{}),
		limiters:       make(map[string]*rate.Limiter),
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
	// Use NormalizeName for Unicode-safe, case-insensitive matching
	e.allowedSet = make(map[string]struct{}, len(policy.Spec.AllowedTools))
	for _, tool := range policy.Spec.AllowedTools {
		normalized := NormalizeName(tool)
		e.allowedSet[normalized] = struct{}{}
	}

	// Compile tool rules with regex patterns and initialize rate limiters
	e.toolRules = make(map[string]*ToolRule, len(policy.Spec.ToolRules))
	e.limiters = make(map[string]*rate.Limiter)
	for i := range policy.Spec.ToolRules {
		rule := &policy.Spec.ToolRules[i]
		normalized := NormalizeName(rule.Tool)

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

		// Compile all regex patterns for this tool with ReDoS protection
		rule.compiledArgs = make(map[string]*regexp.Regexp, len(rule.AllowArgs))
		for argName, pattern := range rule.AllowArgs {
			// Validate regex complexity before compilation (best-effort heuristic)
			if err := ValidateRegexComplexity(pattern); err != nil {
				return fmt.Errorf("potentially dangerous regex for tool %q arg %q: %w", rule.Tool, argName, err)
			}
			// Compile with timeout to prevent ReDoS at compile time
			compiled, err := SafeCompile(pattern, 0)
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

	// Build method allowlist for O(1) lookups
	// If no methods specified, use safe defaults
	e.allowedMethods = make(map[string]struct{})
	e.deniedMethods = make(map[string]struct{})

	if len(policy.Spec.AllowedMethods) > 0 {
		for _, method := range policy.Spec.AllowedMethods {
			normalized := NormalizeName(method)
			e.allowedMethods[normalized] = struct{}{}
		}
	} else {
		// Use default safe methods
		for _, method := range DefaultAllowedMethods {
			e.allowedMethods[NormalizeName(method)] = struct{}{}
		}
	}

	// Build denied methods set (takes precedence over allowed)
	for _, method := range policy.Spec.DeniedMethods {
		normalized := NormalizeName(method)
		e.deniedMethods[normalized] = struct{}{}
	}

	// Initialize protected paths from policy
	e.protectedPaths = make([]string, 0, len(policy.Spec.ProtectedPaths))
	for _, p := range policy.Spec.ProtectedPaths {
		expanded := expandPath(p)
		e.protectedPaths = append(e.protectedPaths, expanded)
	}

	e.policy = &policy
	return nil
}

// LoadFromFile reads and parses a policy file from disk.
// The policy file path is automatically added to protected paths.
func (e *Engine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file %q: %w", path, err)
	}
	if err := e.Load(data); err != nil {
		return err
	}

	// Add the policy file itself to protected paths (always protected)
	absPath, err := filepath.Abs(path)
	if err == nil {
		e.protectedPaths = append(e.protectedPaths, absPath)
	} else {
		// Fallback to original path if abs fails
		e.protectedPaths = append(e.protectedPaths, path)
	}

	return nil
}

// expandPath expands ~ to home directory and resolves to absolute path.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// checkProtectedPaths scans tool arguments for protected file paths.
// Returns the protected path that was found, or empty string if none.
//
// This is a defense against policy self-modification attacks:
//   - Agent tries to write to policy.yaml to add itself to allowed_tools
//   - Agent tries to read policy.yaml to discover blocked tools
//   - Agent tries to modify other sensitive files
//
// The check is performed on all string arguments, recursively scanning
// nested objects and arrays.
func (e *Engine) checkProtectedPaths(args map[string]any) string {
	if len(e.protectedPaths) == 0 {
		return ""
	}
	return e.scanArgsForProtectedPaths(args)
}

// scanArgsForProtectedPaths recursively scans arguments for protected paths.
func (e *Engine) scanArgsForProtectedPaths(v any) string {
	switch val := v.(type) {
	case string:
		return e.matchProtectedPath(val)
	case map[string]any:
		for _, v := range val {
			if found := e.scanArgsForProtectedPaths(v); found != "" {
				return found
			}
		}
	case []any:
		for _, item := range val {
			if found := e.scanArgsForProtectedPaths(item); found != "" {
				return found
			}
		}
	}
	return ""
}

// matchProtectedPath checks if a string value matches any protected path.
func (e *Engine) matchProtectedPath(value string) string {
	// Expand and normalize the value
	expanded := expandPath(value)

	for _, protected := range e.protectedPaths {
		// Exact match
		if expanded == protected || value == protected {
			return protected
		}
		// Check if value is under protected directory
		if strings.HasPrefix(expanded, protected+string(filepath.Separator)) {
			return protected
		}
		// Check if protected path is contained in the value (e.g., in a command string)
		if strings.Contains(value, protected) {
			return protected
		}
		// Also check the base name for common file references
		if filepath.Base(expanded) == filepath.Base(protected) &&
			strings.Contains(value, filepath.Base(protected)) {
			// Only match if it looks like a path (contains separator or starts with .)
			if strings.ContainsAny(value, "/\\") || strings.HasPrefix(value, ".") {
				return protected
			}
		}
	}
	return ""
}

// GetProtectedPaths returns the list of protected paths for logging.
func (e *Engine) GetProtectedPaths() []string {
	return e.protectedPaths
}

// AddProtectedPath adds a path to the protected list.
// Useful for adding paths dynamically (e.g., audit log file).
func (e *Engine) AddProtectedPath(path string) {
	expanded := expandPath(path)
	e.protectedPaths = append(e.protectedPaths, expanded)
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
	// Values: "allow", "block", "ask", "rate_limited", "protected_path"
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

	// ProtectedPath is set when Action=ActionProtectedPath, containing the
	// path that triggered the security block. This is critical for audit.
	ProtectedPath string

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

	// Normalize tool name using Unicode-safe normalization
	// This prevents bypass attacks via fullwidth chars, ligatures, etc.
	normalized := NormalizeName(toolName)

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

	// Step 0.5: Check protected paths (policy self-modification defense)
	// This blocks any attempt to read/write/modify protected files
	// including the policy file itself.
	if protectedPath := e.checkProtectedPaths(args); protectedPath != "" {
		return Decision{
			Allowed:           false,
			Action:            ActionProtectedPath,
			ViolationDetected: true,
			ProtectedPath:     protectedPath,
			Reason:            fmt.Sprintf("access to protected path %q blocked (policy self-modification defense)", protectedPath),
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
			// Check strict args for ASK action too
			if e.isStrictArgs(rule) && len(args) > 0 {
				for argName := range args {
					if _, declared := rule.AllowArgs[argName]; !declared {
						return e.makeDecision(false,
							fmt.Sprintf("undeclared argument %q rejected (strict_args enabled)", argName),
							argName, "")
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

	// Step 5: Strict args mode - reject undeclared arguments
	// This prevents bypass attacks via extra arguments (e.g., headers, metadata)
	if e.isStrictArgs(rule) && len(args) > 0 {
		for argName := range args {
			if _, declared := rule.AllowArgs[argName]; !declared {
				return e.makeDecision(false,
					fmt.Sprintf("undeclared argument %q rejected (strict_args enabled)", argName),
					argName, "")
			}
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

// isStrictArgs returns true if strict argument validation is enabled for a tool rule.
// Strict mode rejects any arguments not explicitly declared in allow_args.
//
// Priority:
//  1. Rule-specific strict_args setting (if explicitly set via pointer)
//  2. Global strict_args_default from policy spec
//  3. Default: false (lenient mode)
func (e *Engine) isStrictArgs(rule *ToolRule) bool {
	if rule == nil {
		// No rule = use global default
		if e.policy != nil {
			return e.policy.Spec.StrictArgsDefault
		}
		return false
	}
	// Rule-specific setting takes precedence (if explicitly set)
	if rule.StrictArgs != nil {
		return *rule.StrictArgs
	}
	// Fall back to global default
	if e.policy != nil {
		return e.policy.Spec.StrictArgsDefault
	}
	return false
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
// Complex types (slices, maps) are marshaled to JSON to ensure deterministic matching.
func argToString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		// Use -1 to format minimal decimal digits needed
		return strconv.FormatFloat(val, 'f', -1, 64)
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	case nil:
		return ""
	default:
		// Fallback for complex types: JSON representation
		// This ensures []string{"a", "b"} becomes `["a","b"]` instead of `[a b]`
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		// Last resort fallback
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
	normalized := NormalizeName(toolName)
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

// -----------------------------------------------------------------------------
// Method-Level Authorization (First Line of Defense)
// -----------------------------------------------------------------------------

// MethodDecision contains the result of a method-level authorization check.
// This is checked BEFORE tool-level policy to prevent bypass attacks via
// uncontrolled MCP methods like resources/read or prompts/get.
type MethodDecision struct {
	// Allowed indicates if the method should be permitted.
	Allowed bool

	// Reason provides a human-readable explanation of the decision.
	Reason string
}

// IsMethodAllowed checks if a JSON-RPC method is permitted by policy.
//
// This is the FIRST line of defense, checked before tool-level policy.
// It prevents bypass attacks where an attacker uses MCP methods that aren't
// subject to tool-level checks (e.g., resources/read, prompts/get).
//
// The check flow is:
//  1. Check if method is in denied_methods → DENY
//  2. Check if "*" wildcard is in allowed_methods → ALLOW
//  3. Check if method is in allowed_methods → ALLOW
//  4. Otherwise → DENY (fail-closed)
//
// Method names are normalized to lowercase for case-insensitive matching.
// This prevents bypass via "Resources/Read" vs "resources/read".
//
// Example:
//
//	decision := engine.IsMethodAllowed("resources/read")
//	if !decision.Allowed {
//	    // Return -32006 Method Not Allowed error
//	}
func (e *Engine) IsMethodAllowed(method string) MethodDecision {
	// Normalize using Unicode-safe normalization
	// This prevents bypass attacks via fullwidth chars, etc.
	normalized := NormalizeName(method)

	// No policy loaded = use defaults (fail-open for basic MCP methods)
	if e.allowedMethods == nil && e.deniedMethods == nil {
		for _, m := range DefaultAllowedMethods {
			if strings.ToLower(m) == normalized {
				return MethodDecision{
					Allowed: true,
					Reason:  "method in default allowlist (no policy loaded)",
				}
			}
		}
		return MethodDecision{
			Allowed: false,
			Reason:  "method not in default allowlist (no policy loaded)",
		}
	}

	// Step 1: Check deny list first (takes precedence)
	if _, denied := e.deniedMethods[normalized]; denied {
		return MethodDecision{
			Allowed: false,
			Reason:  "method explicitly denied by denied_methods",
		}
	}

	// Step 2: Check for wildcard (allows everything not denied)
	if _, ok := e.allowedMethods["*"]; ok {
		return MethodDecision{
			Allowed: true,
			Reason:  "wildcard '*' in allowed_methods permits all methods",
		}
	}

	// Step 3: Check if method is in allowed list
	if _, allowed := e.allowedMethods[normalized]; allowed {
		return MethodDecision{
			Allowed: true,
			Reason:  "method in allowed_methods",
		}
	}

	// Step 4: Default deny (fail-closed)
	return MethodDecision{
		Allowed: false,
		Reason:  fmt.Sprintf("method %q not in allowed_methods", method),
	}
}

// GetAllowedMethods returns a copy of the allowed methods list for inspection.
func (e *Engine) GetAllowedMethods() []string {
	if e.allowedMethods == nil {
		return DefaultAllowedMethods
	}

	result := make([]string, 0, len(e.allowedMethods))
	for method := range e.allowedMethods {
		result = append(result, method)
	}
	return result
}

// GetDeniedMethods returns a copy of the denied methods list for inspection.
func (e *Engine) GetDeniedMethods() []string {
	if e.deniedMethods == nil {
		return nil
	}

	result := make([]string, 0, len(e.deniedMethods))
	for method := range e.deniedMethods {
		result = append(result, method)
	}
	return result
}
