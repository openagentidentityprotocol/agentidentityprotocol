// Package audit provides structured audit logging for AIP policy decisions.
//
// CRITICAL: This logger writes ONLY to a file (aip-audit.jsonl), NEVER to stdout.
// stdout is reserved exclusively for JSON-RPC transport between client and server.
// Writing logs to stdout would corrupt the JSON-RPC message stream.
//
// Log entries are written in JSON Lines format (one JSON object per line) to
// support streaming consumption by log aggregators and SIEM systems.
package audit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Direction indicates the flow direction of the intercepted message.
type Direction string

const (
	// DirectionUpstream = Client → Server (agent → MCP server)
	DirectionUpstream Direction = "upstream"
	// DirectionDownstream = Server → Client (MCP server → agent)
	DirectionDownstream Direction = "downstream"
)

// Decision represents the policy engine's authorization decision.
type Decision string

const (
	// DecisionAllow - Request permitted, forwarded to server
	DecisionAllow Decision = "ALLOW"
	// DecisionBlock - Request denied, error returned to client
	DecisionBlock Decision = "BLOCK"
	// DecisionAllowMonitor - Would be blocked, but monitor mode allowed passthrough
	DecisionAllowMonitor Decision = "ALLOW_MONITOR"
	// DecisionRateLimited - Request denied due to rate limit exceeded
	DecisionRateLimited Decision = "RATE_LIMITED"
)

// PolicyMode represents the enforcement mode of the policy.
type PolicyMode string

const (
	// PolicyModeEnforce - Violations are blocked (default)
	PolicyModeEnforce PolicyMode = "enforce"
	// PolicyModeMonitor - Violations are logged but allowed (dry run)
	PolicyModeMonitor PolicyMode = "monitor"
)

// Entry represents a single audit log entry.
//
// Example JSON output:
//
//	{
//	  "timestamp": "2025-01-20T10:30:45.123Z",
//	  "direction": "upstream",
//	  "method": "tools/call",
//	  "tool": "delete_file",
//	  "args": {"path": "/etc/passwd"},
//	  "decision": "BLOCK",
//	  "policy_mode": "enforce",
//	  "violation": true,
//	  "failed_arg": "path",
//	  "failed_rule": "^/home/.*"
//	}
type Entry struct {
	Timestamp   time.Time      `json:"timestamp"`
	Direction   Direction      `json:"direction"`
	Method      string         `json:"method,omitempty"`
	Tool        string         `json:"tool,omitempty"`
	Args        map[string]any `json:"args,omitempty"`
	Decision    Decision       `json:"decision"`
	PolicyMode  PolicyMode     `json:"policy_mode"`
	Violation   bool           `json:"violation"`
	FailedArg   string         `json:"failed_arg,omitempty"`
	FailedRule  string         `json:"failed_rule,omitempty"`
	PolicyName  string         `json:"policy_name,omitempty"`
	RequestID   string         `json:"request_id,omitempty"`
	ErrorReason string         `json:"error_reason,omitempty"`
}

// Logger provides structured audit logging to a file.
//
// Thread-safety: Logger is safe for concurrent use. The underlying slog.Logger
// and file writes are protected by a mutex.
//
// CRITICAL: This logger NEVER writes to stdout. All output goes to the
// configured file path to preserve the JSON-RPC transport stream.
type Logger struct {
	slogger *slog.Logger
	file    *os.File
	mu      sync.Mutex
	mode    PolicyMode
}

// Config holds configuration for the audit logger.
type Config struct {
	// FilePath is the path to the audit log file.
	// Default: "aip-audit.jsonl" in current directory.
	FilePath string

	// Mode is the policy enforcement mode (enforce/monitor).
	// Used to populate the policy_mode field in log entries.
	Mode PolicyMode
}

// DefaultConfig returns the default audit logger configuration.
func DefaultConfig() *Config {
	return &Config{
		FilePath: "aip-audit.jsonl",
		Mode:     PolicyModeEnforce,
	}
}

// NewLogger creates a new audit logger writing to the specified file.
//
// CRITICAL: This function validates that we are NOT writing to stdout.
// The file is opened in append mode to preserve existing audit trail.
//
// Returns error if:
//   - File path is empty
//   - File cannot be opened/created
//   - File path points to stdout ("/dev/stdout" or similar)
func NewLogger(cfg *Config) (*Logger, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.FilePath == "" {
		cfg.FilePath = "aip-audit.jsonl"
	}

	// CRITICAL SAFETY CHECK: Ensure we NEVER write to stdout
	// stdout is reserved for JSON-RPC transport
	if isStdoutPath(cfg.FilePath) {
		return nil, fmt.Errorf("audit logger MUST NOT write to stdout (path: %s); stdout is reserved for JSON-RPC transport", cfg.FilePath)
	}

	// Open file in append mode, create if not exists
	file, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file %q: %w", cfg.FilePath, err)
	}

	// Create JSON handler writing to file
	// IMPORTANT: We explicitly pass the file, not os.Stdout
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	return &Logger{
		slogger: slog.New(handler),
		file:    file,
		mode:    cfg.Mode,
	}, nil
}

// isStdoutPath checks if the given path would write to stdout.
func isStdoutPath(path string) bool {
	// Common paths that point to stdout
	stdoutPaths := []string{
		"/dev/stdout",
		"/dev/fd/1",
		"/proc/self/fd/1",
	}
	for _, p := range stdoutPaths {
		if path == p {
			return true
		}
	}
	return false
}

// NewNopLogger creates a no-op logger that discards all entries.
// Useful for testing or when audit logging is disabled.
func NewNopLogger() *Logger {
	handler := slog.NewJSONHandler(io.Discard, nil)
	return &Logger{
		slogger: slog.New(handler),
		file:    nil,
		mode:    PolicyModeEnforce,
	}
}

// Log writes an audit entry to the log file.
//
// This method is safe for concurrent use from multiple goroutines.
func (l *Logger) Log(entry *Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Set policy mode from logger config if not specified
	if entry.PolicyMode == "" {
		entry.PolicyMode = l.mode
	}

	// Build slog attributes from entry
	attrs := []slog.Attr{
		slog.Time("timestamp", entry.Timestamp),
		slog.String("direction", string(entry.Direction)),
		slog.String("decision", string(entry.Decision)),
		slog.String("policy_mode", string(entry.PolicyMode)),
		slog.Bool("violation", entry.Violation),
	}

	if entry.Method != "" {
		attrs = append(attrs, slog.String("method", entry.Method))
	}
	if entry.Tool != "" {
		attrs = append(attrs, slog.String("tool", entry.Tool))
	}
	if entry.Args != nil {
		attrs = append(attrs, slog.Any("args", entry.Args))
	}
	if entry.FailedArg != "" {
		attrs = append(attrs, slog.String("failed_arg", entry.FailedArg))
	}
	if entry.FailedRule != "" {
		attrs = append(attrs, slog.String("failed_rule", entry.FailedRule))
	}
	if entry.PolicyName != "" {
		attrs = append(attrs, slog.String("policy_name", entry.PolicyName))
	}
	if entry.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", entry.RequestID))
	}
	if entry.ErrorReason != "" {
		attrs = append(attrs, slog.String("error_reason", entry.ErrorReason))
	}

	// Log the entry
	l.slogger.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
}

// LogToolCall is a convenience method for logging tool call decisions.
func (l *Logger) LogToolCall(tool string, args map[string]any, decision Decision, violation bool, failedArg, failedRule string) {
	l.Log(&Entry{
		Direction:  DirectionUpstream,
		Method:     "tools/call",
		Tool:       tool,
		Args:       args,
		Decision:   decision,
		Violation:  violation,
		FailedArg:  failedArg,
		FailedRule: failedRule,
	})
}

// SetMode updates the policy mode for subsequent log entries.
func (l *Logger) SetMode(mode PolicyMode) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.mode = mode
}

// GetMode returns the current policy mode.
func (l *Logger) GetMode() PolicyMode {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.mode
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Sync flushes any buffered data to the underlying file.
func (l *Logger) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Sync()
	}
	return nil
}
