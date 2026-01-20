// Package dlp implements Data Loss Prevention (DLP) scanning and redaction.
//
// The DLP scanner inspects tool responses flowing downstream from the MCP server
// to the client and redacts sensitive information (PII, API keys, secrets) before
// forwarding. This prevents accidental data exfiltration through tool outputs.
//
// Architecture:
//
//	┌──────────────┐     ┌─────────────┐     ┌──────────────┐
//	│  MCP Server  │────▶│ DLP Scanner │────▶│    Client    │
//	│  (response)  │     │  (redact)   │     │ (sanitized)  │
//	└──────────────┘     └─────────────┘     └──────────────┘
//
// The scanner uses compiled regular expressions for performance, running all
// patterns against each response. Matches are replaced with [REDACTED:<RuleName>].
//
// Encoding Detection:
//
// When detect_encoding is enabled, the scanner also attempts to decode base64
// and hex-encoded strings before pattern matching. This prevents bypass attacks
// where secrets are encoded to evade detection.
package dlp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/ArangoGutierrez/agent-identity-protocol/proxy/pkg/policy"
)

// RedactionEvent captures details of a single redaction for audit logging.
type RedactionEvent struct {
	// RuleName is the name of the DLP rule that matched
	RuleName string

	// MatchCount is the number of matches found for this rule
	MatchCount int
}

// Scanner provides DLP scanning and redaction capabilities.
//
// Thread-safety: Scanner is safe for concurrent use after initialization.
// The compiled patterns are read-only after Compile().
type Scanner struct {
	patterns       []compiledPattern
	enabled        bool
	detectEncoding bool
	mu             sync.RWMutex
}

// compiledPattern holds a pre-compiled regex with its associated rule name.
type compiledPattern struct {
	name  string
	regex *regexp.Regexp
}

// NewScanner creates a new DLP scanner from policy configuration.
//
// Returns nil if DLP is not configured or disabled.
// Returns error if any pattern regex fails to compile.
func NewScanner(cfg *policy.DLPConfig) (*Scanner, error) {
	if cfg == nil || !cfg.IsEnabled() {
		return nil, nil
	}

	s := &Scanner{
		patterns:       make([]compiledPattern, 0, len(cfg.Patterns)),
		enabled:        true,
		detectEncoding: cfg.DetectEncoding,
	}

	for _, p := range cfg.Patterns {
		if p.Name == "" {
			return nil, fmt.Errorf("DLP pattern missing required 'name' field")
		}
		if p.Regex == "" {
			return nil, fmt.Errorf("DLP pattern %q missing required 'regex' field", p.Name)
		}

		// Validate regex complexity before compilation (best-effort ReDoS detection)
		if err := policy.ValidateRegexComplexity(p.Regex); err != nil {
			return nil, fmt.Errorf("DLP pattern %q has potentially dangerous regex: %w", p.Name, err)
		}

		// Compile with timeout to prevent ReDoS at compile time
		compiled, err := policy.SafeCompile(p.Regex, 0)
		if err != nil {
			return nil, fmt.Errorf("DLP pattern %q has invalid regex: %w", p.Name, err)
		}

		s.patterns = append(s.patterns, compiledPattern{
			name:  p.Name,
			regex: compiled,
		})
	}

	return s, nil
}

// IsEnabled returns true if the scanner is active and has patterns configured.
func (s *Scanner) IsEnabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled && len(s.patterns) > 0
}

// Redact scans input string for sensitive data and replaces matches.
//
// Returns:
//   - output: The redacted string with matches replaced by [REDACTED:<RuleName>]
//   - events: List of RedactionEvent for each rule that matched (for audit logging)
//
// If the scanner is nil or disabled, returns the original input unchanged.
//
// When detect_encoding is enabled, also scans decoded base64/hex content.
// If a secret is found in decoded content, the original encoded string is redacted.
//
// Example:
//
//	input:  "API key is AKIAIOSFODNN7EXAMPLE"
//	output: "API key is [REDACTED:AWS Key]"
//	events: [{RuleName: "AWS Key", MatchCount: 1}]
func (s *Scanner) Redact(input string) (output string, events []RedactionEvent) {
	if s == nil || !s.IsEnabled() {
		return input, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	output = input
	events = make([]RedactionEvent, 0)

	// Step 1: Standard pattern matching on raw input
	for _, p := range s.patterns {
		matches := p.regex.FindAllStringIndex(output, -1)
		if len(matches) > 0 {
			// Record the redaction event before modifying the string
			events = append(events, RedactionEvent{
				RuleName:   p.name,
				MatchCount: len(matches),
			})

			// Replace all matches with redaction placeholder
			replacement := fmt.Sprintf("[REDACTED:%s]", p.name)
			output = p.regex.ReplaceAllString(output, replacement)
		}
	}

	// Step 2: Encoding detection (if enabled)
	// Scan for base64/hex encoded secrets that bypass plain regex
	if s.detectEncoding {
		segments := findEncodedSegments(output)
		for _, seg := range segments {
			// Skip if segment was already redacted by a previous (larger) segment
			if !strings.Contains(output, seg.original) {
				continue
			}
			// Check if decoded content contains any secrets
			for _, p := range s.patterns {
				if p.regex.MatchString(seg.decoded) {
					// Found secret in decoded content - redact the original encoded string
					events = append(events, RedactionEvent{
						RuleName:   p.name + " (encoded)",
						MatchCount: 1,
					})
					replacement := fmt.Sprintf("[REDACTED:%s:encoded]", p.name)
					output = strings.Replace(output, seg.original, replacement, 1)
					break // Don't double-count same segment
				}
			}
		}
	}

	return output, events
}

// RedactJSON scans a JSON byte slice for sensitive data in string values.
// This is a convenience wrapper that converts to string, redacts, and returns bytes.
//
// Note: This performs string-level redaction. For structured JSON inspection,
// use the Scanner with the decoded JSON content fields.
func (s *Scanner) RedactJSON(input []byte) (output []byte, events []RedactionEvent) {
	if s == nil || !s.IsEnabled() {
		return input, nil
	}

	redacted, events := s.Redact(string(input))
	return []byte(redacted), events
}

// -----------------------------------------------------------------------------
// Deep/Recursive Scanning
// -----------------------------------------------------------------------------

// RedactDeep recursively scans and redacts sensitive data in nested structures.
//
// This method handles:
//   - Strings: Scanned directly
//   - Maps (map[string]any): Each value is recursively scanned
//   - Slices ([]any): Each element is recursively scanned
//   - Primitives (int, float, bool, nil): Passed through unchanged
//
// SECURITY: This prevents bypass attacks where secrets are hidden in nested
// structures like {"config": {"aws": {"key": "AKIAIOSFODNN7EXAMPLE"}}}.
// The shallow Redact() method would miss this; RedactDeep catches it.
//
// Returns:
//   - result: A new structure with redacted values (original is NOT modified)
//   - events: Combined RedactionEvent list from all nested redactions
//
// Example:
//
//	input:  map[string]any{"nested": map[string]any{"secret": "AKIAIOSFODNN7EXAMPLE"}}
//	output: map[string]any{"nested": map[string]any{"secret": "[REDACTED:AWS Key]"}}
//	events: [{RuleName: "AWS Key", MatchCount: 1}]
func (s *Scanner) RedactDeep(v any) (any, []RedactionEvent) {
	if s == nil || !s.IsEnabled() {
		return v, nil
	}

	var allEvents []RedactionEvent
	result := s.redactDeepInternal(v, &allEvents)
	return result, allEvents
}

// redactDeepInternal is the recursive implementation of RedactDeep.
// It accumulates events into the provided slice to avoid allocations per level.
func (s *Scanner) redactDeepInternal(v any, events *[]RedactionEvent) any {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case string:
		// Base case: scan and redact string
		redacted, newEvents := s.Redact(val)
		*events = append(*events, newEvents...)
		return redacted

	case map[string]any:
		// Recursive case: process each map value
		// Note: map[string]interface{} is the same type as map[string]any in Go 1.18+
		result := make(map[string]any, len(val))
		for k, v := range val {
			result[k] = s.redactDeepInternal(v, events)
		}
		return result

	case []any:
		// Recursive case: process each slice element
		// Note: []interface{} is the same type as []any in Go 1.18+
		result := make([]any, len(val))
		for i, v := range val {
			result[i] = s.redactDeepInternal(v, events)
		}
		return result

	// Primitives pass through unchanged
	case float64, float32, int, int64, int32, int16, int8,
		uint, uint64, uint32, uint16, uint8, bool:
		return val

	default:
		// For unknown types, try to convert to string and scan
		// This catches custom types that implement Stringer
		str := fmt.Sprintf("%v", val)
		if str != "" && str != fmt.Sprintf("%T", val) {
			redacted, newEvents := s.Redact(str)
			if len(newEvents) > 0 {
				*events = append(*events, newEvents...)
				return redacted
			}
		}
		return val
	}
}

// RedactMap is a convenience method for redacting map[string]any structures.
// Returns the redacted map and events. If input is not a map, returns it unchanged.
func (s *Scanner) RedactMap(input map[string]any) (map[string]any, []RedactionEvent) {
	if s == nil || !s.IsEnabled() || input == nil {
		return input, nil
	}

	result, events := s.RedactDeep(input)
	if m, ok := result.(map[string]any); ok {
		return m, events
	}
	return input, nil
}

// PatternCount returns the number of configured DLP patterns.
func (s *Scanner) PatternCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.patterns)
}

// PatternNames returns the names of all configured patterns (for logging).
func (s *Scanner) PatternNames() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, len(s.patterns))
	for i, p := range s.patterns {
		names[i] = p.name
	}
	return names
}

// -----------------------------------------------------------------------------
// Encoding Detection
// -----------------------------------------------------------------------------

// Patterns for detecting potentially encoded strings
var (
	// Base64 standard alphabet with optional padding
	// Matches strings of 16+ chars that look like base64 (to avoid false positives)
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

	// Base64 URL-safe alphabet
	base64URLPattern = regexp.MustCompile(`[A-Za-z0-9_-]{16,}={0,2}`)

	// Hex strings: 0x prefix or long continuous hex (32+ chars for 16+ bytes)
	hexPrefixPattern = regexp.MustCompile(`0[xX][0-9A-Fa-f]{8,}`)
	hexLongPattern   = regexp.MustCompile(`[0-9A-Fa-f]{32,}`)
)

// encodedSegment represents a potentially encoded substring found in input
type encodedSegment struct {
	original string // The original encoded string
	decoded  string // The decoded content
	start    int    // Start position in input
	end      int    // End position in input
}

// findEncodedSegments scans input for base64 and hex encoded substrings.
// Returns segments that successfully decoded to printable text.
//
// Order matters: hex is checked first because hex strings can accidentally
// match base64 patterns (they share [A-Fa-f0-9]), but hex decoding is more
// specific and should take precedence.
func findEncodedSegments(input string) []encodedSegment {
	var segments []encodedSegment
	seen := make(map[string]bool) // Avoid duplicate segments

	// Find hex candidates FIRST (more specific than base64)
	// Hex strings only contain [0-9A-Fa-f] and would be mangled by base64 decode
	for _, pattern := range []*regexp.Regexp{hexPrefixPattern, hexLongPattern} {
		matches := pattern.FindAllStringIndex(input, -1)
		for _, match := range matches {
			encoded := input[match[0]:match[1]]
			if seen[encoded] {
				continue
			}

			decoded, ok := tryDecodeHex(encoded)
			if ok && isPrintableString(decoded) && len(decoded) >= 4 {
				seen[encoded] = true
				segments = append(segments, encodedSegment{
					original: encoded,
					decoded:  decoded,
					start:    match[0],
					end:      match[1],
				})
			}
		}
	}

	// Find base64 candidates (after hex to avoid misclassification)
	for _, pattern := range []*regexp.Regexp{base64Pattern, base64URLPattern} {
		matches := pattern.FindAllStringIndex(input, -1)
		for _, match := range matches {
			encoded := input[match[0]:match[1]]
			if seen[encoded] {
				continue
			}

			decoded, ok := tryDecodeBase64(encoded)
			if ok && isPrintableString(decoded) && len(decoded) >= 4 {
				seen[encoded] = true
				segments = append(segments, encodedSegment{
					original: encoded,
					decoded:  decoded,
					start:    match[0],
					end:      match[1],
				})
			}
		}
	}

	return segments
}

// tryDecodeBase64 attempts to decode a base64 string (standard or URL-safe).
func tryDecodeBase64(s string) (string, bool) {
	// Try standard base64 first
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), true
	}

	// Try URL-safe base64
	decoded, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), true
	}

	// Try without padding (common in URLs/JWT)
	decoded, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), true
	}

	decoded, err = base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), true
	}

	return "", false
}

// tryDecodeHex attempts to decode a hex string.
func tryDecodeHex(s string) (string, bool) {
	// Strip 0x prefix if present
	hexStr := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", false
	}

	return string(decoded), true
}

// isPrintableString returns true if the string contains mostly printable ASCII.
// Used to filter out random binary data that happens to decode.
func isPrintableString(s string) bool {
	if len(s) == 0 {
		return false
	}

	printable := 0
	for _, r := range s {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}

	// Require at least 80% printable characters
	return float64(printable)/float64(len([]rune(s))) >= 0.8
}

// scanDecoded checks if any patterns match the decoded content.
// Returns true if a secret was found.
func (s *Scanner) scanDecoded(decoded string) bool {
	for _, p := range s.patterns {
		if p.regex.MatchString(decoded) {
			return true
		}
	}
	return false
}

// DetectsEncoding returns true if encoding detection is enabled.
func (s *Scanner) DetectsEncoding() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.detectEncoding
}

// -----------------------------------------------------------------------------
// Filtered Writer for Stderr/Output Streams
// -----------------------------------------------------------------------------

// FilteredWriter wraps an io.Writer and applies DLP scanning to all output.
// Use this to filter subprocess stderr or other output streams.
//
// Example:
//
//	filtered := dlp.NewFilteredWriter(os.Stderr, scanner, logger)
//	cmd.Stderr = filtered  // Subprocess stderr now gets DLP scanned
type FilteredWriter struct {
	dest    io.Writer
	scanner *Scanner
	logger  *log.Logger
	prefix  string
}

// NewFilteredWriter creates a writer that scans and redacts output.
//
// Parameters:
//   - dest: The underlying writer (e.g., os.Stderr)
//   - scanner: DLP scanner to use (can be nil to pass through unchanged)
//   - logger: Optional logger for DLP events (can be nil)
//   - prefix: Optional prefix for log messages (e.g., "[stderr]")
func NewFilteredWriter(dest io.Writer, scanner *Scanner, logger *log.Logger, prefix string) *FilteredWriter {
	return &FilteredWriter{
		dest:    dest,
		scanner: scanner,
		logger:  logger,
		prefix:  prefix,
	}
}

// Write implements io.Writer, scanning and redacting content before writing.
func (fw *FilteredWriter) Write(p []byte) (n int, err error) {
	if fw.scanner == nil || !fw.scanner.IsEnabled() {
		// No scanner - pass through unchanged
		return fw.dest.Write(p)
	}

	// Scan and redact the output
	input := string(p)
	redacted, events := fw.scanner.Redact(input)

	// Log DLP events if logger is configured
	if fw.logger != nil && len(events) > 0 {
		for _, event := range events {
			fw.logger.Printf("DLP_STDERR %s: Redacted %d match(es) of %q",
				fw.prefix, event.MatchCount, event.RuleName)
		}
	}

	// Write the redacted output
	written, err := fw.dest.Write([]byte(redacted))
	if err != nil {
		return written, err
	}

	// Return original length to satisfy io.Writer contract
	// (caller expects we consumed all input bytes)
	return len(p), nil
}
