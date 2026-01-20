// Package ui implements human-in-the-loop approval dialogs for AIP.
//
// This package provides native OS dialog integration for the "ask" action
// in policy rules. When a tool call requires user approval, the proxy
// spawns a native dialog box asking the user to Approve or Deny the action.
//
// Platform Support:
//   - macOS: Uses native Cocoa dialogs
//   - Linux: Uses zenity/kdialog (GTK/Qt)
//   - Windows: Uses native Win32 dialogs
//
// Headless Environment Handling:
//
//	When running in a headless environment (CI/CD, containers, SSH without
//	display), the dialog will fail to spawn. In this case, we default to
//	DENY for security (fail-closed behavior).
//
// Timeout Behavior:
//
//	To prevent blocking the agent indefinitely, dialog prompts have a
//	configurable timeout (default: 60 seconds). If the user doesn't respond
//	within the timeout, the request is automatically DENIED.
package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/gen2brain/dlgs"
)

// DefaultTimeout is the default duration to wait for user response.
// After this duration, the request is automatically denied.
const DefaultTimeout = 60 * time.Second

// PrompterConfig holds configuration for the user prompt system.
type PrompterConfig struct {
	// Timeout is the maximum time to wait for user response.
	// Default: 60 seconds. If zero, DefaultTimeout is used.
	Timeout time.Duration

	// Title is the dialog window title.
	// Default: "AIP Security Alert"
	Title string
}

// Prompter handles user approval dialogs.
//
// The prompter is designed to be called from the proxy's main loop
// when a tool call has action="ask" in its policy rule.
type Prompter struct {
	cfg PrompterConfig
}

// NewPrompter creates a new Prompter with the given configuration.
// If cfg is nil, default configuration is used.
func NewPrompter(cfg *PrompterConfig) *Prompter {
	p := &Prompter{
		cfg: PrompterConfig{
			Timeout: DefaultTimeout,
			Title:   "AIP Security Alert",
		},
	}
	if cfg != nil {
		if cfg.Timeout > 0 {
			p.cfg.Timeout = cfg.Timeout
		}
		if cfg.Title != "" {
			p.cfg.Title = cfg.Title
		}
	}
	return p
}

// AskUser displays a native OS dialog asking the user to approve a tool call.
//
// Parameters:
//   - tool: The name of the tool being invoked
//   - args: The arguments passed to the tool (displayed as JSON)
//
// Returns:
//   - true if user clicked "Yes" (approve)
//   - false if user clicked "No" (deny), timeout occurred, or dialog failed
//
// Security Note:
//
//	This function defaults to DENY (false) in all failure cases:
//	- Dialog failed to spawn (headless environment)
//	- User didn't respond within timeout
//	- Any unexpected error occurred
//
// This implements fail-closed security behavior.
func (p *Prompter) AskUser(tool string, args map[string]any) bool {
	return p.AskUserContext(context.Background(), tool, args)
}

// AskUserContext is like AskUser but accepts a context for cancellation.
// The context timeout takes precedence over the configured timeout.
func (p *Prompter) AskUserContext(ctx context.Context, tool string, args map[string]any) bool {
	// Build the message
	message := p.buildMessage(tool, args)

	// Create result channel
	resultCh := make(chan bool, 1)

	// Spawn dialog in goroutine (dlgs.Question is blocking)
	go func() {
		approved, err := dlgs.Question(p.cfg.Title, message, true)
		if err != nil {
			// Dialog failed (headless environment, display error, etc.)
			// Default to DENY for security
			resultCh <- false
			return
		}
		resultCh <- approved
	}()

	// Determine effective timeout
	timeout := p.cfg.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		ctxTimeout := time.Until(deadline)
		if ctxTimeout < timeout {
			timeout = ctxTimeout
		}
	}

	// Wait for result with timeout
	select {
	case result := <-resultCh:
		return result
	case <-time.After(timeout):
		// Timeout - default to DENY
		return false
	case <-ctx.Done():
		// Context cancelled - default to DENY
		return false
	}
}

// buildMessage constructs the dialog message content.
func (p *Prompter) buildMessage(tool string, args map[string]any) string {
	// Format arguments as JSON for display
	argsJSON := "{}"
	if args != nil && len(args) > 0 {
		if data, err := json.MarshalIndent(args, "", "  "); err == nil {
			argsJSON = string(data)
		}
	}

	return fmt.Sprintf(
		"An agent wants to execute a tool that requires your approval.\n\n"+
			"Tool: %s\n\n"+
			"Arguments:\n%s\n\n"+
			"Do you want to allow this action?",
		tool, argsJSON,
	)
}

// IsHeadless returns true if we're likely running in a headless environment.
//
// This is a best-effort detection that checks for common indicators:
//   - DISPLAY environment variable not set (Linux/Unix)
//   - Running in a container (checking for /.dockerenv)
//   - CI environment variables present
//
// Note: This is not foolproof. The actual dialog call may still fail
// in some headless environments, which is handled gracefully.
func IsHeadless() bool {
	// Check for common CI environment variables
	ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "TRAVIS"}
	for _, v := range ciVars {
		if os.Getenv(v) != "" {
			return true
		}
	}

	// Check for Docker container (common indicator)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// On Linux/Unix, check for DISPLAY (X11) or WAYLAND_DISPLAY
	// Note: This doesn't apply to macOS which uses Cocoa
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		// Only consider headless on non-macOS systems
		// macOS uses Cocoa dialogs which don't need DISPLAY
		// We detect this by checking if we're on Darwin (handled by dlgs internally)
		// For simplicity, we assume if both are empty and it's not explicitly macOS,
		// we might be headless. dlgs will handle the actual failure gracefully.
		return false // Let dlgs try; it handles platform detection better
	}

	return false
}
