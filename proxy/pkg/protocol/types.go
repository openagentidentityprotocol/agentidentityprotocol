// Package protocol defines JSON-RPC 2.0 message structures for MCP communication.
//
// The AIP proxy intercepts MCP traffic, which uses JSON-RPC 2.0 as its transport
// protocol. These types allow us to decode incoming messages, inspect them for
// policy enforcement, and construct appropriate responses when blocking requests.
//
// JSON-RPC 2.0 Specification: https://www.jsonrpc.org/specification
// MCP Specification: https://modelcontextprotocol.io/specification
package protocol

import "encoding/json"

// -----------------------------------------------------------------------------
// JSON-RPC 2.0 Core Types
// -----------------------------------------------------------------------------

// Request represents a JSON-RPC 2.0 request message.
//
// In the MCP protocol, the client (agent) sends requests to invoke server methods.
// The proxy intercepts these requests to apply policy checks before forwarding
// to the target MCP server.
//
// Example MCP tool call request:
//
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "method": "tools/call",
//	  "params": {
//	    "name": "github_create_issue",
//	    "arguments": {"repo": "myrepo", "title": "Bug"}
//	  }
//	}
type Request struct {
	// JSONRPC must be exactly "2.0" per specification.
	JSONRPC string `json:"jsonrpc"`

	// ID is the request identifier. Can be string, number, or null.
	// Used to correlate responses with requests.
	// Notifications (requests without ID) do not expect a response.
	ID json.RawMessage `json:"id,omitempty"`

	// Method is the name of the RPC method to invoke.
	// MCP uses methods like "tools/list", "tools/call", "resources/read", etc.
	Method string `json:"method"`

	// Params contains method-specific parameters.
	// Stored as raw JSON to allow flexible parsing based on method type.
	Params json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response message.
//
// The proxy constructs error responses when blocking forbidden tool calls,
// preventing the request from reaching the target server.
type Response struct {
	// JSONRPC must be exactly "2.0" per specification.
	JSONRPC string `json:"jsonrpc"`

	// ID must match the request ID this response corresponds to.
	// For error responses to blocked requests, we echo back the original ID.
	ID json.RawMessage `json:"id,omitempty"`

	// Result contains the method's return value on success.
	// Mutually exclusive with Error.
	Result json.RawMessage `json:"result,omitempty"`

	// Error contains error information on failure.
	// Mutually exclusive with Result.
	Error *Error `json:"error,omitempty"`
}

// Error represents a JSON-RPC 2.0 error object.
//
// Standard error codes (from spec):
//   - -32700: Parse error
//   - -32600: Invalid Request
//   - -32601: Method not found
//   - -32602: Invalid params
//   - -32603: Internal error
//
// AIP-specific error codes (custom range -32000 to -32099):
//   - -32001: Forbidden - Policy denied the tool call
//   - -32002: Rate limited
//   - -32003: Session expired
type Error struct {
	// Code is a number indicating the error type.
	Code int `json:"code"`

	// Message is a short description of the error.
	Message string `json:"message"`

	// Data contains additional information about the error.
	// Optional and may contain any JSON value.
	Data any `json:"data,omitempty"`
}

// -----------------------------------------------------------------------------
// MCP-Specific Parameter Types
// -----------------------------------------------------------------------------

// ToolCallParams represents the parameters for a "tools/call" method.
//
// When the proxy sees method="tools/call", it unmarshals Params into this
// struct to extract the tool name for policy checking.
type ToolCallParams struct {
	// Name is the identifier of the tool being invoked.
	// This is the primary field used for policy enforcement.
	// Examples: "github_create_issue", "postgres_query", "slack_post_message"
	Name string `json:"name"`

	// Arguments contains tool-specific parameters.
	// The proxy does not inspect these for basic allow/deny decisions,
	// but future versions may support argument-level constraints.
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// -----------------------------------------------------------------------------
// AIP Error Codes
// -----------------------------------------------------------------------------

const (
	// ErrCodeForbidden indicates the policy engine denied the request.
	// Returned when a tool call is blocked by agent.yaml policy.
	ErrCodeForbidden = -32001

	// ErrCodeRateLimited indicates the agent exceeded rate limits.
	ErrCodeRateLimited = -32002

	// ErrCodeSessionExpired indicates the agent's session has expired.
	ErrCodeSessionExpired = -32003

	// ErrCodeUserDenied indicates the user explicitly denied the request.
	// Returned when a tool call with action="ask" was rejected by the user.
	ErrCodeUserDenied = -32004

	// ErrCodeUserTimeout indicates the user did not respond in time.
	// Returned when a tool call with action="ask" timed out waiting for user input.
	ErrCodeUserTimeout = -32005
)

// -----------------------------------------------------------------------------
// Constructor Functions
// -----------------------------------------------------------------------------

// NewForbiddenError creates a JSON-RPC error response for blocked tool calls.
//
// This is the primary response type used when the policy engine denies a request.
// The error includes details about which tool was blocked to aid debugging.
func NewForbiddenError(requestID json.RawMessage, toolName string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &Error{
			Code:    ErrCodeForbidden,
			Message: "Forbidden",
			Data: map[string]string{
				"tool":   toolName,
				"reason": "Tool not in allowed_tools list",
			},
		},
	}
}

// NewArgumentError creates a JSON-RPC error response for argument validation failures.
//
// This is used when a tool is allowed but an argument fails regex validation.
// The error includes the specific argument that failed for debugging.
func NewArgumentError(requestID json.RawMessage, toolName, argName, pattern string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &Error{
			Code:    ErrCodeForbidden,
			Message: "Argument validation failed",
			Data: map[string]string{
				"tool":    toolName,
				"arg":     argName,
				"pattern": pattern,
				"reason":  "Argument validation failed for " + argName,
			},
		},
	}
}

// NewParseError creates a JSON-RPC error response for malformed messages.
func NewParseError(requestID json.RawMessage, detail string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &Error{
			Code:    -32700,
			Message: "Parse error",
			Data:    detail,
		},
	}
}

// NewUserDeniedError creates a JSON-RPC error response when user denies a tool call.
//
// This is used when a tool with action="ask" is rejected by the user
// via the native OS dialog prompt.
func NewUserDeniedError(requestID json.RawMessage, toolName string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &Error{
			Code:    ErrCodeUserDenied,
			Message: "User denied",
			Data: map[string]string{
				"tool":   toolName,
				"reason": "User explicitly denied the tool call via approval dialog",
			},
		},
	}
}

// NewUserTimeoutError creates a JSON-RPC error response when user approval times out.
//
// This is used when a tool with action="ask" does not receive user input
// within the configured timeout period (default: 60 seconds).
func NewUserTimeoutError(requestID json.RawMessage, toolName string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &Error{
			Code:    ErrCodeUserTimeout,
			Message: "User approval timeout",
			Data: map[string]string{
				"tool":   toolName,
				"reason": "User did not respond to approval dialog within timeout",
			},
		},
	}
}

// IsToolCall checks if a request is a tool invocation that needs policy checking.
func (r *Request) IsToolCall() bool {
	return r.Method == "tools/call"
}

// GetToolName extracts the tool name from a tools/call request.
// Returns empty string if params cannot be parsed or name is missing.
func (r *Request) GetToolName() string {
	if !r.IsToolCall() {
		return ""
	}

	var params ToolCallParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return ""
	}
	return params.Name
}

// GetToolArgs extracts the tool arguments from a tools/call request.
// Returns nil if params cannot be parsed or arguments are missing.
func (r *Request) GetToolArgs() map[string]any {
	if !r.IsToolCall() {
		return nil
	}

	var params ToolCallParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return nil
	}

	if params.Arguments == nil {
		return make(map[string]any)
	}

	var args map[string]any
	if err := json.Unmarshal(params.Arguments, &args); err != nil {
		return nil
	}
	return args
}
