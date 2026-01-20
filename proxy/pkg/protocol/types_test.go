// Package protocol tests for JSON-RPC message handling.
package protocol

import (
	"encoding/json"
	"testing"
)

// TestIsToolCallCaseInsensitive verifies that IsToolCall() is case-insensitive.
//
// SECURITY: This test prevents CVE-like bypass attacks where an attacker
// sends "Tools/Call" or "TOOLS/CALL" to bypass policy enforcement.
// The method name must be matched case-insensitively per JSON-RPC convention.
func TestIsToolCallCaseInsensitive(t *testing.T) {
	testCases := []struct {
		method string
		want   bool
	}{
		// Standard lowercase - should match
		{"tools/call", true},
		// Mixed case variants - MUST match (security critical)
		{"Tools/Call", true},
		{"TOOLS/CALL", true},
		{"Tools/call", true},
		{"tools/Call", true},
		{"TOOLS/call", true},
		{"tools/CALL", true},
		// Non-matching methods - should not match
		{"tools/list", false},
		{"resources/read", false},
		{"", false},
		{"toolscall", false},
		{"tools call", false},
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			req := &Request{Method: tc.method}
			got := req.IsToolCall()
			if got != tc.want {
				t.Errorf("IsToolCall() for method %q = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}

// TestGetToolName verifies tool name extraction from requests.
func TestGetToolName(t *testing.T) {
	testCases := []struct {
		name   string
		req    *Request
		want   string
	}{
		{
			name: "valid tools/call",
			req: &Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"name": "github_get_repo", "arguments": {}}`),
			},
			want: "github_get_repo",
		},
		{
			name: "tools/call with mixed case method",
			req: &Request{
				Method: "Tools/Call",
				Params: json.RawMessage(`{"name": "dangerous_tool"}`),
			},
			want: "dangerous_tool",
		},
		{
			name: "non-tools/call method",
			req: &Request{
				Method: "tools/list",
				Params: json.RawMessage(`{"name": "should_not_extract"}`),
			},
			want: "",
		},
		{
			name: "invalid params JSON",
			req: &Request{
				Method: "tools/call",
				Params: json.RawMessage(`invalid json`),
			},
			want: "",
		},
		{
			name: "missing name field",
			req: &Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"arguments": {}}`),
			},
			want: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.req.GetToolName()
			if got != tc.want {
				t.Errorf("GetToolName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGetToolArgs verifies argument extraction from requests.
func TestGetToolArgs(t *testing.T) {
	testCases := []struct {
		name     string
		req      *Request
		wantNil  bool
		wantKeys []string
	}{
		{
			name: "valid args",
			req: &Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"name": "test", "arguments": {"path": "/tmp", "mode": "read"}}`),
			},
			wantNil:  false,
			wantKeys: []string{"path", "mode"},
		},
		{
			name: "empty args object",
			req: &Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"name": "test", "arguments": {}}`),
			},
			wantNil:  false,
			wantKeys: []string{},
		},
		{
			name: "missing arguments field",
			req: &Request{
				Method: "tools/call",
				Params: json.RawMessage(`{"name": "test"}`),
			},
			wantNil:  false,
			wantKeys: []string{},
		},
		{
			name: "non-tools/call method",
			req: &Request{
				Method: "tools/list",
				Params: json.RawMessage(`{"name": "test", "arguments": {"key": "value"}}`),
			},
			wantNil: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.req.GetToolArgs()
			if tc.wantNil {
				if got != nil {
					t.Errorf("GetToolArgs() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("GetToolArgs() = nil, want non-nil")
			}
			for _, key := range tc.wantKeys {
				if _, ok := got[key]; !ok {
					t.Errorf("GetToolArgs() missing expected key %q", key)
				}
			}
		})
	}
}

// TestErrorResponseFormat verifies JSON-RPC error responses are well-formed.
func TestErrorResponseFormat(t *testing.T) {
	testCases := []struct {
		name     string
		resp     *Response
		wantCode int
	}{
		{
			name:     "forbidden error",
			resp:     NewForbiddenError(json.RawMessage(`1`), "dangerous_tool"),
			wantCode: ErrCodeForbidden,
		},
		{
			name:     "argument error",
			resp:     NewArgumentError(json.RawMessage(`2`), "fetch_url", "url", "^https://.*"),
			wantCode: ErrCodeForbidden,
		},
		{
			name:     "user denied error",
			resp:     NewUserDeniedError(json.RawMessage(`3`), "exec_command"),
			wantCode: ErrCodeUserDenied,
		},
		{
			name:     "rate limited error",
			resp:     NewRateLimitedError(json.RawMessage(`4`), "api_call"),
			wantCode: ErrCodeRateLimited,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify JSONRPC version
			if tc.resp.JSONRPC != "2.0" {
				t.Errorf("JSONRPC = %q, want %q", tc.resp.JSONRPC, "2.0")
			}

			// Verify error is present
			if tc.resp.Error == nil {
				t.Fatal("Error is nil")
			}

			// Verify error code
			if tc.resp.Error.Code != tc.wantCode {
				t.Errorf("Error.Code = %d, want %d", tc.resp.Error.Code, tc.wantCode)
			}

			// Verify response serializes to valid JSON
			data, err := json.Marshal(tc.resp)
			if err != nil {
				t.Fatalf("Failed to marshal response: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("Response is not valid JSON: %v", err)
			}
		})
	}
}
