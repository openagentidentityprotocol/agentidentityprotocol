package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/pkg/policy"
)

func newTestEngine(t *testing.T) *policy.Engine {
	engine := policy.NewEngine()
	err := engine.Load([]byte(`
apiVersion: aip.io/v1alpha2
kind: AgentPolicy
metadata:
  name: test-policy
spec:
  allowed_tools:
    - allowed_tool
    - another_tool
  tool_rules:
    - tool: blocked_tool
      action: block
`))
	if err != nil {
		t.Fatalf("Failed to load test policy: %v", err)
	}
	return engine
}

func TestHandleValidate_AllowedTool(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	req := ValidationRequest{
		Tool:      "allowed_tool",
		Arguments: map[string]any{"arg1": "value1"},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/validate", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleValidate(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var resp ValidationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Decision != "allow" {
		t.Errorf("Expected decision 'allow', got %q", resp.Decision)
	}
}

func TestHandleValidate_BlockedTool(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	req := ValidationRequest{
		Tool:      "blocked_tool",
		Arguments: map[string]any{},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/validate", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleValidate(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var resp ValidationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Decision != "block" {
		t.Errorf("Expected decision 'block', got %q", resp.Decision)
	}
	if len(resp.Violations) == 0 {
		t.Error("Expected violations to be populated")
	}
}

func TestHandleValidate_UnknownTool(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	req := ValidationRequest{
		Tool:      "unknown_tool",
		Arguments: map[string]any{},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/validate", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleValidate(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var resp ValidationResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Decision != "block" {
		t.Errorf("Expected decision 'block' for unknown tool, got %q", resp.Decision)
	}
}

func TestHandleValidate_MethodNotAllowed(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/validate", nil)
	rec := httptest.NewRecorder()

	handler.HandleValidate(rec, httpReq)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestHandleValidate_InvalidJSON(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/validate", strings.NewReader("invalid json"))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleValidate(rec, httpReq)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestHandleValidate_MissingTool(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	req := ValidationRequest{
		Arguments: map[string]any{},
	}
	body, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/validate", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleValidate(rec, httpReq)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	httpReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.HandleHealth(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %q", resp.Status)
	}
	if resp.Version != "v1alpha2" {
		t.Errorf("Expected version 'v1alpha2', got %q", resp.Version)
	}
	if resp.UptimeSeconds < 0 {
		t.Error("Uptime should be non-negative")
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	httpReq := httptest.NewRequest(http.MethodPost, "/health", nil)
	rec := httptest.NewRecorder()

	handler.HandleHealth(rec, httpReq)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestHandleMetrics(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	// Make some requests to generate metrics
	req := ValidationRequest{Tool: "allowed_tool"}
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.HandleValidate(rec, httpReq)

	// Get metrics
	httpReq = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	handler.HandleMetrics(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	body2 := rec.Body.String()
	if !strings.Contains(body2, "aip_requests_total") {
		t.Error("Metrics should contain aip_requests_total")
	}
	if !strings.Contains(body2, "aip_decisions_total") {
		t.Error("Metrics should contain aip_decisions_total")
	}
}

func TestHandleMetrics_MethodNotAllowed(t *testing.T) {
	engine := newTestEngine(t)
	handler := NewHandler(engine, nil)

	httpReq := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.HandleMetrics(rec, httpReq)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}
