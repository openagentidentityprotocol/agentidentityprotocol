package identity

import (
	"testing"
	"time"
)

func TestNewSession(t *testing.T) {
	policyData := []byte(`{"apiVersion": "aip.io/v1alpha2"}`)
	config := &Config{
		Enabled:          true,
		TokenTTL:         "5m",
		RotationInterval: "4m",
		SessionBinding:   SessionBindingProcess,
	}

	session, err := NewSession("test-agent", "/path/policy.yaml", policyData, config)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if session.ID == "" {
		t.Error("Session ID should not be empty")
	}
	if session.AgentID != "test-agent" {
		t.Errorf("AgentID = %q, want %q", session.AgentID, "test-agent")
	}
	if session.PolicyHash == "" {
		t.Error("PolicyHash should not be empty")
	}
	if session.PolicyPath != "/path/policy.yaml" {
		t.Errorf("PolicyPath = %q, want %q", session.PolicyPath, "/path/policy.yaml")
	}
}

func TestSessionIssueToken(t *testing.T) {
	policyData := []byte(`test policy`)
	session, _ := NewSession("test", "/path", policyData, &Config{
		Enabled:  true,
		TokenTTL: "5m",
	})

	token, err := session.IssueToken()
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	if token.AgentID != session.AgentID {
		t.Errorf("Token AgentID = %q, want %q", token.AgentID, session.AgentID)
	}
	if token.SessionID != session.ID {
		t.Errorf("Token SessionID = %q, want %q", token.SessionID, session.ID)
	}
	if token.PolicyHash != session.PolicyHash {
		t.Errorf("Token PolicyHash = %q, want %q", token.PolicyHash, session.PolicyHash)
	}
}

func TestSessionValidateToken(t *testing.T) {
	policyData := []byte(`test policy`)
	session, _ := NewSession("test", "/path", policyData, &Config{
		Enabled:        true,
		TokenTTL:       "5m",
		SessionBinding: SessionBindingProcess,
	})

	token, _ := session.IssueToken()

	// Valid token
	result := session.ValidateToken(token)
	if !result.Valid {
		t.Errorf("Token should be valid, got error: %s", result.Error)
	}

	// Expired token
	expiredToken, _ := NewToken("test", session.PolicyHash, session.ID, -1*time.Second, nil)
	result = session.ValidateToken(expiredToken)
	if result.Valid {
		t.Error("Expired token should not be valid")
	}
	if result.Error != "token_expired" {
		t.Errorf("Expected error 'token_expired', got %q", result.Error)
	}

	// Wrong policy hash
	wrongHashToken, _ := NewToken("test", "wrong-hash", session.ID, 5*time.Minute, nil)
	result = session.ValidateToken(wrongHashToken)
	if result.Valid {
		t.Error("Token with wrong policy hash should not be valid")
	}
	if result.Error != "policy_changed" {
		t.Errorf("Expected error 'policy_changed', got %q", result.Error)
	}

	// Wrong session ID
	wrongSessionToken, _ := NewToken("test", session.PolicyHash, "wrong-session", 5*time.Minute, nil)
	result = session.ValidateToken(wrongSessionToken)
	if result.Valid {
		t.Error("Token with wrong session ID should not be valid")
	}
	if result.Error != "session_mismatch" {
		t.Errorf("Expected error 'session_mismatch', got %q", result.Error)
	}

	// Wrong version
	wrongVersionToken, _ := NewToken("test", session.PolicyHash, session.ID, 5*time.Minute, nil)
	wrongVersionToken.Version = "invalid/version"
	result = session.ValidateToken(wrongVersionToken)
	if result.Valid {
		t.Error("Token with wrong version should not be valid")
	}
	if result.Error != "token_version_mismatch" {
		t.Errorf("Expected error 'token_version_mismatch', got %q", result.Error)
	}
}

func TestSessionShouldRotate(t *testing.T) {
	policyData := []byte(`test`)
	session, _ := NewSession("test", "/path", policyData, &Config{
		Enabled:          true,
		TokenTTL:         "10s",
		RotationInterval: "8s",
	})

	// No token yet = should rotate
	if !session.ShouldRotate() {
		t.Error("Should rotate when no token exists")
	}

	// Issue token
	_, _ = session.IssueToken()

	// Fresh token = should not rotate
	if session.ShouldRotate() {
		t.Error("Should not rotate immediately after issuing token")
	}
}

func TestSessionStats(t *testing.T) {
	policyData := []byte(`test`)
	session, _ := NewSession("stats-test", "/path", policyData, &Config{
		Enabled:  true,
		TokenTTL: "5m",
	})

	stats := session.GetStats()
	if stats.SessionID != session.ID {
		t.Errorf("Stats SessionID = %q, want %q", stats.SessionID, session.ID)
	}
	if stats.AgentID != "stats-test" {
		t.Errorf("Stats AgentID = %q, want %q", stats.AgentID, "stats-test")
	}
	if stats.HasToken {
		t.Error("Should not have token before issuing")
	}

	_, _ = session.IssueToken()
	stats = session.GetStats()
	if !stats.HasToken {
		t.Error("Should have token after issuing")
	}
	if stats.TokenExpiry == "" {
		t.Error("TokenExpiry should be set")
	}
}

func TestComputePolicyHash(t *testing.T) {
	// Same content = same hash
	hash1 := ComputePolicyHash([]byte(`{"key": "value"}`))
	hash2 := ComputePolicyHash([]byte(`{"key": "value"}`))
	if hash1 != hash2 {
		t.Error("Same content should produce same hash")
	}

	// Different content = different hash
	hash3 := ComputePolicyHash([]byte(`{"key": "different"}`))
	if hash1 == hash3 {
		t.Error("Different content should produce different hash")
	}

	// Hash should be hex string
	if len(hash1) != 64 {
		t.Errorf("SHA-256 hex hash should be 64 chars, got %d", len(hash1))
	}
}
