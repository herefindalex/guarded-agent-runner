package domain

import (
	"strings"
	"testing"
	"time"
)

func TestScopeDigestDetectsMutation(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	scope := AgentSessionScope{
		SchemaVersion: "gar.agent-scope.v1", PrincipalID: "agent-a", SessionID: "session-a",
		EnrollmentID: "enrollment-a", DeploymentGeneration: 7,
		Capabilities: []string{"get_health", "propose_plugin_change"},
		PluginIDs:    []string{"example"}, ArtifactProfileIDs: []string{"example-a-b"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), RevocationEpoch: 1,
	}
	if err := scope.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := scope.Validate(now); err != nil {
		t.Fatal(err)
	}
	scope.Capabilities = append(scope.Capabilities, "intent-approve")
	if err := scope.Validate(now); CodeOf(err) != ErrScopeDenied {
		t.Fatalf("expected SCOPE_DENIED, got %v", err)
	}
}

func TestCanonicalAuthorityPayloadRejectsFloat(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"unsafe": 0.1})
	if err == nil || !strings.Contains(err.Error(), "floating-point") {
		t.Fatalf("expected float rejection, got %v", err)
	}
}
