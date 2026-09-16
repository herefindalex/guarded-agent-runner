package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/store"
	"guarded-agent-runner/internal/workflow"
)

const testBearer = "0123456789abcdefghijklmnopqrstuvwxyz-TEST-token"
const testOrigin = "http://127.0.0.1:4173"

type mcpFixture struct {
	database *store.Store
	service  *workflow.Service
	target   *workflow.FakeTarget
	scope    domain.AgentSessionScope
	handler  http.Handler
	now      time.Time
}

func newMCPFixture(t *testing.T) mcpFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	database, err := store.Open(filepath.Join(t.TempDir(), "gar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	enrollment := domain.Enrollment{
		TargetID: "paper-a", EnrollmentID: "enrollment-a", DeploymentGeneration: 2,
		ContainerID: "sha256:container-a", PolicyRevision: "1", PolicyDigest: "policy-a",
		PaperTuple: "paper-test/java-test/itzg-test", AllowedPlugins: []string{"example"},
	}
	artifacts := map[string]domain.ArtifactRecord{
		"artifact-a": {
			ArtifactID: "artifact-a", PluginID: "example", OwnerTrustConfirmed: true,
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		"artifact-b": {
			ArtifactID: "artifact-b", PluginID: "example", OwnerTrustConfirmed: true,
			SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	profile := domain.TransitionProfile{
		ProfileID: "example-a-b", ProfileDigest: "profile-digest", PluginID: "example",
		FromArtifactID: "artifact-a", ToArtifactID: "artifact-b", PaperTuple: enrollment.PaperTuple,
		VerificationProfileID: "verify-a-b", VerificationDigest: "verify-digest",
		RecoveryContractID: "recover-b-a", RecoveryDigest: "recover-digest",
		Eligibility: "VERIFIED_TRANSITION",
	}
	target := &workflow.FakeTarget{
		Observation: domain.ObservationBundle{
			BundleID: "observation-a", EnrollmentID: enrollment.EnrollmentID,
			DeploymentGeneration: enrollment.DeploymentGeneration, ContainerID: enrollment.ContainerID,
			BootID: "boot-a", InventoryDigest: "inventory-a", ConfigDigest: "config-a",
			ActiveArtifacts: map[string]string{"example": "artifact-a"}, CreatedAt: now,
			Readings: map[string]domain.ObservationValue{
				"players": {
					Availability: domain.Available, Value: 0, Source: "paper-guard",
					ObservedAt: now, BootID: "boot-a",
				},
			},
		},
		Responses: map[string]any{
			"get_health": map[string]any{
				"availability": domain.Available, "source": "fake-target", "observed_at": now,
			},
		},
	}
	scope := domain.AgentSessionScope{
		SchemaVersion: "gar.agent-scope.v1", PrincipalID: "agent-a", SessionID: "session-a",
		EnrollmentID: enrollment.EnrollmentID, DeploymentGeneration: enrollment.DeploymentGeneration,
		Capabilities: toolNames(), PluginIDs: []string{"example"}, ArtifactProfileIDs: []string{profile.ProfileID},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), RevocationEpoch: 1,
	}
	if err := scope.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveSession(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	service := &workflow.Service{
		Store: database, Registry: workflow.Registry{
			Enrollment: enrollment, Artifacts: artifacts,
			Profiles: map[string]domain.TransitionProfile{profile.ProfileID: profile},
		},
		Target: target, Support: policy.DefaultM1Profile(), CurrentRevocationEpoch: 1,
		Now: func() time.Time { return now },
	}
	digest := sha256.Sum256([]byte(testBearer))
	credentials := &CredentialSet{entries: []credentialEntry{{digest: digest, sessionID: scope.SessionID}}}
	handler, err := NewHandler(Options{
		Service: service, Store: database, Credentials: credentials, AllowedOrigin: testOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mcpFixture{database: database, service: service, target: target, scope: scope, handler: handler, now: now}
}

func toolNames() []string {
	names := make([]string, 0, len(domain.AgentTools))
	for _, tool := range domain.AgentTools {
		names = append(names, tool.Name)
	}
	return names
}

func TestAuthenticationAndOriginFailClosed(t *testing.T) {
	fixture := newMCPFixture(t)
	server := httptest.NewServer(fixture.handler)
	defer server.Close()

	for _, test := range []struct {
		name, bearer, origin string
		wantStatus           int
	}{
		{name: "missing bearer", origin: testOrigin, wantStatus: http.StatusUnauthorized},
		{name: "wrong bearer", bearer: "this-is-a-wrong-token-longer-than-thirty-two-bytes", origin: testOrigin, wantStatus: http.StatusUnauthorized},
		{name: "bad origin", bearer: testBearer, origin: "https://attacker.invalid", wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			request.Header.Set("Origin", test.origin)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.wantStatus)
			}
		})
	}
}

func TestRevokedScopeCannotInitialize(t *testing.T) {
	fixture := newMCPFixture(t)
	fixture.service.CurrentRevocationEpoch++
	server := httptest.NewServer(fixture.handler)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testBearer)
	request.Header.Set("Origin", testOrigin)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session status = %d, want 401", response.StatusCode)
	}
}

func TestPerSessionHTTPRateLimit(t *testing.T) {
	limits := &sessionRateLimiters{limiters: map[string]*rate.Limiter{
		"session-a": rate.NewLimiter(0, 2),
	}}
	if !limits.allow("session-a") || !limits.allow("session-a") {
		t.Fatal("limiter rejected a request within the configured burst")
	}
	if limits.allow("session-a") {
		t.Fatal("limiter accepted a request beyond the configured burst")
	}
	if !limits.allow("session-b") {
		t.Fatal("one session consumed another session's independent quota")
	}
}

func TestCredentialFileIsHashedStrictAndOwnerOnly(t *testing.T) {
	digest := sha256.Sum256([]byte(testBearer))
	data := CredentialFile{
		SchemaVersion: CredentialSchemaVersion,
		Credentials: []CredentialRecord{{
			CredentialID: "credential-a", TokenSHA256: hex.EncodeToString(digest[:]), SessionID: "session-a",
		}},
	}
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCredentials(path)
	if err != nil || loaded.Len() != 1 {
		t.Fatalf("valid hashed credential file rejected: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("credential file readable by other users was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	rawPayload := append(payload[:len(payload)-1], []byte(`,"token":"`+testBearer+`"}`)...)
	if err := os.WriteFile(path, rawPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("credential schema accepted a raw bearer field")
	}
}

func TestOfficialClientListsExactToolsAndCallsReadTool(t *testing.T) {
	fixture := newMCPFixture(t)
	session := connectMCP(t, fixture.handler)
	defer session.Close()

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		got = append(got, tool.Name)
		if tool.Name == "approve" || tool.Name == "intent-approve" {
			t.Fatalf("agent catalog exposed approval tool %q", tool.Name)
		}
	}
	want := toolNames()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != 10 || !equalStrings(got, want) {
		t.Fatalf("tool names = %v, want exact fixed catalog %v", got, want)
	}

	call, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_health"})
	if err != nil {
		t.Fatal(err)
	}
	if call.IsError || call.StructuredContent == nil {
		t.Fatalf("unexpected read result: %#v", call)
	}

	rejected, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_health", Arguments: map[string]any{"principal_id": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rejected.IsError {
		t.Fatal("strict tool schema accepted caller-supplied principal_id")
	}
}

func TestSensitiveTargetFieldsFailClosedAtMCPBoundary(t *testing.T) {
	fixture := newMCPFixture(t)
	fixture.target.Responses["get_backup_status"] = map[string]any{
		"availability": domain.Available,
		"archive_path": "/owner/private/backups/server.tar",
	}
	fixture.target.Responses["get_players"] = map[string]any{
		"availability": domain.Available,
		"players":      []any{"private-player-name"},
	}
	session := connectMCP(t, fixture.handler)
	defer session.Close()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_backup_status"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("agent boundary returned a backup archive path")
	}
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_players"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("agent boundary returned player identities instead of a count")
	}
}

func TestReconnectProposalIsIdempotentAndNeverMutates(t *testing.T) {
	fixture := newMCPFixture(t)
	firstSession := connectMCP(t, fixture.handler)
	arguments := map[string]any{
		"plugin_id": "example", "target_artifact_id": "artifact-b",
		"client_request_id": "mcp-request-1", "rationale": "bounded test",
	}
	first, err := firstSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "propose_plugin_change", Arguments: arguments,
	})
	if err != nil || first.IsError {
		t.Fatalf("first proposal failed: result=%#v err=%v", first, err)
	}
	_ = firstSession.Close()

	secondSession := connectMCP(t, fixture.handler)
	defer secondSession.Close()
	second, err := secondSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "propose_plugin_change", Arguments: arguments,
	})
	if err != nil || second.IsError {
		t.Fatalf("replayed proposal failed: result=%#v err=%v", second, err)
	}
	firstOutput := first.StructuredContent.(map[string]any)
	secondOutput := second.StructuredContent.(map[string]any)
	if firstOutput["intent_id"] != secondOutput["intent_id"] || firstOutput["intent_digest"] != secondOutput["intent_digest"] {
		t.Fatal("MCP reconnect replaced the frozen idempotent intent")
	}
	if fixture.target.Mutations != 0 {
		t.Fatalf("proposal dispatched %d mutations", fixture.target.Mutations)
	}

	operator := workflow.OperatorService{Store: fixture.database, Now: func() time.Time { return fixture.now }}
	_, operation, err := operator.Approve(context.Background(), firstOutput["intent_id"].(string), firstOutput["intent_digest"].(string), "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	_ = secondSession.Close()
	persisted, err := fixture.database.GetOperation(context.Background(), operation.OperationID)
	if err != nil || persisted.OperationID != operation.OperationID {
		t.Fatalf("MCP disconnect cancelled durable owner-approved operation: %#v %v", persisted, err)
	}
	if fixture.target.Mutations != 0 {
		t.Fatal("owner approval or disconnect dispatched mutation in M2")
	}
}

func TestListenAddressMustBeLiteralLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8787", "[::1]:8787"} {
		if err := ValidateListenAddress(address); err != nil {
			t.Fatalf("%s rejected: %v", address, err)
		}
	}
	for _, address := range []string{":8787", "0.0.0.0:8787", "localhost:8787", "192.0.2.1:8787"} {
		if err := ValidateListenAddress(address); err == nil {
			t.Fatalf("unsafe listen address %s accepted", address)
		}
	}
}

type headerTransport struct {
	base http.RoundTripper
}

func (transport headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+testBearer)
	clone.Header.Set("Origin", testOrigin)
	return transport.base.RoundTrip(clone)
}

func connectMCP(t *testing.T, handler http.Handler) *mcp.ClientSession {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "gar-m2-test", Version: "0.1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             server.URL,
		HTTPClient:           &http.Client{Transport: headerTransport{base: http.DefaultTransport}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
