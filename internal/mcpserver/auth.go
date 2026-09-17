package mcpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/store"
	"guarded-agent-runner/internal/workflow"
)

const CredentialSchemaVersion = "gar.agent-credentials.v1"

type CredentialRecord struct {
	CredentialID string `json:"credential_id"`
	TokenSHA256  string `json:"token_sha256"`
	SessionID    string `json:"session_id"`
}

type CredentialFile struct {
	SchemaVersion string             `json:"schema_version"`
	Credentials   []CredentialRecord `json:"credentials"`
}

type credentialEntry struct {
	digest    [sha256.Size]byte
	sessionID string
}

type CredentialSet struct {
	entries []credentialEntry
}

type sessionRateLimiters struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newSessionRateLimiters() *sessionRateLimiters {
	return &sessionRateLimiters{limiters: make(map[string]*rate.Limiter)}
}

func (limits *sessionRateLimiters) allow(sessionID string) bool {
	limits.mu.Lock()
	defer limits.mu.Unlock()
	limiter := limits.limiters[sessionID]
	if limiter == nil {
		// GAR-PCS-001 section 21: ten requests/second with a burst of 20.
		limiter = rate.NewLimiter(rate.Limit(10), 20)
		limits.limiters[sessionID] = limiter
	}
	return limiter.Allow()
}

func LoadCredentials(path string) (*CredentialSet, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return nil, fmt.Errorf("credential file security check: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var data CredentialFile
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode credential file: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("credential file contains trailing JSON")
	}
	if data.SchemaVersion != CredentialSchemaVersion {
		return nil, fmt.Errorf("unsupported credential schema %q", data.SchemaVersion)
	}
	if len(data.Credentials) == 0 {
		return nil, fmt.Errorf("credential file contains no credentials")
	}
	set := &CredentialSet{entries: make([]credentialEntry, 0, len(data.Credentials))}
	seenIDs := make(map[string]struct{}, len(data.Credentials))
	seenDigests := make(map[string]struct{}, len(data.Credentials))
	for _, record := range data.Credentials {
		if record.CredentialID == "" || record.SessionID == "" {
			return nil, fmt.Errorf("credential_id and session_id are required")
		}
		if _, exists := seenIDs[record.CredentialID]; exists {
			return nil, fmt.Errorf("duplicate credential_id %q", record.CredentialID)
		}
		digestBytes, err := hex.DecodeString(record.TokenSHA256)
		if err != nil || len(digestBytes) != sha256.Size || record.TokenSHA256 != strings.ToLower(record.TokenSHA256) {
			return nil, fmt.Errorf("credential %q has invalid full lowercase SHA-256", record.CredentialID)
		}
		if _, exists := seenDigests[record.TokenSHA256]; exists {
			return nil, fmt.Errorf("duplicate bearer digest")
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		set.entries = append(set.entries, credentialEntry{digest: digest, sessionID: record.SessionID})
		seenIDs[record.CredentialID] = struct{}{}
		seenDigests[record.TokenSHA256] = struct{}{}
	}
	return set, nil
}

func (set *CredentialSet) resolve(ctx context.Context, database *store.Store, token string) (domain.AgentSessionScope, error) {
	if len(token) < 32 || len(token) > 512 {
		return domain.AgentSessionScope{}, domain.NewError(domain.ErrScopeDenied, "invalid bearer credential")
	}
	digest := sha256.Sum256([]byte(token))
	matched := -1
	for index := range set.entries {
		if subtle.ConstantTimeCompare(digest[:], set.entries[index].digest[:]) == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return domain.AgentSessionScope{}, domain.NewError(domain.ErrScopeDenied, "invalid bearer credential")
	}
	return database.GetSession(ctx, set.entries[matched].sessionID)
}

func (set *CredentialSet) Len() int { return len(set.entries) }

// ValidateSessions lets garctl doctor prove that every bearer mapping resolves
// to a currently valid, fixed scope for this configured deployment.
func (set *CredentialSet) ValidateSessions(ctx context.Context, database *store.Store, enrollmentID string, generation, revocationEpoch int64, now time.Time) error {
	for _, entry := range set.entries {
		scope, err := database.GetSession(ctx, entry.sessionID)
		if err != nil {
			return err
		}
		if err := scope.Validate(now); err != nil {
			return err
		}
		if scope.EnrollmentID != enrollmentID || scope.DeploymentGeneration != generation {
			return domain.NewError(domain.ErrScopeDenied, "credential resolves to a session for another enrollment generation")
		}
		if scope.RevocationEpoch != revocationEpoch {
			return domain.NewError(domain.ErrScopeDenied, "credential resolves to a revoked session epoch")
		}
	}
	return nil
}

type scopeContextKey struct{}

func scopeFromContext(ctx context.Context) (domain.AgentSessionScope, bool) {
	scope, ok := ctx.Value(scopeContextKey{}).(domain.AgentSessionScope)
	return scope, ok
}

func authorizationMiddleware(database *store.Store, credentials *CredentialSet, service *workflow.Service, limits *sessionRateLimiters, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			unauthorized(response)
			return
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			unauthorized(response)
			return
		}
		scope, err := credentials.resolve(request.Context(), database, parts[1])
		if err != nil {
			unauthorized(response)
			return
		}
		if err := scope.Validate(time.Now().UTC()); err != nil ||
			scope.EnrollmentID != service.Registry.Enrollment.EnrollmentID ||
			scope.DeploymentGeneration != service.Registry.Enrollment.DeploymentGeneration ||
			scope.RevocationEpoch != service.CurrentRevocationEpoch {
			unauthorized(response)
			return
		}
		if !limits.allow(scope.SessionID) {
			response.Header().Set("Retry-After", "1")
			http.Error(response, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), scopeContextKey{}, scope)))
	})
}

func unauthorized(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", `Bearer realm="gar-mcp"`)
	http.Error(response, "unauthorized", http.StatusUnauthorized)
}
