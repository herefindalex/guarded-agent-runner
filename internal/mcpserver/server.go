// Package mcpserver exposes only the fixed GAR agent contract over the
// official MCP Streamable HTTP transport.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
	"guarded-agent-runner/internal/workflow"
)

const DefaultMaxRequestBodyBytes = 64 * 1024
const maxToolResponseBytes = 256 * 1024

type Options struct {
	Service       *workflow.Service
	Store         *store.Store
	Credentials   *CredentialSet
	AllowedOrigin string
	MaxBodyBytes  int64
}

type noArguments struct{}

type boundedReadArguments struct {
	Cursor *string `json:"cursor,omitempty" jsonschema:"opaque cursor from the previous response"`
	Limit  *int    `json:"limit,omitempty" jsonschema:"maximum number of entries, from 1 through 200"`
}

type proposalArguments struct {
	PluginID         string `json:"plugin_id" jsonschema:"owner-registered plugin ID"`
	TargetArtifactID string `json:"target_artifact_id" jsonschema:"owner-registered target artifact ID"`
	ClientRequestID  string `json:"client_request_id" jsonschema:"caller-generated idempotency key"`
	Rationale        string `json:"rationale" jsonschema:"untrusted explanatory text; never authority"`
}

type operationArguments struct {
	Reference string `json:"reference" jsonschema:"own client request, intent, operation, or step ID"`
}

func NewHandler(options Options) (http.Handler, error) {
	if options.Service == nil || options.Store == nil || options.Credentials == nil {
		return nil, fmt.Errorf("MCP service, store, and credential set are required")
	}
	allowedOrigin, err := ValidateAllowedOrigin(options.AllowedOrigin)
	if err != nil {
		return nil, err
	}
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = DefaultMaxRequestBodyBytes
	}
	if maxBodyBytes < 1 || maxBodyBytes > 1<<20 {
		return nil, fmt.Errorf("MCP request body limit must be from 1 through 1048576 bytes")
	}

	transport := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		scope, ok := scopeFromContext(request.Context())
		if !ok {
			// The authentication middleware is the only route to this handler.
			// A server with no registered tools is fail-closed if this invariant is
			// violated by future wiring.
			return mcp.NewServer(&mcp.Implementation{Name: "guarded-agent-runner-denied", Version: "0.1"}, nil)
		}
		return newScopedServer(options.Service, scope)
	}, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,
		MaxRequestBodyBytes: maxBodyBytes,
	})

	handler := authorizationMiddleware(options.Store, options.Credentials, options.Service, newSessionRateLimiters(), transport)
	handler = originMiddleware(allowedOrigin, handler)
	return handler, nil
}

func newScopedServer(service *workflow.Service, scope domain.AgentSessionScope) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "guarded-agent-runner",
		Version: "0.1",
	}, &mcp.ServerOptions{
		Instructions: "Read bounded Paper evidence, propose only owner-registered plugin transitions, and query only this principal's operations. Approval is owner-local and is never an MCP tool.",
		PageSize:     10,
	})

	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPointer(false)}
	proposalHints := &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: boolPointer(false), IdempotentHint: true, OpenWorldHint: boolPointer(false)}

	registerNoArgumentRead(server, service, scope, "inspect_server_identity", "Return fixed enrollment identity, support profile, and mutation limitations.", readOnly)
	registerNoArgumentRead(server, service, scope, "get_health", "Return bounded process, ping, guard, boot, readiness, and maintenance observations.", readOnly)
	registerNoArgumentRead(server, service, scope, "get_players", "Return player count without names or UUIDs.", readOnly)
	registerNoArgumentRead(server, service, scope, "get_performance", "Return available TPS, MSPT, CPU, memory, and disk observations with quality metadata.", readOnly)
	registerBoundedRead(server, service, scope, "get_recent_errors", "Return bounded structured errors and limited untrusted log context.", readOnly)
	registerNoArgumentRead(server, service, scope, "list_plugins", "Return bounded runtime plugin inventory and owner-registered transition metadata.", readOnly)
	registerBoundedRead(server, service, scope, "get_recent_changes", "Return bounded GAR changes and observed drift without inventing history.", readOnly)
	registerNoArgumentRead(server, service, scope, "get_backup_status", "Return backup metadata and integrity state without paths or archives.", readOnly)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "propose_plugin_change",
		Description: "Compile one owner-registered plugin artifact transition into a frozen intent. This never approves or dispatches mutation.",
		Annotations: proposalHints,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input proposalArguments) (*mcp.CallToolResult, any, error) {
		record, err := service.Propose(ctx, scope, domain.ProposalInput{
			PluginID: input.PluginID, TargetArtifactID: input.TargetArtifactID,
			ClientRequestID: input.ClientRequestID, Rationale: input.Rationale,
		})
		if err != nil {
			return nil, nil, err
		}
		output := map[string]any{
			"intent_id": record.Intent.IntentID, "intent_digest": record.Intent.IntentDigest,
			"status": record.Status, "approval_required": true,
			"mutation_dispatched": false, "approval_interface": "owner-local garctl only",
		}
		return nil, output, validatePublicResult(output)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_operation",
		Description: "Return this principal's intent or operation by client request, intent, operation, or step reference.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input operationArguments) (*mcp.CallToolResult, any, error) {
		if input.Reference == "" || len(input.Reference) > 256 {
			return nil, nil, domain.NewError(domain.ErrInvalidRequest, "reference must contain 1 through 256 bytes")
		}
		output, err := service.GetOwnOperation(ctx, scope, input.Reference)
		if err != nil {
			return nil, nil, err
		}
		return nil, output, validatePublicResult(output)
	})

	return server
}

func registerNoArgumentRead(server *mcp.Server, service *workflow.Service, scope domain.AgentSessionScope, name, description string, annotations *mcp.ToolAnnotations) {
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, Annotations: annotations},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArguments) (*mcp.CallToolResult, any, error) {
			output, err := service.CallReadTool(ctx, scope, name, map[string]any{})
			if err != nil {
				return nil, nil, err
			}
			return nil, output, validatePublicResult(output)
		})
}

func registerBoundedRead(server *mcp.Server, service *workflow.Service, scope domain.AgentSessionScope, name, description string, annotations *mcp.ToolAnnotations) {
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, Annotations: annotations},
		func(ctx context.Context, _ *mcp.CallToolRequest, input boundedReadArguments) (*mcp.CallToolResult, any, error) {
			arguments := make(map[string]any, 2)
			if input.Cursor != nil {
				arguments["cursor"] = *input.Cursor
			}
			if input.Limit != nil {
				arguments["limit"] = *input.Limit
			}
			output, err := service.CallReadTool(ctx, scope, name, arguments)
			if err != nil {
				return nil, nil, err
			}
			return nil, output, validatePublicResult(output)
		})
}

func ValidateAllowedOrigin(origin string) (string, error) {
	if origin == "" {
		return "", fmt.Errorf("an exact allowed Origin is required")
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("allowed Origin must be an exact HTTP(S) origin without path, query, fragment, or userinfo")
	}
	return origin, nil
}

func originMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		origins := request.Header.Values("Origin")
		if len(origins) > 1 || (len(origins) == 1 && origins[0] != allowedOrigin) ||
			strings.EqualFold(request.Header.Get("Sec-Fetch-Site"), "cross-site") {
			http.Error(response, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func ValidateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("listen address must include a literal loopback IP and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address must use a literal loopback IP")
	}
	return nil
}

func validatePublicResult(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > maxToolResponseBytes {
		return domain.NewError(domain.ErrInvalidRequest, "tool response exceeds 256 KiB evidence limit")
	}
	var generic any
	if err := json.Unmarshal(payload, &generic); err != nil {
		return err
	}
	return rejectSensitiveFields(generic)
}

func rejectSensitiveFields(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(key)
			if lower == "players" {
				if _, isCount := child.(float64); !isCount && child != nil {
					return domain.NewError(domain.ErrScopeDenied, "player identities are forbidden at the agent boundary")
				}
			}
			if strings.Contains(lower, "credential") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "token") || strings.Contains(lower, "archive_path") ||
				strings.Contains(lower, "download_url") || lower == "path" || lower == "uuid" ||
				lower == "player_name" || lower == "player_names" {
				return domain.NewError(domain.ErrScopeDenied, "target response contains a field forbidden at the agent boundary")
			}
			if err := rejectSensitiveFields(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectSensitiveFields(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func boolPointer(value bool) *bool { return &value }
