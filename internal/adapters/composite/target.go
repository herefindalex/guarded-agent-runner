// Package composite combines separately privileged host evidence with Paper
// runtime evidence without giving the GAR MCP frontend host control authority.
package composite

import (
	"context"
	"fmt"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/workflow"
)

const maxObservationSkew = 5 * time.Second

type Target struct {
	Host    workflow.TargetReader
	Runtime workflow.TargetReader
}

func New(host, runtime workflow.TargetReader) (*Target, error) {
	if host == nil || runtime == nil {
		return nil, fmt.Errorf("composite target requires host and Paper runtime adapters")
	}
	return &Target{Host: host, Runtime: runtime}, nil
}

func (target *Target) Observe(ctx context.Context, enrollment domain.Enrollment) (domain.ObservationBundle, error) {
	host, err := target.Host.Observe(ctx, enrollment)
	if err != nil {
		return domain.ObservationBundle{}, fmt.Errorf("host observation is not executable: %w", err)
	}
	runtime, err := target.Runtime.Observe(ctx, enrollment)
	if err != nil {
		return domain.ObservationBundle{}, fmt.Errorf("Paper runtime observation is not executable: %w", err)
	}
	if host.EnrollmentID != enrollment.EnrollmentID || runtime.EnrollmentID != enrollment.EnrollmentID ||
		host.DeploymentGeneration != enrollment.DeploymentGeneration || runtime.DeploymentGeneration != enrollment.DeploymentGeneration ||
		host.ContainerID != enrollment.ContainerID || runtime.ContainerID != enrollment.ContainerID {
		return domain.ObservationBundle{}, fmt.Errorf("composite observation identity mismatch")
	}
	if absoluteDuration(host.CreatedAt.Sub(runtime.CreatedAt)) > maxObservationSkew {
		return domain.ObservationBundle{}, fmt.Errorf("host and Paper observations exceed maximum time skew")
	}
	guard, guardOK := runtime.Readings["guard_ready"]
	players, playersOK := runtime.Readings["players"]
	if !guardOK || guard.Availability != domain.Available || guard.Value != true ||
		!playersOK || players.Availability != domain.Available {
		return domain.ObservationBundle{}, fmt.Errorf("Paper runtime is stale or not ready")
	}
	if runtime.BootID == "" || guard.BootID != runtime.BootID || players.BootID != runtime.BootID {
		return domain.ObservationBundle{}, fmt.Errorf("Paper runtime boot identity is inconsistent")
	}
	readings := make(map[string]domain.ObservationValue, len(host.Readings)+len(runtime.Readings))
	for key, value := range host.Readings {
		readings[key] = value
	}
	for key, value := range runtime.Readings {
		readings[key] = value
	}
	digest, err := domain.Digest([]string{host.BundleID, runtime.BundleID})
	if err != nil {
		return domain.ObservationBundle{}, err
	}
	createdAt := host.CreatedAt
	if runtime.CreatedAt.Before(createdAt) {
		createdAt = runtime.CreatedAt
	}
	return domain.ObservationBundle{
		BundleID: "composite_" + digest, EnrollmentID: enrollment.EnrollmentID,
		DeploymentGeneration: enrollment.DeploymentGeneration, ContainerID: enrollment.ContainerID,
		BootID: runtime.BootID, InventoryDigest: host.InventoryDigest, ConfigDigest: host.ConfigDigest,
		ActiveArtifacts: cloneArtifacts(host.ActiveArtifacts), Readings: readings, CreatedAt: createdAt,
	}, nil
}

func (target *Target) ReadTool(ctx context.Context, name string, arguments map[string]any) (any, error) {
	switch name {
	case "get_players":
		return target.Runtime.ReadTool(ctx, name, arguments)
	case "get_recent_errors", "get_recent_changes", "get_backup_status":
		return target.Host.ReadTool(ctx, name, arguments)
	case "get_health", "get_performance", "list_plugins":
		host, err := target.Host.ReadTool(ctx, name, arguments)
		if err != nil {
			return nil, err
		}
		runtime, err := target.Runtime.ReadTool(ctx, name, arguments)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"availability": combinedAvailability(host, runtime),
			"source":       "gar-composite", "host": host, "runtime": runtime,
		}, nil
	default:
		return nil, domain.NewError(domain.ErrInvalidRequest, "unsupported composite read tool")
	}
}

func combinedAvailability(values ...any) domain.Availability {
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok || object["availability"] != domain.Available {
			return domain.Unavailable
		}
	}
	return domain.Available
}

func cloneArtifacts(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
