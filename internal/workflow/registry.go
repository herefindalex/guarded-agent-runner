package workflow

import (
	"context"
	"fmt"
	"time"

	"guarded-agent-runner/internal/domain"
)

type Registry struct {
	Enrollment domain.Enrollment
	Artifacts  map[string]domain.ArtifactRecord
	Profiles   map[string]domain.TransitionProfile
}

func (registry Registry) ProfileFor(pluginID, targetArtifactID string) (domain.TransitionProfile, error) {
	for _, profile := range registry.Profiles {
		if profile.PluginID == pluginID && profile.ToArtifactID == targetArtifactID &&
			profile.Eligibility == "VERIFIED_TRANSITION" {
			return profile, nil
		}
	}
	return domain.TransitionProfile{}, domain.NewError(domain.ErrUnsupportedTransition,
		"no owner-registered VERIFIED_TRANSITION matches plugin and artifact IDs")
}

// ProfileForG03Acceptance is restricted to the owner-local G-03 harness. MCP
// proposal handling continues to accept VERIFIED_TRANSITION profiles only.
func (registry Registry) ProfileForG03Acceptance(pluginID, targetArtifactID string) (domain.TransitionProfile, error) {
	for _, profile := range registry.Profiles {
		if profile.PluginID == pluginID && profile.ToArtifactID == targetArtifactID && profile.Eligibility == "G03_BACKUP_ONLY" {
			return profile, nil
		}
	}
	return domain.TransitionProfile{}, domain.NewError(domain.ErrUnsupportedTransition,
		"no owner-registered G03_BACKUP_ONLY profile matches plugin and artifact IDs")
}

type TargetReader interface {
	Observe(ctx context.Context, enrollment domain.Enrollment) (domain.ObservationBundle, error)
	ReadTool(ctx context.Context, name string, arguments map[string]any) (any, error)
}

type FakeTarget struct {
	Observation domain.ObservationBundle
	Responses   map[string]any
	Mutations   int
}

// UnavailableTarget is the fail-closed target used by the M2 transport until
// a separately verified Paper/itzg observation adapter is configured. It
// permits the MCP contract to be exercised without fabricating live evidence.
type UnavailableTarget struct {
	Reason string
}

func (target UnavailableTarget) Observe(_ context.Context, _ domain.Enrollment) (domain.ObservationBundle, error) {
	reason := target.Reason
	if reason == "" {
		reason = "Paper/itzg observation adapter is not configured"
	}
	return domain.ObservationBundle{}, fmt.Errorf("%s", reason)
}

func (target UnavailableTarget) ReadTool(_ context.Context, _ string, _ map[string]any) (any, error) {
	reason := target.Reason
	if reason == "" {
		reason = "Paper/itzg observation adapter is not configured"
	}
	return map[string]any{
		"availability": domain.Unavailable,
		"reason":       reason,
		"source":       "gar-m2-transport",
		"observed_at":  time.Now().UTC(),
	}, nil
}

func (target *FakeTarget) Observe(_ context.Context, _ domain.Enrollment) (domain.ObservationBundle, error) {
	return target.Observation, nil
}

func (target *FakeTarget) ReadTool(_ context.Context, name string, _ map[string]any) (any, error) {
	if response, ok := target.Responses[name]; ok {
		return response, nil
	}
	return map[string]any{
		"availability": domain.Unavailable,
		"reason":       "M1 fake target has no configured observation for this tool",
		"observed_at":  time.Now().UTC(),
	}, nil
}
