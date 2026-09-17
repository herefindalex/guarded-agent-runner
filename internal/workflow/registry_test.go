package workflow

import (
	"testing"

	"guarded-agent-runner/internal/domain"
)

func TestG03BackupOnlyProfileIsOwnerHarnessOnly(t *testing.T) {
	profile := domain.TransitionProfile{
		ProfileID: "g03-only", PluginID: "gar-guard",
		FromArtifactID: "artifact-a", ToArtifactID: "artifact-b",
		Eligibility: "G03_BACKUP_ONLY",
	}
	registry := Registry{
		Profiles: map[string]domain.TransitionProfile{profile.ProfileID: profile},
	}

	if _, err := registry.ProfileFor(profile.PluginID, profile.ToArtifactID); domain.CodeOf(err) != domain.ErrUnsupportedTransition {
		t.Fatalf("agent proposal accepted G03_BACKUP_ONLY profile: %v", err)
	}
	got, err := registry.ProfileForG03Acceptance(profile.PluginID, profile.ToArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != profile.ProfileID {
		t.Fatalf("owner G-03 lookup returned %q, want %q", got.ProfileID, profile.ProfileID)
	}
}
