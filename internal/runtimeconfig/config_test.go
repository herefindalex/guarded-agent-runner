package runtimeconfig

import (
	"testing"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/policy"
)

func validConfig() Config {
	enrollment := domain.Enrollment{
		TargetID: "paper-a", EnrollmentID: "enrollment-a", DeploymentGeneration: 1,
		SupportProfileID: "read-only", PaperTuple: "paper/java/itzg",
		AllowedPlugins: []string{"example"},
	}
	return Config{
		SchemaVersion: SchemaVersion, Enrollment: enrollment,
		Artifacts: map[string]domain.ArtifactRecord{
			"artifact-a": {
				ArtifactID: "artifact-a", PluginID: "example",
				SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			"artifact-b": {
				ArtifactID: "artifact-b", PluginID: "example",
				SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		Profiles: map[string]domain.TransitionProfile{
			"example-a-b": {
				ProfileID: "example-a-b", PluginID: "example", FromArtifactID: "artifact-a",
				ToArtifactID: "artifact-b", PaperTuple: enrollment.PaperTuple,
			},
		},
		Support:                policy.SupportProfile{ProfileID: enrollment.SupportProfileID, Mode: policy.ModeReadOnly},
		CurrentRevocationEpoch: 1,
	}
}

func TestConfigBindsCatalogAndSupportToEnrollment(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}

	wrongSupport := validConfig()
	wrongSupport.Support.ProfileID = "other"
	if err := wrongSupport.Validate(); err == nil {
		t.Fatal("support profile mismatch was accepted")
	}

	unknownArtifact := validConfig()
	profile := unknownArtifact.Profiles["example-a-b"]
	profile.ToArtifactID = "not-in-owner-catalog"
	unknownArtifact.Profiles[profile.ProfileID] = profile
	if err := unknownArtifact.Validate(); err == nil {
		t.Fatal("profile referencing an unknown artifact was accepted")
	}

	unsafeSnapshot := validConfig()
	unsafeSnapshot.PaperRuntime = &PaperRuntimeSource{SnapshotPath: "../runtime-observation.json"}
	if err := unsafeSnapshot.Validate(); err == nil {
		t.Fatal("relative Paper runtime snapshot path was accepted")
	}
}
