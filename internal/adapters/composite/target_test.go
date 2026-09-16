package composite

import (
	"context"
	"testing"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/workflow"
)

func TestObserveMergesHostAndReadyRuntimeEvidence(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	enrollment := domain.Enrollment{EnrollmentID: "enrollment-a", DeploymentGeneration: 2, ContainerID: "container-a"}
	host := &workflow.FakeTarget{Observation: domain.ObservationBundle{
		BundleID: "host-a", EnrollmentID: enrollment.EnrollmentID,
		DeploymentGeneration: enrollment.DeploymentGeneration, ContainerID: enrollment.ContainerID,
		InventoryDigest: "inventory-a", ConfigDigest: "config-a",
		ActiveArtifacts: map[string]string{"plugin-a": "artifact-a"}, CreatedAt: now,
		Readings: map[string]domain.ObservationValue{"process": {Availability: domain.Available, Value: "running"}},
	}}
	runtime := &workflow.FakeTarget{Observation: domain.ObservationBundle{
		BundleID: "runtime-a", EnrollmentID: enrollment.EnrollmentID,
		DeploymentGeneration: enrollment.DeploymentGeneration, ContainerID: enrollment.ContainerID,
		BootID: "boot-0123456789abcdef", CreatedAt: now.Add(time.Second),
		Readings: map[string]domain.ObservationValue{
			"guard_ready": {Availability: domain.Available, Value: true, BootID: "boot-0123456789abcdef"},
			"players":     {Availability: domain.Available, Value: 0, BootID: "boot-0123456789abcdef"},
		},
	}}
	target, err := New(host, runtime)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := target.Observe(context.Background(), enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.InventoryDigest != "inventory-a" || bundle.ConfigDigest != "config-a" ||
		bundle.BootID != "boot-0123456789abcdef" || bundle.ActiveArtifacts["plugin-a"] != "artifact-a" {
		t.Fatalf("composite lost authority evidence: %#v", bundle)
	}
}

func TestObserveFailsClosedForStaleRuntimeAndSkew(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	enrollment := domain.Enrollment{EnrollmentID: "e", DeploymentGeneration: 1, ContainerID: "c"}
	base := func() (*workflow.FakeTarget, *workflow.FakeTarget) {
		host := &workflow.FakeTarget{Observation: domain.ObservationBundle{
			BundleID: "h", EnrollmentID: "e", DeploymentGeneration: 1, ContainerID: "c", CreatedAt: now,
		}}
		runtime := &workflow.FakeTarget{Observation: domain.ObservationBundle{
			BundleID: "r", EnrollmentID: "e", DeploymentGeneration: 1, ContainerID: "c",
			BootID: "boot", CreatedAt: now,
			Readings: map[string]domain.ObservationValue{
				"guard_ready": {Availability: domain.Available, Value: true, BootID: "boot"},
				"players":     {Availability: domain.Stale, Value: 0, BootID: "boot"},
			},
		}}
		return host, runtime
	}
	host, runtime := base()
	target, _ := New(host, runtime)
	if _, err := target.Observe(context.Background(), enrollment); err == nil {
		t.Fatal("stale runtime evidence was executable")
	}
	host, runtime = base()
	runtime.Observation.Readings["players"] = domain.ObservationValue{Availability: domain.Available, Value: 0, BootID: "boot"}
	runtime.Observation.CreatedAt = now.Add(maxObservationSkew + time.Second)
	target, _ = New(host, runtime)
	if _, err := target.Observe(context.Background(), enrollment); err == nil {
		t.Fatal("skewed evidence was executable")
	}
}
