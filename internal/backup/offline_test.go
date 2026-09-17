package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
)

func engineFixture(t *testing.T) (*Engine, domain.BackupRecord, string) {
	t.Helper()
	root := t.TempDir()
	dest := t.TempDir()
	if err := os.Chmod(dest, 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("registered source artifact")
	if err := os.WriteFile(filepath.Join(root, "a.jar"), data, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	digest := hex.EncodeToString(h[:])
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	en := domain.Enrollment{TargetID: "target", EnrollmentID: "enrollment", DeploymentGeneration: 1, ContainerID: "container", DataRootIdentity: fmt.Sprintf("dev:%d/inode:%d", st.Dev, st.Ino), PaperTuple: "FAKE_PAPER", PolicyRevision: "1", PolicyDigest: "policy"}
	path := filepath.Join(t.TempDir(), "journal.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now().UTC()
	i := domain.ChangeIntent{IntentID: domain.NewID("intent"), PrincipalID: "agent", ClientRequestID: "request", EnrollmentID: en.EnrollmentID, DeploymentGeneration: en.DeploymentGeneration, ContainerID: en.ContainerID, PaperTuple: en.PaperTuple, ExpectedBootID: "boot", PolicyRevision: "1", PolicyDigest: "policy", PluginID: "plugin", FromArtifactID: "a", FromSHA256: digest, InventoryDigest: "inventory", ConfigDigest: "config", Steps: append([]string(nil), domain.FixedWorkflowSteps...), ReservedBackupID: domain.NewID("backup"), BackupRecipeDigest: domain.OfflineBackupRecipeDigest(), ApprovalDeadline: now.Add(time.Hour), StartBefore: now.Add(time.Hour)}
	if err := i.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PutIntent(context.Background(), domain.IntentRecord{Intent: i, Status: domain.IntentAwaitingApproval, ProposalDigest: "proposal", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_, op, err := db.ApproveIntent(context.Background(), i.IntentID, i.IntentDigest, "independent-owner", os.Getuid(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []domain.OperationStatus{domain.OperationPreparing, domain.OperationExecuting} {
		if err := db.TransitionOperation(context.Background(), op.OperationID, status, domain.VerificationNotStarted, false, now); err != nil {
			t.Fatal(err)
		}
	}
	var stopID, backupStepID string
	for n := 0; n < 6; n++ {
		a, err := db.PrepareStep(context.Background(), op.OperationID, domain.FixedWorkflowSteps[n], now)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.MarkDispatchPossible(context.Background(), op.OperationID, a.StepID, now); err != nil {
			t.Fatal(err)
		}
		if n == 3 {
			stopID = a.StepID
		}
		if n == 5 {
			backupStepID = a.StepID
			break
		}
		if err := db.RecordStepObservation(context.Background(), op.OperationID, a.StepID, domain.EffectExpectedObserved, domain.AttributionCorrelated, []string{"FAKE_TARGET receipt"}, now); err != nil {
			t.Fatal(err)
		}
	}
	before := domain.SafetyObservation{Available: true, ObservedAt: now, Enrollment: en, BootID: i.ExpectedBootID, InventoryDigest: i.InventoryDigest, ConfigDigest: i.ConfigDigest, SourceArtifactID: i.FromArtifactID, SourceSHA256: i.FromSHA256, AdmissionClosed: true, Maintenance: true, FilesystemRootExists: true, NoConflictingWriter: true, References: []string{"FAKE_TARGET snapshot"}}
	offline := before
	offline.ProcessStopped = true
	stop := domain.StopEvidence{State: domain.StopConfirmed, OperationID: op.OperationID, StepID: stopID, ContainerID: i.ContainerID, BootID: i.ExpectedBootID, RequestedAt: now, ObservedAt: now, FinishedAt: now, LifecycleAvailable: true, RuntimeTerminal: true, GracefulTermination: true, Attribution: domain.AttributionCorrelated, References: []string{"FAKE_TARGET exit and terminal runtime"}}
	r := domain.BackupRecord{BackupID: i.ReservedBackupID, SchemaVersion: "gar.backup.v1", TargetID: en.TargetID, EnrollmentID: en.EnrollmentID, DeploymentGeneration: en.DeploymentGeneration, ContainerIdentity: en.ContainerID, DataRootIdentity: en.DataRootIdentity, PaperTuple: en.PaperTuple, BootIDBeforeStop: i.ExpectedBootID, IntentID: i.IntentID, IntentDigest: i.IntentDigest, OperationID: op.OperationID, StepID: backupStepID, SourceInventoryDigest: i.InventoryDigest, SourceConfigDigest: i.ConfigDigest, SourceArtifacts: []domain.ArtifactRecord{{ArtifactID: i.FromArtifactID, SHA256: i.FromSHA256, PluginID: i.PluginID}}, BackupRecipeID: domain.BackupRecipeID, BackupRecipeDigest: i.BackupRecipeDigest, CreatedAt: now, ConsistencyMode: "OFFLINE", Status: domain.BackupCreating, Ready: domain.BackupReadyEvidence{BeforeStop: before, Offline: offline, Stop: stop}}
	e, err := New(Config{DataRoot: root, Destination: dest, SourceArtifactPath: "a.jar", Enrollment: en, MaxBytes: 1 << 20, MaxFiles: 100}, db)
	if err != nil {
		t.Fatal(err)
	}
	r.EvidenceLevel = "FAKE_TARGET"
	return e, r, path
}

func TestArchiveCrashBoundariesSurviveStoreReopen(t *testing.T) {
	for _, point := range []string{"temp_created", "archive_renamed", "metadata_committed"} {
		t.Run(point, func(t *testing.T) {
			e, r, dbPath := engineFixture(t)
			crash := errors.New("injected process death")
			e.boundary = func(name string) error {
				if name == point {
					return crash
				}
				return nil
			}
			if err := e.Create(context.Background(), r, func(context.Context) error { return nil }); !errors.Is(err, crash) {
				t.Fatalf("crash boundary not reached: %v", err)
			}
			if err := e.store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := store.Open(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			e, err = New(e.config, reopened)
			if err != nil {
				t.Fatal(err)
			}
			stored, inspectErr := e.Inspect(context.Background(), r.BackupID)
			name, _ := archiveName(r.BackupID)
			if point == "metadata_committed" {
				if inspectErr != nil || stored.Status != domain.BackupValid {
					t.Fatalf("committed backup did not survive: %v %+v", inspectErr, stored)
				}
				op, _ := reopened.GetOperation(context.Background(), r.OperationID)
				if op.Attempts[5].DispatchState != domain.Acknowledged || op.Attempts[5].Attribution != domain.AttributionCorrelated {
					t.Fatal("metadata and step completion were not atomic")
				}
			} else {
				if domain.CodeOf(inspectErr) != domain.ErrBackupNotReady || stored.Status != domain.BackupCreating {
					t.Fatalf("partial/orphan promoted: %v %+v", inspectErr, stored)
				}
				if point == "temp_created" {
					name += ".partial"
				}
				if _, err := os.Stat(filepath.Join(e.config.Destination, name)); err != nil {
					t.Fatal("incomplete evidence not retained", err)
				}
			}
			if err := e.Create(context.Background(), r, func(context.Context) error { return nil }); err == nil {
				t.Fatal("backup dispatch blindly retried")
			}
		})
	}
}

func TestOfflineArchiveContentsAndIntegrity(t *testing.T) {
	e, r, _ := engineFixture(t)
	if err := os.Mkdir(filepath.Join(e.config.DataRoot, "world"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.config.DataRoot, "world", "level.dat"), []byte("offline world"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(e.config.DataRoot, "logs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.config.DataRoot, "logs", "latest.log"), []byte("excluded"), 0600); err != nil {
		t.Fatal(err)
	}
	checks := 0
	if err := e.Create(context.Background(), r, func(context.Context) error { checks++; return nil }); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatalf("offline checks=%d", checks)
	}
	stored, err := e.Inspect(context.Background(), r.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := archiveName(r.BackupID)
	p := filepath.Join(e.config.Destination, name)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	seen := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		seen[h.Name] = string(b)
	}
	if seen["a.jar"] != "registered source artifact" || seen["world/level.dat"] != "offline world" {
		t.Fatalf("archive lost enrolled data: %v", seen)
	}
	if _, ok := seen["logs/latest.log"]; ok {
		t.Fatal("recipe exclusion ignored")
	}
	if err := e.store.CompleteBackup(context.Background(), r.BackupID, stored.ArchiveSHA256, stored.ArchiveSizeBytes, e.now()); err == nil {
		t.Fatal("completed metadata mutable")
	}
	if err := os.WriteFile(p, []byte("corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Inspect(context.Background(), r.BackupID); domain.CodeOf(err) != domain.ErrBackupNotReady {
		t.Fatalf("corruption accepted: %v", err)
	}
}

func TestArchiveRejectsUnsafeOrChangedSources(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "fifo", "absolute_id", "parent_id", "source_changed", "byte_limit", "file_limit", "offline_lost", "destination_replaced"} {
		t.Run(mode, func(t *testing.T) {
			e, r, _ := engineFixture(t)
			switch mode {
			case "symlink":
				if err := os.Symlink("/etc/passwd", filepath.Join(e.config.DataRoot, "escape")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(e.config.DataRoot, "a.jar"), filepath.Join(e.config.DataRoot, "linked")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(filepath.Join(e.config.DataRoot, "pipe"), 0600); err != nil {
					t.Fatal(err)
				}
			case "absolute_id":
				r.BackupID = "/tmp/escape"
			case "parent_id":
				r.BackupID = "../escape"
			case "source_changed":
				if err := os.WriteFile(filepath.Join(e.config.DataRoot, "a.jar"), []byte("artifact B"), 0600); err != nil {
					t.Fatal(err)
				}
			case "byte_limit":
				e.config.MaxBytes = 600
			case "file_limit":
				e.config.MaxFiles = 1
				if err := os.WriteFile(filepath.Join(e.config.DataRoot, "extra"), []byte("extra"), 0600); err != nil {
					t.Fatal(err)
				}
			case "destination_replaced":
				if err := os.Rename(e.config.Destination, e.config.Destination+"-old"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(e.config.Destination + "-old") })
				if err := os.Mkdir(e.config.Destination, 0700); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			err := e.Create(context.Background(), r, func(context.Context) error {
				checks++
				if mode == "offline_lost" && checks == 2 {
					return domain.NewError(domain.ErrIntentStale, "writer appeared")
				}
				return nil
			})
			if err == nil {
				t.Fatal("unsafe backup succeeded")
			}
			if _, err := e.Inspect(context.Background(), r.BackupID); err == nil {
				t.Fatal("unsafe backup became VALID")
			}
		})
	}
}

func TestBackupConfigRejectsArbitraryRoots(t *testing.T) {
	e, _, _ := engineFixture(t)
	for _, p := range []string{"../x", "/x", "a/../b", ".", "logs/a.jar", "cache/a.jar", "temporary-sockets/a.jar"} {
		cfg := e.config
		cfg.SourceArtifactPath = p
		if _, err := New(cfg, e.store); err == nil {
			t.Fatal("unsafe enrolled artifact path accepted", p)
		}
	}
	cfg := e.config
	cfg.Destination = cfg.DataRoot
	if _, err := New(cfg, e.store); err == nil {
		t.Fatal("backup within source accepted")
	}
	if name, err := archiveName(strings.Repeat("a", 129)); err == nil || name != "" {
		t.Fatal("unbounded archive name")
	}
}

func TestArchiveDigestRereadMustMatchWrittenBytes(t *testing.T) {
	e, r, _ := engineFixture(t)
	e.boundary = func(name string) error {
		if name == "archive_renamed" {
			archive, _ := archiveName(r.BackupID)
			return os.WriteFile(filepath.Join(e.config.Destination, archive), []byte("tampered before digest verification"), 0600)
		}
		return nil
	}
	if err := e.Create(context.Background(), r, func(context.Context) error { return nil }); domain.CodeOf(err) != domain.ErrBackupNotReady {
		t.Fatalf("reread mismatch not detected: %v", err)
	}
	stored, err := e.store.GetBackup(context.Background(), r.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != domain.BackupCreating {
		t.Fatal("digest mismatch became valid")
	}
}

func TestBackupReservationRejectsAlteredApprovedBindings(t *testing.T) {
	for _, field := range []string{"intent", "operation", "generation", "container", "root", "tuple", "recipe", "inventory", "config", "source", "stop_step", "pre_players", "pre_missing", "post_missing", "status"} {
		t.Run(field, func(t *testing.T) {
			e, r, _ := engineFixture(t)
			switch field {
			case "intent":
				r.IntentDigest = "wrong"
			case "operation":
				r.OperationID = "wrong"
			case "generation":
				r.DeploymentGeneration++
			case "container":
				r.ContainerIdentity = "wrong"
			case "root":
				r.DataRootIdentity = "wrong"
			case "tuple":
				r.PaperTuple = "wrong"
			case "recipe":
				r.BackupRecipeDigest = "wrong"
			case "inventory":
				r.SourceInventoryDigest = "wrong"
			case "config":
				r.SourceConfigDigest = "wrong"
			case "source":
				r.SourceArtifacts[0].ArtifactID = "wrong"
			case "stop_step":
				r.Ready.Stop.StepID = "wrong"
			case "pre_players":
				r.Ready.BeforeStop.Players = 1
			case "pre_missing":
				r.Ready.BeforeStop.Available = false
			case "post_missing":
				r.Ready.Offline.Available = false
			case "status":
				r.Status = domain.BackupValid
			}
			if err := e.Create(context.Background(), r, func(context.Context) error { return nil }); err == nil {
				t.Fatal("altered approval binding accepted")
			}
			files, err := os.ReadDir(e.config.Destination)
			if err != nil || len(files) != 0 {
				t.Fatal("artifact creation began before binding check")
			}
		})
	}
}
