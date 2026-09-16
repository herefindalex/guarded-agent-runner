package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
)

// INV-13: a file-backed journal must read back WAL + FULL before use.
func TestJournalSettingsAreReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.JournalSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings.JournalMode != "wal" || settings.Synchronous != 2 || settings.ForeignKeys != 1 {
		t.Fatalf("unsafe SQLite settings: %+v", settings)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.JournalSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseBoundaryRejectsSymlinkAndInsecurePermissions(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real.db")
	if err := os.WriteFile(realPath, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(realPath); domain.CodeOf(err) != domain.ErrJournalUnavailable {
		t.Fatalf("expected insecure permission rejection, got %v", err)
	}
	if err := os.Chmod(realPath, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(realPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	symlink := filepath.Join(directory, "linked.db")
	if err := os.Symlink(realPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(symlink); domain.CodeOf(err) != domain.ErrJournalUnavailable {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}
