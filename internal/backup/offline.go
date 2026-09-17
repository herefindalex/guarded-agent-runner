// Package backup creates bounded offline archives of an owner-enrolled root.
// It exposes no agent tools and implements neither stop, restore nor replacement.
package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
)

type Config struct {
	DataRoot           string
	Destination        string
	SourceArtifactPath string // fixed owner-enrolled path relative to DataRoot
	SourceArtifactFile string // optional fixed host source for an enrolled read-only bind mount
	Enrollment         domain.Enrollment
	MaxBytes           int64
	MaxFiles           int
}

type Engine struct {
	config              Config
	store               *store.Store
	now                 func() time.Time
	boundary            func(string) error
	destinationIdentity os.FileInfo
}

func New(config Config, database *store.Store) (*Engine, error) {
	config.Enrollment.AllowedPlugins = append([]string(nil), config.Enrollment.AllowedPlugins...)
	if !fs.ValidPath(config.SourceArtifactPath) || config.SourceArtifactPath == "." || strings.Contains(config.SourceArtifactPath, "\\") {
		return nil, fmt.Errorf("fixed source artifact path is required")
	}
	if config.SourceArtifactFile != "" {
		if !filepath.IsAbs(config.SourceArtifactFile) || filepath.Clean(config.SourceArtifactFile) != config.SourceArtifactFile {
			return nil, fmt.Errorf("mounted source artifact must be a clean absolute path")
		}
		resolved, err := filepath.EvalSymlinks(config.SourceArtifactFile)
		if err != nil || resolved != config.SourceArtifactFile {
			return nil, fmt.Errorf("mounted source artifact must exist without symlinks")
		}
		info, err := os.Stat(config.SourceArtifactFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 {
			return nil, fmt.Errorf("mounted source artifact must be a non-empty regular file")
		}
	}
	top := strings.Split(config.SourceArtifactPath, "/")[0]
	if top == "logs" || top == "cache" || top == "temporary-sockets" {
		return nil, fmt.Errorf("source artifact cannot be excluded by the approved recipe")
	}
	for _, p := range []string{config.DataRoot, config.Destination} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("backup roots must be clean owner-controlled absolute paths")
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil || resolved != p {
			return nil, fmt.Errorf("backup roots must exist without symlinks")
		}
	}
	if within(config.DataRoot, config.Destination) || within(config.Destination, config.DataRoot) {
		return nil, fmt.Errorf("backup destination and source must be disjoint")
	}
	info, err := os.Stat(config.Destination)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("backup destination must be an owner-only directory")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("backup destination ownership mismatch")
	}
	if database == nil || config.MaxBytes <= 0 || config.MaxBytes > 1<<40 || config.MaxFiles <= 0 || config.MaxFiles > 1000000 {
		return nil, fmt.Errorf("backup requires a durable store and bounded resource limits")
	}
	if config.Enrollment.DataRootIdentity == "" {
		return nil, fmt.Errorf("backup data root must be enrolled")
	}
	return &Engine{config: config, store: database, now: time.Now, destinationIdentity: info}, nil
}

func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func archiveName(id string) (string, error) {
	if len(id) == 0 || len(id) > 128 {
		return "", fmt.Errorf("invalid backup ID")
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", fmt.Errorf("invalid backup ID")
		}
	}
	return id + ".tar", nil
}

func (e *Engine) checkpoint(name string) error {
	if e.boundary != nil {
		return e.boundary(name)
	}
	return nil
}

// Create never resumes partial work. check must freshly revalidate the offline
// writer immediately before and after archive creation. Final metadata and S05
// completion are committed atomically; incomplete/orphan files remain invalid.
func (e *Engine) Create(ctx context.Context, r domain.BackupRecord, check func(context.Context) (domain.BackupReadyEvidence, error)) error {
	if check == nil {
		return domain.NewError(domain.ErrPreconditionUnavailable, "offline revalidation is required")
	}
	ready, err := check(ctx)
	if err != nil {
		return err
	}
	r.Ready = ready
	if r.TargetID != e.config.Enrollment.TargetID || r.DataRootIdentity != e.config.Enrollment.DataRootIdentity {
		return domain.NewError(domain.ErrIntentStale, "backup engine enrollment changed")
	}
	name, err := archiveName(r.BackupID)
	if err != nil {
		return err
	}
	source, err := os.OpenRoot(e.config.DataRoot)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat(".")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || fmt.Sprintf("dev:%d/inode:%d", stat.Dev, stat.Ino) != e.config.Enrollment.DataRootIdentity {
		return domain.NewError(domain.ErrIntentStale, "source filesystem identity changed")
	}
	dest, err := os.OpenRoot(e.config.Destination)
	if err != nil {
		return err
	}
	defer dest.Close()
	destInfo, err := dest.Stat(".")
	if err != nil || !os.SameFile(e.destinationIdentity, destInfo) {
		return domain.NewError(domain.ErrIntentStale, "backup destination identity changed")
	}
	if len(r.SourceArtifacts) != 1 {
		return domain.NewError(domain.ErrPreconditionUnavailable, "source artifact evidence missing")
	}
	artifactDigest, _, err := e.verifySourceArtifact(ctx, source)
	if err != nil {
		return err
	}
	if artifactDigest != r.SourceArtifacts[0].SHA256 {
		return domain.NewError(domain.ErrIntentStale, "offline source artifact bytes changed")
	}
	if _, err := dest.Lstat(name); !os.IsNotExist(err) {
		return domain.NewError(domain.ErrBackupNotReady, "archive exists or cannot be inspected; manual reconciliation required")
	}
	if err := e.store.ReserveBackup(ctx, r, e.now().UTC()); err != nil {
		return err
	}
	if err := e.store.TransitionBackupStatus(ctx, r.BackupID, domain.BackupWriting, e.now().UTC()); err != nil {
		return err
	}
	// Deliberately preserve partial files for inspection; there is no automatic
	// adoption, deletion, overwrite or second dispatch after an interruption.
	file, err := dest.OpenFile(name+".partial", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := e.checkpoint("temp_created"); err != nil {
		return err
	}
	hash := sha256.New()
	limited := &boundedWriter{writer: io.MultiWriter(file, hash), remaining: e.config.MaxBytes}
	if err := e.archive(ctx, source, limited); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := e.store.TransitionBackupStatus(ctx, r.BackupID, domain.BackupFinalizing, e.now().UTC()); err != nil {
		return err
	}
	directory, err := dest.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	// RENAME_NOREPLACE prevents a racing artifact from being overwritten.
	if err := unix.Renameat2(int(directory.Fd()), name+".partial", int(directory.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := e.checkpoint("archive_renamed"); err != nil {
		return err
	}
	if err := e.store.TransitionBackupStatus(ctx, r.BackupID, domain.BackupVerifying, e.now().UTC()); err != nil {
		return err
	}
	digest, size, err := verify(ctx, dest, name, e.config.MaxBytes)
	if err != nil {
		return err
	}
	if digest != hex.EncodeToString(hash.Sum(nil)) {
		return domain.NewError(domain.ErrBackupNotReady, "archive reread digest mismatch")
	}
	ready, err = check(ctx)
	if err != nil {
		return err
	}
	artifactDigest, _, err = e.verifySourceArtifact(ctx, source)
	if err != nil {
		return err
	}
	if artifactDigest != r.SourceArtifacts[0].SHA256 {
		return domain.NewError(domain.ErrIntentStale, "source artifact changed during backup")
	}
	if err := e.store.CompleteBackup(ctx, r.BackupID, digest, size, ready, e.now().UTC()); err != nil {
		return err
	}
	return e.checkpoint("metadata_committed")
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("archive size limit exceeded")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (e *Engine) archive(ctx context.Context, root *os.Root, output io.Writer) error {
	tw := tar.NewWriter(output)
	count := 0
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if !fs.ValidPath(name) || path.IsAbs(name) || strings.Contains(name, "\\") {
			return fmt.Errorf("unsafe archive path")
		}
		if e.config.SourceArtifactFile != "" &&
			(name == e.config.SourceArtifactPath || strings.HasPrefix(name, e.config.SourceArtifactPath+"/")) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		top := strings.Split(name, "/")[0]
		if top == "logs" || top == "cache" || top == "temporary-sockets" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		count++
		if count > e.config.MaxFiles {
			return fmt.Errorf("archive file count limit exceeded")
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if info.IsDir() {
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = name + "/"
			return tw.WriteHeader(header)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archive rejects symlinks, sockets and special files")
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		before, err := f.Stat()
		if err != nil {
			return err
		}
		stat, ok := before.Sys().(*syscall.Stat_t)
		if !ok || !before.Mode().IsRegular() || !os.SameFile(info, before) || stat.Nlink != 1 {
			return fmt.Errorf("archive source is linked or changed")
		}
		header, err := tar.FileInfoHeader(before, "")
		if err != nil {
			return err
		}
		header.Name = name
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := io.CopyN(tw, contextReader{ctx, f}, before.Size()); err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil {
			return err
		}
		if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return fmt.Errorf("offline source changed during backup")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if e.config.SourceArtifactFile != "" {
		count++
		if count > e.config.MaxFiles {
			return fmt.Errorf("archive file count limit exceeded")
		}
		if err := e.archiveMountedArtifact(ctx, tw, e.config.SourceArtifactPath); err != nil {
			return err
		}
	}
	return tw.Close()
}

func (e *Engine) verifySourceArtifact(ctx context.Context, root *os.Root) (string, int64, error) {
	if e.config.SourceArtifactFile == "" {
		return verify(ctx, root, e.config.SourceArtifactPath, e.config.MaxBytes)
	}
	file, err := openNoFollowRegular(e.config.SourceArtifactFile)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	return verifyFile(ctx, file, e.config.MaxBytes)
}

func (e *Engine) archiveMountedArtifact(ctx context.Context, tw *tar.Writer, name string) error {
	file, err := openNoFollowRegular(e.config.SourceArtifactFile)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("mounted source artifact has unsafe link count")
	}
	header, err := tar.FileInfoHeader(before, "")
	if err != nil {
		return err
	}
	header.Name = name
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := io.CopyN(tw, contextReader{ctx, file}, before.Size()); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("mounted source artifact changed during backup")
	}
	return nil
}

func openNoFollowRegular(name string) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("source artifact is not a regular file")
	}
	return file, nil
}

func verifyFile(ctx context.Context, file *os.File, limit int64) (string, int64, error) {
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return "", 0, fmt.Errorf("invalid source artifact file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, limit+1))
	if err != nil || size != info.Size() {
		return "", 0, fmt.Errorf("source artifact changed during verification")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func verify(ctx context.Context, root *os.Root, name string, limit int64) (string, int64, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return "", 0, fmt.Errorf("invalid archive file")
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(contextReader{ctx, f}, limit+1))
	if err != nil {
		return "", 0, err
	}
	if size != info.Size() {
		return "", 0, fmt.Errorf("archive changed during verification")
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// Inspect requires both durable VALID metadata and current artifact integrity.
func (e *Engine) Inspect(ctx context.Context, id string) (domain.BackupRecord, error) {
	r, err := e.store.GetBackup(ctx, id)
	if err != nil {
		return r, err
	}
	if err := r.ValidateCompleted(); err != nil {
		name, nameErr := archiveName(id)
		if nameErr == nil && r.Status != domain.BackupOrphaned {
			root, openErr := os.OpenRoot(e.config.Destination)
			if openErr == nil {
				_, statErr := root.Lstat(name)
				root.Close()
				if statErr == nil {
					if transitionErr := e.store.TransitionBackupStatus(ctx, id, domain.BackupOrphaned, e.now().UTC()); transitionErr == nil {
						r, _ = e.store.GetBackup(ctx, id)
					}
				}
			}
		}
		return r, err
	}
	en := e.config.Enrollment
	if r.TargetID != en.TargetID || r.EnrollmentID != en.EnrollmentID || r.DeploymentGeneration != en.DeploymentGeneration || r.ContainerIdentity != en.ContainerID || r.DataRootIdentity != en.DataRootIdentity || r.PaperTuple != en.PaperTuple {
		return r, domain.NewError(domain.ErrIntentStale, "backup belongs to another enrolled target")
	}
	name, err := archiveName(id)
	if err != nil {
		return r, err
	}
	root, err := os.OpenRoot(e.config.Destination)
	if err != nil {
		return r, err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || !os.SameFile(e.destinationIdentity, info) {
		return r, domain.NewError(domain.ErrIntentStale, "backup destination identity changed")
	}
	digest, size, err := verify(ctx, root, name, e.config.MaxBytes)
	if err != nil {
		return r, err
	}
	if digest != r.ArchiveSHA256 || size != r.ArchiveSizeBytes {
		return r, domain.NewError(domain.ErrBackupNotReady, "backup integrity verification failed")
	}
	return r, nil
}
