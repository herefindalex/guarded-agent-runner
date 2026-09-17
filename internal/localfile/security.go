// Package localfile contains checks for owner-controlled GAR files.
package localfile

import (
	"fmt"
	"os"
	"syscall"
)

// ValidateOwnerOnlyRegular rejects symlinks, non-regular files, files owned by
// another OS user, and group/other permissions. The check is intentionally
// Linux-specific because the v0.1 reference deployment is Linux-only.
func ValidateOwnerOnlyRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not grant group or other access", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must be owned by the current OS user", path)
	}
	return nil
}
