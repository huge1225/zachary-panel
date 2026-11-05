package security

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultStateDir picks a private state directory for the Agent (rule snapshot, engine configs, tunnel certificate).
// Order: explicit value -> $NEXUS_STATE_DIR -> systemd $STATE_DIRECTORY -> /var/lib/nexus-agent (if writable) -> ~/.nexus-agent.
func DefaultStateDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("NEXUS_STATE_DIR"); v != "" {
		return v
	}
	if v := os.Getenv("STATE_DIRECTORY"); v != "" {
		return filepath.SplitList(v)[0]
	}
	if fi, err := os.Stat("/var/lib/nexus-agent"); err == nil && fi.IsDir() {
		return "/var/lib/nexus-agent"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".nexus-agent")
	}
	return "/var/lib/nexus-agent"
}

// EnsurePrivateDir creates dir (0700) if needed and verifies it is a real directory (not a symlink) owned by the
// current user with no group/other permissions. This prevents other local users from pre-creating / hijacking
// the directory that stores tunnel secrets and engine configuration files.
func EnsurePrivateDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("empty state directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state dir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("state dir %s must be a real directory (symlinks are rejected)", dir)
	}
	if err := checkOwner(fi); err != nil {
		return fmt.Errorf("state dir %s: %w", dir, err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("state dir %s has insecure permissions %v and chmod failed: %w", dir, fi.Mode().Perm(), err)
		}
	}
	return nil
}
