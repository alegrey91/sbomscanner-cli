// Package paths centralizes filesystem locations used by sbomscanner-cli.
//
// Layout under $HOME:
//
//	~/.sbomscanner/          (0700)
//	├── data/                (0700)  KEV + EPSS CSVs live here
//	└── layout/              (0700)  local OCI image layout for pack/push
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// File names for the two known data files. Anything else in the data dir
// is ignored by `pack`.
const (
	KEVFileName  = "known_exploited_vulnerabilities.csv"
	EPSSFileName = "epss_scores.csv"
)

// Directory permissions (0700) and file permissions (0600) required by the
// spec. Files not created via os.OpenFile with these modes should be
// explicitly chmod'd after rename (umask can mask bits from OpenFile too).
const (
	DirMode  os.FileMode = 0o700
	FileMode os.FileMode = 0o600
)

// Root returns ~/.sbomscanner. `~` is not expanded by Go so we resolve HOME
// explicitly (honoring $HOME via os.UserHomeDir).
func Root() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".sbomscanner"), nil
}

// DataDir returns ~/.sbomscanner/data.
func DataDir() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "data"), nil
}

// LayoutDir returns ~/.sbomscanner/layout.
func LayoutDir() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "layout"), nil
}

// EnsureDir creates dir (and any missing parents) at 0700.
// It also chmods dir back to 0700 in case an older run left it more permissive
// or the process umask stripped bits.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, DirMode); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// EnsureDataDir ensures both ~/.sbomscanner (parent) and ~/.sbomscanner/data
// exist at 0700.
func EnsureDataDir() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	if err := EnsureDir(root); err != nil {
		return "", err
	}
	data := filepath.Join(root, "data")
	if err := EnsureDir(data); err != nil {
		return "", err
	}
	return data, nil
}

// EnsureLayoutDir ensures both ~/.sbomscanner (parent) and ~/.sbomscanner/layout
// exist at 0700.
func EnsureLayoutDir() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	if err := EnsureDir(root); err != nil {
		return "", err
	}
	layout := filepath.Join(root, "layout")
	if err := EnsureDir(layout); err != nil {
		return "", err
	}
	return layout, nil
}
