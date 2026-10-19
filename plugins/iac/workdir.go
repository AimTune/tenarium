package iac

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// metaDir is the plugin's own directory inside a tenant's working
// directory (variables, cached outputs). It is never copied from or to a
// module.
const metaDir = ".tenarium"

var tenantIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// tenantDir returns the tenant's working directory under root. The tenant
// ID is checked so it cannot escape root.
func tenantDir(root, tenantID string) (string, error) {
	if !tenantIDRE.MatchString(tenantID) || strings.Contains(tenantID, "..") {
		return "", fmt.Errorf("tenant ID %q cannot be used as a directory name", tenantID)
	}
	return filepath.Join(root, tenantID), nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// cleanDir removes every entry of dir except those named in keep.
func cleanDir(dir string, keep []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if slices.Contains(keep, e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies the files of src into dst, skipping entries for which
// skip returns true (paths relative to src, slash-separated). Symlinks to
// files are copied as files; symlinks to directories are skipped.
func copyTree(src, dst string, skip func(rel string, dir bool) bool) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		slash := filepath.ToSlash(rel)
		target := filepath.Join(dst, rel)
		info, err := os.Stat(path) // follows symlinks
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip(slash, true) {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o755)
		}
		if info.IsDir() || !info.Mode().IsRegular() || skip(slash, false) {
			return nil // directory symlink, device, socket, or skipped
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm|0o200)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeFileAtomic writes data to path through a temporary file, so readers
// never see a partial file.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

const outputsFile = "outputs.json"

// saveOutputs caches res in the tenant directory. Sensitive values have
// already been removed.
func saveOutputs(dir string, res *Result) error {
	if err := os.MkdirAll(filepath.Join(dir, metaDir), 0o700); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, metaDir, outputsFile), res)
}

// loadOutputs reads the cached outputs of a tenant, or ErrNoOutputs.
func loadOutputs(dir string) (*Result, error) {
	b, err := os.ReadFile(filepath.Join(dir, metaDir, outputsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoOutputs
	} else if err != nil {
		return nil, err
	}
	var res Result
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("cached outputs: %w", err)
	}
	return &res, nil
}

// checkDir checks that path is an existing directory and returns it
// absolute.
func checkDir(field, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s: %s is not a directory", field, abs)
	}
	return abs, nil
}

// prepareStateDir creates the state directory and returns it absolute.
func prepareStateDir(path string) (string, error) {
	if path == "" {
		return "", errors.New("state_dir is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("state_dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("state_dir: %w", err)
	}
	return abs, nil
}
