package archive

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// objectStore is the little the archive needs from object storage. Keys are
// slash-separated.
type objectStore interface {
	// Put writes an object, replacing any object with the same key. It
	// returns only once the object is durably stored.
	Put(ctx context.Context, key string, body []byte, contentType string) error
	// Get returns an object's content, or an error wrapping errNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// Delete removes an object; a missing object is not an error.
	Delete(ctx context.Context, key string) error
	// List returns the keys of all objects whose key starts with prefix.
	List(ctx context.Context, prefix string) ([]string, error)
	// Check verifies that the storage is reachable (readiness).
	Check(ctx context.Context) error
}

// fileStore keeps objects as files below a directory. Writes go to a
// temporary file that is synced and renamed into place, so an object is
// either complete or absent.
type fileStore struct {
	dir string
}

func newFileStore(dir string) (*fileStore, error) {
	if dir == "" {
		return nil, errors.New("file.dir is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("file.dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, fmt.Errorf("file.dir: %w", err)
	}
	return &fileStore{dir: abs}, nil
}

// path maps a key to a file path, refusing keys that would leave dir.
func (s *fileStore) path(key string) (string, error) {
	if key == "" || strings.HasPrefix(key, "/") || slices.Contains(strings.Split(key, "/"), "..") {
		return "", fmt.Errorf("invalid key %q", key)
	}
	return filepath.Join(s.dir, filepath.FromSlash(key)), nil
}

func (s *fileStore) Put(_ context.Context, key string, body []byte, _ string) error {
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	syncDir(filepath.Dir(p))
	return nil
}

// syncDir makes a rename durable where the platform supports syncing a
// directory (not on Windows, where it is unnecessary).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func (s *fileStore) Get(_ context.Context, key string) ([]byte, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", key, errNotFound)
	}
	return b, err
}

func (s *fileStore) Delete(_ context.Context, key string) error {
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// List walks the deepest directory named by prefix and filters by the full
// prefix.
func (s *fileStore) List(_ context.Context, prefix string) ([]string, error) {
	root := s.dir
	if i := strings.LastIndex(prefix, "/"); i >= 0 {
		var err error
		if root, err = s.path(prefix[:i]); err != nil {
			return nil, err
		}
	}
	var keys []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".tmp-") {
			return nil
		}
		rel, err := filepath.Rel(s.dir, p)
		if err != nil {
			return err
		}
		if key := filepath.ToSlash(rel); strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	return keys, err
}

func (s *fileStore) Check(context.Context) error {
	st, err := os.Stat(s.dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", s.dir)
	}
	return nil
}
