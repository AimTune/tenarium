package sdk

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// ErrNotFound is returned by Host lookups for missing entities.
var ErrNotFound = errors.New("not found")

// Factory creates a fresh plugin instance.
type Factory func() Plugin

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register makes a built-in plugin available under id. It is meant to be
// called from an init function, mirroring database/sql drivers:
//
//	func init() { sdk.Register("kafka", func() sdk.Plugin { return &Plugin{} }) }
//
// Registered plugins are only started if enabled in configuration.
// Register panics if id is empty or already taken.
func Register(id string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if id == "" || f == nil {
		panic("sdk: Register with empty id or nil factory")
	}
	if _, dup := registry[id]; dup {
		panic(fmt.Sprintf("sdk: plugin %q registered twice", id))
	}
	registry[id] = f
}

// Lookup returns the factory registered under id.
func Lookup(id string) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[id]
	return f, ok
}

// Registered returns the sorted ids of all registered plugins.
func Registered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
