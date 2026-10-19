package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"slices"
	"sync"
	"syscall"

	"github.com/AimTune/tenarium/internal/plugin"
)

// ReloadResult reports what a configuration reload changed.
type ReloadResult struct {
	// Applied lists the changes now in effect (e.g. "log.level",
	// "plugins.webhook").
	Applied []string `json:"applied"`
	// RestartRequired lists changed settings that only take effect after a
	// restart.
	RestartRequired []string `json:"restart_required"`
	// Failed maps changes that were rejected to the reason; the old setting
	// stays in effect.
	Failed map[string]string `json:"failed,omitempty"`
}

// WithConfigPath enables reloading the configuration from path (SIGHUP and
// POST /v1/admin/reload).
func WithConfigPath(path string) Option {
	return func(o *options) { o.configPath = path }
}

// WithLevelVar lets reloads change the log level of the logger given to
// New.
func WithLevelVar(lv *slog.LevelVar) Option {
	return func(o *options) { o.level = lv }
}

// ReloadFromFile re-reads the configuration file given to WithConfigPath
// and applies it.
func (a *App) ReloadFromFile(ctx context.Context) (ReloadResult, error) {
	if a.configPath == "" {
		return ReloadResult{}, errors.New("no configuration file to reload")
	}
	cfg, err := LoadConfig(a.configPath)
	if err != nil {
		return ReloadResult{}, fmt.Errorf("config: %w", err)
	}
	return a.Reload(ctx, cfg)
}

// Reload applies what can change while running: the log level and the
// configuration of plugin instances that implement sdk.Reconfigurer.
// Everything else that differs is reported as needing a restart; nothing
// is half-applied.
func (a *App) Reload(ctx context.Context, next Config) (ReloadResult, error) {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	res := ReloadResult{Applied: []string{}, RestartRequired: []string{}, Failed: map[string]string{}}

	// Settings that apply live are synced into a.cfg first, so the section
	// comparison below only sees what still needs a restart.
	if next.Auth.RateLimit != a.cfg.Auth.RateLimit && a.api != nil {
		a.api.SetAuthRateLimit(next.Auth.RateLimit)
		a.cfg.Auth.RateLimit = next.Auth.RateLimit
		res.Applied = append(res.Applied, "auth.rate_limit")
	}
	if !slices.Equal(next.Tenants.Regions, a.cfg.Tenants.Regions) || next.Tenants.DefaultRegion != a.cfg.Tenants.DefaultRegion {
		if err := a.tenants.SetRegions(next.Tenants.Regions, next.Tenants.DefaultRegion); err != nil {
			res.Failed["tenants.regions"] = err.Error()
		} else {
			a.cfg.Tenants.Regions, a.cfg.Tenants.DefaultRegion = next.Tenants.Regions, next.Tenants.DefaultRegion
			res.Applied = append(res.Applied, "tenants.regions")
		}
	}
	if !reflect.DeepEqual(next.Usage, a.cfg.Usage) {
		if err := a.tenants.SetMetricPolicies(next.Usage.Metrics); err != nil {
			res.Failed["usage.metrics"] = err.Error()
		} else {
			a.cfg.Usage = next.Usage
			res.Applied = append(res.Applied, "usage.metrics")
		}
	}
	cur := a.cfg

	// Other top-level sections, except log and plugins, need a restart.
	cv, nv := reflect.ValueOf(cur), reflect.ValueOf(next)
	for i := range cv.NumField() {
		f := cv.Type().Field(i)
		name := cmp.Or(yamlName(f), f.Name)
		if name == "log" || name == "plugins" {
			continue
		}
		if !reflect.DeepEqual(cv.Field(i).Interface(), nv.Field(i).Interface()) {
			res.RestartRequired = append(res.RestartRequired, name)
		}
	}

	if cur.Log.Format != next.Log.Format {
		res.RestartRequired = append(res.RestartRequired, "log.format")
	}
	if cur.Log.Level != next.Log.Level {
		var lvl slog.Level
		switch err := lvl.UnmarshalText([]byte(cmp.Or(next.Log.Level, "info"))); {
		case err != nil:
			res.Failed["log.level"] = err.Error()
		case a.level == nil:
			res.RestartRequired = append(res.RestartRequired, "log.level")
		default:
			a.level.Set(lvl)
			a.cfg.Log.Level = next.Log.Level
			res.Applied = append(res.Applied, "log.level")
		}
	}

	// Plugins: config changes of reconfigurable instances apply in place;
	// added, removed, re-scoped or other changes need a restart.
	old := map[string]PluginSpec{}
	for _, s := range cur.Plugins {
		old[instanceName(s)] = s
	}
	seen := map[string]bool{}
	for i, s := range next.Plugins {
		name := instanceName(s)
		seen[name] = true
		prev, ok := old[name]
		if ok && reflect.DeepEqual(prev, s) {
			continue
		}
		key := "plugins." + name
		if !ok {
			res.RestartRequired = append(res.RestartRequired, key)
			continue
		}
		switch err := a.plugins.Reconfigure(ctx, s); {
		case errors.Is(err, plugin.ErrRestartRequired):
			res.RestartRequired = append(res.RestartRequired, key)
		case err != nil:
			res.Failed[key] = err.Error()
		default:
			for j := range a.cfg.Plugins {
				if instanceName(a.cfg.Plugins[j]) == name {
					a.cfg.Plugins[j] = next.Plugins[i]
				}
			}
			res.Applied = append(res.Applied, key)
		}
	}
	for name := range old {
		if !seen[name] {
			res.RestartRequired = append(res.RestartRequired, "plugins."+name)
		}
	}
	if len(res.Failed) == 0 {
		res.Failed = nil
	}
	a.log.Info("configuration reloaded", "applied", res.Applied, "restart_required", res.RestartRequired, "failed", res.Failed)
	return res, nil
}

func instanceName(s PluginSpec) string { return cmp.Or(s.Name, s.Plugin) }

func yamlName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	for i := range len(tag) {
		if tag[i] == ',' {
			return tag[:i]
		}
	}
	return tag
}

// reloadOnSignal reloads the configuration on SIGHUP until ctx is done.
func (a *App) reloadOnSignal(ctx context.Context, wg *sync.WaitGroup) {
	if a.configPath == "" {
		return
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	wg.Go(func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if _, err := a.ReloadFromFile(ctx); err != nil {
					a.log.Error("configuration reload failed", "err", err)
				}
			}
		}
	})
}

func (a *App) reloadFunc() func(context.Context) (any, error) {
	if a.configPath == "" {
		return nil
	}
	return func(ctx context.Context) (any, error) { return a.ReloadFromFile(ctx) }
}
