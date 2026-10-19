package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"text/tabwriter"

	"github.com/AimTune/tenarium/pkg/client"
)

// config is the tenariumctl configuration file: named connection profiles.
type config struct {
	CurrentProfile string              `json:"current_profile,omitempty"`
	Profiles       map[string]*profile `json:"profiles,omitempty"`
}

type profile struct {
	URL    string            `json:"url,omitempty"`
	APIKey string            `json:"api_key,omitempty"`
	Email  string            `json:"email,omitempty"`
	Tenant string            `json:"tenant,omitempty"`
	Tokens *client.TokenPair `json:"tokens,omitempty"`
}

const defaultProfile = "default"

// configPath returns $TENARIUM_CONFIG or <user config dir>/tenarium/config.json,
// where the user config dir follows os.UserConfigDir (XDG_CONFIG_HOME or
// ~/.config on Unix, %APPDATA% on Windows) using the injected environment.
func (a *app) configPath() (string, error) {
	if p := a.env("TENARIUM_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := a.userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tenarium", "config.json"), nil
}

func (a *app) userConfigDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := a.env("APPDATA"); d != "" {
			return d, nil
		}
		return "", errors.New("%APPDATA% is not set")
	case "darwin", "ios":
		if h := a.env("HOME"); h != "" {
			return filepath.Join(h, "Library", "Application Support"), nil
		}
		return "", errors.New("$HOME is not set")
	default:
		if d := a.env("XDG_CONFIG_HOME"); d != "" {
			if !filepath.IsAbs(d) {
				return "", errors.New("$XDG_CONFIG_HOME must be an absolute path")
			}
			return d, nil
		}
		if h := a.env("HOME"); h != "" {
			return filepath.Join(h, ".config"), nil
		}
		return "", errors.New("neither $XDG_CONFIG_HOME nor $HOME is set")
	}
}

func (a *app) loadConfig() (*config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	p, err := a.configPath()
	if err != nil {
		return nil, fmt.Errorf("locate config: %w", err)
	}
	cfg := &config{}
	b, err := os.ReadFile(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read config: %w", err)
	default:
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", p, err)
		}
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*profile{}
	}
	a.cfg, a.cfgPath = cfg, p
	return cfg, nil
}

// saveConfig writes the config atomically with owner-only permissions; it
// holds credentials.
func (a *app) saveConfig() error {
	if a.cfg == nil {
		return nil
	}
	b, err := json.MarshalIndent(a.cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.cfgPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.cfgPath), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.cfgPath)
}

// profileName is --profile, $TENARIUM_PROFILE, the current profile or "default".
func (a *app) profileName() string {
	cur := ""
	if a.cfg != nil {
		cur = a.cfg.CurrentProfile
	}
	return firstNonEmpty(a.g.profile, a.env("TENARIUM_PROFILE"), cur, defaultProfile)
}

func configGroup() group {
	return group{
		name:    "config",
		summary: "Manage connection profiles",
		verbs: []command{
			{name: "list", summary: "List profiles", run: cmdConfigList},
			{name: "use-profile", args: "<name>", summary: "Make a profile the default", run: cmdConfigUse},
			{name: "delete-profile", args: "<name>", summary: "Delete a profile and its credentials", run: cmdConfigDelete},
			{name: "path", summary: "Print the config file path", run: cmdConfigPath},
		},
	}
}

func cmdConfigList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "List profiles.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		type row struct {
			Name    string `json:"name"`
			Current bool   `json:"current"`
			URL     string `json:"url"`
			Auth    string `json:"auth"`
		}
		rows := []row{}
		for _, n := range sortedKeys(cfg.Profiles) {
			rows = append(rows, row{n, n == a.profileName(), cfg.Profiles[n].URL, authKind(cfg.Profiles[n])})
		}
		return a.writeJSON(rows)
	}
	return a.table(func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "CURRENT\tNAME\tURL\tAUTH")
		for _, n := range sortedKeys(cfg.Profiles) {
			mark := ""
			if n == a.profileName() {
				mark = "*"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", mark, n, cfg.Profiles[n].URL, authKind(cfg.Profiles[n]))
		}
	})
}

func authKind(p *profile) string {
	switch {
	case p.APIKey != "":
		return "api-key"
	case p.Tokens != nil:
		s := "user " + p.Email
		if p.Tenant != "" {
			s += " @" + p.Tenant
		}
		return s
	}
	return "none"
}

func cmdConfigUse(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<name>", "Make a profile the default for later commands.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.Profiles[pos[0]] == nil {
		return fmt.Errorf("profile %q does not exist (see 'tenariumctl config list')", pos[0])
	}
	cfg.CurrentProfile = pos[0]
	if err := a.saveConfig(); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Switched to profile %q.", pos[0]), map[string]any{"current_profile": pos[0]})
}

func cmdConfigDelete(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<name>", "Delete a profile and its stored credentials (the session is not revoked; use logout for that).")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.Profiles[pos[0]] == nil {
		return fmt.Errorf("profile %q does not exist", pos[0])
	}
	delete(cfg.Profiles, pos[0])
	if cfg.CurrentProfile == pos[0] {
		cfg.CurrentProfile = ""
	}
	if err := a.saveConfig(); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Deleted profile %q.", pos[0]), map[string]any{"deleted": pos[0]})
}

func cmdConfigPath(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "Print the config file path.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	p, err := a.configPath()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, p)
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
