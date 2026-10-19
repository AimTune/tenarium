package iac

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// Command is one CLI invocation.
type Command struct {
	// Path is the binary to run.
	Path string
	Args []string
	// Dir is the working directory.
	Dir string
	// Env is the complete environment ("KEY=value"); nothing else is
	// inherited from the Tenarium process.
	Env []string
}

// String renders the command for messages, without the environment.
func (c Command) String() string {
	return strings.Join(append([]string{c.Path}, c.Args...), " ")
}

// RunResult is the output of a command.
type RunResult struct {
	// Stdout is the standard output (bounded).
	Stdout []byte
	// Output is the tail of stdout and stderr interleaved, for logs and
	// error messages.
	Output []byte
}

// Runner executes commands. Tests replace it with a fake.
type Runner interface {
	Run(ctx context.Context, c Command) (RunResult, error)
}

// Limits of ExecRunner's buffers.
const (
	maxStdout     = 16 << 20
	maxOutputTail = 1 << 20
	// cancelGrace is how long a command may take to exit after it was
	// interrupted (the CLI releases state locks) before it is killed.
	cancelGrace = 30 * time.Second
)

// ExecRunner runs commands with os/exec. When the context is done the
// process is interrupted (killed on Windows) and killed after a grace
// period.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, c Command) (RunResult, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Stdin = nil
	cmd.Cancel = func() error {
		if runtime.GOOS == "windows" {
			return cmd.Process.Kill()
		}
		return cmd.Process.Signal(os.Interrupt)
	}
	cmd.WaitDelay = cancelGrace
	stdout := &boundedBuffer{max: maxStdout}
	tail := &tailBuffer{max: maxOutputTail}
	cmd.Stdout = io.MultiWriter(stdout, tail)
	cmd.Stderr = tail
	err := cmd.Run()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return RunResult{Stdout: stdout.Bytes(), Output: tail.Bytes()}, err
}

// boundedBuffer keeps the first max bytes written to it.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

// tailBuffer keeps the last max bytes written to it. It is safe for the
// concurrent writes of stdout and stderr.
type tailBuffer struct {
	mu        sync.Mutex
	buf       []byte
	max       int
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > 2*b.max {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-b.max:]...)
		b.truncated = true
	}
	return len(p), nil
}

func (b *tailBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.buf
	if len(out) > b.max {
		out, b.truncated = out[len(out)-b.max:], true
	}
	if b.truncated {
		return append([]byte(truncatedMark), out...)
	}
	return bytes.Clone(out)
}

const truncatedMark = "[... output truncated ...]\n"

// tail returns the last limit bytes of out, marking truncation.
func tail(out []byte, limit int) string {
	s := strings.TrimSpace(string(out))
	if len(s) <= limit {
		return s
	}
	s = s[len(s)-limit:]
	// Do not start in the middle of a line.
	if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return truncatedMark + strings.TrimPrefix(s, truncatedMark)
}

// baseEnv are passed to every command so CLIs can find their binaries,
// home directory, temporary directory, certificates and proxies.
var baseEnv = []string{
	"PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ", "TMPDIR",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	// Windows.
	"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
	"USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES",
}

// buildEnv assembles a command's environment: the base variables and the
// env_passthrough allowlist taken from the process environment, then the
// configured env, then engine-specific variables (later entries win).
func (p *Plugin) buildEnv(engine map[string]string) []string {
	caseInsensitive := runtime.GOOS == "windows"
	match := func(name, pattern string) bool {
		if caseInsensitive {
			name, pattern = strings.ToUpper(name), strings.ToUpper(pattern)
		}
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
			return strings.HasPrefix(name, prefix)
		}
		return name == pattern
	}
	out := map[string]string{}
	keyOf := func(name string) string {
		if caseInsensitive {
			return strings.ToUpper(name)
		}
		return name
	}
	names := map[string]string{} // key → spelling
	set := func(name, value string) {
		k := keyOf(name)
		names[k] = name
		out[k] = value
	}
	for _, kv := range p.environ() {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" { // Windows has "=C:=C:\..." entries
			continue
		}
		allowed := slices.ContainsFunc(baseEnv, func(b string) bool { return match(name, b) }) ||
			slices.ContainsFunc(p.cfg.EnvPassthrough, func(pat string) bool { return match(name, pat) })
		if allowed {
			set(name, value)
		}
	}
	for k, v := range p.cfg.Env {
		set(k, v)
	}
	for k, v := range engine {
		set(k, v)
	}
	env := make([]string, 0, len(out))
	for _, k := range slices.Sorted(maps.Keys(out)) {
		env = append(env, names[k]+"="+out[k])
	}
	return env
}

func osEnviron() []string { return os.Environ() }

func execLookPath(s string) (string, error) { return exec.LookPath(s) }

// cli is the shared part of the CLI engines.
type cli struct {
	p      *Plugin
	binary string
}

// run executes the binary and wraps failures with the tail of its output.
func (c *cli) run(ctx context.Context, dir string, env []string, args ...string) (RunResult, error) {
	cmd := Command{Path: c.binary, Args: args, Dir: dir, Env: env}
	res, err := c.p.runner.Run(ctx, cmd)
	if err != nil {
		step := c.binary
		if len(args) > 0 {
			step += " " + args[0]
			if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
				step += " " + args[1]
			}
		}
		if out := tail(res.Output, c.p.cfg.LogLimit); out != "" {
			return res, fmt.Errorf("%s: %w\n%s", step, err, out)
		}
		return res, fmt.Errorf("%s: %w", step, err)
	}
	return res, nil
}

// health checks that the binary can be found.
func (c *cli) health(context.Context) error {
	if _, err := c.p.lookPath(c.binary); err != nil {
		return fmt.Errorf("%s not found: %w", c.binary, err)
	}
	return nil
}
