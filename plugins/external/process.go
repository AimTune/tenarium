package external

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/extplugin"
)

// baseEnv lists the environment variables a managed plugin inherits from
// Tenarium. Everything else (database DSNs, API keys, other plugins'
// secrets) stays private unless listed in inherit_env or set in env.
var baseEnv = []string{
	"PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ", "TMPDIR",
	// Windows needs these to start most runtimes.
	"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE",
	"APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "SYSTEMDRIVE",
}

// process supervises a managed plugin. It keeps the same address across
// restarts so registrations stay valid, but every spawn gets a fresh secret
// and proof key.
type process struct {
	cfg       Config
	log       *slog.Logger
	onRestart func(ctx context.Context)
	onExit    func()

	addr string
	ctx  context.Context
	stop context.CancelFunc

	mu       sync.Mutex
	cmd      *exec.Cmd
	exited   chan struct{}
	stopped  bool
	secret   string
	proofKey string
}

func (p *process) start() (string, error) {
	addr, err := freeAddr()
	if err != nil {
		return "", err
	}
	p.addr = addr
	p.ctx, p.stop = context.WithCancel(context.Background())
	p.mu.Lock()
	err = p.spawnLocked()
	p.mu.Unlock()
	if err != nil {
		return "", err
	}
	go p.supervise()
	return addr, nil
}

// credentials returns the current secret and proof key.
func (p *process) credentials() (secret, proofKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.secret, p.proofKey
}

func (p *process) environ() []string {
	env := []string{}
	allowed := append(append([]string{}, baseEnv...), p.cfg.InheritEnv...)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		for _, a := range allowed {
			if name == a || (runtime.GOOS == "windows" && strings.EqualFold(name, a)) {
				env = append(env, kv)
				break
			}
		}
	}
	for k, v := range p.cfg.Env {
		env = append(env, k+"="+v)
	}
	return append(env,
		extplugin.EnvAddr+"="+p.addr,
		extplugin.EnvSecret+"="+p.secret,
		extplugin.EnvProofKey+"="+p.proofKey)
}

// spawnLocked starts a new process; p.mu must be held.
func (p *process) spawnLocked() error {
	if p.stopped {
		return errors.New("plugin stopped")
	}
	p.secret, p.proofKey = randomSecret(), randomSecret()
	cmd := exec.Command(p.cfg.Command[0], p.cfg.Command[1:]...)
	cmd.Dir = p.cfg.Dir
	cmd.Env = p.environ()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start plugin %v: %w", p.cfg.Command, err)
	}
	go p.pipe(stdout, "stdout")
	go p.pipe(stderr, "stderr")
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	p.cmd, p.exited = cmd, exited
	p.log.Info("plugin process started", "pid", cmd.Process.Pid, "addr", p.addr)
	return nil
}

func (p *process) pipe(r io.Reader, stream string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		p.log.Info(sc.Text(), "stream", stream)
	}
}

// supervise restarts the process with exponential backoff when it exits
// unexpectedly.
func (p *process) supervise() {
	backoff := time.Second
	for {
		p.mu.Lock()
		exited := p.exited
		p.mu.Unlock()
		started := time.Now()
		select {
		case <-p.ctx.Done():
			return
		case <-exited:
		}
		p.onExit()
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		p.log.Error("plugin process exited; restarting", "backoff", backoff)
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
		// Holding the lock across the stopped check and the spawn means
		// stop() either prevents the spawn or sees the new process.
		p.mu.Lock()
		err := p.spawnLocked()
		p.mu.Unlock()
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			p.log.Error("restart plugin", "err", err)
			continue
		}
		p.onRestart(p.ctx)
	}
}

func (p *process) shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.stopped = true
	cmd, exited := p.cmd, p.exited
	p.mu.Unlock()
	p.stop()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	// Ask nicely where the OS supports it, then kill.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Process.Kill()
	}
	grace, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case <-exited:
		return nil
	case <-grace.Done():
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		<-exited
		return nil
	}
}

func freeAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

func randomSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
