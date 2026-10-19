// Package wasm runs sandboxed WebAssembly modules as hooks and event
// handlers, so policies can be shipped as data rather than compiled into
// Tenarium. Modules use the ABI described in pkg/wasmguest: a WASI command
// reading one JSON input from stdin and writing one JSON output to stdout.
//
// Modules get no filesystem, network or wall clock, a memory cap and a
// per-invocation timeout, which makes them suitable for untrusted or
// tenant-supplied logic.
package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/wasmguest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

func init() {
	sdk.Register("wasm", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// Module is the path to the .wasm file.
	Module string `json:"module"`
	// Hooks lists hook points the module handles.
	Hooks []string `json:"hooks"`
	// Events, if set, subscribes the module to these event type patterns.
	Events []string `json:"events"`
	// Config is passed to the module on every invocation.
	Config        map[string]any `json:"config"`
	Timeout       string         `json:"timeout"`
	MemoryLimitMB int            `json:"memory_limit_mb"`
	// Priority orders this module's hooks among other plugins' hooks.
	Priority int `json:"priority"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "module": {"type": "string", "minLength": 1},
    "hooks": {"type": "array", "items": {"type": "string"}},
    "events": {"type": "array", "items": {"type": "string"}},
    "config": {"type": "object"},
    "timeout": {"type": "string"},
    "memory_limit_mb": {"type": "integer", "minimum": 1, "maximum": 4096},
    "priority": {"type": "integer"}
  },
  "required": ["module"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg      Config
	timeout  time.Duration
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "wasm", Name: "WebAssembly", Version: "0.1.0",
		Description:  "Runs sandboxed WASM modules as hooks and event handlers.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if len(p.cfg.Hooks) == 0 && len(p.cfg.Events) == 0 {
		return errors.New("configure at least one of hooks or events")
	}
	var err error
	p.timeout = time.Second
	if p.cfg.Timeout != "" {
		if p.timeout, err = time.ParseDuration(p.cfg.Timeout); err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
	}
	memMB := p.cfg.MemoryLimitMB
	if memMB == 0 {
		memMB = 64
	}
	if memMB < 1 || memMB > 4096 {
		return errors.New("memory_limit_mb must be between 1 and 4096")
	}
	code, err := os.ReadFile(p.cfg.Module)
	if err != nil {
		return err
	}
	rc := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(uint32(memMB) * 16). //nolint:gosec // bounded above; 64 KiB pages
		WithCloseOnContextDone(true)
	p.runtime = wazero.NewRuntimeWithConfig(ctx, rc)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, p.runtime); err != nil {
		return err
	}
	if p.compiled, err = p.runtime.CompileModule(ctx, code); err != nil {
		return fmt.Errorf("compile %s: %w", p.cfg.Module, err)
	}

	for _, h := range p.cfg.Hooks {
		point := sdk.HookPoint(h)
		r.Hook(point, p.hook, sdk.WithPriority(p.cfg.Priority))
	}
	if len(p.cfg.Events) > 0 {
		r.Subscribe("events", sdk.EventFilter{Types: p.cfg.Events}, p.event)
	}
	return nil
}

func (p *Plugin) hook(ctx context.Context, req *sdk.HookRequest) error {
	out, err := p.invoke(ctx, wasmguest.Input{Kind: "hook", Hook: req, Config: p.cfg.Config})
	if err != nil {
		return err
	}
	if out.Reject != "" {
		return sdk.Reject("%s", out.Reject)
	}
	if out.Tenant != nil && req.Tenant != nil {
		*req.Tenant = *out.Tenant
	}
	if out.Member != nil && req.Member != nil {
		*req.Member = *out.Member
	}
	return nil
}

func (p *Plugin) event(ctx context.Context, e sdk.Event) error {
	ce := e.CloudEvent()
	_, err := p.invoke(ctx, wasmguest.Input{Kind: "event", Event: &ce, Config: p.cfg.Config})
	return err
}

// invoke instantiates a fresh module instance per call, so invocations share
// no state and a misbehaving call cannot affect the next one.
func (p *Plugin) invoke(ctx context.Context, in wasmguest.Input) (wasmguest.Output, error) {
	input, err := json.Marshal(in)
	if err != nil {
		return wasmguest.Output{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	// Guest memory is capped by the runtime, but anything written to stdout
	// and stderr lands in host memory, so cap that too.
	stdout, stderr := &limitedBuffer{max: maxOutput}, &limitedBuffer{max: 64 << 10}
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithStdin(bytes.NewReader(input)).
		WithStdout(stdout).
		WithStderr(stderr)
	mod, err := p.runtime.InstantiateModule(ctx, p.compiled, cfg)
	if mod != nil {
		_ = mod.Close(context.WithoutCancel(ctx))
	}
	if stdout.overflow {
		return wasmguest.Output{}, fmt.Errorf("wasm module wrote more than %d bytes of output", maxOutput)
	}
	var exit *sys.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == 0:
	case ctx.Err() != nil:
		return wasmguest.Output{}, fmt.Errorf("wasm module timed out after %s", p.timeout)
	case err != nil:
		return wasmguest.Output{}, fmt.Errorf("wasm module failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var out wasmguest.Output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return wasmguest.Output{}, fmt.Errorf("wasm module wrote invalid output: %w", err)
	}
	if out.Error != "" {
		return wasmguest.Output{}, errors.New(out.Error)
	}
	return out, nil
}

// maxOutput bounds a module's stdout.
const maxOutput = 1 << 20

// limitedBuffer keeps at most max bytes and fails writes beyond that, which
// makes the guest's write fail instead of growing host memory.
type limitedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.overflow = true
		return 0, errors.New("output limit exceeded")
	}
	return b.Buffer.Write(p)
}

func (p *Plugin) Stop(ctx context.Context) error {
	if p.runtime == nil {
		return nil
	}
	return p.runtime.Close(ctx)
}
