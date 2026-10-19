// Package wasmguest is the guest side of Tenarium's WASM plugin ABI, for
// modules written in Go (GOOS=wasip1 GOARCH=wasm, or TinyGo -target=wasip1).
//
// A module is a WASI command. For every invocation Tenarium writes one Input
// as JSON to stdin and reads one Output from stdout; a non-zero exit code
// means failure. Modules run sandboxed: no filesystem, no network, no wall
// clock, bounded memory and time. Any language that compiles to WASI can
// implement the same ABI by reading stdin and writing stdout.
//
//	func main() {
//		wasmguest.Run(func(in wasmguest.Input) wasmguest.Output {
//			if in.Hook != nil && strings.HasPrefix(in.Hook.Tenant.Slug, "tmp-") {
//				return wasmguest.Reject("temporary slugs are not allowed")
//			}
//			return wasmguest.Output{}
//		})
//	}
package wasmguest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Input is one invocation.
type Input struct {
	// Kind is "hook" or "event".
	Kind string `json:"kind"`
	// Hook is set for hook invocations.
	Hook *sdk.HookRequest `json:"hook,omitempty"`
	// Event is set for event invocations.
	Event *sdk.CloudEvent `json:"event,omitempty"`
	// Config is the module configuration from Tenarium's config file.
	Config map[string]any `json:"config,omitempty"`
}

// Output is the module's answer. For hooks, Tenant and Member (if set)
// replace the proposed values; Reject refuses the operation.
type Output struct {
	Reject string      `json:"reject,omitempty"`
	Tenant *sdk.Tenant `json:"tenant,omitempty"`
	Member *sdk.Member `json:"member,omitempty"`
	// Error reports a failure (the operation fails with an internal error;
	// events are retried).
	Error string `json:"error,omitempty"`
}

// Reject returns an Output refusing the operation.
func Reject(format string, args ...any) Output {
	return Output{Reject: fmt.Sprintf(format, args...)}
}

// Run reads the input, calls fn and writes its output. It exits non-zero if
// the input cannot be decoded or fn sets Error.
func Run(fn func(Input) Output) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		fail(fmt.Errorf("decode input: %w", err))
	}
	out := fn(in)
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail(err)
	}
	if out.Error != "" {
		fmt.Fprintln(os.Stderr, out.Error)
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
