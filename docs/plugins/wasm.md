# WebAssembly plugins

The `wasm` plugin runs WebAssembly modules as hooks and event handlers, using
[wazero](https://wazero.io), a pure-Go runtime that needs no cgo. Modules are sandboxed:

- no filesystem and no network;
- a fake clock (modules cannot observe real time);
- a memory cap (`memory_limit_mb`, default 64);
- a timeout per invocation (`timeout`, default 1s);
- a fresh instance for every invocation, so no state leaks between calls.

This makes WASM a good fit for policy logic that is shipped as data, edited by another team,
or supplied by tenants.

```yaml
- plugin: wasm
  name: naming-policy
  config:
    module: /etc/tenarium/policy.wasm
    hooks: [tenant.before_create, tenant.before_update]
    events: []                       # optional: also subscribe to these event types
    config: {blocked_words: [admin, root], require_label: owner}
    timeout: 500ms
    memory_limit_mb: 32
    priority: 0
```

## ABI

A module is a **WASI command** (`_start`). For each invocation Tenarium writes one JSON
document to the module's stdin and reads one JSON document from its stdout. A non-zero exit code
is a failure, and stderr is included in the error.

Input:

```json
{"kind": "hook", "hook": {"point": "tenant.before_create", "tenant": {...}, "previous": null, "member": null}, "config": {...}}
{"kind": "event", "event": {CloudEvent}, "config": {...}}
```

Output:

```json
{}                                   // allow, no change
{"reject": "slug must not contain \"admin\""}
{"tenant": {...}}                    // modified tenant (create/update hooks)
{"error": "something broke"}         // internal error; events are retried
```

Any language that compiles to WASI works this way: Go, TinyGo, Rust, C, Zig, AssemblyScript,
and JavaScript through Javy.

## Go modules

`pkg/wasmguest` handles the I/O:

```go
//go:build wasip1

package main

import (
	"strings"

	"github.com/AimTune/tenarium/pkg/wasmguest"
)

func main() {
	wasmguest.Run(func(in wasmguest.Input) wasmguest.Output {
		if in.Hook != nil && strings.HasPrefix(in.Hook.Tenant.Slug, "tmp-") {
			return wasmguest.Reject("temporary slugs are not allowed")
		}
		return wasmguest.Output{}
	})
}
```

```sh
GOOS=wasip1 GOARCH=wasm go build -o policy.wasm ./examples/wasm-policy
# smaller and faster to start:
tinygo build -target=wasip1 -o policy.wasm ./examples/wasm-policy
```

## Rust

```rust
use std::io::{self, Read};

fn main() {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).unwrap();
    let input: serde_json::Value = serde_json::from_str(&s).unwrap();
    let slug = input["hook"]["tenant"]["slug"].as_str().unwrap_or("");
    if slug.contains("admin") {
        println!(r#"{{"reject":"reserved word"}}"#);
    } else {
        println!("{{}}");
    }
}
```

```sh
cargo build --release --target wasm32-wasip1
```

## Performance

Modules are compiled once at startup; each invocation then instantiates a fresh module. With a
module built by the standard Go toolchain (`GOOS=wasip1`), one hook invocation takes about
**9 ms** (measured with `go test -bench HookInvocation ./plugins/wasm/` on a 12-thread
desktop), almost all of it spent starting the Go runtime inside the module. That is fine for
tenant lifecycle hooks, which are rare. For anything on a hot path, build with TinyGo or Rust:
their modules are much smaller and start faster. Measure with the same benchmark.
