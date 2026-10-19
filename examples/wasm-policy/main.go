//go:build wasip1

// Command wasm-policy is an example WASM hook module. Build it with:
//
//	GOOS=wasip1 GOARCH=wasm go build -o policy.wasm ./examples/wasm-policy
//
// and load it with:
//
//	plugins:
//	  - plugin: wasm
//	    name: policy-wasm
//	    config:
//	      module: ./policy.wasm
//	      hooks: [tenant.before_create, tenant.before_update]
//	      config: {blocked_words: [admin, root], require_label: owner}
package main

import (
	"strings"

	"github.com/AimTune/tenarium/pkg/wasmguest"
)

func main() {
	wasmguest.Run(func(in wasmguest.Input) wasmguest.Output {
		if in.Kind != "hook" || in.Hook == nil || in.Hook.Tenant == nil {
			return wasmguest.Output{}
		}
		t := in.Hook.Tenant
		if words, ok := in.Config["blocked_words"].([]any); ok {
			for _, w := range words {
				if s, _ := w.(string); s != "" && strings.Contains(t.Slug, s) {
					return wasmguest.Reject("slug must not contain %q", s)
				}
			}
		}
		if label, _ := in.Config["require_label"].(string); label != "" {
			if _, ok := t.Labels[label]; !ok {
				return wasmguest.Reject("label %q is required", label)
			}
		}
		if t.Labels == nil {
			t.Labels = map[string]string{}
		}
		t.Labels["policy"] = "wasm-checked"
		return wasmguest.Output{Tenant: t}
	})
}
