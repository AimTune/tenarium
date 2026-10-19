package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestSigningKeyRotation(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	base := startServer(t, cfg)
	c := client{t: t, base: base}
	jwksKids := func() []string {
		resp, err := http.Get(base + "/.well-known/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var set struct {
			Keys []struct {
				Kid string `json:"kid"`
			} `json:"keys"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&set)
		var out []string
		for _, k := range set.Keys {
			out = append(out, k.Kid)
		}
		return out
	}

	_, list := c.do("GET", "/v1/signing-keys", nil)
	keys := list["items"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["active"] != true {
		t.Fatalf("keys: %v", keys)
	}
	first := keys[0].(map[string]any)["kid"].(string)
	if code, _ := c.do("DELETE", "/v1/signing-keys/"+first, nil); code != 409 {
		t.Fatalf("retired the active key: %d", code)
	}
	code, rotated := c.do("POST", "/v1/signing-keys/rotate", nil)
	if code != 201 || rotated["kid"] == first || rotated["active"] != true {
		t.Fatalf("rotate: %d %v", code, rotated)
	}
	if kids := jwksKids(); len(kids) != 2 {
		t.Fatalf("jwks after rotation: %v", kids)
	}
	if code, _ := c.do("DELETE", "/v1/signing-keys/"+first, nil); code != 204 {
		t.Fatalf("retire: %d", code)
	}
	if kids := jwksKids(); len(kids) != 1 || kids[0] != rotated["kid"] {
		t.Fatalf("jwks after retire: %v", kids)
	}
	if code, _ := c.do("DELETE", "/v1/signing-keys/nope", nil); code != 404 {
		t.Fatalf("unknown key: %d", code)
	}
	_, audit := c.do("GET", "/v1/audit?type=signing_key.*", nil)
	if n := len(audit["items"].([]any)); n != 2 {
		t.Fatalf("audit events: %d", n)
	}

	// Tenant-scoped callers cannot even read them.
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	_, k := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "o", "roles": []string{"owner"}})
	if code, _ := as(c, k["key"].(string))("GET", "/v1/signing-keys", nil); code != 403 {
		t.Fatalf("tenant key listed signing keys: %d", code)
	}
}
