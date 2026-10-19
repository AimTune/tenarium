package server_test

import (
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestSCIMProvisioning(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	_, k := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "okta", "roles": []string{"admin"}})
	idp := as(c, k["key"].(string))
	_, mk := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "m", "roles": []string{"member"}})
	member := as(c, mk["key"].(string))
	const base = "/v1/tenants/acme/scim/v2"

	if code, cfgDoc := idp("GET", base+"/ServiceProviderConfig", nil); code != 200 || cfgDoc["patch"] == nil {
		t.Fatalf("service provider config: %d %v", code, cfgDoc)
	}
	newUser := map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "ann@acme.example", "name": map[string]any{"givenName": "Ann", "familyName": "Lee"},
		"emails": []map[string]any{{"value": "ann@acme.example", "primary": true}}, "active": true,
	}
	if code, _ := member("POST", base+"/Users", newUser); code != 403 {
		t.Fatalf("member key provisioned: %d", code)
	}
	code, u := idp("POST", base+"/Users", newUser)
	if code != 201 || u["userName"] != "ann@acme.example" || u["active"] != true {
		t.Fatalf("create: %d %v", code, u)
	}
	id := u["id"].(string)
	if code, _ := idp("POST", base+"/Users", newUser); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	_, list := idp("GET", base+`/Users?filter=userName%20eq%20%22ann@acme.example%22`, nil)
	if list["totalResults"] != float64(1) {
		t.Fatalf("filter: %v", list)
	}
	if code, _ := idp("GET", base+`/Users?filter=name.familyName%20co%20%22x%22`, nil); code != 400 {
		t.Fatalf("unsupported filter: %d", code)
	}

	// Okta-style deactivation, then Entra-style reactivation.
	patch := func(ops ...map[string]any) (int, map[string]any) {
		return idp("PATCH", base+"/Users/"+id, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops})
	}
	if code, u := patch(map[string]any{"op": "replace", "value": map[string]any{"active": false}}); code != 200 || u["active"] != false {
		t.Fatalf("deactivate: %d %v", code, u)
	}
	_, m := c.do("GET", "/v1/tenants/acme/members/"+id, nil)
	if m["status"] != "suspended" {
		t.Fatalf("member not suspended: %v", m)
	}
	if code, u := patch(map[string]any{"op": "Replace", "path": "active", "value": "True"}); code != 200 || u["active"] != true {
		t.Fatalf("reactivate: %d %v", code, u)
	}

	// The provider cannot rename people of domains the tenant does not own.
	patch(map[string]any{"op": "replace", "path": "displayName", "value": "Mallory"})
	if _, usr := c.do("GET", "/v1/users/ann@acme.example", nil); usr["name"] == "Mallory" {
		t.Fatal("foreign identity renamed")
	}

	// Groups are roles.
	_, groups := idp("GET", base+"/Groups", nil)
	if groups["totalResults"] != float64(4) {
		t.Fatalf("groups: %v", groups)
	}
	addAdmin := map[string]any{"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": id}}}}}
	if code, g := idp("PATCH", base+"/Groups/admin", addAdmin); code != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("add to admin group: %d %v", code, g)
	}
	if _, m := c.do("GET", "/v1/tenants/acme/members/"+id, nil); m["role"] != "admin" {
		t.Fatalf("role not granted: %v", m)
	}
	removeAdmin := map[string]any{"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + id + `"]`}}}
	idp("PATCH", base+"/Groups/admin", removeAdmin)
	if _, m := c.do("GET", "/v1/tenants/acme/members/"+id, nil); m["role"] != "member" {
		t.Fatalf("role not dropped: %v", m)
	}
	// Other names become tenant groups (teams).
	code, eng := idp("POST", base+"/Groups", map[string]any{"displayName": "Engineering", "members": []map[string]any{{"value": id}}})
	if code != 201 || len(eng["members"].([]any)) != 1 {
		t.Fatalf("team group: %d %v", code, eng)
	}
	_, teams := c.do("GET", "/v1/tenants/acme/groups", nil)
	if items := teams["items"].([]any); len(items) != 1 || items[0].(map[string]any)["name"] != "Engineering" {
		t.Fatalf("tenant groups: %v", teams)
	}

	if code, _ := idp("PUT", base+"/Users/"+id, map[string]any{"userName": "other@acme.example"}); code != 400 {
		t.Fatalf("userName change: %d", code)
	}
	if code, _ := idp("DELETE", base+"/Users/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, body := idp("GET", base+"/Users/"+id, nil); code != 404 || body["status"] != "404" {
		t.Fatalf("after delete: %d %v", code, body)
	}
}
