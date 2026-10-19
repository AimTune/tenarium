package eventschema

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func compile(t *testing.T, name string, raw []byte) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.AssertContent()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatalf("%s: compile: %v", name, err)
	}
	return s
}

// validate marshals v with encoding/json and validates it against s.
func validate(t *testing.T, s *jsonschema.Schema, name string, v any) {
	t.Helper()
	if err := check(s, v); err != nil {
		b, _ := json.Marshal(v)
		t.Errorf("%s: %s does not validate: %v", name, b, err)
	}
}

func check(s *jsonschema.Schema, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}

var sampleTime = time.Date(2026, 10, 11, 12, 30, 0, 123456789, time.UTC)

// sample returns a value of t with every field, element and pointer set.
func sample(t reflect.Type) reflect.Value {
	v := reflect.New(t).Elem()
	fill(v, 0)
	return v
}

func fill(v reflect.Value, depth int) {
	if depth > 6 {
		return
	}
	switch v.Type() {
	case timeType:
		v.Set(reflect.ValueOf(sampleTime))
		return
	case rawType:
		v.Set(reflect.ValueOf(json.RawMessage(`{"k":[1,"x"]}`)))
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.String:
		v.SetString("sample")
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fill(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Array:
		for i := range v.Len() {
			fill(v.Index(i), depth+1)
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return
		}
		m := reflect.MakeMap(v.Type())
		k := reflect.New(v.Type().Key()).Elem()
		k.SetString("key")
		e := reflect.New(v.Type().Elem()).Elem()
		fill(e, depth+1)
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.Interface:
		if v.NumMethod() == 0 {
			v.Set(reflect.ValueOf(map[string]any{"nested": []any{1.0, "x", true}}))
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				fill(f, depth+1)
			}
		}
	}
}

func TestAllSchemasCompileAndAcceptSamples(t *testing.T) {
	all := All()
	if len(all) != len(table) {
		t.Fatalf("All() has %d entries, table %d", len(all), len(table))
	}
	for _, row := range table {
		e, ok := GetVersion(row.typ, row.version)
		if !ok {
			t.Fatalf("%s v%s missing", row.typ, row.version)
		}
		if e.Description == "" || e.Version != Version1 {
			t.Errorf("%s: bad entry %+v", row.typ, e)
		}
		var doc map[string]any
		if err := json.Unmarshal(e.Schema, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["$schema"] != Draft || doc["type"] != "object" || doc["description"] != row.desc {
			t.Errorf("%s: unexpected schema header: %s", row.typ, e.Schema)
		}
		s := compile(t, row.typ+".json", e.Schema)
		validate(t, s, row.typ+" (filled)", sample(row.payload).Interface())
		validate(t, s, row.typ+" (zero)", reflect.Zero(row.payload).Interface())
		if req, _ := doc["required"].([]any); len(req) > 0 && check(s, map[string]any{}) == nil {
			t.Errorf("%s: empty object validates although fields are required", row.typ)
		}
	}
}

// The payloads below are built as maps by the code; keep them in step with
// internal/tenant/gdpr.go, internal/tenant/webauthn.go,
// internal/tenant/impersonation.go, internal/api/signingkeys.go and
// internal/webhooks/webhooks.go.
var mapPayloads = map[string]map[string]any{
	"user.erased":                  {"user_id": "u1", "redacted_events": 3},
	"tenant.purged":                {"tenant_id": "t1"},
	"signing_key.retired":          {"kid": "k1"},
	"user.passkey_added":           {"user_id": "u1", "email": "a@example.com", "passkey_id": "cred", "name": "YubiKey"},
	"user.passkey_removed":         {"user_id": "u1", "email": "a@example.com", "passkey_id": "cred", "name": "YubiKey"},
	"webhook.test":                 {"message": "test delivery"},
	"user.impersonation_consented": {"user_id": "u1", "expires_at": sampleTime},
	"user.impersonated": {"user_id": "u1", "impersonator": "oidc:support", "reason": "ticket 42", "tenant_id": "t1",
		"expires_at": sampleTime, "consent": true},
}

func TestMapPayloads(t *testing.T) {
	for typ, payload := range mapPayloads {
		e, ok := Get(typ)
		if !ok {
			t.Fatalf("%s missing", typ)
		}
		validate(t, compile(t, typ, e.Schema), typ, payload)
		var doc struct {
			Properties map[string]any `json:"properties"`
		}
		_ = json.Unmarshal(e.Schema, &doc)
		if got, want := slices.Sorted(maps.Keys(doc.Properties)), slices.Sorted(maps.Keys(payload)); !slices.Equal(got, want) {
			t.Errorf("%s: schema properties %v, payload keys %v", typ, got, want)
		}
	}
}

func TestSchemasRejectInvalidPayloads(t *testing.T) {
	for typ, bad := range map[string]any{
		sdk.EventTenantCreated:   map[string]any{"tenant": map[string]any{"slug": "x"}},           // id etc. missing
		sdk.EventMemberAdded:     map[string]any{"member": map[string]any{"id": 1}},               // wrong type
		sdk.EventUserUpdated:     sdk.UserEventData{User: sdk.User{ID: "u"}, Previous: nil},       // valid baseline below
		"tenant.quota_exceeded":  map[string]any{"tenant_id": "t", "metric": "m", "current": "1"}, // string, not integer
		"apikey.created":         map[string]any{"id": "k", "created_at": "yesterday"},            // bad date-time
		"user.erased":            map[string]any{"user_id": "u"},                                  // count missing
		"signing_key.rotated":    map[string]any{"kid": "k", "alg": "RS256", "active": "yes"},
		"tenant.action_canceled": []any{},
	} {
		e, _ := Get(typ)
		s := compile(t, typ, e.Schema)
		err := check(s, bad)
		if typ == sdk.EventUserUpdated {
			if err != nil {
				t.Errorf("%s: valid payload rejected: %v", typ, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: invalid payload accepted", typ)
		}
	}
}

func TestGet(t *testing.T) {
	e, ok := Get("tenant.created")
	if !ok || e.Type != "tenant.created" || e.Version != "1" {
		t.Fatalf("Get = %+v, %v", e, ok)
	}
	if _, ok := Get("no.such"); ok {
		t.Error("unknown type found")
	}
	if _, ok := GetVersion("tenant.created", "2"); ok {
		t.Error("unknown version found")
	}
	if v := Versions("tenant.created"); !slices.Equal(v, []string{"1"}) {
		t.Errorf("Versions = %v", v)
	}
	// Returned schemas are copies.
	e.Schema[0] = 'X'
	if again, _ := Get("tenant.created"); again.Schema[0] != '{' {
		t.Error("Get exposes registry storage")
	}
	all := All()
	all[0].Schema[0] = 'X'
	if All()[0].Schema[0] != '{' {
		t.Error("All exposes registry storage")
	}
	if !slices.IsSortedFunc(All(), func(a, b Entry) int {
		if a.Type < b.Type {
			return -1
		}
		if a.Type > b.Type {
			return 1
		}
		return versionNum(a.Version) - versionNum(b.Version)
	}) {
		t.Error("All is not sorted")
	}
	distinct := map[string]bool{}
	for _, row := range table {
		distinct[row.typ] = true
	}
	if ts := Types(); len(ts) != len(distinct) || !slices.IsSorted(ts) {
		t.Errorf("Types = %v", ts)
	}
}

func TestTenantSchemaShape(t *testing.T) {
	e, _ := Get(sdk.EventTenantUpdated)
	var doc struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Type       any            `json:"type"`
			Required   []string       `json:"required"`
			Properties map[string]any `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(e.Schema, &doc); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(doc.Required, []string{"tenant"}) {
		t.Errorf("required = %v", doc.Required)
	}
	if !reflect.DeepEqual(doc.Properties["previous"].Type, []any{"object", "null"}) {
		t.Errorf("previous type = %v", doc.Properties["previous"].Type)
	}
	if !slices.Contains(doc.Properties["tenant"].Required, "id") || slices.Contains(doc.Properties["tenant"].Required, "deleted_at") {
		t.Errorf("tenant required = %v", doc.Properties["tenant"].Required)
	}
	// Secrets are json:"-" and must not be published.
	for _, typ := range []string{"apikey.created", "webhook.created", "sso.updated", "oauth_client.updated"} {
		e, _ := Get(typ)
		for _, secret := range []string{`"hash"`, `"Hash"`, `"secret"`, `"Secret"`, `"client_secret"`, `"ClientSecret"`, `"SAMLMetadata"`, `"SecretHash"`, `"secret_hash"`} {
			if bytes.Contains(e.Schema, []byte(secret)) {
				t.Errorf("%s schema mentions %s", typ, secret)
			}
		}
	}
}

func TestDataSchemaURI(t *testing.T) {
	for _, tc := range []struct{ base, typ, ver, want string }{
		{"https://t.example.com", "tenant.created", "1", "https://t.example.com/v1/event-schemas/tenant.created/1"},
		{"https://t.example.com/", "user.mfa_enabled", "2", "https://t.example.com/v1/event-schemas/user.mfa_enabled/2"},
		{"https://t.example.com/api/", "a b", "1", "https://t.example.com/api/v1/event-schemas/a%20b/1"},
		{"", "plan.created", "1", "/v1/event-schemas/plan.created/1"},
	} {
		if got := DataSchemaURI(tc.base, tc.typ, tc.ver); got != tc.want {
			t.Errorf("DataSchemaURI(%q, %q, %q) = %q, want %q", tc.base, tc.typ, tc.ver, got, tc.want)
		}
	}
}

func TestEnvelope(t *testing.T) {
	raw := EnvelopeSchema()
	s := compile(t, "envelope.json", raw)

	// Every attribute sdk.CloudEvent has must be described.
	var doc struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ce := Generate(reflect.TypeFor[sdk.CloudEvent]())
	for name := range ce["properties"].(Schema) {
		if _, ok := doc.Properties[name]; !ok {
			t.Errorf("envelope schema lacks sdk.CloudEvent attribute %q", name)
		}
	}
	for _, name := range ce["required"].([]string) {
		if !slices.Contains(doc.Required, name) && name != "data" {
			t.Errorf("sdk.CloudEvent always sets %q but the envelope does not require it", name)
		}
	}

	full := sdk.Event{Seq: 42, ID: "0192", Type: "tenant.created", Source: "tenarium", Subject: "tenants/t1",
		TenantID: "t1", Actor: "system", Time: sampleTime, Data: json.RawMessage(`{"tenant":{}}`)}
	validate(t, s, "full", full.CloudEvent())
	validate(t, s, "minimal", sdk.Event{ID: "1", Type: "user.erased", Source: "tenarium", Time: sampleTime}.CloudEvent())

	withSchema := map[string]any{"specversion": "1.0", "id": "1", "source": "tenarium", "type": "plan.created",
		"time": "2026-10-11T00:00:00Z", "sequence": "1",
		"dataschema": DataSchemaURI("https://t.example.com", "plan.created", "1")}
	validate(t, s, "dataschema", withSchema)

	for name, bad := range map[string]map[string]any{
		"specversion": {"specversion": "0.3", "id": "1", "source": "s", "type": "a.b", "time": "2026-10-11T00:00:00Z", "sequence": "1"},
		"no id":       {"specversion": "1.0", "source": "s", "type": "a.b", "time": "2026-10-11T00:00:00Z", "sequence": "1"},
		"bad time":    {"specversion": "1.0", "id": "1", "source": "s", "type": "a.b", "time": "now", "sequence": "1"},
		"bad seq":     {"specversion": "1.0", "id": "1", "source": "s", "type": "a.b", "time": "2026-10-11T00:00:00Z", "sequence": 1},
		"bad type":    {"specversion": "1.0", "id": "1", "source": "s", "type": "Tenant", "time": "2026-10-11T00:00:00Z", "sequence": "1"},
	} {
		if check(s, bad) == nil {
			t.Errorf("envelope accepted %s", name)
		}
	}
}
