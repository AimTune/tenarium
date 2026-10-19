package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/mail"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/store/memory"
)

// refMergePatch is a literal transcription of RFC 7386 section 2, used as
// the oracle for mergePatch. It never mutates its inputs.
func refMergePatch(target any, patch any) any {
	pm, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	tm, ok := target.(map[string]any)
	if !ok {
		tm = map[string]any{}
	}
	out := maps.Clone(tm)
	for k, v := range pm {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = refMergePatch(out[k], v)
	}
	return out
}

func deepCopy(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// FuzzMergePatch compares mergePatch with the RFC 7386 reference, checks
// idempotence (applying a merge patch twice equals applying it once) and
// that nested objects of the original document are not mutated (the
// service relies on this when a hook or a failed transaction discards the
// result).
func FuzzMergePatch(f *testing.F) {
	for _, s := range [][2]string{
		{`{"a":1,"b":{"c":1,"d":2},"e":3}`, `{"a":null,"b":{"c":null,"x":9},"f":"new"}`},
		{`{}`, `{"a":{"b":{"c":null,"d":1}}}`},
		{`{"a":[1,2,{"b":1}]}`, `{"a":[{"b":null}]}`},
		{`{"a":"str"}`, `{"a":{"b":1}}`},
		{`{"a":{"b":1}}`, `{"a":"str"}`},
		{`{"theme":{"color":"blue","font":{"size":12}}}`, `{"theme":{"font":{"size":null},"color":null}}`},
		{`{"a":null}`, `{"a":{"x":null}}`},
	} {
		f.Add([]byte(s[0]), []byte(s[1]))
	}
	f.Fuzz(func(t *testing.T, docJSON, patchJSON []byte) {
		var doc, patch map[string]any
		if json.Unmarshal(docJSON, &doc) != nil || json.Unmarshal(patchJSON, &patch) != nil {
			return
		}
		want := refMergePatch(deepCopy(t, doc), deepCopy(t, patch))
		before := deepCopy(t, doc)
		nested := map[string]any{} // the original nested values, by key
		for k, v := range doc {
			if m, ok := v.(map[string]any); ok {
				nested[k] = m
			}
		}

		got := mergePatch(doc, patch)
		if !reflect.DeepEqual(any(got), want) {
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			t.Fatalf("mergePatch(%s, %s)\n got %s\nwant %s", docJSON, patchJSON, gj, wj)
		}
		for k, m := range nested {
			if !reflect.DeepEqual(m, before[k]) {
				t.Fatalf("nested object %q of the original document was mutated: %v -> %v", k, before[k], m)
			}
		}
		again := mergePatch(deepCopy(t, got), patch)
		if !reflect.DeepEqual(again, got) {
			t.Fatalf("merge patch not idempotent: %v vs %v", got, again)
		}
	})
}

func fuzzService() *Service {
	return NewService(memory.New(), Options{Users: &UserOptions{Log: discard}})
}

func isValidation(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// FuzzCreateTenant drives tenant creation and settings updates with
// arbitrary input. Every failure must be a validation error (or a duplicate
// slug), and every stored tenant must satisfy the documented rules.
func FuzzCreateTenant(f *testing.F) {
	f.Add("acme", "Acme Inc", "", "env", "prod", "sso", int64(10), []byte(`{"region":"eu"}`), []byte(`{"region":null}`))
	f.Add("Bad_Slug", "x", "free", "bad key!", "v", "Upper", int64(-1), []byte(`null`), []byte(`{}`))
	f.Add("018f6b8e-1c2d-7a3b-9c4d-5e6f7a8b9c0d", "uuid", "", "", "", "", int64(0), []byte(`{}`), []byte(`{}`))
	f.Add("a", strings.Repeat("é", 200), "p-1", "example.com/team", strings.Repeat("v", 256), "api_calls", int64(1), []byte(`{"a":{"b":1}}`), []byte(`{"a":{"b":null}}`))
	f.Add("-x", "", "a_b", "a/", "", "x", int64(0), []byte(`{}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, slug, name, plan, labelKey, labelVal, key string, limit int64, settingsJSON, patchJSON []byte) {
		ctx := context.Background()
		svc := fuzzService()
		in := CreateInput{Slug: slug, Name: name, Plan: plan}
		if labelKey != "" {
			in.Labels = map[string]string{labelKey: labelVal}
		}
		if key != "" {
			in.Features = map[string]bool{key: true}
			in.Limits = map[string]int64{key: limit}
		}
		_ = json.Unmarshal(settingsJSON, &in.Settings)

		tn, err := svc.Create(ctx, in)
		if err != nil {
			if !isValidation(err) {
				t.Fatalf("create %+v: non-validation error %v", in, err)
			}
			return
		}
		switch {
		case !slugRe.MatchString(tn.Slug), tn.Name == "", utf8.RuneCountInString(tn.Name) > maxNameLen:
			t.Fatalf("invalid tenant stored: %+v", tn)
		}
		for k := range tn.Labels {
			if !labelKeyRe.MatchString(k) {
				t.Fatalf("invalid label key stored: %q", k)
			}
		}
		for k, v := range tn.Limits {
			if !keyRe.MatchString(k) || v < 0 {
				t.Fatalf("invalid limit stored: %q=%d", k, v)
			}
		}
		got, err := svc.Get(ctx, slug)
		if err != nil || got.ID != tn.ID {
			t.Fatalf("created tenant not found by slug %q: %v", slug, err)
		}
		if _, err := svc.Create(ctx, in); !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("duplicate slug %q: want ErrAlreadyExists, got %v", slug, err)
		}

		var patch map[string]any
		if json.Unmarshal(patchJSON, &patch) != nil {
			return
		}
		want := refMergePatch(deepCopy(t, tn.Settings), deepCopy(t, patch))
		up, err := svc.Update(ctx, tn.ID, UpdateInput{Settings: patch}, nil)
		if err != nil {
			if !isValidation(err) {
				t.Fatalf("update settings %s: non-validation error %v", patchJSON, err)
			}
			return
		}
		// JSON round trip normalises nil vs empty maps for the comparison.
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(up.Settings)
		if len(up.Settings) == 0 {
			gotJSON = []byte("{}")
		}
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("settings after patch %s: got %s want %s", patchJSON, gotJSON, wantJSON)
		}
	})
}

// FuzzCreatePlan checks plan validation.
func FuzzCreatePlan(f *testing.F) {
	f.Add("pro", "Pro", "members", int64(100), true)
	f.Add("Pro!", "", "Bad Key", int64(-5), false)
	f.Add("p", strings.Repeat("x", 201), "a:b.c-d_e", int64(0), true)
	f.Fuzz(func(t *testing.T, id, name, key string, limit int64, feature bool) {
		ctx := context.Background()
		svc := fuzzService()
		in := PlanInput{ID: id, Name: name}
		if key != "" {
			in.Features = map[string]bool{key: feature}
			in.Limits = map[string]int64{key: limit}
		}
		p, err := svc.CreatePlan(ctx, in)
		if err != nil {
			if !isValidation(err) {
				t.Fatalf("create plan %+v: %v", in, err)
			}
			return
		}
		if !slugRe.MatchString(p.ID) || p.Name == "" || utf8.RuneCountInString(p.Name) > maxNameLen {
			t.Fatalf("invalid plan stored: %+v", p)
		}
		for k, v := range p.Limits {
			if !keyRe.MatchString(k) || v < 0 {
				t.Fatalf("invalid limit stored: %q=%d", k, v)
			}
		}
		if got, err := svc.GetPlan(ctx, id); err != nil || got.ID != p.ID {
			t.Fatalf("plan %q not found: %v", id, err)
		}
	})
}

// FuzzAddMember checks member input validation: failures are validation
// errors and do not leave users behind; successes store a plain email and
// an allowed role.
func FuzzAddMember(f *testing.F) {
	f.Add("alice@example.com", "Alice", "member", "")
	f.Add("Bob <bob@example.com>", "", "admin", "")
	f.Add(" carol@example.com ", "", "viewer", "")
	f.Add("dave@example.com", "", "superuser", "")
	f.Add("", "", "member", "no-such-user")
	f.Add("\"quoted local\"@example.com", "", "owner", "")
	f.Add("eve@[127.0.0.1]", strings.Repeat("n", 300), "member", "")
	f.Fuzz(func(t *testing.T, email, name, role, userID string) {
		ctx := context.Background()
		s := memory.New()
		svc := NewService(s, Options{Users: &UserOptions{Log: discard}})
		tn, err := svc.Create(ctx, CreateInput{Slug: "acme", Name: "Acme"})
		if err != nil {
			t.Fatal(err)
		}
		m, err := svc.AddMember(ctx, tn.ID, MemberInput{Email: email, Name: name, Role: role, UserID: userID})
		if err != nil {
			if !isValidation(err) {
				t.Fatalf("add member %q/%q: non-validation error %v", email, role, err)
			}
			if users, _ := s.ListUsers(ctx, store.ListUsersQuery{}); len(users) != 0 {
				t.Fatalf("rejected member %q left users behind: %+v", email, users)
			}
			return
		}
		if addr, err := mail.ParseAddress(m.Email); err != nil || addr.Address != m.Email {
			t.Fatalf("member stored with non-plain email %q (input %q)", m.Email, email)
		}
		if m.Role != role || !svc.roleAllowed(m.Role) {
			t.Fatalf("member stored with role %q (input %q)", m.Role, role)
		}
		if got, err := svc.GetMember(ctx, tn.ID, m.ID); err != nil || got.Email != m.Email {
			t.Fatalf("member not readable: %+v %v", got, err)
		}
	})
}
