package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func reqWithQuery(q url.Values) *http.Request {
	return &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/Users", RawQuery: q.Encode()}}
}

// FuzzFilter parses arbitrary SCIM filters. Errors must be SCIM 400s, and
// an accepted filter must round-trip: re-quoting the parsed value gives
// the same attribute and value back.
func FuzzFilter(f *testing.F) {
	for _, s := range []string{
		`userName eq "alice@example.com"`, `displayName EQ "Admins"`, `externalId eq "x\"y"`,
		`userName sw "a"`, `userName eq alice`, `  emails.value eq "a@b.c"  `, `a eq ""`,
		`userName eq "é\x00"`, `eq eq "eq"`, `a  eq "b"`, ``,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		attr, value, err := filter(reqWithQuery(url.Values{"filter": {s}}))
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.Status != http.StatusBadRequest || se.ScimType != "invalidFilter" {
				t.Fatalf("filter %q: unexpected error %#v", s, err)
			}
			return
		}
		if strings.TrimSpace(s) == "" {
			if attr != "" || value != "" {
				t.Fatalf("empty filter parsed as %q=%q", attr, value)
			}
			return
		}
		if attr == "" || attr != strings.ToLower(attr) || strings.Contains(attr, " ") {
			t.Fatalf("filter %q: bad attribute %q", s, attr)
		}
		a2, v2, err := filter(reqWithQuery(url.Values{"filter": {attr + " eq " + strconv.Quote(value)}}))
		if err != nil || a2 != attr || v2 != value {
			t.Fatalf("filter %q: round trip gave %q %q %v, want %q %q", s, a2, v2, err, attr, value)
		}
	})
}

// FuzzPage checks SCIM pagination bounds for arbitrary startIndex/count.
func FuzzPage(f *testing.F) {
	f.Add("1", "10", 5)
	f.Add("0", "-1", 0)
	f.Add("9223372036854775807", "9223372036854775807", 3)
	f.Add("-9223372036854775808", "200", 300)
	f.Add("x", "", 1)
	f.Fuzz(func(t *testing.T, start, count string, n int) {
		n = max(0, n%1000)
		all := make([]int, n)
		for i := range all {
			all[i] = i
		}
		q := url.Values{}
		if start != "" {
			q.Set("startIndex", start)
		}
		if count != "" {
			q.Set("count", count)
		}
		got, s, err := page(reqWithQuery(q), all)
		if err != nil {
			var se *Error
			if !errors.As(err, &se) || se.Status != http.StatusBadRequest {
				t.Fatalf("unexpected error %#v", err)
			}
			return
		}
		if s < 1 || len(got) > 200 {
			t.Fatalf("start %d len %d", s, len(got))
		}
		for i, v := range got {
			if v != s-1+i {
				t.Fatalf("page [%s,%s] of %d: item %d is %d, want %d", start, count, n, i, v, s-1+i)
			}
		}
	})
}

// FuzzPatchUser folds arbitrary SCIM PATCH bodies into a user. Every
// failure must be a SCIM 400, never a panic.
func FuzzPatchUser(f *testing.F) {
	for _, s := range []string{
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`,
		`{"Operations":[{"op":"Replace","value":{"active":"False"}}]}`,
		`{"Operations":[{"op":"add","path":"roles","value":[{"value":"admin"}]}]}`,
		`{"Operations":[{"op":"replace","path":"displayName","value":"Bob"}]}`,
		`{"Operations":[{"op":"replace","value":{"name":{"givenName":"A","familyName":"B"},"emails":[{"value":"a@b.c","primary":true}]}}]}`,
		`{"Operations":[{"op":"remove","path":"members"}]}`,
		`{"Operations":[{"op":"move"}]}`,
		`{"Operations":[{"op":"add","path":"active","value":"yes"}]}`,
		`{"Operations":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var req patchRequest
		if json.Unmarshal(body, &req) != nil {
			return
		}
		var in userIn
		for _, op := range req.Operations {
			if err := patchUser(&in, op); err != nil {
				var se *Error
				if !errors.As(err, &se) || se.Status != http.StatusBadRequest {
					t.Fatalf("op %+v: unexpected error %#v", op, err)
				}
				return
			}
		}
		// Derived attributes must be computable for any result.
		_, _, _ = in.email(), in.fullName(), in.role()
	})
}
