package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// DNS name limits (RFC 1035), counted without the trailing dot.
const (
	maxLabelLen = 63
	maxNameLen  = 253
)

// Sample tenants used to validate templates at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

func parseTemplate(name, s string) (*template.Template, error) {
	return template.New(name).Option("missingkey=error").Parse(s)
}

func execute(tmpl *template.Template, t sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, t); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SanitizeLabel turns s into a DNS label candidate: lowercase letters,
// digits and hyphens; any other character becomes a hyphen, hyphen runs are
// collapsed and leading/trailing hyphens trimmed. A single leading
// underscore is kept (service labels such as "_acme-challenge"). It does not
// enforce the length limit, which needs the tenant ID; see renderName.
func SanitizeLabel(s string) string {
	underscore := strings.HasPrefix(s, "_")
	if underscore {
		s = s[1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if underscore && out != "" {
		out = "_" + out
	}
	return out
}

// hashSuffix is "-" plus the first 8 hex characters of sha256(tenant ID).
func hashSuffix(tenantID string) string {
	sum := sha256.Sum256([]byte(tenantID))
	return "-" + hex.EncodeToString(sum[:4])
}

// renderName renders a record name template for t and turns it into a
// fully qualified name inside zone (lowercase, without trailing dot).
//
// A rendered name ending with "." is absolute and must lie inside the zone.
// A name equal to the zone or ending with "."+zone is taken as is; any other
// name is relative to the zone. Each label is sanitized with SanitizeLabel
// ("*" is allowed as the first label, for wildcard records); a label longer
// than 63 characters is shortened and suffixed with a hash of the tenant ID,
// so shortening never makes two tenants collide.
func renderName(tmpl *template.Template, t sdk.Tenant, zone string) (string, error) {
	raw, err := execute(tmpl, t)
	if err != nil {
		return "", err
	}
	s := strings.ToLower(strings.TrimSpace(raw))
	absolute := strings.HasSuffix(s, ".")
	s = strings.TrimSuffix(s, ".")
	inZone := s == zone || strings.HasSuffix(s, "."+zone)
	if absolute && !inZone {
		return "", fmt.Errorf("renders %q for tenant %s, which is not inside zone %s", raw, t.ID, zone)
	}
	rel := s
	if inZone {
		rel = strings.TrimSuffix(strings.TrimSuffix(s, zone), ".")
	}
	if rel == "" {
		return "", fmt.Errorf("renders the zone apex for tenant %s; records must be below the zone", t.ID)
	}
	labels := strings.Split(rel, ".")
	for i, l := range labels {
		if i == 0 && l == "*" {
			continue
		}
		l = SanitizeLabel(l)
		if l == "" {
			return "", fmt.Errorf("renders %q for tenant %s, which has an empty label", raw, t.ID)
		}
		if len(l) > maxLabelLen {
			sfx := hashSuffix(t.ID)
			l = strings.TrimRight(l[:maxLabelLen-len(sfx)], "-") + sfx
		}
		labels[i] = l
	}
	name := strings.Join(labels, ".") + "." + zone
	if len(name) > maxNameLen {
		return "", fmt.Errorf("renders %q for tenant %s, longer than %d characters", name, t.ID, maxNameLen)
	}
	return name, nil
}

// validZone reports whether z is a valid lowercase zone name without a
// trailing dot.
func validZone(z string) error {
	if z == "" {
		return errors.New("is empty")
	}
	if len(z) > maxNameLen {
		return fmt.Errorf("is longer than %d characters", maxNameLen)
	}
	for _, l := range strings.Split(z, ".") {
		if l == "" || len(l) > maxLabelLen || l != SanitizeLabel(l) || strings.HasPrefix(l, "_") {
			return fmt.Errorf("has invalid label %q", l)
		}
	}
	return nil
}

// normalizeHost lowercases a host name, drops the trailing dot and checks
// its syntax (letters, digits, hyphens and underscores; 1-63 character
// labels; at most 253 characters).
func normalizeHost(s string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if h == "" || len(h) > maxNameLen {
		return "", fmt.Errorf("invalid host name %q", s)
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > maxLabelLen || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("invalid host name %q", s)
		}
		for _, r := range l {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return "", fmt.Errorf("invalid host name %q", s)
			}
		}
	}
	return h, nil
}

// normalizeValue validates a record value of the given type and returns its
// canonical form, which is how values are compared with what the provider
// reports.
func normalizeValue(typ, v string) (string, error) {
	switch typ {
	case TypeA, TypeAAAA:
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("invalid IP address %q", v)
		}
		if typ == TypeA && !a.Is4() {
			return "", fmt.Errorf("%q is not an IPv4 address", v)
		}
		if typ == TypeAAAA && (!a.Is6() || a.Is4In6()) {
			return "", fmt.Errorf("%q is not an IPv6 address", v)
		}
		return a.String(), nil
	case TypeCNAME:
		return normalizeHost(v)
	case TypeTXT:
		if v == "" {
			return "", errors.New("empty TXT value")
		}
		for _, r := range v {
			if r < 0x20 || r > 0x7e {
				return "", fmt.Errorf("TXT value %q must be printable ASCII", v)
			}
		}
		return v, nil
	}
	return "", fmt.Errorf("unsupported record type %q", typ)
}

// txtEncode encodes a TXT value in zone-file presentation format: one or
// more quoted character-strings of at most 255 bytes each.
func txtEncode(v string) string {
	var parts []string
	for len(v) > 0 || parts == nil {
		n := min(len(v), 255)
		chunk := v[:n]
		v = v[n:]
		chunk = strings.ReplaceAll(chunk, `\`, `\\`)
		chunk = strings.ReplaceAll(chunk, `"`, `\"`)
		parts = append(parts, `"`+chunk+`"`)
	}
	return strings.Join(parts, " ")
}

// txtDecode reverses txtEncode. Unquoted input is returned unchanged (some
// APIs report TXT content without quotes). "\ddd" escapes are decoded as
// octal, as Route 53 uses them.
func txtDecode(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return s
	}
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			in = !in
		case !in:
			// Whitespace between character-strings.
		case c == '\\' && i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]):
			b.WriteByte((s[i+1]-'0')*64 + (s[i+2]-'0')*8 + (s[i+3] - '0'))
			i += 3
		case c == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
