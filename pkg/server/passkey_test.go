package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

var b64 = base64.RawURLEncoding

// softKey is a software authenticator holding one ES256 passkey.
type softKey struct {
	key    *ecdsa.PrivateKey
	id     []byte
	user   []byte
	origin string
	count  uint32
}

func newSoftKey(origin string) *softKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{key: k, id: id, origin: origin}
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// create answers navigator.credentials.create() options.
func (s *softKey) create(t *testing.T, options map[string]any) json.RawMessage {
	t.Helper()
	pk := options["publicKey"].(map[string]any)
	rpID := pk["rp"].(map[string]any)["id"].(string)
	s.user, _ = b64.DecodeString(pk["user"].(map[string]any)["id"].(string))
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1, XCoord: s.key.X.FillBytes(make([]byte, 32)), YCoord: s.key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, 0x45)                // UP | UV | AT
	auth = append(auth, 0, 0, 0, 0)          // sign count
	auth = append(auth, make([]byte, 16)...) // AAGUID
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(s.id)))
	auth = append(auth, s.id...)
	auth = append(auth, cose...)
	att, _ := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(s.id), "rawId": b64.EncodeToString(s.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", pk["challenge"].(string), s.origin)),
			"attestationObject": b64.EncodeToString(att),
		},
		"clientExtensionResults": map[string]any{},
	})
	return resp
}

// get answers navigator.credentials.get() options.
func (s *softKey) get(t *testing.T, options map[string]any, rpID string) json.RawMessage {
	t.Helper()
	pk := options["publicKey"].(map[string]any)
	s.count++
	rpHash := sha256.Sum256([]byte(rpID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, 0x05) // UP | UV
	auth = binary.BigEndian.AppendUint32(auth, s.count)
	cd := clientData("webauthn.get", pk["challenge"].(string), s.origin)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(s.id), "rawId": b64.EncodeToString(s.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(auth),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(s.user),
		},
		"clientExtensionResults": map[string]any{},
	})
	return resp
}

func TestPasskeys(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	origin := "http://localhost:" + port
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Users.PublicURL = origin
	cfg.Auth.RateLimit = 0
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "root@example.com", Password: "root password long enough", Roles: []string{"admin"}}}
	base := serveOn(t, ln, cfg)
	c := client{t: t, base: base}

	_, tok := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "root@example.com", "password": "root password long enough"})
	me := as(c, tok["access_token"].(string))
	key := newSoftKey(origin)

	code, begin := me("POST", "/v1/me/passkeys/register/begin", nil)
	if code != 200 {
		t.Fatalf("begin registration: %d %v", code, begin)
	}
	cred := key.create(t, begin["options"].(map[string]any))
	code, saved := me("POST", "/v1/me/passkeys/register/finish", map[string]any{"ceremony": begin["ceremony"], "name": "laptop", "credential": cred})
	if code != 201 || saved["name"] != "laptop" {
		t.Fatalf("finish registration: %d %v", code, saved)
	}
	// A ceremony cannot be reused.
	if code, _ := me("POST", "/v1/me/passkeys/register/finish", map[string]any{"ceremony": "forged", "credential": cred}); code != 401 {
		t.Fatalf("forged ceremony: %d", code)
	}

	// Passwordless sign-in with a discoverable credential.
	code, lb := c.do("POST", "/v1/auth/passkey/begin", map[string]any{})
	if code != 200 {
		t.Fatalf("begin login: %d %v", code, lb)
	}
	assertion := key.get(t, lb["options"].(map[string]any), "localhost")
	code, pair := c.do("POST", "/v1/auth/passkey/finish", map[string]any{"ceremony": lb["ceremony"], "credential": assertion})
	if code != 200 || pair["access_token"] == nil {
		t.Fatalf("passkey login: %d %v", code, pair)
	}
	// Replaying the same assertion fails (the challenge is bound to one ceremony,
	// and the counter must grow).
	_, lb2 := c.do("POST", "/v1/auth/passkey/begin", map[string]any{"email": "root@example.com"})
	if code, _ := c.do("POST", "/v1/auth/passkey/finish", map[string]any{"ceremony": lb2["ceremony"], "credential": assertion}); code != 401 {
		t.Fatalf("replayed assertion: %d", code)
	}

	_, list := me("GET", "/v1/me/passkeys", nil)
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["last_used_at"] == nil {
		t.Fatalf("passkeys: %v", items)
	}
	id := items[0].(map[string]any)["id"].(string)
	if code, _ := me("DELETE", "/v1/me/passkeys/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	_, lb3 := c.do("POST", "/v1/auth/passkey/begin", nil)
	if code, _ := c.do("POST", "/v1/auth/passkey/finish", map[string]any{"ceremony": lb3["ceremony"], "credential": key.get(t, lb3["options"].(map[string]any), "localhost")}); code != 401 {
		t.Fatalf("deleted passkey still works: %d", code)
	}
	_, audit := c.do("GET", "/v1/audit?type=user.passkey_*", nil)
	if n := len(audit["items"].([]any)); n != 2 {
		t.Fatalf("audit: %d", n)
	}
}
