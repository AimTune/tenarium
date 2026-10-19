package server_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/server"
	"github.com/crewjam/saml"
)

// fakeSAMLIdP is a SAML identity provider built from the library's own IdP
// implementation; it signs in whoever it is told to.
type fakeSAMLIdP struct {
	srv   *httptest.Server
	mu    sync.Mutex
	email string
}

func (p *fakeSAMLIdP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	resp, err := http.Get(id) // the SP entity ID is its metadata URL
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err != nil {
		return nil, err
	}
	return &ed, nil
}

func (p *fakeSAMLIdP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	return &saml.Session{
		ID: randomString(), CreateTime: now, ExpireTime: now.Add(time.Hour), Index: randomString(),
		NameID: p.email, NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail: p.email, UserCommonName: "Ann Lee",
	}
}

func newFakeSAMLIdP(t *testing.T) *fakeSAMLIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	p := &fakeSAMLIdP{}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	meta, _ := url.Parse(p.srv.URL + "/metadata")
	sso, _ := url.Parse(p.srv.URL + "/sso")
	idp := &saml.IdentityProvider{Key: key, Certificate: cert, MetadataURL: *meta, SSOURL: *sso,
		ServiceProviderProvider: p, SessionProvider: p}
	mux.Handle("/", idp.Handler())
	return p
}

var (
	samlResponseRe = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
	relayStateRe   = regexp.MustCompile(`name="RelayState" value="([^"]*)"`)
)

// samlLogin plays the browser: start, IdP form, POST to the ACS, and return
// the session fragment.
func samlLogin(t *testing.T, base string, idp *fakeSAMLIdP, email string) url.Values {
	t.Helper()
	idp.mu.Lock()
	idp.email = email
	idp.mu.Unlock()
	jar, _ := cookiejar.New(nil)
	var fragment string
	errDone := errors.New("done")
	hc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == "/ui/" {
			fragment = req.URL.Fragment
			return errDone
		}
		return nil
	}}
	resp, err := hc.Get(base + "/v1/auth/sso/start?tenant=acme")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sr, rs := samlResponseRe.FindSubmatch(body), relayStateRe.FindSubmatch(body)
	if sr == nil || rs == nil {
		t.Fatalf("no SAML form from the IdP: %d %s", resp.StatusCode, body)
	}
	form := url.Values{"SAMLResponse": {html.UnescapeString(string(sr[1]))}, "RelayState": {html.UnescapeString(string(rs[1]))}}
	resp, err = hc.PostForm(base+"/v1/auth/sso/saml/"+tenantIDOf(t, base, "acme")+"/acs", form)
	if err != nil && !errors.Is(err, errDone) {
		t.Fatal(err)
	}
	if resp != nil {
		resp.Body.Close()
	}
	v, _ := url.ParseQuery(fragment)
	return v
}

func tenantIDOf(t *testing.T, base, slug string) string {
	t.Helper()
	_, tn := client{t: t, base: base}.do("GET", "/v1/tenants/"+slug, nil)
	return tn["id"].(string)
}

func TestTenantSAML(t *testing.T) {
	idp := newFakeSAMLIdP(t)
	dns := &fakeDNS{records: map[string][]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Users.PublicURL = base
	cfg.Auth.RateLimit = 0
	cfg.Auth.SSO.AllowPrivateIssuers = true
	serveOn(t, ln, cfg, server.WithTXTResolver(dns.lookup))
	c := client{t: t, base: base}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	_, added := c.do("POST", "/v1/tenants/acme/domains", map[string]any{"hostname": "acme.example"})
	instr := added["instructions"].(map[string]any)
	dns.mu.Lock()
	dns.records[instr["name"].(string)] = []string{instr["value"].(string)}
	dns.mu.Unlock()
	c.do("POST", "/v1/tenants/acme/domains/acme.example/verify", nil)

	if code, body := c.do("PUT", "/v1/tenants/acme/sso", map[string]any{"protocol": "saml", "saml_metadata": "<nope/>", "domains": []string{"acme.example"}}); code != 400 {
		t.Fatalf("bad metadata accepted: %d %v", code, body)
	}
	code, conn := c.do("PUT", "/v1/tenants/acme/sso", map[string]any{
		"protocol": "saml", "saml_metadata_url": idp.srv.URL + "/metadata", "domains": []string{"acme.example"}, "auto_provision": true,
	})
	if code != 200 || conn["issuer"] != idp.srv.URL+"/metadata" || conn["protocol"] != "saml" {
		t.Fatalf("put saml: %d %v", code, conn)
	}
	resp, err := http.Get(base + "/v1/auth/sso/saml/" + tenantIDOf(t, base, "acme") + "/metadata")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("sp metadata: %v %v", resp, err)
	}
	resp.Body.Close()

	frag := samlLogin(t, base, idp, "ann@acme.example")
	if frag.Get("access_token") == "" {
		t.Fatalf("no session: %v", frag)
	}
	if code, who := as(c, frag.Get("access_token"))("GET", "/v1/me", nil); code != 200 || who["tenant_id"] == nil {
		t.Fatalf("me: %d %v", code, who)
	}
	_, u := c.do("GET", "/v1/users/ann@acme.example", nil)
	if u["name"] != "Ann Lee" {
		t.Fatalf("provisioned user: %v", u)
	}
	// Assertions for other domains are refused.
	if frag := samlLogin(t, base, idp, "eve@evil.example"); frag.Get("error") != "sso_rejected" {
		t.Fatalf("foreign domain: %v", frag)
	}
	// A response without the matching state cookie is refused.
	form := url.Values{"SAMLResponse": {"x"}, "RelayState": {"y"}}
	resp, err = http.PostForm(base+"/v1/auth/sso/saml/"+tenantIDOf(t, base, "acme")+"/acs", form)
	if err != nil || resp.StatusCode != 400 {
		t.Fatalf("acs without state: %v %v", resp, err)
	}
	resp.Body.Close()
}
