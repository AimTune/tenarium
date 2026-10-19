package server_test

import (
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/pkg/server"
)

func TestTwoFactorLogin(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "root@example.com", Password: "root password long enough", Roles: []string{"admin"}}}
	cfg.Auth.RateLimit = 0
	c := client{t: t, base: startServer(t, cfg)}
	login := func(otp string) (int, map[string]any) {
		body := map[string]any{"grant_type": "password", "email": "root@example.com", "password": "root password long enough"}
		if otp != "" {
			body["otp"] = otp
		}
		return c.do("POST", "/v1/auth/token", body)
	}
	errCode := func(body map[string]any) any { return body["error"].(map[string]any)["code"] }

	_, tok := login("")
	me := as(c, tok["access_token"].(string))
	if code, st := me("GET", "/v1/me/mfa", nil); code != 200 || st["enabled"] != false {
		t.Fatalf("status: %d %v", code, st)
	}
	code, enr := me("POST", "/v1/me/mfa/totp", nil)
	if code != 200 || enr["secret"] == nil {
		t.Fatalf("begin: %d %v", code, enr)
	}
	secret := enr["secret"].(string)
	codeAt := func(offset int64) string {
		s, _ := identity.TOTPCode(secret, identity.TOTPStep(time.Now())+offset)
		return s
	}
	if code, body := me("POST", "/v1/me/mfa/totp/confirm", map[string]any{"code": "000000"}); code != 401 || errCode(body) != "invalid_otp" {
		t.Fatalf("confirm with wrong code: %d %v", code, body)
	}
	code, conf := me("POST", "/v1/me/mfa/totp/confirm", map[string]any{"code": codeAt(0)})
	if code != 200 {
		t.Fatalf("confirm: %d %v", code, conf)
	}
	recovery := conf["recovery_codes"].([]any)
	if len(recovery) != 10 {
		t.Fatalf("recovery codes: %v", recovery)
	}

	if code, body := login(""); code != 401 || errCode(body) != "mfa_required" {
		t.Fatalf("login without code: %d %v", code, body)
	}
	if code, body := login("123456"); code != 401 || errCode(body) != "invalid_otp" {
		t.Fatalf("login with wrong code: %d %v", code, body)
	}
	next := codeAt(1)
	if code, body := login(next); code != 200 {
		t.Fatalf("login with code: %d %v", code, body)
	}
	if code, _ := login(next); code != 401 {
		t.Fatalf("code replayed: %d", code)
	}
	rc := recovery[0].(string)
	if code, _ := login(rc); code != 200 {
		t.Fatalf("login with recovery code: %d", code)
	}
	if code, _ := login(rc); code != 401 {
		t.Fatalf("recovery code reused: %d", code)
	}
	if _, st := me("GET", "/v1/me/mfa", nil); st["enabled"] != true || st["recovery_codes_left"] != float64(9) {
		t.Fatalf("status after use: %v", st)
	}
	if code, _ := me("POST", "/v1/me/mfa/totp", nil); code != 409 {
		t.Fatalf("re-enroll while enabled: %d", code)
	}

	// An admin resets a user who lost their device.
	_, u := c.do("GET", "/v1/users/root@example.com", nil)
	if code, _ := c.do("DELETE", "/v1/users/"+u["id"].(string)+"/mfa", nil); code != 204 {
		t.Fatalf("reset: %d", code)
	}
	if code, _ := login(""); code != 200 {
		t.Fatalf("login after reset: %d", code)
	}
	_, audit := c.do("GET", "/v1/audit?type=user.mfa_*", nil)
	if n := len(audit["items"].([]any)); n != 2 {
		t.Fatalf("mfa audit events: %d", n)
	}
}
