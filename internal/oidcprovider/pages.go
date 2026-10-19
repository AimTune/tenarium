package oidcprovider

import (
	"html/template"
	"net/http"

	"github.com/AimTune/tenarium/internal/store"
)

// The pages are deliberately plain: no scripts, no external assets, and a
// strict CSP, since they handle passwords.
var pages = template.Must(template.New("base").Parse(`{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Product}}</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#5d6675;--accent:#2f5bea;--border:#d9dde3;--err:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--card:#1a2029;--fg:#e6e9ef;--muted:#9aa3b2;--accent:#7b9bff;--border:#2c3442;--err:#ff8a80}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
main{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px;width:100%;max-width:380px}
h1{font-size:20px;margin:0 0 4px}p{color:var(--muted);margin:0 0 20px}
label{display:block;font-size:14px;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--border);border-radius:8px;background:transparent;color:inherit;font:inherit}
button{margin-top:20px;width:100%;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;cursor:pointer}
button.secondary{background:transparent;color:var(--fg);border:1px solid var(--border);margin-top:8px}
.err{color:var(--err);margin:12px 0 0}ul{padding-left:20px;color:var(--muted)}
</style></head><body><main>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "login"}}{{template "head" .}}
<h1>Sign in</h1><p>to continue to {{.Client}}</p>
<form method="post" action="/oauth/login">
<input type="hidden" name="flow" value="{{.Flow}}">
<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" value="{{.Email}}" required{{if not .Email}} autofocus{{end}}>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required{{if .Email}} autofocus{{end}}>
{{if .OTP}}<label for="otp">One-time code</label><input id="otp" name="otp" inputmode="numeric" autocomplete="one-time-code">{{end}}
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<button type="submit">Sign in</button></form>
{{template "foot" .}}{{end}}

{{define "consent"}}{{template "head" .}}
<h1>{{.Client}}</h1><p>wants to:</p>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/oauth/consent">
<input type="hidden" name="flow" value="{{.Flow}}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny" class="secondary">Cancel</button></form>
{{template "foot" .}}{{end}}

{{define "message"}}{{template "head" .}}<h1>{{.Product}}</h1><p>{{.Message}}</p>{{template "foot" .}}{{end}}
`))

var scopeText = map[string]string{
	"openid":         "Sign you in",
	"profile":        "See your name",
	"email":          "See your email address",
	"offline_access": "Stay signed in (access when you are not using it)",
}

type pageData struct {
	Product, Client, Flow, Email, Error, Message string
	OTP                                          bool
	Scopes                                       []string
}

func (h *Handler) render(w http.ResponseWriter, status int, name string, d pageData) {
	d.Product = h.cfg.ProductName
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = pages.ExecuteTemplate(w, name, d)
}

func (h *Handler) renderLogin(w http.ResponseWriter, c store.OAuthClient, flow, email, msg string, otp bool) {
	status := http.StatusOK
	if msg != "" {
		status = http.StatusUnauthorized
	}
	h.render(w, status, "login", pageData{Client: c.Name, Flow: flow, Email: email, Error: msg, OTP: otp})
}

func (h *Handler) renderConsent(w http.ResponseWriter, c store.OAuthClient, ar authRequest, flow string) {
	var scopes []string
	for _, s := range ar.Scopes {
		if t, ok := scopeText[s]; ok {
			scopes = append(scopes, t)
		}
	}
	h.render(w, http.StatusOK, "consent", pageData{Client: c.Name, Flow: flow, Scopes: scopes})
}

func (h *Handler) renderError(w http.ResponseWriter, status int, msg string) {
	h.render(w, status, "message", pageData{Message: msg})
}

func (h *Handler) renderMessage(w http.ResponseWriter, msg string) {
	h.render(w, http.StatusOK, "message", pageData{Message: msg})
}
