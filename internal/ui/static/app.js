// Tenarium admin UI: a dependency-free SPA over the /v1 API.
// All user-controlled values are rendered with textContent (never innerHTML).
// UI strings go through t() from i18n.js; the English text is the message key.
"use strict";

// ---- api ------------------------------------------------------------------

const store = (key) => ({
  get: () => sessionStorage.getItem(key) || "",
  set: (v) => (v ? sessionStorage.setItem(key, v) : sessionStorage.removeItem(key)),
});
const authStore = store("tenarium.auth");
const refreshStore = store("tenarium.refresh");
const impStore = store("tenarium.impersonation");
const auth = {
  get header() { return authStore.get(); },
  set header(v) { authStore.set(v); },
  get refresh() { return refreshStore.get(); },
  set refresh(v) { refreshStore.set(v); },
  // useTokens stores a token pair from /v1/auth/token.
  useTokens(pair) {
    this.header = "Bearer " + pair.access_token;
    this.refresh = pair.refresh_token || "";
  },
  clear() {
    this.header = "";
    this.refresh = "";
    impStore.set("");
  },
};

// impersonation keeps the admin's own session aside while acting as a user
// with a short-lived impersonation token (which has no refresh token).
const impersonation = {
  get() {
    try { return JSON.parse(impStore.get() || "null"); } catch { return null; }
  },
  begin(pair, info) {
    impStore.set(JSON.stringify({ header: auth.header, refresh: auth.refresh, ...info }));
    auth.header = "Bearer " + pair.access_token;
    auth.refresh = "";
  },
  // end restores the admin's session; false when not impersonating.
  end() {
    const s = this.get();
    if (!s) return false;
    impStore.set("");
    auth.header = s.header;
    auth.refresh = s.refresh;
    return true;
  },
};

// publicApi calls unauthenticated endpoints (/v1/auth/*).
async function publicApi(method, path, body) {
  const res = await fetch(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

// refreshSession trades the refresh token for a new pair once.
let refreshing = null;
async function refreshSession() {
  if (!auth.refresh) return false;
  refreshing ??= publicApi("POST", "/v1/auth/token", { grant_type: "refresh_token", refresh_token: auth.refresh })
    .then((pair) => { auth.useTokens(pair); return true; })
    .catch(() => false)
    .finally(() => setTimeout(() => (refreshing = null), 0));
  return refreshing;
}

class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message || `HTTP ${status}`);
    this.status = status;
    this.code = body?.error?.code;
  }
}

async function api(method, path, body, headers = {}, retried = false) {
  const res = await fetch(path, {
    method,
    headers: { Authorization: auth.header, ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  api.headers = res.headers; // response headers of the last call (e.g. Tenarium-Deletion-At)
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  // A wrong one-time code is a 401 too, but the session is still fine.
  if (res.status === 401 && data?.error?.code !== "invalid_otp") {
    // An expired impersonation token falls back to the admin's own session.
    if (impersonation.end()) {
      toast(t("The impersonation session ended."));
      history.pushState(null, "", "#/users");
      start();
      throw new ApiError(401, null);
    }
    if (!retried && (await refreshSession())) return api(method, path, body, headers, true);
    auth.clear();
    showLogin(t("Your session is not valid. Sign in again."));
    throw new ApiError(401, null);
  }
  if (!res.ok) {
    const e = new ApiError(res.status, data);
    // A tenant in maintenance is read-only for tenant-scoped callers.
    if (e.code === "maintenance") e.message = t("This tenant is under maintenance and read-only for now. Try again later.");
    throw e;
  }
  return data;
}

// optional calls an endpoint that may be switched off by configuration (404) or
// not allowed for the caller (403): it resolves to {data} on success, {off: message}
// on 404, {denied: message} on 403 (both without a toast) and {} on other errors (toasted).
async function optional(fn) {
  try {
    return { data: await fn() };
  } catch (e) {
    if (e.status === 404) return { off: e.message };
    if (e.status === 403) return { denied: e.message };
    if (e.status !== 401) toast(e.message, true);
    return {};
  }
}

// download saves a JSON export (Content-Disposition names the file).
async function download(path, fallbackName) {
  const data = await api("GET", path);
  const name = /filename="([^"]+)"/.exec(api.headers.get("Content-Disposition") || "")?.[1] || fallbackName;
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = h("a", { href: url, download: name, hidden: true });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(t("Export downloaded"));
}

// ---- webauthn --------------------------------------------------------------

// The API sends WebAuthn options and expects credentials as JSON with
// base64url-encoded binary fields.
const b64u = {
  decode(s) {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  },
  encode(buf) {
    let bin = "";
    for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};
const passkeysSupported = () => Boolean(window.PublicKeyCredential && navigator.credentials);

function creationOptions(o) {
  const pk = { ...o.publicKey, challenge: b64u.decode(o.publicKey.challenge) };
  pk.user = { ...pk.user, id: b64u.decode(pk.user.id) };
  if (pk.excludeCredentials) pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64u.decode(c.id) }));
  return { publicKey: pk };
}

function requestOptions(o) {
  const pk = { ...o.publicKey, challenge: b64u.decode(o.publicKey.challenge) };
  if (pk.allowCredentials) pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64u.decode(c.id) }));
  return { publicKey: pk };
}

function credentialJSON(c) {
  const r = c.response;
  const response = { clientDataJSON: b64u.encode(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = b64u.encode(r.attestationObject);
    if (r.getTransports) response.transports = r.getTransports();
  }
  if (r.authenticatorData) {
    response.authenticatorData = b64u.encode(r.authenticatorData);
    response.signature = b64u.encode(r.signature);
    if (r.userHandle) response.userHandle = b64u.encode(r.userHandle);
  }
  return {
    id: c.id, rawId: b64u.encode(c.rawId), type: c.type, response,
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  };
}

// webauthnError explains browser-side failures of a passkey prompt.
function webauthnError(e) {
  if (e?.name === "NotAllowedError") return t("The passkey prompt was cancelled or timed out.");
  if (e?.name === "InvalidStateError") return t("This passkey is already registered.");
  if (e?.name === "SecurityError") return t("Passkeys need a secure (https) address that matches the server's configuration.");
  return e?.message || String(e);
}

// ---- dom helpers -----------------------------------------------------------

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const main = () => document.getElementById("main");
const fmtTime = (s) => (s ? new Date(s).toLocaleString(lang) : "");
const num = (n) => Number(n ?? 0).toLocaleString(lang);
const badge = (text, cls = text) => h("span", { class: `badge ${cls}` }, text);
// statusBadge shows an API status value translated, styled by the raw value.
const statusBadge = (s) => badge(t(s), s);
const chips = (obj) => h("div", { class: "chips" }, Object.entries(obj || {}).map(([k, v]) => h("span", { class: "chip" }, `${k}=${v}`)));
const chipList = (items, cls = "chip") => h("div", { class: "chips" }, (items || []).map((x) => h("span", { class: cls }, x)));
const json = (v) => h("pre", {}, JSON.stringify(v, null, 2));
// eventDetail shows an event's JSON, with the W3C trace context first when it has one.
const eventDetail = (e) => [
  e.traceparent ? h("p", { class: "small", style: "margin:0 0 8px" }, h("span", { class: "muted" }, `${t("Trace context")}: `), h("code", {}, e.traceparent)) : null,
  json(e)];
const dash = () => h("span", { class: "muted" }, "—");
// validColor accepts only #rgb / #rrggbb, so branding colors are safe in CSS.
const validColor = (c) => typeof c === "string" && /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(c);
const gradeBadge = (g) => badge({ healthy: t("healthy"), at_risk: t("at risk"), critical: t("critical") }[g] || g,
  { healthy: "ok", at_risk: "invited", critical: "failed" }[g] || "");
const yesNo = (b) => (b ? badge(t("yes"), "ok") : badge(t("no"), ""));

function toast(msg, isErr = false) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `toast ${isErr ? "err" : ""}`;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (el.hidden = true), 4000);
}

async function guard(fn) {
  try {
    return await fn();
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
    return undefined;
  }
}

// act makes a button that runs fn; a 403 disables it, since the caller may not do that.
function act(label, cls, fn) {
  const btn = h("button", { type: "button", class: cls, onclick: async () => {
    try {
      await fn();
    } catch (e) {
      if (e.status === 403) {
        btn.disabled = true;
        btn.title = t("You are not allowed to do this.");
      }
      if (e.status !== 401) toast(e.message, true);
    }
  } }, label);
  return btn;
}

function page(title, actions, ...body) {
  const m = main();
  m.replaceChildren(h("div", { class: "page-head" }, h("h1", {}, title), h("div", { class: "toolbar" }, actions)), ...body);
}

// table renders rows under column headers. With open, each row does something: open
// is {href: (r) => url} for rows that navigate or {click: (r) => {}} for rows that open
// a dialog. The first cell then holds a real link or button (reachable with the
// keyboard), and a click anywhere else in the row is forwarded to it.
function table(columns, rows, open) {
  if (!rows.length) return h("div", { class: "card empty" }, t("Nothing here yet."));
  return h("div", { class: "card table-wrap", style: "padding:0" },
    h("table", {},
      h("thead", {}, h("tr", {}, columns.map((c) => h("th", {}, c.label)))),
      h("tbody", {}, rows.map((r) => {
        const cells = columns.map((c) => c.render(r));
        if (!open) return h("tr", {}, cells.map((c) => h("td", {}, c)));
        const control = open.href
          ? h("a", { href: open.href(r), class: "row-link" }, cells[0])
          : h("button", { type: "button", class: "row-link", onclick: () => open.click(r) }, cells[0]);
        return clickableRow(control, h("td", {}, control), ...cells.slice(1).map((c) => h("td", {}, c)));
      }))));
}

// clickableRow builds a row whose mouse clicks act like activating control, a link
// or button in one of its cells; clicks on other controls in the row stay theirs.
function clickableRow(control, ...cells) {
  return h("tr", { class: "clickable", onclick: (ev) => {
    if (!ev.target.closest("a, button, input, select, textarea, label")) control.click();
  } }, cells);
}

// detailToggle is the button that shows and hides a row's detail row.
function detailToggle(detail, ...content) {
  const btn = h("button", { type: "button", class: "row-link", "aria-expanded": "false", onclick: () => {
    detail.hidden = !detail.hidden;
    btn.setAttribute("aria-expanded", String(!detail.hidden));
  } }, content);
  return btn;
}

// form dialog: fields = [{name, label, type, value, options, help, placeholder, required, when, list}]
// type is text-like, "select", "textarea", "checkbox" (boolean), "checks" (array of
// option values) or "range" (min, max, unit). when(values) shows the field conditionally;
// list offers suggestions.
function formDialog(title, fields, submitLabel, onSubmit) {
  const dlg = document.getElementById("dialog");
  const form = document.getElementById("dialog-form");
  const err = h("p", { class: "error", role: "alert", hidden: true });
  const readers = {};
  // Labels name their control through for/id and help text describes it, so the
  // accessible name is just the label (not the help or a select's current option).
  const fieldId = (f) => `field-${f.name}`;
  const helpId = (f) => (f.help ? `help-${f.name}` : null);
  const helpText = (f) => (f.help ? h("span", { class: "muted small", id: helpId(f) }, f.help) : null);
  const rows = fields.map((f) => {
    let input;
    let row;
    if (f.type === "select") {
      input = h("select", { name: f.name }, f.options.map(([v, l]) => h("option", { value: v, selected: v === f.value }, l)));
    } else if (f.type === "textarea") {
      input = h("textarea", { name: f.name, placeholder: f.placeholder || "" });
      input.value = f.value ?? "";
    } else if (f.type === "checkbox") {
      input = h("input", { type: "checkbox", name: f.name, checked: Boolean(f.value) });
      readers[f.name] = () => input.checked;
      row = h("div", { class: "field" }, h("label", { class: "check" }, input, h("span", {}, f.label)), helpText(f));
    } else if (f.type === "checks") {
      const selected = new Set(f.value || []);
      row = h("fieldset", { class: "checks" }, h("legend", {}, f.label),
        f.options.length
          ? h("div", { class: "check-grid" }, f.options.map(([v, l]) =>
            h("label", { class: "check" }, h("input", { type: "checkbox", value: v, checked: selected.has(v) }), h("span", { class: f.mono ? "mono" : "" }, l))))
          : h("span", { class: "muted small" }, t("No options available.")),
        helpText(f));
      readers[f.name] = () => [...row.querySelectorAll("input:checked")].map((c) => c.value);
    } else if (f.type === "range") {
      input = h("input", { type: "range", name: f.name, min: f.min ?? 0, max: f.max ?? 100, step: f.step ?? 1 });
      input.value = f.value ?? 0;
      const out = h("output", {}, `${input.value}${f.unit || ""}`);
      input.addEventListener("input", () => (out.textContent = `${input.value}${f.unit || ""}`));
      readers[f.name] = () => Number(input.value);
      row = h("div", { class: "field" }, h("span", { class: "range-head" }, h("label", { for: fieldId(f) }, f.label), out), input, helpText(f));
    } else {
      input = h("input", { name: f.name, type: f.type || "text", placeholder: f.placeholder || "", required: f.required, list: f.list ? `list-${f.name}` : null });
      input.value = f.value ?? "";
    }
    readers[f.name] ??= () => input.value;
    if (input) {
      input.id = fieldId(f);
      if (f.help) input.setAttribute("aria-describedby", helpId(f));
    }
    row ??= h("div", { class: "field" }, h("label", { for: fieldId(f) }, f.label), input, helpText(f),
      f.list ? h("datalist", { id: `list-${f.name}` }, f.list.map((v) => h("option", { value: v }))) : null);
    return { f, row };
  });
  const read = () => Object.fromEntries(Object.entries(readers).map(([k, fn]) => [k, fn()]));
  const sync = () => {
    const v = read();
    for (const { f, row } of rows) if (f.when) row.hidden = !f.when(v);
  };
  const submit = h("button", { class: "primary", type: "submit" }, submitLabel);
  form.replaceChildren(
    h("h2", { id: "dialog-title" }, title),
    h("div", { class: "fields" }, rows.map((r) => r.row)),
    err,
    h("div", { class: "actions" }, h("button", { type: "button", onclick: () => dlg.close() }, t("Cancel")), submit),
  );
  sync();
  form.onchange = sync;
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    const values = read();
    submit.disabled = true;
    try {
      await onSubmit(values);
      dlg.close();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    } finally {
      submit.disabled = false;
    }
  };
  dlg.showModal();
}

function confirmDialog(title, message, label, onConfirm) {
  formDialog(title, [], label, onConfirm);
  document.querySelector("#dialog-form .fields").append(h("p", {}, message));
}

// infoDialog shows read-only content with a single Close button.
function infoDialog(title, ...content) {
  formDialog(title, [], t("Close"), async () => {});
  document.querySelector("#dialog-form .actions button[type=button]").hidden = true;
  document.querySelector("#dialog-form .fields").append(...content);
}

// copyable renders a read-only value with a Copy button.
function copyable(value) {
  const btn = h("button", { type: "button", onclick: async () => {
    try { await navigator.clipboard.writeText(value); btn.textContent = t("Copied"); } catch { toast(t("Copy failed; select the text instead."), true); }
  } }, t("Copy"));
  return h("div", { class: "copy" }, h("code", { class: "secret" }, value), btn);
}

// secretDialog shows values the server returns only once (keys, secrets, recovery codes).
function secretDialog(title, message, values, extra) {
  formDialog(title, [], t("Done"), async () => {});
  document.querySelector("#dialog-form .actions button[type=button]").hidden = true;
  document.querySelector("#dialog-form .fields").append(
    h("p", { class: "notice warn" }, message),
    ...[].concat(values).map((v) => copyable(v)),
    ...(extra ? [extra] : []));
}

const note = (msg) => h("div", { class: "card empty" }, msg);
const deniedNote = () => note(t("You do not have permission to see this."));
// toISO turns a datetime-local value into RFC 3339 (or undefined when empty).
const toISO = (v) => (v ? new Date(v).toISOString() : undefined);

// "k=v" lines <-> object
const parseKV = (s) => Object.fromEntries(s.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
  const i = l.indexOf("=");
  if (i < 1) throw new Error(t('"{line}" is not key=value', { line: l }));
  return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
}));
const formatKV = (o) => Object.entries(o || {}).map(([k, v]) => `${k}=${v}`).join("\n");
const parseJSON = (s, what) => {
  if (!s.trim()) return undefined;
  try { return JSON.parse(s); } catch { throw new Error(t("{what} must be valid JSON", { what })); }
};
const splitList = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
// splitWords splits on commas, spaces and new lines (IDs, URIs).
const splitWords = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

// view loads a tab's data and renders it; a 403 shows a permission note instead.
async function view(fn, render) {
  const r = await optional(fn);
  if (r.denied) return deniedNote();
  if (r.off) return note(r.off);
  if (!r.data) return h("div");
  return render(r.data);
}

// ---- routing ---------------------------------------------------------------

const routes = {
  dashboard: dashboardPage,
  tenants: tenantsPage,
  tenant: tenantPage,
  plans: plansPage,
  templates: templatesPage,
  rollouts: rolloutsPage,
  users: usersPage,
  events: eventsPage,
  "event-schemas": eventSchemasPage,
  "dead-letters": deadLettersPage,
  plugins: pluginsPage,
  audit: auditPage,
  "oauth-clients": oauthClientsPage,
  "signing-keys": signingKeysPage,
  account: accountPage,
};

let stopPolling = () => {};
let me = null; // the signed-in principal (GET /v1/me)
const isPlatform = () => Boolean(me && !me.tenant_id);

function route() {
  stopPolling();
  stopPolling = () => {};
  const [name, ...rest] = (location.hash.replace(/^#\/?/, "") || "dashboard").split("/");
  document.querySelectorAll("#nav a").forEach((a) => {
    const on = a.dataset.route === name || (name === "tenant" && a.dataset.route === "tenants");
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  (routes[name] || dashboardPage)(...rest.map(decodeURIComponent));
}

// ---- dashboard ---------------------------------------------------------------

const tenantStatuses = ["active", "provisioning", "suspended", "failed", "deleting", "deleted"];

// allTenants pages through /v1/tenants up to 2,000 tenants; more means it stopped early.
async function allTenants() {
  let items = [];
  let after = "";
  for (let i = 0; i < 4; i++) {
    const q = new URLSearchParams({ limit: "500" });
    if (after) q.set("after", after);
    const res = await api("GET", `/v1/tenants?${q}`);
    items = items.concat(res.items || []);
    if (!res.next) return { items, more: false };
    after = res.next;
  }
  return { items, more: true };
}

const countBy = (items, key) => items.reduce((acc, x) => ((acc[key(x)] = (acc[key(x)] || 0) + 1), acc), {});

// bars renders [label, count, class] rows as horizontal bars scaled to the largest count.
function bars(entries) {
  if (!entries.length) return h("p", { class: "muted" }, t("No tenants yet."));
  const max = Math.max(...entries.map((e) => e[1]), 1);
  return h("div", { class: "bars" }, entries.map(([label, n, cls]) => h("div", { class: "bar-row" },
    h("span", { class: "bar-label" }, label),
    h("span", { class: "bar", "aria-hidden": "true" }, h("span", { class: `bar-fill ${cls || ""}`, style: `width:${(n / max) * 100}%` })),
    h("span", { class: "bar-value" }, String(n)))));
}

function tile(label, value, href, cls = "") {
  return h(href ? "a" : "div", { class: `tile card ${cls}`, href },
    h("span", { class: "tile-value" }, String(value)), h("span", { class: "tile-label" }, label));
}

const card = (title, ...body) => h("div", { class: "card" }, h("h2", {}, title), ...body);

async function dashboardPage() {
  const loading = h("p", { class: "muted" }, t("Loading…"));
  page(t("Dashboard"), [h("button", { onclick: dashboardPage }, t("Refresh"))], loading);
  const [tens, dead, recent] = await Promise.all([
    optional(allTenants),
    optional(() => api("GET", "/v1/dead-letters")),
    optional(() => api("GET", "/v1/audit?limit=8")),
  ]);
  if (!loading.isConnected) return;
  await loadPlans();
  const items = tens.data?.items || [];
  const byStatus = countBy(items, (x) => x.status);
  const attention = (byStatus.suspended || 0) + (byStatus.failed || 0);
  const tiles = h("div", { class: "tiles" },
    tens.data ? tile(t("Tenants"), tens.data.more ? `${items.length}+` : items.length, "#/tenants") : null,
    tens.data ? tile(t("Active tenants"), byStatus.active || 0) : null,
    tens.data ? tile(t("Suspended or failed"), attention, null, attention ? "warn" : "") : null,
    dead.data ? tile(t("Dead letters"), dead.data.items.length, "#/dead-letters", dead.data.items.length ? "bad" : "") : null);

  const cards = [];
  const limitsBox = h("div", {}, h("p", { class: "muted" }, t("Checking usage…")));
  const riskBox = h("div", {}, h("p", { class: "muted" }, t("Checking health…")));
  if (tens.data) {
    const planName = (id) => plansCache.find((p) => p.id === id)?.name || id;
    cards.push(card(t("Tenants by status"), bars(tenantStatuses.filter((s) => byStatus[s]).map((s) => [t(s), byStatus[s], s]))));
    cards.push(card(t("Tenants by plan"), bars(Object.entries(countBy(items, (x) => x.plan || "")).sort((a, b) => b[1] - a[1])
      .map(([p, n]) => [p ? planName(p) : t("no plan"), n, "plan"]))));
    cards.push(card(t("Near their limits"), limitsBox));
    cards.push(card(t("At risk"), riskBox));
  }
  if (recent.data) {
    cards.push(card(t("Recent activity"), recent.data.items.length
      ? h("ul", { class: "activity" }, recent.data.items.map((e) => h("li", {},
        badge(e.type, ""), " ",
        h("span", { class: "mono small muted" }, e.actor || ""), " ",
        e.tenantid ? h("a", { href: `#/tenant/${encodeURIComponent(e.tenantid)}`, class: "mono small" }, e.tenantid.slice(0, 8)) : null,
        h("div", { class: "muted small" }, fmtTime(e.time)))))
      : h("p", { class: "muted" }, t("No activity yet.")),
    h("a", { href: "#/audit", class: "small" }, t("Open the audit log"))));
  }
  if (!tiles.children.length && !cards.length) {
    loading.replaceWith(note(t("You do not have permission to see this.")));
    return;
  }
  loading.replaceWith(h("div", { class: "stack" }, tiles, h("div", { class: "grid two" }, cards)));
  if (tens.data) {
    nearLimits(limitsBox, items);
    atRisk(riskBox, items);
  }
}

// eachLimited runs fn over items, six at a time; 403s are counted, other errors skipped.
async function eachLimited(items, fn) {
  let next = 0;
  let denied = 0;
  const worker = async () => {
    while (next < items.length) {
      const x = items[next++];
      try { await fn(x); } catch (e) { if (e.status === 403) denied++; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, items.length) }, worker));
  return denied;
}

// atRisk lists the tenants whose health grade is not "healthy", checking at most 25.
async function atRisk(box, tenants) {
  const live = tenants.filter((x) => !["deleting", "deleted"].includes(x.status));
  const sample = live.slice(0, 25);
  const found = [];
  let ok = 0;
  const denied = await eachLimited(sample, async (tn) => {
    const hl = await api("GET", `/v1/tenants/${tn.id}/health`);
    ok++;
    if (hl.grade !== "healthy") found.push({ tn, hl });
  });
  if (!box.isConnected) return;
  if (!ok && sample.length) {
    // Health scores are unavailable (or not allowed): drop the card.
    if (!denied) box.closest(".card")?.remove();
    else box.replaceChildren(h("p", { class: "muted" }, t("You do not have permission to see this.")));
    return;
  }
  found.sort((a, b) => a.hl.score - b.hl.score);
  box.replaceChildren(
    found.length ? h("ul", { class: "list" }, found.slice(0, 8).map(({ tn, hl }) => h("li", {},
      h("div", {}, h("a", { href: `#/tenant/${tn.id}/overview` }, tn.name),
        hl.factors?.length ? h("div", { class: "muted small" }, hl.factors.slice(0, 2).map((f) => f.detail || f.name).join(" · ")) : null),
      h("span", { class: "toolbar" }, h("strong", {}, String(hl.score)), gradeBadge(hl.grade)))))
      : h("p", { class: "muted" }, t("All checked tenants are healthy.")),
    live.length > sample.length ? h("p", { class: "muted small" }, t("Based on the first {n} tenants.", { n: sample.length })) : "");
}

// nearLimits fills box with the metrics of active tenants at 80% of a limit or more,
// checking the usage of at most 50 tenants, six at a time.
async function nearLimits(box, tenants) {
  const active = tenants.filter((x) => x.status === "active");
  const sample = active.slice(0, 50);
  const found = [];
  let next = 0;
  let denied = false;
  const worker = async () => {
    while (next < sample.length) {
      const tn = sample[next++];
      try {
        const u = await api("GET", `/v1/tenants/${tn.id}/usage`);
        for (const m of u.items || []) if (m.limit && m.value / m.limit >= 0.8) found.push({ tn, m, ratio: m.value / m.limit });
      } catch (e) {
        if (e.status === 403) denied = true;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, sample.length) }, worker));
  if (!box.isConnected) return;
  if (denied && !found.length) {
    box.replaceChildren(h("p", { class: "muted" }, t("You do not have permission to see this.")));
    return;
  }
  found.sort((a, b) => b.ratio - a.ratio);
  box.replaceChildren(
    found.length ? h("div", { class: "stack tight" }, found.slice(0, 8).map(({ tn, m, ratio }) => h("div", {},
      h("div", { class: "page-head", style: "margin:0" },
        h("a", { href: `#/tenant/${tn.id}/usage` }, tn.name, " ", h("span", { class: "mono small muted" }, m.metric)),
        h("span", { class: "muted small" }, `${num(m.value)} / ${num(m.limit)}`)),
      h("div", { class: `meter ${ratio >= 1 ? "full" : "high"}`, role: "meter", "aria-valuemin": "0", "aria-valuemax": String(m.limit), "aria-valuenow": String(m.value),
        "aria-label": `${tn.name} ${m.metric}` }, h("span", { style: `width:${Math.min(100, ratio * 100)}%` })))))
      : h("p", { class: "muted" }, t("No tenant is above 80% of a limit.")),
    active.length > sample.length ? h("p", { class: "muted small" }, t("Based on the first {n} active tenants.", { n: sample.length })) : "");
}

// ---- tenants ---------------------------------------------------------------

let plansCache = [];
async function loadPlans() {
  plansCache = (await optional(() => api("GET", "/v1/plans"))).data?.items || [];
  return plansCache;
}

async function tenantsPage() {
  const state = { status: "", q: "", items: [], next: null };
  const status = h("select", { "aria-label": t("Status"), onchange: () => { state.status = status.value; reload(); } },
    [["", t("All statuses")], ...tenantStatuses.map((s) => [s, t(s)])]
      .map(([v, l]) => h("option", { value: v }, l)));
  const search = h("input", { type: "search", placeholder: t("Filter by slug or name"), "aria-label": t("Filter by slug or name"),
    oninput: () => { state.q = search.value.toLowerCase(); render(); } });
  const list = h("div");
  const more = h("button", { hidden: true, onclick: () => load(true) }, t("Load more"));
  page(t("Tenants"), [search, status, h("button", { class: "primary", onclick: createTenant }, t("New tenant"))], list, h("p", {}, more));

  async function load(append) {
    const q = new URLSearchParams({ limit: "100" });
    if (state.status) q.set("status", state.status);
    if (state.status === "deleted") q.set("include_deleted", "true");
    if (append && state.next) q.set("after", state.next);
    const res = await optional(() => api("GET", `/v1/tenants?${q}`));
    if (res.denied) { list.replaceChildren(deniedNote()); return; }
    if (!res.data) return;
    state.items = append ? state.items.concat(res.data.items) : res.data.items;
    state.next = res.data.next || null;
    render();
  }
  const reload = () => load(false);
  function render() {
    const rows = state.items.filter((x) => !state.q || x.slug.includes(state.q) || x.name.toLowerCase().includes(state.q));
    const regions = rows.some((x) => x.region);
    list.replaceChildren(table([
      { label: t("Tenant"), render: (x) => [h("strong", { class: "block" }, x.name), h("span", { class: "block muted mono" }, x.slug)] },
      { label: t("Status"), render: (x) => statusBadge(x.status) },
      { label: t("Plan"), render: (x) => x.plan || dash() },
      ...(regions ? [{ label: t("Region"), render: (x) => x.region || dash() }] : []),
      { label: t("Labels"), render: (x) => chips(x.labels) },
      { label: t("Created"), render: (x) => h("span", { class: "muted" }, fmtTime(x.created_at)) },
    ], rows, { href: (x) => `#/tenant/${x.id}` }));
    more.hidden = !state.next;
  }
  await loadPlans();
  reload();
}

function planOptions(current) {
  return [["", t("— none —")], ...plansCache.map((p) => [p.id, `${p.name} (${p.id})`])]
    .concat(current && !plansCache.some((p) => p.id === current) ? [[current, current]] : []);
}

async function createTenant(parent) {
  const templates = isPlatform() ? (await optional(() => api("GET", "/v1/tenant-templates"))).data?.items || [] : [];
  formDialog(t("New tenant"), [
    ...(templates.length ? [{ name: "template", label: t("Template"), type: "select", value: "",
      options: [["", t("— none —")], ...templates.map((x) => [x.id, x.name || x.id])],
      help: t("The template's plan, region, labels, settings, branding and roles are defaults; fields below override them.") }] : []),
    { name: "name", label: t("Name"), required: true },
    { name: "slug", label: t("Slug"), required: true, help: t("Lowercase letters, digits and dashes. Cannot be changed later.") },
    { name: "plan", label: t("Plan"), type: "select", options: planOptions() },
    { name: "parent_id", label: t("Parent tenant"), value: typeof parent === "string" ? parent : "", placeholder: t("ID or slug (optional)") },
    { name: "labels", label: t("Labels"), type: "textarea", placeholder: "region=eu\ntier=gold" },
    { name: "settings", label: t("Settings (JSON)"), type: "textarea", placeholder: "{}" },
  ], t("Create"), async (v) => {
    const body = { name: v.name, slug: v.slug, labels: v.labels.trim() ? parseKV(v.labels) : undefined, settings: parseJSON(v.settings, t("Settings")) };
    if (v.template) body.template = v.template;
    if (v.plan) body.plan = v.plan;
    if (v.parent_id) body.parent_id = v.parent_id;
    const tn = await api("POST", "/v1/tenants", body, { "Idempotency-Key": crypto.randomUUID() });
    toast(t("Tenant {slug} created", { slug: tn.slug }));
    location.hash = `#/tenant/${tn.id}`;
  });
}

async function tenantPage(id, tab = "overview") {
  const tn = await guard(() => api("GET", `/v1/tenants/${encodeURIComponent(id)}`));
  if (!tn) return;
  await loadPlans();
  const refresh = () => tenantPage(tn.id, currentTab);
  let currentTab = tab;

  const actions = [];
  if (tn.status === "active") actions.push(act(t("Suspend"), "", () => formDialog(t("Suspend tenant"),
    [{ name: "reason", label: t("Reason"), placeholder: t("e.g. payment overdue") }], t("Suspend"),
    async (v) => { await api("POST", `/v1/tenants/${tn.id}/suspend`, { reason: v.reason }); toast(t("Suspended")); refresh(); })));
  const pendingDeletion = tn.status === "suspended" && tn.status_reason === "pending deletion";
  if (tn.status === "suspended" && !pendingDeletion) actions.push(act(t("Resume"), "", async () => { await api("POST", `/v1/tenants/${tn.id}/resume`); toast(t("Resumed")); refresh(); }));
  if (tn.status === "failed") actions.push(act(t("Retry provisioning"), "", async () => { await api("POST", `/v1/tenants/${tn.id}/retry-provisioning`); toast(t("Provisioning restarted")); refresh(); }));
  if (tn.status !== "deleted") actions.push(act(t("Export data"), "", () => download(`/v1/tenants/${tn.id}/export`, `tenant-${tn.slug}.json`)));
  const inMaintenance = Boolean(tn.maintenance) && !(tn.maintenance.until && new Date(tn.maintenance.until) < new Date());
  if (isPlatform() && !["deleting", "deleted"].includes(tn.status)) {
    actions.push(act(t("Clone"), "", () => cloneTenant(tn)));
    actions.push(inMaintenance
      ? act(t("End maintenance"), "", async () => { await api("DELETE", `/v1/tenants/${tn.id}/maintenance`); toast(t("Maintenance ended")); refresh(); })
      : act(t("Maintenance"), "", startMaintenance));
  }

  function startMaintenance() {
    formDialog(t("Start maintenance"), [
      { name: "message", label: t("Message"), type: "textarea", placeholder: t("e.g. Moving your data to a new region."), help: t("Shown to the tenant's users.") },
      { name: "until", label: t("Until"), type: "datetime-local", help: t("Optional: maintenance ends by itself then.") },
    ], t("Start maintenance"), async (v) => {
      await api("POST", `/v1/tenants/${tn.id}/maintenance`, { message: v.message.trim() || undefined, until: toISO(v.until) });
      toast(t("Maintenance started")); refresh();
    });
    document.querySelector("#dialog-form .fields").prepend(h("p", { class: "notice warn" },
      t("While maintenance is on, the tenant is read-only for its own users and API keys; platform admins can still change it.")));
  }
  if (!["deleting", "deleted"].includes(tn.status)) {
    actions.push(act(t("Edit"), "", () => editTenant(tn, refresh)));
    if (!pendingDeletion) actions.push(act(t("Delete"), "danger", () => confirmDialog(t("Delete tenant"),
      t("Delete {name} ({slug})? Provisioned resources will be removed.", { name: tn.name, slug: tn.slug }), t("Delete"),
      async () => {
        await api("DELETE", `/v1/tenants/${tn.id}`);
        const at = api.headers.get("Tenarium-Deletion-At");
        toast(at ? t("Deletion scheduled for {time}; it can be restored until then.", { time: fmtTime(at) }) : t("Deletion started"));
        refresh();
      })));
    actions.push(act(t("Delete permanently"), "danger", () => confirmDialog(t("Delete permanently"),
      t("Delete {name} ({slug}) now, skipping the grace period? This cannot be undone.", { name: tn.name, slug: tn.slug }), t("Delete permanently"),
      async () => { await api("DELETE", `/v1/tenants/${tn.id}?force=true`); toast(t("Deletion started")); refresh(); })));
  }

  const tabs = [["overview", t("Overview")], ["members", t("Members")], ["roles", t("Roles & groups")], ["usage", t("Usage")],
    ["children", t("Children")], ["events", t("Events")], ["schedule", t("Schedule")], ["domains", t("Domains")],
    ["api-keys", t("API keys")], ["webhooks", t("Webhooks")], ["sso", t("SSO")], ["audit", t("Audit")]];
  const body = h("div", { role: "tabpanel" });
  const tabBar = h("div", { class: "tabs", role: "tablist" }, tabs.map(([name, label]) => h("button", {
    type: "button", class: name === currentTab ? "active" : "", role: "tab", "aria-selected": String(name === currentTab),
    onclick: (e) => {
      currentTab = name;
      history.replaceState(null, "", `#/tenant/${tn.id}/${name}`);
      tabBar.querySelectorAll("button").forEach((b) => { b.classList.remove("active"); b.setAttribute("aria-selected", "false"); });
      e.target.classList.add("active");
      e.target.setAttribute("aria-selected", "true");
      renderTab();
    },
  }, label)));

  let banner = null;
  if (pendingDeletion) {
    const del = (await optional(() => api("GET", `/v1/tenants/${tn.id}/schedule`))).data?.items?.find((a) => a.action === "delete" && a.status === "pending");
    banner = h("div", { class: "notice warn banner", role: "status" },
      h("span", {}, del ? t("This tenant is pending deletion and will be deleted on {time}.", { time: fmtTime(del.run_at) }) : t("This tenant is pending deletion."),
        " ", t("Restore it to cancel the deletion.")),
      act(t("Restore"), "primary", async () => { await api("POST", `/v1/tenants/${tn.id}/restore`); toast(t("Tenant restored")); refresh(); }));
  }

  const maintenanceBanner = inMaintenance ? h("div", { class: "notice warn banner", role: "status" },
    h("span", {}, h("strong", {}, t("Under maintenance")), " · ",
      tn.maintenance.until ? t("since {start}, until {end}", { start: fmtTime(tn.maintenance.started_at), end: fmtTime(tn.maintenance.until) })
        : t("since {start}", { start: fmtTime(tn.maintenance.started_at) }),
      tn.maintenance.message ? h("div", {}, tn.maintenance.message) : null)) : null;

  page(h("span", {}, h("a", { href: "#/tenants", class: "muted" }, `${t("Tenants")} / `), tn.name, " ", statusBadge(tn.status)), actions,
    ...[banner, maintenanceBanner, tabBar, body].filter(Boolean));

  async function renderTab() {
    stopPolling();
    body.replaceChildren(h("p", { class: "muted" }, t("Loading…")));
    const render = { overview, members, roles, usage, children, events, schedule, domains, "api-keys": apiKeys, webhooks, sso, audit }[currentTab] || overview;
    body.replaceChildren(await render());
  }

  async function schedule() {
    return view(() => api("GET", `/v1/tenants/${tn.id}/schedule`), (res) => {
      const add = h("button", { class: "primary", onclick: () => formDialog(t("Schedule an action"), [
        { name: "action", label: t("Action"), type: "select", options: ["suspend", "resume", "set_plan", "delete"].map((a) => [a, a]), value: "suspend" },
        { name: "after", label: t("After"), placeholder: t("e.g. 14d or 36h"), help: t("Relative to now. Give either this or a time.") },
        { name: "at", label: t("At"), type: "datetime-local" },
        { name: "plan", label: t("Plan (set_plan)"), type: "select", options: planOptions(), when: (v) => v.action === "set_plan" },
        { name: "reason", label: t("Reason (suspend)"), placeholder: t("e.g. trial ended"), when: (v) => v.action === "suspend" },
      ], t("Schedule"), async (v) => {
        if (Boolean(v.after) === Boolean(v.at)) throw new Error(t("Give either After or At."));
        if (v.action === "set_plan" && !v.plan) throw new Error(t("Choose a plan for set_plan."));
        const req = { action: v.action, after: v.after || undefined, at: toISO(v.at) };
        if (v.action === "set_plan") req.plan = v.plan;
        if (v.action === "suspend" && v.reason) req.reason = v.reason;
        await api("POST", `/v1/tenants/${tn.id}/schedule`, req);
        toast(t("Action scheduled")); renderTab();
      }) }, t("Schedule action"));
      return h("div", { class: "stack" }, h("div", {}, add), table([
        { label: t("Action"), render: (a) => h("div", {}, h("strong", { class: "mono" }, a.action), a.plan ? h("div", { class: "muted small" }, t("plan {plan}", { plan: a.plan })) : null,
          a.reason ? h("div", { class: "muted small" }, a.reason) : null) },
        { label: t("Runs at"), render: (a) => fmtTime(a.run_at) },
        { label: t("Status"), render: (a) => h("div", {}, badge(t(a.status), { pending: "invited", done: "ok", failed: "failed" }[a.status] || ""),
          a.error ? h("div", { class: "error small" }, a.error) : null) },
        { label: t("By"), render: (a) => h("span", { class: "muted small" }, a.created_by || "") },
        { label: "", render: (a) => (a.status === "pending" ? h("button", { class: "danger", onclick: () => confirmDialog(t("Cancel action"), t("Cancel the scheduled {action}?", { action: a.action }), t("Cancel action"),
          async () => { await api("DELETE", `/v1/tenants/${tn.id}/schedule/${encodeURIComponent(a.id)}`); toast(t("Canceled")); refresh(); }) }, t("Cancel")) : null) },
      ], res.items || []));
    });
  }

  async function domains() {
    const r = await optional(() => api("GET", `/v1/tenants/${tn.id}/domains`));
    if (r.denied) return deniedNote();
    if (!r.data) return h("div");
    const items = r.data.items || [];
    const path = (d) => `/v1/tenants/${tn.id}/domains/${encodeURIComponent(d.hostname)}`;
    // Managed certificates: a 404 on the first lookup means ACME is off, so the column stays hidden.
    const certs = {};
    const verified = items.filter((d) => d.verified);
    if (verified.length) {
      const first = await optional(() => api("GET", `${path(verified[0])}/certificate`));
      if (first.data) {
        certs[verified[0].hostname] = first.data;
        await Promise.all(verified.slice(1).map(async (d) => { certs[d.hostname] = (await optional(() => api("GET", `${path(d)}/certificate`))).data; }));
      }
    }
    const certCell = (d) => {
      const c = certs[d.hostname];
      if (!c) return dash();
      if (!c.issued) return h("div", {}, badge(t("not issued yet"), "invited"), h("div", { class: "muted small" }, t("Issued on the first HTTPS request.")));
      const notAfter = c.certificate?.not_after;
      const soon = notAfter && new Date(notAfter) - Date.now() < 14 * 864e5;
      return h("div", {}, badge(t("issued"), soon ? "invited" : "ok"),
        notAfter ? h("div", { class: "muted small" }, t("Expires {time}", { time: fmtTime(notAfter) })) : null,
        c.certificate?.issuer ? h("div", { class: "muted small" }, c.certificate.issuer) : null);
    };
    const txt = (name, value) => h("dl", { class: "kv" }, h("dt", {}, t("Type")), h("dd", {}, "TXT"),
      h("dt", {}, t("Name")), h("dd", {}, copyable(name)), h("dt", {}, t("Value")), h("dd", {}, copyable(value)));
    const add = h("button", { class: "primary", onclick: () => formDialog(t("Add domain"), [
      { name: "hostname", label: t("Hostname"), required: true, placeholder: "app.acme.com" },
    ], t("Add"), async (v) => {
      const res = await api("POST", `/v1/tenants/${tn.id}/domains`, { hostname: v.hostname.trim() });
      renderTab();
      setTimeout(() => secretDialog(t("Verify {host}", { host: res.domain.hostname }), t("Publish this DNS record, then press Verify on the domain."), [],
        txt(res.instructions.name, res.instructions.value)));
    }) }, t("Add domain"));
    return h("div", { class: "stack" }, h("div", {}, add), table([
      { label: t("Hostname"), render: (d) => h("strong", { class: "mono" }, d.hostname) },
      { label: t("Status"), render: (d) => (d.verified ? badge(t("verified"), "ok") : badge(t("unverified"), "invited")) },
      ...(Object.keys(certs).length ? [{ label: t("Certificate"), render: certCell }] : []),
      { label: t("Added"), render: (d) => h("span", { class: "muted" }, fmtTime(d.created_at)) },
      { label: "", render: (d) => h("div", { class: "toolbar" },
        d.verified ? null : act(t("Verify"), "", async () => { await api("POST", `${path(d)}/verify`); toast(t("Domain verified")); renderTab(); }),
        d.verified ? null : h("button", { onclick: () => secretDialog(t("Verify {host}", { host: d.hostname }), t("Publish this DNS record, then press Verify."), [],
          txt(`_tenarium-challenge.${d.hostname}`, d.verification_token)) }, t("DNS record")),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Remove domain"), t("Remove {host}?", { host: d.hostname }), t("Remove"),
          async () => { await api("DELETE", path(d)); toast(t("Domain removed")); renderTab(); }) }, t("Remove"))) },
    ], items));
  }

  async function apiKeys() {
    return view(() => api("GET", `/v1/tenants/${tn.id}/api-keys`), (res) => {
      const add = h("button", { class: "primary", onclick: () => formDialog(t("New API key"), [
        { name: "name", label: t("Name"), required: true, placeholder: t("e.g. CI deploys") },
        { name: "roles", label: t("Roles"), value: "member", help: t("Member roles, comma separated.") },
        { name: "expires_in", label: t("Expires in"), placeholder: t("e.g. 720h"), help: t("Leave empty for no expiry.") },
      ], t("Create"), async (v) => {
        const k = await api("POST", `/v1/tenants/${tn.id}/api-keys`, { name: v.name, roles: splitList(v.roles), expires_in: v.expires_in || undefined });
        renderTab();
        setTimeout(() => secretDialog(t("API key {name}", { name: k.name }), t("Copy the key now. It is not shown again."), k.key));
      }) }, t("New API key"));
      return h("div", { class: "stack" }, h("div", {}, add), table([
        { label: t("Key"), render: (k) => h("div", {}, h("strong", {}, k.name), h("div", { class: "muted mono" }, `${k.prefix}…`)) },
        { label: t("Roles"), render: (k) => chipList(k.roles) },
        { label: t("Status"), render: (k) => (k.revoked_at ? badge(t("revoked"), "failed") : k.expires_at && new Date(k.expires_at) < new Date() ? badge(t("expired"), "") : badge(t("active"), "active")) },
        { label: t("Expires"), render: (k) => h("span", { class: "muted" }, fmtTime(k.expires_at) || t("never")) },
        { label: t("Last used"), render: (k) => h("span", { class: "muted" }, fmtTime(k.last_used_at) || "—") },
        { label: "", render: (k) => (k.revoked_at ? null : h("button", { class: "danger", onclick: () => confirmDialog(t("Revoke key"), t("Revoke {name}? Clients using it stop working.", { name: k.name }), t("Revoke"),
          async () => { await api("DELETE", `/v1/tenants/${tn.id}/api-keys/${encodeURIComponent(k.id)}`); toast(t("Key revoked")); renderTab(); }) }, t("Revoke"))) },
      ], res.items || []));
    });
  }

  async function webhooks() {
    const base = `/v1/tenants/${tn.id}/webhooks`;
    const { data, off, denied } = await optional(() => api("GET", base));
    if (off) return note(t("Webhooks are not available: {reason}", { reason: off }));
    if (denied) return deniedNote();
    if (!data) return h("div");
    const edit = (w) => formDialog(w ? t("Edit webhook") : t("New webhook"), [
      { name: "url", label: t("URL"), type: "url", required: true, value: w?.url, placeholder: "https://example.com/hooks/tenarium" },
      { name: "description", label: t("Description"), value: w?.description },
      { name: "types", label: t("Event types"), value: (w?.types || []).join(", "), placeholder: "tenant.*, member.added", help: t("Comma separated globs; empty means all events.") },
      { name: "enabled", label: t("Enabled"), type: "checkbox", value: w ? w.enabled : true },
    ], w ? t("Save") : t("Create"), async (v) => {
      const req = { url: v.url, description: v.description, types: splitList(v.types), enabled: v.enabled };
      if (w) { await api("PATCH", `${base}/${encodeURIComponent(w.id)}`, req); toast(t("Webhook saved")); renderTab(); return; }
      const res = await api("POST", base, req);
      renderTab();
      setTimeout(() => secretDialog(t("Webhook signing secret"), t("Copy the secret now to verify signatures. It is not shown again."), res.secret));
    });
    const wpath = (w) => `${base}/${encodeURIComponent(w.id)}`;
    return h("div", { class: "stack" }, h("div", {}, h("button", { class: "primary", onclick: () => edit() }, t("New webhook"))), table([
      { label: t("Webhook"), render: (w) => h("div", {}, h("strong", { class: "mono" }, w.url), w.description ? h("div", { class: "muted small" }, w.description) : null) },
      { label: t("Types"), render: (w) => (w.types?.length ? chipList(w.types, "chip mono") : h("span", { class: "muted" }, t("all"))) },
      { label: t("Status"), render: (w) => h("div", {}, w.enabled ? badge(t("enabled"), "ok") : badge(t("disabled"), "failed"),
        w.failures ? h("div", { class: "muted small" }, t("Failures: {n}", { n: w.failures })) : null) },
      { label: "", render: (w) => h("div", { class: "toolbar" },
        h("button", { onclick: () => guard(async () => { body.replaceChildren(await deliveries(w)); }) }, t("Deliveries")),
        h("button", { onclick: () => guard(async () => { const d = await api("POST", `${wpath(w)}/test`); toast(d.success ? t("Test delivered ({status})", { status: d.status_code }) : t("Test failed: {reason}", { reason: d.error || d.status_code }), !d.success); }) }, t("Test")),
        act(w.enabled ? t("Disable") : t("Enable"), "", async () => { await api("PATCH", wpath(w), { enabled: !w.enabled }); toast(w.enabled ? t("Webhook disabled") : t("Webhook enabled")); renderTab(); }),
        h("button", { onclick: () => edit(w) }, t("Edit")),
        h("button", { onclick: () => confirmDialog(t("Rotate secret"), t("Replace the signing secret? Receivers must switch to the new one."), t("Rotate"),
          async () => { const res = await api("POST", `${wpath(w)}/rotate-secret`); setTimeout(() => secretDialog(t("New signing secret"), t("Copy the secret now. It is not shown again."), res.secret)); }) }, t("Rotate secret")),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Delete webhook"), t("Delete the webhook to {url} and its delivery log?", { url: w.url }), t("Delete"),
          async () => { await api("DELETE", wpath(w)); toast(t("Webhook deleted")); renderTab(); }) }, t("Delete"))) },
    ], data.items || []));
  }

  async function deliveries(w) {
    const path = `/v1/tenants/${tn.id}/webhooks/${encodeURIComponent(w.id)}/deliveries`;
    const tbody = h("tbody");
    const older = h("button", { hidden: true, onclick: () => guard(() => load(older.dataset.next)) }, t("Older"));
    async function load(before) {
      const q = new URLSearchParams({ limit: "50" });
      if (before) q.set("before", before);
      const res = await api("GET", `${path}?${q}`);
      if (!before) tbody.replaceChildren();
      for (const d of res.items || []) {
        const detail = h("tr", { hidden: true }, h("td", { colspan: 6 }, json(d.payload || {})));
        const toggle = detailToggle(detail, badge(d.event_type || "", ""));
        tbody.append(clickableRow(toggle,
          h("td", {}, toggle),
          h("td", {}, d.success ? badge(String(d.status_code || "ok"), "ok") : badge(d.status_code ? String(d.status_code) : t("error"), "failed"),
            d.error ? h("div", { class: "error small" }, d.error) : null),
          h("td", { class: "muted" }, `${d.attempts ?? 0} · ${d.duration_ms ?? 0} ms`),
          h("td", { class: "muted" }, fmtTime(d.created_at)),
          h("td", {}, h("button", { onclick: () => { guard(async () => {
            const r = await api("POST", `${path}/${encodeURIComponent(d.id)}/redeliver`);
            toast(r.success ? t("Redelivered") : t("Redelivery failed: {reason}", { reason: r.error || r.status_code }), !r.success);
            await load();
          }); } }, t("Redeliver")))), detail);
      }
      if (!tbody.children.length) tbody.append(h("tr", {}, h("td", { colspan: 6, class: "empty" }, t("No deliveries yet."))));
      older.dataset.next = res.next || "";
      older.hidden = !res.next;
    }
    await load();
    return h("div", { class: "stack" },
      h("div", { class: "toolbar" }, h("button", { onclick: renderTab }, `← ${t("Webhooks")}`), h("strong", { class: "mono" }, w.url)),
      h("div", { class: "card table-wrap", style: "padding:0" }, h("table", {},
        h("thead", {}, h("tr", {}, [t("Event"), t("Result"), t("Attempts"), t("Time"), ""].map((c) => h("th", {}, c)))), tbody)),
      h("p", {}, older));
  }

  async function sso() {
    const path = `/v1/tenants/${tn.id}/sso`;
    const { data: c, off, denied } = await optional(() => api("GET", path));
    if (denied) return deniedNote();
    if (off && off !== "resource not found") return note(t("Single sign-on is not available: {reason}", { reason: off }));
    if (!c && !off) return h("div");
    const oidc = (v) => v.protocol !== "saml";
    const saml = (v) => v.protocol === "saml";
    const edit = () => formDialog(c ? t("Edit SSO connection") : t("Configure SSO"), [
      { name: "protocol", label: t("Protocol"), type: "select", options: [["oidc", "OpenID Connect"], ["saml", "SAML 2.0"]], value: c?.protocol || "oidc" },
      { name: "issuer", label: t("Issuer URL"), type: "url", value: c?.issuer, placeholder: "https://login.example.com", when: oidc },
      { name: "client_id", label: t("Client ID"), value: c?.client_id, when: oidc },
      { name: "client_secret", label: t("Client secret"), type: "password", when: oidc,
        help: c?.protocol === "oidc" || (c && !c.protocol) ? t("Leave blank to keep the current secret.") : undefined },
      { name: "saml_metadata_url", label: t("IdP metadata URL"), type: "url", value: c?.saml_metadata_url, placeholder: "https://idp.example.com/metadata", when: saml,
        help: t("Fetched once when saved; save again to refresh.") },
      { name: "saml_metadata", label: t("IdP metadata XML"), type: "textarea", when: saml, placeholder: "<EntityDescriptor …>",
        help: t("Paste the XML instead of giving a URL.") },
      { name: "saml_email_attribute", label: t("Email attribute"), value: c?.saml_email_attribute, placeholder: "email", when: saml,
        help: t("Default: email, mail, the email claim URI or an email NameID.") },
      { name: "saml_name_attribute", label: t("Name attribute"), value: c?.saml_name_attribute, placeholder: "displayName", when: saml },
      { name: "domains", label: t("Email domains"), required: true, value: (c?.domains || []).join(", "), help: t("Comma separated; must be verified domains of this tenant.") },
      { name: "enforce", label: t("Enforce (refuse password logins)"), type: "checkbox", value: c?.enforce ?? false },
      { name: "auto_provision", label: t("Auto-provision members"), type: "checkbox", value: c?.auto_provision ?? false },
      { name: "default_role", label: t("Default role"), value: c?.default_role || "member" },
      { name: "enabled", label: t("Enabled"), type: "checkbox", value: c?.enabled ?? true },
    ], t("Save"), async (v) => {
      const req = { protocol: v.protocol, domains: splitList(v.domains), enforce: v.enforce, auto_provision: v.auto_provision,
        default_role: v.default_role || undefined, enabled: v.enabled };
      if (saml(v)) {
        if (!v.saml_metadata_url && !v.saml_metadata.trim() && c?.protocol !== "saml") throw new Error(t("Give the IdP metadata URL or XML."));
        Object.assign(req, { saml_metadata_url: v.saml_metadata_url || undefined, saml_metadata: v.saml_metadata.trim() || undefined,
          saml_email_attribute: v.saml_email_attribute || undefined, saml_name_attribute: v.saml_name_attribute || undefined });
      } else {
        if (!v.issuer || !v.client_id) throw new Error(t("Issuer URL and client ID are required."));
        Object.assign(req, { issuer: v.issuer, client_id: v.client_id, client_secret: v.client_secret || undefined });
      }
      await api("PUT", path, req);
      toast(t("SSO connection saved")); renderTab();
    });
    if (!c) return h("div", { class: "stack" }, note(t("No SSO connection is configured.")), h("div", {}, h("button", { class: "primary", onclick: edit }, t("Configure SSO"))));
    const isSAML = c.protocol === "saml";
    const origin = location.origin;
    const sp = isSAML
      ? [h("dt", {}, t("SP metadata URL")), h("dd", {}, copyable(`${origin}/v1/auth/sso/saml/${tn.id}/metadata`)),
        h("dt", {}, t("ACS URL")), h("dd", {}, copyable(`${origin}/v1/auth/sso/saml/${tn.id}/acs`))]
      : [h("dt", {}, t("Redirect URI")), h("dd", {}, copyable(`${origin}/v1/auth/sso/callback`))];
    return h("div", { class: "grid two" },
      h("div", { class: "card" },
        h("div", { class: "page-head", style: "margin-bottom:12px" }, h("h2", { style: "margin:0" }, isSAML ? "SAML 2.0" : "OpenID Connect"), h("div", { class: "toolbar" },
          act(t("Edit"), "", edit),
          h("button", { class: "danger", onclick: () => confirmDialog(t("Remove SSO"), t("Remove the SSO connection? Users sign in with passwords again."), t("Remove"),
            async () => { await api("DELETE", path); toast(t("SSO connection removed")); renderTab(); }) }, t("Remove")))),
        h("dl", { class: "kv" },
          ...(isSAML
            ? [h("dt", {}, t("IdP metadata URL")), h("dd", { class: "mono" }, c.saml_metadata_url || t("(uploaded XML)")),
              h("dt", {}, t("Email attribute")), h("dd", { class: "mono" }, c.saml_email_attribute || t("default")),
              h("dt", {}, t("Name attribute")), h("dd", { class: "mono" }, c.saml_name_attribute || "—")]
            : [h("dt", {}, t("Issuer")), h("dd", { class: "mono" }, c.issuer),
              h("dt", {}, t("Client ID")), h("dd", { class: "mono" }, c.client_id)]),
          h("dt", {}, t("Domains")), h("dd", {}, chipList(c.domains, "chip mono")),
          h("dt", {}, t("Enabled")), h("dd", {}, yesNo(c.enabled)),
          h("dt", {}, t("Enforce")), h("dd", {}, yesNo(c.enforce)),
          h("dt", {}, t("Auto-provision")), h("dd", {}, yesNo(c.auto_provision)),
          h("dt", {}, t("Default role")), h("dd", {}, c.default_role || "member"),
          h("dt", {}, t("Updated")), h("dd", {}, fmtTime(c.updated_at)))),
      h("div", { class: "card" }, h("h2", {}, t("Identity provider setup")),
        h("p", { class: "muted small" }, t("Give these to your identity provider. They use this server's address; behind a proxy, use the configured public URL instead.")),
        h("dl", { class: "kv" }, ...sp)));
  }

  async function audit() {
    return auditView(`/v1/tenants/${tn.id}/audit`, false);
  }

  async function overview() {
    const [ent, health] = (await Promise.all([
      optional(() => api("GET", `/v1/tenants/${tn.id}/entitlements`)), optional(() => api("GET", `/v1/tenants/${tn.id}/health`))])).map((r) => r.data);
    const platform = isPlatform();
    const b = tn.branding || {};
    return h("div", { class: "grid two" },
      health ? h("div", { class: "card" }, h("h2", {}, t("Health")),
        h("div", { class: "health" }, h("span", { class: `health-score ${health.grade}` }, String(health.score)), gradeBadge(health.grade)),
        health.factors?.length
          ? h("ul", { class: "list" }, health.factors.map((f) => h("li", {},
            h("div", {}, h("strong", { class: "mono small" }, f.name), f.detail ? h("div", { class: "muted small" }, f.detail) : null),
            h("span", { class: "muted" }, `−${Math.abs(f.impact || 0)}`))))
          : h("p", { class: "muted" }, t("Nothing is lowering the score."))) : null,
      h("div", { class: "card" }, h("h2", {}, t("Details")), h("dl", { class: "kv" },
        h("dt", {}, t("ID")), h("dd", { class: "mono" }, tn.id),
        h("dt", {}, t("Slug")), h("dd", { class: "mono" }, tn.slug),
        h("dt", {}, t("Parent")), h("dd", {}, tn.parent_id ? h("a", { href: `#/tenant/${tn.parent_id}`, class: "mono" }, tn.parent_id) : "—"),
        h("dt", {}, t("Status reason")), h("dd", {}, tn.status_reason || "—"),
        h("dt", {}, t("Version")), h("dd", {}, String(tn.version)),
        h("dt", {}, t("Created")), h("dd", {}, fmtTime(tn.created_at)),
        h("dt", {}, t("Updated")), h("dd", {}, fmtTime(tn.updated_at)),
        h("dt", {}, t("Labels")), h("dd", {}, chips(tn.labels)))),
      h("div", { class: "card" }, h("h2", {}, t("Plan & placement")), h("dl", { class: "kv" },
        h("dt", {}, t("Plan")), h("dd", {}, tn.plan || "—"),
        h("dt", {}, t("Plan revision")), h("dd", {}, tn.plan_revision ? badge(t("pinned to revision {n}", { n: tn.plan_revision }), "invited") : t("follows the current plan")),
        h("dt", {}, t("Add-ons")), h("dd", {}, tn.add_ons?.length ? chipList(tn.add_ons, "chip mono") : "—"),
        h("dt", {}, t("Region")), h("dd", {}, tn.region || "—"),
        h("dt", {}, t("Billing anchor")), h("dd", {}, tn.billing_anchor ? fmtTime(tn.billing_anchor) : h("span", { class: "muted" }, t("creation time")))),
      platform && !["deleting", "deleted"].includes(tn.status) ? h("div", { class: "toolbar", style: "margin-top:16px" },
        tn.plan ? act(t("Pin revision"), "", pinRevision) : null,
        act(t("Add-ons"), "", editAddOns),
        act(t("Move region"), "", moveRegion),
        act(t("Billing anchor"), "", editBillingAnchor)) : null),
      h("div", { class: "card" }, h("h2", {}, t("Entitlements")), ent ? h("dl", { class: "kv" },
        h("dt", {}, t("Features")), h("dd", {}, h("div", { class: "chips" }, Object.entries(ent.features).map(([k, on]) => badge(k, on ? "ok" : "")))),
        h("dt", {}, t("Limits")), h("dd", {}, chips(ent.limits))) : null),
      h("div", { class: "card" }, h("h2", {}, t("Branding")),
        Object.keys(b).length ? h("dl", { class: "kv" },
          ...[["display_name", t("Display name")], ["logo_url", t("Logo URL")], ["icon_url", t("Icon URL")], ["primary_color", t("Primary color")],
            ["accent_color", t("Accent color")], ["support_email", t("Support email")], ["support_url", t("Support URL")]]
            .filter(([k]) => b[k]).flatMap(([k, label]) => [h("dt", {}, label), h("dd", { class: "mono" },
              /_color$/.test(k) && validColor(b[k]) ? h("span", { class: "swatch", style: `background:${b[k]}` }) : null, b[k])]))
          : h("p", { class: "muted" }, t("No branding: the default look is used.")),
        !["deleting", "deleted"].includes(tn.status) ? h("div", { class: "toolbar", style: "margin-top:12px" },
          act(t("Edit branding"), "", editBranding),
          Object.keys(b).length ? act(t("Clear branding"), "danger", async () => {
            await api("PATCH", `/v1/tenants/${tn.id}`, { branding: {} }, { "If-Match": `"${tn.version}"` });
            toast(t("Branding cleared")); refresh();
          }) : null) : null),
      h("div", { class: "card" }, h("h2", {}, t("Settings")), json(tn.settings || {})),
      h("div", { class: "card" }, h("h2", {}, t("Overrides")), json({ features: tn.features || {}, limits: tn.limits || {} })));
  }

  async function pinRevision() {
    const revs = (await api("GET", `/v1/plans/${encodeURIComponent(tn.plan)}/revisions`)).items || [];
    formDialog(t("Plan revision"), [
      { name: "revision", label: t("Revision of {plan}", { plan: tn.plan }), type: "select", value: String(tn.plan_revision || 0),
        options: [["0", t("Follow the current plan")], ...revs.map((r) => [String(r.revision), t("Revision {n} · {time}", { n: r.revision, time: fmtTime(r.created_at) })])],
        help: t("A pinned tenant keeps that revision's features and limits when the plan changes.") },
    ], t("Save"), async (v) => {
      await api("PUT", `/v1/tenants/${tn.id}/plan-revision`, { revision: Number(v.revision) });
      toast(Number(v.revision) ? t("Pinned to revision {n}", { n: v.revision }) : t("Following the current plan"));
      refresh();
    });
  }

  function editAddOns() {
    formDialog(t("Add-ons"), [
      { name: "add_ons", label: t("Add-on plans"), type: "checks", value: tn.add_ons || [],
        options: plansCache.filter((p) => p.id !== tn.plan).map((p) => [p.id, `${p.name} (${p.id})`]),
        help: t("Their features and limits stack on the tenant's plan.") },
    ], t("Save"), async (v) => {
      await api("PATCH", `/v1/tenants/${tn.id}`, { add_ons: v.add_ons }, { "If-Match": `"${tn.version}"` });
      toast(t("Add-ons saved"));
      refresh();
    });
  }

  function editBranding() {
    const b = tn.branding || {};
    formDialog(t("Edit branding"), [
      { name: "display_name", label: t("Display name"), value: b.display_name },
      { name: "logo_url", label: t("Logo URL"), type: "url", value: b.logo_url, placeholder: "https://…/logo.svg", help: t("https only.") },
      { name: "icon_url", label: t("Icon URL"), type: "url", value: b.icon_url },
      { name: "primary_color", label: t("Primary color"), value: b.primary_color, placeholder: "#4f46e5" },
      { name: "accent_color", label: t("Accent color"), value: b.accent_color, placeholder: "#0ea5e9" },
      { name: "support_email", label: t("Support email"), type: "email", value: b.support_email },
      { name: "support_url", label: t("Support URL"), type: "url", value: b.support_url },
    ], t("Save"), async (v) => {
      for (const k of ["primary_color", "accent_color"]) if (v[k] && !validColor(v[k])) throw new Error(t("Colors must look like #4f46e5 or #fff."));
      const branding = Object.fromEntries(Object.entries(v).map(([k, x]) => [k, x.trim()]).filter(([, x]) => x));
      await api("PATCH", `/v1/tenants/${tn.id}`, { branding }, { "If-Match": `"${tn.version}"` });
      toast(t("Branding saved")); refresh();
    });
  }

  // datetime-local wants local "YYYY-MM-DDTHH:mm".
  const localInput = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60e3).toISOString().slice(0, 16);
  };

  function editBillingAnchor() {
    formDialog(t("Billing anchor"), [
      { name: "anchor", label: t("Billing cycles start at"), type: "datetime-local", value: localInput(tn.billing_anchor || tn.created_at),
        help: t("Monthly cycles of usage metrics with the period \"cycle\" restart on this day and time.") },
    ], t("Save"), async (v) => {
      if (!v.anchor) throw new Error(t("Choose a date and time."));
      await api("PATCH", `/v1/tenants/${tn.id}`, { billing_anchor: toISO(v.anchor) }, { "If-Match": `"${tn.version}"` });
      toast(t("Billing anchor saved"));
      refresh();
    });
  }

  async function moveRegion() {
    const regions = (await api("GET", "/v1/regions")).items || [];
    const others = regions.filter((r) => r !== tn.region);
    formDialog(t("Move region"), [
      regions.length
        ? { name: "region", label: t("New region"), type: "select", options: others.map((r) => [r, r]), value: others[0] }
        : { name: "region", label: t("New region"), required: true, placeholder: "eu-west" },
    ], t("Move"), async (v) => {
      if (!v.region) throw new Error(t("Choose a region."));
      await api("POST", `/v1/tenants/${tn.id}/move`, { region: v.region });
      toast(t("Moved to {region}", { region: v.region }));
      refresh();
    });
    document.querySelector("#dialog-form .fields").prepend(h("p", { class: "notice warn" },
      t("Currently in {region}. Moving records the new region and emits tenant.region_changed; subscribers migrate the data.", { region: tn.region || "—" })));
  }

  async function members() {
    return view(() => api("GET", `/v1/tenants/${tn.id}/members`), (res) => {
      const roleOpts = res.roles.map((r) => [r, r]);
      const invite = h("button", { class: "primary", onclick: () => formDialog(t("Add member"), [
        { name: "email", label: t("Email"), type: "email", required: true },
        { name: "role", label: t("Role"), type: "select", options: roleOpts, value: "member" },
        { name: "name", label: t("Name"), help: t("Used if this email has no account yet; the person then gets an invitation email.") },
      ], t("Add"), async (v) => {
        const m = await api("POST", `/v1/tenants/${tn.id}/members`, { email: v.email, role: v.role, name: v.name || undefined });
        toast(m.status === "invited" ? t("Invitation sent") : t("Member added")); renderTab();
      }) }, t("Add member"));
      return h("div", { class: "stack" }, h("div", {}, invite), table([
        { label: t("Email"), render: (m) => m.email },
        { label: t("Role"), render: (m) => m.role },
        { label: t("Status"), render: (m) => statusBadge(m.status) },
        { label: t("User"), render: (m) => h("span", { class: "mono muted" }, m.user_id || "—") },
        { label: "", render: (m) => h("div", { class: "toolbar" },
          h("button", { onclick: () => formDialog(t("Change role"), [{ name: "role", label: t("Role"), type: "select", options: roleOpts, value: m.role }], t("Save"),
            async (v) => { await api("PATCH", `/v1/tenants/${tn.id}/members/${m.id}`, { role: v.role }); toast(t("Role updated")); renderTab(); }) }, t("Role")),
          h("button", { class: "danger", onclick: () => confirmDialog(t("Remove member"), t("Remove {email}?", { email: m.email }), t("Remove"),
            async () => { await api("DELETE", `/v1/tenants/${tn.id}/members/${m.id}`); toast(t("Member removed")); renderTab(); }) }, t("Remove"))) },
      ], res.items));
    });
  }

  // roles shows built-in and custom roles plus groups, whose members hold the group's roles.
  async function roles() {
    const base = `/v1/tenants/${tn.id}`;
    const [r, g, a, m] = await Promise.all([
      optional(() => api("GET", `${base}/roles`)), optional(() => api("GET", `${base}/groups`)),
      optional(() => api("GET", "/v1/actions")), optional(() => api("GET", `${base}/members`))]);
    if (r.denied) return deniedNote();
    if (!r.data) return h("div");
    const allActions = a.data?.items || [];
    const roleList = r.data.items || [];
    const memberList = m.data?.items || [];
    const emailOf = (mid) => memberList.find((x) => x.id === mid)?.email || mid;

    const editRole = (role) => formDialog(role ? t("Edit role {name}", { name: role.name }) : t("New role"), [
      ...(role ? [] : [{ name: "name", label: t("Name"), required: true, placeholder: t("e.g. billing"), help: t("Built-in role names are reserved.") }]),
      { name: "description", label: t("Description"), value: role?.description },
      { name: "actions", label: t("Actions"), type: "checks", mono: true, options: allActions.map((x) => [x, x]), value: (role?.actions || []).filter((x) => allActions.includes(x)) },
      { name: "patterns", label: t("Patterns"), value: (role?.actions || []).filter((x) => !allActions.includes(x)).join(", "), placeholder: "members:*, webhooks:read",
        help: t("Extra glob patterns over the actions, comma separated. You can only grant actions you hold yourself.") },
    ], t("Save"), async (v) => {
      const actions = [...v.actions, ...splitList(v.patterns)];
      if (!actions.length) throw new Error(t("Choose at least one action."));
      const name = role ? role.name : v.name.trim();
      await api("PUT", `${base}/roles/${encodeURIComponent(name)}`, { description: v.description, actions });
      toast(t("Role saved")); renderTab();
    });
    const roleNames = roleList.map((x) => x.name);
    const editGroup = (grp) => formDialog(grp ? t("Edit group {name}", { name: grp.name }) : t("New group"), [
      { name: "name", label: t("Name"), required: true, value: grp?.name },
      { name: "description", label: t("Description"), value: grp?.description },
      { name: "roles", label: t("Roles"), type: "checks", options: roleNames.map((x) => [x, x]), value: grp?.roles || [] },
    ], t("Save"), async (v) => {
      const req = { name: v.name, description: v.description, roles: v.roles };
      if (grp) await api("PATCH", `${base}/groups/${encodeURIComponent(grp.id)}`, req);
      else await api("POST", `${base}/groups`, req);
      toast(t("Group saved")); renderTab();
    });
    const groupMembers = (grp) => formDialog(t("Members of {name}", { name: grp.name }), [
      { name: "members", label: t("Members"), type: "checks", options: memberList.map((x) => [x.id, x.email]), value: grp.members || [] },
    ], t("Save"), async (v) => {
      const before = new Set(grp.members || []);
      const after = new Set(v.members);
      const gpath = `${base}/groups/${encodeURIComponent(grp.id)}/members`;
      for (const mid of after) if (!before.has(mid)) await api("PUT", `${gpath}/${encodeURIComponent(mid)}`);
      for (const mid of before) if (!after.has(mid)) await api("DELETE", `${gpath}/${encodeURIComponent(mid)}`);
      toast(t("Group members saved")); renderTab();
    });

    const preview = (list) => {
      const shown = (list || []).slice(0, 8);
      return h("div", { class: "chips" }, shown.map((x) => h("span", { class: "chip mono" }, x)),
        list?.length > shown.length ? h("span", { class: "muted small" }, t("+{n} more", { n: list.length - shown.length })) : null);
    };
    const groups = g.denied ? deniedNote() : !g.data ? h("div") : table([
      { label: t("Group"), render: (x) => h("div", {}, h("strong", {}, x.name), x.description ? h("div", { class: "muted small" }, x.description) : null) },
      { label: t("Roles"), render: (x) => chipList(x.roles) },
      { label: t("Members"), render: (x) => (x.members?.length ? chipList(x.members.map(emailOf)) : dash()) },
      { label: "", render: (x) => h("div", { class: "toolbar" },
        h("button", { onclick: () => groupMembers(x) }, t("Members")),
        h("button", { onclick: () => editGroup(x) }, t("Edit")),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Delete group"), t("Delete the group {name}? Its members lose the group's roles.", { name: x.name }), t("Delete"),
          async () => { await api("DELETE", `${base}/groups/${encodeURIComponent(x.id)}`); toast(t("Group deleted")); renderTab(); }) }, t("Delete"))) },
    ], g.data.items || []);

    return h("div", { class: "stack" },
      h("div", { class: "page-head", style: "margin:0" }, h("h2", { style: "margin:0" }, t("Roles")),
        allActions.length ? h("button", { class: "primary", onclick: () => editRole() }, t("New role")) : null),
      table([
        { label: t("Role"), render: (x) => h("div", {}, h("strong", { class: "mono" }, x.name), " ", x.built_in ? badge(t("built-in"), "") : badge(t("custom"), "invited"),
          x.description ? h("div", { class: "muted small" }, x.description) : null) },
        { label: t("Actions"), render: (x) => preview(x.actions) },
        { label: "", render: (x) => (x.built_in ? null : h("div", { class: "toolbar" },
          h("button", { onclick: () => editRole(x) }, t("Edit")),
          h("button", { class: "danger", onclick: () => confirmDialog(t("Delete role"), t("Delete the role {name}? Roles still in use by members, groups or API keys cannot be deleted.", { name: x.name }), t("Delete"),
            async () => { await api("DELETE", `${base}/roles/${encodeURIComponent(x.name)}`); toast(t("Role deleted")); renderTab(); }) }, t("Delete")))) },
      ], roleList),
      h("div", { class: "page-head", style: "margin:8px 0 0" }, h("h2", { style: "margin:0" }, t("Groups")),
        g.data ? h("button", { class: "primary", onclick: () => editGroup() }, t("New group")) : null),
      groups);
  }

  async function usage() {
    return view(() => api("GET", `/v1/tenants/${tn.id}/usage`), (res) => {
      if (!res.items.length) return h("div", { class: "card empty" }, t("No metered usage or limits."));
      return h("div", { class: "grid two" }, res.items.map((u) => {
        const pct = u.limit ? Math.min(100, (u.value / Math.max(u.limit, 1)) * 100) : 0;
        return h("div", { class: "card" },
          h("div", { class: "page-head", style: "margin:0" }, h("strong", { class: "mono" }, u.metric),
            h("span", { class: "muted" }, u.limit !== undefined ? `${num(u.value)} / ${num(u.limit)}` : t("{value} (unlimited)", { value: num(u.value) }))),
          u.limit !== undefined ? h("div", { class: `meter ${pct >= 100 ? "full" : pct >= 80 ? "high" : ""}`, role: "meter", "aria-label": u.metric,
            "aria-valuemin": "0", "aria-valuemax": String(u.limit), "aria-valuenow": String(u.value) }, h("span", { style: `width:${pct}%` })) : null,
          u.period ? h("div", { class: "muted small", style: "margin-top:6px" }, t("Period {period}", { period: u.period }),
            u.period_end ? ` · ${t("resets {time}", { time: fmtTime(u.period_end) })}` : "",
            u.overage ? " · " : "", u.overage ? badge(t("over the limit"), "failed") : null) : null);
      }));
    });
  }

  async function children() {
    const res = await optional(() => api("GET", `/v1/tenants/${tn.id}/children`));
    if (res.denied) return deniedNote();
    return h("div", { class: "stack" },
      h("div", {}, h("button", { class: "primary", onclick: () => createTenant(tn.id) }, t("New child tenant"))),
      table([
        { label: t("Tenant"), render: (c) => [h("strong", { class: "block" }, c.name), h("span", { class: "block muted mono" }, c.slug)] },
        { label: t("Status"), render: (c) => statusBadge(c.status) },
        { label: t("Plan"), render: (c) => c.plan || "—" },
      ], res.data?.items || [], { href: (c) => `#/tenant/${c.id}` }));
  }

  async function events() {
    const box = h("div");
    await eventList(box, { tenant_id: tn.id });
    return box;
  }

  renderTab();
}

function cloneTenant(tn) {
  formDialog(t("Clone {name}", { name: tn.name }), [
    { name: "name", label: t("Name"), required: true, value: t("{name} (copy)", { name: tn.name }) },
    { name: "slug", label: t("Slug"), required: true, value: `${tn.slug}-copy` },
    { name: "parent_id", label: t("Parent tenant"), value: tn.parent_id || "", placeholder: t("ID or slug (optional)") },
    { name: "members", label: t("Also add the active members"), type: "checkbox" },
  ], t("Clone"), async (v) => {
    const c = await api("POST", `/v1/tenants/${tn.id}/clone`, { name: v.name, slug: v.slug, parent_id: v.parent_id || undefined, members: v.members });
    toast(t("Tenant {slug} created", { slug: c.slug }));
    location.hash = `#/tenant/${c.id}`;
  });
  document.querySelector("#dialog-form .fields").prepend(h("p", { class: "muted small" },
    t("Copies the plan, add-ons, region, labels, settings, overrides, branding and custom roles. Domains, SSO, API keys, webhooks and usage are not copied.")));
}

function editTenant(tn, done) {
  formDialog(t("Edit {slug}", { slug: tn.slug }), [
    { name: "name", label: t("Name"), value: tn.name },
    { name: "plan", label: t("Plan"), type: "select", options: planOptions(tn.plan), value: tn.plan || "" },
    { name: "labels", label: t("Labels (replaces all)"), type: "textarea", value: formatKV(tn.labels) },
    { name: "settings", label: t("Settings merge patch (JSON)"), type: "textarea", placeholder: '{"theme": {"color": "blue"}, "obsolete": null}' },
    { name: "features", label: t("Feature overrides (JSON)"), type: "textarea", value: JSON.stringify(tn.features || {}) },
    { name: "limits", label: t("Limit overrides (JSON)"), type: "textarea", value: JSON.stringify(tn.limits || {}) },
  ], t("Save"), async (v) => {
    const body = { name: v.name, labels: parseKV(v.labels) };
    if ((v.plan || "") !== (tn.plan || "")) body.plan = v.plan;
    const settings = parseJSON(v.settings, t("Settings"));
    if (settings) body.settings = settings;
    const features = parseJSON(v.features, t("Features")) || {};
    const limits = parseJSON(v.limits, t("Limits")) || {};
    if (JSON.stringify(features) !== JSON.stringify(tn.features || {})) body.features = features;
    if (JSON.stringify(limits) !== JSON.stringify(tn.limits || {})) body.limits = limits;
    await api("PATCH", `/v1/tenants/${tn.id}`, body, { "If-Match": `"${tn.version}"` });
    toast(t("Saved"));
    done();
  });
}

// ---- plans -------------------------------------------------------------------

async function plansPage() {
  const plans = await loadPlans();
  page(t("Plans"), [h("button", { class: "primary", onclick: () => editPlan() }, t("New plan"))],
    table([
      { label: t("Plan"), render: (p) => h("div", {}, h("strong", {}, p.name), h("div", { class: "muted mono" }, p.id)) },
      { label: t("Features"), render: (p) => h("div", { class: "chips" }, Object.entries(p.features || {}).map(([k, on]) => badge(k, on ? "ok" : ""))) },
      { label: t("Limits"), render: (p) => chips(p.limits) },
      { label: t("Version"), render: (p) => h("span", { class: "muted" }, String(p.version)) },
      { label: "", render: (p) => h("div", { class: "toolbar" },
        act(t("Revisions"), "", () => planRevisions(p)),
        h("button", { onclick: () => editPlan(p) }, t("Edit")),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Delete plan"), t("Delete plan {id}? Plans in use cannot be deleted.", { id: p.id }), t("Delete"),
          async () => { await api("DELETE", `/v1/plans/${p.id}`); toast(t("Plan deleted")); plansPage(); }) }, t("Delete"))) },
    ], plans));
}

async function planRevisions(p) {
  const res = await api("GET", `/v1/plans/${encodeURIComponent(p.id)}/revisions`);
  infoDialog(t("Revisions of {plan}", { plan: p.name }),
    h("p", { class: "muted small" }, t("Snapshots of the plan's features and limits, newest first. Tenants can be pinned to one from their overview.")),
    table([
      { label: t("Revision"), render: (r) => h("strong", { class: "mono" }, `r${r.revision}`) },
      { label: t("Created"), render: (r) => h("span", { class: "muted small" }, fmtTime(r.created_at)) },
      { label: t("Features"), render: (r) => h("div", { class: "chips" }, Object.entries(r.features || {}).map(([k, on]) => badge(k, on ? "ok" : ""))) },
      { label: t("Limits"), render: (r) => chips(r.limits) },
    ], res.items || []));
}

function editPlan(p) {
  formDialog(p ? t("Edit plan {id}", { id: p.id }) : t("New plan"), [
    ...(p ? [] : [{ name: "id", label: t("ID"), required: true, help: t("Stable identifier, e.g. pro") }]),
    { name: "name", label: t("Name"), value: p?.name, required: true },
    { name: "description", label: t("Description"), value: p?.description },
    { name: "features", label: t("Features (JSON)"), type: "textarea", value: JSON.stringify(p?.features || { sso: false }, null, 2) },
    { name: "limits", label: t("Limits (JSON)"), type: "textarea", value: JSON.stringify(p?.limits || { members: 5 }, null, 2) },
    ...(p ? [{ name: "grandfather", label: t("Grandfather current tenants"), type: "checkbox",
      help: t("Pin the tenants on this plan to its current revision, so the change only affects new subscribers.") }] : []),
  ], p ? t("Save") : t("Create"), async (v) => {
    const body = { name: v.name, description: v.description, features: parseJSON(v.features, t("Features")) || {}, limits: parseJSON(v.limits, t("Limits")) || {} };
    if (p) await api("PATCH", `/v1/plans/${p.id}`, { ...body, grandfather: v.grandfather || undefined }, { "If-Match": `"${p.version}"` });
    else await api("POST", "/v1/plans", { id: v.id, ...body });
    toast(t("Plan saved"));
    plansPage();
  });
}

// ---- tenant templates ---------------------------------------------------------------

async function templatesPage() {
  const { data, off, denied } = await optional(() => api("GET", "/v1/tenant-templates"));
  if (denied || off) {
    page(t("Tenant templates"), [], denied ? deniedNote() : note(t("Tenant templates are not available: {reason}", { reason: off })));
    return;
  }
  if (!data) return;
  await loadPlans();
  const regions = (await optional(() => api("GET", "/v1/regions"))).data?.items || [];
  const tpath = (id) => `/v1/tenant-templates/${encodeURIComponent(id)}`;
  const pretty = (v) => (v && Object.keys(v).length ? JSON.stringify(v, null, 2) : "");

  const edit = (x) => formDialog(x ? t("Edit template {name}", { name: x.name || x.id }) : t("New template"), [
    ...(x ? [] : [{ name: "id", label: t("ID"), required: true, placeholder: "startup", help: t("Stable identifier used when creating tenants.") }]),
    { name: "name", label: t("Name"), required: true, value: x?.name },
    { name: "description", label: t("Description"), value: x?.description },
    { name: "plan", label: t("Plan"), type: "select", options: planOptions(x?.plan), value: x?.plan || "" },
    { name: "add_ons", label: t("Add-on plans"), type: "checks", options: plansCache.map((p) => [p.id, `${p.name} (${p.id})`]), value: x?.add_ons || [] },
    regions.length
      ? { name: "region", label: t("Region"), type: "select", options: [["", t("— none —")], ...regions.map((r) => [r, r])], value: x?.region || "" }
      : { name: "region", label: t("Region"), value: x?.region },
    { name: "labels", label: t("Labels"), type: "textarea", value: formatKV(x?.labels), placeholder: "tier=startup" },
    { name: "settings", label: t("Settings (JSON)"), type: "textarea", value: pretty(x?.settings), placeholder: "{}" },
    { name: "features", label: t("Feature overrides (JSON)"), type: "textarea", value: pretty(x?.features), placeholder: '{"sso": true}' },
    { name: "limits", label: t("Limit overrides (JSON)"), type: "textarea", value: pretty(x?.limits), placeholder: '{"members": 20}' },
    { name: "branding", label: t("Branding (JSON)"), type: "textarea", value: pretty(x?.branding), placeholder: '{"primary_color": "#4f46e5"}' },
    { name: "roles", label: t("Custom roles (JSON)"), type: "textarea", value: x?.roles?.length ? JSON.stringify(x.roles, null, 2) : "",
      placeholder: '[{"name": "billing", "actions": ["usage:read"]}]', help: t("Created in every tenant made from the template.") },
  ], t("Save"), async (v) => {
    const roles = parseJSON(v.roles, t("Custom roles")) || [];
    if (!Array.isArray(roles)) throw new Error(t("{what} must be valid JSON", { what: t("Custom roles") }));
    await api("PUT", tpath(x ? x.id : v.id.trim()), {
      name: v.name, description: v.description, plan: v.plan || undefined, add_ons: v.add_ons, region: v.region || undefined,
      labels: parseKV(v.labels), settings: parseJSON(v.settings, t("Settings")), features: parseJSON(v.features, t("Features")),
      limits: parseJSON(v.limits, t("Limits")), branding: parseJSON(v.branding, t("Branding")), roles,
    });
    toast(t("Template saved"));
    templatesPage();
  });

  page(t("Tenant templates"), [h("button", { class: "primary", onclick: () => edit() }, t("New template"))],
    h("p", { class: "muted" }, t("Starting points for new tenants: plan, placement, settings, branding and roles in one choice.")),
    table([
      { label: t("Template"), render: (x) => h("div", {}, h("strong", {}, x.name || x.id), h("div", { class: "muted mono small" }, x.id),
        x.description ? h("div", { class: "muted small" }, x.description) : null) },
      { label: t("Plan"), render: (x) => h("div", {}, x.plan || "—", x.add_ons?.length ? chipList(x.add_ons, "chip mono") : null) },
      { label: t("Region"), render: (x) => x.region || "—" },
      { label: t("Labels"), render: (x) => chips(x.labels) },
      { label: t("Roles"), render: (x) => (x.roles?.length ? chipList(x.roles.map((r) => r.name), "chip mono") : dash()) },
      { label: "", render: (x) => h("div", { class: "toolbar" },
        h("button", { onclick: () => edit(x) }, t("Edit")),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Delete template"), t("Delete the template {name}? Tenants made from it are not changed.", { name: x.name || x.id }), t("Delete"),
          async () => { await api("DELETE", tpath(x.id)); toast(t("Template deleted")); templatesPage(); }) }, t("Delete"))) },
    ], data.items || []));
}

// ---- rollouts ----------------------------------------------------------------------

async function rolloutsPage() {
  const { data, off, denied } = await optional(() => api("GET", "/v1/rollouts"));
  if (denied || off) {
    page(t("Feature rollouts"), [], denied ? deniedNote() : note(t("Feature rollouts are not available: {reason}", { reason: off })));
    return;
  }
  if (!data) return;
  await loadPlans();
  const regions = (await optional(() => api("GET", "/v1/regions"))).data?.items || [];
  const features = [...new Set(plansCache.flatMap((p) => Object.keys(p.features || {})))].sort();
  const rpath = (f) => `/v1/rollouts/${encodeURIComponent(f)}`;
  const spec = (r) => ({ percentage: r.percentage || 0, plans: r.plans || [], labels: r.labels || {}, regions: r.regions || [],
    include: r.include || [], exclude: r.exclude || [], enabled: Boolean(r.enabled) });

  const edit = (r) => formDialog(r ? t("Edit rollout of {feature}", { feature: r.feature }) : t("New rollout"), [
    ...(r ? [] : [{ name: "feature", label: t("Feature"), required: true, list: features, placeholder: "new_editor" }]),
    { name: "percentage", label: t("Share of matching tenants"), type: "range", min: 0, max: 100, value: r?.percentage ?? 10, unit: "%",
      help: t("Stable per tenant: raising it only adds tenants.") },
    { name: "plans", label: t("Plans"), type: "checks", options: plansCache.map((p) => [p.id, p.name]), value: r?.plans || [], help: t("None means every plan.") },
    { name: "labels", label: t("Labels"), type: "textarea", value: formatKV(r?.labels), placeholder: "tier=beta", help: t("Tenants must carry all of these labels.") },
    regions.length
      ? { name: "regions", label: t("Regions"), type: "checks", options: regions.map((x) => [x, x]), value: r?.regions || [], help: t("None means every region.") }
      : { name: "regions", label: t("Regions"), value: (r?.regions || []).join(", "), placeholder: "eu, us", help: t("Comma separated; empty means every region.") },
    { name: "include", label: t("Always include"), type: "textarea", value: (r?.include || []).join("\n"), placeholder: t("Tenant IDs, one per line") },
    { name: "exclude", label: t("Always exclude"), type: "textarea", value: (r?.exclude || []).join("\n"), placeholder: t("Tenant IDs, one per line") },
    { name: "enabled", label: t("Enabled"), type: "checkbox", value: r ? r.enabled : true, help: t("Kill switch: turning it off removes the feature from every tenant of the rollout at once.") },
  ], t("Save"), async (v) => {
    const feature = r ? r.feature : v.feature.trim();
    await api("PUT", rpath(feature), {
      percentage: v.percentage, plans: v.plans, labels: parseKV(v.labels), regions: Array.isArray(v.regions) ? v.regions : splitList(v.regions),
      include: splitWords(v.include), exclude: splitWords(v.exclude), enabled: v.enabled,
    });
    toast(t("Rollout saved"));
    rolloutsPage();
  });

  page(t("Feature rollouts"), [h("button", { class: "primary", onclick: () => edit() }, t("New rollout"))],
    h("p", { class: "muted" }, t("Turn a feature on for a stable share of the matching tenants. A tenant's own feature override always wins.")),
    table([
      { label: t("Feature"), render: (r) => h("strong", { class: "mono" }, r.feature) },
      { label: t("Rollout"), render: (r) => h("div", { class: "rollout-pct" }, h("span", {}, `${r.percentage || 0}%`),
        h("div", { class: "meter", role: "meter", "aria-label": t("Rollout"), "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(r.percentage || 0) },
          h("span", { style: `width:${r.percentage || 0}%` }))) },
      { label: t("Targeting"), render: (r) => (r.plans?.length || r.regions?.length || Object.keys(r.labels || {}).length
        ? h("div", { class: "stack tight" },
          r.plans?.length ? h("div", {}, h("span", { class: "muted small" }, `${t("Plans")}: `), chipList(r.plans)) : null,
          r.regions?.length ? h("div", {}, h("span", { class: "muted small" }, `${t("Regions")}: `), chipList(r.regions)) : null,
          Object.keys(r.labels || {}).length ? chips(r.labels) : null)
        : h("span", { class: "muted" }, t("all tenants"))) },
      { label: t("Include / exclude"), render: (r) => h("span", { class: "muted" }, `+${r.include?.length || 0} / −${r.exclude?.length || 0}`) },
      { label: t("Status"), render: (r) => (r.enabled ? badge(t("on"), "ok") : badge(t("off"), "failed")) },
      { label: t("Updated"), render: (r) => h("span", { class: "muted small" }, fmtTime(r.updated_at)) },
      { label: "", render: (r) => h("div", { class: "toolbar" },
        h("button", { onclick: () => edit(r) }, t("Edit")),
        act(r.enabled ? t("Turn off") : t("Turn on"), r.enabled ? "danger" : "", async () => {
          await api("PUT", rpath(r.feature), { ...spec(r), enabled: !r.enabled });
          toast(r.enabled ? t("Rollout turned off") : t("Rollout turned on"));
          rolloutsPage();
        }),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Delete rollout"), t("Delete the rollout of {feature}? Tenants keep the feature only through their plan or overrides.", { feature: r.feature }), t("Delete"),
          async () => { await api("DELETE", rpath(r.feature)); toast(t("Rollout deleted")); rolloutsPage(); }) }, t("Delete"))) },
    ], data.items || []));
}

// ---- events --------------------------------------------------------------------

async function eventList(container, filter = {}) {
  let after = 0;
  const tbody = h("tbody");
  const table = h("div", { class: "card table-wrap", style: "padding:0" }, h("table", {},
    h("thead", {}, h("tr", {}, [t("Seq"), t("Type"), t("Tenant"), t("Actor"), t("Time"), ""].map((c) => h("th", {}, c)))), tbody));
  const empty = h("tr", {}, h("td", { colspan: 6, class: "empty" }, t("No events yet.")));
  container.replaceChildren(table);

  // eventRows renders an event and its (hidden) detail row.
  const eventRows = (e) => {
    const detail = h("tr", { hidden: true }, h("td", { colspan: 6 }, eventDetail(e)));
    const toggle = detailToggle(detail, String(e.seq));
    return [
      clickableRow(toggle,
        h("td", { class: "mono" }, toggle),
        h("td", {}, badge(e.type, "")),
        h("td", {}, e.tenantid ? h("a", { href: `#/tenant/${e.tenantid}`, class: "mono" }, e.tenantid.slice(0, 8)) : "—"),
        h("td", { class: "muted" }, e.actor || ""),
        h("td", { class: "muted" }, fmtTime(e.time)),
        h("td", { class: "muted small" }, t("details"))),
      detail,
    ];
  };

  // poll adds new events at the top, newest first, keeping the rows already shown
  // (and so their open details and keyboard focus); at most 500 events stay.
  async function poll() {
    const fresh = [];
    for (;;) {
      const q = new URLSearchParams({ after: String(after), limit: "500", ...filter });
      const res = await guard(() => api("GET", `/v1/events?${q}`));
      if (!res) break;
      fresh.push(...res.items);
      if (res.items.length) after = res.items[res.items.length - 1].seq;
      if (!res.next) break;
      after = Number(res.next);
    }
    if (fresh.length) {
      empty.remove();
      tbody.prepend(...fresh.slice(-500).reverse().flatMap(eventRows));
      while (tbody.children.length > 1000) tbody.lastElementChild.remove();
    }
    if (!tbody.children.length) tbody.append(empty);
  }
  // The timer is registered before the first poll, so leaving the page while it
  // loads stops it too; a tick is skipped while a slow poll is still running.
  let busy = false;
  const tick = async () => {
    if (busy) return;
    busy = true;
    try { await poll(); } finally { busy = false; }
  };
  const timer = setInterval(tick, 3000);
  stopPolling = () => clearInterval(timer);
  await tick();
}

async function eventsPage() {
  const type = h("input", { type: "search", placeholder: t("Type filter, e.g. tenant.*"), "aria-label": t("Type filter, e.g. tenant.*") });
  const box = h("div");
  type.addEventListener("change", () => { stopPolling(); eventList(box, type.value ? { type: type.value } : {}); });
  page(t("Events"), [type, h("span", { class: "muted small" }, t("Live, refreshes every 3s")), h("a", { href: "#/event-schemas", class: "small" }, t("Event schemas"))], box);
  eventList(box);
}

// ---- event schemas ------------------------------------------------------------------

async function eventSchemasPage() {
  const { data, off, denied } = await optional(() => api("GET", "/v1/event-schemas"));
  if (!data) {
    if (off || denied) page(t("Event schemas"), [], denied ? deniedNote() : note(off));
    return;
  }
  const filter = h("input", { type: "search", placeholder: t("Filter by type"), "aria-label": t("Filter by type") });
  const tbody = h("tbody");
  page(t("Event schemas"), [filter, h("button", { onclick: () => infoDialog(t("CloudEvents envelope"), json(data.envelope || {})) }, t("Envelope"))],
    h("p", { class: "muted" }, t("JSON Schemas of each event type's data. Additive changes keep the version; breaking changes publish a new version next to the old one.")),
    h("div", { class: "card table-wrap", style: "padding:0" }, h("table", {},
      h("thead", {}, h("tr", {}, [t("Type"), t("Version"), t("Description")].map((c) => h("th", {}, c)))), tbody)));
  const render = () => {
    const q = filter.value.trim().toLowerCase();
    const rows = (data.items || []).filter((s) => !q || s.type.toLowerCase().includes(q))
      .sort((a, b) => a.type.localeCompare(b.type) || String(a.version).localeCompare(String(b.version)));
    tbody.replaceChildren(...rows.map((s) => {
      const detail = h("tr", { hidden: true }, h("td", { colspan: 3 }, json(s.schema || {})));
      const toggle = detailToggle(detail, badge(s.type, ""));
      return [clickableRow(toggle,
        h("td", {}, toggle),
        h("td", { class: "mono" }, s.version || ""),
        h("td", { class: "muted" }, s.description || "")), detail];
    }).flat());
    if (!rows.length) tbody.replaceChildren(h("tr", {}, h("td", { colspan: 3, class: "empty" }, t("No matching event types."))));
  };
  filter.addEventListener("input", render);
  render();
}

// ---- audit ---------------------------------------------------------------------------

// auditView renders filters and a newest-first audit table over path; platform adds
// the tenant and until filters of /v1/audit.
async function auditView(path, platform) {
  const input = (name, placeholder, type = "text") => h("input", { name, placeholder, type, "aria-label": placeholder });
  const f = {
    ...(platform ? { tenant_id: input("tenant_id", t("Tenant ID or slug")) } : {}),
    actor: input("actor", t("Actor, e.g. system:scheduler")),
    type: input("type", t("Types, e.g. tenant.*, member.added")),
    since: input("since", t("Since"), "datetime-local"),
    ...(platform ? { until: input("until", t("Until"), "datetime-local") } : {}),
  };
  const dateLabel = (name) => h("label", { class: "inline" }, name === "since" ? t("Since") : t("Until"), f[name]);
  const form = h("form", { class: "toolbar filters", onsubmit: (e) => { e.preventDefault(); load().catch(fail); } },
    Object.keys(f).map((k) => (["since", "until"].includes(k) ? dateLabel(k) : f[k])),
    h("button", { type: "submit", class: "primary" }, t("Search")));
  const tbody = h("tbody");
  const older = h("button", { hidden: true, onclick: () => guard(() => load(older.dataset.next)) }, t("Older"));
  const box = h("div", { class: "stack" });

  async function load(before) {
    const q = new URLSearchParams({ limit: "100" });
    for (const k of ["tenant_id", "actor"]) if (f[k]?.value.trim()) q.set(k, f[k].value.trim());
    for (const ty of splitList(f.type.value)) q.append("type", ty);
    for (const k of ["since", "until"]) if (f[k]?.value) q.set(k, toISO(f[k].value));
    if (before) q.set("before", before);
    const res = await api("GET", `${path}?${q}`);
    if (!before) tbody.replaceChildren();
    for (const e of res.items) {
      const detail = h("tr", { hidden: true }, h("td", { colspan: 5 }, eventDetail(e)));
      const toggle = detailToggle(detail, fmtTime(e.time));
      tbody.append(clickableRow(toggle,
        h("td", { class: "muted" }, toggle),
        h("td", {}, badge(e.type, "")),
        h("td", { class: "mono small" }, e.actor || "—"),
        h("td", {}, e.tenantid ? h("a", { href: `#/tenant/${e.tenantid}`, class: "mono" }, e.tenantid.slice(0, 8)) : "—"),
        h("td", { class: "mono muted small" }, String(e.seq))), detail);
    }
    if (!tbody.children.length) tbody.append(h("tr", {}, h("td", { colspan: 5, class: "empty" }, t("No matching events."))));
    older.dataset.next = res.next || "";
    older.hidden = !res.next;
  }
  // fail swaps the view for a permission note on 403 and toasts other errors.
  function fail(e) {
    if (e.status === 403) box.replaceChildren(deniedNote());
    else if (e.status !== 401) toast(e.message, true);
  }
  box.append(form,
    h("div", { class: "card table-wrap", style: "padding:0" }, h("table", {},
      h("thead", {}, h("tr", {}, [t("Time"), t("Type"), t("Actor"), t("Tenant"), t("Seq")].map((c) => h("th", {}, c)))), tbody)),
    h("p", {}, older));
  await load().catch(fail);
  return box;
}

async function auditPage() {
  const loading = h("p", { class: "muted" }, t("Loading…"));
  page(t("Audit"), [h("span", { class: "muted small" }, t("Every change with its actor, newest first"))], loading);
  const v = await auditView("/v1/audit", true);
  if (loading.isConnected) loading.replaceWith(v);
}

// ---- oauth clients (OpenID provider) ------------------------------------------------------

const oauthScopes = ["openid", "profile", "email", "offline_access"];

async function oauthClientsPage() {
  const { data, off, denied } = await optional(() => api("GET", "/v1/oauth-clients"));
  if (denied || off) {
    page(t("OAuth clients"), [], denied ? deniedNote() : note(t("The OpenID provider is not available: {reason}", { reason: off })));
    return;
  }
  if (!data) return;
  const cpath = (c) => `/v1/oauth-clients/${encodeURIComponent(c.client_id)}`;
  const lines = (s) => s.split(/\n/).map((x) => x.trim()).filter(Boolean);
  const showSecret = (title, clientId, secret) => setTimeout(() => secretDialog(title,
    secret ? t("Copy the client secret now. It is not shown again.") : t("Public client: there is no secret; the app must use PKCE."), [],
    h("dl", { class: "kv" }, h("dt", {}, t("Client ID")), h("dd", {}, copyable(clientId)),
      ...(secret ? [h("dt", {}, t("Client secret")), h("dd", {}, copyable(secret))] : []))));

  const edit = (c) => formDialog(c ? t("Edit {name}", { name: c.name }) : t("Register an application"), [
    { name: "name", label: t("Name"), required: true, value: c?.name },
    { name: "redirect_uris", label: t("Redirect URIs"), type: "textarea", value: (c?.redirect_uris || []).join("\n"), placeholder: "https://app.example.com/callback",
      help: t("One per line: https, loopback http or a private-use scheme.") },
    { name: "post_logout_redirect_uris", label: t("Post-logout redirect URIs"), type: "textarea", value: (c?.post_logout_redirect_uris || []).join("\n") },
    { name: "tenant_id", label: t("Tenant"), value: c?.tenant_id, placeholder: t("ID (optional)"), help: t("Scope every session of this app to one tenant.") },
    { name: "scopes", label: t("Scopes"), type: "checks", mono: true, options: oauthScopes.map((s) => [s, s]), value: c?.scopes || ["openid", "profile", "email"] },
    { name: "first_party", label: t("First-party app (skip the consent screen)"), type: "checkbox", value: c?.first_party },
    ...(c ? [] : [{ name: "public", label: t("Public client (no secret)"), type: "checkbox", help: t("For single-page and mobile apps; PKCE is required.") }]),
  ], c ? t("Save") : t("Register"), async (v) => {
    const req = { name: v.name, redirect_uris: lines(v.redirect_uris), post_logout_redirect_uris: lines(v.post_logout_redirect_uris),
      tenant_id: v.tenant_id.trim() || undefined, scopes: v.scopes, first_party: v.first_party };
    if (!req.redirect_uris.length) throw new Error(t("Give at least one redirect URI."));
    if (c) {
      await api("PUT", cpath(c), req);
      toast(t("Application saved"));
      oauthClientsPage();
      return;
    }
    const res = await api("POST", "/v1/oauth-clients", { ...req, public: v.public });
    oauthClientsPage();
    showSecret(t("Application registered"), res.client.client_id, res.client_secret);
  });

  page(t("OAuth clients"), [
    h("a", { href: "/.well-known/openid-configuration", target: "_blank", rel: "noopener", class: "small" }, t("Discovery document")),
    h("button", { class: "primary", onclick: () => edit() }, t("Register an application"))],
  h("p", { class: "muted" }, t("Applications that sign users in through Tenarium (authorization code with PKCE).")),
  table([
    { label: t("Application"), render: (c) => h("div", {}, h("strong", {}, c.name), h("div", { class: "muted mono small" }, c.client_id)) },
    { label: t("Redirect URIs"), render: (c) => h("div", { class: "mono small" }, (c.redirect_uris || []).map((u) => h("div", {}, u))) },
    { label: t("Scopes"), render: (c) => chipList(c.scopes, "chip mono") },
    { label: t("Tenant"), render: (c) => (c.tenant_id ? h("a", { href: `#/tenant/${c.tenant_id}`, class: "mono" }, c.tenant_id.slice(0, 8)) : h("span", { class: "muted" }, t("any"))) },
    { label: t("Consent"), render: (c) => (c.first_party ? badge(t("first-party"), "ok") : badge(t("asks the user"), "")) },
    { label: "", render: (c) => h("div", { class: "toolbar" },
      h("button", { onclick: () => edit(c) }, t("Edit")),
      h("button", { onclick: () => confirmDialog(t("Rotate secret"), t("Replace the client secret of {name}? The app must switch to the new one.", { name: c.name }), t("Rotate"),
        async () => { const res = await api("POST", `${cpath(c)}/rotate-secret`); showSecret(t("New client secret"), c.client_id, res.client_secret); }) }, t("Rotate secret")),
      h("button", { class: "danger", onclick: () => confirmDialog(t("Delete application"), t("Delete {name} and the consents users gave it? Its sign-ins stop working.", { name: c.name }), t("Delete"),
        async () => { await api("DELETE", cpath(c)); toast(t("Application deleted")); oauthClientsPage(); }) }, t("Delete"))) },
  ], data.items || []));
}

// ---- signing keys ----------------------------------------------------------------------

async function signingKeysPage() {
  const { data, off, denied } = await optional(() => api("GET", "/v1/signing-keys"));
  if (denied) { page(t("Signing keys"), [], deniedNote()); return; }
  if (!data && !off) return;
  const rotate = h("button", { class: "primary", hidden: Boolean(off), onclick: () => confirmDialog(t("Rotate signing key"),
    t("Add a new key that signs tokens from now on? Older keys keep verifying until their tokens expire."), t("Rotate"),
    async () => { await api("POST", "/v1/signing-keys/rotate"); toast(t("Signing key rotated")); signingKeysPage(); }) }, t("Rotate key"));
  page(t("Signing keys"), [h("a", { href: "/.well-known/jwks.json", target: "_blank", rel: "noopener", class: "small" }, "JWKS"), rotate],
    off ? note(t("Signing keys are not available: {reason}", { reason: off })) : table([
      { label: t("Key ID"), render: (k) => h("span", { class: "mono" }, k.kid) },
      { label: t("Algorithm"), render: (k) => k.alg },
      { label: t("Created"), render: (k) => h("span", { class: "muted" }, fmtTime(k.created_at)) },
      { label: t("Status"), render: (k) => (k.active ? badge(t("active"), "active") : badge(t("verifying only"), "")) },
      { label: "", render: (k) => (k.active ? null : h("button", { class: "danger", onclick: () => confirmDialog(t("Retire key"),
        t("Retire {kid} now? Tokens it signed stop working immediately.", { kid: k.kid }), t("Retire"),
        async () => { await api("DELETE", `/v1/signing-keys/${encodeURIComponent(k.kid)}`); toast(t("Key retired")); signingKeysPage(); }) }, t("Retire"))) },
    ], data.items || []));
}

// ---- account (signed-in user) --------------------------------------------------------------

async function accountPage() {
  let st;
  try {
    st = await api("GET", "/v1/me/mfa");
  } catch (e) {
    if (e.status === 401) return;
    page(t("Account"), [], note(e.code === "not_a_user" ? t("Account settings are only available to signed-in Tenarium users.") : e.message));
    return;
  }
  const loading = h("p", { class: "muted" }, t("Loading…"));
  const loadingSessions = h("span");
  page(t("Account"), [], h("div", { class: "grid two" }, mfaCard(st), loading, emailCard(), loadingSessions, consentCard(), dataCard()));
  const [pk, sessions] = await Promise.all([passkeysCard(), sessionsCard()]);
  if (loading.isConnected) loading.replaceWith(pk);
  if (loadingSessions.isConnected) loadingSessions.replaceWith(sessions);
}

function mfaCard(st) {
  const codeField = [{ name: "code", label: t("Code from your authenticator app"), required: true, placeholder: "123456" }];
  const showCodes = (r, title) => setTimeout(() => secretDialog(title, t("Store these recovery codes safely. Each works once and they are not shown again."),
    [], h("pre", {}, (r.recovery_codes || []).join("\n"))));
  const enroll = () => guard(async () => {
    const e = await api("POST", "/v1/me/mfa/totp");
    formDialog(t("Set up two-factor authentication"), codeField, t("Confirm"), async (v) => {
      const r = await api("POST", "/v1/me/mfa/totp/confirm", { code: v.code.trim() });
      toast(t("Two-factor authentication enabled"));
      showCodes(r, t("Recovery codes"));
      accountPage();
    });
    document.querySelector("#dialog-form .fields").prepend(
      h("p", {}, t("Add this account to your authenticator app with the secret or the otpauth URL, then enter the current code.")),
      h("span", { class: "muted small" }, t("Secret")), copyable(e.secret),
      h("span", { class: "muted small" }, t("otpauth URL")), copyable(e.otpauth_url));
  });
  const actions = st.enabled ? [
    h("button", { onclick: () => formDialog(t("New recovery codes"), codeField, t("Replace codes"), async (v) => {
      showCodes(await api("POST", "/v1/me/mfa/recovery-codes", { code: v.code.trim() }), t("New recovery codes"));
      accountPage();
    }) }, t("New recovery codes")),
    h("button", { class: "danger", onclick: () => formDialog(t("Turn off two-factor authentication"),
      [{ ...codeField[0], label: t("Authenticator or recovery code") }], t("Turn off"), async (v) => {
        await api("POST", "/v1/me/mfa/disable", { code: v.code.trim() });
        toast(t("Two-factor authentication disabled")); accountPage();
      }) }, t("Turn off")),
  ] : [h("button", { class: "primary", onclick: enroll }, st.pending ? t("Restart setup") : t("Set up"))];
  return h("div", { class: "card" },
    h("h2", {}, t("Two-factor authentication")),
    h("dl", { class: "kv" },
      h("dt", {}, t("Status")), h("dd", {}, st.enabled ? badge(t("enabled"), "ok") : st.pending ? badge(t("pending confirmation"), "invited") : badge(t("off"), "")),
      ...(st.enabled ? [h("dt", {}, t("Recovery codes left")), h("dd", {}, String(st.recovery_codes_left ?? 0))] : [])),
    h("div", { class: "toolbar", style: "margin-top:16px" }, actions));
}

async function passkeysCard() {
  const { data, denied } = await optional(() => api("GET", "/v1/me/passkeys"));
  const box = h("div", { class: "card" }, h("h2", {}, t("Passkeys")));
  if (denied || !data) {
    box.append(h("p", { class: "muted" }, t("Passkeys are not available for this session.")));
    return box;
  }
  const items = data.items || [];
  const add = act(t("Add a passkey"), "primary", registerPasskey);
  if (!passkeysSupported()) {
    add.disabled = true;
    add.title = t("This browser does not support passkeys.");
  }
  box.append(
    h("p", { class: "muted small" }, t("Sign in with your device's screen lock or a security key instead of a password and code.")),
    items.length ? h("ul", { class: "list" }, items.map((p) => h("li", {},
      h("div", {}, h("strong", {}, p.name || t("Passkey")),
        h("div", { class: "muted small" }, t("Added {time}", { time: fmtTime(p.created_at) }),
          p.last_used_at ? ` · ${t("last used {time}", { time: fmtTime(p.last_used_at) })}` : "")),
      h("button", { class: "danger", onclick: () => confirmDialog(t("Remove passkey"), t("Remove the passkey {name}? You can no longer sign in with it.", { name: p.name || p.id }), t("Remove"),
        async () => { await api("DELETE", `/v1/me/passkeys/${encodeURIComponent(p.id)}`); toast(t("Passkey removed")); accountPage(); }) }, t("Remove")))))
      : h("p", { class: "muted" }, t("No passkeys yet.")),
    h("div", { class: "toolbar", style: "margin-top:12px" }, add, passkeysSupported() ? null : h("span", { class: "muted small" }, t("This browser does not support passkeys."))));
  return box;
}

// registerPasskey starts the ceremony first, so the browser prompt opens straight from
// the dialog's submit (browsers want a recent user gesture for it).
async function registerPasskey() {
  let begin;
  try {
    begin = await api("POST", "/v1/me/passkeys/register/begin");
  } catch (e) {
    if (e.status === 404) throw new Error(t("Passkeys are not enabled on this server."));
    throw e;
  }
  formDialog(t("Add a passkey"), [{ name: "name", label: t("Name"), placeholder: t("e.g. Work laptop"), help: t("Helps you tell your passkeys apart.") }],
    t("Continue"), async (v) => {
      let cred;
      try {
        cred = await navigator.credentials.create(creationOptions(begin.options));
      } catch (e) {
        throw new Error(webauthnError(e));
      }
      await api("POST", "/v1/me/passkeys/register/finish", { ceremony: begin.ceremony, name: v.name.trim() || undefined, credential: credentialJSON(cred) });
      toast(t("Passkey added"));
      accountPage();
    });
}

// browserName shortens a User-Agent header to "Browser on OS" for session lists.
function browserName(ua) {
  if (!ua) return t("Unknown device");
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS"
    : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return browser && os ? t("{browser} on {os}", { browser, os }) : ua.slice(0, 60);
}

// sessionList renders signed-in clients with a sign-out button each.
function sessionList(items, revoke) {
  if (!items.length) return h("p", { class: "muted" }, t("No active sessions."));
  return h("ul", { class: "list" }, items.map((s) => h("li", {},
    h("div", {},
      h("strong", { title: s.user_agent || "" }, browserName(s.user_agent)),
      h("div", { class: "muted small" }, [s.ip, s.tenant_id ? t("tenant {name}", { name: s.tenant_id.slice(0, 8) }) : null,
        t("signed in {time}", { time: fmtTime(s.created_at) }), t("last used {time}", { time: fmtTime(s.last_used_at) })].filter(Boolean).join(" · "))),
    act(t("Sign out"), "danger", () => revoke(s)))));
}

async function sessionsCard() {
  const { data, denied } = await optional(() => api("GET", "/v1/me/sessions"));
  if (denied || !data) return "";
  return h("div", { class: "card" }, h("h2", {}, t("Sessions")),
    h("p", { class: "muted small" }, t("Browsers and devices signed in to your account, most recently used first.")),
    sessionList(data.items || [], async (s) => {
      await api("DELETE", `/v1/me/sessions/${encodeURIComponent(s.id)}`);
      toast(t("Session signed out"));
      accountPage();
    }));
}

function emailCard() {
  const email = me?.claims?.email;
  return h("div", { class: "card" }, h("h2", {}, t("Email address")),
    email ? h("p", { class: "mono" }, email) : null,
    act(t("Change email"), "", () => formDialog(t("Change email"), [
      { name: "email", label: t("New email"), type: "email", required: true },
      { name: "password", label: t("Current password"), type: "password", required: true },
    ], t("Send confirmation"), async (v) => {
      await api("POST", "/v1/me/email", { email: v.email.trim(), password: v.password });
      toast(t("Check {email} for a confirmation link.", { email: v.email.trim() }));
    })));
}

function consentCard() {
  return h("div", { class: "card" }, h("h2", {}, t("Support access")),
    h("p", { class: "muted small" }, t("Let platform support act as you for a while. Create a single-use code and give it to them; every action they take is recorded.")),
    act(t("Create consent code"), "", () => formDialog(t("Allow support access"), [
      { name: "ttl", label: t("Valid for"), placeholder: "1h", help: t("Default 1h, at most 24h.") },
    ], t("Create code"), async (v) => {
      const r = await api("POST", "/v1/me/impersonation-consent", v.ttl.trim() ? { ttl: v.ttl.trim() } : {});
      setTimeout(() => secretDialog(t("Consent code"), t("Give this code to support. It works once and expires {time}.", { time: fmtTime(r.expires_at) }), r.code));
    })));
}

function dataCard() {
  return h("div", { class: "card" }, h("h2", {}, t("Your data")),
    h("p", { class: "muted small" }, t("Download everything Tenarium stores about you as JSON.")),
    act(t("Download my data"), "", () => download("/v1/me/export", "my-data.json")));
}

// ---- dead letters -------------------------------------------------------------------

async function deadLettersPage() {
  const { data: res, denied } = await optional(() => api("GET", "/v1/dead-letters"));
  if (denied) { page(t("Dead letters"), [], deniedNote()); return; }
  if (!res) return;
  page(t("Dead letters"), [h("span", { class: "muted small" }, t("Undelivered events: {n}", { n: res.items.length })),
    act(t("Replay events"), "", () => replayEvents(res.subscriptions || []))],
    table([
      { label: t("Subscription"), render: (d) => h("span", { class: "mono" }, d.subscription) },
      { label: t("Event"), render: (d) => h("div", {}, badge(d.event.type, ""), h("div", { class: "muted mono small" }, `seq ${d.event.seq}`)) },
      { label: t("Error"), render: (d) => h("span", { class: "small" }, d.error) },
      { label: t("Failed"), render: (d) => h("span", { class: "muted" }, fmtTime(d.failed_at)) },
      { label: "", render: (d) => h("div", { class: "toolbar" },
        act(t("Replay"), "", async () => { await api("POST", `/v1/dead-letters/${d.id}/replay`); toast(t("Delivered")); deadLettersPage(); }),
        h("button", { onclick: () => infoDialog(t("Event"), json(d.event)) }, t("View")),
        h("button", { class: "danger", onclick: () => confirmDialog(t("Discard"), t("Discard this event for this subscription?"), t("Discard"),
          async () => { await api("DELETE", `/v1/dead-letters/${d.id}`); deadLettersPage(); }) }, t("Discard"))) },
    ], res.items));
}

// replayEvents redelivers the stored events of a time range to one subscription
// without moving its cursor (e.g. after fixing a consumer).
function replayEvents(subscriptions) {
  formDialog(t("Replay events"), [
    subscriptions.length
      ? { name: "subscription", label: t("Subscription"), type: "select", options: subscriptions.map((s) => [s, s]), value: subscriptions[0] }
      : { name: "subscription", label: t("Subscription"), required: true, placeholder: "kafka/events" },
    { name: "since", label: t("Since"), type: "datetime-local", required: true },
    { name: "until", label: t("Until"), type: "datetime-local", help: t("Empty means up to now.") },
    { name: "types", label: t("Event types"), placeholder: "tenant.*, member.added", help: t("Exact types or prefixes ending in *, comma separated; empty means all.") },
    { name: "tenant_ids", label: t("Tenant IDs"), type: "textarea", placeholder: t("Tenant IDs, one per line") },
  ], t("Replay"), async (v) => {
    const r = await api("POST", "/v1/events/replay", {
      subscription: v.subscription, since: toISO(v.since), until: toISO(v.until),
      types: splitList(v.types), tenant_ids: splitWords(v.tenant_ids) });
    setTimeout(() => infoDialog(t("Replay finished"), h("dl", { class: "kv" },
      h("dt", {}, t("Matched")), h("dd", {}, String(r.matched ?? 0)),
      h("dt", {}, t("Delivered")), h("dd", {}, String(r.delivered ?? 0)),
      h("dt", {}, t("Dead-lettered")), h("dd", {}, String(r.dead_lettered ?? 0))),
    r.truncated ? h("p", { class: "notice warn" }, t("Stopped at 10,000 events: replay again from the last delivered event to continue.")) : ""));
    if (r.dead_lettered) deadLettersPage();
  });
}

// ---- plugins -----------------------------------------------------------------------

async function pluginsPage() {
  const { data: res, denied } = await optional(() => api("GET", "/v1/plugins"));
  if (denied) { page(t("Plugins"), [], deniedNote()); return; }
  if (!res) return;
  const list = (label, items) => (items?.length ? [h("dt", {}, label), h("dd", {}, chipList(items, "chip mono"))] : []);
  page(t("Plugins"), [h("span", { class: "muted small" }, t("Compiled in: {list}", { list: res.available.join(", ") }))],
    res.items.length ? h("div", { class: "grid two" }, res.items.map((p) => h("div", { class: "card" },
      h("div", { class: "page-head", style: "margin-bottom:8px" }, h("h2", { style: "margin:0" }, p.name), badge(`${p.manifest.id} ${p.manifest.version}`, "")),
      p.manifest.description ? h("p", { class: "muted" }, p.manifest.description) : null,
      h("dl", { class: "kv" },
        ...list(t("Subscriptions"), p.subscriptions), ...list(t("Hooks"), p.hooks), ...list(t("Provisioners"), p.provisioners),
        ...list(t("Routes"), p.routes), ...list(t("Authenticators"), p.authenticators), ...list(t("Authorizers"), p.authorizers),
        ...(p.scope ? [h("dt", {}, t("Scope")), h("dd", {}, json(p.scope))] : [])))))
      : h("div", { class: "card empty" }, t("No plugins enabled.")));
}

// ---- users -------------------------------------------------------------------

async function usersPage() {
  const state = { q: "", status: "" };
  const search = h("input", { type: "search", placeholder: t("Search email or name"), "aria-label": t("Search email or name"), oninput: () => { state.q = search.value; debounce(load); } });
  const status = h("select", { "aria-label": t("Status"), onchange: () => { state.status = status.value; load(); } },
    [["", t("All statuses")], ["active", t("active")], ["invited", t("invited")], ["disabled", t("disabled")]].map(([v, l]) => h("option", { value: v }, l)));
  const list = h("div");
  page(t("Users"), [search, status, h("button", { class: "primary", onclick: createUser }, t("New user"))], list);

  async function load() {
    const q = new URLSearchParams({ limit: "200" });
    if (state.q) q.set("q", state.q);
    if (state.status) q.set("status", state.status);
    const res = await optional(() => api("GET", `/v1/users?${q}`));
    if (res.denied) { list.replaceChildren(deniedNote()); return; }
    if (!res.data) return;
    list.replaceChildren(table([
      { label: t("User"), render: (u) => [h("strong", { class: "block" }, u.name || u.email), h("span", { class: "block muted small" }, u.email)] },
      { label: t("Status"), render: (u) => statusBadge(u.status) },
      { label: t("Platform roles"), render: (u) => chipList(u.roles) },
      { label: t("Directory"), render: (u) => h("span", { class: "muted" }, u.directory) },
      { label: t("Last login"), render: (u) => h("span", { class: "muted" }, fmtTime(u.last_login_at)) },
    ], res.data.items, { click: (u) => userDialog(u, load) }));
  }
  load();
}

let debounceTimer;
function debounce(fn) {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(fn, 250);
}

function createUser() {
  formDialog(t("New user"), [
    { name: "email", label: t("Email"), type: "email", required: true },
    { name: "name", label: t("Name") },
    { name: "roles", label: t("Platform roles"), placeholder: "admin, viewer", help: t("Leave empty for users who only work inside tenants.") },
    { name: "password", label: t("Password"), type: "password", help: t("Optional. Without it the user gets an invitation email.") },
  ], t("Create"), async (v) => {
    const body = { email: v.email, name: v.name, roles: splitList(v.roles) };
    if (v.password) body.password = v.password;
    await api("POST", "/v1/users", body);
    toast(v.password ? t("User created") : t("Invitation sent"));
    usersPage();
  });
}

async function userDialog(u, reload) {
  const ms = (await optional(() => api("GET", `/v1/users/${u.id}/memberships`))).data?.items || [];
  // dialogAct runs fn, then closes the dialog and reloads the list; a 403 disables the button.
  const dialogAct = (label, cls, fn) => act(label, cls, async () => { await fn(); document.getElementById("dialog").close(); reload(); });
  formDialog(u.email, [
    { name: "name", label: t("Name"), value: u.name },
    { name: "roles", label: t("Platform roles"), value: (u.roles || []).join(", ") },
  ], t("Save"), async (v) => {
    await api("PATCH", `/v1/users/${u.id}`, { name: v.name, roles: splitList(v.roles) }, { "If-Match": `"${u.version}"` });
    toast(t("Saved"));
    reload();
  });
  const canImpersonate = isPlatform() && !impersonation.get() && u.status === "active" && !(u.roles || []).length
    && ms.some((m) => m.status === "active");
  const fields = document.querySelector("#dialog-form .fields");
  fields.append(
    h("dl", { class: "kv" },
      h("dt", {}, t("Status")), h("dd", {}, statusBadge(u.status)),
      h("dt", {}, t("Directory")), h("dd", {}, u.directory + (u.external_id ? ` (${u.external_id})` : "")),
      h("dt", {}, t("Created")), h("dd", {}, fmtTime(u.created_at)),
      h("dt", {}, t("Tenants")), h("dd", {}, ms.length
        ? h("div", { class: "chips" }, ms.map((m) => h("a", { class: "chip", href: `#/tenant/${m.tenant_id}` }, `${m.role} · ${t(m.status)}`)))
        : t("none"))),
    h("div", { class: "toolbar" },
      u.status === "invited" ? dialogAct(t("Resend invitation"), "", async () => { await api("POST", `/v1/users/${u.id}/invitation`); toast(t("Invitation sent")); }) : null,
      u.status === "disabled"
        ? dialogAct(t("Enable"), "", () => api("POST", `/v1/users/${u.id}/enable`))
        : dialogAct(t("Disable"), "", () => api("POST", `/v1/users/${u.id}/disable`)),
      act(t("Sessions"), "", () => userSessions(u)),
      dialogAct(t("Sign out everywhere"), "", async () => { await api("DELETE", `/v1/users/${u.id}/sessions`); toast(t("Sessions revoked")); }),
      dialogAct(t("Reset two-factor"), "", async () => {
        if (!confirm(t("Turn off two-factor authentication for {email}? Use this when they lost their device.", { email: u.email }))) throw new Error(t("Cancelled"));
        await api("DELETE", `/v1/users/${u.id}/mfa`);
        toast(t("Two-factor authentication reset"));
      }),
      act(t("Export data"), "", () => download(`/v1/users/${u.id}/export`, `user-${u.id}.json`)),
      canImpersonate ? h("button", { type: "button", onclick: () => impersonateDialog(u, ms) }, t("Impersonate")) : null,
      dialogAct(t("Delete"), "danger", async () => {
        if (!confirm(t("Delete {email} and all their memberships?", { email: u.email }))) throw new Error(t("Cancelled"));
        await api("DELETE", `/v1/users/${u.id}`);
        toast(t("User deleted"));
      }),
      h("button", { type: "button", class: "danger", onclick: () => eraseDialog(u, reload) }, t("Erase (GDPR)"))));
}

async function userSessions(u) {
  const res = await api("GET", `/v1/users/${u.id}/sessions`);
  infoDialog(t("Sessions of {email}", { email: u.email }), sessionList(res.items || [], async (s) => {
    await api("DELETE", `/v1/users/${u.id}/sessions/${encodeURIComponent(s.id)}`);
    toast(t("Session signed out"));
    userSessions(u);
  }));
}

// eraseDialog removes a user everywhere (right to erasure), optionally redacting past events.
function eraseDialog(u, reload) {
  formDialog(t("Erase {email}", { email: u.email }), [
    { name: "redact_events", label: t("Also replace their name and email in past events with [erased]"), type: "checkbox" },
    { name: "confirm", label: t("Type the email address to confirm"), required: true, placeholder: u.email },
  ], t("Erase permanently"), async (v) => {
    if (v.confirm.trim().toLowerCase() !== u.email.toLowerCase()) throw new Error(t("The email address does not match."));
    const r = await api("POST", `/v1/users/${u.id}/erase`, { redact_events: v.redact_events });
    toast(v.redact_events ? t("User erased; events redacted: {n}", { n: r.redacted_events ?? 0 }) : t("User erased"));
    reload();
  });
  document.querySelector("#dialog-form .fields").prepend(h("p", { class: "notice warn" },
    t("This deletes the user with all memberships, credentials, sessions, passkeys and the directory entry. It cannot be undone.")));
}

// impersonateDialog asks for a reason (and the user's consent code when required) and
// switches this tab to a short-lived session as the user in one of their tenants.
async function impersonateDialog(u, ms) {
  const active = ms.filter((m) => m.status === "active");
  const names = await Promise.all(active.map(async (m) => (await optional(() => api("GET", `/v1/tenants/${m.tenant_id}`))).data?.name || m.tenant_id.slice(0, 8)));
  formDialog(t("Impersonate {email}", { email: u.email }), [
    { name: "tenant", label: t("Tenant"), type: "select", options: active.map((m, i) => [m.tenant_id, `${names[i]} · ${m.role}`]), value: active[0]?.tenant_id },
    { name: "reason", label: t("Reason"), required: true, placeholder: t("e.g. support ticket #1234"), help: t("Recorded with every action you take.") },
    { name: "ttl", label: t("Duration"), placeholder: "15m", help: t("Default 15m, at most the server's maximum (1h by default).") },
    { name: "consent_code", label: t("Consent code"), help: t("When the server requires consent, the user creates this code on their Account page under Support access.") },
  ], t("Start impersonation"), async (v) => {
    let pair;
    try {
      pair = await api("POST", `/v1/users/${u.id}/impersonate`, {
        reason: v.reason, tenant: v.tenant, ttl: v.ttl.trim() || undefined, consent_code: v.consent_code.trim() || undefined });
    } catch (e) {
      if (e.code === "consent_required") throw new Error(t("This user has to consent first: ask them for a consent code (Account → Support access) and enter it here."));
      throw e;
    }
    const i = active.findIndex((m) => m.tenant_id === v.tenant);
    impersonation.begin(pair, { user: u.email, tenant: v.tenant, tenantName: names[i], expires_at: Date.now() + (pair.expires_in || 0) * 1000 });
    history.pushState(null, "", `#/tenant/${v.tenant}`);
    start();
  });
  document.querySelector("#dialog-form .fields").prepend(h("p", { class: "notice warn" },
    t("You will act as this user. Credentials, data exports, API keys, webhooks, roles and SSO cannot be changed while impersonating.")));
}

function renderImpersonation() {
  const bar = document.getElementById("impersonation");
  const s = impersonation.get();
  bar.hidden = !s;
  if (!s) return;
  bar.replaceChildren(
    h("span", {}, h("strong", {}, t("Impersonating {user}", { user: s.user })), " · ", t("tenant {name}", { name: s.tenantName || s.tenant }),
      s.expires_at ? ` · ${t("until {time}", { time: new Date(s.expires_at).toLocaleTimeString(lang) })}` : ""),
    h("button", { type: "button", onclick: stopImpersonation }, t("Stop impersonating")));
}

function stopImpersonation() {
  if (!impersonation.end()) return;
  toast(t("Back to your own session"));
  history.pushState(null, "", "#/users");
  start();
}

// ---- public pages (no session) ----------------------------------------------------

function publicPage(title, intro, fields, submitLabel, onSubmit) {
  const box = document.getElementById("public");
  document.getElementById("app").hidden = true;
  document.getElementById("login").hidden = true;
  box.hidden = false;
  const err = h("p", { class: "error", role: "alert", hidden: true });
  const inputs = fields.map((f) => h("label", {}, f.label, h("input", { name: f.name, type: f.type || "text", required: f.required, autocomplete: f.autocomplete || "off" })));
  const brand = () => h("div", { class: "login-top" }, h("div", { class: "brand big" }, h("span", { class: "logo" }, "T"), " Tenarium"), langPicker());
  const form = h("form", { class: "card login-card" },
    brand(), h("h2", {}, title), h("p", { class: "muted" }, intro), ...inputs, err,
    h("button", { class: "primary", type: "submit" }, submitLabel),
    h("a", { href: "#/", class: "small", onclick: () => { box.hidden = true; } }, t("Back to sign in")));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = Object.fromEntries(new FormData(form));
    try {
      const done = await onSubmit(v);
      form.replaceChildren(brand(), h("p", {}, done),
        h("a", { href: "#/", onclick: () => { box.hidden = true; } }, t("Sign in")));
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
    }
  });
  box.replaceChildren(form);
}

function checkMatch(v) {
  if (v.password !== v.confirm) throw new Error(t("The passwords do not match."));
}

const publicRoutes = {
  accept: (token) => publicPage(t("Activate your account"), t("Choose a password to finish setting up your account."), [
    { name: "name", label: t("Your name"), autocomplete: "name" },
    { name: "password", label: t("Password"), type: "password", required: true, autocomplete: "new-password" },
    { name: "confirm", label: t("Repeat password"), type: "password", required: true, autocomplete: "new-password" },
  ], t("Activate"), async (v) => {
    checkMatch(v);
    const res = await publicApi("POST", "/v1/auth/invitations/accept", { token, password: v.password, name: v.name });
    return t("Your account {email} is active. You can sign in now.", { email: res.email });
  }),
  reset: (token) => publicPage(t("Choose a new password"), t("Pick a new password for your account."), [
    { name: "password", label: t("New password"), type: "password", required: true, autocomplete: "new-password" },
    { name: "confirm", label: t("Repeat password"), type: "password", required: true, autocomplete: "new-password" },
  ], t("Change password"), async (v) => {
    checkMatch(v);
    await publicApi("POST", "/v1/auth/password-reset/confirm", { token, password: v.password });
    return t("Your password was changed and all your sessions were signed out.");
  }),
  forgot: () => publicPage(t("Reset your password"), t("We will email you a link to choose a new password."), [
    { name: "email", label: t("Email"), type: "email", required: true, autocomplete: "username" },
  ], t("Send link"), async (v) => {
    await publicApi("POST", "/v1/auth/password-reset", { email: v.email });
    return t("If an account exists for that address, a reset link is on its way.");
  }),
};

// publicMessage shows a result card without a form (e.g. a confirmed link).
function publicMessage(title, text, isErr = false) {
  const box = document.getElementById("public");
  document.getElementById("app").hidden = true;
  document.getElementById("login").hidden = true;
  box.hidden = false;
  box.replaceChildren(h("div", { class: "card login-card" },
    h("div", { class: "brand big" }, h("span", { class: "logo" }, "T"), " Tenarium"),
    h("h2", {}, title), h("p", { class: isErr ? "error" : "", role: isErr ? "alert" : null }, text),
    h("a", { href: "#/", onclick: () => { box.hidden = true; } }, t("Back to sign in"))));
}

// Links from emails carry single-use tokens; these routes act once on load.
Object.assign(publicRoutes, {
  // magic: a sign-in link; two-factor users are asked for their code and the same token is sent again.
  magic: async (token) => {
    const signIn = async (otp) => {
      const pair = await publicApi("POST", "/v1/auth/token", { grant_type: "magic_link", token, otp });
      auth.clear();
      auth.useTokens(pair);
      history.replaceState(null, "", location.pathname + location.search);
      start();
      return "";
    };
    publicMessage(t("Signing you in…"), t("Checking your sign-in link."));
    try {
      await signIn();
    } catch (e) {
      if (e.code === "mfa_required" || e.code === "invalid_otp") {
        publicPage(t("Two-factor authentication"), t("Enter the code from your authenticator app."), [
          { name: "otp", label: t("Code from your authenticator app"), required: true, autocomplete: "one-time-code" },
        ], t("Sign in"), (v) => signIn(String(v.otp).trim()));
      } else publicMessage(t("This sign-in link does not work"), e.message, true);
    }
  },
  "confirm-email": async (token) => {
    publicMessage(t("Confirming your email address…"), t("One moment."));
    try {
      const u = await publicApi("POST", "/v1/auth/email-change/confirm", { token });
      publicMessage(t("Email address changed"), t("Your email address is now {email}.", { email: u.email }));
    } catch (e) {
      publicMessage(t("This confirmation link does not work"), e.message, true);
    }
  },
});
const oneShotRoutes = new Set(["magic", "confirm-email"]);

// handlePublicRoute renders invitation/reset/link pages, which need no session.
// rerender (after a language change) skips the routes that would spend a token again.
function handlePublicRoute(rerender = false) {
  const [name, token] = location.hash.replace(/^#\/?/, "").split("/");
  if (!Object.hasOwn(publicRoutes, name)) return false;
  if (rerender && oneShotRoutes.has(name)) return true;
  publicRoutes[name](token && decodeURIComponent(token));
  return true;
}

// ---- language --------------------------------------------------------------

// langPicker builds a language select; every picker re-renders the whole UI on change.
function langPicker(select = h("select", { "aria-label": t("Language") })) {
  select.replaceChildren(...languages.map(([code, name]) => h("option", { value: code, selected: code === lang }, name)));
  select.value = lang;
  select.onchange = () => changeLanguage(select.value);
  return select;
}

// translateStatic applies t() to the markup in index.html (data-i18n* hold the keys).
function translateStatic() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => (el.placeholder = t(el.dataset.i18nPlaceholder)));
  document.querySelectorAll("[data-i18n-label]").forEach((el) => el.setAttribute("aria-label", t(el.dataset.i18nLabel)));
  langPicker(document.getElementById("lang"));
  langPicker(document.getElementById("login-lang"));
}

function changeLanguage(code) {
  setLanguage(code);
  translateStatic();
  if (!document.getElementById("public").hidden) handlePublicRoute(true);
  if (!document.getElementById("app").hidden) {
    renderWhoami();
    renderImpersonation();
    route();
  }
}

// ---- auth ------------------------------------------------------------------

function showLogin(message) {
  document.getElementById("app").hidden = true;
  document.getElementById("public").hidden = true;
  document.getElementById("impersonation").hidden = true;
  document.getElementById("login").hidden = false;
  const err = document.getElementById("login-error");
  err.textContent = message || "";
  err.hidden = !message;
  probePasskeys();
  loadSocial();
  if (brandingKey === null) loadBranding(new URLSearchParams({ host: location.hostname }));
}

function renderWhoami() {
  if (!me) return;
  const who = me.claims?.email || me.subject;
  document.getElementById("whoami").textContent = `${who} · ${me.authenticator}${me.tenant_id ? ` · ${t("tenant {name}", { name: me.tenant_id.slice(0, 8) })}` : ""}`;
}

async function start() {
  try {
    me = await api("GET", "/v1/me");
    renderWhoami();
    // Tenant-scoped callers cannot use platform-wide pages.
    for (const r of ["users", "events", "dead-letters", "plugins", "signing-keys", "rollouts", "oauth-clients", "templates"]) {
      document.querySelector(`#nav a[data-route="${r}"]`).hidden = Boolean(me.tenant_id);
    }
    // Account settings apply to signed-in Tenarium users only.
    document.querySelector('#nav a[data-route="account"]').hidden = !(me.authenticator === "core/token" || me.claims?.tenarium_user_id);
    document.getElementById("login").hidden = true;
    document.getElementById("public").hidden = true;
    document.getElementById("app").hidden = false;
    renderImpersonation();
    route();
  } catch (e) {
    if (e.status !== 401) showLogin(e.message);
  }
}

const loginForm = document.getElementById("login-form");
const otpField = document.getElementById("otp-field");
const passkeyButton = document.getElementById("passkey-login");
const showKind = (kind) => {
  loginForm.querySelectorAll("[data-kind]").forEach((el) => (el.hidden = !el.dataset.kind.split(" ").includes(kind)));
  otpField.hidden = true;
  passkeyButton.hidden = !(kind === "password" && passkey.available);
  if (magicOff) magicButton.hidden = true;
};

// passkey sign-in: the server has no capability flag, so a discoverable-credential
// ceremony is started when the login form shows; a 404 means passkeys are off. The
// ceremony is kept so the browser prompt opens right on the click.
const passkey = { available: false, probed: false, begin: null, at: 0 };
async function probePasskeys() {
  if (passkey.probed || !passkeysSupported()) return;
  passkey.probed = true;
  try {
    passkey.begin = await publicApi("POST", "/v1/auth/passkey/begin", {});
    passkey.at = Date.now();
    passkey.available = true;
  } catch {
    passkey.available = false;
  }
  showKind(loginForm.elements.kind.value);
}

passkeyButton.addEventListener("click", async () => {
  const f = new FormData(loginForm);
  const email = String(f.get("email") || "").trim();
  try {
    // Reuse the probed ceremony (valid 5 minutes) unless an email narrows the passkeys.
    let begin = !email && passkey.begin && Date.now() - passkey.at < 4 * 60e3 ? passkey.begin : null;
    passkey.begin = null;
    begin ??= await publicApi("POST", "/v1/auth/passkey/begin", email ? { email } : {});
    let cred;
    try {
      cred = await navigator.credentials.get(requestOptions(begin.options));
    } catch (e) {
      showLogin(webauthnError(e));
      return;
    }
    const pair = await publicApi("POST", "/v1/auth/passkey/finish", { ceremony: begin.ceremony, credential: credentialJSON(cred), tenant: f.get("tenant") || undefined });
    auth.clear();
    auth.useTokens(pair);
    start();
  } catch (ex) {
    if (ex.status === 404) {
      passkey.available = false;
      passkeyButton.hidden = true;
      showLogin(t("Passkeys are not enabled on this server."));
    } else showLogin(ex.message);
  }
});

// magic link: the server answers 202 whether or not the address is known; 404 means it is off.
const magicButton = document.getElementById("magic-link");
let magicOff = false;
magicButton.addEventListener("click", async () => {
  const f = new FormData(loginForm);
  const email = String(f.get("email") || "").trim();
  if (!email) { showLogin(t("Enter your email address first.")); return; }
  try {
    await publicApi("POST", "/v1/auth/magic-link", { email, tenant: f.get("tenant") || undefined });
    showLogin();
    toast(t("If an account exists for {email}, a sign-in link is on its way.", { email }));
  } catch (ex) {
    if (ex.status === 404) {
      magicOff = true;
      magicButton.hidden = true;
      showLogin(t("Sign-in links are not enabled on this server."));
    } else showLogin(ex.message);
  }
});

// social login: buttons for the providers the server lists (none, or 404, hides them).
let socialLoaded = false;
async function loadSocial() {
  if (socialLoaded) return;
  socialLoaded = true;
  const box = document.getElementById("social-login");
  let providers = [];
  try {
    providers = (await publicApi("GET", "/v1/auth/social")).providers || [];
  } catch { /* not configured */ }
  box.hidden = !providers.length;
  box.replaceChildren(h("div", { class: "divider", dataset: { i18n: "or continue with" } }, t("or continue with")), ...providers.map((p) =>
    h("button", { type: "button", onclick: () => {
      const q = new URLSearchParams({ return_to: location.origin + location.pathname });
      const tenant = String(new FormData(loginForm).get("tenant") || "").trim();
      if (tenant) q.set("tenant", tenant);
      location.href = `/v1/auth/social/${encodeURIComponent(p.name)}/start?${q}`;
    } }, p.label || p.name)));
}

// tenant branding on the login form: looked up by the tenant field (or this host's
// custom domain); colors are used only when they are plain hex, logos only over https.
let brandingKey = null;
async function loadBranding(query) {
  const key = query.toString();
  if (key === brandingKey) return;
  brandingKey = key;
  let b = null;
  try { b = await publicApi("GET", `/v1/auth/branding?${query}`); } catch { /* unknown tenant or no branding */ }
  if (brandingKey === key) applyBranding(b);
}

function applyBranding(b) {
  const brand = loginForm.querySelector(".brand");
  loginForm.style.removeProperty("--accent");
  loginForm.style.removeProperty("border-top");
  loginForm.querySelector(".login-support")?.remove();
  const logo = b && /^https:\/\//i.test(b.logo_url || "") ? h("img", { class: "brand-logo", src: b.logo_url, alt: "" }) : h("span", { class: "logo" }, "T");
  brand.replaceChildren(logo, " ", b?.display_name || "Tenarium");
  if (!b) return;
  if (validColor(b.primary_color)) loginForm.style.setProperty("--accent", b.primary_color);
  if (validColor(b.accent_color)) loginForm.style.setProperty("border-top", `4px solid ${b.accent_color}`);
  const help = /^https?:\/\//i.test(b.support_url || "") ? b.support_url : b.support_email ? `mailto:${b.support_email}` : "";
  if (help) loginForm.append(h("a", { class: "small login-support", href: help, target: "_blank", rel: "noopener" }, t("Need help? Contact support")));
}

loginForm.elements.tenant.addEventListener("change", () => {
  const tenant = loginForm.elements.tenant.value.trim();
  loadBranding(new URLSearchParams(tenant ? { tenant } : { host: location.hostname }));
});

showKind("password");
loginForm.addEventListener("change", (e) => {
  if (e.target.name === "kind") showKind(e.target.value);
});
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  switch (f.get("kind")) {
    case "password":
      auth.clear();
      try {
        auth.useTokens(await publicApi("POST", "/v1/auth/token", {
          grant_type: "password", email: f.get("email"), password: f.get("userpassword"), tenant: f.get("tenant") || undefined,
          otp: (!otpField.hidden && f.get("otp")) || undefined,
        }));
      } catch (ex) {
        // Two-factor users need a code: show the field and ask again.
        if (ex.code === "mfa_required" || ex.code === "invalid_otp") {
          otpField.hidden = false;
          otpField.querySelector("input").focus();
          showLogin(ex.code === "mfa_required" ? t("Enter the code from your authenticator app.") : ex.message);
          return;
        }
        showLogin(ex.message);
        return;
      }
      break;
    case "sso": {
      // The provider sends the browser back here with the session in the URL fragment.
      const q = new URLSearchParams();
      if (f.get("email")) q.set("email", f.get("email"));
      if (f.get("tenant")) q.set("tenant", f.get("tenant"));
      if (!q.toString()) { showLogin(t("Enter your email or tenant.")); return; }
      // Probe first: without a connection the server answers with a JSON
      // error instead of a redirect, which belongs in the form, not on a
      // blank page.
      const url = `/v1/auth/sso/start?${q}`;
      try {
        const res = await fetch(url, { redirect: "manual", credentials: "same-origin" });
        if (res.type !== "opaqueredirect" && !res.ok) {
          const body = await res.json().catch(() => ({}));
          showLogin(body.error?.message || t("No single sign-on is set up for this email or tenant."));
          return;
        }
      } catch { /* network trouble: let the navigation report it */ }
      location.href = url;
      return;
    }
    case "basic":
      auth.clear();
      auth.header = "Basic " + btoa(unescape(encodeURIComponent(`${f.get("username")}:${f.get("password")}`)));
      break;
    default:
      auth.clear();
      auth.header = "Bearer " + f.get("token");
  }
  otpField.hidden = true;
  start();
});
document.getElementById("logout").addEventListener("click", () => {
  impersonation.end(); // sign out the admin's own session
  if (auth.refresh) publicApi("POST", "/v1/auth/logout", { refresh_token: auth.refresh }).catch(() => {});
  auth.clear();
  me = null;
  showLogin();
});
window.addEventListener("hashchange", () => {
  if (handlePublicRoute()) return;
  if (!document.getElementById("app").hidden) route();
  else if (auth.header) start();
  else showLogin();
});

// takeSSOResult reads the session (or error) an SSO sign-in put in the URL fragment.
function takeSSOResult() {
  if (!/(^#|&)(access_token|error)=/.test(location.hash)) return null;
  const p = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, "", location.pathname + location.search);
  if (p.get("access_token")) {
    auth.clear();
    auth.useTokens({ access_token: p.get("access_token"), refresh_token: p.get("refresh_token") });
    return "ok";
  }
  return p.get("error_description") || p.get("error");
}

translateStatic();
const ssoResult = takeSSOResult();
// Error codes SSO and social login put in the fragment, explained.
const signInErrors = {
  access_denied: "This account cannot sign in this way: it is unknown here, disabled, or not allowed.",
  sso_required: "Your organization requires its own single sign-on: choose Single sign-on (SSO).",
  mfa_required: "Your account uses two-factor authentication: sign in with your password and code.",
  tenant_required: "Enter a tenant to sign in to.",
  account_locked: "Your account is temporarily locked. Try again later.",
  email_unverified: "The provider has not verified your email address.",
  domain_not_allowed: "Your email domain is not allowed to sign in here.",
  sso_rejected: "The identity provider's answer was rejected.",
  idp_error: "The identity provider reported an error.",
};
if (ssoResult && ssoResult !== "ok") {
  showLogin(signInErrors[ssoResult] ? t(signInErrors[ssoResult]) : t("Single sign-on failed: {reason}", { reason: ssoResult }));
}
else if (!handlePublicRoute()) {
  if (auth.header) start();
  else {
    // Dev mode: the API may allow anonymous access.
    fetch("/v1/me").then((r) => (r.ok ? start() : showLogin())).catch(() => showLogin());
  }
}
