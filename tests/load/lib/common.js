// Shared configuration and helpers for the Tenarium k6 load tests.
//
// Environment variables (pass with `k6 run -e NAME=value` or the shell env):
//   BASE_URL        Tenarium base URL                (default http://localhost:8080)
//   API_KEY         platform API key (Bearer token)  (required unless the server allows anonymous)
//   TENANTS         tenants bootstrapped by setup()  (default 20)
//   PLAN            plan given to bootstrapped tenants (default pro)
//   METRIC          usage metric recorded            (default api_calls)
//   VUS, DURATION   load shape for a single scenario (defaults 10 / 30s)
//   RATE            target iterations/s for open-model scenarios (default 50)
//   P95_MS          p95 latency threshold in ms      (default 300)
//   P99_MS          p99 latency threshold in ms      (default 1000)
//   MAX_ERROR_RATE  allowed share of failed requests (default 0.01)
//   RUN_ID          prefix for created slugs (default: random), so repeated
//                   runs against the same server do not collide.

import http from 'k6/http';
import { check, fail } from 'k6';

export const BASE_URL = (__ENV.BASE_URL || 'http://localhost:8080').replace(/\/+$/, '');
export const API_KEY = __ENV.API_KEY || '';
export const TENANTS = parseInt(__ENV.TENANTS || '20', 10);
export const PLAN = __ENV.PLAN || 'pro';
export const METRIC = __ENV.METRIC || 'api_calls';
export const VUS = parseInt(__ENV.VUS || '10', 10);
export const DURATION = __ENV.DURATION || '30s';
export const RATE = parseInt(__ENV.RATE || '50', 10);
export const P95_MS = parseInt(__ENV.P95_MS || '300', 10);
export const P99_MS = parseInt(__ENV.P99_MS || '1000', 10);
export const MAX_ERROR_RATE = parseFloat(__ENV.MAX_ERROR_RATE || '0.01');
export const RUN_ID = (__ENV.RUN_ID || Math.random().toString(36).slice(2, 8)).toLowerCase();

// Every request carries a "name" tag so latency is reported per endpoint
// instead of per URL (URLs contain IDs).
export function params(name, extra = {}) {
  const headers = { 'Content-Type': 'application/json', ...(extra.headers || {}) };
  if (API_KEY) headers.Authorization = `Bearer ${API_KEY}`;
  return { ...extra, headers, tags: { name, ...(extra.tags || {}) } };
}

export function get(path, name) {
  return http.get(`${BASE_URL}${path}`, params(name));
}

export function post(path, body, name, extra) {
  return http.post(`${BASE_URL}${path}`, JSON.stringify(body), params(name, extra));
}

export function patch(path, body, name, extra) {
  return http.patch(`${BASE_URL}${path}`, JSON.stringify(body), params(name, extra));
}

export function del(path, name) {
  return http.del(`${BASE_URL}${path}`, null, params(name));
}

export function json(res) {
  try {
    return res.json();
  } catch (_) {
    return null;
  }
}

export function ok(res, label, status) {
  const want = Array.isArray(status) ? status : [status || 200];
  return check(res, { [`${label} -> ${want.join('/')}`]: (r) => want.includes(r.status) });
}

// Slugs are DNS labels: lowercase alphanumerics and '-', at most 63 chars.
export function slug(prefix) {
  const rnd = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${RUN_ID}-${__VU}-${__ITER}-${rnd}`.slice(0, 63).replace(/-+$/, '');
}

export function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Thresholds shared by every scenario, plus per-endpoint p95 limits.
export function thresholds(endpoints = []) {
  const t = {
    http_req_failed: [`rate<${MAX_ERROR_RATE}`],
    http_req_duration: [`p(95)<${P95_MS}`, `p(99)<${P99_MS}`],
    checks: [`rate>${1 - MAX_ERROR_RATE}`],
  };
  for (const e of endpoints) {
    t[`http_req_duration{name:${e}}`] = [`p(95)<${P95_MS}`];
  }
  return t;
}

// bootstrap creates the tenants the read/write scenarios work on. It runs
// once in setup(); the returned IDs are passed to every VU.
export function bootstrap() {
  const health = http.get(`${BASE_URL}/healthz`, { tags: { name: 'setup' } });
  if (health.status !== 200) {
    fail(`Tenarium is not reachable at ${BASE_URL} (GET /healthz -> ${health.status})`);
  }
  const auth = get('/v1/me', 'setup');
  if (auth.status !== 200) {
    fail(`API_KEY rejected (GET /v1/me -> ${auth.status}); pass -e API_KEY=...`);
  }
  const ids = [];
  for (let i = 0; i < TENANTS; i++) {
    const res = post('/v1/tenants', {
      slug: `lt-${RUN_ID}-${i}`,
      name: `Load test ${RUN_ID} #${i}`,
      plan: PLAN,
      labels: { 'tenarium.dev/load-test': RUN_ID },
      // Lift the member cap so member-add scenarios never hit 429.
      limits: { members: 1000000 },
    }, 'setup');
    if (res.status !== 201) {
      fail(`setup: creating tenant failed: ${res.status} ${res.body}`);
    }
    ids.push(json(res).id);
  }
  return { tenants: ids, runId: RUN_ID };
}

// cleanup deletes the bootstrapped tenants (they are soft-deleted when the
// server has a deletion grace period). Set KEEP_DATA=1 to keep them.
export function cleanup(data) {
  if (__ENV.KEEP_DATA || !data || !data.tenants) return;
  for (const id of data.tenants) {
    del(`/v1/tenants/${id}`, 'teardown');
  }
}
