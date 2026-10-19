// Usage recording, the hot path: products call it on every metered action.
// Uses an open model (constant arrival rate) so the server, not the
// client, sets the pace; latency thresholds are stricter than elsewhere.
//
//   k6 run -e API_KEY=... -e RATE=200 tests/load/scenarios/usage.js
import {
  VUS, DURATION, RATE, METRIC, P95_MS, bootstrap, cleanup, thresholds, pick, ok, get, post,
} from '../lib/common.js';

export const endpoints = ['POST /v1/tenants/{id}/usage/{metric}'];

const hot = thresholds(endpoints);
// The hot path gets half the general p95 budget.
hot['http_req_duration{name:POST /v1/tenants/{id}/usage/{metric}}'] = [`p(95)<${Math.max(1, Math.floor(P95_MS / 2))}`];

export const options = {
  scenarios: {
    usage: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: VUS,
      maxVUs: VUS * 5,
      exec: 'recordUsage',
    },
  },
  thresholds: hot,
};

export function setup() {
  return bootstrap();
}

export function teardown(data) {
  // Sanity check: the counters moved.
  if (data && data.tenants && data.tenants.length) {
    ok(get(`/v1/tenants/${data.tenants[0]}/usage`, 'GET /v1/tenants/{id}/usage'), 'read usage');
  }
  cleanup(data);
}

export function recordUsage(data) {
  const res = post(`/v1/tenants/${pick(data.tenants)}/usage/${METRIC}`, { delta: 1 }, 'POST /v1/tenants/{id}/usage/{metric}');
  ok(res, 'record usage');
}

export default recordUsage;
