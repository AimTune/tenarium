// Event reads and audit queries: paging through the event log, the
// platform-wide audit trail with filters, and per-tenant audit trails.
//
//   k6 run -e API_KEY=... tests/load/scenarios/events.js
import { sleep } from 'k6';
import {
  VUS, DURATION, bootstrap, cleanup, thresholds, pick, json, ok, get, post,
} from '../lib/common.js';

export const endpoints = ['GET /v1/events', 'GET /v1/audit', 'GET /v1/tenants/{id}/audit'];

export const options = {
  scenarios: {
    events: { executor: 'constant-vus', vus: VUS, duration: DURATION, exec: 'readEvents' },
  },
  thresholds: thresholds(endpoints),
};

export function setup() {
  const data = bootstrap();
  // Give the audit trail some depth: a few updates per tenant.
  for (const id of data.tenants) {
    for (let i = 0; i < 5; i++) {
      post(`/v1/tenants/${id}/usage/api_calls`, { delta: 1 }, 'setup');
    }
  }
  return data;
}

export function teardown(data) {
  cleanup(data);
}

export function readEvents(data) {
  // Page forward through the log from a random early point.
  let after = Math.floor(Math.random() * 50);
  for (let page = 0; page < 3; page++) {
    const res = get(`/v1/events?after=${after}&limit=100`, 'GET /v1/events');
    if (!ok(res, 'read events')) break;
    const body = json(res) || {};
    if (!body.next) break; // end of the log
    after = body.next;
  }

  const since = new Date(Date.now() - 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  ok(get(`/v1/audit?limit=50&type=tenant.created&since=${encodeURIComponent(since)}`, 'GET /v1/audit'), 'platform audit');
  ok(get(`/v1/audit?limit=20&tenant_id=${pick(data.tenants)}`, 'GET /v1/audit'), 'audit by tenant');
  ok(get(`/v1/tenants/${pick(data.tenants)}/audit?limit=20`, 'GET /v1/tenants/{id}/audit'), 'tenant audit');
  sleep(0.1);
}

export default readEvents;
