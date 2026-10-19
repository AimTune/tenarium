// Member adds: invites new users into the bootstrapped tenants and reads
// the member list back.
//
//   k6 run -e API_KEY=... tests/load/scenarios/members.js
import { sleep } from 'k6';
import {
  VUS, DURATION, RUN_ID, bootstrap, cleanup, thresholds, pick, json, ok, get, post,
} from '../lib/common.js';

export const endpoints = ['POST /v1/tenants/{id}/members', 'GET /v1/tenants/{id}/members', 'GET /v1/tenants/{id}/members/{member}'];

export const options = {
  scenarios: {
    members: { executor: 'constant-vus', vus: VUS, duration: DURATION, exec: 'memberAdd' },
  },
  thresholds: thresholds(endpoints),
};

export function setup() {
  return bootstrap();
}

export function teardown(data) {
  cleanup(data);
}

export function memberAdd(data) {
  const tenant = pick(data.tenants);
  const email = `lt-${RUN_ID}-${__VU}-${__ITER}-${Math.random().toString(36).slice(2, 8)}@load.example.com`;
  const res = post(`/v1/tenants/${tenant}/members`, { email, name: 'Load Test', role: pick(['member', 'viewer', 'admin']) },
    'POST /v1/tenants/{id}/members');
  if (ok(res, 'add member', 201)) {
    const m = json(res);
    ok(get(`/v1/tenants/${tenant}/members/${m.id}`, 'GET /v1/tenants/{id}/members/{member}'), 'get member');
  }
  if (__ITER % 10 === 0) {
    ok(get(`/v1/tenants/${tenant}/members`, 'GET /v1/tenants/{id}/members'), 'list members');
  }
  sleep(0.05);
}

export default memberAdd;
