// All scenarios at once, in roughly production proportions: usage
// recording dominates, reads come next, writes are rare.
//
//   k6 run -e API_KEY=... tests/load/mixed.js
//   k6 run -e API_KEY=... -e VUS=50 -e RATE=500 -e DURATION=5m tests/load/mixed.js
import { VUS, DURATION, RATE, P95_MS, bootstrap, cleanup, thresholds } from './lib/common.js';
import { tenantCrud, endpoints as tenantEndpoints } from './scenarios/tenants.js';
import { memberAdd, endpoints as memberEndpoints } from './scenarios/members.js';
import { recordUsage, endpoints as usageEndpoints } from './scenarios/usage.js';
import { readEvents, endpoints as eventEndpoints } from './scenarios/events.js';

export { tenantCrud, memberAdd, recordUsage, readEvents };

const t = thresholds([...tenantEndpoints, ...memberEndpoints, ...usageEndpoints, ...eventEndpoints]);
t['http_req_duration{name:POST /v1/tenants/{id}/usage/{metric}}'] = [`p(95)<${Math.max(1, Math.floor(P95_MS / 2))}`];

export const options = {
  scenarios: {
    usage: {
      executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION,
      preAllocatedVUs: VUS, maxVUs: VUS * 5, exec: 'recordUsage',
    },
    events: { executor: 'constant-vus', vus: Math.max(1, Math.ceil(VUS / 2)), duration: DURATION, exec: 'readEvents' },
    tenants: { executor: 'constant-vus', vus: Math.max(1, Math.ceil(VUS / 5)), duration: DURATION, exec: 'tenantCrud' },
    members: { executor: 'constant-vus', vus: Math.max(1, Math.ceil(VUS / 5)), duration: DURATION, exec: 'memberAdd' },
  },
  thresholds: t,
};

export function setup() {
  return bootstrap();
}

export function teardown(data) {
  cleanup(data);
}
