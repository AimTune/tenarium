// Tenant CRUD: create, read, list, update (settings merge patch with
// If-Match), suspend/resume and delete.
//
//   k6 run -e API_KEY=... tests/load/scenarios/tenants.js
import { sleep } from 'k6';
import {
  VUS, DURATION, bootstrap, cleanup, thresholds, slug, pick, json, ok, get, post, patch, del,
} from '../lib/common.js';

export const endpoints = [
  'POST /v1/tenants', 'GET /v1/tenants/{id}', 'GET /v1/tenants', 'PATCH /v1/tenants/{id}', 'DELETE /v1/tenants/{id}',
];

export const options = {
  scenarios: {
    tenants: { executor: 'constant-vus', vus: VUS, duration: DURATION, exec: 'tenantCrud' },
  },
  thresholds: thresholds(endpoints),
};

export function setup() {
  return bootstrap();
}

export function teardown(data) {
  cleanup(data);
}

export function tenantCrud(data) {
  const create = post('/v1/tenants', {
    slug: slug('crud'),
    name: 'CRUD tenant',
    labels: { env: pick(['dev', 'staging', 'prod']) },
    settings: { region: pick(['eu', 'us', 'ap']), theme: { color: 'blue' } },
  }, 'POST /v1/tenants');
  if (!ok(create, 'create tenant', 201)) return;
  const t = json(create);

  ok(get(`/v1/tenants/${t.id}`, 'GET /v1/tenants/{id}'), 'get tenant');
  ok(get(`/v1/tenants?limit=20&label=env=prod`, 'GET /v1/tenants'), 'list tenants');
  // Also read one of the shared tenants, as dashboards would.
  ok(get(`/v1/tenants/${pick(data.tenants)}`, 'GET /v1/tenants/{id}'), 'get shared tenant');

  const upd = patch(`/v1/tenants/${t.id}`, { name: 'CRUD tenant (renamed)', settings: { theme: { color: null, mode: 'dark' } } },
    'PATCH /v1/tenants/{id}', { headers: { 'If-Match': `"${t.version}"` } });
  ok(upd, 'update tenant');

  ok(del(`/v1/tenants/${t.id}`, 'DELETE /v1/tenants/{id}'), 'delete tenant', [200, 202, 204]);
  sleep(0.1);
}

export default tenantCrud;
