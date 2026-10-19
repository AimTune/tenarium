// Copies the OpenAPI spec and the vendored Redoc standalone bundle into
// static/api/ so the API reference page is served from the site itself
// (no CDN). Runs before `start` and `build`.
import { copyFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const siteDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(siteDir, 'static', 'api');

mkdirSync(outDir, { recursive: true });
copyFileSync(join(siteDir, '..', 'internal', 'api', 'openapi.yaml'), join(outDir, 'openapi.yaml'));
const redocDir = dirname(require.resolve('redoc/package.json'));
for (const f of ['redoc.standalone.js', 'redoc.standalone.js.LICENSE.txt']) {
  copyFileSync(join(redocDir, 'bundles', f), join(outDir, f));
}
console.log('prepare-api: copied openapi.yaml and Redoc bundle to static/api/');
