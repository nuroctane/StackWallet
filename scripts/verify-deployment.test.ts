import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyDeployment } from './verify-deployment.ts';

const build = resolve('.nur', 'deployment-tests', randomUUID());
mkdirSync(resolve(build, 'assets'), { recursive: true });
mkdirSync(resolve(build, 'wasm'));
writeFileSync(resolve(build, 'index.html'), '<html>release</html>');
writeFileSync(resolve(build, 'assets', 'release.js'), 'release-code');
writeFileSync(resolve(build, '_headers'), 'Cloudflare routing configuration');
writeFileSync(resolve(build, 'wasm', '.gitignore'), '*');
writeFileSync(
  resolve(build, 'wasm', 'stackwallet_wasm_bg.wasm'),
  new Uint8Array([0, 97, 115, 109]),
);
function fixture(stale = '', status = 200, server = 'cloudflare'): typeof fetch {
  return async (input) => {
    const path = new URL(String(input)).pathname.slice(1) || 'index.html';
    assert.ok(!path.includes('.gitignore') && path !== '_headers');
    return new Response(path === stale ? 'old release' : readFileSync(resolve(build, path)), {
      status,
      headers: { server },
    });
  };
}
test('verifies every released file, including the signing core', async () => {
  await verifyDeployment('https://deployment.example/', build, fixture());
});
test('refuses old HTML, old JavaScript and old signing WASM', async () => {
  for (const path of ['index.html', 'assets/release.js', 'wasm/stackwallet_wasm_bg.wasm'])
    await assert.rejects(
      verifyDeployment('https://deployment.example', build, fixture(path)),
      /differs/,
    );
});
test('refuses failed responses and the wrong deployment server', async () => {
  await assert.rejects(
    verifyDeployment('https://deployment.example', build, fixture('', 503)),
    /200/,
  );
  await assert.rejects(
    verifyDeployment('https://deployment.example', build, fixture('', 200, 'other')),
    /Cloudflare/,
  );
});
