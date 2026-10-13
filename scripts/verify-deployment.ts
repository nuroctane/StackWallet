import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

export async function verifyDeployment(
  site: string,
  build: string,
  doFetch: typeof fetch = fetch,
): Promise<void> {
  const files = readdirSync(build, { recursive: true })
    .filter((path) => typeof path === 'string' && statSync(join(build, path)).isFile())
    .map((path) => String(path).replaceAll('\\', '/'))
    .filter(
      (path) =>
        !path.split('/').some((part) => part.startsWith('.')) &&
        !['_headers', '_redirects'].includes(path),
    );
  if (!files.includes('index.html') || !files.includes('wasm/stackwallet_wasm_bg.wasm'))
    throw new Error('Release build is missing HTML or WASM');
  for (const path of files) {
    const url = new URL(
      path === 'index.html' ? './' : path,
      site.endsWith('/') ? site : site + '/',
    );
    url.searchParams.set('verify', process.env.GITHUB_SHA ?? 'local');
    const response = await doFetch(url, { cache: 'no-store', signal: AbortSignal.timeout(10_000) });
    if (response.status !== 200 || response.headers.get('server') !== 'cloudflare')
      throw new Error(`Published ${path} did not return 200 from Cloudflare`);
    const expected = readFileSync(join(build, path));
    const actual = Buffer.from(await response.arrayBuffer());
    const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
    if (hash(expected) !== hash(actual))
      throw new Error(`Published ${path} differs from release build`);
  }
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] ?? '')).href) {
  const site = process.env.SITE_URL ?? 'https://stackwallet.civetadeicollegium.workers.dev';
  const build = resolve(process.env.STACKWALLET_BUILD_DIR ?? 'apps/web/dist');
  for (let attempt = 0; ; attempt++) {
    try {
      await verifyDeployment(site, build);
      console.log('Cloudflare serves the exact release HTML, assets and WASM.');
      break;
    } catch (error) {
      if (attempt >= 11) throw error;
      console.warn(error instanceof Error ? error.message : String(error));
      await delay(5_000);
    }
  }
}
