import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

/**
 * Guards the two dependency CVEs fixed by this change so they do not regress:
 * - GHSA-xjj6-f33q-929c (undici DoS via excessive content-encodings): the
 *   resolved undici 7.x line must be >= 7.30.1, not the vulnerable 7.29.1.
 * - GHSA-mrhx-c7xc-m3w5 (zod memory exhaustion on oversized constrained
 *   collections): the resolved zod must be >= 4.6.6.
 */
const lockfile = readFileSync(new URL('../../../pnpm-lock.yaml', import.meta.url), 'utf8');

describe('dependency security pins', () => {
  it('resolves undici to the patched 7.x version (GHSA-xjj6-f33q-929c)', () => {
    expect(lockfile).toMatch(/^ {2}undici@7\.30\.1:/m);
    expect(lockfile).not.toMatch(/^ {2}undici@7\.29\.1:/m);
    expect(lockfile).not.toMatch(/undici: 7\.29\.1/);
  });

  it('resolves zod to the patched 4.6.6 (GHSA-mrhx-c7xc-m3w5)', () => {
    expect(lockfile).toMatch(/^ {2}zod@4\.6\.6:/m);
    expect(lockfile).not.toMatch(/^ {2}zod@4\.6\.5:/m);
    expect(lockfile).not.toMatch(/zod: 4\.6\.5/);
  });
});
