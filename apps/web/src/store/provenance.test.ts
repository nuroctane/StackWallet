import type { ProvenanceTable } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import { setTags, walletTags } from './provenance.js';

const table: ProvenanceTable = {
  wallets: [
    { walletId: 'local', origin: { kind: 'created', atMs: 1 }, exposures: [], transfers: [] },
    {
      walletId: 'exposed',
      origin: { kind: 'created', atMs: 1 },
      exposures: [{ atMs: 2, channel: 'clipboard', what: { kind: 'mnemonic' } }],
      transfers: [],
    },
    {
      walletId: 'arrived',
      origin: {
        kind: 'importedFromDevice',
        atMs: 3,
        deviceId: 'd',
        deviceName: 'phone',
        bundleId: 'b',
      },
      exposures: [{ atMs: 2, channel: 'screen', what: { kind: 'mnemonic' } }],
      transfers: [],
    },
    {
      walletId: 'sent',
      origin: { kind: 'created', atMs: 1 },
      exposures: [],
      transfers: [{ atMs: 4, toDeviceId: 'd', bundleId: 'b' }],
    },
  ],
  sets: [
    {
      folderId: 'f',
      origin: {
        kind: 'importedFromDevice',
        atMs: 3,
        deviceId: 'd',
        deviceName: 'phone',
        bundleId: 'b',
      },
      transfers: [],
    },
  ],
};

const kinds = (id: string, kind: 'single' | 'watch' = 'single') =>
  walletTags(table, { id, kind }).map((t) => t.kind);

describe('provenance tags', () => {
  it('maps history to the tags the user always sees', () => {
    expect(kinds('local')).toEqual(['local']);
    expect(kinds('exposed')).toEqual(['exposed']);
    expect(kinds('arrived')).toEqual(['exposed', 'imported']);
    expect(kinds('sent')).toEqual(['exported']);
    expect(kinds('unknown')).toEqual(['local']);
    expect(kinds('unknown', 'watch')).toEqual([]);
    expect(walletTags(table, { id: 'arrived', kind: 'single' })[1]?.detail).toContain('phone');
  });

  it('adds a locked approvals tag for open allowances on any wallet kind', () => {
    const tags = walletTags(
      table,
      { id: 'unknown', kind: 'watch' },
      { tokens: 2, collectibles: 1 },
    );
    expect(tags.map((t) => t.kind)).toEqual(['approvals']);
    expect(tags[0]!.label).toBe('approvals 3');
    expect(tags[0]!.detail).toContain('2 token allowances and 1 collectible approval');
    expect(kinds('unknown', 'watch')).toEqual([]);
    expect(
      walletTags(table, { id: 'local', kind: 'single' }, { tokens: 0, collectibles: 0 }).map(
        (t) => t.kind,
      ),
    ).toEqual(['local']);
  });

  it('tags whole sets', () => {
    expect(setTags(table, 'f').map((t) => t.kind)).toEqual(['imported']);
    expect(setTags(table, 'nope')).toEqual([]);
  });
});
