import { describe, expect, it } from 'vitest';

import { avatarCells } from '../shell/AddressAvatar.js';
import {
  cleanName,
  ConnectRejected,
  discoverWallets,
  parseAnnouncement,
  requestAddresses,
  safeIcon,
  type InjectedWallet,
} from './injected.js';

const A = '0x52908400098527886E0F7030069857D2E4169EE7';
const B = '0x8617E340B3D01FA5F11F306F4090FD50E238070D';

const provider = (answers: Record<string, unknown>) => ({
  request: async ({ method }: { method: string }) => {
    const a = answers[method];
    if (a instanceof Error || (typeof a === 'object' && a !== null && 'code' in a)) throw a;
    return a;
  },
});

describe('injected wallet announcements', () => {
  it('accepts only inline image icons', () => {
    expect(safeIcon('data:image/png;base64,iVBORw0KGgo=')).not.toBeNull();
    expect(safeIcon('data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=')).not.toBeNull();
    expect(safeIcon('https://evil.example/icon.png')).toBeNull();
    expect(safeIcon('data:image/svg+xml,<svg onload=alert(1)>')).toBeNull();
    expect(safeIcon('javascript:alert(1)')).toBeNull();
  });

  it('cleans names of controls and direction overrides', () => {
    expect(cleanName('Meta\u202eksaM')).toBe('MetaksaM');
    expect(cleanName('  ')).toBe('Browser wallet');
    expect(cleanName(42)).toBe('Browser wallet');
    expect(cleanName('x'.repeat(100))).toHaveLength(40);
  });

  it('rejects announcements without a provider or uuid', () => {
    expect(parseAnnouncement(null)).toBeNull();
    expect(parseAnnouncement({ info: { uuid: 'u' }, provider: {} })).toBeNull();
    expect(parseAnnouncement({ info: { name: 'x' }, provider: provider({}) })).toBeNull();
    expect(
      parseAnnouncement({
        info: { uuid: 'u', name: 'Rabby', rdns: 'io.rabby' },
        provider: provider({}),
      }),
    ).toMatchObject({
      uuid: 'u',
      name: 'Rabby',
      icon: null,
    });
  });

  it('collects announcements once each, and falls back to the legacy global', async () => {
    const target = new EventTarget() as unknown as Window;
    let seen: InjectedWallet[] = [];
    target.addEventListener('eip6963:requestProvider', () => {
      for (const uuid of ['a', 'a', 'b'])
        target.dispatchEvent(
          Object.assign(new Event('eip6963:announceProvider'), {
            detail: { info: { uuid, name: uuid }, provider: provider({}) },
          }),
        );
    });
    const stop = discoverWallets((w) => (seen = w), target);
    expect(seen.map((w) => w.uuid)).toEqual(['a', 'b']);
    stop();

    const bare = Object.assign(new EventTarget(), { ethereum: provider({}) }) as unknown as Window;
    const legacy = await new Promise<InjectedWallet[]>((resolve) => {
      const off = discoverWallets((w) => {
        off();
        resolve(w);
      }, bare);
    });
    expect(legacy[0]?.uuid).toBe('legacy');
  });
});

describe('requestAddresses', () => {
  const wallet = (answers: Record<string, unknown>): InjectedWallet => ({
    uuid: 'u',
    name: 'W',
    icon: null,
    rdns: '',
    provider: provider(answers),
  });

  it('keeps valid unique EVM addresses and reads the current chain', async () => {
    const out = await requestAddresses(
      wallet({ eth_requestAccounts: [A, A.toLowerCase(), 'nope', B, 7], eth_chainId: '0x2105' }),
    );
    expect(out.addresses).toEqual([A, B]);
    expect(out.chainId).toBe('eip155:8453');
  });

  it('reports a declined request plainly', async () => {
    await expect(
      requestAddresses(wallet({ eth_requestAccounts: { code: 4001 } })),
    ).rejects.toBeInstanceOf(ConnectRejected);
  });
});

describe('address avatar', () => {
  it('is stable, mirrored, and case-insensitive for EVM addresses', () => {
    const a = avatarCells(A);
    expect(avatarCells(A.toLowerCase())).toEqual(a);
    for (let row = 0; row < 5; row++) {
      expect(a.on[row * 5]).toBe(a.on[row * 5 + 4]);
      expect(a.on[row * 5 + 1]).toBe(a.on[row * 5 + 3]);
    }
    expect(avatarCells(B)).not.toEqual(a);
  });
});
