import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import {
  CANTON_CHAINS,
  CANTON_MAINNET,
  CANTON_TESTNET,
  CantonAdapter,
  cantonFingerprint,
  cantonPartyId,
  createCantonAdapter,
  isValidCantonPartyId,
} from './canton.js';

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));

// `@canton-network/wallet-sdk` vectors (`.nur/canton-oracle/oracle3.mjs`);
// the Rust core (`canton.rs`) pins the same values.
const PUB_ZEROS = '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29';
const FP_ZEROS = '1220e5a40f14dfbef0e161b3c7f9bb2b03695c984659d4c9489e669ecd8249c0b745';
const PUB_SEVENS = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c';
const FP_SEVENS = '12205822a4a1eae801223c158e256fef229d956e3911284b9c3a7956200f61787ca6';
const PARTY = `alice-1::${FP_ZEROS}`;
const DSO = `DSO::${FP_SEVENS}`;
const UPDATE_ID = 'cafe0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01';

const RPC_A = 'https://scan-a.test';
const RPC_B = 'https://scan-b.test';

const CHAINS: ChainInfo[] = [{ ...CANTON_CHAINS[0]!, defaultRpcs: [RPC_A, RPC_B] }];

class TestAdapter extends CantonAdapter {
  override chains(): ChainInfo[] {
    return CHAINS;
  }
}

type Route = (url: URL, body: unknown) => Response;

function node(routes: Record<string, Route>, dso = DSO) {
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (url.pathname === '/api/scan/v0/dso-party-id')
      return Response.json({ dso_party_id: dso });
    const route = routes[url.pathname];
    if (!route) return new Response('not found', { status: 404 });
    return route(url, body);
  }) as typeof fetch;
  return { fetchImpl };
}

const adapter = (fetchImpl: typeof fetch) =>
  new TestAdapter({ fetch: fetchImpl, rpc: new MemoryRpcPool(CHAINS) });

describe('canton fingerprints and party ids', () => {
  it('matches the wallet-sdk fingerprints byte for byte', () => {
    expect(cantonFingerprint(hexToBytes(PUB_ZEROS))).toBe(FP_ZEROS);
    expect(cantonFingerprint(hexToBytes(PUB_SEVENS))).toBe(FP_SEVENS);
  });
  it('builds and validates party ids', () => {
    expect(cantonPartyId('alice-1', hexToBytes(PUB_ZEROS))).toBe(PARTY);
    expect(isValidCantonPartyId(PARTY)).toBe(true);
  });
  it('rejects malformed party ids', () => {
    expect(isValidCantonPartyId(FP_ZEROS)).toBe(false); // missing hint
    expect(isValidCantonPartyId(`::${FP_ZEROS}`)).toBe(false); // empty hint
    expect(isValidCantonPartyId(`Alice::${FP_ZEROS}`)).toBe(false); // uppercase hint
    expect(isValidCantonPartyId(`alice::${FP_ZEROS}::extra`)).toBe(false); // ambiguous
    expect(isValidCantonPartyId(`alice::${FP_ZEROS.slice(4)}`)).toBe(false); // no 1220
    expect(isValidCantonPartyId(`alice::${FP_ZEROS.toUpperCase()}`)).toBe(false);
    expect(() => cantonFingerprint(new Uint8Array(31))).toThrow();
  });
  it('derives the fingerprint form from an ed25519 public key', () => {
    const a = adapter(node({}).fetchImpl);
    expect(a.deriveAddress({ curve: 'ed25519', hex: PUB_ZEROS }, CANTON_MAINNET)).toBe(FP_ZEROS);
    expect(() =>
      a.deriveAddress({ curve: 'secp256k1', hex: `02${PUB_ZEROS}` }, CANTON_MAINNET),
    ).toThrow();
  });
});

describe('canton adapter reads', () => {
  const summaryRoute: Record<string, Route> = {
    '/api/scan/v0/state/acs/snapshot-timestamp': () =>
      Response.json({ record_time: '2026-10-17T00:00:00.000000Z', migration_id: 4 }),
    '/api/scan/v1/holdings/summary': (_url, body) => {
      const req = body as { owner_party_ids: string[]; migration_id: number };
      expect(req.migration_id).toBe(4);
      return Response.json({
        record_time: '2026-10-17T00:00:00.000000Z',
        migration_id: 4,
        summaries: req.owner_party_ids.map((party_id) => ({
          party_id,
          total_unlocked_coin: '12.5',
          total_locked_coin: '0',
          total_coin_holdings: '12.5',
        })),
      });
    },
  };
  it('reads the CC balance from the holdings summary, cross-checked', async () => {
    const holdings = await adapter(node(summaryRoute).fetchImpl).getBalances(PARTY, CANTON_MAINNET);
    expect(holdings[0]!.amount).toBe('125000000000'); // 12.5 CC in base units
    expect(holdings[0]!.assetRef).toBe(`${CANTON_MAINNET}:native`);
  });
  it('reports zero for a party with no holdings', async () => {
    const routes: Record<string, Route> = {
      '/api/scan/v0/state/acs/snapshot-timestamp': summaryRoute['/api/scan/v0/state/acs/snapshot-timestamp']!,
      '/api/scan/v1/holdings/summary': () =>
        Response.json({ record_time: 't', migration_id: 4, summaries: [] }),
    };
    const holdings = await adapter(node(routes).fetchImpl).getBalances(PARTY, CANTON_MAINNET);
    expect(holdings[0]!.amount).toBe('0');
  });
  it('rejects invalid party ids', async () => {
    await expect(
      adapter(node({}).fetchImpl).getBalances(`Alice::${FP_ZEROS}`, CANTON_MAINNET),
    ).rejects.toThrow();
  });
});

describe('canton status', () => {
  it('confirms an update by hash', async () => {
    const routes: Record<string, Route> = {
      [`/api/scan/v2/updates/hash/${UPDATE_ID}`]: () =>
        Response.json({ update: { update_id: UPDATE_ID, record_time: '2026-10-17T00:00:01Z' } }),
    };
    const s = await adapter(node(routes).fetchImpl).status(UPDATE_ID, CANTON_MAINNET);
    expect(s.state).toBe('confirmed');
    expect(s.state === 'confirmed' ? s.timestampMs : 0).toBe(Date.parse('2026-10-17T00:00:01Z'));
  });
  it('reports absent updates as unknown', async () => {
    const s = await adapter(node({}).fetchImpl).status(UPDATE_ID, CANTON_MAINNET);
    expect(s.state).toBe('unknown');
  });
});

describe('canton misc', () => {
  it('reports the history gap instead of failing', async () => {
    const page = await adapter(node({}).fetchImpl).getHistory(PARTY, CANTON_MAINNET);
    expect(page.items).toEqual([]);
    expect(page.coverage).toMatch(/history/);
  });
  it('exposes the chain ids and factory', () => {
    expect(CANTON_MAINNET).toBe('canton:mainnet');
    expect(CANTON_TESTNET).toBe('canton:testnet');
    expect(createCantonAdapter({ rpc: new MemoryRpcPool(CHAINS) }).chains()[0]!.chainId).toBe(
      CANTON_MAINNET,
    );
  });
});
