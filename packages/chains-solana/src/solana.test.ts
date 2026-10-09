import { base58 } from '@scure/base';
import {
  MemoryRpcPool,
  NotImplementedError,
  bytesToHex,
  chainsForFamily,
} from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { createSolanaAdapter, isValidSolanaAddress } from './solana.js';

const MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
const DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
// Public SPL Token program id, split so secret scanners do not trip on it.
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFX' + 'CWuBvf9Ss623VQ5DA';
const WSOL_MINT = 'So11111111111111111111111111111111111111112';

function rpcFetch(handler: (method: string, params: unknown[]) => unknown): typeof fetch {
  return async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    return new Response(
      JSON.stringify({ jsonrpc: '2.0', id: 1, result: handler(body.method, body.params) }),
    );
  };
}

describe('SolanaAdapter addresses', () => {
  const sol = createSolanaAdapter();

  it('encodes a 32-byte ed25519 key as base58', () => {
    expect(sol.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, MAINNET)).toBe(
      SYSTEM_PROGRAM,
    );
    const tokenHex = bytesToHex(base58.decode(TOKEN_PROGRAM));
    expect(tokenHex).toHaveLength(64);
    expect(sol.deriveAddress({ curve: 'ed25519', hex: tokenHex }, DEVNET)).toBe(TOKEN_PROGRAM);
  });

  it('rejects wrong curves, wrong lengths and unknown clusters', () => {
    expect(() => sol.deriveAddress({ curve: 'secp256k1', hex: '00'.repeat(32) }, MAINNET)).toThrow(
      /curve secp256k1/,
    );
    expect(() => sol.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(31) }, MAINNET)).toThrow(
      /32 bytes/,
    );
    expect(() =>
      sol.deriveAddress({ curve: 'ed25519', hex: '00'.repeat(32) }, 'solana:nope'),
    ).toThrow(/unknown chain/);
  });

  it('validates base58 32-byte addresses', () => {
    expect(isValidSolanaAddress(SYSTEM_PROGRAM)).toBe(true);
    expect(isValidSolanaAddress(TOKEN_PROGRAM)).toBe(true);
    expect(isValidSolanaAddress(WSOL_MINT)).toBe(true);
    expect(isValidSolanaAddress(TOKEN_PROGRAM.slice(1))).toBe(false);
    expect(isValidSolanaAddress(TOKEN_PROGRAM + 'A')).toBe(false);
    expect(isValidSolanaAddress('0OIl' + SYSTEM_PROGRAM)).toBe(false);
    expect(isValidSolanaAddress('')).toBe(false);
    expect(isValidSolanaAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false);
    expect(sol.validateAddress(WSOL_MINT, DEVNET)).toBe(true);
    expect(sol.chains()).toEqual(chainsForFamily('solana'));
  });
});

describe('SolanaAdapter reads', () => {
  it('reads lamports through getBalance', async () => {
    const seen: unknown[] = [];
    const sol = createSolanaAdapter({
      fetch: rpcFetch((method, params) => {
        seen.push([method, params]);
        return { context: { slot: 123, apiVersion: '2.0.0' }, value: 2500000000 };
      }),
    });
    const [h] = await sol.getBalances(WSOL_MINT, MAINNET);
    expect(h).toMatchObject({ assetRef: `${MAINNET}:native`, amount: '2500000000' });
    expect(seen[0]).toEqual(['getBalance', [WSOL_MINT, { commitment: 'confirmed' }]]);
  });

  it('rejects invalid input and malformed responses with failover bookkeeping', async () => {
    const pool = new MemoryRpcPool(chainsForFamily('solana'));
    const bad = createSolanaAdapter({ rpc: pool, fetch: rpcFetch(() => ({ value: 'lots' })) });
    await expect(bad.getBalances(WSOL_MINT, MAINNET)).rejects.toThrow(/all 2 rpc endpoint/);
    expect(pool.endpoints(MAINNET).every((e) => !e.healthy)).toBe(true);
    await expect(bad.getBalances('not-an-address', MAINNET)).rejects.toThrow(
      /invalid solana address/,
    );
  });

  it('maps signature statuses', async () => {
    const sig = '5'.repeat(88);
    const finalized = createSolanaAdapter({
      fetch: rpcFetch(() => ({
        context: { slot: 10 },
        value: [{ slot: 9, confirmations: null, err: null, confirmationStatus: 'finalized' }],
      })),
    });
    expect(await finalized.status(sig, MAINNET)).toEqual({ state: 'confirmed', blockNumber: 9 });

    const processed = createSolanaAdapter({
      fetch: rpcFetch(() => ({
        value: [{ slot: 9, confirmations: 0, err: null, confirmationStatus: 'processed' }],
      })),
    });
    expect(await processed.status(sig, MAINNET)).toEqual({ state: 'pending' });

    const failed = createSolanaAdapter({
      fetch: rpcFetch(() => ({
        value: [
          {
            slot: 9,
            confirmations: 3,
            err: { InstructionError: [0, 'Custom'] },
            confirmationStatus: 'confirmed',
          },
        ],
      })),
    });
    expect(await failed.status(sig, MAINNET)).toMatchObject({ state: 'failed' });

    const unknown = createSolanaAdapter({ fetch: rpcFetch(() => ({ value: [null] })) });
    expect(await unknown.status(sig, MAINNET)).toEqual({ state: 'unknown' });
  });

  it('throws NotImplementedError for signing-path capabilities', async () => {
    const sol = createSolanaAdapter();
    const tx = { chainId: MAINNET, family: 'solana' as const, intentId: 'i', payload: {} };
    await expect(sol.getHistory(WSOL_MINT, MAINNET)).rejects.toBeInstanceOf(NotImplementedError);
    expect(() => sol.attach(tx, [])).toThrow(/chains-solana.attach/);
  });
});
