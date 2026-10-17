import { describe, expect, it } from 'vitest';

import { createDefaultRegistry } from '../data/registry.js';
import { adapterOrNull } from './chains.js';
import {
  keySiblings,
  POINT_DERIVED,
  siblingCurve,
  siblingsHint,
  signsAtPath,
  walletReach,
} from './key-siblings.js';

const registry = createDefaultRegistry();

// BIP39 "abandon ×11 about" at m/44'/60'/0'/0/0 (public, the MetaMask test vector).
const EVM_KEY = '0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299';
const EVM_ADDRESS = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
// The Ed25519 base point, a valid public key on every ed25519 family.
const ED_KEY = '5866666666666666666666666666666666666666666666666666666666666666';

const evmAccount = { family: 'evm' as const, chainId: 'eip155:1', publicKeyHex: EVM_KEY };
const solAccount = {
  family: 'solana' as const,
  chainId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  publicKeyHex: ED_KEY,
};

describe('siblingCurve', () => {
  it('recognises point keys and rejects family-specific ones', () => {
    expect(siblingCurve(evmAccount)).toBe('secp256k1');
    expect(siblingCurve(solAccount)).toBe('ed25519');
    // Cardano stores payment || stake (64 bytes); not a point anyone else can use.
    expect(siblingCurve({ family: 'cardano', publicKeyHex: ED_KEY + ED_KEY })).toBeNull();
    // Starknet stores the ground Stark key, Chia a 48-byte G1 point.
    expect(siblingCurve({ family: 'starknet', publicKeyHex: EVM_KEY })).toBeNull();
    expect(siblingCurve({ family: 'chia', publicKeyHex: 'ab'.repeat(48) })).toBeNull();
    expect(siblingCurve({ family: 'evm', publicKeyHex: '' })).toBeNull();
    expect(siblingCurve({ family: 'evm', publicKeyHex: '04' + 'ab'.repeat(64) })).toBeNull();
  });
});

describe('keySiblings', () => {
  it('maps one secp256k1 key onto every point-derived family and nothing else', () => {
    const rows = keySiblings(registry, evmAccount);
    const families = new Set(rows.map((r) => r.family));
    for (const f of POINT_DERIVED.secp256k1) if (f !== 'evm') expect(families.has(f)).toBe(true);
    expect(families.has('evm')).toBe(false);
    for (const f of ['starknet', 'neo', 'chia', 'antelope', 'solana', 'cardano'] as const)
      expect(families.has(f)).toBe(false);
    // Hypercore speaks lowercase hex on the wire; the account is the same one.
    const hl = rows.find((r) => r.family === 'hyperliquid' && !r.testnet)!;
    expect(hl.address).toBe(EVM_ADDRESS.toLowerCase());
    expect(rows.find((r) => r.family === 'gala' && !r.testnet)!.address).toBe(
      `eth|${EVM_ADDRESS.slice(2)}`,
    );
    expect(rows.find((r) => r.family === 'tron')!.address).toMatch(/^T[1-9A-HJ-NP-Za-km-z]{33}$/);
    expect(rows.find((r) => r.family === 'cosmos' && !r.testnet)!.address).toMatch(/^[a-z]+1/);
  });

  it('maps one ed25519 key onto every ed25519 point family and skips secret-derived ones', () => {
    const rows = keySiblings(registry, solAccount);
    const families = new Set(rows.map((r) => r.family));
    for (const f of POINT_DERIVED.ed25519) if (f !== 'solana') expect(families.has(f)).toBe(true);
    for (const f of ['cardano', 'waves', 'mixin', 'qubic', 'aleo', 'canton', 'evm'] as const)
      expect(families.has(f)).toBe(false);
    expect(rows.find((r) => r.family === 'near')!.address).toBe(ED_KEY);
  });

  it('only prints addresses the target adapter itself accepts', () => {
    for (const account of [evmAccount, solAccount]) {
      for (const row of keySiblings(registry, account)) {
        for (const chain of row.chains) {
          const adapter = adapterOrNull(registry, chain.chainId)!;
          expect(
            adapter.validateAddress(row.address, chain.chainId),
            `${chain.chainId} rejects ${row.address}`,
          ).toBe(true);
        }
      }
    }
  });

  it('groups chains that share an address, mainnets first, and memoises per key', () => {
    const rows = keySiblings(registry, evmAccount);
    const hl = rows.filter((r) => r.family === 'hyperliquid');
    expect(hl[0]!.testnet).toBe(false);
    expect(hl.flatMap((r) => r.chains).length).toBeGreaterThanOrEqual(2);
    const cosmos = rows.filter((r) => r.family === 'cosmos');
    expect(new Set(cosmos.map((r) => r.address)).size).toBe(cosmos.length);
    expect(keySiblings(registry, evmAccount)[0]!.chains).toBe(rows[0]!.chains);
  });

  it('marks rows the wallet already holds', () => {
    const tron = keySiblings(registry, evmAccount).find((r) => r.family === 'tron')!;
    const held = keySiblings(registry, evmAccount, [
      { id: 'a', chainId: tron.chains[0]!.chainId, address: tron.address },
      { id: 'b', chainId: 'eip155:1', address: EVM_ADDRESS },
    ]);
    expect(held.find((r) => r.family === 'tron')!.heldOn).toEqual([tron.chains[0]!.chainId]);
    expect(held.find((r) => r.family === 'hyperliquid')!.heldOn).toEqual([]);
  });

  it('returns nothing for keys that are not points', () => {
    expect(
      keySiblings(registry, {
        family: 'cardano',
        chainId: 'cip34:1-764824073',
        publicKeyHex: ED_KEY + ED_KEY,
      }),
    ).toEqual([]);
    expect(keySiblings(registry, { family: 'evm', chainId: 'eip155:1', publicKeyHex: '' })).toEqual(
      [],
    );
  });
});

describe('signsAtPath', () => {
  it('binds Bitcoin-style testnet signing to coin-type-1 paths and lets others through', () => {
    expect(signsAtPath({ family: 'bitcoin' }, "m/84'/1'/0'/0/0")).toBe(true);
    expect(signsAtPath({ family: 'bitcoin' }, "m/44'/60'/0'/0/0")).toBe(false);
    expect(signsAtPath({ family: 'btcfork' }, "m/44'/1'/0'/0/0")).toBe(true);
    expect(signsAtPath({ family: 'btcfork' }, "m/44'/5'/0'/0/0")).toBe(false);
    expect(signsAtPath({ family: 'everscale' }, "m/44'/1'/0'/0'/0'")).toBe(true);
    expect(signsAtPath({ family: 'everscale' }, "m/44'/396'/0'/0'/0'")).toBe(false);
    expect(signsAtPath({ family: 'solana' }, "m/44'/60'/0'/0/0")).toBe(true);
    expect(signsAtPath({ family: 'cosmos' }, "m/44'/60'/0'/0/0")).toBe(true);
  });
});

describe('hints', () => {
  it('summarises mainnet families and the wallet-level reach', () => {
    const hint = siblingsHint(keySiblings(registry, evmAccount));
    expect(hint).toMatch(/^Same key on \d+ other families: /);
    expect(hint).toContain('+');
    expect(siblingsHint([])).toBeNull();
    const reach = walletReach(registry, [
      { ...evmAccount },
      { family: 'tron', chainId: 'tron:0x2b6653dc', publicKeyHex: EVM_KEY },
    ]);
    expect(reach).not.toContain('evm');
    expect(reach).not.toContain('tron');
    expect(reach).toContain('cosmos');
  });
});
