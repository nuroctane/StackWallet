import { shortAddress, type ChainInfo, type ChainRegistry } from '@stackwallet/chains';
import type { Account, ChainFamily } from '@stackwallet/core-client';

import { adapterOrNull, FAMILY_ORDER, listChains } from './chains.js';

export type SiblingCurve = 'secp256k1' | 'ed25519';

/**
 * Families whose account address is a pure function of the standard curve
 * point, so one key is the same owner on every one of them. Families that
 * hash a secret-derived key instead (Cardano Icarus, Starknet grindKey, Chia
 * BLS, Waves Curve25519, Mixin spend||view, Qubic FourQ), families whose
 * identity is not a receivable account (Antelope keys, Canton party
 * fingerprints) and read-only families (NEO, Aleo) stay out: the adapter
 * would either throw or, worse, print an address nobody controls.
 */
export const POINT_DERIVED: Record<SiblingCurve, readonly ChainFamily[]> = {
  secp256k1: [
    'evm',
    'bitcoin',
    'cosmos',
    'tron',
    'xrpl',
    'hyperliquid',
    'stacks',
    'vechain',
    'icp',
    'ergo',
    'icon',
    'alephium',
    'fuel',
    'aelf',
    'obyte',
    'chromia',
    'keeta',
    'btcfork',
    'gala',
  ],
  ed25519: [
    'solana',
    'substrate',
    'sui',
    'aptos',
    'stellar',
    'near',
    'ton',
    'algorand',
    'tezos',
    'multiversx',
    'everscale',
    'radix',
    'aeternity',
    'starcoin',
    'namada',
  ],
};

const POINT_LENGTH: Record<SiblingCurve, number> = { secp256k1: 66, ed25519: 64 };

export interface KeySibling {
  family: ChainFamily;
  /** Every chain in `family` on which this key has exactly this address, mainnets first. */
  chains: ChainInfo[];
  address: string;
  /** True when every chain in the group is a testnet. */
  testnet: boolean;
  /** Chain ids among `chains` on which the same wallet already holds this address. */
  heldOn: string[];
}

/** The curve a stored account key is a point on, or null when it is a family-specific key. */
export function siblingCurve(
  account: Pick<Account, 'family' | 'publicKeyHex'>,
): SiblingCurve | null {
  const hex = account.publicKeyHex.toLowerCase();
  for (const curve of ['secp256k1', 'ed25519'] as const) {
    if (!POINT_DERIVED[curve].includes(account.family)) continue;
    if (hex.length !== POINT_LENGTH[curve] || !/^[0-9a-f]+$/.test(hex)) return null;
    if (curve === 'secp256k1' && !/^0[23]/.test(hex)) return null;
    return curve;
  }
  return null;
}

/**
 * Whether the core would sign on `chain` with a key at `path`. Bitcoin-style
 * families carry no network id in their signatures, so the core binds testnet
 * signing to coin-type-1 paths; a sibling account added under another family's
 * path still receives and is watched, but Send stays off for it.
 */
export function signsAtPath(chain: Pick<ChainInfo, 'family'>, path: string): boolean {
  switch (chain.family) {
    case 'bitcoin':
      return path.startsWith("m/84'/1'/");
    case 'btcfork':
    case 'everscale':
      return path.startsWith("m/44'/1'/");
    default:
      return true;
  }
}

type Cache = Map<string, KeySibling[]>;
const CACHES = new WeakMap<ChainRegistry, Cache>();

/**
 * The addresses `account`'s key owns on every other point-derived family,
 * grouped by family and address (Cosmos prefixes, SS58 formats and
 * mainnet/testnet encodings split one family into several rows). Pure and
 * memoized per registry and key; `holders` only decorates the result.
 */
export function keySiblings(
  registry: ChainRegistry,
  account: Pick<Account, 'family' | 'publicKeyHex' | 'chainId'>,
  holders: readonly Pick<Account, 'id' | 'chainId' | 'address'>[] = [],
): KeySibling[] {
  const curve = siblingCurve(account);
  if (!curve) return [];
  let cache = CACHES.get(registry);
  if (!cache) {
    cache = new Map();
    CACHES.set(registry, cache);
  }
  const key = `${curve}:${account.publicKeyHex.toLowerCase()}:${account.family}`;
  let rows = cache.get(key);
  if (!rows) {
    rows = derive(registry, curve, account.publicKeyHex.toLowerCase(), account.family);
    cache.set(key, rows);
  }
  if (holders.length === 0) return rows.map((r) => ({ ...r, heldOn: [] }));
  return rows.map((r) => ({
    ...r,
    heldOn: holders
      .filter((h) => h.address === r.address && r.chains.some((c) => c.chainId === h.chainId))
      .map((h) => h.chainId),
  }));
}

function derive(
  registry: ChainRegistry,
  curve: SiblingCurve,
  hex: string,
  own: ChainFamily,
): KeySibling[] {
  const byFamily = new Map<ChainFamily, Map<string, ChainInfo[]>>();
  for (const chain of listChains(registry)) {
    if (chain.family === own || !POINT_DERIVED[curve].includes(chain.family)) continue;
    const adapter = adapterOrNull(registry, chain.chainId);
    if (!adapter) continue;
    let address: string;
    try {
      address = adapter.deriveAddress({ curve, hex }, chain.chainId);
    } catch {
      continue;
    }
    let groups = byFamily.get(chain.family);
    if (!groups) {
      groups = new Map();
      byFamily.set(chain.family, groups);
    }
    const list = groups.get(address) ?? [];
    list.push(chain);
    groups.set(address, list);
  }
  const out: KeySibling[] = [];
  for (const family of FAMILY_ORDER) {
    const groups = byFamily.get(family);
    if (!groups) continue;
    const rows = [...groups.entries()].map(([address, chains]) => {
      chains.sort((a, b) => Number(a.testnet) - Number(b.testnet) || a.name.localeCompare(b.name));
      return { family, address, chains, testnet: chains.every((c) => c.testnet), heldOn: [] };
    });
    // Mainnet rows first, then by how many chains share the address.
    rows.sort((a, b) => Number(a.testnet) - Number(b.testnet) || b.chains.length - a.chains.length);
    out.push(...rows);
  }
  return out;
}

/**
 * Families a wallet's keys reach on mainnet beyond the ones it already holds
 * accounts on, in catalogue order. Feeds the wallet-level hover hint.
 */
export function walletReach(
  registry: ChainRegistry,
  accounts: readonly Pick<Account, 'family' | 'publicKeyHex' | 'chainId'>[],
): ChainFamily[] {
  const held = new Set(accounts.map((a) => a.family));
  const reach = new Set<ChainFamily>();
  for (const a of accounts) {
    for (const row of keySiblings(registry, a)) {
      if (!row.testnet && !held.has(row.family)) reach.add(row.family);
    }
  }
  return FAMILY_ORDER.filter((f) => reach.has(f));
}

/** One line for a hover hint: mainnet rows only, trimmed to `max` families. */
export function siblingsHint(rows: readonly KeySibling[], max = 6): string | null {
  const main = rows.filter((r) => !r.testnet);
  const families = [...new Set(main.map((r) => r.family))];
  if (families.length === 0) return null;
  const shown = families.slice(0, max).map((f) => {
    const row = main.find((r) => r.family === f)!;
    return `${row.chains[0]!.name} ${shortAddress(row.address, 8, 4)}`;
  });
  const more = families.length - shown.length;
  return `Same key on ${families.length} other ${families.length === 1 ? 'family' : 'families'}: ${shown.join(', ')}${more > 0 ? ` +${more} more` : ''}. Click for every address.`;
}
