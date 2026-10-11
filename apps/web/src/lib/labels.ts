import type { Account, Ledger, Wallet } from '@stackwallet/core-client';
import { SERVICE_LABEL, type NameRecord } from '@stackwallet/names';

/**
 * Where a label came from, always shown next to it. Ordered by trust: the
 * user's own wallets first, then names that were verified both ways, then
 * the bundled registry. Nothing else ever names an address.
 */
export type LabelSource = 'wallet' | 'name' | 'known' | 'none';

export interface AddressLabel {
  address: string;
  label: string | null;
  source: LabelSource;
  /** Human-readable source, e.g. "your wallet", "ENS", "known contract". */
  sourceText: string;
  nonAscii: boolean;
  /** First time this directory's ledger sent to the address; null means never. */
  firstSeenMs: number | null;
}

interface Known {
  name: string;
  /** Chains where the label applies; omitted means the address is the same everywhere. */
  chains?: readonly string[];
}

/**
 * Contracts users meet most often. Checksummed addresses; keys are compared
 * lowercased. Kept small on purpose: a wrong entry here would be worse than none.
 */
export const KNOWN_CONTRACTS: Readonly<Record<string, Known>> = {
  '0x000000000022d473030f116ddee9f6b43ac78ba3': { name: 'Uniswap Permit2' },
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { name: 'USDC', chains: ['eip155:1'] },
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { name: 'USDT', chains: ['eip155:1'] },
  '0x6b175474e89094c44da98b954eedeac495271d0f': { name: 'DAI', chains: ['eip155:1'] },
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': { name: 'WETH', chains: ['eip155:1'] },
  '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { name: 'USDC', chains: ['eip155:8453'] },
  '0x4200000000000000000000000000000000000006': {
    name: 'WETH',
    chains: ['eip155:8453', 'eip155:10'],
  },
  '0xaf88d065e77c8cc2239327c5edb3a432268e5831': { name: 'USDC', chains: ['eip155:42161'] },
  '0x0b2c639c533813f4aa9d7837caf62653d097ff85': { name: 'USDC', chains: ['eip155:10'] },
  '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': { name: 'USDC', chains: ['eip155:137'] },
  '0x1c7d4b196cb0c7b01d743fbc6116a902379c7238': {
    name: 'USDC (test)',
    chains: ['eip155:11155111'],
  },
  '0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e': { name: 'ENS Registry' },
};

export interface LabelInputs {
  wallets: readonly Pick<Wallet, 'id' | 'name' | 'kind'>[];
  accounts: readonly Account[];
  /** Verified names keyed by lowercased EVM address (or exact address elsewhere). */
  names: ReadonlyMap<string, NameRecord>;
  walletText: (walletId: string) => string;
  ledger: Ledger | null;
}

const norm = (a: string) => (a.startsWith('0x') ? a.toLowerCase() : a);

/** First send to `address` recorded in the ledger, for the "first seen" line. */
export function firstSeen(ledger: Ledger | null, address: string): number | null {
  if (!ledger) return null;
  const a = norm(address);
  let first: number | null = null;
  for (const t of ledger.txs) {
    const i = t.intent;
    if ((i.kind === 'transfer' || i.kind === 'contractCall') && norm(i.to) === a) {
      first = first === null ? t.createdAtMs : Math.min(first, t.createdAtMs);
    }
  }
  return first;
}

export function labelFor(address: string, chainId: string, inputs: LabelInputs): AddressLabel {
  const a = norm(address);
  const base = { address, nonAscii: false, firstSeenMs: firstSeen(inputs.ledger, address) };
  const own = inputs.accounts.find((acc) => norm(acc.address) === a);
  const wallet = own && inputs.wallets.find((w) => w.id === own.walletId);
  if (own && wallet) {
    return {
      ...base,
      label: inputs.walletText(own.walletId),
      source: 'wallet',
      // A watched address is in the directory but holds no key here: not "yours".
      sourceText: wallet.kind === 'watch' ? 'watched' : 'your wallet',
    };
  }
  const name = inputs.names.get(a);
  if (name) {
    return {
      ...base,
      label: name.name,
      source: 'name',
      sourceText: SERVICE_LABEL[name.service],
      nonAscii: name.nonAscii,
    };
  }
  const known = KNOWN_CONTRACTS[a];
  if (known && (!known.chains || known.chains.includes(chainId))) {
    return { ...base, label: known.name, source: 'known', sourceText: 'known contract' };
  }
  return { ...base, label: null, source: 'none', sourceText: 'unknown' };
}
