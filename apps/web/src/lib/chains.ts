import type { ChainFamily } from '@stackwallet/core-client';
import type { ChainAdapter, ChainInfo, ChainRegistry } from '@stackwallet/chains';

/** Registry calls are wrapped so a half-loaded adapter set degrades to "no chains" instead of a crash. */
export function listChains(registry: ChainRegistry): ChainInfo[] {
  try {
    return registry.chains();
  } catch {
    return [];
  }
}

export function findChain(registry: ChainRegistry, chainId: string): ChainInfo | undefined {
  try {
    return registry.chainInfo(chainId);
  } catch {
    return undefined;
  }
}

export function adapterOrNull(registry: ChainRegistry, chainId: string): ChainAdapter | null {
  try {
    return registry.adapterFor(chainId);
  } catch {
    return null;
  }
}

export function listFamilies(registry: ChainRegistry): ChainFamily[] {
  try {
    return registry.families();
  } catch {
    return [];
  }
}

export const FAMILY_LABEL: Record<ChainFamily, string> = {
  evm: 'EVM',
  bitcoin: 'BITCOIN',
  solana: 'SOLANA',
  cosmos: 'COSMOS',
  tron: 'TRON',
  substrate: 'SUBSTRATE',
  sui: 'SUI',
  aptos: 'APTOS',
  stellar: 'STELLAR',
  near: 'NEAR',
  ton: 'TON',
  xrpl: 'XRPL',
  cardano: 'CARDANO',
  algorand: 'ALGORAND',
  tezos: 'TEZOS',
  multiversx: 'MULTIVERSX',
  antelope: 'ANTELOPE',
  hyperliquid: 'HYPERLIQUID',
  stacks: 'STACKS',
  vechain: 'VECHAIN',
  starknet: 'STARKNET',
  icp: 'ICP',
  waves: 'WAVES',
  neo: 'NEO',
  ergo: 'ERGO',
  icon: 'ICON',
  alephium: 'ALEPHIUM',
  chia: 'CHIA',
  everscale: 'EVERSCALE',
  radix: 'RADIX',
  aeternity: 'AETERNITY',
  fuel: 'FUEL',
  aelf: 'AELF',
  starcoin: 'STARCOIN',
  obyte: 'OBYTE',
  chromia: 'CHROMIA',
  keeta: 'KEETA',
  namada: 'NAMADA',
  btcfork: 'BTC FORKS',
  gala: 'GALA',
  mixin: 'MIXIN',
  qubic: 'QUBIC',
  aleo: 'ALEO',
  canton: 'CANTON',
};

export const FAMILY_ORDER: ChainFamily[] = Object.keys(FAMILY_LABEL) as ChainFamily[];

const ACCOUNT_SEGMENT = new Set<ChainFamily>(['solana', 'substrate', 'stellar', 'sui']);
const TX_ROUTES: readonly [string, string][] = [
  ['/extrinsic/', 'account'],
  ['/txn/', 'account'],
  ['/txblock/', 'address'],
  ['/transactions/', 'accounts'],
  ['/txns/', 'address'],
  ['/txid/', 'address'],
  ['/transaction/', 'account'],
];

/**
 * Explorers publish a tx URL; the address page almost always lives next to it
 * (`/tx/<hash>` -> `/address/<addr>`, Solana explorers use `/account/`). When the
 * pattern does not fit, return nothing rather than guess a broken link.
 */
export function explorerAddressUrl(info: ChainInfo, address: string): string | undefined {
  const tpl = info.explorerTxUrl;
  // An Antelope identity is a key, while explorers page by account name.
  if (!tpl || info.family === 'antelope') return undefined;
  // tonviewer serves accounts at the root: /transaction/<h> -> /<addr>.
  if (info.family === 'ton' && tpl.includes('/transaction/')) {
    const root = tpl.slice(0, tpl.indexOf('/transaction/'));
    return /^https:\/\/[^/]+$/.test(root) ? `${root}/${encodeURIComponent(address)}` : undefined;
  }
  // TzKT serves operations and accounts at the root: /<op> -> /<addr>.
  if (info.family === 'tezos' && tpl.endsWith('/{hash}')) {
    const root = tpl.slice(0, -'/{hash}'.length);
    return /^https:\/\/[^/]+$/.test(root) ? `${root}/${encodeURIComponent(address)}` : undefined;
  }
  // VeChain testnet insight routes in the fragment: /#/test/txs/<h> -> /#/test/accounts/<a>.
  if (info.family === 'vechain' && tpl.includes('/#/test/txs/')) {
    const root = tpl.slice(0, tpl.indexOf('/#/test/txs/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/#/test/accounts/${encodeURIComponent(address)}`
      : undefined;
  }
  // Voyager pages accounts as contracts: /tx/<h> -> /contract/<a>.
  if (info.family === 'starknet' && tpl.includes('/tx/')) {
    const root = tpl.slice(0, tpl.indexOf('/tx/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/contract/${encodeURIComponent(address)}`
      : undefined;
  }
  // Blockchair and defiscan page addresses at /address/.
  if (
    info.family === 'btcfork' &&
    (tpl.includes('blockchair.com') || tpl.includes('defiscan.live'))
  ) {
    const root = tpl.slice(0, tpl.indexOf('/', 'https://'.length));
    return `${root}/address/${encodeURIComponent(address)}`;
  }
  // explorer.obyte.org routes the bare unit id at / and addresses at /address/.
  if (info.family === 'obyte') {
    const slash = tpl.indexOf('/', 'https://'.length);
    return slash > 0 ? `${tpl.slice(0, slash)}/address/${encodeURIComponent(address)}` : undefined;
  }
  // aelfscan pairs /tx/ with /address/ under the same chain segment.
  if (info.family === 'aelf') {
    return tpl.includes('/tx/')
      ? tpl.replace(/\/tx\/\{hash\}.*$/, `/address/${encodeURIComponent(address)}`)
      : undefined;
  }
  // explorer.ergoplatform pairs /en/transactions/ with /en/addresses/.
  if (info.family === 'ergo' && tpl.includes('/en/transactions/')) {
    const root = tpl.slice(0, tpl.indexOf('/en/transactions/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/en/addresses/${encodeURIComponent(address)}`
      : undefined;
  }
  // icpexplorer routes in the fragment: /#/tx/<h> -> /#/account/<a>.
  if (info.family === 'icp' && tpl.includes('/#/tx/')) {
    const root = tpl.slice(0, tpl.indexOf('/#/tx/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/#/account/${encodeURIComponent(address)}`
      : undefined;
  }
  // explorer.qubic.org pages identities under /network/address/, not beside /tx/.
  if (info.family === 'qubic' && tpl.includes('/tx/')) {
    const root = tpl.slice(0, tpl.indexOf('/tx/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/network/address/${encodeURIComponent(address)}`
      : undefined;
  }
  // stcscan keeps the network segment: /<net>/transactions/detail/<h> -> /<net>/address/<a>.
  if (info.family === 'starcoin' && tpl.includes('/transactions/')) {
    const prefix = tpl.slice(0, tpl.indexOf('/transactions/'));
    return /^https:\/\/[^/]+\/[^/]+$/.test(prefix)
      ? `${prefix}/address/${encodeURIComponent(address)}`
      : undefined;
  }
  // The Alephium explorer pairs /transactions/ with /addresses/.
  if (info.family === 'alephium' && tpl.includes('/transactions/')) {
    const root = tpl.slice(0, tpl.indexOf('/transactions/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/addresses/${encodeURIComponent(address)}`
      : undefined;
  }
  // Dora puts the network after the route: /transaction/neo3/<net>/<h> -> /address/neo3/<net>/<a>.
  if (info.family === 'neo' && tpl.includes('/transaction/') && tpl.endsWith('/{hash}')) {
    const idx = tpl.indexOf('/transaction/');
    const root = tpl.slice(0, idx);
    const network = tpl.slice(idx + '/transaction/'.length, -'/{hash}'.length);
    return /^https:\/\/[^/]+$/.test(root) && /^[a-z0-9/]+$/.test(network)
      ? `${root}/address/${network}/${encodeURIComponent(address)}`
      : undefined;
  }
  // explorer.provable.com pairs /transaction/ with /address/.
  if (info.family === 'aleo' && tpl.includes('/transaction/')) {
    const root = tpl.slice(0, tpl.indexOf('/transaction/'));
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/address/${encodeURIComponent(address)}`
      : undefined;
  }
  // Tronscan routes in the fragment: /#/transaction/<id> -> /#/address/<addr>.
  const hashRoute = tpl.indexOf('/#/transaction/');
  if (hashRoute >= 0) {
    const root = tpl.slice(0, hashRoute);
    return /^https:\/\/[^/]+$/.test(root)
      ? `${root}/#/address/${encodeURIComponent(address)}`
      : undefined;
  }
  // Subscan (/extrinsic/), the Aptos explorer (/txn/), IOTA (/txblock/) and the XRPL
  // explorer (/transactions/ -> /accounts/) name their routes differently.
  const named = TX_ROUTES.find(([r]) => tpl.includes(r));
  const route = named?.[0] ?? '/tx/';
  const idx = tpl.indexOf(route);
  if (idx < 0) return undefined;
  // Cardanoscan pairs /transaction/ with /address/, unlike the other /transaction/ explorers.
  const segment =
    info.family === 'cardano' || info.family === 'icon'
      ? 'address'
      : (named?.[1] ?? (ACCOUNT_SEGMENT.has(info.family) ? 'account' : 'address'));
  const base = tpl.slice(0, idx);
  if (!/^https:\/\/[^/]+/.test(base)) return undefined;
  let url: URL;
  try {
    url = new URL(`${base}/${segment}/${encodeURIComponent(address)}`);
  } catch {
    return undefined;
  }
  // Solana explorers encode the cluster as a query parameter; keep it from the template.
  const q = tpl.indexOf('?');
  if (q >= 0) {
    const params = new URLSearchParams(tpl.slice(q + 1));
    params.forEach((v, k) => {
      if (!/[{}]/.test(v)) url.searchParams.set(k, v);
    });
  }
  return url.toString();
}

/**
 * The chain's explorer page for a transaction hash, https only. Hash formats vary too much
 * across families (prefixed ids, base64 units, short hex) to allowlist each; the charset
 * check plus URL encoding is what keeps a hash from smuggling in path segments or queries.
 */
export function explorerTxUrl(info: ChainInfo, hash: string): string | undefined {
  if (!info.explorerTxUrl || !/^[A-Za-z0-9_+/=:\-]{8,128}$/.test(hash)) {
    return undefined;
  }
  const url = info.explorerTxUrl.replace('{hash}', encodeURIComponent(hash));
  return url.startsWith('https://') ? url : undefined;
}

/**
 * EVM networks the core signs on (mirror of `evm::SIGNING_TESTNETS`). The
 * core refuses every other chain id; the UI only offers these.
 */
export const EVM_SIGNING_CHAINS: ReadonlySet<string> = new Set(
  [11155111, 17000, 560048, 84532, 11155420, 421614, 80002].map((n) => `eip155:${n}`),
);

/** EVM networks offered first wherever one address is watched across chains. */
export const POPULAR_EVM: readonly string[] = [
  'eip155:1',
  'eip155:8453',
  'eip155:42161',
  'eip155:10',
  'eip155:137',
  'eip155:56',
  'eip155:43114',
  'eip155:324',
  'eip155:59144',
  'eip155:534352',
];
