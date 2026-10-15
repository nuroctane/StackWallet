/**
 * Regenerates `packages/chains/src/catalog-generated.ts` from DefiLlama's
 * chain list, chainlist.org and the Cosmos chain registry. Every endpoint it
 * keeps was answered live, by the chain it claims, with CORS headers a browser
 * accepts. Run from the repo root:
 *
 *   node --experimental-strip-types scripts/sync-chains.ts
 *
 * This talks to the network and is not part of any test suite. The output is
 * committed, so builds stay reproducible (D8) and the app fetches nothing.
 */
import { writeFileSync } from 'node:fs';

import { CURATED_CATALOG } from '../packages/chains/src/catalog-curated.ts';

const OUT = 'packages/chains/src/catalog-generated.ts';
const ORIGIN = 'https://stackwallet.civetadeicollegium.workers.dev';
const TIMEOUT_MS = 10_000;
const MAX_CANDIDATES = 10;
const KEEP = 3;
const HALTED_MS = 14 * 86_400_000;

type Layer = 'L1' | 'L2' | 'L3' | 'sidechain' | 'parachain' | 'subnet' | 'appchain';
interface LlamaRow {
  name: string;
  chainId: number | null;
  symbol: string | null;
  priceId: string | null;
  tvl: number;
  layer: Layer;
  parent: string | null;
  cats: string[];
}

// DefiLlama lists these as EVM without a chain id; ids checked against chainlist.
const EVM_IDS: Record<string, number> = {
  Flare: 14,
  'X Layer': 196,
  Morph: 2818,
  PulseChain: 369,
  Kava: 2222,
  'Bifrost Network': 3068,
  Merlin: 4200,
  CORE: 1116,
  'WEMIX3.0': 1111,
  BSquared: 223,
  'MAP Protocol': 22776,
  EthereumPoW: 10001,
  Shido: 9008,
  AB: 36888,
  Oasys: 248,
  Vana: 1480,
  Shibarium: 109,
  XO: 3223,
  Rollux: 570,
  OpenGPU: 1071,
  'Areum Network': 463,
  'SKALE Europa': 2046399126,
  'Unit Zero': 88811,
  Xai: 660279,
  Darwinia: 46,
  Elysium: 1339,
  Zeniq: 383414847825,
  K2: 2410,
  Boba_Bnb: 56288,
  HAQQ: 11235,
  Evmos: 9001,
  Canto: 7700,
  Empire: 3693,
  Step: 1234,
  Goerli: 5,
  Bahamut: 5165,
  Boba_Avax: 43288,
  Dogechain: 2000,
  'SX Network': 416,
  'SX Rollup': 4162,
  Dexit: 877,
  Omax: 311,
  Loop: 15551,
  Tombchain: 6969,
  Pego: 20201022,
  FunctionX: 530,
  DuckChain: 5545,
  DSC: 75,
  ALV: 3797,
  ENULS: 119,
  Onus: 1975,
  Tenet: 1559,
  MEER: 813,
  FSC: 201022,
  JBC: 8899,
  BEVM: 11501,
  Bitnet: 210,
  RSS3: 12553,
  SatoshiVM: 3109,
  'EOS EVM': 17777,
  XCHAIN: 94524,
  Eventum: 161803,
  'Strato Chain': 123354377739506,
  // Alt-L1s whose EVM space is a separate network; DefiLlama's row covers both.
  XDC: 50,
  Conflux: 1030,
  RISE: 4153,
  Redbelly: 151,
  Zilliqa: 32769,
  Coti: 2632500,
  Ontology: 58,
};

// DefiLlama ids that point at a retired network; the chain moved to a new id.
const EVM_ID_OVERRIDES: Record<string, number> = {
  Plume: 98866,
  // 5887 is MANTRA's Dukong testnet.
  MANTRA: 5888,
};

// chainlist files a different network under these ids (EthereumPoW shares 10001 with a
// smartBCH testnet); their metadata comes from DefiLlama instead.
const CHAINLIST_COLLISIONS = new Set([10001]);
const COLLISION_RPCS: Record<number, string[]> = { 10001: ['https://mainnet.ethereumpow.org'] };

// Served by curated entries in families the generator does not produce.
const CURATED_LLAMA = new Set(['Bitcoin', 'Litecoin', 'Doge', 'Solana', 'Tron']);

// Listed under EVM by DefiLlama but run their own virtual machines; each needs its own family.
const NOT_EVM = new Set([
  'Tron',
  'Hyperliquid L1',
  'Chainflip',
  'Fuel Ignition',
  'Supra',
  'Namada',
  'Anubis',
  'Naka',
  'Echelon',
]);

const TESTNETS = new Set([5]);

// SVM networks: candidate endpoints; the chain id comes from the genesis hash each one serves.
const SVM: {
  llama: string;
  name: string;
  symbol: string;
  priceId: string | null;
  rpcs: string[];
  explorer: string | null;
  layer: Layer;
  parent: string | null;
}[] = [
  {
    llama: 'Eclipse',
    name: 'Eclipse',
    symbol: 'ETH',
    priceId: 'ethereum',
    layer: 'L2',
    parent: 'Ethereum',
    rpcs: ['https://mainnetbeta-rpc.eclipse.xyz', 'https://eclipse.helius-rpc.com'],
    explorer: 'https://eclipsescan.xyz/tx/{hash}',
  },
  {
    llama: 'Soon Network',
    name: 'SOON',
    symbol: 'ETH',
    priceId: 'ethereum',
    layer: 'L2',
    parent: 'Ethereum',
    rpcs: ['https://rpc.mainnet.soo.network/rpc'],
    explorer: 'https://explorer.soo.network/tx/{hash}',
  },
  {
    llama: 'soonBase',
    name: 'soonBase',
    symbol: 'ETH',
    priceId: 'ethereum',
    layer: 'L2',
    parent: 'Base',
    rpcs: ['https://rpc.base.soo.network/rpc'],
    explorer: 'https://explorer.base.soo.network/tx/{hash}',
  },
  {
    llama: 'svmBNB',
    name: 'svmBNB',
    symbol: 'BNB',
    priceId: 'binancecoin',
    layer: 'L2',
    parent: 'BSC',
    rpcs: ['https://rpc.svmbnbmainnet.soo.network/rpc'],
    explorer: 'https://explorer.svmbnbmainnet.soo.network/tx/{hash}',
  },
  {
    llama: 'Fogo',
    name: 'Fogo',
    symbol: 'FOGO',
    priceId: 'fogo',
    layer: 'L1',
    parent: null,
    rpcs: ['https://mainnet.fogo.io'],
    explorer: 'https://fogoscan.com/tx/{hash}',
  },
  {
    llama: 'RENEC',
    name: 'RENEC',
    symbol: 'RENEC',
    priceId: 'renec',
    layer: 'L1',
    parent: null,
    rpcs: ['https://api-mainnet.renec.foundation:8899'],
    explorer: 'https://explorer.renec.foundation/tx/{hash}',
  },
  {
    llama: 'CookieChain',
    name: 'CookieChain',
    symbol: 'COOKIE',
    priceId: null,
    layer: 'L1',
    parent: null,
    rpcs: ['https://rpc.cookiechain.io'],
    explorer: null,
  },
];

// DefiLlama names that are Cosmos SDK chains but not tagged as such.
const COSMOS_EXTRA = new Set(['CosmosHub', 'Initia', 'Mayachain']);

function toId(v: unknown): number | null {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : null;
}

const norm = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .replace(/(mainnet|network|chain|hub)$/, '');

async function timed(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    // Buffer the body under the same deadline so a trickling server cannot hang the run.
    const res = await fetch(url, { ...init, signal: controller.signal });
    const body = await res.arrayBuffer();
    const empty = [101, 204, 205, 304].includes(res.status);
    return new Response(empty ? null : body, { status: res.status, headers: res.headers });
  } finally {
    clearTimeout(t);
  }
}

async function json(url: string): Promise<any> {
  const res = await timed(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

function corsOk(res: Response): boolean {
  const allow = res.headers.get('access-control-allow-origin');
  return allow === '*' || allow === ORIGIN;
}

/** The browser sends a preflight for JSON POSTs; an endpoint that fails it is unusable. */
async function preflightOk(url: string): Promise<boolean> {
  try {
    const res = await timed(url, {
      method: 'OPTIONS',
      headers: {
        origin: ORIGIN,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    });
    // An unread body pins the socket in undici's pool; enough of them stall every later probe.
    await res.arrayBuffer().catch(() => undefined);
    if (!corsOk(res) || res.status >= 400) return false;
    const headers = (res.headers.get('access-control-allow-headers') ?? '').toLowerCase();
    return headers === '' || headers === '*' || headers.includes('content-type');
  } catch {
    return false;
  }
}

async function rpc(
  url: string,
  method: string,
  params: unknown[] = [],
): Promise<{ result: any; res: Response }> {
  const res = await timed(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = (await res.json()) as { result?: unknown; error?: unknown };
  if (body.error || !('result' in body)) throw new Error('rpc error');
  return { result: body.result, res };
}

interface Probe {
  url: string;
  ms: number;
  latestMs: number | null;
  genesis?: string;
}

export async function probeEvm(url: string, id: number): Promise<Probe | null> {
  const started = Date.now();
  try {
    const { result, res } = await rpc(url, 'eth_chainId');
    if (typeof result !== 'string' || BigInt(result) !== BigInt(id) || !corsOk(res)) return null;
    const ms = Date.now() - started;
    if (!(await preflightOk(url))) return null;
    const block = await rpc(url, 'eth_getBlockByNumber', ['latest', false]);
    const ts = block.result?.timestamp;
    return { url, ms, latestMs: typeof ts === 'string' ? Number(BigInt(ts)) * 1000 : null };
  } catch {
    return null;
  }
}

async function probeSvm(url: string): Promise<Probe | null> {
  const started = Date.now();
  try {
    const { result, res } = await rpc(url, 'getGenesisHash');
    if (typeof result !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(result) || !corsOk(res))
      return null;
    const ms = Date.now() - started;
    if (!(await preflightOk(url))) return null;
    const slot = await rpc(url, 'getSlot');
    const time = await rpc(url, 'getBlockTime', [slot.result]).catch(() => null);
    return {
      url,
      ms,
      genesis: result,
      latestMs: typeof time?.result === 'number' ? time.result * 1000 : null,
    };
  } catch {
    return null;
  }
}

async function probeCosmos(url: string, chainId: string): Promise<Probe | null> {
  const base = url.replace(/\/$/, '');
  const started = Date.now();
  try {
    const res = await timed(`${base}/cosmos/base/tendermint/v1beta1/node_info`, {
      headers: { origin: ORIGIN },
    });
    const body = (await res.json().catch(() => null)) as {
      default_node_info?: { network?: string };
    } | null;
    if (!res.ok || !corsOk(res) || !body) return null;
    if (body.default_node_info?.network !== chainId) return null;
    const ms = Date.now() - started;
    const latest = await timed(`${base}/cosmos/base/tendermint/v1beta1/blocks/latest`, {
      headers: { origin: ORIGIN },
    });
    const time = latest.ok ? ((await latest.json()) as any)?.block?.header?.time : undefined;
    return { url: base, ms, latestMs: time ? Date.parse(time) : null };
  } catch {
    return null;
  }
}

/** A Blockscout v2 instance the browser can read: stats answer with CORS and real block counts. */
async function probeBlockscout(base: string): Promise<boolean> {
  try {
    const res = await timed(`${base}/api/v2/stats`, {
      headers: { origin: ORIGIN, accept: 'application/json' },
    });
    const body = (await res.json().catch(() => null)) as { total_blocks?: unknown } | null;
    if (!res.ok || !corsOk(res) || !body) return false;
    return typeof body.total_blocks === 'string' && Number(body.total_blocks) > 0;
  } catch {
    return false;
  }
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: n }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i] as T);
      }
    }),
  );
  return out;
}

/** Endpoints whose head trails the freshest candidate by more than this are lagging nodes. */
const LAG_MS = 10 * 60_000;

function pick(probes: (Probe | null)[]): Probe[] {
  const live = probes.filter((p): p is Probe => p !== null);
  const freshest = Math.max(0, ...live.map((p) => p.latestMs ?? 0));
  return live
    .filter((p) => p.latestMs === null || freshest === 0 || p.latestMs >= freshest - LAG_MS)
    .sort((a, b) => a.ms - b.ms)
    .slice(0, KEEP);
}

const usable = (url: string) =>
  /^https:\/\/[^\s]+$/.test(url) && !/[${}]|api[-_]?key|apikey|<|>/i.test(url) && url.length <= 200;

function layerOf(meta: any): Layer {
  const types: string[] = meta?.parent?.types ?? [];
  if (types.includes('L3')) return 'L3';
  if (types.includes('L2')) return 'L2';
  if (types.includes('parachain')) return 'parachain';
  if (types.includes('subnet') || types.includes('skale')) return 'subnet';
  if (types.includes('sidechain')) return 'sidechain';
  if ((meta?.categories ?? []).includes('Rollup')) return 'L2';
  return 'L1';
}

async function main() {
  console.log('fetching sources');
  const [v2, config, chainlist, chainlistRpcs, cosmosDir] = await Promise.all([
    json('https://api.llama.fi/v2/chains'),
    json('https://api.llama.fi/config'),
    json('https://chainid.network/chains.json'),
    json('https://chainlist.org/rpcs.json'),
    json('https://chains.cosmos.directory/'),
  ]);
  const ids = config.chainCoingeckoIds as Record<string, any>;
  const rows: LlamaRow[] = (v2 as any[]).map((c) => {
    const meta = ids[c.name] ?? {};
    return {
      name: c.name,
      // DefiLlama serves some ids as strings.
      chainId:
        EVM_ID_OVERRIDES[c.name] ??
        toId(c.chainId) ??
        toId(meta.chainId) ??
        EVM_IDS[c.name] ??
        null,
      symbol: c.tokenSymbol ?? meta.symbol ?? null,
      priceId: c.gasTokenGeckoId ?? meta.gasTokenGeckoId ?? c.gecko_id ?? null,
      tvl: c.tvl ?? 0,
      layer: layerOf(meta),
      parent: meta.parent?.chain ?? null,
      cats: meta.categories ?? [],
    };
  });

  const svmNames = new Set(SVM.map((s) => s.llama));
  const evmRows = rows.filter(
    (r) => !NOT_EVM.has(r.name) && !svmNames.has(r.name) && typeof r.chainId === 'number',
  );
  // Ethermint chains (Kava, Evmos, HAQQ...) carry an EVM id too; they get both sides.
  const cosmosRows = rows.filter((r) => r.cats.includes('Cosmos') || COSMOS_EXTRA.has(r.name));
  const covered = new Set(
    [...evmRows, ...cosmosRows].map((r) => r.name).concat([...svmNames, ...CURATED_LLAMA]),
  );
  const unsupported = rows.filter((r) => !covered.has(r.name)).sort((a, b) => b.tvl - a.tvl);

  // EVM
  const byId = new Map<number, any>((chainlist as any[]).map((c) => [c.chainId, c]));
  const rpcsById = new Map<number, any>((chainlistRpcs as any[]).map((c) => [c.chainId, c]));
  const curated = new Map(CURATED_CATALOG.map((c) => [c.chainId, c]));
  const seen = new Set<number>();
  const evmJobs: { row: LlamaRow; id: number; candidates: string[] }[] = [];
  for (const row of evmRows) {
    const id = row.chainId as number;
    if (seen.has(id)) continue;
    seen.add(id);
    if (CHAINLIST_COLLISIONS.has(id)) {
      // eth_chainId cannot tell the two networks apart, so only the operator's own endpoint is tried.
      evmJobs.push({ row, id, candidates: COLLISION_RPCS[id] ?? [] });
      continue;
    }
    const listed = rpcsById.get(id)?.rpc ?? [];
    const tracked = new Map<string, string>();
    for (const r of listed)
      if (typeof r === 'object') tracked.set(r.url.replace(/\/$/, ''), r.tracking ?? 'unspecified');
    const urls = [
      ...listed.map((r: any) => (typeof r === 'string' ? r : r.url)),
      ...(byId.get(id)?.rpc ?? []),
    ]
      .map((u: string) => u.replace(/\/$/, ''))
      .filter(usable)
      .filter((u: string) => tracked.get(u) !== 'yes');
    const rank = (u: string) => ({ none: 0, limited: 1 })[tracked.get(u) ?? ''] ?? 2;
    const candidates = [...new Set<string>(urls)]
      .sort((a, b) => rank(a) - rank(b))
      .slice(0, MAX_CANDIDATES);
    evmJobs.push({ row, id, candidates });
  }
  console.log(
    `probing ${evmJobs.reduce((n, j) => n + j.candidates.length, 0)} EVM endpoints for ${evmJobs.length} chains`,
  );
  const flat = evmJobs.flatMap((j) => j.candidates.map((url) => ({ j, url })));
  const results = await pool(flat, 24, ({ j, url }) => probeEvm(url, j.id));
  // A wide first pass loses endpoints to queueing behind dead hosts; retry the misses slowly.
  const answered = new Set(flat.filter((_, i) => results[i]).map((f) => f.j));
  const retry = flat.map((f, i) => ({ f, i })).filter(({ f }) => !answered.has(f.j));
  console.log(`retrying ${retry.length} endpoints for ${evmJobs.length - answered.size} chains`);
  const again = await pool(retry, 6, ({ f }) => probeEvm(f.url, f.j.id));
  retry.forEach(({ i }, k) => {
    results[i] = again[k] ?? null;
  });
  const evmOut: any[] = [];
  for (const job of evmJobs) {
    const probes = pick(flat.map((f, i) => (f.j === job ? (results[i] ?? null) : null)));
    const info = CHAINLIST_COLLISIONS.has(job.id) ? undefined : byId.get(job.id);
    const explorer = (info?.explorers ?? [])
      .map((e: any) => String(e.url).replace(/\/$/, ''))
      .find((u: string) => /^https:\/\//.test(u));
    const latest = Math.max(...probes.map((p) => p.latestMs ?? 0));
    // A DefiLlama id that chainlist names as a test network is labelled as one, never priced.
    const testnet = TESTNETS.has(job.id) || /\b(testnet|devnet)\b/i.test(info?.name ?? '');
    if (testnet && !TESTNETS.has(job.id))
      console.log(`  ${job.row.name}: chain ${job.id} is "${info?.name}"`);
    evmOut.push({
      id: job.id,
      llama: job.row.name,
      name:
        curated.get(`eip155:${job.id}`)?.name ??
        info?.name?.replace(/\s+Mainnet$/i, '') ??
        job.row.name,
      symbol: info?.nativeCurrency?.symbol ?? job.row.symbol ?? 'ETH',
      decimals: info?.nativeCurrency?.decimals ?? 18,
      explorer: explorer ? `${explorer}/tx/{hash}` : null,
      rpcs: probes.map((p) => p.url),
      priceId: testnet ? null : job.row.priceId,
      layer: job.row.layer,
      parent: job.row.parent,
      testnet,
      halted: probes.length > 0 && latest > 0 && Date.now() - latest > HALTED_MS,
    });
  }

  // Cosmos
  const registry = (cosmosDir.chains as any[]).filter((c) => c.network_type === 'mainnet');
  const cosmosOut: any[] = [];
  const cosmosMissing: string[] = [];
  const cosmosSeen = new Set<string>();
  // Name matches first: rollups often share their hub's gas token id, so a price-id match alone is weak.
  const byName = (row: LlamaRow) => {
    const n = norm(row.name);
    return registry.find(
      (c) =>
        norm(c.pretty_name ?? '') === n ||
        norm(c.chain_name ?? '') === n ||
        norm(c.name ?? '') === n,
    );
  };
  const cosmosOrdered = [...cosmosRows].sort((a, b) => Number(!byName(a)) - Number(!byName(b)));
  for (const row of cosmosOrdered) {
    const entry =
      byName(row) ?? registry.find((c) => row.priceId && c.coingecko_id === row.priceId);
    if (!entry || cosmosSeen.has(entry.chain_id)) {
      cosmosMissing.push(row.name);
      continue;
    }
    cosmosSeen.add(entry.chain_id);
    const full = await json(`https://chains.cosmos.directory/${entry.path}`)
      .then((d) => d.chain)
      .catch(() => null);
    const fee = full?.fees?.fee_tokens?.[0];
    const candidates = [
      ...(entry.best_apis?.rest ?? []).map((r: any) => String(r.address)),
      ...(entry.proxy_status?.rest ? [`https://rest.cosmos.directory/${entry.path}`] : []),
    ]
      .map((u) => u.replace(/\/$/, ''))
      .filter(usable)
      .slice(0, MAX_CANDIDATES);
    const probes = pick(await Promise.all(candidates.map((u) => probeCosmos(u, entry.chain_id))));
    const tx = (entry.explorers ?? []).find((e: any) =>
      /^https:\/\//.test(e.tx_page ?? ''),
    )?.tx_page;
    const latest = Math.max(...probes.map((p) => p.latestMs ?? 0));
    cosmosOut.push({
      id: entry.chain_id,
      llama: row.name,
      name: full?.pretty_name ?? entry.pretty_name ?? row.name,
      symbol: entry.symbol ?? row.symbol ?? '',
      denom: entry.denom,
      decimals: entry.decimals ?? 6,
      prefix: entry.bech32_prefix,
      coinType: entry.slip44 ?? 118,
      // Registries often omit key_algos for Ethermint chains; coin type 60 is the tell.
      addressAlgo:
        (full?.key_algos ?? []).includes('ethsecp256k1') ||
        ((full?.key_algos ?? []).length === 0 && (entry.slip44 ?? 118) === 60)
          ? 'ethsecp256k1'
          : 'secp256k1',
      gasPrice: fee
        ? `${fee.average_gas_price ?? fee.low_gas_price ?? fee.fixed_min_gas_price ?? 0}${fee.denom}`
        : `0${entry.denom}`,
      explorer: tx ? String(tx).replace('${txHash}', '{hash}') : null,
      rests: probes.map((p) => p.url),
      priceId: entry.coingecko_id ?? row.priceId,
      layer: row.layer,
      parent: row.parent,
      halted:
        entry.status === 'killed' ||
        (probes.length > 0 && latest > 0 && Date.now() - latest > HALTED_MS),
    });
  }

  // SVM
  const svmOut: any[] = [];
  for (const s of SVM) {
    const probes = pick(await Promise.all(s.rpcs.map(probeSvm)));
    const genesis = probes[0]?.genesis;
    if (!genesis) {
      unsupported.push({
        name: s.llama,
        chainId: null,
        symbol: s.symbol,
        priceId: s.priceId,
        tvl: 0,
        layer: s.layer,
        parent: s.parent,
        cats: ['SVM'],
      });
      continue;
    }
    svmOut.push({
      ...s,
      id: genesis.slice(0, 32),
      genesis,
      rpcs: probes.filter((p) => p.genesis === genesis).map((p) => p.url),
    });
  }

  // Blockscout indexers for every EVM chain in the catalog, from Blockscout's own directory.
  const bsDir = (await json('https://chains.blockscout.com/api/chains')) as Record<string, any>;
  const evmIds = new Set<string>([
    ...evmOut.map((c) => String(c.id)),
    ...CURATED_CATALOG.filter((c) => c.family === 'evm').map((c) =>
      c.chainId.slice('eip155:'.length),
    ),
  ]);
  const bsJobs = Object.entries(bsDir)
    .filter(([id]) => evmIds.has(id))
    .flatMap(([id, c]) =>
      (c.explorers ?? [])
        .map((e: any) => String(e.url ?? '').replace(/\/$/, ''))
        .filter(usable)
        .map((base: string) => ({ id, base })),
    );
  const bsOk = await pool(bsJobs, 24, (j) => probeBlockscout(j.base));
  const indexers: Record<string, string> = {};
  bsJobs.forEach((j, i) => {
    if (bsOk[i] && !indexers[`eip155:${j.id}`]) indexers[`eip155:${j.id}`] = j.base;
  });

  const meta = Object.fromEntries(
    [
      ...evmOut.map((c) => [`eip155:${c.id}`, c]),
      ...cosmosOut.map((c) => [`cosmos:${c.id}`, c]),
      ...svmOut.map((c) => [`solana:${c.id}`, c]),
    ].map(([k, c]) => [
      k,
      {
        llama: c.llama,
        layer: c.layer,
        parent: c.parent,
        priceId: c.priceId,
        halted: c.halted ?? false,
      },
    ]),
  );
  meta['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'] = {
    llama: 'Solana',
    layer: 'L1',
    parent: null,
    priceId: 'solana',
    halted: false,
  };
  meta['bip122:000000000019d6689c085ae165831e93'] = {
    llama: 'Bitcoin',
    layer: 'L1',
    parent: null,
    priceId: 'bitcoin',
    halted: false,
  };
  meta['bip122:12a765e31ffd4059bada1e25190f6e98'] = {
    llama: 'Litecoin',
    layer: 'L1',
    parent: null,
    priceId: 'litecoin',
    halted: false,
  };
  meta['bip122:1a91e3dace36e2be3bf030a65679fe82'] = {
    llama: 'Doge',
    layer: 'L1',
    parent: null,
    priceId: 'dogecoin',
    halted: false,
  };

  const line = (x: unknown) => '  ' + JSON.stringify(x) + ',';
  const fresh = (list: any[], ns: string) => list.filter((c) => !curated.has(`${ns}:${c.id}`));
  const text = [
    '// Generated by scripts/sync-chains.ts from DefiLlama, chainlist.org and the Cosmos chain',
    '// registry. Every endpoint answered live as the chain it claims, with browser CORS. Do not edit.',
    `// Sources read ${new Date().toISOString().slice(0, 10)}.`,
    "import type { ChainLayer } from './types.js';",
    '',
    'export interface GeneratedEvm { id: number; name: string; symbol: string; decimals: number; explorer: string | null; rpcs: string[]; testnet: boolean }',
    'export interface GeneratedCosmos { id: string; name: string; symbol: string; denom: string; decimals: number; prefix: string; coinType: number; addressAlgo: "secp256k1" | "ethsecp256k1"; gasPrice: string; explorer: string | null; rests: string[] }',
    'export interface GeneratedSvm { id: string; name: string; symbol: string; explorer: string | null; rpcs: string[] }',
    'export interface ChainMeta { llama: string; layer: ChainLayer; parent: string | null; priceId: string | null; halted: boolean }',
    '',
    'export const GENERATED_EVM: readonly GeneratedEvm[] = [',
    ...fresh(evmOut, 'eip155').map((c) => {
      const indexer = indexers[`eip155:${c.id}`];
      const explorer = c.explorer ?? (indexer ? `${indexer}/tx/{hash}` : null);
      return line({
        id: c.id,
        name: c.name,
        symbol: c.symbol,
        decimals: c.decimals,
        explorer,
        rpcs: c.rpcs,
        testnet: c.testnet,
      });
    }),
    '];',
    '',
    'export const GENERATED_COSMOS: readonly GeneratedCosmos[] = [',
    ...fresh(cosmosOut, 'cosmos').map((c) =>
      line({
        id: c.id,
        name: c.name,
        symbol: c.symbol,
        denom: c.denom,
        decimals: c.decimals,
        prefix: c.prefix,
        coinType: c.coinType,
        addressAlgo: c.addressAlgo,
        gasPrice: c.gasPrice,
        explorer: c.explorer,
        rests: c.rests,
      }),
    ),
    '];',
    '',
    'export const GENERATED_SVM: readonly GeneratedSvm[] = [',
    ...fresh(svmOut, 'solana').map((c) =>
      line({ id: c.id, name: c.name, symbol: c.symbol, explorer: c.explorer, rpcs: c.rpcs }),
    ),
    '];',
    '',
    '/** DefiLlama facts for every catalog chain DefiLlama lists, curated ones included. */',
    'export const CHAIN_META: Readonly<Record<string, ChainMeta>> = {',
    ...Object.entries(meta)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)},`),
    '};',
    '',
    '/** Blockscout v2 instances that answered with browser CORS, by CAIP-2 chain id. */',
    'export const GENERATED_INDEXERS: Readonly<Record<string, string>> = {',
    ...Object.entries(indexers)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)},`),
    '};',
    '',
    '/** DefiLlama chains no StackWallet family serves yet, by TVL. */',
    'export const LLAMA_UNSUPPORTED: readonly string[] = [',
    ...unsupported.map((r) => line(r.name)),
    '];',
    '',
  ].join('\n');
  writeFileSync(OUT, text);

  const noRpc = evmOut.filter((c) => c.rpcs.length === 0).map((c) => `${c.llama}(${c.id})`);
  const noRest = cosmosOut.filter((c) => c.rests.length === 0).map((c) => c.llama);
  console.log(
    `EVM ${evmOut.length} (${fresh(evmOut, 'eip155').length} new), no browser-usable RPC: ${noRpc.length}`,
  );
  console.log('  ' + noRpc.join(', '));
  console.log(
    `Cosmos ${cosmosOut.length} (${fresh(cosmosOut, 'cosmos').length} new), no LCD: ${noRest.join(', ') || 'none'}; not in registry: ${cosmosMissing.join(', ') || 'none'}`,
  );
  console.log(`Blockscout indexers: ${Object.keys(indexers).length}`);
  console.log(`SVM ${svmOut.length}: ${svmOut.map((s) => s.llama).join(', ')}`);
  console.log(
    `Unsupported families (${unsupported.length}): ${unsupported.map((r) => r.name).join(', ')}`,
  );
}

if (import.meta.main) await main();
