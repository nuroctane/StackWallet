import { describe, expect, it } from 'vitest';
import { MemoryRpcPool, type ChainInfo } from '@stackwallet/chains';
import type { PublicKey, TxIntent } from '@stackwallet/core-client';

import {
  CHIA_CHAINS,
  CHIA_TESTNET,
  ChiaAdapter,
  chiaAddressBytes,
  chiaAddressFromPublicKey,
  chiaAddressFromPuzzleHash,
  isValidChiaAddress,
  standardPuzzleHash,
  syntheticPublicKey,
} from './chia.js';
import {
  broadcastChia,
  bundleName,
  chiaApprovalValid,
  chiaTransferStatus,
  prepareChia,
  validateChiaTx,
  type ChiaUnsignedTx,
} from './send.js';
import { hexToBytes } from '@noble/hashes/utils.js';

// Pinned against .nur/chia-ref/vectors.json (generated with @noble/curves and
// cross-checked against the ERC-2333 spec vector and the deployed standard
// puzzle's on-chain tree hash).
const V = {
  pk0: 'b2fcc06b717db87fdb3db4c08e1af09b9dfbd03c26eadbc1f189c2cb0fc613e065b11345e4c8a3b42b1f648ec85e8485',
  syntheticPk0:
    'a190f944426d03ee611ce3051de3fc065c21ab14bedaa4dafef2a91906e8bdcf155a3986eeac6e46fbb4576652528450',
  ph0: '64acb69e5b36b222912a945a87c51660d27b51f0e912ac8c4b0e1560b4e5a0a3',
  ph1: 'c924f604d7ff8e651dd1720edd9f06723bb4435f8d1cd81f89d63571459dd381',
  txch0: 'txch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3sgv6hx3',
  xch0: 'xch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3s9tap8z',
  txch1: 'txch1eyj0vpxhl78x28w3wg8dm8cxwgamgs6l35wds8uf6c6hz3va6wqslwp336',
  tx: {
    from: 'txch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3sgv6hx3',
    to: 'txch1eyj0vpxhl78x28w3wg8dm8cxwgamgs6l35wds8uf6c6hz3va6wqslwp336',
    mojos: '1500000',
    fee: '100',
    parentCoinId: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
    coinMojos: '2000000',
    coinId: 'a816778fb62b4c4628e85809dcabd8ce91160f986d6cf6db39c30c91f78d41db',
    puzzleRevealHex:
      'ff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0a190f944426d03ee611ce3051de3fc065c21ab14bedaa4dafef2a91906e8bdcf155a3986eeac6e46fbb4576652528450ff018080',
    solutionHex:
      'ff80ffff01ffff34ff6480ffff33ffa0c924f604d7ff8e651dd1720edd9f06723bb4435f8d1cd81f89d63571459dd381ff8316e36080ffff33ffa064acb69e5b36b222912a945a87c51660d27b51f0e912ac8c4b0e1560b4e5a0a3ff8307a0bc8080ff8080',
    signature:
      '8aaec188399e9cafc3a38690b3b3188d2fb0e1542fca9effba4680c78d9b1b0afba9cbc9ccd74c06d433ca3ffb360ac516f8021eee45e4c4685069c76f89506c1addf02a71ebacc2730c07de8b951ca954f7bec1e6aea4fe034d73dc97a4bbd3',
    // The name a live testnet11 full node computed for this exact bundle
    // (pushed live; the node rejected only with UNKNOWN_UNSPENT, i.e. the
    // signature passed validation).
    bundleName: '12d2c57b75b1854472edd3c614e63ec215b89b1fb518f0ca5242c013d9151428',
  },
};

const sampleTx: ChiaUnsignedTx = {
  chainId: CHIA_TESTNET,
  from: V.tx.from,
  to: V.tx.to,
  mojos: V.tx.mojos,
  fee: V.tx.fee,
  parentCoinId: V.tx.parentCoinId,
  coinMojos: V.tx.coinMojos,
};

const wire = JSON.stringify({
  coin_spends: [
    {
      coin: {
        parent_coin_info: `0x${V.tx.parentCoinId}`,
        puzzle_hash: `0x${V.ph0}`,
        amount: Number(V.tx.coinMojos),
      },
      puzzle_reveal: `0x${V.tx.puzzleRevealHex}`,
      solution: `0x${V.tx.solutionHex}`,
    },
  ],
  aggregated_signature: `0x${V.tx.signature}`,
});

function intent(over: Partial<TxIntent> = {}): TxIntent {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    walletId: 'w',
    accountId: 'a',
    chainId: CHIA_TESTNET,
    proposer: { kind: 'human', deviceId: 'd' },
    untrustedDestinations: [],
    createdAtMs: 0,
    kind: 'transfer',
    to: V.txch1,
    asset: `${CHIA_TESTNET}:native`,
    amount: '1500000',
    ...over,
  } as TxIntent;
}

/** A fetch stub routing coinset RPC paths to canned responses. */
function nodeFetch(
  handlers: Record<string, (body: Record<string, unknown>) => unknown>,
): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const path = url.replace(/^https:\/\/node\.example/, '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    const handler =
      handlers[path] ??
      (path === '/get_network_info'
        ? () => ({ success: true, network_name: 'testnet11' })
        : undefined);
    if (!handler) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(handler(body)), { status: 200 });
  }) as typeof fetch;
}

const testChain = (url = 'https://node.example'): ChainInfo => ({
  ...CHIA_CHAINS[1]!,
  defaultRpcs: [url],
});

function adapterWith(handlers: Parameters<typeof nodeFetch>[0]): ChiaAdapter {
  const rpc = new MemoryRpcPool([testChain()]);
  return new ChiaAdapter({ rpc, fetch: nodeFetch(handlers) });
}

describe('addresses', () => {
  it('derives the synthetic key, puzzle hash and bech32m address from pk0', () => {
    const pk = hexToBytes(V.pk0);
    expect(Buffer.from(syntheticPublicKey(pk)).toString('hex')).toBe(V.syntheticPk0);
    expect(Buffer.from(standardPuzzleHash(pk)).toString('hex')).toBe(V.ph0);
    expect(chiaAddressFromPublicKey(pk, 'txch')).toBe(V.txch0);
    expect(chiaAddressFromPublicKey(pk, 'xch')).toBe(V.xch0);
  });

  it('round-trips addresses and rejects hostile input', () => {
    expect(Buffer.from(chiaAddressBytes(V.txch0)!).toString('hex')).toBe(V.ph0);
    expect(chiaAddressFromPuzzleHash(hexToBytes(V.ph1), 'txch')).toBe(V.txch1);
    expect(isValidChiaAddress(V.txch0, 'txch')).toBe(true);
    // Prefix binds the network: an xch address is not a txch address.
    expect(isValidChiaAddress(V.xch0, 'txch')).toBe(false);
    expect(isValidChiaAddress('txch1vjktd8jmx6ez9yf2j3dg03gkvrf8k50sayf2erztpc2kpd895z3sgv6hx4')).toBe(
      false,
    );
    expect(isValidChiaAddress('')).toBe(false);
    expect(isValidChiaAddress('xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq')).toBe(
      false,
    );
  });

  it('derives addresses through the adapter for a bls12-381 public key', () => {
    const adapter = adapterWith({});
    const pub = { curve: 'bls12-381', hex: V.pk0 } as unknown as PublicKey;
    expect(adapter.deriveAddress(pub, CHIA_TESTNET)).toBe(V.txch0);
    expect(adapter.validateAddress(V.txch0, CHIA_TESTNET)).toBe(true);
  });
});

describe('transaction validation', () => {
  it('computes the consensus coin id', () => {
    expect(validateChiaTx(sampleTx).coinId).toBe(V.tx.coinId);
  });

  it('rejects hostile fields', () => {
    const bad = (over: Partial<ChiaUnsignedTx>) => () =>
      validateChiaTx({ ...sampleTx, ...over });
    expect(bad({ mojos: '0' })).toThrow(/positive/);
    expect(bad({ mojos: '1.5' })).toThrow();
    expect(bad({ mojos: '010' })).toThrow();
    expect(bad({ mojos: '9223372036854775808' })).toThrow(/cap/);
    expect(bad({ fee: '-1' })).toThrow();
    expect(bad({ mojos: '1999999', fee: '2' })).toThrow(/exceeds/);
    expect(bad({ to: V.tx.from })).toThrow(/differ/);
    expect(bad({ parentCoinId: 'zz'.repeat(32) })).toThrow();
    expect(bad({ from: V.xch0 })).toThrow(/Invalid sender/);
  });

  it('names the pinned bundle exactly as the live testnet11 node did', () => {
    expect(bundleName(JSON.parse(wire))).toBe(V.tx.bundleName);
  });
});

describe('node interactions', () => {
  const coinRecord = (over: Record<string, unknown> = {}) => ({
    coin: {
      parent_coin_info: `0x${V.tx.parentCoinId}`,
      puzzle_hash: `0x${V.ph0}`,
      amount: 2_000_000,
    },
    coinbase: false,
    confirmed_block_index: 100,
    spent_block_index: 0,
    spent: false,
    timestamp: 1_700_000_000,
    ...over,
  });

  it('sums only unspent coins for the balance', async () => {
    const adapter = adapterWith({
      '/get_coin_records_by_puzzle_hash': () => ({
        success: true,
        coin_records: [
          coinRecord(),
          coinRecord({ coin: { parent_coin_info: `0x${'11'.repeat(32)}`, puzzle_hash: `0x${V.ph0}`, amount: 5 }, spent: true, spent_block_index: 200 }),
        ],
      }),
    });
    const [holding] = await adapter.getBalances(V.txch0, CHIA_TESTNET);
    expect(holding?.amount).toBe('2000000');
    expect(holding?.assetRef).toBe(`${CHIA_TESTNET}:native`);
  });

  it('prepares a transfer spending the smallest covering coin', async () => {
    const adapter = adapterWith({
      '/get_coin_records_by_puzzle_hash': () => ({
        success: true,
        coin_records: [
          coinRecord(),
          coinRecord({
            coin: { parent_coin_info: `0x${'22'.repeat(32)}`, puzzle_hash: `0x${V.ph0}`, amount: 9_000_000 },
          }),
        ],
      }),
    });
    const { unsigned, simulation } = await prepareChia(adapter, intent(), V.txch0);
    expect(simulation.ok).toBe(true);
    expect(unsigned.parentCoinId).toBe(V.tx.parentCoinId);
    expect(unsigned.coinMojos).toBe('2000000');
    expect(unsigned.mojos).toBe('1500000');
  });

  it('reports an unspendable balance in the simulation', async () => {
    const adapter = adapterWith({
      '/get_coin_records_by_puzzle_hash': () => ({ success: true, coin_records: [] }),
    });
    const { simulation } = await prepareChia(adapter, intent(), V.txch0);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/No spendable coins/);
  });

  it('approves while the coin is unspent and refuses once gone', async () => {
    let present = true;
    const adapter = adapterWith({
      '/get_coin_records_by_puzzle_hash': () => ({
        success: true,
        coin_records: present ? [coinRecord()] : [],
      }),
    });
    await expect(chiaApprovalValid(adapter, sampleTx)).resolves.toBe(true);
    present = false;
    await expect(chiaApprovalValid(adapter, sampleTx)).resolves.toBe(false);
  });

  it('maps the spent coin record to a confirmed transfer status', async () => {
    const adapter = adapterWith({
      '/get_coin_records_by_puzzle_hash': (body) => ({
        success: true,
        coin_records: body.include_spent_coins
          ? [coinRecord({ spent: true, spent_block_index: 300 })]
          : [coinRecord()],
      }),
    });
    const status = await chiaTransferStatus(adapter, sampleTx, V.tx.bundleName);
    expect(status.state).toBe('confirmed');
    if (status.state === 'confirmed') expect(status.blockNumber).toBe(300);
  });

  it('broadcasts the pinned bundle and returns its name', async () => {
    const pushed: unknown[] = [];
    const adapter = adapterWith({
      '/push_tx': (body) => {
        pushed.push(body);
        return { success: true, status: 'SUCCESS' };
      },
    });
    await expect(broadcastChia(adapter, sampleTx, wire)).resolves.toBe(V.tx.bundleName);
    expect(pushed).toHaveLength(1);
  });

  it('treats ALREADY_INCLUDING_TRANSACTION as success', async () => {
    const adapter = adapterWith({
      '/push_tx': () => ({ success: false, error: 'Failed to include transaction x, error ALREADY_INCLUDING_TRANSACTION' }),
    });
    await expect(broadcastChia(adapter, sampleTx, wire)).resolves.toBe(V.tx.bundleName);
  });

  it('refuses a wire bundle that pays somebody else', async () => {
    const tampered = JSON.parse(wire) as {
      coin_spends: { solution: string }[];
    };
    // Redirect the CREATE_COIN output puzzle hash to the sender (so the
    // declared recipient gets nothing) by reusing the receiver's bytes.
    tampered.coin_spends[0]!.solution = `0x${V.tx.solutionHex.replace(V.ph1, V.ph0)}`;
    const adapter = adapterWith({ '/push_tx': () => ({ success: true, status: 'SUCCESS' }) });
    await expect(broadcastChia(adapter, sampleTx, JSON.stringify(tampered))).rejects.toThrow(
      /amount differs|unexpected/,
    );
  });

  it('maps coin records to status', async () => {
    const adapter = adapterWith({
      '/get_coin_record_by_name': () => ({
        success: true,
        coin_record: coinRecord({ spent: true, spent_block_index: 300 }),
      }),
    });
    const status = await adapter.status(V.tx.coinId, CHIA_TESTNET);
    expect(status.state).toBe('confirmed');
    if (status.state === 'confirmed') expect(status.blockNumber).toBe(300);
  });

  it('rejects an endpoint serving the wrong network', async () => {
    const rpc = new MemoryRpcPool([testChain()]);
    const adapter = new ChiaAdapter({
      rpc,
      fetch: nodeFetch({ '/get_network_info': () => ({ success: true, network_name: 'mainnet' }) }),
    });
    await expect(adapter.getBalances(V.txch0, CHIA_TESTNET)).rejects.toThrow(/mainnet/);
  });
});
