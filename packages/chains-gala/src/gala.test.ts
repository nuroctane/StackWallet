import { MemoryRpcPool } from '@stackwallet/chains';
import type { TxIntent } from '@stackwallet/core-client';
import { describe, expect, it } from 'vitest';

import {
  GALA_CHAINS,
  GALA_TESTNET,
  GalaAdapter,
  createGalaAdapter,
  decimalToGunits,
  galaAddressFromPublicKey,
  gunitsToDecimal,
  isValidGalaAddress,
} from './gala.js';
import {
  GalaTx,
  broadcastGala,
  galaApprovalValid,
  galaLocalId,
  galaPayload,
  galaTransferStatus,
  galaWireBody,
  prepareGala,
} from './send.js';

/**
 * Vectors proven live against both GalaChain gateways: a TransferToken signed
 * with key 0x07..07 over exactly this payload recovered the sender address
 * below (the call failed only on the 1 GALA fee, HTTP 402).
 */
const PUBLIC = '02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f';
const SENDER = 'eth|4a62316623ad457F02cDC5D997deD67a383EC569';
const RECIPIENT = 'eth|8ba1f109551bD432803012645Ac136ddd64DBA72';
const SIGNATURE =
  'e91952ed063994efd30aa1e2dc7ed4bd05f9692e6becb908b9b11ed5b6b06d79396b6df82a72d3c064f06d7458a458bf29e4fc0dd787a28b01dbd6c937fe8c151c';

const tx: GalaTx = {
  chainId: GALA_TESTNET,
  from: SENDER,
  to: RECIPIENT,
  gunits: '100000000',
  uniqueKey: 'stackwallet-probe-1792206705582',
  dtoExpiresAt: 1_792_207_005_582,
};

function intent(overrides: Partial<TxIntent> = {}): TxIntent {
  return {
    chainId: GALA_TESTNET,
    kind: 'transfer',
    to: RECIPIENT,
    asset: `${GALA_TESTNET}:native`,
    amount: '100000000',
    ...overrides,
  } as TxIntent;
}

const GALA_CLASS = { collection: 'GALA', decimals: 8 };

/** Mocks the gateway's DTO POSTs; `routes` map contract method to response envelope. */
function gateway(routes: Record<string, (body: unknown) => unknown>, explorer?: unknown) {
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith('https://explorer-api.galachain.com'))
      return Response.json(explorer ?? { data: { transactions: [] } });
    const method = url.slice(url.lastIndexOf('/') + 1);
    const route = routes[method];
    if (!route) return Response.json({ Message: 'unknown method', ErrorCode: 'NOT_FOUND' });
    return Response.json(route(JSON.parse(String(init?.body))));
  }) as typeof fetch;
  return new GalaAdapter({
    fetch: fetchImpl,
    rpc: new MemoryRpcPool(GALA_CHAINS.map((c) => ({ ...c, defaultRpcs: ['https://gw.test'] }))),
  });
}

const HEALTHY = {
  FetchTokenClasses: () => ({ Data: [GALA_CLASS] }),
};

describe('gala addresses', () => {
  it('derives the gateway-verified address of the probe key', () => {
    expect(
      galaAddressFromPublicKey(Uint8Array.from(PUBLIC.match(/../g)!.map((b) => parseInt(b, 16)))),
    ).toBe(SENDER);
    const a = createGalaAdapter();
    expect(a.deriveAddress({ curve: 'secp256k1', hex: PUBLIC }, GALA_TESTNET)).toBe(SENDER);
    expect(() =>
      a.deriveAddress({ curve: 'ed25519', hex: '11'.repeat(32) }, GALA_TESTNET),
    ).toThrow();
  });

  it('validates checksummed eth| refs only', () => {
    expect(isValidGalaAddress(SENDER)).toBe(true);
    expect(isValidGalaAddress(RECIPIENT)).toBe(true);
    expect(isValidGalaAddress(SENDER.toLowerCase())).toBe(false);
    expect(isValidGalaAddress(SENDER.toUpperCase().replace('ETH|', 'eth|'))).toBe(false);
    expect(isValidGalaAddress('0x4a62316623ad457F02cDC5D997deD67a383EC569')).toBe(false);
    expect(isValidGalaAddress('client|4a62316623ad457F02cDC5D997deD67a383EC569')).toBe(false);
    expect(isValidGalaAddress('eth|0000000000000000000000000000000000000000')).toBe(false);
  });
});

describe('gala transfers', () => {
  it('builds the exact payload and wire the gateways verified live', () => {
    expect(galaPayload(tx)).toBe(
      '{"dtoExpiresAt":1792207005582,"from":"eth|4a62316623ad457F02cDC5D997deD67a383EC569",' +
        '"quantity":"1","to":"eth|8ba1f109551bD432803012645Ac136ddd64DBA72",' +
        '"tokenInstance":{"additionalKey":"none","category":"Unit","collection":"GALA",' +
        '"instance":"0","type":"none"},"uniqueKey":"stackwallet-probe-1792206705582"}',
    );
    expect(galaWireBody(tx, SIGNATURE)).toContain(`"signature":"${SIGNATURE}"`);
    expect(galaWireBody(tx, SIGNATURE)).toBe(
      galaPayload(tx).replace(/}$/, `,"signature":"${SIGNATURE}"}`),
    );
    expect(galaLocalId(tx)).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('matches the SDK deterministic-serialization keccak vector', async () => {
    // @gala-chain/api spec: {"a":3,"b":[{"x":4,"y":5,"z":6},7],"c":8}
    const { keccak_256 } = await import('@noble/hashes/sha3.js');
    const { bytesToHex } = await import('@noble/hashes/utils.js');
    expect(
      bytesToHex(keccak_256(new TextEncoder().encode('{"a":3,"b":[{"x":4,"y":5,"z":6},7],"c":8}'))),
    ).toBe('79dd0efca18dd25aecc5aa5b5c6e89c1ea0ba96a04280cb7cb9a617e771d702b');
  });

  it('converts between gunits and decimals without floats', () => {
    expect(decimalToGunits('1')).toBe('100000000');
    expect(decimalToGunits('25399.4071209')).toBe('2539940712090');
    expect(decimalToGunits('0.00000001')).toBe('1');
    expect(gunitsToDecimal('100000000')).toBe('1');
    expect(gunitsToDecimal('150000000')).toBe('1.5');
    expect(gunitsToDecimal('1')).toBe('0.00000001');
    expect(() => decimalToGunits('0.000000001')).toThrow();
    expect(() => gunitsToDecimal('0')).toThrow();
  });

  it('refuses hostile fields', () => {
    expect(() => galaPayload({ ...tx, chainId: 'gala:mainnet' as never })).toThrow();
    expect(() => galaPayload({ ...tx, gunits: '0' })).toThrow();
    expect(() => galaPayload({ ...tx, gunits: '0100000000' })).toThrow();
    expect(() => galaPayload({ ...tx, to: SENDER })).toThrow();
    expect(() => galaPayload({ ...tx, uniqueKey: 'bad key' })).toThrow();
    expect(() => galaPayload({ ...tx, dtoExpiresAt: Number.MAX_SAFE_INTEGER })).toThrow();
    expect(() =>
      GalaTx.parse({ ...tx, dtoOperation: 'evil' } as Record<string, unknown>),
    ).toThrow();
    expect(() => galaWireBody(tx, SIGNATURE.toUpperCase())).toThrow();
    expect(() => galaWireBody(tx, SIGNATURE.slice(2))).toThrow();
  });

  it('prepares a testnet transfer with the 1 GALA fee in the simulation', async () => {
    const adapter = gateway({
      ...HEALTHY,
      FetchBalances: () => ({
        Data: [
          {
            ...GALA_CLASS,
            category: 'Unit',
            type: 'none',
            additionalKey: 'none',
            owner: SENDER,
            quantity: '10',
          },
        ],
      }),
    });
    const { unsigned, simulation } = await prepareGala(
      adapter,
      intent(),
      SENDER,
      1_792_206_405_582,
      'abcd1234',
    );
    expect(unsigned.uniqueKey).toBe('stackwallet-1792206405582-abcd1234');
    expect(unsigned.dtoExpiresAt).toBe(1_792_206_405_582 + 30 * 60_000);
    expect(simulation.ok).toBe(true);
    expect(simulation.fee?.amount).toBe('100000000');
  });

  it('fails preparation when the balance cannot cover amount plus fee', async () => {
    const adapter = gateway({
      ...HEALTHY,
      FetchBalances: () => ({
        Data: [
          {
            ...GALA_CLASS,
            category: 'Unit',
            type: 'none',
            additionalKey: 'none',
            owner: SENDER,
            quantity: '1',
          },
        ],
      }),
    });
    const { simulation } = await prepareGala(adapter, intent(), SENDER);
    expect(simulation.ok).toBe(false);
    expect(simulation.error).toMatch(/1 GALA fee/);
  });

  it('fails preparation on a gateway that does not serve the GALA class', async () => {
    const adapter = gateway({ FetchTokenClasses: () => ({ Data: [] }) });
    await expect(prepareGala(adapter, intent(), SENDER)).rejects.toThrow(/GALA token class/);
  });

  it('honours the DTO expiry for approval', () => {
    expect(galaApprovalValid(tx, tx.dtoExpiresAt - 61_000)).toBe(true);
    expect(galaApprovalValid(tx, tx.dtoExpiresAt - 59_000)).toBe(false);
  });

  it('broadcasts exactly the checked body and returns the gateway id', async () => {
    let seenBody: unknown;
    const adapter = gateway({
      ...HEALTHY,
      TransferToken: (body) => {
        seenBody = body;
        return { Data: { transactionId: 'abc123' } };
      },
    });
    const id = await broadcastGala(
      adapter,
      tx,
      JSON.stringify({ ...JSON.parse(galaPayload(tx)), signature: SIGNATURE }),
    );
    expect(id).toBe('abc123');
    expect(seenBody).toEqual(JSON.parse(galaWireBody(tx, SIGNATURE)));
  });

  it('surfaces gateway rejections and falls back to the local id', async () => {
    const rejected = gateway({
      ...HEALTHY,
      TransferToken: () => ({ Message: 'Insufficient balance', ErrorCode: 'PAYMENT_REQUIRED' }),
    });
    await expect(
      broadcastGala(rejected, tx, JSON.stringify({ signature: SIGNATURE })),
    ).rejects.toThrow(/Insufficient balance/);
    const noId = gateway({ ...HEALTHY, TransferToken: () => ({ Data: {} }) });
    await expect(broadcastGala(noId, tx, JSON.stringify({ signature: SIGNATURE }))).resolves.toBe(
      galaLocalId(tx),
    );
  });

  it('reports confirmed, failed, unknown and expired', async () => {
    const hash = 'aa'.repeat(32);
    const confirmed = gateway(HEALTHY, {
      data: { transactions: [{ id: hash, validationCode: { validationEnum: 'VALID' } }] },
    });
    await expect(confirmed.status(hash, GALA_TESTNET)).resolves.toEqual({
      state: 'confirmed',
      blockNumber: 0,
    });
    const failed = gateway(HEALTHY, {
      data: {
        transactions: [
          { id: hash, validationCode: { validationEnum: 'ENDORSEMENT_POLICY_FAILURE' } },
        ],
      },
    });
    await expect(failed.status(hash, GALA_TESTNET)).resolves.toEqual({
      state: 'failed',
      reason: 'ENDORSEMENT_POLICY_FAILURE',
    });
    const unknown = gateway(HEALTHY, { data: { transactions: [] } });
    await expect(unknown.status(hash, GALA_TESTNET)).resolves.toEqual({ state: 'unknown' });
    const old = { ...tx, dtoExpiresAt: 1_800_000_000_000 };
    await expect(galaTransferStatus(unknown, old, hash, 1_800_000_060_000)).resolves.toEqual({
      state: 'expired',
    });
    await expect(galaTransferStatus(unknown, tx, hash, tx.dtoExpiresAt - 1)).resolves.toEqual({
      state: 'unknown',
    });
  });

  it('reads the GALA balance from FetchBalances', async () => {
    const adapter = gateway({
      ...HEALTHY,
      FetchBalances: () => ({
        Data: [
          {
            collection: '$GMUSIC',
            category: 'Unit',
            type: 'none',
            additionalKey: 'none',
            owner: SENDER,
            quantity: '25399.4071209',
          },
          {
            ...GALA_CLASS,
            category: 'Unit',
            type: 'none',
            additionalKey: 'none',
            owner: SENDER,
            quantity: '7.5',
          },
        ],
      }),
    });
    const holdings = await adapter.getBalances(SENDER, GALA_TESTNET);
    expect(holdings[0]?.amount).toBe('750000000');
    expect(holdings[0]?.provenance?.kind).toBe('single');
  });
});
