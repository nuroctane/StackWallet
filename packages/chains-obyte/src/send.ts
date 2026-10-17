/**
 * Obyte native GBYTE (bytes) transfers. The adapter picks spendable outputs
 * through the hub's `light/pick_divisible_coins_for_amount`, reads each
 * referenced output's value via `get_joint`, fetches parents/last ball from
 * the hub, and hands the checked fields to the core. The core recomputes
 * commissions and the change output; this module recomputes them too, only to
 * verify the signed wire before broadcasting over the hub websocket.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { Simulation, TxStatus } from '@stackwallet/chains';
import type { ChainId, TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import {
  OBYTE_MAINNET,
  OBYTE_TESTNET,
  ObyteInput,
  ObyteTx,
  base64Decode,
  buildUnit,
  computeCommissions,
  isValidObyteAddress,
  jsonSourceString,
  obyteAddressFromPublicKey,
  unitId,
  unitSighash,
  type ObyteAdapter,
  type ObyteHubTransport,
} from './obyte.js';

export { OBYTE_TESTNET, OBYTE_MAINNET };

const MAX_INPUTS_PER_PAYMENT = 128;
/** Safety margin on top of amount when asking the hub for coins, in bytes. */
const FEE_ESTIMATE = 2048;

const SafeInt = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const B64_32 = z
  .string()
  .length(44)
  .regex(/^[A-Za-z0-9+/]{43}=$/);

const Parents = z.object({
  timestamp: z.number().int().positive(),
  parent_units: z.array(B64_32).min(1).max(16),
  last_stable_mc_ball: B64_32,
  last_stable_mc_ball_unit: B64_32,
  last_stable_mc_ball_mci: SafeInt,
  tps_fee: SafeInt,
  count_primary_aa_triggers: SafeInt.optional(),
});

const CoinSelection = z.object({
  inputs_with_proofs: z
    .array(
      z.object({
        input: z
          .object({
            unit: B64_32.optional(),
            message_index: SafeInt.optional(),
            output_index: SafeInt.optional(),
            type: z.enum(['issue', 'headers_commission', 'witnessing']).optional(),
          })
          .loose(),
      }),
    )
    .min(1),
  total_amount: SafeInt,
});

const Definition = z.tuple([z.literal('sig'), z.object({ pubkey: z.string() }).loose()]).nullable();

const PaymentUnit = z.object({
  unit: z
    .object({
      authors: z.array(z.object({ address: z.string() }).loose()).min(1),
      messages: z.array(
        z
          .object({
            app: z.string(),
            payload: z
              .object({
                asset: z.string().optional(),
                outputs: z.array(z.object({ address: z.string(), amount: SafeInt }).loose()),
              })
              .loose()
              .optional(),
          })
          .loose(),
      ),
    })
    .loose(),
});
/** The wire payload the core returns: canonical JSON of `{"unit": ...}`. */
const WireUnit = z
  .object({
    version: z.string().max(16),
    alt: z.string().max(4),
    timestamp: z.number().int().positive(),
    parent_units: z.array(B64_32).min(1).max(16),
    last_ball: B64_32,
    last_ball_unit: B64_32,
    tps_fee: SafeInt,
    authors: z
      .array(
        z.object({
          address: z.string().length(32),
          authentifiers: z.record(z.string(), z.string().max(4096)),
          definition: z.unknown().optional(),
        }),
      )
      .length(1),
    messages: z.array(z.record(z.string(), z.unknown())).length(1),
    headers_commission: SafeInt,
    payload_commission: SafeInt,
    unit: B64_32,
  })
  .passthrough();
const Wire = z.object({ unit: WireUnit });

/**
 * Default broadcast transport: one hub websocket connection per broadcast.
 * The hub speaks JSON-array frames (`justsaying`/`request`/`response`); light
 * clients must announce the hub's exact protocol version and answer the
 * `subscribe` request with an error before `post_joint` is served. Verified
 * live: a structurally valid unit reached the hub's signature check.
 */
export class ObyteWsHub implements ObyteHubTransport {
  private constructor(
    private readonly ws: WebSocket,
    private readonly pending = new Map<
      string,
      { resolve: (v: unknown) => void; reject: (e: Error) => void }
    >(),
  ) {}

  static async connect(url: string, timeoutMs = 15000): Promise<ObyteWsHub> {
    const testnet = /bb-test|testnet/.test(url);
    const protocolVersion = testnet ? '4.0t' : '4.0';
    const alt = testnet ? '2' : '1';
    const ws = new WebSocket(url);
    const hub = new ObyteWsHub(ws);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.close();
        reject(new Error(`hub websocket open timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      ws.onopen = () => {
        ws.send(
          JSON.stringify([
            'justsaying',
            {
              subject: 'version',
              body: {
                protocol_version: protocolVersion,
                alt,
                library: 'ocore',
                library_version: '0.4.1',
                program: 'ocore-light-client',
                program_version: '0.1.0',
              },
            },
          ]),
        );
        clearTimeout(timer);
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error(`hub websocket failed: ${url}`));
      };
    });
    ws.onmessage = (ev) => {
      let frame: unknown;
      try {
        frame = JSON.parse(String(ev.data));
      } catch {
        return;
      }
      if (!Array.isArray(frame) || frame.length !== 2) return;
      const [type, msg] = frame as [string, { tag?: string; response?: unknown }];
      if (type === 'response' && typeof msg.tag === 'string') {
        const entry = hub.pending.get(msg.tag);
        if (entry) {
          hub.pending.delete(msg.tag);
          entry.resolve(msg.response);
        }
      } else if (type === 'request') {
        // Light clients cannot serve hub requests; answer with an error.
        ws.send(JSON.stringify(['response', { tag: msg.tag, response: { error: "I'm light" } }]));
      }
    };
    ws.onclose = () => {
      for (const entry of hub.pending.values())
        entry.reject(new Error('hub websocket closed while waiting'));
      hub.pending.clear();
    };
    return hub;
  }

  postJoint(joint: { unit: Record<string, unknown> }): Promise<unknown> {
    // Hub request tags must stay short (the hub rejects tags over 44 chars).
    const tag = `pj${Math.random().toString(36).slice(2, 14)}`;
    return new Promise((resolve, reject) => {
      this.pending.set(tag, { resolve, reject });
      this.ws.send(JSON.stringify(['request', { command: 'post_joint', params: joint, tag }]));
    });
  }

  close(): void {
    this.ws.close();
  }
}

/** Default hub websocket urls; verified live (protocol handshake + post_joint). */
export const OBYTE_HUB_WS: Record<string, string> = {
  [OBYTE_TESTNET]: 'wss://obyte.org/bb-test',
  [OBYTE_MAINNET]: 'wss://obyte.org/bb',
};

export async function defaultHub(chainId: ChainId): Promise<ObyteHubTransport> {
  const url = OBYTE_HUB_WS[chainId];
  if (!url) throw new Error(`no hub websocket for ${chainId}`);
  return ObyteWsHub.connect(url);
}

async function outputAmount(
  adapter: ObyteAdapter,
  chainId: ChainId,
  from: string,
  input: { unit: string; message_index: number; output_index: number },
): Promise<bigint> {
  return adapter.withEndpoint(chainId, async (call) => {
    const { joint } = await call(
      'get_joint',
      { unit: input.unit },
      z.object({ joint: PaymentUnit }),
    );
    if (!joint) throw new Error(`input unit ${input.unit} not found`);
    const message = joint.unit.messages[input.message_index];
    const output = message?.payload?.outputs[input.output_index];
    if (!message || message.app !== 'payment' || !output)
      throw new Error(`input ${input.unit} has no such payment output`);
    if (message.payload?.asset) throw new Error('input is not a base-asset output');
    if (output.address !== from) throw new Error('input output does not belong to the sender');
    return BigInt(output.amount);
  });
}

export async function prepareObyte(
  adapter: ObyteAdapter,
  intent: TxIntent,
  from: string,
  /** Base64 33-byte compressed SEC1 public key behind `from`. */
  authorPubkey: string,
): Promise<{ unsigned: ObyteTx; simulation: Simulation }> {
  if (
    intent.chainId !== OBYTE_TESTNET ||
    intent.kind !== 'transfer' ||
    intent.asset !== `${OBYTE_TESTNET}:native`
  )
    throw new Error('Only native GBYTE transfers on the Obyte testnet are enabled');
  if (!isValidObyteAddress(from) || !isValidObyteAddress(intent.to))
    throw new Error('Invalid Obyte address');
  if (!/^[1-9][0-9]{0,15}$/.test(intent.amount))
    throw new Error('Amount must be a positive canonical integer of bytes');
  const pubkey = base64Decode(authorPubkey);
  if (!pubkey || pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03))
    throw new Error('Invalid author public key');
  if (obyteAddressFromPublicKey(pubkey) !== from)
    throw new Error('Author public key does not derive the from address');

  return adapter.withEndpoint(intent.chainId, async (call) => {
    // First spend from an address must embed the definition; the hub answers
    // with no data for addresses it has never seen.
    const definition = await call('light/get_definition', { address: from }, Definition).catch(
      () => null,
    );
    const firstUnit = definition === null;

    const parents = await call(
      'light/get_parents_and_last_ball_and_witness_list_unit',
      { from_addresses: [from], output_addresses: [from, intent.to] },
      Parents,
    );

    // Pick coins with a fee estimate, then recompute the exact commissions and
    // re-pick once if the change would not be positive (commissions grow with
    // the input count, so the loop converges in at most a couple of rounds).
    const amount = BigInt(intent.amount);
    let target = amount + BigInt(FEE_ESTIMATE);
    let inputs: ObyteInput[] = [];
    let fee = 0n;
    for (let round = 0; round < 4; round++) {
      const picked = await call(
        'light/pick_divisible_coins_for_amount',
        {
          addresses: [from],
          last_ball_mci: parents.last_stable_mc_ball_mci,
          amount: Number(target),
        },
        CoinSelection,
      );
      const plain = picked.inputs_with_proofs
        .map((p) => p.input)
        .filter(
          (i): i is { unit: string; message_index: number; output_index: number } =>
            i.type === undefined &&
            i.unit !== undefined &&
            i.message_index !== undefined &&
            i.output_index !== undefined,
        );
      if (plain.length === 0 || plain.length > MAX_INPUTS_PER_PAYMENT)
        throw new Error('No spendable base-asset outputs cover this amount');
      const amounts = await Promise.all(
        plain.map((i) => outputAmount(adapter, intent.chainId, from, i)),
      );
      inputs = plain.map((i, n) =>
        ObyteInput.parse({
          unit: i.unit,
          messageIndex: i.message_index,
          outputIndex: i.output_index,
          amount: amounts[n]!.toString(),
        }),
      );
      const candidate = ObyteTx.parse({
        chainId: intent.chainId,
        from,
        authorPubkey,
        to: intent.to,
        bytes: intent.amount,
        timestamp: parents.timestamp,
        tpsFee: parents.tps_fee,
        parentUnits: parents.parent_units,
        lastBall: parents.last_stable_mc_ball,
        lastBallUnit: parents.last_stable_mc_ball_unit,
        inputs,
        firstUnit,
      });
      const { headers, payload, totalInput, change } = computeCommissions(candidate);
      fee = BigInt(headers + payload + parents.tps_fee);
      if (change > 0n) {
        const warnings: Simulation['warnings'] = [];
        if (firstUnit)
          warnings.push({
            kind: 'other',
            message:
              'This is the first spend from this address; the unit also publishes its public-key definition (a slightly larger commission).',
          });
        return {
          unsigned: candidate,
          simulation: {
            ok: true,
            assetDeltas: [
              { assetRef: intent.asset, amount: `-${intent.amount}` },
              { assetRef: intent.asset, amount: `-${fee.toString()}` },
            ],
            fee: { assetRef: intent.asset, amount: fee.toString() },
            warnings,
          },
        };
      }
      if (round === 3 || totalInput >= amount + fee + 1n) break;
      target = amount + fee + 1n + BigInt(FEE_ESTIMATE);
    }
    return {
      unsigned: ObyteTx.parse({
        chainId: intent.chainId,
        from,
        authorPubkey,
        to: intent.to,
        bytes: intent.amount,
        timestamp: parents.timestamp,
        tpsFee: parents.tps_fee,
        parentUnits: parents.parent_units,
        lastBall: parents.last_stable_mc_ball,
        lastBallUnit: parents.last_stable_mc_ball_unit,
        inputs,
        firstUnit,
      }),
      simulation: {
        ok: false,
        assetDeltas: [
          { assetRef: intent.asset, amount: `-${intent.amount}` },
          { assetRef: intent.asset, amount: `-${fee.toString()}` },
        ],
        fee: { assetRef: intent.asset, amount: fee.toString() },
        warnings: [],
        error: 'Spendable balance does not cover the transfer and its commission',
      },
    };
  });
}

/**
 * Units do not expire, but a prepared unit embeds the hub's timestamp and the
 * hub rejects timestamps in the future; treat the approval as usable while the
 * hub's clock is not past ours by more than two minutes and our timestamp is
 * not stale by more than a day.
 */
export async function obyteApprovalValid(adapter: ObyteAdapter, tx: ObyteTx): Promise<boolean> {
  return adapter.withEndpoint(tx.chainId, async (call) => {
    const parents = await call(
      'light/get_parents_and_last_ball_and_witness_list_unit',
      { from_addresses: [tx.from], output_addresses: [tx.to] },
      Parents,
    );
    return tx.timestamp <= parents.timestamp + 120 && parents.timestamp - tx.timestamp < 86_400;
  });
}

/** Broadcast only a unit that is exactly the core's construction plus one valid signature. */
export async function broadcastObyte(
  adapter: ObyteAdapter,
  unsigned: ObyteTx,
  signedWire: string,
): Promise<string> {
  if (unsigned.chainId !== OBYTE_TESTNET) throw new Error('Only testnet broadcasts are enabled');
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedWire);
  } catch {
    throw new Error('Signed wire is not JSON');
  }
  const wire = Wire.parse(parsed);
  if (wire.unit.authors[0]!.address !== unsigned.from)
    throw new Error('Wire unit author differs from the sender');
  const authentifiers = wire.unit.authors[0]!.authentifiers;
  const sig = authentifiers.r;
  if (Object.keys(authentifiers).length !== 1 || !sig || sig.length !== 88)
    throw new Error('Wire unit must carry exactly one r signature');
  const sigBytes = base64Decode(sig);
  if (!sigBytes || sigBytes.length !== 64) throw new Error('Wire signature is not 64 bytes');

  // The unit minus its signature and id must equal the core's construction.
  const expected = buildUnit(unsigned, '-'.repeat(88));
  const rebuilt = { ...expected, unit: undefined } as Record<string, unknown>;
  delete rebuilt.unit;
  const wireNaked = JSON.parse(JSON.stringify(wire.unit)) as Record<string, unknown>;
  const wireAuthors = wireNaked.authors as Record<string, unknown>[];
  wireAuthors[0]!.authentifiers = { r: '-'.repeat(88) };
  const wireId = wireNaked.unit;
  delete wireNaked.unit;
  if (jsonSourceString(wireNaked) !== jsonSourceString(expected))
    throw new Error('Wire unit differs from the approved transaction');

  // The signature must verify against the sender's public key over the sighash.
  const pubkey = base64Decode(unsigned.authorPubkey);
  if (!pubkey) throw new Error('Invalid author public key');
  const sighash = unitSighash(unsigned);
  // noble/curves v2 prehashes by default; Obyte signs the 32-byte hash directly.
  if (!secp256k1.verify(sigBytes, sighash, pubkey, { prehash: false, lowS: true }))
    throw new Error('Wire signature does not verify');

  const id = unitId(wire.unit as Record<string, unknown>);
  if (wireId !== id) throw new Error('Wire unit id does not match its content');

  const hub = await adapter.hub(unsigned.chainId);
  try {
    const response = await hub.postJoint({ unit: wire.unit as Record<string, unknown> });
    if (response !== 'accepted') {
      const message =
        typeof response === 'object' && response !== null && 'error' in response
          ? String((response as { error: unknown }).error)
          : JSON.stringify(response);
      // A retry of an already-known unit is not a failure.
      if (/known|already|exist/i.test(message)) return id;
      throw new Error(`Broadcast rejected: ${message}`);
    }
    return id;
  } finally {
    hub.close();
  }
}

export async function obyteTransferStatus(
  adapter: ObyteAdapter,
  tx: ObyteTx,
  hash: string,
): Promise<TxStatus> {
  if (tx.chainId !== OBYTE_TESTNET) throw new Error('Only testnet statuses are enabled');
  return adapter.status(hash, tx.chainId);
}
