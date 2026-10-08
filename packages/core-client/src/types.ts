/**
 * Zod mirrors of the Rust core's serde types. Field names and tags match the
 * `#[serde(rename_all = "camelCase")]` / `tag = ...` attributes exactly; a
 * mismatch here is a bug on one side or the other, never a feature.
 */
import { z } from 'zod';

export const ChainFamily = z.enum(['evm', 'bitcoin', 'solana', 'cosmos']);
export type ChainFamily = z.infer<typeof ChainFamily>;

/** CAIP-2: `namespace:reference`. */
export const ChainId = z
  .string()
  .regex(/^[a-z0-9-]{3,8}:[A-Za-z0-9_-]{1,32}$/, 'chain id must be CAIP-2');
export type ChainId = z.infer<typeof ChainId>;

export function chainFamilyOf(chainId: ChainId): ChainFamily | undefined {
  const ns = chainId.split(':')[0];
  switch (ns) {
    case 'eip155':
      return 'evm';
    case 'bip122':
      return 'bitcoin';
    case 'solana':
      return 'solana';
    case 'cosmos':
      return 'cosmos';
    default:
      return undefined;
  }
}

export const AssetRef = z.string().min(1);
export type AssetRef = z.infer<typeof AssetRef>;

export const Curve = z.enum(['secp256k1', 'ed25519', 'secp256k1-tr']);
export type Curve = z.infer<typeof Curve>;

export const PublicKey = z.object({ curve: Curve, hex: z.string().regex(/^[0-9a-f]+$/) });
export type PublicKey = z.infer<typeof PublicKey>;

export const PartyRole = z.enum(['human', 'agent', 'automation']);
export type PartyRole = z.infer<typeof PartyRole>;

export const PartyRef = z.object({ deviceId: z.string(), role: PartyRole });
export type PartyRef = z.infer<typeof PartyRef>;

export const KeyGroup = z.object({
  id: z.string(),
  threshold: z.number().int().min(1).max(255),
  parties: z.array(PartyRef),
  curves: z.array(Curve),
  publicKeys: z.array(PublicKey).default([]),
});
export type KeyGroup = z.infer<typeof KeyGroup>;

/** Base-unit amount as a decimal string. */
export const Amount = z.string().regex(/^[0-9]+$/);
export type Amount = z.infer<typeof Amount>;

export const Proposer = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('human'), deviceId: z.string() }),
  z.object({
    kind: z.literal('agent'),
    sessionId: z.string(),
    grantId: z.string(),
    rationale: z.string(),
  }),
  z.object({ kind: z.literal('automation'), automationId: z.string(), runId: z.string() }),
]);
export type Proposer = z.infer<typeof Proposer>;

const intentBase = {
  id: z.string(),
  walletId: z.string(),
  accountId: z.string(),
  chainId: ChainId,
  proposer: Proposer,
  usdMicros: z.number().int().nonnegative().nullable().optional(),
  untrustedDestinations: z.array(z.string()).default([]),
  createdAtMs: z.number().int(),
};

export const TxIntent = z.discriminatedUnion('kind', [
  z.object({
    ...intentBase,
    kind: z.literal('transfer'),
    to: z.string(),
    asset: AssetRef,
    amount: Amount,
  }),
  z.object({
    ...intentBase,
    kind: z.literal('contractCall'),
    to: z.string(),
    dataHex: z.string(),
    value: Amount,
  }),
  z.object({
    ...intentBase,
    kind: z.literal('swap'),
    sell: AssetRef,
    sellAmount: Amount,
    buy: AssetRef,
    minBuyAmount: Amount,
    maxSlippageBps: z.number().int().nonnegative(),
    aggregator: z.string(),
  }),
  z.object({
    ...intentBase,
    kind: z.literal('stake'),
    validator: z.string(),
    asset: AssetRef,
    amount: Amount,
  }),
  z.object({
    ...intentBase,
    kind: z.literal('unstake'),
    validator: z.string(),
    asset: AssetRef,
    amount: Amount,
  }),
  z.object({ ...intentBase, kind: z.literal('claim'), validator: z.string().nullable() }),
  z.object({
    ...intentBase,
    kind: z.literal('ibcTransfer'),
    to: z.string(),
    asset: AssetRef,
    amount: Amount,
    channel: z.string(),
    destChain: ChainId,
  }),
  z.object({ ...intentBase, kind: z.literal('psbt'), psbtBase64: z.string() }),
]);
export type TxIntent = z.infer<typeof TxIntent>;

export const SignRequest = z.object({
  id: z.string(),
  txId: z.string(),
  keyGroupId: z.string(),
  curve: Curve,
  payloadHashHex: z.string().regex(/^[0-9a-f]{64}$/),
  payloadHex: z.string().regex(/^[0-9a-f]*$/),
});
export type SignRequest = z.infer<typeof SignRequest>;

export const Signature = z.object({
  signRequestId: z.string(),
  curve: Curve,
  signatureHex: z.string(),
  recoveryId: z.number().int().min(0).max(3).nullable().optional(),
});
export type Signature = z.infer<typeof Signature>;

export const Window = z.enum(['tx', '1h', '24h', '7d', '30d']);
export type Window = z.infer<typeof Window>;

export const Rule = z.discriminatedUnion('rule', [
  z.object({
    rule: z.literal('spendCap'),
    window: Window,
    usdMicros: z.number().int().nonnegative(),
  }),
  z.object({ rule: z.literal('destinationAllow'), addresses: z.array(z.string()) }),
  z.object({ rule: z.literal('destinationDeny'), addresses: z.array(z.string()) }),
  z.object({ rule: z.literal('chainAllow'), chainIds: z.array(ChainId) }),
  z.object({ rule: z.literal('assetAllow'), assets: z.array(AssetRef) }),
  z.object({ rule: z.literal('maxSlippageBps'), bps: z.number().int().nonnegative() }),
  z.object({ rule: z.literal('requireSimulationPass') }),
  z.object({
    rule: z.literal('requireApprovers'),
    deviceIds: z.array(z.string()),
    atLeast: z.number().int().min(1),
  }),
  z.object({ rule: z.literal('cooldown'), seconds: z.number().int().nonnegative() }),
  z.object({ rule: z.literal('maxPendingProposals'), count: z.number().int().nonnegative() }),
  z.object({ rule: z.literal('refuseUntrustedDestinations') }),
]);
export type Rule = z.infer<typeof Rule>;

export const PolicyMode = z.enum(['enforce', 'audit']);
export type PolicyMode = z.infer<typeof PolicyMode>;

export const Policy = z.object({
  id: z.string(),
  name: z.string(),
  mode: PolicyMode,
  rules: z.array(Rule),
});
export type Policy = z.infer<typeof Policy>;

export const PolicyContext = z.object({
  nowMs: z.number().int(),
  spentUsdMicros: z.partialRecord(Window, z.number().int().nonnegative()).default({}),
  pendingProposals: z.number().int().nonnegative().default(0),
  lastTxAtMs: z.number().int().nullable().optional(),
  simulationOk: z.boolean().nullable().optional(),
  keyGroup: KeyGroup.nullable().optional(),
});
export type PolicyContext = z.infer<typeof PolicyContext>;

export const ApproverRequirement = z.object({
  deviceIds: z.array(z.string()),
  atLeast: z.number().int().min(1),
});

export const Decision = z.discriminatedUnion('decision', [
  z.object({
    decision: z.literal('allow'),
    requiredApprovers: z.array(ApproverRequirement),
    auditNotes: z.array(z.string()),
  }),
  z.object({
    decision: z.literal('deny'),
    reasons: z.array(z.string()),
    auditNotes: z.array(z.string()),
  }),
]);
export type Decision = z.infer<typeof Decision>;

export const TxState = z.enum([
  'draft',
  'simulated',
  'evaluated',
  'denied',
  'awaiting',
  'signing',
  'signed',
  'broadcast',
  'pending',
  'confirmed',
  'replaced',
  'dropped',
  'expired',
  'rejected',
  'failed',
]);
export type TxState = z.infer<typeof TxState>;

export const WalletKind = z.enum(['tss', 'single', 'watch', 'hardware']);
export type WalletKind = z.infer<typeof WalletKind>;

export const Folder = z.object({
  id: z.string(),
  parentId: z.string().nullable(),
  name: z.string(),
  color: z.string().nullable().optional(),
  tags: z.array(z.string()).default([]),
  defaultPolicyIds: z.array(z.string()).default([]),
  createdAtMs: z.number().int(),
  updatedAtMs: z.number().int(),
});
export type Folder = z.infer<typeof Folder>;

export const Wallet = z.object({
  id: z.string(),
  folderId: z.string(),
  name: z.string(),
  kind: WalletKind,
  keyGroupId: z.string().nullable(),
  tags: z.array(z.string()).default([]),
  notes: z.string().nullable().optional(),
  createdAtMs: z.number().int(),
  updatedAtMs: z.number().int(),
});
export type Wallet = z.infer<typeof Wallet>;

export const Account = z.object({
  id: z.string(),
  walletId: z.string(),
  family: ChainFamily,
  chainId: ChainId,
  address: z.string(),
  derivationPath: z.string().nullable().optional(),
  publicKeyHex: z.string(),
  label: z.string().nullable().optional(),
  hidden: z.boolean().default(false),
});
export type Account = z.infer<typeof Account>;
