/**
 * Everscale / Venom (TVM) adapter: the keyless public surfaces. Everscale
 * mainnet is read over the EverCloud GraphQL API; Venom mainnet and testnet
 * speak the nekoton JRPC dialect. Account and transaction bags-of-cells are
 * decoded here by hand, mirroring the layouts pinned in the core
 * (`crates/stackwallet-core/src/everscale.rs`). Every endpoint proves its
 * network by the key block's global id before it is trusted.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';
import {
  BaseAdapter,
  nativeHolding,
  postJsonText,
  publicKeyBytes,
  requireCurve,
  withCrossCheck,
  withFailover,
  type Address,
  type BaseAdapterOptions,
  type ChainInfo,
  type FetchOptions,
  type Holding,
  type Page,
  type TxHash,
  type TxRecord,
  type TxStatus,
} from '@stackwallet/chains';
import type { ChainId, PublicKey, TxIntent } from '@stackwallet/core-client';
import { z } from 'zod';

import { Cell, parseBoc } from './cell.js';

export const EVERSCALE_MAINNET = 'ever:42';
export const VENOM_MAINNET = 'venom:1';
export const VENOM_TESTNET = 'venom:1002';

/** Representation hash of the EverWallet contract code (`broxus/ever-wallet-contract`). */
export const EVER_WALLET_CODE_HASH =
  '3ba6528ab2694c118180aa3bd10dd19ff400b909ab4dcf58fc69925b2c7b12a6';

const EVER_WALLET_CODE_BOC =
  'te6ccgEBBgEA/AABFP8A9KQT9LzyyAsBAgEgBQIC5vJx1wEBwADyeoMI1xjtRNCDB9cB1ws/yPgozxYjzxbJ+QADcdcBAcMAmoMH1wFRE7ry4GTegEDXAYAg1wGAINcBVBZ1+RDyqPgju/J5Zr74I4EHCKCBA+ioUiC8sfJ0AiCCEEzuZGy64w8ByMv/yz/J7VQEAwA+ghAWnj4Ruo4R+AACkyDXSpd41wHUAvsA6NGTMvI84gCYMALXTND6QIMG1wFx1wF41wHXTPgAcIAQBKoCFLHIywVQBc8WUAP6AstpItAhzzEh10mghAm5mDNwAcsAWM8WlzBxAcsAEsziyQH7AAAE0jA=';

// ---------------------------------------------------------------------------
// Addresses and the EverWallet state init

/** `0:<64 lowercase hex>` is the only spelling accepted anywhere in the family. */
export function parseEverscaleAddress(address: string): Uint8Array | undefined {
  if (!/^0:[0-9a-f]{64}$/.test(address)) return undefined;
  return hexToBytes(address.slice(2));
}

export function isValidEverscaleAddress(address: string): boolean {
  return parseEverscaleAddress(address) !== undefined;
}

export function everWalletCode(): Cell {
  return parseBoc(base64.decode(EVER_WALLET_CODE_BOC));
}

/** StateInit of the EverWallet for an ed25519 key: fixed code, data `[pubkey][timestamp ms]`. */
export function everWalletStateInit(publicKey: PublicKey): Cell {
  requireCurve(publicKey, 'ed25519');
  const pub = publicKeyBytes(publicKey);
  const dataBits = new Uint8Array(40); // 256-bit pubkey + zero timestamp
  dataBits.set(pub, 0);
  // state_init: split_depth none | special none | code some | data some | library none
  return new Cell(new Uint8Array([0b00110000]), 5, [everWalletCode(), new Cell(dataBits, 320, [])]);
}

/** Representation hash of the EverWallet state init — the account id. */
export function everWalletHash(publicKey: PublicKey): Uint8Array {
  return everWalletStateInit(publicKey).hash;
}

export function everscaleAddressFromPublicKey(publicKey: PublicKey): Address {
  return `0:${bytesToHex(everWalletHash(publicKey))}`;
}

// ---------------------------------------------------------------------------
// Cell bit reading

/** A forward cursor over a cell's bits and refs. */
export class Slice {
  private atBit = 0;
  private atRef = 0;
  constructor(readonly cell: Cell) {}

  get position(): number {
    return this.atBit;
  }

  uint(bits: number): bigint {
    if (this.atBit + bits > this.cell.bits) throw new Error('slice overflow');
    let v = 0n;
    for (let i = 0; i < bits; i++) {
      const at = this.atBit + i;
      v = (v << 1n) | BigInt((this.cell.data[at >> 3]! >> (7 - (at & 7))) & 1);
    }
    this.atBit += bits;
    return v;
  }

  bit(): boolean {
    return this.uint(1) === 1n;
  }

  bytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = Number(this.uint(8));
    return out;
  }

  /** VarUInteger n: a `len` of log2(n) bits counting bytes, then that many bytes. */
  varUint(logLenBits: number): bigint {
    const len = Number(this.uint(logLenBits));
    return this.uint(len * 8);
  }

  /** CurrencyCollection: grams as VarUInteger16 plus the (empty) extra map flag. */
  coins(): bigint {
    const grams = this.varUint(4);
    if (this.bit()) throw new Error('non-native currency in CurrencyCollection');
    return grams;
  }

  ref(): Cell {
    if (this.atRef >= this.cell.refs.length) throw new Error('ref overflow');
    return this.cell.refs[this.atRef++]!;
  }
}

// ---------------------------------------------------------------------------
// Account state

export type EverAccountStatus = 'active' | 'uninit' | 'frozen' | 'nonexist';

export interface EverAccount {
  balance: bigint;
  status: EverAccountStatus;
  /** Code hash when active. */
  codeHash?: string;
  /** Stored `timestamp_ms` of an EverWallet (the `time` watermark). */
  timestampMs?: bigint;
}

/** Decodes an account bag-of-cells (`getContractState.account`). */
export function parseAccountBoc(boc: Uint8Array): EverAccount {
  const root = parseBoc(boc);
  const s = new Slice(root);
  if (!s.bit()) throw new Error('account_none');
  s.bytes(32); // addr; the request already named the account
  s.coins(); // storage_stat used
  s.uint(64); // last_trans_lt
  const balance = s.coins();
  // account_state: 0 = active state_init, 10 = uninit, 11 = frozen
  let status: EverAccountStatus;
  let codeHash: string | undefined;
  let timestampMs: bigint | undefined;
  if (!s.bit()) {
    status = 'active';
    // state_init flags: split_depth | special | code | data | library
    if (s.bit()) s.uint(5); // split depth
    if (s.bit()) s.uint(3); // special
    if (s.bit()) codeHash = bytesToHex(s.ref().hash);
    if (s.bit()) {
      const data = s.ref();
      if (codeHash === EVER_WALLET_CODE_HASH && data.bits >= 320) {
        const d = new Slice(data);
        d.bytes(32);
        timestampMs = d.uint(64);
      }
    }
  } else {
    status = s.bit() ? 'frozen' : 'uninit';
  }
  const out: EverAccount = { balance, status };
  if (codeHash !== undefined) out.codeHash = codeHash;
  if (timestampMs !== undefined) out.timestampMs = timestampMs;
  return out;
}

// ---------------------------------------------------------------------------
// Transactions

export interface EverMessage {
  external: boolean;
  source: string | null;
  destination: string | null;
  value: bigint;
}

export interface EverTransaction {
  hash: string;
  lt: string;
  utime: number;
  fee: bigint | null;
  aborted: boolean | null;
  inMsg: EverMessage | null;
  outMsgs: EverMessage[];
}

/** An internal address (`addr_std$10`, no anycast); throws on anything else. */
function readAddr(s: Slice): string {
  if (s.uint(2) !== 0b10n) throw new Error('not an addr_std');
  if (s.bit()) throw new Error('anycast not supported');
  const wc = Number(s.uint(8));
  return `${wc}:${bytesToHex(s.bytes(32))}`;
}

/** Reads a message info cell: internal, ext-in and ext-out headers. */
function parseMessage(cell: Cell): EverMessage {
  const s = new Slice(cell);
  const tag = s.uint(2);
  if (tag === 0b00n) {
    // int_msg_info$0: ihr_disabled bounce bounced src dest value ...
    s.uint(3);
    const source = readAddr(s);
    const destination = readAddr(s);
    const value = s.coins();
    return { external: false, source, destination, value };
  }
  if (tag === 0b10n) {
    // ext_in_msg_info$10: src addr_none, dest, import_fee
    s.uint(2);
    const destination = readAddr(s);
    return { external: true, source: null, destination, value: 0n };
  }
  // ext_out_msg_info$11: src, dest addr_ext
  readAddr(s);
  const destTag = s.uint(2);
  if (destTag === 0b01n) s.uint(Number(s.uint(9))); // addr_ext$01 len:uint9 bits
  return { external: true, source: null, destination: null, value: 0n };
}

const ceilLog2 = (n: number): number => 32 - Math.clz32(n - 1);

/** Walks an `out_msgs` HashmapE (15-bit keys, `^Message` values) depth-first. */
function hashmapValues(cell: Cell, keyBits: number, prefix: boolean[]): Cell[] {
  const s = new Slice(cell);
  // hm_edge label: hml_short$0 | hml_long$10 | hml_same$11
  if (!s.bit()) {
    let len = 0;
    while (s.bit()) len++;
    for (let i = 0; i < len; i++) prefix.push(s.bit());
  } else if (!s.bit()) {
    const len = Number(s.uint(ceilLog2(keyBits + 1)));
    for (let i = 0; i < len; i++) prefix.push(s.bit());
  } else {
    const v = s.bit();
    const len = Number(s.uint(ceilLog2(keyBits + 1)));
    for (let i = 0; i < len; i++) prefix.push(v);
  }
  const remaining = keyBits - prefix.length;
  if (remaining < 0) throw new Error('hashmap label longer than the key');
  if (remaining === 0) {
    if (cell.refs.length !== 1) throw new Error('hashmap leaf without a value ref');
    return [cell.refs[0]!];
  }
  if (cell.refs.length !== 2) throw new Error('hashmap fork without two refs');
  return [
    ...hashmapValues(cell.refs[0]!, keyBits, [...prefix, false]),
    ...hashmapValues(cell.refs[1]!, keyBits, [...prefix, true]),
  ];
}

/**
 * Reads the failure verdict out of an ordinary transaction description;
 * null for merge/split/tick-tock descriptions.
 */
function parseAborted(cell: Cell): boolean | null {
  const s = new Slice(cell);
  if (s.uint(4) !== 0b0000n) return null; // trans_ord only
  s.bit(); // credit_first
  if (s.bit()) {
    // storage_ph
    s.varUint(4); // storage_fees_collected
    if (s.bit()) s.varUint(4); // storage_fees_due
    if (s.bit()) s.uint(2); // status_change beyond acst_unchanged$0
  }
  if (s.bit()) {
    // credit_ph
    if (s.bit()) s.varUint(4); // due_fees_collected
    s.coins(); // credit
  }
  if (!s.bit()) return true; // compute skipped (no state / no gas / suspended)
  // tr_compute_phase_vm$1
  const success = s.bit();
  s.bit(); // msg_state_used
  s.bit(); // account_activated
  s.varUint(4); // gas_fees
  s.varUint(3); // gas_used
  s.varUint(3); // gas_limit
  if (s.bit()) s.varUint(3); // gas_credit
  s.uint(8); // mode
  s.uint(32); // exit_code
  if (s.bit()) s.uint(32); // exit_arg
  s.uint(32); // vm_steps
  s.bytes(32); // vm_init_state_hash
  s.bytes(32); // vm_final_state_hash
  s.bit(); // action: (Maybe ^TrActionPhase)
  const aborted = s.bit();
  return aborted || !success;
}

/** Decodes a transaction bag-of-cells (`getTransactionsList` / `getTransaction`). */
export function parseTransactionBoc(boc: Uint8Array): EverTransaction {
  const root = parseBoc(boc);
  const s = new Slice(root);
  if (s.uint(4) !== 0b0111n) throw new Error('not a transaction');
  s.bytes(32); // account_addr
  const lt = s.uint(64);
  s.bytes(32); // prev_trans_hash
  s.uint(64); // prev_trans_lt
  const utime = Number(s.uint(32));
  s.uint(15); // outmsg_cnt
  s.uint(4); // orig_status, end_status
  const fee = s.coins(); // total_fees
  const msgsCell = root.refs[0];
  const description = root.refs[2];
  let inMsg: EverMessage | null = null;
  let outMsgs: EverMessage[] = [];
  if (msgsCell) {
    const ms = new Slice(msgsCell);
    if (ms.bit()) inMsg = parseMessage(ms.ref());
    if (ms.bit()) outMsgs = hashmapValues(ms.ref(), 15, []).map(parseMessage);
  }
  return {
    hash: bytesToHex(root.hash),
    lt: lt.toString(),
    utime,
    fee,
    aborted: description ? parseAborted(description) : null,
    inMsg,
    outMsgs,
  };
}

// ---------------------------------------------------------------------------
// Endpoint surfaces

export interface SendVerdict {
  accepted: boolean;
  error?: string;
}

export interface EverNode {
  readonly url: string;
  /** Refuses an endpoint whose key block reports another network. */
  checkNetwork(): Promise<void>;
  account(address: string): Promise<EverAccount>;
  transactions(address: string, limit: number, beforeLt?: string): Promise<EverTransaction[]>;
  transactionByHash(hash: string): Promise<EverTransaction | null>;
  transactionByMessage(hash: string): Promise<EverTransaction | null>;
  send(bocBase64: string): Promise<SendVerdict>;
}

// ---------------- EverCloud GraphQL (Everscale mainnet) --------------------

const gqlMessageSchema = z.object({
  src: z.string().nullish(),
  dst: z.string().nullish(),
  value: z.string().nullish(),
  msg_type: z.number().int(),
});

const gqlTxSchema = z.object({
  data: z.object({
    transactions: z.array(
      z.object({
        hash: z.string(),
        lt: z.string(),
        now: z.number().int().nullish(),
        total_fees: z.string().nullish(),
        aborted: z.boolean().nullish(),
        in_message: gqlMessageSchema.nullish(),
        out_messages: z.array(gqlMessageSchema).nullish(),
      }),
    ),
  }),
});

const TX_FIELDS =
  'hash lt now total_fees aborted in_message { src dst value msg_type } out_messages { src dst value msg_type }';

async function graphql<T>(
  url: string,
  query: string,
  schema: z.ZodType<T>,
  fetch: FetchOptions,
): Promise<T> {
  const res = await postJsonText(url, { query }, fetch);
  return schema.parse(JSON.parse(res));
}

const gqlMessage = (m: z.infer<typeof gqlMessageSchema> | null | undefined): EverMessage | null => {
  if (!m) return null;
  return {
    external: m.msg_type === 2,
    source: m.src ?? null,
    destination: m.dst ?? null,
    value: m.value ? BigInt(m.value) : 0n,
  };
};

const gqlTx = (
  t: z.infer<typeof gqlTxSchema>['data']['transactions'][number],
): EverTransaction => ({
  hash: t.hash,
  lt: BigInt(t.lt).toString(),
  utime: t.now ?? 0,
  fee: t.total_fees ? BigInt(t.total_fees) : null,
  aborted: t.aborted ?? null,
  inMsg: gqlMessage(t.in_message),
  outMsgs: (t.out_messages ?? []).map((m) => gqlMessage(m)!),
});

const accTypeName = (t: number): EverAccountStatus =>
  t === 1 ? 'active' : t === 2 ? 'frozen' : t === 0 ? 'uninit' : 'nonexist';

function graphqlNode(url: string, fetch: FetchOptions, expectedGlobalId: number): EverNode {
  return {
    url,
    async checkNetwork() {
      const res = await graphql(
        url,
        'query { blocks(filter: { seq_no: { eq: 1 }, workchain_id: { eq: -1 } }, limit: 1) { global_id } }',
        z.object({ data: z.object({ blocks: z.array(z.object({ global_id: z.number() })) }) }),
        fetch,
      );
      const id = res.data.blocks[0]?.global_id;
      if (id !== expectedGlobalId)
        throw new Error(`global id mismatch: expected ${expectedGlobalId}, got ${id}`);
    },
    async account(address) {
      const res = await graphql(
        url,
        `query { accounts(filter: { id: { eq: "${address}" } }) { balance acc_type code_hash data } }`,
        z.object({
          data: z.object({
            accounts: z.array(
              z.object({
                balance: z.string(),
                acc_type: z.number().int(),
                code_hash: z.string().nullish(),
                data: z.string().nullish(),
              }),
            ),
          }),
        }),
        fetch,
      );
      const row = res.data.accounts[0];
      if (!row) return { balance: 0n, status: 'nonexist' };
      const out: EverAccount = { balance: BigInt(row.balance), status: accTypeName(row.acc_type) };
      if (row.code_hash) out.codeHash = row.code_hash;
      if (row.acc_type === 1 && row.code_hash === EVER_WALLET_CODE_HASH && row.data) {
        try {
          const data = parseBoc(base64.decode(row.data));
          if (data.bits >= 320) {
            const d = new Slice(data);
            d.bytes(32);
            out.timestampMs = d.uint(64);
          }
        } catch {
          // A malformed data cell leaves the timestamp unknown; send then refuses.
        }
      }
      return out;
    },
    async transactions(address, limit, beforeLt) {
      const ltFilter = beforeLt ? `, lt: { lt: "${beforeLt}" }` : '';
      const res = await graphql(
        url,
        `query { transactions(filter: { account_addr: { eq: "${address}" }${ltFilter} }, orderBy: [{ path: "lt", direction: DESC }], limit: ${limit}) { ${TX_FIELDS} } }`,
        gqlTxSchema,
        fetch,
      );
      return res.data.transactions.map(gqlTx);
    },
    async transactionByHash(hash) {
      const res = await graphql(
        url,
        `query { transactions(filter: { hash: { eq: "${hash}" } }, limit: 1) { ${TX_FIELDS} } }`,
        gqlTxSchema,
        fetch,
      );
      return res.data.transactions[0] ? gqlTx(res.data.transactions[0]) : null;
    },
    async transactionByMessage(hash) {
      // The external message id is its hash; the executing transaction names it as in_msg.
      const res = await graphql(
        url,
        `query { transactions(filter: { in_msg: { eq: "${hash}" } }, limit: 1) { ${TX_FIELDS} } }`,
        gqlTxSchema,
        fetch,
      );
      return res.data.transactions[0] ? gqlTx(res.data.transactions[0]) : null;
    },
    send() {
      return Promise.resolve({ accepted: false, error: 'read-only endpoint' });
    },
  };
}

// ---------------- nekoton JRPC (Venom mainnet / testnet) -------------------

async function jrpcCall(
  url: string,
  method: string,
  params: unknown,
  fetch: FetchOptions,
): Promise<unknown> {
  const res = await postJsonText(url, { jsonrpc: '2.0', id: 1, method, params }, fetch);
  return JSON.parse(res) as unknown;
}

function jrpcNode(url: string, fetch: FetchOptions, expectedGlobalId: number): EverNode {
  const transactionByHash = async (hash: string): Promise<EverTransaction | null> => {
    const res = z
      .object({ result: z.string().nullable() })
      .parse(await jrpcCall(url, 'getTransaction', { id: hash }, fetch));
    return res.result ? parseTransactionBoc(base64.decode(res.result)) : null;
  };
  return {
    url,
    async checkNetwork() {
      const res = z
        .object({ result: z.object({ block: z.string() }).nullable() })
        .parse(await jrpcCall(url, 'getLatestKeyBlock', {}, fetch));
      if (!res.result) throw new Error('no key block');
      const s = new Slice(parseBoc(base64.decode(res.result.block)));
      if (s.uint(32) !== 0x11ef55aan) throw new Error('not a block');
      const id = Number(s.uint(32));
      if (id !== expectedGlobalId)
        throw new Error(`global id mismatch: expected ${expectedGlobalId}, got ${id}`);
    },
    async account(address) {
      const res = z
        .object({
          result: z
            .object({ account: z.object({ type: z.string(), boc: z.string().optional() }) })
            .nullable(),
          error: z.object({ message: z.string() }).optional(),
        })
        .parse(await jrpcCall(url, 'getContractState', { address }, fetch));
      if (res.error) throw new Error(res.error.message);
      const account = res.result?.account;
      if (!account || account.type !== 'exists' || !account.boc)
        return { balance: 0n, status: 'nonexist' };
      return parseAccountBoc(base64.decode(account.boc));
    },
    async transactions(address, limit, beforeLt) {
      const res = z
        .object({ result: z.object({ transactions: z.array(z.string()) }) })
        .parse(
          await jrpcCall(
            url,
            'getTransactionsList',
            { account: address, limit, ...(beforeLt ? { lastTransactionLt: beforeLt } : {}) },
            fetch,
          ),
        );
      return res.result.transactions.map((boc) => parseTransactionBoc(base64.decode(boc)));
    },
    transactionByHash,
    async transactionByMessage(hash) {
      const res = z
        .object({ result: z.object({ lt: z.string(), hash: z.string() }).nullable() })
        .parse(await jrpcCall(url, 'getDstTransaction', { messageHash: hash }, fetch));
      if (!res.result) return null;
      return transactionByHash(res.result.hash);
    },
    async send(bocBase64) {
      try {
        const res = z
          .object({ error: z.object({ message: z.string() }).optional() })
          .parse(await jrpcCall(url, 'sendMessage', { message: bocBase64 }, fetch));
        if (res.error?.message) return { accepted: false, error: res.error.message };
        return { accepted: true };
      } catch (error) {
        return { accepted: false, error: error instanceof Error ? error.message : String(error) };
      }
    },
  };
}

/** The global id in the chain id selects the endpoint dialect and its network check. */
function globalId(chain: ChainInfo): number {
  const gid = Number(chain.chainId.split(':')[1]);
  if (!Number.isInteger(gid)) throw new Error(`bad chain id ${chain.chainId}`);
  return gid;
}

/** EverCloud GraphQL for Everscale, nekoton JRPC for Venom. */
export function bindNode(url: string, chain: ChainInfo, fetch: FetchOptions): EverNode {
  return chain.chainId.startsWith('ever:')
    ? graphqlNode(url, fetch, globalId(chain))
    : jrpcNode(url, fetch, globalId(chain));
}

// ---------------------------------------------------------------------------
// Records

function record(chain: ChainInfo, account: string, tx: EverTransaction): TxRecord {
  const inMsg = tx.inMsg;
  const inward = inMsg !== null && !inMsg.external;
  const value = inward ? inMsg.value : tx.outMsgs.reduce((a, m) => a + m.value, 0n);
  const from = inward ? (inMsg.source ?? '') : account;
  const to = inward ? account : (tx.outMsgs[0]?.destination ?? undefined);
  return {
    hash: tx.hash,
    chainId: chain.chainId,
    timestampMs: tx.utime * 1000,
    from,
    ...(to ? { to } : {}),
    assetDeltas: [
      {
        assetRef: chain.nativeAsset.ref,
        amount: (inward ? value : -value).toString(),
      },
    ],
    feeAssetRef: chain.nativeAsset.ref,
    fee: tx.fee !== null ? tx.fee.toString() : null,
    status: tx.aborted === true ? 'failed' : 'confirmed',
    ...(inMsg !== null && inMsg.external && tx.outMsgs.length === 0
      ? { description: 'external message without transfers' }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// The adapter

export class EverscaleAdapter extends BaseAdapter<'everscale'> {
  constructor(opts: BaseAdapterOptions & { minIntervalMs?: number } = {}) {
    super('everscale', opts);
    void opts.minIntervalMs;
  }

  override deriveAddress(pub: PublicKey, chainId: ChainId): Address {
    this.requireChain(chainId);
    return everscaleAddressFromPublicKey(pub);
  }

  override validateAddress(addr: string, chainId: ChainId): boolean {
    this.requireChain(chainId);
    return isValidEverscaleAddress(addr);
  }

  /** One bound, network-checked endpoint for a chain. */
  async withNode<T>(chainId: ChainId, call: (node: EverNode) => Promise<T>): Promise<T> {
    const chain = this.requireChain(chainId);
    return withFailover(this.rpc, chainId, async (url) => {
      const node = bindNode(url, chain, this.fetchOptions());
      await this.verifyEndpoint(chainId, url, () => node.checkNetwork());
      return call(node);
    });
  }

  /** Network-checked account state; used by the send path. */
  accountState(addr: Address, chainId: ChainId): Promise<EverAccount> {
    return this.withNode(chainId, (node) => node.account(addr));
  }

  override async getBalances(addr: Address, chainId: ChainId): Promise<Holding[]> {
    const chain = this.requireChain(chainId);
    const res = await withCrossCheck(
      this.rpc,
      chainId,
      async (url) => {
        const node = bindNode(url, chain, this.fetchOptions());
        await this.verifyEndpoint(chainId, url, () => node.checkNetwork());
        return (await node.account(addr)).balance.toString();
      },
      { equal: (a, b) => a === b },
    );
    return [nativeHolding(chain, res.value, res.provenance)];
  }

  override async getHistory(
    addr: Address,
    chainId: ChainId,
    cursor?: string,
  ): Promise<Page<TxRecord>> {
    const chain = this.requireChain(chainId);
    if (!this.validateAddress(addr, chainId)) throw new Error('Invalid history address');
    const txs = await this.withNode(chainId, (node) => node.transactions(addr, 25, cursor));
    const oldest = txs[txs.length - 1];
    return {
      items: txs.map((t) => record(chain, addr, t)),
      ...(txs.length === 25 && oldest ? { nextCursor: oldest.lt } : {}),
    };
  }

  override async status(hash: TxHash, chainId: ChainId): Promise<TxStatus> {
    this.requireChain(chainId);
    const tx = await this.withNode(chainId, async (node) => {
      // A broadcast produces a message hash; a history entry is a transaction hash.
      return (await node.transactionByMessage(hash)) ?? (await node.transactionByHash(hash));
    });
    if (!tx) return { state: 'pending' };
    if (tx.aborted === true) return { state: 'failed', reason: 'transaction aborted' };
    return { state: 'confirmed', blockNumber: 0, timestampMs: tx.utime * 1000 };
  }
}

// ---------------------------------------------------------------------------
// Intent views shared with send.ts

export interface EverscaleTransfer {
  to: Address;
  evers: string;
}

const nonNegativeInteger = /^[0-9]+$/;

function parseTransfer(intent: TxIntent): EverscaleTransfer | undefined {
  if (intent.kind !== 'transfer') return undefined;
  if (intent.asset !== `${intent.chainId}:native`) return undefined;
  if (!isValidEverscaleAddress(intent.to)) return undefined;
  if (!nonNegativeInteger.test(intent.amount)) return undefined;
  return { to: intent.to, evers: intent.amount };
}

export function transferFromIntent(intent: TxIntent): EverscaleTransfer {
  if (![EVERSCALE_MAINNET, VENOM_MAINNET, VENOM_TESTNET].includes(intent.chainId))
    throw new Error(`Unexpected chain for everscale intent: ${intent.chainId}`);
  const tx = parseTransfer(intent);
  if (!tx) throw new Error('Malformed everscale transfer intent');
  return tx;
}

export function intentMatchesEverscaleTx(
  intent: TxIntent,
  tx: { chainId: ChainId; to: Address; evers: string },
): boolean {
  if (intent.chainId !== tx.chainId) return false;
  const transfer = parseTransfer(intent);
  return (
    !!transfer &&
    transfer.to === tx.to &&
    transfer.evers === tx.evers &&
    nonNegativeInteger.test(tx.evers)
  );
}
