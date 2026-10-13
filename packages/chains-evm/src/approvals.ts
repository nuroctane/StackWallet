import { fetchJson, type FetchOptions } from '@stackwallet/chains';
import { z } from 'zod';

/**
 * Open spending permissions on an EVM address: ERC-20 allowances, ERC-721
 * single-token approvals and operator grants (`setApprovalForAll`, ERC-721
 * and ERC-1155). Discovery reads the owner's `Approval` / `ApprovalForAll`
 * logs from an indexer; every candidate is then re-read from the contract
 * over JSON-RPC, because an indexer is a hint and the contract is the truth
 * (a transfer silently clears an NFT approval, a spend lowers an allowance).
 *
 * The result is conservative: a candidate whose contract read fails stays
 * open and is marked unverified, since a security tag that disappears on a
 * network error would be worse than one that lingers.
 */

/** keccak256("Approval(address,address,uint256)"), shared by ERC-20 and ERC-721. */
export const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
/** keccak256("ApprovalForAll(address,address,bool)"), shared by ERC-721 and ERC-1155. */
export const APPROVAL_FOR_ALL_TOPIC =
  '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31';

const SEL_ALLOWANCE = '0xdd62ed3e';
const SEL_GET_APPROVED = '0x081812fc';
const SEL_OWNER_OF = '0x6352211e';
const SEL_IS_APPROVED_FOR_ALL = '0xe985e9c5';

/** Indexer pages stop here; a full page means the scan may be incomplete. */
export const MAX_APPROVAL_LOGS = 1000;
/** Contract reads per address per scan; anything beyond stays open, unverified. */
export const MAX_APPROVAL_CHECKS = 120;

export type ApprovalKind = 'erc20' | 'nft' | 'operator';

export interface ApprovalLog {
  address: string;
  topics: string[];
  data: string;
  blockNumber: number;
  logIndex: number;
  transactionHash: string;
}

export interface ApprovalCandidate {
  kind: ApprovalKind;
  token: string;
  spender: string;
  tokenId?: string;
  /** Amount granted by the last event (ERC-20 only). */
  granted?: string;
  txHash: string;
  blockNumber: number;
}

export interface OpenApproval extends ApprovalCandidate {
  chainId: string;
  /** Current allowance read from the contract (ERC-20 only). */
  amount?: string;
  unlimited: boolean;
  /** False when the contract could not be read and the indexer's word was kept. */
  verified: boolean;
}

export interface ApprovalScan {
  chainId: string;
  owner: string;
  open: OpenApproval[];
  /** True when the indexer answered with a full page, so older approvals may be missing. */
  truncated: boolean;
  checkedAtMs: number;
}

const ADDR = /^0x[0-9a-f]{40}$/;
const WORD = /^0x[0-9a-f]{64}$/;
const UNLIMITED = (1n << 255n) - 1n;

const pad = (hex: string) => hex.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const topicAddress = (t: string | undefined): string | null => {
  const v = t?.toLowerCase();
  if (!v || !WORD.test(v) || !v.startsWith('0x000000000000000000000000')) return null;
  return `0x${v.slice(26)}`;
};
const hexNumber = z
  .union([z.string().regex(/^(0x[0-9a-fA-F]{1,16}|\d{1,20})$/), z.number().int().nonnegative()])
  .transform((v) => (typeof v === 'number' ? v : Number(BigInt(v))));

const RawLog = z.object({
  address: z.string().max(64),
  topics: z.array(z.string().max(80).nullable()).max(4),
  data: z.string().max(4096),
  blockNumber: hexNumber,
  logIndex: hexNumber.optional(),
  transactionHash: z.string().max(80),
});

const LogsResponse = z.object({
  status: z.string().max(8).optional(),
  message: z.string().max(400).optional(),
  result: z.union([z.array(RawLog).max(MAX_APPROVAL_LOGS * 2), z.string().max(400), z.null()]),
});

/** Parse an Etherscan-compatible `module=logs&action=getLogs` answer (Blockscout serves one). */
export function parseLogsResponse(raw: unknown): ApprovalLog[] {
  const r = LogsResponse.parse(raw);
  if (!Array.isArray(r.result)) {
    // "No logs found" arrives as status 0 with an empty or textual result.
    if (r.status === '0' && /no (records|logs)/i.test(`${r.message ?? ''} ${r.result ?? ''}`))
      return [];
    if (r.result === null || r.result === '') return [];
    throw new Error(`indexer refused the log query: ${r.message ?? r.result}`);
  }
  return r.result.map((l) => ({
    address: l.address.toLowerCase(),
    topics: l.topics.filter((t): t is string => typeof t === 'string').map((t) => t.toLowerCase()),
    data: l.data.toLowerCase(),
    blockNumber: l.blockNumber,
    logIndex: l.logIndex ?? 0,
    transactionHash: l.transactionHash.toLowerCase(),
  }));
}

/**
 * The latest event per (token, spender) / (token, tokenId) / (token, operator)
 * decides whether a candidate exists. Logs not emitted by `owner` are ignored.
 */
export function candidatesFromLogs(
  owner: string,
  logs: readonly ApprovalLog[],
): ApprovalCandidate[] {
  const me = owner.toLowerCase();
  const ordered = [...logs].sort(
    (a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex,
  );
  const latest = new Map<string, ApprovalCandidate | null>();
  for (const log of ordered) {
    if (!ADDR.test(log.address)) continue;
    const [topic0, t1, t2, t3] = log.topics;
    if (topicAddress(t1) !== me) continue;
    const other = topicAddress(t2);
    if (other === null) continue;
    const base = { token: log.address, txHash: log.transactionHash, blockNumber: log.blockNumber };
    if (topic0 === APPROVAL_TOPIC && log.topics.length === 3) {
      if (!WORD.test(log.data)) continue;
      const value = BigInt(log.data);
      latest.set(
        `erc20|${log.address}|${other}`,
        value === 0n ? null : { ...base, kind: 'erc20', spender: other, granted: value.toString() },
      );
    } else if (topic0 === APPROVAL_TOPIC && log.topics.length === 4) {
      if (!t3 || !WORD.test(t3)) continue;
      const tokenId = BigInt(t3).toString();
      latest.set(
        `nft|${log.address}|${tokenId}`,
        other === `0x${'0'.repeat(40)}` ? null : { ...base, kind: 'nft', spender: other, tokenId },
      );
    } else if (topic0 === APPROVAL_FOR_ALL_TOPIC && log.topics.length === 3) {
      if (!WORD.test(log.data)) continue;
      latest.set(
        `operator|${log.address}|${other}`,
        BigInt(log.data) === 0n ? null : { ...base, kind: 'operator', spender: other },
      );
    }
  }
  return [...latest.values()].filter((c): c is ApprovalCandidate => c !== null);
}

/** `eth_call` against `to` with `data`, returning the raw hex result. */
export type ContractRead = (to: string, data: string) => Promise<string>;

function word(result: string, i = 0): string | null {
  const hex = result.toLowerCase().replace(/^0x/, '');
  const w = hex.slice(i * 64, i * 64 + 64);
  return /^[0-9a-f]{64}$/.test(w) ? w : null;
}

/**
 * Re-read every candidate from its contract. A read that *answers* "closed"
 * removes the candidate; a read that fails keeps it as unverified.
 */
export async function verifyCandidates(
  chainId: string,
  owner: string,
  candidates: readonly ApprovalCandidate[],
  read: ContractRead,
): Promise<OpenApproval[]> {
  const me = owner.toLowerCase();
  const out: OpenApproval[] = [];
  for (const [i, c] of candidates.entries()) {
    const unverified: OpenApproval = {
      ...c,
      chainId,
      unlimited:
        c.kind === 'operator' || (c.granted !== undefined && BigInt(c.granted) >= UNLIMITED),
      verified: false,
      ...(c.granted !== undefined ? { amount: c.granted } : {}),
    };
    if (i >= MAX_APPROVAL_CHECKS) {
      out.push(unverified);
      continue;
    }
    try {
      if (c.kind === 'erc20') {
        const w = word(await read(c.token, `${SEL_ALLOWANCE}${pad(me)}${pad(c.spender)}`));
        if (w === null) throw new Error('malformed allowance');
        const amount = BigInt(`0x${w}`);
        if (amount === 0n) continue;
        out.push({
          ...c,
          chainId,
          amount: amount.toString(),
          unlimited: amount >= UNLIMITED,
          verified: true,
        });
      } else if (c.kind === 'operator') {
        const w = word(
          await read(c.token, `${SEL_IS_APPROVED_FOR_ALL}${pad(me)}${pad(c.spender)}`),
        );
        if (w === null) throw new Error('malformed isApprovedForAll');
        if (BigInt(`0x${w}`) === 0n) continue;
        out.push({ ...c, chainId, unlimited: true, verified: true });
      } else {
        const id = pad(BigInt(c.tokenId ?? '0').toString(16));
        let approved: string | null;
        let holder: string | null;
        try {
          approved = word(await read(c.token, `${SEL_GET_APPROVED}${id}`));
          holder = word(await read(c.token, `${SEL_OWNER_OF}${id}`));
        } catch (err) {
          // A revert means the token no longer exists; nothing is approved on it.
          if (err instanceof Error && /revert/i.test(err.message)) continue;
          throw err;
        }
        if (approved === null || holder === null) throw new Error('malformed NFT read');
        const spenderNow = `0x${approved.slice(24)}`;
        const holderNow = `0x${holder.slice(24)}`;
        if (holderNow !== me || spenderNow !== c.spender) continue;
        out.push({ ...c, chainId, unlimited: false, verified: true });
      }
    } catch {
      out.push(unverified);
    }
  }
  return out;
}

export interface ScanOptions {
  chainId: string;
  owner: string;
  /** Indexer base, e.g. `https://eth.blockscout.com`. */
  indexer: string;
  read: ContractRead;
  now?: () => number;
  fetchOptions?: FetchOptions;
}

export function approvalLogsUrl(indexer: string, owner: string, topic0: string): string {
  const qs = new URLSearchParams({
    module: 'logs',
    action: 'getLogs',
    fromBlock: '0',
    toBlock: 'latest',
    topic0,
    topic1: `0x${pad(owner)}`,
    topic0_1_opr: 'and',
  });
  return `${indexer.replace(/\/+$/, '')}/api?${qs.toString()}`;
}

export async function scanApprovals(opts: ScanOptions): Promise<ApprovalScan> {
  const owner = opts.owner.toLowerCase();
  if (!ADDR.test(owner)) throw new TypeError(`invalid evm address ${opts.owner}`);
  const [approvals, operators] = await Promise.all(
    [APPROVAL_TOPIC, APPROVAL_FOR_ALL_TOPIC].map(async (topic) =>
      parseLogsResponse(
        await fetchJson(approvalLogsUrl(opts.indexer, owner, topic), opts.fetchOptions),
      ),
    ),
  );
  const logs = [...approvals!, ...operators!];
  const candidates = candidatesFromLogs(owner, logs);
  const open = await verifyCandidates(opts.chainId, owner, candidates, opts.read);
  return {
    chainId: opts.chainId,
    owner,
    open,
    truncated: approvals!.length >= MAX_APPROVAL_LOGS || operators!.length >= MAX_APPROVAL_LOGS,
    checkedAtMs: (opts.now ?? Date.now)(),
  };
}

/** Calldata that revokes one approval; the user signs it like any other call. */
export function revokeCalldata(a: Pick<OpenApproval, 'kind' | 'spender' | 'tokenId'>): string {
  if (a.kind === 'erc20') return `0x095ea7b3${pad(a.spender)}${'0'.repeat(64)}`;
  if (a.kind === 'operator') return `0xa22cb465${pad(a.spender)}${'0'.repeat(64)}`;
  return `0x095ea7b3${'0'.repeat(64)}${pad(BigInt(a.tokenId ?? '0').toString(16))}`;
}
