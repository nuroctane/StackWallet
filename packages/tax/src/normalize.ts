import type { TxRecord } from '@stackwallet/chains';

import type { AccountHistory, Label, Leg, Overrides, ScopeAccount, TaxEvent } from './model.js';
import { INBOUND_LABELS, OUTBOUND_LABELS } from './model.js';

/**
 * Turns per-account chain history into one event per transaction. The same
 * transaction seen from several of the user's accounts (a payment between two
 * of their own wallets, or one Bitcoin spend from two of their addresses)
 * becomes a single event, so it is neither counted twice nor mistaken for a
 * sale to a stranger.
 */

const caseless = (chainId: string) => chainId.startsWith('eip155:');

export function normAddress(chainId: string, address: string): string {
  return caseless(chainId) ? address.toLowerCase() : address;
}

export function normHash(chainId: string, hash: string): string {
  return chainId.startsWith('solana:') || chainId.startsWith('bip122:') ? hash : hash.toLowerCase();
}

export function eventId(chainId: string, hash: string): string {
  return `${chainId}|${normHash(chainId, hash)}`;
}

interface AccountSlice {
  deltas: Map<string, bigint>;
  fee: bigint | null;
  feeAssetRef: string;
  feeUnknown: boolean;
}

interface Group {
  chainId: string;
  hash: string;
  timestampMs: number | null;
  status: TaxEvent['status'];
  slices: Map<string, AccountSlice>;
  peers: Set<string>;
}

const STATUS_RANK: Record<TaxEvent['status'], number> = { confirmed: 0, pending: 1, failed: 2 };

function slice(g: Group, accountId: string, feeAssetRef: string): AccountSlice {
  let s = g.slices.get(accountId);
  if (!s) {
    s = { deltas: new Map(), fee: null, feeAssetRef, feeUnknown: false };
    g.slices.set(accountId, s);
  }
  return s;
}

function allowed(auto: Label, wanted: Label): boolean {
  if (wanted === auto || wanted === 'spam') return true;
  if (auto === 'receive') return INBOUND_LABELS.includes(wanted);
  if (auto === 'send') return OUTBOUND_LABELS.includes(wanted);
  if (auto === 'trade') return wanted === 'trade';
  return false;
}

/** Labels the user may give an event whose direction was detected as `auto`. */
export function labelsFor(auto: Label): Label[] {
  if (auto === 'receive') return [...INBOUND_LABELS];
  if (auto === 'send') return [...OUTBOUND_LABELS];
  return auto === 'spam' ? ['spam'] : [auto, 'spam'];
}

/** What an event moved in and out of the scope as a whole, per asset, after own-account moves. */
export function eventFlows(e: Pick<TaxEvent, 'legs'>): {
  ins: { assetRef: string; amount: bigint }[];
  outs: { assetRef: string; amount: bigint }[];
} {
  const net = new Map<string, bigint>();
  for (const l of e.legs) net.set(l.assetRef, (net.get(l.assetRef) ?? 0n) + l.amount);
  const ins: { assetRef: string; amount: bigint }[] = [];
  const outs: { assetRef: string; amount: bigint }[] = [];
  for (const [assetRef, amount] of net)
    if (amount > 0n) ins.push({ assetRef, amount });
    else if (amount < 0n) outs.push({ assetRef, amount: -amount });
  return { ins, outs };
}

export function buildEvents(
  accounts: readonly ScopeAccount[],
  histories: readonly AccountHistory[],
  overrides: Overrides,
): TaxEvent[] {
  const byId = new Map(accounts.map((a) => [a.accountId, a]));
  const owned = new Set(accounts.map((a) => `${a.chainId}|${normAddress(a.chainId, a.address)}`));
  const groups = new Map<string, Group>();

  for (const h of histories) {
    const account = byId.get(h.accountId);
    if (!account) continue;
    const self = normAddress(account.chainId, account.address);
    const seen = new Set<string>();
    for (const r of h.records as readonly TxRecord[]) {
      if (r.chainId !== account.chainId) continue;
      const recordKey = r.entryId ?? `${normHash(r.chainId, r.hash)}#tx`;
      if (seen.has(recordKey)) continue;
      seen.add(recordKey);
      const id = eventId(r.chainId, r.hash);
      let g = groups.get(id);
      if (!g) {
        g = {
          chainId: r.chainId,
          hash: r.hash,
          timestampMs: r.timestampMs ?? null,
          status: r.status,
          slices: new Map(),
          peers: new Set(),
        };
        groups.set(id, g);
      }
      if (r.timestampMs !== undefined)
        g.timestampMs =
          g.timestampMs === null ? r.timestampMs : Math.min(g.timestampMs, r.timestampMs);
      if (STATUS_RANK[r.status] > STATUS_RANK[g.status]) g.status = r.status;
      for (const party of [r.from, r.to]) {
        if (!party) continue;
        const key = `${r.chainId}|${normAddress(r.chainId, party)}`;
        if (!owned.has(key)) g.peers.add(party);
      }
      const s = slice(g, account.accountId, r.feeAssetRef);
      for (const d of r.assetDeltas)
        s.deltas.set(d.assetRef, (s.deltas.get(d.assetRef) ?? 0n) + BigInt(d.amount));
      // Only the transaction-level record speaks for the fee; token events share its hash.
      const payer = r.entryId === undefined && normAddress(r.chainId, r.from) === self;
      if (!payer) continue;
      if (r.fee === null) {
        s.feeUnknown = true;
        continue;
      }
      const alreadyPaid = [...g.slices.values()].some((x) => x !== s && x.fee !== null);
      if (s.fee === null && !alreadyPaid) {
        s.fee = BigInt(r.fee);
        s.feeAssetRef = r.feeAssetRef;
        // Adapters report native net changes including the fee; the legs carry value only.
        s.deltas.set(r.feeAssetRef, (s.deltas.get(r.feeAssetRef) ?? 0n) + s.fee);
      }
    }
  }

  const events: TaxEvent[] = [];
  for (const [id, g] of groups) {
    const legs: Leg[] = [];
    let fee: TaxEvent['fee'] = null;
    let feeUnknown = false;
    for (const [accountId, s] of g.slices) {
      const account = byId.get(accountId) as ScopeAccount;
      if (g.status !== 'failed')
        for (const [assetRef, amount] of s.deltas)
          if (amount !== 0n) legs.push({ accountId, walletId: account.walletId, assetRef, amount });
      if (s.fee !== null && s.fee > 0n)
        fee = { accountId, walletId: account.walletId, assetRef: s.feeAssetRef, amount: s.fee };
      feeUnknown ||= s.feeUnknown;
    }
    legs.sort(
      (a, b) => a.assetRef.localeCompare(b.assetRef) || a.accountId.localeCompare(b.accountId),
    );

    const moves: TaxEvent['moves'] = [];
    const net = new Map<string, bigint>();
    for (const assetRef of new Set(legs.map((l) => l.assetRef))) {
      const outs = legs
        .filter((l) => l.assetRef === assetRef && l.amount < 0n)
        .map((l) => ({ id: l.accountId, left: -l.amount }));
      const ins = legs
        .filter((l) => l.assetRef === assetRef && l.amount > 0n)
        .map((l) => ({ id: l.accountId, left: l.amount }));
      for (const o of outs)
        for (const i of ins) {
          const n = o.left < i.left ? o.left : i.left;
          if (n <= 0n || o.id === i.id) continue;
          moves.push({ assetRef, fromAccountId: o.id, toAccountId: i.id, amount: n });
          o.left -= n;
          i.left -= n;
        }
      const total = legs
        .filter((l) => l.assetRef === assetRef)
        .reduce((sum, l) => sum + l.amount, 0n);
      if (total !== 0n) net.set(assetRef, total);
    }
    const hasIn = [...net.values()].some((v) => v > 0n);
    const hasOut = [...net.values()].some((v) => v < 0n);
    const auto: Label =
      hasIn && hasOut
        ? 'trade'
        : hasIn
          ? 'receive'
          : hasOut
            ? 'send'
            : moves.length > 0
              ? 'self'
              : 'fee';
    if (legs.length === 0 && fee === null && !feeUnknown) continue;

    const override = overrides[id];
    const label = override?.label && allowed(auto, override.label) ? override.label : auto;
    events.push({
      id,
      chainId: g.chainId,
      hash: g.hash,
      timestampMs: g.timestampMs,
      status: g.status,
      label,
      auto,
      reviewed:
        auto === 'self' || auto === 'fee' || auto === 'trade' || override?.label !== undefined,
      legs,
      moves,
      fee,
      feeUnknown,
      counterparty: [...g.peers][0] ?? null,
      note: override?.note ?? '',
      override,
    });
  }
  return events.sort(
    (a, b) =>
      (a.timestampMs ?? Number.MAX_SAFE_INTEGER) - (b.timestampMs ?? Number.MAX_SAFE_INTEGER) ||
      a.id.localeCompare(b.id),
  );
}
