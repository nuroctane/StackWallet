import { z } from 'zod';

/**
 * Market conditions shared by alerts and (later) automation triggers. The
 * evaluator is three-valued: a missing, stale or disputed price is
 * `unknown`, which never fires anything, so a provider outage or two sources
 * disagreeing cannot be mistaken for the market crossing a line.
 */

export const STALE_AFTER_MS = 15 * 60_000;

const CoinId = z.string().regex(/^[a-z0-9-]{1,80}$/, 'coin id');

export const Condition = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('price'),
    coinId: CoinId,
    op: z.enum(['above', 'below']),
    usd: z.number().finite().positive().max(1e12),
  }),
  /** The provider's 24h change, in percent (negative for a fall). */
  z.object({
    kind: z.literal('change24h'),
    coinId: CoinId,
    op: z.enum(['above', 'below']),
    percent: z.number().finite().min(-100).max(10_000),
  }),
]);
export type Condition = z.infer<typeof Condition>;

export interface Observation {
  usd: number;
  change24hPct: number | null;
  fetchedAtMs: number;
  confidence: 'single' | 'agreed' | 'divergent';
}

export type Verdict = 'true' | 'false' | 'unknown';

export function evaluate(c: Condition, obs: Observation | undefined, now: number): Verdict {
  if (!obs || now - obs.fetchedAtMs > STALE_AFTER_MS || obs.confidence === 'divergent')
    return 'unknown';
  const value = c.kind === 'price' ? obs.usd : obs.change24hPct;
  if (value === null || !Number.isFinite(value)) return 'unknown';
  const line = c.kind === 'price' ? c.usd : c.percent;
  return (c.op === 'above' ? value > line : value < line) ? 'true' : 'false';
}

export function describeCondition(c: Condition, label: string = c.coinId): string {
  if (c.kind === 'price') return `${label} ${c.op} $${c.usd}`;
  return `${label} 24h change ${c.op} ${c.percent > 0 ? '+' : ''}${c.percent}%`;
}
