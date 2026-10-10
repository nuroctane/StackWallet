import { formatAmount } from '@stackwallet/chains';

/**
 * Display wrapper over the shared `formatAmount`: groups thousands, never
 * throws on malformed input (`?`), and renders non-zero amounts that truncate
 * to zero as `<0.000001` so a dust balance is never shown as a flat `0`.
 */
export function formatUnits(amount: string, decimals: number, maxFraction = 6): string {
  const m = /^(-?)(\d+)$/.exec(amount.trim());
  if (!m || !Number.isInteger(decimals) || decimals < 0) return '?';
  const sign = m[1] ?? '';
  const digits = m[2] ?? '0';
  if (/^0+$/.test(digits)) return '0';

  const text = formatAmount(digits, decimals, { maxFraction });
  if (text === '0') {
    const smallest = maxFraction > 0 ? `0.${'0'.repeat(maxFraction - 1)}1` : '1';
    return sign === '-' ? `>-${smallest}` : `<${smallest}`;
  }
  const [whole = '0', frac] = text.split('.');
  return `${sign}${groupThousands(whole)}${frac ? `.${frac}` : ''}`;
}

export function groupThousands(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** Subsequence match (every query char appears in order), case-insensitive. */
export function fuzzyMatch(query: string, text: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === '') return true;
  const t = text.toLowerCase();
  if (t.includes(q)) return true;
  let i = 0;
  for (const ch of t) {
    if (ch === q[i]) i += 1;
    if (i === q.length) return true;
  }
  return false;
}

/**
 * Coarse "12s" / "3m" age text for live-updating cells, sized for a dense
 * table column; future stamps clamp to "now".
 */
export function relativeTime(thenMs: number, nowMs: number): string {
  const delta = Math.max(0, Math.floor((nowMs - thenMs) / 1000));
  if (delta < 5) return 'now';
  if (delta < 60) return `${delta}s`;
  const minutes = Math.floor(delta / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}
