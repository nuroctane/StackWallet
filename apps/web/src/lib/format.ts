/**
 * Base-unit decimal string -> human units. BigInt only; never a float, so an
 * 18-decimal balance keeps every digit. Non-zero amounts that would round to
 * zero render as `<0.000001` rather than lying with `0`.
 */
export function formatUnits(amount: string, decimals: number, maxFraction = 6): string {
  const trimmed = amount.trim();
  const m = /^(-?)(\d+)$/.exec(trimmed);
  if (!m || !Number.isInteger(decimals) || decimals < 0) return '?';
  const sign = m[1] ?? '';
  const digits = m[2] ?? '0';
  const value = BigInt(digits);
  if (value === 0n) return '0';

  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const frac = value % base;

  let fracStr = '';
  if (decimals > 0 && frac > 0n) {
    fracStr = frac.toString().padStart(decimals, '0').slice(0, maxFraction).replace(/0+$/, '');
  }

  if (whole === 0n && fracStr === '') {
    const smallest = maxFraction > 0 ? `0.${'0'.repeat(maxFraction - 1)}1` : '1';
    return sign === '-' ? `>-${smallest}` : `<${smallest}`;
  }

  const wholeStr = groupThousands(whole.toString());
  return `${sign}${wholeStr}${fracStr ? `.${fracStr}` : ''}`;
}

export function groupThousands(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** `0x1234…abcd` style; short inputs pass through untouched. */
export function shortAddress(address: string, head = 6, tail = 4): string {
  if (address.length <= head + tail + 1) return address;
  return `${address.slice(0, head)}…${address.slice(-tail)}`;
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
