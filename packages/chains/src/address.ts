import type { Amount } from '@stackwallet/core-client';

/** Readable account names (NEAR, ENS, Antelope) that truncation would only obscure. */
const NAMED_ACCOUNT = /^[a-z0-9][a-z0-9._-]{0,30}\.[a-z]{2,}$/i;
/** A bech32 human-readable part (`cosmos1`, `account_rdx1`, `tnam1`) or an underscore tag (`ak_`, `keeta_`). */
const PREFIX = /^(?:[a-z][a-z0-9_]{0,15}1(?=[a-z0-9]{20,}$)|[a-z]{1,8}_)/;

/**
 * `0x7E5F…5Bdf` style truncation for dense UI; returns short inputs and named
 * accounts unchanged. The head always keeps the network prefix plus a few
 * characters, so `account_rdx1…`, `cosmos1…` and `ak_…` stay recognisable
 * instead of collapsing to their prefix alone.
 */
export function shortAddress(addr: string, head = 6, tail = 4): string {
  if (addr.length <= head + tail + 1) return addr;
  if (NAMED_ACCOUNT.test(addr)) return addr;
  const prefix = PREFIX.exec(addr)?.[0] ?? '';
  const keep = Math.max(head, prefix.length + 3);
  if (addr.length <= keep + tail + 1) return addr;
  return `${addr.slice(0, keep)}…${addr.slice(addr.length - tail)}`;
}

export interface FormatAmountOptions {
  /** Maximum fraction digits to show; defaults to `decimals`. Extra digits are truncated, never rounded. */
  maxFraction?: number;
  /** Keep trailing zeros up to `maxFraction` instead of trimming them. */
  keepTrailingZeros?: boolean;
}

/**
 * Base units to a human decimal string using bigint only, so amounts beyond
 * 2^53 never lose precision. Accepts a leading `-` for signed deltas.
 */
export function formatAmount(
  amount: Amount | string,
  decimals: number,
  opts: FormatAmountOptions = {},
): string {
  if (!Number.isInteger(decimals) || decimals < 0) throw new RangeError('decimals must be >= 0');
  const m = /^(-?)([0-9]+)$/.exec(amount);
  if (!m) throw new TypeError(`not a base-unit amount: ${amount}`);
  const sign = m[1] === '-' ? '-' : '';
  const digits = m[2]!.replace(/^0+(?=\d)/, '');

  const whole = digits.length > decimals ? digits.slice(0, digits.length - decimals) : '0';
  let fraction =
    digits.length > decimals
      ? digits.slice(digits.length - decimals)
      : digits.padStart(decimals, '0');

  const maxFraction = Math.min(opts.maxFraction ?? decimals, decimals);
  fraction = fraction.slice(0, maxFraction);
  if (!opts.keepTrailingZeros) fraction = fraction.replace(/0+$/, '');

  const text = fraction.length > 0 ? `${whole}.${fraction}` : whole;
  const isZero = /^0(\.0*)?$/.test(text);
  return isZero ? text : `${sign}${text}`;
}

/**
 * Human decimal text to base units. Returns null for anything ambiguous:
 * more fraction digits than the asset has, signs, exponents, group separators.
 */
export function parseAmount(text: string, decimals: number): Amount | null {
  if (!Number.isInteger(decimals) || decimals < 0) return null;
  const m = /^(\d*)(?:\.(\d*))?$/.exec(text.trim());
  if (!m) return null;
  const whole = m[1] ?? '';
  const fraction = m[2] ?? '';
  if (whole.length === 0 && fraction.length === 0) return null;
  if (fraction.length > decimals) return null;
  const units = BigInt((whole || '0') + fraction.padEnd(decimals, '0'));
  return units.toString();
}
