import { describe, expect, it } from 'vitest';

import { formatUnits, fuzzyMatch, groupThousands, relativeTime } from './format.js';

describe('formatUnits', () => {
  it('formats whole and fractional parts', () => {
    expect(formatUnits('1500000000000000000', 18)).toBe('1.5');
    expect(formatUnits('1000000000000000000', 18)).toBe('1');
    expect(formatUnits('123456789', 6)).toBe('123.456789');
  });

  it('truncates (never rounds) to maxFraction and trims trailing zeros', () => {
    expect(formatUnits('1999999999999999999', 18)).toBe('1.999999');
    expect(formatUnits('1100000000000000000', 18, 2)).toBe('1.1');
    expect(formatUnits('123456789', 6, 2)).toBe('123.45');
  });

  it('renders zero plainly and dust honestly', () => {
    expect(formatUnits('0', 18)).toBe('0');
    expect(formatUnits('000', 18)).toBe('0');
    expect(formatUnits('1', 18)).toBe('<0.000001');
    expect(formatUnits('-1', 18)).toBe('>-0.000001');
    expect(formatUnits('5', 8, 2)).toBe('<0.01');
  });

  it('groups thousands in the integer part', () => {
    expect(formatUnits('1234567890000000000000', 18)).toBe('1,234.56789');
    expect(formatUnits('100000000000', 8)).toBe('1,000');
  });

  it('handles zero decimals and negatives', () => {
    expect(formatUnits('42', 0)).toBe('42');
    expect(formatUnits('-2500000', 6)).toBe('-2.5');
  });

  it('refuses malformed input without throwing', () => {
    expect(formatUnits('1.5', 18)).toBe('?');
    expect(formatUnits('abc', 18)).toBe('?');
    expect(formatUnits('', 18)).toBe('?');
    expect(formatUnits('10', -1)).toBe('?');
  });
});

describe('groupThousands', () => {
  it('inserts separators every three digits', () => {
    expect(groupThousands('1')).toBe('1');
    expect(groupThousands('1000')).toBe('1,000');
    expect(groupThousands('1234567')).toBe('1,234,567');
  });
});

describe('fuzzyMatch', () => {
  it('matches substrings case-insensitively', () => {
    expect(fuzzyMatch('vault', 'BTC Vault')).toBe(true);
  });
  it('matches ordered subsequences', () => {
    expect(fuzzyMatch('bv', 'BTC Vault')).toBe(true);
    expect(fuzzyMatch('vb', 'BTC Vault')).toBe(false);
  });
  it('empty query matches everything', () => {
    expect(fuzzyMatch('  ', 'anything')).toBe(true);
  });
});

describe('relativeTime', () => {
  const now = 1_000_000_000;
  it('steps through seconds, minutes, hours and days', () => {
    expect(relativeTime(now - 2_000, now)).toBe('now');
    expect(relativeTime(now - 12_000, now)).toBe('12s');
    expect(relativeTime(now - 3 * 60_000, now)).toBe('3m');
    expect(relativeTime(now - 5 * 3_600_000, now)).toBe('5h');
    expect(relativeTime(now - 72 * 3_600_000, now)).toBe('3d');
  });
  it('clamps future stamps to now', () => {
    expect(relativeTime(now + 60_000, now)).toBe('now');
  });
});
