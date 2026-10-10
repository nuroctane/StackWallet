import { describe, expect, it } from 'vitest';

import { countdown, fingerprintGroups, shortId } from './DevicesView.js';

describe('devices view helpers', () => {
  it('shortens long ids from both ends and leaves short ones alone', () => {
    expect(shortId('66687aadf862bd776c8fc18b8e9f8e20')).toBe('66687aad…9f8e20');
    expect(shortId('abcd')).toBe('abcd');
  });

  it('groups hex by four for fingerprints', () => {
    expect(fingerprintGroups('66687aadf862bd77')).toEqual(['6668', '7aad', 'f862', 'bd77']);
    expect(fingerprintGroups('abcde')).toEqual(['abcd', 'e']);
    expect(fingerprintGroups('')).toEqual([]);
  });

  it('formats the expiry countdown and clamps at zero', () => {
    expect(countdown(65_000)).toBe('1m 05s');
    expect(countdown(0)).toBe('0m 00s');
    expect(countdown(-5_000)).toBe('0m 00s');
    expect(countdown(3_720_000)).toBe('1h 2m');
  });
});
