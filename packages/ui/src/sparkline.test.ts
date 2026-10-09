import { describe, expect, it } from 'vitest';

import { sparklinePoints } from './Sparkline.js';

describe('sparklinePoints', () => {
  it('returns an empty string for no data', () => {
    expect(sparklinePoints([], 96, 24)).toBe('');
  });

  it('centers a single sample', () => {
    expect(sparklinePoints([5], 96, 24)).toBe('48,12');
  });

  it('puts a flat series on the midline', () => {
    expect(sparklinePoints([3, 3, 3], 10, 4, 0)).toBe('0,2 5,2 10,2');
  });

  it('maps min to the bottom and max to the top with padding', () => {
    expect(sparklinePoints([0, 10], 12, 12, 1)).toBe('1,11 11,1');
  });
});
