import { describe, expect, it } from 'vitest';

import { gridTemplate, visibleRange } from './VirtualTable.js';

describe('visibleRange', () => {
  it('is empty for no rows', () => {
    expect(visibleRange(0, 300, 24, 0, 8)).toEqual({ start: 0, end: 0 });
  });

  it('is empty for a degenerate row height or viewport', () => {
    expect(visibleRange(0, 300, 0, 100, 8)).toEqual({ start: 0, end: 0 });
    expect(visibleRange(0, 0, 24, 100, 8)).toEqual({ start: 0, end: 0 });
  });

  it('starts at zero and covers the viewport plus overscan', () => {
    // 300 / 24 = 12.5 rows → 13 visible, plus 8 overscan.
    expect(visibleRange(0, 300, 24, 1000, 8)).toEqual({ start: 0, end: 21 });
  });

  it('never returns more rows than exist', () => {
    expect(visibleRange(0, 300, 24, 5, 8)).toEqual({ start: 0, end: 5 });
  });

  it('shifts with scroll and applies overscan on both sides', () => {
    // scrollTop 240 = row 10; viewport reaches row ceil((240+300)/24) = 23.
    expect(visibleRange(240, 300, 24, 1000, 8)).toEqual({ start: 2, end: 31 });
  });

  it('clamps at the end of the list', () => {
    const r = visibleRange(24 * 995, 300, 24, 1000, 8);
    expect(r).toEqual({ start: 987, end: 1000 });
  });

  it('treats negative scroll offsets as zero', () => {
    expect(visibleRange(-28, 300, 24, 1000, 0)).toEqual({ start: 0, end: 13 });
  });

  it('works with zero overscan', () => {
    expect(visibleRange(48, 96, 24, 100, 0)).toEqual({ start: 2, end: 6 });
  });
});

describe('gridTemplate', () => {
  it('maps numbers to px, strings verbatim and missing widths to a flexible track', () => {
    expect(gridTemplate([{ width: 80 }, { width: 'max-content' }, {}])).toBe(
      '80px max-content minmax(0,1fr)',
    );
  });

  it('returns an empty template for no columns', () => {
    expect(gridTemplate([])).toBe('');
  });
});
