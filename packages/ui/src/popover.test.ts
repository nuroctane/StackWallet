import { describe, expect, it } from 'vitest';

import { positionPopover } from './Popover.js';

const viewport = { width: 1000, height: 600 };
const anchor = { left: 100, top: 100, width: 80, height: 24 };
const pop = { width: 200, height: 150 };

describe('positionPopover', () => {
  it('opens below the anchor, aligned to its start edge', () => {
    expect(positionPopover(anchor, pop, viewport)).toEqual({ left: 100, top: 130, side: 'bottom' });
  });

  it('aligns to the end edge', () => {
    const a = { left: 500, top: 100, width: 80, height: 24 };
    expect(positionPopover(a, pop, viewport, { align: 'end' }).left).toBe(500 + 80 - 200);
  });

  it('honors a custom offset', () => {
    expect(positionPopover(anchor, pop, viewport, { offset: 12 }).top).toBe(136);
  });

  it('flips to the top when there is no room below but room above', () => {
    const low = { left: 100, top: 500, width: 80, height: 24 };
    const p = positionPopover(low, pop, viewport);
    expect(p.side).toBe('top');
    expect(p.top).toBe(500 - 150 - 6);
  });

  it('keeps the requested side when neither side fits and clamps instead', () => {
    const tall = { width: 200, height: 700 };
    const p = positionPopover(anchor, tall, viewport);
    expect(p.side).toBe('bottom');
    expect(p.top).toBe(8);
  });

  it('flips a top popover to the bottom when the anchor is near the top', () => {
    const high = { left: 100, top: 20, width: 80, height: 24 };
    const p = positionPopover(high, pop, viewport, { side: 'top' });
    expect(p.side).toBe('bottom');
    expect(p.top).toBe(20 + 24 + 6);
  });

  it('clamps horizontally inside the viewport margin', () => {
    const edge = { left: 950, top: 100, width: 40, height: 24 };
    expect(positionPopover(edge, pop, viewport).left).toBe(1000 - 8 - 200);
    const far = { left: -50, top: 100, width: 40, height: 24 };
    expect(positionPopover(far, pop, viewport).left).toBe(8);
  });

  it('adds the scroll offset after clamping', () => {
    const p = positionPopover(anchor, pop, { ...viewport, scrollX: 15, scrollY: 300 });
    expect(p).toEqual({ left: 115, top: 430, side: 'bottom' });
  });

  it('supports a custom margin', () => {
    const far = { left: -50, top: 100, width: 40, height: 24 };
    expect(positionPopover(far, pop, viewport, { margin: 20 }).left).toBe(20);
  });
});
