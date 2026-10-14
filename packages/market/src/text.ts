/**
 * Display text from market providers. Control, bidi and zero-width characters
 * are stripped so a hostile token name cannot reorder or hide what is shown
 * around it; the result is length-capped for layout.
 */
const STRIP = new RegExp(
  '[' +
    [
      '\\u0000-\\u001f',
      '\\u007f-\\u009f',
      '\\u00ad',
      '\\u061c',
      '\\u180e',
      '\\u200b-\\u200f',
      '\\u202a-\\u202e',
      '\\u2060-\\u206f',
      '\\ufeff',
      '\\ufff0-\\uffff',
    ].join('') +
    ']',
  'gu',
);

export function cleanText(raw: unknown, max = 120): string {
  if (typeof raw !== 'string' && typeof raw !== 'number') return '';
  const s = String(raw).normalize('NFC').replace(STRIP, '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
