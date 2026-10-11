/**
 * Names come from public registries anyone can write to, so they are
 * untrusted display text. Control, bidi-override and zero-width characters
 * are refused outright (they can make one name render as another); other
 * non-ASCII is allowed but flagged so the UI can warn about look-alikes.
 */
const FORBIDDEN =
  /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\uffff]/u;

export const MAX_NAME_LENGTH = 96;

export interface CleanName {
  name: string;
  nonAscii: boolean;
}

export function cleanName(raw: unknown): CleanName | null {
  if (typeof raw !== 'string') return null;
  const name = raw.normalize('NFC').trim();
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) return null;
  if (FORBIDDEN.test(name)) return null;
  if (/\s/u.test(name)) return null;
  return { name, nonAscii: /[^\x21-\x7e]/.test(name) };
}
