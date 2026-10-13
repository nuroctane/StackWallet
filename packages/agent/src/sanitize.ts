/**
 * Everything the model reads from the outside world (token names, labels,
 * memos, indexer text) is untrusted. Control, bidi and zero-width
 * characters are removed and length is capped before it reaches a prompt.
 */
const HIDDEN =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;

export function sanitizeUntrusted(text: string, max = 200): string {
  const clean = text.replace(HIDDEN, '').trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

/** Deep-sanitise every string in a tool result. */
export function sanitizeValue<T>(value: T, max = 200): T {
  if (typeof value === 'string') return sanitizeUntrusted(value, max) as T;
  if (Array.isArray(value)) return value.map((v) => sanitizeValue(v, max)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = sanitizeValue(v, max);
    return out as T;
  }
  return value;
}
