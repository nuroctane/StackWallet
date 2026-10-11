import { gatewayCandidates, gatewayUrl } from './solana.js';

/**
 * NFT media is attacker-chosen bytes from attacker-chosen hosts. The page's
 * CSP only allows `blob:` and `data:` images, so every image is fetched here
 * (CORS, no credentials, no referrer), checked for an image type and a size
 * cap, and handed to `<img>` as a blob URL. Nothing else is ever rendered:
 * no HTML, no iframes, no animation URLs.
 */
export const MAX_MEDIA_BYTES = 10 * 1024 * 1024;
export const MEDIA_TIMEOUT_MS = 12_000;

const IMAGE_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
  // SVG inside <img> cannot run script or load subresources, so it is inert here.
  'image/svg+xml',
]);

export interface MediaOptions {
  fetch?: typeof fetch;
  maxBytes?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export type MediaResult = { ok: true; blob: Blob } | { ok: false; reason: string };

function mimeOf(contentType: string | null): string {
  return (contentType ?? '').split(';')[0]!.trim().toLowerCase();
}

/** Decodes a `data:image/...` URL without fetch, which CSP's connect-src would refuse. */
export function decodeDataUrl(url: string, maxBytes = MAX_MEDIA_BYTES): MediaResult {
  const m = /^data:([^;,]+)((?:;[^;,=]+=[^;,]+)*)(;base64)?,(.*)$/s.exec(url);
  if (!m) return { ok: false, reason: 'malformed data url' };
  const type = m[1]!.toLowerCase();
  if (!IMAGE_TYPES.has(type)) return { ok: false, reason: `not an image (${type})` };
  let bytes: Uint8Array;
  try {
    if (m[3]) {
      const bin = atob(m[4]!);
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(m[4]!));
    }
  } catch {
    return { ok: false, reason: 'undecodable data url' };
  }
  if (bytes.length > maxBytes) return { ok: false, reason: 'too large' };
  return { ok: true, blob: new Blob([bytes as BlobPart], { type }) };
}

export function mediaUrl(raw: string): string | null {
  const url = gatewayUrl(raw.trim());
  if (url.startsWith('data:')) return url;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' || u.username || u.password) return null;
    return u.toString();
  } catch {
    return null;
  }
}

function httpsOnly(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' || u.username || u.password) return null;
    return u.toString();
  } catch {
    return null;
  }
}

/**
 * Tries each gateway for content-addressed media, then gives up. A host that
 * refuses CORS shows up as `reason: 'TypeError'`, which callers may answer
 * with a plain `<img>` if the user allows unvetted media.
 */
export async function loadMedia(raw: string, opts: MediaOptions = {}): Promise<MediaResult> {
  const trimmed = raw.trim();
  if (trimmed.startsWith('data:')) return decodeDataUrl(trimmed, opts.maxBytes ?? MAX_MEDIA_BYTES);
  const candidates = gatewayCandidates(trimmed)
    .map(httpsOnly)
    .filter((u): u is string => u !== null);
  if (candidates.length === 0) return { ok: false, reason: 'unsupported url' };
  let last: MediaResult = { ok: false, reason: 'unsupported url' };
  for (const url of candidates) {
    last = await loadOne(url, opts);
    if (last.ok || opts.signal?.aborted) return last;
    // Not an image or too large is the content's fault; another gateway will not change it.
    if (/^(not an image|too large)/.test(last.reason)) return last;
  }
  return last;
}

async function loadOne(url: string, opts: MediaOptions): Promise<MediaResult> {
  const maxBytes = opts.maxBytes ?? MAX_MEDIA_BYTES;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs ?? MEDIA_TIMEOUT_MS);
  const onAbort = () => ctl.abort();
  opts.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    const res = await (opts.fetch ?? fetch)(url, {
      mode: 'cors',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      redirect: 'follow',
      signal: ctl.signal,
    });
    if (!res.ok) return { ok: false, reason: `http ${res.status}` };
    const type = mimeOf(res.headers.get('content-type'));
    if (!IMAGE_TYPES.has(type)) return { ok: false, reason: `not an image (${type || 'unknown'})` };
    const declared = Number(res.headers.get('content-length') ?? '0');
    if (declared > maxBytes) return { ok: false, reason: 'too large' };
    const reader = res.body?.getReader();
    if (!reader) return { ok: false, reason: 'empty body' };
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        return { ok: false, reason: 'too large' };
      }
      chunks.push(value);
    }
    return { ok: true, blob: new Blob(chunks as BlobPart[], { type }) };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.name : 'fetch failed' };
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener('abort', onAbort);
  }
}

/** URL for a plain `<img>` when vetted loading failed; https only, never data or script schemes. */
export function directMediaUrl(raw: string): string | null {
  for (const c of gatewayCandidates(raw.trim())) {
    const u = httpsOnly(c);
    if (u) return u;
  }
  return null;
}
