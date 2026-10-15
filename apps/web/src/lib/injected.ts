import { isValidEvmAddress } from '@stackwallet/chains-evm';

/**
 * Browser-extension wallets, found through EIP-6963 announcements (and the
 * legacy `window.ethereum` when nothing announces). StackWallet only ever asks
 * them for account addresses, which become watch-only wallets here: no
 * signing method is ever called, and the extension keeps its keys.
 *
 * Everything an extension announces is untrusted: names are cleaned, icons
 * are accepted only as inline raster or SVG data URIs (an <img> cannot run an
 * SVG's scripts) and anything else falls back to a monogram.
 */

export interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export interface InjectedWallet {
  uuid: string;
  name: string;
  /** Safe data URI, or null for a monogram. */
  icon: string | null;
  rdns: string;
  provider: Eip1193;
}

const ICON = /^data:image\/(png|svg\+xml|webp|jpeg|gif);base64,[A-Za-z0-9+/=]+$/;
const MAX_ICON = 200_000;

export function cleanName(raw: unknown): string {
  const text = typeof raw === 'string' ? raw : '';
  // Strip controls and bidi overrides that could disguise the name.
  const clean = text
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .trim();
  return clean.slice(0, 40) || 'Browser wallet';
}

export function safeIcon(raw: unknown): string | null {
  return typeof raw === 'string' && raw.length <= MAX_ICON && ICON.test(raw) ? raw : null;
}

function isProvider(p: unknown): p is Eip1193 {
  return typeof p === 'object' && p !== null && typeof (p as Eip1193).request === 'function';
}

export function parseAnnouncement(detail: unknown): InjectedWallet | null {
  if (typeof detail !== 'object' || detail === null) return null;
  const { info, provider } = detail as { info?: Record<string, unknown>; provider?: unknown };
  if (!info || !isProvider(provider)) return null;
  const uuid = typeof info['uuid'] === 'string' ? info['uuid'].slice(0, 64) : '';
  if (!uuid) return null;
  return {
    uuid,
    name: cleanName(info['name']),
    icon: safeIcon(info['icon']),
    rdns: typeof info['rdns'] === 'string' ? info['rdns'].slice(0, 100) : '',
    provider,
  };
}

/**
 * Listens for announcements and asks every wallet to announce itself. The
 * callback receives the full, deduplicated list each time it changes.
 */
export function discoverWallets(
  onChange: (wallets: InjectedWallet[]) => void,
  target: Window | undefined = typeof window === 'undefined' ? undefined : window,
): () => void {
  if (!target) return () => {};
  const found = new Map<string, InjectedWallet>();
  const emit = () => onChange([...found.values()]);
  const onAnnounce = (e: Event) => {
    const w = parseAnnouncement((e as CustomEvent).detail);
    if (!w || found.has(w.uuid)) return;
    found.set(w.uuid, w);
    emit();
  };
  target.addEventListener('eip6963:announceProvider', onAnnounce);
  target.dispatchEvent(new Event('eip6963:requestProvider'));
  // Older extensions only inject a global; offer it when nothing announced.
  const legacy = setTimeout(() => {
    const eth = (target as unknown as { ethereum?: unknown }).ethereum;
    if (found.size === 0 && isProvider(eth)) {
      found.set('legacy', {
        uuid: 'legacy',
        name: 'Browser wallet',
        icon: null,
        rdns: '',
        provider: eth,
      });
      emit();
    }
  }, 400);
  return () => {
    clearTimeout(legacy);
    target.removeEventListener('eip6963:announceProvider', onAnnounce);
  };
}

export class ConnectRejected extends Error {
  override readonly name = 'ConnectRejected';
}

/** Asks the extension to share its accounts. Only valid, unique EVM addresses come back. */
export async function requestAddresses(
  wallet: InjectedWallet,
): Promise<{ addresses: string[]; chainId: string | null }> {
  let raw: unknown;
  try {
    raw = await wallet.provider.request({ method: 'eth_requestAccounts' });
  } catch (e) {
    const code = (e as { code?: unknown })?.code;
    if (code === 4001) throw new ConnectRejected('You declined in the wallet.');
    if (code === -32002)
      throw new ConnectRejected('The wallet already has a request open. Check its window.');
    throw new Error(e instanceof Error ? e.message.slice(0, 200) : 'The wallet did not answer.');
  }
  const list = Array.isArray(raw) ? raw : [];
  const seen = new Set<string>();
  const addresses: string[] = [];
  for (const a of list.slice(0, 50)) {
    if (typeof a !== 'string' || !isValidEvmAddress(a)) continue;
    const key = a.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    addresses.push(a);
  }
  let chainId: string | null = null;
  try {
    const hex = await wallet.provider.request({ method: 'eth_chainId' });
    if (typeof hex === 'string' && /^0x[0-9a-f]{1,16}$/i.test(hex))
      chainId = `eip155:${BigInt(hex).toString()}`;
  } catch {
    // The current chain only preselects a network; without it Ethereum is used.
  }
  return { addresses, chainId };
}
