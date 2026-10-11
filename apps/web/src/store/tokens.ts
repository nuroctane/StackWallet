import { useSyncExternalStore } from 'react';
import { isValidEvmAddress, type EvmAdapter } from '@stackwallet/chains-evm';
import type { ChainRegistry } from '@stackwallet/chains';
import { z } from 'zod';
import type { StorageLike } from './persist.js';

const Token = z.object({
  chainId: z.string().regex(/^eip155:\d+$/),
  address: z
    .string()
    .refine(isValidEvmAddress)
    .transform((a) => a.toLowerCase()),
  symbol: z.string().regex(/^[\x20-\x7e]{1,12}$/),
  decimals: z.number().int().min(0).max(36),
});
export type TrackedToken = z.infer<typeof Token>;
const Tokens = z.array(Token).max(100);
const KEY = 'stackwallet.tokens.v1';

export class TokenStore {
  quarantinedKey: string | undefined;
  private tokens: TrackedToken[] = [];
  private listeners = new Set<() => void>();
  constructor(private storage: StorageLike | null) {
    let raw: string | null | undefined;
    try {
      raw = storage?.getItem(KEY);
      if (raw) this.tokens = Tokens.parse(JSON.parse(raw));
    } catch {
      if (raw) {
        try {
          const key = `${KEY}.corrupt-${Date.now()}`;
          storage?.setItem(key, raw);
          storage?.removeItem(KEY);
          this.quarantinedKey = key;
        } catch {
          // Storage may be inaccessible; the unreadable original stays in place.
        }
      }
    }
  }
  getSnapshot = () => this.tokens;
  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  };
  find(assetRef: string) {
    return this.tokens.find((t) => `${t.chainId}:erc20:${t.address}` === assetRef.toLowerCase());
  }
  track(input: TrackedToken) {
    const token = Token.parse(input);
    this.save([
      ...this.tokens.filter((t) => t.chainId !== token.chainId || t.address !== token.address),
      token,
    ]);
  }
  remove(token: TrackedToken) {
    this.save(
      this.tokens.filter((t) => t.chainId !== token.chainId || t.address !== token.address),
    );
  }
  private save(tokens: TrackedToken[]) {
    const next = Tokens.parse(tokens);
    this.storage?.setItem(KEY, JSON.stringify(next));
    this.tokens = next;
    for (const fn of this.listeners) fn();
  }
  configure(registry: ChainRegistry) {
    const adapter = registry.adapterFor('eip155:1') as unknown as EvmAdapter;
    const apply = () => adapter.setTrackedTokens(this.tokens);
    apply();
    return this.subscribe(apply);
  }
}

function storage(): StorageLike | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}
export const tokenStore = new TokenStore(storage());
export function useTokens() {
  return useSyncExternalStore(tokenStore.subscribe, tokenStore.getSnapshot, tokenStore.getSnapshot);
}
