import { chainFamilyOf, type ChainFamily, type ChainId } from '@stackwallet/core-client';

import type { ChainAdapter, ChainInfo } from './types.js';

export class ChainRegistry {
  private readonly adapters = new Map<ChainFamily, ChainAdapter>();

  register(adapter: ChainAdapter): this {
    if (this.adapters.has(adapter.family)) {
      throw new Error(`adapter for ${adapter.family} already registered`);
    }
    this.adapters.set(adapter.family, adapter);
    return this;
  }

  families(): ChainFamily[] {
    return [...this.adapters.keys()];
  }

  adapterFor(chainId: ChainId): ChainAdapter {
    const family = chainFamilyOf(chainId);
    if (!family) throw new Error(`unknown chain namespace in ${chainId}`);
    const adapter = this.adapters.get(family);
    if (!adapter) throw new Error(`no adapter registered for ${family}`);
    return adapter;
  }

  chains(): ChainInfo[] {
    return [...this.adapters.values()].flatMap((a) => a.chains());
  }

  chainInfo(chainId: ChainId): ChainInfo | undefined {
    return this.chains().find((c) => c.chainId === chainId);
  }
}
