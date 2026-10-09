import { createContext, useContext } from 'react';
import { ChainRegistry } from '@stackwallet/chains';

// An empty registry is a valid state (no adapters loaded), so the fallback never throws.
const fallback = new ChainRegistry();

export const RegistryContext = createContext<ChainRegistry>(fallback);

export function useRegistry(): ChainRegistry {
  return useContext(RegistryContext);
}
