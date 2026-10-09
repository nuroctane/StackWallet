import { ChainRegistry, MemoryRpcPool } from '@stackwallet/chains';
import { createBitcoinAdapter } from '@stackwallet/chains-bitcoin';
import { createCosmosAdapter } from '@stackwallet/chains-cosmos';
import { createEvmAdapter } from '@stackwallet/chains-evm';
import { createSolanaAdapter } from '@stackwallet/chains-solana';

/**
 * One registry per app with every bundled family adapter registered. The
 * adapters share a single pool so user endpoint edits and health tracking
 * apply everywhere at once.
 */
export function createDefaultRegistry(): ChainRegistry {
  const rpc = MemoryRpcPool.fromCatalog();
  return new ChainRegistry()
    .register(createEvmAdapter({ rpc }))
    .register(createBitcoinAdapter({ rpc }))
    .register(createSolanaAdapter({ rpc }))
    .register(createCosmosAdapter({ rpc }));
}
