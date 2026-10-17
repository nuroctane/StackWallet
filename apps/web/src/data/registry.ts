import { ChainRegistry, MemoryRpcPool } from '@stackwallet/chains';
import { createAlgorandAdapter } from '@stackwallet/chains-algorand';
import { createAptosAdapter } from '@stackwallet/chains-aptos';
import { createAntelopeAdapter } from '@stackwallet/chains-antelope';
import { createMultiversxAdapter } from '@stackwallet/chains-multiversx';
import { createTezosAdapter } from '@stackwallet/chains-tezos';
import { createStacksAdapter } from '@stackwallet/chains-stacks';
import { createVechainAdapter } from '@stackwallet/chains-vechain';
import { createHyperliquidAdapter } from '@stackwallet/chains-hyperliquid';
import { createStarknetAdapter } from '@stackwallet/chains-starknet';
import { createIconAdapter } from '@stackwallet/chains-icon';
import { EverscaleAdapter } from '@stackwallet/chains-everscale';
import { WavesAdapter } from '@stackwallet/chains-waves';
import { createRadixAdapter } from '@stackwallet/chains-radix';
import { createIcpAdapter } from '@stackwallet/chains-icp';
import { createErgoAdapter } from '@stackwallet/chains-ergo';
import { createAlephiumAdapter } from '@stackwallet/chains-alephium';
import { createNeoAdapter } from '@stackwallet/chains-neo';
import { createAeternityAdapter } from '@stackwallet/chains-aeternity';
import { createChiaAdapter } from '@stackwallet/chains-chia';
import { createFuelAdapter } from '@stackwallet/chains-fuel';
import { createAelfAdapter } from '@stackwallet/chains-aelf';
import { createStarcoinAdapter } from '@stackwallet/chains-starcoin';
import { createObyteAdapter } from '@stackwallet/chains-obyte';
import { createChromiaAdapter } from '@stackwallet/chains-chromia';
import { createKeetaAdapter } from '@stackwallet/chains-keeta';
import { createNamadaAdapter } from '@stackwallet/chains-namada';
import { createBtcForkAdapter } from '@stackwallet/chains-btcfork';
import { createGalaAdapter } from '@stackwallet/chains-gala';
import { createMixinAdapter } from '@stackwallet/chains-mixin';
import { createQubicAdapter } from '@stackwallet/chains-qubic';
import { createAleoAdapter } from '@stackwallet/chains-aleo';
import { createCantonAdapter } from '@stackwallet/chains-canton';
import { createCardanoAdapter } from '@stackwallet/chains-cardano';
import { createBitcoinAdapter } from '@stackwallet/chains-bitcoin';
import { createCosmosAdapter } from '@stackwallet/chains-cosmos';
import { createEvmAdapter } from '@stackwallet/chains-evm';
import { createSolanaAdapter } from '@stackwallet/chains-solana';
import { createNearAdapter } from '@stackwallet/chains-near';
import { createStellarAdapter } from '@stackwallet/chains-stellar';
import { createSuiAdapter } from '@stackwallet/chains-sui';
import { createSubstrateAdapter } from '@stackwallet/chains-substrate';
import { createTonAdapter } from '@stackwallet/chains-ton';
import { createTronAdapter } from '@stackwallet/chains-tron';
import { createXrplAdapter } from '@stackwallet/chains-xrpl';

import '../store/family-sends.js';

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
    .register(createCosmosAdapter({ rpc }))
    .register(createTronAdapter({ rpc }))
    .register(createSubstrateAdapter({ rpc }))
    .register(createStellarAdapter({ rpc }))
    .register(createAptosAdapter({ rpc }))
    .register(createSuiAdapter({ rpc }))
    .register(createXrplAdapter({ rpc }))
    .register(createNearAdapter({ rpc }))
    .register(createAlgorandAdapter({ rpc }))
    .register(createTonAdapter({ rpc }))
    .register(createCardanoAdapter({ rpc }))
    .register(createAntelopeAdapter({ rpc }))
    .register(createMultiversxAdapter({ rpc }))
    .register(createTezosAdapter({ rpc }))
    .register(createStacksAdapter({ rpc }))
    .register(createVechainAdapter({ rpc }))
    .register(createHyperliquidAdapter({ rpc }))
    .register(createStarknetAdapter({ rpc }))
    .register(createIconAdapter({ rpc }))
    .register(new EverscaleAdapter({ rpc }))
    .register(new WavesAdapter({ rpc }))
    .register(createRadixAdapter({ rpc }))
    .register(createIcpAdapter({ rpc }))
    .register(createErgoAdapter({ rpc }))
    .register(createAlephiumAdapter({ rpc }))
    .register(createNeoAdapter({ rpc }))
    .register(createAeternityAdapter({ rpc }))
    .register(createChiaAdapter({ rpc }))
    .register(createFuelAdapter({ rpc }))
    .register(createAelfAdapter({ rpc }))
    .register(createStarcoinAdapter({ rpc }))
    .register(createObyteAdapter({ rpc }))
    .register(createChromiaAdapter({ rpc }))
    .register(createKeetaAdapter({ rpc }))
    .register(createNamadaAdapter({ rpc }))
    .register(createBtcForkAdapter({ rpc }))
    .register(createGalaAdapter({ rpc }))
    .register(createMixinAdapter({ rpc }))
    .register(createQubicAdapter({ rpc }))
    .register(createAleoAdapter({ rpc }))
    .register(createCantonAdapter({ rpc }));
}
