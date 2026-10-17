import type { Account, Wallet } from '@stackwallet/core-client';
import { BITCOIN_SIGNET } from '@stackwallet/chains-bitcoin';
import { COSMOS_TESTNET } from '@stackwallet/chains-cosmos';
import { SOLANA_DEVNET } from '@stackwallet/chains-solana';
import { ALGORAND_TESTNET } from '@stackwallet/chains-algorand';
import { APTOS_TESTNET } from '@stackwallet/chains-aptos';
import { NEAR_TESTNET } from '@stackwallet/chains-near';
import { STELLAR_TESTNET } from '@stackwallet/chains-stellar';
import { SUI_TESTNET } from '@stackwallet/chains-sui';
import { XRPL_TESTNET } from '@stackwallet/chains-xrpl';
import { SUBSTRATE_WESTEND } from '@stackwallet/chains-substrate';
import { TON_TESTNET } from '@stackwallet/chains-ton';
import { CARDANO_PREPROD } from '@stackwallet/chains-cardano';
import { ANTELOPE_TESTNET } from '@stackwallet/chains-antelope';
import { MULTIVERSX_DEVNET } from '@stackwallet/chains-multiversx';
import { TEZOS_SHADOWNET } from '@stackwallet/chains-tezos';
import { STACKS_TESTNET } from '@stackwallet/chains-stacks';
import { VECHAIN_TESTNET } from '@stackwallet/chains-vechain';
import { HYPERLIQUID_TESTNET } from '@stackwallet/chains-hyperliquid';
import { STARKNET_SEPOLIA } from '@stackwallet/chains-starknet';
import { ICON_LISBON } from '@stackwallet/chains-icon';
import { VENOM_TESTNET } from '@stackwallet/chains-everscale';
import { WAVES_TESTNET } from '@stackwallet/chains-waves';
import { RADIX_STOKENET } from '@stackwallet/chains-radix';
import { ICP_MAINNET } from '@stackwallet/chains-icp';
import { ERGO_TESTNET } from '@stackwallet/chains-ergo';
import { ALEPHIUM_TESTNET } from '@stackwallet/chains-alephium';
import { AETERNITY_TESTNET } from '@stackwallet/chains-aeternity';
import { CHIA_TESTNET } from '@stackwallet/chains-chia';
import { FUEL_SEPOLIA } from '@stackwallet/chains-fuel';
import { AELF_TESTNET } from '@stackwallet/chains-aelf';
import { STARCOIN_BARNARD } from '@stackwallet/chains-starcoin';
import { OBYTE_TESTNET } from '@stackwallet/chains-obyte';
import { CHROMIA_TESTNET } from '@stackwallet/chains-chromia';
import { KEETA_TEST } from '@stackwallet/chains-keeta';
import { NAMADA_HOUSEFIRE } from '@stackwallet/chains-namada';
import { SIGNING_CHAINS as BTCFORK_SIGNING } from '@stackwallet/chains-btcfork';
import { GALA_TESTNET } from '@stackwallet/chains-gala';
import { MIXIN_MAINNET } from '@stackwallet/chains-mixin';
import { QUBIC_MAINNET } from '@stackwallet/chains-qubic';
import { TRON_NILE } from '@stackwallet/chains-tron';

import { familySendFor } from '../store/families.js';
import '../store/family-sends.js';
import { EVM_SIGNING_CHAINS } from './chains.js';

/** One testnet per family the core signs on; new wallets include these so Send works out of the box. */
export const SENDABLE_TESTNETS: readonly string[] = [
  'eip155:11155111',
  BITCOIN_SIGNET,
  SOLANA_DEVNET,
  COSMOS_TESTNET,
  TRON_NILE,
  SUBSTRATE_WESTEND,
  STELLAR_TESTNET,
  APTOS_TESTNET,
  SUI_TESTNET,
  XRPL_TESTNET,
  NEAR_TESTNET,
  ALGORAND_TESTNET,
  TON_TESTNET,
  CARDANO_PREPROD,
  ANTELOPE_TESTNET,
  MULTIVERSX_DEVNET,
  TEZOS_SHADOWNET,
  STACKS_TESTNET,
  VECHAIN_TESTNET,
  HYPERLIQUID_TESTNET,
  STARKNET_SEPOLIA,
  ICON_LISBON,
  VENOM_TESTNET,
  WAVES_TESTNET,
  RADIX_STOKENET,
  // Mainnet, deliberately: ICP has no public testnet ledger to gate signing on.
  ICP_MAINNET,
  ERGO_TESTNET,
  ALEPHIUM_TESTNET,
  AETERNITY_TESTNET,
  CHIA_TESTNET,
  FUEL_SEPOLIA,
  AELF_TESTNET,
  STARCOIN_BARNARD,
  OBYTE_TESTNET,
  CHROMIA_TESTNET,
  KEETA_TEST,
  NAMADA_HOUSEFIRE,
  ...BTCFORK_SIGNING,
  GALA_TESTNET,
  MIXIN_MAINNET,
  QUBIC_MAINNET,
];

/**
 * Whether the core will sign a transfer from this account. Mainnet signing stays behind the
 * support gates in SECURITY.md, so only testnets qualify; the core refuses anything else anyway.
 */
export function canSendFrom(
  account: Pick<Account, 'chainId' | 'family' | 'derivationPath'>,
  wallet: Pick<Wallet, 'kind'> | undefined,
): boolean {
  if (!wallet) return false;
  // A shared wallet signs Solana Devnet transfers through a two-device ceremony.
  if (wallet.kind === 'tss') return account.chainId === SOLANA_DEVNET;
  // A Ledger signs EVM transactions; its accounts send through the device.
  if (wallet.kind !== 'single' && wallet.kind !== 'hardware') return false;
  if (!account.derivationPath) return false;
  switch (account.family) {
    case 'evm':
      return EVM_SIGNING_CHAINS.has(account.chainId);
    case 'solana':
      return account.chainId === SOLANA_DEVNET;
    case 'cosmos':
      return account.chainId === COSMOS_TESTNET;
    case 'bitcoin':
      return account.chainId === BITCOIN_SIGNET;
    case 'tron':
      return account.chainId === TRON_NILE;
    default:
      return familySendFor(account)?.signingChains.includes(account.chainId) ?? false;
  }
}
