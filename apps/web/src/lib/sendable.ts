import type { Account, Wallet } from '@stackwallet/core-client';
import { BITCOIN_SIGNET } from '@stackwallet/chains-bitcoin';
import { COSMOS_TESTNET } from '@stackwallet/chains-cosmos';
import { SOLANA_DEVNET } from '@stackwallet/chains-solana';
import { TRON_NILE } from '@stackwallet/chains-tron';

import { EVM_SIGNING_CHAINS } from './chains.js';

/** One testnet per family the core signs on; new wallets include these so Send works out of the box. */
export const SENDABLE_TESTNETS: readonly string[] = [
  'eip155:11155111',
  BITCOIN_SIGNET,
  SOLANA_DEVNET,
  COSMOS_TESTNET,
  TRON_NILE,
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
  }
}
