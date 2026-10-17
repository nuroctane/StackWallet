import { useId, useState } from 'react';
import { AETERNITY_TESTNET } from '@stackwallet/chains-aeternity';
import { ALEPHIUM_TESTNET } from '@stackwallet/chains-alephium';
import { ALGORAND_TESTNET } from '@stackwallet/chains-algorand';
import { APTOS_TESTNET } from '@stackwallet/chains-aptos';
import { BITCOIN_SIGNET } from '@stackwallet/chains-bitcoin';
import { CARDANO_PREPROD } from '@stackwallet/chains-cardano';
import { CHIA_TESTNET } from '@stackwallet/chains-chia';
import { COSMOS_TESTNET } from '@stackwallet/chains-cosmos';
import { FUEL_SEPOLIA } from '@stackwallet/chains-fuel';
import { HYPERLIQUID_TESTNET } from '@stackwallet/chains-hyperliquid';
import { MULTIVERSX_DEVNET } from '@stackwallet/chains-multiversx';
import { NEAR_TESTNET } from '@stackwallet/chains-near';
import { RADIX_STOKENET } from '@stackwallet/chains-radix';
import { SOLANA_DEVNET } from '@stackwallet/chains-solana';
import { STACKS_TESTNET } from '@stackwallet/chains-stacks';
import { STARCOIN_BARNARD } from '@stackwallet/chains-starcoin';
import { STARKNET_SEPOLIA } from '@stackwallet/chains-starknet';
import { STELLAR_TESTNET } from '@stackwallet/chains-stellar';
import { SUBSTRATE_WESTEND } from '@stackwallet/chains-substrate';
import { SUI_TESTNET } from '@stackwallet/chains-sui';
import { TRON_NILE } from '@stackwallet/chains-tron';
import { VECHAIN_TESTNET } from '@stackwallet/chains-vechain';
import { XRPL_TESTNET } from '@stackwallet/chains-xrpl';
import { Button, Dialog, Field, Select, useToasts } from '@stackwallet/ui';

import { findChain } from '../lib/chains.js';
import { useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { accountsOf } from '../store/selectors.js';
import { KeyReach } from './KeyLinks.js';
import { QrCode } from './views/QrCode.js';

/** Public faucets for the testnets the core signs on; families without a keyless faucet are left out. */
const FAUCETS: Record<string, string> = {
  'eip155:11155111': 'https://cloud.google.com/application/web3/faucet/ethereum/sepolia',
  'eip155:560048': 'https://hoodi-faucet.pk910.de/',
  'eip155:84532': 'https://docs.base.org/base-chain/tools/network-faucets',
  'eip155:11155420': 'https://console.optimism.io/faucet',
  'eip155:421614': 'https://faucet.quicknode.com/arbitrum/sepolia',
  'eip155:80002': 'https://faucet.polygon.technology/',
  [SOLANA_DEVNET]: 'https://faucet.solana.com/',
  [BITCOIN_SIGNET]: 'https://signetfaucet.com/',
  [COSMOS_TESTNET]: 'https://faucet.testnet.osmosis.zone/',
  [TRON_NILE]: 'https://nileex.io/join/getJoinPage',
  [SUBSTRATE_WESTEND]: 'https://faucet.polkadot.io/westend',
  [STELLAR_TESTNET]: 'https://lab.stellar.org/account/fund?$=network$id=testnet',
  [APTOS_TESTNET]: 'https://aptos.dev/network/faucet',
  [SUI_TESTNET]: 'https://faucet.sui.io/',
  [XRPL_TESTNET]: 'https://xrpl.org/resources/dev-tools/xrp-faucets',
  [NEAR_TESTNET]: 'https://near-faucet.io/',
  [ALGORAND_TESTNET]: 'https://bank.testnet.algorand.network/',
  [CARDANO_PREPROD]: 'https://docs.cardano.org/cardano-testnets/tools/faucet',
  [MULTIVERSX_DEVNET]: 'https://devnet-wallet.multiversx.com/',
  [STACKS_TESTNET]: 'https://explorer.hiro.so/sandbox/faucet?chain=testnet',
  [VECHAIN_TESTNET]: 'https://faucet.vecha.in/',
  [HYPERLIQUID_TESTNET]: 'https://app.hyperliquid-testnet.xyz/drip',
  [STARKNET_SEPOLIA]: 'https://starknet-faucet.vercel.app/',
  [RADIX_STOKENET]: 'https://stokenet-dashboard.radixdlt.com/',
  [ALEPHIUM_TESTNET]: 'https://faucet.testnet.alephium.org/',
  [AETERNITY_TESTNET]: 'https://faucet.aepps.com/',
  [CHIA_TESTNET]: 'https://testnet11-faucet.chia.net/',
  [FUEL_SEPOLIA]: 'https://faucet-testnet.fuel.network/',
  [STARCOIN_BARNARD]: 'https://faucet.starcoin.org/barnard',
};

/**
 * One address to receive on, as text and as a QR code. The chain is named
 * above the code because an address on one chain family can be valid, and
 * lost, on another.
 */
export function ReceiveDialog({
  open,
  walletId,
  onClose,
}: {
  open: boolean;
  walletId?: string | undefined;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onClose={onClose} title="Receive" meta="share an address">
      {walletId && <ReceiveBody walletId={walletId} />}
    </Dialog>
  );
}

function ReceiveBody({ walletId }: { walletId: string }) {
  const state = useDirectory();
  const registry = useRegistry();
  const toasts = useToasts();
  const field = useId();
  const accounts = accountsOf(state, walletId).filter((a) => !a.hidden);
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? '');
  const account = accounts.find((a) => a.id === accountId) ?? accounts[0];
  if (!account) return <p className="p-4 text-[12px] text-faint">This wallet has no accounts.</p>;
  const chain = findChain(registry, account.chainId);
  const copy = () =>
    void navigator.clipboard
      .writeText(account.address)
      .then(() => toasts.push('Address copied'))
      .catch(() => toasts.push('Clipboard unavailable', 'danger'));

  return (
    <div className="flex flex-col gap-4 p-4">
      <Field label="Account" htmlFor={field}>
        <Select id={field} value={account.id} onChange={(e) => setAccountId(e.target.value)}>
          {accounts.map((a) => (
            <option key={a.id} value={a.id}>
              {findChain(registry, a.chainId)?.name ?? a.chainId}
              {a.label ? ` · ${a.label}` : ''}
            </option>
          ))}
        </Select>
      </Field>
      <p className="text-[12px] text-muted">
        Send only <span className="text-ink">{chain?.name ?? account.chainId}</span> assets
        {chain?.testnet ? ' (a testnet; its coins have no value)' : ''} to this address.
      </p>
      <div className="mx-auto w-[220px]">
        <QrCode text={account.address} />
      </div>
      <code className="rounded-sw-sm border border-edge bg-paper p-2 text-center font-mono text-[12px] break-all text-ink select-all">
        {account.address}
      </code>
      <KeyReach account={account} />
      {FAUCETS[account.chainId] && (
        <p className="text-[11px] text-faint">
          Free test coins:{' '}
          <a
            href={FAUCETS[account.chainId]}
            target="_blank"
            rel="noreferrer noopener"
            className="text-muted underline"
          >
            {new URL(FAUCETS[account.chainId]!).hostname}
          </a>{' '}
          (a third-party faucet; paste the address above).
        </p>
      )}
      <div className="flex justify-end">
        <Button variant="primary" onClick={copy}>
          Copy address
        </Button>
      </div>
    </div>
  );
}
