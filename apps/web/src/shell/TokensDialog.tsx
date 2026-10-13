import { useState, type FormEvent } from 'react';
import { tokenInfo, isValidEvmAddress, type EvmAdapter } from '@stackwallet/chains-evm';
import {
  solanaTokenInfo,
  isValidSolanaAddress,
  SPL_TOKEN_2022_PROGRAM,
  type SolanaAdapter,
} from '@stackwallet/chains-solana';
import { Button, Dialog, Field, Input, Select } from '@stackwallet/ui';
import { findChain, listChains } from '../lib/chains.js';
import { useRegistry } from '../store/RegistryContext.js';
import { tokenStore, useTokens } from '../store/tokens.js';

export function TokensDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose} title="Tracked tokens" meta="ERC-20 / SPL · public reads">
      {open && <TokensBody />}
    </Dialog>
  );
}
function TokensBody() {
  const registry = useRegistry();
  const tokens = useTokens();
  const chains = listChains(registry).filter((c) => c.family === 'evm' || c.family === 'solana');
  const [chainId, setChainId] = useState(
    chains.find((c) => c.testnet)?.chainId ?? chains[0]?.chainId ?? '',
  );
  const [address, setAddress] = useState('');
  const [label, setLabel] = useState('');
  const solana = findChain(registry, chainId)?.family === 'solana';
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const add = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const contract = address.trim();
      const metadata = solana
        ? {
            ...(await solanaTokenInfo(
              registry.adapterFor(chainId) as unknown as SolanaAdapter,
              chainId,
              contract,
            )),
            symbol: label.trim() || 'SPL',
          }
        : await tokenInfo(registry.adapterFor(chainId) as unknown as EvmAdapter, chainId, contract);
      tokenStore.track({ chainId, address: contract, ...metadata });
      setAddress('');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-4 p-4 text-[12px]">
      <p className="text-faint">
        Add a contract or Solana mint to read balances on that chain. ERC-20 symbols are unverified
        contract data; Solana labels are yours. Decimals are read from the contract or mint. Always
        check the full address. Each lookup shares the address with configured endpoints. Solana
        shows public token-account amounts only; frozen, withheld and confidential balances can
        restrict spendability. SPL and Token-2022 transfers are not enabled.
      </p>
      <ul className="max-h-[35vh] space-y-2 overflow-auto">
        {tokens.map((token) => (
          <li
            key={`${token.chainId}:${token.address}`}
            className="rounded-sw-sm border border-edge p-2"
          >
            <div className="flex justify-between gap-2">
              <span className="min-w-0 break-words">
                {token.symbol} · {findChain(registry, token.chainId)?.name ?? token.chainId} ·{' '}
                {token.decimals} decimals
              </span>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  try {
                    tokenStore.remove(token);
                  } catch (err) {
                    setError(String(err));
                  }
                }}
              >
                Untrack
              </Button>
            </div>
            <span className="font-mono break-all text-faint">{token.address}</span>
            {'programId' in token && (
              <p className="break-all text-faint">
                {token.programId === SPL_TOKEN_2022_PROGRAM ? 'Token-2022' : 'SPL Token'} ·{' '}
                {token.programId}
              </p>
            )}
          </li>
        ))}
      </ul>
      <form onSubmit={(e) => void add(e)} className="space-y-3">
        <Field label="Chain" htmlFor="token-chain">
          <Select
            id="token-chain"
            value={chainId}
            disabled={busy}
            onChange={(e) => setChainId(e.target.value)}
          >
            {chains.map((c) => (
              <option key={c.chainId} value={c.chainId}>
                {c.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label={solana ? 'Mint address' : 'Contract address'} htmlFor="token-contract">
          <Input
            id="token-contract"
            value={address}
            disabled={busy}
            onChange={(e) => setAddress(e.target.value)}
            placeholder={solana ? 'Base58 mint address' : '0x…'}
            spellCheck={false}
          />
        </Field>
        {solana && (
          <Field label="Display label · optional, up to 12 ASCII characters" htmlFor="token-label">
            <Input
              id="token-label"
              value={label}
              maxLength={12}
              disabled={busy}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="SPL"
            />
          </Field>
        )}
        {error && (
          <p role="alert" className="text-danger">
            {error}
          </p>
        )}
        <Button
          type="submit"
          disabled={
            busy ||
            tokens.length >= 100 ||
            !(solana ? isValidSolanaAddress(address.trim()) : isValidEvmAddress(address.trim()))
          }
        >
          {busy ? 'reading…' : 'Track token'}
        </Button>
      </form>
    </div>
  );
}
