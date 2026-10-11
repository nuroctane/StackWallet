import { useState, type FormEvent } from 'react';
import { tokenInfo, isValidEvmAddress, type EvmAdapter } from '@stackwallet/chains-evm';
import { Button, Dialog, Field, Input, Select } from '@stackwallet/ui';
import { findChain, listChains } from '../lib/chains.js';
import { useRegistry } from '../store/RegistryContext.js';
import { tokenStore, useTokens } from '../store/tokens.js';

export function TokensDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose} title="Tracked tokens" meta="ERC-20 · public metadata">
      {open && <TokensBody />}
    </Dialog>
  );
}
function TokensBody() {
  const registry = useRegistry();
  const tokens = useTokens();
  const chains = listChains(registry).filter((c) => c.family === 'evm');
  const [chainId, setChainId] = useState(
    chains.find((c) => c.testnet)?.chainId ?? chains[0]?.chainId ?? '',
  );
  const [address, setAddress] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const add = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const contract = address.trim();
      const metadata = await tokenInfo(
        registry.adapterFor(chainId) as unknown as EvmAdapter,
        chainId,
        contract,
      );
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
        Add a contract to read its balance for accounts on that chain. Symbols and decimals come
        from the contract and are unverified display data; always check the full address.
      </p>
      <ul className="max-h-[35vh] space-y-2 overflow-auto">
        {tokens.map((token) => (
          <li
            key={`${token.chainId}:${token.address}`}
            className="rounded-sw-sm border border-edge p-2"
          >
            <div className="flex justify-between gap-2">
              <span>
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
        <Field label="Contract address" htmlFor="token-contract">
          <Input
            id="token-contract"
            value={address}
            disabled={busy}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="0x…"
            spellCheck={false}
          />
        </Field>
        {error && (
          <p role="alert" className="text-danger">
            {error}
          </p>
        )}
        <Button
          type="submit"
          disabled={busy || tokens.length >= 100 || !isValidEvmAddress(address.trim())}
        >
          {busy ? 'reading…' : 'Track token'}
        </Button>
      </form>
    </div>
  );
}
