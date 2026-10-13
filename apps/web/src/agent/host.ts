import type { AgentHost, HostBalance } from '@stackwallet/agent';
import type { ChainRegistry } from '@stackwallet/chains';

import { findChain } from '../lib/chains.js';
import { labelFor } from '../lib/labels.js';
import { parseUnits } from '../lib/format.js';
import { balanceCache } from '../store/balances.js';
import { directory } from '../store/persist.js';
import { tokenStore } from '../store/tokens.js';
import { proposeSend } from '../store/txs.js';
import { vault } from '../core/bridge.js';

/**
 * The app side of the agent's tools. It reads the directory, balances and
 * labels the user already sees, and proposes through the same path as the
 * send form, marked as the agent's with its rationale. It has no way to
 * approve, sign or broadcast.
 */
export function createAgentHost(
  registry: ChainRegistry,
  session: { sessionId: string; grantId: string },
): AgentHost {
  const chainName = (id: string) => findChain(registry, id)?.name ?? id;
  return {
    wallets: () => {
      const s = directory.getSnapshot();
      return s.wallets.map((w) => ({
        id: w.id,
        name: w.name,
        kind: w.kind,
        accounts: s.accounts
          .filter((a) => a.walletId === w.id && !a.hidden)
          .map((a) => ({ chainId: a.chainId, address: a.address, chain: chainName(a.chainId) })),
      }));
    },
    balances: async (walletId) => {
      const s = directory.getSnapshot();
      const accounts = s.accounts.filter((a) => a.walletId === walletId && !a.hidden);
      await Promise.allSettled(accounts.map((a) => balanceCache.ensure(registry, a)));
      const out: HostBalance[] = [];
      for (const a of accounts) {
        const chain = findChain(registry, a.chainId);
        for (const h of balanceCache.get(a.chainId, a.address)?.holdings ?? []) {
          const native = h.assetRef === `${a.chainId}:native`;
          const symbol = native ? (chain?.nativeAsset.symbol ?? '?') : (h.metadata?.symbol ?? '?');
          const decimals = native
            ? (chain?.nativeAsset.decimals ?? 0)
            : (h.metadata?.decimals ?? 0);
          const amount = h.amount;
          out.push({
            chainId: a.chainId,
            chain: chainName(a.chainId),
            asset: native ? 'native' : h.assetRef.slice(h.assetRef.lastIndexOf(':') + 1),
            symbol,
            amount: decimals > 0 ? `${amount} base units (${decimals} decimals)` : amount,
          });
        }
      }
      return out;
    },
    label: (address, chainId) => {
      const s = directory.getSnapshot();
      const l = labelFor(address, chainId, {
        wallets: s.wallets,
        accounts: s.accounts,
        names: new Map(),
        walletText: (id) => s.wallets.find((w) => w.id === id)?.name ?? id,
        ledger: vault.getSnapshot().ledger,
        contacts: s.contacts,
      });
      return { label: l.label, source: l.source };
    },
    proposeTransfer: async (input) => {
      const s = directory.getSnapshot();
      const account = s.accounts.find(
        (a) => a.walletId === input.walletId && a.chainId === input.chainId && a.derivationPath,
      );
      if (!account) return { ok: false, error: 'No signing account for that wallet on that chain' };
      const chain = findChain(registry, input.chainId);
      const native = input.asset === 'native';
      const token = native ? undefined : tokenStore.find(`${input.chainId}:erc20:${input.asset}`);
      const decimals = native ? chain?.nativeAsset.decimals : token?.decimals;
      if (decimals === undefined)
        return { ok: false, error: 'Unknown asset; track the token first' };
      const units = parseUnits(input.amount, decimals);
      if (units === null) return { ok: false, error: 'Amount has too many decimals' };
      const r = await proposeSend(registry, {
        account,
        to: input.to,
        asset: native ? `${input.chainId}:native` : `${input.chainId}:erc20:${input.asset}`,
        amount: units,
        agent: { ...session, rationale: input.rationale.slice(0, 500) },
        untrustedDestinations: input.untrustedDestination ? [input.to] : [],
      });
      return r.ok
        ? { ok: true, state: r.value.state, txId: r.value.id }
        : { ok: false, error: r.error };
    },
  };
}
