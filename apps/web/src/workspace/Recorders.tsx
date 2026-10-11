import { useEffect, useMemo } from 'react';

import { findChain } from '../lib/chains.js';
import { useBalances } from '../store/balances.js';
import { namesStore } from '../store/names.js';
import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { pollPending } from '../store/txs.js';
import { devices } from '../store/devices.js';
import { directory, useDirectory } from '../store/persist.js';
import { useRegistry } from '../store/RegistryContext.js';
import { aggregateNative } from '../store/totals.js';
import { activityLog } from './activity.js';
import { totalsLedger } from './ledger.js';
import { workspace } from './persist.js';

/**
 * Feeds the two local histories the terrain and ledger elements draw from.
 * Renders nothing. Structural directory changes (not selection or expansion)
 * count as activity; layout edits and device changes count too.
 */
const TX_POLL_MS = 12_000;

export function Recorders() {
  const state = useDirectory();
  const registry = useRegistry();
  const balances = useBalances(state.accounts);

  useEffect(() => {
    let prev = directory.getSnapshot();
    const unsubDir = directory.subscribe(() => {
      const next = directory.getSnapshot();
      if (
        next.folders !== prev.folders ||
        next.wallets !== prev.wallets ||
        next.accounts !== prev.accounts
      ) {
        activityLog.record('directory');
      }
      prev = next;
    });
    let prevDevices = devices.getSnapshot();
    const unsubDevices = devices.subscribe(() => {
      const next = devices.getSnapshot();
      if (next.devices !== prevDevices.devices || next.localDevice !== prevDevices.localDevice) {
        activityLog.record('device');
      }
      prevDevices = next;
    });
    let prevWs = workspace.getSnapshot();
    const unsubWs = workspace.subscribe(() => {
      const next = workspace.getSnapshot();
      if (next.layouts !== prevWs.layouts) activityLog.record('layout');
      prevWs = next;
    });
    return () => {
      unsubDir();
      unsubDevices();
      unsubWs();
    };
  }, []);

  // Pending transactions are asked about until the chain gives a final answer.
  const { ledger } = useVaultView(vault);
  const pending =
    ledger?.txs.filter(
      (t) =>
        t.state === 'pending' ||
        ((t.intent.chainId.startsWith('solana:') || t.intent.chainId.startsWith('cosmos:')) &&
          ['signed', 'broadcast'].includes(t.state)),
    ) ?? [];
  const pendingKey = pending.map((t) => t.id).join('|');
  useEffect(() => {
    if (pendingKey === '') return;
    const tick = () => void pollPending(registry, vault.getSnapshot().ledger?.txs ?? []);
    tick();
    const id = setInterval(tick, TX_POLL_MS);
    return () => clearInterval(id);
  }, [pendingKey, registry]);

  // Names follow the wallets: every account added or watched gets its names looked up.
  useEffect(() => {
    namesStore.ensure(state.accounts);
  }, [state.accounts]);

  const totals = useMemo(
    () => aggregateNative(state.accounts, balances.byAccount, (id) => findChain(registry, id)),
    [state.accounts, balances.byAccount, registry],
  );

  useEffect(() => {
    if (balances.loading) return;
    if (totals.some((t) => !t.incomplete)) {
      totalsLedger.record(totals, Date.now());
      activityLog.record('balance');
    }
  }, [totals, balances.loading]);

  return null;
}
