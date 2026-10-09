import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChainRegistry } from '@stackwallet/chains';
import { createCoreClient, type CoreClient } from '@stackwallet/core-client';
import { ToastProvider, useToasts } from '@stackwallet/ui';

import { createDefaultRegistry } from './data/registry.js';
import { AddFolderDialog } from './shell/AddFolderDialog.js';
import { AddWatchWalletDialog } from './shell/AddWatchWalletDialog.js';
import { ApprovalRail } from './shell/ApprovalRail.js';
import { CommandPalette } from './shell/CommandPalette.js';
import { ConfirmDeleteDialog } from './shell/ConfirmDeleteDialog.js';
import { DirectoryTree } from './shell/DirectoryTree.js';
import { MainPane } from './shell/MainPane.js';
import {
  isTypingTarget,
  ShellContext,
  type ShellApi,
  type ShellDialog,
} from './shell/ShellContext.js';
import { StatusBar } from './shell/StatusBar.js';
import { balanceCache } from './store/balances.js';
import { directory, directoryQuarantinedKey, useDirectory } from './store/persist.js';
import { RegistryContext, useRegistry } from './store/RegistryContext.js';

export interface CoreStatus {
  backend: CoreClient['backend'];
  version?: string;
  reason?: string;
}

function useCoreStatus(): CoreStatus {
  const [core, setCore] = useState<CoreStatus>({ backend: 'unavailable', reason: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void createCoreClient().then(async (client) => {
      if (cancelled) return;
      if (client.backend === 'unavailable') {
        setCore({
          backend: 'unavailable',
          reason: 'reason' in client ? String(client.reason) : 'unknown',
        });
        return;
      }
      try {
        setCore({ backend: client.backend, version: await client.coreVersion() });
      } catch (err) {
        setCore({
          backend: 'unavailable',
          reason: err instanceof Error ? err.message : String(err),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return core;
}

function buildRegistry(): { registry: ChainRegistry; error?: string } {
  try {
    return { registry: createDefaultRegistry() };
  } catch (err) {
    return {
      registry: new ChainRegistry(),
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export function App() {
  const { registry, error: registryError } = useMemo(buildRegistry, []);
  return (
    <RegistryContext value={registry}>
      <ToastProvider>
        <Shell registryError={registryError} />
      </ToastProvider>
    </RegistryContext>
  );
}

function Shell({ registryError }: { registryError?: string | undefined }) {
  const core = useCoreStatus();
  const state = useDirectory();
  const toasts = useToasts();
  const registry = useRegistry();

  const [railOpen, setRailOpen] = useState(true);
  const [dialog, setDialog] = useState<ShellDialog | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    if (directoryQuarantinedKey) {
      toasts.push(
        `Saved directory could not be read; kept under ${directoryQuarantinedKey}`,
        'danger',
      );
    }
    // Runs once: the quarantine happened at module load, before React mounted.
  }, []);

  const refreshBalances = useCallback(() => {
    if (state.accounts.length === 0) {
      toasts.push('No accounts to refresh');
      return;
    }
    void balanceCache.refresh(registry, state.accounts);
  }, [registry, state.accounts, toasts]);

  const shell = useMemo<ShellApi>(
    () => ({
      railOpen,
      toggleRail: () => setRailOpen((v) => !v),
      openDialog: setDialog,
      openPalette: () => setPaletteOpen(true),
      refreshBalances,
    }),
    [railOpen, refreshBalances],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setPaletteOpen((v) => !v);
        return;
      }
      if (mod && e.key === '.') {
        e.preventDefault();
        setRailOpen((v) => !v);
        return;
      }
      if (e.key === 'Escape' && !isTypingTarget(e.target) && state.ui.selectedId !== null) {
        directory.select(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [state.ui.selectedId]);

  const closeDialog = useCallback(() => setDialog(null), []);
  const deleteTarget =
    dialog?.kind === 'deleteWallet'
      ? { kind: 'wallet' as const, id: dialog.walletId }
      : dialog?.kind === 'deleteFolder'
        ? { kind: 'folder' as const, id: dialog.folderId }
        : null;

  return (
    <ShellContext value={shell}>
      <div className="grid h-full grid-rows-[1fr_auto] bg-paper text-ink">
        <div
          className={`grid min-h-0 gap-3 p-3 ${
            railOpen
              ? 'grid-cols-[280px_1fr] min-[1100px]:grid-cols-[280px_1fr_320px]'
              : 'grid-cols-[280px_1fr]'
          }`}
        >
          <DirectoryTree />
          <MainPane />
          {railOpen && <ApprovalRail />}
        </div>
        <StatusBar core={core} registryError={registryError} />
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <AddFolderDialog
        open={dialog?.kind === 'folder'}
        parentId={dialog?.kind === 'folder' ? dialog.parentId : undefined}
        onClose={closeDialog}
      />
      <AddWatchWalletDialog
        open={dialog?.kind === 'watch'}
        folderId={dialog?.kind === 'watch' ? dialog.folderId : undefined}
        onClose={closeDialog}
      />
      <ConfirmDeleteDialog
        open={deleteTarget !== null}
        target={deleteTarget}
        onClose={closeDialog}
      />
    </ShellContext>
  );
}
