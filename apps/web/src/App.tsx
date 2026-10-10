import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChainRegistry } from '@stackwallet/chains';
import { createCoreClient, type CoreClient } from '@stackwallet/core-client';
import { Sheet, ToastProvider, useMediaQuery, useToasts } from '@stackwallet/ui';

import { createDefaultRegistry } from './data/registry.js';
import { AddFolderDialog } from './shell/AddFolderDialog.js';
import { AddWatchWalletDialog } from './shell/AddWatchWalletDialog.js';
import { ApprovalRail } from './shell/ApprovalRail.js';
import { CommandPalette } from './shell/CommandPalette.js';
import { ConfirmDeleteDialog } from './shell/ConfirmDeleteDialog.js';
import { DirectoryTree } from './shell/DirectoryTree.js';
import { MainPane } from './shell/MainPane.js';
import { MoveWalletDialog } from './shell/MoveWalletDialog.js';
import {
  isTypingTarget,
  ShellContext,
  type ShellApi,
  type ShellDialog,
  type ShellLayout,
  type UiRoute,
} from './shell/ShellContext.js';
import { StatusBar } from './shell/StatusBar.js';
import { balanceCache } from './store/balances.js';
import { devicesQuarantinedKey } from './store/devices.js';
import { directory, directoryQuarantinedKey, useDirectory } from './store/persist.js';
import { RegistryContext, useRegistry } from './store/RegistryContext.js';
import { applyRpcSettings, rpcSettings, rpcSettingsQuarantinedKey } from './store/rpcSettings.js';

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
    const registry = createDefaultRegistry();
    applyRpcSettings(registry, rpcSettings.getSnapshot());
    return { registry };
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

function useLayout(): ShellLayout {
  const wide = useMediaQuery('(min-width: 1100px)');
  const medium = useMediaQuery('(min-width: 800px)');
  return wide ? 'three' : medium ? 'two' : 'one';
}

function Shell({ registryError }: { registryError?: string | undefined }) {
  const core = useCoreStatus();
  const state = useDirectory();
  const toasts = useToasts();
  const registry = useRegistry();
  const layout = useLayout();

  // The inline rail remembers its own open state so collapsing it on a wide
  // screen does not also decide whether the sheet pops open on a narrow one.
  const [railInline, setRailInline] = useState(true);
  const [railSheet, setRailSheet] = useState(false);
  const [treeOpen, setTreeOpen] = useState(false);
  const [route, setRoute] = useState<UiRoute>({ kind: 'directory' });
  const [dialog, setDialog] = useState<ShellDialog | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    if (layout === 'three') setRailSheet(false);
    if (layout !== 'one') setTreeOpen(false);
  }, [layout]);

  // Picking or creating a node is a request to look at it, so a settings route
  // must not keep covering the main pane.
  const selectedId = state.ui.selectedId;
  useEffect(() => {
    setRoute((r) => (r.kind === 'directory' ? r : { kind: 'directory' }));
  }, [selectedId]);

  useEffect(() => {
    if (directoryQuarantinedKey) {
      toasts.push(
        `Saved directory could not be read; kept under ${directoryQuarantinedKey}`,
        'danger',
      );
    }
    if (rpcSettingsQuarantinedKey) {
      toasts.push(
        `Saved RPC endpoints could not be read; kept under ${rpcSettingsQuarantinedKey}`,
        'danger',
      );
    }
    if (devicesQuarantinedKey) {
      toasts.push(
        `Saved device table could not be read; kept under ${devicesQuarantinedKey}`,
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

  const railOpen = layout === 'three' ? railInline : railSheet;
  const toggleRail = useCallback(() => {
    if (layout === 'three') setRailInline((v) => !v);
    else setRailSheet((v) => !v);
  }, [layout]);

  const shell = useMemo<ShellApi>(
    () => ({
      layout,
      railOpen,
      toggleRail,
      treeOpen,
      toggleTree: () => setTreeOpen((v) => !v),
      closeTree: () => setTreeOpen(false),
      route,
      navigate: setRoute,
      openDialog: setDialog,
      openPalette: () => setPaletteOpen(true),
      refreshBalances,
    }),
    [layout, railOpen, toggleRail, treeOpen, route, refreshBalances],
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
        toggleRail();
        return;
      }
      if (e.key === 'Escape' && !isTypingTarget(e.target)) {
        // An open dialog or sheet owns Escape; the event target may be the
        // body rather than the dialog when focus sits on the top layer itself.
        if (document.querySelector('dialog[open]')) return;
        if (route.kind !== 'directory') setRoute({ kind: 'directory' });
        else if (state.ui.selectedId !== null) directory.select(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [state.ui.selectedId, toggleRail, route.kind]);

  const closeDialog = useCallback(() => setDialog(null), []);
  const deleteTarget =
    dialog?.kind === 'deleteWallet'
      ? { kind: 'wallet' as const, id: dialog.walletId }
      : dialog?.kind === 'deleteFolder'
        ? { kind: 'folder' as const, id: dialog.folderId }
        : null;

  const columns =
    layout === 'one'
      ? 'grid-cols-[minmax(0,1fr)]'
      : layout === 'two' || !railInline
        ? 'grid-cols-[280px_minmax(0,1fr)]'
        : 'grid-cols-[280px_minmax(0,1fr)_320px]';

  return (
    <ShellContext value={shell}>
      <div className="grid h-full grid-rows-[minmax(0,1fr)_auto] overflow-hidden bg-paper text-ink">
        <div className={`grid min-h-0 min-w-0 gap-3 p-3 ${columns}`}>
          {layout !== 'one' && <DirectoryTree />}
          <MainPane />
          {layout === 'three' && railInline && <ApprovalRail />}
        </div>
        <StatusBar core={core} registryError={registryError} />
      </div>

      {layout === 'one' && (
        <Sheet side="left" open={treeOpen} onClose={() => setTreeOpen(false)} label="Directory">
          <DirectoryTree />
        </Sheet>
      )}
      {layout !== 'three' && (
        <Sheet
          side="right"
          open={railSheet}
          onClose={() => setRailSheet(false)}
          label="Approvals"
          width="w-[min(88vw,360px)]"
        >
          <ApprovalRail />
        </Sheet>
      )}

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
      <MoveWalletDialog
        open={dialog?.kind === 'move'}
        walletId={dialog?.kind === 'move' ? dialog.walletId : undefined}
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
