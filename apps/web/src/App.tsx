import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChainRegistry } from '@stackwallet/chains';
import { ToastProvider, useMediaQuery, useToasts } from '@stackwallet/ui';

import { useCoreStatus } from './core/bridge.js';
import { createDefaultRegistry } from './data/registry.js';
import { AddFolderDialog } from './shell/AddFolderDialog.js';
import { AddWatchWalletDialog } from './shell/AddWatchWalletDialog.js';
import { ApprovalRailBody } from './shell/ApprovalRail.js';
import { ConfirmDeleteDialog } from './shell/ConfirmDeleteDialog.js';
import { MoveWalletDialog } from './shell/MoveWalletDialog.js';
import {
  isTypingTarget,
  ShellContext,
  type ShellApi,
  type ShellDialog,
  type UiRoute,
} from './shell/ShellContext.js';
import { NewWalletDialog } from './shell/NewWalletDialog.js';
import { RevealDialog } from './shell/RevealDialog.js';
import { SendDialog } from './shell/SendDialog.js';
import { PoliciesDialog } from './shell/PoliciesDialog.js';
import { TokensDialog } from './shell/TokensDialog.js';
import { tokenStore } from './store/tokens.js';
import {
  ExportKeyDialog,
  ImportSetDialog,
  TransferSetDialog,
  TransferWalletDialog,
} from './shell/SetTransferDialogs.js';
import { ReceiveDialog } from './shell/ReceiveDialog.js';
import { AddAccountDialog } from './shell/AddAccountDialog.js';
import { ContactsDialog } from './shell/ContactsDialog.js';
import { SignMessageDialog } from './shell/SignMessageDialog.js';
import { HardwareWalletDialog } from './shell/HardwareWalletDialog.js';
import { NftSendDialog } from './shell/NftSendDialog.js';
import { StakeDialog, SwapDialog } from './shell/TradeDialogs.js';
import { WalletConnectDialog, WalletConnectNotifier } from './shell/WalletConnectDialog.js';
import { walletConnect } from './walletconnect/client.js';
import { StatusBar } from './shell/StatusBar.js';
import { ThemeStudio } from './shell/ThemeStudio.js';
import { VaultDialog } from './shell/VaultDialog.js';
import { balanceCache } from './store/balances.js';
import { devicesQuarantinedKey } from './store/devices.js';
import { directoryQuarantinedKey, useDirectory } from './store/persist.js';
import { RegistryContext, useRegistry } from './store/RegistryContext.js';
import { applyRpcSettings, rpcSettings, rpcSettingsQuarantinedKey } from './store/rpcSettings.js';
import { collectiblesStore } from './store/collectibles.js';
import { approvalsStore } from './store/approvals.js';
import { automationStore, startAutomations } from './store/automations.js';
import { namesStore } from './store/names.js';
import { themeQuarantinedKey } from './store/theme.js';
import { ThemeApplier } from './store/ThemeApplier.js';
import { Canvas } from './workspace/Canvas.js';
import { ElementCatalogue } from './workspace/ElementCatalogue.js';
import { registry as elementRegistry } from './workspace/elements/registry.js';
import { LayoutTabs } from './workspace/LayoutTabs.js';
import { LockSignal } from './workspace/LockSignal.js';
import { OmniSearch } from './workspace/OmniSearch.js';
import { workspace, workspaceQuarantinedKey } from './workspace/persist.js';
import { Recorders } from './workspace/Recorders.js';
import type { ElementKind } from './workspace/schema.js';
import { SettingsPopover } from './workspace/SettingsPopover.js';
import { StackMode } from './workspace/StackMode.js';
import { TopBar } from './workspace/TopBar.js';
import { Tray } from './workspace/Tray.js';
import {
  canvasPointRef,
  getCanvasViewport,
  WorkspaceContext,
  type WorkspaceApi,
} from './workspace/WorkspaceContext.js';

function buildRegistry(): { registry: ChainRegistry; error?: string } {
  try {
    const registry = createDefaultRegistry();
    applyRpcSettings(registry, rpcSettings.getSnapshot());
    namesStore.configure(registry);
    collectiblesStore.configure(registry);
    approvalsStore.configure(registry);
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
  useEffect(() => {
    if (registryError) return;
    const unconfigure = tokenStore.configure(registry);
    const unsubscribe = tokenStore.subscribe(() => balanceCache.invalidate());
    const stopAutomations = startAutomations(registry);
    void walletConnect.start(registry);
    return () => {
      unconfigure();
      unsubscribe();
      stopAutomations();
    };
  }, [registry, registryError]);
  return (
    <RegistryContext value={registry}>
      <ToastProvider>
        <Shell registryError={registryError} />
      </ToastProvider>
    </RegistryContext>
  );
}

/** Open the first pane of a kind, or add one at the next free slot. */
function revealElement(kind: ElementKind): void {
  const existing = workspace.findPane(kind);
  if (existing) {
    workspace.raise(existing.id);
    workspace.focus(existing.id);
    return;
  }
  const def = elementRegistry[kind];
  workspace.addPane(
    { kind, props: { ...(def.defaultProps ?? {}) }, w: def.defaultSize.w, h: def.defaultSize.h },
    getCanvasViewport(),
  );
}

const ROUTE_HOME: UiRoute = { kind: 'directory' };

function Shell({ registryError }: { registryError?: string | undefined }) {
  const core = useCoreStatus();
  const state = useDirectory();
  const toasts = useToasts();
  const registry = useRegistry();
  const narrow = useMediaQuery('(max-width: 799px)');

  const [dialog, setDialog] = useState<ShellDialog | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [trayOpen, setTrayOpen] = useState(false);
  const [catalogue, setCatalogue] = useState<HTMLElement | null>(null);
  const [settings, setSettings] = useState<{ paneId: string; anchor: HTMLElement } | null>(null);

  useEffect(() => {
    const quarantined: [string | undefined, string][] = [
      [directoryQuarantinedKey, 'Saved directory'],
      [rpcSettingsQuarantinedKey, 'Saved RPC endpoints'],
      [devicesQuarantinedKey, 'Saved device table'],
      [workspaceQuarantinedKey, 'Saved workspace'],
      [themeQuarantinedKey, 'Saved theme'],
      [tokenStore.quarantinedKey, 'Tracked tokens'],
      [automationStore.quarantinedKey, 'Automations'],
    ];
    for (const [key, what] of quarantined) {
      if (key) toasts.push(`${what} could not be read; kept under ${key}`, 'danger');
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

  // Legacy views still speak the three-column shell's API; the workspace answers it with panes.
  const shell = useMemo<ShellApi>(
    () => ({
      layout: 'three',
      railOpen: trayOpen,
      toggleRail: () => setTrayOpen((v) => !v),
      treeOpen: false,
      toggleTree: () => revealElement('directory'),
      closeTree: () => undefined,
      route: ROUTE_HOME,
      navigate: (route) => {
        if (route.kind === 'devices') revealElement('devices');
        else if (route.kind === 'network') revealElement('network');
        else revealElement('directory');
      },
      openDialog: setDialog,
      openPalette: () => setSearchOpen(true),
      refreshBalances,
    }),
    [trayOpen, refreshBalances],
  );

  const coreLabel =
    core.backend === 'unavailable'
      ? `core unavailable`
      : `core ${core.version ?? '?'} · ${core.backend}`;
  const api = useMemo<WorkspaceApi>(
    () => ({
      registry: elementRegistry,
      openSearch: () => setSearchOpen(true),
      openCatalogue: (anchor) => setCatalogue(anchor),
      openSettings: (paneId, anchor) => setSettings({ paneId, anchor }),
      openVault: () => setDialog({ kind: 'vault' }),
      openTheme: () => setDialog({ kind: 'theme' }),
      coreLabel,
      coreState:
        core.backend === 'unavailable'
          ? core.reason === 'loading'
            ? 'busy'
            : 'offline'
          : 'online',
    }),
    [coreLabel, core.backend, core.reason],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.shiftKey && (e.key === 'E' || e.key === 'e')) {
        e.preventDefault();
        canvasPointRef.current = null;
        setCatalogue(document.body);
        return;
      }
      if (mod && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setSearchOpen((v) => !v);
        return;
      }
      if (isTypingTarget(e.target) || mod || e.altKey) return;
      if (e.key === '/') {
        e.preventDefault();
        setSearchOpen(true);
      } else if (e.key === 't' || e.key === 'T') {
        if (document.querySelector('dialog[open]')) return;
        setDialog({ kind: 'theme' });
      } else if (e.key === 'l' || e.key === 'L') {
        if (document.querySelector('dialog[open]')) return;
        workspace.toggleLock();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const closeDialog = useCallback(() => setDialog(null), []);
  // A dapp's request opens its dialog unless the user is already in another one.
  const openWalletConnect = useCallback(() => setDialog((d) => d ?? { kind: 'walletConnect' }), []);
  const deleteTarget =
    dialog?.kind === 'deleteWallet'
      ? { kind: 'wallet' as const, id: dialog.walletId }
      : dialog?.kind === 'deleteFolder'
        ? { kind: 'folder' as const, id: dialog.folderId }
        : null;

  return (
    <ShellContext value={shell}>
      <ThemeApplier />
      <WorkspaceContext.Provider value={api}>
        <div className="flex h-full flex-col overflow-hidden bg-paper text-ink">
          <TopBar trayOpen={trayOpen} onToggleTray={() => setTrayOpen((v) => !v)} />
          <LayoutTabs />
          {narrow ? <StackMode /> : <Canvas />}
          <StatusBar core={core} registryError={registryError} />
        </div>
        <Tray open={trayOpen} onOpenChange={setTrayOpen}>
          <ApprovalRailBody />
        </Tray>
        <Recorders />
        <LockSignal />

        <OmniSearch
          open={searchOpen}
          onClose={() => setSearchOpen(false)}
          viewport={getCanvasViewport}
        />
        <ElementCatalogue
          anchor={catalogue}
          open={catalogue !== null}
          onClose={() => {
            setCatalogue(null);
            canvasPointRef.current = null;
          }}
          viewport={getCanvasViewport}
          at={canvasPointRef.current}
        />
        <SettingsPopover
          paneId={settings?.paneId ?? null}
          anchor={settings?.anchor ?? null}
          onClose={() => setSettings(null)}
        />
      </WorkspaceContext.Provider>

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
      <VaultDialog open={dialog?.kind === 'vault'} onClose={closeDialog} />
      <ThemeStudio open={dialog?.kind === 'theme'} onClose={closeDialog} />
      <PoliciesDialog open={dialog?.kind === 'policies'} onClose={closeDialog} />
      <TokensDialog open={dialog?.kind === 'tokens'} onClose={closeDialog} />
      <NewWalletDialog
        open={dialog?.kind === 'newWallet'}
        folderId={dialog?.kind === 'newWallet' ? dialog.folderId : undefined}
        onClose={closeDialog}
      />
      <RevealDialog
        open={dialog?.kind === 'reveal'}
        walletId={dialog?.kind === 'reveal' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <TransferSetDialog
        open={dialog?.kind === 'transferSet'}
        folderId={dialog?.kind === 'transferSet' ? dialog.folderId : undefined}
        onClose={closeDialog}
      />
      <TransferWalletDialog
        open={dialog?.kind === 'transferWallet'}
        walletId={dialog?.kind === 'transferWallet' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <ExportKeyDialog
        open={dialog?.kind === 'exportKey'}
        target={dialog?.kind === 'exportKey' ? { scope: dialog.scope, id: dialog.id } : undefined}
        onClose={closeDialog}
      />
      <ImportSetDialog open={dialog?.kind === 'importSet'} onClose={closeDialog} />
      <NftSendDialog
        open={dialog?.kind === 'sendNft'}
        target={dialog?.kind === 'sendNft' ? dialog : undefined}
        onClose={closeDialog}
      />
      <HardwareWalletDialog
        open={dialog?.kind === 'hardwareWallet'}
        folderId={dialog?.kind === 'hardwareWallet' ? dialog.folderId : undefined}
        onClose={closeDialog}
      />
      <SwapDialog
        open={dialog?.kind === 'swap'}
        walletId={dialog?.kind === 'swap' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <StakeDialog
        open={dialog?.kind === 'stake'}
        walletId={dialog?.kind === 'stake' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <SignMessageDialog
        open={dialog?.kind === 'signMessage'}
        walletId={dialog?.kind === 'signMessage' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <ContactsDialog open={dialog?.kind === 'contacts'} onClose={closeDialog} />
      <WalletConnectDialog open={dialog?.kind === 'walletConnect'} onClose={closeDialog} />
      <WalletConnectNotifier onOpen={openWalletConnect} />
      <AddAccountDialog
        open={dialog?.kind === 'addAccount'}
        walletId={dialog?.kind === 'addAccount' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <ReceiveDialog
        open={dialog?.kind === 'receive'}
        walletId={dialog?.kind === 'receive' ? dialog.walletId : undefined}
        onClose={closeDialog}
      />
      <SendDialog
        open={dialog?.kind === 'send'}
        accountId={dialog?.kind === 'send' ? dialog.accountId : undefined}
        onClose={closeDialog}
      />
    </ShellContext>
  );
}
