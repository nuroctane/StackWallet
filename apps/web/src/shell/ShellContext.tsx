import { createContext, useContext } from 'react';

export type ShellDialog =
  | { kind: 'folder'; parentId?: string }
  | { kind: 'watch'; folderId?: string }
  | { kind: 'connect'; folderId?: string }
  | { kind: 'deleteWallet'; walletId: string }
  | { kind: 'deleteFolder'; folderId: string }
  | { kind: 'move'; walletId: string }
  | { kind: 'vault' }
  | { kind: 'theme' }
  | { kind: 'policies' }
  | { kind: 'tokens' }
  | { kind: 'newWallet'; folderId?: string }
  | { kind: 'reveal'; walletId: string }
  | { kind: 'transferSet'; folderId: string }
  | { kind: 'transferWallet'; walletId: string }
  | { kind: 'receive'; walletId: string }
  | { kind: 'addAccount'; walletId: string; chainId?: string }
  | { kind: 'contacts' }
  | { kind: 'walletConnect' }
  | { kind: 'signMessage'; walletId: string }
  | { kind: 'swap'; walletId: string }
  | { kind: 'stake'; walletId: string }
  | { kind: 'hardwareWallet'; folderId?: string }
  | { kind: 'threshold'; target: import('./ThresholdDialog.js').ThresholdTarget }
  | ({ kind: 'sendNft' } & import('./NftSendDialog.js').NftSendTarget)
  | { kind: 'exportKey'; scope: 'folder' | 'wallet'; id: string }
  | { kind: 'importSet' }
  | { kind: 'send'; accountId?: string; walletId?: string };

export type UiRoute = { kind: 'directory' } | { kind: 'network' } | { kind: 'devices' };

/**
 * `three`: tree, main and rail side by side. `two`: the rail is a sheet.
 * `one`: the tree is a drawer as well.
 */
export type ShellLayout = 'three' | 'two' | 'one';

/** Label for the primary modifier in shortcut hints. */
export const MOD_KEY =
  typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl';

export interface ShellApi {
  layout: ShellLayout;
  railOpen: boolean;
  toggleRail: () => void;
  treeOpen: boolean;
  toggleTree: () => void;
  closeTree: () => void;
  route: UiRoute;
  navigate: (route: UiRoute) => void;
  openDialog: (dialog: ShellDialog) => void;
  openPalette: () => void;
  refreshBalances: () => void;
}

const noop: ShellApi = {
  layout: 'three',
  railOpen: true,
  toggleRail: () => undefined,
  treeOpen: false,
  toggleTree: () => undefined,
  closeTree: () => undefined,
  route: { kind: 'directory' },
  navigate: () => undefined,
  openDialog: () => undefined,
  openPalette: () => undefined,
  refreshBalances: () => undefined,
};

export const ShellContext = createContext<ShellApi>(noop);

export function useShell(): ShellApi {
  return useContext(ShellContext);
}

/** True when the key event originated in a text control or an open dialog, where shortcuts must not fire. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  return target.closest('dialog[open]') !== null;
}
