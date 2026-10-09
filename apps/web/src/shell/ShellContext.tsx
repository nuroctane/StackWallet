import { createContext, useContext } from 'react';

export type ShellDialog =
  | { kind: 'folder'; parentId?: string }
  | { kind: 'watch'; folderId?: string }
  | { kind: 'deleteWallet'; walletId: string }
  | { kind: 'deleteFolder'; folderId: string };

export interface ShellApi {
  railOpen: boolean;
  toggleRail: () => void;
  openDialog: (dialog: ShellDialog) => void;
  openPalette: () => void;
  refreshBalances: () => void;
}

const noop: ShellApi = {
  railOpen: true,
  toggleRail: () => undefined,
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
