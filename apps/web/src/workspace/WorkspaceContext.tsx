import { createContext, useContext, type RefObject } from 'react';

import type { ElementRegistry } from './elements/types.js';
import type { Pane } from './schema.js';
import type { Rect } from './store.js';

export type CoreState = 'online' | 'offline' | 'busy';

/** Shell-level services the workspace chrome calls into; the integrator provides them. */
export interface WorkspaceApi {
  registry: ElementRegistry;
  openSearch(): void;
  openCatalogue(anchor: HTMLElement): void;
  openSettings(paneId: string, anchor: HTMLElement): void;
  openVault(): void;
  coreLabel: string;
  coreState: CoreState;
}

export const WorkspaceContext = createContext<WorkspaceApi | null>(null);

export function useWorkspaceApi(): WorkspaceApi {
  const api = useContext(WorkspaceContext);
  if (!api) throw new Error('useWorkspaceApi must be used inside <WorkspaceContext.Provider>');
  return api;
}

/**
 * Mutable handles the canvas shares with its frames. Refs rather than values so a frame can
 * read the current pane list and scroll offset mid-gesture without anyone re-rendering.
 */
export interface CanvasHost {
  panesRef: RefObject<readonly Pane[]>;
  scrollRef: RefObject<{ x: number; y: number }>;
}

export const CanvasHostContext = createContext<CanvasHost>({
  panesRef: { current: [] },
  scrollRef: { current: { x: 0, y: 0 } },
});

export interface CanvasPoint {
  x: number;
  y: number;
}

/**
 * Canvas-space point of the last double-click on empty canvas. The catalogue reads it so the
 * new element lands under the pointer, then clears it; it lives outside React because the
 * catalogue is rendered by the shell, not by the canvas.
 */
export const canvasPointRef: { current: CanvasPoint | null } = { current: null };

/** The scroll container of the mounted canvas, if any. */
export const canvasElementRef: { current: HTMLElement | null } = { current: null };

/** Visible region of the canvas in canvas coordinates, for `WorkspaceStore.addPane`. */
export function getCanvasViewport(): Rect {
  const el = canvasElementRef.current;
  if (el) return { x: el.scrollLeft, y: el.scrollTop, w: el.clientWidth, h: el.clientHeight };
  if (typeof window === 'undefined') return { x: 0, y: 0, w: 1280, h: 800 };
  return { x: 0, y: 0, w: window.innerWidth, h: window.innerHeight };
}
