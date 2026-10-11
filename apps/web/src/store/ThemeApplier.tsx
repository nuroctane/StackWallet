import { useEffect } from 'react';
import { applyTheme } from '@stackwallet/ui';

import { useWorkspace } from '../workspace/persist.js';
import { resolveForLayout, themeStore, useThemeState } from './theme.js';

/** Paints the resolved theme for the active layout onto the document root. */
export function ThemeApplier() {
  const theme = useThemeState();
  const ws = useWorkspace();

  useEffect(() => {
    applyTheme(resolveForLayout(theme, ws.activeId));
  }, [theme, ws.activeId]);

  const liveIds = ws.layouts.map((l) => l.id).join('|');
  useEffect(() => {
    themeStore.pruneLayouts(liveIds.split('|'));
  }, [liveIds]);

  return null;
}
