import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { applyTheme } from '@stackwallet/ui';

import { App } from './App.js';
import { resolveForLayout, themeStore } from './store/theme.js';
import { workspace } from './workspace/persist.js';
import { ErrorBoundary } from './shell/ErrorBoundary.js';
import './app.css';

// Paint the saved theme before the first render so a light theme never flashes dark.
applyTheme(resolveForLayout(themeStore.getSnapshot(), workspace.getSnapshot().activeId));

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');

createRoot(root).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
