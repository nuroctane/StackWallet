import { Button, Panel } from '@stackwallet/ui';

import { useDirectory } from '../store/persist.js';
import { findNode } from '../store/selectors.js';
import { MOD_KEY, useShell } from './ShellContext.js';
import { DevicesView } from './views/DevicesView.js';
import { FolderView } from './views/FolderView.js';
import { NetworkView } from './views/NetworkView.js';
import { Overview } from './views/Overview.js';
import { WalletView } from './views/WalletView.js';

export function MainPane() {
  const state = useDirectory();
  const shell = useShell();
  const node = findNode(state, state.ui.selectedId);
  const isRoot = node?.kind === 'folder' && node.folder.parentId === null;

  const leading =
    shell.layout === 'one' ? (
      <Button
        size="sm"
        variant="ghost"
        className="-ml-2 px-1.5"
        aria-label="Open directory"
        aria-expanded={shell.treeOpen}
        onClick={shell.toggleTree}
      >
        <MenuGlyph />
      </Button>
    ) : undefined;

  const railButton =
    shell.layout !== 'three' ? (
      <Button
        size="sm"
        variant="ghost"
        className="-mr-2"
        aria-expanded={shell.railOpen}
        title={`Approvals (${MOD_KEY} .)`}
        onClick={shell.toggleRail}
      >
        approvals
      </Button>
    ) : null;

  const withRail = (meta: string) => (
    <span className="flex min-w-0 items-center gap-2">
      <span className="min-w-0 truncate">{meta}</span>
      {railButton && <span className="shrink-0">{railButton}</span>}
    </span>
  );

  if (shell.route.kind === 'network') {
    return (
      <Panel
        title="Network"
        meta={withRail('rpc endpoints')}
        leading={leading}
        className="sw-enter min-w-0"
      >
        <NetworkView state={state} />
      </Panel>
    );
  }
  if (shell.route.kind === 'devices') {
    return (
      <Panel
        title="Devices"
        meta={withRail('pairing · trust')}
        leading={leading}
        className="sw-enter min-w-0"
      >
        <DevicesView />
      </Panel>
    );
  }
  if (!node || isRoot) {
    return (
      <Panel
        title="Overview"
        meta={withRail('every chain · your devices · your rules')}
        leading={leading}
        className="sw-enter min-w-0"
      >
        <Overview state={state} />
      </Panel>
    );
  }
  if (node.kind === 'folder') {
    return (
      <Panel
        title="Folder"
        meta={withRail(node.folder.name)}
        leading={leading}
        className="sw-enter min-w-0"
      >
        <FolderView key={node.folder.id} state={state} folder={node.folder} />
      </Panel>
    );
  }
  return (
    <Panel
      title="Wallet"
      meta={withRail(node.wallet.kind)}
      leading={leading}
      className="sw-enter min-w-0"
    >
      <WalletView key={node.wallet.id} state={state} wallet={node.wallet} />
    </Panel>
  );
}

function MenuGlyph() {
  return (
    <svg viewBox="0 0 14 14" className="h-3.5 w-3.5" aria-hidden>
      <path d="M2 3.5h10M2 7h10M2 10.5h10" stroke="currentColor" strokeWidth="1.25" />
    </svg>
  );
}
