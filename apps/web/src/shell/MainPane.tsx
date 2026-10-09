import { Panel } from '@stackwallet/ui';

import { useDirectory } from '../store/persist.js';
import { findNode } from '../store/selectors.js';
import { FolderView } from './views/FolderView.js';
import { Overview } from './views/Overview.js';
import { WalletView } from './views/WalletView.js';

export function MainPane() {
  const state = useDirectory();
  const node = findNode(state, state.ui.selectedId);
  const isRoot = node?.kind === 'folder' && node.folder.parentId === null;

  if (!node || isRoot) {
    return (
      <Panel title="Overview" meta="every chain · your devices · your rules" className="sw-enter">
        <Overview state={state} />
      </Panel>
    );
  }
  if (node.kind === 'folder') {
    return (
      <Panel title="Folder" meta={node.folder.name} className="sw-enter">
        <FolderView key={node.folder.id} state={state} folder={node.folder} />
      </Panel>
    );
  }
  return (
    <Panel title="Wallet" meta={node.wallet.kind} className="sw-enter">
      <WalletView key={node.wallet.id} state={state} wallet={node.wallet} />
    </Panel>
  );
}
