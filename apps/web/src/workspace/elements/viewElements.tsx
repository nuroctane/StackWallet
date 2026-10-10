import { Select } from '@stackwallet/ui';

import { ApprovalRailBody } from '../../shell/ApprovalRail.js';
import { DirectoryTree } from '../../shell/DirectoryTree.js';
import { DevicesView } from '../../shell/views/DevicesView.js';
import { FolderView } from '../../shell/views/FolderView.js';
import { NetworkView } from '../../shell/views/NetworkView.js';
import { Overview } from '../../shell/views/Overview.js';
import { WalletView } from '../../shell/views/WalletView.js';
import { useDirectory } from '../../store/persist.js';
import { pathTo } from '../../store/selectors.js';
import { Embedded } from './embedded.js';
import type { ElementBodyProps } from './types.js';

export function OverviewElement() {
  const state = useDirectory();
  return (
    <div className="sw-embed-scroll">
      <Overview state={state} />
    </div>
  );
}

export function DirectoryElement() {
  return (
    <Embedded>
      <DirectoryTree />
    </Embedded>
  );
}

export function DevicesElement() {
  return (
    <div className="sw-embed-scroll">
      <DevicesView />
    </div>
  );
}

export function NetworkElement() {
  const state = useDirectory();
  return (
    <div className="sw-embed-scroll">
      <NetworkView state={state} />
    </div>
  );
}

export function ApprovalsElement() {
  return (
    <div className="sw-embed-scroll">
      <ApprovalRailBody />
    </div>
  );
}

export function WalletElement({ pane, setProps }: ElementBodyProps) {
  const state = useDirectory();
  const walletId = typeof pane.props['walletId'] === 'string' ? pane.props['walletId'] : '';
  const wallet = state.wallets.find((w) => w.id === walletId);
  if (!wallet) {
    return (
      <Picker
        label="wallet"
        empty="No wallets yet. Add a watch wallet from the directory."
        options={state.wallets.map((w) => ({
          value: w.id,
          label: `${pathTo(state, w.id)
            .slice(1)
            .map((f) => f.name)
            .join(' / ')}${w.folderId ? ' / ' : ''}${w.name}`,
        }))}
        onPick={(id) => setProps({ walletId: id })}
      />
    );
  }
  return (
    <div className="sw-embed-scroll">
      <WalletView key={wallet.id} state={state} wallet={wallet} />
    </div>
  );
}

export function FolderElement({ pane, setProps }: ElementBodyProps) {
  const state = useDirectory();
  const folderId = typeof pane.props['folderId'] === 'string' ? pane.props['folderId'] : '';
  const folder = state.folders.find((f) => f.id === folderId);
  if (!folder) {
    return (
      <Picker
        label="folder"
        empty="No folders yet."
        options={state.folders
          .filter((f) => f.parentId !== null)
          .map((f) => ({
            value: f.id,
            label: pathTo(state, f.id)
              .slice(1)
              .map((p) => p.name)
              .join(' / '),
          }))}
        onPick={(id) => setProps({ folderId: id })}
      />
    );
  }
  return (
    <div className="sw-embed-scroll">
      <FolderView key={folder.id} state={state} folder={folder} />
    </div>
  );
}

function Picker({
  label,
  empty,
  options,
  onPick,
}: {
  label: string;
  empty: string;
  options: { value: string; label: string }[];
  onPick: (id: string) => void;
}) {
  if (options.length === 0) {
    return <p className="p-4 text-[12px] text-faint">{empty}</p>;
  }
  return (
    <div className="flex flex-col gap-2 p-4">
      <span className="text-[11px] text-faint">pick a {label} for this element</span>
      <Select
        aria-label={`Pick ${label}`}
        defaultValue=""
        onChange={(e) => {
          if (e.target.value) onPick(e.target.value);
        }}
      >
        <option value="" disabled>
          {label}…
        </option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}
