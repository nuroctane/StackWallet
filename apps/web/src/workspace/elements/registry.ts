import { directory } from '../../store/persist.js';
import { pathTo } from '../../store/selectors.js';
import { elementDefaults } from '../defaults.js';
import { totalsLedger } from '../ledger.js';
import type { ElementKind, Pane } from '../schema.js';
import { HoldingsElement } from './HoldingsElement.js';
import { LedgerElement, RANGES } from './LedgerElement.js';
import { TerrainElement } from './TerrainElement.js';
import type { ElementDefinition, ElementRegistry } from './types.js';
import {
  ApprovalsElement,
  DevicesElement,
  DirectoryElement,
  FolderElement,
  NetworkElement,
  OverviewElement,
  WalletElement,
} from './viewElements.js';

function walletName(pane: Pane): string | undefined {
  const id = pane.props['walletId'];
  if (typeof id !== 'string') return undefined;
  return directory.getSnapshot().wallets.find((w) => w.id === id)?.name;
}

function folderName(pane: Pane): string | undefined {
  const id = pane.props['folderId'];
  if (typeof id !== 'string') return undefined;
  return directory.getSnapshot().folders.find((f) => f.id === id)?.name;
}

const def = (d: ElementDefinition): ElementDefinition => d;

export const registry: ElementRegistry = {
  overview: def({
    kind: 'overview',
    title: 'overview',
    hint: 'counts, totals, chains in use',
    defaultSize: elementDefaults.overview,
    body: OverviewElement,
  }),
  directory: def({
    kind: 'directory',
    title: 'directory',
    hint: 'folders and wallets',
    defaultSize: elementDefaults.directory,
    minSize: { w: 240, h: 200 },
    body: DirectoryElement,
  }),
  wallet: def({
    kind: 'wallet',
    title: 'wallet',
    hint: 'one wallet: accounts, balances, tags',
    defaultSize: elementDefaults.wallet,
    titleFor: (p) => walletName(p) ?? 'wallet',
    scope: (p) => {
      const state = directory.getSnapshot();
      const id = p.props['walletId'];
      const w = typeof id === 'string' ? state.wallets.find((x) => x.id === id) : undefined;
      if (!w) return [];
      const path = pathTo(state, w.id)
        .slice(1)
        .map((f) => f.name)
        .join(' / ');
      return [{ label: w.kind }, ...(path ? [{ label: path }] : [])];
    },
    settings: [
      {
        key: 'walletId',
        label: 'wallet',
        kind: 'select',
        options: () => directory.getSnapshot().wallets.map((w) => ({ value: w.id, label: w.name })),
      },
    ],
    body: WalletElement,
  }),
  folder: def({
    kind: 'folder',
    title: 'folder',
    hint: 'one folder: wallets inside, totals',
    defaultSize: elementDefaults.folder,
    titleFor: (p) => folderName(p) ?? 'folder',
    settings: [
      {
        key: 'folderId',
        label: 'folder',
        kind: 'select',
        options: () =>
          directory
            .getSnapshot()
            .folders.filter((f) => f.parentId !== null)
            .map((f) => ({ value: f.id, label: f.name })),
      },
    ],
    body: FolderElement,
  }),
  holdings: def({
    kind: 'holdings',
    title: 'holdings',
    hint: 'every account, dense and live',
    defaultSize: elementDefaults.holdings,
    minSize: { w: 320, h: 140 },
    defaultProps: { hideZero: false },
    scope: (p) => (p.props['hideZero'] === true ? [{ label: 'non-zero' }] : []),
    settings: [
      { key: 'hideZero', label: 'hide zero balances', kind: 'toggle' },
      {
        key: 'chainId',
        label: 'chain',
        help: 'limit the table to one chain',
        kind: 'select',
        options: () => {
          const ids = [...new Set(directory.getSnapshot().accounts.map((a) => a.chainId))].sort();
          return [{ value: '', label: 'all' }, ...ids.map((id) => ({ value: id, label: id }))];
        },
      },
    ],
    body: HoldingsElement,
  }),
  terrain: def({
    kind: 'terrain',
    title: 'activity',
    hint: 'isometric terrain of local events',
    defaultSize: elementDefaults.terrain,
    defaultProps: { weeks: 26 },
    scope: (p) => [{ label: `${p.props['weeks'] ?? 26}w` }],
    settings: [{ key: 'weeks', label: 'weeks', kind: 'number', min: 4, max: 57, step: 1 }],
    body: TerrainElement,
  }),
  ledger: def({
    kind: 'ledger',
    title: 'ledger',
    hint: 'native totals over time',
    defaultSize: elementDefaults.ledger,
    defaultProps: { range: '30d' },
    scope: (p) => [{ label: String(p.props['range'] ?? '30d'), tone: 'warm' }],
    settings: [
      {
        key: 'assetRef',
        label: 'asset',
        kind: 'select',
        options: () =>
          totalsLedger.assets().map((a) => ({ value: a.assetRef, label: a.symbol ?? a.assetRef })),
      },
      {
        key: 'range',
        label: 'range',
        kind: 'select',
        options: Object.keys(RANGES).map((r) => ({ value: r, label: r })),
      },
    ],
    body: LedgerElement,
  }),
  approvals: def({
    kind: 'approvals',
    title: 'approvals',
    hint: 'pending signatures, parties, policy',
    defaultSize: elementDefaults.approvals,
    body: ApprovalsElement,
  }),
  devices: def({
    kind: 'devices',
    title: 'devices',
    hint: 'pairing and trust',
    defaultSize: elementDefaults.devices,
    body: DevicesElement,
  }),
  network: def({
    kind: 'network',
    title: 'network',
    hint: 'rpc endpoints per chain',
    defaultSize: elementDefaults.network,
    body: NetworkElement,
  }),
};

export const ELEMENT_KINDS = Object.keys(registry) as ElementKind[];
