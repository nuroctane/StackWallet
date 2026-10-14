import { directory } from '../../store/persist.js';
import { pathTo } from '../../store/selectors.js';
import { elementDefaults } from '../defaults.js';
import { totalsLedger } from '../ledger.js';
import type { ElementKind, Pane } from '../schema.js';
import { HoldingsElement } from './HoldingsElement.js';
import { LedgerElement, RANGES } from './LedgerElement.js';
import { ActivityLogElement } from './ActivityLogElement.js';
import { TerrainElement } from './TerrainElement.js';
import { TransactionsElement } from './TransactionsElement.js';
import { AgentElement } from './AgentElement.js';
import { AutomationsElement } from './AutomationsElement.js';
import { AlertsElement } from './market/AlertsElement.js';
import { CandlesElement } from './market/CandlesElement.js';
import { PortfolioElement } from './market/PortfolioElement.js';
import { WatchlistElement } from './market/WatchlistElement.js';
import type { ElementDefinition, ElementRegistry } from './types.js';
import {
  ApprovalsElement,
  CollectiblesElement,
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
    minSize: { w: 240, h: 140 },
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
    title: 'workspace activity',
    hint: 'Local app events by day: wallet edits, device changes, layout edits and balance refreshes. Drag to turn and tilt; pinch to zoom. No on-chain transaction counts.',
    defaultSize: elementDefaults.terrain,
    defaultProps: { weeks: 26, view: 'terrain' },
    scope: (p) => [{ label: `${p.props['weeks'] ?? 26}w` }],
    settings: [
      { key: 'weeks', label: 'weeks', kind: 'number', min: 4, max: 57, step: 1 },
      {
        key: 'view',
        label: 'view',
        kind: 'select',
        options: [
          { value: 'terrain', label: 'Terrain' },
          { value: 'log', label: 'Event log' },
        ],
      },
    ],
    body: TerrainElement,
  }),
  activityLog: def({
    kind: 'activityLog',
    title: 'workspace event log',
    hint: 'Timestamped local instance events matching the workspace activity terrain: wallet directory, balances, devices, layouts, ceremonies and signing-request events. Includes readable daily totals for older history.',
    defaultSize: elementDefaults.activityLog,
    body: ActivityLogElement,
  }),
  ledger: def({
    kind: 'ledger',
    title: 'balance history',
    hint: 'Native asset totals over time, recorded on this device after complete balance refreshes. Choose an asset and range in settings.',
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
  transactions: def({
    kind: 'transactions',
    title: 'transaction history',
    hint: 'Wallet transactions across EVM L1s, L2s, sidechains and appchains, Bitcoin-family networks, Solana and Cosmos. Local signing records plus paginated public-chain reads; source and coverage are always shown.',
    defaultSize: elementDefaults.transactions,
    defaultProps: { walletId: '' },
    settings: [
      {
        key: 'walletId',
        label: 'wallet',
        kind: 'select',
        options: () => [
          { value: '', label: 'all wallets' },
          ...directory.getSnapshot().wallets.map((w) => ({ value: w.id, label: w.name })),
        ],
      },
    ],
    body: TransactionsElement,
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
  collectibles: def({
    kind: 'collectibles',
    title: 'collectibles',
    hint: 'nfts on every chain with a keyless indexer',
    defaultSize: elementDefaults.collectibles,
    minSize: { w: 280, h: 200 },
    defaultProps: { walletId: '' },
    titleFor: (p) => {
      const name = walletName(p);
      return name ? `collectibles · ${name}` : 'collectibles';
    },
    settings: [
      {
        key: 'walletId',
        label: 'wallet',
        kind: 'select',
        options: () => [
          { value: '', label: 'all wallets' },
          ...directory.getSnapshot().wallets.map((w) => ({ value: w.id, label: w.name })),
        ],
      },
    ],
    body: CollectiblesElement,
  }),
  agent: def({
    kind: 'agent',
    title: 'agent',
    hint: 'bring-your-own-key model; reads granted wallets, proposes into the approval queue',
    defaultSize: elementDefaults.agent,
    minSize: { w: 320, h: 280 },
    defaultProps: { provider: 'anthropic', model: '' },
    body: AgentElement,
  }),
  automations: def({
    kind: 'automations',
    title: 'automations',
    hint: 'scheduled and balance-triggered transfers, each one a proposal you approve',
    defaultSize: elementDefaults.automations,
    minSize: { w: 320, h: 240 },
    body: AutomationsElement,
  }),
  watchlist: def({
    kind: 'watchlist',
    title: 'watchlist',
    hint: 'prices and 24h change for held and watched coins, with sources shown',
    defaultSize: elementDefaults.watchlist,
    minSize: { w: 360, h: 200 },
    body: WatchlistElement,
  }),
  candles: def({
    kind: 'candles',
    title: 'candles',
    hint: 'OHLC chart for a coin from CoinGecko',
    defaultSize: elementDefaults.candles,
    minSize: { w: 320, h: 240 },
    defaultProps: { coinId: '', days: 30 },
    titleFor: (p) =>
      typeof p.props['coinId'] === 'string' && p.props['coinId']
        ? `candles · ${p.props['coinId']}`
        : 'candles',
    scope: (p) => {
      const d = Number(p.props['days'] ?? 30);
      return [{ label: d === 1 ? '24h' : `${d}d`, tone: 'warm' }];
    },
    body: CandlesElement,
  }),
  portfolio: def({
    kind: 'portfolio',
    title: 'portfolio',
    hint: 'USD value over time and allocation, computed on this device',
    defaultSize: elementDefaults.portfolio,
    minSize: { w: 320, h: 280 },
    defaultProps: { days: 30 },
    scope: (p) => {
      const d = Number(p.props['days'] ?? 30);
      return [{ label: d === 1 ? '24h' : `${d}d`, tone: 'warm' }];
    },
    body: PortfolioElement,
  }),
  alerts: def({
    kind: 'alerts',
    title: 'price alerts',
    hint: 'notify when a coin crosses a price or 24h change; never signs',
    defaultSize: elementDefaults.alerts,
    minSize: { w: 320, h: 240 },
    body: AlertsElement,
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
