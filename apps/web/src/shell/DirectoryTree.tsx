import { Badge, Panel } from '@stackwallet/ui';

interface Node {
  id: string;
  name: string;
  kind: 'folder' | 'wallet';
  badges?: Array<{ label: string; tone?: 'neutral' | 'warm' | 'danger' | 'ok' }>;
  children?: Node[];
}

// Scaffold preview only. Phase 3 replaces this with rows from the store.
const PREVIEW: Node[] = [
  {
    id: 'cold',
    name: 'Cold',
    kind: 'folder',
    children: [
      { id: 'savings', name: 'Savings', kind: 'wallet', badges: [{ label: '2-of-2' }] },
      { id: 'btc-vault', name: 'BTC vault', kind: 'wallet', badges: [{ label: '3-of-5' }] },
    ],
  },
  {
    id: 'trading',
    name: 'Trading',
    kind: 'folder',
    children: [
      {
        id: 'agent-lanes',
        name: 'Agent lanes',
        kind: 'folder',
        children: [
          {
            id: 'sol-lane',
            name: 'Solana lane',
            kind: 'wallet',
            badges: [{ label: '2-of-3' }, { label: 'agent', tone: 'warm' }],
          },
          {
            id: 'evm-lane',
            name: 'EVM lane',
            kind: 'wallet',
            badges: [{ label: '2-of-3' }, { label: 'agent', tone: 'warm' }],
          },
        ],
      },
      { id: 'cosmos', name: 'Cosmos staking', kind: 'wallet', badges: [{ label: '2-of-3' }] },
    ],
  },
  {
    id: 'watch',
    name: 'Watch',
    kind: 'folder',
    children: [{ id: 'whales', name: 'Whales', kind: 'wallet', badges: [{ label: 'watch' }] }],
  },
];

function Row({ node, depth }: { node: Node; depth: number }) {
  return (
    <>
      <button
        type="button"
        className="sw-pressable flex w-full items-center gap-2 rounded-sw-sm px-2 py-1.5 text-left"
        style={{ paddingLeft: `${8 + depth * 14}px` }}
      >
        <span
          aria-hidden
          className={`text-[10px] ${node.kind === 'folder' ? 'text-muted' : 'text-faint'}`}
        >
          {node.kind === 'folder' ? '▸' : '·'}
        </span>
        <span className={`flex-1 truncate ${node.kind === 'folder' ? 'text-ink' : 'text-muted'}`}>
          {node.name}
        </span>
        {node.badges?.map((b) => (
          <Badge key={b.label} tone={b.tone ?? 'neutral'}>
            {b.label}
          </Badge>
        ))}
      </button>
      {node.children?.map((c) => (
        <Row key={c.id} node={c} depth={depth + 1} />
      ))}
    </>
  );
}

export function DirectoryTree() {
  return (
    <Panel as="nav" title="Directory" meta="preview" className="sw-enter">
      <div className="flex flex-col gap-0.5 p-2">
        {PREVIEW.map((n) => (
          <Row key={n.id} node={n} depth={0} />
        ))}
      </div>
    </Panel>
  );
}
