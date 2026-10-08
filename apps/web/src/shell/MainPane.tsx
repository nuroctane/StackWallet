import { Badge, Button, Panel } from '@stackwallet/ui';

const PHASES = [
  ['0', 'Scaffold', 'now'],
  ['1', 'Core vault + TSS', ''],
  ['2', 'Transport', ''],
  ['3', 'Directory + EVM', ''],
  ['4', 'Bitcoin, Solana, Cosmos', ''],
  ['5', 'Agent runtime', ''],
  ['6', 'Automations', ''],
  ['7', 'Markets', ''],
  ['8', 'Desktop packaging', ''],
] as const;

export function MainPane() {
  return (
    <Panel title="StackWallet" meta="every chain · your devices · your rules" className="sw-enter">
      <div className="flex flex-col gap-6 p-6">
        <div className="flex flex-col gap-2">
          <h1 className="text-[22px] font-semibold tracking-[-0.01em]">Scaffold is up.</h1>
          <p className="max-w-[60ch] text-muted">
            This shell renders the three-column layout from the design system and talks to the Rust
            core through <code className="text-ink">@stackwallet/core-client</code>. Nothing here
            holds a key yet. Phase 1 adds the vault and threshold signing.
          </p>
        </div>

        <section className="sw-elevated">
          <header className="border-b border-edge px-4 py-2.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted">
            Phases
          </header>
          <ol className="divide-y divide-edge">
            {PHASES.map(([n, name, status]) => (
              <li key={n} className="flex items-center gap-4 px-4 py-2.5">
                <span className="w-4 text-faint">{n}</span>
                <span className="flex-1">{name}</span>
                {status && <Badge tone="warm">{status}</Badge>}
              </li>
            ))}
          </ol>
        </section>

        <div className="flex gap-2">
          <Button variant="primary" disabled>
            Create wallet
          </Button>
          <Button disabled>Pair device</Button>
          <Button variant="ghost" disabled>
            Open agent console
          </Button>
        </div>
      </div>
    </Panel>
  );
}
