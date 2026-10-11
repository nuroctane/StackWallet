import { useEffect, useRef, useState } from 'react';
import { Kbd } from '@stackwallet/ui';

import { vault } from '../core/bridge.js';
import { useVaultView } from '../core/vault.js';
import { useWorkspace, workspace } from './persist.js';
import { canvasPointRef, useWorkspaceApi, type CoreState } from './WorkspaceContext.js';

export interface TopBarProps {
  /** Shown as pressed on the activity button; omit both to hide the button. */
  trayOpen?: boolean | undefined;
  onToggleTray?: (() => void) | undefined;
}

const coreDot: Record<CoreState, string> = {
  online: 'bg-ok',
  busy: 'bg-warm',
  offline: 'bg-danger',
};

const ghost =
  'sw-pressable inline-flex h-7 items-center gap-1.5 rounded-sw-sm border border-transparent px-2 text-[12px] lowercase text-muted';

export function TopBar({ trayOpen, onToggleTray }: TopBarProps) {
  const api = useWorkspaceApi();
  const { locked } = useWorkspace();

  return (
    <header className="flex h-10 flex-none items-center gap-2 border-b border-edge bg-paper px-3 font-mono text-[12px] lowercase">
      <span className="mr-1 font-semibold tracking-[-0.01em] text-ink">stackwallet</span>

      <LayoutLockButton locked={locked} />

      <button
        type="button"
        className="sw-pressable flex h-7 w-[260px] items-center justify-between rounded-sw-sm border border-edge bg-surface px-2 text-left text-faint"
        aria-label="search"
        title="search (/)"
        onClick={() => api.openSearch()}
      >
        <span>search</span>
        <Kbd>/</Kbd>
      </button>

      <button
        type="button"
        className={ghost}
        aria-haspopup="dialog"
        title="add element (ctrl+shift+e)"
        onClick={(e) => {
          // A click here means "next free slot", not the last double-clicked spot.
          canvasPointRef.current = null;
          api.openCatalogue(e.currentTarget);
        }}
      >
        elements
        <span aria-hidden className="text-faint">
          ▾
        </span>
      </button>

      <button
        type="button"
        className={ghost}
        aria-haspopup="dialog"
        title="theme studio (t)"
        onClick={() => api.openTheme()}
      >
        <PaletteIcon />
        theme
      </button>

      <VaultChip onOpen={() => api.openVault()} />

      <span className="inline-flex items-center gap-1.5 px-1 text-[11px] text-faint">
        <span
          aria-hidden
          className={`inline-block h-1.5 w-1.5 rounded-full ${coreDot[api.coreState]}`}
        />
        <span title={`core ${api.coreState}`}>{api.coreLabel}</span>
      </span>

      {onToggleTray && (
        <button
          type="button"
          className={`${ghost} ${trayOpen ? 'text-ink' : ''}`}
          aria-pressed={trayOpen ?? false}
          aria-label="activity"
          title="activity (ctrl+.)"
          onClick={onToggleTray}
        >
          <TrayIcon />
        </button>
      )}
    </header>
  );
}

/**
 * Vault state at a glance, pushed to the right edge. Warm while a passphrase is
 * being stretched, red only when the core itself is missing, since that is the
 * one state the user cannot fix from here.
 */
function VaultChip({ onOpen }: { onOpen: () => void }) {
  const { status, busy } = useVaultView(vault);
  const label =
    status.kind === 'loading'
      ? 'vault'
      : status.kind === 'unavailable'
        ? 'vault · no core'
        : status.kind === 'absent'
          ? 'create vault'
          : status.kind === 'corrupt'
            ? 'vault · unreadable'
            : status.kind === 'locked'
              ? 'vault · locked'
              : 'vault · unlocked';
  const dot = busy
    ? 'bg-warm'
    : status.kind === 'unlocked'
      ? 'bg-ok'
      : status.kind === 'unavailable' || status.kind === 'corrupt'
        ? 'bg-danger'
        : 'bg-faint';
  return (
    <button
      type="button"
      className={`${ghost} ml-auto ${status.kind === 'unlocked' ? 'text-ink' : ''}`}
      aria-haspopup="dialog"
      title={status.kind === 'locked' ? 'unlock vault' : 'vault'}
      disabled={status.kind === 'loading'}
      onClick={onOpen}
    >
      <PadlockIcon locked={status.kind !== 'unlocked'} />
      <span>{label}</span>
      <span aria-hidden className={`inline-block h-1.5 w-1.5 rounded-full ${dot}`} />
    </button>
  );
}

/**
 * State lives in the icon and the tint (closed and filled with the accent while
 * locked, open and plain while unlocked); the hint names the action a press
 * will take. Each toggle replays a short latch so the press registers.
 */
function LayoutLockButton({ locked }: { locked: boolean }) {
  const first = useRef(true);
  const [latch, setLatch] = useState(0);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    setLatch((n) => n + 1);
  }, [locked]);
  const action = locked ? 'unlock layout' : 'lock layout';
  return (
    <button
      type="button"
      className={`sw-pressable sw-lock-btn inline-flex h-7 items-center gap-1.5 rounded-sw-sm border px-2 text-[12px] lowercase ${
        locked ? 'border-warm/60 bg-warm/14 text-warm' : 'border-transparent text-muted'
      }`}
      data-locked={locked ? '' : undefined}
      aria-pressed={locked}
      aria-label={action}
      title={action}
      onClick={() => workspace.toggleLock()}
    >
      <span key={latch} className={latch > 0 ? 'sw-latch inline-flex' : 'inline-flex'}>
        <LockStateIcon locked={locked} />
      </span>
      layout
    </button>
  );
}

function LockStateIcon({ locked }: { locked: boolean }) {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className="sw-lock-icon"
      data-open={locked ? undefined : ''}
    >
      <g className="sw-shackle">
        <path d="M4 5.5V4a2 2 0 0 1 4 0" />
        <path className="sw-shackle-right" d="M8 4v1.5" />
      </g>
      <rect className="sw-lock-body" x="2.5" y="5.5" width="7" height="5" rx="1" />
    </svg>
  );
}

const ICON = {
  width: 12,
  height: 12,
  viewBox: '0 0 12 12',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
};

function PadlockIcon({ locked }: { locked: boolean }) {
  return (
    <svg {...ICON}>
      <rect x="2.5" y="5.5" width="7" height="5" rx="1" />
      <path d={locked ? 'M4 5.5V4a2 2 0 0 1 4 0v1.5' : 'M4 5.5V4a2 2 0 0 1 4 0'} />
    </svg>
  );
}

function PaletteIcon() {
  return (
    <svg {...ICON}>
      <path d="M6 1.5a4.5 4.5 0 1 0 0 9c.8 0 1-.6.7-1.2-.4-.7 0-1.5.8-1.5h1.3A1.7 1.7 0 0 0 10.5 6 4.5 4.5 0 0 0 6 1.5z" />
      <circle cx="3.8" cy="5.2" r=".5" />
      <circle cx="5.8" cy="3.6" r=".5" />
      <circle cx="8" cy="4.4" r=".5" />
    </svg>
  );
}

function TrayIcon() {
  return (
    <svg {...ICON}>
      <path d="M1.5 7h2.5l1 1.5h2l1-1.5h2.5M1.5 7v2.5a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1V7M1.5 7l1.5-4h6l1.5 4" />
    </svg>
  );
}
