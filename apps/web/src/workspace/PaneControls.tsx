import { workspace } from './persist.js';
import type { Pane } from './schema.js';

const ICON = {
  width: 12,
  height: 12,
  viewBox: '0 0 12 12',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.2,
  strokeLinecap: 'round' as const,
  'aria-hidden': true,
};

export function PaneCollapseToggle({ pane }: { pane: Pane }) {
  const collapsed = pane.collapsed === true;
  return (
    <button
      type="button"
      className="sw-pressable sw-pane-icon-btn sw-pane-collapse-toggle"
      aria-label={collapsed ? 'expand element' : 'collapse element'}
      aria-expanded={!collapsed}
      title={collapsed ? 'expand element (c)' : 'collapse element (c)'}
      onClick={() => workspace.toggleCollapsed(pane.id)}
    >
      <span aria-hidden>&gt;</span>
    </button>
  );
}

export function PaneControls({ pane }: { pane: Pane }) {
  const fullscreen = pane.fullscreen === true;
  return (
    <>
      <button
        type="button"
        className="sw-pressable sw-pane-icon-btn"
        aria-label={fullscreen ? 'exit fullscreen' : 'fullscreen'}
        aria-pressed={fullscreen}
        title={fullscreen ? 'exit fullscreen (f)' : 'fullscreen (f)'}
        onClick={() => workspace.toggleFullscreen(pane.id)}
      >
        <svg {...ICON}>
          <path
            d={
              fullscreen
                ? 'M4 1v3H1M8 1v3h3M11 8H8v3M1 8h3v3'
                : 'M1 4V1h3M8 1h3v3M11 8v3H8M4 11H1V8'
            }
          />
        </svg>
      </button>
    </>
  );
}
