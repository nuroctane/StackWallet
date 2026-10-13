import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { PaneCollapseToggle, PaneControls } from './PaneControls.js';
import type { Pane } from './schema.js';

const pane: Pane = { id: 'p', kind: 'overview', props: {}, x: 0, y: 0, w: 400, h: 320, z: 0 };

describe('shared pane controls', () => {
  it('renders distinct fullscreen states and explicit pressed values', () => {
    const normal = renderToStaticMarkup(<PaneControls pane={pane} />);
    const fullscreen = renderToStaticMarkup(<PaneControls pane={{ ...pane, fullscreen: true }} />);
    expect(normal).toContain('aria-label="fullscreen" aria-pressed="false"');
    expect(fullscreen).toContain('aria-label="exit fullscreen" aria-pressed="true"');
    expect(normal).toContain('M1 4V1h3M8 1h3v3M11 8v3H8M4 11H1V8');
    expect(fullscreen).toContain('M4 1v3H1M8 1v3h3M11 8H8v3M1 8h3v3');
    expect(normal).not.toContain('collapse element');
  });

  it('labels collapsed elements as expandable', () => {
    const expanded = renderToStaticMarkup(<PaneCollapseToggle pane={pane} />);
    const collapsed = renderToStaticMarkup(
      <PaneCollapseToggle pane={{ ...pane, collapsed: true }} />,
    );
    expect(expanded).toContain('aria-label="collapse element" aria-expanded="true"');
    expect(collapsed).toContain('aria-label="expand element" aria-expanded="false"');
  });
});
