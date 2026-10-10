import type { ReactNode } from 'react';

import './elements.css';

/**
 * Hosts a legacy shell view inside a pane body. The views render their own
 * glass Panel; the stylesheet flattens that chrome so the pane frame is the
 * only edge and the panel header shrinks to a toolbar.
 */
export function Embedded({ children, padded = false }: { children: ReactNode; padded?: boolean }) {
  return <div className={`sw-embed${padded ? ' sw-embed-padded' : ''}`}>{children}</div>;
}
