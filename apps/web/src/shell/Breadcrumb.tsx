import type { Folder } from '@stackwallet/core-client';

import { directory } from '../store/persist.js';

/** Root maps to "no selection" (the overview); every other crumb selects its folder. */
export function Breadcrumb({ path, leaf }: { path: Folder[]; leaf?: string | undefined }) {
  return (
    <nav
      aria-label="Breadcrumb"
      className="flex flex-wrap items-center gap-1 text-[12px] text-faint"
    >
      {path.map((f, i) => (
        <span key={f.id} className="flex items-center gap-1">
          {i > 0 && <span aria-hidden>/</span>}
          <button
            type="button"
            onClick={() => directory.select(f.parentId === null ? null : f.id)}
            className="sw-pressable rounded-sw-sm px-1 text-muted"
          >
            {f.name}
          </button>
        </span>
      ))}
      {leaf && (
        <span className="flex items-center gap-1">
          <span aria-hidden>/</span>
          <span className="px-1 text-ink">{leaf}</span>
        </span>
      )}
    </nav>
  );
}
