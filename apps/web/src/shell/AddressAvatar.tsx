import { useMemo } from 'react';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * A mirrored 5×5 mark derived from an address, so the same address always
 * looks the same across wallets, history and signing screens, and a one-
 * character difference looks different. Drawn in ink and gray only: the mark
 * identifies, it does not decorate.
 */
export function avatarCells(address: string): { on: boolean[]; shade: number } {
  const key = /^0x[0-9a-f]{40}$/i.test(address) ? address.toLowerCase() : address;
  const h = sha256(new TextEncoder().encode(key));
  const on: boolean[] = [];
  for (let row = 0; row < 5; row++)
    for (let col = 0; col < 5; col++) {
      const c = col < 3 ? col : 4 - col;
      on.push(((h[row * 3 + c] as number) & 1) === 1);
    }
  return { on, shade: (h[20] as number) % 3 };
}

const SHADES = ['var(--sw-ink)', 'var(--sw-muted)', 'var(--sw-faint)'];

export function AddressAvatar({
  address,
  size = 20,
  className = '',
}: {
  address: string;
  size?: number;
  className?: string;
}) {
  const { on, shade } = useMemo(() => avatarCells(address), [address]);
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 5 5"
      aria-hidden="true"
      className={`shrink-0 rounded-[4px] border border-edge ${className}`}
      shapeRendering="crispEdges"
    >
      {on.map((v, i) =>
        v ? (
          <rect key={i} x={i % 5} y={Math.floor(i / 5)} width={1} height={1} fill={SHADES[shade]} />
        ) : null,
      )}
    </svg>
  );
}
