import { useEffect, useMemo, useState } from 'react';

interface Modules {
  size: number;
  data: boolean[][];
}

/**
 * Renders `text` as a QR code in an inline SVG. The encoder is imported on
 * first use so the directory and wallet views never pay for it. Dark modules
 * on a light tile, not the inverse: phone cameras decode inverted codes
 * unreliably, and a code a phone cannot read is not a pairing surface.
 */
export function QrCode({ text, className = '' }: { text: string; className?: string }) {
  const [modules, setModules] = useState<Modules | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setModules(null);
    setError(null);
    import('uqr')
      .then(({ encode }) => {
        if (cancelled) return;
        // Quiet zone of 4 modules is what the QR spec asks for; 'M' keeps
        // the module count down for a ~1 KB offer while surviving a scuffed screen.
        const result = encode(text, { ecc: 'M', border: 4 });
        setModules({ size: result.size, data: result.data });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'could not encode');
      });
    return () => {
      cancelled = true;
    };
  }, [text]);

  const path = useMemo(() => {
    if (!modules) return '';
    const parts: string[] = [];
    modules.data.forEach((row, y) => {
      row.forEach((dark, x) => {
        if (dark) parts.push(`M${x} ${y}h1v1h-1z`);
      });
    });
    return parts.join('');
  }, [modules]);

  if (error) {
    return (
      <div role="alert" className={`text-[11px] text-danger ${className}`}>
        QR unavailable: {error}
      </div>
    );
  }
  if (!modules) {
    return (
      <div
        aria-busy
        className={`aspect-square rounded-sw-sm border border-edge bg-elevated ${className}`}
      />
    );
  }
  return (
    <svg
      viewBox={`0 0 ${modules.size} ${modules.size}`}
      shapeRendering="crispEdges"
      role="img"
      aria-label="Pairing offer as a QR code"
      className={`aspect-square rounded-sw-sm ${className}`}
    >
      <rect width={modules.size} height={modules.size} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  );
}
