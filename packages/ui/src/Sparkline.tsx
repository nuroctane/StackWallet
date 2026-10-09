import type { SVGAttributes } from 'react';

export interface SparklineProps extends Omit<SVGAttributes<SVGSVGElement>, 'points'> {
  data: readonly number[];
  width?: number;
  height?: number;
  strokeWidth?: number;
}

/** Maps samples onto an SVG polyline `points` string; a flat series sits on the midline. */
export function sparklinePoints(
  data: readonly number[],
  width: number,
  height: number,
  pad = 1,
): string {
  if (data.length === 0) return '';
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min;
  const innerW = width - pad * 2;
  const innerH = height - pad * 2;
  const stepX = data.length > 1 ? innerW / (data.length - 1) : 0;
  return data
    .map((v, i) => {
      const x = data.length > 1 ? pad + i * stepX : width / 2;
      const y = span === 0 ? height / 2 : pad + innerH - ((v - min) / span) * innerH;
      return `${round(x)},${round(y)}`;
    })
    .join(' ');
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

export function Sparkline({
  data,
  width = 96,
  height = 24,
  strokeWidth = 1.25,
  className = '',
  ...rest
}: SparklineProps) {
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      aria-hidden
      className={`block text-muted ${className}`}
      {...rest}
    >
      {data.length > 0 && (
        <polyline
          points={sparklinePoints(data, width, height)}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          strokeLinejoin="round"
          strokeLinecap="round"
          vectorEffect="non-scaling-stroke"
        />
      )}
    </svg>
  );
}
