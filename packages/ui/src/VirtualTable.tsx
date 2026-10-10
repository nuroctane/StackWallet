import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
  type UIEvent,
} from 'react';

export interface Column<T> {
  key: string;
  header: ReactNode;
  /** Number → px track; string → raw grid track; omitted → `minmax(0,1fr)`. */
  width?: number | string;
  align?: 'left' | 'right';
  render: (row: T, index: number) => ReactNode;
  headerTitle?: string;
}

export type RowTone = 'default' | 'warm' | 'danger';
/** Live-flash tier; 0 is the newest update and fades through 1 and 2. */
export type RowAge = 0 | 1 | 2;
export type Density = 'tight' | 'normal' | 'loose';

export interface VirtualTableProps<T> {
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (row: T, index: number) => string;
  rowHeight?: number;
  /** Total height of the scroll container in px, header included. */
  height: number;
  overscan?: number;
  onRowClick?: (row: T, index: number) => void;
  selectedKey?: string | null;
  rowTone?: (row: T) => RowTone | undefined;
  rowAge?: (row: T) => RowAge | undefined;
  emptyLabel?: string;
  className?: string;
  stickyHeader?: boolean;
  /** Overrides `rowHeight`: tight 21, normal 24, loose 32. */
  density?: Density;
  ariaLabel: string;
}

export const HEADER_HEIGHT = 28;

const densityHeight: Record<Density, number> = { tight: 21, normal: 24, loose: 32 };

/** Half-open index range `[start, end)` of rows to mount for a scroll position. */
export function visibleRange(
  scrollTop: number,
  viewportHeight: number,
  rowHeight: number,
  count: number,
  overscan: number,
): { start: number; end: number } {
  if (count <= 0 || rowHeight <= 0 || viewportHeight <= 0) return { start: 0, end: 0 };
  const top = Math.max(0, scrollTop);
  const first = Math.floor(top / rowHeight);
  const last = Math.ceil((top + viewportHeight) / rowHeight);
  return {
    start: Math.max(0, Math.min(count, first - overscan)),
    end: Math.max(0, Math.min(count, last + overscan)),
  };
}

export function gridTemplate(columns: readonly { width?: number | string }[]): string {
  return columns
    .map((c) =>
      typeof c.width === 'number'
        ? `${c.width}px`
        : typeof c.width === 'string'
          ? c.width
          : 'minmax(0,1fr)',
    )
    .join(' ');
}

/**
 * Windowed grid for dense monospace data. Only the rows in view (plus overscan) are mounted;
 * each is absolutely placed with a translateY so scrolling never relayouts siblings.
 */
export function VirtualTable<T>({
  rows,
  columns,
  rowKey,
  rowHeight: rowHeightProp = 24,
  height,
  overscan = 8,
  onRowClick,
  selectedKey = null,
  rowTone,
  rowAge,
  emptyLabel = 'nothing here',
  className = '',
  stickyHeader = true,
  density,
  ariaLabel,
}: VirtualTableProps<T>) {
  const rowHeight = density ? densityHeight[density] : rowHeightProp;
  const scroller = useRef<HTMLDivElement>(null);
  const raf = useRef(0);
  const [scrollTop, setScrollTop] = useState(0);

  const onScroll = useCallback((e: UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    if (raf.current !== 0) return;
    raf.current = requestAnimationFrame(() => {
      raf.current = 0;
      setScrollTop(el.scrollTop);
    });
  }, []);

  useEffect(
    () => () => {
      if (raf.current !== 0) cancelAnimationFrame(raf.current);
    },
    [],
  );

  const template = useMemo(() => gridTemplate(columns), [columns]);
  const count = rows.length;
  // The header occupies the first HEADER_HEIGHT px of scroll content, so row i sits at
  // HEADER_HEIGHT + i*rowHeight; shifting scrollTop by the header keeps the range exact.
  const { start, end } = visibleRange(
    scrollTop - HEADER_HEIGHT,
    height,
    rowHeight,
    count,
    overscan,
  );

  const selectedIndex = useMemo(() => {
    if (selectedKey === null) return -1;
    for (let i = 0; i < rows.length; i++) {
      if (rowKey(rows[i] as T, i) === selectedKey) return i;
    }
    return -1;
  }, [rows, rowKey, selectedKey]);

  const select = useCallback(
    (index: number) => {
      if (!onRowClick || count === 0) return;
      const i = Math.max(0, Math.min(count - 1, index));
      onRowClick(rows[i] as T, i);
      const el = scroller.current;
      if (!el) return;
      const rowTop = i * rowHeight;
      const viewTop = el.scrollTop;
      const viewBottom = viewTop + height - HEADER_HEIGHT;
      if (rowTop < viewTop) el.scrollTop = rowTop;
      else if (rowTop + rowHeight > viewBottom)
        el.scrollTop = rowTop + rowHeight - (height - HEADER_HEIGHT);
    },
    [onRowClick, rows, count, rowHeight, height],
  );

  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (!onRowClick || e.target !== e.currentTarget) return;
      switch (e.key) {
        case 'ArrowDown':
          select(selectedIndex < 0 ? 0 : selectedIndex + 1);
          break;
        case 'ArrowUp':
          select(selectedIndex < 0 ? count - 1 : selectedIndex - 1);
          break;
        case 'Home':
          select(0);
          break;
        case 'End':
          select(count - 1);
          break;
        case 'Enter':
          if (selectedIndex >= 0) select(selectedIndex);
          break;
        default:
          return;
      }
      e.preventDefault();
    },
    [onRowClick, select, selectedIndex, count],
  );

  const body: ReactNode[] = [];
  for (let i = start; i < end; i++) {
    const row = rows[i] as T;
    const key = rowKey(row, i);
    const tone = rowTone?.(row);
    const age = rowAge?.(row);
    body.push(
      <div
        key={key}
        role="row"
        aria-rowindex={i + 2}
        aria-selected={onRowClick ? key === selectedKey : undefined}
        data-tone={tone && tone !== 'default' ? tone : undefined}
        data-age={age}
        data-selected={key === selectedKey ? '' : undefined}
        data-clickable={onRowClick ? '' : undefined}
        onClick={onRowClick ? () => onRowClick(row, i) : undefined}
        className={`sw-vrow absolute top-0 left-0 grid w-full items-center border-b border-edge/60 text-[12px] text-ink tabular-nums ${
          onRowClick ? 'cursor-default' : ''
        }`}
        style={{
          height: rowHeight,
          transform: `translateY(${i * rowHeight}px)`,
          gridTemplateColumns: template,
        }}
      >
        {columns.map((c) => (
          <div
            key={c.key}
            role="gridcell"
            className={`min-w-0 truncate px-2 ${c.align === 'right' ? 'text-right' : ''}`}
          >
            {c.render(row, i)}
          </div>
        ))}
      </div>,
    );
  }

  return (
    <div
      ref={scroller}
      role="grid"
      aria-label={ariaLabel}
      aria-rowcount={count + 1}
      tabIndex={0}
      onScroll={onScroll}
      onKeyDown={onKeyDown}
      className={`relative overflow-auto outline-none focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-edge-strong ${className}`}
      style={{ height, contain: 'strict' }}
    >
      <div
        role="row"
        aria-rowindex={1}
        className={`${stickyHeader ? 'sticky top-0 z-10' : ''} grid h-7 min-w-full border-b border-edge bg-surface text-[10px] tracking-[0.12em] text-faint uppercase`}
        style={{ gridTemplateColumns: template }}
      >
        {columns.map((c) => (
          <div
            key={c.key}
            role="columnheader"
            title={c.headerTitle}
            className={`flex min-w-0 items-center truncate px-2 ${
              c.align === 'right' ? 'justify-end text-right' : ''
            }`}
          >
            {c.header}
          </div>
        ))}
      </div>
      {count === 0 ? (
        <div
          className="flex items-center justify-center text-[11px] text-faint lowercase"
          style={{ height: Math.max(0, height - HEADER_HEIGHT) }}
        >
          {emptyLabel}
        </div>
      ) : (
        <div className="relative" style={{ height: count * rowHeight }}>
          {body}
        </div>
      )}
    </div>
  );
}
