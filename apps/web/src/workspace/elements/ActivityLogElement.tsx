import { useState } from 'react';
import { Input, Select } from '@stackwallet/ui';
import {
  ActivityKind,
  ACTIVITY_MAX_EVENTS,
  useActivity,
  type ActivityState,
  dayKey,
} from '../activity.js';
import type { ElementBodyProps } from './types.js';

export const ACTIVITY_LABELS: Record<string, string> = {
  directory: 'Wallet directory changed',
  balance: 'Balance snapshot recorded',
  device: 'Device configuration changed',
  layout: 'Workspace layout changed',
  ceremony: 'Ceremony event recorded',
  transaction: 'Signing request activity observed',
};
export function activityDayCounts(state: ActivityState, selected: string) {
  return Object.entries(state.days)
    .filter(([day]) => !selected || day === selected)
    .sort(([a], [b]) => b.localeCompare(a));
}
export function ActivityLogBody() {
  const state = useActivity();
  const [kind, setKind] = useState('');
  const [day, setDay] = useState('');
  const events = state.events.filter(
    (e) => (!kind || e.kind === kind) && (!day || dayKey(e.atMs) === day),
  );
  return (
    <div className="h-full overflow-auto p-3 text-[11px]">
      <div className="flex flex-wrap gap-2">
        <Select
          aria-label="Workspace event type"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
        >
          <option value="">All event types</option>
          {ActivityKind.options.map((k) => (
            <option key={k} value={k}>
              {ACTIVITY_LABELS[k]}
            </option>
          ))}
        </Select>
        <Input
          type="date"
          aria-label="Workspace event day"
          value={day}
          onChange={(e) => setDay(e.target.value)}
        />
        {(day || kind) && (
          <button
            type="button"
            className="sw-pressable min-h-8 text-muted underline"
            onClick={() => {
              setDay('');
              setKind('');
            }}
          >
            Clear filters
          </button>
        )}
      </div>
      <p className="my-2 leading-relaxed text-faint">
        Local workspace events · the same source as the terrain. Recent{' '}
        {ACTIVITY_MAX_EVENTS.toLocaleString()} event records are retained; older history has day
        totals only. This is not a wallet transaction or core audit log.
      </p>
      {!events.length && (
        <p className="py-2 text-muted">
          No individual events match. Records begin when this event-log version is installed.
        </p>
      )}
      <ol className="divide-y divide-edge">
        {events.map((e, i) => (
          <li key={e.atMs + ':' + i} className="py-2 break-words">
            <time className="block text-faint">{new Date(e.atMs).toLocaleString()}</time>
            <span className="text-ink">
              {ACTIVITY_LABELS[e.kind]} · {e.count} {e.count === 1 ? 'event' : 'events'}
            </span>
          </li>
        ))}
      </ol>
      <details className="mt-3 border-t border-edge py-2">
        <summary className="cursor-pointer text-muted">
          Daily totals, including older terrain history
        </summary>
        <ol>
          {activityDayCounts(state, day).map(([date, counts]) => {
            const filtered = Object.entries(counts.kinds).filter(([k]) => !kind || k === kind);
            if (!filtered.length) return null;
            return (
              <li key={date} className="border-b border-edge py-2 break-words">
                <time className="text-ink">{date}</time>
                {filtered.map(([k, n]) => (
                  <span key={k} className="block text-muted">
                    {ACTIVITY_LABELS[k] ?? k} · {n}
                  </span>
                ))}
              </li>
            );
          })}
        </ol>
      </details>
    </div>
  );
}
export function ActivityLogElement(_props: ElementBodyProps) {
  return <ActivityLogBody />;
}
