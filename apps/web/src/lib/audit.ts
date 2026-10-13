import type { AuditEntry } from '@stackwallet/core-client';

export function auditEventLabel(entry: AuditEntry): string {
  if (entry.event === 'txProposed') return 'proposed';
  if (entry.event === 'txBroadcastRetry') return 'original broadcast retry authorized';
  if (entry.from && entry.to) return `${entry.from} → ${entry.to}`;
  return entry.event;
}
