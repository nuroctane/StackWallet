import type { AuditEntry } from '@stackwallet/core-client';

export function auditEventLabel(entry: AuditEntry): string {
  if (entry.event === 'txProposed') return 'proposed';
  if (entry.event === 'txBroadcastRetry') return 'original broadcast retry authorized';
  if (entry.event === 'shareRefreshed') return 'shares refreshed; waiting for the other devices';
  if (entry.event === 'shareRefreshCommitted') return 'new shares confirmed by every device';
  if (entry.event === 'shareRefreshRolledBack') return 'rolled back to the previous share';
  if (entry.event === 'deviceReplaced')
    return `${String(entry['replaced'])} replaced by ${String(entry['newcomer'])}; waiting for the other devices`;
  if (entry.event === 'shareJoinDropped')
    return 'replacement did not finish everywhere; share dropped';
  if (entry.event === 'messageSigned')
    return `message signed (${entry['kind'] === 'typedData' ? 'EIP-712' : 'EIP-191'})`;
  if (entry.from && entry.to) return `${entry.from} → ${entry.to}`;
  return entry.event;
}
