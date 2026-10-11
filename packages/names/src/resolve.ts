import { SERVICE_PRIORITY, type NameAccount, type NameRecord, type NameService } from './types.js';

export interface ResolveOutcome {
  records: NameRecord[];
  /** Services that failed (network, malformed answer); absent names are not failures. */
  failed: string[];
}

/** Every applicable service in parallel; one failing service never hides the others. */
export async function resolveAccountNames(
  services: readonly NameService[],
  account: NameAccount,
): Promise<ResolveOutcome> {
  const applicable = services.filter((s) => s.appliesTo(account));
  const settled = await Promise.allSettled(applicable.map((s) => s.resolve(account)));
  const records: NameRecord[] = [];
  const failed: string[] = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') records.push(...r.value);
    else failed.push(applicable[i]!.id);
  });
  return { records: sortRecords(records), failed };
}

export function sortRecords(records: readonly NameRecord[]): NameRecord[] {
  const seen = new Set<string>();
  return records
    .filter((r) => {
      const k = `${r.service}:${r.name}:${r.address}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .sort(
      (a, b) =>
        SERVICE_PRIORITY.indexOf(a.service) - SERVICE_PRIORITY.indexOf(b.service) ||
        a.name.localeCompare(b.name),
    );
}

/** The name a wallet is shown under: the highest-priority verified record, if any. */
export function displayName(records: readonly NameRecord[]): NameRecord | null {
  return sortRecords(records)[0] ?? null;
}
