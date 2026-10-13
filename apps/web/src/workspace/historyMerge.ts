import { MetadataConflict } from '../store/metadataMerge.js';

/** Legacy snapshots have no identity; preserve their multiplicity without duplicating a reload. */
export function mergeHistoryRecords<T extends { id?: string | undefined }>(
  left: readonly T[],
  right: readonly T[],
): T[] {
  const records = new Map<string, T>();
  for (const snapshot of [left, right]) {
    const occurrences = new Map<string, number>();
    for (const record of snapshot) {
      const encoded = JSON.stringify(record);
      const occurrence = occurrences.get(encoded) ?? 0;
      occurrences.set(encoded, occurrence + 1);
      const key = record.id ? `id:${record.id}` : `legacy:${encoded}:${occurrence}`;
      const previous = records.get(key);
      if (previous && JSON.stringify(previous) !== encoded)
        throw new MetadataConflict('History record identity has conflicting contents');
      records.set(key, record);
    }
  }
  return [...records.values()];
}
