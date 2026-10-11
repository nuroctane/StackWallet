import type { ChainFamily, ChainId } from '@stackwallet/core-client';
import { z } from 'zod';

export const NameServiceId = z.enum(['ens', 'sns', 'icns', 'thorname']);
export type NameServiceId = z.infer<typeof NameServiceId>;

/** Order used to pick a wallet's display name when several services answer. */
export const SERVICE_PRIORITY: readonly NameServiceId[] = ['ens', 'sns', 'icns', 'thorname'];

export const SERVICE_LABEL: Record<NameServiceId, string> = {
  ens: 'ENS',
  sns: 'SNS',
  icns: 'ICNS',
  thorname: 'THORName',
};

/**
 * A name proven to point at the address it is shown for: every record here
 * passed a forward check (name -> address) after the reverse lookup.
 */
export const NameRecord = z.object({
  service: NameServiceId,
  name: z.string().min(1).max(96),
  /** Address the name was verified against. */
  address: z.string().min(1).max(128),
  /** Chain the verification ran on, for provenance. */
  chainId: z.string().min(1),
  /** Set when the name uses characters outside printable ASCII (homoglyph risk). */
  nonAscii: z.boolean(),
  resolvedAtMs: z.number().int(),
});
export type NameRecord = z.infer<typeof NameRecord>;

export interface NameAccount {
  family: ChainFamily;
  chainId: ChainId;
  address: string;
}

export interface NameService {
  id: NameServiceId;
  appliesTo(account: NameAccount): boolean;
  /** Verified records only; an unverifiable or absent name resolves to []. */
  resolve(account: NameAccount): Promise<NameRecord[]>;
}
