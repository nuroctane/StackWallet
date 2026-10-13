import { Account, Folder, Wallet } from '@stackwallet/core-client';
import { z } from 'zod';

import { MAX_TAG_DEFS, TagDef } from './tagDefs.js';

export const MAX_CONTACTS = 2_000;

/**
 * An address the user named themselves. `chainId: null` means every EVM
 * chain (an EVM address is the same on all of them); other families name
 * one chain.
 */
export const Contact = z.object({
  id: z.string().min(1).max(64),
  name: z.string().trim().min(1).max(60),
  chainId: z.string().max(80).nullable(),
  address: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9]+$/),
  note: z.string().max(200).optional(),
  createdAtMs: z.number().int(),
});
export type Contact = z.infer<typeof Contact>;

/**
 * Persisted records reuse the core-client schemas verbatim so a blob written
 * here parses on the Rust side later. Only the wrapper is app-specific.
 */
export const DirectoryUi = z.object({
  expandedFolderIds: z.array(z.string()).max(10_000),
  selectedId: z.string().nullable(),
});
export type DirectoryUi = z.infer<typeof DirectoryUi>;

export const DIRECTORY_VERSION = 1 as const;

export const DirectoryState = z.object({
  version: z.literal(DIRECTORY_VERSION),
  folders: Folder.array().max(10_000),
  wallets: Wallet.array().max(10_000),
  accounts: Account.array().max(50_000),
  /** Names, colours and icons of the user's own tags; security tags never live here. */
  tagDefs: TagDef.array().max(MAX_TAG_DEFS).default([]),
  /** The user's address book; a label source right after their own wallets. */
  contacts: Contact.array().max(MAX_CONTACTS).default([]),
  ui: DirectoryUi,
});
export type DirectoryState = z.infer<typeof DirectoryState>;
