import { Account, Folder, Wallet } from '@stackwallet/core-client';
import { z } from 'zod';

import { MAX_TAG_DEFS, TagDef } from './tagDefs.js';

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
  ui: DirectoryUi,
});
export type DirectoryState = z.infer<typeof DirectoryState>;
