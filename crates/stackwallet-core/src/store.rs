//! Persistence. Phase 1 implements this on SQLite (rusqlite natively,
//! SQLite-WASM over OPFS in the browser) with the whole file encrypted by the
//! vault's data key. Phase 0 defines the directory records and the schema.

use serde::{Deserialize, Serialize};

use crate::model::ChainFamily;
use crate::model::ChainId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub color: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub default_policy_ids: Vec<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletKind {
    Tss,
    Single,
    Watch,
    Hardware,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wallet {
    pub id: String,
    pub folder_id: String,
    pub name: String,
    pub kind: WalletKind,
    pub key_group_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub wallet_id: String,
    pub family: ChainFamily,
    pub chain_id: ChainId,
    pub address: String,
    pub derivation_path: Option<String>,
    pub public_key_hex: String,
    pub label: Option<String>,
    #[serde(default)]
    pub hidden: bool,
}

/// Schema applied by Phase 1's SQLite store. Kept here so the TypeScript
/// client and the Rust store share one source of truth through the docs.
pub const SCHEMA_SQL: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS folder (
  id TEXT PRIMARY KEY,
  parent_id TEXT REFERENCES folder(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  color TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]',
  default_policy_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS key_group (
  id TEXT PRIMARY KEY,
  threshold INTEGER NOT NULL,
  parties_json TEXT NOT NULL,
  curves_json TEXT NOT NULL,
  public_keys_json TEXT NOT NULL DEFAULT '[]',
  created_at_ms INTEGER NOT NULL,
  refreshed_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS wallet (
  id TEXT PRIMARY KEY,
  folder_id TEXT NOT NULL REFERENCES folder(id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('tss','single','watch','hardware')),
  key_group_id TEXT REFERENCES key_group(id),
  tags_json TEXT NOT NULL DEFAULT '[]',
  notes TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS account (
  id TEXT PRIMARY KEY,
  wallet_id TEXT NOT NULL REFERENCES wallet(id) ON DELETE CASCADE,
  family TEXT NOT NULL,
  chain_id TEXT NOT NULL,
  address TEXT NOT NULL,
  derivation_path TEXT,
  public_key_hex TEXT NOT NULL,
  label TEXT,
  hidden INTEGER NOT NULL DEFAULT 0,
  UNIQUE (wallet_id, chain_id, address)
);

CREATE TABLE IF NOT EXISTS device (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  identity_pub_hex TEXT NOT NULL UNIQUE,
  endpoints_json TEXT NOT NULL DEFAULT '[]',
  paired_at_ms INTEGER NOT NULL,
  last_seen_at_ms INTEGER,
  revoked_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS key_share (
  id TEXT PRIMARY KEY,
  key_group_id TEXT NOT NULL REFERENCES key_group(id) ON DELETE CASCADE,
  curve TEXT NOT NULL,
  device_id TEXT NOT NULL REFERENCES device(id),
  encrypted_share BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL,
  UNIQUE (key_group_id, curve, device_id)
);

CREATE TABLE IF NOT EXISTS policy (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('enforce','audit')),
  rules_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_policy (
  wallet_id TEXT NOT NULL REFERENCES wallet(id) ON DELETE CASCADE,
  policy_id TEXT NOT NULL REFERENCES policy(id) ON DELETE CASCADE,
  PRIMARY KEY (wallet_id, policy_id)
);

CREATE TABLE IF NOT EXISTS agent_grant (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  tool_allow_json TEXT NOT NULL,
  policy_overlay_id TEXT REFERENCES policy(id),
  provider_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS automation (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  wallet_ids_json TEXT NOT NULL,
  trigger_json TEXT NOT NULL,
  conditions_json TEXT NOT NULL DEFAULT '[]',
  action_json TEXT NOT NULL,
  policy_overlay_id TEXT REFERENCES policy(id),
  enabled INTEGER NOT NULL DEFAULT 0,
  last_run_at_ms INTEGER,
  next_run_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS tx (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account(id),
  chain_id TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  unsigned_json TEXT,
  simulation_json TEXT,
  state TEXT NOT NULL,
  approvals_json TEXT NOT NULL DEFAULT '[]',
  hash TEXT,
  error TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tx_state_idx ON tx(state, updated_at_ms);

CREATE TABLE IF NOT EXISTS audit_log (
  idx INTEGER PRIMARY KEY,
  at_ms INTEGER NOT NULL,
  actor_json TEXT NOT NULL,
  event_json TEXT NOT NULL,
  prev_hash_hex TEXT NOT NULL,
  hash_hex TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS asset (
  ref TEXT PRIMARY KEY,
  symbol TEXT NOT NULL,
  name TEXT NOT NULL,
  decimals INTEGER NOT NULL,
  logo TEXT,
  sources_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS price (
  asset_ref TEXT NOT NULL REFERENCES asset(ref),
  quote TEXT NOT NULL,
  value REAL NOT NULL,
  source TEXT NOT NULL,
  fetched_at_ms INTEGER NOT NULL,
  confidence REAL NOT NULL,
  PRIMARY KEY (asset_ref, quote, source, fetched_at_ms)
);

CREATE TABLE IF NOT EXISTS holding (
  account_id TEXT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  asset_ref TEXT NOT NULL REFERENCES asset(ref),
  amount TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (account_id, asset_ref)
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_mentions_every_entity() {
        for table in [
            "folder",
            "key_group",
            "wallet",
            "account",
            "device",
            "key_share",
            "policy",
            "wallet_policy",
            "agent_grant",
            "automation",
            "tx",
            "audit_log",
            "asset",
            "price",
            "holding",
        ] {
            assert!(
                SCHEMA_SQL.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")),
                "{table}"
            );
        }
        assert!(SCHEMA_SQL.contains("PRAGMA foreign_keys = ON"));
    }
}
