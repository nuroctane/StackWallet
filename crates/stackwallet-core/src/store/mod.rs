//! Persistence. Directory records and the schema live here for every target;
//! the SQLite implementation ([`SqliteStore`]) is native-only behind the
//! `store` feature. The browser build reuses the same schema through
//! SQLite-WASM over OPFS, and the whole file is encrypted by the vault's data
//! key on both.

use serde::{Deserialize, Serialize};

use crate::model::{ChainFamily, ChainId, Curve, KeyGroup};

#[cfg(feature = "store")]
mod sqlite;
#[cfg(feature = "store")]
pub use sqlite::SqliteStore;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Desktop,
    Browser,
    Cli,
    Mobile,
}

/// A paired peer. `identity_pub_hex` is the pinned Ed25519 key; `id` is the
/// identifier derived from it by `identity::device_id_for_public_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub name: String,
    pub kind: DeviceKind,
    pub identity_pub_hex: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub paired_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

/// A [`KeyGroup`] plus the bookkeeping columns the model itself does not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGroupRecord {
    #[serde(flatten)]
    pub group: KeyGroup,
    pub created_at_ms: i64,
    pub refreshed_at_ms: Option<i64>,
}

/// One device's share of one group key. `encrypted_share` is sealed by the
/// vault before it reaches the store; the store never sees share plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyShareRecord {
    pub id: String,
    pub key_group_id: String,
    pub curve: Curve,
    pub device_id: String,
    pub encrypted_share: Vec<u8>,
    pub created_at_ms: i64,
}

/// Schema applied by the SQLite store. Kept here so the TypeScript
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
