//! rusqlite-backed store. The live database is an in-memory SQLite image; at
//! rest it is one XChaCha20-Poly1305 blob keyed from the vault's DEK. Working
//! in memory and serializing on save is what lets the same code encrypt the
//! whole file without a SQLite encryption extension.

use std::io::Write;
use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OptionalExtension, Row, MAIN_DB};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{Account, Device, Folder, KeyGroupRecord, KeyShareRecord, Wallet, SCHEMA_SQL};
use crate::audit::{Actor, AuditChain, AuditEntry, AuditEvent};
use crate::model::KeyGroup;
use crate::vault::{derive_subkey, random_array, Secret};
use crate::{CoreError, Result};

/// File layout, all of it authenticated as AAD of the ciphertext that follows:
///
/// ```text
/// "SWDB" || version u8 (= 2) || vault generation u64 BE || nonce (24 bytes)
/// ```
///
/// Version 1 lacked the generation field. No v1 files exist outside tests, so
/// it is rejected rather than migrated.
const FILE_MAGIC: &[u8; 4] = b"SWDB";
const FILE_VERSION: u8 = 2;
const NONCE_LEN: usize = 24;
const GENERATION_OFFSET: usize = FILE_MAGIC.len() + 1;
const NONCE_OFFSET: usize = GENERATION_OFFSET + 8;
const HEADER_LEN: usize = NONCE_OFFSET + NONCE_LEN;
const STORE_KEY_INFO: &[u8] = b"stackwallet/v1/store";

impl From<rusqlite::Error> for CoreError {
    fn from(e: rusqlite::Error) -> Self {
        CoreError::Store(e.to_string())
    }
}

fn store_err(e: impl std::fmt::Display) -> CoreError {
    CoreError::Store(e.to_string())
}

fn to_json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(store_err)
}

/// Enum columns are stored as their serde string form (`"tss"`, `"evm"`,
/// `"secp256k1-tr"`) so the TEXT values match the JSON the frontend sends.
fn enum_to_text<T: Serialize>(v: &T) -> Result<String> {
    match serde_json::to_value(v).map_err(store_err)? {
        serde_json::Value::String(s) => Ok(s),
        other => Err(CoreError::Store(format!(
            "enum did not serialize to a string: {other}"
        ))),
    }
}

fn enum_from_text<T: DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).map_err(store_err)
}

pub struct SqliteStore {
    conn: Connection,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Empty store with the schema applied.
    pub fn create() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.apply_schema()?;
        Ok(store)
    }

    /// Decrypt a blob produced by [`SqliteStore::to_encrypted_bytes`] and
    /// return it with the vault generation recorded in its header. The caller
    /// compares that against the live vault; the store itself cannot know
    /// which generation is current. The schema is re-applied afterwards so a
    /// file written by an older core gains any tables added since.
    pub fn open_encrypted(bytes: &[u8], dek: &Secret) -> Result<(Self, u64)> {
        if bytes.len() < GENERATION_OFFSET || &bytes[..4] != FILE_MAGIC {
            return Err(CoreError::Store("not a StackWallet store file".into()));
        }
        match bytes[4] {
            FILE_VERSION => {}
            1 => {
                return Err(CoreError::Store(
                    "store file version 1 has no vault generation binding and is not supported"
                        .into(),
                ))
            }
            other => {
                return Err(CoreError::Store(format!(
                    "unsupported store file version {other}"
                )))
            }
        }
        if bytes.len() < HEADER_LEN {
            return Err(CoreError::Store("truncated store file header".into()));
        }
        let header = &bytes[..HEADER_LEN];
        let generation = u64::from_be_bytes(
            header[GENERATION_OFFSET..NONCE_OFFSET]
                .try_into()
                .expect("header length checked"),
        );
        let nonce: [u8; NONCE_LEN] = header[NONCE_OFFSET..]
            .try_into()
            .expect("header length checked");
        let key = derive_subkey(dek, STORE_KEY_INFO)?;
        let plain = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: header,
                },
            )
            .map_err(|_| CoreError::Crypto("store decrypt"))?;
        let mut conn = Connection::open_in_memory()?;
        conn.deserialize_read_exact(MAIN_DB, plain.as_slice(), plain.len(), false)?;
        let store = Self { conn };
        store.apply_schema()?;
        Ok((store, generation))
    }

    /// Serialize the database and seal it with a fresh nonce under
    /// HKDF(DEK, "stackwallet/v1/store"). The whole header (magic, version,
    /// generation, nonce) is authenticated so none of it can be rewritten
    /// without detection; `generation` should be the vault's current value so
    /// the two files can be checked against each other on open.
    pub fn to_encrypted_bytes(&self, dek: &Secret, generation: u64) -> Result<Vec<u8>> {
        let image = self.conn.serialize(MAIN_DB)?;
        let nonce: [u8; NONCE_LEN] = random_array()?;
        let mut out = Vec::with_capacity(HEADER_LEN + image.len() + 16);
        out.extend_from_slice(FILE_MAGIC);
        out.push(FILE_VERSION);
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(&nonce);
        let key = derive_subkey(dek, STORE_KEY_INFO)?;
        let sealed = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &image,
                    aad: &out,
                },
            )
            .map_err(|_| CoreError::Crypto("store encrypt"))?;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Encrypt and write durably; see [`SqliteStore::write_atomic`].
    pub fn save_to_path(&self, path: &Path, dek: &Secret, generation: u64) -> Result<()> {
        let bytes = self.to_encrypted_bytes(dek, generation)?;
        Self::write_atomic(path, &bytes)
    }

    pub fn open_path(path: &Path, dek: &Secret) -> Result<(Self, u64)> {
        let bytes = std::fs::read(path).map_err(store_err)?;
        Self::open_encrypted(&bytes, dek)
    }

    /// Replace `path` with `bytes` so that a crash or power loss at any point
    /// leaves either the complete old file or the complete new one. The data
    /// goes to a sibling `.tmp` that is created exclusively (a leftover from
    /// an earlier crash is removed first, never reused), fsynced, then
    /// renamed over the target; on Unix the directory is fsynced too, since
    /// the rename itself is only durable once the directory entry is. The
    /// temp file is created owner-only on Unix because the caller is about to
    /// put ciphertext of key material in it and the default umask may be
    /// group-readable.
    pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
        let with_path =
            |e: std::io::Error, p: &Path| CoreError::Store(format!("{}: {e}", p.display()));
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp = Path::new(&tmp_name);
        match std::fs::remove_file(tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(with_path(e, tmp)),
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let written = (|| {
            let mut file = options.open(tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(tmp, path)
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(tmp);
            return Err(with_path(e, path));
        }
        #[cfg(unix)]
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| with_path(e, dir))?;
        }
        Ok(())
    }

    fn apply_schema(&self) -> Result<()> {
        self.conn.execute_batch(SCHEMA_SQL)?;
        // `CREATE TABLE IF NOT EXISTS` adds nothing to a table that already
        // exists, so columns added after the fact need an explicit upgrade.
        // Devices pinned before the column existed have no Noise static; they
        // must re-pair, which is exactly what an empty static forces.
        let has_noise_static = self
            .conn
            .prepare("PRAGMA table_info(device)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .any(|name| name.map(|n| n == "noise_static_hex").unwrap_or(false));
        if !has_noise_static {
            self.conn.execute_batch(
                "ALTER TABLE device ADD COLUMN noise_static_hex TEXT NOT NULL DEFAULT ''",
            )?;
        }
        let fk: i64 = self
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        if fk != 1 {
            return Err(CoreError::Store(
                "PRAGMA foreign_keys is not enabled".into(),
            ));
        }
        Ok(())
    }

    // ---- folder ---------------------------------------------------------

    pub fn upsert_folder(&self, f: &Folder) -> Result<()> {
        self.conn.execute(
            "INSERT INTO folder (id, parent_id, name, color, tags_json, default_policy_ids_json, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               parent_id = excluded.parent_id, name = excluded.name, color = excluded.color,
               tags_json = excluded.tags_json, default_policy_ids_json = excluded.default_policy_ids_json,
               updated_at_ms = excluded.updated_at_ms",
            params![
                f.id,
                f.parent_id,
                f.name,
                f.color,
                to_json(&f.tags)?,
                to_json(&f.default_policy_ids)?,
                f.created_at_ms,
                f.updated_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get_folder(&self, id: &str) -> Result<Option<Folder>> {
        self.conn
            .query_row(
                &format!("{FOLDER_SELECT} WHERE id = ?1"),
                params![id],
                folder_from_row,
            )
            .optional()
            .map_err(CoreError::from)
    }

    pub fn list_folders(&self) -> Result<Vec<Folder>> {
        collect(
            &self.conn,
            &format!("{FOLDER_SELECT} ORDER BY created_at_ms, id"),
            folder_from_row,
        )
    }

    pub fn delete_folder(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM folder WHERE id = ?1", params![id])?
            > 0)
    }

    // ---- wallet ---------------------------------------------------------

    pub fn upsert_wallet(&self, w: &Wallet) -> Result<()> {
        self.conn.execute(
            "INSERT INTO wallet (id, folder_id, name, kind, key_group_id, tags_json, notes, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               folder_id = excluded.folder_id, name = excluded.name, kind = excluded.kind,
               key_group_id = excluded.key_group_id, tags_json = excluded.tags_json,
               notes = excluded.notes, updated_at_ms = excluded.updated_at_ms",
            params![
                w.id,
                w.folder_id,
                w.name,
                enum_to_text(&w.kind)?,
                w.key_group_id,
                to_json(&w.tags)?,
                w.notes,
                w.created_at_ms,
                w.updated_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get_wallet(&self, id: &str) -> Result<Option<Wallet>> {
        self.conn
            .query_row(
                &format!("{WALLET_SELECT} WHERE id = ?1"),
                params![id],
                wallet_from_row,
            )
            .optional()
            .map_err(CoreError::from)
    }

    pub fn list_wallets(&self) -> Result<Vec<Wallet>> {
        collect(
            &self.conn,
            &format!("{WALLET_SELECT} ORDER BY created_at_ms, id"),
            wallet_from_row,
        )
    }

    pub fn list_wallets_in_folder(&self, folder_id: &str) -> Result<Vec<Wallet>> {
        let mut stmt = self.conn.prepare(&format!(
            "{WALLET_SELECT} WHERE folder_id = ?1 ORDER BY created_at_ms, id"
        ))?;
        let rows = stmt.query_map(params![folder_id], wallet_from_row)?;
        rows.map(|r| r.map_err(CoreError::from)).collect()
    }

    pub fn delete_wallet(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM wallet WHERE id = ?1", params![id])?
            > 0)
    }

    // ---- account --------------------------------------------------------

    pub fn upsert_account(&self, a: &Account) -> Result<()> {
        self.conn.execute(
            "INSERT INTO account (id, wallet_id, family, chain_id, address, derivation_path, public_key_hex, label, hidden)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               wallet_id = excluded.wallet_id, family = excluded.family, chain_id = excluded.chain_id,
               address = excluded.address, derivation_path = excluded.derivation_path,
               public_key_hex = excluded.public_key_hex, label = excluded.label, hidden = excluded.hidden",
            params![
                a.id,
                a.wallet_id,
                enum_to_text(&a.family)?,
                a.chain_id.0,
                a.address,
                a.derivation_path,
                a.public_key_hex,
                a.label,
                a.hidden as i64
            ],
        )?;
        Ok(())
    }

    pub fn get_account(&self, id: &str) -> Result<Option<Account>> {
        self.conn
            .query_row(
                &format!("{ACCOUNT_SELECT} WHERE id = ?1"),
                params![id],
                account_from_row,
            )
            .optional()
            .map_err(CoreError::from)
    }

    pub fn list_accounts(&self, wallet_id: &str) -> Result<Vec<Account>> {
        let mut stmt = self.conn.prepare(&format!(
            "{ACCOUNT_SELECT} WHERE wallet_id = ?1 ORDER BY chain_id, address"
        ))?;
        let rows = stmt.query_map(params![wallet_id], account_from_row)?;
        rows.map(|r| r.map_err(CoreError::from)).collect()
    }

    pub fn delete_account(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM account WHERE id = ?1", params![id])?
            > 0)
    }

    // ---- key group ------------------------------------------------------

    pub fn upsert_key_group(&self, rec: &KeyGroupRecord) -> Result<()> {
        let g = &rec.group;
        self.conn.execute(
            "INSERT INTO key_group (id, threshold, parties_json, curves_json, public_keys_json, created_at_ms, refreshed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               threshold = excluded.threshold, parties_json = excluded.parties_json,
               curves_json = excluded.curves_json, public_keys_json = excluded.public_keys_json,
               refreshed_at_ms = excluded.refreshed_at_ms",
            params![
                g.id,
                g.threshold as i64,
                to_json(&g.parties)?,
                to_json(&g.curves)?,
                to_json(&g.public_keys)?,
                rec.created_at_ms,
                rec.refreshed_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get_key_group(&self, id: &str) -> Result<Option<KeyGroupRecord>> {
        self.conn
            .query_row(
                "SELECT id, threshold, parties_json, curves_json, public_keys_json, created_at_ms, refreshed_at_ms
                 FROM key_group WHERE id = ?1",
                params![id],
                |r| {
                    Ok(KeyGroupRecord {
                        group: KeyGroup {
                            id: r.get(0)?,
                            threshold: r.get::<_, i64>(1)? as u8,
                            parties: from_json_row(r.get::<_, String>(2)?)?,
                            curves: from_json_row(r.get::<_, String>(3)?)?,
                            public_keys: from_json_row(r.get::<_, String>(4)?)?,
                        },
                        created_at_ms: r.get(5)?,
                        refreshed_at_ms: r.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(CoreError::from)
    }

    // ---- device ---------------------------------------------------------

    pub fn upsert_device(&self, d: &Device) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device (id, name, kind, identity_pub_hex, noise_static_hex, endpoints_json, paired_at_ms, last_seen_at_ms, revoked_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, kind = excluded.kind, identity_pub_hex = excluded.identity_pub_hex,
               noise_static_hex = excluded.noise_static_hex, endpoints_json = excluded.endpoints_json, paired_at_ms = excluded.paired_at_ms,
               last_seen_at_ms = excluded.last_seen_at_ms, revoked_at_ms = excluded.revoked_at_ms",
            params![
                d.id,
                d.name,
                enum_to_text(&d.kind)?,
                d.identity_pub_hex,
                d.noise_static_hex,
                to_json(&d.endpoints)?,
                d.paired_at_ms,
                d.last_seen_at_ms,
                d.revoked_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get_device(&self, id: &str) -> Result<Option<Device>> {
        self.conn
            .query_row(
                &format!("{DEVICE_SELECT} WHERE id = ?1"),
                params![id],
                device_from_row,
            )
            .optional()
            .map_err(CoreError::from)
    }

    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self
            .conn
            .prepare(&format!("{DEVICE_SELECT} ORDER BY paired_at_ms, id"))?;
        let rows = stmt.query_map([], device_from_row)?;
        rows.map(|r| r.map_err(CoreError::from)).collect()
    }

    // ---- key share ------------------------------------------------------

    pub fn put_key_share(&self, s: &KeyShareRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO key_share (id, key_group_id, curve, device_id, encrypted_share, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
               key_group_id = excluded.key_group_id, curve = excluded.curve, device_id = excluded.device_id,
               encrypted_share = excluded.encrypted_share, created_at_ms = excluded.created_at_ms",
            params![
                s.id,
                s.key_group_id,
                enum_to_text(&s.curve)?,
                s.device_id,
                s.encrypted_share,
                s.created_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get_key_share(
        &self,
        key_group_id: &str,
        curve: crate::model::Curve,
        device_id: &str,
    ) -> Result<Option<KeyShareRecord>> {
        self.conn
            .query_row(
                "SELECT id, key_group_id, curve, device_id, encrypted_share, created_at_ms
                 FROM key_share WHERE key_group_id = ?1 AND curve = ?2 AND device_id = ?3",
                params![key_group_id, enum_to_text(&curve)?, device_id],
                key_share_from_row,
            )
            .optional()
            .map_err(CoreError::from)
    }

    // ---- audit ----------------------------------------------------------

    pub fn audit_entries(&self) -> Result<Vec<AuditEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT idx, at_ms, actor_json, event_json, prev_hash_hex, hash_hex
             FROM audit_log ORDER BY idx",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AuditEntry {
                index: r.get::<_, i64>(0)? as u64,
                at_ms: r.get(1)?,
                actor: from_json_row(r.get::<_, String>(2)?)?,
                event: from_json_row(r.get::<_, String>(3)?)?,
                prev_hash_hex: r.get(4)?,
                hash_hex: r.get(5)?,
            })
        })?;
        rows.map(|r| r.map_err(CoreError::from)).collect()
    }

    /// The stored log as a verified chain. Fails with `AuditChain(i)` if any
    /// row has been edited, removed or reordered.
    pub fn audit_chain(&self) -> Result<AuditChain> {
        AuditChain::from_entries(self.audit_entries()?)
    }

    /// Append an entry that was formed elsewhere (a synced row, for example).
    /// The whole chain is re-verified first and the entry must extend its
    /// head exactly; the cost is linear in log size, which is the price of
    /// never trusting the on-disk tail.
    pub fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        let mut chain = self.audit_chain()?;
        let expected_index = chain.entries().len();
        let appended = chain.append(entry.at_ms, entry.actor.clone(), entry.event.clone());
        if appended != entry {
            return Err(CoreError::AuditChain(expected_index));
        }
        self.insert_audit_row(entry)
    }

    /// Form the next entry from its content and append it.
    pub fn record_audit(&self, at_ms: i64, actor: Actor, event: AuditEvent) -> Result<AuditEntry> {
        let mut chain = self.audit_chain()?;
        let entry = chain.append(at_ms, actor, event).clone();
        self.insert_audit_row(&entry)?;
        Ok(entry)
    }

    fn insert_audit_row(&self, e: &AuditEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log (idx, at_ms, actor_json, event_json, prev_hash_hex, hash_hex)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                e.index as i64,
                e.at_ms,
                to_json(&e.actor)?,
                to_json(&e.event)?,
                e.prev_hash_hex,
                e.hash_hex
            ],
        )?;
        Ok(())
    }
}

const FOLDER_SELECT: &str = "SELECT id, parent_id, name, color, tags_json, default_policy_ids_json, created_at_ms, updated_at_ms FROM folder";
const WALLET_SELECT: &str = "SELECT id, folder_id, name, kind, key_group_id, tags_json, notes, created_at_ms, updated_at_ms FROM wallet";
const ACCOUNT_SELECT: &str = "SELECT id, wallet_id, family, chain_id, address, derivation_path, public_key_hex, label, hidden FROM account";
const DEVICE_SELECT: &str = "SELECT id, name, kind, identity_pub_hex, noise_static_hex, endpoints_json, paired_at_ms, last_seen_at_ms, revoked_at_ms FROM device";

/// JSON columns decode inside rusqlite's row callback, so their errors have to
/// be expressed as rusqlite errors to flow through `query_row`.
fn from_json_row<T: DeserializeOwned>(s: String) -> rusqlite::Result<T> {
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn enum_from_row<T: DeserializeOwned>(s: String) -> rusqlite::Result<T> {
    enum_from_text(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn folder_from_row(r: &Row<'_>) -> rusqlite::Result<Folder> {
    Ok(Folder {
        id: r.get(0)?,
        parent_id: r.get(1)?,
        name: r.get(2)?,
        color: r.get(3)?,
        tags: from_json_row(r.get::<_, String>(4)?)?,
        default_policy_ids: from_json_row(r.get::<_, String>(5)?)?,
        created_at_ms: r.get(6)?,
        updated_at_ms: r.get(7)?,
    })
}

fn wallet_from_row(r: &Row<'_>) -> rusqlite::Result<Wallet> {
    Ok(Wallet {
        id: r.get(0)?,
        folder_id: r.get(1)?,
        name: r.get(2)?,
        kind: enum_from_row(r.get::<_, String>(3)?)?,
        key_group_id: r.get(4)?,
        tags: from_json_row(r.get::<_, String>(5)?)?,
        notes: r.get(6)?,
        created_at_ms: r.get(7)?,
        updated_at_ms: r.get(8)?,
    })
}

fn account_from_row(r: &Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: r.get(0)?,
        wallet_id: r.get(1)?,
        family: enum_from_row(r.get::<_, String>(2)?)?,
        chain_id: crate::model::ChainId(r.get(3)?),
        address: r.get(4)?,
        derivation_path: r.get(5)?,
        public_key_hex: r.get(6)?,
        label: r.get(7)?,
        hidden: r.get::<_, i64>(8)? != 0,
    })
}

fn device_from_row(r: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: enum_from_row(r.get::<_, String>(2)?)?,
        identity_pub_hex: r.get(3)?,
        noise_static_hex: r.get(4)?,
        endpoints: from_json_row(r.get::<_, String>(5)?)?,
        paired_at_ms: r.get(6)?,
        last_seen_at_ms: r.get(7)?,
        revoked_at_ms: r.get(8)?,
    })
}

fn key_share_from_row(r: &Row<'_>) -> rusqlite::Result<KeyShareRecord> {
    Ok(KeyShareRecord {
        id: r.get(0)?,
        key_group_id: r.get(1)?,
        curve: enum_from_row(r.get::<_, String>(2)?)?,
        device_id: r.get(3)?,
        encrypted_share: r.get(4)?,
        created_at_ms: r.get(5)?,
    })
}

fn collect<T>(
    conn: &Connection,
    sql: &str,
    f: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], f)?;
    rows.map(|r| r.map_err(CoreError::from)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store written before `device.noise_static_hex` existed must gain the
    /// column when a newer core opens it; devices pinned before then carry an
    /// empty static, which makes them re-pair instead of failing queries.
    #[test]
    fn opening_an_older_store_adds_the_noise_static_column() {
        let store = SqliteStore::create().unwrap();
        store
            .conn
            .execute_batch("ALTER TABLE device DROP COLUMN noise_static_hex")
            .unwrap();
        store.apply_schema().unwrap();
        let names: Vec<String> = store
            .conn
            .prepare("PRAGMA table_info(device)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(names.iter().any(|n| n == "noise_static_hex"));
        // And device CRUD works on the migrated table.
        let d = Device {
            id: "d1".into(),
            name: "Old peer".into(),
            kind: crate::store::DeviceKind::Cli,
            identity_pub_hex: "ab".repeat(32),
            noise_static_hex: String::new(),
            endpoints: Vec::new(),
            paired_at_ms: 1,
            last_seen_at_ms: None,
            revoked_at_ms: None,
        };
        store.upsert_device(&d).unwrap();
        assert_eq!(store.get_device("d1").unwrap().unwrap().name, "Old peer");
    }
}
