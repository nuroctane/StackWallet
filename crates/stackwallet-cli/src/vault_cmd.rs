//! `vault init` / `vault status`: the on-disk layout the headless device uses.
//!
//! A vault directory holds two files. `vault.json` is the passphrase-wrapped
//! key material (device identity seed, shares, provider keys); `store.swdb`
//! is the encrypted SQLite image keyed from the vault's DEK. Keeping them
//! separate lets the directory/wallet metadata be re-encrypted and synced
//! independently of the secrets.

use std::io::Read;
use std::path::PathBuf;

use stackwallet_core::audit::{Actor, AuditEvent};
use stackwallet_core::identity::DeviceIdentity;
use stackwallet_core::store::{Device, DeviceKind, SqliteStore};
use stackwallet_core::vault::{EncryptedVault, KdfParams, Secret, Vault};
use stackwallet_core::CoreError;
use zeroize::Zeroizing;

pub const VAULT_FILE: &str = "vault.json";
pub const STORE_FILE: &str = "store.swdb";
pub const IDENTITY_LABEL: &str = "device-identity";
pub const PASSPHRASE_ENV: &str = "STACKWALLET_PASSPHRASE";

pub struct VaultPaths {
    pub dir: PathBuf,
    pub vault: PathBuf,
    pub store: PathBuf,
}

impl VaultPaths {
    pub fn new(dir: &str) -> Self {
        let dir = PathBuf::from(dir);
        Self {
            vault: dir.join(VAULT_FILE),
            store: dir.join(STORE_FILE),
            dir,
        }
    }
}

/// An unlocked vault directory: the vault, its store, and this device's identity.
pub struct Opened {
    pub paths: VaultPaths,
    pub vault: EncryptedVault,
    pub store: SqliteStore,
    pub identity: DeviceIdentity,
}

impl Opened {
    /// Persist both files at the vault's current generation.
    ///
    /// The vault is written first. A `put` has already advanced the
    /// generation in memory, so a crash between the two renames leaves the
    /// vault one ahead of the store, and [`open`] refuses that pair just as it
    /// refuses the opposite one. The order decides what survives such a
    /// crash: with the vault first it is the new key material, which cannot
    /// be regenerated; the store rows that reference it are metadata that a
    /// repair can rebuild or drop. Writing the store first would risk
    /// persisting rows for a share whose only copy died with the process.
    /// Store-only changes (signing updates the audit log, not the vault)
    /// rewrite the store at an unchanged generation with a fresh nonce.
    pub fn save(&self) -> Result<(), String> {
        let dek = self.vault.dek().map_err(fmt_err)?;
        let generation = self.vault.generation();
        SqliteStore::write_atomic(&self.paths.vault, &self.vault.to_bytes().map_err(fmt_err)?)
            .map_err(fmt_err)?;
        self.store
            .save_to_path(&self.paths.store, &dek, generation)
            .map_err(fmt_err)
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn fmt_err(e: CoreError) -> String {
    e.to_string()
}

/// The passphrase comes from `STACKWALLET_PASSPHRASE` or, failing that, the
/// first line of stdin. There is no interactive prompt: this binary runs on
/// headless machines where a supervisor hands the secret in.
pub fn read_passphrase() -> Result<Secret, String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        // Taken once and removed so child processes do not inherit it.
        std::env::remove_var(PASSPHRASE_ENV);
        let p = Zeroizing::new(p);
        if !p.is_empty() {
            return Ok(Secret::new(p.as_bytes().to_vec()));
        }
    }
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("reading passphrase from stdin: {e}"))?;
    let line = buf.lines().next().unwrap_or("").trim_end_matches('\r');
    if line.is_empty() {
        return Err(format!(
            "no passphrase: set {PASSPHRASE_ENV} or pipe one line on stdin"
        ));
    }
    Ok(Secret::new(line.as_bytes().to_vec()))
}

pub fn init(dir: &str, device_name: &str) -> Result<Opened, String> {
    let paths = VaultPaths::new(dir);
    if paths.vault.exists() || paths.store.exists() {
        return Err(format!(
            "{} already contains a vault; refusing to overwrite",
            paths.dir.display()
        ));
    }
    std::fs::create_dir_all(&paths.dir).map_err(|e| format!("{}: {e}", paths.dir.display()))?;
    let passphrase = read_passphrase()?;
    let mut vault = EncryptedVault::create(&passphrase, KdfParams::default()).map_err(fmt_err)?;
    let identity = DeviceIdentity::generate().map_err(fmt_err)?;
    vault
        .put(IDENTITY_LABEL, identity.to_secret())
        .map_err(fmt_err)?;

    let store = SqliteStore::create().map_err(fmt_err)?;
    let at = now_ms();
    store
        .upsert_device(&Device {
            id: identity.device_id(),
            name: device_name.to_owned(),
            kind: DeviceKind::Cli,
            identity_pub_hex: identity.public_hex(),
            noise_static_hex: identity.noise_static_public_hex(),
            endpoints: Vec::new(),
            paired_at_ms: at,
            last_seen_at_ms: Some(at),
            revoked_at_ms: None,
        })
        .map_err(fmt_err)?;
    store
        .record_audit(
            at,
            Actor::Device {
                device_id: identity.device_id(),
            },
            AuditEvent::DevicePaired {
                device_id: identity.device_id(),
            },
        )
        .map_err(fmt_err)?;

    let opened = Opened {
        paths,
        vault,
        store,
        identity,
    };
    opened.save()?;
    Ok(opened)
}

/// Unlock an existing vault directory and load this device's identity.
pub fn open(dir: &str) -> Result<Opened, String> {
    let paths = VaultPaths::new(dir);
    let bytes =
        std::fs::read(&paths.vault).map_err(|e| format!("{}: {e}", paths.vault.display()))?;
    let mut vault = EncryptedVault::open(&bytes).map_err(fmt_err)?;
    let passphrase = read_passphrase()?;
    vault.unlock(&passphrase).map_err(|e| match e {
        CoreError::Unlock => "wrong passphrase".to_owned(),
        other => other.to_string(),
    })?;
    let dek = vault.dek().map_err(fmt_err)?;
    let (store, store_generation) = SqliteStore::open_path(&paths.store, &dek).map_err(fmt_err)?;
    // Both files carry the same generation when written by one `save`. Any
    // difference means one of them was restored from an older copy (or a
    // save was interrupted between the two renames); a store older than the
    // vault could resurrect spent-policy state or drop audit rows, so neither
    // direction is accepted.
    if store_generation != vault.generation() {
        return Err(format!(
            "{STORE_FILE} does not match {VAULT_FILE} (generation {store_generation} vs {}); \
             refusing to open a rolled-back store",
            vault.generation()
        ));
    }
    let handle = vault
        .handle_for(IDENTITY_LABEL)
        .ok_or_else(|| format!("vault has no `{IDENTITY_LABEL}` entry"))?;
    let identity = vault
        .with_secret(&handle, &mut |seed| DeviceIdentity::from_secret(seed))
        .map_err(fmt_err)?
        .map_err(fmt_err)?;
    Ok(Opened {
        paths,
        vault,
        store,
        identity,
    })
}

/// Locked metadata only; no passphrase needed.
pub fn status_locked(dir: &str) -> Result<serde_json::Value, String> {
    let paths = VaultPaths::new(dir);
    let bytes =
        std::fs::read(&paths.vault).map_err(|e| format!("{}: {e}", paths.vault.display()))?;
    let vault = EncryptedVault::open(&bytes).map_err(fmt_err)?;
    let labels: Vec<String> = vault.labels().into_iter().map(|(_, l)| l).collect();
    Ok(serde_json::json!({
        "dir": paths.dir.display().to_string(),
        "unlocked": false,
        "kdf": vault.kdf_params(),
        "entries": labels,
        "storePresent": paths.store.exists(),
    }))
}

/// Full status: unlocks, opens the store and verifies the audit chain.
pub fn status_unlocked(dir: &str) -> Result<serde_json::Value, String> {
    let opened = open(dir)?;
    let labels: Vec<String> = opened.vault.labels().into_iter().map(|(_, l)| l).collect();
    // `audit_chain` re-verifies every link; a break is reported rather than
    // failing the whole status so the operator can still see the rest.
    let audit = match opened.store.audit_chain() {
        Ok(chain) => serde_json::json!({
            "entries": chain.entries().len(),
            "headHash": chain.head_hash(),
            "verified": true,
        }),
        Err(e) => serde_json::json!({
            "entries": opened.store.audit_entries().map_err(fmt_err)?.len(),
            "verified": false,
            "error": e.to_string(),
        }),
    };
    let devices = opened.store.list_devices().map_err(fmt_err)?;
    let wallets = opened.store.list_wallets().map_err(fmt_err)?;
    let folders = opened.store.list_folders().map_err(fmt_err)?;
    Ok(serde_json::json!({
        "dir": opened.paths.dir.display().to_string(),
        "unlocked": true,
        "generation": opened.vault.generation(),
        "kdf": opened.vault.kdf_params(),
        "entries": labels,
        "device": {
            "id": opened.identity.device_id(),
            "publicHex": opened.identity.public_hex(),
        },
        "devices": devices.len(),
        "folders": folders.len(),
        "wallets": wallets.len(),
        "audit": audit,
    }))
}
