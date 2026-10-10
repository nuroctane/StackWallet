//! Encrypted storage for shares, seeds, device identity and provider keys.
//!
//! Layout of one vault file (see `docs/SECURITY.md` section 4):
//!
//! ```text
//! passphrase --Argon2id(salt, params)--> KEK
//! KEK  --XChaCha20-Poly1305, AAD = version + params--> wraps a random 32-byte DEK
//! DEK  --HKDF-SHA256(info = "stackwallet/v1/entry/<id>")--> one key per entry
//! entry key --XChaCha20-Poly1305, AAD = id + label--> entry ciphertext
//! DEK  --HKDF-SHA256(info = "stackwallet/v1/manifest")--> manifest MAC key
//! manifest key --HMAC-SHA256 over generation + every entry--> manifest tag
//! ```
//!
//! Binding the KDF parameters into the DEK wrap's AAD means an attacker who
//! lowers the cost parameters in the file to speed up guessing gets an
//! authentication failure instead of a cheaper oracle. Deriving a separate key
//! per entry means a leaked entry key exposes one secret, not the whole vault.
//!
//! Each entry authenticates itself, but on its own that does not stop someone
//! with write access to the file from deleting an entry, reordering entries,
//! or splicing in an older ciphertext for the same id and label. The manifest
//! tag covers the whole entry set plus a monotonically increasing generation,
//! so any of those edits fails at unlock. The generation is also written into
//! the store file's header, which lets the caller refuse a store that was
//! rolled back independently of the vault.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2_v011::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CoreError, Result};

/// Secret bytes that are wiped when dropped. The only container secrets may
/// live in outside the vault's own ciphertext.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

/// Opaque reference to a secret inside the vault. Handles cross the FFI
/// boundary; bytes never do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretHandle(pub String);

/// How the data encryption key may be unwrapped. Share material always requires
/// at least the passphrase factor; platform unlock alone is never sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockFactor {
    Passphrase,
    PlatformKey,
}

pub trait Vault {
    fn is_unlocked(&self) -> bool;
    fn unlock(&mut self, passphrase: &Secret) -> Result<()>;
    fn lock(&mut self);
    fn put(&mut self, label: &str, secret: Secret) -> Result<SecretHandle>;
    fn with_secret<T>(&self, handle: &SecretHandle, f: &mut dyn FnMut(&Secret) -> T) -> Result<T>;
    fn delete(&mut self, handle: &SecretHandle) -> Result<()>;
}

/// On-disk format version. Bumped only for incompatible layout changes; the
/// value is authenticated as part of the DEK wrap so it cannot be rewritten.
pub const VAULT_VERSION: u32 = 1;

const DEK_LEN: usize = 32;
const KEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const ENTRY_ID_LEN: usize = 16;
const ENTRY_INFO_PREFIX: &str = "stackwallet/v1/entry/";
const MANIFEST_KEY_INFO: &[u8] = b"stackwallet/v1/manifest";
const MANIFEST_DOMAIN: &[u8] = b"stackwallet/vault/v1/manifest";
const MANIFEST_TAG_LEN: usize = 32;

/// Argon2id cost parameters. Platforms raise these to what their hardware
/// tolerates; nothing may go below [`KdfParams::MINIMUM`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP's recommended floor for Argon2id: 19 MiB, 2 iterations, 1 lane.
    pub const MINIMUM: KdfParams = KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    /// Upper bound on memory cost: 4 GiB. Argon2 allocates `m_cost_kib` KiB
    /// before anything in the file is authenticated, so an unbounded value
    /// from a tampered file would be an out-of-memory trigger rather than a
    /// cost parameter.
    pub const MAXIMUM_M_COST_KIB: u32 = 4_194_304;

    pub fn meets_minimum(&self) -> bool {
        self.m_cost_kib >= Self::MINIMUM.m_cost_kib
            && self.t_cost >= Self::MINIMUM.t_cost
            && self.p_cost >= Self::MINIMUM.p_cost
    }

    /// Both bounds at once; everything that is about to run Argon2 goes
    /// through here first.
    pub fn validate(&self) -> Result<()> {
        if !self.meets_minimum() {
            return Err(CoreError::Invalid {
                what: "kdf params",
                reason: format!("{self:?} is below the minimum {:?}", Self::MINIMUM),
            });
        }
        if self.m_cost_kib > Self::MAXIMUM_M_COST_KIB {
            return Err(CoreError::Invalid {
                what: "kdf params",
                reason: format!(
                    "mCostKib {} exceeds the maximum {}",
                    self.m_cost_kib,
                    Self::MAXIMUM_M_COST_KIB
                ),
            });
        }
        Ok(())
    }

    fn to_argon2(self) -> Result<argon2::Argon2<'static>> {
        let params = argon2::Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEK_LEN))
            .map_err(|_| CoreError::Invalid {
                what: "kdf params",
                reason: format!("{self:?} rejected by argon2"),
            })?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::MINIMUM
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KdfSection {
    #[serde(flatten)]
    params: KdfParams,
    salt_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sealed {
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    id: String,
    label: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultFile {
    version: u32,
    kdf: KdfSection,
    wrapped_dek: Sealed,
    generation: u64,
    manifest_tag_hex: String,
    entries: Vec<Entry>,
}

impl VaultFile {
    /// Authenticated alongside the wrapped DEK. Built by hand rather than from
    /// the serde output so that formatting changes in serde_json can never
    /// invalidate existing vaults.
    fn wrap_aad(&self) -> Vec<u8> {
        format!(
            "stackwallet/vault/v{}|{}|{}|{}|{}",
            self.version,
            self.kdf.params.m_cost_kib,
            self.kdf.params.t_cost,
            self.kdf.params.p_cost,
            self.kdf.salt_hex
        )
        .into_bytes()
    }

    /// Canonical byte string the manifest tag is computed over:
    ///
    /// ```text
    /// "stackwallet/vault/v1/manifest" || generation (u64 BE)
    ///   || for each entry in stored order:
    ///        len(id) u32 BE || id || len(label) u32 BE || label
    ///        || len(nonce_hex) u32 BE || nonce_hex
    ///        || len(ciphertext_hex) u32 BE || ciphertext_hex
    /// ```
    ///
    /// Every variable-length field is length-prefixed so no two entry lists
    /// can encode to the same bytes. Entry order is part of the message.
    fn manifest_message(&self) -> Vec<u8> {
        fn push_field(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut out = Vec::with_capacity(
            MANIFEST_DOMAIN.len()
                + 8
                + self
                    .entries
                    .iter()
                    .map(|e| {
                        16 + e.id.len() + e.label.len() + e.nonce_hex.len() + e.ciphertext_hex.len()
                    })
                    .sum::<usize>(),
        );
        out.extend_from_slice(MANIFEST_DOMAIN);
        out.extend_from_slice(&self.generation.to_be_bytes());
        for e in &self.entries {
            push_field(&mut out, &e.id);
            push_field(&mut out, &e.label);
            push_field(&mut out, &e.nonce_hex);
            push_field(&mut out, &e.ciphertext_hex);
        }
        out
    }

    fn manifest_mac(&self, dek: &Secret) -> Result<Hmac<Sha256>> {
        let key = derive_subkey(dek, MANIFEST_KEY_INFO)?;
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_ref())
            .map_err(|_| CoreError::Crypto("vault manifest"))?;
        mac.update(&self.manifest_message());
        Ok(mac)
    }

    fn compute_manifest_tag(&self, dek: &Secret) -> Result<String> {
        let tag = self.manifest_mac(dek)?.finalize().into_bytes();
        Ok(hex::encode(tag))
    }

    fn verify_manifest_tag(&self, dek: &Secret) -> Result<()> {
        let stored =
            hex::decode(&self.manifest_tag_hex).map_err(|_| CoreError::Crypto("vault manifest"))?;
        if stored.len() != MANIFEST_TAG_LEN {
            return Err(CoreError::Crypto("vault manifest"));
        }
        self.manifest_mac(dek)?
            .verify_slice(&stored)
            .map_err(|_| CoreError::Crypto("vault manifest"))
    }
}

/// XChaCha20-Poly1305 vault with an Argon2id-wrapped data key.
pub struct EncryptedVault {
    file: VaultFile,
    dek: Option<Secret>,
}

impl std::fmt::Debug for EncryptedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedVault")
            .field("version", &self.file.version)
            .field("kdf", &self.file.kdf.params)
            .field("unlocked", &self.dek.is_some())
            .field("generation", &self.file.generation)
            .field("entries", &self.file.entries.len())
            .finish()
    }
}

impl EncryptedVault {
    /// New, empty, unlocked vault. Refuses parameters below the OWASP floor
    /// or above [`KdfParams::MAXIMUM_M_COST_KIB`].
    pub fn create(passphrase: &Secret, params: KdfParams) -> Result<Self> {
        params.validate()?;
        let dek = Secret::new(random_array::<DEK_LEN>()?.to_vec());
        let mut file = VaultFile {
            version: VAULT_VERSION,
            kdf: KdfSection {
                params,
                salt_hex: hex::encode(random_array::<SALT_LEN>()?),
            },
            wrapped_dek: Sealed {
                nonce_hex: String::new(),
                ciphertext_hex: String::new(),
            },
            generation: 0,
            manifest_tag_hex: String::new(),
            entries: Vec::new(),
        };
        file.wrapped_dek = wrap_dek(&file, passphrase, &dek)?;
        file.manifest_tag_hex = file.compute_manifest_tag(&dek)?;
        Ok(Self {
            file,
            dek: Some(dek),
        })
    }

    /// Parse a serialized vault. The result is locked; nothing is decrypted
    /// until [`Vault::unlock`] succeeds. KDF parameters are bounds-checked
    /// here, before any Argon2 allocation, because the file is unauthenticated
    /// until the DEK unwrap succeeds and the AAD check can only run after the
    /// (parameter-sized) derivation.
    pub fn open(bytes: &[u8]) -> Result<Self> {
        let file: VaultFile = serde_json::from_slice(bytes).map_err(|_| CoreError::Unlock)?;
        if file.version != VAULT_VERSION {
            return Err(CoreError::Invalid {
                what: "vault",
                reason: format!("unsupported version {}", file.version),
            });
        }
        file.kdf.params.validate()?;
        Ok(Self { file, dek: None })
    }

    /// Counter that advances on every change to the entry set (`put`,
    /// `delete`). Authenticated by the manifest tag and mirrored into the
    /// store file header, so a caller can tell when one of the two files was
    /// restored from an older copy without the other.
    pub fn generation(&self) -> u64 {
        self.file.generation
    }

    /// Alias of [`EncryptedVault::open`] for symmetry with [`EncryptedVault::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::open(bytes)
    }

    /// Serialize everything that belongs on disk. Contains only ciphertext,
    /// labels, ids and KDF parameters.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.file).map_err(|_| CoreError::Crypto("vault encode"))
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.file.kdf.params
    }

    /// Every stored entry as `(handle, label)`. Labels are plaintext metadata
    /// and readable while locked.
    pub fn labels(&self) -> Vec<(SecretHandle, String)> {
        self.file
            .entries
            .iter()
            .map(|e| (SecretHandle(e.id.clone()), e.label.clone()))
            .collect()
    }

    pub fn handle_for(&self, label: &str) -> Option<SecretHandle> {
        self.file
            .entries
            .iter()
            .find(|e| e.label == label)
            .map(|e| SecretHandle(e.id.clone()))
    }

    /// Copy of the data encryption key for the store's file encryption. Never
    /// hand this across the FFI boundary; the store derives its own subkey.
    pub fn dek(&self) -> Result<Secret> {
        let dek = self.dek.as_ref().ok_or(CoreError::Locked)?;
        Ok(Secret::new(dek.expose().to_vec()))
    }

    /// Re-wrap the DEK under a new passphrase and a fresh salt. Works on a
    /// locked vault too, so a locked state stays locked afterwards.
    ///
    /// The generation and manifest tag are left alone on purpose: the tag is
    /// keyed from the DEK, which does not change, and covers the entry set,
    /// which does not change either. The generation tracks entry-set edits
    /// that the store must stay in step with; a passphrase rotation touches
    /// neither the entries nor the store, so bumping it here would only force
    /// a needless store rewrite. Restoring a pre-rotation vault file is not a
    /// rollback the generation can detect; that file is a complete, valid
    /// vault under the old passphrase, which is why the old passphrase should
    /// be treated as compromised once a rotation happens.
    pub fn change_passphrase(&mut self, old: &Secret, new: &Secret) -> Result<()> {
        self.file.kdf.params.validate()?;
        let dek = unwrap_dek(&self.file, old)?;
        let mut candidate = self.file.clone();
        candidate.kdf.salt_hex = hex::encode(random_array::<SALT_LEN>()?);
        candidate.wrapped_dek = wrap_dek(&candidate, new, &dek)?;
        self.file = candidate;
        if self.dek.is_some() {
            self.dek = Some(dek);
        }
        Ok(())
    }

    /// Replace the entry list, advance the generation and re-tag the
    /// manifest as one step, so a failure (which can only be an HKDF/HMAC
    /// error) leaves the in-memory file exactly as it was rather than with
    /// edited entries under a stale tag.
    fn commit_entries(&mut self, entries: Vec<Entry>) -> Result<()> {
        let dek = self.dek.as_ref().ok_or(CoreError::Locked)?;
        let generation = self
            .file
            .generation
            .checked_add(1)
            .ok_or(CoreError::Crypto("vault generation"))?;
        let mut candidate = VaultFile {
            generation,
            entries,
            ..self.file.clone()
        };
        candidate.manifest_tag_hex = candidate.compute_manifest_tag(dek)?;
        self.file = candidate;
        Ok(())
    }

    fn entry_index(&self, handle: &SecretHandle) -> Result<usize> {
        self.file
            .entries
            .iter()
            .position(|e| e.id == handle.0)
            .ok_or_else(|| CoreError::Invalid {
                what: "secret handle",
                reason: format!("unknown handle {}", handle.0),
            })
    }

    fn seal_entry(&self, id: &str, label: &str, secret: &Secret) -> Result<Entry> {
        let dek = self.dek.as_ref().ok_or(CoreError::Locked)?;
        let key = entry_key(dek, id)?;
        let nonce: [u8; NONCE_LEN] = random_array()?;
        let ciphertext = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret.expose(),
                    aad: &entry_aad(id, label),
                },
            )
            .map_err(|_| CoreError::Crypto("entry encrypt"))?;
        Ok(Entry {
            id: id.to_owned(),
            label: label.to_owned(),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        })
    }

    fn open_entry(&self, entry: &Entry) -> Result<Secret> {
        let dek = self.dek.as_ref().ok_or(CoreError::Locked)?;
        let key = entry_key(dek, &entry.id)?;
        let nonce = decode_nonce(&entry.nonce_hex).ok_or(CoreError::Crypto("entry nonce"))?;
        let ciphertext = hex::decode(&entry.ciphertext_hex)
            .map_err(|_| CoreError::Crypto("entry ciphertext"))?;
        let plaintext = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &entry_aad(&entry.id, &entry.label),
                },
            )
            .map_err(|_| CoreError::Crypto("entry decrypt"))?;
        Ok(Secret::new(plaintext))
    }
}

impl Vault for EncryptedVault {
    fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    /// A wrong passphrase is `Unlock`; a correct passphrase over an entry set
    /// that was edited, truncated, reordered or partially rolled back is
    /// `Crypto("vault manifest")`. The vault stays locked in both cases.
    fn unlock(&mut self, passphrase: &Secret) -> Result<()> {
        let dek = unwrap_dek(&self.file, passphrase)?;
        self.file.verify_manifest_tag(&dek)?;
        self.dek = Some(dek);
        Ok(())
    }

    fn lock(&mut self) {
        self.dek = None;
    }

    /// Labels are unique: storing under an existing label replaces that entry
    /// and keeps its handle, so callers holding a handle to "device identity"
    /// are not invalidated by a rotation.
    fn put(&mut self, label: &str, secret: Secret) -> Result<SecretHandle> {
        if self.dek.is_none() {
            return Err(CoreError::Locked);
        }
        let existing = self.file.entries.iter().position(|e| e.label == label);
        let id = match existing {
            Some(i) => self.file.entries[i].id.clone(),
            None => hex::encode(random_array::<ENTRY_ID_LEN>()?),
        };
        let entry = self.seal_entry(&id, label, &secret)?;
        let mut entries = self.file.entries.clone();
        match existing {
            Some(i) => entries[i] = entry,
            None => entries.push(entry),
        }
        self.commit_entries(entries)?;
        Ok(SecretHandle(id))
    }

    fn with_secret<T>(&self, handle: &SecretHandle, f: &mut dyn FnMut(&Secret) -> T) -> Result<T> {
        if self.dek.is_none() {
            return Err(CoreError::Locked);
        }
        let entry = &self.file.entries[self.entry_index(handle)?];
        let secret = self.open_entry(entry)?;
        Ok(f(&secret))
    }

    fn delete(&mut self, handle: &SecretHandle) -> Result<()> {
        if self.dek.is_none() {
            return Err(CoreError::Locked);
        }
        let i = self.entry_index(handle)?;
        let mut entries = self.file.entries.clone();
        entries.remove(i);
        self.commit_entries(entries)
    }
}

/// Fresh OS randomness for key material, salts and nonces.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| CoreError::Crypto("rng"))?;
    Ok(buf)
}

fn decode_nonce(s: &str) -> Option<[u8; NONCE_LEN]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// HKDF-SHA256 over the DEK. Every consumer of the DEK (vault entries, the
/// store file) gets its own `info` string so no two uses share a key.
pub(crate) fn derive_subkey(dek: &Secret, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, dek.expose())
        .expand(info, key.as_mut())
        .map_err(|_| CoreError::Crypto("hkdf"))?;
    Ok(key)
}

fn derive_kek(file: &VaultFile, passphrase: &Secret) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    let salt = hex::decode(&file.kdf.salt_hex).map_err(|_| CoreError::Unlock)?;
    // Params that argon2 refuses can only come from a corrupted or forged file,
    // which is indistinguishable from a wrong passphrase to the caller.
    let argon = file.kdf.params.to_argon2().map_err(|_| CoreError::Unlock)?;
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    argon
        .hash_password_into(passphrase.expose(), &salt, kek.as_mut())
        .map_err(|_| CoreError::Unlock)?;
    Ok(kek)
}

fn wrap_dek(file: &VaultFile, passphrase: &Secret, dek: &Secret) -> Result<Sealed> {
    let kek = derive_kek(file, passphrase)?;
    let nonce: [u8; NONCE_LEN] = random_array()?;
    let ciphertext = XChaCha20Poly1305::new((&*kek).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: dek.expose(),
                aad: &file.wrap_aad(),
            },
        )
        .map_err(|_| CoreError::Crypto("dek wrap"))?;
    Ok(Sealed {
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn unwrap_dek(file: &VaultFile, passphrase: &Secret) -> Result<Secret> {
    let kek = derive_kek(file, passphrase)?;
    let nonce = decode_nonce(&file.wrapped_dek.nonce_hex).ok_or(CoreError::Unlock)?;
    let ciphertext =
        hex::decode(&file.wrapped_dek.ciphertext_hex).map_err(|_| CoreError::Unlock)?;
    let dek = XChaCha20Poly1305::new((&*kek).into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &file.wrap_aad(),
            },
        )
        .map_err(|_| CoreError::Unlock)?;
    if dek.len() != DEK_LEN {
        return Err(CoreError::Unlock);
    }
    Ok(Secret::new(dek))
}

fn entry_key(dek: &Secret, id: &str) -> Result<Zeroizing<[u8; 32]>> {
    derive_subkey(dek, format!("{ENTRY_INFO_PREFIX}{id}").as_bytes())
}

fn entry_aad(id: &str, label: &str) -> Vec<u8> {
    // Ids are fixed-width hex, so plain concatenation cannot be ambiguous.
    format!("{id}{label}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }

    #[test]
    fn secret_debug_does_not_leak() {
        let s = Secret::new(b"hunter2".to_vec());
        assert_eq!(format!("{s:?}"), "Secret(<7 bytes>)");
    }

    #[test]
    fn minimum_params_are_the_default() {
        assert_eq!(KdfParams::default(), KdfParams::MINIMUM);
        assert!(KdfParams::MINIMUM.meets_minimum());
        assert!(!KdfParams {
            t_cost: 1,
            ..KdfParams::MINIMUM
        }
        .meets_minimum());
    }

    #[test]
    fn locked_vault_refuses_everything_but_metadata() {
        let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
        let h = v.put("k", pass("v")).unwrap();
        v.lock();
        assert!(!v.is_unlocked());
        assert!(matches!(v.put("x", pass("y")), Err(CoreError::Locked)));
        assert!(matches!(
            v.with_secret(&h, &mut |_| ()),
            Err(CoreError::Locked)
        ));
        assert!(matches!(v.delete(&h), Err(CoreError::Locked)));
        assert!(matches!(v.dek(), Err(CoreError::Locked)));
        assert_eq!(v.handle_for("k"), Some(h));
        assert_eq!(v.labels().len(), 1);
    }

    #[test]
    fn put_on_existing_label_keeps_handle() {
        let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
        let h1 = v.put("id", pass("one")).unwrap();
        let h2 = v.put("id", pass("two")).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(v.labels().len(), 1);
        let got = v.with_secret(&h1, &mut |s| s.expose().to_vec()).unwrap();
        assert_eq!(got, b"two");
    }

    #[test]
    fn entry_aead_still_catches_tampering_beneath_the_manifest() {
        // The manifest tag fails first from the outside; this reaches past it
        // to check the per-entry layer stands on its own.
        let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
        v.put("label", pass("value")).unwrap();
        let mut entry = v.file.entries[0].clone();
        assert!(v.open_entry(&entry).is_ok());
        entry.label.push('!');
        assert!(matches!(
            v.open_entry(&entry),
            Err(CoreError::Crypto("entry decrypt"))
        ));
    }

    #[test]
    fn manifest_message_is_prefix_free() {
        let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
        v.put("ab", pass("1")).unwrap();
        v.put("c", pass("2")).unwrap();
        let a = v.file.manifest_message();
        let mut moved = v.file.clone();
        // Shift one character across the id/label boundary; the length
        // prefixes must keep the encodings distinct.
        let id_tail = moved.entries[0].id.pop().unwrap();
        moved.entries[0].label.insert(0, id_tail);
        assert_ne!(a, moved.manifest_message());
        let mut swapped = v.file.clone();
        swapped.entries.swap(0, 1);
        assert_ne!(a, swapped.manifest_message());
    }

    #[test]
    fn unknown_handle_is_invalid_not_crypto() {
        let v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
        let err = v
            .with_secret(&SecretHandle("nope".into()), &mut |_| ())
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid { .. }));
    }
}
