//! Moving a directory set (a folder, its subfolders, wallets, accounts and
//! the phrases of its `single` wallets) from one paired device to another.
//!
//! - Both ends must re-enter the vault passphrase (step-up), on top of the
//!   vault being unlocked: one factor to be in the instance, a fresh one to
//!   take a set out or bring one in. The passphrase is the strongest factor a
//!   vault has today; when platform or hardware factors land they join here.
//! - The bundle is sealed to the recipient's pinned X25519 static (ephemeral
//!   ECDH, HKDF, XChaCha20-Poly1305) and signed with the sender's Ed25519
//!   identity, so only the named device can open it and it can only have come
//!   from a device the recipient already paired with.
//! - The sender records the transfer (wallets become `copied`) before the
//!   bundle is returned; the recipient records every wallet and the set as
//!   `imported` from the sending device, and keeps any exposure history the
//!   wallets already had. Exposure is never washed out by a transfer.

use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256v10};
use sha2_v011::Sha256;
use zeroize::Zeroizing;

use crate::identity::{self, DeviceIdentity};
use crate::provenance::{
    self, load_provenance, save_provenance, Exposure, Origin, Transfer, WalletProvenance,
};
use crate::store::devices::load_device_table;
use crate::store::Device;
use crate::vault::{random_array, EncryptedVault, Secret, Vault};
use crate::{CoreError, Result};

pub const BUNDLE_PREFIX: &str = "stackwallet-set:";
const BUNDLE_VERSION: u8 = 1;
const HKDF_INFO: &[u8] = b"stackwallet/v1/set-bundle";
/// Large enough for thousands of accounts, small enough to refuse junk early.
pub const MAX_BUNDLE_CHARS: usize = 8 * 1024 * 1024;
const MAX_WALLETS: usize = 10_000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "set bundle",
        reason: reason.into(),
    }
}

/// What travels inside the encryption. `directory` is the UI's own JSON for
/// the folders, wallets and accounts; the core carries it opaquely and the
/// client validates it against its schemas on arrival.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Plain {
    folder_id: String,
    exported_at_ms: i64,
    directory: serde_json::Value,
    phrases: Vec<PhraseEntry>,
    history: Vec<WalletHistory>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhraseEntry {
    wallet_id: String,
    phrase: String,
}

impl Drop for PhraseEntry {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.phrase);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletHistory {
    wallet_id: String,
    exposures: Vec<Exposure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    v: u8,
    bundle_id: String,
    from_device_id: String,
    from_identity_hex: String,
    to_device_id: String,
    eph_pub_hex: String,
    nonce_hex: String,
    ciphertext_b64: String,
    signature_hex: String,
}

impl Envelope {
    /// Everything the signature and the AEAD bind, in a fixed order.
    fn header(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [
            &BUNDLE_VERSION.to_string(),
            &self.bundle_id,
            &self.from_device_id,
            &self.from_identity_hex,
            &self.to_device_id,
            &self.eph_pub_hex,
            &self.nonce_hex,
        ] {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut h = Sha256v10::new();
        h.update(b"stackwallet/v1/set-bundle/sig");
        h.update(self.header());
        h.update(self.ciphertext_b64.as_bytes());
        h.finalize().to_vec()
    }
}

fn aead_key(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    to_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(to_pub);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(HKDF_INFO, key.as_mut())
        .map_err(|_| CoreError::Crypto("hkdf"))?;
    Ok(key)
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).map_err(|_| invalid(format!("{what} is not hex")))?;
    v.try_into()
        .map_err(|_| invalid(format!("{what} is not 32 bytes")))
}

fn identity_from_vault(vault: &EncryptedVault, label: &str) -> Result<DeviceIdentity> {
    let handle = vault
        .handle_for(label)
        .ok_or_else(|| invalid(format!("no device identity under {label}")))?;
    vault.with_secret(&handle, &mut |seed| DeviceIdentity::from_secret(seed))?
}

fn active_peer(devices: &[Device], id: &str) -> Result<Device> {
    let d = devices
        .iter()
        .find(|d| d.id == id)
        .ok_or_else(|| invalid(format!("device {id} is not paired with this vault")))?;
    if d.revoked_at_ms.is_some() {
        return Err(invalid(format!("device {id} has been revoked")));
    }
    Ok(d.clone())
}

pub struct ExportRequest<'a> {
    pub identity_label: &'a str,
    pub passphrase: &'a Secret,
    pub to_device_id: &'a str,
    pub folder_id: &'a str,
    pub wallet_ids: &'a [String],
    pub directory_json: &'a str,
    pub now_ms: i64,
}

/// Seal a directory set for one paired device. Records the transfer first.
pub fn export_set(vault: &mut EncryptedVault, req: ExportRequest<'_>) -> Result<String> {
    vault.verify_passphrase(req.passphrase)?;
    if req.wallet_ids.len() > MAX_WALLETS {
        return Err(invalid("too many wallets"));
    }
    let me = identity_from_vault(vault, req.identity_label)?;
    let peer = active_peer(&load_device_table(vault)?, req.to_device_id)?;
    if peer.id == me.device_id() {
        return Err(invalid("a set cannot be sent to the device it is on"));
    }
    let directory: serde_json::Value =
        serde_json::from_str(req.directory_json).map_err(|e| invalid(format!("directory: {e}")))?;

    let table = load_provenance(vault)?;
    let mut phrases = Vec::new();
    let mut history = Vec::new();
    for id in req.wallet_ids {
        if provenance::has_single_key(vault, id) {
            phrases.push(PhraseEntry {
                wallet_id: id.clone(),
                phrase: provenance::phrase_for_transfer(vault, id)?,
            });
        }
        if let Some(w) = table.wallet(id) {
            history.push(WalletHistory {
                wallet_id: id.clone(),
                exposures: w.exposures.clone(),
            });
        }
    }

    let bundle_id = hex::encode(random_array::<16>()?);
    let plain = Zeroizing::new(
        serde_json::to_vec(&Plain {
            folder_id: req.folder_id.into(),
            exported_at_ms: req.now_ms,
            directory,
            phrases,
            history,
        })
        .map_err(|e| invalid(e.to_string()))?,
    );

    let to_pub = hex32(&peer.noise_static_hex, "recipient static")?;
    let eph = x25519_dalek::StaticSecret::from(random_array::<32>()?);
    let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let shared = Zeroizing::new(
        eph.diffie_hellman(&x25519_dalek::PublicKey::from(to_pub))
            .to_bytes(),
    );
    let key = aead_key(&shared, &eph_pub, &to_pub)?;
    let nonce: [u8; 24] = random_array()?;

    let mut env = Envelope {
        v: BUNDLE_VERSION,
        bundle_id: bundle_id.clone(),
        from_device_id: me.device_id(),
        from_identity_hex: me.public_hex(),
        to_device_id: peer.id.clone(),
        eph_pub_hex: hex::encode(eph_pub),
        nonce_hex: hex::encode(nonce),
        ciphertext_b64: String::new(),
        signature_hex: String::new(),
    };
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &env.header(),
            },
        )
        .map_err(|_| CoreError::Crypto("bundle encrypt"))?;
    env.ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ct);
    env.signature_hex = hex::encode(me.sign(&env.signed_bytes()));

    // The copy exists the moment the bundle does, so the record comes first.
    let mut table = table;
    let transfer = Transfer {
        at_ms: req.now_ms,
        to_device_id: peer.id.clone(),
        bundle_id,
    };
    table.record_set_transfer(req.folder_id, transfer.clone(), req.now_ms)?;
    for id in req.wallet_ids {
        if table.wallet(id).is_none() {
            // Watch and threshold wallets have no key history yet; the copy still counts.
            table.add_wallet(id, Origin::Created { at_ms: req.now_ms })?;
        }
        table.record_wallet_transfer(id, transfer.clone())?;
    }
    save_provenance(vault, &table)?;

    let json = serde_json::to_vec(&env).map_err(|e| invalid(e.to_string()))?;
    Ok(format!(
        "{BUNDLE_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    ))
}

/// What the client needs to merge an imported set into its directory.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedSet {
    pub bundle_id: String,
    pub folder_id: String,
    pub from_device_id: String,
    pub from_device_name: String,
    pub exported_at_ms: i64,
    pub directory: serde_json::Value,
    pub wallets_with_keys: Vec<String>,
}

/// Open a bundle addressed to this device from a pinned, unrevoked peer.
pub fn import_set(
    vault: &mut EncryptedVault,
    identity_label: &str,
    passphrase: &Secret,
    bundle: &str,
    now_ms: i64,
) -> Result<ImportedSet> {
    vault.verify_passphrase(passphrase)?;
    let text = bundle.trim();
    if text.len() > MAX_BUNDLE_CHARS {
        return Err(invalid("too large"));
    }
    let body = text
        .strip_prefix(BUNDLE_PREFIX)
        .ok_or_else(|| invalid("not a StackWallet set bundle"))?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| invalid("not base64url"))?;
    let env: Envelope = serde_json::from_slice(&json).map_err(|e| invalid(e.to_string()))?;
    if env.v != BUNDLE_VERSION {
        return Err(invalid(format!("unsupported version {}", env.v)));
    }

    let me = identity_from_vault(vault, identity_label)?;
    if env.to_device_id != me.device_id() {
        return Err(invalid("this bundle is addressed to a different device"));
    }
    let sender = active_peer(&load_device_table(vault)?, &env.from_device_id)?;
    if sender.identity_pub_hex != env.from_identity_hex {
        return Err(invalid("sender key does not match the pinned device"));
    }
    let sig: [u8; 64] = hex::decode(&env.signature_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| invalid("bad signature encoding"))?;
    identity::verify(&sender.identity_pub_hex, &env.signed_bytes(), &sig)?;

    let eph_pub = hex32(&env.eph_pub_hex, "ephemeral key")?;
    let nonce: [u8; 24] = hex::decode(&env.nonce_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| invalid("bad nonce"))?;
    let my_static = me.noise_static();
    let my_pub = me.noise_static_public();
    let shared = Zeroizing::new(
        my_static
            .diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub))
            .to_bytes(),
    );
    let key = aead_key(&shared, &eph_pub, &my_pub)?;
    let ct = base64::engine::general_purpose::STANDARD
        .decode(&env.ciphertext_b64)
        .map_err(|_| invalid("ciphertext is not base64"))?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ct,
                    aad: &env.header(),
                },
            )
            .map_err(|_| CoreError::Crypto("bundle decrypt"))?,
    );
    let plain: Plain = serde_json::from_slice(&plain).map_err(|e| invalid(e.to_string()))?;
    if plain.phrases.len() > MAX_WALLETS || plain.history.len() > MAX_WALLETS {
        return Err(invalid("too many wallets"));
    }

    let origin = Origin::ImportedFromDevice {
        at_ms: now_ms,
        device_id: sender.id.clone(),
        device_name: sender.name.clone(),
        bundle_id: env.bundle_id.clone(),
    };
    let mut table = load_provenance(vault)?;
    if table.set(&plain.folder_id).is_some() {
        return Err(invalid("this set is already on this device"));
    }
    // Validate every phrase and id before anything is written.
    let mut parsed = Vec::with_capacity(plain.phrases.len());
    for p in &plain.phrases {
        if provenance::has_single_key(vault, &p.wallet_id) || table.wallet(&p.wallet_id).is_some() {
            return Err(invalid(format!(
                "wallet {} is already on this device",
                p.wallet_id
            )));
        }
        parsed.push((p.wallet_id.clone(), crate::hd::Mnemonic::parse(&p.phrase)?));
    }
    table.add_set(&plain.folder_id, origin.clone())?;
    let mut keyed = Vec::new();
    for h in &plain.history {
        if table.wallet(&h.wallet_id).is_none() {
            table.wallets.push(WalletProvenance {
                wallet_id: h.wallet_id.clone(),
                origin: origin.clone(),
                exposures: h.exposures.clone(),
                transfers: Vec::new(),
            });
        }
    }
    for (id, _) in &parsed {
        if table.wallet(id).is_none() {
            table.add_wallet(id, origin.clone())?;
        }
    }
    table.validate()?;
    save_provenance(vault, &table)?;
    for (id, m) in &parsed {
        vault.put(
            &format!("mnemonic:{id}"),
            Secret::new(m.phrase().as_bytes().to_vec()),
        )?;
        keyed.push(id.clone());
    }

    Ok(ImportedSet {
        bundle_id: env.bundle_id,
        folder_id: plain.folder_id.clone(),
        from_device_id: sender.id,
        from_device_name: sender.name,
        exported_at_ms: plain.exported_at_ms,
        directory: plain.directory.clone(),
        wallets_with_keys: keyed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{create_single, reveal, Channel, Revealed};
    use crate::store::devices::save_device_table;
    use crate::store::DeviceKind;
    use crate::vault::KdfParams;

    const ID: &str = "device-identity";

    fn vault_with_identity() -> (EncryptedVault, DeviceIdentity) {
        let mut v =
            EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap();
        let id = DeviceIdentity::generate().unwrap();
        v.put(ID, id.to_secret()).unwrap();
        (v, id)
    }

    fn as_device(id: &DeviceIdentity, name: &str) -> Device {
        Device {
            id: id.device_id(),
            name: name.into(),
            kind: DeviceKind::Browser,
            identity_pub_hex: id.public_hex(),
            noise_static_hex: id.noise_static_public_hex(),
            endpoints: vec![],
            paired_at_ms: 1,
            last_seen_at_ms: None,
            revoked_at_ms: None,
        }
    }

    fn pw() -> Secret {
        Secret::new(b"pw".to_vec())
    }

    fn paired() -> (
        EncryptedVault,
        DeviceIdentity,
        EncryptedVault,
        DeviceIdentity,
    ) {
        let (mut a, ida) = vault_with_identity();
        let (mut b, idb) = vault_with_identity();
        save_device_table(&mut a, &[as_device(&idb, "phone")]).unwrap();
        save_device_table(&mut b, &[as_device(&ida, "desktop")]).unwrap();
        (a, ida, b, idb)
    }

    fn export(a: &mut EncryptedVault, to: &DeviceIdentity, wallets: &[String]) -> Result<String> {
        export_set(
            a,
            ExportRequest {
                identity_label: ID,
                passphrase: &pw(),
                to_device_id: &to.device_id(),
                folder_id: "set1",
                wallet_ids: wallets,
                directory_json: r#"{"folders":[],"wallets":[],"accounts":[]}"#,
                now_ms: 100,
            },
        )
    }

    #[test]
    fn round_trip_marks_both_sides_and_keeps_exposure() {
        let (mut a, _ida, mut b, idb) = paired();
        create_single(&mut a, "w1", 1).unwrap();
        create_single(&mut a, "w2", 1).unwrap();
        reveal(&mut a, "w2", &pw(), Revealed::Mnemonic, Channel::Screen, 2).unwrap();
        let wallets = vec!["w1".to_string(), "w2".to_string(), "watch".to_string()];
        let bundle = export(&mut a, &idb, &wallets).unwrap();
        assert!(bundle.starts_with(BUNDLE_PREFIX));
        assert!(!bundle.contains("abandon"));

        let sent = load_provenance(&a).unwrap();
        assert_eq!(sent.wallet("w1").unwrap().transfers.len(), 1);
        assert_eq!(sent.wallet("watch").unwrap().transfers.len(), 1);
        assert_eq!(sent.set("set1").unwrap().transfers.len(), 1);

        let got = import_set(&mut b, ID, &pw(), &bundle, 200).unwrap();
        assert_eq!(got.folder_id, "set1");
        assert_eq!(got.from_device_name, "desktop");
        assert_eq!(got.wallets_with_keys, vec!["w1", "w2"]);
        let recv = load_provenance(&b).unwrap();
        assert!(recv.set("set1").unwrap().origin.is_imported());
        assert!(recv.wallet("w1").unwrap().origin.is_imported());
        assert!(recv.wallet("w1").unwrap().exposures.is_empty());
        assert_eq!(
            recv.wallet("w2").unwrap().exposures.len(),
            1,
            "exposure travels"
        );

        // Same keys on both ends.
        let path = "m/44'/60'/0'/0/0";
        assert_eq!(
            provenance::public_key(&a, "w1", crate::model::Curve::Secp256k1, path).unwrap(),
            provenance::public_key(&b, "w1", crate::model::Curve::Secp256k1, path).unwrap()
        );
        // Replays are refused.
        assert!(import_set(&mut b, ID, &pw(), &bundle, 300).is_err());
    }

    #[test]
    fn only_the_addressed_paired_device_can_open_it() {
        let (mut a, ida, mut b, idb) = paired();
        create_single(&mut a, "w1", 1).unwrap();
        let bundle = export(&mut a, &idb, &["w1".into()]).unwrap();

        let (mut c, _idc) = vault_with_identity();
        save_device_table(&mut c, &[as_device(&ida, "desktop")]).unwrap();
        assert!(
            import_set(&mut c, ID, &pw(), &bundle, 1).is_err(),
            "wrong recipient"
        );

        let mut revoked = as_device(&ida, "desktop");
        revoked.revoked_at_ms = Some(5);
        save_device_table(&mut b, &[revoked]).unwrap();
        assert!(
            import_set(&mut b, ID, &pw(), &bundle, 1).is_err(),
            "revoked sender"
        );
    }

    #[test]
    fn tampering_and_wrong_passphrase_are_refused() {
        let (mut a, _ida, mut b, idb) = paired();
        create_single(&mut a, "w1", 1).unwrap();
        let bundle = export(&mut a, &idb, &["w1".into()]).unwrap();
        assert!(import_set(&mut b, ID, &Secret::new(b"x".to_vec()), &bundle, 1).is_err());

        let body = bundle.strip_prefix(BUNDLE_PREFIX).unwrap();
        let mut env: Envelope = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .unwrap(),
        )
        .unwrap();
        env.bundle_id = "00".repeat(16);
        let forged = format!(
            "{BUNDLE_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&env).unwrap())
        );
        assert!(import_set(&mut b, ID, &pw(), &forged, 1).is_err());
        assert!(import_set(&mut b, ID, &pw(), "stackwallet-set:@@@", 1).is_err());
        // Nothing was written by the refusals.
        assert!(load_provenance(&b).unwrap().wallets.is_empty());
    }

    #[test]
    fn export_needs_passphrase_and_a_live_peer() {
        let (mut a, _ida, _b, idb) = paired();
        let err = export_set(
            &mut a,
            ExportRequest {
                identity_label: ID,
                passphrase: &Secret::new(b"x".to_vec()),
                to_device_id: &idb.device_id(),
                folder_id: "set1",
                wallet_ids: &[],
                directory_json: "{}",
                now_ms: 1,
            },
        );
        assert!(err.is_err());
        let stranger = DeviceIdentity::generate().unwrap();
        assert!(export(&mut a, &stranger, &[]).is_err());
        assert!(
            load_provenance(&a).unwrap().sets.is_empty(),
            "no record without a bundle"
        );
    }
}
