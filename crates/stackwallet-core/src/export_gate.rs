//! The gate every export passes: a phrase or private key to the screen or
//! clipboard, one wallet to another device, or a whole directory.
//!
//! Three independent checks, all in the core:
//!
//! 1. **Session**: the person at this device opens its session again, with
//!    the passphrase or a passkey. A PIN opens a session but never an export.
//! 2. **Directory key**: a secret the user sets per folder. Exporting a wallet
//!    needs the key of the folder it sits in; exporting a directory needs the
//!    key of that directory.
//! 3. **Wallet key**: a secret the user sets per wallet, needed for every
//!    export of that wallet on its own (reveal or transfer).
//!
//! Export keys are stored as Argon2id verifiers inside the vault, so they are
//! encrypted at rest and never leave the device. They are set or changed only
//! with a fresh session proof, and changing one needs the old one too.
//!
//! The directory tree itself still lives in the client's interim store, so
//! the core trusts the client for *which* folder a wallet is in. The wallet
//! key is bound to the wallet id and cannot be satisfied by another wallet's.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::vault::{random_array, EncryptedVault, KdfParams, Secret, SessionProof, Vault};
use crate::{CoreError, Result};

const LABEL_PREFIX: &str = "export-key:";
pub const MIN_EXPORT_KEY_CHARS: usize = 8;
pub const MAX_EXPORT_KEY_BYTES: usize = 1024;
const MAX_ID_LEN: usize = 128;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "export key",
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyScope {
    Folder,
    Wallet,
}

impl KeyScope {
    fn as_str(self) -> &'static str {
        match self {
            KeyScope::Folder => "folder",
            KeyScope::Wallet => "wallet",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            KeyScope::Folder => "directory",
            KeyScope::Wallet => "wallet",
        }
    }
}

fn label(scope: KeyScope, id: &str) -> Result<String> {
    if id.is_empty() || id.len() > MAX_ID_LEN || id.chars().any(|c| c.is_control()) {
        return Err(invalid(format!("bad id {id:?}")));
    }
    Ok(format!("{LABEL_PREFIX}{}:{id}", scope.as_str()))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Verifier {
    #[serde(flatten)]
    params: KdfParams,
    salt_hex: String,
    hash_hex: String,
}

fn stretch(params: KdfParams, key: &Secret, salt: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    params.validate()?;
    let p = argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| invalid("kdf params rejected"))?;
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(key.expose(), salt, out.as_mut())
        .map_err(|_| CoreError::Crypto("export key kdf"))?;
    Ok(out)
}

/// Whether `scope`/`id` has an export key. Readable while locked (labels are metadata).
pub fn has_export_key(vault: &EncryptedVault, scope: KeyScope, id: &str) -> bool {
    label(scope, id).is_ok_and(|l| vault.handle_for(&l).is_some())
}

/// Every folder and wallet id with an export key, for the UI's "key set" marks.
pub fn export_key_ids(vault: &EncryptedVault) -> Vec<(KeyScope, String)> {
    vault
        .labels()
        .into_iter()
        .filter_map(|(_, l)| {
            let rest = l.strip_prefix(LABEL_PREFIX)?;
            let (scope, id) = rest.split_once(':')?;
            let scope = match scope {
                "folder" => KeyScope::Folder,
                "wallet" => KeyScope::Wallet,
                _ => return None,
            };
            Some((scope, id.to_owned()))
        })
        .collect()
}

/// Set or change the export key of one folder or wallet. Needs a session proof
/// that is not a PIN, and the current key when one exists.
pub fn set_export_key(
    vault: &mut EncryptedVault,
    scope: KeyScope,
    id: &str,
    session: &SessionProof,
    current: Option<&Secret>,
    next: &Secret,
) -> Result<()> {
    vault.verify_session(session, false)?;
    let l = label(scope, id)?;
    if vault.handle_for(&l).is_some() {
        let current =
            current.ok_or_else(|| invalid(format!("enter the current {} key", scope.noun())))?;
        verify_export_key(vault, scope, id, current)?;
    }
    let text = std::str::from_utf8(next.expose()).map_err(|_| invalid("not utf-8"))?;
    if text.chars().count() < MIN_EXPORT_KEY_CHARS || next.len() > MAX_EXPORT_KEY_BYTES {
        return Err(invalid(format!(
            "a {} key has at least {MIN_EXPORT_KEY_CHARS} characters",
            scope.noun()
        )));
    }
    let params = vault.kdf_params();
    let salt = random_array::<16>()?;
    let hash = stretch(params, next, &salt)?;
    let v = Verifier {
        params,
        salt_hex: hex::encode(salt),
        hash_hex: hex::encode(&hash[..]),
    };
    let bytes = serde_json::to_vec(&v).map_err(|e| invalid(e.to_string()))?;
    vault.put(&l, Secret::new(bytes))?;
    Ok(())
}

/// Check one export key. Missing keys fail: an export cannot proceed until
/// the user has set the keys it needs.
pub fn verify_export_key(
    vault: &EncryptedVault,
    scope: KeyScope,
    id: &str,
    key: &Secret,
) -> Result<()> {
    let l = label(scope, id)?;
    let handle = vault.handle_for(&l).ok_or_else(|| {
        invalid(format!(
            "this {} has no export key yet; set one first",
            scope.noun()
        ))
    })?;
    let ok = vault.with_secret(&handle, &mut |bytes| -> Result<bool> {
        let v: Verifier =
            serde_json::from_slice(bytes.expose()).map_err(|_| invalid("unreadable verifier"))?;
        let salt = hex::decode(&v.salt_hex).map_err(|_| invalid("unreadable verifier"))?;
        let want = hex::decode(&v.hash_hex).map_err(|_| invalid("unreadable verifier"))?;
        let got = stretch(v.params, key, &salt)?;
        Ok(bool::from(got[..].ct_eq(want.as_slice())))
    })??;
    if !ok {
        return Err(invalid(format!("wrong {} key", scope.noun())));
    }
    Ok(())
}

/// Everything an export presents. `wallet_key` is required for single-wallet
/// exports and ignored for directory exports.
pub struct ExportGate<'a> {
    pub session: &'a SessionProof,
    pub folder_id: &'a str,
    pub folder_key: &'a Secret,
    pub wallet_key: Option<&'a Secret>,
}

/// Session, the parent directory's key and the wallet's own key.
pub fn check_wallet_export(
    vault: &EncryptedVault,
    gate: &ExportGate<'_>,
    wallet_id: &str,
) -> Result<()> {
    vault.verify_session(gate.session, false)?;
    verify_export_key(vault, KeyScope::Folder, gate.folder_id, gate.folder_key)?;
    let key = gate
        .wallet_key
        .ok_or_else(|| invalid("exporting a wallet needs its wallet key"))?;
    verify_export_key(vault, KeyScope::Wallet, wallet_id, key)
}

/// Session and the exported directory's key.
pub fn check_directory_export(vault: &EncryptedVault, gate: &ExportGate<'_>) -> Result<()> {
    vault.verify_session(gate.session, false)?;
    verify_export_key(vault, KeyScope::Folder, gate.folder_id, gate.folder_key)
}

/// Fixtures for tests elsewhere in the crate that need to get past the gate.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub const FOLDER: &str = "folder-under-test";

    pub struct Keys {
        pub session: SessionProof,
        pub folder: Secret,
        pub wallet: Secret,
    }

    impl Keys {
        pub fn gate(&self) -> ExportGate<'_> {
            ExportGate {
                session: &self.session,
                folder_id: FOLDER,
                folder_key: &self.folder,
                wallet_key: Some(&self.wallet),
            }
        }
    }

    /// Set the test folder's key and the keys of `wallets` on a vault whose
    /// passphrase is `pw`, and return what an export presents.
    pub fn keys(vault: &mut EncryptedVault, pw: &str, wallets: &[&str]) -> Keys {
        let session = || SessionProof::Passphrase(Secret::new(pw.as_bytes().to_vec()));
        if !has_export_key(vault, KeyScope::Folder, FOLDER) {
            set_export_key(
                vault,
                KeyScope::Folder,
                FOLDER,
                &session(),
                None,
                &Secret::new(b"folder-key".to_vec()),
            )
            .unwrap();
        }
        for w in wallets {
            if !has_export_key(vault, KeyScope::Wallet, w) {
                set_export_key(
                    vault,
                    KeyScope::Wallet,
                    w,
                    &session(),
                    None,
                    &Secret::new(b"wallet-key".to_vec()),
                )
                .unwrap();
            }
        }
        Keys {
            session: session(),
            folder: Secret::new(b"folder-key".to_vec()),
            wallet: Secret::new(b"wallet-key".to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{SlotKind, SlotSecret};

    fn s(t: &str) -> Secret {
        Secret::new(t.as_bytes().to_vec())
    }

    fn vault() -> EncryptedVault {
        EncryptedVault::create(&s("pw"), KdfParams::MINIMUM).unwrap()
    }

    fn pw() -> SessionProof {
        SessionProof::Passphrase(s("pw"))
    }

    #[test]
    fn keys_are_set_with_a_session_and_changed_with_the_old_key() {
        let mut v = vault();
        assert!(!has_export_key(&v, KeyScope::Folder, "f1"));
        assert!(set_export_key(
            &mut v,
            KeyScope::Folder,
            "f1",
            &SessionProof::Passphrase(s("x")),
            None,
            &s("folder-key")
        )
        .is_err());
        assert!(set_export_key(&mut v, KeyScope::Folder, "f1", &pw(), None, &s("short")).is_err());
        set_export_key(
            &mut v,
            KeyScope::Folder,
            "f1",
            &pw(),
            None,
            &s("folder-key"),
        )
        .unwrap();
        assert!(has_export_key(&v, KeyScope::Folder, "f1"));
        assert!(
            !has_export_key(&v, KeyScope::Wallet, "f1"),
            "scopes are separate"
        );
        verify_export_key(&v, KeyScope::Folder, "f1", &s("folder-key")).unwrap();
        assert!(verify_export_key(&v, KeyScope::Folder, "f1", &s("folder-kez")).is_err());

        assert!(set_export_key(
            &mut v,
            KeyScope::Folder,
            "f1",
            &pw(),
            None,
            &s("next-key-1")
        )
        .is_err());
        assert!(set_export_key(
            &mut v,
            KeyScope::Folder,
            "f1",
            &pw(),
            Some(&s("wrong-key")),
            &s("next-key-1")
        )
        .is_err());
        set_export_key(
            &mut v,
            KeyScope::Folder,
            "f1",
            &pw(),
            Some(&s("folder-key")),
            &s("next-key-1"),
        )
        .unwrap();
        verify_export_key(&v, KeyScope::Folder, "f1", &s("next-key-1")).unwrap();
        assert_eq!(
            export_key_ids(&v),
            vec![(KeyScope::Folder, "f1".to_string())]
        );
    }

    #[test]
    fn a_pin_session_cannot_set_keys_or_export() {
        let mut v = vault();
        let device = Secret::new(vec![3; 32]);
        let id = v
            .add_slot(
                &s("pw"),
                SlotKind::Pin,
                "PIN",
                None,
                &SlotSecret {
                    secret: s("123456"),
                    device: Some(Secret::new(vec![3; 32])),
                },
                1,
            )
            .unwrap();
        let pin = SessionProof::Slot {
            id,
            secret: SlotSecret {
                secret: s("123456"),
                device: Some(device),
            },
        };
        assert!(
            set_export_key(&mut v, KeyScope::Folder, "f", &pin, None, &s("folder-key")).is_err()
        );
        set_export_key(&mut v, KeyScope::Folder, "f", &pw(), None, &s("folder-key")).unwrap();
        set_export_key(&mut v, KeyScope::Wallet, "w", &pw(), None, &s("wallet-key")).unwrap();
        let fk = s("folder-key");
        let wk = s("wallet-key");
        let gate = |session| ExportGate {
            session,
            folder_id: "f",
            folder_key: &fk,
            wallet_key: Some(&wk),
        };
        assert!(check_wallet_export(&v, &gate(&pin), "w").is_err());
        let session = pw();
        check_wallet_export(&v, &gate(&session), "w").unwrap();
        check_directory_export(&v, &gate(&session)).unwrap();
    }

    #[test]
    fn every_part_of_the_gate_is_required() {
        let mut v = vault();
        set_export_key(&mut v, KeyScope::Folder, "f", &pw(), None, &s("folder-key")).unwrap();
        let fk = s("folder-key");
        let wk = s("wallet-key");
        let session = pw();
        let gate = ExportGate {
            session: &session,
            folder_id: "f",
            folder_key: &fk,
            wallet_key: Some(&wk),
        };
        assert!(
            check_wallet_export(&v, &gate, "w").is_err(),
            "wallet has no key yet"
        );
        set_export_key(&mut v, KeyScope::Wallet, "w", &pw(), None, &s("wallet-key")).unwrap();
        check_wallet_export(&v, &gate, "w").unwrap();
        assert!(
            check_wallet_export(&v, &gate, "other").is_err(),
            "keys are per wallet"
        );
        let no_wallet_key = ExportGate {
            wallet_key: None,
            ..gate
        };
        assert!(check_wallet_export(&v, &no_wallet_key, "w").is_err());
        let wrong_folder = ExportGate {
            folder_id: "g",
            ..no_wallet_key
        };
        assert!(check_directory_export(&v, &wrong_folder).is_err());
    }
}
