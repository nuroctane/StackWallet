//! Where every key came from and where it has been. The UI turns this into
//! the wallet tags the user always sees:
//!
//! - `exposed`: a private key or phrase of the wallet has left the vault
//!   (screen, clipboard or file). Permanent.
//! - `imported`: the wallet or set arrived from somewhere else (another
//!   device, or a phrase that existed before StackWallet saw it).
//! - `copied`: the wallet was transferred to another device, so a second copy
//!   exists even though no key was ever shown.
//! - none of these on a `single` wallet: local only, and therefore without any
//!   backup.
//!
//! The table is sealed in the vault and only grows: the functions here append
//! and there is no API to remove an exposure. Every reveal records the
//! exposure and seals the table *before* the secret is returned, so a failure
//! to record means the secret never leaves.

use serde::{Deserialize, Serialize};

use crate::export_gate::{check_wallet_export, ExportGate};
use crate::hd::{self, Mnemonic};
use crate::model::Curve;
use crate::vault::{EncryptedVault, Secret, Vault};
use crate::{CoreError, Result};

pub const PROVENANCE_LABEL: &str = "provenance";
const MNEMONIC_LABEL_PREFIX: &str = "mnemonic:";
pub const MAX_TRACKED: usize = 10_000;
const MAX_EVENTS_PER_ITEM: usize = 1_000;
const MAX_ID_LEN: usize = 128;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "provenance",
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Origin {
    /// Generated inside this vault.
    Created { at_ms: i64 },
    /// Typed or pasted by the user: the phrase existed before this vault did.
    ImportedPhrase { at_ms: i64 },
    /// Arrived in a directory-set transfer from another device.
    ImportedFromDevice {
        at_ms: i64,
        device_id: String,
        device_name: String,
        bundle_id: String,
    },
}

impl Origin {
    pub fn is_imported(&self) -> bool {
        !matches!(self, Origin::Created { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Screen,
    Clipboard,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Revealed {
    Mnemonic,
    PrivateKey { curve: Curve, path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exposure {
    pub at_ms: i64,
    pub channel: Channel,
    pub what: Revealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
    pub at_ms: i64,
    pub to_device_id: String,
    pub bundle_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletProvenance {
    pub wallet_id: String,
    pub origin: Origin,
    #[serde(default)]
    pub exposures: Vec<Exposure>,
    #[serde(default)]
    pub transfers: Vec<Transfer>,
}

/// A directory set is a folder and everything beneath it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProvenance {
    pub folder_id: String,
    pub origin: Origin,
    #[serde(default)]
    pub transfers: Vec<Transfer>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvenanceTable {
    #[serde(default)]
    pub wallets: Vec<WalletProvenance>,
    #[serde(default)]
    pub sets: Vec<SetProvenance>,
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID_LEN || id.chars().any(|c| c.is_control()) {
        return Err(invalid(format!("bad id {id:?}")));
    }
    Ok(())
}

impl ProvenanceTable {
    pub fn validate(&self) -> Result<()> {
        if self.wallets.len() > MAX_TRACKED || self.sets.len() > MAX_TRACKED {
            return Err(invalid("too many records"));
        }
        let mut seen = std::collections::HashSet::new();
        for w in &self.wallets {
            check_id(&w.wallet_id)?;
            if !seen.insert(("w", w.wallet_id.as_str())) {
                return Err(invalid(format!("wallet {} appears twice", w.wallet_id)));
            }
            if w.exposures.len() > MAX_EVENTS_PER_ITEM || w.transfers.len() > MAX_EVENTS_PER_ITEM {
                return Err(invalid("too many events"));
            }
        }
        for s in &self.sets {
            check_id(&s.folder_id)?;
            if !seen.insert(("s", s.folder_id.as_str())) {
                return Err(invalid(format!("set {} appears twice", s.folder_id)));
            }
            if s.transfers.len() > MAX_EVENTS_PER_ITEM {
                return Err(invalid("too many events"));
            }
        }
        Ok(())
    }

    pub fn wallet(&self, id: &str) -> Option<&WalletProvenance> {
        self.wallets.iter().find(|w| w.wallet_id == id)
    }

    fn wallet_mut(&mut self, id: &str) -> Result<&mut WalletProvenance> {
        self.wallets
            .iter_mut()
            .find(|w| w.wallet_id == id)
            .ok_or_else(|| invalid(format!("no provenance for wallet {id}")))
    }

    pub fn set(&self, folder_id: &str) -> Option<&SetProvenance> {
        self.sets.iter().find(|s| s.folder_id == folder_id)
    }

    /// First origin wins: a wallet's history is never rewritten by a later import.
    pub fn add_wallet(&mut self, wallet_id: &str, origin: Origin) -> Result<()> {
        check_id(wallet_id)?;
        if self.wallet(wallet_id).is_some() {
            return Err(invalid(format!("wallet {wallet_id} already has a history")));
        }
        self.wallets.push(WalletProvenance {
            wallet_id: wallet_id.into(),
            origin,
            exposures: Vec::new(),
            transfers: Vec::new(),
        });
        Ok(())
    }

    pub fn record_exposure(&mut self, wallet_id: &str, exposure: Exposure) -> Result<()> {
        let w = self.wallet_mut(wallet_id)?;
        if w.exposures.len() >= MAX_EVENTS_PER_ITEM {
            // Saturated: the wallet is exposed either way; keep the first record set.
            return Ok(());
        }
        w.exposures.push(exposure);
        Ok(())
    }

    pub fn record_wallet_transfer(&mut self, wallet_id: &str, t: Transfer) -> Result<()> {
        let w = self.wallet_mut(wallet_id)?;
        if w.transfers.len() < MAX_EVENTS_PER_ITEM {
            w.transfers.push(t);
        }
        Ok(())
    }

    pub fn record_set_transfer(&mut self, folder_id: &str, t: Transfer, now_ms: i64) -> Result<()> {
        check_id(folder_id)?;
        if self.set(folder_id).is_none() {
            self.sets.push(SetProvenance {
                folder_id: folder_id.into(),
                origin: Origin::Created { at_ms: now_ms },
                transfers: Vec::new(),
            });
        }
        let s = self
            .sets
            .iter_mut()
            .find(|s| s.folder_id == folder_id)
            .expect("inserted above");
        if s.transfers.len() < MAX_EVENTS_PER_ITEM {
            s.transfers.push(t);
        }
        Ok(())
    }

    pub fn add_set(&mut self, folder_id: &str, origin: Origin) -> Result<()> {
        check_id(folder_id)?;
        if self.set(folder_id).is_some() {
            return Err(invalid(format!("set {folder_id} already has a history")));
        }
        self.sets.push(SetProvenance {
            folder_id: folder_id.into(),
            origin,
            transfers: Vec::new(),
        });
        Ok(())
    }

    /// True when `next` keeps every record of `self` (same origins, no events
    /// removed). Saves go through this so no path can quietly shrink history.
    pub fn is_extended_by(&self, next: &ProvenanceTable) -> bool {
        self.wallets.iter().all(|old| {
            next.wallet(&old.wallet_id).is_some_and(|new| {
                new.origin == old.origin
                    && new.exposures.starts_with(&old.exposures)
                    && new.transfers.starts_with(&old.transfers)
            })
        }) && self.sets.iter().all(|old| {
            next.set(&old.folder_id).is_some_and(|new| {
                new.origin == old.origin && new.transfers.starts_with(&old.transfers)
            })
        })
    }
}

pub fn load_provenance(vault: &EncryptedVault) -> Result<ProvenanceTable> {
    let Some(handle) = vault.handle_for(PROVENANCE_LABEL) else {
        return Ok(ProvenanceTable::default());
    };
    let table = vault.with_secret(&handle, &mut |bytes| {
        serde_json::from_slice::<ProvenanceTable>(bytes.expose())
            .map_err(|e| invalid(format!("unreadable: {e}")))
    })??;
    table.validate()?;
    Ok(table)
}

/// Seal `next`, refusing any table that drops history already sealed.
pub fn save_provenance(vault: &mut EncryptedVault, next: &ProvenanceTable) -> Result<()> {
    next.validate()?;
    let current = load_provenance(vault)?;
    if !current.is_extended_by(next) {
        return Err(invalid("a save may only add history, never remove it"));
    }
    let bytes = serde_json::to_vec(next).map_err(|e| invalid(e.to_string()))?;
    vault.put(PROVENANCE_LABEL, Secret::new(bytes))?;
    Ok(())
}

fn mnemonic_label(wallet_id: &str) -> String {
    format!("{MNEMONIC_LABEL_PREFIX}{wallet_id}")
}

pub fn has_single_key(vault: &EncryptedVault, wallet_id: &str) -> bool {
    vault.handle_for(&mnemonic_label(wallet_id)).is_some()
}

fn store_phrase(
    vault: &mut EncryptedVault,
    wallet_id: &str,
    phrase: &Mnemonic,
    origin: Origin,
) -> Result<()> {
    check_id(wallet_id)?;
    if has_single_key(vault, wallet_id) {
        return Err(invalid(format!("wallet {wallet_id} already holds a key")));
    }
    let mut table = load_provenance(vault)?;
    table.add_wallet(wallet_id, origin)?;
    // History first: a key never exists in the vault without its origin recorded.
    save_provenance(vault, &table)?;
    vault.put(
        &mnemonic_label(wallet_id),
        Secret::new(phrase.phrase().as_bytes().to_vec()),
    )?;
    Ok(())
}

/// Generate a fresh 24-word phrase for a new `single` wallet.
pub fn create_single(vault: &mut EncryptedVault, wallet_id: &str, now_ms: i64) -> Result<()> {
    let phrase = Mnemonic::generate()?;
    store_phrase(vault, wallet_id, &phrase, Origin::Created { at_ms: now_ms })
}

/// Seal a phrase the user brought from elsewhere; it starts life `imported`.
pub fn import_phrase(
    vault: &mut EncryptedVault,
    wallet_id: &str,
    phrase: &str,
    now_ms: i64,
) -> Result<()> {
    let m = Mnemonic::parse(phrase)?;
    store_phrase(
        vault,
        wallet_id,
        &m,
        Origin::ImportedPhrase { at_ms: now_ms },
    )
}

fn with_mnemonic<T>(
    vault: &EncryptedVault,
    wallet_id: &str,
    f: impl Fn(&Mnemonic) -> Result<T>,
) -> Result<T> {
    let handle = vault
        .handle_for(&mnemonic_label(wallet_id))
        .ok_or_else(|| invalid(format!("wallet {wallet_id} holds no key")))?;
    vault.with_secret(&handle, &mut |bytes| {
        let text =
            std::str::from_utf8(bytes.expose()).map_err(|_| invalid("phrase is not utf-8"))?;
        f(&Mnemonic::parse(text)?)
    })?
}

/// The account index of a CIP-1852 payment path `m/1852'/1815'/{i}'/0/0`.
/// Cardano wallets derive with Icarus BIP32-Ed25519, which SLIP-10 cannot
/// reproduce, so these paths take their own route.
pub(crate) fn cardano_account(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("m/1852'/1815'/")?;
    let account = rest.strip_suffix("'/0/0")?;
    if account.is_empty() || (account.len() > 1 && account.starts_with('0')) {
        return None;
    }
    account.parse::<u32>().ok().filter(|i| *i < 0x8000_0000)
}

/// The account index of a Chia wallet path `m/12381'/8444'/2'/{i}'` (EIP-2334).
/// Chia keys are BLS12-381 scalars derived by EIP-2333, which SLIP-10 cannot
/// reproduce, so these paths take their own route.
pub(crate) fn chia_account(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("m/12381'/8444'/2'/")?;
    let account = rest.strip_suffix("'")?;
    if account.is_empty() || (account.len() > 1 && account.starts_with('0')) {
        return None;
    }
    account.parse::<u32>().ok()
}

/// Payment and stake keys of a Cardano account. Never leaves the core.
pub(crate) fn cardano_keys(
    vault: &EncryptedVault,
    wallet_id: &str,
    account: u32,
) -> Result<crate::cardano::AccountKeys> {
    with_mnemonic(vault, wallet_id, |m| {
        crate::cardano::account_keys(m, "", account)
    })
}

/// Public key at `path`; the private key never leaves this call. For a
/// Cardano payment path this is payment key || stake key (64 bytes), which is
/// what a base address is built from.
pub fn public_key(
    vault: &EncryptedVault,
    wallet_id: &str,
    curve: Curve,
    path: &str,
) -> Result<String> {
    if let Some(account) = cardano_account(path) {
        return Ok(hex::encode(
            cardano_keys(vault, wallet_id, account)?.public(),
        ));
    }
    if path.starts_with("m/44'/9004'/") {
        // Starknet: the account key is the Stark public key (EIP-2645 grindKey
        // of the secp256k1 secret); the SEC1 point cannot derive the address.
        return with_mnemonic(vault, wallet_id, |m| {
            let key = hd::derive(m.to_seed("").as_ref(), Curve::Secp256k1, path)?;
            Ok(hex::encode(crate::starknet::stark_public_key(
                key.secret(),
            )?))
        });
    }
    if let Some(account) = chia_account(path) {
        // Chia: the account key is the 48-byte compressed G1 of the EIP-2333
        // wallet scalar, not any HD curve's public key.
        return with_mnemonic(vault, wallet_id, |m| {
            let master = crate::chia::master_sk_from_seed(m.to_seed("").as_ref())?;
            let sk = crate::chia::wallet_sk(&master, account)?;
            Ok(hex::encode(crate::chia::public_key(&sk)?))
        });
    }
    if path.starts_with("m/44'/5741564'/") {
        // Waves: the account key is the axolotl Curve25519 key derived from the
        // SLIP-10 seed, not the ed25519 verifying key.
        return with_mnemonic(vault, wallet_id, |m| {
            let key = hd::derive(m.to_seed("").as_ref(), Curve::Ed25519, path)?;
            Ok(hex::encode(crate::waves::public_key(key.secret())))
        });
    }
    if path.starts_with("m/44'/2365'/") {
        // Mixin: the account key is the 64-byte spend || view public key the
        // kernel derives from the SLIP-10 seed, not the ed25519 point.
        return with_mnemonic(vault, wallet_id, |m| {
            let key = hd::derive(m.to_seed("").as_ref(), Curve::Ed25519, path)?;
            Ok(hex::encode(crate::mixin::public_from_secret(key.secret())))
        });
    }
    if path.starts_with("m/44'/83293'/") {
        // Qubic: the account key is the FourQ point; the SLIP-10 seed is the
        // SchnorrQ subseed directly, so the ed25519 point is meaningless.
        return with_mnemonic(vault, wallet_id, |m| {
            let key = hd::derive(m.to_seed("").as_ref(), Curve::Ed25519, path)?;
            Ok(hex::encode(crate::qubic::public_key(key.secret())?))
        });
    }
    with_mnemonic(vault, wallet_id, |m| {
        Ok(hd::derive(m.to_seed("").as_ref(), curve, path)?.public_hex())
    })
}

/// What a reveal hands back. Debug never prints the secret.
pub struct RevealedSecret {
    pub what: Revealed,
    pub secret: zeroize::Zeroizing<String>,
    pub public_hex: Option<String>,
}

impl std::fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RevealedSecret({:?})", self.what)
    }
}

/// Take a phrase or private key out of the vault. Passes the export gate
/// (session, parent directory key, wallet key), marks this wallet exposed and
/// seals that record, and only then returns the secret. The mark is permanent
/// by construction and touches no other wallet, not even one in the same folder.
pub fn reveal(
    vault: &mut EncryptedVault,
    wallet_id: &str,
    gate: &ExportGate<'_>,
    what: Revealed,
    channel: Channel,
    now_ms: i64,
) -> Result<RevealedSecret> {
    check_wallet_export(vault, gate, wallet_id)?;
    let (secret, public_hex) = match &what {
        Revealed::Mnemonic => (
            with_mnemonic(vault, wallet_id, |m| {
                Ok(zeroize::Zeroizing::new(m.phrase().to_string()))
            })?,
            None,
        ),
        Revealed::PrivateKey { path, .. } if cardano_account(path).is_some() => {
            let account = cardano_account(path).unwrap_or_default();
            let keys = cardano_keys(vault, wallet_id, account)?;
            (
                zeroize::Zeroizing::new(hex::encode(keys.payment.secret())),
                Some(hex::encode(keys.public())),
            )
        }
        Revealed::PrivateKey { curve, path } => with_mnemonic(vault, wallet_id, |m| {
            let k = hd::derive(m.to_seed("").as_ref(), *curve, path)?;
            Ok((
                zeroize::Zeroizing::new(hex::encode(k.secret())),
                Some(k.public_hex()),
            ))
        })?,
    };
    let mut table = load_provenance(vault)?;
    table.record_exposure(
        wallet_id,
        Exposure {
            at_ms: now_ms,
            channel,
            what: what.clone(),
        },
    )?;
    save_provenance(vault, &table)?;
    Ok(RevealedSecret {
        what,
        secret,
        public_hex,
    })
}

/// A signing key at `path`, for the ledger's approval step. Never leaves the core.
pub(crate) fn signing_key(
    vault: &EncryptedVault,
    wallet_id: &str,
    curve: Curve,
    path: &str,
) -> Result<hd::DerivedKey> {
    if let Some(account) = chia_account(path) {
        // Chia: sign with the EIP-2333 scalar; the public half is its G1 point.
        return with_mnemonic(vault, wallet_id, |m| {
            let master = crate::chia::master_sk_from_seed(m.to_seed("").as_ref())?;
            let sk = crate::chia::wallet_sk(&master, account)?;
            let public = crate::chia::public_key(&sk)?.to_vec();
            Ok(hd::DerivedKey::from_parts(curve, sk, public))
        });
    }
    with_mnemonic(vault, wallet_id, |m| {
        hd::derive(m.to_seed("").as_ref(), curve, path)
    })
}

/// Raw phrase for an authenticated transfer; callers record the transfer.
pub(crate) fn phrase_for_transfer(vault: &EncryptedVault, wallet_id: &str) -> Result<String> {
    with_mnemonic(vault, wallet_id, |m| Ok(m.phrase().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export_gate::testing;
    use crate::vault::{KdfParams, SessionProof};

    fn vault() -> EncryptedVault {
        EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap()
    }

    #[test]
    fn created_wallet_is_local_until_revealed() {
        let mut v = vault();
        create_single(&mut v, "w1", 10).unwrap();
        let t = load_provenance(&v).unwrap();
        let w = t.wallet("w1").unwrap();
        assert_eq!(w.origin, Origin::Created { at_ms: 10 });
        assert!(w.exposures.is_empty());

        let pk = public_key(&v, "w1", Curve::Secp256k1, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(pk.len(), 66);
        assert!(load_provenance(&v)
            .unwrap()
            .wallet("w1")
            .unwrap()
            .exposures
            .is_empty());

        let k = testing::keys(&mut v, "pw", &["w1"]);
        let r = reveal(
            &mut v,
            "w1",
            &k.gate(),
            Revealed::PrivateKey {
                curve: Curve::Secp256k1,
                path: "m/44'/60'/0'/0/0".into(),
            },
            Channel::Clipboard,
            20,
        )
        .unwrap();
        assert_eq!(r.secret.len(), 64);
        assert_eq!(r.public_hex.as_deref(), Some(pk.as_str()));
        assert!(!format!("{r:?}").contains(r.secret.as_str()));
        let exposures = load_provenance(&v)
            .unwrap()
            .wallet("w1")
            .unwrap()
            .exposures
            .clone();
        assert_eq!(exposures.len(), 1);
        assert_eq!(exposures[0].channel, Channel::Clipboard);
    }

    #[test]
    fn wrong_passphrase_reveals_nothing_and_records_nothing() {
        let mut v = vault();
        create_single(&mut v, "w1", 1).unwrap();
        let k = testing::keys(&mut v, "pw", &["w1"]);
        let bad = SessionProof::Passphrase(Secret::new(b"nope".to_vec()));
        let wrong_session = crate::export_gate::ExportGate {
            session: &bad,
            ..k.gate()
        };
        assert!(reveal(
            &mut v,
            "w1",
            &wrong_session,
            Revealed::Mnemonic,
            Channel::Screen,
            2
        )
        .is_err());
        let wrong_key = Secret::new(b"not-the-wallet-key".to_vec());
        let wrong_wallet_key = crate::export_gate::ExportGate {
            wallet_key: Some(&wrong_key),
            ..k.gate()
        };
        assert!(reveal(
            &mut v,
            "w1",
            &wrong_wallet_key,
            Revealed::Mnemonic,
            Channel::Screen,
            2
        )
        .is_err());
        let wrong_folder = crate::export_gate::ExportGate {
            folder_key: &wrong_key,
            ..k.gate()
        };
        assert!(reveal(
            &mut v,
            "w1",
            &wrong_folder,
            Revealed::Mnemonic,
            Channel::Screen,
            2
        )
        .is_err());
        assert!(load_provenance(&v)
            .unwrap()
            .wallet("w1")
            .unwrap()
            .exposures
            .is_empty());
    }

    #[test]
    fn imported_phrase_restores_standard_accounts() {
        let mut v = vault();
        import_phrase(
            &mut v,
            "w2",
            "test test test test test test test test test test test junk",
            5,
        )
        .unwrap();
        assert_eq!(
            load_provenance(&v).unwrap().wallet("w2").unwrap().origin,
            Origin::ImportedPhrase { at_ms: 5 }
        );
        let k = testing::keys(&mut v, "pw", &["w2"]);
        let r = reveal(
            &mut v,
            "w2",
            &k.gate(),
            Revealed::PrivateKey {
                curve: Curve::Secp256k1,
                path: "m/44'/60'/0'/0/0".into(),
            },
            Channel::Screen,
            6,
        )
        .unwrap();
        assert_eq!(
            r.secret.as_str(),
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
        assert!(import_phrase(&mut v, "w2", "abandon abandon", 7).is_err());
        assert!(
            create_single(&mut v, "w2", 7).is_err(),
            "a wallet holds one key"
        );
    }

    #[test]
    fn history_never_shrinks() {
        let mut v = vault();
        create_single(&mut v, "w1", 1).unwrap();
        create_single(&mut v, "w2", 1).unwrap();
        let k = testing::keys(&mut v, "pw", &["w1"]);
        reveal(
            &mut v,
            "w1",
            &k.gate(),
            Revealed::Mnemonic,
            Channel::Screen,
            2,
        )
        .unwrap();
        assert!(
            load_provenance(&v)
                .unwrap()
                .wallet("w2")
                .unwrap()
                .exposures
                .is_empty(),
            "a sibling in the same folder stays untouched"
        );
        let mut forged = load_provenance(&v).unwrap();
        forged.wallets[0].exposures.clear();
        assert!(save_provenance(&mut v, &forged).is_err());
        let mut forged = load_provenance(&v).unwrap();
        forged.wallets[0].origin = Origin::Created { at_ms: 99 };
        assert!(save_provenance(&mut v, &forged).is_err());
        let mut forged = load_provenance(&v).unwrap();
        forged.wallets.clear();
        assert!(save_provenance(&mut v, &forged).is_err());
    }

    #[test]
    fn locked_vault_reveals_nothing() {
        let mut v = vault();
        create_single(&mut v, "w1", 1).unwrap();
        let k = testing::keys(&mut v, "pw", &["w1"]);
        v.lock();
        assert!(reveal(
            &mut v,
            "w1",
            &k.gate(),
            Revealed::Mnemonic,
            Channel::Screen,
            2
        )
        .is_err());
    }
}
