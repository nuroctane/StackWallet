//! wasm-bindgen surface. Everything crosses as JSON (strings in, strings or
//! plain JS values out) so the TypeScript side can Zod-validate it and the
//! Rust side never hands out raw pointers.

mod transport;

use stackwallet_core::identity::{DeviceIdentity, SignedCeremonyMessage};
use stackwallet_core::intent::TxIntent;
use stackwallet_core::lifecycle::TxState;
use stackwallet_core::model::Curve;
use stackwallet_core::policy::Policy;
use stackwallet_core::store::devices::{load_device_table, save_device_table};
use stackwallet_core::store::Device;
use stackwallet_core::tss::CeremonyMessage;
use stackwallet_core::vault::{EncryptedVault, KdfParams, Secret, SecretHandle, Vault};
use stackwallet_core::{ledger, provenance, transfer};
use wasm_bindgen::prelude::*;

pub use transport::{
    pairing_new_code_hex, pairing_offer_decode, pairing_offer_encode, WasmIdentity, WasmSession,
};

#[wasm_bindgen]
pub fn core_version() -> String {
    stackwallet_core::VERSION.to_owned()
}

/// `policies_json: Policy[]`, `intent_json: TxIntent`, `ctx_json: PolicyContext` → `Decision`.
#[wasm_bindgen]
pub fn evaluate_policy(
    policies_json: &str,
    intent_json: &str,
    ctx_json: &str,
) -> Result<String, JsError> {
    let policies: Vec<stackwallet_core::policy::Policy> = serde_json::from_str(policies_json)?;
    let intent: stackwallet_core::intent::TxIntent = serde_json::from_str(intent_json)?;
    let ctx: stackwallet_core::policy::PolicyContext = serde_json::from_str(ctx_json)?;
    let decision = stackwallet_core::policy::evaluate(&policies, &intent, &ctx);
    Ok(serde_json::to_string(&decision)?)
}

/// `KeyGroup` JSON → `null` on success or an error message.
#[wasm_bindgen]
pub fn validate_key_group(group_json: &str) -> Result<Option<String>, JsError> {
    let group: stackwallet_core::model::KeyGroup = serde_json::from_str(group_json)?;
    Ok(group.validate().err().map(|e| e.to_string()))
}

#[wasm_bindgen]
pub fn can_transition(from_json: &str, to_json: &str) -> Result<bool, JsError> {
    let from: stackwallet_core::lifecycle::TxState = serde_json::from_str(from_json)?;
    let to: stackwallet_core::lifecycle::TxState = serde_json::from_str(to_json)?;
    Ok(from.can_transition_to(to))
}

#[wasm_bindgen]
pub fn schema_sql() -> String {
    stackwallet_core::store::SCHEMA_SQL.to_owned()
}

/// The encrypted vault held inside the wasm instance. JS sees ciphertext
/// (`to_bytes`), labels and handles; plaintext secrets are only ever used by
/// operations that run on this side of the boundary. The identity signs only
/// domain-separated ceremony messages, never caller-chosen bytes, so a
/// compromised page cannot turn it into a general signing oracle.
#[wasm_bindgen]
pub struct WasmVault {
    inner: EncryptedVault,
}

/// Passphrases and pasted secrets are taken by value so the copy wasm-bindgen
/// makes on the way in is the one we own and wipe, instead of a borrowed
/// buffer that is freed unwiped after the call.
fn secret_from_string(s: String) -> Secret {
    Secret::new(s.into_bytes())
}

fn core_err(e: stackwallet_core::CoreError) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
impl WasmVault {
    /// New unlocked vault. `kdf_json` is an optional `KdfParams`; omitted
    /// means the OWASP minimum, and anything below it is rejected.
    #[wasm_bindgen(constructor)]
    pub fn create(passphrase: String, kdf_json: Option<String>) -> Result<WasmVault, JsError> {
        let params = match kdf_json {
            Some(j) => serde_json::from_str(&j)?,
            None => KdfParams::default(),
        };
        let inner =
            EncryptedVault::create(&secret_from_string(passphrase), params).map_err(core_err)?;
        Ok(Self { inner })
    }

    /// Parse a serialized vault; the result is locked.
    pub fn open(bytes: &[u8]) -> Result<WasmVault, JsError> {
        Ok(Self {
            inner: EncryptedVault::open(bytes).map_err(core_err)?,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.inner.to_bytes().map_err(core_err)
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    pub fn unlock(&mut self, passphrase: String) -> Result<(), JsError> {
        self.inner
            .unlock(&secret_from_string(passphrase))
            .map_err(core_err)
    }

    pub fn lock(&mut self) {
        self.inner.lock();
    }

    pub fn change_passphrase(&mut self, old: String, new: String) -> Result<(), JsError> {
        self.inner
            .change_passphrase(&secret_from_string(old), &secret_from_string(new))
            .map_err(core_err)
    }

    /// `KdfParams` JSON.
    pub fn kdf_params_json(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(&self.inner.kdf_params())?)
    }

    /// `{ handle: string, label: string }[]`; readable while locked.
    pub fn labels_json(&self) -> Result<String, JsError> {
        let labels: Vec<serde_json::Value> = self
            .inner
            .labels()
            .into_iter()
            .map(|(h, l)| serde_json::json!({ "handle": h.0, "label": l }))
            .collect();
        Ok(serde_json::to_string(&labels)?)
    }

    pub fn handle_for(&self, label: &str) -> Option<String> {
        self.inner.handle_for(label).map(|h| h.0)
    }

    /// Store a secret the UI already holds (a provider API key the user
    /// pasted). Returns the handle. Re-putting a label keeps its handle.
    pub fn put(&mut self, label: &str, secret: Vec<u8>) -> Result<String, JsError> {
        self.inner
            .put(label, Secret::new(secret))
            .map(|h| h.0)
            .map_err(core_err)
    }

    pub fn delete(&mut self, handle: &str) -> Result<(), JsError> {
        self.inner
            .delete(&SecretHandle(handle.to_owned()))
            .map_err(core_err)
    }

    /// Generate an Ed25519 device identity and seal its seed under `label`.
    /// Returns `{ deviceId, publicHex, noiseStaticHex }`; the seed never leaves the vault.
    pub fn create_identity(&mut self, label: &str) -> Result<String, JsError> {
        let id = DeviceIdentity::generate().map_err(core_err)?;
        self.inner.put(label, id.to_secret()).map_err(core_err)?;
        Ok(identity_json(&id))
    }

    /// `{ deviceId, publicHex, noiseStaticHex }` for the identity sealed under `label`.
    pub fn identity_info(&self, label: &str) -> Result<String, JsError> {
        self.with_identity(label, |id| Ok(identity_json(id)))
    }

    /// A live `WasmIdentity` for driving sessions. The seed is copied within
    /// wasm memory only; JS receives an opaque handle it should `free()` once
    /// the session that needed it is over.
    pub fn identity(&self, label: &str) -> Result<WasmIdentity, JsError> {
        self.with_identity(label, |id| {
            DeviceIdentity::from_secret(&id.to_secret())
                .map(WasmIdentity::from_inner)
                .map_err(core_err)
        })
    }

    /// The pinned device table sealed in this vault, validated: `Device[]`
    /// JSON, empty when nothing has been pinned. Needs the vault unlocked.
    pub fn devices_json(&self) -> Result<String, JsError> {
        let table = load_device_table(&self.inner).map_err(core_err)?;
        Ok(serde_json::to_string(&table)?)
    }

    /// Validate and seal a whole `Device[]` table. A record whose id is not
    /// the derivation of its identity key, a duplicate, or an oversized table
    /// is refused before anything is written.
    pub fn set_devices_json(&mut self, devices_json: &str) -> Result<(), JsError> {
        let table: Vec<Device> = serde_json::from_str(devices_json)?;
        save_device_table(&mut self.inner, &table).map_err(core_err)
    }

    /// Sign a `CeremonyMessage` JSON with the identity under `label`;
    /// returns the `SignedCeremonyMessage` JSON.
    pub fn sign_ceremony_message(&self, label: &str, msg_json: &str) -> Result<String, JsError> {
        let msg: CeremonyMessage = serde_json::from_str(msg_json)?;
        self.with_identity(label, |id| {
            let signed = SignedCeremonyMessage::sign(id, msg.clone());
            Ok(serde_json::to_string(&signed)?)
        })
    }

    /// Generate and seal a fresh 24-word phrase for a new `single` wallet.
    pub fn create_single(&mut self, wallet_id: &str, now_ms: f64) -> Result<(), JsError> {
        provenance::create_single(&mut self.inner, wallet_id, now_ms as i64).map_err(core_err)
    }

    /// Seal a phrase the user brought from elsewhere; the wallet starts `imported`.
    pub fn import_phrase(
        &mut self,
        wallet_id: &str,
        phrase: String,
        now_ms: f64,
    ) -> Result<(), JsError> {
        let phrase = zeroize::Zeroizing::new(phrase);
        provenance::import_phrase(&mut self.inner, wallet_id, &phrase, now_ms as i64)
            .map_err(core_err)
    }

    pub fn has_single_key(&self, wallet_id: &str) -> bool {
        provenance::has_single_key(&self.inner, wallet_id)
    }

    /// Public key hex for `curve` (`"secp256k1"` | `"ed25519"`) at a BIP32/SLIP-10 path.
    pub fn single_public_key(
        &self,
        wallet_id: &str,
        curve: &str,
        path: &str,
    ) -> Result<String, JsError> {
        let curve: Curve = serde_json::from_value(serde_json::Value::String(curve.into()))?;
        provenance::public_key(&self.inner, wallet_id, curve, path).map_err(core_err)
    }

    /// Step-up reveal. The exposure is sealed before this returns
    /// `{ what, secret, publicHex }`; a wrong passphrase reveals and records nothing.
    pub fn reveal(
        &mut self,
        wallet_id: &str,
        passphrase: String,
        what_json: &str,
        channel: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let what: provenance::Revealed = serde_json::from_str(what_json)?;
        let channel: provenance::Channel =
            serde_json::from_value(serde_json::Value::String(channel.into()))?;
        let r = provenance::reveal(
            &mut self.inner,
            wallet_id,
            &secret_from_string(passphrase),
            what,
            channel,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::json!({
            "what": r.what,
            "secret": r.secret.as_str(),
            "publicHex": r.public_hex,
        })
        .to_string())
    }

    /// The sealed provenance table (`ProvenanceTable` JSON). Read-only by design.
    pub fn provenance_json(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(
            &provenance::load_provenance(&self.inner).map_err(core_err)?,
        )?)
    }

    /// Seal a directory set for one paired device; returns the `stackwallet-set:` text.
    #[allow(clippy::too_many_arguments)]
    pub fn export_set(
        &mut self,
        identity_label: &str,
        passphrase: String,
        to_device_id: &str,
        folder_id: &str,
        wallet_ids_json: &str,
        directory_json: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let wallet_ids: Vec<String> = serde_json::from_str(wallet_ids_json)?;
        transfer::export_set(
            &mut self.inner,
            transfer::ExportRequest {
                identity_label,
                passphrase: &secret_from_string(passphrase),
                to_device_id,
                folder_id,
                wallet_ids: &wallet_ids,
                directory_json,
                now_ms: now_ms as i64,
            },
        )
        .map_err(core_err)
    }

    /// Open a bundle addressed to this device; returns `ImportedSet` JSON.
    pub fn import_set(
        &mut self,
        identity_label: &str,
        passphrase: String,
        bundle: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let got = transfer::import_set(
            &mut self.inner,
            identity_label,
            &secret_from_string(passphrase),
            bundle,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&got)?)
    }

    /// The sealed ledger (`Ledger` JSON): transactions, policies, audit log.
    pub fn ledger_json(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(
            &ledger::load_ledger(&self.inner).map_err(core_err)?,
        )?)
    }

    pub fn tx_propose(
        &mut self,
        intent_json: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let intent: TxIntent = serde_json::from_str(intent_json)?;
        let rec =
            ledger::propose(&mut self.inner, intent, device_id, now_ms as i64).map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tx_attach(
        &mut self,
        tx_id: &str,
        signer_json: &str,
        unsigned_json: &str,
        simulation_json: &str,
        simulation_ok: bool,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec = ledger::attach(
            &mut self.inner,
            tx_id,
            serde_json::from_str(signer_json)?,
            serde_json::from_str(unsigned_json)?,
            serde_json::from_str(simulation_json)?,
            simulation_ok,
            device_id,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    pub fn tx_evaluate(
        &mut self,
        tx_id: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec =
            ledger::evaluate(&mut self.inner, tx_id, device_id, now_ms as i64).map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    /// Step-up approval: the core re-checks policy, signs and returns the record.
    pub fn tx_approve(
        &mut self,
        tx_id: &str,
        passphrase: String,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec = ledger::approve(
            &mut self.inner,
            tx_id,
            &secret_from_string(passphrase),
            device_id,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    pub fn tx_reject(
        &mut self,
        tx_id: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec =
            ledger::reject(&mut self.inner, tx_id, device_id, now_ms as i64).map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    /// Record a network outcome (`"broadcast"`, `"pending"`, `"confirmed"`, …).
    pub fn tx_report(
        &mut self,
        tx_id: &str,
        state: &str,
        note: Option<String>,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let to: TxState = serde_json::from_value(serde_json::Value::String(state.into()))?;
        let rec = ledger::report(&mut self.inner, tx_id, to, note, device_id, now_ms as i64)
            .map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    pub fn set_policies_json(
        &mut self,
        policies_json: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<(), JsError> {
        let policies: Vec<Policy> = serde_json::from_str(policies_json)?;
        ledger::set_policies(&mut self.inner, policies, device_id, now_ms as i64).map_err(core_err)
    }

    fn with_identity<T>(
        &self,
        label: &str,
        f: impl Fn(&DeviceIdentity) -> Result<T, JsError>,
    ) -> Result<T, JsError> {
        let handle = self
            .inner
            .handle_for(label)
            .ok_or_else(|| JsError::new(&format!("no secret labelled `{label}`")))?;
        self.inner
            .with_secret(&handle, &mut |seed| {
                let id = DeviceIdentity::from_secret(seed).map_err(core_err)?;
                f(&id)
            })
            .map_err(core_err)?
    }
}

fn identity_json(id: &DeviceIdentity) -> String {
    serde_json::json!({
        "deviceId": id.device_id(),
        "publicHex": id.public_hex(),
        "noiseStaticHex": id.noise_static_public_hex(),
    })
    .to_string()
}

/// Verify a `SignedCeremonyMessage` JSON against the sender's pinned public key.
#[wasm_bindgen]
pub fn verify_ceremony_message(signed_json: &str, public_hex: &str) -> Result<bool, JsError> {
    let signed: SignedCeremonyMessage = serde_json::from_str(signed_json)?;
    Ok(signed.verify(public_hex).is_ok())
}

/// Device id derived from an Ed25519 public key hex, as pinned at pairing.
#[wasm_bindgen]
pub fn device_id_from_public_hex(public_hex: &str) -> Result<String, JsError> {
    stackwallet_core::identity::device_id_from_public_hex(public_hex).map_err(core_err)
}
