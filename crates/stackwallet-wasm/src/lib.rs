//! wasm-bindgen surface. Everything crosses as JSON strings so the TypeScript
//! side can Zod-validate it and the Rust side never hands out raw pointers.

use stackwallet_core::identity::{DeviceIdentity, SignedCeremonyMessage};
use stackwallet_core::tss::CeremonyMessage;
use stackwallet_core::vault::{EncryptedVault, KdfParams, Secret, SecretHandle, Vault};
use wasm_bindgen::prelude::*;

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
    /// Returns `{ deviceId, publicHex }`; the seed never leaves the vault.
    pub fn create_identity(&mut self, label: &str) -> Result<String, JsError> {
        let id = DeviceIdentity::generate().map_err(core_err)?;
        self.inner.put(label, id.to_secret()).map_err(core_err)?;
        Ok(identity_json(&id))
    }

    /// `{ deviceId, publicHex }` for the identity sealed under `label`.
    pub fn identity_info(&self, label: &str) -> Result<String, JsError> {
        self.with_identity(label, |id| Ok(identity_json(id)))
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
    serde_json::json!({ "deviceId": id.device_id(), "publicHex": id.public_hex() }).to_string()
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
