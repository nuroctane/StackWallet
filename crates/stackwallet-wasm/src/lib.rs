//! wasm-bindgen surface. Everything crosses as JSON (strings in, strings or
//! plain JS values out) so the TypeScript side can Zod-validate it and the
//! Rust side never hands out raw pointers.

mod transport;

use stackwallet_core::export_gate::{self, ExportGate, KeyScope};
use stackwallet_core::identity::{DeviceIdentity, SignedCeremonyMessage};
use stackwallet_core::intent::TxIntent;
use stackwallet_core::lifecycle::TxState;
use stackwallet_core::model::Curve;
use stackwallet_core::policy::Policy;
use stackwallet_core::store::devices::{load_device_table, save_device_table};
use stackwallet_core::store::Device;
use stackwallet_core::tss::CeremonyMessage;
use stackwallet_core::vault::{
    EncryptedVault, KdfParams, Secret, SecretHandle, SessionProof, SlotKind, SlotSecret, Vault,
};
use stackwallet_core::{ledger, provenance, threshold, transfer};
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

/// A session proof from its three parts: no slot id means `secret` is the
/// passphrase's UTF-8 bytes; otherwise it is the PIN digits or PRF output and
/// `device` the device-held secret a PIN slot is bound to.
fn session_from(slot_id: Option<String>, secret: Vec<u8>, device: Option<Vec<u8>>) -> SessionProof {
    match slot_id {
        None => SessionProof::Passphrase(Secret::new(secret)),
        Some(id) => SessionProof::Slot {
            id,
            secret: SlotSecret {
                secret: Secret::new(secret),
                device: device.map(Secret::new),
            },
        },
    }
}

fn scope_from(scope: &str) -> Result<KeyScope, JsError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        scope.into(),
    ))?)
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

    /// Which kernel outputs (`[{index, mask, keys}]` JSON) the Mixin account at
    /// `path` owns, as `[{position, key}]` JSON. The view key stays inside.
    pub fn mixin_owned_outputs(
        &self,
        wallet_id: &str,
        path: &str,
        candidates_json: &str,
    ) -> Result<String, JsError> {
        let candidates: Vec<stackwallet_core::mixin::CandidateOutput> =
            serde_json::from_str(candidates_json)?;
        let owned = provenance::mixin_owned_outputs(&self.inner, wallet_id, path, &candidates)
            .map_err(core_err)?;
        Ok(serde_json::to_string(&owned)?)
    }

    /// Gated reveal: session proof, the parent directory's export key and the
    /// wallet's export key. The exposure is sealed before this returns
    /// `{ what, secret, publicHex }`; any failed check reveals and records nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn reveal(
        &mut self,
        wallet_id: &str,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        folder_id: &str,
        folder_key: String,
        wallet_key: String,
        what_json: &str,
        channel: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let what: provenance::Revealed = serde_json::from_str(what_json)?;
        let channel: provenance::Channel =
            serde_json::from_value(serde_json::Value::String(channel.into()))?;
        let session = session_from(session_slot, session_secret, session_device);
        let folder_key = secret_from_string(folder_key);
        let wallet_key = secret_from_string(wallet_key);
        let r = provenance::reveal(
            &mut self.inner,
            wallet_id,
            &ExportGate {
                session: &session,
                folder_id,
                folder_key: &folder_key,
                wallet_key: Some(&wallet_key),
            },
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

    /// Seal a directory (`scope = "set"`) or one wallet (`"wallet"`) for one
    /// paired device; returns the `stackwallet-set:` text. `folder_id` is the
    /// exported directory, or the folder the wallet sits in.
    #[allow(clippy::too_many_arguments)]
    pub fn export_bundle(
        &mut self,
        identity_label: &str,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        folder_key: String,
        wallet_key: Option<String>,
        scope: &str,
        to_device_id: &str,
        folder_id: &str,
        wallet_ids_json: &str,
        directory_json: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let wallet_ids: Vec<String> = serde_json::from_str(wallet_ids_json)?;
        let scope: transfer::BundleScope =
            serde_json::from_value(serde_json::Value::String(scope.into()))?;
        let session = session_from(session_slot, session_secret, session_device);
        let folder_key = secret_from_string(folder_key);
        let wallet_key = wallet_key.map(secret_from_string);
        transfer::export_bundle(
            &mut self.inner,
            transfer::ExportRequest {
                identity_label,
                gate: ExportGate {
                    session: &session,
                    folder_id,
                    folder_key: &folder_key,
                    wallet_key: wallet_key.as_ref(),
                },
                scope,
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
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        bundle: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let session = session_from(session_slot, session_secret, session_device);
        let got = transfer::import_set(
            &mut self.inner,
            identity_label,
            &session,
            bundle,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&got)?)
    }

    /// Step-up check with any session factor; `allow_pin` is false for anything
    /// that takes material out of the vault.
    pub fn verify_session(
        &self,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        allow_pin: bool,
    ) -> Result<(), JsError> {
        let session = session_from(session_slot, session_secret, session_device);
        self.inner
            .verify_session(&session, allow_pin)
            .map_err(core_err)
    }

    /// Sign an EIP-191 message (`kind = "personal"`) or EIP-712 typed data
    /// (`"typedData"`, testnet domains only); audited. Returns `SignedMessage` JSON.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_message(
        &mut self,
        wallet_id: &str,
        path: &str,
        address: &str,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        kind: &str,
        payload: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let kind: stackwallet_core::message::MessageKind =
            serde_json::from_value(serde_json::Value::String(kind.into()))?;
        let session = session_from(session_slot, session_secret, session_device);
        let signed = stackwallet_core::message::sign_message(
            &mut self.inner,
            stackwallet_core::message::MessageRequest {
                wallet_id,
                path,
                address,
                session: &session,
                kind,
                payload,
                device_id,
                now_ms: now_ms as i64,
            },
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&signed)?)
    }

    /// A model provider's API key (D4), stored under `provider-key:<id>`.
    /// The only vault read that hands plaintext to the page: provider keys
    /// are the page's to use (it calls the provider directly), and the prefix
    /// check keeps every wallet secret, share and identity out of reach.
    pub fn provider_key(&self, provider: &str) -> Result<Option<String>, JsError> {
        if provider.is_empty()
            || !provider
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-')
        {
            return Err(JsError::new("bad provider id"));
        }
        let Some(handle) = self.inner.handle_for(&format!("provider-key:{provider}")) else {
            return Ok(None);
        };
        let key = self
            .inner
            .with_secret(&handle, &mut |s| String::from_utf8(s.expose().to_vec()))
            .map_err(core_err)?
            .map_err(|_| JsError::new("provider key is not utf-8"))?;
        Ok(Some(key))
    }

    /// An app record the page wrote itself and may read back: agent session
    /// transcripts (`agent-session:<id>`). Sealed at rest like everything in
    /// the vault; the prefix allowlist keeps key material out of reach.
    pub fn app_record(&self, label: &str) -> Result<Option<String>, JsError> {
        if !label.starts_with("agent-session:") || label.len() > 128 {
            return Err(JsError::new("not an app record"));
        }
        let Some(handle) = self.inner.handle_for(label) else {
            return Ok(None);
        };
        let text = self
            .inner
            .with_secret(&handle, &mut |s| String::from_utf8(s.expose().to_vec()))
            .map_err(core_err)?
            .map_err(|_| JsError::new("app record is not utf-8"))?;
        Ok(Some(text))
    }

    /// Register the address a hardware device showed for `path` (EVM).
    pub fn hardware_register(
        &mut self,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        wallet_id: &str,
        path: &str,
        address: &str,
    ) -> Result<String, JsError> {
        let session = session_from(session_slot, session_secret, session_device);
        let acc = stackwallet_core::hardware::register(
            &mut self.inner,
            &session,
            wallet_id,
            path,
            address,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&acc)?)
    }

    /// Hardware approval, first half: `{ record, payloadHex }` (the bytes the device signs).
    pub fn tx_begin_external(
        &mut self,
        tx_id: &str,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let session = session_from(session_slot, session_secret, session_device);
        let (record, payload) =
            ledger::begin_external(&mut self.inner, tx_id, &session, device_id, now_ms as i64)
                .map_err(core_err)?;
        Ok(serde_json::json!({ "record": record, "payloadHex": payload }).to_string())
    }

    /// Hardware approval, second half: the device's (v, r, s); returns the record.
    pub fn tx_complete_external(
        &mut self,
        tx_id: &str,
        v: u8,
        r_hex: &str,
        s_hex: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let word = |h: &str| -> Result<[u8; 32], JsError> {
            hex::decode(h.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| JsError::new("signature words must be 32 bytes"))
        };
        let rec = ledger::complete_external(
            &mut self.inner,
            tx_id,
            v,
            &word(r_hex)?,
            &word(s_hex)?,
            device_id,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    pub fn tx_abort_external(
        &mut self,
        tx_id: &str,
        reason: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec = ledger::abort_external(&mut self.inner, tx_id, reason, device_id, now_ms as i64)
            .map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    /// Threshold wallets this vault holds a share of (`ThresholdAccount[]` JSON).
    pub fn threshold_list(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(
            &threshold::list(&self.inner).map_err(core_err)?,
        )?)
    }

    /// What a co-signer is asked to sign, decoded and policy-checked by the core.
    pub fn threshold_review(
        &self,
        request_json: &str,
        session_json: &str,
        proposer_device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let summary = threshold::review_sign(
            &self.inner,
            &serde_json::from_str(request_json)?,
            &serde_json::from_str(session_json)?,
            proposer_device_id,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&summary)?)
    }

    /// Start (or join) DKG for a new threshold wallet.
    #[allow(clippy::too_many_arguments)]
    pub fn threshold_keygen(
        &mut self,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        wallet_id: &str,
        device_id: &str,
        group_json: &str,
        session_json: &str,
        now_ms: f64,
    ) -> Result<WasmThresholdDriver, JsError> {
        let proof = session_from(session_slot, session_secret, session_device);
        let (driver, outbox) = threshold::Driver::keygen(
            &mut self.inner,
            &proof,
            wallet_id,
            device_id,
            &serde_json::from_str(group_json)?,
            &serde_json::from_str(session_json)?,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(WasmThresholdDriver { driver, outbox })
    }

    /// Join a signing ceremony with this device's sealed share.
    #[allow(clippy::too_many_arguments)]
    pub fn threshold_sign(
        &mut self,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        request_json: &str,
        session_json: &str,
        proposer_device_id: &str,
        now_ms: f64,
    ) -> Result<WasmThresholdDriver, JsError> {
        let proof = session_from(session_slot, session_secret, session_device);
        let (driver, outbox) = threshold::Driver::sign(
            &mut self.inner,
            &proof,
            &serde_json::from_str(request_json)?,
            &serde_json::from_str(session_json)?,
            proposer_device_id,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(WasmThresholdDriver { driver, outbox })
    }

    /// Threshold approval, first half: `{ record, request }` (request is null if policy refused).
    pub fn tx_begin_threshold(
        &mut self,
        tx_id: &str,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let session = session_from(session_slot, session_secret, session_device);
        let (record, request) =
            ledger::begin_threshold(&mut self.inner, tx_id, &session, device_id, now_ms as i64)
                .map_err(core_err)?;
        Ok(serde_json::json!({ "record": record, "request": request }).to_string())
    }

    /// Threshold approval, second half: the ceremony's aggregate signature.
    pub fn tx_complete_threshold(
        &mut self,
        tx_id: &str,
        signature_hex: &str,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec = ledger::complete_threshold(
            &mut self.inner,
            tx_id,
            signature_hex,
            device_id,
            now_ms as i64,
        )
        .map_err(core_err)?;
        Ok(serde_json::to_string(&rec)?)
    }

    /// Device-local unlock methods (`SlotInfo[]` JSON). Readable while locked.
    pub fn slots_json(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(&self.inner.slots())?)
    }

    /// Add a PIN (`kind = "pin"`, `secret` = 6 ASCII digits, `device` = 32
    /// bytes) or a passkey (`"passkey"`, `secret` = 32-byte PRF output,
    /// `credential_id` base64url). Only the passphrase can add one.
    #[allow(clippy::too_many_arguments)]
    pub fn add_slot(
        &mut self,
        passphrase: String,
        kind: &str,
        label: &str,
        credential_id: Option<String>,
        secret: Vec<u8>,
        device: Option<Vec<u8>>,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let kind: SlotKind = serde_json::from_value(serde_json::Value::String(kind.into()))?;
        self.inner
            .add_slot(
                &secret_from_string(passphrase),
                kind,
                label,
                credential_id,
                &SlotSecret {
                    secret: Secret::new(secret),
                    device: device.map(Secret::new),
                },
                now_ms as i64,
            )
            .map_err(core_err)
    }

    pub fn remove_slot(&mut self, id: &str) -> Result<(), JsError> {
        self.inner.remove_slot(id).map_err(core_err)
    }

    pub fn unlock_with_slot(
        &mut self,
        id: &str,
        secret: Vec<u8>,
        device: Option<Vec<u8>>,
    ) -> Result<(), JsError> {
        self.inner
            .unlock_with_slot(
                id,
                &SlotSecret {
                    secret: Secret::new(secret),
                    device: device.map(Secret::new),
                },
            )
            .map_err(core_err)
    }

    /// `[{ scope, id }]` for every folder and wallet that has an export key.
    pub fn export_keys_json(&self) -> Result<String, JsError> {
        let ids: Vec<_> = export_gate::export_key_ids(&self.inner)
            .into_iter()
            .map(|(scope, id)| serde_json::json!({ "scope": scope, "id": id }))
            .collect();
        Ok(serde_json::to_string(&ids)?)
    }

    /// Set or change one export key (`scope` is `"folder"` or `"wallet"`).
    #[allow(clippy::too_many_arguments)]
    pub fn set_export_key(
        &mut self,
        scope: &str,
        id: &str,
        session_slot: Option<String>,
        session_secret: Vec<u8>,
        session_device: Option<Vec<u8>>,
        current: Option<String>,
        next: String,
    ) -> Result<(), JsError> {
        let scope = scope_from(scope)?;
        let session = session_from(session_slot, session_secret, session_device);
        let current = current.map(secret_from_string);
        export_gate::set_export_key(
            &mut self.inner,
            scope,
            id,
            &session,
            current.as_ref(),
            &secret_from_string(next),
        )
        .map_err(core_err)
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
            serde_json::from_str::<ledger::UnsignedTx>(unsigned_json)?,
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

    pub fn tx_retry_broadcast(
        &mut self,
        tx_id: &str,
        passphrase: String,
        device_id: &str,
        now_ms: f64,
    ) -> Result<String, JsError> {
        let rec = ledger::retry_broadcast(
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

/// The session a threshold key generation for `group_json` runs under, bound
/// to the group exactly as every participant's core will check it.
#[wasm_bindgen]
pub fn threshold_keygen_session(
    group_json: &str,
    id: &str,
    now_ms: f64,
) -> Result<String, JsError> {
    let group: stackwallet_core::model::KeyGroup = serde_json::from_str(group_json)?;
    group.validate().map_err(core_err)?;
    Ok(serde_json::to_string(&threshold::keygen_session(
        &group,
        id,
        now_ms as i64,
    ))?)
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

/// One device's side of one threshold ceremony. The share stays inside;
/// the page moves `CeremonyMessage` JSON between this and its peers.
#[wasm_bindgen]
pub struct WasmThresholdDriver {
    driver: threshold::Driver,
    outbox: Vec<CeremonyMessage>,
}

#[wasm_bindgen]
impl WasmThresholdDriver {
    /// The messages produced when the ceremony started (`CeremonyMessage[]`), once.
    pub fn take_initial(&mut self) -> Result<String, JsError> {
        Ok(serde_json::to_string(&std::mem::take(&mut self.outbox))?)
    }

    /// Feed one peer message; returns the replies (`CeremonyMessage[]`).
    pub fn handle(&mut self, msg_json: &str) -> Result<String, JsError> {
        let out = self
            .driver
            .handle(serde_json::from_str(msg_json)?)
            .map_err(core_err)?;
        Ok(serde_json::to_string(&out)?)
    }

    pub fn session_json(&self) -> Result<String, JsError> {
        Ok(serde_json::to_string(self.driver.session())?)
    }

    pub fn complete(&self) -> bool {
        self.driver.state() == stackwallet_core::tss::CeremonyState::Complete
    }

    pub fn signature_hex(&self) -> Result<Option<String>, JsError> {
        self.driver.signature_hex().map_err(core_err)
    }

    /// Seal the new share; returns the `ThresholdAccount` JSON.
    pub fn finish_keygen(&self, vault: &mut WasmVault, now_ms: f64) -> Result<String, JsError> {
        let acc = self
            .driver
            .finish_keygen(&mut vault.inner, now_ms as i64)
            .map_err(core_err)?;
        Ok(serde_json::to_string(&acc)?)
    }

    /// Audit how the ceremony ended here; `aborted` carries the reason.
    pub fn audit_end(
        &self,
        vault: &mut WasmVault,
        aborted: Option<String>,
        now_ms: f64,
    ) -> Result<(), JsError> {
        self.driver
            .audit_end(&mut vault.inner, aborted.as_deref(), now_ms as i64)
            .map_err(core_err)
    }
}
