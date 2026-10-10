//! Browser surface for the sans-IO transport: identity, pairing offers and
//! the `Session` state machine. The JS carrier (a WebRTC data channel) moves
//! the byte buffers; everything that authenticates them stays on this side.

use std::collections::HashMap;

use stackwallet_core::identity::DeviceIdentity;
use stackwallet_core::transport::session::StaticLookup;
use stackwallet_core::transport::{
    Device, Frame, HandshakeRole, PairingOffer, Session, SessionEvent, SessionState,
};
use stackwallet_core::vault::Secret;
use wasm_bindgen::prelude::*;

use crate::core_err;

/// The device's long-term identity held inside the wasm instance. Public
/// halves are readable; the seed never crosses to JS. It is minted and sealed
/// by `WasmVault::create_identity` and reconstituted by `WasmVault::identity`
/// while the vault is unlocked.
#[wasm_bindgen]
pub struct WasmIdentity {
    inner: DeviceIdentity,
}

#[wasm_bindgen]
impl WasmIdentity {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> Result<WasmIdentity, JsError> {
        Ok(Self {
            inner: DeviceIdentity::generate().map_err(core_err)?,
        })
    }

    /// Restore from the 32-byte seed the vault released. Taken by value so the
    /// copy wasm-bindgen made is the one that gets wiped.
    pub fn from_seed(seed: Vec<u8>) -> Result<WasmIdentity, JsError> {
        let secret = Secret::new(seed);
        Ok(Self {
            inner: DeviceIdentity::from_secret(&secret).map_err(core_err)?,
        })
    }

    pub fn public_hex(&self) -> String {
        self.inner.public_hex()
    }

    pub fn device_id(&self) -> String {
        self.inner.device_id()
    }

    pub fn noise_static_public_hex(&self) -> String {
        self.inner.noise_static_public_hex()
    }

    /// `{ deviceId, publicHex, noiseStaticHex }`.
    pub fn info_json(&self) -> String {
        serde_json::json!({
            "deviceId": self.inner.device_id(),
            "publicHex": self.inner.public_hex(),
            "noiseStaticHex": self.inner.noise_static_public_hex(),
        })
        .to_string()
    }
}

impl WasmIdentity {
    pub(crate) fn from_inner(inner: DeviceIdentity) -> Self {
        Self { inner }
    }
}

/// `stackwallet-pair:<base64url JSON>` → the validated `PairingOffer` as a JS value.
#[wasm_bindgen]
pub fn pairing_offer_decode(text: String) -> Result<JsValue, JsError> {
    let offer = PairingOffer::decode(&text).map_err(core_err)?;
    to_js(&offer)
}

/// `PairingOffer` JSON → the `stackwallet-pair:` text shown as QR or pasted.
#[wasm_bindgen]
pub fn pairing_offer_encode(offer_json: String) -> Result<String, JsError> {
    let offer: PairingOffer = serde_json::from_str(&offer_json)?;
    offer.validate().map_err(core_err)?;
    Ok(offer.encode())
}

/// Fresh one-time code as hex, for a device that is about to show an offer.
#[wasm_bindgen]
pub fn pairing_new_code_hex() -> Result<String, JsError> {
    PairingOffer::new_code().map_err(core_err)
}

/// One authenticated channel to one peer. Feed every carrier message to
/// `handle_incoming`, then drain `take_outgoing`; `send_frame` queues an
/// application frame once the session reports `open`.
#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
}

#[wasm_bindgen]
impl WasmSession {
    /// Issuer side of pairing: this device showed the offer.
    pub fn pair_as_issuer(
        identity: &WasmIdentity,
        local_device_json: String,
        offer_json: String,
        now_ms: f64,
    ) -> Result<WasmSession, JsError> {
        let local: Device = serde_json::from_str(&local_device_json)?;
        let offer: PairingOffer = serde_json::from_str(&offer_json)?;
        let inner = Session::pair_as_issuer(&identity.inner, &local, &offer, ms(now_ms)?)
            .map_err(core_err)?;
        Ok(Self { inner })
    }

    /// Scanner side of pairing: this device read the offer.
    pub fn pair_as_scanner(
        identity: &WasmIdentity,
        local_device_json: String,
        offer_json: String,
        now_ms: f64,
    ) -> Result<WasmSession, JsError> {
        let local: Device = serde_json::from_str(&local_device_json)?;
        let offer: PairingOffer = serde_json::from_str(&offer_json)?;
        let inner = Session::pair_as_scanner(&identity.inner, &local, &offer, ms(now_ms)?)
            .map_err(core_err)?;
        Ok(Self { inner })
    }

    /// `IK` initiator against one pinned device record.
    pub fn connect_initiator(
        identity: &WasmIdentity,
        local_device_json: String,
        peer_device_json: String,
        now_ms: f64,
    ) -> Result<WasmSession, JsError> {
        let local: Device = serde_json::from_str(&local_device_json)?;
        let peer: Device = serde_json::from_str(&peer_device_json)?;
        let inner = Session::connect(
            &identity.inner,
            &local,
            HandshakeRole::Initiator,
            Some(&peer),
            None,
            ms(now_ms)?,
        )
        .map_err(core_err)?;
        Ok(Self { inner })
    }

    /// `IK` responder. `known_devices_json` is the `Device[]` this device has
    /// pinned; an initiator whose static is not in it is refused.
    pub fn connect_responder(
        identity: &WasmIdentity,
        local_device_json: String,
        known_devices_json: String,
        now_ms: f64,
    ) -> Result<WasmSession, JsError> {
        let local: Device = serde_json::from_str(&local_device_json)?;
        let known: Vec<Device> = serde_json::from_str(&known_devices_json)?;
        // The lookup closure runs per handshake; keep a pathological caller
        // from turning one call into an unbounded scan.
        if known.len() > 1024 {
            return Err(JsError::new("too many known devices (max 1024)"));
        }
        let inner = Session::connect(
            &identity.inner,
            &local,
            HandshakeRole::Responder,
            None,
            Some(lookup_over(known)),
            ms(now_ms)?,
        )
        .map_err(core_err)?;
        Ok(Self { inner })
    }

    /// Feed one carrier message. Returns `SessionEvent[]` as a JS value:
    /// `{type:'opened'|'paired', peer}`, `{type:'frame', frame}`,
    /// `{type:'relayed', signed}` (caller must verify `signed` against its own
    /// pinned record for the author), `{type:'closed', reason}`.
    pub fn handle_incoming(&mut self, bytes: Vec<u8>) -> Result<JsValue, JsError> {
        let events = self.inner.handle_incoming(&bytes).map_err(core_err)?;
        let json: Vec<serde_json::Value> = events.iter().map(event_json).collect();
        to_js(&json)
    }

    /// Queue a `Frame` JSON for the peer; only valid while `open`.
    pub fn send_frame(&mut self, frame_json: String) -> Result<(), JsError> {
        let frame: Frame = serde_json::from_str(&frame_json)?;
        self.inner.send(frame).map_err(core_err)
    }

    /// Wire messages to deliver, in order, as an array of `Uint8Array`.
    pub fn take_outgoing(&mut self) -> js_sys::Array {
        self.inner
            .take_outgoing()
            .iter()
            .map(|bytes| js_sys::Uint8Array::from(bytes.as_slice()))
            .collect()
    }

    /// `handshaking` | `awaitingHello` | `open` | `closed`.
    pub fn state(&self) -> String {
        match self.inner.state() {
            SessionState::Handshaking => "handshaking",
            SessionState::AwaitingHello => "awaitingHello",
            SessionState::Open => "open",
            SessionState::Closed => "closed",
        }
        .to_owned()
    }

    pub fn is_pairing(&self) -> bool {
        self.inner.is_pairing()
    }

    /// The verified peer `Device` as JSON, or `undefined` before the channel opened.
    pub fn peer_json(&self) -> Result<Option<String>, JsError> {
        self.inner
            .peer()
            .map(|peer| serde_json::to_string(peer).map_err(JsError::from))
            .transpose()
    }

    pub fn close(&mut self, reason: String) {
        self.inner.close(&reason);
    }
}

/// Revoked records are dropped here as well as inside the session, so a
/// caller that forgets to filter its device table still cannot admit one.
fn lookup_over(known: Vec<Device>) -> StaticLookup {
    let by_static: HashMap<[u8; 32], Device> = known
        .into_iter()
        .filter(|d| d.revoked_at_ms.is_none())
        .filter_map(|d| {
            let key: [u8; 32] = hex::decode(&d.noise_static_hex).ok()?.try_into().ok()?;
            Some((key, d))
        })
        .collect();
    Box::new(move |remote: &[u8; 32]| by_static.get(remote).cloned())
}

fn event_json(event: &SessionEvent) -> serde_json::Value {
    match event {
        SessionEvent::Opened { peer } => serde_json::json!({ "type": "opened", "peer": peer }),
        SessionEvent::Paired { peer } => serde_json::json!({ "type": "paired", "peer": peer }),
        SessionEvent::Frame(frame) => serde_json::json!({ "type": "frame", "frame": frame }),
        SessionEvent::Relayed(signed) => {
            serde_json::json!({ "type": "relayed", "signed": signed })
        }
        SessionEvent::Closed { reason } => {
            serde_json::json!({ "type": "closed", "reason": reason })
        }
    }
}

/// JS numbers are doubles; the core wants integer milliseconds. Refuse
/// fractions and non-finite values rather than silently rounding a timestamp
/// that gates one-time-code expiry.
fn ms(value: f64) -> Result<i64, JsError> {
    if !value.is_finite() || value.fract() != 0.0 || value.abs() > i64::MAX as f64 {
        return Err(JsError::new(
            "now_ms must be an integer number of milliseconds",
        ));
    }
    Ok(value as i64)
}

/// Serialize through the JSON text form so JS receives plain objects the
/// Zod schemas can parse, without a second serializer in the dependency tree.
fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let text = serde_json::to_string(value)?;
    js_sys::JSON::parse(&text).map_err(|_| JsError::new("could not build a JS value"))
}
