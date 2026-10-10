//! Pairing: the one QR scan (or pasted code) that introduces two devices.
//!
//! The offer carries the issuer's public keys and a fresh one-time code. The
//! code is the Noise PSK for the pairing handshake only, so an attacker who
//! can see LAN traffic but not the QR cannot complete the handshake, and an
//! attacker who later learns the code cannot reuse it: the issuer forgets it
//! as soon as one handshake succeeds or `expires_at_ms` passes.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::store::DeviceKind;
use crate::vault::random_array;
use crate::{CoreError, Result};

use super::TRANSPORT_VERSION;

/// Bytes of entropy in the one-time code; hex in the offer.
pub const ONE_TIME_CODE_LEN: usize = 32;

/// Text form prefix so a pasted string is recognisable and never confused with
/// an address or a seed phrase.
pub const PAIRING_OFFER_PREFIX: &str = "stackwallet-pair:";

/// Contents of the pairing QR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOffer {
    pub version: u8,
    pub device_id: String,
    pub device_name: String,
    pub kind: DeviceKind,
    pub identity_pub_hex: String,
    pub noise_static_hex: String,
    pub endpoints: Vec<String>,
    pub one_time_code_hex: String,
    pub expires_at_ms: i64,
}

impl PairingOffer {
    pub fn new_code() -> Result<String> {
        Ok(hex::encode(random_array::<ONE_TIME_CODE_LEN>()?))
    }

    /// `stackwallet-pair:<base64url(JSON)>`, the string shown as QR or text.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("offer serialises");
        format!(
            "{PAIRING_OFFER_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        )
    }

    pub fn decode(text: &str) -> Result<Self> {
        let invalid = |reason: &str| CoreError::Invalid {
            what: "pairing offer",
            reason: reason.to_owned(),
        };
        let body = text
            .trim()
            .strip_prefix(PAIRING_OFFER_PREFIX)
            .ok_or_else(|| invalid("missing prefix"))?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| invalid("not base64url"))?;
        let offer: Self = serde_json::from_slice(&json).map_err(|_| invalid("malformed"))?;
        offer.validate()?;
        Ok(offer)
    }

    pub fn validate(&self) -> Result<()> {
        let invalid = |reason: &str| CoreError::Invalid {
            what: "pairing offer",
            reason: reason.to_owned(),
        };
        if self.version != TRANSPORT_VERSION {
            return Err(invalid("unsupported version"));
        }
        if crate::identity::device_id_from_public_hex(&self.identity_pub_hex)? != self.device_id {
            return Err(invalid("device id does not match identity key"));
        }
        if decode_32(&self.noise_static_hex).is_none() {
            return Err(invalid("noise static key must be 32 hex-encoded bytes"));
        }
        if decode_32(&self.one_time_code_hex).is_none() {
            return Err(invalid("one-time code must be 32 hex-encoded bytes"));
        }
        if self.device_name.trim().is_empty() || self.device_name.len() > 64 {
            return Err(invalid("device name must be 1-64 bytes"));
        }
        // Same bounds as `Hello`: an offer is pinned into the store as-is.
        if self.endpoints.len() > 16 || self.endpoints.iter().any(|e| e.len() > 256) {
            return Err(invalid("too many or too long endpoints"));
        }
        Ok(())
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    pub fn one_time_code(&self) -> [u8; ONE_TIME_CODE_LEN] {
        decode_32(&self.one_time_code_hex).expect("validated")
    }

    pub fn noise_static(&self) -> [u8; 32] {
        decode_32(&self.noise_static_hex).expect("validated")
    }
}

pub(crate) fn decode_32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}
