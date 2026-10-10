//! Device identity: one Ed25519 key per install, generated locally and held in
//! the vault. Pairing pins the public half on every peer; afterwards every
//! ceremony message is signed with it so an unknown or substituted device is
//! refused before any protocol code runs.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::tss::CeremonyMessage;
use crate::vault::{random_array, Secret};
use crate::{CoreError, Result};

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Separates ceremony signatures from any other message a device might sign
/// with the same key, so a signature can never be replayed across purposes.
const CEREMONY_DOMAIN: &[u8] = b"stackwallet/v1/ceremony-message";

/// HKDF label for the X25519 Noise static key derived from the identity seed.
const NOISE_STATIC_INFO: &[u8] = b"stackwallet/v1/noise-static";

/// The device's long-term Ed25519 signing key.
pub struct DeviceIdentity {
    signing: SigningKey,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id())
            .field("public_hex", &self.public_hex())
            .finish()
    }
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self> {
        let seed = Zeroizing::new(random_array::<SEED_LEN>()?);
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Restore from the 32-byte seed produced by [`DeviceIdentity::to_secret`].
    pub fn from_secret(seed: &Secret) -> Result<Self> {
        let bytes: Zeroizing<[u8; SEED_LEN]> = seed
            .expose()
            .try_into()
            .map(Zeroizing::new)
            .map_err(|_| CoreError::Invalid {
                what: "identity seed",
                reason: format!("expected {SEED_LEN} bytes, got {}", seed.len()),
            })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    /// The seed, for storage in the vault.
    pub fn to_secret(&self) -> Secret {
        Secret::new(self.signing.to_bytes().to_vec())
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Stable identifier derived from the public key; see [`device_id_for_public_key`].
    pub fn device_id(&self) -> String {
        device_id_for_public_key(&self.public_key())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(msg).to_bytes()
    }

    /// The X25519 static key the Noise channel authenticates with. Derived from
    /// the seed with its own HKDF label rather than by converting the Ed25519
    /// key, so the two keys never share algebraic structure and the identity
    /// key is only ever used for signatures.
    pub fn noise_static(&self) -> Zeroizing<x25519_dalek::StaticSecret> {
        let mut raw = Zeroizing::new([0u8; 32]);
        Hkdf::<sha2_v011::Sha256>::new(None, &self.signing.to_bytes())
            .expand(NOISE_STATIC_INFO, raw.as_mut())
            .expect("32 bytes is within the HKDF-SHA256 output limit");
        Zeroizing::new(x25519_dalek::StaticSecret::from(*raw))
    }

    pub fn noise_static_public(&self) -> [u8; PUBLIC_KEY_LEN] {
        x25519_dalek::PublicKey::from(&*self.noise_static()).to_bytes()
    }

    pub fn noise_static_public_hex(&self) -> String {
        hex::encode(self.noise_static_public())
    }
}

/// Hex of the first 16 bytes of SHA-256(public key). Short enough for table
/// keys and QR codes, and unforgeable without the matching private key.
pub fn device_id_for_public_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..16])
}

/// Same derivation from the hex form used in directory records.
pub fn device_id_from_public_hex(public_hex: &str) -> Result<String> {
    Ok(device_id_for_public_key(
        &parse_public_key(public_hex)?.to_bytes(),
    ))
}

fn parse_public_key(public_hex: &str) -> Result<VerifyingKey> {
    let bytes: [u8; PUBLIC_KEY_LEN] = hex::decode(public_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| CoreError::Invalid {
            what: "public key",
            reason: format!("expected {PUBLIC_KEY_LEN} hex-encoded bytes"),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CoreError::Invalid {
        what: "public key",
        reason: "not a valid Ed25519 point".into(),
    })
}

/// Verify `sig` over `msg` for the device whose public key is `public_hex`.
/// Uses the strict verifier so small-order and non-canonical keys are refused.
pub fn verify(public_hex: &str, msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> Result<()> {
    let key = parse_public_key(public_hex)?;
    let signature = Signature::from_bytes(sig);
    key.verify_strict(msg, &signature)
        .map_err(|_| CoreError::Invalid {
            what: "signature",
            reason: "verification failed".into(),
        })
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Canonical byte encoding of a ceremony message for signing. Length-prefixed
/// fields in a fixed order instead of serde output, so a serializer change on
/// one device cannot produce signatures another device rejects.
pub fn ceremony_message_bytes(msg: &CeremonyMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CEREMONY_DOMAIN.len()
            + msg.session_id.len()
            + msg.payload_hash_hex.len()
            + msg.from_device_id.len()
            + msg.to_device_id.as_ref().map_or(0, String::len)
            + msg.body_hex.len()
            + 7 * 4
            + 2,
    );
    push_field(&mut out, CEREMONY_DOMAIN);
    push_field(&mut out, msg.session_id.as_bytes());
    push_field(&mut out, msg.payload_hash_hex.as_bytes());
    push_field(&mut out, msg.from_device_id.as_bytes());
    // A presence byte keeps a broadcast (None) distinct from a message
    // addressed to an empty device id.
    match &msg.to_device_id {
        Some(to) => {
            push_field(&mut out, &[1]);
            push_field(&mut out, to.as_bytes());
        }
        None => push_field(&mut out, &[0]),
    }
    push_field(&mut out, &[msg.round]);
    push_field(&mut out, msg.body_hex.as_bytes());
    out
}

/// A ceremony message plus the sender's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCeremonyMessage {
    pub msg: CeremonyMessage,
    pub signature_hex: String,
}

impl SignedCeremonyMessage {
    pub fn sign(identity: &DeviceIdentity, msg: CeremonyMessage) -> Self {
        let signature_hex = hex::encode(identity.sign(&ceremony_message_bytes(&msg)));
        Self { msg, signature_hex }
    }

    /// Check the signature against the pinned public key of the device the
    /// message claims to come from. Also requires `from_device_id` to be the id
    /// derived from that key, so a signer cannot impersonate another device by
    /// relabelling its own validly signed message.
    pub fn verify(&self, expected_public_hex: &str) -> Result<()> {
        let expected_id = device_id_from_public_hex(expected_public_hex)?;
        if self.msg.from_device_id != expected_id {
            return Err(CoreError::Invalid {
                what: "ceremony message",
                reason: "from_device_id does not match the signing key".into(),
            });
        }
        let sig: [u8; SIGNATURE_LEN] = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| CoreError::Invalid {
                what: "signature",
                reason: format!("expected {SIGNATURE_LEN} hex-encoded bytes"),
            })?;
        verify(
            expected_public_hex,
            &ceremony_message_bytes(&self.msg),
            &sig,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_stable_and_derived_from_public_key() {
        let id = DeviceIdentity::generate().unwrap();
        let restored = DeviceIdentity::from_secret(&id.to_secret()).unwrap();
        assert_eq!(id.device_id(), restored.device_id());
        assert_eq!(id.public_hex(), restored.public_hex());
        assert_eq!(id.device_id().len(), 32);
        assert_eq!(
            device_id_from_public_hex(&id.public_hex()).unwrap(),
            id.device_id()
        );
    }

    #[test]
    fn debug_never_prints_the_seed() {
        let id = DeviceIdentity::generate().unwrap();
        let seed_hex = hex::encode(id.to_secret().expose());
        let dbg = format!("{id:?}");
        assert!(!dbg.contains(&seed_hex));
        assert!(dbg.contains(&id.device_id()));
    }

    #[test]
    fn seed_length_is_enforced() {
        assert!(DeviceIdentity::from_secret(&Secret::new(vec![0u8; 31])).is_err());
        assert!(DeviceIdentity::from_secret(&Secret::new(vec![0u8; 32])).is_ok());
    }

    #[test]
    fn raw_sign_verify_roundtrip() {
        let id = DeviceIdentity::generate().unwrap();
        let sig = id.sign(b"hello");
        verify(&id.public_hex(), b"hello", &sig).unwrap();
        assert!(verify(&id.public_hex(), b"hellp", &sig).is_err());
        assert!(verify("zz", b"hello", &sig).is_err());
    }

    #[test]
    fn canonical_bytes_distinguish_field_boundaries() {
        let a = CeremonyMessage {
            session_id: "ab".into(),
            payload_hash_hex: "c".into(),
            from_device_id: "d".into(),
            to_device_id: None,
            round: 1,
            body_hex: String::new(),
        };
        let b = CeremonyMessage {
            session_id: "a".into(),
            payload_hash_hex: "bc".into(),
            ..a.clone()
        };
        assert_ne!(ceremony_message_bytes(&a), ceremony_message_bytes(&b));
    }
}
