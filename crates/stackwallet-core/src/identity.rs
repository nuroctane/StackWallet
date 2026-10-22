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
        let seed = Zeroizing::new(self.signing.to_bytes());
        Hkdf::<sha2_v011::Sha256>::new(None, seed.as_ref())
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

const SEAL_INFO: &[u8] = b"stackwallet/v1/ceremony-seal";
const SEAL_NONCE_LEN: usize = 24;

/// Whether a message's body is sealed end to end to its recipient: every
/// addressed protocol round. DKG round 2 carries one party's polynomial at the
/// recipient's index, and a relay that read those could rebuild every
/// polynomial and so the group key; sealing leaves a hub able to drop or
/// delay traffic, never to read it. Proposals (round 0) carry nothing secret.
pub fn is_sealed(msg: &CeremonyMessage) -> bool {
    msg.to_device_id.is_some() && msg.round != 0
}

fn seal_key(
    identity: &DeviceIdentity,
    peer_static: &[u8; PUBLIC_KEY_LEN],
    sender_static: &[u8; PUBLIC_KEY_LEN],
    recipient_static: &[u8; PUBLIC_KEY_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    use sha2_v011::Sha256;
    let shared = Zeroizing::new(
        identity
            .noise_static()
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer_static))
            .to_bytes(),
    );
    // A low-order peer key makes the shared secret all zero; refuse it.
    if shared.iter().all(|b| *b == 0) {
        return Err(CoreError::Crypto("degenerate ceremony seal key"));
    }
    let mut salt = Vec::with_capacity(2 * PUBLIC_KEY_LEN);
    salt.extend_from_slice(sender_static);
    salt.extend_from_slice(recipient_static);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.as_ref())
        .expand(SEAL_INFO, key.as_mut())
        .map_err(|_| CoreError::Crypto("hkdf"))?;
    Ok(key)
}

/// The envelope fields a sealed body is bound to: everything but the body.
fn seal_aad(msg: &CeremonyMessage) -> Vec<u8> {
    ceremony_message_bytes(&CeremonyMessage {
        body_hex: String::new(),
        ..msg.clone()
    })
}

/// Encrypt an addressed protocol message's body to the recipient's pinned
/// Noise static key (static-static X25519, HKDF, XChaCha20-Poly1305 with the
/// envelope as associated data). Other messages pass through unchanged.
pub fn seal_for(
    identity: &DeviceIdentity,
    recipient_static_hex: &str,
    msg: CeremonyMessage,
) -> Result<CeremonyMessage> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    if !is_sealed(&msg) {
        return Ok(msg);
    }
    let recipient = static_from_hex(recipient_static_hex)?;
    let key = seal_key(
        identity,
        &recipient,
        &identity.noise_static_public(),
        &recipient,
    )?;
    let nonce: [u8; SEAL_NONCE_LEN] = random_array()?;
    let body = hex::decode(&msg.body_hex).map_err(|_| CoreError::Invalid {
        what: "ceremony message",
        reason: "body is not hex".into(),
    })?;
    let ct = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &body,
                aad: &seal_aad(&msg),
            },
        )
        .map_err(|_| CoreError::Crypto("ceremony seal"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(CeremonyMessage {
        body_hex: hex::encode(out),
        ..msg
    })
}

/// Open a sealed body addressed to this device, from the sender whose pinned
/// Noise static key is `sender_static_hex`. A body that does not open (a
/// relay altered it, or it was sealed to someone else) is refused.
pub fn open_from(
    identity: &DeviceIdentity,
    sender_static_hex: &str,
    msg: CeremonyMessage,
) -> Result<CeremonyMessage> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    if !is_sealed(&msg) {
        return Ok(msg);
    }
    if msg.to_device_id.as_deref() != Some(identity.device_id().as_str()) {
        return Err(CoreError::Invalid {
            what: "ceremony message",
            reason: "sealed for another device".into(),
        });
    }
    let sender = static_from_hex(sender_static_hex)?;
    let key = seal_key(identity, &sender, &sender, &identity.noise_static_public())?;
    let sealed = hex::decode(&msg.body_hex).map_err(|_| CoreError::Invalid {
        what: "ceremony message",
        reason: "body is not hex".into(),
    })?;
    if sealed.len() < SEAL_NONCE_LEN + 16 {
        return Err(CoreError::Invalid {
            what: "ceremony message",
            reason: "sealed body too short".into(),
        });
    }
    let (nonce, ct) = sealed.split_at(SEAL_NONCE_LEN);
    let body = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            &XNonce::from(<[u8; SEAL_NONCE_LEN]>::try_from(nonce).expect("split at nonce length")),
            Payload {
                msg: ct,
                aad: &seal_aad(&msg),
            },
        )
        .map_err(|_| CoreError::Crypto("ceremony body did not open"))?;
    Ok(CeremonyMessage {
        body_hex: hex::encode(body),
        ..msg
    })
}

fn static_from_hex(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN]> {
    hex::decode(hex_str)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| CoreError::Invalid {
            what: "noise static key",
            reason: "expected 32 hex-encoded bytes".into(),
        })
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

    fn addressed(from: &DeviceIdentity, to: &DeviceIdentity, round: u8) -> CeremonyMessage {
        CeremonyMessage {
            session_id: "s".into(),
            payload_hash_hex: "ab".repeat(32),
            from_device_id: from.device_id(),
            to_device_id: Some(to.device_id()),
            round,
            body_hex: "0102030405".into(),
        }
    }

    #[test]
    fn addressed_rounds_open_only_for_their_recipient() {
        let (a, b, hub) = (
            DeviceIdentity::generate().unwrap(),
            DeviceIdentity::generate().unwrap(),
            DeviceIdentity::generate().unwrap(),
        );
        let msg = addressed(&a, &b, 2);
        let sealed = seal_for(&a, &b.noise_static_public_hex(), msg.clone()).unwrap();
        assert_ne!(sealed.body_hex, msg.body_hex);
        assert!(!sealed.body_hex.contains("0102030405"));
        assert_eq!(
            open_from(&b, &a.noise_static_public_hex(), sealed.clone()).unwrap(),
            msg
        );
        // The relaying hub cannot open it, even claiming to be the recipient.
        assert!(open_from(&hub, &a.noise_static_public_hex(), sealed.clone()).is_err());
        let mut rerouted = sealed.clone();
        rerouted.to_device_id = Some(hub.device_id());
        assert!(open_from(&hub, &a.noise_static_public_hex(), rerouted).is_err());
        // Any change to the envelope or body breaks it.
        let mut moved = sealed.clone();
        moved.round = 1;
        assert!(open_from(&b, &a.noise_static_public_hex(), moved).is_err());
        let mut flipped = sealed.clone();
        flipped.body_hex.replace_range(60..62, "00");
        assert!(open_from(&b, &a.noise_static_public_hex(), flipped).is_err());
        // Wrong sender key: the shared secret differs.
        assert!(open_from(&b, &hub.noise_static_public_hex(), sealed).is_err());
    }

    #[test]
    fn broadcasts_and_proposals_stay_readable() {
        let (a, b) = (
            DeviceIdentity::generate().unwrap(),
            DeviceIdentity::generate().unwrap(),
        );
        let proposal = addressed(&a, &b, 0);
        assert_eq!(
            seal_for(&a, &b.noise_static_public_hex(), proposal.clone()).unwrap(),
            proposal
        );
        let broadcast = CeremonyMessage {
            to_device_id: None,
            ..addressed(&a, &b, 1)
        };
        assert_eq!(
            seal_for(&a, &b.noise_static_public_hex(), broadcast.clone()).unwrap(),
            broadcast
        );
        // A low-order point is refused rather than yielding a zero key.
        assert!(seal_for(&a, &"00".repeat(32), addressed(&a, &b, 2)).is_err());
    }
}
