//! Canton Network, read-only. Canton transfers are DAML exercises submitted
//! to a participant/validator node; an external party (self-custody key) must
//! first be onboarded with three topology transactions (PartyToParticipant,
//! ParticipantToParty, KeyToParty) signed by its own key, and every transfer
//! needs an authenticated validator node to propose and confirm. There is no
//! keyless public API that accepts external-party transactions, and the SV
//! scan APIs answer 403 (RBAC) with no CORS from the public internet
//! (probed 2026-10-17, evidence in `.nur/wiring/canton.md`), so the core
//! cannot sign for Canton today and this module owns the party-id codec.
//!
//! Keys are plain ed25519 (the wallet-sdk uses tweetnacl 64-byte secrets, so
//! the core's 32-byte seeds are the right secret). A party id is
//! `hint::fingerprint`, where the fingerprint is `1220 || sha256(0x0000000C
//! || public key)` hex — a sha2-256 multihash of the "public key" namespace
//! — per the wallet-sdk KeysNamespace. Vectors pinned against
//! `@canton-network/wallet-sdk` (run in `.nur/canton-oracle`).

use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

/// CAIP-2: Canton mainnet (the global synchronizer).
pub const CANTON_MAINNET: &str = "canton:mainnet";
/// CAIP-2: Canton testnet.
pub const CANTON_TESTNET: &str = "canton:testnet";
/// SLIP-44 coin type (used by the wallet-sdk as `CC_COIN_TYPE`).
pub const COIN_TYPE: u32 = 6767;
/// The multihash prefix of a Canton fingerprint: sha2-256 (0x12), 32 bytes (0x20).
const FINGERPRINT_PREFIX: &str = "1220";
/// DAML's public-key purpose tag hashed before the key bytes.
const PUBLIC_KEY_PURPOSE: [u8; 4] = [0x00, 0x00, 0x00, 0x0c];

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Canton party",
        reason: reason.into(),
    }
}

/// Canton is read-only for the reasons in the module docs; this rejects any
/// signing request and accepts both known networks for address work.
pub fn check_chain(chain: &str) -> Result<()> {
    if chain != CANTON_MAINNET && chain != CANTON_TESTNET {
        return Err(invalid("unknown Canton chain"));
    }
    Ok(())
}

/// The 68-hex-char fingerprint of a 32-byte ed25519 public key:
/// `1220 || sha256(0x0000000C || public key)`.
pub fn fingerprint(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("ed25519 public key must be 32 bytes"))?;
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_KEY_PURPOSE);
    hasher.update(key);
    Ok(format!(
        "{FINGERPRINT_PREFIX}{}",
        hex::encode(hasher.finalize())
    ))
}

fn check_hint(hint: &str) -> Result<()> {
    // Party-id hints are user-chosen display names; keep them single-segment
    // so the `hint::fingerprint` split stays unambiguous.
    if hint.is_empty()
        || hint.len() > 64
        || !hint
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid(
            "hint must be 1-64 lowercase alphanumerics or dashes",
        ));
    }
    Ok(())
}

/// The party id `hint::fingerprint` for a hint and a 32-byte ed25519 key.
pub fn party_id(hint: &str, public: &[u8]) -> Result<String> {
    check_hint(hint)?;
    Ok(format!("{hint}::{}", fingerprint(public)?))
}

/// Validates a party id and returns `(hint, fingerprint)`. The fingerprint
/// must carry the sha2-256 multihash prefix.
pub fn parse_party_id(party: &str) -> Result<(String, String)> {
    let (hint, fingerprint) = party
        .split_once("::")
        .ok_or_else(|| invalid("party id must be `hint::fingerprint`"))?;
    check_hint(hint)?;
    if fingerprint.len() != 68
        || !fingerprint.starts_with(FINGERPRINT_PREFIX)
        || !fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b.is_ascii_lowercase())
        || fingerprint.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(invalid(
            "fingerprint must be 68 lowercase hex chars starting 1220",
        ));
    }
    Ok((hint.to_string(), fingerprint.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `@canton-network/wallet-sdk` vectors (`.nur/canton-oracle/oracle3.mjs`):
    // ed25519 public keys from nacl seeds 0x00.. / 0x07.. and the sdk's
    // `fingerprintOf` output.
    const PUB_ZEROS: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const FP_ZEROS: &str = "1220e5a40f14dfbef0e161b3c7f9bb2b03695c984659d4c9489e669ecd8249c0b745";
    const PUB_SEVENS: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const FP_SEVENS: &str = "12205822a4a1eae801223c158e256fef229d956e3911284b9c3a7956200f61787ca6";

    #[test]
    fn fingerprints_match_wallet_sdk() {
        assert_eq!(
            fingerprint(&hex::decode(PUB_ZEROS).unwrap()).unwrap(),
            FP_ZEROS
        );
        assert_eq!(
            fingerprint(&hex::decode(PUB_SEVENS).unwrap()).unwrap(),
            FP_SEVENS
        );
    }

    #[test]
    fn party_ids_round_trip() {
        let party = party_id("alice-1", &hex::decode(PUB_ZEROS).unwrap()).unwrap();
        assert_eq!(party, format!("alice-1::{FP_ZEROS}"));
        let (hint, fp) = parse_party_id(&party).unwrap();
        assert_eq!(hint, "alice-1");
        assert_eq!(fp, FP_ZEROS);
    }

    #[test]
    fn rejects_malformed() {
        assert!(fingerprint(&[0u8; 31]).is_err()); // wrong key length
        assert!(parse_party_id(FP_ZEROS).is_err()); // missing hint
        assert!(parse_party_id(&format!("::{FP_ZEROS}")).is_err()); // empty hint
        assert!(parse_party_id(&format!("Alice::{FP_ZEROS}")).is_err()); // uppercase hint
        assert!(parse_party_id(&format!("alice::{FP_ZEROS}::extra")).is_err()); // ambiguous
        assert!(parse_party_id(&format!("alice::{}", &FP_ZEROS[4..])).is_err()); // no 1220
        let upper = format!("alice::{}", FP_ZEROS.to_uppercase());
        assert!(parse_party_id(&upper).is_err()); // uppercase fingerprint
        assert!(party_id("has space", &hex::decode(PUB_ZEROS).unwrap()).is_err());
    }

    #[test]
    fn chain_gate() {
        check_chain(CANTON_MAINNET).unwrap();
        check_chain(CANTON_TESTNET).unwrap();
        assert!(check_chain("canton:devnet").is_err());
    }
}
