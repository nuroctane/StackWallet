//! NEO N3, read-only. NEO N3 signs with ECDSA over secp256r1 (P-256), a curve
//! the core does not hold: the vendored crypto covers secp256k1 (CGGMP21) and
//! Ed25519/secp256k1-Taproot (FROST), and no threshold protocol for P-256 is
//! vendored either, so shared NEO wallets cannot satisfy D1. Hand-rolling
//! P-256 field arithmetic for a custodial core is not acceptable, so this
//! module derives and validates addresses (hash-only, no curve math) and the
//! TypeScript adapter serves balances and status. There is no `NeoTx`: the
//! core cannot sign for NEO, so there is nothing for an adapter to prepare.
//! Test vectors come from the official `@cityofzion/neon-core` bundle, run in
//! `.nur/neo-scratch/oracle.mjs`.

use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

/// CAIP-2: NEO N3 mainnet, network magic 860833102.
pub const NEO3_MAINNET: &str = "neo3:mainnet";
/// CAIP-2: NEO N3 testnet, network magic 894710606.
pub const NEO3_TESTNET: &str = "neo3:testnet3";
const ADDRESS_VERSION: u8 = 0x35;
/// Interop hash of `System.Crypto.CheckSig`: sha256(name)[0..4], as neon-core emits it.
const CHECKSIG: [u8; 4] = [0x56, 0xe7, 0xb3, 0x27];
/// P-256 field modulus; an SEC1 x coordinate at or above it is not a point.
const FIELD_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "NEO address",
        reason: reason.into(),
    }
}

/// NEO is read-only for the reasons in the module docs; this rejects any
/// signing request and accepts both known networks for address work.
pub fn check_chain(chain: &str) -> Result<()> {
    if chain != NEO3_MAINNET && chain != NEO3_TESTNET {
        return Err(invalid("unknown NEO chain"));
    }
    Ok(())
}

fn hash160(bytes: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(bytes)).into()
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The single-signature verification script `0x0C 0x21 <pubkey> 0x41 56e7b327`
/// (PUSHDATA1 of the 33-byte compressed SEC1 key, then SYSCALL CheckSig).
pub fn verification_script(public: &[u8]) -> Result<[u8; 40]> {
    if public.len() != 33 || (public[0] != 0x02 && public[0] != 0x03) {
        return Err(invalid("public key must be 33-byte compressed SEC1"));
    }
    let x: [u8; 32] = public[1..].try_into().expect("32 bytes");
    if x >= FIELD_P {
        return Err(invalid("public key x coordinate out of range"));
    }
    let mut script = [0u8; 40];
    script[0] = 0x0c;
    script[1] = 0x21;
    script[2..35].copy_from_slice(public);
    script[35] = 0x41;
    script[36..].copy_from_slice(&CHECKSIG);
    Ok(script)
}

/// The 21-byte `0x35 || hash160(verificationScript)` payload behind an address.
pub fn address_payload(public: &[u8]) -> Result<[u8; 21]> {
    let mut payload = [0u8; 21];
    payload[0] = ADDRESS_VERSION;
    payload[1..].copy_from_slice(&hash160(&verification_script(public)?));
    Ok(payload)
}

pub fn address(public: &[u8]) -> Result<String> {
    let payload = address_payload(public)?;
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum(&payload));
    Ok(bs58::encode(full).into_string())
}

/// Validates a base58check NEO address and returns its 21-byte payload.
pub fn address_bytes(address: &str) -> Result<[u8; 21]> {
    if address.len() != 34 || !address.starts_with('N') {
        return Err(invalid("address must be 34 characters starting with N"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 25 || bytes[0] != ADDRESS_VERSION {
        return Err(invalid("not a NEO address"));
    }
    let (payload, check) = bytes.split_at(21);
    if checksum(payload) != check {
        return Err(invalid("address checksum mismatch"));
    }
    Ok(payload.try_into().expect("21 bytes"))
}

/// Kept so a future signing slice can deserialize intents without a new type:
/// NEO N3 transactions carry GAS-denominated fees (`systemFee`, `networkFee`),
/// an 8-decimal NEO/GAS unit model, and expire by `validUntilBlock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NeoAddressRef {
    pub chain_id: String,
    pub address: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // `@cityofzion/neon-core` 5.10.1 (dist bundle), private key 0x01.
    const PUB_ONE: &str = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const VS_ONE: &str =
        "0c21036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964156e7b327";
    const ADDR_ONE: &str = "NVHt5YtAnadMwntAVAJLUy36M2nLYKHUeK";
    // Second neon-core vector, private key 0x7d128a…32550.
    const PUB_TWO: &str = "02d3d9c0ca31fdaf9e9151d5f1c56fb273f068d3db515fa99101ab00609ccaf5dd";
    const ADDR_TWO: &str = "NXTTm4Y92jbKRgw7yB2rnDF1kGi9m5uHrF";

    #[test]
    fn verification_script_matches_neon_core() {
        let public = hex::decode(PUB_ONE).unwrap();
        assert_eq!(hex::encode(verification_script(&public).unwrap()), VS_ONE);
    }

    #[test]
    fn addresses_match_neon_core() {
        assert_eq!(address(&hex::decode(PUB_ONE).unwrap()).unwrap(), ADDR_ONE);
        assert_eq!(address(&hex::decode(PUB_TWO).unwrap()).unwrap(), ADDR_TWO);
    }

    #[test]
    fn address_round_trips() {
        let payload = address_payload(&hex::decode(PUB_ONE).unwrap()).unwrap();
        assert_eq!(address_bytes(ADDR_ONE).unwrap(), payload);
    }

    #[test]
    fn rejects_malformed() {
        assert!(address_bytes(&ADDR_ONE[..33]).is_err());
        assert!(address_bytes("N!Ht5YtAnadMwntAVAJLUy36M2nLYKHUeK").is_err());
        let mut bad = ADDR_ONE.to_string();
        bad.replace_range(10..11, "x");
        assert!(address_bytes(&bad).is_err()); // checksum mismatch
        assert!(address(&[0x02u8; 32]).is_err()); // 32 bytes, not SEC1
        let mut uncompressed = [0x11u8; 33];
        uncompressed[0] = 0x04;
        assert!(address(&uncompressed).is_err()); // uncompressed prefix
        let mut high_x = hex::decode(PUB_ONE).unwrap();
        for b in &mut high_x[1..] {
            *b = 0xff;
        }
        assert!(address(&high_x).is_err()); // x >= field modulus
    }

    #[test]
    fn chain_gate() {
        check_chain(NEO3_MAINNET).unwrap();
        check_chain(NEO3_TESTNET).unwrap();
        assert!(check_chain("neo3:private").is_err());
    }
}
