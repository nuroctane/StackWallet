//! Aleo, read-only. Every Aleo execution — including `credits.aleo`'s
//! `transfer_public` — is a zero-knowledge proof the client must prove
//! locally with snarkVM (wasm or native); there is no "sign bytes and
//! broadcast" path on Aleo. Shipping a prover is a project of its own
//! (snarkVM is a full zkVM stack, not a curve), so this module owns the
//! address codec and validation, and the TypeScript adapter serves balances
//! and status. There is no `AleoTx`: the core cannot prove, so there is
//! nothing for an adapter to prepare.
//!
//! Addresses are bech32m (NOT bech32), hrp `aleo`, 32-byte payload: the
//! little-endian x-coordinate of the account's group element on the
//! Edwards-BLS12 curve, i.e. a BLS12-377 scalar-field element. Key derivation
//! (seed -> private key -> address) runs through Poseidon hashing inside
//! snarkVM and is deliberately not re-implemented here; the official
//! `@provablehq/sdk` vectors are recorded in `.nur/wiring/aleo.md` for a
//! future signing slice.

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};

use crate::{CoreError, Result};

/// CAIP-2: Aleo mainnet.
pub const ALEO_MAINNET: &str = "aleo:mainnet";
/// CAIP-2: Aleo testnet (served by the same explorer API under /testnet).
pub const ALEO_TESTNET: &str = "aleo:testnet";
const HRP: &str = "aleo";

/// BLS12-377 scalar-field modulus (the Edwards-BLS12 base field), LE bytes.
/// An address payload at or above it is not a field element.
const FIELD_R: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, 0x0a, 0x01, 0x00, 0x00, 0xd0, 0xfe, 0x76, 0xaa, 0x59,
    0x01, 0xb0, 0x37, 0x5c, 0x1e, 0x4d, 0xb4, 0x60, 0x56, 0xa5, 0x2c, 0x9a, 0x5e, 0x65, 0xab, 0x12,
];

/// Little-endian `raw >= FIELD_R` (byte-array order is lexicographic, so
/// compare most-significant-first).
fn over_field(raw: &[u8; 32]) -> bool {
    raw.iter().rev().cmp(FIELD_R.iter().rev()) != std::cmp::Ordering::Less
}

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Aleo address",
        reason: reason.into(),
    }
}

/// Aleo is read-only for the reasons in the module docs; this rejects any
/// signing request and accepts both known networks for address work.
pub fn check_chain(chain: &str) -> Result<()> {
    if chain != ALEO_MAINNET && chain != ALEO_TESTNET {
        return Err(invalid("unknown Aleo chain"));
    }
    Ok(())
}

/// The bech32m address for a 32-byte payload (field element, little-endian).
pub fn address(payload: &[u8]) -> Result<String> {
    let raw: [u8; 32] = payload
        .try_into()
        .map_err(|_| invalid("address payload must be 32 bytes"))?;
    if over_field(&raw) {
        return Err(invalid("payload is not a scalar-field element"));
    }
    bech32::encode::<Bech32m>(Hrp::parse(HRP).expect("static hrp"), &raw)
        .map_err(|_| invalid("address encoding failed"))
}

/// Validates an `aleo1…` address and returns its 32-byte payload.
/// Non-canonical spellings (uppercase, non-field-element payloads) are
/// rejected so an address has exactly one spelling.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() > 90 {
        return Err(invalid("address too long"));
    }
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|_| invalid("invalid bech32m address"))?;
    if checked.hrp().as_str() != HRP {
        return Err(invalid("not an aleo address"));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("address payload must be 32 bytes"))?;
    if over_field(&raw) {
        return Err(invalid("payload is not a scalar-field element"));
    }
    if self::address(&raw)? != address {
        return Err(invalid("address is not canonical"));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `@provablehq/sdk` vectors (run in `.nur/aleo-oracle/vectors.mjs`):
    // address <-> 32-byte payload (little-endian field element).
    const ADDR_ZEROS_SEED: &str = "aleo136hx49mdevlqlnrlkhr2alxwn45qtpxv64jwrzk4rv39sclw6yxsms49ms";
    const PAYLOAD_ZEROS_SEED: &str =
        "8eae6a976dcb3e0fcc7fb5c6aefcce9d680584ccd564e18ad51b225863eed10d";
    const ADDR_SEVENS_SEED: &str =
        "aleo1vlklqexj7vrs3vrw77agv5cxucqje6yuuu6lyvgteww3utzlnvrszhlqty";
    const PAYLOAD_SEVENS_SEED: &str =
        "67edf064d2f30708b06ef7ba865306e6012ce89ce735f2310bcb9d1e2c5f9b07";
    const ZERO_ADDRESS: &str = "aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc";

    #[test]
    fn addresses_match_provable_sdk() {
        let payload = hex::decode(PAYLOAD_ZEROS_SEED).unwrap();
        assert_eq!(address(&payload).unwrap(), ADDR_ZEROS_SEED);
        let payload = hex::decode(PAYLOAD_SEVENS_SEED).unwrap();
        assert_eq!(address(&payload).unwrap(), ADDR_SEVENS_SEED);
        assert_eq!(address(&[0u8; 32]).unwrap(), ZERO_ADDRESS);
    }

    #[test]
    fn address_round_trips() {
        let payload: [u8; 32] = hex::decode(PAYLOAD_ZEROS_SEED).unwrap().try_into().unwrap();
        assert_eq!(address_bytes(ADDR_ZEROS_SEED).unwrap(), payload);
        assert_eq!(address_bytes(ZERO_ADDRESS).unwrap(), [0u8; 32]);
    }

    #[test]
    fn rejects_malformed() {
        assert!(address_bytes(&ADDR_ZEROS_SEED[..58]).is_err()); // truncated
        assert!(address_bytes(&ADDR_ZEROS_SEED.to_uppercase()).is_err()); // not canonical
        let mut bad = ADDR_ZEROS_SEED.to_string();
        bad.replace_range(10..11, "x");
        assert!(address_bytes(&bad).is_err()); // checksum mismatch
        assert!(address_bytes(&bad.replace("aleo1", "tnam1")).is_err()); // wrong hrp
        assert!(address(&[0u8; 31]).is_err()); // wrong payload length
        assert!(address(&[0xffu8; 32]).is_err()); // payload >= field modulus
    }

    #[test]
    fn bech32_not_bech32m_is_rejected() {
        // A bech32 (not bech32m) encoding of the same payload must fail:
        // the last checksum character differs between the variants.
        let payload = hex::decode(PAYLOAD_ZEROS_SEED).unwrap();
        let bech32_addr =
            bech32::encode::<bech32::Bech32>(Hrp::parse(HRP).expect("static hrp"), &payload)
                .unwrap();
        assert!(address_bytes(&bech32_addr).is_err());
    }

    #[test]
    fn chain_gate() {
        check_chain(ALEO_MAINNET).unwrap();
        check_chain(ALEO_TESTNET).unwrap();
        assert!(check_chain("aleo:canary").is_err());
    }
}
