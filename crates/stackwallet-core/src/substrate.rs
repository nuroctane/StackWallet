//! Native `Balances.transfer_keep_alive` on Substrate chains, as signed extrinsic v4
//! with an Ed25519 `MultiSignature`. The core encodes the call, the signed extensions
//! and their implicit data from checked fields and a per-chain runtime table, so an
//! adapter cannot change the call, add extensions or pay fees in another asset.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the first 16 bytes of the genesis hash.
pub const WESTEND: &str = "polkadot:e143f23803ac50e8f6f8e62695d1ce9e";
pub const WESTEND_ASSET_HUB: &str = "polkadot:67f9723393ef76214df0118c34bbbd3d";

const SS58_GENERIC: u16 = 42;
const MAX_TIP: u128 = 1_000_000_000_000;
const MIN_ERA_PERIOD: u32 = 4;
/// Westend's `BlockHashCount`; a longer era would point at a birth hash the chain forgot.
const MAX_ERA_PERIOD: u32 = 4096;
const SIGNED_V4: u8 = 0x84;
const MULTI_ADDRESS_ID: u8 = 0x00;
const MULTI_SIGNATURE_ED25519: u8 = 0x00;

type Blake2b256 = Blake2b<U32>;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Substrate transfer",
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeeExtension {
    /// `ChargeTransactionPayment`: `Compact<u128>` tip.
    Native,
    /// `ChargeAssetTxPayment`: `Compact<u128>` tip then `Option<Location>`, always `None`.
    Asset,
}

/// What the live runtime metadata declared when this entry was checked. Both entries carry
/// the extensions AuthorizeCall, CheckNonZeroSender, CheckSpecVersion, CheckTxVersion,
/// CheckGenesis, CheckMortality, CheckNonce, CheckWeight, the fee extension and
/// CheckMetadataHash, with only zero-sized trailers after them (WeightReclaim on the relay;
/// EthSetOrigin and StorageWeightReclaim on Asset Hub). A `transaction_version` bump is
/// how a runtime announces a change to call indices or extensions, so any other version is
/// refused until the table is re-verified.
struct Runtime {
    chain_id: &'static str,
    genesis: [u8; 32],
    ss58: u16,
    /// `(Balances pallet index, transfer_keep_alive call index)`.
    call: [u8; 2],
    transaction_version: u32,
    fee: FeeExtension,
}

const RUNTIMES: &[Runtime] = &[
    Runtime {
        chain_id: WESTEND,
        genesis: hex32("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"),
        ss58: SS58_GENERIC,
        call: [0x04, 0x03],
        transaction_version: 27,
        fee: FeeExtension::Native,
    },
    Runtime {
        chain_id: WESTEND_ASSET_HUB,
        genesis: hex32("67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9"),
        ss58: SS58_GENERIC,
        call: [0x0a, 0x03],
        transaction_version: 16,
        fee: FeeExtension::Asset,
    },
];

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("lowercase hex only"),
    }
}

fn runtime(chain: &str) -> Result<&'static Runtime> {
    RUNTIMES
        .iter()
        .find(|r| r.chain_id == chain)
        .ok_or_else(|| invalid("only Westend and Westend Asset Hub transfers are enabled"))
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnets stay disabled until the family's testnet and threshold support gates pass.
    runtime(chain).map(|_| ())
}

fn ss58_checksum(prefix: &[u8], account: &[u8; 32]) -> [u8; 2] {
    let mut h = Blake2b512::new();
    h.update(b"SS58PRE");
    h.update(prefix);
    h.update(account);
    let d = h.finalize();
    [d[0], d[1]]
}

fn ss58_prefix_bytes(prefix: u16) -> Vec<u8> {
    if prefix < 64 {
        vec![prefix as u8]
    } else {
        vec![
            ((prefix & 0b1111_1100) >> 2) as u8 | 0b0100_0000,
            (prefix >> 8) as u8 | ((prefix & 0b11) << 6) as u8,
        ]
    }
}

/// SS58 for a 32-byte account under a network prefix (0..16383, excluding reserved 46/47).
pub fn encode_address(account: &[u8; 32], prefix: u16) -> Result<String> {
    if prefix > 16383 || prefix == 46 || prefix == 47 {
        return Err(invalid("unsupported SS58 prefix"));
    }
    let mut out = ss58_prefix_bytes(prefix);
    let check = ss58_checksum(&out, account);
    out.extend_from_slice(account);
    out.extend_from_slice(&check);
    Ok(bs58::encode(out).into_string())
}

/// The account behind an SS58 address that must carry exactly `prefix`.
pub fn address_bytes(address: &str, prefix: u16) -> Result<[u8; 32]> {
    if address.len() > 50 {
        return Err(invalid("address too long"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    let (found, plen) = match bytes.first() {
        Some(&b) if b < 64 => (b as u16, 1),
        Some(&b) if b < 128 && bytes.len() > 1 => {
            let lower = (b << 2) | (bytes[1] >> 6);
            let upper = bytes[1] & 0b0011_1111;
            (lower as u16 | ((upper as u16) << 8), 2)
        }
        _ => return Err(invalid("not an SS58 address")),
    };
    if bytes.len() != plen + 34 {
        return Err(invalid("address is not a 32-byte account"));
    }
    if found != prefix {
        return Err(invalid("address belongs to another network"));
    }
    let account: [u8; 32] = bytes[plen..plen + 32].try_into().expect("32 bytes");
    if ss58_checksum(&bytes[..plen], &account) != bytes[plen + 32..] {
        return Err(invalid("address checksum mismatch"));
    }
    if account == [0; 32] {
        return Err(invalid("zero account"));
    }
    // A two-byte prefix can encode small values non-canonically; only the shortest form is accepted.
    if encode_address(&account, prefix)? != address {
        return Err(invalid("address is not canonical"));
    }
    Ok(account)
}

/// Westend-format (prefix 42) address of an Ed25519 public key.
pub fn address(public: &[u8]) -> Result<String> {
    let account: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    encode_address(&account, SS58_GENERIC)
}

fn compact(value: u128, out: &mut Vec<u8>) {
    match value {
        0..=0x3f => out.push((value as u8) << 2),
        0x40..=0x3fff => out.extend_from_slice(&(((value as u16) << 2) | 1).to_le_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(((value as u32) << 2) | 2).to_le_bytes()),
        _ => {
            let bytes = value.to_le_bytes();
            let len = 16 - (value.leading_zeros() as usize / 8);
            out.push((((len - 4) as u8) << 2) | 3);
            out.extend_from_slice(&bytes[..len]);
        }
    }
}

fn fixed_hash(value: &str, what: &str) -> Result<[u8; 32]> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{what} must be 0x-prefixed")))?;
    if digits.len() != 64 || digits.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be 32 lowercase hex bytes")));
    }
    let bytes = hex::decode(digits).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

fn canonical_u128(value: &str, what: &str) -> Result<u128> {
    let n = value
        .parse::<u128>()
        .map_err(|_| invalid(format!("{what} must be a u128 decimal")))?;
    if n.to_string() != value {
        return Err(invalid(format!("{what} must be a canonical decimal")));
    }
    Ok(n)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubstrateTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal planck (1 WND = 10^12 planck); never a JSON floating-point number.
    pub planck: String,
    /// Decimal planck tip on top of the fee.
    pub tip: String,
    pub nonce: u32,
    pub spec_version: u32,
    pub transaction_version: u32,
    /// 0x-prefixed genesis hash; must be the one the chain id names.
    pub genesis_hash: String,
    /// Era birth block: its hash is signed and the transaction is valid for `era_period` blocks from it.
    pub block_hash: String,
    pub block_number: u32,
    /// Power of two; the extrinsic can only be included while `block_number + era_period` is ahead.
    pub era_period: u32,
    /// `CheckMetadataHash` mode; only 0 (disabled) is accepted.
    pub metadata_hash_mode: u8,
}

struct Checked {
    runtime: &'static Runtime,
    from: [u8; 32],
    call: Vec<u8>,
    extra: Vec<u8>,
    implicit: Vec<u8>,
}

impl SubstrateTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        let checked = self.checked()?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native transfers are enabled"));
                }
                let ss58 = checked.runtime.ss58;
                if address_bytes(to, ss58)? != address_bytes(&self.to, ss58)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.planck {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Substrate intent")),
        }
        Ok(())
    }

    /// Mortal era bytes: the low nibble is log2(period) - 1, the rest is the birth phase.
    fn era(&self) -> Result<[u8; 2]> {
        let period = self.era_period;
        if !period.is_power_of_two() || !(MIN_ERA_PERIOD..=MAX_ERA_PERIOD).contains(&period) {
            return Err(invalid("era period must be a power of two from 4 to 4096"));
        }
        let phase = self.block_number % period;
        // Periods up to 4096 have a quantize factor of 1, so every phase is exact.
        let encoded = (period.trailing_zeros() - 1).clamp(1, 15) as u16 | ((phase as u16) << 4);
        Ok(encoded.to_le_bytes())
    }

    fn checked(&self) -> Result<Checked> {
        let runtime = runtime(&self.chain_id)?;
        let from = address_bytes(&self.from, runtime.ss58)?;
        let to = address_bytes(&self.to, runtime.ss58)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u128(&self.planck, "amount")?;
        if amount == 0 {
            return Err(invalid("amount must be positive"));
        }
        let tip = canonical_u128(&self.tip, "tip")?;
        if tip > MAX_TIP {
            return Err(invalid("tip is unreasonably large"));
        }
        if self.spec_version == 0 {
            return Err(invalid("spec version must be set"));
        }
        if self.transaction_version != runtime.transaction_version {
            return Err(invalid(
                "transaction version differs from the verified runtime layout",
            ));
        }
        if fixed_hash(&self.genesis_hash, "genesis hash")? != runtime.genesis {
            return Err(invalid("genesis hash differs from the chain id"));
        }
        let block_hash = fixed_hash(&self.block_hash, "block hash")?;
        if block_hash == [0; 32] {
            return Err(invalid("zero block hash"));
        }
        if self.metadata_hash_mode != 0 {
            return Err(invalid("metadata hash mode must be disabled"));
        }

        let mut call = runtime.call.to_vec();
        call.push(MULTI_ADDRESS_ID);
        call.extend_from_slice(&to);
        compact(amount, &mut call);

        let mut extra = self.era()?.to_vec();
        compact(self.nonce as u128, &mut extra);
        compact(tip, &mut extra);
        if runtime.fee == FeeExtension::Asset {
            extra.push(0x00);
        }
        extra.push(self.metadata_hash_mode);

        let mut implicit = Vec::with_capacity(4 + 4 + 32 + 32 + 1);
        implicit.extend_from_slice(&self.spec_version.to_le_bytes());
        implicit.extend_from_slice(&self.transaction_version.to_le_bytes());
        implicit.extend_from_slice(&runtime.genesis);
        implicit.extend_from_slice(&block_hash);
        // CheckMetadataHash implicit data: `Option<[u8; 32]>::None` while the mode is disabled.
        implicit.push(0x00);

        Ok(Checked {
            runtime,
            from,
            call,
            extra,
            implicit,
        })
    }

    /// `call ++ extra ++ implicit`, the bytes whose signature (or blake2-256 if longer
    /// than 256 bytes) authorizes the extrinsic.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let c = self.checked()?;
        Ok([c.call, c.extra, c.implicit].concat())
    }

    fn signed_message(payload: Vec<u8>) -> Vec<u8> {
        if payload.len() > 256 {
            Blake2b256::digest(&payload).to_vec()
        } else {
            payload
        }
    }

    fn assemble(&self, signature: &[u8; 64]) -> Result<Vec<u8>> {
        let c = self.checked()?;
        let mut body = vec![SIGNED_V4, MULTI_ADDRESS_ID];
        body.extend_from_slice(&c.from);
        body.push(MULTI_SIGNATURE_ED25519);
        body.extend_from_slice(signature);
        body.extend_from_slice(&c.extra);
        body.extend_from_slice(&c.call);
        let mut out = Vec::with_capacity(body.len() + 2);
        compact(body.len() as u128, &mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Returns the 0x-hex signed extrinsic (for `author_submitExtrinsic`) and its
    /// 0x-hex blake2-256 hash as Subscan shows it.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if address(key.verifying_key().as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let message = Self::signed_message(self.signing_payload()?);
        let signature = key.sign(&message).to_bytes();
        let wire = self.assemble(&signature)?;
        let hash = Blake2b256::digest(&wire);
        Ok((
            format!("0x{}", hex::encode(&wire)),
            format!("0x{}", hex::encode(hash)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// `Keyring({ type: 'ed25519' }).addFromSeed(new Uint8Array(32).fill(7))` in @polkadot/keyring.
    const SENDER: &str = "5HMuAqymF33H73ZiBpmZ3TigFzHCopV9doyb9UfQdyDgZMUp";
    const BOB: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";

    fn tx() -> SubstrateTx {
        SubstrateTx {
            chain_id: WESTEND.into(),
            from: SENDER.into(),
            to: BOB.into(),
            planck: "1500000000000".into(),
            tip: "0".into(),
            nonce: 5,
            spec_version: 1_025_002,
            transaction_version: 27,
            genesis_hash: "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                .into(),
            block_hash: format!("0x{}", "ab".repeat(32)),
            block_number: 1_000_000,
            era_period: 256,
            metadata_hash_mode: 0,
        }
    }

    fn asset_hub_tx() -> SubstrateTx {
        SubstrateTx {
            chain_id: WESTEND_ASSET_HUB.into(),
            transaction_version: 16,
            genesis_hash: "0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9"
                .into(),
            ..tx()
        }
    }

    fn intent(tx: &SubstrateTx) -> TxIntent {
        TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(tx.chain_id.clone()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{}:native", tx.chain_id)),
                amount: Amount(tx.planck.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn addresses_match_published_vectors() {
        // Alice's public key and her addresses as the Substrate and Polkadot docs print them.
        let alice = hex32("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
        assert_eq!(
            encode_address(&alice, 42).unwrap(),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
        assert_eq!(
            encode_address(&alice, 0).unwrap(),
            "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
        );
        let key = SigningKey::from_bytes(&SECRET);
        assert_eq!(address(key.verifying_key().as_bytes()).unwrap(), SENDER);
        // Two-byte prefix (Chainflip 2112), from @polkadot/util-crypto encodeAddress.
        let pk = *key.verifying_key().as_bytes();
        let cf = "cFPAg9C99Bd84TCzSmTXBa7GvSt5LxxbAP2p6CMwRWvhNjWij";
        assert_eq!(encode_address(&pk, 2112).unwrap(), cf);
        assert_eq!(address_bytes(cf, 2112).unwrap(), pk);
        assert_eq!(address_bytes(SENDER, 42).unwrap(), pk);
    }

    #[test]
    fn foreign_and_malformed_addresses_are_refused() {
        // Polkadot-format Alice is the same account but not a Westend address.
        assert!(address_bytes("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", 42).is_err());
        assert!(address_bytes("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ", 42).is_err());
        assert!(address_bytes("0x8eaf04151687736326c9fea17e25fc5287613693", 42).is_err());
        assert!(address_bytes(&encode_address(&[0; 32], 42).unwrap(), 42).is_err());
        assert!(address(&[1u8; 33]).is_err());
        assert!(encode_address(&[1; 32], 46).is_err());
    }

    #[test]
    fn compact_encoding_boundaries() {
        let enc = |v: u128| {
            let mut out = vec![];
            compact(v, &mut out);
            hex::encode(out)
        };
        assert_eq!(enc(0), "00");
        assert_eq!(enc(63), "fc");
        assert_eq!(enc(64), "0101");
        assert_eq!(enc(16383), "fdff");
        assert_eq!(enc(16384), "02000100");
        assert_eq!(enc((1 << 30) - 1), "feffffff");
        assert_eq!(enc(1 << 30), "0300000040");
        assert_eq!(enc(1_500_000_000_000), "0b0098f73e5d01");
        assert_eq!(enc(u128::MAX), format!("33{}", "ff".repeat(16)));
    }

    /// The TypeScript adapter encodes the same fields and asserts this exact hex.
    #[test]
    fn signing_payload_matches_the_adapter_vector() {
        assert_eq!(hex::encode(tx().signing_payload().unwrap()), PAYLOAD_VECTOR);
    }
    const PAYLOAD_VECTOR: &str = "0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0098f73e5d010704140000eaa30f001b000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423eabababababababababababababababababababababababababababababababab00";

    /// Byte-for-byte equal to `api.tx.balances.transferKeepAlive(BOB, 1.5e12).sign(pair, ...)`
    /// from @polkadot/api against the live Westend metadata with the same fields; Ed25519
    /// signatures are deterministic, so the whole extrinsic is reproducible.
    #[test]
    fn signed_extrinsic_matches_polkadot_js() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, WESTEND_EXTRINSIC);
        assert_eq!(
            hash,
            "0x1b92d20f51c1470efdff7a9975a488eaa014919931f32f84ff55c8524260e24e"
        );
        let a = asset_hub_tx();
        a.check_matches_intent(&intent(&a)).unwrap();
        let (wire, hash) = a.sign(&SECRET).unwrap();
        assert_eq!(wire, ASSET_HUB_EXTRINSIC);
        assert_eq!(
            hash,
            "0x639878e2c8c7069168579d75ee1761fa3a7a4d7fe87a8cc1153ea6c6d659c925"
        );
    }
    const WESTEND_EXTRINSIC: &str = "0x49028400ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c001a72697254403fde1160a275be1784e7da116b03865790103431a482f17a565cbdf8821bd69823877847a8fd52c5861fa3466c9da223b9321f603b441af3ba0407041400000403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0098f73e5d01";
    const ASSET_HUB_EXTRINSIC: &str = "0x4d028400ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c00a0031f0b5a0d823327011e1036ecae3cfe03632329f44b3493ff1663d45765da2f029a128fd74cb01ce8e4a749222ae80e6168ed9d9557d4be8c40077444b1080704140000000a03008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0098f73e5d01";

    #[test]
    fn signature_verifies_over_the_payload() {
        let t = SubstrateTx {
            planck: u128::MAX.to_string(),
            nonce: u32::MAX,
            tip: MAX_TIP.to_string(),
            ..asset_hub_tx()
        };
        let (wire, hash) = t.sign(&SECRET).unwrap();
        let bytes = hex::decode(wire.trim_start_matches("0x")).unwrap();
        assert_eq!(
            hash,
            format!("0x{}", hex::encode(Blake2b256::digest(&bytes)))
        );
        // Two-byte length prefix, version, MultiAddress::Id, signer, MultiSignature::Ed25519.
        let body = &bytes[2..];
        assert_eq!(body[0], SIGNED_V4);
        assert_eq!(body[1], MULTI_ADDRESS_ID);
        let signer: [u8; 32] = body[2..34].try_into().unwrap();
        assert_eq!(body[34], MULTI_SIGNATURE_ED25519);
        let signature = ed25519_dalek::Signature::from_slice(&body[35..99]).unwrap();
        let payload = t.signing_payload().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&signer)
            .unwrap()
            .verify_strict(&payload, &signature)
            .unwrap();
        let c = t.checked().unwrap();
        assert_eq!(&body[99..], [c.extra, c.call].concat().as_slice());
    }

    #[test]
    fn long_payloads_are_signed_as_their_blake2_hash() {
        let long = vec![1u8; 257];
        assert_eq!(
            SubstrateTx::signed_message(long.clone()),
            Blake2b256::digest(&long).to_vec()
        );
        assert_eq!(SubstrateTx::signed_message(vec![1u8; 256]).len(), 256);
    }

    #[test]
    fn era_encodes_period_and_phase() {
        let mut t = tx();
        assert_eq!(hex::encode(t.era().unwrap()), "0704");
        t.era_period = 64;
        t.block_number = 1_000_000;
        // log2(64) - 1 = 5, phase 1_000_000 % 64 = 0.
        assert_eq!(hex::encode(t.era().unwrap()), "0500");
        t.era_period = 100;
        assert!(t.era().is_err());
        t.era_period = 8192;
        assert!(t.era().is_err());
        t.era_period = 2;
        assert!(t.era().is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let refused = |t: SubstrateTx| assert!(t.signing_payload().is_err(), "{t:?}");
        refused(SubstrateTx {
            chain_id: "polkadot:91b171bb158e2d3848fa23a9f1c25182".into(),
            ..base.clone()
        });
        refused(SubstrateTx {
            planck: "0".into(),
            ..base.clone()
        });
        refused(SubstrateTx {
            planck: "01500000000000".into(),
            ..base.clone()
        });
        refused(SubstrateTx {
            planck: "340282366920938463463374607431768211456".into(),
            ..base.clone()
        });
        refused(SubstrateTx {
            tip: (MAX_TIP + 1).to_string(),
            ..base.clone()
        });
        refused(SubstrateTx {
            to: base.from.clone(),
            ..base.clone()
        });
        refused(SubstrateTx {
            to: "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5".into(),
            ..base.clone()
        });
        refused(SubstrateTx {
            transaction_version: 28,
            ..base.clone()
        });
        refused(SubstrateTx {
            spec_version: 0,
            ..base.clone()
        });
        refused(SubstrateTx {
            genesis_hash: asset_hub_tx().genesis_hash,
            ..base.clone()
        });
        refused(SubstrateTx {
            block_hash: format!("0x{}", "AB".repeat(32)),
            ..base.clone()
        });
        refused(SubstrateTx {
            block_hash: format!("0x{}", "00".repeat(32)),
            ..base.clone()
        });
        refused(SubstrateTx {
            metadata_hash_mode: 1,
            ..base.clone()
        });
        refused(SubstrateTx {
            era_period: 96,
            ..base.clone()
        });
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId(WESTEND_ASSET_HUB.into());
        assert!(base.check_matches_intent(&i).is_err());
        let other = SubstrateTx {
            from: BOB.into(),
            to: SENDER.into(),
            ..base.clone()
        };
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": WESTEND, "from": base.from, "to": base.to, "planck": "1", "tip": "0",
            "nonce": 0, "specVersion": 1, "transactionVersion": 27,
            "genesisHash": base.genesis_hash, "blockHash": base.block_hash,
            "blockNumber": 1, "eraPeriod": 64, "metadataHashMode": 0, "call": "00"
        });
        assert!(serde_json::from_value::<SubstrateTx>(extra).is_err());
        let float = serde_json::json!({
            "chainId": WESTEND, "from": base.from, "to": base.to, "planck": 1.5, "tip": "0",
            "nonce": 0, "specVersion": 1, "transactionVersion": 27,
            "genesisHash": base.genesis_hash, "blockHash": base.block_hash,
            "blockNumber": 1, "eraPeriod": 64, "metadataHashMode": 0
        });
        assert!(serde_json::from_value::<SubstrateTx>(float).is_err());
    }
}
