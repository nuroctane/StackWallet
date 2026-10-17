//! XIN transfers on the Mixin Kernel (TEE-BFT-DAG UTXO network, version-5
//! deterministic binary encoding).
//!
//! Self-custodial kernel flow only (never the app-custodial Safe/Messenger
//! APIs): an address is `XIN` + base58(spendPub || viewPub || checksum), keys
//! are raw edwards25519 scalars, and outputs carry one-time "ghost" keys the
//! sender derives locally from the recipient address. The signing scheme is
//! the kernel's Ed25519 variant (no clamping, wide-reduce nonce), specified in
//! `crypto/signature.go` of MixinNetwork/mixin and pinned here against the Go
//! test vectors (`common/transaction_test.go`, `common/address_test.go`).
//!
//! No public test kernel exists, so signing is gated to the main network id
//! (see `.nur/wiring/mixin.md`); every field is still checked before a byte is
//! encoded, and `sign` proves ownership of every input by re-deriving each
//! ghost key from the secret.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use sha3::Sha3_256;

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// Mainnet network id (first 16 hex chars of the kernel network hash,
/// live-probed from https://kernel.mixin.dev getinfo). No public test kernel
/// exists, so this main id is the signing gate.
pub const MAINNET: &str = "mixin:74c6cdb7d51af570";
/// sha256 of the XIN asset uuid "c94ac88f-4671-3976-b60a-09064f1811e8".
pub const XIN_ASSET: [u8; 32] = [
    0xa9, 0x9c, 0x2e, 0x0e, 0x2b, 0x1d, 0xa4, 0xd6, 0x48, 0x75, 0x5e, 0xf1, 0x9b, 0xd9, 0x51, 0x39,
    0xac, 0xbb, 0xe6, 0x56, 0x4c, 0xfb, 0x06, 0xde, 0xc7, 0xcd, 0x34, 0x93, 0x1c, 0xa7, 0x2c, 0xdc,
];
const ADDRESS_PREFIX: &str = "XIN";
const TX_VERSION: u8 = 5;
const SCRIPT_THRESHOLD_ONE: [u8; 3] = [0xff, 0xfe, 0x01];
const MAX_INPUTS: usize = 8;
const MAX_INPUT_INDEX: u16 = 1024;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Mixin transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    if chain != MAINNET {
        return Err(invalid(
            "only the Mixin main kernel is enabled (no public test kernel exists)",
        ));
    }
    Ok(())
}

/// Go `SetUniformBytes`: little-endian 64-byte input reduced mod L.
fn scalar_wide(seed: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(seed)
}

fn point_bytes(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// Go `CheckKey`: canonical, decompressible point.
fn check_point(bytes: &[u8; 32]) -> Result<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or_else(|| invalid("key is not a valid edwards25519 point"))?;
    if point.compress().to_bytes() != *bytes {
        return Err(invalid("key is not a canonical edwards25519 point"));
    }
    Ok(point)
}

/// Account keys from the 64-byte seed (Go `NewAddressFromSeed`).
/// StackWallet derives the seed deterministically as sha512 of the account's
/// 32-byte SLIP-10 ed25519 secret.
/// Account keys from the 64-byte seed (Go `NewAddressFromSeed`).
/// StackWallet derives the seed deterministically as sha512 of the account's
/// 32-byte SLIP-10 ed25519 secret. NB: the kernel's `crypto.Sha256Hash` is
/// NIST SHA3-256 (Go `crypto/sha3.Sum256`), not SHA-256.
fn keys_from_seed64(seed: &[u8; 64]) -> (Scalar, Scalar) {
    let spend = scalar_wide(seed);
    let h1 = Sha3_256::digest(seed);
    let h2 = Sha3_256::digest(h1);
    let mut view_seed = [0u8; 64];
    view_seed[..32].copy_from_slice(&h1);
    view_seed[32..].copy_from_slice(&h2);
    (spend, scalar_wide(&view_seed))
}

/// The 64-byte account public key: spendPub || viewPub.
pub fn public_from_secret(secret: &[u8; 32]) -> [u8; 64] {
    let seed = Sha512::digest(secret);
    let (spend, view) = keys_from_seed64(seed.as_ref());
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&point_bytes(&(spend * ED25519_BASEPOINT_POINT)));
    out[32..].copy_from_slice(&point_bytes(&(view * ED25519_BASEPOINT_POINT)));
    out
}

/// `XIN...` address from the 64-byte public key (spendPub || viewPub).
pub fn address(public: &[u8]) -> Result<String> {
    let public: &[u8; 64] = public
        .try_into()
        .map_err(|_| invalid("mixin public key must be 64 bytes (spend || view)"))?;
    let spend: &[u8; 32] = public[..32].try_into().expect("slice");
    let view: &[u8; 32] = public[32..].try_into().expect("slice");
    check_point(spend)?;
    check_point(view)?;
    Ok(encode_address(spend, view))
}

fn encode_address(spend: &[u8; 32], view: &[u8; 32]) -> String {
    let mut preimage = Vec::with_capacity(67);
    preimage.extend_from_slice(ADDRESS_PREFIX.as_bytes());
    preimage.extend_from_slice(spend);
    preimage.extend_from_slice(view);
    let checksum = Sha3_256::digest(&preimage);
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(spend);
    data.extend_from_slice(view);
    data.extend_from_slice(&checksum[..4]);
    format!("{ADDRESS_PREFIX}{}", bs58::encode(data).into_string())
}

/// Parses a `XIN` address into (spendPub, viewPub), verifying the checksum
/// and both points.
pub fn address_bytes(address: &str) -> Result<([u8; 32], [u8; 32])> {
    let body = address
        .strip_prefix(ADDRESS_PREFIX)
        .ok_or_else(|| invalid("address must start with XIN"))?;
    let data = bs58::decode(body)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if data.len() != 68 {
        return Err(invalid("address must decode to 68 bytes"));
    }
    let (payload, check) = data.split_at(64);
    let mut preimage = Vec::with_capacity(67);
    preimage.extend_from_slice(ADDRESS_PREFIX.as_bytes());
    preimage.extend_from_slice(payload);
    if Sha3_256::digest(&preimage)[..4] != *check {
        return Err(invalid("address checksum mismatch"));
    }
    let spend: [u8; 32] = payload[..32].try_into().expect("slice");
    let view: [u8; 32] = payload[32..].try_into().expect("slice");
    check_point(&spend)?;
    check_point(&view)?;
    Ok((spend, view))
}

/// Go `binary.PutUvarint` (LEB128).
fn uvarint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

/// Go `crypto.HashScalar`: two chained wide reductions of blake3 over the
/// shared point bytes and the uvarint output index.
fn hash_scalar(shared: &EdwardsPoint, output_index: u64) -> Scalar {
    let mut src = Vec::with_capacity(44);
    src.extend_from_slice(&point_bytes(shared));
    src.extend_from_slice(&uvarint(output_index));
    let first_reduce = |digest_input: &[u8]| -> Scalar {
        let h1 = blake3::hash(digest_input);
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(h1.as_bytes());
        wide[32..].copy_from_slice(blake3::hash(h1.as_bytes()).as_bytes());
        scalar_wide(&wide)
    };
    let s = first_reduce(&src);
    let mut second = [0u8; 64];
    let h1 = blake3::hash(s.as_bytes());
    second[..32].copy_from_slice(h1.as_bytes());
    second[32..].copy_from_slice(blake3::hash(h1.as_bytes()).as_bytes());
    scalar_wide(&second)
}

/// Go `DeriveGhostPublicKey`: recipient spend point plus the scalarized
/// shared secret times the basepoint.
fn ghost_public_key(r: &Scalar, view_pub: &[u8; 32], spend_pub: &[u8; 32], index: u64) -> [u8; 32] {
    let view_point = check_point(view_pub).expect("validated address");
    let spend_point = check_point(spend_pub).expect("validated address");
    let x = hash_scalar(&(view_point * r), index);
    point_bytes(&(spend_point + x * ED25519_BASEPOINT_POINT))
}

#[cfg(test)]
pub(crate) fn ghost_public_for_test(
    r64: &[u8; 64],
    public64: &[u8; 64],
    index: u64,
) -> ([u8; 32], [u8; 32]) {
    let r = scalar_wide(r64);
    let spend: &[u8; 32] = public64[..32].try_into().expect("spend");
    let view: &[u8; 32] = public64[32..].try_into().expect("view");
    let key = ghost_public_key(&r, view, spend, index);
    let mask = point_bytes(&(r * ED25519_BASEPOINT_POINT));
    (key, mask)
}

/// Go `DeriveGhostPrivateKey` for the input owner: Hs(mask*view, index) + spend.
fn ghost_private_key(mask: &[u8; 32], view: &Scalar, spend: &Scalar, index: u64) -> Result<Scalar> {
    let mask_point = check_point(mask)?;
    Ok(hash_scalar(&(mask_point * view), index) + spend)
}

/// Go `Key.Sign`: the kernel's Ed25519 variant (no clamping; nonce and
/// challenge are wide-reduced sha512).
fn kernel_sign(secret_scalar: &Scalar, message: &[u8; 32]) -> [u8; 64] {
    let digest1 = Sha512::digest(secret_scalar.as_bytes());
    let mut h = Sha512::new();
    h.update(&digest1[32..]);
    h.update(message);
    let z = scalar_wide(h.finalize().as_ref());
    let r_point = z * ED25519_BASEPOINT_POINT;
    let public = point_bytes(&(*secret_scalar * ED25519_BASEPOINT_POINT));
    let mut h = Sha512::new();
    h.update(point_bytes(&r_point));
    h.update(public);
    h.update(message);
    let x = scalar_wide(h.finalize().as_ref());
    let s = x * secret_scalar + z;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&point_bytes(&r_point));
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

#[cfg(test)]
fn kernel_verify(public: &[u8; 32], message: &[u8; 32], sig: &[u8; 64]) -> bool {
    let a_bytes: [u8; 32] = sig[..32].try_into().expect("slice");
    let (Ok(a_point), Ok(r_point)) = (check_point(public), check_point(&a_bytes)) else {
        return false;
    };
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("slice");
    let Some(s) = Scalar::from_canonical_bytes(s_bytes).into_option() else {
        return false;
    };
    let mut h = Sha512::new();
    h.update(a_bytes);
    h.update(public);
    h.update(message);
    let x = scalar_wide(h.finalize().as_ref());
    s * ED25519_BASEPOINT_POINT == r_point + x * a_point
}

fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

fn parse_amount(value: &str, what: &str) -> Result<u64> {
    let amount = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} exceeds u64 base units")))?;
    if amount == 0 || amount.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a positive canonical integer"
        )));
    }
    Ok(amount)
}

/// One consumed UTXO of the sender, with the public material the kernel needs
/// to verify the signature (from `getutxo`): the ghost key and output mask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixinInput {
    /// Source transaction hash, 32 lowercase hex bytes.
    pub hash: String,
    /// Output index inside the source transaction.
    pub index: u16,
    /// The output's ghost public key (32 lowercase hex bytes).
    pub key: String,
    /// The output's mask public key (32 lowercase hex bytes).
    pub mask: String,
    /// Decimal base units (1 XIN = 100,000,000 xinat) held by the output.
    pub xinat: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixinTx {
    pub chain_id: String,
    /// Sender `XIN` address; receives the change output when inputs overcover.
    pub from: String,
    /// Recipient `XIN` address.
    pub to: String,
    /// Decimal base units sent to `to`.
    pub xinat: String,
    pub inputs: Vec<MixinInput>,
    /// 64-byte lowercase hex seeds for the recipient and change ghost outputs,
    /// generated by the adapter (fresh randomness per prepared transaction).
    pub to_seed: String,
    pub change_seed: String,
}

/// An output as the encoder sees it; also used by the Go-vector tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawOutput {
    amount: u64,
    keys: Vec<[u8; 32]>,
    mask: [u8; 32],
    script: Vec<u8>,
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_integer(out: &mut Vec<u8>, amount: u64) {
    let bytes = amount.to_be_bytes();
    let size = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    push_u16(out, (bytes.len() - size) as u16);
    out.extend_from_slice(&bytes[size..]);
}

/// The version-5 unsigned transaction encoding; its blake3 is the payload
/// hash that every signature covers and the transaction id.
pub(crate) fn encode_unsigned(
    inputs: &[(/* hash */ [u8; 32], /* index */ u16)],
    outputs: &[RawOutput],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&[0x77, 0x77, 0x00, TX_VERSION]);
    out.extend_from_slice(&XIN_ASSET);
    push_u16(&mut out, inputs.len() as u16);
    for (hash, index) in inputs {
        out.extend_from_slice(hash);
        push_u16(&mut out, *index);
        push_u16(&mut out, 0); // no genesis
        push_u16(&mut out, 0); // no deposit
        push_u16(&mut out, 0); // no mint
    }
    push_u16(&mut out, outputs.len() as u16);
    for o in outputs {
        out.push(0x00);
        out.push(0x00); // OutputTypeScript
        push_integer(&mut out, o.amount);
        push_u16(&mut out, o.keys.len() as u16);
        for k in &o.keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&o.mask);
        push_u16(&mut out, o.script.len() as u16);
        out.extend_from_slice(&o.script);
        push_u16(&mut out, 0); // no withdrawal data
    }
    push_u16(&mut out, 0); // no references
    out.extend_from_slice(&0u32.to_be_bytes()); // extra length
    push_u16(&mut out, 0); // empty signature map count
    out
}

impl MixinTx {
    /// Checked, fully derived transfer plan: input refs, outputs with ghost
    /// keys, and the payload hash. Nothing is trusted from the adapter beyond
    /// shape; ghost keys are re-derived here.
    #[allow(clippy::type_complexity)]
    fn plan(
        &self,
    ) -> Result<(
        Vec<([u8; 32], u16)>,
        Vec<RawOutput>,
        Vec<([u8; 32], [u8; 32])>,
    )> {
        check_chain(&self.chain_id)?;
        let (from_spend, from_view) = address_bytes(&self.from)?;
        let (to_spend, to_view) = address_bytes(&self.to)?;
        if from_spend == to_spend && from_view == to_view {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = parse_amount(&self.xinat, "amount")?;
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(invalid("transfer must spend 1..=8 inputs"));
        }
        let to_seed = fixed_hex::<64>(&self.to_seed, "recipient output seed")?;
        let change_seed = fixed_hex::<64>(&self.change_seed, "change output seed")?;
        let mut input_refs = Vec::with_capacity(self.inputs.len());
        let mut input_pub = Vec::with_capacity(self.inputs.len());
        let mut total = 0u64;
        for (position, input) in self.inputs.iter().enumerate() {
            let hash = fixed_hex::<32>(&input.hash, "input hash")?;
            if input.index > MAX_INPUT_INDEX {
                return Err(invalid("input index exceeds 1024"));
            }
            let key = fixed_hex::<32>(&input.key, "input ghost key")?;
            let mask = fixed_hex::<32>(&input.mask, "input mask")?;
            check_point(&key)?;
            check_point(&mask)?;
            if self.inputs[..position]
                .iter()
                .any(|other| other.hash == input.hash && other.index == input.index)
            {
                return Err(invalid("duplicate input"));
            }
            total = total
                .checked_add(parse_amount(&input.xinat, "input amount")?)
                .ok_or_else(|| invalid("input amounts overflow"))?;
            input_refs.push((hash, input.index));
            input_pub.push((key, mask));
        }
        let change = total
            .checked_sub(amount)
            .ok_or_else(|| invalid("inputs do not cover the amount"))?;
        let mut outputs = Vec::with_capacity(2);
        let r_to = scalar_wide(&to_seed);
        outputs.push(RawOutput {
            amount,
            keys: vec![ghost_public_key(&r_to, &to_view, &to_spend, 0)],
            mask: point_bytes(&(r_to * ED25519_BASEPOINT_POINT)),
            script: SCRIPT_THRESHOLD_ONE.to_vec(),
        });
        if change > 0 {
            let r_change = scalar_wide(&change_seed);
            outputs.push(RawOutput {
                amount: change,
                keys: vec![ghost_public_key(&r_change, &from_view, &from_spend, 1)],
                mask: point_bytes(&(r_change * ED25519_BASEPOINT_POINT)),
                script: SCRIPT_THRESHOLD_ONE.to_vec(),
            });
        }
        Ok((input_refs, outputs, input_pub))
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native XIN transfers are enabled"));
                }
                if self.to != *to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.xinat {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Mixin intent")),
        }
        self.plan()?;
        Ok(())
    }

    /// The unsigned wire encoding (what blake3 hashes to the transaction id).
    pub fn raw_bytes(&self) -> Result<Vec<u8>> {
        let (inputs, outputs, _) = self.plan()?;
        Ok(encode_unsigned(&inputs, &outputs))
    }

    /// blake3 of the unsigned encoding: the payload hash and transaction id.
    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.raw_bytes()?).as_bytes())
    }

    /// Returns the signed transaction as hex (for `sendrawtransaction`) and
    /// the transaction hash as the kernel shows it (64 lowercase hex chars).
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let seed = Sha512::digest(secret);
        let (spend, view) = keys_from_seed64(seed.as_ref());
        if address(&public_from_secret(secret))? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let (input_refs, outputs, input_pub) = self.plan()?;
        let unsigned = encode_unsigned(&input_refs, &outputs);
        let payload_hash: [u8; 32] = *blake3::hash(&unsigned).as_bytes();
        // Re-derive every input's ghost private key; if any does not match the
        // declared ghost public key, the adapter fed us an output we do not own.
        let mut signatures = Vec::with_capacity(input_pub.len());
        for ((hash, index), (key, mask)) in input_refs.iter().zip(input_pub.iter()) {
            let _ = hash;
            let private = ghost_private_key(mask, &view, &spend, u64::from(*index))?;
            let derived_public = point_bytes(&(private * ED25519_BASEPOINT_POINT));
            if derived_public != *key {
                return Err(invalid("input is not owned by the signing key"));
            }
            signatures.push(kernel_sign(&private, &payload_hash));
        }
        let mut wire = unsigned;
        // Rewrite the trailing empty signature count with one map per input.
        wire.truncate(wire.len() - 2);
        push_u16(&mut wire, signatures.len() as u16);
        for sig in &signatures {
            push_u16(&mut wire, 1); // one entry per map
            push_u16(&mut wire, 0); // key index 0 (fffe01 threshold-1 output)
            wire.extend_from_slice(sig);
        }
        Ok((hex::encode(wire), hex::encode(payload_hash)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go `NewAddressFromSeed` vector from common/address_test.go:
    /// seed = bytes 1..=64.
    const GO_SEED: [u8; 64] = {
        let mut s = [0u8; 64];
        let mut i = 0;
        while i < 64 {
            s[i] = (i + 1) as u8;
            i += 1;
        }
        s
    };

    fn go_account(byte_index: usize) -> ([u8; 32], [u8; 32]) {
        // The 16 Go test accounts: index 0 sets the last seed byte to 1,
        // account i>0 sets seed[i] = i.
        let mut seed = [0u8; 64];
        if byte_index == 0 {
            seed[63] = 1;
        } else {
            seed[byte_index] = byte_index as u8;
        }
        let (spend, view) = keys_from_seed64(&seed);
        (
            point_bytes(&(spend * ED25519_BASEPOINT_POINT)),
            point_bytes(&(view * ED25519_BASEPOINT_POINT)),
        )
    }

    #[test]
    fn address_matches_the_go_vector() {
        let (spend, view) = keys_from_seed64(&GO_SEED);
        assert_eq!(
            hex::encode(spend.as_bytes()),
            "c91e0907d114fd83c1edc396490bb2dafa43c19815b0354e70dc80c317c3cb0a"
        );
        assert_eq!(
            hex::encode(view.as_bytes()),
            "8665767180c62fa337b2ff051e0387af66f6feb46acacb82884b062f1fd5ed0b"
        );
        let mut public = [0u8; 64];
        public[..32].copy_from_slice(&point_bytes(&(spend * ED25519_BASEPOINT_POINT)));
        public[32..].copy_from_slice(&point_bytes(&(view * ED25519_BASEPOINT_POINT)));
        assert_eq!(
            hex::encode(&public[..32]),
            "36bb0e309e7e9a82f1527df2c6b0e48181589097fe90c1282c558207ea27ce66"
        );
        assert_eq!(
            hex::encode(&public[32..]),
            "af8f69545b784e71de5e0a0261cb107aea99e9d7fe0df35537899cd9f05ea644"
        );
        let addr = address(&public).unwrap();
        assert_eq!(
            addr,
            "XIN8AJMgQUD11jZYN9ggbQDqkmozrha3zPEZxEkKxVFBufZpEVMtrR6PjtmgtNAH6jrg8dTUQFb9waqqw9euU7Ea8AC6DEu8"
        );
        assert_eq!(
            address_bytes(&addr).unwrap(),
            (
                public[..32].try_into().unwrap(),
                public[32..].try_into().unwrap()
            )
        );
        // checksum and point validation reject tampering
        let mut bad = addr.clone();
        bad.replace_range(4..5, if &addr[4..5] == "A" { "B" } else { "A" });
        assert!(address_bytes(&bad).is_err());
    }

    #[test]
    fn public_from_secret_is_deterministic() {
        let secret = [7u8; 32];
        let a = public_from_secret(&secret);
        let b = public_from_secret(&secret);
        assert_eq!(a, b);
        assert!(address(&a).is_ok());
    }

    /// Reproduces common/transaction_test.go TestTransactionReferences: the
    /// incremental payload hashes and the exact 740-byte marshal `PM`.
    #[test]
    fn encoding_matches_the_go_pinned_transaction() {
        let zero = [0u8; 32];
        // Empty transaction payload hash.
        let empty = encode_unsigned(&[], &[]);
        assert_eq!(
            hex::encode(blake3::hash(&empty).as_bytes()),
            "814d45237cf84feb5be8cb60a3f985a019169a01a6d05924b74aa3493da02dd6"
        );
        let one_input = encode_unsigned(&[(zero, 0)], &[]);
        assert_eq!(
            hex::encode(blake3::hash(&one_input).as_bytes()),
            "826aedc5f8ba217c399bfc798f2d4b7a169b7c9714397b56e32e609b9f5e0a6d"
        );
        let two_inputs = encode_unsigned(&[(zero, 0), (zero, 1)], &[]);
        assert_eq!(
            hex::encode(blake3::hash(&two_inputs).as_bytes()),
            "61f00c8f14383c0a174543f2ba775f10ca38c91cf9f6c0b28de9bb9579fc2c51"
        );
        // Keyless script output (mask from seed 0x01*64), amount 10000 XIN.
        let mask_seed = [1u8; 64];
        let mask = point_bytes(&(scalar_wide(&mask_seed) * ED25519_BASEPOINT_POINT));
        let keyless = RawOutput {
            amount: 10000 * 100_000_000,
            keys: vec![],
            mask,
            script: vec![0xff, 0xfe, 13],
        };
        let with_keyless = encode_unsigned(&[(zero, 0), (zero, 1)], std::slice::from_ref(&keyless));
        assert_eq!(
            hex::encode(blake3::hash(&with_keyless).as_bytes()),
            "4edf7bc13dc688d6ca45c9a6fe577a60e1f21e8474a324c06b7f94d8485681e7"
        );
        // AddScriptOutput of the 16 accounts at output index 1, seed 0x01*64.
        let r = scalar_wide(&mask_seed);
        let keys: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let (spend_pub, view_pub) = go_account(i);
                ghost_public_key(&r, &view_pub, &spend_pub, 1)
            })
            .collect();
        let scripted = RawOutput {
            amount: 10000 * 100_000_000,
            keys,
            mask: point_bytes(&(r * ED25519_BASEPOINT_POINT)),
            script: vec![0xff, 0xfe, 13],
        };
        let full = encode_unsigned(&[(zero, 0), (zero, 1)], &[keyless, scripted]);
        assert_eq!(
            hex::encode(blake3::hash(&full).as_bytes()),
            "f6f8c5fd92dfd697efa4903d70038577391514fd6ad2dfc4984ca072540b5612"
        );
        assert_eq!(hex::encode(&full), GO_PM);
        assert_eq!(full.len(), 740);
    }

    const GO_PM: &str = "77770005a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc00020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000200000005e8d4a510000000c6473159e19ed185b373e935081774e0c133b9416abdff319667187a71dff53e0003fffe0d000000000005e8d4a5100000101a4df331aa9178f1a7f8d8627a6233090bfc2f1c154e4ce052c6e100cd6d511ed069468da7057e644259c5f82cea4f32b481844aff68409a2823e6a2e7d84ae59402e07b4e453035787231b6b9b5c53498573e22e7f0d1440741c95e4c51b96c81ef7ed772d8f864f4a0250478fbc3c2927b7dd5dc364d6ad49156eccdde902c139921b524d87fafa4e671e6f8d9a9b3bbb405573eef90df4ea9d966c1a81b2d99e4228582ee9001653cfb2d7eb61dfe14d243e0280db8ffe2741a89190f532fbbbbe72344c65127e697a246c5f70804342195b92835afa9d8edf7498ba083e407a579b53eb7ce1ee7e97f826e6b463e7ad160cb97c56b6166d125ffd8b6f021d3f4a6136aaddce4bdbfddae92f702c56ccb94edb2f6d93615887f0806900a65c0f230e2e2ae9358beb7e7299cf8a00bc2fd2038540f818db6e16dd4abf4dadce64dd745fe693b2ee41e4ff1b7fccff3f50819a7d41e76cb04fe1065059f3b2068a5f51863e976f65e7b2665045e3e8919b96cae80cbbbf9d33009094b5091dde31937cf61a9d7393c6d4b01f068725f233eb564bb00767138b1c83bd09cf148832f8e5303a3249cee3c707607eb8ea030c0b92777e3ed729fb2aee4c4298bd6dcd0d1c0eff1a06c68bf6459f35c8a047130b631b22bff252edeb03310cf7f2121f21afb2d299f7febc6a3eaa79e5e19bd3a5c299817b50262289e2bc382f173c6473159e19ed185b373e935081774e0c133b9416abdff319667187a71dff53e0003fffe0d00000000000000000000";

    /// End-to-end: a one-input transfer built by hand, signed, and every
    /// signature verified against the ghost public keys (the kernel's own
    /// batch verification does exactly this).
    #[test]
    fn transfer_signs_and_verifies() {
        let secret = [7u8; 32];
        let from = address(&public_from_secret(&secret)).unwrap();
        let (to_spend, to_view) = go_account(3);
        let mut to_pub = [0u8; 64];
        to_pub[..32].copy_from_slice(&to_spend);
        to_pub[32..].copy_from_slice(&to_view);
        let to = address(&to_pub).unwrap();
        // A funding output that pays `from` 2 XIN at source index 0.
        let seed64 = Sha512::digest(secret);
        let (spend, view) = keys_from_seed64(seed64.as_ref());
        let fund_r = scalar_wide(&[9u8; 64]);
        let fund_mask = point_bytes(&(fund_r * ED25519_BASEPOINT_POINT));
        let fund_key = ghost_public_key(
            &fund_r,
            &point_bytes(&(view * ED25519_BASEPOINT_POINT)),
            &point_bytes(&(spend * ED25519_BASEPOINT_POINT)),
            0,
        );
        let tx = MixinTx {
            chain_id: MAINNET.into(),
            from: from.clone(),
            to: to.clone(),
            xinat: "150000000".into(),
            inputs: vec![MixinInput {
                hash: hex::encode([1u8; 32]),
                index: 0,
                key: hex::encode(fund_key),
                mask: hex::encode(fund_mask),
                xinat: "200000000".into(),
            }],
            to_seed: hex::encode([5u8; 64]),
            change_seed: hex::encode([6u8; 64]),
        };
        let intent = TxIntent {
            id: "tx".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: crate::model::ChainId(MAINNET.into()),
            proposer: crate::intent::Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: to.clone(),
                asset: crate::model::AssetRef(format!("{MAINNET}:native")),
                amount: crate::intent::Amount("150000000".into()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        };
        tx.check_matches_intent(&intent).unwrap();
        let (wire, txid) = tx.sign(&secret).unwrap();
        assert_eq!(txid, hex::encode(tx.txid().unwrap()));
        assert_eq!(wire.len() % 2, 0);
        // Decode our own wire and verify the signature over the payload hash.
        let raw = hex::decode(&wire).unwrap();
        let unsigned = tx.raw_bytes().unwrap();
        assert!(raw.starts_with(&unsigned[..unsigned.len() - 2]));
        let sig_count = u16::from_be_bytes([raw[unsigned.len() - 2], raw[unsigned.len() - 1]]);
        assert_eq!(sig_count, 1);
        let mut offset = unsigned.len();
        assert_eq!(&raw[offset..offset + 4], &[0, 1, 0, 0]); // one entry, key index 0
        offset += 4;
        let sig: [u8; 64] = raw[offset..offset + 64].try_into().unwrap();
        assert_eq!(raw.len(), offset + 64);
        let ghost_priv = ghost_private_key(&fund_mask, &view, &spend, 0).unwrap();
        let ghost_pub = point_bytes(&(ghost_priv * ED25519_BASEPOINT_POINT));
        assert_eq!(ghost_pub, fund_key);
        assert!(kernel_verify(&ghost_pub, &tx.txid().unwrap(), &sig));
        // The change output pays back to `from` at index 1.
        let (_, outputs, _) = tx.plan().unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[1].amount, 50_000_000);
        let change_priv_check = ghost_public_key(
            &scalar_wide(&[6u8; 64]),
            &point_bytes(&(view * ED25519_BASEPOINT_POINT)),
            &point_bytes(&(spend * ED25519_BASEPOINT_POINT)),
            1,
        );
        assert_eq!(outputs[1].keys[0], change_priv_check);
    }

    /// Probe helper (run with --nocapture): prints a fully signed transfer for
    /// a throwaway key spending a nonexistent UTXO, used once to capture the
    /// live kernel's rejection of an unknown input.
    #[test]
    fn live_probe_fixture() {
        let secret = [7u8; 32];
        let from = address(&public_from_secret(&secret)).unwrap();
        let (to_spend, to_view) = go_account(3);
        let mut to_pub = [0u8; 64];
        to_pub[..32].copy_from_slice(&to_spend);
        to_pub[32..].copy_from_slice(&to_view);
        let to = address(&to_pub).unwrap();
        let seed64 = Sha512::digest(secret);
        let (spend, view) = keys_from_seed64(seed64.as_ref());
        let fund_r = scalar_wide(&[9u8; 64]);
        let fund_mask = point_bytes(&(fund_r * ED25519_BASEPOINT_POINT));
        let fund_key = ghost_public_key(
            &fund_r,
            &point_bytes(&(view * ED25519_BASEPOINT_POINT)),
            &point_bytes(&(spend * ED25519_BASEPOINT_POINT)),
            0,
        );
        let tx = MixinTx {
            chain_id: MAINNET.into(),
            from,
            to,
            xinat: "150000000".into(),
            inputs: vec![MixinInput {
                hash: hex::encode([1u8; 32]),
                index: 0,
                key: hex::encode(fund_key),
                mask: hex::encode(fund_mask),
                xinat: "200000000".into(),
            }],
            to_seed: hex::encode([5u8; 64]),
            change_seed: hex::encode([6u8; 64]),
        };
        let (wire, txid) = tx.sign(&secret).unwrap();
        println!("PROBE_TXID={txid}");
        println!("PROBE_WIRE={wire}");
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let secret = [7u8; 32];
        let from = address(&public_from_secret(&secret)).unwrap();
        let (to_spend, to_view) = go_account(3);
        let mut to_pub = [0u8; 64];
        to_pub[..32].copy_from_slice(&to_spend);
        to_pub[32..].copy_from_slice(&to_view);
        let to = address(&to_pub).unwrap();
        let seed64 = Sha512::digest(secret);
        let (spend, view) = keys_from_seed64(seed64.as_ref());
        let fund_r = scalar_wide(&[9u8; 64]);
        let fund_mask = point_bytes(&(fund_r * ED25519_BASEPOINT_POINT));
        let fund_key = ghost_public_key(
            &fund_r,
            &point_bytes(&(view * ED25519_BASEPOINT_POINT)),
            &point_bytes(&(spend * ED25519_BASEPOINT_POINT)),
            0,
        );
        let base = MixinTx {
            chain_id: MAINNET.into(),
            from,
            to,
            xinat: "150000000".into(),
            inputs: vec![MixinInput {
                hash: hex::encode([1u8; 32]),
                index: 0,
                key: hex::encode(fund_key),
                mask: hex::encode(fund_mask),
                xinat: "200000000".into(),
            }],
            to_seed: hex::encode([5u8; 64]),
            change_seed: hex::encode([6u8; 64]),
        };
        let mut t = base.clone();
        t.chain_id = "mixin:0000000000000000".into();
        assert!(t.raw_bytes().is_err());
        let mut t = base.clone();
        t.xinat = "0".into();
        assert!(t.raw_bytes().is_err());
        let mut t = base.clone();
        t.xinat = "300000000".into(); // exceeds the inputs
        assert!(t.raw_bytes().is_err());
        let mut t = base.clone();
        t.inputs[0].hash = hex::encode([0xabu8; 32]).to_uppercase();
        assert!(t.raw_bytes().is_err());
        let mut t = base.clone();
        t.inputs[0].index = 1025;
        assert!(t.raw_bytes().is_err());
        let mut t = base.clone();
        t.to_seed = hex::encode([0xabu8; 64]).to_uppercase();
        assert!(t.raw_bytes().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.raw_bytes().is_err());
        // Foreign input: mask of another key is not owned by the signer.
        let mut t = base.clone();
        t.inputs[0].mask = hex::encode([2u8; 32]);
        if check_point(&[2u8; 32]).is_ok() {
            assert!(t.sign(&secret).is_err());
        } else {
            assert!(t.raw_bytes().is_err());
        }
        // Wrong secret cannot sign.
        assert!(base.sign(&[8u8; 32]).is_err());
        let extra = serde_json::json!({
            "chainId": MAINNET, "from": base.from, "to": base.to, "xinat": "1",
            "inputs": [], "toSeed": hex::encode([5u8; 64]), "changeSeed": hex::encode([6u8; 64]),
            "extra": "deadbeef"
        });
        assert!(serde_json::from_value::<MixinTx>(extra).is_err());
    }
}
