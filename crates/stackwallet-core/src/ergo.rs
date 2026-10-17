//! Ergo family: native ERG transfers as P2PK-only eUTXO spends.
//!
//! A transfer spends boxes of the sender's `Dlog` proposition (P2PK) and pays
//! one output to the recipient, change back to the sender and the fee to the
//! protocol fee contract. The core serializes the whole unsigned transaction
//! from checked fields (VLQ counts, raw ergo trees, empty tokens/registers),
//! so an adapter cannot smuggle scripts, tokens or data inputs.
//!
//! The tx id is blake2b256 of the unsigned transaction bytes — proofs are
//! malleable and never part of the id. Signing is Ergo's Schnorr proof of
//! knowledge of the secret: a 192-bit challenge c from
//! `blake2b256(0x010027100108cd || pk || 0x73000021 || g^k || tx)[..24]`
//! and the response `z = k + c*w mod n`; the proof bytes are `c(24) || z(32)`.
//! Byte-for-byte conventions are pinned against fleet-sdk
//! (`@fleet-sdk/serializer` transaction bytes, `@fleet-sdk/wallet` prover).

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 uses the network's logical name.
pub const TESTNET: &str = "ergo:testnet";
pub const MAINNET: &str = "ergo:mainnet";

const PREFIX_P2PK_MAINNET: u8 = 0x01;
const PREFIX_P2PK_TESTNET: u8 = 0x11;
/// `0008cd || compressed pubkey` is the compiled `Dlog` proposition.
const P2PK_TREE_PREFIX: [u8; 3] = [0x00, 0x08, 0xcd];
/// The protocol fee contract every transfer must pay (EIP-12 `FEE_CONTRACT`).
const FEE_CONTRACT: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";
/// Below `SAFE_MIN_BOX_VALUE` an output cannot be mined into a box.
const MIN_BOX_NANOERG: u64 = 1_000_000;
/// 0.001 ERG is the network minimum; 0.01 ERG is already far above congestion pricing.
const MIN_FEE_NANOERG: u64 = 1_000_000;
const MAX_FEE_NANOERG: u64 = 10_000_000;
const MAX_INPUTS: usize = 16;
/// Heights are block counts; this caps obviously-bogus creation heights.
const MAX_HEIGHT: u32 = 100_000_000;
/// Fiat-Shamir commitment framing for a `Dlog` proposition (sigma `ProveDlog`).
const COMMITMENT_PREFIX: [u8; 7] = [0x01, 0x00, 0x27, 0x10, 0x01, 0x08, 0xcd];
const COMMITMENT_POSTFIX: [u8; 4] = [0x73, 0x00, 0x00, 0x21];
const SOUNDNESS_BYTES: usize = 24;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Ergo transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Ergo testnet transfers are enabled"));
    }
    Ok(())
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("32 bytes");
    out
}

/// The raw 34 address bytes (`network||type` head + compressed key) behind a
/// canonical base58 P2PK address. Only P2PK addresses are accepted: the core
/// cannot check funds locked under any other contract.
pub fn address_bytes(address: &str) -> Result<[u8; 34]> {
    if !(address.len() == 51 || address.len() == 52) {
        return Err(invalid("address must be a P2PK base58 address"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 38 {
        return Err(invalid("not a P2PK address"));
    }
    let (payload, check) = bytes.split_at(34);
    if blake2b256(payload)[..4] != *check {
        return Err(invalid("address checksum mismatch"));
    }
    if payload[0] != PREFIX_P2PK_MAINNET && payload[0] != PREFIX_P2PK_TESTNET {
        return Err(invalid(
            "only P2PK (pay-to-public-key) addresses are supported",
        ));
    }
    let out: [u8; 34] = payload.try_into().expect("34 bytes");
    Ok(out)
}

/// The testnet P2PK address of a compressed secp256k1 public key.
pub fn address(public: &[u8]) -> Result<String> {
    if public.len() != 33 || !(public[0] == 2 || public[0] == 3) {
        return Err(invalid("public key must be a compressed SEC1 point"));
    }
    let mut payload = [0u8; 34];
    payload[0] = PREFIX_P2PK_TESTNET;
    payload[1..].copy_from_slice(public);
    let mut full = payload.to_vec();
    full.extend_from_slice(&blake2b256(&payload)[..4]);
    Ok(bs58::encode(full).into_string())
}

fn p2pk_tree(public: &[u8]) -> Vec<u8> {
    let mut tree = Vec::with_capacity(36);
    tree.extend_from_slice(&P2PK_TREE_PREFIX);
    tree.extend_from_slice(public);
    tree
}

fn put_vlq(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn parse_nanoerg(value: &str, min: u64, max: u64, what: &str) -> Result<u64> {
    let amount = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} exceeds u64 nanoERG")))?;
    if amount < min || amount > max || amount.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a canonical integer of {min}..={max} nanoERG"
        )));
    }
    Ok(amount)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErgoTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal nanoERG sent to the recipient (1 ERG = 1,000,000,000 nanoERG).
    pub nanoerg: String,
    /// Input box ids, lowercase hex; every box must be a P2PK box of `from`.
    pub inputs: Vec<String>,
    /// Decimal nanoERG of the change output back to `from`.
    pub change: String,
    /// Decimal nanoERG paid to the protocol fee contract.
    pub fee: String,
    /// Creation height stamped on every output.
    pub height: u32,
}

struct Checked {
    from_pk: [u8; 33],
    to_pk: [u8; 33],
    amount: u64,
    inputs: Vec<[u8; 32]>,
    change: u64,
    fee: u64,
}

impl ErgoTx {
    fn checked(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        if from[0] != PREFIX_P2PK_TESTNET {
            return Err(invalid("sender must be a testnet P2PK address"));
        }
        let to = address_bytes(&self.to)?;
        if to[0] != PREFIX_P2PK_TESTNET {
            return Err(invalid("recipient must be a testnet P2PK address"));
        }
        let from_pk: [u8; 33] = from[1..].try_into().expect("33 bytes");
        let to_pk: [u8; 33] = to[1..].try_into().expect("33 bytes");
        if from_pk == to_pk {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = parse_nanoerg(&self.nanoerg, MIN_BOX_NANOERG, i64::MAX as u64, "amount")?;
        let change = parse_nanoerg(&self.change, MIN_BOX_NANOERG, i64::MAX as u64, "change")?;
        let fee = parse_nanoerg(&self.fee, MIN_FEE_NANOERG, MAX_FEE_NANOERG, "fee")?;
        amount
            .checked_add(change)
            .and_then(|v| v.checked_add(fee))
            .filter(|total| *total <= i64::MAX as u64)
            .ok_or_else(|| invalid("amount, change and fee overflow i64"))?;
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(invalid("expected 1..=16 input boxes"));
        }
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for id in &self.inputs {
            if id.len() != 64 || id.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(invalid("box ids must be 32 lowercase hex bytes"));
            }
            let bytes: [u8; 32] = hex::decode(id)
                .map_err(|_| invalid("box id is not hex"))?
                .try_into()
                .expect("32 bytes");
            if inputs.contains(&bytes) {
                return Err(invalid("duplicate input box"));
            }
            inputs.push(bytes);
        }
        if self.height == 0 || self.height > MAX_HEIGHT {
            return Err(invalid("creation height out of range"));
        }
        Ok(Checked {
            from_pk,
            to_pk,
            amount,
            inputs,
            change,
            fee,
        })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ERG transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.nanoerg {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Ergo intent")),
        }
        self.unsigned_bytes()?;
        Ok(())
    }

    /// The serialized unsigned transaction (message to sign); its blake2b256
    /// is the transaction id.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let checked = self.checked()?;
        let fee_contract = hex::decode(FEE_CONTRACT).expect("static hex");
        let mut out = Vec::with_capacity(64 + self.inputs.len() * 34 + 3 * 128);
        put_vlq(&mut out, checked.inputs.len() as u64);
        for id in &checked.inputs {
            out.extend_from_slice(id);
            out.push(0); // empty proof placeholder
            out.push(0); // empty context extension
        }
        put_vlq(&mut out, 0); // no data inputs
        put_vlq(&mut out, 0); // no distinct token ids
        put_vlq(&mut out, 3); // recipient, change, fee
        put_box(
            &mut out,
            checked.amount,
            &p2pk_tree(&checked.to_pk),
            self.height,
        );
        put_box(
            &mut out,
            checked.change,
            &p2pk_tree(&checked.from_pk),
            self.height,
        );
        put_box(&mut out, checked.fee, &fee_contract, self.height);
        Ok(out)
    }

    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(blake2b256(&self.unsigned_bytes()?))
    }

    /// Returns the EIP-12 signed transaction JSON (for `POST /transactions`)
    /// and the transaction id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let w = Option::<Scalar>::from(Scalar::from_repr((*secret).into()))
            .ok_or_else(|| invalid("invalid signing key"))?;
        if w.is_zero().into() {
            return Err(invalid("invalid signing key"));
        }
        let public = (ProjectivePoint::GENERATOR * w)
            .to_affine()
            .to_encoded_point(true);
        let public = public.as_bytes();
        if address(public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let message = self.unsigned_bytes()?;
        let txid = blake2b256(&message);
        // Ergo's Schnorr (sigma DLogProverInput): c is the first 24 bytes of
        // blake2b256 over the framed commitment, z = k + c*w mod n.
        let proof = schnorr_sign(&w, public, &message)?;
        let checked = self.checked()?;
        let inputs: Vec<serde_json::Value> = self
            .inputs
            .iter()
            .map(|box_id| {
                serde_json::json!({
                    "boxId": box_id,
                    "spendingProof": { "proofBytes": hex::encode(proof), "extension": {} },
                })
            })
            .collect();
        let wire = serde_json::json!({
            "id": hex::encode(txid),
            "inputs": inputs,
            "dataInputs": [],
            "outputs": [
                output_json(checked.amount, &p2pk_tree(&checked.to_pk), self.height),
                output_json(checked.change, &p2pk_tree(&checked.from_pk), self.height),
                output_json(checked.fee, &hex::decode(FEE_CONTRACT).expect("static hex"), self.height),
            ],
        });
        Ok((
            serde_json::to_string(&wire).expect("own json"),
            hex::encode(txid),
        ))
    }
}

fn output_json(value: u64, ergo_tree: &[u8], height: u32) -> serde_json::Value {
    serde_json::json!({
        "value": value,
        "ergoTree": hex::encode(ergo_tree),
        "creationHeight": height,
        "assets": [],
        "additionalRegisters": {},
    })
}

fn put_box(out: &mut Vec<u8>, value: u64, ergo_tree: &[u8], height: u32) {
    put_vlq(out, value);
    out.extend_from_slice(ergo_tree);
    put_vlq(out, height as u64);
    out.push(0); // no tokens
    out.push(0); // no registers
}

/// The Fiat-Shamir challenge over the framed `Dlog` commitment.
fn challenge(public: &[u8], commitment: &[u8; 33], message: &[u8]) -> Scalar {
    let mut preimage = Vec::with_capacity(7 + 33 + 4 + 33 + message.len());
    preimage.extend_from_slice(&COMMITMENT_PREFIX);
    preimage.extend_from_slice(public);
    preimage.extend_from_slice(&COMMITMENT_POSTFIX);
    preimage.extend_from_slice(commitment);
    preimage.extend_from_slice(message);
    let digest = blake2b256(&preimage);
    let mut padded = [0u8; 32];
    padded[32 - SOUNDNESS_BYTES..].copy_from_slice(&digest[..SOUNDNESS_BYTES]);
    // c < 2^192 < n, so the field element always exists.
    Option::<Scalar>::from(Scalar::from_repr(padded.into())).expect("challenge below group order")
}

fn schnorr_sign(w: &Scalar, public: &[u8], message: &[u8]) -> Result<[u8; 56]> {
    // Deterministic nonces keep signatures reproducible for the audit log; the
    // counter domain-separates the vanishingly-rare zero or zero-challenge case.
    for counter in 0u32..100 {
        let mut seed = Vec::with_capacity(13 + 32 + message.len() + 4);
        seed.extend_from_slice(b"ergo-schnorr:");
        seed.extend_from_slice(&w.to_repr());
        seed.extend_from_slice(message);
        seed.extend_from_slice(&counter.to_be_bytes());
        let nonce_bytes = blake2b256(&seed);
        let Some(k) = Option::<Scalar>::from(Scalar::from_repr(nonce_bytes.into())) else {
            continue;
        };
        if bool::from(k.is_zero()) {
            continue;
        }
        let commitment: [u8; 33] = (ProjectivePoint::GENERATOR * k)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("33 bytes");
        let c = challenge(public, &commitment, message);
        if bool::from(c.is_zero()) {
            continue;
        }
        let z = k + c * w;
        // Refuse to emit a proof that fails the verifier equation.
        let recovered = (ProjectivePoint::GENERATOR * z + (ProjectivePoint::GENERATOR * *w) * (-c))
            .to_affine()
            .to_encoded_point(true);
        let again: [u8; 33] = recovered.as_bytes().try_into().expect("33 bytes");
        if challenge(public, &again, message) != c {
            return Err(invalid("signature self-check failed"));
        }
        let mut proof = [0u8; 56];
        proof[..SOUNDNESS_BYTES].copy_from_slice(&c.to_repr()[32 - SOUNDNESS_BYTES..]);
        proof[SOUNDNESS_BYTES..].copy_from_slice(&z.to_repr());
        return Ok(proof);
    }
    Err(invalid("could not draw a usable nonce"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// fleet-sdk (`ErgoAddress.fromPublicKey`) vectors for secret 0x07…07.
    const PUBKEY: &str = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";
    const ADDR_TESTNET: &str = "3WwmRJYcKmDVN3Uqdbh52cn8BmmWfBUVQPxtrJidXb3ofAZmnNEG";
    const ADDR_MAINNET: &str = "9fgGinDXJZHmmGYnPNnHqGLCpZ5JV8roKzou3B7fvzR9sQRNtFZ";
    const ADDR2_TESTNET: &str = "3WzSsD7WkLKAfEMPkP3Mg4yjKCorMPgNjZ649YSyvNqPFzNGACLP";

    fn tx() -> ErgoTx {
        ErgoTx {
            chain_id: TESTNET.into(),
            from: ADDR_TESTNET.into(),
            to: ADDR2_TESTNET.into(),
            nanoerg: "1000000".into(),
            inputs: vec!["ab".repeat(32)],
            change: "5000000".into(),
            fee: "1000000".into(),
            height: 500_000,
        }
    }

    fn intent(tx: &ErgoTx) -> TxIntent {
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
                amount: Amount(tx.nanoerg.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_fleet_vectors() {
        let public = hex::decode(PUBKEY).unwrap();
        assert_eq!(address(&public).unwrap(), ADDR_TESTNET);
        assert_eq!(address_bytes(ADDR_TESTNET).unwrap()[0], PREFIX_P2PK_TESTNET);
        assert_eq!(address_bytes(ADDR_MAINNET).unwrap()[0], PREFIX_P2PK_MAINNET);
        assert_eq!(
            hex::encode(&address_bytes(ADDR_TESTNET).unwrap()[1..]),
            PUBKEY
        );
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("3WwmRJYcKmDVN3Uqdbh52cn8BmmWfBUVQPxtrJidXb3ofAZmnNEH").is_err());
        assert!(address_bytes("0x8ba1f109551bd432803012645ac136ddd64dba72").is_err());
        assert!(address_bytes("4MQyML64GnzMxZgm").is_err());
    }

    /// The TypeScript adapter serializes the same fields and asserts this hex;
    /// produced by `@fleet-sdk/serializer` `serializeTransaction`.
    #[test]
    fn unsigned_bytes_match_the_fleet_vector() {
        assert_eq!(hex::encode(tx().unsigned_bytes().unwrap()), BYTES_VECTOR);
        assert_eq!(hex::encode(tx().txid().unwrap()), TXID_VECTOR);
    }
    const BYTES_VECTOR: &str = "01abababababababababababababababababababababababababababababababab0000000003c0843d0008cd03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661ba0c21e0000c096b1020008cd02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa0c21e0000c0843d1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304a0c21e0000";
    const TXID_VECTOR: &str = "5176877f5d692cf122854804c5cec9700f99f414c48e611d6bcba3ba220455b4";
    const PROOF_VECTOR: &str = "797b1f4c9c34d36fc8c2533134ae174b420b1ffbc9116bc9ee07fc560f7b8a31d10cb2d7dc81200ae6a40a2c9b01d6e872547179b2c0e77c";

    #[test]
    fn signature_satisfies_the_fleet_verification_equation() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(id, TXID_VECTOR);
        let signed: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(signed["id"], id);
        let proof_hex = signed["inputs"][0]["spendingProof"]["proofBytes"]
            .as_str()
            .unwrap();
        // Deterministic nonce makes the proof itself pinnable; this exact
        // proof is accepted by `@fleet-sdk/wallet` `Prover.verify`.
        assert_eq!(proof_hex, PROOF_VECTOR);
        let proof = hex::decode(proof_hex).unwrap();
        assert_eq!(proof.len(), 56);
        // Verify exactly like fleet's `verify`: w' = g^z * pk^-c, then
        // c' == c over the framed commitment.
        let w = Option::<Scalar>::from(Scalar::from_repr(SECRET.into())).unwrap();
        let message = t.unsigned_bytes().unwrap();
        let public = hex::decode(PUBKEY).unwrap();
        let mut padded = [0u8; 32];
        padded[8..].copy_from_slice(&proof[..24]);
        let c = Option::<Scalar>::from(Scalar::from_repr(padded.into())).unwrap();
        let z_bytes: [u8; 32] = proof[24..].try_into().unwrap();
        let z = Option::<Scalar>::from(Scalar::from_repr(z_bytes.into())).unwrap();
        let commitment: [u8; 33] = (ProjectivePoint::GENERATOR * z
            + (ProjectivePoint::GENERATOR * w) * (-c))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(challenge(&public, &commitment, &message), c);
        assert_eq!(signed["outputs"][2]["ergoTree"], FEE_CONTRACT);
        assert_eq!(signed["outputs"][2]["value"], 1_000_000);
        assert!(signed["inputs"][0]["spendingProof"]["extension"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn signatures_are_deterministic() {
        let t = tx();
        assert_eq!(t.sign(&SECRET).unwrap(), t.sign(&SECRET).unwrap());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.nanoerg = "01000000".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.nanoerg = "999999".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.change = "0".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.fee = "999999".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.fee = "10000001".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.to = base.from.clone();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.inputs = vec![];
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.inputs = vec!["ab".repeat(32), "ab".repeat(32)];
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.inputs = vec!["AB".repeat(32)];
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.height = 0;
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.to = ADDR_MAINNET.into();
        assert!(t.unsigned_bytes().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = ADDR2_TESTNET.into();
        other.to = ADDR_TESTNET.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "nanoerg": "1000000",
            "inputs": ["ab".repeat(32)], "change": "5000000", "fee": "1000000",
            "height": 500000, "dataInputs": []
        });
        assert!(serde_json::from_value::<ErgoTx>(extra).is_err());
    }
}
