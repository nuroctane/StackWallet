//! Fuel native-asset transfers. The core encodes the whole `TransactionScript`
//! (Fuel's word-aligned big-endian codec, mirroring fuel-tx and the fuels TS
//! SDK byte for byte) from checked fields: a RET-zero script, one change
//! output back to the sender, one coin output to the recipient, one Coin input
//! per spent UTXO. Policies are exactly `MaxFee` and `Expiration`.
//!
//! Pinned against fuels@0.103.0 (`.nur/fuel-vectors.log`): the same fields
//! produce the same bytes, the same id and the same signature.
//!
//! The transaction id is
//! `sha256(chain_id u64 BE || encode(tx with witnesses removed, receipts root
//! zeroed, coin-input txPointer/predicateGasUsed zeroed, change output amount
//! zeroed))` and the signature is secp256k1 ECDSA `r || s` over that id with
//! the recovery bit packed into the top bit of `s[0]`. Addresses are
//! `0x`-hex of `sha256(uncompressed SEC1 pubkey without the 0x04 prefix)`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// CAIP-2 reference is the decimal Fuel chain id; the signing network is the
/// Fuel Sepolia testnet (chain id 0). Ignition mainnet (9889) stays refused
/// until the family's testnet and threshold gates pass.
pub const SEPOLIA: &str = "fuel:0";
pub const MAINNET: &str = "fuel:9889";

/// Native asset id (ETH, 9 decimals) on every public Fuel network.
pub const BASE_ASSET_ID: [u8; 32] = [
    0xf8, 0xf8, 0xb6, 0x28, 0x3d, 0x7f, 0xa5, 0xb6, 0x72, 0xb5, 0x30, 0xcb, 0xb8, 0x4f, 0xcc, 0xcb,
    0x4f, 0xf8, 0xdc, 0x40, 0xf8, 0x17, 0x6e, 0xf4, 0x54, 0x4d, 0xdb, 0x1f, 0x19, 0x52, 0xad, 0x07,
];
/// `RET REG_ZERO; NOOP` — the script the fuels SDK uses for plain transfers.
const TRANSFER_SCRIPT: [u8; 4] = [0x24, 0x00, 0x00, 0x00];
const POLICY_MAX_FEE: u32 = 8;
const POLICY_EXPIRATION: u32 = 16;
const MAX_INPUTS: usize = 8;
/// consensusParameters.txParams.maxGasPerTx on Ignition and the testnet.
const MAX_GAS_LIMIT: u64 = 30_000_000;
/// Generous fee cap: real transfers cost well under 1e6 base units.
const MAX_FEE_LIMIT: u64 = 1_000_000_000_000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Fuel transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    if chain != SEPOLIA {
        return Err(invalid("only Fuel Sepolia testnet transfers are enabled"));
    }
    Ok(())
}

/// Fuel network id for the CAIP-2 reference (the preimage of the tx id).
fn network_id(chain: &str) -> Result<u64> {
    check_chain(chain)?;
    chain
        .strip_prefix("fuel:")
        .and_then(|r| r.parse::<u64>().ok())
        .ok_or_else(|| invalid("invalid Fuel chain id"))
}

fn b256(value: &str, what: &str) -> Result<[u8; 32]> {
    let hex_part = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{what} must start with 0x")))?;
    if hex_part.len() != 64 || hex_part.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be 32 lowercase hex bytes")));
    }
    let bytes = hex::decode(hex_part).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

/// `0x` + sha256 of the uncompressed SEC1 key without the `0x04` prefix.
pub fn address(public: &[u8]) -> Result<String> {
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| invalid("invalid public key"))?;
    let point = key.to_encoded_point(false);
    let digest = Sha256::digest(&point.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(digest)))
}

fn canonical_u64(value: &str, what: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} must be a canonical u64")))?;
    if n.to_string() != value {
        return Err(invalid(format!("{what} must be a canonical u64")));
    }
    Ok(n)
}

/// One spent UTXO. The owner is always the sender; the tx pointer is always
/// zero (fuel-core ignores it and the fuels SDK hardcodes it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FuelCoinInput {
    /// Lowercase hex id of the transaction that created the coin.
    pub tx_id: String,
    pub output_index: u16,
    /// Decimal base units (9 decimals).
    pub amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FuelTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal base units (1 ETH = 1,000,000,000 base); never a JSON float.
    pub base: String,
    /// Coins the transfer spends, in wire order; each gets one witness.
    pub inputs: Vec<FuelCoinInput>,
    /// `scriptGasLimit`: execution budget of the RET script (tiny).
    pub gas_limit: u64,
    /// Decimal base units; the `MaxFee` policy.
    pub max_fee: String,
    /// Block height after which the network drops the transaction
    /// (the `Expiration` policy).
    pub expiration: u64,
}

struct Checked {
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    max_fee: u64,
    inputs: Vec<([u8; 32], u16, u64)>,
}

impl FuelTx {
    fn check(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = b256(&self.from, "sender")?;
        let to = b256(&self.to, "recipient")?;
        if from == [0; 32] || to == [0; 32] {
            return Err(invalid("zero address"));
        }
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u64(&self.base, "amount")?;
        if amount == 0 {
            return Err(invalid("amount must be positive"));
        }
        let max_fee = canonical_u64(&self.max_fee, "max fee")?;
        if max_fee == 0 || max_fee > MAX_FEE_LIMIT {
            return Err(invalid("max fee out of range"));
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(invalid("transfer spends one to eight coins"));
        }
        if self.gas_limit > MAX_GAS_LIMIT {
            return Err(invalid("gas limit exceeds the network maximum"));
        }
        if self.expiration == 0 || self.expiration > u32::MAX as u64 {
            return Err(invalid("expiration must be a block height"));
        }
        let mut inputs = Vec::with_capacity(self.inputs.len());
        let mut total = 0u64;
        for input in &self.inputs {
            let tx_id = b256(&input.tx_id, "coin transaction id")?;
            let amount = canonical_u64(&input.amount, "coin amount")?;
            if amount == 0 {
                return Err(invalid("coin amount must be positive"));
            }
            total = total
                .checked_add(amount)
                .ok_or_else(|| invalid("coin amounts overflow"))?;
            inputs.push((tx_id, input.output_index, amount));
        }
        let needed = amount
            .checked_add(max_fee)
            .ok_or_else(|| invalid("amount and fee overflow"))?;
        if total < needed {
            return Err(invalid("coins do not cover the transfer and max fee"));
        }
        Ok(Checked {
            from,
            to,
            amount,
            max_fee,
            inputs,
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
                    return Err(invalid("only native ETH transfers are enabled"));
                }
                if b256(to, "intent recipient")? != b256(&self.to, "recipient")? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.base {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Fuel intent")),
        }
        self.check()?;
        Ok(())
    }

    /// The serialized `TransactionScript`; `signed` selects the wire form
    /// (with witnesses) or the id form (witness count zeroed, none appended).
    fn encode(&self, witnesses: &[Vec<u8>]) -> Result<Vec<u8>> {
        let c = self.check()?;
        let asset = BASE_ASSET_ID;
        let mut out = Vec::with_capacity(512);
        let push_u64 = |out: &mut Vec<u8>, v: u64| out.extend_from_slice(&v.to_be_bytes());
        push_u64(&mut out, 0); // TransactionType::Script (u8 padded to a word)
        push_u64(&mut out, self.gas_limit);
        out.extend_from_slice(&[0u8; 32]); // receipts root (zeroed until executed)
        push_u64(&mut out, TRANSFER_SCRIPT.len() as u64);
        push_u64(&mut out, 0); // script data length
        push_u64(&mut out, (POLICY_MAX_FEE | POLICY_EXPIRATION) as u64);
        push_u64(&mut out, c.inputs.len() as u64);
        push_u64(&mut out, 2); // change + coin outputs
        push_u64(&mut out, witnesses.len() as u64);
        out.extend_from_slice(&TRANSFER_SCRIPT);
        out.extend_from_slice(&[0u8; 4]); // script padded to a word
                                          // policies sorted by type: MaxFee (u64), Expiration (u32 word)
        push_u64(&mut out, c.max_fee);
        push_u64(&mut out, self.expiration);
        for (i, (tx_id, output_index, amount)) in c.inputs.iter().enumerate() {
            push_u64(&mut out, 0); // InputType::Coin
            out.extend_from_slice(tx_id);
            push_u64(&mut out, *output_index as u64);
            out.extend_from_slice(&c.from);
            push_u64(&mut out, *amount);
            out.extend_from_slice(&asset);
            push_u64(&mut out, 0); // tx pointer block height
            push_u64(&mut out, 0); // tx pointer index
            push_u64(&mut out, i as u64); // witness index
            push_u64(&mut out, 0); // predicate gas used
            push_u64(&mut out, 0); // predicate length
            push_u64(&mut out, 0); // predicate data length
        }
        // Change output first (the fuels SDK adds it with the first coin input),
        // then the transfer's coin output.
        push_u64(&mut out, 2); // OutputType::Change
        out.extend_from_slice(&c.from);
        push_u64(&mut out, 0); // computed by the VM
        out.extend_from_slice(&asset);
        push_u64(&mut out, 0); // OutputType::Coin
        out.extend_from_slice(&c.to);
        push_u64(&mut out, c.amount);
        out.extend_from_slice(&asset);
        for witness in witnesses {
            push_u64(&mut out, witness.len() as u64);
            out.extend_from_slice(witness);
        }
        Ok(out)
    }

    /// sha256(chain id u64 BE || witness-stripped encoding), as fuel-core shows it.
    pub fn txid(&self) -> Result<[u8; 32]> {
        let mut preimage = network_id(&self.chain_id)?.to_be_bytes().to_vec();
        preimage.extend_from_slice(&self.encode(&[])?);
        Ok(Sha256::digest(preimage).into())
    }

    /// Returns the hex wire transaction (for the GraphQL `submit` mutation) and
    /// its `0x`-prefixed id. Every coin input shares the one signature witness.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let txid = self.txid()?;
        let (parity, r, s) = evm::sign_digest(secret, &txid)?;
        // Fuel packs the recovery bit into the top bit of s (s is < n/2).
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        signature[32] |= parity << 7;
        let witnesses = vec![signature.to_vec(); self.inputs.len()];
        let wire = self.encode(&witnesses)?;
        Ok((
            format!("0x{}", hex::encode(wire)),
            format!("0x{}", hex::encode(txid)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// fuels@0.103.0 `Signer`/`Address` for the key 0x07…07.
    const FROM: &str = "0x63520e389b3e28d9af866d60fc41b6753a4450da0962633143ba5924077fdb28";
    /// …and for the key 0x09…09.
    const TO: &str = "0xd78488241aeebaf5144aa4c891ef681216baf9bc4a2074b8bd573ffbbec41b14";

    fn tx() -> FuelTx {
        FuelTx {
            chain_id: SEPOLIA.into(),
            from: FROM.into(),
            to: TO.into(),
            base: "123456789".into(),
            inputs: vec![FuelCoinInput {
                tx_id: format!("0x{}", "11".repeat(32)),
                output_index: 0,
                amount: "10000000000".into(),
            }],
            gas_limit: 0,
            max_fee: "1000000".into(),
            expiration: 7_600_000,
        }
    }

    fn intent(tx: &FuelTx) -> TxIntent {
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
                amount: Amount(tx.base.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_fuels_sdk() {
        // sha256 of the uncompressed SEC1 key without the prefix; pinned from
        // `new Signer('0x0707…').address` (fuels 0.103.0).
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        assert_eq!(
            address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap(),
            FROM
        );
        assert!(b256(
            "0x3828b21f26c49a0ff546f6f4bcee6a64bdc685faf4a961b3c00d05814cda9801",
            "x"
        )
        .is_ok());
    }

    /// The exact bytes and id the fuels SDK produced for these fields.
    #[test]
    fn wire_and_id_match_the_fuels_sdk() {
        let t = tx();
        assert_eq!(
            format!("0x{}", hex::encode(t.encode(&[]).unwrap())),
            format!("0x{ID_FORM}")
        );
        assert_eq!(
            format!("0x{}", hex::encode(t.txid().unwrap())),
            "0xd3ee1cae6b6e9c5bd2948f7e1c01b99758d42eaf591bd9a50ff3e90fc9716703"
        );
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{WIRE}"));
        assert_eq!(
            id,
            "0xd3ee1cae6b6e9c5bd2948f7e1c01b99758d42eaf591bd9a50ff3e90fc9716703"
        );
    }

    #[test]
    fn signature_recovers_to_the_sender() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let t = tx();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        // Witness section: last 8 bytes length + 64 bytes signature.
        let sig = &wire[wire.len() - 64..];
        let recovery = sig[32] >> 7;
        let mut s = sig[32..].to_vec();
        s[0] &= 0x7f;
        let mut rs = sig[..32].to_vec();
        rs.extend_from_slice(&s);
        let recovered = VerifyingKey::recover_from_prehash(
            &t.txid().unwrap(),
            &Signature::from_slice(&rs).unwrap(),
            RecoveryId::from_byte(recovery).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.txid().is_err());
        assert!(t.check_matches_intent(&intent(&t)).is_err());
        let mut t = base.clone();
        t.base = "0123456789".into();
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.base = "0".into();
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.inputs = vec![];
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.inputs[0].amount = "1".into();
        assert!(t.txid().is_err()); // coins below amount + fee
        let mut t = base.clone();
        t.gas_limit = MAX_GAS_LIMIT + 1;
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.expiration = 0;
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.expiration = u32::MAX as u64 + 1;
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.max_fee = "0".into();
        assert!(t.txid().is_err());
        let mut t = base.clone();
        t.to = "0xd78488241aeebaf5144aa4c891ef681216baf9bc4a2074b8bd573ffbbec41b14".to_uppercase();
        assert!(t.txid().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "123456790".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = TO.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": SEPOLIA, "from": FROM, "to": TO, "base": "1",
            "inputs": [{"txId": format!("0x{}", "11".repeat(32)), "outputIndex": 0, "amount": "100"}],
            "gasLimit": 0, "maxFee": "1000", "expiration": 100, "script": "0x00"
        });
        assert!(serde_json::from_value::<FuelTx>(extra).is_err());
    }

    /// Witness-stripped encoding for the pinned fields (witnessesCount = 0).
    const ID_FORM: &str = concat!(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000040000000000000000",
        "0000000000000018000000000000000100000000000000020000000000000000",
        "240000000000000000000000000f4240000000000073f7800000000000000000",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "000000000000000063520e389b3e28d9af866d60fc41b6753a4450da09626331",
        "43ba5924077fdb2800000002540be400f8f8b6283d7fa5b672b530cbb84fcccb",
        "4ff8dc40f8176ef4544ddb1f1952ad0700000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000263520e389b3e28d9af866d60fc41b6753a4450da09626331",
        "43ba5924077fdb280000000000000000f8f8b6283d7fa5b672b530cbb84fcccb",
        "4ff8dc40f8176ef4544ddb1f1952ad070000000000000000d78488241aeebaf5",
        "144aa4c891ef681216baf9bc4a2074b8bd573ffbbec41b1400000000075bcd15",
        "f8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07"
    );
    /// Signed wire (witness appended) as produced by fuels 0.103.0.
    const WIRE: &str = concat!(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000040000000000000000",
        "0000000000000018000000000000000100000000000000020000000000000001",
        "240000000000000000000000000f4240000000000073f7800000000000000000",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "000000000000000063520e389b3e28d9af866d60fc41b6753a4450da09626331",
        "43ba5924077fdb2800000002540be400f8f8b6283d7fa5b672b530cbb84fcccb",
        "4ff8dc40f8176ef4544ddb1f1952ad0700000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000263520e389b3e28d9af866d60fc41b6753a4450da09626331",
        "43ba5924077fdb280000000000000000f8f8b6283d7fa5b672b530cbb84fcccb",
        "4ff8dc40f8176ef4544ddb1f1952ad070000000000000000d78488241aeebaf5",
        "144aa4c891ef681216baf9bc4a2074b8bd573ffbbec41b1400000000075bcd15",
        "f8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07",
        "0000000000000040f075e2cd0968b06b4b2d1f06ec02ef05c18f614e8c33e6fe",
        "dbf4c54364a40673eb7b1a4a2cbe5d9c413a2dce1bc62fc86f6404ffc01bd3af",
        "5f19b0c2a9935358"
    );
}
