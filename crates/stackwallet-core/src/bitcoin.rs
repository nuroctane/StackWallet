//! Intent-bound Signet P2WPKH sends. Funding transactions bind each input's
//! amount and script; the core constructs the PSBT and all signing digests.
use crate::{
    evm,
    intent::{TxIntent, TxIntentKind},
    CoreError, Result,
};
use bitcoin::{
    absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    psbt::Psbt,
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};

pub const SIGNET: &str = "bip122:00000008819873e925422c1ff0f99f7c";
const MAX_MONEY: u64 = 2_100_000_000_000_000;
fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Bitcoin transfer",
        reason: reason.into(),
    }
}
pub fn check_chain(chain: &str) -> Result<()> {
    if chain != SIGNET {
        return Err(invalid("only Bitcoin Signet sends are enabled"));
    }
    Ok(())
}
fn number(text: &str) -> Result<u64> {
    let n = text
        .parse::<u64>()
        .map_err(|_| invalid("invalid satoshi amount"))?;
    if n.to_string() != text || n > MAX_MONEY {
        return Err(invalid("non-canonical satoshi amount"));
    }
    Ok(n)
}
fn script(address: &str) -> Result<ScriptBuf> {
    let checked = Address::from_str(address)
        .map_err(|_| invalid("invalid address"))?
        .require_network(Network::Signet)
        .map_err(|_| invalid("wrong address network"))?;
    if checked.to_string() != address || !checked.script_pubkey().is_p2wpkh() {
        return Err(invalid("only canonical tb1 P2WPKH addresses are enabled"));
    }
    Ok(checked.script_pubkey())
}
pub fn address(public: &[u8]) -> Result<String> {
    let key =
        CompressedPublicKey::from_slice(public).map_err(|_| invalid("invalid compressed key"))?;
    Ok(Address::p2wpkh(&key, Network::Signet).to_string())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitcoinInput {
    pub txid: String,
    pub vout: u32,
    pub previous_tx_hex: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitcoinTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub fee: String,
    pub inputs: Vec<BitcoinInput>,
}
impl BitcoinTx {
    pub fn psbt(&self) -> Result<Psbt> {
        check_chain(&self.chain_id)?;
        let from = script(&self.from)?;
        let to = script(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        if self.inputs.is_empty() || self.inputs.len() > 8 {
            return Err(invalid("expected one to eight inputs"));
        }
        let amount = number(&self.amount)?;
        let fee = number(&self.fee)?;
        let max_size = 11 + 69 * self.inputs.len() as u64 + 62;
        if amount < 294 || fee == 0 || fee > 100_000 || fee > max_size * 100 {
            return Err(invalid("dust amount or excessive fee"));
        }
        let mut seen = HashSet::new();
        let mut funding = Vec::new();
        let mut total = 0u64;
        for input in &self.inputs {
            if input.previous_tx_hex.len() > 400_000 || input.previous_tx_hex.len() % 2 != 0 {
                return Err(invalid("funding transaction too large or malformed"));
            }
            let bytes =
                hex::decode(&input.previous_tx_hex).map_err(|_| invalid("invalid funding hex"))?;
            let previous: Transaction =
                deserialize(&bytes).map_err(|_| invalid("invalid funding transaction"))?;
            if serialize(&previous) != bytes || previous.is_coinbase() {
                return Err(invalid("non-canonical or coinbase funding is unsupported"));
            }
            if previous.compute_txid().to_string() != input.txid {
                return Err(invalid("funding txid differs"));
            }
            if !seen.insert((input.txid.clone(), input.vout)) {
                return Err(invalid("duplicate input"));
            }
            let output = previous
                .output
                .get(input.vout as usize)
                .ok_or_else(|| invalid("funding output missing"))?;
            if output.script_pubkey != from || output.value.to_sat() == 0 {
                return Err(invalid("funding output does not belong to signer"));
            }
            total = total
                .checked_add(output.value.to_sat())
                .filter(|n| *n <= MAX_MONEY)
                .ok_or_else(|| invalid("input sum exceeds monetary bounds"))?;
            funding.push(output.clone());
        }
        let change = total
            .checked_sub(amount)
            .and_then(|n| n.checked_sub(fee))
            .ok_or_else(|| invalid("inputs do not cover amount and fee"))?;
        if change > 0 && change < 294 {
            return Err(invalid("dust change; select different inputs or amount"));
        }
        let mut output = vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: to,
        }];
        if change > 0 {
            output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: from,
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: self
                .inputs
                .iter()
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_str(&i.txid).expect("checked txid"),
                        vout: i.vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| invalid("invalid PSBT"))?;
        for (input, output) in psbt.inputs.iter_mut().zip(funding) {
            input.witness_utxo = Some(output);
            input.sighash_type = Some(EcdsaSighashType::All.into());
        }
        Ok(psbt)
    }
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        self.psbt()?;
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount }
                if intent.chain_id.0 == self.chain_id
                    && *to == self.to
                    && amount.0 == self.amount
                    && asset.0 == format!("{}:native", SIGNET) =>
            {
                Ok(())
            }
            _ => Err(invalid("transaction differs from intent")),
        }
    }
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let signing = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signer"))?;
        let public = signing.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("signer differs from sender"));
        }
        let mut psbt = self.psbt()?;
        for i in 0..psbt.inputs.len() {
            let funding = psbt.inputs[i]
                .witness_utxo
                .as_ref()
                .expect("core PSBT funding");
            let digest = SighashCache::new(&psbt.unsigned_tx)
                .p2wpkh_signature_hash(
                    i,
                    &funding.script_pubkey,
                    funding.value,
                    EcdsaSighashType::All,
                )
                .map_err(|_| invalid("invalid sighash"))?
                .to_byte_array();
            let (_, r, s) = evm::sign_digest(secret, &digest)?;
            let signature = k256::ecdsa::Signature::from_scalars(r, s)
                .map_err(|_| invalid("invalid signature"))?;
            let mut der = signature.to_der().as_bytes().to_vec();
            der.push(EcdsaSighashType::All as u8);
            psbt.inputs[i].final_script_witness =
                Some(Witness::from_slice(&[der.as_slice(), public.as_bytes()]));
        }
        let tx = psbt
            .extract_tx()
            .map_err(|_| invalid("PSBT finalization failed"))?;
        Ok((
            format!("0x{}", hex::encode(serialize(&tx))),
            tx.compute_txid().to_string(),
        ))
    }
}

#[cfg(test)]
pub(crate) fn fixture(public: &[u8]) -> BitcoinTx {
    let from = address(public).unwrap();
    let recipient = k256::ecdsa::SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let previous = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: script(&from).unwrap(),
        }],
    };
    BitcoinTx {
        chain_id: SIGNET.into(),
        from,
        to: address(recipient.verifying_key().to_encoded_point(true).as_bytes()).unwrap(),
        amount: "50000".into(),
        fee: "500".into(),
        inputs: vec![BitcoinInput {
            txid: previous.compute_txid().to_string(),
            vout: 0,
            previous_tx_hex: hex::encode(serialize(&previous)),
        }],
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_and_bip143_signature_match_independent_verifier() {
        let secret = [1u8; 32];
        let key = k256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
        let tx = fixture(key.verifying_key().to_encoded_point(true).as_bytes());
        let psbt = tx.psbt().unwrap();
        let (raw, hash) = tx.sign(&secret).unwrap();
        let signed: Transaction = deserialize(&hex::decode(&raw[2..]).unwrap()).unwrap();
        assert_eq!(hash, signed.compute_txid().to_string());
        assert_eq!(signed.output, psbt.unsigned_tx.output);
        assert_eq!(signed.input[0].sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
        let funding = psbt.inputs[0].witness_utxo.as_ref().unwrap();
        let digest = SighashCache::new(&signed)
            .p2wpkh_signature_hash(
                0,
                &funding.script_pubkey,
                funding.value,
                EcdsaSighashType::All,
            )
            .unwrap();
        let witness: Vec<_> = signed.input[0].witness.iter().collect();
        assert_eq!(witness.len(), 2);
        let signature = bitcoin::ecdsa::Signature::from_slice(witness[0]).unwrap();
        assert_eq!(signature.sighash_type, EcdsaSighashType::All);
        let public = bitcoin::secp256k1::PublicKey::from_slice(witness[1]).unwrap();
        bitcoin::secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(
                &bitcoin::secp256k1::Message::from_digest(digest.to_byte_array()),
                &signature.signature,
                &public,
            )
            .unwrap();
        assert!(tx.sign(&[3; 32]).is_err());
    }
    #[test]
    fn funding_hidden_outputs_and_fee_bounds_are_not_trusted() {
        let key = k256::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let tx = fixture(key.verifying_key().to_encoded_point(true).as_bytes());
        for fee in ["0", "01", "100001", "14301"] {
            let mut t = tx.clone();
            t.fee = fee.into();
            assert!(t.psbt().is_err());
        }
        let mut t = tx.clone();
        t.inputs.push(t.inputs[0].clone());
        assert!(t.psbt().is_err());
        let mut t = tx.clone();
        t.inputs[0].txid = "a".repeat(64);
        assert!(t.psbt().is_err());
        let mut t = tx.clone();
        t.inputs[0].vout = 1;
        assert!(t.psbt().is_err());
        let mut t = tx.clone();
        t.amount = "99207".into();
        assert!(t.psbt().is_err());
        let mut t = tx.clone();
        t.chain_id = "bip122:000000000019d6689c085ae165831e93".into();
        assert!(t.psbt().is_err());
        let mut payload = serde_json::to_value(tx).unwrap();
        payload["outputs"] = serde_json::json!([]);
        assert!(serde_json::from_value::<BitcoinTx>(payload).is_err());
    }
}
