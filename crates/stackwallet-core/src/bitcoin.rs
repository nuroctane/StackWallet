//! Intent-bound Signet sends. Funding transactions bind each input's amount and
//! script; the core constructs the PSBT and all signing digests. Single keys
//! spend P2WPKH; threshold (FROST secp256k1-tr) wallets spend P2TR key paths,
//! one BIP341 sighash per input, signed together in one ceremony.
use crate::{
    evm,
    intent::{TxIntent, TxIntentKind},
    CoreError, Result,
};
use bitcoin::{
    absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::TweakedPublicKey,
    psbt::Psbt,
    secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey},
    sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
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
fn script(address: &str, recipient: bool) -> Result<ScriptBuf> {
    let checked = Address::from_str(address)
        .map_err(|_| invalid("invalid address"))?
        .require_network(Network::Signet)
        .map_err(|_| invalid("wrong address network"))?;
    let script = checked.script_pubkey();
    if checked.to_string() != address
        || !(script.is_p2wpkh() || script.is_p2tr() || (recipient && script.is_p2wsh()))
    {
        return Err(invalid("unsupported or non-canonical Signet address"));
    }
    Ok(checked.script_pubkey())
}
pub fn address(public: &[u8]) -> Result<String> {
    let key =
        CompressedPublicKey::from_slice(public).map_err(|_| invalid("invalid compressed key"))?;
    Ok(Address::p2wpkh(&key, Network::Signet).to_string())
}
/// The P2TR address of a FROST secp256k1-tr group. frost applies the BIP341
/// unspendable-script-path tweak at DKG, so the group key already is the
/// output key `Q` and is used as is.
pub fn taproot_address(output_key_xonly: &[u8]) -> Result<String> {
    let key = XOnlyPublicKey::from_slice(output_key_xonly)
        .map_err(|_| invalid("invalid x-only output key"))?;
    Ok(Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(key),
        Network::Signet,
    )
    .to_string())
}
/// Size and dust figures for the sender's own script, so fee bounds and change
/// limits follow what the inputs and change output actually weigh.
struct SenderShape {
    input_vbytes: u64,
    change_bytes: u64,
    change_dust: u64,
}
fn sender_shape(from: &ScriptBuf) -> SenderShape {
    if from.is_p2tr() {
        // 41 non-witness bytes plus a 64-byte signature witness (66 WU / 4).
        SenderShape {
            input_vbytes: 58,
            change_bytes: 43,
            change_dust: 330,
        }
    } else {
        SenderShape {
            input_vbytes: 69,
            change_bytes: 31,
            change_dust: 294,
        }
    }
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
    /// The ledger id of a broadcast transaction this one replaces (BIP125).
    /// Absent on ordinary sends, so their serialization is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
}
impl BitcoinTx {
    /// Upper bound on the virtual size, the figure every fee bound uses.
    fn max_vsize(&self) -> Result<u64> {
        let from = script(&self.from, false)?;
        let to = script(&self.to, true)?;
        let shape = sender_shape(&from);
        Ok(11
            + shape.input_vbytes * self.inputs.len() as u64
            + shape.change_bytes
            + 9
            + to.len() as u64)
    }
    pub fn psbt(&self) -> Result<Psbt> {
        check_chain(&self.chain_id)?;
        let from = script(&self.from, false)?;
        let to = script(&self.to, true)?;
        // Paying the sender back is only a cancel: it must replace something
        // and sweep everything into that one output.
        let cancel = from == to;
        if cancel && self.replaces.is_none() {
            return Err(invalid("sender and recipient must differ"));
        }
        if self
            .replaces
            .as_ref()
            .is_some_and(|r| r.is_empty() || r.len() > 128)
        {
            return Err(invalid("bad replaced transaction id"));
        }
        if self.inputs.is_empty() || self.inputs.len() > 8 {
            return Err(invalid("expected one to eight inputs"));
        }
        let amount = number(&self.amount)?;
        let fee = number(&self.fee)?;
        let shape = sender_shape(&from);
        let taproot = from.is_p2tr();
        let recipient_bytes = 9 + to.len() as u64;
        let dust = 3 * (recipient_bytes + 67);
        let max_size = self.max_vsize()?;
        if amount < dust || fee == 0 || fee > 100_000 || fee > max_size * 100 {
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
        if change > 0 && change < shape.change_dust {
            return Err(invalid("dust change; select different inputs or amount"));
        }
        if cancel && change > 0 {
            return Err(invalid("a cancel sweeps every input back in one output"));
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
            input.sighash_type = Some(if taproot {
                TapSighashType::Default.into()
            } else {
                EcdsaSighashType::All.into()
            });
        }
        Ok(psbt)
    }
    /// BIP125 against the transaction being replaced: same sender and chain,
    /// every original input spent again (so at most one of them can confirm),
    /// a strictly higher fee rate, and an absolute fee that also pays the
    /// default 1 sat/vB incremental relay fee for the replacement's own size.
    pub fn check_replaces(&self, original: &BitcoinTx) -> Result<()> {
        self.psbt()?;
        original.psbt()?;
        if self.chain_id != original.chain_id || self.from != original.from {
            return Err(invalid("a replacement must spend from the same sender"));
        }
        let mine: HashSet<_> = self.inputs.iter().map(|i| (&i.txid, i.vout)).collect();
        if !original
            .inputs
            .iter()
            .all(|i| mine.contains(&(&i.txid, i.vout)))
        {
            return Err(invalid("a replacement must spend every original input"));
        }
        let (fee, old) = (number(&self.fee)?, number(&original.fee)?);
        let (size, old_size) = (self.max_vsize()?, original.max_vsize()?);
        if fee < old.saturating_add(size)
            || u128::from(fee) * u128::from(old_size) <= u128::from(old) * u128::from(size)
        {
            return Err(invalid(
                "a replacement must raise the fee rate and pay at least 1 sat/vB more",
            ));
        }
        Ok(())
    }
    /// Whether the sender is a P2TR key path, i.e. a threshold group.
    pub fn is_taproot(&self) -> Result<bool> {
        Ok(script(&self.from, false)?.is_p2tr())
    }
    /// The bytes a threshold ceremony is bound to: this transaction as the core
    /// serializes it. Co-signers decode it with [`BitcoinTx::from_payload`] and
    /// rebuild every digest themselves.
    pub fn payload(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("unserializable transaction"))
    }
    pub fn from_payload(bytes: &[u8]) -> Result<Self> {
        let tx: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("payload is not a transfer"))?;
        if tx.payload()? != bytes {
            return Err(invalid("non-canonical payload"));
        }
        tx.psbt()?;
        Ok(tx)
    }
    /// One BIP341 key-path sighash (SIGHASH_DEFAULT) per input, in input order.
    pub fn taproot_sighashes(&self) -> Result<Vec<[u8; 32]>> {
        if !self.is_taproot()? {
            return Err(invalid("only a P2TR sender signs with Schnorr"));
        }
        let psbt = self.psbt()?;
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|i| i.witness_utxo.clone().expect("core PSBT funding"))
            .collect();
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        (0..prevouts.len())
            .map(|i| {
                cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .map(|h| h.to_byte_array())
                    .map_err(|_| invalid("invalid taproot sighash"))
            })
            .collect()
    }
    /// Finalize a P2TR spend from the ceremony's signatures (64 bytes per
    /// input, concatenated). Each is verified as BIP340 against the sender's
    /// output key over the core's own sighash before it goes into a witness.
    pub fn assemble_taproot(&self, signatures: &[u8]) -> Result<(String, String)> {
        let digests = self.taproot_sighashes()?;
        if signatures.len() != 64 * digests.len() {
            return Err(invalid("expected one 64-byte signature per input"));
        }
        let from = script(&self.from, false)?;
        let key = XOnlyPublicKey::from_slice(&from.as_bytes()[2..])
            .map_err(|_| invalid("invalid sender output key"))?;
        let secp = Secp256k1::verification_only();
        let mut psbt = self.psbt()?;
        for (i, (digest, sig)) in digests.iter().zip(signatures.chunks(64)).enumerate() {
            let sig =
                schnorr::Signature::from_slice(sig).map_err(|_| invalid("malformed signature"))?;
            secp.verify_schnorr(&sig, &Message::from_digest(*digest), &key)
                .map_err(|_| invalid(format!("input {i} signature does not verify")))?;
            psbt.inputs[i].final_script_witness = Some(Witness::from_slice(&[sig.as_ref()]));
        }
        let tx = psbt
            .extract_tx()
            .map_err(|_| invalid("PSBT finalization failed"))?;
        Ok((
            format!("0x{}", hex::encode(serialize(&tx))),
            tx.compute_txid().to_string(),
        ))
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

/// One funding transaction per value, each paying `to`.
#[cfg(test)]
pub(crate) fn funding(to: &str, values: &[u64]) -> Vec<BitcoinInput> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let previous = Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([i as u8 + 1; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script(to, false).unwrap(),
                }],
            };
            BitcoinInput {
                txid: previous.compute_txid().to_string(),
                vout: 0,
                previous_tx_hex: hex::encode(serialize(&previous)),
            }
        })
        .collect()
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
            script_pubkey: script(&from, false).unwrap(),
        }],
    };
    BitcoinTx {
        replaces: None,
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
    fn recipient_scripts_have_independent_dust_and_fee_bounds() {
        let key = k256::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        for prefix in [0x00, 0x51] {
            let mut bytes = vec![prefix, 0x20];
            bytes.extend([2; 32]);
            let destination = ScriptBuf::from_bytes(bytes);
            let mut tx = fixture(key.verifying_key().to_encoded_point(true).as_bytes());
            tx.to = Address::from_script(&destination, Network::Signet)
                .unwrap()
                .to_string();
            tx.amount = "330".into();
            tx.fee = "15400".into();
            assert_eq!(
                tx.psbt().unwrap().unsigned_tx.output[0].script_pubkey,
                destination
            );
            let (raw, _) = tx.sign(&[1; 32]).unwrap();
            let signed: Transaction = deserialize(&hex::decode(&raw[2..]).unwrap()).unwrap();
            assert_eq!(signed.output[0].value.to_sat(), 330);
            assert_eq!(signed.output[0].script_pubkey, destination);
            tx.amount = "329".into();
            assert!(tx.psbt().is_err());
            tx.amount = "330".into();
            tx.fee = "15401".into();
            assert!(tx.psbt().is_err());
            tx.fee = "154".into();
            tx.from = tx.to.clone();
            assert!(tx.psbt().is_err());
        }
        for prefix in [0x52, 0x60] {
            let mut bytes = vec![prefix, 0x20];
            bytes.extend([2; 32]);
            let mut tx = fixture(key.verifying_key().to_encoded_point(true).as_bytes());
            tx.to = Address::from_script(&ScriptBuf::from_bytes(bytes), Network::Signet)
                .unwrap()
                .to_string();
            assert!(tx.psbt().is_err());
        }
    }
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
    fn taproot_senders_use_their_own_size_and_dust_bounds() {
        let g = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let from = taproot_address(&g.unwrap()).unwrap();
        assert!(taproot_address(&[0x79; 32]).is_err());
        assert!(from.starts_with("tb1p"));
        let key = k256::ecdsa::SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let mut tx = BitcoinTx {
            replaces: None,
            chain_id: SIGNET.into(),
            from: from.clone(),
            to: address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap(),
            amount: "50000".into(),
            fee: "500".into(),
            inputs: funding(&from, &[80_000]),
        };
        assert!(tx.is_taproot().unwrap());
        assert_eq!(tx.taproot_sighashes().unwrap().len(), 1);
        // 11 + 58 + 43 change + 31 recipient = 143 vB at the 100 sat/vB cap.
        tx.fee = "14300".into();
        assert!(tx.psbt().is_ok());
        tx.fee = "14301".into();
        assert!(tx.psbt().is_err());
        // P2TR change below 330 sats is dust.
        tx.fee = "500".into();
        tx.amount = "79171".into();
        assert!(tx.psbt().is_err());
        tx.amount = "79170".into();
        assert!(tx.psbt().is_ok());
        // A single key never signs for a Taproot sender, and a P2WPKH sender
        // has no Schnorr path.
        assert!(tx.sign(&[1; 32]).is_err());
        let p2wpkh = fixture(key.verifying_key().to_encoded_point(true).as_bytes());
        assert!(p2wpkh.taproot_sighashes().is_err());
        assert!(tx.assemble_taproot(&[0; 64]).is_err());
        assert!(tx.assemble_taproot(&[0; 63]).is_err());
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
