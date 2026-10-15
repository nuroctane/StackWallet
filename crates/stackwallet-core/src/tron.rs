//! Native TRX transfers. The core encodes the whole `Transaction.raw` protobuf
//! from checked fields, so an adapter cannot add contracts, permissions or data.

use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// CAIP-2 references are the chain's EVM-style chain id (Nile: 3448148188).
pub const NILE: &str = "tron:0xcd8690dc";
const ADDRESS_PREFIX: u8 = 0x41;
const TRANSFER_CONTRACT: i32 = 1;
const TRANSFER_TYPE_URL: &str = "type.googleapis.com/protocol.TransferContract";
const MAX_EXPIRATION_MS: u64 = 24 * 60 * 60 * 1000;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Tron transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != NILE {
        return Err(invalid("only Tron Nile transfers are enabled"));
    }
    Ok(())
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The 21-byte `0x41 || keccak(pubkey)[12..]` form behind a canonical base58check address.
pub fn address_bytes(address: &str) -> Result<[u8; 21]> {
    if address.len() != 34 {
        return Err(invalid("address must be 34 characters"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 25 || bytes[0] != ADDRESS_PREFIX {
        return Err(invalid("not a Tron address"));
    }
    let (payload, check) = bytes.split_at(21);
    if checksum(payload) != check {
        return Err(invalid("address checksum mismatch"));
    }
    let out: [u8; 21] = payload.try_into().expect("21 bytes");
    if out[1..].iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    Ok(out)
}

pub fn encode_address(payload: &[u8; 21]) -> String {
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum(payload));
    bs58::encode(full).into_string()
}

pub fn address(public: &[u8]) -> Result<String> {
    let mut payload = [0u8; 21];
    payload[0] = ADDRESS_PREFIX;
    payload[1..].copy_from_slice(&evm::address_from_public(public)?);
    Ok(encode_address(&payload))
}

fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TronTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal sun (1 TRX = 1,000,000 sun); never a JSON floating-point number.
    pub sun: String,
    /// Bytes 6..8 of the reference block number, hex.
    pub ref_block_bytes: String,
    /// Bytes 8..16 of the reference block id, hex.
    pub ref_block_hash: String,
    /// Unix ms; the network drops the transaction after this.
    pub expiration: u64,
    /// Unix ms the transaction was built.
    pub timestamp: u64,
}

impl TronTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native TRX transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.sun {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Tron intent")),
        }
        self.raw_data()?;
        Ok(())
    }

    /// The serialized `Transaction.raw`; its sha256 is the transaction id and the sighash.
    pub fn raw_data(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = self
            .sun
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 sun"))?;
        if amount == 0 || amount > i64::MAX as u64 || amount.to_string() != self.sun {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        let ref_block_bytes = fixed_hex::<2>(&self.ref_block_bytes, "reference block bytes")?;
        let ref_block_hash = fixed_hex::<8>(&self.ref_block_hash, "reference block hash")?;
        if ref_block_hash == [0; 8] {
            return Err(invalid("zero reference block hash"));
        }
        if self.timestamp == 0
            || self.expiration <= self.timestamp
            || self.expiration - self.timestamp > MAX_EXPIRATION_MS
            || self.expiration > i64::MAX as u64
        {
            return Err(invalid(
                "expiration must fall within a day of the timestamp",
            ));
        }
        let parameter = Any {
            type_url: TRANSFER_TYPE_URL.into(),
            value: TransferContract {
                owner_address: from.to_vec(),
                to_address: to.to_vec(),
                amount: amount as i64,
            }
            .encode_to_vec(),
        };
        Ok(Raw {
            ref_block_bytes: ref_block_bytes.to_vec(),
            ref_block_hash: ref_block_hash.to_vec(),
            expiration: self.expiration as i64,
            contract: vec![Contract {
                r#type: TRANSFER_CONTRACT,
                parameter: Some(parameter),
            }],
            timestamp: self.timestamp as i64,
        }
        .encode_to_vec())
    }

    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.raw_data()?).into())
    }

    /// Returns the serialized signed `Transaction` (for `/wallet/broadcasthex`) and its id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let txid = self.txid()?;
        let (parity, r, s) = evm::sign_digest(secret, &txid)?;
        // java-tron accepts v as 0/1 or 27/28; wallets and TronWeb emit 27/28.
        let signature = [r.as_slice(), s.as_slice(), &[parity + 27]].concat();
        let wire = Transaction {
            raw_data: Some(Raw::decode(self.raw_data()?.as_slice()).expect("own encoding")),
            signature: vec![signature],
        }
        .encode_to_vec();
        Ok((format!("0x{}", hex::encode(wire)), hex::encode(txid)))
    }
}

#[derive(Clone, PartialEq, Message)]
struct TransferContract {
    #[prost(bytes = "vec", tag = "1")]
    owner_address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    to_address: Vec<u8>,
    #[prost(int64, tag = "3")]
    amount: i64,
}
#[derive(Clone, PartialEq, Message)]
struct Any {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct Contract {
    #[prost(int32, tag = "1")]
    r#type: i32,
    #[prost(message, optional, tag = "2")]
    parameter: Option<Any>,
}
#[derive(Clone, PartialEq, Message)]
struct Raw {
    #[prost(bytes = "vec", tag = "1")]
    ref_block_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    ref_block_hash: Vec<u8>,
    #[prost(int64, tag = "8")]
    expiration: i64,
    #[prost(message, repeated, tag = "11")]
    contract: Vec<Contract>,
    #[prost(int64, tag = "14")]
    timestamp: i64,
}
#[derive(Clone, PartialEq, Message)]
struct Transaction {
    #[prost(message, optional, tag = "1")]
    raw_data: Option<Raw>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    signature: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];

    fn sender() -> String {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn tx() -> TronTx {
        TronTx {
            chain_id: NILE.into(),
            from: sender(),
            to: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".into(),
            sun: "1500000".into(),
            ref_block_bytes: "a1b2".into(),
            ref_block_hash: "0123456789abcdef".into(),
            expiration: 1_760_000_060_000,
            timestamp: 1_760_000_000_000,
        }
    }

    fn intent(tx: &TronTx) -> TxIntent {
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
                amount: Amount(tx.sun.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_published_vector() {
        // Private key 1 is 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf on EVM.
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = k256::ecdsa::SigningKey::from_bytes((&one).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(addr, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC");
        assert_eq!(encode_address(&address_bytes(&addr).unwrap()), addr);
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u").is_err());
        assert!(address_bytes("0x8ba1f109551bd432803012645ac136ddd64dba72").is_err());
        let mut zero = [0u8; 21];
        zero[0] = ADDRESS_PREFIX;
        assert!(address_bytes(&encode_address(&zero)).is_err());
    }

    #[test]
    fn signature_recovers_to_the_sender_over_the_txid() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let decoded = Transaction::decode(wire.as_slice()).unwrap();
        assert_eq!(
            decoded.raw_data.unwrap().encode_to_vec(),
            t.raw_data().unwrap()
        );
        let sig = &decoded.signature[0];
        assert_eq!(sig.len(), 65);
        assert_eq!(id, hex::encode(t.txid().unwrap()));
        let recovered = VerifyingKey::recover_from_prehash(
            &t.txid().unwrap(),
            &Signature::from_slice(&sig[..64]).unwrap(),
            RecoveryId::from_byte(sig[64] - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    /// The TypeScript adapter encodes the same fields and asserts this exact hex.
    #[test]
    fn raw_data_matches_the_adapter_vector() {
        let t = TronTx {
            from: "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC".into(),
            ..tx()
        };
        assert_eq!(hex::encode(t.raw_data().unwrap()), RAW_VECTOR);
    }
    const RAW_VECTOR: &str =
        "0a02a1b222080123456789abcdef40e0d4b6c19c335a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15417e5f4552091a69125d5dfcb7b8c2659029395bdf121541a614f803b6fd780986a42c78ec9c7f77e6ded13c18e0c65b708080b3c19c33";

    #[test]
    fn raw_data_layout_is_a_single_transfer_contract() {
        let raw = tx().raw_data().unwrap();
        // ref_block_bytes, ref_block_hash, expiration, one contract, timestamp; nothing else.
        let decoded = Raw::decode(raw.as_slice()).unwrap();
        assert_eq!(decoded.encode_to_vec(), raw);
        assert_eq!(decoded.contract.len(), 1);
        let param = decoded.contract[0].parameter.as_ref().unwrap();
        assert_eq!(param.type_url, TRANSFER_TYPE_URL);
        assert_eq!(raw[0], 0x0a);
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "tron:0x2b6653dc".into();
        assert!(t.raw_data().is_err());
        let mut t = base.clone();
        t.sun = "01500000".into();
        assert!(t.raw_data().is_err());
        let mut t = base.clone();
        t.sun = "0".into();
        assert!(t.raw_data().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.raw_data().is_err());
        let mut t = base.clone();
        t.expiration = t.timestamp + MAX_EXPIRATION_MS + 1;
        assert!(t.raw_data().is_err());
        let mut t = base.clone();
        t.ref_block_hash = "0123456789ABCDEF".into();
        assert!(t.raw_data().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".into();
        other.to = sender();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": NILE, "from": base.from, "to": base.to, "sun": "1",
            "refBlockBytes": "a1b2", "refBlockHash": "0123456789abcdef",
            "expiration": 2, "timestamp": 1, "data": "00"
        });
        assert!(serde_json::from_value::<TronTx>(extra).is_err());
    }
}
