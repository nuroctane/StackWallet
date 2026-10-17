//! Native ELF transfers. The core encodes the whole protobuf `Transaction`
//! (a `Transfer` call on the hardcoded multi-token contract) from checked
//! fields, so an adapter cannot swap the contract, method or params.
//!
//! aelf facts, all pinned against the official `aelf-sdk`:
//! - addresses are base58check of sha256(sha256(uncompressed SEC1 pubkey))
//! - the sighash and the transaction id are both sha256 of the serialized
//!   transaction *without* its signature field
//! - signatures are 65 bytes `r || s || recovery` with recovery in {0, 1}
//! - `TransferInput.amount` is a plain protobuf int64 (not sint64)

use k256::elliptic_curve::sec1::ToEncodedPoint;
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// aelf testnet main chain (`ChainId` from `/api/blockChain/chainStatus`).
pub const TDVV: &str = "aelf:tDVV";
/// `AElf.Contracts.MultiToken` on tDVV, resolved live from the genesis
/// contract's `GetContractAddressByName`.
const TOKEN_TDVV: &str = "7RzVGiuVWkvL4VfVHdZfQF2Tri3sgLe9U991bohHFfSRZXuGX";
const TRANSFER_METHOD: &str = "Transfer";
const NATIVE_SYMBOL: &str = "ELF";

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "aelf transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TDVV {
        return Err(invalid("only aelf tDVV transfers are enabled"));
    }
    Ok(())
}

fn token_contract(chain: &str) -> Result<[u8; 32]> {
    check_chain(chain)?;
    address_bytes(TOKEN_TDVV)
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The 32-byte `sha256d(pubkey)` payload behind a canonical base58check address.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() < 32 || address.len() > 64 {
        return Err(invalid("address length is implausible"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 36 {
        return Err(invalid("not an aelf address"));
    }
    let (payload, check) = bytes.split_at(32);
    if checksum(payload) != check {
        return Err(invalid("address checksum mismatch"));
    }
    let out: [u8; 32] = payload.try_into().expect("32 bytes");
    if out.iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    Ok(out)
}

pub fn encode_address(payload: &[u8; 32]) -> String {
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum(payload));
    bs58::encode(full).into_string()
}

/// aelf hashes the full 65-byte uncompressed SEC1 public key.
pub fn address(public: &[u8]) -> Result<String> {
    let key = k256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("bad public key"))?;
    let point = key.to_encoded_point(false);
    let digest = Sha256::digest(Sha256::digest(point.as_bytes()));
    Ok(encode_address(&digest.into()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AelfTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal elves (1 ELF = 100,000,000 elves); never a JSON floating-point number.
    pub elves: String,
    /// Height of the reference block; the network drops stale references.
    pub ref_block_number: u64,
    /// First four bytes of the reference block hash, hex.
    pub ref_block_prefix: String,
}

impl AelfTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ELF transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.elves {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported aelf intent")),
        }
        self.raw()?;
        Ok(())
    }

    /// The serialized `Transaction` without a signature; its sha256 is both
    /// the transaction id and the sighash.
    pub fn raw(&self) -> Result<Vec<u8>> {
        let contract = token_contract(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        if to == contract {
            return Err(invalid("recipient must not be the token contract"));
        }
        let amount = self
            .elves
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 elves"))?;
        if amount == 0 || amount > i64::MAX as u64 || amount.to_string() != self.elves {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        if self.ref_block_number == 0 || self.ref_block_number > i64::MAX as u64 {
            return Err(invalid("reference block number out of range"));
        }
        let ref_block_prefix = fixed_hex::<4>(&self.ref_block_prefix, "reference block prefix")?;
        if ref_block_prefix == [0; 4] {
            return Err(invalid("zero reference block prefix"));
        }
        let params = TransferInput {
            to: Some(Address { value: to.to_vec() }),
            symbol: NATIVE_SYMBOL.into(),
            amount: amount as i64,
            memo: String::new(),
        }
        .encode_to_vec();
        Ok(Transaction {
            from: Some(Address {
                value: from.to_vec(),
            }),
            to: Some(Address {
                value: contract.to_vec(),
            }),
            ref_block_number: self.ref_block_number as i64,
            ref_block_prefix: ref_block_prefix.to_vec(),
            method_name: TRANSFER_METHOD.into(),
            params,
            signature: Vec::new(),
        }
        .encode_to_vec())
    }

    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.raw()?).into())
    }

    /// Returns the serialized signed `Transaction` (plain hex for
    /// `/api/blockChain/sendTransaction`) and its id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let raw = self.raw()?;
        let txid = self.txid()?;
        let (parity, r, s) = evm::sign_digest(secret, &txid)?;
        let signature = [r.as_slice(), s.as_slice(), &[parity]].concat();
        let wire = Transaction::decode(raw.as_slice())
            .expect("own encoding")
            .with_signature(signature)
            .encode_to_vec();
        Ok((hex::encode(wire), hex::encode(txid)))
    }
}

impl Transaction {
    fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }
}

fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

#[derive(Clone, PartialEq, Message)]
struct Address {
    #[prost(bytes = "vec", tag = "1")]
    value: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct TransferInput {
    #[prost(message, optional, tag = "1")]
    to: Option<Address>,
    #[prost(string, tag = "2")]
    symbol: String,
    #[prost(int64, tag = "3")]
    amount: i64,
    /// proto3: empty memo is omitted from the wire.
    #[prost(string, tag = "4")]
    memo: String,
}
#[derive(Clone, PartialEq, Message)]
struct Transaction {
    #[prost(message, optional, tag = "1")]
    from: Option<Address>,
    #[prost(message, optional, tag = "2")]
    to: Option<Address>,
    #[prost(int64, tag = "3")]
    ref_block_number: i64,
    #[prost(bytes = "vec", tag = "4")]
    ref_block_prefix: Vec<u8>,
    #[prost(string, tag = "5")]
    method_name: String,
    #[prost(bytes = "vec", tag = "6")]
    params: Vec<u8>,
    #[prost(bytes = "vec", tag = "10000")]
    signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    /// aelf-sdk `getWalletByPrivateKey` vectors for keys 1 and 2.
    const KEY1_ADDRESS: &str = "2QCi3Fy1QXZKFmP6tSBtxCXsaztNzeiDfNgWTamcsj428v4cPZ";
    const KEY2_ADDRESS: &str = "2YZDdbxdmb8ve4r8WuqP88zy2noy5wwWb22X8QBhnheNdXCKVK";

    fn sender() -> String {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn tx() -> AelfTx {
        AelfTx {
            chain_id: TDVV.into(),
            from: sender(),
            to: KEY2_ADDRESS.into(),
            elves: "150000000".into(),
            ref_block_number: 12_345_678,
            ref_block_prefix: "a1b2c3d4".into(),
        }
    }

    fn intent(tx: &AelfTx) -> TxIntent {
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
                amount: Amount(tx.elves.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_aelf_sdk_vectors() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = k256::ecdsa::SigningKey::from_bytes((&one).into()).unwrap();
        let compressed = key.verifying_key().to_encoded_point(true);
        assert_eq!(address(compressed.as_bytes()).unwrap(), KEY1_ADDRESS);
        // aelf hashes the uncompressed point; either SEC1 form must agree.
        let uncompressed = key.verifying_key().to_encoded_point(false);
        assert_eq!(address(uncompressed.as_bytes()).unwrap(), KEY1_ADDRESS);
        assert_eq!(
            encode_address(&address_bytes(KEY1_ADDRESS).unwrap()),
            KEY1_ADDRESS
        );
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("2QCi3Fy1QXZKFmP6tSBtxCXsaztNzeiDfNgWTamcsj428v4cP1").is_err());
        assert!(
            address_bytes("ELF_2QCi3Fy1QXZKFmP6tSBtxCXsaztNzeiDfNgWTamcsj428v4cPZ_tDVV").is_err()
        );
        assert!(address_bytes("0x8ba1f109551bd432803012645ac136ddd64dba72").is_err());
        assert!(address_bytes(&encode_address(&[0; 32])).is_err());
    }

    #[test]
    fn signature_recovers_to_the_sender_over_the_txid() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire).unwrap();
        let decoded = Transaction::decode(wire.as_slice()).unwrap();
        assert_eq!(id, hex::encode(t.txid().unwrap()));
        let sig = &decoded.signature;
        assert_eq!(sig.len(), 65);
        let mut unsigned = decoded.clone();
        unsigned.signature = Vec::new();
        assert_eq!(unsigned.encode_to_vec(), t.raw().unwrap());
        let recovered = VerifyingKey::recover_from_prehash(
            &t.txid().unwrap(),
            &Signature::from_slice(&sig[..64]).unwrap(),
            RecoveryId::from_byte(sig[64]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    /// Byte-exact `Transaction` the official aelf-sdk produces for the same
    /// fields (minus the empty memo protobufjs writes); the TS tests pin this.
    #[test]
    fn raw_matches_the_aelf_sdk_vector() {
        let t = AelfTx {
            from: KEY1_ADDRESS.into(),
            ..tx()
        };
        assert_eq!(hex::encode(t.raw().unwrap()), RAW_VECTOR);
    }
    const RAW_VECTOR: &str =
        "0a220a20b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f12220a200e9a238616169860ba4fb502f8e87ce62db9ef321f29fd76d6e1ce30a0e0cdba18cec2f1052204a1b2c3d42a085472616e73666572322e0a220a20cb58bf657f03cf52498df98acaceca4ecb272db2879409e8fe1cc2ec735298121203454c461880a3c347";

    #[test]
    fn raw_layout_is_a_single_transfer_call() {
        let raw = tx().raw().unwrap();
        let decoded = Transaction::decode(raw.as_slice()).unwrap();
        assert_eq!(decoded.encode_to_vec(), raw);
        assert_eq!(decoded.method_name, TRANSFER_METHOD);
        assert!(decoded.signature.is_empty());
        assert_eq!(
            decoded.to.unwrap().value,
            address_bytes(TOKEN_TDVV).unwrap()
        );
        let params = TransferInput::decode(decoded.params.as_slice()).unwrap();
        assert_eq!(params.symbol, NATIVE_SYMBOL);
        assert_eq!(params.amount, 150_000_000);
        assert_eq!(raw[0], 0x0a);
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "aelf:AELF".into();
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.elves = "0150000000".into();
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.elves = "0".into();
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.to = TOKEN_TDVV.into();
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.ref_block_number = 0;
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.ref_block_prefix = "A1B2C3D4".into();
        assert!(t.raw().is_err());
        let mut t = base.clone();
        t.ref_block_prefix = "00000000".into();
        assert!(t.raw().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "150000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = KEY2_ADDRESS.into();
        other.to = sender();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TDVV, "from": base.from, "to": base.to, "elves": "1",
            "refBlockNumber": 7, "refBlockPrefix": "a1b2c3d4", "memo": "hi"
        });
        assert!(serde_json::from_value::<AelfTx>(extra).is_err());
    }
}
