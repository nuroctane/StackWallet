//! Native ALPH transfers. Alephium is a sharded UTXO chain on secp256k1:
//! P2PKH addresses are base58 of `0x00 || blake2b-256(compressed pubkey)` with
//! no checksum, and transactions are signed with deterministic (RFC 6979)
//! low-S ECDSA over the 32-byte blake2b id of the unsigned transaction. The
//! core encodes the whole `UnsignedTx` from checked fields, so an adapter
//! cannot add inputs, outputs, tokens or a script. The byte format is pinned
//! against `@alephium/web3`'s codec and the testnet node's
//! `/transactions/build` output.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 references are the chain's `network_id` (testnet: 1).
pub const TESTNET: &str = "alephium:1";
const TESTNET_NETWORK_ID: u8 = 1;
const TX_VERSION: u8 = 0;
const P2PKH: u8 = 0x00;
/// Smallest spendable output; below it the node rejects the transaction.
pub const DUST_ATTOALPH: u128 = 1_000_000_000_000;
/// A plain P2PKH transfer with change is intrinsic-gas 20,000 (observed on the
/// testnet node's `/transactions/build`); block gas limit is 5,000,000.
const MIN_GAS_AMOUNT: u32 = 20_000;
const MAX_GAS_AMOUNT: u32 = 5_000_000;
const MIN_GAS_PRICE: u128 = 100_000_000_000; // 1e11 attoalph
const MAX_GAS_PRICE: u128 = 1_000_000_000_000_000_000; // 1e18
const MAX_INPUTS: usize = 64;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Alephium transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Alephium testnet transfers are enabled"));
    }
    Ok(())
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

/// The 33 bytes behind a canonical P2PKH address: `0x00 || pubkey hash`.
/// Alephium addresses carry no checksum, so only shape is checked here.
pub fn address_bytes(address: &str) -> Result<[u8; 33]> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if bytes.len() != 33 || bytes[0] != P2PKH {
        return Err(invalid("not an Alephium P2PKH address"));
    }
    if bytes[1..].iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    Ok(bytes.try_into().expect("33 bytes"))
}

pub fn address(public: &[u8]) -> Result<String> {
    let key = k256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("bad public key"))?;
    let compressed = key.to_encoded_point(true);
    let mut bytes = [0u8; 33];
    bytes[1..].copy_from_slice(&blake2b256(compressed.as_bytes()));
    Ok(bs58::encode(bytes).into_string())
}

/// Alephium's signed compact int (i32 codec): single byte under 0x20,
/// two bytes under 0x2000, four bytes under 0x20000000, else 0xc0 + 4 BE bytes.
fn i32_compact(out: &mut Vec<u8>, value: i32) {
    debug_assert!(value >= 0);
    let v = value as u32;
    if v < 0x20 {
        out.push(v as u8);
    } else if v < 0x2000 {
        out.push(0x40 | (v >> 8) as u8);
        out.push(v as u8);
    } else if v < 0x2000_0000 {
        out.push(0x80 | (v >> 24) as u8);
        out.extend(v.to_be_bytes()[1..].iter());
    } else {
        out.push(0xc0);
        out.extend(v.to_be_bytes());
    }
}

/// Alephium's unsigned compact int (u256 codec): u32 encoding below 2^32,
/// else a 0xc0 + (len - 4) header and minimal big-endian bytes.
fn u256_compact(out: &mut Vec<u8>, value: u128) {
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else if value < 0x4000_0000 {
        out.push(0x80 | (value >> 24) as u8);
        out.extend((value as u32).to_be_bytes()[1..].iter());
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(15);
        let body = &bytes[start..];
        debug_assert!(body.len() >= 4);
        out.push(0xc0 + (body.len() - 4) as u8);
        out.extend(body);
    }
}

fn amount(value: &str, what: &str) -> Result<u128> {
    let parsed = value
        .parse::<u128>()
        .map_err(|_| invalid(format!("{what} is not an attoalph integer")))?;
    if parsed.to_string() != value {
        return Err(invalid(format!("{what} must be a canonical integer")));
    }
    Ok(parsed)
}

/// One UTXO reference the transfer spends; the unlock script is always the
/// sender's public key, so only the node-reported hint and key cross the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlephiumInput {
    /// Output-ref hint as the node's `/addresses/{addr}/utxos` reports it.
    pub hint: i32,
    /// The output-ref key, 32 lowercase hex bytes.
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlephiumTx {
    pub chain_id: String,
    pub from: String,
    /// The sender's compressed SEC1 public key, hex; carried because every
    /// input's unlock script needs it, and checked to hash to `from`.
    pub public_key: String,
    pub to: String,
    /// Decimal attoalph to the recipient (1 ALPH = 1e18); at least the dust amount.
    pub attoalph: String,
    /// Decimal attoalph returned to `from`; at least the dust amount.
    pub change: String,
    pub inputs: Vec<AlephiumInput>,
    pub gas_amount: u32,
    /// Decimal attoalph per gas unit.
    pub gas_price: String,
}

struct CheckedFields {
    from: [u8; 33],
    to: [u8; 33],
    value: u128,
    change: u128,
    public: [u8; 33],
}

impl AlephiumTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ALPH transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.attoalph {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Alephium intent")),
        }
        self.unsigned_tx()?;
        Ok(())
    }

    fn checked_fields(&self) -> Result<CheckedFields> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let value = amount(&self.attoalph, "amount")?;
        let change = amount(&self.change, "change")?;
        if value < DUST_ATTOALPH || change < DUST_ATTOALPH {
            return Err(invalid("amounts must cover the 0.001 ALPH dust minimum"));
        }
        let gas_price = amount(&self.gas_price, "gas price")?;
        if !(MIN_GAS_PRICE..=MAX_GAS_PRICE).contains(&gas_price) {
            return Err(invalid("gas price outside the allowed band"));
        }
        if !(MIN_GAS_AMOUNT..=MAX_GAS_AMOUNT).contains(&self.gas_amount) {
            return Err(invalid("gas amount outside the allowed band"));
        }
        (self.gas_amount as u128)
            .checked_mul(gas_price)
            .and_then(|f| f.checked_add(value))
            .and_then(|f| f.checked_add(change))
            .ok_or_else(|| invalid("total exceeds u128"))?;
        if self.public_key.len() != 66 || self.public_key.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(invalid("public key must be 33 lowercase hex bytes"));
        }
        let public: [u8; 33] = hex::decode(&self.public_key)
            .map_err(|_| invalid("public key is not hex"))?
            .try_into()
            .expect("length checked");
        if address(&public)? != self.from {
            return Err(invalid("public key is not the sender's"));
        }
        Ok(CheckedFields {
            from,
            to,
            value,
            change,
            public,
        })
    }

    /// The serialized `UnsignedTx`; its blake2b-256 is the transaction id and sighash.
    pub fn unsigned_tx(&self) -> Result<Vec<u8>> {
        let CheckedFields {
            from,
            to,
            value,
            change,
            public,
        } = self.checked_fields()?;
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(invalid("a transfer needs between 1 and 64 inputs"));
        }
        let gas_price = amount(&self.gas_price, "gas price")?;
        let mut out = vec![TX_VERSION, TESTNET_NETWORK_ID, 0x00];
        i32_compact(&mut out, self.gas_amount as i32);
        u256_compact(&mut out, gas_price);
        i32_compact(&mut out, self.inputs.len() as i32);
        for input in &self.inputs {
            out.extend((input.hint as u32).to_be_bytes());
            if input.key.len() != 64 || input.key.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(invalid("input key must be 32 lowercase hex bytes"));
            }
            let key: [u8; 32] = hex::decode(&input.key)
                .map_err(|_| invalid("input key is not hex"))?
                .try_into()
                .expect("length checked");
            out.extend(key);
            out.push(P2PKH); // unlock script: P2PKH
            out.extend(public);
        }
        i32_compact(&mut out, 2);
        for (hash, amount) in [(to, value), (from, change)] {
            u256_compact(&mut out, amount);
            out.push(P2PKH); // lockup script: P2PKH
            out.extend(&hash[1..]);
            out.extend([0u8; 8]); // lockTime 0
            out.push(0x00); // no tokens
            out.push(0x00); // empty additional data
        }
        Ok(out)
    }

    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(blake2b256(&self.unsigned_tx()?))
    }

    /// Returns the serialized signed `Transaction` and the tx id (both hex, as
    /// the node and explorer show them). `POST /transactions/submit` takes the
    /// unsigned part and the one signature back out of the wire bytes.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let unsigned = self.unsigned_tx()?;
        let id = blake2b256(&unsigned);
        let (sig, _recid): (k256::ecdsa::Signature, _) = key
            .sign_prehash_recoverable(&id)
            .map_err(|_| invalid("signing failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut wire = unsigned;
        wire.push(0x01); // scriptExecutionOk
        wire.push(0x00); // no contract inputs
        wire.push(0x00); // no generated outputs
        wire.push(0x01); // one input signature
        i32_compact(&mut wire, 64);
        wire.extend(sig.to_bytes());
        wire.push(0x00); // no script signatures
        Ok((hex::encode(wire), hex::encode(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{Signature, VerifyingKey};

    const SECRET: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    const PUBKEY1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ADDR1: &str = "13nr2XuF1VYfEgBLsXBQFrZcfzNvACP8cDz5CdAwk6BUz";
    const ADDR2: &str = "1Dxa5jAd2GouRJUPAsqmPGFFnJj6mmWoC6A2kvBacwykc";

    fn tx() -> AlephiumTx {
        AlephiumTx {
            chain_id: TESTNET.into(),
            from: ADDR1.into(),
            public_key: PUBKEY1.into(),
            to: ADDR2.into(),
            attoalph: "1234567890123456789".into(),
            change: "500000000000000000".into(),
            inputs: vec![AlephiumInput {
                hint: -1985788861,
                key: "ab".repeat(32),
            }],
            gas_amount: 20_000,
            gas_price: "100000000000".into(),
        }
    }

    fn intent(tx: &AlephiumTx) -> TxIntent {
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
                amount: Amount(tx.attoalph.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_the_sdk_vector() {
        // @alephium/web3: addressFromPublicKey(publicKeyFromPrivateKey(1), 'default')
        let public = hex::decode(PUBKEY1).unwrap();
        assert_eq!(address(&public).unwrap(), ADDR1);
        assert_eq!(
            bs58::encode(address_bytes(ADDR1).unwrap()).into_string(),
            ADDR1
        );
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        // Alephium addresses carry no checksum; only shape is rejected here.
        assert!(address_bytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb").is_err());
        assert!(address_bytes("13nr2XuF").is_err());
        assert!(address_bytes("tgx7VNFoP9DJiFMFgXXtafQZkUvyEdDHT9ryamHJYrjq").is_err());
        // zero address
    }

    #[test]
    fn unsigned_tx_matches_the_sdk_vector() {
        // `unsignedTxCodec.encode` of the same fields in @alephium/web3.
        assert_eq!(hex::encode(tx().unsigned_tx().unwrap()), UNSIGNED_VECTOR);
        assert_eq!(hex::encode(tx().txid().unwrap()), TXID_VECTOR);
    }
    const UNSIGNED_VECTOR: &str = "00010080004e20c1174876e8000189a34443abababababababababababababababababababababababababababababababab000279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c4112210f47de9811500c08897cdf88a1d9a12667b5bebcf74c06d02e95d38fb5ae44d5fc0f41699cd0100000000000000000000c406f05b59d3b20000002975f1d28b92b6e84499b83b0797ef5235553eeb7edaa0cea243c1128c2fe73700000000000000000000";
    const TXID_VECTOR: &str = "11e03f7ffff566989708c4bb38f9b52b0db635d1ebf68666a6edd440eab11413";

    #[test]
    fn signature_matches_the_sdk_vector() {
        // RFC 6979 is deterministic: @alephium/web3's `sign(txid, key)` emits
        // exactly this low-S compact signature for the pinned transaction.
        let (wire, id) = tx().sign(&SECRET).unwrap();
        assert_eq!(id, TXID_VECTOR);
        assert!(wire.starts_with(UNSIGNED_VECTOR));
        let sig_hex = &wire[UNSIGNED_VECTOR.len() + 12..UNSIGNED_VECTOR.len() + 12 + 128];
        assert_eq!(sig_hex, SIGNATURE_VECTOR);
    }
    const SIGNATURE_VECTOR: &str = "02810c1c0ceb735982cad9f8e9bb6d27d7fa25ca45c44befd7a0422136877d4f751858ecb702fca362a4ecfae98c2a8254954387c376b81ef352648c851d8ecc";

    #[test]
    fn signature_verifies_against_the_sender() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (_wire, id) = t.sign(&SECRET).unwrap();
        let sig = Signature::from_slice(&hex::decode(SIGNATURE_VECTOR).unwrap()).unwrap();
        let public = VerifyingKey::from_sec1_bytes(&hex::decode(PUBKEY1).unwrap()).unwrap();
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        public
            .verify_prehash(&hex::decode(id).unwrap(), &sig)
            .unwrap();
    }

    #[test]
    fn compact_int_boundaries() {
        for (v, want) in [
            (0u128, "00"),
            (0x3f, "3f"),
            (0x40, "4040"),
            (0x3fff, "7fff"),
            (0x4000, "80004000"),
            (0x3fffffff, "bfffffff"),
            (0x40000000, "c040000000"),
        ] {
            let mut out = Vec::new();
            u256_compact(&mut out, v);
            assert_eq!(hex::encode(&out), want, "u256 {v}");
        }
        for (v, want) in [
            (0i32, "00"),
            (0x1f, "1f"),
            (0x20, "4020"),
            (0x1fff, "5fff"),
            (0x2000, "80002000"),
            (0x1fffffff, "9fffffff"),
            (0x20000000, "c020000000"),
        ] {
            let mut out = Vec::new();
            i32_compact(&mut out, v);
            assert_eq!(hex::encode(&out), want, "i32 {v}");
        }
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "alephium:0".into();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.attoalph = "0".into();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.attoalph = "01234567890123456789".into();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.change = "1".into();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.inputs = vec![];
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.gas_amount = 19_999;
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.gas_price = "99999999999".into();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.public_key = t.public_key.to_uppercase();
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        t.inputs[0].key = "AB".repeat(32);
        assert!(t.unsigned_tx().is_err());
        let mut t = base.clone();
        // public key 2 does not hash to ADDR1
        t.public_key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".into();
        assert!(t.unsigned_tx().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1234567890123456790".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = ADDR2.into();
        other.to = ADDR1.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": ADDR1, "publicKey": PUBKEY1, "to": ADDR2,
            "attoalph": "1", "change": "1", "inputs": [], "gasAmount": 20000,
            "gasPrice": "100000000000", "scriptOpt": "00"
        });
        assert!(serde_json::from_value::<AlephiumTx>(extra).is_err());
    }

    #[test]
    fn signature_is_low_s() {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let pub_hex = hex::encode(key.verifying_key().to_encoded_point(true).as_bytes());
        assert_eq!(pub_hex, PUBKEY1);
        let sig = Signature::from_slice(&hex::decode(SIGNATURE_VECTOR).unwrap()).unwrap();
        assert!(sig.normalize_s().is_none());
    }
}
