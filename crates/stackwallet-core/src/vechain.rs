//! Native VET transfers as legacy (type 0) VeChainThor transactions. The core
//! encodes the whole RLP body from checked fields: one clause with no data, no
//! `dependsOn`, no fee delegation, so an adapter cannot add calls or a sponsor.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

type Blake2b256 = Blake2b<U32>;

/// CAIP-2 references are the last 16 bytes of the genesis block id, as VeChain's
/// WalletConnect integration spells them; the chain tag is the id's last byte.
pub const TESTNET: &str = "vechain:87721b09ed2e15997f466536b20bb127";
pub const MAINNET: &str = "vechain:b1ac3413d346d43539627e6be7ec1b4a";
const TESTNET_CHAIN_TAG: u8 = 0x27;
/// A native transfer costs 5000 (tx) + 16000 (clause); the cap leaves room for
/// adapters that pad but stops a fee drain through an absurd limit.
const MIN_GAS: u64 = 21_000;
const MAX_GAS: u64 = 100_000;
/// Blocks after `blockRef`; 720 blocks is about two hours at 10 s per block.
const MAX_EXPIRATION: u32 = 720;
/// VET supply is below 10^29 wei, so anything wider than 16 bytes is nonsense.
const MAX_AMOUNT_BYTES: usize = 16;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "VeChain transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only VeChain testnet transfers are enabled"));
    }
    Ok(())
}

fn chain_tag(chain: &str) -> Result<u8> {
    check_chain(chain)?;
    Ok(TESTNET_CHAIN_TAG)
}

/// Lowercase `0x` + 40 hex, the form thor nodes report. Mixed case must be a valid EIP-55 checksum.
pub fn address_bytes(address: &str) -> Result<[u8; 20]> {
    let body = address
        .strip_prefix("0x")
        .ok_or_else(|| invalid("address needs a 0x prefix"))?;
    if body.len() != 40 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("address must be 20 hex bytes"));
    }
    let bytes = evm::parse_address(address)?;
    let lower = body.bytes().all(|b| !b.is_ascii_uppercase());
    if !lower && evm::checksum_address(&bytes) != address {
        return Err(invalid("address checksum mismatch"));
    }
    if bytes == [0; 20] {
        return Err(invalid("zero address"));
    }
    Ok(bytes)
}

fn canonical_address(address: &str, what: &str) -> Result<[u8; 20]> {
    let bytes = address_bytes(address)?;
    if address != encode_address(&bytes) {
        return Err(invalid(format!("{what} must be lowercase hex")));
    }
    Ok(bytes)
}

pub fn encode_address(bytes: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn address(public: &[u8]) -> Result<String> {
    Ok(encode_address(&evm::address_from_public(public)?))
}

fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    &b[first..]
}

fn rlp_uint(n: u64) -> Vec<u8> {
    evm::rlp_bytes(strip_zeros(&n.to_be_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VechainTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal wei of VET (1 VET = 10^18); never a JSON floating-point number.
    pub vet_wei: String,
    /// First 8 bytes of a recent block id, lowercase hex without 0x.
    pub block_ref: String,
    /// Blocks after `blockRef` the transaction stays includable.
    pub expiration: u32,
    /// Legacy priority: gas price = base gas price * (1 + coef / 255), paid in VTHO.
    pub gas_price_coef: u8,
    pub gas: u64,
    /// 8 random bytes, lowercase hex without 0x; VeChain has no account nonce sequence.
    pub nonce: String,
}

impl VechainTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native VET transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.vet_wei {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported VeChain intent")),
        }
        self.unsigned_fields()?;
        Ok(())
    }

    fn unsigned_fields(&self) -> Result<Vec<Vec<u8>>> {
        let tag = chain_tag(&self.chain_id)?;
        let from = canonical_address(&self.from, "sender")?;
        let to = canonical_address(&self.to, "recipient")?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = evm::decimal_to_be(&self.vet_wei)
            .map_err(|_| invalid("amount must be a decimal integer"))?;
        if amount.is_empty() || amount.len() > MAX_AMOUNT_BYTES || self.vet_wei.starts_with('0') {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        let block_ref = fixed_hex::<8>(&self.block_ref, "block reference")?;
        if self.expiration == 0 || self.expiration > MAX_EXPIRATION {
            return Err(invalid(format!(
                "expiration must be 1..={MAX_EXPIRATION} blocks"
            )));
        }
        if !(MIN_GAS..=MAX_GAS).contains(&self.gas) {
            return Err(invalid(format!("gas must be {MIN_GAS}..={MAX_GAS}")));
        }
        let nonce = fixed_hex::<8>(&self.nonce, "nonce")?;
        let clause = evm::rlp_list(&[
            evm::rlp_bytes(&to),
            evm::rlp_bytes(&amount),
            evm::rlp_bytes(&[]),
        ]);
        Ok(vec![
            rlp_uint(u64::from(tag)),
            // blockRef is a compact fixed blob: leading zero bytes are dropped.
            evm::rlp_bytes(strip_zeros(&block_ref)),
            rlp_uint(u64::from(self.expiration)),
            evm::rlp_list(&[clause]),
            rlp_uint(u64::from(self.gas_price_coef)),
            rlp_uint(self.gas),
            // No dependsOn.
            evm::rlp_bytes(&[]),
            evm::rlp_bytes(strip_zeros(&nonce)),
            // Empty reserved list: features = 0, so no fee delegation.
            evm::rlp_list(&[]),
        ])
    }

    /// The unsigned RLP body; its blake2b-256 is the signing hash.
    pub fn encoded(&self) -> Result<Vec<u8>> {
        Ok(evm::rlp_list(&self.unsigned_fields()?))
    }

    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        Ok(Blake2b256::digest(self.encoded()?).into())
    }

    /// blake2b-256(signing hash || origin), the id thor and explorers report.
    pub fn txid(&self) -> Result<[u8; 32]> {
        let origin = canonical_address(&self.from, "sender")?;
        let mut h = Blake2b256::new();
        h.update(self.signing_hash()?);
        h.update(origin);
        Ok(h.finalize().into())
    }

    /// Returns the signed RLP (`0x` hex for `POST /transactions`) and the `0x` transaction id.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let hash = self.signing_hash()?;
        let (parity, r, s) = evm::sign_digest(secret, &hash)?;
        let signature = [r.as_slice(), s.as_slice(), &[parity]].concat();
        let mut fields = self.unsigned_fields()?;
        fields.push(evm::rlp_bytes(&signature));
        let wire = evm::rlp_list(&fields);
        Ok((
            format!("0x{}", hex::encode(wire)),
            format!("0x{}", hex::encode(self.txid()?)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    /// `Address.ofPublicKey(Secp256k1.derivePublicKey(fill(7)))` in `@vechain/sdk-core` 2.1.0.
    const SENDER: &str = "0x4a62316623ad457f02cdc5d997ded67a383ec569";
    const RECIPIENT: &str = "0x7495dee08f1340fa1fbda59c979f799d7d676fce";

    fn tx() -> VechainTx {
        VechainTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            vet_wei: "1500000000000000000".into(),
            block_ref: "018ff53eb317837f".into(),
            expiration: 720,
            gas_price_coef: 0,
            gas: 21_000,
            nonce: "0102030405060708".into(),
        }
    }

    fn intent(tx: &VechainTx) -> TxIntent {
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
                amount: Amount(tx.vet_wei.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    // `.nur/vechain-sdk/vector.mjs`: `Transaction.of(body)` and `.sign(fill(7))` in `@vechain/sdk-core` 2.1.0.
    const UNSIGNED_VECTOR: &str = "f83d2788018ff53eb317837f8202d0e0df947495dee08f1340fa1fbda59c979f799d7d676fce8814d1120d7b160000808082520880880102030405060708c0";
    const SIGNING_HASH_VECTOR: &str =
        "86d522d04b48ddd6d79fd170cc46b5c9e9513cf94eb0700be6b3968bd6bc846f";
    const SIGNED_VECTOR: &str = "0xf8802788018ff53eb317837f8202d0e0df947495dee08f1340fa1fbda59c979f799d7d676fce8814d1120d7b160000808082520880880102030405060708c0b841b1466082962703304d29f71f6d2dd5e64b2676d36cce6c6b07e5d2e3fc8d3f3e02bc16be132cd0c79badc471fa7b13fe412da119aa730a7ff2999c19cfcbd2f700";
    const TXID_VECTOR: &str = "0xabe7e51af617e1f9dacd359702aabf1085afbb9badaaf6a02678efb62a983915";
    const UNSIGNED_SMALL_VECTOR: &str =
        "e5270120d8d7947495dee08f1340fa1fbda59c979f799d7d676fce01808180830186a08080c0";
    const SIGNED_SMALL_VECTOR: &str = "0xf868270120d8d7947495dee08f1340fa1fbda59c979f799d7d676fce01808180830186a08080c0b841f7b9d039c3581f2d9fcc9d2c1aa0affcc9ca452dc16efe284db419ff297f8e591d1c2f4013461fad746ad0dc29b1aff640c7224764bd0abe171ba74e768a065a01";
    const TXID_SMALL_VECTOR: &str =
        "0x9e4c9f069b5abe57ac4f5c60cf67a7ef957338d2d5d4f2a920406d7ac840b04f";

    #[test]
    fn address_matches_published_vector() {
        // Private key 1 is 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf on EVM and VeChain alike.
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = k256::ecdsa::SigningKey::from_bytes((&one).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(addr, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(false).as_bytes()).unwrap();
        assert_eq!(addr, SENDER);
    }

    #[test]
    fn addresses_are_checked() {
        assert!(address_bytes("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf").is_ok());
        assert!(address_bytes("0x7E5F4552091A69125d5DfCb7b8C2659029395BDF").is_err());
        assert!(address_bytes("7e5f4552091a69125d5dfcb7b8c2659029395bdf").is_err());
        assert!(address_bytes("0x7e5f4552091a69125d5dfcb7b8c2659029395b").is_err());
        assert!(address_bytes("0x+e5f4552091a69125d5dfcb7b8c2659029395bdf").is_err());
        assert!(address_bytes(&encode_address(&[0; 20])).is_err());
        let mut t = tx();
        t.to = "0x7495DEE08F1340FA1FBDA59C979F799D7D676FCE".into();
        assert!(t.encoded().is_err());
    }

    #[test]
    fn encoding_matches_the_sdk_vectors() {
        let t = tx();
        assert_eq!(hex::encode(t.encoded().unwrap()), UNSIGNED_VECTOR);
        assert_eq!(hex::encode(t.signing_hash().unwrap()), SIGNING_HASH_VECTOR);
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, SIGNED_VECTOR);
        assert_eq!(id, TXID_VECTOR);

        // Zero nonce, a one-byte compacted blockRef and single-byte integers.
        let small = VechainTx {
            vet_wei: "1".into(),
            block_ref: "0000000000000001".into(),
            expiration: 32,
            gas_price_coef: 128,
            gas: 100_000,
            nonce: "0000000000000000".into(),
            ..tx()
        };
        assert_eq!(hex::encode(small.encoded().unwrap()), UNSIGNED_SMALL_VECTOR);
        let (wire, id) = small.sign(&SECRET).unwrap();
        assert_eq!(wire, SIGNED_SMALL_VECTOR);
        assert_eq!(id, TXID_SMALL_VECTOR);
    }

    #[test]
    fn signature_recovers_to_the_sender_over_the_signing_hash() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let unsigned = t.encoded().unwrap();
        // Both lists have two-byte headers here: the signed one is the unsigned
        // items followed by one 65-byte string.
        assert_eq!(&wire[..2], &[0xf8, 0x80]);
        assert_eq!(&wire[2..unsigned.len()], &unsigned[2..]);
        assert_eq!(&wire[unsigned.len()..unsigned.len() + 2], &[0xb8, 0x41]);
        let sig = &wire[unsigned.len() + 2..];
        assert_eq!(sig.len(), 65);
        assert!(sig[64] <= 1);
        let recovered = VerifyingKey::recover_from_prehash(
            &t.signing_hash().unwrap(),
            &Signature::from_slice(&sig[..64]).unwrap(),
            RecoveryId::from_byte(sig[64]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
        assert_eq!(id, format!("0x{}", hex::encode(t.txid().unwrap())));
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.encoded().is_err());
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.chain_id = "eip155:1".into();
        assert!(t.encoded().is_err());
        for amount in [
            "0",
            "01",
            "",
            "1.5",
            "-1",
            "340282366920938463463374607431768211456",
        ] {
            let mut t = base.clone();
            t.vet_wei = amount.into();
            assert!(t.encoded().is_err(), "{amount}");
        }
        let mut t = base.clone();
        t.vet_wei = "340282366920938463463374607431768211455".into();
        assert!(t.encoded().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.encoded().is_err());
        for gas in [20_999, 100_001, 0, u64::MAX] {
            let mut t = base.clone();
            t.gas = gas;
            assert!(t.encoded().is_err(), "{gas}");
        }
        for expiration in [0, MAX_EXPIRATION + 1] {
            let mut t = base.clone();
            t.expiration = expiration;
            assert!(t.encoded().is_err());
        }
        let mut t = base.clone();
        t.block_ref = "018FF53EB317837F".into();
        assert!(t.encoded().is_err());
        let mut t = base.clone();
        t.block_ref = "018ff53eb317".into();
        assert!(t.encoded().is_err());
        let mut t = base.clone();
        t.nonce = "0x01020304050607".into();
        assert!(t.encoded().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000000000000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:vip180:0x0000000000000000000000000000456e65726779");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "vetWei": "1",
            "blockRef": base.block_ref, "expiration": 720, "gasPriceCoef": 0,
            "gas": 21000, "nonce": base.nonce, "data": "00"
        });
        assert!(serde_json::from_value::<VechainTx>(extra).is_err());
        let coef = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "vetWei": "1",
            "blockRef": base.block_ref, "expiration": 720, "gasPriceCoef": 256,
            "gas": 21000, "nonce": base.nonce
        });
        assert!(serde_json::from_value::<VechainTx>(coef).is_err());
    }
}
