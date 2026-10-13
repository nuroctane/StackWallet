//! EVM transactions as the core sees them. The adapter proposes the fields;
//! the core serializes them itself (EIP-1559, RLP), checks that they do what
//! the intent says, computes the digest it signs, and produces the raw signed
//! bytes. A buggy or hostile adapter can therefore change gas and nonce but
//! not who gets paid or how much.

use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// `transfer(address,uint256)`
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const MAX_GAS_LIMIT: u64 = 30_000_000;
const MAX_DATA_BYTES: usize = 128 * 1024;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "evm transaction",
        reason: reason.into(),
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Numbers: decimal strings in, minimal big-endian bytes out
// ---------------------------------------------------------------------------

/// A non-negative decimal integer below 2^256 as minimal big-endian bytes
/// (zero is the empty string, as RLP wants).
pub fn decimal_to_be(dec: &str) -> Result<Vec<u8>> {
    if dec.is_empty() || dec.len() > 78 || !dec.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!("not a decimal integer: {dec:?}")));
    }
    let mut out: Vec<u8> = Vec::new();
    for d in dec.bytes() {
        let mut carry = u32::from(d - b'0');
        for byte in out.iter_mut().rev() {
            let v = u32::from(*byte) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let first = out.iter().position(|b| *b != 0).unwrap_or(out.len());
    let out = out[first..].to_vec();
    if out.len() > 32 {
        return Err(invalid("integer does not fit in 256 bits"));
    }
    Ok(out)
}

fn u64_be(n: u64) -> Vec<u8> {
    let b = n.to_be_bytes();
    let first = b.iter().position(|x| *x != 0).unwrap_or(8);
    b[first..].to_vec()
}

fn be_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn pad32(be: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(be);
    out
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    &b[first..]
}

// ---------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------

fn rlp_len_prefix(len: usize, short: u8, long: u8) -> Vec<u8> {
    if len <= 55 {
        vec![short + len as u8]
    } else {
        let lb = u64_be(len as u64);
        let mut out = vec![long + lb.len() as u8];
        out.extend(lb);
        out
    }
}

pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_len_prefix(b.len(), 0x80, 0xb7);
    out.extend_from_slice(b);
    out
}

pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = rlp_len_prefix(payload.len(), 0xc0, 0xf7);
    out.extend(payload);
    out
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

pub fn parse_address(s: &str) -> Result<[u8; 20]> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| invalid(format!("address {s:?} needs 0x")))?;
    let v = hex::decode(body).map_err(|_| invalid(format!("address {s:?} is not hex")))?;
    v.try_into()
        .map_err(|_| invalid(format!("address {s:?} is not 20 bytes")))
}

/// EIP-55 mixed-case spelling.
pub fn checksum_address(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = hex::encode(keccak256(lower.as_bytes()));
    let mut out = String::from("0x");
    for (c, h) in lower.chars().zip(hash.chars()) {
        if c.is_ascii_alphabetic() && h.to_digit(16).unwrap_or(0) >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn address_from_public(sec1: &[u8]) -> Result<[u8; 20]> {
    let pk = k256::PublicKey::from_sec1_bytes(sec1).map_err(|_| invalid("bad public key"))?;
    let point = pk.to_encoded_point(false);
    let h = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The transaction
// ---------------------------------------------------------------------------

/// Unsigned EIP-1559 transaction. Amounts are decimal strings in wei.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: String,
    pub max_fee_per_gas: String,
    pub gas_limit: u64,
    pub to: String,
    pub value: String,
    #[serde(default)]
    pub data_hex: String,
}

impl EvmTx {
    fn data(&self) -> Result<Vec<u8>> {
        let body = self.data_hex.strip_prefix("0x").unwrap_or(&self.data_hex);
        let v = hex::decode(body).map_err(|_| invalid("data is not hex"))?;
        if v.len() > MAX_DATA_BYTES {
            return Err(invalid("data too large"));
        }
        Ok(v)
    }

    pub fn validate(&self) -> Result<()> {
        parse_address(&self.to)?;
        self.data()?;
        let prio = decimal_to_be(&self.max_priority_fee_per_gas)?;
        let max = decimal_to_be(&self.max_fee_per_gas)?;
        decimal_to_be(&self.value)?;
        if be_cmp(&prio, &max) == std::cmp::Ordering::Greater {
            return Err(invalid("priority fee exceeds max fee"));
        }
        if self.gas_limit < 21_000 || self.gas_limit > MAX_GAS_LIMIT {
            return Err(invalid("gas limit out of range"));
        }
        if self.chain_id == 0 {
            return Err(invalid("chain id is zero"));
        }
        Ok(())
    }

    fn fields(&self) -> Result<Vec<Vec<u8>>> {
        Ok(vec![
            rlp_bytes(&u64_be(self.chain_id)),
            rlp_bytes(&u64_be(self.nonce)),
            rlp_bytes(&decimal_to_be(&self.max_priority_fee_per_gas)?),
            rlp_bytes(&decimal_to_be(&self.max_fee_per_gas)?),
            rlp_bytes(&u64_be(self.gas_limit)),
            rlp_bytes(&parse_address(&self.to)?),
            rlp_bytes(&decimal_to_be(&self.value)?),
            rlp_bytes(&self.data()?),
            rlp_list(&[]),
        ])
    }

    /// `0x02 || rlp(fields)`: what gets hashed and signed.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = vec![0x02];
        out.extend(rlp_list(&self.fields()?));
        Ok(out)
    }

    pub fn sighash(&self) -> Result<[u8; 32]> {
        Ok(keccak256(&self.signing_payload()?))
    }

    /// Raw signed transaction, as `eth_sendRawTransaction` takes it.
    pub fn encode_signed(&self, y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<u8>> {
        let mut fields = self.fields()?;
        fields.push(rlp_bytes(&u64_be(u64::from(y_parity))));
        fields.push(rlp_bytes(strip_zeros(r)));
        fields.push(rlp_bytes(strip_zeros(s)));
        let mut out = vec![0x02];
        out.extend(rlp_list(&fields));
        Ok(out)
    }

    /// Fee ceiling in wei: gas limit times max fee, as big-endian bytes.
    pub fn max_fee_wei(&self) -> Result<Vec<u8>> {
        let max = decimal_to_be(&self.max_fee_per_gas)?;
        let mut acc = vec![0u8; max.len() + 8];
        let gas = self.gas_limit;
        let mut carry: u128 = 0;
        for i in (0..max.len()).rev() {
            let v = u128::from(max[i]) * u128::from(gas) + carry;
            acc[i + 8] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        for i in (0..8).rev() {
            acc[i] = (carry & 0xff) as u8;
            carry >>= 8;
        }
        Ok(strip_zeros(&acc).to_vec())
    }
}

/// `${chainId}:erc20:0x…` names a token contract; `${chainId}:native` the gas asset.
pub fn erc20_of(asset: &str, chain_id: &str) -> Option<String> {
    asset
        .strip_prefix(chain_id)
        .and_then(|rest| rest.strip_prefix(":erc20:"))
        .map(str::to_owned)
}

pub fn erc20_transfer_data(to: &str, amount: &str) -> Result<Vec<u8>> {
    let mut data = ERC20_TRANSFER_SELECTOR.to_vec();
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&parse_address(to)?);
    data.extend_from_slice(&pad32(&decimal_to_be(amount)?));
    Ok(data)
}

/// EVM networks the core signs on. Mainnets stay disabled until the EVM
/// support gates in `docs/SECURITY.md` pass, exactly as for the other families:
/// a chain id here can never move funds of value.
pub const SIGNING_TESTNETS: &[u64] = &[
    11_155_111, // Sepolia
    17_000,     // Holesky
    560_048,    // Hoodi
    84_532,     // Base Sepolia
    11_155_420, // OP Sepolia
    421_614,    // Arbitrum Sepolia
    80_002,     // Polygon Amoy
];

/// Refuse any EVM chain that is not a known testnet.
pub fn check_chain(chain_id: &str) -> Result<()> {
    let n = eip155_number(chain_id)?;
    if !SIGNING_TESTNETS.contains(&n) {
        return Err(invalid(format!(
            "EVM signing is enabled on testnets only; {chain_id} is not one"
        )));
    }
    Ok(())
}

/// The numeric chain id of a CAIP-2 `eip155:<n>` id.
pub fn eip155_number(chain_id: &str) -> Result<u64> {
    chain_id
        .strip_prefix("eip155:")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| invalid(format!("{chain_id} is not an eip155 chain")))
}

fn same_address(a: &str, b: &str) -> Result<bool> {
    Ok(parse_address(a)? == parse_address(b)?)
}

/// Refuse any transaction whose destination, value or calldata differs from
/// what the intent asked for. Gas, fees and nonce are the adapter's to choose.
pub fn check_matches_intent(tx: &EvmTx, intent: &TxIntent) -> Result<()> {
    tx.validate()?;
    if tx.chain_id != eip155_number(&intent.chain_id.0)? {
        return Err(invalid("chain id differs from the intent"));
    }
    let data = tx.data()?;
    let value = decimal_to_be(&tx.value)?;
    match &intent.kind {
        TxIntentKind::Transfer { to, asset, amount } => {
            let native = format!("{}:native", intent.chain_id.0);
            if asset.0 == native {
                if !same_address(&tx.to, to)? {
                    return Err(invalid("destination differs from the intent"));
                }
                if value != decimal_to_be(&amount.0)? {
                    return Err(invalid("value differs from the intent"));
                }
                if !data.is_empty() {
                    return Err(invalid("a native transfer carries no calldata"));
                }
            } else if let Some(token) = erc20_of(&asset.0, &intent.chain_id.0) {
                if !same_address(&tx.to, &token)? {
                    return Err(invalid("token contract differs from the intent"));
                }
                if !value.is_empty() {
                    return Err(invalid("a token transfer sends no native value"));
                }
                if data != erc20_transfer_data(to, &amount.0)? {
                    return Err(invalid(
                        "calldata is not transfer(to, amount) for the intent",
                    ));
                }
            } else {
                return Err(invalid(format!("unsupported asset {}", asset.0)));
            }
        }
        TxIntentKind::ContractCall {
            to,
            data_hex,
            value: v,
        } => {
            if !same_address(&tx.to, to)? {
                return Err(invalid("contract differs from the intent"));
            }
            let want = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex))
                .map_err(|_| invalid("intent calldata is not hex"))?;
            if data != want {
                return Err(invalid("calldata differs from the intent"));
            }
            if value != decimal_to_be(&v.0)? {
                return Err(invalid("value differs from the intent"));
            }
        }
        _ => return Err(invalid("this intent kind has no EVM form yet")),
    }
    Ok(())
}

/// Signature over `sighash` with low-S normalization; returns (y parity, r, s).
pub fn sign_digest(secret: &[u8; 32], sighash: &[u8; 32]) -> Result<(u8, [u8; 32], [u8; 32])> {
    let key = SigningKey::from_bytes(secret.into()).map_err(|_| CoreError::Crypto("ecdsa key"))?;
    let (sig, recid): (EcdsaSignature, RecoveryId) = key
        .sign_prehash_recoverable(sighash)
        .map_err(|_| CoreError::Crypto("ecdsa sign"))?;
    let (sig, recid) = match sig.normalize_s() {
        Some(low) => (
            low,
            RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced()),
        ),
        None => (sig, recid),
    };
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Ok((recid.to_byte() & 1, r, s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::VerifyingKey;

    const HARDHAT_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn rlp_reference_vectors() {
        assert_eq!(rlp_bytes(b"dog"), hex::decode("83646f67").unwrap());
        assert_eq!(
            rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")]),
            hex::decode("c88363617483646f67").unwrap()
        );
        assert_eq!(rlp_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        assert_eq!(rlp_bytes(&u64_be(15)), vec![0x0f]);
        assert_eq!(rlp_bytes(&u64_be(1024)), vec![0x82, 0x04, 0x00]);
        let long = vec![b'a'; 56];
        assert_eq!(&rlp_bytes(&long)[..2], &[0xb8, 56]);
    }

    #[test]
    fn decimals() {
        assert_eq!(decimal_to_be("0").unwrap(), Vec::<u8>::new());
        assert_eq!(decimal_to_be("256").unwrap(), vec![1, 0]);
        assert_eq!(
            hex::encode(decimal_to_be("1000000000000000000").unwrap()),
            "0de0b6b3a7640000"
        );
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(decimal_to_be(max).unwrap(), vec![0xff; 32]);
        assert!(decimal_to_be(
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
        )
        .is_err());
        assert!(decimal_to_be("-1").is_err());
        assert!(decimal_to_be("1e18").is_err());
    }

    #[test]
    fn address_from_well_known_key() {
        let key = SigningKey::from_slice(&hex::decode(HARDHAT_KEY).unwrap()).unwrap();
        let sec1 = key.verifying_key().to_encoded_point(true);
        assert_eq!(
            checksum_address(&address_from_public(sec1.as_bytes()).unwrap()),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
    }

    fn tx() -> EvmTx {
        EvmTx {
            chain_id: 11155111,
            nonce: 7,
            max_priority_fee_per_gas: "1500000000".into(),
            max_fee_per_gas: "30000000000".into(),
            gas_limit: 21000,
            to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".into(),
            value: "1000000000000000".into(),
            data_hex: String::new(),
        }
    }

    #[test]
    fn signature_recovers_to_the_signer() {
        let t = tx();
        let h = t.sighash().unwrap();
        let secret: [u8; 32] = hex::decode(HARDHAT_KEY).unwrap().try_into().unwrap();
        let (v, r, s) = sign_digest(&secret, &h).unwrap();
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&r);
        rs[32..].copy_from_slice(&s);
        let sig = EcdsaSignature::from_slice(&rs).unwrap();
        assert!(sig.normalize_s().is_none(), "low-S");
        let rec = VerifyingKey::recover_from_prehash(&h, &sig, RecoveryId::from_byte(v).unwrap())
            .unwrap();
        let addr = address_from_public(rec.to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(
            checksum_address(&addr),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        let raw = t.encode_signed(v, &r, &s).unwrap();
        assert_eq!(raw[0], 0x02);
        assert_eq!(
            t.max_fee_wei().unwrap(),
            decimal_to_be("630000000000000").unwrap()
        );
    }

    fn intent(kind: TxIntentKind) -> TxIntent {
        TxIntent {
            id: "t".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId("eip155:11155111".into()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind,
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn transactions_must_match_their_intent() {
        let native = intent(TxIntentKind::Transfer {
            to: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".into(),
            asset: AssetRef("eip155:11155111:native".into()),
            amount: Amount("1000000000000000".into()),
        });
        assert!(check_matches_intent(&tx(), &native).is_ok());
        let mut other = tx();
        other.to = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".into();
        assert!(check_matches_intent(&other, &native).is_err());
        let mut more = tx();
        more.value = "2000000000000000".into();
        assert!(check_matches_intent(&more, &native).is_err());
        let mut wrong_chain = tx();
        wrong_chain.chain_id = 1;
        assert!(check_matches_intent(&wrong_chain, &native).is_err());

        let token = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
        let erc20 = intent(TxIntentKind::Transfer {
            to: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".into(),
            asset: AssetRef(format!("eip155:11155111:erc20:{token}")),
            amount: Amount("5000000".into()),
        });
        let mut t = tx();
        t.to = token.into();
        t.value = "0".into();
        t.gas_limit = 65000;
        t.data_hex = hex::encode(
            erc20_transfer_data("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "5000000").unwrap(),
        );
        assert!(check_matches_intent(&t, &erc20).is_ok());
        t.data_hex = hex::encode(
            erc20_transfer_data("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", "5000000").unwrap(),
        );
        assert!(
            check_matches_intent(&t, &erc20).is_err(),
            "swapped recipient"
        );
    }

    #[test]
    fn validation_bounds() {
        let mut t = tx();
        t.max_priority_fee_per_gas = "40000000000".into();
        assert!(t.validate().is_err());
        let mut t = tx();
        t.gas_limit = 20_999;
        assert!(t.validate().is_err());
        let mut t = tx();
        t.to = "0x1234".into();
        assert!(t.validate().is_err());
    }
}
