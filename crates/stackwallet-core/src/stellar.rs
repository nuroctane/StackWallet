//! Native XLM transfers. The core XDR-encodes the whole `TransactionEnvelope`
//! from checked fields: one `Payment` or `CreateAccount` operation, no memo,
//! no muxed accounts, a bounded fee and a bounded `maxTime`.

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const TESTNET: &str = "stellar:testnet";
pub const PUBNET: &str = "stellar:pubnet";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
/// StrKey version byte for an Ed25519 account id (`G…`).
const ACCOUNT_VERSION: u8 = 6 << 3;
const ENVELOPE_TYPE_TX: u32 = 2;
const PRECOND_TIME: u32 = 1;
const OP_CREATE_ACCOUNT: u32 = 0;
const OP_PAYMENT: u32 = 1;
/// The network's lowest inclusion fee per operation.
pub const MIN_FEE: u32 = 100;
/// 1 XLM; surge pricing beyond this is refused rather than silently paid.
pub const MAX_FEE: u32 = 10_000_000;
/// Two base reserves (0.5 XLM each): the minimum balance of a new account.
pub const MIN_STARTING_BALANCE: u64 = 10_000_000;
const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

const CRC16: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_XMODEM);

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Stellar transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Stellar testnet transfers are enabled"));
    }
    Ok(())
}

fn network_id(chain: &str) -> Result<[u8; 32]> {
    check_chain(chain)?;
    Ok(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into())
}

/// The Ed25519 public key behind a canonical `G…` StrKey. Muxed (`M…`) and
/// other key kinds are refused.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() != 56 || !address.starts_with('G') {
        return Err(invalid("address must be a 56-character G… account id"));
    }
    let raw = data_encoding::BASE32_NOPAD
        .decode(address.as_bytes())
        .map_err(|_| invalid("invalid base32 address"))?;
    if raw.len() != 35 || raw[0] != ACCOUNT_VERSION {
        return Err(invalid("not a Stellar account id"));
    }
    let crc = CRC16.checksum(&raw[..33]).to_le_bytes();
    if raw[33..] != crc {
        return Err(invalid("address checksum mismatch"));
    }
    let key: [u8; 32] = raw[1..33].try_into().expect("32 bytes");
    // base32 of 35 bytes leaves trailing bits; a non-canonical spelling must not alias.
    if encode_address(&key) != address {
        return Err(invalid("non-canonical address"));
    }
    Ok(key)
}

pub fn encode_address(key: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(35);
    raw.push(ACCOUNT_VERSION);
    raw.extend_from_slice(key);
    let crc = CRC16.checksum(&raw).to_le_bytes();
    raw.extend_from_slice(&crc);
    data_encoding::BASE32_NOPAD.encode(&raw)
}

pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    Ok(encode_address(&key))
}

fn canonical_u64(value: &str, what: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} is not a decimal integer")))?;
    if n == 0 || n > i64::MAX as u64 || n.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a positive canonical int64"
        )));
    }
    Ok(n)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StellarTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal stroops (1 XLM = 10,000,000 stroops); never a JSON floating-point number.
    pub stroops: String,
    /// Total fee bid in stroops for the single operation.
    pub fee: u32,
    /// Decimal int64: the source account's current sequence number plus one.
    pub seq_num: String,
    /// Unix seconds after which the network refuses the transaction.
    pub max_time: u64,
    /// Unix seconds the transaction was built; bounds `max_time`, not encoded.
    pub built_at: u64,
    /// `CreateAccount` for a destination that does not exist yet, else `Payment`.
    pub create_account: bool,
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

impl StellarTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native XLM transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.stroops {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Stellar intent")),
        }
        self.tx_xdr()?;
        Ok(())
    }

    /// XDR of the `Transaction` (envelope v1 body).
    pub fn tx_xdr(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u64(&self.stroops, "amount")?;
        if self.create_account && amount < MIN_STARTING_BALANCE {
            return Err(invalid("a new account must start with at least 1 XLM"));
        }
        let seq = canonical_u64(&self.seq_num, "sequence number")?;
        if !(MIN_FEE..=MAX_FEE).contains(&self.fee) {
            return Err(invalid("fee is outside the accepted range"));
        }
        if self.built_at == 0
            || self.max_time <= self.built_at
            || self.max_time - self.built_at > MAX_LIFETIME_SECS
        {
            return Err(invalid("maxTime must fall within a day of the build time"));
        }

        let mut out = Vec::with_capacity(160);
        // sourceAccount: MuxedAccount KEY_TYPE_ED25519
        put_u32(&mut out, 0);
        out.extend_from_slice(&from);
        put_u32(&mut out, self.fee);
        put_u64(&mut out, seq);
        // cond: PRECOND_TIME { minTime 0, maxTime }
        put_u32(&mut out, PRECOND_TIME);
        put_u64(&mut out, 0);
        put_u64(&mut out, self.max_time);
        // memo: MEMO_NONE
        put_u32(&mut out, 0);
        // operations<100>: exactly one, without its own source account
        put_u32(&mut out, 1);
        put_u32(&mut out, 0);
        if self.create_account {
            put_u32(&mut out, OP_CREATE_ACCOUNT);
            // destination: AccountID PUBLIC_KEY_TYPE_ED25519
            put_u32(&mut out, 0);
            out.extend_from_slice(&to);
            put_u64(&mut out, amount);
        } else {
            put_u32(&mut out, OP_PAYMENT);
            // destination: MuxedAccount KEY_TYPE_ED25519, asset: ASSET_TYPE_NATIVE
            put_u32(&mut out, 0);
            out.extend_from_slice(&to);
            put_u32(&mut out, 0);
            put_u64(&mut out, amount);
        }
        // ext: v0
        put_u32(&mut out, 0);
        Ok(out)
    }

    /// sha256(networkId || ENVELOPE_TYPE_TX || tx): both the signed message and the hash explorers show.
    pub fn hash(&self) -> Result<[u8; 32]> {
        let mut payload = network_id(&self.chain_id)?.to_vec();
        put_u32(&mut payload, ENVELOPE_TYPE_TX);
        payload.extend_from_slice(&self.tx_xdr()?);
        Ok(Sha256::digest(payload).into())
    }

    /// Returns the signed `TransactionEnvelope` as `0x` hex and the transaction hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if encode_address(&key.verifying_key().to_bytes()) != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let hash = self.hash()?;
        self.assemble(&key.sign(&hash).to_bytes())
    }

    /// The envelope for a signature made elsewhere (a threshold ceremony),
    /// accepted only if it verifies against the source account.
    pub fn assemble(&self, signature: &[u8; 64]) -> Result<(String, String)> {
        let hash = self.hash()?;
        let public = address_bytes(&self.from)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| invalid("source account is not an Ed25519 point"))?;
        key.verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the source account"))?;
        let mut wire = Vec::with_capacity(256);
        put_u32(&mut wire, ENVELOPE_TYPE_TX);
        wire.extend_from_slice(&self.tx_xdr()?);
        // signatures<20>: one DecoratedSignature { hint = last 4 key bytes, opaque<64> }
        put_u32(&mut wire, 1);
        wire.extend_from_slice(&public[28..]);
        put_u32(&mut wire, 64);
        wire.extend_from_slice(signature);
        Ok((format!("0x{}", hex::encode(wire)), hex::encode(hash)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// SEP-0005 test 1, m/44'/148'/0': GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6.
    const SEP5_SEED: &str = "SBGWSG6BTNCKCOB3DIFBGCVMUPQFYPA2G4O34RMTB343OYPXU5DJDVMN";
    const SEP5_ADDRESS: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    const RECIPIENT: &str = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";

    fn sender() -> String {
        let addr = encode_address(&SigningKey::from_bytes(&SECRET).verifying_key().to_bytes());
        // Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)) in @stellar/stellar-base.
        assert_eq!(
            addr,
            "GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57"
        );
        addr
    }

    fn tx() -> StellarTx {
        StellarTx {
            chain_id: TESTNET.into(),
            from: sender(),
            to: RECIPIENT.into(),
            stroops: "15000000".into(),
            fee: 1000,
            seq_num: "12000340488487103".into(),
            max_time: 1_760_001_800,
            built_at: 1_760_000_000,
            create_account: false,
        }
    }

    fn intent(tx: &StellarTx) -> TxIntent {
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
                amount: Amount(tx.stroops.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    fn sep5_secret() -> [u8; 32] {
        let raw = data_encoding::BASE32_NOPAD
            .decode(SEP5_SEED.as_bytes())
            .unwrap();
        assert_eq!(raw[0], 18 << 3);
        assert_eq!(raw[33..], CRC16.checksum(&raw[..33]).to_le_bytes());
        raw[1..33].try_into().unwrap()
    }

    #[test]
    fn address_matches_sep5_vector() {
        let key = SigningKey::from_bytes(&sep5_secret());
        let addr = address(&key.verifying_key().to_bytes()).unwrap();
        assert_eq!(addr, SEP5_ADDRESS);
        assert_eq!(encode_address(&address_bytes(&addr).unwrap()), addr);
        assert!(address(&[0u8; 33]).is_err());
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        // Flipped last character: checksum or trailing-bit mismatch.
        assert!(address_bytes("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ7").is_err());
        assert!(address_bytes(&SEP5_ADDRESS.to_lowercase()).is_err());
        assert!(address_bytes(SEP5_SEED).is_err());
        // Muxed account ids are refused.
        assert!(address_bytes(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
        )
        .is_err());
        assert!(address_bytes("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").is_err());
    }

    #[test]
    fn signature_verifies_over_the_hash() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let body = t.tx_xdr().unwrap();
        assert_eq!(wire[..4], ENVELOPE_TYPE_TX.to_be_bytes());
        assert_eq!(wire[4..4 + body.len()], body[..]);
        let rest = &wire[4 + body.len()..];
        assert_eq!(rest.len(), 4 + 4 + 4 + 64);
        let public = SigningKey::from_bytes(&SECRET).verifying_key();
        assert_eq!(rest[4..8], public.to_bytes()[28..]);
        assert_eq!(rest[8..12], 64u32.to_be_bytes());
        let sig = ed25519_dalek::Signature::from_slice(&rest[12..]).unwrap();
        public.verify_strict(&t.hash().unwrap(), &sig).unwrap();
        assert_eq!(id, hex::encode(t.hash().unwrap()));
        assert!(t.assemble(&[0u8; 64]).is_err());
    }

    /// Checked against `@stellar/stellar-base` (TransactionBuilder + Keypair.sign)
    /// for the same fields; the TypeScript adapter asserts the same bytes.
    #[test]
    fn envelope_matches_the_sdk_vectors() {
        let payment = StellarTx {
            from: SEP5_ADDRESS.into(),
            ..tx()
        };
        assert_eq!(hex::encode(payment.tx_xdr().unwrap()), PAYMENT_TX_VECTOR);
        assert_eq!(hex::encode(payment.hash().unwrap()), PAYMENT_HASH_VECTOR);
        let (wire, _) = payment.sign(&sep5_secret()).unwrap();
        assert_eq!(wire, format!("0x{PAYMENT_ENVELOPE_VECTOR}"));
        let create = StellarTx {
            create_account: true,
            ..payment
        };
        assert_eq!(hex::encode(create.tx_xdr().unwrap()), CREATE_TX_VECTOR);
        assert_eq!(hex::encode(create.hash().unwrap()), CREATE_HASH_VECTOR);
    }
    const PAYMENT_TX_VECTOR: &str = "00000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544000003e8002aa23f000000bf0000000100000000000000000000000068e77f080000000000000001000000000000000100000000416edcd6746d5293579a7039ac67bcf1a8698efecf81183bbb0ac877da86ada3000000000000000000e4e1c000000000";
    const PAYMENT_HASH_VECTOR: &str =
        "88d9fbc2c101be1878861eb98a16048e1e361806f377060656d5caaabf56447a";
    const PAYMENT_ENVELOPE_VECTOR: &str = "0000000200000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544000003e8002aa23f000000bf0000000100000000000000000000000068e77f080000000000000001000000000000000100000000416edcd6746d5293579a7039ac67bcf1a8698efecf81183bbb0ac877da86ada3000000000000000000e4e1c000000000000000014e71e54400000040d06acccf6cf7550e2dd025a45fe1ad7305fa59e2744867f4e5c137c79b82a212218b2d42d978c551e5574254bae60a6fbe253c4f9d7f6b9f403ceba35e557b00";
    const CREATE_TX_VECTOR: &str = "00000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e544000003e8002aa23f000000bf0000000100000000000000000000000068e77f080000000000000001000000000000000000000000416edcd6746d5293579a7039ac67bcf1a8698efecf81183bbb0ac877da86ada30000000000e4e1c000000000";
    const CREATE_HASH_VECTOR: &str =
        "c9e0562066e29902d425f2453c7c08a1a351b05f9c7af8a428ab7d6fa04c8db9";

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = PUBNET.into();
        assert!(t.tx_xdr().is_err());
        assert!(check_chain(PUBNET).is_err());
        let mut t = base.clone();
        t.stroops = "015000000".into();
        assert!(t.tx_xdr().is_err());
        let mut t = base.clone();
        t.stroops = "0".into();
        assert!(t.tx_xdr().is_err());
        let mut t = base.clone();
        t.stroops = "9223372036854775808".into();
        assert!(t.tx_xdr().is_err());
        let mut t = base.clone();
        t.stroops = "9999999".into();
        t.create_account = true;
        assert!(t.tx_xdr().is_err());
        t.stroops = "10000000".into();
        assert!(t.tx_xdr().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.tx_xdr().is_err());
        let mut t = base.clone();
        t.fee = 99;
        assert!(t.tx_xdr().is_err());
        t.fee = MAX_FEE + 1;
        assert!(t.tx_xdr().is_err());
        let mut t = base.clone();
        t.max_time = t.built_at + MAX_LIFETIME_SECS + 1;
        assert!(t.tx_xdr().is_err());
        t.max_time = t.built_at;
        assert!(t.tx_xdr().is_err());
        let mut t = base.clone();
        t.seq_num = "0".into();
        assert!(t.tx_xdr().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "15000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = SEP5_ADDRESS.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = SEP5_ADDRESS.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "stroops": "1",
            "fee": 100, "seqNum": "2", "maxTime": 2, "builtAt": 1,
            "createAccount": false, "memo": "hi"
        });
        assert!(serde_json::from_value::<StellarTx>(extra).is_err());
    }
}
