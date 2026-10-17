//! Native-token transfers on Antelope (EOSIO lineage) chains. The core packs a
//! one-action transaction (`eosio.token::transfer` with the chain's system
//! token) from checked fields, signs `sha256(chain_id || packed_trx || 0^32)`
//! with a canonical recoverable secp256k1 signature and returns the
//! `push_transaction` body plus the transaction id, `sha256(packed_trx)`.
//!
//! Antelope accounts are on-chain names, not key hashes. The key the core
//! holds is linked to an account through that account's permissions, which
//! only the chain knows. The core therefore identifies a signer by its
//! `PUB_K1_…` public key; `from` and `permission` are names the adapter looked
//! up on chain, and the chain refuses the transaction if the key does not
//! satisfy `from@permission`.

use k256::ecdsa::hazmat::SignPrimitive;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// A network the core may sign for. Every value that ends up in the signed
/// bytes or the signing digest is pinned here rather than taken from the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub caip2: &'static str,
    /// Full 32-byte chain id; CAIP-2 carries only its first 16 bytes.
    pub chain_id: &'static str,
    pub symbol: &'static str,
    pub precision: u8,
    pub token_contract: &'static str,
}

pub const WAX_TESTNET: &str = "antelope:f16b1833c747c43682f4386fca9cbb32";
pub const TESTNET: &str = WAX_TESTNET;
pub const JUNGLE4: &str = "antelope:73e4385a2708e6d7048834fbc1079f2f";
pub const VAULTA_MAINNET: &str = "antelope:aca376f206b8fc25a6ed44dbdc66547c";
pub const WAX_MAINNET: &str = "antelope:1064487b3cd1a897ce03ae5b6a865651";

// Mainnets stay disabled until the family's testnet and threshold gates pass.
// Jungle4 differs only in its constants; it is left out because its faucet is
// captcha-gated, so no live transfer could be run against it.
const SIGNING_NETWORKS: &[Network] = &[Network {
    caip2: WAX_TESTNET,
    chain_id: "f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12",
    symbol: "WAX",
    precision: 8,
    token_contract: "eosio.token",
}];

/// `asset.amount` is an int64 the token contract bounds to `2^62 - 1`.
pub const MAX_UNITS: u64 = (1 << 62) - 1;
/// `eosio.token::transfer` refuses longer memos.
pub const MAX_MEMO_BYTES: usize = 256;
/// The default `max_transaction_lifetime` of every production chain.
pub const MAX_LIFETIME_SECS: u32 = 3_600;
const MAX_SIGN_ATTEMPTS: u8 = 64;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Antelope transfer",
        reason: reason.into(),
    }
}

pub fn network(chain: &str) -> Result<&'static Network> {
    SIGNING_NETWORKS
        .iter()
        .find(|n| n.caip2 == chain)
        .ok_or_else(|| invalid("only WAX testnet transfers are enabled"))
}

pub fn check_chain(chain: &str) -> Result<()> {
    network(chain).map(|_| ())
}

fn char_value(c: u8) -> Option<u64> {
    match c {
        b'.' => Some(0),
        b'1'..=b'5' => Some(u64::from(c - b'1') + 1),
        b'a'..=b'z' => Some(u64::from(c - b'a') + 6),
        _ => None,
    }
}

/// The u64 behind an account or permission name: up to 12 characters of
/// `.12345a-z`, five bits each from the top, with no trailing dot (which would
/// alias the shorter name). 13-character names are refused; no account uses one.
pub fn name_value(name: &str) -> Result<u64> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 12 || bytes.ends_with(b".") {
        return Err(invalid(
            "name must be 1 to 12 characters without a trailing dot",
        ));
    }
    let mut value = 0u64;
    for (i, c) in bytes.iter().enumerate() {
        let v = char_value(*c).ok_or_else(|| invalid("name may use only a-z, 1-5 and '.'"))?;
        value |= v << (64 - 5 * (i + 1));
    }
    Ok(value)
}

pub fn is_valid_account(name: &str) -> bool {
    name_value(name).is_ok()
}

fn ripemd_check(payload: &[u8], suffix: &[u8]) -> [u8; 4] {
    let mut h = Ripemd160::new();
    h.update(payload);
    h.update(suffix);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

fn encode_k1(prefix: &str, payload: &[u8]) -> String {
    let mut raw = payload.to_vec();
    raw.extend_from_slice(&ripemd_check(payload, b"K1"));
    format!("{prefix}{}", bs58::encode(raw).into_string())
}

/// The `PUB_K1_…` form of a secp256k1 public key (always the compressed point).
pub fn address(public: &[u8]) -> Result<String> {
    let key = k256::PublicKey::from_sec1_bytes(public)
        .map_err(|_| invalid("invalid secp256k1 public key"))?;
    Ok(encode_k1("PUB_K1_", key.to_encoded_point(true).as_bytes()))
}

/// The compressed point behind a canonical `PUB_K1_…` key. Legacy `EOS…` keys
/// are refused here; the adapter converts them before they reach the core.
pub fn public_key_bytes(key: &str) -> Result<[u8; 33]> {
    let body = key
        .strip_prefix("PUB_K1_")
        .ok_or_else(|| invalid("public key must be PUB_K1_"))?;
    let raw = bs58::decode(body)
        .into_vec()
        .map_err(|_| invalid("public key is not base58"))?;
    if raw.len() != 37 || raw[33..] != ripemd_check(&raw[..33], b"K1") {
        return Err(invalid("public key checksum mismatch"));
    }
    let point: [u8; 33] = raw[..33].try_into().expect("33 bytes");
    if address(&point)? != key {
        return Err(invalid("non-canonical public key"));
    }
    Ok(point)
}

fn varuint(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// eosio's "is_canonical": both scalars are 32 bytes with no sign bit and no
/// redundant leading zero. Older nodes refuse anything else, and the official
/// libraries retry signing until it holds, so the core does the same.
fn is_canonical(sig: &[u8; 64]) -> bool {
    let (r, s) = (&sig[..32], &sig[32..]);
    r[0] & 0x80 == 0
        && !(r[0] == 0 && r[1] & 0x80 == 0)
        && s[0] & 0x80 == 0
        && !(s[0] == 0 && s[1] & 0x80 == 0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AntelopeTx {
    pub chain_id: String,
    /// Sending account name; the adapter found it linked to `public_key`.
    pub from: String,
    /// Permission of `from` that `public_key` satisfies, usually `active`.
    pub permission: String,
    pub to: String,
    /// Integer base units of the system token (`1.0000 EOS` is 10000 at precision 4).
    pub antelope_units: String,
    pub symbol: String,
    pub precision: u8,
    pub token_contract: String,
    /// User-entered memo; empty or at most 256 bytes without control characters.
    pub memo: String,
    /// Seconds since the epoch after which the chain refuses the transaction.
    pub expiration: u32,
    /// TaPoS reference: low 16 bits of a recent block number.
    pub ref_block_num: u16,
    /// TaPoS reference: bytes 8..12 of that block's id, little-endian.
    pub ref_block_prefix: u32,
    /// Head block time (seconds) the adapter built against; bounds `expiration`, not encoded.
    pub built_at_secs: u32,
    /// `PUB_K1_…` key of the signer; `sign` refuses any other key.
    pub public_key: String,
}

impl AntelopeTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native-token transfers are enabled"));
                }
                name_value(to)?;
                if *to != self.to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.antelope_units {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Antelope intent")),
        }
        self.packed()?;
        Ok(())
    }

    fn units(&self) -> Result<u64> {
        let units = self
            .antelope_units
            .parse::<u64>()
            .map_err(|_| invalid("amount is not a decimal integer"))?;
        if units == 0 || units > MAX_UNITS || units.to_string() != self.antelope_units {
            return Err(invalid("amount must be canonical positive base units"));
        }
        Ok(units)
    }

    fn check_memo(&self) -> Result<()> {
        if self.memo.len() > MAX_MEMO_BYTES {
            return Err(invalid("memo is longer than 256 bytes"));
        }
        // Bidirectional overrides would let a memo display differently from its bytes.
        let bidi = |c: char| matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if self.memo.chars().any(|c| c.is_control() || bidi(c)) {
            return Err(invalid("memo may not contain control characters"));
        }
        Ok(())
    }

    /// The `eosio.token::transfer` action data: from, to, quantity, memo.
    pub fn action_data(&self) -> Result<Vec<u8>> {
        let net = network(&self.chain_id)?;
        if self.symbol != net.symbol
            || self.precision != net.precision
            || self.token_contract != net.token_contract
        {
            return Err(invalid("token differs from the network's system token"));
        }
        let from = name_value(&self.from)?;
        let to = name_value(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let units = self.units()?;
        self.check_memo()?;
        let mut out = Vec::with_capacity(40 + self.memo.len());
        out.extend_from_slice(&from.to_le_bytes());
        out.extend_from_slice(&to.to_le_bytes());
        out.extend_from_slice(&units.to_le_bytes());
        let mut symbol = [0u8; 8];
        symbol[0] = self.precision;
        symbol[1..1 + self.symbol.len()].copy_from_slice(self.symbol.as_bytes());
        out.extend_from_slice(&symbol);
        // MAX_MEMO_BYTES keeps the length well inside u32.
        varuint(&mut out, self.memo.len() as u32);
        out.extend_from_slice(self.memo.as_bytes());
        Ok(out)
    }

    /// The packed `transaction`, byte for byte what `push_transaction` takes as `packed_trx`.
    pub fn packed(&self) -> Result<Vec<u8>> {
        let data = self.action_data()?;
        let permission = name_value(&self.permission)?;
        public_key_bytes(&self.public_key)?;
        if self.built_at_secs == 0
            || self.expiration <= self.built_at_secs
            || self.expiration - self.built_at_secs > MAX_LIFETIME_SECS
        {
            return Err(invalid(
                "expiration must fall within an hour of the build time",
            ));
        }
        let mut out = Vec::with_capacity(64 + data.len());
        out.extend_from_slice(&self.expiration.to_le_bytes());
        out.extend_from_slice(&self.ref_block_num.to_le_bytes());
        out.extend_from_slice(&self.ref_block_prefix.to_le_bytes());
        varuint(&mut out, 0); // max_net_usage_words
        out.push(0); // max_cpu_usage_ms
        varuint(&mut out, 0); // delay_sec
        varuint(&mut out, 0); // context_free_actions
        varuint(&mut out, 1); // actions
        out.extend_from_slice(&name_value(&self.token_contract)?.to_le_bytes());
        out.extend_from_slice(&name_value("transfer")?.to_le_bytes());
        varuint(&mut out, 1); // authorization
        out.extend_from_slice(&name_value(&self.from)?.to_le_bytes());
        out.extend_from_slice(&permission.to_le_bytes());
        varuint(&mut out, data.len() as u32);
        out.extend_from_slice(&data);
        varuint(&mut out, 0); // transaction_extensions
        Ok(out)
    }

    /// `sha256(packed_trx)`, the id explorers show.
    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.packed()?).into())
    }

    /// `sha256(chain_id || packed_trx || sha256-of-no-context-free-data)`; the
    /// last part is 32 zero bytes because the transaction carries none.
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let net = network(&self.chain_id)?;
        let chain = hex::decode(net.chain_id).expect("pinned chain id");
        let mut h = Sha256::new();
        h.update(chain);
        h.update(self.packed()?);
        h.update([0u8; 32]);
        Ok(h.finalize().into())
    }

    /// Returns the `push_transaction` JSON body and the transaction id (lowercase hex).
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key =
            SigningKey::from_bytes(secret.into()).map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.public_key {
            return Err(invalid("public key differs from signing key"));
        }
        let digest = self.signing_digest()?;
        let scalar: &k256::Scalar = key.as_nonzero_scalar().as_ref();
        // Same nonce schedule as the official libraries: RFC 6979 with the
        // attempt counter as extra data, until the signature is canonical.
        for attempt in 1..=MAX_SIGN_ATTEMPTS {
            let (sig, recid) = scalar
                .try_sign_prehashed_rfc6979::<Sha256>(&digest.into(), &[attempt])
                .map_err(|_| invalid("signing failed"))?;
            let rs: [u8; 64] = sig.to_bytes().into();
            if is_canonical(&rs) {
                let recid = recid.ok_or_else(|| invalid("signing failed"))?;
                return self.assemble_recoverable(&rs, recid);
            }
        }
        Err(invalid("no canonical signature found"))
    }

    /// The signed body for an `r || s` signature made elsewhere (a threshold
    /// ceremony). It must be low-S, eosio-canonical and verify against `publicKey`.
    pub fn assemble(&self, rs: &[u8; 64]) -> Result<(String, String)> {
        let digest = self.signing_digest()?;
        let expected = VerifyingKey::from_sec1_bytes(&public_key_bytes(&self.public_key)?)
            .map_err(|_| invalid("invalid public key"))?;
        let sig = Signature::from_slice(rs).map_err(|_| invalid("invalid signature"))?;
        for byte in 0..2u8 {
            let recid = RecoveryId::from_byte(byte).expect("valid id");
            if VerifyingKey::recover_from_prehash(&digest, &sig, recid).ok() == Some(expected) {
                return self.assemble_recoverable(rs, recid);
            }
        }
        Err(invalid("signature does not verify against the sender"))
    }

    fn assemble_recoverable(&self, rs: &[u8; 64], recid: RecoveryId) -> Result<(String, String)> {
        let sig = Signature::from_slice(rs).map_err(|_| invalid("invalid signature"))?;
        if sig.normalize_s().is_some() || !is_canonical(rs) {
            return Err(invalid("signature must be low-S and canonical"));
        }
        let expected = VerifyingKey::from_sec1_bytes(&public_key_bytes(&self.public_key)?)
            .map_err(|_| invalid("invalid public key"))?;
        let digest = self.signing_digest()?;
        if VerifyingKey::recover_from_prehash(&digest, &sig, recid).ok() != Some(expected) {
            return Err(invalid("signature does not recover the sender key"));
        }
        let mut compact = [0u8; 65];
        compact[0] = 27 + 4 + recid.to_byte();
        compact[1..].copy_from_slice(rs);
        let signature = encode_k1("SIG_K1_", &compact);
        let packed = self.packed()?;
        let body = serde_json::json!({
            "signatures": [signature],
            "compression": 0,
            "packed_context_free_data": "",
            "packed_trx": hex::encode(&packed),
        });
        Ok((body.to_string(), hex::encode(Sha256::digest(&packed))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    /// The eosio development key `5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3`.
    const DEV_SECRET: &str = "d2653ff7cbb2d8ff129ac27ef5781ce68b2558c41a74af1f2ddca635cbeef07d";
    /// Its published key `EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV` in K1 form (wharfkit).
    const DEV_PUBLIC: &str = "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63";
    const ONE_PUBLIC: &str = "PUB_K1_5p78kHbL33Rn3JWkTWRE2B9uz6gy4r1KbfAKLNQGE3ovLY8E9M";

    fn secret() -> [u8; 32] {
        hex::decode(DEV_SECRET).unwrap().try_into().unwrap()
    }

    fn tx() -> AntelopeTx {
        AntelopeTx {
            chain_id: TESTNET.into(),
            from: "stackwallet1".into(),
            permission: "active".into(),
            to: "swrecipient2".into(),
            antelope_units: "123456789".into(),
            symbol: "WAX".into(),
            precision: 8,
            token_contract: "eosio.token".into(),
            memo: String::new(),
            expiration: 1_792_152_000,
            ref_block_num: 0x1234,
            ref_block_prefix: 0xdead_beef,
            built_at_secs: 1_792_151_700,
            public_key: DEV_PUBLIC.into(),
        }
    }

    fn intent(tx: &AntelopeTx) -> TxIntent {
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
                amount: Amount(tx.antelope_units.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn keys_and_names_match_wharfkit() {
        let key = SigningKey::from_bytes((&secret()).into()).unwrap();
        let public = key.verifying_key().to_encoded_point(true);
        assert_eq!(address(public.as_bytes()).unwrap(), DEV_PUBLIC);
        let uncompressed = key.verifying_key().to_encoded_point(false);
        assert_eq!(address(uncompressed.as_bytes()).unwrap(), DEV_PUBLIC);
        let mut one = [0u8; 32];
        one[31] = 1;
        let g = SigningKey::from_bytes((&one).into()).unwrap();
        assert_eq!(
            address(g.verifying_key().to_encoded_point(true).as_bytes()).unwrap(),
            ONE_PUBLIC
        );
        assert_eq!(public_key_bytes(DEV_PUBLIC).unwrap(), public.as_bytes());
        for bad in [
            "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
            "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq64",
            "PUB_R1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63",
            "PUB_K1_",
        ] {
            assert!(public_key_bytes(bad).is_err(), "{bad}");
        }
        for (name, value) in [
            ("eosio.token", 6_138_663_591_592_764_928u64),
            ("transfer", 14_829_575_313_431_724_032),
            ("active", 3_617_214_756_542_218_240),
            ("stackwallet1", 14_288_945_735_872_983_568),
            ("a", 3_458_764_513_820_540_928),
            ("zzzzzzzzzzzz", 18_446_744_073_709_551_600),
            ("1.2.3.4.5", 577_588_303_627_812_864),
        ] {
            assert_eq!(name_value(name).unwrap(), value, "{name}");
        }
        for bad in [
            "",
            "Alice",
            "alice.",
            "abcdefghijklm",
            "a6",
            "a b",
            "a-b",
            "zzzzzzzzzzzzj",
        ] {
            assert!(name_value(bad).is_err(), "{bad}");
        }
    }

    /// Pinned to `@wharfkit/antelope` (`Serializer.encode`, `signingDigest`,
    /// `PrivateKey.signDigest`, `Transaction.id`) for the same fields
    /// (`.nur/antelope-sdk/vector.mjs`); the TypeScript adapter pins the same bytes.
    #[test]
    fn packed_digest_and_signature_match_wharfkit() {
        let t = tx();
        assert_eq!(hex::encode(t.action_data().unwrap()), ACTION_DATA);
        assert_eq!(hex::encode(t.packed().unwrap()), PACKED);
        assert_eq!(hex::encode(t.signing_digest().unwrap()), DIGEST);
        assert_eq!(hex::encode(t.txid().unwrap()), TXID);
        let (wire, id) = t.sign(&secret()).unwrap();
        assert_eq!(id, TXID);
        let body: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(body["signatures"][0], SIG);
        assert_eq!(body["packed_trx"], PACKED);
        assert_eq!(body["compression"], 0);
        assert_eq!(body["packed_context_free_data"], "");

        let memo = AntelopeTx {
            memo: "invoice 42".into(),
            ..tx()
        };
        assert_eq!(hex::encode(memo.packed().unwrap()), MEMO_PACKED);
        let (wire, id) = memo.sign(&secret()).unwrap();
        assert_eq!(id, MEMO_TXID);
        let body: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(body["signatures"][0], MEMO_SIG);
    }
    const ACTION_DATA: &str = "10b28ad170884cc620f254ae3aa42ec715cd5b0700000000085741580000000000";
    const PACKED: &str = "c011d26a3412efbeadde000000000100a6823403ea3055000000572d3ccdcd0110b28ad170884cc600000000a8ed32322110b28ad170884cc620f254ae3aa42ec715cd5b070000000008574158000000000000";
    const DIGEST: &str = "7745d93072e34b64d3fa22f9745f827f48a038aaa3c06086ab1d20482faee2d0";
    const TXID: &str = "e7ccc4604379fa1f6cdf092539ca64ccf3b661cd7cf2c919687fbbf5a34946c7";
    const SIG: &str = "SIG_K1_KVCinNw3R6tf3G6YPVa9NiaXGZQinm44vJ1PUsmADzpdfH334wau5JKfKBPd8nabSQKvmikimcS5R3LSvWCZZUaB3rAdXU";
    const MEMO_PACKED: &str = "c011d26a3412efbeadde000000000100a6823403ea3055000000572d3ccdcd0110b28ad170884cc600000000a8ed32322b10b28ad170884cc620f254ae3aa42ec715cd5b070000000008574158000000000a696e766f69636520343200";
    const MEMO_TXID: &str = "de2ea33d4fe18d369b947eea74e2d6f6f5df520fce08af4eb87335b5981bc92a";
    const MEMO_SIG: &str = "SIG_K1_JxQG57dcqEXL3jQ3XgeEBoRxHRCDmPULaoAciZ3tgdPQsJrsHiJoGZanoaXnX7PpdgXSvwmpxAPXg8QLdjVJpz13z1NXZc";

    #[test]
    fn signatures_recover_the_sender_and_assemble_checks_them() {
        let secret = [7u8; 32];
        let key = SigningKey::from_bytes((&secret).into()).unwrap();
        let t = AntelopeTx {
            public_key: address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap(),
            ..tx()
        };
        t.check_matches_intent(&intent(&t)).unwrap();
        let digest = t.signing_digest().unwrap();
        let (wire, id) = t.sign(&secret).unwrap();
        let body: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let sig = body["signatures"][0].as_str().unwrap();
        let raw = bs58::decode(sig.strip_prefix("SIG_K1_").unwrap())
            .into_vec()
            .unwrap();
        assert_eq!(raw.len(), 69);
        assert_eq!(raw[65..], ripemd_check(&raw[..65], b"K1"));
        assert!((31..=34).contains(&raw[0]));
        let rs: [u8; 64] = raw[1..65].try_into().unwrap();
        assert!(is_canonical(&rs));
        let recid = RecoveryId::from_byte(raw[0] - 31).unwrap();
        let s = Signature::from_slice(&rs).unwrap();
        assert_eq!(
            VerifyingKey::recover_from_prehash(&digest, &s, recid).unwrap(),
            *key.verifying_key()
        );
        assert_eq!(t.assemble(&rs).unwrap(), (wire, id));
        // A high-S twin and a signature by another key are refused.
        let (r, s_scalar) = s.split_scalars();
        let high = Signature::from_scalars(r.to_bytes(), (-*s_scalar).to_bytes()).unwrap();
        assert!(t.assemble(&high.to_bytes().into()).is_err());
        assert!(tx().assemble(&rs).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        base.check_matches_intent(&intent(&base)).unwrap();
        for chain in [
            JUNGLE4,
            VAULTA_MAINNET,
            WAX_MAINNET,
            "antelope:F16B1833C747C43682F4386FCA9CBB32",
            "eip155:1",
        ] {
            let mut t = base.clone();
            t.chain_id = chain.into();
            assert!(t.packed().is_err());
            assert!(check_chain(chain).is_err());
        }
        for units in ["0", "0123", "-1", "1.5", "4611686018427387904", ""] {
            let mut t = base.clone();
            t.antelope_units = units.into();
            assert!(t.packed().is_err(), "{units}");
        }
        let mut t = base.clone();
        t.antelope_units = MAX_UNITS.to_string();
        assert!(t.packed().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.packed().is_err());
        for (sym, prec, contract) in [
            ("EOS", 8, "eosio.token"),
            ("WAX", 4, "eosio.token"),
            ("WAX", 8, "fake.token"),
        ] {
            let mut t = base.clone();
            t.symbol = sym.into();
            t.precision = prec;
            t.token_contract = contract.into();
            assert!(t.packed().is_err(), "{sym} {prec} {contract}");
        }
        for name in ["", "Stackwallet1", "stackwallet1.", "stackwallet12x"] {
            let mut t = base.clone();
            t.to = name.into();
            assert!(t.packed().is_err(), "{name}");
            let mut t = base.clone();
            t.permission = name.into();
            assert!(t.packed().is_err(), "{name}");
        }
        let mut t = base.clone();
        t.memo = "x".repeat(MAX_MEMO_BYTES);
        assert!(t.packed().is_ok());
        t.memo = "x".repeat(MAX_MEMO_BYTES + 1);
        assert!(t.packed().is_err());
        t.memo = "line\nbreak".into();
        assert!(t.packed().is_err());
        t.memo = "\u{202e}".into();
        assert!(t.packed().is_err());
        t.memo = "café ✓".into();
        assert!(t.packed().is_ok());
        let mut t = base.clone();
        t.expiration = t.built_at_secs;
        assert!(t.packed().is_err());
        t.expiration = t.built_at_secs + MAX_LIFETIME_SECS + 1;
        assert!(t.packed().is_err());
        t.built_at_secs = 0;
        assert!(t.packed().is_err());
        let mut t = base.clone();
        t.public_key = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".into();
        assert!(t.packed().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "123456790".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "swrecipient3".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:token:eosio.token:WAX");
        }
        assert!(base.check_matches_intent(&i).is_err());
        assert!(base.sign(&[7u8; 32]).is_err());
        let ok = serde_json::json!({
            "chainId": TESTNET, "from": "stackwallet1", "permission": "active",
            "to": "swrecipient2", "antelopeUnits": "1", "symbol": "WAX", "precision": 8,
            "tokenContract": "eosio.token", "memo": "", "expiration": 1_792_152_000u32,
            "refBlockNum": 1, "refBlockPrefix": 2, "builtAtSecs": 1_792_151_700u32,
            "publicKey": DEV_PUBLIC
        });
        let parsed: AntelopeTx = serde_json::from_value(ok.clone()).unwrap();
        assert!(parsed.packed().is_ok());
        let mut extra = ok.clone();
        extra["data"] = serde_json::json!("00");
        assert!(serde_json::from_value::<AntelopeTx>(extra).is_err());
        let mut missing = ok;
        missing.as_object_mut().unwrap().remove("permission");
        assert!(serde_json::from_value::<AntelopeTx>(missing).is_err());
    }
}
