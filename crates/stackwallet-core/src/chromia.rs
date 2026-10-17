//! Chromia (Postchain) native-token transfers on the FT4 economy chain.
//!
//! Accounts are 32-byte FT4 account ids: `gtv_hash(pubkey)` for a single-sig
//! account, which for a lone byte-array leaf is `sha256(0x01 || gtv(pubkey))`
//! (merkle hash v1 and v2 coincide here). Transactions are GTX bodies
//! `[blockchain_rid, ops, signers]` encoded with GTV (DER-embedded ASN.1),
//! hashed with the GTV merkle scheme (version 2 on both live networks) and
//! signed with plain secp256k1 ECDSA (`r || s`, 64 bytes) per signer.
//! GTX has no fee, gas or expiry fields; a `nop` op carrying a random nonce
//! keeps repeated transfers distinct because the tx rid hashes every op.
//!
//! Byte-level reference: postchain-client 2.1.5 and @chromia/ft4 2.1.0
//! (oracles in `.nur/chromia-oracle`, vectors pinned in tests below).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// CAIP-2 style reference: `chromia:` + first 8 bytes of the economy chain BRID.
pub const TESTNET: &str = "chromia:0x090bcd47149fbb66";
const TESTNET_BRID: [u8; 32] =
    hex_literal_32("090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874");
/// Native tCHR asset on the testnet economy chain (6 decimals).
const TESTNET_ASSET: [u8; 32] =
    hex_literal_32("9ef73a786a66f435b3b40e72f5e9d85a4b09815997e087c809913e1e7ec686b4");
/// Sanity bound above the mainnet CHR total supply (978,064,789 CHR).
const MAX_UCHR: u64 = 1_000_000_000_000_000;

const fn hex_literal_32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = match b[i * 2] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        };
        let lo = match b[i * 2 + 1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        };
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Chromia transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Chromia testnet transfers are enabled"));
    }
    Ok(())
}

fn chain_params(chain: &str) -> Result<([u8; 32], [u8; 32])> {
    check_chain(chain)?;
    Ok((TESTNET_BRID, TESTNET_ASSET))
}

/// A 32-byte account id / nonce / pubkey fragment as 64 lowercase hex chars.
fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

/// The FT4 account id of a single-sig account: `sha256(0x01 || gtv(pubkey))`.
pub fn address(public: &[u8]) -> Result<String> {
    if public.len() != 33 || (public[0] != 2 && public[0] != 3) {
        return Err(invalid(
            "expected a 33-byte compressed secp256k1 public key",
        ));
    }
    // Validate the point so a garbage key cannot alias an account.
    k256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("invalid secp256k1 point"))?;
    Ok(hex::encode(account_id(
        &public.try_into().expect("33 bytes"),
    )))
}

fn account_id(pubkey: &[u8; 33]) -> [u8; 32] {
    // A lone leaf hashes identically under merkle versions 1 and 2.
    let mut preimage = vec![HASH_PREFIX_LEAF];
    preimage.extend(encode(&Gtv::Bytes(pubkey.to_vec())));
    Sha256::digest(preimage).into()
}

fn account_id_of(address: &str) -> Result<[u8; 32]> {
    let id = fixed_hex::<32>(address, "account id")?;
    if id == [0; 32] {
        return Err(invalid("zero account id"));
    }
    Ok(id)
}

fn parse_amount(uchr: &str) -> Result<u64> {
    let amount: u64 = uchr
        .parse()
        .map_err(|_| invalid("amount exceeds u64 micro-CHR"))?;
    if amount == 0 || amount > MAX_UCHR || amount.to_string() != uchr {
        return Err(invalid("amount must be a positive canonical integer"));
    }
    Ok(amount)
}

// ---------------------------------------------------------------------------
// GTV encoding (DER): explicit context tags over NULL/OCTET STRING/UTF8/INTEGER
// and SEQUENCE OF; dict keys sorted. Mirrors @chromia/asn1 `rawGTV`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Gtv {
    Null,
    Bytes(Vec<u8>),
    Str(String),
    Int(u64),
    BigInt(u64),
    Array(Vec<Gtv>),
}

fn tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut n = Vec::new();
        let mut v = len;
        while v > 0 {
            n.push((v & 0xff) as u8);
            v >>= 8;
        }
        n.reverse();
        out.push(0x80 | n.len() as u8);
        out.extend_from_slice(&n);
    }
    out.extend_from_slice(content);
}

fn der_integer(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    let mut content = Vec::new();
    if bytes[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes);
    let mut out = Vec::new();
    tlv(&mut out, 0x02, &content);
    out
}

fn encode(value: &Gtv) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        Gtv::Null => tlv(&mut out, 0xa0, &[0x05, 0x00]),
        Gtv::Bytes(b) => {
            let mut inner = Vec::new();
            tlv(&mut inner, 0x04, b);
            tlv(&mut out, 0xa1, &inner);
        }
        Gtv::Str(s) => {
            let mut inner = Vec::new();
            tlv(&mut inner, 0x0c, s.as_bytes());
            tlv(&mut out, 0xa2, &inner);
        }
        Gtv::Int(v) => {
            let inner = der_integer(*v);
            tlv(&mut out, 0xa3, &inner);
        }
        Gtv::BigInt(v) => {
            let inner = der_integer(*v);
            tlv(&mut out, 0xa6, &inner);
        }
        Gtv::Array(items) => {
            let mut inner = Vec::new();
            for item in items {
                inner.extend(encode(item));
            }
            let mut seq = Vec::new();
            tlv(&mut seq, 0x30, &inner);
            tlv(&mut out, 0xa5, &seq);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// GTV merkle hash (version 2), mirroring merklehashts 1.0.5:
// leaves sha256(0x01 || gtv(value)); plain nodes prefix 0x00; array/dict
// roots prefix 0x07/0x08; empty subtrees are 32 zero bytes.
// ---------------------------------------------------------------------------

const HASH_PREFIX_NODE: u8 = 0;
const HASH_PREFIX_LEAF: u8 = 1;
const HASH_PREFIX_NODE_ARRAY: u8 = 7;

#[derive(Debug, Clone, PartialEq)]
enum Tree {
    Empty,
    Leaf(Gtv),
    Node {
        array_root: bool,
        left: Box<Tree>,
        right: Box<Tree>,
    },
}

impl Tree {
    fn node(left: Tree, right: Tree) -> Tree {
        Tree::Node {
            array_root: false,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    fn array_wrap(left: Tree, right: Tree) -> Tree {
        Tree::Node {
            array_root: true,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

fn build_higher_layer(mut level: Vec<Tree>) -> Tree {
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut it = level.into_iter();
        while let Some(left) = it.next() {
            match it.next() {
                Some(right) => next.push(Tree::node(left, right)),
                // An odd element carries up unpaired.
                None => next.push(left),
            }
        }
        level = next;
    }
    level.into_iter().next().expect("non-empty layer")
}

fn build_tree(value: &Gtv) -> Tree {
    let items = match value {
        Gtv::Array(items) => items,
        leaf => return Tree::Leaf(leaf.clone()),
    };
    if items.is_empty() {
        return Tree::array_wrap(Tree::Empty, Tree::Empty);
    }
    let leaves: Vec<Tree> = items.iter().map(build_tree).collect();
    if leaves.len() == 1 && matches!(leaves[0], Tree::Node { .. }) {
        let only = leaves.into_iter().next().expect("one");
        return Tree::array_wrap(only, Tree::Empty);
    }
    let root = if leaves.len() == 1 {
        leaves.into_iter().next().expect("one")
    } else {
        build_higher_layer(leaves)
    };
    match root {
        Tree::Node { left, right, .. } => Tree::array_wrap(*left, *right),
        leaf => Tree::array_wrap(leaf, Tree::Empty),
    }
}

fn merkle_hash(tree: &Tree) -> [u8; 32] {
    match tree {
        Tree::Empty => [0u8; 32],
        Tree::Leaf(value) => {
            let mut preimage = vec![HASH_PREFIX_LEAF];
            preimage.extend(encode(value));
            Sha256::digest(preimage).into()
        }
        Tree::Node {
            array_root,
            left,
            right,
        } => {
            let prefix = if *array_root {
                HASH_PREFIX_NODE_ARRAY
            } else {
                HASH_PREFIX_NODE
            };
            let mut preimage = vec![prefix];
            preimage.extend(merkle_hash(left));
            preimage.extend(merkle_hash(right));
            Sha256::digest(preimage).into()
        }
    }
}

fn gtv_hash(value: &Gtv) -> [u8; 32] {
    merkle_hash(&build_tree(value))
}

// ---------------------------------------------------------------------------
// GTX bodies
// ---------------------------------------------------------------------------

fn op(name: &str, args: Vec<Gtv>) -> Gtv {
    Gtv::Array(vec![Gtv::Str(name.to_string()), Gtv::Array(args)])
}

/// The single-sig auth descriptor registration GTV: [0, [["A","T"], signer], null].
/// The economy chain mandates both flags (A = account, T = transfer).
fn auth_descriptor(pubkey: &[u8; 33]) -> Gtv {
    Gtv::Array(vec![
        Gtv::Int(0),
        Gtv::Array(vec![
            Gtv::Array(vec![Gtv::Str("A".into()), Gtv::Str("T".into())]),
            Gtv::Bytes(pubkey.to_vec()),
        ]),
        Gtv::Null,
    ])
}

fn signer_of(signer: &str) -> Result<[u8; 33]> {
    let pubkey = fixed_hex::<33>(signer, "signer public key")?;
    if pubkey[0] != 2 && pubkey[0] != 3 {
        return Err(invalid("signer must be a compressed secp256k1 public key"));
    }
    k256::PublicKey::from_sec1_bytes(&pubkey)
        .map_err(|_| invalid("signer is not a secp256k1 point"))?;
    Ok(pubkey)
}

fn body_gtv(brid: &[u8; 32], ops: Vec<Gtv>, pubkey: &[u8; 33]) -> Gtv {
    Gtv::Array(vec![
        Gtv::Bytes(brid.to_vec()),
        Gtv::Array(ops),
        Gtv::Array(vec![Gtv::Bytes(pubkey.to_vec())]),
    ])
}

/// Signs the GTX body merkle root and returns (wire hex, tx rid hex).
fn sign_body(body: &Gtv, secret: &[u8; 32], expect_pubkey: &[u8; 33]) -> Result<(String, String)> {
    let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
        .map_err(|_| invalid("invalid signing key"))?;
    let public = key.verifying_key().to_encoded_point(true);
    let pubkey: [u8; 33] = public.as_bytes().try_into().expect("33 bytes");
    if &pubkey != expect_pubkey {
        return Err(invalid("signer differs from signing key"));
    }
    let txid = gtv_hash(body);
    let (_parity, r, s) = evm::sign_digest(secret, &txid)?;
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&s);
    let wire = encode(&Gtv::Array(vec![
        body.clone(),
        Gtv::Array(vec![Gtv::Bytes(signature)]),
    ]));
    Ok((hex::encode(wire), hex::encode(txid)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChromiaTx {
    pub chain_id: String,
    /// 32-byte FT4 account id of the sender, lowercase hex.
    pub from: String,
    /// 33-byte compressed secp256k1 public key of the sender, lowercase hex.
    pub signer: String,
    /// 32-byte FT4 account id of the recipient, lowercase hex.
    pub to: String,
    /// Decimal micro-CHR (1 CHR = 1,000,000 uchr); never a JSON float.
    pub uchr: String,
    /// 32 random bytes, lowercase hex; carried by a `nop` op for tx uniqueness.
    pub nonce: String,
}

struct TransferFields {
    brid: [u8; 32],
    asset: [u8; 32],
    signer: [u8; 33],
    to: [u8; 32],
    nonce: [u8; 32],
    amount: u64,
}

impl ChromiaTx {
    fn checked_fields(&self) -> Result<TransferFields> {
        let (brid, asset) = chain_params(&self.chain_id)?;
        let from = account_id_of(&self.from)?;
        let to = account_id_of(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let signer = signer_of(&self.signer)?;
        if account_id(&signer) != from {
            return Err(invalid("signer does not own the sender account id"));
        }
        let amount = parse_amount(&self.uchr)?;
        let nonce = fixed_hex::<32>(&self.nonce, "nonce")?;
        if nonce == [0; 32] {
            return Err(invalid("nonce must be random, not zero"));
        }
        Ok(TransferFields {
            brid,
            asset,
            signer,
            to,
            nonce,
            amount,
        })
    }

    fn body(&self) -> Result<(Gtv, [u8; 33])> {
        let f = self.checked_fields()?;
        // Authenticated transfer layout, as ft4 sessions build it: the auth op
        // precedes the transfer and `nop` salts the tx for uniqueness.
        let from = account_id_of(&self.from)?;
        let ad_id = gtv_hash(&auth_descriptor(&f.signer));
        let ops = vec![
            op(
                "ft4.ft_auth",
                vec![Gtv::Bytes(from.to_vec()), Gtv::Bytes(ad_id.to_vec())],
            ),
            op(
                "ft4.transfer",
                vec![
                    Gtv::Bytes(f.to.to_vec()),
                    Gtv::Bytes(f.asset.to_vec()),
                    Gtv::BigInt(f.amount),
                ],
            ),
            op("nop", vec![Gtv::Bytes(f.nonce.to_vec())]),
        ];
        Ok((body_gtv(&f.brid, ops, &f.signer), f.signer))
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native CHR transfers are enabled"));
                }
                if account_id_of(to)? != account_id_of(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.uchr {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Chromia intent")),
        }
        self.body()?;
        Ok(())
    }

    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(gtv_hash(&self.body()?.0))
    }

    /// Returns the serialized signed GTX (posted as octet-stream) and the tx rid.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let (body, signer) = self.body()?;
        let (wire, txid) = sign_body(&body, secret, &signer)?;
        if account_id(&signer) != account_id_of(&self.from)? {
            return Err(invalid("sender differs from signing key"));
        }
        Ok((wire, txid))
    }
}

/// Claims the pending inbound transfer(s) of a not-yet-registered account and
/// creates it with a single-sig transfer auth descriptor. Moves no funds out:
/// it can only claim transfers already addressed to this account id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChromiaRegisterTx {
    pub chain_id: String,
    /// 32-byte FT4 account id being registered, lowercase hex.
    pub from: String,
    /// 33-byte compressed secp256k1 public key of the account, lowercase hex.
    pub signer: String,
    /// Always true; keeps the untagged ledger enum unambiguous.
    pub register: bool,
}

impl ChromiaRegisterTx {
    fn body(&self) -> Result<(Gtv, [u8; 33])> {
        let (brid, _asset) = chain_params(&self.chain_id)?;
        if !self.register {
            return Err(invalid("register flag must be true"));
        }
        let from = account_id_of(&self.from)?;
        let signer = signer_of(&self.signer)?;
        if account_id(&signer) != from {
            return Err(invalid("signer does not own the account id"));
        }
        let ops = vec![
            op(
                "ft4.ras_transfer_open",
                vec![auth_descriptor(&signer), Gtv::Null],
            ),
            op("ft4.register_account", vec![]),
        ];
        Ok((body_gtv(&brid, ops, &signer), signer))
    }

    /// Registration is a self-claim: it matches only a native transfer intent
    /// whose destination is the account itself.
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native CHR self-claims are enabled"));
                }
                if account_id_of(to)? != account_id_of(&self.from)? {
                    return Err(invalid("registration only claims transfers to itself"));
                }
                if amount.0 != "0" {
                    return Err(invalid("registration moves no spendable amount"));
                }
            }
            _ => return Err(invalid("unsupported Chromia registration intent")),
        }
        self.body()?;
        Ok(())
    }

    pub fn txid(&self) -> Result<[u8; 32]> {
        Ok(gtv_hash(&self.body()?.0))
    }

    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let (body, signer) = self.body()?;
        sign_body(&body, secret, &signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    const PUBKEY: &str = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";
    const ACCOUNT: &str = "40e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122";

    fn tx() -> ChromiaTx {
        ChromiaTx {
            chain_id: TESTNET.into(),
            from: ACCOUNT.into(),
            signer: PUBKEY.into(),
            to: "aa".repeat(32),
            uchr: "1500000".into(),
            nonce: "11".repeat(32),
        }
    }

    fn register_tx() -> ChromiaRegisterTx {
        ChromiaRegisterTx {
            chain_id: TESTNET.into(),
            from: ACCOUNT.into(),
            signer: PUBKEY.into(),
            register: true,
        }
    }

    fn intent(tx: &ChromiaTx) -> TxIntent {
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
                amount: Amount(tx.uchr.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    /// postchain-client 2.1.5: sha256(0x01 || gtv(pubkey)) for private key 7.
    #[test]
    fn account_id_matches_the_sdk_vector() {
        let pubkey = hex::decode(PUBKEY).unwrap();
        assert_eq!(address(&pubkey).unwrap(), ACCOUNT);
        assert!(address(&pubkey[..32]).is_err());
        let mut bad = pubkey.clone();
        bad[0] = 4; // uncompressed SEC1 is not accepted
        assert!(address(&bad).is_err());
    }

    /// The whole body encoding, merkle v2 tx rid and RFC6979 signature are
    /// pinned byte for byte against postchain-client (see .nur/chromia-oracle).
    #[test]
    fn transfer_matches_the_sdk_vector() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (body, _) = t.body().unwrap();
        assert_eq!(hex::encode(encode(&body)), BODY_VECTOR);
        assert_eq!(hex::encode(t.txid().unwrap()), TXID_VECTOR);
        let (wire, txid) = t.sign(&SECRET).unwrap();
        assert_eq!(txid, TXID_VECTOR);
        assert_eq!(wire, WIRE_VECTOR);
    }

    #[test]
    fn registration_matches_the_sdk_vector() {
        let r = register_tx();
        let (body, _) = r.body().unwrap();
        assert_eq!(hex::encode(encode(&body)), REG_BODY_VECTOR);
        let (wire, txid) = r.sign(&SECRET).unwrap();
        assert_eq!(txid, REG_TXID_VECTOR);
        assert_eq!(wire, REG_WIRE_VECTOR);
    }

    #[test]
    fn signature_recovers_to_the_signer() {
        let t = tx();
        let (_, txid) = t.sign(&SECRET).unwrap();
        let sig_bytes = hex::decode(&WIRE_VECTOR[WIRE_VECTOR.len() - 128..]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let digest = hex::decode(txid).unwrap();
        // No recovery id on Chromia; both parities must include our key.
        let mut found = false;
        for parity in [false, true] {
            if let Ok(key) = VerifyingKey::recover_from_prehash(
                &digest,
                &sig,
                k256::ecdsa::RecoveryId::new(parity, false),
            ) {
                if hex::encode(key.to_encoded_point(true).as_bytes()) == PUBKEY {
                    found = true;
                }
            }
        }
        assert!(found);
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "chromia:0x15c0ca99bee60a3b".into(); // mainnet refused for now
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.uchr = "0".into();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.uchr = "01500000".into();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.uchr = "1000000000000001".into();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.to = base.from.clone();
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.to = "AA".repeat(32);
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.nonce = "00".repeat(32);
        assert!(t.body().is_err());
        let mut t = base.clone();
        t.signer = PUBKEY[..64].into(); // truncated pubkey
        assert!(t.body().is_err());
        // A different valid key does not own the sender account id.
        let key2 = k256::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let other_pub = hex::encode(key2.verifying_key().to_encoded_point(true).as_bytes());
        let mut t = base.clone();
        t.signer = other_pub.clone();
        assert!(t.body().is_err());
        // sign() refuses a key that is not the declared signer.
        assert!(base.sign(&[8u8; 32]).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut reg = register_tx();
        reg.register = false;
        assert!(reg.body().is_err());
        let reg = register_tx();
        let mut ri = intent(&tx());
        if let TxIntentKind::Transfer { to, amount, .. } = &mut ri.kind {
            *to = ACCOUNT.into();
            amount.0 = "0".into();
        }
        reg.check_matches_intent(&ri).unwrap();
        if let TxIntentKind::Transfer { amount, .. } = &mut ri.kind {
            amount.0 = "1".into();
        }
        assert!(reg.check_matches_intent(&ri).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": ACCOUNT, "signer": PUBKEY,
            "to": "aa".repeat(32), "uchr": "1", "nonce": "11".repeat(32),
            "memo": "00"
        });
        assert!(serde_json::from_value::<ChromiaTx>(extra).is_err());
    }

    // Vectors generated by postchain-client 2.1.5 / @chromia/ft4 2.1.0
    // (.nur/chromia-oracle/oracle3.cjs) and accepted by the live testnet
    // economy chain on 2026-04-20 (execution rejected only on account state:
    // "Account not found" / "No pending transfer" — auth, flags and signature
    // passed the node).
    const BODY_VECTOR: &str = "a58201503082014ca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a581fc3081f9a55d305ba20d0c0b6674342e66745f61757468a54a3048a122042040e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122a1220420e0463c0b221e1498aae3631e413e135288aa13cab1dd72e5fe2f501bc3613bcba5653063a20e0c0c6674342e7472616e73666572a551304fa1220420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12204209ef73a786a66f435b3b40e72f5e9d85a4b09815997e087c809913e1e7ec686b4a605020316e360a531302fa2050c036e6f70a5263024a12204201111111111111111111111111111111111111111111111111111111111111111a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";
    const TXID_VECTOR: &str = "67d8fd5597f0d50c152655010140be38fd6444cea8c630e8e5200b0091af0006";
    const WIRE_VECTOR: &str = "a58201a03082019ca58201503082014ca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a581fc3081f9a55d305ba20d0c0b6674342e66745f61757468a54a3048a122042040e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122a1220420e0463c0b221e1498aae3631e413e135288aa13cab1dd72e5fe2f501bc3613bcba5653063a20e0c0c6674342e7472616e73666572a551304fa1220420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12204209ef73a786a66f435b3b40e72f5e9d85a4b09815997e087c809913e1e7ec686b4a605020316e360a531302fa2050c036e6f70a5263024a12204201111111111111111111111111111111111111111111111111111111111111111a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa5463044a1420440be8a7acd0f86775d4568b4c091fdeb4e2db6546c6ddb5293fbf967420d981cd776407de6af5bf1a5815db87ac20f9d02c735ff004cb079391c2547275b67d93e";
    const REG_BODY_VECTOR: &str = "a581df3081dca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a5818c308189a5673065a2170c156674342e7261735f7472616e736665725f6f70656ea54a3048a5423040a303020100a5353033a50c300aa2030c0141a2030c0154a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa0020500a0020500a51e301ca2160c146674342e72656769737465725f6163636f756e74a5023000a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";
    const REG_TXID_VECTOR: &str =
        "e73776b378023517a0640ed5dac5059c4ab047f3189e481dcdc3c84eeeb56cf0";
    const REG_WIRE_VECTOR: &str = "a582012e3082012aa581df3081dca1220420090bcd47149fbb66f02489372e88a454e7a5645adde82125d40df1ef0c76f874a5818c308189a5673065a2170c156674342e7261735f7472616e736665725f6f70656ea54a3048a5423040a303020100a5353033a50c300aa2030c0141a2030c0154a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa0020500a0020500a51e301ca2160c146674342e72656769737465725f6163636f756e74a5023000a5273025a123042102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fa5463044a1420440cb0d0ef924e7f6a359e61ddc9fd1f00020816f5ace6b733923cda7d7fad4ae826640d16f36018b8ed6118afcc4c13e5895667f4f6e2643a8c5c5320fe460afec";
}
