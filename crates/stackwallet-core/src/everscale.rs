//! Native transfers from an EverWallet contract on Everscale and Venom
//! (both TVM chains; the same wallet contract, code hash `3ba6528a…7b12a6`,
//! serves both networks, verified against live accounts on each).
//!
//! Keys come from BIP39 + SLIP-10 at `m/44'/396'/0'/0'/{i}'`, the path EVER
//! Wallet and Venom Wallet (nekoton) use for their accounts. The address is
//! the workchain-0 account id of the wallet StateInit: code + a 320-bit data
//! cell (256-bit public key, then the 64-bit replay-protection timestamp).
//! The layout is pinned against real on-chain EverWallet accounts.
//!
//! A transfer is an external inbound message to the wallet calling
//! `sendTransaction(dest, value, bounce, flags=3, payload=empty)`. The
//! Ed25519 signature covers the hash of a cell holding the wallet's own
//! address followed by the body bits after the signature (pubkey header,
//! time, expire, function id) plus the argument cell reference — exactly
//! what the contract's `recv_external` recomputes. The encoding is pinned
//! byte-for-byte against `nekoton-wasm` (the SDK behind both wallets).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// Venom testnet is the family's signing network (Everscale has no live
/// public testnet; Venom mainnet is read-only here like Everscale mainnet).
pub const TESTNET: &str = "venom:1002";
/// Everscale mainnet (zerostate global id 42, read live from a key block).
pub const EVER_MAINNET: &str = "ever:42";
/// Venom mainnet (global id 1, read live from a key block).
pub const VENOM_MAINNET: &str = "venom:1";

/// `sendTransaction` pays forward fees separately and ignores action errors.
pub const SEND_FLAGS: u8 = 3;
/// `sendTransaction(address,uint128,bool,uint8,cell)()v2` method id.
const SEND_TRANSACTION_ID: u32 = 0x4cee646c;
const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
/// How far behind the build time the `time` header may lag (clock skew).
const MAX_TIME_SKEW_MS: u64 = 5 * 60 * 1000;
const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
const BOC_MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

/// EverWallet code as published in `broxus/ever-wallet-contract`
/// (`dist/Wallet.code.boc`); its hash is checked by the tests and must match
/// the `code_hash` of every wallet this family sends from.
const EVER_WALLET_CODE: &str = "te6ccgEBBgEA/AABFP8A9KQT9LzyyAsBAgEgBQIC5vJx1wEBwADyeoMI1xjtRNCDB9cB1ws/yPgozxYjzxbJ+QADcdcBAcMAmoMH1wFRE7ry4GTegEDXAYAg1wGAINcBVBZ1+RDyqPgju/J5Zr74I4EHCKCBA+ioUiC8sfJ0AiCCEEzuZGy64w8ByMv/yz/J7VQEAwA+ghAWnj4Ruo4R+AACkyDXSpd41wHUAvsA6NGTMvI84gCYMALXTND6QIMG1wFx1wF41wHXTPgAcIAQBKoCFLHIywVQBc8WUAP6AstpItAhzzEh10mghAm5mDNwAcsAWM8WlzBxAcsAEsziyQH7AAAE0jA=";

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Everscale transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnets stay disabled until the family's mainnet and threshold gates pass.
    if chain != TESTNET {
        return Err(invalid("only Venom testnet transfers are enabled"));
    }
    Ok(())
}

// ---------------------------------------------------------------- cells

/// An ordinary cell: at most 1023 data bits and four references, with its
/// representation hash and depth computed once at construction.
#[derive(Debug)]
struct Cell {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<Rc<Cell>>,
    hash: [u8; 32],
    depth: u16,
}

impl Cell {
    fn new(data: Vec<u8>, bits: usize, refs: Vec<Rc<Cell>>) -> Result<Rc<Cell>> {
        if bits > 1023 || refs.len() > 4 || data.len() != bits.div_ceil(8) {
            return Err(invalid("cell overflow"));
        }
        let depth = match refs.iter().map(|r| r.depth).max() {
            Some(d) => d.checked_add(1).ok_or_else(|| invalid("cell too deep"))?,
            None => 0,
        };
        let mut repr = vec![refs.len() as u8, Self::bits_descriptor(bits)];
        repr.extend_from_slice(&Self::padded(&data, bits));
        for r in &refs {
            repr.extend_from_slice(&r.depth.to_be_bytes());
        }
        for r in &refs {
            repr.extend_from_slice(&r.hash);
        }
        Ok(Rc::new(Cell {
            data,
            bits,
            refs,
            hash: Sha256::digest(&repr).into(),
            depth,
        }))
    }

    fn bits_descriptor(bits: usize) -> u8 {
        (bits.div_ceil(8) + bits / 8) as u8
    }

    /// Data bytes with the completion tag (a 1 bit) after an incomplete last byte.
    fn padded(data: &[u8], bits: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        if !bits.is_multiple_of(8) {
            let last = out.len() - 1;
            out[last] |= 0x80 >> (bits % 8);
        }
        out
    }

    fn bit(&self, i: usize) -> bool {
        self.data[i / 8] & (0x80 >> (i % 8)) != 0
    }
}

#[derive(Default)]
struct Builder {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<Rc<Cell>>,
}

impl Builder {
    fn bit(&mut self, b: bool) -> &mut Self {
        if self.bits.is_multiple_of(8) {
            self.data.push(0);
        }
        if b {
            self.data[self.bits / 8] |= 0x80 >> (self.bits % 8);
        }
        self.bits += 1;
        self
    }

    fn uint(&mut self, v: u128, n: usize) -> &mut Self {
        debug_assert!(n == 128 || v >> n == 0);
        for i in (0..n).rev() {
            self.bit((v >> i) & 1 == 1);
        }
        self
    }

    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        for byte in b {
            self.uint(u128::from(*byte), 8);
        }
        self
    }

    /// `addr_std$10 anycast:nothing workchain_id:int8 address:bits256`.
    fn address(&mut self, workchain: i8, hash: &[u8; 32]) -> &mut Self {
        self.uint(0b10, 2)
            .bit(false)
            .uint(u128::from(workchain as u8), 8)
            .bytes(hash)
    }

    /// `VarUInteger 16`: a 4-bit byte length, then the big-endian value.
    fn coins(&mut self, v: u128) -> &mut Self {
        let len = (128 - v.leading_zeros() as usize).div_ceil(8);
        self.uint(len as u128, 4).uint(v, len * 8)
    }

    fn reference(&mut self, cell: Rc<Cell>) -> &mut Self {
        self.refs.push(cell);
        self
    }

    fn append(&mut self, cell: &Cell) -> &mut Self {
        for i in 0..cell.bits {
            self.bit(cell.bit(i));
        }
        self.refs.extend(cell.refs.iter().cloned());
        self
    }

    fn build(&mut self) -> Result<Rc<Cell>> {
        let b = std::mem::take(self);
        Cell::new(b.data, b.bits, b.refs)
    }
}

/// Deserializes a standard (`b5ee9c72`) bag of cells with one root and only ordinary cells.
fn parse_boc(src: &[u8]) -> Result<Rc<Cell>> {
    struct Reader<'a> {
        src: &'a [u8],
        pos: usize,
    }
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            let end = self.pos.checked_add(n).ok_or_else(bad)?;
            let s = self.src.get(self.pos..end).ok_or_else(bad)?;
            self.pos = end;
            Ok(s)
        }
        fn uint(&mut self, n: usize) -> Result<usize> {
            Ok(self
                .take(n)?
                .iter()
                .fold(0usize, |acc, x| (acc << 8) | usize::from(*x)))
        }
    }
    fn bad() -> CoreError {
        invalid("malformed bag of cells")
    }
    let mut r = Reader { src, pos: 0 };
    if r.take(4)? != BOC_MAGIC {
        return Err(bad());
    }
    let flags = r.take(1)?[0];
    let size = usize::from(flags & 7);
    if !(1..=4).contains(&size) || flags & 0x18 != 0 {
        return Err(bad());
    }
    let off = r.uint(1)?;
    if !(1..=8).contains(&off) {
        return Err(bad());
    }
    let count = r.uint(size)?;
    let roots = r.uint(size)?;
    let _absent = r.uint(size)?;
    let total = r.uint(off)?;
    let root = r.uint(size)?;
    if roots != 1 || count == 0 || count > 1024 || root != 0 {
        return Err(bad());
    }
    if flags & 0x80 != 0 {
        r.take(count * off)?;
    }
    let start = r.pos;
    let mut raw = Vec::with_capacity(count);
    for _ in 0..count {
        let d1 = r.take(1)?[0];
        let d2 = r.take(1)?[0];
        if d1 & 0xf8 != 0 || d1 & 7 > 4 {
            return Err(invalid("only ordinary cells are supported"));
        }
        let len = usize::from(d2).div_ceil(2);
        let mut data = r.take(len)?.to_vec();
        let mut bits = len * 8;
        if d2 % 2 == 1 {
            let last = data.last_mut().ok_or_else(bad)?;
            if *last == 0 {
                return Err(bad());
            }
            let tz = last.trailing_zeros() as usize;
            *last &= !(1u8 << tz);
            bits -= tz + 1;
        }
        let refs = (0..usize::from(d1 & 7))
            .map(|_| r.uint(size))
            .collect::<Result<Vec<_>>>()?;
        raw.push((data, bits, refs));
    }
    if r.pos - start != total {
        return Err(bad());
    }
    if flags & 0x40 != 0 {
        let end = r.pos;
        let crc = r.take(4)?;
        if CRC32C.checksum(&src[..end]).to_le_bytes() != crc {
            return Err(invalid("bag of cells checksum mismatch"));
        }
    }
    if r.pos != src.len() {
        return Err(bad());
    }
    let mut built: Vec<Option<Rc<Cell>>> = vec![None; count];
    for i in (0..count).rev() {
        let (data, bits, refs) = std::mem::take(&mut raw[i]);
        let refs = refs
            .iter()
            .map(|&r| {
                if r <= i {
                    return Err(bad());
                }
                built.get(r).cloned().flatten().ok_or_else(bad)
            })
            .collect::<Result<Vec<_>>>()?;
        built[i] = Some(Cell::new(data, bits, refs)?);
    }
    built[0].take().ok_or_else(bad)
}

/// The cell order `@ton/core` writes: breadth-first discovery, then a
/// depth-first post-order over refs in reverse, reversed. Matching it keeps
/// the serialized bytes identical between the core and the TypeScript side.
fn topological_sort(root: &Rc<Cell>) -> Vec<Rc<Cell>> {
    let mut cells: HashMap<[u8; 32], Rc<Cell>> = HashMap::new();
    let mut order: Vec<[u8; 32]> = Vec::new();
    let mut pending = vec![root.clone()];
    while !pending.is_empty() {
        for cell in std::mem::take(&mut pending) {
            if cells.contains_key(&cell.hash) {
                continue;
            }
            order.push(cell.hash);
            pending.extend(cell.refs.iter().cloned());
            cells.insert(cell.hash, cell);
        }
    }
    fn visit(
        hash: [u8; 32],
        cells: &HashMap<[u8; 32], Rc<Cell>>,
        open: &mut HashSet<[u8; 32]>,
        sorted: &mut Vec<[u8; 32]>,
    ) {
        if !open.contains(&hash) {
            return;
        }
        for r in cells[&hash].refs.iter().rev() {
            visit(r.hash, cells, open, sorted);
        }
        sorted.push(hash);
        open.remove(&hash);
    }
    let mut open: HashSet<[u8; 32]> = order.iter().copied().collect();
    let mut sorted = Vec::with_capacity(order.len());
    for hash in &order {
        visit(*hash, &cells, &mut open, &mut sorted);
    }
    sorted.iter().rev().map(|h| cells[h].clone()).collect()
}

fn byte_len(n: usize) -> usize {
    let bits = (usize::BITS - n.leading_zeros()) as usize;
    bits.div_ceil(8).max(1)
}

/// A one-root bag of cells with a CRC32C trailer and no index.
fn serialize_boc(root: &Rc<Cell>) -> Vec<u8> {
    let cells = topological_sort(root);
    let index: HashMap<[u8; 32], usize> =
        cells.iter().enumerate().map(|(i, c)| (c.hash, i)).collect();
    let size = byte_len(cells.len());
    let total: usize = cells
        .iter()
        .map(|c| 2 + c.data.len() + c.refs.len() * size)
        .sum();
    let off = byte_len(total);
    let be = |out: &mut Vec<u8>, v: usize, n: usize| {
        out.extend_from_slice(&(v as u64).to_be_bytes()[8 - n..]);
    };
    let mut out = BOC_MAGIC.to_vec();
    out.push(0x40 | size as u8);
    out.push(off as u8);
    be(&mut out, cells.len(), size);
    be(&mut out, 1, size);
    be(&mut out, 0, size);
    be(&mut out, total, off);
    be(&mut out, 0, size);
    for c in &cells {
        out.push(c.refs.len() as u8);
        out.push(Cell::bits_descriptor(c.bits));
        out.extend_from_slice(&Cell::padded(&c.data, c.bits));
        for r in &c.refs {
            be(&mut out, index[&r.hash], size);
        }
    }
    let crc = CRC32C.checksum(&out).to_le_bytes();
    out.extend_from_slice(&crc);
    out
}

// ---------------------------------------------------------------- wallet

/// Parses a raw workchain-0 address (`0:<64 lowercase hex>`).
pub fn parse_address(address: &str) -> Result<[u8; 32]> {
    let hex_part = address
        .strip_prefix("0:")
        .ok_or_else(|| invalid("address must be 0: and 64 hex digits"))?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("address must be 0: and 64 lowercase hex digits"));
    }
    hex::decode(hex_part)
        .map_err(|_| invalid("address is not hex"))?
        .try_into()
        .map_err(|_| invalid("address is not 32 bytes"))
}

fn wallet_code() -> Result<Rc<Cell>> {
    let boc = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, EVER_WALLET_CODE)
        .map_err(|_| invalid("wallet code constant"))?;
    parse_boc(&boc)
}

/// The wallet StateInit: code plus a 320-bit data cell (public key, then the
/// replay-protection timestamp, zero at deploy).
fn state_init(public: &[u8; 32]) -> Result<Rc<Cell>> {
    let data = Builder::default().bytes(public).uint(0, 64).build()?;
    // split_depth:none special:none code:just data:just library:empty
    Builder::default()
        .bit(false)
        .bit(false)
        .bit(true)
        .reference(wallet_code()?)
        .bit(true)
        .reference(data)
        .bit(false)
        .build()
}

/// The workchain-0 account id of the wallet for an Ed25519 key: the StateInit hash.
pub fn wallet_hash(public: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(state_init(public)?.hash)
}

/// The wallet address the core signs for: `0:<64 lowercase hex>`.
pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    Ok(format!("0:{}", hex::encode(wallet_hash(&key)?)))
}

// ---------------------------------------------------------------- transaction

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EverscaleTx {
    pub chain_id: String,
    /// The signer's EverWallet, exactly as `address()` spells it (`0:<hex>`).
    pub from: String,
    /// Workchain-0 `0:<hex>` address.
    pub to: String,
    /// Decimal nano units (1 EVER/VENOM = 10^9); never a JSON floating-point number.
    pub evers: String,
    /// The `time` ABI header: milliseconds, must exceed the wallet's stored
    /// timestamp (replay protection) and stay near the build time.
    pub time_ms: u64,
    /// The `expire` ABI header: unix seconds after which the wallet refuses.
    pub expire_at: u32,
    /// Unix milliseconds the transfer was built; bounds `time_ms` and `expire_at`.
    pub built_at_ms: u64,
    /// Bounce flag of the internal message; false for a recipient that is not active.
    pub bounce: bool,
    /// Attach the wallet's StateInit, deploying it with this first message.
    pub deploy: bool,
}

fn canonical_u64(value: &str, what: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} is not a decimal integer")))?;
    if n == 0 || n.to_string() != value {
        return Err(invalid(format!(
            "{what} must be a positive canonical integer"
        )));
    }
    Ok(n)
}

struct Checked {
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
}

impl EverscaleTx {
    fn checked(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = parse_address(&self.from)?;
        let to = parse_address(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u64(&self.evers, "amount")?;
        if self.built_at_ms == 0
            || self.time_ms < self.built_at_ms.saturating_sub(MAX_TIME_SKEW_MS)
            || self.time_ms > self.built_at_ms + MAX_LIFETIME_MS
        {
            return Err(invalid("timeMs must stay near the build time"));
        }
        let built_secs = self.built_at_ms / 1000;
        if self.expire_at as u64 <= built_secs
            || self.expire_at as u64 > built_secs + MAX_LIFETIME_MS / 1000
        {
            return Err(invalid("expireAt must fall within a day of the build time"));
        }
        Ok(Checked { from, to, amount })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        let checked = self.checked()?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native EVER/VENOM transfers are enabled"));
                }
                if parse_address(to)? != checked.to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.evers {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Everscale intent")),
        }
        Ok(())
    }

    /// The argument cell of `sendTransaction`: destination, value, bounce,
    /// send flags, and a reference to the (empty) payload cell.
    fn args_cell(&self, c: &Checked) -> Result<Rc<Cell>> {
        let payload = Builder::default().build()?;
        Builder::default()
            .address(0, &c.to)
            .uint(u128::from(c.amount), 128)
            .bit(self.bounce)
            .uint(u128::from(SEND_FLAGS), 8)
            .reference(payload)
            .build()
    }

    /// The body bits after the signature: pubkey header, time, expire, function id.
    fn body_tail(&self, public: &[u8; 32]) -> Builder {
        let mut b = Builder::default();
        b.bit(true)
            .bytes(public)
            .uint(self.time_ms as u128, 64)
            .uint(u128::from(self.expire_at), 32)
            .uint(u128::from(SEND_TRANSACTION_ID), 32);
        b
    }

    /// The cell the wallet contract hashes and checks the signature against:
    /// its own address, then the body after the signature, with the argument
    /// cell as the single reference.
    fn signing_cell(&self, public: &[u8; 32]) -> Result<Rc<Cell>> {
        let c = self.checked()?;
        let mut b = Builder::default();
        b.address(0, &c.from);
        let mut tail = self.body_tail(public);
        tail.reference(self.args_cell(&c)?);
        let tail = tail.build()?;
        b.append(&tail);
        b.build()
    }

    /// The 32-byte Ed25519 message for `public`'s wallet.
    pub fn signing_hash(&self, public: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(self.signing_cell(public)?.hash)
    }

    /// Signs as the wallet of `secret`; returns the external message BoC as
    /// `0x` hex and the message hash (what explorers and `getDstTransaction`
    /// resolve) as 64 lowercase hex.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let signature = key.sign(&self.signing_hash(&public)?).to_bytes();
        self.assemble(&public, &signature)
    }

    /// The external message for a signature made elsewhere (a threshold
    /// ceremony), accepted only if `public` owns `from` and the signature
    /// verifies over the signing hash the contract recomputes.
    pub fn assemble(&self, public: &[u8; 32], signature: &[u8; 64]) -> Result<(String, String)> {
        if address(public)? != self.from {
            return Err(invalid("public key does not own the sender wallet"));
        }
        let checked = self.checked()?;
        VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("public key is not an Ed25519 point"))?
            .verify_strict(
                &self.signing_hash(public)?,
                &ed25519_dalek::Signature::from_bytes(signature),
            )
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let mut body = Builder::default();
        body.bit(true).bytes(signature);
        let mut tail = self.body_tail(public);
        tail.reference(self.args_cell(&checked)?);
        let tail = tail.build()?;
        body.append(&tail);
        let body = body.build()?;
        let mut ext = Builder::default();
        // ext_in_msg_info$10 src:addr_none dest import_fee:0
        ext.uint(0b10, 2)
            .uint(0, 2)
            .address(0, &checked.from)
            .coins(0);
        if self.deploy {
            let init = state_init(public)?;
            // init inline (Either left), as nekoton lays it out
            ext.bit(true).bit(false).append(&init);
        } else {
            ext.bit(false);
        }
        if 1023 - ext.bits - 1 < body.bits || ext.refs.len() + body.refs.len() > 4 {
            ext.bit(true).reference(body);
        } else {
            ext.bit(false).append(&body);
        }
        let message = ext.build()?;
        Ok((
            format!("0x{}", hex::encode(serialize_boc(&message))),
            hex::encode(message.hash),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::{derive_ed25519, parse_path, Mnemonic};
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    const SENDER: &str = "0:252413205e86517432e0c2ab74a857b0d2e3369989cbef1df1f2c16a8b89ff09";
    const RECIPIENT: &str = "0:120094dedd73dfa077fe4bdaeb97e66455ca8ace3ed68b194979a1b78bc98ee5";
    const PUBLIC: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    fn tx() -> EverscaleTx {
        EverscaleTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            evers: "123456789".into(),
            time_ms: 1_792_159_903_042,
            expire_at: 1_792_159_963,
            built_at_ms: 1_792_159_903_042,
            bounce: false,
            deploy: false,
        }
    }

    fn deploy_tx() -> EverscaleTx {
        EverscaleTx {
            time_ms: 1_792_159_903_028,
            built_at_ms: 1_792_159_903_028,
            deploy: true,
            ..tx()
        }
    }

    fn intent(tx: &EverscaleTx) -> TxIntent {
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
                amount: Amount(tx.evers.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 1_792_159_903_042,
        }
    }

    #[test]
    fn addresses_match_the_on_chain_layout() {
        let code = wallet_code().unwrap();
        assert_eq!(
            hex::encode(code.hash),
            "3ba6528ab2694c118180aa3bd10dd19ff400b909ab4dcf58fc69925b2c7b12a6"
        );
        let public = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        assert_eq!(hex::encode(public), PUBLIC);
        assert_eq!(address(&public).unwrap(), SENDER);
        let nine = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(address(&nine).unwrap(), RECIPIENT);
        // A real EverWallet on Everscale mainnet: the StateInit of its code and
        // a zero-timestamp data cell for this key hashes to its account id
        // (verified against mainnet.evercloud.dev).
        let on_chain_key: [u8; 32] =
            hex::decode("25343c7251e5636db35fc769fb329615085be3c5858d523411daf1f4dbb24256")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            address(&on_chain_key).unwrap(),
            "0:a1c1fd9383ea500bfcbad0b2110700dd121c7e152c910f1311a0b40aa54a4088"
        );
        // SLIP-10 derivation on the nekoton path (same scheme `@ton/crypto` uses).
        let seed = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed("");
        let first = derive_ed25519(&*seed, &parse_path("m/44'/396'/0'/0'/0'").unwrap()).unwrap();
        assert_eq!(address(&first.public).unwrap().len(), 66);
        assert!(address(&public[..31]).is_err());
    }

    #[test]
    fn address_parsing_is_strict() {
        assert_eq!(
            parse_address(SENDER).unwrap(),
            wallet_hash(&hex::decode(PUBLIC).unwrap().try_into().unwrap()).unwrap()
        );
        assert!(
            parse_address("0:252413205e86517432e0c2ab74a857b0d2e3369989cbef1df1f2c16a8b89ff0")
                .is_err()
        );
        assert!(parse_address(
            "0:252413205e86517432e0c2ab74a857b0d2e3369989cbef1df1f2c16a8b89ff09ff"
        )
        .is_err());
        assert!(parse_address(
            "-1:252413205e86517432e0c2ab74a857b0d2e3369989cbef1df1f2c16a8b89ff09"
        )
        .is_err());
        assert!(parse_address(&SENDER.to_ascii_uppercase()).is_err());
        assert!(parse_address(
            "0:ZZ2413205e86517432e0c2ab74a857b0d2e3369989cbef1df1f2c16a8b89ff09"
        )
        .is_err());
        assert!(parse_address(&SENDER[2..]).is_err());
    }

    /// External messages built by `nekoton-wasm` `createExternalMessage` +
    /// `ed25519_sign` (`.nur/ever-ref/vectors-final.cjs`), rebuilt here from
    /// checked fields. Ed25519 is deterministic, so hashes and the signature
    /// match exactly; the TypeScript tests pin the same values. (The BoC bytes
    /// differ only in cell order; the message hash is equal.)
    #[test]
    fn messages_match_the_official_sdk() {
        let public = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        let t = tx();
        assert_eq!(
            hex::encode(t.signing_hash(&public).unwrap()),
            NODEPLOY_SIGNING_HASH
        );
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{NODEPLOY_BOC}"));
        assert_eq!(hash, NODEPLOY_MSG_HASH);
        // The signature is the one the SDK produced.
        let root = parse_boc(&hex::decode(NODEPLOY_BOC).unwrap()).unwrap();
        let body = root.refs[0].clone();
        let sig: Vec<u8> = (1..513)
            .step_by(8)
            .map(|i| (0..8).fold(0u8, |a, k| (a << 1) | u8::from(body.bit(i + k))))
            .collect();
        assert_eq!(hex::encode(sig), NODEPLOY_SIGNATURE);
        let d = deploy_tx();
        assert_eq!(
            hex::encode(d.signing_hash(&public).unwrap()),
            DEPLOY_SIGNING_HASH
        );
        let (wire, hash) = d.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{DEPLOY_BOC}"));
        assert_eq!(hash, DEPLOY_MSG_HASH);
        // The SDK's own BoC (different cell order) parses to the same message.
        let sdk = parse_boc(
            &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, NODEPLOY_SDK_BOC)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(sdk.hash), NODEPLOY_MSG_HASH);
        let mut corrupt = hex::decode(NODEPLOY_BOC).unwrap();
        corrupt[20] ^= 1;
        assert!(parse_boc(&corrupt).is_err());
    }
    const NODEPLOY_SIGNING_HASH: &str =
        "755186d7281139e94388bd5c6bd82330b255b3cbae5db409235a14ddf7f77085";
    const NODEPLOY_MSG_HASH: &str =
        "b907f619cf50e26efc241ad4f36a2c65e8e2ea067e219090e9adaeac0ab29e02";
    const NODEPLOY_SIGNATURE: &str =
        "87bf772dd4b4bd29420d2c231bed297e6e70d8b9d178bfd7dfb031357a16f9671409f0cd482295c4adef6345480976acc425160bf45f5d044e9a18830ebfab05";
    const NODEPLOY_BOC: &str = "b5ee9c724101040100d200014588004a482640bd0ca2e865c18556e950af61a5c66d331397de3be3e582d51713fe120c0101e1c3dfbb96ea5a5e94a10696118df694bf37386c5ce8bc5febefd8189abd0b7cb38a04f866a4114ae256f7b1a2a404bb5662128b05fa2fae82274d0c41875fd582fa929b18f8a71482afbd541ec4cbb17e6551ddabafaf9ee49087ba9a4511b48b0000006851437b509ab48c36d33b991b20020165800240129bdbae7bf40effc97b5d72fccc8ab95159c7dad163292f3436f17931dca0000000000000000000000000eb79a2a038030000839ebf0d";
    const DEPLOY_SIGNING_HASH: &str =
        "77add642b963a951782720857438b4c855af1782b51e5ddd18ac7659bb637112";
    const DEPLOY_MSG_HASH: &str =
        "14ffaae648c16a52e40551670663a5da376ab0b076bac43e6c2f04c44bd6c9bc";
    const DEPLOY_BOC: &str = "b5ee9c7241020b010001fb00034788004a482640bd0ca2e865c18556e950af61a5c66d331397de3be3e582d51713fe1211b00107080114ff00f4a413f4bcf2c80b0202012003040004d23002e6f271d70101c000f27a8308d718ed44d08307d701d70b3fc8f828cf1623cf16c9f9000371d70101c3009a8307d7015113baf2e064de8040d7018020d7018020d701541675f910f2a8f823bbf27966bef823810708a08103e8a85220bcb1f274022082104cee646cbae30f01c8cbffcb3fc9ed54050600983002d74cd0fa408306d70171d70178d701d74cf80070801004aa0214b1c8cb055005cf165003fa02cb6922d021cf3121d749a08409b998337001cb0058cf1697307101cb0012cce2c901fb00003e8210169e3e11ba8e11f800029320d74a9778d701d402fb00e8d19332f23ce20050ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c000000000000000001e1d8613f85d20c3ff653b04113c8cbbb5715c5843daa16f85791a522ef5fffe65af2b19c81b63946cb447c99d50412938d3905e4d1a9dbc4633a1d57f982d0d687fa929b18f8a71482afbd541ec4cbb17e6551ddabafaf9ee49087ba9a4511b48b0000006851437b4d1ab48c36d33b991b20090165800240129bdbae7bf40effc97b5d72fccc8ab95159c7dad163292f3436f17931dca0000000000000000000000000eb79a2a0380a0000ab97d59a";
    const NODEPLOY_SDK_BOC: &str = "te6ccgEBBAEA0gABRYgASkgmQL0MouhlwYVW6VCvYaXGbTMTl9474+WC1RcT/hIMAQHhw9+7lupaXpShBpYRjfaUvzc4bFzovF/r79gYmr0LfLOKBPhmpBFK4lb3saKkBLtWYhKLBfovroInTQxBh1/VgvqSmxj4pxSCr71UHsTLsX5lUd2rr6+e5JCHuppFEbSLAAAAaFFDe1CatIw20zuZGyACAWWAAkASm9uue/QO/8l7XXL8zIq5UVnH2tFjKS80NvF5MdygAAAAAAAAAAAAAAAA63mioDgDAAA=";

    #[test]
    fn signature_verifies_and_threshold_assembly_checks_it() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let key = SigningKey::from_bytes(&SECRET);
        let public = key.verifying_key().to_bytes();
        let signature = key.sign(&t.signing_hash(&public).unwrap()).to_bytes();
        assert_eq!(
            t.assemble(&public, &signature).unwrap(),
            t.sign(&SECRET).unwrap()
        );
        let mut forged = signature;
        forged[0] ^= 1;
        assert!(t.assemble(&public, &forged).is_err());
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(t.assemble(&other, &signature).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let refused = |f: &dyn Fn(&mut EverscaleTx)| {
            let mut t = base.clone();
            f(&mut t);
            t.sign(&SECRET).is_err() && t.check_matches_intent(&intent(&t)).is_err()
        };
        assert!(refused(&|t| t.chain_id = EVER_MAINNET.into()));
        assert!(refused(&|t| t.chain_id = VENOM_MAINNET.into()));
        assert!(refused(&|t| t.chain_id = "venom:1".into()));
        assert!(refused(&|t| t.evers = "0".into()));
        assert!(refused(&|t| t.evers = "0123456789".into()));
        assert!(refused(&|t| t.evers = "18446744073709551616".into()));
        assert!(refused(&|t| t.evers = "1.5".into()));
        assert!(refused(&|t| t.evers = "-1".into()));
        assert!(refused(&|t| t.expire_at = (t.built_at_ms / 1000) as u32));
        assert!(refused(
            &|t| t.expire_at = (t.built_at_ms / 1000) as u32 + 86_401
        ));
        assert!(refused(&|t| t.built_at_ms = 0));
        assert!(refused(&|t| t.time_ms = t.built_at_ms + MAX_LIFETIME_MS + 1));
        assert!(refused(
            &|t| t.time_ms = t.built_at_ms - MAX_TIME_SKEW_MS - 1
        ));
        assert!(refused(&|t| t.to = SENDER.into()));
        assert!(refused(&|t| t.to = format!("1:{}", "ab".repeat(32))));
        // Uppercase hex is not the canonical spelling.
        assert!(refused(&|t| t.from = format!("0:{}", "AB".repeat(32))));
        // A valid but different sender is refused by `sign` (key mismatch).
        assert!(base
            .clone()
            .sign(&SigningKey::from_bytes(&[9u8; 32]).to_bytes())
            .is_err());

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "123456790".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = SENDER.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:tip3:{RECIPIENT}");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId(EVER_MAINNET.into());
        assert!(base.check_matches_intent(&i).is_err());

        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "evers": "1",
            "timeMs": 2, "expireAt": 3, "builtAtMs": 1, "bounce": false, "deploy": true,
            "payload": "00"
        });
        assert!(serde_json::from_value::<EverscaleTx>(extra).is_err());
        let ok = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "evers": "1",
            "timeMs": 2, "expireAt": 3, "builtAtMs": 1, "bounce": false, "deploy": true
        });
        assert!(serde_json::from_value::<EverscaleTx>(ok).is_ok());
    }
}
