//! Native TON transfers from a wallet v4r2 contract. The core builds every
//! cell from checked fields: the internal message (one native transfer, empty
//! body, send mode 3), the wallet's signing message, the StateInit when the
//! wallet is not deployed yet, and the external message bag of cells.
//!
//! Keys come from BIP39 + SLIP-10 at `m/44'/607'/{i}'`, not the TON mnemonic
//! scheme, so a StackWallet phrase does not restore in Tonkeeper and a
//! Tonkeeper phrase does not import here.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const TESTNET: &str = "tvm:-3";
pub const MAINNET: &str = "tvm:-239";
/// The v4r2 default `wallet_id` for workchain 0 (698983191 + workchain), on both networks.
pub const SUBWALLET_ID: u32 = 698_983_191;
/// Pay forward fees separately (1) and ignore action-phase errors (2): what every wallet sends.
pub const SEND_MODE: u8 = 3;
const MAX_LIFETIME_SECS: u32 = 24 * 60 * 60;
/// Wallet v4r2 code as shipped by `@ton/ton` (`WalletContractV4`); its hash is
/// `feb5ff68…bd5c0`, checked by the tests.
const WALLET_V4R2_CODE: &str = "te6ccgECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVA==";

const CRC16: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_XMODEM);
const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
const BOC_MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];
const TAG_BOUNCEABLE: u8 = 0x11;
const TAG_NON_BOUNCEABLE: u8 = 0x51;
const TAG_TEST_ONLY: u8 = 0x80;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "TON transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only TON testnet transfers are enabled"));
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
/// the serialized bytes identical to the SDK's for the same tree.
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

/// A one-root bag of cells with a CRC32C trailer and no index, as `Cell.toBoc()` emits.
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

// ---------------------------------------------------------------- addresses

/// A parsed basechain address and the flags of its user-friendly spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TonAddress {
    pub hash: [u8; 32],
    /// `None` for the raw `0:<hex>` form, which carries no flags.
    pub bounceable: Option<bool>,
    pub test_only: Option<bool>,
}

/// Parses a user-friendly address (url-safe or standard base64, any flags) or
/// the raw `0:<hex>` form. Only workchain 0 is accepted.
pub fn parse_address(address: &str) -> Result<TonAddress> {
    if let Some(hex_part) = address.strip_prefix("0:") {
        if hex_part.len() != 64 {
            return Err(invalid("raw address must be 0: and 64 hex digits"));
        }
        let hash: [u8; 32] = hex::decode(hex_part)
            .map_err(|_| invalid("raw address is not hex"))?
            .try_into()
            .map_err(|_| invalid("raw address is not 32 bytes"))?;
        return Ok(TonAddress {
            hash,
            bounceable: None,
            test_only: None,
        });
    }
    if address.len() != 48 {
        return Err(invalid("address must be 48 base64 characters or 0:<hex>"));
    }
    let raw = if address.contains(['-', '_']) {
        base64::engine::general_purpose::URL_SAFE.decode(address)
    } else {
        base64::engine::general_purpose::STANDARD.decode(address)
    }
    .map_err(|_| invalid("address is not base64"))?;
    if raw.len() != 36 {
        return Err(invalid("address must decode to 36 bytes"));
    }
    if CRC16.checksum(&raw[..34]).to_be_bytes() != raw[34..] {
        return Err(invalid("address checksum mismatch"));
    }
    let tag = raw[0];
    let bounceable = match tag & !TAG_TEST_ONLY {
        TAG_BOUNCEABLE => true,
        TAG_NON_BOUNCEABLE => false,
        _ => return Err(invalid("unknown address flags")),
    };
    if raw[1] != 0 {
        return Err(invalid(
            "only basechain (workchain 0) addresses are supported",
        ));
    }
    Ok(TonAddress {
        hash: raw[2..34].try_into().expect("32 bytes"),
        bounceable: Some(bounceable),
        test_only: Some(tag & TAG_TEST_ONLY != 0),
    })
}

/// The url-safe user-friendly spelling of a basechain address.
pub fn friendly(hash: &[u8; 32], bounceable: bool, test_only: bool) -> String {
    let mut raw = Vec::with_capacity(36);
    let tag = if bounceable {
        TAG_BOUNCEABLE
    } else {
        TAG_NON_BOUNCEABLE
    };
    raw.push(if test_only { tag | TAG_TEST_ONLY } else { tag });
    raw.push(0);
    raw.extend_from_slice(hash);
    raw.extend_from_slice(&CRC16.checksum(&raw).to_be_bytes());
    base64::engine::general_purpose::URL_SAFE.encode(raw)
}

fn wallet_code() -> Result<Rc<Cell>> {
    let boc = base64::engine::general_purpose::STANDARD
        .decode(WALLET_V4R2_CODE)
        .map_err(|_| invalid("wallet code constant"))?;
    parse_boc(&boc)
}

fn state_init(public: &[u8; 32]) -> Result<Rc<Cell>> {
    let data = Builder::default()
        .uint(0, 32)
        .uint(u128::from(SUBWALLET_ID), 32)
        .bytes(public)
        .bit(false)
        .build()?;
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

/// The basechain account id of the v4r2 wallet for an Ed25519 key: the StateInit hash.
pub fn wallet_hash(public: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(state_init(public)?.hash)
}

/// The wallet address the core signs for: non-bounceable and test-only (`0Q…`),
/// as Tonkeeper shows a testnet wallet. Mainnet displays the same account as `UQ…`.
pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    Ok(friendly(&wallet_hash(&key)?, false, true))
}

// ---------------------------------------------------------------- transaction

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TonTx {
    pub chain_id: String,
    /// The signer's v4r2 wallet, exactly as `address()` spells it (`0Q…`).
    pub from: String,
    /// Any user-friendly spelling or `0:<hex>`; only the account id is encoded.
    pub to: String,
    /// Decimal nanotons (1 TON = 10^9); never a JSON floating-point number.
    pub nanoton: String,
    /// The wallet's current seqno; 0 for a wallet that was never used.
    pub seqno: u32,
    /// Unix seconds after which the wallet contract refuses the message.
    pub valid_until: u32,
    /// Unix seconds the transfer was built; bounds `valid_until`, not encoded.
    pub built_at: u32,
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

impl TonTx {
    fn checked(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = parse_address(&self.from)?;
        if friendly(&from.hash, false, true) != self.from {
            return Err(invalid(
                "sender must be the non-bounceable testnet spelling",
            ));
        }
        let to = parse_address(&self.to)?;
        if from.hash == to.hash {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u64(&self.nanoton, "amount")?;
        if self.deploy && self.seqno != 0 {
            return Err(invalid("only a wallet at seqno 0 can be deployed"));
        }
        if self.built_at == 0
            || self.valid_until <= self.built_at
            || self.valid_until - self.built_at > MAX_LIFETIME_SECS
        {
            return Err(invalid(
                "validUntil must fall within a day of the build time",
            ));
        }
        Ok(Checked {
            from: from.hash,
            to: to.hash,
            amount,
        })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        let checked = self.checked()?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native TON transfers are enabled"));
                }
                if parse_address(to)?.hash != checked.to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.nanoton {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported TON intent")),
        }
        Ok(())
    }

    fn internal_message(c: &Checked, bounce: bool) -> Result<Rc<Cell>> {
        // int_msg_info$0 ihr_disabled bounce bounced src:addr_none dest value
        // ihr_fee fwd_fee created_lt created_at, init:nothing, body:inline empty
        Builder::default()
            .bit(false)
            .bit(true)
            .bit(bounce)
            .bit(false)
            .uint(0, 2)
            .address(0, &c.to)
            .coins(u128::from(c.amount))
            .bit(false)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(0, 32)
            .bit(false)
            .bit(false)
            .build()
    }

    fn signing_cell(&self) -> Result<Rc<Cell>> {
        let c = self.checked()?;
        Builder::default()
            .uint(u128::from(SUBWALLET_ID), 32)
            .uint(u128::from(self.valid_until), 32)
            .uint(u128::from(self.seqno), 32)
            .uint(0, 8)
            .uint(u128::from(SEND_MODE), 8)
            .reference(Self::internal_message(&c, self.bounce)?)
            .build()
    }

    /// The 32-byte Ed25519 message: the hash of the wallet's signing cell.
    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        Ok(self.signing_cell()?.hash)
    }

    /// Signs as the wallet of `secret`; returns the external message BoC as `0x`
    /// hex and its normalized hash (TEP-467) as 64 lowercase hex.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let signature = key.sign(&self.signing_hash()?).to_bytes();
        self.assemble(&public, &signature)
    }

    /// The external message for a signature made elsewhere (a threshold
    /// ceremony), accepted only if `public` owns `from` and the signature
    /// verifies over `signing_hash()`.
    pub fn assemble(&self, public: &[u8; 32], signature: &[u8; 64]) -> Result<(String, String)> {
        if address(public)? != self.from {
            return Err(invalid("public key does not own the sender wallet"));
        }
        let checked = self.checked()?;
        let signing = self.signing_cell()?;
        VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("public key is not an Ed25519 point"))?
            .verify_strict(
                &signing.hash,
                &ed25519_dalek::Signature::from_bytes(signature),
            )
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let body = Builder::default()
            .bytes(signature)
            .append(&signing)
            .build()?;
        let init = if self.deploy {
            Some(state_init(public)?)
        } else {
            None
        };
        let mut ext = Builder::default();
        // ext_in_msg_info$10 src:addr_none dest import_fee:0
        ext.uint(0b10, 2)
            .uint(0, 2)
            .address(0, &checked.from)
            .coins(0);
        // Inline-or-ref placement follows `@ton/core` storeMessage, so the bytes match the SDK.
        if let Some(init) = init {
            ext.bit(true);
            if 1023 - ext.bits - 2 < init.bits + body.bits {
                ext.bit(true).reference(init);
            } else {
                ext.bit(false).append(&init);
            }
        } else {
            ext.bit(false);
        }
        if 1023 - ext.bits - 1 < body.bits || ext.refs.len() + body.refs.len() > 4 {
            ext.bit(true).reference(body.clone());
        } else {
            ext.bit(false).append(&body);
        }
        let message = ext.build()?;
        let normalized = Builder::default()
            .uint(0b10, 2)
            .uint(0, 2)
            .address(0, &checked.from)
            .coins(0)
            .bit(false)
            .bit(true)
            .reference(body)
            .build()?;
        Ok((
            format!("0x{}", hex::encode(serialize_boc(&message))),
            hex::encode(normalized.hash),
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
    const SENDER: &str = "0QAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinEb6";
    /// The v4r2 wallet of seed `[9; 32]` in every spelling `@ton/core` 0.63.1 emits.
    const RECIPIENT_FORMS: [&str; 5] = [
        "0:1f3841f04e9a3349f64fe1626c6f045b54d6c2d839d3e0001518331d6c203352",
        "0QAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUpnx",
        "kQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUsQ0",
        "UQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUiJ7",
        "EQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUn--",
    ];
    const RECIPIENT: &str = "kQAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUsQ0";

    fn tx() -> TonTx {
        TonTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            nanoton: "1500000000".into(),
            seqno: 7,
            valid_until: 1_760_001_800,
            built_at: 1_760_000_000,
            bounce: true,
            deploy: false,
        }
    }

    fn deploy_tx() -> TonTx {
        TonTx {
            seqno: 0,
            bounce: false,
            deploy: true,
            ..tx()
        }
    }

    fn intent(tx: &TonTx) -> TxIntent {
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
                amount: Amount(tx.nanoton.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 1_760_000_000_000,
        }
    }

    #[test]
    fn addresses_match_the_official_sdk() {
        let code = wallet_code().unwrap();
        assert_eq!(
            hex::encode(code.hash),
            "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0"
        );
        let public = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        assert_eq!(
            hex::encode(public),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
        assert_eq!(address(&public).unwrap(), SENDER);
        let hash = wallet_hash(&public).unwrap();
        assert_eq!(
            friendly(&hash, true, false),
            "EQAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinKC1"
        );
        assert_eq!(
            friendly(&hash, false, false),
            "UQAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinP1w"
        );
        let nine = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let nine_hash = wallet_hash(&nine).unwrap();
        for form in RECIPIENT_FORMS {
            assert_eq!(parse_address(form).unwrap().hash, nine_hash, "{form}");
        }
        // `@ton/crypto` deriveEd25519Path(bip39Seed, [44, 607, 0]) and [44, 607, 1].
        let seed = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed("");
        let first = derive_ed25519(&*seed, &parse_path("m/44'/607'/0'").unwrap()).unwrap();
        assert_eq!(
            hex::encode(first.secret()),
            "b477ef5ed17fb8a2b8faddd7a9835a227243a82c70b190c7af4896155aa7df9f"
        );
        assert_eq!(
            address(&first.public).unwrap(),
            "0QAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-akS"
        );
        let second = derive_ed25519(&*seed, &parse_path("m/44'/607'/1'").unwrap()).unwrap();
        assert_eq!(
            address(&second.public).unwrap(),
            "0QDVJucJT96vGh_bYm3e5uzenasiTOwA9orUHQiyhNsKmKFF"
        );
        assert!(address(&public[..31]).is_err());
    }

    #[test]
    fn address_parsing_is_strict() {
        let standard = RECIPIENT_FORMS[4].replace('-', "+").replace('_', "/");
        assert_eq!(
            parse_address(&standard).unwrap(),
            parse_address(RECIPIENT_FORMS[4]).unwrap()
        );
        let p = parse_address(RECIPIENT_FORMS[1]).unwrap();
        assert_eq!((p.bounceable, p.test_only), (Some(false), Some(true)));
        let mut bad_crc = RECIPIENT.to_string();
        bad_crc.replace_range(47.., "5");
        assert!(parse_address(&bad_crc).is_err());
        assert!(parse_address(&RECIPIENT[..47]).is_err());
        assert!(parse_address(&format!("-1:{}", "ab".repeat(32))).is_err());
        assert!(parse_address(&format!("0:{}", "ab".repeat(31))).is_err());
        assert!(parse_address(&format!("0:{}", "zz".repeat(32))).is_err());
        // Masterchain account in friendly form (workchain byte 0xff).
        let mut raw = vec![TAG_BOUNCEABLE, 0xff];
        raw.extend_from_slice(&[1u8; 32]);
        raw.extend_from_slice(&CRC16.checksum(&raw).to_be_bytes());
        let master = base64::engine::general_purpose::URL_SAFE.encode(raw);
        assert!(parse_address(&master).is_err());
    }

    /// External messages built by `@ton/ton` 16.3.0 `WalletContractV4.createTransfer` plus
    /// `@ton/core` 0.63.1 `external`/`storeMessage`/`toBoc` (`.nur/ton-scratch/vector.mjs`).
    /// Ed25519 is deterministic, so the bytes match exactly; the TypeScript tests pin them too.
    #[test]
    fn messages_match_the_official_sdk() {
        let t = tx();
        assert_eq!(hex::encode(t.signing_hash().unwrap()), SIGNING_HASH);
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{BOC}"));
        assert_eq!(hash, NORM_HASH);
        let d = deploy_tx();
        assert_eq!(hex::encode(d.signing_hash().unwrap()), DEPLOY_SIGNING_HASH);
        let (wire, hash) = d.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{DEPLOY_BOC}"));
        assert_eq!(hash, DEPLOY_NORM_HASH);
        // The SDK's own BoC parses back into the same tree.
        let parsed = parse_boc(&hex::decode(DEPLOY_BOC).unwrap()).unwrap();
        assert_eq!(hex::encode(parsed.hash), DEPLOY_MSG_HASH);
        assert_eq!(serialize_boc(&parsed), hex::decode(DEPLOY_BOC).unwrap());
        let mut corrupt = hex::decode(BOC).unwrap();
        corrupt[20] ^= 1;
        assert!(parse_boc(&corrupt).is_err());
    }
    const SIGNING_HASH: &str = "af5cc817fa13671125a709434d2949f6ea6eddf50d925591d758647ecb8cc8c8";
    const NORM_HASH: &str = "1eb1024402549e0cde467e76c5dcbfbd5cc52fa7db9d47da03f1560cc2bd03a0";
    const BOC: &str = "b5ee9c724101020100aa0001e1880054ddcd6ffe837fd95fc70670c64b8f512be9fc99c68d631d73829402a5acc53806e8f050f25e5827221d1089040294e028b0d5fee31b01d65da6b462ff4c1a46432f380e1b20dbc381eb12d1d3cd5e4bc1d705231e19228f0d5584cd017a4c38394d4d18bb473bf84000000038001c01006862000f9c20f8274d19a4fb27f0b13637822daa6b616c1ce9f0000a8c198eb61019a922cb41780000000000000000000000000000eda805fb";
    const DEPLOY_SIGNING_HASH: &str =
        "3fcc3c232e95d5bc3f588a13f7fbe354da2c5467b164d0f9ebaa37a4730cfbeb";
    const DEPLOY_NORM_HASH: &str =
        "f8d70d9adebd76454aa6d5f94a1735320e01ea32563ac89db8ec72ea6ec296d0";
    const DEPLOY_MSG_HASH: &str =
        "cce9347f9b0e3f5cb8a8d19731bc142b6ceb94ddc57fd594980cc1b2aa24d148";
    const DEPLOY_BOC: &str = "b5ee9c72410217010003ac0003e3880054ddcd6ffe837fd95fc70670c64b8f512be9fc99c68d631d73829402a5acc53811891dbba91016e803be024cbb26053e9d21142ffabd8a17ca834afc09cef4ebefb2eefd1d9c6b581b22d1883f42db2cb62a692ba81879f0dd14d7ef1e06d9a70125353462ed1cefe1000000000000700115160114ff00f4a413f4bcf2c80b020201200310020148040702e6d001d0d3032171b0925f04e022d749c120925f04e002d31f218210706c7567bd22821064737472bdb0925f05e003fa403020fa4401c8ca07cbffc9d0ed44d0810140d721f404305c810108f40a6fa131b3925f07e005d33fc8258210706c7567ba923830e30d03821064737472ba925f06e30d0506007801fa00f40430f8276f2230500aa121bef2e0508210706c7567831eb17080185004cb0526cf1658fa0219f400cb6917cb1f5260cb3f20c98040fb0006008a5004810108f45930ed44d0810140d720c801cf16f400c9ed540172b08e23821064737472831eb17080185005cb055003cf1623fa0213cb6acb1fcb3fc98040fb00925f03e2020120080f020120090e0201580a0b003db29dfb513420405035c87d010c00b23281f2fff274006040423d029be84c600201200c0d0019adce76a26840206b90eb85ffc00019af1df6a26840106b90eb858fc00011b8c97ed44d0d70b1f80059bd242b6f6a2684080a06b90fa0218470d4080847a4937d29910ce6903e9ff9837812801b7810148987159f318404f8f28308d71820d31fd31fd31f02f823bbf264ed44d0d31fd31fd3fff404d15143baf2a15151baf2a205f901541064f910f2a3f80024a4c8cb1f5240cb1f5230cbff5210f400c9ed54f80f01d30721c0009f6c519320d74a96d307d402fb00e830e021c001e30021c002e30001c0039130e30d03a4c8cb1f12cb1fcbff11121314006ed207fa00d4d422f90005c8ca0715cbffc9d077748018c8cb05cb0222cf165005fa0214cb6b12ccccc973fb00c84014810108f451f2a7020070810108d718fa00d33fc8542047810108f451f2a782106e6f746570748018c8cb05cb025006cf165004fa0214cb6a12cb1fcb3fc973fb0002006c810108d718fa00d33f305224810108f459f2a782106473747270748018c8cb05cb025005cf165003fa0213cb6acb1f12cb3fc973fb00000af400c9ed5400510000000029a9a317ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40006842000f9c20f8274d19a4fb27f0b13637822daa6b616c1ce9f0000a8c198eb61019a922cb417800000000000000000000000000003d2efd08";

    #[test]
    fn signature_verifies_and_threshold_assembly_checks_it() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let key = SigningKey::from_bytes(&SECRET);
        let public = key.verifying_key().to_bytes();
        let signature = key.sign(&t.signing_hash().unwrap()).to_bytes();
        assert_eq!(
            t.assemble(&public, &signature).unwrap(),
            t.sign(&SECRET).unwrap()
        );
        // The body starts right after the 275-bit header and the init bit.
        let root = parse_boc(&hex::decode(BOC).unwrap()).unwrap();
        let sig_bits: Vec<bool> = (277..277 + 512).map(|i| root.bit(i)).collect();
        let embedded: Vec<u8> = sig_bits
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b)))
            .collect();
        assert_eq!(embedded, signature);
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
        let refused = |f: &dyn Fn(&mut TonTx)| {
            let mut t = base.clone();
            f(&mut t);
            t.sign(&SECRET).is_err() && t.check_matches_intent(&intent(&t)).is_err()
        };
        assert!(refused(&|t| t.chain_id = MAINNET.into()));
        assert!(refused(&|t| t.chain_id = "tvm:0".into()));
        assert!(refused(&|t| t.nanoton = "0".into()));
        assert!(refused(&|t| t.nanoton = "01500000000".into()));
        assert!(refused(&|t| t.nanoton = "18446744073709551616".into()));
        assert!(refused(&|t| t.nanoton = "1.5".into()));
        assert!(refused(&|t| t.nanoton = "-1".into()));
        assert!(refused(&|t| t.deploy = true));
        assert!(refused(&|t| t.valid_until = t.built_at));
        assert!(refused(
            &|t| t.valid_until = t.built_at + MAX_LIFETIME_SECS + 1
        ));
        assert!(refused(&|t| t.built_at = 0));
        assert!(refused(&|t| t.to = SENDER.into()));
        assert!(refused(
            &|t| t.to = "UQAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinP1w".into()
        ));
        assert!(refused(&|t| t.to = format!("-1:{}", "ab".repeat(32))));
        // The sender must be the canonical testnet spelling, not another one for the same wallet.
        assert!(refused(
            &|t| t.from = "kQAqbua3_0G_7K_jgzhjJceolfT-TONGsY65wUoBUtZinBs_".into()
        ));
        assert!(refused(&|t| {
            t.from = "0:2a6ee6b7ff41bfecafe383386325c7a895f4fe4ce346b18eb9c14a0152d6629c".into()
        }));
        for form in RECIPIENT_FORMS {
            let mut t = base.clone();
            t.to = form.into();
            t.check_matches_intent(&intent(&base)).unwrap();
            assert_eq!(t.sign(&SECRET).unwrap(), base.sign(&SECRET).unwrap());
        }

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500000001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "0QAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-akS".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:jetton:{RECIPIENT}");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId(MAINNET.into());
        assert!(base.check_matches_intent(&i).is_err());

        let mut other = base.clone();
        other.from = "0QAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUpnx".into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "nanoton": "1",
            "seqno": 0, "validUntil": 2, "builtAt": 1, "bounce": false, "deploy": true,
            "body": "00"
        });
        assert!(serde_json::from_value::<TonTx>(extra).is_err());
        let ok = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "nanoton": "1",
            "seqno": 0, "validUntil": 2, "builtAt": 1, "bounce": false, "deploy": true
        });
        assert!(serde_json::from_value::<TonTx>(ok).is_ok());
    }
}
