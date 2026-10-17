//! Namada family: transparent NAM transfers. The core Borsh-encodes the whole
//! wrapper+inner `Tx` (code/data/commitment sections, both Authorization
//! sections) exactly as namada v1.1.5 / libs v0.251.2 do, hand-rolled because
//! no borsh crate is in the workspace lockfile. The broadcast wire format is
//! the protobuf `types.Tx { bytes data = 1 }` wrapper around the Borsh bytes.

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 chain ids use the chain-id hash suffix: native ids contain a dot,
/// which the CAIP-2 reference alphabet forbids.
pub const MAINNET: &str = "namada:5f5de2dd1b88cba30586420";
pub const HOUSEFIRE: &str = "namada:cc0d3e0c033be";
const NATIVE_MAINNET: &str = "namada.5f5de2dd1b88cba30586420";
const NATIVE_HOUSEFIRE: &str = "housefire-alpaca.cc0d3e0c033be";
/// The NAM token is a genesis established address produced by deterministic
/// tooling, identical on mainnet and housefire; re-verify against a live
/// housefire endpoint before wiring ships.
pub const NAM_TOKEN: &str = "tnam1q9gr66cvu4hrzm0sd5kmlnjje82gs3xlfg3v6nu7";
const HRP: &str = "tnam";
const TRANSFER_WASM_TAG: &str = "tx_transfer.wasm";
const NATIVE_DENOM: u8 = 6;
/// Transparent transfers measure ~20k gas; anything past this is a mistake.
const MAX_GAS_LIMIT: u64 = 1_000_000;
/// Refuse to silently authorize an absurd fee: 100 NAM in namnam.
const MAX_TOTAL_FEE: u128 = 100_000_000;
/// `m/44'/877'/{account}'/0'/{index}'`, all-hardened SLIP-10.
pub const COIN_TYPE: u32 = 877;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Namada transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != HOUSEFIRE {
        return Err(invalid(
            "only Namada Housefire testnet transfers are enabled",
        ));
    }
    Ok(())
}

fn native_id(chain: &str) -> Result<&'static str> {
    match chain {
        MAINNET => Ok(NATIVE_MAINNET),
        HOUSEFIRE => Ok(NATIVE_HOUSEFIRE),
        _ => Err(invalid("unknown Namada network")),
    }
}

/// The 21-byte `[discriminant || 20-byte hash]` form behind a `tnam1…` address.
/// Raw discriminants: 0 implicit, 1 established; internal addresses are
/// refused here because only implicit/established accounts hold spendable NAM.
pub fn address_bytes(address: &str) -> Result<[u8; 21]> {
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|_| invalid("invalid bech32m address"))?;
    if checked.hrp().as_str() != HRP {
        return Err(invalid("not a tnam address"));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    if bytes.len() != 21 {
        return Err(invalid("address payload must be 21 bytes"));
    }
    let out: [u8; 21] = bytes.try_into().expect("21 bytes");
    if out[0] > 1 {
        return Err(invalid(
            "internal addresses cannot hold spendable funds here",
        ));
    }
    if out[1..].iter().all(|b| *b == 0) {
        return Err(invalid("zero address"));
    }
    if encode_address(&out)? != address {
        return Err(invalid("address is not canonical"));
    }
    Ok(out)
}

pub fn encode_address(raw: &[u8; 21]) -> Result<String> {
    bech32::encode::<Bech32m>(Hrp::parse(HRP).expect("static hrp"), raw)
        .map_err(|_| invalid("address encoding failed"))
}

/// The implicit address of a 32-byte Ed25519 public key:
/// `tnam` bech32m of `0x00 || sha256(0x00 || pubkey)[..20]`.
pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    let mut tagged = [0u8; 33];
    tagged[1..].copy_from_slice(&key);
    let digest = Sha256::digest(tagged);
    let mut raw = [0u8; 21];
    raw[1..].copy_from_slice(&digest[..20]);
    encode_address(&raw)
}

fn canonical_u64(value: &str, what: &str, allow_zero: bool) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} is not a decimal integer")))?;
    if (!allow_zero && n == 0) || n.to_string() != value {
        return Err(invalid(format!("{what} must be a canonical decimal")));
    }
    Ok(n)
}

fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!("{what} must be {N} lowercase hex bytes")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{what} is not hex")))?;
    Ok(bytes.try_into().expect("length checked"))
}

/// `DateTimeUtc` serializes as an RFC3339 borsh string with exactly nine
/// fractional digits and a `+00:00` offset; anything else would hash differently.
fn check_timestamp(value: &str) -> Result<()> {
    let b = value.as_bytes();
    let digit = |i: usize| b[i].is_ascii_digit();
    let shape_ok = b.len() == 35
        && (0..20).all(|i| match i {
            4 | 7 => b[i] == b'-',
            10 => b[i] == b'T',
            13 | 16 => b[i] == b':',
            19 => b[i] == b'.',
            _ => digit(i),
        })
        && (20..29).all(digit)
        && &value[29..] == "+00:00";
    if !shape_ok {
        return Err(invalid(
            "timestamp must be RFC3339 with 9 fractional digits, +00:00",
        ));
    }
    let month: u32 = value[5..7].parse().expect("digits");
    let day: u32 = value[8..10].parse().expect("digits");
    let hour: u32 = value[11..13].parse().expect("digits");
    let min: u32 = value[14..16].parse().expect("digits");
    let sec: u32 = value[17..19].parse().expect("digits");
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return Err(invalid("timestamp fields are out of range"));
    }
    Ok(())
}

// ---- hand-rolled Borsh ----

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Borsh of `Address`: enum disc 0 = Established, 1 = Implicit, then 20 bytes.
fn push_address(buf: &mut Vec<u8>, raw: &[u8; 21]) {
    buf.push(match raw[0] {
        0 => 1, // implicit
        1 => 0, // established
        _ => unreachable!("internal refused at decode"),
    });
    buf.extend_from_slice(&raw[1..]);
}

/// Borsh of `token::Amount` = `Uint([u64; 4])` little-endian.
fn push_amount(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&[0u8; 24]);
}

/// Borsh of `DenominatedAmount { amount, denom }`.
fn push_denominated(buf: &mut Vec<u8>, value: u64) {
    push_amount(buf, value);
    buf.push(NATIVE_DENOM);
}

/// Borsh of `common::PublicKey::Ed25519` = 0x00 || 32 bytes.
fn push_public_key(buf: &mut Vec<u8>, public: &[u8; 32]) {
    buf.push(0);
    buf.extend_from_slice(public);
}

/// Borsh of `common::Signature::Ed25519` = 0x00 || 64 bytes.
fn push_signature(buf: &mut Vec<u8>, sig: &[u8; 64]) {
    buf.push(0);
    buf.extend_from_slice(sig);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamadaTx {
    /// CAIP-2 id (`namada:cc0d3e0c033be` for housefire); the native chain id
    /// goes into the header.
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal namnam (1 NAM = 1,000,000 namnam); never a JSON floating-point number.
    pub namnam: String,
    /// Token contract address; must be this network's NAM token.
    pub token: String,
    /// Fee token address; only NAM fees are supported.
    pub fee_token: String,
    /// Fee bid per gas unit in namnam (the on-chain minimum is 1).
    pub fee_per_gas: String,
    pub gas_limit: u64,
    /// On-chain `wasm/hash/tx_transfer.wasm` code hash, 32 lowercase hex bytes.
    pub wasm_code_hash: String,
    /// Header timestamp, RFC3339 with nine fractional digits and `+00:00`.
    pub timestamp: String,
    /// Random 8-byte salt of the code section, hex (generated at prepare time).
    pub code_salt: String,
    /// Random 8-byte salt of the data section, hex.
    pub data_salt: String,
}

struct Checked {
    from: [u8; 21],
    to: [u8; 21],
    token: [u8; 21],
    fee_token: [u8; 21],
    amount: u64,
    fee_per_gas: u64,
    wasm_hash: [u8; 32],
    code_salt: [u8; 8],
    data_salt: [u8; 8],
}

impl NamadaTx {
    fn checked(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        native_id(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        // The sender must be an implicit account: its key both authorizes the
        // inner transfer and pays the wrapper fee.
        if from[0] != 0 {
            return Err(invalid("sender must be an implicit address"));
        }
        let token = address_bytes(&self.token)?;
        let fee_token = address_bytes(&self.fee_token)?;
        if self.token != NAM_TOKEN || self.fee_token != NAM_TOKEN {
            return Err(invalid("only native NAM transfers and fees are enabled"));
        }
        let amount = canonical_u64(&self.namnam, "amount", false)?;
        let fee_per_gas = canonical_u64(&self.fee_per_gas, "fee per gas", false)?;
        if self.gas_limit == 0 || self.gas_limit > MAX_GAS_LIMIT {
            return Err(invalid("gas limit out of range"));
        }
        if (fee_per_gas as u128) * (self.gas_limit as u128) > MAX_TOTAL_FEE {
            return Err(invalid("total fee bid is unreasonable"));
        }
        let wasm_hash = fixed_hex::<32>(&self.wasm_code_hash, "wasm code hash")?;
        if wasm_hash == [0; 32] {
            return Err(invalid("zero wasm code hash"));
        }
        check_timestamp(&self.timestamp)?;
        let code_salt = fixed_hex::<8>(&self.code_salt, "code salt")?;
        let data_salt = fixed_hex::<8>(&self.data_salt, "data salt")?;
        Ok(Checked {
            from,
            to,
            token,
            fee_token,
            amount,
            fee_per_gas,
            wasm_hash,
            code_salt,
            data_salt,
        })
    }

    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native NAM transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.namnam {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Namada intent")),
        }
        self.checked()?;
        Ok(())
    }

    /// Borsh of `token::Transfer` with a single source and target.
    fn transfer_data(c: &Checked) -> Vec<u8> {
        let account = |owner: &[u8; 21]| {
            let mut b = Vec::with_capacity(42);
            push_address(&mut b, owner);
            push_address(&mut b, &c.token);
            b
        };
        let mut out = Vec::new();
        // sources: BTreeMap<Account, DenominatedAmount> with one entry
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&account(&c.from));
        push_denominated(&mut out, c.amount);
        // targets
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&account(&c.to));
        push_denominated(&mut out, c.amount);
        // shielded_section_hash: None
        out.push(0);
        out
    }

    /// `Section::Code` borsh: 0x02 || salt || Commitment::Hash(hash) || Some(tag).
    fn code_section(c: &Checked) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(2);
        out.extend_from_slice(&c.code_salt);
        out.push(0); // Commitment::Hash
        out.extend_from_slice(&c.wasm_hash);
        out.push(1); // Some
        push_str(&mut out, TRANSFER_WASM_TAG);
        out
    }

    /// `Code::hash` commits to salt || code.hash() || tag, NOT the borsh form.
    fn code_section_hash(c: &Checked) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([2u8]); // Section::Code discriminant
        h.update(c.code_salt);
        h.update(c.wasm_hash);
        h.update([1u8]); // Some
        let mut tag = Vec::new();
        push_str(&mut tag, TRANSFER_WASM_TAG);
        h.update(tag);
        h.finalize().into()
    }

    /// `Section::Data` borsh: 0x00 || salt || vec bytes.
    fn data_section(c: &Checked) -> Vec<u8> {
        let data = Self::transfer_data(c);
        let mut out = Vec::new();
        out.push(0);
        out.extend_from_slice(&c.data_salt);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        out
    }

    fn section_hash(section: &[u8]) -> [u8; 32] {
        Sha256::digest(section).into()
    }

    /// Borsh of the header. `wrapper` present ⇔ `TxType::Wrapper`, else `Raw`.
    fn header(&self, c: &Checked, public: Option<&[u8; 32]>) -> Vec<u8> {
        let code_hash = Self::code_section_hash(c);
        let data_hash = Self::section_hash(&Self::data_section(c));
        let mut out = Vec::new();
        push_str(&mut out, native_id(&self.chain_id).expect("checked"));
        out.push(0); // expiration: None
        push_str(&mut out, &self.timestamp);
        // batch: one TxCommitments { code_hash, data_hash, memo_hash: zero }
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&code_hash);
        out.extend_from_slice(&data_hash);
        out.extend_from_slice(&[0u8; 32]);
        out.push(0); // atomic: false
        match public {
            Some(pk) => {
                out.push(1); // TxType::Wrapper
                push_denominated(&mut out, c.fee_per_gas); // fee.amount_per_gas_unit
                push_address(&mut out, &c.fee_token); // fee.token
                push_public_key(&mut out, pk); // pk
                out.extend_from_slice(&self.gas_limit.to_le_bytes()); // gas_limit
            }
            None => out.push(0), // TxType::Raw
        }
        out
    }

    fn header_hash(&self, c: &Checked, public: Option<&[u8; 32]>) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([6u8]); // Section::Header discriminant
        h.update(self.header(c, public));
        h.finalize().into()
    }

    /// The public key behind `from`; verified against the address.
    fn sender_key(&self, secret: &[u8; 32]) -> Result<[u8; 32]> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        Ok(public)
    }

    /// Borsh of an `Authorization` section payload (targets, signer, sigs).
    /// `signer`: `None` → `PubKeys([])` (the raw hash form), `Some((raw_addr
    /// or pk))` per the variant flag.
    fn authorization(
        targets: &[[u8; 32]],
        signer: AuthorizationSigner,
        sig: Option<&[u8; 64]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(targets.len() as u32).to_le_bytes());
        for t in targets {
            out.extend_from_slice(t);
        }
        match signer {
            AuthorizationSigner::Address(raw) => {
                out.push(0); // Signer::Address
                push_address(&mut out, raw);
            }
            AuthorizationSigner::PubKeys(pks) => {
                out.push(1); // Signer::PubKeys
                out.extend_from_slice(&(pks.len() as u32).to_le_bytes());
                for pk in pks {
                    push_public_key(&mut out, pk);
                }
            }
        }
        match sig {
            Some(s) => {
                out.extend_from_slice(&1u32.to_le_bytes());
                out.push(0); // index 0
                push_signature(&mut out, s);
            }
            None => out.extend_from_slice(&0u32.to_le_bytes()),
        }
        out
    }

    /// `Authorization::get_raw_hash`: sha256 over the borsh of the
    /// authorization with `PubKeys([])` signer and no signatures.
    fn raw_sig_hash(targets: &[[u8; 32]]) -> [u8; 32] {
        Sha256::digest(Self::authorization(
            targets,
            AuthorizationSigner::PubKeys(&[]),
            None,
        ))
        .into()
    }

    /// 32-byte message the inner (raw) signature signs directly.
    pub fn inner_sig_hash(&self) -> Result<[u8; 32]> {
        let c = self.checked()?;
        let raw_header = self.header_hash(&c, None);
        Ok(Self::raw_sig_hash(&[raw_header]))
    }

    /// 32-byte message the wrapper signature signs directly, given the
    /// completed inner signature.
    pub fn wrapper_sig_hash(&self, inner_sig: &[u8; 64], public: &[u8; 32]) -> Result<[u8; 32]> {
        let c = self.checked()?;
        if address(public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let inner_auth = self.inner_authorization(&c, inner_sig);
        let targets = [
            self.header_hash(&c, Some(public)),
            Self::code_section_hash(&c),
            Self::section_hash(&Self::data_section(&c)),
            Self::section_hash(&inner_auth),
        ];
        Ok(Self::raw_sig_hash(&targets))
    }

    /// `Section::Authorization` (0x03) over the raw header hash, signed by the
    /// sender; the signer of an implicit account is its address.
    fn inner_authorization(&self, c: &Checked, inner_sig: &[u8; 64]) -> Vec<u8> {
        let raw_header = self.header_hash(c, None);
        let mut out = vec![3u8];
        out.extend_from_slice(&Self::authorization(
            &[raw_header],
            AuthorizationSigner::Address(&c.from),
            Some(inner_sig),
        ));
        out
    }

    /// Full Borsh `Tx` and the protobuf wire form.
    pub fn assemble(
        &self,
        inner_sig: &[u8; 64],
        wrapper_sig: &[u8; 64],
        public: &[u8; 32],
    ) -> Result<(String, String)> {
        let c = self.checked()?;
        if address(public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let inner_auth = self.inner_authorization(&c, inner_sig);
        let wrapper_targets = [
            self.header_hash(&c, Some(public)),
            Self::code_section_hash(&c),
            Self::section_hash(&Self::data_section(&c)),
            Self::section_hash(&inner_auth),
        ];
        let wrapper_auth = {
            let mut out = vec![3u8];
            out.extend_from_slice(&Self::authorization(
                &wrapper_targets,
                AuthorizationSigner::PubKeys(&[*public]),
                Some(wrapper_sig),
            ));
            out
        };
        let mut borsh = self.header(&c, Some(public));
        borsh.extend_from_slice(&4u32.to_le_bytes());
        borsh.extend_from_slice(&Self::code_section(&c));
        borsh.extend_from_slice(&Self::data_section(&c));
        borsh.extend_from_slice(&inner_auth);
        borsh.extend_from_slice(&wrapper_auth);
        let wrapper_hash = hex::encode(wrapper_targets[0]);
        // protobuf types.Tx { bytes data = 1 }
        let mut wire = vec![0x0a];
        let mut len = borsh.len();
        loop {
            let byte = (len & 0x7f) as u8;
            len >>= 7;
            if len > 0 {
                wire.push(byte | 0x80);
            } else {
                wire.push(byte);
                break;
            }
        }
        wire.extend_from_slice(&borsh);
        Ok((hex::encode(wire), wrapper_hash))
    }

    /// Sign both sections with one key; returns (wire hex, wrapper hash hex).
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let public = self.sender_key(secret)?;
        let key = SigningKey::from_bytes(secret);
        let inner = key.sign(&self.inner_sig_hash()?).to_bytes();
        let wrapper = key
            .sign(&self.wrapper_sig_hash(&inner, &public)?)
            .to_bytes();
        self.assemble(&inner, &wrapper, &public)
    }
}

enum AuthorizationSigner<'a> {
    Address(&'a [u8; 21]),
    PubKeys(&'a [[u8; 32]]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    const SENDER: &str = "tnam1qpfe0prje04hulwjdvsjqtmucpfxpttxyy7v2689";
    /// A sampled established address from namada's own test corpus.
    const RECIPIENT: &str = "tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5";
    /// On-chain `wasm/hash/tx_transfer.wasm` on mainnet at probe time.
    const WASM_HASH: &str = "9a950b45d233c8f6fabfa5c473800c182f7666fe0c35c1a612f66a5f094758fe";

    fn tx() -> NamadaTx {
        NamadaTx {
            chain_id: HOUSEFIRE.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            namnam: "123456789".into(),
            token: NAM_TOKEN.into(),
            fee_token: NAM_TOKEN.into(),
            fee_per_gas: "1".into(),
            gas_limit: 50_000,
            wasm_code_hash: WASM_HASH.into(),
            timestamp: "2026-10-16T21:00:00.000000000+00:00".into(),
            code_salt: "0102030405060708".into(),
            data_salt: "0807060504030201".into(),
        }
    }

    fn intent(tx: &NamadaTx) -> TxIntent {
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
                amount: Amount(tx.namnam.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn implicit_address_matches_oracle_vector() {
        let public =
            hex::decode("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
                .unwrap();
        assert_eq!(address(&public).unwrap(), SENDER);
        assert_eq!(
            encode_address(&address_bytes(SENDER).unwrap()).unwrap(),
            SENDER
        );
        // An established address from namada's corpus decodes and re-encodes.
        assert_eq!(
            encode_address(&address_bytes(RECIPIENT).unwrap()).unwrap(),
            RECIPIENT
        );
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        // Wrong checksum char.
        assert!(address_bytes("tnam1qpfe0prje04hulwjdvsjqtmucpfxpttxyy7v2688").is_err());
        // Uppercase is not canonical bech32m.
        assert!(address_bytes(&SENDER.to_uppercase()).is_err());
        // Internal addresses (here the multitoken account) are refused.
        assert!(address_bytes("tnam1pyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqej6juv").is_err());
        // Zero hash is refused.
        assert!(address_bytes("tnam1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjpwq6t").is_err());
        let mut t = tx();
        t.to = t.from.clone();
        assert!(t.inner_sig_hash().is_err());
    }

    /// The whole pipeline is pinned byte-exact against the independent oracle
    /// in `.nur/namada-oracle`, and the equivalent mainnet-shaped bytes passed
    /// mainnet mempool wrapper-signature verification (rejection evidence).
    #[test]
    fn signed_wire_matches_oracle_vector() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(
            hex::encode(t.inner_sig_hash().unwrap()),
            "dbf8a642b30cedbce9eb5bee78d1d92131e6a0d7663448245447cd7925a23743"
        );
        let public = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        let inner = SigningKey::from_bytes(&SECRET)
            .sign(&t.inner_sig_hash().unwrap())
            .to_bytes();
        assert_eq!(
            hex::encode(inner),
            "09892caf565c4974e722cde36e808471a523498032235f47227ded7395b80e304b44aa0518a93b41c365d0a4c886cfce5a843c4e204a7bf62c3ec3d39a98d007"
        );
        assert_eq!(
            hex::encode(t.wrapper_sig_hash(&inner, &public).unwrap()),
            "832d746bfd040f14a6b4561b94baa41e6bb97d8492c0518c3155f0fd58c332fd"
        );
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, WIRE_VECTOR);
        assert_eq!(hash, WRAPPER_HASH_VECTOR);
        // assemble() with the same two signatures must reproduce sign().
        let wrapper = SigningKey::from_bytes(&SECRET)
            .sign(&t.wrapper_sig_hash(&inner, &public).unwrap())
            .to_bytes();
        assert_eq!(t.assemble(&inner, &wrapper, &public).unwrap(), (wire, hash));
    }

    const WRAPPER_HASH_VECTOR: &str =
        "63905a23bbbe5bce76ee8f87deeffcd02d6be2fc29af02c7ca401f5b054c3fc7";
    const WIRE_VECTOR: &str = "0af0061e000000686f757365666972652d616c706163612e636330643365306330333362650023000000323032362d31302d31365432313a30303a30302e3030303030303030302b30303a303001000000bd2cacb080ac06e6ae7e7b29629594403c32cdcb8b0502ca40203c8d4c6f92c3c9a06b58d5e3330340114bfed6da25ec44ae4e8d553d3fefe047a59d17c658710000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000000600503d6b0ce56e316df06d2dbfce52c9d48844df4a00ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c50c300000000000004000000020102030405060708009a950b45d233c8f6fabfa5c473800c182f7666fe0c35c1a612f66a5f094758fe011000000074785f7472616e736665722e7761736d0008070605040302019f000000010000000153978472cbeb7e7dd26b21202f7cc05260ad662100503d6b0ce56e316df06d2dbfce52c9d48844df4a15cd5b0700000000000000000000000000000000000000000000000000000000060100000000e54868c1a502fa105374d2bb3236195125c1d19800503d6b0ce56e316df06d2dbfce52c9d48844df4a15cd5b0700000000000000000000000000000000000000000000000000000000060003010000008dd33d3eec3b798eb08d176eeeb39831793efbf76cab3d17e9df634a56d674b6000153978472cbeb7e7dd26b21202f7cc05260ad662101000000000009892caf565c4974e722cde36e808471a523498032235f47227ded7395b80e304b44aa0518a93b41c365d0a4c886cfce5a843c4e204a7bf62c3ec3d39a98d007030400000063905a23bbbe5bce76ee8f87deeffcd02d6be2fc29af02c7ca401f5b054c3fc7bd2cacb080ac06e6ae7e7b29629594403c32cdcb8b0502ca40203c8d4c6f92c3c9a06b58d5e3330340114bfed6da25ec44ae4e8d553d3fefe047a59d17c658710993480f2675651115eb55cebf6b3568287b0dbc446144852462c865e0a58cdb010100000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c010000000000d8bd536fb11f474d6cc2b78800e7d484347fa276c420070f95ef5e821a501d4235a655cc8dbf35c5f18c8491280b3dd3654e7c5cc285a5c8c0d93609d8902f01";

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        // Mainnet stays refused.
        let mut t = base.clone();
        t.chain_id = MAINNET.into();
        assert!(t.inner_sig_hash().is_err());
        assert!(t.sign(&SECRET).is_err());
        // Non-native token or fee token.
        let mut t = base.clone();
        t.token = RECIPIENT.into();
        assert!(t.inner_sig_hash().is_err());
        let mut t = base.clone();
        t.fee_token = RECIPIENT.into();
        assert!(t.inner_sig_hash().is_err());
        // Amounts and fees must be canonical decimals.
        let mut t = base.clone();
        t.namnam = "0123456789".into();
        assert!(t.inner_sig_hash().is_err());
        let mut t = base.clone();
        t.namnam = "0".into();
        assert!(t.inner_sig_hash().is_err());
        let mut t = base.clone();
        t.fee_per_gas = "0".into();
        assert!(t.inner_sig_hash().is_err());
        // Gas limit out of range.
        let mut t = base.clone();
        t.gas_limit = 0;
        assert!(t.inner_sig_hash().is_err());
        let mut t = base.clone();
        t.gas_limit = MAX_GAS_LIMIT + 1;
        assert!(t.inner_sig_hash().is_err());
        // Absurd total fee.
        let mut t = base.clone();
        t.fee_per_gas = "1000000".into();
        t.gas_limit = MAX_GAS_LIMIT;
        assert!(t.inner_sig_hash().is_err());
        // Timestamps must be the exact DateTimeUtc borsh shape.
        let mut t = base.clone();
        t.timestamp = "2026-10-16T21:00:00Z".into();
        assert!(t.inner_sig_hash().is_err());
        let mut t = base.clone();
        t.timestamp = "2026-13-16T21:00:00.000000000+00:00".into();
        assert!(t.inner_sig_hash().is_err());
        // Sender must be the implicit address of the signing key.
        let mut t = base.clone();
        t.from = RECIPIENT.into();
        assert!(t.sign(&SECRET).is_err());
        let mut t = base.clone();
        t.from = "tnam1qq8wh08lttn4vlkdcvvnmkwlauyvvx2m9vyzu5vp".into();
        assert!(t.sign(&SECRET).is_err());
        // Intent mismatches.
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "123456790".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId(MAINNET.into());
        assert!(base.check_matches_intent(&i).is_err());
        // Unknown serde fields are refused.
        let extra = serde_json::json!({
            "chainId": HOUSEFIRE, "from": base.from, "to": base.to, "namnam": "1",
            "token": NAM_TOKEN, "feeToken": NAM_TOKEN, "feePerGas": "1", "gasLimit": 50000,
            "wasmCodeHash": WASM_HASH, "timestamp": base.timestamp,
            "codeSalt": "0102030405060708", "dataSalt": "0807060504030201", "memo": "00"
        });
        assert!(serde_json::from_value::<NamadaTx>(extra).is_err());
    }
}
