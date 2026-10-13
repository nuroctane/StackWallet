//! Off-chain signatures from a `single` wallet's EVM key: EIP-191 personal
//! messages and EIP-712 typed data.
//!
//! A signature can carry value without a transaction (a token permit, a
//! marketplace order), so the same rules apply as to sending:
//!
//! - a fresh session proof (passphrase or passkey, never a PIN);
//! - the signer key re-derives to the address the user saw;
//! - typed data must name a chain in its domain, and that chain must be one
//!   the core signs transactions on (testnets until the support gates pass),
//!   so a permit cannot reach mainnet funds through the back door;
//! - every signature appends a `messageSigned` row to the audit chain before
//!   it is returned.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::audit::{Actor, AuditEvent};
use crate::evm::{self, keccak256};
use crate::ledger;
use crate::model::Curve;
use crate::provenance;
use crate::vault::{EncryptedVault, SessionProof};
use crate::{CoreError, Result};

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_TYPES: usize = 64;
const MAX_DEPTH: usize = 16;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "message",
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageKind {
    /// EIP-191 version 0x45: `"\x19Ethereum Signed Message:\n" + len + message`.
    Personal,
    /// EIP-712 typed structured data (JSON with types, primaryType, domain, message).
    TypedData,
}

pub struct MessageRequest<'a> {
    pub wallet_id: &'a str,
    pub path: &'a str,
    /// The address the user saw; the derived key must match it.
    pub address: &'a str,
    pub session: &'a SessionProof,
    pub kind: MessageKind,
    /// UTF-8 text for `Personal`, typed-data JSON for `TypedData`.
    pub payload: &'a str,
    pub device_id: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedMessage {
    pub address: String,
    pub digest_hex: String,
    /// 65 bytes: r, s, v with v in {27, 28}.
    pub signature_hex: String,
}

pub fn personal_digest(message: &[u8]) -> [u8; 32] {
    let mut data = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    data.extend_from_slice(message);
    keccak256(&data)
}

pub fn sign_message(vault: &mut EncryptedVault, req: MessageRequest<'_>) -> Result<SignedMessage> {
    vault.verify_session(req.session, false)?;
    if req.payload.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("too large"));
    }
    let digest = match req.kind {
        MessageKind::Personal => personal_digest(req.payload.as_bytes()),
        MessageKind::TypedData => {
            let data: Value =
                serde_json::from_str(req.payload).map_err(|e| invalid(format!("not JSON: {e}")))?;
            let chain = typed_data_chain_id(&data)?;
            evm::check_chain(&format!("eip155:{chain}"))?;
            typed_data_digest(&data)?
        }
    };
    let key = provenance::signing_key(vault, req.wallet_id, Curve::Secp256k1, req.path)?;
    let derived = evm::checksum_address(&evm::address_from_public(
        &hex::decode(key.public_hex()).map_err(|_| invalid("bad public key"))?,
    )?);
    if !derived.eq_ignore_ascii_case(req.address) {
        return Err(invalid(
            "the signing key does not derive to the shown address",
        ));
    }
    let (parity, r, s) = evm::sign_digest(key.secret(), &digest)?;
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&s);
    sig.push(27 + parity);
    let digest_hex = format!("0x{}", hex::encode(digest));
    ledger::append_audit(
        vault,
        req.now_ms,
        Actor::Device {
            device_id: req.device_id.to_owned(),
        },
        AuditEvent::MessageSigned {
            wallet_id: req.wallet_id.to_owned(),
            address: derived.clone(),
            kind: match req.kind {
                MessageKind::Personal => "personal".into(),
                MessageKind::TypedData => "typedData".into(),
            },
            digest_hex: digest_hex.clone(),
        },
    )?;
    Ok(SignedMessage {
        address: derived,
        digest_hex,
        signature_hex: format!("0x{}", hex::encode(sig)),
    })
}

/// `domain.chainId` as a number; typed data without one is refused.
pub fn typed_data_chain_id(data: &Value) -> Result<u64> {
    let v = data
        .get("domain")
        .and_then(|d| d.get("chainId"))
        .ok_or_else(|| invalid("typed data must name its chain in domain.chainId"))?;
    let n = uint_value(v, 256)?;
    u64::try_from(n_to_u128(&n)?).map_err(|_| invalid("chainId out of range"))
}

fn n_to_u128(be: &[u8; 32]) -> Result<u128> {
    if be[..16].iter().any(|b| *b != 0) {
        return Err(invalid("number out of range"));
    }
    let mut x = [0u8; 16];
    x.copy_from_slice(&be[16..]);
    Ok(u128::from_be_bytes(x))
}

type Types = BTreeMap<String, Vec<(String, String)>>;

fn parse_types(data: &Value) -> Result<Types> {
    let obj = data
        .get("types")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("types missing"))?;
    if obj.len() > MAX_TYPES {
        return Err(invalid("too many types"));
    }
    let mut out = Types::new();
    for (name, fields) in obj {
        let list = fields
            .as_array()
            .ok_or_else(|| invalid(format!("type {name} is not a list")))?;
        let mut parsed = Vec::with_capacity(list.len());
        for f in list {
            let n = f
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("field without a name"))?;
            let t = f
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("field without a type"))?;
            parsed.push((n.to_owned(), t.to_owned()));
        }
        out.insert(name.clone(), parsed);
    }
    Ok(out)
}

/// `0x1901 ‖ domainSeparator ‖ hashStruct(primaryType, message)`.
pub fn typed_data_digest(data: &Value) -> Result<[u8; 32]> {
    let mut types = parse_types(data)?;
    let domain = data
        .get("domain")
        .ok_or_else(|| invalid("domain missing"))?;
    if !types.contains_key("EIP712Domain") {
        // Derive the domain type from the fields present, in the EIP's order.
        let mut fields = Vec::new();
        for (n, t) in [
            ("name", "string"),
            ("version", "string"),
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ] {
            if domain.get(n).is_some() {
                fields.push((n.to_owned(), t.to_owned()));
            }
        }
        types.insert("EIP712Domain".into(), fields);
    }
    let primary = data
        .get("primaryType")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("primaryType missing"))?;
    if primary == "EIP712Domain" {
        return Err(invalid("primaryType cannot be the domain"));
    }
    let message = data
        .get("message")
        .ok_or_else(|| invalid("message missing"))?;
    let mut out = vec![0x19, 0x01];
    out.extend_from_slice(&hash_struct(&types, "EIP712Domain", domain, 0)?);
    out.extend_from_slice(&hash_struct(&types, primary, message, 0)?);
    Ok(keccak256(&out))
}

fn base_type(t: &str) -> &str {
    t.split('[').next().unwrap_or(t)
}

fn deps(types: &Types, name: &str, found: &mut BTreeSet<String>) -> Result<()> {
    if found.contains(name) || !types.contains_key(name) {
        return Ok(());
    }
    found.insert(name.to_owned());
    for (_, t) in &types[name] {
        deps(types, base_type(t), found)?;
    }
    Ok(())
}

pub fn encode_type(types: &Types, name: &str) -> Result<String> {
    let mut found = BTreeSet::new();
    deps(types, name, &mut found)?;
    found.remove(name);
    let mut out = String::new();
    for n in std::iter::once(name.to_owned()).chain(found) {
        let fields = types
            .get(&n)
            .ok_or_else(|| invalid(format!("unknown type {n}")))?;
        out.push_str(&n);
        out.push('(');
        out.push_str(
            &fields
                .iter()
                .map(|(f, t)| format!("{t} {f}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push(')');
    }
    Ok(out)
}

fn hash_struct(types: &Types, name: &str, value: &Value, depth: usize) -> Result<[u8; 32]> {
    if depth > MAX_DEPTH {
        return Err(invalid("typed data nests too deeply"));
    }
    let fields = types
        .get(name)
        .ok_or_else(|| invalid(format!("unknown type {name}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| invalid(format!("{name} is not an object")))?;
    let mut enc = keccak256(encode_type(types, name)?.as_bytes()).to_vec();
    for (f, t) in fields {
        let v = obj
            .get(f)
            .ok_or_else(|| invalid(format!("{name}.{f} missing")))?;
        enc.extend_from_slice(&encode_value(types, t, v, depth + 1)?);
    }
    Ok(keccak256(&enc))
}

fn encode_value(types: &Types, t: &str, v: &Value, depth: usize) -> Result<[u8; 32]> {
    if depth > MAX_DEPTH {
        return Err(invalid("typed data nests too deeply"));
    }
    if let Some(inner) = t.strip_suffix(']') {
        let open = inner
            .rfind('[')
            .ok_or_else(|| invalid(format!("bad array type {t}")))?;
        let (elem, len) = (&inner[..open], &inner[open + 1..]);
        let items = v
            .as_array()
            .ok_or_else(|| invalid(format!("{t} is not a list")))?;
        if !len.is_empty() && len.parse::<usize>().ok() != Some(items.len()) {
            return Err(invalid(format!("{t} has the wrong length")));
        }
        let mut buf = Vec::with_capacity(items.len() * 32);
        for item in items {
            buf.extend_from_slice(&encode_value(types, elem, item, depth + 1)?);
        }
        return Ok(keccak256(&buf));
    }
    if types.contains_key(t) {
        return hash_struct(types, t, v, depth + 1);
    }
    match t {
        "string" => Ok(keccak256(
            v.as_str()
                .ok_or_else(|| invalid("string expected"))?
                .as_bytes(),
        )),
        "bytes" => Ok(keccak256(&hex_bytes(v)?)),
        "bool" => {
            let b = v.as_bool().ok_or_else(|| invalid("bool expected"))?;
            let mut out = [0u8; 32];
            out[31] = u8::from(b);
            Ok(out)
        }
        "address" => {
            let raw = hex_bytes(v)?;
            if raw.len() != 20 {
                return Err(invalid("address must be 20 bytes"));
            }
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(&raw);
            Ok(out)
        }
        _ if t.starts_with("bytes") => {
            let n: usize = t[5..]
                .parse()
                .map_err(|_| invalid(format!("unknown type {t}")))?;
            let raw = hex_bytes(v)?;
            if !(1..=32).contains(&n) || raw.len() != n {
                return Err(invalid(format!("{t} must be {n} bytes")));
            }
            let mut out = [0u8; 32];
            out[..n].copy_from_slice(&raw);
            Ok(out)
        }
        _ if t.starts_with("uint") => uint_value(v, bits(t, 4)?),
        _ if t.starts_with("int") => int_value(v, bits(t, 3)?),
        _ => Err(invalid(format!("unknown type {t}"))),
    }
}

fn bits(t: &str, prefix: usize) -> Result<u32> {
    let rest = &t[prefix..];
    let n = if rest.is_empty() {
        256
    } else {
        rest.parse()
            .map_err(|_| invalid(format!("unknown type {t}")))?
    };
    if n == 0 || n > 256 || n % 8 != 0 {
        return Err(invalid(format!("unknown type {t}")));
    }
    Ok(n)
}

fn hex_bytes(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| invalid("hex string expected"))?;
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| invalid("hex must start with 0x"))?;
    hex::decode(h).map_err(|_| invalid("bad hex"))
}

/// Big-endian magnitude of a JSON number or decimal/hex string.
fn magnitude(v: &Value) -> Result<(bool, [u8; 32])> {
    let text = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_owned(),
        _ => return Err(invalid("number expected")),
    };
    let (neg, body) = match text.strip_prefix('-') {
        Some(b) => (true, b.to_owned()),
        None => (false, text),
    };
    let mut out = [0u8; 32];
    if let Some(h) = body.strip_prefix("0x") {
        if h.is_empty() || h.len() > 64 {
            return Err(invalid("hex number out of range"));
        }
        let padded = format!("{h:0>64}");
        let raw = hex::decode(padded).map_err(|_| invalid("bad hex number"))?;
        out.copy_from_slice(&raw);
    } else {
        if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) || body.len() > 78 {
            return Err(invalid("bad decimal number"));
        }
        for d in body.bytes() {
            // out = out * 10 + d
            let mut carry = u32::from(d - b'0');
            for byte in out.iter_mut().rev() {
                let x = u32::from(*byte) * 10 + carry;
                *byte = (x & 0xff) as u8;
                carry = x >> 8;
            }
            if carry != 0 {
                return Err(invalid("number out of range"));
            }
        }
    }
    Ok((neg, out))
}

/// Number of significant bits in a big-endian magnitude.
fn bit_len(be: &[u8; 32]) -> u32 {
    for (i, b) in be.iter().enumerate() {
        if *b != 0 {
            return (32 - i as u32) * 8 - b.leading_zeros();
        }
    }
    0
}

fn fits(be: &[u8; 32], bits: u32) -> bool {
    bit_len(be) <= bits
}

fn uint_value(v: &Value, bits: u32) -> Result<[u8; 32]> {
    let (neg, m) = magnitude(v)?;
    if neg || !fits(&m, bits) {
        return Err(invalid(format!("value does not fit uint{bits}")));
    }
    Ok(m)
}

fn int_value(v: &Value, bits: u32) -> Result<[u8; 32]> {
    let (neg, m) = magnitude(v)?;
    // |x| must fit in bits-1 (or equal 2^(bits-1) when negative).
    let limit_ok = fits(&m, bits - 1) || {
        let mut min = [0u8; 32];
        let bit = bits - 1;
        min[31 - (bit / 8) as usize] = 1 << (bit % 8);
        neg && m == min
    };
    if !limit_ok {
        return Err(invalid(format!("value does not fit int{bits}")));
    }
    if !neg {
        return Ok(m);
    }
    // Two's complement over 256 bits.
    let mut out = m.map(|b| !b);
    for byte in out.iter_mut().rev() {
        let (x, o) = byte.overflowing_add(1);
        *byte = x;
        if !o {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export_gate::testing;
    use crate::provenance::import_phrase;
    use crate::vault::{KdfParams, Secret};

    fn mail(chain: u64) -> Value {
        serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": chain,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }
        })
    }

    #[test]
    fn eip712_matches_the_reference_vector() {
        let types = parse_types(&mail(1)).unwrap();
        assert_eq!(
            encode_type(&types, "Mail").unwrap(),
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
        assert_eq!(
            hex::encode(typed_data_digest(&mail(1)).unwrap()),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn personal_digest_matches_eip191() {
        // keccak256("\x19Ethereum Signed Message:\n11hello world")
        assert_eq!(
            hex::encode(personal_digest(b"hello world")),
            "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"
        );
    }

    #[test]
    fn integers_encode_and_refuse_overflow() {
        assert_eq!(uint_value(&Value::from(255), 8).unwrap()[31], 255);
        assert!(uint_value(&Value::from(256), 8).is_err());
        assert!(uint_value(&Value::from(-1), 256).is_err());
        assert_eq!(int_value(&Value::from(-1), 256).unwrap(), [0xff; 32]);
        assert!(int_value(&Value::from(-128), 8).is_ok());
        assert!(int_value(&Value::from(128), 8).is_err());
        assert_eq!(uint_value(&Value::from("0x10"), 256).unwrap()[31], 16);
    }

    fn recover(sig_hex: &str, digest: &[u8; 32]) -> String {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let sig = hex::decode(sig_hex.trim_start_matches("0x")).unwrap();
        assert_eq!(sig.len(), 65);
        let v = sig[64];
        assert!(v == 27 || v == 28);
        let key = VerifyingKey::recover_from_prehash(
            digest,
            &Signature::from_slice(&sig[..64]).unwrap(),
            RecoveryId::from_byte(v - 27).unwrap(),
        )
        .unwrap();
        evm::checksum_address(
            &evm::address_from_public(key.to_encoded_point(false).as_bytes()).unwrap(),
        )
    }

    #[test]
    fn signs_audited_and_gated_messages() {
        let mut v =
            EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap();
        import_phrase(
            &mut v,
            "w",
            "test test test test test test test test test test test junk",
            1,
        )
        .unwrap();
        let k = testing::keys(&mut v, "pw", &[]);
        let addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        let req = |kind, payload: &'static str| MessageRequest {
            wallet_id: "w",
            path: "m/44'/60'/0'/0/0",
            address: addr,
            session: &k.session,
            kind,
            payload,
            device_id: "d",
            now_ms: 5,
        };
        let s = sign_message(&mut v, req(MessageKind::Personal, "hello world")).unwrap();
        assert_eq!(s.address, addr);
        assert_eq!(
            recover(&s.signature_hex, &personal_digest(b"hello world")),
            addr
        );
        let audit = ledger::load_ledger(&v).unwrap().audit;
        assert!(matches!(
            audit.last().unwrap().event,
            AuditEvent::MessageSigned { .. }
        ));

        let mainnet = mail(1).to_string();
        let sepolia = mail(11_155_111).to_string();
        let leak: &'static str = Box::leak(mainnet.into_boxed_str());
        assert!(
            sign_message(&mut v, req(MessageKind::TypedData, leak)).is_err(),
            "mainnet permit"
        );
        let ok: &'static str = Box::leak(sepolia.into_boxed_str());
        sign_message(&mut v, req(MessageKind::TypedData, ok)).unwrap();

        let wrong = MessageRequest {
            address: "0x0000000000000000000000000000000000000001",
            ..req(MessageKind::Personal, "x")
        };
        assert!(sign_message(&mut v, wrong).is_err());
        let bad = SessionProof::Passphrase(Secret::new(b"no".to_vec()));
        let denied = MessageRequest {
            session: &bad,
            ..req(MessageKind::Personal, "x")
        };
        assert!(sign_message(&mut v, denied).is_err());
    }
}
