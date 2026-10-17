//! Obyte (DAG, secp256k1) family: native GBYTE (bytes) transfers as v4.0t units.
//! The core encodes the whole unit JSON from checked fields, so an adapter
//! cannot add messages, assets or authors.
//!
//! Byte-exactness is pinned against the vendored ocore oracle
//! (`.nur/obyte-oracle`: real `ocore/object_hash.js`, `chash.js`,
//! `object_length.js`, `string_utils.js` plus native `secp256k1`). Addresses,
//! sighashes, payload hashes, commissions and signatures were reproduced from
//! live testnet units, and a deliberately wrong-key unit built this way was
//! accepted by the live hub up to the signature check.
//!
//! Protocol facts baked in here:
//! - Address = chash160 of the legacy source string of the definition
//!   `["sig", {pubkey: <base64 compressed SEC1>}]`: ripemd160, first 4 bytes
//!   dropped, 32 checksum bits (sha256 bytes 5/13/21/29) mixed into the clean
//!   data at pi-digit offsets, RFC4648 base32 without padding (32 chars).
//! - Sighash = sha256 of the JSON source string (sorted keys, compact) of the
//!   naked unit with `authors[].authentifiers` removed.
//! - Unit id = base64 sha256 of the JSON source of the stripped unit (no
//!   timestamp/messages) plus `content_hash` = sha256 of `{messages, timestamp}`.
//! - `payload_hash` = base64 sha256 of the JSON source of the payload.
//! - Commissions: string values count their char length, numbers count 8,
//!   object keys count their length for v4, `parent_units` is replaced by an
//!   88-char placeholder, and the 88-char signature placeholder is present
//!   when sizing headers.
//! - Signature = RFC6979 low-S compact r||s (64 bytes), base64 (88 chars).
//! - v4 units: `version: "4.0t"`, `alt: "2"`, `tps_fee` field, no witnesses.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// Only the Obyte testnet is wired up; mainnet stays disabled until the
/// family's testnet and threshold support gates pass.
pub const TESTNET: &str = "obyte:testnet";

pub const VERSION: &str = "4.0t";
pub const ALT: &str = "2";

const MAX_CAP: u64 = 9_000_000_000_000_000; // ocore constants.MAX_CAP (9e15)
const MAX_INPUTS_PER_PAYMENT: usize = 128; // ocore MAX_INPUTS_PER_PAYMENT_MESSAGE
const MAX_PARENTS_PER_UNIT: usize = 16; // ocore MAX_PARENTS_PER_UNIT
const MAX_UNIT_LENGTH: u64 = 5_000_000; // ocore MAX_UNIT_LENGTH
const B64_HASH_LEN: usize = 44; // base64 of 32 bytes
const SIG_PLACEHOLDER_LEN: usize = 88; // base64 of 64 bytes, counted in headers commission
const PARENT_UNITS_PLACEHOLDER: u64 = 88; // ocore object_length.PARENT_UNITS_SIZE (2 * 44)

const PI_DIGITS: &[u8] = b"14159265358979323846264338327950288419716939937510";

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Obyte transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    if chain != TESTNET {
        return Err(invalid("only Obyte testnet transfers are enabled"));
    }
    Ok(())
}

/// chash160 checksum bit offsets: cumulative sums of nonzero pi digits.
fn chash160_offsets() -> [usize; 32] {
    let mut offsets = Vec::with_capacity(32);
    let mut offset = 0usize;
    for &digit in PI_DIGITS {
        let rel = (digit - b'0') as usize;
        if rel == 0 {
            continue;
        }
        offset += rel;
        if offset >= 160 {
            break;
        }
        offsets.push(offset);
    }
    assert_eq!(offsets.len(), 32, "wrong number of checksum bits");
    let mut out = [0usize; 32];
    out.copy_from_slice(&offsets);
    out
}

fn checksum_bytes(clean_data: &[u8]) -> [u8; 4] {
    let full = Sha256::digest(clean_data);
    [full[5], full[13], full[21], full[29]]
}

fn bit_at(data: &[u8], bit: usize) -> u8 {
    (data[bit / 8] >> (7 - (bit % 8))) & 1
}

/// Mix the 32 checksum bits into the clean data at the pi offsets.
fn mix_checksum(clean_data: &[u8], checksum: &[u8; 4]) -> [u8; 20] {
    let offsets = chash160_offsets();
    let mut out = [0u8; 20];
    let mut clean_bit = 0usize;
    let mut checksum_bit = 0usize;
    let mut next = 0usize;
    for pos in 0..160usize {
        let bit = if next < offsets.len() && pos == offsets[next] {
            next += 1;
            let b = bit_at(checksum, checksum_bit);
            checksum_bit += 1;
            b
        } else {
            let b = bit_at(clean_data, clean_bit);
            clean_bit += 1;
            b
        };
        if bit == 1 {
            out[pos / 8] |= 1 << (7 - (pos % 8));
        }
    }
    out
}

/// Extract (clean data, checksum) from a mixed 160-bit chash.
fn separate_checksum(mixed: &[u8]) -> ([u8; 16], [u8; 4]) {
    let offsets = chash160_offsets();
    let mut clean = [0u8; 16];
    let mut checksum = [0u8; 4];
    let mut clean_bit = 0usize;
    let mut checksum_bit = 0usize;
    let mut next = 0usize;
    for pos in 0..160usize {
        if next < offsets.len() && pos == offsets[next] {
            next += 1;
            if bit_at(mixed, pos) == 1 {
                checksum[checksum_bit / 8] |= 1 << (7 - (checksum_bit % 8));
            }
            checksum_bit += 1;
        } else {
            if bit_at(mixed, pos) == 1 {
                clean[clean_bit / 8] |= 1 << (7 - (clean_bit % 8));
            }
            clean_bit += 1;
        }
    }
    (clean, checksum)
}

/// ocore `getChash160`: ripemd160, drop the first 4 bytes, mix in the
/// checksum bits, RFC4648 base32 without padding.
fn chash160(data: &[u8]) -> String {
    let hash = ripemd::Ripemd160::digest(data);
    let clean: [u8; 16] = hash[4..].try_into().expect("16 bytes");
    let checksum = checksum_bytes(&clean);
    let mixed = mix_checksum(&clean, &checksum);
    data_encoding::BASE32_NOPAD.encode(&mixed)
}

pub fn check_address(address: &str) -> Result<()> {
    if address.len() != 32 {
        return Err(invalid("address must be 32 base32 characters"));
    }
    let mixed = data_encoding::BASE32_NOPAD
        .decode(address.as_bytes())
        .map_err(|_| invalid("address is not RFC4648 base32"))?;
    if mixed.len() != 20 {
        return Err(invalid("address must decode to 20 bytes"));
    }
    let (clean, checksum) = separate_checksum(&mixed);
    if checksum_bytes(&clean) != checksum {
        return Err(invalid("address checksum mismatch"));
    }
    Ok(())
}

fn base64_32(value: &str, what: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    if value.len() != B64_HASH_LEN {
        return Err(invalid(format!(
            "{what} must be {B64_HASH_LEN} base64 characters"
        )));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| invalid(format!("{what} is not standard base64")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid(format!("{what} must decode to 32 bytes")))
}

fn decode_pubkey_base64(pubkey: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey)
        .map_err(|_| invalid("author pubkey is not standard base64"))?;
    if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(invalid("author pubkey must be 33-byte compressed SEC1"));
    }
    Ok(bytes)
}

/// ocore `getSourceString`: legacy "\x00"-joined, type-tagged serialization,
/// used for definitions (address derivation).
fn legacy_source_string(value: &Value) -> Result<String> {
    let mut components: Vec<String> = Vec::new();
    legacy_components(value, &mut components)?;
    Ok(components.join("\x00"))
}

fn legacy_components(value: &Value, out: &mut Vec<String>) -> Result<()> {
    match value {
        Value::Null => Err(invalid("null value in definition")),
        Value::String(s) => {
            out.push("s".into());
            out.push(s.clone());
            Ok(())
        }
        Value::Number(n) => {
            out.push("n".into());
            out.push(n.to_string());
            Ok(())
        }
        Value::Bool(b) => {
            out.push("b".into());
            out.push(b.to_string());
            Ok(())
        }
        Value::Array(items) => {
            if items.is_empty() {
                return Err(invalid("empty array in definition"));
            }
            out.push("[".into());
            for item in items {
                legacy_components(item, out)?;
            }
            out.push("]".into());
            Ok(())
        }
        Value::Object(map) => {
            if map.is_empty() {
                return Err(invalid("empty object in definition"));
            }
            // serde_json maps are BTreeMaps: keys iterate sorted, as ocore sorts them.
            for (key, item) in map {
                out.push(key.clone());
                legacy_components(item, out)?;
            }
            Ok(())
        }
    }
}

/// ocore `getJsonSourceString`: canonical JSON, keys sorted, no whitespace.
/// serde_json without `preserve_order` stores object keys in a BTreeMap, so
/// walking the value in map order already yields the canonical form.
fn json_source_string(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_json(value, &mut out)?;
    Ok(out)
}

fn write_json(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.as_u64().is_none() {
                return Err(invalid(format!("non-unsigned-integer number in unit: {n}")));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            // serde_json escapes exactly like JSON.stringify for the ASCII
            // strings Obyte uses (base64, base32, short tags).
            let encoded = serde_json::to_string(s).map_err(|_| invalid("string escape failed"))?;
            out.push_str(&encoded);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let key_encoded =
                    serde_json::to_string(key).map_err(|_| invalid("key escape failed"))?;
                out.push_str(&key_encoded);
                out.push(':');
                write_json(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn json_hash_b64(value: &Value) -> Result<String> {
    use base64::Engine;
    let source = json_source_string(value)?;
    let digest = Sha256::digest(source.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

/// ocore `object_length.getLength` with bWithKeys (always true for v4):
/// strings count chars, numbers count 8, bools 1, null 0, object keys count
/// their char length.
fn get_length(value: &Value) -> u64 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 8,
        Value::String(s) => s.chars().count() as u64,
        Value::Array(items) => items.iter().map(get_length).sum(),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| k.chars().count() as u64 + get_length(v))
            .sum(),
    }
}

/// Derive the Obyte address of a 33-byte compressed SEC1 public key via the
/// `["sig", {pubkey}]` definition and chash160.
pub fn address(public: &[u8]) -> Result<String> {
    use base64::Engine;
    if public.len() != 33 || (public[0] != 0x02 && public[0] != 0x03) {
        return Err(invalid("expected 33-byte compressed SEC1 public key"));
    }
    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(public);
    let definition = json!(["sig", { "pubkey": pubkey_b64 }]);
    let source = legacy_source_string(&definition)?;
    Ok(chash160(source.as_bytes()))
}

fn parse_amount(raw: &str, what: &str) -> Result<u64> {
    let value: u64 = raw
        .parse()
        .map_err(|_| invalid(format!("{what} must be a canonical non-negative integer")))?;
    if value.to_string() != raw || value > MAX_CAP {
        return Err(invalid(format!(
            "{what} must be canonical and at most MAX_CAP ({MAX_CAP})"
        )));
    }
    Ok(value)
}

/// One spent payment output referenced by `{unit, message_index, output_index}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObyteInput {
    /// Base64 unit id of the unit that created the output.
    pub unit: String,
    pub message_index: u32,
    pub output_index: u32,
    /// Value of the referenced output, decimal string (needed for the change
    /// calculation; not part of the wire unit).
    pub amount: String,
}

/// Unsigned Obyte payment unit intent (single author, single payment message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObyteTx {
    /// Must be [`TESTNET`].
    pub chain_id: String,
    /// Sender address (32-char base32).
    pub from: String,
    /// Base64 compressed SEC1 public key behind `from`; becomes the inline
    /// definition on the first spend from this address.
    pub author_pubkey: String,
    /// Recipient address (32-char base32).
    pub to: String,
    /// Amount in bytes (the Obyte base unit); never a JSON floating-point number.
    pub bytes: String,
    /// Seconds since epoch, from the hub's parents response.
    pub timestamp: u64,
    /// TPS fee from the hub's parents response (0 in practice today).
    pub tps_fee: u64,
    /// 1..=16 base64 unit ids from the hub; sorted on build.
    pub parent_units: Vec<String>,
    /// Base64 last stable MC ball from the hub.
    pub last_ball: String,
    /// Base64 unit id of the last stable MC ball from the hub.
    pub last_ball_unit: String,
    /// Selected spendable outputs; change is returned to `from`.
    pub inputs: Vec<ObyteInput>,
    /// Embed the author definition in the unit (first spend from `from`).
    pub first_unit: bool,
}

impl ObyteTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native GBYTE transfers are enabled"));
                }
                check_address(to)?;
                if *to != self.to {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.bytes {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Obyte intent")),
        }
        self.sighash()?;
        Ok(())
    }

    /// Checks everything that does not depend on the change being positive;
    /// returns (amount, input amounts).
    fn validate(&self) -> Result<(u64, Vec<u64>)> {
        check_chain(&self.chain_id)?;
        check_address(&self.from)?;
        check_address(&self.to)?;
        let pubkey_bytes = decode_pubkey_base64(&self.author_pubkey)?;
        if address(&pubkey_bytes)? != self.from {
            return Err(invalid("author pubkey does not derive the from address"));
        }
        let amount = parse_amount(&self.bytes, "amount")?;
        if amount == 0 {
            return Err(invalid("amount must be positive"));
        }
        if self.timestamp == 0 || self.timestamp >= (1u64 << 53) {
            return Err(invalid("timestamp must be positive unix seconds"));
        }
        if self.parent_units.is_empty() || self.parent_units.len() > MAX_PARENTS_PER_UNIT {
            return Err(invalid(format!(
                "expected 1..={MAX_PARENTS_PER_UNIT} parent units"
            )));
        }
        for parent in &self.parent_units {
            base64_32(parent, "parent unit")?;
        }
        base64_32(&self.last_ball, "last ball")?;
        base64_32(&self.last_ball_unit, "last ball unit")?;
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS_PER_PAYMENT {
            return Err(invalid(format!(
                "expected 1..={MAX_INPUTS_PER_PAYMENT} inputs"
            )));
        }
        let mut input_amounts = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            base64_32(&input.unit, "input unit")?;
            if input.message_index >= (1u32 << 31) || input.output_index >= (1u32 << 31) {
                return Err(invalid("input indexes must be below 2^31"));
            }
            input_amounts.push(parse_amount(&input.amount, "input amount")?);
        }
        Ok((amount, input_amounts))
    }

    fn author_with_placeholder(&self) -> Value {
        let mut author = Map::new();
        author.insert("address".into(), json!(self.from));
        author.insert(
            "authentifiers".into(),
            json!({ "r": "-".repeat(SIG_PLACEHOLDER_LEN) }),
        );
        if self.first_unit {
            author.insert(
                "definition".into(),
                json!(["sig", { "pubkey": self.author_pubkey }]),
            );
        }
        Value::Object(author)
    }

    /// ocore `object_length.getHeadersSize` for this unit shape.
    fn headers_size(&self) -> u64 {
        let header = json!({
            "version": VERSION,
            "alt": ALT,
            "timestamp": self.timestamp,
            "authors": [self.author_with_placeholder()],
            "last_ball": self.last_ball,
            "last_ball_unit": self.last_ball_unit,
            "tps_fee": self.tps_fee,
        });
        // parent_units replaced by a fixed placeholder; the key is still counted.
        get_length(&header) + PARENT_UNITS_PLACEHOLDER + "parent_units".chars().count() as u64
    }

    fn payment_message(&self) -> Result<Value> {
        let amount = parse_amount(&self.bytes, "amount")?;
        let outputs = vec![
            json!({ "address": self.from, "amount": 0 }),
            json!({ "address": self.to, "amount": amount }),
        ];
        let inputs: Vec<Value> = self
            .inputs
            .iter()
            .map(|i| {
                json!({
                    "unit": i.unit,
                    "message_index": i.message_index,
                    "output_index": i.output_index,
                })
            })
            .collect();
        Ok(json!({
            "app": "payment",
            "payload_location": "inline",
            "payload_hash": "-".repeat(B64_HASH_LEN),
            "payload": { "outputs": outputs, "inputs": inputs },
        }))
    }

    /// ocore `object_length.getTotalPayloadSize` for this unit shape.
    fn payload_size(&self) -> Result<u64> {
        let messages = json!({ "messages": [self.payment_message()?] });
        Ok(get_length(&messages))
    }

    /// (headers_commission, payload_commission) exactly as ocore computes them.
    /// Used by the adapter while selecting inputs; does not require the change
    /// to be positive.
    pub fn fees(&self) -> Result<(u64, u64)> {
        self.validate()?;
        Ok((self.headers_size(), self.payload_size()?))
    }

    /// (change, headers_commission, payload_commission, settled payment message).
    fn settled(&self) -> Result<(u64, u64, u64, Value)> {
        let (amount, input_amounts) = self.validate()?;
        let headers = self.headers_size();
        let payload = self.payload_size()?;
        if headers + payload > MAX_UNIT_LENGTH {
            return Err(invalid("unit too large"));
        }
        let total: u128 = input_amounts.iter().map(|a| *a as u128).sum();
        let needed = amount as u128 + headers as u128 + payload as u128 + self.tps_fee as u128;
        if total <= needed {
            return Err(invalid(format!(
                "change would not be positive (inputs sum to {total}, need more than {needed})"
            )));
        }
        let change = (total - needed) as u64;
        let mut message = self.payment_message()?;
        // ocore sets the change amount on the first output (change address),
        // then sorts outputs by (address, amount).
        let mut outputs = vec![(self.from.clone(), change), (self.to.clone(), amount)];
        outputs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let outputs: Vec<Value> = outputs
            .into_iter()
            .map(|(addr, value)| json!({ "address": addr, "amount": value }))
            .collect();
        message["payload"]["outputs"] = json!(outputs);
        message["payload_hash"] = json!(json_hash_b64(&message["payload"])?);
        Ok((change, headers, payload, message))
    }

    /// Full unit value with `signature` in the author authentifiers when given
    /// (base64, 88 chars) and the placeholder otherwise.
    fn unit_value(&self, signature: Option<&str>) -> Result<Value> {
        let (_, headers, payload, message) = self.settled()?;
        let placeholder;
        let sig = match signature {
            Some(s) => s,
            None => {
                placeholder = "-".repeat(SIG_PLACEHOLDER_LEN);
                &placeholder
            }
        };
        let mut author = Map::new();
        author.insert("address".into(), json!(self.from));
        author.insert("authentifiers".into(), json!({ "r": sig }));
        if self.first_unit {
            author.insert(
                "definition".into(),
                json!(["sig", { "pubkey": self.author_pubkey }]),
            );
        }
        let mut parent_units = self.parent_units.clone();
        parent_units.sort();
        Ok(json!({
            "version": VERSION,
            "alt": ALT,
            "timestamp": self.timestamp,
            "parent_units": parent_units,
            "last_ball": self.last_ball,
            "last_ball_unit": self.last_ball_unit,
            "tps_fee": self.tps_fee,
            "authors": [Value::Object(author)],
            "messages": [message],
            "headers_commission": headers,
            "payload_commission": payload,
        }))
    }

    /// ocore `getNakedUnit`: no `unit`, commissions, or message payloads.
    fn naked_unit(unit: &Value) -> Result<Value> {
        let mut naked = unit.clone();
        let map = naked.as_object_mut().expect("unit is an object");
        map.remove("headers_commission");
        map.remove("payload_commission");
        let messages = naked["messages"].as_array_mut().expect("unit has messages");
        for message in messages {
            message
                .as_object_mut()
                .expect("message is an object")
                .remove("payload");
        }
        Ok(naked)
    }

    /// ocore `getUnitHashToSign`: sha256 of the JSON source of the naked unit
    /// (no `unit`, commissions, message payloads, or `authentifiers`).
    pub fn sighash(&self) -> Result<[u8; 32]> {
        let unit = self.unit_value(None)?;
        let mut naked = Self::naked_unit(&unit)?;
        if let Some(Value::Object(author)) =
            naked["authors"].as_array_mut().and_then(|a| a.first_mut())
        {
            author.remove("authentifiers");
        }
        let source = json_source_string(&naked)?;
        Ok(Sha256::digest(source.as_bytes()).into())
    }

    /// ocore `getUnitHash`: base64 sha256 of the JSON source of the stripped
    /// unit: {content_hash, version, alt, authors: [{address}], parent_units,
    /// last_ball, last_ball_unit, timestamp}. `content_hash` is the hash of
    /// the naked unit WITH authentifiers (ocore `getUnitContentHash`).
    fn unit_hash(unit: &Value) -> Result<String> {
        use base64::Engine;
        let naked = Self::naked_unit(unit)?;
        let content_hash = json_hash_b64(&naked)?;
        let authors: Vec<Value> = unit["authors"]
            .as_array()
            .expect("unit has authors")
            .iter()
            .map(|a| json!({ "address": a["address"].clone() }))
            .collect();
        let stripped = json!({
            "content_hash": content_hash,
            "version": unit["version"].clone(),
            "alt": unit["alt"].clone(),
            "authors": authors,
            "parent_units": unit["parent_units"].clone(),
            "last_ball": unit["last_ball"].clone(),
            "last_ball_unit": unit["last_ball_unit"].clone(),
            "timestamp": unit["timestamp"].clone(),
        });
        let source = json_source_string(&stripped)?;
        let digest = Sha256::digest(source.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(digest))
    }

    /// Sign with a 32-byte secp256k1 secret; returns (wire JSON, unit id).
    /// Wire JSON is the canonical (sorted-key) JSON of `{"unit": <unit>}`,
    /// ready to post as the `post_joint` params.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        use base64::Engine;
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let signing_key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid secp256k1 secret key"))?;
        let public = signing_key.verifying_key().to_encoded_point(true);
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        if pubkey_b64 != self.author_pubkey || address(public.as_bytes())? != self.from {
            return Err(invalid("secret key does not match the from address"));
        }
        let sighash = self.sighash()?;
        let signature: k256::ecdsa::Signature = signing_key
            .sign_prehash(&sighash)
            .map_err(|_| invalid("signing failed"))?;
        // k256 normalizes to low-S; compact bytes are r||s, matching ocore.
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        let mut unit = self.unit_value(Some(&signature_b64))?;
        let id = Self::unit_hash(&unit)?;
        unit["unit"] = json!(id);
        let wire = json!({ "unit": unit });
        let wire_json =
            serde_json::to_string(&wire).map_err(|_| invalid("wire serialization failed"))?;
        Ok((wire_json, id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET_A: [u8; 32] = [0x0a; 32];
    const SECRET_B: [u8; 32] = [0x0b; 32];

    const ADDR_A: &str = "CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B";
    const PUB_A: &str = "A/dqOdBWhuNKRCCJfjWTcYNhRd05c+OYJWi2D4Qzrd5u";
    const ADDR_B: &str = "JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ";
    const PUB_B: &str = "AlUsYwtktUv1AhDJ4lPTi9SUnHLiKHNQD2KFwr7eMSqE";

    const PARENT_1: &str = "PwPxpfwrYPDQfYuicOFTVkIiKLfdIOHRRgiUPAmBEXk=";
    const PARENT_2: &str = "kiDPph+cb8xgtphZHAif409MRyYlp8DmKaVCfnCuUgc=";
    const LAST_BALL: &str = "qUfV9bnmLQLiApJ3vWI5Gl/L7NVjsziHiLD2sappBa4=";
    const LAST_BALL_UNIT: &str = "mYm62exZUBgCYPdOHBBhEg6JNIuWDqAv/vGE/+jkd8A=";
    const INPUT_UNIT: &str = "zdr7KkULWJyBVwuXZDHybnbb/F3Q5byBwVlxgrL1mkU=";

    fn secret_pubkey(secret: &[u8; 32]) -> Vec<u8> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into()).unwrap();
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn vector_v1() -> ObyteTx {
        ObyteTx {
            chain_id: TESTNET.into(),
            from: ADDR_A.into(),
            author_pubkey: PUB_A.into(),
            to: ADDR_B.into(),
            bytes: "1000".into(),
            timestamp: 1792194192,
            tps_fee: 0,
            parent_units: vec![PARENT_1.into(), PARENT_2.into()],
            last_ball: LAST_BALL.into(),
            last_ball_unit: LAST_BALL_UNIT.into(),
            inputs: vec![ObyteInput {
                unit: INPUT_UNIT.into(),
                message_index: 0,
                output_index: 0,
                amount: "3256".into(),
            }],
            first_unit: true,
        }
    }

    fn vector_v2() -> ObyteTx {
        ObyteTx {
            chain_id: TESTNET.into(),
            from: ADDR_B.into(),
            author_pubkey: PUB_B.into(),
            to: ADDR_A.into(),
            bytes: "50".into(),
            timestamp: 1792200001,
            tps_fee: 3,
            parent_units: vec![PARENT_2.into()],
            last_ball: LAST_BALL.into(),
            last_ball_unit: LAST_BALL_UNIT.into(),
            inputs: vec![
                ObyteInput {
                    unit: INPUT_UNIT.into(),
                    message_index: 0,
                    output_index: 1,
                    amount: "1000".into(),
                },
                ObyteInput {
                    unit: PARENT_1.into(),
                    message_index: 2,
                    output_index: 0,
                    amount: "700".into(),
                },
            ],
            first_unit: false,
        }
    }

    fn intent(tx: &ObyteTx) -> TxIntent {
        TxIntent {
            id: "i".into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId(tx.chain_id.clone()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{}:native", tx.chain_id)),
                amount: Amount(tx.bytes.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    const V1_WIRE: &str = "{\"unit\":{\"alt\":\"2\",\"authors\":[{\"address\":\"CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B\",\"authentifiers\":{\"r\":\"K10wN1JJZMAnCysII9gdqeDj5EG2E916H+aTFbrXEn8gilMOR/KZTUmKl00vraVRtWJP0mXYrOrCy4e1Rf1Raw==\"},\"definition\":[\"sig\",{\"pubkey\":\"A/dqOdBWhuNKRCCJfjWTcYNhRd05c+OYJWi2D4Qzrd5u\"}]}],\"headers_commission\":469,\"last_ball\":\"qUfV9bnmLQLiApJ3vWI5Gl/L7NVjsziHiLD2sappBa4=\",\"last_ball_unit\":\"mYm62exZUBgCYPdOHBBhEg6JNIuWDqAv/vGE/+jkd8A=\",\"messages\":[{\"app\":\"payment\",\"payload\":{\"inputs\":[{\"message_index\":0,\"output_index\":0,\"unit\":\"zdr7KkULWJyBVwuXZDHybnbb/F3Q5byBwVlxgrL1mkU=\"}],\"outputs\":[{\"address\":\"CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B\",\"amount\":1476},{\"address\":\"JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ\",\"amount\":1000}]},\"payload_hash\":\"QNa67aASnpOaNnhiSVLCSmw1TcxMu4nbjAgQbfkd8R4=\",\"payload_location\":\"inline\"}],\"parent_units\":[\"PwPxpfwrYPDQfYuicOFTVkIiKLfdIOHRRgiUPAmBEXk=\",\"kiDPph+cb8xgtphZHAif409MRyYlp8DmKaVCfnCuUgc=\"],\"payload_commission\":311,\"timestamp\":1792194192,\"tps_fee\":0,\"unit\":\"HPyRHXyVdRL9AVvtXNIVbXlUj/AkWhySLVaNd+/i5BY=\",\"version\":\"4.0t\"}}";

    const V2_WIRE: &str = "{\"unit\":{\"alt\":\"2\",\"authors\":[{\"address\":\"JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ\",\"authentifiers\":{\"r\":\"SYLnnwcR7G/G6H5Gpj0qgjZDLYkEevLis6he0bVEpRInvnqhgrP0rGDMev6dGM9qMm/jLagHzArlFPxusL/s0Q==\"}}],\"headers_commission\":406,\"last_ball\":\"qUfV9bnmLQLiApJ3vWI5Gl/L7NVjsziHiLD2sappBa4=\",\"last_ball_unit\":\"mYm62exZUBgCYPdOHBBhEg6JNIuWDqAv/vGE/+jkd8A=\",\"messages\":[{\"app\":\"payment\",\"payload\":{\"inputs\":[{\"message_index\":0,\"output_index\":1,\"unit\":\"zdr7KkULWJyBVwuXZDHybnbb/F3Q5byBwVlxgrL1mkU=\"},{\"message_index\":2,\"output_index\":0,\"unit\":\"PwPxpfwrYPDQfYuicOFTVkIiKLfdIOHRRgiUPAmBEXk=\"}],\"outputs\":[{\"address\":\"CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B\",\"amount\":50},{\"address\":\"JS3E63CPEJ35EVE5SB5PISN47EJNBAXQ\",\"amount\":841}]},\"payload_hash\":\"5iTCXtL8Sbu7p1XhmklP/aWZPwfmzmHgCsBNfuudE50=\",\"payload_location\":\"inline\"}],\"parent_units\":[\"kiDPph+cb8xgtphZHAif409MRyYlp8DmKaVCfnCuUgc=\"],\"payload_commission\":400,\"timestamp\":1792200001,\"tps_fee\":3,\"unit\":\"kOfHH88PZQA09EeNDefrFmJlQljfLLsuyLeYKMKG2Ts=\",\"version\":\"4.0t\"}}";

    #[test]
    fn check_chain_accepts_only_testnet() {
        assert!(check_chain(TESTNET).is_ok());
        assert!(check_chain("obyte:mainnet").is_err());
        assert!(check_chain("").is_err());
    }

    #[test]
    fn address_derivation_matches_ocore() {
        assert_eq!(address(&secret_pubkey(&SECRET_A)).unwrap(), ADDR_A);
        assert_eq!(address(&secret_pubkey(&SECRET_B)).unwrap(), ADDR_B);
        assert!(address(&[0x02; 32]).is_err());
    }

    #[test]
    fn address_checksum_roundtrip_and_real_witnesses() {
        // Live testnet witness addresses, checksummed against ocore.
        for addr in [
            "2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX",
            "2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7",
            "DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP",
            ADDR_A,
            ADDR_B,
        ] {
            check_address(addr).unwrap();
        }
        assert!(check_address("2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GA").is_err()); // tampered
        assert!(check_address("SHORT").is_err());
        assert!(check_address("2ff7psl7fyxvu5uiqhcvdttpuoog75gx").is_err()); // lowercase
    }

    #[test]
    fn witness_definition_derives_published_address() {
        use base64::Engine;
        // Pubkey from the live testnet genesis author definition.
        let pubkey = base64::engine::general_purpose::STANDARD
            .decode("AqYvfx6o4sFL4qXVaBPUKMMpYkk8dYI9OFaT7N6RhGPq")
            .unwrap();
        assert_eq!(
            address(&pubkey).unwrap(),
            "2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX"
        );
    }

    #[test]
    fn v1_first_unit_matches_ocore_oracle() {
        let tx = vector_v1();
        let (headers, payload) = tx.fees().unwrap();
        assert_eq!(headers, 469);
        assert_eq!(payload, 311);
        assert_eq!(
            hex::encode(tx.sighash().unwrap()),
            "b53bc529d95704096f28a70d7a76ca370fe14a8a109972d640865d91ce040a61"
        );
        let (wire, id) = tx.sign(&SECRET_A).unwrap();
        assert_eq!(id, "HPyRHXyVdRL9AVvtXNIVbXlUj/AkWhySLVaNd+/i5BY=");
        assert_eq!(wire, V1_WIRE);
    }

    #[test]
    fn v2_known_address_matches_ocore_oracle() {
        let tx = vector_v2();
        let (headers, payload) = tx.fees().unwrap();
        assert_eq!(headers, 406);
        assert_eq!(payload, 400);
        assert_eq!(
            hex::encode(tx.sighash().unwrap()),
            "2eeccc6ff07ca7c1a237e24779c2cd7ddcd3b4a9c0d6ba6e7bb9c99a38fa3dfb"
        );
        let (wire, id) = tx.sign(&SECRET_B).unwrap();
        assert_eq!(id, "kOfHH88PZQA09EeNDefrFmJlQljfLLsuyLeYKMKG2Ts=");
        assert_eq!(wire, V2_WIRE);
    }

    #[test]
    fn signature_verifies_with_k256_and_is_low_s() {
        use base64::Engine;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let tx = vector_v1();
        let sighash = tx.sighash().unwrap();
        let (wire, _) = tx.sign(&SECRET_A).unwrap();
        let parsed: Value = serde_json::from_str(&wire).unwrap();
        let sig_b64 = parsed["unit"]["authors"][0]["authentifiers"]["r"]
            .as_str()
            .unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        let verifying_key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&secret_pubkey(&SECRET_A)).unwrap();
        assert!(verifying_key.verify_prehash(&sighash, &signature).is_ok());
        // low-S: normalize_s is a no-op for already-normalized signatures
        assert!(signature.normalize_s().is_none());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = vector_v1();
        assert!(base.sign(&SECRET_B).is_err());

        let mut t = base.clone();
        t.chain_id = "obyte:mainnet".into();
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.bytes = "01000".into();
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.bytes = "9000000000000001".into(); // MAX_CAP + 1
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.parent_units.clear();
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.inputs[0].amount = "1500".into(); // change would be <= 0
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.author_pubkey = PUB_B.into();
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.to = "2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GA".into(); // bad checksum
        assert!(t.sighash().is_err());

        let mut t = base.clone();
        t.timestamp = 0;
        assert!(t.sighash().is_err());

        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "authorPubkey": base.author_pubkey,
            "to": base.to, "bytes": "1", "timestamp": 1, "tpsFee": 0,
            "parentUnits": [PARENT_1], "lastBall": LAST_BALL, "lastBallUnit": LAST_BALL_UNIT,
            "inputs": [{"unit": INPUT_UNIT, "messageIndex": 0, "outputIndex": 0, "amount": "100"}],
            "firstUnit": true, "witnesses": []
        });
        assert!(serde_json::from_value::<ObyteTx>(extra).is_err());
    }

    #[test]
    fn check_matches_intent_happy_and_mismatch() {
        let tx = vector_v1();
        tx.check_matches_intent(&intent(&tx)).unwrap();

        let mut i = intent(&tx);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1001".into();
        }
        assert!(tx.check_matches_intent(&i).is_err());

        let mut i = intent(&tx);
        i.chain_id = ChainId("obyte:mainnet".into());
        assert!(tx.check_matches_intent(&i).is_err());

        let mut i = intent(&tx);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{}:asset:something", tx.chain_id);
        }
        assert!(tx.check_matches_intent(&i).is_err());
    }
}
