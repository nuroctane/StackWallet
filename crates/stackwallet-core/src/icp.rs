//! Native ICP transfers on the Internet Computer. The core derives the
//! self-authenticating principal and the legacy-ledger account identifier from
//! the secp256k1 public key, encodes the Candid `TransferArgs` and the CBOR
//! call envelope itself from checked fields, and signs
//! `sha256("\x0Aic-request" || request_id)`.
//!
//! ICP has no public testnet ledger (dfx replicas are local-only), so the
//! usual testnet gate has no network to point at: the single mainnet id is
//! the only chain accepted, and every signed field is bounded instead. The
//! fee is fixed at the ledger's 10_000 e8s so an adapter cannot inflate it.

use crc::{Crc, CRC_32_ISO_HDLC};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha224, Sha256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// No registered CAIP-2 namespace exists for ICP; the reference is the Rosetta
/// network identifier of the single mainnet.
pub const MAINNET: &str = "icp:00000000000000000000";
/// ryjl3-tyaaa-aaaaa-aaaba-cai, the ICP ledger canister.
pub const LEDGER_CANISTER: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 2, 1, 1];
/// DER wrapping for an uncompressed secp256k1 key (id-ecPublicKey + secp256k1
/// OID), as the IC expects `sender_pubkey`.
const DER_PREFIX: [u8; 23] = [
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
];
/// The ledger's fixed transfer fee.
pub const FEE_E8S: u64 = 10_000;
/// Well under the ~470M ICP supply; anything larger is a bug, not a payment.
const MAX_E8S: u64 = 500_000_000_000_000_000;
/// The replica drops requests whose ingress expiry is too far in the future.
const MAX_INGRESS_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "ICP transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // ICP has no public testnet ledger; mainnet is the only network that
    // exists, so it is the only chain id accepted.
    if chain != MAINNET {
        return Err(invalid("unknown Internet Computer network"));
    }
    Ok(())
}

/// DER-wrapped uncompressed secp256k1 public key from a 33-byte SEC1 key.
pub fn der_public_key(public: &[u8]) -> Result<[u8; 88]> {
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| invalid("invalid secp256k1 public key"))?;
    let point = key.to_encoded_point(false);
    let mut der = [0u8; 88];
    der[..23].copy_from_slice(&DER_PREFIX);
    der[23..].copy_from_slice(point.as_bytes());
    Ok(der)
}

/// Self-authenticating principal: `sha224(der) || 0x02`.
pub fn principal(public: &[u8]) -> Result<[u8; 29]> {
    let digest = Sha224::digest(der_public_key(public)?);
    let mut out = [0u8; 29];
    out[..28].copy_from_slice(&digest);
    out[28] = 0x02;
    Ok(out)
}

/// `crc32(h) || h` with `h = sha224("\x0Aaccount-id" || principal || subaccount)`.
pub fn account_identifier(principal: &[u8; 29], subaccount: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(11 + 29 + 32);
    input.push(0x0a);
    input.extend_from_slice(b"account-id");
    input.extend_from_slice(principal);
    input.extend_from_slice(subaccount);
    let digest = Sha224::digest(&input);
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&CRC32.checksum(&digest).to_be_bytes());
    out[4..].copy_from_slice(&digest);
    out
}

/// The default-subaccount account identifier of the key, as 64 lowercase hex.
pub fn address(public: &[u8]) -> Result<String> {
    let principal = principal(public)?;
    Ok(hex::encode(account_identifier(&principal, &[0u8; 32])))
}

/// Parses a 64-hex account identifier and verifies its crc32 prefix.
pub fn account_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() != 64 || address.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(invalid(
            "account identifier must be 64 lowercase hex characters",
        ));
    }
    let bytes: [u8; 32] = hex::decode(address)
        .map_err(|_| invalid("account identifier is not hex"))?
        .try_into()
        .expect("32 bytes");
    let (check, digest) = bytes.split_at(4);
    if CRC32.checksum(digest).to_be_bytes() != check {
        return Err(invalid("account identifier checksum mismatch"));
    }
    if bytes == [0; 32] {
        return Err(invalid("zero account identifier"));
    }
    Ok(bytes)
}

fn canonical_u64(value: &str, what: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{what} must be a decimal u64")))?;
    if n.to_string() != value {
        return Err(invalid(format!("{what} must be canonical decimal")));
    }
    Ok(n)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IcpTx {
    pub chain_id: String,
    /// Sender account identifier (64 lowercase hex), default subaccount.
    pub from: String,
    /// Recipient account identifier.
    pub to: String,
    /// Decimal e8s (1 ICP = 100,000,000 e8s); the fee is a fixed 10_000.
    pub e8s: String,
    /// Ledger memo; 0 when unused.
    pub memo: u64,
    /// Nanoseconds since the Unix epoch, as canonical decimal (exceeds 2^53).
    pub created_at_nanos: String,
    /// Nanoseconds after which the replica drops the request, canonical decimal.
    pub ingress_expiry_nanos: String,
}

fn leb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// --- minimal deterministic CBOR (definite lengths, lexicographic keys) ------

enum Cbor {
    Bytes(Vec<u8>),
    Text(&'static str),
    /// Positive bignum (tag 2) over minimal big-endian bytes.
    Bignum(Vec<u8>),
    Map(Vec<(&'static str, Cbor)>),
}

fn cbor_head(major: u8, len: u64, out: &mut Vec<u8>) {
    if len < 24 {
        out.push(major << 5 | len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[major << 5 | 24, len as u8]);
    } else {
        out.extend_from_slice(&[major << 5 | 25]);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn cbor_encode(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Bytes(bytes) => {
            cbor_head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Cbor::Text(text) => {
            cbor_head(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        Cbor::Bignum(be) => {
            out.push(0xc2);
            cbor_head(2, be.len() as u64, out);
            out.extend_from_slice(be);
        }
        Cbor::Map(entries) => {
            cbor_head(5, entries.len() as u64, out);
            let mut entries: Vec<_> = entries.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            for (key, value) in entries {
                cbor_encode(&Cbor::Text(key), out);
                cbor_encode(value, out);
            }
        }
    }
}

fn bignum(value: u64) -> Cbor {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    Cbor::Bignum(bytes[first..].to_vec())
}

struct Checked {
    to: [u8; 32],
    amount: u64,
    created: u64,
    expiry: u64,
}

impl IcpTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ICP transfers are enabled"));
                }
                if account_bytes(to)? != account_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.e8s {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported ICP intent")),
        }
        self.checked_fields()?;
        Ok(())
    }

    /// Bounds-checked field values shared by encoding and signing.
    fn checked_fields(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = account_bytes(&self.from)?;
        let to = account_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_u64(&self.e8s, "amount")?;
        if amount == 0 || amount > MAX_E8S {
            return Err(invalid("amount is out of range"));
        }
        let created = canonical_u64(&self.created_at_nanos, "created_at_time")?;
        let expiry = canonical_u64(&self.ingress_expiry_nanos, "ingress expiry")?;
        if created == 0 || expiry <= created || expiry - created > MAX_INGRESS_WINDOW_NS {
            return Err(invalid(
                "ingress expiry must fall within ten minutes of created_at_time",
            ));
        }
        if created > i64::MAX as u64 || expiry > i64::MAX as u64 {
            return Err(invalid("timestamps must fit int64 nanos"));
        }
        Ok(Checked {
            to,
            amount,
            created,
            expiry,
        })
    }

    /// Candid encoding of the legacy ledger `TransferArgs`, pinned byte-for-byte
    /// against @dfinity/candid `IDL.encode` in the tests below.
    pub fn candid_args(&self) -> Result<Vec<u8>> {
        let checked = self.checked_fields()?;
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"DIDL");
        out.push(6); // type table entries
        out.extend_from_slice(&[0x6d, 0x7b]); // t0 = vec nat8
        out.extend_from_slice(&[0x6c, 0x01, 0xe0, 0xa9, 0xb3, 0x02, 0x78]); // t1 = record { e8s: nat64 }
        out.extend_from_slice(&[0x6e, 0x00]); // t2 = opt t0
        out.extend_from_slice(&[0x6c, 0x01, 0xd6, 0xf6, 0x8e, 0x80, 0x01, 0x78]); // t3 = record { timestamp_nanos: nat64 }
        out.extend_from_slice(&[0x6e, 0x03]); // t4 = opt t3
                                              // t5 = record { to: t0; fee: t1; memo: nat64; from_subaccount: t2; created_at_time: t4; amount: t1 }
        out.extend_from_slice(&[
            0x6c, 0x06, 0xfb, 0xca, 0x01, 0x00, 0xc6, 0xfc, 0xb6, 0x02, 0x01, 0xba, 0x89, 0xe5,
            0xc2, 0x04, 0x78, 0xa2, 0xde, 0x94, 0xeb, 0x06, 0x02, 0x82, 0xf3, 0xf3, 0x91, 0x0c,
            0x04, 0xd8, 0xa3, 0x8c, 0xa8, 0x0d, 0x01,
        ]);
        out.extend_from_slice(&[0x01, 0x05]); // one argument of type 5
        out.extend_from_slice(&leb128(32));
        out.extend_from_slice(&checked.to);
        out.extend_from_slice(&FEE_E8S.to_le_bytes());
        out.extend_from_slice(&self.memo.to_le_bytes());
        out.push(0x00); // from_subaccount: none (default subaccount)
        out.push(0x01); // created_at_time: some
        out.extend_from_slice(&checked.created.to_le_bytes());
        out.extend_from_slice(&checked.amount.to_le_bytes());
        Ok(out)
    }

    /// Request id of the call content for a given sender principal, per the
    /// IC spec's hash-of-map construction.
    pub fn request_id(&self, sender: &[u8; 29]) -> Result<[u8; 32]> {
        let expiry = self.checked_fields()?.expiry;
        let arg = self.candid_args()?;
        let pairs: [(&str, Vec<u8>); 6] = [
            ("arg", arg),
            ("canister_id", LEDGER_CANISTER.to_vec()),
            ("ingress_expiry", leb128(expiry)),
            ("method_name", b"transfer".to_vec()),
            ("request_type", b"call".to_vec()),
            ("sender", sender.to_vec()),
        ];
        let mut hashed: Vec<[u8; 64]> = pairs
            .iter()
            .map(|(k, v)| {
                let mut pair = [0u8; 64];
                pair[..32].copy_from_slice(&sha256(k.as_bytes()));
                pair[32..].copy_from_slice(&sha256(v));
                pair
            })
            .collect();
        hashed.sort();
        let mut flat = Vec::with_capacity(64 * hashed.len());
        for pair in &hashed {
            flat.extend_from_slice(pair);
        }
        Ok(sha256(&flat))
    }

    /// The CBOR envelope (tag 55799, sorted keys) posted to
    /// `/api/v3/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/call`.
    pub fn envelope(&self, sender_der: &[u8; 88], signature: &[u8; 64]) -> Result<Vec<u8>> {
        let expiry = self.checked_fields()?.expiry;
        let arg = self.candid_args()?;
        let sender = {
            let digest = Sha224::digest(sender_der);
            let mut p = [0u8; 29];
            p[..28].copy_from_slice(&digest);
            p[28] = 0x02;
            p
        };
        if account_identifier(&sender, &[0u8; 32]) != account_bytes(&self.from)? {
            return Err(invalid(
                "sender public key does not match the sender account",
            ));
        }
        let content = Cbor::Map(vec![
            ("request_type", Cbor::Text("call")),
            ("canister_id", Cbor::Bytes(LEDGER_CANISTER.to_vec())),
            ("method_name", Cbor::Text("transfer")),
            ("arg", Cbor::Bytes(arg)),
            ("sender", Cbor::Bytes(sender.to_vec())),
            ("ingress_expiry", bignum(expiry)),
        ]);
        let envelope = Cbor::Map(vec![
            ("content", content),
            ("sender_pubkey", Cbor::Bytes(sender_der.to_vec())),
            ("sender_sig", Cbor::Bytes(signature.to_vec())),
        ]);
        let mut out = vec![0xd9, 0xd9, 0xf7]; // self-describe CBOR
        cbor_encode(&envelope, &mut out);
        Ok(out)
    }

    /// Signs the request. Returns the CBOR envelope as `0x`-hex (POST body for
    /// the v3 call endpoint) and the request id hex. ICP transfers have no
    /// tx hash; the ledger assigns a block height, which the broadcast call
    /// response carries back.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let der = der_public_key(public.as_bytes())?;
        let sender = principal(public.as_bytes())?;
        let request_id = self.request_id(&sender)?;
        let mut preimage = Vec::with_capacity(43);
        preimage.extend_from_slice(b"\x0Aic-request");
        preimage.extend_from_slice(&request_id);
        let sighash = sha256(&preimage);
        let (_, r, s) = evm::sign_digest(secret, &sighash)?;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        let wire = self.envelope(&der, &signature)?;
        Ok((format!("0x{}", hex::encode(wire)), hex::encode(request_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// Vectors pinned against @dfinity/identity-secp256k1, @dfinity/ledger-icp,
    /// @dfinity/candid and @dfinity/agent 2.4.1 (probe: .nur/icp-sdk/probe3.mjs).
    const KEY7_DER: &str = "3056301006072a8648ce3d020106052b8104000a03420004989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f631f4d05b3ae518776ee08755a7703e64b2ebc32547504de0b55a142d4ecdf80";
    const KEY7_PRINCIPAL: &str = "ebb18233c45a50841a64c0076e3ea4a3bfa332c603cb2362436985db02";
    const KEY7_ACCOUNT: &str = "b7350197f5cc3597b65d5647d94b48b6d5e6a3ec7760e3bc91baba0b4597bdb5";
    const KEY1_ACCOUNT: &str = "1a230b1734a5a64feba98d21979a3d9384c92e27e6bba1fdd29c6028003764c3";
    const CANDID_VECTOR: &str = "4449444c066d7b6c01e0a9b302786e006c01d6f68e8001786e036c06fbca0100c6fcb60201ba89e5c20478a2de94eb060282f3f3910c04d8a38ca80d010105201a230b1734a5a64feba98d21979a3d9384c92e27e6bba1fdd29c6028003764c310270000000000002a0000000000000000010000b0d4acc66c1860e3160000000000";
    const REQUEST_ID: &str = "958da04033ffa8369aa967501b442ef0427e81a409d26bb51e0a505a100538a4";
    const SIGNATURE: &str = "ca80b129e0970d7293a17e8b36733c4cae9faf56ca90ac6100127947ef17425822ef37856290d53ac574ae53056c28a60961746a21ec592cc2f45d69a6cc6aca";

    fn sender() -> String {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn tx() -> IcpTx {
        IcpTx {
            chain_id: MAINNET.into(),
            from: sender(),
            to: KEY1_ACCOUNT.into(),
            e8s: "1500000".into(),
            memo: 42,
            created_at_nanos: "1760000000000000000".into(),
            ingress_expiry_nanos: "1760000300000000000".into(),
        }
    }

    fn intent(tx: &IcpTx) -> TxIntent {
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
                amount: Amount(tx.e8s.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn key_material_matches_the_dfinity_sdk() {
        let key = k256::ecdsa::SigningKey::from_bytes((&SECRET).into()).unwrap();
        let sec1 = key.verifying_key().to_encoded_point(true);
        assert_eq!(
            hex::encode(der_public_key(sec1.as_bytes()).unwrap()),
            KEY7_DER
        );
        assert_eq!(
            hex::encode(principal(sec1.as_bytes()).unwrap()),
            KEY7_PRINCIPAL
        );
        assert_eq!(address(sec1.as_bytes()).unwrap(), KEY7_ACCOUNT);
        // Private key 1's account id, from @dfinity/ledger-icp.
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = k256::ecdsa::SigningKey::from_bytes((&one).into()).unwrap();
        let addr = address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap();
        assert_eq!(addr, KEY1_ACCOUNT);
        assert_eq!(hex::encode(account_bytes(&addr).unwrap()), addr);
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        let mut upper = KEY1_ACCOUNT.to_uppercase();
        assert!(account_bytes(&upper).is_err());
        upper = KEY1_ACCOUNT.to_string();
        assert!(account_bytes(&upper[..62]).is_err());
        // Flip one nibble: the crc32 prefix no longer matches the digest.
        let mut bad = KEY1_ACCOUNT.to_string();
        bad.replace_range(62..64, "00");
        assert!(account_bytes(&bad).is_err());
        assert!(account_bytes(&hex::encode([0u8; 32])).is_err());
        assert!(account_bytes("0x1a230b17").is_err());
    }

    #[test]
    fn candid_args_match_idl_encode() {
        assert_eq!(hex::encode(tx().candid_args().unwrap()), CANDID_VECTOR);
    }

    #[test]
    fn request_id_matches_agent_js() {
        let sender: [u8; 29] = hex::decode(KEY7_PRINCIPAL).unwrap().try_into().unwrap();
        assert_eq!(hex::encode(tx().request_id(&sender).unwrap()), REQUEST_ID);
    }

    #[test]
    fn signature_and_envelope_match_agent_js_byte_for_byte() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        assert_eq!(id, REQUEST_ID);
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        // The signature is deterministic (RFC 6979, low-s) and pins the whole
        // envelope: identical bytes to @dfinity/agent's Cbor.encode output.
        assert!(hex::encode(&wire).contains(SIGNATURE));
        let der: [u8; 88] = hex::decode(KEY7_DER).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(SIGNATURE).unwrap().try_into().unwrap();
        assert_eq!(t.envelope(&der, &sig).unwrap(), wire);
        // The replica verifies secp256k1 over sha256("\x0Aic-request" || request_id).
        let mut preimage = b"\x0Aic-request".to_vec();
        preimage.extend_from_slice(&hex::decode(REQUEST_ID).unwrap());
        let sighash = sha256(&preimage);
        assert_eq!(
            hex::encode(sighash),
            "ea14bfb30beaa175fda4f1a73723ecddce139c4d57700e11b7630ec7028704df"
        );
        let verifying = *k256::ecdsa::SigningKey::from_bytes((&SECRET).into())
            .unwrap()
            .verifying_key();
        let signature = k256::ecdsa::Signature::from_slice(&sig).unwrap();
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        assert!(verifying.verify_prehash(&sighash, &signature).is_ok());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "icp:testnet".into();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.e8s = "01500000".into();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.e8s = "0".into();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.e8s = (MAX_E8S + 1).to_string();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.ingress_expiry_nanos = t.created_at_nanos.clone();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.ingress_expiry_nanos =
            (1_760_000_000_000_000_000 + MAX_INGRESS_WINDOW_NS + 1).to_string();
        assert!(t.candid_args().is_err());
        let mut t = base.clone();
        t.to = t.to.to_uppercase();
        assert!(t.candid_args().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = KEY1_ACCOUNT.into();
        other.to = sender();
        assert!(other.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": MAINNET, "from": base.from, "to": base.to, "e8s": "1",
            "memo": 0, "createdAtNanos": "1", "ingressExpiryNanos": "2", "subaccount": "00"
        });
        assert!(serde_json::from_value::<IcpTx>(extra).is_err());
    }
}
