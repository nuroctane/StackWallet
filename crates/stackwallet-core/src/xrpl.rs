//! Native XRP payments. The core encodes the canonical binary `Payment` from
//! checked fields (no paths, no memos, no partial-payment flags, no issued
//! currencies), signs SHA-512Half of the signing prefix and those fields with a
//! low-S DER secp256k1 signature, and returns the signed blob and its hash.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::evm;
use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

pub const MAINNET: &str = "xrpl:0";
pub const TESTNET: &str = "xrpl:1";
pub const DEVNET: &str = "xrpl:2";
/// 100 billion XRP: the total supply, so no valid payment is larger.
pub const MAX_DROPS: u64 = 100_000_000_000 * 1_000_000;
/// The reference transaction cost.
pub const MIN_FEE: u32 = 10;
/// 1 XRP; open-ledger fee escalation beyond this is refused rather than silently paid.
pub const MAX_FEE: u32 = 1_000_000;
/// About two hours of ledgers; bounds how long a signed payment stays valid.
pub const MAX_LEDGER_WINDOW: u32 = 2_000;
const ACCOUNT_VERSION: u8 = 0;
const HASH_PREFIX_SIGN: [u8; 4] = *b"STX\0";
const HASH_PREFIX_TX_ID: [u8; 4] = *b"TXN\0";
const PAYMENT: u16 = 0;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "XRPL payment",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only XRP Ledger testnet payments are enabled"));
    }
    Ok(())
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = Sha256::digest(Sha256::digest(payload));
    [h[0], h[1], h[2], h[3]]
}

pub fn encode_address(account: &[u8; 20]) -> String {
    let mut raw = Vec::with_capacity(25);
    raw.push(ACCOUNT_VERSION);
    raw.extend_from_slice(account);
    let sum = checksum(&raw);
    raw.extend_from_slice(&sum);
    bs58::encode(raw)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

/// The 20-byte AccountID behind a classic `r…` address. X-addresses, seeds and
/// the black-hole accounts zero and one are refused.
pub fn address_bytes(address: &str) -> Result<[u8; 20]> {
    if !(25..=35).contains(&address.len()) || !address.starts_with('r') {
        return Err(invalid("address must be a classic r… account"));
    }
    let raw = bs58::decode(address)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .map_err(|_| invalid("invalid base58 address"))?;
    if raw.len() != 25 || raw[0] != ACCOUNT_VERSION {
        return Err(invalid("not an XRPL account address"));
    }
    if raw[21..] != checksum(&raw[..21]) {
        return Err(invalid("address checksum mismatch"));
    }
    let account: [u8; 20] = raw[1..21].try_into().expect("20 bytes");
    let mut one = [0u8; 20];
    one[19] = 1;
    if account == [0u8; 20] || account == one {
        return Err(invalid("address is an unspendable special account"));
    }
    if encode_address(&account) != address {
        return Err(invalid("non-canonical address"));
    }
    Ok(account)
}

pub fn address(public: &[u8]) -> Result<String> {
    let key = k256::PublicKey::from_sec1_bytes(public)
        .map_err(|_| invalid("invalid secp256k1 public key"))?;
    let hash = Ripemd160::digest(Sha256::digest(key.to_encoded_point(true).as_bytes()));
    Ok(encode_address(&hash.into()))
}

fn sha512_half(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let full = h.finalize();
    full[..32].try_into().expect("32 bytes")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XrplTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal drops (1 XRP = 1,000,000 drops); never a JSON floating-point number.
    pub drops: String,
    /// Transaction cost in drops.
    pub fee: u32,
    /// The sender account's current `Sequence`.
    pub sequence: u32,
    /// Last ledger in which the payment may be included; the network drops it after.
    pub last_ledger_sequence: u32,
    /// Ledger index the adapter built against; bounds `last_ledger_sequence`, not encoded.
    pub built_at_ledger: u32,
    /// Routes the payment inside a shared (exchange or custodial) account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_tag: Option<u32>,
    /// Compressed SEC1 secp256k1 key of `from`, lowercase hex; encoded as `SigningPubKey`.
    pub public_key_hex: String,
}

fn field_u32(out: &mut Vec<u8>, header: &[u8], v: u32) {
    out.extend_from_slice(header);
    out.extend_from_slice(&v.to_be_bytes());
}

fn field_xrp(out: &mut Vec<u8>, header: u8, drops: u64) {
    out.push(header);
    // Bit 63 clear marks native XRP, bit 62 set marks a positive amount.
    out.extend_from_slice(&(0x4000_0000_0000_0000 | drops).to_be_bytes());
}

fn field_vl(out: &mut Vec<u8>, header: u8, bytes: &[u8]) {
    // Every blob here is far below 193 bytes, the limit of a one-byte length prefix.
    debug_assert!(bytes.len() <= 192);
    out.push(header);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

impl XrplTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native XRP payments are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.drops {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported XRPL intent")),
        }
        self.fields(None)?;
        Ok(())
    }

    fn public_key(&self) -> Result<[u8; 33]> {
        let raw =
            hex::decode(&self.public_key_hex).map_err(|_| invalid("public key is not hex"))?;
        if hex::encode(&raw) != self.public_key_hex {
            return Err(invalid("public key must be lowercase hex"));
        }
        let key: [u8; 33] = raw
            .try_into()
            .map_err(|_| invalid("public key must be 33 compressed bytes"))?;
        if address(&key)? != self.from {
            return Err(invalid("public key does not belong to the sender"));
        }
        Ok(key)
    }

    /// Canonical binary fields in field-id order, with `TxnSignature` when given.
    fn fields(&self, signature: Option<&[u8]>) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let drops = self
            .drops
            .parse::<u64>()
            .map_err(|_| invalid("amount is not a decimal integer"))?;
        if drops == 0 || drops > MAX_DROPS || drops.to_string() != self.drops {
            return Err(invalid(
                "amount must be canonical drops within the XRP supply",
            ));
        }
        if !(MIN_FEE..=MAX_FEE).contains(&self.fee) {
            return Err(invalid("fee is outside the accepted range"));
        }
        if self.sequence == 0 {
            return Err(invalid("sequence must be positive"));
        }
        if self.built_at_ledger == 0
            || self.last_ledger_sequence <= self.built_at_ledger
            || self.last_ledger_sequence - self.built_at_ledger > MAX_LEDGER_WINDOW
        {
            return Err(invalid(
                "lastLedgerSequence must fall shortly after the build ledger",
            ));
        }
        let public = self.public_key()?;

        let mut out = Vec::with_capacity(240);
        // TransactionType (UInt16, field 2)
        out.push(0x12);
        out.extend_from_slice(&PAYMENT.to_be_bytes());
        // Flags (UInt32, 2): none, so no partial payment.
        field_u32(&mut out, &[0x22], 0);
        // Sequence (UInt32, 4)
        field_u32(&mut out, &[0x24], self.sequence);
        // DestinationTag (UInt32, 14)
        if let Some(tag) = self.destination_tag {
            field_u32(&mut out, &[0x2e], tag);
        }
        // LastLedgerSequence (UInt32, 27)
        field_u32(&mut out, &[0x20, 0x1b], self.last_ledger_sequence);
        // Amount (Amount, 1) and Fee (Amount, 8)
        field_xrp(&mut out, 0x61, drops);
        field_xrp(&mut out, 0x68, u64::from(self.fee));
        // SigningPubKey (Blob, 3) and TxnSignature (Blob, 4)
        field_vl(&mut out, 0x73, &public);
        if let Some(sig) = signature {
            field_vl(&mut out, 0x74, sig);
        }
        // Account (AccountID, 1) and Destination (AccountID, 3)
        field_vl(&mut out, 0x81, &from);
        field_vl(&mut out, 0x83, &to);
        Ok(out)
    }

    /// The single-signing payload: `STX\0` followed by the unsigned fields.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let mut out = HASH_PREFIX_SIGN.to_vec();
        out.extend_from_slice(&self.fields(None)?);
        Ok(out)
    }

    /// SHA-512Half of the signing payload: the 32-byte digest the ECDSA signature covers.
    pub fn signing_hash(&self) -> Result<[u8; 32]> {
        Ok(sha512_half(&[&self.signing_payload()?]))
    }

    /// Returns the signed blob as `0x` hex and the transaction hash as uppercase hex.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key =
            SigningKey::from_bytes(secret.into()).map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from
            || hex::encode(public.as_bytes()) != self.public_key_hex
        {
            return Err(invalid("sender differs from signing key"));
        }
        let (_, r, s) = evm::sign_digest(secret, &self.signing_hash()?)?;
        let sig = Signature::from_scalars(r, s).map_err(|_| invalid("invalid signature"))?;
        self.assemble(sig.to_der().as_bytes())
    }

    /// The signed blob for a DER signature made elsewhere (a threshold ceremony),
    /// accepted only if it is low-S and verifies against `publicKeyHex`.
    pub fn assemble(&self, der: &[u8]) -> Result<(String, String)> {
        let digest = self.signing_hash()?;
        let sig = Signature::from_der(der).map_err(|_| invalid("signature is not strict DER"))?;
        if sig.normalize_s().is_some() || sig.to_der().as_bytes() != der {
            return Err(invalid("signature must be canonical low-S DER"));
        }
        let key = VerifyingKey::from_sec1_bytes(&self.public_key()?)
            .map_err(|_| invalid("invalid public key"))?;
        key.verify_prehash(&digest, &sig)
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let blob = self.fields(Some(der))?;
        let hash = sha512_half(&[&HASH_PREFIX_TX_ID, &blob]);
        Ok((format!("0x{}", hex::encode(blob)), hex::encode_upper(hash)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const ONE: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    /// `ripple-keypairs.deriveAddress` of the generator point G (secret key 1).
    const ONE_ADDRESS: &str = "rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH";
    const ONE_PUBLIC: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const RECIPIENT: &str = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

    fn tx() -> XrplTx {
        XrplTx {
            chain_id: TESTNET.into(),
            from: ONE_ADDRESS.into(),
            to: RECIPIENT.into(),
            drops: "1500000".into(),
            fee: 12,
            sequence: 1_234_567,
            last_ledger_sequence: 21_564_000,
            built_at_ledger: 21_563_550,
            destination_tag: Some(12345),
            public_key_hex: ONE_PUBLIC.into(),
        }
    }

    fn intent(tx: &XrplTx) -> TxIntent {
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
                amount: Amount(tx.drops.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn addresses_match_published_vectors() {
        let key = SigningKey::from_bytes((&ONE).into()).unwrap();
        let public = key.verifying_key().to_encoded_point(true);
        assert_eq!(hex::encode(public.as_bytes()), ONE_PUBLIC);
        assert_eq!(address(public.as_bytes()).unwrap(), ONE_ADDRESS);
        // The genesis account from the XRPL docs (master seed snoPBrXtMeMyMHUVTgbuqAfg1SUTb).
        let genesis =
            hex::decode("0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020")
                .unwrap();
        assert_eq!(
            address(&genesis).unwrap(),
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        );
        let uncompressed = key.verifying_key().to_encoded_point(false);
        assert_eq!(address(uncompressed.as_bytes()).unwrap(), ONE_ADDRESS);
        assert!(address(&[5u8; 33]).is_err());
        assert_eq!(
            encode_address(&address_bytes(RECIPIENT).unwrap()),
            RECIPIENT
        );
    }

    #[test]
    fn bad_addresses_are_refused() {
        assert!(address_bytes("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYf").is_err());
        assert!(address_bytes("XVLhHMPHU98es4dbozjVtdWzVrDjtV18pX8yuPT7y4xaEHi").is_err());
        assert!(address_bytes("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").is_err());
        // ACCOUNT_ZERO and ACCOUNT_ONE black holes.
        assert!(address_bytes("rrrrrrrrrrrrrrrrrrrrrhoLvTp").is_err());
        assert!(address_bytes("rrrrrrrrrrrrrrrrrrrrBZbvji").is_err());
        assert!(address_bytes("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").is_err());
        assert!(address_bytes(" rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").is_err());
    }

    /// Checked against `ripple-binary-codec` `encodeForSigning`/`encode`,
    /// `ripple-keypairs.sign` and `xrpl` `hashes.hashSignedTx` for the same
    /// fields (`.nur/xrpl-sdk/vector.mjs`); the TypeScript adapter pins the same bytes.
    #[test]
    fn blob_matches_the_sdk_vectors() {
        let t = tx();
        assert_eq!(
            hex::encode_upper(t.signing_payload().unwrap()),
            TAG_SIGNING_VECTOR
        );
        let (wire, hash) = t.sign(&ONE).unwrap();
        assert_eq!(wire, format!("0x{}", TAG_BLOB_VECTOR.to_lowercase()));
        assert_eq!(hash, TAG_HASH_VECTOR);
        let untagged = XrplTx {
            destination_tag: None,
            ..t
        };
        assert_eq!(
            hex::encode_upper(untagged.signing_payload().unwrap()),
            SIGNING_VECTOR
        );
        let (wire, hash) = untagged.sign(&ONE).unwrap();
        assert_eq!(wire, format!("0x{}", BLOB_VECTOR.to_lowercase()));
        assert_eq!(hash, HASH_VECTOR);
    }
    const TAG_SIGNING_VECTOR: &str = "535458001200002200000000240012D6872E00003039201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817988114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8";
    const TAG_BLOB_VECTOR: &str = "1200002200000000240012D6872E00003039201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F8179874463044022059D7EFE1EDC50C6A8CD48DA5DD29BA0E959E317D2DE7F317A365CF20790FBDBF02203E04418A7B5925331F805BD0662C7CC07B864BF63ACA83E5295ECEBCD660E2CB8114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8";
    const TAG_HASH_VECTOR: &str =
        "2F4B4D918AB68BF6A51D0388BC07F6411814CD67CC6702BD3D9308AEB28A03B5";
    const SIGNING_VECTOR: &str = "535458001200002200000000240012D687201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817988114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8";
    const BLOB_VECTOR: &str = "1200002200000000240012D687201B01490A6061400000000016E36068400000000000000C73210279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817987446304402204642E4ECDB7CE25974D21CF06F3920982BC2CE36F985B666F0AF6EE790467563022074486FE5A9E8440D584CE89703E44762BDE755E80A36E6106F35DE4CC3BD2F998114751E76E8199196D454941C45D1B3A323F1433BD68314F667B0CA50CC7709A220B0561B85E53A48461FA8";
    const HASH_VECTOR: &str = "495B5003C925F46D0EFD2D37D98433AD5E6DFC9AFBDBE647541713557EF4A93C";

    #[test]
    fn signature_verifies_over_the_signing_hash() {
        let secret = [7u8; 32];
        let key = SigningKey::from_bytes((&secret).into()).unwrap();
        let public = key.verifying_key().to_encoded_point(true);
        let t = XrplTx {
            from: address(public.as_bytes()).unwrap(),
            public_key_hex: hex::encode(public.as_bytes()),
            ..tx()
        };
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, hash) = t.sign(&secret).unwrap();
        let blob = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let unsigned = t.fields(None).unwrap();
        // The signature sits between SigningPubKey and Account.
        let split = unsigned.len() - 44;
        assert_eq!(blob[..split], unsigned[..split]);
        assert_eq!(blob[blob.len() - 44..], unsigned[split..]);
        assert_eq!(blob[split], 0x74);
        let der = &blob[split + 2..split + 2 + blob[split + 1] as usize];
        let sig = Signature::from_der(der).unwrap();
        assert!(sig.normalize_s().is_none());
        key.verifying_key()
            .verify_prehash(&t.signing_hash().unwrap(), &sig)
            .unwrap();
        assert_eq!(
            hash,
            hex::encode_upper(sha512_half(&[&HASH_PREFIX_TX_ID, &blob]))
        );
        // A high-S twin of a valid signature is refused.
        let (r, s) = sig.split_scalars();
        let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        assert!(t.assemble(high.to_der().as_bytes()).is_err());
        assert!(tx().assemble(der).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        base.check_matches_intent(&intent(&base)).unwrap();
        for chain in [MAINNET, DEVNET, "xrpl:01", "eip155:1"] {
            let mut t = base.clone();
            t.chain_id = chain.into();
            assert!(t.signing_payload().is_err());
            assert!(check_chain(chain).is_err());
        }
        for drops in ["0", "01500000", "-1", "1.5", "100000000000000001"] {
            let mut t = base.clone();
            t.drops = drops.into();
            assert!(t.signing_payload().is_err(), "{drops}");
        }
        let mut t = base.clone();
        t.drops = MAX_DROPS.to_string();
        assert!(t.signing_payload().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.signing_payload().is_err());
        let mut t = base.clone();
        t.fee = MIN_FEE - 1;
        assert!(t.signing_payload().is_err());
        t.fee = MAX_FEE + 1;
        assert!(t.signing_payload().is_err());
        let mut t = base.clone();
        t.sequence = 0;
        assert!(t.signing_payload().is_err());
        let mut t = base.clone();
        t.last_ledger_sequence = t.built_at_ledger;
        assert!(t.signing_payload().is_err());
        t.last_ledger_sequence = t.built_at_ledger + MAX_LEDGER_WINDOW + 1;
        assert!(t.signing_payload().is_err());
        let mut t = base.clone();
        t.public_key_hex = ONE_PUBLIC.to_uppercase();
        assert!(t.signing_payload().is_err());
        t.public_key_hex = format!("03{}", &ONE_PUBLIC[2..]);
        assert!(t.signing_payload().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = "xrpl:1:iou:USD".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        assert!(base.sign(&[7u8; 32]).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "drops": "1",
            "fee": 12, "sequence": 1, "lastLedgerSequence": 3, "builtAtLedger": 2,
            "publicKeyHex": ONE_PUBLIC, "memo": "hi"
        });
        assert!(serde_json::from_value::<XrplTx>(extra).is_err());
        let ok = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "drops": "1",
            "fee": 12, "sequence": 1, "lastLedgerSequence": 3, "builtAtLedger": 2,
            "publicKeyHex": ONE_PUBLIC
        });
        let parsed: XrplTx = serde_json::from_value(ok).unwrap();
        assert_eq!(parsed.destination_tag, None);
        assert!(parsed.signing_payload().is_ok());
    }
}
