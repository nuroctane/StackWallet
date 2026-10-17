//! Native STX transfers. The core serializes the whole SIP-005 transaction from
//! checked fields: a standard single-sig P2PKH spending condition, anchor mode
//! any, post-condition mode deny with no post conditions, a token-transfer
//! payload and an empty memo. An adapter cannot add contract calls, sponsors or
//! post conditions.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512_256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{evm, CoreError, Result};

/// CAIP-2 references are the network id `/v2/info` reports (testnet 0x80000000).
pub const TESTNET: &str = "stacks:2147483648";
const TX_VERSION_TESTNET: u8 = 0x80;
const CHAIN_ID_TESTNET: u32 = 0x8000_0000;
const VERSION_P2PKH_TESTNET: u8 = 26;
const VERSION_P2SH_TESTNET: u8 = 21;
const AUTH_STANDARD: u8 = 0x04;
const HASH_MODE_P2PKH: u8 = 0x00;
const KEY_COMPRESSED: u8 = 0x00;
const ANCHOR_ANY: u8 = 0x03;
const POST_CONDITION_DENY: u8 = 0x02;
const PAYLOAD_TOKEN_TRANSFER: u8 = 0x00;
const PRINCIPAL_STANDARD: u8 = 0x05;
const MEMO_LEN: usize = 34;
/// A plain transfer is ~180 bytes; even a congested mempool prices it far below 1 STX.
pub const MAX_FEE: u64 = 1_000_000;
const MAX_NONCE: u64 = (1 << 53) - 1;
const C32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Stacks transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Stacks testnet transfers are enabled"));
    }
    Ok(())
}

fn c32_encode(data: &[u8]) -> String {
    let mut digits = Vec::new();
    let mut num = data.to_vec();
    while num.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        for byte in num.iter_mut() {
            let acc = (rem << 8) | u32::from(*byte);
            *byte = (acc / 32) as u8;
            rem = acc % 32;
        }
        digits.push(C32[rem as usize]);
    }
    let zeros = data.iter().take_while(|b| **b == 0).count();
    digits.extend(std::iter::repeat_n(b'0', zeros));
    digits.reverse();
    String::from_utf8(digits).expect("ascii")
}

fn c32_decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text.bytes().take_while(|c| *c == b'0').count();
    let mut num: Vec<u8> = Vec::new();
    for c in text.bytes().skip(zeros) {
        let mut carry = C32.iter().position(|x| *x == c)? as u32;
        for byte in num.iter_mut().rev() {
            let acc = u32::from(*byte) * 32 + carry;
            *byte = acc as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            num.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num);
    Some(out)
}

fn checksum(version: u8, hash: &[u8; 20]) -> [u8; 4] {
    let mut payload = vec![version];
    payload.extend_from_slice(hash);
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

pub fn encode_address(version: u8, hash: &[u8; 20]) -> String {
    let mut data = hash.to_vec();
    data.extend_from_slice(&checksum(version, hash));
    format!("S{}{}", C32[version as usize] as char, c32_encode(&data))
}

/// The c32check version and hash160 behind a canonical testnet standard principal.
pub fn address_bytes(address: &str) -> Result<(u8, [u8; 20])> {
    let bytes = address.as_bytes();
    // Leading zero bytes shorten the c32 digits, so only the upper bound is fixed.
    if !(3..=41).contains(&bytes.len()) || bytes[0] != b'S' {
        return Err(invalid("not a Stacks address"));
    }
    let version = C32
        .iter()
        .position(|c| *c == bytes[1])
        .ok_or_else(|| invalid("not a Stacks address"))? as u8;
    if version != VERSION_P2PKH_TESTNET && version != VERSION_P2SH_TESTNET {
        return Err(invalid("not a Stacks testnet address"));
    }
    let data = c32_decode(&address[2..]).ok_or_else(|| invalid("invalid c32 address"))?;
    if data.len() != 24 {
        return Err(invalid("invalid c32 address length"));
    }
    let hash: [u8; 20] = data[..20].try_into().expect("20 bytes");
    if checksum(version, &hash) != data[20..] {
        return Err(invalid("address checksum mismatch"));
    }
    if encode_address(version, &hash) != address {
        return Err(invalid("address is not canonical"));
    }
    if hash == [0; 20] {
        return Err(invalid("zero address"));
    }
    Ok((version, hash))
}

fn hash160(public: &[u8]) -> Result<[u8; 20]> {
    let key = k256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("bad public key"))?;
    Ok(Ripemd160::digest(Sha256::digest(key.to_encoded_point(true).as_bytes())).into())
}

/// Testnet P2PKH address of the compressed key, as Leather and Xverse derive it.
pub fn address(public: &[u8]) -> Result<String> {
    Ok(encode_address(VERSION_P2PKH_TESTNET, &hash160(public)?))
}

fn sha512_256(data: &[u8]) -> [u8; 32] {
    Sha512_256::digest(data).into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StacksTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal microSTX (1 STX = 1,000,000 microSTX); never a JSON floating-point number.
    pub microstx: String,
    /// Total fee in microSTX, at most `MAX_FEE`.
    pub fee: u64,
    /// The sender account's next nonce.
    pub nonce: u64,
}

struct Checked {
    signer: [u8; 20],
    recipient: (u8, [u8; 20]),
    amount: u64,
}

impl StacksTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native STX transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.microstx {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Stacks intent")),
        }
        self.check()?;
        Ok(())
    }

    fn check(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let (version, signer) = address_bytes(&self.from)?;
        if version != VERSION_P2PKH_TESTNET {
            return Err(invalid("sender must be a single-sig testnet address"));
        }
        let recipient = address_bytes(&self.to)?;
        if recipient.1 == signer {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = self
            .microstx
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds u64 microSTX"))?;
        if amount == 0 || amount.to_string() != self.microstx {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        if self.fee == 0 || self.fee > MAX_FEE {
            return Err(invalid(format!("fee must be 1..={MAX_FEE} microSTX")));
        }
        if self.nonce > MAX_NONCE {
            return Err(invalid("nonce out of range"));
        }
        Ok(Checked {
            signer,
            recipient,
            amount,
        })
    }

    fn encode(&self, fee: u64, nonce: u64, signature: &[u8; 65]) -> Result<Vec<u8>> {
        let c = self.check()?;
        let mut out = Vec::with_capacity(180);
        out.push(TX_VERSION_TESTNET);
        out.extend_from_slice(&CHAIN_ID_TESTNET.to_be_bytes());
        out.push(AUTH_STANDARD);
        out.push(HASH_MODE_P2PKH);
        out.extend_from_slice(&c.signer);
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&fee.to_be_bytes());
        out.push(KEY_COMPRESSED);
        out.extend_from_slice(signature);
        out.push(ANCHOR_ANY);
        out.push(POST_CONDITION_DENY);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(PAYLOAD_TOKEN_TRANSFER);
        out.push(PRINCIPAL_STANDARD);
        out.push(c.recipient.0);
        out.extend_from_slice(&c.recipient.1);
        out.extend_from_slice(&c.amount.to_be_bytes());
        out.extend_from_slice(&[0u8; MEMO_LEN]);
        Ok(out)
    }

    /// The transaction with a zero signature, as `@stacks/transactions` serializes it unsigned.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        self.encode(self.fee, self.nonce, &[0; 65])
    }

    /// SIP-005 presign sighash: the cleared-auth txid bound to auth type, fee and nonce.
    pub fn sighash(&self) -> Result<[u8; 32]> {
        let initial = sha512_256(&self.encode(0, 0, &[0; 65])?);
        let mut presign = initial.to_vec();
        presign.push(AUTH_STANDARD);
        presign.extend_from_slice(&self.fee.to_be_bytes());
        presign.extend_from_slice(&self.nonce.to_be_bytes());
        Ok(sha512_256(&presign))
    }

    /// Returns the serialized signed transaction (for `/v2/transactions`) and its `0x` txid.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid("invalid signing key"))?;
        let public = key.verifying_key().to_encoded_point(true);
        if address(public.as_bytes())? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let (parity, r, s) = evm::sign_digest(secret, &self.sighash()?)?;
        // Stacks message signatures put the recovery id first: v || r || s.
        let mut signature = [0u8; 65];
        signature[0] = parity;
        signature[1..33].copy_from_slice(&r);
        signature[33..].copy_from_slice(&s);
        let wire = self.encode(self.fee, self.nonce, &signature)?;
        Ok((
            format!("0x{}", hex::encode(&wire)),
            format!("0x{}", hex::encode(sha512_256(&wire))),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const SECRET: [u8; 32] = [7u8; 32];
    const RECIPIENT: &str = "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG";
    const KEY_ONE_ADDRESS: &str = "ST1THWXQ8368SDN2MJGE4BMDKMCHZ2GSVTSQDA7QF";

    fn one() -> [u8; 32] {
        let mut one = [0u8; 32];
        one[31] = 1;
        one
    }

    fn sender(secret: &[u8; 32]) -> String {
        let key = k256::ecdsa::SigningKey::from_bytes(secret.into()).unwrap();
        address(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn tx() -> StacksTx {
        StacksTx {
            chain_id: TESTNET.into(),
            from: KEY_ONE_ADDRESS.into(),
            to: RECIPIENT.into(),
            microstx: "1500000".into(),
            fee: 180,
            nonce: 7,
        }
    }

    fn intent(tx: &StacksTx) -> TxIntent {
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
                amount: Amount(tx.microstx.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn address_matches_sdk_and_c32check_vectors() {
        // `@stacks/transactions` getAddressFromPrivateKey for keys 1 and 0x07 * 32.
        assert_eq!(sender(&one()), KEY_ONE_ADDRESS);
        assert_eq!(sender(&SECRET), "ST2HWDCFE994XKWNF7CW055T78KXTJ90P9B4HHQDZ");
        // c32check README: c32address(22, a46ff888...) on mainnet.
        let hash: [u8; 20] = hex::decode("a46ff88886c2ef9762d970b4d2c63678835bd39d")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            encode_address(22, &hash),
            "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7"
        );
        let (version, hash) = address_bytes(RECIPIENT).unwrap();
        assert_eq!(version, 26);
        assert_eq!(
            hex::encode(hash),
            "99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd23"
        );
        // A hash with a leading zero byte keeps a leading '0' digit.
        let mut low = [0u8; 20];
        low[19] = 1;
        let addr = encode_address(26, &low);
        assert!(addr.starts_with("ST0"));
        assert_eq!(address_bytes(&addr).unwrap(), (26, low));
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        assert!(address_bytes("ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AH").is_err());
        assert!(address_bytes("st2cy5v39nhdpwsxmw9qdt3hc3gd6q6xx4cfrk9ag").is_err());
        assert!(address_bytes("SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7").is_err());
        assert!(address_bytes("ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.contract").is_err());
        assert!(address_bytes("ST02CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG").is_err());
        assert!(address_bytes(&encode_address(26, &[0; 20])).is_err());
    }

    /// `@stacks/transactions` makeUnsignedSTXTokenTransfer / makeSTXTokenTransfer output for
    /// these fields; the TypeScript adapter pins the same hex.
    #[test]
    fn bytes_match_the_sdk_and_adapter_vectors() {
        let t = tx();
        assert_eq!(hex::encode(t.unsigned_bytes().unwrap()), UNSIGNED_VECTOR);
        let (wire, id) = t.sign(&one()).unwrap();
        assert_eq!(wire, format!("0x{SIGNED_VECTOR}"));
        assert_eq!(id, format!("0x{TXID_VECTOR}"));
        let big = StacksTx {
            microstx: "123456789012345".into(),
            fee: 3000,
            nonce: 300,
            ..tx()
        };
        let (wire, id) = big.sign(&one()).unwrap();
        assert_eq!(wire, format!("0x{SIGNED_BIG_VECTOR}"));
        assert_eq!(
            id,
            "0xf0b01b4176333afddd38d8606f0a2fbc91b3d8fe941102ebdee9dc5f29319c36"
        );
    }
    const UNSIGNED_VECTOR: &str = "80800000000400751e76e8199196d454941c45d1b3a323f1433bd6000000000000000700000000000000b400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd23000000000016e36000000000000000000000000000000000000000000000000000000000000000000000";
    const SIGNED_VECTOR: &str = "80800000000400751e76e8199196d454941c45d1b3a323f1433bd6000000000000000700000000000000b40000cdd4dfa8b6c82ef87bebf85581c142d592374b7f7051ddbc23509dbec52a1f500ad387b563c2b7df70d2c7dc77a94b237aa872f2362f6bd3fb965dc5f6facfea03020000000000051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd23000000000016e36000000000000000000000000000000000000000000000000000000000000000000000";
    const TXID_VECTOR: &str = "b1f0e6c2f0e261b47dc201e563f8e75def59f58b98aafc7ba602f57589abcdc9";
    const SIGNED_BIG_VECTOR: &str = "80800000000400751e76e8199196d454941c45d1b3a323f1433bd6000000000000012c0000000000000bb80000cab402b33cb2e05bbf7e2b86df5500d87814680b3d0ba3345f26db3c0e1c0cea3f3dc8a0e4538d171800f6a8286b92d8d64fd301d65fdd5bdd6338ba98c2dbeb03020000000000051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd2300007048860ddf7900000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn signature_recovers_to_the_sender_over_the_presign_sighash() {
        let t = StacksTx {
            from: sender(&SECRET),
            ..tx()
        };
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, id) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let unsigned = t.unsigned_bytes().unwrap();
        assert_eq!(wire.len(), unsigned.len());
        // Only the 65 signature bytes after the key-encoding byte differ.
        assert_eq!(wire[..44], unsigned[..44]);
        assert_eq!(wire[109..], unsigned[109..]);
        let sig = &wire[44..109];
        assert_eq!(id, format!("0x{}", hex::encode(sha512_256(&wire))));
        let recovered = VerifyingKey::recover_from_prehash(
            &t.sighash().unwrap(),
            &Signature::from_slice(&sig[1..]).unwrap(),
            RecoveryId::from_byte(sig[0]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            address(recovered.to_encoded_point(true).as_bytes()).unwrap(),
            t.from
        );
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let mut t = base.clone();
        t.chain_id = "stacks:1".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.chain_id = "stacks:2147483649".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.microstx = "01500000".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.microstx = "0".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.microstx = "18446744073709551616".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.fee = 0;
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.fee = MAX_FEE + 1;
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.nonce = MAX_NONCE + 1;
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.to = "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7".into();
        assert!(t.unsigned_bytes().is_err());
        let mut t = base.clone();
        t.from = encode_address(VERSION_P2SH_TESTNET, &address_bytes(&base.from).unwrap().1);
        assert!(t.unsigned_bytes().is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = sender(&SECRET);
        }
        assert!(base.check_matches_intent(&i).is_err());
        assert!(base.sign(&SECRET).is_err());
        let extra = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "microstx": "1",
            "fee": 180, "nonce": 0, "memo": "00"
        });
        assert!(serde_json::from_value::<StacksTx>(extra).is_err());
        let float = serde_json::json!({
            "chainId": TESTNET, "from": base.from, "to": base.to, "microstx": 1.5,
            "fee": 180, "nonce": 0
        });
        assert!(serde_json::from_value::<StacksTx>(float).is_err());
    }
}
