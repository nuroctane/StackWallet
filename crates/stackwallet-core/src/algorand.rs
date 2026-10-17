//! Native ALGO payments. The core msgpack-encodes the whole `pay` transaction
//! from checked fields (canonical encoding: sorted keys, zero values omitted).
//! There is no note, no `close`/`closeRemainderTo` and no `rekey`, so a signed
//! transfer can never empty or hand over the sender's account.

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512_256};

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

/// CAIP-2 for Algorand TestNet: the first 32 base64url characters of its genesis hash.
pub const TESTNET: &str = "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe";
pub const MAINNET: &str = "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k";
pub const VOI_MAINNET: &str = "algorand:r20fSQI8gWe_kFZziNonSPCXLwcQmH_n";
pub const TESTNET_GENESIS_ID: &str = "testnet-v1.0";
pub const TESTNET_GENESIS_HASH: &str = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";
/// The protocol minimum fee per transaction.
pub const MIN_FEE: u64 = 1_000;
/// 1 ALGO; congestion pricing beyond this is refused rather than silently paid.
pub const MAX_FEE: u64 = 1_000_000;
/// Every account must hold 0.1 ALGO; a payment that creates one must carry at least this.
pub const MIN_BALANCE: u64 = 100_000;
/// Total ALGO supply in microalgos: no valid amount exceeds it.
pub const MAX_MICROALGOS: u64 = 10_000_000_000_000_000;
/// Consensus `MaxTxnLife`: `lastValid - firstValid` may not exceed it.
pub const MAX_LIFETIME_ROUNDS: u64 = 1_000;
/// The domain-separation prefix for transaction signatures and ids.
const TX_TAG: &[u8] = b"TX";

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Algorand transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet and Voi stay read-only until the family's testnet and threshold support gates pass.
    if chain != TESTNET {
        return Err(invalid("only Algorand testnet transfers are enabled"));
    }
    Ok(())
}

fn checksum(key: &[u8; 32]) -> [u8; 4] {
    let digest = Sha512_256::digest(key);
    digest[28..].try_into().expect("4 bytes")
}

pub fn encode_address(key: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(36);
    raw.extend_from_slice(key);
    raw.extend_from_slice(&checksum(key));
    data_encoding::BASE32_NOPAD.encode(&raw)
}

/// The Ed25519 public key behind a canonical 58-character address.
pub fn address_bytes(address: &str) -> Result<[u8; 32]> {
    if address.len() != 58 {
        return Err(invalid("address must be 58 base32 characters"));
    }
    let raw = data_encoding::BASE32_NOPAD
        .decode(address.as_bytes())
        .map_err(|_| invalid("invalid base32 address"))?;
    if raw.len() != 36 {
        return Err(invalid("not an Algorand address"));
    }
    let key: [u8; 32] = raw[..32].try_into().expect("32 bytes");
    if raw[32..] != checksum(&key) {
        return Err(invalid("address checksum mismatch"));
    }
    // 36 bytes leave two spare base32 bits; a non-canonical spelling must not alias.
    if encode_address(&key) != address {
        return Err(invalid("non-canonical address"));
    }
    Ok(key)
}

pub fn address(public: &[u8]) -> Result<String> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    Ok(encode_address(&key))
}

fn canonical_amount(value: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid("amount is not a decimal integer"))?;
    if n == 0 || n > MAX_MICROALGOS || n.to_string() != value {
        return Err(invalid(
            "amount must be a positive canonical microalgo count",
        ));
    }
    Ok(n)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgorandTx {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    /// Decimal microalgos (1 ALGO = 1,000,000); never a JSON floating-point number.
    pub microalgos: String,
    /// Flat fee in microalgos.
    pub fee: u64,
    /// First round in which the transaction may be included.
    pub first_valid: u64,
    /// Last round in which the transaction may be included.
    pub last_valid: u64,
    #[serde(rename = "genesisID")]
    pub genesis_id: String,
    /// Standard base64 of the network's 32-byte genesis hash.
    pub genesis_hash: String,
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // Every key and the genesis id are short ASCII strings: fixstr.
    debug_assert!(s.len() < 32);
    out.push(0xa0 | s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

fn put_bin(out: &mut Vec<u8>, b: &[u8]) {
    debug_assert!(b.len() < 256);
    out.push(0xc4);
    out.push(b.len() as u8);
    out.extend_from_slice(b);
}

/// Smallest msgpack unsigned encoding, as Algorand's canonical codec requires.
fn put_uint(out: &mut Vec<u8>, v: u64) {
    if v < 0x80 {
        out.push(v as u8);
    } else if v <= u8::MAX as u64 {
        out.extend_from_slice(&[0xcc, v as u8]);
    } else if v <= u16::MAX as u64 {
        out.push(0xcd);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= u32::MAX as u64 {
        out.push(0xce);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

impl AlgorandTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native ALGO transfers are enabled"));
                }
                if address_bytes(to)? != address_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.microalgos {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Algorand intent")),
        }
        self.txn_msgpack()?;
        Ok(())
    }

    /// Canonical msgpack of the `pay` transaction (keys in lexical order, no zero values).
    pub fn txn_msgpack(&self) -> Result<Vec<u8>> {
        check_chain(&self.chain_id)?;
        if self.genesis_id != TESTNET_GENESIS_ID || self.genesis_hash != TESTNET_GENESIS_HASH {
            return Err(invalid("genesis id or hash is not Algorand testnet"));
        }
        let genesis_hash = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.genesis_hash,
        )
        .map_err(|_| invalid("genesis hash is not base64"))?;
        let from = address_bytes(&self.from)?;
        let to = address_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = canonical_amount(&self.microalgos)?;
        if !(MIN_FEE..=MAX_FEE).contains(&self.fee) {
            return Err(invalid("fee is outside the accepted range"));
        }
        if self.first_valid == 0
            || self.first_valid > i64::MAX as u64
            || self.last_valid < self.first_valid
            || self.last_valid - self.first_valid > MAX_LIFETIME_ROUNDS
        {
            return Err(invalid(
                "validity window must be at most 1000 rounds from a positive first round",
            ));
        }

        let mut out = Vec::with_capacity(200);
        // fixmap of 9: amt fee fv gen gh lv rcv snd type
        out.push(0x89);
        put_str(&mut out, "amt");
        put_uint(&mut out, amount);
        put_str(&mut out, "fee");
        put_uint(&mut out, self.fee);
        put_str(&mut out, "fv");
        put_uint(&mut out, self.first_valid);
        put_str(&mut out, "gen");
        put_str(&mut out, &self.genesis_id);
        put_str(&mut out, "gh");
        put_bin(&mut out, &genesis_hash);
        put_str(&mut out, "lv");
        put_uint(&mut out, self.last_valid);
        put_str(&mut out, "rcv");
        put_bin(&mut out, &to);
        put_str(&mut out, "snd");
        put_bin(&mut out, &from);
        put_str(&mut out, "type");
        put_str(&mut out, "pay");
        Ok(out)
    }

    /// `"TX" || msgpack(txn)`: the exact Ed25519 message.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let mut msg = TX_TAG.to_vec();
        msg.extend_from_slice(&self.txn_msgpack()?);
        Ok(msg)
    }

    /// The transaction id as explorers show it: base32(sha512/256("TX" || txn)), unpadded.
    pub fn txid(&self) -> Result<String> {
        let digest = Sha512_256::digest(self.signing_message()?);
        Ok(data_encoding::BASE32_NOPAD.encode(&digest))
    }

    /// Returns the signed transaction (`0x` + hex msgpack) and its txid.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        if encode_address(&key.verifying_key().to_bytes()) != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let signature = key.sign(&self.signing_message()?).to_bytes();
        self.assemble(&signature)
    }

    /// The signed transaction for a signature made elsewhere (a threshold
    /// ceremony), accepted only if it verifies against the sender.
    pub fn assemble(&self, signature: &[u8; 64]) -> Result<(String, String)> {
        let msg = self.signing_message()?;
        let public = address_bytes(&self.from)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| invalid("sender is not an Ed25519 point"))?;
        key.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let mut wire = Vec::with_capacity(msg.len() + 80);
        // SignedTxn { sig, txn } with keys in lexical order.
        wire.push(0x82);
        put_str(&mut wire, "sig");
        put_bin(&mut wire, signature);
        put_str(&mut wire, "txn");
        wire.extend_from_slice(&msg[TX_TAG.len()..]);
        Ok((format!("0x{}", hex::encode(wire)), self.txid()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::{derive_ed25519, parse_path, Mnemonic};
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    /// algosdk 3.9.0 `mnemonicToSecretKey(mnemonicFromSeed([7; 32]))`.
    const SENDER: &str = "5JFGYY7CTRJAVPXVKB5RGLWF7GKUO5VOX27HXESCD3VGSFCG2IWAKDM5YU";
    /// The same for seed `[9; 32]`.
    const RECIPIENT: &str = "7ULSIOC2UDDVWZH3PDGWAL5B3GI7327XNMJ4LDWXALVMQNPJ6YMB7QOADI";

    fn tx() -> AlgorandTx {
        AlgorandTx {
            chain_id: TESTNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            microalgos: "1500000".into(),
            fee: 1000,
            first_valid: 68_321_000,
            last_valid: 68_322_000,
            genesis_id: TESTNET_GENESIS_ID.into(),
            genesis_hash: TESTNET_GENESIS_HASH.into(),
        }
    }

    fn intent(tx: &AlgorandTx) -> TxIntent {
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
                amount: Amount(tx.microalgos.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn addresses_match_sdk_vectors() {
        let seven = SigningKey::from_bytes(&SECRET).verifying_key().to_bytes();
        assert_eq!(address(&seven).unwrap(), SENDER);
        let nine = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(address(&nine).unwrap(), RECIPIENT);
        assert_eq!(address_bytes(SENDER).unwrap(), seven);
        assert!(address(&[0u8; 33]).is_err());
        // The zero key's well-known address.
        assert_eq!(
            encode_address(&[0u8; 32]),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
        );
        // SLIP-10 m/44'/283'/0'/0'/0' of "abandon … about", derived independently
        // (node crypto HMAC) and addressed by algosdk.
        let seed = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
        .to_seed("");
        let key = derive_ed25519(&*seed, &parse_path("m/44'/283'/0'/0'/0'").unwrap()).unwrap();
        assert_eq!(
            hex::encode(key.secret()),
            "222743717649e675ead31326b1a5bc2ebc3b6121fd333a71266b00a6698c3cf8"
        );
        assert_eq!(
            address(&key.public).unwrap(),
            "EP2D7TV7IAFANZHK3B6QLKB53N5UTD7RARVXZTWCPCRQQBKYVGM2XIMT2Q"
        );
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        // Flipped last character: checksum or spare-bit mismatch.
        assert!(
            address_bytes("5JFGYY7CTRJAVPXVKB5RGLWF7GKUO5VOX27HXESCD3VGSFCG2IWAKDM5YV").is_err()
        );
        assert!(
            address_bytes("5JFGYY7CTRJAVPXVKB5RGLWF7GKUO5VOX27HXESCD3VGSFCG2IWAKDM5YQ").is_err()
        );
        assert!(address_bytes(&SENDER.to_lowercase()).is_err());
        assert!(address_bytes(&SENDER[..57]).is_err());
        assert!(address_bytes(&format!("{SENDER}=")).is_err());
        assert!(address_bytes("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6").is_err());
    }

    /// Produced by algosdk 3.9.0 (`makePaymentTxnWithSuggestedParamsFromObject`,
    /// `toByte`, `txID`, `signTxn`) for the same fields; the TypeScript tests pin them too.
    #[test]
    fn encoding_matches_the_sdk_vectors() {
        let small = tx();
        assert_eq!(hex::encode(small.txn_msgpack().unwrap()), SMALL_TXN);
        assert_eq!(small.txid().unwrap(), SMALL_TXID);
        let (wire, id) = small.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{SMALL_SIGNED}"));
        assert_eq!(id, SMALL_TXID);

        let big = AlgorandTx {
            microalgos: "9000000000000000".into(),
            fee: 250_000,
            first_valid: 5,
            last_valid: 1004,
            ..tx()
        };
        assert_eq!(hex::encode(big.txn_msgpack().unwrap()), BIG_TXN);
        assert_eq!(big.txid().unwrap(), BIG_TXID);
        assert_eq!(big.sign(&SECRET).unwrap().0, format!("0x{BIG_SIGNED}"));

        let tiny = AlgorandTx {
            microalgos: "1".into(),
            first_valid: 127,
            last_valid: 128,
            ..tx()
        };
        assert_eq!(hex::encode(tiny.txn_msgpack().unwrap()), TINY_TXN);
        assert_eq!(tiny.txid().unwrap(), TINY_TXID);
        assert_eq!(tiny.sign(&SECRET).unwrap().0, format!("0x{TINY_SIGNED}"));
        assert_eq!(SMALL_TXID.len(), 52);
    }
    const SMALL_TXN: &str = "89a3616d74ce0016e360a3666565cd03e8a26676ce04127ee8a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76ce041282d0a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179";
    const SMALL_TXID: &str = "J2ZUC43BOWQL7A2ZEWYF53UMG24HCN3P7UL5LF6M4VV5CPRMROHQ";
    const SMALL_SIGNED: &str = "82a3736967c440bac24643b1616dc4ee75f7c335ea7580ec7f53e909744c14d3b155db913d535e656ff523e253e7122fbdd5ba6bca100aec48b36db8146e0a029c6ab1ba67f909a374786e89a3616d74ce0016e360a3666565cd03e8a26676ce04127ee8a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76ce041282d0a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179";
    const BIG_TXN: &str = "89a3616d74cf001ff973cafa8000a3666565ce0003d090a2667605a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76cd03eca3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179";
    const BIG_TXID: &str = "GAHQSBQVFR27KVPZUJ722ZPEAJFVLOGRDUZBT3K5OTTWR6PPFSDA";
    const BIG_SIGNED: &str = "82a3736967c440a8a73d7f08f94fa24ab4a926c215c2c9cfbc10b2f83506efd3c1d4f987d2905f6d0f552134dc48e429ccc4eb6636575bb997015e8e7dd572caec4dc232e46103a374786e89a3616d74cf001ff973cafa8000a3666565ce0003d090a2667605a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76cd03eca3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179";
    const TINY_TXN: &str = "89a3616d7401a3666565cd03e8a266767fa367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76cc80a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179";
    const TINY_TXID: &str = "72RT7KS25RZP4IYPXNASOZLFJAQOXPJ3DGOG64MCFZFJB5UEQV2Q";
    const TINY_SIGNED: &str = "82a3736967c44057e56d69010e0b5e332273e505a59cfbd05e26f3ed588ebd373d1985c128499c7ed15c9e62bd1eea5b306fc9ae509850ed35084ead56d6eb3200935c9ae66b02a374786e89a3616d7401a3666565cd03e8a266767fa367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76cc80a3726376c420fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3736e64c420ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca474797065a3706179";

    #[test]
    fn signature_verifies_over_the_tagged_message() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let wire = hex::decode(wire.trim_start_matches("0x")).unwrap();
        assert_eq!(wire[..7], [0x82, 0xa3, b's', b'i', b'g', 0xc4, 0x40]);
        let sig = ed25519_dalek::Signature::from_slice(&wire[7..71]).unwrap();
        let public = SigningKey::from_bytes(&SECRET).verifying_key();
        public
            .verify_strict(&t.signing_message().unwrap(), &sig)
            .unwrap();
        assert_eq!(wire[71..75], [0xa3, b't', b'x', b'n']);
        assert_eq!(wire[75..], t.txn_msgpack().unwrap()[..]);
        assert!(t.assemble(&[0u8; 64]).is_err());
        let mut forged = sig.to_bytes();
        forged[0] ^= 1;
        assert!(t.assemble(&forged).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        for chain in [MAINNET, VOI_MAINNET, "algorand:testnet"] {
            assert!(check_chain(chain).is_err());
            let mut t = base.clone();
            t.chain_id = chain.into();
            assert!(t.txn_msgpack().is_err());
        }
        let mut t = base.clone();
        t.genesis_id = "mainnet-v1.0".into();
        assert!(t.txn_msgpack().is_err());
        let mut t = base.clone();
        t.genesis_hash = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=".into();
        assert!(t.txn_msgpack().is_err());
        for amount in [
            "0",
            "01500000",
            "+1",
            "1.5",
            "10000000000000001",
            "18446744073709551616",
        ] {
            let mut t = base.clone();
            t.microalgos = amount.into();
            assert!(t.txn_msgpack().is_err(), "{amount}");
        }
        let mut t = base.clone();
        t.microalgos = MAX_MICROALGOS.to_string();
        assert!(t.txn_msgpack().is_ok());
        let mut t = base.clone();
        t.to = t.from.clone();
        assert!(t.txn_msgpack().is_err());
        let mut t = base.clone();
        t.fee = MIN_FEE - 1;
        assert!(t.txn_msgpack().is_err());
        t.fee = MAX_FEE + 1;
        assert!(t.txn_msgpack().is_err());
        let mut t = base.clone();
        t.first_valid = 0;
        t.last_valid = 10;
        assert!(t.txn_msgpack().is_err());
        let mut t = base.clone();
        t.last_valid = t.first_valid + MAX_LIFETIME_ROUNDS + 1;
        assert!(t.txn_msgpack().is_err());
        t.last_valid = t.first_valid - 1;
        assert!(t.txn_msgpack().is_err());
        t.last_valid = t.first_valid;
        assert!(t.txn_msgpack().is_ok());

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = SENDER.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{TESTNET}:asa:10458941");
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        i.chain_id = ChainId(MAINNET.into());
        assert!(base.check_matches_intent(&i).is_err());
        let mut other = base.clone();
        other.from = RECIPIENT.into();
        other.to = SENDER.into();
        assert!(other.sign(&SECRET).is_err());

        let json = |extra: (&str, serde_json::Value)| {
            let mut v = serde_json::to_value(&base).unwrap();
            v.as_object_mut().unwrap().insert(extra.0.into(), extra.1);
            serde_json::from_value::<AlgorandTx>(v)
        };
        assert!(serde_json::from_value::<AlgorandTx>(serde_json::to_value(&base).unwrap()).is_ok());
        assert_eq!(
            serde_json::to_value(&base).unwrap()["genesisID"],
            TESTNET_GENESIS_ID
        );
        for field in ["note", "closeRemainderTo", "rekeyTo", "lease", "stroops"] {
            assert!(json((field, serde_json::json!("x"))).is_err(), "{field}");
        }
    }
}
