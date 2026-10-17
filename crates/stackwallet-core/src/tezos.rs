//! Native tez transfers between implicit accounts. The core forges the whole
//! manager operation (an optional `reveal` of the signing key, then one
//! `transaction` with no parameters) from checked fields, so an adapter cannot
//! add contract calls, delegations or a foreign public key.

use blake2::digest::consts::{U20, U32};
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::intent::{TxIntent, TxIntentKind};
use crate::{CoreError, Result};

type Blake2b160 = Blake2b<U20>;
type Blake2b256 = Blake2b<U32>;

/// Shadownet, the long-running application testnet that replaced Ghostnet.
pub const SHADOWNET: &str = "tezos:NetXsqzbfFenSTS";
pub const MAINNET: &str = "tezos:NetXdQprcVkpaWU";

const TZ1: [u8; 3] = [6, 161, 159];
const TZ2: [u8; 3] = [6, 161, 161];
const TZ3: [u8; 3] = [6, 161, 164];
const TZ4: [u8; 3] = [6, 161, 166];
const BLOCK: [u8; 2] = [1, 52];
const OPERATION: [u8; 2] = [5, 116];

const TAG_REVEAL: u8 = 0x6b;
const TAG_TRANSACTION: u8 = 0x6c;
/// Generic-operation watermark the protocol prepends before hashing a manager operation.
const WATERMARK: u8 = 0x03;

pub const MIN_FEE: u64 = 100;
pub const MAX_FEE: u64 = 100_000;
pub const MAX_GAS_LIMIT: u64 = 100_000;
pub const MAX_REVEAL_GAS_LIMIT: u64 = 10_000;
/// Covers the 257-byte allocation of a new implicit account (about 0.064 tez burnt)
/// while capping the storage burn at 0.25 tez.
pub const MAX_STORAGE_LIMIT: u64 = 1_000;
const MAX_COUNTER: u64 = 9_007_199_254_740_990;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "Tezos transfer",
        reason: reason.into(),
    }
}

pub fn check_chain(chain: &str) -> Result<()> {
    // Mainnet stays disabled until the family's testnet and threshold support gates pass.
    if chain != SHADOWNET {
        return Err(invalid("only Tezos Shadownet transfers are enabled"));
    }
    Ok(())
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

fn b58check(prefix: &[u8], payload: &[u8]) -> String {
    let mut full = [prefix, payload].concat();
    let check = checksum(&full);
    full.extend_from_slice(&check);
    bs58::encode(full).into_string()
}

fn b58check_decode<const N: usize>(value: &str, prefix: &[u8], what: &str) -> Result<[u8; N]> {
    if value.len() > 64 {
        return Err(invalid(format!("{what} is too long")));
    }
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| invalid(format!("{what} is not base58")))?;
    if bytes.len() != prefix.len() + N + 4 || !bytes.starts_with(prefix) {
        return Err(invalid(format!("{what} has the wrong prefix or length")));
    }
    let (body, check) = bytes.split_at(bytes.len() - 4);
    if checksum(body) != check {
        return Err(invalid(format!("{what} checksum mismatch")));
    }
    let out: [u8; N] = body[prefix.len()..].try_into().expect("length checked");
    if b58check(prefix, &out) != value {
        return Err(invalid(format!("{what} is not canonical")));
    }
    Ok(out)
}

/// The binary `public_key_hash` of an implicit account: one curve tag byte, then 20 bytes.
pub fn implicit_bytes(address: &str) -> Result<[u8; 21]> {
    let (tag, prefix) = match address.get(..3) {
        Some("tz1") => (0u8, TZ1),
        Some("tz2") => (1, TZ2),
        Some("tz3") => (2, TZ3),
        Some("tz4") => (3, TZ4),
        _ => return Err(invalid("not an implicit tz1/tz2/tz3/tz4 address")),
    };
    let hash = b58check_decode::<20>(address, &prefix, "address")?;
    if hash == [0; 20] {
        return Err(invalid("zero address"));
    }
    let mut out = [0u8; 21];
    out[0] = tag;
    out[1..].copy_from_slice(&hash);
    Ok(out)
}

/// tz1 address of a 32-byte Ed25519 public key: base58check of its blake2b-160.
pub fn address(public: &[u8]) -> Result<String> {
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    Ok(b58check(&TZ1, &Blake2b160::digest(public)))
}

fn zarith(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    Blake2b256::digest(bytes).into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TezosReveal {
    /// Mutez paid for the reveal operation.
    pub fee: u64,
    pub gas_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TezosTx {
    pub chain_id: String,
    /// tz1 address of the signing key.
    pub from: String,
    /// Implicit recipient (tz1/tz2/tz3/tz4); contracts are refused.
    pub to: String,
    /// Decimal mutez (1 tez = 1,000,000 mutez); never a JSON floating-point number.
    pub mutez: String,
    /// Block hash the operation is anchored to; it expires `max_operations_ttl` blocks later.
    pub branch: String,
    /// Counter of the first content: the account counter plus one.
    pub counter: u64,
    pub fee: u64,
    pub gas_limit: u64,
    pub storage_limit: u64,
    /// Present when the account's key is not revealed yet; the core reveals its own key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reveal: Option<TezosReveal>,
}

struct Checked {
    from: [u8; 21],
    to: [u8; 21],
    amount: u64,
    branch: [u8; 32],
}

impl TezosTx {
    pub fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        check_chain(&self.chain_id)?;
        if self.chain_id != intent.chain_id.0 {
            return Err(invalid("chain differs from intent"));
        }
        match &intent.kind {
            TxIntentKind::Transfer { to, asset, amount } => {
                if asset.0 != format!("{}:native", self.chain_id) {
                    return Err(invalid("only native tez transfers are enabled"));
                }
                if implicit_bytes(to)? != implicit_bytes(&self.to)? {
                    return Err(invalid("destination differs from intent"));
                }
                if amount.0 != self.mutez {
                    return Err(invalid("amount differs from intent"));
                }
            }
            _ => return Err(invalid("unsupported Tezos intent")),
        }
        self.checked()?;
        Ok(())
    }

    fn checked(&self) -> Result<Checked> {
        check_chain(&self.chain_id)?;
        let from = implicit_bytes(&self.from)?;
        if from[0] != 0 {
            return Err(invalid("sender must be a tz1 (Ed25519) account"));
        }
        let to = implicit_bytes(&self.to)?;
        if from == to {
            return Err(invalid("sender and recipient must differ"));
        }
        let amount = self
            .mutez
            .parse::<u64>()
            .map_err(|_| invalid("amount exceeds int64 mutez"))?;
        if amount == 0 || amount > i64::MAX as u64 || amount.to_string() != self.mutez {
            return Err(invalid("amount must be a positive canonical integer"));
        }
        let branch = b58check_decode::<32>(&self.branch, &BLOCK, "branch")?;
        if branch == [0; 32] {
            return Err(invalid("zero branch"));
        }
        if self.counter == 0 || self.counter > MAX_COUNTER {
            return Err(invalid("counter is out of range"));
        }
        if !(MIN_FEE..=MAX_FEE).contains(&self.fee) {
            return Err(invalid("fee is outside the accepted range"));
        }
        if self.gas_limit == 0 || self.gas_limit > MAX_GAS_LIMIT {
            return Err(invalid("gas limit is outside the accepted range"));
        }
        if self.storage_limit > MAX_STORAGE_LIMIT {
            return Err(invalid("storage limit is outside the accepted range"));
        }
        if let Some(reveal) = &self.reveal {
            if !(MIN_FEE..=MAX_FEE).contains(&reveal.fee) {
                return Err(invalid("reveal fee is outside the accepted range"));
            }
            if reveal.gas_limit == 0 || reveal.gas_limit > MAX_REVEAL_GAS_LIMIT {
                return Err(invalid("reveal gas limit is outside the accepted range"));
            }
        }
        Ok(Checked {
            from,
            to,
            amount,
            branch,
        })
    }

    /// Total mutez the sender pays in fees across the operation's contents.
    pub fn total_fee(&self) -> u64 {
        self.fee + self.reveal.as_ref().map_or(0, |r| r.fee)
    }

    /// The forged operation bytes (branch then contents). `public` is the
    /// sender's key; it is only written into the reveal, and only if it
    /// derives `from`.
    pub fn forge(&self, public: &[u8; 32]) -> Result<Vec<u8>> {
        let c = self.checked()?;
        if address(public)? != self.from {
            return Err(invalid("public key does not derive the sender address"));
        }
        let mut out = Vec::with_capacity(32 + 2 * 120);
        out.extend_from_slice(&c.branch);
        let mut counter = self.counter;
        if let Some(reveal) = &self.reveal {
            out.push(TAG_REVEAL);
            out.extend_from_slice(&c.from);
            zarith(&mut out, reveal.fee);
            zarith(&mut out, counter);
            zarith(&mut out, reveal.gas_limit);
            zarith(&mut out, 0);
            // public_key: Ed25519 tag, key; then an absent BLS proof of possession.
            out.push(0);
            out.extend_from_slice(public);
            out.push(0);
            counter += 1;
        }
        out.push(TAG_TRANSACTION);
        out.extend_from_slice(&c.from);
        zarith(&mut out, self.fee);
        zarith(&mut out, counter);
        zarith(&mut out, self.gas_limit);
        zarith(&mut out, self.storage_limit);
        zarith(&mut out, c.amount);
        // destination: implicit contract tag, then the recipient's public_key_hash.
        out.push(0);
        out.extend_from_slice(&c.to);
        // No parameters: a plain transfer to the default entrypoint of an implicit account.
        out.push(0);
        Ok(out)
    }

    /// blake2b-256(0x03 || forged): what the Ed25519 key signs.
    pub fn signing_digest(&self, public: &[u8; 32]) -> Result<[u8; 32]> {
        let forged = self.forge(public)?;
        Ok(blake2b256(&[&[WATERMARK], forged.as_slice()].concat()))
    }

    /// Returns `0x` hex of the forged bytes followed by the 64-byte signature
    /// (the body `/injection/operation` takes) and the `o…` operation hash.
    pub fn sign(&self, secret: &[u8; 32]) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        if address(&public)? != self.from {
            return Err(invalid("sender differs from signing key"));
        }
        let digest = self.signing_digest(&public)?;
        self.assemble(&key.sign(&digest).to_bytes(), &public)
    }

    /// The wire for a signature made elsewhere (a threshold ceremony), accepted
    /// only if the key derives the sender address and the signature verifies.
    pub fn assemble(&self, signature: &[u8; 64], public: &[u8; 32]) -> Result<(String, String)> {
        let forged = self.forge(public)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(public)
            .map_err(|_| invalid("sender key is not an Ed25519 point"))?;
        let digest = blake2b256(&[&[WATERMARK], forged.as_slice()].concat());
        key.verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| invalid("signature does not verify against the sender"))?;
        let mut wire = forged;
        wire.extend_from_slice(signature);
        let hash = b58check(&OPERATION, &blake2b256(&wire));
        Ok((format!("0x{}", hex::encode(wire)), hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::{derive_ed25519, parse_path, Mnemonic};
    use crate::intent::{Amount, Proposer};
    use crate::model::{AssetRef, ChainId};

    const SECRET: [u8; 32] = [7u8; 32];
    // Vectors from Taquito 25.0.0 (`.nur/tezos-sdk/vector.mjs`), whose forged bytes
    // the Shadownet node's `helpers/forge/operations` reproduced exactly.
    const SENDER: &str = "tz1Qr9uevaimfiPS6X1otehsKrwvZjX7bsyL";
    const RECIPIENT: &str = "tz1fRryceCL4hCAGhoKiNm8oUqA54ZBFuHGV";
    const TZ2_ADDR: &str = "tz29sUbQkQxxNVXNWmxepLyN4L4iStKf9x8Y";
    const TZ3_ADDR: &str = "tz3PSXUovu1WTaZmUWSCuTPkMorvqWdNEYHV";
    const TZ4_ADDR: &str = "tz4DfyP6p6Lt5nnjJ9tLfFL1PW2dyCE5VeGs";
    const KT1_ADDR: &str = "KT1EojJ4VZAAd3rt3vRTTXb9ofsRWwL2Q56G";
    const BRANCH: &str = "BKnG8VoprFn4jYo8qWdGo3LGwpV9xqtqyb4deycpahXkr3C6drE";
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// The TypeScript adapter forges the same fields and asserts this exact hex.
    const REVEAL_TRANSFER: &str = "09090909090909090909090909090909090909090909090909090909090909096b003923a4e9144201ffcc3d4ac891d14a14df438c52f602cec2f105e8070000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c006c003923a4e9144201ffcc3d4ac891d14a14df438c52c203cfc2f105a9019502e0c65b0000d91569fa225ce7ef4d794d706cab5f1c18f7d0da00";
    const REVEAL_TRANSFER_SIG: &str = "dd44ee8fdcff3ea4ff91ca1b5df81a8ae784f2f4d754a7338c13b328b58cbf4bd734b5b022afca3ec3a78bb9c7777ef7e9e22ea9cfb82dda22e6a2f75fa6b10a";
    const REVEAL_TRANSFER_HASH: &str = "onrstUdQcArgPF85uKfE3yY7QSUF1W8UAL16rudLxG63okS6Zqv";

    fn public() -> [u8; 32] {
        SigningKey::from_bytes(&SECRET).verifying_key().to_bytes()
    }

    fn tx() -> TezosTx {
        TezosTx {
            chain_id: SHADOWNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            mutez: "1500000".into(),
            branch: BRANCH.into(),
            counter: 12_345_678,
            fee: 450,
            gas_limit: 169,
            storage_limit: 277,
            reveal: Some(TezosReveal {
                fee: 374,
                gas_limit: 1000,
            }),
        }
    }

    fn intent(tx: &TezosTx) -> TxIntent {
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
                amount: Amount(tx.mutez.clone()),
            },
            usd_micros: None,
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    #[test]
    fn addresses_match_taquito() {
        assert_eq!(address(&public()).unwrap(), SENDER);
        let eight = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(address(&eight).unwrap(), RECIPIENT);
        let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("");
        let k0 = derive_ed25519(&*seed, &parse_path("m/44'/1729'/0'/0'").unwrap()).unwrap();
        assert_eq!(
            address(&k0.public).unwrap(),
            "tz1VQA4RP4fLjEEMW2FR4pE9kAg5abb5h5GL"
        );
        let k1 = derive_ed25519(&*seed, &parse_path("m/44'/1729'/1'/0'").unwrap()).unwrap();
        assert_eq!(
            address(&k1.public).unwrap(),
            "tz1gvekQVEwFFdxT2KrcY6kZgFK1qMN3mmWF"
        );
        assert!(address(&[0; 31]).is_err());
    }

    #[test]
    fn address_forms_are_canonical() {
        assert_eq!(implicit_bytes(TZ2_ADDR).unwrap()[..2], [1, 0x11]);
        assert_eq!(implicit_bytes(TZ3_ADDR).unwrap()[..2], [2, 0x22]);
        assert_eq!(implicit_bytes(TZ4_ADDR).unwrap()[..2], [3, 0x33]);
        assert!(implicit_bytes(KT1_ADDR).is_err());
        assert!(implicit_bytes("tz1Qr9uevaimfiPS6X1otehsKrwvZjX7bsyM").is_err());
        assert!(implicit_bytes(&SENDER.to_lowercase()).is_err());
        assert!(implicit_bytes(&format!(" {SENDER}")).is_err());
        assert!(implicit_bytes(&b58check(&TZ1, &[0; 20])).is_err());
        // A tz1 prefix pasted onto tz2 bytes must not decode as tz1.
        assert!(implicit_bytes(&format!("tz1{}", &TZ2_ADDR[3..])).is_err());
        assert!(implicit_bytes("0x8ba1f109551bd432803012645ac136ddd64dba72").is_err());
    }

    #[test]
    fn forged_bytes_signature_and_hash_match_taquito() {
        let t = tx();
        t.check_matches_intent(&intent(&t)).unwrap();
        assert_eq!(hex::encode(t.forge(&public()).unwrap()), REVEAL_TRANSFER);
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(wire, format!("0x{REVEAL_TRANSFER}{REVEAL_TRANSFER_SIG}"));
        assert_eq!(hash, REVEAL_TRANSFER_HASH);
        assert_eq!(t.total_fee(), 824);
    }

    #[test]
    fn transfers_to_other_curves_match_taquito() {
        let cases = [
            (
                TZ2_ADDR,
                "9007199254740991",
                1,
                100_000,
                10_000,
                0,
                "6c003923a4e9144201ffcc3d4ac891d14a14df438c52a08d0601904e00ffffffffffffff0f0001111111111111111111111111111111111111111100",
                "opPaEV1KrNreA2PV7e3WELT5euXHHr7ZaumSr22xMXuB4vg5vvW",
            ),
            (
                TZ4_ADDR,
                "42",
                99,
                1000,
                200,
                300,
                "6c003923a4e9144201ffcc3d4ac891d14a14df438c52e80763c801ac022a0003333333333333333333333333333333333333333300",
                "ooahRpni4vFn5kwHS6orwuYXdn9xALBp9zad3qYKjSL2w5jTXBY",
            ),
        ];
        for (to, mutez, counter, fee, gas, storage, contents, hash) in cases {
            let t = TezosTx {
                to: to.into(),
                mutez: mutez.into(),
                counter,
                fee,
                gas_limit: gas,
                storage_limit: storage,
                reveal: None,
                ..tx()
            };
            let forged = t.forge(&public()).unwrap();
            assert_eq!(hex::encode(&forged[32..]), contents);
            assert_eq!(t.sign(&SECRET).unwrap().1, hash);
        }
        // Taquito's tz3 vector uses a 16,384-byte storage limit, which the core caps.
        let t = TezosTx {
            to: TZ3_ADDR.into(),
            mutez: "1".into(),
            counter: 128,
            fee: 127,
            gas_limit: 16_383,
            storage_limit: 16_384,
            reveal: None,
            ..tx()
        };
        assert!(t.forge(&public()).is_err());
    }

    /// Reveal plus transfer from the `[7; 32]` test key that Shadownet included at
    /// level 5506037 as `ooss2qoWjSUpyUr3U9vhceXRpJA1GdgG5jp4LP7o7L2k7ECyRXQ`.
    #[test]
    fn reproduces_an_operation_shadownet_included() {
        let t = TezosTx {
            chain_id: SHADOWNET.into(),
            from: SENDER.into(),
            to: RECIPIENT.into(),
            mutez: "1000000".into(),
            branch: "BM37M44HghFhLuj4Rfx5YVTX3KhzqNRdiLYU4HfiVzcCnmNkDEX".into(),
            counter: 33_463_037,
            fee: 550,
            gas_limit: 2201,
            storage_limit: 257,
            reveal: Some(TezosReveal {
                fee: 128,
                gas_limit: 271,
            }),
        };
        let (wire, hash) = t.sign(&SECRET).unwrap();
        assert_eq!(hash, "ooss2qoWjSUpyUr3U9vhceXRpJA1GdgG5jp4LP7o7L2k7ECyRXQ");
        assert_eq!(
            wire,
            "0xae726584072b19595ece47dc756fd6b81787b742a9e5922d88c8e16523125fdd6b003923a4e9144201ffcc3d4ac891d14a14df438c528001fdb5fa0f8f020000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c006c003923a4e9144201ffcc3d4ac891d14a14df438c52a604feb5fa0f99118102c0843d0000d91569fa225ce7ef4d794d706cab5f1c18f7d0da006bc86688f1e17fae65e2cc23ff230e490617d284f5b863da55a98812fcef74f17f47cee9be2ccb18b402576f96a8affd3fedc00feab548926a963cfe65d54b05"
        );
    }

    #[test]
    fn zarith_matches_the_protocol_encoding() {
        let enc = |v| {
            let mut out = vec![];
            zarith(&mut out, v);
            hex::encode(out)
        };
        assert_eq!(enc(0), "00");
        assert_eq!(enc(127), "7f");
        assert_eq!(enc(128), "8001");
        assert_eq!(enc(16_383), "ff7f");
        assert_eq!(enc(16_384), "808001");
        assert_eq!(enc(9_007_199_254_740_991), "ffffffffffffff0f");
    }

    #[test]
    fn signature_verifies_and_assemble_checks_it() {
        let t = tx();
        let (wire, _) = t.sign(&SECRET).unwrap();
        let bytes = hex::decode(wire.trim_start_matches("0x")).unwrap();
        let (forged, sig) = bytes.split_at(bytes.len() - 64);
        let digest = blake2b256(&[&[WATERMARK], forged].concat());
        let sig: [u8; 64] = sig.try_into().unwrap();
        SigningKey::from_bytes(&SECRET)
            .verifying_key()
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&sig))
            .unwrap();
        assert_eq!(digest, t.signing_digest(&public()).unwrap());
        assert!(t.assemble(&sig, &public()).is_ok());
        let mut forged_sig = sig;
        forged_sig[0] ^= 1;
        assert!(t.assemble(&forged_sig, &public()).is_err());
        assert!(t.assemble(&[0; 64], &public()).is_err());
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert!(t.assemble(&sig, &other).is_err());
        assert!(t.forge(&other).is_err());
        assert!(t.sign(&[8; 32]).is_err());
    }

    #[test]
    fn hostile_payloads_are_refused() {
        let base = tx();
        let refused = |f: &dyn Fn(&mut TezosTx)| {
            let mut t = base.clone();
            f(&mut t);
            assert!(t.forge(&public()).is_err(), "{t:?}");
        };
        refused(&|t| t.chain_id = MAINNET.into());
        refused(&|t| t.chain_id = "tezos:NetXnHfVqm9iesp".into());
        refused(&|t| t.mutez = "0".into());
        refused(&|t| t.mutez = "01500000".into());
        refused(&|t| t.mutez = "1.5".into());
        refused(&|t| t.mutez = "9223372036854775808".into());
        refused(&|t| t.to = t.from.clone());
        refused(&|t| t.to = KT1_ADDR.into());
        refused(&|t| t.from = TZ2_ADDR.into());
        refused(&|t| t.branch = "BKnG8VoprFn4jYo8qWdGo3LGwpV9xqtqyb4deycpahXkr3C6drF".into());
        refused(&|t| t.branch = b58check(&BLOCK, &[0; 32]));
        refused(&|t| t.counter = 0);
        refused(&|t| t.counter = MAX_COUNTER + 1);
        refused(&|t| t.fee = MIN_FEE - 1);
        refused(&|t| t.fee = MAX_FEE + 1);
        refused(&|t| t.gas_limit = 0);
        refused(&|t| t.gas_limit = MAX_GAS_LIMIT + 1);
        refused(&|t| t.storage_limit = MAX_STORAGE_LIMIT + 1);
        refused(&|t| t.reveal.as_mut().unwrap().fee = MAX_FEE + 1);
        refused(&|t| t.reveal.as_mut().unwrap().gas_limit = MAX_REVEAL_GAS_LIMIT + 1);

        let mut i = intent(&base);
        if let TxIntentKind::Transfer { amount, .. } = &mut i.kind {
            amount.0 = "1500001".into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { to, .. } = &mut i.kind {
            *to = TZ2_ADDR.into();
        }
        assert!(base.check_matches_intent(&i).is_err());
        let mut i = intent(&base);
        if let TxIntentKind::Transfer { asset, .. } = &mut i.kind {
            asset.0 = format!("{SHADOWNET}:fa2:{KT1_ADDR}:0");
        }
        assert!(base.check_matches_intent(&i).is_err());

        let json = serde_json::json!({
            "chainId": SHADOWNET, "from": SENDER, "to": RECIPIENT, "mutez": "1",
            "branch": BRANCH, "counter": 1, "fee": 400, "gasLimit": 169, "storageLimit": 0,
        });
        let parsed: TezosTx = serde_json::from_value(json.clone()).unwrap();
        assert!(parsed.reveal.is_none());
        for (key, value) in [
            ("parameters", serde_json::json!("00")),
            ("publicKey", serde_json::json!("edpk")),
            ("sun", serde_json::json!("1")),
        ] {
            let mut extra = json.clone();
            extra[key] = value;
            assert!(serde_json::from_value::<TezosTx>(extra).is_err());
        }
        let mut reveal = json.clone();
        reveal["reveal"] = serde_json::json!({ "fee": 374, "gasLimit": 1000, "publicKey": "edpk" });
        assert!(serde_json::from_value::<TezosTx>(reveal).is_err());
    }
}
