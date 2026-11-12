//! Seeded ceremony fuzzing for the TSS support gate: every run of DKG, batch
//! signing and refresh goes through a network that drops, duplicates,
//! corrupts and reorders traffic at random, and whatever happens, the
//! invariants below must hold. A run may fail; it must never fail wrongly.
//!
//! - Parties that finish a DKG agree on the group key.
//! - Any signature a party reports verifies, under an independent verifier,
//!   for the message that was asked for, and the signers agree on it.
//! - A refresh never changes the group key, and a clean one still signs.
//! - Nothing that parses network or page bytes panics on garbage.
//!
//! `STACKWALLET_FUZZ_SEEDS` raises the number of seeds per scenario.

use sha2::{Digest, Sha256};

use stackwallet_core::bitcoin::BitcoinTx;
use stackwallet_core::identity::{self, DeviceIdentity};
use stackwallet_core::intent::SignRequest;
use stackwallet_core::model::{Curve, KeyGroup, PartyRef, PartyRole};
use stackwallet_core::solana::{self, SolanaTx};
use stackwallet_core::tss::frost::FrostCurve;
use stackwallet_core::tss::harness::{Delivery, Faithful, LocalHarness, XorShift64};
use stackwallet_core::tss::{
    CeremonyKind, CeremonyMessage, CeremonySession, CeremonyState, ThresholdScheme,
};

type Tr = frost_secp256k1_tr::Secp256K1Sha256TR;
type Ed = frost_ed25519::Ed25519Sha512;

fn seeds(default: u64) -> u64 {
    std::env::var("STACKWALLET_FUZZ_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// A network that loses, repeats, mangles and reorders, with odds in per mille.
struct Chaos {
    rng: XorShift64,
    drop: u64,
    dup: u64,
    corrupt: u64,
    participants: Vec<String>,
}

impl Chaos {
    fn new(seed: u64, participants: &[&str]) -> Self {
        Self {
            rng: XorShift64::new(seed),
            drop: 15,
            dup: 40,
            corrupt: 20,
            participants: participants.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn roll(&mut self, per_mille: u64) -> bool {
        self.rng.next_u64() % 1000 < per_mille
    }

    fn mangle(&mut self, mut m: CeremonyMessage) -> CeremonyMessage {
        let mut body = hex::decode(&m.body_hex).unwrap_or_default();
        match self.rng.below(8) {
            0 if !body.is_empty() => {
                let i = self.rng.below(body.len());
                body[i] ^= 1 << self.rng.below(8);
            }
            1 if !body.is_empty() => body.truncate(self.rng.below(body.len())),
            2 => body.push(self.rng.next_u64() as u8),
            3 => m.round = m.round.wrapping_add(1 + self.rng.below(2) as u8),
            4 => {
                let i = self.rng.below(self.participants.len() + 1);
                m.to_device_id = self.participants.get(i).cloned();
            }
            5 => m.session_id.push('x'),
            6 => m.payload_hash_hex = hex::encode(Sha256::digest(m.payload_hash_hex.as_bytes())),
            _ => {
                let i = self.rng.below(self.participants.len());
                m.from_device_id = self.participants[i].clone();
            }
        }
        m.body_hex = hex::encode(body);
        m
    }
}

impl Delivery for Chaos {
    fn on_send(&mut self, produced: Vec<CeremonyMessage>) -> Vec<CeremonyMessage> {
        let mut out = Vec::new();
        for m in produced {
            if self.roll(self.drop) {
                continue;
            }
            let m = if self.roll(self.corrupt) {
                self.mangle(m)
            } else {
                m
            };
            if self.roll(self.dup) {
                out.push(m.clone());
            }
            out.push(m);
        }
        out
    }

    fn next(&mut self, in_flight: &mut Vec<CeremonyMessage>) -> Option<CeremonyMessage> {
        if in_flight.is_empty() {
            None
        } else {
            let i = self.rng.below(in_flight.len());
            Some(in_flight.swap_remove(i))
        }
    }
}

/// How an outsider checks one curve's signatures.
trait Verify: FrostCurve {
    /// The messages a batch signs for `seed`, and the request binding them.
    fn batch(group_id: &str, seed: u64) -> (SignRequest, Vec<Vec<u8>>);
    fn verifies(public_key_hex: &str, message: &[u8], signature: &[u8]) -> bool;
}

impl Verify for Tr {
    fn batch(group_id: &str, seed: u64) -> (SignRequest, Vec<Vec<u8>>) {
        // Taproot spends sign one 32-byte sighash per input.
        let messages: Vec<Vec<u8>> = (0..1 + seed % 3)
            .map(|i| Sha256::digest(format!("{seed}-{i}")).to_vec())
            .collect();
        let payload = messages.concat();
        (
            request(group_id, Curve::Secp256k1Tr, seed, &payload),
            messages,
        )
    }

    fn verifies(public_key_hex: &str, message: &[u8], signature: &[u8]) -> bool {
        let sec1 = hex::decode(public_key_hex).unwrap();
        let Ok(vk) = k256::schnorr::VerifyingKey::from_bytes(&sec1[1..33]) else {
            return false;
        };
        let Ok(sig) = k256::schnorr::Signature::try_from(signature) else {
            return false;
        };
        vk.verify_raw(message, &sig).is_ok()
    }
}

impl Verify for Ed {
    fn batch(group_id: &str, seed: u64) -> (SignRequest, Vec<Vec<u8>>) {
        let payload: Vec<u8> = (0..120u64).map(|i| (i ^ seed) as u8).collect();
        (
            request(group_id, Curve::Ed25519, seed, &payload),
            vec![payload],
        )
    }

    fn verifies(public_key_hex: &str, message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 32]>::try_from(hex::decode(public_key_hex).unwrap()) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    }
}

fn request(group_id: &str, curve: Curve, seed: u64, payload: &[u8]) -> SignRequest {
    SignRequest {
        id: format!("req-{seed}"),
        tx_id: format!("tx-{seed}"),
        key_group_id: group_id.into(),
        curve,
        payload_hash_hex: hex::encode(Sha256::digest(payload)),
        payload_hex: hex::encode(payload),
    }
}

fn group(curve: Curve, threshold: u8, ids: &[&str]) -> KeyGroup {
    KeyGroup {
        id: format!("fuzz-{threshold}-{}", ids.len()),
        threshold,
        parties: ids
            .iter()
            .map(|d| PartyRef {
                device_id: (*d).into(),
                role: PartyRole::Human,
            })
            .collect(),
        curves: vec![curve],
        public_keys: vec![],
    }
}

fn session_named(id: &str, kind: CeremonyKind) -> CeremonySession {
    CeremonySession {
        id: id.into(),
        kind,
        key_group_id: String::new(),
        curve: Curve::Ed25519,
        payload_hash_hex: None,
        participants: vec![],
        state: CeremonyState::Rounds,
        created_at_ms: 0,
        expires_at_ms: 0,
    }
}

/// Every signature any signer holds for the last run verifies for every
/// message, and all of them are the same.
fn check_signatures<C: Verify>(
    h: &LocalHarness<C>,
    signers: &[&str],
    public_key_hex: &str,
    messages: &[Vec<u8>],
) {
    let report = h.last_run().unwrap();
    let session = session_named(&report.session_id, CeremonyKind::Sign);
    let mut seen: Option<String> = None;
    for s in signers {
        let Ok(Some(sig)) = h.party(s).unwrap().sign_result(&session) else {
            continue;
        };
        let bytes = hex::decode(&sig.signature_hex).unwrap();
        assert_eq!(
            bytes.len(),
            64 * messages.len(),
            "{s}: one signature per message"
        );
        for (m, chunk) in messages.iter().zip(bytes.chunks(64)) {
            assert!(
                C::verifies(public_key_hex, m, chunk),
                "{s} holds a signature that does not verify: {report:?}"
            );
        }
        if let Some(other) = &seen {
            assert_eq!(other, &sig.signature_hex, "signers disagree");
        }
        seen = Some(sig.signature_hex);
    }
}

/// One seed: DKG, a batch signature and a refresh, all under chaos.
fn lifecycle<C: Verify>(g: &KeyGroup, signers: &[&str], seed: u64) -> &'static str {
    let ids: Vec<&str> = g.parties.iter().map(|p| p.device_id.as_str()).collect();
    let mut net = Chaos::new(seed, &ids);
    let mut h = LocalHarness::<C>::new(g).unwrap();

    let keygen = h.keygen(&mut net);
    let keys: Vec<_> = ids
        .iter()
        .filter_map(|d| h.party(d).unwrap().public_key().unwrap())
        .collect();
    assert!(
        keys.windows(2).all(|w| w[0] == w[1]),
        "seed {seed}: parties finished DKG on different keys"
    );
    let Ok(pk) = keygen else {
        return "keygen failed";
    };

    let (req, messages) = C::batch(&g.id, seed);
    let signed = h.sign_batch(signers, &req, &messages, &mut net);
    check_signatures(&h, signers, &pk.hex, &messages);
    if signed.is_err() {
        return "sign failed";
    }

    let refreshed = h.refresh(&mut net);
    for d in &ids {
        if let Some(k) = h.party(d).unwrap().public_key().unwrap() {
            assert_eq!(k, pk, "seed {seed}: a refresh changed {d}'s group key");
        }
    }
    if refreshed.is_err() {
        return "refresh failed";
    }
    // A completed refresh leaves shares that still sign together.
    let (req, messages) = C::batch(&g.id, seed + 1);
    h.sign_batch(signers, &req, &messages, &mut Faithful)
        .unwrap_or_else(|e| panic!("seed {seed}: refreshed shares no longer sign: {e}"));
    check_signatures(&h, signers, &pk.hex, &messages);
    "complete"
}

fn fuzz<C: Verify>(g: KeyGroup, signers: &[&str], seeds: u64) {
    let mut outcomes = std::collections::BTreeMap::<&str, u64>::new();
    for seed in 1..=seeds {
        *outcomes
            .entry(lifecycle::<C>(&g, signers, seed * 0x9E37_79B9))
            .or_default() += 1;
    }
    // A fuzzer that never lets a ceremony finish, or never breaks one, is not
    // exercising both sides of the invariants.
    assert!(outcomes.contains_key("complete"), "{outcomes:?}");
    assert!(outcomes.len() > 1, "{outcomes:?}");
    eprintln!(
        "{:?} {}-of-{}: {outcomes:?}",
        g.curves[0],
        g.threshold,
        g.parties.len()
    );
}

#[test]
fn taproot_two_of_three_under_chaos() {
    fuzz::<Tr>(
        group(Curve::Secp256k1Tr, 2, &["laptop", "phone", "desk"]),
        &["phone", "desk"],
        seeds(24),
    );
}

#[test]
fn taproot_three_of_five_under_chaos() {
    fuzz::<Tr>(
        group(Curve::Secp256k1Tr, 3, &["a", "b", "c", "d", "e"]),
        &["a", "c", "e"],
        seeds(8),
    );
}

#[test]
fn ed25519_two_of_three_under_chaos() {
    // Curve25519 arithmetic is slow in unoptimized builds; the delivery logic
    // is the same as for Taproot.
    fuzz::<Ed>(
        group(Curve::Ed25519, 2, &["laptop", "phone", "desk"]),
        &["laptop", "desk"],
        seeds(8),
    );
}

// ---------------------------------------------------------------------------
// Parsers that take bytes from the network or the page never panic.
// ---------------------------------------------------------------------------

fn random_bytes(rng: &mut XorShift64, max: usize) -> Vec<u8> {
    (0..rng.below(max + 1))
        .map(|_| rng.next_u64() as u8)
        .collect()
}

#[test]
fn ceremony_bodies_and_transaction_payloads_never_panic() {
    let mut rng = XorShift64::new(0x5EED);
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let valid_btc = serde_json::json!({
        "chainId": "bip122:00000008819873e925422c1ff0f99f7c",
        "from": "tb1pjfymghqd4lskedjflrpym77aca5afstyr5yunudzgcfmslpgwj7q6k2qfd",
        "to": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "amount": "5000",
        "fee": "300",
        "inputs": [{"txid": "11".repeat(32), "vout": 0, "previousTxHex": "0200"}]
    })
    .to_string()
    .into_bytes();
    for _ in 0..seeds(1) * 3000 {
        // Sealed ceremony bodies: garbage must be refused, never panic.
        let msg = CeremonyMessage {
            session_id: "s".into(),
            payload_hash_hex: hex::encode(random_bytes(&mut rng, 40)),
            from_device_id: a.device_id(),
            to_device_id: Some(b.device_id()),
            round: 1 + rng.below(4) as u8,
            body_hex: hex::encode(random_bytes(&mut rng, 200)),
        };
        assert!(identity::open_from(&b, &a.noise_static_public_hex(), msg).is_err());

        // Solana messages and Bitcoin payloads, random and mutated.
        let _ = SolanaTx::from_message(solana::DEVNET, &random_bytes(&mut rng, 300));
        let mut payload = valid_btc.clone();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(payload.len());
            payload[i] = rng.next_u64() as u8;
        }
        let _ = BitcoinTx::from_payload(&payload);
        let _ = BitcoinTx::from_payload(&random_bytes(&mut rng, 300));
    }
}

#[test]
fn ceremony_drivers_refuse_garbage_rounds_without_panicking() {
    // Random bodies for every round of keygen and signing, from a real peer
    // and under the real session: the driver aborts or refuses, never panics.
    let mut rng = XorShift64::new(0xBAD5EED);
    let g = group(Curve::Secp256k1Tr, 2, &["laptop", "phone"]);
    let mut h = LocalHarness::<Tr>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    for _ in 0..seeds(1) * 200 {
        let session = CeremonySession {
            id: format!("g-{}", rng.next_u64()),
            kind: CeremonyKind::Sign,
            key_group_id: g.id.clone(),
            curve: Curve::Secp256k1Tr,
            payload_hash_hex: Some(hex::encode([7u8; 32])),
            participants: vec!["laptop".into(), "phone".into()],
            state: CeremonyState::Rounds,
            created_at_ms: 0,
            expires_at_ms: 60_000,
        };
        let req = SignRequest {
            id: "r".into(),
            tx_id: "t".into(),
            key_group_id: g.id.clone(),
            curve: Curve::Secp256k1Tr,
            payload_hash_hex: hex::encode([7u8; 32]),
            payload_hex: String::new(),
        };
        let mut party = stackwallet_core::tss::frost::FrostParty::<Tr>::new("laptop");
        party
            .import_share(&h.party("laptop").unwrap().export_share().unwrap())
            .unwrap();
        party.sign_start(&req, &session).unwrap();
        for _ in 0..4 {
            let garbage = CeremonyMessage {
                session_id: session.id.clone(),
                payload_hash_hex: hex::encode([7u8; 32]),
                from_device_id: "phone".into(),
                to_device_id: None,
                round: 1 + rng.below(2) as u8,
                body_hex: hex::encode(random_bytes(&mut rng, 160)),
            };
            let _ = party.handle(&session, garbage);
        }
        assert_ne!(party.state(), CeremonyState::Complete);
    }
}
