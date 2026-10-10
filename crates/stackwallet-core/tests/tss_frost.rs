//! FROST gate tests: DKG, sign, refresh across 2-of-3 and 3-of-5 on both
//! curves, independent signature verification, and ceremony fuzzing with
//! dropped, reordered, duplicated, corrupted and payload-substituted messages.

use sha2::{Digest, Sha256};

use stackwallet_core::intent::SignRequest;
use stackwallet_core::model::{Curve, KeyGroup, PartyRef, PartyRole};
use stackwallet_core::tss::frost::{
    keygen_binding_hex, Ed25519Party, FrostCurve, FrostParty, Secp256k1TrParty,
};
use stackwallet_core::tss::harness::{Delivery, Faithful, LocalHarness, Shuffled};
use stackwallet_core::tss::{
    CeremonyKind, CeremonyMessage, CeremonySession, CeremonyState, ThresholdScheme,
};
use stackwallet_core::CoreError;

// ---------------------------------------------------------------------------
// Per-curve glue: how a sign request looks and how an outsider verifies.
// ---------------------------------------------------------------------------

trait Suite: FrostCurve {
    const NAME: &'static str;
    fn request(key_group_id: &str, seed: u8) -> SignRequest;
    fn verify_independently(
        public_key_hex: &str,
        request: &SignRequest,
        signature_hex: &str,
    ) -> bool;
}

impl Suite for frost_ed25519::Ed25519Sha512 {
    const NAME: &'static str = "ed25519";

    fn request(key_group_id: &str, seed: u8) -> SignRequest {
        let payload: Vec<u8> = (0..200u32).map(|i| (i as u8) ^ seed).collect();
        SignRequest {
            id: format!("req-{seed}"),
            tx_id: format!("tx-{seed}"),
            key_group_id: key_group_id.into(),
            curve: Curve::Ed25519,
            payload_hash_hex: hex::encode(Sha256::digest(&payload)),
            payload_hex: hex::encode(payload),
        }
    }

    fn verify_independently(
        public_key_hex: &str,
        request: &SignRequest,
        signature_hex: &str,
    ) -> bool {
        let pk: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();
        let message = hex::decode(&request.payload_hex).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    }
}

impl Suite for frost_secp256k1_tr::Secp256K1Sha256TR {
    const NAME: &'static str = "secp256k1-tr";

    fn request(key_group_id: &str, seed: u8) -> SignRequest {
        SignRequest {
            id: format!("req-{seed}"),
            tx_id: format!("tx-{seed}"),
            key_group_id: key_group_id.into(),
            curve: Curve::Secp256k1Tr,
            payload_hash_hex: hex::encode(Sha256::digest([seed; 40])),
            payload_hex: String::new(),
        }
    }

    fn verify_independently(
        public_key_hex: &str,
        request: &SignRequest,
        signature_hex: &str,
    ) -> bool {
        let sec1 = hex::decode(public_key_hex).unwrap();
        assert_eq!(sec1.len(), 33, "compressed SEC1 group key");
        let vk = k256::schnorr::VerifyingKey::from_bytes(&sec1[1..33]).unwrap();
        let sig_bytes = hex::decode(signature_hex).unwrap();
        let sig = k256::schnorr::Signature::try_from(&sig_bytes[..]).unwrap();
        let sighash = hex::decode(&request.payload_hash_hex).unwrap();
        vk.verify_raw(&sighash, &sig).is_ok()
    }
}

fn group(id: &str, threshold: u8, ids: &[(&str, PartyRole)], curve: Curve) -> KeyGroup {
    KeyGroup {
        id: id.into(),
        threshold,
        parties: ids
            .iter()
            .map(|(d, role)| PartyRef {
                device_id: (*d).into(),
                role: *role,
            })
            .collect(),
        curves: vec![curve],
        public_keys: vec![],
    }
}

fn two_of_three(curve: Curve) -> KeyGroup {
    group(
        "g23",
        2,
        &[
            ("laptop", PartyRole::Human),
            ("phone", PartyRole::Human),
            ("agent", PartyRole::Agent),
        ],
        curve,
    )
}

fn three_of_five(curve: Curve) -> KeyGroup {
    group(
        "g35",
        3,
        &[
            ("laptop", PartyRole::Human),
            ("phone", PartyRole::Human),
            ("agent", PartyRole::Agent),
            ("cli", PartyRole::Automation),
            ("tablet", PartyRole::Human),
        ],
        curve,
    )
}

/// Applies a per-message rewrite to everything parties emit.
struct Tamper<F: FnMut(CeremonyMessage) -> Vec<CeremonyMessage>>(F);

impl<F: FnMut(CeremonyMessage) -> Vec<CeremonyMessage>> Delivery for Tamper<F> {
    fn on_send(&mut self, produced: Vec<CeremonyMessage>) -> Vec<CeremonyMessage> {
        let mut out = Vec::new();
        for m in produced {
            out.extend((self.0)(m));
        }
        out
    }
}

/// Fires `f` on the first message matching sender and round, once.
fn once(
    from: &'static str,
    round: u8,
    mut f: impl FnMut(CeremonyMessage) -> Vec<CeremonyMessage>,
) -> impl FnMut(CeremonyMessage) -> Vec<CeremonyMessage> {
    let mut done = false;
    move |m| {
        if !done && m.from_device_id == from && m.round == round {
            done = true;
            f(m)
        } else {
            vec![m]
        }
    }
}

fn flip_byte(body_hex: &str) -> String {
    let mut bytes = hex::decode(body_hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// DKG -> sign -> independent verification
// ---------------------------------------------------------------------------

fn dkg_sign_verify<C: Suite>(g: KeyGroup, signers: &[&str]) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    let pk = h.keygen(&mut Faithful).unwrap();
    assert_eq!(pk.curve, C::CURVE);
    for id in h.device_ids() {
        assert!(h.party(&id).unwrap().has_share(), "{} holds a share", id);
        assert_eq!(h.party(&id).unwrap().public_key().unwrap().unwrap(), pk);
    }
    let req = C::request(&g.id, 7);
    let sig = h.sign(signers, &req, &mut Faithful).unwrap();
    assert_eq!(sig.sign_request_id, req.id);
    assert_eq!(sig.curve, C::CURVE);
    assert_eq!(sig.recovery_id, None);
    assert!(
        C::verify_independently(&pk.hex, &req, &sig.signature_hex),
        "{} signature must verify outside frost",
        C::NAME
    );
    // A different signer subset must also produce a valid signature.
    let others: Vec<&str> = g
        .parties
        .iter()
        .map(|p| p.device_id.as_str())
        .rev()
        .take(g.threshold as usize)
        .collect();
    let req2 = C::request(&g.id, 9);
    let sig2 = h.sign(&others, &req2, &mut Faithful).unwrap();
    assert!(C::verify_independently(&pk.hex, &req2, &sig2.signature_hex));
    // And a signature over one request never verifies for another.
    assert!(!C::verify_independently(&pk.hex, &req2, &sig.signature_hex));
}

#[test]
fn ed25519_two_of_three_signs_and_verifies_with_dalek() {
    dkg_sign_verify::<frost_ed25519::Ed25519Sha512>(
        two_of_three(Curve::Ed25519),
        &["laptop", "agent"],
    );
}

#[test]
fn ed25519_three_of_five_signs_and_verifies_with_dalek() {
    dkg_sign_verify::<frost_ed25519::Ed25519Sha512>(
        three_of_five(Curve::Ed25519),
        &["phone", "cli", "tablet"],
    );
}

#[test]
fn secp256k1_tr_two_of_three_signs_and_verifies_with_k256_bip340() {
    dkg_sign_verify::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        two_of_three(Curve::Secp256k1Tr),
        &["phone", "agent"],
    );
}

#[test]
fn secp256k1_tr_three_of_five_signs_and_verifies_with_k256_bip340() {
    dkg_sign_verify::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        &["laptop", "agent", "cli"],
    );
}

#[test]
fn taproot_output_key_is_the_x_only_group_key() {
    let g = two_of_three(Curve::Secp256k1Tr);
    let mut h = LocalHarness::<frost_secp256k1_tr::Secp256K1Sha256TR>::new(&g).unwrap();
    let pk = h.keygen(&mut Faithful).unwrap();
    let xonly = h
        .party("laptop")
        .unwrap()
        .taproot_output_key_hex()
        .unwrap()
        .unwrap();
    assert_eq!(xonly.len(), 64);
    assert_eq!(xonly, pk.hex[2..]);
    assert!(k256::schnorr::VerifyingKey::from_bytes(&hex::decode(&xonly).unwrap()).is_ok());
}

// ---------------------------------------------------------------------------
// Threshold is enforced
// ---------------------------------------------------------------------------

fn below_threshold_refused<C: Suite>(g: KeyGroup, signers: &[&str]) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let req = C::request(&g.id, 1);
    let err = h.sign(signers, &req, &mut Faithful).unwrap_err();
    assert!(
        matches!(err, CoreError::Ceremony(ref m) if m.contains("below threshold")),
        "{err}"
    );
    // Nothing started: the parties still sit on the finished keygen ceremony.
    assert_eq!(h.last_run().unwrap().kind, CeremonyKind::KeyGen);
    for id in h.device_ids() {
        assert_eq!(
            h.party(&id).unwrap().progress().unwrap().kind,
            CeremonyKind::KeyGen
        );
    }
}

/// Bypasses the driver entirely and asks frost itself to sign with t-1 key
/// packages, so the threshold is shown to be enforced by the maths and not
/// only by the gate in `sign_start`.
fn frost_refuses_t_minus_one<C: Suite>(g: KeyGroup) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let t = g.threshold as usize;
    let blobs: Vec<_> = h
        .device_ids()
        .iter()
        .take(t - 1)
        .map(|d| h.party(d).unwrap().export_share().unwrap())
        .collect();
    let packages: Vec<frost_core::keys::KeyPackage<C>> = blobs
        .iter()
        .map(|b| frost_core::keys::KeyPackage::<C>::deserialize(&b.key_package).unwrap())
        .collect();
    let pubkeys =
        frost_core::keys::PublicKeyPackage::<C>::deserialize(&blobs[0].public_key_package).unwrap();
    let mut rng = rand_core_06::OsRng;
    let mut nonces = Vec::new();
    let mut commitments = std::collections::BTreeMap::new();
    for kp in &packages {
        let (n, c) = frost_core::round1::commit(kp.signing_share(), &mut rng);
        nonces.push(n);
        commitments.insert(*kp.identifier(), c);
    }
    let package = frost_core::SigningPackage::<C>::new(commitments, b"short of signers");
    for (kp, n) in packages.iter().zip(&nonces) {
        assert!(frost_core::round2::sign(&package, n, kp).is_err());
    }
    let shares = std::collections::BTreeMap::new();
    assert!(frost_core::aggregate(&package, &shares, &pubkeys).is_err());
}

#[test]
fn frost_itself_refuses_t_minus_one_signers() {
    frost_refuses_t_minus_one::<frost_ed25519::Ed25519Sha512>(two_of_three(Curve::Ed25519));
    frost_refuses_t_minus_one::<frost_secp256k1_tr::Secp256K1Sha256TR>(three_of_five(
        Curve::Secp256k1Tr,
    ));
}

#[test]
fn t_minus_one_signers_are_refused() {
    below_threshold_refused::<frost_ed25519::Ed25519Sha512>(
        two_of_three(Curve::Ed25519),
        &["laptop"],
    );
    below_threshold_refused::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        &["laptop", "phone"],
    );
}

/// Every signer aggregates for itself, so losing one party's share leaves the
/// others one short while that party, which holds all t shares, still
/// finishes. The deprived parties must stall at round 2 with no signature.
fn missing_share_blocks_aggregation<C: Suite>(g: KeyGroup, signers: &[&str], victim: &'static str) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let req = C::request(&g.id, 2);
    let mut drop_share = Tamper(once(victim, 2, |_| vec![]));
    let err = h.sign(signers, &req, &mut drop_share).unwrap_err();
    assert!(matches!(err, CoreError::Ceremony(_)), "{err}");
    let report = h.last_run().unwrap();
    assert!(report.aborted.is_empty(), "{report:?}");
    assert_eq!(report.incomplete_round(), Some(2));
    assert_eq!(report.complete, vec![victim.to_owned()]);
    let session = session_stub(report.session_id.clone(), &req);
    for id in signers.iter().filter(|s| **s != victim) {
        let party = h.party(id).unwrap();
        assert_eq!(party.state(), CeremonyState::Rounds);
        assert_eq!(party.progress().unwrap().missing, vec![victim.to_owned()]);
        assert!(party.sign_result(&session).unwrap().is_none());
    }
}

fn session_stub(id: String, req: &SignRequest) -> CeremonySession {
    CeremonySession {
        id,
        kind: CeremonyKind::Sign,
        key_group_id: req.key_group_id.clone(),
        curve: req.curve,
        payload_hash_hex: Some(req.payload_hash_hex.clone()),
        participants: vec![],
        state: CeremonyState::Rounds,
        created_at_ms: 0,
        expires_at_ms: 0,
    }
}

#[test]
fn t_minus_one_signature_shares_cannot_aggregate() {
    missing_share_blocks_aggregation::<frost_ed25519::Ed25519Sha512>(
        two_of_three(Curve::Ed25519),
        &["laptop", "phone"],
        "phone",
    );
    missing_share_blocks_aggregation::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        &["laptop", "phone", "cli"],
        "cli",
    );
}

// ---------------------------------------------------------------------------
// Payload binding
// ---------------------------------------------------------------------------

fn payload_substitution_aborts<C: Suite>(g: KeyGroup, signers: &[&str]) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let req = C::request(&g.id, 3);
    let other = C::request(&g.id, 4);
    let mut swap = Tamper(once("phone", 1, move |mut m| {
        m.payload_hash_hex = other.payload_hash_hex.clone();
        vec![m]
    }));
    let err = h.sign(signers, &req, &mut swap).unwrap_err();
    assert!(matches!(err, CoreError::Ceremony(_)), "{err}");
    let report = h.last_run().unwrap();
    let aborted: Vec<&str> = report.aborted.iter().map(|(d, _)| d.as_str()).collect();
    for s in signers.iter().filter(|s| **s != "phone") {
        assert!(
            aborted.contains(s),
            "{s} must abort on a substituted payload: {report:?}"
        );
        assert_eq!(h.party(s).unwrap().state(), CeremonyState::Aborted);
    }
    assert!(report
        .aborted
        .iter()
        .all(|(_, why)| why.contains("different payload")));
    assert_ne!(h.party("phone").unwrap().state(), CeremonyState::Complete);
}

#[test]
fn substituted_payload_is_refused_and_aborts() {
    payload_substitution_aborts::<frost_ed25519::Ed25519Sha512>(
        two_of_three(Curve::Ed25519),
        &["laptop", "phone"],
    );
    payload_substitution_aborts::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        &["laptop", "phone", "tablet"],
    );
}

/// A stranger who learns the session id and injects a message bound to a
/// different payload must be refused without taking the live ceremony down.
#[test]
fn stranger_with_wrong_binding_is_refused_not_fatal() {
    let g = two_of_three(Curve::Secp256k1Tr);
    let mut h = LocalHarness::<frost_secp256k1_tr::Secp256K1Sha256TR>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let req = <frost_secp256k1_tr::Secp256K1Sha256TR as Suite>::request(&g.id, 6);
    let other = <frost_secp256k1_tr::Secp256K1Sha256TR as Suite>::request(&g.id, 7);
    let mut inject = Tamper(once("phone", 1, move |m| {
        let mut forged = m.clone();
        forged.from_device_id = "stranger".into();
        forged.payload_hash_hex = other.payload_hash_hex.clone();
        vec![forged, m]
    }));
    let sig = h.sign(&["laptop", "phone"], &req, &mut inject).unwrap();
    assert_eq!(sig.curve, Curve::Secp256k1Tr);
    let report = h.last_run().unwrap();
    assert!(report.aborted.is_empty(), "{report:?}");
    assert!(
        report
            .refused
            .iter()
            .any(|(_, why)| why.contains("not part of this ceremony")),
        "{report:?}"
    );
}

#[test]
fn sign_session_must_be_bound_to_the_request_hash() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let req = <frost_ed25519::Ed25519Sha512 as Suite>::request(&g.id, 5);
    let mut session = session_stub("loose".into(), &req);
    session.participants = vec!["laptop".into(), "phone".into()];
    session.payload_hash_hex = None;
    let err = h
        .party_mut("laptop")
        .unwrap()
        .sign_start(&req, &session)
        .unwrap_err();
    assert!(matches!(err, CoreError::Invalid { .. }), "{err}");
    let tampered = SignRequest {
        payload_hash_hex: "11".repeat(32),
        ..req.clone()
    };
    session.payload_hash_hex = Some(tampered.payload_hash_hex.clone());
    let err = h
        .party_mut("laptop")
        .unwrap()
        .sign_start(&tampered, &session)
        .unwrap_err();
    assert!(matches!(err, CoreError::Invalid { .. }), "{err}");
}

// ---------------------------------------------------------------------------
// Fuzz: reorder, drop, duplicate, corrupt
// ---------------------------------------------------------------------------

fn full_lifecycle_under<C: Suite>(g: &KeyGroup, signers: &[&str], delivery: &mut dyn Delivery) {
    let mut h = LocalHarness::<C>::new(g).unwrap();
    let pk = h.keygen(delivery).unwrap();
    let req = C::request(&g.id, 11);
    let sig = h.sign(signers, &req, delivery).unwrap();
    assert!(C::verify_independently(&pk.hex, &req, &sig.signature_hex));
    assert_eq!(h.refresh(delivery).unwrap(), pk);
    let req2 = C::request(&g.id, 12);
    let sig2 = h.sign(signers, &req2, delivery).unwrap();
    assert!(C::verify_independently(&pk.hex, &req2, &sig2.signature_hex));
}

#[test]
fn reordered_delivery_still_completes() {
    // curve25519 arithmetic is slow in unoptimized builds, so Ed25519 gets
    // fewer seeds on the smaller group; the ordering logic is curve-agnostic.
    for seed in 1..=6u64 {
        full_lifecycle_under::<frost_secp256k1_tr::Secp256K1Sha256TR>(
            &three_of_five(Curve::Secp256k1Tr),
            &["phone", "cli", "tablet"],
            &mut Shuffled::new(seed * 7919),
        );
    }
    for seed in 1..=2u64 {
        full_lifecycle_under::<frost_ed25519::Ed25519Sha512>(
            &two_of_three(Curve::Ed25519),
            &["laptop", "agent"],
            &mut Shuffled::new(seed),
        );
    }
}

#[test]
fn reordering_crosses_rounds_and_exercises_buffering() {
    // Shuffling the whole in-flight set lets a fast party's round-2 message
    // arrive before a slow party's round-1 message. The harness report must
    // show no refusals: everything was buffered, nothing was bounced.
    let g = three_of_five(Curve::Ed25519);
    let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();
    let mut d = Shuffled::new(0xC0FFEE);
    h.keygen(&mut d).unwrap();
    assert!(h.last_run().unwrap().refused.is_empty());
    let req = <frost_ed25519::Ed25519Sha512 as Suite>::request(&g.id, 13);
    h.sign(&["laptop", "phone", "agent", "cli", "tablet"], &req, &mut d)
        .unwrap();
    assert!(h.last_run().unwrap().refused.is_empty());
}

#[test]
fn dropped_message_reports_the_incomplete_round() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();

    let mut drop_r1 = Tamper(once("agent", 1, |_| vec![]));
    let err = h.keygen(&mut drop_r1).unwrap_err();
    assert!(err.to_string().contains("round 1 incomplete"), "{err}");
    let report = h.last_run().unwrap();
    assert_eq!(report.incomplete_round(), Some(1));
    assert!(report.aborted.is_empty());
    assert!(report
        .stalled
        .iter()
        .all(|(d, p)| d == "agent" || p.missing == vec!["agent".to_owned()]));

    // Fresh parties: the first attempt left them with no share. Round 2 of
    // DKG is peer-to-peer, so dropping laptop's first round-2 message starves
    // exactly one recipient; the others legitimately finish.
    let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();
    let mut starved = None;
    let mut drop_r2 = Tamper(once("laptop", 2, |m| {
        starved = m.to_device_id.clone();
        vec![]
    }));
    let err = h.keygen(&mut drop_r2).unwrap_err();
    drop(drop_r2);
    assert!(err.to_string().contains("round 2 incomplete"), "{err}");
    let report = h.last_run().unwrap().clone();
    assert_eq!(report.incomplete_round(), Some(2));
    let starved = starved.expect("round 2 is addressed");
    assert_eq!(report.stalled.len(), 1);
    assert_eq!(report.stalled[0].0, starved);
    assert_eq!(report.stalled[0].1.missing, vec!["laptop".to_owned()]);
    assert!(!h.party(&starved).unwrap().has_share());
    assert_eq!(report.complete.len(), 2);
}

#[test]
fn duplicated_messages_are_no_ops() {
    let g = three_of_five(Curve::Secp256k1Tr);
    let mut dup_all = Tamper(|m: CeremonyMessage| vec![m.clone(), m]);
    full_lifecycle_under::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        &g,
        &["laptop", "phone", "agent"],
        &mut dup_all,
    );
    let mut h = LocalHarness::<frost_secp256k1_tr::Secp256K1Sha256TR>::new(&g).unwrap();
    h.keygen(&mut dup_all).unwrap();
    let report = h.last_run().unwrap();
    assert!(report.refused.is_empty(), "{report:?}");
    assert!(report.aborted.is_empty());
}

#[test]
fn corrupted_body_aborts_without_a_signature() {
    for round in [1u8, 2] {
        let g = two_of_three(Curve::Ed25519);
        let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();
        h.keygen(&mut Faithful).unwrap();
        let req = <frost_ed25519::Ed25519Sha512 as Suite>::request(&g.id, 20 + round);
        let mut corrupt = Tamper(once("phone", round, |mut m| {
            m.body_hex = flip_byte(&m.body_hex);
            vec![m]
        }));
        let err = h
            .sign(&["laptop", "phone"], &req, &mut corrupt)
            .unwrap_err();
        let report = h.last_run().unwrap();
        let laptop_abort = report.aborted.iter().find(|(d, _)| d == "laptop");
        // A flipped byte either fails to deserialize (abort on receipt) or
        // decodes to a wrong value that frost rejects at the protocol step.
        assert!(laptop_abort.is_some(), "round {round}: {err} / {report:?}");
        assert_eq!(h.party("laptop").unwrap().state(), CeremonyState::Aborted);
        assert!(h
            .party("laptop")
            .unwrap()
            .sign_result(&session_stub(report.session_id.clone(), &req))
            .is_err());
        if round == 1 {
            // Phone built its signing package from its own good commitment,
            // laptop from the corrupted one; neither can finish.
            assert_ne!(h.party("phone").unwrap().state(), CeremonyState::Complete);
        }
    }
}

#[test]
fn corrupted_dkg_broadcast_aborts_everyone_who_receives_it() {
    let g = three_of_five(Curve::Secp256k1Tr);
    let mut h = LocalHarness::<frost_secp256k1_tr::Secp256K1Sha256TR>::new(&g).unwrap();
    let mut corrupt = Tamper(once("cli", 1, |mut m| {
        m.body_hex = flip_byte(&m.body_hex);
        vec![m]
    }));
    h.keygen(&mut corrupt).unwrap_err();
    for id in ["laptop", "phone", "agent", "tablet"] {
        assert_eq!(h.party(id).unwrap().state(), CeremonyState::Aborted, "{id}");
        assert!(!h.party(id).unwrap().has_share());
    }
}

// ---------------------------------------------------------------------------
// Round discipline on the bare party API
// ---------------------------------------------------------------------------

fn pair_keygen_round1() -> (Ed25519Party, Ed25519Party, CeremonySession, CeremonyMessage) {
    let g = group(
        "pair",
        2,
        &[("a", PartyRole::Human), ("b", PartyRole::Human)],
        Curve::Ed25519,
    );
    let session = CeremonySession {
        id: "pair-keygen".into(),
        kind: CeremonyKind::KeyGen,
        key_group_id: g.id.clone(),
        curve: Curve::Ed25519,
        payload_hash_hex: Some(keygen_binding_hex(&g, Curve::Ed25519)),
        participants: vec!["a".into(), "b".into()],
        state: CeremonyState::Rounds,
        created_at_ms: 0,
        expires_at_ms: 0,
    };
    let mut a = Ed25519Party::new("a");
    let mut b = Ed25519Party::new("b");
    let from_a = a.keygen_start(&g, &session).unwrap().remove(0);
    let _from_b = b.keygen_start(&g, &session).unwrap();
    (a, b, session, from_a)
}

#[test]
fn far_future_round_is_refused_without_aborting() {
    let (_a, mut b, session, from_a) = pair_keygen_round1();
    let mut ahead = from_a.clone();
    ahead.round = 3;
    assert!(b.handle(&session, ahead).is_err());
    assert_eq!(b.state(), CeremonyState::Rounds);
    let mut zero = from_a.clone();
    zero.round = 0;
    assert!(b.handle(&session, zero).is_err());
    assert_eq!(b.state(), CeremonyState::Rounds);
    // The genuine message still goes through afterwards.
    assert_eq!(b.handle(&session, from_a).unwrap().len(), 1);
}

#[test]
fn next_round_is_buffered_and_stale_round_refused() {
    let (_a, mut b, session, from_a) = pair_keygen_round1();
    let mut next = from_a.clone();
    next.round = 2;
    next.to_device_id = Some("b".into());
    assert!(b.handle(&session, next).unwrap().is_empty());
    assert_eq!(b.progress().unwrap().missing, vec!["a".to_owned()]);
    assert_eq!(b.state(), CeremonyState::Rounds);

    let mut misrouted = from_a.clone();
    misrouted.to_device_id = Some("someone-else".into());
    assert!(b.handle(&session, misrouted).is_err());
    assert_eq!(b.state(), CeremonyState::Rounds);

    let mut from_self = from_a.clone();
    from_self.from_device_id = "b".into();
    assert!(b.handle(&session, from_self).is_err());
    assert_eq!(b.state(), CeremonyState::Rounds);
}

#[test]
fn equivocation_aborts_but_identical_duplicate_does_not() {
    let (a, mut b, session, from_a) = pair_keygen_round1();
    let (_, c, _, from_c) = pair_keygen_round1();
    // b accepts a's broadcast once and ignores an identical copy.
    let replies = b.handle(&session, from_a.clone()).unwrap();
    assert_eq!(replies.len(), 1, "round 2 is peer-to-peer, one peer");
    assert!(b.handle(&session, from_a.clone()).unwrap().is_empty());
    assert_eq!(b.state(), CeremonyState::Rounds);
    // Then a second, different round-1 body claiming to be from a.
    let mut forged = from_c.clone();
    forged.from_device_id = "a".into();
    forged.session_id = session.id.clone();
    forged.payload_hash_hex = from_a.payload_hash_hex.clone();
    let err = b.handle(&session, forged).unwrap_err();
    assert!(err.to_string().contains("two different"), "{err}");
    assert_eq!(b.state(), CeremonyState::Aborted);
    assert!(b.handle(&session, from_a).is_err());
    // Unrelated parties are untouched.
    assert_eq!(a.state(), CeremonyState::Rounds);
    assert_eq!(c.state(), CeremonyState::Rounds);
}

#[test]
fn wrong_session_is_refused_without_aborting() {
    let (_a, mut b, session, from_a) = pair_keygen_round1();
    let mut other = session.clone();
    other.id = "another".into();
    assert!(b.handle(&other, from_a.clone()).is_err());
    let mut wrong = from_a;
    wrong.session_id = "another".into();
    assert!(b.handle(&session, wrong).is_err());
    assert_eq!(b.state(), CeremonyState::Rounds);
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

fn refresh_rotates_shares_but_not_the_key<C: Suite>(g: KeyGroup, signers: &[&str]) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    let pk = h.keygen(&mut Faithful).unwrap();
    let old: Vec<_> = h
        .device_ids()
        .iter()
        .map(|d| h.party(d).unwrap().export_share().unwrap())
        .collect();

    assert_eq!(h.refresh(&mut Faithful).unwrap(), pk);
    for (blob, d) in old.iter().zip(h.device_ids()) {
        let fresh = h.party(&d).unwrap().export_share().unwrap();
        assert_ne!(fresh.key_package, blob.key_package, "{d} share must rotate");
        assert_ne!(fresh.public_key_package, blob.public_key_package);
        assert_eq!(h.party(&d).unwrap().public_key().unwrap().unwrap(), pk);
    }

    let req = C::request(&g.id, 30);
    let sig = h.sign(signers, &req, &mut Faithful).unwrap();
    assert!(C::verify_independently(&pk.hex, &req, &sig.signature_hex));

    // One party rolls back to its pre-refresh share: it can no longer sign
    // with the others, and nobody ends up holding a valid signature.
    let stale = signers[0];
    let stale_blob = old.iter().find(|b| b.device_id == stale).expect("exported");
    h.party_mut(stale)
        .unwrap()
        .import_share(stale_blob)
        .unwrap();
    let req2 = C::request(&g.id, 31);
    let err = h.sign(signers, &req2, &mut Faithful).unwrap_err();
    assert!(matches!(err, CoreError::Ceremony(_)), "{err}");
    let report = h.last_run().unwrap();
    assert!(!report.aborted.is_empty(), "{report:?}");
    assert!(report.complete.is_empty(), "{report:?}");
}

#[test]
fn refresh_keeps_public_key_and_invalidates_old_shares() {
    refresh_rotates_shares_but_not_the_key::<frost_ed25519::Ed25519Sha512>(
        two_of_three(Curve::Ed25519),
        &["laptop", "agent"],
    );
    refresh_rotates_shares_but_not_the_key::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        &["phone", "agent", "tablet"],
    );
}

#[test]
fn refresh_among_a_subset_removes_the_rest() {
    let g = three_of_five(Curve::Ed25519);
    let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();
    let pk = h.keygen(&mut Faithful).unwrap();
    let kept = ["laptop", "phone", "agent", "cli"];
    assert_eq!(h.refresh_with(&kept, &mut Faithful).unwrap(), pk);
    let req = <frost_ed25519::Ed25519Sha512 as Suite>::request(&g.id, 40);
    let sig = h
        .sign(&["laptop", "phone", "cli"], &req, &mut Faithful)
        .unwrap();
    assert!(
        <frost_ed25519::Ed25519Sha512 as Suite>::verify_independently(
            &pk.hex,
            &req,
            &sig.signature_hex
        )
    );
    // The removed tablet cannot even start a ceremony with refreshed peers.
    let req2 = <frost_ed25519::Ed25519Sha512 as Suite>::request(&g.id, 41);
    assert!(h
        .sign(&["laptop", "phone", "tablet"], &req2, &mut Faithful)
        .is_err());
}

// ---------------------------------------------------------------------------
// Share export / import
// ---------------------------------------------------------------------------

fn export_import_then_sign<C: Suite>(g: KeyGroup, signers: &[&str]) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    let pk = h.keygen(&mut Faithful).unwrap();
    let blobs: Vec<_> = h
        .device_ids()
        .iter()
        .map(|d| h.party(d).unwrap().export_share().unwrap())
        .collect();
    for b in &blobs {
        assert_eq!(b.curve, C::CURVE);
        assert_eq!(b.key_group_id, g.id);
        let json = serde_json::to_string(b).unwrap();
        assert!(json.contains("\"keyPackage\""));
        let back: stackwallet_core::tss::ShareBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, b);
    }

    let mut restored = LocalHarness::<C>::new(&g).unwrap();
    for b in &blobs {
        restored
            .party_mut(&b.device_id)
            .unwrap()
            .import_share(b)
            .unwrap();
        assert_eq!(
            restored
                .party(&b.device_id)
                .unwrap()
                .public_key()
                .unwrap()
                .unwrap(),
            pk
        );
    }
    let req = C::request(&g.id, 50);
    let sig = restored.sign(signers, &req, &mut Faithful).unwrap();
    assert!(C::verify_independently(&pk.hex, &req, &sig.signature_hex));
}

#[test]
fn exported_shares_import_and_sign() {
    export_import_then_sign::<frost_ed25519::Ed25519Sha512>(
        two_of_three(Curve::Ed25519),
        &["phone", "agent"],
    );
    export_import_then_sign::<frost_secp256k1_tr::Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        &["laptop", "cli", "tablet"],
    );
}

#[test]
fn import_rejects_foreign_or_mismatched_blobs() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let laptop = h.party("laptop").unwrap().export_share().unwrap();

    let mut other_device = Ed25519Party::new("phone");
    assert!(matches!(
        other_device.import_share(&laptop),
        Err(CoreError::Invalid { .. })
    ));

    let mut relabelled = laptop.clone();
    relabelled.device_id = "phone".into();
    assert!(matches!(
        other_device.import_share(&relabelled),
        Err(CoreError::Invalid { .. })
    ));

    let mut wrong_curve = Secp256k1TrParty::new("laptop");
    assert!(matches!(
        wrong_curve.import_share(&laptop),
        Err(CoreError::Invalid { .. })
    ));

    let mut truncated = laptop.clone();
    truncated.key_package.truncate(8);
    assert!(matches!(
        Ed25519Party::new("laptop").import_share(&truncated),
        Err(CoreError::Crypto(_))
    ));
}

// ---------------------------------------------------------------------------
// D6 and structural refusals
// ---------------------------------------------------------------------------

#[test]
fn harness_refuses_agent_only_threshold() {
    let g = group(
        "d6",
        1,
        &[("agent", PartyRole::Agent), ("laptop", PartyRole::Human)],
        Curve::Ed25519,
    );
    assert!(matches!(
        LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g),
        Err(CoreError::AgentThreshold(_))
    ));
    // The party itself refuses as well, so a bypassed harness gains nothing.
    let session = CeremonySession {
        id: "d6".into(),
        kind: CeremonyKind::KeyGen,
        key_group_id: g.id.clone(),
        curve: Curve::Ed25519,
        payload_hash_hex: None,
        participants: vec!["agent".into(), "laptop".into()],
        state: CeremonyState::Rounds,
        created_at_ms: 0,
        expires_at_ms: 0,
    };
    assert!(matches!(
        Ed25519Party::new("agent").keygen_start(&g, &session),
        Err(CoreError::AgentThreshold(_))
    ));
}

#[test]
fn harness_refuses_group_without_its_curve() {
    let g = two_of_three(Curve::Secp256k1Tr);
    assert!(LocalHarness::<frost_ed25519::Ed25519Sha512>::new(&g).is_err());
}

#[test]
fn dkg_participants_must_match_the_group() {
    let g = two_of_three(Curve::Ed25519);
    let mut session = CeremonySession {
        id: "s".into(),
        kind: CeremonyKind::KeyGen,
        key_group_id: g.id.clone(),
        curve: Curve::Ed25519,
        payload_hash_hex: None,
        participants: vec!["laptop".into(), "phone".into()],
        state: CeremonyState::Rounds,
        created_at_ms: 0,
        expires_at_ms: 0,
    };
    let mut p = Ed25519Party::new("laptop");
    assert!(p.keygen_start(&g, &session).is_err());
    session.participants.push("agent".into());
    session.payload_hash_hex = Some("00".repeat(32));
    assert!(p.keygen_start(&g, &session).is_err(), "wrong binding");
    session.payload_hash_hex = None;
    assert_eq!(p.keygen_start(&g, &session).unwrap().len(), 1);
    assert_eq!(p.state(), CeremonyState::Rounds);
    assert!(
        p.keygen_start(&g, &session).is_err(),
        "one ceremony at a time"
    );
}

#[test]
fn generic_party_type_is_object_safe() {
    let parties: Vec<Box<dyn ThresholdScheme>> = vec![
        Box::new(FrostParty::<frost_ed25519::Ed25519Sha512>::new("x")),
        Box::new(Secp256k1TrParty::new("y")),
    ];
    assert_eq!(parties[0].curve(), Curve::Ed25519);
    assert_eq!(parties[1].curve(), Curve::Secp256k1Tr);
    assert_eq!(parties[1].party_id(), "y");
    assert_eq!(parties[0].state(), CeremonyState::Proposed);
    assert!(parties[0].progress().is_none());
}
