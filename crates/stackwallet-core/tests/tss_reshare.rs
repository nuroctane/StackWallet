//! Device-loss drill: a lost device is replaced by a fresh one without
//! changing the group key, so every address stays; the replacement signs with
//! the others; the lost device's share no longer combines with any current
//! one; and a helper that lies, a replaced device that keeps talking, or a
//! group that cannot spare the device are all refused without changing a
//! single share.

use std::collections::BTreeMap;

use frost_core::keys::repairable::Sigma;
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Field, Group, SigningPackage};
use rand_core_06::OsRng;
use sha2::{Digest, Sha256};

use stackwallet_core::intent::SignRequest;
use stackwallet_core::model::{Curve, KeyGroup, PartyRef, PartyRole, PublicKey};
use stackwallet_core::tss::frost::{
    identifier_for, replaced_group, reshare_binding_hex, Ed25519Sha512, FrostCurve, FrostParty,
    Secp256K1Sha256TR,
};
use stackwallet_core::tss::harness::{Delivery, Faithful, LocalHarness, Shuffled};
use stackwallet_core::tss::{
    CeremonyKind, CeremonyMessage, CeremonySession, CeremonyState, ThresholdScheme,
};
use stackwallet_core::CoreError;

const NEWCOMER: &str = "replacement";

trait Suite: FrostCurve {
    fn request(key_group_id: &str, seed: u8) -> SignRequest;
    /// Verifies with a library that is not frost.
    fn verifies(public_key_hex: &str, request: &SignRequest, signature_hex: &str) -> bool;
}

impl Suite for Ed25519Sha512 {
    fn request(key_group_id: &str, seed: u8) -> SignRequest {
        let payload: Vec<u8> = (0..120u32).map(|i| (i as u8) ^ seed).collect();
        SignRequest {
            id: format!("req-{seed}"),
            tx_id: format!("tx-{seed}"),
            key_group_id: key_group_id.into(),
            curve: Curve::Ed25519,
            payload_hash_hex: hex::encode(Sha256::digest(&payload)),
            payload_hex: hex::encode(payload),
        }
    }

    fn verifies(public_key_hex: &str, request: &SignRequest, signature_hex: &str) -> bool {
        let pk: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();
        let message = hex::decode(&request.payload_hex).unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    }
}

impl Suite for Secp256K1Sha256TR {
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

    fn verifies(public_key_hex: &str, request: &SignRequest, signature_hex: &str) -> bool {
        let sec1 = hex::decode(public_key_hex).unwrap();
        let vk = k256::schnorr::VerifyingKey::from_bytes(&sec1[1..33]).unwrap();
        let sig = hex::decode(signature_hex).unwrap();
        let sig = k256::schnorr::Signature::try_from(&sig[..]).unwrap();
        vk.verify_raw(&hex::decode(&request.payload_hash_hex).unwrap(), &sig)
            .is_ok()
    }
}

fn party(device_id: &str, role: PartyRole) -> PartyRef {
    PartyRef {
        device_id: device_id.into(),
        role,
    }
}

fn group(id: &str, threshold: u8, parties: &[(&str, PartyRole)], curve: Curve) -> KeyGroup {
    KeyGroup {
        id: id.into(),
        threshold,
        parties: parties.iter().map(|(d, r)| party(d, *r)).collect(),
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

fn packages<C: FrostCurve>(p: &FrostParty<C>) -> (KeyPackage<C>, PublicKeyPackage<C>) {
    let blob = p.export_share().unwrap();
    (
        KeyPackage::deserialize(&blob.key_package).unwrap(),
        PublicKeyPackage::deserialize(&blob.public_key_package).unwrap(),
    )
}

/// Whether two shares together produce a signature the group key accepts,
/// driving frost directly, as a thief holding a share would.
fn cosign<C: Ciphersuite>(
    a: &KeyPackage<C>,
    b: &KeyPackage<C>,
    group: &PublicKeyPackage<C>,
) -> bool {
    let message = b"device-loss drill";
    let (na, ca) = frost_core::round1::commit(a.signing_share(), &mut OsRng);
    let (nb, cb) = frost_core::round1::commit(b.signing_share(), &mut OsRng);
    let package = SigningPackage::new(
        BTreeMap::from([(*a.identifier(), ca), (*b.identifier(), cb)]),
        message,
    );
    let (Ok(sa), Ok(sb)) = (
        frost_core::round2::sign(&package, &na, a),
        frost_core::round2::sign(&package, &nb, b),
    ) else {
        return false;
    };
    let shares = BTreeMap::from([(*a.identifier(), sa), (*b.identifier(), sb)]);
    frost_core::aggregate(&package, &shares, group)
        .is_ok_and(|sig| group.verifying_key().verify(message, &sig).is_ok())
}

/// Applies a per-message rewrite to everything parties emit.
struct Tamper<F: FnMut(CeremonyMessage) -> Vec<CeremonyMessage>>(F);

impl<F: FnMut(CeremonyMessage) -> Vec<CeremonyMessage>> Delivery for Tamper<F> {
    fn on_send(&mut self, produced: Vec<CeremonyMessage>) -> Vec<CeremonyMessage> {
        produced.into_iter().flat_map(|m| (self.0)(m)).collect()
    }
}

/// The length-prefixed items of a repair body: the sigma, then the view.
fn items(body_hex: &str) -> Vec<Vec<u8>> {
    let body = hex::decode(body_hex).unwrap();
    let mut rest = &body[..];
    let mut out = Vec::new();
    while !rest.is_empty() {
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        out.push(rest[4..4 + n].to_vec());
        rest = &rest[4 + n..];
    }
    out
}

fn joined(items: &[Vec<u8>]) -> String {
    let mut out = Vec::new();
    for item in items {
        out.extend((item.len() as u32).to_be_bytes());
        out.extend(item);
    }
    hex::encode(out)
}

/// Rewrites what `from` (every helper when `None`) sends the newcomer in the
/// repair round.
fn rewrite_repair(
    from: Option<&'static str>,
    mut f: impl FnMut(&mut [Vec<u8>]),
) -> impl FnMut(CeremonyMessage) -> Vec<CeremonyMessage> {
    move |mut m| {
        let repair = m.round == 2 && m.to_device_id.as_deref() == Some(NEWCOMER);
        if repair && from.is_none_or(|f| m.from_device_id == f) {
            let mut parts = items(&m.body_hex);
            f(&mut parts);
            m.body_hex = joined(&parts);
        }
        vec![m]
    }
}

/// A sigma that still parses but is one off.
fn bump_sigma<C: Ciphersuite>(parts: &mut [Vec<u8>]) {
    let sigma = Sigma::<C>::deserialize(&parts[0]).unwrap();
    let one = <<C::Group as Group>::Field as Field>::one();
    parts[0] = Sigma::<C>::new(sigma.to_scalar() + one).serialize();
}

/// The same group, claimed to need one more signer.
fn raise_threshold<C: Ciphersuite>(parts: &mut [Vec<u8>]) {
    let view = PublicKeyPackage::<C>::deserialize(&parts[1]).unwrap();
    parts[1] = PublicKeyPackage::new(
        view.verifying_shares().clone(),
        *view.verifying_key(),
        view.min_signers().map(|m| m + 1),
    )
    .serialize()
    .unwrap();
}

fn shares_of<C: FrostCurve>(h: &LocalHarness<C>) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    h.device_ids()
        .into_iter()
        .map(|d| {
            let blob = h.party(&d).unwrap().export_share().unwrap();
            (d, blob.key_package.clone(), blob.public_key_package.clone())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The replacement itself
// ---------------------------------------------------------------------------

fn replacement_keeps_the_key<C: Suite>(g: KeyGroup, lost: &str, signer_sets: &[&[&str]]) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    let key = h.keygen(&mut Faithful).unwrap();
    let after = h
        .replace(lost, &party(NEWCOMER, PartyRole::Human), &mut Faithful)
        .unwrap();
    assert_eq!(
        after, key,
        "the group key, and every address from it, survives"
    );

    let members: Vec<&str> = h
        .group()
        .parties
        .iter()
        .map(|p| p.device_id.as_str())
        .collect();
    assert!(members.contains(&NEWCOMER) && !members.contains(&lost));
    assert_eq!(h.group().threshold, g.threshold);
    assert!(h.party(lost).is_none() && h.retired(lost).is_some());
    let views: Vec<Vec<u8>> = shares_of(&h).into_iter().map(|(_, _, v)| v).collect();
    assert!(
        views.windows(2).all(|w| w[0] == w[1]),
        "every member ends on the same public view of the group"
    );

    for (i, signers) in signer_sets.iter().enumerate() {
        let req = C::request(&g.id, i as u8);
        let sig = h.sign(signers, &req, &mut Faithful).unwrap();
        assert!(
            C::verifies(&key.hex, &req, &sig.signature_hex),
            "{signers:?} sign for the unchanged key"
        );
    }
}

#[test]
fn a_lost_device_is_replaced_without_changing_the_key() {
    let pairs: &[&[&str]] = &[
        &["laptop", NEWCOMER],
        &[NEWCOMER, "agent"],
        &["laptop", "agent"],
    ];
    replacement_keeps_the_key::<Ed25519Sha512>(two_of_three(Curve::Ed25519), "phone", pairs);
    replacement_keeps_the_key::<Secp256K1Sha256TR>(
        two_of_three(Curve::Secp256k1Tr),
        "phone",
        pairs,
    );
    replacement_keeps_the_key::<Ed25519Sha512>(
        three_of_five(Curve::Ed25519),
        "tablet",
        &[&[NEWCOMER, "laptop", "cli"], &["phone", "agent", NEWCOMER]],
    );
    replacement_keeps_the_key::<Secp256K1Sha256TR>(
        three_of_five(Curve::Secp256k1Tr),
        "laptop",
        &[&[NEWCOMER, "phone", "cli"], &["tablet", "agent", "phone"]],
    );
}

fn lost_share_is_useless<C: Suite>() {
    let g = two_of_three(C::CURVE);
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let (laptop_before, group_before) = packages(h.party("laptop").unwrap());
    let (phone_old, _) = packages(h.party("phone").unwrap());
    assert!(
        cosign(&laptop_before, &phone_old, &group_before),
        "control: the two shares signed together before"
    );

    h.replace("phone", &party(NEWCOMER, PartyRole::Human), &mut Faithful)
        .unwrap();
    let retired = h
        .retired("phone")
        .expect("the replaced device is kept aside");
    assert_eq!(
        packages(retired).0.serialize().unwrap(),
        phone_old.serialize().unwrap(),
        "the lost device still holds exactly the share it had"
    );
    let (laptop, group_now) = packages(h.party("laptop").unwrap());
    let (agent, _) = packages(h.party("agent").unwrap());
    let (newcomer, _) = packages(h.party(NEWCOMER).unwrap());
    assert!(
        cosign(&laptop, &newcomer, &group_now),
        "control: the replacement co-signs"
    );

    // Give the thief every advantage: a group view that still lists the lost
    // device's old verifying share beside the current ones.
    let phone = identifier_for::<C>("phone").unwrap();
    let mut shares = group_now.verifying_shares().clone();
    shares.insert(phone, group_before.verifying_shares()[&phone]);
    let lenient =
        PublicKeyPackage::new(shares, *group_now.verifying_key(), group_now.min_signers());
    for current in [&laptop, &agent, &newcomer] {
        assert!(
            !cosign(current, &phone_old, &lenient),
            "the lost share must not combine with a current one"
        );
    }
}

#[test]
fn a_lost_share_no_longer_combines_with_current_ones() {
    lost_share_is_useless::<Ed25519Sha512>();
    lost_share_is_useless::<Secp256K1Sha256TR>();
}

#[test]
fn replacement_completes_under_any_delivery_order() {
    fn run<C: Suite>(seed: u64) {
        let g = three_of_five(C::CURVE);
        let mut h = LocalHarness::<C>::new(&g).unwrap();
        let key = h.keygen(&mut Shuffled::new(seed)).unwrap();
        let newcomer = party(NEWCOMER, PartyRole::Automation);
        let after = h
            .replace("cli", &newcomer, &mut Shuffled::new(seed ^ 0xA5A5))
            .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        assert_eq!(after, key, "seed {seed}");
        let req = C::request(&g.id, seed as u8);
        let sig = h
            .sign(
                &[NEWCOMER, "agent", "tablet"],
                &req,
                &mut Shuffled::new(seed + 1),
            )
            .unwrap();
        assert!(
            C::verifies(&key.hex, &req, &sig.signature_hex),
            "seed {seed}"
        );
    }
    // Curve25519 is slow in unoptimized builds, and the ordering logic is
    // shared, so Ed25519 gets fewer seeds.
    for seed in 1..=8 {
        if seed <= 3 {
            run::<Ed25519Sha512>(seed);
        }
        run::<Secp256K1Sha256TR>(seed);
    }
}

#[test]
fn a_group_survives_successive_replacements() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<Ed25519Sha512>::new(&g).unwrap();
    let key = h.keygen(&mut Faithful).unwrap();
    for (lost, fresh, role) in [
        ("phone", "phone-2", PartyRole::Human),
        ("agent", "agent-2", PartyRole::Agent),
        ("laptop", "laptop-2", PartyRole::Human),
    ] {
        let after = h.replace(lost, &party(fresh, role), &mut Faithful).unwrap();
        assert_eq!(after, key, "replacing {lost}");
    }
    for (i, signers) in [["phone-2", "agent-2"], ["laptop-2", "phone-2"]]
        .iter()
        .enumerate()
    {
        let req = Ed25519Sha512::request(&g.id, 40 + i as u8);
        let sig = h.sign(signers, &req, &mut Faithful).unwrap();
        assert!(Ed25519Sha512::verifies(&key.hex, &req, &sig.signature_hex));
    }
}

// ---------------------------------------------------------------------------
// Misbehaviour and refusals
// ---------------------------------------------------------------------------

/// Runs a replacement of `phone` under `delivery`, expects the newcomer to
/// abort with `why`, then checks nothing changed: same group, same shares,
/// and the original devices still sign.
fn refused_without_a_trace<C: Suite>(g: KeyGroup, delivery: &mut dyn Delivery, why: &str) {
    let mut h = LocalHarness::<C>::new(&g).unwrap();
    let key = h.keygen(&mut Faithful).unwrap();
    let before = shares_of(&h);

    assert!(h
        .replace("phone", &party(NEWCOMER, PartyRole::Human), delivery)
        .is_err());
    let report = h.last_run().unwrap();
    assert!(
        report
            .aborted
            .iter()
            .any(|(d, reason)| d == NEWCOMER && reason.contains(why)),
        "{report:?}"
    );
    assert_eq!(h.group(), &g);
    assert!(h.party(NEWCOMER).is_none() && h.retired("phone").is_none());
    assert_eq!(shares_of(&h), before, "no share changed");

    h.abandon();
    let signers: Vec<&str> = std::iter::once("phone")
        .chain(
            g.parties
                .iter()
                .map(|p| p.device_id.as_str())
                .filter(|d| *d != "phone"),
        )
        .take(g.threshold as usize)
        .collect();
    let req = C::request(&g.id, 77);
    let sig = h.sign(&signers, &req, &mut Faithful).unwrap();
    assert!(
        C::verifies(&key.hex, &req, &sig.signature_hex),
        "the device that was to be replaced still signs"
    );
}

#[test]
fn a_helper_sending_a_wrong_repair_value_is_caught() {
    fn run<C: Suite>() {
        refused_without_a_trace::<C>(
            two_of_three(C::CURVE),
            &mut Tamper(rewrite_repair(Some("laptop"), bump_sigma::<C>)),
            "does not match the group",
        );
    }
    run::<Ed25519Sha512>();
    run::<Secp256K1Sha256TR>();
}

#[test]
fn helpers_must_agree_on_the_group_they_hand_over() {
    fn run<C: Suite>() {
        refused_without_a_trace::<C>(
            three_of_five(C::CURVE),
            &mut Tamper(rewrite_repair(Some("agent"), raise_threshold::<C>)),
            "disagree about the group",
        );
        // Even if every helper told the same story, it must be the proposed
        // group.
        refused_without_a_trace::<C>(
            three_of_five(C::CURVE),
            &mut Tamper(rewrite_repair(None, raise_threshold::<C>)),
            "another group than the one proposed",
        );
    }
    run::<Ed25519Sha512>();
    run::<Secp256K1Sha256TR>();
}

#[test]
fn the_replaced_device_cannot_take_part() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<Ed25519Sha512>::new(&g).unwrap();
    let key = h.keygen(&mut Faithful).unwrap();
    // The lost device (or whoever holds it) replays a refresh broadcast
    // under its own name, bound to the right session.
    let mut injected = false;
    let mut forge = Tamper(move |m: CeremonyMessage| {
        if injected || m.round != 3 {
            return vec![m];
        }
        injected = true;
        let mut fake = m.clone();
        fake.from_device_id = "phone".into();
        vec![m, fake]
    });
    let after = h
        .replace("phone", &party(NEWCOMER, PartyRole::Human), &mut forge)
        .unwrap();
    assert_eq!(after, key);
    let report = h.last_run().unwrap();
    assert!(
        report
            .refused
            .iter()
            .any(|(_, why)| why.contains("not part of this ceremony")),
        "{report:?}"
    );
}

#[test]
fn replacements_that_would_weaken_the_group_are_refused() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<Ed25519Sha512>::new(&g).unwrap();
    h.keygen(&mut Faithful).unwrap();
    // An agent in the phone's place would let agents alone meet the
    // threshold (D6).
    let err = h
        .replace("phone", &party("agent-2", PartyRole::Agent), &mut Faithful)
        .unwrap_err();
    assert!(matches!(err, CoreError::AgentThreshold(_)), "{err}");
    // The newcomer must be new, and the replaced device a member.
    assert!(h
        .replace("phone", &party("laptop", PartyRole::Human), &mut Faithful)
        .is_err());
    assert!(h
        .replace(
            "stranger",
            &party("tablet", PartyRole::Human),
            &mut Faithful
        )
        .is_err());
    assert_eq!(h.group(), &g);

    // A 2-of-2 that loses a device has nobody left to repair a share from.
    let pair = group(
        "g22",
        2,
        &[("laptop", PartyRole::Human), ("phone", PartyRole::Human)],
        Curve::Ed25519,
    );
    let mut h = LocalHarness::<Ed25519Sha512>::new(&pair).unwrap();
    h.keygen(&mut Faithful).unwrap();
    let err = h
        .replace("phone", &party("tablet", PartyRole::Human), &mut Faithful)
        .unwrap_err();
    assert!(err.to_string().contains("cannot repair"), "{err}");
    assert_eq!(h.group(), &pair);
}

#[test]
fn every_party_checks_what_the_reshare_is_bound_to() {
    let g = two_of_three(Curve::Ed25519);
    let mut h = LocalHarness::<Ed25519Sha512>::new(&g).unwrap();
    let key = h.keygen(&mut Faithful).unwrap();
    let newcomer = party(NEWCOMER, PartyRole::Human);
    let next = replaced_group(&g, "phone", &newcomer).unwrap();
    let raw = hex::decode(&key.hex).unwrap();
    let session = |binding: String| CeremonySession {
        id: "reshare-1".into(),
        kind: CeremonyKind::Reshare,
        key_group_id: g.id.clone(),
        curve: Curve::Ed25519,
        payload_hash_hex: Some(binding),
        participants: next.parties.iter().map(|p| p.device_id.clone()).collect(),
        state: CeremonyState::Rounds,
        created_at_ms: 0,
        expires_at_ms: 60_000,
    };
    let right = reshare_binding_hex(&next, Curve::Ed25519, "phone", &raw);

    // Bound to replacing another device: helper and newcomer both refuse.
    let wrong = session(reshare_binding_hex(&next, Curve::Ed25519, "agent", &raw));
    let laptop = h.party_mut("laptop").unwrap();
    assert!(laptop
        .reshare_start(&g, &wrong, "phone", &newcomer, &key)
        .is_err());
    let mut fresh = FrostParty::<Ed25519Sha512>::new(NEWCOMER);
    assert!(fresh
        .reshare_start(&g, &wrong, "phone", &newcomer, &key)
        .is_err());

    // A session that leaves out a remaining party is refused: the refresh
    // would strand that party on a share nobody else can use.
    let mut partial = session(right.clone());
    partial.participants.retain(|d| d != "agent");
    assert!(laptop
        .reshare_start(&g, &partial, "phone", &newcomer, &key)
        .is_err());

    // A group key other than the one this share belongs to is refused.
    let other = PublicKey {
        curve: Curve::Ed25519,
        hex: hex::encode([7u8; 32]),
    };
    let bound_other = session(reshare_binding_hex(
        &next,
        Curve::Ed25519,
        "phone",
        &[7u8; 32],
    ));
    assert!(laptop
        .reshare_start(&g, &bound_other, "phone", &newcomer, &other)
        .is_err());

    assert!(laptop
        .reshare_start(&g, &session(right), "phone", &newcomer, &key)
        .is_ok());
}
