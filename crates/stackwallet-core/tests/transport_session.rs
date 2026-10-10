//! Two `Session`s wired back to back through an in-memory pump, plus a
//! hand-driven Noise peer for the cases an honest `Session` cannot produce.

use stackwallet_core::identity::{DeviceIdentity, SignedCeremonyMessage};
use stackwallet_core::store::{Device, DeviceKind};
use stackwallet_core::transport::{
    hello_binding, Frame, HandshakeRole, Hello, NoiseHandshake, PairingOffer, Session,
    SessionEvent, SessionState, StaticLookup, MAX_FRAME_LEN, TRANSPORT_VERSION,
};
use stackwallet_core::tss::CeremonyMessage;
use stackwallet_core::CoreError;

const NOW: i64 = 1_700_000_000_000;
const LATER: i64 = NOW + 60_000;

struct Party {
    identity: DeviceIdentity,
    device: Device,
}

fn party(name: &str, kind: DeviceKind) -> Party {
    let identity = DeviceIdentity::generate().unwrap();
    let device = Device {
        id: identity.device_id(),
        name: name.into(),
        kind,
        identity_pub_hex: identity.public_hex(),
        noise_static_hex: identity.noise_static_public_hex(),
        endpoints: vec![format!("tcp://10.0.0.1:{}", name.len())],
        paired_at_ms: NOW - 1,
        last_seen_at_ms: None,
        revoked_at_ms: None,
    };
    Party { identity, device }
}

fn offer_from(issuer: &Party, expires_at_ms: i64) -> PairingOffer {
    PairingOffer {
        version: TRANSPORT_VERSION,
        device_id: issuer.device.id.clone(),
        device_name: issuer.device.name.clone(),
        kind: issuer.device.kind,
        identity_pub_hex: issuer.device.identity_pub_hex.clone(),
        noise_static_hex: issuer.device.noise_static_hex.clone(),
        endpoints: issuer.device.endpoints.clone(),
        one_time_code_hex: PairingOffer::new_code().unwrap(),
        expires_at_ms,
    }
}

/// Shuttle bytes until both sides go quiet. Input errors (a closed session
/// being fed) end the pump rather than panic, so refusal paths can be probed.
fn pump(a: &mut Session, b: &mut Session) -> (Vec<SessionEvent>, Vec<SessionEvent>) {
    let mut ea = Vec::new();
    let mut eb = Vec::new();
    for _ in 0..32 {
        let to_b = a.take_outgoing();
        let to_a = b.take_outgoing();
        if to_b.is_empty() && to_a.is_empty() {
            return (ea, eb);
        }
        for m in to_b {
            if let Ok(ev) = b.handle_incoming(&m) {
                eb.extend(ev);
            }
        }
        for m in to_a {
            if let Ok(ev) = a.handle_incoming(&m) {
                ea.extend(ev);
            }
        }
    }
    panic!("pump did not settle");
}

fn lookup_for(devices: Vec<Device>) -> StaticLookup {
    Box::new(move |s: &[u8; 32]| {
        let hex = hex::encode(s);
        devices.iter().find(|d| d.noise_static_hex == hex).cloned()
    })
}

fn open_ik(initiator: &Party, responder: &Party) -> (Session, Session) {
    let mut a = Session::connect(
        &initiator.identity,
        &initiator.device,
        HandshakeRole::Initiator,
        Some(&responder.device),
        None,
        LATER,
    )
    .unwrap();
    let mut b = Session::connect(
        &responder.identity,
        &responder.device,
        HandshakeRole::Responder,
        None,
        Some(lookup_for(vec![initiator.device.clone()])),
        LATER,
    )
    .unwrap();
    let (ea, eb) = pump(&mut a, &mut b);
    assert!(
        matches!(ea.as_slice(), [SessionEvent::Opened { .. }]),
        "{ea:?}"
    );
    assert!(
        matches!(eb.as_slice(), [SessionEvent::Opened { .. }]),
        "{eb:?}"
    );
    assert_eq!(a.state(), SessionState::Open);
    assert_eq!(b.state(), SessionState::Open);
    (a, b)
}

fn closed_reason(events: &[SessionEvent]) -> &str {
    match events {
        [SessionEvent::Closed { reason }] => reason,
        other => panic!("expected a single Closed event, got {other:?}"),
    }
}

fn ceremony(from: &Party, from_device_id: &str) -> SignedCeremonyMessage {
    SignedCeremonyMessage::sign(
        &from.identity,
        CeremonyMessage {
            session_id: "s1".into(),
            payload_hash_hex: "ab".repeat(32),
            from_device_id: from_device_id.into(),
            to_device_id: None,
            round: 1,
            body_hex: "00ff".into(),
        },
    )
}

// --- pairing -------------------------------------------------------------

#[test]
fn pairing_succeeds_and_pins_both_sides() {
    let issuer = party("desk", DeviceKind::Desktop);
    let scanner = party("phone", DeviceKind::Mobile);
    let offer = offer_from(&issuer, LATER);

    let mut i = Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW).unwrap();
    let mut s = Session::pair_as_scanner(&scanner.identity, &scanner.device, &offer, NOW).unwrap();
    assert!(i.is_pairing() && s.is_pairing());
    assert_eq!(i.state(), SessionState::Handshaking);
    assert_eq!(s.state(), SessionState::Handshaking);

    let (es, ei) = pump(&mut s, &mut i);
    let [SessionEvent::Paired { peer: issuer_seen }] = &es[..] else {
        panic!("{es:?}")
    };
    let [SessionEvent::Paired { peer: scanner_seen }] = &ei[..] else {
        panic!("{ei:?}")
    };
    assert_eq!(s.state(), SessionState::Open);
    assert_eq!(i.state(), SessionState::Open);

    // Scanner's record of the issuer: everything the QR said, stamped now.
    assert_eq!(issuer_seen.id, issuer.device.id);
    assert_eq!(issuer_seen.identity_pub_hex, issuer.device.identity_pub_hex);
    assert_eq!(issuer_seen.noise_static_hex, issuer.device.noise_static_hex);
    assert_eq!(issuer_seen.endpoints, issuer.device.endpoints);
    assert_eq!(issuer_seen.paired_at_ms, NOW);
    assert_eq!(issuer_seen.last_seen_at_ms, Some(NOW));
    assert_eq!(issuer_seen.revoked_at_ms, None);

    // Issuer's record of the scanner: learned entirely from the handshake
    // and the signed Hello.
    assert_eq!(scanner_seen.id, scanner.device.id);
    assert_eq!(scanner_seen.name, "phone");
    assert_eq!(scanner_seen.kind, DeviceKind::Mobile);
    assert_eq!(
        scanner_seen.identity_pub_hex,
        scanner.device.identity_pub_hex
    );
    assert_eq!(
        scanner_seen.noise_static_hex,
        scanner.device.noise_static_hex
    );
    assert_eq!(scanner_seen.endpoints, scanner.device.endpoints);
    assert_eq!(scanner_seen.paired_at_ms, NOW);
    assert_eq!(scanner_seen.last_seen_at_ms, Some(NOW));

    assert_eq!(s.peer(), Some(issuer_seen));
    assert_eq!(i.peer(), Some(scanner_seen));

    // The channel carries authenticated ceremony traffic both ways.
    s.send(Frame::Ceremony(ceremony(&scanner, &scanner.device.id)))
        .unwrap();
    i.send(Frame::Ceremony(ceremony(&issuer, &issuer.device.id)))
        .unwrap();
    let (es, ei) = pump(&mut s, &mut i);
    assert!(matches!(
        es.as_slice(),
        [SessionEvent::Frame(Frame::Ceremony(_))]
    ));
    assert!(matches!(
        ei.as_slice(),
        [SessionEvent::Frame(Frame::Ceremony(_))]
    ));
}

#[test]
fn pairing_with_wrong_one_time_code_fails() {
    let issuer = party("desk", DeviceKind::Desktop);
    let scanner = party("phone", DeviceKind::Mobile);
    let offer = offer_from(&issuer, LATER);
    let mut guessed = offer.clone();
    guessed.one_time_code_hex = PairingOffer::new_code().unwrap();

    let mut i = Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW).unwrap();
    let mut s =
        Session::pair_as_scanner(&scanner.identity, &scanner.device, &guessed, NOW).unwrap();
    let (es, ei) = pump(&mut s, &mut i);
    assert_eq!(closed_reason(&es), "handshake failed");
    assert!(ei.is_empty(), "{ei:?}");
    assert_eq!(s.state(), SessionState::Closed);
    assert_ne!(i.state(), SessionState::Open);
    assert!(i.peer().is_none());
}

#[test]
fn expired_offer_is_refused_on_both_sides() {
    let issuer = party("desk", DeviceKind::Desktop);
    let scanner = party("phone", DeviceKind::Mobile);
    let offer = offer_from(&issuer, NOW);
    for r in [
        Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW).err(),
        Session::pair_as_scanner(&scanner.identity, &scanner.device, &offer, NOW + 1).err(),
    ] {
        assert!(matches!(
            r,
            Some(CoreError::Invalid {
                what: "pairing offer",
                ref reason
            }) if reason == "expired"
        ));
    }
    assert!(Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW - 1).is_ok());
}

#[test]
fn issuer_refuses_an_offer_it_did_not_issue_and_scanner_refuses_itself() {
    let issuer = party("desk", DeviceKind::Desktop);
    let other = party("other", DeviceKind::Cli);
    let offer = offer_from(&issuer, LATER);
    assert!(Session::pair_as_issuer(&other.identity, &other.device, &offer, NOW).is_err());
    assert!(Session::pair_as_scanner(&issuer.identity, &issuer.device, &offer, NOW).is_err());
}

#[test]
fn local_record_must_match_identity() {
    let a = party("a", DeviceKind::Cli);
    let b = party("b", DeviceKind::Cli);
    let offer = offer_from(&a, LATER);
    assert!(matches!(
        Session::pair_as_scanner(&b.identity, &a.device, &offer, NOW),
        Err(CoreError::Invalid {
            what: "session",
            ..
        })
    ));
}

// --- IK ------------------------------------------------------------------

#[test]
fn ik_connect_opens_with_pinned_records() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (a, b) = open_ik(&alice, &bob);
    let bob_seen = a.peer().unwrap();
    let alice_seen = b.peer().unwrap();
    assert_eq!(bob_seen.id, bob.device.id);
    assert_eq!(bob_seen.noise_static_hex, bob.device.noise_static_hex);
    assert_eq!(bob_seen.last_seen_at_ms, Some(LATER));
    assert_eq!(bob_seen.paired_at_ms, bob.device.paired_at_ms);
    assert_eq!(alice_seen.id, alice.device.id);
    assert_eq!(alice_seen.last_seen_at_ms, Some(LATER));
    assert!(!a.is_pairing());
}

#[test]
fn initiator_with_wrong_pinned_static_never_opens() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let carol = party("carol", DeviceKind::Browser);
    let mut stale_bob = bob.device.clone();
    stale_bob.noise_static_hex = carol.device.noise_static_hex.clone();

    let mut a = Session::connect(
        &alice.identity,
        &alice.device,
        HandshakeRole::Initiator,
        Some(&stale_bob),
        None,
        LATER,
    )
    .unwrap();
    let mut b = Session::connect(
        &bob.identity,
        &bob.device,
        HandshakeRole::Responder,
        None,
        Some(lookup_for(vec![alice.device.clone()])),
        LATER,
    )
    .unwrap();
    let (ea, eb) = pump(&mut a, &mut b);
    assert_eq!(closed_reason(&eb), "handshake failed");
    assert!(ea.is_empty());
    assert_eq!(a.state(), SessionState::Handshaking);
    assert!(b.take_outgoing().is_empty());
}

#[test]
fn responder_refuses_unknown_static_before_replying() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mut a = Session::connect(
        &alice.identity,
        &alice.device,
        HandshakeRole::Initiator,
        Some(&bob.device),
        None,
        LATER,
    )
    .unwrap();
    let mut b = Session::connect(
        &bob.identity,
        &bob.device,
        HandshakeRole::Responder,
        None,
        Some(lookup_for(Vec::new())),
        LATER,
    )
    .unwrap();
    let (ea, eb) = pump(&mut a, &mut b);
    assert_eq!(closed_reason(&eb), "unknown device");
    assert!(ea.is_empty());
    assert_eq!(a.state(), SessionState::Handshaking);
    assert!(matches!(
        b.handle_incoming(&[0u8; 48]),
        Err(CoreError::Invalid {
            what: "session",
            ..
        })
    ));
}

#[test]
fn revoked_device_is_refused_by_both_roles() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mut revoked_alice = alice.device.clone();
    revoked_alice.revoked_at_ms = Some(NOW);

    let mut a = Session::connect(
        &alice.identity,
        &alice.device,
        HandshakeRole::Initiator,
        Some(&bob.device),
        None,
        LATER,
    )
    .unwrap();
    let mut b = Session::connect(
        &bob.identity,
        &bob.device,
        HandshakeRole::Responder,
        None,
        Some(lookup_for(vec![revoked_alice.clone()])),
        LATER,
    )
    .unwrap();
    let (_, eb) = pump(&mut a, &mut b);
    assert_eq!(closed_reason(&eb), "revoked device");

    assert!(matches!(
        Session::connect(
            &bob.identity,
            &bob.device,
            HandshakeRole::Initiator,
            Some(&revoked_alice),
            None,
            LATER,
        ),
        Err(CoreError::Invalid { what: "session", ref reason }) if reason == "revoked device"
    ));
}

#[test]
fn connect_requires_the_role_specific_argument() {
    let alice = party("alice", DeviceKind::Desktop);
    assert!(Session::connect(
        &alice.identity,
        &alice.device,
        HandshakeRole::Initiator,
        None,
        None,
        LATER
    )
    .is_err());
    assert!(Session::connect(
        &alice.identity,
        &alice.device,
        HandshakeRole::Responder,
        None,
        None,
        LATER
    )
    .is_err());
}

// --- hand-driven initiator for Hello attacks ------------------------------

/// Drives the Noise side of an IK initiator by hand so the test can choose
/// what goes into `Hello`. Returns the transport once the responder's second
/// message has been consumed.
struct RawInitiator {
    transport: stackwallet_core::transport::NoiseTransport,
}

impl RawInitiator {
    fn ik(as_party: &Party, responder_party: &Party, responder: &mut Session) -> Self {
        let mut hs = NoiseHandshake::session(
            HandshakeRole::Initiator,
            &as_party.identity.noise_static(),
            Some(&responder_party.identity.noise_static_public()),
        )
        .unwrap();
        Self::finish(hs_write(&mut hs), hs, responder)
    }

    fn pairing(as_party: &Party, offer: &PairingOffer, responder: &mut Session) -> Self {
        let mut hs = NoiseHandshake::pairing(
            HandshakeRole::Initiator,
            &as_party.identity.noise_static(),
            Some(&offer.noise_static()),
            &offer.one_time_code(),
        )
        .unwrap();
        Self::finish(hs_write(&mut hs), hs, responder)
    }

    fn finish(msg1: Vec<u8>, mut hs: NoiseHandshake, responder: &mut Session) -> Self {
        assert!(responder.handle_incoming(&msg1).unwrap().is_empty());
        let mut out = responder.take_outgoing();
        assert_eq!(out.len(), 2, "msg2 then the responder's Hello");
        hs.read_message(&out.remove(0)).unwrap();
        assert!(hs.is_finished());
        let mut transport = hs.into_transport().unwrap();
        // Consume the responder's Hello so our own nonce stream stays aligned.
        let hello = Frame::from_bytes(&transport.decrypt(&out.remove(0)).unwrap()).unwrap();
        assert!(matches!(hello, Frame::Hello(_)));
        Self { transport }
    }

    fn hello(&self, signer: &Party, claim: &Party, noise_static_of: &Party) -> Hello {
        let binding = hello_binding(
            self.transport.handshake_hash(),
            &noise_static_of.identity.noise_static_public(),
        );
        Hello {
            device_id: claim.device.id.clone(),
            device_name: claim.device.name.clone(),
            kind: claim.device.kind,
            identity_pub_hex: claim.device.identity_pub_hex.clone(),
            handshake_sig_hex: hex::encode(signer.identity.sign(&binding)),
            endpoints: Vec::new(),
        }
    }

    fn deliver(&mut self, responder: &mut Session, frame: Frame) -> Vec<SessionEvent> {
        let ct = self.transport.encrypt(&frame.to_bytes().unwrap()).unwrap();
        responder.handle_incoming(&ct).unwrap()
    }
}

fn hs_write(hs: &mut NoiseHandshake) -> Vec<u8> {
    hs.write_message(&[]).unwrap()
}

fn ik_responder(me: &Party, known: Vec<Device>) -> Session {
    let s = Session::connect(
        &me.identity,
        &me.device,
        HandshakeRole::Responder,
        None,
        Some(lookup_for(known)),
        LATER,
    )
    .unwrap();
    s
}

#[test]
fn honest_raw_initiator_is_accepted() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mut b = ik_responder(&bob, vec![alice.device.clone()]);
    let mut raw = RawInitiator::ik(&alice, &bob, &mut b);
    let hello = raw.hello(&alice, &alice, &alice);
    let ev = raw.deliver(&mut b, Frame::Hello(hello));
    assert!(
        matches!(ev.as_slice(), [SessionEvent::Opened { .. }]),
        "{ev:?}"
    );
}

#[test]
fn hello_signed_by_another_identity_is_refused() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mallory = party("mallory", DeviceKind::Browser);
    let mut b = ik_responder(&bob, vec![alice.device.clone()]);
    let mut raw = RawInitiator::ik(&alice, &bob, &mut b);
    // Mallory holds Alice's Noise static (say, a stolen derived key) but not
    // her identity key, and tries to claim Alice's identity anyway.
    let hello = raw.hello(&mallory, &alice, &alice);
    let ev = raw.deliver(&mut b, Frame::Hello(hello));
    assert!(closed_reason(&ev).contains("signature"), "{ev:?}");
    assert_eq!(b.state(), SessionState::Closed);
    assert!(b.peer().is_none());
}

#[test]
fn hello_claiming_an_identity_other_than_the_pinned_one_is_refused() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mallory = party("mallory", DeviceKind::Browser);
    let mut b = ik_responder(&bob, vec![alice.device.clone()]);
    let mut raw = RawInitiator::ik(&alice, &bob, &mut b);
    // Correctly signed by Mallory over Alice's static, but the responder
    // pinned Alice for this static.
    let hello = raw.hello(&mallory, &mallory, &alice);
    let ev = raw.deliver(&mut b, Frame::Hello(hello));
    assert!(closed_reason(&ev).contains("pinned"), "{ev:?}");
}

#[test]
fn hello_with_mismatched_device_id_is_refused() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mut b = ik_responder(&bob, vec![alice.device.clone()]);
    let mut raw = RawInitiator::ik(&alice, &bob, &mut b);
    let mut hello = raw.hello(&alice, &alice, &alice);
    hello.device_id = "0".repeat(32);
    let ev = raw.deliver(&mut b, Frame::Hello(hello));
    assert!(closed_reason(&ev).starts_with("hello rejected"), "{ev:?}");
}

#[test]
fn pairing_issuer_refuses_reflected_and_misbound_hello() {
    let issuer = party("desk", DeviceKind::Desktop);
    let scanner = party("phone", DeviceKind::Mobile);
    let offer = offer_from(&issuer, LATER);

    // Reflection: hand the issuer its own identity, signed with its own key
    // over its own static. The signature verifies against that static, but
    // the handshake authenticated a different one.
    let mut i = Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW).unwrap();
    let mut raw = RawInitiator::pairing(&scanner, &offer, &mut i);
    let hello = raw.hello(&issuer, &issuer, &issuer);
    let ev = raw.deliver(&mut i, Frame::Hello(hello));
    assert_eq!(closed_reason(&ev), "peer presented our own identity");

    // Signature over someone else's static than the one in the handshake.
    let other = party("other", DeviceKind::Cli);
    let mut i = Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW).unwrap();
    let mut raw = RawInitiator::pairing(&scanner, &offer, &mut i);
    let hello = raw.hello(&scanner, &scanner, &other);
    let ev = raw.deliver(&mut i, Frame::Hello(hello));
    assert!(closed_reason(&ev).contains("signature"), "{ev:?}");

    // Positive control: the honest Hello pairs.
    let mut i = Session::pair_as_issuer(&issuer.identity, &issuer.device, &offer, NOW).unwrap();
    let mut raw = RawInitiator::pairing(&scanner, &offer, &mut i);
    let hello = raw.hello(&scanner, &scanner, &scanner);
    let ev = raw.deliver(&mut i, Frame::Hello(hello));
    assert!(
        matches!(ev.as_slice(), [SessionEvent::Paired { .. }]),
        "{ev:?}"
    );
}

#[test]
fn frame_before_hello_and_duplicate_hello_close() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);

    let mut b = ik_responder(&bob, vec![alice.device.clone()]);
    let mut raw = RawInitiator::ik(&alice, &bob, &mut b);
    let ev = raw.deliver(&mut b, Frame::Ping { nonce: 1 });
    assert_eq!(closed_reason(&ev), "frame before hello");

    let mut b = ik_responder(&bob, vec![alice.device.clone()]);
    let mut raw = RawInitiator::ik(&alice, &bob, &mut b);
    let hello = raw.hello(&alice, &alice, &alice);
    assert!(matches!(
        raw.deliver(&mut b, Frame::Hello(hello.clone())).as_slice(),
        [SessionEvent::Opened { .. }]
    ));
    let ev = raw.deliver(&mut b, Frame::Hello(hello));
    assert_eq!(closed_reason(&ev), "duplicate hello");
    // A refusal after the handshake tells the peer only that it was refused.
    let out = b.take_outgoing();
    assert_eq!(out.len(), 1);
    let bye = Frame::from_bytes(&raw.transport.decrypt(&out[0]).unwrap()).unwrap();
    assert_eq!(
        bye,
        Frame::Bye {
            reason: "refused".into()
        }
    );
}

// --- open-channel behaviour -----------------------------------------------

#[test]
fn replayed_ciphertext_closes_the_session() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (mut a, mut b) = open_ik(&alice, &bob);
    a.send(Frame::Signal {
        to_device_id: "x".into(),
        from_device_id: "y".into(),
        sdp_or_ice_json: "{}".into(),
    })
    .unwrap();
    let ct = a.take_outgoing().remove(0);
    assert!(matches!(
        b.handle_incoming(&ct).unwrap().as_slice(),
        [SessionEvent::Frame(Frame::Signal { .. })]
    ));
    let ev = b.handle_incoming(&ct).unwrap();
    assert_eq!(closed_reason(&ev), "decrypt failed");
    assert_eq!(b.state(), SessionState::Closed);
    assert!(b.send(Frame::Ping { nonce: 0 }).is_err());
}

#[test]
fn tampered_ciphertext_closes_the_session() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (mut a, mut b) = open_ik(&alice, &bob);
    a.send(Frame::Ping { nonce: 9 }).unwrap();
    let mut ct = a.take_outgoing().remove(0);
    ct[3] ^= 0x01;
    let ev = b.handle_incoming(&ct).unwrap();
    assert_eq!(closed_reason(&ev), "decrypt failed");
    assert!(b.take_outgoing().len() == 1, "a generic Bye goes out");
}

#[test]
fn ceremony_frame_must_be_signed_by_the_peer() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let carol = party("carol", DeviceKind::Browser);

    // Anything not labelled as the peer's is handed back unverified as a
    // relay; the channel only vouches for Alice, so Bob must check Carol's
    // signature against his own pinned record. That check catches Alice
    // signing under Carol's name.
    let (mut a, mut b) = open_ik(&alice, &bob);
    let forged = ceremony(&alice, &carol.device.id);
    let genuine = ceremony(&carol, &carol.device.id);
    a.send(Frame::Ceremony(forged.clone())).unwrap();
    a.send(Frame::Ceremony(genuine.clone())).unwrap();
    let (_, eb) = pump(&mut a, &mut b);
    assert_eq!(
        eb,
        vec![
            SessionEvent::Relayed(forged.clone()),
            SessionEvent::Relayed(genuine.clone())
        ]
    );
    assert_eq!(b.state(), SessionState::Open);
    assert!(forged.verify(&carol.device.identity_pub_hex).is_err());
    assert!(genuine.verify(&carol.device.identity_pub_hex).is_ok());

    // Tampered body under a genuine signature.
    let (mut a, mut b) = open_ik(&alice, &bob);
    let mut signed = ceremony(&alice, &alice.device.id);
    signed.msg.round = 2;
    a.send(Frame::Ceremony(signed)).unwrap();
    let (_, eb) = pump(&mut a, &mut b);
    assert_eq!(
        closed_reason(&eb),
        "ceremony message not signed by the peer"
    );
}

#[test]
fn ping_is_answered_with_the_same_nonce() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (mut a, mut b) = open_ik(&alice, &bob);
    a.send(Frame::Ping { nonce: 0xdead_beef }).unwrap();
    let (ea, eb) = pump(&mut a, &mut b);
    assert!(eb.is_empty(), "ping is handled internally: {eb:?}");
    assert_eq!(
        ea,
        vec![SessionEvent::Frame(Frame::Pong { nonce: 0xdead_beef })]
    );
    assert_eq!(a.state(), SessionState::Open);
    assert_eq!(b.state(), SessionState::Open);
}

#[test]
fn bye_closes_both_ends() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (mut a, mut b) = open_ik(&alice, &bob);
    a.close("done");
    assert_eq!(a.state(), SessionState::Closed);
    let (_, eb) = pump(&mut a, &mut b);
    assert_eq!(closed_reason(&eb), "peer closed: done");
    assert_eq!(b.state(), SessionState::Closed);
    assert!(matches!(
        a.send(Frame::Ping { nonce: 1 }),
        Err(CoreError::Invalid {
            what: "session",
            ..
        })
    ));
    assert!(a.handle_incoming(&[1, 2, 3]).is_err());
    // Closing again is harmless and queues nothing more.
    a.close("again");
    assert!(a.take_outgoing().is_empty());

    // `send(Bye)` is the same as `close`.
    let (mut a, mut b) = open_ik(&alice, &bob);
    a.send(Frame::Bye {
        reason: "via send".into(),
    })
    .unwrap();
    let (_, eb) = pump(&mut a, &mut b);
    assert_eq!(closed_reason(&eb), "peer closed: via send");
}

#[test]
fn send_before_open_is_an_error_and_hello_cannot_be_sent_by_hand() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let mut a = Session::connect(
        &alice.identity,
        &alice.device,
        HandshakeRole::Initiator,
        Some(&bob.device),
        None,
        LATER,
    )
    .unwrap();
    assert!(matches!(
        a.send(Frame::Ping { nonce: 1 }),
        Err(CoreError::Invalid {
            what: "session",
            ..
        })
    ));
    let (mut a, _b) = open_ik(&alice, &bob);
    assert!(matches!(
        a.send(Frame::Hello(Hello {
            device_id: alice.device.id.clone(),
            device_name: "alice".into(),
            kind: DeviceKind::Desktop,
            identity_pub_hex: alice.device.identity_pub_hex.clone(),
            handshake_sig_hex: String::new(),
            endpoints: Vec::new(),
        })),
        Err(CoreError::Invalid { what: "frame", .. })
    ));
}

#[test]
fn sessions_do_not_share_cipher_state() {
    // A ciphertext from one open session is garbage to another, even between
    // the same two devices.
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (mut a1, _b1) = open_ik(&alice, &bob);
    let (_a2, mut b2) = open_ik(&alice, &bob);
    a1.send(Frame::Ping { nonce: 1 }).unwrap();
    let ct = a1.take_outgoing().remove(0);
    assert_eq!(
        closed_reason(&b2.handle_incoming(&ct).unwrap()),
        "decrypt failed"
    );
}

// --- pairing offer and frame encoding -------------------------------------

#[test]
fn pairing_offer_roundtrips_and_rejects_bad_fields() {
    let issuer = party("desk", DeviceKind::Desktop);
    let offer = offer_from(&issuer, LATER);
    let text = offer.encode();
    assert!(text.starts_with("stackwallet-pair:"));
    assert_eq!(PairingOffer::decode(&text).unwrap(), offer);
    assert_eq!(PairingOffer::decode(&format!("  {text}\n")).unwrap(), offer);

    let mut bad_id = offer.clone();
    bad_id.device_id = "0".repeat(32);
    assert!(matches!(
        PairingOffer::decode(&bad_id.encode()),
        Err(CoreError::Invalid { what: "pairing offer", ref reason })
            if reason.contains("device id")
    ));

    let mut bad_version = offer.clone();
    bad_version.version = TRANSPORT_VERSION + 1;
    assert!(matches!(
        PairingOffer::decode(&bad_version.encode()),
        Err(CoreError::Invalid { what: "pairing offer", ref reason })
            if reason.contains("version")
    ));

    let mut bad_code = offer.clone();
    bad_code.one_time_code_hex = "abcd".into();
    assert!(PairingOffer::decode(&bad_code.encode()).is_err());

    let mut bad_static = offer.clone();
    bad_static.noise_static_hex = "zz".repeat(32);
    assert!(PairingOffer::decode(&bad_static.encode()).is_err());

    let mut bad_name = offer.clone();
    bad_name.device_name = String::new();
    assert!(PairingOffer::decode(&bad_name.encode()).is_err());

    assert!(PairingOffer::decode("not-an-offer").is_err());
    assert!(PairingOffer::decode("stackwallet-pair:!!!").is_err());
    assert!(PairingOffer::decode("stackwallet-pair:e30").is_err());
    assert!(Session::pair_as_scanner(
        &party("x", DeviceKind::Cli).identity,
        &issuer.device,
        &bad_id,
        NOW
    )
    .is_err());
}

#[test]
fn frames_respect_the_noise_message_limit() {
    let small = Frame::Signal {
        to_device_id: "a".into(),
        from_device_id: "b".into(),
        sdp_or_ice_json: "x".repeat(1024),
    };
    let bytes = small.to_bytes().unwrap();
    assert_eq!(Frame::from_bytes(&bytes).unwrap(), small);
    assert!(bytes.len() <= MAX_FRAME_LEN);

    let huge = Frame::Signal {
        to_device_id: "a".into(),
        from_device_id: "b".into(),
        sdp_or_ice_json: "x".repeat(MAX_FRAME_LEN),
    };
    assert!(matches!(
        huge.to_bytes(),
        Err(CoreError::Invalid { what: "frame", .. })
    ));
    assert!(Frame::from_bytes(b"{\"type\":\"nope\"}").is_err());

    // The open session enforces the same limit on send.
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (mut a, _b) = open_ik(&alice, &bob);
    assert!(a.send(huge).is_err());
    assert_eq!(a.state(), SessionState::Open);
}

/// A carrier without its own length cap (a browser data channel) cannot make
/// the session allocate a peer-sized buffer; oversize input closes the
/// session before the handshake layer ever sees it.
#[test]
fn oversize_wire_input_closes_the_session() {
    let alice = party("alice", DeviceKind::Desktop);
    let bob = party("bob", DeviceKind::Cli);
    let (a, mut b) = open_ik(&alice, &bob);

    let huge = vec![0u8; u16::MAX as usize + 1];
    let events = b.handle_incoming(&huge).unwrap();
    assert_eq!(b.state(), SessionState::Closed);
    assert_eq!(closed_reason(&events), "oversize message");

    // The other direction is unaffected until it hears from us again.
    assert_eq!(a.state(), SessionState::Open);
}
