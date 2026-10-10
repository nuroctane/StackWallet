use stackwallet_core::identity::{
    ceremony_message_bytes, device_id_from_public_hex, DeviceIdentity, SignedCeremonyMessage,
};
use stackwallet_core::tss::CeremonyMessage;
use stackwallet_core::CoreError;

fn message(from: &str) -> CeremonyMessage {
    CeremonyMessage {
        session_id: "session-1".into(),
        payload_hash_hex: "ab".repeat(32),
        from_device_id: from.into(),
        to_device_id: Some("peer".into()),
        round: 2,
        body_hex: "deadbeef".into(),
    }
}

#[test]
fn signed_message_roundtrip() {
    let id = DeviceIdentity::generate().unwrap();
    let signed = SignedCeremonyMessage::sign(&id, message(&id.device_id()));
    signed.verify(&id.public_hex()).unwrap();

    let json = serde_json::to_string(&signed).unwrap();
    let parsed: SignedCeremonyMessage = serde_json::from_str(&json).unwrap();
    parsed.verify(&id.public_hex()).unwrap();
}

#[test]
fn signature_from_another_identity_is_rejected() {
    let alice = DeviceIdentity::generate().unwrap();
    let mallory = DeviceIdentity::generate().unwrap();
    // Mallory signs a message that claims to come from Alice.
    let forged = SignedCeremonyMessage::sign(&mallory, message(&alice.device_id()));
    assert!(matches!(
        forged.verify(&alice.public_hex()),
        Err(CoreError::Invalid {
            what: "signature",
            ..
        })
    ));
}

#[test]
fn from_device_id_must_match_the_key() {
    let alice = DeviceIdentity::generate().unwrap();
    let bob = DeviceIdentity::generate().unwrap();
    // Bob signs honestly but labels the message as Alice's.
    let signed = SignedCeremonyMessage::sign(&bob, message(&alice.device_id()));
    assert!(matches!(
        signed.verify(&bob.public_hex()),
        Err(CoreError::Invalid {
            what: "ceremony message",
            ..
        })
    ));
}

#[test]
fn every_field_is_covered_by_the_signature() {
    let id = DeviceIdentity::generate().unwrap();
    let signed = SignedCeremonyMessage::sign(&id, message(&id.device_id()));
    let public_hex = id.public_hex();

    type Mutation = Box<dyn Fn(&mut CeremonyMessage)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|m| m.session_id.push('x')),
        Box::new(|m| m.payload_hash_hex = "cd".repeat(32)),
        Box::new(|m| m.to_device_id = None),
        Box::new(|m| m.to_device_id = Some("other".into())),
        Box::new(|m| m.round += 1),
        Box::new(|m| m.body_hex = "deadbeee".into()),
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut tampered = signed.clone();
        mutate(&mut tampered.msg);
        assert!(
            tampered.verify(&public_hex).is_err(),
            "mutation {i} should break the signature"
        );
    }

    let mut bad_sig = signed.clone();
    bad_sig.signature_hex = "00".repeat(64);
    assert!(bad_sig.verify(&public_hex).is_err());
    bad_sig.signature_hex = "zz".into();
    assert!(bad_sig.verify(&public_hex).is_err());
}

#[test]
fn canonical_bytes_are_deterministic_and_length_prefixed() {
    let a = message("dev");
    let bytes = ceremony_message_bytes(&a);
    assert_eq!(bytes, ceremony_message_bytes(&a.clone()));

    let mut shifted = a.clone();
    shifted.session_id = "session-".into();
    shifted.payload_hash_hex = format!("1{}", a.payload_hash_hex);
    assert_ne!(bytes, ceremony_message_bytes(&shifted));

    // A broadcast and a message addressed to an empty device id must not
    // share a signature.
    let mut none_to = a.clone();
    none_to.to_device_id = None;
    let mut empty_to = a;
    empty_to.to_device_id = Some(String::new());
    assert_ne!(
        ceremony_message_bytes(&none_to),
        ceremony_message_bytes(&empty_to)
    );
}

#[test]
fn device_id_matches_between_identity_and_public_hex() {
    let id = DeviceIdentity::generate().unwrap();
    assert_eq!(
        device_id_from_public_hex(&id.public_hex()).unwrap(),
        id.device_id()
    );
    assert!(device_id_from_public_hex("00").is_err());
}
