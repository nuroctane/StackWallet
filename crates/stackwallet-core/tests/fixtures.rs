//! Wire-format pins shared with `packages/core-client`. See `fixtures/README.md`.

use stackwallet_core::intent::TxIntent;
use stackwallet_core::policy::{evaluate, Decision, Policy, PolicyContext};

const POLICIES: &str = include_str!("../../../fixtures/policies.json");
const INTENT_TRANSFER: &str = include_str!("../../../fixtures/intent-transfer.json");
const INTENT_SWAP: &str = include_str!("../../../fixtures/intent-swap.json");
const CONTEXT: &str = include_str!("../../../fixtures/context.json");
const DECISION_ALLOW: &str = include_str!("../../../fixtures/decision-allow.json");
const DECISION_DENY: &str = include_str!("../../../fixtures/decision-deny.json");

fn load() -> (Vec<Policy>, PolicyContext) {
    (
        serde_json::from_str(POLICIES).expect("policies fixture"),
        serde_json::from_str(CONTEXT).expect("context fixture"),
    )
}

#[test]
fn transfer_fixture_is_allowed_with_approvers() {
    let (policies, ctx) = load();
    let intent: TxIntent = serde_json::from_str(INTENT_TRANSFER).expect("intent fixture");
    let expected: Decision = serde_json::from_str(DECISION_ALLOW).expect("decision fixture");
    assert_eq!(evaluate(&policies, &intent, &ctx), expected);
}

#[test]
fn swap_fixture_is_denied_for_three_reasons() {
    let (policies, ctx) = load();
    let intent: TxIntent = serde_json::from_str(INTENT_SWAP).expect("intent fixture");
    let expected: Decision = serde_json::from_str(DECISION_DENY).expect("decision fixture");
    assert_eq!(evaluate(&policies, &intent, &ctx), expected);
}

#[test]
fn fixtures_round_trip_in_camel_case() {
    let (policies, ctx) = load();
    let intent: TxIntent = serde_json::from_str(INTENT_SWAP).unwrap();
    for json in [
        serde_json::to_string(&policies).unwrap(),
        serde_json::to_string(&ctx).unwrap(),
        serde_json::to_string(&intent).unwrap(),
        serde_json::to_string(&evaluate(&policies, &intent, &ctx)).unwrap(),
    ] {
        assert!(
            !json.contains('_'),
            "snake_case leaked into wire format: {json}"
        );
    }
    let back: TxIntent = serde_json::from_str(&serde_json::to_string(&intent).unwrap()).unwrap();
    assert_eq!(back, intent);
}
