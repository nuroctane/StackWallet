//! wasm-bindgen surface. Everything crosses as JSON strings so the TypeScript
//! side can Zod-validate it and the Rust side never hands out raw pointers.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn core_version() -> String {
    stackwallet_core::VERSION.to_owned()
}

/// `policies_json: Policy[]`, `intent_json: TxIntent`, `ctx_json: PolicyContext` → `Decision`.
#[wasm_bindgen]
pub fn evaluate_policy(
    policies_json: &str,
    intent_json: &str,
    ctx_json: &str,
) -> Result<String, JsError> {
    let policies: Vec<stackwallet_core::policy::Policy> = serde_json::from_str(policies_json)?;
    let intent: stackwallet_core::intent::TxIntent = serde_json::from_str(intent_json)?;
    let ctx: stackwallet_core::policy::PolicyContext = serde_json::from_str(ctx_json)?;
    let decision = stackwallet_core::policy::evaluate(&policies, &intent, &ctx);
    Ok(serde_json::to_string(&decision)?)
}

/// `KeyGroup` JSON → `null` on success or an error message.
#[wasm_bindgen]
pub fn validate_key_group(group_json: &str) -> Result<Option<String>, JsError> {
    let group: stackwallet_core::model::KeyGroup = serde_json::from_str(group_json)?;
    Ok(group.validate().err().map(|e| e.to_string()))
}

#[wasm_bindgen]
pub fn can_transition(from_json: &str, to_json: &str) -> Result<bool, JsError> {
    let from: stackwallet_core::lifecycle::TxState = serde_json::from_str(from_json)?;
    let to: stackwallet_core::lifecycle::TxState = serde_json::from_str(to_json)?;
    Ok(from.can_transition_to(to))
}

#[wasm_bindgen]
pub fn schema_sql() -> String {
    stackwallet_core::store::SCHEMA_SQL.to_owned()
}
