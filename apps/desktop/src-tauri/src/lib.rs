//! Tauri commands. Same JSON-in / JSON-out contract as the wasm crate so
//! `@stackwallet/core-client` can drive either backend with one code path.

use stackwallet_core::intent::TxIntent;
use stackwallet_core::lifecycle::TxState;
use stackwallet_core::model::KeyGroup;
use stackwallet_core::policy::{evaluate, Decision, Policy, PolicyContext};

#[tauri::command]
fn core_version() -> String {
    stackwallet_core::VERSION.to_owned()
}

#[tauri::command]
fn evaluate_policy(policies: Vec<Policy>, intent: TxIntent, ctx: PolicyContext) -> Decision {
    evaluate(&policies, &intent, &ctx)
}

#[tauri::command]
fn validate_key_group(group: KeyGroup) -> Option<String> {
    group.validate().err().map(|e| e.to_string())
}

#[tauri::command]
fn can_transition(from: TxState, to: TxState) -> bool {
    from.can_transition_to(to)
}

#[tauri::command]
fn schema_sql() -> String {
    stackwallet_core::store::SCHEMA_SQL.to_owned()
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            core_version,
            evaluate_policy,
            validate_key_group,
            can_transition,
            schema_sql
        ])
        .run(tauri::generate_context!())
        .expect("error while running StackWallet");
}
