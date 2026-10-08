//! StackWallet core.
//!
//! The only code in the system that may hold key material or decide whether a
//! signature is produced. Everything here is platform-neutral: it compiles to
//! native code for the desktop and CLI and to wasm32 for the browser.
//!
//! Module map (see `docs/SPEC.md`):
//! - [`model`]     identifiers, curves, parties, key groups
//! - [`intent`]    what the user or agent wants to do, and what must be signed
//! - [`policy`]    deterministic rule evaluation
//! - [`lifecycle`] the transaction state machine
//! - [`audit`]     hash-chained audit log
//! - [`vault`]     encrypted storage of shares and secrets (Phase 1)
//! - [`tss`]       threshold signing parties and ceremonies (Phase 1)
//! - [`transport`] device-to-device channel (Phase 2)
//! - [`store`]     SQLite persistence (Phase 1)

pub mod audit;
pub mod intent;
pub mod lifecycle;
pub mod model;
pub mod policy;
pub mod store;
pub mod transport;
pub mod tss;
pub mod vault;

/// Crate version, surfaced to every frontend so the UI can show which core it talks to.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid {what}: {reason}")]
    Invalid { what: &'static str, reason: String },
    #[error("key group violates D6: {0}")]
    AgentThreshold(String),
    #[error("illegal transition {from:?} -> {to:?}")]
    Transition {
        from: lifecycle::TxState,
        to: lifecycle::TxState,
    },
    #[error("audit chain broken at index {0}")]
    AuditChain(usize),
    #[error("not implemented until {phase}: {what}")]
    NotYet {
        phase: &'static str,
        what: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, CoreError>;
