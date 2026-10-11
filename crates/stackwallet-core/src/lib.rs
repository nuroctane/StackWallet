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
//! - [`vault`]     encrypted storage of shares and secrets
//! - [`identity`]  Ed25519 device identity and message authentication
//! - [`tss`]       threshold signing parties and ceremonies
//! - [`transport`] pairing, Noise channel and session framing (sans-IO)
//! - [`store`]     SQLite persistence

pub mod audit;
pub mod bitcoin;
pub mod cosmos;
pub mod evm;
pub mod hd;
pub mod identity;
pub mod intent;
pub mod ledger;
pub mod lifecycle;
pub mod model;
pub mod policy;
pub mod provenance;
pub mod solana;
pub mod store;
pub mod transfer;
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
    #[error("vault is locked")]
    Locked,
    #[error("wrong passphrase or corrupted vault")]
    Unlock,
    #[error("crypto failure in {0}")]
    Crypto(&'static str),
    #[error("ceremony {0}")]
    Ceremony(String),
    #[error("store: {0}")]
    Store(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
