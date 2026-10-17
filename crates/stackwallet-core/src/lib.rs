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
//! - [`vault`]     encrypted storage of shares and secrets, device-local unlock slots
//! - [`export_gate`] session, directory and wallet keys every export must present
//! - [`identity`]  Ed25519 device identity and message authentication
//! - [`tss`]       threshold signing parties and ceremonies
//! - [`transport`] pairing, Noise channel and session framing (sans-IO)
//! - [`store`]     SQLite persistence

pub mod aelf;
pub mod aeternity;
pub mod aleo;
pub mod alephium;
pub mod algorand;
pub mod antelope;
pub mod aptos;
pub mod audit;
pub mod bitcoin;
pub mod btcfork;
pub mod canton;
pub mod cardano;
pub mod chia;
pub mod chromia;
pub mod cosmos;
pub mod ergo;
pub mod everscale;
pub mod evm;
pub mod export_gate;
pub mod fuel;
pub mod gala;
pub mod hardware;
pub mod hd;
pub mod hyperliquid;
pub mod icon;
pub mod icp;
pub mod identity;
pub mod intent;
pub mod keeta;
pub mod ledger;
pub mod lifecycle;
pub mod message;
pub mod mixin;
pub mod model;
pub mod multiversx;
pub mod namada;
pub mod near;
pub mod neo;
pub mod obyte;
pub mod policy;
pub mod provenance;
pub mod qubic;
pub mod radix;
pub mod solana;
pub mod stacks;
pub mod starcoin;
pub mod starknet;
pub mod stellar;
pub mod store;
pub mod substrate;
pub mod sui;
pub mod tezos;
pub mod threshold;
pub mod ton;
pub mod transfer;
pub mod transport;
pub mod tron;
pub mod tss;
pub mod vault;
pub mod vechain;
pub mod waves;
pub mod xrpl;

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
