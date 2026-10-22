//! Hash-chained audit log. Each entry's hash covers the previous hash and the
//! entry's own content, so a removed, reordered or edited row breaks every
//! later hash. The UI verifies the chain and shows a break as a red banner.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::lifecycle::TxState;
use crate::{CoreError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Actor {
    Device {
        device_id: String,
    },
    AgentSession {
        session_id: String,
    },
    Automation {
        automation_id: String,
        run_id: String,
    },
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "event",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum AuditEvent {
    /// A transaction entered the ledger as a draft; transitions follow.
    TxProposed {
        tx_id: String,
        wallet_id: String,
        chain_id: String,
    },
    TxTransition {
        tx_id: String,
        from: TxState,
        to: TxState,
        note: Option<String>,
    },
    TxBroadcastRetry {
        tx_id: String,
        hash: String,
    },
    CeremonyStarted {
        session_id: String,
        /// Absent for key generation and refresh.
        sign_request_id: Option<String>,
    },
    CeremonyCompleted {
        session_id: String,
    },
    CeremonyAborted {
        session_id: String,
        reason: String,
    },
    /// A proposed ceremony was refused before it started (unknown or revoked
    /// participant, bad binding, expired session). Refusals are the events an
    /// operator most wants to find later, so they are audited like outcomes.
    CeremonyRefused {
        session_id: String,
        proposer_device_id: String,
        reason: String,
    },
    /// A refresh finished on this device; the previous share is kept until
    /// every peer confirms (committed) or one fails (rolled back).
    ShareRefreshed {
        wallet_id: String,
        session_id: String,
    },
    ShareRefreshCommitted {
        wallet_id: String,
    },
    ShareRefreshRolledBack {
        wallet_id: String,
    },
    DevicePaired {
        device_id: String,
    },
    DeviceRevoked {
        device_id: String,
    },
    PolicyChanged {
        policy_id: String,
    },
    GrantChanged {
        grant_id: String,
    },
    /// An off-chain signature (EIP-191 or EIP-712) left the vault.
    MessageSigned {
        wallet_id: String,
        address: String,
        kind: String,
        digest_hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub index: u64,
    pub at_ms: i64,
    pub actor: Actor,
    #[serde(flatten)]
    pub event: AuditEvent,
    pub prev_hash_hex: String,
    pub hash_hex: String,
}

/// Hash of the genesis predecessor: 32 zero bytes.
pub const GENESIS_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn compute_hash(index: u64, at_ms: i64, actor: &Actor, event: &AuditEvent, prev: &str) -> String {
    // serde_json is deterministic for these enums (struct field order is fixed),
    // and the field layout is part of the hashed format.
    let body = serde_json::json!({
        "index": index,
        "atMs": at_ms,
        "actor": actor,
        "event": event,
        "prev": prev,
    });
    let mut h = Sha256::new();
    h.update(body.to_string().as_bytes());
    hex::encode(h.finalize())
}

#[derive(Debug, Default, Clone)]
pub struct AuditChain {
    entries: Vec<AuditEntry>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: Vec<AuditEntry>) -> Result<Self> {
        let chain = Self { entries };
        chain.verify()?;
        Ok(chain)
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn head_hash(&self) -> &str {
        self.entries
            .last()
            .map(|e| e.hash_hex.as_str())
            .unwrap_or(GENESIS_HASH_HEX)
    }

    pub fn append(&mut self, at_ms: i64, actor: Actor, event: AuditEvent) -> &AuditEntry {
        let index = self.entries.len() as u64;
        let prev = self.head_hash().to_owned();
        let hash_hex = compute_hash(index, at_ms, &actor, &event, &prev);
        self.entries.push(AuditEntry {
            index,
            at_ms,
            actor,
            event,
            prev_hash_hex: prev,
            hash_hex,
        });
        self.entries.last().expect("just pushed")
    }

    /// Recompute every hash. Returns the index of the first bad entry on failure.
    pub fn verify(&self) -> Result<()> {
        let mut prev = GENESIS_HASH_HEX.to_owned();
        for (i, e) in self.entries.iter().enumerate() {
            let expected = compute_hash(e.index, e.at_ms, &e.actor, &e.event, &prev);
            if e.index != i as u64 || e.prev_hash_hex != prev || e.hash_hex != expected {
                return Err(CoreError::AuditChain(i));
            }
            prev = e.hash_hex.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(tx: &str, from: TxState, to: TxState) -> AuditEvent {
        AuditEvent::TxTransition {
            tx_id: tx.into(),
            from,
            to,
            note: None,
        }
    }

    #[test]
    fn chain_verifies_and_detects_edits() {
        let mut c = AuditChain::new();
        c.append(
            1,
            Actor::System,
            transition("t", TxState::Draft, TxState::Simulated),
        );
        c.append(
            2,
            Actor::Device {
                device_id: "laptop".into(),
            },
            transition("t", TxState::Simulated, TxState::Evaluated),
        );
        c.append(
            3,
            Actor::AgentSession {
                session_id: "s".into(),
            },
            transition("t", TxState::Evaluated, TxState::Awaiting),
        );
        c.verify().unwrap();

        let mut tampered = c.entries().to_vec();
        if let AuditEvent::TxTransition { to, .. } = &mut tampered[1].event {
            *to = TxState::Signing;
        }
        assert!(matches!(
            AuditChain::from_entries(tampered),
            Err(CoreError::AuditChain(1))
        ));

        let mut reordered = c.entries().to_vec();
        reordered.swap(0, 1);
        assert!(AuditChain::from_entries(reordered).is_err());

        let mut truncated = c.entries().to_vec();
        truncated.remove(1);
        assert!(AuditChain::from_entries(truncated).is_err());
    }

    #[test]
    fn empty_chain_is_valid() {
        AuditChain::new().verify().unwrap();
        assert_eq!(AuditChain::new().head_hash(), GENESIS_HASH_HEX);
    }
}
