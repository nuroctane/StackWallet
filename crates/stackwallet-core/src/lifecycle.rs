//! Transaction state machine. The graph here is the one in `docs/SPEC.md` §6;
//! any transition not listed is illegal and must never be written to the store.

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TxState {
    Draft,
    Simulated,
    Evaluated,
    Denied,
    Awaiting,
    Signing,
    Signed,
    Broadcast,
    Pending,
    Confirmed,
    Replaced,
    Dropped,
    Expired,
    Rejected,
    Failed,
}

impl TxState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TxState::Denied
                | TxState::Confirmed
                | TxState::Replaced
                | TxState::Dropped
                | TxState::Expired
                | TxState::Rejected
                | TxState::Failed
        )
    }

    /// Spend that must count against caps while the transaction is in flight.
    pub fn reserves_spend(self) -> bool {
        matches!(
            self,
            TxState::Awaiting
                | TxState::Signing
                | TxState::Signed
                | TxState::Broadcast
                | TxState::Pending
        )
    }

    pub fn can_transition_to(self, to: TxState) -> bool {
        use TxState::*;
        matches!(
            (self, to),
            (Draft, Simulated)
                | (Draft, Evaluated)
                | (Simulated, Evaluated)
                | (Evaluated, Denied)
                | (Evaluated, Awaiting)
                | (Evaluated, Signing)
                | (Awaiting, Signing)
                | (Awaiting, Expired)
                | (Awaiting, Rejected)
                | (Signing, Signed)
                | (Signing, Failed)
                | (Signed, Broadcast)
                | (Broadcast, Pending)
                | (Broadcast, Failed)
                | (Pending, Confirmed)
                | (Pending, Replaced)
                | (Pending, Dropped)
        )
    }
}

pub fn transition(from: TxState, to: TxState) -> Result<TxState> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(CoreError::Transition { from, to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TxState::*;

    #[test]
    fn happy_path() {
        let mut s = Draft;
        for next in [
            Simulated, Evaluated, Awaiting, Signing, Signed, Broadcast, Pending, Confirmed,
        ] {
            s = transition(s, next).unwrap();
        }
        assert!(s.is_terminal());
    }

    #[test]
    fn cannot_skip_evaluation() {
        assert!(transition(Draft, Signing).is_err());
        assert!(transition(Simulated, Signed).is_err());
    }

    #[test]
    fn terminal_states_have_no_exits() {
        for t in [
            Denied, Confirmed, Replaced, Dropped, Expired, Rejected, Failed,
        ] {
            for to in [Draft, Signing, Broadcast, Confirmed] {
                assert!(
                    transition(t, to).is_err(),
                    "{t:?} -> {to:?} should be illegal"
                );
            }
        }
    }

    #[test]
    fn reserved_spend_states() {
        assert!(Awaiting.reserves_spend());
        assert!(Pending.reserves_spend());
        assert!(!Draft.reserves_spend());
        assert!(!Confirmed.reserves_spend());
    }
}
