//! Identifiers and structural types shared by every module.

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// Chain families supported by adapters. New families are additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainFamily {
    Evm,
    Bitcoin,
    Solana,
    Cosmos,
}

/// CAIP-2 chain identifier, e.g. `eip155:1` or `cosmos:osmosis-1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub String);

impl ChainId {
    pub fn parse(s: &str) -> Result<Self> {
        let (ns, reference) = s.split_once(':').ok_or_else(|| CoreError::Invalid {
            what: "chain id",
            reason: format!("missing namespace separator in {s:?}"),
        })?;
        let ok_ns = (3..=8).contains(&ns.len())
            && ns
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        let ok_ref = (1..=32).contains(&reference.len())
            && reference
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !ok_ns || !ok_ref {
            return Err(CoreError::Invalid {
                what: "chain id",
                reason: format!("{s:?} is not CAIP-2"),
            });
        }
        Ok(Self(s.to_owned()))
    }

    pub fn namespace(&self) -> &str {
        self.0.split_once(':').map(|(ns, _)| ns).unwrap_or("")
    }

    pub fn family(&self) -> Option<ChainFamily> {
        match self.namespace() {
            "eip155" => Some(ChainFamily::Evm),
            "bip122" => Some(ChainFamily::Bitcoin),
            "solana" => Some(ChainFamily::Solana),
            "cosmos" => Some(ChainFamily::Cosmos),
            _ => None,
        }
    }
}

/// `<chainId>:<kind>:<identifier>`; see `docs/CHAINS.md`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssetRef(pub String);

/// Signature curves. One `tss` wallet holds one group key per curve it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Curve {
    /// ECDSA over secp256k1: EVM, Bitcoin legacy/SegWit, Cosmos. CGGMP21.
    Secp256k1,
    /// EdDSA over Ed25519: Solana. FROST.
    Ed25519,
    /// BIP340 Schnorr over secp256k1: Bitcoin Taproot. FROST.
    Secp256k1Tr,
}

impl Curve {
    pub fn for_family(family: ChainFamily) -> &'static [Curve] {
        match family {
            ChainFamily::Evm | ChainFamily::Cosmos => &[Curve::Secp256k1],
            ChainFamily::Bitcoin => &[Curve::Secp256k1, Curve::Secp256k1Tr],
            ChainFamily::Solana => &[Curve::Ed25519],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub curve: Curve,
    /// Hex, no 0x prefix. Compressed SEC1 for secp256k1 variants, 32 bytes for Ed25519.
    pub hex: String,
}

/// Who holds a share. The role drives the D6 invariant in [`KeyGroup::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartyRole {
    Human,
    Agent,
    Automation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyRef {
    pub device_id: String,
    pub role: PartyRole,
}

/// A t-of-n signing group. Public keys are filled in after DKG, one per curve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGroup {
    pub id: String,
    pub threshold: u8,
    pub parties: Vec<PartyRef>,
    pub curves: Vec<Curve>,
    #[serde(default)]
    pub public_keys: Vec<PublicKey>,
}

impl KeyGroup {
    pub fn agent_share_count(&self) -> usize {
        self.parties
            .iter()
            .filter(|p| p.role == PartyRole::Agent)
            .count()
    }

    /// Structural validity plus the D6 invariant: a group that contains an agent
    /// party must not be satisfiable by agent parties alone.
    pub fn validate(&self) -> Result<()> {
        let n = self.parties.len();
        if n == 0 {
            return Err(CoreError::Invalid {
                what: "key group",
                reason: "no parties".into(),
            });
        }
        if self.threshold == 0 || self.threshold as usize > n {
            return Err(CoreError::Invalid {
                what: "key group",
                reason: format!("threshold {} out of range for {n} parties", self.threshold),
            });
        }
        let mut ids: Vec<&str> = self.parties.iter().map(|p| p.device_id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(CoreError::Invalid {
                what: "key group",
                reason: "duplicate device in party set".into(),
            });
        }
        if self.curves.is_empty() {
            return Err(CoreError::Invalid {
                what: "key group",
                reason: "no curves".into(),
            });
        }
        let agents = self.agent_share_count();
        if agents > 0 && (self.threshold as usize) <= agents {
            return Err(CoreError::AgentThreshold(format!(
                "threshold {} can be met by {agents} agent share(s) alone",
                self.threshold
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(id: &str, role: PartyRole) -> PartyRef {
        PartyRef {
            device_id: id.into(),
            role,
        }
    }

    #[test]
    fn caip2_parsing() {
        assert_eq!(
            ChainId::parse("eip155:1").unwrap().family(),
            Some(ChainFamily::Evm)
        );
        assert_eq!(
            ChainId::parse("cosmos:osmosis-1").unwrap().family(),
            Some(ChainFamily::Cosmos)
        );
        assert!(ChainId::parse("mainnet").is_err());
        assert!(ChainId::parse("EIP155:1").is_err());
    }

    #[test]
    fn d6_agent_alone_is_rejected() {
        let g = KeyGroup {
            id: "g".into(),
            threshold: 1,
            parties: vec![
                party("agent", PartyRole::Agent),
                party("laptop", PartyRole::Human),
            ],
            curves: vec![Curve::Secp256k1],
            public_keys: vec![],
        };
        assert!(matches!(g.validate(), Err(CoreError::AgentThreshold(_))));
    }

    #[test]
    fn d6_two_of_three_with_agent_is_fine() {
        let g = KeyGroup {
            id: "g".into(),
            threshold: 2,
            parties: vec![
                party("laptop", PartyRole::Human),
                party("phone", PartyRole::Human),
                party("agent", PartyRole::Agent),
            ],
            curves: vec![Curve::Secp256k1, Curve::Ed25519],
            public_keys: vec![],
        };
        g.validate().unwrap();
    }

    #[test]
    fn two_agents_need_threshold_three() {
        let g = KeyGroup {
            id: "g".into(),
            threshold: 2,
            parties: vec![
                party("a1", PartyRole::Agent),
                party("a2", PartyRole::Agent),
                party("laptop", PartyRole::Human),
            ],
            curves: vec![Curve::Ed25519],
            public_keys: vec![],
        };
        assert!(g.validate().is_err());
    }
}
