//! In-memory multi-party runner for FROST ceremonies.
//!
//! Every party of a key group lives in one process and messages are shuttled
//! through a [`Delivery`], which is the hook ceremony fuzzing uses to drop,
//! reorder, duplicate and corrupt traffic. The CLI reuses the same runner for
//! local self-tests, so it is compiled into the crate rather than test-only.

use super::frost::{keygen_binding_hex, refresh_binding_hex, FrostCurve, FrostParty};
use super::{
    CeremonyKind, CeremonyMessage, CeremonyProgress, CeremonySession, CeremonyState,
    ThresholdScheme,
};
use crate::intent::{SignRequest, Signature};
use crate::model::{KeyGroup, PublicKey};
use crate::{CoreError, Result};

/// The network between harness parties.
pub trait Delivery {
    /// Sees every batch a party emits and returns what actually enters the
    /// network. Dropping, duplicating or rewriting happens here.
    fn on_send(&mut self, produced: Vec<CeremonyMessage>) -> Vec<CeremonyMessage> {
        produced
    }

    /// Picks the next in-flight message. Returning `None` while messages
    /// remain stalls the run, which the report records as incomplete.
    fn next(&mut self, in_flight: &mut Vec<CeremonyMessage>) -> Option<CeremonyMessage> {
        if in_flight.is_empty() {
            None
        } else {
            Some(in_flight.remove(0))
        }
    }
}

/// Delivers everything, in order, exactly once.
#[derive(Debug, Default, Clone, Copy)]
pub struct Faithful;

impl Delivery for Faithful {}

/// Tiny deterministic generator for reproducible fuzz orderings. Not a CSPRNG
/// and never used for key material; frost draws its randomness from the OS.
#[derive(Debug, Clone)]
pub struct XorShift64(u64);

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        // A zero state would stay zero forever.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        (self.next_u64() % n as u64) as usize
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// Delivers every message exactly once but in a seeded random order, across
/// rounds as well as within them.
#[derive(Debug, Clone)]
pub struct Shuffled {
    rng: XorShift64,
}

impl Shuffled {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: XorShift64::new(seed),
        }
    }
}

impl Delivery for Shuffled {
    fn next(&mut self, in_flight: &mut Vec<CeremonyMessage>) -> Option<CeremonyMessage> {
        if in_flight.is_empty() {
            None
        } else {
            let i = self.rng.below(in_flight.len());
            Some(in_flight.swap_remove(i))
        }
    }
}

/// What happened during one ceremony run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub session_id: String,
    pub kind: CeremonyKind,
    pub delivered: usize,
    pub complete: Vec<String>,
    /// Devices whose driver aborted, with the reason it gave.
    pub aborted: Vec<(String, String)>,
    /// Devices still waiting when traffic ran out.
    pub stalled: Vec<(String, CeremonyProgress)>,
    /// Messages a driver refused without aborting (stale rounds, misrouting).
    pub refused: Vec<(String, String)>,
}

impl RunReport {
    pub fn is_complete(&self) -> bool {
        self.aborted.is_empty() && self.stalled.is_empty()
    }

    /// The earliest round any party is still waiting on.
    pub fn incomplete_round(&self) -> Option<u8> {
        self.stalled.iter().map(|(_, p)| p.round).min()
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.aborted.is_empty() {
            let items: Vec<String> = self
                .aborted
                .iter()
                .map(|(d, r)| format!("{d}: {r}"))
                .collect();
            parts.push(format!("aborted [{}]", items.join("; ")));
        }
        if !self.stalled.is_empty() {
            let items: Vec<String> = self
                .stalled
                .iter()
                .map(|(d, p)| format!("{d}: round {} incomplete, missing {:?}", p.round, p.missing))
                .collect();
            parts.push(format!("stalled [{}]", items.join("; ")));
        }
        format!(
            "{:?} {} did not complete: {}",
            self.kind,
            self.session_id,
            parts.join("; ")
        )
    }
}

/// All parties of one key group on one curve, in one process.
pub struct LocalHarness<C: FrostCurve> {
    group: KeyGroup,
    parties: Vec<FrostParty<C>>,
    sessions: u64,
    last_run: Option<RunReport>,
    /// Timestamps stamped onto sessions; the harness has no clock of its own.
    pub now_ms: i64,
    pub ttl_ms: i64,
}

/// Upper bound on deliveries per run so a delivery that duplicates forever
/// cannot hang a test.
const MAX_DELIVERIES: usize = 100_000;

impl<C: FrostCurve> LocalHarness<C> {
    /// Refuses groups that fail [`KeyGroup::validate`], including the D6
    /// agent-only threshold, before any party exists.
    pub fn new(group: &KeyGroup) -> Result<Self> {
        group.validate()?;
        if !group.curves.contains(&C::CURVE) {
            return Err(CoreError::Invalid {
                what: "key group",
                reason: format!("group does not include {:?}", C::CURVE),
            });
        }
        Ok(Self {
            group: group.clone(),
            parties: group
                .parties
                .iter()
                .map(|p| FrostParty::new(p.device_id.clone()))
                .collect(),
            sessions: 0,
            last_run: None,
            now_ms: 0,
            ttl_ms: 60_000,
        })
    }

    pub fn group(&self) -> &KeyGroup {
        &self.group
    }

    pub fn device_ids(&self) -> Vec<String> {
        self.parties
            .iter()
            .map(|p| p.party_id().to_owned())
            .collect()
    }

    pub fn party(&self, device_id: &str) -> Option<&FrostParty<C>> {
        self.parties.iter().find(|p| p.party_id() == device_id)
    }

    pub fn party_mut(&mut self, device_id: &str) -> Option<&mut FrostParty<C>> {
        self.parties.iter_mut().find(|p| p.party_id() == device_id)
    }

    pub fn last_run(&self) -> Option<&RunReport> {
        self.last_run.as_ref()
    }

    /// The id the next ceremony of `kind` will run under, so a caller can
    /// write its audit row before the ceremony starts.
    pub fn next_session_id(&self, kind: CeremonyKind) -> String {
        self.session_id(kind, self.sessions + 1)
    }

    fn session_id(&self, kind: CeremonyKind, n: u64) -> String {
        format!("{}-{:?}-{}", self.group.id, kind, n).to_lowercase()
    }

    fn session(
        &mut self,
        kind: CeremonyKind,
        participants: &[String],
        payload_hash_hex: Option<String>,
    ) -> CeremonySession {
        self.sessions += 1;
        CeremonySession {
            id: self.session_id(kind, self.sessions),
            kind,
            key_group_id: self.group.id.clone(),
            curve: C::CURVE,
            payload_hash_hex,
            participants: participants.to_vec(),
            state: CeremonyState::Rounds,
            created_at_ms: self.now_ms,
            expires_at_ms: self.now_ms + self.ttl_ms,
        }
    }

    /// Runs DKG across every party and returns the group public key.
    pub fn keygen(&mut self, delivery: &mut dyn Delivery) -> Result<PublicKey> {
        let all = self.device_ids();
        let binding = keygen_binding_hex(&self.group, C::CURVE);
        let session = self.session(CeremonyKind::KeyGen, &all, Some(binding));
        let group = self.group.clone();
        let report = self.run(&session, delivery, |p| p.keygen_start(&group, &session))?;
        self.finish(&report)?;
        let keys = self.collect(&all, |p| p.keygen_result(&session))?;
        Self::unanimous(keys, "public key")
    }

    /// Runs a signing ceremony among `signers` only.
    pub fn sign(
        &mut self,
        signers: &[&str],
        request: &SignRequest,
        delivery: &mut dyn Delivery,
    ) -> Result<Signature> {
        let signers: Vec<String> = signers.iter().map(|s| (*s).to_owned()).collect();
        for s in &signers {
            if self.party(s).is_none() {
                return Err(CoreError::Invalid {
                    what: "signer set",
                    reason: format!("{s} is not in the key group"),
                });
            }
        }
        let session = self.session(
            CeremonyKind::Sign,
            &signers,
            Some(request.payload_hash_hex.clone()),
        );
        let report = self.run(&session, delivery, |p| p.sign_start(request, &session))?;
        self.finish(&report)?;
        let sigs = self.collect(&signers, |p| p.sign_result(&session))?;
        Self::unanimous(sigs, "signature")
    }

    /// Refreshes every party's share; the public key must come back unchanged.
    pub fn refresh(&mut self, delivery: &mut dyn Delivery) -> Result<PublicKey> {
        let all = self.device_ids();
        let refs: Vec<&str> = all.iter().map(String::as_str).collect();
        self.refresh_with(&refs, delivery)
    }

    /// Refreshes among a subset of at least `threshold` parties. Parties left
    /// out keep shares that no longer combine with the refreshed ones, so they
    /// are effectively removed; the `KeyGroup` record itself is not edited
    /// here, the caller decides whether to drop them from it.
    pub fn refresh_with(
        &mut self,
        participants: &[&str],
        delivery: &mut dyn Delivery,
    ) -> Result<PublicKey> {
        let participants: Vec<String> = participants.iter().map(|s| (*s).to_owned()).collect();
        let first = participants.first().ok_or_else(|| CoreError::Invalid {
            what: "refresh set",
            reason: "no participants".into(),
        })?;
        let vk = self
            .party(first)
            .ok_or_else(|| CoreError::Invalid {
                what: "refresh set",
                reason: format!("{first} is not in the key group"),
            })?
            .verifying_key_bytes()?
            .ok_or_else(|| CoreError::Ceremony("refresh before keygen".into()))?;
        let binding = refresh_binding_hex(
            &self.group.id,
            C::CURVE,
            self.group.threshold as u16,
            &participants,
            &vk,
        );
        let session = self.session(CeremonyKind::Refresh, &participants, Some(binding));
        let report = self.run(&session, delivery, |p| p.refresh_start(&session))?;
        self.finish(&report)?;
        let keys = self.collect(&participants, |p| p.keygen_result(&session))?;
        Self::unanimous(keys, "public key")
    }

    fn run(
        &mut self,
        session: &CeremonySession,
        delivery: &mut dyn Delivery,
        mut start: impl FnMut(&mut FrostParty<C>) -> Result<Vec<CeremonyMessage>>,
    ) -> Result<RunReport> {
        let participants = session.participants.clone();
        let mut in_flight = Vec::new();
        for device in &participants {
            let party = self.party_mut(device).ok_or_else(|| CoreError::Invalid {
                what: "ceremony session",
                reason: format!("{device} is not in the key group"),
            })?;
            let produced = start(party)?;
            in_flight.extend(delivery.on_send(produced));
        }

        let mut report = RunReport {
            session_id: session.id.clone(),
            kind: session.kind,
            delivered: 0,
            complete: vec![],
            aborted: vec![],
            stalled: vec![],
            refused: vec![],
        };
        while let Some(msg) = delivery.next(&mut in_flight) {
            if report.delivered >= MAX_DELIVERIES {
                break;
            }
            report.delivered += 1;
            let recipients: Vec<String> = match &msg.to_device_id {
                Some(to) => vec![to.clone()],
                None => participants
                    .iter()
                    .filter(|d| **d != msg.from_device_id)
                    .cloned()
                    .collect(),
            };
            for device in recipients {
                let Some(party) = self.party_mut(&device) else {
                    report
                        .refused
                        .push((device, "message addressed to an unknown device".into()));
                    continue;
                };
                match party.handle(session, msg.clone()) {
                    Ok(produced) => in_flight.extend(delivery.on_send(produced)),
                    Err(e) => {
                        if party.state() == CeremonyState::Aborted {
                            if !report.aborted.iter().any(|(d, _)| *d == device) {
                                report.aborted.push((device, e.to_string()));
                            }
                        } else {
                            report.refused.push((device, e.to_string()));
                        }
                    }
                }
            }
        }

        for device in &participants {
            let party = self.party(device).expect("participant exists");
            match party.state() {
                CeremonyState::Complete => report.complete.push(device.clone()),
                CeremonyState::Aborted => {
                    if !report.aborted.iter().any(|(d, _)| d == device) {
                        report.aborted.push((device.clone(), "aborted".into()));
                    }
                }
                _ => {
                    if let Some(progress) = party.progress() {
                        report.stalled.push((device.clone(), progress));
                    }
                }
            }
        }
        self.last_run = Some(report.clone());
        Ok(report)
    }

    fn finish(&self, report: &RunReport) -> Result<()> {
        if report.is_complete() {
            Ok(())
        } else {
            Err(CoreError::Ceremony(report.summary()))
        }
    }

    fn collect<T>(
        &self,
        devices: &[String],
        mut get: impl FnMut(&FrostParty<C>) -> Result<Option<T>>,
    ) -> Result<Vec<T>> {
        devices
            .iter()
            .map(|d| {
                let party = self.party(d).expect("participant exists");
                get(party)?.ok_or_else(|| {
                    CoreError::Ceremony(format!("{d} reports complete but has no result"))
                })
            })
            .collect()
    }

    /// Every party computes the result independently; a disagreement means a
    /// party aggregated different inputs and must be surfaced, not averaged.
    fn unanimous<T: PartialEq>(mut values: Vec<T>, what: &str) -> Result<T> {
        let first = values
            .pop()
            .ok_or_else(|| CoreError::Ceremony(format!("no {what} produced")))?;
        if values.iter().all(|v| *v == first) {
            Ok(first)
        } else {
            Err(CoreError::Ceremony(format!(
                "parties disagree on the {what}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xorshift_is_deterministic_and_shuffles_every_position() {
        let mut a = XorShift64::new(42);
        let mut b = XorShift64::new(42);
        let mut va: Vec<u32> = (0..32).collect();
        let mut vb = va.clone();
        a.shuffle(&mut va);
        b.shuffle(&mut vb);
        assert_eq!(va, vb);
        assert_ne!(va, (0..32).collect::<Vec<u32>>());
        let mut sorted = va.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..32).collect::<Vec<u32>>());
    }

    #[test]
    fn zero_seed_does_not_stick() {
        let mut r = XorShift64::new(0);
        assert_ne!(r.next_u64(), r.next_u64());
    }
}
