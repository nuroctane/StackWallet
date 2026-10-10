//! FROST party for the two Schnorr curves, generic over the frost ciphersuite.
//!
//! The party is coordinator-less: every signer collects every commitment,
//! builds the same `SigningPackage`, and every signer aggregates, so no single
//! device is trusted to assemble the signature. DKG and refresh follow the
//! frost-core three-part flow (broadcast, peer-to-peer, finalize).
//!
//! Rounds are numbered 1 and 2 for every ceremony kind. A party accepts the
//! round it is collecting and buffers exactly the next one, because a fast
//! peer legitimately finishes a round before a slow peer's message has
//! reached us; anything else is refused. A peer that sends two different
//! bodies for the same round is equivocating and the ceremony aborts, since
//! frost has no way to tell which one the other parties used.

use std::collections::{BTreeMap, BTreeSet};

use frost_core::keys::dkg;
use frost_core::keys::{refresh, KeyPackage, PublicKeyPackage};
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_core::round2::SignatureShare;
use frost_core::{Ciphersuite, Identifier, SigningPackage};
use rand_core_06::OsRng;
use sha2::{Digest, Sha256};

use super::{
    CeremonyKind, CeremonyMessage, CeremonyProgress, CeremonySession, CeremonyState, ShareBlob,
    ThresholdScheme,
};
use crate::intent::{SignRequest, Signature};
use crate::model::{Curve, KeyGroup, PublicKey};
use crate::{CoreError, Result};

/// Ties a frost ciphersuite to the wallet's curve enum.
pub trait FrostCurve: Ciphersuite {
    const CURVE: Curve;
}

impl FrostCurve for frost_ed25519::Ed25519Sha512 {
    const CURVE: Curve = Curve::Ed25519;
}

impl FrostCurve for frost_secp256k1_tr::Secp256K1Sha256TR {
    const CURVE: Curve = Curve::Secp256k1Tr;
}

/// Re-exported so callers can name the ciphersuites without depending on
/// the frost crates themselves.
pub use frost_ed25519::Ed25519Sha512;
pub use frost_secp256k1_tr::Secp256K1Sha256TR;

pub type Ed25519Party = FrostParty<Ed25519Sha512>;
pub type Secp256k1TrParty = FrostParty<Secp256K1Sha256TR>;

/// Deterministic device-id to frost identifier mapping. Every party computes
/// it locally, so no coordination round is needed to agree on identifiers.
pub fn identifier_for<C: Ciphersuite>(device_id: &str) -> Result<Identifier<C>> {
    Identifier::<C>::derive(device_id.as_bytes())
        .map_err(|_| CoreError::Crypto("frost identifier derivation"))
}

/// The bytes the group actually signs for `request`.
///
/// Ed25519 chains verify a signature over the whole message, so the payload
/// itself is signed and its digest is recomputed here rather than trusted from
/// the adapter. BIP340 signs the 32-byte sighash directly; computing that hash
/// needs the full spend context (prevouts, script path), which only the
/// Bitcoin adapter has, so the hash is taken as given.
pub fn message_to_sign(request: &SignRequest) -> Result<Vec<u8>> {
    let hash = decode_hash(&request.payload_hash_hex)?;
    match request.curve {
        Curve::Ed25519 => {
            let payload = hex::decode(&request.payload_hex).map_err(|_| CoreError::Invalid {
                what: "sign request",
                reason: "payload is not hex".into(),
            })?;
            if payload.is_empty() {
                return Err(CoreError::Invalid {
                    what: "sign request",
                    reason: "empty payload".into(),
                });
            }
            if Sha256::digest(&payload)[..] != hash[..] {
                return Err(CoreError::Invalid {
                    what: "sign request",
                    reason: "payload hash does not match sha256(payload)".into(),
                });
            }
            Ok(payload)
        }
        Curve::Secp256k1Tr => Ok(hash.to_vec()),
        Curve::Secp256k1 => Err(CoreError::Invalid {
            what: "sign request",
            reason: "secp256k1 ECDSA is not a FROST curve".into(),
        }),
    }
}

/// Hash every party must agree on before DKG: n, t, the curve and the exact
/// party set. Binding round-1 messages to it turns a parameter mismatch into an
/// immediate refusal instead of an opaque DKG failure two rounds later.
pub fn keygen_binding_hex(group: &KeyGroup, curve: Curve) -> String {
    // Roles are part of the binding: relabelling a party (e.g. an agent as
    // human to dodge the D6 invariant) must change the session binding, or
    // the proposer could rewrite roles without any peer noticing.
    let mut ids: Vec<String> = group
        .parties
        .iter()
        .map(|p| {
            let role = serde_json::to_value(p.role)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("{:?}", p.role).to_lowercase());
            format!("{}:{role}", p.device_id)
        })
        .collect();
    ids.sort_unstable();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    binding_hex(
        "keygen",
        &group.id,
        curve,
        group.threshold as u16,
        &refs,
        b"",
    )
}

/// Same idea for refresh, additionally bound to the group key being refreshed.
pub fn refresh_binding_hex(
    key_group_id: &str,
    curve: Curve,
    threshold: u16,
    participants: &[String],
    verifying_key: &[u8],
) -> String {
    let mut ids: Vec<&str> = participants.iter().map(String::as_str).collect();
    ids.sort_unstable();
    binding_hex(
        "refresh",
        key_group_id,
        curve,
        threshold,
        &ids,
        verifying_key,
    )
}

fn binding_hex(
    domain: &str,
    key_group_id: &str,
    curve: Curve,
    threshold: u16,
    sorted_ids: &[&str],
    extra: &[u8],
) -> String {
    let mut h = Sha256::new();
    h.update(b"stackwallet-tss-");
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(key_group_id.as_bytes());
    h.update([0u8]);
    h.update(format!("{curve:?}").as_bytes());
    h.update(threshold.to_be_bytes());
    for id in sorted_ids {
        h.update((id.len() as u32).to_be_bytes());
        h.update(id.as_bytes());
    }
    h.update(extra);
    hex::encode(h.finalize())
}

fn decode_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|_| CoreError::Invalid {
        what: "payload hash",
        reason: "not hex".into(),
    })?;
    <[u8; 32]>::try_from(bytes).map_err(|_| CoreError::Invalid {
        what: "payload hash",
        reason: "must be 32 bytes".into(),
    })
}

fn body_digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

fn ceremony_err(msg: impl Into<String>) -> CoreError {
    CoreError::Ceremony(msg.into())
}

fn frost_err<C: Ciphersuite>(ctx: &str) -> impl Fn(frost_core::Error<C>) -> CoreError + '_ {
    move |e| CoreError::Ceremony(format!("{ctx}: {e}"))
}

enum Body<C: Ciphersuite> {
    Dkg1(dkg::round1::Package<C>),
    Dkg2(dkg::round2::Package<C>),
    Commitments(SigningCommitments<C>),
    Share(SignatureShare<C>),
}

enum Phase<C: Ciphersuite> {
    DkgRound1 {
        secret: dkg::round1::SecretPackage<C>,
        packages: BTreeMap<Identifier<C>, dkg::round1::Package<C>>,
    },
    DkgRound2 {
        secret: dkg::round2::SecretPackage<C>,
        round1: BTreeMap<Identifier<C>, dkg::round1::Package<C>>,
        round2: BTreeMap<Identifier<C>, dkg::round2::Package<C>>,
    },
    SignRound1 {
        nonces: SigningNonces<C>,
        commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
    },
    SignRound2 {
        package: SigningPackage<C>,
        shares: BTreeMap<Identifier<C>, SignatureShare<C>>,
    },
    Finished,
}

struct Ceremony<C: Ciphersuite> {
    session_id: String,
    kind: CeremonyKind,
    binding_hex: String,
    message: Vec<u8>,
    sign_request_id: Option<String>,
    /// Every other participant, by device id.
    peers: BTreeMap<String, Identifier<C>>,
    round: u8,
    /// Digest of the body already accepted per (round, sender), for duplicate
    /// and equivocation detection. Round-2 DKG bodies carry a secret share, so
    /// only the hash is kept.
    seen: BTreeMap<(u8, String), [u8; 32]>,
    buffered: Vec<CeremonyMessage>,
    phase: Phase<C>,
    state: CeremonyState,
    signature: Option<Signature>,
    public_key: Option<PublicKey>,
}

impl<C: Ciphersuite> Ceremony<C> {
    fn missing(&self) -> Vec<String> {
        self.peers
            .keys()
            .filter(|d| !self.seen.contains_key(&(self.round, (*d).clone())))
            .cloned()
            .collect()
    }

    fn round_complete(&self) -> bool {
        self.missing().is_empty()
    }

    fn abort(&mut self, reason: String) -> CoreError {
        self.state = CeremonyState::Aborted;
        self.phase = Phase::Finished;
        self.buffered.clear();
        ceremony_err(format!("aborted: {reason}"))
    }

    fn envelope(&self, from: &str, to: Option<String>, round: u8, body: &[u8]) -> CeremonyMessage {
        CeremonyMessage {
            session_id: self.session_id.clone(),
            payload_hash_hex: self.binding_hex.clone(),
            from_device_id: from.to_owned(),
            to_device_id: to,
            round,
            body_hex: hex::encode(body),
        }
    }
}

/// One FROST party: a device's share of one key group on one curve.
pub struct FrostParty<C: FrostCurve> {
    device_id: String,
    key_group_id: Option<String>,
    key_package: Option<KeyPackage<C>>,
    public_key_package: Option<PublicKeyPackage<C>>,
    ceremony: Option<Ceremony<C>>,
}

impl<C: FrostCurve> FrostParty<C> {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            key_group_id: None,
            key_package: None,
            public_key_package: None,
            ceremony: None,
        }
    }

    pub fn has_share(&self) -> bool {
        self.key_package.is_some() && self.public_key_package.is_some()
    }

    pub fn key_group_id(&self) -> Option<&str> {
        self.key_group_id.as_deref()
    }

    /// Group verifying key in the wire encoding used by [`PublicKey`]
    /// (32 bytes for Ed25519, 33-byte compressed SEC1 for secp256k1-tr).
    pub fn verifying_key_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.public_key_package
            .as_ref()
            .map(|p| {
                p.verifying_key()
                    .serialize()
                    .map_err(|_| CoreError::Crypto("frost verifying key serialization"))
            })
            .transpose()
    }

    pub fn public_key(&self) -> Result<Option<PublicKey>> {
        Ok(self.verifying_key_bytes()?.map(|bytes| PublicKey {
            curve: C::CURVE,
            hex: hex::encode(bytes),
        }))
    }

    fn own_identifier(&self) -> Result<Identifier<C>> {
        identifier_for::<C>(&self.device_id)
    }

    fn require_idle(&self) -> Result<()> {
        match self.ceremony.as_ref().map(|c| c.state) {
            Some(CeremonyState::Rounds) | Some(CeremonyState::Collecting) => {
                Err(ceremony_err("a ceremony is already in progress"))
            }
            _ => Ok(()),
        }
    }

    fn require_key(&self) -> Result<(&KeyPackage<C>, &PublicKeyPackage<C>, &str)> {
        match (
            &self.key_package,
            &self.public_key_package,
            &self.key_group_id,
        ) {
            (Some(k), Some(p), Some(g)) => Ok((k, p, g.as_str())),
            _ => Err(ceremony_err("party holds no share")),
        }
    }

    fn check_session(
        &self,
        session: &CeremonySession,
        kind: CeremonyKind,
        key_group_id: &str,
    ) -> Result<()> {
        if session.kind != kind {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: format!("expected {kind:?}, got {:?}", session.kind),
            });
        }
        if session.curve != C::CURVE {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: format!(
                    "curve {:?} does not match party {:?}",
                    session.curve,
                    C::CURVE
                ),
            });
        }
        if session.key_group_id != key_group_id {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "key group does not match".into(),
            });
        }
        let mut sorted: Vec<&str> = session.participants.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "duplicate participant".into(),
            });
        }
        if !session.participants.iter().any(|p| p == &self.device_id) {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: format!("{} is not a participant", self.device_id),
            });
        }
        Ok(())
    }

    /// Maps the other participants to identifiers, refusing a collision since
    /// two devices sharing an identifier would silently corrupt the DKG.
    fn peer_identifiers(&self, participants: &[String]) -> Result<BTreeMap<String, Identifier<C>>> {
        let own = self.own_identifier()?;
        let mut peers = BTreeMap::new();
        let mut ids = BTreeSet::from([own]);
        for p in participants.iter().filter(|p| **p != self.device_id) {
            let id = identifier_for::<C>(p)?;
            if !ids.insert(id) {
                return Err(ceremony_err(format!("identifier collision for {p}")));
            }
            peers.insert(p.clone(), id);
        }
        Ok(peers)
    }

    /// `signing` carries the message bytes and request id for sign ceremonies;
    /// keygen and refresh have neither.
    fn begin(
        &mut self,
        session: &CeremonySession,
        kind: CeremonyKind,
        binding_hex: String,
        peers: BTreeMap<String, Identifier<C>>,
        phase: Phase<C>,
        signing: Option<(Vec<u8>, String)>,
    ) {
        let (message, sign_request_id) = signing.unzip();
        self.ceremony = Some(Ceremony {
            session_id: session.id.clone(),
            kind,
            binding_hex,
            message: message.unwrap_or_default(),
            sign_request_id,
            peers,
            round: 1,
            seen: BTreeMap::new(),
            buffered: Vec::new(),
            phase,
            state: CeremonyState::Rounds,
            signature: None,
            public_key: None,
        });
    }

    fn broadcast(&self, round: u8, body: &[u8]) -> Vec<CeremonyMessage> {
        let c = self.ceremony.as_ref().expect("ceremony begun");
        vec![c.envelope(&self.device_id, None, round, body)]
    }

    /// Decodes and files a message for the round currently being collected,
    /// then runs the protocol step once the round is full.
    fn ingest(&mut self, msg: CeremonyMessage) -> Result<Vec<CeremonyMessage>> {
        let c = self.ceremony.as_mut().expect("ceremony active");
        let sender = msg.from_device_id.clone();
        let id = *c.peers.get(&sender).expect("sender validated");
        let body = match hex::decode(&msg.body_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(c.abort(format!("round {} body from {sender} is not hex", msg.round)))
            }
        };
        let parsed = match &c.phase {
            Phase::DkgRound1 { .. } => dkg::round1::Package::<C>::deserialize(&body)
                .ok()
                .map(Body::Dkg1),
            Phase::DkgRound2 { .. } => dkg::round2::Package::<C>::deserialize(&body)
                .ok()
                .map(Body::Dkg2),
            Phase::SignRound1 { .. } => SigningCommitments::<C>::deserialize(&body)
                .ok()
                .map(Body::Commitments),
            Phase::SignRound2 { .. } => SignatureShare::<C>::deserialize(&body)
                .ok()
                .map(Body::Share),
            Phase::Finished => return Err(ceremony_err("ceremony is not collecting messages")),
        };
        let Some(parsed) = parsed else {
            return Err(c.abort(format!(
                "round {} body from {sender} failed to deserialize",
                msg.round
            )));
        };
        match (&mut c.phase, parsed) {
            (Phase::DkgRound1 { packages, .. }, Body::Dkg1(p)) => {
                packages.insert(id, p);
            }
            (Phase::DkgRound2 { round2, .. }, Body::Dkg2(p)) => {
                round2.insert(id, p);
            }
            (Phase::SignRound1 { commitments, .. }, Body::Commitments(p)) => {
                commitments.insert(id, p);
            }
            (Phase::SignRound2 { shares, .. }, Body::Share(p)) => {
                shares.insert(id, p);
            }
            _ => return Err(ceremony_err("message body does not fit the current phase")),
        }
        c.seen.insert((msg.round, sender), body_digest(&body));
        if !c.round_complete() {
            return Ok(vec![]);
        }
        let mut out = self.advance()?;
        // Messages for the round we just entered may already be waiting.
        let waiting =
            std::mem::take(&mut self.ceremony.as_mut().expect("ceremony active").buffered);
        for m in waiting {
            if self.ceremony.as_ref().map(|c| c.state) != Some(CeremonyState::Rounds) {
                break;
            }
            out.extend(self.ingest(m)?);
        }
        Ok(out)
    }

    /// A failed protocol step (bad proof, invalid share, serialization) is
    /// unrecoverable for this ceremony, so it aborts rather than waiting for
    /// more input that could never fix it.
    fn advance(&mut self) -> Result<Vec<CeremonyMessage>> {
        let mut c = self.ceremony.take().expect("ceremony active");
        let result = match self.step(&mut c) {
            Ok(out) => Ok(out),
            Err(e) if c.state == CeremonyState::Aborted => Err(e),
            Err(e) => Err(c.abort(e.to_string())),
        };
        self.ceremony = Some(c);
        result
    }

    fn step(&mut self, c: &mut Ceremony<C>) -> Result<Vec<CeremonyMessage>> {
        let phase = std::mem::replace(&mut c.phase, Phase::Finished);
        match phase {
            Phase::DkgRound1 { secret, packages } => {
                let (secret2, outgoing) = if c.kind == CeremonyKind::Refresh {
                    refresh::refresh_dkg_part2(secret, &packages)
                        .map_err(frost_err("refresh part 2"))?
                } else {
                    dkg::part2(secret, &packages).map_err(frost_err("dkg part 2"))?
                };
                let mut out = Vec::with_capacity(outgoing.len());
                for (device, id) in &c.peers {
                    let pkg = outgoing
                        .get(id)
                        .ok_or_else(|| ceremony_err(format!("no round 2 package for {device}")))?;
                    let body = pkg
                        .serialize()
                        .map_err(frost_err("dkg round 2 serialization"))?;
                    out.push(c.envelope(&self.device_id, Some(device.clone()), 2, &body));
                }
                c.phase = Phase::DkgRound2 {
                    secret: secret2,
                    round1: packages,
                    round2: BTreeMap::new(),
                };
                c.round = 2;
                Ok(out)
            }
            Phase::DkgRound2 {
                secret,
                round1,
                round2,
            } => {
                let (kp, pkp) = if c.kind == CeremonyKind::Refresh {
                    let (old_kp, old_pkp, _) = self.require_key()?;
                    refresh::refresh_dkg_shares(
                        &secret,
                        &round1,
                        &round2,
                        old_pkp.clone(),
                        old_kp.clone(),
                    )
                    .map_err(frost_err("refresh finalize"))?
                } else {
                    dkg::part3(&secret, &round1, &round2).map_err(frost_err("dkg part 3"))?
                };
                let vk = pkp
                    .verifying_key()
                    .serialize()
                    .map_err(frost_err("verifying key serialization"))?;
                self.key_package = Some(kp);
                self.public_key_package = Some(pkp);
                c.public_key = Some(PublicKey {
                    curve: C::CURVE,
                    hex: hex::encode(vk),
                });
                c.state = CeremonyState::Complete;
                Ok(vec![])
            }
            Phase::SignRound1 {
                nonces,
                commitments,
            } => {
                let (kp, _, _) = self.require_key()?;
                let package = SigningPackage::new(commitments, &c.message);
                let share = frost_core::round2::sign(&package, &nonces, kp)
                    .map_err(frost_err("sign round 2"))?;
                let own = *kp.identifier();
                let body = share.serialize();
                c.phase = Phase::SignRound2 {
                    package,
                    shares: BTreeMap::from([(own, share)]),
                };
                c.round = 2;
                Ok(vec![c.envelope(&self.device_id, None, 2, &body)])
            }
            Phase::SignRound2 { package, shares } => {
                let (_, pkp, _) = self.require_key()?;
                let sig = frost_core::aggregate(&package, &shares, pkp)
                    .map_err(frost_err("aggregate"))?;
                pkp.verifying_key()
                    .verify(&c.message, &sig)
                    .map_err(frost_err("group signature verification"))?;
                let bytes = sig
                    .serialize()
                    .map_err(frost_err("signature serialization"))?;
                c.signature = Some(Signature {
                    sign_request_id: c.sign_request_id.clone().unwrap_or_default(),
                    curve: C::CURVE,
                    signature_hex: hex::encode(bytes),
                    recovery_id: None,
                });
                c.state = CeremonyState::Complete;
                Ok(vec![])
            }
            Phase::Finished => Err(ceremony_err("ceremony already finished")),
        }
    }

    fn result_for(
        &self,
        session: &CeremonySession,
        kinds: &[CeremonyKind],
    ) -> Result<Option<&Ceremony<C>>> {
        let Some(c) = self.ceremony.as_ref() else {
            return Err(ceremony_err("no ceremony"));
        };
        if c.session_id != session.id {
            return Err(ceremony_err("result requested for a different session"));
        }
        if !kinds.contains(&c.kind) {
            return Err(ceremony_err(format!("ceremony is {:?}", c.kind)));
        }
        match c.state {
            CeremonyState::Complete => Ok(Some(c)),
            CeremonyState::Aborted => Err(ceremony_err("ceremony aborted")),
            _ => Ok(None),
        }
    }
}

impl FrostParty<frost_secp256k1_tr::Secp256K1Sha256TR> {
    /// The x-only Taproot output key (BIP341 `Q`), hex. frost applies the
    /// unspendable-script-path tweak at DKG time, so the group key is already
    /// the output key and BIP340 verifiers check signatures against this.
    pub fn taproot_output_key_hex(&self) -> Result<Option<String>> {
        Ok(self
            .verifying_key_bytes()?
            .map(|sec1| hex::encode(&sec1[1..33])))
    }
}

impl<C: FrostCurve> ThresholdScheme for FrostParty<C> {
    fn curve(&self) -> Curve {
        C::CURVE
    }

    fn party_id(&self) -> &str {
        &self.device_id
    }

    fn state(&self) -> CeremonyState {
        self.ceremony
            .as_ref()
            .map(|c| c.state)
            .unwrap_or(CeremonyState::Proposed)
    }

    fn progress(&self) -> Option<CeremonyProgress> {
        self.ceremony.as_ref().map(|c| CeremonyProgress {
            kind: c.kind,
            state: c.state,
            round: c.round,
            missing: if c.state == CeremonyState::Rounds {
                c.missing()
            } else {
                vec![]
            },
        })
    }

    fn keygen_start(
        &mut self,
        group: &KeyGroup,
        session: &CeremonySession,
    ) -> Result<Vec<CeremonyMessage>> {
        group.validate()?;
        self.require_idle()?;
        if self.has_share() {
            return Err(ceremony_err("party already holds a share; use a new party"));
        }
        if !group.curves.contains(&C::CURVE) {
            return Err(CoreError::Invalid {
                what: "key group",
                reason: format!("group does not include {:?}", C::CURVE),
            });
        }
        self.check_session(session, CeremonyKind::KeyGen, &group.id)?;
        let mut expected: Vec<&str> = group.parties.iter().map(|p| p.device_id.as_str()).collect();
        expected.sort_unstable();
        let mut given: Vec<&str> = session.participants.iter().map(String::as_str).collect();
        given.sort_unstable();
        if expected != given {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "DKG participants must be exactly the key group parties".into(),
            });
        }
        let binding = keygen_binding_hex(group, C::CURVE);
        if matches!(&session.payload_hash_hex, Some(h) if *h != binding) {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "session binding does not match the key group".into(),
            });
        }
        let peers = self.peer_identifiers(&session.participants)?;
        let n = group.parties.len() as u16;
        let t = group.threshold as u16;
        let (secret, package) =
            dkg::part1(self.own_identifier()?, n, t, OsRng).map_err(frost_err("dkg part 1"))?;
        let body = package
            .serialize()
            .map_err(frost_err("dkg round 1 serialization"))?;
        self.key_group_id = Some(group.id.clone());
        self.begin(
            session,
            CeremonyKind::KeyGen,
            binding,
            peers,
            Phase::DkgRound1 {
                secret,
                packages: BTreeMap::new(),
            },
            None,
        );
        Ok(self.broadcast(1, &body))
    }

    fn sign_start(
        &mut self,
        request: &SignRequest,
        session: &CeremonySession,
    ) -> Result<Vec<CeremonyMessage>> {
        self.require_idle()?;
        let (kp, pkp, group_id) = self.require_key()?;
        if request.curve != C::CURVE {
            return Err(CoreError::Invalid {
                what: "sign request",
                reason: format!(
                    "curve {:?} does not match party {:?}",
                    request.curve,
                    C::CURVE
                ),
            });
        }
        if request.key_group_id != group_id {
            return Err(CoreError::Invalid {
                what: "sign request",
                reason: "key group does not match this share".into(),
            });
        }
        self.check_session(session, CeremonyKind::Sign, group_id)?;
        let message = message_to_sign(request)?;
        let binding = request.payload_hash_hex.clone();
        if session.payload_hash_hex.as_deref() != Some(binding.as_str()) {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "sign session must be bound to the request payload hash".into(),
            });
        }
        let min = pkp
            .min_signers()
            .ok_or_else(|| ceremony_err("public key package has no threshold"))?;
        if session.participants.len() < min as usize {
            return Err(ceremony_err(format!(
                "{} signers is below threshold {min}",
                session.participants.len()
            )));
        }
        let peers = self.peer_identifiers(&session.participants)?;
        if let Some(stranger) = peers
            .iter()
            .find(|(_, id)| !pkp.verifying_shares().contains_key(id))
        {
            return Err(ceremony_err(format!(
                "{} holds no share of this group",
                stranger.0
            )));
        }
        let own = *kp.identifier();
        let (nonces, commitments) = frost_core::round1::commit(kp.signing_share(), &mut OsRng);
        let body = commitments
            .serialize()
            .map_err(frost_err("commitment serialization"))?;
        self.begin(
            session,
            CeremonyKind::Sign,
            binding,
            peers,
            Phase::SignRound1 {
                nonces,
                commitments: BTreeMap::from([(own, commitments)]),
            },
            Some((message, request.id.clone())),
        );
        Ok(self.broadcast(1, &body))
    }

    fn refresh_start(&mut self, session: &CeremonySession) -> Result<Vec<CeremonyMessage>> {
        self.require_idle()?;
        let (_, pkp, group_id) = self.require_key()?;
        self.check_session(session, CeremonyKind::Refresh, group_id)?;
        let min = pkp
            .min_signers()
            .ok_or_else(|| ceremony_err("public key package has no threshold"))?;
        if session.participants.len() < min as usize {
            return Err(ceremony_err(format!(
                "{} refreshing parties is below threshold {min}",
                session.participants.len()
            )));
        }
        let peers = self.peer_identifiers(&session.participants)?;
        if let Some(stranger) = peers
            .iter()
            .find(|(_, id)| !pkp.verifying_shares().contains_key(id))
        {
            return Err(ceremony_err(format!(
                "{} holds no share of this group",
                stranger.0
            )));
        }
        let vk = pkp
            .verifying_key()
            .serialize()
            .map_err(frost_err("verifying key serialization"))?;
        let binding = refresh_binding_hex(group_id, C::CURVE, min, &session.participants, &vk);
        if matches!(&session.payload_hash_hex, Some(h) if *h != binding) {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "session binding does not match the refresh parameters".into(),
            });
        }
        let n = session.participants.len() as u16;
        let (secret, package) = refresh::refresh_dkg_part1(self.own_identifier()?, n, min, OsRng)
            .map_err(frost_err("refresh part 1"))?;
        let body = package
            .serialize()
            .map_err(frost_err("refresh round 1 serialization"))?;
        self.begin(
            session,
            CeremonyKind::Refresh,
            binding,
            peers,
            Phase::DkgRound1 {
                secret,
                packages: BTreeMap::new(),
            },
            None,
        );
        Ok(self.broadcast(1, &body))
    }

    fn handle(
        &mut self,
        session: &CeremonySession,
        msg: CeremonyMessage,
    ) -> Result<Vec<CeremonyMessage>> {
        let Some(c) = self.ceremony.as_mut() else {
            return Err(ceremony_err("no active ceremony"));
        };
        if c.state == CeremonyState::Aborted {
            return Err(ceremony_err("ceremony aborted"));
        }
        let live = c.state == CeremonyState::Rounds;
        if msg.session_id != c.session_id || session.id != c.session_id {
            return Err(ceremony_err("message is for a different session"));
        }
        // Who sent it is settled before anything that can abort: a stranger
        // who knows the session id must not be able to kill a live ceremony
        // by sending a mismatched binding.
        if msg.from_device_id == self.device_id {
            return Err(ceremony_err("message from self"));
        }
        if !c.peers.contains_key(&msg.from_device_id) {
            return Err(ceremony_err(format!(
                "{} is not part of this ceremony",
                msg.from_device_id
            )));
        }
        if matches!(&msg.to_device_id, Some(to) if *to != self.device_id) {
            return Err(ceremony_err("message addressed to another device"));
        }
        if msg.payload_hash_hex != c.binding_hex {
            let reason = format!(
                "{} sent a message bound to a different payload",
                msg.from_device_id
            );
            return Err(if live {
                c.abort(reason)
            } else {
                ceremony_err(reason)
            });
        }
        if let Err(e) = session.accepts(&msg) {
            return Err(ceremony_err(format!("refused by session: {e}")));
        }
        let Ok(body) = hex::decode(&msg.body_hex) else {
            let reason = format!(
                "round {} body from {} is not hex",
                msg.round, msg.from_device_id
            );
            return Err(if live {
                c.abort(reason)
            } else {
                ceremony_err(reason)
            });
        };
        // Redelivery is normal on a lossy network, so an exact repeat of
        // something already accepted is silently dropped even after the
        // ceremony finished; a different body under the same (round, sender)
        // is equivocation.
        let previous = c
            .seen
            .get(&(msg.round, msg.from_device_id.clone()))
            .map(|b| *b == body_digest(&body))
            .or_else(|| {
                c.buffered
                    .iter()
                    .find(|m| m.round == msg.round && m.from_device_id == msg.from_device_id)
                    .map(|m| hex::decode(&m.body_hex).ok().as_deref() == Some(&body[..]))
            });
        match previous {
            Some(true) => return Ok(vec![]),
            Some(false) => {
                let reason = format!(
                    "{} sent two different round {} messages",
                    msg.from_device_id, msg.round
                );
                return Err(if live {
                    c.abort(reason)
                } else {
                    ceremony_err(reason)
                });
            }
            None => {}
        }
        if !live {
            return Err(ceremony_err("ceremony already complete"));
        }
        if msg.round == 0 || msg.round > 2 {
            return Err(ceremony_err(format!(
                "round {} does not exist in this protocol",
                msg.round
            )));
        }
        if msg.round < c.round {
            return Err(ceremony_err(format!(
                "round {} is already complete",
                msg.round
            )));
        }
        if msg.round > c.round + 1 {
            return Err(ceremony_err(format!(
                "round {} is more than one round ahead of {}",
                msg.round, c.round
            )));
        }
        if msg.round == c.round + 1 {
            c.buffered.push(msg);
            return Ok(vec![]);
        }
        self.ingest(msg)
    }

    fn keygen_result(&self, session: &CeremonySession) -> Result<Option<PublicKey>> {
        Ok(self
            .result_for(session, &[CeremonyKind::KeyGen, CeremonyKind::Refresh])?
            .and_then(|c| c.public_key.clone()))
    }

    fn sign_result(&self, session: &CeremonySession) -> Result<Option<Signature>> {
        Ok(self
            .result_for(session, &[CeremonyKind::Sign])?
            .and_then(|c| c.signature.clone()))
    }

    fn export_share(&self) -> Result<ShareBlob> {
        let (kp, pkp, group_id) = self.require_key()?;
        Ok(ShareBlob {
            curve: C::CURVE,
            key_group_id: group_id.to_owned(),
            device_id: self.device_id.clone(),
            key_package: kp
                .serialize()
                .map_err(|_| CoreError::Crypto("key package serialization"))?,
            public_key_package: pkp
                .serialize()
                .map_err(|_| CoreError::Crypto("public key package serialization"))?,
        })
    }

    fn import_share(&mut self, blob: &ShareBlob) -> Result<()> {
        self.require_idle()?;
        if blob.curve != C::CURVE {
            return Err(CoreError::Invalid {
                what: "share blob",
                reason: format!("curve {:?} does not match party {:?}", blob.curve, C::CURVE),
            });
        }
        if blob.device_id != self.device_id {
            return Err(CoreError::Invalid {
                what: "share blob",
                reason: "share belongs to another device".into(),
            });
        }
        let kp = KeyPackage::<C>::deserialize(&blob.key_package)
            .map_err(|_| CoreError::Crypto("key package deserialization"))?;
        let pkp = PublicKeyPackage::<C>::deserialize(&blob.public_key_package)
            .map_err(|_| CoreError::Crypto("public key package deserialization"))?;
        let own = self.own_identifier()?;
        if *kp.identifier() != own {
            return Err(CoreError::Invalid {
                what: "share blob",
                reason: "key package identifier does not derive from this device id".into(),
            });
        }
        if kp.verifying_key() != pkp.verifying_key() {
            return Err(CoreError::Invalid {
                what: "share blob",
                reason: "key package and public key package disagree on the group key".into(),
            });
        }
        if pkp.verifying_shares().get(&own) != Some(kp.verifying_share()) {
            return Err(CoreError::Invalid {
                what: "share blob",
                reason: "public key package does not list this device's verifying share".into(),
            });
        }
        if pkp.min_signers().is_none() {
            return Err(CoreError::Invalid {
                what: "share blob",
                reason: "public key package carries no threshold".into(),
            });
        }
        self.key_group_id = Some(blob.key_group_id.clone());
        self.key_package = Some(kp);
        self.public_key_package = Some(pkp);
        self.ceremony = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PartyRef, PartyRole};

    fn group(ids: &[&str]) -> KeyGroup {
        KeyGroup {
            id: "g".into(),
            threshold: 2,
            parties: ids
                .iter()
                .map(|d| PartyRef {
                    device_id: (*d).into(),
                    role: PartyRole::Human,
                })
                .collect(),
            curves: vec![Curve::Ed25519],
            public_keys: vec![],
        }
    }

    #[test]
    fn keygen_binding_ignores_party_order_but_not_membership() {
        let a = keygen_binding_hex(&group(&["a", "b", "c"]), Curve::Ed25519);
        let b = keygen_binding_hex(&group(&["c", "a", "b"]), Curve::Ed25519);
        let c = keygen_binding_hex(&group(&["a", "b", "d"]), Curve::Ed25519);
        let d = keygen_binding_hex(&group(&["a", "b", "c"]), Curve::Secp256k1Tr);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn identifiers_are_stable_per_device() {
        let a = identifier_for::<frost_ed25519::Ed25519Sha512>("laptop").unwrap();
        let b = identifier_for::<frost_ed25519::Ed25519Sha512>("laptop").unwrap();
        let c = identifier_for::<frost_ed25519::Ed25519Sha512>("phone").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ed25519_requests_sign_the_payload_and_recheck_its_digest() {
        let payload = b"solana message bytes".to_vec();
        let req = SignRequest {
            id: "r".into(),
            tx_id: "t".into(),
            key_group_id: "g".into(),
            curve: Curve::Ed25519,
            payload_hash_hex: hex::encode(Sha256::digest(&payload)),
            payload_hex: hex::encode(&payload),
        };
        assert_eq!(message_to_sign(&req).unwrap(), payload);
        let tampered = SignRequest {
            payload_hash_hex: "00".repeat(32),
            ..req
        };
        assert!(message_to_sign(&tampered).is_err());
    }

    #[test]
    fn taproot_requests_sign_the_sighash_itself() {
        let req = SignRequest {
            id: "r".into(),
            tx_id: "t".into(),
            key_group_id: "g".into(),
            curve: Curve::Secp256k1Tr,
            payload_hash_hex: "ab".repeat(32),
            payload_hex: String::new(),
        };
        assert_eq!(message_to_sign(&req).unwrap(), vec![0xab; 32]);
        let short = SignRequest {
            payload_hash_hex: "ab".repeat(31),
            ..req
        };
        assert!(message_to_sign(&short).is_err());
    }
}
