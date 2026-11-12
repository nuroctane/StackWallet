//! FROST party for the two Schnorr curves, generic over the frost ciphersuite.
//!
//! The party is coordinator-less: every signer collects every commitment,
//! builds the same `SigningPackage`, and every signer aggregates, so no single
//! device is trusted to assemble the signature. DKG and refresh follow the
//! frost-core three-part flow (broadcast, peer-to-peer, finalize).
//!
//! Keygen, refresh and sign number their rounds 1 and 2; a reshare uses 1 to 4
//! (below). A party accepts the round it is collecting and buffers exactly
//! the next one it takes part in, because a fast
//! peer legitimately finishes a round before a slow peer's message has
//! reached us; anything else is refused. A peer that sends two different
//! bodies for the same round is equivocating and the ceremony aborts, since
//! frost has no way to tell which one the other parties used.
//!
//! FROST's DKG assumes every party sees the same round-1 broadcasts. Over
//! point-to-point links a party could show two consistent transcripts to two
//! groups of parties, which would then finish on different group keys without
//! any error. So each round-2 body leads with a hash of every round-1 package
//! its sender saw, and a receiver whose own view differs aborts. Every pair of
//! honest parties exchanges round 2 directly, so any split between them shows.
//!
//! A reshare replaces one device without changing the group key: every other
//! party helps the newcomer repair a share at its own identifier (frost's
//! repairable threshold scheme), then all of them run a refresh, which leaves
//! the replaced device's old share unable to combine with anything. Survivors
//! walk rounds 1, 3 and 4 and the newcomer 2, 3 and 4, each buffering only its
//! own next round; the newcomer checks its repaired share against the group's
//! public data before it uses it.
//!
//! A sign ceremony may cover several messages at once (one Taproot sighash per
//! transaction input), each with its own fresh nonces, so one approval and one
//! round trip sign the whole transaction. With a single message the round
//! bodies are the plain frost serializations; with several, each body is the
//! per-message items, length-prefixed, in message order.

use std::collections::{BTreeMap, BTreeSet};

use frost_core::keys::dkg;
use frost_core::keys::repairable::{self, Delta, Sigma};
use frost_core::keys::{refresh, KeyPackage, PublicKeyPackage, VerifyingShare};
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_core::round2::SignatureShare;
use frost_core::{Ciphersuite, Group, Identifier, SigningPackage};
use rand_core_06::OsRng;
use sha2::{Digest, Sha256};

use super::{
    CeremonyKind, CeremonyMessage, CeremonyProgress, CeremonySession, CeremonyState, ShareBlob,
    ThresholdScheme,
};
use crate::intent::{SignRequest, Signature};
use crate::model::{Curve, KeyGroup, PartyRef, PublicKey};
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

/// Most messages one sign ceremony covers; a Bitcoin spend has at most eight
/// inputs, and anything larger only gives a peer more to make us compute.
pub const MAX_BATCH: usize = 16;

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
    let ids = party_labels(group);
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

/// Each party as `device:role`, sorted. Roles are part of every binding that
/// sets up a group: relabelling a party (an agent as human, to dodge the D6
/// invariant) must change the binding, or the proposer could rewrite roles
/// without any peer noticing.
fn party_labels(group: &KeyGroup) -> Vec<String> {
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
    ids
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

/// The group a reshare leaves behind: `newcomer` in `replaced`'s place, with
/// the same id, threshold, curves and key. Refused when it breaks the group
/// rules (D6 included).
pub fn replaced_group(group: &KeyGroup, replaced: &str, newcomer: &PartyRef) -> Result<KeyGroup> {
    if !group.parties.iter().any(|p| p.device_id == replaced) {
        return Err(CoreError::Invalid {
            what: "reshare",
            reason: format!("{replaced} is not a party of the group"),
        });
    }
    if group
        .parties
        .iter()
        .any(|p| p.device_id == newcomer.device_id)
    {
        return Err(CoreError::Invalid {
            what: "reshare",
            reason: format!("{} already holds a share", newcomer.device_id),
        });
    }
    let mut next = group.clone();
    for p in &mut next.parties {
        if p.device_id == replaced {
            *p = newcomer.clone();
        }
    }
    next.validate()?;
    Ok(next)
}

/// What every party of a reshare must agree on: the group it leaves behind
/// (roles included, so no one can be relabelled on the way), the device it
/// replaces and the group key that must survive.
pub fn reshare_binding_hex(next: &KeyGroup, curve: Curve, replaced: &str, key: &[u8]) -> String {
    let ids = party_labels(next);
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut extra = (key.len() as u32).to_be_bytes().to_vec();
    extra.extend(key);
    extra.extend((replaced.len() as u32).to_be_bytes());
    extra.extend(replaced.as_bytes());
    binding_hex(
        "reshare",
        &next.id,
        curve,
        next.threshold as u16,
        &refs,
        &extra,
    )
}

/// The group's public package with `newcomer`'s verifying share in place of
/// `replaced`'s. The share is interpolated in the exponent from the helpers'
/// shares at the newcomer's identifier, which is exactly where the repair
/// puts its secret share, so anyone holding the package can check it.
fn joined_package<C: Ciphersuite>(
    pkp: &PublicKeyPackage<C>,
    helpers: &BTreeSet<Identifier<C>>,
    newcomer: Identifier<C>,
    replaced: Identifier<C>,
) -> Result<PublicKeyPackage<C>> {
    let mut acc = <C::Group as Group>::identity();
    for id in helpers {
        let lambda = frost_core::compute_lagrange_coefficient(helpers, Some(newcomer), *id)
            .map_err(frost_err("lagrange coefficient"))?;
        let share = pkp
            .verifying_shares()
            .get(id)
            .ok_or_else(|| ceremony_err("a helper is missing from the group's public package"))?;
        acc = acc + share.to_element() * lambda;
    }
    let mut shares = pkp.verifying_shares().clone();
    shares.remove(&replaced);
    shares.insert(newcomer, VerifyingShare::new(acc));
    Ok(PublicKeyPackage::new(
        shares,
        *pkp.verifying_key(),
        pkp.min_signers(),
    ))
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

fn encode_items(items: &[Vec<u8>]) -> Vec<u8> {
    if let [one] = items {
        return one.clone();
    }
    let mut out = Vec::new();
    for item in items {
        out.extend((item.len() as u32).to_be_bytes());
        out.extend(item);
    }
    out
}

/// Exactly `n` items or nothing: a short, long or padded body is refused.
fn decode_items(body: &[u8], n: usize) -> Option<Vec<&[u8]>> {
    if n == 1 {
        return Some(vec![body]);
    }
    let mut rest = body;
    let mut out = Vec::with_capacity(n);
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let item = rest.get(4..4usize.checked_add(len)?)?;
        out.push(item);
        rest = &rest[4 + len..];
    }
    (out.len() == n).then_some(out)
}

fn decode_all<T>(body: &[u8], n: usize, parse: impl Fn(&[u8]) -> Option<T>) -> Option<Vec<T>> {
    decode_items(body, n)?.into_iter().map(parse).collect()
}

const ECHO_LEN: usize = 32;

/// Hash of every round-1 package of a DKG or refresh, this party's included,
/// in identifier order.
fn round1_transcript<C: Ciphersuite>(
    own_id: Identifier<C>,
    own: &dkg::round1::Package<C>,
    others: &BTreeMap<Identifier<C>, dkg::round1::Package<C>>,
) -> Result<[u8; ECHO_LEN]> {
    let mut all: BTreeMap<Identifier<C>, &dkg::round1::Package<C>> =
        others.iter().map(|(id, p)| (*id, p)).collect();
    all.insert(own_id, own);
    let mut h = Sha256::new();
    h.update(b"stackwallet-tss-dkg-echo");
    for (id, pkg) in all {
        let id = id.serialize();
        let pkg = pkg
            .serialize()
            .map_err(|_| CoreError::Crypto("round 1 package serialization"))?;
        h.update((id.len() as u32).to_be_bytes());
        h.update(&id);
        h.update((pkg.len() as u32).to_be_bytes());
        h.update(&pkg);
    }
    Ok(h.finalize().into())
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
    /// The sender's round-1 transcript hash, then its package.
    Dkg2([u8; ECHO_LEN], dkg::round2::Package<C>),
    Commitments(Vec<SigningCommitments<C>>),
    Share(Vec<SignatureShare<C>>),
    Delta(Delta<C>),
    /// A helper's repair value and its view of the group after the reshare.
    Repair(Sigma<C>, PublicKeyPackage<C>),
}

enum Phase<C: Ciphersuite> {
    DkgRound1 {
        secret: dkg::round1::SecretPackage<C>,
        own: dkg::round1::Package<C>,
        packages: BTreeMap<Identifier<C>, dkg::round1::Package<C>>,
    },
    DkgRound2 {
        secret: dkg::round2::SecretPackage<C>,
        round1: BTreeMap<Identifier<C>, dkg::round1::Package<C>>,
        round2: BTreeMap<Identifier<C>, dkg::round2::Package<C>>,
        /// This party's own round-1 transcript, which every peer must echo.
        transcript: [u8; ECHO_LEN],
    },
    SignRound1 {
        nonces: Vec<SigningNonces<C>>,
        commitments: BTreeMap<Identifier<C>, Vec<SigningCommitments<C>>>,
    },
    SignRound2 {
        packages: Vec<SigningPackage<C>>,
        shares: BTreeMap<Identifier<C>, Vec<SignatureShare<C>>>,
    },
    /// A helper collecting the other helpers' parts of its repair value.
    RepairDeltas {
        deltas: BTreeMap<Identifier<C>, Delta<C>>,
    },
    /// The newcomer collecting every helper's repair value and view.
    RepairSigmas {
        sigmas: BTreeMap<Identifier<C>, Sigma<C>>,
        views: BTreeMap<Identifier<C>, PublicKeyPackage<C>>,
    },
    Finished,
}

/// Who replaces whom in a reshare ceremony.
struct Reshare<C: Ciphersuite> {
    group_id: String,
    threshold: u16,
    helpers: BTreeSet<Identifier<C>>,
    newcomer: Identifier<C>,
    replaced: Identifier<C>,
    /// The serialized group key, which must come out of the reshare unchanged.
    group_key: Vec<u8>,
    /// The share and group this party carries into the closing refresh. They
    /// stay here, not on the party, so a reshare that aborts changes nothing.
    joined: Option<(KeyPackage<C>, PublicKeyPackage<C>)>,
}

struct Ceremony<C: Ciphersuite> {
    session_id: String,
    kind: CeremonyKind,
    binding_hex: String,
    messages: Vec<Vec<u8>>,
    sign_request_id: Option<String>,
    /// Every other participant, by device id.
    peers: BTreeMap<String, Identifier<C>>,
    round: u8,
    /// The rounds this party takes part in, in order; `round` walks them.
    rounds: Vec<u8>,
    /// Who must send in a round, where that is not every peer.
    senders: BTreeMap<u8, BTreeSet<String>>,
    /// The two DKG rounds; a reshare runs its refresh after the repair rounds.
    dkg_rounds: [u8; 2],
    reshare: Option<Reshare<C>>,
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
        let expected: Vec<&String> = match self.senders.get(&self.round) {
            Some(from) => from.iter().collect(),
            None => self.peers.keys().collect(),
        };
        expected
            .into_iter()
            .filter(|d| !self.seen.contains_key(&(self.round, (*d).clone())))
            .cloned()
            .collect()
    }

    fn position(&self, round: u8) -> Option<usize> {
        self.rounds.iter().position(|r| *r == round)
    }

    fn next_round(&self) -> Option<u8> {
        self.position(self.round)
            .and_then(|i| self.rounds.get(i + 1))
            .copied()
    }

    /// Whether `sender` has anything to say to this party in `round`.
    fn expects(&self, round: u8, sender: &str) -> bool {
        self.position(round).is_some()
            && self
                .senders
                .get(&round)
                .is_none_or(|from| from.contains(sender))
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

    /// Drops any ceremony in progress, as a device does when its session
    /// expires or is cancelled. Shares are untouched: every ceremony commits
    /// its result only when it completes.
    pub fn abandon(&mut self) {
        self.ceremony = None;
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

    /// `signing` carries the messages and request id for sign ceremonies;
    /// keygen and refresh have neither.
    fn begin(
        &mut self,
        session: &CeremonySession,
        kind: CeremonyKind,
        binding_hex: String,
        peers: BTreeMap<String, Identifier<C>>,
        phase: Phase<C>,
        signing: Option<(Vec<Vec<u8>>, String)>,
    ) {
        let (messages, sign_request_id) = signing.unzip();
        self.ceremony = Some(Ceremony {
            session_id: session.id.clone(),
            kind,
            binding_hex,
            messages: messages.unwrap_or_default(),
            sign_request_id,
            peers,
            round: 1,
            rounds: vec![1, 2],
            senders: BTreeMap::new(),
            dkg_rounds: [1, 2],
            reshare: None,
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
        let n = c.messages.len();
        let parsed = match &c.phase {
            Phase::DkgRound1 { .. } => dkg::round1::Package::<C>::deserialize(&body)
                .ok()
                .map(Body::Dkg1),
            Phase::DkgRound2 { .. } => {
                body.split_first_chunk::<ECHO_LEN>()
                    .and_then(|(echo, rest)| {
                        dkg::round2::Package::<C>::deserialize(rest)
                            .ok()
                            .map(|p| Body::Dkg2(*echo, p))
                    })
            }
            Phase::SignRound1 { .. } => {
                decode_all(&body, n, |b| SigningCommitments::<C>::deserialize(b).ok())
                    .map(Body::Commitments)
            }
            Phase::SignRound2 { .. } => {
                decode_all(&body, n, |b| SignatureShare::<C>::deserialize(b).ok()).map(Body::Share)
            }
            Phase::RepairDeltas { .. } => Delta::<C>::deserialize(&body).ok().map(Body::Delta),
            Phase::RepairSigmas { .. } => decode_items(&body, 2).and_then(|items| {
                Some(Body::Repair(
                    Sigma::<C>::deserialize(items[0]).ok()?,
                    PublicKeyPackage::<C>::deserialize(items[1]).ok()?,
                ))
            }),
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
            (
                Phase::DkgRound2 {
                    round2, transcript, ..
                },
                Body::Dkg2(echo, p),
            ) => {
                if echo != *transcript {
                    return Err(c.abort(format!(
                        "{sender} saw different round-1 packages than this device; a party sent conflicting broadcasts"
                    )));
                }
                round2.insert(id, p);
            }
            (Phase::SignRound1 { commitments, .. }, Body::Commitments(p)) => {
                commitments.insert(id, p);
            }
            (Phase::SignRound2 { shares, .. }, Body::Share(p)) => {
                shares.insert(id, p);
            }
            (Phase::RepairDeltas { deltas }, Body::Delta(d)) => {
                deltas.insert(id, d);
            }
            (Phase::RepairSigmas { sigmas, views }, Body::Repair(sigma, view)) => {
                sigmas.insert(id, sigma);
                views.insert(id, view);
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
            Phase::DkgRound1 {
                secret,
                own,
                packages,
            } => {
                let transcript = round1_transcript(self.own_identifier()?, &own, &packages)?;
                let (secret2, outgoing) = if c.kind != CeremonyKind::KeyGen {
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
                    let mut body = transcript.to_vec();
                    body.extend(
                        pkg.serialize()
                            .map_err(frost_err("dkg round 2 serialization"))?,
                    );
                    out.push(c.envelope(
                        &self.device_id,
                        Some(device.clone()),
                        c.dkg_rounds[1],
                        &body,
                    ));
                }
                c.phase = Phase::DkgRound2 {
                    secret: secret2,
                    round1: packages,
                    round2: BTreeMap::new(),
                    transcript,
                };
                c.round = c.dkg_rounds[1];
                Ok(out)
            }
            Phase::DkgRound2 {
                secret,
                round1,
                round2,
                ..
            } => {
                let (kp, pkp) = if c.kind == CeremonyKind::KeyGen {
                    dkg::part3(&secret, &round1, &round2).map_err(frost_err("dkg part 3"))?
                } else {
                    let (old_kp, old_pkp) = match c.reshare.as_ref() {
                        Some(r) => r
                            .joined
                            .clone()
                            .ok_or_else(|| ceremony_err("the reshare has no share to refresh"))?,
                        None => {
                            let (k, p, _) = self.require_key()?;
                            (k.clone(), p.clone())
                        }
                    };
                    let before = *old_pkp.verifying_key();
                    let (kp, pkp) =
                        refresh::refresh_dkg_shares(&secret, &round1, &round2, old_pkp, old_kp)
                            .map_err(frost_err("refresh finalize"))?;
                    // A refresh re-randomizes the shares and nothing else.
                    if *pkp.verifying_key() != before {
                        return Err(ceremony_err("the refresh would change the group key"));
                    }
                    (kp, pkp)
                };
                let vk = pkp
                    .verifying_key()
                    .serialize()
                    .map_err(frost_err("verifying key serialization"))?;
                self.key_package = Some(kp);
                self.public_key_package = Some(pkp);
                if let Some(r) = &c.reshare {
                    self.key_group_id = Some(r.group_id.clone());
                }
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
                let own = *kp.identifier();
                let mut packages = Vec::with_capacity(c.messages.len());
                let mut mine = Vec::with_capacity(c.messages.len());
                for (i, (message, nonces)) in c.messages.iter().zip(&nonces).enumerate() {
                    let round: BTreeMap<_, _> =
                        commitments.iter().map(|(id, all)| (*id, all[i])).collect();
                    let package = SigningPackage::new(round, message);
                    mine.push(
                        frost_core::round2::sign(&package, nonces, kp)
                            .map_err(frost_err("sign round 2"))?,
                    );
                    packages.push(package);
                }
                let bodies: Vec<Vec<u8>> = mine.iter().map(|s| s.serialize()).collect();
                let body = encode_items(&bodies);
                c.phase = Phase::SignRound2 {
                    packages,
                    shares: BTreeMap::from([(own, mine)]),
                };
                c.round = 2;
                Ok(vec![c.envelope(&self.device_id, None, 2, &body)])
            }
            Phase::SignRound2 { packages, shares } => {
                let (_, pkp, _) = self.require_key()?;
                let mut all = Vec::new();
                for (i, (package, message)) in packages.iter().zip(&c.messages).enumerate() {
                    let round: BTreeMap<_, _> = shares.iter().map(|(id, s)| (*id, s[i])).collect();
                    let sig = frost_core::aggregate(package, &round, pkp)
                        .map_err(frost_err("aggregate"))?;
                    pkp.verifying_key()
                        .verify(message, &sig)
                        .map_err(frost_err("group signature verification"))?;
                    all.extend(
                        sig.serialize()
                            .map_err(frost_err("signature serialization"))?,
                    );
                }
                c.signature = Some(Signature {
                    sign_request_id: c.sign_request_id.clone().unwrap_or_default(),
                    curve: C::CURVE,
                    signature_hex: hex::encode(all),
                    recovery_id: None,
                });
                c.state = CeremonyState::Complete;
                Ok(vec![])
            }
            Phase::RepairDeltas { deltas } => {
                let r = c.reshare.as_ref().expect("a reshare ceremony");
                let sigma =
                    repairable::repair_share_part2(&deltas.into_values().collect::<Vec<_>>());
                let (kp, pkp, _) = self.require_key()?;
                let joined = joined_package(pkp, &r.helpers, r.newcomer, r.replaced)?;
                let view = joined
                    .serialize()
                    .map_err(frost_err("public key package serialization"))?;
                let newcomer = c
                    .peers
                    .iter()
                    .find(|(_, id)| **id == r.newcomer)
                    .map(|(d, _)| d.clone())
                    .ok_or_else(|| ceremony_err("the newcomer is not a participant"))?;
                let mut out = vec![c.envelope(
                    &self.device_id,
                    Some(newcomer),
                    2,
                    &encode_items(&[sigma.serialize(), view]),
                )];
                out.extend(self.open_refresh(c, (kp.clone(), joined))?);
                Ok(out)
            }
            Phase::RepairSigmas { sigmas, views } => {
                let r = c.reshare.as_ref().expect("a reshare ceremony");
                // Every helper must describe the same group: the proposed key,
                // threshold and members.
                let mut described = views.into_values();
                let view = described
                    .next()
                    .ok_or_else(|| ceremony_err("no helper described the group"))?;
                let bytes = view
                    .serialize()
                    .map_err(frost_err("public key package serialization"))?;
                if described.any(|other| other.serialize().ok().as_deref() != Some(&bytes[..])) {
                    return Err(ceremony_err("the helpers disagree about the group"));
                }
                let key = view
                    .verifying_key()
                    .serialize()
                    .map_err(frost_err("verifying key serialization"))?;
                let members: BTreeSet<Identifier<C>> =
                    view.verifying_shares().keys().copied().collect();
                let mut expected = r.helpers.clone();
                expected.insert(r.newcomer);
                if key != r.group_key
                    || view.min_signers() != Some(r.threshold)
                    || members != expected
                {
                    return Err(ceremony_err(
                        "the helpers describe another group than the one proposed",
                    ));
                }
                let kp = repairable::repair_share_part3(
                    &sigmas.into_values().collect::<Vec<_>>(),
                    r.newcomer,
                    &view,
                )
                .map_err(frost_err("repair"))?;
                // frost does not check the repaired share against the group;
                // a helper that sent a wrong value is caught here.
                if view.verifying_shares().get(&r.newcomer) != Some(kp.verifying_share()) {
                    return Err(ceremony_err(
                        "the repaired share does not match the group; a helper sent a wrong value",
                    ));
                }
                self.open_refresh(c, (kp, view))
            }
            Phase::Finished => Err(ceremony_err("ceremony already finished")),
        }
    }

    /// Opens the refresh that ends a reshare, among every participant, from
    /// the share and group this party has just joined with.
    fn open_refresh(
        &self,
        c: &mut Ceremony<C>,
        joined: (KeyPackage<C>, PublicKeyPackage<C>),
    ) -> Result<Vec<CeremonyMessage>> {
        let min = joined
            .1
            .min_signers()
            .ok_or_else(|| ceremony_err("public key package has no threshold"))?;
        let n = (c.peers.len() + 1) as u16;
        let (secret, package) = refresh::refresh_dkg_part1(self.own_identifier()?, n, min, OsRng)
            .map_err(frost_err("refresh part 1"))?;
        let body = package
            .serialize()
            .map_err(frost_err("refresh round 1 serialization"))?;
        c.reshare.as_mut().expect("a reshare ceremony").joined = Some(joined);
        c.phase = Phase::DkgRound1 {
            secret,
            own: package,
            packages: BTreeMap::new(),
        };
        c.round = c.dkg_rounds[0];
        Ok(vec![c.envelope(
            &self.device_id,
            None,
            c.dkg_rounds[0],
            &body,
        )])
    }

    /// Join (or propose) the replacement of `replaced` by `newcomer` in
    /// `group`, keeping `group_key`. Every other party of the group is a
    /// helper and must take part, since a refresh leaves out whoever is
    /// absent; at least the threshold of them are needed to repair a share.
    pub fn reshare_start(
        &mut self,
        group: &KeyGroup,
        session: &CeremonySession,
        replaced: &str,
        newcomer: &PartyRef,
        group_key: &PublicKey,
    ) -> Result<Vec<CeremonyMessage>> {
        self.require_idle()?;
        group.validate()?;
        if group_key.curve != C::CURVE || !group.curves.contains(&C::CURVE) {
            return Err(CoreError::Invalid {
                what: "reshare",
                reason: "the group key is on another curve".into(),
            });
        }
        let next = replaced_group(group, replaced, newcomer)?;
        self.check_session(session, CeremonyKind::Reshare, &group.id)?;
        let mut expected: Vec<&str> = next.parties.iter().map(|p| p.device_id.as_str()).collect();
        let mut given: Vec<&str> = session.participants.iter().map(String::as_str).collect();
        expected.sort_unstable();
        given.sort_unstable();
        if expected != given {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "a reshare runs among every remaining party and the newcomer".into(),
            });
        }
        let key = hex::decode(&group_key.hex).map_err(|_| CoreError::Invalid {
            what: "reshare",
            reason: "group key is not hex".into(),
        })?;
        let binding = reshare_binding_hex(&next, C::CURVE, replaced, &key);
        if session.payload_hash_hex.as_deref() != Some(binding.as_str()) {
            return Err(CoreError::Invalid {
                what: "ceremony session",
                reason: "session binding does not match the reshare".into(),
            });
        }
        let helper_devices: BTreeSet<String> = session
            .participants
            .iter()
            .filter(|p| **p != newcomer.device_id)
            .cloned()
            .collect();
        if helper_devices.len() < group.threshold as usize {
            return Err(CoreError::Invalid {
                what: "reshare",
                reason: format!(
                    "{} remaining parties cannot repair a share of a {}-of-{} group",
                    helper_devices.len(),
                    group.threshold,
                    group.parties.len()
                ),
            });
        }
        let helpers = helper_devices
            .iter()
            .map(|d| identifier_for::<C>(d))
            .collect::<Result<BTreeSet<_>>>()?;
        let newcomer_id = identifier_for::<C>(&newcomer.device_id)?;
        let replaced_id = identifier_for::<C>(replaced)?;
        let peers = self.peer_identifiers(&session.participants)?;
        let reshare = Reshare {
            group_id: group.id.clone(),
            threshold: group.threshold as u16,
            helpers: helpers.clone(),
            newcomer: newcomer_id,
            replaced: replaced_id,
            group_key: key.clone(),
            joined: None,
        };

        if self.device_id == newcomer.device_id {
            if self.has_share() {
                return Err(ceremony_err("the newcomer already holds a share"));
            }
            self.begin(
                session,
                CeremonyKind::Reshare,
                binding,
                peers,
                Phase::RepairSigmas {
                    sigmas: BTreeMap::new(),
                    views: BTreeMap::new(),
                },
                None,
            );
            let c = self.ceremony.as_mut().expect("ceremony begun");
            c.rounds = vec![2, 3, 4];
            c.round = 2;
            c.senders = BTreeMap::from([(2, helper_devices)]);
            c.dkg_rounds = [3, 4];
            c.reshare = Some(reshare);
            return Ok(vec![]);
        }

        let (kp, pkp, group_id) = self.require_key()?;
        if group_id != group.id {
            return Err(ceremony_err("this share belongs to another group"));
        }
        let own_key = pkp
            .verifying_key()
            .serialize()
            .map_err(frost_err("verifying key serialization"))?;
        if own_key != key {
            return Err(ceremony_err("the proposed group key is not this group's"));
        }
        let members = group
            .parties
            .iter()
            .map(|p| identifier_for::<C>(&p.device_id))
            .collect::<Result<BTreeSet<_>>>()?;
        let held: BTreeSet<Identifier<C>> = pkp.verifying_shares().keys().copied().collect();
        if held != members || pkp.min_signers() != Some(group.threshold as u16) {
            return Err(ceremony_err(
                "the group record does not match the share this device holds",
            ));
        }
        let mut deltas = repairable::repair_share_part1(
            &helpers.iter().copied().collect::<Vec<_>>(),
            kp,
            &mut OsRng,
            newcomer_id,
        )
        .map_err(frost_err("repair part 1"))?;
        let own_id = self.own_identifier()?;
        let own = deltas
            .remove(&own_id)
            .ok_or_else(|| ceremony_err("no repair value for this device"))?;
        self.begin(
            session,
            CeremonyKind::Reshare,
            binding,
            peers,
            Phase::RepairDeltas {
                deltas: BTreeMap::from([(own_id, own)]),
            },
            None,
        );
        let self_id = self.device_id.clone();
        let c = self.ceremony.as_mut().expect("ceremony begun");
        c.rounds = vec![1, 3, 4];
        c.senders = BTreeMap::from([(
            1,
            helper_devices
                .iter()
                .filter(|d| **d != self_id)
                .cloned()
                .collect(),
        )]);
        c.dkg_rounds = [3, 4];
        c.reshare = Some(reshare);
        Ok(c.peers
            .iter()
            .filter_map(|(device, id)| {
                let delta = deltas.get(id)?;
                Some(c.envelope(&self_id, Some(device.clone()), 1, &delta.serialize()))
            })
            .collect())
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

impl<C: FrostCurve> FrostParty<C> {
    /// Sign several messages under one ceremony, each with fresh nonces. The
    /// caller derives `messages` from the request's payload, which the session
    /// binds, so every party signs what its own core computed. The result's
    /// `signature_hex` is the signatures concatenated in message order.
    pub fn sign_batch_start(
        &mut self,
        request: &SignRequest,
        session: &CeremonySession,
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<CeremonyMessage>> {
        if messages.is_empty() || messages.len() > MAX_BATCH {
            return Err(CoreError::Invalid {
                what: "sign request",
                reason: format!("expected 1 to {MAX_BATCH} messages"),
            });
        }
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
        let (nonces, commitments): (Vec<_>, Vec<_>) = messages
            .iter()
            .map(|_| frost_core::round1::commit(kp.signing_share(), &mut OsRng))
            .unzip();
        let bodies = commitments
            .iter()
            .map(|c| c.serialize())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(frost_err("commitment serialization"))?;
        let body = encode_items(&bodies);
        self.begin(
            session,
            CeremonyKind::Sign,
            binding,
            peers,
            Phase::SignRound1 {
                nonces,
                commitments: BTreeMap::from([(own, commitments)]),
            },
            Some((messages, request.id.clone())),
        );
        Ok(self.broadcast(1, &body))
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
                own: package,
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
        let message = message_to_sign(request)?;
        FrostParty::sign_batch_start(self, request, session, vec![message])
    }

    fn sign_batch_start(
        &mut self,
        request: &SignRequest,
        session: &CeremonySession,
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<CeremonyMessage>> {
        FrostParty::sign_batch_start(self, request, session, messages)
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
                own: package,
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
        if c.position(msg.round).is_none() {
            return Err(ceremony_err(format!(
                "round {} does not exist in this protocol",
                msg.round
            )));
        }
        if !c.expects(msg.round, &msg.from_device_id) {
            return Err(ceremony_err(format!(
                "{} has nothing to send in round {}",
                msg.from_device_id, msg.round
            )));
        }
        if msg.round != c.round {
            if Some(msg.round) == c.next_round() {
                c.buffered.push(msg);
                return Ok(vec![]);
            }
            return Err(ceremony_err(
                if c.position(msg.round) < c.position(c.round) {
                    format!("round {} is already complete", msg.round)
                } else {
                    format!(
                        "round {} is more than one round ahead of {}",
                        msg.round, c.round
                    )
                },
            ));
        }
        self.ingest(msg)
    }

    fn keygen_result(&self, session: &CeremonySession) -> Result<Option<PublicKey>> {
        Ok(self
            .result_for(
                session,
                &[
                    CeremonyKind::KeyGen,
                    CeremonyKind::Refresh,
                    CeremonyKind::Reshare,
                ],
            )?
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
    fn batch_bodies_carry_exactly_one_item_per_message() {
        let items = vec![vec![1, 2], vec![], vec![3]];
        let body = encode_items(&items);
        let back: Vec<Vec<u8>> = decode_items(&body, 3)
            .unwrap()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        assert_eq!(back, items);
        assert!(decode_items(&body, 2).is_none());
        assert!(decode_items(&body, 4).is_none());
        assert!(decode_items(&body[..body.len() - 1], 3).is_none());
        assert!(decode_items(&[0, 0, 0, 9, 1], 2).is_none());
        // A single message keeps the plain frost serialization.
        assert_eq!(encode_items(&[vec![7, 8]]), vec![7, 8]);
        assert_eq!(decode_items(&[7, 8], 1).unwrap(), vec![&[7u8, 8][..]]);
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
