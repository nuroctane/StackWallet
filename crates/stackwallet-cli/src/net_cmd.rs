//! `serve`, `net keygen`, `net sign`: FROST ceremonies between paired devices.
//!
//! The topology is a star. The initiator opens one IK session per peer and
//! relays peer-to-peer traffic; a `serve` process only ever talks to the
//! initiator and hands it everything, addressed or broadcast. Every ceremony
//! message is signed end to end by its author and verified by each receiver
//! against the pinned identity of the device it claims to come from, so the
//! hub can neither forge nor alter a message; the worst it can do is drop or
//! withhold traffic, which aborts the ceremony and nothing else.
//!
//! The session authenticates only its own peer. A message it forwards for a
//! third device arrives as `SessionEvent::Relayed`, unverified, and is
//! admitted here against this device's own table, which is why every
//! participant must be paired with every other participant and not just
//! with the hub: an author we never pinned is refused and the ceremony
//! aborts.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use stackwallet_core::identity::SignedCeremonyMessage;
use stackwallet_core::intent::{SignRequest, Signature};
use stackwallet_core::model::{Curve, KeyGroup, PartyRef, PartyRole, PublicKey};
use stackwallet_core::store::{Device, KeyGroupRecord};
use stackwallet_core::transport::{Endpoint, Frame, HandshakeRole, Session, SessionEvent};
use stackwallet_core::tss::frost::{keygen_binding_hex, FrostCurve, FrostParty};
use stackwallet_core::tss::{
    CeremonyKind, CeremonyMessage, CeremonySession, CeremonyState, ThresholdScheme,
};

use crate::discovery;
use crate::harness_cmd::{
    audited, curve_slug, load_group, load_share_at, parse_curve, sha256_hex, store_share_at,
    with_frost_curve,
};
use crate::net::{self, Hub, CONNECT_RETRY, IDLE_TIMEOUT};
use crate::pair_cmd::local_device;
use crate::vault_cmd::{self, fmt_err, now_ms, Opened};

pub const SERVE_USAGE: &str = "stackwallet serve <dir> --listen host:port [--once] [--no-mdns]

Accept IK connections from paired devices and take part in the ceremonies
they start. The share this device produces or uses is stored in the vault as
`share/<group-id>/<curve>`. --once exits after the first completed ceremony;
--no-mdns skips the LAN advertisement.
";

pub const NET_USAGE: &str = "stackwallet net <command>

Commands:
  keygen <dir> --group <id> --curve <ed25519|secp256k1-tr> --threshold <t>
                --peers <device-id[:role],...> [--role human|agent|automation]
                [--addr <device-id>=host:port]...
                               run DKG with this device and every peer; peers must be
                               paired and running `serve`; role defaults to human
  sign <dir> --group <id> --curve <curve> --payload-hex <hex>
             --peers <device-id,...> [--addr <device-id>=host:port]...
                               sign payload-hex with this device and the listed peers

Peers are reached at --addr, else at the endpoint pinned when pairing, else
through mDNS. Discovery never changes who is trusted: the connection still has
to authenticate against the keys pinned at pairing.
";

/// How long a proposed ceremony stays valid for the parties that join it.
const SESSION_TTL_MS: i64 = 120_000;
const MDNS_RESOLVE: Duration = Duration::from_secs(3);

/// Round number the CLI reserves for the message that opens a ceremony. The
/// FROST driver rejects round 0 outright, so a proposal can never be fed to
/// it by mistake and a protocol message can never be mistaken for one.
const PROPOSAL_ROUND: u8 = 0;

/// What the initiator sends each peer before any protocol message, signed
/// like every other ceremony message so the peer knows who is proposing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum Proposal {
    KeyGen {
        group: KeyGroup,
        session: CeremonySession,
    },
    Sign {
        request: SignRequest,
        session: CeremonySession,
    },
}

impl Proposal {
    fn session(&self) -> &CeremonySession {
        match self {
            Proposal::KeyGen { session, .. } | Proposal::Sign { session, .. } => session,
        }
    }

    fn sign_request_id(&self) -> Option<String> {
        match self {
            Proposal::Sign { request, .. } => Some(request.id.clone()),
            Proposal::KeyGen { .. } => None,
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Proposal::KeyGen { .. } => "keyGen",
            Proposal::Sign { .. } => "sign",
        }
    }

    fn to_message(&self, from: &str, to: &str) -> Result<CeremonyMessage, String> {
        let session = self.session();
        Ok(CeremonyMessage {
            session_id: session.id.clone(),
            payload_hash_hex: session.payload_hash_hex.clone().unwrap_or_default(),
            from_device_id: from.to_owned(),
            to_device_id: Some(to.to_owned()),
            round: PROPOSAL_ROUND,
            body_hex: hex::encode(serde_json::to_vec(self).map_err(|e| e.to_string())?),
        })
    }

    fn from_message(msg: &CeremonyMessage) -> Result<Self, String> {
        let body = hex::decode(&msg.body_hex).map_err(|_| "proposal body is not hex")?;
        let proposal: Self =
            serde_json::from_slice(&body).map_err(|e| format!("malformed proposal: {e}"))?;
        let session = proposal.session();
        if session.id != msg.session_id
            || session.payload_hash_hex.as_deref() != Some(msg.payload_hash_hex.as_str())
        {
            return Err("proposal envelope does not match its session".into());
        }
        Ok(proposal)
    }

    fn start(&self, party: &mut dyn ThresholdScheme) -> Result<Vec<CeremonyMessage>, String> {
        match self {
            Proposal::KeyGen { group, session } => party.keygen_start(group, session),
            Proposal::Sign { request, session } => party.sign_start(request, session),
        }
        .map_err(fmt_err)
    }
}

fn share_label(group_id: &str, curve: Curve) -> String {
    format!("share/{group_id}/{}", curve_slug(curve))
}

fn boxed_party<C: FrostCurve>(device_id: &str) -> Result<Box<dyn ThresholdScheme>, String> {
    Ok(Box::new(FrostParty::<C>::new(device_id)))
}

fn new_party(curve: Curve, device_id: &str) -> Result<Box<dyn ThresholdScheme>, String> {
    with_frost_curve!(curve, boxed_party(device_id))
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(None),
        Some(i) => args
            .get(i + 1)
            .map(String::as_str)
            .ok_or_else(|| format!("{name} needs a value"))
            .map(Some),
    }
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    flag(args, name)?.ok_or_else(|| format!("{name} is required"))
}

fn parse_role(s: &str) -> Result<PartyRole, String> {
    match s {
        "human" => Ok(PartyRole::Human),
        "agent" => Ok(PartyRole::Agent),
        "automation" => Ok(PartyRole::Automation),
        other => Err(format!("unknown role `{other}`")),
    }
}

/// `--peers a,b:agent,c` into party refs; roles default to human.
fn parse_peers(spec: &str) -> Result<Vec<PartyRef>, String> {
    let mut peers = Vec::new();
    for item in spec.split(',').filter(|s| !s.is_empty()) {
        let (device_id, role) = match item.split_once(':') {
            Some((d, r)) => (d, parse_role(r)?),
            None => (item, PartyRole::Human),
        };
        if device_id.is_empty() {
            return Err(format!("peer `{item}` has an empty device id"));
        }
        if peers.iter().any(|p: &PartyRef| p.device_id == device_id) {
            return Err(format!("peer `{device_id}` listed twice"));
        }
        peers.push(PartyRef {
            device_id: device_id.to_owned(),
            role,
        });
    }
    if peers.is_empty() {
        return Err("--peers needs at least one device id".into());
    }
    Ok(peers)
}

/// Every `--addr <device-id>=host:port` on the command line.
fn parse_addr_overrides(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a != "--addr" {
            continue;
        }
        let value = it.next().ok_or("--addr needs <device-id>=host:port")?;
        let (id, addr) = value
            .split_once('=')
            .ok_or_else(|| format!("--addr `{value}` must be <device-id>=host:port"))?;
        addr.parse::<SocketAddr>()
            .map_err(|_| format!("--addr `{value}`: `{addr}` is not host:port"))?;
        out.insert(id.to_owned(), addr.to_owned());
    }
    Ok(out)
}

fn touch_last_seen(opened: &Opened, device_id: &str) -> Result<(), String> {
    if let Some(mut d) = opened.store.get_device(device_id).map_err(fmt_err)? {
        d.last_seen_at_ms = Some(now_ms());
        opened.store.upsert_device(&d).map_err(fmt_err)?;
    }
    Ok(())
}

/// A pinned, unrevoked device, or the reason it cannot take part.
fn pinned(opened: &Opened, device_id: &str) -> Result<Device, String> {
    let device = opened
        .store
        .get_device(device_id)
        .map_err(fmt_err)?
        .ok_or_else(|| format!("device `{device_id}` is not paired with this one"))?;
    if device.revoked_at_ms.is_some() {
        return Err(format!("device `{device_id}` is revoked"));
    }
    Ok(device)
}

fn identities_of(
    opened: &Opened,
    participants: &[String],
    self_id: &str,
) -> Result<BTreeMap<String, String>, String> {
    participants
        .iter()
        .filter(|p| p.as_str() != self_id)
        .map(|p| pinned(opened, p).map(|d| (p.clone(), d.identity_pub_hex)))
        .collect()
}

/// Admit one envelope that arrived over the network, direct or relayed, to
/// the current ceremony. `identities` holds the pinned identity key of every
/// other participant, so an author outside it is either not a participant or
/// was never paired; both are refused before the body is looked at.
fn admit(
    signed: &SignedCeremonyMessage,
    session: &CeremonySession,
    identities: &BTreeMap<String, String>,
) -> Result<(), String> {
    let from = &signed.msg.from_device_id;
    let key = identities
        .get(from)
        .ok_or_else(|| format!("`{from}` is not a pinned participant of this ceremony"))?;
    signed
        .verify(key)
        .map_err(|e| format!("message from `{from}` fails verification: {e}"))?;
    if signed.msg.round == PROPOSAL_ROUND {
        return Err(format!("`{from}` tried to open a ceremony of its own"));
    }
    if signed.msg.session_id != session.id {
        return Err(format!("`{from}` sent a message for another session"));
    }
    if let Some(to) = &signed.msg.to_device_id {
        if to == from {
            return Err(format!("`{from}` addressed a message to itself"));
        }
        if !session.participants.contains(to) {
            return Err(format!(
                "`{from}` addressed `{to}`, which is not a participant"
            ));
        }
    }
    Ok(())
}

/// Reason a party gives in its `Bye` once it holds the result; the hub treats
/// that goodbye as success even while it is still waiting on other peers.
const BYE_COMPLETE: &str = "complete";

/// Feed one verified message to the local party. A driver that refuses a
/// message without aborting (a duplicate, a stale round) is not fatal.
fn handle_locally(
    party: &mut dyn ThresholdScheme,
    session: &CeremonySession,
    msg: CeremonyMessage,
) -> Result<Vec<CeremonyMessage>, String> {
    match party.handle(session, msg) {
        Ok(produced) => Ok(produced),
        Err(e) if party.state() == CeremonyState::Aborted => Err(e.to_string()),
        Err(e) => {
            eprintln!("refused: {e}");
            Ok(Vec::new())
        }
    }
}

fn record_keygen(opened: &Opened, group: &KeyGroup, public_key: &PublicKey) -> Result<(), String> {
    let at = now_ms();
    let mut record = match opened.store.get_key_group(&group.id).map_err(fmt_err)? {
        Some(existing) => existing,
        None => KeyGroupRecord {
            group: group.clone(),
            created_at_ms: at,
            refreshed_at_ms: None,
        },
    };
    if !record.group.curves.contains(&public_key.curve) {
        record.group.curves.push(public_key.curve);
    }
    record
        .group
        .public_keys
        .retain(|k| k.curve != public_key.curve);
    record.group.public_keys.push(public_key.clone());
    opened.store.upsert_key_group(&record).map_err(fmt_err)
}

fn public_key_of(group: &KeyGroup, curve: Curve) -> Option<PublicKey> {
    group.public_keys.iter().find(|k| k.curve == curve).cloned()
}

/// Checks a key group this device is about to generate a share for, on both
/// the initiating and the accepting side.
fn check_keygen(
    opened: &Opened,
    group: &KeyGroup,
    curve: Curve,
    self_id: &str,
) -> Result<(), String> {
    group.validate().map_err(fmt_err)?;
    if !group.curves.contains(&curve) {
        return Err(format!(
            "group `{}` does not include {}",
            group.id,
            curve_slug(curve)
        ));
    }
    if !group.parties.iter().any(|p| p.device_id == self_id) {
        return Err(format!(
            "this device is not a party of group `{}`",
            group.id
        ));
    }
    let label = share_label(&group.id, curve);
    if opened.vault.handle_for(&label).is_some() {
        return Err(format!(
            "the vault already holds `{label}`; refusing to overwrite a share"
        ));
    }
    if let Some(existing) = opened.store.get_key_group(&group.id).map_err(fmt_err)? {
        if existing.group.parties != group.parties || existing.group.threshold != group.threshold {
            return Err(format!(
                "group `{}` exists with a different party set or threshold",
                group.id
            ));
        }
        if public_key_of(&existing.group, curve).is_some() {
            return Err(format!(
                "group `{}` already has a {} key",
                group.id,
                curve_slug(curve)
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

struct Peer {
    device: Device,
    conn: usize,
    addr: String,
    done: bool,
}

fn addresses_for(device: &Device, overrides: &BTreeMap<String, String>) -> Vec<String> {
    if let Some(addr) = overrides.get(&device.id) {
        return vec![addr.clone()];
    }
    let pinned: Vec<String> = device
        .endpoints
        .iter()
        .filter_map(|e| match Endpoint::parse(e)? {
            Endpoint::Tcp { addr } => Some(addr),
            Endpoint::WebRtc { .. } => None,
        })
        .collect();
    if !pinned.is_empty() {
        return pinned;
    }
    discovery::resolve(device, MDNS_RESOLVE)
        .into_iter()
        .map(|a| a.to_string())
        .collect()
}

/// Connect to every peer and wait until each session is authenticated.
fn connect_peers(
    opened: &Opened,
    hub: &mut Hub,
    peer_ids: &[String],
    overrides: &BTreeMap<String, String>,
) -> Result<Vec<Peer>, String> {
    let self_id = opened.identity.device_id();
    let mut devices = Vec::new();
    for id in peer_ids {
        if *id == self_id {
            return Err("this device cannot be its own peer".into());
        }
        devices.push(pinned(opened, id)?);
    }
    let local = local_device(opened, Vec::new())?;
    let mut peers = Vec::new();
    for device in devices {
        let addrs = addresses_for(&device, overrides);
        if addrs.is_empty() {
            return Err(format!(
                "no address for `{}`: pass --addr, pair again with --listen, or start it with `serve`",
                device.id
            ));
        }
        let stream = net::connect_with_retry(&addrs, CONNECT_RETRY)
            .map_err(|e| format!("{}: {e}", device.id))?;
        let addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let session = Session::connect(
            &opened.identity,
            &local,
            HandshakeRole::Initiator,
            Some(&device),
            None,
            now_ms(),
        )
        .map_err(fmt_err)?;
        let conn = hub.add(stream, session)?;
        peers.push(Peer {
            device,
            conn,
            addr,
            done: false,
        });
    }

    let mut opened_count = 0;
    while opened_count < peers.len() {
        match hub.next_event(IDLE_TIMEOUT)? {
            Some((idx, SessionEvent::Opened { peer })) => {
                let expected = peers
                    .iter()
                    .find(|p| p.conn == idx)
                    .ok_or("event for an unknown connection")?;
                if peer.id != expected.device.id {
                    return Err(format!(
                        "{} answered as `{}`, expected `{}`",
                        expected.addr, peer.id, expected.device.id
                    ));
                }
                touch_last_seen(opened, &peer.id)?;
                opened_count += 1;
            }
            Some((idx, SessionEvent::Closed { reason })) => {
                let who = peers
                    .iter()
                    .find(|p| p.conn == idx)
                    .map(|p| p.device.id.clone())
                    .unwrap_or_default();
                return Err(format!("{who}: {reason}"));
            }
            Some(_) => {}
            None => return Err("every connection closed before the handshake finished".into()),
        }
    }
    Ok(peers)
}

/// Run one ceremony as the hub: propose, start the local party, relay until
/// the local party has a result and every peer has said goodbye.
fn hub_ceremony(
    opened: &Opened,
    hub: &mut Hub,
    peers: &mut [Peer],
    proposal: &Proposal,
    party: &mut dyn ThresholdScheme,
) -> Result<(), String> {
    let self_id = opened.identity.device_id();
    let session = proposal.session().clone();
    let identities: BTreeMap<String, String> = peers
        .iter()
        .map(|p| (p.device.id.clone(), p.device.identity_pub_hex.clone()))
        .collect();

    for peer in peers.iter() {
        let msg = proposal.to_message(&self_id, &peer.device.id)?;
        let signed = SignedCeremonyMessage::sign(&opened.identity, msg);
        hub.send(peer.conn, Frame::Ceremony(signed))?;
    }

    // Fan one envelope out to every peer it is for, skipping the author and
    // peers that already finished: a party only says goodbye once it holds
    // the result, so anything still addressed to it is a stray.
    let forward = |hub: &mut Hub, peers: &[Peer], signed: &SignedCeremonyMessage| {
        for peer in peers.iter().filter(|p| !p.done) {
            let wanted = match &signed.msg.to_device_id {
                Some(to) => *to == peer.device.id,
                None => peer.device.id != signed.msg.from_device_id,
            };
            if wanted {
                hub.send(peer.conn, Frame::Ceremony(signed.clone()))?;
            }
        }
        Ok::<(), String>(())
    };

    let mut outbox: Vec<CeremonyMessage> = proposal.start(party)?;
    loop {
        // Anything the local party produced is signed here; anything relayed
        // keeps the author's signature untouched.
        for msg in outbox.drain(..) {
            let signed = SignedCeremonyMessage::sign(&opened.identity, msg);
            forward(hub, peers, &signed)?;
        }
        if party.state() == CeremonyState::Complete && peers.iter().all(|p| p.done) {
            return Ok(());
        }
        let Some((idx, event)) = hub.next_event(IDLE_TIMEOUT)? else {
            return Err("every peer connection closed".into());
        };
        let peer_pos = peers
            .iter()
            .position(|p| p.conn == idx)
            .ok_or("event for an unknown connection")?;
        match event {
            SessionEvent::Frame(Frame::Ceremony(signed)) => {
                admit(&signed, &session, &identities)?;
                forward(hub, peers, &signed)?;
                let for_us = signed
                    .msg
                    .to_device_id
                    .as_ref()
                    .is_none_or(|to| *to == self_id);
                if for_us {
                    outbox.extend(handle_locally(party, &session, signed.msg)?);
                }
            }
            SessionEvent::Relayed(signed) => {
                // In a star only the hub forwards; a peer presenting someone
                // else's envelope is talking to the wrong device.
                return Err(format!(
                    "{} relayed a message from `{}`; peers do not relay",
                    peers[peer_pos].device.id, signed.msg.from_device_id
                ));
            }
            SessionEvent::Closed { reason } => {
                let finished = reason.ends_with(BYE_COMPLETE);
                if !finished && party.state() != CeremonyState::Complete {
                    return Err(format!(
                        "{} left before the ceremony finished: {reason}",
                        peers[peer_pos].device.id
                    ));
                }
                peers[peer_pos].done = true;
            }
            _ => {}
        }
    }
}

fn session_for(
    kind: CeremonyKind,
    group_id: &str,
    curve: Curve,
    binding_hex: String,
    participants: Vec<String>,
) -> CeremonySession {
    let at = now_ms();
    CeremonySession {
        id: format!("{group_id}-{kind:?}-{at}").to_lowercase(),
        kind,
        key_group_id: group_id.to_owned(),
        curve,
        payload_hash_hex: Some(binding_hex),
        participants,
        state: CeremonyState::Rounds,
        created_at_ms: at,
        expires_at_ms: at + SESSION_TTL_MS,
    }
}

fn keygen(args: &[String]) -> Result<serde_json::Value, String> {
    let dir = args.first().ok_or("net keygen needs a vault directory")?;
    let group_id = required(args, "--group")?;
    let curve = parse_curve(required(args, "--curve")?)?;
    let threshold: u8 = required(args, "--threshold")?
        .parse()
        .map_err(|e| format!("--threshold: {e}"))?;
    let peers = parse_peers(required(args, "--peers")?)?;
    if peers.len() + 1 < threshold as usize {
        return Err(format!(
            "need at least {} peer(s) for a threshold of {threshold}, got {}",
            threshold as usize - 1,
            peers.len()
        ));
    }
    let self_role = flag(args, "--role")?.map(parse_role).transpose()?;
    let overrides = parse_addr_overrides(args)?;

    let mut opened = vault_cmd::open(dir)?;
    let self_id = opened.identity.device_id();
    let mut parties = vec![PartyRef {
        device_id: self_id.clone(),
        role: self_role.unwrap_or(PartyRole::Human),
    }];
    parties.extend(peers);
    let group = KeyGroup {
        id: group_id.to_owned(),
        threshold,
        parties,
        curves: vec![curve],
        public_keys: Vec::new(),
    };
    check_keygen(&opened, &group, curve, &self_id)?;
    let peer_ids: Vec<String> = group
        .parties
        .iter()
        .map(|p| p.device_id.clone())
        .filter(|d| *d != self_id)
        .collect();

    let mut hub = Hub::new();
    let mut peers = connect_peers(&opened, &mut hub, &peer_ids, &overrides)?;
    let participants: Vec<String> = group.parties.iter().map(|p| p.device_id.clone()).collect();
    let session = session_for(
        CeremonyKind::KeyGen,
        group_id,
        curve,
        keygen_binding_hex(&group, curve),
        participants,
    );
    let proposal = Proposal::KeyGen {
        group: group.clone(),
        session: session.clone(),
    };
    let mut party = new_party(curve, &self_id)?;
    let result = audited(&mut opened, session.id.clone(), None, |opened| {
        hub_ceremony(opened, &mut hub, &mut peers, &proposal, party.as_mut())?;
        let public_key = party
            .keygen_result(&session)
            .map_err(fmt_err)?
            .ok_or("ceremony complete but no public key")?;
        let blob = party.export_share().map_err(fmt_err)?;
        store_share_at(opened, &share_label(group_id, curve), &blob)?;
        record_keygen(opened, &group, &public_key)?;
        Ok(public_key)
    });
    hub.close_all(if result.is_ok() {
        BYE_COMPLETE
    } else {
        "aborted"
    });
    let public_key = result?;
    opened.save()?;
    Ok(serde_json::json!({
        "groupId": group_id,
        "threshold": threshold,
        "parties": group.parties,
        "publicKey": public_key,
        "sessionId": session.id,
        "peers": peers.iter().map(|p| serde_json::json!({
            "deviceId": p.device.id,
            "addr": p.addr,
        })).collect::<Vec<_>>(),
    }))
}

fn sign(args: &[String]) -> Result<serde_json::Value, String> {
    let dir = args.first().ok_or("net sign needs a vault directory")?;
    let group_id = required(args, "--group")?;
    let curve = parse_curve(required(args, "--curve")?)?;
    let payload = required(args, "--payload-hex")?;
    let peer_ids: Vec<String> = parse_peers(required(args, "--peers")?)?
        .into_iter()
        .map(|p| p.device_id)
        .collect();
    let overrides = parse_addr_overrides(args)?;
    let payload_bytes = hex::decode(payload).map_err(|_| "--payload-hex must be hex".to_owned())?;
    if payload_bytes.is_empty() {
        return Err("payload is empty".into());
    }

    let mut opened = vault_cmd::open(dir)?;
    let self_id = opened.identity.device_id();
    let record = load_group(&opened, group_id)?;
    let public_key = public_key_of(&record.group, curve)
        .ok_or_else(|| format!("group `{group_id}` has no {} key", curve_slug(curve)))?;
    for id in &peer_ids {
        if !record.group.parties.iter().any(|p| p.device_id == *id) {
            return Err(format!("`{id}` is not a party of group `{group_id}`"));
        }
    }
    let blob = load_share_at(&opened, &share_label(group_id, curve))?;

    let mut hub = Hub::new();
    let mut peers = connect_peers(&opened, &mut hub, &peer_ids, &overrides)?;
    let at = now_ms();
    let request = SignRequest {
        id: format!("net-sign-{at}"),
        tx_id: format!("net-tx-{at}"),
        key_group_id: group_id.to_owned(),
        curve,
        payload_hash_hex: sha256_hex(&payload_bytes),
        payload_hex: payload.to_lowercase(),
    };
    let mut participants = vec![self_id.clone()];
    participants.extend(peer_ids.iter().cloned());
    let session = session_for(
        CeremonyKind::Sign,
        group_id,
        curve,
        request.payload_hash_hex.clone(),
        participants.clone(),
    );
    let proposal = Proposal::Sign {
        request: request.clone(),
        session: session.clone(),
    };
    let mut party = new_party(curve, &self_id)?;
    party.import_share(&blob).map_err(fmt_err)?;
    let result = audited(
        &mut opened,
        session.id.clone(),
        Some(request.id.clone()),
        |opened| {
            hub_ceremony(opened, &mut hub, &mut peers, &proposal, party.as_mut())?;
            party
                .sign_result(&session)
                .map_err(fmt_err)?
                .ok_or_else(|| "ceremony complete but no signature".to_owned())
        },
    );
    hub.close_all(if result.is_ok() {
        BYE_COMPLETE
    } else {
        "aborted"
    });
    let signature = result?;
    opened.save()?;
    Ok(serde_json::json!({
        "groupId": group_id,
        "signers": participants,
        "request": request,
        "publicKey": public_key,
        "signature": signature,
        "sessionId": session.id,
    }))
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

enum Outcome {
    KeyGen(PublicKey),
    Sign(Signature),
}

/// Everything a party checks before it lets a proposal touch its share.
fn check_proposal(
    opened: &Opened,
    proposal: &Proposal,
    proposer: &Device,
    self_id: &str,
) -> Result<BTreeMap<String, String>, String> {
    let session = proposal.session();
    if !session.participants.iter().any(|p| p == self_id) {
        return Err("this device is not a participant".into());
    }
    if !session.participants.contains(&proposer.id) {
        return Err("the proposer is not a participant".into());
    }
    if session.payload_hash_hex.is_none() {
        return Err("session carries no binding".into());
    }
    if now_ms() >= session.expires_at_ms {
        return Err("session already expired".into());
    }
    let identities = identities_of(opened, &session.participants, self_id)?;
    match proposal {
        Proposal::KeyGen { group, session } => {
            if session.kind != CeremonyKind::KeyGen || session.key_group_id != group.id {
                return Err("keygen session does not match its group".into());
            }
            check_keygen(opened, group, session.curve, self_id)?;
            let mut expected: Vec<&str> =
                group.parties.iter().map(|p| p.device_id.as_str()).collect();
            let mut given: Vec<&str> = session.participants.iter().map(String::as_str).collect();
            expected.sort_unstable();
            given.sort_unstable();
            if expected != given {
                return Err("keygen participants must be exactly the group parties".into());
            }
            if session.payload_hash_hex.as_deref()
                != Some(keygen_binding_hex(group, session.curve).as_str())
            {
                return Err("keygen binding does not match the group".into());
            }
        }
        Proposal::Sign { request, session } => {
            if session.kind != CeremonyKind::Sign
                || request.key_group_id != session.key_group_id
                || request.curve != session.curve
                || session.payload_hash_hex.as_deref() != Some(request.payload_hash_hex.as_str())
            {
                return Err("sign session does not match its request".into());
            }
            let record = load_group(opened, &request.key_group_id)?;
            for p in &session.participants {
                if !record
                    .group
                    .parties
                    .iter()
                    .any(|party| party.device_id == *p)
                {
                    return Err(format!(
                        "`{p}` is not a party of group `{}`",
                        record.group.id
                    ));
                }
            }
        }
    }
    Ok(identities)
}

fn party_ceremony(
    opened: &mut Opened,
    hub: &mut Hub,
    conn: usize,
    proposal: &Proposal,
    identities: &BTreeMap<String, String>,
) -> Result<Outcome, String> {
    let self_id = opened.identity.device_id();
    let session = proposal.session().clone();
    let mut party = new_party(session.curve, &self_id)?;
    if let Proposal::Sign { request, .. } = proposal {
        let blob = load_share_at(opened, &share_label(&request.key_group_id, request.curve))?;
        party.import_share(&blob).map_err(fmt_err)?;
    }
    let mut outbox = proposal.start(party.as_mut())?;
    loop {
        for msg in outbox.drain(..) {
            let signed = SignedCeremonyMessage::sign(&opened.identity, msg);
            hub.send(conn, Frame::Ceremony(signed))?;
        }
        if party.state() == CeremonyState::Complete {
            break;
        }
        let Some((_, event)) = hub.next_event(IDLE_TIMEOUT)? else {
            return Err("connection closed".into());
        };
        match event {
            // Direct frames were already checked against the hub's key by
            // the session; relayed ones were not checked by anyone. Both go
            // through the same admission so the difference cannot matter.
            SessionEvent::Frame(Frame::Ceremony(signed)) | SessionEvent::Relayed(signed) => {
                admit(&signed, &session, identities)?;
                if let Some(to) = &signed.msg.to_device_id {
                    if *to != self_id {
                        return Err(format!(
                            "the hub delivered a message from `{}` meant for `{to}`",
                            signed.msg.from_device_id
                        ));
                    }
                }
                outbox.extend(handle_locally(party.as_mut(), &session, signed.msg)?);
            }
            SessionEvent::Closed { reason } => {
                return Err(format!("initiator left: {reason}"));
            }
            _ => {}
        }
    }
    let outcome = match proposal {
        Proposal::KeyGen { group, session } => {
            let public_key = party
                .keygen_result(session)
                .map_err(fmt_err)?
                .ok_or("ceremony complete but no public key")?;
            let blob = party.export_share().map_err(fmt_err)?;
            store_share_at(opened, &share_label(&group.id, session.curve), &blob)?;
            record_keygen(opened, group, &public_key)?;
            Outcome::KeyGen(public_key)
        }
        Proposal::Sign { session, .. } => Outcome::Sign(
            party
                .sign_result(session)
                .map_err(fmt_err)?
                .ok_or("ceremony complete but no signature")?,
        ),
    };
    // A write failure here only means the hub already went away; the result
    // is still ours to keep.
    let _ = hub.send(
        conn,
        Frame::Bye {
            reason: BYE_COMPLETE.into(),
        },
    );
    Ok(outcome)
}

/// One accepted connection: authenticate, take one proposal, run it.
fn serve_connection(
    opened: &mut Opened,
    hub: &mut Hub,
    conn: usize,
) -> Result<serde_json::Value, String> {
    let self_id = opened.identity.device_id();
    let proposer = loop {
        match hub.next_event(IDLE_TIMEOUT)? {
            Some((_, SessionEvent::Opened { peer })) => break peer,
            Some((_, SessionEvent::Closed { reason })) => return Err(reason),
            Some(_) => {}
            None => return Err("connection closed during the handshake".into()),
        }
    };
    touch_last_seen(opened, &proposer.id)?;
    let proposal = loop {
        match hub.next_event(IDLE_TIMEOUT)? {
            Some((_, SessionEvent::Frame(Frame::Ceremony(signed)))) => {
                signed.verify(&proposer.identity_pub_hex).map_err(|e| {
                    format!(
                        "{} sent a message that fails verification: {e}",
                        proposer.id
                    )
                })?;
                if signed.msg.round != PROPOSAL_ROUND {
                    return Err(format!(
                        "{} sent a protocol message before a proposal",
                        proposer.id
                    ));
                }
                if signed.msg.to_device_id.as_deref() != Some(self_id.as_str()) {
                    return Err("proposal addressed to another device".into());
                }
                break Proposal::from_message(&signed.msg)?;
            }
            Some((_, SessionEvent::Relayed(signed))) => {
                return Err(format!(
                    "{} relayed a message from `{}` before a proposal",
                    proposer.id, signed.msg.from_device_id
                ));
            }
            Some((_, SessionEvent::Closed { reason })) => {
                return Err(format!("{} left before proposing: {reason}", proposer.id));
            }
            Some(_) => {}
            None => return Err("connection closed before a proposal".into()),
        }
    };
    let identities = check_proposal(opened, &proposal, &proposer, &self_id).map_err(|e| {
        format!(
            "refusing {} from {}: {e}",
            proposal.kind_name(),
            proposer.id
        )
    })?;
    let session = proposal.session().clone();
    let outcome = audited(
        opened,
        session.id.clone(),
        proposal.sign_request_id(),
        |opened| party_ceremony(opened, hub, conn, &proposal, &identities),
    )?;
    opened.save()?;
    let mut out = serde_json::json!({
        "ceremony": proposal.kind_name(),
        "sessionId": session.id,
        "groupId": session.key_group_id,
        "curve": session.curve,
        "proposer": proposer.id,
    });
    match outcome {
        Outcome::KeyGen(pk) => {
            out["publicKey"] = serde_json::to_value(pk).map_err(|e| e.to_string())?
        }
        Outcome::Sign(sig) => {
            out["signature"] = serde_json::to_value(sig).map_err(|e| e.to_string())?
        }
    }
    Ok(out)
}

fn print_line(v: &serde_json::Value) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{v}").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

pub fn serve(args: &[String]) -> Result<ExitCode, String> {
    let (Some(dir), Ok(Some(listen))) = (args.first(), flag(args, "--listen")) else {
        eprint!("{SERVE_USAGE}");
        return Ok(ExitCode::from(64));
    };
    let listen: SocketAddr = listen
        .parse()
        .map_err(|_| "--listen must be host:port".to_owned())?;
    let once = args.iter().any(|a| a == "--once");
    let no_mdns = args.iter().any(|a| a == "--no-mdns");

    let mut opened = vault_cmd::open(dir)?;
    let listener = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let local = local_device(
        &opened,
        vec![Endpoint::Tcp {
            addr: bound.to_string(),
        }
        .to_string()],
    )?;
    let _advertiser = if no_mdns {
        None
    } else {
        match discovery::advertise(&local, bound.port()) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("warning: not advertising on the LAN: {e}");
                None
            }
        }
    };
    print_line(&serde_json::json!({ "listening": bound.to_string(), "device": local.id }))?;

    loop {
        let (stream, from) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        // Only devices pinned before this connection arrived can complete the
        // handshake; the lookup sees a snapshot so a pairing that lands
        // mid-handshake cannot change the answer.
        let self_id = opened.identity.device_id();
        let known: Vec<Device> = opened
            .store
            .list_devices()
            .map_err(fmt_err)?
            .into_iter()
            .filter(|d| d.revoked_at_ms.is_none() && d.id != self_id)
            .collect();
        let lookup = move |remote: &[u8; 32]| {
            let hex = hex::encode(remote);
            known.iter().find(|d| d.noise_static_hex == hex).cloned()
        };
        let result = Session::connect(
            &opened.identity,
            &local,
            HandshakeRole::Responder,
            None,
            Some(Box::new(lookup)),
            now_ms(),
        )
        .map_err(fmt_err)
        .and_then(|session| {
            let mut hub = Hub::new();
            let conn = hub.add(stream, session)?;
            let out = serve_connection(&mut opened, &mut hub, conn);
            hub.close_all(if out.is_ok() { BYE_COMPLETE } else { "aborted" });
            out
        });
        match result {
            Ok(out) => {
                print_line(&out)?;
                if once {
                    return Ok(ExitCode::SUCCESS);
                }
            }
            Err(e) => {
                eprintln!("error: {from}: {e}");
                if once {
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
    }
}

pub fn run(args: &[String]) -> Result<ExitCode, String> {
    let out = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..])?,
        Some("sign") => sign(&args[1..])?,
        _ => {
            eprint!("{NET_USAGE}");
            return Ok(ExitCode::from(64));
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_parse_with_default_and_explicit_roles() {
        let peers = parse_peers("aaaa,bbbb:agent,cccc").unwrap();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].role, PartyRole::Human);
        assert_eq!(peers[1].role, PartyRole::Agent);
        assert!(parse_peers("aaaa,aaaa").is_err());
        assert!(parse_peers(":human").is_err());
        assert!(parse_peers("").is_err());
    }

    #[test]
    fn addr_overrides_require_a_socket_address() {
        let args: Vec<String> = ["--addr", "dev=127.0.0.1:4701", "--addr", "x=bad"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert!(parse_addr_overrides(&args).is_err());
        let ok = parse_addr_overrides(&args[..2]).unwrap();
        assert_eq!(ok.get("dev").map(String::as_str), Some("127.0.0.1:4701"));
    }

    #[test]
    fn admission_checks_author_signature_session_and_addressing() {
        use stackwallet_core::identity::DeviceIdentity;
        let alice = DeviceIdentity::generate().unwrap();
        let mallory = DeviceIdentity::generate().unwrap();
        let (a, m) = (alice.device_id(), mallory.device_id());
        let session = session_for(
            CeremonyKind::KeyGen,
            "g",
            Curve::Ed25519,
            "ab".repeat(32),
            vec!["self".into(), a.clone(), "bob".into()],
        );
        let identities = BTreeMap::from([(a.clone(), alice.public_hex())]);
        let msg = |from: &str, to: Option<&str>, round: u8, sid: &str| CeremonyMessage {
            session_id: sid.into(),
            payload_hash_hex: "ab".repeat(32),
            from_device_id: from.into(),
            to_device_id: to.map(str::to_owned),
            round,
            body_hex: "00".into(),
        };
        let ok = SignedCeremonyMessage::sign(&alice, msg(&a, None, 1, &session.id));
        assert!(admit(&ok, &session, &identities).is_ok());
        let addressed = SignedCeremonyMessage::sign(&alice, msg(&a, Some("bob"), 2, &session.id));
        assert!(admit(&addressed, &session, &identities).is_ok());

        let unknown = SignedCeremonyMessage::sign(&mallory, msg(&m, None, 1, &session.id));
        assert!(admit(&unknown, &session, &identities)
            .unwrap_err()
            .contains("not a pinned participant"));
        let forged = SignedCeremonyMessage::sign(&mallory, msg(&a, None, 1, &session.id));
        assert!(admit(&forged, &session, &identities)
            .unwrap_err()
            .contains("fails verification"));
        let other = SignedCeremonyMessage::sign(&alice, msg(&a, None, 1, "elsewhere"));
        assert!(admit(&other, &session, &identities)
            .unwrap_err()
            .contains("another session"));
        let proposal = SignedCeremonyMessage::sign(&alice, msg(&a, None, 0, &session.id));
        assert!(admit(&proposal, &session, &identities).is_err());
        let stranger = SignedCeremonyMessage::sign(&alice, msg(&a, Some("eve"), 1, &session.id));
        assert!(admit(&stranger, &session, &identities)
            .unwrap_err()
            .contains("not a participant"));
        let to_self = SignedCeremonyMessage::sign(&alice, msg(&a, Some(&a), 1, &session.id));
        assert!(admit(&to_self, &session, &identities).is_err());
    }

    #[test]
    fn proposal_round_trips_and_checks_its_envelope() {
        let session = session_for(
            CeremonyKind::Sign,
            "g",
            Curve::Ed25519,
            "ab".repeat(32),
            vec!["a".into(), "b".into()],
        );
        let proposal = Proposal::Sign {
            request: SignRequest {
                id: "r".into(),
                tx_id: "t".into(),
                key_group_id: "g".into(),
                curve: Curve::Ed25519,
                payload_hash_hex: "ab".repeat(32),
                payload_hex: "00".into(),
            },
            session,
        };
        let mut msg = proposal.to_message("a", "b").unwrap();
        assert_eq!(msg.round, PROPOSAL_ROUND);
        assert!(Proposal::from_message(&msg).is_ok());
        msg.session_id = "other".into();
        assert!(Proposal::from_message(&msg).is_err());
    }
}
