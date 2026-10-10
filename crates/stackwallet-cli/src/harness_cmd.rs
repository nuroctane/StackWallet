//! `harness keygen|sign|refresh`: run every party of a FROST key group inside
//! this process, persisting shares in the vault and the group in the store.
//!
//! One machine holding every share is only acceptable for development and for
//! exercising the vault, store and audit path end to end; the device-to-device
//! transport replaces the in-process delivery for real wallets. Share labels
//! carry a `harness/` prefix so nothing mistakes them for a single-party share.

use std::process::ExitCode;

use stackwallet_core::audit::{Actor, AuditEvent};
use stackwallet_core::intent::{SignRequest, Signature};
use stackwallet_core::model::{Curve, KeyGroup, PartyRef, PartyRole, PublicKey};
use stackwallet_core::store::KeyGroupRecord;
use stackwallet_core::tss::frost::FrostCurve;
use stackwallet_core::tss::harness::{Delivery, Faithful, LocalHarness, Shuffled};
use stackwallet_core::tss::{CeremonyKind, ShareBlob, ThresholdScheme};
use stackwallet_core::vault::{Secret, Vault};

use crate::vault_cmd::{self, fmt_err, now_ms, Opened};

pub const USAGE: &str = "stackwallet harness <command>

Commands:
  keygen <dir> <group-id> <curve> <threshold> <device:role>...
                               run DKG for every party in-process; curve is ed25519 or
                               secp256k1-tr; role is human, agent or automation
  sign <dir> <group-id> <curve> <signer,signer,...> <payload-hex> [--shuffle <seed>]
                               sign payload-hex with the listed parties; prints the signature
  refresh <dir> <group-id> <curve> [--shuffle <seed>]
                               refresh every party's share; the public key must not change

Shares are stored in the vault as `harness/<group-id>/<curve>/<device>`.
";

pub(crate) const ECDSA_UNAVAILABLE: &str =
    "secp256k1 ECDSA is not available yet: CGGMP24 has no stable release (SPEC 5.1)";

/// Curve names on the command line are the same kebab-case strings the
/// `Curve` enum uses in JSON and in the store.
pub(crate) fn parse_curve(s: &str) -> Result<Curve, String> {
    match serde_json::from_value::<Curve>(serde_json::Value::String(s.to_owned())) {
        Ok(Curve::Secp256k1) => Err(ECDSA_UNAVAILABLE.into()),
        Ok(curve) => Ok(curve),
        Err(_) => Err(format!("unknown curve `{s}`")),
    }
}

pub(crate) fn curve_slug(curve: Curve) -> String {
    match serde_json::to_value(curve) {
        Ok(serde_json::Value::String(s)) => s,
        _ => format!("{curve:?}").to_lowercase(),
    }
}

/// Runs a generic function with the frost ciphersuite that implements `curve`.
macro_rules! with_frost_curve {
    ($curve:expr, $f:ident($($arg:expr),* $(,)?)) => {
        match $curve {
            stackwallet_core::model::Curve::Ed25519 => {
                $f::<stackwallet_core::tss::frost::Ed25519Sha512>($($arg),*)
            }
            stackwallet_core::model::Curve::Secp256k1Tr => {
                $f::<stackwallet_core::tss::frost::Secp256K1Sha256TR>($($arg),*)
            }
            stackwallet_core::model::Curve::Secp256k1 => {
                Err($crate::harness_cmd::ECDSA_UNAVAILABLE.to_owned())
            }
        }
    };
}
pub(crate) use with_frost_curve;

fn parse_party(spec: &str) -> Result<PartyRef, String> {
    let (device, role) = spec
        .split_once(':')
        .ok_or_else(|| format!("party `{spec}` must be device:role"))?;
    let role = match role {
        "human" => PartyRole::Human,
        "agent" => PartyRole::Agent,
        "automation" => PartyRole::Automation,
        other => return Err(format!("unknown role `{other}` in `{spec}`")),
    };
    if device.is_empty() {
        return Err(format!("party `{spec}` has an empty device id"));
    }
    Ok(PartyRef {
        device_id: device.to_owned(),
        role,
    })
}

fn share_label(group_id: &str, curve: Curve, device_id: &str) -> String {
    format!("harness/{group_id}/{}/{device_id}", curve_slug(curve))
}

/// `--shuffle <seed>` swaps faithful in-order delivery for a seeded shuffle,
/// which is how the tests exercise out-of-order rounds.
fn delivery_from_args(args: &[String]) -> Result<Box<dyn Delivery>, String> {
    match args.iter().position(|a| a == "--shuffle") {
        None => Ok(Box::new(Faithful)),
        Some(i) => {
            let seed = args
                .get(i + 1)
                .ok_or("--shuffle needs a seed")?
                .parse::<u64>()
                .map_err(|e| format!("--shuffle seed: {e}"))?;
            Ok(Box::new(Shuffled::new(seed)))
        }
    }
}

pub(crate) fn store_share_at(
    opened: &mut Opened,
    label: &str,
    blob: &ShareBlob,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(blob).map_err(|e| e.to_string())?;
    opened
        .vault
        .put(label, Secret::new(bytes))
        .map(|_| ())
        .map_err(fmt_err)
}

pub(crate) fn load_share_at(opened: &Opened, label: &str) -> Result<ShareBlob, String> {
    let handle = opened
        .vault
        .handle_for(label)
        .ok_or_else(|| format!("no share `{label}` in the vault"))?;
    opened
        .vault
        .with_secret(&handle, &mut |s| {
            serde_json::from_slice::<ShareBlob>(s.expose()).map_err(|e| e.to_string())
        })
        .map_err(fmt_err)?
}

fn store_share(opened: &mut Opened, blob: &ShareBlob) -> Result<(), String> {
    store_share_at(
        opened,
        &share_label(&blob.key_group_id, blob.curve, &blob.device_id),
        blob,
    )
}

fn load_share(
    opened: &Opened,
    group_id: &str,
    curve: Curve,
    device_id: &str,
) -> Result<ShareBlob, String> {
    load_share_at(opened, &share_label(group_id, curve, device_id))
}

pub(crate) fn load_group(opened: &Opened, group_id: &str) -> Result<KeyGroupRecord, String> {
    opened
        .store
        .get_key_group(group_id)
        .map_err(fmt_err)?
        .ok_or_else(|| format!("no key group `{group_id}` in the store"))
}

fn export_all<C: FrostCurve>(opened: &mut Opened, harness: &LocalHarness<C>) -> Result<(), String> {
    for device in harness.device_ids() {
        let blob = harness
            .party(&device)
            .ok_or_else(|| format!("{device} vanished from the harness"))?
            .export_share()
            .map_err(fmt_err)?;
        store_share(opened, &blob)?;
    }
    Ok(())
}

fn harness_with_shares<C: FrostCurve>(
    opened: &Opened,
    group: &KeyGroup,
) -> Result<LocalHarness<C>, String> {
    let mut harness = LocalHarness::<C>::new(group).map_err(fmt_err)?;
    harness.now_ms = now_ms();
    for device in harness.device_ids() {
        let blob = load_share(opened, &group.id, C::CURVE, &device)?;
        harness
            .party_mut(&device)
            .ok_or_else(|| format!("{device} vanished from the harness"))?
            .import_share(&blob)
            .map_err(fmt_err)?;
    }
    Ok(harness)
}

/// Brackets one ceremony with audit rows: `CeremonyStarted` before the first
/// message, then `CeremonyCompleted` or `CeremonyAborted`. The store is saved
/// after an abort so the failure is on record even though nothing else
/// changed.
pub(crate) fn audited<T>(
    opened: &mut Opened,
    session_id: String,
    sign_request_id: Option<String>,
    run: impl FnOnce(&mut Opened) -> Result<T, String>,
) -> Result<T, String> {
    let actor = Actor::Device {
        device_id: opened.identity.device_id(),
    };
    opened
        .store
        .record_audit(
            now_ms(),
            actor.clone(),
            AuditEvent::CeremonyStarted {
                session_id: session_id.clone(),
                sign_request_id,
            },
        )
        .map_err(fmt_err)?;
    match run(opened) {
        Ok(value) => {
            opened
                .store
                .record_audit(
                    now_ms(),
                    actor,
                    AuditEvent::CeremonyCompleted { session_id },
                )
                .map_err(fmt_err)?;
            Ok(value)
        }
        Err(reason) => {
            opened
                .store
                .record_audit(
                    now_ms(),
                    actor,
                    AuditEvent::CeremonyAborted {
                        session_id,
                        reason: reason.clone(),
                    },
                )
                .map_err(fmt_err)?;
            opened.save()?;
            Err(reason)
        }
    }
}

fn keygen_on<C: FrostCurve>(
    opened: &mut Opened,
    group: &mut KeyGroup,
    delivery: &mut dyn Delivery,
) -> Result<PublicKey, String> {
    let mut harness = LocalHarness::<C>::new(group).map_err(fmt_err)?;
    harness.now_ms = now_ms();
    let session_id = harness.next_session_id(CeremonyKind::KeyGen);
    let public_key = audited(opened, session_id, None, |opened| {
        let public_key = harness.keygen(delivery).map_err(fmt_err)?;
        export_all(opened, &harness)?;
        Ok(public_key)
    })?;
    group.public_keys.retain(|k| k.curve != C::CURVE);
    group.public_keys.push(public_key.clone());
    Ok(public_key)
}

fn keygen(args: &[String]) -> Result<serde_json::Value, String> {
    let [dir, group_id, curve, threshold] = [args.first(), args.get(1), args.get(2), args.get(3)]
        .map(|a| a.ok_or("keygen needs <dir> <group-id> <curve> <threshold> <device:role>..."));
    let (dir, group_id, curve, threshold) = (dir?, group_id?, curve?, threshold?);
    let curve = parse_curve(curve)?;
    let threshold: u8 = threshold.parse().map_err(|e| format!("threshold: {e}"))?;
    let parties = args[4..]
        .iter()
        .map(|s| parse_party(s))
        .collect::<Result<Vec<_>, _>>()?;
    if parties.is_empty() {
        return Err("keygen needs at least one device:role party".into());
    }

    let mut opened = vault_cmd::open(dir)?;
    let at = now_ms();
    let mut record = match opened.store.get_key_group(group_id).map_err(fmt_err)? {
        Some(existing) => {
            if existing.group.public_keys.iter().any(|k| k.curve == curve) {
                return Err(format!(
                    "group `{group_id}` already has a {} key; use refresh",
                    curve_slug(curve)
                ));
            }
            if existing.group.parties != parties || existing.group.threshold != threshold {
                return Err(format!(
                    "group `{group_id}` exists with a different party set or threshold"
                ));
            }
            let mut existing = existing;
            if !existing.group.curves.contains(&curve) {
                existing.group.curves.push(curve);
            }
            existing
        }
        None => KeyGroupRecord {
            group: KeyGroup {
                id: group_id.clone(),
                threshold,
                parties,
                curves: vec![curve],
                public_keys: Vec::new(),
            },
            created_at_ms: at,
            refreshed_at_ms: None,
        },
    };
    record.group.validate().map_err(fmt_err)?;

    let mut delivery = Faithful;
    let public_key = with_frost_curve!(
        curve,
        keygen_on(&mut opened, &mut record.group, &mut delivery)
    )?;
    opened.store.upsert_key_group(&record).map_err(fmt_err)?;
    opened.save()?;
    Ok(serde_json::json!({
        "groupId": group_id,
        "threshold": record.group.threshold,
        "parties": record.group.parties,
        "publicKey": public_key,
        "sharesStored": record.group.parties.len(),
    }))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn sign_on<C: FrostCurve>(
    opened: &mut Opened,
    group: &KeyGroup,
    signers: &[&str],
    request: &SignRequest,
    delivery: &mut dyn Delivery,
) -> Result<Signature, String> {
    let mut harness = harness_with_shares::<C>(opened, group)?;
    let session_id = harness.next_session_id(CeremonyKind::Sign);
    audited(opened, session_id, Some(request.id.clone()), |_| {
        harness.sign(signers, request, delivery).map_err(fmt_err)
    })
}

fn sign(args: &[String]) -> Result<serde_json::Value, String> {
    let [dir, group_id, curve, signers, payload] = [
        args.first(),
        args.get(1),
        args.get(2),
        args.get(3),
        args.get(4),
    ]
    .map(|a| a.ok_or("sign needs <dir> <group-id> <curve> <signer,...> <payload-hex>"));
    let (dir, group_id, curve, signers, payload) = (dir?, group_id?, curve?, signers?, payload?);
    let curve = parse_curve(curve)?;
    let signers: Vec<&str> = signers.split(',').filter(|s| !s.is_empty()).collect();
    let payload_bytes = hex::decode(payload).map_err(|_| "payload must be hex".to_owned())?;
    if payload_bytes.is_empty() {
        return Err("payload is empty".into());
    }
    let mut delivery = delivery_from_args(&args[5..])?;

    let mut opened = vault_cmd::open(dir)?;
    let record = load_group(&opened, group_id)?;
    let at = now_ms();
    let request = SignRequest {
        id: format!("harness-sign-{at}"),
        tx_id: format!("harness-tx-{at}"),
        key_group_id: group_id.clone(),
        curve,
        payload_hash_hex: sha256_hex(&payload_bytes),
        payload_hex: payload.to_lowercase(),
    };
    let signature = with_frost_curve!(
        curve,
        sign_on(
            &mut opened,
            &record.group,
            &signers,
            &request,
            delivery.as_mut()
        )
    )?;
    opened.save()?;
    let public_key = record
        .group
        .public_keys
        .iter()
        .find(|k| k.curve == curve)
        .cloned();
    Ok(serde_json::json!({
        "groupId": group_id,
        "signers": signers,
        "request": request,
        "publicKey": public_key,
        "signature": signature,
    }))
}

fn refresh_on<C: FrostCurve>(
    opened: &mut Opened,
    group: &KeyGroup,
    expected: &PublicKey,
    delivery: &mut dyn Delivery,
) -> Result<PublicKey, String> {
    let mut harness = harness_with_shares::<C>(opened, group)?;
    let session_id = harness.next_session_id(CeremonyKind::Refresh);
    audited(opened, session_id, None, |opened| {
        let public_key = harness.refresh(delivery).map_err(fmt_err)?;
        if &public_key != expected {
            return Err(format!(
                "refresh changed the public key ({} -> {}); shares were not saved",
                expected.hex, public_key.hex
            ));
        }
        export_all(opened, &harness)?;
        Ok(public_key)
    })
}

fn refresh(args: &[String]) -> Result<serde_json::Value, String> {
    let [dir, group_id, curve] = [args.first(), args.get(1), args.get(2)]
        .map(|a| a.ok_or("refresh needs <dir> <group-id> <curve>"));
    let (dir, group_id, curve) = (dir?, group_id?, curve?);
    let curve = parse_curve(curve)?;
    let mut delivery = delivery_from_args(&args[3..])?;

    let mut opened = vault_cmd::open(dir)?;
    let mut record = load_group(&opened, group_id)?;
    let before = record
        .group
        .public_keys
        .iter()
        .find(|k| k.curve == curve)
        .cloned()
        .ok_or_else(|| format!("group `{group_id}` has no {} key yet", curve_slug(curve)))?;
    let group = record.group.clone();
    let after = with_frost_curve!(
        curve,
        refresh_on(&mut opened, &group, &before, delivery.as_mut())
    )?;
    record.refreshed_at_ms = Some(now_ms());
    opened.store.upsert_key_group(&record).map_err(fmt_err)?;
    opened.save()?;
    Ok(serde_json::json!({
        "groupId": group_id,
        "publicKey": after,
        "refreshedAtMs": record.refreshed_at_ms,
    }))
}

pub fn run(args: &[String]) -> Result<ExitCode, String> {
    let out = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..])?,
        Some("sign") => sign(&args[1..])?,
        Some("refresh") => refresh(&args[1..])?,
        _ => {
            eprint!("{USAGE}");
            return Ok(ExitCode::from(64));
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}
