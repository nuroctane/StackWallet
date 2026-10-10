//! `pair offer` / `pair accept` / `devices`: introducing two devices once.
//!
//! The issuer prints a one-time offer and waits for exactly one connection;
//! the scanner pastes the offer and connects. Both run the core's pairing
//! session over the TCP carrier and pin whatever `Paired` hands them. The
//! offer is spent by the first attempt, successful or not, so a wrong code
//! never gets a second try against the same listener.

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use stackwallet_core::audit::{Actor, AuditEvent};
use stackwallet_core::store::{Device, DeviceKind};
use stackwallet_core::transport::{
    Endpoint, PairingOffer, Session, SessionEvent, TRANSPORT_VERSION,
};

use crate::net::{self, Hub, IDLE_TIMEOUT};
use crate::vault_cmd::{self, fmt_err, now_ms, Opened};

pub const USAGE: &str = "stackwallet pair <command>

Commands:
  offer <dir> [--listen host:port] [--ttl-secs n]
                               print a one-time pairing offer, wait for one peer to
                               connect, pin it; --listen defaults to 127.0.0.1:0 and
                               should be the address this device will later `serve` on
  accept <dir> <offer> [--listen host:port]
                               connect to the device that printed <offer> and pin it;
                               --listen is the address this device will `serve` on,
                               recorded on the peer

The offer is spent by the first connection attempt, successful or not.
";

const DEFAULT_TTL_SECS: u64 = 120;

/// This device as the core wants to see it, with the endpoints it is
/// willing to tell the peer about.
pub(crate) fn local_device(opened: &Opened, endpoints: Vec<String>) -> Result<Device, String> {
    let id = opened.identity.device_id();
    let mut device = opened
        .store
        .get_device(&id)
        .map_err(fmt_err)?
        .ok_or_else(|| format!("the store has no row for this device ({id})"))?;
    device.identity_pub_hex = opened.identity.public_hex();
    device.noise_static_hex = opened.identity.noise_static_public_hex();
    device.endpoints = endpoints;
    Ok(device)
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

fn parse_socket_addr(s: &str) -> Result<SocketAddr, String> {
    s.parse().map_err(|_| format!("`{s}` is not host:port"))
}

/// The address a peer on the LAN should dial when we bound a wildcard. A UDP
/// `connect` only picks a route; no packet leaves the machine.
fn routable_ip() -> Option<IpAddr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    probe.local_addr().ok().map(|a| a.ip())
}

fn advertised(bound: SocketAddr) -> SocketAddr {
    if bound.ip().is_unspecified() {
        if let Some(ip) = routable_ip() {
            return SocketAddr::new(ip, bound.port());
        }
    }
    bound
}

/// Wait for one connection, giving up when the offer expires.
fn accept_until(listener: &TcpListener, expires_at_ms: i64) -> Result<TcpStream, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if now_ms() >= expires_at_ms {
                    return Err("pairing offer expired before anyone connected".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("accept: {e}")),
        }
    }
}

/// Replace wildcard hosts in the peer's declared endpoints with the address
/// it actually connected from; a peer that declared nothing stays
/// unreachable until it pairs again with a `--listen`.
fn concretise_endpoints(declared: &[String], from: IpAddr) -> Vec<String> {
    declared
        .iter()
        .filter_map(|e| {
            let endpoint = Endpoint::parse(e)?;
            Some(match endpoint {
                Endpoint::Tcp { addr } => match addr.parse::<SocketAddr>() {
                    Ok(sa) if sa.ip().is_unspecified() && sa.port() != 0 => Endpoint::Tcp {
                        addr: SocketAddr::new(from, sa.port()).to_string(),
                    },
                    Ok(sa) if sa.port() == 0 => return None,
                    _ => Endpoint::Tcp { addr },
                },
                other => other,
            })
        })
        .map(|e| e.to_string())
        .collect()
}

fn pin_peer(opened: &mut Opened, mut peer: Device) -> Result<serde_json::Value, String> {
    let at = now_ms();
    if let Some(existing) = opened.store.get_device(&peer.id).map_err(fmt_err)? {
        peer.paired_at_ms = existing.paired_at_ms;
    }
    if peer.paired_at_ms == 0 {
        peer.paired_at_ms = at;
    }
    peer.last_seen_at_ms = Some(at);
    peer.revoked_at_ms = None;
    opened.store.upsert_device(&peer).map_err(fmt_err)?;
    opened
        .store
        .record_audit(
            at,
            Actor::Device {
                device_id: opened.identity.device_id(),
            },
            AuditEvent::DevicePaired {
                device_id: peer.id.clone(),
            },
        )
        .map_err(fmt_err)?;
    opened.save()?;
    Ok(serde_json::json!({
        "paired": {
            "id": peer.id,
            "name": peer.name,
            "kind": peer.kind,
            "identityPubHex": peer.identity_pub_hex,
            "endpoints": peer.endpoints,
        }
    }))
}

/// Drive one pairing session to `Paired` or failure.
fn run_pairing(hub: &mut Hub, expires_at_ms: i64) -> Result<Device, String> {
    loop {
        let remaining = (expires_at_ms - now_ms()).max(0) as u64;
        let timeout = IDLE_TIMEOUT.min(Duration::from_millis(remaining.max(1)));
        match hub.next_event(timeout)? {
            Some((_, SessionEvent::Paired { peer })) => return Ok(peer),
            Some((_, SessionEvent::Closed { reason })) => {
                return Err(format!("pairing failed: {reason}"))
            }
            Some(_) => {}
            None => return Err("pairing failed: connection closed".into()),
        }
    }
}

fn offer(args: &[String]) -> Result<serde_json::Value, String> {
    let dir = args.first().ok_or("pair offer needs a vault directory")?;
    let listen = parse_socket_addr(flag(args, "--listen")?.unwrap_or("127.0.0.1:0"))?;
    let ttl_secs: u64 = match flag(args, "--ttl-secs")? {
        Some(s) => s.parse().map_err(|e| format!("--ttl-secs: {e}"))?,
        None => DEFAULT_TTL_SECS,
    };
    if ttl_secs == 0 {
        return Err("--ttl-secs must be at least 1".into());
    }

    let mut opened = vault_cmd::open(dir)?;
    let listener = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let endpoint = Endpoint::Tcp {
        addr: advertised(bound).to_string(),
    }
    .to_string();
    let local = local_device(&opened, vec![endpoint.clone()])?;
    let offer = PairingOffer {
        version: TRANSPORT_VERSION,
        device_id: local.id.clone(),
        device_name: local.name.clone(),
        kind: DeviceKind::Cli,
        identity_pub_hex: local.identity_pub_hex.clone(),
        noise_static_hex: local.noise_static_hex.clone(),
        endpoints: vec![endpoint],
        one_time_code_hex: PairingOffer::new_code().map_err(fmt_err)?,
        expires_at_ms: now_ms() + (ttl_secs as i64) * 1000,
    };
    offer.validate().map_err(fmt_err)?;

    // The offer is the first and only thing on stdout until pairing ends so
    // a wrapper can read one line and hand it to the other device.
    {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{}", offer.encode()).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
    }
    eprintln!("listening on {bound} for {ttl_secs}s");

    // A failed handshake (wrong code, prober who saw the QR late) must not
    // burn the offer for the legitimate scanner, so keep listening; the code
    // stays guess-proof and a bounded number of failures aborts the offer.
    const MAX_FAILED_ATTEMPTS: u32 = 5;
    let mut failed = 0u32;
    let peer = loop {
        if failed >= MAX_FAILED_ATTEMPTS {
            return Err(format!(
                "pairing aborted after {MAX_FAILED_ATTEMPTS} failed attempts"
            ));
        }
        let stream = accept_until(&listener, offer.expires_at_ms)?;
        let from = stream.peer_addr().map_err(|e| e.to_string())?.ip();
        // Built after accept so the session's own freshness check sees the
        // moment the peer actually arrived, not the moment the offer was printed.
        let session =
            Session::pair_as_issuer(&opened.identity, &local, &offer, now_ms()).map_err(fmt_err)?;
        let mut hub = Hub::new();
        hub.add(stream, session)?;
        match run_pairing(&mut hub, offer.expires_at_ms) {
            Ok(mut peer) => {
                peer.endpoints = concretise_endpoints(&peer.endpoints, from);
                hub.close_all("paired");
                break peer;
            }
            Err(e) => {
                failed += 1;
                eprintln!("pairing attempt {failed}/{MAX_FAILED_ATTEMPTS} failed: {e}");
            }
        }
    };
    drop(listener);
    let result = pin_peer(&mut opened, peer)?;
    Ok(result)
}

fn accept(args: &[String]) -> Result<serde_json::Value, String> {
    let dir = args.first().ok_or("pair accept needs a vault directory")?;
    let text = args.get(1).ok_or("pair accept needs the offer string")?;
    let listen = flag(args, "--listen")?.map(parse_socket_addr).transpose()?;
    let offer = PairingOffer::decode(text).map_err(fmt_err)?;
    if offer.is_expired(now_ms()) {
        return Err("pairing offer has expired".into());
    }
    let targets: Vec<String> = offer
        .endpoints
        .iter()
        .filter_map(|e| match Endpoint::parse(e)? {
            Endpoint::Tcp { addr } => Some(addr),
            Endpoint::WebRtc { .. } => None,
        })
        .collect();
    if targets.is_empty() {
        return Err("offer has no tcp:// endpoint to connect to".into());
    }

    let mut opened = vault_cmd::open(dir)?;
    if offer.device_id == opened.identity.device_id() {
        return Err("that offer was issued by this very device".into());
    }
    let endpoints = listen
        .map(|l| {
            vec![Endpoint::Tcp {
                addr: l.to_string(),
            }
            .to_string()]
        })
        .unwrap_or_default();
    let local = local_device(&opened, endpoints)?;
    let stream = net::connect_with_retry(&targets, Duration::from_secs(5))?;
    let session =
        Session::pair_as_scanner(&opened.identity, &local, &offer, now_ms()).map_err(fmt_err)?;
    let mut hub = Hub::new();
    hub.add(stream, session)?;
    let peer = run_pairing(&mut hub, offer.expires_at_ms)?;
    let result = pin_peer(&mut opened, peer)?;
    hub.close_all("paired");
    Ok(result)
}

pub fn devices(args: &[String]) -> Result<ExitCode, String> {
    let dir = args.first().ok_or("devices needs a vault directory")?;
    let opened = vault_cmd::open(dir)?;
    let own = opened.identity.device_id();
    let rows: Vec<serde_json::Value> = opened
        .store
        .list_devices()
        .map_err(fmt_err)?
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "id": d.id,
                "name": d.name,
                "kind": d.kind,
                "self": d.id == own,
                "identityPubHex": d.identity_pub_hex,
                "noiseStaticHex": d.noise_static_hex,
                "endpoints": d.endpoints,
                "pairedAtMs": d.paired_at_ms,
                "lastSeenAtMs": d.last_seen_at_ms,
                "revokedAtMs": d.revoked_at_ms,
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}

pub fn run(args: &[String]) -> Result<ExitCode, String> {
    let out = match args.first().map(String::as_str) {
        Some("offer") => offer(&args[1..])?,
        Some("accept") => accept(&args[1..])?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_endpoints_take_the_connecting_address() {
        let from: IpAddr = "10.1.2.3".parse().unwrap();
        let declared = vec![
            "tcp://0.0.0.0:4701".to_owned(),
            "tcp://192.168.1.9:4702".to_owned(),
            "tcp://0.0.0.0:0".to_owned(),
            "webrtc-via://abcd".to_owned(),
            "bogus".to_owned(),
        ];
        assert_eq!(
            concretise_endpoints(&declared, from),
            vec![
                "tcp://10.1.2.3:4701",
                "tcp://192.168.1.9:4702",
                "webrtc-via://abcd"
            ]
        );
    }
}
