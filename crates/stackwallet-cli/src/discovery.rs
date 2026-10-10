//! LAN discovery over mDNS, as a hint only.
//!
//! A `serve` process advertises its device id with its public keys in TXT
//! records; an initiator browses to turn a pinned device id into `ip:port`.
//! Nothing learned here is ever pinned: the device table is the only source
//! of trust, the IK handshake still has to succeed against the pinned static,
//! and a record whose keys disagree with the pinned ones is simply skipped.
//! Any failure degrades to "not found" so an explicit address still works
//! on networks that filter multicast.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use stackwallet_core::store::Device;
use stackwallet_core::transport::{MDNS_SERVICE_TYPE, TRANSPORT_VERSION};

/// A registered advertisement; dropping it withdraws the record.
pub struct Advertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

pub fn advertise(local: &Device, port: u16) -> Result<Advertiser, String> {
    let daemon = ServiceDaemon::new().map_err(|e| format!("mdns: {e}"))?;
    let props = HashMap::from([
        ("identity".to_owned(), local.identity_pub_hex.clone()),
        ("noise".to_owned(), local.noise_static_hex.clone()),
        ("v".to_owned(), TRANSPORT_VERSION.to_string()),
    ]);
    let info = ServiceInfo::new(
        MDNS_SERVICE_TYPE,
        &local.id,
        &format!("{}.local.", local.id),
        "",
        port,
        props,
    )
    .map_err(|e| format!("mdns: {e}"))?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_owned();
    daemon.register(info).map_err(|e| format!("mdns: {e}"))?;
    Ok(Advertiser { daemon, fullname })
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        if let Ok(rx) = self.daemon.unregister(&self.fullname) {
            let _ = rx.recv_timeout(Duration::from_millis(500));
        }
        let _ = self.daemon.shutdown();
    }
}

/// Addresses currently advertised for `device`, best first, or empty when
/// nothing answered within `timeout`.
pub fn resolve(device: &Device, timeout: Duration) -> Vec<SocketAddr> {
    let Ok(daemon) = ServiceDaemon::new() else {
        return Vec::new();
    };
    let Ok(rx) = daemon.browse(MDNS_SERVICE_TYPE) else {
        return Vec::new();
    };
    let wanted = format!("{}.{MDNS_SERVICE_TYPE}", device.id);
    let deadline = Instant::now() + timeout;
    let mut found = Vec::new();
    while found.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if info.get_fullname() != wanted {
                    continue;
                }
                if info.get_property_val_str("identity") != Some(device.identity_pub_hex.as_str())
                    || info.get_property_val_str("noise") != Some(device.noise_static_hex.as_str())
                {
                    continue;
                }
                let port = info.get_port();
                let mut ips: Vec<IpAddr> = info
                    .get_addresses()
                    .iter()
                    .map(|a| a.to_ip_addr())
                    .collect();
                // IPv4 first: link-local IPv6 needs a scope id to connect to.
                ips.sort_by_key(|ip| (!ip.is_ipv4(), ip.is_loopback()));
                found.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.stop_browse(MDNS_SERVICE_TYPE);
    let _ = daemon.shutdown();
    found
}
