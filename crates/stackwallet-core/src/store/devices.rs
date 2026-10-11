//! The pinned device table as a vault record. Until the encrypted SQLite
//! store is wired on every target, the table of paired peers is sealed in
//! the vault under one label, so it carries the vault's integrity: an edit
//! from outside the core fails to open rather than silently adding a peer.
//! The core validates the table on every read and write; a UI cache (the
//! browser's localStorage) is only ever a copy of what came out of here.

use std::collections::HashSet;

use crate::identity::device_id_from_public_hex;
use crate::vault::{EncryptedVault, Secret, Vault};
use crate::{CoreError, Result};

use super::Device;

/// Vault label the table lives under.
pub const DEVICE_TABLE_LABEL: &str = "device-table";
/// Generous for a personal device set, small enough to bound the JSON blob.
pub const MAX_DEVICES: usize = 256;
pub const MAX_DEVICE_NAME_CHARS: usize = 64;
const X25519_HEX_LEN: usize = 64;

fn invalid(reason: String) -> CoreError {
    CoreError::Invalid {
        what: "device table",
        reason,
    }
}

/// Refuse a table the session layer could not trust: every id must be the
/// derivation of its identity key, every Noise static must be a 32-byte hex
/// string, names must be present and bounded, ids unique, count bounded.
pub fn validate_device_table(devices: &[Device]) -> Result<()> {
    if devices.len() > MAX_DEVICES {
        return Err(invalid(format!("more than {MAX_DEVICES} devices")));
    }
    let mut seen = HashSet::with_capacity(devices.len());
    for d in devices {
        if d.name.trim().is_empty() || d.name.chars().count() > MAX_DEVICE_NAME_CHARS {
            return Err(invalid(format!("device {} has a bad name", d.id)));
        }
        let expected = device_id_from_public_hex(&d.identity_pub_hex)
            .map_err(|e| invalid(format!("device {}: {e}", d.id)))?;
        if expected != d.id {
            return Err(invalid(format!(
                "device {} does not match its identity key",
                d.id
            )));
        }
        if d.noise_static_hex.len() != X25519_HEX_LEN
            || !d.noise_static_hex.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(invalid(format!("device {} has a bad Noise static", d.id)));
        }
        if d.paired_at_ms < 0 {
            return Err(invalid(format!("device {} has a negative pairedAt", d.id)));
        }
        if !seen.insert(d.id.as_str()) {
            return Err(invalid(format!("device {} appears twice", d.id)));
        }
    }
    Ok(())
}

/// The validated table, or empty when nothing has been pinned yet.
pub fn load_device_table(vault: &EncryptedVault) -> Result<Vec<Device>> {
    let Some(handle) = vault.handle_for(DEVICE_TABLE_LABEL) else {
        return Ok(Vec::new());
    };
    let parsed = vault.with_secret(&handle, &mut |bytes| {
        serde_json::from_slice::<Vec<Device>>(bytes.expose())
            .map_err(|e| invalid(format!("unreadable: {e}")))
    })??;
    validate_device_table(&parsed)?;
    Ok(parsed)
}

/// Validate, then seal the whole table. Writes are whole-table so a partial
/// update can never leave a device half-pinned.
pub fn save_device_table(vault: &mut EncryptedVault, devices: &[Device]) -> Result<()> {
    validate_device_table(devices)?;
    let bytes = serde_json::to_vec(devices).map_err(|e| invalid(e.to_string()))?;
    vault.put(DEVICE_TABLE_LABEL, Secret::new(bytes))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::store::DeviceKind;
    use crate::vault::KdfParams;

    fn device(name: &str) -> Device {
        let id = DeviceIdentity::generate().unwrap();
        Device {
            id: id.device_id(),
            name: name.into(),
            kind: DeviceKind::Browser,
            identity_pub_hex: id.public_hex(),
            noise_static_hex: id.noise_static_public_hex(),
            endpoints: vec![],
            paired_at_ms: 1,
            last_seen_at_ms: None,
            revoked_at_ms: None,
        }
    }

    fn vault() -> EncryptedVault {
        EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap()
    }

    #[test]
    fn empty_until_saved_then_round_trips() {
        let mut v = vault();
        assert!(load_device_table(&v).unwrap().is_empty());
        let table = vec![device("a"), device("b")];
        save_device_table(&mut v, &table).unwrap();
        assert_eq!(load_device_table(&v).unwrap(), table);
        // Re-saving keeps one record under the label.
        save_device_table(&mut v, &table[..1]).unwrap();
        assert_eq!(load_device_table(&v).unwrap(), table[..1]);
        assert_eq!(v.labels().len(), 1);
    }

    #[test]
    fn refuses_forged_id_and_duplicates() {
        let mut forged = device("x");
        forged.id = "00".repeat(16);
        assert!(validate_device_table(&[forged]).is_err());
        let d = device("y");
        assert!(validate_device_table(&[d.clone(), d]).is_err());
        let mut bad_static = device("z");
        bad_static.noise_static_hex = "zz".repeat(32);
        assert!(validate_device_table(&[bad_static]).is_err());
        let mut nameless = device("w");
        nameless.name = "  ".into();
        assert!(validate_device_table(&[nameless]).is_err());
    }

    #[test]
    fn tampered_record_does_not_load() {
        let mut v = vault();
        save_device_table(&mut v, &[device("a")]).unwrap();
        // A record that parses but fails validation is refused on load.
        let mut forged = device("evil");
        forged.id = "11".repeat(16);
        v.put(
            DEVICE_TABLE_LABEL,
            Secret::new(serde_json::to_vec(&[forged]).unwrap()),
        )
        .unwrap();
        assert!(load_device_table(&v).is_err());
    }

    #[test]
    fn locked_vault_refuses() {
        let mut v = vault();
        save_device_table(&mut v, &[device("a")]).unwrap();
        v.lock();
        assert!(matches!(load_device_table(&v), Err(CoreError::Locked)));
        assert!(matches!(
            save_device_table(&mut v, &[device("b")]),
            Err(CoreError::Locked)
        ));
    }
}
