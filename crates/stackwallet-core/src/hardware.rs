//! Hardware signers (a Ledger over WebHID or HID). The device holds the key;
//! the core holds the rules. An account is registered once with the address
//! the device showed for a path, so proposals can be checked against it, and
//! a device signature is accepted only when it recovers to that address over
//! the sighash the core computed from its own serialization of the
//! transaction it already checked against the intent.

use serde::{Deserialize, Serialize};

use crate::evm;
use crate::vault::{EncryptedVault, Secret, SessionProof, Vault};
use crate::{CoreError, Result};

const PREFIX: &str = "hardware:";
const MAX_PATH: usize = 64;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "hardware signer",
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareAccount {
    pub wallet_id: String,
    pub path: String,
    /// Checksummed EVM address the device reported for `path`.
    pub address: String,
}

fn label(wallet_id: &str, path: &str) -> Result<String> {
    if wallet_id.is_empty()
        || wallet_id.len() > 128
        || path.len() > MAX_PATH
        || !path.starts_with("m/")
        || wallet_id.chars().chain(path.chars()).any(char::is_control)
    {
        return Err(invalid("bad wallet id or path"));
    }
    Ok(format!("{PREFIX}{wallet_id}:{path}"))
}

/// Seal one device account. A fresh session proof is required so a page
/// cannot quietly point an existing wallet at another address.
pub fn register(
    vault: &mut EncryptedVault,
    session: &SessionProof,
    wallet_id: &str,
    path: &str,
    address: &str,
) -> Result<HardwareAccount> {
    vault.verify_session(session, true)?;
    let parsed = evm::parse_address(address)?;
    let account = HardwareAccount {
        wallet_id: wallet_id.into(),
        path: path.into(),
        address: evm::checksum_address(&parsed),
    };
    let l = label(wallet_id, path)?;
    if let Some(existing) = lookup(vault, wallet_id, path)? {
        if existing.address != account.address {
            return Err(invalid(
                "this path is already registered with another address",
            ));
        }
        return Ok(existing);
    }
    let bytes = serde_json::to_vec(&account).map_err(|e| invalid(e.to_string()))?;
    vault.put(&l, Secret::new(bytes))?;
    Ok(account)
}

pub fn lookup(
    vault: &EncryptedVault,
    wallet_id: &str,
    path: &str,
) -> Result<Option<HardwareAccount>> {
    let Some(handle) = vault.handle_for(&label(wallet_id, path)?) else {
        return Ok(None);
    };
    let account = vault.with_secret(&handle, &mut |b| {
        serde_json::from_slice::<HardwareAccount>(b.expose()).map_err(|_| invalid("unreadable"))
    })??;
    Ok(Some(account))
}

/// Address that signs `sighash` with (y parity, r, s); refuses high-S.
pub fn recover_evm(sighash: &[u8; 32], y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Result<String> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    let sig = Signature::from_slice(&rs).map_err(|_| invalid("malformed signature"))?;
    if sig.normalize_s().is_some() {
        return Err(invalid("high-S signature"));
    }
    let id = RecoveryId::from_byte(y_parity & 1).ok_or_else(|| invalid("bad recovery id"))?;
    let key = VerifyingKey::recover_from_prehash(sighash, &sig, id)
        .map_err(|_| invalid("signature does not recover"))?;
    Ok(evm::checksum_address(&evm::address_from_public(
        key.to_encoded_point(false).as_bytes(),
    )?))
}
