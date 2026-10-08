//! Encrypted storage for shares, seeds, device identity and provider keys.
//!
//! Phase 1 implements this with XChaCha20-Poly1305 for data and Argon2id for
//! wrapping the data encryption key (see `docs/SECURITY.md` §4). Phase 0 fixes
//! the shape so the rest of the core can be written against it.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CoreError, Result};

/// Secret bytes that are wiped when dropped. The only container secrets may
/// live in outside the vault's own ciphertext.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

/// Opaque reference to a secret inside the vault. Handles cross the FFI
/// boundary; bytes never do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretHandle(pub String);

/// How the data encryption key may be unwrapped. Share material always requires
/// at least the passphrase factor; platform unlock alone is never sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockFactor {
    Passphrase,
    PlatformKey,
}

pub trait Vault {
    fn is_unlocked(&self) -> bool;
    fn unlock(&mut self, passphrase: &Secret) -> Result<()>;
    fn lock(&mut self);
    fn put(&mut self, label: &str, secret: Secret) -> Result<SecretHandle>;
    fn with_secret<T>(&self, handle: &SecretHandle, f: &mut dyn FnMut(&Secret) -> T) -> Result<T>;
    fn delete(&mut self, handle: &SecretHandle) -> Result<()>;
}

/// Placeholder until Phase 1. Every call fails closed.
#[derive(Debug, Default)]
pub struct UnimplementedVault;

impl Vault for UnimplementedVault {
    fn is_unlocked(&self) -> bool {
        false
    }
    fn unlock(&mut self, _passphrase: &Secret) -> Result<()> {
        Err(CoreError::NotYet {
            phase: "Phase 1",
            what: "vault unlock",
        })
    }
    fn lock(&mut self) {}
    fn put(&mut self, _label: &str, _secret: Secret) -> Result<SecretHandle> {
        Err(CoreError::NotYet {
            phase: "Phase 1",
            what: "vault put",
        })
    }
    fn with_secret<T>(&self, _h: &SecretHandle, _f: &mut dyn FnMut(&Secret) -> T) -> Result<T> {
        Err(CoreError::NotYet {
            phase: "Phase 1",
            what: "vault read",
        })
    }
    fn delete(&mut self, _h: &SecretHandle) -> Result<()> {
        Err(CoreError::NotYet {
            phase: "Phase 1",
            what: "vault delete",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_does_not_leak() {
        let s = Secret::new(b"hunter2".to_vec());
        assert_eq!(format!("{s:?}"), "Secret(<7 bytes>)");
    }

    #[test]
    fn unimplemented_vault_fails_closed() {
        let mut v = UnimplementedVault;
        assert!(!v.is_unlocked());
        assert!(v.unlock(&Secret::new(vec![])).is_err());
    }
}
