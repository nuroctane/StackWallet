//! Vault support gate: zeroization, checked by inspecting memory.
//!
//! This test binary's global allocator looks at every heap block as it goes
//! back to the allocator (including the old block a `realloc` moves away
//! from) and searches it for canaries: a passphrase, a sealed secret, a
//! recovery phrase, and the seed and private key derived from it, raw and
//! hex-encoded. A hit means a copy of key material was freed without being
//! wiped first, where any later allocation could read it back.
//!
//! The harness sees heap blocks only; stack copies and registers are outside
//! what it can check.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use stackwallet_core::hd::{self, Mnemonic};
use stackwallet_core::message::{self, MessageKind, MessageRequest};
use stackwallet_core::model::Curve;
use stackwallet_core::provenance;
use stackwallet_core::vault::{EncryptedVault, KdfParams, Secret, SessionProof, Vault};

const PASSPHRASE: &[u8] = b"zq9-canary-passphrase-7f3e2b1a0c9d";
const NEW_PASSPHRASE: &[u8] = b"zq9-canary-rotated-passphrase-55aa";
const SECRET: [u8; 32] = [
    0xC3, 0x5A, 0x91, 0x0E, 0x7D, 0x22, 0xB4, 0x6F, 0x18, 0xE9, 0x3C, 0xA7, 0x50, 0x0B, 0xD6, 0x8E,
    0x41, 0xF2, 0x2D, 0x99, 0x6A, 0xC0, 0x37, 0x85, 0x1E, 0xBB, 0x04, 0x73, 0xDA, 0x5C, 0x29, 0xF8,
];
/// BIP39 test vector; only ever written into the vault by the test below.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PHRASE_NEEDLE: &[u8] = b"sausage worth useful";
const PATH: &str = "m/44'/60'/0'/0/0";

/// Derived material, filled in before the allocator is armed.
struct Derived {
    seed: UnsafeCell<[u8; 64]>,
    key: UnsafeCell<[u8; 32]>,
    key_hex: UnsafeCell<[u8; 64]>,
    secret_hex: UnsafeCell<[u8; 64]>,
}
// Written once while unarmed and single-threaded, only read afterwards.
unsafe impl Sync for Derived {}
static DERIVED: Derived = Derived {
    seed: UnsafeCell::new([0; 64]),
    key: UnsafeCell::new([0; 32]),
    key_hex: UnsafeCell::new([0; 64]),
    secret_hex: UnsafeCell::new([0; 64]),
};

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static LAST_NEEDLE: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_SIZE: AtomicUsize = AtomicUsize::new(0);

const NEEDLE_NAMES: [&str; 8] = [
    "passphrase",
    "rotated passphrase",
    "sealed secret",
    "sealed secret (hex)",
    "recovery phrase",
    "seed",
    "private key",
    "private key (hex)",
];

fn needles() -> [&'static [u8]; 8] {
    // SAFETY: only read after `DERIVED` was written, before arming.
    unsafe {
        [
            PASSPHRASE,
            NEW_PASSPHRASE,
            &SECRET,
            &*DERIVED.secret_hex.get(),
            PHRASE_NEEDLE,
            &*DERIVED.seed.get(),
            &*DERIVED.key.get(),
            &*DERIVED.key_hex.get(),
        ]
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    // Matching a long needle by its first 16 bytes still catches a partial
    // copy while keeping a 19 MiB Argon2 block quick to scan.
    let needle = &needle[..needle.len().min(16)];
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn inspect(ptr: *mut u8, size: usize) {
    if !ARMED.load(Ordering::Relaxed) || size == 0 {
        return;
    }
    // SAFETY: the allocator still owns this block; it is being freed.
    let block = unsafe { std::slice::from_raw_parts(ptr, size) };
    for (i, n) in needles().iter().enumerate() {
        if contains(block, n) {
            HITS.fetch_add(1, Ordering::Relaxed);
            LAST_NEEDLE.store(i, Ordering::Relaxed);
            LAST_SIZE.store(size, Ordering::Relaxed);
        }
    }
}

struct Inspecting;

unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        inspect(ptr, layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    /// Always moves, so the abandoned block goes through `dealloc` and is
    /// inspected: a growing buffer that held a secret leaves a copy behind
    /// whenever the system allocator moves it.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new = unsafe { System.alloc(new_layout) };
        if !new.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new
    }
}

#[global_allocator]
static GLOBAL: Inspecting = Inspecting;

/// How many freed blocks held a canary while `f` ran.
fn hits_during(f: impl FnOnce()) -> usize {
    HITS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    HITS.load(Ordering::Relaxed)
}

/// Run `f` with the allocator armed; any freed block holding a canary fails.
fn armed<T>(phase: &str, f: impl FnOnce() -> T) -> T {
    HITS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::SeqCst);
    let out = f();
    ARMED.store(false, Ordering::SeqCst);
    let hits = HITS.load(Ordering::Relaxed);
    let which = LAST_NEEDLE.load(Ordering::Relaxed);
    assert_eq!(
        hits,
        0,
        "{phase}: {hits} freed block(s) still held key material, last a {}-byte block with the {}",
        LAST_SIZE.load(Ordering::Relaxed),
        NEEDLE_NAMES.get(which).unwrap_or(&"?"),
    );
    out
}

fn hex_into(src: &[u8], dst: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in src.iter().enumerate() {
        dst[2 * i] = DIGITS[(b >> 4) as usize];
        dst[2 * i + 1] = DIGITS[(b & 15) as usize];
    }
}

fn prepare_needles() -> String {
    let mnemonic = Mnemonic::parse(PHRASE).unwrap();
    let seed = mnemonic.to_seed("");
    let key = hd::derive(&*seed, Curve::Secp256k1, PATH).unwrap();
    // SAFETY: unarmed and single-threaded; nothing reads these yet.
    unsafe {
        (*DERIVED.seed.get()).copy_from_slice(&*seed);
        (*DERIVED.key.get()).copy_from_slice(key.secret());
        hex_into(key.secret(), &mut *DERIVED.key_hex.get());
        hex_into(&SECRET, &mut *DERIVED.secret_hex.get());
    }
    key.public_hex()
}

#[test]
fn key_material_is_wiped_before_its_memory_is_freed() {
    let public_hex = prepare_needles();

    // The harness itself must see what it is meant to catch: a plain copy
    // freed as is, and a buffer wiped at the end but moved while it grew.
    use zeroize::Zeroize;
    assert!(
        hits_during(|| drop(SECRET.to_vec())) > 0,
        "a raw copy went unseen"
    );
    assert!(
        hits_during(|| drop(PHRASE.to_owned())) > 0,
        "a phrase copy went unseen"
    );
    assert!(
        hits_during(|| {
            let mut v = Vec::with_capacity(SECRET.len());
            v.extend_from_slice(&SECRET);
            v.reserve(4096);
            v.zeroize();
        }) > 0,
        "the copy a growing buffer left behind went unseen"
    );
    assert_eq!(
        hits_during(|| {
            let mut v = SECRET.to_vec();
            v.zeroize();
        }),
        0,
        "a wiped copy was flagged"
    );

    // Create a vault, seal a secret, read it back, serialize and lock.
    let bytes = armed("create and seal", || {
        let pass = Secret::new(PASSPHRASE.to_vec());
        let mut v = EncryptedVault::create(&pass, KdfParams::MINIMUM).unwrap();
        let h = v.put("canary", Secret::new(SECRET.to_vec())).unwrap();
        v.with_secret(&h, &mut |s| assert!(s.expose() == SECRET))
            .unwrap();
        let bytes = v.to_bytes().unwrap();
        v.lock();
        bytes
    });

    // Reopen from bytes, unlock, read, rotate the passphrase, check both.
    let bytes = armed("reopen, unlock and rotate", || {
        let mut v = EncryptedVault::open(&bytes).unwrap();
        let pass = Secret::new(PASSPHRASE.to_vec());
        v.unlock(&pass).unwrap();
        let h = v.handle_for("canary").unwrap();
        v.with_secret(&h, &mut |s| assert!(s.expose() == SECRET))
            .unwrap();
        let rotated = Secret::new(NEW_PASSPHRASE.to_vec());
        v.change_passphrase(&pass, &rotated).unwrap();
        v.verify_passphrase(&rotated).unwrap();
        assert!(v.verify_passphrase(&pass).is_err());
        let bytes = v.to_bytes().unwrap();
        v.lock();
        bytes
    });

    // Seal a recovery phrase, derive its key and sign with it.
    armed("phrase, derivation and signing", || {
        let mut v = EncryptedVault::open(&bytes).unwrap();
        let pass = Secret::new(NEW_PASSPHRASE.to_vec());
        v.unlock(&pass).unwrap();
        provenance::import_phrase(&mut v, "w", PHRASE, 1).unwrap();
        let public = provenance::public_key(&v, "w", Curve::Secp256k1, PATH).unwrap();
        assert!(public == public_hex);
        let address = stackwallet_core::evm::checksum_address(
            &stackwallet_core::evm::address_from_public(&hex::decode(&public).unwrap()).unwrap(),
        );
        let session = SessionProof::Passphrase(Secret::new(NEW_PASSPHRASE.to_vec()));
        let signed = message::sign_message(
            &mut v,
            MessageRequest {
                wallet_id: "w",
                path: PATH,
                address: &address,
                session: &session,
                kind: MessageKind::Personal,
                payload: "hello",
                device_id: "d",
                now_ms: 2,
            },
        )
        .unwrap();
        assert!(!signed.signature_hex.is_empty());
        v.lock();
    });
}
