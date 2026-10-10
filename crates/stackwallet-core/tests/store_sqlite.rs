#![cfg(feature = "store")]

use stackwallet_core::audit::{Actor, AuditEvent};
use stackwallet_core::lifecycle::TxState;
use stackwallet_core::model::{ChainFamily, ChainId, Curve, KeyGroup, PartyRef, PartyRole};
use stackwallet_core::store::{
    Account, Device, DeviceKind, Folder, KeyGroupRecord, KeyShareRecord, SqliteStore, Wallet,
    WalletKind,
};
use stackwallet_core::vault::Secret;
use stackwallet_core::CoreError;

fn dek() -> Secret {
    Secret::new((0u8..32).collect())
}

fn folder(id: &str) -> Folder {
    Folder {
        id: id.into(),
        parent_id: None,
        name: format!("Folder {id} with a distinctive name"),
        color: Some("#111".into()),
        tags: vec!["savings".into()],
        default_policy_ids: vec![],
        created_at_ms: 1,
        updated_at_ms: 1,
    }
}

fn wallet(id: &str, folder_id: &str) -> Wallet {
    Wallet {
        id: id.into(),
        folder_id: folder_id.into(),
        name: "Main".into(),
        kind: WalletKind::Tss,
        key_group_id: None,
        tags: vec![],
        notes: Some("note".into()),
        created_at_ms: 2,
        updated_at_ms: 2,
    }
}

fn account(id: &str, wallet_id: &str) -> Account {
    Account {
        id: id.into(),
        wallet_id: wallet_id.into(),
        family: ChainFamily::Evm,
        chain_id: ChainId("eip155:1".into()),
        address: "0xabc".into(),
        derivation_path: None,
        public_key_hex: "02aa".into(),
        label: None,
        hidden: false,
    }
}

fn device(id: &str, pub_hex: &str) -> Device {
    Device {
        id: id.into(),
        name: "Laptop".into(),
        kind: DeviceKind::Desktop,
        identity_pub_hex: pub_hex.into(),
        noise_static_hex: "ab".repeat(32),
        endpoints: vec!["192.168.1.2:4000".into()],
        paired_at_ms: 10,
        last_seen_at_ms: None,
        revoked_at_ms: None,
    }
}

fn key_group(id: &str) -> KeyGroupRecord {
    KeyGroupRecord {
        group: KeyGroup {
            id: id.into(),
            threshold: 2,
            parties: vec![
                PartyRef {
                    device_id: "laptop".into(),
                    role: PartyRole::Human,
                },
                PartyRef {
                    device_id: "phone".into(),
                    role: PartyRole::Human,
                },
                PartyRef {
                    device_id: "agent".into(),
                    role: PartyRole::Agent,
                },
            ],
            curves: vec![Curve::Secp256k1, Curve::Ed25519],
            public_keys: vec![],
        },
        created_at_ms: 5,
        refreshed_at_ms: None,
    }
}

#[test]
fn create_applies_schema_and_enforces_foreign_keys() {
    let store = SqliteStore::create().unwrap();
    assert!(store.list_folders().unwrap().is_empty());
    let err = store.upsert_wallet(&wallet("w1", "missing")).unwrap_err();
    assert!(matches!(err, CoreError::Store(_)), "{err:?}");
    assert!(store.list_wallets().unwrap().is_empty());
}

#[test]
fn folder_wallet_account_crud() {
    let store = SqliteStore::create().unwrap();
    let f = folder("f1");
    store.upsert_folder(&f).unwrap();
    assert_eq!(store.get_folder("f1").unwrap().as_ref(), Some(&f));

    let mut w = wallet("w1", "f1");
    store.upsert_wallet(&w).unwrap();
    w.name = "Renamed".into();
    w.kind = WalletKind::Watch;
    store.upsert_wallet(&w).unwrap();
    assert_eq!(store.get_wallet("w1").unwrap().as_ref(), Some(&w));
    assert_eq!(store.list_wallets_in_folder("f1").unwrap(), vec![w.clone()]);

    let a = account("a1", "w1");
    store.upsert_account(&a).unwrap();
    assert_eq!(store.get_account("a1").unwrap().as_ref(), Some(&a));
    assert_eq!(store.list_accounts("w1").unwrap(), vec![a.clone()]);

    assert!(store.delete_account("a1").unwrap());
    assert!(!store.delete_account("a1").unwrap());
    assert!(store.delete_wallet("w1").unwrap());
    assert!(store.delete_folder("f1").unwrap());
    assert!(store.get_folder("f1").unwrap().is_none());
}

#[test]
fn account_cascade_on_wallet_delete() {
    let store = SqliteStore::create().unwrap();
    store.upsert_folder(&folder("f1")).unwrap();
    store.upsert_wallet(&wallet("w1", "f1")).unwrap();
    store.upsert_account(&account("a1", "w1")).unwrap();
    store.delete_wallet("w1").unwrap();
    assert!(store.get_account("a1").unwrap().is_none());
}

#[test]
fn key_group_device_and_share_roundtrip() {
    let store = SqliteStore::create().unwrap();
    let g = key_group("g1");
    store.upsert_key_group(&g).unwrap();
    assert_eq!(store.get_key_group("g1").unwrap().as_ref(), Some(&g));

    let d = device("laptop", &"aa".repeat(32));
    store.upsert_device(&d).unwrap();
    assert_eq!(store.get_device("laptop").unwrap().as_ref(), Some(&d));
    assert_eq!(store.list_devices().unwrap(), vec![d.clone()]);

    let share = KeyShareRecord {
        id: "s1".into(),
        key_group_id: "g1".into(),
        curve: Curve::Ed25519,
        device_id: "laptop".into(),
        encrypted_share: vec![9, 8, 7, 6],
        created_at_ms: 6,
    };
    store.put_key_share(&share).unwrap();
    assert_eq!(
        store
            .get_key_share("g1", Curve::Ed25519, "laptop")
            .unwrap()
            .as_ref(),
        Some(&share)
    );
    assert!(store
        .get_key_share("g1", Curve::Secp256k1, "laptop")
        .unwrap()
        .is_none());

    // A share for an unpaired device is refused by the schema.
    let orphan = KeyShareRecord {
        id: "s2".into(),
        device_id: "stranger".into(),
        ..share
    };
    assert!(store.put_key_share(&orphan).is_err());
}

#[test]
fn encrypted_roundtrip_restores_rows_and_hides_plaintext() {
    let store = SqliteStore::create().unwrap();
    let f = folder("f1");
    store.upsert_folder(&f).unwrap();
    store.upsert_wallet(&wallet("w1", "f1")).unwrap();

    let bytes = store.to_encrypted_bytes(&dek(), 3).unwrap();
    assert!(
        !bytes.windows(f.name.len()).any(|w| w == f.name.as_bytes()),
        "folder name must not appear in the encrypted file"
    );

    let (reopened, generation) = SqliteStore::open_encrypted(&bytes, &dek()).unwrap();
    assert_eq!(generation, 3);
    assert_eq!(reopened.get_folder("f1").unwrap().as_ref(), Some(&f));
    assert_eq!(reopened.list_wallets().unwrap().len(), 1);
    // Foreign keys stay enforced on a reopened image.
    assert!(reopened.upsert_wallet(&wallet("w2", "missing")).is_err());

    // Each save uses a fresh nonce.
    let again = store.to_encrypted_bytes(&dek(), 3).unwrap();
    assert_ne!(bytes, again);
}

#[test]
fn wrong_dek_and_tampering_are_rejected() {
    let store = SqliteStore::create().unwrap();
    store.upsert_folder(&folder("f1")).unwrap();
    let bytes = store.to_encrypted_bytes(&dek(), 0).unwrap();

    let wrong = Secret::new(vec![7u8; 32]);
    assert!(matches!(
        SqliteStore::open_encrypted(&bytes, &wrong),
        Err(CoreError::Crypto(_))
    ));

    // 5..13 is the generation, 13..37 the nonce; both are in the AAD.
    for pos in [5, 12, 20, bytes.len() / 2, bytes.len() - 1] {
        let mut t = bytes.clone();
        t[pos] ^= 0x01;
        assert!(
            SqliteStore::open_encrypted(&t, &dek()).is_err(),
            "flip at {pos} should fail"
        );
    }
    assert!(SqliteStore::open_encrypted(b"SWDB", &dek()).is_err());
    assert!(SqliteStore::open_encrypted(&bytes[..40], &dek()).is_err());
}

#[test]
fn header_carries_generation_in_the_clear_but_authenticated() {
    let store = SqliteStore::create().unwrap();
    let generation = 0x0102_0304_0506_0708u64;
    let bytes = store.to_encrypted_bytes(&dek(), generation).unwrap();
    assert_eq!(&bytes[..4], b"SWDB");
    assert_eq!(bytes[4], 2, "store file version");
    assert_eq!(&bytes[5..13], &generation.to_be_bytes());
    let (_, got) = SqliteStore::open_encrypted(&bytes, &dek()).unwrap();
    assert_eq!(got, generation);

    // Rewriting the generation (to pass a rollback off as current) is an
    // authentication failure, not a successful open at the forged value.
    let mut forged = bytes.clone();
    forged[5..13].copy_from_slice(&(generation + 1).to_be_bytes());
    assert!(matches!(
        SqliteStore::open_encrypted(&forged, &dek()),
        Err(CoreError::Crypto("store decrypt"))
    ));
}

#[test]
fn rolled_back_store_is_detectable_by_generation() {
    // The caller holds the vault's generation; an older store image decrypts
    // fine but reports the generation it was written at.
    let store = SqliteStore::create().unwrap();
    store.upsert_folder(&folder("f1")).unwrap();
    let old = store.to_encrypted_bytes(&dek(), 7).unwrap();
    store.upsert_folder(&folder("f2")).unwrap();
    let new = store.to_encrypted_bytes(&dek(), 8).unwrap();

    let (from_new, g_new) = SqliteStore::open_encrypted(&new, &dek()).unwrap();
    assert_eq!(g_new, 8);
    assert_eq!(from_new.list_folders().unwrap().len(), 2);

    let (from_old, g_old) = SqliteStore::open_encrypted(&old, &dek()).unwrap();
    assert_eq!(from_old.list_folders().unwrap().len(), 1);
    assert_ne!(g_old, 8, "a vault at 8 must refuse this store");
}

#[test]
fn version_1_header_is_rejected_with_a_store_error() {
    let store = SqliteStore::create().unwrap();
    let mut bytes = store.to_encrypted_bytes(&dek(), 0).unwrap();
    bytes[4] = 1;
    match SqliteStore::open_encrypted(&bytes, &dek()) {
        Err(CoreError::Store(msg)) => assert!(msg.contains("version 1"), "{msg}"),
        other => panic!("expected Store error, got {other:?}"),
    }
    bytes[4] = 9;
    assert!(matches!(
        SqliteStore::open_encrypted(&bytes, &dek()),
        Err(CoreError::Store(_))
    ));
}

#[test]
fn save_to_path_writes_atomically_and_reopens() {
    let dir = std::env::temp_dir().join(format!(
        "stackwallet-store-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.swdb");

    let store = SqliteStore::create().unwrap();
    store.upsert_folder(&folder("f1")).unwrap();
    store.save_to_path(&path, &dek(), 1).unwrap();
    store.upsert_folder(&folder("f2")).unwrap();
    // A stale temp file from an interrupted earlier save must not block or
    // be reused by the next one.
    std::fs::write(dir.join("store.swdb.tmp"), b"stale").unwrap();
    store.save_to_path(&path, &dek(), 2).unwrap();

    assert!(path.exists());
    assert!(!dir.join("store.swdb.tmp").exists());
    let (reopened, generation) = SqliteStore::open_path(&path, &dek()).unwrap();
    assert_eq!(generation, 2);
    assert_eq!(reopened.list_folders().unwrap().len(), 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store file must be owner-only");
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn write_atomic_replaces_existing_file_and_cleans_temp() {
    let dir = std::env::temp_dir().join(format!(
        "stackwallet-write-atomic-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.json");
    SqliteStore::write_atomic(&path, b"one").unwrap();
    SqliteStore::write_atomic(&path, b"two").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"two");
    assert!(!dir.join("vault.json.tmp").exists());

    // A missing parent directory is a clean error, not a panic or a stray file.
    let missing = dir.join("nope").join("vault.json");
    assert!(matches!(
        SqliteStore::write_atomic(&missing, b"x"),
        Err(CoreError::Store(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn audit_chain_append_and_verify() {
    let store = SqliteStore::create().unwrap();
    let e0 = store
        .record_audit(
            1,
            Actor::System,
            AuditEvent::TxTransition {
                tx_id: "t".into(),
                from: TxState::Draft,
                to: TxState::Simulated,
                note: None,
            },
        )
        .unwrap();
    let e1 = store
        .record_audit(
            2,
            Actor::Device {
                device_id: "laptop".into(),
            },
            AuditEvent::DevicePaired {
                device_id: "phone".into(),
            },
        )
        .unwrap();
    assert_eq!(e1.prev_hash_hex, e0.hash_hex);
    let chain = store.audit_chain().unwrap();
    assert_eq!(chain.entries(), &[e0.clone(), e1.clone()]);

    // Appending a pre-formed entry works when it extends the head exactly...
    let mut next = chain.clone();
    let e2 = next
        .append(
            3,
            Actor::System,
            AuditEvent::PolicyChanged {
                policy_id: "p".into(),
            },
        )
        .clone();
    store.append_audit(&e2).unwrap();
    assert_eq!(store.audit_entries().unwrap().len(), 3);

    // ...and is refused when it does not: wrong prev hash, wrong index, or
    // content that does not hash to the claimed value.
    let mut stale = e2.clone();
    stale.index = 3;
    assert!(matches!(
        store.append_audit(&stale),
        Err(CoreError::AuditChain(3))
    ));
    let mut forged = e2.clone();
    forged.index = 3;
    forged.prev_hash_hex = e2.hash_hex.clone();
    forged.at_ms = 4;
    assert!(store.append_audit(&forged).is_err());

    // Rows survive the encrypted round trip with the chain intact.
    let bytes = store.to_encrypted_bytes(&dek(), 0).unwrap();
    let (reopened, _) = SqliteStore::open_encrypted(&bytes, &dek()).unwrap();
    assert_eq!(reopened.audit_chain().unwrap().entries().len(), 3);
}
