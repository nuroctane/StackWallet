//! Every test here runs Argon2id at the OWASP minimum, so expect a few hundred
//! milliseconds per unlock. Tests that unlock several times are the slow ones.

use stackwallet_core::vault::{EncryptedVault, KdfParams, Secret, Vault};
use stackwallet_core::CoreError;

fn pass(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

const KNOWN_SECRET: &[u8] = b"correct horse battery staple 0123456789abcdef";

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn create_put_serialize_open_unlock_read() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    assert!(v.is_unlocked());
    let h = v
        .put(
            "share:g1:ed25519",
            pass(std::str::from_utf8(KNOWN_SECRET).unwrap()),
        )
        .unwrap();
    let bytes = v.to_bytes().unwrap();

    let mut reopened = EncryptedVault::open(&bytes).unwrap();
    assert!(!reopened.is_unlocked());
    reopened.unlock(&pass("pw")).unwrap();
    assert!(reopened.is_unlocked());
    let got = reopened
        .with_secret(&h, &mut |s| s.expose().to_vec())
        .unwrap();
    assert_eq!(got, KNOWN_SECRET);
    assert_eq!(reopened.handle_for("share:g1:ed25519"), Some(h));
}

#[test]
fn wrong_passphrase_is_unlock_error() {
    let v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    let mut reopened = EncryptedVault::open(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        reopened.unlock(&pass("pW")),
        Err(CoreError::Unlock)
    ));
    assert!(!reopened.is_unlocked());
}

#[test]
fn params_below_minimum_are_rejected_on_create() {
    for params in [
        KdfParams {
            m_cost_kib: KdfParams::MINIMUM.m_cost_kib - 1,
            ..KdfParams::MINIMUM
        },
        KdfParams {
            t_cost: 1,
            ..KdfParams::MINIMUM
        },
        KdfParams {
            p_cost: 0,
            ..KdfParams::MINIMUM
        },
    ] {
        assert!(matches!(
            EncryptedVault::create(&pass("pw"), params),
            Err(CoreError::Invalid {
                what: "kdf params",
                ..
            })
        ));
    }
}

#[test]
fn locked_vault_refuses_reads() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    let h = v.put("k", pass("v")).unwrap();
    v.lock();
    assert!(matches!(
        v.with_secret(&h, &mut |_| ()),
        Err(CoreError::Locked)
    ));
    v.unlock(&pass("pw")).unwrap();
    assert_eq!(
        v.with_secret(&h, &mut |s| s.expose().to_vec()).unwrap(),
        b"v"
    );
}

#[test]
fn delete_removes_entry() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    let h = v.put("k", pass("v")).unwrap();
    v.delete(&h).unwrap();
    assert!(v.labels().is_empty());
    assert!(matches!(
        v.with_secret(&h, &mut |_| ()),
        Err(CoreError::Invalid { .. })
    ));
    assert!(v.delete(&h).is_err());
}

#[test]
fn change_passphrase_rotates_wrap() {
    // Three Argon2 derivations (change + two unlock attempts), so this one is slow.
    let mut v = EncryptedVault::create(&pass("old"), KdfParams::MINIMUM).unwrap();
    let h = v.put("k", pass("v")).unwrap();
    assert!(matches!(
        v.change_passphrase(&pass("wrong"), &pass("new")),
        Err(CoreError::Unlock)
    ));
    v.change_passphrase(&pass("old"), &pass("new")).unwrap();
    assert!(v.is_unlocked());

    let bytes = v.to_bytes().unwrap();
    let mut a = EncryptedVault::open(&bytes).unwrap();
    assert!(matches!(a.unlock(&pass("old")), Err(CoreError::Unlock)));
    a.unlock(&pass("new")).unwrap();
    assert_eq!(
        a.with_secret(&h, &mut |s| s.expose().to_vec()).unwrap(),
        b"v"
    );
}

#[test]
fn change_passphrase_on_locked_vault_stays_locked() {
    let mut v = EncryptedVault::create(&pass("old"), KdfParams::MINIMUM).unwrap();
    v.lock();
    v.change_passphrase(&pass("old"), &pass("new")).unwrap();
    assert!(!v.is_unlocked());
}

#[test]
fn debug_output_contains_no_key_material() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    v.put("k", pass(std::str::from_utf8(KNOWN_SECRET).unwrap()))
        .unwrap();
    let dek_hex = hex::encode(v.dek().unwrap().expose());
    let dbg = format!("{v:?}");
    assert!(!dbg.contains(&dek_hex));
    assert!(!dbg.contains(std::str::from_utf8(KNOWN_SECRET).unwrap()));
    assert!(dbg.contains("unlocked: true"));
}

#[test]
fn serialized_file_contains_no_plaintext_or_dek() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    v.put("k", Secret::new(KNOWN_SECRET.to_vec())).unwrap();
    let bytes = v.to_bytes().unwrap();
    assert!(!contains(&bytes, KNOWN_SECRET));
    assert!(!contains(&bytes, hex::encode(KNOWN_SECRET).as_bytes()));
    let dek = v.dek().unwrap();
    assert!(!contains(&bytes, dek.expose()));
    assert!(!contains(&bytes, hex::encode(dek.expose()).as_bytes()));
    assert!(!contains(&bytes, b"pw\""));
}

/// Flip one byte inside the value of `field` in the serialized JSON and
/// return the mutated bytes. Fields are located by their JSON key, so this
/// stays independent of serde's field ordering.
fn flip_in_field(bytes: &[u8], field: &str, offset: usize) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    let key = format!("\"{field}\":\"");
    let start = text.find(&key).unwrap_or_else(|| panic!("field {field}")) + key.len();
    let mut out = bytes.to_vec();
    // Hex digits: swapping within [0-9a-f] keeps the field decodable so the
    // failure is an authentication failure, not a parse failure.
    out[start + offset] = if out[start + offset] == b'0' {
        b'1'
    } else {
        b'0'
    };
    out
}

#[test]
fn tampering_with_wrapped_dek_or_kdf_fails_unlock() {
    let v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    let bytes = v.to_bytes().unwrap();
    for (field, offset) in [("nonceHex", 3), ("ciphertextHex", 7), ("saltHex", 0)] {
        // The first nonceHex/ciphertextHex in the file belong to wrappedDek
        // because serde writes struct fields in declaration order.
        let mutated = flip_in_field(&bytes, field, offset);
        let mut t = EncryptedVault::open(&mutated).unwrap();
        assert!(
            matches!(t.unlock(&pass("pw")), Err(CoreError::Unlock)),
            "{field} tamper should fail unlock"
        );
    }

    // Changing a cost parameter to another in-range value parses and passes
    // the bounds check, but the AAD catches it.
    let text = String::from_utf8(bytes.clone()).unwrap();
    let raised = text.replacen("\"mCostKib\":19456", "\"mCostKib\":19457", 1);
    assert_ne!(raised, text);
    let mut t = EncryptedVault::open(raised.as_bytes()).unwrap();
    assert!(matches!(t.unlock(&pass("pw")), Err(CoreError::Unlock)));
}

#[test]
fn open_rejects_out_of_range_kdf_params_before_unlock() {
    let v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    let text = String::from_utf8(v.to_bytes().unwrap()).unwrap();
    let cases = [
        text.replacen("\"tCost\":2", "\"tCost\":1", 1),
        text.replacen("\"pCost\":1", "\"pCost\":0", 1),
        text.replacen("\"mCostKib\":19456", "\"mCostKib\":19455", 1),
        // Far beyond MAXIMUM_M_COST_KIB: must fail without touching Argon2.
        text.replacen("\"mCostKib\":19456", "\"mCostKib\":4294967295", 1),
        text.replacen(
            "\"mCostKib\":19456",
            &format!("\"mCostKib\":{}", KdfParams::MAXIMUM_M_COST_KIB + 1),
            1,
        ),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert_ne!(case, &text, "case {i} did not change the file");
        assert!(
            matches!(
                EncryptedVault::open(case.as_bytes()),
                Err(CoreError::Invalid {
                    what: "kdf params",
                    ..
                })
            ),
            "case {i} should be rejected at open"
        );
    }
    assert!(matches!(
        EncryptedVault::create(
            &pass("pw"),
            KdfParams {
                m_cost_kib: KdfParams::MAXIMUM_M_COST_KIB + 1,
                ..KdfParams::MINIMUM
            }
        ),
        Err(CoreError::Invalid {
            what: "kdf params",
            ..
        })
    ));
}

#[test]
fn tampering_with_entry_fields_fails_unlock() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    v.put("label", Secret::new(KNOWN_SECRET.to_vec())).unwrap();
    let bytes = v.to_bytes().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let entries_at = text.find("\"entries\"").unwrap();
    let (head, tail) = bytes.split_at(entries_at);

    let mut cases: Vec<Vec<u8>> = Vec::new();
    for (field, offset) in [("nonceHex", 5), ("ciphertextHex", 11)] {
        let mut mutated = head.to_vec();
        mutated.extend_from_slice(&flip_in_field(tail, field, offset));
        cases.push(mutated);
    }
    let relabeled = text.replacen("\"label\":\"label\"", "\"label\":\"lapel\"", 1);
    assert_ne!(relabeled, text);
    cases.push(relabeled.into_bytes());
    let reid = {
        let key = "\"id\":\"";
        let at = text[entries_at..].find(key).unwrap() + entries_at + key.len();
        let mut m = bytes.clone();
        m[at] = if m[at] == b'0' { b'1' } else { b'0' };
        m
    };
    cases.push(reid);

    // Every entry edit is now caught by the manifest tag at unlock, before
    // any entry is decrypted, and the vault stays locked.
    for (i, mutated) in cases.into_iter().enumerate() {
        let mut t = EncryptedVault::open(&mutated).unwrap();
        assert!(
            matches!(
                t.unlock(&pass("pw")),
                Err(CoreError::Crypto("vault manifest"))
            ),
            "case {i}: expected manifest failure"
        );
        assert!(!t.is_unlocked());
    }
}

/// The serialized vault split into the JSON objects of `entries`, so tests
/// can splice, drop or reorder whole entries without caring about field
/// order inside them.
fn split_entries(bytes: &[u8]) -> (String, Vec<String>, String) {
    let text = std::str::from_utf8(bytes).unwrap();
    let key = "\"entries\":[";
    let start = text.find(key).unwrap() + key.len();
    let end = text[start..].find(']').unwrap() + start;
    let body = &text[start..end];
    let mut entries = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for c in body.chars() {
        match c {
            '{' => {
                depth += 1;
                cur.push(c);
            }
            '}' => {
                depth -= 1;
                cur.push(c);
                if depth == 0 {
                    entries.push(std::mem::take(&mut cur));
                }
            }
            ',' if depth == 0 => {}
            _ => cur.push(c),
        }
    }
    (text[..start].to_owned(), entries, text[end..].to_owned())
}

fn join_entries(head: &str, entries: &[String], tail: &str) -> Vec<u8> {
    format!("{head}{}{tail}", entries.join(",")).into_bytes()
}

fn expect_manifest_failure(bytes: &[u8], what: &str) {
    let mut t = EncryptedVault::open(bytes).unwrap_or_else(|e| panic!("{what}: open: {e}"));
    assert!(
        matches!(
            t.unlock(&pass("pw")),
            Err(CoreError::Crypto("vault manifest"))
        ),
        "{what}: expected manifest failure"
    );
    assert!(!t.is_unlocked(), "{what}: must stay locked");
}

#[test]
fn manifest_catches_entry_rollback_deletion_and_reordering() {
    // One vault, several file-level edits, one Argon2 run per edit.
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    v.put("first", pass("v1")).unwrap();
    let snapshot = v.to_bytes().unwrap();
    v.put("first", pass("v2")).unwrap();
    v.put("second", pass("w")).unwrap();
    let current = v.to_bytes().unwrap();

    let (head, entries, tail) = split_entries(&current);
    assert_eq!(entries.len(), 2);
    let (_, old_entries, _) = split_entries(&snapshot);
    assert_eq!(old_entries.len(), 1);

    // Splice the older ciphertext for the same id and label back in. The
    // per-entry AEAD accepts it (same key, same AAD, valid tag); only the
    // manifest knows it is stale.
    let mut rolled = entries.clone();
    rolled[0] = old_entries[0].clone();
    assert_ne!(rolled, entries);
    expect_manifest_failure(&join_entries(&head, &rolled, &tail), "rolled-back entry");

    expect_manifest_failure(&join_entries(&head, &entries[1..], &tail), "deleted entry");

    let swapped = vec![entries[1].clone(), entries[0].clone()];
    expect_manifest_failure(&join_entries(&head, &swapped, &tail), "reordered entries");

    // Rolling back the generation alone, or the tag alone, fails the same way.
    let text = String::from_utf8(current.clone()).unwrap();
    let gen_key = format!("\"generation\":{}", v.generation());
    let older = text.replacen(
        &gen_key,
        &format!("\"generation\":{}", v.generation() - 1),
        1,
    );
    assert_ne!(older, text);
    expect_manifest_failure(older.as_bytes(), "generation rollback");
    expect_manifest_failure(
        &flip_in_field(&current, "manifestTagHex", 0),
        "tag bit flip",
    );

    // The genuine file still opens.
    let mut ok = EncryptedVault::open(&current).unwrap();
    ok.unlock(&pass("pw")).unwrap();
    assert_eq!(ok.generation(), v.generation());
}

#[test]
fn generation_tracks_entry_mutations_only() {
    let mut v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    assert_eq!(v.generation(), 0);
    let h = v.put("a", pass("1")).unwrap();
    assert_eq!(v.generation(), 1);
    v.put("a", pass("2")).unwrap();
    assert_eq!(v.generation(), 2, "replacing under the same label counts");
    v.put("b", pass("3")).unwrap();
    assert_eq!(v.generation(), 3);
    v.delete(&h).unwrap();
    assert_eq!(v.generation(), 4);
    assert!(v.delete(&h).is_err());
    assert_eq!(v.generation(), 4, "a failed delete does not advance");

    v.change_passphrase(&pass("pw"), &pass("new")).unwrap();
    assert_eq!(
        v.generation(),
        4,
        "passphrase rotation is not a content change"
    );

    // Survives the round trip and the rotated wrap still verifies the tag.
    let mut reopened = EncryptedVault::open(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(reopened.generation(), 4);
    reopened.unlock(&pass("new")).unwrap();
    assert_eq!(reopened.labels().len(), 1);
}

#[test]
fn unsupported_version_is_rejected() {
    let v = EncryptedVault::create(&pass("pw"), KdfParams::MINIMUM).unwrap();
    let text = String::from_utf8(v.to_bytes().unwrap()).unwrap();
    let bumped = text.replacen("\"version\":1", "\"version\":2", 1);
    assert!(matches!(
        EncryptedVault::open(bumped.as_bytes()),
        Err(CoreError::Invalid { what: "vault", .. })
    ));
    assert!(matches!(
        EncryptedVault::open(b"not json"),
        Err(CoreError::Unlock)
    ));
}
