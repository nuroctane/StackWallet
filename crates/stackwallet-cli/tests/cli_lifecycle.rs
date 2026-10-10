//! Drives the built binary through init, DKG, signing, refresh and status.
//! secp256k1-tr is used because Ed25519 DKG is several seconds per run in an
//! unoptimized build; the curve-specific paths are covered in the core tests.

use std::path::PathBuf;
use std::process::{Command, Output};

const PASSPHRASE: &str = "correct horse battery staple";

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stackwallet-cli-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn stackwallet(passphrase: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stackwallet"))
        .env("STACKWALLET_PASSPHRASE", passphrase)
        .args(args)
        .output()
        .expect("binary runs")
}

fn ok_json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout is JSON")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn init_keygen_sign_refresh_status() {
    let dir = temp_dir("lifecycle");
    let d = dir.to_str().unwrap();

    let init = ok_json(&stackwallet(PASSPHRASE, &["vault", "init", d, "test-cli"]));
    let device_id = init["device"]["id"].as_str().unwrap().to_owned();
    assert_eq!(device_id.len(), 32);
    assert!(dir.join("vault.json").is_file());
    assert!(dir.join("store.swdb").is_file());

    let again = stackwallet(PASSPHRASE, &["vault", "init", d]);
    assert!(!again.status.success());
    assert!(stderr_of(&again).contains("refusing to overwrite"));

    let locked = ok_json(&stackwallet("", &["vault", "status", d]));
    assert_eq!(locked["unlocked"], false);
    assert_eq!(locked["entries"], serde_json::json!(["device-identity"]));

    let wrong = stackwallet("nope", &["vault", "status", d, "--unlock"]);
    assert!(!wrong.status.success());
    assert!(stderr_of(&wrong).contains("wrong passphrase"));

    let keygen = ok_json(&stackwallet(
        PASSPHRASE,
        &[
            "harness",
            "keygen",
            d,
            "g1",
            "secp256k1-tr",
            "2",
            "laptop:human",
            "phone:human",
            "agent:agent",
        ],
    ));
    let pk = keygen["publicKey"]["hex"].as_str().unwrap().to_owned();
    assert_eq!(pk.len(), 66, "compressed SEC1");
    assert_eq!(keygen["sharesStored"], 3);

    let payload = "68656c6c6f";
    let sign = ok_json(&stackwallet(
        PASSPHRASE,
        &[
            "harness",
            "sign",
            d,
            "g1",
            "secp256k1-tr",
            "laptop,agent",
            payload,
            "--shuffle",
            "7",
        ],
    ));
    assert_eq!(
        sign["signature"]["signatureHex"].as_str().unwrap().len(),
        128
    );
    assert_eq!(sign["publicKey"]["hex"], pk);
    assert_eq!(
        sign["request"]["payloadHashHex"],
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );

    let below = stackwallet(
        PASSPHRASE,
        &["harness", "sign", d, "g1", "secp256k1-tr", "agent", payload],
    );
    assert!(!below.status.success());
    assert!(stderr_of(&below).contains("below threshold"));

    let refresh = ok_json(&stackwallet(
        PASSPHRASE,
        &["harness", "refresh", d, "g1", "secp256k1-tr"],
    ));
    assert_eq!(refresh["publicKey"]["hex"], pk, "refresh keeps the key");

    let after = ok_json(&stackwallet(
        PASSPHRASE,
        &[
            "harness",
            "sign",
            d,
            "g1",
            "secp256k1-tr",
            "phone,laptop",
            payload,
        ],
    ));
    assert_eq!(after["signature"]["curve"], "secp256k1-tr");

    let status = ok_json(&stackwallet(
        PASSPHRASE,
        &["vault", "status", d, "--unlock"],
    ));
    assert_eq!(status["unlocked"], true);
    assert_eq!(status["device"]["id"], device_id);
    assert_eq!(status["devices"], 1);
    assert_eq!(status["audit"]["verified"], true);
    // DevicePaired, then started+completed for keygen, sign, refresh, sign,
    // and started+aborted for the below-threshold attempt.
    assert_eq!(status["audit"]["entries"], 11);
    let labels = status["entries"].as_array().unwrap();
    assert_eq!(labels.len(), 4, "identity + three harness shares");
    assert!(labels.iter().any(|l| l == "harness/g1/secp256k1-tr/agent"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_store_rolled_back_behind_the_vault() {
    let dir = temp_dir("rollback");
    let d = dir.to_str().unwrap();
    ok_json(&stackwallet(PASSPHRASE, &["vault", "init", d]));
    let store = dir.join("store.swdb");
    let vault = dir.join("vault.json");
    let old_store = std::fs::read(&store).unwrap();
    let old_vault = std::fs::read(&vault).unwrap();

    // keygen stores shares in the vault, which advances its generation and
    // rewrites the store at the new one.
    ok_json(&stackwallet(
        PASSPHRASE,
        &[
            "harness",
            "keygen",
            d,
            "g1",
            "secp256k1-tr",
            "2",
            "laptop:human",
            "phone:human",
        ],
    ));
    ok_json(&stackwallet(
        PASSPHRASE,
        &["vault", "status", d, "--unlock"],
    ));

    // Restore the pre-keygen store next to the current vault: refused.
    let new_store = std::fs::read(&store).unwrap();
    std::fs::write(&store, &old_store).unwrap();
    let rolled = stackwallet(PASSPHRASE, &["vault", "status", d, "--unlock"]);
    assert!(!rolled.status.success());
    assert!(
        stderr_of(&rolled).contains("refusing to open a rolled-back store"),
        "{}",
        stderr_of(&rolled)
    );

    // The opposite direction (old vault, current store) is refused too.
    std::fs::write(&store, &new_store).unwrap();
    std::fs::write(&vault, &old_vault).unwrap();
    let rolled = stackwallet(PASSPHRASE, &["vault", "status", d, "--unlock"]);
    assert!(!rolled.status.success());
    assert!(stderr_of(&rolled).contains("does not match"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_agent_only_threshold_and_ecdsa() {
    let dir = temp_dir("refusals");
    let d = dir.to_str().unwrap();
    ok_json(&stackwallet(PASSPHRASE, &["vault", "init", d]));

    let d6 = stackwallet(
        PASSPHRASE,
        &[
            "harness",
            "keygen",
            d,
            "g2",
            "ed25519",
            "1",
            "agent:agent",
            "laptop:human",
        ],
    );
    assert!(!d6.status.success());
    assert!(stderr_of(&d6).contains("D6"));

    let ecdsa = stackwallet(
        PASSPHRASE,
        &[
            "harness",
            "keygen",
            d,
            "g3",
            "secp256k1",
            "2",
            "a:human",
            "b:human",
        ],
    );
    assert!(!ecdsa.status.success());
    assert!(stderr_of(&ecdsa).contains("CGGMP24"));

    let _ = std::fs::remove_dir_all(&dir);
}
