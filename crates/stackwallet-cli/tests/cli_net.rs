//! Two CLI processes on 127.0.0.1: pair, then run FROST keygen and signing
//! over the authenticated channel, with the signature checked independently
//! against the printed group key.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;

const PASSPHRASE: &str = "correct horse battery staple";
const WAIT: Duration = Duration::from_secs(120);

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stackwallet-net-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stackwallet"));
    cmd.env("STACKWALLET_PASSPHRASE", PASSPHRASE).args(args);
    cmd
}

fn run(args: &[&str]) -> Output {
    command(args).output().expect("binary runs")
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A long-running CLI process whose stdout is read line by line. Killed on
/// drop so a failing assertion never leaves a listener behind.
struct Server {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl Server {
    fn spawn(args: &[&str]) -> Self {
        let mut child = command(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("binary spawns");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Self { child, stdout }
    }

    fn read_line(&mut self) -> String {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).expect("stdout readable");
        assert!(n > 0, "process ended before printing a line");
        line.trim_end().to_owned()
    }

    /// Drain the rest of stdout, then wait for exit (bounded).
    fn finish(mut self) -> (bool, String) {
        let mut rest = String::new();
        self.stdout
            .read_to_string(&mut rest)
            .expect("stdout drains");
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return (status.success(), rest);
            }
            assert!(
                started.elapsed() < WAIT,
                "process did not exit; stdout so far: {rest}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn init(dir: &str, name: &str) -> String {
    let v = ok_json(&run(&["vault", "init", dir, name]));
    v["device"]["id"].as_str().unwrap().to_owned()
}

fn device_rows(dir: &str) -> Vec<serde_json::Value> {
    ok_json(&run(&["devices", dir]))
        .as_array()
        .cloned()
        .unwrap()
}

/// Pair two vaults, the issuer declaring the address it will later `serve`
/// on. Returns the offer so a caller can replay or tamper with it.
fn pair(issuer_dir: &str, issuer_addr: &str, scanner_dir: &str, scanner_addr: &str) -> String {
    let mut issuer = Server::spawn(&[
        "pair",
        "offer",
        issuer_dir,
        "--listen",
        issuer_addr,
        "--ttl-secs",
        "60",
    ]);
    let offer = issuer.read_line();
    assert!(offer.starts_with("stackwallet-pair:"), "{offer}");
    let accepted = ok_json(&run(&[
        "pair",
        "accept",
        scanner_dir,
        &offer,
        "--listen",
        scanner_addr,
    ]));
    let issuer_id = accepted["paired"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        accepted["paired"]["endpoints"],
        serde_json::json!([format!("tcp://{issuer_addr}")])
    );
    let (ok, rest) = issuer.finish();
    assert!(ok, "issuer failed: {rest}");
    let issued: serde_json::Value = serde_json::from_str(&rest).expect("issuer prints JSON");
    let scanner_id = issued["paired"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        issued["paired"]["endpoints"],
        serde_json::json!([format!("tcp://{scanner_addr}")])
    );
    assert!(device_rows(issuer_dir)
        .iter()
        .any(|r| r["id"] == scanner_id));
    assert!(device_rows(scanner_dir)
        .iter()
        .any(|r| r["id"] == issuer_id));
    offer
}

#[test]
fn pair_keygen_sign_over_tcp() {
    let dir_a = temp_dir("a");
    let dir_b = temp_dir("b");
    let (a, b) = (dir_a.to_str().unwrap(), dir_b.to_str().unwrap());
    let id_a = init(a, "alpha");
    let id_b = init(b, "beta");
    let port_a = free_port();
    let port_b = free_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    // Pairing: A issues on the address it will later serve on, B declares its.
    pair(a, &addr_a, b, &addr_b);

    // Both device tables know both devices.
    let rows_a = device_rows(a);
    assert_eq!(rows_a.len(), 2);
    let peer_on_a = rows_a
        .iter()
        .find(|r| r["id"] == id_b)
        .expect("B pinned on A");
    assert_eq!(peer_on_a["self"], false);
    assert_eq!(peer_on_a["revokedAtMs"], serde_json::Value::Null);
    assert_eq!(
        peer_on_a["endpoints"],
        serde_json::json!([format!("tcp://{addr_b}")])
    );
    let rows_b = device_rows(b);
    assert!(rows_b.iter().any(|r| r["id"] == id_a && r["self"] == false));
    assert!(rows_b.iter().any(|r| r["id"] == id_b && r["self"] == true));

    // 2-of-2 DKG: B serves, A initiates and reaches B at the pinned endpoint.
    let mut server = Server::spawn(&["serve", b, "--listen", &addr_b, "--once", "--no-mdns"]);
    let listening: serde_json::Value = serde_json::from_str(&server.read_line()).unwrap();
    assert_eq!(listening["listening"], addr_b);
    let keygen = ok_json(&run(&[
        "net",
        "keygen",
        a,
        "--group",
        "g1",
        "--curve",
        "ed25519",
        "--threshold",
        "2",
        "--peers",
        &id_b,
    ]));
    let pk_hex = keygen["publicKey"]["hex"].as_str().unwrap().to_owned();
    assert_eq!(pk_hex.len(), 64);
    assert_eq!(keygen["peers"][0]["deviceId"], id_b);
    let (ok, rest) = server.finish();
    assert!(ok, "server failed: {rest}");
    let served: serde_json::Value = serde_json::from_str(rest.trim()).unwrap();
    assert_eq!(served["ceremony"], "keyGen");
    assert_eq!(
        served["publicKey"]["hex"], pk_hex,
        "both parties agree on the key"
    );
    assert_eq!(served["proposer"], id_a);

    // Signing over the same pair.
    let payload = "68656c6c6f";
    let mut server = Server::spawn(&["serve", b, "--listen", &addr_b, "--once", "--no-mdns"]);
    server.read_line();
    let sign = ok_json(&run(&[
        "net",
        "sign",
        a,
        "--group",
        "g1",
        "--curve",
        "ed25519",
        "--payload-hex",
        payload,
        "--peers",
        &id_b,
    ]));
    let sig_hex = sign["signature"]["signatureHex"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(sig_hex.len(), 128);
    assert_eq!(sign["publicKey"]["hex"], pk_hex);
    let (ok, rest) = server.finish();
    assert!(ok, "server failed: {rest}");
    let served: serde_json::Value = serde_json::from_str(rest.trim()).unwrap();
    assert_eq!(served["ceremony"], "sign");
    assert_eq!(served["signature"]["signatureHex"], sig_hex);

    // Independent verification against the printed group key.
    verify_ed25519(&pk_hex, &sig_hex, payload);

    // Both vaults hold their own share and an intact audit chain.
    for (dir, expected_devices) in [(a, 2), (b, 2)] {
        let status = ok_json(&run(&["vault", "status", dir, "--unlock"]));
        assert_eq!(status["audit"]["verified"], true, "{dir}");
        assert_eq!(status["devices"], expected_devices);
        let labels = status["entries"].as_array().unwrap();
        assert!(labels.iter().any(|l| l == "share/g1/ed25519"), "{labels:?}");
    }

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn tampered_one_time_code_is_refused() {
    let dir_a = temp_dir("tamper-a");
    let dir_b = temp_dir("tamper-b");
    let (a, b) = (dir_a.to_str().unwrap(), dir_b.to_str().unwrap());
    init(a, "alpha");
    init(b, "beta");

    let mut issuer = Server::spawn(&["pair", "offer", a, "--ttl-secs", "30"]);
    let offer = issuer.read_line();
    let body = offer.strip_prefix("stackwallet-pair:").unwrap();
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut json: serde_json::Value =
        serde_json::from_slice(&engine.decode(body).unwrap()).unwrap();
    let code = json["oneTimeCodeHex"].as_str().unwrap().to_owned();
    let flipped = if code.starts_with('0') { "1" } else { "0" };
    json["oneTimeCodeHex"] = serde_json::Value::String(format!("{flipped}{}", &code[1..]));
    let tampered = format!(
        "stackwallet-pair:{}",
        engine.encode(serde_json::to_vec(&json).unwrap())
    );

    let accept = run(&["pair", "accept", b, &tampered]);
    assert!(!accept.status.success());
    assert!(
        stderr_of(&accept).contains("pairing failed"),
        "{}",
        stderr_of(&accept)
    );

    // A failed attempt must not burn the one-time code: the issuer keeps
    // listening and the legitimate scanner still pairs with the real offer.
    let accept = run(&["pair", "accept", b, &offer]);
    assert!(accept.status.success(), "{}", stderr_of(&accept));
    let (ok, _) = issuer.finish();
    assert!(ok, "the issuer accepts the real scanner after a prober");
    assert_eq!(device_rows(a).len(), 2, "issuer pinned the scanner");
    assert_eq!(device_rows(b).len(), 2, "scanner pinned the issuer");

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn keygen_to_an_unpaired_device_fails_fast() {
    let dir = temp_dir("unpaired");
    let d = dir.to_str().unwrap();
    init(d, "alpha");
    let started = Instant::now();
    let out = run(&[
        "net",
        "keygen",
        d,
        "--group",
        "g1",
        "--curve",
        "ed25519",
        "--threshold",
        "2",
        "--peers",
        "00000000000000000000000000000000",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("not paired"),
        "{}",
        stderr_of(&out)
    );
    assert!(started.elapsed() < Duration::from_secs(10));

    let sign = run(&[
        "net",
        "sign",
        d,
        "--group",
        "g1",
        "--curve",
        "ed25519",
        "--payload-hex",
        "00",
        "--peers",
        "00000000000000000000000000000000",
    ]);
    assert!(!sign.status.success());
    assert!(
        stderr_of(&sign).contains("no key group"),
        "{}",
        stderr_of(&sign)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn verify_ed25519(pk_hex: &str, sig_hex: &str, payload_hex: &str) {
    let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    let sig: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    key.verify_strict(
        &hex::decode(payload_hex).unwrap(),
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .expect("FROST signature verifies as plain Ed25519");
}

/// The hub holds one session per peer and forwards their messages along; the
/// peers only ever talk to the hub. Every participant is still paired with
/// every other participant, because each side verifies relayed envelopes
/// against its own pinned table.
#[test]
fn three_party_keygen_and_sign_through_the_hub() {
    let dir_h = temp_dir("hub");
    let dir_b = temp_dir("three-b");
    let dir_c = temp_dir("three-c");
    let (h, b, c) = (
        dir_h.to_str().unwrap(),
        dir_b.to_str().unwrap(),
        dir_c.to_str().unwrap(),
    );
    let id_h = init(h, "hub");
    let id_b = init(b, "beta");
    let id_c = init(c, "gamma");
    let addr_b = format!("127.0.0.1:{}", free_port());
    let addr_c = format!("127.0.0.1:{}", free_port());

    // Full pairing mesh: the peers need each other's pinned identities to
    // verify relayed envelopes, even though they never connect directly.
    let hub_addr = format!("127.0.0.1:{}", free_port());
    pair(h, &hub_addr, b, &addr_b);
    pair(h, &hub_addr, c, &addr_c);
    pair(b, &addr_b, c, &addr_c);

    // 2-of-3 DKG with the hub as initiator and B and C serving.
    let mut server_b = Server::spawn(&["serve", b, "--listen", &addr_b, "--once", "--no-mdns"]);
    let mut server_c = Server::spawn(&["serve", c, "--listen", &addr_c, "--once", "--no-mdns"]);
    server_b.read_line();
    server_c.read_line();
    let peers = format!("{id_b},{id_c}");
    let keygen = ok_json(&run(&[
        "net",
        "keygen",
        h,
        "--group",
        "g2",
        "--curve",
        "ed25519",
        "--threshold",
        "2",
        "--peers",
        &peers,
    ]));
    let pk_hex = keygen["publicKey"]["hex"].as_str().unwrap().to_owned();
    assert_eq!(pk_hex.len(), 64);
    for (server, name) in [(server_b, "B"), (server_c, "C")] {
        let (ok, rest) = server.finish();
        assert!(ok, "server {name} failed: {rest}");
        let served: serde_json::Value = serde_json::from_str(rest.trim()).unwrap();
        assert_eq!(served["ceremony"], "keyGen");
        assert_eq!(
            served["publicKey"]["hex"], pk_hex,
            "{name} agrees on the key"
        );
    }
    for dir in [h, b, c] {
        let status = ok_json(&run(&["vault", "status", dir, "--unlock"]));
        let labels = status["entries"].as_array().unwrap();
        assert!(labels.iter().any(|l| l == "share/g2/ed25519"), "{labels:?}");
    }

    // Signing with a device that is not a party of the group fails before any
    // network traffic.
    let payload = "68656c6c6f";
    let stranger = run(&[
        "net",
        "sign",
        h,
        "--group",
        "g2",
        "--curve",
        "ed25519",
        "--payload-hex",
        payload,
        "--peers",
        "00000000000000000000000000000000",
    ]);
    assert!(!stranger.status.success());
    assert!(
        stderr_of(&stranger).contains("not a party of group"),
        "{}",
        stderr_of(&stranger)
    );

    // 2-of-3 signing: hub + B, C stays home.
    let mut server_b = Server::spawn(&["serve", b, "--listen", &addr_b, "--once", "--no-mdns"]);
    server_b.read_line();
    let sign = ok_json(&run(&[
        "net",
        "sign",
        h,
        "--group",
        "g2",
        "--curve",
        "ed25519",
        "--payload-hex",
        payload,
        "--peers",
        &id_b,
    ]));
    let sig_hex = sign["signature"]["signatureHex"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(sign["publicKey"]["hex"], pk_hex);
    assert_eq!(sign["signers"], serde_json::json!([id_h, id_b]));
    let (ok, rest) = server_b.finish();
    assert!(ok, "server failed: {rest}");
    let served: serde_json::Value = serde_json::from_str(rest.trim()).unwrap();
    assert_eq!(served["signature"]["signatureHex"], sig_hex);
    verify_ed25519(&pk_hex, &sig_hex, payload);

    let _ = std::fs::remove_dir_all(&dir_h);
    let _ = std::fs::remove_dir_all(&dir_b);
    let _ = std::fs::remove_dir_all(&dir_c);
}
