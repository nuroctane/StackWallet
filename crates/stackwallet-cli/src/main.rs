//! Headless StackWallet: the encrypted vault, the device identity and
//! threshold ceremonies without a UI. `pair` (device-to-device transport) and
//! `run` (the scheduler that makes this binary the automation device) are
//! not wired yet and say so.

mod harness_cmd;
mod vault_cmd;

use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "stackwallet <command>

Commands:
  version                      print core and CLI versions
  schema                       print the SQLite schema the store applies
  policy-eval <policies.json> <intent.json> <context.json>
                               evaluate policies offline; exit 0 on allow, 2 on deny
  key-group-check [file.json]  validate a KeyGroup (stdin if no file); exit 2 on violation
  vault init <dir> [name]      create an encrypted vault + store with a fresh device identity
  vault status <dir> [--unlock]
                               locked metadata; with --unlock also opens the store and
                               verifies the audit chain
  harness keygen|sign|refresh  run every FROST party in-process (see `harness` for usage)
  pair | sign | run            not yet (Phase 2 / Phase 6)

The passphrase is read from STACKWALLET_PASSPHRASE or the first line of stdin.
";

fn read_arg_or_stdin(path: Option<&str>) -> std::io::Result<String> {
    match path {
        Some(p) => std::fs::read_to_string(p),
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("version") => {
            println!("stackwallet-cli {}", env!("CARGO_PKG_VERSION"));
            println!("stackwallet-core {}", stackwallet_core::VERSION);
            Ok(ExitCode::SUCCESS)
        }
        Some("schema") => {
            print!("{}", stackwallet_core::store::SCHEMA_SQL);
            Ok(ExitCode::SUCCESS)
        }
        Some("policy-eval") => {
            let [p, i, c] = [args.get(1), args.get(2), args.get(3)]
                .map(|a| a.ok_or("policy-eval needs three files"));
            let (p, i, c) = (p?, i?, c?);
            let read =
                |path: &String| std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"));
            let policies: Vec<stackwallet_core::policy::Policy> =
                serde_json::from_str(&read(p)?).map_err(|e| format!("policies: {e}"))?;
            let intent: stackwallet_core::intent::TxIntent =
                serde_json::from_str(&read(i)?).map_err(|e| format!("intent: {e}"))?;
            let ctx: stackwallet_core::policy::PolicyContext =
                serde_json::from_str(&read(c)?).map_err(|e| format!("context: {e}"))?;
            let decision = stackwallet_core::policy::evaluate(&policies, &intent, &ctx);
            println!(
                "{}",
                serde_json::to_string_pretty(&decision).map_err(|e| e.to_string())?
            );
            Ok(if decision.is_allowed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Some("key-group-check") => {
            let text =
                read_arg_or_stdin(args.get(1).map(String::as_str)).map_err(|e| e.to_string())?;
            let group: stackwallet_core::model::KeyGroup =
                serde_json::from_str(&text).map_err(|e| format!("key group: {e}"))?;
            match group.validate() {
                Ok(()) => {
                    println!(
                        "ok: {}-of-{} with {} agent share(s)",
                        group.threshold,
                        group.parties.len(),
                        group.agent_share_count()
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("{e}");
                    Ok(ExitCode::from(2))
                }
            }
        }
        Some("vault") => vault(&args[1..]),
        Some("harness") => harness_cmd::run(&args[1..]),
        Some("pair") | Some("sign") => Err("not yet: Phase 2".into()),
        Some("run") => Err("not yet: Phase 6".into()),
        _ => {
            eprint!("{USAGE}");
            Ok(ExitCode::from(64))
        }
    }
}

fn print_json(v: &serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(v).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn vault(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let dir = args.get(1).ok_or("vault init needs a directory")?;
            let name = args.get(2).map(String::as_str).unwrap_or("stackwallet-cli");
            let opened = vault_cmd::init(dir, name)?;
            print_json(&serde_json::json!({
                "dir": opened.paths.dir.display().to_string(),
                "device": {
                    "id": opened.identity.device_id(),
                    "name": name,
                    "publicHex": opened.identity.public_hex(),
                },
                "kdf": opened.vault.kdf_params(),
            }))?;
            Ok(ExitCode::SUCCESS)
        }
        Some("status") => {
            let dir = args.get(1).ok_or("vault status needs a directory")?;
            let unlock = args.iter().skip(2).any(|a| a == "--unlock");
            let status = if unlock {
                vault_cmd::status_unlocked(dir)?
            } else {
                vault_cmd::status_locked(dir)?
            };
            print_json(&status)?;
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            eprint!("{USAGE}");
            Ok(ExitCode::from(64))
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
