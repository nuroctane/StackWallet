# StackWallet — Security model

This document is the threat model and the list of support gates. Treat every signing path as
able to lose real money until it has passed the gates in section 6.

## 1. Assets to protect

1. Share material and seeds (loss = theft of funds).
2. The data encryption key (DEK) and the passphrase that wraps it.
3. Device identity keys (loss = an attacker can join ceremonies as you).
4. Model provider keys (loss = someone else's bill, and a prompt-injection channel).
5. The audit log's integrity (loss = you cannot tell what the agent did).
6. Directory metadata (addresses, balances, policies) as privacy-sensitive data.

## 2. Trust boundaries

```
untrusted ──► model output, tool results, chain data, token metadata, web content, RPC responses
   │
   ▼
TypeScript (UI, agent runtime, chain adapters)      no secrets, no signing authority
   │  JSON requests + opaque handles
   ▼
Rust core (vault, TSS, policy, transport, audit)    the only holder of secrets and the only
                                                    place a signature can originate
   │  authenticated, payload-bound messages
   ▼
other paired devices (their own core)
```

- The core never returns secret bytes across the boundary. It returns handles, public keys,
  signatures, decisions and store rows.
- The policy engine runs inside the core before any share participates. UI checks are
  convenience only.
- Chain adapters receive public keys and return unsigned transactions, sighashes and signed
  transactions. They never see shares.
- The agent runtime receives tool results and proposal status. Provider requests are authorized
  through a scoped core handle so the raw provider key never enters JavaScript.

## 3. Threats and mitigations

| Threat                                                     | Mitigation                                                                                                                                                                                                                           |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Agent is prompt-injected into sending funds to an attacker | D6: agent is at most one party; every agent-inclusive threshold needs a non-agent share. Policy caps and allowlists. Destinations sourced from untrusted content are flagged in the proposal. Hard per-session caps in the run loop. |
| Agent exfiltrates keys                                     | Agent never receives keys, shares, provider keys, or RPC credentials. Tools are a fixed allowlist with Zod-validated arguments.                                                                                                      |
| Malicious peer joins a ceremony                            | Pairing pins Ed25519 identities with a one-time PSK; later sessions require the pinned identity. Unknown identities are refused, not prompted.                                                                                       |
| Peer substitutes a different payload mid-ceremony          | Every protocol message is bound to `sessionId` and the `SignRequest` hash. Mismatch aborts the ceremony and writes an audit row.                                                                                                     |
| Replay of an old signing request                           | Requests carry a nonce and TTL; presignatures are single-use and discarded on expiry.                                                                                                                                                |
| Device theft                                               | DB encrypted at rest (XChaCha20-Poly1305, Argon2id-wrapped DEK). Shares encrypted again with a per-share key. Platform unlock is optional and never the only factor for share material.                                              |
| Browser storage cleared                                    | Share-level encrypted backups; recovery drills in the Devices page; re-sharing from remaining parties when `n - lost >= t`.                                                                                                          |
| Supply chain compromise of a chain SDK                     | SDKs never see keys. Sighash is recomputed in the core from the serialized unsigned tx for families where that is tractable (EVM, Solana, Cosmos). Lockfiles pinned; `pnpm audit` and `cargo audit` in CI.                           |
| Malicious RPC                                              | Simulation results and balances are cross-checked across at least two endpoints when available; user-editable RPC pool with health tracking. Broadcast failures never mark a tx as confirmed.                                        |
| Fake token / lookalike address                             | Asset registry provenance; address first-seen tracking; unicode and prefix/suffix similarity warnings on approval screens.                                                                                                           |
| Local malware with user privileges                         | Out of scope for software alone. Recommended: run the agent and the automation CLI under a separate OS account or on a separate machine with only their own share.                                                                   |
| Time-of-check / time-of-use on caps                        | Caps count reserved spend (`Awaiting`, `Signing`) in addition to confirmed transactions.                                                                                                                                             |
| Audit log tampering                                        | Hash-chained rows; UI verifies the chain and shows breaks.                                                                                                                                                                           |

## 4. Cryptography

- Encryption at rest: XChaCha20-Poly1305. KDF: Argon2id (memory-hard parameters tuned per
  platform, never below OWASP minimums).
- Device identity: Ed25519. Channel: Noise IK with PSK at pairing, then Noise with pinned statics.
- TSS: CGGMP21 (secp256k1 ECDSA), FROST (Ed25519, secp256k1-tr). Only audited, maintained
  implementations; no bespoke protocol code. Pre-release crates are not accepted for signing
  schemes: the ECDSA scheme stays disabled until `cggmp24` ships a stable release (SPEC §5.1).
- Randomness: OS CSPRNG via `getrandom`. No userland PRNG seeding for key material.
- Secrets are `Zeroize`d on drop. WASM memory for secrets is allocated in the core's own arena
  and never handed to JS as views.

## 5. Privacy

- No telemetry, analytics or crash reporting. No remote fonts.
- Market data requests reveal which assets you look at to the data provider; the UI says so in
  Settings and lets you choose providers per family or disable them.
- RPC requests reveal your addresses to the RPC provider; users can supply their own endpoints.

## 6. Support gates

Nothing below moves to mainnet funds until its gate passes.

1. **Vault**: round-trip encryption tests; KDF parameter tests; zeroization checked with a
   memory-inspection test harness on native.
2. **TSS**: DKG, sign, refresh and re-share exercised across 2-of-3 and 3-of-5 in a local
   multi-process harness; ceremony fuzzing with dropped, reordered, duplicated and corrupted
   messages; signature verification against the chain's own verifier (viem / bitcoinjs /
   @solana/kit / cosmjs) for every curve.
3. **Transport**: pairing replay tests; unknown-identity rejection; payload-binding mismatch aborts.
4. **Policy**: property tests for composition order-independence; denylist-over-allowlist;
   reserved-spend accounting; D6 defense-in-depth denial.
5. **Chain adapters**: full lifecycle on each family's testnet with a `tss` wallet; sighash
   recomputation matches the adapter's.
6. **Agent**: red-team prompt set (injection via token names, calldata, memos, tool results)
   must produce zero unflagged proposals outside policy.
7. **Recovery**: device-loss drill documented and executed; share backup restore verified.

## 7. Reporting

Security issues: open a private report to the repository owner. Do not file public issues
containing exploit details.
