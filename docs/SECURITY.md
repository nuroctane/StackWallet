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

| Threat                                                     | Mitigation                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent is prompt-injected into sending funds to an attacker | D6: agent is at most one party; every agent-inclusive threshold needs a non-agent share. Policy caps and allowlists. Destinations sourced from untrusted content are flagged in the proposal. Hard per-session caps in the run loop.                                                                                                                                                                              |
| Agent exfiltrates keys                                     | Agent never receives keys, shares, provider keys, or RPC credentials. Tools are a fixed allowlist with Zod-validated arguments.                                                                                                                                                                                                                                                                                   |
| Malicious peer joins a ceremony                            | Pairing pins the Ed25519 identity and X25519 Noise static under a one-time PSK; later sessions are Noise IK against the pinned static. Unknown or revoked statics are refused before any application byte is read, not prompted.                                                                                                                                                                                  |
| Attacker on the LAN during pairing                         | The pairing handshake is `IKpsk2` keyed with the QR one-time code, so observing or injecting traffic without the QR cannot complete it; the code is single-use and expires. mDNS is a hint only and never pins anything.                                                                                                                                                                                          |
| Malicious WebRTC signalling via a relay                    | `Signal` frames are opaque to the relay and unauthenticated by design; the browser validates SDP/ICE at the WebRTC layer, and the data channel still requires the Noise handshake against a pinned static.                                                                                                                                                                                                        |
| Pasted pairing code points the browser at an attacker      | The SDP in a `stackwallet-rtc:` blob only decides where bytes go; it carries no trust. The core's `IKpsk2` handshake against the offer's static and one-time code is what pins a peer, and the browser's carrier gathers host candidates only (no STUN/TURN), so a code cannot route a session through a third party.                                                                                             |
| Replay or reorder of channel traffic                       | Noise nonces are strictly increasing per direction; any decrypt failure closes the session rather than skipping the message. A relaying device can drop or delay envelopes (aborts the ceremony) but cannot forge them.                                                                                                                                                                                           |
| Peer substitutes a different payload mid-ceremony          | Every protocol message is bound to `sessionId` and the `SignRequest` hash. Mismatch aborts the ceremony and writes an audit row.                                                                                                                                                                                                                                                                                  |
| Attacker who saw the QR races the real scanner             | Residual risk of one-time-PSK pairing: a QR observer learns the code and can connect first. The issuer therefore prints the pinned peer's identity fingerprint for out-of-band comparison, and `devices` shows what was pinned.                                                                                                                                                                                   |
| Paired device goes rogue                                   | Pairing plus group membership is currently full signing authority within threshold: the CLI `serve` path is operator-run and does not yet evaluate policies per request. The policy gate arrives with the `SignRequest` lifecycle UI.                                                                                                                                                                             |
| Replay of an old signing request                           | Ceremony sessions carry an id and a TTL checked at admission; mid-ceremony stalls are bounded by the carrier idle timeout. Per-request nonces and presignature TTL land with the lifecycle and resumption work (not yet implemented).                                                                                                                                                                             |
| Device theft                                               | DB encrypted at rest (XChaCha20-Poly1305, Argon2id-wrapped DEK). Shares encrypted again with a per-share key. Platform unlock is optional and never the only factor for share material.                                                                                                                                                                                                                           |
| Browser storage cleared                                    | Share-level encrypted backups; recovery drills in the Devices page; re-sharing from remaining parties when `n - lost >= t`.                                                                                                                                                                                                                                                                                       |
| Supply chain compromise of a chain SDK                     | SDKs never see keys. Sighash is recomputed in the core from the serialized unsigned tx for families where that is tractable (EVM, Solana, Cosmos). Lockfiles pinned; `pnpm audit` and `cargo audit` in CI.                                                                                                                                                                                                        |
| Malicious RPC                                              | Simulation results and balances are cross-checked across at least two endpoints when available; user-editable RPC pool with health tracking. Broadcast failures never mark a tx as confirmed.                                                                                                                                                                                                                     |
| Fake token / lookalike address                             | Asset registry provenance; address first-seen tracking; unicode and prefix/suffix similarity warnings on approval screens.                                                                                                                                                                                                                                                                                        |
| Key export without the user noticing later                 | `reveal` runs in the core: passphrase re-verified, exposure sealed in the vault's append-only provenance table, then the secret is returned. A wrong passphrase reveals and records nothing. The red `exposed` tag cannot be cleared and travels with the wallet in set transfers. Clipboard copies are wiped after 30s if unchanged.                                                                             |
| Stolen or replayed directory-set bundle                    | Sealed to one device's pinned X25519 static (ephemeral ECDH, HKDF, XChaCha20-Poly1305) and signed by the sender's identity; the recipient refuses unknown or revoked senders, bundles addressed elsewhere, and sets already present. Both ends re-enter the vault passphrase. A bundle holds plaintext phrases only inside the AEAD.                                                                              |
| Spoofed or look-alike name-service name                    | Names are shown only after a reverse lookup is confirmed by a forward lookup to the same address (ENS via the Universal Resolver, SNS by owner and reverse-record checks on chain, ICNS and THORName by forward query). Control, bidi and zero-width characters refuse the name; other non-ASCII names carry a visible marker. The raw address stays one click away and the user's tag is always shown alongside. |
| Hostile NFT metadata or media                              | Metadata text is stripped of control/bidi characters and length-capped. Media is fetched over CORS without credentials or referrer, type-checked (raster or SVG only) and size-capped, then shown as a blob; no HTML, iframes or animation URLs are rendered. Hosts without CORS may serve a plain `<img>` only when the media setting is `all`. Spam-flagged items never load media.                             |
| Local malware with user privileges                         | Out of scope for software alone. Recommended: run the agent and the automation CLI under a separate OS account or on a separate machine with only their own share.                                                                                                                                                                                                                                                |
| Time-of-check / time-of-use on caps                        | Caps count reserved spend (`Awaiting`, `Signing`) in addition to confirmed transactions.                                                                                                                                                                                                                                                                                                                          |
| Audit log tampering                                        | Hash-chained rows; UI verifies the chain and shows breaks.                                                                                                                                                                                                                                                                                                                                                        |

## 4. Cryptography

- Encryption at rest: XChaCha20-Poly1305. KDF: Argon2id (memory-hard parameters tuned per
  platform, never below OWASP minimums).
- Device identity: Ed25519 (signatures only). Channel static: X25519 derived from the same seed by
  HKDF with a distinct label, never by converting the Ed25519 key. Channel:
  `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` at pairing, `Noise_IK_25519_ChaChaPoly_BLAKE2s` after,
  via `snow` with pure-Rust primitives so the same code runs in the browser build. Both sides sign
  the handshake hash and their own Noise static with the identity key in the first frame, so a
  Hello cannot be reflected back at its author.
- TSS: CGGMP21 (secp256k1 ECDSA), FROST (Ed25519, secp256k1-tr). Only audited, maintained
  implementations; no bespoke protocol code. Pre-release crates are not accepted for signing
  schemes: the ECDSA scheme stays disabled until `cggmp24` ships a stable release (SPEC §5.1).
- Randomness: OS CSPRNG via `getrandom`. No userland PRNG seeding for key material.
- Secrets are `Zeroize`d on drop, with one documented exception: `snow` holds the in-progress
  handshake keys without zeroizing (library limitation). The wasm identity seed never crosses
  the JS boundary: `WasmVault::create_identity` mints and seals it in one call and
  `WasmVault::identity` reconstitutes a session identity inside wasm memory while the vault is
  unlocked. JS only ever holds opaque handles. Everything else — Noise statics, DEK/KEK,
  shares — stays in Rust-owned memory.
- The pairing one-time code's single-use property is enforced by the carrier, not the
  stateless core: the CLI issuer burns the offer after one success, and the browser's pairing
  controller does the same: a rejected answer paste keeps the offer, but once an answer is
  accepted the offer is spent whether the handshake succeeds or fails, and it is never
  re-emitted after a `paired` event.
- The browser's device list in localStorage is a cache, not the trust root. The pinned device
  table is sealed in the vault under the `device-table` label; the core validates every table
  it loads or saves (each id is the derivation of its identity key, Noise statics are 32 bytes,
  names are bounded, ids are unique, at most 256 entries) and refuses the write otherwise. The
  UI replaces its cache with the core's copy on unlock and refuses every table change while the
  vault is locked.

## 5. Privacy

- No telemetry, analytics or crash reporting. No remote fonts.
- Market data requests reveal which assets you look at to the data provider; the UI says so in
  Settings and lets you choose providers per family or disable them.
- RPC requests reveal your addresses to the RPC provider; users can supply their own endpoints.
- Name lookups send each address to the ENS/Solana/Osmosis RPC pools and to a THORChain Midgard
  gateway; collectible lists send it to the chain's Blockscout instance or Solana RPC.
- Every remote collectible image tells its host this device's IP address. The collectibles
  element offers `all`, `vetted only` (CORS hosts only) and `off`; spam-flagged items never
  load media because airdropped images are a known deanonymization beacon.
- The web build sends `Cross-Origin-Embedder-Policy: credentialless` (not `require-corp`) so
  images from hosts without CORP can load without cookies; scripts and fonts stay same-origin.

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
