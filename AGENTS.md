# StackWallet — agent guide

Local-first, self-custodial, agentic harness for crypto wallets on every chain. Web app (static)
and Tauri 2 desktop first; Android/iOS later through the same Rust core. The specification is
`docs/SPEC.md`; the threat model is `docs/SECURITY.md`; visual rules are `docs/DESIGN.md`;
the chain adapter contract is `docs/CHAINS.md`.

## Locked decisions (non-negotiable)

- **D1** Shared wallets are real threshold signatures (CGGMP21 for secp256k1 ECDSA, FROST for
  Ed25519 and secp256k1-Taproot). No party ever holds a complete private key for a `tss` wallet.
- **D2** Key material, encryption, TSS, the policy engine, transport and the audit log live in the
  Rust core (`crates/stackwallet-core`). TypeScript owns UI and chain-SDK glue only. Chain
  adapters never see private keys or shares.
- **D3** No server. The web app is a static bundle; devices talk to each other directly
  (LAN discovery + WebRTC, QR pairing). Market data is fetched by the client from public APIs.
- **D4** Model providers are BYOK cloud (Anthropic, OpenAI, Google, OpenRouter) behind one
  abstraction (Vercel AI SDK). Provider keys live in the encrypted vault.
- **D5** Chain families in v1: EVM, Bitcoin family, Solana, Cosmos SDK. New families are additive
  implementations of `ChainAdapter`.
- **D6** The agent cannot move funds alone. An agent session is at most one TSS party, and every
  threshold that includes an agent share must also require a non-agent share. The core validates
  this at wallet creation; policy double-checks it at signing time.
- **D7** Design is the night glass family (see `docs/DESIGN.md`): near-black paper, white/gray
  ink, hairline edges, JetBrains Mono, ease-out motion under 300ms. Night glass is the default
  theme and the house chrome never adds blue/indigo/purple on its own. Users may switch to any
  NurCLI preset or edit every colour token, globally or per layout (theme engine in
  `packages/ui/src/theme`); the `danger` role keeps its meaning (destructive, exposed keys,
  signing danger) whatever colour it is given.
- **D8** No telemetry, no analytics, no remote fonts. Builds must be reproducible.
- **D9** No time estimates anywhere in docs, specs, issues or commit messages. Work is organized
  in phases only.

## Layout

```
crates/stackwallet-core     pure Rust: model, intent, policy, lifecycle, audit, vault, tss, transport, store
crates/stackwallet-wasm     wasm-bindgen surface for the browser build of the core
crates/stackwallet-cli      headless binary: pairing, signing party, scheduler ("automation device")
apps/desktop/src-tauri      Tauri 2 crate (`stackwallet-tauri`) wrapping the core natively
packages/core-client        TS types (Zod) + one CoreClient API over WASM or Tauri IPC
packages/chains             ChainAdapter contract, registry, shared tx model
packages/chains-*           per-family adapters (evm, bitcoin, solana, cosmos)
packages/agent              providers, tools, run loop, grants
packages/automations        triggers, actions, scheduler
packages/market             price aggregation, asset registry, candles, valuation
packages/ui                 design tokens and components (Tailwind v4)
apps/web                    Vite React SPA; the desktop shell loads the same bundle
docs                        SPEC, SECURITY, DESIGN, CHAINS
```

`cargo test` runs the default members (core + cli). The Tauri crate is excluded from
`default-members` because it needs platform webview libraries; build it with
`pnpm --filter @stackwallet/desktop desktop` or `cargo check -p stackwallet-tauri`.

## Conventions

- TypeScript strict everywhere. Zod-validate every payload that crosses a package boundary
  or comes from a network, a model, or a chain.
- INTEGER ms timestamps. TEXT uuid primary keys. `PRAGMA foreign_keys = ON`.
- Every transaction state transition writes an `audit_log` row (hash-chained). A transition
  without an audit row is a ship-blocker.
- The policy engine runs inside the core before any share participates in a ceremony. UI code
  must never gate signing on its own checks alone.
- Anything the model reads (token names, calldata decodes, web content) is untrusted input.
  Sanitize before it reaches the prompt; flag destinations that are not in the user's allowlists.
- Comments explain why, never what. No task or PR references in code comments.
- Workspace artifacts (plans, logs, scratch) live under `.nur/` (gitignored).

## Ship / push / deploy (mandatory)

When the user says **ship**, **push**, **deploy**, **put on main**, **release**, **publish**, or similar:

1. Read and execute **`C:\Users\david\.agents\SHIP.md`**
2. Or run: `powershell -File $env:USERPROFILE\.agents\ship.ps1 -Repo StackWallet [-Message "..."]`
3. Skill: `ship-deploy`

**Pipeline for this repo:** Commit on Laboratory → Push `origin main` → Backup 7z to `D:\BACKUP\CODE Backups\StackWallet\`
Pattern: `StackWallet_YYYY-MM-DD_<sha>_<slug>.7z` (exclude target, .git, node_modules, dist, .next, .nur)

Never bare-push without backup. Report commit + remote + full backup path.

**Deploy (web):** remote is private `github.com/nuroctane/StackWallet`. Every push to `main`
runs `.github/workflows/deploy.yml`, which builds `apps/web` and deploys the assets-only
Worker `stackwallet` (config in `apps/web/wrangler.jsonc`) to
`https://stackwallet.civetadeicollegium.workers.dev`, then verifies the page is live and
opens+closes a `deployment` issue. It needs the repo secrets `CLOUDFLARE_API_TOKEN`
(Workers Scripts: Edit) and `CLOUDFLARE_ACCOUNT_ID`; missing credentials fail the workflow.
Successful deployments verify every published build file before notifying GitHub.
Do not also run `wrangler deploy` by hand after a push (double deploy).
Manual fallback: `pnpm --filter @stackwallet/web build; pnpm --filter @stackwallet/web run deploy`.

**Windows shell note:** this machine's `PATH` is longer than cmd.exe's 8191-char limit, so pnpm
lifecycle scripts fail with `'node' is not recognized`. Set a trimmed `$env:Path` (nodejs, pnpm,
cargo, Git, System32) in the same command before running `pnpm`.
The Bitcoin WASM dependency also needs Clang; include the installed LLVM `bin` directory in
that trimmed path when building the browser core.
