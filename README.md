# StackWallet

Local-first, self-custodial, agentic harness for crypto wallets on every chain.

- Wallets organized in folders and subfolders, each with policies, automations and agent grants.
- Real threshold signatures: your devices and your agent each hold a share; no single place ever
  holds a complete key. The agent cannot move funds without a human co-signature.
- EVM, Bitcoin family, Solana and Cosmos SDK chains behind one adapter contract.
- Agent console (BYOK cloud models) whose every proposal goes through simulation, policy and
  the approval queue before a signing ceremony starts.
- Market data and charts for every asset you hold, fetched directly by the client.
- No server. The web app is a static bundle; the desktop app is Tauri 2 around the same Rust core.

Read `docs/SPEC.md` for the full specification and `docs/SECURITY.md` for the threat model.

## Develop

```powershell
pnpm install
cargo test                      # core + cli
pnpm check                      # typecheck every package
pnpm test                       # vitest across packages
pnpm dev                        # web shell at http://127.0.0.1:1420
pnpm desktop                    # Tauri dev window (needs Rust + WebView2)
```

Browser build of the core: `rustup target add wasm32-unknown-unknown` once, then
`pnpm --filter @stackwallet/web build:wasm` (needs `wasm-pack` and Clang on `PATH`
for the Bitcoin library's public-key validation code). On Windows, add your LLVM `bin`
directory to the trimmed path used for pnpm lifecycle commands, and set
`$env:AR_wasm32_unknown_unknown` to the full path of `llvm-ar.exe` before a WASM build.

Workspace elements include **workspace activity** (local events, with mouse/touch terrain
navigation), **balance history** (local totals and readable snapshots), and **transaction history**
(local core signing records plus paginated public EVM/Bitcoin/Solana/Cosmos reads).
Narrow panes retain full details through wrapping, stacked tables and expandable rows.
See [history coverage](docs/CHAINS.md#read-only-transaction-history) for endpoint requirements
and decoding limits.
