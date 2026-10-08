# Cross-language fixtures

JSON consumed by both `crates/stackwallet-core` tests (via `include_str!`) and
`packages/core-client` tests (via import). They pin the wire format between the Rust core and
TypeScript: if serde output and the Zod schemas disagree, one of these fails.

- `policies.json`: three `Policy` objects covering every `Rule` variant.
- `intent-transfer.json`, `intent-swap.json`: `TxIntent` with agent and automation proposers.
- `context.json`: `PolicyContext` with reserved spend and an agent-inclusive 2-of-3 key group.
- `decision-allow.json`: the `Decision` the core must return for `intent-transfer.json`.
- `decision-deny.json`: the `Decision` the core must return for `intent-swap.json`.

Regenerate the decision files only by running the core and reviewing the diff.
