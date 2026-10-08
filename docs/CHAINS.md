# StackWallet — Chain adapter contract

Adapters live in `packages/chains-<family>` and implement the `ChainAdapter` interface from
`packages/chains`. They never see private keys or shares. They build unsigned transactions,
compute sighashes, simulate, attach signatures, broadcast and report status.

## Identifiers

- Chain ids are CAIP-2: `eip155:1`, `bip122:000000000019d6689c085ae165831e9934ff763ae46a2a6c172b3f1b60a8ce26f`,
  `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`, `cosmos:osmosis-1`.
- Asset refs are `<chainId>:<kind>:<identifier>` where kind ∈ `native | erc20 | erc721 | erc1155 |
spl | spl2022 | ibc | factory | cw20 | brc20 | rune`.
- Public keys are `{ curve: 'secp256k1' | 'ed25519' | 'secp256k1-tr', bytes: hex }`.

## Interface

```ts
interface ChainAdapter {
  family: 'evm' | 'bitcoin' | 'solana' | 'cosmos';
  chains(): ChainInfo[];
  deriveAddress(pub: PublicKey, chain: ChainId): Address;
  getBalances(addr: Address, chain: ChainId): Promise<Holding[]>;
  getHistory(addr: Address, chain: ChainId, cursor?: string): Promise<Page<TxRecord>>;
  build(intent: TxIntent, chain: ChainId): Promise<UnsignedTx>;
  simulate(tx: UnsignedTx): Promise<Simulation>;
  sighashes(tx: UnsignedTx): SignRequest[];
  attach(tx: UnsignedTx, sigs: Signature[]): SignedTx;
  broadcast(tx: SignedTx): Promise<TxHash>;
  status(hash: TxHash, chain: ChainId): Promise<TxStatus>;
  rpc: RpcPool;
}
```

`TxIntent` variants: `transfer`, `contractCall`, `swap`, `stake`, `unstake`, `claim`,
`ibcTransfer`, `psbt`. All amounts are decimal strings in base units; the UI formats them.

`Simulation` must include `assetDeltas[]` (per asset ref, signed base-unit amounts), `fee`,
`warnings[]` (approval granted, unlimited allowance, contract unverified, destination is a
contract, etc.), and `ok`.

## RpcPool

User-editable list of endpoints per chain with health tracking (latency, error rate, last
block). Reads rotate across healthy endpoints; balance and simulation results are cross-checked
on two endpoints when two are healthy. Broadcast goes to every healthy endpoint.

## Per-family notes

### EVM (`chains-evm`, viem)

- Registry: chainlist-derived JSON bundled at build time plus user-added chains.
- EIP-1559 fees with legacy fallback. Nonce management per account with pending-aware queries.
- Decoding: ERC-20/721/1155 transfers and approvals, 4byte signatures, Sourcify ABIs when
  verified. Permit / Permit2 detection surfaces as a warning.
- Simulation: `eth_call` plus `debug_traceCall` (callTracer) where supported; asset deltas from
  logs and balance diffs.
- Sighash: keccak256 of the RLP-serialized typed transaction. The core recomputes it from the
  serialized unsigned bytes.
- Signature: secp256k1 ECDSA with recovery id; CGGMP21 output is normalized to low-s.

### Bitcoin family (`chains-bitcoin`, bitcoinjs-lib, Electrum / mempool.space)

- Networks: BTC mainnet/testnet4/signet, LTC, DOGE. Address types P2WPKH (ECDSA via CGGMP21)
  and P2TR (Schnorr via FROST secp256k1-tr).
- PSBT throughout; coin control; RBF enabled by default; fee estimation from mempool.space.
- One `SignRequest` per input. Taproot key-path spends use BIP340 sighash with the tweaked key;
  the FROST implementation applies the taproot tweak to the group key.
- Status via Electrum subscriptions or mempool.space polling.

### Solana (`chains-solana`, @solana/kit)

- Versioned transactions, address lookup tables, compute budget and priority fee instructions.
- SPL and Token-2022 (transfer fees, hooks surfaced as warnings). Associated token account
  creation folded into the intent's fee preview.
- Simulation: `simulateTransaction` with account diffs for asset deltas.
- Sighash: the serialized message bytes; Ed25519 via FROST.
- Blockhash expiry handled by rebuilding the message before a stale ceremony resumes.

### Cosmos SDK (`chains-cosmos`, cosmjs, chain-registry)

- Chain metadata, denoms, gas prices and bech32 prefixes from chain-registry, bundled and
  user-extendable.
- Messages: bank send, IBC transfer (with channel discovery), staking delegate/undelegate/
  redelegate, distribution withdraw, gov vote, CosmWasm execute.
- Simulation: `simulate` for gas; asset deltas from message semantics plus balance diff.
- Sighash: SIGN_MODE_DIRECT `SignDoc` SHA-256; secp256k1 ECDSA via CGGMP21. Ed25519-keyed chains
  are treated as a later extension.
- IBC transfers track the acknowledgement on the destination chain before `Confirmed`.

## Adding a family

1. Create `packages/chains-<family>` implementing `ChainAdapter`.
2. Register curve requirements so DKG for a new curve can be added to existing `tss` wallets.
3. Add registry data and a testnet.
4. Pass the chain-adapter support gate in `SECURITY.md` section 6.
