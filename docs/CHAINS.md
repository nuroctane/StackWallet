# StackWallet — Chain adapter contract

Adapters live in `packages/chains-<family>` and implement the `ChainAdapter` interface from
`packages/chains`. They never see private keys or shares. They build unsigned transactions,
compute sighashes, simulate, attach signatures, broadcast and report status.

## Identifiers

- Chain ids are CAIP-2: `eip155:1`, `bip122:000000000019d6689c085ae165831e93` (first 32 hex
  chars of the genesis block hash), `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`, `cosmos:osmosis-1`.
- The bundled list is `CHAIN_CATALOG` in `packages/chains/src/catalog.ts`; `chainsForFamily()`
  slices it per adapter. Family-specific facts (bech32 prefix, base denom, address algorithm,
  base58 version bytes) live in `ChainInfo.extra`.
- Asset refs are `<chainId>:<kind>:<identifier>` where kind ∈ `native | erc20 | erc721 | erc1155 |
spl | spl2022 | ibc | factory | cw20 | brc20 | rune`.
- Public keys are `{ curve: 'secp256k1' | 'ed25519' | 'secp256k1-tr', hex }`.

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

Current state (`packages/chains/src/rpc.ts`):

- `MemoryRpcPool` keeps, per endpoint, `healthy`, `latencyMs`, `lastErrorAtMs`, a rolling
  `errorRate` over the last 10 attempts, and `lastBlock` (set through `markBlock` when an
  adapter learns a head for free: Solana `getBalance` returns its slot; EVM, Bitcoin and Cosmos
  reads do not carry one and no extra request is made for it). `pick` ranks healthy endpoints
  by error rate, then latency, and round-robins ties; a failed endpoint is re-admitted after a
  60 s cooldown, and when every endpoint is down the least recently failed one is still tried.
- Endpoints set through `setEndpoints` that are not catalog defaults carry `custom: true`;
  `resetEndpoints(chainId)` restores the defaults and `allChainIds()` lists configured chains.
  Editing a list keeps the health history of the urls that stay.
- `withFailover` tries endpoints in rank order until one succeeds; only thrown errors count
  against an endpoint. Every body is read under the request timeout and capped at 1 MiB.
- `withCrossCheck` asks two endpoints run by different operators (registrable domain, so
  `eth.drpc.org` and `lb.drpc.org` count as one witness) in parallel and returns
  `{ value, provenance }`. The native balance in every family's `getBalances` goes through it
  and each `Holding` carries a `provenance`: `agreed` (both answered alike), `disagreed` (a
  catalog default beats a user-added `custom` endpoint, otherwise the faster answer is kept; the
  other amount is recorded, and neither endpoint is marked failed because a one-block lag is not
  malice) or `single` (one endpoint configured, both under the same operator, or the second
  request failed). Bitcoin and Cosmos treat "not indexed here" (404, and 400 for LCDs) from
  exactly one side as a non-answer and keep the other side as `single`. Cosmos cross-checks the
  whole bank response and flags only the denoms that differ. Simulation cross-checks arrive with
  transaction building.
- `scripts/probe-rpcs.ts` (`pnpm probe:rpcs`) hits every catalog endpoint once and verifies it
  serves the claimed chain (`eth_chainId`, Solana `getGenesisHash`, Cosmos `node_info.network`,
  Bitcoin `/blocks/tip/height`). It cannot check CORS, so a browser may still reject an endpoint
  the probe accepts.

## Per-family notes

Current state: every adapter extends `BaseAdapter` (`packages/chains/src/base-adapter.ts`),
which supplies `chains()` from the catalog, the default `MemoryRpcPool`, `requireChain`
(throws `UnknownChainError`), shared fetch options and the `NotImplementedError` stubs for the
signing path. Each family implements `deriveAddress`, `validateAddress`, native-asset
`getBalances` and `status` with `@noble/hashes` and `@scure/base` only, through the shared
`fetchJson` / `fetchJsonRpc` helpers, `withFailover` and `withCrossCheck` over the `RpcPool`.
The remaining methods (`getHistory`, `build`, `simulate`, `sighashes`, `attach`, `broadcast`)
throw `NotImplementedError` until the family SDKs named below are added; they never return a
fake success. Public keys arrive as `{ curve, hex }`; compressed secp256k1 keys are decompressed with
field arithmetic in `packages/chains/src/keys.ts`, so no curve library is needed for addresses.

### EVM (`chains-evm`, viem)

- Implemented sends use `prepareEvm` / `broadcastEvm` with the Rust core's checked EIP-1559
  serialization and signing; the generic adapter signing stubs are still unsupported.
- Balances include native assets and explicitly tracked ERC-20 contracts. `balanceOf(address)`
  returns must be exactly one ABI word; both reads use RPC cross-checks and expose disagreement.
  A token read failure produces an unavailable token row without hiding native balances.
  No indexer or automatic token discovery is used. Symbols and decimals are read from the
  contract, bounded (12 printable ASCII characters, 0–36 decimals), and treated as untrusted
  display data. Chain and full contract address remain the token's identity.
- Registry: chainlist-derived JSON bundled at build time plus user-added chains.
- Addresses: keccak256 of the uncompressed key, EIP-55 checksum on output; validation accepts
  all-lower or all-upper hex and rejects mixed case with a bad checksum.
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
  and P2TR (Schnorr via FROST secp256k1-tr). DOGE has no segwit, so it gets P2PKH (version
  `0x1e`); legacy P2PKH/P2SH addresses validate on every network.
- A `secp256k1-tr` public key handed to the adapter is the 32-byte x-only _output_ key: the
  core applies the taproot tweak before the key reaches TypeScript.
- Reads use the mempool.space REST shape (`/address/{addr}`, `/tx/{hash}/status`). Dogecoin
  ships with no default endpoint; the user supplies one.
- PSBT throughout; coin control; RBF enabled by default; fee estimation from mempool.space.
- One `SignRequest` per input. Taproot key-path spends use BIP340 sighash with the tweaked key;
  the FROST implementation applies the taproot tweak to the group key.
- Status via Electrum subscriptions or mempool.space polling.

Current Bitcoin send coverage is single-key native P2WPKH on Signet only. The endpoint's full
genesis hash is checked before dependent reads. Preparation selects up to eight confirmed UTXOs,
checks outspend status and fetches each complete funding transaction. Rust independently checks
its transaction ID, output script and value, rejects coinbase funding, duplicate inputs, dust
and excessive fees, and constructs a PSBT with SIGHASH_ALL. Only one recipient and optional
change to the same sender are produced. The fee rate preview accepts 1–100 sat/vbyte and total
fees are capped at 100,000 sats. Recipient and change must be canonical `tb1` P2WPKH addresses;
minimum output value is 294 sats. Keys remain in the vault.

Local funding validation is not network simulation. The simulation flag is false, and
`RequireSimulationPass` refuses these proposals. Before approval each selected input must still
be observed unspent; active proposals reserve inputs in the core. Broadcast errors and absent
index entries remain pending under the core transaction ID, with no automatic resend, expiry
or release of spend reservations. Restart resumes tracking. Six observed confirmations are
required; RPC observations are not chain proofs. RBF is signaled but replacement is not
implemented. Funded Signet confirmation, explicit coin control, Taproot, threshold signing,
mainnet and other Bitcoin-family sends remain outside this increment.

### Solana (`chains-solana`, @solana/kit)

Current send coverage is single-key native SOL on Devnet only. `prepareSolana` produces a bounded
legacy transfer and simulation for the core ledger; the core independently constructs the wire
message and signs after policy re-evaluation and passphrase approval. The adapter does not receive
key bytes. Every signing-flow RPC verifies `getGenesisHash` against the requested CAIP-2 cluster.
RPC integer amounts outside JavaScript's exact range are refused. Simulation errors and transfers
to executable or non-System-owned accounts appear in approval. The native message has no priority
fee instruction; its fee preview comes from `getFeeForMessage`.

Before approval, a stale blockhash expires the proposal. A broadcast timeout retains the core's
signature as pending; finality polling decides confirmed/failed, and finalized height beyond the
last valid height plus a missing signature in a history response at least as recent as the
finalized slot decides expired. These dependent observations share one verified RPC endpoint.
Restarted signed/broadcast records
resume signature tracking without an automatic resend. `@solana/kit` is a pinned test dependency
for independent wire decoding; runtime assembly is checked separately in Rust and TypeScript.
Mainnet sends, TSS ceremonies, SPL, versioned messages and swaps remain disabled/unimplemented.
The remaining bullets describe target coverage:

- Versioned transactions, address lookup tables, compute budget and priority fee instructions.
- SPL and Token-2022 (transfer fees, hooks surfaced as warnings). Associated token account
  creation folded into the intent's fee preview.
- Simulation: `simulateTransaction` with account diffs for asset deltas.
- Sighash: the serialized message bytes; Ed25519 via FROST.
- Blockhash expiry requires rebuilding, fresh policy evaluation and fresh approval before a
  ceremony resumes; an old approval never authorizes a replacement message.

### Cosmos SDK (`chains-cosmos`, cosmjs, chain-registry)

Current send coverage is single-key native `uosmo` bank transfers on Osmosis Testnet only.
`prepareCosmos` checks the LCD's `node_info.network`, reads a funded BaseAccount, estimates gas
and simulates the final bounded fee/message. The core independently encodes exactly one
`MsgSend`, one secp256k1 DIRECT signer, one `uosmo` fee and a timeout height, then signs after
policy re-evaluation and passphrase approval. Account numbers, sequences and amounts remain
canonical uint64 strings; gas and timeout heights are bounded exact integers. Addresses must be
canonical lowercase `osmo` bech32. Fees and gas are capped, and arbitrary messages, memos,
fee grants and additional signers are not accepted. `cosmjs-types` supplies pinned public codecs;
CosmJS cryptography is a test dependency for independent verification of the core signature.

Before signing, a height-pinned account read must still match the prepared account number and
sequence and the timeout must remain valid. The LCD's ABCI account-store query must return the
requested height and account key in its JSON response; unavailable or mismatched observations
refuse signing. This avoids relying on metadata headers that LCD CORS hides from browsers. Broadcast uses
`BROADCAST_MODE_SYNC`. Uncertain responses keep the core transaction hash pending and restart
resumes tracking without an automatic resend. An indexed positive-height result decides success
or failure. A missing index entry alone never proves expiry: after timeout, an account observation
pinned to the latest height must show the original sequence unchanged. An advanced sequence or
an unavailable historical read leaves the spend reserved. These dependent reads share one
verified LCD endpoint. Funded testnet confirmation is not yet verified. Mainnet and threshold
sends remain disabled. The remaining bullets describe target coverage:

- Chain metadata, denoms, gas prices and bech32 prefixes from chain-registry, bundled and
  user-extendable. Until then the catalog carries `bech32Prefix`, `baseDenom`, `gasPrice` and
  `addressAlgo` per chain.
- Addresses: `secp256k1` chains use ripemd160(sha256(compressed key)); `ethsecp256k1` chains
  (Injective) use the last 20 bytes of keccak256(uncompressed key). Both are bech32 with the
  chain prefix; 20-byte accounts and 32-byte module accounts validate.
- Reads use the LCD: `/cosmos/bank/v1beta1/balances/{addr}` (non-native denoms become
  `<chainId>:ibc:<hash>`, `<chainId>:factory:<path>` or `<chainId>:native:<denom>`) and
  `/cosmos/tx/v1beta1/txs/{hash}`.
- Messages: bank send, IBC transfer (with channel discovery), staking delegate/undelegate/
  redelegate, distribution withdraw, gov vote, CosmWasm execute.
- Simulation: `simulate` for gas; asset deltas from message semantics plus balance diff.
- Sighash: SIGN_MODE_DIRECT `SignDoc` SHA-256; secp256k1 ECDSA via CGGMP21. Ed25519-keyed chains
  are treated as a later extension.
- IBC transfers track the acknowledgement on the destination chain before `Confirmed`.

## Names and collectibles

Both live outside the adapters (`packages/names`, `packages/collectibles`) and reuse the
registry's RPC pools, so a user's custom endpoints apply to them too.

| Service / source | Covers                        | How it is read                                                                                    |
| ---------------- | ----------------------------- | ------------------------------------------------------------------------------------------------- |
| ENS              | every EVM account             | Universal Resolver `reverse(bytes,uint256)` on Ethereum mainnet; forward-verified by the resolver |
| SNS              | Solana                        | favourite-domain, name and reverse accounts via `getMultipleAccounts`; owner and hash checked     |
| ICNS             | every bech32 Cosmos account   | `primary_name` on the Osmosis resolver, then `address{name, bech32_prefix}` must match            |
| THORName         | any address THORChain aliases | Midgard `rlookup`, then `lookup` must list the address                                            |
| Blockscout       | 13 EVM chains                 | `/api/v2/addresses/{addr}/nft`; `reputation` flags spam                                           |
| Metaplex         | Solana                        | token accounts (needs an RPC that allows `getTokenAccountsByOwner`) and metadata PDAs             |

L2 primary names (Basenames and other ENSIP-19 chains) need CCIP-Read and are not resolved yet.
Bitcoin ordinals need an indexer API key and Cosmos NFTs have no keyless indexer, so both show a
reason instead of an empty grid.

## Adding a family

1. Create `packages/chains-<family>` implementing `ChainAdapter`.
2. Register curve requirements so DKG for a new curve can be added to existing `tss` wallets.
3. Add registry data and a testnet.
4. Pass the chain-adapter support gate in `SECURITY.md` section 6.
