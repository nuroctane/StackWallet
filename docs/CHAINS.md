# StackWallet — Chain adapter contract

Adapters live in `packages/chains-<family>` and implement the `ChainAdapter` interface from
`packages/chains`. They never see private keys or shares. They build unsigned transactions,
compute sighashes, simulate, attach signatures, broadcast and report status.

## Identifiers

- Chain ids are CAIP-2: `eip155:1`, `bip122:000000000019d6689c085ae165831e93` (first 32 hex
  chars of the genesis block hash), `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`, `cosmos:osmosis-1`,
  `tron:0x2b6653dc`.
- The bundled list is `CHAIN_CATALOG` in `packages/chains/src/catalog.ts`; `chainsForFamily()`
  slices it per adapter. Family-specific facts (bech32 prefix, base denom, address algorithm,
  base58 version bytes) live in `ChainInfo.extra`.
- The catalog has two halves. `catalog-curated.ts` holds hand-checked entries.
  `catalog-generated.ts` is written by `scripts/sync-chains.ts` (`pnpm sync:chains`). It covers
  every chain on DefiLlama's list (L1s, alt-L1s, L2s, L3s, sidechains, appchains) that an
  existing family can serve: EVM chains from chainlist, Cosmos SDK chains from the Cosmos chain
  registry, and SVM networks. It also lists the Blockscout v2 indexers from Blockscout's
  directory. Every endpoint the generator keeps answered live with the chain identity it
  claims (`eth_chainId`, genesis hash, `node_info.network`), answered a browser CORS preflight
  from the deployed origin, and is not marked as tracking users on chainlist. The fastest
  three are kept. Curated entries win on conflict.
- `CHAIN_META` adds DefiLlama facts to both halves: `layer` (L1, L2, L3, sidechain, parachain,
  subnet, appchain), `parent` (the settlement chain), `priceId` (the native asset's CoinGecko
  id, used ahead of the symbol because symbols collide) and `halted` (no new block for 14 days
  at generation time). Chains with no endpoint that passed are still listed so their balances
  can be read after the user adds an endpoint. `LLAMA_UNSUPPORTED` lists the DefiLlama chains
  that need a new family.
- The generated file is committed, so builds stay reproducible and the app fetches no chain
  registry at runtime (D8). Regenerate it from the repo root and review the diff.
- Asset refs are `<chainId>:<kind>:<identifier>` where kind ∈ `native | erc20 | erc721 | erc1155 |
spl | spl2022 | ibc | factory | cw20 | brc20 | rune | trc20`.
- Public keys are `{ curve: 'secp256k1' | 'ed25519' | 'secp256k1-tr', hex }`.

## Interface

```ts
interface ChainAdapter {
  family: ChainFamily; // 44 families; see Signing families and Read-only families below
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
  Bitcoin `/blocks/tip/height`). It does not check CORS. `pnpm sync:chains` does check CORS for
  the endpoints it generates.

## Per-family notes

Current state: every adapter extends `BaseAdapter` (`packages/chains/src/base-adapter.ts`),
which supplies `chains()` from the catalog, the default `MemoryRpcPool`, `requireChain`
(throws `UnknownChainError`), shared fetch options and the `NotImplementedError` stubs for the
signing path. Each family implements `deriveAddress`, `validateAddress`, native-asset
`getBalances` and `status` with `@noble/hashes` and `@scure/base` only, through the shared
`fetchJson` / `fetchJsonRpc` helpers, `withFailover` and `withCrossCheck` over the `RpcPool`.
The generic signing methods (`build`, `simulate`, `sighashes`, `attach`, `broadcast`)
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

Current Bitcoin send coverage uses single-key P2WPKH inputs on Signet only, with canonical
P2WPKH, P2WSH or P2TR recipient outputs. The endpoint's full
genesis hash is checked before dependent reads. Preparation selects up to eight confirmed UTXOs
automatically or uses the exact confirmed outpoints chosen in coin control. Manual selection
never adds or substitutes an input; stale, spent, insufficient or dust-producing selections fail.
The coin list is an endpoint observation and is refreshed and validated again at preparation. It
checks outspend status and fetches each complete funding transaction. Rust independently checks
its transaction ID, output script and value, rejects coinbase funding, duplicate inputs, dust
and excessive fees, and constructs a PSBT with SIGHASH_ALL. Only one recipient and optional
change to the same sender are produced. The fee rate preview accepts 1–100 sat/vbyte and total
fees are capped at 100,000 sats. The estimate includes the recipient script's actual output size.
Sender and change remain canonical `tb1` P2WPKH addresses (294 sats minimum); P2WSH and P2TR
recipients require 330 sats. Unknown witness versions and legacy outputs are refused.
These dust bounds follow [Bitcoin Core's default dust policy](https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.cpp).
Keys remain in the vault.

Local funding validation is not network simulation. The simulation flag is false, and
`RequireSimulationPass` refuses these proposals. Before approval each selected input must still
be observed unspent; active proposals reserve inputs in the core. Broadcast errors and absent
index entries remain pending under the core transaction ID, with no automatic resend, expiry
or release of spend reservations. Restart resumes tracking. Six observed confirmations are
required; RPC observations are not chain proofs. RBF is signaled but replacement is not
implemented. Funded Signet confirmation, Taproot input signing, threshold signing,
mainnet and other Bitcoin-family sends remain outside this increment.

### Solana (`chains-solana`, @solana/kit)

Current send coverage is single-key native SOL on Devnet only. `prepareSolana` produces a bounded
legacy or v0 native transfer and simulation for the core ledger; the core independently constructs the wire
message and signs after policy re-evaluation and passphrase approval. The adapter does not receive
key bytes. Every signing-flow RPC verifies `getGenesisHash` against the requested CAIP-2 cluster.
RPC integer amounts outside JavaScript's exact range are refused. Simulation errors and transfers
to executable or non-System-owned accounts appear in approval. The native message has no priority
fee instruction; its fee preview comes from `getFeeForMessage` for the exact selected message.
Legacy remains the default; existing saved records without a version field stay legacy. The v0
increment keeps the sender, recipient and System Program inline and encodes zero lookup tables.
Both formats contain exactly one native transfer, with no added signers or program instructions.
Approval exposes the chosen format. Broadcast accepts only the core's bounded native wire shape.

Before approval, a stale blockhash expires the proposal. A broadcast timeout retains the core's
signature as pending; finality polling decides confirmed/failed, and finalized height beyond the
last valid height plus a missing signature in a history response at least as recent as the
finalized slot decides expired. These dependent observations share one verified RPC endpoint.
Restarted signed/broadcast records
resume signature tracking without an automatic resend. `@solana/kit` is a pinned test dependency
for independent wire decoding; runtime assembly is checked separately in Rust and TypeScript.
Explicitly tracked SPL Token and Token-2022 mints support public balance reads on catalogued
clusters. Each endpoint verifies cluster genesis, initialized mint ownership and decimals before
reading owner accounts at a slot at least as recent as the mint observation. Account mint, owner,
program and decimals must agree; duplicate accounts and overflowing integer sums are refused.
Independent endpoints cross-check exact base-unit totals. Read errors stay on the token row.
Frozen, withheld and confidential amounts can restrict spendability; displayed public amounts
do not authorize transfers. Labels are local display metadata and mint addresses preserve case.
Mainnet sends, TSS ceremonies, SPL transfers, address lookup tables, v1 messages and swaps remain disabled/unimplemented.
The remaining bullets describe target coverage:

- Address lookup tables, v1 messages, compute budget and priority fee instructions.
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

### Tron (`chains-tron`, java-tron HTTP API)

Chain ids are `tron:<EVM-style chain id>`: `tron:0x2b6653dc` (mainnet), `tron:0xcd8690dc` (Nile),
`tron:0x94a9059e` (Shasta). The genesis block id ends with the same eight hex digits, so every
endpoint proves its network through `/wallet/getblockbynum {num: 0}` before it is used.
Addresses are base58check of `0x41 || keccak256(uncompressed key)[12..]`; accounts derive at
`m/44'/195'/0'/0/i` like TronLink. java-tron reports balances as bare JSON numbers that can
exceed 2^53, so responses are read as text and long integers are quoted before parsing.

Reads: TRX from `/wallet/getaccount` (an address that never received TRX reads as zero) and the
mainnet USDT TRC-20 balance from `balanceOf` through `/wallet/triggerconstantcontract`, both
cross-checked across endpoints. History comes from TronGrid's indexed `/v1/accounts/{addr}/transactions`,
which plain java-tron nodes do not serve; TRX transfers carry net changes and other contract
calls are listed without them. Keyless TronGrid allows 3 requests a second, so PublicNode is
the first mainnet endpoint.

Current send coverage is single-key native TRX on Nile only. `prepareTron` takes the reference
block from `/wallet/getnowblock` and sets a 30-minute expiration. It reads the chain parameters,
bandwidth and both accounts, then estimates the fee. Sending to an address with no account
burns the activation fee, and the simulation warns about it. The core independently encodes
`Transaction.raw` with exactly one `TransferContract` and no permission id, data, fee limit or
extra contracts. It signs sha256 of those bytes (the transaction id) with recoverable
secp256k1 ECDSA and returns the serialized `Transaction`. Rust and TypeScript share a pinned
byte vector. Approval is refused within a minute of expiration. Broadcast accepts only the
ledger's own bytes plus one 65-byte signature, through `/wallet/broadcasthex`. Status comes from
`/walletsolidity/gettransactioninfobyid`. Expiry is reported only after a solidified block
passes the expiration and the id is still absent. TRC-20 transfers, staking, resources,
mainnet and threshold sends are not enabled. Threshold Tron needs CGGMP21.

### Signing families

**Substrate (`polkadot:<first 32 hex of the genesis hash>`, `chains-substrate`).** Sixteen chains:
Polkadot, Kusama, their asset hubs, Bittensor, Hydration, Bifrost, Acala, Karura, Vara, SORA and
Chainflip, plus the Westend and Paseo test networks. Ed25519 SLIP-10 at `m/44'/354'/0'/0'/i'` on
every chain (one key, one account everywhere; sr25519 wallets such as Polkadot.js derive
differently and cannot be imported). The address is the raw 32-byte key, SS58-encoded under the
chain's prefix. Reads are storage queries against genesis-proven HTTPS JSON-RPC endpoints,
cross-checked where two operators exist (Acala, Karura, SORA and Chainflip have one); Asset Hubs
also read USDt/USDC asset balances. There is no history: nodes do not index by account and
Subscan needs an API key. Sends are native `transfer_keep_alive` on Westend and Westend Asset Hub
only, with a mortal era of 256 blocks (about 25 minutes) as real on-chain expiry. A runtime
upgrade that bumps `transactionVersion` refuses signing until the layout is re-verified and
re-pinned. A funded Westend broadcast has not been verified.

**Stellar (`stellar:pubnet|testnet`, `chains-stellar`).** Ed25519 SEP-0005 at `m/44'/148'/i'`
(Lobstr, Freighter, Solar, Ledger); StrKey `G…` addresses, muxed `M…` refused. Horizon endpoints
prove their network through the root document's `network_passphrase`; mainnet XLM and USDC are
cross-checked across SDF and Lobstr. Sends are native XLM payments on testnet only, becoming
`CreateAccount` for unfunded recipients; `maxTime` (30 minutes) is a network-enforced expiry, and
a stuck transfer expires because there is no fee bump. Confirmed end to end on testnet.

**Aptos (`aptos:<ledger chain_id>`, plus `movement:126` and `supra:8`, `chains-aptos`).** Ed25519
at `m/44'/637'/i'/0'/0'` (Petra, Pontem, Martian); the address is sha3-256 of the key with the
single-sig scheme byte. Each endpoint proves its ledger chain id before use. Mainnet USDC is read
as a fungible asset; Movement reads balances and history; Supra is balances-only (its REST fork
wraps view results differently). Sends are native APT on `aptos:2` (testnet) only, with
`expirationTimestampSecs` (30 minutes) as real expiry. A noble-signed testnet broadcast was
accepted by the validator up to the unfunded fee; a confirmed transfer was not exercised (the
faucet needs a browser login).

**Sui (`sui:mainnet|testnet|devnet`, `iota:*` read-only, `chains-sui`).** Ed25519 at
`m/44'/<coin>'/0'/0'/i'` (784 Sui, 4218 IOTA); blake2b-256 addresses, with a flag byte on Sui and
without on IOTA. Public Sui fullnodes dropped JSON-RPC, so the adapter reads, dry-runs and
broadcasts through the Mysten GraphQL service (protocol chosen by namespace, not URL); IOTA still
serves JSON-RPC and is read-only here. Mainnet USDC is read-only. Sends are native SUI on testnet
as a one-command programmable transaction paying gas from the sender's coin objects. There is no
time expiry; the transaction dies once any gas coin's version moves, which is reported as
`expired`. A funded broadcast was not verified (the faucet refuses scripted requests).

**XRPL (`xrpl:0|1|2` network ids, `chains-xrpl`).** Secp256k1 at `m/44'/144'/0'/0/i` (Xaman, Trust,
Ledger); classic `r…` base58check addresses, X-addresses refused. rippled's public JSON-RPC ports
send no CORS headers, so `:51234` endpoints are rewritten to WebSocket; every endpoint proves its
`network_id`. No issued-currency balances are read (decimal-string trustlines, skipped as not
cheap). Sends are XRP payments on testnet (`xrpl:1`) with an optional destination tag — the tag is
not bound by the intent, so the approval dialog shows it. `lastLedgerSequence` (open ledger + 300,
about 15-20 minutes) is real on-chain expiry. Confirmed end to end on testnet, including a tagged
account activation.

**NEAR (`near:mainnet|testnet`, `chains-near`).** Ed25519 at `m/44'/397'/i'` (the
MyNearWallet/Meteor layout; Ledger's app nests two more levels). The address is the implicit
account id, the 64 lowercase hex of the key. Endpoints prove their genesis hash; history comes
from the keyless FastNEAR indexer (NearBlocks loses precision to JSON floats). Mainnet USDC
(NEP-141) is read-only. Sends are native NEAR on testnet from the implicit account; the referenced
block hash keeps the transaction valid for 86,400 blocks (about a day), a real expiry. A funded
end-to-end transfer was not exercised (no keyless faucet).

**Algorand (`algorand:<32 base64url chars of the genesis hash>` per CAIP-2, `chains-algorand`).**
Mainnet, testnet and Voi. Ed25519 SLIP-10 at `m/44'/283'/i'/0'/0'` — Pera/Defly 25-word phrases
are not BIP39 and Ledger's Algorand app uses BIP32-Ed25519, so neither imports. Reads pair algod
with the indexer (every indexer answer must carry the expected genesis hash); mainnet USDC (ASA 31566704) and Voi are read-only. Sends are native ALGO on testnet, deliberately without a note
field (the intent cannot bind one); `lastValid` (1000 rounds, about 45 minutes) is real expiry. A
rekeyed sender is refused. No confirmed testnet transfer yet (faucets need a login).

**TON (`tvm:-239` mainnet, `tvm:-3` testnet, `chains-ton`).** Ed25519 at `m/44'/607'/i'` (Trust
Wallet/Ledger; Tonkeeper-style TON mnemonics derive differently). The address is the v4r2 wallet's
StateInit hash. Reads use toncenter v2/v3 and tonapi, proven by the masterchain zerostate root
hash and rate-limited to about 1 request per second keyless; the stored hash is the TEP-467
normalized message hash. Sends are native TON on testnet; the first transfer deploys the wallet
contract, and `validUntil` (30 minutes) is enforced by the wallet itself (exit code 36). There is
no comment field, so exchange deposits that need one cannot be paid. Confirmed end to end on
testnet. Jettons are not decoded.

**Cardano (CIP-34 `cip34:<networkId>-<networkMagic>`, `chains-cardano`).** Ed25519, but not
SLIP-10: CIP-1852 with the CIP-3 Icarus master and BIP32-Ed25519 children, payment
`m/1852'/1815'/i'/0/0` plus stake `…/2/0`, yielding a bech32 base address. Each chain needs one
Yoroi indexer endpoint (UTxOs, balances, history) and one Koios Ogmios endpoint (tip, parameters,
submit), each proven by an anchor block or the network magic; each kind has a single operator, so
there is no cross-provider check. Sends are native ADA on preprod, spending ADA-only UTxOs
(token-bearing ones are never spent), with a ledger-enforced `ttl` (2 hours) as expiry. Confirmed
end to end on preprod. Preview is not catalogued (no keyless indexer exists for it).

**Antelope (`antelope:<first 32 hex of the chain id>`, `chains-antelope`).** Vaulta, Jungle4, XPR
Network and its testnet, WAX and its testnet, and Telos and its testnet (the EVM sidechains stay
EVM entries). Secp256k1 at `m/44'/194'/0'/0/i`; the account is an on-chain name and the derived
identity is the `PUB_K1_` key. Reads use the chain API; history and status fallback use Hyperion
v2 from per-network tables. Sends are native WAX on WAX testnet only, with an optional memo that
the intent does not bind (the approval dialog shows it). TaPoS plus `expiration` is real on-chain
expiry; there is no nonce or fee market, so a stuck transaction expires and is rebuilt.

**MultiversX (`mvx:1` mainnet, `mvx:D` devnet, `chains-multiversx`).** Ed25519 at
`m/44'/508'/0'/0'/i'` (xPortal, web wallet, sdk-core); bech32 `erd1` addresses. The API and
gateway dialects are classified by hostname and both are probed for `erd_chain_id`; they share
one operator, so provenance is `single` — no independent keyless endpoint was found. Mainnet
USDC (ESDT `USDC-c76f1f`) is read-only. Sends are native EGLD on devnet. Transactions carry no
expiry field and stay valid until the nonce is consumed, at which point the transfer can never
land and is reported as `expired`.

**Tezos (`tezos:<base58 chain id>`, `chains-tezos`).** Mainnet `NetXdQprcVkpaWU` and Shadownet
`NetXsqzbfFenSTS` — Ghostnet no longer resolves, so Shadownet is the signing network. Ed25519 at
`m/44'/1729'/i'/0'` (Temple, Kukai, Umami); `tz1` addresses. Reads pair Octez node RPCs with the
TzKT indexer, both checked by chain id; mainnet is read-only and there are no FA1.2/FA2 token
reads. Sends are native tez on Shadownet to implicit (`tz*`) accounts only, never KT1 contracts.
The branch stays valid for 600 blocks, a real expiry.

**Stacks (`stacks:<network_id>`, `chains-stacks`).** Mainnet `stacks:1`, testnet
`stacks:2147483648`. Secp256k1 at `m/44'/5757'/0'/0/i` (Leather, Xverse); c32check addresses.
Hiro is the only keyless operator, so provenance is `single`. Sends are native STX on testnet.
There is no time-based expiry: a transaction dies when another one consumes its nonce (reported
as `expired`), and a same-nonce higher-fee replacement is valid RBF (reported as `replaced`).

**VeChain (`vechain:<last 32 hex of the genesis block id>`, `chains-vechain`).** Secp256k1 at
`m/44'/818'/0'/0/i` (VeWorld, Sync2). Endpoints prove the full genesis id via `/blocks/0`; the
signed chain tag is its last byte. Sends are native VET on testnet, with VTHO as the fee token.
The transaction is includable until `blockRef + expiration` (180 blocks, about 30 minutes), a
real expiry reported as `Expired`.

**Hyperliquid (`hl:mainnet|testnet`, `chains-hyperliquid`).** Secp256k1 at `m/44'/60'/0'/0/i` —
standard Ethereum accounts, canonical lowercase because the address characters enter the EIP-712
digest. Each network has an API endpoint (`/info`, `/exchange`) and an explorer RPC on one
operator, so provenance is `single`. The native holding is the HyperCore perp account's
withdrawable USDC; spot USDC and HYPE are read-only. Sends are testnet USDC via `usdSend`. There
is no expiry field, but the nonce must sit within block time −2 days/+1 day, so a stale transfer
is effectively dead and reported as `expired`.

**Starknet (`starknet:SN_MAIN`, `starknet:SN_SEPOLIA`, `chains-starknet`).** The account secret is
secp256k1 at `m/44'/9004'/0'/0/i` (Braavos/Argent X prefix), ground into the Stark key (EIP-2645);
the address is the Pedersen contract address of the OpenZeppelin account class. JSON-RPC endpoints
prove `starknet_chainId`; drpc's free tier lacks `starknet_simulateTransactions`. Sends are
native STRK on Sepolia, bundling DEPLOY_ACCOUNT v3 with the first INVOKE v3 in one approval.
v3 transactions have no expiry — the ledger never reports `Expired` for Starknet. Mainnet is
read-only.

**Icon (`icon:<decimal nid>`, `chains-icon`).** Mainnet `icon:1`, Lisbon testnet `icon:2`.
Secp256k1 at `m/44'/4801368'/0'/0'/i'` (IIP-48; the ecosystem uses 4801368, not SLIP-44's 74).
The address is `hx` + sha3-256 (not keccak) of the uncompressed key. Each network is pinned by
its block-1,000,000 hash. Mainnet reads include bnUSD; history comes from the tracker REST API.
Sends are native ICX on Lisbon at a fixed step fee. There is no expiry field, but nodes reject
timestamps outside about ±2 hours, so the built-in 1-hour window can surface `Expired`. Lisbon
has exactly one known public endpoint (the solidwallet zone is dead), which is the family's main
risk.

**Everscale/Venom (`ever:42`, `venom:1`, `venom:1002`, `chains-everscale`).** Ed25519 at
`m/44'/396'/0'/0'/i'` on the mainnets (both share SLIP-44 396, nekoton-style) and
`m/44'/1'/0'/0'/i'` on Venom testnet. TVM external messages carry no network id and the
EverWallet contract runs on both networks (same code hash, confirmed live), so a testnet
signature from a coin-396 key would be a valid mainnet spend from the same address; the core
therefore refuses to sign an Everscale transaction unless the signer's path starts with
`m/44'/1'/`. Everscale reads over EverCloud GraphQL, Venom over JRPC; the dialect is picked from
the namespace. `ever:42` and `venom:1` are read-only. Sends are native VENOM on Venom testnet
only; the first transfer deploys the wallet, and the wallet refuses the message after
`expireAt`, a real expiry. The Venom testnet endpoint was down at build time; its global id
(1002) comes from secondary sources.

**Waves (`waves:87` mainnet, `waves:84` testnet, `chains-waves`).** Ed25519 SLIP-10 at
`m/44'/5741564'/0'/0'/i'`, but the signing key is derived from that secret by Waves's own
hash-and-clamp ("axolotl") scheme, so the account key is a Curve25519 key and threshold wallets
cannot sign Waves. Each network is pinned by its height-1 block signature. Testnet has exactly
one usable endpoint, so provenance is `single`. Sends are native WAVES on testnet (v3 protobuf
body, JSON broadcast) at a fixed 0.001 WAVES fee; nodes reject timestamps more than 2 hours
stale, which is reported as `expired`. Mainnet is read-only (balances, history, status, one
issued token).

**Radix (`radix:mainnet`, `radix:stokenet`, `chains-radix`).** Ed25519 CAP-26 at
`m/44'/1022'/2'/525'/1460'/i'` (network 2 = Stokenet is baked into the path). Babylon transfers
are `NotarizedTransactionV1`s, byte-exact against the Radix Engine Toolkit. The Gateway API
(balances, history, status, submit) is run by RDX Works only, so provenance is `single` until
community gateways are configured. Sends are native XRD on Stokenet; 5 XRD is locked as a fee
deposit and the unused part is refunded. A transaction is permanently rejected once the epoch
passes `end_epoch_exclusive`, reported as `expired`. Mainnet is read-only.

**ICP (`icp:00000000000000000000`, the Rosetta network id, `chains-icp`).** There is no public
testnet ledger, so mainnet is the signing network, accepted with strict amount and expiry bounds.
Secp256k1 at `m/44'/223'/0'/0/i` (Plug convention); the address is the 64-hex account identifier
derived from the self-authenticating principal. Boundary nodes (`icp-api.io`, `ic0.app`,
`icp0.io`) are pinned by the mainnet root key. Sends are native ICP on mainnet;
`ingressExpiryNanos` (at most 10 minutes) makes the replica refuse late submissions, a real
expiry, and the fixed fee is deducted from the amount's remainder.

**Ergo (`ergo:mainnet|testnet`, `chains-ergo`).** Secp256k1 at `m/44'/429'/0'/0/i` (EIP-3);
P2PK base58 addresses. Reads come from the explorer API over HTTPS; the public broadcast nodes
are HTTP-only, so sends from the HTTPS web bundle are mixed-content blocked and work from the
desktop shell. Sends are native ERG on testnet with the protocol fee contract and change to the
sender. UTxO transactions cannot expire — a spent input kills the transfer, and the ledger never
reports `Expired` for Ergo. No funded end-to-end send yet (the faucet is captcha-gated).

**Alephium (`alephium:0` mainnet, `alephium:1` testnet, `chains-alephium`).** Secp256k1 at
`m/44'/1234'/0'/0/i` (the third level is the key type, not an account index). Addresses are
checksum-less base58, so validation is shape-only. Node REST serves balances, UTxOs, build and
submit; history lives on the explorer backend. Sends are native ALPH on testnet and were
confirmed end to end against the live node. UTxO transactions never expire. Faucet coins arrive
timelocked for about a day, and prepare skips locked UTXOs.

**Aeternity (`aet:ae_mainnet`, `aet:ae_uat`, `chains-aeternity`).** Ed25519 at
`m/44'/457'/0'/0'/i'` (aepp-sdk, AirGap, Ledger); `ak_` base58check addresses. Node `/v3` plus
the middleware serve reads and history; account balances are bare JSON numbers past 2^53, so
responses are parsed as text. Sends are native AE on testnet (`ae_uat`), confirmed end to end
with a live faucet and a mined transaction. The `ttl` height bound is real on-chain expiry;
there is no replace-by-fee.

**Chia (`chia:<first 8 hex of the genesis challenge>`, `chains-chia`).** BLS12-381 wallet keys by
EIP-2333 at `m/12381'/8444'/2'/i'` through a provenance route, not SLIP-10; the address is the
bech32m puzzle hash of the synthetic-key standard puzzle. The coinset.org full-node RPC is
keyless and CORS-clean; Spacescan is Cloudflare-blocked from some networks and not depended on.
Sends are native XCH on testnet11 as single-coin spends (no joins or splits), fee "0" acceptable
on an empty mempool. Coin spends never expire. The core-client `Curve` enum has no `bls12-381`
variant, so the adapter checks the key by length; no funded broadcast yet (captcha faucet).

**Fuel (`fuel:9889` Ignition, `fuel:0` Sepolia, `chains-fuel`).** Secp256k1 at
`m/44'/1179993420'/i'/0/0` (fuels HDWallet default); sha256-based `0x` addresses. Both networks
are GraphQL with CORS `*`; reads and history (`transactionsByOwner`) work on both, but mainnet
signing is refused. Sends are native ETH (9 decimals) on Sepolia with adapter-prepared gas;
`expiration` is a block height (head + 600, about 10 minutes), a real `Expired` state, and the
unused fee returns as change. Wire validity was proven by node error discrimination; a funded
send was not exercised (captcha faucet).

**aelf (`aelf:AELF`, `aelf:tDVV`, `chains-aelf`).** Secp256k1 at `m/44'/1616'/0'/0/i` (aelf-sdk,
NightELF, Portkey); base58check of the double-sha256 of the uncompressed key. aelf nodes have no
keyless view endpoint, so `GetBalance` calls are signed with a well-known throwaway key and the
balance carries a provenance notice; there is no keyless history indexer, so history is
unavailable. Sends are native ELF on tDVV. The reference-block validity window (a conservative
512 blocks, a few minutes) is real expiry; the exact fee cannot be quoted keylessly, so a 0.01
ELF allowance is reserved.

**Starcoin (`starcoin:1` mainnet, `starcoin:251` Barnard, `chains-starcoin`).** Ed25519 at
`m/44'/101010'/0'/0'/i'` (StarMask); the address is the sha3-256 auth-key tail. The seed nodes
omit CORS headers entirely, so the web bundle cannot reach them and sends require the desktop
shell; Barnard itself was unreachable at wiring time (kept so a revival needs no code change).
Sends are native STC on Barnard only, expiring 30 minutes after preparation (real
`expiration_timestamp_secs` expiry). History is unavailable (the stcscan API errors); no
end-to-end broadcast has been possible.

**Obyte (`obyte:mainnet|testnet`, `chains-obyte`).** Secp256k1 at `m/44'/0'/0'/0/i` — the
reference wallet predates SLIP-44 592 and derives at Bitcoin's coin type. Addresses are base32
chash160 of the signature definition. Obyte is a DAG: reads are hub REST calls proven against
the genesis unit, and broadcast is websocket-only (`wss://…/bb`, one connection per post). Sends
are native GBYTE on testnet; the fee equals the unit's storage size in bytes. Units never expire
on-chain — staleness is an approval check and the ledger refuses `Expired` for Obyte. The public
testnet faucets are dead, so no funded send was exercised.

**Chromia (`chromia:0x<first 8 bytes of the BRID>`, `chains-chromia`).** Postchain: the family
serves the FT4 economy chain, found through the directory chain. Secp256k1 at the plain EVM path
`m/44'/60'/0'/0/i`, deliberately — Chromia has no SLIP-44 coin type and its official wallet is
EVM-key-centric. The account id is `gtvHash(pubkey)` as 64 hex. Endpoints prove themselves with
the merkle-hash-version feature probe. Sends are native CHR on testnet; a GTX has no deadline,
so there is no `Expired` state. A brand-new account id needs a one-time registration transaction,
which the ledger and package support but the web send form does not offer yet. No accepted
on-chain send yet (the faucet is social-gated).

**Keeta (`keeta:main`, `keeta:test`, `chains-keeta`).** Secp256k1 at `m/44'/9797'/0'/0/i` — 9797
is unregistered and documented as ours, because Keeta's own scheme (HKDF-SHA3) is not BIP-32.
Addresses are `keeta_` base32 with a sha3-256 checksum. Representative REST nodes serve ledger
reads (hex-bigint strings); broadcast goes through the publish-aid, which collects votes
server-side. Sends are native KTA (18 decimals) on the test network. Blocks never expire; if the
sender's head moves first, the transfer is reported `dropped`, never `Expired`. The faucet is
social-gated, so no funded send was exercised.

**Namada (`namada:<chain-id hash suffix>`, `chains-namada`).** The full native id
(`namada.5f5de2dd…` / `housefire-alpaca.cc0d3e0c…`) is pinned in the core because CAIP-2
references forbid dots. Ed25519 at `m/44'/877'/0'/0'/i'`; bech32m `tnam` addresses. Mainnet reads
pair CometBFT `abci_query` storage proofs with the official indexer (both CORS `*`). Signing is
gated to Housefire (`namada:cc0d3e0c033be`), but every documented Housefire RPC was dead at
wiring time — the dead entries are kept so a revival needs no code change. Wrapper transactions
carry no expiration, so Namada never reports `Expired`.

**Bitcoin forks (`btcfork:<name>-mainnet|testnet`, `chains-btcfork`).** Bitcoin Cash (145), Dash
(5), Zcash (133), DefiChain (1129) and Verus (141) share one module: secp256k1 at
`m/44'/<coin>'/0'/0/i` on mainnets and `m/44'/1'/0'/0/i` on every testnet (no segwit on any
fork), transparent addresses only, P2PKH sends of one to eight inputs with change to the sender.
A fork sighash carries no network id, so a testnet key at the mainnet coin type would sign a
valid mainnet spend from the same script; like Bitcoin, the core refuses fork transactions from
any path that does not start with `m/44'/1'/`. BCH derives CashAddr and accepts legacy base58.
Signing is enabled on the five testnets, but only Dash testnet has a live public endpoint
(insight), so new wallets receive only that one; the other four carry empty RPC lists, throw
honestly and can be added by hand. Zcash testnet speaks the `zcash-rpc` driver (a zcashd or
zebrad node with the address index: `getaddressutxos`, `getrawtransaction`,
`sendrawtransaction`, `getblockchaininfo`), so one user-added node makes reads and sends work.
Mainnet reads come from Blockchair (BCH/Dash/ZEC — the keyless tier degrades to HTTP 430 under
load), ocean (DefiChain balance only; it has no UTXO listing, so DFI sends cannot be prepared),
and a Verus JSON-RPC proxy with an address index. Zcash and Verus v4 carry a real `expiryHeight`
(tip + 100) and can report `Expired`; the other forks never expire. Zcash rotates its ZIP-143
consensus branch id at every network upgrade, so the adapter reads
`getblockchaininfo.consensus.nextblock` at prepare time and carries it as `consensusBranchId`;
the core accepts it only on Zcash, refuses zero and Verus's pinned Sapling id (a Zcash-shaped
transaction hashed under it would be a Verus spend from the same key), and falls back to its last
known id (NU6.3) when no node reported one. A stale id only yields a transaction the network
rejects — the digest is always computed by the core over its own serialization — so a Zcash
upgrade needs no wallet release.

**Gala (`gala:mainnet|testnet`, `chains-gala`).** GalaChain uses Ethereum keys verbatim, so
secp256k1 at the plain EVM path `m/44'/60'/0'/0/i`; addresses are `eth|<EIP-55>` and the checksum
case is part of what the chaincode recovers. The gateway APIs are CORS-clean but rate-limited
(about 20 requests per minute); the explorer API has no by-hash or by-address route, so status is
a bounded latest-page scan and history is unavailable. Sends are native GALA on testnet, burning
a fixed 1 GALA fee; `dtoExpiresAt` (30 minutes) is a real chaincode-enforced expiry, and the
gateway assigns the real transaction id synchronously at broadcast. Both gateways recovered the
expected signer from local signatures live; a funded broadcast was not exercised.

**Mixin (`mixin:<first 16 hex of the kernel network id>`, `chains-mixin`).** Self-custodial Mixin
Kernel only — the Messenger/Safe APIs are app-custodial and unused. The account secret is ed25519
SLIP-10 at `m/44'/2365'/0'/0'/i'`, but kernel signatures are raw edwards25519 scalars with a
custom Schnorr-like scheme over spend/view keys, so threshold wallets cannot sign Mixin. The
single HTTPS kernel endpoint means `single` provenance. Signing is gated to the main network
deliberately — no public test kernel exists — and the send form says plainly that real XIN moves.
Transfers are fee-free, spend one to eight ghost-key inputs and return change; they never expire
(approval re-verifies every input instead). The honest gap: the kernel indexes outputs by ghost
key, not address, so balances and prepare need an injected `utxos` provider until a core-side
view-key UTXO scanner lands; without it those calls throw and history is an empty page with a
coverage note.

**Qubic (`qubic:mainnet`, `chains-qubic`).** No testnet exists, so mainnet is the signing network
deliberately. The derivation is ed25519 SLIP-10 at `m/44'/83293'/0'/0'/i'`, but the signing curve
is hand-rolled FourQ/SchnorrQ over KangarooTwelve — a FROST group key is not a SchnorrQ key, so
threshold wallets cannot sign Qubic. Identities are 60 uppercase letters with a K12 checksum.
`rpc.qubic.org` is the only keyless endpoint (`single` provenance), and the archiver was
unreachable, so history reports its gap. Sends are fee-free whole-unit QU that execute at a target
tick about a minute after preparation; a passed tick is a real expiry. A core-signed transaction
was accepted and relayed by the live mainnet (rejection-level proof only; no funded execution).
Qubic has no mempool view, so a broadcast transfer is `unknown` until its tick.

### Read-only families

**NEO N3 (`neo3:mainnet|testnet3`, `chains-neo`).** Signing is out: NEO uses P-256, the core has
no secp256r1 curve or vendored p256 crate, and D1 would need threshold P-256 that does not exist
in the vendored set — so only the address codec (verification script to base58check) lives in the
core. Reads are NEO/GAS balances via `getnep17balances` cross-checked across two operators and
status via `getrawtransaction`; no keyless history indexer is alive (Dora and NeoTube serve only
SPA shells), so history reports the gap.

**Aleo (`aleo:mainnet|testnet`, `chains-aleo`).** Every Aleo execution is a client-side SNARK
proof (snarkVM), and even key derivation runs through Poseidon, so `deriveAddress` throws and no
keyed accounts exist yet; the bech32m address codec and oracle vectors are pinned for a future
proving slice. Read-only public-credit balances come from the Provable explorer API with a pinned
genesis hash; record-held (private) balances are invisible to any API by design, and there is no
keyless history endpoint.

**Canton (`canton:mainnet|testnet`, `chains-canton`).** Self-custody needs validator-node
credentials (topology onboarding) plus a reimplementation of Canton's `signTransactionHash`
wrapping and DAML encoding, and every public SV scan route answers 403 RBAC without CORS, so
Canton ships as a read-only scaffold with the ed25519 party-id codec
(`hint::1220<sha256 fingerprint>`) ready. The adapter implements the official scan OpenAPI shapes
and reports the 403 gap until a keyless scan answers.

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

## Read-only transaction history

Every family adapter implements getHistory through the bounded readers in
packages/chains/src/history.ts. Each read validates the address and endpoint network identity,
uses the shared whole-body timeout/body-size limit, and reports its source and coverage.
A caller can cancel reads; failures never become an empty successful history.

| Family                                                        | Public history                                                                                                                                                                                                                                                                                 | Pagination and limits                                                                                                                  |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| EVM, including L1, L2, sidechain and appchain catalog entries | Any compatible RPC can scan external transactions and execution fees. Optional keyless Blockscout v2 indexers supply indexed external transactions or individual token-transfer events. Common hosted instances are bundled; a pane can specify another HTTPS instance for the selected chain. | RPC scans 12 blocks per page; Blockscout pages by its validated cursor. ERC-20 transfer events retain their log identity across pages. |
| Bitcoin family                                                | Esplora-compatible address transaction history, including mempool records, input/output net changes and whole-transaction fees.                                                                                                                                                                | 25 confirmed records per page; confirmed hash cursor. Dogecoin needs a user-supplied compatible endpoint.                              |
| Solana                                                        | Confirmed signatures referencing the address, including program calls; transaction details provide SOL net changes and fees.                                                                                                                                                                   | 20 signatures per page; signature cursor. Pruned details are unknown; SPL deltas are not decoded.                                      |
| Cosmos SDK                                                    | Indexed sender and recipient events, deduplicated by transaction hash; bank transfer events and native-denom fees.                                                                                                                                                                             | Two 20-record queries per page; modern page/limit plus legacy pagination. A node must expose transaction indexing and the LCD service. |

These are unverified endpoint observations, not cryptographic inclusion proofs. EVM RPC scans
are not indexed lifetime history and omit internal calls, token logs and additional rollup fees.
Blockscout external transactions and token transfers have separate coverage; neither promises
complete internal-call or bridge decoding. Cosmos bank events do not fully decode staking,
contracts or the IBC lifecycle. Net balance changes must not be labelled transfer amounts:
Bitcoin and Solana changes can include fees/rent, and EVM execution fees are included where known.
Unavailable fees/details remain unknown instead of becoming zero.

The transaction-history element separates public observations from the encrypted core's local
signing records. Denied, rejected and awaiting requests remain local records; they are never
presented as completed on-chain transfers. Public reads are requested for one selected account,
including watch accounts, and the UI shows source, scope, coverage, filters, full details and
older-page controls. Changing account/address/method cancels the old request and clears its
cursor. The view retains at most 1,000 rows. Read-only history does not change signing eligibility,
policy decisions, threshold rules or audit transitions.

Indexed Blockscout pages use an 8 MiB response limit because 50-record pages include rich
metadata even when the UI only needs transaction fields. Ordinary RPC responses retain their
1 MiB limit. Streaming and declared-size checks enforce both limits under the whole-body timeout.
Network identity is checked through RPC failover first; indexer failures are reported directly
and do not penalize healthy RPC endpoints or retry the same indexer on another RPC node.
